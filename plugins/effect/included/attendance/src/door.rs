//! The two doors of the session service, over HTTP on one Unix socket. The
//! delegate door answers `invoke_agent`. The dispatch door answers
//! `enqueue` and `job_status`. Each door takes its own bearer. Every answer
//! is untrusted input: its shape and size are checked before use.

use std::path::Path;
use std::time::Duration;

use chaperone_ulid::Ulid;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    DelegateBody, DispatchBody, DoorToken, Enqueue, Family, InvokeAgent, JobStatus, JobsBody,
    Reason, Refusal, cap,
};

/// A Unix socket carries no host. The name is never resolved.
const BASE_URL: &str = "http://sessiond";

const DELEGATE_PATH: &str = "/delegate";
const DISPATCH_PATH: &str = "/dispatch";
const JOBS_PATH: &str = "/dispatch/jobs";

/// The longest wait for the delegate door, for the whole call.
// DESIGN-QUESTION: docs/design.md 5.5 bounds an upstream call at 30
// seconds, so chaperone ends a delegate call first, with
// `upstream_timeout`. The reading: both bounds stay. A change gives this
// upstream its own bound in 5.5.
pub const DELEGATE_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest wait for the dispatch door. No call waits for a job.
pub const DISPATCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The most rows of `job_status` that reach the model.
pub const MAX_JOBS: usize = 200;

/// The largest door answer the plugin reads, in bytes.
const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;

const DISPATCH_SILENT: &str = "the dispatch door did not answer";

/// Why a request to a door gave no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostFault {
    Timeout,
    Unreachable,
}

/// The two doors and their bearers.
#[derive(Debug)]
pub struct Doors {
    client: reqwest::Client,
    delegate_token: DoorToken,
    dispatch_token: DoorToken,
}

/// The status of a delegate answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DelegateStatus {
    Ok,
    Timeout,
    Failed,
}

impl Doors {
    /// # Errors
    ///
    /// Returns the [`reqwest::Error`] of a client that cannot be built.
    pub fn new(
        socket: &Path,
        delegate_token: DoorToken,
        dispatch_token: DoorToken,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder().unix_socket(socket).build()?;
        Ok(Self {
            client,
            delegate_token,
            dispatch_token,
        })
    }

    /// Ask another family and wait for its answer. The answer is wrapped as
    /// untrusted data.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] for every answer that is not a clean answer.
    pub async fn invoke_agent(
        &self,
        caller: &Family,
        call: &InvokeAgent,
    ) -> Result<Value, Refusal> {
        let id = mint()?;
        let body = DelegateBody {
            caller_family: caller.as_str(),
            target_family: call.family.as_str(),
            delegation_id: id.as_str(),
            claimed_session_id: None,
            message: &call.message,
        };
        let target = call.family.as_str();
        let sent = self
            .post(DELEGATE_PATH, &self.delegate_token, &body, DELEGATE_TIMEOUT)
            .await;
        let (status, bytes) = match sent {
            Ok(answer) => answer,
            Err(PostFault::Timeout) => {
                return Err(self.refusal(
                    Reason::DelegateTimeout,
                    &format!("{target} did not answer within 120s"),
                ));
            }
            Err(PostFault::Unreachable) => {
                return Err(
                    self.refusal(Reason::UpstreamFailed, "the delegate door did not answer")
                );
            }
        };
        if status != StatusCode::OK {
            let detail = format!("the delegate door answered HTTP {}", status.as_u16());
            return Err(self.refusal(Reason::UpstreamFailed, &detail));
        }
        let answer = object(&bytes, "the delegate door")
            .map_err(|detail| self.refusal(Reason::UpstreamFailed, &detail))?;
        let status = match answer.get("status").and_then(Value::as_str) {
            Some("ok") => DelegateStatus::Ok,
            Some("timeout") => DelegateStatus::Timeout,
            Some("failed") => DelegateStatus::Failed,
            Some(_) | None => {
                return Err(self.refusal(
                    Reason::UpstreamFailed,
                    "the delegate door sent no known status",
                ));
            }
        };
        let error = text(&answer, "error").filter(|error| !error.is_empty());
        match status {
            DelegateStatus::Ok => Ok(serde_json::json!({
                "untrusted": true,
                "source": format!("family:{target}"),
                "content": cap(&self.scrub(&text(&answer, "content").unwrap_or_default())),
            })),
            DelegateStatus::Timeout => Err(self.refusal(
                Reason::DelegateTimeout,
                &error.unwrap_or_else(|| format!("{target} did not answer in time")),
            )),
            DelegateStatus::Failed => Err(self.refusal(
                Reason::UpstreamFailed,
                &error.unwrap_or_else(|| format!("{target} did not answer")),
            )),
        }
    }

    /// Start one session in another family and answer with its ID.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] with the reason the door's error code maps to.
    pub async fn enqueue(&self, caller: &Family, call: &Enqueue) -> Result<Value, Refusal> {
        let id = mint()?;
        let body = DispatchBody {
            caller_family: caller.as_str(),
            target_family: call.family.as_str(),
            delegation_id: id.as_str(),
            chain: [caller.as_str(), call.family.as_str()],
            claimed_session_id: None,
            message: &call.message,
            idempotency_key: call.idempotency_key.as_deref(),
        };
        let answer = self.dispatch(DISPATCH_PATH, &body).await?;
        let session = text(&answer, "session_id")
            .filter(|session| !session.is_empty())
            .ok_or_else(|| {
                self.refusal(Reason::UpstreamFailed, "the dispatch door named no session")
            })?;
        Ok(serde_json::json!({
            "session": session,
            "family": call.family.as_str(),
            "status": text(&answer, "status").unwrap_or_default(),
            "created": answer.get("created") != Some(&Value::Bool(false)),
        }))
    }

    /// Read the jobs the caller enqueued, newest first.
    ///
    /// # Errors
    ///
    /// Returns a [`Refusal`] with the reason the door's error code maps to.
    pub async fn job_status(&self, caller: &Family, call: &JobStatus) -> Result<Value, Refusal> {
        let body = JobsBody {
            caller_family: caller.as_str(),
            session: call.session.as_deref(),
            since: call.since.as_deref(),
            limit: call.limit,
        };
        let mut answer = self.dispatch(JOBS_PATH, &body).await?;
        let Some(Value::Array(rows)) = answer.remove("jobs") else {
            return Err(self.refusal(Reason::UpstreamFailed, "the dispatch door sent no job list"));
        };
        let jobs: Vec<Value> = rows
            .into_iter()
            .take(MAX_JOBS)
            .filter(Value::is_object)
            .collect();
        Ok(serde_json::json!({ "jobs": jobs }))
    }

    /// One call of the dispatch door: the answer object, or the refusal its
    /// error body maps to.
    async fn dispatch(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<Map<String, Value>, Refusal> {
        let (status, bytes) = self
            .post(path, &self.dispatch_token, body, DISPATCH_TIMEOUT)
            .await
            .map_err(|_| self.refusal(Reason::UpstreamFailed, DISPATCH_SILENT))?;
        if status != StatusCode::OK {
            return Err(self.dispatch_refusal(status, &bytes));
        }
        object(&bytes, "the dispatch door")
            .map_err(|detail| self.refusal(Reason::UpstreamFailed, &detail))
    }

    /// The refusal of an error answer `{"error": {"code", "message"}}`. A
    /// code the table does not name is `upstream_failed`.
    fn dispatch_refusal(&self, status: StatusCode, bytes: &[u8]) -> Refusal {
        let error = object(bytes, "")
            .ok()
            .and_then(|mut body| match body.remove("error") {
                Some(Value::Object(error)) => Some(error),
                Some(_) | None => None,
            })
            .unwrap_or_default();
        let code = text(&error, "code").unwrap_or_default();
        let reason = match code.as_str() {
            "dispatch_not_declared" | "forbidden" | "family_unknown" | "family_invalid" => {
                Reason::ToolNotGranted
            }
            "bad_request" | "idempotency_mismatch" | "payload_too_large" => Reason::ArgValidation,
            "queue_full" => Reason::RateLimited,
            _ => {
                let detail = format!("the dispatch door answered HTTP {}", status.as_u16());
                return self.refusal(Reason::UpstreamFailed, &detail);
            }
        };
        let detail = text(&error, "message")
            .filter(|message| !message.is_empty())
            .unwrap_or(code);
        self.refusal(reason, &detail)
    }

    /// Send one `POST` with the bearer `token`, bounded by `timeout`, and
    /// read at most [`MAX_ANSWER_BYTES`] of the answer.
    async fn post(
        &self,
        path: &str,
        token: &DoorToken,
        body: &impl Serialize,
        timeout: Duration,
    ) -> Result<(StatusCode, Vec<u8>), PostFault> {
        let fault = |error: reqwest::Error| {
            if error.is_timeout() {
                PostFault::Timeout
            } else {
                PostFault::Unreachable
            }
        };
        let mut response = self
            .client
            .post(format!("{BASE_URL}{path}"))
            .bearer_auth(token.expose())
            .json(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(fault)?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(fault)? {
            if bytes.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(PostFault::Unreachable);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }

    /// A refusal whose detail holds no token (G9).
    fn refusal(&self, reason: Reason, detail: &str) -> Refusal {
        Refusal::new(reason, cap(&self.scrub(detail)))
    }

    /// `text` with each copy of either bearer blanked (G9).
    fn scrub(&self, text: &str) -> String {
        text.replace(self.delegate_token.expose(), "[redacted]")
            .replace(self.dispatch_token.expose(), "[redacted]")
    }
}

/// A new delegation ID, minted per call.
fn mint() -> Result<Ulid, Refusal> {
    Ulid::mint().map_err(|error| Refusal::new(Reason::UpstreamFailed, error.to_string()))
}

/// The answer as a JSON object, or the detail of why it is not one.
fn object(bytes: &[u8], door: &str) -> Result<Map<String, Value>, String> {
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(object)) => Ok(object),
        Ok(_) => Err(format!("{door} sent no object")),
        Err(_) => Err(format!("{door} sent no JSON")),
    }
}

/// One string field of an answer. A value of another type reads as absent.
fn text(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_owned)
}
