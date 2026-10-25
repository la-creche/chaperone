//! The effect half of `attendance` (`docs/design.md` section 12). It serves
//! three tools and sends each call to a door of the session service, over
//! HTTP on a Unix socket. This module checks the arguments, builds the door
//! bodies and turns each door answer into the result the model sees. The
//! decision half fences the target family before a call reaches this
//! process.

pub mod door;

use serde::Serialize;
use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The `_meta` key that holds the app ID of a call (`docs/design.md` 7.7).
const APP_META_KEY: &str = "chaperone.app";

const MAX_MESSAGE_CHARS: usize = 65_536;
const MAX_ATTACHMENTS: usize = 16;
const MAX_ATTACHMENT_CHARS: usize = 255;
const MAX_IDEMPOTENCY_CHARS: usize = 128;
const MAX_LIMIT: i64 = 200;

/// The most characters of one string of a door answer that reach the model.
const MAX_TEXT_CHARS: usize = 64 * 1024;

/// The shortest door token, in bytes.
pub const MIN_TOKEN_BYTES: usize = 32;

/// A family name: `a-z`, then 1 to 30 of `a-z`, `0-9` and `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Family(String);

impl Family {
    /// `text` as a family name, or nothing when it breaks the rule.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (first, rest) = text.as_bytes().split_first()?;
        let valid = (1..=30).contains(&rest.len())
            && first.is_ascii_lowercase()
            && rest
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
        valid.then(|| Self(text.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One bearer of a door. Its `Debug` shows no value (G9).
pub struct DoorToken(String);

impl std::fmt::Debug for DoorToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DoorToken")
    }
}

impl DoorToken {
    /// `text` as a token, or nothing when it is shorter than
    /// [`MIN_TOKEN_BYTES`].
    #[must_use]
    pub fn parse(text: String) -> Option<Self> {
        (text.len() >= MIN_TOKEN_BYTES).then_some(Self(text))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

/// The reason name of a refused call, as the door contract names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    ToolNotGranted,
    ArgValidation,
    RateLimited,
    UpstreamFailed,
    DelegateTimeout,
}

impl Reason {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ToolNotGranted => "tool_not_granted",
            Self::ArgValidation => "arg_validation",
            Self::RateLimited => "rate_limited",
            Self::UpstreamFailed => "upstream_failed",
            Self::DelegateTimeout => "delegate_timeout",
        }
    }
}

/// A call that gives an error result: a reason and a detail text. The
/// detail never holds a token (G9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    reason: Reason,
    detail: String,
}

impl Refusal {
    #[must_use]
    pub fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The text of the error result: `{"ok": false, "reason", "detail"}`.
    #[must_use]
    pub fn text(&self) -> String {
        serde_json::json!({"ok": false, "reason": self.reason.code(), "detail": self.detail})
            .to_string()
    }
}

fn invalid(detail: &str) -> Refusal {
    Refusal::new(Reason::ArgValidation, detail)
}

/// The caller of a call: the app ID in `_meta`, read as a family name.
///
/// # Errors
///
/// Returns a [`Refusal`] when `_meta` holds no app ID that is a family name.
pub fn caller(meta: &Map<String, Value>) -> Result<Family, Refusal> {
    // DESIGN-QUESTION: docs/design.md 7.7 allows an app ID of 64 characters
    // and `_`. The reading: an app ID that is not a family name is refused.
    // A change maps app IDs to family names in the install arguments.
    meta.get(APP_META_KEY)
        .and_then(Value::as_str)
        .and_then(Family::parse)
        .ok_or_else(|| {
            Refusal::new(
                Reason::UpstreamFailed,
                "the call carries no app ID that is a family name",
            )
        })
}

/// One string argument, or nothing. A value of another type is refused.
fn text_arg(args: &mut Map<String, Value>, key: &str) -> Result<Option<String>, Refusal> {
    match args.remove(key) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(invalid("an argument that takes text holds another type")),
    }
}

fn family_arg(args: &mut Map<String, Value>) -> Result<Family, Refusal> {
    text_arg(args, "family")?
        .as_deref()
        .and_then(Family::parse)
        .ok_or_else(|| invalid("family is a-z, then 1 to 30 of a-z, 0-9 and -"))
}

fn message_arg(args: &mut Map<String, Value>) -> Result<String, Refusal> {
    text_arg(args, "message")?
        .filter(|text| (1..=MAX_MESSAGE_CHARS).contains(&text.chars().count()))
        .ok_or_else(|| invalid("message is 1 to 65536 characters"))
}

fn no_other_args(args: &Map<String, Value>) -> Result<(), Refusal> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(invalid("the call holds an argument the tool does not take"))
    }
}

/// The checked arguments of `invoke_agent`. The attachments are checked
/// and never forwarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeAgent {
    pub family: Family,
    pub message: String,
}

impl InvokeAgent {
    /// # Errors
    ///
    /// Returns an `arg_validation` [`Refusal`] that names the broken rule.
    pub fn parse(mut args: Map<String, Value>) -> Result<Self, Refusal> {
        let family = family_arg(&mut args)?;
        let message = message_arg(&mut args)?;
        if let Some(attachments) = args.remove("attachments") {
            let Value::Array(items) = attachments else {
                return Err(invalid("attachments is a list"));
            };
            let valid = items.len() <= MAX_ATTACHMENTS
                && items.iter().all(|item| {
                    item.as_str()
                        .is_some_and(|text| text.chars().count() <= MAX_ATTACHMENT_CHARS)
                });
            if !valid {
                return Err(invalid(
                    "attachments is up to 16 texts of up to 255 characters",
                ));
            }
        }
        no_other_args(&args)?;
        Ok(Self { family, message })
    }
}

/// The checked arguments of `enqueue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enqueue {
    pub family: Family,
    pub message: String,
    pub idempotency_key: Option<String>,
}

impl Enqueue {
    /// # Errors
    ///
    /// Returns an `arg_validation` [`Refusal`] that names the broken rule.
    pub fn parse(mut args: Map<String, Value>) -> Result<Self, Refusal> {
        let family = family_arg(&mut args)?;
        let message = message_arg(&mut args)?;
        let idempotency_key = text_arg(&mut args, "idempotency_key")?;
        if idempotency_key
            .as_ref()
            .is_some_and(|key| key.chars().count() > MAX_IDEMPOTENCY_CHARS)
        {
            return Err(invalid("idempotency_key is up to 128 characters"));
        }
        no_other_args(&args)?;
        Ok(Self {
            family,
            message,
            idempotency_key,
        })
    }
}

/// The checked arguments of `job_status`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JobStatus {
    pub session: Option<String>,
    pub since: Option<String>,
    pub limit: Option<i64>,
}

fn is_session(text: &str) -> bool {
    text.bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

impl JobStatus {
    /// # Errors
    ///
    /// Returns an `arg_validation` [`Refusal`] that names the broken rule.
    pub fn parse(mut args: Map<String, Value>) -> Result<Self, Refusal> {
        let session = text_arg(&mut args, "session")?;
        if session.as_deref().is_some_and(|text| !is_session(text)) {
            return Err(invalid("session is A-Z, a-z or 0-9, then those and . _ -"));
        }
        let since = text_arg(&mut args, "since")?;
        if since
            .as_deref()
            .is_some_and(|text| OffsetDateTime::parse(text, &Rfc3339).is_err())
        {
            return Err(invalid("since is an RFC 3339 date-time"));
        }
        let limit = match args.remove("limit") {
            None => None,
            Some(value) => Some(
                value
                    .as_i64()
                    .filter(|limit| (1..=MAX_LIMIT).contains(limit))
                    .ok_or_else(|| invalid("limit is an integer from 1 to 200"))?,
            ),
        };
        no_other_args(&args)?;
        Ok(Self {
            session,
            since,
            limit,
        })
    }
}

/// The body of `POST /delegate`.
#[derive(Debug, Serialize)]
pub struct DelegateBody<'a> {
    pub caller_family: &'a str,
    pub target_family: &'a str,
    pub delegation_id: &'a str,
    pub claimed_session_id: Option<&'a str>,
    pub message: &'a str,
}

/// The body of `POST /dispatch`. `chain` is the caller, then the target.
#[derive(Debug, Serialize)]
pub struct DispatchBody<'a> {
    pub caller_family: &'a str,
    pub target_family: &'a str,
    pub delegation_id: &'a str,
    pub chain: [&'a str; 2],
    pub claimed_session_id: Option<&'a str>,
    pub message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<&'a str>,
}

/// The body of `POST /dispatch/jobs`. An unset field is left out.
#[derive(Debug, Serialize)]
pub struct JobsBody<'a> {
    pub caller_family: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

/// `text` cut to [`MAX_TEXT_CHARS`] characters.
#[must_use]
pub fn cap(text: &str) -> String {
    text.chars().take(MAX_TEXT_CHARS).collect()
}
