//! The client of the chaperone admin socket (`docs/design.md` 10): HTTP/1.1
//! over a Unix socket, one request per connection. The editor checks
//! nothing itself. Every check goes through here.

use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The most of an answer the client reads, in bytes.
const ANSWER_CAP: usize = 8 * 1024 * 1024;

/// Why the admin socket gave no usable answer.
#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    #[error("cannot reach the admin socket {}: {error}", path.display())]
    Connect {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("the admin socket closed the connection: {0}")]
    Io(#[from] std::io::Error),
    #[error("the admin socket sent no HTTP answer")]
    NoAnswer,
    #[error("the admin socket sent an answer that is not JSON")]
    NotJson,
}

/// One answer of the admin socket.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub body: serde_json::Value,
}

/// The admin socket of one chaperone deployment.
#[derive(Debug, Clone)]
pub struct AdminSocket {
    path: PathBuf,
}

impl AdminSocket {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// `GET /schema`.
    ///
    /// # Errors
    ///
    /// Returns a [`SocketError`] when the socket gives no usable answer.
    pub async fn schema(&self) -> Result<Answer, SocketError> {
        self.request("GET", "/schema", None).await
    }

    /// `POST /check` with the candidate `content` of `file`.
    ///
    /// # Errors
    ///
    /// Returns a [`SocketError`] when the socket gives no usable answer.
    pub async fn check(&self, file: &str, content: &str) -> Result<Answer, SocketError> {
        let body = serde_json::json!({ "file": file, "content": content });
        self.request("POST", "/check", Some(&body)).await
    }

    /// `POST /token` for `app`.
    ///
    /// # Errors
    ///
    /// Returns a [`SocketError`] when the socket gives no usable answer.
    pub async fn token(&self, app: &str) -> Result<Answer, SocketError> {
        let body = serde_json::json!({ "app": app });
        self.request("POST", "/token", Some(&body)).await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<Answer, SocketError> {
        let mut stream =
            UnixStream::connect(&self.path)
                .await
                .map_err(|error| SocketError::Connect {
                    path: self.path.clone(),
                    error,
                })?;
        let body = body.map(serde_json::Value::to_string).unwrap_or_default();
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: chaperone\r\nConnection: close\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        // The answer asks for `Connection: close`, so the socket ends the
        // stream after the answer. A half-close from this side would end
        // it before the answer.
        let mut raw = Vec::new();
        stream.take(ANSWER_CAP as u64).read_to_end(&mut raw).await?;
        parse_answer(&raw)
    }
}

/// Split one HTTP/1.1 answer into its status and its JSON body.
fn parse_answer(raw: &[u8]) -> Result<Answer, SocketError> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or(SocketError::NoAnswer)?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(SocketError::NoAnswer)?;
    let chunked = head.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    });
    let body = if chunked {
        dechunk(body)
    } else {
        body.to_owned()
    };
    let body = serde_json::from_str(&body).map_err(|_| SocketError::NotJson)?;
    Ok(Answer { status, body })
}

/// Join the chunks of a chunked body.
fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let Some((size, after)) = rest.split_once("\r\n") else {
            return out;
        };
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            return out;
        };
        if size == 0 || after.len() < size {
            return out;
        }
        out.push_str(&after[..size]);
        rest = after[size..].strip_prefix("\r\n").unwrap_or("");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_is_split_into_status_and_json() {
        let raw = b"HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\n\r\n{\"ok\":false}";
        let answer = parse_answer(raw).unwrap();
        assert_eq!(answer.status, 422);
        assert_eq!(answer.body["ok"], false);
    }

    #[test]
    fn a_chunked_answer_is_joined() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n{\"ok\":\r\n5\r\ntrue}\r\n0\r\n\r\n";
        let answer = parse_answer(raw).unwrap();
        assert_eq!(answer.body["ok"], true);
    }

    #[test]
    fn no_head_or_no_json_is_an_error() {
        assert!(matches!(
            parse_answer(b"nothing"),
            Err(SocketError::NoAnswer)
        ));
        assert!(matches!(
            parse_answer(b"HTTP/1.1 200 OK\r\n\r\n<html>"),
            Err(SocketError::NotJson)
        ));
    }
}
