//! The default audit sink. It appends one JSON line per record to one file
//! and syncs the file before it returns (G6). The file is created with mode
//! 0600. Times are RFC 3339 in UTC.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;

use chaperone_core::{AuditError, AuditEvent, AuditRecord, AuditSink};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FILE_MODE: u32 = 0o600;

/// The JSONL audit sink.
#[derive(Debug)]
pub struct JsonlAudit {
    file: Mutex<File>,
}

impl JsonlAudit {
    /// Open `path` for append. Create it with mode 0600 if it is missing.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the file cannot be opened.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(FILE_MODE)
            .open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

/// One line of the audit file.
#[derive(Debug, Serialize)]
struct Line<'a> {
    call: u64,
    time: String,
    app: Option<&'a str>,
    tool: &'a str,
    arguments_sha256: &'a str,
    event: &'static str,
    detail: String,
}

fn rfc3339(millis: i64) -> Result<String, AuditError> {
    let nanos = i128::from(millis) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|error| AuditError(error.to_string()))?
        .format(&Rfc3339)
        .map_err(|error| AuditError(error.to_string()))
}

fn event_parts(event: &AuditEvent) -> (&'static str, String) {
    match event {
        AuditEvent::Decided(decision) => ("decided", AuditRecord::decision_code(decision)),
        AuditEvent::Ran { is_error } => ("ran", format!("is_error:{is_error}")),
        AuditEvent::Failed(fault) => ("failed", fault.code().to_owned()),
    }
}

impl AuditSink for JsonlAudit {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let (event, detail) = event_parts(&record.event);
        let line = Line {
            call: record.call.0,
            time: rfc3339(record.time.unix_millis())?,
            app: record.app.as_ref().map(|app| app.as_str()),
            tool: &record.tool,
            arguments_sha256: &record.arguments_sha256,
            event,
            detail,
        };
        let mut text =
            serde_json::to_string(&line).map_err(|error| AuditError(error.to_string()))?;
        text.push('\n');

        let mut file = self
            .file
            .lock()
            .map_err(|_| AuditError("the audit file lock is poisoned".to_owned()))?;
        file.write_all(text.as_bytes())
            .map_err(|error| AuditError(error.to_string()))?;
        file.sync_data()
            .map_err(|error| AuditError(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use chaperone_core::{AppId, CallFault, CallNumber, Decision, DenyReason, Timestamp};

    use super::*;

    fn record(call: u64, event: AuditEvent) -> AuditRecord {
        AuditRecord {
            call: CallNumber(call),
            time: Timestamp::from_unix_millis(1_761_264_000_123),
            app: Some(AppId::try_new("librechat").unwrap()),
            tool: "vikunja__list_tasks".to_owned(),
            arguments_sha256: "ab".repeat(32),
            event,
        }
    }

    #[test]
    fn writes_one_line_per_record_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let audit = JsonlAudit::open(&path).unwrap();

        audit
            .write(&record(1, AuditEvent::Decided(Decision::Allow)))
            .unwrap();
        audit
            .write(&record(
                2,
                AuditEvent::Decided(Decision::Deny(DenyReason::ToolNotGranted)),
            ))
            .unwrap();
        audit
            .write(&record(2, AuditEvent::Failed(CallFault::NotConnected)))
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(
            lines[0].contains(r#""time":"2025-10-24T00:00:00.123Z""#),
            "{}",
            lines[0]
        );
        assert!(lines[1].contains(r#""detail":"deny:tool_not_granted""#));
        assert!(lines[2].contains(r#""event":"failed","detail":"not_connected""#));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn appends_to_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        JsonlAudit::open(&path)
            .unwrap()
            .write(&record(1, AuditEvent::Ran { is_error: false }))
            .unwrap();
        JsonlAudit::open(&path)
            .unwrap()
            .write(&record(2, AuditEvent::Ran { is_error: true }))
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }
}
