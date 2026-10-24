//! The default audit sink. It appends one JSON line per audit record to one
//! file and makes each line durable before it returns (G6). `docs/design.md`
//! section 5.4 lists the records of each call path.
//!
//! Each write ends with `sync_all`. A new file and its parent directory are
//! also synced, so the new directory entry survives a crash.
//!
//! The sink refuses an unsafe audit path. It refuses a symbolic link, a
//! file that is not a regular file, and a file with a mode other than 0600.
//! A link could send the records elsewhere. A wider mode would let another
//! OS user read or change them.

use std::fs::{File, FileType, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

use chaperone_core::{AuditError, AuditEvent, AuditRecord, AuditSink};
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FILE_MODE: u32 = 0o600;
const MODE_BITS: u32 = 0o777;

/// Why the audit file cannot be used. chaperone then refuses to start (G6).
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("the audit file could not be opened or synced: {0}")]
    Io(#[from] std::io::Error),
    #[error("the audit path is a symbolic link")]
    Link,
    #[error("the audit path is not a regular file")]
    NotRegular,
    #[error("the audit file has mode {found:o}, not {FILE_MODE:o}")]
    Mode { found: u32 },
}

#[derive(Debug)]
pub struct JsonlAudit {
    file: Mutex<File>,
}

impl JsonlAudit {
    /// Open `path` for append. Create it with mode 0600 if it is missing.
    /// Refuse a link, a file that is not regular and a file with another
    /// mode. Sync a new file and its parent directory before return.
    ///
    /// # Errors
    ///
    /// Returns an [`OpenError`] when the path is unsafe or the I/O fails.
    pub fn open(path: &Path) -> Result<Self, OpenError> {
        let file = open_no_follow(path)?;
        check_file(&file)?;
        file.sync_all()?;
        sync_parent(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

/// Open `path` for append without following a final symbolic link. Create
/// the file with mode 0600 when it is missing.
fn open_no_follow(path: &Path) -> Result<File, OpenError> {
    let created = OpenOptions::new()
        .append(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path);
    let existing = match created {
        Ok(file) => return Ok(file),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path),
        Err(error) => return Err(OpenError::Io(error)),
    };
    match existing {
        Ok(file) => Ok(file),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => Err(OpenError::Link),
        Err(error) => Err(OpenError::Io(error)),
    }
}

/// Check the opened file, not the path. A file swapped in after the open
/// is checked too.
fn check_file(file: &File) -> Result<(), OpenError> {
    let metadata = file.metadata()?;
    if !FileType::is_file(&metadata.file_type()) {
        return Err(OpenError::NotRegular);
    }
    let found = metadata.permissions().mode() & MODE_BITS;
    if found != FILE_MODE {
        return Err(OpenError::Mode { found });
    }
    Ok(())
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        Some(_) | None => Path::new("."),
    };
    File::open(parent)?.sync_all()
}

/// One line of the audit file.
#[derive(Debug, Serialize)]
struct Line<'a> {
    run: String,
    call: u64,
    started: String,
    time: String,
    app: Option<&'a str>,
    tool: &'a str,
    arguments_sha256: String,
    event: &'static str,
    detail: String,
}

fn rfc3339(millis: i64) -> Result<String, AuditError> {
    let nanos = i128::from(millis) * 1_000_000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|_| AuditError::Encode)?
        .format(&Rfc3339)
        .map_err(|_| AuditError::Encode)
}

fn event_parts(event: &AuditEvent) -> (&'static str, String) {
    match event {
        AuditEvent::Decided(decision) => ("decided", decision.code()),
        AuditEvent::Ran { is_error } => ("ran", format!("is_error:{is_error}")),
        AuditEvent::Waiting(gate) => ("waiting", format!("gate:{gate}")),
        AuditEvent::Failed(fault) => ("failed", fault.code().to_owned()),
    }
}

impl AuditSink for JsonlAudit {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let (event, detail) = event_parts(record.event());
        let line = Line {
            run: record.run().to_hex(),
            call: record.call().get(),
            started: rfc3339(record.started_at().unix_millis())?,
            time: rfc3339(record.time().unix_millis())?,
            app: record.app().map(|app| app.as_str()),
            tool: record.tool().as_str(),
            arguments_sha256: record.arguments().to_hex(),
            event,
            detail,
        };
        let mut text = serde_json::to_string(&line).map_err(|_| AuditError::Encode)?;
        text.push('\n');

        let mut file = self.file.lock().map_err(|_| AuditError::LockPoisoned)?;
        file.write_all(text.as_bytes())
            .map_err(|error| AuditError::Io(error.kind()))?;
        file.sync_all()
            .map_err(|error| AuditError::Io(error.kind()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use chaperone_core::{
        AfterDecision, AppId, ArgumentsDigest, AuditApp, AuditTool, CallAudit, CallFault,
        CallNumber, Decision, DenyReason, RunId, Timestamp,
    };

    use super::*;

    const START: Timestamp = Timestamp::from_unix_millis(1_761_264_000_123);
    const END: Timestamp = Timestamp::from_unix_millis(1_761_264_060_123);

    fn audit(call: CallNumber) -> CallAudit {
        CallAudit::new(
            RunId::from_bytes([7; 16]),
            call,
            START,
            AuditApp::lookup(Some(&AppId::try_new("librechat").unwrap()), None),
            AuditTool::lookup("token-looking-text", None),
            ArgumentsDigest::of(&BTreeMap::new()),
        )
    }

    /// Write the decision record of an allow and return the next state.
    fn allowed(call: CallNumber, sink: &JsonlAudit) -> chaperone_core::AllowedCall {
        match audit(call).decided(Decision::Allow, START, sink).unwrap() {
            AfterDecision::Allowed(allowed) => allowed,
            AfterDecision::Denied(_) | AfterDecision::Gated(_) => panic!("an allow"),
        }
    }

    #[test]
    fn writes_safe_records_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlAudit::open(&path).unwrap();
        let first = CallNumber::FIRST;
        let second = first.checked_next().unwrap();

        allowed(first, &sink)
            .failed(CallFault::NotConnected, END, &sink)
            .unwrap();
        let denied = audit(second)
            .decided(Decision::Deny(DenyReason::ToolNotGranted), START, &sink)
            .unwrap();
        assert!(matches!(denied, AfterDecision::Denied(_)));

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains(&format!(r#""run":"{}""#, "07".repeat(16))));
        assert!(lines[0].contains(r#""tool":"<unknown>""#));
        assert!(!text.contains("token-looking-text"));
        assert!(lines[0].contains(r#""time":"2025-10-24T00:00:00.123Z""#));
        assert!(lines[1].contains(r#""event":"failed","detail":"not_connected""#));
        assert!(lines[1].contains(r#""started":"2025-10-24T00:00:00.123Z""#));
        assert!(lines[1].contains(r#""time":"2025-10-24T00:01:00.123Z""#));
        assert!(lines[2].contains(r#""detail":"deny:tool_not_granted""#));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn refuses_a_symbolic_link() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere.jsonl");
        std::fs::write(&target, b"").unwrap();
        let link = dir.path().join("audit.jsonl");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(JsonlAudit::open(&link), Err(OpenError::Link)));
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 0);
    }

    #[test]
    fn refuses_a_file_with_a_wider_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            JsonlAudit::open(&path),
            Err(OpenError::Mode { found: 0o644 })
        ));
    }

    #[test]
    fn refuses_a_path_that_is_not_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(JsonlAudit::open(dir.path()).is_err());
    }

    #[test]
    fn creates_and_then_appends_to_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        assert!(!path.exists());
        let first = CallNumber::FIRST;
        let second = first.checked_next().unwrap();

        let sink = JsonlAudit::open(&path).unwrap();
        allowed(first, &sink).ran(false, END, &sink).unwrap();
        drop(sink);
        let sink = JsonlAudit::open(&path).unwrap();
        allowed(second, &sink).ran(true, END, &sink).unwrap();

        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 4);
    }
}
