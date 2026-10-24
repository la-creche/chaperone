//! The default audit sink. It appends one JSON line per audit record to one
//! file and makes each line durable before it returns (G6). `docs/design.md`
//! 5.4 lists the records of each path. The file is created with mode 0600.
//! Times are RFC 3339 in UTC.
//!
//! Durability: each write ends with `sync_all`, which flushes the data and
//! the metadata. When `open` creates the file, it also syncs the parent
//! directory, so the new directory entry survives a crash (fsync(2)).

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
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
    /// Open `path` for append. Create it with mode 0600 if it is missing,
    /// and then sync the new file and its parent directory.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the file cannot be opened, created or
    /// synced.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let created = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(path);
        let file = match created {
            Ok(file) => {
                file.sync_all()?;
                sync_parent(path)?;
                file
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                OpenOptions::new().append(true).open(path)?
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            file: Mutex::new(file),
        })
    }
}

/// Sync the directory that holds `path`, so a new entry in it is durable.
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
    arguments_sha256: &'a str,
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
        AuditEvent::Decided(decision) => ("decided", AuditRecord::decision_code(decision)),
        AuditEvent::Ran { is_error } => ("ran", format!("is_error:{is_error}")),
        AuditEvent::Waiting(gate) => ("waiting", format!("gate:{gate}")),
        AuditEvent::Failed(fault) => ("failed", fault.code().to_owned()),
    }
}

impl AuditSink for JsonlAudit {
    fn write(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let (event, detail) = event_parts(record.event());
        let arguments_sha256 = record.arguments().to_hex();
        let line = Line {
            run: record.run().to_hex(),
            call: record.call().0,
            started: rfc3339(record.started_at().unix_millis())?,
            time: rfc3339(record.time().unix_millis())?,
            app: record.app().map(|app| app.as_str()),
            tool: record.tool().as_str(),
            arguments_sha256: &arguments_sha256,
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
    use std::os::unix::fs::PermissionsExt;

    use std::collections::BTreeMap;

    use chaperone_core::{
        AfterDecision, AppId, ArgumentsDigest, AuditTool, CallAudit, CallFault, CallNumber,
        Catalog, Decision, DenyReason, Found, InstallFile, Location, Manifest, PluginKey, Policy,
        RunId, Timestamp,
    };

    use super::*;

    fn empty_policy() -> Policy {
        let mut catalog = Catalog::new();
        for (name, kind, slot) in [
            ("mcp-http", "adapter", "front_door"),
            ("bearer", "decision", "identity"),
            ("secret-files", "adapter", "secret_source"),
            ("audit-jsonl", "adapter", "audit_sink"),
        ] {
            let text = format!(
                r#"{{"name":"{name}","version":"1","kind":"{kind}","slot":"{slot}","hooks":["{slot}"]}}"#
            );
            let manifest = Manifest::read(text.as_bytes()).unwrap();
            catalog.insert(
                PluginKey::from_manifest(&manifest),
                Found {
                    location: Location::Default,
                    manifest,
                },
            );
        }
        let manifest = Manifest::read(
            br#"{"name":"deny-all","version":"1","kind":"effect","slot":"approval_channel",
                "hooks":["approval"],"command":["deny-all"]}"#,
        )
        .unwrap();
        catalog.insert(
            PluginKey::from_manifest(&manifest),
            Found {
                location: Location::Default,
                manifest,
            },
        );
        let install = InstallFile::read(br#"{"version":1}"#).unwrap();
        let setup = chaperone_core::resolve(&install, &catalog).unwrap();
        Policy::load(br#"{"version":1}"#, &setup, &[]).unwrap()
    }

    const START: Timestamp = Timestamp::from_unix_millis(1_761_264_000_123);
    const END: Timestamp = Timestamp::from_unix_millis(1_761_264_060_123);

    fn audit(call: u64) -> CallAudit {
        CallAudit::new(
            RunId::from_bytes([7; 16]),
            CallNumber(call),
            START,
            Some(AppId::try_new("librechat").unwrap()),
            AuditTool::lookup("secret-looking-text", &empty_policy()),
            ArgumentsDigest::of(&BTreeMap::new()),
        )
    }

    fn decided(call: u64, decision: &Decision) -> AuditRecord {
        audit(call).decided(decision.clone(), START).0
    }

    fn allowed(call: u64) -> chaperone_core::AllowedCall {
        match audit(call).decided(Decision::Allow, START).1 {
            AfterDecision::Allowed(allowed) => allowed,
            AfterDecision::Denied(_) | AfterDecision::Gated(_) => panic!("an allow"),
        }
    }

    #[test]
    fn writes_one_line_per_record_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let sink = JsonlAudit::open(&path).unwrap();

        sink.write(&decided(1, &Decision::Allow)).unwrap();
        sink.write(&allowed(1).failed(CallFault::NotConnected, END))
            .unwrap();
        sink.write(&decided(2, &Decision::Deny(DenyReason::ToolNotGranted)))
            .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains(&format!(r#""run":"{}""#, "07".repeat(16))));
        assert!(lines[0].contains(r#""tool":"<unknown>""#));
        assert!(!text.contains("secret-looking-text"));
        assert!(
            lines[0].contains(r#""time":"2025-10-24T00:00:00.123Z""#),
            "{}",
            lines[0]
        );
        assert!(lines[1].contains(r#""event":"failed","detail":"not_connected""#));
        assert!(
            lines[1].contains(r#""started":"2025-10-24T00:00:00.123Z""#),
            "{}",
            lines[1]
        );
        assert!(
            lines[1].contains(r#""time":"2025-10-24T00:01:00.123Z""#),
            "{}",
            lines[1]
        );
        assert!(lines[2].contains(r#""detail":"deny:tool_not_granted""#));

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn creates_the_file_in_a_new_directory_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        assert!(!path.exists());
        let sink = JsonlAudit::open(&path).unwrap();
        assert!(path.exists());
        sink.write(&allowed(1).ran(false, END)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
    }

    #[test]
    fn appends_to_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        JsonlAudit::open(&path)
            .unwrap()
            .write(&allowed(1).ran(false, END))
            .unwrap();
        JsonlAudit::open(&path)
            .unwrap()
            .write(&allowed(2).ran(true, END))
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }
}
