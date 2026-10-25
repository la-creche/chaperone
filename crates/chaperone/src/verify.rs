//! `chaperone verify` (`docs/design.md` 10). It answers whether the
//! installed chaperone works now. It reads both configuration files through
//! the strict reader and every cross-file rule, then asks the running front
//! door for `GET /healthz`. It writes nothing and holds no secret. A release
//! tool runs it after an install and reads only the exit code and the
//! report.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use chaperone_core::{INSTALL_FILE_CAP, POLICY_FILE_CAP};
use serde::Serialize;

use crate::admin::{self, ConfigFile};
use crate::files;

/// The longest the probe waits to connect, and then for each read or write.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes of the probe answer that the check reads. The status
/// line comes first.
const PROBE_CAP: u64 = 4096;

/// The status line of a healthy answer.
const HEALTHY_STATUS: &str = "HTTP/1.1 200 ";

/// One check and its result.
#[derive(Debug, Serialize)]
pub struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

/// Every check of one run, in a fixed order.
#[derive(Debug, Serialize)]
pub struct Report {
    ok: bool,
    checks: Vec<Check>,
}

impl Report {
    /// Whether every check passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.ok
    }

    /// One line per check: `PASS <name>: <detail>` or `FAIL <name>: <detail>`.
    #[must_use]
    pub fn lines(&self) -> String {
        let mut text = String::new();
        for check in &self.checks {
            let word = if check.ok { "PASS" } else { "FAIL" };
            text.push_str(&format!("{word} {}: {}\n", check.name, check.detail));
        }
        text
    }

    /// The report as one JSON object: `ok`, then `checks`, each with
    /// `name`, `ok` and `detail`.
    #[must_use]
    pub fn json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| r#"{"ok":false,"checks":[]}"#.to_owned())
    }
}

/// Check `install.toml` and `policy.toml` in `config_dir` against the
/// plugins in `plugins_dir`, then probe the front door at `listen`.
#[must_use]
pub fn run(config_dir: &Path, plugins_dir: &Path, listen: SocketAddr) -> Report {
    let checks = vec![
        config_check(ConfigFile::Install, config_dir, plugins_dir),
        config_check(ConfigFile::Policy, config_dir, plugins_dir),
        health_check(listen),
    ];
    Report {
        ok: checks.iter().all(|check| check.ok),
        checks,
    }
}

fn config_check(file: ConfigFile, config_dir: &Path, plugins_dir: &Path) -> Check {
    let cap = match file {
        ConfigFile::Install => INSTALL_FILE_CAP,
        ConfigFile::Policy => POLICY_FILE_CAP,
    };
    let checked = files::read_capped(&config_dir.join(file.name()), cap)
        .map_err(admin::CheckError::from)
        .and_then(|bytes| admin::check(file, &bytes, config_dir, plugins_dir));
    let (ok, detail) = match checked {
        Ok(()) => (true, "ok".to_owned()),
        Err(error) => (false, error.to_string()),
    };
    Check {
        name: file.name(),
        ok,
        detail,
    }
}

fn health_check(listen: SocketAddr) -> Check {
    let (ok, detail) = match probe(listen) {
        Ok(status) if status.starts_with(HEALTHY_STATUS) => {
            (true, format!("{listen} answered 200"))
        }
        Ok(status) => (false, format!("{listen} answered {}", status.trim_end())),
        Err(error) => (false, format!("{listen}: {error}")),
    };
    Check {
        name: "healthz",
        ok,
        detail,
    }
}

/// The status line of `GET /healthz` at `listen`.
fn probe(listen: SocketAddr) -> std::io::Result<String> {
    let mut stream = TcpStream::connect_timeout(&listen, PROBE_TIMEOUT)?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT))?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT))?;
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {listen}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut answer = Vec::new();
    stream.take(PROBE_CAP).read_to_end(&mut answer)?;
    let text = String::from_utf8_lossy(&answer);
    Ok(text.lines().next().unwrap_or_default().to_owned())
}
