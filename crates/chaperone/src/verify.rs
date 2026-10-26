//! `chaperone verify` (`docs/design.md` 10). It answers whether the
//! installed chaperone works now. It reads both configuration files through
//! the strict reader and every cross-file rule, then asks the running front
//! door for `GET /healthz`. The address of the front door comes from
//! `--listen`, or from one key of an env file. It writes nothing and holds
//! no secret. A release
//! tool runs it after an install and reads only the exit code and the
//! report.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use chaperone_core::{INSTALL_FILE_CAP, POLICY_FILE_CAP};
use serde::Serialize;

use crate::admin::{self, ConfigFile};
use crate::env_file::{self, EnvKey};
use crate::files;

/// The longest the probe waits to connect, and then for each read or write.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The most bytes of the probe answer that the check reads. The status
/// line comes first.
const PROBE_CAP: u64 = 4096;

/// The name of the probe check.
const HEALTH_CHECK: &str = "healthz";

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

/// Where the probe finds the front door.
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    /// The address of `--listen`.
    Listen(SocketAddr),
    /// The value of `key` in the env file at `path`.
    EnvFile { path: &'a Path, key: &'a EnvKey },
}

/// Check `install.toml` and `policy.toml` in `config_dir` against the
/// plugins in `plugins_dir`, then probe the front door at `target`.
#[must_use]
pub fn run(config_dir: &Path, plugins_dir: &Path, target: Target<'_>) -> Report {
    let mut checks = vec![
        config_check(ConfigFile::Install, config_dir, plugins_dir),
        config_check(ConfigFile::Policy, config_dir, plugins_dir),
    ];
    match target {
        Target::Listen(listen) => checks.push(health_check(listen, &listen.to_string())),
        Target::EnvFile { path, key } => {
            let (check, listen) = env_check(path, key);
            checks.push(check);
            // The probe names the key, not the address, so nothing of the
            // file is printed.
            checks.push(match listen {
                Some(listen) => health_check(listen, &format!("the address of {key}")),
                None => Check {
                    name: HEALTH_CHECK,
                    ok: false,
                    detail: "no address to probe".to_owned(),
                },
            });
        }
    }
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

/// Read the front door address from the env file. The detail names the
/// key and never the value.
fn env_check(path: &Path, key: &EnvKey) -> (Check, Option<SocketAddr>) {
    let (ok, detail, listen) = match env_file::read_listen(path, key) {
        Ok(listen) => (true, format!("{key} holds a socket address"), Some(listen)),
        Err(error) => (false, error.to_string(), None),
    };
    let check = Check {
        name: "env-file",
        ok,
        detail,
    };
    (check, listen)
}

/// Probe the front door at `listen`. The detail names it as `shown`.
fn health_check(listen: SocketAddr, shown: &str) -> Check {
    let (ok, detail) = match probe(listen) {
        Ok(status) if status.starts_with(HEALTHY_STATUS) => (true, format!("{shown} answered 200")),
        Ok(status) => (false, format!("{shown} answered {}", status.trim_end())),
        Err(error) => (false, format!("{shown}: {error}")),
    };
    Check {
        name: HEALTH_CHECK,
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
