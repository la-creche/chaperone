//! The steps of `chaperone-as` that need no privilege (`docs/design.md`
//! 8). `src/main.rs` does the switch and the exec.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use chaperone_core::strict::{self, ByteCap};
use chaperone_core::{CHILD_ENV_VAR, PluginUser};

/// The exit code of every refusal. `env(1)` uses it for a failure of the
/// launcher itself, so it never reads as the exit of the plugin.
pub const REFUSED_EXIT: u8 = 125;

const USAGE: &str = "usage: chaperone-as mcp-<name> /absolute/command [args...]";
const CHILD_ENV_CAP: ByteCap = ByteCap::new(256 * 1024);
const SHOWN_MAX: usize = 80;

/// One reason the helper stops. It never holds a value of the child
/// environment, because a value can be a secret (G9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(String);

impl Refusal {
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }

    /// The one stderr line of the refusal.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "chaperone-as: refused: {}",
            self.0.replace(['\n', '\r'], " ")
        )
    }
}

/// The user, the command and its arguments.
#[derive(Debug)]
pub struct Launch {
    pub user: PluginUser,
    pub command: PathBuf,
    pub args: Vec<OsString>,
}

/// The ids to switch to. Neither is root's or the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub uid: u32,
    pub gid: u32,
}

/// A short, quoted copy of an argument, so a refusal stays one line.
fn shown(text: &OsStr) -> String {
    let text: String = text.to_string_lossy().chars().take(SHOWN_MAX).collect();
    format!("{text:?}")
}

/// Step 1: a plugin user, an absolute command, then its arguments. The
/// command is not looked up on `PATH`, because that `PATH` is chaperone's.
///
/// # Errors
///
/// Returns a [`Refusal`] that names the broken rule.
pub fn parse_args(argv: impl IntoIterator<Item = OsString>) -> Result<Launch, Refusal> {
    let mut argv = argv.into_iter();
    let (Some(user), Some(command)) = (argv.next(), argv.next()) else {
        return Err(Refusal::new(USAGE));
    };
    let user = user
        .to_str()
        .and_then(|text| PluginUser::try_new(text).ok())
        .ok_or_else(|| Refusal::new(format!("{} is not an mcp-<name> user", shown(&user))))?;
    let command = PathBuf::from(command);
    if !command.is_absolute() {
        let shown = shown(command.as_os_str());
        return Err(Refusal::new(format!("{shown} is not an absolute path")));
    }
    let args = argv.collect();
    Ok(Launch {
        user,
        command,
        args,
    })
}

/// Step 2: the environment of the plugin, from the one variable.
///
/// # Errors
///
/// Returns a [`Refusal`] when the variable is missing or is not a JSON
/// object of strings that `execve` can carry.
pub fn child_env(raw: Option<&OsStr>) -> Result<BTreeMap<String, String>, Refusal> {
    let refused = || Refusal::new(format!("{CHILD_ENV_VAR} is not a JSON object of strings"));
    let text = raw.and_then(OsStr::to_str).ok_or_else(refused)?;
    let env: BTreeMap<String, String> =
        strict::read(text.as_bytes(), CHILD_ENV_CAP).map_err(|_| refused())?;
    let carried = |(name, value): (&String, &String)| {
        !name.is_empty() && !name.contains(['=', '\0']) && !value.contains('\0')
    };
    if !env.iter().all(carried) {
        return Err(refused());
    }
    Ok(env)
}

/// Step 3: the ids of `user` from the text of `/etc/passwd`. Root's ids
/// and the caller's ids are refused, whatever the line says.
///
/// # Errors
///
/// Returns a [`Refusal`] for a user that is not there exactly once, a
/// line that does not read, or a refused id.
pub fn resolve(user: &PluginUser, passwd: &str, own: Target) -> Result<Target, Refusal> {
    let mut lines = passwd
        .lines()
        .filter(|line| line.split(':').next() == Some(user.as_str()));
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(Refusal::new(format!("{user} is not once in /etc/passwd")));
    };
    let fields: Vec<&str> = line.split(':').collect();
    let id = |index: usize| {
        fields
            .get(index)
            .and_then(|field| field.parse::<u32>().ok())
    };
    let (Some(uid), Some(gid)) = (id(2), id(3)) else {
        return Err(Refusal::new(format!(
            "the passwd line of {user} does not read"
        )));
    };
    let refused = [0, u32::MAX, own.uid].contains(&uid) || [0, u32::MAX, own.gid].contains(&gid);
    if refused {
        let text = format!("{user} is uid {uid} gid {gid}, the ids of root or of chaperone");
        return Err(Refusal::new(text));
    }
    Ok(Target { uid, gid })
}

/// Step 5: the view of the kernel after the drop. A field the kernel did
/// not print is a refusal, not a zero.
///
/// # Errors
///
/// Returns a [`Refusal`] that names the first field that is not as wanted.
pub fn check_status(status: &str, target: Target) -> Result<(), Refusal> {
    let fields: BTreeMap<&str, Vec<&str>> = status
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key, value.split_whitespace().collect()))
        .collect();
    let (uid, gid) = (target.uid.to_string(), target.gid.to_string());
    let wanted: [(&str, Vec<&str>); 5] = [
        ("Uid", vec![&uid; 4]),
        ("Gid", vec![&gid; 4]),
        ("Groups", Vec::new()),
        ("NoNewPrivs", vec!["1"]),
        // The calls of step 4 change one thread, so the helper has one.
        ("Threads", vec!["1"]),
    ];
    let refused = |field: &str| Refusal::new(format!("the switch did not take: {field}"));
    for (field, want) in wanted {
        if fields.get(field) != Some(&want) {
            return Err(refused(field));
        }
    }
    let zero =
        |value: &Vec<&str>| matches!(value[..], [hex] if u64::from_str_radix(hex, 16) == Ok(0));
    for field in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
        if !fields.get(field).is_some_and(zero) {
            return Err(refused(field));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWN: Target = Target { uid: 990, gid: 990 };
    const PASSWD: &str = "root:x:0:0::/root:/bin/sh\nmcp-ha:x:991:991::/:/bin/false\n\
        mcp-root:x:0:992::/:/bin/false\nmcp-self:x:993:990::/:/bin/false\n\
        mcp-two:x:994:994::/:/bin/false\nmcp-two:x:995:995::/:/bin/false\n";

    fn user(text: &str) -> PluginUser {
        PluginUser::try_new(text).unwrap()
    }

    #[test]
    fn step_2_shows_no_value() {
        let env = child_env(Some(OsStr::new(r#"{"T":"tok-123"}"#))).unwrap();
        assert_eq!(env["T"], "tok-123");
        assert!(child_env(None).is_err());
        for bad in [
            r#"["tok-123"]"#,
            r#"{"T=":"tok-123"}"#,
            r#"{"T":"x","T":"tok-123"}"#,
        ] {
            let refusal = child_env(Some(OsStr::new(bad))).unwrap_err();
            assert!(!refusal.line().contains("tok-123"), "{bad}");
        }
    }

    #[test]
    fn step_3_refuses_root_the_caller_and_an_unclear_user() {
        let ha = Target { uid: 991, gid: 991 };
        assert_eq!(resolve(&user("mcp-ha"), PASSWD, OWN), Ok(ha));
        for name in ["mcp-root", "mcp-self", "mcp-two", "mcp-nobody"] {
            assert!(resolve(&user(name), PASSWD, OWN).is_err(), "{name}");
        }
        assert!(resolve(&user("mcp-ha"), PASSWD, ha).is_err());
    }

    #[test]
    fn step_5_needs_every_field_as_wanted() {
        let zero = "0000000000000000";
        let good = format!(
            "Uid:\t991\t991\t991\t991\nGid:\t991\t991\t991\t991\nGroups:\t\nNoNewPrivs:\t1\n\
             Threads:\t1\nCapInh:\t{zero}\nCapPrm:\t{zero}\nCapEff:\t{zero}\nCapAmb:\t{zero}\n"
        );
        let target = Target { uid: 991, gid: 991 };
        assert_eq!(check_status(&good, target), Ok(()));
        for (from, to) in [
            ("CapEff:\t0000000000000000", "CapEff:\t00000000000000c0"),
            ("Groups:\t", "Groups:\t990"),
            ("Threads:\t1", "Threads:\t2"),
            ("NoNewPrivs:\t1\n", ""),
            ("Uid:\t991\t991", "Uid:\t991\t990"),
        ] {
            assert!(
                check_status(&good.replace(from, to), target).is_err(),
                "{to}"
            );
        }
    }
}
