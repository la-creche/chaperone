//! `chaperone-as <user> <command> [args...]` starts one effect plugin as
//! its own OS user (`docs/design.md` 8). A step that fails writes one line
//! to stderr and exits 125. Stdout is the MCP channel of the plugin, so the
//! helper never writes it.

use std::convert::Infallible;
use std::process::ExitCode;

use chaperone_run_as::{REFUSED_EXIT, Refusal};

fn main() -> ExitCode {
    match run() {
        Ok(never) => match never {},
        Err(refusal) => {
            eprintln!("{}", refusal.line());
            ExitCode::from(REFUSED_EXIT)
        }
    }
}

/// Steps 1 to 6. It returns only to refuse. A success is an exec.
#[cfg(target_os = "linux")]
fn run() -> Result<Infallible, Refusal> {
    use std::os::unix::process::CommandExt;

    use chaperone_core::CHILD_ENV_VAR;
    use chaperone_run_as::{Target, check_status, child_env, parse_args, resolve};

    let launch = parse_args(std::env::args_os().skip(1))?;
    let env = child_env(std::env::var_os(CHILD_ENV_VAR).as_deref())?;
    let own = Target {
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
    };
    let target = resolve(&launch.user, &read("/etc/passwd")?, own)?;
    switch::become_user(target)?;
    check_status(&read("/proc/self/status")?, target)?;
    let error = std::process::Command::new(&launch.command)
        .args(&launch.args)
        .env_clear()
        .envs(&env)
        .exec();
    let command = launch.command.display();
    Err(Refusal::new(format!("cannot run {command}: {error}")))
}

#[cfg(target_os = "linux")]
fn read(path: &str) -> Result<String, Refusal> {
    std::fs::read_to_string(path)
        .map_err(|error| Refusal::new(format!("cannot read {path}: {error}")))
}

/// Steps 4 and 5 through the safe calls of `rustix`. The calls change the
/// calling thread, and the helper runs on one thread.
#[cfg(target_os = "linux")]
mod switch {
    use chaperone_run_as::{Refusal, Target};
    use rustix::thread::{self, CapabilitySet, CapabilitySets, Gid, Uid};

    fn cannot(step: &'static str) -> impl Fn(rustix::io::Errno) -> Refusal {
        move |error| Refusal::new(format!("cannot {step}: {error}"))
    }

    /// Every id the target's, then no capability and no way to gain one.
    pub(crate) fn become_user(target: Target) -> Result<(), Refusal> {
        let (uid, gid) = (Uid::from_raw(target.uid), Gid::from_raw(target.gid));
        thread::set_thread_groups(&[]).map_err(cannot("drop the groups"))?;
        thread::set_thread_res_gid(gid, gid, gid).map_err(cannot("set the group"))?;
        thread::set_thread_res_uid(uid, uid, uid).map_err(cannot("set the user"))?;
        thread::clear_ambient_capability_set().map_err(cannot("clear the ambient set"))?;
        let empty = CapabilitySets {
            effective: CapabilitySet::empty(),
            permitted: CapabilitySet::empty(),
            inheritable: CapabilitySet::empty(),
        };
        thread::set_capabilities(None, empty).map_err(cannot("clear the other sets"))?;
        thread::set_no_new_privs(true).map_err(cannot("set no_new_privs"))
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<Infallible, Refusal> {
    Err(Refusal::new("switching users needs Linux"))
}
