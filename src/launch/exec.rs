//! Finding Claude Code and the replacement itself.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{EnvPlan, Refusal};

/// The first `claude` on the search path that is an executable file.
pub(super) fn find_claude() -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH").ok_or_else(|| "PATH is not set".to_string())?;
    let names: Vec<String> = if cfg!(windows) {
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.CMD;.BAT".into());
        exts.split(';')
            .filter(|e| !e.is_empty())
            .map(|e| format!("claude{}", e.to_ascii_lowercase()))
            .collect()
    } else {
        vec!["claude".to_string()]
    };
    for dir in std::env::split_paths(&path) {
        for name in &names {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Ok(candidate);
            }
        }
    }
    Err("no `claude` on PATH".to_string())
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn command(claude: &Path, args: &[OsString], plan: &EnvPlan) -> Command {
    let mut command = Command::new(claude);
    command.args(args);
    for name in &plan.unset {
        command.env_remove(name);
    }
    for (name, value) in &plan.set {
        command.env(name, value);
    }
    command
}

/// On Unix the launcher's process *becomes* Claude Code, so its
/// exit code and signals are Claude Code's; `exec` returns only on failure.
#[cfg(unix)]
pub(super) fn exec(claude: &Path, args: &[OsString], plan: &EnvPlan) -> Result<i32, Refusal> {
    use std::os::unix::process::CommandExt;
    let error = command(claude, args, plan).exec();
    Err(Refusal::new(
        1,
        "cli_internal",
        format!("could not start {}: {error}", claude.display()),
    ))
}

/// Where no `exec` exists: wait for Claude Code and exit with its
/// status. (Console interrupts reach every process of the console group, so
/// Claude Code receives them directly.)
#[cfg(not(unix))]
pub(super) fn exec(claude: &Path, args: &[OsString], plan: &EnvPlan) -> Result<i32, Refusal> {
    let status = command(claude, args, plan).status().map_err(|error| {
        Refusal::new(
            1,
            "cli_internal",
            format!("could not start {}: {error}", claude.display()),
        )
    })?;
    Ok(status.code().unwrap_or(1))
}
