//! `alias`: print — and only print — the one shell line
//! that makes `claude` run `jaynshare claude`, quoting the executable's absolute
//! path when it is not on the search path. No file is written.

use super::args::Shell;
use super::{Failure, Outcome};
use crate::launch::shell as sh;

pub(super) fn alias(shell: Option<Shell>) -> Outcome {
    let shell = match shell {
        Some(Shell::Sh) => sh::Shell::Sh,
        Some(Shell::Fish) => sh::Shell::Fish,
        Some(Shell::Powershell) => sh::Shell::Powershell,
        Some(Shell::Cmd) => sh::Shell::Cmd,
        None => sh::detect(),
    };

    let exe = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|e| {
            Failure::local(
                1,
                "cli_internal",
                format!("cannot locate this executable: {e}"),
            )
        })?;

    // On the search path there is a `jaynshare` that is this binary;
    // then the bare name is the program word.
    let name = if cfg!(windows) {
        "jaynshare.exe"
    } else {
        "jaynshare"
    };
    let on_path = std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|dir| dir.join(name).canonicalize().is_ok_and(|c| c == exe))
        })
        .unwrap_or(false);

    let path = exe.display().to_string();
    let program = if on_path {
        name.to_string()
    } else if shell == sh::Shell::Cmd {
        // cmd's doskey keeps the whole `claude=…` as one word; a plain pair
        // of quotes around the path is all it can parse.
        format!("\"{path}\"")
    } else {
        sh::quote(shell, &path)
    };

    let line = match shell {
        sh::Shell::Sh => format!(
            "alias claude={}",
            sh::quote(sh::Shell::Sh, &format!("{program} claude"))
        ),
        sh::Shell::Fish => {
            format!(
                "alias claude {}",
                sh::quote(sh::Shell::Fish, &format!("{program} claude"))
            )
        }
        sh::Shell::Powershell => format!("function claude {{ & {program} claude @args }}"),
        sh::Shell::Cmd => format!("doskey claude={program} claude $*"),
    };
    Ok((serde_json::Value::Null, line))
}
