//! Quoting for `env` and `alias`: one value, safe for the
//! named shell to evaluate, so the secret reaches the environment without
//! ever being a command-line word.

/// The shells `env` and `alias` support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Sh,
    Fish,
    Powershell,
    Cmd,
}

/// `value` as one word of `shell`, exactly as given: POSIX and fish single
/// quotes, PowerShell's verbatim string, and for cmd a double-quoted word
/// (`env` writes cmd's `set` lines itself, see `set_line`).
pub fn quote(shell: Shell, value: &str) -> String {
    match shell {
        // POSIX: nothing is special inside '…' but the quote itself.
        Shell::Sh => format!("'{}'", value.replace('\'', r"'\''")),
        // fish: inside '…' only \ and ' are escapes.
        Shell::Fish => format!("'{}'", value.replace('\\', r"\\").replace('\'', r"\'")),
        // PowerShell: a verbatim string doubles its quote.
        Shell::Powershell => format!("'{}'", value.replace('\'', "''")),
        // cmd has no escape inside "…"; a quote would end the word.
        Shell::Cmd => format!("\"{}\"", value.replace('"', "")),
    }
}

/// The line that sets `name` to `value` for the shell's session.
pub fn set_line(shell: Shell, name: &str, value: &str) -> String {
    match shell {
        Shell::Sh => format!("export {name}={}", quote(shell, value)),
        Shell::Fish => format!("set -gx {name} {}", quote(shell, value)),
        Shell::Powershell => format!("$env:{name} = {}", quote(shell, value)),
        // `set "NAME=value"`: the quotes keep & | < > literal. `%` would
        // still expand at a prompt, so it is doubled (literal in a script).
        Shell::Cmd => format!(
            "set \"{name}={}\"",
            value.replace('"', "").replace('%', "%%")
        ),
    }
}

/// The line that removes `name` from the shell's session.
pub fn unset_line(shell: Shell, name: &str) -> String {
    match shell {
        Shell::Sh => format!("unset {name}"),
        Shell::Fish => format!("set -e {name}"),
        Shell::Powershell => {
            format!("Remove-Item Env:{name} -ErrorAction SilentlyContinue")
        }
        Shell::Cmd => format!("set \"{name}=\""),
    }
}

/// The shell detected from the parent when `--shell` is omitted. Unix: the parent process's command name (`ps`), then `$SHELL`;
/// fish is fish and every other name is POSIX. Windows: PowerShell sets
/// `PSModulePath` and cmd sets `PROMPT`, so PowerShell is a module path
/// without a cmd prompt.
pub fn detect() -> Shell {
    #[cfg(windows)]
    {
        let powershell =
            std::env::var_os("PSModulePath").is_some() && std::env::var_os("PROMPT").is_none();
        if powershell {
            Shell::Powershell
        } else {
            Shell::Cmd
        }
    }
    #[cfg(unix)]
    {
        let parent = std::process::Command::new("ps")
            .args([
                "-o",
                "comm=",
                "-p",
                &std::os::unix::process::parent_id().to_string(),
            ])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|name| !name.is_empty());
        let name = parent
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_default();
        from_name(&name)
    }
}

/// The shell a process or path name names: its last path component, less a
/// leading `-` (a login shell).
#[cfg(any(unix, test))]
fn from_name(name: &str) -> Shell {
    let base = name
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .trim_start_matches('-');
    match base {
        "fish" => Shell::Fish,
        "pwsh" | "powershell" => Shell::Powershell,
        _ => Shell::Sh,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_shell_quotes_a_single_quote() {
        let value = "http://host/it's";
        assert_eq!(quote(Shell::Sh, value), r"'http://host/it'\''s'");
        assert_eq!(quote(Shell::Fish, value), r"'http://host/it\'s'");
        assert_eq!(quote(Shell::Powershell, value), "'http://host/it''s'");
        assert_eq!(
            set_line(Shell::Cmd, "ANTHROPIC_BASE_URL", value),
            "set \"ANTHROPIC_BASE_URL=http://host/it's\""
        );
    }

    #[test]
    fn set_and_unset_lines() {
        assert_eq!(set_line(Shell::Sh, "A", "b c"), "export A='b c'");
        assert_eq!(set_line(Shell::Fish, "A", r"b\c"), r"set -gx A 'b\\c'");
        assert_eq!(set_line(Shell::Powershell, "A", "b"), "$env:A = 'b'");
        assert_eq!(set_line(Shell::Cmd, "A", "50%"), "set \"A=50%%\"");
        assert_eq!(unset_line(Shell::Sh, "A"), "unset A");
        assert_eq!(unset_line(Shell::Fish, "A"), "set -e A");
        assert_eq!(unset_line(Shell::Cmd, "A"), "set \"A=\"");
    }

    #[test]
    fn names_map_to_shells() {
        assert_eq!(from_name("-zsh"), Shell::Sh);
        assert_eq!(from_name("/usr/local/bin/fish"), Shell::Fish);
        assert_eq!(from_name("pwsh"), Shell::Powershell);
        assert_eq!(from_name("bash"), Shell::Sh);
    }
}
