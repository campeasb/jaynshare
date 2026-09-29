//! Platform default paths: the per-OS roots for the
//! configuration file, state and logs.

use std::path::PathBuf;

/// The credentials file lives under the *server's* home.
pub fn home() -> PathBuf {
    #[allow(deprecated)]
    std::env::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn config_file() -> PathBuf {
    config_root().join("config.toml")
}

pub fn state_file() -> PathBuf {
    state_root().join("state.json")
}

pub fn log_directory() -> PathBuf {
    if cfg!(target_os = "macos") {
        home().join("Library/Logs/Jaynshare")
    } else {
        state_root().join("log")
    }
}

/// The per-user configuration root on this platform.
pub fn config_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        env_dir("APPDATA").unwrap_or_else(home).join("Jaynshare")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support/Jaynshare")
    } else {
        env_dir("XDG_CONFIG_HOME")
            .unwrap_or_else(|| home().join(".config"))
            .join("jaynshare")
    }
}

fn state_root() -> PathBuf {
    if cfg!(target_os = "windows") {
        env_dir("LOCALAPPDATA")
            .unwrap_or_else(home)
            .join("Jaynshare")
    } else if cfg!(target_os = "macos") {
        home().join("Library/Application Support/Jaynshare")
    } else {
        env_dir("XDG_STATE_HOME")
            .unwrap_or_else(|| home().join(".local/state"))
            .join("jaynshare")
    }
}

/// The enrolled client's directory; its `client.toml` is what makes
/// a machine an engineer's.
pub fn client_directory() -> PathBuf {
    config_root().join("client")
}

/// The client executable's installed path. Windows keeps it out of
/// the roaming profile, under the per-user programs folder, while the installation's
/// files stay in `%APPDATA%`.
pub fn client_binary() -> PathBuf {
    if cfg!(target_os = "windows") {
        env_dir("LOCALAPPDATA")
            .unwrap_or_else(home)
            .join("Programs")
            .join("Jaynshare")
            .join("jaynshare.exe")
    } else {
        config_root().join("bin").join("jaynshare")
    }
}

/// The pinned release public key, installed once by the documented
/// install path (see `bundle::PinnedKey::load`).
pub fn release_key_file() -> PathBuf {
    config_root().join("release.pub")
}
