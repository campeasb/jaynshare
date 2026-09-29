//! The Linux release binary for the tests that run the product inside a
//! container: built once per suite run in `rust:1.95-alpine` for the Docker
//! VM's own architecture (`aarch64-unknown-linux-musl` on Apple silicon),
//! with its own target directory `target/linux-musl`, or taken as given from
//! `JAYNSHARE_LINUX_BIN` (e.g. `tools/release/cross.sh`'s output).
//!
//! A test that needs it calls [`docker_available`] first and skips
//! explicitly when there is no daemon; a failed build is a failure.
#![allow(dead_code)] // the real-Docker tests and LinuxBox call these

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// `docker <args>` with standard input closed; `Err` when it cannot start.
pub(crate) fn docker(args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("docker: {e}"))
}

/// A Docker daemon that runs a container: `docker info` answers within 20
/// seconds and `docker run --rm alpine:3 true` exits 0 within 120 (a daemon
/// that answers but never starts a container is as absent as none). Asked
/// once per suite run.
pub(crate) fn docker_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        within(&["info", "--format", "{{.ServerVersion}}"], 20)
            && within(&["run", "--rm", "alpine:3", "true"], 120)
    })
}

/// `docker <args>` exits 0 within `seconds`; killed and `false` otherwise.
fn within(args: &[&str], seconds: u64) -> bool {
    let Ok(mut child) = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// The daemon's platform and the matching musl target:
/// `("linux/arm64", "aarch64-unknown-linux-musl")` or the amd64 pair.
pub(crate) fn docker_platform() -> Result<(&'static str, &'static str), String> {
    let output = docker(&["info", "--format", "{{.Architecture}}"])?;
    match String::from_utf8_lossy(&output.stdout).trim() {
        "aarch64" | "arm64" => Ok(("linux/arm64", "aarch64-unknown-linux-musl")),
        "x86_64" | "amd64" => Ok(("linux/amd64", "x86_64-unknown-linux-musl")),
        other => Err(format!("docker info: unsupported architecture {other:?}")),
    }
}

/// The repository root (the acceptance crate is the product crate).
fn repository() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The commit the binary reports: this checkout's `HEAD`, since the
/// build container has no `git`.
pub(crate) fn head_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "0".repeat(40))
}

/// The musl `jaynshare` for the daemon's architecture: `JAYNSHARE_LINUX_BIN`
/// when set, else built once per suite run (incremental across runs; the
/// crate registry is the named volume `jaynshare-acceptance-cargo`).
pub(crate) fn linux_binary() -> Result<PathBuf, String> {
    static BINARY: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            if let Some(given) = std::env::var_os("JAYNSHARE_LINUX_BIN") {
                let given = PathBuf::from(given);
                return if given.is_file() {
                    Ok(given)
                } else {
                    Err(format!("JAYNSHARE_LINUX_BIN: {} is not a file", given.display()))
                };
            }
            let (platform, target) = docker_platform()?;
            let target_dir = repository().join("target").join("linux-musl");
            std::fs::create_dir_all(&target_dir)
                .map_err(|e| format!("{}: {e}", target_dir.display()))?;
            let build = format!(
                "apk add --no-cache musl-dev >/dev/null && \
                 cargo build --release --locked --target {target} --target-dir /target --bin jaynshare"
            );
            let output = docker(&[
                "run",
                "--rm",
                "--platform",
                platform,
                "-v",
                &format!("{}:/src:ro", repository().display()),
                "-v",
                &format!("{}:/target", target_dir.display()),
                "-v",
                "jaynshare-acceptance-cargo:/usr/local/cargo/registry",
                "-e",
                &format!("JAYNSHARE_COMMIT={}", head_commit()),
                "-e",
                "CARGO_TERM_COLOR=never",
                "-w",
                "/src",
                "rust:1.95-alpine",
                "sh",
                "-c",
                &build,
            ])?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
                return Err(format!(
                    "the musl build failed ({}):\n{}",
                    output.status,
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                ));
            }
            let binary = target_dir.join(target).join("release").join("jaynshare");
            if binary.is_file() {
                Ok(binary)
            } else {
                Err(format!("the musl build wrote no {}", binary.display()))
            }
        })
        .clone()
}

/// The platform image of: this repository's `Dockerfile` built once
/// per suite run with the musl binary of [`linux_binary`] as the `bin` build
/// context (only that directory — the root context carries `LICENSE` and
/// `NOTICE.md` alone), loaded into the daemon as the local tag
/// `jaynshare-acceptance:platform`. `Err` with the build's last 20 stderr
/// lines when the build fails.
pub(crate) fn platform_image() -> Result<String, String> {
    static IMAGE: OnceLock<Result<String, String>> = OnceLock::new();
    IMAGE
        .get_or_init(|| {
            const TAG: &str = "jaynshare-acceptance:platform";
            let binary = linux_binary()?;
            let context = repository().join("target/linux-musl/image-bin");
            std::fs::create_dir_all(&context).map_err(|e| format!("{}: {e}", context.display()))?;
            let (platform, _) = docker_platform()?;
            let staged = context
                .join(platform.split_once('/').expect("os/arch").1)
                .join("jaynshare");
            std::fs::create_dir_all(staged.parent().expect("arch dir"))
                .map_err(|e| format!("{}: {e}", context.display()))?;
            std::fs::copy(&binary, &staged).map_err(|e| format!("{}: {e}", staged.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
                    .map_err(|e| format!("chmod {}: {e}", staged.display()))?;
            }
            let output = docker(&[
                "buildx",
                "build",
                "--load",
                "--platform",
                platform,
                "--provenance=false",
                "--sbom=false",
                "--build-context",
                &format!("bin={}", context.display()),
                "--build-arg",
                &format!("VERSION={}", env!("CARGO_PKG_VERSION")),
                "--build-arg",
                &format!("COMMIT={}", head_commit()),
                "-t",
                TAG,
                "-f",
                &repository().join("Dockerfile").display().to_string(),
                &repository().display().to_string(),
            ])?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
                return Err(format!(
                    "the platform image build failed ({}):\n{}",
                    output.status,
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                ));
            }
            Ok(TAG.to_owned())
        })
        .clone()
}
