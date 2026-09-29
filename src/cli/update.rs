//! `update --from <client-kit.zip>`: replace only the executable,
//! the two Claude Code settings entries (merged) and release identity;
//! reuse `client.toml`, `client-secret` and `ca.pem`; ask for no code; roll
//! the replacements back when the authenticated post-update status check
//! fails.

use std::path::Path;
use std::time::Duration;

use serde_json::json;

use super::args::Cli;
use super::{Failure, Outcome};
use crate::bundle::{self, PinnedKey};
use crate::client;

fn installation_refusal((code, message): (i32, String)) -> Failure {
    let slug = match code {
        11 => "cli_not_enrolled",
        5 => "cli_refused",
        3 => "cli_configuration_invalid",
        _ => "cli_internal",
    };
    local(code, slug, message)
}

fn local(code: i32, slug: &str, message: impl Into<String>) -> Failure {
    Failure::local(code, slug, message)
}

/// Writes `bytes` to `<path>.new` (mode 0700 on Unix) and renames over
/// `path`, so the old file stands until the replacement is complete.
fn replace_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut staged = path.to_path_buf();
    let mut name = staged.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    staged.set_file_name(name);
    std::fs::write(&staged, bytes).map_err(|e| format!("{}: {e}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", staged.display()))?;
    }
    std::fs::rename(&staged, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// `update [--from <kit>] [--version <semver>]
/// [--release-origin <https-origin>]`. With `--from` the given archive is
/// applied; without it, `--version`'s client kit — or the newest published
/// one (the origin's latest redirect) — is fetched from the origin first,
/// verified by [`bundle::verify_kit_zip`], then the same pipeline runs. The
/// fetched kit is a private temporary file, deleted afterwards.
pub(super) async fn update(
    cli: &Cli,
    from: Option<&Path>,
    version: Option<&str>,
    release_origin: Option<&str>,
) -> Outcome {
    let staged = match from {
        Some(_) => None,
        None => {
            let requested = match version {
                Some(version) => version.to_string(),
                None => {
                    eprintln!("asking the release host for its newest release");
                    crate::deploy::release::newest_version(release_origin, cli.tls_ca.as_deref())
                        .await
                        .map_err(|why| local(4, "cli_unreachable", why))?
                }
            };
            eprintln!("fetching the client kit for {requested}");
            Some(
                crate::deploy::release::fetch_client_kit(
                    &requested,
                    release_origin,
                    cli.tls_ca.as_deref(),
                )
                .await
                .map_err(|why| local(17, "cli_release_unverified", why))?,
            )
        }
    };
    let outcome = update_from(from.unwrap_or_else(|| {
        staged
            .as_deref()
            .expect("the fetched kit stands in for --from")
    }))
    .await;
    if let Some(dir) = staged.and_then(|p| p.parent().map(Path::to_path_buf)) {
        let _ = std::fs::remove_dir_all(dir);
    }
    outcome
}

/// The `--from` pipeline.
async fn update_from(from: &Path) -> Outcome {
    let installation = client::read_installation().map_err(installation_refusal)?;
    let secret = client::read_secret(&installation).map_err(installation_refusal)?;

    let key = PinnedKey::load().map_err(|why| {
        local(
            17,
            "cli_release_unverified",
            format!("the client kit cannot be verified: {why}"),
        )
    })?;
    let kit = bundle::verify_kit_zip(from, &key).map_err(|why| {
        local(
            17,
            "cli_release_unverified",
            format!("{}: {why}", from.display()),
        )
    })?;
    let Some(payload_member) = bundle::native_payload() else {
        return Err(local(
            18,
            "cli_preflight_failed",
            format!(
                "this platform ({}/{}) has no client payload in the kit",
                std::env::consts::OS,
                std::env::consts::ARCH
            ),
        ));
    };
    let executable = kit.members[payload_member].clone();

    let binary = crate::config::platform::client_binary();
    let old_executable = std::fs::read(&binary).unwrap_or_default();
    let settings_path = crate::settings::path();
    let old_settings = std::fs::read(&settings_path).ok();

    // The settings error already names the file.
    let plan = crate::settings::plan_install(&binary)
        .map_err(|why| local(1, "cli_internal", format!("{why}; nothing was changed")))?;
    if let Some(command) = crate::settings::foreign_status_line(&binary) {
        eprintln!(
            "notice: Claude Code's status line is another tool's ({command}); it was left in place and the jaynshare status line was not installed. Remove it and run `jaynshare update --from <kit>` to install ours."
        );
    }

    if let Err(why) = replace_atomically(&binary, &executable) {
        return Err(local(1, "cli_internal", why));
    }
    if let Some(plan) = &plan
        && let Err(why) = crate::settings::commit(plan)
    {
        return Err(local(1, "cli_internal", why));
    }

    match client::snapshot(&installation, &secret, None, Duration::from_secs(5)).await {
        Ok(_) => {
            let mut result = client::client_result(&installation);
            result["version"] = json!(kit.version);
            let human = format!(
                "updated the client to {} ({})",
                kit.version, installation.client_id
            );
            Ok((result, human))
        }
        Err((code, why)) => {
            // The replacements roll back; the three client files
            // never were touched.
            let _ = if old_executable.is_empty() && !binary.is_file() {
                std::fs::remove_file(&binary).map_err(|e| e.to_string())
            } else {
                replace_atomically(&binary, &old_executable)
            };
            match &old_settings {
                Some(bytes) => {
                    let _ = crate::state::write_private_atomic(&settings_path, bytes)
                        .map_err(|e| e.to_string());
                }
                None => {
                    let _ = std::fs::remove_file(&settings_path);
                }
            }
            let slug = match code {
                4 => "cli_unreachable",
                5 => "cli_refused",
                _ => "cli_incompatible_server",
            };
            Err(local(
                code,
                slug,
                format!(
                    "the post-update status check failed ({why}); the executable and the Claude Code settings entries were rolled back"
                ),
            ))
        }
    }
}
