//! The container-first deployment, `container
//! install|update|status|backup|restore|uninstall`. Docker is reached only
//! through [`docker`], by name from `PATH` (the test suite's fake answers
//! it).
//!
//! Check names start with their exit class (`cli/deploy.rs::exit_row`):
//! `preflight.*` (18), `release.*` (17), `manager.*` (19), `confirmation.*`
//! (21), `conflict.*` (8), `configuration.*` (3); `rolled_back` is 20.

use std::path::{Path, PathBuf};
use std::process::Output;

use super::address::{self, AddressClass};
use super::compose;
use super::release;
use super::result::{Check, DeployResult};
use crate::bundle;

/// The one Docker wrapper: `docker <args>`, standard input closed.
pub fn docker(args: &[&str]) -> Result<Output, String> {
    std::process::Command::new("docker")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("docker: {e}"))
}

/// Where `container install` materialises project `<name>`, one
/// owner-only directory per project under the configuration root:
/// `containers/<name>/` holding the reviewed `compose.yaml` (rendered by
/// `compose::render`) and the verified release set it came from
/// (`release.json`, `release.json.minisig`, `SHA256SUMS`, the Compose kit).
pub fn project_dir(project: &str) -> std::path::PathBuf {
    crate::config::platform::config_root()
        .join("containers")
        .join(project)
}

/// The one Compose invocation, through [`docker`]: `docker compose -p
/// <project> -f <project_dir>/compose.yaml <args>`.
pub fn compose(project: &str, args: &[&str]) -> Result<Output, String> {
    let file = project_dir(project).join("compose.yaml");
    let file = file.display().to_string();
    let mut full = vec!["compose", "-p", project, "-f", file.as_str()];
    full.extend_from_slice(args);
    docker(&full)
}

/// The project's one named volume as Compose names it (the kit's
/// volume key is `state`).
pub fn volume_name(project: &str) -> String {
    format!("{project}_state")
}

/// A project name is `[a-z0-9][a-z0-9_-]{0,31}`.
pub fn valid_project(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

/// The resource limits of one installed project; each defaults and is never omitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// CPUs as Compose spells them (`"1.0"`).
    pub cpus: String,
    /// Memory as Compose spells it (`"512m"`).
    pub memory: String,
    pub pids: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            cpus: "1.0".into(),
            memory: "512m".into(),
            pids: 128,
        }
    }
}

/// What `container install` was given.
pub struct InstallInputs<'a> {
    pub project: &'a str,
    /// The Compose kit, verified first.
    pub kit: &'a Path,
    /// One or two explicit `host-ip:port` publications.
    pub publish: &'a [std::net::SocketAddr],
    /// The configuration mounted read-only: the global `--config`.
    pub config: &'a Path,
    pub limits: Limits,
}

/// The daemon must be rootless and local, Engine ≥ 28.0.0, Compose ≥ 2.20.2,
/// and the project file validates without an override.
pub fn check_context(project_dir: Option<&Path>) -> Vec<Check> {
    let run = |args: &[&str]| -> Result<String, String> {
        let output = docker(args)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            let stderr = stderr.trim().lines().next().unwrap_or("");
            return Err(format!(
                "docker exited {}: {}",
                output.status,
                stderr.lines().next().unwrap_or("")
            ));
        }
        String::from_utf8(output.stdout).map_err(|_| "docker: the output is not UTF-8".into())
    };
    let (info, context, compose) = match (
        run(&["info", "--format", "{{json .}}"]),
        run(&["context", "inspect"]),
        run(&["compose", "version", "--short"]),
    ) {
        (Ok(i), Ok(c), Ok(v)) => (i, c, v),
        (Err(e), ..) | (_, Err(e), _) | (_, _, Err(e)) => {
            return vec![Check::fail("preflight.docker", e)];
        }
    };
    let info = serde_json::from_str(&info)
        .map_err(|e| format!("docker info: {e}"))
        .and_then(|v| serde_json::from_value::<serde_json::Value>(v).map_err(|e| e.to_string()));
    let context = serde_json::from_str::<serde_json::Value>(&context)
        .map_err(|e| format!("docker context inspect: {e}"))
        .and_then(|v| match v.as_array().and_then(|a| a.first()) {
            Some(first) => Ok(first.clone()),
            None => Err("docker context inspect: no context".into()),
        });
    match (info, context) {
        (Ok(info), Ok(context)) => judge_context(&info, &context, &compose, project_dir),
        (Err(e), _) | (_, Err(e)) => vec![Check::fail("preflight.docker", e)],
    }
}

/// The pure part of [`check_context`]: the three answers already in hand.
/// `project_dir` of `None` skips the override check.
pub fn judge_context(
    info: &serde_json::Value,
    context: &serde_json::Value,
    compose_version: &str,
    project_dir: Option<&Path>,
) -> Vec<Check> {
    let mut checks = Vec::new();

    let rootless = info["SecurityOptions"]
        .as_array()
        .map(|options| options.iter().any(|o| o.as_str() == Some("name=rootless")))
        .unwrap_or(false);
    checks.push(if rootless {
        Check::pass("preflight.rootless", "the Docker daemon is rootless")
    } else {
        Check::fail(
            "preflight.rootless",
            "the Docker daemon is not rootless; rootless mode is required",
        )
    });

    let host = context["Endpoints"]["docker"]["Host"]
        .as_str()
        .unwrap_or("");
    checks.push(if host.starts_with("unix://") {
        Check::pass("preflight.local", "the Docker context is local")
    } else {
        Check::fail(
            "preflight.local",
            format!("the Docker context is not local ({host}); a unix socket is required"),
        )
    });

    let engine = info["ServerVersion"].as_str().unwrap_or("");
    checks.push(if at_least(engine, [28, 0, 0]) {
        Check::pass("preflight.engine", format!("Docker Engine {engine}"))
    } else {
        Check::fail(
            "preflight.engine",
            format!("Docker Engine {engine} is older than the required 28.0.0"),
        )
    });

    let compose = compose_version.strip_prefix('v').unwrap_or(compose_version);
    checks.push(if at_least(compose, [2, 20, 2]) {
        Check::pass("preflight.compose", format!("Docker Compose {compose}"))
    } else {
        Check::fail(
            "preflight.compose",
            format!("Docker Compose {compose} is older than the required 2.20.2"),
        )
    });

    if let Some(dir) = project_dir {
        let overrides = ["compose.override.yaml", "docker-compose.override.yml"];
        let found = overrides.iter().find(|n| dir.join(n).exists());
        checks.push(match found {
            None => Check::pass(
                "preflight.override",
                "no Compose override file beside the project file",
            ),
            Some(name) => Check::fail(
                "preflight.override",
                format!("{name} beside the project file would alter the deployment"),
            ),
        });
    }

    checks
}

/// `version`'s numeric prefix against a `major.minor.patch` floor.
fn at_least(version: &str, floor: [u64; 3]) -> bool {
    let mut actual = [0u64; 3];
    for (i, part) in version.split('.').take(3).enumerate() {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        actual[i] = digits.parse().unwrap_or(0);
    }
    actual >= floor
}

/// A digest's only accepted form: `sha256:` plus 64 lowercase hex digits.
fn is_well_formed_digest(value: &str) -> bool {
    let hex = value.strip_prefix("sha256:").unwrap_or("");
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (0x61..=0x66).contains(&b))
}

/// The image `compose_image` names, against `manifest.image`.
/// `fetch(reference)` returns a registry's exact bytes for
/// `<repository>@<digest>`; production passes [`registry_raw`].
pub fn verify_image(
    manifest: &crate::deploy::release::ReleaseManifest,
    compose_image: &str,
    fetch: impl Fn(&str) -> Result<Vec<u8>, String>,
) -> Vec<Check> {
    use crate::bundle::sha256_hex;
    use crate::deploy::release::OCI_REPOSITORY;

    let Some(record) = &manifest.image else {
        return vec![Check::fail(
            "release.image",
            "release.json has no `image` record; this release publishes no container image",
        )];
    };

    // 1. The record itself.
    if record.repository != OCI_REPOSITORY {
        return vec![Check::fail(
            "release.image",
            format!(
                "`image.repository` is {:?}, not the official {:?}",
                record.repository, OCI_REPOSITORY
            ),
        )];
    }
    if record.tag != manifest.version {
        return vec![Check::fail(
            "release.image",
            format!(
                "`image.tag` is {:?}, not the release version {:?}",
                record.tag, manifest.version
            ),
        )];
    }
    if !is_well_formed_digest(&record.index_digest) {
        return vec![Check::fail(
            "release.image",
            "`image.index_digest` is not a `sha256:<64 hex>` digest",
        )];
    }
    for (i, platform) in record.platforms.iter().enumerate() {
        if platform.platform != "linux/amd64" && platform.platform != "linux/arm64" {
            return vec![Check::fail(
                "release.image",
                format!(
                    "`image.platforms[{i}].platform` is {:?}, not linux/amd64 or linux/arm64",
                    platform.platform
                ),
            )];
        }
        if !is_well_formed_digest(&platform.manifest_digest) {
            return vec![Check::fail(
                "release.image",
                format!("`image.platforms[{i}].manifest_digest` is not a `sha256:<64 hex>` digest"),
            )];
        }
        if !is_well_formed_digest(&platform.config_digest) {
            return vec![Check::fail(
                "release.image",
                format!("`image.platforms[{i}].config_digest` is not a `sha256:<64 hex>` digest"),
            )];
        }
        if platform.layer_digests.is_empty() {
            return vec![Check::fail(
                "release.image",
                format!("`image.platforms[{i}].layer_digests` lists no layer"),
            )];
        }
        for (n, digest) in platform.layer_digests.iter().enumerate() {
            if !is_well_formed_digest(digest) {
                return vec![Check::fail(
                    "release.image",
                    format!(
                        "`image.platforms[{i}].layer_digests[{n}]` is not a `sha256:<64 hex>` digest"
                    ),
                )];
            }
        }
    }
    for wanted in ["linux/amd64", "linux/arm64"] {
        let count = record
            .platforms
            .iter()
            .filter(|p| p.platform == wanted)
            .count();
        if count != 1 {
            return vec![Check::fail(
                "release.image",
                format!("`image.platforms` lists {wanted} {count} times, not once"),
            )];
        }
    }

    // 2. The compose kit's reference.
    let pinned = format!("{}@{}", record.repository, record.index_digest);
    if compose_image != pinned {
        let why = if compose_image.contains('@') {
            "a digest reference that differs from the record's"
        } else {
            "a mutable tag; the digest reference is required"
        };
        return vec![Check::fail(
            "release.image_pin",
            format!("the compose kit pins {compose_image:?} ({why} {pinned:?})"),
        )];
    }

    // 3. The index.
    let index_bytes = match fetch(&pinned) {
        Ok(bytes) => bytes,
        Err(error) => return vec![Check::fail("release.image_index", error)],
    };
    if sha256_hex(&index_bytes) != record.index_digest["sha256:".len()..] {
        return vec![Check::fail(
            "release.image_index",
            format!("the registry's {pinned} does not hash to the recorded `image.index_digest`"),
        )];
    }
    let index: serde_json::Value = match serde_json::from_slice(&index_bytes) {
        Ok(value) => value,
        Err(e) => {
            return vec![Check::fail(
                "release.image_index",
                format!("the registry's {pinned} is not JSON: {e}"),
            )];
        }
    };
    let media_type = index["mediaType"].as_str().unwrap_or("");
    if media_type != "application/vnd.oci.image.index.v1+json"
        && media_type != "application/vnd.docker.distribution.manifest.list.v2+json"
    {
        return vec![Check::fail(
            "release.image_index",
            format!("the index's mediaType is {media_type:?}, not an image index"),
        )];
    }
    let manifests = match index["manifests"].as_array() {
        Some(manifests) => manifests,
        None => {
            return vec![Check::fail(
                "release.image_index",
                "the index has no `manifests` array",
            )];
        }
    };
    if manifests.len() != 2 {
        return vec![Check::fail(
            "release.image_index",
            format!(
                "the index lists {} manifests, not the two platforms",
                manifests.len()
            ),
        )];
    }
    for recorded in &record.platforms {
        let served = manifests.iter().find(|m| {
            format!(
                "{}/{}",
                m["platform"]["os"].as_str().unwrap_or(""),
                m["platform"]["architecture"].as_str().unwrap_or("")
            ) == recorded.platform
        });
        let Some(served) = served else {
            return vec![Check::fail(
                "release.image_index",
                format!("the index has no entry for {}", recorded.platform),
            )];
        };
        let served_digest = served["digest"].as_str().unwrap_or("");
        if served_digest != recorded.manifest_digest {
            return vec![Check::fail(
                "release.image_index",
                format!(
                    "{}: the index serves {}, but the record says {}",
                    recorded.platform, served_digest, recorded.manifest_digest
                ),
            )];
        }
    }

    // 4. Each platform manifest.
    for recorded in &record.platforms {
        let reference = format!("{}@{}", record.repository, recorded.manifest_digest);
        let bytes = match fetch(&reference) {
            Ok(bytes) => bytes,
            Err(error) => return vec![Check::fail("release.image_platform", error)],
        };
        if sha256_hex(&bytes) != recorded.manifest_digest["sha256:".len()..] {
            return vec![Check::fail(
                "release.image_platform",
                format!(
                    "{}: the registry's {reference} does not hash to the recorded manifest digest",
                    recorded.platform
                ),
            )];
        }
        let manifest: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(e) => {
                return vec![Check::fail(
                    "release.image_platform",
                    format!("{}: {reference} is not JSON: {e}", recorded.platform),
                )];
            }
        };
        let config_digest = manifest["config"]["digest"].as_str().unwrap_or("");
        if config_digest != recorded.config_digest {
            return vec![Check::fail(
                "release.image_platform",
                format!(
                    "{}: config digest {config_digest} differs from the recorded {}",
                    recorded.platform, recorded.config_digest
                ),
            )];
        }
        let layers: Vec<&str> = manifest["layers"]
            .as_array()
            .map(|layers| {
                layers
                    .iter()
                    .map(|layer| layer["digest"].as_str().unwrap_or(""))
                    .collect()
            })
            .unwrap_or_default();
        if layers.len() != recorded.layer_digests.len() {
            return vec![Check::fail(
                "release.image_platform",
                format!(
                    "{}: the manifest has {} layers, the record lists {}",
                    recorded.platform,
                    layers.len(),
                    recorded.layer_digests.len()
                ),
            )];
        }
        for (n, served) in layers.iter().enumerate() {
            if *served != recorded.layer_digests[n] {
                return vec![Check::fail(
                    "release.image_platform",
                    format!(
                        "{}: layer {} serves {served}, but the record says {}",
                        recorded.platform,
                        n + 1,
                        recorded.layer_digests[n]
                    ),
                )];
            }
        }
    }

    // 5. Everything agreed.
    vec![Check::pass(
        "release.image_platform",
        format!("{pinned} verified: linux/amd64, linux/arm64"),
    )]
}

/// The registry read behind [`verify_image`]'s `fetch`: `docker buildx
/// imagetools inspect --raw <reference>` through [`docker`], its standard
/// output as bytes; a non-zero exit is an `Err` naming the exit and stderr's
/// first line.
pub fn registry_raw(reference: &str) -> Result<Vec<u8>, String> {
    let output = docker(&["buildx", "imagetools", "inspect", "--raw", reference])?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "docker exited {}: {}",
            output.status,
            stderr.lines().next().unwrap_or("")
        ));
    }
    Ok(output.stdout)
}

/// The one `image:` line of a compose file's exact text, its unquoted
/// reference (`install` step 2). None when the file has none or two.
fn image_line(compose_yaml: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(compose_yaml).ok()?;
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("image:") else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        let value = rest.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        found = Some(value.to_string());
    }
    found
}

/// `update` step 7: the current compose.yaml with only its `image:` value
/// replaced by the new reference; everything else was reviewed at install.
/// The original line's indentation and quoting style are kept. None when the
/// file has no single `image:` line.
fn replace_image_line(compose_yaml: &[u8], new_reference: &str) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(compose_yaml).ok()?;
    let mut count = 0usize;
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("image:") {
            count += 1;
            if count > 1 {
                return None;
            }
            let indent = &line[..line.len() - trimmed.len()];
            let value = rest.trim();
            let quoted = value.len() >= 2 && value.starts_with('"') && value.ends_with('"');
            if quoted {
                out.push_str(&format!("{indent}image: \"{new_reference}\"\n"));
            } else {
                out.push_str(&format!("{indent}image: {new_reference}\n"));
            }
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if count == 0 {
        return None;
    }
    Some(out.into_bytes())
}

/// The `Health` of a service in `docker compose ps --format json`'s answer
/// (`install` step 13, `status`).
fn ps_health(ps_json: &str, service: &str) -> Option<String> {
    ps_field(ps_json, service, "Health")
}

/// The `State` of a service in the same answer (`update` step 4: was it
/// running before).
fn ps_state(ps_json: &str, service: &str) -> Option<String> {
    ps_field(ps_json, service, "State")
}

/// One service's one string field of that answer.
fn ps_field(ps_json: &str, service: &str, field: &str) -> Option<String> {
    let documents: Vec<serde_json::Value> = ps_json
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()
        .ok()?;
    documents
        .iter()
        .find(|document| document["Service"].as_str() == Some(service))
        .and_then(|document| document[field].as_str())
        .map(str::to_owned)
}

/// The host's `NCPU` and `MemTotal` from `docker info --format
/// '{{json .}}''s answer — the daemon's machine, not the invoking shell's.
fn daemon_resources(info_json: &str) -> Result<(f64, u64), String> {
    let info: serde_json::Value =
        serde_json::from_str(info_json).map_err(|e| format!("docker info: {e}"))?;
    let cpus = info["NCPU"]
        .as_f64()
        .ok_or_else(|| "docker info: NCPU missing".to_string())?;
    let memory = info["MemTotal"]
        .as_u64()
        .ok_or_else(|| "docker info: MemTotal missing".to_string())?;
    Ok((cpus, memory))
}

/// The one JSON document `docker compose … config --format json` printed.
fn compose_config_json(output: &Output, what: &str) -> Result<serde_json::Value, String> {
    if !output.status.success() {
        return Err(format!(
            "docker compose config: docker exited {} ({what}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("")
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("docker compose config: not JSON ({what}): {e}"))
}

/// The one `Check` an error message is.
fn failure_check(name: &str, message: impl Into<String>) -> Check {
    Check::fail(name, message)
}

/// Install/update steps 1–4: the release set beside `kit`
/// verifies under the planted key, the kit's compose.yaml pins one image by
/// index digest, the registry serves the recorded digests, and the Docker
/// context is rootless and local. `None` when a check failed (the result
/// carries it); otherwise the manifest, the pinned reference and the
/// canonical manifest bytes the verified set carries.
fn verify_kit(
    result: &mut DeployResult,
    kit: &Path,
) -> Option<(release::ReleaseManifest, String, Vec<u8>)> {
    // 1. The release set beside the kit, under the planted key.
    let verified = release::verify(kit, None);
    result.checks.extend(verified.checks);
    if result.failed().is_some() {
        result.version = verified.version;
        result.commit = verified.commit;
        return None;
    }
    let manifest_bytes = release::read_release(kit)
        .ok()
        .and_then(|release| release.files.get("release.json").cloned());
    let Some(manifest_bytes) = manifest_bytes else {
        result.checks.push(failure_check(
            "release.read",
            "release.json is not beside the kit",
        ));
        return None;
    };
    let Ok(manifest) = release::ReleaseManifest::parse(&manifest_bytes) else {
        result.checks.push(failure_check(
            "release.manifest",
            "release.json beside the kit does not parse",
        ));
        return None;
    };
    result.version = Some(manifest.version.clone());
    result.commit = Some(manifest.commit.clone());

    // 2. The kit's one `image:` line.
    let members = match bundle::read_zip(kit) {
        Ok(members) => members,
        Err(why) => {
            result.checks.push(failure_check("release.kit", why));
            return None;
        }
    };
    let Some(compose_yaml) = members.get("compose.yaml") else {
        result
            .checks
            .push(failure_check("release.kit", "the kit has no compose.yaml"));
        return None;
    };
    let Some(reference) = image_line(compose_yaml) else {
        result.checks.push(failure_check(
            "release.image_pin",
            "compose.yaml has no single `image:` line pinning the release digest",
        ));
        return None;
    };

    // 3. The image the kit names, against release.json's record.
    let image_checks = verify_image(&manifest, &reference, registry_raw);
    result.checks.extend(image_checks);
    if result.failed().is_some() {
        return None;
    }

    // 4. The context is rootless and local, no override.
    let context_checks = check_context(None);
    result.checks.extend(context_checks);
    if result.failed().is_some() {
        return None;
    }
    Some((manifest, reference, manifest_bytes))
}

/// The mounted configuration's own listeners, judged inside the
/// container: the wildcard exception applies — `0.0.0.0`/`::` and loopback
/// pass, any closed-list address passes, anything else fails. The
/// publication stays `compose::check_publications`' (the closed list of
/// `--publish` host IPs). The proxy listener is judged unless
/// `mitm.enabled` is false.
fn check_listeners(config: &Path) -> Vec<Check> {
    let judge = |name: &str, text: &str| -> Check {
        let Ok(address) = text.parse::<std::net::SocketAddr>() else {
            return Check::fail(
                name,
                format!("{text:?} is not one numeric IP address and port"),
            );
        };
        let class = address::classify(address.ip());
        let wildcard = class == AddressClass::Unspecified;
        let message = if wildcard {
            format!("{address} is {class:?}: the container wildcard exception")
        } else {
            format!("{address} is {class:?}")
        };
        if class.passes() || wildcard {
            Check::pass(name, message)
        } else {
            Check::fail(name, message)
        }
    };
    let mut checks = vec![];
    let table = std::fs::read_to_string(config)
        .map_err(|e| e.to_string())
        .and_then(|text| toml::from_str::<toml::Table>(&text).map_err(|e| e.to_string()));
    let table = match table {
        Ok(table) => table,
        Err(why) => {
            checks.push(Check::fail(
                "configuration.valid",
                format!(
                    "the configuration {} did not parse: {why}",
                    config.display()
                ),
            ));
            return checks;
        }
    };
    let listen = |key: &str| {
        table
            .get(key)
            .and_then(|t| t.get("listen"))
            // A non-string value cannot be a listen address; its TOML form
            // then fails the socket-address parse below.
            .map(|v| v.as_str().map_or(v.to_string(), str::to_owned))
    };
    let data_plane = listen("data_plane").unwrap_or_else(|| crate::config::DEFAULT_LISTEN.into());
    checks.push(judge("preflight.listener.data_plane", &data_plane));
    let mitm_enabled = table
        .get("mitm")
        .and_then(|t| t.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if mitm_enabled {
        let proxy =
            listen("mitm").unwrap_or_else(|| crate::config::default_mitm_listen(&data_plane));
        checks.push(judge("preflight.listener.proxy", &proxy));
    }
    checks
}

/// `container install`.
pub fn install(inputs: &InstallInputs<'_>) -> DeployResult {
    let mut result = DeployResult::new("container install");
    result.project = Some(inputs.project.to_string());
    if !valid_project(inputs.project) {
        result.checks.push(failure_check(
            "conflict.project",
            format!(
                "project {:?} is not [a-z0-9][a-z0-9_-]{{0,31}}",
                inputs.project
            ),
        ));
        return result;
    }

    // 1–4. The release set and the kit verify, the registry
    // serves the recorded digests, the context is rootless and local.
    let Some((manifest, reference, manifest_bytes)) = verify_kit(&mut result, inputs.kit) else {
        return result;
    };

    // 5. No project in the way.
    let dir = project_dir(inputs.project);
    if dir.join("compose.yaml").exists() {
        result.checks.push(failure_check(
            "conflict.project",
            format!(
                "project {} is already installed ({}); use container update",
                inputs.project,
                dir.display()
            ),
        ));
        return result;
    }

    // 6. The rendered file, staged beside the project.
    let rendered = compose::render(&compose::ProjectInputs {
        project: inputs.project,
        image: &reference,
        config: inputs.config,
        publish: inputs.publish,
        limits: &inputs.limits,
    });
    let staging = staging_dir(inputs.project);
    let _ = std::fs::remove_dir_all(&staging);
    if crate::state::ensure_private_dir(&staging).is_err() {
        result.checks.push(failure_check(
            "manager.staging",
            format!("cannot create the staging directory {}", staging.display()),
        ));
        return result;
    }
    if let Err(why) = private_file(&staging.join("compose.yaml"), rendered.as_bytes()) {
        result.checks.push(failure_check("manager.staging", why));
        let _ = std::fs::remove_dir_all(&staging);
        return result;
    }

    // 7. The rendered file's publications, no override beside it.
    let document = match compose_staging_config(inputs.project, &staging) {
        Ok(document) => document,
        Err(message) => {
            result
                .checks
                .push(failure_check("preflight.compose", message));
            let _ = std::fs::remove_dir_all(&staging);
            return result;
        }
    };
    let publication_checks = compose::check_publications(&document);
    result.checks.extend(publication_checks);
    let override_checks = check_context(Some(&staging));
    result.checks.extend(override_checks);
    if result.failed().is_some() {
        let _ = std::fs::remove_dir_all(&staging);
        return result;
    }

    // 8. The limits across the daemon's host, other projects first.
    let (host_cpus, host_memory) = match daemon_host_resources() {
        Ok(resources) => resources,
        Err(message) => {
            result
                .checks
                .push(failure_check("preflight.docker", message));
            let _ = std::fs::remove_dir_all(&staging);
            return result;
        }
    };
    let others = other_projects_limits(inputs.project);
    let limit_checks = compose::check_limits(&inputs.limits, &others, host_cpus, host_memory);
    result.checks.extend(limit_checks);
    if result.failed().is_some() {
        let _ = std::fs::remove_dir_all(&staging);
        return result;
    }

    // 9. The configuration is one existing regular file; the path is
    // spoken, the contents never are. A file owned by the
    // service identity in an owner-only directory is, by design, not
    // readable from this shell: the project reads and
    // validates it at start, and the health window below refuses a bad one.
    let metadata = std::fs::metadata(inputs.config);
    let service_owned = matches!(
        &metadata,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    ) || matches!(
        std::fs::File::open(inputs.config),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    );
    if service_owned {
        result.checks.push(Check::pass(
            "preflight.config",
            format!(
                "{} is not readable from this shell, as intended for a file owned by the service identity; the project reads and validates it at start",
                inputs.config.display()
            ),
        ));
    } else if !metadata.as_ref().is_ok_and(|m| m.is_file()) {
        result.checks.push(failure_check(
            "preflight.config",
            format!(
                "the configuration {} is absent or not a regular file",
                inputs.config.display()
            ),
        ));
        let _ = std::fs::remove_dir_all(&staging);
        return result;
    }

    // 9b. The configuration's own listeners, judged inside the
    // container where the wildcard exception applies; the publications
    // stayed `compose::check_publications`' above. A service-owned
    // file is judged by the server itself at start.
    if !service_owned {
        result.checks.extend(check_listeners(inputs.config));
    }
    if result.failed().is_some() {
        let _ = std::fs::remove_dir_all(&staging);
        return result;
    }

    // 10. One reviewed project, the release set beside the file.
    if let Err(why) = materialise(inputs, &staging, &manifest_bytes) {
        result.checks.push(failure_check("manager.install", why));
        let _ = std::fs::remove_dir_all(&staging);
        return result;
    }
    result.paths.push(dir.display().to_string());

    // 11–14. The explicit pull, the no-pull start, the health
    // window and the one operator status read.
    if let Err(stop) = start_and_check(&mut result, inputs.project, &manifest, &reference) {
        // 15. The failed project stops for inspection; the directory
        // and the volume stay. Rollback is update's, not install's.
        let _ = compose(inputs.project, &["down"]);
        result.checks.push(stop);
    }
    result
}

/// `install` steps 11–14; `Ok` only when the project is healthy and its
/// status read agrees with the release.
fn start_and_check(
    result: &mut DeployResult,
    project: &str,
    manifest: &release::ReleaseManifest,
    reference: &str,
) -> Result<(), Check> {
    // 11. Install is an explicit operator verb: it may pull.
    let pulled = docker(&["pull", reference]);
    if !pulled.as_ref().is_ok_and(|output| output.status.success()) {
        return Err(failure_check(
            "manager.pull",
            format!(
                "docker pull of the project image failed; the project {project} is stopped for inspection"
            ),
        ));
    }

    // 12. Pulling disabled at start (a running project never pulls).
    let up = compose(project, &["up", "-d", "--pull", "never", "--no-build"]);
    if !up.as_ref().is_ok_and(|output| output.status.success()) {
        return Err(failure_check(
            "manager.start",
            format!("docker compose up of project {project} failed; it is stopped for inspection"),
        ));
    }
    poll_and_status(result, project, manifest)
}

/// Install steps 13–14; update step 8. `Ok` only when the project is healthy
/// and its status read agrees with the release.
fn poll_and_status(
    result: &mut DeployResult,
    project: &str,
    manifest: &release::ReleaseManifest,
) -> Result<(), Check> {
    // 13. Healthy within 30 s, one read a second.
    match poll_health(project) {
        Ok(()) => result.checks.push(Check::pass(
            "manager.health",
            format!("project {project} reports healthy"),
        )),
        Err(message) => return Err(failure_check("manager.health", message)),
    }

    // 14. One real operator status read through exec, the version
    // and the configuration digest it carries.
    let status = status_read(project)?;
    if status.version != manifest.version {
        return Err(failure_check(
            "manager.status",
            format!(
                "project {project} reports version {:?}, not the release's {:?}",
                status.version, manifest.version
            ),
        ));
    }
    let Some(digest) = status.config_digest else {
        return Err(failure_check(
            "manager.status",
            format!("project {project}'s status carries no configuration digest"),
        ));
    };
    result.checks.push(Check::pass(
        "manager.status",
        format!(
            "project {project} reports version {} with configuration digest {digest}",
            status.version
        ),
    ));
    Ok(())
}

/// The health poll itself: healthy within 30 s, one read a second; a
/// definite `unhealthy` answer fails at once, so no wait outlives a verdict.
fn poll_health(project: &str) -> Result<(), String> {
    let deadline = std::time::Instant::now() + HEALTH_WINDOW;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Ok(output) = compose(project, &["ps", "--format", "json", "server"])
            && output.status.success()
        {
            match ps_health(&String::from_utf8_lossy(&output.stdout), "server").as_deref() {
                Some("healthy") => return Ok(()),
                Some("unhealthy") => {
                    return Err(format!("project {project} reports unhealthy"));
                }
                _ => {}
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "project {project} is not healthy within 30 seconds"
            ));
        }
    }
}

/// The health window: 30 seconds.
const HEALTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(30);

/// The staging directory beside the project: `<project_dir>.staging`.
fn staging_dir(project: &str) -> PathBuf {
    let mut name = project_dir(project).into_os_string();
    name.push(".staging");
    PathBuf::from(name)
}

/// `docker compose -p <project> -f <staging>/compose.yaml config --format json`.
fn compose_staging_config(project: &str, staging: &Path) -> Result<serde_json::Value, String> {
    let file = staging.join("compose.yaml");
    let file = file.display().to_string();
    let output = docker(&[
        "compose",
        "-p",
        project,
        "-f",
        file.as_str(),
        "config",
        "--format",
        "json",
    ])?;
    compose_config_json(&output, "the rendered compose.yaml")
}

/// `docker info --format '{{json .}}''s `NCPU` and `MemTotal`.
fn daemon_host_resources() -> Result<(f64, u64), String> {
    let output = docker(&["info", "--format", "{{json .}}"])?;
    if !output.status.success() {
        return Err(format!(
            "docker info: docker exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .unwrap_or("")
        ));
    }
    daemon_resources(&String::from_utf8_lossy(&output.stdout))
}

/// Every other project's limits under `<config root>/containers/`,
/// each read through `docker compose config --format json`.
fn other_projects_limits(project: &str) -> Vec<Limits> {
    let root = crate::config::platform::config_root().join("containers");
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut others = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == project {
            continue;
        }
        let file = entry.path().join("compose.yaml");
        if !file.exists() {
            continue;
        }
        let file = file.display().to_string();
        let Ok(output) = docker(&[
            "compose",
            "-p",
            &name,
            "-f",
            file.as_str(),
            "config",
            "--format",
            "json",
        ]) else {
            continue;
        };
        if let Ok(document) = compose_config_json(&output, &name)
            && let Some(limits) = limits_of(&document)
        {
            others.push(limits);
        }
    }
    others
}

/// The `deploy.resources.limits` of a parsed Compose document, as [`Limits`].
fn limits_of(document: &serde_json::Value) -> Option<Limits> {
    let limits = &document["services"]["server"]["deploy"]["resources"]["limits"];
    Some(Limits {
        cpus: limits["cpus"].as_str()?.to_string(),
        memory: limits["memory"].as_str()?.to_string(),
        pids: limits["pids"].as_str()?.parse().ok()?,
    })
}

/// `install` step 10: the staged directory becomes the project, the release
/// set is copied beside the file, everything owner-only.
fn materialise(
    inputs: &InstallInputs<'_>,
    staging: &Path,
    manifest_bytes: &[u8],
) -> Result<(), String> {
    let dir = project_dir(inputs.project);
    let parent = dir
        .parent()
        .ok_or_else(|| format!("{}: no parent", dir.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    std::fs::rename(staging, &dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let release = release::read_release(inputs.kit)?;
    for name in [
        "release.json",
        "release.json.minisig",
        "SHA256SUMS",
        release.selected.as_deref().unwrap_or("compose.yaml"),
    ] {
        let Some(bytes) = release.files.get(name) else {
            return Err(format!("{}: not beside the kit", name));
        };
        let bytes = if name == "release.json" {
            manifest_bytes
        } else {
            bytes.as_slice()
        };
        private_file(&dir.join(name), bytes).map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

/// An owner-only regular file: created or truncated at 0600, via
/// `state::open_private`.
fn private_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut file =
        crate::state::open_private(path).map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

/// What the container's status read answered: the envelope's `result`, the
/// version and the configuration digest.
struct StatusRead {
    version: String,
    config_digest: Option<String>,
}

/// One `docker compose exec -T server … status --json`, the
/// envelope's `result` judged.
fn status_read(project: &str) -> Result<StatusRead, Check> {
    let output = compose(
        project,
        &[
            "exec",
            "-T",
            "server",
            "/usr/local/bin/jaynshare",
            "status",
            "--json",
        ],
    );
    let output =
        output.map_err(|error| failure_check("manager.status", format!("docker: {error}")))?;
    if !output.status.success() {
        return Err(failure_check(
            "manager.status",
            format!(
                "the status read inside project {project} exited {}",
                output.status
            ),
        ));
    }
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).map_err(|error| {
        failure_check(
            "manager.status",
            format!("the status read inside project {project} is not JSON: {error}"),
        )
    })?;
    let inner = envelope.get("result").cloned().unwrap_or(envelope.clone());
    let version = inner
        .get("version")
        .and_then(|value| value.as_str())
        .map(str::to_owned)
        .ok_or_else(|| {
            failure_check(
                "manager.status",
                format!("the status read inside project {project} names no version"),
            )
        })?;
    let config_digest = inner
        .get("config_digest")
        .or_else(|| inner.get("digest"))
        .and_then(|value| value.as_str())
        .map(str::to_owned);
    Ok(StatusRead {
        version,
        config_digest,
    })
}

/// `container update` — the new kit verifies as an install's, the restart is
/// confirmed on the terminal, the new digest is pulled explicitly,
/// the project volume is snapshotted owner-only, and only this project's
/// compose.yaml (`image:` value) and container are replaced; the health and
/// status checks decide between keeping (and deleting the snapshot) and
/// restoring the old digest, volume bytes and running state, reported as
/// `rolled_back` (20). No other project stops or restarts, and no
/// prune is ever invoked.
pub fn update(
    project: &str,
    kit: &Path,
    yes: bool,
    confirm: &dyn Fn(&str) -> Result<String, String>,
) -> DeployResult {
    let mut result = DeployResult::new("container update");
    result.project = Some(project.to_string());
    let dir = project_dir(project);
    let file = dir.join("compose.yaml");
    if !file.exists() {
        result.checks.push(failure_check(
            "conflict.project",
            format!("no project {project}: {} is missing", file.display()),
        ));
        return result;
    }

    // 1–3. The new kit verifies exactly as an install's does.
    let Some((manifest, reference, manifest_bytes)) = verify_kit(&mut result, kit) else {
        return result;
    };

    // 4. The restart is confirmed on the terminal, `--yes` instead.
    if !yes {
        let typed = match confirm(&format!(
            "restart project {project} on {}? [y/N] ",
            manifest.version
        )) {
            Ok(line) => line,
            Err(why) => {
                result
                    .checks
                    .push(failure_check("confirmation.required", why));
                return result;
            }
        };
        if !typed.trim().eq_ignore_ascii_case("y") {
            result.checks.push(Check::pass(
                "confirmation.declined",
                "the answer was not yes; nothing was changed",
            ));
            return result;
        }
    }

    // 5. Before: the current bytes and whether the service is running.
    let previous_bytes = match std::fs::read(&file) {
        Ok(bytes) => bytes,
        Err(e) => {
            result.checks.push(failure_check(
                "manager.update",
                format!("{}: {e}", file.display()),
            ));
            return result;
        }
    };
    // The replaced file is computed before anything runs: a compose.yaml
    // without its single pinned `image:` line is refused before any daemon
    // work, so the rollback below never meets a half-shaped state.
    let Some(replaced_bytes) = replace_image_line(&previous_bytes, &reference) else {
        result.checks.push(failure_check(
            "release.image_pin",
            format!(
                "{} has no single `image:` line pinning the release digest",
                file.display()
            ),
        ));
        return result;
    };
    let was_running = match compose(project, &["ps", "--format", "json", "server"]) {
        Ok(output) if output.status.success() => {
            ps_state(&String::from_utf8_lossy(&output.stdout), "server").as_deref()
                == Some("running")
        }
        Ok(output) => {
            result.checks.push(failure_check(
                "manager.compose",
                format!(
                    "docker compose ps of project {project}: {}",
                    docker_failure(&output)
                ),
            ));
            return result;
        }
        Err(e) => {
            result.checks.push(failure_check("manager.compose", e));
            return result;
        }
    };

    // 6. The explicit pull of the new digest.
    let pulled = match docker(&["pull", reference.as_str()]) {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            result.checks.push(failure_check(
                "manager.pull",
                format!(
                    "docker pull of the new image failed; project {project} was not touched: {}",
                    docker_failure(&output)
                ),
            ));
            return result;
        }
        Err(e) => {
            result.checks.push(failure_check("manager.pull", e));
            return result;
        }
    };
    let _ = pulled;

    // 7. Stop (SIGTERM gets 30 s so the server can flush its state), then the
    // owner-only snapshot of the volume. Nothing is replaced yet, so a
    // failure here only puts the service back the way it was.
    let snapshot = dir.join(".update-snapshot");
    let _ = std::fs::remove_dir_all(&snapshot);
    let stopped_output = match compose(project, &["stop", "-t", "30"]) {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            restart_if_running(project, was_running);
            result.checks.push(failure_check(
                "manager.stop",
                format!(
                    "docker compose stop of project {project} failed: {}",
                    docker_failure(&output)
                ),
            ));
            return result;
        }
        Err(e) => {
            restart_if_running(project, was_running);
            result.checks.push(failure_check("manager.stop", e));
            return result;
        }
    };
    let _ = stopped_output;
    if let Err(e) = crate::state::ensure_private_dir(&snapshot) {
        restart_if_running(project, was_running);
        result.checks.push(failure_check(
            "manager.snapshot",
            format!("{}: {e}", snapshot.display()),
        ));
        return result;
    }
    let volume_mount = format!("{}:/state:ro", volume_name(project));
    let backup_mount = format!("{}:/backup", snapshot.display());
    match docker(&[
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        volume_mount.as_str(),
        "-v",
        backup_mount.as_str(),
        "alpine:3",
        "tar",
        "-C",
        "/state",
        "-czf",
        "/backup/state.tar.gz",
        ".",
    ]) {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let _ = std::fs::remove_dir_all(&snapshot);
            restart_if_running(project, was_running);
            result.checks.push(failure_check(
                "manager.snapshot",
                format!(
                    "the volume snapshot of project {project} failed: {}",
                    docker_failure(&output)
                ),
            ));
            return result;
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&snapshot);
            restart_if_running(project, was_running);
            result.checks.push(failure_check("manager.snapshot", e));
            return result;
        }
    }

    // 8. Replace only this project's file (atomically, the old bytes
    // kept) and then its container, with pulling disabled.
    let previous_path = dir.join("compose.yaml.previous");
    if let Err(why) = write_private(&previous_path, &previous_bytes) {
        let _ = std::fs::remove_dir_all(&snapshot);
        restart_if_running(project, was_running);
        result.checks.push(failure_check("manager.update", why));
        return result;
    }
    let staged = dir.join("compose.yaml.update");
    let written = write_private(&staged, &replaced_bytes).and_then(|()| {
        std::fs::rename(&staged, &file).map_err(|e| format!("{}: {e}", staged.display()))
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&staged);
        rollback(&mut result, project, was_running, &snapshot);
        return result;
    }
    match compose(project, &["up", "-d", "--pull", "never", "--no-build"]) {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            result.checks.push(failure_check(
                "manager.start",
                format!(
                    "docker compose up of project {project} failed: {}",
                    docker_failure(&output)
                ),
            ));
            rollback(&mut result, project, was_running, &snapshot);
            return result;
        }
        Err(e) => {
            result.checks.push(failure_check("manager.start", e));
            rollback(&mut result, project, was_running, &snapshot);
            return result;
        }
    }

    // 9. The health window and the one operator status read.
    if let Err(check) = poll_and_status(&mut result, project, &manifest) {
        result.checks.push(check);
        rollback(&mut result, project, was_running, &snapshot);
        return result;
    }

    // 10. Success: the snapshot and the kept old file go, and the new
    // release set replaces the old beside compose.yaml (owner-only).
    let _ = std::fs::remove_dir_all(&snapshot);
    let _ = std::fs::remove_file(&previous_path);
    match store_release_set(kit, &dir, &manifest_bytes) {
        Ok(()) => result.checks.push(Check::pass(
            "manager.update",
            format!("project {project} now names {reference}; the volume snapshot is removed"),
        )),
        Err(why) => result.checks.push(failure_check("manager.update", why)),
    }
    result.paths = vec![dir.display().to_string(), file.display().to_string()];
    result
}

/// `update`'s best effort at putting the service back when nothing
/// was replaced yet (the old digest still holds).
fn restart_if_running(project: &str, was_running: bool) {
    if was_running {
        let _ = compose(project, &["up", "-d", "--pull", "never", "--no-build"]);
    }
}

/// The new release set (`release.json`, its signature, `SHA256SUMS`
/// and the kit) beside `dir`'s compose.yaml, everything owner-only.
fn store_release_set(kit: &Path, dir: &Path, manifest_bytes: &[u8]) -> Result<(), String> {
    let release = release::read_release(kit)?;
    let kit_name = release
        .selected
        .clone()
        .unwrap_or_else(|| "compose.yaml".to_string());
    private_file(&dir.join("release.json"), manifest_bytes)?;
    for name in ["release.json.minisig", "SHA256SUMS", kit_name.as_str()] {
        let Some(bytes) = release.files.get(name) else {
            return Err(format!("{name}: not beside the kit"));
        };
        private_file(&dir.join(name), bytes)?;
    }
    Ok(())
}

/// Failure after the replacement — the old digest, the volume's
/// bytes and the running state go back; `manager.rollback` passes or names
/// the step that failed (the snapshot is then kept at its path).
fn rollback(result: &mut DeployResult, project: &str, was_running: bool, snapshot: &Path) {
    result.rolled_back = true;
    let restore = (|| -> Result<(), String> {
        match compose(project, &["stop", "-t", "30"]) {
            Ok(output) if output.status.success() => {}
            Ok(output) => return Err(format!("docker compose stop: {}", docker_failure(&output))),
            Err(e) => return Err(format!("docker compose stop: {e}")),
        }
        let dir = project_dir(project);
        std::fs::rename(dir.join("compose.yaml.previous"), dir.join("compose.yaml"))
            .map_err(|e| format!("compose.yaml.previous back: {e}"))?;
        let volume_mount = format!("{}:/state", volume_name(project));
        let backup_mount = format!("{}:/backup:ro", snapshot.display());
        match docker(&[
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            volume_mount.as_str(),
            "-v",
            backup_mount.as_str(),
            "alpine:3",
            "sh",
            "-c",
            "find /state -mindepth 1 -delete && tar -C /state -xzf /backup/state.tar.gz",
        ]) {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return Err(format!(
                    "the volume restore from {}: {}",
                    snapshot.display(),
                    docker_failure(&output)
                ));
            }
            Err(e) => {
                return Err(format!(
                    "the volume restore from {}: {e}",
                    snapshot.display()
                ));
            }
        }
        if was_running {
            match compose(project, &["up", "-d", "--pull", "never", "--no-build"]) {
                Ok(output) if output.status.success() => {}
                Ok(output) => {
                    return Err(format!(
                        "docker compose up of the restored project: {}",
                        docker_failure(&output)
                    ));
                }
                Err(e) => {
                    return Err(format!("docker compose up of the restored project: {e}"));
                }
            }
        }
        // A project that was stopped before the update stays stopped, so
        // there is no health to wait for.
        if !was_running {
            return Ok(());
        }
        poll_health(project).map_err(|e| format!("the restored project's health: {e}"))
    })();
    match restore {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(snapshot);
            result.checks.push(Check::pass(
                "manager.rollback",
                format!(
                    "project {project}'s previous digest, volume bytes and running state are restored"
                ),
            ));
        }
        Err(why) => {
            result.paths.push(snapshot.display().to_string());
            result.checks.push(Check::fail(
                "manager.rollback",
                format!(
                    "the rollback failed: {why}; the snapshot is kept at {}",
                    snapshot.display()
                ),
            ));
        }
    }
}

/// `container status`, the health and one status read via exec.
pub fn status(project: &str) -> DeployResult {
    let mut result = DeployResult::new("container status");
    result.project = Some(project.to_string());
    if !valid_project(project) {
        result.checks.push(failure_check(
            "conflict.project",
            format!("project {:?} is not [a-z0-9][a-z0-9_-]{{0,31}}", project),
        ));
        return result;
    }
    let dir = project_dir(project);
    if !dir.join("compose.yaml").exists() {
        result.checks.push(failure_check(
            "conflict.project",
            format!(
                "no such project {project} ({} has no compose.yaml)",
                dir.display()
            ),
        ));
        return result;
    }

    // The health as one read, no wait (the operator verb checks, the
    // install waited).
    let health = match compose(project, &["ps", "--format", "json", "server"]) {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            match ps_health(&text, "server").as_deref() {
                Some("healthy") => Check::pass(
                    "manager.health",
                    format!("project {project} reports healthy"),
                ),
                Some(other) => Check::fail(
                    "manager.health",
                    format!("project {project} reports {other:?}, not healthy"),
                ),
                None => Check::fail(
                    "manager.health",
                    format!("project {project}'s server service has no Health (is it started?)"),
                ),
            }
        }
        Ok(output) => Check::fail(
            "manager.health",
            format!(
                "docker compose ps of project {project} exited {}",
                output.status
            ),
        ),
        Err(error) => Check::fail("manager.health", format!("docker: {error}")),
    };
    result.checks.push(health);

    // The one operator status read, the version from it.
    match status_read(project) {
        Ok(read) => {
            result.version = Some(read.version.clone());
            result.checks.push(Check::pass(
                "manager.status",
                format!(
                    "project {project} reports version {}{}",
                    read.version,
                    read.config_digest
                        .map(|digest| format!(" with configuration digest {digest}"))
                        .unwrap_or_default()
                ),
            ));
        }
        Err(check) => result.checks.push(check),
    }
    result
}

/// `Some(why)` when `docker compose ls --format json`'s listing
/// names `project` whose config files are not `expected` (the project's own
/// compose.yaml): an ambiguous target. No listing of the project, or an
/// unparseable listing, is not ambiguous.
fn compose_ls_ambiguity(listing: &str, project: &str, expected: &Path) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(listing).ok()?;
    let expected = expected.display().to_string();
    for entry in parsed.as_array()? {
        if entry["Name"].as_str() != Some(project) {
            continue;
        }
        let files: Vec<String> = match &entry["ConfigFiles"] {
            serde_json::Value::String(text) => text.split(',').map(str::to_string).collect(),
            serde_json::Value::Array(items) => items
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        if files.iter().any(|file| file == &expected) {
            return None;
        }
        return Some(format!(
            "docker compose ls lists project {project} from {}, not from {expected}",
            files.join(", "),
        ));
    }
    None
}

/// The one bind mount's source in a rendered compose.yaml — the
/// configuration file, the `source:` after `- type: bind`.
fn bind_source(yaml: &str) -> Option<String> {
    let mut lines = yaml.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "- type: bind" {
            continue;
        }
        for candidate in lines.by_ref() {
            let value = candidate.trim();
            if let Some(source) = value.strip_prefix("source: ") {
                return Some(unquote(source));
            }
            if value.starts_with("- ") {
                break; // the next mount began before any source
            }
        }
    }
    None
}

/// The `compose.yaml` source value: a double-quoted string (compose's
/// `quoted`), with `\"` and `\\` the only escapes.
fn unquote(value: &str) -> String {
    let value = value.trim();
    let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
        return value.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `Some(entry)` naming the archive-listing entry (`tar -tzf`'s
/// output) that is an absolute path or contains `..`; a clean listing is
/// `None`.
fn archive_path_offender(listing: &str) -> Option<String> {
    use std::path::Component;
    listing.lines().map(str::trim).find_map(|entry| {
        if entry.is_empty() {
            return None;
        }
        let path = Path::new(entry);
        if path.is_absolute()
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            Some(entry.to_owned())
        } else {
            None
        }
    })
}

/// A failed docker call's message: the exit and stderr's first line.
fn docker_failure(output: &Output) -> String {
    format!(
        "docker exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .next()
            .unwrap_or("")
    )
}

/// The file's sha256 as lowercase hex.
fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

/// The file at mode 0600 (owner-only); platforms without modes
/// simply write the bytes.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut file| file.write_all(bytes))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))
}

/// Sets an existing file's mode to 0600 where the platform has modes.
fn make_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// A result carrying one failed check.
fn failed(operation: &str, project: &str, check: Check) -> DeployResult {
    let mut result = DeployResult::new(operation);
    result.project = Some(project.to_owned());
    result.checks.push(check);
    result
}

/// The project is stopped — `compose ps -q` prints no container id.
fn stopped(project: &str) -> Result<(), Check> {
    let output = compose(project, &["ps", "-q"]).map_err(|e| Check::fail("manager.compose", e))?;
    if !output.status.success() {
        return Err(Check::fail(
            "manager.compose",
            format!("compose ps -q: {}", docker_failure(&output)),
        ));
    }
    if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
        return Err(Check::fail(
            "preflight.running",
            format!(
                "project {project} is running; stop it first: docker compose -p {project} stop"
            ),
        ));
    }
    Ok(())
}

/// Backup of one stopped project, owner-only.
pub fn backup(project: &str, out: &Path) -> DeployResult {
    let fail = |check: Check| failed("container backup", project, check);
    let file = project_dir(project).join("compose.yaml");
    if !file.exists() {
        return fail(Check::fail(
            "conflict.project",
            format!("no project {project}: {} is missing", file.display()),
        ));
    }
    if out.exists() {
        return fail(Check::fail(
            "conflict.exists",
            format!("{} already exists", out.display()),
        ));
    }
    if let Err(check) = stopped(project) {
        return fail(check);
    }
    let Some(name) = out.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return fail(Check::fail(
            "configuration.archive",
            format!("{} names no archive file", out.display()),
        ));
    };
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let volume_mount = format!("{}:/state:ro", volume_name(project));
    let backup_mount = format!("{}:/backup", parent.display());
    let archive_target = format!("/backup/{name}");
    let output = docker(&[
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        &volume_mount,
        "-v",
        &backup_mount,
        "alpine:3",
        "tar",
        "-C",
        "/state",
        "-czf",
        &archive_target,
        ".",
    ]);
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => return fail(Check::fail("manager.archive", docker_failure(&output))),
        Err(e) => return fail(Check::fail("manager.archive", e)),
    };
    let _ = output;
    if let Err(e) = make_private(out) {
        return fail(Check::fail("manager.archive", e));
    }
    let digest = match sha256_file(out) {
        Ok(digest) => digest,
        Err(e) => return fail(Check::fail("release.backup", e)),
    };
    let sha_path = std::path::PathBuf::from(format!("{}.sha256", out.display()));
    if let Err(e) = write_private(&sha_path, format!("{digest}  {name}\n").as_bytes()) {
        return fail(Check::fail("release.backup", e));
    }
    let mut result = DeployResult::new("container backup");
    result.project = Some(project.to_owned());
    result.checks.push(Check::pass(
        "manager.archive",
        format!(
            "archived project {project}'s volume {} to {}",
            volume_name(project),
            out.display()
        ),
    ));
    result.checks.push(Check::pass(
        "manager.digest",
        format!("wrote {} (sha256 {digest})", sha_path.display()),
    ));
    result.paths = vec![out.display().to_string(), sha_path.display().to_string()];
    result
}

/// Restore, verified before replacement.
pub fn restore(project: &str, from: &Path) -> DeployResult {
    let fail = |check: Check| failed("container restore", project, check);
    let file = project_dir(project).join("compose.yaml");
    if !file.exists() {
        return fail(Check::fail(
            "conflict.project",
            format!("no project {project}: {} is missing", file.display()),
        ));
    }
    if !from.exists() {
        return fail(Check::fail(
            "release.backup",
            format!("no archive at {}", from.display()),
        ));
    }
    if let Err(check) = stopped(project) {
        return fail(check);
    }
    let sha_path = std::path::PathBuf::from(format!("{}.sha256", from.display()));
    let recorded = match std::fs::read_to_string(&sha_path) {
        Ok(recorded) => recorded,
        Err(e) => {
            return fail(Check::fail(
                "release.backup",
                format!("{}: {e}", sha_path.display()),
            ));
        }
    };
    let Some(expected) = recorded.split_whitespace().next() else {
        return fail(Check::fail(
            "release.backup",
            format!("{} names no sha256 digest", sha_path.display()),
        ));
    };
    let actual = match sha256_file(from) {
        Ok(actual) => actual,
        Err(e) => return fail(Check::fail("release.backup", e)),
    };
    if actual != expected {
        return fail(Check::fail(
            "release.backup",
            format!(
                "{} does not match {} (sha256 {expected}); verified before replacement",
                from.display(),
                sha_path.display()
            ),
        ));
    }
    let Some(name) = from.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return fail(Check::fail(
            "configuration.archive",
            format!("{} names no archive file", from.display()),
        ));
    };
    let parent = from
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let backup_mount = format!("{}:/backup:ro", parent.display());
    let archive_target = format!("/backup/{name}");
    // The archive's own listing first: no absolute path, no `..`.
    let listing = docker(&[
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        &backup_mount,
        "alpine:3",
        "tar",
        "-tzf",
        &archive_target,
    ]);
    let listing = match listing {
        Ok(output) if output.status.success() => output,
        Ok(output) => return fail(Check::fail("manager.archive", docker_failure(&output))),
        Err(e) => return fail(Check::fail("manager.archive", e)),
    };
    if let Some(entry) = archive_path_offender(&String::from_utf8_lossy(&listing.stdout)) {
        return fail(Check::fail(
            "release.archive_path",
            format!(
                "{} lists {entry:?}: an archive holds relative paths only",
                from.display()
            ),
        ));
    }
    let volume_mount = format!("{}:/state", volume_name(project));
    let extract = docker(&[
        "run",
        "--rm",
        "--network",
        "none",
        "-v",
        &volume_mount,
        "-v",
        &backup_mount,
        "alpine:3",
        "sh",
        "-c",
        &format!("find /state -mindepth 1 -delete && tar -C /state -xzf {archive_target}"),
    ]);
    match extract {
        Ok(output) if output.status.success() => {}
        Ok(output) => return fail(Check::fail("manager.restore", docker_failure(&output))),
        Err(e) => return fail(Check::fail("manager.restore", e)),
    }
    let mut result = DeployResult::new("container restore");
    result.project = Some(project.to_owned());
    result.checks.push(Check::pass(
        "manager.restore",
        format!(
            "restored project {project}'s volume {} from {}",
            volume_name(project),
            from.display()
        ),
    ));
    result.paths = vec![from.display().to_string(), volume_name(project)];
    result
}

/// Preserve-uninstall, or the confirmed purge. `confirm(prompt)` reads the
/// typed confirmation on a terminal: `Ok(the typed line)`, or
/// `Err(why)` when there is none, and then the purge refuses with a
/// `confirmation.*` check (21).
pub fn uninstall(
    project: &str,
    purge: bool,
    confirm: &dyn Fn(&str) -> Result<String, String>,
) -> DeployResult {
    let fail = |check: Check| failed("container uninstall", project, check);
    let file = project_dir(project).join("compose.yaml");
    if !file.exists() {
        return fail(Check::fail(
            "conflict.project",
            format!("no project {project}: {} is missing", file.display()),
        ));
    }
    // An ambiguous target is refused, naming both config files.
    let ambiguous = match docker(&["compose", "ls", "--format", "json"]) {
        Ok(output) if output.status.success() => {
            compose_ls_ambiguity(&String::from_utf8_lossy(&output.stdout), project, &file)
        }
        Ok(output) => return fail(Check::fail("manager.docker", docker_failure(&output))),
        Err(e) => return fail(Check::fail("manager.docker", e)),
    };
    if let Some(why) = ambiguous {
        return fail(Check::fail("conflict.project", why));
    }
    let config = match std::fs::read_to_string(&file)
        .map_err(|e| format!("{}: {e}", file.display()))
        .and_then(|yaml| {
            bind_source(&yaml).ok_or_else(|| "the file names no bind source".to_owned())
        }) {
        Ok(config) => config,
        Err(e) => {
            return fail(Check::fail(
                "configuration.compose_source",
                format!("{}: {e}", file.display()),
            ));
        }
    };
    let volume = volume_name(project);
    if !purge {
        let output = compose(project, &["down"]);
        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => return fail(Check::fail("manager.compose", docker_failure(&output))),
            Err(e) => return fail(Check::fail("manager.compose", e)),
        }
        let mut result = DeployResult::new("container uninstall");
        result.project = Some(project.to_owned());
        result.checks.push(Check::pass(
            "manager.compose",
            format!(
                "removed project {project}'s container and network; kept {}, {config} and volume {volume}",
                project_dir(project).display()
            ),
        ));
        result.paths = vec![project_dir(project).display().to_string(), config, volume];
        return result;
    }
    // The purge names every object it removes, warns, and reads a
    // typed confirmation before removing anything.
    eprintln!("purging project {project}");
    eprintln!("  configuration source: {config}");
    eprintln!("  volume: {volume}");
    eprintln!(
        "warning: project {project}'s pooled credentials, audit history and trust material become irrecoverable"
    );
    let typed = match confirm("type the project name to purge it: ") {
        Ok(line) => line,
        Err(why) => return fail(Check::fail("confirmation.required", why)),
    };
    if typed.trim() != project {
        return fail(Check::fail(
            "confirmation.mismatch",
            "the typed name is not the project name; nothing was removed",
        ));
    }
    let output = compose(project, &["down"]);
    match output {
        Ok(output) if output.status.success() => {}
        Ok(output) => return fail(Check::fail("manager.compose", docker_failure(&output))),
        Err(e) => return fail(Check::fail("manager.compose", e)),
    }
    let volume_output = docker(&["volume", "rm", &volume]);
    match volume_output {
        Ok(output) if output.status.success() => {}
        Ok(output) => return fail(Check::fail("manager.volume", docker_failure(&output))),
        Err(e) => return fail(Check::fail("manager.volume", e)),
    }
    if let Err(e) = std::fs::remove_file(&config) {
        return fail(Check::fail("manager.files", format!("{config}: {e}")));
    }
    if let Err(e) = std::fs::remove_dir_all(project_dir(project)) {
        return fail(Check::fail(
            "manager.files",
            format!("{}: {e}", project_dir(project).display()),
        ));
    }
    let mut result = DeployResult::new("container uninstall");
    result.project = Some(project.to_owned());
    result.checks.push(Check::pass(
        "manager.compose",
        format!("removed project {project}'s container and network"),
    ));
    result.checks.push(Check::pass(
        "manager.volume",
        format!("removed volume {volume}"),
    ));
    result.checks.push(Check::pass(
        "manager.files",
        format!("removed {config} and {}", project_dir(project).display()),
    ));
    result.paths = vec![config, volume, project_dir(project).display().to_string()];
    result
}

#[cfg(test)]
mod tests {
    use super::daemon_resources;
    use super::{image_line, ps_health};
    #[test]
    fn image_line_reads_the_one_reference() {
        assert_eq!(
            image_line(b"services:\n  server:\n    image: \"ghcr.io/x@sha256:abc\"\n"),
            Some("ghcr.io/x@sha256:abc".into())
        );
        assert_eq!(
            image_line(b"    image: ghcr.io/x:tag\n"),
            Some("ghcr.io/x:tag".into())
        );
        assert_eq!(image_line(b"services: {}\n"), None);
        assert_eq!(image_line(b"image: a\nimage: b\n"), None);
    }

    #[test]
    fn ps_health_finds_the_service() {
        let line = r#"{"Service":"server","Health":"healthy","Name":"a"}
{"Service":"other","Health":"starting","Name":"b"}
"#;
        assert_eq!(ps_health(line, "server").as_deref(), Some("healthy"));
        assert_eq!(ps_health(line, "other").as_deref(), Some("starting"));
        assert_eq!(ps_health(line, "absent"), None);
        assert_eq!(ps_health("not json", "server"), None);
    }

    #[test]
    fn daemon_resources_reads_ncpu_and_memtotal() {
        let info = r#"{"NCPU":8,"MemTotal":17179869184,"ServerVersion":"28.0.0"}"#;
        assert_eq!(daemon_resources(info), Ok((8.0, 17179869184)));
        assert!(daemon_resources("{}").is_err());
    }
}

#[cfg(test)]
mod verify_tests {
    use super::judge_context;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;

    use crate::deploy::result::Check;

    /// A good rootless context: Engine 28, Compose 2.20.2, a unix socket.
    fn good() -> (serde_json::Value, serde_json::Value, String) {
        (
            json!({"ServerVersion": "28.0.0", "SecurityOptions": ["name=rootless", "other=x"]}),
            json!({"Endpoints": {"docker": {"Host": "unix:///run/user/1000/docker.sock"}}}),
            "v2.20.2".into(),
        )
    }

    #[test]
    fn good_rootless_context() {
        let (info, context, compose) = good();
        let checks = judge_context(&info, &context, &compose, None);
        assert!(checks.iter().all(|c| c.passed), "{checks:?}");
        assert_eq!(
            checks.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            [
                "preflight.rootless",
                "preflight.local",
                "preflight.engine",
                "preflight.compose",
            ]
        );
    }

    #[test]
    fn rootful_daemon() {
        let (mut info, context, compose) = good();
        info["SecurityOptions"] = json!(["name=seccomp,profile=unconfined"]);
        let checks = judge_context(&info, &context, &compose, None);
        assert_eq!(
            checks
                .iter()
                .find(|c| c.name == "preflight.rootless")
                .unwrap(),
            &Check::fail(
                "preflight.rootless",
                "the Docker daemon is not rootless; rootless mode is required"
            )
        );
        assert!(checks[1..].iter().all(|c| c.passed), "{checks:?}");
    }

    #[test]
    fn tcp_host() {
        let (info, mut context, compose) = good();
        context["Endpoints"]["docker"]["Host"] = json!("tcp://127.0.0.1:2375");
        let checks = judge_context(&info, &context, &compose, None);
        assert!(!checks[1].passed);
        assert!(checks[1].message.contains("tcp://127.0.0.1:2375"));
    }

    #[test]
    fn ssh_host() {
        let (info, mut context, compose) = good();
        context["Endpoints"]["docker"]["Host"] = json!("ssh://deploy@host.example");
        let checks = judge_context(&info, &context, &compose, None);
        assert!(!checks[1].passed);
        assert!(checks[1].message.contains("ssh://"));
    }

    #[test]
    fn engine_27_5_1() {
        let (info, context, compose) = good();
        let mut info = info;
        info["ServerVersion"] = json!("27.5.1");
        let checks = judge_context(&info, &context, &compose, None);
        assert!(!checks[2].passed);
        assert!(checks[2].message.contains("27.5.1"));
    }

    #[test]
    fn engine_28_0_0_passes() {
        let (info, context, compose) = good();
        assert!(judge_context(&info, &context, &compose, None)[2].passed);
    }

    #[test]
    fn compose_2_20_1() {
        let (info, context, _) = good();
        let checks = judge_context(&info, &context, "v2.20.1", None);
        assert!(!checks[3].passed);
        assert!(checks[3].message.contains("2.20.1"));
    }

    #[test]
    fn compose_2_20_2_passes() {
        let (info, context, _) = good();
        assert!(judge_context(&info, &context, "v2.20.2", None)[3].passed);
    }

    /// A temporary directory whose `compose.yaml` gains one override file.
    fn project_with(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{name}-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn override_yaml_is_refused() {
        let dir = project_with("override-yaml");
        fs::write(dir.join("compose.override.yaml"), b"services: {}").unwrap();
        let (info, context, compose) = good();
        let checks = judge_context(&info, &context, &compose, Some(&dir));
        assert_eq!(
            *checks.last().unwrap(),
            Check::fail(
                "preflight.override",
                "compose.override.yaml beside the project file would alter the deployment"
            )
        );
        // None means "not checked": no override check is reported.
        assert_eq!(judge_context(&info, &context, &compose, None).len(), 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn override_yml_is_refused_and_absent_passes() {
        let dir = project_with("override-yml");
        fs::write(dir.join("docker-compose.override.yml"), b"services: {}").unwrap();
        let (info, context, compose) = good();
        let checks = judge_context(&info, &context, &compose, Some(&dir));
        assert_eq!(
            *checks.last().unwrap(),
            Check::fail(
                "preflight.override",
                "docker-compose.override.yml beside the project file would alter the deployment"
            )
        );
        fs::remove_file(dir.join("docker-compose.override.yml")).unwrap();
        let checks = judge_context(&info, &context, &compose, Some(&dir));
        assert!(checks.iter().all(|c| c.passed), "{checks:?}");
        fs::remove_dir(&dir).unwrap();
    }

    // ---- verify_image ----------------------------------------------------

    use super::verify_image;
    use std::collections::HashMap;

    const REPO: &str = "ghcr.io/jaynlabs/jaynshare";
    const VERSION: &str = "0.7.0";

    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{}", crate::bundle::sha256_hex(bytes))
    }

    /// A well-formed stand-in digest that does not need to hash anything.
    fn fake_digest(tag: char) -> String {
        format!("sha256:{}", tag.to_string().repeat(64))
    }

    /// A platform image manifest's exact bytes, as a registry would serve them.
    fn platform_manifest(config_digest: &str, layer_digests: &[String]) -> Vec<u8> {
        let layers: serde_json::Value = layer_digests
            .iter()
            .map(|digest| {
                json!({
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": digest,
                    "size": 1024,
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": 512,
            },
            "layers": layers,
        }))
        .expect("manifest")
    }

    /// An image index's exact bytes, as a registry would serve them.
    fn image_index(manifests: &[(String, Vec<u8>)]) -> Vec<u8> {
        let entries: serde_json::Value = manifests
            .iter()
            .map(|(platform, bytes)| {
                let (os, architecture) = platform.split_once('/').expect("os/architecture");
                json!({
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": digest(bytes),
                    "size": bytes.len(),
                    "platform": { "architecture": architecture, "os": os },
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": entries,
        }))
        .expect("index")
    }

    /// The hand-built fixture: a good `image` record, the bytes a registry
    /// serves for it, and the reference the compose kit names.
    struct Image {
        record: serde_json::Value,
        compose_image: String,
        registry: HashMap<String, Vec<u8>>,
    }

    impl Image {
        fn checks(&self) -> Vec<Check> {
            let record = manifest(Some(self.record.clone()));
            verify_image(&record, &self.compose_image, fetcher(&self.registry))
        }
    }

    fn good_image() -> Image {
        let amd64_layers = vec![fake_digest('1'), fake_digest('2')];
        let arm64_layers = vec![fake_digest('3'), fake_digest('4')];
        let amd64 = platform_manifest(&fake_digest('a'), &amd64_layers);
        let arm64 = platform_manifest(&fake_digest('b'), &arm64_layers);
        let amd64_digest = digest(&amd64);
        let arm64_digest = digest(&arm64);
        let index = image_index(&[
            ("linux/amd64".into(), amd64.clone()),
            ("linux/arm64".into(), arm64.clone()),
        ]);
        let index_digest = digest(&index);
        let record = json!({
            "repository": REPO,
            "tag": VERSION,
            "index_digest": index_digest,
            "platforms": [
                {"platform": "linux/amd64", "manifest_digest": amd64_digest,
                 "config_digest": fake_digest('a'), "layer_digests": amd64_layers},
                {"platform": "linux/arm64", "manifest_digest": arm64_digest,
                 "config_digest": fake_digest('b'), "layer_digests": arm64_layers},
            ],
        });
        let registry = HashMap::from([
            (format!("{REPO}@{index_digest}"), index),
            (format!("{REPO}@{amd64_digest}"), amd64),
            (format!("{REPO}@{arm64_digest}"), arm64),
        ]);
        Image {
            record,
            compose_image: format!("{REPO}@{index_digest}"),
            registry,
        }
    }

    /// A minimal `release.json` for [`ReleaseManifest::parse`], optionally
    /// carrying the `image` record.
    fn manifest(image: Option<serde_json::Value>) -> crate::deploy::release::ReleaseManifest {
        let mut base = json!({
            "schema_version": 1,
            "version": VERSION,
            "commit": "0000000000000000000000000000000000000000",
            "published_at": "2026-09-23T00:00:00Z",
            "key_id": "0123456789ABCDEF",
            "sha256sums_sha256": "unused",
            "artifacts": [],
        });
        if let Some(image) = image {
            base["image"] = image;
        }
        crate::deploy::release::ReleaseManifest::parse(&serde_json::to_vec(&base).unwrap())
            .expect("release.json")
    }

    fn fetcher(
        registry: &HashMap<String, Vec<u8>>,
    ) -> impl Fn(&str) -> Result<Vec<u8>, String> + '_ {
        move |reference: &str| {
            registry
                .get(reference)
                .cloned()
                .ok_or_else(|| format!("no such reference {reference:?}"))
        }
    }

    #[test]
    fn good_image_passes() {
        let image = good_image();
        let checks = image.checks();
        assert!(checks.iter().all(|c| c.passed), "{checks:?}");
        let last = checks.last().unwrap();
        assert_eq!(last.name, "release.image_platform");
        assert!(
            last.message.contains(&image.compose_image),
            "{}",
            last.message
        );
        assert!(last.message.contains("linux/amd64"), "{}", last.message);
        assert!(last.message.contains("linux/arm64"), "{}", last.message);
    }

    #[test]
    fn no_image_record() {
        let image = good_image();
        let checks = verify_image(
            &manifest(None),
            &image.compose_image,
            fetcher(&image.registry),
        );
        assert_eq!(checks[0].name, "release.image");
        assert!(!checks[0].passed);
    }

    #[test]
    fn wrong_repository() {
        let mut image = good_image();
        image.record["repository"] = json!("ghcr.io/other/repo");
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image");
        assert!(!checks[0].passed);
        assert!(
            checks[0].message.contains("repository"),
            "{}",
            checks[0].message
        );
    }

    #[test]
    fn tag_is_not_the_version() {
        let mut image = good_image();
        image.record["tag"] = json!("0.8.0");
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image");
        assert!(checks[0].message.contains("tag"), "{}", checks[0].message);
    }

    #[test]
    fn malformed_digest() {
        let mut image = good_image();
        image.record["index_digest"] = json!("sha256:ABCD");
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image");
        assert!(
            checks[0].message.contains("index_digest"),
            "{}",
            checks[0].message
        );
    }

    #[test]
    fn missing_platform() {
        let mut image = good_image();
        image.record["platforms"].as_array_mut().unwrap().remove(1);
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image");
        assert!(
            checks[0].message.contains("linux/arm64"),
            "{}",
            checks[0].message
        );
    }

    #[test]
    fn mutable_tag_reference() {
        let mut image = good_image();
        image.compose_image = format!("{REPO}:{VERSION}");
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_pin");
        assert!(!checks[0].passed);
        assert!(
            checks[0].message.contains("mutable tag"),
            "{}",
            checks[0].message
        );
        assert!(
            checks[0].message.contains(&image.compose_image),
            "{}",
            checks[0].message
        );
    }

    #[test]
    fn different_digest_reference() {
        let mut image = good_image();
        image.compose_image = format!("{REPO}@{}", fake_digest('9'));
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_pin");
        assert!(
            checks[0].message.contains(&image.compose_image),
            "{}",
            checks[0].message
        );
    }

    #[test]
    fn index_fetch_fails() {
        let mut image = good_image();
        image.registry.remove(&image.compose_image);
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_index");
        assert!(!checks[0].passed);
    }

    #[test]
    fn index_bytes_changed() {
        let mut image = good_image();
        image.registry.get_mut(&image.compose_image).unwrap()[0] ^= 0x20;
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_index");
        assert!(!checks[0].passed);
    }

    #[test]
    fn third_platform_in_index() {
        let mut image = good_image();
        let amd64 = image.registry.get(&image.compose_image).cloned().unwrap();
        let extra = platform_manifest(&fake_digest('c'), &[fake_digest('5')]);
        let served = image_index(&[
            ("linux/amd64".into(), amd64),
            ("linux/arm64".into(), extra.clone()),
            ("linux/riscv64".into(), extra),
        ]);
        image.registry.insert(image.compose_image.clone(), served);
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_index");
        assert!(!checks[0].passed);
    }

    #[test]
    fn served_manifest_layer_changed() {
        let mut image = good_image();
        let amd64_digest = image.record["platforms"][0]["manifest_digest"]
            .as_str()
            .unwrap()
            .to_string();
        image
            .registry
            .get_mut(&format!("{REPO}@{amd64_digest}"))
            .unwrap()[0] ^= 0x20;
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_platform");
        assert!(!checks[0].passed);
        assert!(
            checks[0].message.contains("linux/amd64"),
            "{}",
            checks[0].message
        );
    }

    #[test]
    fn recorded_layers_differ_from_manifest() {
        let mut image = good_image();
        image.record["platforms"][0]["layer_digests"][1] = json!(fake_digest('9'));
        let checks = image.checks();
        assert_eq!(checks[0].name, "release.image_platform");
        assert!(!checks[0].passed);
        assert!(
            checks[0].message.contains("linux/amd64"),
            "{}",
            checks[0].message
        );
        assert!(
            checks[0].message.contains("layer 2"),
            "{}",
            checks[0].message
        );
    }

    // ------------------------------------------------------------------
    // The pure helpers of backup/restore/uninstall.

    #[test]
    fn compose_ls_from_another_directory_is_ambiguous() {
        let expected = PathBuf::from("/opt/jaynshare/containers/alpha/compose.yaml");
        let listing = r#"[
            {"Name":"alpha","Status":"exited","ConfigFiles":"/elsewhere/alpha/compose.yaml"},
            {"Name":"beta","Status":"running","ConfigFiles":"/opt/jaynshare/containers/beta/compose.yaml"}
        ]"#;
        let why = super::compose_ls_ambiguity(listing, "alpha", &expected)
            .expect("a project listed from another directory is ambiguous");
        assert!(why.contains("/elsewhere/alpha/compose.yaml"), "{why}");
        assert!(why.contains(&expected.display().to_string()), "{why}");
        // The project's own compose.yaml is not ambiguous, and neither is a
        // listing without the project or an unparseable one.
        let own = r#"[{"Name":"alpha","Status":"exited","ConfigFiles":"/opt/jaynshare/containers/alpha/compose.yaml"}]"#;
        assert_eq!(super::compose_ls_ambiguity(own, "alpha", &expected), None);
        assert_eq!(super::compose_ls_ambiguity("[]", "alpha", &expected), None);
        assert_eq!(
            super::compose_ls_ambiguity("not json", "alpha", &expected),
            None
        );
    }

    #[test]
    fn bind_source_reads_the_rendered_mount() {
        let yaml = "name: alpha\nservices:\n  server:\n    volumes:\n      - type: bind\n        source: \"/home/op/config.toml\"\n        target: \"/etc/jaynshare/config.toml\"\n        read_only: true\n        bind:\n          create_host_path: false\n      - type: volume\n        source: state\n        target: \"/var/lib/jaynshare\"\n";
        assert_eq!(
            super::bind_source(yaml),
            Some("/home/op/config.toml".into())
        );
        // The render-quoted escapes unquote back to the source path.
        let quoted = "volumes:\n      - type: bind\n        source: \"/home/op/my \\\"conf\\\\ig/config.toml\"\n";
        assert_eq!(
            super::bind_source(quoted),
            Some("/home/op/my \"conf\\ig/config.toml".into())
        );
        assert_eq!(super::bind_source("name: alpha\n"), None);
    }

    #[test]
    fn archive_listing_judges_paths() {
        assert_eq!(
            super::archive_path_offender("./\n./etc/jaynshare\n./var/lib/jaynshare/state\n"),
            None
        );
        assert_eq!(
            super::archive_path_offender("/etc/passwd\n"),
            Some("/etc/passwd".into())
        );
        assert_eq!(
            super::archive_path_offender("a/../b\n"),
            Some("a/../b".into())
        );
    }
}

#[cfg(test)]
mod update_tests {
    use super::{ps_state, replace_image_line};

    #[test]
    fn replace_image_line_swaps_only_the_value() {
        let yaml =
            b"services:\n  server:\n    image: \"ghcr.io/x@sha256:aaa\"\n    read_only: true\n";
        let replaced = replace_image_line(yaml, "ghcr.io/x@sha256:bbb").expect("one image line");
        assert_eq!(
            std::str::from_utf8(&replaced).expect("UTF-8"),
            "services:\n  server:\n    image: \"ghcr.io/x@sha256:bbb\"\n    read_only: true\n"
        );
        // The quoting style of the original line is kept.
        let replaced =
            replace_image_line(b"  image: ghcr.io/x:tag\n", "n@sha256:c").expect("one image line");
        assert_eq!(
            std::str::from_utf8(&replaced).expect("UTF-8"),
            "  image: n@sha256:c\n"
        );
        // None when the file has no or two `image:` lines.
        assert!(replace_image_line(b"services: {}\n", "x").is_none());
        assert!(replace_image_line(b"image: a\nimage: b\n", "x").is_none());
    }

    #[test]
    fn ps_state_reads_the_running_state() {
        let line = "{\"Service\":\"server\",\"State\":\"running\",\"Health\":\"healthy\"}\n";
        assert_eq!(ps_state(line, "server").as_deref(), Some("running"));
        assert_eq!(ps_state(line, "other"), None);
        assert_eq!(ps_state("{\"Service\":\"server\"}\n", "server"), None);
        assert_eq!(ps_state("not json", "server"), None);
    }
}

#[cfg(test)]
mod listener_tests {
    use super::check_listeners;

    /// Judges one configuration document through the product's own check.
    fn judged(name: &str, config: &str) -> Vec<crate::deploy::result::Check> {
        let dir =
            std::env::temp_dir().join(format!("container-listeners-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        let path = dir.join("config.toml");
        std::fs::write(&path, config).expect("the configuration");
        let checks = check_listeners(&path);
        let _ = std::fs::remove_dir_all(&dir);
        checks
    }

    fn named<'a>(
        checks: &'a [crate::deploy::result::Check],
        name: &str,
    ) -> &'a crate::deploy::result::Check {
        checks.iter().find(|c| c.name == name).expect("the check")
    }

    #[test]
    fn wildcard_loopback_and_closed_list_pass_inside_the_container() {
        for address in ["0.0.0.0", "[::]", "127.0.0.1", "10.0.0.5", "[fd00::5]"] {
            let checks = judged(
                "wild",
                &format!("version = 1\n\n[data_plane]\nlisten = \"{address}:17421\"\n"),
            );
            let check = named(&checks, "preflight.listener.data_plane");
            assert!(check.passed, "{address}: {}", check.message);
        }
    }

    #[test]
    fn everything_off_the_closed_list_fails_naming_the_address() {
        for address in ["8.8.8.8", "169.254.1.1", "224.0.0.1", "[fe80::1]"] {
            let checks = judged(
                "off-list",
                &format!("version = 1\n\n[data_plane]\nlisten = \"{address}:17421\"\n"),
            );
            let check = named(&checks, "preflight.listener.data_plane");
            assert!(!check.passed, "{address}: {}", check.message);
            assert!(check.message.contains(address));
        }
    }

    #[test]
    fn the_proxy_listener_is_judged_only_when_mitm_is_enabled() {
        let on = judged(
            "mitm-on",
            "version = 1\n[mitm]\nenabled = true\nlisten = \"0.0.0.0:17422\"\n",
        );
        assert!(named(&on, "preflight.listener.proxy").passed, "{on:?}");
        let off = judged(
            "mitm-off",
            "version = 1\n[mitm]\nenabled = false\nlisten = \"8.8.8.8:17422\"\n",
        );
        assert!(off.iter().all(|c| c.name != "preflight.listener.proxy"));
        let global = judged(
            "mitm-global",
            "version = 1\n[mitm]\nenabled = true\nlisten = \"8.8.8.8:17422\"\n",
        );
        assert!(!named(&global, "preflight.listener.proxy").passed);
    }

    #[test]
    fn the_absent_data_plane_table_leaves_the_default_loopback_listener() {
        let checks = judged("default", "name = \"pool\"\n");
        let check = named(&checks, "preflight.listener.data_plane");
        assert!(check.passed, "{}", check.message);
        assert!(
            check.message.contains("127.0.0.1:17421"),
            "{}",
            check.message
        );
    }

    #[test]
    fn a_non_numeric_listen_is_a_failure() {
        let checks = judged(
            "non-numeric",
            "version = 1\n\n[data_plane]\nlisten = \"localhost:17421\"\n",
        );
        let check = named(&checks, "preflight.listener.data_plane");
        assert!(!check.passed, "{}", check.message);
        assert!(check.message.contains("numeric"), "{}", check.message);
    }
}
