//! Container deployment. The fake `docker` (`fake_tools::FakeTools`)
//! answers every test but the real-image ones, which skip without a Docker
//! daemon.

#[allow(unused_imports)]
use crate::fake_tools::FakeTools;
#[allow(unused_imports)]
use crate::harness::{cli_pty, cli_raw, isolated_env, private_dir, scratch};
#[allow(unused_imports)]
use crate::release_fx::{
    FIXTURE_VERSION, ImageFx, OCI_REPOSITORY, ReleaseKey, compose_kit_zip, oci_digest,
    platform_manifest, sha256_hex, sha256sums, write_release,
};

// ------------------------------------------------------------------ the image checks

use crate::bundle::config_root;
use crate::harness::cli_pty_answers;

use std::path::Path;

/// Writes one installed project's `compose.yaml` the way `compose::render`
/// shapes it (one read-only bind source, one project volume) and
/// the configuration source file it names. Returns the project directory.
fn installed_project(home: &Path, name: &str) -> std::path::PathBuf {
    let config = home.join("config").join(format!("{name}.toml"));
    std::fs::create_dir_all(config.parent().expect("config parent")).expect("config directory");
    std::fs::write(&config, "# the operator's configuration\n").expect("config file");
    let dir = config_root(home).join("containers").join(name);
    std::fs::create_dir_all(&dir).expect("project directory");
    let image = format!("registry.example.com/jaynshare@sha256:{}", "a".repeat(64));
    std::fs::write(
        dir.join("compose.yaml"),
        format!(
            "name: {name}\nservices:\n  server:\n    image: \"{image}\"\n    read_only: true\n    volumes:\n      - type: bind\n        source: \"{}\"\n        target: \"/etc/jaynshare/config.toml\"\n        read_only: true\n        bind:\n          create_host_path: false\n      - type: volume\n        source: state\n        target: \"/var/lib/jaynshare\"\n    environment:\n      JAYNSHARE_CONFIG: \"/etc/jaynshare/config.toml\"\nvolumes:\n  state: {{}}\n",
            config.display()
        ),
    )
    .expect("compose.yaml");
    dir
}

/// The `run`-rule helper the fake `docker` executes for the backup's tar
/// call: it receives the whole call's arguments after `run` (`{argv}`) and
/// writes the archive the `-czf` target names, at the `/backup` mount's
/// host path.
fn write_backup_helper(root: &Path) -> std::path::PathBuf {
    let script = root.join("fake-backup.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\ndir=\"\"\nname=\"\"\nprev=\"\"\nfor a in \"$@\"; do\n  if [ \"$prev\" = \"-v\" ] && [ \"${a%:/backup}\" != \"$a\" ]; then dir=\"${a%:/backup}\"; fi\n  if [ \"$prev\" = \"-czf\" ]; then name=\"$a\"; fi\n  prev=\"$a\"\ndone\nif [ -z \"$dir\" ] || [ -z \"$name\" ]; then exit 1; fi\nprintf 'backup bytes\\n' > \"$dir/${name#/backup/}\"\n",
    )
    .expect("backup helper");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("backup helper mode");
    }
    script
}

/// The calls that removed or pruned something: `docker` argvs naming a
/// daemon-wide prune, or the `-v` short removal flag.
fn pruned_or_short_flagged(calls: &[Vec<String>]) -> Vec<Vec<String>> {
    calls
        .iter()
        .filter(|argv| {
            argv.iter().any(|a| {
                a.contains("prune") || a == "-v" || a.ends_with(" -v") || a.contains(" -v")
            })
        })
        .cloned()
        .collect()
}

/// Removal touches only the named project:
/// preserve keeps the configuration and volume, the typed-confirmed purge
/// removes only the named objects, and backup/restore touch one stopped
/// project owner-only.
#[tokio::test(flavor = "multi_thread")]
async fn removal_touches_only_the_named_project() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("removal-touches-named");
    let home = root.join("home");
    private_dir(&home);
    let tools = FakeTools::new(&root, &["docker"]);
    let env = [isolated_env(&home), tools.env()].concat();

    // Two installed projects, without `container install`: the rendered
    // compose.yaml and the configuration source each names.
    let alpha_dir = installed_project(&home, "alpha");
    installed_project(&home, "beta");
    let alpha_compose = alpha_dir.join("compose.yaml").display().to_string();

    // 1. Preserve uninstall of alpha: exit 0; only alpha's runtime objects
    // are removed; the project directory and configuration source remain.
    let (code, stdout, stderr) = cli_raw(
        &["container", "uninstall", "--project", "alpha"],
        &env,
        None,
    );
    assert_eq!(code, 0, "preserve uninstall succeeds: {stderr}");
    let calls = tools.calls("docker");
    assert!(
        calls
            .iter()
            .any(|argv| argv == &["compose", "-p", "alpha", "-f", &alpha_compose, "down"]),
        "the down call names the project: {calls:?}"
    );
    assert!(
        pruned_or_short_flagged(&calls).is_empty(),
        "no prune and no -v: {:?}",
        pruned_or_short_flagged(&calls)
    );
    assert!(
        !calls
            .iter()
            .any(|argv| argv.iter().any(|a| a.contains("beta"))),
        "beta is untouched: {calls:?}"
    );
    assert!(
        project_compose_path_exists(&home, "alpha"),
        "the project stays"
    );
    assert!(
        home.join("config/alpha.toml").exists(),
        "the configuration source stays"
    );
    let _ = stdout;

    // 2. Purge without a terminal: 21, and nothing is removed.
    let before_purge = tools.calls("docker").len();
    let (code, _, stderr) = cli_raw(
        &["container", "uninstall", "--project", "alpha", "--purge"],
        &env,
        None,
    );
    assert_eq!(code, 21, "purge is interactive-only: {stderr}");
    for argv in &tools.calls("docker")[before_purge..] {
        assert!(
            !argv.iter().any(|a| a == "down"),
            "no down before confirmation: {argv:?}"
        );
        assert!(
            !argv.iter().any(|a| a == "volume"),
            "no volume rm before confirmation: {argv:?}"
        );
    }
    assert!(
        project_compose_path_exists(&home, "alpha"),
        "nothing removed"
    );

    // 3. Purge on a pty, answering `beta` (wrong): 21, nothing removed.
    let (code, transcript) = cli_pty_answers(
        "removal-touches-named-purge-wrong",
        &["container", "uninstall", "--project", "alpha", "--purge"],
        &env,
        &[("type the project name to purge it: ", "beta\n")],
    );
    assert_eq!(code, 21, "the wrong typed name refuses: {transcript}");
    assert!(
        transcript.contains("alpha"),
        "the plan names the project: {transcript}"
    );
    assert!(
        project_compose_path_exists(&home, "alpha"),
        "nothing removed"
    );
    assert!(
        home.join("config/alpha.toml").exists(),
        "the configuration source stays"
    );

    // 4. Purge answering `alpha`: down, then `volume rm alpha_state`; the
    // configuration file and project directory are gone; beta untouched;
    // never a prune.
    let before_confirmed = tools.calls("docker").len();
    let (code, transcript) = cli_pty_answers(
        "removal-touches-named-purge",
        &["container", "uninstall", "--project", "alpha", "--purge"],
        &env,
        &[("type the project name to purge it: ", "alpha\n")],
    );
    assert_eq!(code, 0, "the confirmed purge removes: {transcript}");
    let calls = &tools.calls("docker")[before_confirmed..];
    let down_at = calls
        .iter()
        .position(|argv| argv.last() == Some(&"down".to_string()))
        .expect("the purge runs down");
    let volume_at = calls
        .iter()
        .position(|argv| argv == &["volume", "rm", "alpha_state"])
        .expect("the purge removes the volume");
    assert!(down_at < volume_at, "down first, then volume rm: {calls:?}");
    assert!(
        pruned_or_short_flagged(calls).is_empty(),
        "no prune and no -v: {:?}",
        pruned_or_short_flagged(calls)
    );
    assert!(
        !project_compose_path_exists(&home, "alpha"),
        "the project is gone"
    );
    assert!(
        !home.join("config/alpha.toml").exists(),
        "the configuration source is gone"
    );
    let beta_dir = config_root(&home).join("containers/beta");
    assert!(
        beta_dir.join("compose.yaml").exists(),
        "beta's files are untouched"
    );
    assert!(
        home.join("config/beta.toml").exists(),
        "beta's configuration source stays"
    );

    // 5. A project that does not exist: 8.
    let (code, _, stderr) = cli_raw(
        &["container", "uninstall", "--project", "gamma"],
        &env,
        None,
    );
    assert_eq!(code, 8, "a missing project refuses: {stderr}");
    assert!(
        stderr.contains("gamma"),
        "the refusal names the project: {stderr}"
    );

    // 6. `compose ls` listing beta from another directory: ambiguous, 8.
    tools
        .rule("docker", &["compose", "ls"])
        .times(1)
        .stdout("[{\"Name\":\"beta\",\"Status\":\"exited\",\"ConfigFiles\":\"/elsewhere/beta/compose.yaml\"}]\n");
    let (code, _, stderr) = cli_raw(&["container", "uninstall", "--project", "beta"], &env, None);
    assert_eq!(code, 8, "an ambiguous project refuses: {stderr}");
    assert!(
        stderr.contains("/elsewhere/beta/compose.yaml"),
        "the refusal names the other directory's config: {stderr}"
    );
    assert!(
        stderr.contains("containers/beta/compose.yaml"),
        "the refusal names the project's own compose.yaml: {stderr}"
    );
    assert!(beta_dir.join("compose.yaml").exists());

    // 7. Backup of a running project: 18, and the archive is never written.
    tools
        .rule("docker", &["compose", "ps", "-q"])
        .times(1)
        .stdout("abc123def\n");
    let out = root.join("backup").join("alpha.tar.gz");
    std::fs::create_dir_all(out.parent().expect("out parent")).expect("backup directory");
    let (code, _, stderr) = cli_raw(
        &[
            "container",
            "backup",
            "--project",
            "beta",
            "--out",
            &out.display().to_string(),
        ],
        &env,
        None,
    );
    assert_eq!(code, 18, "a running project refuses backup: {stderr}");
    assert!(
        stderr.contains("stop it first"),
        "the refusal says how to stop: {stderr}"
    );
    assert!(!out.exists(), "a running project writes no archive");

    // 8. Backup to an existing file: 8.
    std::fs::write(&out, "already there\n").expect("the existing archive");
    let (code, _, stderr) = cli_raw(
        &[
            "container",
            "backup",
            "--project",
            "beta",
            "--out",
            &out.display().to_string(),
        ],
        &env,
        None,
    );
    assert_eq!(code, 8, "an existing archive refuses: {stderr}");
    assert!(
        !calls_mount_volume_read_write(&tools),
        "no run mounted the volume read-write: {calls:?}"
    );

    // 9. Backup of the stopped project: the throwaway container mounts the
    // volume read-only with `--network none`, and the archive and its
    // digest come out owner-only (0600). The `run` rule executes a small
    // shell script that writes the archive at the mounted path.
    tools
        .rule("docker", &["run"])
        .times(1)
        .run(&write_backup_helper(&root), &["{argv}"]);
    let archive = root.join("backup").join("beta.tar.gz");
    let (code, _, stderr) = cli_raw(
        &[
            "container",
            "backup",
            "--project",
            "beta",
            "--out",
            &archive.display().to_string(),
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "the stopped project backs up: {stderr}");
    let run_calls: Vec<Vec<String>> = tools
        .calls("docker")
        .into_iter()
        .filter(|argv| argv.contains(&"run".to_string()))
        .collect();
    assert_eq!(run_calls.len(), 1, "one run call: {run_calls:?}");
    assert!(
        run_calls[0]
            .windows(2)
            .any(|pair| pair == ["-v", "beta_state:/state:ro"]),
        "the volume is mounted read-only: {:?}",
        run_calls[0]
    );
    assert!(
        run_calls[0]
            .windows(2)
            .any(|pair| pair == ["--network", "none"]),
        "the throwaway container has no network: {:?}",
        run_calls[0]
    );
    assert!(
        !calls_mount_volume_read_write(&tools),
        "no run mounted the volume read-write: {run_calls:?}"
    );
    assert_eq!(mode_of(&archive), 0o600, "the archive is owner-only");
    let sha = std::path::PathBuf::from(format!("{}.sha256", archive.display()));
    assert_eq!(mode_of(&sha), 0o600, "the digest file is owner-only");
    let recorded = std::fs::read_to_string(&sha).expect("the digest file");
    assert_eq!(
        recorded.split_whitespace().count(),
        2,
        "the digest file records a digest and the archive's name: {recorded}"
    );
    assert_ne!(
        recorded.split_whitespace().next(),
        Some("backup"),
        "the digest file records a digest, not the archive's bytes: {recorded}"
    );

    // 10. Restore with a tampered digest: 17, and no run that mounts the
    // volume read-write (verified before replacement).
    let digest = recorded.split_whitespace().next().expect("the digest");
    let tampered = format!("{}  alpha.tar.gz\n", "0".repeat(digest.len().min(64)));
    std::fs::write(&sha, tampered).expect("the tampered digest");
    let (code, _, stderr) = cli_raw(
        &[
            "container",
            "restore",
            "--project",
            "beta",
            "--from",
            &archive.display().to_string(),
        ],
        &env,
        None,
    );
    assert_eq!(code, 17, "a tampered archive refuses: {stderr}");
    assert!(
        !calls_mount_volume_read_write(&tools),
        "no run mounted the volume read-write: {:?}",
        tools.calls("docker")
    );
}

/// Whether the project directory's compose.yaml exists.
fn project_compose_path_exists(home: &Path, name: &str) -> bool {
    config_root(home)
        .join("containers")
        .join(name)
        .join("compose.yaml")
        .exists()
}

/// Whether any recorded `docker run` mounts a `:/state` volume without
/// `:ro` (the restore replacement would).
fn calls_mount_volume_read_write(tools: &FakeTools) -> bool {
    tools.calls("docker").iter().any(|argv| {
        argv.windows(2)
            .any(|pair| pair[0] == "-v" && pair[1].ends_with(":/state"))
    })
}

/// The file's mode (0 where the platform has none).
#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .expect("the file's metadata")
        .permissions()
        .mode()
        & 0o777
}
#[cfg(not(unix))]
fn mode_of(_: &Path) -> u32 {
    0
}

use serde_json::{Value, json};
use std::path::PathBuf;

/// One variant's rig under `root`: a home, a fake `docker` with its own
/// rules directory, and the environment that runs the CLI against both.
/// `root` is always the scenario's own scratch subtree, so the roots stay
/// distinct per scenario.
fn rig(root: &Path) -> (PathBuf, FakeTools, Vec<(String, String)>) {
    let home = root.join("home");
    private_dir(&home);
    let tools = FakeTools::new(&root.join("fake-docker"), &["docker"]);
    let env = [isolated_env(&home), tools.env()].concat();
    (home, tools, env)
}

/// The context answer accepts: one local unix socket.
const LOCAL_CONTEXT: &str = "unix:///run/user/1000/docker.sock";

/// `docker info --format '{{json.}}'`: rootless, Engine 28, eight CPUs and
/// 16 GiB — the daemon's machine.
fn good_info() -> Value {
    json!({
        "NCPU": 8,
        "MemTotal": 16i64 * 1024 * 1024 * 1024,
        "ServerVersion": "28.3.2",
        "SecurityOptions": ["name=rootless"],
    })
}

/// `docker context inspect`'s one context, over `host`.
fn context_inspect(host: &str) -> String {
    serde_json::to_string(&json!([{ "Endpoints": { "docker": { "Host": host } } }]))
        .expect("context JSON")
}

/// The parsed `config --format json` document the fake answers for the
/// staged file: one `server` service, one bridge network, the good
/// long-form loopback publication; `mutate` makes a variant.
fn document(mutate: impl FnOnce(&mut Value)) -> Value {
    let mut document = json!({
        "name": "alpha",
        "services": {
            "server": {
                "ports": [ {
                    "mode": "host",
                    "protocol": "tcp",
                    "host_ip": "127.0.0.1",
                    "published": "27400",
                    "target": 17421,
                } ],
                "networks": { "pool": null },
            }
        },
        "networks": { "pool": { "driver": "bridge" } },
    });
    mutate(&mut document);
    document
}

/// `docker compose ps --format json server`: healthy.
const HEALTHY_PS: &str = "{\"Service\":\"server\",\"Health\":\"healthy\"}\n";

/// The status envelope `docker compose exec -T server jaynshare status
/// --json` answers with: envelope, `result` naming the version
/// and the configuration digest.
fn status_envelope(version: &str) -> String {
    serde_json::to_string(&json!({
        "ok": true,
        "result": { "version": version, "config_digest": "c".repeat(64) },
    }))
    .expect("status JSON")
}

/// Scripts every docker call `install` makes through these answers.
fn script(tools: &FakeTools, info: &Value, context: &str, compose: &str, document: &Value) {
    tools
        .rule("docker", &["info", "--format"])
        .stdout(&serde_json::to_string(info).expect("info JSON"));
    tools
        .rule("docker", &["context", "inspect"])
        .stdout(&context_inspect(context));
    tools
        .rule("docker", &["compose", "version", "--short"])
        .stdout(compose);
    tools
        .rule("docker", &["compose", "config", "--format", "json"])
        .stdout(&serde_json::to_string(document).expect("document JSON"));
    tools
        .rule("docker", &["ps", "--format", "json"])
        .stdout(HEALTHY_PS);
    tools
        .rule("docker", &["exec", "-T", "server"])
        .stdout(&status_envelope(FIXTURE_VERSION));
}

/// One rig's planted key, release set and `--config` file (0600). `image`
/// replaces the kit's `image:` pin (and the signed lengths beside it), so a
/// kit whose compose.yaml names the wrong reference stays a valid release.
fn rig_install(
    root: &Path,
    key: &ReleaseKey,
    image: Option<&str>,
) -> (PathBuf, FakeTools, Vec<(String, String)>, PathBuf, PathBuf) {
    let (home, tools, env) = rig(root);
    key.plant(&home);
    let release = write_release(
        &home.join("release"),
        key,
        |parts| {
            let Some(image) = image else { return };
            let bytes = compose_kit_zip(image);
            let name = format!(
                "jaynshare-{}-compose.zip",
                parts.manifest["version"].as_str().expect("version")
            );
            let slot = parts
                .artifacts
                .iter_mut()
                .find(|(n, _)| *n == name)
                .expect("the kit's artifact");
            slot.1 = bytes.clone();
            let entry = parts.manifest["artifacts"]
                .as_array_mut()
                .expect("artifacts")
                .iter_mut()
                .find(|entry| entry["filename"] == json!(name))
                .expect("the kit's manifest entry");
            entry["length"] = json!(bytes.len());
            entry["sha256"] = json!(sha256_hex(&bytes));
            parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sha256sums(&parts.artifacts)));
        },
        |_| {},
    );
    let config = root.join("config.toml");
    std::fs::write(&config, "name = \"pool\"\n").expect("the configuration");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
            .expect("0600 config");
    }
    let kit = release.join(format!("jaynshare-{FIXTURE_VERSION}-compose.zip"));
    (home, tools, env, kit, config)
}

/// One `container install` of `project` through the CLI.
fn install(
    env: &[(String, String)],
    kit: &Path,
    config: &Path,
    project: &str,
    publish: &str,
) -> (i32, String, String) {
    cli_raw(
        &[
            "--config",
            &config.display().to_string(),
            "container",
            "install",
            "--project",
            project,
            "--from",
            &kit.display().to_string(),
            "--publish",
            publish,
        ],
        env,
        None,
    )
}

/// `docker` was never asked to start anything (`up`), and for a refusal
/// before the daemon work it was never asked to pull either.
fn assert_no_start(tools: &FakeTools, pull_too: bool) {
    let calls = tools.calls("docker");
    assert!(
        !calls.iter().any(|call| call.iter().any(|arg| arg == "up")),
        "no compose up: {calls:?}"
    );
    if pull_too {
        assert!(
            !calls
                .iter()
                .any(|call| call.first() == Some(&"pull".to_string())),
            "no pull: {calls:?}"
        );
    }
}

/// The image is verified against the signed record before the
/// project is written or started: the good install pulls before it starts,
/// A kit naming a mutable tag is refused (exit 17 `release.image_pin`)
/// before any registry read or project directory, and a registry serving a
/// changed platform manifest under the recorded digest is refused (exit 17
/// `release.image_platform`) before anything starts.
#[tokio::test(flavor = "multi_thread")]
async fn the_image_is_verified_against_the_signed_record_before_start() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("image-verified-against");
    let key = ReleaseKey::generate();

    // The good install: pull before up, the project materialised.
    let (home, tools, env, kit, config) = rig_install(&root.join("good"), &key, None);
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
    assert_eq!(code, 0, "the good install: {out}{err}");
    assert!(
        out.contains(FIXTURE_VERSION),
        "the version is reported: {out}"
    );
    let calls = tools.calls("docker");
    let pull = calls
        .iter()
        .position(|call| call.first() == Some(&"pull".to_string()))
        .expect("the pull");
    let up = calls
        .iter()
        .position(|call| call.iter().any(|arg| arg == "up"))
        .expect("the up");
    assert!(pull < up, "pull before up: {calls:?}");
    assert!(
        crate::bundle::config_root(&home)
            .join("containers/alpha/compose.yaml")
            .exists(),
        "the project is materialised under the configuration root"
    );

    // A kit whose compose.yaml names a mutable tag instead of the digest:
    // A signed lie is still a lie.
    let (home, tools, env, kit, config) = rig_install(
        &root.join("tag"),
        &key,
        Some(&format!("{OCI_REPOSITORY}:{FIXTURE_VERSION}")),
    );
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
    assert_eq!(code, 17, "the tagged kit: {out}{err}");
    assert!(
        format!("{out}{err}").contains("release.image_pin"),
        "the pin check names it: {out}{err}"
    );
    assert_no_start(&tools, true);
    assert!(
        !crate::bundle::config_root(&home)
            .join("containers/alpha")
            .exists(),
        "no project directory is written"
    );

    // A registry serving one changed layer under the recorded digest: the
    // rule is scripted before `script_registry`'s, so it answers first.
    let (home, tools, env, kit, config) = rig_install(&root.join("layer"), &key, None);
    let image = ImageFx::fixture();
    let amd64 = &image.platforms[0];
    let mut layers = amd64.layer_digests.clone();
    layers[0] = oci_digest(b"a changed layer");
    let tampered = platform_manifest(&amd64.config_digest, &layers);
    tools
        .rule(
            "docker",
            &[
                "buildx",
                "imagetools",
                "inspect",
                "--raw",
                &format!("{}@{}", OCI_REPOSITORY, oci_digest(&amd64.manifest)),
            ],
        )
        .stdout(std::str::from_utf8(&tampered).expect("OCI JSON is UTF-8"));
    image.script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
    assert_eq!(code, 17, "the tampered manifest: {out}{err}");
    assert!(
        format!("{out}{err}").contains("release.image_platform"),
        "the platform check names it: {out}{err}"
    );
    assert_no_start(&tools, true);
    assert!(
        !crate::bundle::config_root(&home)
            .join("containers/alpha")
            .exists(),
        "no project directory is written"
    );
}

/// A rootful, remote or old Docker context is refused (exit 18,
/// its `preflight.*` check, nothing started); the good rootless local
/// context passes.
#[tokio::test(flavor = "multi_thread")]
async fn a_rootful_remote_old_or_overridden_context_is_refused() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("rootful-remote-old");
    let key = ReleaseKey::generate();
    let rootful = {
        let mut info = good_info();
        info["SecurityOptions"] = json!(["name=default"]);
        info
    };
    let old_engine = {
        let mut info = good_info();
        info["ServerVersion"] = json!("27.5.1");
        info
    };
    let cases: [(&str, Value, &str, &str, &str); 4] = [
        (
            "rootful",
            rootful,
            LOCAL_CONTEXT,
            "2.29.1",
            "preflight.rootless",
        ),
        (
            "remote",
            good_info(),
            "tcp://192.0.2.1:2375",
            "2.29.1",
            "preflight.local",
        ),
        (
            "old-engine",
            old_engine,
            LOCAL_CONTEXT,
            "2.29.1",
            "preflight.engine",
        ),
        (
            "old-compose",
            good_info(),
            LOCAL_CONTEXT,
            "2.20.1",
            "preflight.compose",
        ),
    ];
    for (name, info, context, compose, check) in cases {
        let (_, tools, env, kit, config) = rig_install(&root.join(name), &key, None);
        ImageFx::fixture().script_registry(&tools);
        script(&tools, &info, context, compose, &document(|_| {}));
        let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
        assert_eq!(code, 18, "{name}: {out}{err}");
        assert!(
            format!("{out}{err}").contains(check),
            "{name} names {check}: {out}{err}"
        );
        assert_no_start(&tools, false);
    }

    // The good context passes.
    let (_, tools, env, kit, config) = rig_install(&root.join("good"), &key, None);
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
    assert_eq!(code, 0, "the good context: {out}{err}");
}

/// Publications must name an explicit private host address:
/// an omitted `host_ip`, `0.0.0.0`, `published: 0`, `network_mode: host`
/// and a second service are each refused (exit 18, no `up`); a
/// `--publish 0.0.0.0:…` is refused with them; the good document passes.
#[tokio::test(flavor = "multi_thread")]
async fn publications_must_name_an_explicit_private_host_address() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("publications-must-name");
    let key = ReleaseKey::generate();
    let wildcard = |d: &mut Value| {
        d["services"]["server"]["ports"][0]["host_ip"] = json!("0.0.0.0");
    };
    let cases: [(&str, Value, &str); 5] = [
        (
            "no-host-ip",
            document(|d| {
                d["services"]["server"]["ports"][0]
                    .as_object_mut()
                    .expect("the ports entry")
                    .remove("host_ip");
            }),
            "preflight.publication",
        ),
        ("wildcard-ip", document(wildcard), "preflight.publication"),
        (
            "random-port",
            document(|d| d["services"]["server"]["ports"][0]["published"] = json!("0")),
            "preflight.publication",
        ),
        (
            "host-network",
            document(|d| d["services"]["server"]["network_mode"] = json!("host")),
            "preflight.network",
        ),
        (
            "second-service",
            document(|d| d["services"]["helper"] = json!({ "image": "busybox" })),
            "preflight.services",
        ),
    ];
    for (name, document, check) in cases {
        let (_, tools, env, kit, config) = rig_install(&root.join(name), &key, None);
        ImageFx::fixture().script_registry(&tools);
        script(&tools, &good_info(), LOCAL_CONTEXT, "2.29.1", &document);
        let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
        assert_eq!(code, 18, "{name}: {out}{err}");
        assert!(
            format!("{out}{err}").contains(check),
            "{name} names {check}: {out}{err}"
        );
        assert_no_start(&tools, false);
    }

    // `--publish 0.0.0.0:27400` renders a wildcard publication; the fake
    // answers what a real Compose would parse out of that file.
    let (_, tools, env, kit, config) = rig_install(&root.join("publish-wildcard"), &key, None);
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(wildcard),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "0.0.0.0:27400");
    assert_eq!(code, 18, "the wildcard publish: {out}{err}");
    assert!(
        format!("{out}{err}").contains("preflight.publication"),
        "the publication check names it: {out}{err}"
    );
    assert_no_start(&tools, false);

    // The good document passes.
    let (_, tools, env, kit, config) = rig_install(&root.join("good"), &key, None);
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
    assert_eq!(code, 0, "the good document: {out}{err}");
}

use crate::linux_fx::{docker, docker_available, head_commit, linux_binary, platform_image};
use std::collections::BTreeMap;
use std::io::Read as _;

/// The platform image is minimal and the kit's container is
/// confined. The image built from the repository's
/// `Dockerfile` holds only the musl binary, a public TLS root bundle,
/// `LICENSE` and `NOTICE.md`, runs as the numeric uid 10001 with a fixed
/// private home, and starts `jaynshare serve`; there is no shell to exec.
/// The shipped Compose kit's service — created against the real daemon
/// gets a read-only root, drops every capability, never gains privilege,
/// keeps a private cgroup namespace, bounds `/tmp`, mounts no device or
/// Docker socket and shares no host namespace.
#[tokio::test(flavor = "multi_thread")]
async fn the_platform_image_and_service_are_minimal_and_confined() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !docker_available() {
        eprintln!("skipping: container: no Docker daemon runs a container within 120 s");
        return;
    }
    let image = platform_image().unwrap_or_else(|e| panic!("{e}"));
    let root = scratch("platform-image-service");

    // The image configuration.
    let config = json_of(
        &docker(&["image", "inspect", &image, "--format", "{{json .Config}}"])
            .expect("docker image inspect"),
        "image config",
    );
    assert_eq!(
        config["User"], "10001:10001",
        "the image runs as a fixed numeric non-root uid/gid"
    );
    assert_eq!(
        config["Entrypoint"],
        serde_json::json!(["/usr/local/bin/jaynshare"]),
        "the entrypoint is the binary"
    );
    assert_eq!(config["Cmd"], serde_json::json!(["serve"]), "serve");
    assert_eq!(
        config["WorkingDir"], "/var/lib/jaynshare",
        "the fixed home is the working directory"
    );
    let env: Vec<String> = config["Env"]
        .as_array()
        .expect("image Env")
        .iter()
        .map(|v| v.as_str().expect("Env entry").to_owned())
        .collect();
    assert!(
        env.iter().any(|e| e == "HOME=/var/lib/jaynshare"),
        ": HOME is the fixed home: {env:?}"
    );
    assert!(
        env.iter()
            .any(|e| e == "JAYNSHARE_CONFIG=/etc/jaynshare/config.toml"),
        ": JAYNSHARE_CONFIG is the fixed path: {env:?}"
    );
    assert!(
        env.len() <= 3
            && env.iter().all(|e| e.starts_with("HOME=")
                || e.starts_with("JAYNSHARE_CONFIG=")
                || e.starts_with("PATH=")),
        "at most PATH joins the two fixed entries: {env:?}"
    );
    assert_eq!(
        config["Healthcheck"]["Test"],
        serde_json::json!(["CMD", "/usr/local/bin/jaynshare", "status", "--check"]),
        "the health check is the binary's own status read"
    );
    let labels = config["Labels"].as_object().expect("image Labels");
    assert_eq!(
        labels["org.opencontainers.image.version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "the labels state the version"
    );
    assert_eq!(
        labels["org.opencontainers.image.revision"].as_str(),
        Some(head_commit().as_str()),
        "the labels state the commit"
    );
    assert_eq!(
        labels["org.opencontainers.image.licenses"].as_str(),
        Some("MIT"),
        "the labels state the licence"
    );
    assert_eq!(
        labels["org.opencontainers.image.source"].as_str(),
        Some("https://github.com/jaynlabs/jaynshare"),
        "the labels state the source repository"
    );

    // The image's file tree, read from `docker image save`'s OCI
    // layout (index.json → manifest → layers, a layer possibly gzipped).
    let image_tar = root.join("image.tar");
    must(
        docker(&[
            "image",
            "save",
            &image,
            "-o",
            &image_tar.display().to_string(),
        ])
        .expect("docker image save"),
        "docker image save",
    );
    let (files, dirs) = read_image_tar(&image_tar);
    assert_eq!(
        files.keys().collect::<Vec<_>>(),
        [
            "LICENSE",
            "NOTICE.md",
            "etc/ssl/certs/ca-certificates.crt",
            "usr/local/bin/jaynshare"
        ],
        "the regular files are exactly the binary, the root bundle, LICENSE and NOTICE.md"
    );
    let binary_bytes =
        std::fs::read(linux_binary().expect("the musl binary")).expect("read the musl binary");
    let bin = &files["usr/local/bin/jaynshare"];
    assert_eq!(bin.mode, 0o555, "the binary is read-execute only");
    assert_eq!(
        bin.bytes, binary_bytes,
        "the image payload is the release binary, byte for byte"
    );
    let roots = &files["etc/ssl/certs/ca-certificates.crt"];
    assert!(!roots.bytes.is_empty(), "the root bundle is present");
    assert!(
        roots.bytes.starts_with(b"-----BEGIN CERTIFICATE-----"),
        "the root bundle begins with a certificate"
    );
    for name in ["LICENSE", "NOTICE.md"] {
        let expected = std::fs::read(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), name))
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(
            files[name].bytes, expected,
            "{name} in the image is the repository's"
        );
    }
    let home = dirs
        .get("var/lib/jaynshare")
        .expect("var/lib/jaynshare is a directory in the image");
    assert_eq!(
        (home.uid, home.gid, home.mode),
        (10001, 10001, 0o700),
        "the service home is owned by the service uid at 0700, so the \
         named volume inherits a writable owner"
    );
    let mut allowed = std::collections::BTreeSet::from([
        "var/lib/jaynshare".to_owned(),
        "etc/jaynshare".to_owned(),
    ]);
    for name in files.keys() {
        for ancestor in std::path::Path::new(name).ancestors().skip(1) {
            let ancestor = ancestor.to_string_lossy();
            if !ancestor.is_empty() {
                allowed.insert(ancestor.into_owned());
            }
        }
    }
    for base in ["var/lib/jaynshare", "etc/jaynshare"] {
        for ancestor in std::path::Path::new(base).ancestors().skip(1) {
            let ancestor = ancestor.to_string_lossy();
            if !ancestor.is_empty() {
                allowed.insert(ancestor.into_owned());
            }
        }
    }
    for name in dirs.keys() {
        assert!(
            allowed.contains(name),
            "{name} is neither a parent of the payload nor etc/jaynshare"
        );
    }

    // No shell to exec.
    let shell = docker(&[
        "run",
        "--rm",
        "--entrypoint",
        "/bin/sh",
        &image,
        "-c",
        "true",
    ])
    .expect("docker run");
    assert!(
        !shell.status.success(),
        ": /bin/sh ran; the image admits no shell"
    );

    // The kit's service, created against the real daemon.
    let kit = std::fs::read_to_string(format!(
        "{}/tools/release/compose-kit/compose.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read the shipped compose kit");
    let compose_path = root.join("compose.yaml");
    std::fs::write(&compose_path, kit.replace("@IMAGE@", &image))
        .expect("write the scenario compose.yaml");
    let config_dir = root.join("config-dir");
    private_dir(&config_dir);
    std::fs::write(
        config_dir.join("config.toml"),
        "# any content; create does not start it\n",
    )
    .expect("write the scenario config.toml");
    let port = free_port();
    let project = format!("platform-image-service-{}", std::process::id());
    let envs: Vec<(&str, String)> = vec![
        ("JAYNSHARE_CONFIG_DIR", config_dir.display().to_string()),
        ("JAYNSHARE_HOST_IP", "127.0.0.1".to_owned()),
        ("JAYNSHARE_HOST_PORT", port.to_string()),
    ];

    struct ComposeDown {
        project: String,
    }
    impl Drop for ComposeDown {
        fn drop(&mut self) {
            // By project name alone: the kit's file needs JAYNSHARE_HOST_*
            // to interpolate, so `-f` without them fails.
            let _ = std::process::Command::new("docker")
                .args(["compose", "-p", &self.project, "down", "-v"])
                .output();
        }
    }
    let _guard = ComposeDown {
        project: project.clone(),
    };

    let args = |rest: &[&str]| -> Vec<String> {
        [
            "compose".to_owned(),
            "-p".to_owned(),
            project.clone(),
            "-f".to_owned(),
            compose_path.display().to_string(),
        ]
        .into_iter()
        .chain(rest.iter().map(|s| (*s).to_owned()))
        .collect()
    };
    must(
        run_env("docker", &args(&["create"]), &envs),
        "compose create",
    );
    let ids = String::from_utf8_lossy(
        &must(
            run_env("docker", &args(&["ps", "-aq", "server"]), &envs),
            "compose ps -aq server",
        )
        .stdout,
    )
    .trim()
    .to_owned();
    assert!(!ids.is_empty(), "compose created no server container");
    let container = json_of(
        &docker(&["inspect", &ids]).expect("docker inspect"),
        "container inspect",
    )[0]
    .clone();
    let host = &container["HostConfig"];
    let conf = &container["Config"];
    assert_eq!(
        host["ReadonlyRootfs"].as_bool(),
        Some(true),
        "the service's root filesystem is read-only"
    );
    assert!(
        has_str(&host["CapDrop"], "ALL"),
        "the service drops every capability"
    );
    assert!(
        host["CapAdd"].as_array().is_none_or(|a| a.is_empty()),
        "the service adds no capability"
    );
    assert_eq!(
        host["Privileged"].as_bool(),
        Some(false),
        "the service is not privileged"
    );
    assert!(
        has_str(&host["SecurityOpt"], "no-new-privileges:true"),
        "the service cannot gain privilege"
    );
    assert_eq!(
        host["CgroupnsMode"].as_str(),
        Some("private"),
        "a private cgroup namespace"
    );
    assert!(
        host["Tmpfs"]["/tmp"]
            .as_str()
            .unwrap_or_default()
            .contains("size="),
        ": /tmp is a size-bounded tmpfs"
    );
    assert!(
        host["Devices"].as_array().is_none_or(|a| a.is_empty()),
        "the service mounts no device"
    );
    let sources = [
        host["Binds"].as_array(),
        host["Mounts"].as_array(),
        container["Mounts"].as_array(),
    ]
    .into_iter()
    .flatten()
    .flatten()
    .map(|v| v.as_str().unwrap_or_default().to_owned())
    .collect::<Vec<_>>();
    for source in sources {
        assert!(
            !source.ends_with("docker.sock"),
            "{source} mounts the Docker socket"
        );
    }
    let network_mode = host["NetworkMode"].as_str().unwrap_or_default();
    assert_ne!(network_mode, "host", "no host network");
    assert!(
        !network_mode.starts_with("container:"),
        "no foreign container's network"
    );
    for mode in ["PidMode", "IpcMode", "UsernsMode", "UTSMode"] {
        assert_ne!(
            host[mode].as_str(),
            Some("host"),
            "{mode} shares no host namespace"
        );
    }
    assert_eq!(
        conf["User"], "10001:10001",
        "the service runs as the image's numeric non-root uid"
    );
}

/// `program <args>` with `envs` set, output captured.
fn run_env(program: &str, args: &[String], envs: &[(&str, String)]) -> std::process::Output {
    let mut command = std::process::Command::new(program);
    command.envs(envs.iter().cloned());
    command
        .stdin(std::process::Stdio::null())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("{program} {args:?}: {e}"))
}

/// An output that had to succeed.
fn must(output: std::process::Output, what: &str) -> std::process::Output {
    assert!(
        output.status.success(),
        "{what} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// The JSON the output's stdout holds.
fn json_of(output: &std::process::Output, what: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{what}: {e}"))
}

/// Whether a JSON array holds a given string.
fn has_str(value: &Value, wanted: &str) -> bool {
    value
        .as_array()
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(wanted)))
}

/// One ephemeral loopback port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("the bound port")
        .port()
}

/// A regular file from the image's layers.
struct ImageFile {
    mode: u32,
    bytes: Vec<u8>,
}

/// A directory from the image's layers.
struct ImageDir {
    uid: u64,
    gid: u64,
    mode: u32,
}

/// Reads `docker image save`'s OCI layout: `index.json` → manifest → layers,
/// each layer a (possibly gzipped) tar. Regular files and directories across
/// all layers; a symlink, hard link, device or whiteout is a failure.
fn read_image_tar(
    path: &std::path::Path,
) -> (BTreeMap<String, ImageFile>, BTreeMap<String, ImageDir>) {
    fn blob(name: &str) -> String {
        let digest = name.strip_prefix("sha256:").expect("a sha256 digest");
        format!("blobs/sha256/{digest}")
    }
    fn name_of(entry: &std::path::Path) -> String {
        entry
            .to_string_lossy()
            .trim_start_matches("./")
            .trim_end_matches('/')
            .to_owned()
    }
    fn whiteout(name: &str) -> bool {
        name.starts_with(".wh.") || name.contains("/.wh.")
    }

    let saved = std::fs::File::open(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut blobs = BTreeMap::new();
    for entry in tar::Archive::new(saved)
        .entries()
        .expect("the saved OCI layout")
    {
        let mut entry = entry.expect("layout entry");
        let name = name_of(&entry.path().expect("layout entry path"));
        if name.is_empty() {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        blobs.insert(name, bytes);
    }

    let index: Value =
        serde_json::from_slice(&blobs["index.json"]).expect("the layout's index.json");
    let manifest: Value = serde_json::from_slice(
        &blobs[&blob(
            index["manifests"][0]["digest"]
                .as_str()
                .expect("manifest digest"),
        )],
    )
    .expect("the manifest");
    let layers = manifest["layers"].as_array().expect("manifest layers");

    let mut files = BTreeMap::new();
    let mut dirs = BTreeMap::new();
    for layer in layers {
        let bytes = &blobs[&blob(layer["digest"].as_str().expect("layer digest"))];
        let reader: Box<dyn std::io::Read> = if bytes.starts_with(&[0x1f, 0x8b]) {
            Box::new(flate2::read::GzDecoder::new(&bytes[..]))
        } else {
            Box::new(&bytes[..])
        };
        for entry in tar::Archive::new(reader).entries().expect("layer entries") {
            let mut entry = entry.expect("layer entry");
            let name = name_of(&entry.path().expect("layer entry path"));
            if name.is_empty() {
                continue;
            }
            assert!(!whiteout(&name), "{name} is a whiteout");
            let header = entry.header();
            match header.entry_type() {
                tar::EntryType::Regular => {
                    let mode = header.mode().expect("file mode") & 0o7777;
                    let mut contents = Vec::new();
                    entry
                        .read_to_end(&mut contents)
                        .unwrap_or_else(|e| panic!("{name}: {e}"));
                    files.insert(
                        name,
                        ImageFile {
                            mode,
                            bytes: contents,
                        },
                    );
                }
                tar::EntryType::Directory => {
                    let (uid, gid, mode) = (
                        header.uid().expect("directory uid"),
                        header.gid().expect("directory gid"),
                        header.mode().expect("directory mode") & 0o7777,
                    );
                    dirs.insert(name, ImageDir { uid, gid, mode });
                }
                tar::EntryType::Symlink | tar::EntryType::Link => {
                    panic!("{name} is a symlink or hard link")
                }
                tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
                    panic!("{name} is a device or fifo")
                }
                tar::EntryType::XHeader | tar::EntryType::XGlobalHeader => {}
                other => panic!("{name} is an unexpected entry ({other:?})"),
            }
        }
    }
    (files, dirs)
}

/// One installed project's metadata holds
/// only the fixed configuration-path variable, one read-only configuration
/// mount, one project volume and bounded Docker logs — and no secret from
/// the operator's configuration file appears in any file under the project,
/// any `docker` argv or the CLI's output (human and `--json`).
#[tokio::test(flavor = "multi_thread")]
async fn one_project_carries_no_secret_and_only_the_fixed_path() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("project-carries-no-secret");
    let key = ReleaseKey::generate();
    let (home, tools, env, kit, config) = rig_install(&root.join("rig"), &key, None);

    // The operator's configuration holds the needles — plausible values, the
    // operator's bytes. `rig_install` wrote a placeholder; the product never
    // reads the contents, only the path, so the rewrite keeps the
    // 0600 regular file the install checks.
    let needles = [
        "sk-ant-oat01-0needle0-0needle0needle0needle0needle0needle00000",
        "31-ClientSecret-n0t4re4l0ne-9f8e7d6c5b4a3210fedcba9876",
        "project-carries-no-secret operator password",
    ];
    let configuration = format!(
        "# The operator's Jaynshare configuration; the values are\n\
         # this scenario's needles: plausible secrets that must never leak.\n\
         name = \"pool\"\n\
         \n[anthropic]\n\
         # The pooled upstream OAuth token, rotated by the operator.\n\
         oauth_token = \"{}\"\n\
         \n[upstream]\n\
         client_id = \"jaynshare-pool\"\n\
         client_secret = \"{}\"\n\
         password = \"{}\"\n",
        needles[0], needles[1], needles[2],
    );
    std::fs::write(&config, configuration).expect("the configuration");

    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "gamma", "127.0.0.1:27400");
    assert_eq!(code, 0, "the install: {out}{err}");

    // The materialised project's compose.yaml, read as the text `docker
    // compose config --format json` parses. No YAML crate is a dependency;
    // the assertions are on the lines `compose::render` writes.
    let dir = crate::bundle::config_root(&home).join("containers/gamma");
    let compose = std::fs::read_to_string(dir.join("compose.yaml")).expect("the compose.yaml");
    let lines: Vec<&str> = compose.lines().collect();

    // `environment` is exactly the one fixed-path variable.
    assert_eq!(compose.matches("JAYNSHARE_CONFIG").count(), 1);
    let environment = lines
        .iter()
        .position(|line| *line == "    environment:")
        .expect("the environment block");
    assert_eq!(
        lines[environment + 1],
        "      JAYNSHARE_CONFIG: \"/etc/jaynshare/config.toml\"",
        "the one environment entry is the fixed path"
    );
    assert_eq!(
        lines[environment + 2],
        "    ports:",
        "environment is exactly one entry"
    );

    // Exactly one bind mount — the `--config` file at the fixed
    // path, read-only, no host path created — and exactly one project
    // volume, `state` → `/var/lib/jaynshare`.
    assert_eq!(compose.matches("- type: bind").count(), 1);
    assert_eq!(compose.matches("- type: volume").count(), 1);
    let bind = lines
        .iter()
        .position(|line| *line == "      - type: bind")
        .expect("the bind mount");
    assert_eq!(
        lines[bind + 1],
        format!("        source: \"{}\"", config.display()),
        "the bind source is the --config file"
    );
    assert_eq!(
        lines[bind + 2],
        "        target: \"/etc/jaynshare/config.toml\""
    );
    assert_eq!(lines[bind + 3], "        read_only: true");
    assert_eq!(lines[bind + 4], "        bind:");
    assert_eq!(lines[bind + 5], "          create_host_path: false");
    let volume = lines
        .iter()
        .position(|line| *line == "      - type: volume")
        .expect("the volume mount");
    assert_eq!(lines[volume + 1], "        source: state");
    assert_eq!(lines[volume + 2], "        target: \"/var/lib/jaynshare\"");
    // Project-scoped: Compose names it `gamma_state` (`-p gamma`).
    assert_eq!(lines[0], "name: \"gamma\"");
    let top_volumes = lines
        .iter()
        .rposition(|line| *line == "volumes:")
        .expect("the top-level volumes");
    assert_eq!(lines[top_volumes + 1], "  state: {}");
    assert_eq!(
        top_volumes + 2,
        lines.len(),
        "the only project volume is state"
    );

    // Standard output/error go to a size-rotated local log.
    let logging = lines
        .iter()
        .position(|line| *line == "    logging:")
        .expect("the logging block");
    assert_eq!(lines[logging + 1], "      driver: local");
    assert_eq!(lines[logging + 2], "      options:");
    assert_eq!(lines[logging + 3], "        max-size: \"10m\"");
    assert_eq!(lines[logging + 4], "        max-file: \"3\"");

    // No `env_file`, `secrets`, `configs` or `labels` key anywhere.
    for banned in ["env_file:", "secrets:", "configs:", "labels:"] {
        assert!(
            !lines
                .iter()
                .any(|line| line.trim_start().starts_with(banned)),
            "no {banned} key: {compose}"
        );
    }

    // None of the needles appears in any file under the project
    // directory, any `docker` argv, or the CLI's output (human and --json).
    let scan = |place: &str, text: &str| {
        for needle in needles {
            assert!(
                !text.contains(needle),
                "{place} carries the needle {needle:?}"
            );
        }
    };
    let mut stack = vec![dir.clone()];
    while let Some(path) = stack.pop() {
        if std::fs::metadata(&path).expect("project entry").is_dir() {
            for entry in std::fs::read_dir(&path).expect("project directory") {
                stack.push(entry.expect("project entry").path());
            }
        } else {
            let bytes = std::fs::read(&path).expect("project file");
            scan(
                &path.display().to_string(),
                &String::from_utf8_lossy(&bytes),
            );
        }
    }
    for argv in tools.calls("docker") {
        for argument in argv {
            scan("docker argv", &argument);
        }
    }
    scan("stdout (human)", &out);
    scan("stderr (human)", &err);
    let (code, json_out, json_err) = cli_raw(
        &["--json", "container", "status", "--project", "gamma"],
        &env,
        None,
    );
    assert_eq!(code, 0, "status --json: {json_out}{json_err}");
    scan("stdout (--json)", &json_out);
    scan("stderr (--json)", &json_err);
}

use std::io::Write as _;
use std::time::{Duration, Instant};

/// A staged pre-enrolment client container shares the server
/// service's network namespace and reaches the instance as the loopback
/// operator, while a host caller through the kit's
/// loopback publication arrives under a translated address and is refused
/// The staged container is removed afterwards; the server, the
/// project volume and network and the platform image are all unchanged by
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn a_staged_client_is_loopback_and_a_host_caller_is_not() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !docker_available() {
        eprintln!("skipping: container: no Docker daemon runs a container within 120 s");
        return;
    }
    let image = platform_image().unwrap_or_else(|e| panic!("{e}"));
    let root = scratch("staged-client-loopback");
    let port = free_port();
    let project = format!("staged-client-loopback-{}", std::process::id());

    // The in-container configuration, modelled on deploy-host.sh's minus
    // TLS, the MITM listener and the advertised origins (runs before
    // enrolment, so nothing is advertised yet).
    let config = "\
version = 1\n\
[data_plane]\n\
listen = \"0.0.0.0:17421\"\n\
telemetry_policy = \"forward\"\n\
[data_plane.egress]\n\
mode = \"off\"\n\
[storage]\n\
state_file = \"/var/lib/jaynshare/state/state.json\"\n\
[logging]\n\
directory = \"/var/lib/jaynshare/log\"\n\
level = \"info\"\n\
";

    // The bind configuration first: on Docker Desktop a bind-mounted host
    // file lands as the operator's uid and refuses it, in which case
    // the named-volume fallback below carries the configuration with its
    // permissions.
    let config_dir = root.join("config-dir");
    private_dir(&config_dir);
    std::fs::write(config_dir.join("config.toml"), config).expect("write config.toml");
    let kit = std::fs::read_to_string(format!(
        "{}/tools/release/compose-kit/compose.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read the shipped compose kit");
    let compose_path = root.join("compose.yaml");
    std::fs::write(&compose_path, kit.replace("@IMAGE@", &image)).expect("write compose.yaml");
    let bind_block = "      - type: bind\n        source: ${JAYNSHARE_CONFIG_DIR:?set JAYNSHARE_CONFIG_DIR to the owner-only configuration directory}/config.toml\n        target: /etc/jaynshare/config.toml\n        read_only: true\n        bind: { create_host_path: false }";
    let cfg_volume = format!("{project}-cfg");
    let volume_block = format!(
        "      - type: volume\n        source: {cfg_volume}\n        target: /etc/jaynshare\n        read_only: true"
    );
    let derived = kit
        .replace("@IMAGE@", &image)
        .replacen(bind_block, &volume_block, 1)
        .replace(
            "volumes:\n  state:",
            &format!("volumes:\n  {cfg_volume}:\n    external: true\n  state:"),
        );
    assert_ne!(
        derived,
        kit.replace("@IMAGE@", &image),
        "the bind block moved"
    );

    let envs: Vec<(&str, String)> = vec![
        ("JAYNSHARE_CONFIG_DIR", config_dir.display().to_string()),
        ("JAYNSHARE_HOST_IP", "127.0.0.1".to_owned()),
        ("JAYNSHARE_HOST_PORT", port.to_string()),
    ];
    let args = |rest: &[&str]| -> Vec<String> {
        [
            "compose".to_owned(),
            "-p".to_owned(),
            project.clone(),
            "-f".to_owned(),
            compose_path.display().to_string(),
        ]
        .into_iter()
        .chain(rest.iter().map(|s| (*s).to_owned()))
        .collect()
    };

    struct Down {
        project: String,
        cfg_volume: String,
    }
    impl Drop for Down {
        fn drop(&mut self) {
            // By project name alone: the kit's file needs JAYNSHARE_HOST_*
            // to interpolate, so `-f` without them fails.
            let _ = std::process::Command::new("docker")
                .args(["compose", "-p", &self.project, "down", "-v"])
                .output();
            let _ = std::process::Command::new("docker")
                .args(["volume", "rm", &self.cfg_volume])
                .output();
        }
    }
    let guard = Down {
        project: project.clone(),
        cfg_volume,
    };

    // The bind composition first; the refusal of the bind-mounted
    // configuration (its owner inside the container is not uid 10001) is
    // read from the container's logs and printed below.
    must(
        run_env("docker", &args(&["up", "-d"]), &envs),
        "compose up -d",
    );
    let container = server_container(&project, &compose_path, &envs);
    if !wait_healthy(&container) {
        let logs = run_env("docker", &args(&["logs", "server"]), &envs);
        println!(
            "the bind-mounted configuration was refused, falling back to the named volume:\n{}{}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr)
        );
        must(
            run_env("docker", &args(&["down", "-v"]), &envs),
            "compose down -v",
        );

        // The fallback: the configuration is prepared inside the named
        // volume by a throwaway rootless container, so it is owned by the
        // service uid at the modes (the same hand-over deploy-host.sh
        // and the kit README prescribe), and the compose bind becomes that
        // volume mounted read-only at /etc/jaynshare.
        docker(&["volume", "create", &guard.cfg_volume]).expect("docker volume create");
        feed(
            &[
                "run",
                "--rm",
                "-i",
                "-v",
                &format!("{}:/cfg", guard.cfg_volume),
                "alpine:3",
                "sh",
                "-c",
                "cat > /cfg/config.toml && chown -R 10001:10001 /cfg && chmod 700 /cfg && chmod 600 /cfg/config.toml",
            ],
            config.as_bytes(),
            "the configuration is written into the named volume",
        );
        std::fs::write(&compose_path, &derived).expect("write the derived compose.yaml");
        must(
            run_env("docker", &args(&["up", "-d"]), &envs),
            "compose up -d",
        );
        let container = server_container(&project, &compose_path, &envs);
        assert!(
            wait_healthy(&container),
            "the volume-backed service never turned healthy"
        );

        // ... and the rest of the scenario runs against that composition.
        staged_and_host(&project, &compose_path, &envs, &container, port);
        return;
    }

    staged_and_host(&project, &compose_path, &envs, &container, port);
    drop(guard);
}

/// The server container's id of the current compose project.
fn server_container(
    project: &str,
    compose_path: &std::path::Path,
    envs: &[(&str, String)],
) -> String {
    let args = |rest: &[&str]| -> Vec<String> {
        [
            "compose".to_owned(),
            "-p".to_owned(),
            project.to_owned(),
            "-f".to_owned(),
            compose_path.display().to_string(),
        ]
        .into_iter()
        .chain(rest.iter().map(|s| (*s).to_owned()))
        .collect()
    };
    let id = String::from_utf8_lossy(
        &must(
            run_env("docker", &args(&["ps", "-aq", "server"]), envs),
            "compose ps -aq server",
        )
        .stdout,
    )
    .trim()
    .to_owned();
    assert!(!id.is_empty(), "compose created no server container");
    id
}

/// `docker inspect` the health status until healthy or unhealthy, 60 s.
fn wait_healthy(container: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = inspect_one(container, "{{.State.Health.Status}}");
        match status.as_str() {
            "healthy" => return true,
            "unhealthy" => return false,
            _ if Instant::now() >= deadline => return false,
            _ => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}

/// the staged client (an alpine container in the server's network
/// namespace) reads the operator status as the loopback operator, the host
/// caller through the publication is refused, and afterwards the server, the
/// project volume, network and image are all unchanged.
fn staged_and_host(
    project: &str,
    compose_path: &std::path::Path,
    envs: &[(&str, String)],
    container: &str,
    port: u16,
) {
    // Record: the server's id, StartedAt, health and image id, and the
    // project's volume and network ids.
    let before = format!(
        "{}|{}|{}",
        inspect_one(
            container,
            "{{.Id}}|{{.State.StartedAt}}|{{.State.Health.Status}}"
        ),
        inspect_one(container, "{{.Image}}"),
        project_objects(project),
    );

    // The staged client, in the server's network namespace, no
    // credential: it arrives as the instance loopback and is the loopback
    // operator.
    let staged = docker(&[
        "run",
        "--rm",
        "--network",
        &format!("container:{container}"),
        "alpine:3",
        "wget",
        "-qO-",
        "-S",
        "http://127.0.0.1:17421/control/v1/status",
    ])
    .expect("docker run (the staged client)");
    assert!(
        staged.status.success(),
        "the staged client's read failed: {}{}",
        String::from_utf8_lossy(&staged.stdout),
        String::from_utf8_lossy(&staged.stderr)
    );
    assert!(
        String::from_utf8_lossy(&staged.stderr).contains("200 OK"),
        "the staged read is HTTP 200: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let body: Value =
        serde_json::from_slice(&staged.stdout).expect("the staged read returns the status JSON");
    assert!(
        body.get("status").is_some_and(|s| s.is_object()),
        "the body is the operator status projection: {body}"
    );

    // The server logged no refusal of the loopback read
    // (the health check is the same read, so nothing has been refused yet).
    let logs = run_env(
        "docker",
        &[
            "compose".to_owned(),
            "-p".to_owned(),
            project.to_owned(),
            "-f".to_owned(),
            compose_path.display().to_string(),
            "logs".to_owned(),
            "server".to_owned(),
        ],
        envs,
    );
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&logs.stdout),
        String::from_utf8_lossy(&logs.stderr)
    );
    assert!(
        !logs.contains("control_refusal"),
        "/: the loopback staged read was never refused: {logs}"
    );

    // The same GET through the publication. The peer arrives
    // translated (the bridge gateway, or slirp4netns' 10.0.2.2) and is
    // refused, not 200.
    let reply = raw_get(port);
    let status_line = reply.lines().next().unwrap_or_default().to_owned();
    assert!(
        status_line.starts_with("HTTP/1.1 401 ") || status_line.starts_with("HTTP/1.1 403 "),
        "the translated host caller is refused, not served: {status_line}"
    );
    let refusal = reply
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    assert!(
        !carries_token(&refusal),
        "the refusal names no secret: {refusal}"
    );

    // After the staged container is gone (--rm), the server, its
    // image, the project volume and network are all unchanged.
    let after = format!(
        "{}|{}|{}",
        inspect_one(
            container,
            "{{.Id}}|{{.State.StartedAt}}|{{.State.Health.Status}}"
        ),
        inspect_one(container, "{{.Image}}"),
        project_objects(project),
    );
    assert_eq!(
        before, after,
        "the project is unchanged by the staged client"
    );
}

/// The project's volume and network ids.
fn project_objects(project: &str) -> String {
    let objects = |kind: &str| -> String {
        let out = docker(&[
            kind,
            "ls",
            "-q",
            "--filter",
            &format!("label=com.docker.compose.project={project}"),
        ])
        .expect("docker volume/network ls");
        let ids = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            ids.matches(',').count() + usize::from(!ids.is_empty()),
            1,
            "the project holds exactly one {kind}"
        );
        ids
    };
    format!("{};{}", objects("volume"), objects("network"))
}

/// A raw HTTP/1.1 GET from the host to the published loopback port.
fn raw_get(port: u16) -> String {
    use std::io::Read as _;
    let mut stream =
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("the host caller connects");
    stream
        .write_all(
            b"GET /control/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .expect("the request is written");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).expect("the reply is read");
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Whether `text` carries a credential-sized base64-ish token.
fn carries_token(text: &str) -> bool {
    let mut run = 0usize;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' {
            run += 1;
            if run >= 32 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// One `docker inspect --format` value.
fn inspect_one(id: &str, template: &str) -> String {
    String::from_utf8_lossy(
        &docker(&["inspect", "--format", template, id])
            .expect("docker inspect")
            .stdout,
    )
    .trim()
    .to_owned()
}

/// One started compose project and the teardown of everything it created.
struct ProjectGuard {
    project: String,
    file: std::path::PathBuf,
    cfg_volume: String,
    container: String,
    envs: Vec<(&'static str, String)>,
}

impl Drop for ProjectGuard {
    fn drop(&mut self) {
        // By project name alone: the kit's file needs JAYNSHARE_HOST_* to
        // interpolate, so `-f` without them fails before removing anything.
        let _ = std::process::Command::new("docker")
            .args(["compose", "-p", &self.project, "down", "-v"])
            .output();
        let _ = std::process::Command::new("docker")
            .args(["volume", "rm", &self.cfg_volume])
            .output();
    }
}

/// `a_staged_client_is_loopback_and_a_host_caller_is_not`'s healthy bring-up, for one project of: the shipped
/// kit's `server` service with the bind configuration replaced by a named
/// volume holding the configuration at the modes, started and waited
/// healthy. (`a_staged_client_is_loopback_and_a_host_caller_is_not` first tries the bind and falls back on Docker
/// Desktop; the helper goes straight to the volume, which works everywhere.)
fn start_project(name: &str, host_port: u16) -> ProjectGuard {
    let image = platform_image().unwrap_or_else(|e| panic!("{e}"));
    let config = "\
version = 1\n\
[data_plane]\n\
listen = \"0.0.0.0:17421\"\n\
telemetry_policy = \"forward\"\n\
[data_plane.egress]\n\
mode = \"off\"\n\
[storage]\n\
state_file = \"/var/lib/jaynshare/state/state.json\"\n\
[logging]\n\
directory = \"/var/lib/jaynshare/log\"\n\
level = \"info\"\n\
";
    let cfg_volume = format!("{name}-cfg");
    let dir = root().join(name);
    std::fs::create_dir_all(&dir).expect("the project's directory");
    let compose_path = dir.join("compose.yaml");
    let kit = std::fs::read_to_string(format!(
        "{}/tools/release/compose-kit/compose.yaml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("read the shipped compose kit");
    let bind_block = "      - type: bind\n        source: ${JAYNSHARE_CONFIG_DIR:?set JAYNSHARE_CONFIG_DIR to the owner-only configuration directory}/config.toml\n        target: /etc/jaynshare/config.toml\n        read_only: true\n        bind: { create_host_path: false }";
    let volume_block = format!(
        "      - type: volume\n        source: {cfg_volume}\n        target: /etc/jaynshare\n        read_only: true"
    );
    let derived = kit
        .replace("@IMAGE@", &image)
        .replacen(bind_block, &volume_block, 1)
        .replace(
            "volumes:\n  state:",
            &format!("volumes:\n  {cfg_volume}:\n    external: true\n  state:"),
        );
    assert_ne!(
        derived,
        kit.replace("@IMAGE@", &image),
        "the bind block moved"
    );
    std::fs::write(&compose_path, &derived).expect("write compose.yaml");

    docker(&["volume", "create", &cfg_volume]).expect("docker volume create");
    feed(
        &[
            "run",
            "--rm",
            "-i",
            "-v",
            &format!("{cfg_volume}:/cfg"),
            "alpine:3",
            "sh",
            "-c",
            "cat > /cfg/config.toml && chown -R 10001:10001 /cfg && chmod 700 /cfg && chmod 600 /cfg/config.toml",
        ],
        config.as_bytes(),
        "the configuration is written into the named volume",
    );

    let envs: Vec<(&'static str, String)> = vec![
        (
            "JAYNSHARE_CONFIG_DIR",
            dir.join("config-dir").display().to_string(),
        ),
        ("JAYNSHARE_HOST_IP", "127.0.0.1".to_owned()),
        ("JAYNSHARE_HOST_PORT", host_port.to_string()),
    ];
    let args = |rest: &[&str]| -> Vec<String> {
        [
            "compose".to_owned(),
            "-p".to_owned(),
            name.to_owned(),
            "-f".to_owned(),
            compose_path.display().to_string(),
        ]
        .into_iter()
        .chain(rest.iter().map(|s| (*s).to_owned()))
        .collect()
    };
    must(
        run_env("docker", &args(&["up", "-d"]), &envs),
        "compose up -d",
    );
    let container = server_container(name, &compose_path, &envs);
    assert!(
        wait_healthy(&container),
        "{name}: the service never turned healthy"
    );
    ProjectGuard {
        project: name.to_owned(),
        file: compose_path,
        cfg_volume,
        container,
        envs,
    }
}

/// The scenario's scratch root, claimed once (`scratch` refuses a second
/// claim).
fn root() -> &'static std::path::PathBuf {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| scratch("project-never-reaches"))
}

/// The digest of one project volume's files: names and hashes, sorted.
fn state_digest(volume: &str) -> String {
    String::from_utf8_lossy(
        &docker(&[
            "run",
            "--rm",
            "-v",
            &format!("{volume}:/s:ro"),
            "alpine:3",
            "sh",
            "-c",
            "cd /s && find . -type f | sort | xargs -r sha256sum",
        ])
        .expect("docker run (the state digest)")
        .stdout,
    )
    .trim()
    .to_owned()
}

/// The fingerprint of one project: container id, StartedAt, Pid,
/// health, network id and state digest.
fn project_fingerprint(container: &str, volume: &str, network: &str) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        inspect_one(container, "{{.Id}}"),
        inspect_one(container, "{{.State.StartedAt}}"),
        inspect_one(container, "{{.State.Pid}}"),
        inspect_one(container, "{{.State.Health.Status}}"),
        network,
        state_digest(volume),
    )
}

/// Two Compose projects on distinct ports and state run side by
/// side: from A's network namespace B is unreachable over
/// B's own bridge address, the published host port serves A nothing with a
/// token, and A mounts none of B's volumes; starving A (8 MiB), restarting,
/// stopping and starting it never changes B's container, process, health,
/// network or state digest.
#[tokio::test(flavor = "multi_thread")]
async fn one_project_never_reaches_or_disturbs_another() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    if !docker_available() {
        eprintln!("skipping: container: no Docker daemon runs a container within 120 s");
        return;
    }
    let pid = std::process::id();
    let a_port = free_port();
    let b_port = free_port();
    let a = start_project(&format!("project-never-reaches-a-{pid}"), a_port);
    let b = start_project(&format!("project-never-reaches-b-{pid}"), b_port);

    // Record B: its container identity, health, project objects and state
    // digest (a short settle first, so the freshly healthy server is done
    // writing startup files).
    std::thread::sleep(Duration::from_secs(3));
    let objects = project_objects(&b.project);
    let (b_volume, b_network) = objects.split_once(';').expect("volume;network");
    let before = project_fingerprint(&b.container, b_volume, b_network);

    // No reach from A's namespace: B's own bridge address is unreachable
    // (the projects' bridges are separate)...
    let b_ip = inspect_one(
        &b.container,
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
    );
    assert!(!b_ip.is_empty(), "B's container holds no bridge address");
    let cross = docker(&[
        "run",
        "--rm",
        "--network",
        &format!("container:{}", a.container),
        "alpine:3",
        "wget",
        "-T",
        "3",
        "-qO-",
        &format!("http://{b_ip}:17421/control/v1/status"),
    ])
    .expect("docker run (the cross-project read)");
    assert!(
        !cross.status.success(),
        ": A read B's status over B's bridge address {b_ip}: {}{}",
        String::from_utf8_lossy(&cross.stdout),
        String::from_utf8_lossy(&cross.stderr)
    );

    // ... the published host port through A's namespace is unreachable or
    // refused with no token in the answer...
    let via_host = docker(&[
        "run",
        "--rm",
        "--network",
        &format!("container:{}", a.container),
        "alpine:3",
        "wget",
        "-S",
        "-T",
        "3",
        "-qO-",
        "/dev/null",
        &format!("http://host.docker.internal:{b_port}/control/v1/status"),
    ])
    .expect("docker run (the published-port read)");
    let answer = format!(
        "{}{}",
        String::from_utf8_lossy(&via_host.stdout),
        String::from_utf8_lossy(&via_host.stderr)
    );
    for line in answer
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("HTTP/"))
    {
        assert!(
            line.starts_with("HTTP/1.1 401 ") || line.starts_with("HTTP/1.1 403 "),
            "/: the published port serves A's namespace no status: {line}"
        );
    }
    assert!(
        !carries_token(&answer),
        "/: the published port's answer carries no token: {answer}"
    );

    // ... and A mounts none of B's volumes.
    let mounts = json_of(
        &docker(&["inspect", "--format", "{{json .Mounts}}", &a.container])
            .expect("docker inspect A"),
        "A's mounts",
    );
    let names: Vec<&str> = mounts
        .as_array()
        .expect("A's mounts are an array")
        .iter()
        .filter_map(|m| m.get("Name").and_then(Value::as_str))
        .collect();
    assert!(
        !names.contains(&b_volume) && !names.contains(&b.cfg_volume.as_str()),
        "/: A mounts none of B's volumes: {names:?}"
    );

    // Mutate and starve A: 8 MiB of memory OOM-kills or sickens it within
    // 30 s, and the record says which.
    must(
        docker(&[
            "update",
            "--memory",
            "8m",
            "--memory-swap",
            "8m",
            &a.container,
        ])
        .expect("docker update --memory"),
        "docker update --memory",
    );
    let mut starved = "still running after 30 s".to_owned();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let state = inspect_one(
            &a.container,
            "{{.State.OOMKilled}}|{{.State.Health.Status}}",
        );
        if state.contains("true") {
            starved = "OOM-killed".to_owned();
            break;
        }
        if state.contains("unhealthy") {
            starved = "unhealthy".to_owned();
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    println!(": A under 8 MiB ended up {starved}");

    let a_args = |rest: &[&str]| -> Vec<String> {
        [
            "compose".to_owned(),
            "-p".to_owned(),
            a.project.clone(),
            "-f".to_owned(),
            a.file.display().to_string(),
        ]
        .into_iter()
        .chain(rest.iter().map(|s| (*s).to_owned()))
        .collect()
    };
    let unchanged = |what: &str| {
        assert_eq!(
            project_fingerprint(&b.container, b_volume, b_network),
            before,
            "/: B changed by {what}"
        );
    };

    must(
        run_env("docker", &a_args(&["restart"]), &a.envs),
        "compose restart A",
    );
    unchanged("A's restart");
    must(
        run_env("docker", &a_args(&["stop"]), &a.envs),
        "compose stop A",
    );
    unchanged("A's stop");
    must(
        run_env("docker", &a_args(&["start"]), &a.envs),
        "compose start A",
    );
    unchanged("A's start");
}

/// `docker <args>` with `input` on standard input.
fn feed(args: &[&str], input: &[u8], what: &str) -> std::process::Output {
    let mut child = std::process::Command::new("docker")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    child
        .stdin
        .take()
        .expect("the child's stdin")
        .write_all(input)
        .unwrap_or_else(|e| panic!("{what}: {e}"));
    child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("{what}: {e}"))
}

/// Every `docker compose ps --format json server` answer carries both the
/// running state (`update`'s `before` read) and the health (the poll's).
const RUNNING_HEALTHY_PS: &str =
    "{\"Service\":\"server\",\"State\":\"running\",\"Health\":\"healthy\"}\n";
const RUNNING_UNHEALTHY_PS: &str =
    "{\"Service\":\"server\",\"State\":\"running\",\"Health\":\"unhealthy\"}\n";

/// A directory tree's bytes: `(relative path, bytes)`, in walk order.
fn tree_bytes(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).expect("directory") {
            let path = entry.expect("entry").path();
            let rel = format!(
                "{}/{}",
                prefix,
                path.file_name().expect("name").to_string_lossy()
            );
            if path.is_dir() {
                walk(&path, &rel, out);
            } else {
                out.push((rel, std::fs::read(&path).expect("file bytes")));
            }
        }
    }
    let mut walked = Vec::new();
    walk(root, "", &mut walked);
    walked
}

/// The update's docker answers: what `install` reads plus the `ps` and
/// `exec` answers in the order the scenario's calls need them.
fn script_update(tools: &FakeTools) {
    tools
        .rule("docker", &["info", "--format"])
        .stdout(&serde_json::to_string(&good_info()).expect("info JSON"));
    tools
        .rule("docker", &["context", "inspect"])
        .stdout(&context_inspect(LOCAL_CONTEXT));
    tools
        .rule("docker", &["compose", "version", "--short"])
        .stdout("2.29.1");
    tools
        .rule("docker", &["compose", "config", "--format", "json"])
        .stdout(&serde_json::to_string(&document(|_| {})).expect("document JSON"));
    // Two install polls (alpha, beta), then the good attempt's `before`
    // read and its poll.
    tools
        .rule("docker", &["ps", "--format", "json"])
        .stdout(RUNNING_HEALTHY_PS)
        .times(4);
    // The failing attempt's `before` read and first poll read: unhealthy.
    tools
        .rule("docker", &["ps", "--format", "json"])
        .stdout(RUNNING_UNHEALTHY_PS)
        .times(2);
    // The rollback's poll: healthy again.
    tools
        .rule("docker", &["ps", "--format", "json"])
        .stdout(RUNNING_HEALTHY_PS);
    // Two install status reads, then the update's.
    tools
        .rule("docker", &["exec", "-T", "server"])
        .stdout(&status_envelope(FIXTURE_VERSION))
        .times(2);
    tools
        .rule("docker", &["exec", "-T", "server"])
        .stdout(&status_envelope("0.7.1-acceptance"));
}

/// `container update` verifies
/// and pulls the new digest, snapshots the volume owner-only, replaces only
/// that project's container, and restores the digest, the volume bytes and
/// the running state when health fails; the restart is confirmed (21
/// without a terminal and without `--yes`), and no other project is touched.
#[tokio::test(flavor = "multi_thread")]
async fn update_succeeds_then_a_failing_candidate_rolls_back() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("update-succeeds-failing");
    let key = ReleaseKey::generate();

    // Setup: `alpha` and `beta` installed through `container install`.
    let (home, tools, env, kit, config) = rig_install(&root.join("setup"), &key, None);
    ImageFx::fixture().script_registry(&tools);
    script_update(&tools);
    for project in ["alpha", "beta"] {
        let (code, out, err) = install(&env, &kit, &config, project, "127.0.0.1:27400");
        assert_eq!(code, 0, "the {project} install: {out}{err}");
    }
    let containers = config_root(&home).join("containers");
    let alpha_dir = containers.join("alpha");
    let beta_dir = containers.join("beta");
    let beta_before = tree_bytes(&beta_dir);

    // The second release: 0.7.1-acceptance, one changed layer per platform,
    // its own image record and registry rules.
    let next_version = "0.7.1-acceptance";
    let base = ImageFx::fixture();
    let platforms: Vec<crate::release_fx::PlatformFx> = base
        .platforms
        .iter()
        .map(|p| {
            let mut layers = p.layer_digests.clone();
            layers[0] = oci_digest(format!("changed layer {}", p.platform).as_bytes());
            crate::release_fx::PlatformFx {
                platform: p.platform.clone(),
                config_digest: p.config_digest.clone(),
                layer_digests: layers.clone(),
                manifest: platform_manifest(&p.config_digest, &layers),
            }
        })
        .collect();
    let image_b = crate::release_fx::ImageFx {
        repository: OCI_REPOSITORY.to_string(),
        tag: next_version.to_string(),
        index: crate::release_fx::image_index(
            &platforms
                .iter()
                .map(|p| (p.platform.clone(), p.manifest.clone()))
                .collect::<Vec<_>>(),
        ),
        platforms,
    };
    let reference_b = image_b.reference();
    let record_b = image_b.record();
    let next_dir = root.join("next");
    let next_release = crate::release_fx::write_release_of(
        &next_dir,
        &key,
        next_version,
        |parts| {
            let bytes = compose_kit_zip(&reference_b);
            let name = format!("jaynshare-{next_version}-compose.zip");
            let slot = parts
                .artifacts
                .iter_mut()
                .find(|(n, _)| *n == name)
                .expect("the kit's artifact");
            slot.1 = bytes.clone();
            let entry = parts.manifest["artifacts"]
                .as_array_mut()
                .expect("artifacts")
                .iter_mut()
                .find(|entry| entry["filename"] == json!(name))
                .expect("the kit's manifest entry");
            entry["length"] = json!(bytes.len());
            entry["sha256"] = json!(sha256_hex(&bytes));
            parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sha256sums(&parts.artifacts)));
            parts.manifest["image"] = record_b;
        },
        |_| {},
    );
    let next_kit = next_release.join(format!("jaynshare-{next_version}-compose.zip"));
    image_b.script_registry(&tools);

    // No terminal and no `--yes` → 21, before any pull.
    let before = tools.calls("docker").len();
    let (code, out, err) = cli_raw(
        &[
            "container",
            "update",
            "--project",
            "alpha",
            "--from",
            &next_kit.display().to_string(),
        ],
        &env,
        None,
    );
    assert_eq!(code, 21, "no terminal, no --yes: {out}{err}");
    assert!(
        format!("{out}{err}").contains("confirmation.required"),
        "the confirmation check names it: {out}{err}"
    );
    let calls = tools.calls("docker");
    assert!(
        !calls[before..]
            .iter()
            .any(|call| call.first() == Some(&"pull".to_string())),
        "no pull without the confirmation: {calls:?}"
    );
    assert_eq!(
        tree_bytes(&beta_dir),
        beta_before,
        "beta untouched by the refusal"
    );

    // The good path: `--yes`, exit 0, pull → stop → snapshot run → up →
    // ps → exec, and the file now names the new reference.
    let before = tools.calls("docker").len();
    let (code, out, err) = cli_raw(
        &[
            "container",
            "update",
            "--project",
            "alpha",
            "--from",
            &next_kit.display().to_string(),
            "--yes",
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "the good update: {out}{err}");
    let calls = tools.calls("docker");
    let calls = &calls[before..];
    let position = |words: &[&str]| -> usize {
        calls
            .iter()
            .rposition(|call| words.iter().all(|w| call.contains(&w.to_string())))
            .unwrap_or_else(|| panic!("no call matching {words:?}: {calls:?}"))
    };
    let pull = position(&["pull", &reference_b]);
    let stop = position(&["compose", "stop"]);
    let snapshot_run = position(&["run", &format!("{}:/state:ro", "alpha_state")]);
    let up = position(&["up", "-d"]);
    let ps = position(&["ps", "--format", "json"]);
    let exec = position(&["exec", "-T", "server"]);
    assert!(pull < stop, "pull before stop: {calls:?}");
    assert!(stop < snapshot_run, "stop before the snapshot: {calls:?}");
    assert!(snapshot_run < up, "snapshot before up: {calls:?}");
    assert!(up < ps, "up before the health read: {calls:?}");
    assert!(ps < exec, "health before the status read: {calls:?}");
    assert!(
        calls[snapshot_run].contains(&format!("{}/.update-snapshot:/backup", alpha_dir.display())),
        "the snapshot directory is /backup: {:?}",
        calls[snapshot_run]
    );
    let post_good_yaml =
        std::fs::read(alpha_dir.join("compose.yaml")).expect("alpha's updated file");
    assert!(
        String::from_utf8_lossy(&post_good_yaml).contains(&reference_b),
        "the updated compose.yaml names the new reference: {}",
        String::from_utf8_lossy(&post_good_yaml)
    );
    assert!(
        !alpha_dir.join(".update-snapshot").exists(),
        "no snapshot remains after health succeeds"
    );
    assert_eq!(
        tree_bytes(&beta_dir),
        beta_before,
        "beta untouched by the update"
    );

    // The failing candidate: `ps` answers unhealthy for the new container →
    // exit 20, the pre-update bytes back, the volume restored read-write
    // from the read-only snapshot, and one final `up`.
    let before = tools.calls("docker").len();
    let (code, out, err) = cli_raw(
        &[
            "container",
            "update",
            "--project",
            "alpha",
            "--from",
            &next_kit.display().to_string(),
            "--yes",
        ],
        &env,
        None,
    );
    assert_eq!(code, 20, "the failing update: {out}{err}");
    assert!(
        format!("{out}{err}").contains("unhealthy"),
        "the health check names it: {out}{err}"
    );
    let yaml = std::fs::read(alpha_dir.join("compose.yaml")).expect("alpha's rolled-back file");
    assert_eq!(yaml, post_good_yaml, "the compose.yaml bytes are restored");
    assert!(
        !alpha_dir.join(".update-snapshot").exists(),
        "the snapshot goes once the rollback's health succeeds"
    );
    let calls = tools.calls("docker");
    let calls = &calls[before..];
    let restored = calls
        .iter()
        .position(|call| {
            call.contains(&"run".to_string())
                && call.windows(2).any(|pair| pair[1] == "alpha_state:/state")
                && call.windows(2).any(|pair| {
                    pair[1] == format!("{}/.update-snapshot:/backup:ro", alpha_dir.display())
                })
        })
        .expect("the restore run");
    let final_up = calls
        .iter()
        .rposition(|call| call.iter().any(|arg| arg == "up"))
        .expect("the final up");
    assert!(
        restored < final_up,
        "restore before the final up: {calls:?}"
    );
    assert!(
        !calls.iter().any(|call| call
            .iter()
            .any(|arg| arg == "beta" || arg.contains("prune"))),
        "no call names beta or prune: {calls:?}"
    );
    assert_eq!(
        tree_bytes(&beta_dir),
        beta_before,
        "beta untouched by the rollback"
    );
}

/// B — the configuration's own listeners, judged inside the
/// container (the wildcard exception applies) while the publication
/// stays `check_publications`'. A wildcard listener passes only
/// beside an explicit closed-list host publication; a listener off the
/// closed list fails `preflight.listener.data_plane` (18) with no `up`.
#[tokio::test(flavor = "multi_thread")]
async fn a_container_wildcard_needs_an_explicit_private_publication() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    // The native half above claims the box scratch `container-wildcard-needs`, so
    // the container rig takes a distinct name (the harness refuses a second
    // claim of one scratch name).
    let root = scratch("container-wildcard-needs-b");
    let key = ReleaseKey::generate();
    let config_text =
        |listen: &str| format!("version = 1\n\n[data_plane]\nlisten = \"{listen}:17421\"\n");

    // 1. `0.0.0.0:17421` beside `--publish 10.0.0.5:27400`: both pass.
    let (_, tools, env, kit, config) = rig_install(&root.join("wildcard-private"), &key, None);
    std::fs::write(&config, config_text("0.0.0.0")).expect("the configuration");
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|d| d["services"]["server"]["ports"][0]["host_ip"] = json!("10.0.0.5")),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "10.0.0.5:27400");
    assert_eq!(code, 0, "the wildcard beside 10.0.0.5: {out}{err}");
    let listener = format!("{out}{err}")
        .lines()
        .find(|l| l.contains("preflight.listener.data_plane"))
        .expect("the listener check line")
        .to_string();
    assert!(
        listener.contains("ok") && !listener.contains("FAILED"),
        "the wildcard listener passes: {listener}"
    );

    // 2. The same wildcard listener beside `--publish 0.0.0.0:27400`: the
    // listener passes, the publication fails.
    let (_, tools, env, kit, config) = rig_install(&root.join("publish-wildcard"), &key, None);
    std::fs::write(&config, config_text("0.0.0.0")).expect("the configuration");
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|d| d["services"]["server"]["ports"][0]["host_ip"] = json!("0.0.0.0")),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "0.0.0.0:27400");
    assert_eq!(code, 18, "the wildcard publication: {out}{err}");
    assert!(
        format!("{out}{err}").contains("preflight.publication"),
        "the publication check names it: {out}{err}"
    );
    assert_no_start(&tools, false);

    // 3. `--publish 8.8.8.8:27400`: the publication is off the closed list.
    let (_, tools, env, kit, config) = rig_install(&root.join("publish-global"), &key, None);
    std::fs::write(&config, config_text("0.0.0.0")).expect("the configuration");
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|d| d["services"]["server"]["ports"][0]["host_ip"] = json!("8.8.8.8")),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "8.8.8.8:27400");
    assert_eq!(code, 18, "the global publication: {out}{err}");
    assert!(
        format!("{out}{err}").contains("preflight.publication"),
        "the publication check names it: {out}{err}"
    );
    assert_no_start(&tools, false);

    // 4. The listener itself off the closed list: 18
    // `preflight.listener.data_plane`, and no `up` was asked for.
    let (_, tools, env, kit, config) = rig_install(&root.join("listener-global"), &key, None);
    std::fs::write(&config, config_text("8.8.8.8")).expect("the configuration");
    ImageFx::fixture().script_registry(&tools);
    script(
        &tools,
        &good_info(),
        LOCAL_CONTEXT,
        "2.29.1",
        &document(|_| {}),
    );
    let (code, out, err) = install(&env, &kit, &config, "alpha", "127.0.0.1:27400");
    assert_eq!(code, 18, "the global listener: {out}{err}");
    assert!(
        format!("{out}{err}").contains("preflight.listener.data_plane"),
        "the listener check names it: {out}{err}"
    );
    assert_no_start(&tools, false);
}

/// B — `container install`
/// prints its plan on standard error first (the project, the kit's claimed
/// version, the publication, the configuration path, the three limits); a
/// health-failing `container update` exits 20 and its stderr says the
/// rollback's own outcome; and `--project` off the pattern is refused
/// with exit 2 `cli_usage` before the fake `docker` is ever asked anything.
/// The failing-candidate setup is `update_succeeds_then_a_failing_candidate_rolls_back`'s, copied.
#[tokio::test(flavor = "multi_thread")]
async fn container_plan_first_rollback_and_project_pattern() {
    let _leak_sweep = crate::leaks::LeakGuard::default();
    let root = scratch("native-plan-first-b");
    let key = ReleaseKey::generate();

    // `update_succeeds_then_a_failing_candidate_rolls_back`'s setup, copied: `alpha` and `beta` installed, then a second
    // release whose candidate fails health.
    let (_home, tools, env, kit, config) = rig_install(&root.join("setup"), &key, None);
    ImageFx::fixture().script_registry(&tools);
    script_update(&tools);
    for project in ["alpha", "beta"] {
        let (code, out, err) = install(&env, &kit, &config, project, "127.0.0.1:27400");
        assert_eq!(code, 0, "the {project} install: {out}{err}");
        if project == "alpha" {
            let plan = err.lines().next().expect("a stderr plan line");
            for needle in [
                "installing project alpha",
                "claims version 0.7.0-acceptance",
                "publish 127.0.0.1:27400",
                &format!("config {}", config.display()),
                "cpus 1.0",
                "memory 512m",
                "pids 128",
            ] {
                assert!(
                    plan.contains(needle),
                    "the plan line names {needle}: {plan}"
                );
            }
        }
    }

    // The second release: 0.7.1-acceptance, one changed layer per platform
    // (copied from `update_succeeds_then_a_failing_candidate_rolls_back`).
    let next_version = "0.7.1-acceptance";
    let base = ImageFx::fixture();
    let platforms: Vec<crate::release_fx::PlatformFx> = base
        .platforms
        .iter()
        .map(|p| {
            let mut layers = p.layer_digests.clone();
            layers[0] = oci_digest(format!("changed layer {}", p.platform).as_bytes());
            crate::release_fx::PlatformFx {
                platform: p.platform.clone(),
                config_digest: p.config_digest.clone(),
                layer_digests: layers.clone(),
                manifest: platform_manifest(&p.config_digest, &layers),
            }
        })
        .collect();
    let image_b = crate::release_fx::ImageFx {
        repository: OCI_REPOSITORY.to_string(),
        tag: next_version.to_string(),
        index: crate::release_fx::image_index(
            &platforms
                .iter()
                .map(|p| (p.platform.clone(), p.manifest.clone()))
                .collect::<Vec<_>>(),
        ),
        platforms,
    };
    let reference_b = image_b.reference();
    let record_b = image_b.record();
    let next_dir = root.join("next");
    let next_release = crate::release_fx::write_release_of(
        &next_dir,
        &key,
        next_version,
        |parts| {
            let bytes = compose_kit_zip(&reference_b);
            let name = format!("jaynshare-{next_version}-compose.zip");
            let slot = parts
                .artifacts
                .iter_mut()
                .find(|(n, _)| *n == name)
                .expect("the kit's artifact");
            slot.1 = bytes.clone();
            let entry = parts.manifest["artifacts"]
                .as_array_mut()
                .expect("artifacts")
                .iter_mut()
                .find(|entry| entry["filename"] == json!(name))
                .expect("the kit's manifest entry");
            entry["length"] = json!(bytes.len());
            entry["sha256"] = json!(sha256_hex(&bytes));
            parts.manifest["sha256sums_sha256"] = json!(sha256_hex(&sha256sums(&parts.artifacts)));
            parts.manifest["image"] = record_b;
        },
        |_| {},
    );
    let next_kit = next_release.join(format!("jaynshare-{next_version}-compose.zip"));
    image_b.script_registry(&tools);

    // The good update: exit 0, so the failing candidate below rolls back
    // from a live prior version (`update_succeeds_then_a_failing_candidate_rolls_back`'s sequence).
    let (code, out, err) = cli_raw(
        &[
            "container",
            "update",
            "--project",
            "alpha",
            "--from",
            &next_kit.display().to_string(),
            "--yes",
        ],
        &env,
        None,
    );
    assert_eq!(code, 0, "the good update: {out}{err}");

    // The failing candidate: exit 20, and the stderr says the rollback's
    // own outcome.
    let (code, out, err) = cli_raw(
        &[
            "container",
            "update",
            "--project",
            "alpha",
            "--from",
            &next_kit.display().to_string(),
            "--yes",
        ],
        &env,
        None,
    );
    assert_eq!(code, 20, "the failing update: {out}{err}");
    assert!(
        err.contains("rollback succeeded"),
        "the outcome of the rollback itself: {err}"
    );

    // `--project` off the pattern: every container verb refuses with
    // exit 2 `cli_usage`, and the fake `docker` records no call.
    let before_bad = tools.calls("docker").len();
    let long = "a".repeat(33);
    let backup = root.join("backup.tar").display().to_string();
    let kit_path = kit.display().to_string();
    let next_kit_path = next_kit.display().to_string();
    for project in ["Bad_Name", long.as_str()] {
        let verbs: Vec<Vec<&str>> = vec![
            vec!["--from", &kit_path, "--publish", "127.0.0.1:27400"],
            vec!["--from", &next_kit_path],
            vec![],
            vec!["--out", &backup],
            vec!["--from", &backup],
            vec![],
        ];
        for (name, extra) in [
            "install",
            "update",
            "status",
            "backup",
            "restore",
            "uninstall",
        ]
        .into_iter()
        .zip(&verbs)
        {
            let mut args: Vec<String> = vec![
                "container".into(),
                name.into(),
                "--project".into(),
                project.into(),
            ];
            args.extend(extra.iter().map(|s| s.to_string()));
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let (code, out, err) = cli_raw(&args, &env, None);
            assert_eq!(code, 2, "{name} --project {project}: {out}{err}");
            assert!(
                format!("{out}{err}").contains("cli_usage"),
                "the refusal is a usage error: {out}{err}"
            );
        }
    }
    assert_eq!(
        tools.calls("docker").len(),
        before_bad,
        "the fake docker was never asked: {:?}",
        tools.calls("docker")
    );
}
