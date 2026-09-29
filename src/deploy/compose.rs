//! The release-specific Compose project — the file this
//! installation materialises and the rules any project file must obey.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use serde_json::Value;
use std::fmt::Write as _;

use super::container::Limits;
use super::result::Check;

/// What one project's `compose.yaml` is rendered from.
pub struct ProjectInputs<'a> {
    pub project: &'a str,
    /// `<repository>@sha256:<index digest>` (never a mutable tag).
    pub image: &'a str,
    /// The configuration source file, mounted read-only.
    pub config: &'a Path,
    /// Data-plane and, when MITM is on, proxy publications.
    pub publish: &'a [SocketAddr],
    pub limits: &'a Limits,
}

/// The project's `compose.yaml` — one read-only config
/// mount, only `JAYNSHARE_CONFIG`, one project volume, rotated logs, the
/// hardening, the long-form publications and the limits.
pub fn render(inputs: &ProjectInputs<'_>) -> String {
    // The project must name the image by index digest, never a
    // mutable tag; release-side construction upholds it, debug_assert
    // documents it.
    debug_assert!(
        inputs.image.contains("@sha256:"),
        "image must be pinned by index digest (`<repo>@sha256:<digest>`)"
    );

    let mut yaml = format!(
        r#"name: {}
services:
  server:
    image: {}
    read_only: true
    cap_drop:
      - "ALL"
    security_opt:
      - "no-new-privileges:true"
    cgroup: private
    tmpfs:
      - "/tmp:size=16m,mode=1777"
    volumes:
      - type: bind
        source: {}
        target: "/etc/jaynshare/config.toml"
        read_only: true
        bind:
          create_host_path: false
      - type: volume
        source: state
        target: "/var/lib/jaynshare"
    environment:
      JAYNSHARE_CONFIG: "/etc/jaynshare/config.toml"
    ports:
"#,
        quoted(inputs.project),
        quoted(inputs.image),
        quoted(&inputs.config.to_string_lossy()),
    );
    for (index, publication) in inputs.publish.iter().enumerate() {
        yaml.push_str(&format!(
            "      - target: {}\n        host_ip: {}\n        published: {}\n        protocol: tcp\n        mode: host\n",
            FIRST_TARGET_PORT + index as u16,
            quoted(&publication.ip().to_string()),
            quoted(&publication.port().to_string()),
        ));
    }
    yaml.push_str(&format!(
        r#"    deploy:
      resources:
        limits:
          cpus: {}
          memory: {}
          pids: {}
    stop_grace_period: "30s"
    healthcheck:
      test:
        - "CMD"
        - "/usr/local/bin/jaynshare"
        - "status"
        - "--check"
      interval: "10s"
      timeout: "5s"
      retries: 3
      start_period: "10s"
    logging:
      driver: local
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - pool
networks:
  pool:
    driver: bridge
volumes:
  state: {{}}
"#,
        quoted(&inputs.limits.cpus),
        quoted(&inputs.limits.memory),
        inputs.limits.pids,
    ));
    yaml
}

/// The server's data-plane container port; the proxy, when published, is
/// the next one (one explicit target per publication).
const FIRST_TARGET_PORT: u16 = 17421;

/// Double-quote a scalar so YAML cannot misread it, escaping `"`
/// and `\`.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The value is present, a string and non-empty.
fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value.and_then(|v| v.as_str()).filter(|s| !s.is_empty())
}

/// The `ports` entry's host IP classifies as passing.
fn host_ip_passes(entry: &Value, message: &mut String) -> bool {
    let Some(text) = non_empty_string(entry.get("host_ip")) else {
        *message = "a ports entry has no host IP".to_string();
        return false;
    };
    let Ok(ip) = text.parse::<IpAddr>() else {
        *message = format!("a ports entry's host IP {text:?} is not an IP address");
        return false;
    };
    let class = super::address::classify(ip);
    if !class.passes() {
        *message =
            format!("a ports entry publishes on {text}, class {class:?}, not on the closed list");
        return false;
    }
    *message = format!("publications on {text} (class {class:?})");
    true
}

/// The publication checks over a parsed Compose document (`docker compose config
/// --format json`): long form, explicit closed-list host IP, explicit
/// unique host port, no `published: 0`, no host network, one service and
/// one network.
pub fn check_publications(document: &Value) -> Vec<Check> {
    let services = document
        .get("services")
        .and_then(|s| s.as_object())
        .expect("a Compose document has services");

    let mut checks = vec![];

    // preflight.services: exactly one service.
    let mut message = format!("{} service(s)", services.len());
    if services.len() == 1 {
        checks.push(Check::pass("preflight.services", message));
    } else {
        checks.push(Check::fail(
            "preflight.services",
            std::mem::take(&mut message),
        ));
    }

    // preflight.network: no network_mode, one bridge non-external network
    // attached to the one service.
    let mut network_message = String::new();
    let mut network_ok = true;
    let networks = document
        .get("networks")
        .and_then(|n| n.as_object())
        .expect("a Compose document has networks");
    if networks.len() != 1 {
        network_ok = false;
        let _ = write!(
            network_message,
            "{} network(s) in the project; ",
            networks.len()
        );
    }
    for (name, network) in networks {
        if network
            .get("external")
            .filter(|e| !e.is_null())
            .is_some_and(|external| {
                external.as_bool() != Some(false)
                    || external.as_str().is_some_and(|s| !s.is_empty())
            })
        {
            network_ok = false;
            let _ = write!(network_message, "network {name:?} is external; ");
        }
        let driver = network.get("driver").and_then(|d| d.as_str());
        if driver.is_some_and(|d| d != "bridge") {
            network_ok = false;
            let _ = write!(
                network_message,
                "network {name:?} uses driver {:?}, not bridge; ",
                driver.unwrap()
            );
        }
    }
    for (name, service) in services {
        if let Some(mode) = non_empty_string(service.get("network_mode")) {
            network_ok = false;
            let _ = write!(
                network_message,
                "service {name:?} sets network_mode {mode:?}; "
            );
        }
        let attached = service
            .get("networks")
            .and_then(|n| n.as_object())
            .map(|n| n.len());
        if attached != Some(1) && networks.len() == 1 {
            network_ok = false;
            let _ = write!(
                network_message,
                "service {name:?} attaches to {} network(s); ",
                attached.unwrap_or(0)
            );
        }
    }
    if network_message.is_empty() {
        network_message = "one bridge network attached to the one service".to_string();
    }
    if network_ok {
        checks.push(Check::pass("preflight.network", network_message));
    } else {
        checks.push(Check::fail("preflight.network", network_message));
    }

    // preflight.publication: long form, closed-list host IP, explicit unique
    // port, no published: 0.
    let mut publication_message = String::new();
    let mut publication_ok = true;
    let mut published_ports: HashSet<&str> = HashSet::new();
    for (name, service) in services {
        if let Some(ports) = service.get("ports").and_then(|p| p.as_array()) {
            for entry in ports {
                let mut entry_message = String::new();
                let ip_ok = host_ip_passes(entry, &mut entry_message);
                if !ip_ok {
                    publication_ok = false;
                    let _ = write!(publication_message, "service {name:?}: {entry_message}; ");
                }
                let published = non_empty_string(entry.get("published"));
                match published {
                    None => {
                        publication_ok = false;
                        let _ = write!(
                            publication_message,
                            "service {name:?}: a ports entry has no published port; "
                        );
                    }
                    Some("0") => {
                        publication_ok = false;
                        let _ = write!(
                            publication_message,
                            "service {name:?}: a ports entry publishes 0; "
                        );
                    }
                    Some(port_text) => {
                        if port_text.contains('-') || port_text.contains(':') {
                            publication_ok = false;
                            let _ = write!(
                                publication_message,
                                "service {name:?}: a ports entry publishes the range {port_text:?}; "
                            );
                        } else if !published_ports.insert(port_text) {
                            publication_ok = false;
                            let _ = write!(
                                publication_message,
                                "service {name:?}: port {port_text} is published twice; "
                            );
                        }
                    }
                }
            }
        }
    }
    if publication_message.is_empty() {
        publication_message =
            "every ports entry is long form on an explicit unique port".to_string();
    }
    if publication_ok {
        checks.push(Check::pass("preflight.publication", publication_message));
    } else {
        checks.push(Check::fail("preflight.publication", publication_message));
    }

    // preflight.expose: no expose list and no publish_all.
    let mut expose_message = String::new();
    let mut expose_ok = true;
    for (name, service) in services {
        if service.get("expose").filter(|e| !e.is_null()).is_some() {
            expose_ok = false;
            let _ = write!(expose_message, "service {name:?} sets expose; ");
        }
        if service
            .get("publish_all")
            .is_some_and(|all| all.as_bool() == Some(true))
        {
            expose_ok = false;
            let _ = write!(expose_message, "service {name:?} sets publish_all; ");
        }
    }
    if expose_message.is_empty() {
        expose_message = "no expose or publish_all".to_string();
    }
    if expose_ok {
        checks.push(Check::pass("preflight.expose", expose_message));
    } else {
        checks.push(Check::fail("preflight.expose", expose_message));
    }

    checks
}

/// The host's reserve for the host itself and the rootless daemon.
const RESERVE_CPUS: f64 = 1.0;
const RESERVE_MEMORY_BYTES: u128 = 512 * 1024 * 1024;

fn parse_cpus(raw: &str) -> Result<f64, String> {
    match raw.trim().parse::<f64>() {
        Ok(v) if v.is_finite() && v > 0.0 => Ok(v),
        Ok(_) => Err("zero or negative cpus limit".into()),
        Err(_) => Err("the cpus limit is not a decimal number".into()),
    }
}

/// Compose itself is decimal; they drift only through whitespace.
fn parse_memory(raw: &str) -> Result<u128, String> {
    let flag_error =
        || "the memory limit is not a byte count with an optional b/k/m/g unit".to_string();
    let t = raw.trim();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (number, unit) = t.split_at(split);
    let count: u64 = number.parse().map_err(|_| flag_error())?;
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1u128,
        "k" | "kb" => 1024,
        "m" | "mb" => 1024 * 1024,
        "g" | "gb" => 1024 * 1024 * 1024,
        _ => return Err(flag_error()),
    };
    let bytes = (count as u128)
        .checked_mul(multiplier)
        .ok_or_else(|| "the memory limit is too large".to_string())?;
    if bytes == 0 {
        return Err("zero or negative memory limit".into());
    }
    Ok(bytes)
}

/// The requested totals across every project leave the host at
/// least 512 MiB and one CPU.
pub fn check_limits(
    requested: &Limits,
    others: &[Limits],
    host_cpus: f64,
    host_memory_bytes: u64,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut total_cpus = 0.0f64;
    let mut total_memory_bytes = 0u128;
    let mut every_limit_well_formed = true;
    for limits in std::iter::once(requested).chain(others.iter()) {
        match parse_cpus(&limits.cpus) {
            Ok(cpus) => {
                total_cpus += cpus;
            }
            Err(message) => {
                checks.push(Check::fail("preflight.limits", message));
                every_limit_well_formed = false;
            }
        }
        match parse_memory(&limits.memory) {
            Ok(bytes) => {
                total_memory_bytes += bytes;
            }
            Err(message) => {
                checks.push(Check::fail("preflight.limits", message));
                every_limit_well_formed = false;
            }
        }
        if limits.pids == 0 {
            checks.push(Check::fail(
                "preflight.limits",
                "zero or negative pids limit",
            ));
            every_limit_well_formed = false;
        }
    }
    if !every_limit_well_formed {
        return checks;
    }
    checks.push(Check::pass(
        "preflight.limits",
        "every project's cpus, memory and pids limit is present and within range",
    ));
    let host_memory = host_memory_bytes as u128;
    let remaining_cpus = host_cpus - total_cpus;
    let remaining_memory_bytes = host_memory.saturating_sub(total_memory_bytes);
    if remaining_cpus >= RESERVE_CPUS && remaining_memory_bytes >= RESERVE_MEMORY_BYTES {
        checks.push(Check::pass(
            "preflight.reserve",
            format!(
                "projects request {} CPUs and {} bytes; the host's {} CPUs and {} bytes leave at least 1 CPU and 512 MiB reserve",
                total_cpus, total_memory_bytes, host_cpus, host_memory
            ),
        ));
    } else {
        checks.push(Check::fail(
            "preflight.reserve",
            format!(
                "projects request {} CPUs and {} bytes; the host's {} CPUs and {} bytes leave {} CPUs and {} bytes, below the reserve of 1 CPU and 512 MiB",
                total_cpus,
                total_memory_bytes,
                host_cpus,
                host_memory,
                remaining_cpus,
                remaining_memory_bytes
            ),
        ));
    }
    checks
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};

    fn check_names(checks: &[Check]) -> Vec<(&str, bool)> {
        checks
            .iter()
            .map(|c| (c.name.split('.').next().unwrap(), c.passed))
            .collect()
    }

    #[test]
    fn default_limits_pass_on_4_cpu_4_gib_host() {
        let checks = check_limits(&Limits::default(), &[], 4.0, 4 * 1024 * 1024 * 1024);
        assert_eq!(
            check_names(&checks),
            vec![("preflight", true), ("preflight", true)]
        );
    }

    #[test]
    fn three_defaults_on_2_cpu_host_fail_reserve() {
        let one = Limits::default();
        let checks = check_limits(
            &one.clone(),
            &[one.clone(), one],
            2.0,
            4 * 1024 * 1024 * 1024,
        );
        assert_eq!(
            check_names(&checks),
            vec![("preflight", true), ("preflight", false)]
        );
        assert!(checks[1].message.contains("reserve"));
    }

    #[test]
    fn memory_reserve_boundary() {
        let host = 1024 * 1024 * 1024u64;
        // 512 MiB leaves exactly the 512 MiB reserve: passes.
        let checks = check_limits(&Limits::default(), &[], 4.0, host);
        assert_eq!(
            check_names(&checks),
            vec![("preflight", true), ("preflight", true)]
        );
        // 513 MiB leaves 511 MiB: fails.
        let tight = Limits {
            memory: "513m".into(),
            ..Limits::default()
        };
        let checks = check_limits(&tight, &[], 4.0, host);
        assert_eq!(
            check_names(&checks),
            vec![("preflight", true), ("preflight", false)]
        );
    }

    #[test]
    fn memory_reserve_boundary_across_projects() {
        let other = Limits {
            memory: "1024m".into(),
            ..Limits::default()
        };
        let exact = Limits {
            memory: "512m".into(),
            ..Limits::default()
        };
        // 2 GiB host − 1024 MiB − 512 MiB leaves exactly 512 MiB: passes.
        let checks = check_limits(
            &exact,
            std::slice::from_ref(&other),
            4.0,
            2 * 1024 * 1024 * 1024,
        );
        assert_eq!(
            check_names(&checks),
            vec![("preflight", true), ("preflight", true)]
        );
        // 513 MiB instead leaves 511 MiB: fails.
        let tight = Limits {
            memory: "513m".into(),
            ..Limits::default()
        };
        let checks = check_limits(&tight, &[other], 4.0, 2 * 1024 * 1024 * 1024);
        assert_eq!(
            check_names(&checks),
            vec![("preflight", true), ("preflight", false)]
        );
    }

    #[test]
    fn unit_spellings_parse() {
        assert_eq!(parse_memory("1g").unwrap(), 1_073_741_824);
        assert_eq!(parse_memory("1gb").unwrap(), 1_073_741_824);
        assert_eq!(parse_memory("512m").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("512mb").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("1k").unwrap(), 1024);
        assert_eq!(parse_memory("100b").unwrap(), 100);
        assert_eq!(parse_memory("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_memory("512").unwrap(), 512);
    }

    #[test]
    fn unparsable_memory_fails_limits() {
        let bad = Limits {
            memory: "abc".into(),
            ..Limits::default()
        };
        let checks = check_limits(&bad, &[], 4.0, 4 * 1024 * 1024 * 1024);
        assert_eq!(check_names(&checks), vec![("preflight", false)]);
    }

    #[test]
    fn zero_pids_fails_limits() {
        let bad = Limits {
            pids: 0,
            ..Limits::default()
        };
        let checks = check_limits(&bad, &[], 4.0, 4 * 1024 * 1024 * 1024);
        assert!(
            checks
                .iter()
                .any(|c| !c.passed && c.message.contains("pids"))
        );
    }

    #[test]
    fn zero_and_negative_cpus_fail() {
        for cpus in ["0", "-1.0"] {
            let bad = Limits {
                cpus: cpus.into(),
                ..Limits::default()
            };
            let checks = check_limits(&bad, &[], 4.0, 4 * 1024 * 1024 * 1024);
            assert!(
                checks
                    .iter()
                    .any(|c| !c.passed && c.name == "preflight.limits")
            );
        }
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    fn golden_inputs<'a>(
        config: &'a Path,
        publish: &'a [SocketAddr],
        limits: &'a Limits,
    ) -> ProjectInputs<'a> {
        ProjectInputs {
            project: "project-carries-no-secret",
            image: "ghcr.io/jaynshare/jaynshare@sha256:abcd1234",
            config,
            publish,
            limits,
        }
    }

    /// The golden file for a fixed input.
    #[test]
    fn golden_render() {
        let limits = Limits::default();
        let publish = [addr(18421), addr(18422)];
        let rendered = render(&golden_inputs(
            Path::new("/home/op/config.toml"),
            &publish,
            &limits,
        ));
        let expected = r#"name: "project-carries-no-secret"
services:
  server:
    image: "ghcr.io/jaynshare/jaynshare@sha256:abcd1234"
    read_only: true
    cap_drop:
      - "ALL"
    security_opt:
      - "no-new-privileges:true"
    cgroup: private
    tmpfs:
      - "/tmp:size=16m,mode=1777"
    volumes:
      - type: bind
        source: "/home/op/config.toml"
        target: "/etc/jaynshare/config.toml"
        read_only: true
        bind:
          create_host_path: false
      - type: volume
        source: state
        target: "/var/lib/jaynshare"
    environment:
      JAYNSHARE_CONFIG: "/etc/jaynshare/config.toml"
    ports:
      - target: 17421
        host_ip: "127.0.0.1"
        published: "18421"
        protocol: tcp
        mode: host
      - target: 17422
        host_ip: "127.0.0.1"
        published: "18422"
        protocol: tcp
        mode: host
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: "512m"
          pids: 128
    stop_grace_period: "30s"
    healthcheck:
      test:
        - "CMD"
        - "/usr/local/bin/jaynshare"
        - "status"
        - "--check"
      interval: "10s"
      timeout: "5s"
      retries: 3
      start_period: "10s"
    logging:
      driver: local
      options:
        max-size: "10m"
        max-file: "3"
    networks:
      - pool
networks:
  pool:
    driver: bridge
volumes:
  state: {}
"#;
        assert_eq!(rendered, expected);
    }

    /// Nothing in the file may widen the container's surface.
    #[test]
    fn no_forbidden_constructs() {
        let limits = Limits::default();
        let publish = [addr(18421)];
        let rendered = render(&golden_inputs(
            Path::new("/home/op/config.toml"),
            &publish,
            &limits,
        ));
        for line in rendered.lines() {
            for forbidden in [
                "container_name",
                "network_mode",
                "privileged",
                "devices",
                "docker.sock",
                "0.0.0.0",
            ] {
                assert!(
                    !line.contains(forbidden),
                    "line contains {forbidden:?}: {line}"
                );
            }
        }
    }

    /// A configuration path with `"` and `\` survives quoting.
    #[test]
    fn quotes_tricky_paths() {
        let limits = Limits::default();
        let publish = [addr(18421)];
        let rendered = render(&golden_inputs(
            Path::new("/home/op/my \"conf\\ig/config.toml"),
            &publish,
            &limits,
        ));
        let source_line = format!("source: {}", quoted("/home/op/my \"conf\\ig/config.toml"));
        assert!(rendered.contains(&source_line), "{rendered}");
    }

    /// One long-form entry per publication, targets in order.
    #[test]
    fn one_ports_entry_per_publication() {
        let limits = Limits::default();
        let one = [addr(18421)];
        let rendered = render(&golden_inputs(
            Path::new("/home/op/config.toml"),
            &one,
            &limits,
        ));
        assert_eq!(rendered.matches("mode: host").count(), 1);
        assert!(rendered.contains(
            "- target: 17421\n        host_ip: \"127.0.0.1\"\n        published: \"18421\""
        ));

        let two = [addr(18421), addr(18422)];
        let rendered = render(&golden_inputs(
            Path::new("/home/op/config.toml"),
            &two,
            &limits,
        ));
        assert_eq!(rendered.matches("mode: host").count(), 2);
        assert!(rendered.contains(
            "- target: 17422\n        host_ip: \"127.0.0.1\"\n        published: \"18422\""
        ));
    }

    /// The good one-service, two-publication document every rule accepts.
    fn good() -> Value {
        json!({
            "name": "jaynshare-instance",
            "services": {
                "server": {
                    "ports": [
                        {
                            "mode": "host",
                            "host_ip": "100.64.0.5",
                            "target": 17421,
                            "published": "17421",
                            "protocol": "tcp"
                        },
                        {
                            "mode": "host",
                            "host_ip": "100.64.0.5",
                            "target": 17422,
                            "published": "17422",
                            "protocol": "tcp"
                        }
                    ],
                    "networks": { "jaynshare": null }
                }
            },
            "networks": {
                "jaynshare": { "driver": "bridge", "external": false }
            }
        })
    }

    fn names(checks: &[Check]) -> Vec<&str> {
        checks.iter().map(|c| c.name.as_str()).collect()
    }

    fn failed(checks: &[Check]) -> Vec<&str> {
        checks
            .iter()
            .filter(|c| !c.passed)
            .map(|c| c.name.as_str())
            .collect()
    }

    /// Mutates one part of the good document: the service `name`'s `ports`
    /// entry `index`, or the top-level `networks`.
    fn mutate(good: Value, f: impl FnOnce(&mut Value)) -> Value {
        let mut document = good;
        f(&mut document);
        document
    }

    /// A shapes-only variant of the good document: no `ports`, so no
    /// address is ever classified.
    fn shape_only() -> Value {
        json!({
            "name": "jaynshare-instance",
            "services": {
                "server": { "networks": { "jaynshare": null } }
            },
            "networks": {
                "jaynshare": { "driver": "bridge", "external": false }
            }
        })
    }

    #[test]
    fn good_document_passes_every_check() {
        let checks = check_publications(&good());
        assert_eq!(
            names(&checks),
            [
                "preflight.services",
                "preflight.network",
                "preflight.publication",
                "preflight.expose"
            ]
        );
        assert!(checks.iter().all(|c| c.passed), "{checks:?}");
    }

    #[test]
    fn missing_host_ip_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][0]
                .as_object_mut()
                .unwrap()
                .remove("host_ip");
            // Drop the second entry so no address is classified.
            d["services"]["server"]["ports"]
                .as_array_mut()
                .unwrap()
                .truncate(1);
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn wildcard_ipv4_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][0]["host_ip"] = json!("0.0.0.0")
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn wildcard_ipv6_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][0]["host_ip"] = json!("::")
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn global_address_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][0]["host_ip"] = json!("203.0.113.7")
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn published_zero_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][0]["published"] = json!("0")
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn published_range_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][0]["published"] = json!("17421-17422")
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn duplicate_port_fails_publication() {
        let document = mutate(good(), |d| {
            d["services"]["server"]["ports"][1]["published"] = json!("17421")
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.publication"]
        );
    }

    #[test]
    fn host_network_mode_fails_network() {
        let document = mutate(shape_only(), |d| {
            d["services"]["server"]["network_mode"] = json!("host")
        });
        let checks = check_publications(&document);
        assert_eq!(failed(&checks), ["preflight.network"]);
        // All four checks are still reported.
        assert_eq!(names(&checks).len(), 4);
    }

    #[test]
    fn two_services_fail_services() {
        let document = mutate(shape_only(), |d| {
            let services = d["services"].as_object_mut().unwrap();
            services.insert(
                "sidecar".to_string(),
                json!({ "networks": { "jaynshare": null } }),
            );
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.services"]
        );
    }

    #[test]
    fn two_networks_fail_network() {
        let document = mutate(shape_only(), |d| {
            d["networks"]["extra"] = json!({ "driver": "bridge", "external": false });
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.network"]
        );
    }

    #[test]
    fn external_network_fails_network() {
        let document = mutate(shape_only(), |d| {
            d["networks"]["jaynshare"]["external"] = json!(true)
        });
        assert_eq!(
            failed(&check_publications(&document)),
            ["preflight.network"]
        );
    }

    #[test]
    fn expose_fails_expose() {
        let document = mutate(shape_only(), |d| {
            d["services"]["server"]["expose"] = json!(["17421/tcp"])
        });
        assert_eq!(failed(&check_publications(&document)), ["preflight.expose"]);
    }
}
