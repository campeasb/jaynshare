//! The optional OS trust-store step. The default install
//! trusts the CA only through the per-launch `NODE_EXTRA_CA_CERTS` path;
//! `trust-ca add` / `enrol --trust-os-store` add the exact CA to the macOS
//! login keychain or the Windows current-user root store after explaining
//! the broader effect, and `trust-ca remove` removes exactly the fingerprint
//! `client.toml` names. The tools are `security` (macOS) and `certutil`
//! (Windows), one wrapper each (the test suite's fakes answer them).

use std::path::Path;
use std::process::Output;

/// Adds `ca_pem`, whose fingerprint must be `fingerprint`, to the
/// user's OS trust store. Only the exact confirmed fingerprint is
/// ever added, so the certificate on disk is checked against it first.
pub fn add(ca_pem: &Path, fingerprint: &str) -> Result<(), String> {
    let pem = std::fs::read_to_string(ca_pem).map_err(|e| format!("{}: {e}", ca_pem.display()))?;
    check(&ca_pem.display().to_string(), &pem, fingerprint)?;
    if cfg!(target_os = "macos") {
        let keychain = login_keychain()?;
        let path = ca_pem.display().to_string();
        let output = security(&[
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-k",
            &keychain,
            &path,
        ])?;
        success("security", output)
    } else if cfg!(target_os = "windows") {
        let path = ca_pem.display().to_string();
        let output = certutil(&["-user", "-addstore", "Root", &path])?;
        success("certutil", output)
    } else {
        Err(format!(
            "the OS trust store is not supported on {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    }
}

/// Removes exactly the certificate whose fingerprint is `fingerprint`
/// from the user's OS trust store, nothing else. The fingerprint is
/// the one `client.toml` names, and the installed `ca.pem` must carry it —
/// the removal argument is the certificate's own SHA-1 hash.
pub fn remove(fingerprint: &str) -> Result<(), String> {
    let ca = crate::config::platform::client_directory().join("ca.pem");
    let pem = std::fs::read_to_string(&ca).map_err(|e| format!("{}: {e}", ca.display()))?;
    check(&ca.display().to_string(), &pem, fingerprint)?;
    let sha1 = sha1_of(&pem)?;
    if cfg!(target_os = "macos") {
        let keychain = login_keychain()?;
        let output = security(&["delete-certificate", "-Z", &sha1, &keychain])?;
        success("security", output)
    } else if cfg!(target_os = "windows") {
        let output = certutil(&["-user", "-delstore", "Root", &sha1])?;
        success("certutil", output)
    } else {
        Err(format!(
            "the OS trust store is not supported on {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ))
    }
}

/// The exact-match rule: `pem`'s fingerprint must be
/// `fingerprint`, spelled as `bundle::fingerprint` spells it.
fn check(where_: &str, pem: &str, fingerprint: &str) -> Result<(), String> {
    let actual = crate::bundle::fingerprint(pem).map_err(|e| format!("{where_}: {e}"))?;
    if actual != fingerprint {
        return Err(format!(
            "{where_}: its fingerprint is {actual}, not the confirmed {fingerprint}"
        ));
    }
    Ok(())
}

/// The SHA-1 hash of `pem`'s DER certificate (macOS `delete-certificate -Z`).
fn sha1_of(pem: &str) -> Result<String, String> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| format!("the CA certificate is not a PEM block: {e}"))?;
    parsed
        .parse_x509()
        .map_err(|e| format!("the CA certificate does not parse: {e}"))?;
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &parsed.contents);
    Ok(digest.as_ref().iter().map(|b| format!("{b:02X}")).collect())
}

/// The user's login keychain (`$HOME/Library/Keychains/login.keychain-db`).
fn login_keychain() -> Result<String, String> {
    std::env::var_os("HOME")
        .map(|home| {
            Path::new(&home)
                .join("Library/Keychains/login.keychain-db")
                .display()
                .to_string()
        })
        .ok_or_else(|| "$HOME is not set".to_string())
}

/// A tool that did not answer success fails with its stderr, one line.
fn success(tool: &str, output: Output) -> Result<(), String> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let one_line = stderr.trim().lines().next().unwrap_or_default();
    Err(format!("{tool} exited {}: {one_line}", output.status))
}

/// The macOS wrapper: `security <args>`.
pub fn security(args: &[&str]) -> Result<Output, String> {
    run("security", args)
}

/// The Windows wrapper: `certutil <args>`.
pub fn certutil(args: &[&str]) -> Result<Output, String> {
    run("certutil", args)
}

fn run(tool: &str, args: &[&str]) -> Result<Output, String> {
    std::process::Command::new(tool)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{tool}: {e}"))
}
