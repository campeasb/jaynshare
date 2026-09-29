//! The binary reports its full source commit and Rust target.

use std::process::Command;

fn main() {
    let commit = std::env::var("JAYNSHARE_COMMIT")
        .ok()
        .filter(|c| !c.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_else(|| "0000000000000000000000000000000000000000".into());
    println!("cargo:rustc-env=JAYNSHARE_COMMIT={commit}");
    println!(
        "cargo:rustc-env=JAYNSHARE_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
    println!("cargo:rerun-if-env-changed=JAYNSHARE_COMMIT");
    // `.git/HEAD` only names the branch; the commit lives in the ref it points
    // at (or in `packed-refs` after a gc), so watch those too or a stale
    // commit survives across `cargo build`s.
    println!("cargo:rerun-if-changed=.git/HEAD");
    if let Ok(head) = std::fs::read_to_string(".git/HEAD")
        && let Some(reference) = head.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed=.git/{reference}");
    }
    println!("cargo:rerun-if-changed=.git/packed-refs");
}
