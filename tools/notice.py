#!/usr/bin/env python3
"""Regenerate NOTICE.md from Cargo.lock's resolved graph.

Run from the repository root after any dependency change:  python3 tools/notice.py
"""
import json
import subprocess
from pathlib import Path

metadata = json.loads(
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--all-features", "--locked"],
        capture_output=True, check=True, text=True,
    ).stdout
)
crates = sorted(
    (p["name"], p["version"], p.get("license") or "see repository", p.get("repository") or "")
    for p in metadata["packages"]
    if p["name"] != "jaynshare"
)
lines = [
    "# NOTICE",
    "",
    "Jaynshare is distributed under the MIT license in `LICENSE`.",
    "",
    "It links the Rust crates below, each under its own license. Regenerate this",
    "file with `python3 tools/notice.py` whenever `Cargo.lock` changes; the license",
    "set is enforced in CI by `cargo-deny` (`deny.toml`).",
    "",
    "| Crate | Version | Licence | Source |",
    "|---|---|---|---|",
]
lines += [f"| `{n}` | {v} | {lic} | {repo} |" for n, v, lic, repo in crates]
lines += [
    "",
    "## The platform image",
    "",
    "The OCI platform image adds the Mozilla CA root bundle",
    "(`/etc/ssl/certs/ca-certificates.crt`, from Alpine's `ca-certificates-bundle`,",
    "MPL-2.0), taken from the digest-pinned `alpine` stage named in the",
    "`Dockerfile`. Nothing else enters the image.",
]
Path("NOTICE.md").write_text("\n".join(lines) + "\n")
print(f"NOTICE.md: {len(crates)} crates")
