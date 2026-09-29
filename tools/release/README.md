# Release tooling

Builds one release set from given binaries:

- five platform archives (`.tar.gz`, windows `.zip`);
- the client kit and the Compose kit;
- the canonical `release.json`, `SHA256SUMS` and `release.json.minisig`;
- the OCI index for `linux/amd64` and `linux/arm64`.

| File | Does |
|---|---|
| `build.py` | archives, kits, manifest, sums and signature from `--bin <target>=<path>` inputs |
| `build.py` | key rotation: `--next-key <seed>` adds `next_key_id` to `release.json` and writes `release.json.<id>.minisig` and `release-key-<id>.pub` beside the set; `release verify --key-id <id>` admits the next key |
| `build.py` | the image: `--image-repository <repo>` + `--image-out <dir>` build the linux/amd64+arm64 OCI index from the musl `--bin` inputs, record it in `release.json` (`image`), pin `@IMAGE@` in the Compose kit to `<repo>@<index_digest>`; `--image-push` publishes the index first and checks the pushed bytes against the recorded digest |
| `compose-kit/` | the release-specific, digest-pinned `compose.yaml`, `env.example` and instructions |
| `check-compose-kit.sh` | the gate over `compose-kit/compose.yaml`: fails on any deployment-forbidden key or value (run after editing the kit) |
| `cross.sh` | the five binaries: alpine musl ×2, macOS ×2 natively, `cargo xwin` for msvc (needs `cargo install --locked cargo-xwin`, `rustup component add llvm-tools` and the owner's acceptance of Microsoft's CRT/SDK license) — `tools/release/cross.sh --out <dir> [--target <triple>]... [--commit <40 hex>] [--allow-dirty]` |
| `publish.sh` | one-command release: validates the signing key path, builds all five targets, publishes the OCI image, and creates the GitHub release with every release artifact |

The signing seed never enters the repository, the build workspace, an
artifact or a log. The tools read it from a path outside the repository
(`--key <seed>`). The public half is `deploy/release-key.pub`, which the
verifier embeds.
