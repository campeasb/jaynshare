//! The private-network preflight. `server preflight` is interactive-only,
//! so its tests drive it through `cli_pty`. The root, systemd and `nft`
//! cases run in a `LinuxBox` and skip without it.

#[allow(unused_imports)]
use crate::harness::{cli_pty, cli_raw, isolated_env, scratch};
