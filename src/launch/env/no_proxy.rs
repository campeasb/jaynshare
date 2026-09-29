//! In MITM mode the no-proxy list is loopback plus the engineer's
//! own `no_proxy` members from `client.toml`, in both spellings.

use super::EnvPlan;

const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "::1"];

/// The no-proxy list is the loopback entries plus the `client.toml`
/// members, in both spellings, replacing whatever the shell exported.
pub fn apply(plan: &mut EnvPlan, members: &[String]) {
    let mut entries: Vec<String> = LOOPBACK.iter().map(|e| e.to_string()).collect();
    for member in members {
        let member = member.trim();
        if !member.is_empty() && !entries.iter().any(|e| e == member) {
            entries.push(member.to_string());
        }
    }
    let value = entries.join(",");
    for name in super::NO_PROXY_VARIABLES {
        plan.set(name, value.clone());
    }
}
