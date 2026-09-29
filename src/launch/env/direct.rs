//! `--direct` removes every launch-set variable — the four
//! proxy spellings, the no-proxy list, `ANTHROPIC_BASE_URL`,
//! `ANTHROPIC_API_KEY`, `NODE_EXTRA_CA_CERTS`, `ANTHROPIC_CUSTOM_HEADERS` and
//! `API_TIMEOUT_MS` — even when the shell exported them.

use super::EnvPlan;

pub fn apply(plan: &mut EnvPlan) {
    for name in super::PROXY_VARIABLES {
        plan.unset(name);
    }
    for name in super::NO_PROXY_VARIABLES {
        plan.unset(name);
    }
    for name in [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_API_KEY",
        "NODE_EXTRA_CA_CERTS",
        "ANTHROPIC_CUSTOM_HEADERS",
        // The launcher cannot tell whose `API_TIMEOUT_MS` it is, so it
        // goes too.
        "API_TIMEOUT_MS",
    ] {
        plan.unset(name);
    }
}
