//! MITM mode — the four proxy variable spellings carrying
//! `http://<token>:<secret>@<proxy origin>`, `NODE_EXTRA_CA_CERTS`
//! at the installation's `ca.pem` as a native path, and `ANTHROPIC_BASE_URL`
//! and `ANTHROPIC_API_KEY` removed. The secret travels as the proxy URL's
//! password; no bearer-token variable.

use super::{EnvPlan, Inputs, PROXY_VARIABLES};

pub fn apply(plan: &mut EnvPlan, inputs: &Inputs<'_>) {
    let origin = inputs.installation.proxy.as_deref().unwrap_or_default();
    let authority = origin
        .strip_prefix("http://")
        .unwrap_or(origin)
        .trim_end_matches('/');
    let user = inputs
        .token
        .map(crate::client::percent_encode)
        .unwrap_or_default();
    let password = crate::client::percent_encode(inputs.secret);
    let url = format!("http://{user}:{password}@{authority}");
    for name in PROXY_VARIABLES.iter() {
        plan.set(name, url.clone());
    }
    plan.set(
        "NODE_EXTRA_CA_CERTS",
        inputs
            .installation
            .directory
            .join("ca.pem")
            .display()
            .to_string(),
    );
    plan.unset("ANTHROPIC_BASE_URL");
    plan.unset("ANTHROPIC_API_KEY");
    plan.unset("ANTHROPIC_CUSTOM_HEADERS");
}
