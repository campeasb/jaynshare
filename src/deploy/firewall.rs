//! Whether the host firewall admits a listener from a public interface or
//! source range. The one tool wrapper is [`nft_ruleset`]; the test suite's
//! fake `nft` answers only it.

use serde_json::Value;

use std::net::SocketAddr;

use super::address::{self, AddressClass};

/// The firewall check's three outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Admitted only from the private interface or source range.
    Private,
    /// Admitted from a public interface or source range: the rule that does it.
    PublicAdmitted(String),
    /// The firewall could not be inspected: why. Unattended installs refuse.
    Unknown(String),
}

/// The firewall verdict for one listener on `interface`.
pub fn inspect(listener: SocketAddr, interface: &str) -> Verdict {
    match nft_ruleset() {
        Ok(ruleset) => judge(&ruleset, listener, interface),
        Err(why) => Verdict::Unknown(why),
    }
}

/// [`judge`] reads only these payload/meta matches and these verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadKind {
    L4proto,
    Dport,
    Iifname,
    Saddr,
}

/// What one rule contributes to a chain's walk.
enum RuleOutcome {
    /// The rule cannot match new TCP traffic to the port, or is restricted
    /// to the private interface or a closed source range: keep walking.
    Skip,
    /// An unrestricted accept for the port: publicly admitted.
    Public(String),
    /// An unrestricted drop or reject for the port: nothing after it admits.
    Ends,
}

/// A relevant chain: `filter` type, `input` or `forward` hook.
struct RelevantChain<'a> {
    name: &'a str,
    policy_drop: bool,
    rules: Vec<&'a Value>,
}

/// The firewall verdict over an already-read `nft -j list ruleset` JSON
/// document. Pure: no `nft`, no host — every unit test is hand-written JSON.
pub fn judge(ruleset_json: &str, listener: SocketAddr, interface: &str) -> Verdict {
    let ruleset: Value = match serde_json::from_str(ruleset_json) {
        Ok(ruleset) => ruleset,
        Err(e) => return Verdict::Unknown(format!("cannot parse the nft ruleset JSON: {e}")),
    };
    let Some(objects) = ruleset.get("nftables").and_then(Value::as_array) else {
        return Verdict::Unknown("the nft ruleset JSON has no nftables list".into());
    };
    let mut chains: Vec<RelevantChain<'_>> = Vec::new();
    for object in objects {
        let Some(chain) = object.get("chain") else {
            continue;
        };
        if !matches!(
            chain.get("family").and_then(Value::as_str),
            Some("inet" | "ip" | "ip6")
        ) {
            continue;
        }
        if chain.get("type").and_then(Value::as_str) != Some("filter") {
            continue;
        }
        if !matches!(
            chain.get("hook").and_then(Value::as_str),
            Some("input" | "forward")
        ) {
            continue;
        }
        let name = chain.get("name").and_then(Value::as_str).unwrap_or("");
        let table = chain.get("table").and_then(Value::as_str).unwrap_or("");
        chains.push(RelevantChain {
            name,
            policy_drop: chain.get("policy").and_then(Value::as_str) == Some("drop"),
            rules: objects
                .iter()
                .filter_map(|object| object.get("rule"))
                .filter(|rule| {
                    rule.get("family").and_then(Value::as_str)
                        == chain.get("family").and_then(Value::as_str)
                        && rule.get("table").and_then(Value::as_str) == Some(table)
                        && rule.get("chain").and_then(Value::as_str) == Some(name)
                })
                .collect(),
        });
    }
    if chains.is_empty() {
        return Verdict::PublicAdmitted("no input chain: every interface is admitted".into());
    }
    for chain in &chains {
        match walk_chain(chain, listener.port(), interface) {
            Verdict::PublicAdmitted(why) => return Verdict::PublicAdmitted(why),
            Verdict::Unknown(why) => return Verdict::Unknown(why),
            Verdict::Private => {}
        }
    }
    Verdict::Private
}

fn walk_chain(chain: &RelevantChain<'_>, port: u16, interface: &str) -> Verdict {
    for rule in &chain.rules {
        match judge_rule(rule, port, interface, chain.name) {
            Ok(RuleOutcome::Skip) => {}
            Ok(RuleOutcome::Public(why)) => return Verdict::PublicAdmitted(why),
            Ok(RuleOutcome::Ends) => break,
            Err(why) => return Verdict::Unknown(why),
        }
    }
    if chain.policy_drop {
        Verdict::Private
    } else {
        Verdict::PublicAdmitted(format!("chain {} policy accept", chain.name))
    }
}

/// One rule's effect on new TCP traffic to `port`, or why it is unreadable.
fn judge_rule(
    rule: &Value,
    port: u16,
    interface: &str,
    chain: &str,
) -> Result<RuleOutcome, String> {
    let handle = rule.get("handle").and_then(Value::as_u64).unwrap_or(0);
    let unknown = |what: &str| {
        format!("rule {handle} in chain {chain} uses {what}, which preflight does not read")
    };
    let Some(exprs) = rule.get("expr").and_then(Value::as_array) else {
        return Ok(RuleOutcome::Skip);
    };
    let mut applies = true;
    let mut restricted = false;
    let mut reason = "no interface or source restriction".to_string();
    let mut verdict: Option<&str> = None;
    for item in exprs {
        let Some((key, value)) = item.as_object().and_then(|o| o.iter().next()) else {
            return Err(unknown("an unreadable expression"));
        };
        match key.as_str() {
            "counter" => {}
            // nft writes a verdict statement bare (`{"accept": null}`); the
            // `verdict` wrapper is read too.
            "accept" => verdict = Some("accept"),
            "drop" => verdict = Some("drop"),
            "reject" => verdict = Some("reject"),
            "verdict" => {
                verdict = Some(
                    verdict_name(value)
                        .ok_or_else(|| unknown("a verdict preflight does not read"))?,
                );
            }
            "match" => {
                read_match(
                    value,
                    port,
                    interface,
                    &mut applies,
                    &mut restricted,
                    &mut reason,
                    &unknown,
                )?;
            }
            other => return Err(unknown(other)),
        }
    }
    if !applies {
        // The rule can never match new TCP traffic to the port.
        return Ok(RuleOutcome::Skip);
    }
    match verdict {
        None => Ok(RuleOutcome::Skip),
        Some("accept") if restricted => Ok(RuleOutcome::Skip),
        Some("accept") => Ok(RuleOutcome::Public(format!(
            "chain {chain} rule {handle}: {reason}"
        ))),
        Some("drop" | "reject") if restricted => Ok(RuleOutcome::Skip),
        Some("drop" | "reject") => Ok(RuleOutcome::Ends),
        Some(_) => unreachable!("verdict_name only returns accept, drop and reject"),
    }
}

fn read_match(
    value: &Value,
    port: u16,
    interface: &str,
    applies: &mut bool,
    restricted: &mut bool,
    reason: &mut String,
    unknown: &dyn Fn(&str) -> String,
) -> Result<(), String> {
    let left = value.get("left").unwrap_or(&Value::Null);
    let right = value.get("right").unwrap_or(&Value::Null);
    let op = value.get("op").and_then(Value::as_str).unwrap_or("==");
    if left.get("ct").is_some() {
        // `ct state established,related` admits no new connection; a rule
        // whose conntrack state excludes `new`/`untracked` cannot match it.
        return match ct_states(right) {
            Some(states) if !states.iter().any(|s| s == "new" || s == "untracked") => {
                *applies = false;
                Ok(())
            }
            Some(_) => Ok(()),
            None => Err(unknown("an unreadable conntrack match")),
        };
    }
    let kind = if let Some(meta) = left.get("meta").and_then(Value::as_object) {
        match meta.get("key").and_then(Value::as_str) {
            Some("l4proto") => ReadKind::L4proto,
            Some("iifname") => ReadKind::Iifname,
            _ => return Err(unknown("an unreadable meta match")),
        }
    } else if let Some(payload) = left.get("payload").and_then(Value::as_object) {
        match (
            payload.get("protocol").and_then(Value::as_str),
            payload.get("field").and_then(Value::as_str),
        ) {
            (Some("tcp"), Some("dport")) => ReadKind::Dport,
            (Some("ip" | "ip6"), Some("saddr")) => ReadKind::Saddr,
            _ => return Err(unknown("an unreadable payload match")),
        }
    } else {
        return Err(unknown("an unreadable match"));
    };
    let text = || match right.as_str() {
        Some(text) => text.to_string(),
        None => right.to_string(),
    };
    // Equality or set membership only: any other operator on a port or a
    // protocol is outside this subset, and guessing could call a public
    // admission private.
    let equality = matches!(op, "==" | "in");
    match kind {
        ReadKind::L4proto => match (equality, holds(right, &|v| is_tcp(v))) {
            (true, Some(true)) => {}
            // The rule can never match TCP traffic.
            (true, Some(false)) => *applies = false,
            _ => return Err(unknown("an unreadable protocol match")),
        },
        ReadKind::Dport => match (equality, holds(right, &|v| holds_port(v, port))) {
            (true, Some(true)) => {}
            // A different port: the rule cannot match.
            (true, Some(false)) => *applies = false,
            _ => return Err(unknown("an unreadable port match")),
        },
        // A rule's matches all hold at once, so one restricting match
        // restricts the rule; a match that does not restrict leaves it as is.
        ReadKind::Iifname => {
            let names = holds(right, &|v| {
                v.as_str().map(|name| name == interface || name == "lo")
            });
            if equality && names == Some(true) {
                *restricted = true;
            } else if !*restricted {
                *reason = format!("iifname {op} {}", text());
            }
        }
        ReadKind::Saddr => {
            let Some(inside) = every(right, &saddr_restricted) else {
                return Err(unknown("an unreadable source-address match"));
            };
            if equality && inside {
                *restricted = true;
            } else if !*restricted {
                *reason = format!("source {op} {}", text());
            }
        }
    }
    Ok(())
}

/// `accept` / `drop` / `reject`, as nft's JSON writes them (bare string or
/// one-key object).
fn verdict_name(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(s) => match s.as_str() {
            "accept" => Some("accept"),
            "drop" => Some("drop"),
            "reject" => Some("reject"),
            _ => None,
        },
        Value::Object(o) => ["accept", "drop", "reject"]
            .into_iter()
            .find(|name| o.contains_key(*name)),
        _ => None,
    }
}

fn ct_states(right: &Value) -> Option<Vec<String>> {
    match right {
        Value::String(s) => Some(s.split(',').map(str::trim).map(String::from).collect()),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(String::from))
            .collect(),
        _ => None,
    }
}

/// `pred` over a match's right-hand side: a scalar, or `{"set": [...]}`
/// holding when any member does. `None` when anything is unreadable.
fn holds(right: &Value, pred: &dyn Fn(&Value) -> Option<bool>) -> Option<bool> {
    match right.get("set").and_then(Value::as_array) {
        Some(members) => members
            .iter()
            .try_fold(false, |any, member| Some(pred(member)? || any)),
        None => pred(right),
    }
}

/// [`holds`] with every member of a set required to hold.
fn every(right: &Value, pred: &dyn Fn(&Value) -> Option<bool>) -> Option<bool> {
    match right.get("set").and_then(Value::as_array) {
        Some(members) => members
            .iter()
            .try_fold(true, |all, member| Some(pred(member)? && all)),
        None => pred(right),
    }
}

/// `tcp` by name or protocol number.
fn is_tcp(value: &Value) -> Option<bool> {
    match value {
        Value::String(name) => Some(name == "tcp"),
        Value::Number(number) => Some(number.as_u64()? == 6),
        _ => None,
    }
}

/// A port number, or `{"range": [low, high]}`, covering `port`.
fn holds_port(value: &Value, port: u16) -> Option<bool> {
    let port = u64::from(port);
    match value {
        Value::Number(number) => Some(number.as_u64()? == port),
        Value::Object(object) => {
            let range = object.get("range")?.as_array()?;
            let [low, high] = range.as_slice() else {
                return None;
            };
            Some((low.as_u64()?..=high.as_u64()?).contains(&port))
        }
        _ => None,
    }
}

/// A source network is restricted when it lies entirely inside the
/// closed list: `address::classify` of the network address must pass, and
/// the prefix must be no shorter than the closed range's.
/// `None` when the element is unreadable.
fn saddr_restricted(right: &Value) -> Option<bool> {
    let (ip_text, prefix) = match right {
        Value::String(text) => match text.split_once('/') {
            Some((ip_text, prefix)) => (ip_text, Some(prefix.parse::<u8>().ok()?)),
            None => (text.as_str(), None),
        },
        // nft's JSON form of `10.0.0.0/8`.
        Value::Object(object) => {
            let prefix = object.get("prefix")?;
            (
                prefix.get("addr")?.as_str()?,
                Some(u8::try_from(prefix.get("len")?.as_u64()?).ok()?),
            )
        }
        _ => return None,
    };
    let ip: std::net::IpAddr = ip_text.parse().ok()?;
    let class = address::classify(ip);
    if !class.passes() {
        return Some(false);
    }
    let prefix = prefix.unwrap_or(match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    });
    let closed = match (ip, class) {
        (std::net::IpAddr::V4(_), AddressClass::Loopback) => 8,
        (std::net::IpAddr::V4(v4), AddressClass::Private) => match v4.octets() {
            [10, ..] => 8,
            [172, 16..=31, ..] => 12,
            _ => 16,
        },
        (std::net::IpAddr::V4(_), AddressClass::SharedAddressSpace) => 10,
        (std::net::IpAddr::V6(_), AddressClass::Loopback) => 128,
        (std::net::IpAddr::V6(_), AddressClass::UniqueLocal) => 7,
        _ => return Some(false),
    };
    Some(prefix >= closed)
}

/// `nft -j list ruleset`: the JSON ruleset, or why it could not be read.
pub fn nft_ruleset() -> Result<String, String> {
    let output = std::process::Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .map_err(|e| format!("nft: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "nft exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "nft: the ruleset is not UTF-8".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::net::{IpAddr, Ipv4Addr};

    const PORT: u16 = 8080;
    const INTERFACE: &str = "eth1";

    fn chain(policy: &str) -> Value {
        json!({"chain": {
            "family": "inet", "table": "filter", "name": "input",
            "type": "filter", "hook": "input", "policy": policy,
        }})
    }

    fn rule(handle: u64, expr: Value) -> Value {
        json!({"rule": {
            "family": "inet", "table": "filter", "chain": "input",
            "handle": handle, "expr": expr,
        }})
    }

    fn dport_match() -> Value {
        json!({"match": {
            "op": "==",
            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
            "right": PORT,
        }})
    }

    fn iifname_match(name: &str) -> Value {
        json!({"match": {
            "op": "==",
            "left": {"meta": {"key": "iifname"}},
            "right": name,
        }})
    }

    fn saddr_match(network: &str) -> Value {
        json!({"match": {
            "op": "==",
            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
            "right": network,
        }})
    }

    fn accept() -> Value {
        json!({"verdict": {"accept": null}})
    }

    fn drop() -> Value {
        json!({"verdict": {"drop": null}})
    }

    fn judge_chains(items: Vec<Value>) -> Verdict {
        judge(
            &json!({"nftables": items}).to_string(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), PORT),
            INTERFACE,
        )
    }

    #[test]
    fn empty_ruleset_is_publicly_admitted() {
        assert_eq!(
            judge_chains(vec![]),
            Verdict::PublicAdmitted("no input chain: every interface is admitted".into())
        );
    }

    #[test]
    fn policy_drop_private_interface_is_private() {
        let verdict = judge_chains(vec![
            chain("drop"),
            rule(
                5,
                json!([dport_match(), iifname_match(INTERFACE), accept()]),
            ),
        ]);
        assert_eq!(verdict, Verdict::Private);
    }

    #[test]
    fn policy_drop_other_interface_is_publicly_admitted() {
        let verdict = judge_chains(vec![
            chain("drop"),
            rule(5, json!([dport_match(), iifname_match("eth0"), accept()])),
        ]);
        assert!(matches!(verdict, Verdict::PublicAdmitted(_)), "{verdict:?}");
    }

    #[test]
    fn unrestricted_drop_before_accept_is_private() {
        let verdict = judge_chains(vec![
            chain("drop"),
            rule(5, json!([dport_match(), drop()])),
            rule(6, json!([dport_match(), accept()])),
        ]);
        assert_eq!(verdict, Verdict::Private);
    }

    #[test]
    fn policy_drop_unrestricted_accept_is_publicly_admitted() {
        let verdict = judge_chains(vec![
            chain("drop"),
            rule(
                5,
                json!([{ "counter": {"bytes": 1}}, dport_match(), accept()]),
            ),
        ]);
        assert!(matches!(verdict, Verdict::PublicAdmitted(_)), "{verdict:?}");
    }

    #[test]
    fn policy_accept_is_publicly_admitted() {
        let verdict = judge_chains(vec![chain("accept")]);
        assert_eq!(
            verdict,
            Verdict::PublicAdmitted("chain input policy accept".into())
        );
    }

    #[test]
    fn private_source_restriction_is_private() {
        let verdict = judge_chains(vec![
            chain("drop"),
            rule(
                5,
                json!([dport_match(), saddr_match("10.0.0.0/8"), accept()]),
            ),
        ]);
        assert_eq!(verdict, Verdict::Private);
    }

    #[test]
    fn any_source_restriction_is_publicly_admitted() {
        let verdict = judge_chains(vec![
            chain("drop"),
            rule(
                5,
                json!([dport_match(), saddr_match("0.0.0.0/0"), accept()]),
            ),
        ]);
        assert!(matches!(verdict, Verdict::PublicAdmitted(_)), "{verdict:?}");
    }

    #[test]
    fn unknown_expression_is_unknown() {
        for expr in [
            json!([{ "jump": {"target": "other"}}, accept()]),
            json!([{ "vmap": {"key": {}, "map": {}}}, accept()]),
        ] {
            let verdict = judge_chains(vec![chain("drop"), rule(5, expr)]);
            assert!(matches!(verdict, Verdict::Unknown(_)), "{verdict:?}");
        }
    }

    #[test]
    fn unparsable_json_is_unknown() {
        assert!(matches!(
            judge(
                "not json",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), PORT),
                INTERFACE
            ),
            Verdict::Unknown(_)
        ));
    }

    /// nft's own JSON: bare verdict statements and `{"prefix": …}` sources.
    fn nft_prefix(addr: &str, len: u8) -> Value {
        json!({"match": {
            "op": "==",
            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
            "right": {"prefix": {"addr": addr, "len": len}},
        }})
    }

    #[test]
    fn nfts_own_verdict_and_prefix_forms_are_read() {
        let bare_accept = json!({"accept": null});
        assert_eq!(
            judge_chains(vec![
                chain("drop"),
                rule(
                    1,
                    json!([dport_match(), nft_prefix("10.0.0.0", 8), bare_accept])
                ),
            ]),
            Verdict::Private
        );
        assert!(matches!(
            judge_chains(vec![
                chain("drop"),
                rule(
                    2,
                    json!([dport_match(), nft_prefix("0.0.0.0", 0), {"accept": null}])
                ),
            ]),
            Verdict::PublicAdmitted(_)
        ));
        assert!(matches!(
            judge_chains(vec![
                chain("drop"),
                rule(3, json!([dport_match(), {"accept": null}]))
            ]),
            Verdict::PublicAdmitted(_)
        ));
    }

    #[test]
    fn a_port_or_protocol_set_holding_the_port_is_read_not_skipped() {
        let port_set = json!({"match": {
            "op": "==",
            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
            "right": {"set": [22, {"range": [8000, 9000]}]},
        }});
        assert!(matches!(
            judge_chains(vec![chain("drop"), rule(1, json!([port_set, accept()]))]),
            Verdict::PublicAdmitted(_)
        ));
        let other_ports = json!({"match": {
            "op": "==",
            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
            "right": {"set": [22, 443]},
        }});
        assert_eq!(
            judge_chains(vec![chain("drop"), rule(2, json!([other_ports, accept()]))]),
            Verdict::Private
        );
        let protocols = json!({"match": {
            "op": "==",
            "left": {"meta": {"key": "l4proto"}},
            "right": {"set": ["udp", "tcp"]},
        }});
        assert!(matches!(
            judge_chains(vec![chain("drop"), rule(3, json!([protocols, accept()]))]),
            Verdict::PublicAdmitted(_)
        ));
        let not_the_port = json!({"match": {
            "op": "!=",
            "left": {"payload": {"protocol": "tcp", "field": "dport"}},
            "right": 22,
        }});
        assert!(matches!(
            judge_chains(vec![
                chain("drop"),
                rule(4, json!([not_the_port, accept()]))
            ]),
            Verdict::Unknown(_)
        ));
    }

    #[test]
    fn a_negated_private_source_or_interface_restricts_nothing() {
        let not_private = json!({"match": {
            "op": "!=",
            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
            "right": {"prefix": {"addr": "10.0.0.0", "len": 8}},
        }});
        assert!(matches!(
            judge_chains(vec![
                chain("drop"),
                rule(1, json!([dport_match(), not_private, accept()]))
            ]),
            Verdict::PublicAdmitted(_)
        ));
        let not_private_interface = json!({"match": {
            "op": "!=",
            "left": {"meta": {"key": "iifname"}},
            "right": INTERFACE,
        }});
        assert!(matches!(
            judge_chains(vec![
                chain("drop"),
                rule(2, json!([dport_match(), not_private_interface, accept()])),
            ]),
            Verdict::PublicAdmitted(_)
        ));
        // Both matches hold at once: the private interface restricts the
        // rule even beside a wide source.
        assert_eq!(
            judge_chains(vec![
                chain("drop"),
                rule(
                    3,
                    json!([
                        dport_match(),
                        iifname_match(INTERFACE),
                        saddr_match("0.0.0.0/0"),
                        accept()
                    ])
                ),
            ]),
            Verdict::Private
        );
    }
}
