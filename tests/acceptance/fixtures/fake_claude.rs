//! The fake `claude`: an executable named as Claude Code
//! is named, compiled by the harness with `rustc` (std only), never part of
//! the product.
//!
//! When run it:
//! - writes its argument vector (without argv[0]) to `$FAKE_CLAUDE_OUT/argv.json`
//!   and its whole environment to `$FAKE_CLAUDE_OUT/env.json`;
//! - exits with `$FAKE_CLAUDE_EXIT` (default 0).
//!
//! It makes no network request: every launch is MITM mode, and a scenario
//! that needs Claude Code's request sends it from the recorded environment
//! (`proxy::claude_request`), since this fake has no TLS.

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write(dir: &str, name: &str, contents: &str) {
    let path = std::path::Path::new(dir).join(name);
    let _ = std::fs::write(path, contents);
}

fn main() {
    let out = std::env::var("FAKE_CLAUDE_OUT").ok();
    if let Some(dir) = &out {
        let argv: Vec<String> = std::env::args_os()
            .skip(1)
            .map(|a| json_string(&a.to_string_lossy()))
            .collect();
        write(dir, "argv.json", &format!("[{}]", argv.join(",")));
        let env: Vec<String> = std::env::vars_os()
            .map(|(k, v)| {
                format!(
                    "{}:{}",
                    json_string(&k.to_string_lossy()),
                    json_string(&v.to_string_lossy())
                )
            })
            .collect();
        write(dir, "env.json", &format!("{{{}}}", env.join(",")));
    }
    let code = std::env::var("FAKE_CLAUDE_EXIT")
        .ok()
        .and_then(|c| c.parse::<i32>().ok())
        .unwrap_or(0);
    std::process::exit(code);
}
