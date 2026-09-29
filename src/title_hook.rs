//! `jaynshare title-hook`: Claude Code's
//! `UserPromptSubmit` hook. It reads the hook payload and, for a prompt that
//! is a topic, prints the hook JSON with the session title. It exits 0 in
//! every case, makes no network request, writes no terminal escape and
//! nothing but its own output — it sees the engineer's prompt, the most
//! sensitive thing on the machine.

use std::io::Read;

use serde_json::{Value, json};

/// Far above any prompt a terminal submits; the hook never blocks on more.
const MAX_INPUT: u64 = 4 * 1024 * 1024;

pub fn main() -> i32 {
    let mut input = Vec::new();
    let mut stdin = std::io::stdin().lock();
    if stdin
        .by_ref()
        .take(MAX_INPUT)
        .read_to_end(&mut input)
        .is_err()
    {
        return 0;
    }
    // A payload over the cap is no payload. The rest is drained, not
    // left unread, so the writer never sees a broken pipe; the 2 s
    // timeout bounds the drain.
    if std::io::copy(&mut stdin, &mut std::io::sink()).unwrap_or(0) > 0 {
        return 0;
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&input) else {
        return 0;
    };
    let Some(prompt) = payload["prompt"].as_str() else {
        return 0;
    };
    if let Some(title) = preview(prompt) {
        let output = json!({
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "sessionTitle": title,
            }
        });
        println!("{output}");
    }
    0
}

/// The whole title (at most 72 characters) from `prompt`: control
/// characters removed, whitespace runs collapsed, trimmed, truncated with an
/// ellipsis. The prompt alone — the product never brands the session's
/// title. `None` for an empty prompt or one whose first character marks an
/// instruction (`/`, `#`, `!`).
pub fn preview(prompt: &str) -> Option<String> {
    match prompt.chars().find(|c| !c.is_whitespace()) {
        None => return None,
        Some('/') | Some('#') | Some('!') => return None,
        Some(_) => {}
    }
    let cleaned: String = prompt
        .chars()
        .filter_map(|c| {
            if c.is_control() {
                c.is_whitespace().then_some(' ')
            } else {
                Some(c)
            }
        })
        .collect();
    let text = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.is_empty() {
        return None;
    }
    if text.chars().count() > 72 {
        let cut: String = text.chars().take(71).collect();
        return Some(format!("{}\u{2026}", cut.trim_end()));
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_and_empty_prompts_give_none() {
        assert_eq!(preview(""), None);
        assert_eq!(preview("   "), None);
        assert_eq!(preview("/help"), None);
        assert_eq!(preview("  /compact now"), None);
        assert_eq!(preview("# remember the port"), None);
        assert_eq!(preview("!ls -la"), None);
    }

    #[test]
    fn cleaning_collapses_whitespace_and_drops_controls() {
        assert_eq!(
            preview("fix\tthe\n\nlogin   bug\u{7}"),
            Some("fix the login bug".to_owned())
        );
        assert_eq!(
            preview("  café  au  lait  "),
            Some("café au lait".to_owned())
        );
    }

    #[test]
    fn the_whole_title_is_at_most_72_characters() {
        let kept = preview(&"x".repeat(72)).unwrap();
        assert_eq!(kept.chars().count(), 72);
        assert!(kept.ends_with('x'));

        let cut = preview(&"x".repeat(73)).unwrap();
        assert_eq!(cut.chars().count(), 72);
        assert!(cut.ends_with("x\u{2026}"));
    }

    #[test]
    fn the_title_carries_no_product_mark() {
        assert!(!preview("fix the login bug").unwrap().contains("jaynshare"));
    }
}
