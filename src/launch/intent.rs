//! Account intent: a named reference resolved against the
//! catalogue, or the picker's choice, as the `pin.` intent token of the
//! canonical handle — never the string the engineer typed.

use crate::client::{self, ClientInstallation};
use crate::data_plane::intent::encode_token;
use crate::picker;

use super::{READ_TIMEOUT, Refusal};

/// Resolve `reference` read-only; the token pins its handle.
/// Nothing matched → 6, ambiguous → 7 naming the display names; resolved but
/// unselectable → a warning, and the launch proceeds (the first prompt gets
/// the 429 naming it).
pub(super) async fn resolve(
    installation: &ClientInstallation,
    secret: &str,
    reference: &str,
    notices: &mut Vec<String>,
) -> Result<Option<String>, Refusal> {
    let entry = client::resolve(installation, secret, reference, READ_TIMEOUT)
        .await
        .map_err(|(code, message)| {
            let slug = match code {
                6 => "cli_not_found",
                7 => "cli_ambiguous",
                4 => "cli_unreachable",
                5 => "cli_refused",
                _ => "cli_incompatible_server",
            };
            Refusal::new(code, slug, message)
        })?;
    if !entry.selectable {
        notices.push(format!(
            "jaynshare: warning: {} cannot serve right now; the session is pinned to it, so the first prompt fails naming it — quit and relaunch to switch",
            entry.display_name
        ));
    }
    Ok(Some(encode_token(true, &entry.handle)))
}

/// The picker over the catalogue; its selection is a pin, its
/// automatic row is no token.
pub(super) async fn pick(
    installation: &ClientInstallation,
    secret: &str,
    kind: picker::Kind,
) -> Result<Option<String>, Refusal> {
    let entries = client::catalogue(installation, secret, READ_TIMEOUT)
        .await
        .map_err(|(code, message)| {
            let slug = if code == 4 {
                "cli_unreachable"
            } else {
                "cli_refused"
            };
            Refusal::new(code, slug, message)
        })?;
    let rows: Vec<picker::Row> = entries
        .into_iter()
        .map(|e| picker::Row {
            handle: e.handle,
            display_name: e.display_name,
            selectable: e.selectable,
            five_hour: e.five_hour,
            weekly: e.weekly,
        })
        .collect();
    match picker::pick(&rows, kind) {
        Ok(picker::Choice::Automatic) => Ok(None),
        Ok(picker::Choice::Account(handle)) => Ok(Some(encode_token(true, &handle))),
        Err(picker::PickError::Cancelled) => {
            Err(Refusal::new(15, "cli_picker_cancelled", picker::CANCELLED))
        }
        Err(picker::PickError::NoTerminal) => Err(Refusal::new(
            16,
            "cli_no_terminal",
            "there is no terminal for the account picker; launch with --account <reference> or --auto",
        )),
        Err(picker::PickError::Io(why)) => Err(Refusal::new(
            1,
            "cli_internal",
            format!("the account picker failed: {why}"),
        )),
    }
}
