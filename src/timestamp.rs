//! RFC 3339 rendering shared by the state file, the logs and the control API.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Every persisted or reported timestamp is RFC 3339.
pub fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339)
        .expect("RFC 3339 formats any OffsetDateTime")
}
