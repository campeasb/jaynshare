//! The account picker: a first **automatic** row,
//! then the catalogue in the server's order, each row a display name, its
//! five-hour and weekly utilisation, and whether it can be chosen now. Two
//! implementations: a keyboard picker when the controlling
//! terminal can be put in raw mode, a numbered prompt otherwise.
//! Both draw on the terminal, never on standard output.

/// The refusal when the picker is cancelled — shared with
/// `src/launch/intent.rs` so they cannot drift. The trailing marker is part
/// of the observable message (the acceptance test matches it verbatim).
pub const CANCELLED: &str = "the account picker was cancelled; nothing was launched. Launch without the picker with --account <reference> or --auto";

pub mod keyboard;
pub mod mode;
pub mod numbered;
pub mod render;
pub mod tty;

/// One catalogue entry as the picker shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub handle: String,
    pub display_name: String,
    pub selectable: bool,
    pub five_hour: Option<f64>,
    pub weekly: Option<f64>,
}

/// What the engineer chose: the automatic row, or one account by handle
/// (the handle, never the display name).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Automatic,
    Account(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickError {
    /// The cancel key, an interrupt or end of input.
    Cancelled,
    /// No usable terminal.
    NoTerminal,
    /// A drawing or reading failure; the terminal is restored first.
    Io(String),
}

/// The two pickers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Keyboard,
    Numbered,
}

/// The picker this launch can run — `forced` is `--picker`, which
/// wins over `JAYNSHARE_PICKER` — or `None` when there is no usable terminal.
/// `Err` is a `JAYNSHARE_PICKER` value outside its closed set, whose
/// message names the variable and the two values.
pub fn choose(forced: Option<Kind>) -> Result<Option<Kind>, String> {
    mode::choose(forced)
}

/// Show `rows` and return the engineer's choice.
pub fn pick(rows: &[Row], kind: Kind) -> Result<Choice, PickError> {
    match kind {
        Kind::Keyboard => keyboard::pick(rows),
        Kind::Numbered => numbered::pick(rows),
    }
}
