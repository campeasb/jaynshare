//! The keyboard picker — a moving marker, up/down wrap
//! at both ends, confirm does nothing on an unselectable row, the cancel key
//! and Ctrl-C (a byte in raw mode) cancel. Drawn inline on the controlling
//! terminal (`/dev/tty` where there is one), raw mode and the cursor
//! restored on every exit path by a guard's `Drop`.

use super::{Choice, PickError, Row};
use std::fs::File;
use std::io::Write;

use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
use crossterm::{cursor, execute, queue, style, terminal};

/// Restores raw mode and the cursor when dropped — every return,
/// `?` and panic. The panic and drawing-error paths share this one guard.
struct Restore<'a>(&'a mut File);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = execute!(self.0, cursor::Show, style::Print("\r\n"),);
    }
}

fn io(why: std::io::Error) -> PickError {
    PickError::Io(why.to_string())
}

/// The arrow-key picker; `j` and `k` move like the arrows.
pub fn pick(rows: &[Row]) -> Result<Choice, PickError> {
    let mut terminal = super::tty::open().map_err(|_| PickError::NoTerminal)?;
    let charset = super::render::charset();
    let labels = super::render::labels(rows, super::render::name_width(), charset);
    let marker = super::render::marker(charset);
    let n = labels.len();
    let selectable = |i: usize| i == 0 || rows[i - 1].selectable;

    terminal::enable_raw_mode().map_err(io)?;
    queue!(terminal.output, cursor::Hide).map_err(io)?;
    let restore = Restore(&mut terminal.output);

    let mut current = 0usize;
    queue!(
        restore.0,
        terminal::Clear(terminal::ClearType::FromCursorDown)
    )
    .map_err(io)?;
    let mut text =
        String::from("Choose the account for this session (up/down or j/k, Enter; Esc cancels):");
    for (i, label) in labels.iter().enumerate() {
        text.push_str(&format!(
            "\r\n\r{} {label}",
            if i == current { marker } else { " " },
        ));
    }
    text.push_str("\r\n");
    write!(restore.0, "{text}").map_err(io)?;
    restore.0.flush().map_err(io)?;

    loop {
        let event = read().map_err(io)?;
        let Event::Key(key) = event else { continue };
        if key.kind == KeyEventKind::Release {
            continue;
        }
        match (key.code, key.modifiers) {
            (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                current = (current + n - 1) % n;
                redraw(restore.0, &labels, marker, current)?;
            }
            (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                current = (current + 1) % n;
                redraw(restore.0, &labels, marker, current)?;
            }
            (KeyCode::Enter, _) if selectable(current) => {
                return if current == 0 {
                    Ok(Choice::Automatic)
                } else {
                    Ok(Choice::Account(rows[current - 1].handle.clone()))
                };
            }
            (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => return Err(PickError::Cancelled),
            (KeyCode::Char('c'), KeyModifiers::CONTROL)
            | (KeyCode::Char('d'), KeyModifiers::CONTROL) => return Err(PickError::Cancelled),
            _ => {} // Confirm (and anything else) ignored where not applicable
        }
    }
}

/// Rewrite the rows in place after a move.
fn redraw(
    out: &mut File,
    labels: &[String],
    marker: &str,
    current: usize,
) -> Result<(), PickError> {
    let n = labels.len();
    queue!(out, cursor::MoveUp(n as u16)).map_err(io)?;
    for (i, label) in labels.iter().enumerate() {
        queue!(out, terminal::Clear(terminal::ClearType::CurrentLine)).map_err(io)?;
        write!(
            out,
            "{} {label}\r\n",
            if i == current { marker } else { " " }
        )
        .map_err(io)?;
    }
    out.flush().map_err(io)
}
