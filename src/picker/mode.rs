//! Which picker runs. The choice is made from the input
//! descriptor — can the controlling terminal be put in raw mode — never
//! from the platform. `--picker` wins over `JAYNSHARE_PICKER`; with
//! no terminal at all there is no picker.

use super::Kind;

/// `forced` is `--picker`, which wins over `JAYNSHARE_PICKER`.
/// `Ok(None)` is no controlling terminal; `Err` is a variable value
/// outside its closed set, checked whether or not there is one.
pub fn choose(forced: Option<Kind>) -> Result<Option<Kind>, String> {
    let variable = std::env::var("JAYNSHARE_PICKER").ok();
    let terminal = super::tty::open().is_ok();
    // The raw probe only runs when the descriptor must decide —
    // no terminal, an override, or an explicit variable settles it first.
    let raw = terminal
        && forced.is_none()
        && parse(variable.as_deref())?.is_none()
        && crossterm::terminal::enable_raw_mode().is_ok();
    if raw {
        let _ = crossterm::terminal::disable_raw_mode();
    }
    decide(forced, variable.as_deref(), terminal, raw)
}

/// The decision, pure: the variable is checked first (whether or not
/// there is an override), then no terminal is `Ok(None)`, then the
/// override, then the variable's kind, then the descriptor — `raw` gets the
/// keyboard picker, otherwise the numbered prompt.
fn decide(
    forced: Option<Kind>,
    variable: Option<&str>,
    terminal: bool,
    raw: bool,
) -> Result<Option<Kind>, String> {
    if forced.is_none() {
        parse(variable)?;
    }
    if !terminal {
        return Ok(None);
    }
    if let Some(kind) = forced {
        return Ok(Some(kind));
    }
    if let Some(kind) = parse(variable)? {
        return Ok(Some(kind));
    }
    Ok(if raw {
        Some(Kind::Keyboard)
    } else {
        Some(Kind::Numbered)
    })
}

/// The closed set. `None` or empty means no override.
fn parse(value: Option<&str>) -> Result<Option<Kind>, String> {
    match value {
        None | Some("") => Ok(None),
        Some("keyboard") => Ok(Some(Kind::Keyboard)),
        Some("numbered") => Ok(Some(Kind::Numbered)),
        Some(value) => Err(format!(
            "JAYNSHARE_PICKER={value:?} is not a picker; set it to keyboard or numbered, or unset it"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_or_empty_means_no_override() {
        assert_eq!(parse(None), Ok(None));
        assert_eq!(parse(Some("")), Ok(None));
    }

    #[test]
    fn the_two_values_are_the_pickers() {
        assert_eq!(parse(Some("keyboard")), Ok(Some(Kind::Keyboard)));
        assert_eq!(parse(Some("numbered")), Ok(Some(Kind::Numbered)));
    }

    #[test]
    fn anything_else_refuses_naming_the_variable_and_the_values() {
        let error = parse(Some("sideways")).unwrap_err();
        assert!(error.contains("JAYNSHARE_PICKER"));
        assert!(error.contains("keyboard") && error.contains("numbered"));
        assert_eq!(
            error,
            "JAYNSHARE_PICKER=\"sideways\" is not a picker; set it to keyboard or numbered, or unset it"
        );
    }

    // The descriptor without raw mode gets the numbered picker.
    #[test]
    fn no_raw_mode_means_numbered() {
        assert_eq!(decide(None, None, true, false), Ok(Some(Kind::Numbered)));
    }

    #[test]
    fn raw_mode_means_keyboard() {
        assert_eq!(decide(None, None, true, true), Ok(Some(Kind::Keyboard)));
    }

    // An override forces either, whatever the descriptor says.
    #[test]
    fn the_override_wins_over_the_descriptor() {
        assert_eq!(
            decide(Some(Kind::Keyboard), None, true, false),
            Ok(Some(Kind::Keyboard))
        );
        assert_eq!(
            decide(Some(Kind::Numbered), None, true, true),
            Ok(Some(Kind::Numbered))
        );
    }

    #[test]
    fn the_variable_chooses_the_kind() {
        assert_eq!(
            decide(None, Some("numbered"), true, true),
            Ok(Some(Kind::Numbered))
        );
    }

    // `--picker` wins over the variable.
    #[test]
    fn the_override_wins_over_the_variable() {
        assert_eq!(
            decide(Some(Kind::Numbered), Some("keyboard"), true, true),
            Ok(Some(Kind::Numbered))
        );
    }

    // No terminal, no picker.
    #[test]
    fn no_terminal_means_no_picker() {
        assert_eq!(decide(None, None, false, true), Ok(None));
    }
}
