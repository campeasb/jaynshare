//! The controlling terminal, opened directly so a launch whose
//! standard input or output is redirected still gets a picker, and so the
//! picker never draws on standard output. `/dev/tty` on Unix; the console's
//! `CONIN$`/`CONOUT$` on Windows.

use std::fs::{File, OpenOptions};
use std::io;

/// The terminal to read keys or lines from, and the one to draw on.
pub struct Terminal {
    pub input: File,
    pub output: File,
}

/// The controlling terminal, or the error that says there is none.
pub fn open() -> io::Result<Terminal> {
    #[cfg(unix)]
    {
        let input = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
        let output = input.try_clone()?;
        Ok(Terminal { input, output })
    }
    #[cfg(windows)]
    {
        let input = OpenOptions::new().read(true).write(true).open("CONIN$")?;
        let output = OpenOptions::new().read(true).write(true).open("CONOUT$")?;
        Ok(Terminal { input, output })
    }
}
