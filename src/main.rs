//! qeminga daemon entry point (design §6): parse the command line, then
//! hand over to [`qeminga::run`], which loads the configuration, opens the
//! channel, drops capabilities, installs seccomp, and starts the runtime.
//!
//! Nothing here may panic (AGENTS.md): arguments are handled as `OsString`
//! so a non-UTF-8 argument is a usage error, and every failure maps to a
//! sysexits code.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use qeminga::daemon::{EX_USAGE, USAGE};

fn main() -> ExitCode {
    match qeminga::parse_args(std::env::args_os().skip(1)) {
        Ok(opts) if opts.version => print_version(),
        Ok(opts) => qeminga::run(opts),
        Err(err) => {
            diag(&format!("qeminga: {err}"));
            diag(USAGE);
            ExitCode::from(EX_USAGE)
        }
    }
}

/// Exit status for an I/O error while writing output (`EX_IOERR`).
const EXIT_IOERR: u8 = 74;

/// Writes the version line to stdout, mapping write failures to exit codes.
fn print_version() -> ExitCode {
    let mut out = io::stdout().lock();
    match writeln!(out, "qeminga {}", qeminga::VERSION).and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        // A closed pipe (`qeminga --version | head -c1`) is not an error for a CLI.
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(EXIT_IOERR),
    }
}

/// Best-effort diagnostic on stderr. A failed write is deliberately ignored:
/// there is nowhere left to report it, and panicking would be worse.
fn diag(msg: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{msg}");
}
