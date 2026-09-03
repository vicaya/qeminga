//! qeminga daemon entry point.
//!
//! Responsibilities (design §6): parse configuration, open the channel,
//! drop capabilities, install seccomp, then start the async runtime and the
//! dispatcher loop. Only `--version` is implemented so far; the rest is
//! tracked in `docs/tasks.md`.
//!
//! Nothing here may panic (AGENTS.md): arguments are handled as `OsStr` so a
//! non-UTF-8 argument is a usage error, and output failures are mapped to
//! exit codes instead of aborting.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

/// Exit status for usage errors (`EX_USAGE` from sysexits).
const EXIT_USAGE: u8 = 64;
/// Exit status for an I/O error while writing output (`EX_IOERR` from sysexits).
const EXIT_IOERR: u8 = 74;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [flag] if flag.as_os_str() == "--version" || flag.as_os_str() == "-V" => print_version(),
        [] => {
            diag("qeminga: daemon mode is not implemented yet (see docs/tasks.md)");
            ExitCode::from(EXIT_USAGE)
        }
        other => {
            let rendered: Vec<String> = other
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
            diag(&format!(
                "qeminga: unrecognised arguments: {}",
                rendered.join(" ")
            ));
            diag("usage: qeminga [--version]");
            ExitCode::from(EXIT_USAGE)
        }
    }
}

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
