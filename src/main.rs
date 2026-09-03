//! qeminga daemon entry point.
//!
//! Responsibilities (design §6): parse configuration, open the channel,
//! drop capabilities, install seccomp, then start the async runtime and the
//! dispatcher loop. Only `--version` is implemented so far; the rest is
//! tracked in `docs/tasks.md`.
#![forbid(unsafe_code)]

use std::process::ExitCode;

/// Exit status used for usage errors (mirrors `EX_USAGE` from sysexits).
const EXIT_USAGE: u8 = 64;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["--version" | "-V"] => {
            println!("qeminga {}", qeminga::version());
            ExitCode::SUCCESS
        }
        [] => {
            eprintln!("qeminga: daemon mode is not implemented yet (see docs/tasks.md)");
            ExitCode::from(EXIT_USAGE)
        }
        other => {
            eprintln!("qeminga: unrecognised arguments: {}", other.join(" "));
            eprintln!("usage: qeminga [--version]");
            ExitCode::from(EXIT_USAGE)
        }
    }
}
