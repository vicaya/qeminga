//! Integration tests that exercise the built `qeminga` binary end to end.
//!
//! Cargo exposes the path to the compiled binary through the
//! `CARGO_BIN_EXE_<name>` environment variable at compile time.
#![forbid(unsafe_code)]

use std::process::Command;

fn qeminga() -> Command {
    Command::new(env!("CARGO_BIN_EXE_qeminga"))
}

#[test]
fn version_flag_prints_crate_version() {
    let output = qeminga()
        .arg("--version")
        .output()
        .expect("failed to run qeminga");
    assert!(output.status.success(), "status: {:?}", output.status);
    let stdout = String::from_utf8(output.stdout).expect("stdout is not UTF-8");
    assert_eq!(stdout.trim_end(), format!("qeminga {}", qeminga::version()));
}

#[test]
fn unknown_argument_is_a_usage_error() {
    let output = qeminga()
        .arg("--bogus")
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(64), "expected EX_USAGE");
    let stderr = String::from_utf8(output.stderr).expect("stderr is not UTF-8");
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}
