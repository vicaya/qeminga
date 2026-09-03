//! Integration tests that exercise the built `qeminga` binary end to end.
//!
//! Cargo exposes the path to the compiled binary through the
//! `CARGO_BIN_EXE_<name>` environment variable at compile time.
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::process::{Command, Output, Stdio};

/// Exit status for usage errors (`EX_USAGE` from sysexits).
const EX_USAGE: i32 = 64;
/// Exit status for an I/O error while writing output (`EX_IOERR` from sysexits).
const EX_IOERR: i32 = 74;

fn qeminga() -> Command {
    Command::new(env!("CARGO_BIN_EXE_qeminga"))
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn version_flag_prints_crate_version() {
    let output = qeminga()
        .arg("--version")
        .output()
        .expect("failed to run qeminga");
    assert!(output.status.success(), "status: {:?}", output.status);
    assert_eq!(
        stdout_of(&output).trim_end(),
        format!("qeminga {}", qeminga::VERSION)
    );
}

#[test]
fn short_version_alias_matches_long_flag() {
    let long = qeminga()
        .arg("--version")
        .output()
        .expect("failed to run qeminga");
    let short = qeminga().arg("-V").output().expect("failed to run qeminga");
    assert!(short.status.success(), "status: {:?}", short.status);
    assert_eq!(short.stdout, long.stdout);
}

#[test]
fn no_arguments_is_a_usage_error_until_daemon_mode_exists() {
    let output = qeminga().output().expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_USAGE), "expected EX_USAGE");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("not implemented"), "stderr was: {stderr}");
}

#[test]
fn unknown_argument_is_a_usage_error() {
    let output = qeminga()
        .arg("--bogus")
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_USAGE), "expected EX_USAGE");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}

#[test]
fn non_utf8_argument_is_a_usage_error_not_a_panic() {
    let output = qeminga()
        .arg(OsStr::from_bytes(b"--\xff"))
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_USAGE), "expected EX_USAGE");
    let stderr = stderr_of(&output);
    assert!(!stderr.contains("panicked"), "stderr was: {stderr}");
    assert!(stderr.contains("usage:"), "stderr was: {stderr}");
}

#[test]
fn version_write_failure_is_an_io_error_not_a_panic() {
    // /dev/full accepts the open and fails every write with ENOSPC.
    let full = File::create("/dev/full").expect("/dev/full is required on Linux");
    let output = qeminga()
        .arg("--version")
        .stdout(Stdio::from(full))
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_IOERR), "expected EX_IOERR");
    let stderr = stderr_of(&output);
    assert!(!stderr.contains("panicked"), "stderr was: {stderr}");
}

#[test]
fn version_to_a_closed_pipe_is_not_an_error() {
    // Closing the reading end before the child starts makes every write
    // fail with EPIPE deterministically; a CLI treats that as success.
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);
    let output = qeminga()
        .arg("--version")
        .stdout(Stdio::from(writer))
        .output()
        .expect("failed to run qeminga");
    assert!(output.status.success(), "status: {:?}", output.status);
    let stderr = stderr_of(&output);
    assert!(!stderr.contains("panicked"), "stderr was: {stderr}");
}
