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

/// Exit status for a configuration problem (`EX_CONFIG` from sysexits).
const EX_CONFIG: i32 = 78;

#[test]
fn cli_accepts_config_path_and_version() {
    // `--config PATH` is honoured: a missing file is a configuration error
    // that names the path, before anything else is attempted.
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.toml");
    let output = qeminga()
        .arg("--config")
        .arg(&missing)
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_CONFIG), "expected EX_CONFIG");
    let stderr = stderr_of(&output);
    assert!(stderr.contains("missing.toml"), "stderr was: {stderr}");
    // `--config=PATH` too.
    let output = qeminga()
        .arg(format!("--config={}", missing.display()))
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_CONFIG));
    // An invalid file names the offending key.
    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "[agent]\nfsfreeze_idle_timeout_secs = 0\n").expect("write");
    let output = qeminga()
        .arg("--config")
        .arg(&bad)
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_CONFIG));
    assert!(stderr_of(&output).contains("fsfreeze_idle_timeout_secs"));
    // `--config` without a value is a usage error.
    let output = qeminga()
        .arg("--config")
        .output()
        .expect("failed to run qeminga");
    assert_eq!(output.status.code(), Some(EX_USAGE));
    assert!(stderr_of(&output).contains("usage:"));
    // `--version` wins over everything else.
    let output = qeminga()
        .args(["--config", "/nonexistent.toml", "--version"])
        .output()
        .expect("failed to run qeminga");
    assert!(output.status.success());
    assert!(stdout_of(&output).starts_with("qeminga "));
}

#[test]
fn no_arguments_uses_the_default_config_path() {
    // The default /etc/qeminga/config.toml is absent on a build host, so
    // the daemon exits with EX_CONFIG naming it (and never touches a
    // device). On a host that has the file (the package installed) the
    // daemon would open the real channel or retry it for ever, so the
    // test is skipped before spawning anything, and the spawn is bounded.
    if std::path::Path::new("/etc/qeminga/config.toml").exists() {
        eprintln!("skipped: /etc/qeminga/config.toml exists");
        return;
    }
    let mut child = qeminga()
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run qeminga");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("qeminga did not exit within 10 s without a configuration");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut stderr = String::new();
    std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert_eq!(status.code(), Some(EX_CONFIG), "stderr was: {stderr}");
    assert!(
        stderr.contains("/etc/qeminga/config.toml"),
        "stderr was: {stderr}"
    );
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
