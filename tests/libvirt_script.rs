//! `scripts/e2e-libvirt.sh` (T5.4, AC16) against a scripted `virsh`: the
//! shell logic must reach PASS when every libvirt step behaves, and FAIL
//! when the guest accepts `guest-exec`.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::Command;

/// A `virsh` stand-in: one state file records frozen/thawed/shutoff. With
/// `EXEC_ACCEPTED=1` it accepts `guest-exec`, which the script must reject.
const FAKE_VIRSH: &str = r#"#!/bin/sh
state="${FAKE_STATE:?}"
[ -f "$state" ] || echo thawed > "$state"
cmd=$1; shift
case "$cmd" in
    version) echo "Compiled against library: libvirt 10.0.0"; exit 0 ;;
    help)
        # Only the commands real virsh has (`virsh help domshutdown` fails
        # on the real CLI, and so does this stand-in).
        case "$1" in
            domfsfreeze|domfsthaw|domifaddr|domfsinfo|domstate|qemu-agent-command|shutdown) echo "  NAME"; exit 0 ;;
            *) echo "error: command '$1' doesn't exist" >&2; exit 1 ;;
        esac ;;
    domfsfreeze) echo frozen > "$state"; echo "Froze ${FAKE_FREEZE_COUNT:-1} filesystem(s)"; exit 0 ;;
    domfsthaw) echo thawed > "$state"; echo "Thawed ${FAKE_FREEZE_COUNT:-1} filesystem(s)"; exit 0 ;;
    domifaddr) printf ' Name       MAC address          Protocol     Address\n lo         00:00:00:00:00:00    ipv4         127.0.0.1/8\n'; exit 0 ;;
    domfsinfo) printf 'Mountpoint   Name   Type   Target\n/            vda1   ext4   vda\n'; exit 0 ;;
    shutdown)
        [ "$2" = "--mode" ] && [ "$3" = "agent" ] || { echo "error: expected --mode agent" >&2; exit 1; }
        echo shutoff > "$state"; echo "Domain 'dom' is being shutdown"; exit 0 ;;
    domstate) if [ "$(cat "$state")" = shutoff ]; then echo "shut off"; else echo running; fi; exit 0 ;;
    qemu-agent-command)
        json=$2
        case "$json" in
            *guest-ping*) echo '{"return":{}}' ;;
            *guest-info*) echo '{"return":{"version":"0.1.0","supported_commands":[{"name":"guest-ping","enabled":true,"success-response":true},{"name":"guest-fsfreeze-freeze","enabled":true,"success-response":true}]}}' ;;
            *guest-exec*)
                if [ "${EXEC_ACCEPTED:-0}" = 1 ]; then echo '{"return":{"pid":1}}'; exit 0; fi
                echo "error: internal error: unable to execute QEMU agent command 'guest-exec': The command guest-exec has not been found" >&2
                exit 1 ;;
            *guest-fsfreeze-status*) printf '{"return":"%s"}\n' "$(cat "$state")" ;;
            *guest-fsfreeze-freeze-list*)
                if [ -n "${EXPECT_FREEZE_MOUNT:-}" ]; then
                    got="$(printf '%s\n' "$json" | jq -r '.arguments.mountpoints[0]')"
                    if [ "$got" != "$EXPECT_FREEZE_MOUNT" ]; then
                        echo "error: expected mount '$EXPECT_FREEZE_MOUNT', got '$got'" >&2
                        exit 1
                    fi
                fi
                if [ -n "${FAKE_FREEZE_LIST_RAW:-}" ]; then
                    echo frozen > "$state"
                    printf '%s\n' "$FAKE_FREEZE_LIST_RAW"
                else
                    n="${FAKE_FREEZE_LIST_COUNT:-1}"
                    if [ "$n" -gt 0 ]; then echo frozen > "$state"; fi
                    printf '{"return":%s}\n' "$n"
                fi ;;
            *guest-fsfreeze-thaw*)
                echo thawed > "$state"
                if [ -n "${FAKE_THAW_LIST_RAW:-}" ]; then
                    printf '%s\n' "$FAKE_THAW_LIST_RAW"
                else
                    printf '{"return":%s}\n' "${FAKE_THAW_LIST_COUNT:-1}"
                fi ;;
            *guest-get-osinfo*) echo '{"return":{"id":"debian","name":"Debian GNU/Linux"}}' ;;
            *) echo "error: unknown command" >&2; exit 1 ;;
        esac
        exit 0 ;;
    *) echo "fake virsh: unknown $cmd" >&2; exit 1 ;;
esac
"#;

fn run_script_raw(
    exec_accepted: bool,
    freeze_count: u32,
    freeze_mount: Option<&str>,
    freeze_list_count: u32,
    thaw_list_count: u32,
    freeze_list_raw: Option<&str>,
    thaw_list_raw: Option<&str>,
) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let virsh = bin.join("virsh");
    std::fs::write(&virsh, FAKE_VIRSH).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&virsh, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/e2e-libvirt.sh");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut cmd = Command::new("bash");
    cmd.arg(script);
    if let Some(mount) = freeze_mount {
        cmd.arg("--freeze-mount").arg(mount);
        cmd.env("EXPECT_FREEZE_MOUNT", mount);
    }
    if let Some(raw) = freeze_list_raw {
        cmd.env("FAKE_FREEZE_LIST_RAW", raw);
    }
    if let Some(raw) = thaw_list_raw {
        cmd.env("FAKE_THAW_LIST_RAW", raw);
    }
    let output = cmd
        .arg("dom")
        .env("PATH", path)
        .env("FAKE_STATE", dir.path().join("state"))
        .env("EXEC_ACCEPTED", if exec_accepted { "1" } else { "0" })
        .env("FAKE_FREEZE_COUNT", freeze_count.to_string())
        .env("FAKE_FREEZE_LIST_COUNT", freeze_list_count.to_string())
        .env("FAKE_THAW_LIST_COUNT", thaw_list_count.to_string())
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

fn run_script(
    exec_accepted: bool,
    freeze_count: u32,
    freeze_mount: Option<&str>,
    freeze_list_count: u32,
    thaw_list_count: u32,
) -> (bool, String) {
    run_script_raw(
        exec_accepted,
        freeze_count,
        freeze_mount,
        freeze_list_count,
        thaw_list_count,
        None,
        None,
    )
}

fn run_with(exec_accepted: bool, freeze_count: u32) -> (bool, String) {
    run_script(exec_accepted, freeze_count, None, 1, 1)
}

fn run(exec_accepted: bool) -> (bool, String) {
    run_with(exec_accepted, 1)
}

#[test]
fn script_passes_when_every_libvirt_step_behaves() {
    let (ok, text) = run(false);
    assert!(ok, "{text}");
    assert!(text.contains("RESULT: PASS (AC16)"), "{text}");
    assert!(!text.contains("FAILED"), "{text}");
    assert!(!text.contains("command not found"), "{text}");
    for step in [
        "-- ok: guest-ping",
        "-- ok: guest-exec is refused (AC1)",
        "-- ok: domfsfreeze",
        "-- ok: guest-fsfreeze-status is frozen",
        "-- ok: domfsthaw",
        "-- ok: guest-fsfreeze-status is thawed",
        "-- ok: domifaddr --source agent",
        "-- ok: shutdown --mode agent",
        "-- ok: domain stopped",
    ] {
        assert!(text.contains(step), "{step} missing in {text}");
    }
}

#[test]
fn script_fails_when_the_guest_accepts_guest_exec() {
    let (ok, text) = run(true);
    assert!(!ok, "{text}");
    assert!(
        text.contains("-- FAILED: guest-exec is refused (AC1)"),
        "{text}"
    );
    assert!(text.contains("RESULT: FAIL"), "{text}");
}

#[test]
fn script_fails_when_domfsfreeze_freezes_zero_filesystems() {
    // #66: a read-only remount or mount-namespace bug must never pass
    // vacuously by freezing zero guest filesystems.
    let (ok, text) = run_with(false, 0);
    assert!(!ok, "{text}");
    assert!(text.contains("-- FAILED: domfsfreeze"), "{text}");
    assert!(text.contains("RESULT: FAIL"), "{text}");
}

#[test]
fn script_exercises_freeze_mount_when_requested() {
    // #66: ProtectHome=read-only verification exercises freezing and thawing
    // a dedicated mount under /home by name (including paths with spaces and /).
    for mount in ["/home/qeminga-test-vol", "/home/with space", "/"] {
        let (ok, text) = run_script(false, 2, Some(mount), 1, 1);
        assert!(ok, "mount={mount}: {text}");
        assert!(text.contains("RESULT: PASS (AC16)"), "{text}");
        for step in [
            format!("-- ok: guest-fsfreeze-freeze-list ({mount})"),
            format!("-- ok: guest-fsfreeze-status is frozen ({mount})"),
            format!("-- ok: guest-fsfreeze-thaw ({mount})"),
            format!("-- ok: guest-fsfreeze-status is thawed ({mount})"),
        ] {
            assert!(text.contains(&step), "{step} missing in {text}");
        }
    }
}

#[test]
fn script_fails_when_freeze_mount_returns_zero() {
    let (ok, text) = run_script(false, 1, Some("/home/qeminga-test-vol"), 0, 0);
    assert!(!ok, "{text}");
    assert!(
        text.contains("-- FAILED: guest-fsfreeze-freeze-list (/home/qeminga-test-vol)"),
        "{text}"
    );
    assert!(text.contains("RESULT: FAIL"), "{text}");
}

#[test]
fn script_rejects_fractional_nested_and_malformed_freeze_list_counts() {
    let mount = "/home/qeminga-test-vol";
    for bad in [
        r#"{"return":1.5}"#,
        r#"{"return":1.0}"#,
        r#"{"return":"1"}"#,
        r#"{"return":{"return":1}}"#,
        r#"{"return":1"#,
    ] {
        let (ok, text) = run_script_raw(false, 2, Some(mount), 1, 1, Some(bad), None);
        assert!(!ok, "freeze-list accepted malformed reply {bad}: {text}");
        assert!(
            text.contains("-- FAILED: guest-fsfreeze-freeze-list (/home/qeminga-test-vol)"),
            "bad={bad}: {text}"
        );
        let (ok, text) = run_script_raw(false, 2, Some(mount), 1, 1, None, Some(bad));
        assert!(!ok, "thaw accepted malformed reply {bad}: {text}");
        assert!(
            text.contains("-- FAILED: guest-fsfreeze-thaw (/home/qeminga-test-vol)"),
            "bad={bad}: {text}"
        );
    }
}
