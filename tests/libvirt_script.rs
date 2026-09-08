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
    domfsfreeze) echo frozen > "$state"; echo "Froze 1 filesystem(s)"; exit 0 ;;
    domfsthaw) echo thawed > "$state"; echo "Thawed 1 filesystem(s)"; exit 0 ;;
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
            *guest-get-osinfo*) echo '{"return":{"id":"debian","name":"Debian GNU/Linux"}}' ;;
            *) echo "error: unknown command" >&2; exit 1 ;;
        esac
        exit 0 ;;
    *) echo "fake virsh: unknown $cmd" >&2; exit 1 ;;
esac
"#;

fn run(exec_accepted: bool) -> (bool, String) {
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
    let output = Command::new("bash")
        .arg(script)
        .arg("dom")
        .env("PATH", path)
        .env("FAKE_STATE", dir.path().join("state"))
        .env("EXEC_ACCEPTED", if exec_accepted { "1" } else { "0" })
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
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
