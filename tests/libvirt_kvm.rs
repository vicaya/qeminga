//! The libvirt + QEMU KVM smoke lanes (#53, AC16):
//!
//! - `.github/workflows/libvirt-kvm-hosted.yml`: builds the production release
//!   candidate on GitHub-hosted `ubuntu-24.04` (`x86_64`), enables `/dev/kvm`
//!   for the unprivileged `runner` user via the `99-kvm4all.rules` udev
//!   workaround (`OPTIONS+="static_node=kvm"`), and exercises the candidate
//!   under real libvirt + KVM (`qemu:///session`, no `sudo` during the run) on
//!   `push` (`main`), `pull_request`, and `workflow_dispatch`.
//! - `.github/workflows/libvirt-kvm.yml` + `libvirt-kvm-lane.yml`:
//!   `workflow_dispatch`-only lane that builds on GitHub-hosted runners and
//!   exercises the exact candidate on self-hosted `x86_64` and `aarch64` KVM
//!   runners without root, `sudo`, or a Rust toolchain.
//!
//! Mirrors `tests/libvirt_tcg_smoke.rs` for the KVM lanes: candidate manifest
//! and fail-closed verification, image-pin parity with the TCG script, KVM
//! domain XML (`type='kvm'`, `host-passthrough`, aarch64 UEFI + `gic host`,
//! unprivileged `user` networking under `qemu:///session`), URI validation,
//! missing/non-char `/dev/kvm` fail-closed preflight, stale-domain and cleanup
//! namespace guards, the `libvirt-kvm-smoke-v1` result contract (refusing TCG
//! as a pass), and workflow security/shape invariants for both the self-hosted
//! and GitHub-hosted workflows.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn script() -> PathBuf {
    root().join("scripts/ci/libvirt-kvm-smoke.sh")
}

fn sysfs_module() -> PathBuf {
    root().join("scripts/ci/libvirt_kvm_sysfs.py")
}

fn tcg_script() -> PathBuf {
    root().join("scripts/ci/libvirt-tcg-smoke.sh")
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn lane(args: &[&str]) -> Output {
    lane_env(args, &[], None)
}

fn lane_env(args: &[&str], env: &[(&str, &str)], bin: Option<&Path>) -> Output {
    let mut cmd = Command::new("bash");
    cmd.arg(script()).args(args);
    if let Some(bin) = bin {
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn require_jq() {
    let found = Command::new("jq")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        found,
        "jq is required by scripts/ci/libvirt-kvm-smoke.sh and these tests"
    );
}

fn private_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

fn create_private_dir(path: &Path) {
    create_dir_mode(path, 0o700);
}

/// Returns true when `target` is mapped in the current user namespace's
/// `/proc/self/uid_map` (always true on normal hosts, GitHub runners, and
/// multi-UID containers; false for arbitrary test UIDs inside a single-UID
/// `unshare -U --map-current-user` namespace where kernel `setxattr` rejects
/// unmapped ACL UIDs with `EINVAL`).
fn uid_is_mapped(target: u32) -> bool {
    let Ok(map) = std::fs::read_to_string("/proc/self/uid_map") else {
        return true;
    };
    for line in map.lines() {
        let mut parts = line.split_whitespace();
        if let (Some(inside), Some(_outside), Some(len)) =
            (parts.next(), parts.next(), parts.next())
            && let (Ok(start), Ok(count)) = (inside.parse::<u64>(), len.parse::<u64>())
            && u64::from(target) >= start
            && u64::from(target) < start.saturating_add(count)
        {
            return true;
        }
    }
    false
}

fn write_exec(path: &Path, body: &str) {
    write_file_mode(path, 0o700, body.as_bytes());
}

fn sha256_hex(path: &Path) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn common_script() -> PathBuf {
    root().join("scripts/ci/libvirt-smoke-common.sh")
}

// ---- candidate manifest & shared image-pin helper -------------------------

#[test]
fn kvm_and_tcg_scripts_share_common_candidate_and_image_helper() {
    let common = std::fs::read_to_string(common_script())
        .unwrap_or_else(|e| panic!("missing scripts/ci/libvirt-smoke-common.sh: {e}"));
    let kvm = std::fs::read_to_string(script()).unwrap();
    let tcg = std::fs::read_to_string(tcg_script()).unwrap();

    // Shared pins and candidate/image-fetch logic live in one file.
    for required in [
        "SOURCE_REPOSITORY=\"vicaya/qeminga\"",
        "BUILD_COMMAND=\"cargo build --release --locked --features seccomp\"",
        "PACKAGING_FILES=\"",
        "IMAGE_RELEASE=\"",
        "IMAGE_SHA256_x86_64=\"",
        "IMAGE_SHA256_aarch64=\"",
        "cmd_manifest()",
        "cmd_verify_candidate()",
        "cmd_image_key()",
        "cmd_fetch_image()",
    ] {
        assert!(
            common.contains(required),
            "common helper must define {required:?}"
        );
    }

    for (label, body) in [("kvm", &kvm), ("tcg", &tcg)] {
        assert!(
            body.contains("source \"$HERE/libvirt-smoke-common.sh\""),
            "{label} script must source libvirt-smoke-common.sh"
        );
        for duplicated in [
            "IMAGE_RELEASE=\"",
            "IMAGE_SHA256_x86_64=\"",
            "IMAGE_SHA256_aarch64=\"",
            "PACKAGING_FILES=\"",
            "BUILD_COMMAND=\"",
            "cmd_manifest()",
            "cmd_verify_candidate()",
            "cmd_fetch_image()",
        ] {
            assert!(
                !body.contains(duplicated),
                "{label} script must not duplicate {duplicated:?} (keep in libvirt-smoke-common.sh)"
            );
        }
    }
}

#[test]
fn kvm_manifest_and_candidate_verification_fail_closed() {
    require_jq();
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let out = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        out.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        "aarch64",
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "99",
        "--run-attempt",
        "1",
        "--runner",
        "ubuntu-24.04-arm",
    ]);
    assert!(m.status.success(), "{}", text(&m));

    let verified = lane(&["verify-candidate", out.to_str().unwrap(), "aarch64", SHA]);
    assert!(verified.status.success(), "{}", text(&verified));
    assert_eq!(
        String::from_utf8_lossy(&verified.stdout).trim(),
        sha256_hex(&out.join("qeminga"))
    );

    // Wrong arch, wrong SHA, and tampered binary fail closed.
    assert!(
        !lane(&["verify-candidate", out.to_str().unwrap(), "x86_64", SHA])
            .status
            .success()
    );
    assert!(
        !lane(&[
            "verify-candidate",
            out.to_str().unwrap(),
            "aarch64",
            &SHA.replace('0', "f")
        ])
        .status
        .success()
    );
    std::fs::write(out.join("qeminga"), b"tampered").unwrap();
    assert!(
        !lane(&["verify-candidate", out.to_str().unwrap(), "aarch64", SHA])
            .status
            .success()
    );
}

// ---- KVM domain XML -------------------------------------------------------

fn domain_xml(arch: &str, env: &[(&str, &str)]) -> Output {
    lane_env(
        &[
            "domain-xml",
            "--arch",
            arch,
            "--name",
            "qeminga-e2e-42-1-x",
            "--dir",
            "/var/lib/qeminga-runner/images/qeminga-e2e-42-1-x",
        ],
        env,
        None,
    )
}

#[test]
fn kvm_domain_xml_uses_kvm_and_host_passthrough_on_both_architectures() {
    for (arch, machine) in [("x86_64", "q35"), ("aarch64", "virt")] {
        let out = domain_xml(arch, &[]);
        assert!(out.status.success(), "{arch}: {}", text(&out));
        let xml = String::from_utf8(out.stdout).unwrap();
        assert!(xml.contains("<domain type='kvm'>"), "{arch}: {xml}");
        assert!(!xml.contains("<domain type='qemu'>"), "{arch}: {xml}");
        assert!(
            xml.contains(&format!(
                "<type arch='{arch}' machine='{machine}'>hvm</type>"
            )),
            "{arch}: {xml}"
        );
        assert!(
            xml.contains("<cpu mode='host-passthrough' check='none'/>"),
            "{arch}: {xml}"
        );
        assert!(
            xml.contains("<target type='virtio' name='org.qemu.guest_agent.0'/>"),
            "{arch}: {xml}"
        );
        // Unprivileged qemu:///session default uses user-mode networking, not a root bridge.
        assert!(xml.contains("<interface type='user'>"), "{arch}: {xml}");
        assert!(!xml.contains("source network='default'"), "{arch}: {xml}");
        assert!(xml.contains("<rom enabled='no'/>"), "{arch}: {xml}");

        if arch == "x86_64" {
            assert!(xml.contains("<apic/>"), "{arch}: {xml}");
        } else {
            assert!(
                xml.contains("<gic version='host'/>"),
                "aarch64 KVM must match host GIC version: {xml}"
            );
            assert!(
                xml.contains("<loader readonly='yes' type='pflash'>"),
                "aarch64 KVM boots UEFI: {xml}"
            );
            assert!(xml.contains("<nvram template='"), "{xml}");
        }
    }

    // qemu:///system mode uses the default libvirt network bridge.
    let sys = domain_xml("x86_64", &[("QEMINGA_E2E_CONNECT", "qemu:///system")]);
    assert!(sys.status.success(), "{}", text(&sys));
    let xml = String::from_utf8(sys.stdout).unwrap();
    assert!(xml.contains("<interface type='network'>"), "{xml}");
    assert!(xml.contains("<source network='default'/>"), "{xml}");
}

#[test]
fn refuses_unknown_libvirt_connect_uris_and_missing_expect_sha256() {
    for bad_uri in [
        "qemu+ssh://root@evil.example/system",
        "qemu+tcp://127.0.0.1/system",
        "lxc:///",
        "qemu:///session;id",
    ] {
        let out = domain_xml("x86_64", &[("QEMINGA_E2E_CONNECT", bad_uri)]);
        assert!(!out.status.success(), "{bad_uri}: {}", text(&out));
    }

    // Missing or malformed --expect-sha256 is refused before preflight.
    for expect in [None, Some(""), Some("not-a-digest")] {
        let mut args = vec![
            "run",
            "--arch",
            "aarch64",
            "--candidate",
            "/nonexistent/candidate",
            "--source-sha",
            SHA,
            "--run-id",
            "42",
            "--run-attempt",
            "1",
            "--out",
            "/nonexistent/out",
        ];
        if let Some(e) = expect {
            args.extend(["--expect-sha256", e]);
        }
        let out = lane(&args);
        assert!(!out.status.success(), "{expect:?}: {}", text(&out));
        assert!(text(&out).contains("--expect-sha256"), "{}", text(&out));
        assert!(!text(&out).contains("preflight"), "{}", text(&out));
    }
}

// ---- stale domains & conservative cleanup ---------------------------------

const FAKE_VIRSH: &str = r#"#!/bin/sh
echo "$*" >> "${FAKE_LOG:?}"
case "$1" in --connect=*) shift ;; esac
case "$1" in
    list)
        [ "${FAKE_LIST_FAILS:-0}" = 1 ] && { echo "error: failed to connect" >&2; exit 1; }
        printf '%s\n' ${FAKE_LIST:-} ""; exit 0 ;;
    domstate)
        [ "${FAKE_STATE_FAILS:-0}" = 1 ] && { echo "error: internal error" >&2; exit 1; }
        if [ -n "${FAKE_LIST:-}" ]; then echo "${FAKE_DOMSTATE:-running}"; exit 0; fi
        echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    *) exit 0 ;;
esac
"#;

#[test]
fn stale_check_and_cleanup_protect_unrelated_domains_and_unknown_state() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    create_dir_mode(&bin, 0o700);
    write_exec(&bin.join("virsh"), FAKE_VIRSH);
    let log = dir.path().join("virsh.log");
    let images = dir.path().join("images");
    let mine = images.join("qeminga-e2e-42-1-aarch64");
    let other = images.join("qeminga-e2e-43-1-aarch64");
    std::fs::create_dir_all(&mine).unwrap();
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(mine.join("root.qcow2"), b"x").unwrap();
    std::fs::write(other.join("root.qcow2"), b"y").unwrap();

    // Clean stale-check uses qemu:///session by default.
    let clean = lane_env(
        &["stale-check"],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("FAKE_LIST", "other-vm"),
        ],
        Some(&bin),
    );
    assert!(clean.status.success(), "{}", text(&clean));
    assert!(
        std::fs::read_to_string(&log)
            .unwrap()
            .contains("--connect=qemu:///session")
    );

    // Stale qeminga domain stops the lane.
    let stale = lane_env(
        &["stale-check"],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("FAKE_LIST", "qeminga-e2e-42-1-aarch64"),
        ],
        Some(&bin),
    );
    assert!(!stale.status.success());

    // Unknown libvirt state keeps the disks.
    let unknown = lane_env(
        &[
            "cleanup",
            "--arch",
            "aarch64",
            "--run-id",
            "42",
            "--run-attempt",
            "1",
        ],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
            ("FAKE_LIST", "qeminga-e2e-42-1-aarch64"),
            ("FAKE_STATE_FAILS", "1"),
        ],
        Some(&bin),
    );
    assert!(!unknown.status.success());
    assert!(mine.join("root.qcow2").exists());

    // Absent domain removes only the current run's directory.
    let done = lane_env(
        &[
            "cleanup",
            "--arch",
            "aarch64",
            "--run-id",
            "42",
            "--run-attempt",
            "1",
        ],
        &[
            ("FAKE_LOG", log.to_str().unwrap()),
            ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(done.status.success(), "{}", text(&done));
    assert!(!mine.exists());
    assert!(other.join("root.qcow2").exists());
}

#[test]
fn kvm_run_directory_permissions_match_libvirt_connection_mode() {
    require_jq();
    let arch = std::env::consts::ARCH;
    assert!(
        arch == "x86_64" || arch == "aarch64",
        "unexpected test arch {arch}"
    );

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    create_private_dir(&bin);
    // Grant traversal on the fixture root for simulated QEMU checks while keeping `bin` 0700.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    // Build a valid candidate bundle matching the host arch.
    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let candidate = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        candidate.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "77",
        "--run-attempt",
        "1",
        "--runner",
        "test-runner",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    let digest = sha256_hex(&candidate.join("qeminga"));

    // Resolve the pinned image SHA for this arch from the common helper so our
    // mock curl / cache-hit fixtures exercise the real `fetch_image` path.
    let img_key = lane(&["image-key", arch]);
    assert!(img_key.status.success(), "{}", text(&img_key));
    let pinned_image_sha = String::from_utf8(img_key.stdout)
        .unwrap()
        .trim()
        .rsplit('-')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(pinned_image_sha.len(), 64);

    // Current primary group number so real `chgrp` succeeds unprivileged while
    // `qemu_acct_num` is strictly distinct from the current caller account.
    let caller_grp_num = String::from_utf8(
        Command::new("/usr/bin/id")
            .arg("-g")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let qemu_acct_num = "64055";
    let qemu_user_spec = format!("+{qemu_acct_num}");
    let qemu_group_spec = format!("+{caller_grp_num}");

    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
case "$1" in --connect=*) shift ;; esac
case "$1" in
    version) echo "Compiled against library: libvirt 10.0.0"; exit 0 ;;
    capabilities) if [ -n "${FAKE_VIRSH_CAPABILITIES:-}" ]; then printf '%s\n' "$FAKE_VIRSH_CAPABILITIES"; fi; exit 0 ;;
    domcapabilities) echo "<domainCapabilities/>"; exit 0 ;;
    net-info) echo "Active:         yes"; exit 0 ;;
    list) echo ""; exit 0 ;;
    define) exit 0 ;;
    start) exit 42 ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(&bin.join("qemu-img"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("genisoimage"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -output) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] && : > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join(format!("qemu-system-{arch}")),
        "#!/bin/sh\necho 'QEMU emulator version 8.2.2'\n",
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
if [ -n "${FAKE_CURL_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_CURL_LOG"; fi
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf 'fake qcow2 bytes\n' > "$out"
if [ "${FAKE_CURL_OPEN_MODE:-0}" = "1" ]; then
    chmod 0644 "$out"
fi
exit 0
"#,
    );
    write_exec(
        &bin.join("sha256sum"),
        r#"#!/bin/sh
case "$1" in
    *.qcow2.part | */img-cache/*) printf '%s  %s\n' "${FAKE_IMAGE_SHA:?}" "$1"; exit 0 ;;
esac
exec /usr/bin/sha256sum "$@"
"#,
    );
    write_exec(
        &bin.join("chown"),
        r#"#!/bin/sh
if [ -n "${FAKE_CHOWN_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_CHOWN_LOG"; fi
exit 0
"#,
    );
    write_exec(
        &bin.join("df"),
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/mock 99999999 0 99999999 0%% /\\n'\n",
    );
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo "${FAKE_ID_U:?}"; exit 0; fi
exec /usr/bin/id "$@"
"#,
    );
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let acls_can_name_test_uids = uid_is_mapped(64055) && uid_is_mapped(64099);

    // Helper: run `libvirt-kvm-smoke.sh` under an explicit umask (e.g., 0077 or 0022).
    // Simulated unprivileged `qemu:///system` runs anchor their trust walk at the
    // fixture-owned `dir.path()` descriptor so the ordinary test suite stays portable
    // inside unprivileged user namespaces where host `/` reports overflow UID 65534;
    // the full host-root `/` walk is exercised as real root in
    // `privileged_kvm_system_lane_kernel_verdicts`.
    let run_with_umask = |mask: &str, args: &[&str], env: &[(&str, &str)]| -> Output {
        let mut cmd = Command::new("bash");
        cmd.args(["-c", r#"umask "$1"; shift; exec bash "$@""#, "_"]);
        cmd.arg(mask).arg(script()).args(args);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
        if env
            .iter()
            .any(|(k, v)| *k == "QEMINGA_E2E_CONNECT" && *v == "qemu:///system")
        {
            cmd.env("QEMINGA_TEST_SYSFS_ROOT", dir.path());
            if !acls_can_name_test_uids
                && !env.iter().any(|(k, _)| *k == "QEMINGA_TEST_DISABLE_ACL")
            {
                cmd.env("QEMINGA_TEST_DISABLE_ACL", "1");
            }
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    // Helper: evaluate effective Linux directory traversal (standard POSIX mode + POSIX ACL
    // xattr `system.posix_acl_access`) for a given numeric account/group along every component
    // from `stop_ancestor` down to `leaf_dir`.
    let check_effective_traversal =
        |stop_ancestor: &Path, leaf_dir: &Path, acct: &str, grp: &str| -> bool {
            let out = Command::new("python3")
                .args([
                    "-I",
                    "-c",
                    r#"
import errno, os, stat, struct, sys

stop = os.path.normpath(sys.argv[1])
leaf = os.path.normpath(sys.argv[2])
target_u = int(sys.argv[3])
target_g = int(sys.argv[4])

def can_traverse(p):
    st = os.stat(p)
    if not stat.S_ISDIR(st.st_mode):
        return False
    if target_u == 0:
        return True
    try:
        raw = os.getxattr(p, b"system.posix_acl_access")
    except OSError:
        raw = None
    if raw and len(raw) >= 4:
        ver, = struct.unpack_from("<I", raw, 0)
        if ver == 2:
            mask = 0o7
            entries = []
            for off in range(4, len(raw), 8):
                if off + 8 <= len(raw):
                    tag, perm, eid = struct.unpack_from("<HHI", raw, off)
                    entries.append((tag, perm, eid))
                    if tag == 0x10:
                        mask = perm
            if target_u == st.st_uid:
                for tag, perm, _ in entries:
                    if tag == 0x01:
                        return bool(perm & 1)
            for tag, perm, eid in entries:
                if tag == 0x02 and eid == target_u:
                    return bool((perm & mask) & 1)
            matched_grp = False
            for tag, perm, eid in entries:
                if (tag == 0x04 and st.st_gid == target_g) or (tag == 0x08 and eid == target_g):
                    matched_grp = True
                    if (perm & mask) & 1:
                        return True
            if matched_grp:
                return False
            for tag, perm, _ in entries:
                if tag == 0x20:
                    return bool(perm & 1)
            return False
    if target_u == st.st_uid:
        return bool(st.st_mode & 0o100)
    if target_g == st.st_gid:
        return bool(st.st_mode & 0o010)
    return bool(st.st_mode & 0o001)

cur = leaf
chain = []
while True:
    chain.append(cur)
    if cur == stop or cur == "/":
        break
    cur = os.path.dirname(cur)
for p in reversed(chain):
    if not can_traverse(p):
        sys.stderr.write(f"blocked at {p} mode={oct(os.stat(p).st_mode & 0o777)}\n")
        sys.exit(1)
"#,
                    stop_ancestor.to_str().unwrap(),
                    leaf_dir.to_str().unwrap(),
                    acct,
                    grp,
                ])
                .output()
                .unwrap();
            out.status.success()
        };

    // 1. qemu:///session (under umask 0022): run dir stays 0700 and root.qcow2 is private 0600.
    {
        let images = dir.path().join("session-images");
        let out_dir = dir.path().join("out-session");
        let run_out = run_with_umask(
            "0022",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "77",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///session"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "1000"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_OPEN_MODE", "1"),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-77-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        assert_eq!(
            std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "session mode run dir must remain 0700"
        );
        assert_eq!(
            std::fs::metadata(&disk).unwrap().permissions().mode() & 0o777,
            0o600,
            "session mode root.qcow2 must be private 0600"
        );
    }

    // 2. qemu:///system download path under restrictive umask 0077 with a NEW nested
    //    QEMINGA_E2E_IMAGES root:
    //    - Both new image root components AND run dir must grant effective traversal to QEMU
    //      without exposing world access (`mode & 0o007 == 0`).
    //    - Even if curl produces a 0644 file, `root.qcow2` MUST be private 0600 and chowned
    //      to the configured QEMU identity before boot.
    {
        let images = dir.path().join("sys-new-parent/nested-images");
        let out_dir = dir.path().join("out-sys-dl");
        let chown_log = dir.path().join("chown-dl.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "78",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_OPEN_MODE", "1"),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-78-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        assert!(
            check_effective_traversal(dir.path(), &run_dir, qemu_acct_num, &caller_grp_num),
            "QEMU identity must have effective traversal across newly created image root and run dir under umask 0077: {}",
            text(&run_out)
        );
        let run_dir_mode = std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            run_dir_mode & 0o007,
            0,
            "system mode run dir must not grant world access (got {run_dir_mode:#o})"
        );
        let disk_mode = std::fs::metadata(&disk).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            disk_mode, 0o600,
            "system mode downloaded root.qcow2 must be private 0600, got {disk_mode:#o}"
        );
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && chowns.contains(disk.to_str().unwrap()),
            "system mode root.qcow2 must be chowned to configured QEMU identity before boot:\n{chowns}"
        );
    }

    // 3. qemu:///system cache-hit path under umask 0022 with a world-readable `0644` cache file:
    //    copied `root.qcow2` MUST STILL end up private `0600` owned by QEMU (never `0644`)!
    {
        let cache_dir = dir.path().join("img-cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let cached = cache_dir.join(&pinned_image_sha);
        std::fs::write(&cached, b"cached qcow2 image\n").unwrap();
        std::fs::set_permissions(&cached, std::fs::Permissions::from_mode(0o644)).unwrap();

        let images = dir.path().join("sys-cache-images");
        let out_dir = dir.path().join("out-sys-cache");
        let chown_log = dir.path().join("chown-cache.log");
        let run_out = run_with_umask(
            "0022",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "79",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
                "--image-cache",
                cache_dir.to_str().unwrap(),
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-79-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        let disk_mode = std::fs::metadata(&disk).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            disk_mode, 0o600,
            "system mode cache-hit root.qcow2 copied from 0644 cache must be private 0600, got {disk_mode:#o}"
        );
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && chowns.contains(disk.to_str().unwrap()),
            "system mode cache-hit root.qcow2 must be chowned to configured QEMU identity:\n{chowns}"
        );
    }

    // 4. qemu:///system with an EXISTING untraversable ancestor (`0700`):
    //    `preflight` MUST report the blocking ancestor path, fail BEFORE downloading the image,
    //    and leave the ancestor's `0700` permissions untouched!
    {
        let blocked_ancestor = dir.path().join("blocked-0700-ancestor");
        std::fs::create_dir(&blocked_ancestor).unwrap();
        std::fs::set_permissions(&blocked_ancestor, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let images = blocked_ancestor.join("images");
        let out_dir = dir.path().join("out-sys-blocked");
        let curl_log = dir.path().join("curl-blocked.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "80",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_LOG", curl_log.to_str().unwrap()),
            ],
        );
        let msg = text(&run_out);
        assert!(
            !run_out.status.success(),
            "system mode run with untraversable ancestor must fail closed: {msg}"
        );
        assert!(
            msg.contains(blocked_ancestor.to_str().unwrap()),
            "error must report the blocking ancestor path ({}):\n{msg}",
            blocked_ancestor.display()
        );
        assert!(
            !curl_log.exists() && !images.exists(),
            "must fail in preflight before creating images dir or downloading image:\n{msg}"
        );
        assert_eq!(
            std::fs::metadata(&blocked_ancestor)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "existing blocking ancestor permissions must remain untouched (0700)"
        );
    }

    // 5. qemu:///system identity resolution from `/etc/libvirt/qemu.conf` (via
    //    `QEMINGA_LIBVIRT_QEMU_CONF`, without `QEMINGA_E2E_QEMU_USER/GROUP` overrides):
    //    must parse active `user = ...` / `group = ...` entries (ignoring comments) and
    //    apply them to both traversal provisioning and private disk ownership.
    {
        let qemu_conf = dir.path().join("qemu.conf");
        std::fs::write(
            &qemu_conf,
            format!(
                "# user = \"nobody\"\nuser = \"{qemu_user_spec}\" # active user\ngroup = \"{qemu_group_spec}\"\n"
            ),
        )
        .unwrap();
        let images = dir.path().join("sys-conf-images");
        let out_dir = dir.path().join("out-sys-conf");
        let chown_log = dir.path().join("chown-conf.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "81",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_LIBVIRT_QEMU_CONF", qemu_conf.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let run_dir = images.join(format!("qeminga-e2e-81-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));
        assert!(
            check_effective_traversal(dir.path(), &run_dir, qemu_acct_num, &caller_grp_num),
            "qemu.conf identity must have effective traversal across image root and run dir"
        );
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && chowns.contains(disk.to_str().unwrap()),
            "qemu.conf identity must be applied to root.qcow2 ownership:\n{chowns}"
        );
    }

    // Helper: evaluate effective 3-bit Linux permissions (r=4, w=2, x=1) for (acct, grp) on a
    // single path using standard POSIX mode + `system.posix_acl_access`.
    let effective_rights = |target: &Path, acct: &str, grp: &str| -> u8 {
        let out = Command::new("python3")
            .args([
                "-I",
                "-c",
                r#"
import os, struct, sys
p = sys.argv[1]
u = int(sys.argv[2])
g = int(sys.argv[3])
st = os.stat(p)
try:
    raw = os.getxattr(p, b"system.posix_acl_access")
except OSError:
    raw = None
if raw and len(raw) >= 4:
    ver, = struct.unpack_from("<I", raw, 0)
    if ver == 2:
        mask = 7
        entries = []
        for off in range(4, len(raw), 8):
            if off + 8 <= len(raw):
                tag, perm, eid = struct.unpack_from("<HHI", raw, off)
                entries.append((tag, perm, eid))
                if tag == 0x10:
                    mask = perm
        if u == st.st_uid:
            for tag, perm, _ in entries:
                if tag == 0x01:
                    print(perm); sys.exit(0)
        for tag, perm, eid in entries:
            if tag == 0x02 and eid == u:
                print(perm & mask); sys.exit(0)
        matched = [perm & mask for tag, perm, eid in entries if (tag == 0x04 and st.st_gid == g) or (tag == 0x08 and eid == g)]
        if matched:
            val = 0
            for m in matched:
                val |= m
            print(val); sys.exit(0)
        for tag, perm, _ in entries:
            if tag == 0x20:
                print(perm); sys.exit(0)
        print(0); sys.exit(0)
if u == st.st_uid:
    print((st.st_mode >> 6) & 7)
elif g == st.st_gid:
    print((st.st_mode >> 3) & 7)
else:
    print(st.st_mode & 7)
"#,
                target.to_str().unwrap(),
                acct,
                grp,
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", text(&out));
        String::from_utf8(out.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };

    // 6. Parent with a kernel default ACL granting `rwx` to an unrelated user (`64099`):
    //    Provisioning MUST replace inherited ACL entries completely, limit the mask to `--x`,
    //    and strip inherited `system.posix_acl_default` before creating children so unrelated
    //    accounts receive ZERO rights (`0`) on new image-root dirs, run dir, and `root.qcow2`
    //    while QEMU receives `--x` (`1`) traversal!
    if acls_can_name_test_uids {
        let other_acct_num = "64099";
        let other_grp_num = "64099";
        let acl_parent = dir.path().join("with-default-acl");
        std::fs::create_dir(&acl_parent).unwrap();
        std::fs::set_permissions(&acl_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let set_def = Command::new("python3")
            .args([
                "-I",
                "-c",
                r#"
import os, struct, sys
p = sys.argv[1]
other_u = int(sys.argv[2])
entries = [
    (0x01, 7, 0xFFFFFFFF),
    (0x02, 7, other_u),
    (0x04, 0, 0xFFFFFFFF),
    (0x10, 7, 0xFFFFFFFF),
    (0x20, 0, 0xFFFFFFFF),
]
raw = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, perm, eid) for t, perm, eid in entries)
os.setxattr(p, b"system.posix_acl_default", raw)
"#,
                acl_parent.to_str().unwrap(),
                other_acct_num,
            ])
            .output()
            .unwrap();
        assert!(
            set_def.status.success(),
            "test fixture requires POSIX ACL xattr support on tempdir: {}",
            text(&set_def)
        );

        let images = acl_parent.join("nested-acl/images");
        let out_dir = dir.path().join("out-sys-defacl");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "82",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let nested_dir = acl_parent.join("nested-acl");
        let run_dir = images.join(format!("qeminga-e2e-82-1-{arch}"));
        let disk = run_dir.join("root.qcow2");
        assert!(run_dir.is_dir() && disk.is_file(), "{}", text(&run_out));

        for d in [&nested_dir, &images, &run_dir] {
            assert_eq!(
                effective_rights(d, qemu_acct_num, &caller_grp_num),
                1,
                "QEMU must have search-only (--x = 1) on {}",
                d.display()
            );
            assert_eq!(
                effective_rights(d, other_acct_num, other_grp_num),
                0,
                "unrelated account must have ZERO effective rights (--- = 0) on {} even under parent default ACL",
                d.display()
            );
            let has_def = Command::new("python3")
                .args([
                    "-I",
                    "-c",
                    r#"
import os, sys
try:
    os.getxattr(sys.argv[1], b"system.posix_acl_default")
    sys.exit(1)
except OSError:
    sys.exit(0)
"#,
                    d.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                has_def.status.success(),
                "inherited default ACL must be stripped on {}",
                d.display()
            );
        }
        assert_eq!(
            effective_rights(&disk, other_acct_num, other_grp_num),
            0,
            "unrelated account must have ZERO effective rights on root.qcow2"
        );
    }

    // 7. Shared writable ancestors MUST be refused with a clear diagnostic BEFORE any
    //    privileged mutation (mkdir, curl, chmod, chown):
    //    - 7a: world-writable `0777` ancestor
    //    - 7b: group-writable `0775` (non-root group) ancestor
    //    - 7c: sticky world-writable `1777` parent of missing image root
    //    - 7d: access-ACL-writable (`u:64099:rwx`) ancestor (when test UIDs are mapped)
    {
        let shared_world = dir.path().join("shared-0777");
        let shared_group = dir.path().join("shared-0775");
        let shared_sticky = dir.path().join("shared-1777");
        let shared_acl = dir.path().join("shared-acl");
        let mut shared_cases: Vec<PathBuf> = Vec::new();
        for (p, mode) in [
            (&shared_world, 0o777),
            (&shared_group, 0o775),
            (&shared_sticky, 0o1777),
        ] {
            std::fs::create_dir(p).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
            shared_cases.push(p.clone());
        }
        if acls_can_name_test_uids {
            std::fs::create_dir(&shared_acl).unwrap();
            std::fs::set_permissions(&shared_acl, std::fs::Permissions::from_mode(0o755)).unwrap();
            let set_acc_acl = Command::new("python3")
                .args([
                    "-I",
                    "-c",
                    r#"
import os, struct, sys
p = sys.argv[1]
entries = [
    (0x01, 7, 0xFFFFFFFF),
    (0x02, 7, 64099),
    (0x04, 5, 0xFFFFFFFF),
    (0x10, 7, 0xFFFFFFFF),
    (0x20, 5, 0xFFFFFFFF),
]
raw = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, perm, eid) for t, perm, eid in entries)
os.setxattr(p, b"system.posix_acl_access", raw)
"#,
                    shared_acl.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(set_acc_acl.status.success(), "{}", text(&set_acc_acl));
            shared_cases.push(shared_acl);
        }

        for (idx, parent) in shared_cases.iter().enumerate() {
            let images = parent.join("images");
            let out_dir = dir.path().join(format!("out-sys-shared-{idx}"));
            let curl_log = dir.path().join(format!("curl-shared-{idx}.log"));
            let chown_log = dir.path().join(format!("chown-shared-{idx}.log"));
            let run_id = format!("{}", 83 + idx);
            let run_out = run_with_umask(
                "0077",
                &[
                    "run",
                    "--arch",
                    arch,
                    "--candidate",
                    candidate.to_str().unwrap(),
                    "--source-sha",
                    SHA,
                    "--run-id",
                    &run_id,
                    "--run-attempt",
                    "1",
                    "--out",
                    out_dir.to_str().unwrap(),
                    "--expect-sha256",
                    &digest,
                ],
                &[
                    ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                    ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                    ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                    ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                    ("QEMINGA_KVM_DEVICE", "/dev/null"),
                    ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                    ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                    ("FAKE_ID_U", "0"),
                    ("FAKE_IMAGE_SHA", &pinned_image_sha),
                    ("FAKE_CURL_LOG", curl_log.to_str().unwrap()),
                    ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
                ],
            );
            let msg = text(&run_out);
            assert!(
                !run_out.status.success(),
                "shared writable ancestor {} MUST be refused before any mutation: {msg}",
                parent.display()
            );
            assert!(
                msg.contains(parent.to_str().unwrap()),
                "shared writable ancestor error must name {}:\n{msg}",
                parent.display()
            );
            assert!(
                !images.exists() && !curl_log.exists() && !chown_log.exists(),
                "must refuse shared writable ancestor {} BEFORE mkdir/curl/chown:\n{msg}",
                parent.display()
            );
        }
    }

    // 8. Live daemon `dac` KVM base label from `virsh capabilities` AND unprefixed numeric
    //    `qemu.conf` entries with no NSS record:
    //    - 8a: `virsh capabilities` `dac` KVM baselabel wins over `qemu.conf` when overrides
    //          are not set.
    //    - 8b: Unprefixed decimal `user = "64055"` / `group = "64056"` in `qemu.conf` with no
    //          NSS entries is accepted per libvirt numeric-ID rules.
    {
        let qemu_conf = dir.path().join("qemu-caps-vs-conf.conf");
        std::fs::write(&qemu_conf, "user = \"+64088\"\ngroup = \"+64088\"\n").unwrap();
        let caps_xml = format!(
            "<capabilities><host><secmodel><model>dac</model><doi>0</doi><baselabel type='kvm'>+{qemu_acct_num}:+{caller_grp_num}</baselabel><baselabel type='qemu'>+64077:+64077</baselabel></secmodel></host></capabilities>"
        );
        let images = dir.path().join("sys-caps-images");
        let out_dir = dir.path().join("out-sys-caps");
        let chown_log = dir.path().join("chown-caps.log");
        let run_out = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "87",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_LIBVIRT_QEMU_CONF", qemu_conf.to_str().unwrap()),
                ("FAKE_VIRSH_CAPABILITIES", &caps_xml),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CHOWN_LOG", chown_log.to_str().unwrap()),
            ],
        );
        assert!(!run_out.status.success(), "{}", text(&run_out));
        let chowns = std::fs::read_to_string(&chown_log).unwrap_or_default();
        assert!(
            chowns.contains(&format!("{qemu_acct_num}:{caller_grp_num}"))
                && !chowns.contains("64088"),
            "connected daemon dac KVM baselabel must take precedence over qemu.conf:\n{chowns}\n{}",
            text(&run_out)
        );

        let unmapped_grp_num = if acls_can_name_test_uids {
            "64056"
        } else {
            caller_grp_num.as_str()
        };
        let qemu_conf_num = dir.path().join("qemu-unprefixed-num.conf");
        std::fs::write(
            &qemu_conf_num,
            format!("user = \"{qemu_acct_num}\"\ngroup = \"{unmapped_grp_num}\"\n"),
        )
        .unwrap();
        let images_num = dir.path().join("sys-num-images");
        let out_dir_num = dir.path().join("out-sys-num");
        let chown_log_num = dir.path().join("chown-num.log");
        let run_num = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "88",
                "--run-attempt",
                "1",
                "--out",
                out_dir_num.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images_num.to_str().unwrap()),
                ("QEMINGA_LIBVIRT_QEMU_CONF", qemu_conf_num.to_str().unwrap()),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CHOWN_LOG", chown_log_num.to_str().unwrap()),
            ],
        );
        assert!(!run_num.status.success(), "{}", text(&run_num));
        let run_dir_num = images_num.join(format!("qeminga-e2e-88-1-{arch}"));
        assert!(
            run_dir_num.is_dir(),
            "unprefixed numeric qemu.conf identity with no NSS entry must succeed: {}",
            text(&run_num)
        );
        let chowns_num = std::fs::read_to_string(&chown_log_num).unwrap_or_default();
        assert!(
            chowns_num.contains(&format!("{qemu_acct_num}:{unmapped_grp_num}")),
            "unprefixed numeric qemu.conf identity must be applied to root.qcow2:\n{chowns_num}"
        );
    }

    // 9. Intermediate symlink passing through a non-searchable directory to a searchable final
    //    target (`link1 -> secret_0700/link2 -> searchable_0755`):
    //    - 9a: Must refuse BEFORE creating dirs or downloading, reporting `secret_0700`.
    //    - 9b: Independent real Linux kernel verdict using a mode-`0000` intermediate directory
    //          (non-searchable by the current caller account) confirms `stat(link1)` gets EACCES
    //          from the kernel AND `libvirt-kvm-smoke.sh` refuses it too.
    {
        let secret_hop = dir.path().join("secret-hop-0700");
        let final_target = dir.path().join("searchable-target");
        std::fs::create_dir(&secret_hop).unwrap();
        std::fs::create_dir(&final_target).unwrap();
        std::fs::set_permissions(&secret_hop, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&final_target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hop_link = secret_hop.join("hop");
        std::os::unix::fs::symlink(&final_target, &hop_link).unwrap();
        let outer_alias = dir.path().join("storage-alias");
        std::os::unix::fs::symlink(&hop_link, &outer_alias).unwrap();

        let images = outer_alias.join("images");
        let out_dir = dir.path().join("out-sys-symlink-hop");
        let curl_log = dir.path().join("curl-symlink-hop.log");
        let run_hop = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "89",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ("FAKE_CURL_LOG", curl_log.to_str().unwrap()),
            ],
        );
        let hop_msg = text(&run_hop);
        assert!(
            !run_hop.status.success()
                && !final_target.join("images").exists()
                && !curl_log.exists(),
            "intermediate non-searchable symlink hop MUST be refused before creating dirs or downloading:\n{hop_msg}"
        );
        assert!(
            hop_msg.contains(secret_hop.to_str().unwrap()),
            "error must pinpoint the intermediate blocking directory {}:\n{hop_msg}",
            secret_hop.display()
        );

        // 9b: Independent real Linux kernel verdict for non-root caller account via 0o000 hop.
        let caller_acct_num = String::from_utf8(
            Command::new("/usr/bin/id")
                .arg("-u")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        if caller_acct_num != "0" {
            struct RestoreModeGuard(PathBuf);
            impl Drop for RestoreModeGuard {
                fn drop(&mut self) {
                    let _ =
                        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
                }
            }
            let ksecret = dir.path().join("kernel-secret-0000");
            std::fs::create_dir(&ksecret).unwrap();
            std::fs::set_permissions(&ksecret, std::fs::Permissions::from_mode(0o700)).unwrap();
            let khop = ksecret.join("hop");
            std::os::unix::fs::symlink(&final_target, &khop).unwrap();
            let kalias = dir.path().join("kernel-alias");
            std::os::unix::fs::symlink(&khop, &kalias).unwrap();
            std::fs::set_permissions(&ksecret, std::fs::Permissions::from_mode(0o000)).unwrap();
            let _guard = RestoreModeGuard(ksecret.clone());

            // Real kernel verdict on the original lexical path MUST be PermissionDenied (EACCES).
            let kernel_err = std::fs::metadata(&kalias).unwrap_err();
            assert_eq!(
                kernel_err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "Linux kernel must return EACCES traversing intermediate 0000 symlink hop"
            );

            let caller_user_spec = format!("+{caller_acct_num}");
            let k_out = run_with_umask(
                "0077",
                &[
                    "run",
                    "--arch",
                    arch,
                    "--candidate",
                    candidate.to_str().unwrap(),
                    "--source-sha",
                    SHA,
                    "--run-id",
                    "90",
                    "--run-attempt",
                    "1",
                    "--out",
                    dir.path().join("out-sys-kernel-hop").to_str().unwrap(),
                    "--expect-sha256",
                    &digest,
                ],
                &[
                    ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                    (
                        "QEMINGA_E2E_IMAGES",
                        kalias.join("images").to_str().unwrap(),
                    ),
                    ("QEMINGA_E2E_QEMU_USER", &caller_user_spec),
                    ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                    ("QEMINGA_KVM_DEVICE", "/dev/null"),
                    ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                    ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                    ("FAKE_ID_U", "0"),
                    ("FAKE_IMAGE_SHA", &pinned_image_sha),
                ],
            );
            assert!(
                !k_out.status.success(),
                "helper must agree with Linux kernel EACCES verdict on intermediate symlink hop: {}",
                text(&k_out)
            );
        }
    }

    // 10. Failed first-time image-root provisioning MUST NOT leave behind a `0700` blocking
    //     public directory — an ordinary retry MUST succeed! Also verify the script never
    //     falls back to world-searchable mode `0711`.
    {
        let retry_parent = dir.path().join("retry-root");
        let images = retry_parent.join("nested-images");
        let out_fail = dir.path().join("out-sys-retry-fail");
        let first_attempt = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "91",
                "--run-attempt",
                "1",
                "--out",
                out_fail.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", "+64099"),
                ("QEMINGA_TEST_DISABLE_ACL", "1"),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ],
        );
        assert!(
            !first_attempt.status.success(),
            "first provisioning attempt with failing grant must fail: {}",
            text(&first_attempt)
        );
        assert!(
            !retry_parent.exists(),
            "failed first grant MUST NOT leave behind a blocking 0700 directory at {}",
            retry_parent.display()
        );

        let out_ok = dir.path().join("out-sys-retry-ok");
        let retry_attempt = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "91",
                "--run-attempt",
                "2",
                "--out",
                out_ok.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ],
        );
        assert!(!retry_attempt.status.success(), "{}", text(&retry_attempt));
        let run_dir = images.join(format!("qeminga-e2e-91-2-{arch}"));
        assert!(
            run_dir.is_dir() && run_dir.join("root.qcow2").is_file(),
            "ordinary retry after failed first grant MUST succeed cleanly: {}",
            text(&retry_attempt)
        );

        // 10b. No-ACL fallback (`QEMINGA_TEST_DISABLE_ACL=1`) MUST set group-only `0710` (zero
        //      world bits) even when `qemu_gid == 0` — never `0711`.
        let images_noacl = dir.path().join("sys-noacl-images");
        let run_noacl = run_with_umask(
            "0077",
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                candidate.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "91",
                "--run-attempt",
                "3",
                "--out",
                dir.path().join("out-sys-noacl").to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_E2E_CONNECT", "qemu:///system"),
                ("QEMINGA_E2E_IMAGES", images_noacl.to_str().unwrap()),
                ("QEMINGA_E2E_QEMU_USER", &qemu_user_spec),
                ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
                ("QEMINGA_TEST_DISABLE_ACL", "1"),
                ("QEMINGA_KVM_DEVICE", "/dev/null"),
                ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
                ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
                ("FAKE_ID_U", "0"),
                ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ],
        );
        assert!(!run_noacl.status.success(), "{}", text(&run_noacl));
        let run_dir_noacl = images_noacl.join(format!("qeminga-e2e-91-3-{arch}"));
        assert!(run_dir_noacl.is_dir(), "{}", text(&run_noacl));
        for d in [&images_noacl, &run_dir_noacl] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o710,
                "no-ACL fallback must set 0710 on {}",
                d.display()
            );
            assert_eq!(effective_rights(d, qemu_acct_num, &caller_grp_num), 1);
            assert_eq!(effective_rights(d, "64099", "64099"), 0);
        }

        // Verify `provision_private_dir_fd` with `qemu_gid == 0` under no-ACL fallback uses
        // group-only `0o710` (group 0) rather than world-searchable `0o711`.
        let grp0_check = Command::new("python3")
            .args([
                "-IB",
                "-c",
                r#"
import importlib.util, os, sys

spec = importlib.util.spec_from_file_location("libvirt_kvm_sysfs", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

target = sys.argv[2]
os.makedirs(target, mode=0o700)
fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
chowned = []
chmodded = []
orig_os = mod.os
class FakeStat:
    def __init__(self, real_st, gid_override):
        self._st = real_st
        self.st_gid = gid_override
        self.st_uid = 0
        self.st_mode = real_st.st_mode
    def __getattr__(self, name):
        return getattr(self._st, name)
cur_gid = [0]
class SpyOs:
    def __getattr__(self, name):
        return getattr(orig_os, name)
    def geteuid(self):
        return 0
    def fchown(self, f, u, g):
        chowned.append((u, g))
        cur_gid[0] = g
    def fchmod(self, f, mode):
        chmodded.append(mode)
        return orig_os.fchmod(f, mode)
    def fstat(self, f):
        return FakeStat(orig_os.fstat(f), cur_gid[0])
mod.os = SpyOs()
orig_os.environ["QEMINGA_TEST_DISABLE_ACL"] = "1"
try:
    mod.provision_private_dir_fd(fd, 64055, 0, {0})
    assert (0, 0) in chowned, f"expected fchown(0, 0), got {chowned}"
    assert chmodded[-1] == 0o710, f"expected 0o710 for qemu_gid=0 fallback, got {oct(chmodded[-1])}"
    st = mod.os.fstat(fd)
    assert mod.effective_perms_fd(fd, st, 64055, {0}) == 1
    assert mod.effective_perms_fd(fd, st, 64099, {64099}) == 0
finally:
    mod.os = orig_os
    orig_os.close(fd)
"#,
                sysfs_module().to_str().unwrap(),
                dir.path().join("py-grp0-fallback").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            grp0_check.status.success(),
            "no-ACL fallback for qemu_gid=0 must use group-only 0710: {}",
            text(&grp0_check)
        );
    }
}

#[test]
#[ignore = "needs root (drops privileges in child process to verify real Linux kernel DAC/ACL/symlink verdicts)"]
fn privileged_kvm_system_lane_kernel_verdicts() {
    require_jq();
    let euid_out = Command::new("/usr/bin/id").arg("-u").output().unwrap();
    assert_eq!(
        String::from_utf8(euid_out.stdout).unwrap().trim(),
        "0",
        "privileged_kvm_system_lane_kernel_verdicts must run as root"
    );
    let arch = std::env::consts::ARCH;
    assert!(arch == "x86_64" || arch == "aarch64");

    // Keep the fixture root and root's PATH executable directory strictly `0700` from
    // creation (even under `umask 000`). Use a separate sibling `data_dir` narrowed to
    // traversal-only `0711` solely for the dropped non-root kernel-verdict child.
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    create_private_dir(&bin);
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let data_dir = private_tempdir();
    std::fs::set_permissions(data_dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();

    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let candidate = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        candidate.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "92",
        "--run-attempt",
        "1",
        "--runner",
        "test-runner",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    let digest = sha256_hex(&candidate.join("qeminga"));
    let img_key = lane(&["image-key", arch]);
    assert!(img_key.status.success(), "{}", text(&img_key));
    let pinned_image_sha = String::from_utf8(img_key.stdout)
        .unwrap()
        .trim()
        .rsplit('-')
        .next()
        .unwrap()
        .to_string();

    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
case "$1" in --connect=*) shift ;; esac
case "$1" in
    version) echo "Compiled against library: libvirt 10.0.0"; exit 0 ;;
    capabilities) if [ -n "${FAKE_VIRSH_CAPABILITIES:-}" ]; then printf '%s\n' "$FAKE_VIRSH_CAPABILITIES"; fi; exit 0 ;;
    domcapabilities) echo "<domainCapabilities/>"; exit 0 ;;
    net-info) echo "Active:         yes"; exit 0 ;;
    list) echo ""; exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    define) exit 0 ;;
    start) exit 42 ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(&bin.join("qemu-img"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("genisoimage"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -output) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] && : > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join(format!("qemu-system-{arch}")),
        "#!/bin/sh\necho 'QEMU emulator version 8.2.2'\n",
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf 'fake qcow2 bytes\n' > "$out"
chmod 0644 "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join("sha256sum"),
        r#"#!/bin/sh
case "$1" in
    *.qcow2.part) printf '%s  %s\n' "${FAKE_IMAGE_SHA:?}" "$1"; exit 0 ;;
esac
exec /usr/bin/sha256sum "$@"
"#,
    );
    write_exec(
        &bin.join("df"),
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/mock 99999999 0 99999999 0%% /\\n'\n",
    );
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let run_root = |args: &[&str], env: &[(&str, &str)]| -> Output {
        let mut cmd = Command::new("bash");
        cmd.args(["-c", r#"umask 0077; exec bash "$@""#, "_"]);
        cmd.arg(script()).args(args);
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        cmd.env("PATH", path);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    };

    // Independent Linux kernel verdict helper: forks as real non-root (acct, grp) and checks
    // os.access(path, mode_bit) / open() directly in the kernel!
    let kernel_can = |path: &Path, acct: &str, grp: &str, op: &str| -> bool {
        let out = Command::new("python3")
            .args([
                "-I",
                "-c",
                r#"
import os, sys
p = sys.argv[1]
u = int(sys.argv[2])
g = int(sys.argv[3])
op = sys.argv[4]
os.setgroups([g])
os.setgid(g)
os.setuid(u)
if op == "x":
    try:
        os.stat(p)
        sys.exit(0 if os.access(p, os.X_OK) else 1)
    except OSError:
        sys.exit(1)
elif op == "r":
    try:
        fd = os.open(p, os.O_RDONLY)
        os.close(fd)
        sys.exit(0)
    except OSError:
        sys.exit(1)
elif op == "w":
    try:
        sys.exit(0 if os.access(p, os.W_OK) else 1)
    except OSError:
        sys.exit(1)
"#,
                path.to_str().unwrap(),
                acct,
                grp,
                op,
            ])
            .output()
            .unwrap();
        out.status.success()
    };

    let qemu_acct = "64055";
    let qemu_grp = "64055";
    let other_acct = "64099";
    let other_grp = "64099";

    // A. Default ACL isolation verified by real Linux kernel as non-root 64055 vs 64099.
    let acl_parent = data_dir.path().join("root-defacl");
    create_private_dir(&acl_parent);
    std::fs::set_permissions(&acl_parent, std::fs::Permissions::from_mode(0o711)).unwrap();
    let set_def = Command::new("python3")
        .args([
            "-I",
            "-c",
            r#"
import os, struct, sys
p = sys.argv[1]
entries = [
    (0x01, 7, 0xFFFFFFFF),
    (0x02, 7, 64099),
    (0x04, 0, 0xFFFFFFFF),
    (0x10, 7, 0xFFFFFFFF),
    (0x20, 0, 0xFFFFFFFF),
]
raw = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", t, perm, eid) for t, perm, eid in entries)
os.setxattr(p, b"system.posix_acl_default", raw)
"#,
            acl_parent.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(set_def.status.success(), "{}", text(&set_def));

    let images_acl = acl_parent.join("images");
    let out_acl = run_root(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "92",
            "--run-attempt",
            "1",
            "--out",
            dir.path().join("out-acl").to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", images_acl.to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_USER", "+64055"),
            ("QEMINGA_E2E_QEMU_GROUP", "+64055"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
    );
    let run_dir_acl = images_acl.join(format!("qeminga-e2e-92-1-{arch}"));
    let disk_acl = run_dir_acl.join("root.qcow2");
    assert!(
        run_dir_acl.is_dir() && disk_acl.is_file(),
        "{}",
        text(&out_acl)
    );
    assert!(
        kernel_can(&run_dir_acl, qemu_acct, qemu_grp, "x")
            && kernel_can(&disk_acl, qemu_acct, qemu_grp, "r"),
        "kernel must allow QEMU to traverse run dir and read chowned root.qcow2"
    );
    assert!(
        !kernel_can(&images_acl, other_acct, other_grp, "x")
            && !kernel_can(&images_acl, other_acct, other_grp, "w")
            && !kernel_can(&run_dir_acl, other_acct, other_grp, "x")
            && !kernel_can(&disk_acl, other_acct, other_grp, "r"),
        "kernel must deny unrelated account 64099 all access even when parent had default:u:64099:rwx"
    );

    // B. No-ACL fallback with non-root QEMU in group 0: mode 0710 (root:root), NOT 0711.
    let images_grp0 = data_dir.path().join("root-grp0-images");
    let out_grp0 = run_root(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "93",
            "--run-attempt",
            "1",
            "--out",
            dir.path().join("out-grp0").to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", images_grp0.to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_USER", "+64055"),
            ("QEMINGA_E2E_QEMU_GROUP", "+0"),
            ("QEMINGA_TEST_DISABLE_ACL", "1"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
    );
    let run_dir_grp0 = images_grp0.join(format!("qeminga-e2e-93-1-{arch}"));
    assert!(run_dir_grp0.is_dir(), "{}", text(&out_grp0));
    assert_eq!(
        std::fs::metadata(&run_dir_grp0)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o710,
        "no-ACL fallback for non-root QEMU in group 0 must use 0710, not 0711"
    );
    assert!(
        kernel_can(&run_dir_grp0, qemu_acct, "0", "x")
            && !kernel_can(&run_dir_grp0, other_acct, other_grp, "x"),
        "kernel must allow (64055, grp 0) to traverse 0710 dir while blocking unrelated (64099, 64099)"
    );

    // C. Intermediate symlink through root-owned 0700 dir: kernel denies 64055 and helper agrees.
    let secret = data_dir.path().join("root-secret-0700");
    let pub_target = data_dir.path().join("root-pub-0711");
    create_private_dir(&secret);
    create_private_dir(&pub_target);
    std::fs::set_permissions(&pub_target, std::fs::Permissions::from_mode(0o711)).unwrap();
    let hop = secret.join("hop");
    std::os::unix::fs::symlink(&pub_target, &hop).unwrap();
    let alias = data_dir.path().join("root-alias");
    std::os::unix::fs::symlink(&hop, &alias).unwrap();
    assert!(!kernel_can(&alias, qemu_acct, qemu_grp, "x"));
    let out_hop = run_root(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "94",
            "--run-attempt",
            "1",
            "--out",
            dir.path().join("out-hop").to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", alias.join("images").to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_USER", "+64055"),
            ("QEMINGA_E2E_QEMU_GROUP", "+64055"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
    );
    assert!(
        !out_hop.status.success() && !pub_target.join("images").exists(),
        "real root lane must refuse intermediate non-searchable symlink hop: {}",
        text(&out_hop)
    );

    // D. Real non-root-owned (64099) ancestor directory MUST be refused by real root in BOTH
    //    `run` (without leaking pre-planted serial.log) AND standalone `cleanup` (without deleting).
    let nonroot_anc = data_dir.path().join("nonroot-owned-0755");
    create_private_dir(&nonroot_anc);
    std::fs::set_permissions(&nonroot_anc, std::fs::Permissions::from_mode(0o755)).unwrap();
    let nonroot_images = nonroot_anc.join("images");
    let nonroot_run_dir = nonroot_images.join(format!("qeminga-e2e-95-1-{arch}"));
    std::fs::create_dir_all(&nonroot_run_dir).unwrap();
    std::fs::write(nonroot_run_dir.join("serial.log"), b"NONROOT_SECRET\n").unwrap();
    let nonroot_keep = nonroot_run_dir.join("keep.dat");
    std::fs::write(&nonroot_keep, b"must-not-delete\n").unwrap();
    let ch = Command::new("/usr/bin/chown")
        .args(["-R", "64099:64099", nonroot_anc.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(ch.success());
    let out_nr_dir = dir.path().join("out-nonroot");
    let out_nr = run_root(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "95",
            "--run-attempt",
            "1",
            "--out",
            out_nr_dir.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", nonroot_images.to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_USER", "+64055"),
            ("QEMINGA_E2E_QEMU_GROUP", "+64055"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
    );
    assert!(
        !out_nr.status.success() && !out_nr_dir.join("serial.log").exists(),
        "real root lane must refuse non-root-owned ancestor without leaking serial.log: {}",
        text(&out_nr)
    );
    let out_nr_clean_dir = dir.path().join("out-nonroot-clean");
    let out_nr_clean = run_root(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "95",
            "--run-attempt",
            "1",
            "--out",
            out_nr_clean_dir.to_str().unwrap(),
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", nonroot_images.to_str().unwrap()),
        ],
    );
    assert!(
        !out_nr_clean.status.success()
            && nonroot_keep.is_file()
            && !out_nr_clean_dir.join("serial.log").exists(),
        "real root cleanup must refuse non-root-owned image root and leave files intact: {}",
        text(&out_nr_clean)
    );

    // E. Real root MUST reject QEMINGA_TEST_SYSFS_ROOT (full host-root '/' walk cannot be bypassed).
    let out_override = run_root(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "96",
            "--run-attempt",
            "1",
            "--out",
            dir.path().join("out-override").to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", images_acl.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", data_dir.path().to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_USER", "+64055"),
            ("QEMINGA_E2E_QEMU_GROUP", "+64055"),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
    );
    assert!(
        !out_override.status.success()
            && text(&out_override).contains("QEMINGA_TEST_SYSFS_ROOT is forbidden"),
        "real root must refuse QEMINGA_TEST_SYSFS_ROOT override: {}",
        text(&out_override)
    );
}

#[test]
fn system_mode_diagnostics_and_cleanup_require_verified_image_root_and_regular_log() {
    require_jq();
    let arch = std::env::consts::ARCH;
    assert!(arch == "x86_64" || arch == "aarch64");

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let sys_root = dir.path().join("sys-root");
    create_private_dir(&bin);
    create_private_dir(&sys_root);
    std::fs::set_permissions(&sys_root, std::fs::Permissions::from_mode(0o755)).unwrap();

    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let candidate = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        candidate.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "101",
        "--run-attempt",
        "1",
        "--runner",
        "test-runner",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    let digest = sha256_hex(&candidate.join("qeminga"));
    let img_key = lane(&["image-key", arch]);
    assert!(img_key.status.success(), "{}", text(&img_key));
    let pinned_image_sha = String::from_utf8(img_key.stdout)
        .unwrap()
        .trim()
        .rsplit('-')
        .next()
        .unwrap()
        .to_string();
    let caller_grp_num = String::from_utf8(
        Command::new("/usr/bin/id")
            .arg("-g")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let qemu_user_spec = "+64055";
    let qemu_group_spec = format!("+{caller_grp_num}");

    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
case "$1" in --connect=*) shift ;; esac
case "$1" in
    version) echo "Compiled against library: libvirt 10.0.0"; exit 0 ;;
    capabilities) exit 0 ;;
    domcapabilities) echo "<domainCapabilities/>"; exit 0 ;;
    net-info) echo "Active:         yes"; exit 0 ;;
    list) echo ""; exit 0 ;;
    domstate) echo "error: failed to get domain '$2'" >&2; exit 1 ;;
    define) exit 0 ;;
    start)
        if [ -n "${FAKE_PLANT_SERIAL_SYMLINK:-}" ]; then
            ln -s "${FAKE_PLANT_SERIAL_SYMLINK}" "${FAKE_PLANT_SERIAL_DEST:?}"
        elif [ -n "${FAKE_PLANT_SERIAL_CONTENT:-}" ]; then
            printf '%s\n' "${FAKE_PLANT_SERIAL_CONTENT}" > "${FAKE_PLANT_SERIAL_DEST:?}"
        fi
        exit 42
        ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(&bin.join("qemu-img"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("genisoimage"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -output) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] && : > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join(format!("qemu-system-{arch}")),
        "#!/bin/sh\necho 'QEMU emulator version 8.2.2'\n",
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf 'fake qcow2 bytes\n' > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join("sha256sum"),
        r#"#!/bin/sh
case "$1" in
    *.qcow2.part) printf '%s  %s\n' "${FAKE_IMAGE_SHA:?}" "$1"; exit 0 ;;
esac
exec /usr/bin/sha256sum "$@"
"#,
    );
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("df"),
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/mock 99999999 0 99999999 0%% /\\n'\n",
    );
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo "0"; exit 0; fi
exec /usr/bin/id "$@"
"#,
    );
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    let host_secret = dir.path().join("host-secret.txt");
    std::fs::write(&host_secret, b"TOP_SECRET_HOST_DATA\n").unwrap();

    // 1. Rejected shared-writable QEMINGA_E2E_IMAGES with a pre-planted serial.log:
    //    `cmd_run` exit trap MUST NOT copy serial.log into OUT, while still producing result.json.
    let shared_parent = sys_root.join("shared-0777");
    create_private_dir(&shared_parent);
    std::fs::set_permissions(&shared_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let bad_images = shared_parent.join("images");
    let bad_run_name = format!("qeminga-e2e-101-1-{arch}");
    let bad_run_dir = bad_images.join(&bad_run_name);
    std::fs::create_dir_all(&bad_run_dir).unwrap();
    std::fs::write(
        bad_run_dir.join("serial.log"),
        b"LEAKED_FROM_REJECTED_ROOT\n",
    )
    .unwrap();
    let victim_file = bad_run_dir.join("unrelated.dat");
    std::fs::write(&victim_file, b"must-survive-cleanup\n").unwrap();

    let out_reject = sys_root.join("out-reject");
    let run_reject = lane_env(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "101",
            "--run-attempt",
            "1",
            "--out",
            out_reject.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", bad_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_USER", qemu_user_spec),
            ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
        Some(&bin),
    );
    assert!(!run_reject.status.success(), "{}", text(&run_reject));
    assert!(
        out_reject.join("result.json").is_file(),
        "preflight failure should still emit result.json: {}",
        text(&run_reject)
    );
    assert!(
        !out_reject.join("serial.log").exists(),
        "rejected QEMINGA_E2E_IMAGES MUST NOT leak serial.log into evidence dir"
    );

    // 2. Standalone `cmd_cleanup --out` against the same rejected shared-writable image root:
    //    MUST refuse cleanup, keep `unrelated.dat` intact, AND NOT leak `serial.log` into OUT!
    let out_cleanup_reject = sys_root.join("out-cleanup-reject");
    let cleanup_reject = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "101",
            "--run-attempt",
            "1",
            "--out",
            out_cleanup_reject.to_str().unwrap(),
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", bad_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !cleanup_reject.status.success(),
        "standalone cleanup MUST reject untrusted/shared-writable QEMINGA_E2E_IMAGES: {}",
        text(&cleanup_reject)
    );
    assert!(
        victim_file.is_file(),
        "standalone cleanup MUST leave files in rejected image root untouched"
    );
    assert!(
        !out_cleanup_reject.join("serial.log").exists(),
        "standalone cleanup MUST NOT collect serial.log from rejected image root"
    );

    let acls_can_name_test_uids = uid_is_mapped(64055) && uid_is_mapped(64099);
    let disable_acl_flag = if acls_can_name_test_uids { "0" } else { "1" };

    // 3. Trusted image root:
    //    - 3a: Symlinked `serial.log` inside verified run dir MUST be refused (`O_NOFOLLOW`).
    //    - 3b: Regular `serial.log` inside verified run dir IS collected into OUT.
    //    - 3c: Standalone `cleanup` on trusted root removes ONLY the target run dir (leaving sibling).
    let good_images = sys_root.join("trusted-images");
    let run_sym_dir = good_images.join(format!("qeminga-e2e-102-1-{arch}"));
    let out_sym = sys_root.join("out-sym");
    let run_sym = lane_env(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "102",
            "--run-attempt",
            "1",
            "--out",
            out_sym.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("QEMINGA_TEST_DISABLE_ACL", disable_acl_flag),
            ("QEMINGA_E2E_QEMU_USER", qemu_user_spec),
            ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ("FAKE_PLANT_SERIAL_SYMLINK", host_secret.to_str().unwrap()),
            (
                "FAKE_PLANT_SERIAL_DEST",
                run_sym_dir.join("serial.log").to_str().unwrap(),
            ),
        ],
        Some(&bin),
    );
    assert!(!run_sym.status.success(), "{}", text(&run_sym));
    assert!(run_sym_dir.is_dir(), "{}", text(&run_sym));
    assert!(
        !out_sym.join("serial.log").exists(),
        "symlinked serial.log inside verified run dir MUST NOT be copied into OUT"
    );

    let run_ok_dir = good_images.join(format!("qeminga-e2e-103-1-{arch}"));
    let out_ok = sys_root.join("out-ok");
    let run_ok = lane_env(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "103",
            "--run-attempt",
            "1",
            "--out",
            out_ok.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("QEMINGA_TEST_DISABLE_ACL", disable_acl_flag),
            ("QEMINGA_E2E_QEMU_USER", qemu_user_spec),
            ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ("FAKE_PLANT_SERIAL_CONTENT", "VALID_GUEST_CONSOLE_LINE"),
            (
                "FAKE_PLANT_SERIAL_DEST",
                run_ok_dir.join("serial.log").to_str().unwrap(),
            ),
        ],
        Some(&bin),
    );
    assert!(!run_ok.status.success(), "{}", text(&run_ok));
    assert_eq!(
        std::fs::read_to_string(out_ok.join("serial.log"))
            .unwrap_or_default()
            .trim(),
        "VALID_GUEST_CONSOLE_LINE",
        "genuine regular serial.log in verified run dir should be collected"
    );

    // Symlinked run dir under trusted images root MUST be refused by cleanup without touching target.
    let outside_victim = sys_root.join("outside-victim");
    create_private_dir(&outside_victim);
    let outside_file = outside_victim.join("keep.txt");
    std::fs::write(&outside_file, b"keep").unwrap();
    let sym_run = good_images.join(format!("qeminga-e2e-104-1-{arch}"));
    std::os::unix::fs::symlink(&outside_victim, &sym_run).unwrap();
    let clean_sym = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "104",
            "--run-attempt",
            "1",
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        !clean_sym.status.success() && outside_file.is_file(),
        "cleanup MUST refuse symlinked run directory and keep target untouched: {}",
        text(&clean_sym)
    );
    std::fs::remove_file(&sym_run).unwrap();

    // Legitimate cleanup removes run 103 while keeping sibling run 102 intact.
    let clean_ok = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "103",
            "--run-attempt",
            "1",
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
        ],
        Some(&bin),
    );
    assert!(
        clean_ok.status.success() && !run_ok_dir.exists() && run_sym_dir.is_dir(),
        "trusted system cleanup must remove only the target run dir: {}",
        text(&clean_ok)
    );
}

#[test]
fn sysfs_module_enforces_atomic_noreplace_recovers_failed_sync_and_isolates_root_fd() {
    let dir = private_tempdir();
    let sys_root = dir.path().join("sys-root");
    create_private_dir(&sys_root);
    std::fs::set_permissions(&sys_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let acls_can_name_test_uids = uid_is_mapped(64055) && uid_is_mapped(64099);

    let mut cmd = Command::new("python3");
    if !acls_can_name_test_uids {
        cmd.env("QEMINGA_TEST_DISABLE_ACL", "1");
    }
    let py = cmd
        .args([
            "-IB",
            "-c",
            r#"
import ctypes, errno, importlib.util, os, stat, sys

mod_path = sys.argv[1]
root_path = sys.argv[2]
assert os.path.isfile(mod_path), f"missing importable sysfs module: {mod_path}"
spec = importlib.util.spec_from_file_location("libvirt_kvm_sysfs", mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

euid = os.geteuid()
egid = os.getegid()
root_fd = os.open(root_path, mod.READ_DIR_FLAGS)
try:
    # 1. Fixture-owned root_fd isolates walk from host '/' UID mapping (even when '/' reports 65534).
    orig_fstat = mod.os.fstat
    class FakeOverflowStat:
        def __init__(self, st):
            self._st = st
            self.st_uid = 65534
        def __getattr__(self, name):
            return getattr(self._st, name)
    real_root_fd = os.open("/", mod.READ_DIR_FLAGS)
    try:
        real_root_id = (os.fstat(real_root_fd).st_dev, os.fstat(real_root_fd).st_ino)
    finally:
        os.close(real_root_fd)
    def fake_fstat_overflow_slash(fd):
        st = orig_fstat(fd)
        if (st.st_dev, st.st_ino) == real_root_id:
            return FakeOverflowStat(st)
        return st
    mod.os.fstat = fake_fstat_overflow_slash
    try:
        # Production host-root walk MUST reject untrusted '/' (uid 65534).
        try:
            mod.walk_existing_prefix(os.path.join(root_path, "from-slash"), 64055, {egid}, {0, euid})
            raise AssertionError("host-root walk must refuse untrusted '/'")
        except OSError as exc:
            assert exc.errno == errno.EACCES, f"expected EACCES on untrusted '/', got {exc}"
        # Fixture-owned root_fd walk SUCCEEDS even when '/' reports 65534!
        images_path = os.path.join(root_path, "isolated-images")
        mod.prepare_images_root(images_path, 64055, egid, {egid}, root_fd=root_fd, root_path=root_path)
        assert os.path.isdir(images_path)
    finally:
        mod.os.fstat = orig_fstat

    # 2. Unsupported RENAME_NOREPLACE (EINVAL, ENOSYS, EOPNOTSUPP, and None):
    #    MUST fail closed BEFORE publication, never invoke os.rename, clean up init staging dir,
    #    and preserve both absent and existing empty destinations!
    images_fd = os.open(images_path, mod.READ_DIR_FLAGS)
    try:
        orig_r2 = mod._RENAMEAT2
        orig_rename = mod.os.rename
        rename_called = []
        def forbid_rename(*a, **kw):
            rename_called.append((a, kw))
            raise AssertionError("non-atomic os.rename fallback must NEVER be called")
        mod.os.rename = forbid_rename
        try:
            for err_code in (errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP, None):
                if err_code is None:
                    mod._RENAMEAT2 = None
                else:
                    def make_fail(ec):
                        def _fail(*_args):
                            ctypes.set_errno(ec)
                            return -1
                        return _fail
                    mod._RENAMEAT2 = make_fail(err_code)
                absent_name = f"qeminga-e2e-201-{err_code or 0}-x86_64"
                try:
                    mod.create_component_in_fd(
                        images_fd, images_path, absent_name, 64055, egid, {egid}, fail_if_exists=True
                    )
                    raise AssertionError(f"must refuse unsupported RENAME_NOREPLACE ({err_code})")
                except OSError as exc:
                    assert exc.errno in (errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL), exc
                assert not os.path.exists(os.path.join(images_path, absent_name))

                existing_name = f"qeminga-e2e-202-{err_code or 0}-x86_64"
                existing_path = os.path.join(images_path, existing_name)
                os.mkdir(existing_path, 0o700)
                before_id = (os.lstat(existing_path).st_dev, os.lstat(existing_path).st_ino)
                try:
                    mod.create_component_in_fd(
                        images_fd, images_path, existing_name, 64055, egid, {egid}, fail_if_exists=True
                    )
                    raise AssertionError(f"must refuse existing dest under unsupported RENAME_NOREPLACE ({err_code})")
                except OSError as exc:
                    assert exc.errno in (errno.EOPNOTSUPP, errno.ENOSYS, errno.EINVAL), exc
                after_id = (os.lstat(existing_path).st_dev, os.lstat(existing_path).st_ino)
                assert before_id == after_id, "existing empty directory inode must be preserved"
                os.rmdir(existing_path)
            assert not rename_called
            leftovers = [n for n in os.listdir(images_path) if n.startswith(".qeminga-e2e-init.")]
            assert not leftovers, f"unexpected staging leftovers: {leftovers}"
        finally:
            mod._RENAMEAT2 = orig_r2
            mod.os.rename = orig_rename

        # 3. Existing destination with real renameat2(RENAME_NOREPLACE): EEXIST + untouched inode.
        other_run = "qeminga-e2e-203-1-x86_64"
        other_path = os.path.join(images_path, other_run)
        os.mkdir(other_path, 0o700)
        other_before = (os.lstat(other_path).st_dev, os.lstat(other_path).st_ino)
        try:
            mod.create_component_in_fd(
                images_fd, images_path, other_run, 64055, egid, {egid}, fail_if_exists=True
            )
            raise AssertionError("existing run dir must fail with EEXIST")
        except OSError as exc:
            assert exc.errno == errno.EEXIST, exc
        assert (os.lstat(other_path).st_dev, os.lstat(other_path).st_ino) == other_before
        os.rmdir(other_path)

        # 4. Failed os.fsync(parent_fd) AFTER renameat2 publishes the run directory:
        #    MUST return EIO, reclaim THIS invocation's still-empty directory, and let an
        #    ordinary retry succeed cleanly (while still refusing an unrelated pre-existing dir
        #    and never removing a directory whose inode changed before rollback).
        retry_run = "qeminga-e2e-204-1-x86_64"
        retry_path = os.path.join(images_path, retry_run)
        orig_fsync = mod.os.fsync
        saw_visible_at_sync = []
        def fail_parent_fsync(fd):
            if fd == images_fd:
                saw_visible_at_sync.append(os.path.isdir(retry_path))
                raise OSError(errno.EIO, "simulated parent directory fsync failure")
            return orig_fsync(fd)
        mod.os.fsync = fail_parent_fsync
        try:
            try:
                mod.create_component_in_fd(
                    images_fd, images_path, retry_run, 64055, egid, {egid}, fail_if_exists=True
                )
                raise AssertionError("expected EIO from parent fsync failure")
            except OSError as exc:
                assert exc.errno == errno.EIO, exc
        finally:
            mod.os.fsync = orig_fsync
        assert saw_visible_at_sync == [True], f"expected directory visible at sync time, got {saw_visible_at_sync}"
        assert not os.path.exists(retry_path), "failed parent fsync must reclaim this invocation's still-empty run dir"

        # If another actor replaced retry_run with a different inode before rollback, rollback MUST NOT remove it!
        replaced_run = "qeminga-e2e-205-1-x86_64"
        replaced_path = os.path.join(images_path, replaced_run)
        aside_path = os.path.join(images_path, ".replaced-aside")
        def swap_and_fail_fsync(fd):
            if fd == images_fd:
                os.rename(replaced_path, aside_path)
                os.mkdir(replaced_path, 0o700)
                raise OSError(errno.EIO, "simulated sync failure after concurrent replacement")
            return orig_fsync(fd)
        mod.os.fsync = swap_and_fail_fsync
        try:
            try:
                mod.create_component_in_fd(
                    images_fd, images_path, replaced_run, 64055, egid, {egid}, fail_if_exists=True
                )
                raise AssertionError("expected EIO")
            except OSError as exc:
                assert exc.errno == errno.EIO, exc
        finally:
            mod.os.fsync = orig_fsync
        assert os.path.isdir(replaced_path), "rollback must preserve directory whose inode changed"
        os.rmdir(replaced_path)
        os.rmdir(aside_path)

        # Ordinary retry now succeeds cleanly!
        rfd = mod.create_component_in_fd(
            images_fd, images_path, retry_run, 64055, egid, {egid}, fail_if_exists=True
        )
        os.close(rfd)
        assert os.path.isdir(retry_path)

        # And a second attempt while retry_run exists STILL refuses with EEXIST and keeps it!
        keep_id = (os.lstat(retry_path).st_dev, os.lstat(retry_path).st_ino)
        try:
            mod.create_component_in_fd(
                images_fd, images_path, retry_run, 64055, egid, {egid}, fail_if_exists=True
            )
            raise AssertionError("retry_run owned by previous run must refuse with EEXIST")
        except OSError as exc:
            assert exc.errno == errno.EEXIST, exc
        assert (os.lstat(retry_path).st_dev, os.lstat(retry_path).st_ino) == keep_id

        # 5. cleanup_run_dir refuses untrusted-owner run dir AND cross-device mountpoints!
        untrusted_run = "qeminga-e2e-206-1-x86_64"
        untrusted_path = os.path.join(images_path, untrusted_run)
        os.mkdir(untrusted_path, 0o700)
        keep_marker = os.path.join(untrusted_path, "keep.txt")
        with open(keep_marker, "w", encoding="utf-8") as fh:
            fh.write("keep\n")
        untrusted_id = (os.lstat(untrusted_path).st_dev, os.lstat(untrusted_path).st_ino)
        def fake_untrusted_fstat(fd):
            st = orig_fstat(fd)
            if (st.st_dev, st.st_ino) == untrusted_id:
                return FakeOverflowStat(st)
            return st
        mod.os.fstat = fake_untrusted_fstat
        try:
            try:
                mod.cleanup_run_dir(images_path, untrusted_run, root_fd=root_fd, root_path=root_path)
                raise AssertionError("cleanup_run_dir must refuse untrusted-owner run dir")
            except OSError as exc:
                assert exc.errno == errno.EACCES, exc
        finally:
            mod.os.fstat = orig_fstat
        assert os.path.isfile(keep_marker), "untrusted run dir contents must survive refused cleanup"

        # Cross-device mountpoint inside run dir MUST fail closed with EXDEV!
        sub_mount = os.path.join(untrusted_path, "mnt-sub")
        os.mkdir(sub_mount, 0o700)
        sub_file = os.path.join(sub_mount, "mounted.txt")
        with open(sub_file, "w", encoding="utf-8") as fh:
            fh.write("mounted\n")
        sub_id = (os.lstat(sub_mount).st_dev, os.lstat(sub_mount).st_ino)
        class FakeCrossDevStat:
            def __init__(self, st):
                self._st = st
                self.st_dev = st.st_dev + 1
            def __getattr__(self, name):
                return getattr(self._st, name)
        def fake_crossdev_fstat(fd):
            st = orig_fstat(fd)
            if (st.st_dev, st.st_ino) == sub_id:
                return FakeCrossDevStat(st)
            return st
        mod.os.fstat = fake_crossdev_fstat
        try:
            try:
                mod.cleanup_run_dir(images_path, untrusted_run, root_fd=root_fd, root_path=root_path)
                raise AssertionError("cleanup_run_dir must refuse cross-device subdirectory")
            except OSError as exc:
                assert exc.errno == errno.EXDEV, exc
        finally:
            mod.os.fstat = orig_fstat
        assert os.path.isfile(sub_file), "cross-device mountpoint contents must survive refused cleanup"
    finally:
        os.close(images_fd)

    # 6. CLI refuses QEMINGA_TEST_SYSFS_ROOT when euid == 0 (never bypass host-root walk as root).
    orig_geteuid = mod.os.geteuid
    mod.os.geteuid = lambda: 0
    orig_env = os.environ.get("QEMINGA_TEST_SYSFS_ROOT")
    os.environ["QEMINGA_TEST_SYSFS_ROOT"] = root_path
    try:
        try:
            mod.resolve_cli_root()
            raise AssertionError("root process MUST reject QEMINGA_TEST_SYSFS_ROOT")
        except OSError as exc:
            assert exc.errno == errno.EPERM, exc
    finally:
        mod.os.geteuid = orig_geteuid
        if orig_env is None:
            os.environ.pop("QEMINGA_TEST_SYSFS_ROOT", None)
        else:
            os.environ["QEMINGA_TEST_SYSFS_ROOT"] = orig_env
finally:
    os.close(root_fd)
"#,
            sysfs_module().to_str().unwrap(),
            sys_root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        py.status.success(),
        "sysfs module unit tests failed:\n{}",
        text(&py)
    );
}

#[test]
fn private_fixture_helpers_create_0700_dirs_and_tools_even_under_umask_000() {
    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    create_private_dir(&bin);
    let tool = bin.join("tool");
    write_exec(&tool, "#!/bin/sh\nexit 0\n");

    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&tool).unwrap().permissions().mode() & 0o777,
        0o700
    );

    // Confirm privileged_kvm_system_lane_kernel_verdicts requests 0700 at creation (not tempfile::tempdir()).
    let src = std::fs::read_to_string(root().join("tests/libvirt_kvm.rs")).unwrap();
    let priv_start = src
        .find("fn privileged_kvm_system_lane_kernel_verdicts()")
        .unwrap();
    let priv_end = src[priv_start..]
        .find("\n#[test]\n")
        .map(|off| priv_start + off)
        .unwrap_or(src.len());
    let priv_body = &src[priv_start..priv_end];
    assert!(
        !priv_body.contains("tempfile::tempdir()")
            && priv_body.contains("private_tempdir()")
            && priv_body.contains("create_private_dir(&bin)"),
        "privileged_kvm_system_lane_kernel_verdicts must create its fixture root and bin directory with 0700 permissions at creation"
    );
}

#[test]
fn sysfs_module_enforces_same_mount_id_and_reclaims_on_final_traversal_failure() {
    let dir = private_tempdir();
    let sys_root = dir.path().join("sys-root");
    create_private_dir(&sys_root);
    std::fs::set_permissions(&sys_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let acls_can_name_test_uids = uid_is_mapped(64055) && uid_is_mapped(64099);

    let mut cmd = Command::new("python3");
    if !acls_can_name_test_uids {
        cmd.env("QEMINGA_TEST_DISABLE_ACL", "1");
    }
    let py = cmd
        .args([
            "-IB",
            "-c",
            r#"
import errno, importlib.util, os, sys

mod_path = sys.argv[1]
root_path = sys.argv[2]
spec = importlib.util.spec_from_file_location("libvirt_kvm_sysfs", mod_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

assert hasattr(mod, "fd_mnt_id"), "libvirt_kvm_sysfs must expose fd_mnt_id"
assert hasattr(mod, "scan_open_dir_same_mount"), "libvirt_kvm_sysfs must expose scan_open_dir_same_mount"

egid = os.getegid()
root_fd = os.open(root_path, mod.READ_DIR_FLAGS)
try:
    images_path = os.path.join(root_path, "mnt-images")
    mod.prepare_images_root(images_path, 64055, egid, {egid}, root_fd=root_fd, root_path=root_path)

    # 1. Same-st_dev bind mount inside run dir: pre-scan MUST reject BEFORE unlinking any sibling!
    run_bind_sub = "qeminga-e2e-301-1-x86_64"
    run_bind_sub_path = os.path.join(images_path, run_bind_sub)
    os.mkdir(run_bind_sub_path, 0o700)
    sibling = os.path.join(run_bind_sub_path, "a_sibling.txt")
    with open(sibling, "w", encoding="utf-8") as fh:
        fh.write("sibling-must-survive\n")
    bind_sub = os.path.join(run_bind_sub_path, "z_bind_sub")
    os.mkdir(bind_sub, 0o700)
    bind_secret = os.path.join(bind_sub, "mounted_secret.txt")
    with open(bind_secret, "w", encoding="utf-8") as fh:
        fh.write("host-bind-data\n")
    bind_sub_id = (os.lstat(bind_sub).st_dev, os.lstat(bind_sub).st_ino)
    orig_fd_mnt_id = mod.fd_mnt_id
    triggered = []
    def fake_bind_sub_mnt_id(fd):
        st = os.fstat(fd)
        mid = orig_fd_mnt_id(fd)
        if (st.st_dev, st.st_ino) == bind_sub_id:
            triggered.append("z_bind_sub")
            return mid + 77
        return mid
    mod.fd_mnt_id = fake_bind_sub_mnt_id
    try:
        try:
            mod.cleanup_run_dir(images_path, run_bind_sub, root_fd=root_fd, root_path=root_path)
            raise AssertionError("cleanup_run_dir must reject same-st_dev bind mount subdir")
        except OSError as exc:
            assert exc.errno == errno.EXDEV, exc
            assert "z_bind_sub" in str(exc), f"expected rejection on z_bind_sub, got {exc}"
    finally:
        mod.fd_mnt_id = orig_fd_mnt_id
    assert triggered == ["z_bind_sub"], f"expected z_bind_sub mount-id mismatch, got {triggered}"
    assert os.path.isfile(sibling), "pre-scan must abort BEFORE unlinking sibling files"
    assert os.path.isfile(bind_secret), "same-st_dev bind mount target files must survive"

    # 2. Same-st_dev bind mount directly at run_dir itself: MUST reject with EXDEV!
    run_bind_self_id = (os.lstat(run_bind_sub_path).st_dev, os.lstat(run_bind_sub_path).st_ino)
    triggered_self = []
    def fake_bind_self_mnt_id(fd):
        st = os.fstat(fd)
        mid = orig_fd_mnt_id(fd)
        if (st.st_dev, st.st_ino) == run_bind_self_id:
            triggered_self.append("run_dir")
            return mid + 88
        return mid
    mod.fd_mnt_id = fake_bind_self_mnt_id
    try:
        try:
            mod.cleanup_run_dir(images_path, run_bind_sub, root_fd=root_fd, root_path=root_path)
            raise AssertionError("cleanup_run_dir must reject same-st_dev bind mount at run_dir")
        except OSError as exc:
            assert exc.errno == errno.EXDEV, exc
    finally:
        mod.fd_mnt_id = orig_fd_mnt_id
    assert triggered_self == ["run_dir"], f"expected run_dir mount-id mismatch, got {triggered_self}"
    assert os.path.isfile(sibling)

    # 3. Same-st_dev single-file bind mount at serial.log: collect_serial_log MUST reject with EXDEV!
    slog = os.path.join(run_bind_sub_path, "serial.log")
    with open(slog, "w", encoding="utf-8") as fh:
        fh.write("BIND_MOUNTED_SECRET\n")
    slog_id = (os.lstat(slog).st_dev, os.lstat(slog).st_ino)
    out_dir = os.path.join(root_path, "out-bind-serial")
    os.mkdir(out_dir, 0o755)
    triggered_slog = []
    def fake_bind_serial_mnt_id(fd):
        st = os.fstat(fd)
        mid = orig_fd_mnt_id(fd)
        if (st.st_dev, st.st_ino) == slog_id:
            triggered_slog.append("serial.log")
            return mid + 99
        return mid
    mod.fd_mnt_id = fake_bind_serial_mnt_id
    try:
        try:
            mod.collect_serial_log(
                images_path, run_bind_sub, out_dir, "serial.log", root_fd=root_fd, root_path=root_path
            )
            raise AssertionError("collect_serial_log must reject bind-mounted serial.log")
        except OSError as exc:
            assert exc.errno == errno.EXDEV, exc
    finally:
        mod.fd_mnt_id = orig_fd_mnt_id
    assert triggered_slog == ["serial.log"], f"expected serial.log mount-id mismatch, got {triggered_slog}"
    assert not os.path.exists(os.path.join(out_dir, "serial.log"))

    # Positive controls (including on Linux overlayfs where file st_dev != dir st_dev while mnt_id matches):
    assert mod.collect_serial_log(
        images_path, run_bind_sub, out_dir, "serial.log", root_fd=root_fd, root_path=root_path
    ) is True
    assert open(os.path.join(out_dir, "serial.log"), encoding="utf-8").read().strip() == "BIND_MOUNTED_SECRET"
    assert mod.cleanup_run_dir(images_path, run_bind_sub, root_fd=root_fd, root_path=root_path) == "removed"
    assert not os.path.exists(run_bind_sub_path)

    # 4. Transient EAGAIN on the final kernel_verdict_traversal in create_run_dir:
    #    MUST reclaim this invocation's still-empty run dir while descriptors remain open,
    #    allowing an ordinary retry to succeed cleanly!
    final_run = "qeminga-e2e-302-1-x86_64"
    final_run_path = os.path.join(images_path, final_run)
    orig_kvt = mod.kernel_verdict_traversal
    calls = []
    def fail_final_kvt(path, u, g, grps):
        calls.append(path)
        if os.path.normpath(path) == os.path.normpath(final_run_path):
            assert os.path.isdir(final_run_path), "run dir must exist when final check runs"
            raise OSError(errno.EAGAIN, "simulated transient final traversal error")
        return orig_kvt(path, u, g, grps)
    mod.kernel_verdict_traversal = fail_final_kvt
    try:
        try:
            mod.create_run_dir(
                images_path, final_run, 64055, egid, {egid}, root_fd=root_fd, root_path=root_path
            )
            raise AssertionError("expected EAGAIN from final kernel_verdict_traversal")
        except OSError as exc:
            assert exc.errno == errno.EAGAIN, exc
    finally:
        mod.kernel_verdict_traversal = orig_kvt
    assert os.path.normpath(final_run_path) in [os.path.normpath(c) for c in calls], (
        f"final kernel_verdict_traversal must be invoked on {final_run_path}, got {calls}"
    )
    assert not os.path.exists(final_run_path), (
        "create_run_dir must reclaim its still-empty run dir when final traversal check fails"
    )
    # Ordinary retry now succeeds cleanly!
    mod.create_run_dir(
        images_path, final_run, 64055, egid, {egid}, root_fd=root_fd, root_path=root_path
    )
    assert os.path.isdir(final_run_path)
finally:
    os.close(root_fd)
"#,
            sysfs_module().to_str().unwrap(),
            sys_root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        py.status.success(),
        "mount-id and final-traversal rollback tests failed:\n{}",
        text(&py)
    );
    assert!(
        !root().join("scripts/ci/__pycache__").exists(),
        "Python test invocations must pass -B and never leave scripts/ci/__pycache__ behind"
    );
}

#[test]
fn system_mode_protects_evidence_destination_and_verifies_domain_before_destroy() {
    require_jq();
    let arch = std::env::consts::ARCH;
    assert!(arch == "x86_64" || arch == "aarch64");

    let dir = private_tempdir();
    let bin = dir.path().join("bin");
    let sys_root = dir.path().join("sys-root");
    create_private_dir(&bin);
    create_private_dir(&sys_root);
    std::fs::set_permissions(&sys_root, std::fs::Permissions::from_mode(0o755)).unwrap();

    let binary = dir.path().join("qeminga-bin");
    std::fs::write(&binary, b"fake release binary\n").unwrap();
    let candidate = dir.path().join("candidate");
    let m = lane(&[
        "manifest",
        "--out",
        candidate.to_str().unwrap(),
        "--binary",
        binary.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "105",
        "--run-attempt",
        "1",
        "--runner",
        "test-runner",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    let digest = sha256_hex(&candidate.join("qeminga"));
    let img_key = lane(&["image-key", arch]);
    assert!(img_key.status.success(), "{}", text(&img_key));
    let pinned_image_sha = String::from_utf8(img_key.stdout)
        .unwrap()
        .trim()
        .rsplit('-')
        .next()
        .unwrap()
        .to_string();
    let caller_grp_num = String::from_utf8(
        Command::new("/usr/bin/id")
            .arg("-g")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let qemu_user_spec = "+64055";
    let qemu_group_spec = format!("+{caller_grp_num}");
    let acls_can_name_test_uids = uid_is_mapped(64055) && uid_is_mapped(64099);
    let disable_acl_flag = if acls_can_name_test_uids { "0" } else { "1" };

    write_exec(
        &bin.join("virsh"),
        r#"#!/bin/sh
case "$1" in --connect=*) shift ;; esac
if [ -n "${FAKE_VIRSH_LOG:-}" ]; then printf '%s\n' "$*" >> "$FAKE_VIRSH_LOG"; fi
case "$1" in
    version) echo "Compiled against library: libvirt 10.0.0"; exit 0 ;;
    capabilities) exit 0 ;;
    domcapabilities) echo "<domainCapabilities/>"; exit 0 ;;
    net-info) echo "Active:         yes"; exit 0 ;;
    list)
        if [ -n "${FAKE_DOM_STATE_FILE:-}" ] && [ -f "$FAKE_DOM_STATE_FILE" ]; then
            st="$(cat "$FAKE_DOM_STATE_FILE")"
            if [ "$st" != "absent" ]; then printf '%s\n' "${FAKE_DOM_NAME:-}"; fi
        fi
        exit 0
        ;;
    domstate)
        if [ -n "${FAKE_DOM_STATE_FILE:-}" ] && [ -f "$FAKE_DOM_STATE_FILE" ]; then
            st="$(cat "$FAKE_DOM_STATE_FILE")"
            if [ "$st" != "absent" ]; then echo "$st"; exit 0; fi
        fi
        echo "error: failed to get domain '$2'" >&2; exit 1
        ;;
    dumpxml)
        if [ -n "${FAKE_DUMPXML_CONTENT:-}" ]; then
            printf '%s\n' "$FAKE_DUMPXML_CONTENT"
            exit 0
        fi
        exit 1
        ;;
    destroy)
        if [ -n "${FAKE_DOM_STATE_FILE:-}" ]; then echo "shut off" > "$FAKE_DOM_STATE_FILE"; fi
        exit 0
        ;;
    undefine)
        if [ -n "${FAKE_DOM_STATE_FILE:-}" ]; then echo "absent" > "$FAKE_DOM_STATE_FILE"; fi
        exit 0
        ;;
    define) exit 0 ;;
    start)
        if [ -n "${FAKE_PLANT_SERIAL_CONTENT:-}" ]; then
            printf '%s\n' "${FAKE_PLANT_SERIAL_CONTENT}" > "${FAKE_PLANT_SERIAL_DEST:?}"
        fi
        exit 42
        ;;
    *) exit 0 ;;
esac
"#,
    );
    write_exec(&bin.join("qemu-img"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("genisoimage"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -output) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$out" ] && : > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join(format!("qemu-system-{arch}")),
        "#!/bin/sh\necho 'QEMU emulator version 8.2.2'\n",
    );
    write_exec(
        &bin.join("curl"),
        r#"#!/bin/sh
out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
printf 'fake qcow2 bytes\n' > "$out"
exit 0
"#,
    );
    write_exec(
        &bin.join("sha256sum"),
        r#"#!/bin/sh
case "$1" in
    *.qcow2.part) printf '%s  %s\n' "${FAKE_IMAGE_SHA:?}" "$1"; exit 0 ;;
esac
exec /usr/bin/sha256sum "$@"
"#,
    );
    write_exec(&bin.join("chown"), "#!/bin/sh\nexit 0\n");
    write_exec(
        &bin.join("df"),
        "#!/bin/sh\nprintf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/mock 99999999 0 99999999 0%% /\\n'\n",
    );
    write_exec(
        &bin.join("id"),
        r#"#!/bin/sh
if [ "$1" = "-u" ] && [ -z "${2:-}" ]; then echo "0"; exit 0; fi
exec /usr/bin/id "$@"
"#,
    );
    let aavmf_code = dir.path().join("AAVMF_CODE.fd");
    let aavmf_vars = dir.path().join("AAVMF_VARS.fd");
    std::fs::write(&aavmf_code, b"code").unwrap();
    std::fs::write(&aavmf_vars, b"vars").unwrap();

    // 1. Evidence destination protection:
    //    - Pre-existing private `0600` file in OUT MUST keep mode `0600` (no `chmod -R a+rX`!).
    //    - Pre-existing hard-linked `serial.log`, `domain.xml`, and `qemu.log` MUST NEVER have
    //      their shared victim inodes truncated or chmodded!
    let good_images = sys_root.join("trusted-ev-images");
    let qemu_log_dir = sys_root.join("qemu-logs");
    create_private_dir(&qemu_log_dir);
    let run_name = format!("qeminga-e2e-105-1-{arch}");
    let run_dir = good_images.join(&run_name);
    let qlog_file = qemu_log_dir.join(format!("{run_name}.log"));
    std::fs::write(&qlog_file, b"QEMU_LOG_LINE\n").unwrap();

    let out_ev = sys_root.join("out-evidence");
    create_private_dir(&out_ev);
    std::fs::set_permissions(&out_ev, std::fs::Permissions::from_mode(0o755)).unwrap();
    let unrelated_priv = out_ev.join("unrelated.key");
    std::fs::write(&unrelated_priv, b"PRIVATE_KEY_MATERIAL\n").unwrap();
    std::fs::set_permissions(&unrelated_priv, std::fs::Permissions::from_mode(0o600)).unwrap();

    let victim_dir = sys_root.join("victims");
    create_private_dir(&victim_dir);
    let victim_serial = victim_dir.join("victim-serial.txt");
    let victim_dom = victim_dir.join("victim-dom.txt");
    let victim_qemu = victim_dir.join("victim-qemu.txt");
    for (v, orig, dest_name) in [
        (&victim_serial, "ORIGINAL_SERIAL\n", "serial.log"),
        (&victim_dom, "ORIGINAL_DOM\n", "domain.xml"),
        (&victim_qemu, "ORIGINAL_QEMU\n", "qemu.log"),
    ] {
        std::fs::write(v, orig).unwrap();
        std::fs::set_permissions(v, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(v, out_ev.join(dest_name)).unwrap();
    }

    let matching_xml = format!(
        "<domain type='kvm'><name>{run_name}</name><devices><disk type='file'><source file='{}/root.qcow2'/></disk><serial type='file'><source path='{}/serial.log'/></serial></devices></domain>",
        run_dir.display(),
        run_dir.display()
    );
    let run_ev = lane_env(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "105",
            "--run-attempt",
            "1",
            "--out",
            out_ev.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_E2E_QEMU_LOG_DIR", qemu_log_dir.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("QEMINGA_TEST_DISABLE_ACL", disable_acl_flag),
            ("QEMINGA_E2E_QEMU_USER", qemu_user_spec),
            ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
            ("FAKE_DUMPXML_CONTENT", &matching_xml),
            ("FAKE_PLANT_SERIAL_CONTENT", "FRESH_SERIAL_OUTPUT"),
            (
                "FAKE_PLANT_SERIAL_DEST",
                run_dir.join("serial.log").to_str().unwrap(),
            ),
        ],
        Some(&bin),
    );
    assert!(!run_ev.status.success(), "{}", text(&run_ev));
    assert_eq!(
        std::fs::metadata(&unrelated_priv)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "system-mode diagnostics MUST NOT chmod unrelated pre-existing files in OUT"
    );
    for (v, expected_orig, dest_name, expected_new) in [
        (
            &victim_serial,
            "ORIGINAL_SERIAL",
            "serial.log",
            "FRESH_SERIAL_OUTPUT",
        ),
        (&victim_dom, "ORIGINAL_DOM", "domain.xml", "<domain"),
        (&victim_qemu, "ORIGINAL_QEMU", "qemu.log", "QEMU_LOG_LINE"),
    ] {
        assert_eq!(
            std::fs::read_to_string(v).unwrap().trim(),
            expected_orig,
            "hard-linked victim for {dest_name} MUST NOT be truncated or overwritten"
        );
        assert_eq!(
            std::fs::metadata(v).unwrap().permissions().mode() & 0o777,
            0o600,
            "hard-linked victim for {dest_name} MUST keep original 0600 permissions"
        );
        let published = std::fs::read_to_string(out_ev.join(dest_name)).unwrap_or_default();
        assert!(
            published.contains(expected_new),
            "published {dest_name} should contain {expected_new:?}, got:\n{published}"
        );
        assert_eq!(
            std::fs::metadata(out_ev.join(dest_name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644,
            "newly published {dest_name} should be 0644"
        );
    }

    // Untrusted/shared-writable OUT dir (0777 ancestor) MUST be refused!
    let bad_out_parent = sys_root.join("shared-out-0777");
    create_private_dir(&bad_out_parent);
    std::fs::set_permissions(&bad_out_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
    let bad_out = bad_out_parent.join("evidence");
    let run_bad_out = lane_env(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            candidate.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "106",
            "--run-attempt",
            "1",
            "--out",
            bad_out.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("QEMINGA_TEST_DISABLE_ACL", disable_acl_flag),
            ("QEMINGA_E2E_QEMU_USER", qemu_user_spec),
            ("QEMINGA_E2E_QEMU_GROUP", &qemu_group_spec),
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_AAVMF_CODE", aavmf_code.to_str().unwrap()),
            ("QEMINGA_AAVMF_VARS", aavmf_vars.to_str().unwrap()),
            ("FAKE_IMAGE_SHA", &pinned_image_sha),
        ],
        Some(&bin),
    );
    assert!(
        !run_bad_out.status.success() && !bad_out.exists(),
        "system-mode run MUST refuse shared-writable OUT directory before writing evidence: {}",
        text(&run_bad_out)
    );

    // 2. Domain verification BEFORE destructive `virsh destroy` / `undefine` in `cmd_cleanup`:
    let virsh_log = dir.path().join("cleanup-virsh.log");
    let dom_state_file = dir.path().join("dom.state");

    // 2a: Rejected image root (0777 ancestor) with a RUNNING domain -> MUST fail BEFORE destroy/undefine!
    let bad_img_root = bad_out_parent.join("images");
    let bad_run_dir = bad_img_root.join(&run_name);
    std::fs::create_dir_all(&bad_run_dir).unwrap();
    let bad_keep = bad_run_dir.join("keep.dat");
    std::fs::write(&bad_keep, b"keep").unwrap();
    std::fs::write(&dom_state_file, "running\n").unwrap();
    let _ = std::fs::remove_file(&virsh_log);
    let clean_bad_root = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "105",
            "--run-attempt",
            "1",
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", bad_img_root.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("FAKE_DOM_STATE_FILE", dom_state_file.to_str().unwrap()),
            ("FAKE_DOM_NAME", &run_name),
            ("FAKE_DUMPXML_CONTENT", &matching_xml),
        ],
        Some(&bin),
    );
    let vlog_bad = std::fs::read_to_string(&virsh_log).unwrap_or_default();
    assert!(
        !clean_bad_root.status.success()
            && !vlog_bad.contains("destroy")
            && !vlog_bad.contains("undefine")
            && std::fs::read_to_string(&dom_state_file).unwrap().trim() == "running"
            && bad_keep.is_file(),
        "cleanup MUST refuse rejected image root BEFORE destroying/undefining domain (virsh_log:\n{vlog_bad}): {}",
        text(&clean_bad_root)
    );

    // 2b: Trusted image root, RUNNING domain whose XML points to an UNRELATED disk -> MUST fail
    //     BEFORE destroy/undefine and leave BOTH domain and storage intact!
    let unrelated_xml = format!(
        "<domain type='kvm'><name>{run_name}</name><devices><disk type='file'><source file='/var/lib/libvirt/images/unrelated-prod/root.qcow2'/></disk></devices></domain>"
    );
    std::fs::write(&dom_state_file, "running\n").unwrap();
    let _ = std::fs::remove_file(&virsh_log);
    let clean_mismatch = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "105",
            "--run-attempt",
            "1",
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("FAKE_DOM_STATE_FILE", dom_state_file.to_str().unwrap()),
            ("FAKE_DOM_NAME", &run_name),
            ("FAKE_DUMPXML_CONTENT", &unrelated_xml),
        ],
        Some(&bin),
    );
    let vlog_mis = std::fs::read_to_string(&virsh_log).unwrap_or_default();
    assert!(
        !clean_mismatch.status.success()
            && !vlog_mis.contains("destroy")
            && !vlog_mis.contains("undefine")
            && std::fs::read_to_string(&dom_state_file).unwrap().trim() == "running"
            && run_dir.is_dir(),
        "cleanup MUST refuse domain whose XML disk source does not match expected run dir (virsh_log:\n{vlog_mis}): {}",
        text(&clean_mismatch)
    );

    // 2b-ii: Domain with a non-file block disk attached alongside run root.qcow2 -> MUST fail
    //        BEFORE destroy/undefine!
    let block_disk_xml = format!(
        "<domain type='kvm'><name>{run_name}</name><devices><disk type='file'><source file='{}/root.qcow2'/></disk><disk type='block'><source dev='/dev/nvme0n1'/></disk></devices></domain>",
        run_dir.display()
    );
    std::fs::write(&dom_state_file, "running\n").unwrap();
    let _ = std::fs::remove_file(&virsh_log);
    let clean_block = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "105",
            "--run-attempt",
            "1",
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("FAKE_DOM_STATE_FILE", dom_state_file.to_str().unwrap()),
            ("FAKE_DOM_NAME", &run_name),
            ("FAKE_DUMPXML_CONTENT", &block_disk_xml),
        ],
        Some(&bin),
    );
    let vlog_blk = std::fs::read_to_string(&virsh_log).unwrap_or_default();
    assert!(
        !clean_block.status.success()
            && !vlog_blk.contains("destroy")
            && !vlog_blk.contains("undefine")
            && std::fs::read_to_string(&dom_state_file).unwrap().trim() == "running"
            && run_dir.is_dir(),
        "cleanup MUST refuse domain with non-file block disk BEFORE destroy/undefine (virsh_log:\n{vlog_blk}): {}",
        text(&clean_block)
    );

    // 2b-iii: Shared-writable --out on cmd_cleanup -> MUST fail closed before touching virsh or run_dir!
    let bad_clean_out = bad_out_parent.join("clean-evidence");
    std::fs::write(&dom_state_file, "running\n").unwrap();
    let _ = std::fs::remove_file(&virsh_log);
    let clean_bad_out = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "105",
            "--run-attempt",
            "1",
            "--out",
            bad_clean_out.to_str().unwrap(),
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("FAKE_DOM_STATE_FILE", dom_state_file.to_str().unwrap()),
            ("FAKE_DOM_NAME", &run_name),
            ("FAKE_DUMPXML_CONTENT", &matching_xml),
        ],
        Some(&bin),
    );
    let vlog_cout = std::fs::read_to_string(&virsh_log).unwrap_or_default();
    assert!(
        !clean_bad_out.status.success()
            && !bad_clean_out.exists()
            && !vlog_cout.contains("destroy")
            && !vlog_cout.contains("undefine")
            && run_dir.is_dir(),
        "cleanup MUST refuse shared-writable --out BEFORE touching virsh or run dir: {}",
        text(&clean_bad_out)
    );

    // 2c: Trusted image root AND matching XML -> destroys, undefines, and removes run_dir cleanly!
    std::fs::write(&dom_state_file, "running\n").unwrap();
    let _ = std::fs::remove_file(&virsh_log);
    let clean_match = lane_env(
        &[
            "cleanup",
            "--arch",
            arch,
            "--run-id",
            "105",
            "--run-attempt",
            "1",
        ],
        &[
            ("QEMINGA_E2E_CONNECT", "qemu:///system"),
            ("QEMINGA_E2E_IMAGES", good_images.to_str().unwrap()),
            ("QEMINGA_TEST_SYSFS_ROOT", sys_root.to_str().unwrap()),
            ("FAKE_VIRSH_LOG", virsh_log.to_str().unwrap()),
            ("FAKE_DOM_STATE_FILE", dom_state_file.to_str().unwrap()),
            ("FAKE_DOM_NAME", &run_name),
            ("FAKE_DUMPXML_CONTENT", &matching_xml),
        ],
        Some(&bin),
    );
    let vlog_ok = std::fs::read_to_string(&virsh_log).unwrap_or_default();
    assert!(
        clean_match.status.success()
            && vlog_ok.contains("destroy")
            && vlog_ok.contains("undefine")
            && !run_dir.exists(),
        "cleanup with trusted image root and matching domain XML should destroy, undefine, and remove run dir (virsh_log:\n{vlog_ok}): {}",
        text(&clean_match)
    );
    assert!(
        !root().join("scripts/ci/__pycache__").exists(),
        "libvirt-kvm-smoke.sh must invoke python3 with -B so scripts/ci/__pycache__ is never created"
    );
}

// ---- result contract ------------------------------------------------------

const MANDATORY: [&str; 4] = [
    "production_install",
    "accelerator_kvm",
    "libvirt_interop",
    "agent_shutdown",
];

fn result(tests: &[(&str, &str)], accelerator: &str) -> (bool, serde_json::Value) {
    require_jq();
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("tests")).unwrap();
    for (name, status) in tests {
        std::fs::write(dir.path().join("tests").join(name), status).unwrap();
    }
    let output = lane(&[
        "result",
        "--out",
        dir.path().to_str().unwrap(),
        "--arch",
        "aarch64",
        "--source-sha",
        SHA,
        "--binary-sha256",
        &"a".repeat(64),
        "--accelerator",
        accelerator,
    ]);
    let json = serde_json::from_slice(&std::fs::read(dir.path().join("result.json")).unwrap())
        .unwrap_or_else(|e| panic!("{e}: {}", text(&output)));
    (output.status.success(), json)
}

#[test]
fn passing_result_requires_kvm_accelerator_and_all_mandatory_tests() {
    let all: Vec<(&str, &str)> = MANDATORY.iter().map(|t| (*t, "pass")).collect();
    let (ok, json) = result(&all, "kvm");
    assert!(ok);
    assert_eq!(json["schema"], 1);
    assert_eq!(json["suite"], "libvirt-kvm-smoke-v1");
    assert_eq!(json["virtualization"]["hypervisor"], "qemu");
    assert_eq!(json["virtualization"]["accelerator"], "kvm");
    assert_eq!(json["virtualization"]["machine"], "virt");
    assert_eq!(json["result"], "pass");
    for t in MANDATORY {
        assert_eq!(json["tests"][t], "pass", "{t}");
    }

    // A TCG fallback must NEVER pass the KVM lane.
    let (ok, json) = result(&all, "tcg");
    assert!(!ok);
    assert_eq!(json["result"], "fail");

    // Any missing or failed mandatory test fails closed.
    for skip in MANDATORY {
        let partial: Vec<(&str, &str)> = MANDATORY
            .iter()
            .filter(|t| **t != skip)
            .map(|t| (*t, "pass"))
            .collect();
        let (ok, json) = result(&partial, "kvm");
        assert!(!ok, "{skip} missing");
        assert_eq!(json["tests"][skip], "not_run");
        assert_eq!(json["result"], "fail");
    }
}

// ---- workflow security & shape --------------------------------------------

fn caller() -> String {
    std::fs::read_to_string(root().join(".github/workflows/libvirt-kvm.yml")).unwrap()
}

fn lane_workflow() -> String {
    std::fs::read_to_string(root().join(".github/workflows/libvirt-kvm-lane.yml")).unwrap()
}

fn job<'a>(text: &'a str, name: &str) -> &'a str {
    let key = format!("\n  {name}:\n");
    let start = text.find(&key).unwrap_or_else(|| panic!("no job {name}")) + 1;
    let rest = &text[start + key.len() - 1..];
    let end = rest
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .find(|&i| {
            let line = &rest[i..];
            line.starts_with("  ")
                && !line.starts_with("   ")
                && !line.trim_start().starts_with('#')
                && line
                    .lines()
                    .next()
                    .is_some_and(|l| l.trim_end().ends_with(':'))
        })
        .unwrap_or(rest.len());
    &text[start..start + key.len() - 1 + end]
}

#[test]
fn kvm_workflow_never_triggers_on_pull_requests_and_supports_both_arches() {
    let text = caller();
    // Self-hosted runners on a public repository must NEVER run on pull_request events.
    assert!(text.contains("workflow_dispatch:"), "{text}");
    for forbidden_trigger in ["pull_request:", "pull_request_target:", "issue_comment:"] {
        assert!(
            !text.contains(forbidden_trigger),
            "forbidden trigger {forbidden_trigger} in libvirt-kvm.yml"
        );
    }
    assert!(text.contains("permissions:\n  contents: read"), "{text}");
    // Never accept a user-controlled ref/SHA input in workflow_dispatch: checking out an
    // arbitrary SHA in the default branch context risks cache poisoning (CodeQL) and could
    // check out a commit outside the donor runner's ALLOWED_REFS allowlist.
    assert!(
        !text.contains("source_sha:"),
        "libvirt-kvm.yml must not accept a user-controlled source_sha input:\n{text}"
    );
    // Resolve one vetted vicaya/qeminga commit once (works both from a private controller
    // repository via qeminga-target.rev / vicaya/qeminga main and from vicaya/qeminga itself).
    let resolve = job(&text, "resolve");
    assert!(resolve.contains("target_rev:"), "{resolve}");
    assert!(resolve.contains("vicaya/qeminga"), "{resolve}");
    assert!(resolve.contains("qeminga-target.rev"), "{resolve}");
    assert!(resolve.contains("persist-credentials: false"), "{resolve}");

    let lane = lane_workflow();
    assert!(
        !lane.contains("source_sha:"),
        "libvirt-kvm-lane.yml must not accept a source_sha input:\n{lane}"
    );
    assert!(
        lane.contains("target_rev:"),
        "libvirt-kvm-lane.yml must accept the resolved target_rev:\n{lane}"
    );
    // Caller must NEVER control the hosted build runner or runner_arch labels.
    assert!(
        !lane.contains("build_runner:"),
        "libvirt-kvm-lane.yml must derive build runner from arch, never accept build_runner input:\n{lane}"
    );
    assert!(
        !lane.contains("runner_arch:"),
        "libvirt-kvm-lane.yml must derive runner_arch from arch, never accept runner_arch input:\n{lane}"
    );

    for arch in ["x86_64", "aarch64"] {
        let j = job(&text, arch);
        assert!(j.contains("needs: resolve"), "{arch}");
        assert!(
            j.contains("uses: ./.github/workflows/libvirt-kvm-lane.yml"),
            "{arch}"
        );
        assert!(j.contains(&format!("arch: {arch}\n")), "{arch}");
        assert!(
            j.contains("target_rev: ${{ needs.resolve.outputs.target_rev }}\n"),
            "{arch}"
        );
        assert!(
            !j.contains("build_runner:") && !j.contains("runner_arch:"),
            "{arch}: caller must not pass build_runner or runner_arch to reusable lane:\n{j}"
        );
    }
    assert!(
        !text.contains("strategy:") && !lane.contains("strategy:"),
        "no matrix couples x86_64 and aarch64"
    );
}

#[test]
fn kvm_lane_builds_on_hosted_runner_and_tests_unprivileged_on_self_hosted_kvm_runner() {
    let text = lane_workflow();
    assert!(text.contains("workflow_call:"));
    assert!(text.contains("permissions:\n  contents: read"));

    // Fixed hosted verify gate enforces caller workflow, event, ref, arch, and
    // commit reachability from vicaya/qeminga's protected main branch BEFORE
    // scheduling candidate or self-hosted kvm jobs.
    let verify = job(&text, "verify");
    assert!(
        verify.contains("runs-on: ubuntu-24.04\n"),
        "verify gate must run on fixed GitHub-hosted ubuntu-24.04:\n{verify}"
    );
    assert!(
        verify.contains("github.event_name == 'workflow_dispatch'"),
        "verify gate must restrict event to workflow_dispatch:\n{verify}"
    );
    assert!(
        verify.contains("github.ref == 'refs/heads/main'"),
        "verify gate must restrict ref to refs/heads/main:\n{verify}"
    );
    assert!(
        verify.contains(".github/workflows/libvirt-kvm.yml"),
        "verify gate must restrict caller workflow to libvirt-kvm.yml:\n{verify}"
    );
    assert!(
        verify.contains("merge-base --is-ancestor \"$TARGET_REV\" FETCH_HEAD"),
        "verify gate must prove target_rev is reachable from vicaya/qeminga main:\n{verify}"
    );
    assert!(
        verify.contains("https://github.com/vicaya/qeminga.git")
            && verify.contains("refs/heads/main"),
        "verify gate must check ancestry against vicaya/qeminga refs/heads/main:\n{verify}"
    );

    let build = job(&text, "candidate");
    assert!(build.contains("needs: verify"), "{build}");
    assert!(
        build.contains(
            "runs-on: ${{ inputs.arch == 'x86_64' && 'ubuntu-24.04' || 'ubuntu-24.04-arm' }}"
        ),
        "candidate must derive hosted build runner from a fixed architecture mapping:\n{build}"
    );
    assert!(
        build.contains("github.event_name == 'workflow_dispatch'")
            && build.contains("github.ref == 'refs/heads/main'"),
        "candidate must repeat caller/event/ref guard:\n{build}"
    );
    assert!(build.contains("repository: vicaya/qeminga"));
    assert!(build.contains("ref: ${{ needs.verify.outputs.target_rev }}"));
    assert!(build.contains("cargo build --release --locked --features seccomp\n"));
    assert!(build.contains("sha256: ${{ steps.digest.outputs.sha256 }}"));
    assert!(build.contains("persist-credentials: false"));
    assert!(
        build.contains(r#"test "$(git rev-parse HEAD)" = "$TARGET_REV""#),
        "candidate must verify checked-out commit equals target_rev:\n{build}"
    );
    assert!(
        build.contains(r#"--source-sha "$TARGET_REV""#),
        "candidate must stamp manifest with the vetted vicaya/qeminga TARGET_REV:\n{build}"
    );
    for forbidden in ["--all-features", "test-fakes", "seccomp-log"] {
        assert!(!build.contains(forbidden), "candidate: {forbidden}");
    }

    let kvm = job(&text, "kvm");
    assert!(kvm.contains("needs: [verify, candidate]"), "{kvm}");
    assert!(
        kvm.contains(
            r#"runs-on: [self-hosted, linux, "${{ inputs.arch == 'x86_64' && 'X64' || 'ARM64' }}", qeminga-kvm]"#
        ),
        "kvm must derive runner_arch from a fixed architecture mapping:\n{kvm}"
    );
    assert!(
        kvm.contains("github.event_name == 'workflow_dispatch'")
            && kvm.contains("github.ref == 'refs/heads/main'"),
        "kvm must repeat caller/event/ref guard:\n{kvm}"
    );
    assert!(kvm.contains("repository: vicaya/qeminga"));
    assert!(kvm.contains("ref: ${{ needs.verify.outputs.target_rev }}"));
    assert!(kvm.contains("cancel-in-progress: false"));
    assert!(kvm.contains("timeout-minutes:"));
    assert!(kvm.contains("persist-credentials: false"));
    assert!(kvm.contains(r#"test "$(uname -m)" = "$ARCH""#));
    assert!(kvm.contains(r#"EXPECTED_RUNNER_ARCH: ${{ needs.verify.outputs.expected_arch }}"#));
    assert!(kvm.contains(r#"test "$RUNNER_ARCH" = "$EXPECTED_RUNNER_ARCH""#));
    assert!(
        kvm.contains(r#"test "$(git rev-parse HEAD)" = "$TARGET_REV""#),
        "kvm job must verify checked-out commit equals target_rev:\n{kvm}"
    );
    assert!(
        kvm.contains(r#"--source-sha "$TARGET_REV""#),
        "kvm job must verify candidate against the vetted vicaya/qeminga TARGET_REV:\n{kvm}"
    );
    assert!(kvm.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#));
    assert!(kvm.contains("libvirt-kvm-smoke.sh run"));
    assert!(kvm.contains("libvirt-kvm-smoke.sh cleanup"));
    assert!(!kvm.contains("continue-on-error"));

    // The self-hosted KVM runner must NEVER need sudo, apt-get, cargo, or rustup.
    for forbidden in ["sudo ", "apt-get", "cargo ", "rustup"] {
        assert!(
            !kvm.contains(forbidden),
            "self-hosted kvm job must not use {forbidden:?}:\n{kvm}"
        );
    }

    // Cleanup and artifact upload run even on failure.
    let cleanup_idx = kvm.find("libvirt-kvm-smoke.sh cleanup").unwrap();
    let cleanup_step = &kvm[kvm[..cleanup_idx].rfind("- name:").unwrap()..cleanup_idx];
    assert!(cleanup_step.contains("if: always()"), "{cleanup_step}");
    let upload_idx = kvm.find("actions/upload-artifact").unwrap();
    let upload_step = &kvm[kvm[..upload_idx].rfind("- name:").unwrap()..upload_idx];
    assert!(upload_step.contains("if: always()"), "{upload_step}");

    // Validate strict YAML syntax for all KVM workflow files when Ruby Psych is installed.
    let has_ruby = Command::new("ruby")
        .args(["-ryaml", "-e", "exit 0"])
        .output()
        .is_ok_and(|o| o.status.success());
    if has_ruby {
        for rel in [
            ".github/workflows/libvirt-kvm.yml",
            ".github/workflows/libvirt-kvm-lane.yml",
            ".github/workflows/libvirt-kvm-hosted.yml",
        ] {
            let path = root().join(rel);
            let out = Command::new("ruby")
                .args(["-ryaml", "-e", "YAML.load_file(ARGV[0])"])
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "invalid YAML in {rel}:\n{}",
                self::text(&out)
            );
        }
    }
}

fn hosted_workflow() -> String {
    let path = root().join(".github/workflows/libvirt-kvm-hosted.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn hosted_amd64_kvm_workflow_enables_dev_kvm_via_udev_and_runs_unprivileged_session_kvm() {
    let text = hosted_workflow();

    // Runs automatically on pushes to main, pull requests, and manual dispatch
    // because GitHub-hosted ubuntu-24.04 runners are ephemeral.
    assert!(text.contains("push:\n    branches: [main]"), "{text}");
    assert!(text.contains("pull_request:"), "{text}");
    assert!(text.contains("workflow_dispatch:"), "{text}");
    assert!(text.contains("permissions:\n  contents: read"), "{text}");
    assert!(
        text.contains("cancel-in-progress: ${{ github.event_name == 'pull_request' }}"),
        "{text}"
    );
    assert!(
        !text.contains("self-hosted"),
        "hosted workflow must never target self-hosted runners:\n{text}"
    );

    // Gated on docs-only change classification just like ci.yml and libvirt-tcg.yml.
    let changes = job(&text, "changes");
    assert!(changes.contains("runs-on: ubuntu-24.04\n"), "{changes}");
    assert!(changes.contains("persist-credentials: false"), "{changes}");
    assert!(changes.contains("scripts/ci/docs-only.sh"), "{changes}");

    // Candidate build job: native x86_64, production features only, digest anchored.
    let build = job(&text, "candidate");
    assert!(build.contains("needs: changes"), "{build}");
    assert!(
        build.contains("if: needs.changes.outputs.code == 'true'"),
        "{build}"
    );
    assert!(build.contains("runs-on: ubuntu-24.04\n"), "{build}");
    assert!(build.contains("timeout-minutes:"), "{build}");
    assert!(!build.contains("continue-on-error"), "{build}");
    assert!(build.contains("persist-credentials: false"), "{build}");
    assert!(
        build.contains(r#"test "$(uname -m)" = "x86_64""#),
        "{build}"
    );
    assert!(build.contains(r#"test "$RUNNER_ARCH" = "X64""#), "{build}");
    assert!(
        build.contains(r#"rustc -vV | grep -qx "host: x86_64-unknown-linux-gnu""#),
        "{build}"
    );
    assert!(build.contains("cargo build --release --locked --features seccomp\n"));
    assert!(build.contains("sha256: ${{ steps.digest.outputs.sha256 }}"));
    assert!(build.contains("sha256sum target/release/qeminga"));
    assert!(build.contains("scripts/ci/libvirt-kvm-smoke.sh manifest"));
    for forbidden in ["--all-features", "test-fakes", "seccomp-log"] {
        assert!(!build.contains(forbidden), "candidate: {forbidden}");
    }

    // Hosted KVM smoke job: native ubuntu-24.04, fail-fast udev workaround for /dev/kvm,
    // minimal session packages, unprivileged qemu:///session run, always() cleanup & upload.
    let smoke = job(&text, "smoke");
    assert!(smoke.contains("needs: candidate"), "{smoke}");
    assert!(smoke.contains("runs-on: ubuntu-24.04\n"), "{smoke}");
    assert!(smoke.contains("timeout-minutes:"), "{smoke}");
    assert!(!smoke.contains("continue-on-error"), "{smoke}");
    assert!(smoke.contains("persist-credentials: false"), "{smoke}");
    assert!(
        smoke.contains(r#"test "$(uname -m)" = "x86_64""#),
        "{smoke}"
    );
    assert!(smoke.contains(r#"test "$RUNNER_ARCH" = "X64""#), "{smoke}");
    assert!(
        smoke.contains("QEMINGA_E2E_CONNECT: qemu:///session"),
        "{smoke}"
    );
    for forbidden in ["cargo ", "rustup", "libvirt-daemon-system"] {
        assert!(
            !smoke.contains(forbidden),
            "hosted smoke job must not use {forbidden:?}:\n{smoke}"
        );
    }

    // The udev rule from GitHub's 2024-04-02 changelog / randax/talos-box#74 applies
    // MODE="0666" to the static /dev/kvm node; explicit mode checks before apt-get and
    // again inside libvirt-kvm-smoke.sh preflight detect any permissions regression.
    let udev_rule = r#"KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm""#;
    let udev_idx = smoke
        .find(udev_rule)
        .unwrap_or_else(|| panic!("missing 99-kvm4all.rules with static_node=kvm:\n{smoke}"));
    assert!(
        smoke.contains("/etc/udev/rules.d/99-kvm4all.rules"),
        "{smoke}"
    );
    assert!(smoke.contains("udevadm control --reload-rules"), "{smoke}");
    assert!(
        smoke.contains("udevadm trigger --name-match=kvm"),
        "{smoke}"
    );
    assert!(smoke.contains("udevadm settle"), "{smoke}");
    assert!(smoke.contains("test -c /dev/kvm"), "{smoke}");
    let rw_idx = smoke
        .find("test -r /dev/kvm && test -w /dev/kvm")
        .unwrap_or_else(|| panic!("missing fail-fast /dev/kvm rw check:\n{smoke}"));
    let apt_idx = smoke.find("apt-get install").unwrap();
    let run_idx = smoke.find("libvirt-kvm-smoke.sh run").unwrap();
    assert!(
        udev_idx < rw_idx && rw_idx < apt_idx && apt_idx < run_idx,
        "udev workaround and fail-fast /dev/kvm check must happen before apt-get and run"
    );

    // Minimal unprivileged session virtualization packages (no root libvirtd-system).
    for pkg in [
        "libvirt-daemon",
        "libvirt-daemon-driver-qemu",
        "libvirt-clients",
        "qemu-system-x86",
        "qemu-utils",
        "genisoimage",
    ] {
        assert!(smoke.contains(pkg), "missing package {pkg}:\n{smoke}");
    }

    // Guest image cached under a distinct key prefix so its path never collides with TCG's.
    assert!(
        smoke.contains("scripts/ci/libvirt-kvm-smoke.sh image-key"),
        "{smoke}"
    );
    assert!(smoke.contains("kvm-hosted-"), "{smoke}");
    assert!(smoke.contains("uses: actions/cache@"), "{smoke}");
    assert!(smoke.contains("--image-cache"), "{smoke}");

    // Binary digest anchored to build job output; smoke and cleanup run unprivileged (no sudo).
    assert!(
        smoke.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#),
        "{smoke}"
    );
    for line in smoke.lines().filter(|l| l.contains("libvirt-kvm-smoke.sh")) {
        assert!(
            !line.contains("sudo"),
            "hosted qemu:///session invocation must not use sudo: {line}"
        );
    }

    // Output directory must live under RUNNER_TEMP (outside the checkout) and
    // be exported via GITHUB_ENV in an early step — GitHub Actions disallows
    // the `runner` context inside job-level `env:`.
    let smoke_env_end = smoke.find("\n    steps:\n").unwrap();
    let smoke_job_header = &smoke[..smoke_env_end];
    assert!(
        !smoke_job_header.contains("${{ runner."),
        "job-level env must not reference runner.* context (invalid in GitHub Actions):\n{smoke_job_header}"
    );
    assert!(
        !smoke.contains("OUT: ${{ github.workspace }}"),
        "OUT must not live under github.workspace:\n{smoke}"
    );
    let out_step_idx = smoke
        .find(r#"out="${RUNNER_TEMP:?}/libvirt-kvm-hosted-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}""#)
        .unwrap_or_else(|| panic!("missing RUNNER_TEMP per-run OUT setup step:\n{smoke}"));
    assert!(
        smoke.contains(r#"echo "OUT=$out" >> "$GITHUB_ENV""#),
        "per-run OUT must be exported via GITHUB_ENV:\n{smoke}"
    );
    assert!(
        out_step_idx < udev_idx,
        "OUT must be prepared before the first fail-fast check so early failures still publish evidence"
    );

    // Cleanup, fallback failure-result generation (for early exits before `run` installs its
    // EXIT trap), summary, and artifact upload all run under `if: always()` in order.
    let cleanup_idx = smoke.find("libvirt-kvm-smoke.sh cleanup").unwrap();
    let cleanup_step = &smoke[smoke[..cleanup_idx].rfind("- name:").unwrap()..cleanup_idx];
    assert!(cleanup_step.contains("if: always()"), "{cleanup_step}");

    let fallback_idx = smoke
        .find("libvirt-kvm-smoke.sh ensure-result")
        .unwrap_or_else(|| {
            panic!("missing early-failure structured result.json ensure-result step:\n{smoke}")
        });
    let fallback_start = smoke[..fallback_idx].rfind("- name:").unwrap();
    let summary_idx = smoke.find("- name: Result summary").unwrap();
    let fallback_step = &smoke[fallback_start..summary_idx];
    assert!(fallback_step.contains("if: always()"), "{fallback_step}");
    assert!(fallback_step.contains(r#"--out "$OUT""#), "{fallback_step}");
    assert!(
        fallback_step.contains(r#"--arch "$ARCH""#),
        "{fallback_step}"
    );
    assert!(
        fallback_step.contains(r#"--source-sha "$GITHUB_SHA""#),
        "{fallback_step}"
    );
    assert!(
        fallback_step.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#),
        "fallback must bind any preserved pass record to the candidate digest:\n{fallback_step}"
    );

    let upload_idx = smoke.find("actions/upload-artifact").unwrap();
    let upload_step = &smoke[smoke[..upload_idx].rfind("- name:").unwrap()..upload_idx];
    assert!(upload_step.contains("if: always()"), "{upload_step}");

    // On an otherwise-green job path (no `if: always()`), explicitly require a
    // validated run-bound passing `result.json` AFTER upload so replacing
    // missing/invalid evidence with a failure record can never finish green.
    let verify_idx = smoke
        .find("libvirt-kvm-smoke.sh verify-pass")
        .unwrap_or_else(|| {
            panic!("missing success-path validated pass gate (verify-pass):\n{smoke}")
        });
    let verify_start = smoke[..verify_idx].rfind("- name:").unwrap();
    let verify_step = &smoke[verify_start..];
    assert!(
        !verify_step.contains("if: always()"),
        "verify-pass gate must run only on the success path (not if: always()):\n{verify_step}"
    );
    assert!(verify_step.contains(r#"--out "$OUT""#), "{verify_step}");
    assert!(verify_step.contains(r#"--arch "$ARCH""#), "{verify_step}");
    assert!(
        verify_step.contains(r#"--source-sha "$GITHUB_SHA""#),
        "{verify_step}"
    );
    assert!(
        verify_step.contains(r#"--expect-sha256 "${{ needs.candidate.outputs.sha256 }}""#),
        "{verify_step}"
    );

    assert!(
        cleanup_idx < fallback_idx
            && fallback_idx < summary_idx
            && summary_idx < upload_idx
            && upload_idx < verify_idx,
        "cleanup -> fallback result -> summary -> upload -> verify-pass ordering must hold"
    );
}

#[test]
fn write_result_propagates_publish_failure_in_exit_trap_context_and_cleans_temp() {
    require_jq();
    let digest = "a".repeat(64);
    let script_path = script();

    // Helper: invoke `write_result ... || rc=1` in a subshell where bash
    // disables `errexit` inside `write_result`, matching `cmd_run`'s EXIT trap.
    let run_trap_context = |out_dir: &Path, bin_override: Option<&Path>| {
        let mut cmd = Command::new("bash");
        cmd.args([
            "--noprofile",
            "--norc",
            "-euo",
            "pipefail",
            "-c",
            r#"body="$(sed -e 's|\${BASH_SOURCE\[0\]}|"$SCRIPT_PATH"|g' -e '/^# ---- dispatch/q' "$SCRIPT_PATH")"
eval "$body"
rc=0
write_result "$1" x86_64 "$2" "$3" kvm || rc=1
exit "$rc""#,
            "bash",
        ])
        .arg(out_dir)
        .arg(SHA)
        .arg(&digest)
        .env("SCRIPT_PATH", &script_path);
        if let Some(bin) = bin_override {
            let path = format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            );
            cmd.env("PATH", path);
        }
        cmd.output().unwrap()
    };

    // Case 1: all four mandatory checks passed, but `out/result.json` is an
    // existing directory. `mv -f -T` must fail, clean up its temporary file,
    // leave the directory empty, and return nonzero even under `|| rc=1`.
    let dir1 = private_tempdir();
    let out1 = dir1.path().join("out");
    std::fs::create_dir_all(out1.join("tests")).unwrap();
    for t in MANDATORY {
        std::fs::write(out1.join("tests").join(t), "pass\n").unwrap();
    }
    let blocking_dir = out1.join("result.json");
    std::fs::create_dir(&blocking_dir).unwrap();
    let res1 = run_trap_context(&out1, None);
    assert!(
        !res1.status.success(),
        "directory at result.json must fail write_result even when all checks pass: {}",
        text(&res1)
    );
    let leftovers1: Vec<String> = std::fs::read_dir(&out1)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".result.json.tmp"))
        .collect();
    assert!(
        leftovers1.is_empty(),
        "temp file must be cleaned up on mv failure: {leftovers1:?}"
    );
    assert_eq!(
        std::fs::read_dir(&blocking_dir).unwrap().count(),
        0,
        "mv -T must never move temp file inside an existing result.json directory"
    );

    // Case 2: `mv` fails with an I/O error after all four checks passed.
    let dir2 = private_tempdir();
    assert_eq!(
        std::fs::metadata(dir2.path()).unwrap().mode() & 0o777,
        0o700,
        "executable test-double root dir2 must be created 0700"
    );
    let out2 = dir2.path().join("out");
    std::fs::create_dir_all(out2.join("tests")).unwrap();
    for t in MANDATORY {
        std::fs::write(out2.join("tests").join(t), "pass\n").unwrap();
    }
    let fake_bin = dir2.path().join("bin");
    create_dir_mode(&fake_bin, 0o700);
    assert_eq!(
        std::fs::metadata(&fake_bin).unwrap().mode() & 0o777,
        0o700,
        "executable test-double bin dir must be created 0700"
    );
    write_exec(
        &fake_bin.join("mv"),
        "#!/bin/sh\necho 'mv: simulated rename failure' >&2\nexit 1\n",
    );
    let res2 = run_trap_context(&out2, Some(&fake_bin));
    assert!(
        !res2.status.success(),
        "failing mv must fail write_result in || rc=1 trap context: {}",
        text(&res2)
    );
    let leftovers2: Vec<String> = std::fs::read_dir(&out2)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".result.json.tmp"))
        .collect();
    assert!(
        leftovers2.is_empty(),
        "temp file must be cleaned up after mv error: {leftovers2:?}"
    );
    assert!(
        !out2.join("result.json").exists(),
        "result.json must not exist after failed mv"
    );

    // Case 3: `cat` fails after publishing when all four checks passed.
    let dir3 = private_tempdir();
    assert_eq!(
        std::fs::metadata(dir3.path()).unwrap().mode() & 0o777,
        0o700,
        "executable test-double root dir3 must be created 0700"
    );
    let out3 = dir3.path().join("out");
    std::fs::create_dir_all(out3.join("tests")).unwrap();
    for t in MANDATORY {
        std::fs::write(out3.join("tests").join(t), "pass\n").unwrap();
    }
    let fake_cat_bin = dir3.path().join("bin");
    create_dir_mode(&fake_cat_bin, 0o700);
    assert_eq!(
        std::fs::metadata(&fake_cat_bin).unwrap().mode() & 0o777,
        0o700,
        "executable test-double cat bin dir must be created 0700"
    );
    write_exec(
        &fake_cat_bin.join("cat"),
        "#!/bin/sh\necho 'cat: simulated read failure' >&2\nexit 1\n",
    );
    let res3 = run_trap_context(&out3, Some(&fake_cat_bin));
    assert!(
        !res3.status.success(),
        "failing cat must fail write_result in || rc=1 trap context: {}",
        text(&res3)
    );
}

#[test]
fn early_failure_fallback_writes_structured_fail_result_json() {
    require_jq();
    let sentinel = "0".repeat(64);
    let candidate_digest = "a".repeat(64);
    let other_digest = "b".repeat(64);
    let other_sha = SHA.replace('0', "f");

    // 1. Direct `result` subcommand exits non-zero (fail-closed) and publishes
    // result.json atomically via a temporary file + `mv -f -T`, leaving no temp files.
    let direct_dir = tempfile::tempdir().unwrap();
    let direct_out = direct_dir.path().join("out");
    std::fs::create_dir(&direct_out).unwrap();
    let output = lane(&[
        "result",
        "--out",
        direct_out.to_str().unwrap(),
        "--arch",
        "x86_64",
        "--source-sha",
        SHA,
        "--binary-sha256",
        &sentinel,
        "--accelerator",
        "unknown",
    ]);
    assert!(
        !output.status.success(),
        "fallback result must exit non-zero (fail-closed): {}",
        text(&output)
    );
    let entries: Vec<String> = std::fs::read_dir(&direct_out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(entries, vec!["result.json"], "no leftover temp files");
    let script_src = std::fs::read_to_string(script()).unwrap();
    let wr_start = script_src.find("write_result()").unwrap();
    let wr_end = script_src[wr_start..].find("\ncmd_result()").unwrap() + wr_start;
    let write_result_fn = &script_src[wr_start..wr_end];
    assert!(
        write_result_fn.contains("mv -f -T ")
            && !write_result_fn.contains(r#">"$out/result.json""#),
        "write_result must publish atomically via temp file + mv -f -T:\n{write_result_fn}"
    );

    // Helper: produce an authentic writer-generated `result.json` using the
    // script's own `result` subcommand.
    let write_real_result =
        |out: &Path, arch: &str, sha: &str, digest: &str, accel: &str, pass_all: bool| {
            std::fs::create_dir_all(out.join("tests")).unwrap();
            for t in MANDATORY {
                std::fs::write(
                    out.join("tests").join(t),
                    if pass_all { "pass\n" } else { "fail\n" },
                )
                .unwrap();
            }
            let r = lane(&[
                "result",
                "--out",
                out.to_str().unwrap(),
                "--arch",
                arch,
                "--source-sha",
                sha,
                "--binary-sha256",
                digest,
                "--accelerator",
                accel,
            ]);
            if pass_all && accel == "kvm" {
                assert!(r.status.success(), "{}", text(&r));
            } else {
                assert!(!r.status.success(), "{}", text(&r));
            }
        };

    // 2. Exercise `libvirt-kvm-smoke.sh ensure-result` and `verify-pass`
    // directly (no Ruby required) across missing, corrupt, concatenated,
    // forged, foreign-run, and valid writer-produced records.
    let cases = [
        ("missing", candidate_digest.as_str(), false),
        ("empty", candidate_digest.as_str(), false),
        ("truncated", candidate_digest.as_str(), false),
        ("two_field_pass", candidate_digest.as_str(), false),
        ("concatenated_pass", candidate_digest.as_str(), false),
        ("wrong_sha_pass", candidate_digest.as_str(), false),
        ("wrong_sha_fail", candidate_digest.as_str(), false),
        ("wrong_arch_pass", candidate_digest.as_str(), false),
        ("wrong_digest_pass", candidate_digest.as_str(), false),
        ("empty_expect_pass", "", false),
        ("forged_tcg_pass", candidate_digest.as_str(), false),
        ("forged_partial_pass", candidate_digest.as_str(), false),
        ("valid_pass", candidate_digest.as_str(), true),
        ("valid_fail", candidate_digest.as_str(), true),
    ];

    for (case, expect, preserve) in cases {
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("out");
        match case {
            "missing" => {}
            "empty" => {
                std::fs::create_dir(&out_dir).unwrap();
                std::fs::write(out_dir.join("result.json"), b"").unwrap();
            }
            "truncated" => {
                std::fs::create_dir(&out_dir).unwrap();
                std::fs::write(out_dir.join("result.json"), b"{\"schema\": 1, \"suite\":").unwrap();
            }
            "two_field_pass" => {
                std::fs::create_dir(&out_dir).unwrap();
                std::fs::write(
                    out_dir.join("result.json"),
                    r#"{"suite":"libvirt-kvm-smoke-v1","result":"pass"}"#,
                )
                .unwrap();
            }
            "concatenated_pass" => {
                write_real_result(&out_dir, "x86_64", SHA, &candidate_digest, "kvm", true);
                let valid = std::fs::read(out_dir.join("result.json")).unwrap();
                let mut two = Vec::from(&b"{\"stale\":true}\n"[..]);
                two.extend_from_slice(&valid);
                std::fs::write(out_dir.join("result.json"), two).unwrap();
            }
            "wrong_sha_pass" => {
                write_real_result(
                    &out_dir,
                    "x86_64",
                    &other_sha,
                    &candidate_digest,
                    "kvm",
                    true,
                );
            }
            "wrong_sha_fail" => {
                write_real_result(
                    &out_dir,
                    "x86_64",
                    &other_sha,
                    &candidate_digest,
                    "kvm",
                    false,
                );
            }
            "wrong_arch_pass" => {
                write_real_result(&out_dir, "aarch64", SHA, &candidate_digest, "kvm", true);
            }
            "wrong_digest_pass" => {
                write_real_result(&out_dir, "x86_64", SHA, &other_digest, "kvm", true);
            }
            "empty_expect_pass" => {
                write_real_result(&out_dir, "x86_64", SHA, &candidate_digest, "kvm", true);
            }
            "forged_tcg_pass" => {
                write_real_result(&out_dir, "x86_64", SHA, &candidate_digest, "kvm", true);
                let mut doc: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(out_dir.join("result.json")).unwrap())
                        .unwrap();
                doc["virtualization"]["accelerator"] = serde_json::json!("tcg");
                std::fs::write(
                    out_dir.join("result.json"),
                    serde_json::to_vec(&doc).unwrap(),
                )
                .unwrap();
            }
            "forged_partial_pass" => {
                write_real_result(&out_dir, "x86_64", SHA, &candidate_digest, "kvm", true);
                let mut doc: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(out_dir.join("result.json")).unwrap())
                        .unwrap();
                doc["tests"]["agent_shutdown"] = serde_json::json!("not_run");
                std::fs::write(
                    out_dir.join("result.json"),
                    serde_json::to_vec(&doc).unwrap(),
                )
                .unwrap();
            }
            "valid_pass" => {
                write_real_result(&out_dir, "x86_64", SHA, &candidate_digest, "kvm", true);
            }
            "valid_fail" => {
                write_real_result(&out_dir, "x86_64", SHA, &candidate_digest, "kvm", false);
            }
            _ => unreachable!(),
        }

        // Plant an unrelated diagnostic file under `out/tests/` when the
        // directory already exists: synthesizing a fallback result must NEVER
        // delete caller-owned files under `tests/`.
        let unrelated_path = out_dir.join("tests/keep-me.txt");
        if out_dir.exists() {
            std::fs::create_dir_all(out_dir.join("tests")).unwrap();
            std::fs::write(&unrelated_path, b"do not delete\n").unwrap();
        }

        // Before fallback, `verify-pass` succeeds ONLY for `valid_pass`.
        let pre_verify = lane(&[
            "verify-pass",
            "--out",
            out_dir.to_str().unwrap(),
            "--arch",
            "x86_64",
            "--source-sha",
            SHA,
            "--expect-sha256",
            expect,
        ]);
        if case == "valid_pass" {
            assert!(
                pre_verify.status.success(),
                "{case}: verify-pass must accept valid run-bound pass: {}",
                text(&pre_verify)
            );
        } else {
            assert!(
                !pre_verify.status.success(),
                "{case}: verify-pass must reject non-pass / invalid record: {}",
                text(&pre_verify)
            );
        }

        let before = std::fs::read(out_dir.join("result.json")).ok();
        let run = lane(&[
            "ensure-result",
            "--out",
            out_dir.to_str().unwrap(),
            "--arch",
            "x86_64",
            "--source-sha",
            SHA,
            "--expect-sha256",
            expect,
        ]);
        assert!(run.status.success(), "{case}: {}", text(&run));
        if before.is_some() {
            assert_eq!(
                std::fs::read(&unrelated_path).ok().as_deref(),
                Some(&b"do not delete\n"[..]),
                "{case}: ensure-result must preserve unrelated files under tests/"
            );
        }

        let after = std::fs::read(out_dir.join("result.json")).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&after)
            .unwrap_or_else(|e| panic!("{case}: invalid result.json: {e}: {}", text(&run)));
        if preserve {
            assert_eq!(
                Some(after),
                before,
                "{case}: valid run-bound record must be preserved untouched"
            );
            if case == "valid_pass" {
                assert_eq!(json["result"], "pass", "{case}");
                assert_eq!(json["candidate_binary_sha256"], candidate_digest, "{case}");
                assert_eq!(json["virtualization"]["accelerator"], "kvm", "{case}");
            } else {
                assert_eq!(json["result"], "fail", "{case}");
                assert_eq!(json["candidate_binary_sha256"], candidate_digest, "{case}");
                assert_eq!(json["tests"]["production_install"], "fail", "{case}");
            }
        } else {
            assert_eq!(json["schema"], 1, "{case}");
            assert_eq!(json["suite"], "libvirt-kvm-smoke-v1", "{case}");
            assert_eq!(json["source_repository"], "vicaya/qeminga", "{case}");
            assert_eq!(json["source_sha"], SHA, "{case}");
            assert_eq!(json["architecture"], "x86_64", "{case}");
            assert_eq!(json["candidate_binary_sha256"], sentinel, "{case}");
            assert_eq!(json["virtualization"]["hypervisor"], "qemu", "{case}");
            assert_eq!(json["virtualization"]["accelerator"], "unknown", "{case}");
            assert_eq!(json["virtualization"]["machine"], "q35", "{case}");
            for t in MANDATORY {
                assert_eq!(json["tests"][t], "not_run", "{case}/{t}");
            }
            assert_eq!(json["result"], "fail", "{case}");
        }

        // After fallback, `verify-pass` STILL succeeds ONLY for `valid_pass`
        // (so a synthesized failure record makes the success-path job go red).
        let post_verify = lane(&[
            "verify-pass",
            "--out",
            out_dir.to_str().unwrap(),
            "--arch",
            "x86_64",
            "--source-sha",
            SHA,
            "--expect-sha256",
            expect,
        ]);
        assert_eq!(
            post_verify.status.success(),
            case == "valid_pass",
            "{case}: post-fallback verify-pass status mismatch: {}",
            text(&post_verify)
        );
    }

    // 3. `ensure-result` also fails closed (and leaves no temp files) if
    // publication itself is blocked (e.g. a directory at `result.json`).
    let blocked = tempfile::tempdir().unwrap();
    let blocked_out = blocked.path().join("out");
    std::fs::create_dir_all(blocked_out.join("result.json")).unwrap();
    let res = lane(&[
        "ensure-result",
        "--out",
        blocked_out.to_str().unwrap(),
        "--arch",
        "x86_64",
        "--source-sha",
        SHA,
        "--expect-sha256",
        &candidate_digest,
    ]);
    assert!(
        !res.status.success(),
        "ensure-result must fail closed when result.json cannot be published: {}",
        text(&res)
    );
    assert_eq!(
        std::fs::read_dir(blocked_out.join("result.json"))
            .unwrap()
            .count(),
        0
    );
}

/// Runs `libvirt-kvm-smoke.sh` guaranteed unprivileged (dropping to uid/gid
/// 65534 if the test suite itself is invoked as root) so `qemu:///session`'s
/// root refusal can never satisfy an assertion meant for a later preflight check.
fn lane_unprivileged(args: &[&str], env: &[(&str, &str)], path_override: Option<&Path>) -> Output {
    let bash = ["/usr/bin/bash", "/bin/bash"]
        .iter()
        .find(|p| Path::new(p).exists())
        .unwrap();
    let mut cmd = Command::new(bash);
    cmd.arg(script()).args(args);
    if let Some(p) = path_override {
        cmd.env("PATH", p);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    if std::fs::metadata("/proc/self").unwrap().uid() == 0 {
        cmd.uid(65534).gid(65534);
    }
    cmd.output().unwrap()
}

/// Creates a directory with explicit Unix `mode` at creation time (masked only
/// by `umask`, never widening beyond `mode`, so `0700` stays `0700` even under
/// `umask 000`).
fn create_dir_mode(path: &Path, mode: u32) {
    std::fs::DirBuilder::new().mode(mode).create(path).unwrap();
}

/// Creates a new file with explicit Unix `mode` at creation time and writes
/// `bytes`, never creating a world-writable file even under `umask 000`.
fn write_file_mode(path: &Path, mode: u32, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
}

/// Gives the dropped test subprocess (uid/gid 65534 when the test runner is
/// root) private ownership of `path` with `mode`; leaves unprivileged runs at
/// their creation-time private permissions.
fn grant_child_private(path: &Path, mode: u32, as_root: bool) {
    if as_root {
        std::os::unix::fs::chown(path, Some(65534), Some(65534)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

#[test]
fn run_fails_closed_with_result_json_when_kvm_device_is_missing_or_not_a_char_device() {
    require_jq();
    let arch = std::env::consts::ARCH;
    if arch != "x86_64" && arch != "aarch64" {
        return;
    }
    let as_root = std::fs::metadata("/proc/self").unwrap().uid() == 0;
    let dir = private_tempdir();
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().mode() & 0o777,
        0o700,
        "temp parent must be created with 0700 permissions even under permissive umask"
    );
    if as_root {
        // Grant traversal-only to the dropped child only AFTER the directory
        // exists as 0700; parent stays root-owned and never world-writable.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o711)).unwrap();
    }
    assert_eq!(
        std::fs::metadata(dir.path()).unwrap().mode() & 0o002,
        0,
        "temp parent must never be world-writable"
    );

    // Build a real, valid candidate directory and matching digest so the test
    // cannot accidentally pass because of a missing candidate.
    let bin_file = dir.path().join("built-qeminga");
    write_file_mode(&bin_file, 0o600, b"valid fake candidate\n");
    let cand_dir = dir.path().join("candidate");
    create_dir_mode(&cand_dir, 0o755);
    let m = lane(&[
        "manifest",
        "--out",
        cand_dir.to_str().unwrap(),
        "--binary",
        bin_file.to_str().unwrap(),
        "--arch",
        arch,
        "--source-sha",
        SHA,
        "--version",
        "0.1.0",
        "--run-id",
        "42",
        "--run-attempt",
        "1",
        "--runner",
        "ubuntu-24.04",
    ]);
    assert!(m.status.success(), "{}", text(&m));
    if as_root {
        std::fs::set_permissions(&cand_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for entry in std::fs::read_dir(&cand_dir).unwrap() {
            let p = entry.unwrap().path();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
    let digest = sha256_hex(&cand_dir.join("qeminga"));

    let missing = dir.path().join("no-such-kvm");
    let regular = dir.path().join("regular-file-kvm");
    write_file_mode(&regular, 0o600, b"");
    assert_eq!(
        std::fs::metadata(&regular).unwrap().mode() & 0o777,
        0o600,
        "regular fixture file must be created 0600"
    );
    grant_child_private(&regular, 0o600, as_root);

    let images_dir = dir.path().join("images");
    create_dir_mode(&images_dir, 0o700);
    assert_eq!(
        std::fs::metadata(&images_dir).unwrap().mode() & 0o777,
        0o700,
        "images dir must be created 0700"
    );
    grant_child_private(&images_dir, 0o700, as_root);

    for (label, kvm_path) in [("missing", &missing), ("regular", &regular)] {
        let out_dir = dir.path().join(format!("out-{label}"));
        create_dir_mode(&out_dir, 0o700);
        assert_eq!(
            std::fs::metadata(&out_dir).unwrap().mode() & 0o777,
            0o700,
            "out dir must be created 0700"
        );
        grant_child_private(&out_dir, 0o700, as_root);
        let output = lane_unprivileged(
            &[
                "run",
                "--arch",
                arch,
                "--candidate",
                cand_dir.to_str().unwrap(),
                "--source-sha",
                SHA,
                "--run-id",
                "42",
                "--run-attempt",
                "1",
                "--out",
                out_dir.to_str().unwrap(),
                "--expect-sha256",
                &digest,
            ],
            &[
                ("QEMINGA_KVM_DEVICE", kvm_path.to_str().unwrap()),
                ("QEMINGA_E2E_IMAGES", images_dir.to_str().unwrap()),
            ],
            None,
        );
        let combined = text(&output);
        assert!(
            !output.status.success(),
            "{label}: expected failure: {combined}"
        );
        let expected_diag = format!(
            "KVM device {} is missing or not readable/writable by uid ",
            kvm_path.display()
        );
        assert!(
            combined.contains(&expected_diag),
            "{label}: failure must name the rejected KVM device path ({expected_diag:?}):\n{combined}"
        );
        assert!(
            !combined.contains("refusing to run qemu:///session as root"),
            "{label}: must not stop at root-session check:\n{combined}"
        );
        assert!(
            !combined.contains("missing tool:"),
            "{label}: must fail at the KVM device check before tool checks:\n{combined}"
        );
        let result_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out_dir.join("result.json")).unwrap())
                .unwrap_or_else(|e| panic!("{label}: {e}: {combined}"));
        assert_eq!(result_json["suite"], "libvirt-kvm-smoke-v1", "{label}");
        assert_eq!(result_json["result"], "fail", "{label}");
        assert_eq!(
            result_json["virtualization"]["accelerator"], "unknown",
            "{label}: must never silently fall back to tcg"
        );
        assert_eq!(
            result_json["tests"]["accelerator_kvm"], "not_run",
            "{label}"
        );
    }

    // Positive control: a readable/writable char device (/dev/null) gets PAST the KVM device
    // guard and reaches the subsequent tool check (stopping at `missing tool: virsh` under a
    // PATH that omits `virsh`), proving the assertions above only pass because of the guard.
    let minimal_bin = dir.path().join("minimal-bin");
    create_dir_mode(&minimal_bin, 0o755);
    for tool in [
        "dirname", "basename", "uname", "id", "mkdir", "rm", "cat", "tr", "jq", "printf", "cut",
        "cp", "mv",
    ] {
        if let Some(real) = ["/usr/bin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join(tool))
            .find(|p| p.exists())
        {
            std::os::unix::fs::symlink(real, minimal_bin.join(tool)).unwrap();
        }
    }
    let ctrl_out = dir.path().join("out-control");
    create_dir_mode(&ctrl_out, 0o700);
    assert_eq!(
        std::fs::metadata(&ctrl_out).unwrap().mode() & 0o777,
        0o700,
        "ctrl out dir must be created 0700"
    );
    grant_child_private(&ctrl_out, 0o700, as_root);
    let ctrl = lane_unprivileged(
        &[
            "run",
            "--arch",
            arch,
            "--candidate",
            cand_dir.to_str().unwrap(),
            "--source-sha",
            SHA,
            "--run-id",
            "42",
            "--run-attempt",
            "1",
            "--out",
            ctrl_out.to_str().unwrap(),
            "--expect-sha256",
            &digest,
        ],
        &[
            ("QEMINGA_KVM_DEVICE", "/dev/null"),
            ("QEMINGA_E2E_IMAGES", images_dir.to_str().unwrap()),
        ],
        Some(&minimal_bin),
    );
    let ctrl_text = text(&ctrl);
    assert!(!ctrl.status.success(), "{ctrl_text}");
    assert!(
        !ctrl_text.contains("KVM device /dev/null is missing"),
        "rw char device must pass the KVM device check:\n{ctrl_text}"
    );
    assert!(
        ctrl_text.contains("missing tool: virsh"),
        "control run should reach the next preflight stage (missing tool: virsh):\n{ctrl_text}"
    );
}

#[test]
fn kvm_device_fixture_stays_private_under_permissive_umask() {
    let exe = std::env::current_exe().unwrap();
    for test_name in [
        "run_fails_closed_with_result_json_when_kvm_device_is_missing_or_not_a_char_device",
        "write_result_propagates_publish_failure_in_exit_trap_context_and_cleans_temp",
    ] {
        let out = Command::new("/bin/sh")
            .args(["-c", r#"umask 000 && exec "$1" --exact "$2""#, "sh"])
            .arg(&exe)
            .arg(test_name)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{test_name} must remain private under umask 000:\n{}",
            text(&out)
        );
    }
}
