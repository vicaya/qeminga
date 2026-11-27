//! Privileged and end-to-end boundary verification suite for OQ-10 two-process
//! parser/executor isolation (Issue #79, `docs/isolation-design.md` §6).
//!
//! Covers all seven automated acceptance checks of `docs/isolation-design.md` §6:
//! 1. Parser credential, backing-object descriptor, and seccomp inspection under
//!    the enforced CVM profile (using `QEMINGA_RELEASE_BINARY` when provided).
//! 2. Confidentiality boundary probe against synthetic `0600 root:root` and
//!    `0644 root:root` secrets, `/etc/qeminga/config.toml`, `/proc/self/mountinfo`,
//!    and `getdents64` on `/var/lib/qeminga-boundary-test` (both enforcing
//!    seccomp `SIGSYS` and companion UID-601 DAC `EACCES`).
//! 3. Integrity boundary probe (`openat(O_WRONLY)`/`unlinkat` on unrelated
//!    writable files and `/run/qeminga/frozen`), descriptor-level virtio-serial
//!    channel verification (including simulated hotplug minor renumbering) under
//!    the enforcing CVM executor filter, and malicious IPC / `MSG_CTRUNC` /
//!    parser-side cmsg rejections / no-`CAP_KILL` systemd `KillMode=control-group`
//!    supervision under the enforcing CVM executor filter.
//! 4. Audit-sink isolation probe proving a compromised parser cannot forge
//!    `command_received` records through fds `1`/`2` or any non-IPC descriptor.
//! 5. Deterministic reconnect & late-reply isolation (`session_gen`) across a
//!    mid-operation disconnect/reopen boundary with reused QGA `id`.
//! 6. Large-payload §5.10, `GetOsInfo` (> 32 KiB `PRETTY_NAME`), > 256-entry
//!    `guest-fsfreeze-freeze-list` (#63 omitted/empty/mixed semantics), and
//!    mixed-outcome > 1 MiB opted-in `guest-fstrim` bounds.
//! 7. Authorized freeze/thaw + CVM recovery cycle (initial + reopened `SCM_RIGHTS`,
//!    mode-`0700 root:root` mountpoint, `SIGKILL` and `ipc_protocol_violation`
//!    while `Frozen`, policy narrowing across crash/restart, `#69` cooperative
//!    ownership preservation of a foreign-frozen filesystem, final freeze/thaw,
//!    and intact-fixture byte/inode/mtime assertions).
//!
//! Unprivileged twins for Checks 4, 5, and 6 run under normal `cargo test`.
//! All seven privileged checks are `#[ignore]`d and named `privileged_oq10_*`
//! so CI runs them serially as root on both `x86_64` and `aarch64` under both
//! `seccomp-log` and enforced builds.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod e2e;

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{File, Permissions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use e2e::{Agent, SpawnOptions, ThawGuard, dev_of, handle};
use nix::errno::Errno;
use nix::fcntl::{AT_FDCWD, AtFlags, FcntlArg, OFlag, fcntl, open, openat};
use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::sys::signal::{Signal, kill};
use nix::sys::stat::{Mode, SFlag, fchmod, fstat, fstatat, major, minor};
use nix::unistd::{Gid, Pid, Uid, UnlinkatFlags, chown, fchown, mkdir, pipe, unlinkat};
use serde_json::{Value, json};

use qeminga::audit::Router;
use qeminga::channel::OpenError;
use qeminga::channel_verify::{ChannelIdentityPolicy, open_verified_channel};
use qeminga::config::{Authority, Config};
use qeminga::dispatch::Context;
use qeminga::executor::{ExecutorExitError, VerifiedOpenFn, serve_ipc_with_backoff};
use qeminga::handlers::fsfreeze::LifecycleHooks;
use qeminga::handlers::fsinfo::{Statfs, StatfsSource};
use qeminga::handlers::osinfo::{OsInfoSource, Uname};
use qeminga::ipc::{
    IPC_FD, IpcRequest, IpcResponse, MAX_PACKET_BYTES, PeerRole, StreamAssembler,
    encode_request_chunks, encode_response_chunks, recv_request, send_response,
};
use qeminga::kernel::caps::{Account, SystemCaps, drop_parser_privileges_to, drop_privileges_to};
use qeminga::kernel::fake::FakeKernel;
use qeminga::kernel::ipc::{
    pin_unused_fd_cloexec, recv_packet, send_packet, send_packet_fds, seqpacket_pair,
};
use qeminga::kernel::process::{ParserSpawnSpec, apply_parser_rlimit_and_chdir, spawn_parser};
use qeminga::kernel::{KernelError, KernelOps, LinuxKernel, Mount, RebootCommand, Trimmed};
use qeminga::marker::Marker;
use qeminga::mountinfo::MountSource;
use qeminga::ownership::{LinuxOwnershipStore, OwnershipStore, TargetOwnership};
use qeminga::parser_proc::{ParserExit, run_parser_loop};
use qeminga::proto::Error as ProtoError;
use qeminga::state::{FreezeState, FreezeStateMachine};

const SECRET_DIR: &str = "/var/lib/qeminga-boundary-test";
const ROOT_SECRET_PATH: &str = "/var/lib/qeminga-boundary-test/root-secret";
const WORLD_SECRET_PATH: &str = "/var/lib/qeminga-boundary-test/world-secret";
const UID600_FILE_PATH: &str = "/tmp/qeminga-boundary-uid600";
const WORLD_FILE_PATH: &str = "/tmp/qeminga-boundary-world";
const CONFIG_PATH: &str = "/etc/qeminga/config.toml";

const ROOT_SECRET_BYTES: &[u8] = b"synthetic-root-secret-oq10";
const WORLD_SECRET_BYTES: &[u8] = b"synthetic-world-secret-oq10";
const UID600_FILE_BYTES: &[u8] = b"untouched-uid600";
const WORLD_FILE_BYTES: &[u8] = b"untouched-world";

const RETURNED_WITHOUT_SIGSYS: i32 = 99;
const ENV_PROBE: &str = "QEMINGA_OQ10_PROBE";
const ENV_AUX: &str = "QEMINGA_OQ10_AUX";
const ENV_AUX2: &str = "QEMINGA_OQ10_AUX2";

// ---- Shared helpers --------------------------------------------------------

fn is_enforced_seccomp() -> bool {
    qeminga::daemon::seccomp_mode() == "enforce"
}

fn release_or_test_binary() -> Option<PathBuf> {
    if is_enforced_seccomp() {
        std::env::var_os("QEMINGA_RELEASE_BINARY").map(PathBuf::from)
    } else {
        None
    }
}

fn cvm_real_kernel(agent_extra: &str) -> SpawnOptions {
    SpawnOptions {
        fake_kernel: false,
        agent_extra: agent_extra.to_owned(),
        features_extra: "shutdown = false\ninformation = false\nfstrim = false\n".to_owned(),
        enforce_hardening: is_enforced_seccomp(),
        binary: release_or_test_binary(),
        ..SpawnOptions::default()
    }
}

fn ext4_mount() -> String {
    std::env::var("QEMINGA_TEST_EXT4_MOUNT")
        .expect("QEMINGA_TEST_EXT4_MOUNT: run scripts/ci/mk-loop-fs.sh setup")
}

fn freeze_list(agent: &mut Agent, mounts: &[String]) -> Value {
    let req =
        json!({"execute": "guest-fsfreeze-freeze-list", "arguments": {"mountpoints": mounts}});
    agent.request(&req.to_string())
}

#[cfg(feature = "seccomp")]
fn install_parser_seccomp() {
    let prog = qeminga::seccomp::parser_profile(qeminga::seccomp::Target::current()).unwrap();
    qeminga::seccomp::install(&prog).unwrap();
}

#[cfg(not(feature = "seccomp"))]
fn install_parser_seccomp() {}

#[cfg(feature = "seccomp")]
fn install_cvm_executor_seccomp() {
    let prog = qeminga::seccomp::executor_profile(
        qeminga::seccomp::Target::current(),
        &Authority::data_protection(),
    )
    .unwrap();
    qeminga::seccomp::install(&prog).unwrap();
}

#[cfg(not(feature = "seccomp"))]
fn install_cvm_executor_seccomp() {}

fn qeminga_account(name: &str, expected_id: u32) -> Account {
    let user = nix::unistd::User::from_name(name)
        .unwrap()
        .unwrap_or_else(|| {
            panic!("missing system account `{name}` (install packaging/sysusers.d/qeminga.conf)")
        });
    assert_eq!(user.uid.as_raw(), expected_id, "{name} uid");
    assert_eq!(user.gid.as_raw(), expected_id, "{name} gid");
    Account {
        uid: user.uid,
        gid: user.gid,
    }
}

/// An exclusively created boundary fixture file that retains a read-capable
/// descriptor and recorded identity/metadata so both integrity checks and
/// teardown verify the directory entry via `fstatat(..., AT_SYMLINK_NOFOLLOW)`
/// before touching contents or unlinking.
struct OwnedFixtureFile {
    parent_dir: PathBuf,
    name: String,
    file: File,
    expected_bytes: Vec<u8>,
    dev: u64,
    ino: u64,
    size: i64,
    mtime: i64,
    mtime_nsec: i64,
}

impl OwnedFixtureFile {
    fn try_create_exclusive(
        parent_dir: &Path,
        name: &str,
        uid: Uid,
        gid: Gid,
        mode: u32,
        bytes: &[u8],
    ) -> Result<Self, Errno> {
        let dirfd = open(
            parent_dir,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let fd = openat(
            &dirfd,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?;
        fchown(&fd, Some(uid), Some(gid))?;
        fchmod(&fd, Mode::from_bits_truncate(mode))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|e| Errno::from_raw(e.raw_os_error().unwrap_or(nix::libc::EIO)))?;
        let st = fstat(&file)?;
        Ok(OwnedFixtureFile {
            parent_dir: parent_dir.to_path_buf(),
            name: name.to_owned(),
            file,
            expected_bytes: bytes.to_vec(),
            dev: st.st_dev,
            ino: st.st_ino,
            size: st.st_size,
            mtime: st.st_mtime,
            mtime_nsec: st.st_mtime_nsec,
        })
    }

    /// Verifies that the directory entry still refers to the original regular
    /// file inode without following symlinks, checks held-fd metadata, and
    /// reads at most `expected_bytes.len() + 1` bytes from the held descriptor.
    /// Diagnostics report only the path and differing field (never file bytes).
    fn assert_intact(&self) {
        let full = self.parent_dir.join(&self.name);
        let dirfd = open(
            &self.parent_dir,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap_or_else(|e| panic!("open parent dir {}: {e}", self.parent_dir.display()));
        let dir_st = fstatat(&dirfd, self.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            .unwrap_or_else(|e| panic!("fstatat {}: {e}", full.display()));
        let dir_type = SFlag::from_bits_truncate(dir_st.st_mode) & SFlag::S_IFMT;
        assert_eq!(
            dir_type,
            SFlag::S_IFREG,
            "boundary fixture {} file type changed (mode={:#o})",
            full.display(),
            dir_st.st_mode
        );
        assert_eq!(
            (dir_st.st_dev, dir_st.st_ino),
            (self.dev, self.ino),
            "boundary fixture {} directory entry identity changed (expected dev={}, ino={}, got dev={}, ino={})",
            full.display(),
            self.dev,
            self.ino,
            dir_st.st_dev,
            dir_st.st_ino
        );

        let fd_st = fstat(&self.file)
            .unwrap_or_else(|e| panic!("fstat held fd for {}: {e}", full.display()));
        assert_eq!(
            (fd_st.st_dev, fd_st.st_ino),
            (self.dev, self.ino),
            "boundary fixture {} held descriptor identity changed",
            full.display()
        );
        assert_eq!(
            fd_st.st_size,
            self.size,
            "boundary fixture {} size changed (expected {}, got {})",
            full.display(),
            self.size,
            fd_st.st_size
        );
        assert_eq!(
            (fd_st.st_mtime, fd_st.st_mtime_nsec),
            (self.mtime, self.mtime_nsec),
            "boundary fixture {} mtime changed (expected {}.{:09}, got {}.{:09})",
            full.display(),
            self.mtime,
            self.mtime_nsec,
            fd_st.st_mtime,
            fd_st.st_mtime_nsec
        );

        let mut buf = vec![0u8; self.expected_bytes.len() + 1];
        let mut total = 0usize;
        while total < buf.len() {
            match self.file.read_at(&mut buf[total..], total as u64) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("read held fd for {}: {e}", full.display()),
            }
        }
        assert!(
            &buf[..total] == self.expected_bytes.as_slice(),
            "boundary fixture {} content diverged (read {} bytes, expected {})",
            full.display(),
            total,
            self.expected_bytes.len()
        );
    }
}

impl Drop for OwnedFixtureFile {
    fn drop(&mut self) {
        let Ok(dirfd) = open(
            &self.parent_dir,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) else {
            return;
        };
        if let Ok(st) = fstatat(&dirfd, self.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            && (st.st_dev, st.st_ino) == (self.dev, self.ino)
        {
            let _ = unlinkat(&dirfd, self.name.as_str(), UnlinkatFlags::NoRemoveDir);
        }
    }
}

/// An exclusively created directory whose `(dev, ino)` is verified before
/// teardown calls `rmdir` on it; pre-existing directories are never mutated or
/// removed.
struct OwnedFixtureDir {
    parent_dir: PathBuf,
    name: String,
    dev: u64,
    ino: u64,
}

impl OwnedFixtureDir {
    fn try_create_exclusive(parent_dir: &Path, name: &str, mode: u32) -> Option<Self> {
        let full = parent_dir.join(name);
        match mkdir(&full, Mode::from_bits_truncate(0o700)) {
            Ok(()) => {
                let dfd = open(
                    &full,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                fchown(&dfd, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
                fchmod(&dfd, Mode::from_bits_truncate(mode)).unwrap();
                let st = fstat(&dfd).unwrap();
                Some(OwnedFixtureDir {
                    parent_dir: parent_dir.to_path_buf(),
                    name: name.to_owned(),
                    dev: st.st_dev,
                    ino: st.st_ino,
                })
            }
            Err(Errno::EEXIST) => None,
            Err(e) => panic!("mkdir {}: {e}", full.display()),
        }
    }
}

impl Drop for OwnedFixtureDir {
    fn drop(&mut self) {
        let Ok(parent_fd) = open(
            &self.parent_dir,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) else {
            return;
        };
        if let Ok(st) = fstatat(&parent_fd, self.name.as_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
            && (st.st_dev, st.st_ino) == (self.dev, self.ino)
        {
            let _ = unlinkat(&parent_fd, self.name.as_str(), UnlinkatFlags::RemoveDir);
        }
    }
}

/// The four synthetic guest secrets and unrelated writable files required
/// simultaneously by `docs/isolation-design.md` §6, acquired exclusively with
/// descriptor-pinned ownership/mode, held read-capable descriptors, and
/// identity-verified teardown.
struct BoundaryFixtures {
    // Field drop order is declaration order: files unlink before dirs rmdir.
    boundary_files: Vec<OwnedFixtureFile>,
    _owned_config: Option<OwnedFixtureFile>,
    _owned_dirs: Vec<OwnedFixtureDir>,
}

impl BoundaryFixtures {
    fn setup() -> Self {
        e2e::require_service_account_when_root();
        let uid600 = qeminga_account("qeminga", 600);
        let _uid601 = qeminga_account("qeminga-parser", 601);

        let mut owned_dirs = Vec::new();
        let mut boundary_files = Vec::new();

        if let Some(d) = OwnedFixtureDir::try_create_exclusive(
            Path::new("/var/lib"),
            "qeminga-boundary-test",
            0o755,
        ) {
            owned_dirs.push(d);
        }

        for (parent, name, bytes, uid, gid, mode) in [
            (
                Path::new(SECRET_DIR),
                "root-secret",
                ROOT_SECRET_BYTES,
                Uid::from_raw(0),
                Gid::from_raw(0),
                0o600u32,
            ),
            (
                Path::new(SECRET_DIR),
                "world-secret",
                WORLD_SECRET_BYTES,
                Uid::from_raw(0),
                Gid::from_raw(0),
                0o644,
            ),
            (
                Path::new("/tmp"),
                "qeminga-boundary-uid600",
                UID600_FILE_BYTES,
                uid600.uid,
                uid600.gid,
                0o600,
            ),
            (
                Path::new("/tmp"),
                "qeminga-boundary-world",
                WORLD_FILE_BYTES,
                Uid::from_raw(0),
                Gid::from_raw(0),
                0o666,
            ),
        ] {
            let owned =
                OwnedFixtureFile::try_create_exclusive(parent, name, uid, gid, mode, bytes)
                    .unwrap_or_else(|e| {
                        panic!(
                            "boundary fixture {}/{name} must not pre-exist (exclusive creation failed: {e})",
                            parent.display()
                        )
                    });
            boundary_files.push(owned);
        }

        // Ensure `/etc/qeminga/config.toml` exists for Check 2's read probe,
        // creating and owning it (and `/etc/qeminga`) only when absent.
        if let Some(d) = OwnedFixtureDir::try_create_exclusive(Path::new("/etc"), "qeminga", 0o755)
        {
            owned_dirs.push(d);
        }
        let owned_config = match OwnedFixtureFile::try_create_exclusive(
            Path::new("/etc/qeminga"),
            "config.toml",
            Uid::from_raw(0),
            Gid::from_raw(0),
            0o644,
            b"[agent]\nlog_level = \"info\"\n",
        ) {
            Ok(owned) => Some(owned),
            Err(Errno::EEXIST) => None,
            Err(e) => panic!("create {CONFIG_PATH}: {e}"),
        };

        BoundaryFixtures {
            boundary_files,
            _owned_config: owned_config,
            _owned_dirs: owned_dirs,
        }
    }

    fn assert_all_intact(&self) {
        for f in &self.boundary_files {
            f.assert_intact();
        }
    }
}

/// Discovers direct child PIDs of `parent_pid` from `/proc`.
fn child_pids(parent_pid: u32) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(tasks) = std::fs::read_dir(format!("/proc/{parent_pid}/task")) {
        for entry in tasks.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path().join("children")) {
                for tok in text.split_whitespace() {
                    if let Ok(pid) = tok.parse::<u32>()
                        && !out.contains(&pid)
                    {
                        out.push(pid);
                    }
                }
            }
        }
    }
    if !out.is_empty() {
        return out;
    }
    let ppid_line = format!("PPid:\t{parent_pid}");
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if let Ok(status) = std::fs::read_to_string(entry.path().join("status"))
                && status.lines().any(|l| l.trim() == ppid_line)
            {
                out.push(pid);
            }
        }
    }
    out
}

fn wait_for_parser_child(executor_pid: u32) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let children = child_pids(executor_pid);
        if children.len() == 1 {
            return children[0];
        }
        assert!(
            Instant::now() < deadline,
            "expected exactly one parser child of {executor_pid}, found {children:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_pid_gone(pid: u32, timeout: Duration) {
    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    let deadline = Instant::now() + timeout;
    while proc_dir.exists() {
        if let Ok(status) = std::fs::read_to_string(proc_dir.join("status"))
            && status.lines().any(|l| l.starts_with("State:\tZ"))
        {
            return;
        }
        if Instant::now() >= deadline {
            let status_summary = std::fs::read_to_string(proc_dir.join("status"))
                .map(|s| {
                    s.lines()
                        .filter(|l| l.starts_with("State:") || l.starts_with("Uid:"))
                        .collect::<Vec<_>>()
                        .join("; ")
                })
                .unwrap_or_else(|e| format!("<unreadable status: {e}>"));
            let cgroup = std::fs::read_to_string(proc_dir.join("cgroup"))
                .unwrap_or_else(|e| format!("<unreadable cgroup: {e}>"));
            panic!(
                "process {pid} did not exit within {timeout:?} (status: {status_summary}; cgroup: {})",
                cgroup.trim()
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn status_field(status: &str, key: &str) -> String {
    status
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .unwrap_or_else(|| panic!("{key} missing in:\n{status}"))
        .trim()
        .to_owned()
}

fn run_self_probe(test_name: &str, probe: &str, aux: Option<&str>) -> std::process::Output {
    let mut cmd = ProcessCommand::new(std::env::current_exe().unwrap());
    cmd.args([
        "--exact",
        test_name,
        "--include-ignored",
        "--nocapture",
        "--test-threads=1",
    ])
    .env(ENV_PROBE, probe);
    if let Some(aux) = aux {
        cmd.env(ENV_AUX, aux);
    }
    cmd.output().unwrap()
}

/// Runs a two-generation supervision probe inside a transient systemd service
/// unit configured with `KillMode=control-group`, `TimeoutStopSec=2s`,
/// `SendSIGKILL=yes`, `RuntimeMaxSec=30s`, and `Restart=on-failure`.
///
/// Generation 1 writes its mock UID-601 parser PID into `state_dir/gen1_parser_pid`
/// and its completion marker into `state_dir/gen1_result`, then exits non-zero
/// while the uncooperative `SIG_IGN` UID-601 parser is still alive. Systemd
/// enforces `KillMode=control-group` (`SIGTERM`, then `SIGKILL` after
/// `TimeoutStopSec=2s`) before starting Generation 2, which verifies BEFORE
/// serving that `old_pid` is gone and `cgroup.procs` contains only Generation 2,
/// writes `state_dir/gen2_result`, and exits `0`.
fn run_self_probe_in_cgroup_restart(
    test_name: &str,
    probe: &str,
    extra_env: &[(&str, &str)],
) -> (std::process::Output, String) {
    assert!(
        Path::new("/run/systemd/system").is_dir(),
        "cgroup supervision probe `{probe}` requires systemd PID 1 (/run/systemd/system)"
    );
    let exe = std::env::current_exe().unwrap();
    let unit = format!("qeminga-oq10-{probe}-{}.service", std::process::id());
    let mut cmd = ProcessCommand::new("systemd-run");
    cmd.args([
        "--wait",
        "--collect",
        "--quiet",
        "--service-type=exec",
        &format!("--unit={unit}"),
        "-p",
        "KillMode=control-group",
        "-p",
        "TimeoutStopSec=2s",
        "-p",
        "SendSIGKILL=yes",
        "-p",
        "RuntimeMaxSec=30s",
        "-p",
        "Restart=on-failure",
        "-p",
        "RestartSec=100ms",
        "-p",
        "StartLimitIntervalSec=60s",
        "-p",
        "StartLimitBurst=3",
        "-E",
        &format!("{ENV_PROBE}={probe}"),
    ]);
    for (k, v) in extra_env {
        assert!(
            !v.contains('\n') && !v.contains('\0'),
            "systemd-run -E value for {k} must not contain control characters"
        );
        cmd.args(["-E", &format!("{k}={v}")]);
    }
    if let Ok(bin) = std::env::var("QEMINGA_RELEASE_BINARY") {
        cmd.args(["-E", &format!("QEMINGA_RELEASE_BINARY={bin}")]);
    }
    let out = cmd
        .arg("--")
        .arg(exe)
        .args([
            "--exact",
            test_name,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    (out, unit)
}

fn unit_journal_tail(unit: &str) -> String {
    ProcessCommand::new("journalctl")
        .args(["-u", unit, "--no-pager", "-n", "60"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_else(|e| format!("<journalctl failed: {e}>"))
}

/// Executed by Generation 2 of a `run_self_probe_in_cgroup_restart` unit before
/// serving anything: verifies Generation 1 completed its assertions, the
/// previous uncooperative UID-601 parser PID is already gone, and the service
/// cgroup contains ONLY Generation 2's own PID.
fn verify_prev_generation_reaped_before_restart(state_dir: &Path, expected_gen1_marker: &str) {
    let old_pid: u32 = std::fs::read_to_string(state_dir.join("gen1_parser_pid"))
        .expect("gen1_parser_pid missing in restarted generation")
        .trim()
        .parse()
        .expect("invalid gen1_parser_pid");
    let gen1_result = std::fs::read_to_string(state_dir.join("gen1_result")).unwrap_or_default();
    assert!(
        gen1_result.contains(expected_gen1_marker),
        "generation 1 did not record `{expected_gen1_marker}` before restart (got `{gen1_result}`)"
    );

    let old_proc = PathBuf::from(format!("/proc/{old_pid}"));
    if old_proc.exists() {
        let status = std::fs::read_to_string(old_proc.join("status")).unwrap_or_default();
        let cgroup = std::fs::read_to_string(old_proc.join("cgroup")).unwrap_or_default();
        if !status.lines().any(|l| l.starts_with("State:\tZ")) {
            panic!(
                "old UID-601 parser {old_pid} was still alive when replacement generation started!\nstatus:\n{status}\ncgroup:\n{cgroup}"
            );
        }
    }

    let my_pid = std::process::id();
    let self_cgroup =
        std::fs::read_to_string("/proc/self/cgroup").expect("read /proc/self/cgroup in gen2");
    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        let rel = self_cgroup
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .map(|s| s.trim().trim_start_matches('/'))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                panic!("expected unified 0:: cgroup entry in /proc/self/cgroup:\n{self_cgroup}")
            });
        let procs_path = Path::new("/sys/fs/cgroup").join(rel).join("cgroup.procs");
        let procs_raw = std::fs::read_to_string(&procs_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", procs_path.display()));
        let pids: Vec<u32> = procs_raw
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().parse::<u32>().unwrap())
            .collect();
        assert_eq!(
            pids,
            vec![my_pid],
            "service cgroup {} must contain ONLY replacement generation pid {my_pid}, found {pids:?}",
            procs_path.display()
        );
    }

    std::fs::write(
        state_dir.join("gen2_result"),
        format!("GEN2_CLEAN_CGROUP_OK\nold_pid={old_pid}\nreplacement_pid={my_pid}\n"),
    )
    .unwrap();
    std::process::exit(0);
}

/// Asserts that `mount` accepts an exclusive temporary file write within
/// `timeout`, without truncating any pre-existing file or leaving probe files
/// behind. A still-frozen filesystem blocks the worker in D-state so the test
/// thread times out and unwinds cleanly into `ThawGuard` instead of hanging.
fn assert_writable_within(mount: &str, phase: &str, timeout: Duration) {
    let dir = PathBuf::from(mount);
    let (tx, rx) = mpsc::sync_channel::<Result<(), String>>(1);
    std::thread::spawn(move || {
        let res = (|| -> std::io::Result<()> {
            let mut tmp = tempfile::Builder::new()
                .prefix(".qeminga-oq10-probe-")
                .tempfile_in(&dir)?;
            tmp.write_all(b"ok")?;
            tmp.flush()?;
            drop(tmp);
            Ok(())
        })()
        .map_err(|e| e.to_string());
        let _ = tx.send(res);
    });
    match rx.recv_timeout(timeout) {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{phase}: write probe on {mount} failed: {err}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("{phase}: {mount} remained unwritable (likely still frozen) after {timeout:?}")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("{phase}: write probe worker for {mount} exited unexpectedly")
        }
    }
}

fn assert_sigsys(out: &std::process::Output, label: &str) {
    assert_eq!(
        out.status.signal(),
        Some(nix::libc::SIGSYS),
        "{label} must terminate with SIGSYS under enforced seccomp (exit={:?}); stdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Allocates a raw Unix98 PTY pair and keeps one slave holder open so the
/// master side does not return EIO while waiting for readers.
struct TestPty {
    master: File,
    slave_path: String,
    _holder: OwnedFd,
    rdev_maj: u32,
    rdev_min: u32,
}

impl TestPty {
    fn open(world_rw_if_root: bool) -> Self {
        let master =
            nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
        nix::pty::grantpt(&master).unwrap();
        nix::pty::unlockpt(&master).unwrap();
        let slave_path = nix::pty::ptsname_r(&master).unwrap();
        let mut t = nix::sys::termios::tcgetattr(&master).unwrap();
        nix::sys::termios::cfmakeraw(&mut t);
        nix::sys::termios::tcsetattr(&master, nix::sys::termios::SetArg::TCSANOW, &t).unwrap();

        let holder = open(
            Path::new(&slave_path),
            OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut ts = nix::sys::termios::tcgetattr(&holder).unwrap();
        nix::sys::termios::cfmakeraw(&mut ts);
        nix::sys::termios::tcsetattr(&holder, nix::sys::termios::SetArg::TCSANOW, &ts).unwrap();

        if world_rw_if_root && nix::unistd::geteuid().is_root() {
            std::fs::set_permissions(&slave_path, Permissions::from_mode(0o666)).unwrap();
        }
        let st = fstat(&holder).unwrap();
        let rdev_maj = u32::try_from(major(st.st_rdev)).unwrap();
        let rdev_min = u32::try_from(minor(st.st_rdev)).unwrap();

        let master: OwnedFd = master.into();
        let flags = OFlag::from_bits_retain(fcntl(master.as_fd(), FcntlArg::F_GETFL).unwrap());
        fcntl(master.as_fd(), FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();

        TestPty {
            master: File::from(master),
            slave_path,
            _holder: holder,
            rdev_maj,
            rdev_min,
        }
    }

    fn open_slave_nonblock(&self) -> OwnedFd {
        open(
            Path::new(&self.slave_path),
            OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap()
    }

    fn send_line(&mut self, json: &str) {
        let mut bytes = json.as_bytes().to_vec();
        bytes.push(b'\n');
        let mut offset = 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        while offset < bytes.len() {
            let mut pfd = [PollFd::new(self.master.as_fd(), PollFlags::POLLOUT)];
            let _ = nix::poll::poll(&mut pfd, PollTimeout::from(50u16));
            match self.master.write(&bytes[offset..]) {
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("pty write failed: {e}"),
            }
            assert!(Instant::now() < deadline, "pty write timed out");
        }
    }

    fn read_line(&mut self, pending: &mut Vec<u8>, timeout: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 65536];
        loop {
            if let Some(pos) = pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = pending.drain(..=pos).collect();
                return Some(line[..line.len() - 1].to_vec());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let wait_ms = u16::try_from((deadline - now).as_millis()).unwrap_or(u16::MAX);
            let mut pfd = [PollFd::new(self.master.as_fd(), PollFlags::POLLIN)];
            let ready = match nix::poll::poll(&mut pfd, PollTimeout::from(wait_ms)) {
                Ok(0) => PollFlags::empty(),
                Ok(_) => pfd[0].revents().unwrap_or(PollFlags::empty()),
                Err(Errno::EINTR) => PollFlags::empty(),
                Err(e) => panic!("pty poll failed: {e}"),
            };
            if ready.contains(PollFlags::POLLIN) {
                loop {
                    match self.master.read(&mut buf) {
                        Ok(0) => return None,
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.raw_os_error() == Some(Errno::EIO as i32) => return None,
                        Err(e) => panic!("pty read failed: {e}"),
                    }
                }
            } else if ready.contains(PollFlags::POLLHUP) {
                return None;
            }
        }
    }

    fn request(&mut self, pending: &mut Vec<u8>, json: &str) -> Value {
        self.send_line(json);
        let raw = self
            .read_line(pending, Duration::from_secs(15))
            .unwrap_or_else(|| panic!("no reply to {json}"));
        let body = raw.strip_prefix(&[0xFF]).unwrap_or(&raw);
        serde_json::from_slice(body)
            .unwrap_or_else(|e| panic!("bad JSON reply {:?}: {e}", String::from_utf8_lossy(&raw)))
    }
}

/// Capturing audit writer shared between executor subscriber and test assertions.
#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct StaticMounts(String);

impl MountSource for StaticMounts {
    fn read_mountinfo(&self) -> Result<Vec<u8>, ProtoError> {
        Ok(self.0.as_bytes().to_vec())
    }
}

struct StaticStatfs;

impl StatfsSource for StaticStatfs {
    fn statfs(
        &self,
        _mount_point: &Path,
        _expected_dev: (u32, u32),
        _expected_mount_id: u32,
    ) -> Result<Statfs, ProtoError> {
        Ok(Statfs {
            bsize: 4096,
            blocks: 1024,
            bfree: 512,
        })
    }
}

/// Private bind mount of a unique per-run `0700 root:root` subdirectory on the
/// real ext4 superblock so opening the mountpoint exercises
/// `CAP_DAC_READ_SEARCH` without mutating the source loop mount's root inode or
/// touching any fixed path on ext4.
struct PrivateBindMount {
    // Drop runs `PrivateBindMount::drop` (umount) before dropping fields.
    mount_dir: tempfile::TempDir,
    _backing_subdir: tempfile::TempDir,
}

impl PrivateBindMount {
    fn create(source: &str, mount_parent: &Path, mode: u32) -> Self {
        let backing_subdir = tempfile::Builder::new()
            .prefix("qeminga-oq10-0700-sub-")
            .tempdir_in(source)
            .unwrap();
        let dfd = open(
            backing_subdir.path(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        fchown(&dfd, Some(Uid::from_raw(0)), Some(Gid::from_raw(0))).unwrap();
        fchmod(&dfd, Mode::from_bits_truncate(mode)).unwrap();
        drop(dfd);

        let mount_dir = tempfile::Builder::new()
            .prefix("qeminga-oq10-0700-mnt-")
            .tempdir_in(mount_parent)
            .unwrap();
        let status = ProcessCommand::new("mount")
            .args([
                "--bind",
                backing_subdir.path().to_str().unwrap(),
                mount_dir.path().to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mount --bind {} -> {}",
            backing_subdir.path().display(),
            mount_dir.path().display()
        );
        let status = ProcessCommand::new("mount")
            .args(["--make-private", mount_dir.path().to_str().unwrap()])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "mount --make-private {}",
            mount_dir.path().display()
        );
        PrivateBindMount {
            mount_dir,
            _backing_subdir: backing_subdir,
        }
    }

    fn path(&self) -> &Path {
        self.mount_dir.path()
    }
}

impl Drop for PrivateBindMount {
    fn drop(&mut self) {
        let _ = ProcessCommand::new("umount")
            .arg(self.mount_dir.path())
            .status();
    }
}

/// Second independent loop filesystem (reusing `QEMINGA_TEST_XFS_MOUNT` when set).
struct SecondFs {
    mount: String,
    loop_dev: Option<String>,
    _dir: Option<tempfile::TempDir>,
}

impl SecondFs {
    fn new() -> Self {
        if let Ok(mount) = std::env::var("QEMINGA_TEST_XFS_MOUNT") {
            return SecondFs {
                mount,
                loop_dev: None,
                _dir: None,
            };
        }
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("second.img");
        let mount = dir.path().join("second");
        std::fs::create_dir(&mount).unwrap();
        let ok = |cmd: &str, args: &[&str]| {
            let out = ProcessCommand::new(cmd).args(args).output().unwrap();
            assert!(
                out.status.success(),
                "{cmd} {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        ok("truncate", &["-s", "64M", image.to_str().unwrap()]);
        ok("mkfs.ext4", &["-q", image.to_str().unwrap()]);
        let loop_dev = ok("losetup", &["--find", "--show", image.to_str().unwrap()]);
        ok("mount", &[&loop_dev, mount.to_str().unwrap()]);
        SecondFs {
            mount: mount.to_str().unwrap().to_owned(),
            loop_dev: Some(loop_dev),
            _dir: Some(dir),
        }
    }
}

impl Drop for SecondFs {
    fn drop(&mut self) {
        if let Some(loop_dev) = &self.loop_dev {
            let _ = ProcessCommand::new("umount").arg(&self.mount).status();
            let _ = ProcessCommand::new("losetup")
                .args(["-d", loop_dev])
                .status();
        }
    }
}

// ---- Check 1: Parser credentials, backing-object fds & seccomp -------------

#[test]
#[ignore = "needs root and qeminga/qeminga-parser accounts (OQ-10 §6 Check 1)"]
fn privileged_oq10_check1_parser_credentials_backing_fds_and_seccomp() {
    let fixtures = BoundaryFixtures::setup();
    let mut agent = Agent::spawn_with(cvm_real_kernel(""));
    agent.wait_for_stderr("\"event\":\"privileges_dropped\"", e2e::REPLY_TIMEOUT);
    assert_eq!(
        agent.request(r#"{"execute":"guest-ping","id":101}"#),
        json!({"return": {}, "id": 101})
    );

    let exec_pid = agent.pid();
    let parser_pid = wait_for_parser_child(exec_pid);
    assert_ne!(parser_pid, exec_pid);

    // Inspect EVERY thread of the parser child.
    let parser_threads = e2e::thread_statuses(parser_pid);
    assert_eq!(
        parser_threads.len(),
        1,
        "parser must remain single-threaded: {parser_threads:?}"
    );
    for t in &parser_threads {
        assert_eq!(t.name, "qeminga-parser");
        assert_eq!(t.field("Threads:"), "1");
        assert_eq!(t.field("Uid:"), "601\t601\t601\t601");
        assert_eq!(t.field("Gid:"), "601\t601\t601\t601");
        for set in ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"] {
            assert_eq!(
                t.field(set),
                "0000000000000000",
                "parser {set} must be all zeros"
            );
        }
        assert_eq!(t.field("NoNewPrivs:"), "1");
        if cfg!(feature = "seccomp") {
            assert_eq!(t.field("Seccomp:"), "2");
        }
    }

    // Inspect EVERY thread of the CVM executor: CAP_SYS_ADMIN + CAP_DAC_READ_SEARCH
    // only (0x200004; no CAP_SYS_BOOT, no CAP_KILL).
    let exec_threads = e2e::thread_statuses(exec_pid);
    assert!(exec_threads.len() >= 2, "{exec_threads:?}");
    for t in &exec_threads {
        assert_eq!(t.field("Uid:"), "600\t600\t600\t600", "{}", t.name);
        assert_eq!(t.field("Gid:"), "600\t600\t600\t600", "{}", t.name);
        for set in ["CapEff:", "CapPrm:", "CapBnd:"] {
            assert_eq!(
                t.field(set),
                "0000000000200004",
                "CVM executor {} {set} must hold only CAP_SYS_ADMIN + CAP_DAC_READ_SEARCH",
                t.name
            );
        }
        assert_eq!(t.field("CapInh:"), "0000000000000000", "{}", t.name);
        assert_eq!(t.field("CapAmb:"), "0000000000000000", "{}", t.name);
        assert_eq!(t.field("NoNewPrivs:"), "1", "{}", t.name);
        if cfg!(feature = "seccomp") {
            assert_eq!(t.field("Seccomp:"), "2", "{}", t.name);
        }
    }

    // Verify parser fds 0/1/2 by backing kernel object: S_ISCHR(1, 3) /dev/null
    // and distinct (st_dev, st_ino) from executor's inherited stderr audit sink.
    let exec_stderr = std::fs::metadata(format!("/proc/{exec_pid}/fd/2")).unwrap();
    for fd_num in [0u32, 1, 2] {
        let meta = std::fs::metadata(format!("/proc/{parser_pid}/fd/{fd_num}")).unwrap();
        assert!(
            meta.file_type().is_char_device(),
            "parser fd {fd_num} must be char device"
        );
        assert_eq!(
            (major(meta.rdev()), minor(meta.rdev())),
            (1, 3),
            "parser fd {fd_num} must resolve to /dev/null (1, 3)"
        );
        assert_ne!(
            (meta.dev(), meta.ino()),
            (exec_stderr.dev(), exec_stderr.ino()),
            "parser fd {fd_num} must never alias executor stderr audit fd"
        );
    }

    // Strict allowlist on `/proc/<parser_pid>/fd`: ONLY /dev/null (0/1/2),
    // IPC_FD (3) socket, one verified channel char device, and optional
    // epoll/eventfd descriptors.
    let mut channel_fd_count = 0usize;
    let mut saw_ipc_fd = false;
    let state_dir = agent.state_dir().to_string_lossy().into_owned();
    for entry in std::fs::read_dir(format!("/proc/{parser_pid}/fd")).unwrap() {
        let entry = entry.unwrap();
        let fd_num: i32 = entry.file_name().to_string_lossy().parse().unwrap();
        let target = std::fs::read_link(entry.path())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let meta = std::fs::metadata(entry.path()).unwrap();
        assert!(
            !target.contains(&state_dir)
                && !target.contains("mountinfo")
                && !target.contains("config.toml")
                && !target.contains("qeminga-boundary"),
            "unexpected executor/guest fd {fd_num} -> {target} in parser"
        );
        match fd_num {
            0..=2 => {
                assert!(meta.file_type().is_char_device());
                assert_eq!((major(meta.rdev()), minor(meta.rdev())), (1, 3));
            }
            fd if fd == IPC_FD => {
                assert!(
                    meta.file_type().is_socket() && target.starts_with("socket:["),
                    "parser IPC_FD (3) must be a Unix socket: {target}"
                );
                saw_ipc_fd = true;
            }
            _ => {
                if meta.file_type().is_char_device()
                    && (target.starts_with("/dev/pts/") || target.starts_with("/dev/vport"))
                {
                    channel_fd_count += 1;
                } else if target.starts_with("anon_inode:[eventpoll]")
                    || target.starts_with("anon_inode:[eventfd]")
                {
                    // Permitted by §6 Check 1.
                } else {
                    panic!("parser holds unexpected open fd {fd_num} -> {target}");
                }
            }
        }
    }
    assert!(saw_ipc_fd, "parser must hold IPC_FD = 3");
    assert_eq!(
        channel_fd_count, 1,
        "parser must hold exactly one verified channel char device"
    );

    // Executor must hold IPC_FD = 3 socket and ZERO channel char device fds.
    let exec_ipc = std::fs::read_link(format!("/proc/{exec_pid}/fd/{IPC_FD}"))
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        exec_ipc.starts_with("socket:["),
        "executor fd 3: {exec_ipc}"
    );
    for entry in std::fs::read_dir(format!("/proc/{exec_pid}/fd")).unwrap() {
        let entry = entry.unwrap();
        if let Ok(target) = std::fs::read_link(entry.path()) {
            let s = target.to_string_lossy();
            assert!(
                !s.starts_with("/dev/pts/") && !s.starts_with("/dev/vport"),
                "executor must close channel fd immediately after handoff, still holds: {s}"
            );
        }
    }

    assert!(agent.stop().success());
    wait_for_pid_gone(parser_pid, Duration::from_secs(5));
    fixtures.assert_all_intact();
}

// ---- Check 2: Confidentiality boundary probe -------------------------------

#[test]
#[ignore = "needs root and qeminga/qeminga-parser accounts (OQ-10 §6 Check 2)"]
fn privileged_oq10_check2_confidentiality_boundary_probe() {
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        let parser_acct = qeminga_account("qeminga-parser", 601);
        match probe.as_str() {
            "read-root-secret" | "read-world-secret" | "read-config" | "read-mountinfo" => {
                let target = match probe.as_str() {
                    "read-root-secret" => ROOT_SECRET_PATH,
                    "read-world-secret" => WORLD_SECRET_PATH,
                    "read-config" => CONFIG_PATH,
                    "read-mountinfo" => "/proc/self/mountinfo",
                    _ => unreachable!(),
                };
                drop_parser_privileges_to(parser_acct, &SystemCaps).unwrap();
                apply_parser_rlimit_and_chdir().unwrap();
                install_parser_seccomp();
                if let Ok(fd) = openat(
                    AT_FDCWD,
                    target,
                    OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                    Mode::empty(),
                ) {
                    let mut buf = [0u8; 64];
                    let _ = File::from(fd).read(&mut buf);
                }
                std::process::exit(RETURNED_WITHOUT_SIGSYS);
            }
            "getdents-secret-dir" => {
                // Open the directory BEFORE seccomp so we specifically test
                // that `getdents64` itself is denied by `parser_profile`.
                let mut dir = nix::dir::Dir::open(
                    SECRET_DIR,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .unwrap();
                drop_parser_privileges_to(parser_acct, &SystemCaps).unwrap();
                apply_parser_rlimit_and_chdir().unwrap();
                install_parser_seccomp();
                let _ = dir.iter().next();
                std::process::exit(RETURNED_WITHOUT_SIGSYS);
            }
            "uid601-dac-no-seccomp" => {
                let marker_dir = std::env::var(ENV_AUX).unwrap();
                drop_parser_privileges_to(parser_acct, &SystemCaps).unwrap();
                apply_parser_rlimit_and_chdir().unwrap();

                let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
                assert_eq!(status_field(&status, "Uid:"), "601\t601\t601\t601");
                assert_eq!(status_field(&status, "NoNewPrivs:"), "1");
                for set in ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"] {
                    assert_eq!(status_field(&status, set), "0000000000000000", "{set}");
                }

                assert_eq!(
                    openat(
                        AT_FDCWD,
                        ROOT_SECRET_PATH,
                        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
                        Mode::empty()
                    )
                    .unwrap_err(),
                    Errno::EACCES,
                    "UID 601 with zero caps must get EACCES on 0600 root-secret"
                );
                assert_eq!(
                    openat(
                        AT_FDCWD,
                        marker_dir.as_str(),
                        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                        Mode::empty()
                    )
                    .unwrap_err(),
                    Errno::EACCES,
                    "UID 601 with zero caps must get EACCES on 0700 qeminga marker dir"
                );
                println!("CHECK2_UID601_DAC_OK");
                return;
            }
            other => panic!("unknown check2 probe: {other}"),
        }
    }

    let fixtures = BoundaryFixtures::setup();
    let uid600 = qeminga_account("qeminga", 600);
    let marker_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-marker-")
        .tempdir_in("/dev/shm")
        .unwrap();
    chown(marker_dir.path(), Some(uid600.uid), Some(uid600.gid)).unwrap();
    std::fs::set_permissions(marker_dir.path(), Permissions::from_mode(0o700)).unwrap();

    // Companion without-seccomp UID/capability check runs in BOTH log and enforce builds.
    let dac = run_self_probe(
        "privileged_oq10_check2_confidentiality_boundary_probe",
        "uid601-dac-no-seccomp",
        Some(marker_dir.path().to_str().unwrap()),
    );
    let dac_out = String::from_utf8_lossy(&dac.stdout);
    assert!(
        dac.status.success() && dac_out.contains("CHECK2_UID601_DAC_OK"),
        "uid601 DAC check failed: {:?}\nstdout={dac_out}\nstderr={}",
        dac.status,
        String::from_utf8_lossy(&dac.stderr)
    );

    // Enforced seccomp SIGSYS probes on all five confidentiality targets.
    if is_enforced_seccomp() {
        for probe in [
            "read-root-secret",
            "read-world-secret",
            "read-config",
            "read-mountinfo",
            "getdents-secret-dir",
        ] {
            let out = run_self_probe(
                "privileged_oq10_check2_confidentiality_boundary_probe",
                probe,
                None,
            );
            assert_sigsys(&out, probe);
        }
    }

    fixtures.assert_all_intact();
}

// ---- Check 3: Integrity, channel verification, malicious IPC & no-CAP_KILL -

/// Peer helper for Check 3b: receives two `OkChannelFd` `SCM_RIGHTS` transfers
/// on `IPC_FD = 3`, verifies each descriptor's `(major, minor)` matches the
/// expected backing device, atomically repoints the udev symlink between
/// transfers (outside the CVM executor's seccomp filter) to simulate hotplug
/// minor renumbering, and sends `RequestChannelReopen` (opcode 16).
const CHANNEL_VERIFY_PEER_PY: &str = r#"
import array, os, socket, struct, sys

v1_maj, v1_min = int(sys.argv[1]), int(sys.argv[2])
v2_maj, v2_min = int(sys.argv[3]), int(sys.argv[4])
udev_link = sys.argv[5]
v2_slave = sys.argv[6]

os.write(5, b"R")
os.close(5)

sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_SEQPACKET)
os.close(3)
sock.setblocking(True)

def recv_channel_fd(expect_maj, expect_min, err_base):
    data, ancdata, flags, _ = sock.recvmsg(4096, socket.CMSG_SPACE(4))
    if len(data) != 23 or data[17] != 0x0c:
        sys.exit(err_base + 1)
    if (flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)) != 0:
        sys.exit(err_base + 2)
    fds = array.array("i")
    for level, typ, cmsg_data in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            fds.frombytes(cmsg_data[: len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
    if len(fds) != 1:
        sys.exit(err_base + 3)
    fd = fds[0]
    try:
        st = os.fstat(fd)
        if (os.major(st.st_rdev), os.minor(st.st_rdev)) != (expect_maj, expect_min):
            sys.exit(err_base + 4)
    finally:
        os.close(fd)

# 1. Verify initial verified handoff (minor 1).
recv_channel_fd(v1_maj, v1_min, 10)

# 2. Simulate udev hotplug minor renumbering outside the executor's seccomp filter.
next_link = udev_link + ".next"
os.symlink(v2_slave, next_link)
os.replace(next_link, udev_link)

# 3. Ask executor for RequestChannelReopen (opcode 16, empty payload).
sock.send(struct.pack("<BQQBBHH", 1, 2, 2, 16, 0, 0, 0))

# 4. Verify reopened verified handoff (minor 2).
recv_channel_fd(v2_maj, v2_min, 20)
sock.close()
"#;

fn run_cvm_channel_verify_child(work_dir: &Path) {
    let uid600 = qeminga_account("qeminga", 600);

    // Pin executor IPC socket to `IPC_FD = 3` FIRST while fd 3 is guaranteed
    // unused (before opening the 4 PTY fixtures that would otherwise claim it).
    let (exec_raw, peer_sock) = seqpacket_pair(false).unwrap();
    let exec_sock = pin_unused_fd_cloexec(exec_raw, IPC_FD).unwrap();
    assert_eq!(exec_sock.as_raw_fd(), IPC_FD);

    let regular = work_dir.join("regular");
    std::fs::write(&regular, b"not-a-device").unwrap();
    std::fs::set_permissions(&regular, Permissions::from_mode(0o666)).unwrap();

    let symlink_regular = work_dir.join("link-to-regular");
    symlink(&regular, &symlink_regular).unwrap();

    // Four PTY slaves standing in for char devices (distinct minors for hotplug
    // renumbering, non-virtio-ports subsystem with matching name, and missing sysfs).
    let pty_v1 = TestPty::open(true);
    let pty_v2 = TestPty::open(true);
    assert_ne!(
        (pty_v1.rdev_maj, pty_v1.rdev_min),
        (pty_v2.rdev_maj, pty_v2.rdev_min)
    );
    let pty_wrong_subsys = TestPty::open(true);
    let pty_vanished_sysfs = TestPty::open(true);

    let sysfs = work_dir.join("sys");
    let make_sysfs = |maj: u32, min: u32, subsys: Option<&str>, name: Option<&str>| {
        let dev_dir = sysfs.join("dev").join("char").join(format!("{maj}:{min}"));
        std::fs::create_dir_all(&dev_dir).unwrap();
        if let Some(sub) = subsys {
            symlink(format!("../../bus/{sub}"), dev_dir.join("subsystem")).unwrap();
        }
        if let Some(port_name) = name {
            std::fs::write(dev_dir.join("name"), port_name).unwrap();
        }
    };
    make_sysfs(
        pty_v1.rdev_maj,
        pty_v1.rdev_min,
        Some("virtio-ports"),
        Some("org.qemu.guest_agent.0\n"),
    );
    make_sysfs(
        pty_v2.rdev_maj,
        pty_v2.rdev_min,
        Some("virtio-ports"),
        Some("org.qemu.guest_agent.0\n"),
    );
    make_sysfs(
        pty_wrong_subsys.rdev_maj,
        pty_wrong_subsys.rdev_min,
        Some("tty"),
        Some("org.qemu.guest_agent.0\n"),
    );
    make_sysfs(
        pty_vanished_sysfs.rdev_maj,
        pty_vanished_sysfs.rdev_min,
        Some("virtio-ports"),
        None,
    );

    let udev_dir = work_dir.join("udev-virtio-ports");
    std::fs::create_dir_all(&udev_dir).unwrap();
    let udev_link = udev_dir.join("org.qemu.guest_agent.0");
    symlink(&pty_v1.slave_path, &udev_link).unwrap();
    std::fs::set_permissions(&udev_dir, Permissions::from_mode(0o755)).unwrap();

    // Spawn the peer child with the other IPC socket end before dropping
    // privileges or installing CVM executor seccomp.
    let mut peer = spawn_parser(ParserSpawnSpec {
        exe: PathBuf::from("/usr/bin/python3"),
        args: vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(CHANNEL_VERIFY_PEER_PY),
            OsString::from(pty_v1.rdev_maj.to_string()),
            OsString::from(pty_v1.rdev_min.to_string()),
            OsString::from(pty_v2.rdev_maj.to_string()),
            OsString::from(pty_v2.rdev_min.to_string()),
            udev_link.as_os_str().to_owned(),
            OsString::from(&pty_v2.slave_path),
        ],
        parser_ipc: peer_sock,
        initial_channel: None,
        ready_timeout: Duration::from_secs(10),
    })
    .unwrap();

    // Drop to UID/GID 600 with CVM authority (no CAP_SYS_BOOT, no CAP_KILL)
    // and install the enforcing CVM executor seccomp profile.
    drop_privileges_to(uid600, &SystemCaps, &Authority::data_protection()).unwrap();
    install_cvm_executor_seccomp();

    let policy = ChannelIdentityPolicy::virtio_serial_with_sysfs("org.qemu.guest_agent.0", &sysfs);

    // Every rejected path must fail closed with zero SCM_RIGHTS handoff.
    for bad in [
        regular.as_path(),
        symlink_regular.as_path(),
        Path::new("/dev/null"),
        Path::new("/dev/zero"),
        Path::new(&pty_wrong_subsys.slave_path),
        Path::new(&pty_vanished_sysfs.slave_path),
    ] {
        assert!(
            open_verified_channel(bad, &policy, false).is_err(),
            "channel verifier MUST reject {} under enforcing CVM executor filter",
            bad.display()
        );
    }

    // Valid udev-style virtio-port symlink (minor 1) passes fstat + readlinkat
    // + name under enforcing CVM executor filter and transfers via SCM_RIGHTS on IPC_FD.
    let fd1 = open_verified_channel(&udev_link, &policy, false).unwrap();
    send_response(
        exec_sock.as_fd(),
        1,
        1,
        &IpcResponse::OkChannelFd,
        Some(fd1.as_fd()),
    )
    .unwrap();
    drop(fd1);

    // Wait for peer to verify minor 1, atomically repoint symlink to pty_v2,
    // and send RequestChannelReopen over IPC_FD (recvmsg on IPC_FD = 3 only).
    let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
    let reopen = recv_request(exec_sock.as_fd(), &mut exec_asm)
        .unwrap()
        .unwrap();
    assert_eq!(reopen.request, IpcRequest::RequestChannelReopen);

    // Verify reopened target (minor 2) under the SAME enforcing CVM executor filter.
    let fd2 = open_verified_channel(&udev_link, &policy, false).unwrap();
    send_response(
        exec_sock.as_fd(),
        2,
        2,
        &IpcResponse::OkChannelFd,
        Some(fd2.as_fd()),
    )
    .unwrap();
    drop(fd2);

    let status = peer.wait().unwrap();
    assert_eq!(
        status,
        nix::sys::wait::WaitStatus::Exited(peer.pid(), 0),
        "channel-verify peer failed: {status:?}"
    );
    drop((pty_v1, pty_v2, pty_wrong_subsys, pty_vanished_sysfs));
    println!("CVM_CHANNEL_VERIFY_OK");
}

fn verify_stream_assembler_cmsg_and_trunc_fd_closure() {
    let assert_pipe_eof = |r: &OwnedFd, label: &str| {
        let mut b = [0u8; 1];
        assert_eq!(
            nix::unistd::read(r, &mut b),
            Ok(0),
            "{label}: rejected packet leaked received SCM_RIGHTS descriptor"
        );
    };

    // --- Executor side: rejects MSG_TRUNC, 1 fd, 2 fds, and MSG_CTRUNC (4 fds),
    // closing every received fd on rejection. ---
    {
        let (exec_sock, peer_sock) = seqpacket_pair(false).unwrap();
        let valid_ping = encode_request_chunks(1, 1, &IpcRequest::Ping)
            .unwrap()
            .remove(0);

        // 1 unexpected SCM_RIGHTS fd.
        let (r1, w1) = pipe().unwrap();
        send_packet(peer_sock.as_fd(), &valid_ping, Some(w1.as_fd())).unwrap();
        drop(w1);
        let pkt = recv_packet(exec_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        let mut asm = StreamAssembler::new(PeerRole::Executor);
        assert!(
            asm.push(pkt).is_err(),
            "executor must reject 1 unexpected fd"
        );
        assert_pipe_eof(&r1, "executor 1 unexpected fd");

        // 2 unexpected SCM_RIGHTS fds (exceeds single-fd CMSG_SPACE -> MSG_CTRUNC or >1 fd).
        let (r2a, w2a) = pipe().unwrap();
        let (r2b, w2b) = pipe().unwrap();
        send_packet_fds(peer_sock.as_fd(), &valid_ping, &[w2a.as_fd(), w2b.as_fd()]).unwrap();
        drop((w2a, w2b));
        let pkt = recv_packet(exec_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        let mut asm = StreamAssembler::new(PeerRole::Executor);
        assert!(
            asm.push(pkt).is_err(),
            "executor must reject >1 fds / MSG_CTRUNC"
        );
        assert_pipe_eof(&r2a, "executor 2 fds [0]");
        assert_pipe_eof(&r2b, "executor 2 fds [1]");

        // 4 fds guaranteed to trip MSG_CTRUNC on CMSG_SPACE(sizeof(int)).
        let pipes: Vec<(OwnedFd, OwnedFd)> = (0..4).map(|_| pipe().unwrap()).collect();
        let w_fds: Vec<_> = pipes.iter().map(|(_, w)| w.as_fd()).collect();
        send_packet_fds(peer_sock.as_fd(), &valid_ping, &w_fds).unwrap();
        let r_fds: Vec<OwnedFd> = pipes.into_iter().map(|(r, _w)| r).collect();
        let pkt = recv_packet(exec_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        assert!(pkt.cmsg_truncated, "expected MSG_CTRUNC for 4 fds");
        let mut asm = StreamAssembler::new(PeerRole::Executor);
        assert!(asm.push(pkt).is_err(), "executor must reject MSG_CTRUNC");
        for (i, r) in r_fds.iter().enumerate() {
            assert_pipe_eof(r, &format!("executor MSG_CTRUNC fd {i}"));
        }

        // MSG_TRUNC: packet larger than recv buffer.
        let oversize = vec![0xAAu8; MAX_PACKET_BYTES + 64];
        send_packet(peer_sock.as_fd(), &oversize, None).unwrap();
        let pkt = recv_packet(exec_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        assert!(pkt.truncated, "expected MSG_TRUNC for oversized packet");
        let mut asm = StreamAssembler::new(PeerRole::Executor);
        assert!(asm.push(pkt).is_err(), "executor must reject MSG_TRUNC");
    }

    // --- Parser side: OkChannelFd rejects 0 fds, >1 fds, MSG_CTRUNC; OkEmpty
    // rejects unexpected ancillary data; every received fd closed on rejection. ---
    {
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        let ch_pkt = encode_response_chunks(1, 1, &IpcResponse::OkChannelFd)
            .unwrap()
            .remove(0);
        let ok_pkt = encode_response_chunks(1, 2, &IpcResponse::OkEmpty)
            .unwrap()
            .remove(0);

        // OkChannelFd with 0 fds.
        send_packet(exec_sock.as_fd(), &ch_pkt, None).unwrap();
        let pkt = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        let mut asm = StreamAssembler::new(PeerRole::Parser);
        assert!(asm.push(pkt).is_err(), "OkChannelFd with 0 fds must fail");

        // OkChannelFd with 2 fds.
        let (ra, wa) = pipe().unwrap();
        let (rb, wb) = pipe().unwrap();
        send_packet_fds(exec_sock.as_fd(), &ch_pkt, &[wa.as_fd(), wb.as_fd()]).unwrap();
        drop((wa, wb));
        let pkt = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        let mut asm = StreamAssembler::new(PeerRole::Parser);
        assert!(asm.push(pkt).is_err(), "OkChannelFd with 2 fds must fail");
        assert_pipe_eof(&ra, "parser OkChannelFd 2 fds [0]");
        assert_pipe_eof(&rb, "parser OkChannelFd 2 fds [1]");

        // OkChannelFd with 4 fds (MSG_CTRUNC).
        let pipes: Vec<(OwnedFd, OwnedFd)> = (0..4).map(|_| pipe().unwrap()).collect();
        let w_fds: Vec<_> = pipes.iter().map(|(_, w)| w.as_fd()).collect();
        send_packet_fds(exec_sock.as_fd(), &ch_pkt, &w_fds).unwrap();
        let r_fds: Vec<OwnedFd> = pipes.into_iter().map(|(r, _w)| r).collect();
        let pkt = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        assert!(pkt.cmsg_truncated, "expected MSG_CTRUNC on parser side");
        let mut asm = StreamAssembler::new(PeerRole::Parser);
        assert!(asm.push(pkt).is_err(), "OkChannelFd MSG_CTRUNC must fail");
        for (i, r) in r_fds.iter().enumerate() {
            assert_pipe_eof(r, &format!("parser OkChannelFd MSG_CTRUNC fd {i}"));
        }

        // Non-handoff OkEmpty with 1 unexpected SCM_RIGHTS fd.
        let (r_ok, w_ok) = pipe().unwrap();
        send_packet(exec_sock.as_fd(), &ok_pkt, Some(w_ok.as_fd())).unwrap();
        drop(w_ok);
        let pkt = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        let mut asm = StreamAssembler::new(PeerRole::Parser);
        assert!(
            asm.push(pkt).is_err(),
            "non-handoff OkEmpty with SCM_RIGHTS must fail"
        );
        assert_pipe_eof(&r_ok, "parser OkEmpty unexpected fd");
    }
}

/// Python script run inside a real UID-601 mock compromised parser child
/// spawned by `spawn_parser` (so fds 0/1/2 are `/dev/null`, fd 3 is `IPC_FD`,
/// fd 5 is `PARSER_READY_FD`):
/// 1. Drops to UID/GID 601 and arms `PR_SET_PDEATHSIG(SIGKILL)` + parent check.
/// 2. Signals readiness on fd 5 and ignores SIGTERM.
/// 3. Sends unauthorized CVM opcodes (`GetFsInfo`, `Shutdown`, `Fstrim`),
///    verifying all three return `Err(Disabled)`.
/// 4. Sends 4 pipe write ends via `SCM_RIGHTS` (`MSG_CTRUNC` protocol violation)
///    and sleeps uncooperatively until killed by `PR_SET_PDEATHSIG(SIGKILL)`
///    when the UID-600 executor exits without `CAP_KILL`.
const MOCK_COMPROMISED_PARSER_PY: &str = r#"
import array, ctypes, os, signal, socket, struct, sys, time

expected_ppid = int(sys.argv[1])
os.setgroups([])
os.setgid(601)
os.setuid(601)

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
if libc.prctl(1, 9, 0, 0, 0) != 0:
    sys.exit(21)
if os.getppid() != expected_ppid:
    sys.exit(0)

signal.signal(signal.SIGTERM, signal.SIG_IGN)
os.write(5, b"R")
os.close(5)

sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_SEQPACKET)
os.close(3)
sock.setblocking(True)

def pkt(session_gen, req_id, opcode, payload):
    hdr = struct.pack("<BQQBBHH", 1, session_gen, req_id, opcode, 0, 0, len(payload))
    return hdr + payload

# 1. Unauthorized CVM opcodes: GetFsInfo(11), Shutdown(13, mode=0), Fstrim(12, min=0)
#    All carry HostIdPrefix = 0 (absent host_id).
for req_id, op, body in [
    (1, 11, b"\x00"),
    (2, 13, b"\x00\x00"),
    (3, 12, b"\x00" + struct.pack("<Q", 0)),
]:
    sock.send(pkt(1, req_id, op, body))
    reply = sock.recv(4096)
    # Header is 23 bytes; status byte at offset 17 must be 0x80 (Err),
    # and IpcErrorCode tag at offset 23 must be 1 (Disabled).
    if len(reply) < 25 or reply[17] != 0x80 or reply[23] != 1:
        sys.exit(30 + req_id)

# 2. Send 4 SCM_RIGHTS fds (tripping MSG_CTRUNC in executor's single-fd cmsg buffer)
#    with a Ping request, close local write ends, and verify executor closed all 4.
pipes = [os.pipe() for _ in range(4)]
w_fds = [w for (_, w) in pipes]
sock.sendmsg(
    [pkt(1, 4, 1, b"\x00")],
    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", w_fds))],
)
for w in w_fds:
    os.close(w)

# Sleep uncooperatively (ignoring SIGTERM): under the shipped no-CAP_KILL unit,
# systemd's `KillMode=control-group` (`SIGTERM`, then `SIGKILL` after
# `TimeoutStopSec`) must terminate this UID-601 child before restarting the unit.
time.sleep(60)
"#;

fn run_cvm_malicious_ipc_child(state_dir: &Path) {
    if state_dir.join("gen1_parser_pid").exists() {
        verify_prev_generation_reaped_before_restart(state_dir, "CVM_MALICIOUS_IPC_OK");
        return;
    }

    let uid600 = qeminga_account("qeminga", 600);
    let _uid601 = qeminga_account("qeminga-parser", 601);

    let (exec_raw, parser_sock) = seqpacket_pair(true).unwrap();
    let exec_sock = pin_unused_fd_cloexec(exec_raw, IPC_FD).unwrap();
    assert_eq!(exec_sock.as_raw_fd(), IPC_FD);

    let my_pid = std::process::id().to_string();
    let child = spawn_parser(ParserSpawnSpec {
        exe: PathBuf::from("/usr/bin/python3"),
        args: vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(MOCK_COMPROMISED_PARSER_PY),
            OsString::from(my_pid),
        ],
        parser_ipc: parser_sock,
        initial_channel: None,
        ready_timeout: Duration::from_secs(10),
    })
    .unwrap();
    let child_pid = child.pid().as_raw();
    std::fs::write(state_dir.join("gen1_parser_pid"), format!("{child_pid}\n")).unwrap();
    let mut gen1_result = File::create(state_dir.join("gen1_result")).unwrap();

    chown(state_dir, Some(uid600.uid), Some(uid600.gid)).unwrap();
    let marker = Marker::open(state_dir.join("frozen")).unwrap();

    // Drop to UID/GID 600 with CVM authority (no CAP_KILL, no CAP_SYS_BOOT),
    // start the audit writer thread under the dropped ceiling, then install
    // the enforcing CVM executor seccomp profile.
    drop_privileges_to(uid600, &SystemCaps, &Authority::data_protection()).unwrap();
    let status = std::fs::read_to_string("/proc/thread-self/status").unwrap();
    assert_eq!(status_field(&status, "CapEff:"), "0000000000200004");
    assert_eq!(status_field(&status, "CapPrm:"), "0000000000200004");
    assert_eq!(status_field(&status, "CapBnd:"), "0000000000200004");
    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    install_cvm_executor_seccomp();

    let mut cfg = Config::default();
    cfg.features.shutdown = false;
    cfg.features.information = false;
    cfg.features.fstrim = false;
    let ctx = Arc::new(
        Context::new(
            Arc::new(cfg),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            marker,
        )
        .with_kernel(Arc::new(FakeKernel::new()))
        .with_mounts(Arc::new(StaticMounts(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n".to_owned(),
        ))),
    );
    let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
    let dispatch = tracing::Dispatch::new(qeminga::audit::subscriber(
        tracing::Level::INFO,
        router.clone(),
    ));
    tracing::dispatcher::set_global_default(dispatch).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let exit = rt.block_on(serve_ipc_with_backoff(
        Arc::clone(&ctx),
        exec_sock,
        PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
        opener,
        false,
        Some(child),
        false,
        std::future::pending::<&'static str>(),
        Duration::from_millis(20),
        Duration::from_millis(50),
        Duration::from_millis(20),
    ));

    assert!(
        matches!(exit, Err(ExecutorExitError::ProtocolViolation(_))),
        "expected ProtocolViolation, got {exit:?}"
    );
    assert_eq!(
        ctx.handler_calls(),
        0,
        "unauthorized CVM opcodes must never execute handlers"
    );
    assert_eq!(ctx.state.current(), FreezeState::Thawed);
    assert!(router.settle(Duration::from_secs(2)));
    let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("\"event\":\"ipc_protocol_violation\""),
        "expected ipc_protocol_violation in logs:\n{logs}"
    );
    writeln!(gen1_result, "CVM_MALICIOUS_IPC_OK").unwrap();
    gen1_result.flush().unwrap();
    std::process::exit(42);
}

#[test]
#[ignore = "needs root and qeminga/qeminga-parser accounts (OQ-10 §6 Check 3)"]
fn privileged_oq10_check3_integrity_channel_verify_malicious_ipc_and_no_cap_kill() {
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        let parser_acct = qeminga_account("qeminga-parser", 601);
        match probe.as_str() {
            "write-uid600" | "write-world" | "write-marker" => {
                let target = match probe.as_str() {
                    "write-uid600" => UID600_FILE_PATH.to_owned(),
                    "write-world" => WORLD_FILE_PATH.to_owned(),
                    "write-marker" => std::env::var(ENV_AUX).unwrap(),
                    _ => unreachable!(),
                };
                drop_parser_privileges_to(parser_acct, &SystemCaps).unwrap();
                apply_parser_rlimit_and_chdir().unwrap();
                install_parser_seccomp();
                let _ = openat(
                    AT_FDCWD,
                    target.as_str(),
                    OFlag::O_WRONLY | OFlag::O_CLOEXEC,
                    Mode::empty(),
                );
                std::process::exit(RETURNED_WITHOUT_SIGSYS);
            }
            "unlink-uid600" | "unlink-world" | "unlink-marker" => {
                let target = match probe.as_str() {
                    "unlink-uid600" => UID600_FILE_PATH.to_owned(),
                    "unlink-world" => WORLD_FILE_PATH.to_owned(),
                    "unlink-marker" => std::env::var(ENV_AUX).unwrap(),
                    _ => unreachable!(),
                };
                drop_parser_privileges_to(parser_acct, &SystemCaps).unwrap();
                apply_parser_rlimit_and_chdir().unwrap();
                install_parser_seccomp();
                let _ = unlinkat(AT_FDCWD, target.as_str(), UnlinkatFlags::NoRemoveDir);
                std::process::exit(RETURNED_WITHOUT_SIGSYS);
            }
            "uid601-integrity-dac" => {
                let marker_file = std::env::var(ENV_AUX).unwrap();
                drop_parser_privileges_to(parser_acct, &SystemCaps).unwrap();
                apply_parser_rlimit_and_chdir().unwrap();
                assert_eq!(
                    openat(
                        AT_FDCWD,
                        UID600_FILE_PATH,
                        OFlag::O_WRONLY | OFlag::O_CLOEXEC,
                        Mode::empty()
                    )
                    .unwrap_err(),
                    Errno::EACCES
                );
                let unlink_err =
                    unlinkat(AT_FDCWD, UID600_FILE_PATH, UnlinkatFlags::NoRemoveDir).unwrap_err();
                assert!(
                    matches!(unlink_err, Errno::EPERM | Errno::EACCES),
                    "unexpected unlink err on sticky /tmp: {unlink_err}"
                );
                assert_eq!(
                    openat(
                        AT_FDCWD,
                        marker_file.as_str(),
                        OFlag::O_WRONLY | OFlag::O_CLOEXEC,
                        Mode::empty()
                    )
                    .unwrap_err(),
                    Errno::EACCES
                );
                assert_eq!(
                    unlinkat(AT_FDCWD, marker_file.as_str(), UnlinkatFlags::NoRemoveDir)
                        .unwrap_err(),
                    Errno::EACCES
                );
                println!("CHECK3_UID601_INTEGRITY_DAC_OK");
                return;
            }
            "cvm-channel-verify" => {
                let work_dir = PathBuf::from(std::env::var(ENV_AUX).unwrap());
                run_cvm_channel_verify_child(&work_dir);
                return;
            }
            "cvm-malicious-ipc" => {
                let state_dir = PathBuf::from(std::env::var(ENV_AUX).unwrap());
                run_cvm_malicious_ipc_child(&state_dir);
                return;
            }
            other => panic!("unknown check3 probe: {other}"),
        }
    }

    let fixtures = BoundaryFixtures::setup();
    let uid600 = qeminga_account("qeminga", 600);
    let marker_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-c3-marker-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let marker_file = marker_dir.path().join("frozen");
    std::fs::write(&marker_file, b"").unwrap();
    chown(marker_dir.path(), Some(uid600.uid), Some(uid600.gid)).unwrap();
    std::fs::set_permissions(marker_dir.path(), Permissions::from_mode(0o700)).unwrap();
    chown(&marker_file, Some(uid600.uid), Some(uid600.gid)).unwrap();
    std::fs::set_permissions(&marker_file, Permissions::from_mode(0o600)).unwrap();

    // 3a. Integrity boundary probes (UID-601 DAC layer + enforced seccomp SIGSYS).
    let dac = run_self_probe(
        "privileged_oq10_check3_integrity_channel_verify_malicious_ipc_and_no_cap_kill",
        "uid601-integrity-dac",
        Some(marker_file.to_str().unwrap()),
    );
    assert!(
        dac.status.success()
            && String::from_utf8_lossy(&dac.stdout).contains("CHECK3_UID601_INTEGRITY_DAC_OK"),
        "check3 UID-601 integrity DAC probe failed: {:?}\nstderr={}",
        dac.status,
        String::from_utf8_lossy(&dac.stderr)
    );
    if is_enforced_seccomp() {
        for probe in [
            "write-uid600",
            "unlink-uid600",
            "write-world",
            "unlink-world",
            "write-marker",
            "unlink-marker",
        ] {
            let out = run_self_probe(
                "privileged_oq10_check3_integrity_channel_verify_malicious_ipc_and_no_cap_kill",
                probe,
                Some(marker_file.to_str().unwrap()),
            );
            assert_sigsys(&out, probe);
        }
    }
    assert!(marker_file.exists(), "marker file must remain intact");

    // 3b. Channel descriptor identity verification under enforcing CVM executor filter.
    let work_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-c3-chan-")
        .tempdir_in("/dev/shm")
        .unwrap();
    std::fs::set_permissions(work_dir.path(), Permissions::from_mode(0o755)).unwrap();
    let chan_out = run_self_probe(
        "privileged_oq10_check3_integrity_channel_verify_malicious_ipc_and_no_cap_kill",
        "cvm-channel-verify",
        Some(work_dir.path().to_str().unwrap()),
    );
    assert!(
        chan_out.status.success()
            && String::from_utf8_lossy(&chan_out.stdout).contains("CVM_CHANNEL_VERIFY_OK"),
        "cvm-channel-verify failed: {:?}\nstdout={}\nstderr={}",
        chan_out.status,
        String::from_utf8_lossy(&chan_out.stdout),
        String::from_utf8_lossy(&chan_out.stderr)
    );

    // 3c. StreamAssembler cmsg/MSG_CTRUNC/MSG_TRUNC fd closure on both peers,
    // plus live enforcing CVM executor + uncooperative SIG_IGN UID-601 mock
    // parser inside a `KillMode=control-group` + `Restart=on-failure` systemd
    // transient unit proving cgroup supervision terminates Generation 1's
    // uncooperative UID-601 parser and empties the cgroup BEFORE Generation 2
    // starts (without `CAP_KILL` on UID 600).
    verify_stream_assembler_cmsg_and_trunc_fd_closure();

    let mal_state_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-c3-mal-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let (mal_out, mal_unit) = run_self_probe_in_cgroup_restart(
        "privileged_oq10_check3_integrity_channel_verify_malicious_ipc_and_no_cap_kill",
        "cvm-malicious-ipc",
        &[(ENV_AUX, mal_state_dir.path().to_str().unwrap())],
    );
    let mal_gen1 =
        std::fs::read_to_string(mal_state_dir.path().join("gen1_result")).unwrap_or_default();
    let mal_gen2 =
        std::fs::read_to_string(mal_state_dir.path().join("gen2_result")).unwrap_or_default();
    assert!(
        mal_out.status.success()
            && mal_gen1.contains("CVM_MALICIOUS_IPC_OK")
            && mal_gen2.contains("GEN2_CLEAN_CGROUP_OK"),
        "cvm-malicious-ipc 2-generation cgroup restart check failed: {:?}\ngen1={mal_gen1}\ngen2={mal_gen2}\nstderr={}\njournal:\n{}",
        mal_out.status,
        String::from_utf8_lossy(&mal_out.stderr),
        unit_journal_tail(&mal_unit)
    );
    let mock_pid: u32 = std::fs::read_to_string(mal_state_dir.path().join("gen1_parser_pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    wait_for_pid_gone(mock_pid, Duration::from_secs(3));

    fixtures.assert_all_intact();
}

// ---- Check 4: Audit-sink isolation probe (unprivileged + privileged) -------

const AUDIT_INJECTION_PARSER_PY: &str = r#"
import os, socket, struct, sys

drop_uid = int(sys.argv[1])
if drop_uid > 0:
    os.setgroups([])
    os.setgid(drop_uid)
    os.setuid(drop_uid)

os.write(5, b"R")
os.close(5)

# Attempt to forge authoritative command_received JSON on stdout (1) and stderr (2).
forged = b'{"event":"command_received","command":"guest-ping","method":"guest-ping","disposition":"allowed","outcome":"allowed","id":9999}\n'
os.write(1, forged)
os.write(2, forged)

# Probe every non-IPC descriptor 4 and 6..64: all must be closed (EBADF).
for fd in [4] + list(range(6, 64)):
    try:
        os.fstat(fd)
    except OSError:
        continue
    else:
        sys.exit(55)

sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_SEQPACKET)
os.close(3)
sock.setblocking(True)

def pkt(session_gen, req_id, opcode, payload):
    hdr = struct.pack("<BQQBBHH", 1, session_gen, req_id, opcode, 0, 0, len(payload))
    return hdr + payload

# 1. Genuine Ping with host_id = 401 (has_host_id = 1, i64 LE 401).
sock.send(pkt(1, 1, 1, b"\x01" + struct.pack("<q", 401)))
r1 = sock.recv(4096)
if len(r1) < 23 or r1[17] != 0x01:
    sys.exit(61)

# 2. ReportParseRejection (opcode 15): kind=2 (UnknownMethod), frame_len=26 (u32 LE),
#    has_id=1 + id=402 (i64 LE), method_tag=1 (Full), method="guest-exec".
method_bytes = b"guest-exec"
rej = (
    struct.pack("<BIBqB", 2, 26, 1, 402, 1)
    + struct.pack("<H", len(method_bytes))
    + method_bytes
)
sock.send(pkt(1, 2, 15, rej))
r2 = sock.recv(4096)
if len(r2) < 23 or r2[17] != 0x0b:
    sys.exit(62)

sock.close()
"#;

async fn run_check4_executor_subprocess(drop_to_uid601: bool) {
    let router = Router::stderr().unwrap();
    let dispatch = tracing::Dispatch::new(qeminga::audit::subscriber(
        tracing::Level::INFO,
        router.clone(),
    ));
    tracing::dispatcher::set_global_default(dispatch).unwrap();

    let state_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-c4-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let marker = Marker::open(state_dir.path().join("frozen")).unwrap();
    let ctx = Arc::new(
        Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            marker,
        )
        .with_kernel(Arc::new(FakeKernel::new())),
    );

    let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
    let drop_arg = if drop_to_uid601 { "601" } else { "0" };
    let mut child = spawn_parser(ParserSpawnSpec {
        exe: PathBuf::from("/usr/bin/python3"),
        args: vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(AUDIT_INJECTION_PARSER_PY),
            OsString::from(drop_arg),
        ],
        parser_ipc: parser_sock,
        initial_channel: None,
        ready_timeout: Duration::from_secs(10),
    })
    .unwrap();

    let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
    let res = serve_ipc_with_backoff(
        Arc::clone(&ctx),
        exec_sock,
        PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
        opener,
        false,
        None,
        false,
        std::future::pending::<&'static str>(),
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_millis(20),
    )
    .await;

    assert!(
        matches!(res, Err(ExecutorExitError::ParserLost)),
        "expected ParserLost after mock parser closed IPC, got {res:?}"
    );
    let wait_status = child.wait().unwrap();
    assert_eq!(
        wait_status,
        nix::sys::wait::WaitStatus::Exited(child.pid(), 0),
        "mock audit-injection parser exited unexpectedly: {wait_status:?}"
    );
    assert!(router.settle(Duration::from_secs(2)));
    println!("CHECK4_EXECUTOR_OK");
    let _ = std::io::stdout().flush();
}

fn verify_check4_captured_stderr(test_name: &str) {
    let out = run_self_probe(test_name, "audit-sink-executor", None);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let logs = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("CHECK4_EXECUTOR_OK"),
        "check4 executor subprocess failed: {:?}\nstdout={stdout}\nstderr={logs}",
        out.status
    );
    assert!(
        !stdout.contains("9999") && !stdout.contains("\"outcome\":\"allowed\""),
        "forged audit payload leaked onto executor stdout: {stdout}"
    );

    let cmd_lines: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("\"event\":\"command_received\""))
        .collect();
    assert_eq!(
        cmd_lines.len(),
        1,
        "must record ONLY the single genuine executor-admitted command (zero forged): {logs}"
    );
    assert!(
        cmd_lines[0].contains("\"method\":\"guest-ping\"")
            && cmd_lines[0].contains("\"id\":401")
            && cmd_lines[0].contains("\"disposition\":\"allowed\""),
        "unexpected command_received record: {}",
        cmd_lines[0]
    );
    assert!(
        !logs.contains("9999") && !logs.contains("\"outcome\":\"allowed\""),
        "forged audit payload leaked into authoritative stderr audit pipe: {logs}"
    );

    let obs_lines: Vec<&str> = logs
        .lines()
        .filter(|l| l.contains("\"event\":\"parser_rejection_observed\""))
        .collect();
    assert_eq!(obs_lines.len(), 1, "expected 1 parser observation: {logs}");
    assert!(
        obs_lines[0].contains("\"source\":\"untrusted_parser\"")
            && obs_lines[0].contains("\"method\":\"guest-exec\"")
            && obs_lines[0].contains("\"id\":402"),
        "unexpected parser_rejection_observed record: {}",
        obs_lines[0]
    );
}

#[tokio::test]
async fn oq10_check4_audit_sink_isolation_probe_unprivileged() {
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        assert_eq!(probe, "audit-sink-executor");
        run_check4_executor_subprocess(false).await;
        return;
    }
    verify_check4_captured_stderr("oq10_check4_audit_sink_isolation_probe_unprivileged");
}

#[tokio::test]
#[ignore = "needs root and qeminga-parser account (OQ-10 §6 Check 4)"]
async fn privileged_oq10_check4_audit_sink_isolation_probe() {
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        assert_eq!(probe, "audit-sink-executor");
        run_check4_executor_subprocess(true).await;
        return;
    }
    let fixtures = BoundaryFixtures::setup();
    verify_check4_captured_stderr("privileged_oq10_check4_audit_sink_isolation_probe");
    fixtures.assert_all_intact();
}

// ---- Check 5: Deterministic reconnect & late-reply isolation (session_gen) -

struct BarrierFreezeKernel {
    inner: FakeKernel,
    entered_tx: Mutex<Option<mpsc::SyncSender<()>>>,
    release_rx: Mutex<Option<mpsc::Receiver<()>>>,
}

impl KernelOps for BarrierFreezeKernel {
    fn open_mount(&self, path: &Path, expected_dev: (u32, u32)) -> Result<Mount, KernelError> {
        self.inner.open_mount(path, expected_dev)
    }

    fn fifreeze(&self, mount: &Mount) -> Result<(), KernelError> {
        let gate = (
            self.entered_tx.lock().unwrap().take(),
            self.release_rx.lock().unwrap().take(),
        );
        if let (Some(entered_tx), Some(release_rx)) = gate {
            let _ = entered_tx.send(());
            // Unblocks either on explicit release or when the driver drops
            // `release_tx` during unwind, so a failed test never hangs.
            let _ = release_rx.recv();
        }
        self.inner.fifreeze(mount)
    }

    fn fithaw(&self, mount: &Mount) -> Result<(), KernelError> {
        self.inner.fithaw(mount)
    }

    fn fitrim(&self, mount: &Mount, minimum: u64) -> Result<Trimmed, KernelError> {
        self.inner.fitrim(mount, minimum)
    }

    fn sync(&self) {
        self.inner.sync();
    }

    fn reboot(&self, cmd: RebootCommand) -> Result<(), KernelError> {
        self.inner.reboot(cmd)
    }
}

async fn run_check5_deterministic_reconnect() {
    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    let dispatch = tracing::Dispatch::new(qeminga::audit::subscriber(
        tracing::Level::INFO,
        router.clone(),
    ));
    tracing::dispatcher::set_global_default(dispatch).unwrap();

    let state_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-c5-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let marker_path = state_dir.path().join("frozen");
    let marker = Marker::open(&marker_path).unwrap();

    let (entered_tx, entered_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let kernel = Arc::new(BarrierFreezeKernel {
        inner: FakeKernel::new(),
        entered_tx: Mutex::new(Some(entered_tx)),
        release_rx: Mutex::new(Some(release_rx)),
    });
    // Enable `information` so session G+1's queued `guest-get-osinfo` (Kind::Ordinary)
    // is authorized by config and waits in ExecutorLaneGate behind session G's freeze.
    let mut cfg = Config::default();
    cfg.features.information = true;
    cfg.agent.fsfreeze_idle_timeout_secs = 30;
    cfg.agent.fsfreeze_max_timeout_secs = 60;
    let ctx = Arc::new(
        Context::new(
            Arc::new(cfg),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            marker,
        )
        .with_kernel(Arc::clone(&kernel) as Arc<dyn KernelOps>)
        .with_mounts(Arc::new(StaticMounts(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n".to_owned(),
        )))
        .with_hooks(Arc::new(LifecycleHooks)),
    );

    let mut pty1 = TestPty::open(false);
    let mut pty2 = TestPty::open(false);
    let pty1_slave = pty1.open_slave_nonblock();
    let pty2_slave_slot = Arc::new(Mutex::new(Some(pty2.open_slave_nonblock())));

    let opener_slot = Arc::clone(&pty2_slave_slot);
    let opener: VerifiedOpenFn = Arc::new(move |path| {
        opener_slot
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| OpenError::NotFound {
                path: path.to_owned(),
            })
    });

    let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();

    let exec_task = tokio::spawn(serve_ipc_with_backoff(
        Arc::clone(&ctx),
        exec_sock,
        PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
        opener,
        true,
        None,
        false,
        async move { stop_rx.await.unwrap_or("SIGTERM") },
        Duration::from_millis(10),
        Duration::from_millis(20),
        Duration::from_millis(20),
    ));

    let parser_thread = std::thread::spawn(move || run_parser_loop(parser_sock, Some(pty1_slave)));

    let ctx_check = Arc::clone(&ctx);
    let marker_check = marker_path.clone();
    tokio::task::spawn_blocking(move || {
        // Session G: send guest-fsfreeze-freeze with id=42 and wait until the
        // executor is inside `fifreeze`.
        pty1.send_line(r#"{"execute":"guest-fsfreeze-freeze","id":42}"#);
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("executor did not enter fifreeze");

        // Disconnect session G completely (closing both master and slave holder
        // yields POLLHUP on the parser's channel fd so it bumps session_gen and
        // sends RequestChannelReopen -> receives pty2_slave via SCM_RIGHTS).
        drop(pty1);

        // Deterministic readiness signal on session G+1: `guest-fsfreeze-status`
        // (Kind::Control) succeeds immediately while session G's freeze is still
        // blocked at the barrier (wire status is "frozen" while internal state
        // is `FreezeState::Freezing`), proving pty2 is installed and live.
        let mut p2_buf = Vec::new();
        assert_eq!(
            pty2.request(
                &mut p2_buf,
                r#"{"execute":"guest-fsfreeze-status","id":100}"#
            ),
            json!({"return": "frozen", "id": 100}),
            "session G+1 must be live while session G's freeze is still blocked"
        );
        assert_eq!(
            ctx_check.state.current(),
            FreezeState::Freezing,
            "session G's freeze must still be in-flight when session G+1 becomes ready"
        );

        // Send a reused-id=42 Ordinary request (`guest-get-osinfo`) followed by
        // a Control probe (`guest-ping`, id=101). Because IPC_FD is ordered:
        //   1. Parser registers (G+1, id=42) in its pending table and sends GetOsInfo(42).
        //   2. Executor parks GetOsInfo(42) in ExecutorLaneGate behind session G's freeze.
        //   3. Executor executes Ping(101) immediately and bumps `ctx.handler_calls()`
        //      (audit lines stay buffered in `Mode::Ring` while Freezing), proving
        //      deterministically that (G+1, id=42) is actively pending in BOTH peers!
        let calls_before = ctx_check.handler_calls();
        pty2.send_line(r#"{"execute":"guest-get-osinfo","id":42}"#);
        pty2.send_line(r#"{"execute":"guest-ping","id":101}"#);
        let deadline = Instant::now() + Duration::from_secs(5);
        while ctx_check.handler_calls() <= calls_before {
            assert!(
                Instant::now() < deadline,
                "executor did not admit trailing Ping(101) behind pending GetOsInfo(42) (calls={})",
                ctx_check.handler_calls()
            );
            std::thread::sleep(Duration::from_millis(2));
        }

        // Release session G's blocked `fifreeze` WHILE (G+1, id=42) is actively
        // pending in the parser: executor finishes session G's freeze, transitions
        // to Frozen, keeps marker & watchdog, sends session G's late `OkCount(1)`
        // (which the parser MUST discard!), and then completes (G+1, id=42) with
        // Frozen followed in wire order by Ping(101).
        release_tx.send(()).unwrap();

        let raw_42 = pty2
            .read_line(&mut p2_buf, Duration::from_secs(10))
            .expect("session G+1 reply for id=42");
        let reply_42: Value = serde_json::from_slice(&raw_42).unwrap();
        assert_eq!(reply_42["id"], 42);
        assert_eq!(
            reply_42["error"]["class"], "GenericError",
            "session G+1 id=42 must receive its own Frozen error, never session G's return:1 ({reply_42})"
        );
        assert!(
            reply_42.get("return").is_none(),
            "stale session G return:1 leaked into session G+1: {reply_42}"
        );

        let raw_101 = pty2
            .read_line(&mut p2_buf, Duration::from_secs(10))
            .expect("session G+1 reply for trailing Ping(101)");
        let reply_101: Value = serde_json::from_slice(&raw_101).unwrap();
        assert_eq!(reply_101, json!({"return": {}, "id": 101}));

        assert_eq!(ctx_check.state.current(), FreezeState::Frozen);
        assert!(
            marker_check.exists(),
            "executor must retain recovery marker after session G disconnect"
        );

        // Confirm executor preserved Frozen state and watchdog, then thaw cleanly.
        assert_eq!(
            pty2.request(
                &mut p2_buf,
                r#"{"execute":"guest-fsfreeze-status","id":43}"#
            ),
            json!({"return": "frozen", "id": 43})
        );
        assert_eq!(
            pty2.request(&mut p2_buf, r#"{"execute":"guest-fsfreeze-thaw","id":44}"#),
            json!({"return": 1, "id": 44})
        );
        assert!(!marker_check.exists(), "thaw must remove recovery marker");
        assert!(
            pty2.read_line(&mut p2_buf, Duration::from_millis(100))
                .is_none(),
            "no stray late reply may appear on session G+1"
        );
        let _ = stop_tx.send("SIGTERM");
        drop(pty2);
    })
    .await
    .unwrap();

    exec_task.await.unwrap().unwrap();
    assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    assert!(router.settle(Duration::from_secs(2)));

    let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let records: Vec<Value> = logs
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<Value>(l)
                .unwrap_or_else(|e| panic!("invalid JSON audit line `{l}`: {e}"))
        })
        .collect();
    let freeze_records = records
        .iter()
        .filter(|r| {
            r["event"] == "command_received"
                && r["method"] == "guest-fsfreeze-freeze"
                && r["id"] == 42
                && r["disposition"] == "allowed"
        })
        .count();
    assert_eq!(
        freeze_records, 1,
        "expected exactly one allowed guest-fsfreeze-freeze command_received record with id=42:\n{logs}"
    );
    let osinfo_records = records
        .iter()
        .filter(|r| {
            r["event"] == "command_received"
                && r["method"] == "guest-get-osinfo"
                && r["id"] == 42
                && r["disposition"] == "denied"
                && r["reason"] == "frozen"
        })
        .count();
    assert_eq!(
        osinfo_records, 1,
        "expected exactly one denied (frozen) guest-get-osinfo command_received record with id=42:\n{logs}"
    );

    // Sub-case B: hold session G+1's normal `guest-ping` (reused id=42) actively
    // pending in `run_parser_loop` while session G's late `OkCount(1)` (and even
    // a stale-generation reply with a colliding req_id) arrives first on IPC_FD.
    tokio::task::spawn_blocking(|| {
        let mut pty1 = TestPty::open(false);
        let mut pty2 = TestPty::open(false);
        let pty1_slave = pty1.open_slave_nonblock();
        let pty2_slave = pty2.open_slave_nonblock();

        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        let flags = OFlag::from_bits_retain(fcntl(parser_sock.as_fd(), FcntlArg::F_GETFL).unwrap());
        fcntl(
            parser_sock.as_fd(),
            FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK),
        )
        .unwrap();

        let parser_thread =
            std::thread::spawn(move || run_parser_loop(parser_sock, Some(pty1_slave)));
        let mut asm = StreamAssembler::new(PeerRole::Executor);

        // 1. Session G sends freeze(id=42); executor holds it without replying yet.
        pty1.send_line(r#"{"execute":"guest-fsfreeze-freeze","id":42}"#);
        let old_req = recv_request(exec_sock.as_fd(), &mut asm).unwrap().unwrap();
        assert_eq!(old_req.request, IpcRequest::FsfreezeFreeze);

        // 2. Disconnect session G and complete RequestChannelReopen with pty2_slave.
        drop(pty1);
        let reopen_req = recv_request(exec_sock.as_fd(), &mut asm).unwrap().unwrap();
        assert_eq!(reopen_req.request, IpcRequest::RequestChannelReopen);
        assert!(reopen_req.session_gen > old_req.session_gen);
        send_response(
            exec_sock.as_fd(),
            reopen_req.session_gen,
            reopen_req.req_id,
            &IpcResponse::OkChannelFd,
            Some(pty2_slave.as_fd()),
        )
        .unwrap();
        drop(pty2_slave);

        // 3. Session G+1 sends normal `guest-ping` reusing `id: 42`; wait until
        //    the executor receives it over IPC_FD (100% guaranteed pending in parser).
        pty2.send_line(r#"{"execute":"guest-ping","id":42}"#);
        let new_ping = recv_request(exec_sock.as_fd(), &mut asm).unwrap().unwrap();
        assert_eq!(new_ping.session_gen, reopen_req.session_gen);
        assert_eq!(new_ping.request, IpcRequest::Ping);

        // 4. Deliver session G's late `OkCount(1)` (and a stale-gen reply reusing
        //    `new_ping.req_id`) BEFORE answering `new_ping` with `OkEmpty`.
        send_response(
            exec_sock.as_fd(),
            old_req.session_gen,
            old_req.req_id,
            &IpcResponse::OkCount(1),
            None,
        )
        .unwrap();
        send_response(
            exec_sock.as_fd(),
            old_req.session_gen,
            new_ping.req_id,
            &IpcResponse::OkCount(99),
            None,
        )
        .unwrap();
        send_response(
            exec_sock.as_fd(),
            new_ping.session_gen,
            new_ping.req_id,
            &IpcResponse::OkEmpty,
            None,
        )
        .unwrap();

        let mut p2_buf = Vec::new();
        let raw = pty2
            .read_line(&mut p2_buf, Duration::from_secs(10))
            .expect("normal guest-ping reply on session G+1");
        let reply: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            reply,
            json!({"return": {}, "id": 42}),
            "session G+1 must receive ONLY its own pending guest-ping reply"
        );
        assert!(
            pty2.read_line(&mut p2_buf, Duration::from_millis(100))
                .is_none(),
            "no stale session G reply may leak to session G+1"
        );

        drop(exec_sock);
        drop(pty2);
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    })
    .await
    .unwrap();
}

fn run_check5_subprocess() {
    let out = run_self_probe(
        "oq10_check5_deterministic_reconnect_and_late_reply_isolation_unprivileged",
        "check5-reconnect",
        None,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("CHECK5_RECONNECT_OK"),
        "check5 reconnect subprocess failed: {:?}\nstdout={stdout}\nstderr={stderr}",
        out.status
    );
}

#[tokio::test]
async fn oq10_check5_deterministic_reconnect_and_late_reply_isolation_unprivileged() {
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        assert_eq!(probe, "check5-reconnect", "unknown check5 probe: {probe}");
        run_check5_deterministic_reconnect().await;
        println!("\nCHECK5_RECONNECT_OK");
        return;
    }
    tokio::task::spawn_blocking(run_check5_subprocess)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "OQ-10 §6 Check 5 privileged runner verification"]
async fn privileged_oq10_check5_deterministic_reconnect_and_late_reply_isolation() {
    let fixtures = BoundaryFixtures::setup();
    // Layer 1: deterministic barrier-synchronized late-reply isolation (pending reused id=42).
    tokio::task::spawn_blocking(run_check5_subprocess)
        .await
        .unwrap();

    // Layer 2: deployed process-pair (QEMINGA_RELEASE_BINARY in enforced CI) real
    // SCM_RIGHTS reconnect under UID 600/601 + enforcing seccomp filters.
    tokio::task::spawn_blocking(|| {
        let mut agent = Agent::spawn_with(cvm_real_kernel(""));
        agent.wait_for_stderr("\"event\":\"privileges_dropped\"", e2e::REPLY_TIMEOUT);
        assert_eq!(
            agent.request(r#"{"execute":"guest-ping","id":501}"#),
            json!({"return": {}, "id": 501})
        );
        let parser_pid = wait_for_parser_child(agent.pid());
        let before = e2e::thread_statuses(parser_pid);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].field("Uid:"), "601\t601\t601\t601");
        if cfg!(feature = "seccomp") {
            assert_eq!(before[0].field("Seccomp:"), "2");
        }

        // Trigger real disconnect + RequestChannelReopen + SCM_RIGHTS handoff,
        // then send a distinct command reusing the exact same QGA id (501).
        agent.reopen_channel();
        assert_eq!(
            agent.request_timeout(
                r#"{"execute":"guest-fsfreeze-status","id":501}"#,
                e2e::REOPEN_TIMEOUT
            ),
            json!({"return": "thawed", "id": 501})
        );
        assert_eq!(
            agent.request(r#"{"execute":"guest-ping","id":502}"#),
            json!({"return": {}, "id": 502})
        );
        assert_eq!(
            wait_for_parser_child(agent.pid()),
            parser_pid,
            "parser child must survive ordinary channel reconnect without respawning"
        );
        assert!(agent.stop().success());
        wait_for_pid_gone(parser_pid, Duration::from_secs(5));
    })
    .await
    .unwrap();

    fixtures.assert_all_intact();
}

// ---- Check 6: Large payloads, GetOsInfo (>32 KiB) & mixed-outcome Fstrim ---

struct LargeOsInfo {
    pretty_name: String,
}

impl OsInfoSource for LargeOsInfo {
    fn uname(&self) -> Result<Uname, ProtoError> {
        Ok(Uname {
            release: "6.8.0-oq10".to_owned(),
            version: "#1 SMP".to_owned(),
            machine: std::env::consts::ARCH.to_owned(),
        })
    }

    fn os_release(&self) -> Option<String> {
        Some(format!(
            "ID=qeminga-test\nNAME=QemingaTest\nPRETTY_NAME=\"{}\"\n",
            self.pretty_name
        ))
    }
}

async fn run_check6_large_payloads() {
    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    let dispatch = tracing::Dispatch::new(qeminga::audit::subscriber(
        tracing::Level::INFO,
        router.clone(),
    ));
    tracing::dispatcher::set_global_default(dispatch).unwrap();

    // --- Sub-check 6a(i) + 6b + 6c:
    //   - `guest-get-fsinfo` > 256 KiB and <= 1 MiB across multi-chunk IPC
    //   - `guest-fsfreeze-freeze-list` with 300 short mount names (< 64 KiB) +
    //     omitted vs `[]` vs unauthorized-only vs mixed under #63 allowlist
    //   - `guest-get-osinfo` with 48 KiB PRETTY_NAME (> 32 KiB single-chunk
    //     boundary, <= 128 KiB IPC cap) + follow-up `guest-ping`
    {
        let mut table = String::from("1 0 8:0 / / rw - ext4 /dev/vda0 rw\n");
        let long_seg = "x".repeat(120);
        // 1600 mounts x ~220 B JSON each ≈ 350 KiB (> 256 KiB, <= 1 MiB).
        for i in 1..=1600u32 {
            let _ = writeln!(
                table,
                "{} 1 253:{i} / /vol-{i:04}-{long_seg} rw - ext4 /dev/vdb{i} rw",
                10 + i
            );
        }
        // Two short allowlisted mounts for #63 freeze-list checks.
        let _ = writeln!(table, "9001 1 254:1 / /m0 rw - ext4 /dev/vdc0 rw");
        let _ = writeln!(table, "9002 1 254:2 / /m1 rw - ext4 /dev/vdc1 rw");
        for i in 2..=10u32 {
            let _ = writeln!(
                table,
                "{} 1 254:{i} / /u{i} rw - ext4 /dev/vdc{i} rw",
                9000 + i
            );
        }

        let mut cfg = Config::default();
        cfg.features.information = true;
        cfg.features.fstrim = true;
        cfg.agent.freeze_allowed_mountpoints = Some(vec!["/m0".to_owned(), "/m1".to_owned()]);
        cfg.rate_limits.fsfreeze_freeze_per_min = 100;
        cfg.rate_limits.get_commands_per_min = 100;
        cfg.rate_limits.ping_sync_per_min = 100;

        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-oq10-c6a-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker = Marker::open(state_dir.path().join("frozen")).unwrap();
        let pretty_48k = "P".repeat(48 * 1024);
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                router.clone(),
                marker,
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table)))
            .with_statfs(Arc::new(StaticStatfs))
            .with_osinfo(Arc::new(LargeOsInfo {
                pretty_name: pretty_48k.clone(),
            })),
        );

        let mut pty = TestPty::open(false);
        let pty_slave = pty.open_slave_nonblock();
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            Arc::clone(&ctx),
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            true,
            None,
            false,
            async move { stop_rx.await.unwrap_or("SIGTERM") },
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(20),
        ));
        let parser_thread =
            std::thread::spawn(move || run_parser_loop(parser_sock, Some(pty_slave)));

        tokio::task::spawn_blocking(move || {
            let mut buf = Vec::new();

            // 6a(i): `guest-get-fsinfo` > 256 KiB and <= 1 MiB.
            pty.send_line(r#"{"execute":"guest-get-fsinfo","id":601}"#);
            let raw = pty
                .read_line(&mut buf, Duration::from_secs(15))
                .expect("fsinfo > 256 KiB reply");
            assert!(
                raw.len() > 256 * 1024 && raw.len() <= 1024 * 1024,
                "expected 256 KiB < fsinfo <= 1 MiB, got {} bytes",
                raw.len()
            );
            let fsinfo: Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(fsinfo["id"], 601);
            assert!(
                fsinfo["return"].as_array().unwrap().len() >= 1600,
                "fsinfo must not truncate entries"
            );

            // 6b: `guest-fsfreeze-freeze-list` with 300 short mountpoint names
            // (> 256 entries inside 64 KiB frame) + #63 allowlist filtering.
            let mut list_300 = vec!["/m0".to_owned(), "/m1".to_owned()];
            for i in 2..300 {
                list_300.push(format!("/u{i}"));
            }
            let req_300 = json!({
                "execute": "guest-fsfreeze-freeze-list",
                "arguments": { "mountpoints": list_300 },
                "id": 602
            })
            .to_string();
            assert!(req_300.len() < 64 * 1024);
            assert_eq!(
                pty.request(&mut buf, &req_300),
                json!({"return": 2, "id": 602}),
                "300-entry mixed list must freeze only the 2 allowlisted targets"
            );
            assert_eq!(
                pty.request(&mut buf, r#"{"execute":"guest-fsfreeze-thaw","id":603}"#),
                json!({"return": 2, "id": 603})
            );

            // Explicit empty `mountpoints: []` -> 0 and stays Thawed.
            assert_eq!(
                pty.request(
                    &mut buf,
                    r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]},"id":604}"#
                ),
                json!({"return": 0, "id": 604})
            );
            assert_eq!(
                pty.request(&mut buf, r#"{"execute":"guest-fsfreeze-status","id":605}"#),
                json!({"return": "thawed", "id": 605})
            );

            // Unauthorized-only list -> guest-independent 0 and stays Thawed.
            assert_eq!(
                pty.request(
                    &mut buf,
                    r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/u2","/u3"]},"id":606}"#
                ),
                json!({"return": 0, "id": 606})
            );
            assert_eq!(
                pty.request(&mut buf, r#"{"execute":"guest-fsfreeze-status","id":607}"#),
                json!({"return": "thawed", "id": 607})
            );

            // Omitted `mountpoints` field -> freezes only the #63 allowlist (2).
            assert_eq!(
                pty.request(
                    &mut buf,
                    r#"{"execute":"guest-fsfreeze-freeze-list","id":608}"#
                ),
                json!({"return": 2, "id": 608})
            );
            assert_eq!(
                pty.request(&mut buf, r#"{"execute":"guest-fsfreeze-thaw","id":609}"#),
                json!({"return": 2, "id": 609})
            );

            // 6c: Opted-in `guest-get-osinfo` with 48 KiB PRETTY_NAME (> 32 KiB
            // single-chunk boundary) + follow-up `guest-ping` on same connection.
            let osinfo = pty.request(&mut buf, r#"{"execute":"guest-get-osinfo","id":610}"#);
            assert_eq!(osinfo["id"], 610);
            assert_eq!(osinfo["return"]["pretty-name"], pretty_48k);
            assert_eq!(
                pty.request(&mut buf, r#"{"execute":"guest-ping","id":611}"#),
                json!({"return": {}, "id": 611})
            );

            let _ = stop_tx.send("SIGTERM");
            drop(pty);
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    }

    // --- Sub-check 6a(ii) + 6d:
    //   - `guest-get-fsinfo` > 1 MiB -> GenericError (never truncated), session intact
    //   - mixed-outcome `guest-fstrim` > 1 MiB (4999 ok, 1 open ENOENT, 1 ioctl
    //     EOPNOTSUPP) -> fixed GenericError with exact `trimmed 4999 target(s) (2 failed)`,
    //     bounded local audit, and intact IPC session (`guest-ping` succeeds).
    {
        let mut table = String::from("1 0 8:0 / / rw - ext4 /dev/vda0 rw\n");
        let long_seg = "y".repeat(220);
        // 5000 extra ext4 mounts (plus `/`) => 5001 targets, > 1 MiB for both
        // fsinfo and fstrim replies.
        for i in 0..5000u32 {
            let _ = writeln!(
                table,
                "{} 1 253:{i} / /trim-{i:04}-{long_seg} rw - ext4 /dev/vdb{i} rw",
                10 + i
            );
        }

        assert!(router.settle(Duration::from_secs(2)));
        sink.0.lock().unwrap().clear();

        let kernel = Arc::new(FakeKernel::new());
        // Root `/` + 4998 other mounts succeed (4999 trimmed);
        // mount 0 fails open (ENOENT, no FITRIM issued);
        // mount 1 fails FITRIM ioctl (EOPNOTSUPP).
        kernel.script_open_error(format!("/trim-0000-{long_seg}"), Errno::ENOENT);
        kernel.script_trim(format!("/trim-0001-{long_seg}"), Err(Errno::EOPNOTSUPP));

        let mut cfg = Config::default();
        cfg.features.information = true;
        cfg.features.fstrim = true;
        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-oq10-c6d-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker = Marker::open(state_dir.path().join("frozen")).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                router.clone(),
                marker,
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table)))
            .with_statfs(Arc::new(StaticStatfs)),
        );

        let mut pty = TestPty::open(false);
        let pty_slave = pty.open_slave_nonblock();
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            Arc::clone(&ctx),
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            true,
            None,
            false,
            async move { stop_rx.await.unwrap_or("SIGTERM") },
            Duration::from_millis(10),
            Duration::from_millis(20),
            Duration::from_millis(20),
        ));
        let parser_thread =
            std::thread::spawn(move || run_parser_loop(parser_sock, Some(pty_slave)));

        tokio::task::spawn_blocking(move || {
            let mut buf = Vec::new();

            // 6a(ii): over-1 MiB `guest-get-fsinfo` -> GenericError, never truncated.
            let over_fs = pty.request(&mut buf, r#"{"execute":"guest-get-fsinfo","id":620}"#);
            assert_eq!(over_fs["id"], 620);
            assert_eq!(over_fs["error"]["class"], "GenericError", "{over_fs}");
            let desc = over_fs["error"]["desc"].as_str().unwrap_or("");
            assert!(
                desc.contains("1048576") || desc.contains("1 MiB"),
                "oversize fsinfo error must name bound: {over_fs}"
            );

            // 6d: mixed-outcome over-1 MiB `guest-fstrim` -> exact counts, intact session.
            let over_trim = pty.request(&mut buf, r#"{"execute":"guest-fstrim","id":621}"#);
            assert_eq!(over_trim["id"], 621);
            assert_eq!(over_trim["error"]["class"], "GenericError", "{over_trim}");
            let trim_desc = over_trim["error"]["desc"].as_str().unwrap_or("");
            assert!(
                trim_desc.contains("trimmed 4999 target(s) (2 failed)"),
                "mixed-outcome fstrim error must report exact 4999 trimmed / 2 failed: {over_trim}"
            );
            assert!(
                !trim_desc.contains("/trim-"),
                "oversize fstrim error must not emit partial paths: {over_trim}"
            );

            // IPC session and executor state remain completely intact.
            assert_eq!(
                pty.request(&mut buf, r#"{"execute":"guest-ping","id":622}"#),
                json!({"return": {}, "id": 622})
            );

            let _ = stop_tx.send("SIGTERM");
            drop(pty);
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
        assert!(router.settle(Duration::from_secs(2)));

        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("\"event\":\"fstrim_reply_too_large\""),
            "expected bounded fstrim_reply_too_large summary record: {logs}"
        );
        assert!(
            !logs.contains("\"event\":\"ipc_protocol_violation\""),
            "oversize fstrim must never be treated as ipc_protocol_violation: {logs}"
        );
    }
}

fn run_check6_subprocess() {
    let out = run_self_probe(
        "oq10_check6_large_payloads_osinfo_and_mixed_outcome_fstrim_unprivileged",
        "check6-large-payloads",
        None,
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("CHECK6_LARGE_PAYLOADS_OK"),
        "check6 large-payload subprocess failed: {:?}\nstdout={stdout}\nstderr={stderr}",
        out.status
    );
}

#[tokio::test]
async fn oq10_check6_large_payloads_osinfo_and_mixed_outcome_fstrim_unprivileged() {
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        assert_eq!(
            probe, "check6-large-payloads",
            "unknown check6 probe: {probe}"
        );
        run_check6_large_payloads().await;
        println!("\nCHECK6_LARGE_PAYLOADS_OK");
        return;
    }
    tokio::task::spawn_blocking(run_check6_subprocess)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "OQ-10 §6 Check 6 privileged runner verification"]
async fn privileged_oq10_check6_large_payloads_osinfo_and_mixed_outcome_fstrim() {
    let fixtures = BoundaryFixtures::setup();
    // Layer 1: deterministic synthetic large-payload bounds (>256 KiB & >1 MiB
    // fsinfo, >256-entry freeze-list + #63, 48 KiB os-release > 32 KiB chunk,
    // 5001-target mixed-outcome >1 MiB fstrim).
    tokio::task::spawn_blocking(run_check6_subprocess)
        .await
        .unwrap();

    // Layer 2: deployed process-pair (QEMINGA_RELEASE_BINARY in enforced CI)
    // exercising multi-chunk (>32 KiB, >256-entry) freeze-list + #63 allowlist
    // and opted-in inventory traffic under UID 600/601 + enforcing seccomp.
    tokio::task::spawn_blocking(|| {
        let ext4 = ext4_mount();
        let _thaw = ThawGuard::new(std::slice::from_ref(&ext4));
        let mut agent = Agent::spawn_with(SpawnOptions {
            fake_kernel: false,
            agent_extra: format!("freeze_allowed_mountpoints = [\"{ext4}\"]\n"),
            features_extra: "shutdown = false\ninformation = true\nfstrim = false\n".to_owned(),
            enforce_hardening: is_enforced_seccomp(),
            binary: release_or_test_binary(),
            ..Default::default()
        });
        agent.wait_for_stderr("\"event\":\"privileges_dropped\"", e2e::REPLY_TIMEOUT);

        // Multi-chunk IPC request: 301 mountpoints totaling > 32 KiB (spanning
        // 2 SOCK_SEQPACKET chunks from parser -> executor while staying < 64 KiB).
        let pad = "a".repeat(100);
        let mut list_multichunk = vec![ext4.clone()];
        for i in 0..300u32 {
            list_multichunk.push(format!("/oq10-unauth-{pad}-{i:03}"));
        }
        let req = json!({
            "execute": "guest-fsfreeze-freeze-list",
            "arguments": { "mountpoints": list_multichunk },
            "id": 650
        })
        .to_string();
        assert!(
            req.len() > 32 * 1024 && req.len() < 64 * 1024,
            "expected multi-chunk (>32 KiB, <64 KiB) freeze-list frame, got {} bytes",
            req.len()
        );
        assert_eq!(
            agent.request(&req),
            json!({"return": 1, "id": 650}),
            "deployed process pair must reassemble multi-chunk freeze-list and filter to allowlisted ext4"
        );
        assert_eq!(
            agent.request(r#"{"execute":"guest-fsfreeze-thaw","id":651}"#),
            json!({"return": 1, "id": 651})
        );
        assert_eq!(
            agent.request(
                r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":[]},"id":652}"#
            ),
            json!({"return": 0, "id": 652})
        );
        assert_eq!(
            agent.request(
                r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/oq10-unauth-only"]},"id":653}"#
            ),
            json!({"return": 0, "id": 653})
        );

        // Opted-in inventory commands across the deployed enforcing process pair.
        let osinfo = agent.request(r#"{"execute":"guest-get-osinfo","id":654}"#);
        assert!(
            osinfo["return"].is_object(),
            "expected osinfo object: {osinfo}"
        );
        let ifaces = agent.request(r#"{"execute":"guest-network-get-interfaces","id":655}"#);
        assert!(
            ifaces["return"].is_array(),
            "expected interfaces array: {ifaces}"
        );
        let fsinfo = agent.request(r#"{"execute":"guest-get-fsinfo","id":656}"#);
        assert!(
            fsinfo["return"].is_array(),
            "expected fsinfo array: {fsinfo}"
        );
        assert_eq!(
            agent.request(r#"{"execute":"guest-ping","id":657}"#),
            json!({"return": {}, "id": 657})
        );

        // Even with `information = true`, the parser child retains identical
        // zero-capability UID-601 seccomp confinement.
        let parser_pid = wait_for_parser_child(agent.pid());
        let threads = e2e::thread_statuses(parser_pid);
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].name, "qeminga-parser");
        assert_eq!(threads[0].field("Uid:"), "601\t601\t601\t601");
        for set in ["CapEff:", "CapPrm:", "CapBnd:", "CapInh:", "CapAmb:"] {
            assert_eq!(threads[0].field(set), "0000000000000000", "{set}");
        }
        assert_eq!(threads[0].field("NoNewPrivs:"), "1");
        if cfg!(feature = "seccomp") {
            assert_eq!(threads[0].field("Seccomp:"), "2");
        }
        assert!(agent.stop().success());
        wait_for_pid_gone(parser_pid, Duration::from_secs(5));
    })
    .await
    .unwrap();

    fixtures.assert_all_intact();
}

// ---- Check 7: Authorized freeze/thaw + CVM recovery + policy narrowing -----

const FREEZE_THEN_VIOLATE_PARSER_PY: &str = r#"
import os, signal, socket, struct, sys, time, ctypes

expected_ppid = int(sys.argv[1])
mount_path = sys.argv[2].encode("utf-8")

os.setgroups([])
os.setgid(601)
os.setuid(601)

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
if libc.prctl(1, 9, 0, 0, 0) != 0:
    sys.exit(21)
if os.getppid() != expected_ppid:
    sys.exit(0)

signal.signal(signal.SIGTERM, signal.SIG_IGN)
os.write(5, b"R")
os.close(5)

sock = socket.fromfd(3, socket.AF_UNIX, socket.SOCK_SEQPACKET)
os.close(3)
sock.setblocking(True)

def pkt(session_gen, req_id, opcode, payload):
    hdr = struct.pack("<BQQBBHH", 1, session_gen, req_id, opcode, 0, 0, len(payload))
    return hdr + payload

# 1. Freeze the real loop mountpoint via FsfreezeFreezeList (opcode 7).
#    HostIdPrefix=0, has_list=1, count=1, len(u16 LE), mount_path bytes.
payload = struct.pack("<BBHH", 0, 1, 1, len(mount_path)) + mount_path
sock.send(pkt(1, 1, 7, payload))
reply = sock.recv(4096)
# OkCount = 0x05, count(u64 LE) == 1 at offset 23.
if len(reply) < 31 or reply[17] != 0x05:
    sys.exit(71)
(count,) = struct.unpack("<Q", reply[23:31])
if count != 1:
    sys.exit(72)

# 2. Trigger ipc_protocol_violation (invalid version 99) while Frozen.
sock.send(bytes([99] * 23))

# Stay alive uncooperatively until executor finishes watchdog thaw and exits.
time.sleep(60)
"#;

fn run_cvm_violation_while_frozen_child(mount: &str, state_dir: &Path) {
    if state_dir.join("gen1_parser_pid").exists() {
        verify_prev_generation_reaped_before_restart(state_dir, "CVM_VIOLATION_FROZEN_OK");
        return;
    }

    let uid600 = qeminga_account("qeminga", 600);
    let _uid601 = qeminga_account("qeminga-parser", 601);

    let (exec_raw, parser_sock) = seqpacket_pair(true).unwrap();
    let exec_sock = pin_unused_fd_cloexec(exec_raw, IPC_FD).unwrap();
    assert_eq!(exec_sock.as_raw_fd(), IPC_FD);

    let my_pid = std::process::id().to_string();
    let child = spawn_parser(ParserSpawnSpec {
        exe: PathBuf::from("/usr/bin/python3"),
        args: vec![
            OsString::from("/usr/bin/python3"),
            OsString::from("-c"),
            OsString::from(FREEZE_THEN_VIOLATE_PARSER_PY),
            OsString::from(my_pid),
            OsString::from(mount),
        ],
        parser_ipc: parser_sock,
        initial_channel: None,
        ready_timeout: Duration::from_secs(10),
    })
    .unwrap();
    let child_pid = child.pid().as_raw();
    std::fs::write(state_dir.join("gen1_parser_pid"), format!("{child_pid}\n")).unwrap();
    let mut gen1_result = File::create(state_dir.join("gen1_result")).unwrap();

    chown(state_dir, Some(uid600.uid), Some(uid600.gid)).unwrap();
    let marker_path = state_dir.join("frozen");
    let marker = Marker::open(&marker_path).unwrap();

    drop_privileges_to(uid600, &SystemCaps, &Authority::data_protection()).unwrap();
    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    install_cvm_executor_seccomp();

    let mut cfg = Config::default();
    cfg.features.shutdown = false;
    cfg.features.information = false;
    cfg.features.fstrim = false;
    cfg.agent.fsfreeze_idle_timeout_secs = 2;
    cfg.agent.fsfreeze_max_timeout_secs = 5;
    cfg.agent.freeze_allowed_mountpoints = Some(vec![mount.to_owned()]);

    let ctx = Arc::new(
        Context::new(
            Arc::new(cfg),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            marker,
        )
        .with_kernel(Arc::new(LinuxKernel))
        .with_hooks(Arc::new(LifecycleHooks)),
    );
    let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
    let dispatch = tracing::Dispatch::new(qeminga::audit::subscriber(
        tracing::Level::INFO,
        router.clone(),
    ));
    tracing::dispatcher::set_global_default(dispatch).unwrap();

    let started = Instant::now();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let exit = rt.block_on(serve_ipc_with_backoff(
        Arc::clone(&ctx),
        exec_sock,
        PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
        opener,
        false,
        Some(child),
        false,
        std::future::pending::<&'static str>(),
        Duration::from_millis(20),
        Duration::from_millis(50),
        Duration::from_millis(25),
    ));
    let elapsed = started.elapsed();

    assert!(
        matches!(exit, Err(ExecutorExitError::ProtocolViolation(_))),
        "expected ProtocolViolation after watchdog thaw, got {exit:?}"
    );
    assert!(
        elapsed >= Duration::from_millis(1500),
        "executor must stay alive while Frozen until watchdog thaws (elapsed={elapsed:?})"
    );
    assert_eq!(ctx.state.current(), FreezeState::Thawed);
    assert!(
        !marker_path.exists(),
        "watchdog thaw must remove recovery marker before executor exits"
    );
    assert!(router.settle(Duration::from_secs(2)));
    let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("\"event\":\"ipc_protocol_violation\"")
            && logs.contains("\"event\":\"watchdog_thaw\"")
            && logs.contains("\"event\":\"fsfreeze_thawed\""),
        "expected protocol violation, watchdog_thaw, and fsfreeze_thawed in logs:\n{logs}"
    );
    writeln!(gen1_result, "CVM_VIOLATION_FROZEN_OK").unwrap();
    gen1_result.flush().unwrap();
    std::process::exit(43);
}

#[test]
#[ignore = "needs root and loop ext4/xfs filesystems (OQ-10 §6 Check 7)"]
fn privileged_oq10_check7_authorized_freeze_thaw_cvm_recovery_policy_narrowing_and_intact_fixtures()
{
    if let Ok(probe) = std::env::var(ENV_PROBE) {
        if probe == "cvm-violation-while-frozen" {
            let mount = std::env::var(ENV_AUX).expect("ENV_AUX must carry mount");
            let state_dir = std::env::var(ENV_AUX2).expect("ENV_AUX2 must carry state_dir");
            run_cvm_violation_while_frozen_child(&mount, Path::new(&state_dir));
            return;
        }
        panic!("unknown check7 probe: {probe}");
    }

    let fixtures = BoundaryFixtures::setup();
    let ext4 = ext4_mount();
    let second = SecondFs::new();
    let second_mount = second.mount.clone();

    // Create a mode-0700 root:root private bind mount of the real ext4 loop fs
    // BEFORE `_thaw` so LIFO unwinding drops `_thaw` first (thawing both
    // superblocks) before `PrivateBindMount::drop` unmounts and removes its
    // backing directory on ext4.
    let base = Path::new(&ext4).parent().unwrap().to_path_buf();
    let protected_bind = PrivateBindMount::create(&ext4, &base, 0o700);
    let protected_mount = protected_bind.path().to_str().unwrap().to_owned();
    let _thaw = ThawGuard::new(&[ext4.clone(), second_mount.clone()]);
    assert_eq!(
        std::fs::metadata(&protected_mount).unwrap().mode() & 0o777,
        0o700
    );

    let both_cfg = format!(
        "fsfreeze_idle_timeout_secs = 2\nfsfreeze_max_timeout_secs = 5\nfreeze_allowed_mountpoints = [\"{protected_mount}\", \"{second_mount}\"]\n"
    );
    let narrowed_cfg = format!(
        "fsfreeze_idle_timeout_secs = 2\nfsfreeze_max_timeout_secs = 5\nfreeze_allowed_mountpoints = [\"{protected_mount}\"]\n"
    );
    const WRITE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

    // 1. Real SCM_RIGHTS channel handoff (initial + RequestChannelReopen) + ping.
    let mut agent = Agent::spawn_with(cvm_real_kernel(&both_cfg));
    assert_eq!(agent.execute("guest-ping")["return"], json!({}));
    agent.reopen_channel();
    assert_eq!(
        agent.request_timeout(r#"{"execute":"guest-ping"}"#, e2e::REOPEN_TIMEOUT)["return"],
        json!({})
    );

    // 2. Freeze real 0700 ext4 + second fs -> exact count 2, marker owned by UID 600.
    assert_eq!(
        freeze_list(&mut agent, &[protected_mount.clone(), second_mount.clone()]),
        json!({"return": 2})
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    let marker_meta = std::fs::metadata(agent.state_dir().join("frozen")).unwrap();
    assert_eq!(
        marker_meta.uid(),
        600,
        "recovery marker must be created by executor UID 600"
    );

    // 3a. SIGKILL parser child while Frozen -> executor keeps Frozen + marker +
    //     watchdog running, reaps via wait4, autonomously thaws at idle expiry,
    //     removes marker, makes both mounts writable, and ONLY THEN exits non-zero.
    let parser_pid = wait_for_parser_child(agent.pid());
    kill(Pid::from_raw(parser_pid as i32), Signal::SIGKILL).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        agent.is_running(),
        "executor must NOT exit prematurely while filesystems are frozen"
    );
    assert!(agent.state_dir().join("frozen").exists());
    let exit_status = agent
        .wait_exit(Duration::from_secs(12))
        .expect("executor must exit non-zero once watchdog thaw completes");
    assert!(
        !exit_status.success(),
        "executor must exit non-zero after parser SIGKILL + watchdog thaw: {exit_status}"
    );
    assert!(
        !agent.state_dir().join("frozen").exists(),
        "watchdog must remove recovery marker before executor exits"
    );
    assert_writable_within(
        &protected_mount,
        "after-sigkill-watchdog (protected)",
        WRITE_PROBE_TIMEOUT,
    );
    assert_writable_within(
        &second_mount,
        "after-sigkill-watchdog (second)",
        WRITE_PROBE_TIMEOUT,
    );
    wait_for_pid_gone(parser_pid, Duration::from_secs(5));
    drop(agent);

    // 3b. ipc_protocol_violation while Frozen under enforcing CVM executor filter
    //     inside a `KillMode=control-group` + `Restart=on-failure` + `RuntimeMaxSec=30s`
    //     systemd transient unit -> Generation 1 closes IPC_FD, keeps watchdog +
    //     marker alive until autonomous thaw completes, exits non-zero, and
    //     systemd cgroup supervision terminates the sleeping SIG_IGN UID-601
    //     mock parser and empties the cgroup BEFORE Generation 2 starts (without
    //     CAP_KILL on UID 600).
    let viol_state_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-c7v-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let (viol, viol_unit) = run_self_probe_in_cgroup_restart(
        "privileged_oq10_check7_authorized_freeze_thaw_cvm_recovery_policy_narrowing_and_intact_fixtures",
        "cvm-violation-while-frozen",
        &[
            (ENV_AUX, &protected_mount),
            (ENV_AUX2, viol_state_dir.path().to_str().unwrap()),
        ],
    );
    let viol_gen1 =
        std::fs::read_to_string(viol_state_dir.path().join("gen1_result")).unwrap_or_default();
    let viol_gen2 =
        std::fs::read_to_string(viol_state_dir.path().join("gen2_result")).unwrap_or_default();
    assert!(
        viol.status.success()
            && viol_gen1.contains("CVM_VIOLATION_FROZEN_OK")
            && viol_gen2.contains("GEN2_CLEAN_CGROUP_OK"),
        "cvm-violation-while-frozen 2-generation cgroup restart check failed: {:?}\ngen1={viol_gen1}\ngen2={viol_gen2}\nstderr={}\njournal:\n{}",
        viol.status,
        String::from_utf8_lossy(&viol.stderr),
        unit_journal_tail(&viol_unit)
    );
    let viol_parser_pid: u32 =
        std::fs::read_to_string(viol_state_dir.path().join("gen1_parser_pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
    wait_for_pid_gone(viol_parser_pid, Duration::from_secs(3));
    assert_writable_within(
        &protected_mount,
        "after-violation-watchdog (protected)",
        WRITE_PROBE_TIMEOUT,
    );

    // 4. Policy narrowing across crash/restart:
    //    Freeze BOTH mounts, SIGKILL executor, restart with policy narrowed to
    //    `[protected_mount]` only -> recovery thaw drains BOTH superblocks before
    //    removing marker while reporting ONLY current policy's count `1` on wire!
    let mut agent = Agent::spawn_with(cvm_real_kernel(&both_cfg));
    assert_eq!(
        freeze_list(&mut agent, &[protected_mount.clone(), second_mount.clone()]),
        json!({"return": 2})
    );
    let saved_state_dir = agent.kill();
    assert!(saved_state_dir.path().join("frozen").exists());

    let mut agent = Agent::spawn_with(SpawnOptions {
        state_dir: Some(saved_state_dir),
        ..cvm_real_kernel(&narrowed_cfg)
    });
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert_eq!(
        agent.execute("guest-fsfreeze-thaw"),
        json!({"return": 1}),
        "wire thaw count after policy narrowing must report ONLY current policy count (1)"
    );
    assert!(!agent.state_dir().join("frozen").exists());
    // Both superblocks must actually be thawed and writable!
    assert_writable_within(
        &protected_mount,
        "after-narrowing (protected)",
        WRITE_PROBE_TIMEOUT,
    );
    assert_writable_within(
        &second_mount,
        "after-narrowing (second)",
        WRITE_PROBE_TIMEOUT,
    );
    assert!(agent.stop().success());

    // 5. Cooperative ownership (#69) preservation alongside a foreign-frozen fs:
    //    Foreign freezer claims + freezes `second_mount`; qeminga freezes
    //    `protected_mount`, crashes, restarts with narrowed/same policy, thaws
    //    ONLY its own freeze, removes marker, and leaves `second_mount` frozen
    //    with foreign ownership intact.
    let uid600 = qeminga_account("qeminga", 600);
    let own_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-own-")
        .tempdir_in("/dev/shm")
        .unwrap();
    chown(own_dir.path(), Some(Uid::from_raw(0)), Some(uid600.gid)).unwrap();
    std::fs::set_permissions(own_dir.path(), Permissions::from_mode(0o3770)).unwrap();

    let own_store = LinuxOwnershipStore::open(own_dir.path()).unwrap();
    let second_dev = dev_of(Path::new(&second_mount));
    assert!(own_store.claim_as("foreign-freezer", second_dev).unwrap());
    let second_handle = handle(Path::new(&second_mount));
    LinuxKernel.fifreeze(&second_handle).unwrap();

    let coop_cfg = format!(
        "fsfreeze_idle_timeout_secs = 30\nfsfreeze_max_timeout_secs = 60\nfreeze_ownership_dir = \"{}\"\nfreeze_allowed_mountpoints = [\"{protected_mount}\", \"{second_mount}\"]\n",
        own_dir.path().display()
    );
    let mut agent = Agent::spawn_with(cvm_real_kernel(&coop_cfg));
    assert_eq!(
        freeze_list(&mut agent, &[protected_mount.clone(), second_mount.clone()]),
        json!({"return": 1}),
        "cooperative mode must freeze only qeminga-claimable protected_mount and skip foreign-owned second_mount"
    );
    let coop_state_dir = agent.kill();
    assert!(coop_state_dir.path().join("frozen").exists());

    let mut agent = Agent::spawn_with(SpawnOptions {
        state_dir: Some(coop_state_dir),
        ..cvm_real_kernel(&coop_cfg)
    });
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert_eq!(
        agent.execute("guest-fsfreeze-thaw"),
        json!({"return": 1}),
        "cooperative recovery thaw must drain only qeminga-owned superblock"
    );
    assert!(!agent.state_dir().join("frozen").exists());
    assert_writable_within(
        &protected_mount,
        "after-coop (protected)",
        WRITE_PROBE_TIMEOUT,
    );
    // Foreign-owned `second_mount` MUST still be frozen (EBUSY on FIFREEZE)
    // and retain its foreign owner claim!
    assert!(
        matches!(
            LinuxKernel.fifreeze(&second_handle),
            Err(KernelError::Errno(Errno::EBUSY))
        ),
        "cooperative recovery must never thaw a foreign-owned filesystem"
    );
    assert_eq!(
        own_store.inspect(second_dev).unwrap(),
        TargetOwnership::OwnedByOther {
            owner: "foreign-freezer".to_owned()
        }
    );
    assert!(agent.stop().success());

    // Release foreign freeze & claim before final normal freeze/thaw cycle.
    LinuxKernel.fithaw(&second_handle).unwrap();
    std::fs::remove_file(
        own_dir
            .path()
            .join(qeminga::ownership::format_dev_filename(second_dev)),
    )
    .unwrap();
    assert_writable_within(
        &second_mount,
        "after-foreign-thaw (second)",
        WRITE_PROBE_TIMEOUT,
    );

    // 6. Final normal freeze -> thaw cycle + intact-fixture byte/inode/mtime check.
    let mut agent = Agent::spawn_with(cvm_real_kernel(&both_cfg));
    assert_eq!(
        freeze_list(&mut agent, &[protected_mount.clone(), second_mount.clone()]),
        json!({"return": 2})
    );
    assert_eq!(agent.execute("guest-fsfreeze-status")["return"], "frozen");
    assert_eq!(agent.execute("guest-fsfreeze-thaw"), json!({"return": 2}));
    assert!(!agent.state_dir().join("frozen").exists());
    assert_writable_within(
        &protected_mount,
        "after-final (protected)",
        WRITE_PROBE_TIMEOUT,
    );
    assert_writable_within(&second_mount, "after-final (second)", WRITE_PROBE_TIMEOUT);
    assert!(agent.stop().success());

    // 7. Assert all four boundary fixtures have identical bytes, dev, inode, mtime.
    fixtures.assert_all_intact();
}

#[test]
fn oq10_fixture_and_writable_probe_helpers_unprivileged() {
    let dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-helper-test-")
        .tempdir_in("/dev/shm")
        .unwrap();
    let uid = Uid::current();
    let gid = Gid::current();

    // 1. OwnedFixtureFile intact happy path + clean unlink on drop.
    let fixture =
        OwnedFixtureFile::try_create_exclusive(dir.path(), "fixture", uid, gid, 0o600, b"expected")
            .unwrap();
    fixture.assert_intact();

    // 2. Mutating bytes through the held inode fails WITHOUT echoing file contents.
    let secret_marker = b"TOP-SECRET-RUNNER-DATA";
    std::fs::write(dir.path().join("fixture"), secret_marker).unwrap();
    let mut_err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.assert_intact();
    }))
    .unwrap_err();
    let mut_msg = mut_err
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| mut_err.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        !mut_msg.contains("TOP-SECRET-RUNNER-DATA"),
        "assert_intact must never disclose file contents in panic output: {mut_msg}"
    );

    // 3. Replacing the directory entry with a symlink to another file fails at
    //    the AT_SYMLINK_NOFOLLOW identity check BEFORE reading anything.
    let other = dir.path().join("other-secret");
    std::fs::write(&other, b"OTHER-SENSITIVE-BYTES").unwrap();
    std::fs::remove_file(dir.path().join("fixture")).unwrap();
    symlink(&other, dir.path().join("fixture")).unwrap();
    let link_err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.assert_intact();
    }))
    .unwrap_err();
    let link_msg = link_err
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| link_err.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(
        link_msg.contains("file type changed") && !link_msg.contains("OTHER-SENSITIVE-BYTES"),
        "symlink replacement must fail on file type without reading target: {link_msg}"
    );
    drop(fixture);
    // Drop must NOT unlink the replaced symlink (identity mismatch).
    assert!(dir.path().join("fixture").symlink_metadata().is_ok());

    // 4. assert_writable_within succeeds and leaves zero probe files behind.
    let probe_dir = tempfile::Builder::new()
        .prefix("qeminga-oq10-writable-test-")
        .tempdir_in("/dev/shm")
        .unwrap();
    assert_writable_within(
        probe_dir.path().to_str().unwrap(),
        "unprivileged-self-test",
        Duration::from_secs(2),
    );
    assert_eq!(
        std::fs::read_dir(probe_dir.path()).unwrap().count(),
        0,
        "assert_writable_within must leave zero probe files behind"
    );
}
