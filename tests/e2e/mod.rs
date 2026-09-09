//! End-to-end harness (T4.7, C-15): a temporary configuration, a pty pair
//! whose slave is the daemon's channel (through a symlink so it can be
//! swapped for AC18), the real `qeminga` binary spawned from
//! `CARGO_BIN_EXE_qeminga`, and a line-oriented client with timeouts.
//!
//! The harness owns the only master descriptor and drives it with
//! `poll(2)`, so closing it is a real HUP for the daemon. When the tests
//! run as root the daemon drops to `qeminga`; the state directory is
//! chowned to that account (as systemd's `RuntimeDirectory=` would) and
//! replacement pty slaves are made world-accessible so the reopen works.
#![forbid(unsafe_code)]
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::poll::{PollFd, PollFlags, PollTimeout};
use serde_json::Value;

/// Default reply timeout.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for the first request after [`Agent::reopen_channel`]: the
/// daemon reopens with 1, 2, 4 ... s backoff.
pub const REOPEN_TIMEOUT: Duration = Duration::from_secs(40);

/// Options for [`Agent::spawn_with`].
#[derive(Debug)]
pub struct SpawnOptions {
    /// Use the fake kernel (`test-fakes` builds only; ignored otherwise).
    pub fake_kernel: bool,
    /// Extra TOML appended to the `[agent]` section.
    pub agent_extra: String,
    /// Extra TOML appended to the `[features]` section.
    pub features_extra: String,
    /// Reuse an existing state directory (a restart, AC10) instead of a
    /// fresh one; the marker inside it is left untouched.
    pub state_dir: Option<tempfile::TempDir>,
    /// Give the daemon a pipe as stderr instead of a file; the read end is
    /// returned by [`Agent::take_stderr_pipe`] (AC13).
    pub stderr_pipe: bool,
    /// Leave a recovery marker in the state directory before the spawn,
    /// so the daemon starts in recovery mode (`Frozen`, the ring holding
    /// its records) without any ioctl: the way to a frozen agent that
    /// works unprivileged and without fakes.
    pub recovery_marker: bool,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        SpawnOptions {
            fake_kernel: true,
            agent_extra: String::new(),
            features_extra: String::new(),
            state_dir: None,
            stderr_pipe: false,
            recovery_marker: false,
        }
    }
}

/// A pty pair with the slave kept open (so the master never reads EIO).
struct Pty {
    master: File,
    slave_path: String,
    _holder: OwnedFd,
}

fn raw(fd: &impl AsFd) {
    let mut t = nix::sys::termios::tcgetattr(fd).unwrap();
    nix::sys::termios::cfmakeraw(&mut t);
    nix::sys::termios::tcsetattr(fd, nix::sys::termios::SetArg::TCSANOW, &t).unwrap();
}

fn open_pty() -> Pty {
    let master =
        nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
    nix::pty::grantpt(&master).unwrap();
    nix::pty::unlockpt(&master).unwrap();
    let slave_path = nix::pty::ptsname_r(&master).unwrap();
    raw(&master);
    let holder = nix::fcntl::open(
        Path::new(&slave_path),
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .unwrap();
    raw(&holder);
    if nix::unistd::geteuid().is_root() {
        // The dropped daemon must be able to reopen it (AC18).
        std::fs::set_permissions(&slave_path, std::fs::Permissions::from_mode(0o666)).unwrap();
    }
    let master: OwnedFd = master.into();
    let flags = nix::fcntl::fcntl(master.as_fd(), nix::fcntl::FcntlArg::F_GETFL).unwrap();
    nix::fcntl::fcntl(
        master.as_fd(),
        nix::fcntl::FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )
    .unwrap();
    Pty {
        master: File::from(master),
        slave_path,
        _holder: holder,
    }
}

/// Root without the service account cannot run the daemon at all: the
/// §5.4 drop is mandatory when started as root (C-18 skips it only when
/// *not* root), so every test would otherwise report the daemon's exit 77.
/// Fail once, before spawning, with the fix.
pub fn require_service_account_when_root() {
    if nix::unistd::geteuid().is_root()
        && nix::unistd::User::from_name("qeminga").unwrap().is_none()
    {
        panic!(
            "running as root without the `qeminga` account: the daemon refuses to start (cannot drop privileges, exit 77). \
             Create it with `sudo systemd-sysusers packaging/sysusers.d/qeminga.conf` \
             (or `groupadd -g 600 qeminga && useradd -r -u 600 -g 600 -M -s /usr/sbin/nologin qeminga`), \
             or run the tests unprivileged."
        );
    }
}

/// A running daemon and the client end of its channel.
pub struct Agent {
    child: Child,
    pty: Pty,
    dir: Option<tempfile::TempDir>,
    link: PathBuf,
    stderr_path: PathBuf,
    stderr_pipe: Option<File>,
    stderr_writer: Option<File>,
    pending: Vec<u8>,
}

impl Agent {
    /// Spawns with the default options (fake kernel when available).
    pub fn spawn() -> Agent {
        Agent::spawn_with(SpawnOptions::default())
    }

    /// Spawns the real binary with a fresh configuration and pty.
    pub fn spawn_with(opts: SpawnOptions) -> Agent {
        require_service_account_when_root();
        let dir = opts.state_dir.unwrap_or_else(|| {
            tempfile::Builder::new()
                .prefix("qeminga-e2e-")
                .tempdir_in("/dev/shm")
                .expect("tmpfs at /dev/shm")
        });
        let pty = open_pty();
        let link = dir.path().join("channel");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&pty.slave_path, &link).unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "[agent]\nchannel_path = \"{}\"\nstate_path = \"{}\"\nlog_level = \"debug\"\n{}\n[features]\nseccomp = true\n{}\n",
                link.display(),
                dir.path().join("frozen").display(),
                opts.agent_extra,
                opts.features_extra
            ),
        )
        .unwrap();
        if opts.recovery_marker {
            std::fs::write(dir.path().join("frozen"), b"").unwrap();
        }
        if nix::unistd::geteuid().is_root()
            && let Some(user) = nix::unistd::User::from_name("qeminga").unwrap()
        {
            nix::unistd::chown(dir.path(), Some(user.uid), Some(user.gid)).unwrap();
            if opts.recovery_marker {
                nix::unistd::chown(&dir.path().join("frozen"), Some(user.uid), Some(user.gid))
                    .unwrap();
            }
        }
        let stderr_path = dir.path().join("stderr.log");
        let mut stderr_pipe = None;
        let mut stderr_writer = None;
        let stderr: Stdio = if opts.stderr_pipe {
            let (reader, writer) = std::io::pipe().unwrap();
            stderr_pipe = Some(File::from(OwnedFd::from(reader)));
            // A dup of the write end stays with the test so it can fill
            // the pipe itself (a blocked journald leaves it full).
            stderr_writer = Some(File::from(OwnedFd::from(writer.try_clone().unwrap())));
            Stdio::from(writer)
        } else {
            // Append: a restart (AC10) keeps the previous log.
            Stdio::from(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&stderr_path)
                    .unwrap(),
            )
        };
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_qeminga"));
        cmd.arg("--config")
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        if opts.fake_kernel && cfg!(feature = "test-fakes") {
            cmd.env("QEMINGA_TEST_FAKE_KERNEL", "1");
        }
        let child = cmd.spawn().expect("spawn qeminga");
        let mut agent = Agent {
            child,
            pty,
            dir: Some(dir),
            link,
            stderr_path,
            stderr_pipe,
            stderr_writer,
            pending: Vec::new(),
        };
        if opts.recovery_marker {
            // Recovery mode writes nothing to stderr until a thaw (§4.4):
            // the channel is proved open by a reply instead.
            let reply = agent.request_timeout(r#"{"execute":"guest-ping"}"#, REPLY_TIMEOUT);
            assert_eq!(
                reply,
                serde_json::json!({"return": {}}),
                "recovery-mode start"
            );
        } else if agent.stderr_pipe.is_none() {
            agent.wait_for_stderr("\"event\":\"channel_open\"", Duration::from_secs(10));
        } else {
            // Give the daemon time to open the channel; the caller drains
            // the pipe itself.
            std::thread::sleep(Duration::from_millis(300));
        }
        agent
    }

    /// The read end of the stderr pipe (once), for `stderr_pipe` spawns.
    pub fn take_stderr_pipe(&mut self) -> Option<File> {
        self.stderr_pipe.take()
    }

    /// A write end of the stderr pipe (once), for `stderr_pipe` spawns:
    /// lets a test fill the pipe to capacity, as a journald that stopped
    /// reading would leave it.
    pub fn take_stderr_writer(&mut self) -> Option<File> {
        self.stderr_writer.take()
    }

    /// Fills the daemon's stderr pipe to capacity from the test's own
    /// write end and leaves it full, so the daemon's next write to stderr
    /// blocks as a journald that stopped reading would make it (§9.1).
    /// `O_NONBLOCK` is a status flag of the open file description, which
    /// the dup shares with the daemon's stderr: it is set only while the
    /// pipe is being filled and cleared before returning. Returns the
    /// number of bytes it took.
    pub fn fill_stderr_pipe(&mut self) -> usize {
        use std::io::Write;
        let writer = self.stderr_writer.as_ref().expect("a stderr_pipe spawn");
        let set_nonblock = |writer: &File, on: bool| {
            use std::os::fd::AsFd;
            let fd = writer.as_fd();
            let flags = nix::fcntl::OFlag::from_bits_retain(
                nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).unwrap(),
            );
            let flags = if on {
                flags | nix::fcntl::OFlag::O_NONBLOCK
            } else {
                flags - nix::fcntl::OFlag::O_NONBLOCK
            };
            nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags)).unwrap();
        };
        set_nonblock(writer, true);
        let mut filled = 0usize;
        loop {
            match (&*writer).write(&[b'#'; 4096]) {
                Ok(n) => filled += n,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => panic!("filling the pipe: {err}"),
            }
        }
        set_nonblock(writer, false);
        assert!(filled > 0, "the pipe was filled to capacity");
        filled
    }

    /// Kills the daemon with SIGKILL (a crash) and returns the state
    /// directory so a restart can reuse it (AC10).
    pub fn kill(mut self) -> tempfile::TempDir {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.dir.take().unwrap()
    }

    /// `true` when the binary can fake the kernel.
    pub fn has_fake_kernel() -> bool {
        cfg!(feature = "test-fakes")
    }

    /// The daemon's stderr so far.
    pub fn stderr_text(&self) -> String {
        std::fs::read_to_string(&self.stderr_path).unwrap_or_default()
    }

    /// Waits until stderr contains `needle`.
    pub fn wait_for_stderr(&mut self, needle: &str, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !self.stderr_text().contains(needle) {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!(
                    "daemon exited with {status}; stderr:\n{}",
                    self.stderr_text()
                );
            }
            assert!(
                Instant::now() < deadline,
                "timeout waiting for {needle:?}; stderr:\n{}",
                self.stderr_text()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn poll(&self, flags: PollFlags, timeout: Duration) -> PollFlags {
        let fd = self.pty.master.as_fd();
        let mut fds = [PollFd::new(fd, flags)];
        let ms = u16::try_from(timeout.as_millis()).unwrap_or(u16::MAX);
        match nix::poll::poll(&mut fds, PollTimeout::from(ms)) {
            Ok(0) => PollFlags::empty(),
            Ok(_) => fds[0].revents().unwrap_or(PollFlags::empty()),
            Err(nix::errno::Errno::EINTR) => PollFlags::empty(),
            Err(err) => panic!("poll: {err}"),
        }
    }

    fn drain_readable(&mut self) {
        let mut buf = [0u8; 65536];
        loop {
            match self.pty.master.read(&mut buf) {
                Ok(0) => return,
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return,
                Err(err) if err.raw_os_error() == Some(nix::errno::Errno::EIO as i32) => return,
                Err(err) => panic!("read: {err}"),
            }
        }
    }

    /// Writes `bytes` to the channel, draining replies meanwhile so a large
    /// write (the flood) cannot deadlock on the pty buffers.
    pub fn send(&mut self, bytes: &[u8]) {
        let mut offset = 0;
        let deadline = Instant::now() + REPLY_TIMEOUT;
        while offset < bytes.len() {
            let ready = self.poll(
                PollFlags::POLLIN | PollFlags::POLLOUT,
                Duration::from_millis(50),
            );
            if ready.contains(PollFlags::POLLIN) {
                self.drain_readable();
            }
            if ready.contains(PollFlags::POLLOUT) {
                match self.pty.master.write(&bytes[offset..]) {
                    Ok(n) => offset += n,
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => panic!("write: {err}"),
                }
            }
            assert!(
                Instant::now() < deadline,
                "write stalled after {offset} bytes"
            );
        }
    }

    /// Sends one request line.
    pub fn send_line(&mut self, json: &str) {
        let mut line = json.as_bytes().to_vec();
        line.push(b'\n');
        self.send(&line);
    }

    /// The next reply line without its newline (a leading `0xFF` is kept),
    /// or `None` on timeout.
    pub fn read_line(&mut self, timeout: Duration) -> Option<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(pos) = self.pending.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.pending.drain(..=pos).collect();
                return Some(line[..line.len() - 1].to_vec());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let ready = self.poll(PollFlags::POLLIN, deadline - now);
            if ready.contains(PollFlags::POLLIN) {
                self.drain_readable();
            } else if ready.contains(PollFlags::POLLHUP) {
                return None;
            }
        }
    }

    /// Sends a request and returns the raw reply line.
    pub fn request_raw(&mut self, json: &str) -> Vec<u8> {
        self.send_line(json);
        self.read_line(REPLY_TIMEOUT)
            .unwrap_or_else(|| panic!("no reply to {json}; stderr:\n{}", self.stderr_text()))
    }

    /// Sends a request and parses the reply (a `0xFF` prefix is stripped).
    pub fn request(&mut self, json: &str) -> Value {
        let raw = self.request_raw(json);
        let body = raw.strip_prefix(&[0xFF]).unwrap_or(&raw);
        serde_json::from_slice(body)
            .unwrap_or_else(|e| panic!("bad reply {:?}: {e}", String::from_utf8_lossy(&raw)))
    }

    /// `execute` with no arguments.
    pub fn execute(&mut self, method: &str) -> Value {
        self.request(&format!(r#"{{"execute":"{method}"}}"#))
    }

    /// Creates a new pty, points the channel symlink at it, then closes the
    /// old master (HUP for the daemon), whose reopen lands on the new pty
    /// (AC18). Nothing is read from stderr here: while frozen, audit output
    /// stays in the ring (§9.1). Use [`request_timeout`](Self::request_timeout)
    /// with [`REOPEN_TIMEOUT`] for the first request afterwards.
    pub fn reopen_channel(&mut self) {
        let fresh = open_pty();
        let tmp = self.state_dir().join("channel.new");
        let _ = std::fs::remove_file(&tmp);
        std::os::unix::fs::symlink(&fresh.slave_path, &tmp).unwrap();
        std::fs::rename(&tmp, &self.link).unwrap();
        let old = std::mem::replace(&mut self.pty, fresh);
        drop(old);
        self.pending.clear();
    }

    /// Sends a request and parses the reply, waiting up to `timeout`.
    pub fn request_timeout(&mut self, json: &str, timeout: Duration) -> Value {
        self.send_line(json);
        let raw = self.read_line(timeout).unwrap_or_else(|| {
            panic!(
                "no reply to {json} within {timeout:?}; stderr:\n{}",
                self.stderr_text()
            )
        });
        let body = raw.strip_prefix(&[0xFF]).unwrap_or(&raw);
        serde_json::from_slice(body)
            .unwrap_or_else(|e| panic!("bad reply {:?}: {e}", String::from_utf8_lossy(&raw)))
    }

    /// The state directory.
    pub fn state_dir(&self) -> &Path {
        self.dir.as_ref().unwrap().path()
    }

    /// `true` while the daemon is alive.
    pub fn is_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// SIGTERM and wait.
    pub fn stop(mut self) -> ExitStatus {
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(self.child.id() as i32),
            nix::sys::signal::Signal::SIGTERM,
        )
        .ok();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                let status = self.child.wait().unwrap();
                panic!(
                    "daemon did not exit on SIGTERM ({status}); stderr:\n{}",
                    self.stderr_text()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// The §2.3 denied-command table.
pub const DENIED: &[&str] = &[
    "guest-exec",
    "guest-exec-status",
    "guest-file-open",
    "guest-file-read",
    "guest-file-write",
    "guest-file-close",
    "guest-file-seek",
    "guest-file-flush",
    "guest-set-user-password",
    "guest-ssh-add-authorized-keys",
    "guest-ssh-remove-authorized-keys",
    "guest-ssh-get-authorized-keys",
    "guest-set-time",
    "guest-set-vcpus",
    "guest-set-memory-blocks",
    "guest-suspend-disk",
    "guest-suspend-hybrid",
    "guest-get-users",
    "guest-get-host-name",
    "guest-get-time",
    "guest-get-timezone",
    "guest-get-devices",
    "guest-get-disks",
    "guest-get-diskstats",
    "guest-get-cpustats",
    "guest-get-load",
    "guest-get-vcpus",
    "guest-get-memory-blocks",
    "guest-get-memory-block-info",
    "guest-network-get-route",
];
