//! Isolated parser child spawning, descriptor adoption, and process sandbox
//! primitives (OQ-10 §3.2, §5.3; #78).
//!
//! Lives under `src/kernel/` because `fork(2)`, `execve(2)`, `dup2(2)`, and
//! raw inherited descriptor adoption require `unsafe`. Every `unsafe` block
//! performs a single reviewed OS operation and carries a `// SAFETY:` comment.
#![allow(unsafe_code)]

use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl, open};
use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::Signal;
use nix::sys::stat::{Mode, SFlag, fstat, major, minor};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, getppid, pipe2};

use crate::ipc::IPC_FD;
use crate::kernel::ipc::dup_above_cloexec;

/// Fixed descriptor slot inherited by `--internal-parser` when the executor
/// opened the verified channel before `fork` + `execve` (OQ-10 §3.2).
pub const INITIAL_CHANNEL_FD: RawFd = 4;

/// Transient descriptor slot used by `--internal-parser` to write one `'R'`
/// byte and close immediately after completing privilege drop, `chdir("/")`,
/// `RLIMIT_NOFILE`, `PR_SET_PDEATHSIG`, and seccomp installation.
pub const PARSER_READY_FD: RawFd = 5;

/// `RLIMIT_NOFILE` cap installed inside the unprivileged parser process
/// (OQ-10 §3.2).
pub const PARSER_NOFILE_LIMIT: u64 = 64;

/// First temporary fd slot used to park child descriptors clear of `0..=5`
/// before `fork` + `dup2`.
const STAGING_MIN_FD: RawFd = 16;

/// Why spawning or handshaking with the isolated parser child failed.
#[derive(Debug, thiserror::Error)]
pub enum SpawnParserError {
    /// Executable path or argument contains an interior NUL byte.
    #[error("parser spawn argument contains interior NUL byte")]
    InteriorNul,
    /// Opening or verifying `/dev/null` failed.
    #[error("cannot prepare /dev/null for parser stdio: {0}")]
    DevNull(#[source] io::Error),
    /// Creating helper pipes or staging descriptors failed.
    #[error("cannot prepare parser spawn descriptors: {0}")]
    Descriptors(#[source] io::Error),
    /// `fork(2)` failed.
    #[error("fork(2) failed: {0}")]
    Fork(#[source] io::Error),
    /// `execve(2)` inside the parser child failed.
    #[error("execve(2) of parser failed: {0}")]
    Exec(#[source] io::Error),
    /// The parser child exited or was signalled before reporting readiness.
    #[error("parser child failed during startup ({status:?})")]
    ChildStartupFailed {
        /// Wait status reported by `waitpid(2)`.
        status: WaitStatus,
    },
    /// The parser child did not report readiness within the startup deadline.
    #[error("parser child did not become ready within startup timeout")]
    ReadyTimeout,
}

impl SpawnParserError {
    /// Returns the child's exit code if the parser exited cleanly with a
    /// sysexits status during startup (e.g. `77` for missing `qeminga-parser`
    /// account or `78` for enforced hardening refusal).
    pub fn child_exit_code(&self) -> Option<i32> {
        match self {
            Self::ChildStartupFailed {
                status: WaitStatus::Exited(_, code),
            } => Some(*code),
            _ => None,
        }
    }
}

/// Parameters for [`spawn_parser`].
pub struct ParserSpawnSpec {
    /// Executable path to `execve` (production: `/proc/self/exe` or current exe).
    pub exe: PathBuf,
    /// Complete `argv` including `argv[0]`.
    pub args: Vec<OsString>,
    /// Parser's end of the `AF_UNIX` `SOCK_SEQPACKET` pair (becomes fd `3`).
    pub parser_ipc: OwnedFd,
    /// Optional verified initial channel descriptor (becomes fd `4`).
    pub initial_channel: Option<OwnedFd>,
    /// Maximum time to wait for the parser child's post-sandbox readiness byte.
    pub ready_timeout: Duration,
}

/// Handle to the spawned parser child owned by the executor.
///
/// The executor runs as UID `600` without `CAP_KILL`, so this handle never
/// calls `kill(2)`; it only reaps the child via `wait4(2)` (`waitpid`), while
/// termination is enforced by closing `IPC_FD`, `PR_SET_PDEATHSIG(SIGKILL)`,
/// and systemd's `KillMode=control-group` (OQ-10 §5.3).
#[derive(Debug)]
pub struct ParserChild {
    pid: Pid,
    reaped: bool,
}

impl ParserChild {
    /// Process ID of the parser child.
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Non-blocking reap check (`waitpid(pid, WNOHANG)` / `wait4`).
    pub fn try_wait(&mut self) -> Result<Option<WaitStatus>, Errno> {
        if self.reaped {
            return Ok(None);
        }
        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => Ok(None),
            Ok(status) => {
                self.reaped = true;
                Ok(Some(status))
            }
            Err(Errno::ECHILD) => {
                self.reaped = true;
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }

    /// Blocking wait for the parser child to exit (`waitpid(pid, 0)`).
    pub fn wait(&mut self) -> Result<WaitStatus, Errno> {
        loop {
            match waitpid(self.pid, None) {
                Ok(status) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Err(Errno::EINTR) => continue,
                Err(err) => return Err(err),
            }
        }
    }
}

impl Drop for ParserChild {
    fn drop(&mut self) {
        let _ = self.try_wait();
    }
}

/// Verifies that `fd` refers to the kernel `/dev/null` character device `(1, 3)`.
fn assert_is_dev_null(fd: BorrowedFd<'_>) -> io::Result<()> {
    let st = fstat(fd).map_err(io::Error::from)?;
    let ftype = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT;
    let maj = major(st.st_rdev);
    let min = minor(st.st_rdev);
    if ftype != SFlag::S_IFCHR || (maj, min) != (1, 3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "expected /dev/null char(1,3), got mode={:#o} rdev=({maj},{min})",
                st.st_mode
            ),
        ));
    }
    Ok(())
}

/// Opens `/dev/null` (`O_RDWR | O_CLOEXEC`) and verifies its backing device `(1, 3)`.
fn open_verified_dev_null() -> io::Result<OwnedFd> {
    let fd = open(
        Path::new("/dev/null"),
        OFlag::O_RDWR | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    assert_is_dev_null(fd.as_fd())?;
    Ok(fd)
}

/// Verifies inside the parser child that fds `0`, `1`, and `2` are all backed
/// by `/dev/null` (`char(1, 3)`), never the executor's `stderr`/journald sink.
pub fn verify_stdio_is_dev_null() -> io::Result<()> {
    for raw in [0, 1, 2] {
        // SAFETY: fds 0, 1, and 2 are standard process descriptors whose
        // liveness is checked immediately via `fstat` without taking ownership.
        let borrowed = unsafe { BorrowedFd::borrow_raw(raw) };
        assert_is_dev_null(borrowed)?;
    }
    Ok(())
}

/// Spawns the isolated `--internal-parser` child via `fork(2)` + `execve(2)`
/// with an empty environment, `/dev/null` on fds `0`/`1`/`2`, `IPC_FD` (`3`),
/// optional `INITIAL_CHANNEL_FD` (`4`), and transient `PARSER_READY_FD` (`5`),
/// and waits up to `spec.ready_timeout` for the post-sandbox readiness byte.
///
/// Must be called while the executor is still **single-threaded** (before
/// starting the audit writer thread or Tokio runtime) so `fork(2)` cannot
/// inherit locked mutexes from sibling threads.
pub fn spawn_parser(spec: ParserSpawnSpec) -> Result<ParserChild, SpawnParserError> {
    let exe_c =
        CString::new(spec.exe.as_os_str().as_bytes()).map_err(|_| SpawnParserError::InteriorNul)?;
    let mut arg_cs = Vec::with_capacity(spec.args.len());
    for arg in &spec.args {
        arg_cs.push(CString::new(arg.as_bytes()).map_err(|_| SpawnParserError::InteriorNul)?);
    }
    if arg_cs.is_empty() {
        arg_cs.push(exe_c.clone());
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = arg_cs.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    // Empty environment: parser inherits zero environment variables from executor.
    let envp_ptrs: [*const libc::c_char; 1] = [std::ptr::null()];

    let dev_null = open_verified_dev_null().map_err(SpawnParserError::DevNull)?;
    let (exec_err_r, exec_err_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?;
    let (ready_r, ready_w) =
        pipe2(OFlag::O_CLOEXEC).map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?;

    // Park every fd that the child will `dup2` onto 0..=5 well above 5
    // (`>= STAGING_MIN_FD`) so no `dup2` target can collide with a source fd.
    let dev_null = dup_above_cloexec(dev_null, STAGING_MIN_FD)
        .map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?;
    let parser_ipc = dup_above_cloexec(spec.parser_ipc, STAGING_MIN_FD)
        .map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?;
    let initial_channel = match spec.initial_channel {
        Some(ch) => Some(
            dup_above_cloexec(ch, STAGING_MIN_FD)
                .map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?,
        ),
        None => None,
    };
    let exec_err_w = dup_above_cloexec(exec_err_w, STAGING_MIN_FD)
        .map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?;
    let ready_w = dup_above_cloexec(ready_w, STAGING_MIN_FD)
        .map_err(|e| SpawnParserError::Descriptors(io::Error::from(e)))?;

    let dev_null_raw = dev_null.as_raw_fd();
    let parser_ipc_raw = parser_ipc.as_raw_fd();
    let initial_ch_raw = initial_channel.as_ref().map_or(-1, AsRawFd::as_raw_fd);
    let exec_err_w_raw = exec_err_w.as_raw_fd();
    let ready_w_raw = ready_w.as_raw_fd();

    // SAFETY: Caller invokes `spawn_parser` during single-threaded startup
    // before any background thread or Tokio runtime exists; the child branch
    // invokes only async-signal-safe POSIX syscalls (`dup2`, `execve`, `write`,
    // `_exit`) with pre-allocated C pointers and zero heap allocations.
    let pid_raw = unsafe { libc::fork() };
    if pid_raw < 0 {
        return Err(SpawnParserError::Fork(io::Error::last_os_error()));
    }
    if pid_raw == 0 {
        child_exec_parser(
            dev_null_raw,
            parser_ipc_raw,
            initial_ch_raw,
            ready_w_raw,
            exec_err_w_raw,
            exe_c.as_ptr(),
            argv_ptrs.as_ptr(),
            envp_ptrs.as_ptr(),
        );
    }

    // Parent: drop every child-side fd immediately (including parent's copy of
    // the initial verified channel descriptor and both pipe write ends).
    drop(dev_null);
    drop(parser_ipc);
    drop(initial_channel);
    drop(exec_err_w);
    drop(ready_w);

    let mut child = ParserChild {
        pid: Pid::from_raw(pid_raw),
        reaped: false,
    };

    // 1. Check whether `execve` failed (`exec_err_w` has O_CLOEXEC, so EOF on
    //    `exec_err_r` proves `execve` succeeded).
    let mut errno_buf = [0u8; 4];
    let mut got_err = 0usize;
    while got_err < errno_buf.len() {
        match nix::unistd::read(&exec_err_r, &mut errno_buf[got_err..]) {
            Ok(0) => break,
            Ok(n) => got_err += n,
            Err(Errno::EINTR) => continue,
            Err(e) => {
                let _ = child.wait();
                return Err(SpawnParserError::Exec(io::Error::from(e)));
            }
        }
    }
    drop(exec_err_r);
    if got_err == errno_buf.len() {
        let err_raw = i32::from_ne_bytes(errno_buf);
        let _ = child.wait();
        return Err(SpawnParserError::Exec(io::Error::from_raw_os_error(
            err_raw,
        )));
    }

    // 2. Wait up to `ready_timeout` for the single post-sandbox readiness byte
    //    `'R'` on `ready_r`.
    let deadline = Instant::now() + spec.ready_timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
        let mut pfds = [PollFd::new(ready_r.as_fd(), PollFlags::POLLIN)];
        match poll(&mut pfds, timeout) {
            Ok(0) => return Err(SpawnParserError::ReadyTimeout),
            Ok(_) => {
                let mut byte = [0u8; 1];
                match nix::unistd::read(&ready_r, &mut byte) {
                    Ok(1) if byte[0] == b'R' => return Ok(child),
                    Ok(_) => {
                        let status = child.wait().unwrap_or(WaitStatus::StillAlive);
                        return Err(SpawnParserError::ChildStartupFailed { status });
                    }
                    Err(Errno::EINTR) => continue,
                    Err(_) => {
                        let status = child.wait().unwrap_or(WaitStatus::StillAlive);
                        return Err(SpawnParserError::ChildStartupFailed { status });
                    }
                }
            }
            Err(Errno::EINTR) => continue,
            Err(_) => {
                let status = child.wait().unwrap_or(WaitStatus::StillAlive);
                return Err(SpawnParserError::ChildStartupFailed { status });
            }
        }
    }
}

/// Async-signal-safe child trampoline executed immediately after `fork(2)`.
#[allow(clippy::too_many_arguments)]
fn child_exec_parser(
    dev_null_raw: RawFd,
    parser_ipc_raw: RawFd,
    initial_ch_raw: RawFd,
    ready_w_raw: RawFd,
    exec_err_w_raw: RawFd,
    exe: *const libc::c_char,
    argv: *const *const libc::c_char,
    envp: *const *const libc::c_char,
) -> ! {
    // `dup2` onto a distinct fd clears `FD_CLOEXEC`; all source fds are
    // `>= STAGING_MIN_FD` (`16`) so none equals any target in `0..=5`.
    let dup_target = |src: RawFd, dst: RawFd| -> Result<(), i32> {
        loop {
            // SAFETY: `src` is a valid open descriptor staged above 5 and `dst`
            // is a fixed child slot in `0..=5`; `dup2` is async-signal-safe.
            let rc = unsafe { libc::dup2(src, dst) };
            if rc >= 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if err != libc::EINTR {
                return Err(err);
            }
        }
    };

    let fail_and_exit = |errno: i32| -> ! {
        let bytes = errno.to_ne_bytes();
        // SAFETY: `exec_err_w_raw` is an open pipe write end and `bytes` is a
        // 4-byte stack buffer; `write` and `_exit` are async-signal-safe.
        let _ = unsafe { libc::write(exec_err_w_raw, bytes.as_ptr().cast(), bytes.len()) };
        // SAFETY: `_exit` terminates the child immediately without running
        // parent atexit handlers or stdio flushes.
        unsafe { libc::_exit(127) }
    };

    if let Err(e) = dup_target(dev_null_raw, 0) {
        fail_and_exit(e);
    }
    if let Err(e) = dup_target(dev_null_raw, 1) {
        fail_and_exit(e);
    }
    if let Err(e) = dup_target(dev_null_raw, 2) {
        fail_and_exit(e);
    }
    if let Err(e) = dup_target(parser_ipc_raw, IPC_FD) {
        fail_and_exit(e);
    }
    if initial_ch_raw >= 0
        && let Err(e) = dup_target(initial_ch_raw, INITIAL_CHANNEL_FD)
    {
        fail_and_exit(e);
    }
    if let Err(e) = dup_target(ready_w_raw, PARSER_READY_FD) {
        fail_and_exit(e);
    }

    // SAFETY: `exe`, `argv`, and `envp` are NUL-terminated arrays allocated in
    // the parent before `fork(2)`; every other descriptor in the child carries
    // `FD_CLOEXEC` and is closed atomically by `execve(2)`.
    unsafe {
        libc::execve(exe, argv, envp);
    }
    let err = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO);
    fail_and_exit(err);
}

/// Adopts an inherited descriptor (`IPC_FD`, `INITIAL_CHANNEL_FD`, or
/// `PARSER_READY_FD`) inside `--internal-parser`, verifying it is open and
/// setting `FD_CLOEXEC`.
pub fn adopt_inherited_fd_cloexec(raw_fd: RawFd) -> Result<OwnedFd, Errno> {
    if raw_fd <= 2 {
        return Err(Errno::EINVAL);
    }
    // SAFETY: `borrowed` does not take ownership; `fcntl(F_GETFD)` safely
    // probes whether `raw_fd` is open and returns `EBADF` otherwise.
    let borrowed = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let _ = fcntl(borrowed, FcntlArg::F_GETFD)?;
    fcntl(borrowed, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
    // SAFETY: `raw_fd` was inherited exclusively by this freshly exec'd parser
    // process (`> 2`), verified open above, and is wrapped in `OwnedFd` once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

/// Arms `PR_SET_PDEATHSIG(SIGKILL)` and immediately checks whether
/// `getppid() == expected_ppid` to close the Linux parent-death race
/// (OQ-10 §3.2). Must be called **after** `setresuid`/`setresgid` because
/// credential transitions clear `pdeath_signal` on Linux.
///
/// Returns `Ok(true)` when the parent still matches `expected_ppid`, or
/// `Ok(false)` if the parent has already exited and this child was reparented.
pub fn arm_pdeathsig_and_verify_parent(expected_ppid: u32) -> Result<bool, Errno> {
    nix::sys::prctl::set_pdeathsig(Some(Signal::SIGKILL))?;
    Ok(u32::try_from(getppid().as_raw()).ok() == Some(expected_ppid))
}

/// Applies the parser's filesystem-independent working directory (`chdir("/")`)
/// and descriptor ceiling (`RLIMIT_NOFILE <= PARSER_NOFILE_LIMIT`) before
/// installing seccomp (OQ-10 §3.2).
pub fn apply_parser_rlimit_and_chdir() -> io::Result<()> {
    std::env::set_current_dir("/")?;
    let mut cur = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `cur` is a valid writable `libc::rlimit` struct for `RLIMIT_NOFILE`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let target = (PARSER_NOFILE_LIMIT as libc::rlim_t).min(cur.rlim_max);
    let next = libc::rlimit {
        rlim_cur: target,
        rlim_max: target,
    };
    // SAFETY: `next` is a valid readable `libc::rlimit` struct with `rlim_cur <= rlim_max <= cur.rlim_max`.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::kernel::ipc::seqpacket_pair;

    #[test]
    fn spawn_parser_binds_dev_null_empty_env_and_exact_inherited_fds() {
        // Spawn `/bin/sh -c ...` as a lightweight stand-in child to inspect its
        // exact inherited environment, stdio backing device, fd table, and
        // readiness handshake.
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let (ch_r, ch_w) = pipe2(OFlag::O_CLOEXEC).unwrap();

        let script = concat!(
            "set -e\n",
            "test -z \"$(/usr/bin/env | grep -v '^PWD=' | grep -v '^SHLVL=' | grep -v '^_=' || true)\"\n",
            "for d in 0 1 2; do\n",
            "    test \"$(readlink /proc/$$/fd/$d)\" = \"/dev/null\"\n",
            "done\n",
            "test -e /proc/$$/fd/3\n",
            "test -e /proc/$$/fd/4\n",
            "test -e /proc/$$/fd/5\n",
            "printf 'R' >&5\n",
            "exec 5>&-\n",
        );
        let mut child = spawn_parser(ParserSpawnSpec {
            exe: PathBuf::from("/bin/sh"),
            args: vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from(script),
            ],
            parser_ipc: parser_sock,
            initial_channel: Some(ch_w),
            ready_timeout: Duration::from_secs(5),
        })
        .unwrap();

        // Parent's copy of `ch_w` was dropped inside `spawn_parser`; once the
        // shell exits, `ch_r` sees EOF.
        let status = child.wait().unwrap();
        assert_eq!(status, WaitStatus::Exited(child.pid(), 0));
        let mut b = [0u8; 1];
        assert_eq!(nix::unistd::read(&ch_r, &mut b), Ok(0));
        drop(exec_sock);
    }

    #[test]
    fn spawn_parser_reports_exec_failure_and_startup_exit_code() {
        let (_exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let err = spawn_parser(ParserSpawnSpec {
            exe: PathBuf::from("/nonexistent/qeminga-no-such-binary"),
            args: vec![OsString::from("missing")],
            parser_ipc: parser_sock,
            initial_channel: None,
            ready_timeout: Duration::from_secs(5),
        })
        .unwrap_err();
        assert!(matches!(err, SpawnParserError::Exec(_)), "{err:?}");

        let (_exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let err = spawn_parser(ParserSpawnSpec {
            exe: PathBuf::from("/bin/sh"),
            args: vec![
                OsString::from("/bin/sh"),
                OsString::from("-c"),
                OsString::from("exit 77"),
            ],
            parser_ipc: parser_sock,
            initial_channel: None,
            ready_timeout: Duration::from_secs(5),
        })
        .unwrap_err();
        assert_eq!(err.child_exit_code(), Some(77), "{err:?}");
    }

    #[test]
    fn arm_pdeathsig_verifies_current_parent_and_detects_mismatch() {
        let ppid = u32::try_from(getppid().as_raw()).unwrap();
        assert!(arm_pdeathsig_and_verify_parent(ppid).unwrap());
        assert!(!arm_pdeathsig_and_verify_parent(ppid.wrapping_add(1)).unwrap());
        // Reset pdeathsig on test runner thread so it doesn't alter harness behavior.
        nix::sys::prctl::set_pdeathsig(None).unwrap();
    }
}
