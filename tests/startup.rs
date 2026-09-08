//! The startup sequence and the runtime loop (T4.6): ordered steps through
//! a recording `Startup`, `state_path` validation, `EBUSY`, recovery mode,
//! deferred stop (C-21), and a smoke run of the real binary over a pty.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::io::Write;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nix::errno::Errno;
use qeminga::audit::{Mode, Router};
use qeminga::channel::{Channel, OpenError, OpenFn};
use qeminga::config::{Config, ConfigError, LogLevel};
use qeminga::daemon::{self, EX_CONFIG, EX_UNAVAILABLE, Options, RunError, Startup};
use qeminga::dispatch::Context;
use qeminga::kernel::caps::{Outcome, PrivilegeError};
use qeminga::kernel::fake::FakeKernel;
use qeminga::marker::Marker;
use qeminga::mountinfo::{MountEntry, StaticMounts, parse_mountinfo};
use qeminga::state::FreezeState;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::instrument::WithSubscriber;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mountinfo")
            .join(name),
    )
    .unwrap()
}

/// A tmpfs-backed directory for markers (never covered by a freeze plan).
fn shm_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("qeminga-test-")
        .tempdir_in("/dev/shm")
        .unwrap()
}

#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Records every step; behaviour is scripted per field.
struct FakeStartup {
    steps: RefCell<Vec<String>>,
    config: String,
    /// Whether the marker exists in `dir` when step 2 looks.
    marker: bool,
    /// The real directory the fake's marker lives in (tmpfs), whatever
    /// path the configuration names.
    dir: tempfile::TempDir,
    mountinfo: String,
    open: Result<(), Errno>,
    sink: SharedSink,
}

impl FakeStartup {
    fn new() -> Self {
        FakeStartup {
            steps: RefCell::new(Vec::new()),
            config: "[agent]\nstate_path = \"/run/qeminga/frozen\"\n".to_owned(),
            marker: false,
            dir: shm_dir(),
            mountinfo: fixture("tmpfs_and_nfs.txt"),
            open: Ok(()),
            sink: SharedSink::default(),
        }
    }
    fn log(&self, s: impl Into<String>) {
        self.steps.borrow_mut().push(s.into());
    }
    fn steps(&self) -> Vec<String> {
        self.steps.borrow().clone()
    }
}

impl Startup for FakeStartup {
    fn load_config(&self, path: &Path) -> Result<Config, ConfigError> {
        self.log(format!("config {}", path.display()));
        Config::parse(&self.config)
    }
    fn open_marker(&self, path: &Path) -> Result<Marker, RunError> {
        self.log(format!("marker {}", path.display()));
        let marker = Marker::open(self.dir.path().join("frozen"))?;
        if self.marker && !marker.exists() {
            marker.create().unwrap();
        }
        Ok(marker)
    }
    fn init_logging(&self, level: LogLevel, ring: bool) -> Result<Router, RunError> {
        self.log(format!("logging {} ring={ring}", level.as_str()));
        let router = Router::new(Box::new(self.sink.clone()));
        if ring {
            router.enter_ring();
        }
        Ok(router)
    }
    fn mount_table(&self) -> Result<Vec<MountEntry>, String> {
        self.log("mounts");
        Ok(parse_mountinfo(&self.mountinfo))
    }
    fn open_channel(&self, path: &Path) -> Result<Option<OwnedFd>, OpenError> {
        self.log(format!("channel {}", path.display()));
        match self.open {
            Ok(()) => {
                let (a, _b) = nix::sys::socket::socketpair(
                    nix::sys::socket::AddressFamily::Unix,
                    nix::sys::socket::SockType::Stream,
                    None,
                    nix::sys::socket::SockFlag::SOCK_CLOEXEC,
                )
                .unwrap();
                Ok(Some(a))
            }
            Err(errno) => {
                let err = OpenError::from_io(path, std::io::Error::from_raw_os_error(errno as i32));
                if err.is_terminal() {
                    Err(err)
                } else {
                    self.log("channel deferred");
                    Ok(None)
                }
            }
        }
    }
    fn drop_privileges(&self) -> Result<Outcome, PrivilegeError> {
        self.log("caps");
        Ok(Outcome::SkippedUnprivileged)
    }
    fn install_seccomp(&self, config: &Config) -> Result<bool, RunError> {
        self.log(format!("seccomp enabled={}", config.features.seccomp));
        Ok(false)
    }
    fn serve(
        &self,
        _config: Arc<Config>,
        router: Router,
        recovery: bool,
        channel: Option<OwnedFd>,
        _marker: Marker,
    ) -> Result<(), RunError> {
        self.log(format!(
            "runtime recovery={recovery} mode={:?} channel={}",
            router.mode(),
            if channel.is_some() { "open" } else { "none" }
        ));
        Ok(())
    }
}

#[test]
fn startup_order_is_config_marker_channel_caps_seccomp_runtime() {
    let startup = FakeStartup::new();
    let opts = Options {
        config_path: PathBuf::from("/etc/qeminga/config.toml"),
        version: false,
    };
    daemon::run_with(&opts, &startup).unwrap();
    assert_eq!(
        startup.steps(),
        [
            "config /etc/qeminga/config.toml",
            "marker /run/qeminga/frozen",
            "logging info ring=false",
            "mounts",
            "channel /dev/virtio-ports/org.qemu.guest_agent.0",
            "caps",
            "seccomp enabled=true",
            "runtime recovery=false mode=Normal channel=open",
        ]
    );
    // No ioctl and no marker write before the runtime: the fake kernel is
    // never involved and the marker step only opens the directory and
    // looks (`open_marker` creates nothing).
    let text = startup.sink.text();
    assert!(!text.contains("fifreeze"), "{text}");
    assert!(!text.contains("fithaw"), "{text}");
}

/// `(major, minor)` of the filesystem holding `path`, as `stat` sees it.
fn dev_of(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).unwrap().dev();
    (
        u32::try_from(nix::sys::stat::major(dev)).unwrap(),
        u32::try_from(nix::sys::stat::minor(dev)).unwrap(),
    )
}

#[test]
fn freezable_state_path_is_rejected_before_opening_channel() {
    // What is judged is the device of the marker's directory as opened,
    // not the configured pathname: the fake's directory is on tmpfs, so
    // the mount table is made to list that very device as a planned ext4
    // root (the configured path plays no part).
    let mut startup = FakeStartup::new();
    startup.config = "[agent]\nstate_path = \"/var/lib/qeminga/frozen\"\n".to_owned();
    let (major, minor) = dev_of(startup.dir.path());
    startup.mountinfo = format!(
        "27 1 {major}:{minor} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
         28 27 0:30 / /run rw,nosuid - tmpfs tmpfs rw\n"
    );
    let err = daemon::run_with(&Options::default(), &startup).unwrap_err();
    assert_eq!(err.exit_code(), EX_CONFIG);
    let msg = err.to_string();
    assert!(msg.contains("/var/lib/qeminga/frozen"), "{msg}");
    assert!(
        msg.contains(&format!("is on / ({major}:{minor}),")),
        "names the covering mount and device: {msg}"
    );
    assert!(msg.contains("tmpfs"), "{msg}");
    let steps = startup.steps();
    assert_eq!(
        steps.last().unwrap(),
        "mounts",
        "stopped before the channel: {steps:?}"
    );
    assert!(!steps.iter().any(|s| s.starts_with("channel")));
    // A pathname under a planned mount is fine when its directory is on
    // tmpfs: `/var/lib/qeminga/frozen` with the default fixture (where the
    // fake's tmpfs device is not planned) passes, prefix or no prefix.
    let mut startup = FakeStartup::new();
    startup.config = "[agent]\nstate_path = \"/var/lib/qeminga/frozen\"\n".to_owned();
    daemon::run_with(&Options::default(), &startup).unwrap();
    // A marker directory that cannot be opened stops the sequence at step
    // 2 with EX_CONFIG.
    let mut startup = FakeStartup::new();
    startup.dir = shm_dir();
    let gone = startup.dir.path().to_path_buf();
    std::fs::remove_dir(&gone).unwrap();
    let err = daemon::run_with(&Options::default(), &startup).unwrap_err();
    assert_eq!(err.exit_code(), EX_CONFIG);
    assert!(err.to_string().contains("directory"), "{err}");
    assert_eq!(
        startup.steps().last().unwrap(),
        "marker /run/qeminga/frozen"
    );
    std::fs::create_dir(&gone).unwrap();
}

#[test]
fn ebusy_on_channel_exits_with_channel_already_open_and_nonzero_code() {
    let mut startup = FakeStartup::new();
    startup.open = Err(Errno::EBUSY);
    let err = daemon::run_with(&Options::default(), &startup).unwrap_err();
    assert_eq!(err.exit_code(), EX_UNAVAILABLE);
    assert!(err.to_string().starts_with("channel_already_open"), "{err}");
    let steps = startup.steps();
    assert!(steps.last().unwrap().starts_with("channel"));
    assert!(
        !steps.contains(&"caps".to_owned()),
        "no drop after a terminal open error"
    );
}

#[test]
fn a_missing_channel_never_delays_the_drop_the_filter_or_recovery() {
    // ENOENT on the one privileged open attempt is not terminal: the
    // sequence goes on to the privilege drop, the seccomp filter and the
    // runtime, which starts in recovery mode with no channel and leaves
    // the reopening to the loop (OQ-7).
    let mut startup = FakeStartup::new();
    startup.marker = true;
    startup.open = Err(Errno::ENOENT);
    daemon::run_with(&Options::default(), &startup).unwrap();
    assert_eq!(
        startup.steps()[4..],
        [
            "channel /dev/virtio-ports/org.qemu.guest_agent.0",
            "channel deferred",
            "caps",
            "seccomp enabled=true",
            "runtime recovery=true mode=Ring channel=none",
        ]
    );
    // Any other non-EBUSY error is deferred the same way.
    let mut startup = FakeStartup::new();
    startup.open = Err(Errno::EACCES);
    daemon::run_with(&Options::default(), &startup).unwrap();
    assert!(startup.steps().contains(&"channel deferred".to_owned()));
    assert_eq!(
        startup.steps().last().unwrap(),
        "runtime recovery=false mode=Normal channel=none"
    );
}

#[test]
fn feature_warnings_are_logged_once_at_startup() {
    // Observed on the real binary's stderr (its global subscriber), which is
    // deterministic; scoped test subscribers race with each other under
    // parallel tests.
    let expected = Config::parse("[features]\nseccomp = true\nsuspend_ram = true\n")
        .unwrap()
        .warnings()
        .len();
    let (stderr, status) = run_binary_over_pty("seccomp = true\nsuspend_ram = true\n");
    assert!(status.success(), "{status}: {stderr}");
    assert_eq!(
        stderr.matches("\"event\":\"feature_warning\"").count(),
        expected,
        "{stderr}"
    );
    if !cfg!(feature = "suspend_ram") {
        assert!(stderr.contains("suspend_ram"), "{stderr}");
    }
    if !cfg!(feature = "seccomp") {
        assert!(stderr.contains("features.seccomp"), "{stderr}");
    }
    // The warnings precede the startup record and appear exactly once.
    let first_warning = stderr.find("feature_warning");
    let startup = stderr.find("\"event\":\"startup\"").unwrap();
    if let Some(w) = first_warning {
        assert!(w < startup);
    }
}

/// In-process runtime rig: fake kernel, fixture mounts, tmpfs marker, a
/// socketpair as the channel, and an injectable "signal".
struct Rig {
    ctx: Arc<Context>,
    peer: OwnedFd,
    _dir: tempfile::TempDir,
}

fn rig(recovery: bool, sink: &SharedSink) -> Rig {
    rig_with_idle(recovery, sink, 30)
}

fn rig_with_idle(recovery: bool, sink: &SharedSink, idle_secs: u64) -> Rig {
    let dir = shm_dir();
    let marker = Marker::open(dir.path().join("frozen")).unwrap();
    if recovery {
        marker.create().unwrap();
    }
    let router = Router::new(Box::new(sink.clone()));
    if recovery {
        router.enter_ring();
    }
    let config = Config::parse(&format!(
        "[agent]\nstate_path = \"{}\"\nfsfreeze_idle_timeout_secs = {idle_secs}\n",
        marker.path().display()
    ))
    .unwrap();
    let ctx = daemon::production_context(Arc::new(config), router, recovery, marker);
    let ctx = Arc::new(
        Arc::try_unwrap(ctx)
            .unwrap_or_else(|_| panic!("unshared"))
            .with_kernel(Arc::new(FakeKernel::new()))
            .with_mounts(Arc::new(StaticMounts(fixture("simple.txt")))),
    );
    let (ours, peer) = nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::Stream,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    // `ours` is handed to the loop as the initial descriptor.
    Rig {
        ctx,
        peer,
        _dir: dir,
    }
    .with_initial(ours)
}

impl Rig {
    fn with_initial(self, ours: OwnedFd) -> Self {
        INITIAL.with(|slot| *slot.borrow_mut() = Some(ours));
        self
    }
}

thread_local! {
    static INITIAL: RefCell<Option<OwnedFd>> = const { RefCell::new(None) };
}

fn take_initial() -> OwnedFd {
    INITIAL.with(|slot| slot.borrow_mut().take().unwrap())
}

fn never_open() -> OpenFn {
    Arc::new(|_| Err(std::io::Error::from_raw_os_error(Errno::ENOENT as i32)))
}

async fn request(peer: &mut Channel, json: &str) -> String {
    peer.write_all(format!("{json}\n").as_bytes())
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut buf))
        .await
        .expect("reply within 5 s")
        .unwrap();
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn marker_present_starts_in_frozen_recovery_mode_with_ring_audit_and_watchdog_armed() {
    let sink = SharedSink::default();
    let rig = rig(true, &sink);
    let ctx = rig.ctx.clone();
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let initial = take_initial();
    let server = tokio::spawn(async move {
        daemon::serve_until_signal(
            ctx,
            Path::new("/dev/virtio-ports/fake"),
            never_open(),
            Some(initial),
            true,
            async move { signal_rx.await.unwrap_or("closed") },
            Duration::from_millis(20),
        )
        .await
    });
    let mut peer = Channel::from_fd(rig.peer).unwrap();
    // Recovery mode: frozen, ring audit, watchdog armed (C-14).
    assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-status"}"#).await;
    assert_eq!(reply, "{\"return\":\"frozen\"}\n");
    assert_eq!(rig.ctx.audit.mode(), Mode::Ring);
    assert!(rig.ctx.watchdog_slot().is_some());
    let reply = request(&mut peer, r#"{"execute":"guest-get-osinfo"}"#).await;
    assert!(reply.contains("filesystems are frozen"), "{reply}");
    assert!(
        sink.text().is_empty(),
        "nothing reaches stderr while recovering"
    );
    // Thaw: normal mode, marker gone.
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-thaw"}"#).await;
    assert_eq!(reply, "{\"return\":2}\n");
    assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
    assert_eq!(rig.ctx.audit.mode(), Mode::Normal);
    assert!(!rig.ctx.marker.exists());
    signal_tx.send("SIGTERM").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_thaws_without_the_channel_ever_opening() {
    // A marker from a previous instance and a port that never appears:
    // the watchdog armed at startup drains and removes the marker on its
    // own, and the agent then honours the stop (OQ-7, C-14).
    let sink = SharedSink::default();
    let rig = rig_with_idle(true, &sink, 1);
    let ctx = rig.ctx.clone();
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    drop(take_initial());
    let router = rig.ctx.audit.clone();
    let server = tokio::spawn(
        async move {
            daemon::serve_until_signal(
                ctx,
                Path::new("/dev/virtio-ports/never"),
                never_open(),
                None,
                true,
                async move { signal_rx.await.unwrap_or("closed") },
                Duration::from_millis(20),
            )
            .await
        }
        .with_subscriber(qeminga::audit::subscriber(tracing::Level::INFO, router)),
    );
    assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
    let start = std::time::Instant::now();
    while rig.ctx.watchdog_slot().is_none() && rig.ctx.state.current() == FreezeState::Frozen {
        assert!(start.elapsed() < Duration::from_secs(5), "never armed");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    while rig.ctx.state.current() != FreezeState::Thawed {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the watchdog never thawed: {}",
            rig.ctx.state.current()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!rig.ctx.marker.exists(), "recovered without a host");
    assert_eq!(rig.ctx.audit.mode(), Mode::Normal);
    assert!(!server.is_finished(), "still trying to open the port");
    signal_tx.send("SIGTERM").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("exits while the port is still missing")
        .unwrap();
    assert!(result.is_ok());
    // The stop was logged by the loop itself (the watchdog task's own
    // records go to the global dispatcher, not this scoped one).
    let text = sink.text();
    assert!(text.contains("\"event\":\"signal\""), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_while_thawed_exits_zero_promptly() {
    let sink = SharedSink::default();
    let rig = rig(false, &sink);
    let ctx = rig.ctx.clone();
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let initial = take_initial();
    let server = tokio::spawn(async move {
        daemon::serve_until_signal(
            ctx,
            Path::new("/dev/virtio-ports/fake"),
            never_open(),
            Some(initial),
            false,
            async move { signal_rx.await.unwrap_or("closed") },
            Duration::from_millis(20),
        )
        .await
    });
    let mut peer = Channel::from_fd(rig.peer).unwrap();
    let reply = request(&mut peer, r#"{"execute":"guest-ping"}"#).await;
    assert_eq!(reply, "{\"return\":{}}\n");
    let started = std::time::Instant::now();
    signal_tx.send("SIGTERM").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_while_frozen_is_deferred_until_thaw() {
    let sink = SharedSink::default();
    let rig = rig(false, &sink);
    let ctx = rig.ctx.clone();
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let initial = take_initial();
    let router = rig.ctx.audit.clone();
    let server = tokio::spawn(
        async move {
            daemon::serve_until_signal(
                ctx,
                Path::new("/dev/virtio-ports/fake"),
                never_open(),
                Some(initial),
                false,
                async move { signal_rx.await.unwrap_or("closed") },
                Duration::from_millis(20),
            )
            .await
        }
        .with_subscriber(qeminga::audit::subscriber(tracing::Level::INFO, router)),
    );
    let mut peer = Channel::from_fd(rig.peer).unwrap();
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
    assert_eq!(reply, "{\"return\":2}\n");
    assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
    signal_tx.send("SIGTERM").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !server.is_finished(),
        "stop is deferred while frozen (C-21)"
    );
    // The frozen-safe set is still served.
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-status"}"#).await;
    assert_eq!(reply, "{\"return\":\"frozen\"}\n");
    assert!(rig.ctx.marker.exists());
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-thaw"}"#).await;
    assert_eq!(reply, "{\"return\":2}\n");
    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_ok(), "exits after the thaw");
    assert!(!rig.ctx.marker.exists());
    let text = sink.text();
    assert!(
        text.contains("\"event\":\"stop_deferred\""),
        "the deferral is logged: {text}"
    );
}

#[test]
fn runtime_is_multi_thread_with_at_least_two_workers() {
    let rt = daemon::build_runtime().unwrap();
    let workers = rt.block_on(async { tokio::runtime::Handle::current().metrics().num_workers() });
    assert!(workers >= 2);
}

/// Runs the real binary against a fresh pty with `features_toml` in the
/// `[features]` section: one ping round trip, then SIGTERM. Returns the
/// daemon's stderr and exit status.
fn run_binary_over_pty(features_toml: &str) -> (String, std::process::ExitStatus) {
    use nix::fcntl::OFlag;
    let master =
        nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
    nix::pty::grantpt(&master).unwrap();
    nix::pty::unlockpt(&master).unwrap();
    let slave_path = nix::pty::ptsname_r(&master).unwrap();
    let mut termios = nix::sys::termios::tcgetattr(&master).unwrap();
    nix::sys::termios::cfmakeraw(&mut termios);
    nix::sys::termios::tcsetattr(&master, nix::sys::termios::SetArg::TCSANOW, &termios).unwrap();
    // The slave must be raw too. Keep this descriptor open for the whole
    // run: with no slave open at all, reads on the master fail with EIO.
    let slave_holder = nix::fcntl::open(
        Path::new(&slave_path),
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    )
    .unwrap();
    let mut t = nix::sys::termios::tcgetattr(&slave_holder).unwrap();
    nix::sys::termios::cfmakeraw(&mut t);
    nix::sys::termios::tcsetattr(&slave_holder, nix::sys::termios::SetArg::TCSANOW, &t).unwrap();
    let dir = shm_dir();
    if nix::unistd::geteuid().is_root()
        && let Some(user) = nix::unistd::User::from_name("qeminga").unwrap()
    {
        nix::unistd::chown(dir.path(), Some(user.uid), Some(user.gid)).unwrap();
    }
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[agent]\nchannel_path = \"{slave_path}\"\nstate_path = \"{}\"\nlog_level = \"debug\"\n[features]\n{features_toml}\n",
            dir.path().join("frozen").display()
        ),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_qeminga"))
        .arg("--config")
        .arg(&config_path)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let master: OwnedFd = master.into();
    let flags = nix::fcntl::fcntl(master.as_fd(), nix::fcntl::FcntlArg::F_GETFL).unwrap();
    nix::fcntl::fcntl(
        master.as_fd(),
        nix::fcntl::FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )
    .unwrap();
    let mut master_file = std::fs::File::from(master);
    use std::io::Read;
    master_file
        .write_all(b"{\"execute\":\"guest-ping\",\"id\":1}\n")
        .unwrap();
    let mut reply = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !reply.ends_with(b"\n") {
        let exited = child.try_wait().unwrap().is_some();
        if exited || std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "no reply (exited={exited}); stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let mut fds = [nix::poll::PollFd::new(
            master_file.as_fd(),
            nix::poll::PollFlags::POLLIN,
        )];
        let _ = nix::poll::poll(&mut fds, nix::poll::PollTimeout::from(100u16));
        let mut buf = [0u8; 256];
        match master_file.read(&mut buf) {
            Ok(n) => reply.extend_from_slice(&buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => panic!("read: {err}"),
        }
    }
    assert_eq!(reply, b"{\"return\":{},\"id\":1}\n");
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    let output = child.wait_with_output().unwrap();
    drop(slave_holder);
    (
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status,
    )
}

/// The real binary, unprivileged config, pty channel: ping round trip, then
/// SIGTERM exits 0 (T4.6 "done when"; the full harness is T4.7).
#[test]
fn binary_serves_a_pty_and_exits_on_sigterm() {
    let (stderr, status) = run_binary_over_pty("seccomp = true\n");
    assert!(status.success(), "status {status}; stderr: {stderr}");
    assert!(
        stderr.contains("\"event\":\"command_received\""),
        "{stderr}"
    );
    assert!(stderr.contains("\"signal\":\"SIGTERM\""), "{stderr}");
    // The startup record names the seccomp policy this build installs, so
    // a run can prove whether it enforced or only logged.
    let expected = format!(
        "\"event\":\"seccomp\",\"installed\":{},\"mode\":\"{}\"",
        cfg!(feature = "seccomp"),
        daemon::seccomp_mode()
    );
    assert!(stderr.contains(&expected), "{expected} not in {stderr}");
    assert_eq!(
        stderr.contains("\"event\":\"seccomp_log_mode\""),
        cfg!(feature = "seccomp") && daemon::seccomp_mode() == "log",
        "{stderr}"
    );
}
