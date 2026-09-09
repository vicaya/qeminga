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
use qeminga::daemon::{self, BuildProfile, EX_CONFIG, EX_UNAVAILABLE, Options, RunError, Startup};
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

fn fixture_config(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config")
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

/// A sink whose first write takes `delay`: what the writer thread is
/// doing when the daemon returns is then never a matter of luck.
#[derive(Clone)]
struct SlowSink {
    inner: SharedSink,
    delay: Duration,
    slept: Arc<std::sync::atomic::AtomicBool>,
}

impl Write for SlowSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if !self.slept.swap(true, std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(self.delay);
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Installs, once per test process, a global subscriber that enables
/// every record and delivers it nowhere. Scoped subscribers in a
/// multi-threaded test binary need it: `tracing` caches a callsite's
/// interest through the current thread's dispatcher while a single one
/// is registered, so a callsite first hit on a thread without any (a test
/// calling `run_with` directly) would be cached as never interesting, and
/// a parallel test's scoped subscriber would never see that record. With
/// a global that enables everything, no callsite can be cached that way.
fn permissive_global_subscriber() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(qeminga::audit::subscriber(
            tracing::Level::TRACE,
            Router::new(Box::new(std::io::sink())),
        ));
    });
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
    /// The router `init_logging` hands out (over `sink`, possibly slow),
    /// so a test can subscribe the thread to it and read the sink.
    router: Router,
    /// What the fake build can enforce (a full production build unless a
    /// test says otherwise).
    build: BuildProfile,
    /// Whether the fake capability drop ran (root) or was skipped.
    root: bool,
    /// Whether the fake filter installs.
    filter_installs: bool,
    /// An error the fake installer fails with (a kernel that refuses the
    /// filter), instead of installing or not.
    filter_error: Option<&'static str>,
}

/// The `[agent]` lines every fake configuration starts with: the
/// development opt-out, since the fake startup is not root and most of
/// these tests are about the sequence, not the sandbox.
const DEV_AGENT: &str =
    "[agent]\nstate_path = \"/run/qeminga/frozen\"\nhardening = \"unenforced-development-only\"\n";

impl FakeStartup {
    fn new() -> Self {
        let sink = SharedSink::default();
        Self::over(sink.clone(), Box::new(sink))
    }
    /// A fake whose router delivers to `writer`, a view of `sink`.
    fn over(sink: SharedSink, writer: Box<dyn Write + Send>) -> Self {
        FakeStartup {
            steps: RefCell::new(Vec::new()),
            config: DEV_AGENT.to_owned(),
            marker: false,
            dir: shm_dir(),
            mountinfo: fixture("tmpfs_and_nfs.txt"),
            open: Ok(()),
            sink,
            router: Router::new(writer),
            build: BuildProfile {
                seccomp_compiled: true,
                seccomp_mode: "enforce",
                fake_kernel_requested: false,
            },
            root: false,
            filter_installs: true,
            filter_error: None,
        }
    }
    /// A fake whose sink takes `delay` over its first write.
    fn with_slow_sink(delay: Duration) -> Self {
        let sink = SharedSink::default();
        let slow = SlowSink {
            inner: sink.clone(),
            delay,
            slept: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        Self::over(sink, Box::new(slow))
    }
    /// Makes the marker's directory look like a planned ext4 root, so the
    /// start fails on the `state_path` check: a failure after logging is
    /// up, in ring mode when `marker` is set.
    fn failing_after_logging(mut self) -> Self {
        let (major, minor) = dev_of(self.dir.path());
        self.mountinfo = format!(
            "27 1 {major}:{minor} / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
             28 27 0:30 / /run rw,nosuid - tmpfs tmpfs rw\n"
        );
        self
    }
    /// Runs the daemon's startup with this thread subscribed to the
    /// fake's router, as the binary's global subscriber would be.
    fn run(&self) -> Result<(), RunError> {
        permissive_global_subscriber();
        tracing::subscriber::with_default(
            qeminga::audit::subscriber(tracing::Level::INFO, self.router.clone()),
            || daemon::run_with(&Options::default(), self),
        )
    }

    /// A fake production host: root, a full build, the default
    /// (enforced) configuration.
    fn production() -> Self {
        let mut startup = Self::new();
        startup.config = "[agent]\nstate_path = \"/run/qeminga/frozen\"\n".to_owned();
        startup.root = true;
        startup
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
    fn build_profile(&self) -> BuildProfile {
        self.build
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
        if ring {
            self.router.enter_ring();
        }
        Ok(self.router.clone())
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
        Ok(if self.root {
            Outcome::Dropped
        } else {
            Outcome::SkippedUnprivileged
        })
    }
    fn start_audit_writer(&self, router: &Router) -> Result<(), RunError> {
        self.log("audit writer");
        router
            .start_writer()
            .map_err(|err| RunError::Runtime(err.to_string()))
    }
    fn install_seccomp(&self, config: &Config) -> Result<bool, RunError> {
        self.log(format!("seccomp enabled={}", config.features.seccomp));
        if let Some(reason) = self.filter_error {
            return Err(RunError::Seccomp(reason.to_owned()));
        }
        // The fake models a full build: installed iff enabled (and the
        // fake installer is not scripted to fail).
        Ok(config.features.seccomp && self.filter_installs)
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
            "audit writer",
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

#[test]
fn a_failure_after_recovery_logging_started_still_reports_itself() {
    // A marker is present, so logging is in ring mode when the start is
    // refused (here by the `state_path` check; #47's hardening refusals
    // after the capability drop are the same path). The process is
    // leaving: the ring is flushed and its records, the refusal among
    // them, are delivered before `run_with` returns, or the journal shows
    // a restart loop with no reason.
    let mut startup = FakeStartup::new().failing_after_logging();
    startup.marker = true;
    assert_eq!(startup.steps().len(), 0);
    let err = startup.run().unwrap_err();
    assert_eq!(err.exit_code(), EX_CONFIG);
    assert!(
        startup
            .steps()
            .contains(&"logging info ring=true".to_owned())
    );
    // Written in ring mode, delivered anyway: the ring was flushed on the
    // way out and nothing is left in it.
    let text = startup.sink.text();
    assert!(text.contains("\"event\":\"startup_failed\""), "{text}");
    assert!(text.contains("state_path"), "{text}");
    assert_eq!(startup.router.mode(), Mode::Normal);
    assert_eq!(startup.router.lost(), 0);
}

#[test]
fn leaving_delivers_the_queued_records_before_returning() {
    // The global subscriber keeps a handle to the router for the life of
    // the process, so its last-handle grace never runs: the exit paths
    // settle the queue themselves, bounded. A sink slow over its first
    // write shows the difference: the refusal (and, on the other path,
    // the startup record) is on the sink when `run_with` returns.
    let startup = FakeStartup::with_slow_sink(Duration::from_millis(300)).failing_after_logging();
    let err = startup.run().unwrap_err();
    assert_eq!(err.exit_code(), EX_CONFIG);
    let text = startup.sink.text();
    assert!(text.contains("\"event\":\"startup_failed\""), "{text}");
    let startup = FakeStartup::with_slow_sink(Duration::from_millis(300));
    startup.run().unwrap();
    let text = startup.sink.text();
    assert!(text.contains("\"event\":\"startup\""), "{text}");
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
    startup.config = "[agent]\nstate_path = \"/var/lib/qeminga/frozen\"\nhardening = \"unenforced-development-only\"\n".to_owned();
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
fn a_configuration_without_the_operation_timeout_and_a_short_cap_starts() {
    // Written before `fsfreeze_operation_timeout_secs` existed: the
    // deadline is derived under the cap instead of failing startup.
    let mut startup = FakeStartup::production();
    startup.config = fixture_config("legacy_short_cap.toml");
    daemon::run_with(&Options::default(), &startup).unwrap();
    assert!(
        startup.steps().last().unwrap().starts_with("runtime"),
        "{:?}",
        startup.steps()
    );
}

fn hardening_refusal(startup: &FakeStartup) -> String {
    let err = daemon::run_with(&Options::default(), startup).unwrap_err();
    assert!(matches!(err, RunError::Hardening(_)), "{err}");
    assert_eq!(err.exit_code(), EX_CONFIG);
    let text = err.to_string();
    assert!(text.contains("refusing to serve the host"), "{text}");
    assert!(text.contains("unenforced-development-only"), "{text}");
    text
}

#[test]
fn enforced_hardening_refuses_what_the_build_cannot_enforce_before_the_marker_is_touched() {
    // #43 §4: a production configuration (the default) on a binary
    // without the filter, or with a logging filter, or asked to fake the
    // kernel, never gets past step 1: no marker opened, no logging, no
    // channel, and a marker of a previous instance is left as it was.
    for (what, build) in [
        (
            "without the `seccomp` Cargo feature",
            BuildProfile {
                seccomp_compiled: false,
                seccomp_mode: "unavailable",
                fake_kernel_requested: false,
            },
        ),
        (
            "would only log",
            BuildProfile {
                seccomp_compiled: true,
                seccomp_mode: "log",
                fake_kernel_requested: false,
            },
        ),
        (
            "test-kernel substitution",
            BuildProfile {
                seccomp_compiled: true,
                seccomp_mode: "enforce",
                fake_kernel_requested: true,
            },
        ),
    ] {
        let mut startup = FakeStartup::production();
        startup.build = build;
        startup.marker = true;
        let marker_path = startup.dir.path().join("frozen");
        std::fs::write(&marker_path, b"").unwrap();
        let text = hardening_refusal(&startup);
        assert!(text.contains(what), "{text}");
        assert_eq!(startup.steps(), ["config /etc/qeminga/config.toml"]);
        assert!(marker_path.exists(), "the recovery marker is untouched");
    }
    // The same builds serve a development host (the warning they get is
    // observed on the real binary in `feature_warnings_are_logged_once_at_startup`).
    let mut startup = FakeStartup::new();
    startup.build = BuildProfile {
        seccomp_compiled: false,
        seccomp_mode: "unavailable",
        fake_kernel_requested: true,
    };
    daemon::run_with(&Options::default(), &startup).unwrap();
    assert!(startup.steps().last().unwrap().starts_with("runtime"));
}

#[test]
fn enforced_hardening_refuses_a_start_whose_sandbox_did_not_come_up() {
    // Steps 5 and 6: not root (the capability drop cannot run) and a
    // filter that did not install are refusals too, before the runtime.
    let mut startup = FakeStartup::production();
    startup.root = false;
    let text = hardening_refusal(&startup);
    assert!(text.contains("not started as root"), "{text}");
    assert!(!startup.steps().iter().any(|s| s.starts_with("runtime")));
    let mut startup = FakeStartup::production();
    startup.filter_installs = false;
    let text = hardening_refusal(&startup);
    assert!(text.contains("not installed"), "{text}");
    assert!(!startup.steps().iter().any(|s| s.starts_with("runtime")));
    // And a production host that has everything serves.
    let startup = FakeStartup::production();
    daemon::run_with(&Options::default(), &startup).unwrap();
    assert!(startup.steps().last().unwrap().starts_with("runtime"));
}

#[test]
fn a_refusal_after_recovery_logging_started_is_reported_on_the_way_out() {
    // A marker is present (recovery mode: logging in the ring) and the
    // enforcing build was started unprivileged: the refusal comes after
    // step 2b, and is delivered on the way out all the same, so the
    // journal of a restart loop says why (#47 review).
    let mut startup = FakeStartup::production();
    startup.marker = true;
    startup.root = false;
    let err = startup.run().unwrap_err();
    assert!(matches!(err, RunError::Hardening(_)), "{err}");
    assert_eq!(err.exit_code(), EX_CONFIG);
    assert!(
        startup
            .steps()
            .contains(&"logging info ring=true".to_owned())
    );
    let text = startup.sink.text();
    assert!(text.contains("\"event\":\"startup_failed\""), "{text}");
    assert!(text.contains("not started as root"), "{text}");
    assert!(text.contains("unenforced-development-only"), "{text}");
    assert_eq!(startup.router.mode(), Mode::Normal);
    assert!(
        startup.dir.path().join("frozen").exists(),
        "marker untouched"
    );
}

#[test]
fn a_filter_the_kernel_refuses_is_a_hardening_refusal_when_enforced_and_a_warning_otherwise() {
    // The installer fails (a kernel or container policy that rejects the
    // filter): under enforced hardening that is the hardening refusal,
    // exit 78 with the cause and the opt-out named, not EX_OSERR; under
    // the development opt-out it is a warning and the daemon runs without
    // the filter, as for a filter that is absent.
    let mut startup = FakeStartup::production();
    startup.filter_error = Some("prctl(PR_SET_SECCOMP): EACCES");
    let text = hardening_refusal(&startup);
    assert!(text.contains("could not be installed"), "{text}");
    assert!(text.contains("EACCES"), "{text}");
    assert!(!startup.steps().iter().any(|s| s.starts_with("runtime")));
    let mut startup = FakeStartup::new();
    startup.filter_error = Some("prctl(PR_SET_SECCOMP): EACCES");
    startup.run().unwrap();
    assert!(startup.steps().last().unwrap().starts_with("runtime"));
    let text = startup.sink.text();
    assert!(text.contains("\"event\":\"seccomp_unavailable\""), "{text}");
    assert!(text.contains("EACCES"), "{text}");
    assert!(text.contains("\"installed\":false"), "{text}");
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
            "audit writer",
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
    let expected = Config::parse(
        "[agent]\nhardening = \"unenforced-development-only\"\n[features]\nseccomp = true\nsuspend_ram = true\n",
    )
    .unwrap()
    .warnings()
    .len();
    assert!(expected >= 1, "the opt-out itself is warned about");
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
    assert!(rig.ctx.audit.settle(Duration::from_secs(10)));
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
    assert!(rig.ctx.audit.settle(Duration::from_secs(10)));
    let text = sink.text();
    assert!(
        text.contains("\"event\":\"stop_deferred\""),
        "the deferral is logged: {text}"
    );
}

/// An opener that answers `EBUSY` (another process took the port) and
/// counts its calls.
fn busy_open(calls: &Arc<std::sync::atomic::AtomicUsize>) -> OpenFn {
    let calls = Arc::clone(calls);
    Arc::new(move |_| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::from_raw_os_error(Errno::EBUSY as i32))
    })
}

async fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out: {what}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_terminal_channel_error_while_frozen_waits_for_the_thaw() {
    // The host froze the guest, the session ended, and the reopen finds
    // the port held by another process (EBUSY): serving stops for good,
    // but the exit is deferred like a requested stop (C-21) until the
    // filesystems are thawed, here by the watchdog, since no host can
    // reach this process any more. The terminal error is still reported.
    let sink = SharedSink::default();
    let rig = rig_with_idle(false, &sink, 3);
    let ctx = rig.ctx.clone();
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (_signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let initial = take_initial();
    let router = rig.ctx.audit.clone();
    let open = busy_open(&opens);
    let server = tokio::spawn(
        async move {
            daemon::serve_until_signal(
                ctx,
                Path::new("/dev/virtio-ports/fake"),
                open,
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
    drop(peer);
    let opens_seen = || opens.load(std::sync::atomic::Ordering::SeqCst) >= 1;
    wait_for("the reopen attempt", opens_seen).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        !server.is_finished(),
        "the terminal error must not bypass the thaw"
    );
    assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
    assert!(rig.ctx.marker.exists());
    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("exits once the watchdog has thawed")
        .unwrap();
    let err = result.unwrap_err();
    assert!(err.is_terminal(), "{err}");
    assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
    assert!(!rig.ctx.marker.exists());
    assert_eq!(
        opens.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "no competing for the port"
    );
    assert!(rig.ctx.audit.settle(Duration::from_secs(10)));
    let text = sink.text();
    assert!(text.contains("\"event\":\"channel_lost\""), "{text}");
    assert!(text.contains("\"event\":\"stop_deferred\""), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_terminal_channel_error_during_a_thaw_waits_for_its_completion() {
    // The watchdog's thaw is in flight (its first FITHAW is held behind a
    // barrier) when the reopen hits EBUSY: serving ends only after that
    // thaw has completed, so the runtime is never torn down under a
    // destructive operation.
    let sink = SharedSink::default();
    let rig = rig_with_idle(false, &sink, 1);
    let gate = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    /// Releases the barrier when dropped, so a failed assertion never
    /// leaves the thaw (and the runtime's shutdown) blocked.
    struct Release(Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            let (open, released) = &*self.0;
            *open.lock().unwrap() = true;
            released.notify_all();
        }
    }
    let release = Release(Arc::clone(&gate));
    let kernel = Arc::new(FakeKernel::new());
    let hook_gate = Arc::clone(&gate);
    kernel.set_hook(Box::new(move |call| {
        if matches!(call, qeminga::kernel::fake::Call::Fithaw(_)) {
            let (open, released) = &*hook_gate;
            let mut open = open.lock().unwrap();
            while !*open {
                open = released.wait(open).unwrap();
            }
        }
    }));
    let ctx = Arc::new(
        Arc::try_unwrap(rig.ctx)
            .unwrap_or_else(|_| panic!("unshared"))
            .with_kernel(kernel),
    );
    let opens = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (_signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let initial = take_initial();
    let open = busy_open(&opens);
    let server_ctx = Arc::clone(&ctx);
    let server = tokio::spawn(async move {
        daemon::serve_until_signal(
            server_ctx,
            Path::new("/dev/virtio-ports/fake"),
            open,
            Some(initial),
            false,
            async move { signal_rx.await.unwrap_or("closed") },
            Duration::from_millis(20),
        )
        .await
    });
    let mut peer = Channel::from_fd(rig.peer).unwrap();
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
    assert_eq!(reply, "{\"return\":2}\n");
    wait_for("the watchdog's thaw", || {
        ctx.state.current() == FreezeState::Thawing
    })
    .await;
    drop(peer);
    wait_for("the reopen attempt", || {
        opens.load(std::sync::atomic::Ordering::SeqCst) >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!server.is_finished(), "a thaw is in flight");
    assert_eq!(ctx.state.current(), FreezeState::Thawing);
    drop(release);
    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("exits once the thaw has completed")
        .unwrap();
    assert!(result.unwrap_err().is_terminal());
    assert_eq!(ctx.state.current(), FreezeState::Thawed);
    assert!(!ctx.marker.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_during_an_unresolved_freeze_waits_for_its_settlement() {
    // The freeze aborts on its deadline with a FIFREEZE still in flight;
    // the request has failed, but the process may not exit until the
    // in-flight call has returned and the recovery settled (C-21): the
    // stop is deferred, then honoured once `Thawed`.
    let sink = SharedSink::default();
    let rig = rig(false, &sink);
    let kernel = Arc::new(FakeKernel::new());
    let gate = kernel.script_freeze_gate("/");
    let _release = gate.release_on_drop();
    let ctx = Arc::new(
        Arc::try_unwrap(rig.ctx)
            .unwrap_or_else(|_| panic!("unshared"))
            .with_kernel(kernel)
            .with_freeze_operation_timeout(Duration::from_millis(300)),
    );
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel::<&'static str>();
    let initial = take_initial();
    let server_ctx = Arc::clone(&ctx);
    let server = tokio::spawn(async move {
        daemon::serve_until_signal(
            server_ctx,
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
    // simple.txt freezes /home first, then / (blocked at the gate).
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
    assert!(reply.contains("freeze aborted"), "{reply}");
    assert_eq!(ctx.state.current(), FreezeState::Thawing);
    assert!(ctx.marker.exists());
    signal_tx.send("SIGTERM").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!server.is_finished(), "stop deferred while unresolved");
    let reply = request(&mut peer, r#"{"execute":"guest-fsfreeze-status"}"#).await;
    assert_eq!(reply, "{\"return\":\"frozen\"}\n");
    gate.release();
    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("exits once the operation has settled")
        .unwrap();
    assert!(result.is_ok());
    assert_eq!(ctx.state.current(), FreezeState::Thawed);
    assert!(!ctx.marker.exists());
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
    run_binary_over_pty_with(
        "hardening = \"unenforced-development-only\"\n",
        features_toml,
        true,
    )
}

/// As [`run_binary_over_pty`], with `agent_toml` appended to `[agent]`;
/// with `expect_reply` false the daemon is expected to exit on its own
/// without serving, and its status and stderr are returned.
fn run_binary_over_pty_with(
    agent_toml: &str,
    features_toml: &str,
    expect_reply: bool,
) -> (String, std::process::ExitStatus) {
    use nix::fcntl::OFlag;
    // As in tests/e2e/mod.rs: root without the service account cannot run
    // the daemon (exit 77); say so once instead of failing obscurely.
    if nix::unistd::geteuid().is_root()
        && nix::unistd::User::from_name("qeminga").unwrap().is_none()
    {
        panic!(
            "running as root without the `qeminga` account: create it with \
             `sudo systemd-sysusers packaging/sysusers.d/qeminga.conf` or run the tests unprivileged"
        );
    }
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
            "[agent]\nchannel_path = \"{slave_path}\"\nstate_path = \"{}\"\nlog_level = \"debug\"\n{agent_toml}[features]\n{features_toml}\n",
            dir.path().join("frozen").display()
        ),
    )
    .unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_qeminga"));
    command
        .arg("--config")
        .arg(&config_path)
        .env_remove("QEMINGA_TEST_FAKE_KERNEL")
        .stderr(std::process::Stdio::piped());
    ENV_OVERRIDE.with(|cell| {
        if let Some((name, value)) = cell.borrow().as_ref() {
            command.env(name, value);
        }
    });
    let mut child = command.spawn().unwrap();
    let master: OwnedFd = master.into();
    let flags = nix::fcntl::fcntl(master.as_fd(), nix::fcntl::FcntlArg::F_GETFL).unwrap();
    nix::fcntl::fcntl(
        master.as_fd(),
        nix::fcntl::FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )
    .unwrap();
    let mut master_file = std::fs::File::from(master);
    use std::io::Read;
    if !expect_reply {
        let output = child.wait_with_output().unwrap();
        drop(slave_holder);
        return (
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status,
        );
    }
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

/// The real binary under the default (enforced) hardening: it serves
/// only as root with an enforcing filter compiled in and no test-kernel
/// request; anything else exits 78 before the marker is touched, and says
/// what was missing (#43 §4).
#[test]
fn the_binary_refuses_enforced_hardening_it_cannot_provide() {
    let root = nix::unistd::geteuid().is_root();
    let enforcing = cfg!(feature = "seccomp") && daemon::seccomp_mode() == "enforce";
    if root && enforcing {
        // A full production start; the fake-kernel request alone is
        // refused (test-fakes builds honour the variable only under the
        // development opt-out; other builds refuse it all the same).
        let (stderr, status) = run_binary_over_pty_with("", "seccomp = true\n", true);
        assert!(status.success(), "{status}: {stderr}");
        assert!(
            stderr.contains("\"event\":\"privileges_dropped\""),
            "{stderr}"
        );
        assert!(
            stderr.contains("\"installed\":true,\"mode\":\"enforce\""),
            "{stderr}"
        );
    }
    let (stderr, status) = {
        // The variable is what production_context would act on; set for
        // the child only.
        let saved = std::env::var_os("QEMINGA_TEST_FAKE_KERNEL");
        // SAFETY-free: the harness spawns the child with the parent's
        // environment, so set it around the spawn.
        unsafe_free_setenv("QEMINGA_TEST_FAKE_KERNEL", Some("1"));
        let out = run_binary_over_pty_with("", "seccomp = true\n", false);
        unsafe_free_setenv(
            "QEMINGA_TEST_FAKE_KERNEL",
            saved.as_deref().and_then(|s| s.to_str()),
        );
        out
    };
    assert_eq!(status.code(), Some(i32::from(EX_CONFIG)), "{stderr}");
    assert!(stderr.contains("refusing to serve the host"), "{stderr}");
    let expected = if !cfg!(feature = "seccomp") {
        "without the `seccomp` Cargo feature"
    } else if daemon::seccomp_mode() != "enforce" {
        "would only log"
    } else {
        "QEMINGA_TEST_FAKE_KERNEL is set"
    };
    assert!(
        stderr.contains(expected),
        "expected {expected:?} in {stderr}"
    );
    assert!(
        !stderr.contains("\"event\":\"startup\""),
        "refused before logging: {stderr}"
    );
    // A disabled filter is a configuration error under the default.
    let (stderr, status) = run_binary_over_pty_with("", "seccomp = false\n", false);
    assert_eq!(status.code(), Some(i32::from(EX_CONFIG)), "{stderr}");
    assert!(stderr.contains("features.seccomp"), "{stderr}");
    // Unprivileged, or a build that cannot enforce: refused as such.
    if !(root && enforcing) {
        let (stderr, status) = run_binary_over_pty_with("", "seccomp = true\n", false);
        assert_eq!(status.code(), Some(i32::from(EX_CONFIG)), "{stderr}");
        assert!(stderr.contains("refusing to serve the host"), "{stderr}");
    }
}

/// Sets or removes a process environment variable for the tests' child
/// processes. Tests in this file run in one process, so the variable is
/// visible to concurrently spawned children for the duration; the only
/// other spawn here reads it through `production_context`, which the
/// development opt-out ignores.
fn unsafe_free_setenv(name: &str, value: Option<&str>) {
    // `std::env::set_var` is unsafe in edition 2024; the harness uses a
    // per-child override instead, so this helper only records the intent.
    ENV_OVERRIDE.with(|cell| {
        *cell.borrow_mut() = value.map(|v| (name.to_owned(), v.to_owned()));
    });
}

thread_local! {
    static ENV_OVERRIDE: RefCell<Option<(String, String)>> = const { RefCell::new(None) };
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
