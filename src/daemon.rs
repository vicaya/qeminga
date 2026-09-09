//! Startup sequence, runtime, and signal handling (design §6 `main.rs`,
//! §5.4/§5.5 order, §4.4 recovery mode, §5.7 deferred stop, §8.2
//! `state_path` validation, §8.4 `EBUSY` is terminal; C-14, C-18, C-21).
//!
//! The sequence, each step behind the [`Startup`] trait so it is testable
//! against a recording fake:
//!
//! 1. load and validate the configuration;
//! 2. open the recovery marker's directory (read-only; the descriptor is
//!    kept for every later marker operation, §4.4) and look for the
//!    marker to choose the initial state; start logging, in ring mode
//!    when recovering (§4.4): records are queued from here, the writer
//!    thread that delivers them starts at step 5b;
//! 3. reject a `state_path` whose directory is on a filesystem the freeze
//!    plan would freeze (§8.2), judged by the device of the opened
//!    directory, not by the pathname;
//! 4. open the channel (`EBUSY` is terminal, §8.4);
//! 5. drop capabilities (skipped with a warning when not root, C-18), then
//!    start the audit writer thread (5b): every thread of the process is
//!    created under the dropped ceiling, which the drop establishes only
//!    for the calling thread (§5.4);
//! 6. install seccomp when compiled in and enabled;
//! 7. start the multi-threaded runtime and serve until a signal.
//!
//! No ioctl and no marker write happens before step 7. A `SIGTERM`/`SIGINT`
//! while the state is not `Thawed` is deferred until the thaw completes
//! (C-21). Once the loop has stopped, the runtime is shut down under
//! [`RUNTIME_SHUTDOWN_GRACE`]: freeze, thaw and trim always run to
//! completion before that point (the stop waits for them), so the bound
//! only ever cuts short an abandoned informational walk
//! (`guest-get-fsinfo`), which a blocked `statfs` could otherwise hold
//! open for ever.
#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::future::Future;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::audit::{self, Router};
use crate::channel::{self, OpenError, OpenFn};
use crate::config::{Config, ConfigError, DEFAULT_CONFIG_PATH, LogLevel};
use crate::dispatch::{Context, Dispatcher};
use crate::freeze_plan::FreezePlan;
use crate::handlers::fsfreeze;
use crate::kernel::caps::{Outcome, PrivilegeError};
use crate::marker::{Marker, MarkerError};
use crate::mountinfo::{MountEntry, MountSource};
use crate::state::{FreezeState, FreezeStateMachine};

/// The service account (§5.4, §8.3).
pub const SERVICE_USER: &str = "qeminga";

/// `EX_USAGE`.
pub const EX_USAGE: u8 = 64;
/// `EX_UNAVAILABLE`: the channel cannot be served (already open).
pub const EX_UNAVAILABLE: u8 = 69;
/// `EX_SOFTWARE`: internal failure.
pub const EX_SOFTWARE: u8 = 70;
/// `EX_OSERR`: the runtime or seccomp could not be set up.
pub const EX_OSERR: u8 = 71;
/// `EX_NOPERM`: the capability drop failed.
pub const EX_NOPERM: u8 = 77;
/// `EX_CONFIG`: configuration or `state_path` problem.
pub const EX_CONFIG: u8 = 78;

/// How often a deferred stop re-checks the freeze state (C-21).
pub const STOP_POLL: Duration = Duration::from_millis(250);

/// How long the runtime shutdown waits for blocking work once the loop
/// has stopped. Every freeze, thaw and trim has completed by then (a stop
/// is deferred until `Thawed` and the session finishes its command), so
/// only an abandoned `guest-get-fsinfo` walk stuck in `statfs(2)` can
/// still be running, and it must not hold the exit.
pub const RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Usage line.
pub const USAGE: &str = "usage: qeminga [--config PATH] [--version]";

/// Parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Configuration file (`--config`, default [`DEFAULT_CONFIG_PATH`]).
    pub config_path: PathBuf,
    /// `--version`/`-V` was given.
    pub version: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
            version: false,
        }
    }
}

/// A command-line error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UsageError(pub String);

/// Hand-rolled argument parsing: `--config PATH`, `--config=PATH`,
/// `--version`/`-V`. Anything else is a usage error.
pub fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Options, UsageError> {
    let mut opts = Options::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if arg == "--version" || arg == "-V" {
            opts.version = true;
        } else if arg == "--config" {
            match iter.next() {
                Some(path) => opts.config_path = PathBuf::from(path),
                None => return Err(UsageError("--config needs a PATH".to_owned())),
            }
        } else if let Some(path) = arg.as_encoded_bytes().strip_prefix(b"--config=") {
            // Byte-wise, so a non-UTF-8 path works in this form as it does
            // in the two-token form.
            if path.is_empty() {
                return Err(UsageError("--config needs a PATH".to_owned()));
            }
            opts.config_path = PathBuf::from(OsStr::from_bytes(path));
        } else {
            return Err(UsageError(format!(
                "unrecognised argument: {}",
                arg.to_string_lossy()
            )));
        }
    }
    Ok(opts)
}

/// Why startup or serving failed; maps to an exit code.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// Configuration file problem.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// The recovery marker's directory could not be opened, or the path
    /// has no directory or file name.
    #[error("{0}")]
    Marker(#[from] MarkerError),
    /// `state_path` is on a filesystem the freeze plan would freeze: its
    /// directory, opened and resolved as the kernel does, is on a planned
    /// device.
    #[error(
        "state_path {} is on {} ({}:{}), which the freeze plan would freeze; put it on tmpfs (e.g. /run)",
        path.display(),
        mount.display(),
        dev.0,
        dev.1
    )]
    StatePath {
        /// The configured path.
        path: PathBuf,
        /// A mount point of the planned filesystem the directory is on.
        mount: PathBuf,
        /// That filesystem's `(major, minor)`.
        dev: (u32, u32),
    },
    /// The mount table could not be read for the `state_path` check.
    #[error("cannot read the mount table: {0}")]
    MountTable(String),
    /// The channel could not be opened.
    #[error("{0}")]
    Channel(#[from] OpenError),
    /// The capability drop failed.
    #[error("cannot drop privileges: {0}")]
    Privileges(#[from] PrivilegeError),
    /// The seccomp filter could not be built or installed.
    #[error("seccomp: {0}")]
    Seccomp(String),
    /// `[agent] hardening = "enforced"` and the advertised sandbox is
    /// unavailable, disabled or would not be installed (#43 §4): the
    /// daemon refuses to serve the host. A recovery marker, if any, is
    /// left in place for the next start.
    #[error(
        "hardening: {0}; refusing to serve the host (set [agent] hardening = \"unenforced-development-only\" on a development host only)"
    )]
    Hardening(String),
    /// The runtime could not be built or logging could not be initialised.
    #[error("{0}")]
    Runtime(String),
}

impl RunError {
    /// The sysexits-style code for this error.
    pub fn exit_code(&self) -> u8 {
        match self {
            RunError::Config(_)
            | RunError::Marker(_)
            | RunError::StatePath { .. }
            | RunError::MountTable(_)
            | RunError::Hardening(_) => EX_CONFIG,
            RunError::Channel(_) => EX_UNAVAILABLE,
            RunError::Privileges(_) => EX_NOPERM,
            RunError::Seccomp(_) | RunError::Runtime(_) => EX_OSERR,
        }
    }
}

/// What this build can enforce (§8.1, #43 §4): checked against
/// `[agent] hardening` right after the configuration is loaded, before
/// the marker is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildProfile {
    /// The `seccomp` Cargo feature is compiled in.
    pub seccomp_compiled: bool,
    /// The filter's mode: `"enforce"`, `"log"` or `"unavailable"`.
    pub seccomp_mode: &'static str,
    /// A test-kernel substitution was requested (`QEMINGA_TEST_FAKE_KERNEL`
    /// is set), whether or not this build could honour it.
    pub fake_kernel_requested: bool,
}

impl BuildProfile {
    /// The running binary's profile.
    pub fn current() -> Self {
        BuildProfile {
            seccomp_compiled: cfg!(feature = "seccomp"),
            seccomp_mode: seccomp_mode(),
            fake_kernel_requested: std::env::var_os(FAKE_KERNEL_ENV).is_some(),
        }
    }
}

/// Refuses, under `hardening = "enforced"`, what this build or this
/// configuration cannot enforce: a filter that is not compiled in, that is
/// disabled (already a configuration error), that would only log, or a
/// requested test-kernel substitution. Nothing here has touched the marker.
pub fn check_hardening(config: &Config, build: &BuildProfile) -> Result<(), RunError> {
    if !config.agent.hardening.is_enforced() {
        return Ok(());
    }
    if !config.features.seccomp {
        return Err(RunError::Hardening(
            "the seccomp filter is disabled ([features] seccomp = false)".to_owned(),
        ));
    }
    if !build.seccomp_compiled {
        return Err(RunError::Hardening(
            "this binary was built without the `seccomp` Cargo feature".to_owned(),
        ));
    }
    if build.seccomp_mode != "enforce" {
        return Err(RunError::Hardening(format!(
            "this binary's seccomp filter would only {} (a `seccomp-log` debug build)",
            build.seccomp_mode
        )));
    }
    if build.fake_kernel_requested {
        return Err(RunError::Hardening(format!(
            "{FAKE_KERNEL_ENV} is set: a test-kernel substitution is never honoured under enforced hardening"
        )));
    }
    Ok(())
}

/// The steps of the startup sequence, in the order [`run_with`] calls
/// them. Production is [`SystemStartup`]; tests record the calls.
pub trait Startup {
    /// Step 1.
    fn load_config(&self, path: &Path) -> Result<Config, ConfigError>;
    /// Step 1b: what this build can enforce, for [`check_hardening`].
    fn build_profile(&self) -> BuildProfile;
    /// Step 2a: open the recovery marker's directory, read-only, and keep
    /// it for every later marker operation (§4.4); the marker's presence
    /// (`exists`) chooses the initial state. Nothing is created.
    fn open_marker(&self, path: &Path) -> Result<Marker, RunError>;
    /// Step 2b: start logging; `ring` is `true` in recovery mode.
    fn init_logging(&self, level: LogLevel, ring: bool) -> Result<Router, RunError>;
    /// Step 3: the mount table for the `state_path` check (the device of
    /// the opened marker directory against the freeze plan, §8.2).
    fn mount_table(&self) -> Result<Vec<MountEntry>, String>;
    /// Step 4: one attempt to open the channel while still privileged.
    /// `EBUSY` is terminal; any other failure yields `Ok(None)` and the
    /// runtime's reopen loop (§5.7) retries after the drop, so a missing
    /// device never delays the privilege drop, the seccomp filter or the
    /// recovery watchdog (C-14, OQ-7).
    fn open_channel(&self, path: &Path) -> Result<Option<OwnedFd>, OpenError>;
    /// Step 5.
    fn drop_privileges(&self) -> Result<Outcome, PrivilegeError>;
    /// Step 5b: start the audit writer thread, after the drop so that it
    /// is created under the dropped ceiling (§5.4).
    fn start_audit_writer(&self, router: &Router) -> Result<(), RunError> {
        router
            .start_writer()
            .map_err(|err| RunError::Runtime(format!("cannot start the audit writer: {err}")))
    }
    /// Step 6: `Ok(true)` when a filter was installed.
    fn install_seccomp(&self, config: &Config) -> Result<bool, RunError>;
    /// Step 7: run until a signal; `recovery` selects the `Frozen` start;
    /// `channel` is the descriptor step 4 opened, if it did; `marker` is
    /// the handle step 2 opened.
    fn serve(
        &self,
        config: Arc<Config>,
        router: Router,
        recovery: bool,
        channel: Option<OwnedFd>,
        marker: Marker,
    ) -> Result<(), RunError>;
}

/// The seccomp mode this binary installs: `"enforce"`, `"log"` (the
/// `seccomp-log` feature in a debug build) or `"unavailable"` (built
/// without the `seccomp` feature). Logged in the startup audit record so a
/// test run can prove which policy it exercised.
pub fn seccomp_mode() -> &'static str {
    #[cfg(feature = "seccomp")]
    {
        crate::seccomp::mode()
    }
    #[cfg(not(feature = "seccomp"))]
    {
        "unavailable"
    }
}

/// Runs the startup sequence through `startup`. Once logging is up, every
/// way out, a refusal or the end of serving, is reported to it and then
/// gives delivery the bounded [`audit::DELIVERY_GRACE`], the ring flushed
/// first: the process is leaving, so a refusal that came after recovery
/// logging started (§4.4) is not left in a ring nothing will drain, and a
/// record queued behind a slow sink is not lost to the exit. The global
/// subscriber keeps its handle for the life of the process, so this is
/// the settlement, not the last handle's drop.
pub fn run_with(opts: &Options, startup: &dyn Startup) -> Result<(), RunError> {
    let config = startup.load_config(&opts.config_path)?;
    // Before the marker is even opened: a refusal leaves a recovery marker
    // exactly as it was, for the next start to act on.
    check_hardening(&config, &startup.build_profile())?;
    let marker = startup.open_marker(&config.agent.state_path)?;
    let recovery = marker.exists();
    let router = startup.init_logging(config.agent.log_level, recovery)?;
    let logging = router.clone();
    let result = serve_after_logging(opts, startup, config, marker, recovery, router);
    if let Err(err) = &result {
        tracing::error!(event = "startup_failed", error = %err, "exiting");
    }
    logging.flush_to_normal();
    // A refusal before the drop leaves without a writer thread: one is
    // started now, to say why, with whatever privileges the process still
    // has, since it is leaving.
    let _ = logging.start_writer();
    logging.settle(audit::DELIVERY_GRACE);
    result
}

/// The steps after logging is up (see [`run_with`]).
fn serve_after_logging(
    opts: &Options,
    startup: &dyn Startup,
    config: Config,
    marker: Marker,
    recovery: bool,
    router: Router,
) -> Result<(), RunError> {
    for warning in config.warnings() {
        tracing::warn!(
            event = "feature_warning",
            warning = warning.as_str(),
            "configuration warning"
        );
    }
    tracing::info!(
        event = "startup",
        version = crate::VERSION,
        config = %opts.config_path.display(),
        recovery,
        "starting"
    );
    let mounts = startup.mount_table().map_err(RunError::MountTable)?;
    let plan = FreezePlan::build(&mounts);
    // The device of the directory the kernel resolved the path to, not
    // the pathname's prefix: `/run/../var/lib/x` and a symlinked parent
    // both look like `/run` to a prefix match (§8.2).
    let dev = marker.dev();
    if plan.covers_device(dev) {
        let mount = mounts
            .iter()
            .find(|entry| entry.dev() == dev)
            .map(|entry| entry.mount_point.clone())
            .unwrap_or_default();
        return Err(RunError::StatePath {
            path: config.agent.state_path.clone(),
            mount,
            dev,
        });
    }
    let channel = startup.open_channel(&config.agent.channel_path)?;
    if channel.is_none() {
        tracing::warn!(
            event = "channel_open_deferred",
            path = %config.agent.channel_path.display(),
            "channel not open yet; the runtime retries after the privilege drop"
        );
    }
    match startup.drop_privileges()? {
        Outcome::Dropped => tracing::info!(
            event = "privileges_dropped",
            user = SERVICE_USER,
            "capabilities dropped"
        ),
        Outcome::SkippedUnprivileged if config.agent.hardening.is_enforced() => {
            return Err(RunError::Hardening(
                "not started as root, so the capability drop did not run".to_owned(),
            ));
        }
        Outcome::SkippedUnprivileged => {}
    }
    // Only now a second thread: created by the dropped thread, it inherits
    // the dropped ceiling (uid, capability sets, bounding set).
    startup.start_audit_writer(&router)?;
    // An installer that fails (a kernel or a container policy refusing
    // the filter) is a hardening outcome like a filter that is absent:
    // the refusal under the enforced profile, a warning under the
    // development opt-out. It is never an `EX_OSERR` exit of its own.
    let seccomp = match startup.install_seccomp(&config) {
        Ok(installed) => installed,
        Err(RunError::Seccomp(reason)) if config.agent.hardening.is_enforced() => {
            return Err(RunError::Hardening(format!(
                "the seccomp filter could not be installed: {reason}"
            )));
        }
        Err(RunError::Seccomp(reason)) => {
            tracing::warn!(
                event = "seccomp_unavailable",
                reason = %reason,
                "the seccomp filter could not be installed; running without it (development hardening)"
            );
            false
        }
        Err(other) => return Err(other),
    };
    if !seccomp && config.agent.hardening.is_enforced() {
        return Err(RunError::Hardening(
            "the seccomp filter was not installed".to_owned(),
        ));
    }
    let mode = seccomp_mode();
    tracing::info!(
        event = "seccomp",
        installed = seccomp,
        mode,
        "seccomp filter"
    );
    if seccomp && mode == "log" {
        tracing::warn!(
            event = "seccomp_log_mode",
            "compatibility build: unlisted syscalls are logged, not killed (never for a release)"
        );
    }
    startup.serve(Arc::new(config), router, recovery, channel, marker)
}

/// Production entry point: parse, run, map errors to exit codes.
pub fn run(opts: Options) -> ExitCode {
    if opts.version {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "qeminga {}", crate::VERSION);
        return ExitCode::SUCCESS;
    }
    match run_with(&opts, &SystemStartup) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Logging up: `run_with` reported the failure to it and gave
            // delivery its grace. Failed before logging existed (a
            // configuration error): stderr is the only channel left.
            if !tracing::dispatcher::has_been_set() {
                diag(&format!("qeminga: {err}"));
            }
            ExitCode::from(err.exit_code())
        }
    }
}

/// Best-effort diagnostic on stderr. A failed write is deliberately
/// ignored: there is nowhere left to report it, and panicking would be
/// worse.
pub fn diag(msg: &str) {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{msg}");
}

/// The real steps.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemStartup;

impl Startup for SystemStartup {
    fn load_config(&self, path: &Path) -> Result<Config, ConfigError> {
        Config::load(path)
    }

    fn build_profile(&self) -> BuildProfile {
        BuildProfile::current()
    }

    fn open_marker(&self, path: &Path) -> Result<Marker, RunError> {
        Ok(Marker::open(path)?)
    }

    fn init_logging(&self, level: LogLevel, ring: bool) -> Result<Router, RunError> {
        // Not started: the writer thread is step 5b, after the drop.
        let router = Router::stderr_unstarted();
        if ring {
            // Recovery mode: nothing reaches stderr until a thaw succeeds
            // (§4.4, §9.1).
            router.enter_ring();
        }
        audit::init_tracing(level.as_tracing(), router.clone())
            .map_err(|err| RunError::Runtime(err.to_string()))?;
        Ok(router)
    }

    fn mount_table(&self) -> Result<Vec<MountEntry>, String> {
        crate::mountinfo::ProcMounts
            .mounts()
            .map_err(|err| err.to_string())
    }

    fn open_channel(&self, path: &Path) -> Result<Option<OwnedFd>, OpenError> {
        // One attempt, no waiting: retrying here would hold the process as
        // root with no runtime, no seccomp and, in recovery mode, no
        // watchdog, for as long as the device is missing. The reopen loop
        // retries with backoff once the runtime is up (the udev rule of
        // §8.3 lets the service account open the port).
        match channel::open_device(path) {
            Ok(fd) => Ok(Some(fd)),
            Err(err) => {
                let err = OpenError::from_io(path, err);
                if err.is_terminal() {
                    return Err(err);
                }
                tracing::warn!(event = "channel_open_failed", error = %err, "cannot open channel now");
                Ok(None)
            }
        }
    }

    fn drop_privileges(&self) -> Result<Outcome, PrivilegeError> {
        crate::kernel::caps::drop_privileges(SERVICE_USER, &crate::kernel::caps::SystemCaps)
    }

    #[cfg(feature = "seccomp")]
    fn install_seccomp(&self, config: &Config) -> Result<bool, RunError> {
        if !config.seccomp_enabled() {
            return Ok(false);
        }
        let program = crate::seccomp::profile(crate::seccomp::Target::current())
            .map_err(|err| RunError::Seccomp(err.to_string()))?;
        crate::seccomp::install(&program).map_err(|err| RunError::Seccomp(err.to_string()))?;
        Ok(true)
    }

    #[cfg(not(feature = "seccomp"))]
    fn install_seccomp(&self, config: &Config) -> Result<bool, RunError> {
        let _ = config.seccomp_enabled();
        Ok(false)
    }

    fn serve(
        &self,
        config: Arc<Config>,
        router: Router,
        recovery: bool,
        channel: Option<OwnedFd>,
        marker: Marker,
    ) -> Result<(), RunError> {
        let runtime = build_runtime().map_err(|err| RunError::Runtime(err.to_string()))?;
        let path = config.agent.channel_path.clone();
        let ctx = production_context(config, router, recovery, marker);
        let served = runtime.block_on(async move {
            // Register the handlers before serving anything: a SIGTERM that
            // arrives after the first reply must be deferred, not fatal.
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate())
                .map_err(|err| RunError::Runtime(format!("cannot listen for SIGTERM: {err}")))?;
            let mut int = signal(SignalKind::interrupt())
                .map_err(|err| RunError::Runtime(format!("cannot listen for SIGINT: {err}")))?;
            let signal = async move {
                tokio::select! {
                    _ = term.recv() => "SIGTERM",
                    _ = int.recv() => "SIGINT",
                }
            };
            serve_until_signal(
                ctx,
                &path,
                Arc::new(channel::open_device),
                channel,
                recovery,
                signal,
                STOP_POLL,
            )
            .await
            .map_err(RunError::from)
        });
        finish_runtime(runtime, RUNTIME_SHUTDOWN_GRACE);
        served
    }
}

/// Shuts the runtime down, waiting at most `grace` for blocking work.
/// Dropping a runtime would wait for ever for a started blocking task;
/// by the time [`serve_until_signal`] has returned, on a stop or on a
/// terminal channel error alike, the state is `Thawed`, so the only such
/// task can be an abandoned `guest-get-fsinfo` walk (see
/// [`RUNTIME_SHUTDOWN_GRACE`]).
pub fn finish_runtime(runtime: tokio::runtime::Runtime, grace: Duration) {
    runtime.shutdown_timeout(grace);
}

/// The multi-threaded runtime (§7): at least two workers so the watchdog
/// and the channel loop never starve each other.
pub fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(2)
        .max(2);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("qeminga-worker")
        .enable_all()
        .build()
}

/// Environment variable that, in `test-fakes` builds only, replaces the
/// kernel shim with the scripted fake (`kernel::fake::FakeKernel`).
pub const FAKE_KERNEL_ENV: &str = "QEMINGA_TEST_FAKE_KERNEL";

/// The production context: real sources, state chosen by `recovery`, the
/// marker handle opened at startup.
///
/// With the `test-fakes` Cargo feature **and** [`FAKE_KERNEL_ENV`] set
/// **and** development hardening, the kernel shim is the fake: no ioctl,
/// `sync` or `reboot` ever reaches the kernel. A release build cannot
/// carry the feature (`compile_error!` in the crate root), and enforced
/// hardening refuses the variable before anything starts.
pub fn production_context(
    config: Arc<Config>,
    router: Router,
    recovery: bool,
    marker: Marker,
) -> Arc<Context> {
    let state = if recovery {
        FreezeStateMachine::starting_frozen()
    } else {
        FreezeStateMachine::new()
    };
    let ctx = Context::new(config, Arc::new(state), router, marker);
    // Never under enforced hardening (`check_hardening` refused the start
    // already; this keeps the swap itself conditional on the profile).
    #[cfg(feature = "test-fakes")]
    let ctx = if std::env::var_os(FAKE_KERNEL_ENV).is_some()
        && !ctx.config.agent.hardening.is_enforced()
    {
        tracing::warn!(
            event = "fake_kernel",
            "test-fakes: kernel operations are faked; no ioctl, sync or reboot will run"
        );
        ctx.with_kernel(Arc::new(crate::kernel::fake::FakeKernel::new()))
    } else {
        ctx
    };
    Arc::new(ctx)
}

/// Serves the channel until `signal` resolves and the state is `Thawed`
/// (a stop while not thawed is deferred, C-21). In recovery mode the ring
/// and the watchdog are set up first (C-14), before and independently of
/// any channel: with no `initial` descriptor the loop keeps trying to
/// open `path` with backoff while the watchdog runs, so an abandoned
/// freeze is bounded even if the host never connects (OQ-7). Returns the
/// terminal channel error, if any.
///
/// Every way out obeys the same rule: a terminal channel error (`EBUSY`,
/// §8.4: the port is not competed for) ends the serving, but not the
/// process while a filesystem may be frozen or a thaw is in flight. The
/// exit is deferred until the state is `Thawed`, which the watchdog
/// bounds since no host can reach this process any more, so the runtime
/// is only ever torn down (`finish_runtime`) once every destructive
/// operation has completed.
pub async fn serve_until_signal<S>(
    ctx: Arc<Context>,
    path: &Path,
    open: OpenFn,
    initial: Option<OwnedFd>,
    recovery: bool,
    signal: S,
    stop_poll: Duration,
) -> Result<(), OpenError>
where
    S: Future<Output = &'static str>,
{
    if recovery && let Err(err) = fsfreeze::start_recovery(&ctx) {
        tracing::error!(event = "recovery_failed", error = %err, "recovery startup failed");
    }
    let dispatcher = Dispatcher::new(Arc::clone(&ctx));
    let (cancel_tx, cancel_rx) = channel::cancel_pair();
    let stop_ctx = Arc::clone(&ctx);
    let stopper = async move {
        let name = signal.await;
        tracing::info!(event = "signal", signal = name, "stop requested");
        loop {
            wait_until_thawed(&stop_ctx, stop_poll).await;
            // Ask the loop to stop. A session finishes the command it is
            // handling first and stops only if the state is still
            // `Thawed`; a freeze that slipped in between this check and
            // the request is therefore never abandoned, and the request
            // is simply repeated once the state is `Thawed` again.
            if cancel_tx.send(true).is_err() {
                return;
            }
            tokio::time::sleep(stop_poll).await;
        }
    };
    let served = channel::serve_with_initial(path, open, &dispatcher, cancel_rx, initial);
    tokio::pin!(served);
    tokio::pin!(stopper);
    let result = tokio::select! {
        result = &mut served => result,
        () = &mut stopper => {
            // Cancellation was sent; let the loop observe it and return.
            served.await
        }
    };
    if let Err(err) = &result {
        tracing::error!(event = "channel_lost", error = %err, "channel lost for good; exiting once thawed");
    }
    // A stop honoured by the loop is already thawed; a terminal error is
    // not necessarily.
    wait_until_thawed(&ctx, stop_poll).await;
    result
}

/// Returns once the state is `Thawed`, polling every `poll`; logs the
/// deferral once. The watchdog (§4.4) bounds the wait for a freeze this
/// process holds, and a thaw in flight completes on the blocking pool.
async fn wait_until_thawed(ctx: &Context, poll: Duration) {
    let mut warned = false;
    while ctx.state.current() != FreezeState::Thawed {
        if !warned {
            tracing::warn!(event = "stop_deferred", state = %ctx.state.current(), "stop deferred until thaw completes");
            warned = true;
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::ffi::OsStringExt;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn parse_args_handles_config_and_version() {
        assert_eq!(parse_args(args(&[])).unwrap(), Options::default());
        assert!(parse_args(args(&["--version"])).unwrap().version);
        assert!(parse_args(args(&["-V"])).unwrap().version);
        assert_eq!(
            parse_args(args(&["--config", "/x.toml"]))
                .unwrap()
                .config_path,
            PathBuf::from("/x.toml")
        );
        assert_eq!(
            parse_args(args(&["--config=/y.toml"])).unwrap().config_path,
            PathBuf::from("/y.toml")
        );
        assert!(parse_args(args(&["--config"])).is_err());
        assert!(parse_args(args(&["--config="])).is_err());
        assert!(parse_args(args(&["--bogus"])).is_err());
        assert!(parse_args(args(&["extra"])).is_err());
        assert!(parse_args(vec![OsString::from("--\u{fffd}")]).is_err());
        // A non-UTF-8 path in the `--config=` form (bytes preserved).
        let raw = OsString::from_vec(b"--config=/etc/q\xff.toml".to_vec());
        assert_eq!(
            parse_args(vec![raw])
                .unwrap()
                .config_path
                .as_os_str()
                .as_bytes(),
            b"/etc/q\xff.toml"
        );
        assert_eq!(
            parse_args(args(&["--bogus"])).unwrap_err().to_string(),
            "unrecognised argument: --bogus"
        );
    }

    #[test]
    fn run_errors_map_to_sysexits_codes() {
        assert_eq!(
            RunError::Config(ConfigError::Parse {
                path: None,
                message: "x".into()
            })
            .exit_code(),
            EX_CONFIG
        );
        assert_eq!(
            RunError::StatePath {
                path: "/x".into(),
                mount: "/".into(),
                dev: (8, 1)
            }
            .exit_code(),
            EX_CONFIG
        );
        assert_eq!(
            RunError::Channel(OpenError::AlreadyOpen {
                path: "/dev/x".into()
            })
            .exit_code(),
            EX_UNAVAILABLE
        );
        assert_eq!(
            RunError::Privileges(PrivilegeError::UnknownUser("q".into())).exit_code(),
            EX_NOPERM
        );
        assert_eq!(RunError::Seccomp("x".into()).exit_code(), EX_OSERR);
        assert_eq!(RunError::Runtime("x".into()).exit_code(), EX_OSERR);
        assert_eq!(
            RunError::Marker(MarkerError::InvalidPath { path: "/".into() }).exit_code(),
            EX_CONFIG
        );
        assert_eq!(RunError::MountTable("x".into()).exit_code(), EX_CONFIG);
    }

    #[test]
    fn runtime_shutdown_is_bounded_by_an_abandoned_blocking_task() {
        // A blocking task that never returns (a statfs on a dead share):
        // dropping the runtime would wait for it for ever; the finish is
        // bounded by the grace, and the task is left behind.
        let runtime = build_runtime().unwrap();
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Arc::clone(&started);
        runtime.spawn_blocking(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = stuck.recv();
        });
        while !started.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let clock = std::time::Instant::now();
        finish_runtime(runtime, Duration::from_millis(200));
        assert!(
            clock.elapsed() < Duration::from_secs(5),
            "{:?}",
            clock.elapsed()
        );
        drop(release);
        assert!(RUNTIME_SHUTDOWN_GRACE >= Duration::from_secs(1));
    }

    #[test]
    fn runtime_is_multi_thread_with_at_least_two_workers() {
        let rt = build_runtime().unwrap();
        let workers =
            rt.block_on(async { tokio::runtime::Handle::current().metrics().num_workers() });
        assert!(workers >= 2, "{workers}");
        assert_eq!(
            rt.handle().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        );
    }
}
