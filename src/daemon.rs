//! Startup sequence, runtime, and signal handling (design §6 `main.rs`,
//! §5.4/§5.5 order, §4.4 recovery mode, §5.7 deferred stop, §8.2
//! `state_path` validation, §8.4 `EBUSY` is terminal; C-14, C-18, C-21).
//!
//! The sequence, each step behind the [`Startup`] trait so it is testable
//! against a recording fake:
//!
//! 1. load and validate the configuration;
//! 2. look for the recovery marker (read-only) to choose the initial
//!    state; start logging, in ring mode when recovering (§4.4);
//! 3. reject a `state_path` that the freeze plan would freeze (§8.2);
//! 4. open the channel (`EBUSY` is terminal, §8.4);
//! 5. drop capabilities (skipped with a warning when not root, C-18);
//! 6. install seccomp when compiled in and enabled;
//! 7. start the multi-threaded runtime and serve until a signal.
//!
//! No ioctl and no marker write happens before step 7. A `SIGTERM`/`SIGINT`
//! while the state is not `Thawed` is deferred until the thaw completes
//! (C-21).
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
    /// `state_path` is on a filesystem the freeze plan would freeze.
    #[error(
        "state_path {} is on {}, which the freeze plan would freeze; put it on tmpfs (e.g. /run)",
        path.display(),
        mount.display()
    )]
    StatePath {
        /// The configured path.
        path: PathBuf,
        /// The covering mount point.
        mount: PathBuf,
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
    /// The runtime could not be built or logging could not be initialised.
    #[error("{0}")]
    Runtime(String),
}

impl RunError {
    /// The sysexits-style code for this error.
    pub fn exit_code(&self) -> u8 {
        match self {
            RunError::Config(_) | RunError::StatePath { .. } | RunError::MountTable(_) => EX_CONFIG,
            RunError::Channel(_) => EX_UNAVAILABLE,
            RunError::Privileges(_) => EX_NOPERM,
            RunError::Seccomp(_) | RunError::Runtime(_) => EX_OSERR,
        }
    }
}

/// The steps of the startup sequence, in the order [`run_with`] calls
/// them. Production is [`SystemStartup`]; tests record the calls.
pub trait Startup {
    /// Step 1.
    fn load_config(&self, path: &Path) -> Result<Config, ConfigError>;
    /// Step 2a: is the recovery marker present? Read-only.
    fn marker_present(&self, path: &Path) -> bool;
    /// Step 2b: start logging; `ring` is `true` in recovery mode.
    fn init_logging(&self, level: LogLevel, ring: bool) -> Result<Router, RunError>;
    /// Step 3: the mount table for the `state_path` check.
    fn mount_table(&self) -> Result<Vec<MountEntry>, String>;
    /// Step 4: one attempt to open the channel while still privileged.
    /// `EBUSY` is terminal; any other failure yields `Ok(None)` and the
    /// runtime's reopen loop (§5.7) retries after the drop, so a missing
    /// device never delays the privilege drop, the seccomp filter or the
    /// recovery watchdog (C-14, OQ-7).
    fn open_channel(&self, path: &Path) -> Result<Option<OwnedFd>, OpenError>;
    /// Step 5.
    fn drop_privileges(&self) -> Result<Outcome, PrivilegeError>;
    /// Step 6: `Ok(true)` when a filter was installed.
    fn install_seccomp(&self, config: &Config) -> Result<bool, RunError>;
    /// Step 7: run until a signal; `recovery` selects the `Frozen` start;
    /// `channel` is the descriptor step 4 opened, if it did.
    fn serve(
        &self,
        config: Arc<Config>,
        router: Router,
        recovery: bool,
        channel: Option<OwnedFd>,
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

/// Runs the startup sequence through `startup`.
pub fn run_with(opts: &Options, startup: &dyn Startup) -> Result<(), RunError> {
    let config = startup.load_config(&opts.config_path)?;
    let recovery = startup.marker_present(&config.agent.state_path);
    let router = startup.init_logging(config.agent.log_level, recovery)?;
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
    if plan.covers(&config.agent.state_path) {
        let mount = plan
            .mount_of(&config.agent.state_path)
            .map(|(mp, _)| mp.to_owned())
            .unwrap_or_default();
        return Err(RunError::StatePath {
            path: config.agent.state_path.clone(),
            mount,
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
        Outcome::SkippedUnprivileged => {}
    }
    let seccomp = startup.install_seccomp(&config)?;
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
    startup.serve(Arc::new(config), router, recovery, channel)
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
            if tracing::dispatcher::has_been_set() {
                // Logging is up: the record goes where the router sends
                // it. In recovery mode that is the ring, never fd 2
                // (§4.4, §9.1), and in normal mode this is the one line
                // on stderr.
                tracing::error!(event = "startup_failed", error = %err, "exiting");
            } else {
                // Failed before logging existed (a configuration error):
                // stderr is the only channel left.
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

    fn marker_present(&self, path: &Path) -> bool {
        crate::marker::Marker::new(path).exists()
    }

    fn init_logging(&self, level: LogLevel, ring: bool) -> Result<Router, RunError> {
        let router = Router::stderr();
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
    ) -> Result<(), RunError> {
        let runtime = build_runtime().map_err(|err| RunError::Runtime(err.to_string()))?;
        let path = config.agent.channel_path.clone();
        let ctx = production_context(config, router, recovery);
        runtime.block_on(async move {
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
        })
    }
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

/// The production context: real sources, state chosen by `recovery`.
pub fn production_context(config: Arc<Config>, router: Router, recovery: bool) -> Arc<Context> {
    let state = if recovery {
        FreezeStateMachine::starting_frozen()
    } else {
        FreezeStateMachine::new()
    };
    Arc::new(Context::new(config, Arc::new(state), router))
}

/// Serves the channel until `signal` resolves and the state is `Thawed`
/// (a stop while not thawed is deferred, C-21). In recovery mode the ring
/// and the watchdog are set up first (C-14), before and independently of
/// any channel: with no `initial` descriptor the loop keeps trying to
/// open `path` with backoff while the watchdog runs, so an abandoned
/// freeze is bounded even if the host never connects (OQ-7). Returns the
/// terminal channel error, if any.
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
            let mut warned = false;
            while stop_ctx.state.current() != FreezeState::Thawed {
                if !warned {
                    tracing::warn!(event = "stop_deferred", state = %stop_ctx.state.current(), "stop deferred until thaw completes");
                    warned = true;
                }
                tokio::time::sleep(stop_poll).await;
            }
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
    tokio::select! {
        result = &mut served => result,
        () = &mut stopper => {
            // Cancellation was sent; let the loop observe it and return.
            served.await
        }
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
                mount: "/".into()
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
        assert_eq!(RunError::MountTable("x".into()).exit_code(), EX_CONFIG);
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
