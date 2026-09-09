//! Request dispatch: the static allowlist, the gates, and the rate limiter
//! (design §4.3, §5.1, §5.3, §9; AC1, AC9; C-2, C-7).
//!
//! Order of evaluation for every frame (C-7):
//!
//! 1. parse ([`crate::proto::parse_request`], bounds first);
//! 2. allowlist ([`is_allowlisted`], a `match` on the method string);
//! 3. runtime feature gate (`guest-fstrim`, `guest-suspend-ram` may be
//!    disabled by configuration → `CommandNotFound`, C-2);
//! 4. rate limiter ([`ratelimit`]);
//! 5. freeze gate ([`is_frozen_safe`]; anything else is rejected while the
//!    state is not `Thawed`, AC9);
//! 6. the handler, chosen by a static `match` (§5.1). There is no lookup
//!    table, registry, or plugin mechanism.
//!
//! Every received frame produces exactly one audit record (§9), emitted
//! before the handler runs so that a `guest-shutdown` record precedes the
//! reboot.
#![forbid(unsafe_code)]

pub mod ratelimit;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::audit::{AuditRecord, Disposition, Router, project_method};
use crate::channel::Kind;
use crate::config::Config;
use crate::framing::{DecodeEvent, encode};
use crate::handlers;
use crate::proto::{Error, Request, Response, parse_request};
use crate::state::FreezeStateMachine;
use ratelimit::{CommandClass, RateLimiter};

/// `true` for the commands in the design §3 allowlist.
///
/// A `match`, not a table lookup (§5.1); the consistency test keeps it in
/// step with [`handlers::SUPPORTED_COMMANDS`].
pub fn is_allowlisted(method: &str) -> bool {
    matches!(
        method,
        "guest-ping"
            | "guest-info"
            | "guest-sync"
            | "guest-sync-delimited"
            | "guest-get-osinfo"
            | "guest-network-get-interfaces"
            | "guest-get-fsinfo"
            | "guest-fsfreeze-status"
            | "guest-fsfreeze-freeze"
            | "guest-fsfreeze-freeze-list"
            | "guest-fsfreeze-thaw"
            | "guest-fstrim"
            | "guest-shutdown"
            | "guest-suspend-ram"
    )
}

/// `true` for the six commands accepted while filesystems are frozen
/// (§5.3): status, thaw, ping, sync, sync-delimited, info.
pub fn is_frozen_safe(method: &str) -> bool {
    matches!(
        method,
        "guest-fsfreeze-status"
            | "guest-fsfreeze-thaw"
            | "guest-ping"
            | "guest-sync"
            | "guest-sync-delimited"
            | "guest-info"
    )
}

/// The session lane of an allowlisted method (§5.7): the frozen-safe
/// controls run beside the command in progress, a thaw beside a freeze,
/// everything else one at a time. Derived from [`is_frozen_safe`] so the
/// two never disagree.
pub fn lane(method: &str) -> Kind {
    match method {
        "guest-fsfreeze-thaw" => Kind::Thaw,
        "guest-fsfreeze-freeze" | "guest-fsfreeze-freeze-list" => Kind::Freeze,
        _ if is_frozen_safe(method) => Kind::Control,
        _ => Kind::Ordinary,
    }
}

/// Audit `reason` values for denied frames.
pub mod reason {
    /// The frame exceeded the frame length bound (AC4).
    pub const OVERSIZED_FRAME: &str = "oversized_frame";
    /// The frame was not a valid request (bounds, JSON, or schema).
    pub const PARSE_ERROR: &str = "parse_error";
    /// The method is not allowlisted (AC1).
    pub const COMMAND_NOT_FOUND: &str = "command_not_found";
    /// The method is allowlisted but disabled by configuration.
    pub const DISABLED: &str = "disabled";
    /// The class's token bucket was empty (AC5).
    pub const RATE_LIMITED: &str = "rate_limited";
    /// The method is not frozen-safe and filesystems are frozen (AC9).
    pub const FROZEN: &str = "frozen";
}

/// How a thaw finds the filesystems it must drain (§4.2 "Thaw scope").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThawScope {
    /// Every obligation is a held descriptor: a freeze operation this
    /// process completed with no target's outcome unknown. The thaw
    /// drains the descriptors the operation published and nothing else,
    /// and reads no mount table: a superblock the operation never
    /// touched cannot hold its thaw.
    Tracked,
    /// A filesystem may be frozen with no descriptor to show for it:
    /// after a restart, for a drain from `Thawed`, or after an operation
    /// that lost a worker or a drain. The thaw discovers every eligible
    /// superblock through the mount table, by its pathnames and aliases.
    Discovery,
}

/// Everything handlers need, shared behind an `Arc`. Tests build it with
/// fakes; later tasks add the kernel shim and information sources.
pub struct Context {
    /// Validated configuration.
    pub config: Arc<Config>,
    /// The freeze state machine (C-6).
    pub state: Arc<FreezeStateMachine>,
    /// The audit router (ring/normal mode switch, §9.1).
    pub audit: Router,
    /// Source of `guest-get-osinfo` data (production: the running system).
    pub osinfo: Arc<dyn handlers::osinfo::OsInfoSource>,
    /// Source of `guest-network-get-interfaces` records.
    pub interfaces: Arc<dyn handlers::interfaces::InterfaceSource>,
    /// Source of the mount table (`guest-get-fsinfo`, freeze plan).
    pub mounts: Arc<dyn crate::mountinfo::MountSource>,
    /// Source of filesystem sizes (`guest-get-fsinfo`).
    pub statfs: Arc<dyn handlers::fsinfo::StatfsSource>,
    /// Slots for live `guest-get-fsinfo` walks
    /// ([`MAX_FSINFO_WALKS`](handlers::fsinfo::MAX_FSINFO_WALKS)); a slot is
    /// held by the walk itself until it returns, not by its request.
    pub fsinfo_walks: Arc<tokio::sync::Semaphore>,
    /// The kernel shim (ioctls, sync, reboot).
    pub kernel: Arc<dyn crate::kernel::KernelOps>,
    /// The recovery marker at `config.agent.state_path` (§4.4).
    pub marker: crate::marker::Marker,
    /// Freeze lifecycle callbacks (watchdog, audit ring).
    pub hooks: Arc<dyn handlers::fsfreeze::FreezeHooks>,
    /// The sysfs power interface (`guest-suspend-ram`).
    pub suspend: Arc<dyn handlers::suspend::SuspendOps>,
    /// The armed watchdog, if any (§4.4).
    watchdog: std::sync::Mutex<Option<crate::watchdog::WatchdogHandle>>,
    /// Handles of the filesystems this process froze (or found frozen),
    /// held until their drain completes: a thaw drains the filesystem
    /// each was opened on, whatever its pathnames lead to by then (§4.2).
    frozen_mounts: std::sync::Mutex<Vec<crate::kernel::Mount>>,
    /// How the next thaw finds what it must drain (§4.2 "Thaw scope").
    thaw_scope: std::sync::Mutex<ThawScope>,
    /// The freeze operation in progress, from `Freezing` until it settles
    /// (§4.4 operation deadline).
    freeze_op: std::sync::Mutex<Option<Arc<crate::freeze_op::FreezeOp>>>,
    /// The freeze operation deadline (`fsfreeze_operation_timeout_secs`).
    freeze_operation_timeout: std::time::Duration,
    /// The clock the deadline is measured against (tests inject a manual
    /// one).
    freeze_clock: Arc<dyn crate::freeze_op::FreezeClock>,
    handler_calls: AtomicU64,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("state", &self.state.current())
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

impl Context {
    /// Builds a context from its parts, using the production information
    /// sources. Tests swap in fakes with the `with_*` methods.
    ///
    /// In this crate's own unit tests (`cfg(test)`) the kernel shim defaults
    /// to the scripted fake, so no unit test can reach `FIFREEZE`, `FITHAW`,
    /// `FITRIM` or `reboot(2)` by omission; integration tests must install
    /// the fake explicitly with [`Context::with_kernel`].
    pub fn new(
        config: Arc<Config>,
        state: Arc<FreezeStateMachine>,
        audit: Router,
        marker: crate::marker::Marker,
    ) -> Self {
        #[cfg(not(test))]
        let kernel: Arc<dyn crate::kernel::KernelOps> = Arc::new(crate::kernel::LinuxKernel);
        #[cfg(test)]
        let kernel: Arc<dyn crate::kernel::KernelOps> =
            Arc::new(crate::kernel::fake::FakeKernel::new());
        let freeze_operation_timeout =
            std::time::Duration::from_secs(config.agent.fsfreeze_operation_timeout_secs());
        Context {
            config,
            state,
            audit,
            kernel,
            marker,
            hooks: Arc::new(handlers::fsfreeze::LifecycleHooks),
            suspend: Arc::new(handlers::suspend::SysPower),
            watchdog: std::sync::Mutex::new(None),
            osinfo: Arc::new(handlers::osinfo::SystemOsInfo),
            interfaces: Arc::new(handlers::interfaces::SystemInterfaces),
            mounts: Arc::new(crate::mountinfo::ProcMounts),
            statfs: Arc::new(handlers::fsinfo::SystemStatfs),
            fsinfo_walks: Arc::new(tokio::sync::Semaphore::new(
                handlers::fsinfo::MAX_FSINFO_WALKS,
            )),
            frozen_mounts: std::sync::Mutex::new(Vec::new()),
            thaw_scope: std::sync::Mutex::new(ThawScope::Discovery),
            freeze_op: std::sync::Mutex::new(None),
            freeze_operation_timeout,
            freeze_clock: Arc::new(crate::freeze_op::TokioClock),
            handler_calls: AtomicU64::new(0),
        }
    }

    /// Replaces the freeze operation deadline (tests use short ones).
    #[must_use]
    pub fn with_freeze_operation_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.freeze_operation_timeout = timeout;
        self
    }

    /// The freeze operation deadline, measured from entry into `Freezing`.
    pub fn freeze_operation_timeout(&self) -> std::time::Duration {
        self.freeze_operation_timeout
    }

    /// Replaces the clock the freeze operation deadline is measured
    /// against.
    #[must_use]
    pub fn with_freeze_clock(mut self, clock: Arc<dyn crate::freeze_op::FreezeClock>) -> Self {
        self.freeze_clock = clock;
        self
    }

    /// The clock the freeze operation deadline is measured against.
    pub fn freeze_clock(&self) -> Arc<dyn crate::freeze_op::FreezeClock> {
        Arc::clone(&self.freeze_clock)
    }

    /// The freeze operation in progress, if any.
    pub fn freeze_op(&self) -> Option<Arc<crate::freeze_op::FreezeOp>> {
        self.freeze_op
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Registers the freeze operation (or, with `None`, clears the slot).
    pub(crate) fn set_freeze_op(&self, op: Option<Arc<crate::freeze_op::FreezeOp>>) {
        *self
            .freeze_op
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = op;
    }

    /// Retires `op`: clears the slot only if it still holds that very
    /// operation, so a settling operation can never clear a successor
    /// that was admitted after it published its terminal state.
    pub(crate) fn retire_freeze_op(&self, op: &Arc<crate::freeze_op::FreezeOp>) {
        let mut slot = self
            .freeze_op
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, op))
        {
            *slot = None;
        }
    }

    /// Replaces the mount-table source.
    #[must_use]
    pub fn with_mounts(mut self, mounts: Arc<dyn crate::mountinfo::MountSource>) -> Self {
        self.mounts = mounts;
        self
    }

    /// Replaces the `statfs` source.
    #[must_use]
    pub fn with_statfs(mut self, statfs: Arc<dyn handlers::fsinfo::StatfsSource>) -> Self {
        self.statfs = statfs;
        self
    }

    /// Replaces the kernel shim (tests use `kernel::fake::FakeKernel`).
    #[must_use]
    pub fn with_kernel(mut self, kernel: Arc<dyn crate::kernel::KernelOps>) -> Self {
        self.kernel = kernel;
        self
    }

    /// Replaces the recovery marker.
    #[must_use]
    pub fn with_marker(mut self, marker: crate::marker::Marker) -> Self {
        self.marker = marker;
        self
    }

    /// Replaces the sysfs power interface.
    #[must_use]
    pub fn with_suspend(mut self, suspend: Arc<dyn handlers::suspend::SuspendOps>) -> Self {
        self.suspend = suspend;
        self
    }

    /// Replaces the freeze lifecycle hooks.
    #[must_use]
    pub fn with_hooks(mut self, hooks: Arc<dyn handlers::fsfreeze::FreezeHooks>) -> Self {
        self.hooks = hooks;
        self
    }

    /// Replaces the `guest-network-get-interfaces` source.
    #[must_use]
    pub fn with_interfaces(
        mut self,
        interfaces: Arc<dyn handlers::interfaces::InterfaceSource>,
    ) -> Self {
        self.interfaces = interfaces;
        self
    }

    /// Replaces the `guest-get-osinfo` source.
    #[must_use]
    pub fn with_osinfo(mut self, osinfo: Arc<dyn handlers::osinfo::OsInfoSource>) -> Self {
        self.osinfo = osinfo;
        self
    }

    /// Ends everything this instance has in flight, as the process's death
    /// would: the watchdog is cancelled and a freeze walk waiting on its
    /// workers is aborted, so neither can publish a state, write a marker
    /// or thaw after the instance is gone. Blocking work already in the
    /// kernel (an ioctl) completes on its own thread, as an in-flight
    /// syscall does. For harnesses that model a crash (`SIGKILL`) and a
    /// restart in one process; never called by the daemon itself, and
    /// not an API for anything else: like the crash it models, it leaves
    /// the state machine where it was (`Freezing`, a live marker, a
    /// request never answered), which only a new instance's recovery
    /// resolves.
    #[doc(hidden)]
    pub fn abort_tasks(&self) {
        if let Some(watchdog) = self.watchdog_slot().take() {
            watchdog.cancel();
        }
        if let Some(op) = self.freeze_op() {
            op.abort_driver();
        }
    }

    /// The watchdog slot. The guard is short-lived and never held across
    /// an `.await`.
    pub fn watchdog_slot(
        &self,
    ) -> std::sync::MutexGuard<'_, Option<crate::watchdog::WatchdogHandle>> {
        self.watchdog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Takes the held handles of frozen filesystems for a drain; the
    /// guard is short-lived and never held across an `.await`.
    pub fn take_frozen_mounts(&self) -> Vec<crate::kernel::Mount> {
        std::mem::take(&mut *self.frozen_mounts_slot())
    }

    /// Holds handles of filesystems frozen by this process (added to any
    /// already held) until a drain completes them.
    pub fn hold_frozen_mounts(&self, mounts: Vec<crate::kernel::Mount>) {
        self.frozen_mounts_slot().extend(mounts);
    }

    /// Number of handles currently held.
    pub fn frozen_mount_count(&self) -> usize {
        self.frozen_mounts_slot().len()
    }

    /// How the next thaw finds what it must drain (§4.2 "Thaw scope").
    pub fn thaw_scope(&self) -> ThawScope {
        *self
            .thaw_scope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records how the next thaw must find what it drains: a settling
    /// freeze operation sets it from what it knows of its targets, a
    /// completed thaw resets it.
    pub fn set_thaw_scope(&self, scope: ThawScope) {
        *self
            .thaw_scope
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = scope;
    }

    /// The lock behind the held handles, for tests that must hold the
    /// driver between a completion and its next decision boundary.
    #[cfg(test)]
    pub(crate) fn frozen_mounts_lock_for_tests(
        &self,
    ) -> std::sync::MutexGuard<'_, Vec<crate::kernel::Mount>> {
        self.frozen_mounts_slot()
    }

    fn frozen_mounts_slot(&self) -> std::sync::MutexGuard<'_, Vec<crate::kernel::Mount>> {
        self.frozen_mounts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Number of times a handler was invoked (gates passed).
    pub fn handler_calls(&self) -> u64 {
        self.handler_calls.load(Ordering::SeqCst)
    }

    /// A context with default configuration, a thawed state machine, an
    /// audit router that discards output, and a marker in the temporary
    /// directory that nothing creates unless a test freezes.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            crate::marker::Marker::for_tests(),
        )
        .with_kernel(Arc::new(crate::kernel::fake::FakeKernel::new()))
    }
}

/// The dispatcher: gates plus the static `match`.
#[derive(Debug)]
pub struct Dispatcher {
    ctx: Arc<Context>,
    limiter: RateLimiter,
}

impl Dispatcher {
    /// Builds a dispatcher whose limiter is configured from `ctx.config`.
    pub fn new(ctx: Arc<Context>) -> Self {
        let limiter = RateLimiter::new(&ctx.config.rate_limits);
        Dispatcher { ctx, limiter }
    }

    /// The shared context.
    pub fn context(&self) -> &Arc<Context> {
        &self.ctx
    }

    /// Handles one decoder event and returns the encoded reply, if any.
    ///
    /// `None` is returned for an oversized frame (nothing to reply to) and
    /// for a successful `guest-shutdown` or `guest-suspend-ram`
    /// (`success-response: false`).
    pub async fn handle(&self, event: DecodeEvent) -> Option<Vec<u8>> {
        let freeze_state_before = self.ctx.state.current().as_str();
        let bytes = match event {
            DecodeEvent::Oversized { discarded } => {
                AuditRecord {
                    method: project_method(""),
                    id: None,
                    disposition: Disposition::Denied,
                    reason: Some(reason::OVERSIZED_FRAME),
                    freeze_state_before,
                }
                .emit();
                tracing::warn!(event = "oversized_frame", discarded, "frame discarded");
                return None;
            }
            DecodeEvent::Frame { bytes, .. } => bytes,
        };

        let req = match parse_request(&bytes) {
            Ok(req) => req,
            Err(err) => {
                AuditRecord {
                    method: project_method(""),
                    id: None,
                    disposition: Disposition::Denied,
                    reason: Some(reason::PARSE_ERROR),
                    freeze_state_before,
                }
                .emit();
                return Some(encode(&Response::error(None, &err).to_json(), false));
            }
        };

        let result = match self.gates(&req) {
            Ok(()) => {
                AuditRecord {
                    method: project_method(&req.method),
                    id: req.id,
                    disposition: Disposition::Allowed,
                    reason: None,
                    freeze_state_before,
                }
                .emit();
                self.run_handler(&req).await
            }
            Err((denial, err)) => {
                AuditRecord {
                    method: project_method(&req.method),
                    id: req.id,
                    disposition: Disposition::Denied,
                    reason: Some(denial),
                    freeze_state_before,
                }
                .emit();
                Err(err)
            }
        };

        let suppress_success = handlers::spec(&req.method).is_some_and(|s| !s.success_response);
        if result.is_ok() && suppress_success {
            return None;
        }
        // Every reply to `guest-sync-delimited` (success or error) carries
        // the sentinel so a client that is resynchronising can find it (C-10).
        let sentinel = req.method == "guest-sync-delimited";
        Some(encode(
            &Response::from_result(req.id, result).to_json(),
            sentinel,
        ))
    }

    /// The lane `event` runs in (§5.7), decided by the session before the
    /// frame is handled. The frame is parsed once more here, without any
    /// side effect (no audit record, no gate): a frame that cannot be
    /// parsed, like an oversized one, is answered without running
    /// anything and counts as a control; an unknown method is treated as
    /// an ordinary command and rejected in its turn.
    pub fn classify(&self, event: &DecodeEvent) -> Kind {
        match event {
            DecodeEvent::Oversized { .. } => Kind::Control,
            DecodeEvent::Frame { bytes, .. } => match parse_request(bytes) {
                Ok(req) => lane(&req.method),
                Err(_) => Kind::Control,
            },
        }
    }

    /// Steps 2–5 of the dispatch order (C-7). On denial returns the audit
    /// reason together with the wire error.
    fn gates(&self, req: &Request) -> Result<(), (&'static str, Error)> {
        let method = req.method.as_str();
        if !is_allowlisted(method) {
            return Err((
                reason::COMMAND_NOT_FOUND,
                Error::CommandNotFound(method.to_owned()),
            ));
        }
        self.runtime_feature_gate(method)
            .map_err(|err| (reason::DISABLED, err))?;
        // Every allowlisted method has a class; treat the impossible `None`
        // as the strictest class rather than skipping the limiter.
        let class = CommandClass::of(method).unwrap_or(CommandClass::Shutdown);
        self.limiter
            .check(class)
            .map_err(|err| (reason::RATE_LIMITED, Error::from(err)))?;
        if self.ctx.state.is_frozen_for_gate() && !is_frozen_safe(method) {
            return Err((reason::FROZEN, Error::Frozen));
        }
        Ok(())
    }

    /// Runtime half of the two-level feature switches (§8.1, C-2).
    fn runtime_feature_gate(&self, method: &str) -> Result<(), Error> {
        let config = &self.ctx.config;
        match method {
            "guest-fstrim" if !config.fstrim_enabled() => Err(Error::Disabled(method.to_owned())),
            "guest-suspend-ram" if !config.suspend_ram_enabled() => {
                Err(Error::Disabled(method.to_owned()))
            }
            _ => Ok(()),
        }
    }

    /// Step 6: the static allowlist `match` (§5.1). Nothing is looked up
    /// in a table.
    async fn run_handler(&self, req: &Request) -> Result<Value, Error> {
        self.ctx.handler_calls.fetch_add(1, Ordering::SeqCst);
        let ctx = &*self.ctx;
        match req.method.as_str() {
            "guest-ping" => handlers::ping::handle(ctx, req).await,
            "guest-info" => handlers::info::handle(ctx, req).await,
            "guest-sync" => handlers::sync::sync(ctx, req).await,
            "guest-sync-delimited" => handlers::sync::sync_delimited(ctx, req).await,
            "guest-get-osinfo" => handlers::osinfo::handle(ctx, req).await,
            "guest-network-get-interfaces" => handlers::interfaces::handle(ctx, req).await,
            "guest-get-fsinfo" => handlers::fsinfo::handle(ctx, req).await,
            "guest-fsfreeze-status" => handlers::fsfreeze::status(&self.ctx, req).await,
            "guest-fsfreeze-freeze" => handlers::fsfreeze::freeze(&self.ctx, req).await,
            "guest-fsfreeze-freeze-list" => handlers::fsfreeze::freeze_list(&self.ctx, req).await,
            "guest-fsfreeze-thaw" => handlers::fsfreeze::thaw(&self.ctx, req).await,
            "guest-fstrim" => handlers::fstrim::handle(ctx, req).await,
            "guest-shutdown" => handlers::shutdown::handle(ctx, req).await,
            #[cfg(feature = "suspend_ram")]
            "guest-suspend-ram" => handlers::suspend::handle(ctx, req).await,
            // Unreachable: the runtime feature gate already answered
            // `Disabled` for builds without the feature (§8.1).
            #[cfg(not(feature = "suspend_ram"))]
            "guest-suspend-ram" => Err(Error::Disabled(req.method.clone())),
            other => Err(Error::CommandNotFound(other.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;
    use crate::framing::MAX_FRAME_LEN;

    #[test]
    fn retiring_an_operation_never_clears_its_successor() {
        use crate::freeze_op::FreezeOp;
        let ctx = Context::for_tests();
        let a = FreezeOp::detached_for_tests();
        let b = FreezeOp::detached_for_tests();
        ctx.set_freeze_op(Some(Arc::clone(&a)));
        assert!(Arc::ptr_eq(&ctx.freeze_op().unwrap(), &a));
        // A's settlement overlaps B's admission: A's retirement is a no-op.
        ctx.set_freeze_op(Some(Arc::clone(&b)));
        ctx.retire_freeze_op(&a);
        assert!(Arc::ptr_eq(&ctx.freeze_op().unwrap(), &b));
        // Only B retires B; a repeated retirement is harmless.
        ctx.retire_freeze_op(&b);
        assert!(ctx.freeze_op().is_none());
        ctx.retire_freeze_op(&b);
        assert!(ctx.freeze_op().is_none());
    }
    use crate::state::FreezeState;
    use serde_json::json;
    use std::io::Write;
    use std::sync::Mutex;
    use tracing::Level;
    use tracing::instrument::WithSubscriber;

    /// The §2.3 denied-command table.
    const DENIED: &[&str] = &[
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

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl SharedSink {
        fn lines(&self) -> Vec<Value> {
            let bytes = self.0.lock().unwrap().clone();
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
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

    struct Harness {
        dispatcher: Dispatcher,
        sink: SharedSink,
        _dir: tempfile::TempDir,
    }

    impl Harness {
        fn new(state: FreezeState, config: Config) -> Self {
            let sink = SharedSink::default();
            let router = Router::new(Box::new(sink.clone()));
            // Fakes for everything a freeze touches: a root `cargo test`
            // on a host that runs qeminga must never read its mount table
            // or create and remove the live agent's marker.
            let dir = tempfile::tempdir().unwrap();
            let mountinfo = std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/mountinfo/simple.txt"),
            )
            .unwrap();
            let ctx = Context::new(
                Arc::new(config),
                Arc::new(FreezeStateMachine::starting_in(state)),
                router,
                crate::marker::Marker::open(dir.path().join("frozen")).unwrap(),
            )
            .with_kernel(Arc::new(crate::kernel::fake::FakeKernel::new()))
            .with_mounts(Arc::new(crate::mountinfo::StaticMounts(mountinfo)));
            Harness {
                dispatcher: Dispatcher::new(Arc::new(ctx)),
                sink,
                _dir: dir,
            }
        }

        fn thawed() -> Self {
            Self::new(FreezeState::Thawed, Config::default())
        }

        fn ctx(&self) -> &Context {
            self.dispatcher.context()
        }

        async fn send(&self, frame: &[u8]) -> Option<Vec<u8>> {
            let router = self.ctx().audit.clone();
            self.dispatcher
                .handle(DecodeEvent::Frame {
                    bytes: frame.to_vec(),
                    sentinel: false,
                })
                .with_subscriber(audit::subscriber(Level::TRACE, router))
                .await
        }

        async fn send_json(&self, frame: &[u8]) -> Value {
            let reply = self.send(frame).await.expect("expected a reply");
            assert_eq!(reply.last(), Some(&b'\n'));
            let body = reply.strip_prefix(&[0xFF]).unwrap_or(&reply);
            serde_json::from_slice(&body[..body.len() - 1]).unwrap()
        }

        async fn execute(&self, method: &str) -> Value {
            self.send_json(format!(r#"{{"execute":"{method}"}}"#).as_bytes())
                .await
        }

        fn audit_records(&self) -> Vec<Value> {
            assert!(
                self.ctx().audit.settle(std::time::Duration::from_secs(10)),
                "audit delivery stalled"
            );
            self.sink
                .lines()
                .into_iter()
                .filter(|l| l["event"] == audit::EVENT_COMMAND_RECEIVED)
                .collect()
        }
    }

    fn error_class(reply: &Value) -> &str {
        reply["error"]["class"].as_str().unwrap()
    }

    fn error_desc(reply: &Value) -> &str {
        reply["error"]["desc"].as_str().unwrap()
    }

    #[test]
    fn unit_test_contexts_default_to_the_fake_kernel() {
        // The real shim would fail to open this path (ENOENT); the fake
        // records the call and succeeds.
        let ctx = Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            crate::marker::Marker::for_tests(),
        );
        let mount = ctx
            .kernel
            .open_mount(std::path::Path::new("/definitely/not/a/mountpoint"), (0, 0))
            .unwrap();
        assert!(ctx.kernel.fifreeze(&mount).is_ok());
    }

    #[tokio::test]
    async fn every_denied_command_in_design_table_returns_command_not_found() {
        let h = Harness::thawed();
        for method in DENIED {
            assert!(!is_allowlisted(method), "{method}");
            let reply = h.execute(method).await;
            assert_eq!(error_class(&reply), "CommandNotFound", "{method}");
            assert_eq!(
                error_desc(&reply),
                format!("The command {method} has not been found")
            );
        }
        assert_eq!(
            h.ctx().handler_calls(),
            0,
            "denied commands never reach a handler"
        );
        let records = h.audit_records();
        assert_eq!(records.len(), DENIED.len());
        for record in records {
            assert_eq!(record["disposition"], "denied");
            assert_eq!(record["reason"], reason::COMMAND_NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn unknown_method_returns_command_not_found() {
        let h = Harness::thawed();
        for method in ["", "ping", "GUEST-PING", "guest-ping ", "guest-pingx"] {
            let reply = h.execute(method).await;
            assert_eq!(error_class(&reply), "CommandNotFound", "{method:?}");
        }
        // A method longer than 64 bytes is projected in the audit record.
        let long = "guest-".to_owned() + &"x".repeat(100);
        let reply = h.execute(&long).await;
        assert_eq!(error_class(&reply), "CommandNotFound");
        let record = h.audit_records().pop().unwrap();
        assert!(record.get("method").is_none());
        assert_eq!(record["method_len_bytes"], 106);
        assert_eq!(h.ctx().handler_calls(), 0);
    }

    #[tokio::test]
    async fn ping_returns_empty_object() {
        let h = Harness::thawed();
        let reply = h.send(br#"{"execute":"guest-ping"}"#).await.unwrap();
        assert_eq!(reply, b"{\"return\":{}}\n");
        let reply = h.send_json(br#"{"execute":"guest-ping","id":9}"#).await;
        assert_eq!(reply, json!({"return": {}, "id": 9}));
        assert_eq!(h.ctx().handler_calls(), 2);
    }

    #[tokio::test]
    async fn frozen_gate_rejects_non_safe_commands_with_exact_desc() {
        for state in [
            FreezeState::Frozen,
            FreezeState::Freezing,
            FreezeState::Thawing,
        ] {
            let h = Harness::new(state, Config::default());
            for method in [
                "guest-get-osinfo",
                "guest-get-fsinfo",
                "guest-network-get-interfaces",
                "guest-fsfreeze-freeze",
                "guest-fsfreeze-freeze-list",
                "guest-fstrim",
                "guest-shutdown",
                "guest-suspend-ram",
            ] {
                let reply = h.execute(method).await;
                if method == "guest-suspend-ram" && !h.ctx().config.suspend_ram_enabled() {
                    // The runtime gate precedes the freeze gate (C-7).
                    assert_eq!(error_class(&reply), "CommandNotFound", "{state} {method}");
                    continue;
                }
                assert_eq!(error_class(&reply), "GenericError", "{state} {method}");
                assert_eq!(
                    error_desc(&reply),
                    "filesystems are frozen; retry after thaw",
                    "{state} {method}"
                );
            }
            assert_eq!(h.ctx().handler_calls(), 0, "{state}: no handler ran");
            let records = h.audit_records();
            assert!(!records.is_empty());
            for record in records.iter().filter(|r| r["reason"] == reason::FROZEN) {
                assert_eq!(record["disposition"], "denied");
                assert_eq!(record["freeze_state_before"], state.as_str());
            }
        }
    }

    #[test]
    fn lanes_follow_the_frozen_safe_set() {
        // The thaw and the two freezes have lanes of their own; the other
        // frozen-safe commands are controls; everything else, unknown
        // methods included, is serial.
        for spec in handlers::SUPPORTED_COMMANDS {
            let expected = match spec.name {
                "guest-fsfreeze-thaw" => Kind::Thaw,
                "guest-fsfreeze-freeze" | "guest-fsfreeze-freeze-list" => Kind::Freeze,
                name if is_frozen_safe(name) => Kind::Control,
                _ => Kind::Ordinary,
            };
            assert_eq!(lane(spec.name), expected, "{}", spec.name);
        }
        assert_eq!(lane("guest-exec"), Kind::Ordinary);
    }

    #[test]
    fn classification_parses_without_side_effects() {
        let ctx = Arc::new(Context::for_tests());
        let d = Dispatcher::new(Arc::clone(&ctx));
        let frame = |bytes: &[u8]| DecodeEvent::Frame {
            bytes: bytes.to_vec(),
            sentinel: false,
        };
        assert_eq!(
            d.classify(&frame(br#"{"execute":"guest-fsfreeze-status"}"#)),
            Kind::Control
        );
        assert_eq!(
            d.classify(&frame(br#"{"execute":"guest-fsfreeze-thaw","id":1}"#)),
            Kind::Thaw
        );
        assert_eq!(
            d.classify(&frame(br#"{"execute":"guest-fsfreeze-freeze-list"}"#)),
            Kind::Freeze
        );
        assert_eq!(
            d.classify(&frame(br#"{"execute":"guest-fstrim"}"#)),
            Kind::Ordinary
        );
        assert_eq!(
            d.classify(&frame(br#"{"execute":"guest-exec"}"#)),
            Kind::Ordinary
        );
        // Answered without running anything: never in the way of a thaw.
        assert_eq!(d.classify(&frame(b"not json")), Kind::Control);
        assert_eq!(
            d.classify(&DecodeEvent::Oversized { discarded: 1 }),
            Kind::Control
        );
        assert_eq!(ctx.handler_calls(), 0, "classification ran nothing");
    }

    #[tokio::test]
    async fn frozen_safe_set_is_exactly_six() {
        let safe: Vec<&str> = handlers::SUPPORTED_COMMANDS
            .iter()
            .map(|s| s.name)
            .filter(|name| is_frozen_safe(name))
            .collect();
        assert_eq!(
            safe,
            [
                "guest-ping",
                "guest-info",
                "guest-sync",
                "guest-sync-delimited",
                "guest-fsfreeze-status",
                "guest-fsfreeze-thaw",
            ]
        );
        assert!(!is_frozen_safe("guest-exec"));
        let h = Harness::new(FreezeState::Frozen, Config::default());
        for method in &safe {
            let reply = h.execute(method).await;
            assert_ne!(
                error_desc_opt(&reply),
                Some("filesystems are frozen; retry after thaw"),
                "{method} must pass the gate"
            );
        }
        assert_eq!(h.ctx().handler_calls(), safe.len() as u64);
    }

    fn error_desc_opt(reply: &Value) -> Option<&str> {
        reply.get("error").and_then(|e| e["desc"].as_str())
    }

    #[tokio::test]
    async fn rate_limited_request_returns_generic_error() {
        let h = Harness::thawed();
        for _ in 0..120 {
            assert_eq!(h.execute("guest-ping").await, json!({"return": {}}));
        }
        let reply = h.execute("guest-ping").await;
        assert_eq!(error_class(&reply), "GenericError");
        assert_eq!(error_desc(&reply), "rate limit exceeded for ping_sync");
        let record = h.audit_records().pop().unwrap();
        assert_eq!(record["disposition"], "denied");
        assert_eq!(record["reason"], reason::RATE_LIMITED);
        assert_eq!(h.ctx().handler_calls(), 120);
    }

    #[tokio::test]
    async fn thaw_is_never_rate_limited_even_after_flood() {
        let h = Harness::new(FreezeState::Frozen, Config::default());
        for _ in 0..1000 {
            h.execute("guest-ping").await;
        }
        for _ in 0..1000 {
            let reply = h.execute("guest-fsfreeze-thaw").await;
            // The handler is a placeholder; the point is that neither the
            // limiter nor the freeze gate rejected it.
            assert_ne!(
                error_desc_opt(&reply),
                Some("rate limit exceeded for unlimited")
            );
            assert_ne!(
                error_desc_opt(&reply),
                Some("filesystems are frozen; retry after thaw")
            );
            let reply = h.execute("guest-fsfreeze-status").await;
            assert_ne!(
                error_desc_opt(&reply),
                Some("rate limit exceeded for unlimited")
            );
        }
        assert_eq!(h.ctx().handler_calls(), 120 + 2000);
    }

    #[tokio::test]
    async fn disabled_fstrim_returns_command_not_found_with_disabled_desc() {
        let config = Config::parse("[features]\nfstrim = false\n").unwrap();
        let h = Harness::new(FreezeState::Thawed, config);
        let reply = h.execute("guest-fstrim").await;
        assert_eq!(error_class(&reply), "CommandNotFound");
        assert_eq!(error_desc(&reply), "command guest-fstrim has been disabled");
        assert_eq!(h.ctx().handler_calls(), 0);
        let record = h.audit_records().pop().unwrap();
        assert_eq!(record["reason"], reason::DISABLED);

        // Enabled: reaches the handler (which trims the plan; the default
        // test context has no eligible mounts on a fixture-free rig, so the
        // exact reply is the handler's concern, not the gate's).
        let h = Harness::thawed();
        let _ = h.execute("guest-fstrim").await;
        assert_eq!(h.ctx().handler_calls(), 1);

        // suspend-ram: disabled by default at runtime regardless of build.
        let h = Harness::thawed();
        let reply = h.execute("guest-suspend-ram").await;
        assert_eq!(error_class(&reply), "CommandNotFound");
        assert_eq!(
            error_desc(&reply),
            "command guest-suspend-ram has been disabled"
        );
    }

    #[tokio::test]
    async fn parse_error_returns_generic_error_and_no_panic() {
        let h = Harness::thawed();
        for frame in [
            &b"garbage"[..],
            b"{",
            b"[\"guest-ping\"]",
            b"{\"execute\":\"guest-ping\",\"id\":\"x\"}",
            b"{\"execute\":\"guest-ping\"} trailing",
            b"\xff\xfe",
            b"{\"execute\":\"\xff\"}",
        ] {
            let reply = h.send_json(frame).await;
            assert_eq!(error_class(&reply), "GenericError", "{frame:?}");
            assert!(reply.get("id").is_none());
        }
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        let reply = h.send_json(deep.as_bytes()).await;
        assert_eq!(error_class(&reply), "GenericError");

        let none = h
            .dispatcher
            .handle(DecodeEvent::Oversized {
                discarded: MAX_FRAME_LEN + 1,
            })
            .await;
        assert!(none.is_none(), "an oversized frame gets no reply");
        assert_eq!(h.ctx().handler_calls(), 0);
    }

    #[tokio::test]
    async fn oversized_event_is_audited_as_denied_without_reply() {
        let h = Harness::thawed();
        let router = h.ctx().audit.clone();
        let reply = h
            .dispatcher
            .handle(DecodeEvent::Oversized { discarded: 70_000 })
            .with_subscriber(audit::subscriber(Level::TRACE, router))
            .await;
        assert!(reply.is_none());
        let records = h.audit_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["disposition"], "denied");
        assert_eq!(records[0]["reason"], reason::OVERSIZED_FRAME);
        assert_eq!(records[0]["freeze_state_before"], "thawed");
    }

    #[tokio::test]
    async fn every_request_emits_one_audit_record_with_disposition() {
        let h = Harness::thawed();
        h.send(br#"{"execute":"guest-ping","id":1}"#).await;
        h.send(br#"{"execute":"guest-exec","id":2}"#).await;
        h.send(b"not json").await;
        let config = Config::parse("[features]\nfstrim = false\n").unwrap();
        let frozen = Harness::new(FreezeState::Frozen, config);
        frozen
            .send(br#"{"execute":"guest-get-osinfo","id":3}"#)
            .await;
        frozen.send(br#"{"execute":"guest-fstrim","id":4}"#).await;
        frozen
            .send(br#"{"execute":"guest-fsfreeze-thaw","id":5}"#)
            .await;

        let mut records = h.audit_records();
        records.extend(frozen.audit_records());
        assert_eq!(records.len(), 6);
        let expect = [
            (Some(1), "allowed", None, "thawed"),
            (Some(2), "denied", Some(reason::COMMAND_NOT_FOUND), "thawed"),
            (None, "denied", Some(reason::PARSE_ERROR), "thawed"),
            (Some(3), "denied", Some(reason::FROZEN), "frozen"),
            (Some(4), "denied", Some(reason::DISABLED), "frozen"),
            (Some(5), "allowed", None, "frozen"),
        ];
        for (record, (id, disposition, reason, state)) in records.iter().zip(expect) {
            assert_eq!(record["event"], audit::EVENT_COMMAND_RECEIVED);
            assert_eq!(record["id"].as_i64(), id, "{record}");
            assert_eq!(record["disposition"], disposition, "{record}");
            assert_eq!(
                record.get("reason").and_then(Value::as_str),
                reason,
                "{record}"
            );
            assert_eq!(record["freeze_state_before"], state, "{record}");
            assert_eq!(
                record["level"],
                if disposition == "allowed" {
                    "INFO"
                } else {
                    "WARN"
                }
            );
        }
    }

    #[tokio::test]
    async fn sync_delimited_reply_starts_with_0xff() {
        let h = Harness::thawed();
        // Without a sentinel on the request frame.
        let reply = h
            .send(br#"{"execute":"guest-sync-delimited","arguments":{"id":1}}"#)
            .await
            .unwrap();
        assert_eq!(reply[0], 0xFF);
        assert_eq!(&reply[1..], b"{\"return\":1}\n");
        // With one.
        let router = h.ctx().audit.clone();
        let reply = h
            .dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-sync-delimited","arguments":{"id":2},"id":7}"#
                    .to_vec(),
                sentinel: true,
            })
            .with_subscriber(audit::subscriber(Level::TRACE, router))
            .await
            .unwrap();
        assert_eq!(&reply[..2], b"\xff{");
        assert_eq!(&reply[1..], b"{\"return\":2,\"id\":7}\n");
        // Errors for that method carry it too; other methods never do.
        let reply = h
            .send(br#"{"execute":"guest-sync-delimited"}"#)
            .await
            .unwrap();
        assert_eq!(reply[0], 0xFF);
        assert!(reply[1..].starts_with(b"{\"error\""));
        let reply = h
            .send(br#"{"execute":"guest-sync","arguments":{"id":1}}"#)
            .await
            .unwrap();
        assert_eq!(reply, b"{\"return\":1}\n");
    }

    #[tokio::test]
    async fn shutdown_success_yields_no_response() {
        let h = Harness::thawed();
        assert!(
            h.send(br#"{"execute":"guest-shutdown","id":1}"#)
                .await
                .is_none()
        );
        assert_eq!(h.ctx().handler_calls(), 1);
        assert_eq!(h.audit_records().len(), 1);
        // Errors are still reported (rate limit: 2/min).
        h.send(br#"{"execute":"guest-shutdown"}"#).await;
        let reply = h.execute("guest-shutdown").await;
        assert_eq!(error_class(&reply), "GenericError");
        assert_eq!(error_desc(&reply), "rate limit exceeded for shutdown");
        // While frozen the gate error is reported too.
        let frozen = Harness::new(FreezeState::Frozen, Config::default());
        let reply = frozen.execute("guest-shutdown").await;
        assert_eq!(
            error_desc(&reply),
            "filesystems are frozen; retry after thaw"
        );
    }

    #[tokio::test]
    async fn supported_command_table_and_match_arms_agree() {
        let config = Config::parse("[features]\nfstrim = true\nsuspend_ram = true\n").unwrap();
        let enabled_suspend = config.suspend_ram_enabled();
        let h = Harness::new(FreezeState::Thawed, config);
        let mut names: Vec<&str> = handlers::SUPPORTED_COMMANDS
            .iter()
            .map(|s| s.name)
            .collect();
        for name in &names {
            assert!(
                is_allowlisted(name),
                "{name} in table but not in allowlist match"
            );
            assert!(
                CommandClass::of(name).is_some(),
                "{name} has no rate-limit class"
            );
            let Some(reply) = h
                .send(format!(r#"{{"execute":"{name}"}}"#).as_bytes())
                .await
            else {
                assert_eq!(*name, "guest-shutdown", "only shutdown is silent");
                continue;
            };
            let body = reply.strip_prefix(&[0xFF]).unwrap_or(&reply);
            let reply: Value = serde_json::from_slice(&body[..body.len() - 1]).unwrap();
            let class = reply
                .get("error")
                .map(|e| e["class"].as_str().unwrap().to_owned());
            if *name == "guest-suspend-ram" && !enabled_suspend {
                assert_eq!(class.as_deref(), Some("CommandNotFound"));
            } else {
                assert_ne!(class.as_deref(), Some("CommandNotFound"), "{name}");
            }
        }
        // Each name appears exactly once; `guest-shutdown` and
        // `guest-suspend-ram` are the commands without a success response
        // (upstream's contract, OQ-2).
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        assert_eq!(count, 14);
        let no_success: Vec<&str> = handlers::SUPPORTED_COMMANDS
            .iter()
            .filter(|s| !s.success_response)
            .map(|s| s.name)
            .collect();
        assert_eq!(no_success, ["guest-shutdown", "guest-suspend-ram"]);
        // Every match arm's name is in the table: probing the arms with a
        // method that is allowlisted but absent from the table is impossible
        // by construction, so check the inverse direction on the allowlist.
        for method in DENIED {
            assert!(handlers::spec(method).is_none());
        }
    }
}
