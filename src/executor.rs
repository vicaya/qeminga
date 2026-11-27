//! Privileged policy & kernel executor (`qeminga`, UID/GID `600`; OQ-10 §3.2,
//! §4.2, §5.1–§5.4; #78).
//!
//! Never parses JSON and never reads from or writes to the host channel.
//! Receives typed binary [`IpcRequest`] messages from the isolated parser
//! child over `IPC_FD` (`3`), independently enforces:
//!
//! 1. guest command policy ([`Command::is_enabled`] derived from guest config);
//! 2. per-class token-bucket rate limits ([`RateLimiter`]);
//! 3. freeze gate ([`Command::is_frozen_safe`]);
//! 4. guest-owned freeze mount-point allowlist (`#63`) and optional cooperative
//!    per-superblock freeze ownership (`#69`);
//! 5. authoritative `command_received` audit records (sole writer to inherited
//!    `stderr`/journald), distinct from rate-bounded `parser_rejection_observed`
//!    (`source = "untrusted_parser"`) records for `ReportParseRejection`;
//! 6. verified channel opens/reopens (`fstat` + sysfs `virtio-ports` + exact
//!    port name, or explicit `pty-test-only` devpts check), passing only the
//!    single verified descriptor via `SCM_RIGHTS` and closing its own copy;
//! 7. supervision without `CAP_KILL`: on `ipc_protocol_violation` or parser
//!    crash/EOF, closes `IPC_FD` immediately (revoking all executor authority
//!    and ending cooperating parsers on `EOF`), reaps via `wait4(WNOHANG)`, and
//!    **always waits until `FreezeState == Thawed`** (keeping held mount fds,
//!    recovery marker, and watchdog alive) before exiting non-zero so systemd's
//!    `KillMode=control-group` cleans up any uncooperative UID-`601` parser
//!    (`SIGTERM`, then `SIGKILL` after `TimeoutStopSec`) before launching a
//!    replacement generation (with `PR_SET_PDEATHSIG(SIGKILL)` additionally
//!    covering same-UID or `CAP_KILL`-holding invocations).
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use governor::Quota;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use nix::errno::Errno;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinSet;

use crate::audit::{AuditRecord, Disposition, MethodField};
use crate::channel::{INITIAL_BACKOFF, Kind, MAX_BACKOFF, OpenError};
use crate::dispatch::ratelimit::RateLimiter;
use crate::dispatch::{Context, reason};
use crate::freeze_plan::FreezePlan;
use crate::handlers::{
    Command, fsfreeze, fsinfo, fstrim, interfaces, osinfo, serialized_reply_line_bytes, shutdown,
};
use crate::ipc::{
    AssembledMessage, CommandCapability, FlushOutcome, FreezeListSelection, FsInfoDto,
    InterfaceDto, IpcErrorCode, IpcOutbox, IpcRequest, IpcResponse, MAX_CONCURRENT_STREAMS,
    MAX_PACKET_BYTES, ParseRejection, ParseRejectionKind, PeerRole, ProjectedMethod,
    ReceivedRequest, StreamAssembler, TrimPathDto, encode_response_chunks,
};
use crate::kernel::async_fd::OwnedAsyncFd;
use crate::kernel::ipc::recv_packet;
use crate::kernel::process::ParserChild;
use crate::state::FreezeState;

/// Callback opening and verifying the host channel descriptor on
/// `RequestChannelReopen` (production calls
/// [`crate::channel_verify::open_verified_channel`] with `before_seccomp = false`).
pub type VerifiedOpenFn = Arc<dyn Fn(&Path) -> Result<OwnedFd, OpenError> + Send + Sync>;

/// Maximum concurrent in-flight executor operations admitted from the parser
/// (matches `MAX_CONCURRENT_STREAMS` / `MAX_QUEUED = 8`).
const MAX_IN_FLIGHT_OPS: usize = MAX_CONCURRENT_STREAMS;

/// Soft backpressure watermarks on the executor's outbound IPC queue (§5.10):
/// once reached, the executor stops reading new requests from `IPC_FD` until
/// the parser drains responses so an unread compromised parser cannot grow
/// privileged-process memory indefinitely.
const MAX_OUTBOX_PACKETS: usize = 64;
const MAX_OUTBOX_BYTES: usize = 2 * 1024 * 1024;

/// Hard defensive ceilings on the executor's outbound IPC queue (sufficient to
/// absorb replies from every already-in-flight operation once backpressure
/// pauses reading, while terminating a misbehaving IPC peer if ever exceeded).
const HARD_MAX_OUTBOX_PACKETS: usize = 256;
const HARD_MAX_OUTBOX_BYTES: usize = 4 * 1024 * 1024;

/// Per-second rate cap on untrusted `parser_rejection_observed` audit records
/// so a compromised parser cannot flood journald (§3.4).
const PARSER_OBSERVATION_PER_SEC: u32 = 64;

/// Why [`serve_ipc`] exited.
#[derive(Debug, thiserror::Error)]
pub enum ExecutorExitError {
    /// Terminal `EBUSY` on channel open/reopen (`EX_UNAVAILABLE`, §8.4).
    #[error("{0}")]
    ChannelTerminal(#[from] OpenError),
    /// Parser sent malformed IPC, unexpected ancillary data, or violated bounds.
    #[error("ipc protocol violation: {0}")]
    ProtocolViolation(String),
    /// Parser process exited unexpectedly (crash or seccomp kill).
    #[error("parser process exited unexpectedly")]
    ParserLost,
    /// Executor failed to register or poll `IPC_FD`.
    #[error("executor IPC I/O error: {0}")]
    IpcIo(String),
}

/// Outbound response queued by an executor task for delivery over `IPC_FD`.
struct OutboundReply {
    session_gen: u64,
    req_id: u64,
    response: IpcResponse,
    channel_fd: Option<OwnedFd>,
    /// Set when a `RequestChannelReopen` observed terminal `EBUSY` (§8.4).
    terminal_channel_err: Option<OpenError>,
}

type ObservationLimiter = governor::RateLimiter<
    NotKeyed,
    InMemoryState,
    DefaultClock,
    NoOpMiddleware<<DefaultClock as governor::clock::Clock>::Instant>,
>;

/// Lifecycle phase of the active freeze slot inside [`ExecutorLaneGate`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum FreezeStage {
    /// No freeze command currently holds the freeze lane.
    #[default]
    Inactive,
    /// A freeze command owns the freeze lane and is running its synchronous
    /// admission / `begin_freeze()` / `freeze_op::start()` prefix; a later
    /// `Thaw` must wait until it either publishes `FreezeOp` or finishes.
    Starting,
    /// The freeze command has published `Freezing` and its `FreezeOp` in `ctx`
    /// and is now awaiting completion; a later `Thaw` may run concurrently to
    /// join/abort it.
    Published,
}

/// Executor-enforced §5.7 lane serialization so neither channel reconnects nor
/// a compromised parser can reorder serial side effects or let a later thaw
/// race ahead of an earlier freeze's startup, while still letting `Control`
/// run concurrently and letting `Thaw` overtake queued `Ordinary` work once an
/// active `Freeze` has published its operation.
#[derive(Default)]
struct LaneState {
    freeze_stage: FreezeStage,
    thaw_or_ordinary_active: bool,
    next_ticket: u64,
    waiters: VecDeque<(u64, Kind)>,
}

impl LaneState {
    fn can_acquire(&self, ticket: u64, kind: Kind) -> bool {
        match kind {
            Kind::Control => true,
            Kind::Freeze | Kind::Ordinary => {
                self.waiters.front() == Some(&(ticket, kind))
                    && self.freeze_stage == FreezeStage::Inactive
                    && !self.thaw_or_ordinary_active
            }
            Kind::Thaw => {
                if self.thaw_or_ordinary_active {
                    return false;
                }
                match self.freeze_stage {
                    FreezeStage::Inactive => self.waiters.front() == Some(&(ticket, Kind::Thaw)),
                    FreezeStage::Starting => false,
                    FreezeStage::Published => !self
                        .waiters
                        .iter()
                        .take_while(|&&(t, _)| t != ticket)
                        .any(|&(_, k)| matches!(k, Kind::Freeze | Kind::Thaw)),
                }
            }
        }
    }
}

#[derive(Default)]
struct ExecutorLaneGate {
    state: StdMutex<LaneState>,
    notify: Notify,
}

impl ExecutorLaneGate {
    /// Synchronously registers a request in IPC receive order BEFORE spawning
    /// its handler task, returning `None` for `Kind::Control`.
    fn register(self: &Arc<Self>, kind: Kind) -> Option<LaneTicket> {
        if kind == Kind::Control {
            return None;
        }
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.next_ticket = st.next_ticket.wrapping_add(1);
        let ticket = st.next_ticket;
        st.waiters.push_back((ticket, kind));
        Some(LaneTicket {
            gate: Arc::clone(self),
            ticket,
            kind,
            registered: true,
        })
    }
}

/// A receive-ordered reservation in [`ExecutorLaneGate`]; dropping it before
/// [`LaneTicket::acquire`] removes the waiter and wakes successors.
struct LaneTicket {
    gate: Arc<ExecutorLaneGate>,
    ticket: u64,
    kind: Kind,
    registered: bool,
}

impl LaneTicket {
    async fn acquire(mut self) -> ExecutorLaneGuard {
        loop {
            let notified = self.gate.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
                if st.can_acquire(self.ticket, self.kind) {
                    st.waiters.retain(|&(t, _)| t != self.ticket);
                    self.registered = false;
                    match self.kind {
                        Kind::Freeze => st.freeze_stage = FreezeStage::Starting,
                        Kind::Thaw | Kind::Ordinary => st.thaw_or_ordinary_active = true,
                        Kind::Control => {}
                    }
                    return ExecutorLaneGuard {
                        gate: Arc::clone(&self.gate),
                        kind: self.kind,
                    };
                }
            }
            notified.await;
        }
    }
}

impl Drop for LaneTicket {
    fn drop(&mut self) {
        if self.registered {
            let mut st = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
            st.waiters.retain(|&(t, _)| t != self.ticket);
            drop(st);
            self.gate.notify.notify_waiters();
        }
    }
}

struct ExecutorLaneGuard {
    gate: Arc<ExecutorLaneGate>,
    kind: Kind,
}

impl ExecutorLaneGuard {
    /// Marks an active `Kind::Freeze` guard as having published `Freezing` and
    /// its `FreezeOp` in `ctx`, unblocking any waiting `Kind::Thaw` to join it.
    fn mark_freeze_published(&self) {
        if self.kind != Kind::Freeze {
            return;
        }
        let mut st = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.freeze_stage == FreezeStage::Starting {
            st.freeze_stage = FreezeStage::Published;
        }
        drop(st);
        self.gate.notify.notify_waiters();
    }
}

impl Drop for ExecutorLaneGuard {
    fn drop(&mut self) {
        let mut st = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        match self.kind {
            Kind::Freeze => st.freeze_stage = FreezeStage::Inactive,
            Kind::Thaw | Kind::Ordinary => st.thaw_or_ordinary_active = false,
            Kind::Control => {}
        }
        drop(st);
        self.gate.notify.notify_waiters();
    }
}

/// State shared across the executor's spawned request tasks.
struct ExecutorState {
    ctx: Arc<Context>,
    limiter: RateLimiter,
    observation_limiter: ObservationLimiter,
    channel_path: PathBuf,
    channel_opener: VerifiedOpenFn,
    reopen_backoff: StdMutex<ReopenBackoff>,
    reopen_gate: Arc<Semaphore>,
    op_slots: Semaphore,
    lanes: Arc<ExecutorLaneGate>,
    /// Permanently latched to `true` on the first stop signal (`SIGTERM`/`SIGINT`).
    ///
    /// While `Frozen`, C-21 defers executor exit so a legitimate host can still
    /// observe `"frozen"` and thaw cleanly, but once `stopping` is latched:
    /// - every non-frozen-safe command (including any `FsfreezeFreeze` or
    ///   `FsfreezeFreezeList` already queued behind `FsfreezeThaw`) is
    ///   permanently denied at `evaluate_command_gates`, preventing a
    ///   compromised parser from re-freezing after thaw;
    /// - `FsfreezeStatus` stops refreshing the idle watchdog heartbeat,
    ///   preventing heartbeat spam from stretching a freeze toward
    ///   `TimeoutStopSec`.
    stopping: AtomicBool,
}

/// Executor-owned channel reopen backoff (§5.7) immune to parser spoofing:
/// resets to [`INITIAL_BACKOFF`] only when the executor itself admitted a
/// command since the last channel open, otherwise doubles up to [`MAX_BACKOFF`].
struct ReopenBackoff {
    delay: Duration,
    saw_command_since_open: bool,
    has_open_channel: bool,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl ReopenBackoff {
    fn new(had_initial_channel: bool, initial_backoff: Duration, max_backoff: Duration) -> Self {
        Self {
            // If startup already tried and failed to open the channel, begin
            // with `initial_backoff`; if startup opened a channel, the first
            // reopen after a session that carried commands uses `initial_backoff`.
            delay: if had_initial_channel {
                Duration::ZERO
            } else {
                initial_backoff
            },
            saw_command_since_open: had_initial_channel,
            has_open_channel: had_initial_channel,
            initial_backoff,
            max_backoff,
        }
    }

    fn note_command(&mut self) {
        self.saw_command_since_open = true;
    }

    fn next_sleep(&mut self) -> (Duration, bool) {
        let was_open = std::mem::replace(&mut self.has_open_channel, false);
        let sleep = if self.saw_command_since_open {
            self.saw_command_since_open = false;
            self.delay = self.initial_backoff;
            self.initial_backoff
        } else {
            let sleep = self.delay.clamp(self.initial_backoff, self.max_backoff);
            self.delay = (sleep * 2).min(self.max_backoff);
            sleep
        };
        (sleep, was_open)
    }

    fn note_open_succeeded(&mut self) {
        self.has_open_channel = true;
        self.delay = self.initial_backoff;
    }
}

fn outbox_backpressured(outbox: &IpcOutbox) -> bool {
    outbox.pending_packets() >= MAX_OUTBOX_PACKETS || outbox.pending_bytes() >= MAX_OUTBOX_BYTES
}

/// Single executor outbox flush entry point: checks `stop_requested` +
/// `FreezeState::Thawed` before sending every fd-bearing (`OkChannelFd`) packet
/// so no flush path (loop top, `writable` arm, read-loop synchronous flush,
/// `terminal_channel_err` flush, or final drain) can hand off a channel
/// descriptor after shutdown reaches `Thawed`, while ordinary replies such as
/// `ChannelTerminalBusy` continue to flush normally.
fn flush_executor_outbox(
    outbox: &mut IpcOutbox,
    sock: std::os::fd::BorrowedFd<'_>,
    ctx: &Context,
    stop_requested: bool,
) -> Result<FlushOutcome, Errno> {
    outbox.flush_with_fd_gate(sock, || {
        !(stop_requested && ctx.state.current() == FreezeState::Thawed)
    })
}

/// Pushes one response onto `outbox` and enforces the hard defensive backlog
/// ceiling so an unread compromised parser can never grow executor memory
/// without bound (§5.10).
fn push_checked_response(
    outbox: &mut IpcOutbox,
    session_gen: u64,
    req_id: u64,
    response: &IpcResponse,
    channel_fd: Option<OwnedFd>,
) -> Result<(), ExecutorExitError> {
    if let Err(err) = outbox.push_response(session_gen, req_id, response, channel_fd) {
        tracing::error!(
            event = "ipc_response_encode_failed",
            error = %err,
            "failed to encode executor IPC response"
        );
        let _ = outbox.push_response(
            session_gen,
            req_id,
            &IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::Ping,
            }),
            None,
        );
    }
    if outbox.pending_packets() > HARD_MAX_OUTBOX_PACKETS
        || outbox.pending_bytes() > HARD_MAX_OUTBOX_BYTES
    {
        tracing::error!(
            event = "ipc_protocol_violation",
            pending_packets = outbox.pending_packets(),
            pending_bytes = outbox.pending_bytes(),
            error = "executor outbound IPC backlog exceeded bound",
            "closing IPC and terminating parser"
        );
        return Err(ExecutorExitError::ProtocolViolation(
            "executor outbound IPC backlog exceeded bound".to_owned(),
        ));
    }
    Ok(())
}

/// Runs the privileged executor loop over `ipc_fd` until graceful shutdown
/// (`signal` while `Thawed`), terminal channel `EBUSY`, parser exit, or
/// `ipc_protocol_violation` (OQ-10 §4–§5, #78).
///
/// Invariant: **never returns while filesystems may be frozen** (`FreezeState !=
/// Thawed`). On any stop signal, terminal channel error, parser crash, or
/// protocol violation while frozen, `IPC_FD` is closed immediately (severing
/// all parser access to the executor), the child is reaped if dead via
/// `wait4(WNOHANG)`, and the executor keeps `FreezeState`, held mount
/// descriptors, `/run/qeminga/frozen`, and the watchdog alive until `Thawed`.
#[allow(clippy::too_many_arguments)]
pub async fn serve_ipc<S>(
    ctx: Arc<Context>,
    ipc_fd: OwnedFd,
    channel_path: PathBuf,
    channel_opener: VerifiedOpenFn,
    had_initial_channel: bool,
    parser_child: Option<ParserChild>,
    recovery: bool,
    signal: S,
    stop_poll: Duration,
) -> Result<(), ExecutorExitError>
where
    S: Future<Output = &'static str>,
{
    serve_ipc_with_backoff(
        ctx,
        ipc_fd,
        channel_path,
        channel_opener,
        had_initial_channel,
        parser_child,
        recovery,
        signal,
        stop_poll,
        INITIAL_BACKOFF,
        MAX_BACKOFF,
    )
    .await
}

/// Same as [`serve_ipc`] with explicit reopen backoff bounds (tests use short
/// backoffs).
#[allow(clippy::too_many_arguments)]
pub async fn serve_ipc_with_backoff<S>(
    ctx: Arc<Context>,
    ipc_fd: OwnedFd,
    channel_path: PathBuf,
    channel_opener: VerifiedOpenFn,
    had_initial_channel: bool,
    mut parser_child: Option<ParserChild>,
    recovery: bool,
    signal: S,
    stop_poll: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> Result<(), ExecutorExitError>
where
    S: Future<Output = &'static str>,
{
    if recovery && let Err(err) = fsfreeze::start_recovery(&ctx) {
        tracing::error!(event = "recovery_failed", error = %err, "recovery startup failed");
    }
    if had_initial_channel {
        tracing::info!(
            event = "channel_open",
            path = %channel_path.display(),
            "channel opened"
        );
    }

    let async_ipc = OwnedAsyncFd::register(ipc_fd)
        .map_err(|e| ExecutorExitError::IpcIo(format!("cannot register IPC_FD: {e}")))?;

    let obs_quota =
        Quota::per_second(NonZeroU32::new(PARSER_OBSERVATION_PER_SEC).unwrap_or(NonZeroU32::MIN));
    let state = Arc::new(ExecutorState {
        limiter: RateLimiter::new(&ctx.config.rate_limits),
        observation_limiter: governor::RateLimiter::direct(obs_quota),
        ctx: Arc::clone(&ctx),
        channel_path,
        channel_opener,
        reopen_backoff: StdMutex::new(ReopenBackoff::new(
            had_initial_channel,
            initial_backoff,
            max_backoff,
        )),
        reopen_gate: Arc::new(Semaphore::new(1)),
        op_slots: Semaphore::new(MAX_IN_FLIGHT_OPS),
        lanes: Arc::new(ExecutorLaneGate::default()),
        stopping: AtomicBool::new(false),
    });

    let (reply_tx, mut reply_rx) = mpsc::channel::<OutboundReply>(MAX_IN_FLIGHT_OPS * 2);
    let (reopen_cancel_tx, reopen_cancel_rx) = tokio::sync::watch::channel(false);
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut assembler = StreamAssembler::new(PeerRole::Executor);
    let mut outbox = IpcOutbox::new();

    let mut stop_requested = false;
    let mut stop_warned = false;
    let mut stop_ticker = tokio::time::interval(stop_poll);
    stop_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    tokio::pin!(signal);
    let mut signal_pending = true;

    let exit_result: Result<(), ExecutorExitError> = loop {
        // Reap any completed task handles so JoinSet never accumulates metadata.
        while tasks.try_join_next().is_some() {}

        // If a stop signal was received and the guest is now Thawed with no
        // active tasks, drain any replies already produced by finished tasks
        // and attempt one non-blocking flush, then abandon any undelivered
        // replies the peer is not accepting so shutdown never depends on an
        // untrusted parser (design §5.7).
        if stop_requested {
            if ctx.state.current() == FreezeState::Thawed {
                let _ = reopen_cancel_tx.send(true);
                outbox.discard_channel_fd_packets();
            }
            if ctx.state.current() == FreezeState::Thawed && tasks.is_empty() {
                let mut terminal_err: Option<OpenError> = None;
                while let Ok(reply) = reply_rx.try_recv() {
                    if let Some(term_err) = reply.terminal_channel_err {
                        tracing::error!(
                            event = "channel_lost",
                            error = %term_err,
                            "channel lost for good; exiting once thawed"
                        );
                        let _ = outbox.push_response(
                            reply.session_gen,
                            reply.req_id,
                            &IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy),
                            None,
                        );
                        if terminal_err.is_none() {
                            terminal_err = Some(term_err);
                        }
                    } else if reply.channel_fd.is_some()
                        || matches!(reply.response, IpcResponse::OkChannelFd)
                    {
                        // Stop already accepted in `Thawed`: drop the reopened
                        // descriptor instead of handing it off via SCM_RIGHTS.
                        drop(reply.channel_fd);
                    } else {
                        let _ = outbox.push_response(
                            reply.session_gen,
                            reply.req_id,
                            &reply.response,
                            None,
                        );
                    }
                }
                outbox.discard_channel_fd_packets();
                if !outbox.is_empty() {
                    let _ =
                        flush_executor_outbox(&mut outbox, async_ipc.as_fd(), &ctx, stop_requested);
                }
                if let Some(err) = terminal_err {
                    break Err(ExecutorExitError::ChannelTerminal(err));
                }
                if !outbox.is_empty() {
                    tracing::debug!(
                        event = "stop_abandoned_ipc_replies",
                        pending_packets = outbox.pending_packets(),
                        pending_bytes = outbox.pending_bytes(),
                        "abandoning undelivered IPC replies on graceful stop"
                    );
                }
                break Ok(());
            }
            if ctx.state.current() != FreezeState::Thawed && !stop_warned {
                tracing::warn!(
                    event = "stop_deferred",
                    state = %ctx.state.current(),
                    "stop deferred until thaw completes"
                );
                stop_warned = true;
            }
        }

        // Flush any queued outbound packets non-blockingly before awaiting.
        if !outbox.is_empty() {
            match flush_executor_outbox(&mut outbox, async_ipc.as_fd(), &ctx, stop_requested) {
                Ok(FlushOutcome::Drained | FlushOutcome::WouldBlock) => {}
                Err(err) => {
                    tracing::error!(
                        event = "parser_ipc_write_failed",
                        errno = %err,
                        "IPC write failed; closing IPC"
                    );
                    break if stop_requested {
                        Ok(())
                    } else {
                        Err(ExecutorExitError::ParserLost)
                    };
                }
            }
        }

        let can_read_ipc = !outbox_backpressured(&outbox)
            && !(stop_requested && ctx.state.current() == FreezeState::Thawed);

        tokio::select! {
            name = &mut signal, if signal_pending => {
                signal_pending = false;
                stop_requested = true;
                state.stopping.store(true, Ordering::SeqCst);
                tracing::info!(event = "signal", signal = name, "stop requested");
                if ctx.state.current() == FreezeState::Thawed {
                    let _ = reopen_cancel_tx.send(true);
                    outbox.discard_channel_fd_packets();
                }
            }
            _ = stop_ticker.tick(), if stop_requested => {
                if ctx.state.current() == FreezeState::Thawed {
                    let _ = reopen_cancel_tx.send(true);
                    outbox.discard_channel_fd_packets();
                }
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            maybe_reply = reply_rx.recv() => {
                let Some(reply) = maybe_reply else {
                    break Ok(());
                };
                if let Some(term_err) = reply.terminal_channel_err {
                    tracing::error!(
                        event = "channel_lost",
                        error = %term_err,
                        "channel lost for good; exiting once thawed"
                    );
                    let _ = outbox.push_response(
                        reply.session_gen,
                        reply.req_id,
                        &IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy),
                        None,
                    );
                    let _ = flush_executor_outbox(&mut outbox, async_ipc.as_fd(), &ctx, stop_requested);
                    break Err(ExecutorExitError::ChannelTerminal(term_err));
                }
                if stop_requested
                    && ctx.state.current() == FreezeState::Thawed
                    && (reply.channel_fd.is_some()
                        || matches!(reply.response, IpcResponse::OkChannelFd))
                {
                    // Stop already accepted in `Thawed`: discard newly opened
                    // descriptor rather than handing it off to the parser.
                    drop(reply.channel_fd);
                } else if stop_requested
                    && ctx.state.current() == FreezeState::Thawed
                    && outbox_backpressured(&outbox)
                {
                    // Stop already accepted and parser is not draining; abandon reply.
                } else if let Err(err) = push_checked_response(
                    &mut outbox,
                    reply.session_gen,
                    reply.req_id,
                    &reply.response,
                    reply.channel_fd,
                ) {
                    break Err(err);
                }
            }
            writable = async_ipc.writable(), if !outbox.is_empty() => {
                match writable {
                    Ok(mut guard) => {
                        match flush_executor_outbox(&mut outbox, async_ipc.as_fd(), &ctx, stop_requested) {
                            Ok(FlushOutcome::Drained) => {}
                            Ok(FlushOutcome::WouldBlock) => guard.clear_ready(),
                            Err(err) => {
                                tracing::error!(
                                    event = "parser_ipc_write_failed",
                                    errno = %err,
                                    "IPC write failed; closing IPC"
                                );
                                break if stop_requested {
                                    Ok(())
                                } else {
                                    Err(ExecutorExitError::ParserLost)
                                };
                            }
                        }
                    }
                    Err(err) => {
                        break Err(ExecutorExitError::IpcIo(err.to_string()));
                    }
                }
            }
            readable = async_ipc.readable(), if can_read_ipc => {
                match readable {
                    Ok(mut guard) => {
                        let mut read_exit: Option<Result<(), ExecutorExitError>> = None;
                        loop {
                            if outbox_backpressured(&outbox)
                                || (stop_requested && ctx.state.current() == FreezeState::Thawed)
                            {
                                break;
                            }
                            match recv_packet(async_ipc.as_fd(), MAX_PACKET_BYTES) {
                                Ok(Some(pkt)) => match assembler.push(pkt) {
                                    Ok(Some(AssembledMessage::Request(req))) => {
                                        if stop_requested && ctx.state.current() == FreezeState::Thawed {
                                            // Stop already accepted while Thawed: stop reading immediately.
                                            break;
                                        }
                                        if let Err(err) = dispatch_ipc_request(
                                            Arc::clone(&state),
                                            req,
                                            reply_tx.clone(),
                                            reopen_cancel_rx.clone(),
                                            &mut outbox,
                                            &mut tasks,
                                        ) {
                                            read_exit = Some(Err(err));
                                            break;
                                        }
                                        // Flush synchronously generated replies (e.g.
                                        // ReportParseRejection or capacity denial)
                                        // so the socket stays drained and backpressure
                                        // triggers accurately when the peer stops reading.
                                        if !outbox.is_empty()
                                            && let Err(err) = flush_executor_outbox(
                                                &mut outbox,
                                                async_ipc.as_fd(),
                                                &ctx,
                                                stop_requested,
                                            )
                                        {
                                            tracing::error!(
                                                event = "parser_ipc_write_failed",
                                                errno = %err,
                                                "IPC write failed; closing IPC"
                                            );
                                            read_exit = Some(if stop_requested {
                                                Ok(())
                                            } else {
                                                Err(ExecutorExitError::ParserLost)
                                            });
                                            break;
                                        }
                                    }
                                    Ok(Some(AssembledMessage::Response(_))) => {
                                        tracing::error!(
                                            event = "ipc_protocol_violation",
                                            error = "executor received response opcode from parser",
                                            "closing IPC and terminating parser"
                                        );
                                        read_exit = Some(Err(ExecutorExitError::ProtocolViolation(
                                            "executor received response opcode from parser".to_owned(),
                                        )));
                                        break;
                                    }
                                    Ok(None) => {}
                                    Err(err) => {
                                        tracing::error!(
                                            event = "ipc_protocol_violation",
                                            error = %err,
                                            "closing IPC and terminating parser"
                                        );
                                        read_exit = Some(Err(ExecutorExitError::ProtocolViolation(
                                            err.to_string(),
                                        )));
                                        break;
                                    }
                                },
                                Ok(None) => {
                                    if stop_requested && ctx.state.current() == FreezeState::Thawed {
                                        read_exit = Some(Ok(()));
                                    } else {
                                        tracing::warn!(
                                            event = "parser_exited",
                                            state = %ctx.state.current(),
                                            "parser IPC closed unexpectedly"
                                        );
                                        read_exit = Some(Err(ExecutorExitError::ParserLost));
                                    }
                                    break;
                                }
                                Err(Errno::EAGAIN) => {
                                    guard.clear_ready();
                                    break;
                                }
                                Err(Errno::EINTR) => continue,
                                Err(err) => {
                                    tracing::error!(
                                        event = "parser_ipc_read_failed",
                                        errno = %err,
                                        "IPC read failed; closing IPC"
                                    );
                                    read_exit = Some(Err(ExecutorExitError::ParserLost));
                                    break;
                                }
                            }
                        }
                        if let Some(res) = read_exit {
                            break res;
                        }
                    }
                    Err(err) => {
                        break Err(ExecutorExitError::IpcIo(err.to_string()));
                    }
                }
            }
        }
    };

    // Cancel any in-flight reopen backoff sleep, close `reply_rx` so no
    // finishing task can block on `reply_tx.send().await`, and immediately
    // close `IPC_FD`, severing every authority path from the parser (§5.3, §5.7).
    let _ = reopen_cancel_tx.send(true);
    drop(reply_rx);
    drop(outbox);
    drop(async_ipc);

    // Reap parser child if already exited (`wait4(WNOHANG)` — never calls `kill`,
    // since UID 600 does not hold `CAP_KILL`).
    if let Some(child) = parser_child.as_mut() {
        let _ = child.try_wait();
    }

    // Never leave while any in-flight operation (especially freeze/thaw/trim)
    // is still running or while filesystems may remain frozen (§5.3, §5.7, C-21).
    while tasks.join_next().await.is_some() {}
    wait_until_thawed(&ctx, stop_poll).await;

    // One final non-blocking reap attempt after settling.
    if let Some(child) = parser_child.as_mut() {
        let _ = child.try_wait();
    }

    exit_result
}

/// Dispatches one validated [`ReceivedRequest`] onto the executor's task set
/// (or answers synchronously for non-blocking observations / capacity denials).
fn dispatch_ipc_request(
    state: Arc<ExecutorState>,
    req: ReceivedRequest,
    reply_tx: mpsc::Sender<OutboundReply>,
    reopen_cancel: tokio::sync::watch::Receiver<bool>,
    outbox: &mut IpcOutbox,
    tasks: &mut JoinSet<()>,
) -> Result<(), ExecutorExitError> {
    use tracing::instrument::WithSubscriber;

    let ReceivedRequest {
        session_gen,
        req_id,
        host_id,
        request,
    } = req;
    let dispatch = tracing::dispatcher::get_default(Clone::clone);

    // Special non-command operation: RequestChannelReopen (at most 1 spawned task).
    if matches!(request, IpcRequest::RequestChannelReopen) {
        let Ok(reopen_permit) = Arc::clone(&state.reopen_gate).try_acquire_owned() else {
            return push_checked_response(
                outbox,
                session_gen,
                req_id,
                &IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
                None,
            );
        };
        tasks.spawn(
            async move {
                let reply = handle_channel_reopen(
                    &state,
                    session_gen,
                    req_id,
                    reopen_permit,
                    reopen_cancel,
                )
                .await;
                let _ = reply_tx.send(reply).await;
            }
            .with_subscriber(dispatch),
        );
        return Ok(());
    }

    // Special non-command operation: ReportParseRejection runs synchronously
    // (zero spawned tasks, rate-bounded observation log only, never emits
    // `command_received`).
    if let IpcRequest::ReportParseRejection(rej) = request {
        let response = handle_parse_rejection(&state, rej);
        return push_checked_response(outbox, session_gen, req_id, &response, None);
    }

    // Bound concurrent spawned operations so a compromised parser cannot
    // exhaust executor task capacity. Denials at capacity still emit one
    // authoritative `command_received` audit record (preserving disabled
    // precedence, C-7).
    let Ok(permit) = Arc::clone(&state).try_acquire_op_slot() else {
        let response = if let Some(cmd) = command_of_request(&request) {
            deny_at_capacity(&state, cmd, host_id)
        } else {
            IpcResponse::OkAck
        };
        return push_checked_response(outbox, session_gen, req_id, &response, None);
    };

    // Register the §5.7 lane ticket synchronously in IPC receive order BEFORE
    // spawning the task so Tokio scheduling can never reorder serial commands
    // or let a later thaw race ahead of an earlier freeze's startup.
    let lane_ticket = command_of_request(&request).and_then(|cmd| state.lanes.register(cmd.lane()));
    {
        let mut backoff = state
            .reopen_backoff
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        backoff.note_command();
    }

    tasks.spawn(
        async move {
            let _permit = permit;
            let response = execute_command_request(&state, host_id, request, lane_ticket).await;
            let _ = reply_tx
                .send(OutboundReply {
                    session_gen,
                    req_id,
                    response,
                    channel_fd: None,
                    terminal_channel_err: None,
                })
                .await;
        }
        .with_subscriber(dispatch),
    );
    Ok(())
}

impl ExecutorState {
    fn try_acquire_op_slot(self: Arc<Self>) -> Result<OpSlotGuard, ()> {
        let permit = self.op_slots.try_acquire().map_err(|_| ())?;
        // Forget the borrowed permit and restore manually in Drop via Arc so
        // the guard is `'static + Send`.
        permit.forget();
        Ok(OpSlotGuard { state: self })
    }
}

struct OpSlotGuard {
    state: Arc<ExecutorState>,
}

impl Drop for OpSlotGuard {
    fn drop(&mut self) {
        self.state.op_slots.add_permits(1);
    }
}

/// Maps every command [`IpcRequest`] variant to its allowlisted [`Command`].
fn command_of_request(req: &IpcRequest) -> Option<Command> {
    match req {
        IpcRequest::Ping => Some(Command::Ping),
        IpcRequest::Info => Some(Command::Info),
        IpcRequest::Sync { .. } => Some(Command::Sync),
        IpcRequest::SyncDelimited { .. } => Some(Command::SyncDelimited),
        IpcRequest::GetOsInfo => Some(Command::GetOsInfo),
        IpcRequest::NetworkGetInterfaces => Some(Command::NetworkGetInterfaces),
        IpcRequest::GetFsInfo => Some(Command::GetFsInfo),
        IpcRequest::FsfreezeStatus => Some(Command::FsfreezeStatus),
        IpcRequest::FsfreezeFreeze => Some(Command::FsfreezeFreeze),
        IpcRequest::FsfreezeFreezeList(_) => Some(Command::FsfreezeFreezeList),
        IpcRequest::FsfreezeThaw => Some(Command::FsfreezeThaw),
        IpcRequest::Fstrim { .. } => Some(Command::Fstrim),
        IpcRequest::Shutdown { .. } => Some(Command::Shutdown),
        IpcRequest::SuspendRam => Some(Command::SuspendRam),
        IpcRequest::ReportParseRejection(_) | IpcRequest::RequestChannelReopen => None,
    }
}

/// Evaluates the executor's independent authorization gates for `cmd`
/// (`is_enabled -> rate_limit -> freeze_gate`, C-7) without emitting an audit
/// record.
fn evaluate_command_gates(
    state: &ExecutorState,
    cmd: Command,
) -> Result<(), (&'static str, IpcErrorCode)> {
    let authority = state.ctx.config.authority();
    if !cmd.is_enabled(&authority) {
        Err((reason::DISABLED, IpcErrorCode::Disabled { command: cmd }))
    } else if let Err(rl) = state.limiter.check(cmd.rate_class()) {
        Err((
            reason::RATE_LIMITED,
            IpcErrorCode::RateLimited { class: rl.class },
        ))
    } else if (state.ctx.state.is_frozen_for_gate() || state.stopping.load(Ordering::SeqCst))
        && !cmd.is_frozen_safe()
    {
        Err((reason::FROZEN, IpcErrorCode::Frozen))
    } else {
        Ok(())
    }
}

/// Evaluates the executor's independent authorization gates for `cmd`
/// (`is_enabled -> rate_limit -> freeze_gate`, C-7) and emits the single
/// authoritative `command_received` audit record (§9).
fn admit_command(state: &ExecutorState, cmd: Command, id: Option<i64>) -> Result<(), IpcErrorCode> {
    let freeze_state_before = state.ctx.state.current().as_str();
    match evaluate_command_gates(state, cmd) {
        Ok(()) => {
            AuditRecord {
                method: MethodField::Full(cmd.name().to_owned()),
                id,
                disposition: Disposition::Allowed,
                reason: None,
                freeze_state_before,
            }
            .emit();
            Ok(())
        }
        Err((denial_reason, code)) => {
            AuditRecord {
                method: MethodField::Full(cmd.name().to_owned()),
                id,
                disposition: Disposition::Denied,
                reason: Some(denial_reason),
                freeze_state_before,
            }
            .emit();
            Err(code)
        }
    }
}

/// Emits one authoritative `command_received` denial record when a typed
/// command hits the executor's concurrent operation cap, preserving C-7
/// disabled-command precedence.
fn deny_at_capacity(state: &ExecutorState, cmd: Command, id: Option<i64>) -> IpcResponse {
    let freeze_state_before = state.ctx.state.current().as_str();
    let authority = state.ctx.config.authority();
    let (denial_reason, code) = if !cmd.is_enabled(&authority) {
        (reason::DISABLED, IpcErrorCode::Disabled { command: cmd })
    } else {
        (
            reason::RATE_LIMITED,
            IpcErrorCode::RateLimited {
                class: cmd.rate_class(),
            },
        )
    };
    AuditRecord {
        method: MethodField::Full(cmd.name().to_owned()),
        id,
        disposition: Disposition::Denied,
        reason: Some(denial_reason),
        freeze_state_before,
    }
    .emit();
    IpcResponse::Err(code)
}

/// Handles `IpcRequest::ReportParseRejection` synchronously:
/// - For an allowlisted command with invalid arguments (`ParseError` +
///   `method: Some(Full(cmd_name))`), evaluates the executor's gates
///   (`is_enabled -> rate_limit -> freeze_gate`) so the wire reply preserves
///   `C-7` precedence over `InvalidArguments`, while NEVER emitting an
///   authoritative `command_received` record (no command ran).
/// - Emits a rate-bounded `parser_rejection_observed` record explicitly marked
///   `source = "untrusted_parser"` for all rejection kinds (§3.4).
fn handle_parse_rejection(state: &ExecutorState, rej: ParseRejection) -> IpcResponse {
    let freeze_state_before = state.ctx.state.current().as_str();
    let (reason_str, response) = if rej.kind == ParseRejectionKind::ParseError
        && let Some(ProjectedMethod::Full(ref name)) = rej.method
        && let Some(cmd) = Command::from_method(name)
    {
        match evaluate_command_gates(state, cmd) {
            Ok(()) => (
                reason::INVALID_ARGUMENTS,
                IpcResponse::Err(IpcErrorCode::InvalidArguments { command: cmd }),
            ),
            Err((denial_reason, code)) => (denial_reason, IpcResponse::Err(code)),
        }
    } else {
        let reason_str = match rej.kind {
            ParseRejectionKind::Oversized => reason::OVERSIZED_FRAME,
            ParseRejectionKind::ParseError => reason::PARSE_ERROR,
            ParseRejectionKind::UnknownMethod => reason::COMMAND_NOT_FOUND,
        };
        (reason_str, IpcResponse::OkAck)
    };

    if state.observation_limiter.check().is_ok() {
        match rej.method.as_ref().map(ProjectedMethod::to_method_field) {
            Some(MethodField::Full(m)) => {
                tracing::warn!(
                    event = "parser_rejection_observed",
                    source = "untrusted_parser",
                    reason = reason_str,
                    method = m.as_str(),
                    id = rej.id,
                    frame_len = rej.frame_len,
                    freeze_state_before,
                    "untrusted parser reported rejected frame"
                );
            }
            Some(MethodField::Projected {
                method_prefix,
                method_len_bytes,
                method_digest,
            }) => {
                tracing::warn!(
                    event = "parser_rejection_observed",
                    source = "untrusted_parser",
                    reason = reason_str,
                    method_prefix = method_prefix.as_str(),
                    method_len_bytes,
                    method_digest = method_digest.as_str(),
                    id = rej.id,
                    frame_len = rej.frame_len,
                    freeze_state_before,
                    "untrusted parser reported rejected frame"
                );
            }
            None => {
                tracing::warn!(
                    event = "parser_rejection_observed",
                    source = "untrusted_parser",
                    reason = reason_str,
                    id = rej.id,
                    frame_len = rej.frame_len,
                    freeze_state_before,
                    "untrusted parser reported rejected frame"
                );
            }
        }
    }
    response
}

/// Handles `IpcRequest::RequestChannelReopen`: serializes reopens, enforces
/// executor-owned backoff (1 s -> 30 s), verifies backing character-device
/// identity, detects terminal `EBUSY`, and returns the single verified fd via
/// `SCM_RIGHTS`.
async fn handle_channel_reopen(
    state: &ExecutorState,
    session_gen: u64,
    req_id: u64,
    _reopen_permit: OwnedSemaphorePermit,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) -> OutboundReply {
    if *cancel.borrow() {
        return OutboundReply {
            session_gen,
            req_id,
            response: IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
            channel_fd: None,
            terminal_channel_err: None,
        };
    }
    let (sleep_dur, was_open) = {
        let mut backoff = state
            .reopen_backoff
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        backoff.next_sleep()
    };
    if was_open {
        tracing::warn!(
            event = "channel_closed",
            reopen_in_ms = u64::try_from(sleep_dur.as_millis()).unwrap_or(u64::MAX),
            "channel closed; reopening"
        );
    }
    if !sleep_dur.is_zero() {
        tokio::select! {
            () = tokio::time::sleep(sleep_dur) => {}
            _ = cancel.wait_for(|v| *v) => {
                return OutboundReply {
                    session_gen,
                    req_id,
                    response: IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
                    channel_fd: None,
                    terminal_channel_err: None,
                };
            }
        }
    }
    if *cancel.borrow() {
        return OutboundReply {
            session_gen,
            req_id,
            response: IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
            channel_fd: None,
            terminal_channel_err: None,
        };
    }

    let path = state.channel_path.clone();
    let opener = Arc::clone(&state.channel_opener);
    let opened = tokio::task::spawn_blocking(move || opener(&path)).await;
    match opened {
        Ok(Ok(fd)) => {
            if *cancel.borrow() {
                drop(fd);
                return OutboundReply {
                    session_gen,
                    req_id,
                    response: IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
                    channel_fd: None,
                    terminal_channel_err: None,
                };
            }
            {
                let mut backoff = state
                    .reopen_backoff
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                backoff.note_open_succeeded();
            }
            tracing::info!(
                event = "channel_open",
                path = %state.channel_path.display(),
                "channel opened"
            );
            OutboundReply {
                session_gen,
                req_id,
                response: IpcResponse::OkChannelFd,
                channel_fd: Some(fd),
                terminal_channel_err: None,
            }
        }
        Ok(Err(err)) if err.is_terminal() => OutboundReply {
            session_gen,
            req_id,
            response: IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy),
            channel_fd: None,
            terminal_channel_err: Some(err),
        },
        Ok(Err(err)) => {
            tracing::warn!(
                event = "channel_open_retry",
                error = %err,
                "cannot open or verify channel; parser will retry"
            );
            OutboundReply {
                session_gen,
                req_id,
                response: IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
                channel_fd: None,
                terminal_channel_err: None,
            }
        }
        Err(_) => OutboundReply {
            session_gen,
            req_id,
            response: IpcResponse::Err(IpcErrorCode::ChannelRetryLater),
            channel_fd: None,
            terminal_channel_err: None,
        },
    }
}

/// Exhaustive static `match` executing one allowlisted typed command in the
/// privileged executor (design §5.1, §5.7, §9, OQ-10 §4.2).
async fn execute_command_request(
    state: &ExecutorState,
    host_id: Option<i64>,
    req: IpcRequest,
    lane_ticket: Option<LaneTicket>,
) -> IpcResponse {
    let Some(cmd) = command_of_request(&req) else {
        return IpcResponse::OkAck;
    };
    let lane_guard = match lane_ticket {
        Some(ticket) => Some(ticket.acquire().await),
        None => None,
    };
    if let Err(code) = admit_command(state, cmd, host_id) {
        return IpcResponse::Err(code);
    }
    state.ctx.record_handler_call();
    let ctx = &state.ctx;
    let publish_freeze = || {
        if let Some(ref guard) = lane_guard {
            guard.mark_freeze_published();
        }
    };
    match req {
        IpcRequest::Ping => IpcResponse::OkEmpty,
        IpcRequest::Info => {
            let authority = ctx.config.authority();
            let caps = Command::ALL
                .iter()
                .map(|&c| CommandCapability {
                    command: c,
                    enabled: c.is_enabled(&authority),
                    success_response: c.success_response(),
                })
                .collect();
            IpcResponse::OkInfo(caps)
        }
        IpcRequest::Sync { id } | IpcRequest::SyncDelimited { id } => IpcResponse::OkI64(id),
        IpcRequest::FsfreezeStatus => {
            let status = if state.stopping.load(Ordering::SeqCst) {
                crate::ipc::WireFreezeStatus::from_state(ctx.state.current())
            } else {
                fsfreeze::execute_status_ipc(ctx)
            };
            IpcResponse::OkFreezeStatus(status)
        }
        IpcRequest::FsfreezeFreeze => {
            match fsfreeze::execute_freeze_ipc_with_published(ctx, None, publish_freeze).await {
                Ok(n) => IpcResponse::OkCount(n),
                Err(code) => IpcResponse::Err(code),
            }
        }
        IpcRequest::FsfreezeFreezeList(selection) => {
            let restrict = match selection {
                FreezeListSelection::Omitted => None,
                FreezeListSelection::Present(list) => Some(list),
            };
            match fsfreeze::execute_freeze_ipc_with_published(ctx, restrict, publish_freeze).await {
                Ok(n) => IpcResponse::OkCount(n),
                Err(code) => IpcResponse::Err(code),
            }
        }
        IpcRequest::FsfreezeThaw => {
            let res = if state.stopping.load(Ordering::SeqCst) {
                fsfreeze::execute_thaw_existing_ipc(ctx).await
            } else {
                fsfreeze::execute_thaw_ipc(ctx).await
            };
            match res {
                Ok(n) => IpcResponse::OkCount(n),
                Err(code) => IpcResponse::Err(code),
            }
        }
        IpcRequest::GetOsInfo => execute_osinfo(ctx).await,
        IpcRequest::NetworkGetInterfaces => execute_interfaces(ctx).await,
        IpcRequest::GetFsInfo => execute_fsinfo(ctx).await,
        IpcRequest::Fstrim { minimum } => execute_fstrim(ctx, minimum).await,
        IpcRequest::Shutdown { mode } => match shutdown::execute_shutdown(ctx, mode).await {
            Ok(()) => IpcResponse::OkSilent,
            Err(err) => {
                tracing::error!(event = "shutdown_failed", error = %err, "shutdown failed");
                IpcResponse::Err(IpcErrorCode::HandlerFailed {
                    command: Command::Shutdown,
                })
            }
        },
        IpcRequest::SuspendRam => execute_suspend_ipc(ctx).await,
        IpcRequest::ReportParseRejection(_) | IpcRequest::RequestChannelReopen => {
            IpcResponse::OkAck
        }
    }
}

async fn execute_osinfo(ctx: &Arc<Context>) -> IpcResponse {
    let source = Arc::clone(&ctx.osinfo);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let res = tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || osinfo::os_info(source.as_ref()))
    })
    .await;
    let info = match res {
        Ok(Ok(info)) => info,
        Ok(Err(err)) => {
            tracing::warn!(event = "osinfo_failed", error = %err, "osinfo failed");
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::GetOsInfo,
            });
        }
        Err(_) => {
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::GetOsInfo,
            });
        }
    };
    match serialized_reply_line_bytes("osinfo", &info) {
        Ok((_, line)) if line > osinfo::MAX_OSINFO_REPLY_BYTES => {
            IpcResponse::Err(IpcErrorCode::ReplyTooLarge {
                command: Command::GetOsInfo,
                reply_bytes: line as u64,
                limit_bytes: osinfo::MAX_OSINFO_REPLY_BYTES as u64,
            })
        }
        Ok(_) => IpcResponse::OkOsInfo(Box::new(info)),
        Err(_) => IpcResponse::Err(IpcErrorCode::HandlerFailed {
            command: Command::GetOsInfo,
        }),
    }
}

async fn execute_interfaces(ctx: &Arc<Context>) -> IpcResponse {
    let source = Arc::clone(&ctx.interfaces);
    let res =
        tokio::task::spawn_blocking(move || source.addresses().map(interfaces::collect)).await;
    let list = match res {
        Ok(Ok(list)) => list,
        Ok(Err(err)) => {
            tracing::warn!(event = "interfaces_failed", error = %err, "interfaces failed");
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::NetworkGetInterfaces,
            });
        }
        Err(_) => {
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::NetworkGetInterfaces,
            });
        }
    };
    match serialized_reply_line_bytes("interfaces", &list) {
        Ok((_, line)) if line > interfaces::MAX_INTERFACES_REPLY_BYTES => {
            IpcResponse::Err(IpcErrorCode::ReplyTooLarge {
                command: Command::NetworkGetInterfaces,
                reply_bytes: line as u64,
                limit_bytes: interfaces::MAX_INTERFACES_REPLY_BYTES as u64,
            })
        }
        Ok(_) => match list
            .iter()
            .map(InterfaceDto::from_handler)
            .collect::<Option<Vec<_>>>()
        {
            Some(dtos) => IpcResponse::OkInterfaces(dtos),
            None => IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::NetworkGetInterfaces,
            }),
        },
        Err(_) => IpcResponse::Err(IpcErrorCode::HandlerFailed {
            command: Command::NetworkGetInterfaces,
        }),
    }
}

async fn execute_fsinfo(ctx: &Arc<Context>) -> IpcResponse {
    let Ok(slot) = Arc::clone(&ctx.fsinfo_walks).try_acquire_owned() else {
        return IpcResponse::Err(IpcErrorCode::FsinfoBusy);
    };
    let mounts = Arc::clone(&ctx.mounts);
    let statfs = Arc::clone(&ctx.statfs);
    let walk = tokio::task::spawn_blocking(move || {
        let _walk = slot;
        let mut snapshot = mounts.mount_snapshot()?;
        let (entries, monitor) = snapshot.split_mut();
        fsinfo::fs_info_with_monitor(entries, statfs.as_ref(), monitor)
    });
    let info = match tokio::time::timeout(fsinfo::FSINFO_TIMEOUT, walk).await {
        Ok(Ok(Ok(info))) => info,
        Ok(Ok(Err(err))) => {
            tracing::warn!(event = "fsinfo_failed", error = %err, "fsinfo failed");
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::GetFsInfo,
            });
        }
        Ok(Err(_)) => {
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::GetFsInfo,
            });
        }
        Err(_) => return IpcResponse::Err(IpcErrorCode::FsinfoTimeout),
    };
    match serialized_reply_line_bytes("fsinfo", &info) {
        Ok((_, line)) if line > fsinfo::MAX_FSINFO_REPLY_BYTES => {
            IpcResponse::Err(IpcErrorCode::ReplyTooLarge {
                command: Command::GetFsInfo,
                reply_bytes: line as u64,
                limit_bytes: fsinfo::MAX_FSINFO_REPLY_BYTES as u64,
            })
        }
        Ok(_) => {
            let dtos = info.iter().map(FsInfoDto::from_handler).collect();
            IpcResponse::OkFsInfo(dtos)
        }
        Err(_) => IpcResponse::Err(IpcErrorCode::HandlerFailed {
            command: Command::GetFsInfo,
        }),
    }
}

async fn execute_fstrim(ctx: &Arc<Context>, minimum: u64) -> IpcResponse {
    let kernel = Arc::clone(&ctx.kernel);
    let mounts = Arc::clone(&ctx.mounts);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let entries = match tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let plan = FreezePlan::build(&mounts.mounts()?);
            Ok::<_, crate::proto::Error>(fstrim::trim_plan_entries(kernel.as_ref(), &plan, minimum))
        })
    })
    .await
    {
        Ok(Ok(entries)) => entries,
        Ok(Err(err)) => {
            tracing::warn!(event = "fstrim_failed", error = %err, "fstrim failed");
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::Fstrim,
            });
        }
        Err(_) => {
            return IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::Fstrim,
            });
        }
    };

    let response = fstrim::TrimResponse {
        paths: entries.iter().map(fstrim::TrimEntry::to_result).collect(),
    };
    match fstrim::check_fstrim_reply_bounds(&response) {
        Ok(_) => {
            let dtos: Vec<TrimPathDto> = entries.iter().map(TrimPathDto::from_entry).collect();
            let candidate = IpcResponse::OkFstrim(dtos);
            // Defensive check: if binary IPC framing itself ever exceeded
            // `MAX_FSTRIM_IPC_BYTES`, degrade cleanly to `FstrimReplyTooLarge`
            // rather than dropping the IPC session.
            if encode_response_chunks(0, 0, &candidate).is_err() {
                let trimmed_targets = entries
                    .iter()
                    .filter(|e| matches!(e.outcome, fstrim::TrimPathOutcome::Trimmed { .. }))
                    .count() as u64;
                let failed_targets = entries.len() as u64 - trimmed_targets;
                tracing::warn!(
                    event = "fstrim_reply_too_large",
                    trimmed_targets,
                    failed_targets,
                    limit_bytes = fstrim::MAX_FSTRIM_REPLY_BYTES as u64,
                    "fstrim IPC payload exceeds bound; returning summary counts only"
                );
                return IpcResponse::Err(IpcErrorCode::FstrimReplyTooLarge {
                    trimmed_targets,
                    failed_targets,
                    limit_bytes: fstrim::MAX_FSTRIM_REPLY_BYTES as u64,
                });
            }
            candidate
        }
        Err(Ok(oversize)) => {
            tracing::warn!(
                event = "fstrim_reply_too_large",
                trimmed_targets = oversize.trimmed_targets,
                failed_targets = oversize.failed_targets,
                reply_bytes = oversize.reply_bytes as u64,
                limit_bytes = oversize.limit_bytes as u64,
                "fstrim reply exceeds 1 MiB bound; returning summary counts only"
            );
            IpcResponse::Err(IpcErrorCode::FstrimReplyTooLarge {
                trimmed_targets: oversize.trimmed_targets,
                failed_targets: oversize.failed_targets,
                limit_bytes: oversize.limit_bytes as u64,
            })
        }
        Err(Err(_)) => IpcResponse::Err(IpcErrorCode::HandlerFailed {
            command: Command::Fstrim,
        }),
    }
}

#[cfg(feature = "suspend_ram")]
async fn execute_suspend_ipc(ctx: &Arc<Context>) -> IpcResponse {
    match crate::handlers::suspend::execute_suspend(ctx).await {
        Ok(()) => IpcResponse::OkSilent,
        Err(err) => {
            tracing::error!(event = "suspend_failed", error = %err, "suspend failed");
            IpcResponse::Err(IpcErrorCode::HandlerFailed {
                command: Command::SuspendRam,
            })
        }
    }
}

#[cfg(not(feature = "suspend_ram"))]
async fn execute_suspend_ipc(_ctx: &Arc<Context>) -> IpcResponse {
    IpcResponse::Err(IpcErrorCode::Disabled {
        command: Command::SuspendRam,
    })
}

async fn wait_until_thawed(ctx: &Context, poll: Duration) {
    let mut warned = false;
    while ctx.state.current() != FreezeState::Thawed {
        if !warned {
            tracing::warn!(
                event = "stop_deferred",
                state = %ctx.state.current(),
                "stop deferred until thaw completes"
            );
            warned = true;
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::Write;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tracing::instrument::WithSubscriber;

    use super::*;
    use crate::audit::Router;
    use crate::config::Config;
    use crate::ipc::{
        IpcRequest, IpcResponse, PeerRole, StreamAssembler, WireFreezeStatus, recv_response,
        send_request,
    };
    use crate::kernel::fake::FakeKernel;
    use crate::kernel::ipc::{send_packet, seqpacket_pair};
    use crate::marker::Marker;
    use crate::mountinfo::StaticMounts;
    use crate::state::FreezeStateMachine;

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);
    impl Write for SharedSink {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn set_blocking(fd: std::os::fd::BorrowedFd<'_>) {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL).unwrap());
        fcntl(fd, FcntlArg::F_SETFL(flags - OFlag::O_NONBLOCK)).unwrap();
    }

    #[tokio::test]
    async fn executor_enforces_cvm_policy_c7_precedence_and_untrusted_observation_distinction() {
        let sink = SharedSink::default();
        let router = Router::new(Box::new(sink.clone()));
        let mut cfg = Config::default();
        cfg.features.information = false;
        cfg.features.fstrim = false;
        cfg.features.shutdown = false;
        cfg.agent.freeze_allowed_mountpoints = Some(vec!["/data".to_owned()]);
        let table = concat!(
            "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n",
            "2 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n",
        );
        let kernel = Arc::new(FakeKernel::new());
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                router.clone(),
                Marker::for_tests(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table.to_owned()))),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::INFO,
            router.clone(),
        ));
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();
        let exec_task = tokio::spawn(
            serve_ipc_with_backoff(
                Arc::clone(&ctx),
                exec_sock,
                PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
                opener,
                true,
                None,
                false,
                async move { stop_rx.await.unwrap_or("SIGTERM") },
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(50),
            )
            .with_subscriber(dispatch.clone()),
        );

        // Drive parser end on a blocking thread so tokio workers stay free.
        let client = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);

            // 1. Disabled CVM command (`GetOsInfo`) rejected with `Disabled` and zero handler calls,
            //    preserving host QGA `id` (701) in authoritative audit.
            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                1,
                Some(701),
                &IpcRequest::GetOsInfo,
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::Err(IpcErrorCode::Disabled {
                    command: Command::GetOsInfo
                })
            );

            // 2. Disabled command with bad args (`ReportParseRejection(ParseError, Full("guest-fstrim"))`)
            //    returns `Disabled`, NOT `InvalidArguments` (C-7 precedence), and must NOT emit `command_received`.
            send_request(
                parser_sock.as_fd(),
                1,
                2,
                &IpcRequest::ReportParseRejection(ParseRejection {
                    kind: ParseRejectionKind::ParseError,
                    frame_len: 40,
                    id: Some(9),
                    method: Some(ProjectedMethod::Full("guest-fstrim".to_owned())),
                }),
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::Err(IpcErrorCode::Disabled {
                    command: Command::Fstrim
                })
            );

            // 3. Enabled command (`guest-ping`) with bad args returns `InvalidArguments`
            //    and must NOT emit `command_received` (only `parser_rejection_observed`).
            send_request(
                parser_sock.as_fd(),
                1,
                3,
                &IpcRequest::ReportParseRejection(ParseRejection {
                    kind: ParseRejectionKind::ParseError,
                    frame_len: 40,
                    id: Some(10),
                    method: Some(ProjectedMethod::Full("guest-ping".to_owned())),
                }),
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::Err(IpcErrorCode::InvalidArguments {
                    command: Command::Ping
                })
            );

            // 4. Unknown method logged as `parser_rejection_observed` (`source = "untrusted_parser"`).
            send_request(
                parser_sock.as_fd(),
                1,
                4,
                &IpcRequest::ReportParseRejection(ParseRejection {
                    kind: ParseRejectionKind::UnknownMethod,
                    frame_len: 32,
                    id: Some(11),
                    method: Some(ProjectedMethod::Full("guest-exec".to_owned())),
                }),
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r.response, IpcResponse::OkAck);

            // 5. #63 allowlist enforced in executor: freezing `/` (disallowed) returns 0;
            //    freezing `/data` (allowed) returns 1 and thaws cleanly.
            send_request(
                parser_sock.as_fd(),
                1,
                5,
                &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec!["/".to_owned()])),
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r.response, IpcResponse::OkCount(0));

            send_request(
                parser_sock.as_fd(),
                1,
                6,
                &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec![
                    "/data".to_owned(),
                ])),
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r.response, IpcResponse::OkCount(1));

            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                7,
                Some(-702),
                &IpcRequest::FsfreezeStatus,
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::OkFreezeStatus(WireFreezeStatus::Frozen)
            );

            send_request(parser_sock.as_fd(), 1, 8, &IpcRequest::FsfreezeThaw).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r.response, IpcResponse::OkCount(1));

            let _ = stop_tx.send("SIGTERM");
            (parser_sock, asm)
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        // Executor closed IPC_FD on clean SIGTERM shutdown; parser sees EOF.
        let (parser_sock, mut asm) = client;
        assert!(
            recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .is_none()
        );
        drop(parser_sock);
        assert!(router.settle(Duration::from_secs(2)));
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = logs.lines().collect();
        // Unknown method observation.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"event\":\"parser_rejection_observed\"")
                    && l.contains("\"source\":\"untrusted_parser\"")
                    && l.contains("\"method\":\"guest-exec\"")
                    && l.contains("\"reason\":\"command_not_found\"")),
            "expected untrusted unknown-method observation record: {logs}"
        );
        // Known-method invalid-arguments observations (both disabled and enabled)
        // must appear ONLY as `parser_rejection_observed`, NEVER as `command_received`.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"event\":\"parser_rejection_observed\"")
                    && l.contains("\"source\":\"untrusted_parser\"")
                    && l.contains("\"method\":\"guest-fstrim\"")
                    && l.contains("\"reason\":\"disabled\"")
                    && l.contains("\"id\":9")),
            "expected known-method disabled observation record: {logs}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"event\":\"parser_rejection_observed\"")
                    && l.contains("\"source\":\"untrusted_parser\"")
                    && l.contains("\"method\":\"guest-ping\"")
                    && l.contains("\"reason\":\"invalid_arguments\"")
                    && l.contains("\"id\":10")),
            "expected known-method invalid_arguments observation record: {logs}"
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("\"event\":\"command_received\"")
                    && (l.contains("\"method\":\"guest-fstrim\"")
                        || l.contains("\"method\":\"guest-ping\""))),
            "parser-reported argument errors must NEVER emit authoritative command_received records: {logs}"
        );
        // Real typed commands preserve host QGA `id` on both denied and allowed records.
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"event\":\"command_received\"")
                    && l.contains("\"method\":\"guest-get-osinfo\"")
                    && l.contains("\"disposition\":\"denied\"")
                    && l.contains("\"reason\":\"disabled\"")
                    && l.contains("\"id\":701")),
            "expected authoritative disabled command_received record with id=701: {logs}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains("\"event\":\"command_received\"")
                    && l.contains("\"method\":\"guest-fsfreeze-status\"")
                    && l.contains("\"disposition\":\"allowed\"")
                    && l.contains("\"id\":-702")),
            "expected authoritative allowed command_received record with id=-702: {logs}"
        );
    }

    #[tokio::test]
    async fn protocol_violation_while_frozen_closes_ipc_and_preserves_watchdog_until_thaw() {
        let mut cfg = Config::default();
        cfg.agent.fsfreeze_idle_timeout_secs = 1;
        cfg.agent.fsfreeze_max_timeout_secs = 5;
        let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let router = Router::new(Box::new(std::io::sink()));
        let dir = tempfile::Builder::new()
            .prefix("qeminga-exec-test-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker = Marker::open(dir.path().join("frozen")).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                router,
                marker,
            )
            .with_kernel(Arc::new(FakeKernel::new()))
            .with_mounts(Arc::new(StaticMounts(table.to_owned()))),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            Arc::clone(&ctx),
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            true,
            None,
            false,
            std::future::pending::<&'static str>(),
            Duration::from_millis(20),
            Duration::from_millis(10),
            Duration::from_millis(50),
        ));

        tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            // Freeze the guest cleanly first.
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::FsfreezeFreeze).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r.response, IpcResponse::OkCount(1));

            // Now simulate a compromised parser sending an unauthorized SCM_RIGHTS fd!
            let (pipe_r, pipe_w) = nix::unistd::pipe().unwrap();
            let bogus = vec![1u8; 23];
            send_packet(parser_sock.as_fd(), &bogus, Some(pipe_w.as_fd())).unwrap();
            drop(pipe_w);

            // Executor MUST immediately close IPC_FD (yielding EOF on parser_sock)
            // and close the received pipe_w (yielding EOF on pipe_r) while STILL
            // staying alive until the 1s watchdog finishes thawing!
            assert!(
                recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES)
                    .unwrap()
                    .is_none()
            );
            let mut b = [0u8; 1];
            assert_eq!(nix::unistd::read(&pipe_r, &mut b), Ok(0));
        })
        .await
        .unwrap();

        let err = exec_task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, ExecutorExitError::ProtocolViolation(_)),
            "{err:?}"
        );
        // Executor did NOT exit until the watchdog thawed the guest and removed the marker!
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!ctx.marker.exists());
    }

    #[tokio::test]
    async fn channel_reopen_hands_off_verified_fd_and_handles_terminal_ebusy() {
        let ctx = Arc::new(Context::for_tests());
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let opener: VerifiedOpenFn = Arc::new(move |p| {
            let n = calls_clone.fetch_add(1, Ordering::SeqCst);
            match n {
                0 => Err(OpenError::NotFound { path: p.to_owned() }),
                1 => {
                    let (_r, w) = nix::unistd::pipe().unwrap();
                    Ok(w)
                }
                _ => Err(OpenError::AlreadyOpen { path: p.to_owned() }),
            }
        });

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            Arc::clone(&ctx),
            exec_sock,
            PathBuf::from("/dev/virtio-ports/test"),
            opener,
            false,
            None,
            false,
            std::future::pending::<&'static str>(),
            Duration::from_millis(10),
            Duration::from_millis(5),
            Duration::from_millis(10),
        ));

        tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            // Attempt 0: ENOENT -> ChannelRetryLater
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::RequestChannelReopen).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::Err(IpcErrorCode::ChannelRetryLater)
            );
            assert!(r.channel_fd.is_none());

            // Attempt 1: succeeds -> OkChannelFd with 1 SCM_RIGHTS fd
            send_request(parser_sock.as_fd(), 1, 2, &IpcRequest::RequestChannelReopen).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r.response, IpcResponse::OkChannelFd);
            assert!(r.channel_fd.is_some());

            // Attempt 2: EBUSY -> terminal exit!
            send_request(parser_sock.as_fd(), 2, 3, &IpcRequest::RequestChannelReopen).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy)
            );
        })
        .await
        .unwrap();

        let err = exec_task.await.unwrap().unwrap_err();
        assert!(
            matches!(
                err,
                ExecutorExitError::ChannelTerminal(OpenError::AlreadyOpen { .. })
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn executor_handles_inventory_fstrim_oversize_and_power_commands() {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::audit;
        use crate::handlers::interfaces::{InterfaceSource, RawAddr};
        use crate::handlers::osinfo::{OsInfoSource, Uname};
        use crate::proto::Error as ProtoError;

        struct FakeOsInfo;
        impl OsInfoSource for FakeOsInfo {
            fn uname(&self) -> Result<Uname, ProtoError> {
                Ok(Uname {
                    release: "6.8.0".to_owned(),
                    version: "#1 SMP".to_owned(),
                    machine: "x86_64".to_owned(),
                })
            }
            fn os_release(&self) -> Option<String> {
                Some("ID=ubuntu\nNAME=\"Ubuntu\"\n".to_owned())
            }
        }
        struct FakeIfaces;
        impl InterfaceSource for FakeIfaces {
            fn addresses(&self) -> Result<Vec<RawAddr>, ProtoError> {
                Ok(vec![RawAddr {
                    ifname: "eth0".to_owned(),
                    loopback: false,
                    mac: None,
                    addr: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
                    netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
                }])
            }
        }

        let mut cfg = Config::default();
        cfg.features.shutdown = true;
        cfg.features.information = true;
        cfg.features.fstrim = true;
        cfg.features.suspend_ram = true;

        // Build mountinfo text with 1 real temp mountpoint plus 5000 distinct
        // synthetic mounts to push fstrim's assembled reply over 1 MiB.
        let mount_dir = tempfile::tempdir().unwrap();
        let mut mountinfo = format!(
            "1 0 8:1 / {} rw - ext4 /dev/vda1 rw\n",
            mount_dir.path().display()
        );
        let long_seg = "x".repeat(220);
        for i in 0..5000u32 {
            use std::fmt::Write as _;
            let _ = writeln!(
                mountinfo,
                "{} 1 253:{i} / /nonexistent-trim-{i}-{long_seg} rw - ext4 /dev/vdb{i} rw",
                10 + i
            );
        }

        let sink = SharedSink::default();
        let router = Router::new(Box::new(sink.clone()));
        let dispatch =
            tracing::Dispatch::new(audit::subscriber(tracing::Level::DEBUG, router.clone()));
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let kernel = Arc::new(FakeKernel::new());
        kernel.script_open_error(format!("/nonexistent-trim-0-{long_seg}"), Errno::ENOENT);
        kernel.script_trim(
            format!("/nonexistent-trim-1-{long_seg}"),
            Err(Errno::EOPNOTSUPP),
        );
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                router.clone(),
                Marker::for_tests(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(mountinfo)))
            .with_osinfo(Arc::new(FakeOsInfo))
            .with_interfaces(Arc::new(FakeIfaces)),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
        let exec_task = tokio::spawn(
            serve_ipc(
                Arc::clone(&ctx),
                exec_sock,
                PathBuf::from("/dev/virtio-ports/test"),
                opener,
                true,
                None,
                false,
                async move { stop_rx.await.unwrap_or("SIGTERM") },
                Duration::from_millis(10),
            )
            .with_subscriber(dispatch.clone()),
        );

        let client = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);

            // 1. Info returns all 14 commands.
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::Info).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert!(matches!(r.response, IpcResponse::OkInfo(ref v) if v.len() == 14));

            // 2. Sync & SyncDelimited echo id.
            send_request(parser_sock.as_fd(), 1, 2, &IpcRequest::Sync { id: 99 }).unwrap();
            assert_eq!(
                recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap()
                    .response,
                IpcResponse::OkI64(99)
            );
            send_request(
                parser_sock.as_fd(),
                1,
                3,
                &IpcRequest::SyncDelimited { id: 100 },
            )
            .unwrap();
            assert_eq!(
                recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap()
                    .response,
                IpcResponse::OkI64(100)
            );

            // 3. GetOsInfo & NetworkGetInterfaces succeed.
            send_request(parser_sock.as_fd(), 1, 4, &IpcRequest::GetOsInfo).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert!(
                matches!(r.response, IpcResponse::OkOsInfo(ref o) if o.id.as_deref() == Some("ubuntu"))
            );

            send_request(parser_sock.as_fd(), 1, 5, &IpcRequest::NetworkGetInterfaces).unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert!(matches!(r.response, IpcResponse::OkInterfaces(ref v) if v.len() == 1));

            // 4. Fstrim over 1 MiB returns mixed-outcome FstrimReplyTooLarge
            //    (4999 trimmed + 1 pre-ioctl open error + 1 FITRIM error)
            //    WITHOUT dropping the IPC session!
            send_request(
                parser_sock.as_fd(),
                1,
                6,
                &IpcRequest::Fstrim { minimum: 0 },
            )
            .unwrap();
            let r = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                r.response,
                IpcResponse::Err(IpcErrorCode::FstrimReplyTooLarge {
                    trimmed_targets: 4999,
                    failed_targets: 2,
                    limit_bytes: crate::handlers::fstrim::MAX_FSTRIM_REPLY_BYTES as u64,
                })
            );

            // 5. Session stays intact after oversize fstrim: Ping succeeds!
            send_request(parser_sock.as_fd(), 1, 7, &IpcRequest::Ping).unwrap();
            assert_eq!(
                recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap()
                    .response,
                IpcResponse::OkEmpty
            );

            // 6. Shutdown returns OkSilent with FakeKernel.
            send_request(
                parser_sock.as_fd(),
                1,
                8,
                &IpcRequest::Shutdown {
                    mode: crate::handlers::shutdown::ShutdownMode::Powerdown,
                },
            )
            .unwrap();
            assert_eq!(
                recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap()
                    .response,
                IpcResponse::OkSilent
            );

            let _ = stop_tx.send("SIGTERM");
            (parser_sock, asm)
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        let (parser_sock, mut asm) = client;
        assert!(
            recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .is_none()
        );
        drop(parser_sock);
        assert!(router.settle(Duration::from_secs(2)));
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("\"event\":\"fstrim_reply_too_large\""),
            "expected bounded fstrim_reply_too_large audit record: {logs}"
        );
    }

    #[tokio::test]
    async fn executor_exits_promptly_after_rejection_flood_and_protocol_violation() {
        // Codex P1 #2: sending > 16 `ReportParseRejection` requests without
        // reading replies followed by a malformed IPC packet must NEVER hang
        // waiting on `reply_tx.send()` during cleanup.
        let cfg = Config::default();
        let router = Router::new(Box::new(std::io::sink()));
        let ctx = Arc::new(Context::new(
            Arc::new(cfg),
            Arc::new(FreezeStateMachine::new()),
            router,
            Marker::for_tests(),
        ));
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            ctx,
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            true,
            None,
            false,
            std::future::pending(),
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_millis(50),
        ));

        tokio::task::spawn_blocking(move || {
            for i in 1..=32u64 {
                send_request(
                    parser_sock.as_fd(),
                    1,
                    i,
                    &IpcRequest::ReportParseRejection(ParseRejection {
                        kind: ParseRejectionKind::ParseError,
                        frame_len: 16,
                        id: Some(i as i64),
                        method: None,
                    }),
                )
                .unwrap();
            }
            // Follow immediately with a malformed IPC packet (wrong version).
            let _ = send_packet(parser_sock.as_fd(), &[99u8; 23], None);
            // Keep socket alive briefly; executor must close IPC_FD and exit
            // promptly even while replies remain unread.
            std::thread::sleep(Duration::from_millis(100));
            drop(parser_sock);
        })
        .await
        .unwrap();

        let res = tokio::time::timeout(Duration::from_secs(3), exec_task)
            .await
            .expect("executor must not deadlock in cleanup join_next")
            .unwrap();
        assert!(
            matches!(res, Err(ExecutorExitError::ProtocolViolation(_))),
            "expected ProtocolViolation, got {res:?}"
        );
    }

    #[tokio::test]
    async fn executor_backpressures_unread_outbox_and_exits_cleanly_on_peer_close() {
        // Codex P1 #1: flooding requests without reading responses must hit
        // outbox backpressure (stopping IPC reads so memory stays bounded) and
        // still detect peer close promptly via writable `EPIPE`.
        let cfg = Config::default();
        let router = Router::new(Box::new(std::io::sink()));
        let ctx = Arc::new(Context::new(
            Arc::new(cfg),
            Arc::new(FreezeStateMachine::new()),
            router,
            Marker::for_tests(),
        ));
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            ctx,
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            true,
            None,
            false,
            std::future::pending(),
            Duration::from_millis(10),
            Duration::from_millis(10),
            Duration::from_millis(50),
        ));

        // Send non-blocking ReportParseRejection packets without ever reading
        // responses until the kernel send buffer fills because the executor
        // paused reading under outbox backpressure.
        let hit_eagain = tokio::task::spawn_blocking(move || {
            let mut saw_eagain = false;
            for i in 1..=2000u64 {
                let pkt = crate::ipc::encode_request_chunks(
                    1,
                    i,
                    &IpcRequest::ReportParseRejection(ParseRejection {
                        kind: ParseRejectionKind::ParseError,
                        frame_len: 12,
                        id: None,
                        method: None,
                    }),
                )
                .unwrap()
                .remove(0);
                match send_packet(parser_sock.as_fd(), &pkt, None) {
                    Ok(()) => {}
                    Err(Errno::EAGAIN) => {
                        saw_eagain = true;
                        break;
                    }
                    Err(err) => panic!("unexpected send error: {err}"),
                }
                if i % 32 == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            // Drop peer while executor outbox is backpressured: writable EPIPE
            // must wake the executor immediately.
            drop(parser_sock);
            saw_eagain
        })
        .await
        .unwrap();

        assert!(
            hit_eagain,
            "parser sends must eventually hit EAGAIN once executor outbox backpressures IPC reads"
        );
        let res = tokio::time::timeout(Duration::from_secs(3), exec_task)
            .await
            .expect("executor must exit promptly on peer close under backpressure")
            .unwrap();
        assert!(
            matches!(res, Err(ExecutorExitError::ParserLost)),
            "expected ParserLost, got {res:?}"
        );
    }

    #[tokio::test]
    async fn executor_audits_capacity_denials_and_enforces_serial_lane_across_concurrent_ipc() {
        // Covers BOTH:
        // 1. Codex P1 #3 (executor-side defense in depth): sending `GetOsInfo`
        //    (Ordinary serial lane) followed immediately by `FsfreezeFreeze`
        //    over raw IPC without waiting MUST serialize the freeze behind the
        //    active serial operation, while `Ping` (Control) runs concurrently.
        // 2. Astra Thread 9: saturating all 8 `op_slots` audits every denied
        //    typed command ONCE with method, host_id, reason, and freeze_state,
        //    preserving disabled-command precedence over capacity rate limit.
        struct GatedOsInfo {
            entered: std::sync::Barrier,
            release: std::sync::Barrier,
        }
        impl crate::handlers::osinfo::OsInfoSource for GatedOsInfo {
            fn uname(&self) -> Result<crate::handlers::osinfo::Uname, crate::proto::Error> {
                self.entered.wait();
                self.release.wait();
                Ok(crate::handlers::osinfo::Uname {
                    release: "6.8.0".to_owned(),
                    version: "#1".to_owned(),
                    machine: "x86_64".to_owned(),
                })
            }
            fn os_release(&self) -> Option<String> {
                Some("ID=linux\n".to_owned())
            }
        }

        let sink = SharedSink::default();
        let router = Router::new(Box::new(sink.clone()));
        let mut cfg = Config::default();
        cfg.features.shutdown = false; // Disabled command for precedence check at capacity.
        let kernel = Arc::new(FakeKernel::new());
        let os_gate = Arc::new(GatedOsInfo {
            entered: std::sync::Barrier::new(2),
            release: std::sync::Barrier::new(2),
        });
        let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                router.clone(),
                Marker::for_tests(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table.to_owned())))
            .with_osinfo(Arc::clone(&os_gate) as Arc<dyn crate::handlers::osinfo::OsInfoSource>),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::INFO,
            router.clone(),
        ));
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let exec_task = tokio::spawn(
            serve_ipc_with_backoff(
                Arc::clone(&ctx),
                exec_sock,
                PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
                opener,
                true,
                None,
                false,
                async move { stop_rx.await.unwrap_or("SIGTERM") },
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(50),
            )
            .with_subscriber(dispatch.clone()),
        );

        let ctx_check = Arc::clone(&ctx);
        let client = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);

            // 1. Start `GetOsInfo` (Ordinary serial lane) and wait until it is
            //    actively running inside the handler.
            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                1,
                Some(100),
                &IpcRequest::GetOsInfo,
            )
            .unwrap();
            os_gate.entered.wait();

            // 2. Immediately send `FsfreezeFreeze` (Freeze) plus 6 more queued
            //    `GetFsInfo` (Ordinary) so all 8 `op_slots` are occupied!
            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                2,
                Some(200),
                &IpcRequest::FsfreezeFreeze,
            )
            .unwrap();
            for req_id in 3..=8u64 {
                crate::ipc::send_request_with_id(
                    parser_sock.as_fd(),
                    1,
                    req_id,
                    Some(200 + req_id as i64),
                    &IpcRequest::GetFsInfo,
                )
                .unwrap();
            }

            // Give the executor a moment to spawn all 8 tasks and confirm that
            // `FsfreezeFreeze` has NOT entered Frozen while `GetOsInfo` is active.
            std::thread::sleep(Duration::from_millis(80));
            assert_eq!(
                ctx_check.state.current(),
                FreezeState::Thawed,
                "freeze must NOT begin while an earlier serial operation (GetOsInfo) is still active"
            );

            // 3. With all 8 `op_slots` saturated:
            //    - enabled `Ping(id=901)` is denied at capacity with RateLimited;
            //    - disabled `Shutdown(id=902)` is denied with Disabled (C-7 precedence).
            // Ensure no concurrent no-subscriber unit test cached `Interest::never()`
            // on the `Disposition::Denied` callsite during the sleep above.
            tracing::callsite::rebuild_interest_cache();
            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                9,
                Some(901),
                &IpcRequest::Ping,
            )
            .unwrap();
            let r_cap = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r_cap.req_id, 9);
            assert_eq!(
                r_cap.response,
                IpcResponse::Err(IpcErrorCode::RateLimited {
                    class: crate::dispatch::ratelimit::CommandClass::PingSync,
                })
            );

            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                10,
                Some(902),
                &IpcRequest::Shutdown {
                    mode: crate::handlers::shutdown::ShutdownMode::Powerdown,
                },
            )
            .unwrap();
            let r_dis = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(r_dis.req_id, 10);
            assert_eq!(
                r_dis.response,
                IpcResponse::Err(IpcErrorCode::Disabled {
                    command: Command::Shutdown,
                })
            );

            // 4. Release the blocked `GetOsInfo`: now req 1 finishes first,
            //    then req 2 (`FsfreezeFreeze`) runs and freezes the guest,
            //    then reqs 3..=8 (`GetFsInfo`) are denied by the freeze gate.
            os_gate.release.wait();

            let mut replies = std::collections::BTreeMap::new();
            for _ in 0..8 {
                let r = recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap();
                replies.insert(r.req_id, r.response);
            }
            assert!(matches!(replies.get(&1), Some(IpcResponse::OkOsInfo(_))));
            assert_eq!(replies.get(&2), Some(&IpcResponse::OkCount(1)));
            for req_id in 3..=8u64 {
                assert_eq!(
                    replies.get(&req_id),
                    Some(&IpcResponse::Err(IpcErrorCode::Frozen))
                );
            }

            // Thaw cleanly before SIGTERM.
            crate::ipc::send_request_with_id(
                parser_sock.as_fd(),
                1,
                11,
                Some(903),
                &IpcRequest::FsfreezeThaw,
            )
            .unwrap();
            assert_eq!(
                recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap()
                    .response,
                IpcResponse::OkCount(1)
            );

            let _ = stop_tx.send("SIGTERM");
            (parser_sock, asm)
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        let (parser_sock, mut asm) = client;
        assert!(
            recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .is_none()
        );
        drop(parser_sock);
        assert!(router.settle(Duration::from_secs(2)));
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = logs.lines().collect();

        let cap_ping_lines: Vec<&&str> = lines
            .iter()
            .filter(|l| {
                l.contains("\"event\":\"command_received\"")
                    && l.contains("\"method\":\"guest-ping\"")
                    && l.contains("\"id\":901")
            })
            .collect();
        assert_eq!(
            cap_ping_lines.len(),
            1,
            "capacity-denied guest-ping must be audited exactly once: {logs}"
        );
        assert!(
            cap_ping_lines[0].contains("\"disposition\":\"denied\"")
                && cap_ping_lines[0].contains("\"reason\":\"rate_limited\"")
                && cap_ping_lines[0].contains("\"freeze_state_before\":\"thawed\""),
            "unexpected capacity denial audit record: {}",
            cap_ping_lines[0]
        );

        let cap_shutdown_lines: Vec<&&str> = lines
            .iter()
            .filter(|l| {
                l.contains("\"event\":\"command_received\"")
                    && l.contains("\"method\":\"guest-shutdown\"")
                    && l.contains("\"id\":902")
            })
            .collect();
        assert_eq!(
            cap_shutdown_lines.len(),
            1,
            "capacity-denied disabled guest-shutdown must be audited exactly once: {logs}"
        );
        assert!(
            cap_shutdown_lines[0].contains("\"disposition\":\"denied\"")
                && cap_shutdown_lines[0].contains("\"reason\":\"disabled\"")
                && cap_shutdown_lines[0].contains("\"freeze_state_before\":\"thawed\""),
            "unexpected disabled capacity denial audit record: {}",
            cap_shutdown_lines[0]
        );
    }

    #[tokio::test]
    async fn executor_abandons_undelivered_outbox_replies_on_stop_when_parser_stops_reading() {
        // Codex P2: when a stop signal is honored in Thawed with all active
        // tasks finished, undelivered replies in a stalled parser's outbox MUST
        // be abandoned rather than blocking graceful exit until systemd kills
        // the unit at TimeoutStopSec (design §5.7).
        let mut cfg = Config::default();
        cfg.rate_limits.ping_sync_per_min = 10_000;
        let router = Router::new(Box::new(std::io::sink()));
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::INFO,
            router.clone(),
        ));
        let ctx = Arc::new(Context::new(
            Arc::new(cfg),
            Arc::new(FreezeStateMachine::new()),
            router,
            Marker::for_tests(),
        ));
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(
            serve_ipc_with_backoff(
                ctx,
                exec_sock,
                PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
                opener,
                true,
                None,
                false,
                async move { stop_rx.await.unwrap_or("SIGTERM") },
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(50),
            )
            .with_subscriber(dispatch),
        );

        // Flood requests without reading ANY response until the executor's
        // outbox backpressures IPC reads (`EAGAIN`), keeping `parser_sock`
        // open the entire time.
        let (parser_sock, hit_eagain) = tokio::task::spawn_blocking(move || {
            let mut saw_eagain = false;
            for i in 1..=2000u64 {
                let chunks = crate::ipc::encode_request_chunks(1, i, &IpcRequest::Ping).unwrap();
                match crate::kernel::ipc::send_packet(parser_sock.as_fd(), &chunks[0], None) {
                    Ok(()) => {}
                    Err(Errno::EAGAIN) => {
                        saw_eagain = true;
                        break;
                    }
                    Err(err) => panic!("unexpected send error: {err}"),
                }
                if i % 32 == 0 {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            (parser_sock, saw_eagain)
        })
        .await
        .unwrap();

        assert!(
            hit_eagain,
            "parser sends must fill executor outbox to backpressure before stop"
        );

        // Request graceful stop while the parser keeps `parser_sock` open and
        // unread: executor MUST abandon undelivered replies and exit Ok(()).
        let _ = stop_tx.send("SIGTERM");
        let res = tokio::time::timeout(Duration::from_secs(2), exec_task)
            .await
            .expect("executor must abandon undelivered IPC replies on SIGTERM while Thawed")
            .unwrap();
        assert!(
            res.is_ok(),
            "expected clean Ok(()) stop while Thawed, got {res:?}"
        );
        drop(parser_sock);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn executor_freeze_followed_by_thaw_burst_never_leaves_guest_frozen() {
        // Astra review: sending `FsfreezeFreeze` immediately followed by
        // `FsfreezeThaw` in a single IPC burst MUST execute in IPC receive
        // order so the thaw joins or follows the freeze instead of racing
        // ahead as a Thawed recovery drain and leaving the guest Frozen.
        let mut cfg = Config::default();
        cfg.rate_limits.fsfreeze_freeze_per_min = 10_000;
        let kernel = Arc::new(FakeKernel::new());
        let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(SharedSink::default())),
                Marker::for_tests(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table.to_owned()))),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
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
            Duration::from_millis(10),
            Duration::from_millis(50),
        ));

        let ctx_check = Arc::clone(&ctx);
        let parser_sock = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            let mut next_req = 1u64;
            for iter in 0..30u64 {
                let freeze_req = next_req;
                let thaw_req = next_req + 1;
                next_req += 2;

                // Queue freeze then thaw back-to-back before reading either reply.
                send_request(parser_sock.as_fd(), 1, freeze_req, &IpcRequest::FsfreezeFreeze)
                    .unwrap();
                send_request(parser_sock.as_fd(), 1, thaw_req, &IpcRequest::FsfreezeThaw).unwrap();

                let r1 = recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap();
                let r2 = recv_response(parser_sock.as_fd(), &mut asm)
                    .unwrap()
                    .unwrap();
                let thaw_resp = if r1.req_id == thaw_req {
                    &r1.response
                } else {
                    &r2.response
                };
                // If thaw aborted an in-flight freeze, wait briefly for the
                // aborted freeze op to settle Thawed.
                if matches!(
                    thaw_resp,
                    IpcResponse::Err(IpcErrorCode::ThawAbortPending { .. })
                ) {
                    let deadline = std::time::Instant::now() + Duration::from_secs(2);
                    while ctx_check.state.current() != FreezeState::Thawed
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                }
                assert_eq!(
                    ctx_check.state.current(),
                    FreezeState::Thawed,
                    "iteration {iter}: guest ended up frozen after freeze+thaw burst (r1={r1:?}, r2={r2:?})"
                );
            }
            let _ = stop_tx.send("SIGTERM");
            parser_sock
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        drop(parser_sock);
    }

    #[tokio::test]
    async fn executor_lane_gate_preserves_receive_order_and_waits_for_freeze_publication() {
        let gate = Arc::new(ExecutorLaneGate::default());
        assert!(gate.register(Kind::Control).is_none());

        // 1. Register Freeze then Thaw in receive order; poll Thaw FIRST.
        //    Thaw must wait while Freeze is still unacquired AND while Freeze
        //    is in `FreezeStage::Starting`, then unblock immediately once
        //    `mark_freeze_published()` runs.
        let freeze_t = gate.register(Kind::Freeze).unwrap();
        let thaw_t = gate.register(Kind::Thaw).unwrap();
        let mut thaw_fut = Box::pin(thaw_t.acquire());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut thaw_fut)
                .await
                .is_err(),
            "Thaw must not acquire before earlier Freeze starts"
        );
        let freeze_guard = freeze_t.acquire().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut thaw_fut)
                .await
                .is_err(),
            "Thaw must wait while earlier Freeze is still in FreezeStage::Starting"
        );
        freeze_guard.mark_freeze_published();
        let thaw_guard = tokio::time::timeout(Duration::from_millis(200), thaw_fut)
            .await
            .expect("Thaw must acquire immediately once Freeze publishes its FreezeOp");
        drop(thaw_guard);

        // 2. While Freeze is still Published, queue Ordinary then Thaw:
        //    Thaw must overtake Ordinary (design §5.7) while Ordinary waits for
        //    both Freeze and Thaw to finish.
        let ord_t = gate.register(Kind::Ordinary).unwrap();
        let thaw2_t = gate.register(Kind::Thaw).unwrap();
        let mut ord_fut = Box::pin(ord_t.acquire());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut ord_fut)
                .await
                .is_err(),
            "Ordinary must wait while Freeze is active"
        );
        let thaw2_guard = tokio::time::timeout(Duration::from_millis(200), thaw2_t.acquire())
            .await
            .expect("Thaw must overtake queued Ordinary while Freeze is Published");
        drop(freeze_guard);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut ord_fut)
                .await
                .is_err(),
            "Ordinary must still wait while Thaw is active"
        );
        drop(thaw2_guard);
        let ord_guard = tokio::time::timeout(Duration::from_millis(200), ord_fut)
            .await
            .expect("Ordinary must acquire once Freeze and Thaw finish");
        drop(ord_guard);

        // 3. Register Ordinary then Freeze while idle; polling Freeze FIRST must
        //    still wait until Ordinary acquires and finishes (or drops).
        let ord2_t = gate.register(Kind::Ordinary).unwrap();
        let freeze2_t = gate.register(Kind::Freeze).unwrap();
        let mut freeze2_fut = Box::pin(freeze2_t.acquire());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut freeze2_fut)
                .await
                .is_err(),
            "Freeze must wait behind earlier Ordinary even when polled first"
        );
        // Dropping an unacquired ticket must unblock successors.
        drop(ord2_t);
        let freeze2_guard = tokio::time::timeout(Duration::from_millis(200), freeze2_fut)
            .await
            .expect("dropping unacquired Ordinary ticket must unblock waiting Freeze");
        drop(freeze2_guard);
    }

    #[tokio::test]
    async fn executor_preserves_completed_terminal_reopen_error_on_graceful_stop() {
        // Astra review: when a reopen worker completes with terminal EBUSY and
        // SIGTERM arrives before `reply_rx.recv()` processes it, the graceful
        // stop drain must preserve `ExecutorExitError::ChannelTerminal` and log
        // `channel_lost` rather than silently returning `Ok(())`.
        let sink = SharedSink::default();
        let router = Router::new(Box::new(sink.clone()));
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::INFO,
            router.clone(),
        ));
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let ctx = Arc::new(Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            Marker::for_tests(),
        ));
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let opener: VerifiedOpenFn = Arc::new(move |p| {
            let _ = entered_tx.send(());
            let _ = release_rx.lock().unwrap().recv();
            Err(OpenError::AlreadyOpen { path: p.to_owned() })
        });

        send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::RequestChannelReopen).unwrap();

        let exec_task = tokio::spawn(
            serve_ipc_with_backoff(
                ctx,
                exec_sock,
                PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
                opener,
                false,
                None,
                false,
                async move { stop_rx.await.unwrap_or("SIGTERM") },
                Duration::from_millis(10),
                Duration::ZERO,
                Duration::ZERO,
            )
            .with_subscriber(dispatch.clone()),
        );

        // Wait until the reopen worker is past its cancelable sleep and inside
        // the blocking opener, send SIGTERM, and wait for the executor's signal
        // audit record so `stop_requested` is guaranteed latched before the
        // reopen worker completes with terminal EBUSY. Dropping `release_tx` on
        // unwind guarantees the blocking opener never hangs Tokio shutdown.
        let sink_check = sink.clone();
        tokio::task::spawn_blocking(move || {
            let release_tx = release_tx;
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("reopen worker did not enter blocking opener");
            let _ = stop_tx.send("SIGTERM");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            loop {
                let so_far = String::from_utf8_lossy(&sink_check.0.lock().unwrap()).into_owned();
                if so_far.contains("\"event\":\"signal\"") {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "executor did not latch SIGTERM before releasing reopen worker: {so_far}"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            let _ = release_tx.send(());
        })
        .await
        .unwrap();

        let res = exec_task.await.unwrap();

        assert!(
            matches!(
                res,
                Err(ExecutorExitError::ChannelTerminal(
                    OpenError::AlreadyOpen { .. }
                ))
            ),
            "expected ChannelTerminal(AlreadyOpen), got {res:?}"
        );
        drop(parser_sock);
        assert!(router.settle(Duration::from_secs(2)));
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("\"event\":\"channel_lost\""),
            "expected channel_lost audit event: {logs}"
        );
    }

    #[tokio::test]
    async fn executor_ipc_thaw_joins_inflight_freeze_and_clears_marker() {
        // Astra review: deterministically gate FIFREEZE in flight, send
        // FsfreezeThaw over IPC to verify ThawAbortPending(InFlightFifreeze),
        // then release the gate and assert the aborted freeze removes the
        // recovery marker and settles Thawed.
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let gate = kernel.script_freeze_gate("/");
        let _release_guard = gate.release_on_drop();
        let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-exec-thaw-join-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker_path = state_dir.path().join("frozen");
        let marker = Marker::open(&marker_path).unwrap();
        let router = Router::new(Box::new(std::io::sink()));
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::INFO,
            router.clone(),
        ));
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                router,
                marker,
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table.to_owned()))),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));

        let exec_task = tokio::spawn(
            serve_ipc_with_backoff(
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
            )
            .with_subscriber(dispatch),
        );

        let ctx_check = Arc::clone(&ctx);
        let marker_check = marker_path.clone();
        let parser_sock = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            // 1. Start freeze; wait until FIFREEZE is blocked at the gate.
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::FsfreezeFreeze).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while gate.waiting() == 0 {
                assert!(
                    std::time::Instant::now() < deadline,
                    "FIFREEZE never reached gate"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert_eq!(ctx_check.state.current(), FreezeState::Freezing);
            assert!(
                marker_check.exists(),
                "recovery marker must exist while FIFREEZE is in flight"
            );

            // 2. Send FsfreezeThaw over IPC while FIFREEZE is in flight:
            //    must join the active FreezeOp and return ThawAbortPending.
            send_request(parser_sock.as_fd(), 1, 2, &IpcRequest::FsfreezeThaw).unwrap();
            let thaw_reply = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(thaw_reply.req_id, 2);
            assert_eq!(
                thaw_reply.response,
                IpcResponse::Err(IpcErrorCode::ThawAbortPending {
                    activity: crate::ipc::AbortActivity::InFlightFifreeze,
                    thawed: 0,
                })
            );

            // 3. Release the blocked FIFREEZE: freeze aborts, drains the late
            //    frozen target, removes the recovery marker, and settles Thawed.
            gate.release();
            let freeze_reply = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(freeze_reply.req_id, 1);
            assert!(
                matches!(
                    freeze_reply.response,
                    IpcResponse::Err(IpcErrorCode::FreezeAborted { .. })
                ),
                "expected FreezeAborted reply, got {:?}",
                freeze_reply.response
            );

            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while ctx_check.state.current() != FreezeState::Thawed
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(ctx_check.state.current(), FreezeState::Thawed);
            assert!(
                !marker_check.exists(),
                "recovery marker must be removed after aborted freeze settles Thawed"
            );

            // 4. Normal freeze -> thaw round-trip verifying real state and marker transitions.
            send_request(parser_sock.as_fd(), 1, 3, &IpcRequest::FsfreezeFreeze).unwrap();
            let fr = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(fr.response, IpcResponse::OkCount(1));
            assert_eq!(ctx_check.state.current(), FreezeState::Frozen);
            assert!(marker_check.exists());

            send_request(parser_sock.as_fd(), 1, 4, &IpcRequest::FsfreezeThaw).unwrap();
            let tr = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(tr.response, IpcResponse::OkCount(1));
            assert_eq!(ctx_check.state.current(), FreezeState::Thawed);
            assert!(!marker_check.exists());

            let _ = stop_tx.send("SIGTERM");
            parser_sock
        })
        .await
        .unwrap();

        exec_task.await.unwrap().unwrap();
        assert_eq!(
            ctx.handler_calls(),
            4,
            "all 4 admitted IPC commands must increment Context::handler_calls"
        );
        drop(parser_sock);
    }

    #[tokio::test]
    async fn executor_denies_new_or_queued_freeze_after_stop_signal_while_frozen() {
        // Codex Security Review P1: when SIGTERM arrives while Frozen, a
        // compromised parser must NOT be able to submit `FsfreezeThaw` followed
        // by `FsfreezeFreeze` (or `FsfreezeFreezeList`) to re-freeze after thaw
        // and carry the freeze past TimeoutStopSec. C-21 frozen-safe status and
        // thaw remain served, while non-frozen-safe commands are permanently
        // denied once stop is requested.
        let sink = SharedSink::default();
        let router = Router::new(Box::new(sink.clone()));
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::INFO,
            router.clone(),
        ));
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();

        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-exec-stop-refreeze-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker_path = state_dir.path().join("frozen");
        let marker = Marker::open(&marker_path).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                router.clone(),
                marker,
            )
            .with_kernel(Arc::clone(&kernel) as Arc<dyn crate::kernel::KernelOps>)
            .with_mounts(Arc::new(StaticMounts(table.to_owned()))),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let stop_fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_fired_sig = Arc::clone(&stop_fired);
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
        let exec_task = tokio::spawn(
            serve_ipc_with_backoff(
                Arc::clone(&ctx),
                exec_sock,
                PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
                opener,
                true,
                None,
                false,
                async move {
                    let sig = stop_rx.await.unwrap_or("SIGTERM");
                    stop_fired_sig.store(true, std::sync::atomic::Ordering::SeqCst);
                    sig
                },
                Duration::from_millis(10),
                Duration::ZERO,
                Duration::ZERO,
            )
            .with_subscriber(dispatch.clone()),
        );

        let parser_sock = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            // 1. Freeze filesystem.
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::FsfreezeFreeze).unwrap();
            let fr = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(fr.response, IpcResponse::OkCount(1));

            // 2. Send SIGTERM while Frozen and wait until the signal future has
            //    resolved and the executor loop has observed it.
            let _ = stop_tx.send("SIGTERM");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !stop_fired.load(std::sync::atomic::Ordering::SeqCst) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "executor did not poll stop signal future"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(50));

            // 3. C-21: status still works while frozen (and proves another
            //    select! iteration completed after SIGTERM was latched).
            send_request(parser_sock.as_fd(), 1, 2, &IpcRequest::FsfreezeStatus).unwrap();
            let st = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                st.response,
                IpcResponse::OkFreezeStatus(crate::ipc::WireFreezeStatus::Frozen)
            );

            // 4. Compromised parser pipelines FsfreezeThaw IMMEDIATELY followed
            //    by FsfreezeFreeze and FsfreezeFreezeList in the same burst.
            send_request(parser_sock.as_fd(), 1, 3, &IpcRequest::FsfreezeThaw).unwrap();
            send_request(parser_sock.as_fd(), 1, 4, &IpcRequest::FsfreezeFreeze).unwrap();
            send_request(
                parser_sock.as_fd(),
                1,
                5,
                &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Omitted),
            )
            .unwrap();

            // Thaw succeeds; any reply to the trailing freeze attempts MUST be
            // an error (or IPC EOF after immediate stop), NEVER OkCount(1)!
            let mut saw_thaw_ok = false;
            loop {
                match recv_response(parser_sock.as_fd(), &mut asm) {
                    Ok(Some(resp)) => match resp.req_id {
                        3 => {
                            assert_eq!(resp.response, IpcResponse::OkCount(1));
                            saw_thaw_ok = true;
                        }
                        4 | 5 => {
                            assert_eq!(
                                resp.response,
                                IpcResponse::Err(IpcErrorCode::Frozen),
                                "re-freeze attempt req_id={} after SIGTERM must be denied, got {:?}",
                                resp.req_id,
                                resp.response
                            );
                        }
                        other => panic!("unexpected req_id {other}: {:?}", resp.response),
                    },
                    Ok(None) => break,
                    Err(err) => panic!("unexpected IPC error: {err}"),
                }
            }
            assert!(saw_thaw_ok, "C-21 thaw reply must be delivered before stop");
            parser_sock
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(3), exec_task)
            .await
            .expect("executor must exit promptly once thaw completes without re-freezing")
            .unwrap()
            .unwrap();
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(
            !marker_path.exists(),
            "marker must remain removed after thaw + stop"
        );
        let freeze_calls = kernel
            .calls()
            .into_iter()
            .filter(|c| matches!(c, crate::kernel::fake::Call::Fifreeze(_)))
            .count();
        assert_eq!(
            freeze_calls, 1,
            "fifreeze must have run only once (never re-frozen after SIGTERM)"
        );
        drop(parser_sock);
    }

    #[tokio::test]
    async fn executor_stops_refreshing_watchdog_heartbeat_after_stop_signal() {
        // Codex Security Review P1: once SIGTERM is latched while Frozen,
        // `FsfreezeStatus` still answers `Frozen` (C-21) but must NOT refresh
        // the idle watchdog, so a compromised parser spamming heartbeats cannot
        // stretch a frozen shutdown past `fsfreeze_idle_timeout_secs`.
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let table = "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n";
        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-exec-stop-hb-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker_path = state_dir.path().join("frozen");
        let marker = Marker::open(&marker_path).unwrap();
        let mut cfg = Config::default();
        cfg.agent.fsfreeze_idle_timeout_secs = 1;
        cfg.agent.fsfreeze_max_timeout_secs = 60;
        let ctx = Arc::new(
            Context::new(
                Arc::new(cfg),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(Arc::clone(&kernel) as Arc<dyn crate::kernel::KernelOps>)
            .with_mounts(Arc::new(StaticMounts(table.to_owned())))
            .with_hooks(Arc::new(crate::handlers::fsfreeze::LifecycleHooks)),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
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
            Duration::ZERO,
            Duration::ZERO,
        ));

        let ctx_check = Arc::clone(&ctx);
        let parser_thread = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::FsfreezeFreeze).unwrap();
            let fr = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(fr.response, IpcResponse::OkCount(1));
            assert_eq!(ctx_check.state.current(), FreezeState::Frozen);

            let _ = stop_tx.send("SIGTERM");

            // Spam FsfreezeStatus heartbeats every 150ms for up to 4s. Without
            // heartbeat suppression on stop, the 1s idle watchdog would never
            // fire during this 4s window (hard cap is 60s).
            let deadline = std::time::Instant::now() + Duration::from_secs(4);
            let mut req_id = 2u64;
            let mut saw_ipc_eof = false;
            while std::time::Instant::now() < deadline {
                if send_request(parser_sock.as_fd(), 1, req_id, &IpcRequest::FsfreezeStatus)
                    .is_err()
                {
                    saw_ipc_eof = true;
                    break;
                }
                req_id += 1;
                match recv_response(parser_sock.as_fd(), &mut asm) {
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => {
                        saw_ipc_eof = true;
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            assert!(
                saw_ipc_eof,
                "idle watchdog must still fire and close IPC despite post-SIGTERM FsfreezeStatus heartbeat spam"
            );
        });

        tokio::time::timeout(Duration::from_secs(6), exec_task)
            .await
            .expect("executor must thaw at idle timeout and exit despite heartbeat spam")
            .unwrap()
            .unwrap();
        parser_thread.await.unwrap();
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert!(!marker_path.exists());
    }

    #[tokio::test]
    async fn executor_queued_duplicate_thaw_after_stop_does_not_start_recovery_drain() {
        // Astra review: when SIGTERM is latched while Frozen and two
        // `FsfreezeThaw` requests are pipelined together, the first thaw
        // settles `Thawed`; the second already-queued thaw MUST return `0`
        // without calling `claim_thaw` from `Thawed`, reading mountinfo, or
        // issuing a fresh `FITHAW` recovery drain during shutdown.
        struct CountingMounts {
            table: String,
            reads: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl crate::mountinfo::MountSource for CountingMounts {
            fn read_mountinfo(&self) -> Result<Vec<u8>, crate::proto::Error> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(self.table.as_bytes().to_vec())
            }
        }

        let mount_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-exec-dup-thaw-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker_path = state_dir.path().join("frozen");
        let marker = Marker::open(&marker_path).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(Arc::clone(&kernel) as Arc<dyn crate::kernel::KernelOps>)
            .with_mounts(Arc::new(CountingMounts {
                table: "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n".to_owned(),
                reads: Arc::clone(&mount_reads),
            })),
        );

        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let stop_fired = Arc::new(AtomicBool::new(false));
        let stop_fired_sig = Arc::clone(&stop_fired);
        let opener: VerifiedOpenFn = Arc::new(|p| Err(OpenError::NotFound { path: p.to_owned() }));
        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            Arc::clone(&ctx),
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            true,
            None,
            false,
            async move {
                let sig = stop_rx.await.unwrap_or("SIGTERM");
                stop_fired_sig.store(true, Ordering::SeqCst);
                sig
            },
            Duration::from_millis(10),
            Duration::ZERO,
            Duration::ZERO,
        ));

        let reads_check = Arc::clone(&mount_reads);
        let parser_sock = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            // 1. Freeze filesystem (1 mountinfo read).
            send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::FsfreezeFreeze).unwrap();
            let fr = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(fr.response, IpcResponse::OkCount(1));
            let reads_after_freeze = reads_check.load(Ordering::SeqCst);
            assert_eq!(reads_after_freeze, 1);

            // 2. Latch SIGTERM while Frozen and confirm C-21 status works.
            let _ = stop_tx.send("SIGTERM");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !stop_fired.load(Ordering::SeqCst) {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(50));
            send_request(parser_sock.as_fd(), 1, 2, &IpcRequest::FsfreezeStatus).unwrap();
            let st = recv_response(parser_sock.as_fd(), &mut asm)
                .unwrap()
                .unwrap();
            assert_eq!(
                st.response,
                IpcResponse::OkFreezeStatus(crate::ipc::WireFreezeStatus::Frozen)
            );

            // 3. Pipeline TWO FsfreezeThaw requests in one burst so req 4 is
            //    already dispatched with a lane ticket behind req 3.
            send_request(parser_sock.as_fd(), 1, 3, &IpcRequest::FsfreezeThaw).unwrap();
            send_request(parser_sock.as_fd(), 1, 4, &IpcRequest::FsfreezeThaw).unwrap();

            let mut saw_first_thaw = false;
            loop {
                match recv_response(parser_sock.as_fd(), &mut asm) {
                    Ok(Some(resp)) => match resp.req_id {
                        3 => {
                            assert_eq!(resp.response, IpcResponse::OkCount(1));
                            saw_first_thaw = true;
                        }
                        4 => {
                            assert_eq!(
                                resp.response,
                                IpcResponse::OkCount(0),
                                "duplicate queued thaw after stop must return 0 without recovery drain"
                            );
                        }
                        other => panic!("unexpected req_id {other}: {:?}", resp.response),
                    },
                    Ok(None) => break,
                    Err(err) => panic!("unexpected IPC error: {err}"),
                }
            }
            assert!(saw_first_thaw, "first thaw reply must arrive");
            parser_sock
        })
        .await
        .unwrap();

        tokio::time::timeout(Duration::from_secs(3), exec_task)
            .await
            .expect("executor must exit cleanly after thaw")
            .unwrap()
            .unwrap();
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        let fithaw_calls = kernel
            .calls()
            .into_iter()
            .filter(|c| matches!(c, crate::kernel::fake::Call::Fithaw(_)))
            .count();
        // One depth-1 tracked thaw performs two `FITHAW` calls (drain -> 0,
        // then terminating `EINVAL`); a fresh recovery drain from queued req 4
        // would add a 3rd `FITHAW` and a 2nd `mountinfo` read.
        assert_eq!(
            fithaw_calls, 2,
            "duplicate queued thaw after stop must NOT issue a fresh recovery FITHAW (saw {fithaw_calls})"
        );
        assert_eq!(
            mount_reads.load(Ordering::SeqCst),
            1,
            "duplicate queued thaw after stop must NOT perform fresh mountinfo discovery"
        );
        drop(parser_sock);
    }

    #[tokio::test]
    async fn executor_discards_successful_reopen_fd_when_stop_latched_in_thawed() {
        // Astra review: if a blocking channel opener is already running when
        // SIGTERM is latched in `Thawed` and subsequently succeeds with an
        // `OwnedFd`, the executor MUST discard that descriptor (never hand it
        // to the parser over `SCM_RIGHTS` in either the normal reply path or
        // the final shutdown flush) and exit `Ok(())`.
        let ctx = Arc::new(Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            Marker::for_tests(),
        ));
        let (exec_sock, parser_sock) = seqpacket_pair(true).unwrap();
        set_blocking(parser_sock.as_fd());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<&'static str>();
        let stop_fired = Arc::new(AtomicBool::new(false));
        let stop_fired_sig = Arc::clone(&stop_fired);

        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let entered_tx = Arc::new(StdMutex::new(Some(entered_tx)));
        let release_rx = Arc::new(StdMutex::new(release_rx));

        let (pipe_r, pipe_w) = nix::unistd::pipe().unwrap();
        let pipe_r_slot = Arc::new(StdMutex::new(Some(pipe_r)));
        let opener: VerifiedOpenFn = Arc::new(move |_| {
            if let Some(tx) = entered_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let _ = release_rx.lock().unwrap().recv();
            Ok(pipe_r_slot
                .lock()
                .unwrap()
                .take()
                .expect("opener called once"))
        });

        send_request(parser_sock.as_fd(), 1, 1, &IpcRequest::RequestChannelReopen).unwrap();

        let exec_task = tokio::spawn(serve_ipc_with_backoff(
            Arc::clone(&ctx),
            exec_sock,
            PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            opener,
            false,
            None,
            false,
            async move {
                let sig = stop_rx.await.unwrap_or("SIGTERM");
                stop_fired_sig.store(true, Ordering::SeqCst);
                sig
            },
            Duration::from_millis(10),
            Duration::ZERO,
            Duration::ZERO,
        ));

        tokio::task::spawn_blocking(move || {
            let release_tx = release_tx;
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("reopen worker did not enter blocking opener");
            let _ = stop_tx.send("SIGTERM");
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while !stop_fired.load(Ordering::SeqCst) {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(2));
            }
            std::thread::sleep(Duration::from_millis(50));
            let _ = release_tx.send(());
        })
        .await
        .unwrap();

        let res = tokio::time::timeout(Duration::from_secs(3), exec_task)
            .await
            .expect("executor must exit cleanly once blocked opener returns")
            .unwrap();
        assert!(res.is_ok(), "expected Ok(()), got {res:?}");

        // Parser MUST NOT receive any SCM_RIGHTS descriptor or OkChannelFd.
        let received = tokio::task::spawn_blocking(move || {
            let mut asm = StreamAssembler::new(PeerRole::Parser);
            let mut responses = Vec::new();
            let mut received_fds = 0usize;
            while let Some(pkt) = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES).unwrap() {
                received_fds += pkt.fds.len();
                if let Some(AssembledMessage::Response(resp)) = asm.push(pkt).unwrap() {
                    responses.push(resp.response);
                }
            }
            (responses, received_fds)
        })
        .await
        .unwrap();
        assert_eq!(
            received.1, 0,
            "executor must NOT hand off any channel fd after stop in Thawed (responses={:?})",
            received.0
        );
        assert!(
            !received
                .0
                .iter()
                .any(|r| matches!(r, IpcResponse::OkChannelFd)),
            "OkChannelFd must never be delivered after stop in Thawed: {:?}",
            received.0
        );
        // The executor must have closed `pipe_r` itself: writing to `pipe_w`
        // must fail with EPIPE (broken pipe).
        assert_eq!(
            nix::unistd::write(&pipe_w, b"x").unwrap_err(),
            Errno::EPIPE,
            "discarded channel OwnedFd must be closed rather than leaked"
        );
    }

    #[tokio::test]
    async fn execute_thaw_existing_ipc_on_settled_thawed_returns_zero_without_discovery_or_fithaw()
    {
        // Astra review: deterministic, scheduling-independent test proving
        // `execute_thaw_existing_ipc` on a settled `Thawed` context returns
        // `Ok(0)` with zero mountinfo discovery and zero `FITHAW` calls, both
        // directly from `Thawed` and immediately after a real freeze+thaw.
        struct CountingMounts {
            table: String,
            reads: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl crate::mountinfo::MountSource for CountingMounts {
            fn read_mountinfo(&self) -> Result<Vec<u8>, crate::proto::Error> {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(self.table.as_bytes().to_vec())
            }
        }

        let mount_reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let kernel = Arc::new(FakeKernel::new());
        kernel.track_freeze_depth();
        let state_dir = tempfile::Builder::new()
            .prefix("qeminga-thaw-existing-")
            .tempdir_in("/dev/shm")
            .unwrap();
        let marker = Marker::open(state_dir.path().join("frozen")).unwrap();
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::new()),
                Router::new(Box::new(std::io::sink())),
                marker,
            )
            .with_kernel(Arc::clone(&kernel) as Arc<dyn crate::kernel::KernelOps>)
            .with_mounts(Arc::new(CountingMounts {
                table: "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n".to_owned(),
                reads: Arc::clone(&mount_reads),
            })),
        );

        // 1. On an already-`Thawed` context, returns `Ok(0)` with zero I/O.
        assert_eq!(fsfreeze::execute_thaw_existing_ipc(&ctx).await, Ok(0));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert_eq!(mount_reads.load(Ordering::SeqCst), 0);
        assert!(kernel.calls().is_empty());

        // 2. Freeze (`1` mount read), thaw via `execute_thaw_existing_ipc`
        //    (`Ok(1)`), then invoke `execute_thaw_existing_ipc` a second time
        //    on the settled `Thawed` context: returns `Ok(0)` with ZERO extra
        //    mountinfo reads and ZERO extra kernel calls.
        assert_eq!(
            fsfreeze::execute_freeze_ipc_with_published(&ctx, None, || {}).await,
            Ok(1)
        );
        assert_eq!(fsfreeze::execute_thaw_existing_ipc(&ctx).await, Ok(1));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        let calls_after_first_thaw = kernel.calls().len();
        let reads_after_first_thaw = mount_reads.load(Ordering::SeqCst);
        assert_eq!(reads_after_first_thaw, 1);

        assert_eq!(fsfreeze::execute_thaw_existing_ipc(&ctx).await, Ok(0));
        assert_eq!(ctx.state.current(), FreezeState::Thawed);
        assert_eq!(
            mount_reads.load(Ordering::SeqCst),
            reads_after_first_thaw,
            "second execute_thaw_existing_ipc must not read mountinfo"
        );
        assert_eq!(
            kernel.calls().len(),
            calls_after_first_thaw,
            "second execute_thaw_existing_ipc must not issue any kernel ioctl"
        );
    }

    #[test]
    fn flush_executor_outbox_drops_queued_fd_and_delivers_terminal_busy_after_thaw() {
        // Astra review: start with a pending `OkChannelFd` queued during the
        // frozen interval followed by `ChannelTerminalBusy`; once stop is
        // requested and `ctx.state` is `Thawed`, `flush_executor_outbox` MUST
        // drop the queued `OwnedFd` (never sending it over `SCM_RIGHTS`) while
        // still delivering `ChannelTerminalBusy` intact.
        let ctx = Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            Marker::for_tests(),
        );
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        let (pipe_r, pipe_w) = nix::unistd::pipe().unwrap();

        let mut outbox = IpcOutbox::new();
        outbox
            .push_response(1, 10, &IpcResponse::OkChannelFd, Some(pipe_r))
            .unwrap();
        outbox
            .push_response(
                1,
                11,
                &IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy),
                None,
            )
            .unwrap();
        assert_eq!(outbox.pending_packets(), 2);

        // Stop requested and state is now `Thawed`: flush must discard the
        // queued fd-bearing packet and deliver only `ChannelTerminalBusy`.
        assert_eq!(
            flush_executor_outbox(&mut outbox, exec_sock.as_fd(), &ctx, true).unwrap(),
            FlushOutcome::Drained
        );
        assert!(outbox.is_empty());
        assert_eq!(outbox.pending_bytes(), 0);
        assert_eq!(
            nix::unistd::write(&pipe_w, b"x").unwrap_err(),
            Errno::EPIPE,
            "queued OkChannelFd descriptor must be closed without transmission"
        );

        drop(exec_sock);
        let mut asm = StreamAssembler::new(PeerRole::Parser);
        let mut replies = Vec::new();
        let mut received_fds = 0usize;
        while let Some(pkt) = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES).unwrap() {
            received_fds += pkt.fds.len();
            if let Some(AssembledMessage::Response(r)) = asm.push(pkt).unwrap() {
                replies.push((r.req_id, r.response));
            }
        }
        assert_eq!(
            received_fds, 0,
            "no SCM_RIGHTS fd may be sent after thaw+stop"
        );
        assert_eq!(
            replies,
            vec![(11, IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy))]
        );
    }
}
