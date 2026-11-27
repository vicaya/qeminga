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
//!    crash/EOF, closes `IPC_FD` immediately, reaps via `wait4(WNOHANG)`, and
//!    **always waits until `FreezeState == Thawed`** (keeping held mount fds,
//!    recovery marker, and watchdog alive) before exiting non-zero so
//!    `PR_SET_PDEATHSIG(SIGKILL)` and systemd `KillMode=control-group` clean up
//!    any uncooperative parser and restart the unit cleanly.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
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

/// Executor-enforced §5.7 lane serialization so neither channel reconnects nor
/// a compromised parser can start a freeze while an earlier serial operation
/// (e.g. `guest-fstrim`) is still active, while still letting `Control` run
/// concurrently and letting `Thaw` overtake queued serial work or join an
/// active `Freeze`.
#[derive(Default)]
struct LaneState {
    freeze_active: bool,
    thaw_or_ordinary_active: bool,
    next_ticket: u64,
    serial_waiters: VecDeque<u64>,
}

#[derive(Default)]
struct ExecutorLaneGate {
    state: StdMutex<LaneState>,
    notify: Notify,
}

impl ExecutorLaneGate {
    async fn acquire(self: &Arc<Self>, kind: Kind) -> Option<ExecutorLaneGuard> {
        match kind {
            Kind::Control => None,
            Kind::Thaw => loop {
                let notified = self.notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    if !st.thaw_or_ordinary_active {
                        st.thaw_or_ordinary_active = true;
                        return Some(ExecutorLaneGuard {
                            gate: Arc::clone(self),
                            kind,
                        });
                    }
                }
                notified.await;
            },
            Kind::Freeze | Kind::Ordinary => {
                let ticket = {
                    let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    st.next_ticket = st.next_ticket.wrapping_add(1);
                    let ticket = st.next_ticket;
                    st.serial_waiters.push_back(ticket);
                    ticket
                };
                let mut cleanup = SerialWaiterCleanup {
                    gate: Arc::clone(self),
                    ticket,
                    active: true,
                };
                loop {
                    let notified = self.notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    {
                        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
                        if st.serial_waiters.front() == Some(&ticket)
                            && !st.freeze_active
                            && !st.thaw_or_ordinary_active
                        {
                            let _ = st.serial_waiters.pop_front();
                            cleanup.active = false;
                            if kind == Kind::Freeze {
                                st.freeze_active = true;
                            } else {
                                st.thaw_or_ordinary_active = true;
                            }
                            return Some(ExecutorLaneGuard {
                                gate: Arc::clone(self),
                                kind,
                            });
                        }
                    }
                    notified.await;
                }
            }
        }
    }
}

struct SerialWaiterCleanup {
    gate: Arc<ExecutorLaneGate>,
    ticket: u64,
    active: bool,
}

impl Drop for SerialWaiterCleanup {
    fn drop(&mut self) {
        if self.active {
            let mut st = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
            st.serial_waiters.retain(|&t| t != self.ticket);
            drop(st);
            self.gate.notify.notify_waiters();
        }
    }
}

struct ExecutorLaneGuard {
    gate: Arc<ExecutorLaneGate>,
    kind: Kind,
}

impl Drop for ExecutorLaneGuard {
    fn drop(&mut self) {
        let mut st = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        match self.kind {
            Kind::Freeze => st.freeze_active = false,
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
    reopen_backoff: tokio::sync::Mutex<ReopenBackoff>,
    reopen_gate: Arc<Semaphore>,
    op_slots: Semaphore,
    lanes: Arc<ExecutorLaneGate>,
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
        reopen_backoff: tokio::sync::Mutex::new(ReopenBackoff::new(
            had_initial_channel,
            initial_backoff,
            max_backoff,
        )),
        reopen_gate: Arc::new(Semaphore::new(1)),
        op_slots: Semaphore::new(MAX_IN_FLIGHT_OPS),
        lanes: Arc::new(ExecutorLaneGate::default()),
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
        // active tasks, stop cleanly.
        if stop_requested {
            if ctx.state.current() == FreezeState::Thawed && tasks.is_empty() && outbox.is_empty() {
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
            match outbox.flush(async_ipc.as_fd()) {
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

        let can_read_ipc = !outbox_backpressured(&outbox);

        tokio::select! {
            name = &mut signal, if signal_pending => {
                signal_pending = false;
                stop_requested = true;
                tracing::info!(event = "signal", signal = name, "stop requested");
                if ctx.state.current() == FreezeState::Thawed {
                    let _ = reopen_cancel_tx.send(true);
                }
            }
            _ = stop_ticker.tick(), if stop_requested => {
                if ctx.state.current() == FreezeState::Thawed {
                    let _ = reopen_cancel_tx.send(true);
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
                    let _ = outbox.flush(async_ipc.as_fd());
                    break Err(ExecutorExitError::ChannelTerminal(term_err));
                }
                if let Err(err) = push_checked_response(
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
                        match outbox.flush(async_ipc.as_fd()) {
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
                            if outbox_backpressured(&outbox) {
                                break;
                            }
                            match recv_packet(async_ipc.as_fd(), MAX_PACKET_BYTES) {
                                Ok(Some(pkt)) => match assembler.push(pkt) {
                                    Ok(Some(AssembledMessage::Request(req))) => {
                                        if stop_requested && ctx.state.current() == FreezeState::Thawed {
                                            // Stop already accepted while Thawed: do not start new work.
                                            continue;
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
                                            && let Err(err) = outbox.flush(async_ipc.as_fd())
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

    tasks.spawn(
        async move {
            let _permit = permit;
            {
                let mut backoff = state.reopen_backoff.lock().await;
                backoff.note_command();
            }
            let response = execute_command_request(&state, host_id, request).await;
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
    } else if state.ctx.state.is_frozen_for_gate() && !cmd.is_frozen_safe() {
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
    let (sleep_dur, was_open) = {
        let mut backoff = state.reopen_backoff.lock().await;
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
            _ = cancel.changed() => {
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

    let path = state.channel_path.clone();
    let opener = Arc::clone(&state.channel_opener);
    let opened = tokio::task::spawn_blocking(move || opener(&path)).await;
    match opened {
        Ok(Ok(fd)) => {
            {
                let mut backoff = state.reopen_backoff.lock().await;
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
) -> IpcResponse {
    let Some(cmd) = command_of_request(&req) else {
        return IpcResponse::OkAck;
    };
    let _lane_guard = state.lanes.acquire(cmd.lane()).await;
    if let Err(code) = admit_command(state, cmd, host_id) {
        return IpcResponse::Err(code);
    }
    state.ctx.record_handler_call();
    let ctx = &state.ctx;
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
            IpcResponse::OkFreezeStatus(fsfreeze::execute_status_ipc(ctx))
        }
        IpcRequest::FsfreezeFreeze => match fsfreeze::execute_freeze_ipc(ctx, None).await {
            Ok(n) => IpcResponse::OkCount(n),
            Err(code) => IpcResponse::Err(code),
        },
        IpcRequest::FsfreezeFreezeList(selection) => {
            let restrict = match selection {
                FreezeListSelection::Omitted => None,
                FreezeListSelection::Present(list) => Some(list),
            };
            match fsfreeze::execute_freeze_ipc(ctx, restrict).await {
                Ok(n) => IpcResponse::OkCount(n),
                Err(code) => IpcResponse::Err(code),
            }
        }
        IpcRequest::FsfreezeThaw => match fsfreeze::execute_thaw_ipc(ctx).await {
            Ok(n) => IpcResponse::OkCount(n),
            Err(code) => IpcResponse::Err(code),
        },
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
            .with_subscriber(dispatch),
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
        let subscriber = audit::subscriber(tracing::Level::DEBUG, router.clone());

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
            .with_subscriber(subscriber),
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
            .with_subscriber(dispatch),
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
}
