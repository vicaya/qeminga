//! The virtio-serial channel: open, session loop, EOF/HUP reconnect
//! (design §4.1 I/O layer, §5.7 reconnect rules, §8.4 `EBUSY` is
//! terminal; AC18; C-15).
//!
//! [`Channel`] wraps the device descriptor in a Tokio [`AsyncFd`] and
//! implements `AsyncRead`/`AsyncWrite`. [`run_session`] reads frames,
//! hands each decoder event to a [`Handle`] (the dispatcher) and writes
//! the replies back in order; it ends on EOF/HUP or an I/O error.
//! [`serve`] wraps that in the reopen loop: a fresh decoder per session,
//! never any change to the freeze state, the watchdog, the marker or the
//! audit mode (those live in the shared context, untouched here).
//!
//! Opening the channel maps `EBUSY` to the terminal
//! [`OpenError::AlreadyOpen`] (§8.4) and retries `ENOENT` (device not
//! yet present) with a bounded exponential backoff: 1 s, 2 s, 4 s, ...
//! capped at [`MAX_BACKOFF`], forever, until cancelled.
//!
//! The same backoff separates sessions: a virtio port whose host side is
//! disconnected opens successfully and reports EOF at once, so reopening
//! immediately would spin. After a session that received nothing the
//! delay doubles up to [`MAX_BACKOFF`]; a session that carried data
//! resets it to [`INITIAL_BACKOFF`].
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::dispatch::Dispatcher;
use crate::framing::{DecodeEvent, FrameDecoder};
use crate::state::FreezeState;

/// First delay of the open-retry and reopen backoff.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Upper bound of the reopen backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Read chunk size for the session loop.
const READ_CHUNK: usize = 4096;

/// Why the channel could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// Another process holds the single-open device (`EBUSY`): terminal,
    /// reported as `channel_already_open` (§8.4).
    #[error("channel_already_open: {path} is held by another process")]
    AlreadyOpen {
        /// The device path.
        path: PathBuf,
    },
    /// The device does not exist yet (`ENOENT`): retried with backoff.
    #[error("channel {path} not found")]
    NotFound {
        /// The device path.
        path: PathBuf,
    },
    /// Any other error: retried with backoff.
    #[error("cannot open channel {path}: {source}")]
    Io {
        /// The device path.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

impl OpenError {
    /// Classifies an `open(2)` failure for `path`.
    pub fn from_io(path: &Path, source: io::Error) -> Self {
        match source.raw_os_error().map(Errno::from_raw) {
            Some(Errno::EBUSY) => OpenError::AlreadyOpen {
                path: path.to_owned(),
            },
            Some(Errno::ENOENT) => OpenError::NotFound {
                path: path.to_owned(),
            },
            _ => OpenError::Io {
                path: path.to_owned(),
                source,
            },
        }
    }

    /// `true` for [`OpenError::AlreadyOpen`], which must not be retried.
    pub fn is_terminal(&self) -> bool {
        matches!(self, OpenError::AlreadyOpen { .. })
    }
}

/// How a descriptor for the channel path is obtained; production uses
/// [`open_device`], tests inject failures and pty descriptors.
pub type OpenFn = Arc<dyn Fn(&Path) -> io::Result<OwnedFd> + Send + Sync>;

/// `open(2)` with `O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`.
pub fn open_device(path: &Path) -> io::Result<OwnedFd> {
    let flags = OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    open(path, flags, Mode::empty()).map_err(io::Error::from)
}

/// The channel descriptor registered with the Tokio reactor.
#[derive(Debug)]
pub struct Channel {
    fd: AsyncFd<OwnedFd>,
}

impl Channel {
    /// Opens `path` with [`open_device`].
    pub fn open(path: &Path) -> Result<Channel, OpenError> {
        Self::open_with(path, &open_device)
    }

    /// Opens `path` through `open` and registers the descriptor.
    pub fn open_with(
        path: &Path,
        open: &(dyn Fn(&Path) -> io::Result<OwnedFd> + Send + Sync),
    ) -> Result<Channel, OpenError> {
        let fd = open(path).map_err(|err| OpenError::from_io(path, err))?;
        Channel::from_fd(fd).map_err(|err| OpenError::from_io(path, err))
    }

    /// Wraps an already open descriptor, switching it to non-blocking
    /// mode. Must be called within a Tokio runtime.
    pub fn from_fd(fd: OwnedFd) -> io::Result<Channel> {
        let flags = nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_GETFL)?;
        let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
        nix::fcntl::fcntl(fd.as_fd(), nix::fcntl::FcntlArg::F_SETFL(flags))?;
        Ok(Channel {
            fd: AsyncFd::new(fd)?,
        })
    }

    /// The raw descriptor (diagnostics only).
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }
}

impl AsyncRead for Channel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| {
                nix::unistd::read(inner.get_ref(), unfilled).map_err(io::Error::from)
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Channel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard
                .try_io(|inner| nix::unistd::write(inner.get_ref(), data).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// What the session hands decoder events to. Implemented by the
/// [`Dispatcher`]; tests use fakes.
pub trait Handle: Send + Sync {
    /// Handles one event and returns the encoded reply, if any.
    fn handle(&self, event: DecodeEvent) -> impl Future<Output = Option<Vec<u8>>> + Send;

    /// `true` when a requested stop may take effect now. The daemon answers
    /// `false` while the state is not `Thawed` (C-21), so a stop that
    /// arrives while a command is mid-freeze is deferred until the thaw.
    fn may_stop(&self) -> bool {
        true
    }

    /// The lane `event` runs in (§5.7), decided before it is started;
    /// must have no side effects. Everything is serial unless overridden.
    fn classify(&self, event: &DecodeEvent) -> Kind {
        let _ = event;
        Kind::Ordinary
    }
}

impl Handle for Dispatcher {
    fn handle(&self, event: DecodeEvent) -> impl Future<Output = Option<Vec<u8>>> + Send {
        Dispatcher::handle(self, event)
    }

    fn may_stop(&self) -> bool {
        self.context().state.current() == FreezeState::Thawed
    }

    fn classify(&self, event: &DecodeEvent) -> Kind {
        Dispatcher::classify(self, event)
    }
}

/// Why a session ended.
#[derive(Debug)]
pub enum SessionEnd {
    /// A requested stop took effect once no command was running (see
    /// [`run_session_until`]).
    Cancelled,
    /// The peer closed the channel (read returned 0, or HUP).
    Eof,
    /// A read failed.
    ReadError(io::Error),
    /// A write failed.
    WriteError(io::Error),
}

impl std::fmt::Display for SessionEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionEnd::Eof => f.write_str("eof"),
            SessionEnd::Cancelled => f.write_str("cancelled"),
            SessionEnd::ReadError(err) => write!(f, "read error: {err}"),
            SessionEnd::WriteError(err) => write!(f, "write error: {err}"),
        }
    }
}

/// Runs one session: reads bytes, decodes frames, dispatches, writes
/// replies in order. Returns when the peer goes away or I/O fails; the
/// `decoder` is left in whatever state the stream reached (callers make a
/// fresh one per session).
pub async fn run_session<R, W, H>(
    reader: R,
    writer: W,
    handler: &H,
    decoder: &mut FrameDecoder,
) -> SessionReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handle,
{
    // A cancellation source that never fires (the sender stays alive).
    let (_never_sent, mut never) = cancel_pair();
    run_session_until(reader, writer, handler, decoder, &mut never).await
}

/// The lane a frame runs in (design §5.7). The session serialises every
/// command that may change the guest, and only lets the host's
/// frozen-safe controls (and a thaw aimed at a freeze under way) run
/// beside the one command in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A read-only, frozen-safe control (`guest-fsfreeze-status`,
    /// `guest-ping`, `guest-sync`, `guest-sync-delimited`, `guest-info`)
    /// or a frame that is answered without running anything (unparseable,
    /// oversized): runs beside any command, up to [`MAX_CONTROLS`] at once.
    Control,
    /// `guest-fsfreeze-thaw`: runs beside a [`Kind::Freeze`] in progress
    /// (to abort it), otherwise in the serial lane.
    Thaw,
    /// `guest-fsfreeze-freeze` and `-freeze-list`: the serial lane.
    Freeze,
    /// Everything else (trim, shutdown, suspend, the walks, unknown
    /// methods): the serial lane.
    Ordinary,
}

/// Frozen-safe controls the session handles beside the command in
/// progress. A reply that is pending (a freeze whose walk is under way,
/// a recovery drain that is blocked) must not stop the host's controls
/// from being answered; they are read-only, so they overlap nothing.
pub const MAX_CONTROLS: usize = 3;

/// Commands the session holds at once: running, or finished with the
/// reply waiting behind an earlier one. The channel is not read while
/// this many are held, so nothing queues without limit; one read's worth
/// of frames may be decoded beyond it.
///
/// This bounds the host's interruption of a freeze: a
/// `guest-fsfreeze-thaw` sent behind a pending freeze reply is read, and
/// aborts the walk, as long as fewer than this many commands are
/// unanswered. A host that sends `MAX_QUEUED - 1` further commands
/// without reading a reply has its next frame read only once the freeze
/// reply is out: at the latest at the operation deadline (§4.4).
pub const MAX_QUEUED: usize = 8;

/// A command the session holds, in request order: running, or finished
/// with its reply not yet written.
enum Slot<'a> {
    Pending(
        Kind,
        Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>,
    ),
    Done(Option<Vec<u8>>),
}

/// Polls every running command and resolves once any of them finished
/// (its slot is then `Done`).
fn drive_any<'a, 'b>(slots: &'b mut VecDeque<Slot<'a>>) -> impl Future<Output = ()> + 'b {
    std::future::poll_fn(move |cx| {
        let mut finished = false;
        for slot in slots.iter_mut() {
            if let Slot::Pending(_, fut) = slot
                && let Poll::Ready(reply) = fut.as_mut().poll(cx)
            {
                *slot = Slot::Done(reply);
                finished = true;
            }
        }
        if finished {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
}

/// Whether the frame at the head of the wait queue may start now, given
/// the commands running (§5.7). Admission is in request order: a frame
/// whose lane is busy holds every frame behind it, so side effects happen
/// in the order the host asked for them; only a control or an aborting
/// thaw ever runs beside another command.
fn admits(slots: &VecDeque<Slot<'_>>, kind: Kind) -> bool {
    let running = slots.iter().filter_map(|slot| match slot {
        Slot::Pending(kind, _) => Some(*kind),
        Slot::Done(_) => None,
    });
    match kind {
        Kind::Control => running.filter(|k| *k == Kind::Control).count() < MAX_CONTROLS,
        Kind::Thaw => !running
            .clone()
            .any(|k| matches!(k, Kind::Thaw | Kind::Ordinary)),
        Kind::Freeze | Kind::Ordinary => !running
            .clone()
            .any(|k| matches!(k, Kind::Thaw | Kind::Freeze | Kind::Ordinary)),
    }
}

/// The one writer's queue: reply bytes in request order and how many of
/// them the host has accepted. Kept across loop iterations so a write
/// the host is slow to accept resumes where it stopped, while the loop
/// keeps polling the commands and the stop; it is never restarted, so
/// no reply is ever appended to a partial frame except the rest of that
/// frame.
struct Outbox {
    bytes: Vec<u8>,
    written: usize,
}

impl Outbox {
    fn new() -> Self {
        Outbox {
            bytes: Vec::new(),
            written: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.written == self.bytes.len()
    }

    fn push(&mut self, reply: &[u8]) {
        if self.is_empty() {
            self.bytes.clear();
            self.written = 0;
        }
        self.bytes.extend_from_slice(reply);
    }

    /// Drops whatever the host has not accepted.
    fn abandon(&mut self) {
        self.bytes.clear();
        self.written = 0;
    }

    /// Writes and flushes the queued bytes; resolves once the host has
    /// accepted all of them, or with the write error.
    fn drain<'a, W>(&'a mut self, writer: &'a mut W) -> impl Future<Output = io::Result<()>> + 'a
    where
        W: AsyncWrite + Unpin,
    {
        std::future::poll_fn(move |cx| {
            while self.written < self.bytes.len() {
                let n = ready!(Pin::new(&mut *writer).poll_write(cx, &self.bytes[self.written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.written += n;
            }
            ready!(Pin::new(&mut *writer).poll_flush(cx))?;
            self.bytes.clear();
            self.written = 0;
            Poll::Ready(Ok(()))
        })
    }
}

/// [`run_session`] that also ends with [`SessionEnd::Cancelled`] once
/// `cancel` is `true` **and** `handler.may_stop()` holds.
///
/// Three concerns are kept apart (§5.7):
///
/// * **Admission.** Frames start in request order, each when its lane
///   is free ([`Kind`], `admits`): one command that may change the
///   guest at a time, the frozen-safe controls (up to [`MAX_CONTROLS`])
///   and a thaw aimed at a freeze under way beside it. At most
///   [`MAX_QUEUED`] commands are held; the channel is not read while
///   that many are.
/// * **Completion.** Every command that started is polled until it
///   finishes, whatever the writer or the stop are doing: a command is
///   never dropped mid-way (a freeze abandoned at its `.await` would
///   leave the filesystems frozen with the state stuck in `Freezing`,
///   contrary to C-21/§5.7), and a handler's continuation after its
///   kernel work (publishing `Thawed`, finalising the audit) never waits
///   for the host to read an earlier reply.
/// * **Delivery.** Replies go out through one `Outbox` strictly in
///   request order, whatever order the commands finish in: the wire
///   keeps the correlation a host relies on for requests without an
///   `id`, and a `guest-sync-delimited` reply follows every earlier
///   reply, which the host discards up to the sentinel. A write the host
///   is slow to accept is resumed, never restarted, and stalls nothing
///   but the replies behind it.
///
/// A stop the handler allows (`Thawed`) enters a draining state: nothing
/// more is read or started, the commands running are finished, and the
/// session then ends, abandoning a reply the host is not accepting (C-21
/// protects the command, not the delivery: a host that keeps the port
/// open but stops reading must not hold the agent's shutdown). If a
/// command that was running froze the guest meanwhile the stop is
/// withdrawn and the session serves on, so the host can thaw; the
/// daemon's stopper repeats the request once the state is `Thawed`. A
/// stop the handler does not allow is re-checked on every later
/// notification and whenever a command finishes.
///
/// When the peer goes away or a read fails, the commands received are
/// still handled and finished (their side effects are complete before
/// the session ends; the replies are written on a best-effort basis) and
/// only then does the session end.
pub async fn run_session_until<R, W, H>(
    mut reader: R,
    mut writer: W,
    handler: &H,
    decoder: &mut FrameDecoder,
    cancel: &mut Cancel,
) -> SessionReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handle,
{
    let mut buf = vec![0u8; READ_CHUNK];
    let mut received: u64 = 0;
    // Once the sender is gone there is nothing left to wait for.
    let mut cancel_live = true;
    let report = |end, received| SessionReport { end, received };
    let mut slots: VecDeque<Slot<'_>> = VecDeque::new();
    // Frames decoded but not started yet (their lane was busy, or the
    // bound was reached); at most one read's worth beyond the bound,
    // since nothing is read meanwhile.
    let mut waiting: VecDeque<DecodeEvent> = VecDeque::new();
    let mut outbox = Outbox::new();
    // The input ended: finish what was received, then report why.
    let mut input_end: Option<SessionEnd> = None;
    // The writer failed: the peer is gone, no reply is delivered any more.
    let mut write_failed = false;
    // A stop was accepted: finish the commands running, start nothing.
    let mut draining = false;
    loop {
        // Replies leave in request order, as soon as the one before them
        // has finished.
        while let Some(Slot::Done(_)) = slots.front() {
            if let Some(Slot::Done(Some(reply))) = slots.pop_front()
                && !write_failed
            {
                outbox.push(&reply);
            }
        }
        let running = slots.iter().any(|slot| matches!(slot, Slot::Pending(..)));
        if !draining && !running && *cancel.borrow_and_update() && handler.may_stop() {
            draining = true;
        }
        if draining && !running {
            if handler.may_stop() {
                // A reply the host accepts right now still goes out; one
                // the host is not accepting is abandoned.
                if !outbox.is_empty() && !write_failed {
                    tokio::select! {
                        biased;
                        _ = outbox.drain(&mut writer) => {}
                        () = std::future::ready(()) => {}
                    }
                }
                return report(SessionEnd::Cancelled, received);
            }
            // A command that was running froze the guest: the stop is
            // withdrawn until the thaw (C-21).
            draining = false;
        }
        if !draining {
            while let Some(event) = waiting.front() {
                let kind = handler.classify(event);
                if !admits(&slots, kind) {
                    break;
                }
                if let Some(event) = waiting.pop_front() {
                    slots.push_back(Slot::Pending(kind, Box::pin(handler.handle(event))));
                }
            }
        }
        let running = slots.iter().any(|slot| matches!(slot, Slot::Pending(..)));
        if !running
            && slots.is_empty()
            && waiting.is_empty()
            && (outbox.is_empty() || write_failed)
            && let Some(end) = input_end.take()
        {
            return report(end, received);
        }
        let can_read =
            input_end.is_none() && !draining && waiting.is_empty() && slots.len() < MAX_QUEUED;
        let can_write = !outbox.is_empty() && !write_failed;
        tokio::select! {
            biased;
            changed = cancel.changed(), if cancel_live => {
                cancel_live = changed.is_ok();
                if !draining && stop_now(cancel, handler) {
                    draining = true;
                }
            }
            () = drive_any(&mut slots), if running => {}
            written = outbox.drain(&mut writer), if can_write => {
                if let Err(err) = written {
                    // The peer is gone; finish the commands received
                    // (nothing more is read), then report the write.
                    write_failed = true;
                    outbox.abandon();
                    input_end.get_or_insert(SessionEnd::WriteError(err));
                }
            }
            read = reader.read(&mut buf), if can_read => match read {
                Ok(0) => input_end = Some(SessionEnd::Eof),
                Ok(n) => {
                    received += n as u64;
                    waiting.extend(decoder.push(&buf[..n]));
                }
                Err(err) => input_end = Some(SessionEnd::ReadError(err)),
            },
            else => {
                // Nothing running, nothing to write, nothing to read and
                // no cancellation to wait for: the input has ended.
                return report(input_end.take().unwrap_or(SessionEnd::Eof), received);
            }
        }
    }
}

/// How a session ended and how much it read; [`serve`] uses the byte
/// count to decide whether the next reopen backs off.
#[derive(Debug)]
pub struct SessionReport {
    /// Why the session ended.
    pub end: SessionEnd,
    /// Bytes read from the channel during the session.
    pub received: u64,
}

/// A cancellation signal for [`serve`]: `true` once cancelled.
pub type Cancel = watch::Receiver<bool>;

/// Creates a cancellation pair.
pub fn cancel_pair() -> (watch::Sender<bool>, Cancel) {
    watch::channel(false)
}

/// Opens the channel, retrying non-terminal failures with bounded
/// exponential backoff until it succeeds or `cancel` fires. Returns
/// `Ok(None)` when cancelled.
pub async fn open_with_retry(
    path: &Path,
    open: &OpenFn,
    cancel: &mut Cancel,
) -> Result<Option<Channel>, OpenError> {
    let mut delay = INITIAL_BACKOFF;
    loop {
        match Channel::open_with(path, open.as_ref()) {
            Ok(channel) => return Ok(Some(channel)),
            Err(err) if err.is_terminal() => return Err(err),
            Err(err) => {
                tracing::warn!(event = "channel_open_retry", error = %err, delay_secs = delay.as_secs(), "cannot open channel; retrying");
            }
        }
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    return Ok(None);
                }
            }
        }
        if *cancel.borrow() {
            return Ok(None);
        }
        delay = (delay * 2).min(MAX_BACKOFF);
    }
}

/// The daemon's channel loop: open (with retry), run a session with a
/// fresh decoder, and on EOF/HUP or an I/O error reopen. Ends with
/// `Ok(())` when `cancel` fires between sessions, or with the terminal
/// [`OpenError::AlreadyOpen`].
pub async fn serve<H: Handle>(
    path: &Path,
    open: OpenFn,
    handler: &H,
    cancel: Cancel,
) -> Result<(), OpenError> {
    serve_inner(path, open, handler, cancel, None, Backoff::default()).await
}

/// Bounds of the pause between sessions (§5.7); production uses
/// [`INITIAL_BACKOFF`] and [`MAX_BACKOFF`], tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// The pause after a session that carried data, and the first pause.
    pub initial: Duration,
    /// The longest pause after repeated sessions that received nothing.
    pub max: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff {
            initial: INITIAL_BACKOFF,
            max: MAX_BACKOFF,
        }
    }
}

/// [`serve`] with explicit reopen backoff bounds.
pub async fn serve_with_backoff<H: Handle>(
    path: &Path,
    open: OpenFn,
    handler: &H,
    cancel: Cancel,
    backoff: Backoff,
) -> Result<(), OpenError> {
    serve_inner(path, open, handler, cancel, None, backoff).await
}

/// [`serve`] whose first session uses an already open descriptor (the one
/// `main` opened before dropping privileges, §5.4 step 1); later sessions
/// reopen through `open`.
pub async fn serve_with_initial<H: Handle>(
    path: &Path,
    open: OpenFn,
    handler: &H,
    cancel: Cancel,
    initial: Option<OwnedFd>,
) -> Result<(), OpenError> {
    serve_inner(path, open, handler, cancel, initial, Backoff::default()).await
}

async fn serve_inner<H: Handle>(
    path: &Path,
    open: OpenFn,
    handler: &H,
    mut cancel: Cancel,
    initial: Option<OwnedFd>,
    backoff: Backoff,
) -> Result<(), OpenError> {
    let mut initial = initial;
    // Zero before the first open; afterwards the pause before each reopen.
    let mut reopen_delay = Duration::ZERO;
    let mut cancel_live = true;
    loop {
        if stop_now(&mut cancel, handler) {
            return Ok(());
        }
        if !reopen_delay.is_zero() {
            tokio::select! {
                () = tokio::time::sleep(reopen_delay) => {}
                changed = cancel.changed(), if cancel_live => {
                    cancel_live = changed.is_ok();
                    if stop_now(&mut cancel, handler) {
                        return Ok(());
                    }
                    // Not allowed to stop yet (C-21): keep serving.
                }
            }
        }
        let channel = match initial.take() {
            Some(fd) => match Channel::from_fd(fd) {
                Ok(channel) => channel,
                Err(err) => {
                    tracing::warn!(event = "channel_register_failed", error = %err, "cannot register the initial channel; reopening");
                    continue;
                }
            },
            None => {
                let Some(channel) = open_with_retry(path, &open, &mut cancel).await? else {
                    if handler.may_stop() {
                        return Ok(());
                    }
                    // Stop requested but not allowed yet (C-21): keep
                    // trying to reopen at a bounded cadence.
                    tokio::time::sleep(backoff.initial).await;
                    continue;
                };
                channel
            }
        };
        tracing::info!(event = "channel_open", path = %path.display(), "channel open");
        let (reader, writer) = tokio::io::split(channel);
        let mut decoder = FrameDecoder::new();
        let report = run_session_until(reader, writer, handler, &mut decoder, &mut cancel).await;
        if matches!(report.end, SessionEnd::Cancelled) {
            return Ok(());
        }
        // A session that carried data resets the backoff; a host-disconnected
        // port reports EOF immediately and must not be reopened in a loop.
        reopen_delay = if report.received > 0 {
            backoff.initial
        } else {
            (reopen_delay * 2).clamp(backoff.initial, backoff.max)
        };
        tracing::warn!(
            event = "channel_closed",
            reason = %report.end,
            received = report.received,
            reopen_in_ms = reopen_delay.as_millis() as u64,
            "channel session ended; reopening"
        );
    }
}

/// `true` when a stop has been requested and the handler allows it now.
fn stop_now<H: Handle>(cancel: &mut Cancel, handler: &H) -> bool {
    *cancel.borrow_and_update() && handler.may_stop()
}

/// Production entry point: serve `path` with the real `open(2)`.
pub async fn serve_device(
    path: &Path,
    dispatcher: &Dispatcher,
    cancel: Cancel,
) -> Result<(), OpenError> {
    serve(path, Arc::new(open_device), dispatcher, cancel).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{FreezeState, FreezeStateMachine};
    use std::sync::Mutex;

    /// Runs a session test under a real-time bound. A decoder or session
    /// that never replies then fails this test alone instead of hanging
    /// the test binary until cargo-mutants kills it: a mutant that breaks
    /// framing is caught, not timed out (T5.6).
    async fn bounded<T>(test: impl Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(10), test)
            .await
            .expect("session test hung: no reply within 10 s")
    }
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncWriteExt, duplex};

    /// Echoes each frame's bytes back, uppercased, as its reply; `None`
    /// for frames starting with `shutdown`; records oversized events.
    #[derive(Default)]
    struct FakeDispatcher {
        seen: Mutex<Vec<DecodeEvent>>,
    }

    impl Handle for FakeDispatcher {
        async fn handle(&self, event: DecodeEvent) -> Option<Vec<u8>> {
            self.seen.lock().unwrap().push(event.clone());
            match event {
                DecodeEvent::Frame { bytes, sentinel } => {
                    if bytes.starts_with(b"shutdown") {
                        return None;
                    }
                    let mut reply = if sentinel { vec![0xFF] } else { Vec::new() };
                    reply.extend(bytes.to_ascii_uppercase());
                    reply.push(b'\n');
                    Some(reply)
                }
                DecodeEvent::Oversized { .. } => None,
            }
        }
    }

    #[tokio::test]
    async fn session_reads_frames_dispatches_and_writes_replies() {
        bounded(async {
            let (mut peer, ours) = duplex(1024);
            let (reader, writer) = tokio::io::split(ours);
            let handler = FakeDispatcher::default();
            let session = tokio::spawn(async move {
                let mut decoder = FrameDecoder::new();
                let handler = handler;
                let end = run_session(reader, writer, &handler, &mut decoder)
                    .await
                    .end;
                (end, handler)
            });
            peer.write_all(b"one\ntwo\nthr").await.unwrap();
            peer.write_all(b"ee\n\xFFfour\n").await.unwrap();
            let mut out = vec![0u8; 64];
            let mut got = Vec::new();
            while got.len() < b"ONE\nTWO\nTHREE\n\xFFFOUR\n".len() {
                let n = peer.read(&mut out).await.unwrap();
                got.extend_from_slice(&out[..n]);
            }
            assert_eq!(got, b"ONE\nTWO\nTHREE\n\xFFFOUR\n");
            drop(peer);
            let (end, handler) = session.await.unwrap();
            assert!(matches!(end, SessionEnd::Eof), "{end}");
            assert_eq!(handler.seen.lock().unwrap().len(), 4);
        })
        .await;
    }

    /// A handler that blocks inside `handle` until released and reports
    /// whether it allows a stop; models a command that is mid-freeze.
    struct SlowHandler {
        started: tokio::sync::Notify,
        release: tokio::sync::Notify,
        allow_stop: std::sync::atomic::AtomicBool,
        finished: std::sync::atomic::AtomicBool,
    }

    impl Handle for SlowHandler {
        async fn handle(&self, _event: DecodeEvent) -> Option<Vec<u8>> {
            self.started.notify_one();
            self.release.notified().await;
            self.finished
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Some(b"done\n".to_vec())
        }
        fn may_stop(&self) -> bool {
            self.allow_stop.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn cancel_finishes_the_in_flight_command_and_waits_for_may_stop() {
        bounded(async {
            use std::sync::atomic::Ordering;
            let (mut peer, ours) = duplex(1024);
            let (reader, writer) = tokio::io::split(ours);
            let handler = Arc::new(SlowHandler {
                started: tokio::sync::Notify::new(),
                release: tokio::sync::Notify::new(),
                allow_stop: std::sync::atomic::AtomicBool::new(false),
                finished: std::sync::atomic::AtomicBool::new(false),
            });
            let (cancel_tx, mut cancel_rx) = cancel_pair();
            let h = handler.clone();
            let session = tokio::spawn(async move {
                let mut decoder = FrameDecoder::new();
                run_session_until(reader, writer, h.as_ref(), &mut decoder, &mut cancel_rx).await
            });
            peer.write_all(b"freeze\n").await.unwrap();
            handler.started.notified().await;
            // The stop arrives while the command is being handled: the
            // command must complete (its reply is written) and, because the
            // handler does not allow a stop yet, the session must go on.
            cancel_tx.send(true).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!handler.finished.load(Ordering::SeqCst));
            assert!(!session.is_finished(), "handler still running");
            handler.release.notify_one();
            let mut out = [0u8; 8];
            let n = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut out))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&out[..n], b"done\n", "the in-flight command completed");
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !session.is_finished(),
                "not allowed to stop yet: the session keeps serving"
            );
            // Once the handler allows it, the next notification ends the session.
            handler.allow_stop.store(true, Ordering::SeqCst);
            cancel_tx.send(true).unwrap();
            let report = tokio::time::timeout(Duration::from_secs(5), session)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(report.end, SessionEnd::Cancelled),
                "{}",
                report.end
            );
            assert_eq!(report.end.to_string(), "cancelled");
        })
        .await;
    }

    /// Blocks every command whose frame does not contain `quick` until
    /// released, counts how many run at once and records the order they
    /// started in; replies name the frame (a frame containing `big`
    /// gets a 4 KiB reply). The lane is the frame's prefix: `ctl-` is a
    /// control, `thaw-` a thaw, `freeze-` a freeze, anything else
    /// ordinary. A finished freeze forbids a stop, a finished thaw allows
    /// it again.
    struct CountingHandler {
        release: tokio::sync::Notify,
        running: AtomicUsize,
        peak: AtomicUsize,
        started: Mutex<Vec<String>>,
        allow_stop: std::sync::atomic::AtomicBool,
    }

    impl CountingHandler {
        fn new() -> Arc<Self> {
            Arc::new(CountingHandler {
                release: tokio::sync::Notify::new(),
                running: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                started: Mutex::new(Vec::new()),
                allow_stop: std::sync::atomic::AtomicBool::new(true),
            })
        }

        /// Waits (yielding) until `n` commands are running; a handshake,
        /// not a timing assumption.
        async fn running_is(&self, n: usize) {
            let start = std::time::Instant::now();
            while self.running.load(Ordering::SeqCst) != n {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "running={} never reached {n}",
                    self.running.load(Ordering::SeqCst)
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        /// Waits until the command named `frame` has started.
        async fn started_is(&self, frame: &str) {
            let start = std::time::Instant::now();
            while !self.started().iter().any(|f| f == frame) {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "{frame} never started; started: {:?}",
                    self.started()
                );
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }

        fn started(&self) -> Vec<String> {
            self.started.lock().unwrap().clone()
        }
    }

    impl Handle for CountingHandler {
        async fn handle(&self, event: DecodeEvent) -> Option<Vec<u8>> {
            let DecodeEvent::Frame { bytes, .. } = event else {
                return None;
            };
            let name = String::from_utf8_lossy(&bytes).into_owned();
            self.started.lock().unwrap().push(name.clone());
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            if !name.contains("quick") {
                self.release.notified().await;
            }
            self.running.fetch_sub(1, Ordering::SeqCst);
            if name.starts_with("freeze") {
                self.allow_stop.store(false, Ordering::SeqCst);
            } else if name.starts_with("thaw") {
                self.allow_stop.store(true, Ordering::SeqCst);
            }
            let mut reply = if name.contains("big") {
                vec![b'x'; 4096]
            } else {
                bytes
            };
            reply.push(b'\n');
            Some(reply)
        }

        fn may_stop(&self) -> bool {
            self.allow_stop.load(Ordering::SeqCst)
        }

        fn classify(&self, event: &DecodeEvent) -> Kind {
            let DecodeEvent::Frame { bytes, .. } = event else {
                return Kind::Control;
            };
            if bytes.starts_with(b"ctl-") {
                Kind::Control
            } else if bytes.starts_with(b"thaw-") {
                Kind::Thaw
            } else if bytes.starts_with(b"freeze-") {
                Kind::Freeze
            } else {
                Kind::Ordinary
            }
        }
    }

    /// A session over a duplex of `buffer` bytes with a counting handler.
    fn counting_session(
        buffer: usize,
    ) -> (
        tokio::io::DuplexStream,
        Arc<CountingHandler>,
        watch::Sender<bool>,
        tokio::task::JoinHandle<SessionReport>,
    ) {
        let (peer, ours) = duplex(buffer);
        let (reader, writer) = tokio::io::split(ours);
        let (cancel_tx, mut cancel_rx) = cancel_pair();
        let handler = CountingHandler::new();
        let h = handler.clone();
        let session = tokio::spawn(async move {
            let mut decoder = FrameDecoder::new();
            run_session_until(reader, writer, h.as_ref(), &mut decoder, &mut cancel_rx).await
        });
        (peer, handler, cancel_tx, session)
    }

    /// Reads from `peer` until `expected` has arrived.
    async fn read_exactly(peer: &mut tokio::io::DuplexStream, expected: &[u8]) {
        let mut got = Vec::new();
        let mut out = [0u8; 256];
        while got.len() < expected.len() {
            let n = peer.read(&mut out).await.unwrap();
            assert!(n > 0, "peer closed");
            got.extend_from_slice(&out[..n]);
        }
        assert_eq!(got, expected, "replies, in request order");
    }

    /// Asserts that nothing is on the wire for a while.
    async fn nothing_to_read(peer: &mut tokio::io::DuplexStream) {
        let mut out = [0u8; 32];
        let pending = tokio::time::timeout(Duration::from_millis(100), peer.read(&mut out)).await;
        assert!(pending.is_err(), "unexpected reply");
    }

    #[tokio::test]
    async fn a_control_runs_while_a_freeze_reply_is_pending_and_replies_keep_request_order() {
        // The freeze blocks; the control behind it finishes at once. Its
        // reply is held until the freeze reply has gone out, and the wire
        // carries the replies in request order.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"freeze-1\nctl-quick-2\n").await.unwrap();
            handler.started_is("ctl-quick-2").await;
            assert_eq!(handler.peak.load(Ordering::SeqCst), 2, "both ran at once");
            nothing_to_read(&mut peer).await;
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"freeze-1\nctl-quick-2\n").await;
            drop(peer);
            let report = session.await.unwrap();
            assert!(matches!(report.end, SessionEnd::Eof), "{}", report.end);
        })
        .await;
    }

    #[tokio::test]
    async fn an_ordinary_command_waits_for_the_one_running_before_it() {
        // Two ordinary commands: the second is not started while the
        // first runs, whatever the first is doing; a freeze behind an
        // ordinary command waits just the same, and a control behind
        // that freeze waits its turn (admission is in request order).
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"slow-1\nfreeze-2\nctl-quick-3\n")
                .await
                .unwrap();
            handler.running_is(1).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(handler.started(), ["slow-1"], "nothing overtakes");
            handler.release.notify_waiters();
            handler.started_is("freeze-2").await;
            handler.started_is("ctl-quick-3").await;
            assert_eq!(handler.peak.load(Ordering::SeqCst), 2);
            read_exactly(&mut peer, b"slow-1\n").await;
            nothing_to_read(&mut peer).await;
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"freeze-2\nctl-quick-3\n").await;
            assert_eq!(handler.started(), ["slow-1", "freeze-2", "ctl-quick-3"]);
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn a_thaw_runs_beside_a_freeze_but_not_beside_an_ordinary_command() {
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"freeze-1\nthaw-quick-2\n").await.unwrap();
            handler.started_is("thaw-quick-2").await;
            assert_eq!(
                handler.peak.load(Ordering::SeqCst),
                2,
                "the thaw reached the freeze"
            );
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"freeze-1\nthaw-quick-2\n").await;
            peer.write_all(b"slow-3\nthaw-quick-4\n").await.unwrap();
            handler.started_is("slow-3").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(handler.started().len(), 3, "the thaw waits for the trim");
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"slow-3\nthaw-quick-4\n").await;
            assert_eq!(handler.peak.load(Ordering::SeqCst), 2);
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn at_most_max_controls_run_beside_the_command_in_progress() {
        // A freeze and ten blocking controls: MAX_CONTROLS controls run
        // beside the freeze, the rest wait, and every reply arrives in
        // order once they are released.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(4096);
            let mut frames = b"freeze-0\n".to_vec();
            frames.extend((1..=10).flat_map(|i| format!("ctl-{i}\n").into_bytes()));
            peer.write_all(&frames).await.unwrap();
            handler.running_is(1 + MAX_CONTROLS).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(handler.peak.load(Ordering::SeqCst), 1 + MAX_CONTROLS);
            assert_eq!(handler.running.load(Ordering::SeqCst), 1 + MAX_CONTROLS);
            let mut got = Vec::new();
            let mut out = [0u8; 256];
            while got.len() < frames.len() {
                handler.release.notify_waiters();
                tokio::time::sleep(Duration::from_millis(10)).await;
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(20), peer.read(&mut out)).await
                {
                    got.extend_from_slice(&out[..n]);
                }
            }
            assert_eq!(got, frames, "all replies, in request order");
            assert!(handler.peak.load(Ordering::SeqCst) <= 1 + MAX_CONTROLS);
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn a_thaw_behind_finished_controls_still_reaches_the_pending_freeze() {
        // Finished controls whose replies wait behind the freeze reply
        // hold no lane: the thaw sent after them is read and started.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"freeze-1\n").await.unwrap();
            handler.running_is(1).await;
            for i in 2..=4 {
                let frame = format!("ctl-quick-{i}");
                peer.write_all(format!("{frame}\n").as_bytes())
                    .await
                    .unwrap();
                handler.started_is(&frame).await;
            }
            peer.write_all(b"thaw-quick-5\n").await.unwrap();
            handler.started_is("thaw-quick-5").await;
            handler.release.notify_waiters();
            read_exactly(
                &mut peer,
                b"freeze-1\nctl-quick-2\nctl-quick-3\nctl-quick-4\nthaw-quick-5\n",
            )
            .await;
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn the_queue_is_bounded_and_a_frame_behind_a_saturated_backlog_waits_for_the_reply() {
        // MAX_QUEUED commands unanswered (the freeze and the controls
        // finished behind it): the channel is not read, so the thaw is
        // started only once the freeze reply is out.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"freeze-1\n").await.unwrap();
            handler.running_is(1).await;
            let mut expected = b"freeze-1\n".to_vec();
            for i in 2..=MAX_QUEUED {
                let frame = format!("ctl-quick-{i}");
                peer.write_all(format!("{frame}\n").as_bytes())
                    .await
                    .unwrap();
                handler.started_is(&frame).await;
                expected.extend(format!("{frame}\n").into_bytes());
            }
            peer.write_all(b"thaw-quick-9\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(handler.started().len(), MAX_QUEUED, "the thaw is not read");
            handler.release.notify_waiters();
            expected.extend(b"thaw-quick-9\n");
            read_exactly(&mut peer, &expected).await;
            assert_eq!(handler.started().len(), MAX_QUEUED + 1);
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn a_blocked_reply_does_not_stall_the_commands_behind_it() {
        // The first reply is far larger than the 16-byte duplex and the
        // peer reads nothing: the command behind it is still polled to
        // completion, and a stop then ends the session without the host
        // ever reading.
        bounded(async {
            let (mut peer, handler, cancel, session) = counting_session(16);
            peer.write_all(b"ctl-big-quick-1\nslow-2\n").await.unwrap();
            handler.started_is("slow-2").await;
            handler.release.notify_waiters();
            handler.running_is(0).await;
            assert!(!session.is_finished());
            cancel.send(true).unwrap();
            let report = session.await.unwrap();
            assert!(
                matches!(report.end, SessionEnd::Cancelled),
                "{}",
                report.end
            );
            let mut out = vec![0u8; 64];
            let n = peer.read(&mut out).await.unwrap();
            assert!(n <= 16 && out[..n].iter().all(|&b| b == b'x'), "{n}");
        })
        .await;
    }

    #[tokio::test]
    async fn a_stop_during_a_blocked_reply_finishes_the_running_command_and_starts_nothing() {
        // A control's reply is stuck on the unread duplex while an
        // ordinary command runs. The stop is accepted (Thawed) but the
        // session drains: it neither returns nor drops the running
        // command until it finishes, and a frame sent meanwhile is never
        // started.
        bounded(async {
            let (mut peer, handler, cancel, session) = counting_session(16);
            peer.write_all(b"ctl-big-quick-1\nslow-2\n").await.unwrap();
            handler.started_is("slow-2").await;
            cancel.send(true).unwrap();
            peer.write_all(b"quick-3\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!session.is_finished(), "waits for the running command");
            assert_eq!(handler.running.load(Ordering::SeqCst), 1);
            handler.release.notify_waiters();
            let report = session.await.unwrap();
            assert!(
                matches!(report.end, SessionEnd::Cancelled),
                "{}",
                report.end
            );
            assert_eq!(handler.started(), ["ctl-big-quick-1", "slow-2"]);
            assert_eq!(handler.running.load(Ordering::SeqCst), 0);
        })
        .await;
    }

    #[tokio::test]
    async fn a_stop_accepted_while_a_freeze_runs_is_withdrawn_once_it_froze() {
        // The stop is accepted while the freeze is still running and the
        // state Thawed; the freeze finishes and forbids the stop, so the
        // session serves on (the thaw is read and handled) and stops on
        // the standing request once thawed.
        bounded(async {
            let (mut peer, handler, cancel, session) = counting_session(1024);
            peer.write_all(b"freeze-1\n").await.unwrap();
            handler.running_is(1).await;
            cancel.send(true).unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!session.is_finished());
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"freeze-1\n").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!session.is_finished(), "frozen: the stop is withdrawn");
            peer.write_all(b"thaw-quick-2\n").await.unwrap();
            read_exactly(&mut peer, b"thaw-quick-2\n").await;
            // The standing request takes effect once thawed.
            let report = session.await.unwrap();
            assert!(
                matches!(report.end, SessionEnd::Cancelled),
                "{}",
                report.end
            );
        })
        .await;
    }

    #[tokio::test]
    async fn eof_finishes_the_commands_received_before_the_session_ends() {
        // The peer goes away while a command is being handled and another
        // waits behind it: both complete (their side effects are what
        // matter), then the session reports the EOF.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"slow-1\nquick-2\n").await.unwrap();
            handler.running_is(1).await;
            drop(peer);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!session.is_finished(), "waits for the command in flight");
            assert_eq!(handler.running.load(Ordering::SeqCst), 1);
            handler.release.notify_waiters();
            let report = session.await.unwrap();
            assert!(
                matches!(report.end, SessionEnd::Eof | SessionEnd::WriteError(_)),
                "{}",
                report.end
            );
            assert_eq!(handler.started(), ["slow-1", "quick-2"]);
            assert_eq!(handler.running.load(Ordering::SeqCst), 0);
        })
        .await;
    }

    #[tokio::test]
    async fn session_ends_cleanly_on_eof_and_reports_reason() {
        let (peer, ours) = duplex(64);
        let (reader, writer) = tokio::io::split(ours);
        drop(peer);
        let handler = FakeDispatcher::default();
        let mut decoder = FrameDecoder::new();
        let report = run_session(reader, writer, &handler, &mut decoder).await;
        assert!(matches!(report.end, SessionEnd::Eof));
        assert_eq!(report.end.to_string(), "eof");
        assert_eq!(report.received, 0);
        assert!(handler.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn session_never_replies_to_a_shutdown_success() {
        bounded(async {
            let (mut peer, ours) = duplex(1024);
            let (reader, writer) = tokio::io::split(ours);
            let handler = Arc::new(FakeDispatcher::default());
            let h = handler.clone();
            let session = tokio::spawn(async move {
                let mut decoder = FrameDecoder::new();
                run_session(reader, writer, h.as_ref(), &mut decoder).await
            });
            peer.write_all(b"shutdown\nafter\n").await.unwrap();
            let mut out = vec![0u8; 64];
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(
                &out[..n],
                b"AFTER\n",
                "nothing was written for the shutdown frame"
            );
            drop(peer);
            session.await.unwrap();
            assert_eq!(handler.seen.lock().unwrap().len(), 2);
        })
        .await;
    }

    /// Replies with a frame far larger than a tiny duplex buffer and
    /// allows a stop only when told to.
    struct BigReplyHandler {
        allow_stop: std::sync::atomic::AtomicBool,
    }

    impl Handle for BigReplyHandler {
        async fn handle(&self, _event: DecodeEvent) -> Option<Vec<u8>> {
            let mut reply = vec![b'x'; 4096];
            reply.push(b'\n');
            Some(reply)
        }
        fn may_stop(&self) -> bool {
            self.allow_stop.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A session over a 16-byte duplex whose peer never reads: the reply
    /// write blocks after the first bytes. Returns the peer (kept alive,
    /// unread) and the session task.
    fn blocked_reply_session(
        handler: Arc<BigReplyHandler>,
    ) -> (
        tokio::io::DuplexStream,
        watch::Sender<bool>,
        tokio::task::JoinHandle<SessionReport>,
    ) {
        let (peer, ours) = duplex(16);
        let (reader, writer) = tokio::io::split(ours);
        let (cancel_tx, mut cancel_rx) = cancel_pair();
        let session = tokio::spawn(async move {
            let mut decoder = FrameDecoder::new();
            run_session_until(
                reader,
                writer,
                handler.as_ref(),
                &mut decoder,
                &mut cancel_rx,
            )
            .await
        });
        (peer, cancel_tx, session)
    }

    #[tokio::test]
    async fn a_stop_is_honoured_while_the_host_is_not_reading_the_reply() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let handler = Arc::new(BigReplyHandler {
                allow_stop: std::sync::atomic::AtomicBool::new(true),
            });
            let (mut peer, cancel_tx, session) = blocked_reply_session(handler);
            peer.write_all(b"ping\n").await.unwrap();
            // The handler ran and the reply write is stuck on the full
            // buffer; the peer keeps the port open but reads nothing.
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(!session.is_finished(), "blocked on the unread reply");
            cancel_tx.send(true).unwrap();
            let report = tokio::time::timeout(Duration::from_secs(2), session)
                .await
                .expect("the stop ends the session without the host draining")
                .unwrap();
            assert!(
                matches!(report.end, SessionEnd::Cancelled),
                "{}",
                report.end
            );
            assert_eq!(report.received, 5);
            drop(peer);
        })
        .await
        .expect("test hung");
    }

    #[tokio::test]
    async fn a_blocked_reply_while_frozen_waits_for_the_thaw_then_stops() {
        tokio::time::timeout(Duration::from_secs(10), async {
            use std::sync::atomic::Ordering;
            // Frozen: the stop is not allowed, so the blocked write is
            // kept (not restarted) and the session goes on. Once the
            // watchdog or the host thaws, the repeated stop request ends
            // the session even though the host still reads nothing.
            let handler = Arc::new(BigReplyHandler {
                allow_stop: std::sync::atomic::AtomicBool::new(false),
            });
            let (mut peer, cancel_tx, session) = blocked_reply_session(Arc::clone(&handler));
            peer.write_all(b"ping\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_tx.send(true).unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(!session.is_finished(), "not allowed to stop while frozen");
            // Thawed: the daemon's stopper re-sends the request each poll.
            handler.allow_stop.store(true, Ordering::SeqCst);
            cancel_tx.send(true).unwrap();
            let report = tokio::time::timeout(Duration::from_secs(2), session)
                .await
                .expect("the stop ends the session once allowed")
                .unwrap();
            assert!(
                matches!(report.end, SessionEnd::Cancelled),
                "{}",
                report.end
            );
            // The peer sees the partial frame that was written before the
            // buffer filled: at most the buffer's worth, never a second
            // reply appended to it.
            let mut out = vec![0u8; 64];
            let n = peer.read(&mut out).await.unwrap();
            assert!(n <= 16 && out[..n].iter().all(|&b| b == b'x'), "{n}");
        })
        .await
        .expect("test hung");
    }

    #[tokio::test]
    async fn write_error_ends_session_without_panic() {
        bounded(async {
            struct FailingWriter;
            impl AsyncWrite for FailingWriter {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _: &mut TaskContext<'_>,
                    _: &[u8],
                ) -> Poll<io::Result<usize>> {
                    Poll::Ready(Err(io::Error::from_raw_os_error(Errno::EPIPE as i32)))
                }
                fn poll_flush(
                    self: Pin<&mut Self>,
                    _: &mut TaskContext<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _: &mut TaskContext<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }
            let (mut peer, ours) = duplex(64);
            let (reader, _writer) = tokio::io::split(ours);
            peer.write_all(b"frame\n").await.unwrap();
            let handler = FakeDispatcher::default();
            let mut decoder = FrameDecoder::new();
            let end = run_session(reader, FailingWriter, &handler, &mut decoder)
                .await
                .end;
            assert!(matches!(end, SessionEnd::WriteError(_)), "{end}");
            assert!(end.to_string().contains("write error"));
        })
        .await;
    }

    #[tokio::test]
    async fn open_maps_ebusy_to_channel_already_open_terminal_error() {
        let open: OpenFn = Arc::new(|_| Err(io::Error::from_raw_os_error(Errno::EBUSY as i32)));
        let err = Channel::open_with(Path::new("/dev/virtio-ports/x"), open.as_ref()).unwrap_err();
        assert!(matches!(err, OpenError::AlreadyOpen { .. }), "{err:?}");
        assert!(err.is_terminal());
        assert!(err.to_string().starts_with("channel_already_open"));
        // Through the retry loop: immediate, no backoff, no retry.
        let (_tx, mut cancel) = cancel_pair();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let open: OpenFn = Arc::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(Errno::EBUSY as i32))
        });
        let err = open_with_retry(Path::new("/dev/x"), &open, &mut cancel)
            .await
            .unwrap_err();
        assert!(err.is_terminal());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // serve() surfaces it too.
        let handler = FakeDispatcher::default();
        let (_tx, cancel) = cancel_pair();
        let err = serve(Path::new("/dev/x"), open, &handler, cancel)
            .await
            .unwrap_err();
        assert!(err.is_terminal());
        // Other errnos are not terminal.
        let err = OpenError::from_io(
            Path::new("/dev/x"),
            io::Error::from_raw_os_error(Errno::EACCES as i32),
        );
        assert!(matches!(err, OpenError::Io { .. }));
        assert!(!err.is_terminal());
    }

    #[tokio::test(start_paused = true)]
    async fn open_retries_enoent_with_bounded_backoff() {
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let a = attempts.clone();
        let start = tokio::time::Instant::now();
        let open: OpenFn = Arc::new(move |_| {
            a.lock().unwrap().push(start.elapsed());
            Err(io::Error::from_raw_os_error(Errno::ENOENT as i32))
        });
        let (tx, mut cancel) = cancel_pair();
        let path = PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0");
        let task = tokio::spawn(async move { open_with_retry(&path, &open, &mut cancel).await });
        // Let it retry for a while: 1, 2, 4, 8, 16, 30, 30, 30 ... The
        // clock advances one second at a time so attempt times are exact.
        tokio::task::yield_now().await;
        for _ in 0..400 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        let secs: Vec<u64> = attempts
            .lock()
            .unwrap()
            .iter()
            .map(|d| d.as_secs())
            .collect();
        assert_eq!(&secs[..7], &[0, 1, 3, 7, 15, 31, 61]);
        assert!(
            secs.windows(2).skip(6).all(|w| w[1] - w[0] == 30),
            "{secs:?}"
        );
        assert!(secs.len() > 10, "keeps trying: {secs:?}");
        assert!(!task.is_finished(), "never gives up on its own");
        // ... but is cancellable.
        tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Ok(None)));
    }

    #[tokio::test]
    async fn reconnect_resets_decoder_but_not_state() {
        bounded(async {
            // Two sessions over the same `serve` loop: the first ends after a
            // partial frame; the second must not see it. The freeze state
            // machine handed to the (fake) dispatcher stays Frozen throughout.
            let state = Arc::new(FreezeStateMachine::starting_frozen());
            let handler = Arc::new(FakeDispatcher::default());
            let sessions: Arc<Mutex<Vec<tokio::io::DuplexStream>>> =
                Arc::new(Mutex::new(Vec::new()));
            let (peer1, ours1) = duplex(1024);
            let (peer2, ours2) = duplex(1024);
            sessions.lock().unwrap().push(ours2);
            sessions.lock().unwrap().push(ours1);
            // The "device": each open hands out the next duplex end as a pty-like
            // fd is not available for DuplexStream, so drive `run_session`
            // directly the way `serve` does, with a fresh decoder per session.
            let h = handler.clone();
            let loop_task = tokio::spawn(async move {
                let mut ends = Vec::new();
                loop {
                    let next = sessions.lock().unwrap().pop();
                    let Some(stream) = next else { break };
                    let (r, w) = tokio::io::split(stream);
                    let mut decoder = FrameDecoder::new();
                    ends.push(
                        run_session(r, w, h.as_ref(), &mut decoder)
                            .await
                            .end
                            .to_string(),
                    );
                }
                ends
            });
            let mut peer1 = peer1;
            peer1
                .write_all(b"complete\npartial-without-newline")
                .await
                .unwrap();
            let mut out = vec![0u8; 64];
            let n = peer1.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"COMPLETE\n");
            drop(peer1); // EOF: session 1 ends with the partial frame buffered.
            let mut peer2 = peer2;
            peer2.write_all(b"fresh\n").await.unwrap();
            let n = peer2.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"FRESH\n", "the partial frame was discarded");
            drop(peer2);
            let ends = loop_task.await.unwrap();
            assert_eq!(ends, ["eof", "eof"]);
            let frames: Vec<Vec<u8>> = handler
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter_map(|e| match e {
                    DecodeEvent::Frame { bytes, .. } => Some(bytes.clone()),
                    _ => None,
                })
                .collect();
            assert_eq!(frames, [b"complete".to_vec(), b"fresh".to_vec()]);
            assert_eq!(
                state.current(),
                FreezeState::Frozen,
                "reconnection never touches the state"
            );
        })
        .await;
    }

    /// A socket whose peer is already gone: opens fine, EOF at once, like
    /// a virtio port whose host side is disconnected.
    fn dead_socket() -> OwnedFd {
        let (ours, peer) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        drop(peer);
        ours
    }

    /// Short real-time backoff for the reopen tests (paused time cannot be
    /// combined with descriptor readiness).
    const TEST_BACKOFF: Backoff = Backoff {
        initial: Duration::from_millis(50),
        max: Duration::from_millis(400),
    };

    /// Serves `open` for `horizon` and returns the gaps between successive
    /// opens.
    async fn open_gaps(
        opens: Arc<Mutex<Vec<std::time::Instant>>>,
        open: OpenFn,
        horizon: Duration,
    ) -> Vec<Duration> {
        let (tx, cancel) = cancel_pair();
        let handler = Arc::new(FakeDispatcher::default());
        let server = tokio::spawn(async move {
            serve_with_backoff(
                Path::new("/dev/virtio-ports/fake"),
                open,
                handler.as_ref(),
                cancel,
                TEST_BACKOFF,
            )
            .await
        });
        tokio::time::sleep(horizon).await;
        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
        let opens = opens.lock().unwrap();
        opens.windows(2).map(|w| w[1] - w[0]).collect()
    }

    /// `gap` is at least `expected` and not absurdly longer (scheduling
    /// jitter on a loaded runner).
    fn about(gap: Duration, expected: Duration) -> bool {
        gap >= expected && gap < expected + Duration::from_millis(100)
    }

    #[tokio::test]
    async fn disconnected_port_is_reopened_with_growing_backoff_not_a_busy_loop() {
        // Every session reads EOF immediately: reopen after 50, 100, 200,
        // 400, 400, ... ms rather than in a tight loop.
        let opens = Arc::new(Mutex::new(Vec::new()));
        let o = opens.clone();
        let open: OpenFn = Arc::new(move |_| {
            o.lock().unwrap().push(std::time::Instant::now());
            Ok(dead_socket())
        });
        let gaps = open_gaps(opens, open, Duration::from_millis(1600)).await;
        assert!(gaps.len() >= 5, "{gaps:?}");
        let ms = |n: u64| Duration::from_millis(n);
        assert!(about(gaps[0], ms(50)), "{gaps:?}");
        assert!(about(gaps[1], ms(100)), "{gaps:?}");
        assert!(about(gaps[2], ms(200)), "{gaps:?}");
        for gap in &gaps[3..] {
            assert!(about(*gap, ms(400)), "capped: {gaps:?}");
        }
    }

    #[tokio::test]
    async fn a_session_that_carried_data_resets_the_reopen_backoff() {
        // Two dead sessions (pauses 50 ms, 100 ms), then one that receives
        // a frame: the next reopen waits only `initial` again, not 200 ms.
        let opens = Arc::new(Mutex::new(Vec::new()));
        let o = opens.clone();
        let open: OpenFn = Arc::new(move |_| {
            let mut o = o.lock().unwrap();
            o.push(std::time::Instant::now());
            if o.len() == 3 {
                let (ours, peer) = nix::sys::socket::socketpair(
                    nix::sys::socket::AddressFamily::Unix,
                    nix::sys::socket::SockType::Stream,
                    None,
                    nix::sys::socket::SockFlag::SOCK_CLOEXEC,
                )
                .unwrap();
                nix::unistd::write(&peer, b"ping\n").unwrap();
                drop(peer);
                Ok(ours)
            } else {
                Ok(dead_socket())
            }
        });
        let gaps = open_gaps(opens, open, Duration::from_millis(700)).await;
        assert!(gaps.len() >= 4, "{gaps:?}");
        let ms = |n: u64| Duration::from_millis(n);
        assert!(about(gaps[0], ms(50)), "{gaps:?}");
        assert!(about(gaps[1], ms(100)), "{gaps:?}");
        assert!(about(gaps[2], ms(50)), "reset after data: {gaps:?}");
        assert!(about(gaps[3], ms(100)), "{gaps:?}");
    }

    #[tokio::test]
    async fn serve_reopens_after_eof_until_cancelled() {
        bounded(async {
            // A real fd-backed channel through a pty pair, reopened twice.
            let opened = Arc::new(AtomicUsize::new(0));
            let masters: Arc<Mutex<Vec<nix::pty::PtyMaster>>> = Arc::new(Mutex::new(Vec::new()));
            let o = opened.clone();
            let m = masters.clone();
            let open: OpenFn = Arc::new(move |_| {
                let master = nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY)?;
                nix::pty::grantpt(&master)?;
                nix::pty::unlockpt(&master)?;
                let slave_path = nix::pty::ptsname_r(&master)?;
                raw_mode(&master);
                let slave = open_device(Path::new(&slave_path))?;
                raw_mode(&slave);
                m.lock().unwrap().push(master);
                o.fetch_add(1, Ordering::SeqCst);
                Ok(slave)
            });
            let handler = Arc::new(FakeDispatcher::default());
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve(
                    Path::new("/dev/virtio-ports/fake"),
                    open,
                    h.as_ref(),
                    cancel,
                )
                .await
            });
            for round in 0..2 {
                while opened.load(Ordering::SeqCst) <= round {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let master = {
                    let mut m = masters.lock().unwrap();
                    OwnedFd::from(m.remove(0))
                };
                let mut master = Channel::from_fd(master).unwrap();
                master.write_all(b"ping\n").await.unwrap();
                let mut out = vec![0u8; 16];
                let n = master.read(&mut out).await.unwrap();
                assert_eq!(&out[..n], b"PING\n", "round {round}");
                drop(master); // HUP on the slave: the session ends and serve reopens.
            }
            while opened.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            tx.send(true).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap();
            assert!(result.is_ok());
            assert_eq!(handler.seen.lock().unwrap().len(), 2);
        })
        .await;
    }

    fn raw_mode(fd: &impl AsFd) {
        let mut termios = nix::sys::termios::tcgetattr(fd).unwrap();
        nix::sys::termios::cfmakeraw(&mut termios);
        nix::sys::termios::tcsetattr(fd, nix::sys::termios::SetArg::TCSANOW, &termios).unwrap();
    }

    #[tokio::test]
    async fn open_on_pty_slave_works() {
        let master = nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).unwrap();
        nix::pty::grantpt(&master).unwrap();
        nix::pty::unlockpt(&master).unwrap();
        let slave_path = nix::pty::ptsname_r(&master).unwrap();
        raw_mode(&master);
        let mut channel = Channel::open(Path::new(&slave_path)).unwrap();
        raw_mode(&channel.fd.get_ref());
        assert!(channel.as_raw_fd() >= 0);
        let mut master = Channel::from_fd(OwnedFd::from(master)).unwrap();
        // Host → guest.
        master
            .write_all(b"{\"execute\":\"guest-ping\"}\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let n = channel.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"{\"execute\":\"guest-ping\"}\n");
        // Guest → host.
        channel.write_all(b"{\"return\":{}}\n").await.unwrap();
        let n = master.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"{\"return\":{}}\n");
        // Closing the master makes the slave read EOF/HUP.
        drop(master);
        let end = channel.read(&mut buf).await;
        assert!(matches!(end, Ok(0) | Err(_)), "{end:?}");
        // A missing device is `NotFound`, not terminal.
        let err = Channel::open(Path::new("/dev/virtio-ports/does-not-exist")).unwrap_err();
        assert!(matches!(err, OpenError::NotFound { .. }));
        assert!(!err.is_terminal());
    }
}
