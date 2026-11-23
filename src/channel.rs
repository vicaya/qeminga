//! The virtio-serial channel: open, session loop, EOF/HUP reconnect
//! (design §4.1 I/O layer, §5.7 reconnect rules, §8.4 `EBUSY` is
//! terminal; AC18; C-15).
//!
//! [`Channel`] wraps the device descriptor in an [`OwnedAsyncFd`] and
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
//! When a Linux `virtio_console` port is opened before the host connects
//! (or after the host disconnects), the kernel reports `POLLIN | POLLHUP`
//! without `POLLOUT`, `POLLERR`, or `POLLRDHUP`, and `read(2)` returns EOF
//! immediately. Closing the descriptor would clear `guest_connected` and
//! cause QEMU to emit `VSERPORT_CHANGE (open=false)`, racing libvirt's
//! asynchronous host-side connection. [`serve`] therefore keeps the
//! underlying descriptor open and unregistered from Tokio while draining
//! any stale unread driver input and polling readiness with bounded backoff
//! ([`HOST_WAIT_INITIAL`] doubling to [`HOST_WAIT_MAX`]). Once the host is
//! ready, [`serve`] creates a fresh [`Channel`] reactor registration (so
//! sticky `READ_CLOSED`/`WRITE_CLOSED` bits from a prior `EPOLLHUP` never
//! spin an idle session) and a fresh [`FrameDecoder`]; on an observed
//! virtio hangup or fast reconnect, accepted commands still finish while
//! undelivered replies for the departed peer are discarded, and repeated
//! empty EOFs on an open ready port are paced with the same bounded delay.
//!
//! When the descriptor itself is closed, hot-unplugged, or errors (bare
//! `POLLHUP`, a dead PTY/socket peer, or an I/O error), [`serve`] drops it
//! and reopens with bounded backoff: after a session that received nothing
//! the delay doubles up to [`MAX_BACKOFF`]; a session that carried data
//! resets it to [`INITIAL_BACKOFF`].
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::Duration;

use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::poll::PollFlags;
use nix::sys::stat::Mode;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::watch;

use crate::dispatch::Dispatcher;
use crate::framing::{DecodeEvent, FrameDecoder};
use crate::kernel::async_fd::OwnedAsyncFd;
use crate::state::FreezeState;

/// First delay of the open-retry and reopen backoff.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Upper bound of the reopen backoff.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Initial poll interval while waiting for the host side of an open
/// virtio-serial port to connect (§5.7).
pub const HOST_WAIT_INITIAL: Duration = Duration::from_millis(10);

/// Upper bound of the poll interval while waiting for the host side of an
/// open virtio-serial port to connect (§5.7).
pub const HOST_WAIT_MAX: Duration = Duration::from_millis(500);

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
    fd: OwnedAsyncFd,
}

/// Switches `fd` to non-blocking mode (`O_NONBLOCK`).
fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL)?;
    let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags))?;
    Ok(())
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
        set_nonblocking(fd.as_fd())?;
        Ok(Channel {
            fd: OwnedAsyncFd::register(fd)?,
        })
    }

    /// Deregisters the channel from the Tokio reactor and returns the still-open
    /// descriptor so the next session can establish a fresh reactor registration.
    pub fn into_fd(self) -> OwnedFd {
        self.fd.into_fd()
    }

    /// The raw descriptor (diagnostics only).
    pub fn as_raw_fd(&self) -> i32 {
        self.fd.as_fd().as_raw_fd()
    }
}

/// Shared read/write view of a [`Channel`] so [`serve`] can inspect the
/// underlying descriptor during a session without `tokio::io::split`.
struct ChannelRef<'a>(&'a Channel);

impl AsyncRead for ChannelRef<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = ready!(self.0.fd.poll_read(cx, buf.initialize_unfilled()))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ChannelRef<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.0.fd.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Channel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = ready!(self.fd.poll_read(cx, buf.initialize_unfilled()))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Channel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.fd.poll_write(cx, data)
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

/// Places in the session's queue. A command owns one from its frame's
/// decoding to its reply's delivery: waiting for a lane, running,
/// finished with the reply waiting behind an earlier one, or with the
/// reply in the outbox but not yet accepted by the host. A reply keeps
/// its place until the host has taken it, so a peer that stops reading
/// stops being read. The channel is not read while every place is
/// taken; one read's worth of frames may be decoded beyond that, and
/// waits for a place.
///
/// This bounds the host's interruption of a freeze: a
/// `guest-fsfreeze-thaw` sent behind a pending freeze reply is read, and
/// aborts the walk, as long as fewer than this many commands are held.
/// A host that sends `MAX_QUEUED - 1` further commands without reading
/// a reply has its next frame read only once the freeze reply is out: at
/// the latest at the operation deadline (§4.4).
pub const MAX_QUEUED: usize = 8;

/// Bytes of replies the session keeps for a host that has not accepted
/// them yet. Once the outbox holds this much, nothing more is started;
/// once the outbox and the finished replies behind earlier ones together
/// hold this much, nothing more is read. A single reply larger than the
/// budget is kept whole (it exists already) and pauses the session until
/// the host has taken it. With [`MAX_QUEUED`] this bounds the session's
/// memory against a peer that stops reading: the budget, plus the
/// replies of the commands already started when it was reached.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

/// A command the session holds, in request order.
enum Slot<'a> {
    /// Decoded; its lane is not free yet, or the reply budget is spent.
    Waiting(Kind, DecodeEvent),
    /// Running.
    Pending(
        Kind,
        Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>,
    ),
    /// Finished; the reply waits for the ones before it.
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

/// What is running, by lane.
#[derive(Default)]
struct Lanes {
    controls: usize,
    freeze: bool,
    thaw_or_ordinary: bool,
}

impl Lanes {
    fn of(slots: &VecDeque<Slot<'_>>) -> Self {
        let mut lanes = Lanes::default();
        for slot in slots {
            if let Slot::Pending(kind, _) = slot {
                lanes.take(*kind);
            }
        }
        lanes
    }

    fn take(&mut self, kind: Kind) {
        match kind {
            Kind::Control => self.controls += 1,
            Kind::Freeze => self.freeze = true,
            Kind::Thaw | Kind::Ordinary => self.thaw_or_ordinary = true,
        }
    }

    fn exclusive(&self) -> bool {
        self.freeze || self.thaw_or_ordinary
    }
}

/// Starts the waiting commands among the oldest `window` whose lane is
/// free (§5.7). The window is the queue's capacity not taken by
/// undelivered replies: each of the oldest commands owns its place from
/// its decoding to its delivery, waiting or not, so a later command that
/// overtakes it can never use up the capacity it needs to start once its
/// lane frees; frames decoded beyond the window stay in staging until
/// the window reaches them. The serial lane is first come, first served:
/// a freeze or an ordinary command starts only when nothing exclusive is
/// running and no earlier serial command is still waiting, so side
/// effects happen in the order the host asked for them. A control, or a
/// thaw while nothing but a freeze runs, is not held back by a serial
/// command waiting ahead of it: the host's `guest-fsfreeze-thaw` must
/// reach the freeze under way even when a walk the freeze gate would
/// refuse anyway is queued between them. Replies still leave in request
/// order, whatever the order of admission.
fn admit<'a, H: Handle>(slots: &mut VecDeque<Slot<'a>>, handler: &'a H, window: usize) {
    let mut lanes = Lanes::of(slots);
    let mut serial_waiting = false;
    for slot in slots.iter_mut().take(window) {
        let Slot::Waiting(kind, _) = slot else {
            continue;
        };
        let kind = *kind;
        let free = match kind {
            Kind::Control => lanes.controls < MAX_CONTROLS,
            Kind::Thaw => !lanes.thaw_or_ordinary,
            Kind::Freeze | Kind::Ordinary => !lanes.exclusive() && !serial_waiting,
        };
        if !free {
            if kind != Kind::Control {
                serial_waiting = true;
            }
            continue;
        }
        if let Slot::Waiting(_, event) = std::mem::replace(slot, Slot::Done(None)) {
            *slot = Slot::Pending(kind, Box::pin(handler.handle(event)));
            lanes.take(kind);
        }
    }
}

/// The one writer's queue: the replies the host has not accepted yet, in
/// request order, and how much of the first one it has taken. Kept
/// across loop iterations so a write the host is slow to accept resumes
/// where it stopped, while the loop keeps polling the commands and the
/// stop; a frame is never restarted, and a reply is released as soon as
/// the host has taken all of it.
struct Outbox {
    replies: VecDeque<Vec<u8>>,
    /// Bytes of the first reply the host has accepted.
    written: usize,
    /// Bytes not yet accepted, over all replies.
    pending: usize,
}

impl Outbox {
    fn new() -> Self {
        Outbox {
            replies: VecDeque::new(),
            written: 0,
            pending: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.replies.is_empty()
    }

    /// Replies not yet fully accepted by the host.
    fn count(&self) -> usize {
        self.replies.len()
    }

    /// Bytes not yet accepted by the host.
    fn pending_bytes(&self) -> usize {
        self.pending
    }

    fn push(&mut self, reply: Vec<u8>) {
        self.pending += reply.len();
        self.replies.push_back(reply);
    }

    /// Drops whatever the host has not accepted.
    fn abandon(&mut self) {
        self.replies.clear();
        self.written = 0;
        self.pending = 0;
    }

    /// Writes and flushes the queued replies; resolves once the host has
    /// accepted all of them, or with the write error.
    fn drain<'a, W>(&'a mut self, writer: &'a mut W) -> impl Future<Output = io::Result<()>> + 'a
    where
        W: AsyncWrite + Unpin,
    {
        std::future::poll_fn(move |cx| {
            while let Some(front) = self.replies.front() {
                let n = ready!(Pin::new(&mut *writer).poll_write(cx, &front[self.written..]))?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                self.written += n;
                self.pending -= n;
                if self.written == front.len() {
                    self.replies.pop_front();
                    self.written = 0;
                }
            }
            ready!(Pin::new(&mut *writer).poll_flush(cx))?;
            Poll::Ready(Ok(()))
        })
    }
}

/// [`run_session`] that also ends with [`SessionEnd::Cancelled`] once
/// `cancel` is `true` **and** `handler.may_stop()` holds.
///
/// Three concerns are kept apart (§5.7):
///
/// * **Admission.** Every decoded frame takes a slot in request order
///   and starts when its lane is free ([`Kind`], `admit`): one command
///   that may change the guest at a time, in request order among
///   themselves; the frozen-safe controls (up to [`MAX_CONTROLS`]) and a
///   thaw aimed at a freeze under way beside it, not held back by a
///   serial command waiting ahead of them. The queue has [`MAX_QUEUED`]
///   places, each owned by one command from its decoding to its reply's
///   delivery (an undelivered reply keeps its place), in request order:
///   a command without a place waits for one, and a command that
///   overtakes an earlier one can never use up the place the earlier
///   one needs to start. Past [`MAX_REPLY_BYTES`] of undelivered replies
///   nothing more is started; past either bound nothing more is read.
///   The bounds hold back new work only; what runs is always polled to
///   its end.
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
    reader: R,
    writer: W,
    handler: &H,
    decoder: &mut FrameDecoder,
    cancel: &mut Cancel,
) -> SessionReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handle,
{
    run_session_inner(reader, writer, handler, decoder, cancel, || false).await
}

async fn run_session_inner<R, W, H, F>(
    mut reader: R,
    mut writer: W,
    handler: &H,
    decoder: &mut FrameDecoder,
    cancel: &mut Cancel,
    abandon_on_eof: F,
) -> SessionReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handle,
    F: Fn() -> bool,
{
    let mut buf = vec![0u8; READ_CHUNK];
    let mut received: u64 = 0;
    // Once the sender is gone there is nothing left to wait for.
    let mut cancel_live = true;
    let report = |end, received| SessionReport { end, received };
    // Every frame decoded, in request order, until its reply has left
    // for the outbox.
    let mut slots: VecDeque<Slot<'_>> = VecDeque::new();
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
                outbox.push(reply);
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
        // The oldest commands own the queue's places, from decoding to
        // delivery; frames decoded beyond them wait for a place.
        if !draining && outbox.pending_bytes() < MAX_REPLY_BYTES {
            admit(
                &mut slots,
                handler,
                MAX_QUEUED.saturating_sub(outbox.count()),
            );
        }
        let running = slots.iter().any(|slot| matches!(slot, Slot::Pending(..)));
        if !running
            && slots.is_empty()
            && (outbox.is_empty() || write_failed)
            && let Some(end) = input_end.take()
        {
            return report(end, received);
        }
        let finished_bytes: usize = slots
            .iter()
            .map(|slot| match slot {
                Slot::Done(Some(reply)) => reply.len(),
                _ => 0,
            })
            .sum();
        let can_read = input_end.is_none()
            && !draining
            && slots.len() + outbox.count() < MAX_QUEUED
            && outbox.pending_bytes() + finished_bytes < MAX_REPLY_BYTES;
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
                Ok(0) => {
                    input_end = Some(SessionEnd::Eof);
                    if abandon_on_eof() {
                        // Virtio hangup / reconnect: finish accepted commands
                        // for their side effects and audit records, but discard
                        // undelivered replies so they cannot block on EAGAIN or
                        // bleed into the next connection (§5.7).
                        write_failed = true;
                        outbox.abandon();
                    }
                }
                Ok(n) => {
                    received += n as u64;
                    for event in decoder.push(&buf[..n]) {
                        let kind = handler.classify(&event);
                        slots.push_back(Slot::Waiting(kind, event));
                    }
                },
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

/// Opens the raw channel descriptor without registering it with Tokio yet,
/// retrying non-terminal failures with bounded exponential backoff until it
/// succeeds or `cancel` fires. Keeping the descriptor unregistered until the
/// host connects avoids latching Mio/Tokio's sticky `READ_CLOSED`/`WRITE_CLOSED`
/// bits on an initial virtio-serial `EPOLLHUP` (§5.7).
async fn open_fd_with_retry(
    path: &Path,
    open: &OpenFn,
    cancel: &mut Cancel,
) -> Result<Option<OwnedFd>, OpenError> {
    let mut delay = INITIAL_BACKOFF;
    loop {
        match open(path).map_err(|err| OpenError::from_io(path, err)) {
            Ok(fd) => return Ok(Some(fd)),
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

/// Default poll cadence while waiting for the host side of an open
/// virtio-serial port to connect.
const DEFAULT_HOST_WAIT: Backoff = Backoff {
    initial: HOST_WAIT_INITIAL,
    max: HOST_WAIT_MAX,
};

/// Upper bound of unread driver bytes drained per disconnect observation so a
/// misbehaving or flapping host cannot pin the wait loop (§5.7).
const MAX_DRAIN_BYTES: usize = 64 * 1024;

/// Peer state of an already-open channel descriptor, inferred from a
/// non-blocking `ppoll(2)` probe (§5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostState {
    /// Connected (or no disconnect indicated): start a session.
    Ready,
    /// Open Linux `virtio_console` port whose host side is disconnected:
    /// keep the descriptor open while waiting for the host to connect.
    VirtioHostDisconnected,
    /// Closed peer, hot-unplugged port, or error: close and reopen with
    /// backoff.
    Closed,
}

/// Outcome of waiting for the host side of an open virtio-serial port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostWait {
    Ready,
    Closed,
    Cancelled,
}

/// Linux `POLLRDHUP` (stream socket peer closed or shut down writing); `nix`
/// 0.31 does not expose it as a named [`PollFlags`] constant, so we pass it via
/// `from_bits_retain` and check it explicitly (and `PollFd::revents()` also
/// fails closed to `None` when unknown bits are returned).
const POLLRDHUP_FLAG: PollFlags = PollFlags::from_bits_retain(nix::libc::POLLRDHUP);

#[derive(Debug, Clone, Copy)]
struct ServeTimers {
    reopen: Backoff,
    host_wait: Backoff,
}

fn classify_channel_revents(revents: PollFlags) -> HostState {
    if revents.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL | POLLRDHUP_FLAG) {
        return HostState::Closed;
    }
    if revents.contains(PollFlags::POLLHUP) {
        // Linux `virtio_console` with `guest_connected == true` and
        // `host_connected == false` sets `POLLIN | POLLRDNORM | POLLHUP`
        // while leaving `POLLOUT` clear (`will_write_block` is true when
        // `!host_connected`) and setting neither `POLLERR` nor `POLLRDHUP`.
        // Hot-unplugged virtio ports return bare `POLLHUP` (`POLLIN` clear);
        // closed PTY slaves return `POLLERR`; closed Unix sockets return
        // `POLLOUT | POLLRDHUP`.
        if revents.contains(PollFlags::POLLIN) && !revents.contains(PollFlags::POLLOUT) {
            return HostState::VirtioHostDisconnected;
        }
        return HostState::Closed;
    }
    HostState::Ready
}

fn poll_host_state(fd: BorrowedFd<'_>) -> HostState {
    use nix::poll::{PollFd, ppoll};
    use nix::sys::time::TimeSpec;

    let timeout = TimeSpec::new(0, 0);
    let events = PollFlags::POLLIN | PollFlags::POLLOUT | POLLRDHUP_FLAG;
    loop {
        let mut fds = [PollFd::new(fd, events)];
        match ppoll(&mut fds, Some(timeout), None) {
            Ok(0) => return HostState::Ready,
            Ok(_) => {
                // Unknown bits (including `POLLRDHUP` while `nix` omits it
                // from `PollFlags::all()`) fail closed.
                let revents = fds[0].revents().unwrap_or(PollFlags::POLLERR);
                return classify_channel_revents(revents);
            }
            Err(Errno::EINTR) => continue,
            Err(_) => return HostState::Closed,
        }
    }
}

fn is_host_disconnect_end(end: &SessionEnd) -> bool {
    matches!(end, SessionEnd::Eof)
        || matches!(end, SessionEnd::WriteError(err) if err.kind() == io::ErrorKind::BrokenPipe)
}

/// Discards unread bytes buffered in a non-blocking, host-disconnected
/// virtio-serial port so a partial frame left by a previous host cannot prefix
/// the next connection's first request (§5.7). Callers must have just observed
/// [`HostState::VirtioHostDisconnected`] and ensured `O_NONBLOCK` on `fd`;
/// `probe` is re-checked before any subsequent read so newly connected host
/// traffic is never consumed.
fn drain_disconnected_input<P>(fd: BorrowedFd<'_>, probe: &P) -> HostState
where
    P: Fn(BorrowedFd<'_>) -> HostState + Send + Sync,
{
    let mut buf = [0u8; READ_CHUNK];
    let mut discarded: usize = 0;
    loop {
        match nix::unistd::read(fd, &mut buf) {
            Ok(0) | Err(Errno::EAGAIN) => {
                if discarded > 0 {
                    tracing::debug!(
                        event = "channel_stale_input_discarded",
                        bytes = discarded,
                        "discarded unread bytes from disconnected channel"
                    );
                }
                return HostState::VirtioHostDisconnected;
            }
            Ok(n) => {
                discarded += n;
                if discarded >= MAX_DRAIN_BYTES {
                    tracing::debug!(
                        event = "channel_stale_input_discarded",
                        bytes = discarded,
                        "discarded unread bytes from disconnected channel"
                    );
                    return probe(fd);
                }
                let state = probe(fd);
                if state != HostState::VirtioHostDisconnected {
                    tracing::debug!(
                        event = "channel_stale_input_discarded",
                        bytes = discarded,
                        "discarded unread bytes from disconnected channel"
                    );
                    return state;
                }
            }
            Err(Errno::EINTR) => continue,
            Err(_) => return HostState::Closed,
        }
    }
}

/// Sleeps for `delay` unless `cancel` fires and `handler.may_stop()` allows a
/// stop. Returns `true` when cancelled.
async fn sleep_or_cancel<H: Handle>(
    delay: Duration,
    handler: &H,
    cancel: &mut Cancel,
    cancel_live: &mut bool,
) -> bool {
    if delay.is_zero() {
        return stop_now(cancel, handler);
    }
    tokio::select! {
        () = tokio::time::sleep(delay) => {}
        changed = cancel.changed(), if *cancel_live => {
            *cancel_live = changed.is_ok();
            if stop_now(cancel, handler) {
                return true;
            }
            // Not allowed to stop yet (C-21): keep serving.
        }
    }
    stop_now(cancel, handler)
}

/// Polls a non-blocking, unregistered virtio-serial descriptor until the host
/// connects, the port hot-unplugs, or a stop is allowed. Drains any stale
/// unread input buffered in the driver on each observed disconnect (§5.7).
async fn wait_for_virtio_host<H, P>(
    fd: BorrowedFd<'_>,
    probe: &P,
    handler: &H,
    cancel: &mut Cancel,
    cancel_live: &mut bool,
    wait: Backoff,
) -> HostWait
where
    H: Handle,
    P: Fn(BorrowedFd<'_>) -> HostState + Send + Sync,
{
    let mut delay = wait.initial;
    loop {
        if stop_now(cancel, handler) {
            return HostWait::Cancelled;
        }
        let slept = tokio::select! {
            () = tokio::time::sleep(delay) => true,
            changed = cancel.changed(), if *cancel_live => {
                *cancel_live = changed.is_ok();
                if stop_now(cancel, handler) {
                    return HostWait::Cancelled;
                }
                false
            }
        };
        if stop_now(cancel, handler) {
            return HostWait::Cancelled;
        }
        match probe(fd) {
            HostState::Ready => return HostWait::Ready,
            HostState::Closed => return HostWait::Closed,
            HostState::VirtioHostDisconnected => {
                match drain_disconnected_input(fd, probe) {
                    HostState::Ready => return HostWait::Ready,
                    HostState::Closed => return HostWait::Closed,
                    HostState::VirtioHostDisconnected => {}
                }
                if slept {
                    delay = (delay * 2).clamp(wait.initial, wait.max);
                }
            }
        }
    }
}

async fn serve_inner<H: Handle>(
    path: &Path,
    open: OpenFn,
    handler: &H,
    cancel: Cancel,
    initial: Option<OwnedFd>,
    backoff: Backoff,
) -> Result<(), OpenError> {
    serve_inner_with_probe(
        path,
        open,
        handler,
        cancel,
        initial,
        ServeTimers {
            reopen: backoff,
            host_wait: DEFAULT_HOST_WAIT,
        },
        poll_host_state,
    )
    .await
}

async fn serve_inner_with_probe<H, P>(
    path: &Path,
    open: OpenFn,
    handler: &H,
    mut cancel: Cancel,
    initial: Option<OwnedFd>,
    timers: ServeTimers,
    probe: P,
) -> Result<(), OpenError>
where
    H: Handle,
    P: Fn(BorrowedFd<'_>) -> HostState + Send + Sync,
{
    // An already-open, unregistered descriptor kept across virtio host
    // disconnects (and initialised from `main`'s pre-drop open) so
    // `guest_connected` stays asserted while each connected session receives a
    // fresh Tokio reactor registration (§5.7).
    let mut pending_fd: Option<OwnedFd> = initial;
    // Zero before the first open; afterwards the pause before each reopen.
    let mut reopen_delay = Duration::ZERO;
    // Bounded pacing when an open Ready port reports consecutive empty EOFs.
    let mut empty_eof_delay = Duration::ZERO;
    let mut cancel_live = true;
    loop {
        if stop_now(&mut cancel, handler) {
            return Ok(());
        }
        if pending_fd.is_none()
            && !reopen_delay.is_zero()
            && sleep_or_cancel(reopen_delay, handler, &mut cancel, &mut cancel_live).await
        {
            return Ok(());
        }
        let fd = match pending_fd.take() {
            Some(fd) => fd,
            None => {
                let Some(fd) = open_fd_with_retry(path, &open, &mut cancel).await? else {
                    if handler.may_stop() {
                        return Ok(());
                    }
                    // Stop requested but not allowed yet (C-21): keep
                    // trying to reopen at a bounded cadence.
                    tokio::time::sleep(timers.reopen.initial).await;
                    continue;
                };
                fd
            }
        };
        if let Err(err) = set_nonblocking(fd.as_fd()) {
            reopen_delay = (reopen_delay * 2).clamp(timers.reopen.initial, timers.reopen.max);
            empty_eof_delay = Duration::ZERO;
            tracing::warn!(
                event = "channel_register_failed",
                error = %err,
                "cannot set non-blocking mode on channel; reopening"
            );
            continue;
        }
        if probe(fd.as_fd()) == HostState::VirtioHostDisconnected {
            let after_drain = drain_disconnected_input(fd.as_fd(), &probe);
            match after_drain {
                HostState::Ready => {
                    empty_eof_delay = Duration::ZERO;
                }
                HostState::Closed => {
                    reopen_delay =
                        (reopen_delay * 2).clamp(timers.reopen.initial, timers.reopen.max);
                    empty_eof_delay = Duration::ZERO;
                    tracing::warn!(
                        event = "channel_closed",
                        reason = "eof",
                        received = 0u64,
                        reopen_in_ms = reopen_delay.as_millis() as u64,
                        "channel closed while draining disconnected input; reopening"
                    );
                    continue;
                }
                HostState::VirtioHostDisconnected => {
                    tracing::info!(
                        event = "channel_waiting_for_host",
                        path = %path.display(),
                        "channel open; waiting for host"
                    );
                    match wait_for_virtio_host(
                        fd.as_fd(),
                        &probe,
                        handler,
                        &mut cancel,
                        &mut cancel_live,
                        timers.host_wait,
                    )
                    .await
                    {
                        HostWait::Ready => {
                            empty_eof_delay = Duration::ZERO;
                        }
                        HostWait::Cancelled => return Ok(()),
                        HostWait::Closed => {
                            reopen_delay =
                                (reopen_delay * 2).clamp(timers.reopen.initial, timers.reopen.max);
                            empty_eof_delay = Duration::ZERO;
                            tracing::warn!(
                                event = "channel_closed",
                                reason = "eof",
                                received = 0u64,
                                reopen_in_ms = reopen_delay.as_millis() as u64,
                                "channel closed while waiting for host; reopening"
                            );
                            continue;
                        }
                    }
                }
            }
        }
        let channel = match Channel::from_fd(fd) {
            Ok(channel) => channel,
            Err(err) => {
                reopen_delay = (reopen_delay * 2).clamp(timers.reopen.initial, timers.reopen.max);
                empty_eof_delay = Duration::ZERO;
                tracing::warn!(
                    event = "channel_register_failed",
                    error = %err,
                    "cannot register channel; reopening"
                );
                continue;
            }
        };
        tracing::info!(event = "channel_open", path = %path.display(), "channel open");
        let mut decoder = FrameDecoder::new();
        let report = run_session_inner(
            ChannelRef(&channel),
            ChannelRef(&channel),
            handler,
            &mut decoder,
            &mut cancel,
            || probe(channel.fd.as_fd()) != HostState::Closed,
        )
        .await;
        if matches!(report.end, SessionEnd::Cancelled) {
            return Ok(());
        }
        // Deregister from Tokio before keeping or inspecting the descriptor so
        // any latched READ_CLOSED/WRITE_CLOSED bits from a virtio hangup never
        // carry into the next connected session.
        let fd = channel.into_fd();
        if is_host_disconnect_end(&report.end) {
            match probe(fd.as_fd()) {
                HostState::VirtioHostDisconnected => {
                    if drain_disconnected_input(fd.as_fd(), &probe) != HostState::Closed {
                        tracing::warn!(
                            event = "channel_closed",
                            reason = %report.end,
                            received = report.received,
                            "host disconnected; keeping channel open while waiting for host"
                        );
                        pending_fd = Some(fd);
                        reopen_delay = Duration::ZERO;
                        empty_eof_delay = Duration::ZERO;
                        continue;
                    }
                }
                HostState::Ready => {
                    tracing::warn!(
                        event = "channel_closed",
                        reason = %report.end,
                        received = report.received,
                        "channel session ended; host already connected on open channel"
                    );
                    pending_fd = Some(fd);
                    reopen_delay = Duration::ZERO;
                    if report.received > 0 {
                        empty_eof_delay = Duration::ZERO;
                    } else {
                        if sleep_or_cancel(empty_eof_delay, handler, &mut cancel, &mut cancel_live)
                            .await
                        {
                            return Ok(());
                        }
                        empty_eof_delay = if empty_eof_delay.is_zero() {
                            timers.host_wait.initial
                        } else {
                            (empty_eof_delay * 2)
                                .clamp(timers.host_wait.initial, timers.host_wait.max)
                        };
                    }
                    continue;
                }
                HostState::Closed => {}
            }
        }
        // A session that carried data resets the backoff; a closed/errored
        // descriptor is dropped and reopened with growing backoff.
        empty_eof_delay = Duration::ZERO;
        reopen_delay = if report.received > 0 {
            timers.reopen.initial
        } else {
            (reopen_delay * 2).clamp(timers.reopen.initial, timers.reopen.max)
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
    /// released (`release`, or `release_b` for a frame containing
    /// `holdb`), counts how many run at once and records the order they
    /// started in; replies name the frame (a frame containing `big`
    /// gets a 4 KiB reply, `huge` a 40 KiB one). The lane is the frame's prefix: `ctl-` is a
    /// control, `thaw-` a thaw, `freeze-` a freeze, anything else
    /// ordinary. A finished freeze forbids a stop, a finished thaw allows
    /// it again.
    struct CountingHandler {
        release: tokio::sync::Notify,
        /// Releases the frames containing `holdb` instead.
        release_b: tokio::sync::Notify,
        running: AtomicUsize,
        peak: AtomicUsize,
        started: Mutex<Vec<String>>,
        allow_stop: std::sync::atomic::AtomicBool,
    }

    impl CountingHandler {
        fn new() -> Arc<Self> {
            Arc::new(CountingHandler {
                release: tokio::sync::Notify::new(),
                release_b: tokio::sync::Notify::new(),
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
            if name.contains("holdb") {
                self.release_b.notified().await;
            } else if !name.contains("quick") {
                self.release.notified().await;
            }
            self.running.fetch_sub(1, Ordering::SeqCst);
            if name.starts_with("freeze") {
                self.allow_stop.store(false, Ordering::SeqCst);
            } else if name.starts_with("thaw") {
                self.allow_stop.store(true, Ordering::SeqCst);
            }
            let mut reply = if name.contains("huge") {
                vec![b'x'; 40 * 1024]
            } else if name.contains("big") {
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

    /// A session whose input and output are separate duplex streams, so
    /// the peer can keep sending while it reads nothing: `input` bytes
    /// of request buffer, `output` bytes of reply buffer. Returns the
    /// peer's writer and reader.
    fn counting_session_split(
        input: usize,
        output: usize,
    ) -> (
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
        Arc<CountingHandler>,
        tokio::task::JoinHandle<SessionReport>,
    ) {
        let (peer_tx, reader) = duplex(input);
        let (peer_rx, writer) = duplex(output);
        let (_cancel_tx, mut cancel_rx) = cancel_pair();
        let handler = CountingHandler::new();
        let h = handler.clone();
        let session = tokio::spawn(async move {
            let mut decoder = FrameDecoder::new();
            let report =
                run_session_until(reader, writer, h.as_ref(), &mut decoder, &mut cancel_rx).await;
            drop(_cancel_tx);
            report
        });
        (peer_tx, peer_rx, handler, session)
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
        // Two serial commands: the second is not started while the first
        // runs, whatever the first is doing; a freeze behind an ordinary
        // command waits just the same. A control behind that freeze is
        // not held back by it, and its reply still leaves last.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"slow-1\nfreeze-2\nctl-quick-3\n")
                .await
                .unwrap();
            handler.started_is("ctl-quick-3").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                handler.started(),
                ["slow-1", "ctl-quick-3"],
                "the freeze waits, the control does not"
            );
            nothing_to_read(&mut peer).await;
            handler.release.notify_waiters();
            handler.started_is("freeze-2").await;
            read_exactly(&mut peer, b"slow-1\n").await;
            nothing_to_read(&mut peer).await;
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"freeze-2\nctl-quick-3\n").await;
            assert_eq!(handler.peak.load(Ordering::SeqCst), 2);
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn a_thaw_behind_a_waiting_serial_command_still_reaches_the_freeze() {
        // A freeze runs; an ordinary command waits for the serial lane;
        // the thaw behind it is not held back: it runs beside the freeze
        // at once. The ordinary command runs only once the freeze has
        // finished, and the replies leave in request order.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(1024);
            peer.write_all(b"freeze-1\nslow-2\nthaw-quick-3\n")
                .await
                .unwrap();
            handler.started_is("thaw-quick-3").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(handler.started(), ["freeze-1", "thaw-quick-3"]);
            handler.release.notify_waiters();
            handler.started_is("slow-2").await;
            read_exactly(&mut peer, b"freeze-1\n").await;
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"slow-2\nthaw-quick-3\n").await;
            drop(peer);
            session.await.unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn bypassed_replies_cannot_consume_the_head_waiters_admission_credit() {
        // Ten frames in one read: a freeze, an ordinary command that
        // waits for the serial lane, a thaw that overtakes it and stays
        // pending beside the freeze, seven quick controls. The freeze
        // finishes and its reply is read; the thaw finishes last. The
        // controls that overtook the ordinary command must not have used
        // up the place it needs: it starts as soon as the thaw is done,
        // and every reply leaves in request order, the peer reading all
        // along.
        bounded(async {
            let (mut peer, handler, _cancel, session) = counting_session(4096);
            let mut frames = b"freeze-1\nquick-2\nthaw-holdb-3\n".to_vec();
            let mut expected = frames.clone();
            for i in 4..=10 {
                frames.extend(format!("ctl-quick-{i}\n").into_bytes());
                expected.extend(format!("ctl-quick-{i}\n").into_bytes());
            }
            peer.write_all(&frames).await.unwrap();
            handler.started_is("thaw-holdb-3").await;
            handler.started_is("ctl-quick-8").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            let started = handler.started();
            assert!(!started.contains(&"quick-2".to_owned()), "{started:?}");
            assert_eq!(
                started.len(),
                7,
                "the oldest MAX_QUEUED own the places: {started:?}"
            );
            handler.release.notify_waiters();
            read_exactly(&mut peer, b"freeze-1\n").await;
            handler.started_is("ctl-quick-9").await;
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(
                !handler.started().contains(&"quick-2".to_owned()),
                "still behind the pending thaw"
            );
            handler.release_b.notify_waiters();
            handler.started_is("quick-2").await;
            read_exactly(&mut peer, &expected[b"freeze-1\n".len()..]).await;
            assert_eq!(handler.started().len(), 10);
            drop(peer);
            let report = session.await.unwrap();
            assert!(matches!(report.end, SessionEnd::Eof), "{}", report.end);
        })
        .await;
    }

    #[tokio::test]
    async fn undelivered_replies_hold_their_place_until_the_host_takes_them() {
        // The peer keeps the port open and reads nothing. Each control
        // finishes at once, but its reply stays undelivered and keeps
        // counting: after MAX_QUEUED of them nothing more is read, however
        // many frames the peer sends. Once the peer reads, every reply
        // arrives once, in order, and the session serves the rest.
        bounded(async {
            let (mut tx, mut rx, handler, session) = counting_session_split(4096, 8);
            let mut expected = Vec::new();
            for i in 1..=MAX_QUEUED {
                let frame = format!("ctl-quick-{i}");
                tx.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
                handler.started_is(&frame).await;
                expected.extend(format!("{frame}\n").into_bytes());
            }
            for i in MAX_QUEUED + 1..=3 * MAX_QUEUED {
                let frame = format!("ctl-quick-{i}");
                tx.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
                expected.extend(format!("{frame}\n").into_bytes());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                handler.started().len(),
                MAX_QUEUED,
                "nothing is read while MAX_QUEUED replies are undelivered"
            );
            read_exactly(&mut rx, &expected).await;
            handler
                .started_is(&format!("ctl-quick-{}", 3 * MAX_QUEUED))
                .await;
            drop(tx);
            let report = session.await.unwrap();
            assert!(matches!(report.end, SessionEnd::Eof), "{}", report.end);
        })
        .await;
    }

    #[tokio::test]
    async fn the_reply_budget_pauses_the_session_before_the_count_does() {
        // Two 40 KiB replies exceed MAX_REPLY_BYTES: the third frame is
        // neither read nor started while the peer reads nothing, well
        // under MAX_QUEUED commands. Once the peer drains the replies,
        // in order and unduplicated, the rest are served.
        bounded(async {
            const { assert!(2 * 40 * 1024 > MAX_REPLY_BYTES && 40 * 1024 < MAX_REPLY_BYTES) };
            let (mut tx, mut rx, handler, session) = counting_session_split(4096, 1024);
            let mut expected = Vec::new();
            for i in 1..=4 {
                let frame = format!("ctl-huge-quick-{i}");
                if i > 2 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                tx.write_all(format!("{frame}\n").as_bytes()).await.unwrap();
                if i <= 2 {
                    handler.started_is(&frame).await;
                }
                let mut reply = vec![b'x'; 40 * 1024];
                reply.push(b'\n');
                expected.extend(reply);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(handler.started().len(), 2, "the budget holds the third");
            read_exactly(&mut rx, &expected).await;
            assert_eq!(handler.started().len(), 4);
            drop(tx);
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
        raw_mode(&channel.fd);
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

    #[test]
    fn classify_channel_revents_distinguishes_virtio_host_disconnect_from_closed_peers() {
        // Ready states (connected peer, including full TX queue with empty revents).
        assert_eq!(
            classify_channel_revents(PollFlags::empty()),
            HostState::Ready
        );
        assert_eq!(
            classify_channel_revents(PollFlags::POLLOUT),
            HostState::Ready
        );
        assert_eq!(
            classify_channel_revents(PollFlags::POLLIN | PollFlags::POLLOUT),
            HostState::Ready
        );
        assert_eq!(
            classify_channel_revents(PollFlags::POLLIN),
            HostState::Ready
        );

        // Linux virtio_console with guest_connected=true, host_connected=false:
        // POLLIN | [POLLRDNORM |] POLLHUP, no POLLOUT / POLLERR / POLLRDHUP.
        assert_eq!(
            classify_channel_revents(PollFlags::POLLIN | PollFlags::POLLHUP),
            HostState::VirtioHostDisconnected
        );
        assert_eq!(
            classify_channel_revents(
                PollFlags::POLLIN | PollFlags::POLLRDNORM | PollFlags::POLLHUP
            ),
            HostState::VirtioHostDisconnected
        );

        // Hot-unplugged virtio port or drained closed pipe: bare POLLHUP.
        assert_eq!(
            classify_channel_revents(PollFlags::POLLHUP),
            HostState::Closed
        );
        // Dead Unix socketpair.
        assert_eq!(
            classify_channel_revents(
                PollFlags::POLLIN | PollFlags::POLLOUT | PollFlags::POLLHUP | POLLRDHUP_FLAG
            ),
            HostState::Closed
        );
        assert_eq!(
            classify_channel_revents(PollFlags::POLLIN | PollFlags::POLLOUT | PollFlags::POLLHUP),
            HostState::Closed
        );
        // Half-closed Unix socketpair (peer shutdown(SHUT_WR)).
        assert_eq!(
            classify_channel_revents(PollFlags::POLLIN | PollFlags::POLLOUT | POLLRDHUP_FLAG),
            HostState::Closed
        );
        // Dead PTY slave (master closed).
        assert_eq!(
            classify_channel_revents(
                PollFlags::POLLIN | PollFlags::POLLOUT | PollFlags::POLLERR | PollFlags::POLLHUP
            ),
            HostState::Closed
        );
        // Error / invalid descriptor flags fail closed.
        assert_eq!(
            classify_channel_revents(PollFlags::POLLIN | PollFlags::POLLERR | PollFlags::POLLHUP),
            HostState::Closed
        );
        assert_eq!(
            classify_channel_revents(PollFlags::POLLNVAL),
            HostState::Closed
        );
    }

    #[test]
    fn poll_host_state_classifies_real_socketpair_and_pty_descriptors() {
        // Connected, half-closed, and dead Unix socketpairs.
        let (ours, peer) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        assert_eq!(poll_host_state(ours.as_fd()), HostState::Ready);
        nix::sys::socket::shutdown(peer.as_raw_fd(), nix::sys::socket::Shutdown::Write).unwrap();
        assert_eq!(poll_host_state(ours.as_fd()), HostState::Closed);
        drop(peer);
        assert_eq!(poll_host_state(ours.as_fd()), HostState::Closed);

        // Connected and closed PTY slave.
        let master = nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).unwrap();
        nix::pty::grantpt(&master).unwrap();
        nix::pty::unlockpt(&master).unwrap();
        let slave_path = nix::pty::ptsname_r(&master).unwrap();
        let slave = open_device(Path::new(&slave_path)).unwrap();
        assert_eq!(poll_host_state(slave.as_fd()), HostState::Ready);
        drop(master);
        assert_eq!(poll_host_state(slave.as_fd()), HostState::Closed);
    }

    #[tokio::test(start_paused = true)]
    async fn wait_for_virtio_host_waits_for_ready_handles_hot_unplug_and_honours_deferred_stop() {
        let (ours, _peer) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::Stream,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        set_nonblocking(ours.as_fd()).unwrap();
        let wait = Backoff {
            initial: Duration::from_millis(10),
            max: Duration::from_millis(50),
        };

        // Case A: VirtioHostDisconnected × 3 -> Ready, with exponential backoff clamped to max.
        let polls = AtomicUsize::new(0);
        let (_tx, mut cancel) = cancel_pair();
        let mut cancel_live = true;
        let handler = FakeDispatcher::default();
        let start = tokio::time::Instant::now();
        let outcome = wait_for_virtio_host(
            ours.as_fd(),
            &|_| {
                if polls.fetch_add(1, Ordering::SeqCst) < 3 {
                    HostState::VirtioHostDisconnected
                } else {
                    HostState::Ready
                }
            },
            &handler,
            &mut cancel,
            &mut cancel_live,
            wait,
        )
        .await;
        assert_eq!(outcome, HostWait::Ready);
        assert_eq!(polls.load(Ordering::SeqCst), 4);
        // 4 sleeps before 4 probes: 10 ms + 20 ms + 40 ms + 50 ms (clamped) = 120 ms.
        assert_eq!(start.elapsed(), Duration::from_millis(120));

        // Case B: hot-unplug while waiting returns Closed.
        let polls = AtomicUsize::new(0);
        let (_tx, mut cancel) = cancel_pair();
        let mut cancel_live = true;
        let outcome = wait_for_virtio_host(
            ours.as_fd(),
            &|_| {
                if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    HostState::VirtioHostDisconnected
                } else {
                    HostState::Closed
                }
            },
            &handler,
            &mut cancel,
            &mut cancel_live,
            wait,
        )
        .await;
        assert_eq!(outcome, HostWait::Closed);
        assert_eq!(polls.load(Ordering::SeqCst), 2);

        // Case C: cancel when may_stop() == true returns Cancelled immediately without waiting.
        let (tx, mut cancel) = cancel_pair();
        let mut cancel_live = true;
        let long_wait = Backoff {
            initial: Duration::from_secs(10),
            max: Duration::from_secs(10),
        };
        let start = tokio::time::Instant::now();
        let stopper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            tx.send(true).unwrap();
        });
        let outcome = wait_for_virtio_host(
            ours.as_fd(),
            &|_| HostState::VirtioHostDisconnected,
            &handler,
            &mut cancel,
            &mut cancel_live,
            long_wait,
        )
        .await;
        stopper.await.unwrap();
        assert_eq!(outcome, HostWait::Cancelled);
        assert_eq!(start.elapsed(), Duration::from_millis(5));

        // Case D: cancel while may_stop() == false (Frozen, C-21) is deferred until thaw.
        let slow = Arc::new(SlowHandler {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            allow_stop: std::sync::atomic::AtomicBool::new(false),
            finished: std::sync::atomic::AtomicBool::new(false),
        });
        let (tx, mut cancel) = cancel_pair();
        let mut cancel_live = true;
        let slow_flip = slow.clone();
        let start = tokio::time::Instant::now();
        let driver = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            tx.send(true).unwrap(); // Arrives while frozen: must not stop yet.
            tokio::time::sleep(Duration::from_millis(30)).await;
            slow_flip.allow_stop.store(true, Ordering::SeqCst);
            tx.send(true).unwrap(); // Thawed: now stop may take effect.
        });
        let outcome = wait_for_virtio_host(
            ours.as_fd(),
            &|_| HostState::VirtioHostDisconnected,
            slow.as_ref(),
            &mut cancel,
            &mut cancel_live,
            wait,
        )
        .await;
        driver.await.unwrap();
        assert_eq!(outcome, HostWait::Cancelled);
        assert_eq!(start.elapsed(), Duration::from_millis(35));
    }

    #[tokio::test]
    async fn serve_keeps_virtio_fd_open_while_waiting_for_host_to_connect() {
        bounded(async {
            let (ours, peer) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::SeqPacket,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            let opened = Arc::new(AtomicUsize::new(0));
            let o = opened.clone();
            let open: OpenFn = Arc::new(move |_| {
                o.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::from_raw_os_error(nix::libc::ENOENT))
            });
            // Pass the pre-opened fd via `initial` (the `main` pre-drop path):
            // 3 VirtioHostDisconnected probes, then Ready.
            let probes = Arc::new(AtomicUsize::new(0));
            let p = probes.clone();
            let handler = Arc::new(FakeDispatcher::default());
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve_inner_with_probe(
                    Path::new("/dev/virtio-ports/fake"),
                    open,
                    h.as_ref(),
                    cancel,
                    Some(ours),
                    ServeTimers {
                        reopen: TEST_BACKOFF,
                        host_wait: Backoff {
                            initial: Duration::from_millis(5),
                            max: Duration::from_millis(20),
                        },
                    },
                    move |_| {
                        if p.fetch_add(1, Ordering::SeqCst) < 3 {
                            HostState::VirtioHostDisconnected
                        } else {
                            HostState::Ready
                        }
                    },
                )
                .await
            });
            let mut peer = Channel::from_fd(peer).unwrap();
            while probes.load(Ordering::SeqCst) < 4 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            peer.write_all(b"ping\n").await.unwrap();
            let mut out = [0u8; 16];
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"PING\n");
            assert!(
                probes.load(Ordering::SeqCst) >= 4,
                "waited through host-disconnected polls before serving"
            );
            assert_eq!(
                opened.load(Ordering::SeqCst),
                0,
                "initial descriptor was kept open without reopening"
            );
            tx.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn serve_keeps_virtio_fd_open_across_host_disconnect_and_discards_partial_frame() {
        bounded(async {
            let (ours, peer) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::SeqPacket,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            let first = Arc::new(Mutex::new(Some(ours)));
            let opened = Arc::new(AtomicUsize::new(0));
            let o = opened.clone();
            let open: OpenFn = Arc::new(move |_| {
                o.fetch_add(1, Ordering::SeqCst);
                first
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::ENOENT))
            });
            // 0 = Ready, 1 = VirtioHostDisconnected
            let mode = Arc::new(AtomicUsize::new(0));
            let wait_probes = Arc::new(AtomicUsize::new(0));
            let m = mode.clone();
            let wp = wait_probes.clone();
            let handler = Arc::new(FakeDispatcher::default());
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve_inner_with_probe(
                    Path::new("/dev/virtio-ports/fake"),
                    open,
                    h.as_ref(),
                    cancel,
                    None,
                    ServeTimers {
                        reopen: TEST_BACKOFF,
                        host_wait: Backoff {
                            initial: Duration::from_millis(5),
                            max: Duration::from_millis(20),
                        },
                    },
                    move |_| {
                        if m.load(Ordering::SeqCst) == 0 {
                            HostState::Ready
                        } else {
                            wp.fetch_add(1, Ordering::SeqCst);
                            HostState::VirtioHostDisconnected
                        }
                    },
                )
                .await
            });
            let mut peer = Channel::from_fd(peer).unwrap();

            // Session 1: send one complete frame plus a trailing partial frame.
            peer.write_all(b"one\npartial-without-newline")
                .await
                .unwrap();
            let mut out = [0u8; 32];
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"ONE\n");

            // Host disconnects: flip probe and deliver a 0-byte packet (EOF) on the open socket.
            mode.store(1, Ordering::SeqCst);
            nix::sys::socket::send(peer.as_raw_fd(), &[], nix::sys::socket::MsgFlags::empty())
                .unwrap();
            while wait_probes.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(
                opened.load(Ordering::SeqCst),
                1,
                "descriptor must remain open across host disconnect"
            );

            // Host reconnects: fresh decoder discards the partial frame from session 1.
            mode.store(0, Ordering::SeqCst);
            peer.write_all(b"two\n").await.unwrap();
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"TWO\n");
            assert_eq!(opened.load(Ordering::SeqCst), 1);

            // Fast reconnect: host disconnects and reconnects before probe runs (Ready + received > 0).
            peer.write_all(b"three\npartial-two").await.unwrap();
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"THREE\n");
            nix::sys::socket::send(peer.as_raw_fd(), &[], nix::sys::socket::MsgFlags::empty())
                .unwrap();
            peer.write_all(b"four\n").await.unwrap();
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(&out[..n], b"FOUR\n");
            assert_eq!(
                opened.load(Ordering::SeqCst),
                1,
                "fast reconnect keeps the open descriptor without reopening"
            );

            tx.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn serve_closes_and_reopens_when_virtio_port_hot_unplugs_while_waiting() {
        bounded(async {
            let (ours1, peer1) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::Stream,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            let (ours2, peer2) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::Stream,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            let fds = Arc::new(Mutex::new(VecDeque::from([ours1, ours2])));
            let opened = Arc::new(AtomicUsize::new(0));
            let o = opened.clone();
            let open: OpenFn = Arc::new(move |_| {
                o.fetch_add(1, Ordering::SeqCst);
                fds.lock()
                    .unwrap()
                    .pop_front()
                    .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::ENOENT))
            });
            // Probe 0: VirtioHostDisconnected (enters wait), Probe 1: Closed (hot-unplug!),
            // Probe 2+: Ready (second opened fd).
            let probes = Arc::new(AtomicUsize::new(0));
            let p = probes.clone();
            let handler = Arc::new(FakeDispatcher::default());
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve_inner_with_probe(
                    Path::new("/dev/virtio-ports/fake"),
                    open,
                    h.as_ref(),
                    cancel,
                    None,
                    ServeTimers {
                        reopen: TEST_BACKOFF,
                        host_wait: Backoff {
                            initial: Duration::from_millis(5),
                            max: Duration::from_millis(20),
                        },
                    },
                    move |_| match p.fetch_add(1, Ordering::SeqCst) {
                        0 => HostState::VirtioHostDisconnected,
                        1 => HostState::Closed,
                        _ => HostState::Ready,
                    },
                )
                .await
            });

            // First fd must be dropped when hot-unplugged while waiting.
            let mut peer1 = Channel::from_fd(peer1).unwrap();
            let mut buf = [0u8; 16];
            assert_eq!(peer1.read(&mut buf).await.unwrap(), 0, "first fd closed");

            // Second fd opens after backoff and serves commands normally.
            let mut peer2 = Channel::from_fd(peer2).unwrap();
            peer2.write_all(b"after\n").await.unwrap();
            let n = peer2.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"AFTER\n");
            assert_eq!(opened.load(Ordering::SeqCst), 2);

            tx.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await;
    }

    #[test]
    fn is_host_disconnect_end_matches_eof_and_broken_pipe_only() {
        assert!(is_host_disconnect_end(&SessionEnd::Eof));
        assert!(is_host_disconnect_end(&SessionEnd::WriteError(
            io::Error::from(io::ErrorKind::BrokenPipe)
        )));
        assert!(!is_host_disconnect_end(&SessionEnd::WriteError(
            io::Error::from(io::ErrorKind::Other)
        )));
        assert!(!is_host_disconnect_end(&SessionEnd::ReadError(
            io::Error::from(io::ErrorKind::BrokenPipe)
        )));
        assert!(!is_host_disconnect_end(&SessionEnd::Cancelled));
    }

    #[tokio::test]
    async fn serve_refreshes_reactor_registration_after_real_epollhup_on_idle_reconnect() {
        bounded(async {
            // Real Linux FIFO: closing writer1 delivers an actual kernel
            // EPOLLHUP into Tokio's epoll reactor (latching sticky READ_CLOSED
            // on the old AsyncFd), and opening an idle writer2 clears POLLHUP
            // so `read(2)` returns EAGAIN. `serve` must refresh the Tokio
            // registration so the idle reconnected port parks cleanly without
            // spinning or repeatedly ending sessions, while keeping the same
            // underlying fd open (`opened == 0`).
            let dir = tempfile::tempdir().unwrap();
            let fifo = dir.path().join("virtio-sim.fifo");
            nix::unistd::mkfifo(&fifo, Mode::S_IRWXU).unwrap();

            let reader = open(
                &fifo,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .unwrap();
            let writer1 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();

            let opened = Arc::new(AtomicUsize::new(0));
            let o = opened.clone();
            let open_fn: OpenFn = Arc::new(move |_| {
                o.fetch_add(1, Ordering::SeqCst);
                Err(io::Error::from_raw_os_error(nix::libc::ENOENT))
            });
            let hup_probes = Arc::new(AtomicUsize::new(0));
            let ready_probes = Arc::new(AtomicUsize::new(0));
            let hp = hup_probes.clone();
            let rp = ready_probes.clone();
            let handler = Arc::new(FakeDispatcher::default());
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve_inner_with_probe(
                    Path::new("/dev/virtio-ports/fake"),
                    open_fn,
                    h.as_ref(),
                    cancel,
                    Some(reader),
                    ServeTimers {
                        reopen: TEST_BACKOFF,
                        host_wait: Backoff {
                            initial: Duration::from_millis(5),
                            max: Duration::from_millis(20),
                        },
                    },
                    move |fd| {
                        use nix::poll::{PollFd, ppoll};
                        use nix::sys::time::TimeSpec;
                        let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
                        let revents = match ppoll(&mut fds, Some(TimeSpec::new(0, 0)), None) {
                            Ok(0) => PollFlags::empty(),
                            Ok(_) => fds[0].revents().unwrap_or(PollFlags::POLLERR),
                            Err(_) => PollFlags::POLLERR,
                        };
                        if revents.contains(PollFlags::POLLHUP) {
                            hp.fetch_add(1, Ordering::SeqCst);
                            HostState::VirtioHostDisconnected
                        } else {
                            rp.fetch_add(1, Ordering::SeqCst);
                            HostState::Ready
                        }
                    },
                )
                .await
            });

            // Session 1: `shutdown*` yields no reply (FIFO reader is O_RDONLY).
            nix::unistd::write(&writer1, b"shutdown1\n").unwrap();
            while handler.seen.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // Let the session park on epoll before writer1 closes so the
            // kernel delivers a real EPOLLHUP into the registered AsyncFd.
            tokio::time::sleep(Duration::from_millis(25)).await;
            drop(writer1);

            while hup_probes.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            // Reconnect an idle writer2: POLLHUP clears and read() returns EAGAIN.
            let writer2 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
            let start_ready = ready_probes.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(120)).await;
            let delta_ready = ready_probes.load(Ordering::SeqCst) - start_ready;
            assert!(
                delta_ready <= 2,
                "idle reconnected port must park on a fresh AsyncFd instead of spinning/re-probing ({delta_ready} probes in 120 ms)"
            );
            assert_eq!(
                opened.load(Ordering::SeqCst),
                0,
                "initial descriptor stayed open across EPOLLHUP and idle reconnect"
            );

            nix::unistd::write(&writer2, b"shutdown2\n").unwrap();
            while handler.seen.lock().unwrap().len() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(opened.load(Ordering::SeqCst), 0);
            tx.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn serve_abandons_undelivered_replies_on_virtio_disconnect_while_finishing_commands() {
        bounded(async {
            let (ours, peer) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::SeqPacket,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            let first = Arc::new(Mutex::new(Some(ours)));
            let opened = Arc::new(AtomicUsize::new(0));
            let o = opened.clone();
            let open: OpenFn = Arc::new(move |_| {
                o.fetch_add(1, Ordering::SeqCst);
                first
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::ENOENT))
            });
            let mode = Arc::new(AtomicUsize::new(0));
            let wait_probes = Arc::new(AtomicUsize::new(0));
            let m = mode.clone();
            let wp = wait_probes.clone();
            let handler = CountingHandler::new();
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve_inner_with_probe(
                    Path::new("/dev/virtio-ports/fake"),
                    open,
                    h.as_ref(),
                    cancel,
                    None,
                    ServeTimers {
                        reopen: TEST_BACKOFF,
                        host_wait: Backoff {
                            initial: Duration::from_millis(5),
                            max: Duration::from_millis(20),
                        },
                    },
                    move |_| {
                        if m.load(Ordering::SeqCst) == 0 {
                            HostState::Ready
                        } else {
                            wp.fetch_add(1, Ordering::SeqCst);
                            HostState::VirtioHostDisconnected
                        }
                    },
                )
                .await
            });
            let mut peer = Channel::from_fd(peer).unwrap();

            // Start a command that blocks until released.
            peer.write_all(b"slow-1\n").await.unwrap();
            handler.running_is(1).await;

            // Host disconnects while `slow-1` is still running.
            mode.store(1, Ordering::SeqCst);
            nix::sys::socket::send(peer.as_raw_fd(), &[], nix::sys::socket::MsgFlags::empty())
                .unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert_eq!(
                handler.running.load(Ordering::SeqCst),
                1,
                "accepted command must finish on disconnect"
            );

            // Release `slow-1`: it completes, its reply is abandoned, and serve
            // moves into the host-disconnected wait on the same open fd.
            handler.release.notify_waiters();
            while wait_probes.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert_eq!(handler.running.load(Ordering::SeqCst), 0);
            assert_eq!(handler.started(), ["slow-1"]);

            // Next connection must receive ONLY its own reply, never `slow-1\n`.
            mode.store(0, Ordering::SeqCst);
            peer.write_all(b"quick-2\n").await.unwrap();
            let mut out = [0u8; 32];
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(
                &out[..n],
                b"quick-2\n",
                "old session reply must be abandoned, never delivered to the next connection"
            );
            assert_eq!(opened.load(Ordering::SeqCst), 1);

            tx.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn serve_drains_unread_kernel_bytes_on_observed_virtio_disconnect() {
        bounded(async {
            let (ours, peer) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::SeqPacket,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            // Buffer a partial frame in the kernel BEFORE serve ever reads from
            // the descriptor (simulating unread input retained by Linux
            // virtio_console when a prior host closed).
            nix::unistd::write(&peer, b"stale-before-open").unwrap();

            let first = Arc::new(Mutex::new(Some(ours)));
            let opened = Arc::new(AtomicUsize::new(0));
            let o = opened.clone();
            let open: OpenFn = Arc::new(move |_| {
                o.fetch_add(1, Ordering::SeqCst);
                first
                    .lock()
                    .unwrap()
                    .take()
                    .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::ENOENT))
            });
            let mode = Arc::new(AtomicUsize::new(1)); // start VirtioHostDisconnected
            let wait_probes = Arc::new(AtomicUsize::new(0));
            let m = mode.clone();
            let wp = wait_probes.clone();
            let handler = Arc::new(FakeDispatcher::default());
            let (tx, cancel) = cancel_pair();
            let h = handler.clone();
            let server = tokio::spawn(async move {
                serve_inner_with_probe(
                    Path::new("/dev/virtio-ports/fake"),
                    open,
                    h.as_ref(),
                    cancel,
                    None,
                    ServeTimers {
                        reopen: TEST_BACKOFF,
                        host_wait: Backoff {
                            initial: Duration::from_millis(5),
                            max: Duration::from_millis(20),
                        },
                    },
                    move |_| {
                        if m.load(Ordering::SeqCst) == 0 {
                            HostState::Ready
                        } else {
                            wp.fetch_add(1, Ordering::SeqCst);
                            HostState::VirtioHostDisconnected
                        }
                    },
                )
                .await
            });
            let mut peer = Channel::from_fd(peer).unwrap();

            // Wait until disconnected state has been observed and drained.
            while wait_probes.load(Ordering::SeqCst) < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            mode.store(0, Ordering::SeqCst);
            peer.write_all(b"fresh1\n").await.unwrap();
            let mut out = [0u8; 64];
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(
                &out[..n],
                b"FRESH1\n",
                "unread bytes buffered before open must be drained while disconnected"
            );

            // Disconnect again, inject unread partial bytes while disconnected
            // (simulating a peer connecting, sending a partial frame, and
            // disconnecting between two probes), wait for a probe to drain it,
            // then connect a new peer.
            let base_probes = wait_probes.load(Ordering::SeqCst);
            mode.store(1, Ordering::SeqCst);
            nix::sys::socket::send(peer.as_raw_fd(), &[], nix::sys::socket::MsgFlags::empty())
                .unwrap();
            while wait_probes.load(Ordering::SeqCst) < base_probes + 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            peer.write_all(b"stale-during-wait").await.unwrap();
            let mid_probes = wait_probes.load(Ordering::SeqCst);
            while wait_probes.load(Ordering::SeqCst) < mid_probes + 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            mode.store(0, Ordering::SeqCst);
            peer.write_all(b"fresh2\n").await.unwrap();
            let n = peer.read(&mut out).await.unwrap();
            assert_eq!(
                &out[..n],
                b"FRESH2\n",
                "unread bytes buffered between disconnected probes must be drained"
            );
            assert_eq!(opened.load(Ordering::SeqCst), 1);

            tx.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn serve_preserves_idle_port_on_fast_reconnect_before_first_request_and_paces_empty_eofs()
    {
        let (ours, peer) = nix::sys::socket::socketpair(
            nix::sys::socket::AddressFamily::Unix,
            nix::sys::socket::SockType::SeqPacket,
            None,
            nix::sys::socket::SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        set_nonblocking(peer.as_fd()).unwrap();
        let first = Arc::new(Mutex::new(Some(ours)));
        let opened = Arc::new(AtomicUsize::new(0));
        let o = opened.clone();
        let open: OpenFn = Arc::new(move |_| {
            o.fetch_add(1, Ordering::SeqCst);
            first
                .lock()
                .unwrap()
                .take()
                .ok_or_else(|| io::Error::from_raw_os_error(nix::libc::ENOENT))
        });
        let handler = Arc::new(FakeDispatcher::default());
        let (tx, cancel) = cancel_pair();
        let h = handler.clone();
        let server = tokio::spawn(async move {
            serve_inner_with_probe(
                Path::new("/dev/virtio-ports/fake"),
                open,
                h.as_ref(),
                cancel,
                None,
                ServeTimers {
                    reopen: TEST_BACKOFF,
                    host_wait: Backoff {
                        initial: Duration::from_millis(15),
                        max: Duration::from_millis(60),
                    },
                },
                |_| HostState::Ready,
            )
            .await
        });

        let try_read_peer = |peer: &OwnedFd| -> Option<Vec<u8>> {
            let mut out = [0u8; 32];
            match nix::unistd::read(peer, &mut out) {
                Ok(n) => Some(out[..n].to_vec()),
                Err(Errno::EAGAIN) => None,
                Err(err) => panic!("unexpected peer read error: {err}"),
            }
        };

        // Fast reconnect BEFORE the first request (received == 0 while probe
        // already observes Ready): must keep the descriptor open and answer the
        // new peer's first request at t = 0 without reopening or sleeping.
        let t0 = tokio::time::Instant::now();
        nix::sys::socket::send(peer.as_raw_fd(), &[], nix::sys::socket::MsgFlags::empty()).unwrap();
        nix::unistd::write(&peer, b"first\n").unwrap();
        let mut reply = None;
        for _ in 0..32 {
            tokio::task::yield_now().await;
            if let Some(bytes) = try_read_peer(&peer) {
                reply = Some(bytes);
                break;
            }
        }
        assert_eq!(reply.as_deref(), Some(&b"FIRST\n"[..]));
        assert_eq!(
            t0.elapsed(),
            Duration::ZERO,
            "first idle fast reconnect must incur zero virtual delay"
        );
        assert_eq!(
            opened.load(Ordering::SeqCst),
            1,
            "idle fast reconnect before first request must not reopen"
        );

        // End the `first\n` session (received > 0, resetting pacing to 0),
        // then send 4 consecutive empty EOFs with Ready followed by `after\n`.
        // The 4 empty sessions must be paced by 0 + 15 + 30 + 60 = 105 ms of
        // virtual time while keeping the single descriptor open (`opened == 1`).
        let start = tokio::time::Instant::now();
        for _ in 0..5 {
            nix::sys::socket::send(peer.as_raw_fd(), &[], nix::sys::socket::MsgFlags::empty())
                .unwrap();
        }
        nix::unistd::write(&peer, b"after\n").unwrap();
        // Pump the reactor at t = 0 so `server` wakes from epoll, finishes the
        // `first\n` session, handles the unpaced first empty EOF, and arms the
        // 15 ms sleep at virtual t = 0.
        tokio::time::advance(Duration::ZERO).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(try_read_peer(&peer), None, "must be paused at t = 0");

        // Advance step-by-step across 15 ms, 30 ms, and 60 ms sleeps; `AFTER\n`
        // must NOT arrive before the full 105 ms virtual backoff elapses.
        for step in [14u64, 1, 29, 1, 59] {
            tokio::time::advance(Duration::from_millis(step)).await;
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                try_read_peer(&peer),
                None,
                "reply arrived too early at {:?}",
                start.elapsed()
            );
        }
        tokio::time::advance(Duration::from_millis(1)).await;
        let mut after = None;
        for _ in 0..32 {
            tokio::task::yield_now().await;
            if let Some(bytes) = try_read_peer(&peer) {
                after = Some(bytes);
                break;
            }
        }
        assert_eq!(after.as_deref(), Some(&b"AFTER\n"[..]));
        assert_eq!(
            start.elapsed(),
            Duration::from_millis(105),
            "repeated empty EOFs must complete at exact 15 + 30 + 60 ms virtual pacing"
        );
        assert_eq!(opened.load(Ordering::SeqCst), 1);

        tx.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}
