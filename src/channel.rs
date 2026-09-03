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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::watch;

use crate::dispatch::Dispatcher;
use crate::framing::{DecodeEvent, FrameDecoder};

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
}

impl Handle for Dispatcher {
    fn handle(&self, event: DecodeEvent) -> impl Future<Output = Option<Vec<u8>>> + Send {
        Dispatcher::handle(self, event)
    }
}

/// Why a session ended.
#[derive(Debug)]
pub enum SessionEnd {
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
    mut reader: R,
    mut writer: W,
    handler: &H,
    decoder: &mut FrameDecoder,
) -> SessionReport
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    H: Handle,
{
    let mut buf = vec![0u8; READ_CHUNK];
    let mut received: u64 = 0;
    let report = |end, received| SessionReport { end, received };
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) => return report(SessionEnd::Eof, received),
            Ok(n) => n,
            Err(err) => return report(SessionEnd::ReadError(err), received),
        };
        received += n as u64;
        for event in decoder.push(&buf[..n]) {
            if let Some(reply) = handler.handle(event).await {
                if let Err(err) = writer.write_all(&reply).await {
                    return report(SessionEnd::WriteError(err), received);
                }
                if let Err(err) = writer.flush().await {
                    return report(SessionEnd::WriteError(err), received);
                }
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
    loop {
        if *cancel.borrow() {
            return Ok(());
        }
        if !reopen_delay.is_zero() {
            tokio::select! {
                () = tokio::time::sleep(reopen_delay) => {}
                () = wait_cancel(&mut cancel) => return Ok(()),
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
                    return Ok(());
                };
                channel
            }
        };
        tracing::info!(event = "channel_open", path = %path.display(), "channel open");
        let (reader, writer) = tokio::io::split(channel);
        let mut decoder = FrameDecoder::new();
        let report = tokio::select! {
            report = run_session(reader, writer, handler, &mut decoder) => report,
            _ = wait_cancel(&mut cancel) => return Ok(()),
        };
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

async fn wait_cancel(cancel: &mut Cancel) {
    while !*cancel.borrow() {
        if cancel.changed().await.is_err() {
            return;
        }
    }
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::duplex;

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
    }

    #[tokio::test]
    async fn write_error_ends_session_without_panic() {
        struct FailingWriter;
        impl AsyncWrite for FailingWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut TaskContext<'_>,
                _: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Err(io::Error::from_raw_os_error(Errno::EPIPE as i32)))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
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
        // Two sessions over the same `serve` loop: the first ends after a
        // partial frame; the second must not see it. The freeze state
        // machine handed to the (fake) dispatcher stays Frozen throughout.
        let state = Arc::new(FreezeStateMachine::starting_frozen());
        let handler = Arc::new(FakeDispatcher::default());
        let sessions: Arc<Mutex<Vec<tokio::io::DuplexStream>>> = Arc::new(Mutex::new(Vec::new()));
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
