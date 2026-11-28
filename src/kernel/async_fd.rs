//! An owned descriptor registered with the Tokio reactor (design §4.1 I/O
//! layer, §5.6).
//!
//! Tokio's `AsyncFd<T>` accepts any `T: AsRawFd`, so it cannot tell an
//! owned descriptor from a borrowed or reused number; since tokio 1.53.3
//! (RUSTSEC-2026-0386) registration is the `unsafe` [`AsyncFd::register`],
//! whose caller promises that the descriptor stays valid, open and
//! unchanged for as long as it is registered. [`OwnedAsyncFd`] keeps that
//! promise by construction: it takes the [`OwnedFd`] by value, never hands
//! out `&mut` access to it while registered (no `get_mut`), and offers only
//! readiness-driven reads and writes plus a shared borrow of the
//! descriptor, which under I/O safety cannot be used to close or replace
//! it. [`OwnedAsyncFd::into_fd`] consumes the wrapper and deregisters from
//! the reactor before returning ownership of the [`OwnedFd`]; dropping it
//! deregisters first, then closes.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::task::{Context, Poll, ready};

use tokio::io::unix::AsyncFd;

/// An [`OwnedFd`] registered with the current Tokio reactor for read and
/// write readiness. The descriptor must already be non-blocking.
#[derive(Debug)]
pub struct OwnedAsyncFd {
    inner: AsyncFd<OwnedFd>,
}

impl OwnedAsyncFd {
    /// Registers `fd` with the current reactor. Must be called within a
    /// Tokio runtime with I/O enabled. Fails (closing `fd`) when the
    /// reactor refuses the descriptor, for example a regular file, which
    /// `epoll` cannot watch.
    pub fn register(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: `AsyncFd::register` requires the descriptor to be valid,
        // open and to keep referring to the same file description until
        // the `AsyncFd` is deregistered or dropped. `fd` is an `OwnedFd`
        // taken by value, so it is valid and open and nothing else owns it;
        // this type never gives out `&mut OwnedFd` while registered (no
        // `get_mut`), so it cannot be closed or replaced while registered,
        // and `OwnedFd` always reports the same number. `into_fd` calls
        // `AsyncFd::into_inner`, which deregisters before returning the
        // `OwnedFd`; dropping the `AsyncFd` deregisters before closing it.
        let inner = unsafe { AsyncFd::register(fd) }?;
        Ok(OwnedAsyncFd { inner })
    }

    /// Reports whether Tokio's reactor has already latched hangup or error
    /// readiness (`READ_CLOSED`, `WRITE_CLOSED`, or `ERROR`) on this
    /// registration. Polls a single `AsyncFd::ready(READABLE | WRITABLE |
    /// ERROR)` future once so cached bits are inspected directly without
    /// checking Tokio's task cooperative budget, without masking out
    /// standalone `ERROR`, and without replacing any existing directional
    /// read/write waiter (§5.7).
    pub fn has_latched_hangup(&self) -> bool {
        use std::future::Future;
        use tokio::io::Interest;

        let mut cx = Context::from_waker(std::task::Waker::noop());
        let interest = Interest::READABLE | Interest::WRITABLE | Interest::ERROR;
        let fut = std::pin::pin!(self.inner.ready(interest));
        matches!(
            fut.poll(&mut cx),
            Poll::Ready(Ok(guard))
                if guard.ready().is_read_closed()
                    || guard.ready().is_write_closed()
                    || guard.ready().is_error()
        )
    }

    /// Deregisters the descriptor from the Tokio reactor and returns it
    /// still open. Consuming the registration drops any latched
    /// `READ_CLOSED`/`WRITE_CLOSED` readiness bits (for example after a
    /// Linux `virtio_console` host hangup), so a subsequent
    /// [`OwnedAsyncFd::register`] starts clean.
    pub fn into_fd(self) -> OwnedFd {
        self.inner.into_inner()
    }

    /// Reads into `buf` once the descriptor is readable; `Pending` until
    /// then. A read that would block clears the readiness and waits again,
    /// except when Tokio has already latched `READ_CLOSED` (which
    /// `clear_readiness` never clears): in that case it reports `Ok(0)`
    /// rather than spinning so the caller can re-register a fresh
    /// [`OwnedAsyncFd`].
    pub fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        self.poll_read_checked(cx, buf, || false)
    }

    /// Reads into `buf` once the descriptor is readable; `Pending` until
    /// then. If the reactor has already latched `READ_CLOSED` (`EPOLLHUP` /
    /// `EPOLLRDHUP`) and `stop_on_hangup()` returns `true`, returns `Ok(0)`
    /// **before** calling `read(2)` so bytes sent by a newly reconnected peer
    /// remain intact for the next session's fresh registration and decoder.
    /// When `read(2)` would block after `READ_CLOSED` is latched, also returns
    /// `Ok(0)` rather than spinning on Tokio's sticky closed readiness.
    pub fn poll_read_checked(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        mut stop_on_hangup: impl FnMut() -> bool,
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            let read_closed = guard.ready().is_read_closed();
            if read_closed && stop_on_hangup() {
                return Poll::Ready(Ok(0));
            }
            match guard
                .try_io(|inner| nix::unistd::read(inner.get_ref(), buf).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) if read_closed => return Poll::Ready(Ok(0)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Waits until the registered descriptor becomes readable and returns a
    /// readiness guard whose `clear_ready()` resets edge-triggered readiness
    /// after `EAGAIN`.
    pub async fn readable(&self) -> io::Result<tokio::io::unix::AsyncFdReadyGuard<'_, OwnedFd>> {
        self.inner.readable().await
    }

    /// Waits until the registered descriptor becomes writable and returns a
    /// readiness guard whose `clear_ready()` resets edge-triggered readiness
    /// after `EAGAIN`.
    pub async fn writable(&self) -> io::Result<tokio::io::unix::AsyncFdReadyGuard<'_, OwnedFd>> {
        self.inner.writable().await
    }

    /// Writes from `data` once the descriptor is writable; `Pending` until
    /// then. If Tokio has already latched `WRITE_CLOSED` (`EPOLLHUP` /
    /// `EPOLLERR`), returns `BrokenPipe` **before** calling `write(2)` so an
    /// undelivered reply from a departed virtio-serial session can neither
    /// spin on `EAGAIN` nor leak into a newly reconnected peer.
    pub fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            if guard.ready().is_write_closed() {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            match guard
                .try_io(|inner| nix::unistd::write(inner.get_ref(), data).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsFd for OwnedAsyncFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::future::poll_fn;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// One end registered, the other a plain blocking socket for the test.
    fn pair() -> (OwnedAsyncFd, UnixStream) {
        let (ours, peer) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        (OwnedAsyncFd::register(OwnedFd::from(ours)).unwrap(), peer)
    }

    #[tokio::test]
    async fn a_registered_descriptor_reads_and_writes() {
        let (fd, mut peer) = pair();
        let n = poll_fn(|cx| fd.poll_write(cx, b"ping\n")).await.unwrap();
        assert_eq!(n, 5);
        let mut got = [0u8; 5];
        peer.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping\n");

        peer.write_all(b"PONG\n").unwrap();
        let mut buf = [0u8; 16];
        let n = poll_fn(|cx| fd.poll_read(cx, &mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"PONG\n");
    }

    #[tokio::test]
    async fn a_read_waits_for_data_instead_of_failing_with_would_block() {
        let (fd, mut peer) = pair();
        let mut buf = [0u8; 8];
        let pending = tokio::time::timeout(
            Duration::from_millis(50),
            poll_fn(|cx| fd.poll_read(cx, &mut buf)),
        )
        .await;
        assert!(pending.is_err(), "no data yet: the read must stay pending");

        peer.write_all(b"late").unwrap();
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| fd.poll_read(cx, &mut buf)),
        )
        .await
        .expect("readiness must wake the read")
        .unwrap();
        assert_eq!(&buf[..n], b"late");
    }

    #[tokio::test]
    async fn dropping_it_closes_the_descriptor() {
        let (fd, mut peer) = pair();
        drop(fd);
        let mut buf = [0u8; 1];
        assert_eq!(peer.read(&mut buf).unwrap(), 0, "the peer sees EOF");
    }

    #[tokio::test]
    async fn the_borrowed_descriptor_is_the_registered_one() {
        use std::os::fd::AsRawFd;
        let (ours, _peer) = UnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let raw = ours.as_raw_fd();
        let fd = OwnedAsyncFd::register(OwnedFd::from(ours)).unwrap();
        assert_eq!(fd.as_fd().as_raw_fd(), raw);
    }

    #[tokio::test]
    async fn a_descriptor_the_reactor_cannot_watch_is_an_error() {
        let file = tempfile::tempfile().unwrap();
        let err = OwnedAsyncFd::register(OwnedFd::from(file)).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(nix::libc::EPERM), "{err}");
    }

    /// Pumps Tokio's I/O reactor (`epoll_wait(0)`) under `start_paused = true`
    /// without advancing virtual time or relying on wall-clock sleeps.
    async fn pump_reactor() {
        tokio::time::advance(Duration::ZERO).await;
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
    }

    /// Creates a `0600` FIFO inside an owner-only `0700` temporary directory
    /// (independent of process `umask`) so repeated pathname opens cannot race
    /// another local user in the shared temp area.
    fn private_fifo(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        use nix::sys::stat::Mode;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let fifo = dir.path().join(name);
        nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();
        (dir, fifo)
    }

    #[tokio::test(start_paused = true)]
    async fn into_fd_refreshes_registration_after_real_epollhup_without_spinning() {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;

        let (_dir, fifo) = private_fifo("port.fifo");

        let reader = open(
            &fifo,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let writer1 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        let old = OwnedAsyncFd::register(reader).unwrap();

        nix::unistd::write(&writer1, b"first\n").unwrap();
        let mut buf = [0u8; 16];
        let n = poll_fn(|cx| old.poll_read(cx, &mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"first\n");

        // Synchronously drain the initial READABLE bit until `poll_read`
        // genuinely returns `Poll::Pending` (parked on epoll); dropping
        // `writer1` then delivers a real kernel EPOLLHUP, latching
        // Mio/Tokio's sticky READ_CLOSED bit on `old`.
        assert!(
            poll_fn(|cx| Poll::Ready(old.poll_read(cx, &mut buf)))
                .await
                .is_pending(),
            "reader must synchronously park on epoll while writer1 is idle"
        );

        drop(writer1);
        pump_reactor().await;
        let n = match poll_fn(|cx| Poll::Ready(old.poll_read(cx, &mut buf))).await {
            Poll::Ready(res) => res.unwrap(),
            Poll::Pending => {
                panic!("EOF must be delivered via kernel EPOLLHUP after writer1 closed")
            }
        };
        assert_eq!(
            n, 0,
            "EOF delivered via kernel EPOLLHUP after writer1 closed"
        );

        // Opening an idle second writer clears kernel POLLHUP (`read` now
        // returns EAGAIN). The stale registration still has READ_CLOSED
        // latched, so `poll_read` must NOT busy-spin (it surfaces EOF), and
        // refreshing the registration via `into_fd` + `register` parks cleanly
        // across an idle virtual-time window until data arrives.
        let writer2 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        let stale = match poll_fn(|cx| Poll::Ready(old.poll_read(cx, &mut buf))).await {
            Poll::Ready(res) => res.unwrap(),
            Poll::Pending => panic!("stale READ_CLOSED registration must surface EOF immediately"),
        };
        assert_eq!(stale, 0);

        let fresh = OwnedAsyncFd::register(old.into_fd()).unwrap();
        assert!(
            poll_fn(|cx| Poll::Ready(fresh.poll_read(cx, &mut buf)))
                .await
                .is_pending(),
            "fresh registration on idle connected peer must park in Pending"
        );
        tokio::time::advance(Duration::from_millis(50)).await;
        pump_reactor().await;
        assert!(
            poll_fn(|cx| Poll::Ready(fresh.poll_read(cx, &mut buf)))
                .await
                .is_pending(),
            "fresh registration must remain Pending across the idle window"
        );

        nix::unistd::write(&writer2, b"second\n").unwrap();
        pump_reactor().await;
        let n = match poll_fn(|cx| Poll::Ready(fresh.poll_read(cx, &mut buf))).await {
            Poll::Ready(res) => res.unwrap(),
            Poll::Pending => panic!("fresh registration must wake on new writer data"),
        };
        assert_eq!(&buf[..n], b"second\n");
    }

    #[tokio::test(start_paused = true)]
    async fn poll_write_refuses_io_after_real_epollerr_even_when_new_reader_is_ready() {
        use nix::errno::Errno;
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;

        let (_dir, fifo) = private_fifo("write-hup.fifo");

        let reader1 = open(
            &fifo,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let writer_fd = open(
            &fifo,
            OFlag::O_WRONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let old = OwnedAsyncFd::register(writer_fd).unwrap();

        // Synchronously fill the FIFO pipe buffer until `poll_write` clears
        // initial WRITABLE and genuinely returns `Poll::Pending`; closing
        // `reader1` then delivers a real kernel EPOLLERR, latching
        // Mio/Tokio's sticky WRITE_CLOSED bit on `old`.
        let chunk = [b'a'; 4096];
        loop {
            match poll_fn(|cx| Poll::Ready(old.poll_write(cx, &chunk))).await {
                Poll::Pending => break,
                Poll::Ready(res) => {
                    res.unwrap();
                }
            }
        }

        drop(reader1);
        pump_reactor().await;
        let err = match poll_fn(|cx| Poll::Ready(old.poll_write(cx, b"x"))).await {
            Poll::Ready(res) => res.unwrap_err(),
            Poll::Pending => panic!("EPOLLERR must wake writer and latch WRITE_CLOSED"),
        };
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);

        // Reconnect a ready reader2 (draining any old buffered bytes so the
        // FIFO is writable again): `old.poll_write` MUST refuse to call
        // write(2) because WRITE_CLOSED is latched, leaking ZERO bytes to r2.
        let reader2 = open(
            &fifo,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut drain = [0u8; 4096];
        while nix::unistd::read(&reader2, &mut drain).is_ok_and(|n| n > 0) {}

        let refused = match poll_fn(|cx| Poll::Ready(old.poll_write(cx, b"stale-reply\n"))).await {
            Poll::Ready(res) => res.unwrap_err(),
            Poll::Pending => panic!("latched WRITE_CLOSED must refuse write immediately"),
        };
        assert_eq!(
            refused.kind(),
            io::ErrorKind::BrokenPipe,
            "latched WRITE_CLOSED must refuse write before calling write(2)"
        );
        let mut got = [0u8; 32];
        assert_eq!(
            nix::unistd::read(&reader2, &mut got),
            Err(Errno::EAGAIN),
            "no stale reply bytes may leak to the new reader"
        );

        // Refreshing the registration via `into_fd` + `register` allows the new
        // session to write normally.
        let fresh = OwnedAsyncFd::register(old.into_fd()).unwrap();
        let n = poll_fn(|cx| fresh.poll_write(cx, b"fresh-reply\n"))
            .await
            .unwrap();
        assert_eq!(n, b"fresh-reply\n".len());
        let n = nix::unistd::read(&reader2, &mut got).unwrap();
        assert_eq!(&got[..n], b"fresh-reply\n");
    }

    #[tokio::test(start_paused = true)]
    async fn poll_read_checked_refuses_read_on_latched_read_closed_when_stop_on_hangup_holds() {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;

        let (_dir, fifo) = private_fifo("read-hup.fifo");

        let reader = open(
            &fifo,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let writer1 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        let old = OwnedAsyncFd::register(reader).unwrap();

        let mut buf = [0u8; 32];
        assert!(
            poll_fn(|cx| Poll::Ready(old.poll_read(cx, &mut buf)))
                .await
                .is_pending(),
            "reader must synchronously park on epoll while writer1 is idle"
        );

        drop(writer1);
        pump_reactor().await;
        let eof = match poll_fn(|cx| Poll::Ready(old.poll_read(cx, &mut buf))).await {
            Poll::Ready(res) => res.unwrap(),
            Poll::Pending => panic!("EPOLLHUP must latch READ_CLOSED"),
        };
        assert_eq!(eof, 0, "EPOLLHUP latches READ_CLOSED");

        // Writer 2 reconnects and ALREADY sends its first request before the
        // old registration polls again: `poll_read_checked(..., || true)` must
        // return Ok(0) WITHOUT consuming writer2's request!
        let writer2 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        nix::unistd::write(&writer2, b"new-request\n").unwrap();
        pump_reactor().await;

        let n = match poll_fn(|cx| Poll::Ready(old.poll_read_checked(cx, &mut buf, || true))).await
        {
            Poll::Ready(res) => res.unwrap(),
            Poll::Pending => panic!("latched READ_CLOSED must return EOF immediately"),
        };
        assert_eq!(
            n, 0,
            "latched READ_CLOSED must return EOF before calling read(2)"
        );

        // Fresh registration receives writer2's complete first request intact.
        let fresh = OwnedAsyncFd::register(old.into_fd()).unwrap();
        let n = poll_fn(|cx| fresh.poll_read(cx, &mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"new-request\n");
    }

    #[tokio::test(start_paused = true)]
    async fn has_latched_hangup_detects_real_epollhup_while_reads_are_idle() {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;

        let (_dir, fifo) = private_fifo("idle-hup.fifo");

        let reader = open(
            &fifo,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let writer1 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        let reg = OwnedAsyncFd::register(reader).unwrap();

        // Park reader on epoll while writer1 is open, then stop polling reads.
        let mut buf = [0u8; 32];
        assert!(
            poll_fn(|cx| Poll::Ready(reg.poll_read(cx, &mut buf)))
                .await
                .is_pending()
        );
        assert!(
            !reg.has_latched_hangup(),
            "freshly registered idle peer must not report latched hangup"
        );

        // Writer 1 closes (real kernel EPOLLHUP latched by Tokio while no read
        // or write is polled) and writer 2 reconnects (clearing kernel POLLHUP).
        drop(writer1);
        pump_reactor().await;
        let _writer2 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        pump_reactor().await;

        assert!(
            reg.has_latched_hangup(),
            "cached reactor readiness must retain latched EPOLLHUP even after writer2 clears POLLHUP"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn has_latched_hangup_survives_exhausted_coop_budget_and_preserves_waiter() {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::{Wake, Waker};

        struct CountWaker(AtomicUsize);
        impl Wake for CountWaker {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let (_dir, fifo) = private_fifo("coop-and-waker.fifo");
        let reader = open(
            &fifo,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let writer1 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        let reg = OwnedAsyncFd::register(reader).unwrap();

        // Park a real directional read waiter via `poll_read`, then call
        // `has_latched_hangup()` while idle: it must return `false` WITHOUT
        // overwriting the registered directional read waker.
        let mut buf = [0u8; 32];
        let counter = Arc::new(CountWaker(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        {
            let mut cx = Context::from_waker(&waker);
            assert!(reg.poll_read(&mut cx, &mut buf).is_pending());
        }
        assert!(!reg.has_latched_hangup());

        nix::unistd::write(&writer1, b"x").unwrap();
        pump_reactor().await;
        assert!(
            counter.0.load(Ordering::SeqCst) >= 1,
            "has_latched_hangup must not replace an existing directional read waiter"
        );
        // Drain the byte and re-park on epoll.
        let n = poll_fn(|cx| reg.poll_read(cx, &mut buf)).await.unwrap();
        assert_eq!(&buf[..n], b"x");
        assert!(
            poll_fn(|cx| Poll::Ready(reg.poll_read(cx, &mut buf)))
                .await
                .is_pending()
        );

        // Latch real EPOLLHUP via writer1 closing, then clear kernel POLLHUP
        // with writer2.
        drop(writer1);
        pump_reactor().await;
        let _writer2 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        pump_reactor().await;

        // Exhaust the task's entire Tokio cooperative budget inside a single
        // task poll (verified by `poll_read_checked` returning `Poll::Pending`
        // despite latched `READ_CLOSED`), then assert `has_latched_hangup()`
        // STILL returns `true` without being suppressed by coop budget.
        let (budget_exhausted, detected_under_exhausted_budget) = poll_fn(|cx| {
            let mut exhausted = false;
            for _ in 0..512 {
                if reg.poll_read_checked(cx, &mut buf, || true).is_pending() {
                    exhausted = true;
                    break;
                }
            }
            Poll::Ready((exhausted, reg.has_latched_hangup()))
        })
        .await;
        assert!(
            budget_exhausted,
            "test must genuinely exhaust Tokio's cooperative budget"
        );
        assert!(
            detected_under_exhausted_budget,
            "has_latched_hangup must detect cached hangup even when task cooperative budget is exhausted"
        );
    }
}
