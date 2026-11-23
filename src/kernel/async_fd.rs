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
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            let read_closed = guard.ready().is_read_closed();
            match guard
                .try_io(|inner| nix::unistd::read(inner.get_ref(), buf).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) if read_closed => return Poll::Ready(Ok(0)),
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes from `data` once the descriptor is writable; `Pending` until
    /// then. A write that would block clears the readiness and waits again,
    /// except when Tokio has already latched `WRITE_CLOSED` (for example a
    /// non-blocking `virtio_console` write returning `EAGAIN` while the
    /// host is disconnected): in that case it reports `BrokenPipe` rather
    /// than spinning.
    pub fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            let write_closed = guard.ready().is_write_closed();
            match guard
                .try_io(|inner| nix::unistd::write(inner.get_ref(), data).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) if write_closed => {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
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

    #[tokio::test]
    async fn into_fd_refreshes_registration_after_real_epollhup_without_spinning() {
        use nix::fcntl::{OFlag, open};
        use nix::sys::stat::Mode;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("port.fifo");
        nix::unistd::mkfifo(&fifo, Mode::S_IRWXU).unwrap();

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

        // Drain the initial READABLE bit so `old` parks on epoll; dropping
        // `writer1` then wakes it via a real kernel EPOLLHUP, latching
        // Mio/Tokio's sticky READ_CLOSED bit on `old`.
        let parked = tokio::time::timeout(
            Duration::from_millis(20),
            poll_fn(|cx| old.poll_read(cx, &mut buf)),
        )
        .await;
        assert!(
            parked.is_err(),
            "reader should park on epoll while writer1 is idle"
        );

        drop(writer1);
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| old.poll_read(cx, &mut buf)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            n, 0,
            "EOF delivered via kernel EPOLLHUP after writer1 closed"
        );

        // Opening an idle second writer clears kernel POLLHUP (`read` now
        // returns EAGAIN). The stale registration still has READ_CLOSED
        // latched, so `poll_read` must NOT busy-spin (it surfaces EOF), and
        // refreshing the registration via `into_fd` + `register` parks cleanly
        // until data arrives.
        let writer2 = open(&fifo, OFlag::O_WRONLY | OFlag::O_CLOEXEC, Mode::empty()).unwrap();
        let stale = tokio::time::timeout(
            Duration::from_millis(200),
            poll_fn(|cx| old.poll_read(cx, &mut buf)),
        )
        .await
        .expect("stale READ_CLOSED registration must surface EOF rather than spinning")
        .unwrap();
        assert_eq!(stale, 0);

        let fresh = OwnedAsyncFd::register(old.into_fd()).unwrap();
        let pending = tokio::time::timeout(
            Duration::from_millis(50),
            poll_fn(|cx| fresh.poll_read(cx, &mut buf)),
        )
        .await;
        assert!(
            pending.is_err(),
            "fresh registration on idle connected peer must park in Pending"
        );

        nix::unistd::write(&writer2, b"second\n").unwrap();
        let n = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| fresh.poll_read(cx, &mut buf)),
        )
        .await
        .expect("fresh registration wakes on new writer data")
        .unwrap();
        assert_eq!(&buf[..n], b"second\n");
    }
}
