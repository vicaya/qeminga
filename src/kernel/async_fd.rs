//! An owned descriptor registered with the Tokio reactor (design §4.1 I/O
//! layer, §5.6).
//!
//! Tokio's `AsyncFd<T>` accepts any `T: AsRawFd`, so it cannot tell an
//! owned descriptor from a borrowed or reused number; since tokio 1.53.3
//! (RUSTSEC-2026-0386) registration is the `unsafe` [`AsyncFd::register`],
//! whose caller promises that the descriptor stays valid, open and
//! unchanged for as long as it is registered. [`OwnedAsyncFd`] keeps that
//! promise by construction: it takes the [`OwnedFd`] by value, never hands
//! out `&mut` access to it (no `get_mut`, no `into_inner`), and offers only
//! readiness-driven reads and writes plus a shared borrow of the
//! descriptor, which under I/O safety cannot be used to close or replace
//! it. Dropping it deregisters first, then closes.

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
        // the `AsyncFd` is dropped. `fd` is an `OwnedFd` taken by value, so
        // it is valid and open and nothing else owns it; this type never
        // gives out `&mut OwnedFd` (no `get_mut`, no `into_inner`), so it
        // cannot be closed or replaced while registered, and `OwnedFd`
        // always reports the same number. Dropping the `AsyncFd`
        // deregisters before the `OwnedFd` closes the descriptor.
        let inner = unsafe { AsyncFd::register(fd) }?;
        Ok(OwnedAsyncFd { inner })
    }

    /// Reads into `buf` once the descriptor is readable; `Pending` until
    /// then. A read that would block clears the readiness and waits again.
    pub fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard
                .try_io(|inner| nix::unistd::read(inner.get_ref(), buf).map_err(io::Error::from))
            {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes from `data` once the descriptor is writable; `Pending` until
    /// then. A write that would block clears the readiness and waits again.
    pub fn poll_write(&self, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
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
}
