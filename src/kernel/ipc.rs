//! Low-level `AF_UNIX` `SOCK_SEQPACKET` + `SCM_RIGHTS` transport shim
//! (OQ-10 §4.1, §5.6, #77).
//!
//! This is the thin `unsafe` boundary inside `src/kernel/` that exposes safe,
//! leak-proof packet send/receive operations to [`crate::ipc`]:
//! - Every `recvmsg(2)` call passes `MSG_CMSG_CLOEXEC` with an aligned
//!   control buffer (`>= CMSG_SPACE(sizeof(int))`).
//! - Every `SCM_RIGHTS` control message delivered by the kernel is walked via
//!   `CMSG_FIRSTHDR`/`CMSG_NXTHDR` and every received descriptor is wrapped
//!   immediately in [`OwnedFd`], so dropping [`RawPacket`] on any rejection
//!   path closes all descriptors without leaking.
//! - Both `MSG_TRUNC` and `MSG_CTRUNC` plus raw `msg_controllen` and any
//!   non-`SCM_RIGHTS` control messages are surfaced explicitly for strict
//!   validation before dispatch.

use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::libc;
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

/// Maximum number of descriptors that [`send_packet_fds`] may pack into one
/// `SCM_RIGHTS` control message (production sends at most 1; tests send up to
/// 4 to exercise `fds.len() > 1` and real kernel `MSG_CTRUNC`).
const MAX_SEND_FDS: usize = 8;

/// Number of `RawFd` slots sized into the `recvmsg` ancillary buffer: room
/// for 2 descriptors allows tests to observe both exact `fds.len() > 1`
/// rejection (2 fds) and kernel `MSG_CTRUNC` (3+ fds) while keeping the
/// buffer tiny on the stack.
const RECV_CMSG_FD_SLOTS: usize = 2;

/// Properly aligned control-message buffer for `msghdr::msg_control`.
#[repr(C)]
struct AlignedCmsgBuf<const N: usize> {
    _align: [libc::cmsghdr; 0],
    bytes: [u8; N],
}

impl<const N: usize> AlignedCmsgBuf<N> {
    const fn zeroed() -> Self {
        Self {
            _align: [],
            bytes: [0u8; N],
        }
    }
}

/// Raw `SOCK_SEQPACKET` packet and ancillary-data inspection record returned
/// by [`recv_packet`].
///
/// Every file descriptor received via `SCM_RIGHTS` is already owned by
/// [`RawPacket::fds`], so dropping this value on any error or rejection path
/// automatically closes every descriptor.
#[derive(Debug)]
pub struct RawPacket {
    /// Received payload bytes (capped at `max_bytes` when `truncated` is set).
    pub bytes: Vec<u8>,
    /// File descriptors received via `SCM_RIGHTS` (opened with `FD_CLOEXEC`).
    pub fds: Vec<OwnedFd>,
    /// `true` when `msghdr.msg_flags` had `MSG_TRUNC` set.
    pub truncated: bool,
    /// `true` when `msghdr.msg_flags` had `MSG_CTRUNC` set.
    pub cmsg_truncated: bool,
    /// Total control messages walked in `msg_control`.
    pub control_message_count: usize,
    /// Control messages other than `(SOL_SOCKET, SCM_RIGHTS)`.
    pub non_rights_cmsgs: usize,
    /// Raw `msghdr.msg_controllen` reported by the kernel.
    pub raw_controllen: usize,
}

/// Creates a connected `AF_UNIX` `SOCK_SEQPACKET` socketpair with
/// `SOCK_CLOEXEC` (and optionally `SOCK_NONBLOCK`).
pub fn seqpacket_pair(nonblocking: bool) -> Result<(OwnedFd, OwnedFd), Errno> {
    let mut flags = SockFlag::SOCK_CLOEXEC;
    if nonblocking {
        flags |= SockFlag::SOCK_NONBLOCK;
    }
    socketpair(AddressFamily::Unix, SockType::SeqPacket, None, flags)
}

/// Sends a single `SOCK_SEQPACKET` message carrying `payload` and zero or one
/// `SCM_RIGHTS` file descriptor (`MSG_NOSIGNAL`).
pub fn send_packet(
    sock: BorrowedFd<'_>,
    payload: &[u8],
    fd: Option<BorrowedFd<'_>>,
) -> Result<(), Errno> {
    match fd {
        Some(fd) => send_packet_fds(sock, payload, &[fd]),
        None => send_packet_fds(sock, payload, &[]),
    }
}

/// Sends a single `SOCK_SEQPACKET` message carrying `payload` and `fds`
/// (`0..=8` descriptors) via `SCM_RIGHTS` (`MSG_NOSIGNAL`).
///
/// Production code should use [`send_packet`], which accepts at most one
/// descriptor; this helper lets boundary tests send multiple descriptors to
/// exercise `fds.len() > 1` and real kernel `MSG_CTRUNC` rejection.
pub fn send_packet_fds(
    sock: BorrowedFd<'_>,
    payload: &[u8],
    fds: &[BorrowedFd<'_>],
) -> Result<(), Errno> {
    if fds.len() > MAX_SEND_FDS {
        return Err(Errno::EINVAL);
    }

    // 128 bytes comfortably holds `CMSG_SPACE(8 * sizeof(c_int))` (48 bytes on
    // 64-bit Linux) while remaining const-sized and aligned to `cmsghdr`.
    const SEND_CMSG_BUF_LEN: usize = 128;
    let mut cmsg_buf = AlignedCmsgBuf::<SEND_CMSG_BUF_LEN>::zeroed();

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };

    // SAFETY: `libc::msghdr` is a plain C struct; zero-initialising all fields
    // (including glibc's private padding fields) is valid before populating
    // `msg_iov`/`msg_control`.
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    if !fds.is_empty() {
        let raw_fds_len = fds.len() * size_of::<RawFd>();
        let raw_fds_len_u32 = u32::try_from(raw_fds_len).map_err(|_| Errno::EINVAL)?;
        // SAFETY: `CMSG_SPACE` is a pure integer alignment calculation.
        let space = unsafe { libc::CMSG_SPACE(raw_fds_len_u32) } as usize;
        // SAFETY: `CMSG_LEN` is a pure integer header+payload length calculation.
        let len = unsafe { libc::CMSG_LEN(raw_fds_len_u32) } as usize;
        if space > cmsg_buf.bytes.len() {
            return Err(Errno::EINVAL);
        }
        msg.msg_control = cmsg_buf.bytes.as_mut_ptr().cast();
        msg.msg_controllen = space;

        // SAFETY: `msg.msg_control` points to `cmsg_buf` aligned to
        // `libc::cmsghdr` with `msg.msg_controllen == space >= CMSG_SPACE(len)`.
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        if cmsg.is_null() {
            return Err(Errno::EINVAL);
        }
        // SAFETY: `cmsg` is non-null and points into our uniquely owned,
        // `cmsghdr`-aligned `cmsg_buf`.
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
        }
        // SAFETY: `cmsg` is valid for writes inside `cmsg_buf`.
        unsafe {
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        }
        // SAFETY: `cmsg` is valid for writes inside `cmsg_buf`.
        unsafe {
            (*cmsg).cmsg_len = len;
        }
        // SAFETY: `CMSG_DATA` returns a pointer into `cmsg_buf` with at least
        // `raw_fds_len` writable bytes because `space == CMSG_SPACE(raw_fds_len)`.
        let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
        for (i, fd) in fds.iter().enumerate() {
            let raw: RawFd = fd.as_raw_fd();
            // SAFETY: `i * size_of::<RawFd>() + size_of::<RawFd>() <= raw_fds_len`,
            // staying strictly inside `cmsg_buf`.
            let dst = unsafe { data_ptr.add(i * size_of::<RawFd>()) };
            // SAFETY: `dst` points to `size_of::<RawFd>()` writable bytes inside
            // `cmsg_buf`; `write_unaligned` avoids any alignment assumption.
            unsafe {
                std::ptr::write_unaligned(dst.cast::<RawFd>(), raw);
            }
        }
    }

    loop {
        // SAFETY: `sock` is a valid borrowed descriptor, `msg` references live
        // `iov` and `cmsg_buf` buffers for the duration of the syscall.
        let rc = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if rc < 0 {
            let err = Errno::last();
            if err == Errno::EINTR {
                continue;
            }
            return Err(err);
        }
        if usize::try_from(rc).ok() != Some(payload.len()) {
            return Err(Errno::EIO);
        }
        return Ok(());
    }
}

/// Receives one `SOCK_SEQPACKET` packet up to `max_bytes` payload bytes using
/// `MSG_CMSG_CLOEXEC`, walking every control message and wrapping every
/// received `SCM_RIGHTS` descriptor immediately in [`OwnedFd`].
///
/// Returns `Ok(None)` on clean peer EOF (`recvmsg` returned `0` with no
/// ancillary data and neither `MSG_TRUNC` nor `MSG_CTRUNC`).
pub fn recv_packet(sock: BorrowedFd<'_>, max_bytes: usize) -> Result<Option<RawPacket>, Errno> {
    let mut bytes = vec![0u8; max_bytes];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };

    let cmsg_fd_bytes =
        u32::try_from(RECV_CMSG_FD_SLOTS * size_of::<RawFd>()).map_err(|_| Errno::EINVAL)?;
    // SAFETY: `CMSG_SPACE` is a pure integer alignment calculation.
    let recv_cmsg_space = unsafe { libc::CMSG_SPACE(cmsg_fd_bytes) } as usize;
    const RECV_CMSG_BUF_LEN: usize = 64;
    let mut cmsg_buf = AlignedCmsgBuf::<RECV_CMSG_BUF_LEN>::zeroed();
    let control_len = recv_cmsg_space.min(cmsg_buf.bytes.len());

    // SAFETY: `libc::msghdr` is a plain C struct; zero-initialising all fields
    // is valid before populating `msg_iov` and `msg_control`.
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.bytes.as_mut_ptr().cast();
    msg.msg_controllen = control_len;

    let rc = loop {
        // SAFETY: `sock` is a valid borrowed descriptor, and `msg` points to
        // live writable `bytes` and `cmsg_buf` buffers for the syscall's
        // duration. `MSG_CMSG_CLOEXEC` sets `FD_CLOEXEC` atomically on every
        // received `SCM_RIGHTS` descriptor.
        let rc = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if rc < 0 {
            let err = Errno::last();
            if err == Errno::EINTR {
                continue;
            }
            return Err(err);
        }
        break rc;
    };

    let truncated = (msg.msg_flags & libc::MSG_TRUNC) != 0;
    let cmsg_truncated = (msg.msg_flags & libc::MSG_CTRUNC) != 0;
    let raw_controllen = msg.msg_controllen;

    // Immediately walk EVERY control message and wrap EVERY received
    // `SCM_RIGHTS` descriptor in `OwnedFd` before doing anything else so no
    // early return or error path can leak an fd.
    let mut fds = Vec::new();
    let mut control_message_count = 0usize;
    let mut non_rights_cmsgs = 0usize;
    // SAFETY: `CMSG_LEN(0)` is a pure integer header-size calculation.
    let cmsg_hdr_len = unsafe { libc::CMSG_LEN(0) } as usize;

    // SAFETY: `msg` was populated by the kernel `recvmsg` call above and its
    // `msg_control` buffer (`cmsg_buf`) is still live and aligned.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        control_message_count += 1;
        // SAFETY: `cmsg` is a valid non-null pointer returned by
        // `CMSG_FIRSTHDR`/`CMSG_NXTHDR` into `cmsg_buf`.
        let level = unsafe { (*cmsg).cmsg_level };
        // SAFETY: `cmsg` is valid for reads inside `cmsg_buf`.
        let ty = unsafe { (*cmsg).cmsg_type };
        // SAFETY: `cmsg` is valid for reads inside `cmsg_buf`.
        let len = unsafe { (*cmsg).cmsg_len };
        if level == libc::SOL_SOCKET && ty == libc::SCM_RIGHTS {
            let data_len = len.saturating_sub(cmsg_hdr_len);
            let fd_count = data_len / size_of::<RawFd>();
            // SAFETY: `CMSG_DATA` returns a pointer to `data_len` initialized
            // bytes written by the kernel inside `cmsg_buf`.
            let data_ptr = unsafe { libc::CMSG_DATA(cmsg) };
            for i in 0..fd_count {
                // SAFETY: `i * size_of::<RawFd>() + size_of::<RawFd>() <= data_len`,
                // staying strictly inside the kernel-written cmsg payload.
                let src = unsafe { data_ptr.add(i * size_of::<RawFd>()) };
                // SAFETY: `src` points to `size_of::<RawFd>()` initialized bytes
                // inside `cmsg_buf`; `read_unaligned` avoids alignment UB.
                let raw_fd = unsafe { std::ptr::read_unaligned(src.cast::<RawFd>()) };
                if raw_fd >= 0 {
                    // SAFETY: The kernel just transferred sole ownership of
                    // `raw_fd` to this process via `SCM_RIGHTS` with
                    // `MSG_CMSG_CLOEXEC`.
                    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
                    fds.push(owned);
                }
            }
        } else {
            non_rights_cmsgs += 1;
        }
        // SAFETY: `cmsg` is a valid pointer inside `msg`'s live control buffer.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    if rc == 0 && raw_controllen == 0 && !truncated && !cmsg_truncated {
        return Ok(None);
    }

    let n = usize::try_from(rc).unwrap_or(0).min(max_bytes);
    bytes.truncate(n);
    Ok(Some(RawPacket {
        bytes,
        fds,
        truncated,
        cmsg_truncated,
        control_message_count,
        non_rights_cmsgs,
        raw_controllen,
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::unistd::pipe;

    use super::*;

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    #[test]
    fn seqpacket_round_trips_payload_and_single_cloexec_fd() {
        let (a, b) = seqpacket_pair(false).unwrap();
        send_packet(a.as_fd(), b"hello-ipc", None).unwrap();
        let pkt = recv_packet(b.as_fd(), 64).unwrap().unwrap();
        assert_eq!(pkt.bytes, b"hello-ipc");
        assert!(pkt.fds.is_empty());
        assert!(!pkt.truncated);
        assert!(!pkt.cmsg_truncated);
        assert_eq!(pkt.control_message_count, 0);
        assert_eq!(pkt.non_rights_cmsgs, 0);
        assert_eq!(pkt.raw_controllen, 0);

        let (r_end, w_end) = pipe().unwrap();
        send_packet(a.as_fd(), b"with-fd", Some(r_end.as_fd())).unwrap();
        drop(r_end);

        let mut pkt = recv_packet(b.as_fd(), 64).unwrap().unwrap();
        assert_eq!(pkt.bytes, b"with-fd");
        assert_eq!(pkt.fds.len(), 1);
        assert!(!pkt.truncated);
        assert!(!pkt.cmsg_truncated);
        assert_eq!(pkt.control_message_count, 1);
        assert_eq!(pkt.non_rights_cmsgs, 0);
        let received = pkt.fds.pop().unwrap();
        let flags = FdFlag::from_bits_truncate(fcntl(&received, FcntlArg::F_GETFD).unwrap());
        assert!(
            flags.contains(FdFlag::FD_CLOEXEC),
            "MSG_CMSG_CLOEXEC must set FD_CLOEXEC on received descriptor"
        );
        let mut writer = std::fs::File::from(w_end);
        let mut reader = std::fs::File::from(received);
        writer.write_all(b"ping").unwrap();
        drop(writer);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"ping");
    }

    #[test]
    fn recv_packet_detects_msg_trunc_multi_fd_msg_ctrunc_and_leaks_zero_fds() {
        let (a, b) = seqpacket_pair(false).unwrap();

        // 1. Oversized packet sets MSG_TRUNC.
        send_packet(a.as_fd(), &[0xAB; 128], None).unwrap();
        let pkt = recv_packet(b.as_fd(), 32).unwrap().unwrap();
        assert!(pkt.truncated, "expected MSG_TRUNC");
        assert_eq!(pkt.bytes.len(), 32);

        // 2. Two fds fit inside the 2-slot control buffer so caller sees
        //    `fds.len() == 2` without MSG_CTRUNC, and dropping RawPacket
        //    closes both descriptors.
        let before_two = open_fd_count();
        {
            let (p1, _) = pipe().unwrap();
            let (p2, _) = pipe().unwrap();
            send_packet_fds(a.as_fd(), b"two", &[p1.as_fd(), p2.as_fd()]).unwrap();
            let pkt = recv_packet(b.as_fd(), 32).unwrap().unwrap();
            assert!(!pkt.cmsg_truncated);
            assert_eq!(pkt.fds.len(), 2);
            drop(pkt);
        }
        assert_eq!(
            open_fd_count(),
            before_two,
            "dropping rejected 2-fd packet must not leak descriptors"
        );

        // 3. Four fds overflow the 2-slot control buffer -> kernel sets
        //    MSG_CTRUNC and dropping RawPacket closes every delivered fd.
        let before_four = open_fd_count();
        {
            let (p1, _) = pipe().unwrap();
            let (p2, _) = pipe().unwrap();
            let (p3, _) = pipe().unwrap();
            let (p4, _) = pipe().unwrap();
            send_packet_fds(
                a.as_fd(),
                b"four",
                &[p1.as_fd(), p2.as_fd(), p3.as_fd(), p4.as_fd()],
            )
            .unwrap();
            let pkt = recv_packet(b.as_fd(), 32).unwrap().unwrap();
            assert!(pkt.cmsg_truncated, "expected real kernel MSG_CTRUNC");
            drop(pkt);
        }
        assert_eq!(
            open_fd_count(),
            before_four,
            "dropping MSG_CTRUNC packet must close every delivered descriptor"
        );

        // 4. Clean peer EOF returns Ok(None).
        drop(a);
        assert!(recv_packet(b.as_fd(), 32).unwrap().is_none());
    }

    #[test]
    fn recv_packet_surfaces_non_rights_control_messages() {
        let (a, b) = seqpacket_pair(false).unwrap();
        let enable: libc::c_int = 1;
        // SAFETY: `b` is a valid AF_UNIX socket descriptor and `&enable` points
        // to an initialized `c_int` for `SO_PASSCRED`.
        let rc = unsafe {
            libc::setsockopt(
                b.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&raw const enable).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt(SO_PASSCRED) failed: {}", Errno::last());
        send_packet(a.as_fd(), b"cred", None).unwrap();
        let pkt = recv_packet(b.as_fd(), 32).unwrap().unwrap();
        assert!(pkt.fds.is_empty());
        assert!(pkt.raw_controllen > 0);
        assert!(pkt.control_message_count >= 1);
        assert!(pkt.non_rights_cmsgs >= 1);
    }
}
