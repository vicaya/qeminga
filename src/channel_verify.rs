//! Channel descriptor identity verification (OQ-10 §4.2, #78).
//!
//! Opening `config.agent.channel_path` by name alone is insufficient to guarantee
//! that an ordinary file or unrelated character device never crosses IPC into
//! the parser, and a driver-defined sysfs `name` attribute alone does not prove
//! the device's subsystem class. Before handing any channel descriptor to the
//! parser (either at startup or on `RequestChannelReopen`), the executor
//! verifies the **opened descriptor** itself so path TOCTOU is eliminated:
//!
//! 1. `fstat(fd)` must report a character device (`S_ISCHR`).
//! 2. Under [`ChannelIdentityPolicy::VirtioSerial`] (production default):
//!    extract `(major, minor)` from `st_rdev`, open
//!    `<sysfs_root>/dev/char/<major>:<minor>` (`O_RDONLY | O_DIRECTORY | O_CLOEXEC`),
//!    and require **both**:
//!    - `readlinkat(dirfd, "subsystem")` has final path component `"virtio-ports"`,
//!      and
//!    - `openat(dirfd, "name", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)` (bounded read)
//!      matches `<expected_port_name>\n` byte-for-byte.
//!
//!    Any missing, unreadable, mismatched, or hot-unplugged sysfs attribute fails
//!    closed: the descriptor is immediately closed and never passed to the parser.
//! 3. Under [`ChannelIdentityPolicy::PtyTestOnly`] (explicit test/development
//!    harness opt-in): require `S_ISCHR`, Unix98 PTY slave major (`136..=143`),
//!    and `st_dev` matching `/dev/pts` (verified as `DEVPTS_SUPER_MAGIC` at
//!    startup before seccomp). Before seccomp is installed, also verify
//!    `fstatfs(fd) == DEVPTS_SUPER_MAGIC` and `isatty(fd)`. Post-seccomp reopens
//!    rely only on `fstat(fd)`, requiring zero extra syscalls in the CVM
//!    executor seccomp filter.
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use nix::fcntl::{OFlag, open, openat, readlinkat};
use nix::sys::stat::{Mode, SFlag, fstat, major, minor};
use nix::sys::statfs::{DEVPTS_SUPER_MAGIC, fstatfs, statfs};

use crate::channel::{OpenError, open_device};
use crate::config::{ChannelTransport, Config};
use crate::ipc::IPC_FD;
use crate::kernel::ipc::dup_above_cloexec;

/// Upper bound on reading `/sys/dev/char/<major>:<minor>/name` (a port name
/// plus trailing newline is at most 256 bytes; reading 512 bytes detects
/// oversized/unexpected files without unbounded allocation).
const MAX_SYSFS_NAME_BYTES: usize = 512;

/// First Linux Unix98 PTY slave major (`UNIX98_PTY_SLAVE_MAJOR`, Linux ABI).
const UNIX98_PTY_SLAVE_MAJOR_MIN: u32 = 136;

/// Last Linux Unix98 PTY slave major (`UNIX98_PTY_SLAVE_MAJOR + 7`, Linux ABI).
const UNIX98_PTY_SLAVE_MAJOR_MAX: u32 = 143;

/// Expected sysfs subsystem name for virtio-serial ports (matching
/// `packaging/udev/99-qeminga.rules`).
const VIRTIO_PORTS_SUBSYSTEM: &str = "virtio-ports";

/// Why an opened channel descriptor failed identity verification.
#[derive(Debug, thiserror::Error)]
pub enum ChannelVerifyError {
    /// `fstat(2)` on the opened descriptor failed.
    #[error("cannot fstat opened channel descriptor: {0}")]
    Stat(#[source] io::Error),
    /// The opened path is not a character device (`S_ISCHR`).
    #[error("opened channel is not a character device (st_mode={mode:#o})")]
    NotCharDevice {
        /// Raw `st_mode` reported by `fstat(2)`.
        mode: u32,
    },
    /// Opening `/sys/dev/char/<major>:<minor>` failed (missing device,
    /// unreadable sysfs, or hotplug race).
    #[error("cannot open sysfs device directory for {major}:{minor}: {source}")]
    SysfsDirOpen {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// Reading the `subsystem` symlink under the sysfs device directory failed.
    #[error("cannot read sysfs subsystem link for {major}:{minor}: {source}")]
    SubsystemRead {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// The device does not belong to the `virtio-ports` subsystem.
    #[error(
        "character device {major}:{minor} belongs to subsystem {found:?}, expected \"virtio-ports\""
    )]
    SubsystemMismatch {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
        /// Observed final path component of the `subsystem` symlink.
        found: String,
    },
    /// Opening or reading the `name` sysfs attribute failed.
    #[error("cannot read sysfs port name for {major}:{minor}: {source}")]
    PortNameRead {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },
    /// The sysfs `name` attribute did not match `<expected>\n` byte-for-byte.
    #[error("virtio-port {major}:{minor} has sysfs name {found:?}, expected {expected:?}")]
    PortNameMismatch {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
        /// Expected port name (without trailing newline).
        expected: String,
        /// Observed sysfs content (bounded lossy representation).
        found: String,
    },
    /// `/dev/pts` could not be verified as a `devpts` mount when constructing
    /// the test-only PTY policy.
    #[error("devpts verification unavailable for pty-test-only transport")]
    DevptsUnavailable,
    /// The opened character device is not a Unix98 PTY slave on the verified
    /// `devpts` filesystem.
    #[error("character device {major}:{minor} is not a verified devpts PTY slave")]
    NotDevptsPty {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
    },
    /// Pre-seccomp `isatty(3)` rejected the opened descriptor.
    #[error("character device {major}:{minor} is not a tty")]
    NotTty {
        /// Character device major number.
        major: u32,
        /// Character device minor number.
        minor: u32,
    },
}

/// Verification rule applied to every channel descriptor opened by the executor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelIdentityPolicy {
    /// Production: require `S_ISCHR` + sysfs `subsystem == "virtio-ports"` +
    /// exact `name == "<expected_port_name>\n"`.
    VirtioSerial {
        /// Expected virtio-serial port name (without trailing `\n`).
        expected_port_name: String,
        /// Root of sysfs (production: `/sys`; tests may inject a temp root).
        sysfs_root: PathBuf,
    },
    /// Test/development harness opt-in: require `S_ISCHR` + Unix98 PTY slave
    /// major (`136..=143`) + `st_dev == devpts_st_dev` (plus `fstatfs` +
    /// `isatty` before seccomp is installed).
    PtyTestOnly {
        /// `st_dev` of `/dev/pts` verified as `DEVPTS_SUPER_MAGIC` at startup
        /// before seccomp is installed (`None` fails closed).
        devpts_st_dev: Option<u64>,
    },
}

/// Probes `/dev/pts` before seccomp to capture its `st_dev` only if `statfs(2)`
/// confirms `DEVPTS_SUPER_MAGIC`.
fn probe_devpts_st_dev() -> Option<u64> {
    let devpts = Path::new("/dev/pts");
    let fs = statfs(devpts).ok()?;
    if fs.filesystem_type() != DEVPTS_SUPER_MAGIC {
        return None;
    }
    let st = nix::sys::stat::stat(devpts).ok()?;
    Some(st.st_dev)
}

impl ChannelIdentityPolicy {
    /// Derives the verification policy from validated guest configuration.
    ///
    /// Must be called before installing seccomp when `channel_transport ==
    /// PtyTestOnly` so `/dev/pts` is verified via `statfs(2)` once at startup.
    pub fn from_config(config: &Config) -> Self {
        match config.agent.channel_transport {
            ChannelTransport::VirtioSerial => Self::VirtioSerial {
                expected_port_name: config.agent.expected_virtio_port_name().to_owned(),
                sysfs_root: PathBuf::from("/sys"),
            },
            ChannelTransport::PtyTestOnly => Self::PtyTestOnly {
                devpts_st_dev: probe_devpts_st_dev(),
            },
        }
    }

    /// Constructs a `VirtioSerial` policy rooted at `sysfs_root` (for tests).
    pub fn virtio_serial_with_sysfs(
        expected_port_name: impl Into<String>,
        sysfs_root: impl Into<PathBuf>,
    ) -> Self {
        Self::VirtioSerial {
            expected_port_name: expected_port_name.into(),
            sysfs_root: sysfs_root.into(),
        }
    }

    /// Constructs a `PtyTestOnly` policy by probing `/dev/pts` now.
    pub fn pty_test_only() -> Self {
        Self::PtyTestOnly {
            devpts_st_dev: probe_devpts_st_dev(),
        }
    }

    /// Verifies that the already-opened descriptor `fd` satisfies this policy.
    ///
    /// `before_seccomp` is `true` only during initial startup before the
    /// executor installs its seccomp filter (enabling pre-seccomp `fstatfs` and
    /// `isatty` checks for `PtyTestOnly`).
    pub fn verify_fd(
        &self,
        fd: BorrowedFd<'_>,
        before_seccomp: bool,
    ) -> Result<(), ChannelVerifyError> {
        let st = fstat(fd).map_err(|e| ChannelVerifyError::Stat(io::Error::from(e)))?;
        let file_type = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT;
        if file_type != SFlag::S_IFCHR {
            return Err(ChannelVerifyError::NotCharDevice { mode: st.st_mode });
        }
        let maj = u32::try_from(major(st.st_rdev)).unwrap_or(u32::MAX);
        let min = u32::try_from(minor(st.st_rdev)).unwrap_or(u32::MAX);
        match self {
            Self::VirtioSerial {
                expected_port_name,
                sysfs_root,
            } => verify_virtio_sysfs(sysfs_root, maj, min, expected_port_name),
            Self::PtyTestOnly { devpts_st_dev } => {
                let Some(expected_dev) = devpts_st_dev else {
                    return Err(ChannelVerifyError::DevptsUnavailable);
                };
                if !(UNIX98_PTY_SLAVE_MAJOR_MIN..=UNIX98_PTY_SLAVE_MAJOR_MAX).contains(&maj)
                    || st.st_dev != *expected_dev
                {
                    return Err(ChannelVerifyError::NotDevptsPty {
                        major: maj,
                        minor: min,
                    });
                }
                if before_seccomp {
                    let fs = fstatfs(fd).map_err(|_| ChannelVerifyError::NotDevptsPty {
                        major: maj,
                        minor: min,
                    })?;
                    if fs.filesystem_type() != DEVPTS_SUPER_MAGIC {
                        return Err(ChannelVerifyError::NotDevptsPty {
                            major: maj,
                            minor: min,
                        });
                    }
                    match nix::unistd::isatty(fd) {
                        Ok(true) => {}
                        _ => {
                            return Err(ChannelVerifyError::NotTty {
                                major: maj,
                                minor: min,
                            });
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// Verifies `<sysfs_root>/dev/char/<major>:<minor>` has `subsystem` ending in
/// `"virtio-ports"` and `name` equal to `<expected_port_name>\n`.
fn verify_virtio_sysfs(
    sysfs_root: &Path,
    maj: u32,
    min: u32,
    expected_port_name: &str,
) -> Result<(), ChannelVerifyError> {
    let dir_path = sysfs_root
        .join("dev")
        .join("char")
        .join(format!("{maj}:{min}"));
    // Intentionally follow the kernel's `/sys/dev/char/<maj>:<min>` symlink to
    // the device directory (OQ-10 §4.2), pinning that directory descriptor for
    // both attribute checks.
    let dirfd = open(
        &dir_path,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ChannelVerifyError::SysfsDirOpen {
        major: maj,
        minor: min,
        source: io::Error::from(e),
    })?;

    let subsystem_target =
        readlinkat(&dirfd, "subsystem").map_err(|e| ChannelVerifyError::SubsystemRead {
            major: maj,
            minor: min,
            source: io::Error::from(e),
        })?;
    let subsystem_name = Path::new(&subsystem_target).file_name();
    if subsystem_name != Some(OsStr::new(VIRTIO_PORTS_SUBSYSTEM)) {
        return Err(ChannelVerifyError::SubsystemMismatch {
            major: maj,
            minor: min,
            found: subsystem_name
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| subsystem_target.to_string_lossy().into_owned()),
        });
    }

    let name_fd = openat(
        &dirfd,
        "name",
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| ChannelVerifyError::PortNameRead {
        major: maj,
        minor: min,
        source: io::Error::from(e),
    })?;
    let mut buf = Vec::with_capacity(64);
    let mut reader = std::fs::File::from(name_fd).take((MAX_SYSFS_NAME_BYTES + 1) as u64);
    reader
        .read_to_end(&mut buf)
        .map_err(|source| ChannelVerifyError::PortNameRead {
            major: maj,
            minor: min,
            source,
        })?;

    let mut expected = Vec::with_capacity(expected_port_name.len() + 1);
    expected.extend_from_slice(expected_port_name.as_bytes());
    expected.push(b'\n');
    if buf != expected {
        let preview_len = buf.len().min(64);
        return Err(ChannelVerifyError::PortNameMismatch {
            major: maj,
            minor: min,
            expected: expected_port_name.to_owned(),
            found: String::from_utf8_lossy(&buf[..preview_len]).into_owned(),
        });
    }
    Ok(())
}

/// Opens `path` with `O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC`, verifies its
/// backing character-device identity against `policy`, and closes the
/// descriptor immediately on any verification failure.
///
/// When `before_seccomp` is `true`, ensures the returned descriptor is `> IPC_FD`
/// so slot `IPC_FD` (`3`) stays unoccupied for pinning the executor IPC socket.
pub fn open_verified_channel(
    path: &Path,
    policy: &ChannelIdentityPolicy,
    before_seccomp: bool,
) -> Result<OwnedFd, OpenError> {
    let fd = open_device(path).map_err(|err| OpenError::from_io(path, err))?;
    if let Err(err) = policy.verify_fd(fd.as_fd(), before_seccomp) {
        drop(fd);
        return Err(OpenError::Io {
            path: path.to_owned(),
            source: io::Error::new(io::ErrorKind::PermissionDenied, err),
        });
    }
    if before_seccomp && fd.as_raw_fd() <= IPC_FD {
        return dup_above_cloexec(fd, IPC_FD + 1)
            .map_err(|e| OpenError::from_io(path, io::Error::from(e)));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::os::unix::fs::symlink;

    use super::*;

    fn open_test_pty() -> (OwnedFd, String, OwnedFd) {
        let master =
            nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
        nix::pty::grantpt(&master).unwrap();
        nix::pty::unlockpt(&master).unwrap();
        let slave_path = nix::pty::ptsname_r(&master).unwrap();
        let holder = open(
            Path::new(&slave_path),
            OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        (master.into(), slave_path, holder)
    }

    #[test]
    fn rejects_non_char_devices_and_unrelated_char_devices_under_both_policies() {
        let dir = tempfile::tempdir().unwrap();
        let regular = dir.path().join("regular");
        std::fs::write(&regular, b"hello").unwrap();
        let fifo = dir.path().join("fifo");
        nix::unistd::mkfifo(&fifo, Mode::from_bits_truncate(0o600)).unwrap();

        let virtio = ChannelIdentityPolicy::virtio_serial_with_sysfs(
            "org.qemu.guest_agent.0",
            dir.path().join("sys"),
        );
        let pty_pol = ChannelIdentityPolicy::pty_test_only();

        // Regular file rejected by both policies.
        for policy in [&virtio, &pty_pol] {
            let err = open_verified_channel(&regular, policy, true).unwrap_err();
            assert!(err.to_string().contains("not a character device"), "{err}");
            assert!(!err.is_terminal());
        }

        // Directory rejected directly by verify_fd.
        let dir_fd = open(
            dir.path(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            virtio.verify_fd(dir_fd.as_fd(), true),
            Err(ChannelVerifyError::NotCharDevice { .. })
        ));
        assert!(matches!(
            pty_pol.verify_fd(dir_fd.as_fd(), true),
            Err(ChannelVerifyError::NotCharDevice { .. })
        ));

        // FIFO rejected directly by verify_fd.
        let fifo_fd = open(
            &fifo,
            OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            virtio.verify_fd(fifo_fd.as_fd(), true),
            Err(ChannelVerifyError::NotCharDevice { .. })
        ));

        // Unix socket rejected directly by verify_fd.
        let (s1, _s2) = crate::kernel::ipc::seqpacket_pair(true).unwrap();
        assert!(matches!(
            virtio.verify_fd(s1.as_fd(), true),
            Err(ChannelVerifyError::NotCharDevice { .. })
        ));
        assert!(matches!(
            pty_pol.verify_fd(s1.as_fd(), true),
            Err(ChannelVerifyError::NotCharDevice { .. })
        ));

        // `/dev/null` (char device 1:3) rejected by both policies.
        let null_fd = open(
            Path::new("/dev/null"),
            OFlag::O_RDWR | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            virtio.verify_fd(null_fd.as_fd(), true),
            Err(ChannelVerifyError::SysfsDirOpen {
                major: 1,
                minor: 3,
                ..
            })
        ));
        assert!(matches!(
            pty_pol.verify_fd(null_fd.as_fd(), true),
            Err(ChannelVerifyError::NotDevptsPty { major: 1, minor: 3 })
        ));

        // `/dev/ptmx` (master, major 5) is rejected by PtyTestOnly even though
        // it is a char device.
        let ptmx =
            nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC).unwrap();
        assert!(matches!(
            pty_pol.verify_fd(ptmx.as_fd(), true),
            Err(ChannelVerifyError::NotDevptsPty { .. })
        ));
    }

    #[test]
    fn pty_test_only_accepts_real_pty_slave_pre_and_post_seccomp_while_virtio_rejects_it() {
        let (_master, slave_path, _holder) = open_test_pty();
        let pty_pol = ChannelIdentityPolicy::pty_test_only();

        // Both pre-seccomp (fstat + fstatfs + isatty) and post-seccomp (fstat only) accept.
        let fd_pre = open_verified_channel(Path::new(&slave_path), &pty_pol, true).unwrap();
        assert!(fd_pre.as_raw_fd() > IPC_FD);
        let fd_post = open_verified_channel(Path::new(&slave_path), &pty_pol, false).unwrap();
        drop((fd_pre, fd_post));

        // Production VirtioSerial policy rejects a PTY slave.
        let cfg = Config::default();
        let prod = ChannelIdentityPolicy::from_config(&cfg);
        assert!(open_verified_channel(Path::new(&slave_path), &prod, true).is_err());

        // Unavailable devpts_st_dev fails closed.
        let closed = ChannelIdentityPolicy::PtyTestOnly {
            devpts_st_dev: None,
        };
        assert!(open_verified_channel(Path::new(&slave_path), &closed, true).is_err());
    }

    #[test]
    fn virtio_sysfs_verification_checks_subsystem_and_exact_port_name_and_fails_closed() {
        // Use `/dev/null` (1:3) as a real openable character device against a
        // synthetic sysfs root to test every virtio-ports predicate cleanly
        // without needing real QEMU virtio-console hardware.
        let sysfs = tempfile::tempdir().unwrap();
        let dev_dir = sysfs.path().join("devices/vport0p1");
        let bus_virtio = sysfs.path().join("bus/virtio-ports");
        let bus_misc = sysfs.path().join("bus/misc");
        std::fs::create_dir_all(&dev_dir).unwrap();
        std::fs::create_dir_all(&bus_virtio).unwrap();
        std::fs::create_dir_all(&bus_misc).unwrap();
        std::fs::create_dir_all(sysfs.path().join("dev/char")).unwrap();

        let char_link = sysfs.path().join("dev/char/1:3");
        symlink(&dev_dir, &char_link).unwrap();
        let subsys_link = dev_dir.join("subsystem");
        symlink(&bus_virtio, &subsys_link).unwrap();
        std::fs::write(dev_dir.join("name"), b"org.qemu.guest_agent.0\n").unwrap();

        let policy =
            ChannelIdentityPolicy::virtio_serial_with_sysfs("org.qemu.guest_agent.0", sysfs.path());
        // Valid virtio-ports subsystem + exact name passes.
        let fd = open_verified_channel(Path::new("/dev/null"), &policy, true).unwrap();
        assert!(fd.as_raw_fd() > IPC_FD);
        drop(fd);

        // Wrong port name fails.
        std::fs::write(dev_dir.join("name"), b"org.qemu.guest_agent.1\n").unwrap();
        let null_fd = open(
            Path::new("/dev/null"),
            OFlag::O_RDWR | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        assert!(matches!(
            policy.verify_fd(null_fd.as_fd(), false),
            Err(ChannelVerifyError::PortNameMismatch {
                major: 1,
                minor: 3,
                ..
            })
        ));

        // Missing trailing newline fails (exact byte-for-byte check).
        std::fs::write(dev_dir.join("name"), b"org.qemu.guest_agent.0").unwrap();
        assert!(matches!(
            policy.verify_fd(null_fd.as_fd(), false),
            Err(ChannelVerifyError::PortNameMismatch { .. })
        ));

        // Symlinked `name` attribute rejected via O_NOFOLLOW.
        let decoy = sysfs.path().join("decoy-name");
        std::fs::write(&decoy, b"org.qemu.guest_agent.0\n").unwrap();
        std::fs::remove_file(dev_dir.join("name")).unwrap();
        symlink(&decoy, dev_dir.join("name")).unwrap();
        assert!(matches!(
            policy.verify_fd(null_fd.as_fd(), false),
            Err(ChannelVerifyError::PortNameRead { .. })
        ));

        // Restore real file, then spoof subsystem (`misc` with matching `name`):
        // must fail closed!
        std::fs::remove_file(dev_dir.join("name")).unwrap();
        std::fs::write(dev_dir.join("name"), b"org.qemu.guest_agent.0\n").unwrap();
        std::fs::remove_file(&subsys_link).unwrap();
        symlink(&bus_misc, &subsys_link).unwrap();
        assert!(matches!(
            policy.verify_fd(null_fd.as_fd(), false),
            Err(ChannelVerifyError::SubsystemMismatch {
                major: 1,
                minor: 3,
                ref found,
            }) if found == "misc"
        ));

        // Missing `subsystem` symlink fails closed.
        std::fs::remove_file(&subsys_link).unwrap();
        assert!(matches!(
            policy.verify_fd(null_fd.as_fd(), false),
            Err(ChannelVerifyError::SubsystemRead { .. })
        ));

        // Hot-unplugged `/sys/dev/char/1:3` fails closed (`ENOENT`).
        std::fs::remove_file(&char_link).unwrap();
        assert!(matches!(
            policy.verify_fd(null_fd.as_fd(), false),
            Err(ChannelVerifyError::SysfsDirOpen { .. })
        ));
    }
}
