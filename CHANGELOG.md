# Changelog

All notable changes to qeminga. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning.

## [0.1.0] - 2026-09-03

First release: the complete command set of `docs/design.md`.

### Added

- Protocol core: QGA wire types with a strict map-only request parser
  (unknown and duplicate keys rejected, `i64` ids), newline framing with a
  64 KiB frame bound, discard-until-newline and `0xFF` resynchronisation,
  and pre-parse bounds on JSON depth (32) and string length (4096 bytes).
- Static allowlist dispatcher (`match` arms only) with the runtime feature
  gate, per-class token-bucket rate limiting (120/30/10/5/2 per minute,
  thaw and status unlimited), and the frozen gate.
- Handlers: `guest-ping`, `guest-info`, `guest-sync`, `guest-sync-delimited`,
  `guest-get-osinfo`, `guest-network-get-interfaces`, `guest-get-fsinfo`,
  `guest-fsfreeze-status/freeze/freeze-list/thaw`, `guest-fstrim`,
  `guest-shutdown`, and the opt-in `guest-suspend-ram`.
- Freeze lifecycle: mount plan from `/proc/self/mountinfo` (ext4/xfs on
  `/dev` nodes, bind mounts de-duplicated, reverse mount order), recovery
  marker created with `O_EXCL` + `fsync` before the first `FIFREEZE`, thaw
  drains until `EINVAL`, watchdog with idle timeout and hard cap, and
  recovery mode after a crash.
- Audit: one structured JSON record per command, method projection with a
  SHA-256 digest for over-long names, and a 64 KiB freeze-safe ring with a
  loss record on overflow.
- Privilege containment: capability drop to `CAP_SYS_ADMIN`, `CAP_SYS_BOOT`,
  `CAP_DAC_READ_SEARCH` under the `qeminga` account with
  `PR_SET_NO_NEW_PRIVS`, and per-architecture seccomp profiles (x86-64,
  aarch64) with `ioctl` restricted to `FIFREEZE`/`FITHAW`/`FITRIM`.
- Channel handling: non-blocking virtio-serial I/O, EOF/HUP reconnect with
  bounded backoff, `EBUSY` as the terminal `channel_already_open` error,
  deferred `SIGTERM` while frozen.
- Packaging: systemd unit, udev rule, sysusers entry, example config.
- Tests: property tests, fuzz targets, an unprivileged end-to-end suite
  over a pty, privileged tests on loop-mounted filesystems, and a manual
  libvirt interoperability script.

### Known gaps

- The privileged and seccomp matrix jobs run on x86-64 only; the aarch64
  profile is compiled and checked but not executed.
- The libvirt interoperability script has not yet been run against a real
  host; see `docs/tasks.md` §7.
