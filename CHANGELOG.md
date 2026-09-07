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
  `guest-fsfreeze-status/freeze/freeze-list/thaw`, `guest-fstrim` (reports
  the minimum extent the kernel applied, not the requested one),
  `guest-shutdown` (`sync(2)` then `reboot(2)`: a hard shutdown, no
  service is stopped; no success reply), and the opt-in
  `guest-suspend-ram` (no success reply, as upstream: the host watches the
  QMP `SUSPEND`/`WAKEUP` events).
- Freeze lifecycle: mount plan from `/proc/self/mountinfo`, parsed as
  bytes so a mount point that is not UTF-8 is kept byte-exact (ext4/xfs on
  `/dev` nodes, bind mounts de-duplicated, reverse mount order), recovery
  marker created with `O_EXCL` + `fsync` before the first `FIFREEZE`, thaw
  drains each target until its first error (bounded at 1024 calls; a denied
  first `FITHAW` or a drain that never converges keeps the state `Frozen`),
  a failed freeze rolls back every processed target before reporting the
  first one it could not thaw, the audit flush of a thaw completes before
  the state is published as thawed, watchdog with idle timeout and hard cap
  (deadlines take priority over heartbeats), and recovery mode after a
  crash, armed before and independently of the channel.
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

- `guest-shutdown` has hard semantics (`sync(2)` + `reboot(2)`); an orderly
  service-manager shutdown needs `CAP_KILL` or D-Bus and is an open design
  decision (`docs/tasks.md` OQ-1).

- The privileged and seccomp matrix jobs run on x86-64 only; the aarch64
  profile is compiled and checked but not executed.
- The libvirt interoperability script has not yet been run against a real
  host; see `docs/tasks.md` §7.
