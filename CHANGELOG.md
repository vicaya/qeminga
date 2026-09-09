# Changelog

All notable changes to qeminga. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
semantic versioning.

## [Unreleased]

### Added

- Freeze operation deadline (`[agent] fsfreeze_operation_timeout_secs`;
  omitted it derives `min(60, fsfreeze_max_timeout_secs)`, an explicit
  value must be at most the hard cap): a `guest-fsfreeze-freeze` whose
  walk is still inside `FIFREEZE` when the deadline expires is aborted;
  the targets frozen so far are thawed through their descriptors while
  the blocked call is still awaited, the request fails with a
  `GenericError` naming the target in flight, and the marker, the frozen
  gate and the freeze-safe audit mode stay until the operation settles
  (design §4.4 "Operation deadline", OQ-8 freeze-walk part, #39).

### Changed

- A `guest-fsfreeze-thaw` received while a freeze walk is under way aborts
  the walk and is answered at once with the recovery pending, instead of
  being refused.
- The channel session admits commands by lane: one command that may
  change the guest at a time, in request order among themselves; up to
  three frozen-safe controls beside it (status is served while a
  recovery drain is blocked) and a thaw beside a running freeze (it
  reaches the operation before the deadline, even behind a queued walk).
  At most eight commands are held from decoding to delivery and at most
  64 KiB of undelivered replies are kept, so a peer that stops reading
  stops being read; replies stay in request order; a reply the host is
  slow to read stalls neither the commands behind it nor a stop; a stop
  finishes the commands running before the session ends, and so does a
  lost peer.
- The freeze walk runs one tracked blocking task per target, publishing
  each completed descriptor before the next target is authorised; a late
  completion is drained through its own descriptor and is never published
  as `Frozen`.

## [0.1.0] - 2026-09-03

First release: the complete command set of `docs/design.md`.

### Added

- CI: coverage over the unprivileged suites with `cargo llvm-cov`, an
  85 % floor on production lines (inline test modules and the scripted
  kernel double excluded), and CI,
  tests and coverage badges rendered by `scripts/ci/badge.sh` and
  published to the `badges` branch by a separate job.
- Protocol core: QGA wire types with a strict map-only request parser
  (unknown and duplicate keys rejected, `i64` ids), newline framing with a
  64 KiB frame bound, discard-until-newline and `0xFF` resynchronisation,
  and pre-parse bounds on JSON depth (32) and string length (4096 bytes).
- Static allowlist dispatcher (`match` arms only) with the runtime feature
  gate, per-class token-bucket rate limiting (120/30/10/5/2 per minute,
  thaw and status unlimited), and the frozen gate.
- Handlers: `guest-ping`, `guest-info`, `guest-sync`, `guest-sync-delimited`,
  `guest-get-osinfo`, `guest-network-get-interfaces`, `guest-get-fsinfo`
  (sizes skipped on network, FUSE and autofs mounts; the walk bounded at
  10 s and at most two walks alive at once, so a share whose server is
  gone cannot pile up stuck threads),
  `guest-fsfreeze-status/freeze/freeze-list/thaw`, `guest-fstrim` (reports
  the minimum extent the kernel applied, not the requested one),
  `guest-shutdown` (`sync(2)` then `reboot(2)`: a hard shutdown, no
  service is stopped; no success reply), and the opt-in
  `guest-suspend-ram` (no success reply, as upstream: the host watches the
  QMP `SUSPEND`/`WAKEUP` events).
- Freeze lifecycle: mount plan from `/proc/self/mountinfo`, parsed as
  bytes so a mount point that is not UTF-8 is kept byte-exact (ext4/xfs on
  `/dev` nodes, bind mounts de-duplicated with every mount point of a
  superblock kept as an alias, reverse mount order); every `FIFREEZE`,
  `FITHAW` and `FITRIM` goes through a descriptor opened on one of the
  target's mount points and verified with `fstat(2)` against the planned
  device, so a mount placed over a planned mountpoint is never frozen or
  thawed in its place (a hidden first pathname is retried through an
  alias, the descriptors a freeze opened are held until their drain
  completes, and a superblock no pathname leads to is reported unreachable
  with the recovery state retained); recovery marker created with
  `O_EXCL` + `fsync` before the first `FIFREEZE`, in a directory opened
  once at startup and judged by its device against the plan (never by the
  pathname, which sees neither `..` nor a symlinked parent); thaw drains
  each target until its first error (bounded at 1024 calls) and counts it
  complete only on the kernel's own "not frozen" answer (`EINVAL`, or
  `EOPNOTSUPP` for a filesystem that cannot freeze): a denied or failed
  `FITHAW`, an error from before the ioctl whatever its errno, or a drain
  that never converges keeps the marker and the state `Frozen`,
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
  deferred `SIGTERM` while frozen (and, once thawed, honoured even while a
  reply is stuck on a host that has stopped reading); the runtime is shut
  down under a 5 s bound once the loop has stopped, so an abandoned
  `statfs` cannot hold the exit.
- Packaging: systemd unit (not bound to the port's device unit, so a crash
  while frozen is recovered whether or not the port is there), udev rule,
  sysusers entry, example config.
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
