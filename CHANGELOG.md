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

### Added

- Design §4.5, the snapshot controller contract: what the freeze, status
  and thaw replies mean, the one supported protocol for the interval a
  freeze protects (one mount point per required superblock, one freeze
  per cycle under a client timeout, heartbeats and a cycle budget under
  the hard cap, one thaw, quiesced only when the freeze count and the
  thaw count both equal the number requested), its assumptions and
  their limit; the reference controller in `tests/controller_contract.rs`
  exercises it against the production coordinator and watchdog (#43 §1);
  a thaw reply past the budget is rejected whatever its count. The
  scripted kernel can model the freeze nesting depth per superblock
  (`FakeKernel::track_freeze_depth`), and a harness can end a dead
  instance's tasks as a crash would (`Context::abort_tasks`, hidden from
  the documented API; the daemon never calls it).

### Fixed

- The thaw of a freeze operation this process completed drains the
  descriptors the operation published (its frozen targets and the
  `EBUSY` ones it retained) and nothing else, reading no mount table: a
  superblock the operation never froze, one hidden under a mount over
  its ancestor or one outside a `guest-fsfreeze-freeze-list` request,
  cannot hold the thaw. Before, every thaw discovered every eligible
  superblock through the table and reported a planned one reached by no
  pathname as unrecoverable, so after a freeze through a directory
  overmount the marker and the frozen gate stayed while a filesystem
  that was never frozen remained hidden. Recovery drains (after a
  restart, from `Thawed`, or after an operation or a thaw that lost a
  worker or a drain) keep the table-wide discovery and the conservative
  rule (design §4.2 "Thaw scope"; #43, external review).
- `guest-fsfreeze-freeze-list`: a mount table whose root carries its own
  id as its parent id (valid per proc_pid_mountinfo(5)) resolved no
  requested name, so the request froze nothing and replied `0`; such a
  root is now walked from (#43, external review).
- `guest-fsfreeze-freeze-list`: a requested mount point selects the
  superblock its pathname leads to now, resolved as the kernel resolves
  the path (from the root mount along the components, by mount ids and
  parents), never a superblock whose mount point is hidden by a mount
  over it or over any directory above it, and the freeze opens a
  selected superblock on the requested name only, so a name that leads
  elsewhere fails the operation instead of an alias standing in. Before,
  a name carried by two targets (one of them hidden) selected both, so
  the count could equal the number requested while a requested
  filesystem was never frozen; a controller relying on the count (design
  §4.2 "Coverage", §4.5) would have accepted that (#43 §1, external
  review).
  superblock mounted at that path now, never a superblock whose former
  mount point has been hidden by a mount over it. Before, a name carried
  by two targets (one of them hidden) selected both, so the count could
  equal the number requested while a requested filesystem was never
  frozen; a controller relying on the count (design §4.2 "Coverage",
  §4.5) would have accepted that (#43 §1, external review).
- Audit delivery is off every recovery and finalisation path (#43 §3):
  the sink is written by one dedicated writer thread through a bounded
  256 KiB delivery queue, so a journald that stops reading blocks that
  thread and nothing else; a thaw finalises its marker and publishes
  `Thawed` whether or not a record has been delivered. The writer parks
  while the freeze-safe ring is in use. Records dropped at a full queue
  or refused by the sink are counted and reported, like the ring's
  overflow, by an `audit_records_lost` record delivered where the gap
  is, now with a `reason` (`ring_overflow`, `sink_backpressure`,
  `sink_error`). `guest-shutdown` waits at most 2 s for its own record
  before `reboot(2)`.
- A freeze that froze nothing and holds nothing (an empty plan, a
  `guest-fsfreeze-freeze-list` matching no mount point, or a plan every
  target of which was skipped) settles `Thawed` with its marker removed
  and replies `0`, instead of `Frozen` with the watchdog armed and the
  gate closed on nothing. An `EBUSY` target, an uncertain result or a
  marker that cannot be removed still keep the conservative state; the
  last is now reported as an error rather than a `0` (#43 §2).

### Changed

- A `guest-fsfreeze-thaw` received while a freeze walk is under way aborts
  the walk and is answered at once with the recovery pending, instead of
  being refused.
- The channel session admits commands by lane: one command that may
  change the guest at a time, in request order among themselves; up to
  three frozen-safe controls beside it (status is served while a
  recovery drain is blocked) and a thaw beside a running freeze (it
  reaches the operation before the deadline, even behind a queued walk).
  The queue has eight places owned from decoding to delivery in request
  order (an overtaking control never takes the place of the command it
  overtook) and a 64 KiB backpressure threshold on undelivered replies,
  so a peer that stops reading stops being read; replies stay in request order; a reply the host is
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
