# Packaging qeminga

Files shipped with the daemon (design §8.2–§8.4, §5.7, §8.5, C-20):

| File | Installs to | Purpose |
|---|---|---|
| `systemd/qeminga.service` | `/usr/lib/systemd/system/` | The unit: conflicts with `qemu-guest-agent.service`, deliberately does not bind to the virtio port device (a crash while frozen is recovered whether or not the port is there; the daemon retries the open), hands `/run/qeminga` to the service account before every start (privileged `ExecStartPre` lines; not `RuntimeDirectory=`, see below), `TimeoutStopSec=330s` for the default 300 s freeze cap. |
| `udev/99-qeminga.rules` | `/etc/udev/rules.d/` or `/usr/lib/udev/rules.d/` | Hands the single-open port `org.qemu.guest_agent.0` to the `qeminga` account, mode 0600 (§8.3). |
| `sysusers.d/qeminga.conf` | `/usr/lib/sysusers.d/` | Creates user and group `qeminga`, uid/gid 600, no login shell. |
| `config-data-protection.toml` | `/etc/qeminga/config.toml` (**CVM installation default**) | The data-protection profile (§5.9): freeze, thaw, status and the controls only; explicitly sets `shutdown = false`, `information = false`, and `fstrim = false` so `CAP_SYS_BOOT`, `reboot(2)`, `uname`, `statfs`, netlink and `FITRIM` are given up. |
| `config.toml` | `/etc/qeminga/config.toml` (general-VM / TOML schema default) | General-VM / libvirt lifecycle defaults (§8.2): enables `guest-shutdown`, `guest-fstrim`, and the information commands (`guest-get-osinfo`, `guest-network-get-interfaces`, `guest-get-fsinfo`); every key is optional and omitted `[features]` switches default to `true`. |
| `tmpfiles.d/qeminga.conf` | `/usr/lib/tmpfiles.d/` | Creates `/run/qeminga` (0700, owned by `qeminga`) at boot for the recovery marker (C-20). Always install it and run `systemd-tmpfiles --create`. |
| `tmpfiles.d/qeminga-suspend.conf` | `/usr/lib/tmpfiles.d/` **only with** `[features] suspend_ram = true` | Hands `/sys/power/state` to group `qeminga` (mode 0664) on every boot, without which the dropped daemon cannot write it (OQ-6). Not installed by default. |

The binary itself goes to `/usr/bin/qeminga`. Build releases with
`cargo build --release --locked --features seccomp`. Never build releases
with `--all-features`: both `seccomp::log_mode` and the `test-fakes`
compile-time guard (`compile_error!` in `src/lib.rs`) key off
`cfg!(debug_assertions)` (disabled in Cargo's standard `release` profile;
downstream Cargo profiles that override `debug-assertions` change both).
Under the shipped `release` profile (`debug_assertions = false`),
`test-fakes` fails to compile — so `cargo build --release --all-features`
fails at compile time — and `seccomp-log` still compiles an enforcing
(`kill_process`) filter. By contrast, a **debug** binary built with
`seccomp-log` (including `cargo build --all-features`) runs the filter in
logging mode (`debug_assertions = true`) and therefore fails the
`hardening = "enforced"` check at startup.

## Migration from qemu-guest-agent

qeminga and `qemu-guest-agent` must never run together: both contend for
the single-open channel (§8.4). The unit declares
`Conflicts=qemu-guest-agent.service`, and a package should declare a
package-level conflict too. To migrate by hand:

```sh
sudo systemctl disable --now qemu-guest-agent.service
sudo install -m 0755 target/release/qeminga /usr/bin/qeminga
sudo install -m 0644 packaging/sysusers.d/qeminga.conf /usr/lib/sysusers.d/
sudo systemd-sysusers                      # creates qeminga (600:600)
sudo install -m 0644 packaging/udev/99-qeminga.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger --subsystem-match=virtio-ports
sudo install -m 0644 packaging/tmpfiles.d/qeminga.conf /usr/lib/tmpfiles.d/
sudo systemd-tmpfiles --create qeminga.conf
sudo install -d -m 0755 /etc/qeminga
sudo install -m 0644 packaging/config-data-protection.toml /etc/qeminga/config.toml
sudo install -m 0644 packaging/systemd/qeminga.service /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now qeminga.service
```

The command above installs `packaging/config-data-protection.toml` (the
CVM installation default: snapshot coordination only). For a general-VM
deployment that needs `guest-shutdown`, `guest-fstrim`, or the
information commands (for example `virsh domifaddr`, `virsh domfsinfo`,
or `virsh shutdown --mode agent`), install `packaging/config.toml` as
`/etc/qeminga/config.toml` instead.

Verify with `systemctl status qeminga` and, from the host,
`virsh qemu-agent-command <domain> '{"execute":"guest-ping"}'`.

## Suspend to RAM

`guest-suspend-ram` is disabled by default. Enabling it takes the
`suspend_ram` Cargo feature, `[features] suspend_ram = true` in
`config.toml`, **and** two grants installed inside the guest for `/sys/power/state`:

1. Discretionary write access for the service account: the file is `0644 root:root` and none of the daemon's remaining capabilities bypasses that, so install `tmpfiles.d/qeminga-suspend.conf` and run `sudo systemd-tmpfiles --create qeminga-suspend.conf` (OQ-6).
2. A mount-namespace write exception: `qeminga.service` mounts `/sys` read-only inside the service's mount namespace (`ProtectKernelTunables=yes` and `BindReadOnlyPaths=/sys`). Add a drop-in (for example `/etc/systemd/system/qeminga.service.d/suspend.conf`), then run `sudo systemctl daemon-reload && sudo systemctl restart qeminga.service`:

```ini
[Service]
ReadWritePaths=/sys/power/state
```

Do not install either rule otherwise: together they are what lets the
account suspend the guest while leaving neighboring `/sys/power/*`
attributes read-only.

## Filesystem write confinement

The shipped unit (`packaging/systemd/qeminga.service`) confines ordinary
filesystem writes to `/run/qeminga` via `ProtectSystem=strict`,
`ProtectHome=read-only`, `ReadWritePaths=-/run/qeminga`,
`ProtectKernelTunables=yes`, `BindReadOnlyPaths=/sys /dev`,
`ReadOnlyPaths=/run`, `SystemCallFilter=~@mount`, and `UMask=0077`
(design §8.4, #66). `ProtectSystem=strict` and `ProtectHome=read-only`
remount the filesystem hierarchy read-only at the mount layer
(`MNT_READONLY`, not `SB_RDONLY`), so `FIFREEZE`, `FITHAW`, and `FITRIM`
on `O_RDONLY | O_DIRECTORY` descriptors still work on real `ext4`/`xfs`
superblocks (including separate `/home` mounts) while ordinary files
outside `/run/qeminga` cannot be modified or unlinked even when their
Unix permissions grant write access to UID `600`.
`BindReadOnlyPaths=/sys /dev` and `ReadOnlyPaths=/run` close the systemd
v248–v262 `MountAPIVFS` interaction where `ProtectKernelTunables=yes`
otherwise skips remounting already-mounted `/sys` and `/run` read-only,
and recursively lock ordinary files on `/dev` itself plus every
filesystem already mounted beneath `/dev` (`/dev/shm`, `/dev/mqueue`,
`/dev/hugepages`, etc.) read-only while keeping existing character
devices openable `O_RDWR` and still allowing a suspend drop-in to punch
`ReadWritePaths=/sys/power/state`. `SystemCallFilter=~@mount` (alongside
qeminga's own seccomp filter omitting mount syscalls and
`RestrictNamespaces=yes`) prevents undoing the read-only mount namespace
even while `CAP_SYS_ADMIN` is held.

### Writable object inventory (packaged CVM service)

- **During privileged startup (before privilege drop and seccomp):**
  - `ExecStartPre=+` runs as root without the unit's read-only sandboxing solely to ensure `/run/qeminga` exists (`mkdir -p`), is owned by `qeminga:qeminga` (`chown`), and is mode `0700` (`chmod`) — preserving any pre-existing recovery marker across restarts — before `ExecStart` enters its confined mount namespace. The leading `-` on `ReadWritePaths=-/run/qeminga` is required because systemd still evaluates `ReadWritePaths=` for `ExecStartPre=+`; without `-`, a missing `/run/qeminga` fails `ExecStartPre=+` with `226/NAMESPACE` before `mkdir -p` runs.
  - `ExecStart=/usr/bin/qeminga` starts inside the confined mount namespace (`ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=-/run/qeminga`, `ProtectKernelTunables=yes`, `BindReadOnlyPaths=/sys /dev`, `ReadOnlyPaths=/run`, `SystemCallFilter=~@mount`) as UID `0` with `CapabilityBoundingSet` (`CAP_SYS_ADMIN`, `CAP_SYS_BOOT`, `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`) to read `/etc/qeminga/config.toml`, pin `/run/qeminga`, open the channel device (`O_RDWR`), drop to UID/GID `600`, drop excess capabilities, set `NoNewPrivs`, and install the seccomp filter — before reading any host input.
- **After privilege drop (serving host input):**
  - `/run/qeminga` (`0700 qeminga:qeminga`, explicit `ReadWritePaths=-/run/qeminga`): the only ordinary-file directory writable to the service (for mounts present at service start), holding `/run/qeminga/frozen` (mode `0600`, reinforced by `UMask=0077`).
  - `/dev/virtio-ports/org.qemu.guest_agent.0` (`0600 qeminga:qeminga`, symlink to `/dev/vport*`): the read-write virtio-serial character device opened at startup and reopened after disconnect/hot-unplug.
  - Inherited `stderr` journald stream (`StandardError=journal`): structured audit records.
  - `/sys/power/state` **only** when the guest operator opts into `suspend_ram` (both guest-installed `tmpfiles.d/qeminga-suspend.conf` and a guest `ReadWritePaths=/sys/power/state` drop-in).
- **Residual writable locations:**
  - World-writable character devices under `/dev` (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/tty`, `/dev/ptmx`), because `PrivateDevices=yes` cannot be enabled without hiding `/dev/virtio-ports/org.qemu.guest_agent.0` (and PTY slaves used in installed-unit tests). Ordinary files on `/dev` itself and on every filesystem already mounted beneath `/dev` (such as `/dev/shm`, `/dev/mqueue`, and `/dev/hugepages`) are recursively locked read-only (`MNT_READONLY`) by `BindReadOnlyPaths=/sys /dev`, which blocks ordinary-file writes and unlinks (`EROFS`) while allowing `O_RDWR` open and I/O on existing character devices (including virtio-serial reopen after disconnect/hotplug).
  - Per-process procfs attribute files under `/proc/self/` (such as `/proc/self/comm` and `/proc/self/oom_score_adj`), which are kernel process interfaces rather than ordinary files.
  - **Filesystems mounted in the guest after the service starts:** per `systemd.exec(5)`, mount propagation from the guest's system-manager mount namespace passes newly attached guest mounts into the service's mount namespace with their original mount flags (so a read-write guest mount stays read-write, still bounded by UID `600` Unix permissions without `CAP_DAC_OVERRIDE`, while a read-only guest mount stays read-only), whereas every filesystem already mounted at service start is remounted `MNT_READONLY`. Restart `qeminga.service` if a static guest filesystem is mounted after boot and should also be locked `MNT_READONLY`.

### Why `PrivateTmp=no` and `ProtectHome=read-only` are chosen

- `PrivateTmp=no`: `PrivateTmp=yes` would overmount `/tmp` and `/var/tmp` with *writable* private tmpfs mounts. With `ProtectSystem=strict` and `PrivateTmp=no`, `/tmp` and `/var/tmp` are read-only (`MNT_READONLY`) and any real filesystem mounted there stays visible to `FreezePlan`.
- `ProtectHome=read-only`: `ProtectSystem=strict` deliberately leaves `/home`, `/root`, and `/run/user` to `ProtectHome=`, so `ProtectHome=no` would leave them writable, while `ProtectHome=yes` would overmount `/home` with an inaccessible node that hides separate `/home` ext4/xfs volumes from `FIFREEZE`. `ProtectHome=read-only` remounts `/home`, `/root`, and `/run/user` `MNT_READONLY` while keeping separate `/home` mounts visible and freezable.

### Custom marker location (`[agent] state_path`)

If you move `[agent] state_path` out of `/run/qeminga` (it must still
live on an unfreezable filesystem such as `tmpfs`; startup refuses a
freezable path), provision the parent directory (`0700 qeminga:qeminga`)
via `tmpfiles.d` and an `ExecStartPre=+` drop-in **and** grant it write
access with the leading `-` prefix (resetting `ExecStartPre=` and
`ReadWritePaths=` first so `/run/qeminga` is no longer created or left
writable, and keeping `-` so an absent directory can be created by
`ExecStartPre=+` on cold start without failing with `226/NAMESPACE`
while preserving any pre-existing marker across restarts).

**Trusted-parent requirement:** In the supported v1 recipe, `ExecStartPre=+`
resolves this pathname before changing ownership and mode, systemd resolves
`ReadWritePaths` independently when constructing the service mount namespace,
and `Marker::open` opens the configured parent directory by pathname again at
daemon startup — none of those steps passes a verified directory descriptor to
the next. With a replaceable ancestor, a later step could therefore resolve a
different directory (including one missing an existing recovery marker). Every
ancestor component of a custom marker directory **must** remain owned by
`root` and non-writable by `qeminga` or any other untrusted user for the
entire lifetime of the path (for example, directly under root-owned `0755`
`/run`, as in `/run/custom-qeminga` below — never under `/tmp`, `/var/tmp`, or
a service-writable directory):

```ini
[Service]
ExecStartPre=
ExecStartPre=+/usr/bin/mkdir -p /run/custom-qeminga
ExecStartPre=+/usr/bin/chown qeminga:qeminga /run/custom-qeminga
ExecStartPre=+/usr/bin/chmod 0700 /run/custom-qeminga
ReadWritePaths=
ReadWritePaths=-/run/custom-qeminga
```

### Supported systemd baseline

All directives in `packaging/systemd/qeminga.service` are supported on
**systemd 245 or newer** (matching the existing `ProtectClock=yes`
baseline; `ProtectHome=read-only` requires 227+, `ReadWritePaths=`,
`ReadOnlyPaths=`, and `SystemCallFilter=~@mount` require 231+,
`ProtectSystem=strict` and `ProtectKernelTunables=yes` require 232+,
`BindReadOnlyPaths=` requires 233+, `RestrictSUIDSGID=` and
`ProtectHostname=` require 242+, and `ProtectKernelLogs=` requires
244+). This covers Ubuntu 20.04+, Debian 11+, and RHEL 9+ (CI verifies
Ubuntu 24.04 with systemd 255 on both `x86_64` and `aarch64`).

## Changing the freeze cap

`fsfreeze_max_timeout_secs` in `config.toml` and `TimeoutStopSec=` in
the unit are coupled (§8.4): keep `TimeoutStopSec` greater than the cap
plus a thaw-drain margin (30 s), otherwise a stop requested during a
freeze falls back to the forced-stop recovery path (§5.7) instead of
waiting for the thaw. `tests/packaging.rs` checks the shipped pair.
`fsfreeze_operation_timeout_secs` (the freeze walk's own deadline, §4.4)
is validated to be at most the cap, so it never needs a margin of its
own.

## Data-protection profile and CVM deployment guidance

Confidential VM (CVM) deployments and guests whose only job for the host
is snapshot coordination install `config-data-protection.toml` as
`/etc/qeminga/config.toml`. General-VM deployments that need lifecycle
management and host-driven inventory install `config.toml` instead. The
two packaged profiles differ in commands, retained privileges, and
post-compromise authority (design §5.9):

- **CVM / data-protection profile (`config-data-protection.toml`, CVM installation default):**
  Accepts only `guest-fsfreeze-*`, `guest-ping`, `guest-sync*`, and
  `guest-info`; explicitly disables `guest-shutdown`, `guest-get-osinfo`,
  `guest-network-get-interfaces`, `guest-get-fsinfo`, `guest-fstrim`, and
  `guest-suspend-ram`. After dropping to `qeminga` (UID/GID 600),
  `CapEff`, `CapPrm`, and `CapBnd` retain **only** `CAP_SYS_ADMIN` and
  `CAP_DAC_READ_SEARCH`, with `CapInh` and `CapAmb` empty (`CAP_SYS_BOOT`
  absent from all five sets). The seccomp filter omits `reboot`, `sync`,
  `uname`, `statfs`, `fstatfs`, the netlink syscalls, `socket`, the
  inventory `sendto` rule, and `FITRIM` (see *Sockets and IPC* below for
  the narrowed runtime signal rules).
- **General-VM / lifecycle profile (`config.toml`, TOML schema default):**
  Adds `guest-shutdown`, `guest-fstrim`, `guest-get-osinfo`,
  `guest-network-get-interfaces`, and `guest-get-fsinfo`. `CapEff`,
  `CapPrm`, and `CapBnd` retain `CAP_SYS_ADMIN`, `CAP_SYS_BOOT`, and
  `CAP_DAC_READ_SEARCH`, with `CapInh` and `CapAmb` empty; seccomp keeps
  `reboot`, `sync`, `uname`, `statfs`, `fstatfs`, `FITRIM`, `socket`
  restricted to `(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)`,
  the inventory `sendto` rule (`flags == 0`, `addrlen == 12`), and the
  netlink syscalls.
- **Custom CVM configs must disable features explicitly:** The CVM
  installation default comes from installing `config-data-protection.toml`.
  An empty or partial `config.toml` is valid even under
  `hardening = "enforced"`, and omitted `information`, `fstrim`, and
  `shutdown` keys default to `true` in the TOML schema (matching
  `config.toml`). Stripping those keys from a custom CVM config therefore
  exposes inventory and trim and retains `CAP_SYS_BOOT`/`reboot(2)`; set
  `shutdown = false`, `information = false`, and `fstrim = false`
  explicitly.

In both profiles the daemon derives its authority from `config.toml`
before accepting any host request; nothing the host sends re-enables a
disabled feature, `guest-info` lists disabled commands as disabled, and
freeze/thaw error replies emit only `GenericError`, a fixed reason,
recovery state, and counts (never guest mount names, alternate paths,
device numbers, or marker paths).

- **Authority of a compromised parser process (both profiles):**
  - *Broad file reads + host channel:* Retaining `CAP_DAC_READ_SEARCH`
    and `openat`/`read`/`getdents64` in the same process that writes to
    the virtio host channel means seccomp is **not** a confidentiality
    boundary for guest-readable or root-owned file contents after a
    parser-process compromise (design §5.9, OQ-10).
  - *Ordinary file writes:* Seccomp keeps `openat`, `write`, `writev`,
    `pwrite64`, `fsync`, and `unlinkat` (for the channel, stderr, marker,
    and optional `/sys/power/state`). Ordinary writes are limited by
    guest Unix permissions (UID/GID 600, with `CAP_DAC_OVERRIDE` dropped)
    and the shipped unit's read-only mount namespace (see *Filesystem
    write confinement* above: `ProtectSystem=strict`,
    `ProtectHome=read-only`, `PrivateTmp=no`,
    `ReadWritePaths=-/run/qeminga`, `ProtectKernelTunables=yes`,
    `BindReadOnlyPaths=/sys /dev`, `ReadOnlyPaths=/run`,
    `SystemCallFilter=~@mount`, and `UMask=0077`), which confines
    ordinary file writes on mounts present at service start to
    `/run/qeminga` (plus `/sys/power/state` only with guest-installed
    `tmpfiles.d/qeminga-suspend.conf` and a guest suspend drop-in) while
    leaving the residual writable objects inventoried above (character
    devices under `/dev`, `/proc/self/*`, and filesystems mounted in the
    guest's system-manager mount namespace after service start).
  - *Sockets and IPC:* Under an installed, enforcing seccomp filter
    (required by `hardening = "enforced"`; the filter may be absent or
    logging-only under the development-only opt-out
    `hardening = "unenforced-development-only"`),
    IP socket creation (`AF_INET`/`AF_INET6`), `connect`/`accept`/`listen`,
    and `execve`/`execveat` are denied in every profile. With
    `information = false`, `socket`, `bind`, `sendmsg`, `recvmsg`,
    `setsockopt`, `getsockname`, and peer-addressed `sendto` are absent
    from the filter; with `information = true`, `socket` is restricted to
    `(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)` alongside an
    additional inventory `sendto` rule restricted to `flags == 0` and
    `addrlen == 12` (`sizeof(struct sockaddr_nl)`). In every profile,
    `socketpair` is restricted to
    `(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)`,
    `recvfrom` is restricted to peerless calls (`src_addr == NULL`,
    `addrlen == NULL`), and `sendto` keeps the peerless form
    (`dest_addr == NULL`, `addrlen == 0`) for the Tokio/mio runtime
    signal driver; seccomp-BPF cannot dereference pointers or inspect
    already-open descriptors such as the signal socketpair or inherited
    journald `stderr` (design §§5.5, 5.9).
- **Inventory and trim stay explicit guest choices.** Turning off
  `information = false` alone does not disable `guest-fstrim`:
  `guest-fstrim` replies independently list eligible mount paths even
  when `information = false`, so keep `[features] fstrim = false` in
  CVMs unless the guest explicitly opts into block discard (trim
  open-failure errors still keep alternate aliases and device numbers in
  guest-local logs only). If a deployment opts into
  `[features] information = true`, `guest-get-fsinfo` lists only mounts
  visible in the mount tree with valid UTF-8 mount points (preferring
  visible UTF-8 bind aliases, omitting non-representable mounts so each
  advertised path round-trips byte-exact to its row without lossy
  `U+FFFD` collisions while full-guest freeze stays byte-exact for
  still-reachable raw non-UTF-8 directory paths, opening targets with
  metadata-only `O_PATH`, verifying both device and mount ID via
  `statx(STATX_MNT_ID)` with `/proc/self/fdinfo/<fd>` fallback on Linux
  5.4–5.7 before `fstatfs(2)`, discarding sizes if the open
  `/proc/self/mountinfo` descriptor reports a mount-namespace change via
  `ppoll(POLLPRI)`, and erroring on a non-empty mount table with no
  recognizable `/` root) and emits an opaque
  per-superblock identifier (`fs-1`, `fs-2`, …) in `name` shared by all
  visible valid-UTF-8 aliases of a superblock and never publishes raw
  mount sources (such as FUSE or network URLs) or device numbers. Each
  `fs-N` identifier is valid only within that single reply (rebuilt in
  mount-table order on each call, so removing an earlier mount can
  assign an old number to a different filesystem); controllers should
  group aliases within one reply and use provisioned mount paths across
  requests. Enabling `information` also enables `guest-get-osinfo` and
  `guest-network-get-interfaces`.
- **Freeze-count confidentiality and guest target policy (#63).**
  Controller provisioning (telling the host backup controller which mount
  points to request) is separate from policy enforced by the guest agent.
  With `[agent] freeze_allowed_mountpoints` unset (the default in
  `config-data-protection.toml`), the guest authorizes the host to learn
  distinct-superblock coverage counts for host-named mount paths and
  aggregate whole-guest counts even with `information = false` and
  `fstrim = false` (zero counts remain ambiguous and ordinary file
  contents are never disclosed; design §4.5). A CVM deployment promising
  to conceal unprovisioned mount-point eligibility from an untrusted host
  must set `[agent] freeze_allowed_mountpoints = [...]` in
  `/etc/qeminga/config.toml` (canonical absolute mount paths, alongside
  `information = false` and `fstrim = false`): unauthorized names and
  aliases are discarded before mount-table lookup and settle directly to
  the guest-independent count `0` without reading `/proc/self/mountinfo`
  or touching the recovery marker, whole-guest and omitted-list requests
  are narrowed to the allowlist, recovery thaws from `Thawed` (only when
  marker absence is confirmed via `ENOENT`) restrict discovery strictly to
  currently visible allowlisted devices and never remove a marker, and
  crash recovery from a present or indeterminate `/run/qeminga/frozen`
  marker drains every eligible v1 superblock before removing the marker
  (so narrowing `freeze_allowed_mountpoints` across a crash cannot strand
  an earlier freeze) while reporting only currently visible allowlisted
  counts on the wire and collapsing failures attributable solely to
  excluded or unverified targets to one fixed host-safe reason — when
  `/proc/self/mountinfo` cannot be read on a restricted recovery retry,
  retained descriptors are still drained for guest recovery while their
  wire credit and specific target error classes remain suppressed until
  current visibility can be verified (when `[agent] freeze_ownership_dir`
  is also enabled under OQ-11 / #69 below, cooperative recovery drains and
  releases only `qeminga`-owned superblocks — including any outside the
  narrowed allowlist, with wire count `0` and `RecoveryIncomplete` error
  collapsing — while leaving foreign-owned allowlisted superblocks frozen,
  and idle cooperative thaws still require confirmed `ENOENT` marker
  absence before fast-pathing `0`).
- **Mount-binding assumption (v1).** Whether required mount paths come
  from provisioning (`config-data-protection.toml`) or from
  `guest-get-fsinfo`, the guest must keep each required path bound to
  its intended volume from provisioning or discovery through the freeze,
  or invalidate the cycle when the binding changes (design §§4.5, 5.9).
  Replacing a required path with another eligible filesystem before
  `guest-fsfreeze-freeze-list` still yields a matching freeze and thaw
  count because reply-local `fs-N` identifiers cannot detect remounts.
- **Single-freezer assumption (default) and cooperative multi-freezer mode (OQ-11, #69).**
  By default (`[agent] freeze_ownership_dir` unset), design §4.2 assumes
  qeminga is the sole freezer in the guest: a host-requested
  `guest-fsfreeze-thaw` while qeminga is already `Thawed` runs a
  discovery drain over all eligible filesystems even with no qeminga
  operation or marker, and `guest-fsfreeze-freeze` retains an
  already-frozen (`EBUSY`) superblock for later thaw. Do **not** deploy
  the default sole-freezer mode in a CVM that relies on an independent
  in-guest freezer (such as an in-guest backup or integrity check
  holding `FIFREEZE` outside qeminga), because the host could release
  that freeze early.

  To support a second cooperating in-guest freezer safely across normal
  thaw, host-requested `Thawed` drain, automatic watchdog thaw,
  rollback, crash/restart with a recovery marker, and ambiguous
  ownership, configure `[agent] freeze_ownership_dir` (for example
  `"/run/qeminga-freeze-owners"`) and satisfy **all** of these
  deployment preconditions:

  1. **Single shared guest-local `tmpfs` directory (`03770 root:<freezer-group>`):**
     Provision the directory once for the guest boot on a guest-local
     runtime `tmpfs` under trusted root-owned parent directories (such
     as `/run/qeminga-freeze-owners`, distinct from `state_path` and its
     parent directory `/run/qeminga`). All participating services must
     share the **same** directory object for the lifetime of their
     freezes and recovery: preserve it across individual service
     restarts (never recreate or wipe it while any owner may hold a
     claim, and never start a participating service in a separate mount
     namespace with a private copy), and drain all outstanding claims
     before relocating the directory or switching ownership modes.
     Per-descriptor metadata checks cannot detect two distinct compliant
     directories after a restart. Startup checks the pinned directory
     descriptor before opening the channel: it refuses any freezable
     filesystem and, under `hardening = "enforced"`, verifies via
     `fstatfs(2)` that the directory resides on guest-local `tmpfs`
     (rejecting network filesystems and host-provided shares outside the
     freeze plan) and refuses any directory that is not owned by `root`,
     belongs to group `0`, lacks the sticky bit (`01000`) or setgid bit
     (`02000`), lacks group `rwx` (`0070`), or grants any permission to
     other users (`0007`).
  2. **Distinct OS UIDs, `SupplementaryGroups=`, `UMask=0027`, and `ReadWritePaths=`:** Run
     each cooperating freezer under its own OS UID belonging to the
     dedicated non-root `<freezer-group>` so the sticky bit prevents one
     freezer from unlinking or renaming another owner's claim file, the
     setgid bit gives created claim files `<freezer-group>` ownership,
     and qeminga can verify `st_uid == geteuid()` on `"qeminga"` claims.
     Add a systemd drop-in for `qeminga.service` granting
     `SupplementaryGroups=<freezer-group>`, `UMask=0027` (overriding the
     shipped unit's `UMask=0077` so `0640` claim files remain readable by
     `<freezer-group>` while `0600` `/run/qeminga/frozen` stays private to
     `qeminga`), and an appended
     `ReadWritePaths=-/run/qeminga-freeze-owners` (without resetting
     `ReadWritePaths=`, punching the ownership directory alongside
     `-/run/qeminga` under the shipped unit's `ProtectSystem=strict` and
     `ReadOnlyPaths=/run`). During privilege drop (`setgroups`),
     qeminga preserves only that single authorized non-root group when
     it is present in inherited supplementary groups, dropping every
     other inherited group.
  3. **All protected in-guest freezers participate in the shared claim
     protocol:** Participation in this protocol is an explicit
     prerequisite for protecting a guest-owned freeze, including across
     crashes and restarts. Before `FIFREEZE` on `(major, minor)`,
     atomically create `<major>-<minor>` with
     `O_CREAT | O_EXCL | O_NOFOLLOW`, write `<owner-tag>\n` (`qeminga\n`
     for qeminga; ASCII `[A-Za-z0-9._-]`, distinct per component), and
     `fsync` both the file and the directory. Once acquired, the claim
     must remain exclusively held by that owner until its thaw drain
     reaches a terminal `FITHAW` (`EINVAL`/`EOPNOTSUPP`) and releases
     `<major>-<minor>` (followed by `fsync` of the directory);
     concurrent live handoff during an active drain is not part of the
     protocol. With `freeze_ownership_dir` enabled, qeminga skips
     foreign-claimed targets without opening or freezing them, verifies
     current `qeminga` ownership once immediately before starting each
     target's `FITHAW` drain (tracked thaw, rollback, abort, and
     recovery; not between repeated `FITHAW` calls inside a single
     drain), restricts recovery drains to `qeminga`-owned superblocks
     (falling back to per-target direct claim verification on mounted
     filesystems if directory enumeration fails), and fails closed
     (draining reachable `qeminga` targets while establishing and
     retaining `/run/qeminga/frozen` — or reporting `marker unavailable`
     if the marker cannot be created while startup still re-checks the
     ownership directory on restart — alongside uncertain handles and
     `Frozen` state without touching foreign freezes) whenever any entry
     is ambiguous or directory scanning fails. If an unannounced non-cooperating
     freezer holds `FIFREEZE`, qeminga releases its fresh claim on
     `EBUSY` only when the freeze worker survives to observe that
     error; a crash between persisting the claim and handling `EBUSY`
     leaves a `qeminga` claim that restart recovery
     will drain, so operators running an integrity checker outside the
     shared claim protocol cannot rely on cooperative mode to protect
     its freezes. Omitting `freeze_ownership_dir` keeps the default
     sole-freezer restriction above.

## Hardening profile and a failed upgrade or configuration

The shipped configuration says `hardening = "enforced"` (design §8.1):
the daemon refuses to serve the host, exit status 78 and one line in the
journal (`refusing to serve the host`), unless it was started as root,
the seccomp filter is compiled in, enabled and installed in its enforcing
mode, and no test-kernel substitution was requested. `Restart=always`
restarts it a second later, refusing each time, until systemd's start
rate limit ends the loop (five starts in ten seconds by default): the
unit is then `failed`, and a `systemctl restart` inside that window is
rejected until `systemctl reset-failed qeminga`. It never falls back to
serving without the sandbox. Typical causes after an upgrade: a binary
built without `--features seccomp`, a binary with `debug_assertions`
enabled built with `--features seccomp-log` or `--all-features` (which
puts the filter into logging mode when `debug_assertions = true`; Cargo's
standard `release` profile sets `debug_assertions = false`, where the
filter always enforces and `test-fakes` fails to compile), a stray
`QEMINGA_TEST_FAKE_KERNEL` in the unit's environment, or a kernel or
container runtime that refuses the filter (the line names the installer's
error).
`[features] seccomp = false` left in the configuration is refused one
step earlier, as a configuration error naming `features.seccomp`: the
same exit status 78, without the `refusing to serve` line.

The refusal happens before the recovery marker is touched (the drop's
and the installer's outcomes are checked later, but still before the
runtime, and are reported to the journal even when a marker put logging
into recovery mode). If the
previous instance was frozen when it died, `/run/qeminga/frozen` is still
there and the filesystems may still be frozen: fix the cause, then
`systemctl reset-failed qeminga` and `systemctl restart qeminga`; the
start that can provide the profile
enters recovery mode from the marker and thaws (§4.4). Do not remove the
marker by hand, and do not set `hardening = "unenforced-development-only"`
to get past the refusal on a production host: that value is for a
development machine only, where it allows an unprivileged start, a
missing or logging filter and the faked kernel, with warnings.

## Recovery marker

`/run/qeminga/frozen` is created before the first `FIFREEZE` and removed
after a complete thaw (§4.4). The daemon creates and removes it after
dropping to the `qeminga` account, so `/run/qeminga` must belong to that
account: `tmpfiles.d/qeminga.conf` creates it that way at boot, and the
unit's privileged `ExecStartPre` lines (`mkdir -p`, `chown`, `chmod 0700`)
re-provision it before every start. The unit deliberately does not use
`RuntimeDirectory=`: with no `User=`, systemd re-applies root ownership to
such a directory before every `ExecStart`, which undid the hand-over and
left the dropped daemon unable to create or remove its marker. Nothing
removes the directory on `systemctl stop`, so a marker left by a forced
stop makes the next start enter recovery mode; a reboot clears `/run` and
the kernel freeze state together. Never put `state_path` on a filesystem
the freeze plan could freeze; startup refuses such a path.
