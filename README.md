# qeminga

[![CI](https://github.com/vicaya/qeminga/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vicaya/qeminga/actions/workflows/ci.yml?query=branch%3Amain)
[![Tests](https://github.com/vicaya/qeminga/raw/badges/main/tests.svg)](https://github.com/vicaya/qeminga/actions/workflows/ci.yml?query=branch%3Amain)
[![Coverage](https://github.com/vicaya/qeminga/raw/badges/main/coverage.svg)](https://github.com/vicaya/qeminga/actions/workflows/ci.yml?query=branch%3Amain)

A minimum secure subset of the QEMU guest agent (`qemu-ga`), written in safe
Rust. qeminga exposes only the guest-agent commands needed for VM lifecycle
management (ping, info, shutdown, filesystem freeze/thaw/trim, read-only
OS, filesystem, and network information) and refuses every command that
would let the hypervisor execute code, touch files, or change credentials in
the guest.

**Status:** 0.1.0. Every command in the design is implemented and tested
(unit, property, fuzz, end-to-end over a pty, and privileged tests on
loop-mounted filesystems, natively on x86-64 and aarch64) and exercised
against real libvirt in CI under real KVM on GitHub-hosted x86-64
(`ubuntu-24.04`) and under QEMU's TCG emulator on both architectures.
The remaining release-qualification items (`libvirt-release-v1` suite
and evidence verifier; native aarch64 KVM is tracked separately as
optional coverage) are in [`docs/tasks.md`](docs/tasks.md) §7.

## Commands

| Allowed | Refused (`CommandNotFound`) |
|---|---|
| `guest-ping`, `guest-info`, `guest-sync`, `guest-sync-delimited` | `guest-exec*`, `guest-file-*`, `guest-set-user-password`, `guest-ssh-*` |
| `guest-get-osinfo`, `guest-network-get-interfaces`, `guest-get-fsinfo` | `guest-set-time`, `guest-set-vcpus`, `guest-set-memory-blocks` |
| `guest-fsfreeze-status`, `guest-fsfreeze-freeze`, `guest-fsfreeze-freeze-list`, `guest-fsfreeze-thaw`, `guest-fstrim` | `guest-suspend-disk`, `guest-suspend-hybrid` |
| `guest-shutdown`, `guest-suspend-ram` (opt-in) | every other read-only upstream command (`guest-get-users`, `guest-get-time`, `guest-network-get-route`, ...) |

## Running

```sh
qeminga --config /etc/qeminga/config.toml   # the daemon (see packaging/README.md)
qeminga --version
```

The daemon starts as root to open the virtio-serial port, drops to the
`qeminga` account (UID/GID 600), derives its retained privileges from
`config.toml`, installs a per-architecture seccomp-BPF filter (with the
`seccomp` feature), and serves newline-delimited QGA JSON. The two packaged
profiles differ in host command surface and retained authority (see
[`docs/design.md`](docs/design.md) §5.9):

| Profile | Config file | Host commands accepted | Privileges retained after drop |
|---|---|---|---|
| **CVM / data-protection** (CVM installation default) | [`packaging/config-data-protection.toml`](packaging/config-data-protection.toml) | Snapshot coordination and controls only (`guest-fsfreeze-*`, `guest-ping`, `guest-sync*`, `guest-info`); `shutdown`, `information`, `fstrim`, and `suspend_ram` disabled | `CapEff`/`CapPrm`/`CapBnd` hold `CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH`, `CapInh`/`CapAmb` empty (`CAP_SYS_BOOT` absent from all sets); seccomp omits `reboot`/`sync`, `uname`/`statfs`/`fstatfs`, netlink syscalls, `socket`, the inventory `sendto` rule, and `FITRIM`; keeps `socketpair(AF_UNIX, SOCK_STREAM \| SOCK_NONBLOCK \| SOCK_CLOEXEC, 0)`, peerless `recvfrom` (`src_addr == NULL`, `addrlen == NULL`), and peerless `sendto` (`dest_addr == NULL`, `addrlen == 0`) for runtime signal delivery |
| **General-VM / lifecycle** (TOML schema default) | [`packaging/config.toml`](packaging/config.toml) | Adds `guest-shutdown`, `guest-fstrim`, `guest-get-osinfo`, `guest-network-get-interfaces`, and `guest-get-fsinfo` (`guest-suspend-ram` remains opt-in) | `CapEff`/`CapPrm`/`CapBnd` hold `CAP_SYS_ADMIN`, `CAP_SYS_BOOT`, and `CAP_DAC_READ_SEARCH`, `CapInh`/`CapAmb` empty; seccomp adds `reboot`/`sync`, `uname`/`statfs`/`fstatfs`, `socket(AF_NETLINK, SOCK_RAW \| SOCK_CLOEXEC, NETLINK_ROUTE)`, an inventory `sendto` rule (`flags == 0`, `addrlen == 12`), netlink syscalls, and `FITRIM` |

Installing `packaging/config-data-protection.toml` is what establishes the
CVM default; an empty or partial `config.toml` defaults omitted
`information`, `fstrim`, and `shutdown` keys to `true` even under
`hardening = "enforced"`, so custom CVM configs must set them to `false`
explicitly. If a defect compromised the parser process after startup, the
process would still hold `CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH` (plus
`CAP_SYS_BOOT` in the general-VM profile), `openat`/`read`/`getdents64`,
and the writable host virtio channel — so seccomp is **not** a
confidentiality boundary for guest file contents after parser compromise
(see `docs/design.md` §5.9 and `docs/tasks.md` OQ-10). Ordinary file opens,
writes, and unlinks (`openat`/`write`/`pwrite64`/`fsync`/`unlinkat`) remain
in the filter and are bounded by guest Unix permissions (UID/GID 600, with
`CAP_DAC_OVERRIDE` dropped) and the shipped systemd unit confinement
(`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=no`,
`ReadWritePaths=-/run/qeminga`, `ProtectKernelTunables=yes`,
`BindReadOnlyPaths=/sys /dev`, `ReadOnlyPaths=/run`,
`SystemCallFilter=~@mount`, and `UMask=0077`), confining ordinary file writes
on mounts present at service start to `/run/qeminga` (with residual writable
objects inventoried in `packaging/README.md`). Under an installed, enforcing
seccomp filter (required by `hardening = "enforced"`; the filter may be absent
or logging-only under the development-only opt-out
`hardening = "unenforced-development-only"`),
IP socket creation (`AF_INET`/`AF_INET6`), `connect`/`accept`/`listen`, and
`execve`/`execveat` are denied in every profile. `socket` is absent when
`information = false` and restricted to
`(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)` when
`information = true`. When `information = true`, an additional `sendto`
rule permits `flags == 0` and `addrlen == 12` (`sizeof(struct sockaddr_nl)`)
for `getifaddrs(3)` netlink requests (seccomp-BPF cannot inspect the file
descriptor type or pointed-to address); when `information = false`, that
rule is absent. In every profile, `socketpair`
(`AF_UNIX`, `SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC`, `0`), peerless
`recvfrom` (`src_addr == NULL`, `addrlen == NULL`), and peerless `sendto`
(`dest_addr == NULL`, `addrlen == 0`) remain allowed for runtime signal
delivery (see `docs/design.md` §§5.5, 5.9).

Filesystem freezes are bounded by a watchdog (30 s idle, 300 s hard cap by
default) and survive an agent crash through a recovery marker on tmpfs.
Every command is audited as one JSON line on stderr; during a freeze the
audit records are held in a 64 KiB ring so the agent can never block on a
frozen journal. A marker left by a crashed instance arms that watchdog at
startup whether or not the host's port can be opened yet. `guest-shutdown`
is a hard shutdown, `sync(2)` followed by `reboot(2)`: no service is
stopped and nothing is unmounted (`docs/tasks.md` OQ-1).

Installation files (systemd unit, udev rule, sysusers, tmpfiles,
configurations), the migration steps from `qemu-guest-agent`, and the
confidential VM (CVM) deployment guidance — using the data-protection
profile (`packaging/config-data-protection.toml`) as the CVM default and
noting the v1 single-freezer assumption — are in
[`packaging/README.md`](packaging/README.md). The libvirt
interoperability checks (the TCG smoke lane in CI, the GitHub-hosted
`x86_64` KVM smoke lane, the self-hosted `x86_64` / `arm64` KVM lane
and community runner setup script `scripts/setup-kvm-runner.sh`, and the
manual KVM recipe) are described in [`docs/testing.md`](docs/testing.md).

- [`docs/design.md`](docs/design.md) — the design document (normative).
- [`docs/tasks.md`](docs/tasks.md) — the implementation task list, with
  clarifications, open questions, and an acceptance-criteria matrix.
- [`AGENTS.md`](AGENTS.md) — contributor and coding-agent conventions.

## Building and testing

The toolchain is pinned by `rust-toolchain.toml`; `rustup` installs it on
first use.

```sh
cargo build --release --features seccomp   # panic=abort, LTO; the release configuration
cargo test --all-features                  # unit, property, integration and E2E tests
cargo clippy --all-targets --all-features -- -D warnings
scripts/check-unsafe.sh                    # no `unsafe` outside src/kernel/
scripts/check-shell.sh                     # shellcheck over every shell script
```

Cargo features (compile-time half of the two-level switches in the design):

| Feature | Effect |
|---|---|
| `seccomp` | Build the seccomp-BPF filter (`seccompiler`). Release builds use it. |
| `seccomp-log` | Same profile, logging instead of killing **in debug builds only** (`seccomp::log_mode`); release builds always enforce (`kill_process`), while debug builds with `seccomp-log` fail the enforced-hardening startup check. |
| `suspend_ram` | Build the opt-in `guest-suspend-ram` handler. |
| `test-fakes` | Let the binary fake the kernel shim for the E2E suite (development hardening only). An independent compile-time guard (`compile_error!` in `src/lib.rs`) rejects release builds carrying `test-fakes`, including `cargo build --release --all-features`. |

Tests that need root or `CAP_SYS_ADMIN` are `#[ignore]`d and named
`privileged_*`; see `AGENTS.md`.

Coverage is measured by `cargo llvm-cov` over every suite that runs
unprivileged (unit, property, integration and end-to-end) and CI fails
below **85 % of production lines**, meaning the instrumented lines of
`src/` outside the inline `#[cfg(test)] mod tests` blocks and outside the
scripted kernel double (`src/kernel/fake.rs`) that the end-to-end suite
runs against: `scripts/ci/coverage-gate.py` removes both from the report
first, because test code is covered by construction and would inflate
the number. The run summary shows both figures. The daemon is measured with
the seccomp *logging* build, since the LLVM profile runtime calls
`prctl(2)` with an argument the production filter refuses; the enforced
filter is exercised by the privileged CI job. The tests and coverage
badges above are generated on every push to `main` and stored on the
`badges` branch, so they need no external service (the repository is
private); the job that publishes them checks that GitHub serves them as
images from the rendered README.

## Platform

Linux 5.4+ on `x86_64` and `aarch64`, running as a systemd-managed service
in the initial user namespace. See design §8.5.

## License

AGPL-3.0. See [`LICENSE`](LICENSE).
