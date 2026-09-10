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
loop-mounted filesystems). Two items stay open, tracked in
[`docs/tasks.md`](docs/tasks.md) §7: the manual libvirt run log (AC16) and
arm64 execution in CI (AC15).

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
`qeminga` account keeping exactly `CAP_SYS_ADMIN`, `CAP_SYS_BOOT` and
`CAP_DAC_READ_SEARCH`, installs a per-architecture seccomp filter (with
the `seccomp` feature), and serves newline-delimited QGA JSON. Filesystem
freezes are bounded by a watchdog (30 s idle, 300 s hard cap by default)
and survive an agent crash through a recovery marker on tmpfs. Every
command is audited as one JSON line on stderr; during a freeze the audit
records are held in a 64 KiB ring so the agent can never block on a frozen
journal. A marker left by a crashed instance arms that watchdog at startup
whether or not the host's port can be opened yet. `guest-shutdown` is a
hard shutdown, `sync(2)` followed by `reboot(2)`: no service is stopped
and nothing is unmounted (`docs/tasks.md` OQ-1).

Installation files (systemd unit, udev rule, sysusers, example config) and
the migration steps from `qemu-guest-agent` are in
[`packaging/README.md`](packaging/README.md). Manual libvirt
interoperability checks are described in [`docs/testing.md`](docs/testing.md).

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
```

Cargo features (compile-time half of the two-level switches in the design):

| Feature | Effect |
|---|---|
| `seccomp` | Build the seccomp-BPF filter (`seccompiler`). Release builds use it. |
| `seccomp-log` | Same profile, logging instead of killing (compatibility runs only). |
| `suspend_ram` | Build the opt-in `guest-suspend-ram` handler. |
| `test-fakes` | Let the binary fake the kernel shim for the E2E suite (development hardening only). A compile error in release builds. |

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
