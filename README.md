# qeminga

A minimum secure subset of the QEMU guest agent (`qemu-ga`), written in safe
Rust. qeminga exposes only the guest-agent commands needed for VM lifecycle
management (ping, info, shutdown, filesystem freeze/thaw/trim, read-only
OS, filesystem, and network information) and refuses every command that
would let the hypervisor execute code, touch files, or change credentials in
the guest.

**Status:** pre-alpha. The design is complete; implementation is tracked as
a task list for coding agents.

- [`docs/design.md`](docs/design.md) — the design document (normative).
- [`docs/tasks.md`](docs/tasks.md) — the implementation task list, with
  clarifications, open questions, and an acceptance-criteria matrix.
- [`AGENTS.md`](AGENTS.md) — contributor and coding-agent conventions.

## Building and testing

The toolchain is pinned by `rust-toolchain.toml`; `rustup` installs it on
first use.

```sh
cargo build --release              # panic=abort, LTO
cargo test --all-features          # unit + integration tests
cargo clippy --all-targets --all-features -- -D warnings
scripts/check-unsafe.sh            # no `unsafe` outside src/kernel/
```

Cargo features (compile-time half of the two-level switches in the design):

| Feature | Effect |
|---|---|
| `seccomp` | Build the seccomp-BPF filter (`seccompiler`). |
| `suspend_ram` | Build the opt-in `guest-suspend-ram` handler. |

Tests that need root or `CAP_SYS_ADMIN` are `#[ignore]`d and named
`privileged_*`; see `AGENTS.md`.

## Platform

Linux 5.4+ on `x86_64` and `aarch64`, running as a systemd-managed service
in the initial user namespace. See design §8.5.

## License

AGPL-3.0. See [`LICENSE`](LICENSE).
