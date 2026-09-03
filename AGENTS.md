# Working on qeminga

qeminga is a minimum secure subset of the QEMU guest agent, written in safe
Rust. This file is the contract for coding agents (and humans) contributing
to the repository.

- **Specification:** [`docs/design.md`](docs/design.md) is normative. Do not
  change behaviour it specifies without a design change.
- **Work queue:** [`docs/tasks.md`](docs/tasks.md). Pick a task there, claim
  it, implement it test-first, mark it done.
- **Ambiguities:** resolved ones are listed in `docs/tasks.md` §3; unresolved
  ones in §4. Add to §4 instead of guessing.

## Workflow (TDD, always)

1. Branch from `main`: `task/<id>-<slug>` (for example `task/t1.2-frame-decoder`).
2. Write the failing tests named in the task first. Run `cargo test` and
   confirm they fail *for the expected reason* (a missing function is not
   the expected reason for a behaviour test — add the stub, then see the
   assertion fail).
3. Write the smallest production change that makes them pass.
4. Refactor with the tests green. Commit at every green step.
5. Run the full check suite below before pushing. All of it must pass.
6. Update the task's **Status** in `docs/tasks.md` in the same PR.

Commit subjects reference the task and acceptance criteria:
`T1.2: discard-until-newline on oversized frames (AC4)`.

## Checks

These are exactly what CI runs. Run them locally before every push:

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo test --locked                       # default features too
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
scripts/check-unsafe.sh
cargo deny check                          # cargo install cargo-deny --locked
cargo audit --deny warnings              # cargo install cargo-audit --locked
cargo check --target aarch64-unknown-linux-gnu --all-targets --all-features --locked
cargo build --release --locked --all-features
```

Privileged tests (root / `CAP_SYS_ADMIN`) are `#[ignore]`d, named
`privileged_*`, and run with:

```sh
sudo -E cargo test --all-features -- --ignored privileged_
```

## Code rules

- **No `unsafe` outside `src/kernel/`.** The crate root has
  `#![deny(unsafe_code)]`; every other `.rs` file (modules, tests, benches,
  examples, build scripts, fuzz targets) starts with
  `#![forbid(unsafe_code)]`; `src/kernel/` may `#![allow(unsafe_code)]` and
  every `unsafe` block carries a `// SAFETY:` comment.
  `scripts/check-unsafe.sh` enforces this.
- **No `unwrap`/`expect`/`panic!`/`todo!` in production code.** Return
  `Result` with `thiserror` types. Tests may unwrap freely (`clippy.toml`).
- **OS access goes through traits** (`KernelOps`, `MountSource`,
  `OsInfoSource`, `InterfaceSource`, …) with fakes for tests. Production
  implementations are thin.
- **Static allowlist.** Commands are dispatched by a `match` on the method
  string (design §5.1). Never introduce a lookup table, registry, or
  plugin mechanism for commands.
- **Bounded input.** Every parser has an explicit size bound and a
  `proptest` property test; decoders are fuzz targets.
- **Async discipline.** Blocking syscalls (`FIFREEZE`, `FITHAW`, `FITRIM`)
  run under `tokio::task::spawn_blocking`; never hold a `std::sync::Mutex`
  across an `.await`; time-based tests use `start_paused = true`.
- **Audit everything.** Every received command produces exactly one audit
  record (design §9) via `tracing`; field values are structured, never
  formatted into the message.
- **Public items are documented** (`missing_docs` is on).
- **Dependencies:** adding one needs a sentence in the PR explaining why and
  a green `cargo deny check`. `Cargo.lock` is committed; always build with
  `--locked` in CI.
- **Wire format** is QEMU guest-agent (QMP-style) JSON, one message per
  line, as described in `docs/tasks.md` C-1. Use the fixtures in
  `tests/fixtures/qga/` and add to them.

## Layout

```
src/lib.rs          crate root, #![deny(unsafe_code)], pub mod declarations
src/main.rs         thin binary: args → qeminga::run
src/<module>.rs     one module per design §6 entry (may become a directory)
src/handlers/       one file per command family
src/kernel/         the only place `unsafe` may appear
tests/              integration and end-to-end tests (`tests/e2e/` harness)
tests/fixtures/     mountinfo, os-release, config, and wire-format samples
scripts/            CI helpers (`check-unsafe.sh`, loop-device setup)
packaging/          systemd unit, udev rule, sysusers, example config
docs/               design.md (spec), tasks.md (work queue)
```

## Definition of done for a task

- Tests listed in the task exist, were red first, and are green.
- All checks above pass locally and in CI.
- `docs/tasks.md` status updated; new open questions recorded.
- No behaviour outside the task's scope changed.
