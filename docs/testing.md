# Testing qeminga

Automated coverage lives in CI (`AGENTS.md` §Checks, `.github/workflows/`):
unit and property tests, the unprivileged end-to-end suite over a pty,
the privileged job on loop-mounted filesystems, fuzzing, and the
packaging checks. The test and privileged jobs run natively on both
supported architectures (`ubuntu-24.04` for x86-64, `ubuntu-24.04-arm`
for aarch64; #51): the aarch64 privileged leg is the execution evidence
for the aarch64 seccomp profile (AC15), and each leg proves its
architecture (`uname -m`, `RUNNER_ARCH`, the rustc host triple) before
it builds anything. This page also covers interoperability with a real
libvirt/QEMU host (AC16, T5.4): an automated smoke lane under QEMU's TCG
accelerator on both architectures (below), and the manual recipe for a
KVM host.

## libvirt TCG smoke lane (CI)

`.github/workflows/libvirt-tcg.yml` (#53, part) runs AC16 against real
libvirt on GitHub-hosted runners, natively on each architecture
(`ubuntu-24.04`, `ubuntu-24.04-arm`). Hosted arm64 runners offer no
nested KVM and the lane does not rely on it on x86-64 either: the guest
is a `<domain type='qemu'>`, i.e. QEMU's TCG emulator, and the lane
proves it (`info kvm` answers `kvm support: disabled`, the QEMU command
line carries `-accel tcg`) before it counts any result.

1. **Candidate.** The `candidate` job builds
   `cargo build --release --locked --features seccomp` on the hosted
   runner of each architecture and uploads the binary, the packaging
   files and a `manifest.json` (source SHA, architecture, version,
   SHA-256 of the binary and of each packaging file, build run). The
   `smoke` job has no toolchain and never builds: it verifies the
   manifest against the commit, the architecture and the bytes
   (`scripts/ci/libvirt-tcg-smoke.sh verify-candidate`).
2. **Guest.** A disposable Ubuntu 24.04 server cloud image, pinned by
   release date and SHA-256 in the script (x86-64: `q35`, SeaBIOS,
   `qemu64`; aarch64: `virt`, UEFI from `qemu-efi-aarch64`,
   `cortex-a57`), with the `org.qemu.guest_agent.0` virtio-serial
   channel. A read-only payload disk carries the candidate;
   cloud-init runs `scripts/ci/libvirt-tcg-guest.sh`, which masks
   `qemu-guest-agent` and installs qeminga with the steps of
   `packaging/README.md`, then checks from inside the guest that the
   installed binary has the candidate's digest, the service is active as
   uid 600 with `NoNewPrivs: 1` and `Seccomp: 2`, the upstream agent is
   not active, and the port belongs to `qeminga` with mode 0600. Its
   verdict and the unit's journal reach the host on the serial console.
3. **AC16.** The host checks that `guest-info` reports the candidate's
   version, runs `scripts/e2e-libvirt.sh --no-shutdown` against the
   domain, then `virsh shutdown --mode agent` and requires `domstate` to
   become exactly `shut off`.
4. **Evidence.** `result.json` (schema 1, suite `libvirt-tcg-smoke-v1`):
   source SHA, architecture, candidate digest, `virtualization`
   (`hypervisor: qemu`, `accelerator: tcg`, `machine`), the pinned image,
   and `production_install`, `accelerator_tcg`, `libvirt_interop`,
   `agent_shutdown`, each `pass`, `fail` or `not_run`; the result is
   `pass` only when all four pass under TCG. The artifact also holds the
   AC16 transcript, the serial console, the QEMU log, the domain XML and
   the libvirt/QEMU versions.
5. **Cleanup.** Every resource is named
   `qeminga-e2e-<run id>-<attempt>-<arch>` and lives in
   `/var/lib/libvirt/images/<that name>/`. Before starting, the lane
   refuses a host that already has a `qeminga-e2e-*` domain or whose
   domains cannot be listed; afterwards (`if: always()`) it destroys and
   undefines only this run's domain and removes only its directory, and
   keeps the disks when the domain's state cannot be established.

This is smoke evidence on an emulated CPU, not KVM evidence and not a
release qualification. Not covered yet (the rest of #53): ext4/XFS data
disks, FSTRIM, a quiesced snapshot and its restore, the idle watchdog
through libvirt, the x86-64 KVM lane and release verification. Timeouts
are explicit: `QEMINGA_E2E_BOOT_TIMEOUT_SECS` (default 1800) bounds boot
plus install under emulation, `QEMINGA_E2E_SHUTDOWN_TIMEOUT_SECS`
(default 300) the agent shutdown, and the job has `timeout-minutes`.
To run it on an Ubuntu 24.04 machine of either architecture:

```sh
sudo apt-get install --no-install-recommends libvirt-daemon-system libvirt-clients \
  qemu-utils genisoimage dnsmasq-base qemu-system-x86   # aarch64: qemu-system-arm qemu-efi-aarch64
cargo build --release --locked --features seccomp
sha=$(git rev-parse HEAD)
scripts/ci/libvirt-tcg-smoke.sh manifest --out /tmp/candidate --binary target/release/qeminga \
  --arch "$(uname -m)" --source-sha "$sha" --version 0.1.0 --run-id 1 --run-attempt 1 --runner local
sudo scripts/ci/libvirt-tcg-smoke.sh run --arch "$(uname -m)" --candidate /tmp/candidate \
  --source-sha "$sha" --run-id 1 --run-attempt 1 --out /tmp/tcg-out
sudo scripts/ci/libvirt-tcg-smoke.sh cleanup --arch "$(uname -m)" --run-id 1 --run-attempt 1
```

## Manual run on a KVM host

### VM recipe

1. **Guest image.** Any Linux 5.4+ cloud image with systemd (Debian 12,
   Fedora 40, Ubuntu 24.04). ext4 or XFS root.
2. **Channel.** The domain XML needs the guest-agent virtio-serial port:

   ```xml
   <channel type='unix'>
     <source mode='bind'/>
     <target type='virtio' name='org.qemu.guest_agent.0'/>
   </channel>
   ```

   `virt-install --channel unix,mode=bind,target_type=virtio,name=org.qemu.guest_agent.0`
   adds it; most cloud-image workflows already have it because
   `qemu-guest-agent` is preinstalled.
3. **Install qeminga in the guest** (replacing `qemu-guest-agent`):

   ```sh
   cargo build --release --locked --features seccomp
   scp -r target/release/qeminga packaging/ guest:/tmp/
   # in the guest, as root:
   systemctl disable --now qemu-guest-agent.service
   install -m 0755 /tmp/qeminga /usr/bin/qeminga
   install -m 0644 /tmp/packaging/sysusers.d/qeminga.conf /usr/lib/sysusers.d/ && systemd-sysusers
   install -m 0644 /tmp/packaging/udev/99-qeminga.rules /etc/udev/rules.d/
   udevadm control --reload && udevadm trigger --subsystem-match=virtio-ports
   install -d /etc/qeminga && install -m 0644 /tmp/packaging/config.toml /etc/qeminga/
   install -m 0644 /tmp/packaging/systemd/qeminga.service /usr/lib/systemd/system/
   systemctl daemon-reload && systemctl enable --now qeminga.service
   journalctl -u qeminga -n 5     # expect the JSON "startup" and "channel_open" records
   ```

   See `packaging/README.md` for the same steps with explanations.

4. **Run the script from the host:**

   ```sh
   scripts/e2e-libvirt.sh [--connect qemu:///system] [--no-shutdown] <domain>
   ```

   It exits non-zero unless `virsh domfsfreeze`, `virsh domfsthaw`,
   `virsh domifaddr --source agent` and `virsh shutdown --mode agent`
   all succeed (plus `guest-info`, `guest-ping`, `guest-get-osinfo`,
   `domfsinfo`, and a check that `guest-exec` is refused). Attach its
   output to the pull request that changes protocol-facing code.

### What a passing run looks like

```
qeminga libvirt interoperability run: 2026-09-03T10:00:00Z domain=qeminga-test host=...
== guest-ping: virsh qemu-agent-command qeminga-test {"execute":"guest-ping"}
{"return":{}}
-- ok: guest-ping
...
== domfsfreeze: virsh domfsfreeze qeminga-test
Froze 1 filesystem(s)
-- ok: domfsfreeze
...
RESULT: PASS (AC16)
```

## Privileged tests locally

The enforced build, which is what CI gates on (AC15):

```sh
eval "$(sudo scripts/ci/mk-loop-fs.sh setup)"
sudo -E cargo test \
  --features seccomp,suspend_ram,test-fakes \
  --locked -- --ignored --test-threads=1 privileged_
sudo scripts/ci/mk-loop-fs.sh teardown
```

`--all-features` would build the `seccomp-log` filter, which only logs
unlisted syscalls instead of killing the process; that compatibility run
is a separate, clearly labelled step:

```sh
sudo -E cargo test --all-features --locked -- --ignored --test-threads=1 privileged_   # seccomp-log build: logs, does not enforce
```

The privileged E2E tests create a `qeminga` account requirement: when
run as root the daemon drops to it, so the account must exist
(`systemd-sysusers packaging/sysusers.d/qeminga.conf`).

## Fuzzing locally

```sh
cargo install cargo-fuzz
cargo +nightly fuzz run frame_decoder -- -max_total_time=60
```

## Coverage locally

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
scripts/ci/coverage.sh                 # same command as CI; reports in target/coverage/
cargo llvm-cov --features seccomp-log,suspend_ram,test-fakes --locked --html   # target/llvm-cov/html/index.html
```

`scripts/ci/coverage.sh` runs every unprivileged suite under
`cargo llvm-cov`, writes `lcov.info`, `coverage.json` and `coverage.log`,
then `scripts/ci/coverage-gate.py` removes each file's inline
`#[cfg(test)] mod tests` block and the test-support files named by
`COVERAGE_EXCLUDE` (default `src/kernel/fake.rs`, the scripted kernel
double the end-to-end suite runs against) from the LCOV
(`lcov-production.info`, a line and branch report without function
records) and applies the floor (`COVERAGE_FLOOR_LINES`, 85 %) to the
remaining **production lines**; `coverage-summary.md` and
`coverage-summary.json` carry both figures and name the excluded files.
The gate requires the inline test module to be the last item of its
file, which every module here follows.

The measurement uses the seccomp logging build (`COVERAGE_FEATURES`):
the LLVM profile runtime calls `prctl(2)` with an argument other than
`PR_SET_NAME`, which the production filter kills, so an enforced
instrumented daemon never writes its profile. The privileged tests are
`#[ignore]`d and therefore not counted; the kernel shim, the capability
drop and the seccomp installer are the files with the lowest figures for
that reason. CI publishes the numbers as badges on the `badges` branch
(`scripts/ci/publish-badges.sh`, rendered by `scripts/ci/badge.sh`) and
then checks that the rendered README serves them as SVG images
(`scripts/ci/verify-badges-render.sh`). The publisher only publishes
figures for the current tip of their source branch (checked before
generating and before every push), so a slow run for an older commit
never overwrites a newer one's badges; overlapping writers of the badges
branch are resolved by regenerating on the fetched tip and retrying.
