# Testing qeminga

Automated coverage lives in CI (`AGENTS.md` §Checks, `.github/workflows/`):
unit and property tests, the unprivileged end-to-end suite over a pty,
the privileged job on loop-mounted filesystems, fuzzing, and the
packaging checks. This page covers the one check that stays manual:
interoperability with a real libvirt/QEMU host (AC16, T5.4). Hosted CI
runners have no nested virtualisation.

## VM recipe

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

## What a passing run looks like

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
