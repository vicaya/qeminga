# Testing qeminga

Automated coverage lives in CI (`AGENTS.md` §Checks, `.github/workflows/`):
unit and property tests, the unprivileged end-to-end suite over a pty,
the privileged job on loop-mounted filesystems, fuzzing, and the
packaging checks. The test and privileged jobs run natively on both
supported architectures (`ubuntu-24.04` for x86-64, `ubuntu-24.04-arm`
for aarch64; #51): the aarch64 privileged leg is the execution evidence
for the aarch64 seccomp profile (AC15), and each leg proves its
architecture (`uname -m`, `RUNNER_ARCH`, the rustc host triple) before
it builds anything. This page also covers interoperability with a real libvirt/QEMU host
(AC16, T5.4): an automated smoke lane under QEMU's TCG accelerator on
both architectures, a `workflow_dispatch`-only KVM smoke lane on
self-hosted x86-64 and aarch64 (arm64) runners with a hardened community
runner setup script (`scripts/setup-kvm-runner.sh`), and the manual
recipe for a KVM host.

## libvirt TCG smoke lane (CI)

`.github/workflows/libvirt-tcg.yml` (#53, part) runs AC16 against real
libvirt on GitHub-hosted runners, natively on each architecture
(`ubuntu-24.04`, `ubuntu-24.04-arm`). It calls
`.github/workflows/libvirt-tcg-lane.yml` once per architecture, so each
architecture's smoke job waits only for its own build, and one
architecture's failed build never skips the other's lane. Hosted arm64 runners offer no
nested KVM and the lane does not rely on it on x86-64 either: the guest
is a `<domain type='qemu'>`, i.e. QEMU's TCG emulator, and the lane
proves it (`info kvm` answers `kvm support: disabled`, the QEMU command
line carries `-accel tcg`) before it counts any result.

1. **Candidate.** The `candidate` job builds
   `cargo build --release --locked --features seccomp` on the hosted
   runner of its architecture and uploads the binary, the packaging
   files and a `manifest.json` (source SHA, architecture, version,
   SHA-256 of the binary and of each packaging file, build run). It
   also reports the SHA-256 of the binary it built as a job output. The
   `smoke` job has no toolchain and never builds. It checks the manifest
   against the commit, the architecture and the files beside it, which
   proves the artifact is *consistent*: the manifest travels in the same
   artifact, so whoever could replace one could replace both. What ties
   the installed binary to the build is the job output: the lane refuses
   a binary whose digest is not the one the build job reported
   (`run --expect-sha256`).
2. **Guest.** A disposable Ubuntu 24.04 server cloud image, pinned by
   release date and SHA-256 in the script. Because the digest is checked
   after every fetch, the bytes may come from anywhere: the job's
   `actions/cache` entry (keyed by `image-key`, the release and the
   digest), then `cloud-images.ubuntu.com`, then the archive host
   Canonical moves pruned serials to; anything with another digest is
   ignored (x86-64: `q35`, SeaBIOS,
   `qemu64`; aarch64: `virt`, UEFI from `qemu-efi-aarch64`,
   `cortex-a57`), with the `org.qemu.guest_agent.0` virtio-serial
   channel and as many vCPUs as the runner has CPUs (at most 8).
   Multi-threaded TCG, one host thread per vCPU, is QEMU's default for
   both pairs and libvirt has no setting for it; the lane reports the
   observed threading (`TCG threading: multi (N vCPU threads)`).
   Host-passthrough or host-model CPUs need KVM; of the TCG models,
   `qemu64` reached an installed agent faster than `max` on x86-64
   (181 s against 219 s with 4 vCPUs; 230 s with 2), and on aarch64
   `max` is avoided because its QARMA pointer authentication is slow
   under emulation. A read-only payload disk carries the candidate;
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
   `/var/lib/libvirt/images/<that name>/` (`QEMINGA_E2E_IMAGES`
   overrides the root; it must be a plain absolute path of
   `[A-Za-z0-9._/-]`, because it is written into the domain XML
   unescaped). Before starting, the lane refuses a host that already has
   a `qeminga-e2e-*` domain or whose domains cannot be listed;
   afterwards (`if: always()`) it destroys and undefines only this run's
   domain and removes only its directory, and keeps the disks when the
   domain's state cannot be established. A run that failed before
   libvirt was installed has nothing to clean and the step says so
   instead of failing a second time.

This is smoke evidence on an emulated CPU, not KVM evidence and not a
release qualification. Not covered yet (the rest of #53): ext4/XFS data
disks, FSTRIM, a quiesced snapshot and its restore, the idle watchdog
through libvirt, and the private-controller release verification. Timeouts
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
  --source-sha "$sha" --run-id 1 --run-attempt 1 --out /tmp/tcg-out \
  --expect-sha256 "$(sha256sum target/release/qeminga | cut -d' ' -f1)"
sudo scripts/ci/libvirt-tcg-smoke.sh cleanup --arch "$(uname -m)" --run-id 1 --run-attempt 1
```

## libvirt KVM smoke lane & community runner setup (x86_64 and arm64)

`.github/workflows/libvirt-kvm.yml` (calling `.github/workflows/libvirt-kvm-lane.yml`
independently per architecture) exercises real hardware-accelerated KVM on
self-hosted `x86_64` and `aarch64` (`arm64`) Linux servers alongside the
hosted TCG lane:

- **Trust boundary:** `libvirt-kvm.yml` is triggered **only** via
  `workflow_dispatch` (never `pull_request`, `pull_request_target`, or
  comments), with `permissions: contents: read` and zero secrets passed to
  the self-hosted runner. Inside the reusable `libvirt-kvm-lane.yml` itself,
  every job requires `workflow_dispatch`, `refs/heads/main`, and caller
  `.github/workflows/libvirt-kvm.yml`; a fixed GitHub-hosted `verify` job
  (`ubuntu-24.04`) proves `target_rev` is a 40-hex commit reachable from
  `vicaya/qeminga` `refs/heads/main` before either `candidate` or `kvm`
  schedules, and `candidate` derives its hosted runner label
  (`ubuntu-24.04` / `ubuntu-24.04-arm`) from a fixed architecture mapping
  (never a caller input). The `candidate` job builds
  `cargo build --release --locked --features seccomp`, and the `kvm` job
  verifies the binary against
  `--expect-sha256 "${{ needs.candidate.outputs.sha256 }}"` with no Rust
  toolchain, no `apt-get`, and no `sudo` on the self-hosted runner.
- **Native KVM on both architectures:** `scripts/ci/libvirt-kvm-smoke.sh`
  (sharing candidate manifest/digest checks, pinned Ubuntu cloud image
  digests, and verified image fetch with `scripts/ci/libvirt-tcg-smoke.sh`
  via `scripts/ci/libvirt-smoke-common.sh`) boots a disposable guest with
  `<domain type='kvm'>` and `<cpu mode='host-passthrough' check='none'/>`
  (`x86_64`: `q35`, SeaBIOS, `<apic/>`; `aarch64`: `virt`, UEFI from
  `qemu-efi-aarch64` / `edk2-aarch64`, `<gic version='host'/>` to match
  GICv2 or GICv3 arm64 servers automatically), proves KVM via `virsh dumpxml`,
  HMP `info kvm` (`kvm support: enabled`), and the QEMU command line
  (`-accel kvm` / `accel=kvm`, refusing any TCG fallback), installs the
  candidate via `scripts/ci/libvirt-tcg-guest.sh`, runs
  `scripts/e2e-libvirt.sh`, and records `suite: "libvirt-kvm-smoke-v1"`
  with `accelerator: "kvm"`.
- **Unprivileged by default:** defaults to `QEMINGA_E2E_CONNECT=qemu:///session`
  with QEMU user-mode networking (`<interface type='user'>` via `libslirp`)
  and refuses to run as root in session mode.

### Setting up a community-donated KVM runner (`x86_64` or `arm64`)

Community members with a Linux KVM server (bare metal or nested-KVM VPS,
`x86_64` or `aarch64`/`arm64`, Ubuntu/Debian or Fedora/RHEL with systemd
and cgroup v2) can check readiness and provision a hardened runner with
`scripts/setup-kvm-runner.sh`.

**GitHub-side dispatch restriction is mandatory:** never register a donated
runner directly on public `vicaya/qeminga`. In `actions/runner`, action
preparation runs before `ACTIONS_RUNNER_HOOK_JOB_STARTED`, and steps with
`if: always()` or `if: failure()` still execute after a hook failure, so a
hook alone cannot keep untrusted jobs off the runner. Register the runner
against either:

1. **Private controller repository (default, #53):** a private repository
   containing `.github/workflows/libvirt-kvm.yml` and
   `.github/workflows/libvirt-kvm-lane.yml` (optionally pinning a 40-hex
   commit in `qeminga-target.rev`; otherwise resolving `vicaya/qeminga`
   `refs/heads/main`). `install` checks repository visibility and refuses
   public repositories (including `vicaya/qeminga`).
2. **Restricted organization runner group:** an organization runner group
   (`--org https://github.com/<org> --runner-group <GROUP> --allow-repo vicaya/qeminga`)
   restricted in GitHub's runner-group settings to the reviewed repository
   and workflow/ref.

```sh
# 1. Read-only check (architecture, /dev/kvm, cgroup v2, libvirt/QEMU, AAVMF on arm64, RAM/disk, DNS)
scripts/setup-kvm-runner.sh preflight

# 2. One-command hardened setup against the private controller repository
#    (prompts for the 1-hour GitHub registration token with hidden input, or
#    pass --token-file /path/to/mode-0600-token or --token-file -)
sudo scripts/setup-kvm-runner.sh install \
  --repo https://github.com/<owner>/qeminga-kvm-controller

# Alternative: restricted GitHub organization runner group
# sudo scripts/setup-kvm-runner.sh install \
#   --org https://github.com/<org> \
#   --runner-group <restricted-group> \
#   --allow-repo vicaya/qeminga

# Inspect active hardening score, policy, and logs:
scripts/setup-kvm-runner.sh status
journalctl -u qeminga-kvm-runner.service -f
```

For one-shot ephemeral runs, pass `--ephemeral` or (with a private `--repo`
controller) `--jitconfig-file /path/to/jitconfig` (mode `0600`; organization
JIT provisioning is refused because JIT blobs do not cryptographically bind
the GitHub runner group, and unbound JIT blobs omitting or emptying
`gitHubUrl` are refused in favor of `--token-file` / interactive token
registration because shared `actions.githubusercontent.com` endpoints do
not identify the repository; the single-use credential is decoded after
package installation supplies `jq`, validated for its exact matching
`gitHubUrl` and direct-child workspace path `$INSTALL_DIR/<name>` or exact
`$STATE_DIR/work`, delivered via systemd `LoadCredential=`, and removed
automatically on service stop). You can inspect the generated unit and
hooks before touching the host with `render-unit` and `render-hooks`.

### Security-by-default controls on donated runners

1. **Dedicated locked account (`qeminga-runner`) and scoped ownership:**
   system user with `/usr/sbin/nologin`, no `sudo`, no `libvirt`, `docker`,
   or `adm` group; only supplementary group `kvm` (to open `/dev/kvm`).
   `install` validates every ancestor component from `/` down to each
   managed directory (refusing symlinks, non-root owners, and group- or
   world-writable modes), refuses to adopt unrelated pre-existing accounts
   (or accounts in any group beyond `{qeminga-runner, kvm}`), unmanaged
   pre-existing directories, or existing systemd units (including vendor
   units) without a matching unit ownership record. It reserves a fresh
   config directory exclusively as root before creating the service account
   (rolling back both the empty directory and newly created account if the
   initial record cannot be written), claims each remaining top-level
   managed directory exclusively via `mkdir` and publishes fresh systemd
   units via hard link (`link(2)`) so concurrent creations or systemd mask
   symlinks (`/dev/null`) fail atomically without mutating foreign files,
   and records the provisioned UID/GID, dedicated non-overlapping paths,
   and per-resource acquisition markers (`OWNED_CONFIG_DIR`,
   `OWNED_STATE_DIR`, `OWNED_INSTALL_DIR`, `OWNED_HOOK_DIR`, `OWNED_UNIT`)
   in root-owned `/etc/qeminga-runner/install.env` (`0600`) immediately
   upon creation and before initializing contents
   (`RECORD_STATE=installing`, finalized to `installed` only after startup
   readiness succeeds unless `--no-start` is set), so an interrupted first
   install (including a failure while initializing state subdirectories)
   stays recoverable without ever claiming a unit name or directory created
   independently afterwards, stops an existing runner service only when
   owned by this installation, and creates runtime state subdirectories
   (`work/`, `images/`, `image-cache/`, etc.) as the unprivileged runner
   user rather than root.
2. **Unprivileged `qemu:///session` isolation:** installs only minimal
   session packages (`libvirt-daemon`, `libvirt-daemon-driver-qemu`,
   `libvirt-clients`, `qemu-system-x86` or `qemu-system-arm` +
   `qemu-efi-aarch64`, `qemu-utils`, `genisoimage`, `git`, `jq`, `curl`,
   `python3`); no `libvirt-daemon-system`, no host bridge, no `docker`, and
   no access to the donor's own `qemu:///system` VMs.
3. **Kernel-enforced systemd sandbox:** `NoNewPrivileges=yes`, empty
   `CapabilityBoundingSet=` / `AmbientCapabilities=`, `ProtectSystem=strict`,
   `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectProc=invisible`,
   `DevicePolicy=closed` with `DeviceAllow=/dev/kvm rw` only,
   `RestrictNamespaces=yes`, `RestrictSUIDSGID=yes`, `LockPersonality=yes`,
   `RestrictRealtime=yes`, `SystemCallArchitectures=native`,
   `SystemCallFilter=@system-service` (blocking mount, module, reboot, swap,
   raw I/O, clock, and debug syscalls), `UMask=0077`, `KillMode=control-group`,
   and host-protecting bounds (`MemoryMax=80%`, `TasksMax=512`, optional
   `--cpu-quota`). (`MemoryDenyWriteExecute` is omitted because `.NET`,
   Node.js, and QEMU need JIT mappings.)
4. **Verified cgroup BPF egress firewall:** denies a unit-specific loopback
   sentinel (`127.255.255.254/32`), cloud instance metadata
   (`169.254.0.0/16`, `fe80::/10`, and AWS IPv6 IMDS `fd00:ec2::254/128`
   unconditionally, even with `--no-lan-deny`), multicast, and private LANs
   (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`,
   `fc00::/7`) by default while allowing `127.0.0.0/9` (`127.0.0.1`,
   `systemd-resolved` at `127.0.0.53`) and `::1/128`. Because systemd
   silently skips `IPAddressDeny=` on hosts or containers without cgroup
   BPF firewalling (and excludes `ExecStartPre=` from
   `RestartPreventExitStatus=`), the unit uses `Type=notify` with
   `NotifyAccess=main` and `TimeoutStartSec=60s`: the root-owned
   main-process launcher (`run-runner.sh` or `run-jit.sh`) invokes
   `check-egress-firewall.sh` before signaling `READY=1` as MainPID and
   `exec`'ing the runner listener (stripping `NOTIFY_SOCKET`). That check
   runs `/usr/bin/python3` in isolated mode (`-I -S`) under `env -i` so
   runner-writable `HOME` / user-site configuration cannot influence the
   verdict, proves this unit's cgroup BPF policy rejects the loopback
   sentinel (`127.255.255.254`), IMDS, and configured private LANs with
   `EPERM` (distinguishing unit policy from host-wide IMDS blocks), and
   exits `78` directly in the main process without sending `READY=1` so
   `systemctl start` / `install` fails immediately and
   `RestartPreventExitStatus=78` stops restarts on unsupported hosts.
   Because QEMU runs in the same cgroup, disposable guest VMs inherit the
   same block. Hosts with a private DNS resolver can pass
   `--allow-ip <ip>/32` (IMDS ranges, the loopback sentinel, and default
   routes are always refused).
5. **Host-enforced pre- and post-job hooks (defense-in-depth):** root-owned
   `/usr/local/libexec/qeminga-runner/hook-job-{started,completed}.sh`
   wired via systemd `Environment=` and configured by root-owned
   `/etc/qeminga-runner/policy.env` (`0640`). As a second check behind
   GitHub-side repo/runner-group restriction, `hook-job-started.sh`
   enforces exact whole-string allowlists on `GITHUB_REPOSITORY`,
   `GITHUB_EVENT_NAME` (default `workflow_dispatch` only; `pull_request`
   and `pull_request_target` are unconditionally refused), `GITHUB_REF`
   (default `refs/heads/main`), `GITHUB_WORKFLOW_REF` (default
   `.github/workflows/libvirt-kvm.yml`), and optional `--allow-actor`, plus
   checks `/dev/kvm` and stale `qeminga-e2e-*` domains. After every job,
   `hook-job-completed.sh` destroys/undefines any stray `qeminga-e2e-*`
   session domains (leaving unrelated domains alone and keeping disks if
   state is unknown), anchors image verification and recursive same-mount
   run-directory and `WORK_DIR` removal strictly to their trusted parent
   FDs via kernel `O_PATH | O_DIRECTORY | O_NOFOLLOW` ancestor traversal
   (supporting search-only `0711` parents) plus `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`
   on the enumerated directory and `/proc/self/mountinfo` +
   `/proc/self/fdinfo` `mnt_id` verification (so symlinks, cross-device
   mounts, and same-filesystem bind mounts — whether directly at
   `WORK_DIR`/`$STATE_DIR/images` or beneath them — fail closed without
   touching external targets), restricts `WORK_DIR` to exact
   `$STATE_DIR/work` or a single non-reserved child under `$INSTALL_DIR`,
   and keeps the SHA-256-verified image cache.
6. **Pinned, read-only runner binaries & safe update/reinstall/uninstall:**
   downloads official `actions/runner` over HTTPS TLS 1.2+ and checks the
   pinned SHA-256 digest for `linux-x64` or `linux-arm64` before
   extraction. `install`, `update`, and `uninstall` serialize overlapping
   invocations for the same `--config-dir` with an exclusive root-owned
   `flock` under `/run/.qeminga-runner.locks` (a hidden path outside the
   service `RuntimeDirectory=` namespace, with explicit collision checks
   against `--service` and any custom `QEMINGA_LOCK_DIR`) before reading
   `install.env`. Fresh installs write a durable
   `RECORD_STATE=user-pending` record with a unique `INSTALL_ID` before
   `useradd`, stamp `qeminga-runner-<INSTALL_ID>` into the new account's
   GECOS (verified alongside numeric UID/GID across bootstrap, `install`,
   `update`, and `uninstall`, so an unrelated or recycled-UID account is
   never adopted, modified, or purged while legacy records without
   `INSTALL_ID` remain distinguishable during migration), record each owned
   path's backing volume fingerprint (`VOL_*`) by resolving the opened
   `O_PATH` FD's kernel `mnt_id` in `/proc/self/mountinfo` together with
   its persistent filesystem UUID / `f_fsid` (catching directory overmounts
   and reusable `/dev/sdX` device names across remounts), enforce
   mount-bounded recursive ownership changes (`fs_ops safe-chown-tree` over
   open FDs, never crossing nested bind mounts), and publish fresh systemd
   units with `ln -T` (updating owned units with `mv -T -f` after verifying
   `VOL_UNIT`) so an existing file, mask symlink, or directory destination
   fails closed. Registration tokens are refused on the command line
   (`--token` is rejected) and passed solely via the inherited
   `ACTIONS_RUNNER_INPUT_TOKEN` environment variable. Reinstalls verify all
   owned resource volumes (including refusing absent legacy directories
   with no recorded `VOL_*`) and inspect existing `.runner` registrations
   before stopping the service (reusing matching registrations, refusing
   incompatible ones, and restoring locked permissions + restarting the
   service if reconfiguration fails). Auto-updates are disabled by default
   (`--disableupdate`) so runner binaries stay kernel-read-only; GitHub
   requires runner updates within 30 days of a new release — update cleanly
   with `sudo scripts/setup-kvm-runner.sh update` (which requires a valid
   root-owned `install.env` in `installed` state, verifies live numeric
   UID/GID, `INSTALL_ID` marker, recorded backing volumes, and absence of
   nested mounts before stopping the service or modifying files, and
   refuses mismatched flags, or opt in to GitHub self-updates with
   `--allow-auto-update`). Remove only resources owned by the recorded
   installation with
   `sudo scripts/setup-kvm-runner.sh uninstall [--token-file PATH] [--purge-user]`
   (uninstall shares the same record, numeric UID/GID, `INSTALL_ID` marker,
   volume, and mount checks BEFORE any `runuser`, `chown`, service stop, or
   token handoff — leaving `install.env` intact on mismatch — stages and
   runs the current installer's own domain-only cleanup logic with a
   minimal `STATE_DIR`/`IMAGES_DIR` policy over a private temporary runtime
   dir once `OWNED_UNIT=0`, fails closed in the fallback path when
   `runuser` or the service account is unavailable and `$STATE_DIR/images`
   cannot be verified clean without following symlinks or crossing a mount,
   verifies each owned or staged path's recorded `VOL_*` backing volume
   before accepting absence as deleted or modifying it, refuses to stage or
   delete across any active mount or same-filesystem bind mount via
   `/proc/self/mountinfo` and kernel `fdinfo` `mnt_id`, moves each owned
   unit or directory via pure `rename(2)` (no copy-and-delete fallback on
   `EXDEV`) into a private root-only `0700` `.qeminga-removing.*` staging
   container recorded in `STAGED_*` before clearing `OWNED_*=0` and
   reloading systemd — refusing to purge the service account or remove
   `install.env` until every staged container is confirmed deleted so
   failed deletions stay recoverable on retry without touching replacement
   paths — preserves `$STATE_DIR/images` and `$STATE_DIR/.config` if
   session domain cleanup cannot confirm domains are gone, and when run
   without `--purge-user` retains a minimal `RECORD_STATE=user-only`
   UID/GID/marker record in `/etc/qeminga-runner/install.env` so a later
   default reinstall or `uninstall --purge-user` recognizes the surviving
   managed account).

### Running the KVM smoke script locally (unprivileged)

On any `x86_64` or `aarch64` Linux host where your account is in the `kvm`
group and `libvirt-daemon`, `libvirt-daemon-driver-qemu`, `libvirt-clients`,
`qemu-system-{x86,arm}` (plus `qemu-efi-aarch64` on arm64), `qemu-utils`,
`genisoimage`, `jq`, and `curl` are installed:

```sh
cargo build --release --locked --features seccomp
sha=$(git rev-parse HEAD)
scripts/ci/libvirt-kvm-smoke.sh manifest --out /tmp/candidate --binary target/release/qeminga \
  --arch "$(uname -m)" --source-sha "$sha" --version 0.1.0 --run-id 1 --run-attempt 1 --runner local
scripts/ci/libvirt-kvm-smoke.sh run --arch "$(uname -m)" --candidate /tmp/candidate \
  --source-sha "$sha" --run-id 1 --run-attempt 1 --out /tmp/kvm-out \
  --expect-sha256 "$(sha256sum target/release/qeminga | cut -d' ' -f1)"
scripts/ci/libvirt-kvm-smoke.sh cleanup --arch "$(uname -m)" --run-id 1 --run-attempt 1
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
