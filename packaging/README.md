# Packaging qeminga

Files shipped with the daemon (design §8.2–§8.4, §5.7, §8.5, C-20):

| File | Installs to | Purpose |
|---|---|---|
| `systemd/qeminga.service` | `/usr/lib/systemd/system/` | The unit: conflicts with `qemu-guest-agent.service`, deliberately does not bind to the virtio port device (a crash while frozen is recovered whether or not the port is there; the daemon retries the open), hands `/run/qeminga` to the service account before every start (privileged `ExecStartPre` lines; not `RuntimeDirectory=`, see below), `TimeoutStopSec=330s` for the default 300 s freeze cap. |
| `udev/99-qeminga.rules` | `/etc/udev/rules.d/` or `/usr/lib/udev/rules.d/` | Hands the single-open port `org.qemu.guest_agent.0` to the `qeminga` account, mode 0600 (§8.3). |
| `sysusers.d/qeminga.conf` | `/usr/lib/sysusers.d/` | Creates user and group `qeminga`, uid/gid 600, no login shell. |
| `config.toml` | `/etc/qeminga/config.toml` | The documented defaults (§8.2); every key is optional. |
| `tmpfiles.d/qeminga.conf` | `/usr/lib/tmpfiles.d/` | Creates `/run/qeminga` (0700, owned by `qeminga`) at boot for the recovery marker (C-20). Always install it and run `systemd-tmpfiles --create`. |
| `tmpfiles.d/qeminga-suspend.conf` | `/usr/lib/tmpfiles.d/` **only with** `[features] suspend_ram = true` | Hands `/sys/power/state` to group `qeminga` (mode 0664) on every boot, without which the dropped daemon cannot write it (OQ-6). Not installed by default. |

The binary itself goes to `/usr/bin/qeminga`. Build releases with
`cargo build --release --locked --features seccomp` (never
`--all-features`: the test-only `test-fakes` feature is a compile error
in a release build, and `seccomp-log` would fail the enforced hardening
check at startup).

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
sudo install -d -m 0755 /etc/qeminga
sudo install -m 0644 packaging/config.toml /etc/qeminga/config.toml
sudo install -m 0644 packaging/systemd/qeminga.service /usr/lib/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now qeminga.service
```

Verify with `systemctl status qeminga` and, from the host,
`virsh qemu-agent-command <domain> '{"execute":"guest-ping"}'`.

## Suspend to RAM

`guest-suspend-ram` is disabled by default. Enabling it takes the
`suspend_ram` Cargo feature, `[features] suspend_ram = true` in
`config.toml`, **and** write access to `/sys/power/state` for the service
account: the file is `0644 root:root` and none of the daemon's remaining
capabilities bypasses that, so install `tmpfiles.d/qeminga-suspend.conf`
and run `sudo systemd-tmpfiles --create qeminga-suspend.conf` (OQ-6). Do
not install the rule otherwise: it is what lets the account suspend the
guest.

## Changing the freeze cap

`fsfreeze_max_timeout_secs` in `config.toml` and `TimeoutStopSec=` in
the unit are coupled (§8.4): keep `TimeoutStopSec` greater than the cap
plus a thaw-drain margin (30 s), otherwise a stop requested during a
freeze falls back to the forced-stop recovery path (§5.7) instead of
waiting for the thaw. `tests/packaging.rs` checks the shipped pair.
`fsfreeze_operation_timeout_secs` (the freeze walk's own deadline, §4.4)
is validated to be at most the cap, so it never needs a margin of its
own.

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
built without `--features seccomp` (or with `--all-features`, which adds
the logging filter), a stray `QEMINGA_TEST_FAKE_KERNEL` in the unit's
environment, or a kernel or container runtime that refuses the filter
(the line names the installer's error). `[features] seccomp = false`
left in the configuration is refused one step earlier, as a
configuration error naming `features.seccomp`: the same exit status 78,
without the `refusing to serve` line.

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
