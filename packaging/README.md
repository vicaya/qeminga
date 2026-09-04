# Packaging qeminga

Files shipped with the daemon (design §8.2–§8.4, §5.7, §8.5, C-20):

| File | Installs to | Purpose |
|---|---|---|
| `systemd/qeminga.service` | `/usr/lib/systemd/system/` | The unit: conflicts with `qemu-guest-agent.service`, binds to the virtio port device, provisions `/run/qeminga` (`RuntimeDirectory=`, preserved across stops), `TimeoutStopSec=330s` for the default 300 s freeze cap. |
| `udev/99-qeminga.rules` | `/etc/udev/rules.d/` or `/usr/lib/udev/rules.d/` | Hands the single-open port `org.qemu.guest_agent.0` to the `qeminga` account, mode 0600 (§8.3). |
| `sysusers.d/qeminga.conf` | `/usr/lib/sysusers.d/` | Creates user and group `qeminga`, uid/gid 600, no login shell. |
| `config.toml` | `/etc/qeminga/config.toml` | The documented defaults (§8.2); every key is optional. |
| `tmpfiles.d/qeminga-suspend.conf` | `/usr/lib/tmpfiles.d/` **only with** `[features] suspend_ram = true` | Hands `/sys/power/state` to group `qeminga` (mode 0664) on every boot, without which the dropped daemon cannot write it (OQ-6). Not installed by default. |

The binary itself goes to `/usr/bin/qeminga`. Build releases with
`cargo build --release --locked --features seccomp` (never
`--all-features`, which includes the test-only `test-fakes` feature).

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

## Recovery marker

`/run/qeminga/frozen` is created before the first `FIFREEZE` and removed
after a complete thaw (§4.4). The daemon creates it after dropping to
the `qeminga` account, so the unit's `ExecStartPre=+chown` hands
`/run/qeminga` (created root-owned by `RuntimeDirectory=`, mode 0700) to
that account on every start. `RuntimeDirectoryPreserve=yes` keeps the
directory across `systemctl stop`, so a marker left by a forced stop makes
the next start enter recovery mode; a reboot clears `/run` and the kernel
freeze state together. Never put `state_path` on a filesystem the freeze
plan could freeze; startup refuses such a path.
