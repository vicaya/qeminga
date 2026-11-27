#!/usr/bin/env bash
# Runs inside the disposable guest of the libvirt TCG smoke lane
# (scripts/ci/libvirt-tcg-smoke.sh), as root, from cloud-init, with the
# read-only payload disk mounted at $1. Installs the hosted candidate
# with the repository's own packaging files, exactly the steps of
# packaging/README.md, then checks the production state the host cannot
# see through the agent: the installed binary is the candidate, the
# service is active under the qeminga account with NoNewPrivs and an
# enforced seccomp filter, the upstream agent is not running, and the
# channel belongs to the service account. Ends with one line the host
# waits for on the serial console:
#
#   qeminga-e2e-guest: RESULT PASS | RESULT FAIL
set -uo pipefail

src="${1:?usage: guest.sh PAYLOAD_DIR}"
HOME_TEST_MOUNT="/home/qeminga-test-vol"
HOME_TEST_IMG="/run/qeminga-home-test.img"
log() { printf 'qeminga-e2e-guest: %s\n' "$*"; }

# Create and mount a dedicated ext4 filesystem under /home BEFORE starting
# qeminga.service so ProtectHome=read-only is exercised against a real
# separate /home volume (read-only for ordinary writes, visible and freezable
# by guest-fsfreeze-freeze-list; #66).
prepare_home_filesystem() {
    modprobe loop 2>/dev/null || true
    rm -f "$HOME_TEST_IMG"
    truncate -s 16M "$HOME_TEST_IMG" || return 1
    chmod 0600 "$HOME_TEST_IMG" || return 1
    mkfs.ext4 -q -F -b 1024 -m 0 "$HOME_TEST_IMG" || return 1
    install -d -m 0755 "$HOME_TEST_MOUNT" || return 1
    mount -o loop "$HOME_TEST_IMG" "$HOME_TEST_MOUNT" || return 1
    log "install: mounted separate ext4 volume at $HOME_TEST_MOUNT"
}

install_candidate() {
    log "install: masking qemu-guest-agent"
    systemctl mask --now qemu-guest-agent.service || return 1
    prepare_home_filesystem || return 1
    install -m 0755 "$src/qeminga" /usr/bin/qeminga || return 1
    install -m 0644 "$src/packaging/sysusers.d/qeminga.conf" /usr/lib/sysusers.d/ || return 1
    systemd-sysusers || return 1
    install -m 0644 "$src/packaging/udev/99-qeminga.rules" /etc/udev/rules.d/ || return 1
    udevadm control --reload || return 1
    udevadm trigger --subsystem-match=virtio-ports --action=add || return 1
    udevadm settle --timeout=60 || return 1
    install -m 0644 "$src/packaging/tmpfiles.d/qeminga.conf" /usr/lib/tmpfiles.d/ || return 1
    systemd-tmpfiles --create qeminga.conf || return 1
    install -d -m 0755 /etc/qeminga || return 1
    # AC16 exercises domifaddr, guest-get-osinfo, domfsinfo and shutdown, so
    # this smoke lane installs the lifecycle profile rather than the CVM default
    # (packaging/config-data-protection.toml).
    install -m 0644 "$src/packaging/config.toml" /etc/qeminga/config.toml || return 1
    install -m 0644 "$src/packaging/systemd/qeminga.service" /usr/lib/systemd/system/ || return 1
    systemctl daemon-reload || return 1
    systemctl enable --now qeminga.service || return 1
    log "install: done"
}

status_field() { awk -v k="$2:" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' "/proc/$1/status"; }

QEMINGA_PID=""
QEMINGA_UID=""
QEMINGA_NNP=""
QEMINGA_SECCOMP=""

wait_for_qeminga_ready() {
    QEMINGA_PID=""
    QEMINGA_UID=""
    QEMINGA_NNP=""
    QEMINGA_SECCOMP=""
    local pid uid nnp seccomp
    for _ in $(seq 1 60); do
        if systemctl is-active --quiet qeminga.service; then
            pid="$(systemctl show -p MainPID --value qeminga.service)"
            if [ -n "$pid" ] && [ "$pid" != 0 ] && [ -r "/proc/$pid/status" ]; then
                uid="$(status_field "$pid" Uid)"
                nnp="$(status_field "$pid" NoNewPrivs)"
                seccomp="$(status_field "$pid" Seccomp)"
                QEMINGA_PID="$pid"
                QEMINGA_UID="$uid"
                QEMINGA_NNP="$nnp"
                QEMINGA_SECCOMP="$seccomp"
                if [ "$uid" = "600 600 600 600" ] && [ "$nnp" = 1 ] && [ "$seccomp" = 2 ]; then
                    return 0
                fi
            fi
        fi
        sleep 1
    done
    return 1
}

check_production_state() {
    local ok=0 want got
    want="$(cat "$src/qeminga.sha256")"
    got="$(sha256sum /usr/bin/qeminga | cut -d' ' -f1)"
    if [ "$got" = "$want" ]; then log "ok: /usr/bin/qeminga sha256 $got is the candidate"
    else log "FAILED: /usr/bin/qeminga sha256 $got, candidate $want"; ok=1; fi

    if [ "$(getent passwd qeminga | cut -d: -f3,4)" = "600:600" ]; then log "ok: account qeminga is 600:600"
    else log "FAILED: account qeminga: $(getent passwd qeminga || echo missing)"; ok=1; fi

    if [ "$(getent passwd qeminga-parser | cut -d: -f3,4)" = "601:601" ]; then log "ok: account qeminga-parser is 601:601"
    else log "FAILED: account qeminga-parser: $(getent passwd qeminga-parser || echo missing)"; ok=1; fi

    # The daemon drops and installs its filter after start (design §5.4);
    # give it a bounded moment under emulation.
    wait_for_qeminga_ready || true
    local pid="$QEMINGA_PID" uid="$QEMINGA_UID" nnp="$QEMINGA_NNP" seccomp="$QEMINGA_SECCOMP"
    if systemctl is-active --quiet qeminga.service; then log "ok: qeminga.service is active (pid $pid)"
    else log "FAILED: qeminga.service is $(systemctl is-active qeminga.service)"; ok=1; fi
    if [ "${uid:-}" = "600 600 600 600" ]; then log "ok: running as uid 600"
    else log "FAILED: Uid ${uid:-unknown}"; ok=1; fi
    if [ "${nnp:-}" = 1 ]; then log "ok: NoNewPrivs 1"
    else log "FAILED: NoNewPrivs ${nnp:-unknown}"; ok=1; fi
    if [ "${seccomp:-}" = 2 ]; then log "ok: Seccomp 2 (filter enforced)"
    else log "FAILED: Seccomp ${seccomp:-unknown}"; ok=1; fi

    if systemctl is-active --quiet qemu-guest-agent.service; then
        log "FAILED: qemu-guest-agent is active"; ok=1
    else
        log "ok: qemu-guest-agent is $(systemctl is-active qemu-guest-agent.service)"
    fi

    local port=/dev/virtio-ports/org.qemu.guest_agent.0 mode
    mode="$(stat -L -c '%U:%G:%a' "$port" 2>/dev/null)"
    if [ "$mode" = "qeminga:qeminga:600" ]; then log "ok: $port is $mode"
    else log "FAILED: $port is ${mode:-missing}"; ok=1; fi

    if [ -n "$pid" ] && [ "$pid" != 0 ] && [ -r "/proc/$pid/mountinfo" ]; then
        check_write_confinement "$pid" || ok=1
        check_parser_isolation "$QEMINGA_PID" || ok=1
    else
        log "FAILED: cannot inspect /proc/${pid:-0}/mountinfo for write confinement"
        ok=1
    fi
    return "$ok"
}

# Print "<mnt_id> <vfs_opts> <mount_point>" for the mount actually serving $2
# inside PID $1's mount namespace, using /proc/self/fdinfo/<fd> mnt_id.
effective_mount_in_ns() {
    local pid="$1" target="$2"
    nsenter --mount="/proc/$pid/ns/mnt" -- python3 - "$target" <<'PY'
import os, sys

target = sys.argv[1]
fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
try:
    mnt_id = None
    with open(f"/proc/self/fdinfo/{fd}", "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("mnt_id:"):
                mnt_id = line.split()[1]
                break
    if mnt_id is None:
        raise RuntimeError(f"mnt_id missing in fdinfo for {target}")
    with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
        for line in f:
            parts = line.split()
            if parts and parts[0] == mnt_id:
                print(f"{mnt_id} {parts[5]} {parts[4]}")
                sys.exit(0)
    raise RuntimeError(f"mnt_id {mnt_id} not found in mountinfo for {target}")
finally:
    os.close(fd)
PY
}

vfs_opts_have() {
    local opts="$1" want="$2"
    case ",$opts," in
        *,"$want",*) return 0 ;;
        *) return 1 ;;
    esac
}

# Open $2 with O_WRONLY (no O_CREAT, no O_TRUNC, zero writes) and immediately
# close it, as uid/gid 600 either on the host ("host") or inside PID $1's mount
# namespace. Prints "OK" or "ERRNO=<name> <strerror>".
probe_open_wronly() {
    local where="$1" target="$2"
    local -a cmd=(setpriv --reuid 600 --regid 600 --clear-groups -- python3 - "$target")
    if [ "$where" != "host" ]; then
        cmd=(nsenter --mount="/proc/$where/ns/mnt" -- "${cmd[@]}")
    fi
    "${cmd[@]}" <<'PY'
import errno, os, sys

try:
    fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CLOEXEC)
except OSError as exc:
    name = errno.errorcode.get(exc.errno, str(exc.errno))
    print(f"ERRNO={name} {exc.strerror}")
    sys.exit(1)
else:
    os.close(fd)
    print("OK")
PY
}

# Create a unique UID-600-owned directory under $2 with two exclusive files
# ("probe" and "unlink-outside") set via fchown/fchmod on open fds, confirm
# write + unlink succeed outside confinement, then assert both fail with EROFS
# inside PID $1's mount namespace and clean up only the created directory.
check_ro_dir_confinement() {
    local pid="$1" parent="$2" label="$3"
    local dir probe unlink_outside err="" ok=0

    dir="$(mktemp -d "$parent/qeminga-confinement.XXXXXX")" || {
        log "FAILED: cannot create unique probe dir under $parent"
        return 1
    }
    probe="$dir/probe"
    unlink_outside="$dir/unlink-outside"

    if ! python3 - "$dir" <<'PY'
import os, sys

dpath = sys.argv[1]
dfd = os.open(dpath, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    os.fchown(dfd, 600, 600)
    os.fchmod(dfd, 0o700)
    for name in ("probe", "unlink-outside"):
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dfd,
        )
        try:
            os.fchown(fd, 600, 600)
            os.fchmod(fd, 0o600)
            os.write(fd, b"intact\n")
        finally:
            os.close(fd)
finally:
    os.close(dfd)
PY
    then
        log "FAILED: cannot initialize exclusive probe files in $dir"
        rm -rf -- "$dir"
        return 1
    fi

    # Outside confinement, UID 600 must genuinely be able to write and unlink.
    # shellcheck disable=SC2016 # $1 is expanded by the inner /bin/sh
    if setpriv --reuid 600 --regid 600 --clear-groups -- /bin/sh -c 'printf "intact\n" > "$1"' _ "$probe" \
        && setpriv --reuid 600 --regid 600 --clear-groups -- /bin/rm -- "$unlink_outside"; then
        log "ok: $label ($dir) allows uid 600 write and unlink outside confinement"
    else
        log "FAILED: $label ($dir) was not writable/unlinkable to uid 600 outside confinement"
        ok=1
    fi

    # Inside the service's mount namespace, writing or unlinking must fail EROFS.
    # shellcheck disable=SC2016 # $1 is expanded by the inner /bin/sh
    if err="$(LC_ALL=C nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- /bin/sh -c 'printf "tampered\n" > "$1"' _ "$probe" 2>&1)"; then
        log "FAILED: uid 600 wrote $probe inside qeminga.service mount namespace"
        ok=1
    elif printf '%s\n' "$err" | grep -Fq 'Read-only file system'; then
        log "ok: write under $label denied with EROFS in service namespace ($err)"
    else
        log "FAILED: write under $label failed without EROFS ($err)"
        ok=1
    fi

    if err="$(LC_ALL=C nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- /bin/rm -- "$probe" 2>&1)"; then
        log "FAILED: uid 600 unlinked $probe inside qeminga.service mount namespace"
        ok=1
    elif printf '%s\n' "$err" | grep -Fq 'Read-only file system'; then
        log "ok: unlink under $label denied with EROFS in service namespace ($err)"
    else
        log "FAILED: unlink under $label failed without EROFS ($err)"
        ok=1
    fi

    if [ -f "$probe" ] && [ "$(cat "$probe")" = "intact" ]; then
        log "ok: $label probe remained intact"
    else
        log "FAILED: $label probe was modified or removed"
        ok=1
    fi

    rm -rf -- "$dir"
    return "$ok"
}

check_sys_power_confinement() {
    local pid="$1" ok=0
    local state=/sys/power/state neighbor="" cand cand_mode
    if [ ! -f "$state" ]; then
        log "FAILED: $state missing in disposable guest"
        return 1
    fi
    for cand in /sys/power/pm_freeze_timeout /sys/power/wakeup_count /sys/power/pm_async /sys/power/disk /sys/power/*; do
        if [ "$cand" != "$state" ] && [ -f "$cand" ]; then
            cand_mode="$(stat -c '%A' "$cand" 2>/dev/null || true)"
            case "$cand_mode" in
                -?w*) neighbor="$cand"; break ;;
            esac
        fi
    done
    if [ -z "$neighbor" ]; then
        log "FAILED: no neighboring writable attribute under /sys/power"
        return 1
    fi

    local state_orig neighbor_orig state_uid state_gid state_mode nb_uid nb_gid nb_mode
    state_orig="$(stat -c '%u:%g:%a' "$state")"
    neighbor_orig="$(stat -c '%u:%g:%a' "$neighbor")"
    IFS=: read -r state_uid state_gid state_mode <<<"$state_orig"
    IFS=: read -r nb_uid nb_gid nb_mode <<<"$neighbor_orig"

    local dropin_dir=/etc/systemd/system/qeminga.service.d
    local dropin="$dropin_dir/99-suspend-confinement-test.conf"
    local installed_dropin=0

    # Grant UID 600 DAC write access (matching tmpfiles.d/qeminga-suspend.conf)
    # to both /sys/power/state and the neighboring attribute so only the mount
    # namespace distinguishes the default unit from the suspend drop-in.
    if chown root:qeminga "$state" "$neighbor" && chmod 0664 "$state" "$neighbor"; then
        local out
        if out="$(probe_open_wronly host "$state")"; then
            log "ok: $state open(O_WRONLY) allowed for uid 600 outside confinement ($out)"
        else
            log "FAILED: $state open(O_WRONLY) denied outside confinement despite DAC grant ($out)"
            ok=1
        fi
        if out="$(probe_open_wronly host "$neighbor")"; then
            log "ok: $neighbor open(O_WRONLY) allowed for uid 600 outside confinement ($out)"
        else
            log "FAILED: $neighbor open(O_WRONLY) denied outside confinement despite DAC grant ($out)"
            ok=1
        fi

        # 1. Default unit: effective mounts for /sys, /sys/power/state, and neighbor
        #    are all ro, and O_WRONLY opens fail with EROFS despite DAC permission.
        local p info mnt_id vfs_opts mp
        for p in /sys "$state" "$neighbor"; do
            if info="$(effective_mount_in_ns "$pid" "$p")"; then
                read -r mnt_id vfs_opts mp <<<"$info"
                if vfs_opts_have "$vfs_opts" ro; then
                    log "ok: default unit effective mount for $p is ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                else
                    log "FAILED: default unit effective mount for $p is not ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                    ok=1
                fi
            else
                log "FAILED: cannot determine effective mount for $p in default unit"
                ok=1
            fi
        done

        if out="$(probe_open_wronly "$pid" "$state")"; then
            log "FAILED: default unit allowed uid 600 open(O_WRONLY) on $state ($out)"
            ok=1
        elif printf '%s\n' "$out" | grep -Fq 'ERRNO=EROFS'; then
            log "ok: default unit denied uid 600 open(O_WRONLY) on $state ($out)"
        else
            log "FAILED: default unit denied $state without EROFS ($out)"
            ok=1
        fi

        if out="$(probe_open_wronly "$pid" "$neighbor")"; then
            log "FAILED: default unit allowed uid 600 open(O_WRONLY) on $neighbor ($out)"
            ok=1
        elif printf '%s\n' "$out" | grep -Fq 'ERRNO=EROFS'; then
            log "ok: default unit denied uid 600 open(O_WRONLY) on $neighbor ($out)"
        else
            log "FAILED: default unit denied $neighbor without EROFS ($out)"
            ok=1
        fi

        # 2. Documented suspend drop-in: ReadWritePaths=/sys/power/state allows
        #    open(O_WRONLY) on /sys/power/state while /sys and $neighbor stay ro.
        mkdir -p "$dropin_dir"
        printf '[Service]\nReadWritePaths=/sys/power/state\n' > "$dropin"
        installed_dropin=1
        if systemctl daemon-reload && systemctl restart qeminga.service && wait_for_qeminga_ready; then
            local spid="$QEMINGA_PID" sys_mnt="" state_mnt=""
            log "ok: suspend drop-in unit active and dropped (pid $spid)"
            if info="$(effective_mount_in_ns "$spid" /sys)"; then
                read -r mnt_id vfs_opts mp <<<"$info"
                sys_mnt="$mnt_id"
                if vfs_opts_have "$vfs_opts" ro; then
                    log "ok: suspend drop-in effective mount for /sys remains ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                else
                    log "FAILED: suspend drop-in /sys is not ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                    ok=1
                fi
            else
                log "FAILED: cannot determine effective mount for /sys under suspend drop-in"
                ok=1
            fi
            if info="$(effective_mount_in_ns "$spid" "$state")"; then
                read -r mnt_id vfs_opts mp <<<"$info"
                state_mnt="$mnt_id"
                if vfs_opts_have "$vfs_opts" rw && [ -n "$sys_mnt" ] && [ "$state_mnt" != "$sys_mnt" ]; then
                    log "ok: suspend drop-in effective mount for $state is rw on dedicated bind mount (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                else
                    log "FAILED: suspend drop-in $state is not rw on a distinct mount (mnt_id=$mnt_id sys_mnt=$sys_mnt opts=$vfs_opts mp=$mp)"
                    ok=1
                fi
            else
                log "FAILED: cannot determine effective mount for $state under suspend drop-in"
                ok=1
            fi
            if info="$(effective_mount_in_ns "$spid" "$neighbor")"; then
                read -r mnt_id vfs_opts mp <<<"$info"
                if vfs_opts_have "$vfs_opts" ro; then
                    log "ok: suspend drop-in effective mount for $neighbor remains ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                else
                    log "FAILED: suspend drop-in $neighbor is not ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                    ok=1
                fi
            else
                log "FAILED: cannot determine effective mount for $neighbor under suspend drop-in"
                ok=1
            fi

            if out="$(probe_open_wronly "$spid" "$state")"; then
                log "ok: suspend drop-in allowed uid 600 open(O_WRONLY) on $state without writing ($out)"
            else
                log "FAILED: suspend drop-in denied uid 600 open(O_WRONLY) on $state ($out)"
                ok=1
            fi
            if out="$(probe_open_wronly "$spid" "$neighbor")"; then
                log "FAILED: suspend drop-in allowed uid 600 open(O_WRONLY) on $neighbor ($out)"
                ok=1
            elif printf '%s\n' "$out" | grep -Fq 'ERRNO=EROFS'; then
                log "ok: suspend drop-in kept $neighbor denied with EROFS ($out)"
            else
                log "FAILED: suspend drop-in denied $neighbor without EROFS ($out)"
                ok=1
            fi
        else
            log "FAILED: qeminga.service did not become ready with suspend drop-in"
            ok=1
        fi
    else
        log "FAILED: could not grant temporary DAC write permissions on $state and $neighbor"
        ok=1
    fi

    # Always restore the default unit and original sysfs permissions before
    # host-side AC16 checks talk to the service.
    chown "$state_uid:$state_gid" "$state" && chmod "$state_mode" "$state" || ok=1
    chown "$nb_uid:$nb_gid" "$neighbor" && chmod "$nb_mode" "$neighbor" || ok=1
    if [ "$installed_dropin" -eq 1 ]; then
        rm -f "$dropin"
        rmdir "$dropin_dir" 2>/dev/null || true
        if systemctl daemon-reload && systemctl restart qeminga.service && wait_for_qeminga_ready; then
            log "ok: restored default qeminga.service (pid $QEMINGA_PID)"
        else
            log "FAILED: could not restore default qeminga.service after suspend drop-in check"
            ok=1
        fi
    fi
    return "$ok"
}

check_write_confinement() {
    local pid="$1" ok=0 p info mnt_id vfs_opts mp root_mnt_id="" home_vol_mnt_id=""

    check_ro_dir_confinement "$pid" /var/tmp "/var/tmp" || ok=1
    check_ro_dir_confinement "$pid" /home "/home" || ok=1
    check_ro_dir_confinement "$pid" "$HOME_TEST_MOUNT" "$HOME_TEST_MOUNT (separate ext4 under /home)" || ok=1
    check_ro_dir_confinement "$pid" /run "/run" || ok=1
    check_ro_dir_confinement "$pid" /dev "/dev" || ok=1
    check_ro_dir_confinement "$pid" /dev/shm "/dev/shm" || ok=1

    for p in / /run /home "$HOME_TEST_MOUNT" /dev /dev/shm; do
        if info="$(effective_mount_in_ns "$pid" "$p")"; then
            read -r mnt_id vfs_opts mp <<<"$info"
            if [ "$p" = "/" ]; then root_mnt_id="$mnt_id"; fi
            if [ "$p" = "$HOME_TEST_MOUNT" ]; then
                home_vol_mnt_id="$mnt_id"
                if [ "$mp" != "$HOME_TEST_MOUNT" ]; then
                    log "FAILED: $HOME_TEST_MOUNT resolved to mountpoint $mp instead of its own mount"
                    ok=1
                fi
            fi
            if vfs_opts_have "$vfs_opts" ro; then
                log "ok: effective mount for $p is ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
            else
                log "FAILED: effective mount for $p is not ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                ok=1
            fi
        else
            log "FAILED: cannot determine effective mount for $p"
            ok=1
        fi
    done

    if [ -n "$root_mnt_id" ] && [ -n "$home_vol_mnt_id" ] && [ "$home_vol_mnt_id" != "$root_mnt_id" ]; then
        log "ok: $HOME_TEST_MOUNT has distinct ro mount id ($home_vol_mnt_id != root $root_mnt_id)"
    else
        log "FAILED: $HOME_TEST_MOUNT does not have a distinct mount id from / (root=${root_mnt_id:-unset} vol=${home_vol_mnt_id:-unset})"
        ok=1
    fi

    if mountpoint -q /dev/mqueue 2>/dev/null; then
        if info="$(effective_mount_in_ns "$pid" /dev/mqueue)"; then
            read -r mnt_id vfs_opts mp <<<"$info"
            if vfs_opts_have "$vfs_opts" ro; then
                log "ok: effective mount for /dev/mqueue is ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
            else
                log "FAILED: effective mount for /dev/mqueue is not ro (mnt_id=$mnt_id opts=$vfs_opts mp=$mp)"
                ok=1
            fi
        else
            log "FAILED: cannot determine effective mount for /dev/mqueue"
            ok=1
        fi
    fi

    # /run/qeminga must stay writable to uid 600 inside the service namespace
    # using a unique exclusively-created probe file.
    if nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- python3 - <<'PY'
import os, tempfile

fd, path = tempfile.mkstemp(prefix="confinement-probe.", dir="/run/qeminga")
try:
    os.write(fd, b"ok\n")
finally:
    os.close(fd)
    os.unlink(path)
PY
    then
        log "ok: /run/qeminga is writable to uid 600 in service namespace"
    else
        log "FAILED: /run/qeminga is not writable to uid 600 in service namespace"
        ok=1
    fi

    check_sys_power_confinement "$pid" || ok=1
    return "$ok"
}

# Inspect the live isolated parser child of the installed qeminga.service
# (OQ-10 §6 Checks 1-3 in the disposable guest on both x86_64 and aarch64):
# - single-threaded `qeminga-parser` child running as 601:601 with zero caps,
#   NoNewPrivs=1, Seccomp=2 on every thread
# - backing-object fd check: fds 0/1/2 are S_ISCHR(1,3) /dev/null distinct from
#   executor stderr; fd 3 is a Unix socket in both processes; parser holds
#   strictly /dev/null (0/1/2), IPC socket (3), one verified virtio-port char
#   device, and optional epoll/eventfd; executor holds zero virtio-port fds
# - UID 601 DAC confinement inside the service mount namespace against a
#   synthetic 0600 root:root secret, a 0600 qeminga:qeminga file, the
#   virtio-port device, and /run/qeminga.
check_parser_isolation() {
    local pid="$1" ok=0 out=""
    if [ -z "$pid" ] || [ "$pid" = 0 ] || [ ! -r "/proc/$pid/status" ]; then
        log "FAILED: cannot inspect parser isolation for missing executor pid ${pid:-0}"
        return 1
    fi

    if out="$(python3 - "$pid" /dev/virtio-ports/org.qemu.guest_agent.0 <<'PY' 2>&1
import os, stat, sys, time

exec_pid = int(sys.argv[1])
port_path = sys.argv[2]

port_st = os.stat(port_path)
if not stat.S_ISCHR(port_st.st_mode):
    raise RuntimeError(f"{port_path} is not a char device")
port_rdev = (os.major(port_st.st_rdev), os.minor(port_st.st_rdev))

def read_status(path):
    fields = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip()] = " ".join(v.split())
    return fields

def find_children(parent_pid):
    children = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            st = read_status(f"/proc/{entry}/status")
        except OSError:
            continue
        if st.get("PPid") == str(parent_pid):
            children.append((int(entry), st))
    return children

def count_port_fds(target_pid):
    count = 0
    for name in os.listdir(f"/proc/{target_pid}/fd"):
        try:
            st = os.stat(f"/proc/{target_pid}/fd/{name}")
        except OSError:
            continue
        if stat.S_ISCHR(st.st_mode) and (os.major(st.st_rdev), os.minor(st.st_rdev)) == port_rdev:
            count += 1
    return count

deadline = time.monotonic() + 15.0
parser_pid = None
last_diag = "no child found"
while time.monotonic() < deadline:
    kids = find_children(exec_pid)
    if len(kids) == 1:
        cpid, st = kids[0]
        try:
            p_fds = count_port_fds(cpid)
        except OSError:
            p_fds = 0
        if (
            st.get("Name") == "qeminga-parser"
            and st.get("Uid") == "601 601 601 601"
            and st.get("Seccomp") == "2"
            and p_fds == 1
        ):
            parser_pid = cpid
            break
        last_diag = (
            f"child pid={cpid} name={st.get('Name')} uid={st.get('Uid')} "
            f"seccomp={st.get('Seccomp')} port_fds={p_fds}"
        )
    else:
        last_diag = f"found {len(kids)} direct children: {[k[0] for k in kids]}"
    time.sleep(0.2)

if parser_pid is None:
    raise RuntimeError(f"parser child did not settle within 15s ({last_diag})")

# Verify every thread of the parser child.
tasks = sorted(os.listdir(f"/proc/{parser_pid}/task"))
if len(tasks) != 1:
    raise RuntimeError(f"parser has {len(tasks)} threads, expected 1: {tasks}")
for tid in tasks:
    st = read_status(f"/proc/{parser_pid}/task/{tid}/status")
    checks = {
        "Name": "qeminga-parser",
        "Threads": "1",
        "Uid": "601 601 601 601",
        "Gid": "601 601 601 601",
        "CapEff": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapInh": "0000000000000000",
        "CapAmb": "0000000000000000",
        "NoNewPrivs": "1",
        "Seccomp": "2",
    }
    for k, want in checks.items():
        got = st.get(k)
        if got != want:
            raise RuntimeError(f"parser tid {tid} {k}={got!r}, expected {want!r}")

# Verify backing kernel objects of parser and executor descriptors.
exec_stderr = os.stat(f"/proc/{exec_pid}/fd/2")
exec_stderr_id = (exec_stderr.st_dev, exec_stderr.st_ino)
exec_ipc = os.stat(f"/proc/{exec_pid}/fd/3")
if not stat.S_ISSOCK(exec_ipc.st_mode):
    raise RuntimeError("executor fd 3 is not a Unix socket")

seen_ipc = False
channel_fds = 0
for name in sorted(os.listdir(f"/proc/{parser_pid}/fd"), key=int):
    fd_num = int(name)
    fd_path = f"/proc/{parser_pid}/fd/{name}"
    target = os.readlink(fd_path)
    st = os.stat(fd_path)
    if fd_num in (0, 1, 2):
        if not stat.S_ISCHR(st.st_mode) or (os.major(st.st_rdev), os.minor(st.st_rdev)) != (1, 3):
            raise RuntimeError(f"parser fd {fd_num} -> {target} is not /dev/null (1,3)")
        if (st.st_dev, st.st_ino) == exec_stderr_id:
            raise RuntimeError(f"parser fd {fd_num} aliases executor stderr")
    elif fd_num == 3:
        if not stat.S_ISSOCK(st.st_mode) or not target.startswith("socket:["):
            raise RuntimeError(f"parser fd 3 -> {target} is not a Unix socket")
        seen_ipc = True
    elif stat.S_ISCHR(st.st_mode) and (os.major(st.st_rdev), os.minor(st.st_rdev)) == port_rdev:
        channel_fds += 1
    elif target.startswith("anon_inode:[eventpoll]") or target.startswith("anon_inode:[eventfd]"):
        pass
    else:
        raise RuntimeError(f"parser holds unexpected fd {fd_num} -> {target}")

if not seen_ipc:
    raise RuntimeError("parser is missing IPC socket on fd 3")
if channel_fds != 1:
    raise RuntimeError(f"parser holds {channel_fds} virtio-port fds, expected 1")

# Verify executor closed its virtio-port descriptor immediately after handoff.
exec_port_fds = count_port_fds(exec_pid)
if exec_port_fds != 0:
    raise RuntimeError(f"executor still holds {exec_port_fds} virtio-port fd(s)")

print(f"parser pid={parser_pid} uid=601 caps=0 nnp=1 seccomp=2 fds=strict")
PY
    )"; then
        log "ok: parser isolation verified ($out)"
    else
        log "FAILED: parser isolation check failed: $out"
        ok=1
    fi

    # Verify UID 601 DAC and unit-layer read-only mount boundaries inside the
    # service's mount namespace (OQ-10 §6 Checks 2-3):
    # - 0600 root:root secret and 0600 qeminga:qeminga file fail EACCES (DAC)
    # - 0666 world-writable file on /tmp (present at service startup) is
    #   openable O_WRONLY to UID 601 outside the unit, and MUST fail EROFS on
    #   both O_WRONLY open and unlink inside the service's mount namespace.
    local secret_dir uid600_dir secret_file uid600_file world_file
    secret_dir="$(mktemp -d /var/lib/qeminga-parser-probe.XXXXXX)" || {
        log "FAILED: cannot create temp dir under /var/lib"
        return 1
    }
    uid600_dir="$(mktemp -d /tmp/qeminga-parser-probe.XXXXXX)" || {
        rm -rf -- "$secret_dir"
        log "FAILED: cannot create temp dir under /tmp"
        return 1
    }
    secret_file="$secret_dir/root-secret"
    uid600_file="$uid600_dir/uid600-secret"
    world_file="$uid600_dir/world-writable"

    if ! python3 - "$secret_dir" "$uid600_dir" <<'PY'
import os, sys

secret_dir, tmp_dir = sys.argv[1:3]

def make_file(parent, name, uid, gid, mode, data):
    dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
            dir_fd=dfd,
        )
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            os.write(fd, data)
        finally:
            os.close(fd)
    finally:
        os.close(dfd)

make_file(secret_dir, "root-secret", 0, 0, 0o600, b"synthetic-root-secret-oq10\n")
make_file(tmp_dir, "uid600-secret", 600, 600, 0o600, b"untouched-uid600\n")
make_file(tmp_dir, "world-writable", 0, 0, 0o666, b"untouched-world\n")
for d in (secret_dir, tmp_dir):
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fchmod(dfd, 0o755)
    finally:
        os.close(dfd)
PY
    then
        log "FAILED: cannot initialize exclusive parser boundary probe files"
        rm -rf -- "$secret_dir" "$uid600_dir"
        return 1
    fi

    # Outside the service namespace, UID 601 MUST be able to open the 0666 file
    # O_WRONLY (zero bytes written), establishing that DAC does not mask EROFS.
    if out="$(setpriv --reuid 601 --regid 601 --clear-groups -- python3 - "$world_file" <<'PY' 2>&1
import os, sys

fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CLOEXEC)
os.close(fd)
print("world-writable O_WRONLY allowed outside unit")
PY
    )"; then
        log "ok: parser UID 601 outside-unit baseline verified ($out)"
    else
        log "FAILED: parser UID 601 could not open 0666 fixture outside unit: $out"
        ok=1
    fi

    if out="$(nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 601 --regid 601 --clear-groups -- python3 - "$secret_file" "$uid600_file" "$world_file" /dev/virtio-ports/org.qemu.guest_agent.0 /run/qeminga <<'PY' 2>&1
import errno, os, sys

secret_file, uid600_file, world_file, port_path, run_dir = sys.argv[1:6]

def expect_err(label, path, flags, want):
    try:
        fd = os.open(path, flags | os.O_CLOEXEC)
    except OSError as exc:
        if exc.errno != want:
            want_name = errno.errorcode.get(want, str(want))
            got = errno.errorcode.get(exc.errno, str(exc.errno))
            raise RuntimeError(f"{label}: got {got}, expected {want_name}")
    else:
        os.close(fd)
        raise RuntimeError(f"{label}: unexpectedly succeeded as uid 601")

expect_err("root-secret rdonly", secret_file, os.O_RDONLY, errno.EACCES)
expect_err("uid600-file rdonly", uid600_file, os.O_RDONLY, errno.EACCES)
expect_err("world-file wronly", world_file, os.O_WRONLY, errno.EROFS)
try:
    os.unlink(world_file)
except OSError as exc:
    if exc.errno != errno.EROFS:
        got = errno.errorcode.get(exc.errno, str(exc.errno))
        raise RuntimeError(f"world-file unlink: got {got}, expected EROFS")
else:
    raise RuntimeError("world-file unlink unexpectedly succeeded as uid 601")
expect_err("virtio-port rdwr", port_path, os.O_RDWR, errno.EACCES)
expect_err("/run/qeminga dir", run_dir, os.O_RDONLY | os.O_DIRECTORY, errno.EACCES)
print("uid601 denied root-secret/uid600-file/virtio-port/run (EACCES) and world-file write/unlink (EROFS)")
PY
    )"; then
        log "ok: parser UID 601 DAC and unit-layer EROFS boundary verified ($out)"
    else
        log "FAILED: parser UID 601 boundary probe failed: $out"
        ok=1
    fi

    if [ "$(cat "$secret_file")" != "synthetic-root-secret-oq10" ] \
        || [ "$(cat "$uid600_file")" != "untouched-uid600" ] \
        || [ "$(cat "$world_file")" != "untouched-world" ]; then
        log "FAILED: parser boundary probe fixtures were modified"
        ok=1
    fi
    rm -rf -- "$secret_dir" "$uid600_dir"
    return "$ok"
}

# shellcheck disable=SC1091
log "guest $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
verdict=FAIL
if install_candidate && check_production_state; then verdict=PASS; fi
journalctl -u qeminga.service -b --no-pager -n 40 -o cat 2>&1 | sed 's/^/qeminga-e2e-journal: /'
log "RESULT $verdict"
