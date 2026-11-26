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
log() { printf 'qeminga-e2e-guest: %s\n' "$*"; }

install_candidate() {
    log "install: masking qemu-guest-agent"
    systemctl mask --now qemu-guest-agent.service || return 1
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
    local pid="$1" ok=0 p info mnt_id vfs_opts mp

    check_ro_dir_confinement "$pid" /var/tmp "/var/tmp" || ok=1
    check_ro_dir_confinement "$pid" /home "/home" || ok=1
    check_ro_dir_confinement "$pid" /run "/run" || ok=1
    check_ro_dir_confinement "$pid" /dev/shm "/dev/shm" || ok=1

    for p in / /run /home; do
        if info="$(effective_mount_in_ns "$pid" "$p")"; then
            read -r mnt_id vfs_opts mp <<<"$info"
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

# shellcheck disable=SC1091
log "guest $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
verdict=FAIL
if install_candidate && check_production_state; then verdict=PASS; fi
journalctl -u qeminga.service -b --no-pager -n 40 -o cat 2>&1 | sed 's/^/qeminga-e2e-journal: /'
log "RESULT $verdict"
