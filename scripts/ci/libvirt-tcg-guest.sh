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
    local pid="" uid nnp seccomp
    for _ in $(seq 1 60); do
        if systemctl is-active --quiet qeminga.service; then
            pid="$(systemctl show -p MainPID --value qeminga.service)"
            if [ -n "$pid" ] && [ "$pid" != 0 ] && [ -r "/proc/$pid/status" ]; then
                uid="$(status_field "$pid" Uid)"
                nnp="$(status_field "$pid" NoNewPrivs)"
                seccomp="$(status_field "$pid" Seccomp)"
                if [ "$uid" = "600 600 600 600" ] && [ "$nnp" = 1 ] && [ "$seccomp" = 2 ]; then
                    break
                fi
            fi
        fi
        sleep 1
    done
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

mount_is_ro() {
    awk -v target="$2" '
        $5 == target {
            n = split($6, opts, ",")
            found = 0
            for (i = 1; i <= n; i++) if (opts[i] == "ro") found = 1
            last = found
        }
        END { exit(last == 1 ? 0 : 1) }
    ' "/proc/$1/mountinfo"
}

check_write_confinement() {
    local pid="$1" ok=0 probe=/var/tmp/qeminga-confinement-probe
    local shm_probe=/dev/shm/qeminga-confinement-probe
    local marker_probe=/run/qeminga/confinement-probe
    local err=""

    rm -f "$probe" "$shm_probe" "$marker_probe"
    printf 'intact\n' > "$probe" || { log "FAILED: cannot create $probe"; return 1; }
    chown qeminga:qeminga "$probe" || { rm -f "$probe"; return 1; }
    chmod 0600 "$probe" || { rm -f "$probe"; return 1; }

    # Confirm normal Unix permissions grant UID 600 write access outside the
    # service's mount namespace.
    # shellcheck disable=SC2016 # $1 is expanded by the inner /bin/sh
    if setpriv --reuid 600 --regid 600 --clear-groups -- /bin/sh -c 'printf "intact\n" > "$1"' _ "$probe"; then
        log "ok: $probe is writable to uid 600 outside qeminga.service"
    else
        log "FAILED: $probe was not writable to uid 600 outside confinement"
        ok=1
    fi

    # Inside qeminga.service's mount namespace, writing or unlinking the
    # UID-600-owned file outside /run/qeminga must fail with EROFS.
    # shellcheck disable=SC2016 # $1 is expanded by the inner /bin/sh
    if err="$(LC_ALL=C nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- /bin/sh -c 'printf "tampered\n" > "$1"' _ "$probe" 2>&1)"; then
        log "FAILED: uid 600 wrote $probe inside qeminga.service mount namespace"
        ok=1
    elif printf '%s\n' "$err" | grep -Fq 'Read-only file system'; then
        log "ok: write to $probe denied with EROFS in service namespace ($err)"
    else
        log "FAILED: write to $probe failed without EROFS ($err)"
        ok=1
    fi
    if err="$(LC_ALL=C nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- /bin/rm -- "$probe" 2>&1)"; then
        log "FAILED: uid 600 unlinked $probe inside qeminga.service mount namespace"
        ok=1
    elif printf '%s\n' "$err" | grep -Fq 'Read-only file system'; then
        log "ok: unlink of $probe denied with EROFS in service namespace ($err)"
    else
        log "FAILED: unlink of $probe failed without EROFS ($err)"
        ok=1
    fi
    if [ -f "$probe" ] && [ "$(cat "$probe")" = "intact" ]; then
        log "ok: $probe remained intact"
    else
        log "FAILED: $probe was modified or removed"
        ok=1
    fi

    # /dev/shm must also be read-only inside the service namespace.
    # shellcheck disable=SC2016 # $1 is expanded by the inner /bin/sh
    if err="$(LC_ALL=C nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- /bin/sh -c ': > "$1"' _ "$shm_probe" 2>&1)"; then
        log "FAILED: uid 600 created $shm_probe inside qeminga.service mount namespace"
        ok=1
    elif printf '%s\n' "$err" | grep -Fq 'Read-only file system'; then
        log "ok: write to /dev/shm denied with EROFS in service namespace ($err)"
    else
        log "FAILED: write to /dev/shm failed without EROFS ($err)"
        ok=1
    fi

    # / and /sys must be mounted read-only in the service namespace.
    if mount_is_ro "$pid" /; then log "ok: / is mounted ro in service namespace"
    else log "FAILED: / is not mounted ro in service namespace"; ok=1; fi
    if mount_is_ro "$pid" /sys; then log "ok: /sys is mounted ro in service namespace"
    else log "FAILED: /sys is not mounted ro in service namespace"; ok=1; fi

    # /run/qeminga must stay writable to uid 600 inside the service namespace.
    # shellcheck disable=SC2016 # $1 is expanded by the inner /bin/sh
    if nsenter --mount="/proc/$pid/ns/mnt" -- setpriv --reuid 600 --regid 600 --clear-groups -- /bin/sh -c ': > "$1" && rm -f "$1"' _ "$marker_probe"; then
        log "ok: /run/qeminga is writable to uid 600 in service namespace"
    else
        log "FAILED: /run/qeminga is not writable to uid 600 in service namespace"
        ok=1
    fi

    rm -f "$probe" "$shm_probe" "$marker_probe"
    return "$ok"
}

# shellcheck disable=SC1091
log "guest $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
verdict=FAIL
if install_candidate && check_production_state; then verdict=PASS; fi
journalctl -u qeminga.service -b --no-pager -n 40 -o cat 2>&1 | sed 's/^/qeminga-e2e-journal: /'
log "RESULT $verdict"
