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
    return "$ok"
}

# shellcheck disable=SC1091
log "guest $(uname -srm); $(. /etc/os-release && echo "$PRETTY_NAME")"
verdict=FAIL
if install_candidate && check_production_state; then verdict=PASS; fi
journalctl -u qeminga.service -b --no-pager -n 40 -o cat 2>&1 | sed 's/^/qeminga-e2e-journal: /'
log "RESULT $verdict"
