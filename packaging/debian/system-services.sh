#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
# Helper for the AnonyHost package. AnonyHost runs its own private tor and nginx, so the distribution's
# tor and nginx *services* are not needed. This switches them off, but only when nobody has configured
# them (still the stock configuration), and switches them back on when AnonyHost is removed.
# DPKG_ROOT / ANONYHOST_ROOT allow running against another root directory (used by the tests).
ROOT="${ANONYHOST_ROOT:-${DPKG_ROOT:-}}"
STATE="$ROOT/var/lib/anonyhost/disabled-services"
KEEP="$ROOT/etc/anonyhost/keep-system-services"

have_systemd() { [ -n "${ANONYHOST_FORCE_SYSTEMD:-}" ] || [ -d "$ROOT/run/systemd/system" ]; }

# md5sum of a configuration file as its package shipped it (empty when unknown)
shipped_md5() {
    dpkg-query -W -f='${Conffiles}\n' 2>/dev/null | awk -v f="$1" '$1 == f { print $2; exit }'
}

# true when the file still equals the packaged version
unmodified() {
    [ -f "$ROOT$1" ] || return 1
    want="$(shipped_md5 "$1")"
    [ -n "$want" ] || return 1
    have="$(md5sum "$ROOT$1" | awk '{ print $1 }')"
    [ "$have" = "$want" ]
}

tor_is_default() { unmodified /etc/tor/torrc; }

nginx_is_default() {
    unmodified /etc/nginx/nginx.conf || return 1
    unmodified /etc/nginx/sites-available/default || return 1
    for f in "$ROOT"/etc/nginx/sites-enabled/*; do          # only the stock "default" site may be enabled
        { [ -e "$f" ] || [ -L "$f" ]; } || continue
        [ "$(basename "$f")" = default ] || return 1
    done
    for f in "$ROOT"/etc/nginx/conf.d/*.conf "$ROOT"/etc/nginx/streams-enabled/*; do
        [ -e "$f" ] && return 1
    done
    return 0
}

disable_unit() {
    if systemctl is-enabled --quiet "$1" 2>/dev/null || systemctl is-active --quiet "$1" 2>/dev/null; then
        if systemctl disable --now "$1" >/dev/null 2>&1; then
            echo "$1" >> "$STATE"
            echo "anonyhost: switched off the unused system service $1 (AnonyHost runs its own)."
        fi
    fi
    return 0
}

disable_defaults() {
    have_systemd || return 0
    [ -e "$KEEP" ] && return 0
    [ -e "$STATE" ] && return 0                              # decided on an earlier install: never touch twice
    mkdir -p "$(dirname "$STATE")" || return 0
    : > "$STATE"
    if tor_is_default; then
        disable_unit tor.service
        disable_unit tor@default.service
    fi
    if nginx_is_default; then
        disable_unit nginx.service
    fi
    return 0
}

restore_services() {
    if [ -s "$STATE" ] && have_systemd; then
        while read -r unit; do
            [ -n "$unit" ] || continue
            systemctl enable --now "$unit" >/dev/null 2>&1 || true
        done < "$STATE"
    fi
    rm -f "$STATE"
    return 0
}
