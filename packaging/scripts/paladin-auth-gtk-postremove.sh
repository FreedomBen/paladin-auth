#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# paladin-auth-gtk postremove scriptlet (.deb and .rpm).
#
# Refresh the same two system-owned freedesktop caches the
# postinstall scriptlet rebuilds, so an `apt remove` / `dnf
# remove` of paladin-auth-gtk leaves the launcher in a clean state:
# the stale "Paladin Auth" entry disappears from the app drawer
# immediately rather than persisting until the next unrelated
# package transaction triggers a refresh.
#
# Security posture matches paladin-auth-gtk-postinstall.sh — see the
# header there for the full pinned-properties list. In short:
# touches only /usr/share, no $HOME / $XDG_* / user-vault paths,
# no network calls, fail-soft on missing helpers.

set -e

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || :
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -qtf /usr/share/icons/hicolor || :
fi

exit 0
