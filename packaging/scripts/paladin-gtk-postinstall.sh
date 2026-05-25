#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# paladin-gtk postinstall scriptlet (.deb and .rpm).
#
# Refresh the two system-owned freedesktop caches that the newly
# installed payload depends on:
#
#   * /usr/share/applications/mimeinfo.cache  — populated by
#     `update-desktop-database` so the desktop entry installed at
#     /usr/share/applications/org.tamx.Paladin.Gui.desktop becomes
#     visible to GNOME Shell, KDE, XFCE, MATE, and any other
#     freedesktop-aware launcher without requiring the user to log
#     out and back in.
#   * /usr/share/icons/hicolor/icon-theme.cache — populated by
#     `gtk-update-icon-cache` so the hicolor PNG / SVG icons under
#     /usr/share/icons/hicolor/<size>/apps/ resolve to the icon name
#     org.tamx.Paladin.Gui (referenced from both the .desktop entry
#     and the AppStream metainfo).
#
# Security posture (pinned by
# crates/paladin-gtk/tests/packaging_deb_nfpm_manifest_logic.rs and
# crates/paladin-gtk/tests/packaging_rpm_nfpm_manifest_logic.rs):
#
#   * Touches ONLY paths under /usr/share. No user-home or
#     $XDG_* path is read or written. The user vault under
#     $XDG_DATA_HOME/paladin/ is never created or altered by
#     package install / removal — that contract from DESIGN.md
#     §11.3 still holds.
#   * No network calls (no curl, wget, nc, ssh, …).
#   * Fail-soft on missing helpers: `command -v` gates each
#     invocation so a minimal image without
#     `desktop-file-utils` or `gtk-update-icon-cache` installed
#     still completes the package transaction.
#   * `|| :` swallows non-zero exits from the helpers themselves
#     so a transient cache-rebuild error does not abort the
#     install — the next package transaction will retry.
#
# Sourced verbatim into the .deb (control.tar.gz) and the .rpm
# (header scripts) by nfpm at build time; both packaging formats
# reference this same file so a bug fix lands in both at once.

set -e

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || :
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -qtf /usr/share/icons/hicolor || :
fi

exit 0
