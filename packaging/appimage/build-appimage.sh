#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# AppImage assembly script for paladin-gtk.
#
# Per docs/IMPLEMENTATION_PLAN_04_GTK.md §11.5, this script wraps
# linuxdeploy + linuxdeploy-plugin-gtk to bundle the GTK4 runtime
# pieces (modules, GSettings schemas, gdk-pixbuf loaders) inside the
# resulting AppImage so the artifact runs on a host whose GTK theme
# or pixbuf loader set is older than the bundled binary requires.
#
# Inputs (env vars):
#   PALADIN_VERSION    Required. Release-tag-derived semver the release
#                      pipeline injects, matching the workspace
#                      [workspace.package].version. Drives the output
#                      filename and ${OUTPUT}'s version slot.
#   SOURCE_DATE_EPOCH  Optional. Release-tag-derived Unix timestamp
#                      (docs/DESIGN.md §11.6 "Reproducible builds"). When
#                      set, the script exports it so the cargo build,
#                      linuxdeploy, linuxdeploy-plugin-gtk, and the
#                      mksquashfs step appimagetool invokes all see
#                      it — which is what makes successive runs of
#                      the same tag produce byte-identical .AppImage
#                      output. The release pipeline injects it from
#                      `git log -1 --format=%ct ${tag}`; local dry
#                      runs may leave it unset (the resulting
#                      .AppImage is then unreproducible but
#                      otherwise correct).
#
# Inputs (CLI):
#   none. The release artifact paths are computed from
#   ${WORKSPACE_ROOT} which is resolved relative to this script.
#
# Outputs:
#   paladin-gtk-${PALADIN_VERSION}-x86_64.AppImage  in the current
#   working directory, with embedded zsync update info pointing at
#   the GitHub Releases feed (gh-releases-zsync|FreedomBen|paladin
#   |latest|paladin-gtk-*-x86_64.AppImage.zsync).
#
# Dependencies (must be on $PATH):
#   linuxdeploy
#   linuxdeploy-plugin-gtk
#   install   (coreutils)
#   cargo     (only if you have not already run `cargo build --release
#              --locked -p paladin-gtk` separately; the script will
#              run it for you if the release binary is missing)
#
# Contract pinned by
#   crates/paladin-gtk/tests/packaging_appimage_build_script_logic.rs

set -euo pipefail

# Bail loudly if PALADIN_VERSION is not provided. The release
# pipeline always injects it; a local run must do so explicitly
# rather than producing `paladin-gtk--x86_64.AppImage`.
: "${PALADIN_VERSION:?PALADIN_VERSION must be set to the release version}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${WORKSPACE_ROOT}"

# Export SOURCE_DATE_EPOCH (if set by the release pipeline) so every
# subprocess this script spawns — cargo build, linuxdeploy,
# linuxdeploy-plugin-gtk, and the mksquashfs step appimagetool invokes
# transitively — embeds the same tag-timestamp instead of wall-clock
# `now`. That is what docs/DESIGN.md §11.6 "Reproducible builds" relies on
# to guarantee byte-identical AppImage output across re-runs of the
# same tag. Pinned by
# crates/paladin-gtk/tests/packaging_reproducible_build_logic.rs::appimage_script_exports_source_date_epoch_for_linuxdeploy_subprocess.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  export SOURCE_DATE_EPOCH
fi

# Build the release binary if it is not already present. The release
# pipeline ordinarily runs `cargo build --release --locked` ahead of
# this step; this fallback keeps the script self-contained for local
# packaging dry-runs.
RELEASE_BIN="${WORKSPACE_ROOT}/target/release/paladin-gtk"
if [ ! -x "${RELEASE_BIN}" ]; then
  cargo build --release --locked -p paladin-gtk
fi

# Stage a fresh AppDir under target/appimage/ so repeated runs do
# not accumulate stale icons / metainfo across rebuilds.
APPDIR="${WORKSPACE_ROOT}/target/appimage/paladin-gtk.AppDir"
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}"

# Pre-stage data files that linuxdeploy itself does not relocate —
# the AppStream metainfo and the additional hicolor sizes beyond
# the one passed via --icon-file. linuxdeploy bundles --desktop-file
# and --icon-file automatically.
install -Dm644 \
  "${WORKSPACE_ROOT}/crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml" \
  "${APPDIR}/usr/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml"

# Stage the full hicolor icon set so the AppImage's icon-theme lookup
# resolves at every size the desktop launcher might request, not just
# the single --icon-file linuxdeploy receives.
install -Dm644 \
  "${WORKSPACE_ROOT}/crates/paladin-gtk/data/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg" \
  "${APPDIR}/usr/share/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg"
install -Dm644 \
  "${WORKSPACE_ROOT}/crates/paladin-gtk/data/icons/hicolor/16x16/apps/org.tamx.Paladin.Gui.png" \
  "${APPDIR}/usr/share/icons/hicolor/16x16/apps/org.tamx.Paladin.Gui.png"
install -Dm644 \
  "${WORKSPACE_ROOT}/crates/paladin-gtk/data/icons/hicolor/24x24/apps/org.tamx.Paladin.Gui.png" \
  "${APPDIR}/usr/share/icons/hicolor/24x24/apps/org.tamx.Paladin.Gui.png"
install -Dm644 \
  "${WORKSPACE_ROOT}/crates/paladin-gtk/data/icons/hicolor/32x32/apps/org.tamx.Paladin.Gui.png" \
  "${APPDIR}/usr/share/icons/hicolor/32x32/apps/org.tamx.Paladin.Gui.png"
install -Dm644 \
  "${WORKSPACE_ROOT}/crates/paladin-gtk/data/icons/hicolor/48x48/apps/org.tamx.Paladin.Gui.png" \
  "${APPDIR}/usr/share/icons/hicolor/48x48/apps/org.tamx.Paladin.Gui.png"

# linuxdeploy-plugin-gtk reads these to copy GTK runtime files into
# the AppDir. Pinned by the contract test
# `appimage_script_invokes_linuxdeploy_with_gtk_plugin`.
export OUTPUT="paladin-gtk-${PALADIN_VERSION}-x86_64.AppImage"

# Embedded AppImageUpdate metadata. AppImageUpdate (and the
# zsync-aware `AppImageUpdate.AppImage` tool) reads this string from
# the produced AppImage and uses it to delta-fetch the next release
# from GitHub Releases. The literal `paladin-gtk-*-x86_64.AppImage.zsync`
# wildcard matches any future version-tagged artifact published to
# the same release asset namespace.
export UPDATE_INFORMATION="gh-releases-zsync|FreedomBen|paladin|latest|paladin-gtk-*-x86_64.AppImage.zsync"

# Pin the AppImage target architecture explicitly. linuxdeploy
# normally infers it from the staged binary, but Milestone 7
# §11.5 ships an x86_64-only artifact for v0.2, so we hard-code
# the value here and let any future cross-build need land in a
# follow-up plan update.
export ARCH=x86_64

linuxdeploy \
  --appdir "${APPDIR}" \
  --desktop-file "${WORKSPACE_ROOT}/crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop" \
  --icon-file "${WORKSPACE_ROOT}/crates/paladin-gtk/data/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg" \
  --executable "${RELEASE_BIN}" \
  --plugin gtk \
  --output appimage

echo "AppImage assembled: ${OUTPUT}"
