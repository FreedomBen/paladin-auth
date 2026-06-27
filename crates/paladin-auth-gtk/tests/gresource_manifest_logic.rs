// SPDX-License-Identifier: AGPL-3.0-or-later

//! Gresource manifest contract tests for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop integration" /
//! §"Crate layout" and the Milestone 7 checklist entry "Wire
//! `build.rs` + `data/paladin-auth-gtk.gresource.xml` to compile the
//! gresource bundle deterministically via `glib-compile-resources`
//! (fixed input order)".
//!
//! The gresource bundle is compiled by `build.rs` from
//! `data/paladin-auth-gtk.gresource.xml`. The XML manifest declares each
//! payload explicitly (no glob patterns) so the input order is
//! deterministic — `glib-compile-resources` writes the entries to
//! the binary bundle in the same order they appear in the manifest.
//!
//! These assertions live as pure-logic tests against the manifest XML
//! so a future regression that drops a payload, breaks the resource
//! prefix, or trades the deterministic explicit-listing pattern for a
//! glob fails CI immediately, independent of the GTK runtime.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use paladin_auth_gtk::APP_ID;

/// Path to the gresource manifest, relative to the crate root.
const MANIFEST_RELPATH: &str = "data/paladin-auth-gtk.gresource.xml";

/// Build script path, relative to the crate root.
const BUILD_SCRIPT_RELPATH: &str = "build.rs";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_manifest() -> String {
    let path = crate_root().join(MANIFEST_RELPATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_build_script() -> String {
    let path = crate_root().join(BUILD_SCRIPT_RELPATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

/// Return the trimmed text values of every `alias` attribute on
/// `<file>` entries in the manifest. The XML is regular enough that a
/// substring scan suffices — every entry is shaped as
/// `<file compressed="true" alias="…">…</file>` so a future drift to a
/// non-aliased entry would surface here as a missing alias.
fn manifest_aliases(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let needle = "alias=\"";
    let mut cursor = 0;
    while let Some(found) = manifest[cursor..].find(needle) {
        let start = cursor + found + needle.len();
        let end = manifest[start..]
            .find('"')
            .map(|idx| start + idx)
            .expect("`alias=\"...\"` is closed by a matching quote");
        out.push(manifest[start..end].to_owned());
        cursor = end + 1;
    }
    out
}

// --- Existence + basic shape -------------------------------------------------

#[test]
fn manifest_exists_at_expected_path() {
    let path = crate_root().join(MANIFEST_RELPATH);
    assert!(
        path.is_file(),
        "expected gresource manifest at {}",
        path.display(),
    );
}

#[test]
fn manifest_carries_spdx_header() {
    let manifest = read_manifest();
    assert!(
        manifest.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
        "gresource manifest must carry the AGPL-3.0-or-later SPDX header",
    );
}

#[test]
fn manifest_prefix_matches_app_id_reverse_dns_path() {
    let manifest = read_manifest();
    // The §"Crate layout" section pins the resource pool prefix to
    // `/org/tamx/PaladinAuth/Gui` (APP_ID split on `.`). Anything inside
    // the bundle resolves at runtime under `/org/tamx/PaladinAuth/Gui/…`.
    let expected = format!("prefix=\"/{}\"", APP_ID.replace('.', "/"));
    assert!(
        manifest.contains(&expected),
        "manifest must declare {expected} as the <gresource> prefix",
    );
}

#[test]
fn manifest_uses_explicit_file_entries_not_globs() {
    let manifest = read_manifest();
    // glib-compile-resources accepts a `*-prefix` glob form via
    // <file>...</file> elements, but `glob` patterns would make the
    // bundle's payload order depend on filesystem walk order — i.e.,
    // a non-reproducible build. Reject glob characters in any alias /
    // path entry so the deterministic-input-order property the plan
    // requires can never silently regress.
    let aliases = manifest_aliases(&manifest);
    for alias in &aliases {
        assert!(
            !alias.contains('*') && !alias.contains('?'),
            "manifest aliases must be literal paths (no globs): {alias:?}",
        );
    }
}

#[test]
fn manifest_aliases_are_unique() {
    let manifest = read_manifest();
    let aliases = manifest_aliases(&manifest);
    let mut seen = HashSet::new();
    for alias in &aliases {
        assert!(
            seen.insert(alias.clone()),
            "manifest alias {alias:?} appears more than once — gresource compiler would silently keep the last entry, breaking deterministic lookup",
        );
    }
}

// --- Required payloads -------------------------------------------------------

#[test]
fn manifest_carries_app_stylesheet_entry() {
    let manifest = read_manifest();
    assert!(
        manifest.contains("alias=\"style.css\""),
        "manifest must bundle style.css for wire_app_css_provider",
    );
}

#[test]
fn manifest_carries_placeholder_icon_entry() {
    let manifest = read_manifest();
    // `crate::icon_resolution::PLACEHOLDER_ICON_NAME` is
    // `dialog-password-symbolic`; the freedesktop directory layout
    // pins it under `icons/scalable/actions/<name>.svg` so
    // `gtk::IconTheme::add_resource_path` discovers it via the
    // standard hicolor walk.
    assert!(
        manifest.contains("alias=\"icons/scalable/actions/dialog-password-symbolic.svg\""),
        "manifest must bundle the dialog-password-symbolic placeholder icon",
    );
}

#[test]
fn manifest_carries_license_text_entry() {
    let manifest = read_manifest();
    // `format_app_about_dialog_license_resource_path` resolves to
    // `/<APP_ID-prefix>/LICENSE`; the workspace `LICENSE` file ships
    // through here so the about dialog's bundled body and the
    // `include_str!` body in `format_app_about_dialog_license_text`
    // share the same on-disk source of truth.
    assert!(
        manifest.contains("alias=\"LICENSE\""),
        "manifest must bundle the workspace LICENSE under the app prefix",
    );
}

#[test]
fn manifest_carries_app_icon_entries_for_in_app_lookup() {
    let manifest = read_manifest();
    // Bundle the app icon (and its symbolic) so the in-app
    // `gtk::IconTheme::for_display(...).lookup_icon(APP_ID, ...)`
    // resolves even when the system hicolor theme has not yet
    // indexed the freshly installed PNGs (notably during `cargo
    // run`, the `xvfb-run` smoke test, and Flatpak sandboxes
    // whose runtime theme omits the package). The freedesktop
    // `add_resource_path` walks `<root>/scalable/apps/<name>.svg`
    // and `<root>/symbolic/apps/<name>-symbolic.svg`, so the
    // gresource aliases mirror that layout exactly.
    assert!(
        manifest.contains(&format!("alias=\"icons/scalable/apps/{APP_ID}.svg\"")),
        "manifest must bundle the scalable app icon under icons/scalable/apps/",
    );
    assert!(
        manifest.contains(&format!(
            "alias=\"icons/symbolic/apps/{APP_ID}-symbolic.svg\""
        )),
        "manifest must bundle the symbolic app icon under icons/symbolic/apps/",
    );
}

#[test]
fn manifest_file_entries_are_compressed() {
    let manifest = read_manifest();
    // Every `<file>` entry should set `compressed="true"`. The
    // payload is shipped in the binary; compression keeps the bundle
    // size down without changing the deterministic write order (the
    // compressor runs per-entry and the entries are still written in
    // manifest order).
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<file") {
            assert!(
                trimmed.contains("compressed=\"true\""),
                "every <file> entry must set compressed=\"true\" for a compact bundle: {trimmed:?}",
            );
        }
    }
}

// --- Build-script wiring -----------------------------------------------------

#[test]
fn build_script_invokes_glib_compile_resources_against_manifest() {
    let build_script = read_build_script();
    assert!(
        build_script.contains("compile_resources"),
        "build.rs must invoke glib_build_tools::compile_resources to pack the manifest into a deterministic gresource bundle",
    );
    assert!(
        build_script.contains("data/paladin-auth-gtk.gresource.xml"),
        "build.rs must reference the gresource manifest by path",
    );
}

#[test]
fn build_script_tracks_workspace_license_for_rerun() {
    let build_script = read_build_script();
    // The workspace LICENSE feeds the bundled license body. Pin the
    // `cargo:rerun-if-changed` directive so a future LICENSE edit
    // forces a rebuild and the bundled body stays in lockstep with
    // the on-disk source of truth.
    assert!(
        build_script.contains("cargo:rerun-if-changed=../../LICENSE"),
        "build.rs must declare cargo:rerun-if-changed=../../LICENSE so a LICENSE edit re-runs the build script",
    );
}

#[test]
fn build_script_declares_workspace_root_as_secondary_source_dir() {
    let build_script = read_build_script();
    // `compile_resources` first sourcedir is `data`; the second
    // sourcedir is `../..` (the workspace root) so the manifest's
    // `LICENSE` alias resolves against the repo-root LICENSE file
    // without a duplicate copy under `data/`.
    assert!(
        build_script.contains("\"data\", \"../..\"") || build_script.contains("\"data\",\"../..\""),
        "build.rs must declare both `data` and the workspace-root sourcedir to compile_resources",
    );
}
