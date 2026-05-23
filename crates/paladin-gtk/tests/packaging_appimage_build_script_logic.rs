// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppImage` assembly script contract tests for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §11.5 and the Milestone 7
//! packaging checklist entry "Wire `AppImage` assembly via
//! `linuxdeploy` + `linuxdeploy-plugin-gtk`":
//!
//! * Lives at `packaging/appimage/build-appimage.sh`.
//! * Has the executable bit set (so a checkout-and-run path is
//!   `./packaging/appimage/build-appimage.sh`, mirroring the
//!   `chmod +x` convention CI scripts in this repo follow).
//! * Sets the strict shell mode `set -euo pipefail` so a missing
//!   dependency, an undefined variable, or a failed `linuxdeploy`
//!   step aborts the build immediately rather than producing a
//!   half-staged `AppImage`.
//! * Invokes `linuxdeploy` with `--plugin gtk` so
//!   `linuxdeploy-plugin-gtk` bundles GTK4 modules, `GSettings`
//!   schemas, and `gdk-pixbuf` loaders inside the `AppDir`. Without
//!   the GTK plugin the `AppImage` would launch on a host whose GTK
//!   theme / pixbuf loaders mismatch the bundled binary's
//!   expectations.
//! * Stages the freedesktop `.desktop` entry, the scalable app
//!   icon, the binary, and the `AppStream` metainfo into the
//!   `AppDir`. These map onto the same source files the `.deb` /
//!   `.rpm` / Flatpak manifests already install.
//! * Writes the output as
//!   `paladin-gtk-${PALADIN_VERSION}-x86_64.AppImage` (the
//!   §11.5 artifact name shape).
//! * Carries the `UPDATE_INFORMATION` env var with the
//!   `gh-releases-zsync|FreedomBen|paladin|latest|paladin-gtk-*-x86_64.AppImage.zsync`
//!   value so the resulting `AppImage` embeds the `GitHub` Releases
//!   `zsync` pointer per §11.5.
//! * Reads `PALADIN_VERSION` from the environment (the release
//!   pipeline injects it from the tag; the script never invents
//!   a version, so a stray local run that forgets to set it
//!   fails loudly instead of writing `paladin-gtk--x86_64.AppImage`).
//!
//! Tests intentionally read the script as plain text so the
//! contract is auditable in CI without `linuxdeploy` itself being
//! installed on the runner.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Path to the `AppImage` build script, relative to the workspace root.
const APPIMAGE_SCRIPT_RELPATH: &str = "packaging/appimage/build-appimage.sh";

/// Required `linuxdeploy` invocation tokens. Each MUST appear in the
/// script body somewhere on the same logical command (joined across
/// continuation lines by the parser below).
const REQUIRED_LINUXDEPLOY_TOKENS: &[&str] = &[
    "linuxdeploy",
    "--appdir",
    "--desktop-file",
    "--icon-file",
    "--executable",
    "--plugin gtk",
    "--output appimage",
];

/// Required in-tree references the script must stage into the `AppDir`.
/// These mirror the `.deb` / `.rpm` install layouts so `AppImage` users
/// get the same data files at runtime as native-package users do.
const REQUIRED_IN_TREE_REFERENCES: &[&str] = &[
    "crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop",
    "crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml",
    "crates/paladin-gtk/data/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg",
];

/// The expected `UPDATE_INFORMATION` value. Pinned by literal so a
/// future repository move (e.g. `FreedomBen` → an org) requires an
/// explicit edit here, not a silent drift in the `AppImage`'s update
/// pointer.
const EXPECTED_UPDATE_INFORMATION: &str =
    "gh-releases-zsync|FreedomBen|paladin|latest|paladin-gtk-*-x86_64.AppImage.zsync";

/// The expected output-filename shape (template, not literal —
/// `${PALADIN_VERSION}` is substituted by the script at run time).
const EXPECTED_OUTPUT_NAME: &str = "paladin-gtk-${PALADIN_VERSION}-x86_64.AppImage";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_root()
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| panic!("crate_root has no grandparent: {}", crate_root().display()))
        .to_path_buf()
}

fn appimage_script_path() -> PathBuf {
    workspace_root().join(APPIMAGE_SCRIPT_RELPATH)
}

fn read_appimage_script() -> String {
    fs::read_to_string(appimage_script_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", appimage_script_path().display()))
}

/// Join shell continuation lines (`\\\n`) so a multi-line
/// `linuxdeploy` invocation becomes one searchable string. Returns
/// the joined script body.
fn join_continuations(script: &str) -> String {
    let mut out = String::with_capacity(script.len());
    let lines: Vec<&str> = script.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(without_slash) = line.strip_suffix('\\') {
            out.push_str(without_slash);
            out.push(' ');
            i += 1;
            continue;
        }
        out.push_str(line);
        out.push('\n');
        i += 1;
    }
    out
}

// --- tests -------------------------------------------------------------------

#[test]
fn appimage_script_exists_at_expected_path() {
    let path = appimage_script_path();
    assert!(
        path.is_file(),
        "expected AppImage build script at {} — Milestone 7 packaging \
         checklist requires `packaging/appimage/build-appimage.sh`",
        path.display(),
    );
}

#[test]
fn appimage_script_is_executable() {
    let path = appimage_script_path();
    let metadata =
        fs::metadata(&path).unwrap_or_else(|err| panic!("stat {}: {err}", path.display()));
    let mode = metadata.permissions().mode();
    // owner-execute bit (0o100) at minimum — checkout-and-run is the
    // shape every other build script in this repo follows.
    assert!(
        mode & 0o100 != 0,
        "AppImage build script at {} must have the executable bit set \
         (current mode: {:o})",
        path.display(),
        mode & 0o777,
    );
}

#[test]
fn appimage_script_starts_with_bash_shebang() {
    let script = read_appimage_script();
    let first_line = script.lines().next().unwrap_or("");
    assert!(
        first_line == "#!/usr/bin/env bash" || first_line == "#!/bin/bash",
        "AppImage build script must start with a bash shebang (`#!/usr/bin/env bash` or \
         `#!/bin/bash`) so the strict-mode flags below resolve against bash semantics; \
         got: {first_line:?}",
    );
}

#[test]
fn appimage_script_carries_spdx_license_header() {
    let script = read_appimage_script();
    let header_found = script
        .lines()
        .take(5)
        .any(|line| line.contains("SPDX-License-Identifier: AGPL-3.0-or-later"));
    assert!(
        header_found,
        "AppImage build script must declare `SPDX-License-Identifier: AGPL-3.0-or-later` \
         within its first 5 lines (the same SPDX convention every other workspace source \
         file follows)",
    );
}

#[test]
fn appimage_script_enables_strict_shell_mode() {
    let script = read_appimage_script();
    // Match the canonical form anywhere in the script body. Allow
    // alternative orderings (e.g. `set -eu -o pipefail`) since
    // bash treats them equivalently.
    let landed = script.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "set -euo pipefail"
            || trimmed == "set -eu -o pipefail"
            || trimmed == "set -e -u -o pipefail"
    });
    assert!(
        landed,
        "AppImage build script must enable strict shell mode via `set -euo pipefail` so a \
         missing dependency, an undefined variable, or a failed `linuxdeploy` step aborts \
         the build immediately; the script body did not contain that directive",
    );
}

#[test]
fn appimage_script_invokes_linuxdeploy_with_gtk_plugin() {
    let script = read_appimage_script();
    let joined = join_continuations(&script);
    let mut missing = Vec::new();
    for token in REQUIRED_LINUXDEPLOY_TOKENS {
        if !joined.contains(token) {
            missing.push(*token);
        }
    }
    assert!(
        missing.is_empty(),
        "AppImage build script must invoke `linuxdeploy` with the GTK plugin and the \
         standard appdir / desktop-file / icon-file / executable / output flags; missing \
         tokens: {missing:?}",
    );
}

#[test]
fn appimage_script_references_every_required_in_tree_source() {
    let script = read_appimage_script();
    let mut missing = Vec::new();
    for needle in REQUIRED_IN_TREE_REFERENCES {
        if !script.contains(needle) {
            missing.push(*needle);
        }
    }
    assert!(
        missing.is_empty(),
        "AppImage build script must reference each of {REQUIRED_IN_TREE_REFERENCES:?} so \
         the staged AppDir mirrors the .deb / .rpm / Flatpak install layouts; missing \
         references: {missing:?}",
    );
}

#[test]
fn appimage_script_in_tree_references_all_exist_under_the_workspace() {
    let workspace = workspace_root();
    let mut missing = Vec::new();
    for needle in REQUIRED_IN_TREE_REFERENCES {
        let full = workspace.join(needle);
        if !full.is_file() {
            missing.push((*needle, full));
        }
    }
    assert!(
        missing.is_empty(),
        "AppImage build script references in-tree paths that do not exist on disk — \
         renames must land in lockstep with the script: {missing:?}",
    );
}

#[test]
fn appimage_script_carries_zsync_update_information_pointing_at_github_releases() {
    let script = read_appimage_script();
    assert!(
        script.contains(EXPECTED_UPDATE_INFORMATION),
        "AppImage build script must set `UPDATE_INFORMATION` to {EXPECTED_UPDATE_INFORMATION:?} \
         per §11.5 so the resulting AppImage embeds the GitHub Releases zsync pointer for \
         in-place updates; that exact value was not present in the script body",
    );
}

#[test]
fn appimage_script_declares_versioned_output_filename() {
    let script = read_appimage_script();
    assert!(
        script.contains(EXPECTED_OUTPUT_NAME),
        "AppImage build script must declare the §11.5 artifact name shape \
         {EXPECTED_OUTPUT_NAME:?} (typically through `OUTPUT=` or in a `mv` rename); that \
         literal was not present in the script body",
    );
}

#[test]
fn appimage_script_reads_paladin_version_from_environment() {
    let script = read_appimage_script();
    // The script may either reference `${PALADIN_VERSION}` directly
    // or use the parameter-expansion guard form `${PALADIN_VERSION:?msg}`
    // (which is the stronger, fail-loud variant); either is acceptable.
    let landed = script.contains("${PALADIN_VERSION}") || script.contains("${PALADIN_VERSION:?");
    assert!(
        landed,
        "AppImage build script must read PALADIN_VERSION from the environment so the release \
         pipeline can inject the tag-derived version; the script body referenced neither \
         `${{PALADIN_VERSION}}` nor `${{PALADIN_VERSION:?...}}`",
    );
}

#[test]
fn appimage_script_does_not_hardcode_a_version_string() {
    // Pin that the script never embeds a literal semver string. The
    // release pipeline injects PALADIN_VERSION; a hard-coded
    // `0.0.1` / `0.1.0` / similar would silently desync from the
    // workspace `[workspace.package].version` and from the AppImage
    // tag.
    let script = read_appimage_script();
    // Coarse but effective heuristic: scan for `0.0.1` / `0.1.0` /
    // similar tokens that look like semvers.
    let suspicious_tokens = ["0.0.1", "0.0.0", "0.1.0", "0.2.0", "1.0.0"];
    let mut found = Vec::new();
    for token in &suspicious_tokens {
        if script.contains(token) {
            found.push(*token);
        }
    }
    assert!(
        found.is_empty(),
        "AppImage build script must not hard-code a semver — PALADIN_VERSION is the only \
         source of truth; found suspicious literals: {found:?}",
    );
}

#[test]
fn appimage_script_targets_x86_64_architecture_explicitly() {
    // §11.5 outputs a single x86_64 AppImage for Milestone 7. Pin
    // the architecture token explicitly so a future cross-build
    // change has to land an architecture-matrix update here too.
    let script = read_appimage_script();
    assert!(
        script.contains("x86_64"),
        "AppImage build script must declare the x86_64 target architecture explicitly per \
         §11.5; the script body did not contain the literal `x86_64`",
    );
}

// --- helper self-tests -------------------------------------------------------

#[test]
fn join_continuations_concatenates_backslash_terminated_lines() {
    let script = "\
linuxdeploy \\
  --appdir AppDir \\
  --plugin gtk \\
  --output appimage
";
    let joined = join_continuations(script);
    // Whitespace count between tokens is unspecified — what matters
    // is that each token is reachable from the joined string, so a
    // subsequent `contains(...)` against the production
    // `linuxdeploy` flags resolves regardless of how the script
    // formats its continuation lines.
    assert!(joined.contains("linuxdeploy"));
    assert!(joined.contains("--appdir AppDir"));
    assert!(joined.contains("--plugin gtk"));
    assert!(joined.contains("--output appimage"));
    // The newline that ended the un-continued tail line is preserved.
    assert!(joined.ends_with("--output appimage\n"));
}

#[test]
fn join_continuations_preserves_non_continuation_lines() {
    let script = "\
set -euo pipefail
echo hello
";
    let joined = join_continuations(script);
    assert!(joined.contains("set -euo pipefail"));
    assert!(joined.contains("echo hello"));
}
