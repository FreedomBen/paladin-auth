// SPDX-License-Identifier: AGPL-3.0-or-later

//! Flatpak (`flatpak-builder`) manifest contract tests for
//! `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §11.4 and the Milestone 7
//! packaging checklist entry "Add `packaging/flatpak/paladin-gtk.yml`":
//!
//! * Declares the app ID `org.tamx.Paladin.Gui` — the same string
//!   passed to `RelmApp::new(APP_ID)` and set as `StartupWMClass`
//!   in `data/org.tamx.Paladin.Gui.desktop` so window-to-launcher
//!   mapping works identically in native and Flatpak builds.
//! * Builds against `org.gnome.Platform//47` + the matching
//!   `org.gnome.Sdk` — that runtime bundles GTK 4.16 and
//!   libadwaita 1.6, matching the build-time `gtk4` (`v4_16`) /
//!   `libadwaita` (`v1_6`) crate features so the Adwaita widget
//!   set (`AdwAlertDialog`, `AdwAboutDialog`, `AdwPreferencesDialog`)
//!   is available identically in Flatpak and native packagings.
//! * Sets `command: paladin-gtk` so `flatpak run org.tamx.Paladin.Gui`
//!   launches the GUI binary.
//! * `finish-args:` declares the §11.4 sandbox permissions verbatim
//!   (`--socket=wayland`, `--socket=fallback-x11`, `--share=ipc`,
//!   `--filesystem=xdg-data/paladin:create`,
//!   `--filesystem=xdg-config/paladin:create`) and **does not**
//!   declare `--share=network` (docs/DESIGN.md §3 / §5 forbid all
//!   network access; the Flatpak sandbox is the strongest place to
//!   enforce that posture).
//! * Installs the desktop entry, the `AppStream` metainfo, and the
//!   hicolor icon set into `/app/share/...` (the Flatpak runtime
//!   prefix that flatpak-builder exports to the host's
//!   freedesktop `share/metainfo/` / `share/applications/` /
//!   `share/icons/hicolor/` locations). The plan describes this as
//!   "exporting the metainfo file to `/usr/share/metainfo/`" — that
//!   is the freedesktop-semantics shorthand for the
//!   `/app/share/metainfo/` install path inside the sandbox.
//! * Installs the binary to `/app/bin/paladin-gtk` (mode `0755`),
//!   and stages it from the workspace `cargo build --release`
//!   output via a `simple` buildsystem with vendored `--offline`
//!   `--locked` Cargo flags so Flathub builds reproducibly without
//!   network access.
//!
//! Tests read the manifest as plain text — no `serde_yaml`
//! dependency lands here, matching the dependency-free style of
//! the deb / rpm manifest contract tests in this crate.

use std::fs;
use std::path::PathBuf;

/// Path to the Flatpak manifest, relative to the workspace root.
///
/// Note the `.yml` extension (not `.yaml`) — flatpak-builder and
/// Flathub both accept either, and §11.4 pins `.yml` so a casual
/// rename does not silently re-route the packaging dry-run away
/// from the file it expects.
const FLATPAK_MANIFEST_RELPATH: &str = "packaging/flatpak/paladin-gtk.yml";

/// The Flatpak app ID. Must match `paladin_gtk::APP_ID` byte-for-byte
/// — pinning is by literal here so a future rename of either side
/// surfaces in a focused failure rather than only in the smoke test.
const APP_ID: &str = "org.tamx.Paladin.Gui";

/// Required `finish-args:` sandbox permissions, in the exact form
/// flatpak-builder consumes them. Order is irrelevant.
const REQUIRED_FINISH_ARGS: &[&str] = &[
    "--socket=wayland",
    "--socket=fallback-x11",
    "--share=ipc",
    "--filesystem=xdg-data/paladin:create",
    "--filesystem=xdg-config/paladin:create",
];

/// `finish-args:` permissions that MUST NOT appear under any
/// circumstances. `--share=network` would breach docs/DESIGN.md §3 / §5
/// "No network, no telemetry"; other broad portals would weaken the
/// XDG-scoped vault-only filesystem posture.
const FORBIDDEN_FINISH_ARGS: &[&str] = &[
    "--share=network",
    "--filesystem=home",
    "--filesystem=host",
    "--filesystem=host-os",
    "--filesystem=host-etc",
];

/// `/app/<path>` install destinations the manifest's `build-commands:`
/// MUST land. These are the Flatpak runtime equivalents of the
/// `.deb` / `.rpm` `/usr/<path>` install layout; flatpak-builder
/// re-exports `/app/share/...` to the host's freedesktop directories
/// at install time.
const REQUIRED_INSTALL_DESTINATIONS: &[&str] = &[
    "/app/bin/paladin-gtk",
    "/app/share/applications/org.tamx.Paladin.Gui.desktop",
    "/app/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml",
    "/app/share/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg",
    "/app/share/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg",
    "/app/share/icons/hicolor/16x16/apps/org.tamx.Paladin.Gui.png",
    "/app/share/icons/hicolor/24x24/apps/org.tamx.Paladin.Gui.png",
    "/app/share/icons/hicolor/32x32/apps/org.tamx.Paladin.Gui.png",
    "/app/share/icons/hicolor/48x48/apps/org.tamx.Paladin.Gui.png",
];

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

fn flatpak_manifest_path() -> PathBuf {
    workspace_root().join(FLATPAK_MANIFEST_RELPATH)
}

fn read_flatpak_manifest() -> String {
    fs::read_to_string(flatpak_manifest_path()).unwrap_or_else(|err| {
        panic!(
            "failed to read {}: {err}",
            flatpak_manifest_path().display()
        )
    })
}

/// Read a top-level scalar (`key: value`) from the Flatpak manifest.
/// Returns the value with surrounding quotes / whitespace trimmed,
/// or `None` if the key is absent.
fn top_level_scalar(manifest: &str, key: &str) -> Option<String> {
    for raw_line in manifest.lines() {
        let line = strip_trailing_comment(raw_line);
        if !line.starts_with(&format!("{key}:")) {
            continue;
        }
        let rhs = &line[key.len() + 1..];
        let trimmed = rhs.trim();
        if trimmed.is_empty() {
            // `key:` with nothing on the same line — this is a
            // mapping/sequence header, not a scalar.
            return None;
        }
        return Some(trimmed.trim_matches(['"', '\'']).to_string());
    }
    None
}

/// Read the list of scalar entries under a top-level sequence key
/// (canonical block-list form `key:\n  - "a"\n  - "b"`). Quoted and
/// unquoted entries are both supported.
fn top_level_sequence_scalars(manifest: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let header = format!("{key}:");
    let lines: Vec<&str> = manifest.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_trailing_comment(lines[i]);
        if line == header {
            i += 1;
            while i < lines.len() {
                let raw = lines[i];
                let trimmed = strip_trailing_comment(raw).trim_end();
                if trimmed.is_empty() {
                    i += 1;
                    continue;
                }
                if !raw.starts_with(' ') && !raw.starts_with('\t') {
                    break;
                }
                let stripped = trimmed.trim_start();
                if let Some(item) = stripped.strip_prefix("- ") {
                    out.push(item.trim().trim_matches(['"', '\'']).to_string());
                } else if stripped == "-" {
                    out.push(String::new());
                }
                i += 1;
            }
            return out;
        }
        i += 1;
    }
    out
}

/// Extract every `build-commands:` entry across every module. Each
/// returned string is the post-`- ` literal with surrounding
/// quotes trimmed. The result is a flat `Vec<String>` because the
/// tests only assert on individual command strings (no per-module
/// grouping needed).
fn all_build_commands(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_trailing_comment(lines[i]).trim_end();
        if line.trim_start() == "build-commands:" {
            // Capture the indent of the `build-commands:` key so
            // we can stop at the next sibling key with the same or
            // lower indent.
            let key_indent = lines[i].len() - lines[i].trim_start().len();
            i += 1;
            while i < lines.len() {
                let raw = lines[i];
                let stripped_end = strip_trailing_comment(raw).trim_end();
                if stripped_end.is_empty() {
                    i += 1;
                    continue;
                }
                let line_indent = raw.len() - raw.trim_start().len();
                let stripped = stripped_end.trim_start();
                if line_indent <= key_indent && !stripped.starts_with("- ") {
                    break;
                }
                if let Some(cmd) = stripped.strip_prefix("- ") {
                    out.push(cmd.trim().trim_matches(['"', '\'']).to_string());
                }
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

fn strip_trailing_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

// --- tests -------------------------------------------------------------------

#[test]
fn flatpak_manifest_exists_at_expected_path() {
    let path = flatpak_manifest_path();
    assert!(
        path.is_file(),
        "expected Flatpak manifest at {} — Milestone 7 packaging \
         checklist requires `packaging/flatpak/paladin-gtk.yml`",
        path.display(),
    );
}

#[test]
fn flatpak_manifest_starts_with_spdx_license_header() {
    let manifest = read_flatpak_manifest();
    let first_meaningful_line = manifest
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    assert!(
        first_meaningful_line.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
        "Flatpak manifest must lead with an SPDX-License-Identifier comment matching the \
         workspace AGPL-3.0-or-later license; first line was {first_meaningful_line:?}",
    );
}

#[test]
fn flatpak_manifest_declares_app_id_matching_app_constant() {
    let manifest = read_flatpak_manifest();
    let app_id = top_level_scalar(&manifest, "app-id")
        .expect("Flatpak manifest has a top-level `app-id:` key");
    assert_eq!(
        app_id, APP_ID,
        "Flatpak `app-id:` must equal `paladin_gtk::APP_ID` so the desktop entry's \
         `StartupWMClass`, `RelmApp::new`, and the AppStream `<id>` all resolve to the \
         same identifier; got {app_id:?}",
    );
}

#[test]
fn flatpak_manifest_declares_gnome_runtime_47_and_matching_sdk() {
    let manifest = read_flatpak_manifest();
    let runtime = top_level_scalar(&manifest, "runtime")
        .expect("Flatpak manifest has a top-level `runtime:` key");
    let runtime_version = top_level_scalar(&manifest, "runtime-version")
        .expect("Flatpak manifest has a top-level `runtime-version:` key");
    let sdk =
        top_level_scalar(&manifest, "sdk").expect("Flatpak manifest has a top-level `sdk:` key");
    assert_eq!(
        runtime, "org.gnome.Platform",
        "Flatpak `runtime:` must be `org.gnome.Platform` — that bundles GTK 4.16 and \
         libadwaita 1.6 matching the build-time `gtk4` (v4_16) / `libadwaita` (v1_6) \
         features; got {runtime:?}",
    );
    assert_eq!(
        runtime_version, "47",
        "Flatpak `runtime-version:` must be `47` (the §11.4 baseline); got {runtime_version:?}",
    );
    assert_eq!(
        sdk, "org.gnome.Sdk",
        "Flatpak `sdk:` must be `org.gnome.Sdk` to match the GNOME Platform runtime; \
         got {sdk:?}",
    );
}

#[test]
fn flatpak_manifest_declares_command_paladin_gtk() {
    let manifest = read_flatpak_manifest();
    let command = top_level_scalar(&manifest, "command")
        .expect("Flatpak manifest has a top-level `command:` key");
    assert_eq!(
        command, "paladin-gtk",
        "Flatpak `command:` must be `paladin-gtk` so `flatpak run {APP_ID}` invokes the \
         installed binary at /app/bin/paladin-gtk; got {command:?}",
    );
}

#[test]
fn flatpak_manifest_declares_every_required_finish_arg() {
    let manifest = read_flatpak_manifest();
    let finish_args = top_level_sequence_scalars(&manifest, "finish-args");
    let mut missing = Vec::new();
    for required in REQUIRED_FINISH_ARGS {
        if !finish_args.iter().any(|arg| arg == required) {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "Flatpak `finish-args:` must include each of {REQUIRED_FINISH_ARGS:?} per §11.4; \
         missing: {missing:?}; got: {finish_args:?}",
    );
}

#[test]
fn flatpak_manifest_does_not_declare_any_forbidden_finish_arg() {
    // docs/DESIGN.md §3 / §5 "No network, no telemetry" — the Flatpak
    // sandbox is the strongest place to enforce that posture. The
    // file system surface is also scoped strictly to the paladin
    // XDG namespace, so a future merge that adds `--filesystem=host`
    // or similar gets a focused failure here.
    let manifest = read_flatpak_manifest();
    let finish_args = top_level_sequence_scalars(&manifest, "finish-args");
    let mut found = Vec::new();
    for forbidden in FORBIDDEN_FINISH_ARGS {
        if finish_args.iter().any(|arg| arg == forbidden) {
            found.push(*forbidden);
        }
    }
    assert!(
        found.is_empty(),
        "Flatpak `finish-args:` must NOT declare any of {FORBIDDEN_FINISH_ARGS:?} — \
         docs/DESIGN.md §3 / §5 forbid network access and the §11.4 filesystem posture is \
         strictly scoped to the paladin XDG namespace; found: {found:?}",
    );
}

#[test]
fn flatpak_manifest_finish_args_are_exactly_the_milestone_7_baseline_set() {
    // Pin the finish-args set so an accidental addition (a portal,
    // a new socket, an extra filesystem) lands an explicit review.
    // Milestone 7 / §11.4 scope the permissions to the five entries
    // in REQUIRED_FINISH_ARGS — anything else needs a plan update
    // before the test.
    let manifest = read_flatpak_manifest();
    let finish_args = top_level_sequence_scalars(&manifest, "finish-args");
    let extras: Vec<&str> = finish_args
        .iter()
        .map(String::as_str)
        .filter(|arg| !REQUIRED_FINISH_ARGS.contains(arg))
        .collect();
    assert!(
        extras.is_empty(),
        "Flatpak `finish-args:` must declare ONLY the §11.4 baseline set \
         {REQUIRED_FINISH_ARGS:?}; found unexpected entries: {extras:?}. If a new \
         sandbox permission is genuinely required, update \
         docs/IMPLEMENTATION_PLAN_04_GTK.md §11.4 first and add it to REQUIRED_FINISH_ARGS \
         in this test.",
    );
}

#[test]
fn flatpak_manifest_install_steps_cover_every_required_destination() {
    let manifest = read_flatpak_manifest();
    let cmds = all_build_commands(&manifest);
    let mut missing = Vec::new();
    for required in REQUIRED_INSTALL_DESTINATIONS {
        let landed = cmds.iter().any(|cmd| cmd.contains(required));
        if !landed {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "Flatpak `build-commands:` must install each of {REQUIRED_INSTALL_DESTINATIONS:?} \
         via `install -Dm... <src> <dst>` (or equivalent); missing destinations: \
         {missing:?}; got commands: {cmds:?}",
    );
}

#[test]
fn flatpak_manifest_binary_install_uses_executable_mode_0755() {
    // The /app/bin/paladin-gtk install MUST be 0755 — anything less
    // lands a non-executable binary inside the sandbox and breaks
    // `flatpak run`. Pin the install command shape so a future
    // refactor that drops `-Dm755` lights up here.
    let manifest = read_flatpak_manifest();
    let cmds = all_build_commands(&manifest);
    let landed = cmds.iter().any(|cmd| {
        cmd.contains("/app/bin/paladin-gtk")
            && (cmd.contains("-Dm755") || cmd.contains("--mode=755"))
    });
    assert!(
        landed,
        "Flatpak `build-commands:` must install /app/bin/paladin-gtk with mode 0755 \
         (e.g. `install -Dm755 target/release/paladin-gtk /app/bin/paladin-gtk`); \
         got commands: {cmds:?}",
    );
}

#[test]
fn flatpak_manifest_metainfo_install_lands_under_app_share_metainfo() {
    // The plan describes "exporting the metainfo file to
    // `/usr/share/metainfo/`" — that is the freedesktop-semantics
    // shorthand. Inside the Flatpak runtime the install path is
    // `/app/share/metainfo/`, which flatpak-builder re-exports to
    // the host's freedesktop metainfo directory. Pin the exact
    // sandbox path so a future copy-paste from the .deb / .rpm
    // manifest does not land the file at `/usr/share/metainfo/`
    // (which would create an unexported file inside the sandbox).
    let manifest = read_flatpak_manifest();
    let cmds = all_build_commands(&manifest);
    let landed = cmds.iter().any(|cmd| {
        cmd.contains("crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml")
            && cmd.contains("/app/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml")
    });
    assert!(
        landed,
        "Flatpak `build-commands:` must install the AppStream metainfo from \
         crates/paladin-gtk/data/metainfo/... to /app/share/metainfo/... — that path \
         is what flatpak-builder exports to the host's freedesktop metainfo directory; \
         got commands: {cmds:?}",
    );
}

#[test]
fn flatpak_manifest_uses_locked_offline_cargo_build() {
    // §"Reproducible builds" requires `cargo build --locked` plus
    // vendored deps so Flathub builds reproducibly without network
    // access at build time. The Flatpak sandbox blocks network
    // during the build (no `--share=network` in finish-args), so
    // any `cargo` invocation must use `--offline` and a vendored
    // crate source.
    let manifest = read_flatpak_manifest();
    let cmds = all_build_commands(&manifest);
    let cargo_cmds: Vec<&String> = cmds.iter().filter(|cmd| cmd.contains("cargo")).collect();
    assert!(
        !cargo_cmds.is_empty(),
        "Flatpak `build-commands:` must invoke `cargo` to build paladin-gtk; got commands: \
         {cmds:?}",
    );
    for cmd in &cargo_cmds {
        assert!(
            cmd.contains("--locked"),
            "Flatpak `build-commands:` cargo invocation must include `--locked` for \
             reproducibility; got: {cmd:?}",
        );
        assert!(
            cmd.contains("--offline"),
            "Flatpak `build-commands:` cargo invocation must include `--offline` because the \
             sandbox has no network access at build time; got: {cmd:?}",
        );
        assert!(
            cmd.contains("--release"),
            "Flatpak `build-commands:` cargo invocation must build a release artifact \
             (`--release`); got: {cmd:?}",
        );
    }
}

#[test]
fn flatpak_manifest_module_name_matches_app_id_basename() {
    // Convention: the primary build module is named after the
    // binary, so flatpak-builder's status output is readable.
    let manifest = read_flatpak_manifest();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut found = false;
    for raw in lines {
        let trimmed = strip_trailing_comment(raw).trim();
        if trimmed == "- name: paladin-gtk" || trimmed == "- name: \"paladin-gtk\"" {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "Flatpak `modules:` list must contain an entry whose `name` is `paladin-gtk`",
    );
}

// --- helper self-tests -------------------------------------------------------

#[test]
fn top_level_scalar_reads_quoted_and_unquoted_values() {
    let manifest = "\
app-id: org.tamx.Paladin.Gui
runtime-version: '47'
command: \"paladin-gtk\"
";
    assert_eq!(
        top_level_scalar(manifest, "app-id").as_deref(),
        Some("org.tamx.Paladin.Gui"),
    );
    assert_eq!(
        top_level_scalar(manifest, "runtime-version").as_deref(),
        Some("47"),
    );
    assert_eq!(
        top_level_scalar(manifest, "command").as_deref(),
        Some("paladin-gtk"),
    );
    assert_eq!(top_level_scalar(manifest, "missing"), None);
}

#[test]
fn top_level_sequence_scalars_reads_block_list_entries() {
    let manifest = "\
finish-args:
  - --socket=wayland
  - --share=ipc
modules:
  - name: paladin-gtk
";
    let args = top_level_sequence_scalars(manifest, "finish-args");
    assert_eq!(
        args,
        vec!["--socket=wayland".to_string(), "--share=ipc".to_string()],
    );
    assert!(top_level_sequence_scalars(manifest, "missing").is_empty());
}

#[test]
fn all_build_commands_collects_entries_across_modules() {
    let manifest = "\
modules:
  - name: paladin-gtk
    buildsystem: simple
    build-commands:
      - cargo build --release --locked --offline -p paladin-gtk
      - install -Dm755 target/release/paladin-gtk /app/bin/paladin-gtk
    sources:
      - type: dir
        path: ../..
";
    let cmds = all_build_commands(manifest);
    assert_eq!(
        cmds,
        vec![
            "cargo build --release --locked --offline -p paladin-gtk".to_string(),
            "install -Dm755 target/release/paladin-gtk /app/bin/paladin-gtk".to_string(),
        ],
    );
}

#[test]
fn strip_trailing_comment_drops_inline_comment() {
    assert_eq!(
        strip_trailing_comment("runtime-version: '47' # GNOME 47"),
        "runtime-version: '47' "
    );
    assert_eq!(strip_trailing_comment("# header"), "");
    assert_eq!(strip_trailing_comment("no comment here"), "no comment here");
}
