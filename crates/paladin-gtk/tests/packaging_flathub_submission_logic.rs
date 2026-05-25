// SPDX-License-Identifier: AGPL-3.0-or-later
//! Flathub submission contract tests for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Milestone 7 checklist" entry
//! "File the Flathub submission and inherit Flatpak signing from
//! Flathub" and `docs/DESIGN.md` §11.4 ("Publication. Flathub. Each
//! front-end is its own Flathub submission..."), the in-tree
//! `packaging/flathub/` tree carries the artifacts that get PR'd to
//! <https://github.com/flathub/flathub> to register the
//! `org.tamx.Paladin.Gui` app and the subsequent commits to the
//! resulting `flathub/org.tamx.Paladin.Gui` app repo:
//!
//! * `packaging/flathub/org.tamx.Paladin.Gui.yml` — the Flathub
//!   manifest, named with the app-id basename per Flathub
//!   convention. Distinct from `packaging/flatpak/paladin-gtk.yml`
//!   (which targets the local packaging dry-run and uses
//!   `type: dir, path: ../..` to build from the workspace tree):
//!   the Flathub manifest must use an upstream source pointer
//!   (`type: git` or `type: archive`) so Flathub's builder fetches
//!   the tagged release rather than relying on a local checkout.
//! * `packaging/flathub/flathub.json` — the Flathub build-options
//!   companion, declaring `only-arches: ["x86_64"]` so the initial
//!   submission scopes the build matrix to the architecture the
//!   `.deb` / `.rpm` / `AppImage` pipeline already covers
//!   (docs/DESIGN.md §11.3 / §11.5). Additional arches land in follow-
//!   up commits once the corresponding native artifacts ship.
//! * `packaging/flathub/README.md` — the submission instructions:
//!   how the PR against `flathub/flathub` is filed, how the
//!   per-release source pointer + `cargo-sources.json` get stamped
//!   each release, and how Flatpak signing is inherited from
//!   Flathub's published key (docs/DESIGN.md §11.4 / §11.6: "Flatpak
//!   releases inherit Flathub's signing").
//!
//! Tests read every file as plain text — no `serde_yaml` /
//! `serde_json` dependency lands here, matching the dependency-free
//! style of the deb / rpm / Flatpak manifest contract tests in
//! this crate.
use std::fs;
use std::path::PathBuf;

/// Path to the Flathub submission directory, relative to the
/// workspace root.
const FLATHUB_DIR_RELPATH: &str = "packaging/flathub";

/// Path to the Flathub manifest, relative to the workspace root.
///
/// Flathub convention: the manifest filename is the app-id basename
/// suffixed with `.yml`. When the submission lands at
/// `flathub/org.tamx.Paladin.Gui`, the file at the repo root is the
/// same `org.tamx.Paladin.Gui.yml` shipped here.
const FLATHUB_MANIFEST_RELPATH: &str = "packaging/flathub/org.tamx.Paladin.Gui.yml";

/// Path to the Flathub build-options companion, relative to the
/// workspace root.
const FLATHUB_JSON_RELPATH: &str = "packaging/flathub/flathub.json";

/// Path to the Flathub submission README, relative to the workspace
/// root.
const FLATHUB_README_RELPATH: &str = "packaging/flathub/README.md";

/// The Flatpak / Flathub app ID. Must match `paladin_gtk::APP_ID`
/// byte-for-byte — pinned by literal here so a rename of either
/// side surfaces in a focused failure.
const APP_ID: &str = "org.tamx.Paladin.Gui";

/// Upstream repository URL. Must match the workspace
/// `[workspace.package].repository` field so the Flathub source
/// pointer keeps pointing at the same canonical Git host the rest
/// of the release pipeline references.
const UPSTREAM_REPOSITORY_URL: &str = "https://github.com/FreedomBen/paladin";

/// Required `finish-args:` sandbox permissions — identical to the
/// `packaging/flatpak/paladin-gtk.yml` baseline so Flathub builds
/// run with the same sandbox posture as the local packaging
/// dry-run.
const REQUIRED_FINISH_ARGS: &[&str] = &[
    "--socket=wayland",
    "--socket=fallback-x11",
    "--share=ipc",
    "--filesystem=xdg-data/paladin:create",
    "--filesystem=xdg-config/paladin:create",
];

/// `finish-args:` permissions that MUST NOT appear. `--share=network`
/// would breach docs/DESIGN.md §3 / §5 "No network, no telemetry"; broad
/// `--filesystem=host*` portals would weaken the XDG-scoped vault-
/// only filesystem posture.
const FORBIDDEN_FINISH_ARGS: &[&str] = &[
    "--share=network",
    "--filesystem=home",
    "--filesystem=host",
    "--filesystem=host-os",
    "--filesystem=host-etc",
];

/// `/app/<path>` install destinations the manifest's
/// `build-commands:` MUST land. Identical to the Flatpak dry-run
/// manifest's layout so a Flathub install and a local Flatpak
/// install stage byte-identical payloads.
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
    "/app/share/icons/hicolor/64x64/apps/org.tamx.Paladin.Gui.png",
    "/app/share/icons/hicolor/128x128/apps/org.tamx.Paladin.Gui.png",
    "/app/share/icons/hicolor/256x256/apps/org.tamx.Paladin.Gui.png",
    "/app/share/icons/hicolor/512x512/apps/org.tamx.Paladin.Gui.png",
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

fn flathub_dir_path() -> PathBuf {
    workspace_root().join(FLATHUB_DIR_RELPATH)
}

fn flathub_manifest_path() -> PathBuf {
    workspace_root().join(FLATHUB_MANIFEST_RELPATH)
}

fn flathub_json_path() -> PathBuf {
    workspace_root().join(FLATHUB_JSON_RELPATH)
}

fn flathub_readme_path() -> PathBuf {
    workspace_root().join(FLATHUB_README_RELPATH)
}

fn read_flathub_manifest() -> String {
    fs::read_to_string(flathub_manifest_path()).unwrap_or_else(|err| {
        panic!(
            "failed to read {}: {err}",
            flathub_manifest_path().display()
        )
    })
}

fn read_flathub_json() -> String {
    fs::read_to_string(flathub_json_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", flathub_json_path().display()))
}

fn read_flathub_readme() -> String {
    fs::read_to_string(flathub_readme_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", flathub_readme_path().display()))
}

/// Read a top-level scalar (`key: value`) from a YAML manifest.
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
            return None;
        }
        return Some(
            trimmed
                .trim_matches(|c: char| c == '\'' || c == '"')
                .to_string(),
        );
    }
    None
}

/// Read a top-level block sequence (`key:\n  - v1\n  - v2`) from a
/// YAML manifest. Returns each entry with surrounding quotes /
/// whitespace trimmed.
fn top_level_sequence_scalars(manifest: &str, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let header = format!("{key}:");
    let lines: Vec<&str> = manifest.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_trailing_comment(lines[i]).trim_end();
        if line == header {
            i += 1;
            while i < lines.len() {
                let entry_line = strip_trailing_comment(lines[i]);
                let trimmed = entry_line.trim_start();
                if trimmed.is_empty() {
                    i += 1;
                    continue;
                }
                if !trimmed.starts_with("- ") {
                    // Next top-level key or non-sequence content;
                    // sequence is over.
                    break;
                }
                let value = trimmed[2..]
                    .trim()
                    .trim_matches(|c: char| c == '\'' || c == '"');
                out.push(value.to_string());
                i += 1;
            }
            return out;
        }
        i += 1;
    }
    out
}

/// Extract every `build-commands:` entry across every module.
fn all_build_commands(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_trailing_comment(lines[i]).trim_end();
        if line.trim_start() == "build-commands:" {
            let key_indent = line.len() - line.trim_start().len();
            i += 1;
            while i < lines.len() {
                let entry_line = strip_trailing_comment(lines[i]);
                let trimmed = entry_line.trim_start();
                if trimmed.is_empty() {
                    i += 1;
                    continue;
                }
                let this_indent = entry_line.len() - trimmed.len();
                if this_indent <= key_indent {
                    break;
                }
                if !trimmed.starts_with("- ") {
                    break;
                }
                let value = trimmed[2..]
                    .trim()
                    .trim_matches(|c: char| c == '\'' || c == '"');
                out.push(value.to_string());
                i += 1;
            }
            continue;
        }
        i += 1;
    }
    out
}

/// Return every `type:` value inside a `sources:` block. Each entry
/// is the value with surrounding whitespace / quotes trimmed.
fn source_types(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut in_sources = false;
    let mut sources_indent: usize = 0;
    for raw in lines {
        let line = strip_trailing_comment(raw).trim_end();
        let trimmed = line.trim_start();
        let this_indent = line.len() - trimmed.len();
        if !in_sources {
            if trimmed == "sources:" {
                in_sources = true;
                sources_indent = this_indent;
            }
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if this_indent <= sources_indent && !trimmed.starts_with("- ") {
            in_sources = false;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("type:") {
            let value = rest.trim().trim_matches(|c: char| c == '\'' || c == '"');
            out.push(value.to_string());
        } else if let Some(rest) = trimmed.strip_prefix("- type:") {
            let value = rest.trim().trim_matches(|c: char| c == '\'' || c == '"');
            out.push(value.to_string());
        }
    }
    out
}

fn strip_trailing_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

// --- manifest existence + header ---------------------------------------------

#[test]
fn flathub_submission_directory_exists() {
    let path = flathub_dir_path();
    assert!(
        path.is_dir(),
        "expected Flathub submission directory at {} — Milestone 7 packaging \
         checklist requires `packaging/flathub/` to carry the submission \
         artifacts that get PR'd to flathub/flathub",
        path.display(),
    );
}

#[test]
fn flathub_manifest_exists_at_app_id_basename() {
    let path = flathub_manifest_path();
    assert!(
        path.is_file(),
        "expected Flathub manifest at {} — Flathub convention names the \
         manifest with the app-id basename (`{APP_ID}.yml`) so the PR \
         against flathub/flathub maps directly onto the resulting \
         flathub/{APP_ID} app repo with no rename",
        path.display(),
    );
}

#[test]
fn flathub_manifest_starts_with_spdx_license_header() {
    let manifest = read_flathub_manifest();
    let first_meaningful_line = manifest
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    assert!(
        first_meaningful_line.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
        "Flathub manifest must lead with an SPDX-License-Identifier comment matching \
         the workspace AGPL-3.0-or-later license; first line was \
         {first_meaningful_line:?}",
    );
}

// --- manifest top-level keys -------------------------------------------------

#[test]
fn flathub_manifest_declares_app_id_matching_app_constant() {
    let manifest = read_flathub_manifest();
    let app_id = top_level_scalar(&manifest, "app-id")
        .expect("Flathub manifest has a top-level `app-id:` key");
    assert_eq!(
        app_id, APP_ID,
        "Flathub `app-id:` must equal `paladin_gtk::APP_ID` so Flathub's \
         resulting repo (flathub/{APP_ID}), the desktop entry's \
         `StartupWMClass`, `RelmApp::new(APP_ID)`, and the AppStream `<id>` \
         all resolve to the same identifier; got {app_id:?}",
    );
}

#[test]
fn flathub_manifest_declares_gnome_runtime_47_and_matching_sdk() {
    let manifest = read_flathub_manifest();
    let runtime = top_level_scalar(&manifest, "runtime")
        .expect("Flathub manifest has a top-level `runtime:` key");
    let runtime_version = top_level_scalar(&manifest, "runtime-version")
        .expect("Flathub manifest has a top-level `runtime-version:` key");
    let sdk =
        top_level_scalar(&manifest, "sdk").expect("Flathub manifest has a top-level `sdk:` key");
    assert_eq!(
        runtime, "org.gnome.Platform",
        "Flathub `runtime:` must be `org.gnome.Platform` — that bundles GTK 4.16 \
         and libadwaita 1.6 matching the build-time `gtk4` (v4_16) / \
         `libadwaita` (v1_6) features; got {runtime:?}",
    );
    assert_eq!(
        runtime_version, "47",
        "Flathub `runtime-version:` must be `47` (the §11.4 baseline matching \
         the local Flatpak manifest); got {runtime_version:?}",
    );
    assert_eq!(
        sdk, "org.gnome.Sdk",
        "Flathub `sdk:` must be `org.gnome.Sdk` to match the GNOME Platform \
         runtime; got {sdk:?}",
    );
}

#[test]
fn flathub_manifest_declares_command_paladin_gtk() {
    let manifest = read_flathub_manifest();
    let command = top_level_scalar(&manifest, "command")
        .expect("Flathub manifest has a top-level `command:` key");
    assert_eq!(
        command, "paladin-gtk",
        "Flathub `command:` must be `paladin-gtk` so `flatpak run {APP_ID}` \
         invokes the installed binary at /app/bin/paladin-gtk; got {command:?}",
    );
}

// --- finish-args -------------------------------------------------------------

#[test]
fn flathub_manifest_declares_every_required_finish_arg() {
    let manifest = read_flathub_manifest();
    let finish_args = top_level_sequence_scalars(&manifest, "finish-args");
    let mut missing = Vec::new();
    for required in REQUIRED_FINISH_ARGS {
        if !finish_args.iter().any(|arg| arg == required) {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "Flathub `finish-args:` must include each of {REQUIRED_FINISH_ARGS:?} per \
         §11.4; missing: {missing:?}; got: {finish_args:?}",
    );
}

#[test]
fn flathub_manifest_does_not_declare_any_forbidden_finish_arg() {
    let manifest = read_flathub_manifest();
    let finish_args = top_level_sequence_scalars(&manifest, "finish-args");
    let mut found = Vec::new();
    for forbidden in FORBIDDEN_FINISH_ARGS {
        if finish_args.iter().any(|arg| arg == forbidden) {
            found.push(*forbidden);
        }
    }
    assert!(
        found.is_empty(),
        "Flathub `finish-args:` must NOT declare any of {FORBIDDEN_FINISH_ARGS:?} \
         — docs/DESIGN.md §3 / §5 forbid network access and the §11.4 baseline scopes \
         the filesystem surface strictly to the paladin XDG namespace; \
         found: {found:?}",
    );
}

#[test]
fn flathub_manifest_finish_args_are_exactly_the_milestone_7_baseline_set() {
    let manifest = read_flathub_manifest();
    let finish_args = top_level_sequence_scalars(&manifest, "finish-args");
    let extras: Vec<&str> = finish_args
        .iter()
        .map(String::as_str)
        .filter(|arg| !REQUIRED_FINISH_ARGS.contains(arg))
        .collect();
    assert!(
        extras.is_empty(),
        "Flathub `finish-args:` must declare ONLY the §11.4 baseline set \
         {REQUIRED_FINISH_ARGS:?}; found unexpected entries: {extras:?}. If a \
         new sandbox permission is genuinely required, update \
         docs/IMPLEMENTATION_PLAN_04_GTK.md §11.4 + REQUIRED_FINISH_ARGS in this \
         test first.",
    );
}

// --- install steps -----------------------------------------------------------

#[test]
fn flathub_manifest_install_steps_cover_every_required_destination() {
    let manifest = read_flathub_manifest();
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
        "Flathub `build-commands:` must install each of \
         {REQUIRED_INSTALL_DESTINATIONS:?} via `install -Dm... <src> <dst>` (or \
         equivalent); missing destinations: {missing:?}; got commands: {cmds:?}",
    );
}

#[test]
fn flathub_manifest_binary_install_uses_executable_mode_0755() {
    let manifest = read_flathub_manifest();
    let cmds = all_build_commands(&manifest);
    let landed = cmds.iter().any(|cmd| {
        cmd.contains("/app/bin/paladin-gtk")
            && (cmd.contains("-Dm755") || cmd.contains("--mode=755"))
    });
    assert!(
        landed,
        "Flathub `build-commands:` must install /app/bin/paladin-gtk with mode \
         0755; got commands: {cmds:?}",
    );
}

// --- reproducible-build invariants -------------------------------------------

#[test]
fn flathub_manifest_uses_locked_offline_cargo_build() {
    // §"Reproducible builds" requires `cargo build --locked
    // --offline --release` so Flathub builds reproducibly without
    // network access. The Flathub sandbox blocks network during
    // build (no `--share=network`), so any `cargo` invocation
    // building source must carry --offline.
    let manifest = read_flathub_manifest();
    let cmds = all_build_commands(&manifest);
    let cargo_build_cmds: Vec<&String> = cmds
        .iter()
        .filter(|cmd| cmd.contains("cargo") && cmd.contains("build"))
        .collect();
    assert!(
        !cargo_build_cmds.is_empty(),
        "Flathub `build-commands:` must invoke `cargo build` to compile \
         paladin-gtk; got commands: {cmds:?}",
    );
    for cmd in &cargo_build_cmds {
        assert!(
            cmd.contains("--locked"),
            "Flathub `cargo build` must include `--locked` for reproducibility; \
             got: {cmd:?}",
        );
        assert!(
            cmd.contains("--offline"),
            "Flathub `cargo build` must include `--offline` because the sandbox \
             has no network access at build time; got: {cmd:?}",
        );
        assert!(
            cmd.contains("--release"),
            "Flathub `cargo build` must build a release artifact (`--release`); \
             got: {cmd:?}",
        );
    }
}

#[test]
fn flathub_manifest_module_name_matches_app_id_basename() {
    let manifest = read_flathub_manifest();
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
        "Flathub `modules:` list must contain an entry whose `name` is \
         `paladin-gtk`",
    );
}

// --- Flathub-specific source pointer -----------------------------------------

#[test]
fn flathub_manifest_source_is_upstream_not_local_dir() {
    // This is the differentiator between
    // packaging/flatpak/paladin-gtk.yml (which uses `type: dir,
    // path: ../..` for the local packaging dry-run) and the
    // Flathub submission. Flathub builds in its own infra without
    // access to a local checkout, so the manifest MUST source
    // upstream via `type: git` or `type: archive`.
    let manifest = read_flathub_manifest();
    let types = source_types(&manifest);
    assert!(
        !types.is_empty(),
        "Flathub manifest must declare at least one `sources:` entry with a \
         `type:` key; got: {types:?}",
    );
    assert!(
        !types.iter().any(|t| t == "dir"),
        "Flathub manifest must NOT use `type: dir` (that pattern is reserved \
         for `packaging/flatpak/paladin-gtk.yml`'s local packaging dry-run). \
         Flathub builds without access to a local checkout — use `type: git` \
         or `type: archive` instead; got source types: {types:?}",
    );
    assert!(
        types.iter().any(|t| t == "git" || t == "archive"),
        "Flathub manifest's primary source must be `type: git` or `type: \
         archive` so Flathub's builder fetches the tagged release; got source \
         types: {types:?}",
    );
}

#[test]
fn flathub_manifest_source_references_paladin_github_repository() {
    let manifest = read_flathub_manifest();
    assert!(
        manifest.contains(UPSTREAM_REPOSITORY_URL),
        "Flathub manifest's `sources:` `url:` must reference \
         `{UPSTREAM_REPOSITORY_URL}` so the build pulls from the same Git host \
         as the workspace `[workspace.package].repository` field. The exact \
         URL may carry a suffix like `.git` or `/archive/...` — the substring \
         match keeps the contract flexible across the `type: git` / `type: \
         archive` shapes.",
    );
}

// --- flathub.json ------------------------------------------------------------

#[test]
fn flathub_json_exists_at_expected_path() {
    let path = flathub_json_path();
    assert!(
        path.is_file(),
        "expected `flathub.json` at {} — Flathub uses this companion file to \
         scope per-app build options like `only-arches`",
        path.display(),
    );
}

#[test]
fn flathub_json_declares_only_arches_with_x86_64() {
    let json = read_flathub_json();
    // Plain-text check: a real JSON parser would force a serde
    // dep that the deb / rpm / Flatpak tests deliberately avoid.
    // The `only-arches` value is a short JSON array — substring
    // matching keeps the contract precise without a parser.
    assert!(
        json.contains("\"only-arches\""),
        "`flathub.json` must declare `\"only-arches\"` so Flathub scopes the \
         build matrix; got: {json:?}",
    );
    assert!(
        json.contains("\"x86_64\""),
        "`flathub.json` `only-arches` must include \"x86_64\" — the §11.3 / \
         §11.5 native artifact pipeline targets x86_64 baseline. Other \
         architectures land in follow-up commits alongside their native \
         counterparts; got: {json:?}",
    );
}

// --- submission README -------------------------------------------------------

#[test]
fn flathub_submission_readme_exists() {
    let path = flathub_readme_path();
    assert!(
        path.is_file(),
        "expected `packaging/flathub/README.md` at {} — the Milestone 7 \
         checklist requires the submission process to be documented in-tree \
         so filing the actual PR against flathub/flathub is a copy-paste",
        path.display(),
    );
}

#[test]
fn flathub_submission_readme_documents_pr_filing_against_flathub_org() {
    let readme = read_flathub_readme();
    let lowered = readme.to_ascii_lowercase();
    assert!(
        lowered.contains("flathub/flathub"),
        "`packaging/flathub/README.md` must mention `flathub/flathub` — that \
         is the GitHub repo the new-app submission PR is filed against. \
         Without that pointer the documentation does not actually tell the \
         release manager where to send the submission; got: {readme:?}",
    );
    assert!(
        lowered.contains("submission") || lowered.contains("submit"),
        "`packaging/flathub/README.md` must describe how to submit / file the \
         submission; got: {readme:?}",
    );
}

#[test]
fn flathub_submission_readme_documents_signing_inheritance() {
    let readme = read_flathub_readme();
    let lowered = readme.to_ascii_lowercase();
    assert!(
        lowered.contains("sign"),
        "`packaging/flathub/README.md` must mention signing so the release \
         manager knows that Flatpak signing is inherited from Flathub's \
         published key (docs/DESIGN.md §11.4 / §11.6) and that \
         `packaging/sign/sign-artifact.sh` is NOT invoked for the Flatpak \
         output; got: {readme:?}",
    );
    assert!(
        lowered.contains("flathub"),
        "`packaging/flathub/README.md` must mention Flathub explicitly in the \
         signing-inheritance discussion; got: {readme:?}",
    );
}

#[test]
fn flathub_submission_readme_documents_cargo_sources_regeneration() {
    let readme = read_flathub_readme();
    let lowered = readme.to_ascii_lowercase();
    assert!(
        lowered.contains("cargo-sources"),
        "`packaging/flathub/README.md` must document `cargo-sources.json` — \
         the vendored-Cargo-deps file referenced by the manifest that the \
         release pipeline regenerates per release. Without that documentation \
         the release manager cannot reproduce the submission; got: {readme:?}",
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
fn source_types_reads_git_and_archive_entries() {
    let manifest = "\
modules:
  - name: paladin-gtk
    sources:
      - type: git
        url: https://example.invalid/p.git
        tag: v0.2.0
      - type: archive
        url: https://example.invalid/p.tar.gz
      - cargo-sources.json
";
    let types = source_types(manifest);
    assert_eq!(types, vec!["git".to_string(), "archive".to_string()]);
}

#[test]
fn source_types_rejects_dir_type() {
    let manifest = "\
modules:
  - name: paladin-gtk
    sources:
      - type: dir
        path: ../..
";
    let types = source_types(manifest);
    assert_eq!(types, vec!["dir".to_string()]);
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
