// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nfpm` `.rpm` manifest contract tests for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux distribution and
//! signing" and the Milestone 7 packaging checklist entry "Add
//! `packaging/rpm/paladin-gtk.yaml` (`nfpm`)":
//!
//! * Installs the same payload as the matching
//!   `packaging/deb/paladin-gtk.yaml`: `/usr/bin/paladin-gtk`, the
//!   freedesktop desktop entry at `/usr/share/applications/`, the
//!   `AppStream` metainfo at `/usr/share/metainfo/`, and the hicolor
//!   icon set at `/usr/share/icons/hicolor/`. The installed layout is
//!   identical so a Fedora user and a Debian user see the same
//!   filesystem footprint after `dnf install` / `apt install`.
//! * Declares the Fedora dependency names `gtk4 >= 4.16` and
//!   `libadwaita >= 1.6` — the same `4.16` / `1.6` baselines the
//!   build-time `gtk4` (`v4_16`) / `libadwaita` (`v1_6`) crate
//!   features enforce, just spelled with the Fedora package
//!   names instead of the Debian `libgtk-4-1` /
//!   `libadwaita-1-0` ones.
//! * Declares NO `scripts:` section, for the same reason the `.deb`
//!   manifest omits one: package state never touches user vault
//!   state.
//! * Inherits `version` / `description` / `homepage` / `license` /
//!   `maintainer` from the workspace `Cargo.toml`'s
//!   `[workspace.package]` table or from build-time environment
//!   variables (e.g. `${PALADIN_VERSION}`).
//!
//! Tests intentionally read the manifest as plain text — no
//! `serde_yaml` dependency lands here. The implementation reuses the
//! same parser helpers from
//! `tests/packaging_deb_nfpm_manifest_logic.rs`, copied module-local
//! so each tests file stays self-contained per the workspace
//! convention (no shared `tests/common/` for paladin-gtk).

use std::fs;
use std::path::PathBuf;

/// Path to the `nfpm` `.rpm` manifest, relative to the workspace root.
const RPM_MANIFEST_RELPATH: &str = "packaging/rpm/paladin-gtk.yaml";

/// Required `depends:` entries using the Fedora dependency names.
/// `nfpm` writes these verbatim into the RPM's `Requires:` headers.
///
/// Note the absence of parentheses — RPM's spec syntax accepts
/// `pkg >= version` directly, unlike Debian's `pkg (>= version)`.
const REQUIRED_RPM_DEPENDS: &[&str] = &["gtk4 >= 4.16", "libadwaita >= 1.6"];

/// `dst` paths the manifest MUST install, matching the `.deb`
/// manifest byte-for-byte so the installed layout is portable
/// across distributions.
const REQUIRED_INSTALL_DESTINATIONS: &[&str] = &[
    "/usr/bin/paladin-gtk",
    "/usr/share/applications/org.tamx.Paladin.Gui.desktop",
    "/usr/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml",
    "/usr/share/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg",
    "/usr/share/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg",
    "/usr/share/icons/hicolor/16x16/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/24x24/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/32x32/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/48x48/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/64x64/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/128x128/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/256x256/apps/org.tamx.Paladin.Gui.png",
    "/usr/share/icons/hicolor/512x512/apps/org.tamx.Paladin.Gui.png",
];

/// `src` paths each `dst` MUST source from, in the same order as
/// `REQUIRED_INSTALL_DESTINATIONS`. Matches the `.deb` manifest's
/// sources verbatim so the two formats stage the same files.
const REQUIRED_INSTALL_SOURCES: &[&str] = &[
    "target/release/paladin-gtk",
    "crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop",
    "crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml",
    "crates/paladin-gtk/data/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg",
    "crates/paladin-gtk/data/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg",
    "crates/paladin-gtk/data/icons/hicolor/16x16/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/24x24/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/32x32/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/48x48/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/64x64/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/128x128/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/256x256/apps/org.tamx.Paladin.Gui.png",
    "crates/paladin-gtk/data/icons/hicolor/512x512/apps/org.tamx.Paladin.Gui.png",
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

fn rpm_manifest_path() -> PathBuf {
    workspace_root().join(RPM_MANIFEST_RELPATH)
}

fn read_rpm_manifest() -> String {
    fs::read_to_string(rpm_manifest_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", rpm_manifest_path().display()))
}

fn top_level_scalar(manifest: &str, key: &str) -> Option<String> {
    for raw_line in manifest.lines() {
        let line = strip_trailing_comment(raw_line);
        if !line.starts_with(&format!("{key}:")) {
            continue;
        }
        let rhs = &line[key.len() + 1..];
        return Some(rhs.trim().trim_matches(['"', '\'']).to_string());
    }
    None
}

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

fn contents_src_dst_pairs(manifest: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if strip_trailing_comment(lines[i]) == "contents:" {
            i += 1;
            break;
        }
        i += 1;
    }
    let mut current_src: Option<String> = None;
    let mut current_dst: Option<String> = None;
    while i < lines.len() {
        let raw = lines[i];
        if !raw.starts_with(' ') && !raw.starts_with('\t') && !raw.is_empty() {
            break;
        }
        let trimmed = strip_trailing_comment(raw).trim_end();
        let stripped = trimmed.trim_start();
        if let Some(after_dash) = stripped.strip_prefix("- ") {
            if current_src.is_some() || current_dst.is_some() {
                out.push((
                    current_src.take().unwrap_or_default(),
                    current_dst.take().unwrap_or_default(),
                ));
            }
            absorb_kv(after_dash, &mut current_src, &mut current_dst);
        } else {
            absorb_kv(stripped, &mut current_src, &mut current_dst);
        }
        i += 1;
    }
    if current_src.is_some() || current_dst.is_some() {
        out.push((
            current_src.unwrap_or_default(),
            current_dst.unwrap_or_default(),
        ));
    }
    out
}

fn absorb_kv(token: &str, src: &mut Option<String>, dst: &mut Option<String>) {
    if let Some(rest) = token.strip_prefix("src:") {
        *src = Some(rest.trim().trim_matches(['"', '\'']).to_string());
    } else if let Some(rest) = token.strip_prefix("dst:") {
        *dst = Some(rest.trim().trim_matches(['"', '\'']).to_string());
    }
}

fn strip_trailing_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

// --- tests -------------------------------------------------------------------

#[test]
fn rpm_manifest_exists_at_expected_path() {
    let path = rpm_manifest_path();
    assert!(
        path.is_file(),
        "expected nfpm .rpm manifest at {} — Milestone 7 packaging \
         checklist requires `packaging/rpm/paladin-gtk.yaml`",
        path.display(),
    );
}

#[test]
fn rpm_manifest_starts_with_spdx_license_header() {
    let manifest = read_rpm_manifest();
    let first_meaningful_line = manifest
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    assert!(
        first_meaningful_line.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
        "rpm nfpm manifest must lead with an SPDX-License-Identifier comment matching the \
         workspace AGPL-3.0-or-later license; first line was {first_meaningful_line:?}",
    );
}

#[test]
fn rpm_manifest_declares_package_name_paladin_gtk() {
    let manifest = read_rpm_manifest();
    let name =
        top_level_scalar(&manifest, "name").expect("rpm nfpm manifest has a top-level `name:` key");
    assert_eq!(
        name, "paladin-gtk",
        "rpm package name must be `paladin-gtk` so the published artifact matches the binary \
         and the workspace member name; got {name:?}",
    );
}

#[test]
fn rpm_manifest_declares_linux_platform_and_amd64_arch() {
    let manifest = read_rpm_manifest();
    let platform = top_level_scalar(&manifest, "platform")
        .expect("rpm nfpm manifest has a top-level `platform:` key");
    assert_eq!(
        platform, "linux",
        "rpm nfpm manifest `platform:` must be `linux`; got {platform:?}",
    );
    let arch =
        top_level_scalar(&manifest, "arch").expect("rpm nfpm manifest has a top-level `arch:` key");
    assert_eq!(
        arch, "amd64",
        "rpm nfpm manifest `arch:` must be `amd64` (nfpm normalizes to `x86_64` for RPM \
         output) — Milestone 7 targets x86_64 only; got {arch:?}",
    );
}

#[test]
fn rpm_manifest_declares_workspace_license() {
    let manifest = read_rpm_manifest();
    let license = top_level_scalar(&manifest, "license")
        .expect("rpm nfpm manifest has a top-level `license:` key");
    assert_eq!(
        license, "AGPL-3.0-or-later",
        "rpm nfpm manifest `license:` must match the workspace [workspace.package] license; \
         got {license:?}",
    );
}

#[test]
fn rpm_manifest_declares_workspace_homepage() {
    let manifest = read_rpm_manifest();
    let homepage = top_level_scalar(&manifest, "homepage")
        .expect("rpm nfpm manifest has a top-level `homepage:` key");
    assert_eq!(
        homepage, "https://paladin.tamx.org",
        "rpm nfpm manifest `homepage:` must match the workspace [workspace.package] homepage; \
         got {homepage:?}",
    );
}

#[test]
fn rpm_manifest_declares_required_runtime_depends_with_fedora_package_names() {
    let manifest = read_rpm_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    let mut missing = Vec::new();
    for required in REQUIRED_RPM_DEPENDS {
        if !depends.iter().any(|d| d == required) {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "rpm nfpm manifest `depends:` must include each of {REQUIRED_RPM_DEPENDS:?} — Fedora \
         package names without Debian-style parentheses around the version constraint; \
         missing: {missing:?}; got: {depends:?}",
    );
}

#[test]
fn rpm_manifest_declares_no_extra_depends_beyond_baseline_set() {
    let manifest = read_rpm_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    let extras: Vec<&str> = depends
        .iter()
        .map(String::as_str)
        .filter(|d| !REQUIRED_RPM_DEPENDS.contains(d))
        .collect();
    assert!(
        extras.is_empty(),
        "rpm nfpm manifest `depends:` must declare ONLY the Milestone 7 baselines \
         {REQUIRED_RPM_DEPENDS:?}; found unexpected entries: {extras:?}. If a new runtime \
         dep is genuinely required, update docs/IMPLEMENTATION_PLAN_04_GTK.md §11.3 first and \
         add it to REQUIRED_RPM_DEPENDS in this test.",
    );
}

#[test]
fn rpm_manifest_does_not_use_debian_package_names() {
    // A common authoring slip is to copy the .deb depends list
    // verbatim into the .rpm manifest. Pin the negation explicitly
    // so a future merge or refactor that loses the rename gets a
    // pointed error message rather than just a missing-Fedora-name
    // failure.
    let manifest = read_rpm_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    for d in &depends {
        assert!(
            !d.starts_with("libgtk-4-1"),
            "rpm nfpm manifest `depends:` must not use the Debian name `libgtk-4-1` — \
             Fedora uses `gtk4`; found: {d:?}",
        );
        assert!(
            !d.starts_with("libadwaita-1-0"),
            "rpm nfpm manifest `depends:` must not use the Debian name `libadwaita-1-0` — \
             Fedora uses `libadwaita`; found: {d:?}",
        );
    }
}

#[test]
fn rpm_manifest_installs_every_required_destination() {
    let manifest = read_rpm_manifest();
    let pairs = contents_src_dst_pairs(&manifest);
    let destinations: Vec<&str> = pairs.iter().map(|(_src, dst)| dst.as_str()).collect();
    let mut missing = Vec::new();
    for required in REQUIRED_INSTALL_DESTINATIONS {
        if !destinations.iter().any(|d| d == required) {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "rpm nfpm manifest `contents:` must install each of \
         {REQUIRED_INSTALL_DESTINATIONS:?}; missing: {missing:?}; got destinations: \
         {destinations:?}",
    );
}

#[test]
fn rpm_manifest_sources_each_install_from_the_expected_in_tree_path() {
    let manifest = read_rpm_manifest();
    let pairs = contents_src_dst_pairs(&manifest);
    for (expected_src, expected_dst) in REQUIRED_INSTALL_SOURCES
        .iter()
        .zip(REQUIRED_INSTALL_DESTINATIONS.iter())
    {
        let actual_src = pairs
            .iter()
            .find(|(_src, dst)| dst == expected_dst)
            .map_or_else(
                || panic!("rpm nfpm manifest is missing dst {expected_dst:?}"),
                |(src, _dst)| src.as_str(),
            );
        assert_eq!(
            actual_src, *expected_src,
            "rpm nfpm manifest `contents:` entry for dst {expected_dst:?} must source from \
             {expected_src:?}; got src {actual_src:?}",
        );
    }
}

#[test]
fn rpm_manifest_in_tree_sources_all_exist_under_the_workspace() {
    let workspace = workspace_root();
    let mut missing = Vec::new();
    for src in REQUIRED_INSTALL_SOURCES {
        if src.starts_with("target/") {
            continue;
        }
        let full = workspace.join(src);
        if !full.is_file() {
            missing.push((*src, full));
        }
    }
    assert!(
        missing.is_empty(),
        "rpm nfpm manifest references in-tree sources that do not exist on disk — \
         renames must land in lockstep with the manifest: {missing:?}",
    );
}

#[test]
fn rpm_manifest_has_no_maintainer_scripts_section() {
    let manifest = read_rpm_manifest();
    for raw_line in manifest.lines() {
        let line = strip_trailing_comment(raw_line);
        assert!(
            !line.starts_with("scripts:"),
            "rpm nfpm manifest must NOT declare a `scripts:` section — Milestone 7 forbids \
             maintainer scripts on the .rpm; found: {raw_line:?}",
        );
    }
}

#[test]
fn rpm_manifest_binary_install_uses_executable_mode() {
    let manifest = read_rpm_manifest();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut binary_block_start: Option<usize> = None;
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = strip_trailing_comment(raw).trim();
        if trimmed == "dst: /usr/bin/paladin-gtk" || trimmed == "dst: \"/usr/bin/paladin-gtk\"" {
            binary_block_start = Some(idx);
            break;
        }
    }
    let start = binary_block_start.expect(
        "rpm nfpm manifest is missing the /usr/bin/paladin-gtk dst entry — covered by \
         rpm_manifest_installs_every_required_destination, but re-asserted here so the \
         executable-mode check has something to anchor against",
    );
    let mut found_mode_0755 = false;
    let mut j = start;
    while j < lines.len() {
        let raw = lines[j];
        if j > start {
            let stripped = strip_trailing_comment(raw).trim_start();
            if stripped.starts_with("- ")
                || (!raw.starts_with(' ') && !raw.starts_with('\t') && !raw.trim().is_empty())
            {
                break;
            }
        }
        if strip_trailing_comment(raw).contains("mode: 0755") {
            found_mode_0755 = true;
            break;
        }
        j += 1;
    }
    assert!(
        found_mode_0755,
        "rpm nfpm manifest must set `mode: 0755` on the /usr/bin/paladin-gtk entry so the \
         installed binary is executable; nfpm defaults to 0644 when `mode:` is omitted",
    );
}

#[test]
fn rpm_manifest_install_layout_matches_deb_manifest_layout() {
    // Cross-format guarantee: the .rpm and .deb manifests stage
    // identical filesystem destinations so users get the same
    // layout regardless of which packaging they install from. Pin
    // this directly so a future drift in either manifest fails the
    // shared-layout test rather than only the per-format checks.
    let rpm = read_rpm_manifest();
    let rpm_pairs = contents_src_dst_pairs(&rpm);
    let rpm_destinations: Vec<&str> = rpm_pairs.iter().map(|(_src, dst)| dst.as_str()).collect();

    let deb_path = workspace_root().join("packaging/deb/paladin-gtk.yaml");
    let deb = fs::read_to_string(&deb_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", deb_path.display()));
    let deb_pairs = contents_src_dst_pairs(&deb);
    let deb_destinations: Vec<&str> = deb_pairs.iter().map(|(_src, dst)| dst.as_str()).collect();

    assert_eq!(
        rpm_destinations, deb_destinations,
        "rpm and deb nfpm manifests must install the same filesystem layout so Fedora and \
         Debian users see an identical footprint; rpm: {rpm_destinations:?}; deb: \
         {deb_destinations:?}",
    );
}

// --- helper self-tests -------------------------------------------------------

#[test]
fn top_level_scalar_reads_quoted_and_unquoted_values() {
    let manifest = "\
name: paladin-gtk
arch: \"amd64\"
platform: 'linux'
";
    assert_eq!(
        top_level_scalar(manifest, "name").as_deref(),
        Some("paladin-gtk"),
    );
    assert_eq!(top_level_scalar(manifest, "arch").as_deref(), Some("amd64"));
    assert_eq!(
        top_level_scalar(manifest, "platform").as_deref(),
        Some("linux"),
    );
    assert_eq!(top_level_scalar(manifest, "missing"), None);
}

#[test]
fn top_level_sequence_scalars_reads_block_list_entries() {
    let manifest = "\
depends:
  - gtk4 >= 4.16
  - libadwaita >= 1.6
contents:
  - src: a
";
    let depends = top_level_sequence_scalars(manifest, "depends");
    assert_eq!(
        depends,
        vec!["gtk4 >= 4.16".to_string(), "libadwaita >= 1.6".to_string()],
    );
    assert!(top_level_sequence_scalars(manifest, "missing").is_empty());
}

#[test]
fn contents_src_dst_pairs_extracts_canonical_entries() {
    let manifest = "\
contents:
  - src: target/release/paladin-gtk
    dst: /usr/bin/paladin-gtk
    file_info:
      mode: 0755
  - src: crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop
    dst: /usr/share/applications/org.tamx.Paladin.Gui.desktop
";
    let pairs = contents_src_dst_pairs(manifest);
    assert_eq!(
        pairs,
        vec![
            (
                "target/release/paladin-gtk".to_string(),
                "/usr/bin/paladin-gtk".to_string(),
            ),
            (
                "crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop".to_string(),
                "/usr/share/applications/org.tamx.Paladin.Gui.desktop".to_string(),
            ),
        ],
    );
}

#[test]
fn strip_trailing_comment_drops_inline_comment() {
    assert_eq!(
        strip_trailing_comment("arch: amd64 # x86_64 only"),
        "arch: amd64 "
    );
    assert_eq!(strip_trailing_comment("# header"), "");
    assert_eq!(strip_trailing_comment("no comment here"), "no comment here");
}
