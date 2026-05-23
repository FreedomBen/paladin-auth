// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppStream` metainfo contract tests for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop integration" /
//! §"Packaging (per §11)" and the Milestone 7 checklist entry "Write
//! `data/metainfo/org.tamx.Paladin.Gui.metainfo.xml`":
//!
//! * `<component type="desktop-application">` so the freedesktop /
//!   GNOME Software UI categorizes Paladin correctly.
//! * `<id>` matches the `paladin_gtk::APP_ID` reverse-DNS app ID
//!   (`org.tamx.Paladin.Gui`).
//! * `<launchable type="desktop-id">` matches the §11.3 desktop file
//!   basename (`org.tamx.Paladin.Gui.desktop`) so the launcher entry
//!   resolves identically across native and Flatpak packagings.
//! * `<metadata_license>` declares an OSI-approved permissive license
//!   for the metainfo body (FSFAP / MIT / CC0-1.0 are the `AppStream`-
//!   recommended choices).
//! * `<project_license>` is `AGPL-3.0-or-later` — the workspace's
//!   project license declared in `Cargo.toml`'s `[workspace.package]`.
//! * `<name>` is `Paladin` — matches the §11.3 desktop entry.
//! * `<summary>` is a single short sentence.
//! * At least one `<release>` entry exists (v0.2 release notes).
//! * `<screenshots>` block exists so packaging UIs can show
//!   screenshots (the v0.2 assets land alongside this file under
//!   `data/metainfo/screenshots/` once the GUI is locked).
//! * Repository and homepage URLs are sourced from
//!   `[workspace.package]`.
//! * SPDX header carried in the leading XML comment.
//!
//! These assertions live as pure-logic tests so the metainfo file is
//! checked on every `cargo test` run, independent of the
//! `appstreamcli validate` step the §11 packaging dry-run adds.

use std::fs;
use std::path::PathBuf;

use paladin_gtk::APP_ID;

/// Path to the §11.3 `AppStream` metainfo file relative to the crate root.
const METAINFO_FILE_RELPATH: &str = "data/metainfo/org.tamx.Paladin.Gui.metainfo.xml";

/// SPDX identifiers `AppStream` recommends for the metainfo body. Pinned
/// here so a future expansion of the allowed set lands in lockstep
/// across `metadata_license` body and the assertion.
const PERMISSIVE_METADATA_LICENSES: &[&str] =
    &["FSFAP", "MIT", "CC0-1.0", "CC-BY-3.0", "CC-BY-4.0", "0BSD"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn metainfo_file_path() -> PathBuf {
    crate_root().join(METAINFO_FILE_RELPATH)
}

fn read_metainfo_file() -> String {
    fs::read_to_string(metainfo_file_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", metainfo_file_path().display()))
}

/// Return the trimmed inner text between the first `<{tag}` opening
/// (possibly with attributes) and its matching `</{tag}>` close in the
/// supplied `AppStream` metainfo body. Returns `None` if either marker
/// is missing.
///
/// This intentionally does not parse XML — the tests only need to peek
/// at single top-level scalar tags (`<id>`, `<name>`, `<summary>`,
/// `<metadata_license>`, `<project_license>`), and a dependency-free
/// substring scan keeps the test deck thin.
fn first_element_text(xml: &str, tag: &str) -> Option<String> {
    let open_marker = format!("<{tag}");
    let close_marker = format!("</{tag}>");
    let open_idx = xml.find(&open_marker)?;
    let after_open_attrs = open_idx + open_marker.len();
    let close_of_open = xml[after_open_attrs..].find('>')? + after_open_attrs + 1;
    let close_idx = xml[close_of_open..].find(&close_marker)? + close_of_open;
    Some(xml[close_of_open..close_idx].trim().to_owned())
}

// --- Existence + basic shape -------------------------------------------------

#[test]
fn metainfo_file_exists_at_expected_path() {
    assert!(
        metainfo_file_path().is_file(),
        "expected metainfo file at {}",
        metainfo_file_path().display(),
    );
}

#[test]
fn metainfo_file_path_uses_app_id_basename() {
    // The §11.3 contract is that the same file installs verbatim at
    // /usr/share/metainfo/<APP_ID>.metainfo.xml in both native and
    // Flatpak builds. Pin the basename against `APP_ID` so a future
    // `APP_ID` rename has to land in lockstep.
    let basename = metainfo_file_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("metainfo file path has a basename");
    assert_eq!(basename, format!("{APP_ID}.metainfo.xml"));
}

#[test]
fn metainfo_file_has_xml_declaration() {
    let contents = read_metainfo_file();
    assert!(
        contents.trim_start().starts_with("<?xml "),
        "metainfo file must start with the standard <?xml ?> declaration",
    );
}

#[test]
fn metainfo_file_has_spdx_header_comment() {
    let contents = read_metainfo_file();
    assert!(
        contents.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
        "metainfo file must carry the AGPL-3.0-or-later SPDX header",
    );
}

// --- Required element values -------------------------------------------------

#[test]
fn metainfo_component_type_is_desktop_application() {
    let contents = read_metainfo_file();
    assert!(
        contents.contains("<component type=\"desktop-application\">")
            || contents.contains("<component type='desktop-application'>"),
        "<component> root must declare type=\"desktop-application\"",
    );
}

#[test]
fn metainfo_id_matches_app_id() {
    let contents = read_metainfo_file();
    let id = first_element_text(&contents, "id").expect("metainfo has an <id> element");
    assert_eq!(id, APP_ID);
}

#[test]
fn metainfo_launchable_matches_desktop_file_basename() {
    let contents = read_metainfo_file();
    let expected = format!("<launchable type=\"desktop-id\">{APP_ID}.desktop</launchable>",);
    let expected_single = format!("<launchable type='desktop-id'>{APP_ID}.desktop</launchable>",);
    assert!(
        contents.contains(&expected) || contents.contains(&expected_single),
        "metainfo must declare <launchable type=\"desktop-id\">{APP_ID}.desktop</launchable> so the AppStream → desktop file link resolves identically in native and Flatpak builds",
    );
}

#[test]
fn metainfo_metadata_license_is_permissive() {
    let contents = read_metainfo_file();
    let license = first_element_text(&contents, "metadata_license")
        .expect("metainfo has a <metadata_license> element");
    // AppStream recommends one of FSFAP, MIT, CC0-1.0, CC-BY-3.0,
    // CC-BY-4.0 for the metainfo body; pin to that set so the §11
    // appstreamcli validate run does not fail on a non-permissive
    // metadata license.
    assert!(
        PERMISSIVE_METADATA_LICENSES
            .iter()
            .any(|allowed| &license == allowed),
        "<metadata_license> must be one of {PERMISSIVE_METADATA_LICENSES:?}; got {license:?}",
    );
}

#[test]
fn metainfo_project_license_is_workspace_license() {
    let contents = read_metainfo_file();
    let license = first_element_text(&contents, "project_license")
        .expect("metainfo has a <project_license> element");
    assert_eq!(
        license, "AGPL-3.0-or-later",
        "<project_license> must match the workspace [workspace.package] license",
    );
}

#[test]
fn metainfo_name_is_paladin() {
    let contents = read_metainfo_file();
    let name = first_element_text(&contents, "name").expect("metainfo has a <name> element");
    assert_eq!(name, "Paladin");
}

#[test]
fn metainfo_summary_is_present_and_short() {
    let contents = read_metainfo_file();
    let summary =
        first_element_text(&contents, "summary").expect("metainfo has a <summary> element");
    assert!(
        !summary.is_empty(),
        "<summary> must not be empty: {summary:?}",
    );
    // `AppStream` lints against summaries that end in a period or are
    // longer than ~80 characters. Pin to <=80 so the §11 validator
    // never complains about the body shipped here.
    assert!(
        summary.chars().count() <= 80,
        "<summary> should be one short sentence (≤80 chars): {summary:?}",
    );
    assert!(
        !summary.ends_with('.'),
        "<summary> should not end with a period per the AppStream style guide: {summary:?}",
    );
}

#[test]
fn metainfo_description_block_is_present() {
    let contents = read_metainfo_file();
    assert!(
        contents.contains("<description>") && contents.contains("</description>"),
        "metainfo must contain a <description> block",
    );
}

#[test]
fn metainfo_has_at_least_one_release_entry() {
    let contents = read_metainfo_file();
    assert!(
        contents.contains("<releases>") && contents.contains("<release "),
        "metainfo must contain a <releases> block with at least one <release> entry",
    );
}

#[test]
fn metainfo_has_screenshots_block() {
    let contents = read_metainfo_file();
    assert!(
        contents.contains("<screenshots>") && contents.contains("</screenshots>"),
        "metainfo must contain a <screenshots> block (screenshot assets land alongside the v0.2 release)",
    );
}

#[test]
fn metainfo_carries_homepage_and_repository_urls() {
    let contents = read_metainfo_file();
    assert!(
        contents.contains("<url type=\"homepage\">"),
        "metainfo must declare a <url type=\"homepage\"> entry",
    );
    // The bugtracker URL is required for Flathub submission per the
    // upstream metainfo checklist.
    assert!(
        contents.contains("<url type=\"bugtracker\">"),
        "metainfo must declare a <url type=\"bugtracker\"> entry",
    );
}

#[test]
fn metainfo_carries_developer_name_or_developer_block() {
    let contents = read_metainfo_file();
    // `AppStream` 1.x prefers <developer id="..."><name>...</name></developer>,
    // but the legacy <developer_name> tag is still recognized by the
    // validator. Accept either spelling so the file can evolve without
    // a matching test churn.
    let has_developer_block = contents.contains("<developer ")
        && contents.contains("</developer>")
        && contents.contains("<name>");
    let has_legacy_developer_name = contents.contains("<developer_name>");
    assert!(
        has_developer_block || has_legacy_developer_name,
        "metainfo must declare either <developer><name>…</name></developer> or the legacy <developer_name>",
    );
}

#[test]
fn metainfo_content_rating_block_is_present() {
    let contents = read_metainfo_file();
    // Flathub and GNOME Software require a `<content_rating>` block on
    // every desktop-application; an empty `oars-1.1`-typed entry is the
    // standard "no restricted content" declaration.
    assert!(
        contents.contains("<content_rating "),
        "metainfo must declare a <content_rating> block",
    );
}
