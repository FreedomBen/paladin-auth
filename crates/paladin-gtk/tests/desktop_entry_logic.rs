// SPDX-License-Identifier: AGPL-3.0-or-later

//! Desktop-entry contract tests for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop integration" and
//! the Milestone 7 checklist entry "Write
//! `data/org.tamx.Paladin.Gui.desktop`":
//!
//! * `Name=Paladin`
//! * `Icon=org.tamx.Paladin.Gui` (the §11.4 app ID — same string
//!   `RelmApp::new(APP_ID)` consumes and the hicolor install layout
//!   resolves)
//! * `StartupWMClass=org.tamx.Paladin.Gui` (so window-to-launcher
//!   mapping works identically in native and Flatpak installs)
//! * `Categories=Utility;Security;`
//! * `Keywords=` includes the security / authenticator vocabulary
//!   freedesktop launchers index on
//! * `Exec=paladin-gtk` with **no** `%F` / `%U` / `%f` / `%u` file or
//!   URI placeholders — v0.2 does not accept positional file or URI
//!   arguments; imports start inside `ImportDialog`
//!
//! These assertions live as pure-logic tests so the desktop entry is
//! checked on every `cargo test` run, independent of the
//! `desktop-file-validate` step the §11 packaging dry-run adds.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use paladin_gtk::APP_ID;

/// Path to the §11.3 desktop entry file relative to the crate root.
const DESKTOP_FILE_RELPATH: &str = "data/org.tamx.Paladin.Gui.desktop";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn desktop_file_path() -> PathBuf {
    crate_root().join(DESKTOP_FILE_RELPATH)
}

fn read_desktop_file() -> String {
    fs::read_to_string(desktop_file_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", desktop_file_path().display()))
}

/// Parse the `[Desktop Entry]` section of a freedesktop `.desktop` file
/// into a key → value map.
///
/// The freedesktop Desktop Entry Specification allows multiple groups
/// (`[Desktop Action ...]` blocks, for example); for v0.2 the GUI ships
/// a single `[Desktop Entry]` group, so this parser intentionally only
/// reads keys until the next `[...]` group header (or end of file).
fn parse_desktop_entry_section(contents: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut in_section = false;
    for raw_line in contents.lines() {
        let line = raw_line.trim_end_matches(['\r']);
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_section = line == "[Desktop Entry]";
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            out.insert(key.trim().to_owned(), value.trim().to_owned());
        }
    }
    out
}

// --- Existence + basic shape -------------------------------------------------

#[test]
fn desktop_file_exists_at_expected_path() {
    assert!(
        desktop_file_path().is_file(),
        "expected desktop file at {}",
        desktop_file_path().display(),
    );
}

#[test]
fn desktop_file_path_uses_app_id_basename() {
    // The §11.3 contract is that the same filename installs verbatim
    // under `/usr/share/applications/<APP_ID>.desktop` in both native
    // and Flatpak builds so the AppStream `<launchable>` reference
    // resolves identically. Pin the basename against `APP_ID` so a
    // future rename of either has to land in lockstep.
    let basename = desktop_file_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("desktop file path has a basename");
    assert_eq!(basename, format!("{APP_ID}.desktop"));
}

#[test]
fn desktop_file_starts_with_desktop_entry_group_header() {
    let contents = read_desktop_file();
    let first = contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .expect("desktop file has at least one non-comment, non-blank line");
    assert_eq!(
        first, "[Desktop Entry]",
        "first non-comment, non-blank line must be the [Desktop Entry] group header",
    );
}

#[test]
fn desktop_file_has_spdx_header_comment() {
    let contents = read_desktop_file();
    assert!(
        contents
            .lines()
            .take_while(|line| line.starts_with('#'))
            .any(|line| line.contains("SPDX-License-Identifier: AGPL-3.0-or-later")),
        "desktop file must carry the AGPL-3.0-or-later SPDX header before the [Desktop Entry] group",
    );
}

// --- Required field values ---------------------------------------------------

#[test]
fn desktop_entry_type_is_application() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    assert_eq!(entry.get("Type").map(String::as_str), Some("Application"));
}

#[test]
fn desktop_entry_name_is_paladin() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    assert_eq!(entry.get("Name").map(String::as_str), Some("Paladin"));
}

#[test]
fn desktop_entry_icon_matches_app_id() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    assert_eq!(entry.get("Icon").map(String::as_str), Some(APP_ID));
}

#[test]
fn desktop_entry_startup_wm_class_matches_app_id() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    assert_eq!(
        entry.get("StartupWMClass").map(String::as_str),
        Some(APP_ID),
    );
}

#[test]
fn desktop_entry_exec_is_paladin_gtk_binary_name() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    assert_eq!(entry.get("Exec").map(String::as_str), Some("paladin-gtk"));
}

#[test]
fn desktop_entry_exec_has_no_file_or_uri_placeholders() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    let exec = entry.get("Exec").expect("Exec key present");
    // No MIME type or URI handler is registered; imports start inside
    // `ImportDialog`, so the launcher must never pass file or URI
    // arguments. Reject every freedesktop placeholder.
    for placeholder in [
        "%f", "%F", "%u", "%U", "%d", "%D", "%n", "%N", "%v", "%m", "%k",
    ] {
        assert!(
            !exec.contains(placeholder),
            "Exec must not carry the {placeholder} placeholder: {exec:?}",
        );
    }
}

#[test]
fn desktop_entry_categories_includes_utility_and_security() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    let categories = entry.get("Categories").expect("Categories key present");
    let split: Vec<&str> = categories.split(';').filter(|s| !s.is_empty()).collect();
    assert!(
        split.contains(&"Utility"),
        "Categories must contain Utility: {categories:?}",
    );
    assert!(
        split.contains(&"Security"),
        "Categories must contain Security: {categories:?}",
    );
    assert!(
        categories.ends_with(';'),
        "Categories must end with a trailing semicolon per the Desktop Entry spec: {categories:?}",
    );
}

#[test]
fn desktop_entry_keywords_covers_security_authenticator_vocabulary() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    let keywords = entry.get("Keywords").expect("Keywords key present");
    let lowered = keywords.to_lowercase();
    // The launcher's search index uses these terms to surface Paladin
    // when users type security or authenticator vocabulary. Verify the
    // most discoverable terms are present so a launcher search for
    // "otp", "totp", "hotp", or "authenticator" finds Paladin.
    for needle in ["otp", "totp", "hotp", "authenticator", "2fa"] {
        assert!(
            lowered.contains(needle),
            "Keywords must mention {needle:?}: {keywords:?}",
        );
    }
    assert!(
        keywords.ends_with(';'),
        "Keywords must end with a trailing semicolon per the Desktop Entry spec: {keywords:?}",
    );
}

#[test]
fn desktop_entry_terminal_is_false() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    assert_eq!(entry.get("Terminal").map(String::as_str), Some("false"));
}

#[test]
fn desktop_entry_has_a_summary_comment_field() {
    let entry = parse_desktop_entry_section(&read_desktop_file());
    let comment = entry
        .get("Comment")
        .expect("Comment summary field present so launchers can render a tooltip");
    assert!(
        !comment.trim().is_empty(),
        "Comment must not be empty: {comment:?}",
    );
}

// --- Validation rules tied to the AppStream metainfo file --------------------

#[test]
fn desktop_entry_basename_matches_appstream_launchable_filename() {
    // The §11 packaging dry-run validates that AppStream's
    // `<launchable type="desktop-id">org.tamx.Paladin.Gui.desktop</launchable>`
    // resolves to the file installed at
    // `/usr/share/applications/<basename>`. The basename derives from
    // `APP_ID` here, so a future `APP_ID` change ripples through the
    // launchable reference automatically.
    let expected = format!("{APP_ID}.desktop");
    let basename = desktop_file_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("desktop file path has a basename");
    assert_eq!(basename, expected);
}
