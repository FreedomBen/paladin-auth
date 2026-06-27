// SPDX-License-Identifier: AGPL-3.0-or-later

//! Workspace-metadata inheritance contract tests for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Milestone 7 packaging section,
//! `crates/paladin-auth-gtk/Cargo.toml` must inherit `description`,
//! `repository`, `homepage`, `license`, `edition`, and `rust-version`
//! from the workspace `[workspace.package]` table (so a single bump in
//! the workspace manifest propagates through every published artifact
//! — `.deb`, `.rpm`, Flatpak, `AppImage`), and must declare the binary-
//! specific `keywords` / `categories` locally so the GUI binary's
//! crates.io facets stay distinct from the CLI / TUI / core ones.
//!
//! These tests scan both manifests as plain text — no `toml` parser
//! dependency lands here, mirroring `tests/thinness.rs` and
//! `tests/metainfo_logic.rs`. A future drift in either file fails the
//! relevant test immediately so the packaging contract stays auditable
//! from `cargo test --workspace --all-targets`.

use std::fs;
use std::path::PathBuf;

/// Fields the `paladin-auth-gtk` package MUST inherit from
/// `[workspace.package]` via the `<field>.workspace = true` form.
const INHERITED_FIELDS: &[&str] = &[
    "version",
    "edition",
    "rust-version",
    "license",
    "repository",
    "homepage",
    "description",
];

/// Binary-specific facets the `paladin-auth-gtk` package MUST declare
/// locally (NOT inherit). Listed as the exact expected literal so a
/// future drift away from the GUI-binary identity (e.g. losing the
/// `"gtk"` keyword or the `"gui"` category) is caught immediately.
const LOCAL_KEYWORDS: &[&str] = &["otp", "totp", "hotp", "authenticator", "gtk"];
const LOCAL_CATEGORIES: &[&str] = &["gui", "authentication"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    // `paladin-auth-gtk` lives at `<workspace>/crates/paladin-auth-gtk`, so two
    // `parent()` hops land on the workspace root regardless of where
    // `cargo test` was invoked from.
    let crate_dir = crate_root();
    crate_dir
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| panic!("crate_root has no grandparent: {}", crate_dir.display()))
        .to_path_buf()
}

fn read_crate_manifest() -> String {
    let path = crate_root().join("Cargo.toml");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_workspace_manifest() -> String {
    let path = workspace_root().join("Cargo.toml");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

/// Extract the text of the `[package]` section from a crate manifest
/// (everything from the `[package]` header up to the next `[` header
/// at column zero, or the end of file).
fn package_section(manifest: &str) -> &str {
    section(manifest, "[package]")
}

/// Extract the text of the `[workspace.package]` section from the
/// workspace manifest, using the same column-zero header convention as
/// `package_section`.
fn workspace_package_section(manifest: &str) -> &str {
    section(manifest, "[workspace.package]")
}

fn section<'a>(manifest: &'a str, header: &str) -> &'a str {
    let start = manifest
        .find(&format!("{header}\n"))
        .or_else(|| manifest.find(header))
        .unwrap_or_else(|| panic!("manifest has no `{header}` header"));
    let after_header = start + header.len();
    let tail = &manifest[after_header..];
    // Find the next column-zero `[…]` header. Scanning line-by-line
    // (rather than `find("\n[")`) keeps this robust against headers
    // that contain a `.` (e.g. `[workspace.package]`).
    let mut cut: Option<usize> = None;
    let mut cursor = 0usize;
    for line in tail.split_inclusive('\n') {
        let trimmed_start = line.trim_start();
        if trimmed_start.starts_with('[') && line.starts_with('[') && cursor != 0 {
            cut = Some(cursor);
            break;
        }
        cursor += line.len();
    }
    match cut {
        Some(end) => &manifest[start..after_header + end],
        None => &manifest[start..],
    }
}

/// Return `true` if `field` is declared as `<field>.workspace = true`
/// in `package_section`, allowing arbitrary inner whitespace around
/// the `=` and a trailing comment.
fn declares_workspace_inheritance(package_section: &str, field: &str) -> bool {
    for raw_line in package_section.lines() {
        let line = strip_trailing_comment(raw_line).trim();
        let prefix = format!("{field}.workspace");
        if let Some(rest) = line.strip_prefix(&prefix) {
            let rest = rest.trim_start();
            if let Some(rhs) = rest.strip_prefix('=') {
                if rhs.trim() == "true" {
                    return true;
                }
            }
        }
    }
    false
}

/// Return `true` if `field` is declared as a *local* scalar / array
/// in `package_section` — i.e. `field = <value>` without a
/// `.workspace = true` form. Used to assert that `keywords` /
/// `categories` are NOT mistakenly inherited.
fn declares_local_field(package_section: &str, field: &str) -> bool {
    for raw_line in package_section.lines() {
        let line = strip_trailing_comment(raw_line).trim();
        if line.starts_with(&format!("{field} ")) || line.starts_with(&format!("{field}=")) {
            // Distinguish from `field.workspace = true` (which would be
            // caught by `declares_workspace_inheritance` instead).
            if !line.starts_with(&format!("{field}.workspace")) {
                return true;
            }
        }
    }
    false
}

/// Parse a TOML array literal of strings, returning the list of
/// string values. Tolerates whitespace and trailing commas. Panics
/// with a descriptive message if the array is malformed — that means
/// the manifest is broken, which is exactly what the test should
/// surface.
fn parse_string_array(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or_else(|| panic!("expected a `[..]` array literal, got {value:?}"));
    let mut out = Vec::new();
    for raw in inner.split(',') {
        let piece = raw.trim();
        if piece.is_empty() {
            continue;
        }
        let s = piece
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or_else(|| panic!("expected a quoted string in array, got {piece:?}"));
        out.push(s.to_string());
    }
    out
}

/// Find the RHS of the first `<field> = <rhs>` line in
/// `package_section`. Returns `None` if the field is not declared
/// locally. Used to read out `keywords` / `categories` literals.
fn local_field_rhs(package_section: &str, field: &str) -> Option<String> {
    for raw_line in package_section.lines() {
        let line = strip_trailing_comment(raw_line).trim();
        if line.starts_with(&format!("{field}.workspace")) {
            continue;
        }
        let prefix_eq = format!("{field} =");
        let prefix_tight = format!("{field}=");
        let rhs = if let Some(rest) = line.strip_prefix(&prefix_eq) {
            Some(rest.trim().to_string())
        } else {
            line.strip_prefix(&prefix_tight)
                .map(|rest| rest.trim().to_string())
        };
        if rhs.is_some() {
            return rhs;
        }
    }
    None
}

fn strip_trailing_comment(line: &str) -> &str {
    // Manifest values used here never embed `#` inside quoted strings,
    // so a naive `find('#')` is sufficient and matches the comment-
    // stripping done in `tests/thinness.rs` / `tests/metainfo_logic.rs`.
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

// --- tests -------------------------------------------------------------------

#[test]
fn crate_manifest_inherits_required_fields_from_workspace_package() {
    let manifest = read_crate_manifest();
    let pkg = package_section(&manifest);
    let mut missing = Vec::new();
    for field in INHERITED_FIELDS {
        if !declares_workspace_inheritance(pkg, field) {
            missing.push(*field);
        }
    }
    assert!(
        missing.is_empty(),
        "paladin-auth-gtk Cargo.toml [package] must inherit each of {INHERITED_FIELDS:?} \
         from [workspace.package] via `<field>.workspace = true`; missing: {missing:?}",
    );
}

#[test]
fn crate_manifest_declares_keywords_locally_with_expected_values() {
    let manifest = read_crate_manifest();
    let pkg = package_section(&manifest);
    assert!(
        declares_local_field(pkg, "keywords"),
        "paladin-auth-gtk Cargo.toml [package] must declare `keywords` locally — \
         binary-specific facets do not belong on [workspace.package]",
    );
    let rhs = local_field_rhs(pkg, "keywords")
        .unwrap_or_else(|| panic!("keywords field present but RHS unreadable"));
    let parsed = parse_string_array(&rhs);
    assert_eq!(
        parsed.iter().map(String::as_str).collect::<Vec<_>>(),
        LOCAL_KEYWORDS,
        "paladin-auth-gtk keywords must be the GUI-binary set {LOCAL_KEYWORDS:?}; \
         got {parsed:?}",
    );
}

#[test]
fn crate_manifest_declares_categories_locally_with_expected_values() {
    let manifest = read_crate_manifest();
    let pkg = package_section(&manifest);
    assert!(
        declares_local_field(pkg, "categories"),
        "paladin-auth-gtk Cargo.toml [package] must declare `categories` locally — \
         binary-specific facets do not belong on [workspace.package]",
    );
    let rhs = local_field_rhs(pkg, "categories")
        .unwrap_or_else(|| panic!("categories field present but RHS unreadable"));
    let parsed = parse_string_array(&rhs);
    assert_eq!(
        parsed.iter().map(String::as_str).collect::<Vec<_>>(),
        LOCAL_CATEGORIES,
        "paladin-auth-gtk categories must be the GUI-binary set {LOCAL_CATEGORIES:?}; \
         got {parsed:?}",
    );
}

#[test]
fn crate_manifest_does_not_inherit_keywords_or_categories_from_workspace() {
    // Cargo's workspace-inheritance form for `keywords` / `categories`
    // would be `keywords.workspace = true`. Pin that this is NOT used:
    // binary-specific facets must live on the binary, not the
    // workspace, so each binary published from this workspace gets the
    // crates.io facet set that actually matches its UI surface.
    let manifest = read_crate_manifest();
    let pkg = package_section(&manifest);
    assert!(
        !declares_workspace_inheritance(pkg, "keywords"),
        "paladin-auth-gtk Cargo.toml [package] must NOT use \
         `keywords.workspace = true` — binary-specific keywords must be local",
    );
    assert!(
        !declares_workspace_inheritance(pkg, "categories"),
        "paladin-auth-gtk Cargo.toml [package] must NOT use \
         `categories.workspace = true` — binary-specific categories must be local",
    );
}

#[test]
fn workspace_manifest_supplies_each_inherited_field() {
    // The crate manifest's `*.workspace = true` declarations only
    // resolve cleanly if the workspace root actually defines each
    // field on `[workspace.package]`. Pin that contract end-to-end so
    // a bad edit to the workspace manifest fails this test (and not
    // just `cargo build`) — and the failure message points at the
    // packaging-inheritance milestone instead of a generic resolver
    // error.
    let manifest = read_workspace_manifest();
    let ws_pkg = workspace_package_section(&manifest);
    let mut missing = Vec::new();
    for field in INHERITED_FIELDS {
        let prefix_eq = format!("{field} =");
        let prefix_tight = format!("{field}=");
        let present = ws_pkg.lines().any(|raw| {
            let line = strip_trailing_comment(raw).trim();
            line.starts_with(&prefix_eq) || line.starts_with(&prefix_tight)
        });
        if !present {
            missing.push(*field);
        }
    }
    assert!(
        missing.is_empty(),
        "[workspace.package] in the workspace Cargo.toml must declare each of \
         {INHERITED_FIELDS:?} so the paladin-auth-gtk crate's inheritance resolves; \
         missing: {missing:?}",
    );
}

// --- helper self-tests -------------------------------------------------------

#[test]
fn declares_workspace_inheritance_accepts_canonical_form() {
    let snippet = "[package]\nname = \"x\"\nversion.workspace = true\n";
    assert!(declares_workspace_inheritance(snippet, "version"));
    assert!(!declares_workspace_inheritance(snippet, "edition"));
}

#[test]
fn declares_workspace_inheritance_rejects_non_true_rhs() {
    let snippet = "[package]\nversion.workspace = false\n";
    assert!(!declares_workspace_inheritance(snippet, "version"));
}

#[test]
fn declares_workspace_inheritance_tolerates_whitespace_and_comments() {
    let snippet = "[package]\n  version.workspace   =   true   # inherited\n";
    assert!(declares_workspace_inheritance(snippet, "version"));
}

#[test]
fn declares_local_field_distinguishes_inheritance_from_literal() {
    let with_workspace = "[package]\nversion.workspace = true\n";
    assert!(!declares_local_field(with_workspace, "version"));
    let with_local = "[package]\nversion = \"0.1.0\"\n";
    assert!(declares_local_field(with_local, "version"));
}

#[test]
fn parse_string_array_reads_canonical_literals() {
    assert_eq!(parse_string_array("[]"), Vec::<String>::new());
    assert_eq!(
        parse_string_array("[\"a\", \"b\"]"),
        vec!["a".to_string(), "b".to_string()],
    );
    assert_eq!(
        parse_string_array("  [ \"a\" , \"b\" , ] "),
        vec!["a".to_string(), "b".to_string()],
    );
}

#[test]
fn section_stops_at_next_top_level_header() {
    let manifest =
        "[package]\nname = \"x\"\nversion.workspace = true\n\n[dependencies]\nfoo = \"1\"\n";
    let pkg = section(manifest, "[package]");
    assert!(pkg.contains("name = \"x\""));
    assert!(pkg.contains("version.workspace = true"));
    assert!(!pkg.contains("[dependencies]"));
    assert!(!pkg.contains("foo = \"1\""));
}

#[test]
fn section_handles_dotted_workspace_package_header() {
    let manifest = "\
[workspace]
members = [\"a\"]

[workspace.package]
version = \"0.0.1\"
license = \"AGPL-3.0-or-later\"

[workspace.lints.rust]
unsafe_code = \"forbid\"
";
    let ws_pkg = section(manifest, "[workspace.package]");
    assert!(ws_pkg.contains("version = \"0.0.1\""));
    assert!(ws_pkg.contains("license = \"AGPL-3.0-or-later\""));
    assert!(!ws_pkg.contains("[workspace.lints.rust]"));
    assert!(!ws_pkg.contains("unsafe_code"));
}
