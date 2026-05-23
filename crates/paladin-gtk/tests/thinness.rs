// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thinness contract test for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Thinness contract", crypto,
//! storage, import/export, and OTP primitives must never be re-
//! implemented or imported directly here — they belong in
//! `paladin-core` (DESIGN §3). This test enforces that contract by
//! scanning:
//!
//! 1. Every `.rs` file under `crates/paladin-gtk/src/` for direct
//!    references to forbidden crate-name spellings, and
//! 2. The crate manifest at `crates/paladin-gtk/Cargo.toml`'s
//!    `[dependencies]` section for direct declarations of those
//!    same crates.
//!
//! The deny list mirrors the plan: argon2, chacha20poly1305,
//! bincode, hmac, sha1, sha2, rqrr, image, getrandom, directories,
//! url. GUI image clipboard imports route raw RGBA buffers through
//! `paladin_core::import::qr_image_bytes`, so neither `image` nor
//! `rqrr` belong in this crate.

use std::fs;
use std::path::{Path, PathBuf};

/// Forbidden direct dependencies / source references for `paladin-gtk`.
///
/// See `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Thinness contract".
const FORBIDDEN: &[&str] = &[
    "argon2",
    "chacha20poly1305",
    "bincode",
    "hmac",
    "sha1",
    "sha2",
    "rqrr",
    "image",
    "getrandom",
    "directories",
    "url",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn source_files_have_no_forbidden_crate_references() {
    let src = crate_root().join("src");
    let mut offenses = Vec::new();
    walk_rs_files(&src, &mut |path, contents| {
        for (lineno, raw_line) in contents.lines().enumerate() {
            let code = strip_line_comment(raw_line);
            for forbidden in FORBIDDEN {
                if contains_word(code, forbidden) {
                    offenses.push(format!(
                        "  {}:{}: forbidden `{}` reference\n    {}",
                        path.display(),
                        lineno + 1,
                        forbidden,
                        raw_line.trim_end(),
                    ));
                }
            }
        }
    });
    assert!(
        offenses.is_empty(),
        "paladin-gtk must not reach into crypto / storage / import / \
         OTP primitives directly — move offending logic into paladin-core \
         per docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Thinness contract\":\n{}",
        offenses.join("\n"),
    );
}

#[test]
fn manifest_declares_no_forbidden_direct_dependencies() {
    let manifest_path = crate_root().join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("read crates/paladin-gtk/Cargo.toml");
    let declared = direct_dependency_names(&manifest);
    let offenders: Vec<&str> = declared
        .iter()
        .filter(|name| FORBIDDEN.contains(&name.as_str()))
        .map(String::as_str)
        .collect();
    assert!(
        offenders.is_empty(),
        "paladin-gtk Cargo.toml [dependencies] must not declare any of: \
         {FORBIDDEN:?}\nfound: {offenders:?}",
    );
}

// --- helpers -----------------------------------------------------------------

/// Walk every `.rs` file under `dir` recursively, invoking `visit` with
/// the file path and the file's UTF-8 contents.
fn walk_rs_files(dir: &Path, visit: &mut dyn FnMut(&Path, &str)) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()));
    for entry in entries {
        let entry = entry.expect("read dir entry");
        let path = entry.path();
        let ft = entry.file_type().expect("file type");
        if ft.is_dir() {
            walk_rs_files(&path, visit);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let contents = fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
            visit(&path, &contents);
        }
    }
}

/// Strip everything from the first `//` to end of line. Handles `///`
/// doc comments and inline `//` trailing comments equally. Block
/// comments (`/* … */`) are left in place — `paladin-gtk` does not use
/// them as of this commit; if a future change introduces one that
/// contains a forbidden token, the test will surface it and the
/// contributor should refactor or replace the comment with `//` lines.
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Return `true` if `needle` appears in `haystack` with a word
/// boundary on each side (neither preceding nor following byte is an
/// ASCII identifier character).
///
/// UTF-8 multibyte characters are not ASCII identifier characters, so
/// they correctly act as boundaries; the check is conservative.
fn contains_word(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut cursor = 0;
    while cursor <= bytes.len().saturating_sub(needle.len()) {
        let Some(rel) = haystack[cursor..].find(needle) else {
            return false;
        };
        let abs = cursor + rel;
        let before_ok = abs == 0 || !is_ident_byte(bytes[abs - 1]);
        let after_idx = abs + needle.len();
        let after_ok = after_idx == bytes.len() || !is_ident_byte(bytes[after_idx]);
        if before_ok && after_ok {
            return true;
        }
        cursor = abs + 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Extract the names of direct dependencies declared in
/// `[dependencies]` (both inline `name = ...` rows and the
/// `[dependencies.name]` table form). Dev / build / target /
/// workspace dependency sections are intentionally not inspected —
/// the thinness contract only constrains runtime deps of the
/// `paladin-gtk` crate.
fn direct_dependency_names(manifest: &str) -> Vec<String> {
    let mut current_section: Option<String> = None;
    let mut names: Vec<String> = Vec::new();
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                let section = rest[..end].to_string();
                if let Some(name) = section.strip_prefix("dependencies.") {
                    push_unique(&mut names, name.to_string());
                }
                current_section = Some(section);
            }
            continue;
        }
        if current_section.as_deref() != Some("dependencies") {
            continue;
        }
        let name_end = trimmed
            .find(|c: char| c == '=' || c.is_whitespace() || c == '.')
            .unwrap_or(trimmed.len());
        let name = trimmed[..name_end].trim();
        if !name.is_empty() {
            push_unique(&mut names, name.to_string());
        }
    }
    names
}

fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.iter().any(|x| x == &s) {
        v.push(s);
    }
}

// --- helper self-tests -------------------------------------------------------
//
// Cover the scanner primitives directly so a future regression in
// `contains_word` / `strip_line_comment` / `direct_dependency_names`
// is caught even if `src/` happens to be empty.

#[test]
fn contains_word_respects_boundaries() {
    assert!(contains_word("use argon2;", "argon2"));
    assert!(contains_word("argon2::Params", "argon2"));
    assert!(contains_word("(argon2)", "argon2"));
    assert!(contains_word("argon2", "argon2"));
    assert!(!contains_word("argon2id_helper", "argon2"));
    assert!(!contains_word("my_argon2_alias", "argon2"));
    assert!(!contains_word("xargon2y", "argon2"));
    assert!(!contains_word("", "argon2"));
}

#[test]
fn strip_line_comment_drops_doc_and_trailing_comments() {
    assert_eq!(strip_line_comment("/// argon2 is forbidden"), "");
    assert_eq!(strip_line_comment("//! argon2 is forbidden"), "");
    assert_eq!(strip_line_comment("let _ = 1; // argon2"), "let _ = 1; ");
    assert_eq!(strip_line_comment("let x = 1;"), "let x = 1;");
}

#[test]
fn direct_dependency_names_parses_inline_table_and_dotted_section() {
    let manifest = "\
[package]
name = \"demo\"

# This comment mentions argon2 but is not a dep.
[dependencies]
paladin-core = { path = \"../paladin-core\" }
clap = \"4.5\"
# next line is a comment, skip it
serde = { version = \"1\", features = [\"derive\"] }

[dependencies.rare]
version = \"0.1\"

[dev-dependencies]
tempfile = \"3\"

[target.'cfg(unix)'.dependencies]
nix = \"0.27\"
";
    let names = direct_dependency_names(manifest);
    assert!(names.iter().any(|n| n == "paladin-core"));
    assert!(names.iter().any(|n| n == "clap"));
    assert!(names.iter().any(|n| n == "serde"));
    assert!(names.iter().any(|n| n == "rare"));
    // Dev / target deps are not part of the contract surface.
    assert!(!names.iter().any(|n| n == "tempfile"));
    assert!(!names.iter().any(|n| n == "nix"));
    // The argon2 mention in the comment must not be misread as a dep.
    assert!(!names.iter().any(|n| n == "argon2"));
}
