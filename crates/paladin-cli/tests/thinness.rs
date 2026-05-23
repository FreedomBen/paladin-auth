// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Source-level "thinness contract" guard for `paladin-cli`
// (docs/IMPLEMENTATION_PLAN_02_CLI.md "Thinness contract" / docs/DESIGN.md §3).
//
// The `paladin` binary is a presentation layer. Crypto, storage,
// import/export, and OTP primitives must never be re-implemented or
// imported directly here — they belong in `paladin-core`. This test
// scans the production CLI source tree and crate manifest for direct
// references to denied crates and fails with a `git diff`-able,
// human-readable message pointing at the offending file and pattern so
// the logic can be moved into `paladin-core`.
//
// This mirrors the defense-in-depth pattern used by
// `paladin-core/tests/no_network.rs`. Update the pattern lists below
// in lockstep with the docs/IMPLEMENTATION_PLAN_02_CLI.md "Thinness
// contract" denylist.

use std::fs;
use std::path::{Path, PathBuf};

/// Crate names the CLI must never reference directly. Production
/// behavior for crypto, storage, OTP, and import/export lives in
/// `paladin-core`; the CLI consumes its public API instead. Update
/// alongside `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Thinness contract".
const FORBIDDEN_CRATES: &[&str] = &[
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

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn collect_rs_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, files);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

/// Build the set of unambiguous import / path patterns for one crate.
/// `use {name}` catches `use {name}::Foo;` and `use {name};` and
/// `use {name} as Bar;`; `{name}::` catches qualified path access; and
/// `extern crate {name}` catches the explicit extern declaration. All
/// three forms are case-sensitive; lowercase Cargo crate names will
/// not collide with `PascalCase` paladin-core types like `Algorithm::Sha1`
/// or `Argon2Params` that are re-exported through `paladin_core::*`.
fn forbidden_source_patterns(name: &str) -> [String; 3] {
    [
        format!("use {name}"),
        format!("{name}::"),
        format!("extern crate {name}"),
    ]
}

#[test]
fn paladin_cli_source_tree_does_not_reference_forbidden_crates() {
    let src_dir = crate_dir().join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);
    assert!(
        !files.is_empty(),
        "no .rs files found under {}",
        src_dir.display(),
    );

    let mut hits = Vec::new();
    for path in &files {
        let content =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        for crate_name in FORBIDDEN_CRATES {
            for pattern in forbidden_source_patterns(crate_name) {
                if let Some(offset) = content.find(&pattern) {
                    let line = content[..offset].matches('\n').count() + 1;
                    hits.push(format!("{}:{line}: `{}`", path.display(), pattern));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "paladin-cli/src/ contains forbidden crate references — move the \
         underlying logic into paladin-core and import via `paladin_core::*`:\n  {}",
        hits.join("\n  "),
    );
}

#[test]
fn paladin_cli_manifest_does_not_declare_forbidden_dependency() {
    let manifest_path = crate_dir().join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));

    // Walk lines, tracking the active TOML table header. Only the
    // production `[dependencies]` table is checked: dev-dependencies
    // are allowed to pull paladin-core test features, and
    // `[features]`, `[package]`, and other tables don't introduce
    // build-time linkage. This matches the "direct [dependencies]
    // entry" wording in docs/IMPLEMENTATION_PLAN_02_CLI.md.
    let mut hits = Vec::new();
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(header) = rest.strip_suffix(']') {
                in_dependencies = header == "dependencies";
                // `[dependencies.foo]` is itself a forbidden-table form
                // we want to flag — handle it inline so the check is
                // not gated on `in_dependencies` toggling first.
                if let Some(dep_name) = header.strip_prefix("dependencies.") {
                    if FORBIDDEN_CRATES.contains(&dep_name) {
                        hits.push(format!("[dependencies.{dep_name}]"));
                    }
                }
                continue;
            }
        }
        if !in_dependencies {
            continue;
        }
        // Inside `[dependencies]`, look for `name =` style entries.
        // Strip a leading key (everything up to the first `=`) and
        // compare against the forbidden list verbatim.
        if let Some(eq_idx) = trimmed.find('=') {
            let key = trimmed[..eq_idx].trim();
            if FORBIDDEN_CRATES.contains(&key) {
                hits.push(format!("dependencies.{key}"));
            }
        }
    }
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "paladin-cli/Cargo.toml declares forbidden direct dependencies — \
         move the underlying logic into paladin-core: {hits:?}",
    );
}
