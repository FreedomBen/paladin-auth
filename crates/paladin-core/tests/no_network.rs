// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase J.5 — source-level "no network, no telemetry" guard
// (DESIGN.md §8 / IMPLEMENTATION_PLAN_01_CORE.md Phase J).
//
// Defense-in-depth on top of `cargo deny`: scans the production
// `paladin-core` manifest and `src/` tree for direct references to
// network-stack APIs, and verifies via the workspace `Cargo.lock`
// that no resolved (direct or transitive) dependency matches the
// `cargo deny` network denylist.
//
// This is intentionally a concrete file scan rather than a vacuous
// missing-symbol compile-fail: the goal is to catch a regression in
// a `git diff`-able, human-readable form even if `cargo deny` is
// skipped, misconfigured, or temporarily allowlisted.
//
// The denylists below mirror `deny.toml` and the tokens enumerated in
// the Phase J.5 plan bullet. Update both lockstep with `deny.toml`.

use std::fs;
use std::path::{Path, PathBuf};

/// Substrings that must not appear in any `.rs` file under `src/`.
/// Patterns are chosen to be unambiguous: `tokio::` is a use site or
/// path expression, `use tokio` is an `use`-import — neither is
/// plausibly an English-prose comment fragment.
const FORBIDDEN_SOURCE_PATTERNS: &[&str] = &[
    "std::net",
    "TcpStream",
    "UdpSocket",
    "ToSocketAddrs",
    "use tokio",
    "tokio::",
    "extern crate tokio",
    "use reqwest",
    "reqwest::",
    "extern crate reqwest",
    "use hyper",
    "hyper::",
    "extern crate hyper",
    "use async_std",
    "async_std::",
    "use actix_web",
    "actix_web::",
    "use ureq",
    "ureq::",
    "use isahc",
    "isahc::",
    "use curl",
    "curl::",
    "use native_tls",
    "native_tls::",
    "use openssl",
    "openssl::",
    "use rustls",
    "rustls::",
    "use trust_dns_resolver",
    "trust_dns_resolver::",
    "use hickory_resolver",
    "hickory_resolver::",
    "use quinn",
    "quinn::",
];

/// Workspace-level `cargo deny` ban list, in `Cargo.lock` package-name
/// form. Mirrors the `[bans] deny = [...]` block in `deny.toml`.
const FORBIDDEN_LOCK_NAMES: &[&str] = &[
    "tokio",
    "tokio-util",
    "tokio-rustls",
    "tokio-native-tls",
    "async-std",
    "smol",
    "reqwest",
    "hyper",
    "hyper-tls",
    "hyper-rustls",
    "actix-web",
    "actix-http",
    "warp",
    "axum",
    "rocket",
    "ureq",
    "isahc",
    "curl",
    "curl-sys",
    "libcurl-sys",
    "native-tls",
    "openssl",
    "openssl-sys",
    "rustls",
    "rustls-native-certs",
    "trust-dns-resolver",
    "hickory-resolver",
    "h2",
    "h3",
    "quinn",
];

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    // crates/paladin-core -> crates -> workspace root
    crate_dir()
        .parent()
        .and_then(Path::parent)
        .expect("workspace root above crates/paladin-core")
        .to_path_buf()
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

#[test]
fn paladin_core_source_tree_has_no_network_symbols() {
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
        for pattern in FORBIDDEN_SOURCE_PATTERNS {
            if content.contains(pattern) {
                hits.push(format!("{}: `{}`", path.display(), pattern));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "paladin-core src/ contains forbidden network references:\n  {}",
        hits.join("\n  "),
    );
}

#[test]
fn paladin_core_manifest_has_no_network_dependency() {
    let manifest_path = crate_dir().join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));

    let mut hits = Vec::new();
    for name in FORBIDDEN_LOCK_NAMES {
        // A dep declared as `tokio = "1"` shows up as `\ntokio = `.
        // A dep declared in `[dependencies.tokio]` table shows up as
        // `[dependencies.tokio]`. A workspace inheritance form shows
        // up as `tokio.workspace = true` — same prefix.
        let needle_assignment = format!("\n{name} =");
        let needle_table = format!("[dependencies.{name}]");
        let needle_dev_table = format!("[dev-dependencies.{name}]");
        let needle_build_table = format!("[build-dependencies.{name}]");
        if manifest.contains(&needle_assignment)
            || manifest.contains(&needle_table)
            || manifest.contains(&needle_dev_table)
            || manifest.contains(&needle_build_table)
        {
            hits.push((*name).to_string());
        }
    }
    assert!(
        hits.is_empty(),
        "paladin-core/Cargo.toml directly depends on denied crates: {hits:?}",
    );
}

#[test]
fn workspace_lockfile_resolves_no_network_dependencies() {
    let lockfile_path = workspace_root().join("Cargo.lock");
    let lockfile = fs::read_to_string(&lockfile_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", lockfile_path.display()));

    // `Cargo.lock` is TOML; each `[[package]]` block contains exactly
    // one `name = "..."` line. We do a line-based scan rather than
    // pull in a TOML parser dep.
    let mut hits = Vec::new();
    for line in lockfile.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("name = \"") {
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                if FORBIDDEN_LOCK_NAMES.contains(&name) {
                    hits.push(name.to_string());
                }
            }
        }
    }
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "Cargo.lock resolves denied network deps: {hits:?}",
    );
}
