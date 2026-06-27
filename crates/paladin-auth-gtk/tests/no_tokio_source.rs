// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-level no-`tokio` guard for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"GUI runtime carve-out" /
//! docs/DESIGN.md §8 bullet 10, `paladin-auth-gtk` may carry `tokio` in its
//! transitive lockfile through `relm4`, but the crate's own source
//! files must not reach for `tokio` directly. GTK's main loop is
//! the executor and `gio::spawn_blocking` runs long-running work;
//! a GUI feature that needs a tokio runtime is a sign the work
//! belongs behind `gio::spawn_blocking` instead.
//!
//! This test mirrors `crates/paladin-auth-core/tests/no_network.rs`'s
//! source-pattern scan and is intentionally a concrete file scan
//! rather than a compile-time check: it catches a regression in a
//! `git diff`-readable form even if the rule is forgotten by a
//! future reviewer. The `paladin-auth-gtk` `Cargo.toml` is also scanned
//! to forbid direct declarations of `tokio` and its near
//! relatives.
//!
//! Update lockstep with `deny.toml`'s `[bans] deny` list and
//! `crates/paladin-auth-core/tests/no_network.rs`'s
//! `FORBIDDEN_SOURCE_PATTERNS`.

use std::fs;
use std::path::{Path, PathBuf};

/// Substrings that must not appear in any `.rs` file under
/// `paladin-auth-gtk/src/`. Only the source-level rule of the broader
/// "no network" guard applies here — the GUI legitimately uses
/// `gio::spawn_blocking` for blocking work, so `std::net` /
/// `TcpStream` / `UdpSocket` patterns from `paladin-auth-core`'s list
/// are still forbidden but `tokio` is the headline rule for the
/// GUI.
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

/// Direct-dependency names that must not appear in
/// `paladin-auth-gtk/Cargo.toml`. `tokio` is exempted *only* when it
/// reaches the lockfile transitively through `relm4`; a direct
/// declaration here would bypass the §"GUI runtime carve-out"
/// rule.
const FORBIDDEN_MANIFEST_NAMES: &[&str] = &[
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
fn paladin_auth_gtk_source_tree_has_no_tokio_or_network_symbols() {
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
        "paladin-auth-gtk src/ contains forbidden tokio / network references — \
         GTK's main loop is the executor (docs/IMPLEMENTATION_PLAN_04_GTK.md \
         §\"GUI runtime carve-out\"); move long work behind \
         `gio::spawn_blocking` instead:\n  {}",
        hits.join("\n  "),
    );
}

#[test]
fn paladin_auth_gtk_manifest_has_no_direct_tokio_or_network_dependency() {
    let manifest_path = crate_dir().join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));

    let mut hits = Vec::new();
    for name in FORBIDDEN_MANIFEST_NAMES {
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
        "paladin-auth-gtk/Cargo.toml directly depends on forbidden crates — \
         the §\"GUI runtime carve-out\" admits `tokio` only when it reaches \
         the lockfile through `relm4`, not as a direct dep here: {hits:?}",
    );
}
