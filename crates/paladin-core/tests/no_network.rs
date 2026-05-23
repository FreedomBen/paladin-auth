// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase J.5 — source-level "no network, no telemetry" guard
// (docs/DESIGN.md §8 / docs/IMPLEMENTATION_PLAN_01_CORE.md Phase J).
//
// Defense-in-depth on top of `cargo deny`: scans the production
// `paladin-core` manifest and `src/` tree for direct references to
// network-stack APIs, and verifies via the workspace `Cargo.lock`
// that no resolved (direct or transitive) dependency of the
// security-sensitive subtree matches the `cargo deny` network
// denylist.
//
// This is intentionally a concrete file scan rather than a vacuous
// missing-symbol compile-fail: the goal is to catch a regression in
// a `git diff`-able, human-readable form even if `cargo deny` is
// skipped, misconfigured, or temporarily allowlisted.
//
// The denylists below mirror `deny.toml` and the tokens enumerated in
// the Phase J.5 plan bullet. Update both lockstep with `deny.toml`.
//
// Subtree scoping: the lockfile check is rooted at `paladin-core`,
// `paladin-cli`, and `paladin-tui` — the no-network surface per
// docs/DESIGN.md §8 and §13. `paladin-gtk` is intentionally excluded
// because its GUI framework (`relm4`) pulls `tokio` in transitively
// as a structured-concurrency primitive, not as a network stack;
// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Dependencies" and §"GUI runtime
// carve-out" describe why this is safe (GTK's main loop is the
// executor, and `gio::spawn_blocking` does the long work; no
// network sockets are opened).

use std::collections::{HashMap, HashSet, VecDeque};
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

/// Workspace members rooted at the no-network surface. Any package
/// transitively reachable from one of these must not appear in
/// [`FORBIDDEN_LOCK_NAMES`]. `paladin-gtk` is intentionally not in
/// this list — see the module-level comment.
const NO_NETWORK_SUBTREE_ROOTS: &[&str] = &["paladin-core", "paladin-cli", "paladin-tui"];

#[test]
fn no_network_subtree_resolves_no_network_dependencies() {
    let lockfile_path = workspace_root().join("Cargo.lock");
    let lockfile = fs::read_to_string(&lockfile_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", lockfile_path.display()));

    let graph = parse_lockfile_graph(&lockfile);
    let reachable = reachable_packages(&graph, NO_NETWORK_SUBTREE_ROOTS);

    let mut hits: Vec<String> = FORBIDDEN_LOCK_NAMES
        .iter()
        .copied()
        .filter(|name| reachable.contains(*name))
        .map(String::from)
        .collect();
    hits.sort();
    hits.dedup();
    assert!(
        hits.is_empty(),
        "Cargo.lock subtree under {NO_NETWORK_SUBTREE_ROOTS:?} resolves denied network \
         deps: {hits:?}.\n\
         If the offending dep is reachable only from `paladin-gtk` via `relm4`, the \
         scoping above already excludes it; investigate the new edge in the no-network \
         subtree instead of widening the carve-out.",
    );
}

/// Parse `Cargo.lock` into an adjacency map `package_name -> direct
/// dep names`. The lockfile is TOML, but we do a line-based scan
/// rather than pull in a TOML parser dev-dep — the layout is fixed
/// by Cargo and there is no need for arbitrary-TOML support.
///
/// When multiple versions of the same crate are present, Cargo
/// disambiguates dep references as `"name version source"`. We take
/// the leading whitespace-delimited token so the resulting graph
/// keys on bare crate names; the BFS in
/// [`reachable_packages`] then over-approximates conservatively
/// (every direct dep of any version of `X` is treated as reachable
/// from `X`), which can only produce false positives, never false
/// negatives — exactly the bias the security guard wants.
fn parse_lockfile_graph(lockfile: &str) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    let mut current_name: Option<String> = None;
    let mut current_deps: Vec<String> = Vec::new();
    let mut in_dependencies = false;

    let mut commit_package = |name: &mut Option<String>, deps: &mut Vec<String>| {
        if let Some(n) = name.take() {
            let entry = graph.entry(n).or_default();
            for dep in deps.drain(..) {
                if !entry.contains(&dep) {
                    entry.push(dep);
                }
            }
        }
    };

    for line in lockfile.lines() {
        let trimmed = line.trim();

        if trimmed == "[[package]]" {
            commit_package(&mut current_name, &mut current_deps);
            in_dependencies = false;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("name = \"") {
            if let Some(end) = rest.find('"') {
                current_name = Some(rest[..end].to_string());
            }
            in_dependencies = false;
            continue;
        }

        if trimmed.starts_with("dependencies = [") {
            in_dependencies = true;
            // Same-line dep e.g. `dependencies = ["foo", "bar"]` is
            // rare but valid; the inline parser below covers it.
            let after = trimmed
                .strip_prefix("dependencies = [")
                .expect("just checked");
            for quoted in after.split('"') {
                if let Some(name) = quoted.split_whitespace().next() {
                    if !name.is_empty() && !name.starts_with(',') && !name.starts_with(']') {
                        current_deps.push(name.to_string());
                    }
                }
            }
            if trimmed.ends_with(']') {
                in_dependencies = false;
            }
            continue;
        }

        if in_dependencies {
            if trimmed == "]" {
                in_dependencies = false;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix('"') {
                if let Some(end) = rest.find('"') {
                    let dep_str = &rest[..end];
                    if let Some(name) = dep_str.split_whitespace().next() {
                        current_deps.push(name.to_string());
                    }
                }
            }
        }
    }

    commit_package(&mut current_name, &mut current_deps);
    graph
}

/// Breadth-first traversal of the [`parse_lockfile_graph`] adjacency
/// map starting from each name in `roots`. The returned set
/// contains every package transitively reachable from any root —
/// the roots themselves are included.
fn reachable_packages(graph: &HashMap<String, Vec<String>>, roots: &[&str]) -> HashSet<String> {
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for root in roots {
        if visited.insert((*root).to_string()) {
            queue.push_back((*root).to_string());
        }
    }
    while let Some(name) = queue.pop_front() {
        if let Some(deps) = graph.get(&name) {
            for dep in deps {
                if visited.insert(dep.clone()) {
                    queue.push_back(dep.clone());
                }
            }
        }
    }
    visited
}

#[test]
fn parse_lockfile_graph_handles_basic_package_with_deps() {
    let src = r#"
# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "foo"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = [
 "bar",
 "baz",
]

[[package]]
name = "bar"
version = "1.0.0"

[[package]]
name = "baz"
version = "1.0.0"
"#;
    let graph = parse_lockfile_graph(src);
    assert_eq!(
        graph.get("foo").unwrap(),
        &vec!["bar".to_string(), "baz".to_string()]
    );
    assert_eq!(graph.get("bar").unwrap(), &Vec::<String>::new());
    assert_eq!(graph.get("baz").unwrap(), &Vec::<String>::new());
}

#[test]
fn parse_lockfile_graph_handles_versioned_dep_disambiguation() {
    let src = r#"
[[package]]
name = "foo"
version = "1.0.0"
dependencies = [
 "bar 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "bar"
version = "1.0.0"
"#;
    let graph = parse_lockfile_graph(src);
    assert_eq!(graph.get("foo").unwrap(), &vec!["bar".to_string()]);
}

#[test]
fn reachable_packages_walks_transitive_edges() {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    graph.insert("root".into(), vec!["a".into(), "b".into()]);
    graph.insert("a".into(), vec!["c".into()]);
    graph.insert("b".into(), Vec::new());
    graph.insert("c".into(), Vec::new());
    graph.insert("orphan".into(), Vec::new());

    let reached = reachable_packages(&graph, &["root"]);
    assert!(reached.contains("root"));
    assert!(reached.contains("a"));
    assert!(reached.contains("b"));
    assert!(reached.contains("c"));
    assert!(!reached.contains("orphan"));
}

#[test]
fn reachable_packages_excludes_paladin_gtk_subtree() {
    // Models the live workspace: `paladin-core` depends on `argon2`
    // (clean); `paladin-gtk` depends on `relm4` which carries
    // `tokio`. From `paladin-core`'s root only, `tokio` must not
    // appear in the reachable set.
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    graph.insert("paladin-core".into(), vec!["argon2".into()]);
    graph.insert("argon2".into(), Vec::new());
    graph.insert("paladin-gtk".into(), vec!["relm4".into()]);
    graph.insert("relm4".into(), vec!["tokio".into()]);
    graph.insert("tokio".into(), Vec::new());

    let reached = reachable_packages(&graph, &["paladin-core"]);
    assert!(!reached.contains("tokio"));
    assert!(!reached.contains("relm4"));
    assert!(reached.contains("argon2"));
}
