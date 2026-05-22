// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reproducible-build contract tests for the workspace.
//!
//! Per `DESIGN.md` §11.6 ("Reproducible builds") and
//! `IMPLEMENTATION_PLAN_04_GTK.md` Milestone 7 checklist entry
//! "Make the build reproducible: vendored deps, `cargo build
//! --locked`, `SOURCE_DATE_EPOCH` from the release tag, with the
//! gresource bundle and `linuxdeploy` step both deterministic":
//!
//! * The Rust toolchain is pinned in `rust-toolchain.toml` at the
//!   workspace root. The channel must be a concrete version (so a
//!   future `nightly`/`stable` drift cannot silently re-pick the
//!   compiler).
//! * The toolchain pins `rustfmt` and `clippy` as required
//!   components so the §10 CI gate (`cargo fmt --check`,
//!   `cargo clippy -- -D warnings`) resolves against the same
//!   compiler version the release artifacts are built with.
//! * The pinned channel matches the workspace `[workspace.package]
//!   .rust-version` floor; otherwise a release build can target a
//!   compiler newer than the workspace declares it requires, which
//!   is a reproducibility hole.
//! * The `AppImage` assembly script reads `SOURCE_DATE_EPOCH` so the
//!   release pipeline can inject the tag-timestamp the spec requires
//!   and forwards it through `linuxdeploy`'s subprocess environment.
//! * The `AppImage` assembly script invokes `cargo build` with
//!   `--locked` (parity with the Flatpak `--locked --offline`
//!   contract).
//!
//! Tests intentionally read each artifact as plain text so the
//! contracts are auditable in CI without rust-up / linuxdeploy
//! actually being installed on the runner.

use std::fs;
use std::path::PathBuf;

/// Path to the workspace-root `rust-toolchain.toml`, relative to the
/// workspace root.
const RUST_TOOLCHAIN_RELPATH: &str = "rust-toolchain.toml";

/// Path to the workspace-root `Cargo.toml`, relative to the workspace
/// root.
const WORKSPACE_CARGO_RELPATH: &str = "Cargo.toml";

/// Path to the `AppImage` build script, relative to the workspace root.
const APPIMAGE_SCRIPT_RELPATH: &str = "packaging/appimage/build-appimage.sh";

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

fn rust_toolchain_path() -> PathBuf {
    workspace_root().join(RUST_TOOLCHAIN_RELPATH)
}

fn workspace_cargo_path() -> PathBuf {
    workspace_root().join(WORKSPACE_CARGO_RELPATH)
}

fn appimage_script_path() -> PathBuf {
    workspace_root().join(APPIMAGE_SCRIPT_RELPATH)
}

fn read_to_string(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn read_rust_toolchain() -> String {
    read_to_string(&rust_toolchain_path())
}

fn read_workspace_cargo() -> String {
    read_to_string(&workspace_cargo_path())
}

fn read_appimage_script() -> String {
    read_to_string(&appimage_script_path())
}

/// Extract the `channel = "..."` value from a `rust-toolchain.toml`
/// body. Returns `None` if no `channel = "..."` line is present.
fn extract_toolchain_channel(toolchain_toml: &str) -> Option<String> {
    for line in toolchain_toml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("channel") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if let Some(unquoted) = rest
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                {
                    return Some(unquoted.to_string());
                }
            }
        }
    }
    None
}

/// Extract the workspace `rust-version = "..."` value from a
/// workspace-level `Cargo.toml`. Returns `None` if no
/// `rust-version = "..."` line is present in the
/// `[workspace.package]` section.
fn extract_workspace_rust_version(workspace_cargo: &str) -> Option<String> {
    let mut in_workspace_package = false;
    for line in workspace_cargo.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_workspace_package = trimmed == "[workspace.package]";
            continue;
        }
        if !in_workspace_package {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("rust-version") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if let Some(unquoted) = rest
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                {
                    return Some(unquoted.to_string());
                }
            }
        }
    }
    None
}

// --- rust-toolchain.toml tests ----------------------------------------------

#[test]
fn rust_toolchain_file_exists_at_workspace_root() {
    let path = rust_toolchain_path();
    assert!(
        path.is_file(),
        "expected `rust-toolchain.toml` at {} — DESIGN.md §11.6 requires the workspace \
         toolchain to be pinned for reproducible release builds",
        path.display(),
    );
}

#[test]
fn rust_toolchain_declares_toolchain_table_header() {
    let body = read_rust_toolchain();
    assert!(
        body.lines().any(|line| line.trim() == "[toolchain]"),
        "rust-toolchain.toml must declare the `[toolchain]` table header so rustup picks up \
         the pinned channel; body:\n{body}",
    );
}

#[test]
fn rust_toolchain_pins_a_concrete_channel_version() {
    let body = read_rust_toolchain();
    let channel = extract_toolchain_channel(&body).unwrap_or_else(|| {
        panic!(
            "rust-toolchain.toml must declare a `channel = \"X.Y.Z\"` value so the release \
             pipeline can rebuild against a fixed compiler; body:\n{body}",
        )
    });
    // The channel must be a concrete version like `1.94.1`, never a
    // floating identifier like `stable` / `beta` / `nightly` — those
    // would let `rustup` re-pick a different compiler at every CI run.
    let floating = ["stable", "beta", "nightly"];
    assert!(
        !floating.iter().any(|tag| channel == *tag),
        "rust-toolchain.toml channel must pin a concrete `X.Y.Z` version, not a floating \
         identifier (`stable` / `beta` / `nightly`); got: {channel:?}",
    );
    let dots = channel.chars().filter(|c| *c == '.').count();
    assert!(
        dots >= 2,
        "rust-toolchain.toml channel must look like a concrete `X.Y.Z` version with at least \
         two dots; got: {channel:?}",
    );
}

#[test]
fn rust_toolchain_declares_rustfmt_and_clippy_components() {
    let body = read_rust_toolchain();
    let required = ["rustfmt", "clippy"];
    let mut missing = Vec::new();
    for comp in required {
        if !body.contains(&format!("\"{comp}\"")) {
            missing.push(comp);
        }
    }
    assert!(
        missing.is_empty(),
        "rust-toolchain.toml must list `rustfmt` and `clippy` under `components` so the §10 \
         CI gate (`cargo fmt --check`, `cargo clippy -- -D warnings`) resolves against the \
         pinned compiler; missing: {missing:?}\n\nbody:\n{body}",
    );
}

#[test]
fn rust_toolchain_uses_minimal_profile() {
    let body = read_rust_toolchain();
    // The minimal profile keeps the release toolchain footprint
    // small — only the explicitly-listed components are installed.
    // A different profile (default / complete) would pull in
    // additional components that drift from the declared list.
    let landed = body.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "profile = \"minimal\"" || trimmed == "profile = 'minimal'"
    });
    assert!(
        landed,
        "rust-toolchain.toml must declare `profile = \"minimal\"` so the release toolchain \
         only installs the listed components; body:\n{body}",
    );
}

#[test]
fn rust_toolchain_channel_matches_workspace_rust_version_floor() {
    // The channel must be at least as new as the workspace
    // `[workspace.package].rust-version`; otherwise a release build
    // can target a compiler the workspace doesn't declare as
    // sufficient. Pinning equality (rather than `>=`) is the
    // stronger contract — DESIGN §11.6 calls for pinned
    // toolchains, not toolchains that happen to satisfy the MSRV
    // floor — so the test asserts the prefix match.
    let toolchain_body = read_rust_toolchain();
    let cargo_body = read_workspace_cargo();
    let channel = extract_toolchain_channel(&toolchain_body).unwrap_or_else(|| {
        panic!("rust-toolchain.toml must declare a channel; body:\n{toolchain_body}")
    });
    let rust_version = extract_workspace_rust_version(&cargo_body).unwrap_or_else(|| {
        panic!(
            "workspace Cargo.toml must declare `[workspace.package].rust-version`; \
             body:\n{cargo_body}",
        )
    });
    assert!(
        channel.starts_with(&rust_version),
        "rust-toolchain.toml channel ({channel:?}) must start with the workspace \
         `[workspace.package].rust-version` ({rust_version:?}) so a release build never \
         resolves against an older compiler than the workspace declares it requires",
    );
}

// --- AppImage SOURCE_DATE_EPOCH / --locked tests ----------------------------

#[test]
fn appimage_script_reads_source_date_epoch_from_environment() {
    // §11.6 requires `SOURCE_DATE_EPOCH` to be exported from the
    // release tag and consumed by every byte-affecting tool in the
    // build (compilers, packers, AppImage assemblers). The release
    // pipeline injects SOURCE_DATE_EPOCH; the script must reference
    // it so a future edit that drops the propagation step fails this
    // test immediately, independent of whether SOURCE_DATE_EPOCH was
    // actually set when the script ran.
    let script = read_appimage_script();
    assert!(
        script.contains("SOURCE_DATE_EPOCH"),
        "AppImage build script must reference `SOURCE_DATE_EPOCH` so the release pipeline \
         can inject the tag-timestamp for reproducible builds per DESIGN §11.6; the script \
         body did not contain that literal",
    );
}

#[test]
fn appimage_script_exports_source_date_epoch_for_linuxdeploy_subprocess() {
    // `linuxdeploy`, `appimagetool` (invoked transitively),
    // `mksquashfs`, and the GTK plugin all consume
    // `SOURCE_DATE_EPOCH` from their own environment. Only an
    // `export SOURCE_DATE_EPOCH` (or assignment-with-export) in the
    // script reliably propagates the value to those grandchildren —
    // a bare local assignment would not. Match either form so a
    // future cleanup that switches to `export SOURCE_DATE_EPOCH=...`
    // syntax (instead of two separate statements) still passes.
    let script = read_appimage_script();
    let exports = script.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("export SOURCE_DATE_EPOCH")
            || trimmed.contains("export SOURCE_DATE_EPOCH")
    });
    assert!(
        exports,
        "AppImage build script must `export SOURCE_DATE_EPOCH` so the value reaches \
         linuxdeploy / appimagetool / mksquashfs subprocesses for byte-identical AppImage \
         output per DESIGN §11.6; the script body had no `export SOURCE_DATE_EPOCH` directive",
    );
}

#[test]
fn appimage_script_uses_cargo_build_locked() {
    // §11.6 requires `cargo build --locked` for reproducible
    // release builds. Pin the literal so a future edit that drops
    // `--locked` (and lets the lockfile drift at build time) fails
    // this test immediately. Mirrors the Flatpak manifest's
    // `flatpak_manifest_uses_locked_offline_cargo_build` assertion.
    //
    // Comment lines and shell-substitution comments are filtered
    // out — only real `cargo build` invocations need the flag.
    let script = read_appimage_script();
    let cargo_invocations: Vec<&str> = script
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with('#') && trimmed.starts_with("cargo build")
        })
        .collect();
    assert!(
        !cargo_invocations.is_empty(),
        "AppImage build script must invoke `cargo build` at least once (for the release \
         fallback when the binary is missing); the script body had no `cargo build` invocation",
    );
    for line in &cargo_invocations {
        assert!(
            line.contains("--locked"),
            "Every `cargo build` invocation in the AppImage build script must include \
             `--locked` for reproducibility per DESIGN §11.6; got: {line:?}",
        );
    }
}

#[test]
fn appimage_script_cargo_invocations_target_release_profile() {
    // The release pipeline ships a release-profile binary; a
    // debug-profile fallback would silently produce a slow, larger
    // AppImage. Pin that any `cargo build` invocation in the script
    // body uses `--release`.
    let script = read_appimage_script();
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("cargo build") {
            assert!(
                trimmed.contains("--release"),
                "AppImage build script `cargo build` invocations must use `--release` so the \
                 AppImage carries the release-profile binary; got: {trimmed:?}",
            );
        }
    }
}

// --- helper self-tests ------------------------------------------------------

#[test]
fn extract_toolchain_channel_returns_quoted_value() {
    let body = "[toolchain]\nchannel = \"1.94.1\"\nprofile = \"minimal\"\n";
    assert_eq!(extract_toolchain_channel(body), Some("1.94.1".to_string()));
}

#[test]
fn extract_toolchain_channel_returns_none_when_absent() {
    let body = "[toolchain]\nprofile = \"minimal\"\n";
    assert_eq!(extract_toolchain_channel(body), None);
}

#[test]
fn extract_toolchain_channel_handles_single_quotes() {
    let body = "[toolchain]\nchannel = '1.94.1'\n";
    assert_eq!(extract_toolchain_channel(body), Some("1.94.1".to_string()));
}

#[test]
fn extract_workspace_rust_version_returns_value_inside_workspace_package() {
    let body = "[workspace]\nresolver = \"2\"\n\n[workspace.package]\nrust-version = \"1.94\"\n";
    assert_eq!(
        extract_workspace_rust_version(body),
        Some("1.94".to_string()),
    );
}

#[test]
fn extract_workspace_rust_version_ignores_rust_version_outside_workspace_package() {
    // A `rust-version` outside `[workspace.package]` (e.g. in a
    // crate manifest) must not be returned.
    let body = "[workspace.package]\nedition = \"2021\"\n\n[other]\nrust-version = \"1.99\"\n";
    assert_eq!(extract_workspace_rust_version(body), None);
}
