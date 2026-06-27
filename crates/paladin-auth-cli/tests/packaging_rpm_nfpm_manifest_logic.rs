// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nfpm` `.rpm` manifest contract tests for the `paladin-auth` CLI.
//!
//! Per `docs/DESIGN.md` §11.3 ("Per-front-end packages") and
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` §"Packaging (per §11)":
//!
//! * Installs `/usr/bin/paladin-auth` and the gzipped man page at
//!   `/usr/share/man/man1/paladin-auth.1.gz`.
//! * Depends only on `glibc` — the binary is otherwise statically
//!   linked where possible. Matches the headless-friendly footprint
//!   §11.3 promises.
//! * No maintainer scripts: the vault lives under
//!   `$XDG_DATA_HOME/paladin-auth/` and is created on first use, so install
//!   and removal touch nothing global.
//! * Inherits `version` / `description` / `homepage` / `license` /
//!   `maintainer` from the workspace `[workspace.package]` table or
//!   from `${PALADIN_AUTH_VERSION}` at packaging time.
//!
//! Tests read the manifest as plain text so no `serde_yaml`
//! dependency lands here — mirrors the parser helpers in
//! `crates/paladin-auth-gtk/tests/packaging_rpm_nfpm_manifest_logic.rs`,
//! copied module-local per the workspace convention (no shared
//! `tests/common/` across crates for packaging contracts).

use std::fs;
use std::path::PathBuf;

const RPM_MANIFEST_RELPATH: &str = "packaging/rpm/paladin-auth.yaml";

const REQUIRED_RPM_DEPENDS: &[&str] = &["glibc"];

const REQUIRED_INSTALL_DESTINATIONS: &[&str] = &[
    "/usr/bin/paladin-auth",
    "/usr/share/man/man1/paladin-auth.1.gz",
];

const REQUIRED_INSTALL_SOURCES: &[&str] = &[
    "target/release/paladin-auth",
    "target/man/paladin-auth.1.gz",
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

fn strip_trailing_comment(line: &str) -> &str {
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
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
                let trimmed = strip_trailing_comment(raw);
                let stripped = trimmed.trim_start();
                if !raw.starts_with([' ', '\t']) && !trimmed.is_empty() {
                    break;
                }
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

fn assign_src_or_dst(token: &str, src: &mut Option<String>, dst: &mut Option<String>) {
    if let Some(rest) = token.strip_prefix("src:") {
        *src = Some(rest.trim().trim_matches(['"', '\'']).to_string());
    } else if let Some(rest) = token.strip_prefix("dst:") {
        *dst = Some(rest.trim().trim_matches(['"', '\'']).to_string());
    }
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
        let trimmed = strip_trailing_comment(raw);
        let stripped = trimmed.trim_start();
        if !raw.starts_with([' ', '\t']) && !trimmed.is_empty() {
            break;
        }
        if let Some(rest) = stripped.strip_prefix("- ") {
            if let (Some(src), Some(dst)) = (current_src.take(), current_dst.take()) {
                out.push((src, dst));
            }
            assign_src_or_dst(rest.trim_start(), &mut current_src, &mut current_dst);
        } else {
            assign_src_or_dst(stripped, &mut current_src, &mut current_dst);
        }
        i += 1;
    }
    if let (Some(src), Some(dst)) = (current_src.take(), current_dst.take()) {
        out.push((src, dst));
    }
    out
}

// --- tests -------------------------------------------------------------------

#[test]
fn rpm_manifest_exists_at_expected_path() {
    let path = rpm_manifest_path();
    assert!(
        path.is_file(),
        "expected nfpm .rpm manifest at {} — DESIGN.md §11.3 requires \
         `packaging/rpm/paladin-auth.yaml` for the CLI",
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
fn rpm_manifest_declares_package_name_paladin_auth() {
    let manifest = read_rpm_manifest();
    let name =
        top_level_scalar(&manifest, "name").expect("rpm nfpm manifest has a top-level `name:` key");
    assert_eq!(
        name, "paladin-auth",
        "rpm package name must be `paladin-auth` so the published artifact matches the binary; \
         got {name:?}",
    );
}

#[test]
fn rpm_manifest_declares_linux_platform_and_amd64_arch() {
    let manifest = read_rpm_manifest();
    let platform = top_level_scalar(&manifest, "platform")
        .expect("rpm nfpm manifest has a top-level `platform:` key");
    assert_eq!(
        platform, "linux",
        "platform must be `linux`; got {platform:?}"
    );
    let arch =
        top_level_scalar(&manifest, "arch").expect("rpm nfpm manifest has a top-level `arch:` key");
    assert_eq!(arch, "amd64", "arch must be `amd64`; got {arch:?}");
}

#[test]
fn rpm_manifest_declares_workspace_license() {
    let manifest = read_rpm_manifest();
    let license = top_level_scalar(&manifest, "license")
        .expect("rpm nfpm manifest has a top-level `license:` key");
    assert_eq!(
        license, "AGPL-3.0-or-later",
        "license must match the workspace [workspace.package] license; got {license:?}",
    );
}

#[test]
fn rpm_manifest_declares_workspace_homepage() {
    let manifest = read_rpm_manifest();
    let homepage = top_level_scalar(&manifest, "homepage")
        .expect("rpm nfpm manifest has a top-level `homepage:` key");
    assert_eq!(
        homepage, "https://paladin-auth.tamx.org",
        "homepage must match the workspace [workspace.package] homepage; got {homepage:?}",
    );
}

#[test]
fn rpm_manifest_version_is_interpolated_from_paladin_auth_version_env() {
    let manifest = read_rpm_manifest();
    let version = top_level_scalar(&manifest, "version")
        .expect("rpm nfpm manifest has a top-level `version:` key");
    assert_eq!(
        version, "${PALADIN_AUTH_VERSION}",
        "rpm `version:` must inherit from ${{PALADIN_AUTH_VERSION}} so the CLI artifact ships under \
         the same string the release tag drives (DESIGN §11.6); got {version:?}",
    );
}

#[test]
fn rpm_manifest_declares_glibc_runtime_dep_only() {
    let manifest = read_rpm_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    for required in REQUIRED_RPM_DEPENDS {
        assert!(
            depends.iter().any(|d| d == required),
            "rpm `depends:` must include `{required}`; got {depends:?}",
        );
    }
    // The CLI is otherwise statically linked per DESIGN §11.3 — any
    // dep beyond the baseline is a regression that masks a runtime
    // surprise on minimal Fedora installs.
    assert_eq!(
        depends.len(),
        REQUIRED_RPM_DEPENDS.len(),
        "rpm `depends:` must match the baseline `{REQUIRED_RPM_DEPENDS:?}` exactly; got {depends:?}",
    );
}

#[test]
fn rpm_manifest_installs_every_required_destination() {
    let manifest = read_rpm_manifest();
    let pairs = contents_src_dst_pairs(&manifest);
    let dsts: Vec<&str> = pairs.iter().map(|(_, dst)| dst.as_str()).collect();
    for required in REQUIRED_INSTALL_DESTINATIONS {
        assert!(
            dsts.iter().any(|d| d == required),
            "rpm `contents:` must install to `{required}`; got destinations {dsts:?}",
        );
    }
}

#[test]
fn rpm_manifest_sources_each_install_from_the_expected_in_tree_path() {
    let manifest = read_rpm_manifest();
    let pairs = contents_src_dst_pairs(&manifest);
    for (required_src, required_dst) in REQUIRED_INSTALL_SOURCES
        .iter()
        .zip(REQUIRED_INSTALL_DESTINATIONS)
    {
        let found = pairs
            .iter()
            .any(|(src, dst)| src == required_src && dst == required_dst);
        assert!(
            found,
            "rpm `contents:` must source `{required_dst}` from `{required_src}`; got {pairs:?}",
        );
    }
}

#[test]
fn rpm_manifest_uses_fedora_package_naming_convention() {
    let manifest = read_rpm_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    for dep in &depends {
        // Debian uses `libc6` for the C runtime; Fedora ships it as
        // `glibc`. Catching a stray `libc6` here is the contract
        // analogue of `rpm_manifest_does_not_use_debian_package_names`
        // in the paladin-auth-gtk test.
        assert!(
            !dep.contains("libc6"),
            "rpm `depends:` must use Fedora package names — `libc6` is Debian; got {dep:?}",
        );
        // RPM's spec syntax accepts `pkg >= version` directly; the
        // Debian parenthesized form `pkg (>= version)` is invalid here.
        assert!(
            !dep.contains('('),
            "rpm `depends:` must use Fedora `pkg >= version` form, not Debian \
             `pkg (>= version)`; got {dep:?}",
        );
    }
}

#[test]
fn rpm_manifest_has_no_maintainer_scripts_section() {
    let manifest = read_rpm_manifest();
    // No `scripts:` key — the CLI never runs preinst, postinst,
    // prerm, or postrm hooks. Vault files live under
    // `$XDG_DATA_HOME/paladin-auth/` and are created by `paladin-auth init`.
    assert!(
        manifest.lines().all(|line| {
            let trimmed = strip_trailing_comment(line).trim_end();
            trimmed != "scripts:"
        }),
        "rpm manifest must not declare a `scripts:` section — DESIGN §11.3 \
         pins package state and user state strictly separate",
    );
}
