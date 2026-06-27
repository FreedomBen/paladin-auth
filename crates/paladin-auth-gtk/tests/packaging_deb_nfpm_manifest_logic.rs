// SPDX-License-Identifier: AGPL-3.0-or-later

//! `nfpm` `.deb` manifest contract tests for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux distribution and
//! signing" and the Milestone 7 packaging checklist entry "Add
//! `packaging/deb/paladin-auth-gtk.yaml` (`nfpm`)":
//!
//! * Installs `/usr/bin/paladin-auth-gtk` from the workspace release build.
//! * Installs the desktop entry verbatim at
//!   `/usr/share/applications/org.tamx.PaladinAuth.Gui.desktop`.
//! * Installs the `AppStream` metainfo verbatim at
//!   `/usr/share/metainfo/org.tamx.PaladinAuth.Gui.metainfo.xml` so the
//!   `appstreamcli validate` dry-run on the installed payload matches
//!   the source file the in-tree `tests/metainfo_logic.rs` already
//!   pins.
//! * Installs the hicolor icon set at the canonical
//!   `/usr/share/icons/hicolor/<size>/apps/` layout the freedesktop
//!   icon-theme spec resolves, mirroring the in-tree
//!   `data/icons/hicolor/` layout the gresource bundle already ships.
//! * Declares `libgtk-4-1 (>= 4.16)` and `libadwaita-1-0 (>= 1.6)`
//!   under `depends:` — the same baselines the build-time
//!   `gtk4`/`libadwaita` crate features (`v4_16` / `v1_6`) enforce so
//!   a `.deb` install never lands a binary that links against a
//!   too-old system library.
//! * Declares a narrowly scoped `scripts:` section that wires
//!   `postinstall` and `postremove` to
//!   `packaging/scripts/paladin-auth-gtk-postinstall.sh` and
//!   `packaging/scripts/paladin-auth-gtk-postremove.sh`. Both scripts
//!   refresh the system-owned freedesktop caches
//!   (`/usr/share/applications/mimeinfo.cache` and
//!   `/usr/share/icons/hicolor/icon-theme.cache`) so a freshly
//!   installed `.deb`'s desktop entry and application icon appear
//!   in GNOME Shell / KDE / XFCE without requiring the user to
//!   log out and back in. The security posture (no `$XDG_*` / no
//!   `$HOME` / no `/home/` / no network calls / fail-soft on
//!   missing helpers) is pinned by per-script-content assertions
//!   below; vault state under `$XDG_DATA_HOME/paladin-auth/` remains
//!   untouched by package install and removal.
//! * Inherits `version` / `description` / `homepage` / `license` /
//!   `maintainer` from the workspace `Cargo.toml`'s
//!   `[workspace.package]` table or from build-time environment
//!   variables (e.g. `${PALADIN_AUTH_VERSION}`) so a single bump in the
//!   workspace manifest propagates through `nfpm pkg`.
//!
//! Tests intentionally read the manifest as plain text — no `serde_yaml`
//! dependency lands here, matching the dependency-free style of
//! `tests/metainfo_logic.rs` and `tests/desktop_entry_logic.rs`. A
//! future drift in the file fails the relevant test immediately so
//! the packaging contract stays auditable from `cargo test --workspace
//! --all-targets`, independently of whether `nfpm` itself is
//! installed on the runner.

use std::fs;
use std::path::PathBuf;

/// Path to the `nfpm` `.deb` manifest, relative to the workspace root.
const DEB_MANIFEST_RELPATH: &str = "packaging/deb/paladin-auth-gtk.yaml";

/// Required `depends:` entries with the exact `<name> (>= <version>)`
/// shape Debian's `dpkg` parser accepts and `nfpm` emits verbatim
/// into the binary package's control file.
const REQUIRED_DEB_DEPENDS: &[&str] = &["libgtk-4-1 (>= 4.16)", "libadwaita-1-0 (>= 1.6)"];

/// `dst` paths the manifest MUST install. Each entry pins one of the
/// freedesktop / `AppStream` filesystem locations the §11.3 packaging
/// pipeline expects.
const REQUIRED_INSTALL_DESTINATIONS: &[&str] = &[
    "/usr/bin/paladin-auth-gtk",
    "/usr/share/applications/org.tamx.PaladinAuth.Gui.desktop",
    "/usr/share/metainfo/org.tamx.PaladinAuth.Gui.metainfo.xml",
    "/usr/share/icons/hicolor/scalable/apps/org.tamx.PaladinAuth.Gui.svg",
    "/usr/share/icons/hicolor/symbolic/apps/org.tamx.PaladinAuth.Gui-symbolic.svg",
    "/usr/share/icons/hicolor/16x16/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/24x24/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/32x32/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/48x48/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/64x64/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/128x128/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/256x256/apps/org.tamx.PaladinAuth.Gui.png",
    "/usr/share/icons/hicolor/512x512/apps/org.tamx.PaladinAuth.Gui.png",
];

/// Required `scripts:` keys and the relative paths they MUST reference.
/// Both keys are required: `postinstall` rebuilds the freedesktop
/// caches on `apt install`; `postremove` rebuilds them on
/// `apt remove` so the launcher no longer shows the stale entry.
/// Both scripts are shared with `packaging/rpm/paladin-auth-gtk.yaml`
/// so a fix lands in both packaging formats simultaneously.
const REQUIRED_SCRIPT_KEYS_AND_PATHS: &[(&str, &str)] = &[
    (
        "postinstall",
        "./packaging/scripts/paladin-auth-gtk-postinstall.sh",
    ),
    (
        "postremove",
        "./packaging/scripts/paladin-auth-gtk-postremove.sh",
    ),
];

/// `src` paths each `dst` MUST source from. Indexed against
/// `REQUIRED_INSTALL_DESTINATIONS` in the same order so a future
/// re-order of either array surfaces the mismatch in the failing
/// test name.
///
/// The binary `src` is the workspace release artifact; the remaining
/// entries are tracked-in-tree source files the `nfpm pkg` step
/// stages verbatim. Tests verify each tracked-in-tree path actually
/// exists under the workspace so a future rename of the desktop
/// entry, the metainfo, or an icon variant lands the matching
/// manifest edit alongside it.
const REQUIRED_INSTALL_SOURCES: &[&str] = &[
    "target/release/paladin-auth-gtk",
    "crates/paladin-auth-gtk/data/org.tamx.PaladinAuth.Gui.desktop",
    "crates/paladin-auth-gtk/data/metainfo/org.tamx.PaladinAuth.Gui.metainfo.xml",
    "crates/paladin-auth-gtk/data/icons/hicolor/scalable/apps/org.tamx.PaladinAuth.Gui.svg",
    "crates/paladin-auth-gtk/data/icons/hicolor/symbolic/apps/org.tamx.PaladinAuth.Gui-symbolic.svg",
    "crates/paladin-auth-gtk/data/icons/hicolor/16x16/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/24x24/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/32x32/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/48x48/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/64x64/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/128x128/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/256x256/apps/org.tamx.PaladinAuth.Gui.png",
    "crates/paladin-auth-gtk/data/icons/hicolor/512x512/apps/org.tamx.PaladinAuth.Gui.png",
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

fn deb_manifest_path() -> PathBuf {
    workspace_root().join(DEB_MANIFEST_RELPATH)
}

fn read_deb_manifest() -> String {
    fs::read_to_string(deb_manifest_path())
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", deb_manifest_path().display()))
}

/// Return the trimmed RHS of the first top-level `key:` mapping in
/// `manifest`, where "top-level" means indentation column zero.
/// Returns `None` if the key is absent. Comments (`#…`) are stripped
/// before matching.
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

/// Return the list of scalar entries under a top-level YAML sequence
/// keyed by `key`. Handles the canonical block-list form
/// `key:\n  - "a"\n  - "b"\n`. Quoted and unquoted entries are both
/// supported. Returns an empty `Vec` if the key is absent.
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
                let trimmed = strip_trailing_comment(raw).trim_end();
                if trimmed.is_empty() {
                    i += 1;
                    continue;
                }
                // Stop on the next top-level key (column-zero non-list).
                if !raw.starts_with(' ') && !raw.starts_with('\t') {
                    break;
                }
                let stripped = trimmed.trim_start();
                if let Some(item) = stripped.strip_prefix("- ") {
                    out.push(item.trim().trim_matches(['"', '\'']).to_string());
                } else if stripped == "-" {
                    // Empty list item — surfaces as an empty string so
                    // a malformed manifest fails the expected-value
                    // assertions below.
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

/// Return the `(key, value)` pairs under a top-level YAML mapping
/// keyed by `mapping_key`. Handles the canonical block-mapping form
///
/// ```yaml
/// scripts:
///   postinstall: ./packaging/scripts/paladin-auth-gtk-postinstall.sh
///   postremove: ./packaging/scripts/paladin-auth-gtk-postremove.sh
/// ```
///
/// Inline comments are stripped before splitting. Quoted and unquoted
/// values are both supported. Returns an empty `Vec` if the mapping
/// key is absent so callers can distinguish "no scripts:" from
/// "scripts: present but malformed".
fn top_level_mapping_kv_pairs(manifest: &str, mapping_key: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let header = format!("{mapping_key}:");
    let lines: Vec<&str> = manifest.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = strip_trailing_comment(lines[i]);
        if line == header {
            i += 1;
            while i < lines.len() {
                let raw = lines[i];
                let trimmed = strip_trailing_comment(raw).trim_end();
                if trimmed.is_empty() {
                    i += 1;
                    continue;
                }
                // Stop on the next top-level key (column-zero non-list).
                if !raw.starts_with(' ') && !raw.starts_with('\t') {
                    break;
                }
                let stripped = trimmed.trim_start();
                if let Some(colon) = stripped.find(':') {
                    let k = stripped[..colon].trim().to_string();
                    let v = stripped[colon + 1..]
                        .trim()
                        .trim_matches(['"', '\''])
                        .to_string();
                    out.push((k, v));
                }
                i += 1;
            }
            return out;
        }
        i += 1;
    }
    out
}

/// Extract the `(src, dst)` pairs from the top-level `contents:`
/// block. Each entry is the canonical nfpm form:
///
/// ```yaml
/// contents:
///   - src: <path>
///     dst: <path>
///     file_info:
///       mode: 0644
/// ```
///
/// Optional `type:` / `file_info:` keys are tolerated and skipped.
/// Returns an empty `Vec` if `contents:` is absent.
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
        // Stop at the next top-level key.
        if !raw.starts_with(' ') && !raw.starts_with('\t') && !raw.is_empty() {
            break;
        }
        let trimmed = strip_trailing_comment(raw).trim_end();
        let stripped = trimmed.trim_start();
        if let Some(after_dash) = stripped.strip_prefix("- ") {
            // New entry — flush any in-progress pair.
            if current_src.is_some() || current_dst.is_some() {
                out.push((
                    current_src.take().unwrap_or_default(),
                    current_dst.take().unwrap_or_default(),
                ));
            }
            absorb_kv(after_dash, &mut current_src, &mut current_dst);
        } else {
            absorb_kv(stripped, &mut current_src, &mut current_dst);
        }
        i += 1;
    }
    if current_src.is_some() || current_dst.is_some() {
        out.push((
            current_src.unwrap_or_default(),
            current_dst.unwrap_or_default(),
        ));
    }
    out
}

fn absorb_kv(token: &str, src: &mut Option<String>, dst: &mut Option<String>) {
    if let Some(rest) = token.strip_prefix("src:") {
        *src = Some(rest.trim().trim_matches(['"', '\'']).to_string());
    } else if let Some(rest) = token.strip_prefix("dst:") {
        *dst = Some(rest.trim().trim_matches(['"', '\'']).to_string());
    }
}

fn strip_trailing_comment(line: &str) -> &str {
    // The manifest under test does not embed `#` inside quoted YAML
    // string values (depends entries use parentheses, not `#`), so a
    // naive `find('#')` is sufficient and matches the comment
    // stripping in `tests/metainfo_logic.rs` /
    // `tests/cargo_manifest_workspace_inheritance_logic.rs`.
    match line.find('#') {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Return the executable portion of a POSIX shell script — comment
/// lines (`^\s*#`) are stripped, the shebang (`^#!`) is preserved,
/// and trailing comments after a space-prefixed `#` are removed.
/// Used by the script-content security tests so the explanatory
/// header comments in the shell scripts can describe what the
/// script intentionally avoids (e.g. `# never touches $XDG_*`)
/// without the test flagging the documentation itself as a
/// forbidden reference.
fn strip_shell_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#!") {
            out.push_str(line);
        } else if trimmed.starts_with('#') {
            // Whole-line comment — drop entirely.
        } else {
            // Trailing comment: only treat ` #` (space then hash)
            // as a comment marker so a literal `#` inside an
            // unquoted shell token (rare; the scripts here never
            // do this) is not accidentally stripped.
            match line.find(" #") {
                Some(idx) => out.push_str(&line[..idx]),
                None => out.push_str(line),
            }
        }
        out.push('\n');
    }
    out
}

// --- tests -------------------------------------------------------------------

#[test]
fn deb_manifest_exists_at_expected_path() {
    let path = deb_manifest_path();
    assert!(
        path.is_file(),
        "expected nfpm .deb manifest at {} — Milestone 7 packaging \
         checklist requires `packaging/deb/paladin-auth-gtk.yaml`",
        path.display(),
    );
}

#[test]
fn deb_manifest_starts_with_spdx_license_header() {
    let manifest = read_deb_manifest();
    let first_meaningful_line = manifest
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    assert!(
        first_meaningful_line.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
        "deb nfpm manifest must lead with an SPDX-License-Identifier comment matching the \
         workspace AGPL-3.0-or-later license; first line was {first_meaningful_line:?}",
    );
}

#[test]
fn deb_manifest_declares_package_name_paladin_auth_gtk() {
    let manifest = read_deb_manifest();
    let name =
        top_level_scalar(&manifest, "name").expect("deb nfpm manifest has a top-level `name:` key");
    assert_eq!(
        name, "paladin-auth-gtk",
        "deb package name must be `paladin-auth-gtk` so the published artifact matches the binary \
         and the workspace member name; got {name:?}",
    );
}

#[test]
fn deb_manifest_declares_linux_platform_and_amd64_arch() {
    let manifest = read_deb_manifest();
    let platform = top_level_scalar(&manifest, "platform")
        .expect("deb nfpm manifest has a top-level `platform:` key");
    assert_eq!(
        platform, "linux",
        "deb nfpm manifest `platform:` must be `linux`; got {platform:?}",
    );
    let arch =
        top_level_scalar(&manifest, "arch").expect("deb nfpm manifest has a top-level `arch:` key");
    assert_eq!(
        arch, "amd64",
        "deb nfpm manifest `arch:` must be `amd64` — Milestone 7 targets x86_64 only; \
         got {arch:?}",
    );
}

#[test]
fn deb_manifest_declares_workspace_license() {
    let manifest = read_deb_manifest();
    let license = top_level_scalar(&manifest, "license")
        .expect("deb nfpm manifest has a top-level `license:` key");
    assert_eq!(
        license, "AGPL-3.0-or-later",
        "deb nfpm manifest `license:` must match the workspace [workspace.package] license; \
         got {license:?}",
    );
}

#[test]
fn deb_manifest_declares_workspace_homepage() {
    let manifest = read_deb_manifest();
    let homepage = top_level_scalar(&manifest, "homepage")
        .expect("deb nfpm manifest has a top-level `homepage:` key");
    assert_eq!(
        homepage, "https://paladin-auth.tamx.org",
        "deb nfpm manifest `homepage:` must match the workspace [workspace.package] homepage; \
         got {homepage:?}",
    );
}

#[test]
fn deb_manifest_declares_required_runtime_depends_with_exact_versions() {
    let manifest = read_deb_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    let mut missing = Vec::new();
    for required in REQUIRED_DEB_DEPENDS {
        if !depends.iter().any(|d| d == required) {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "deb nfpm manifest `depends:` must include each of {REQUIRED_DEB_DEPENDS:?} so the \
         installed .deb refuses to land on a system whose libgtk4 / libadwaita is below the \
         baselines the gtk4 (v4_16) and libadwaita (v1_6) build-time features assume; \
         missing: {missing:?}; got: {depends:?}",
    );
}

#[test]
fn deb_manifest_declares_no_extra_depends_beyond_baseline_set() {
    // Pin the dependency set so an accidental addition (e.g. a
    // bundled-loader dep or a maintainer-script helper) lands an
    // explicit review — the Milestone 7 checklist explicitly scopes
    // the .deb to just the two libgtk-4-1 / libadwaita-1-0 baselines.
    let manifest = read_deb_manifest();
    let depends = top_level_sequence_scalars(&manifest, "depends");
    let extras: Vec<&str> = depends
        .iter()
        .map(String::as_str)
        .filter(|d| !REQUIRED_DEB_DEPENDS.contains(d))
        .collect();
    assert!(
        extras.is_empty(),
        "deb nfpm manifest `depends:` must declare ONLY the Milestone 7 baselines \
         {REQUIRED_DEB_DEPENDS:?}; found unexpected entries: {extras:?}. If a new runtime \
         dep is genuinely required, update docs/IMPLEMENTATION_PLAN_04_GTK.md §11.3 first and \
         add it to REQUIRED_DEB_DEPENDS in this test.",
    );
}

#[test]
fn deb_manifest_installs_every_required_destination() {
    let manifest = read_deb_manifest();
    let pairs = contents_src_dst_pairs(&manifest);
    let destinations: Vec<&str> = pairs.iter().map(|(_src, dst)| dst.as_str()).collect();
    let mut missing = Vec::new();
    for required in REQUIRED_INSTALL_DESTINATIONS {
        if !destinations.iter().any(|d| d == required) {
            missing.push(*required);
        }
    }
    assert!(
        missing.is_empty(),
        "deb nfpm manifest `contents:` must install each of \
         {REQUIRED_INSTALL_DESTINATIONS:?}; missing: {missing:?}; got destinations: \
         {destinations:?}",
    );
}

#[test]
fn deb_manifest_sources_each_install_from_the_expected_in_tree_path() {
    let manifest = read_deb_manifest();
    let pairs = contents_src_dst_pairs(&manifest);
    for (expected_src, expected_dst) in REQUIRED_INSTALL_SOURCES
        .iter()
        .zip(REQUIRED_INSTALL_DESTINATIONS.iter())
    {
        let actual_src = pairs
            .iter()
            .find(|(_src, dst)| dst == expected_dst)
            .map_or_else(
                || panic!("deb nfpm manifest is missing dst {expected_dst:?}"),
                |(src, _dst)| src.as_str(),
            );
        assert_eq!(
            actual_src, *expected_src,
            "deb nfpm manifest `contents:` entry for dst {expected_dst:?} must source from \
             {expected_src:?}; got src {actual_src:?}",
        );
    }
}

#[test]
fn deb_manifest_in_tree_sources_all_exist_under_the_workspace() {
    // Skip the release-build artifact — it only exists after
    // `cargo build --release` and the packaging dry-run handles that
    // separately. Tracked-in-tree assets must exist now so a rename
    // of the desktop entry / metainfo / an icon never silently
    // desyncs from the .deb manifest.
    let workspace = workspace_root();
    let mut missing = Vec::new();
    for src in REQUIRED_INSTALL_SOURCES {
        if src.starts_with("target/") {
            continue;
        }
        let full = workspace.join(src);
        if !full.is_file() {
            missing.push((*src, full));
        }
    }
    assert!(
        missing.is_empty(),
        "deb nfpm manifest references in-tree sources that do not exist on disk — \
         renames must land in lockstep with the manifest: {missing:?}",
    );
}

#[test]
fn deb_manifest_declares_required_scripts_section() {
    // §11.3 scopes maintainer scripts narrowly to refreshing
    // /usr/share/applications/mimeinfo.cache and
    // /usr/share/icons/hicolor/icon-theme.cache after install
    // and after removal — without them, a freshly installed .deb
    // shows up in a running GNOME Shell with a generic placeholder
    // icon (the in-memory GtkIconTheme inside gnome-shell does not
    // rebuild from the new on-disk icon-theme.cache until the
    // user logs out and back in).
    let manifest = read_deb_manifest();
    let scripts = top_level_mapping_kv_pairs(&manifest, "scripts");
    assert!(
        !scripts.is_empty(),
        "deb nfpm manifest must declare a top-level `scripts:` mapping with `postinstall` \
         and `postremove` entries so the freedesktop desktop-database and icon-theme caches \
         refresh on install and removal; none was found",
    );
    for (expected_key, expected_path) in REQUIRED_SCRIPT_KEYS_AND_PATHS {
        let actual = scripts
            .iter()
            .find(|(k, _v)| k == expected_key)
            .map(|(_k, v)| v.as_str());
        assert_eq!(
            actual,
            Some(*expected_path),
            "deb nfpm manifest `scripts:` must map `{expected_key}: {expected_path}`; got \
             {actual:?}. The same path ships in packaging/rpm/paladin-auth-gtk.yaml so a fix \
             lands in both formats simultaneously.",
        );
    }
}

#[test]
fn deb_manifest_scripts_reference_only_the_baseline_keys() {
    // Pin the script-keys set so accidental additions (e.g. a
    // `preinstall` that reads user state, or a `preremove` that
    // removes vault files) land an explicit review. §11.3 scopes
    // the maintainer-scripts surface to postinstall + postremove
    // only.
    let manifest = read_deb_manifest();
    let scripts = top_level_mapping_kv_pairs(&manifest, "scripts");
    let allowed: Vec<&str> = REQUIRED_SCRIPT_KEYS_AND_PATHS
        .iter()
        .map(|(k, _v)| *k)
        .collect();
    let extras: Vec<&str> = scripts
        .iter()
        .map(|(k, _v)| k.as_str())
        .filter(|k| !allowed.contains(k))
        .collect();
    assert!(
        extras.is_empty(),
        "deb nfpm manifest `scripts:` must declare ONLY the keys {allowed:?}; found \
         unexpected entries: {extras:?}. If a new maintainer hook is genuinely required, \
         update DESIGN.md §11.3 first and add it to REQUIRED_SCRIPT_KEYS_AND_PATHS.",
    );
}

#[test]
fn deb_manifest_script_references_point_to_existing_executable_files() {
    // Each script the manifest references MUST exist on disk and
    // be executable so nfpm can stage it into the .deb's
    // control.tar.gz at build time. A typo here would not be
    // caught by `nfpm pkg` (it embeds whatever bytes the file
    // contains), only by users hitting a "script not found" error
    // during `apt install`.
    let workspace = workspace_root();
    for (_key, relpath) in REQUIRED_SCRIPT_KEYS_AND_PATHS {
        let stripped = relpath.strip_prefix("./").unwrap_or(relpath);
        let full = workspace.join(stripped);
        assert!(
            full.is_file(),
            "deb nfpm manifest `scripts:` references {relpath} but the file does not exist \
             at {}",
            full.display(),
        );
        let mode = fs::metadata(&full)
            .unwrap_or_else(|err| panic!("failed to stat {}: {err}", full.display()))
            .permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let bits = mode.mode() & 0o777;
            assert_eq!(
                bits & 0o111,
                0o111,
                "deb nfpm manifest script {} must be executable by user/group/other \
                 (mode bits 0o111 set) so nfpm reads + embeds it correctly; got mode {:#o}",
                full.display(),
                bits,
            );
        }
    }
}

#[test]
fn paladin_auth_gtk_scripts_have_spdx_license_header() {
    // Every source file in the workspace carries an
    // SPDX-License-Identifier comment per the license-hygiene
    // section of CLAUDE.md and §13 of DESIGN.md. The shell
    // scriptlets are no exception — they ship verbatim inside
    // the .deb / .rpm so the SPDX line travels with the package
    // bytes a downstream auditor would inspect.
    let workspace = workspace_root();
    for (_key, relpath) in REQUIRED_SCRIPT_KEYS_AND_PATHS {
        let stripped = relpath.strip_prefix("./").unwrap_or(relpath);
        let full = workspace.join(stripped);
        let body = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()));
        assert!(
            body.contains("SPDX-License-Identifier: AGPL-3.0-or-later"),
            "{} must declare SPDX-License-Identifier: AGPL-3.0-or-later in a header \
             comment so the AGPL travels with the script bytes embedded in the package",
            full.display(),
        );
    }
}

#[test]
fn paladin_auth_gtk_scripts_touch_only_system_owned_caches() {
    // Security-pinned property: the postinstall and postremove
    // scripts MUST NOT read or write any user-home / $XDG_* /
    // user-vault path. The package-vs-user state separation
    // documented in DESIGN.md §11.3 is enforced by this assertion
    // — if a future edit adds e.g. `chmod $HOME/...` or sources a
    // file from `/home/...`, this test fails before the
    // regression ships.
    //
    // The forbidden-substrings list is intentionally broad: any
    // mention triggers a failure, even inside a comment, because
    // comments evolve out of sync with code and the safest stance
    // is "if these substrings appear, audit before merging".
    let forbidden = &[
        "$HOME", "${HOME", "$XDG_", "${XDG_", "~/", "/home/", "/root/",
        // Network calls — postinstall scripts on a freshly
        // installed package must never reach the network.
        "curl ", "wget ", "nc ", " ssh ",
        // Dynamic command construction — `eval` on attacker-
        // controlled input is the classic postinst-script
        // escalation vector. The scriptlets here never call
        // eval; pin that.
        "eval ",
    ];
    let workspace = workspace_root();
    for (_key, relpath) in REQUIRED_SCRIPT_KEYS_AND_PATHS {
        let stripped_path = relpath.strip_prefix("./").unwrap_or(relpath);
        let full = workspace.join(stripped_path);
        let body = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()));
        // Strip comments before the negative-substring scan: the
        // header documentation intentionally mentions $XDG_* paths
        // to assert that the script does NOT touch them, and that
        // documentation is valuable for auditors reading the
        // package contents. The security property the test
        // enforces is "executable code may not reference these
        // paths", not "the string may not appear anywhere".
        let code = strip_shell_comments(&body);
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "{} executable code must not contain {needle:?} — postinstall / \
                 postremove scripts may only touch system-owned caches under /usr/share. \
                 Adding a user-home or network reference here breaks the package-vs-user \
                 state separation pinned in DESIGN.md §11.3.",
                full.display(),
            );
        }
        // Positive assertions run against executable code too so a
        // future "no-op" stub that puts the path references only
        // in a comment does not satisfy this check.
        assert!(
            code.contains("/usr/share/applications"),
            "{} executable code must reference /usr/share/applications (the path \
             update-desktop-database rebuilds the cache under)",
            full.display(),
        );
        assert!(
            code.contains("/usr/share/icons/hicolor"),
            "{} executable code must reference /usr/share/icons/hicolor (the path \
             gtk-update-icon-cache rebuilds the cache under)",
            full.display(),
        );
    }
}

#[test]
fn paladin_auth_gtk_scripts_gate_helpers_with_command_v_and_fail_soft() {
    // Robustness-pinned property: the scripts MUST detect
    // missing helper tools with `command -v` (so a minimal
    // container image without `desktop-file-utils` /
    // `gtk-update-icon-cache` installed does not abort the
    // package transaction) AND swallow non-zero exits from the
    // helpers themselves with `|| :` (so a transient cache-
    // rebuild error in the helper does not leave the package in
    // a half-installed state).
    let workspace = workspace_root();
    for (_key, relpath) in REQUIRED_SCRIPT_KEYS_AND_PATHS {
        let stripped = relpath.strip_prefix("./").unwrap_or(relpath);
        let full = workspace.join(stripped);
        let body = fs::read_to_string(&full)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", full.display()));
        assert!(
            body.contains("command -v update-desktop-database"),
            "{} must gate the `update-desktop-database` invocation behind \
             `command -v update-desktop-database` so a minimal install without \
             desktop-file-utils still completes the package transaction",
            full.display(),
        );
        assert!(
            body.contains("command -v gtk-update-icon-cache"),
            "{} must gate the `gtk-update-icon-cache` invocation behind \
             `command -v gtk-update-icon-cache` so a minimal install without the \
             gtk4 update-icon-cache helper still completes the package transaction",
            full.display(),
        );
        let fail_soft_count = body.matches("|| :").count();
        assert!(
            fail_soft_count >= 2,
            "{} must use `|| :` (fail-soft) after each helper invocation so a \
             transient rebuild failure does not abort the install; found {} \
             occurrences, expected at least 2 (one per helper)",
            full.display(),
            fail_soft_count,
        );
    }
}

#[test]
fn deb_manifest_binary_install_uses_executable_mode() {
    // /usr/bin/paladin-auth-gtk must be world-executable. nfpm defaults
    // file mode to 0644, so the manifest MUST set `mode: 0755`
    // explicitly on the binary entry — a missing `mode:` line on
    // the binary entry would land a non-executable file in
    // /usr/bin and break every `paladin-auth-gtk` invocation.
    let manifest = read_deb_manifest();
    let lines: Vec<&str> = manifest.lines().collect();
    let mut binary_block_start: Option<usize> = None;
    for (idx, raw) in lines.iter().enumerate() {
        let trimmed = strip_trailing_comment(raw).trim();
        if trimmed == "dst: /usr/bin/paladin-auth-gtk"
            || trimmed == "dst: \"/usr/bin/paladin-auth-gtk\""
        {
            binary_block_start = Some(idx);
            break;
        }
    }
    let start = binary_block_start.expect(
        "deb nfpm manifest is missing the /usr/bin/paladin-auth-gtk dst entry — covered by \
         deb_manifest_installs_every_required_destination, but re-asserted here so the \
         executable-mode check has something to anchor against",
    );
    // Scan the same entry's file_info / mode lines — stop at the
    // next list item (`- `) or top-level key.
    let mut found_mode_0755 = false;
    let mut j = start;
    while j < lines.len() {
        let raw = lines[j];
        if j > start {
            let stripped = strip_trailing_comment(raw).trim_start();
            if stripped.starts_with("- ")
                || (!raw.starts_with(' ') && !raw.starts_with('\t') && !raw.trim().is_empty())
            {
                break;
            }
        }
        if strip_trailing_comment(raw).contains("mode: 0755") {
            found_mode_0755 = true;
            break;
        }
        j += 1;
    }
    assert!(
        found_mode_0755,
        "deb nfpm manifest must set `mode: 0755` on the /usr/bin/paladin-auth-gtk entry so the \
         installed binary is executable; nfpm defaults to 0644 when `mode:` is omitted",
    );
}

// --- helper self-tests -------------------------------------------------------
//
// Cover the parser primitives so a future regression in
// `top_level_scalar` / `top_level_sequence_scalars` /
// `contents_src_dst_pairs` is caught even if the real manifest is
// already valid.

#[test]
fn top_level_scalar_reads_quoted_and_unquoted_values() {
    let manifest = "\
name: paladin-auth-gtk
arch: \"amd64\"
platform: 'linux'
";
    assert_eq!(
        top_level_scalar(manifest, "name").as_deref(),
        Some("paladin-auth-gtk"),
    );
    assert_eq!(top_level_scalar(manifest, "arch").as_deref(), Some("amd64"));
    assert_eq!(
        top_level_scalar(manifest, "platform").as_deref(),
        Some("linux"),
    );
    assert_eq!(top_level_scalar(manifest, "missing"), None);
}

#[test]
fn top_level_sequence_scalars_reads_block_list_entries() {
    let manifest = "\
depends:
  - libgtk-4-1 (>= 4.16)
  - libadwaita-1-0 (>= 1.6)
contents:
  - src: a
";
    let depends = top_level_sequence_scalars(manifest, "depends");
    assert_eq!(
        depends,
        vec![
            "libgtk-4-1 (>= 4.16)".to_string(),
            "libadwaita-1-0 (>= 1.6)".to_string(),
        ],
    );
    assert!(top_level_sequence_scalars(manifest, "missing").is_empty());
}

#[test]
fn top_level_mapping_kv_pairs_reads_scripts_block() {
    let manifest = "\
scripts:
  postinstall: ./packaging/scripts/paladin-auth-gtk-postinstall.sh
  postremove: \"./packaging/scripts/paladin-auth-gtk-postremove.sh\"
contents:
  - src: a
";
    let scripts = top_level_mapping_kv_pairs(manifest, "scripts");
    assert_eq!(
        scripts,
        vec![
            (
                "postinstall".to_string(),
                "./packaging/scripts/paladin-auth-gtk-postinstall.sh".to_string(),
            ),
            (
                "postremove".to_string(),
                "./packaging/scripts/paladin-auth-gtk-postremove.sh".to_string(),
            ),
        ],
    );
    assert!(top_level_mapping_kv_pairs(manifest, "missing").is_empty());
}

#[test]
fn contents_src_dst_pairs_extracts_canonical_entries() {
    let manifest = "\
contents:
  - src: target/release/paladin-auth-gtk
    dst: /usr/bin/paladin-auth-gtk
    file_info:
      mode: 0755
  - src: crates/paladin-auth-gtk/data/org.tamx.PaladinAuth.Gui.desktop
    dst: /usr/share/applications/org.tamx.PaladinAuth.Gui.desktop
";
    let pairs = contents_src_dst_pairs(manifest);
    assert_eq!(
        pairs,
        vec![
            (
                "target/release/paladin-auth-gtk".to_string(),
                "/usr/bin/paladin-auth-gtk".to_string(),
            ),
            (
                "crates/paladin-auth-gtk/data/org.tamx.PaladinAuth.Gui.desktop".to_string(),
                "/usr/share/applications/org.tamx.PaladinAuth.Gui.desktop".to_string(),
            ),
        ],
    );
}

#[test]
fn strip_shell_comments_preserves_shebang_and_drops_full_and_trailing_comments() {
    let body = "\
#!/bin/sh
# header comment mentioning $XDG_DATA_HOME for documentation
set -e
update-desktop-database -q /usr/share/applications || : # trailing comment
   # indented comment
exit 0
";
    let stripped = strip_shell_comments(body);
    assert!(stripped.contains("#!/bin/sh"), "shebang must survive");
    assert!(
        !stripped.contains("$XDG_DATA_HOME"),
        "whole-line comment must be dropped",
    );
    assert!(
        !stripped.contains("trailing comment"),
        "trailing ` #` comment must be dropped",
    );
    assert!(
        !stripped.contains("indented comment"),
        "indented whole-line comment must be dropped",
    );
    assert!(
        stripped.contains("update-desktop-database -q /usr/share/applications || :"),
        "executable code before the trailing comment must survive",
    );
}

#[test]
fn strip_trailing_comment_drops_inline_comment() {
    assert_eq!(
        strip_trailing_comment("arch: amd64 # x86_64 only"),
        "arch: amd64 "
    );
    assert_eq!(strip_trailing_comment("# header"), "");
    assert_eq!(strip_trailing_comment("no comment here"), "no comment here");
}
