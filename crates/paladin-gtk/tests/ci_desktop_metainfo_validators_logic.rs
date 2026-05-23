// SPDX-License-Identifier: AGPL-3.0-or-later

//! Guard test: the CI workflow runs `desktop-file-validate` and the
//! `AppStream` validator against the paladin-gtk desktop + metainfo
//! files.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop integration" and
//! the Milestone 7 checklist entry "Add `desktop-file-validate` and the
//! `AppStream` validator to the CI / packaging dry-run so both files are
//! checked on every build."
//!
//! The freedesktop / `AppStream` validators are external binaries; they
//! belong in CI, not in the unit-test loop. This file therefore guards
//! the *workflow declaration* in `.github/workflows/ci.yml`: a future
//! edit that drops either validator from CI will fail this test
//! immediately, independent of whether the validators are installed
//! locally.

use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    // tests run in `crates/paladin-gtk/`; the workspace root is two
    // levels up. The `docs/IMPLEMENTATION_PLAN_04_GTK.md` and the
    // `.github/workflows/` checkout live there.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/paladin-gtk lives two levels below the workspace root")
        .to_owned()
}

fn read_ci_workflow() -> String {
    let path = workspace_root()
        .join(".github")
        .join("workflows")
        .join("ci.yml");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn ci_workflow_runs_desktop_file_validate_on_the_desktop_entry() {
    let workflow = read_ci_workflow();
    assert!(
        workflow.contains("desktop-file-validate"),
        ".github/workflows/ci.yml must run `desktop-file-validate` against the §11.3 desktop entry per docs/IMPLEMENTATION_PLAN_04_GTK.md",
    );
    assert!(
        workflow.contains("crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop"),
        "the desktop-file-validate step must reference the desktop file at its committed path",
    );
}

#[test]
fn ci_workflow_runs_appstreamcli_validate_on_the_metainfo_file() {
    let workflow = read_ci_workflow();
    assert!(
        workflow.contains("appstreamcli validate"),
        ".github/workflows/ci.yml must run `appstreamcli validate` against the AppStream metainfo per docs/IMPLEMENTATION_PLAN_04_GTK.md",
    );
    assert!(
        workflow.contains("crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml"),
        "the appstreamcli validate step must reference the metainfo file at its committed path",
    );
    // `--no-net` keeps the validator off the network so the job
    // never depends on external URLs being reachable — the
    // substantive schema / required-field checks still run.
    assert!(
        workflow.contains("appstreamcli validate --no-net"),
        "appstreamcli must run with --no-net so CI does not depend on network reachability of any homepage / screenshot URL",
    );
}

#[test]
fn ci_workflow_installs_both_validators_in_one_apt_invocation() {
    let workflow = read_ci_workflow();
    // The `desktop-file-utils` package ships `desktop-file-validate`
    // and the `appstream` package ships `appstreamcli` on Debian /
    // Ubuntu runners. A single `apt-get install` keeps the CI image
    // setup terse.
    assert!(
        workflow.contains("desktop-file-utils"),
        "CI must install the `desktop-file-utils` Debian package (ships desktop-file-validate)",
    );
    assert!(
        workflow.contains("appstream"),
        "CI must install the `appstream` Debian package (ships appstreamcli)",
    );
}
