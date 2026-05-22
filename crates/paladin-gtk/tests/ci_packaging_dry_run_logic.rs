// SPDX-License-Identifier: AGPL-3.0-or-later

//! Guard test: the CI workflow runs a packaging dry-run that builds
//! the `.deb` / `.rpm` artifacts via `nfpm` from the in-tree
//! manifests and validates the installed payload with
//! `desktop-file-validate` plus `appstreamcli validate --no-net`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` Milestone 7 checklist entry
//! "Add the packaging dry-run job to CI: produces `.deb`, `.rpm`,
//! Flatpak, and `AppImage` artifacts and runs `desktop-file-validate`
//! plus the `AppStream` validator on the installed payload":
//!
//! * A `packaging-dry-run` job in `.github/workflows/ci.yml`
//!   exercises the `.deb` and `.rpm` pipelines end-to-end —
//!   producing the artifacts, extracting them into a staging
//!   directory, and running both validators against the installed
//!   payload.
//! * `nfpm` is installed via its upstream `GitHub` release artifact
//!   so the version stays pinned (a `dnf` / `apt` install would let
//!   the distro pick a divergent version).
//! * The release binary is built with `cargo build --release
//!   --locked -p paladin-gtk` for parity with the
//!   `tests/packaging_reproducible_build_logic.rs` AppImage-script
//!   contract — the same `--locked` flag the §11.6 reproducibility
//!   gate requires.
//! * `PALADIN_VERSION` is exported into the job environment so the
//!   `version: ${PALADIN_VERSION}` substitution in both nfpm
//!   manifests resolves to a concrete value.
//! * Both validators run on the *installed* payload (the files at
//!   the FHS paths the manifests claim), not on the source-tree
//!   originals — that closes the gap the existing
//!   `desktop-metainfo` source-validator job leaves open: a future
//!   regression that drops the desktop entry from the
//!   `contents:` block of either nfpm manifest would land in CI
//!   without breaking the source-validator job, but it must fail
//!   the packaging dry-run.
//!
//! Tests intentionally read the workflow as plain text so the
//! contract is auditable in CI without `nfpm` / `dpkg-deb` /
//! `rpm2cpio` actually being installed on the test runner. The
//! workflow file itself is the source of truth; this test guards
//! it against silent removal.

use std::fs;
use std::path::PathBuf;

/// Path to the workflow file, relative to the workspace root.
const CI_WORKFLOW_RELPATH: &str = ".github/workflows/ci.yml";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/paladin-gtk lives two levels below the workspace root")
        .to_owned()
}

fn read_ci_workflow() -> String {
    let path = workspace_root().join(CI_WORKFLOW_RELPATH);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

/// Extract the body of the `packaging-dry-run:` job from the
/// workflow YAML — every line from the job header through the next
/// top-level `<name>:` header (a non-indented identifier followed
/// by `:`). Returns `None` if the job is absent.
fn extract_packaging_dry_run_job(workflow: &str) -> Option<String> {
    let mut in_job = false;
    let mut body = String::new();
    for line in workflow.lines() {
        if !in_job {
            if line.trim_start() == "packaging-dry-run:"
                && line.starts_with("  ")
                && !line.starts_with("    ")
            {
                in_job = true;
                body.push_str(line);
                body.push('\n');
            }
            continue;
        }
        // A new job starts at the same indentation level (2 spaces)
        // — `  <name>:` with no leading whitespace beyond that.
        let trimmed = line.trim_end();
        let next_job = line.starts_with("  ") && !line.starts_with("   ") && trimmed.ends_with(':');
        if next_job {
            break;
        }
        body.push_str(line);
        body.push('\n');
    }
    if body.is_empty() {
        None
    } else {
        Some(body)
    }
}

// --- job-existence tests ----------------------------------------------------

#[test]
fn ci_workflow_declares_packaging_dry_run_job() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow);
    assert!(
        job.is_some(),
        ".github/workflows/ci.yml must declare a `packaging-dry-run:` job per Milestone 7 \
         packaging checklist; no such job header found in the workflow body",
    );
}

#[test]
fn ci_packaging_dry_run_job_has_a_human_readable_name() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow)
        .expect("packaging-dry-run job must exist; see ci_workflow_declares_packaging_dry_run_job");
    assert!(
        job.contains("name:"),
        "packaging-dry-run job must declare a `name:` field so the GitHub Actions UI shows a \
         readable summary; got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_job_runs_in_a_fedora_container() {
    // The clippy / test jobs both use `fedora:42` so the GTK 4.16 +
    // libadwaita 1.6 floor resolves against the system headers
    // without a PPA dance. The packaging dry-run still needs to
    // `cargo build -p paladin-gtk` (which pulls those system
    // libraries), so it picks the same container.
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow)
        .expect("packaging-dry-run job must exist; see ci_workflow_declares_packaging_dry_run_job");
    assert!(
        job.contains("fedora:42"),
        "packaging-dry-run job must run inside the `fedora:42` container so GTK 4.16 + \
         libadwaita 1.6 headers are available for the release-binary build; got:\n{job}",
    );
}

// --- nfpm install + invocation -----------------------------------------------

#[test]
fn ci_packaging_dry_run_installs_nfpm() {
    // nfpm is the deb/rpm builder both nfpm manifests target. Pin
    // that CI installs it explicitly. The exact install mechanism
    // (curl + tar, `go install`, dnf) is left open — only the
    // presence of the `nfpm` literal is required.
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    assert!(
        job.contains("nfpm"),
        "packaging-dry-run job must install / invoke `nfpm` so the .deb / .rpm pipelines \
         actually run; got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_builds_release_binary_with_locked_lockfile() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    // Parity with packaging/appimage/build-appimage.sh and the
    // §11.6 reproducibility gate: every cargo build invocation in
    // the packaging path uses `--locked` so the lockfile cannot
    // drift between the artifact and the rebuild.
    assert!(
        job.contains("cargo build"),
        "packaging-dry-run job must run `cargo build` so the binary nfpm packages is fresh; \
         got:\n{job}",
    );
    assert!(
        job.contains("--release"),
        "packaging-dry-run job must build with `--release` so the package ships the \
         release-profile binary; got:\n{job}",
    );
    assert!(
        job.contains("--locked"),
        "packaging-dry-run job must build with `--locked` for reproducibility per DESIGN \
         §11.6; got:\n{job}",
    );
    assert!(
        job.contains("paladin-gtk"),
        "packaging-dry-run job must explicitly target `paladin-gtk` (the workspace ships \
         multiple binaries); got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_exports_paladin_version() {
    // Both nfpm manifests reference `${PALADIN_VERSION}` directly:
    //   packaging/deb/paladin-gtk.yaml: version: ${PALADIN_VERSION}
    //   packaging/rpm/paladin-gtk.yaml: version: ${PALADIN_VERSION}
    // The dry-run job must export the value so the substitution
    // resolves to a concrete string (nfpm reads it from the
    // environment when building).
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    assert!(
        job.contains("PALADIN_VERSION"),
        "packaging-dry-run job must export PALADIN_VERSION so the nfpm manifests' \
         `version: ${{PALADIN_VERSION}}` substitution resolves to a concrete value; got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_builds_deb_package_via_nfpm() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    // The deb manifest lives at packaging/deb/paladin-gtk.yaml.
    // Pin that the workflow references that exact path so a future
    // rename has to land an explicit workflow edit too.
    assert!(
        job.contains("packaging/deb/paladin-gtk.yaml"),
        "packaging-dry-run job must reference the in-tree deb manifest path; got:\n{job}",
    );
    // The packager is `nfpm package -p deb`. Match the flag pair
    // rather than the whole command so leading-flag reorderings are
    // accepted.
    assert!(
        job.contains("-p deb") || job.contains("--packager deb"),
        "packaging-dry-run job must invoke nfpm with `-p deb` (or `--packager deb`) to \
         produce the .deb artifact; got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_builds_rpm_package_via_nfpm() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    assert!(
        job.contains("packaging/rpm/paladin-gtk.yaml"),
        "packaging-dry-run job must reference the in-tree rpm manifest path; got:\n{job}",
    );
    assert!(
        job.contains("-p rpm") || job.contains("--packager rpm"),
        "packaging-dry-run job must invoke nfpm with `-p rpm` (or `--packager rpm`) to \
         produce the .rpm artifact; got:\n{job}",
    );
}

// --- payload extraction + validation ----------------------------------------

#[test]
fn ci_packaging_dry_run_extracts_deb_payload() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    // `dpkg-deb -x <pkg> <dir>` extracts the data tarball into a
    // staging directory. Pin that the workflow uses it so the
    // validators run on the actual installed payload, not just on
    // the source-tree originals.
    assert!(
        job.contains("dpkg-deb -x") || job.contains("dpkg-deb --extract"),
        "packaging-dry-run job must extract the .deb payload via `dpkg-deb -x` (or \
         `dpkg-deb --extract`) so the validators check the installed files; got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_extracts_rpm_payload() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    // `rpm2cpio <pkg> | cpio -idmv -D <dir>` is the canonical
    // dependency-free .rpm extraction recipe on Fedora.
    assert!(
        job.contains("rpm2cpio"),
        "packaging-dry-run job must extract the .rpm payload via `rpm2cpio` (piped to \
         `cpio`) so the validators check the installed files; got:\n{job}",
    );
    assert!(
        job.contains("cpio"),
        "packaging-dry-run job must pipe rpm2cpio output through `cpio` (the canonical \
         dependency-free extractor); got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_runs_desktop_file_validate_on_extracted_payload() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    // The installed payload's .desktop lives under
    // `usr/share/applications/org.tamx.Paladin.Gui.desktop` per
    // the deb / rpm manifests. The workflow must run
    // `desktop-file-validate` against that path so a regression in
    // the manifest's `contents:` block (wrong dst path, missing
    // entry, mode change that strips read permissions) fails CI.
    assert!(
        job.contains("desktop-file-validate"),
        "packaging-dry-run job must run `desktop-file-validate` on the installed payload's \
         .desktop entry; got:\n{job}",
    );
    assert!(
        job.contains("usr/share/applications/org.tamx.Paladin.Gui.desktop"),
        "packaging-dry-run job must reference the installed .desktop path \
         `usr/share/applications/org.tamx.Paladin.Gui.desktop` so the validator runs on the \
         extracted payload, not the source-tree original; got:\n{job}",
    );
}

#[test]
fn ci_packaging_dry_run_runs_appstreamcli_validate_on_extracted_payload() {
    let workflow = read_ci_workflow();
    let job = extract_packaging_dry_run_job(&workflow).expect("packaging-dry-run job must exist");
    assert!(
        job.contains("appstreamcli validate"),
        "packaging-dry-run job must run `appstreamcli validate` on the installed payload's \
         metainfo file; got:\n{job}",
    );
    // `--no-net` keeps the validator off the network so the job
    // never depends on external URLs being reachable.
    assert!(
        job.contains("appstreamcli validate --no-net"),
        "packaging-dry-run appstreamcli invocation must include `--no-net` so the job does \
         not depend on network reachability of any homepage / screenshot URL; got:\n{job}",
    );
    assert!(
        job.contains("usr/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml"),
        "packaging-dry-run job must reference the installed metainfo path \
         `usr/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml` so the validator runs on the \
         extracted payload, not the source-tree original; got:\n{job}",
    );
}

// --- helper self-tests ------------------------------------------------------

#[test]
fn extract_packaging_dry_run_job_returns_only_the_named_job_body() {
    let workflow = "\
jobs:
  fmt:
    name: cargo fmt --check
    runs-on: ubuntu-latest
    steps:
      - run: cargo fmt --all -- --check

  packaging-dry-run:
    name: packaging dry-run
    runs-on: ubuntu-latest
    steps:
      - run: nfpm package

  audit:
    name: cargo audit
    runs-on: ubuntu-latest
";
    let body = extract_packaging_dry_run_job(workflow).expect("packaging-dry-run job must extract");
    assert!(body.contains("packaging-dry-run:"));
    assert!(body.contains("name: packaging dry-run"));
    assert!(body.contains("nfpm package"));
    assert!(!body.contains("cargo audit"));
    assert!(!body.contains("cargo fmt --check"));
}

#[test]
fn extract_packaging_dry_run_job_returns_none_when_absent() {
    let workflow = "\
jobs:
  fmt:
    name: cargo fmt --check
    runs-on: ubuntu-latest
";
    assert!(extract_packaging_dry_run_job(workflow).is_none());
}
