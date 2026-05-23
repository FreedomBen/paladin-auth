// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build script for `paladin-gtk`.
//!
//! Two responsibilities:
//!
//! 1. Pack `data/paladin-gtk.gresource.xml` into a binary
//!    `paladin-gtk.gresource` under `OUT_DIR` via
//!    `glib_build_tools::compile_resources`.  The compiled bundle
//!    is `include_bytes!`-embedded by
//!    `paladin_gtk::app::model::register_app_gresource_bundle`,
//!    which registers it with `gio::resources_register` at startup
//!    before `wire_app_css_provider` loads
//!    `/org/tamx/Paladin/Gui/style.css` through `gtk::CssProvider`.
//!
//! 2. Compile `data/org.tamx.Paladin.Gui.gschema.xml` into
//!    `OUT_DIR/schemas/gschemas.compiled` via the system
//!    `glib-compile-schemas` and export the directory path as
//!    `PALADIN_GTK_SCHEMA_DIR` so `paladin_gtk::gsettings` can
//!    `gio::SettingsSchemaSource::from_directory` it for dev /
//!    test runs without relying on a system-wide install of the
//!    schema.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // `glib-compile-resources` searches each `--sourcedir` in order
    // for files referenced by the manifest. `data` covers the
    // GTK-owned payload (`style.css`, bundled icons). `../..`
    // (the workspace root relative to this build script's cwd,
    // which is `crates/paladin-gtk/`) lets the manifest pull in
    // the repo-root `LICENSE` (AGPL-3.0-or-later body shipped
    // under `/org/tamx/Paladin/Gui/LICENSE`) without a duplicate
    // copy under `data/`. Track the LICENSE file explicitly so
    // a `LICENSE` edit re-runs the build script and the bundled
    // body stays in lockstep with the on-disk source of truth.
    println!("cargo:rerun-if-changed=../../LICENSE");
    glib_build_tools::compile_resources(
        &["data", "../.."],
        "data/paladin-gtk.gresource.xml",
        "paladin-gtk.gresource",
    );

    compile_gsettings_schema();
}

/// Compile `data/org.tamx.Paladin.Gui.gschema.xml` into
/// `OUT_DIR/schemas/gschemas.compiled`.
///
/// Copies the source XML into the staging dir first so
/// `glib-compile-schemas` (which compiles every `.gschema.xml` in
/// the directory it is pointed at) operates on a clean tree.
/// Exports `PALADIN_GTK_SCHEMA_DIR` so `paladin_gtk::gsettings`
/// can pick up the compiled schema for dev / test runs without
/// requiring a system-wide install of the schema.
fn compile_gsettings_schema() {
    println!("cargo:rerun-if-changed=data/org.tamx.Paladin.Gui.gschema.xml");

    let out_dir = std::env::var_os("OUT_DIR").expect("OUT_DIR set by cargo");
    let schema_dir = PathBuf::from(&out_dir).join("schemas");
    std::fs::create_dir_all(&schema_dir).expect("create OUT_DIR/schemas");

    let src = PathBuf::from("data/org.tamx.Paladin.Gui.gschema.xml");
    let dst = schema_dir.join("org.tamx.Paladin.Gui.gschema.xml");
    std::fs::copy(&src, &dst).expect("copy gschema.xml into OUT_DIR/schemas");

    let status = Command::new("glib-compile-schemas")
        .arg(&schema_dir)
        .status()
        .expect("invoke glib-compile-schemas — install glib2 / glib-2.0-dev");
    assert!(
        status.success(),
        "glib-compile-schemas failed for {}",
        schema_dir.display(),
    );

    println!(
        "cargo:rustc-env=PALADIN_GTK_SCHEMA_DIR={}",
        schema_dir.display(),
    );
}
