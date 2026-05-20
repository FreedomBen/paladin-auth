// SPDX-License-Identifier: AGPL-3.0-or-later

//! Build script for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Crate layout" the GUI binary
//! ships icons, the application stylesheet, and (in subsequent
//! commits) `*.ui` templates and the placeholder icon through a
//! single `gresource` bundle. This build script invokes
//! `glib_build_tools::compile_resources` to pack the
//! `data/paladin-gtk.gresource.xml` manifest into a binary
//! `paladin-gtk.gresource` under `OUT_DIR`. The compiled bundle is
//! `include_bytes!`-embedded by
//! `paladin_gtk::app::model::register_app_gresource_bundle`, which
//! registers it with `gio::resources_register` at startup before
//! `wire_app_css_provider` loads
//! `/org/tamx/Paladin/Gui/style.css` through `gtk::CssProvider`.

fn main() {
    glib_build_tools::compile_resources(
        &["data"],
        "data/paladin-gtk.gresource.xml",
        "paladin-gtk.gresource",
    );
}
