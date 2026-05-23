// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coverage for `paladin_gtk::gsettings`.
//!
//! These exercise the schema-source lookup wired up by
//! `build.rs` (which compiles `data/org.tamx.Paladin.Gui.gschema.xml`
//! into `OUT_DIR/schemas/`) so a regression in either the schema
//! XML or the `PALADIN_GTK_SCHEMA_DIR` export surfaces as a
//! failing test rather than as a "preferences dialog never
//! remembers anything" symptom at runtime.
//!
//! `GSettings` reads / writes go through a memory backend so the
//! tests do not touch the user's dconf store.  The schema
//! lookup itself, however, comes from the build-time directory —
//! that is the path the in-process `paladin_gtk::gsettings::app_settings`
//! consults first.

use paladin_gtk::gsettings::{SCHEMA_ID, SHOW_COLUMN_HEADERS_KEY, SHOW_SECTION_HEADERS_KEY};
use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;

const BUILD_TIME_SCHEMA_DIR: &str = env!("PALADIN_GTK_SCHEMA_DIR");

fn build_time_schema() -> gio::SettingsSchema {
    let source = gio::SettingsSchemaSource::from_directory(BUILD_TIME_SCHEMA_DIR, None, false)
        .expect("build.rs should have compiled gschemas into PALADIN_GTK_SCHEMA_DIR");
    source
        .lookup(SCHEMA_ID, true)
        .expect("schema id must match the <schema id=…> attribute in the XML")
}

fn memory_backed_settings() -> gio::Settings {
    let schema = build_time_schema();
    let backend = gio::functions::memory_settings_backend_new();
    gio::Settings::new_full(&schema, Some(&backend), None)
}

#[test]
fn schema_carries_show_section_headers_key() {
    let schema = build_time_schema();
    assert!(
        schema.has_key(SHOW_SECTION_HEADERS_KEY),
        "the gschema must declare `{SHOW_SECTION_HEADERS_KEY}` so \
         `paladin_gtk::gsettings::show_section_headers` resolves",
    );
}

#[test]
fn show_section_headers_default_is_false() {
    // Default-off is the contract pinned in DESIGN §7: section
    // headers are an opt-in display preference, never on out of
    // the box.
    let settings = memory_backed_settings();
    assert!(
        !settings.boolean(SHOW_SECTION_HEADERS_KEY),
        "section headers default to false per DESIGN §7",
    );
}

#[test]
fn show_section_headers_round_trip_via_memory_backend() {
    let settings = memory_backed_settings();
    settings
        .set_boolean(SHOW_SECTION_HEADERS_KEY, true)
        .expect("write the show-section-headers key");
    assert!(
        settings.boolean(SHOW_SECTION_HEADERS_KEY),
        "writing true and re-reading should return true",
    );
    settings
        .set_boolean(SHOW_SECTION_HEADERS_KEY, false)
        .expect("write the show-section-headers key back to false");
    assert!(
        !settings.boolean(SHOW_SECTION_HEADERS_KEY),
        "writing false and re-reading should return false",
    );
}

#[test]
fn changed_signal_fires_for_show_section_headers_write() {
    // The AppModel registers a `changed::show-section-headers`
    // handler on its `gio::Settings` clone so a toggle from
    // SettingsComponent dispatches a refresh to AccountListComponent.
    // Pin the contract that a write actually fires the signal so
    // that wiring does not silently no-op if either the key name
    // or the gschema id drifts.
    //
    // Each signal-fired test runs inside a fresh `MainContext`
    // (pushed as this thread's default for the duration of the
    // closure) so parallel cargo-test threads cannot steal each
    // other's pending dispatches.
    run_with_isolated_main_context(|| {
        let settings = memory_backed_settings();
        let fired: std::rc::Rc<std::cell::Cell<bool>> =
            std::rc::Rc::new(std::cell::Cell::new(false));
        let fired_for_closure = std::rc::Rc::clone(&fired);
        settings.connect_changed(Some(SHOW_SECTION_HEADERS_KEY), move |_, _| {
            fired_for_closure.set(true);
        });
        settings
            .set_boolean(SHOW_SECTION_HEADERS_KEY, true)
            .expect("write the show-section-headers key");
        assert!(
            fired.get(),
            "writing the key must fire the `changed::{SHOW_SECTION_HEADERS_KEY}` signal",
        );
    });
}

#[test]
fn schema_carries_show_column_headers_key() {
    let schema = build_time_schema();
    assert!(
        schema.has_key(SHOW_COLUMN_HEADERS_KEY),
        "the gschema must declare `{SHOW_COLUMN_HEADERS_KEY}` so \
         `paladin_gtk::gsettings::show_column_headers` resolves",
    );
}

#[test]
fn show_column_headers_default_is_true() {
    // Default-on is the contract chosen for the column-header
    // strip — most users benefit from the labels, and a single
    // GSettings toggle is the escape hatch for users who want a
    // chrome-free list.
    let settings = memory_backed_settings();
    assert!(
        settings.boolean(SHOW_COLUMN_HEADERS_KEY),
        "column headers default to true",
    );
}

#[test]
fn show_column_headers_round_trip_via_memory_backend() {
    let settings = memory_backed_settings();
    settings
        .set_boolean(SHOW_COLUMN_HEADERS_KEY, false)
        .expect("write the show-column-headers key");
    assert!(
        !settings.boolean(SHOW_COLUMN_HEADERS_KEY),
        "writing false and re-reading should return false",
    );
    settings
        .set_boolean(SHOW_COLUMN_HEADERS_KEY, true)
        .expect("write the show-column-headers key back to true");
    assert!(
        settings.boolean(SHOW_COLUMN_HEADERS_KEY),
        "writing true and re-reading should return true",
    );
}

#[test]
fn changed_signal_fires_for_show_column_headers_write() {
    // `AppModel` registers a `changed::show-column-headers`
    // handler so SettingsComponent toggles route through
    // `AppMsg::ShowColumnHeadersChanged` →
    // `AccountListMsg::SetShowColumnHeaders`. Pin the contract
    // that a write actually fires the signal.  Runs inside its
    // own `MainContext` so it does not race with the matching
    // section-headers test on the GLib default context.
    run_with_isolated_main_context(|| {
        let settings = memory_backed_settings();
        let fired: std::rc::Rc<std::cell::Cell<bool>> =
            std::rc::Rc::new(std::cell::Cell::new(false));
        let fired_for_closure = std::rc::Rc::clone(&fired);
        settings.connect_changed(Some(SHOW_COLUMN_HEADERS_KEY), move |_, _| {
            fired_for_closure.set(true);
        });
        settings
            .set_boolean(SHOW_COLUMN_HEADERS_KEY, false)
            .expect("write the show-column-headers key");
        assert!(
            fired.get(),
            "writing the key must fire the `changed::{SHOW_COLUMN_HEADERS_KEY}` signal",
        );
    });
}

/// Push a fresh `glib::MainContext` as this thread's default for the
/// duration of `body`, then drain pending dispatches.  Necessary
/// because cargo runs tests on a thread pool that shares the `GLib`
/// default `MainContext`, so two `changed::*` tests racing on that
/// context can steal each other's pending signals and surface as
/// "the closure never ran" assertion failures.
fn run_with_isolated_main_context<F: FnOnce()>(body: F) {
    let ctx = relm4::gtk::glib::MainContext::new();
    ctx.with_thread_default(|| {
        body();
        while ctx.iteration(false) {}
    })
    .expect("push a fresh GLib MainContext as this thread's default");
}
