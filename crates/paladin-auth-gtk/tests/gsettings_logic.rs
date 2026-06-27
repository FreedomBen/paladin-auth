// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coverage for `paladin_auth_gtk::gsettings`.
//!
//! These exercise the schema-source lookup wired up by
//! `build.rs` (which compiles `data/org.tamx.PaladinAuth.Gui.gschema.xml`
//! into `OUT_DIR/schemas/`) so a regression in either the schema
//! XML or the `PALADIN_AUTH_GTK_SCHEMA_DIR` export surfaces as a
//! failing test rather than as a "preferences dialog never
//! remembers anything" symptom at runtime.
//!
//! `GSettings` reads / writes go through a memory backend so the
//! tests do not touch the user's dconf store.  The schema
//! lookup itself, however, comes from the build-time directory —
//! that is the path the in-process `paladin_auth_gtk::gsettings::app_settings`
//! consults first.

use paladin_auth_gtk::gsettings::{
    SCHEMA_ID, SHOW_COLUMN_HEADERS_KEY, SHOW_NEXT_CODE_COLUMN_KEY, SHOW_SECTION_HEADERS_KEY,
};
use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;
use relm4::gtk::glib;
use std::sync::{Mutex, MutexGuard, PoisonError};

const BUILD_TIME_SCHEMA_DIR: &str = env!("PALADIN_AUTH_GTK_SCHEMA_DIR");

/// Drain the supplied `glib::MainContext` so any queued
/// `notify::` / `changed::` signal emissions from a preceding
/// `gio::Settings::set_*` call run before the assertion checks
/// them.  Without this the `connect_changed` closure may not
/// have observed the write yet — `gio::Settings` dispatches its
/// signals via the main context that was thread-default at
/// construction time, not synchronously from `set_boolean`.
fn drain(ctx: &glib::MainContext) {
    while ctx.iteration(false) {}
}

/// Serializes the `changed_signal_fires_for_*_write` tests.
/// `gio::Settings` dispatches `changed::` signals via the shared
/// thread-default `glib::MainContext` (`MainContext::default()`).
/// When two of those tests run in parallel each pushes its own
/// `MainContext` onto the thread default in different threads, but
/// the underlying `GLib` mutex on the global default context can
/// drop emissions for the contender that lost the race.  Serializing
/// the two signal tests through a single mutex makes the contract
/// deterministic.  Mirrors the `SCHEDULE_LOCK` pattern in
/// `tests/clipboard_clear_logic.rs`.
static SIGNAL_LOCK: Mutex<()> = Mutex::new(());

fn signal_lock() -> MutexGuard<'static, ()> {
    SIGNAL_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Run `body` inside an owned `glib::MainContext` so any
/// `gio::Settings` constructed inside dispatches its `changed::`
/// signals onto that context instead of the shared default.
/// Drains the context once `body` returns so queued emissions
/// fire before the assertion checks them.
fn with_owned_context<F>(body: F)
where
    F: FnOnce(&gio::Settings),
{
    let ctx = glib::MainContext::new();
    ctx.with_thread_default(|| {
        let settings = memory_backed_settings();
        body(&settings);
        drain(&ctx);
    })
    .expect("nested with_thread_default");
}

fn build_time_schema() -> gio::SettingsSchema {
    let source = gio::SettingsSchemaSource::from_directory(BUILD_TIME_SCHEMA_DIR, None, false)
        .expect("build.rs should have compiled gschemas into PALADIN_AUTH_GTK_SCHEMA_DIR");
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
         `paladin_auth_gtk::gsettings::show_section_headers` resolves",
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
fn schema_carries_show_column_headers_key() {
    let schema = build_time_schema();
    assert!(
        schema.has_key(SHOW_COLUMN_HEADERS_KEY),
        "the gschema must declare `{SHOW_COLUMN_HEADERS_KEY}` so \
         `paladin_auth_gtk::gsettings::show_column_headers` resolves",
    );
}

#[test]
fn show_column_headers_default_is_true() {
    // Default-on is the contract pinned in IMPLEMENTATION_PLAN_04
    // §A.4 (Column-header visibility): column headers are visible
    // out of the box because the ColumnView shape only makes
    // sense with labelled columns; users can hide them via the
    // Display preferences group.
    let settings = memory_backed_settings();
    assert!(
        settings.boolean(SHOW_COLUMN_HEADERS_KEY),
        "column headers default to true per IMPLEMENTATION_PLAN_04 §A.4",
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
    // Mirrors the `show-section-headers` contract: AppModel
    // registers a `changed::show-column-headers` handler so a
    // toggle from SettingsComponent dispatches a refresh to
    // AccountListComponent.  Pin the contract that a write
    // actually fires the signal so wiring does not silently
    // no-op if either the key name or the gschema id drifts.
    let _guard = signal_lock();
    let fired: std::rc::Rc<std::cell::Cell<bool>> = std::rc::Rc::new(std::cell::Cell::new(false));
    let fired_for_closure = std::rc::Rc::clone(&fired);
    with_owned_context(|settings| {
        settings.connect_changed(Some(SHOW_COLUMN_HEADERS_KEY), move |_, _| {
            fired_for_closure.set(true);
        });
        settings
            .set_boolean(SHOW_COLUMN_HEADERS_KEY, false)
            .expect("write the show-column-headers key");
    });
    assert!(
        fired.get(),
        "writing the key must fire the `changed::{SHOW_COLUMN_HEADERS_KEY}` signal",
    );
}

#[test]
fn helper_round_trip_for_show_column_headers() {
    // The typed helpers `show_column_headers` / `set_show_column_headers`
    // are what the production wiring calls; pin a round-trip so a
    // refactor of those wrappers does not silently break the
    // contract that reads see the most-recent write.
    use paladin_auth_gtk::gsettings::{set_show_column_headers, show_column_headers};
    let settings = memory_backed_settings();
    assert!(
        show_column_headers(&settings),
        "default read via helper must be true",
    );
    set_show_column_headers(&settings, false).expect("helper write");
    assert!(
        !show_column_headers(&settings),
        "helper read after a false write must be false",
    );
    set_show_column_headers(&settings, true).expect("helper write back");
    assert!(
        show_column_headers(&settings),
        "helper read after a true write must be true",
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
    let _guard = signal_lock();
    let fired: std::rc::Rc<std::cell::Cell<bool>> = std::rc::Rc::new(std::cell::Cell::new(false));
    let fired_for_closure = std::rc::Rc::clone(&fired);
    with_owned_context(|settings| {
        settings.connect_changed(Some(SHOW_SECTION_HEADERS_KEY), move |_, _| {
            fired_for_closure.set(true);
        });
        settings
            .set_boolean(SHOW_SECTION_HEADERS_KEY, true)
            .expect("write the show-section-headers key");
    });
    assert!(
        fired.get(),
        "writing the key must fire the `changed::{SHOW_SECTION_HEADERS_KEY}` signal",
    );
}

#[test]
fn schema_carries_show_next_code_column_key() {
    let schema = build_time_schema();
    assert!(
        schema.has_key(SHOW_NEXT_CODE_COLUMN_KEY),
        "the gschema must declare `{SHOW_NEXT_CODE_COLUMN_KEY}` so \
         `paladin_auth_gtk::gsettings::show_next_code_column` resolves",
    );
}

#[test]
fn show_next_code_column_default_is_true() {
    // Default-on is the contract pinned in IMPLEMENTATION_PLAN_04
    // §"Next-code column implementation": the Next column is
    // visible out of the box because TOTP users overwhelmingly
    // benefit from seeing the upcoming code when the current one
    // is about to expire; users who prefer a compact list can
    // hide it from the Display preferences group.
    let settings = memory_backed_settings();
    assert!(
        settings.boolean(SHOW_NEXT_CODE_COLUMN_KEY),
        "next-code column defaults to true per IMPLEMENTATION_PLAN_04",
    );
}

#[test]
fn show_next_code_column_round_trip_via_memory_backend() {
    let settings = memory_backed_settings();
    settings
        .set_boolean(SHOW_NEXT_CODE_COLUMN_KEY, false)
        .expect("write the show-next-code-column key");
    assert!(
        !settings.boolean(SHOW_NEXT_CODE_COLUMN_KEY),
        "writing false and re-reading should return false",
    );
    settings
        .set_boolean(SHOW_NEXT_CODE_COLUMN_KEY, true)
        .expect("write the show-next-code-column key back to true");
    assert!(
        settings.boolean(SHOW_NEXT_CODE_COLUMN_KEY),
        "writing true and re-reading should return true",
    );
}

#[test]
fn changed_signal_fires_for_show_next_code_column_write() {
    // The AppModel registers a `changed::show-next-code-column`
    // handler on its `gio::Settings` clone so a toggle from
    // SettingsComponent dispatches a refresh to
    // AccountListComponent (which calls `set_visible` on the
    // held `gtk::ColumnViewColumn`).  Pin the contract that a
    // write actually fires the signal so that wiring does not
    // silently no-op if either the key name or the gschema id
    // drifts.
    let _guard = signal_lock();
    let fired: std::rc::Rc<std::cell::Cell<bool>> = std::rc::Rc::new(std::cell::Cell::new(false));
    let fired_for_closure = std::rc::Rc::clone(&fired);
    with_owned_context(|settings| {
        settings.connect_changed(Some(SHOW_NEXT_CODE_COLUMN_KEY), move |_, _| {
            fired_for_closure.set(true);
        });
        settings
            .set_boolean(SHOW_NEXT_CODE_COLUMN_KEY, false)
            .expect("write the show-next-code-column key");
    });
    assert!(
        fired.get(),
        "writing the key must fire the `changed::{SHOW_NEXT_CODE_COLUMN_KEY}` signal",
    );
}

#[test]
fn helper_round_trip_for_show_next_code_column() {
    // Mirrors `helper_round_trip_for_show_column_headers`: the
    // typed `show_next_code_column` / `set_show_next_code_column`
    // helpers are what production wiring calls.  Pin a round-trip
    // so a refactor of those wrappers does not silently break the
    // contract that reads see the most-recent write.
    use paladin_auth_gtk::gsettings::{set_show_next_code_column, show_next_code_column};
    let settings = memory_backed_settings();
    assert!(
        show_next_code_column(&settings),
        "default read via helper must be true",
    );
    set_show_next_code_column(&settings, false).expect("helper write");
    assert!(
        !show_next_code_column(&settings),
        "helper read after a false write must be false",
    );
    set_show_next_code_column(&settings, true).expect("helper write back");
    assert!(
        show_next_code_column(&settings),
        "helper read after a true write must be true",
    );
}
