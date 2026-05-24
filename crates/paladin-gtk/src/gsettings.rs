// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-user `GSettings` access for `paladin-gtk`.
//!
//! The reverse-DNS schema id ([`SCHEMA_ID`]) and the per-key
//! constants below mirror `data/org.tamx.Paladin.Gui.gschema.xml`.
//! That schema is compiled at build time by `build.rs` into
//! `OUT_DIR/schemas/gschemas.compiled` and the directory path is
//! exposed through the `PALADIN_GTK_SCHEMA_DIR` cargo env var so
//! [`app_settings`] can look the schema up for dev / test runs
//! without requiring the `.gschema.xml` to be installed at
//! `/usr/share/glib-2.0/schemas/` first.
//!
//! Lookup order in [`app_settings`]:
//!
//! 1. The build-time `PALADIN_GTK_SCHEMA_DIR` directory (always
//!    populated for dev runs and the test suite).
//! 2. The default schema source — what
//!    `gio::Settings::new(SCHEMA_ID)` would consult.  Used by
//!    installed builds whose `.gschema.xml` has been deployed to
//!    `/usr/share/glib-2.0/schemas/` by packaging.
//!
//! Keys exposed here describe per-user GUI display preferences
//! only — never vault behavior.  Vault-bound preferences
//! (auto-lock, clipboard auto-clear, …) live in
//! `paladin_core::VaultSettings` and are persisted inside the
//! vault payload per DESIGN §4.7.

use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;

/// Reverse-DNS schema id; matches `crate::APP_ID` and the `id`
/// attribute on the `<schema>` element in
/// `data/org.tamx.Paladin.Gui.gschema.xml`.
pub const SCHEMA_ID: &str = "org.tamx.Paladin.Gui";

/// `show-section-headers` key name as declared in the gschema.
///
/// Controls whether the unlocked account list groups consecutive
/// rows by issuer and renders an inline section header above each
/// group.  See `crates/paladin-gtk/src/account_list.rs` for the
/// dispatch table the `header_func` consults.
pub const SHOW_SECTION_HEADERS_KEY: &str = "show-section-headers";

/// `show-column-headers` key name as declared in the gschema.
///
/// Controls whether the unlocked account list shows the
/// `gtk::ColumnView` header strip (Account / Code / Time / Copy /
/// Menu).  Default `true` — see
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.4 "Column-header
/// visibility preference" for the rationale.
pub const SHOW_COLUMN_HEADERS_KEY: &str = "show-column-headers";

/// `show-next-code-column` key name as declared in the gschema.
///
/// Controls whether the unlocked account list shows the per-TOTP-row
/// Next column (between Code and Time) that surfaces the upcoming
/// TOTP digits with a clickable copy-to-clipboard affordance.  The
/// rendered column is the AND of this key and
/// `column_view::any_totp(&rows)` — either latch off hides the
/// column.  Default `true` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` "Next-code column
/// implementation".
pub const SHOW_NEXT_CODE_COLUMN_KEY: &str = "show-next-code-column";

/// Build-time path to the directory containing the compiled
/// gschemas (`gschemas.compiled`).  Set by `build.rs`.
const BUILD_TIME_SCHEMA_DIR: &str = env!("PALADIN_GTK_SCHEMA_DIR");

/// Construct a [`gio::Settings`] bound to the [`SCHEMA_ID`]
/// schema, preferring the build-time schema directory exported by
/// `build.rs` and falling back to the default schema source.
///
/// Panics with a descriptive message if neither source carries the
/// schema — that indicates a packaging defect (the
/// `data/org.tamx.Paladin.Gui.gschema.xml` was not compiled into
/// the binary's build directory and is also not installed at
/// `/usr/share/glib-2.0/schemas/`), so a hard failure surfaces it
/// at startup rather than as a silent "preferences dialog never
/// remembers anything" symptom.
///
/// The returned `gio::Settings` can be `clone`d cheaply — the
/// underlying `GObject` is reference counted, so each clone shares
/// the same backend state and receives `changed::<key>` signals
/// for any write.  Callers that want to drive multiple subscribers
/// (e.g. `AppModel` + `SettingsComponent`) can hold their own clones.
#[must_use]
pub fn app_settings() -> gio::Settings {
    if let Some(schema) = lookup_build_time_schema() {
        return gio::Settings::new_full(&schema, gio::SettingsBackend::NONE, None);
    }
    if let Some(schema) = lookup_default_schema() {
        return gio::Settings::new_full(&schema, gio::SettingsBackend::NONE, None);
    }
    panic!(
        "GSettings schema `{SCHEMA_ID}` not found.  Build-time \
         schema dir `{BUILD_TIME_SCHEMA_DIR}` did not carry it, \
         and the default schema source (typically \
         `/usr/share/glib-2.0/schemas/`) does not either.  Check \
         that `build.rs` compiled \
         `data/org.tamx.Paladin.Gui.gschema.xml` or that \
         packaging installed and recompiled the schemas.",
    );
}

/// Read the [`SHOW_SECTION_HEADERS_KEY`] boolean.
#[must_use]
pub fn show_section_headers(settings: &gio::Settings) -> bool {
    settings.boolean(SHOW_SECTION_HEADERS_KEY)
}

/// Write the [`SHOW_SECTION_HEADERS_KEY`] boolean.
///
/// Returns the underlying `Result` from `gio::Settings::set_boolean`;
/// failures typically indicate the key is read-only because the
/// schema is mis-declared or the backend is locked.  Callers
/// should surface the failure rather than silently swallowing it
/// — a write that does not stick leaves the visible widget out of
/// sync with the persisted value.
pub fn set_show_section_headers(
    settings: &gio::Settings,
    value: bool,
) -> Result<(), gio::glib::error::BoolError> {
    settings.set_boolean(SHOW_SECTION_HEADERS_KEY, value)
}

/// Read the [`SHOW_COLUMN_HEADERS_KEY`] boolean.
#[must_use]
pub fn show_column_headers(settings: &gio::Settings) -> bool {
    settings.boolean(SHOW_COLUMN_HEADERS_KEY)
}

/// Write the [`SHOW_COLUMN_HEADERS_KEY`] boolean.
///
/// Mirrors [`set_show_section_headers`]: callers must surface any
/// failure rather than silently swallowing it — a write that does
/// not stick leaves the visible widget out of sync with the
/// persisted value.
pub fn set_show_column_headers(
    settings: &gio::Settings,
    value: bool,
) -> Result<(), gio::glib::error::BoolError> {
    settings.set_boolean(SHOW_COLUMN_HEADERS_KEY, value)
}

/// Read the [`SHOW_NEXT_CODE_COLUMN_KEY`] boolean.
#[must_use]
pub fn show_next_code_column(settings: &gio::Settings) -> bool {
    settings.boolean(SHOW_NEXT_CODE_COLUMN_KEY)
}

/// Write the [`SHOW_NEXT_CODE_COLUMN_KEY`] boolean.
///
/// Mirrors [`set_show_column_headers`]: callers must surface any
/// failure rather than silently swallowing it — a write that does
/// not stick leaves the visible widget out of sync with the
/// persisted value.
pub fn set_show_next_code_column(
    settings: &gio::Settings,
    value: bool,
) -> Result<(), gio::glib::error::BoolError> {
    settings.set_boolean(SHOW_NEXT_CODE_COLUMN_KEY, value)
}

fn lookup_build_time_schema() -> Option<gio::SettingsSchema> {
    let source =
        gio::SettingsSchemaSource::from_directory(BUILD_TIME_SCHEMA_DIR, None, false).ok()?;
    source.lookup(SCHEMA_ID, true)
}

fn lookup_default_schema() -> Option<gio::SettingsSchema> {
    gio::SettingsSchemaSource::default()?.lookup(SCHEMA_ID, true)
}
