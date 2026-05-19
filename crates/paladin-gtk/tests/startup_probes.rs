// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for `app::model::run_startup_probes` and the
//! shared `startup_state_marker` helper.
//!
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" pins the
//! startup sequence: resolve vault path (`--vault` override or
//! `paladin_core::default_vault_path()`), call `paladin_core::inspect`,
//! and — for `VaultStatus::Plaintext` — `paladin_core::Store::open`
//! on the GTK main loop. These tests exercise that helper directly so
//! the assertions run without a display server (the parallel
//! `tests/gtk_smoke.rs` covers the same path end-to-end under
//! `xvfb-run` in CI).
//!
//! The `startup_state_marker` helper is the source of truth for the
//! stdout line `paladin-gtk` emits under `--exit-after-startup`. The
//! smoke test in `tests/gtk_smoke.rs` greps for that line, so the
//! string format is locked here.

use std::path::PathBuf;

use paladin_gtk::app::model::{run_startup_probes, startup_state_marker, StartupOutcome};
use paladin_gtk::app::state::AppState;
use paladin_gtk::startup_error::StartupErrorSource;

/// Helper: create a plaintext vault at `<tempdir>/vault.bin` and
/// drop the `(Vault, Store)` pair so the file is closed before the
/// probe reopens it. `paladin_core` enforces `0700` on the vault
/// parent directory (§4.3); the tempdir is chmodded to `0700` in
/// case the test runner's `umask` would otherwise produce `0770`.
fn prepare_plaintext_vault() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let tempdir = tempfile::tempdir().expect("create tempdir");
    std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir to 0700 so paladin_core::Store::create accepts it");

    let path = tempdir.path().join("vault.bin");
    {
        // `Store::create` stages the in-memory vault; the file is not
        // written until `Vault::save` runs the §4.3 atomic-write
        // pipeline (see `paladin_core::Store::create` docs).
        let (vault, store) = paladin_core::Store::create(&path, paladin_core::VaultInit::Plaintext)
            .expect("create plaintext vault");
        vault.save(&store).expect("persist plaintext vault to disk");
    }
    (tempdir, path)
}

#[test]
fn run_startup_probes_opens_prepared_plaintext_vault() {
    let (_tempdir, path) = prepare_plaintext_vault();

    let StartupOutcome { state, vault } = run_startup_probes(Some(path.clone()));

    match state {
        AppState::Unlocked { path: resolved } => {
            assert_eq!(
                resolved, path,
                "Unlocked state must carry the resolved vault path"
            );
        }
        other => panic!("expected AppState::Unlocked, got {other:?}"),
    }
    assert!(
        vault.is_some(),
        "Plaintext branch must hand the (Vault, Store) pair back to AppModel",
    );
}

#[test]
fn run_startup_probes_routes_missing_path_to_missing_state() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let path = tempdir.path().join("does-not-exist.bin");

    let StartupOutcome { state, vault } = run_startup_probes(Some(path.clone()));

    match state {
        AppState::Missing { path: resolved } => {
            assert_eq!(resolved, path, "Missing state must carry the probed path");
        }
        other => panic!("expected AppState::Missing, got {other:?}"),
    }
    assert!(
        vault.is_none(),
        "Missing branch owns no vault — InitDialog is responsible for create",
    );
}

#[test]
fn run_startup_probes_routes_corrupted_file_to_startup_error() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let path = tempdir.path().join("vault.bin");
    // A non-magic byte run forces `paladin_core::inspect` into the
    // invalid-header branch, which routes to StartupError(Inspect).
    std::fs::write(&path, b"not a paladin vault").expect("write corrupted vault");

    let StartupOutcome { state, vault } = run_startup_probes(Some(path.clone()));

    match state {
        AppState::StartupError {
            path: error_path,
            error,
        } => {
            assert_eq!(
                error_path.as_deref(),
                Some(path.as_path()),
                "StartupError from inspect must carry the probed path",
            );
            assert_eq!(
                error.source,
                StartupErrorSource::Inspect,
                "Corrupt header routes through inspect, not path-resolution or open",
            );
        }
        other => panic!("expected AppState::StartupError, got {other:?}"),
    }
    assert!(
        vault.is_none(),
        "StartupError branch never owns a vault — the file never opened",
    );
}

#[test]
fn startup_state_marker_unlocked_includes_path() {
    let path = PathBuf::from("/tmp/example/vault.bin");
    let state = AppState::Unlocked { path: path.clone() };
    assert_eq!(
        startup_state_marker(&state),
        "paladin-gtk: startup_state=Unlocked path=/tmp/example/vault.bin",
    );
}

#[test]
fn startup_state_marker_locked_and_missing_include_path() {
    let path = PathBuf::from("/tmp/example/vault.bin");
    assert_eq!(
        startup_state_marker(&AppState::Locked { path: path.clone() }),
        "paladin-gtk: startup_state=Locked path=/tmp/example/vault.bin",
    );
    assert_eq!(
        startup_state_marker(&AppState::Missing { path: path.clone() }),
        "paladin-gtk: startup_state=Missing path=/tmp/example/vault.bin",
    );
}

#[test]
fn startup_state_marker_startup_error_renders_path_or_placeholder() {
    let path = PathBuf::from("/tmp/example/vault.bin");
    let with_path_marker = startup_state_marker(&AppState::StartupError {
        path: Some(path.clone()),
        error: paladin_gtk::startup_error::StartupError {
            source: StartupErrorSource::Inspect,
            kind: paladin_core::ErrorKind::InvalidHeader,
            rendered: String::new(),
        },
    });
    assert_eq!(
        with_path_marker,
        "paladin-gtk: startup_state=StartupError path=/tmp/example/vault.bin",
    );

    let without_path_marker = startup_state_marker(&AppState::StartupError {
        path: None,
        error: paladin_gtk::startup_error::StartupError {
            source: StartupErrorSource::PathResolution,
            kind: paladin_core::ErrorKind::IoError,
            rendered: String::new(),
        },
    });
    assert_eq!(
        without_path_marker,
        "paladin-gtk: startup_state=StartupError path=(unresolved)",
    );
}

#[test]
fn format_app_window_default_size_returns_640_by_480() {
    // The `AppModel`'s `adw::ApplicationWindow::set_default_size`
    // tuple is populated from this helper. The (width, height)
    // pair `(640, 480)` matches the libadwaita HIG's narrow-
    // window initial size — wide enough for the
    // `AccountListComponent`'s `<issuer>:<label>` lines without
    // forcing an `AdwSqueezer`, tall enough to expose the header
    // bar and a useful run of accounts without dominating a
    // smaller display. Per the libadwaita HIG, the
    // `ApplicationWindow` then becomes user-resizable so the
    // initial dimensions are a starting size, not a clamp.
    // Pinning the dimensions through a helper keeps the values
    // in one place shared by the widget binding and the pure-
    // logic tests in `tests/startup_probes.rs`.
    //
    // No TUI parity: the TUI inherits the terminal's dimensions
    // and has no initial-size contract to mirror.
    use paladin_gtk::app::model::format_app_window_default_size;

    assert_eq!(
        format_app_window_default_size(),
        (640, 480),
        "ApplicationWindow default size matches the libadwaita HIG narrow-window pair",
    );
}

#[test]
fn format_app_window_default_size_pair_is_positive() {
    // Defense-in-depth against a zero / negative dimension
    // accidentally landing here: `adw::ApplicationWindow` would
    // accept the pair but render a degenerate window. Pinning a
    // positivity assertion alongside the full-value assertion
    // guards the invariant the helper is meant to encode.
    use paladin_gtk::app::model::format_app_window_default_size;

    let (width, height) = format_app_window_default_size();
    assert!(
        width > 0 && height > 0,
        "ApplicationWindow default size must be a strictly positive (width, height) pair; got ({width}, {height})",
    );
}

#[test]
fn format_app_add_button_icon_name_returns_list_add_symbolic() {
    // The `AppModel`'s header-bar add `gtk::Button`'s
    // `set_icon_name` attribute is populated from this helper.
    // The icon (`"list-add-symbolic"`) is the freedesktop-
    // standard glyph for "add to list" — resolving through the
    // system icon theme so the wordless icon matches every other
    // GNOME app's `+` header-bar affordance. The `-symbolic`
    // suffix is required by the libadwaita HIG for header-bar
    // icons so the glyph recolors with the theme. Pinning the
    // icon name through a helper keeps the string in one place
    // shared by the widget binding and the pure-logic tests.
    //
    // No TUI parity: the TUI is text-only and has no icon to
    // mirror. Distinct from the dialog-status-icon siblings
    // (`format_unlock_dialog_icon_name`,
    // `format_init_dialog_icon_name`,
    // `format_startup_error_icon_name`,
    // `format_remove_dialog_icon_name`) which pin
    // `AdwStatusPage` icons rather than header-bar button
    // icons; pairing this helper with the existing app-level
    // `format_app_add_button_tooltip` keeps both halves of the
    // icon-only button's accessibility surface against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_add_button_icon_name;

    assert_eq!(
        format_app_add_button_icon_name(),
        "list-add-symbolic",
        "header-bar add button icon uses the freedesktop-standard add-to-list glyph",
    );
}

#[test]
fn format_app_add_button_icon_name_ends_with_symbolic_suffix() {
    // The libadwaita HIG requires header-bar icons to be
    // symbolic so they recolor with the theme; the icon-name
    // contract is to end with `-symbolic`. Pinning a suffix
    // assertion alongside the full-string assertion guards
    // against an accidental rename to a non-symbolic glyph.
    use paladin_gtk::app::model::format_app_add_button_icon_name;

    let icon = format_app_add_button_icon_name();
    assert!(
        icon.ends_with("-symbolic"),
        "header-bar icon name must end with `-symbolic` for HIG-conformant theming; got {icon:?}",
    );
}

#[test]
fn format_app_add_button_tooltip_returns_add_account() {
    // The `AppModel`'s header-bar add `gtk::Button`'s
    // `set_tooltip_text` attribute is populated from this helper.
    // The wording (`"Add account"`) names the action the button
    // dispatches (`AppMsg::OpenAddDialog`) and matches the
    // GNOME-HIG verb-led tooltip convention used by every other
    // GNOME app's header-bar `+` affordance. The tooltip is the
    // user-visible label for an icon-only button that otherwise
    // shows only `list-add-symbolic`, so pinning the wording
    // through a helper guards the accessibility surface
    // (screen-readers read tooltips) against silent copy drift.
    //
    // Distinct from `paladin_gtk::add_account::format_add_dialog_title`
    // (`"Add account"`) which names the surface the tooltip
    // opens: the two strings happen to match today but live on
    // different surfaces — a future copy change should land on
    // one without silently moving the other. No TUI parity: the
    // TUI is text-only and surfaces actions through command
    // names rather than tooltips. Pinning the wording through a
    // helper keeps the string in one place shared by the widget
    // binding and the pure-logic tests in
    // `tests/startup_probes.rs`.
    use paladin_gtk::app::model::format_app_add_button_tooltip;

    assert_eq!(
        format_app_add_button_tooltip(),
        "Add account",
        "header-bar add button tooltip uses the GNOME-HIG verb-led wording",
    );
}

#[test]
fn format_app_window_title_returns_paladin() {
    // The `AppModel`'s `adw::ApplicationWindow::set_title` attribute
    // is populated from this helper. The wording (`"Paladin"`) names
    // the application — surfaced verbatim through libadwaita's
    // window chrome and (on Wayland / X11) by the desktop's window
    // list, so the bare application name is the right wording (no
    // state-specific suffixes like " — Locked" / " — Unlocked",
    // which would otherwise leak the live vault state into the
    // window-list across application switches). Matches the GNOME
    // app-id naming used by the `.desktop` / AppStream metadata
    // referenced by `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Linux desktop integration". Pinning the title through a
    // helper keeps the wording in one place shared by the widget
    // binding and the pure-logic tests in `tests/startup_probes.rs`.
    //
    // No TUI parity: the TUI is a single-process terminal app and
    // has no window-list entry to mirror. Distinct from the in-
    // window dialog titles (`format_unlock_dialog_title`,
    // `format_init_dialog_title`, `format_rename_dialog_title`,
    // `format_add_dialog_title`, `format_startup_error_title`,
    // `format_remove_dialog_title`), which name surfaces inside
    // the window rather than the window itself.
    use paladin_gtk::app::model::format_app_window_title;

    assert_eq!(
        format_app_window_title(),
        "Paladin",
        "ApplicationWindow title surfaces the bare application name",
    );
}

#[test]
fn format_app_search_button_icon_name_returns_system_search_symbolic() {
    // The `AppModel`'s header-bar search-toggle `gtk::ToggleButton`'s
    // `set_icon_name` attribute is populated from this helper. The
    // icon (`"system-search-symbolic"`) is the freedesktop-standard
    // glyph for "search" — resolving through the system icon theme
    // so the wordless icon matches every other GNOME app's
    // search-toggle header-bar affordance. The `-symbolic` suffix is
    // required by the libadwaita HIG for header-bar icons so the
    // glyph recolors with the theme. Pinning the icon name through
    // a helper keeps the string in one place shared by the widget
    // binding and the pure-logic tests.
    //
    // No TUI parity: the TUI is text-only and exposes search
    // through the existing `/` keybinding rather than an icon.
    // Sibling of `format_app_add_button_icon_name` on the
    // header-bar-icon side; together they pin the wordless
    // affordances against a single source of truth.
    use paladin_gtk::app::model::format_app_search_button_icon_name;

    assert_eq!(
        format_app_search_button_icon_name(),
        "system-search-symbolic",
        "header-bar search button icon uses the freedesktop-standard search glyph",
    );
}

#[test]
fn format_app_search_button_icon_name_ends_with_symbolic_suffix() {
    // The libadwaita HIG requires header-bar icons to be symbolic
    // so they recolor with the theme; the icon-name contract is to
    // end with `-symbolic`. Pinning a suffix assertion alongside
    // the full-string assertion guards against an accidental
    // rename to a non-symbolic glyph.
    use paladin_gtk::app::model::format_app_search_button_icon_name;

    let icon = format_app_search_button_icon_name();
    assert!(
        icon.ends_with("-symbolic"),
        "header-bar search icon name must end with `-symbolic` for HIG-conformant theming; got {icon:?}",
    );
}

#[test]
fn format_app_search_button_tooltip_returns_search_accounts() {
    // The `AppModel`'s header-bar search-toggle
    // `gtk::ToggleButton`'s `set_tooltip_text` attribute is
    // populated from this helper. The wording (`"Search accounts"`)
    // names the action the toggle dispatches (revealing the
    // `gtk::SearchBar` in `AccountListComponent`) and matches the
    // GNOME-HIG verb-led tooltip convention used by every other
    // GNOME app's search-toggle header-bar affordance. The tooltip
    // is the user-visible label for an icon-only button that
    // otherwise shows only `system-search-symbolic`, so pinning
    // the wording through a helper guards the accessibility
    // surface (screen-readers read tooltips) against silent copy
    // drift.
    //
    // Pure — returns a `'static str` without allocating. No TUI
    // parity: the TUI is text-only and surfaces search through
    // the `/` keybinding rather than tooltips. Sibling of
    // `format_app_add_button_tooltip` on the header-bar-tooltip
    // side; together they pin both icon-only-button labels
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_search_button_tooltip;

    assert_eq!(
        format_app_search_button_tooltip(),
        "Search accounts",
        "header-bar search button tooltip uses the GNOME-HIG verb-led wording",
    );
}

#[test]
fn format_app_search_button_tooltip_is_non_empty() {
    // Defense-in-depth against an accidental empty tooltip
    // landing here: an icon-only button without a tooltip
    // strips a screen-reader's only label for the affordance,
    // breaking the accessibility contract that `set_tooltip_text`
    // is meant to satisfy. Pinning a non-empty invariant alongside
    // the full-string assertion guards against an accidental
    // empty-string regression.
    use paladin_gtk::app::model::format_app_search_button_tooltip;

    let tooltip = format_app_search_button_tooltip();
    assert!(
        !tooltip.is_empty(),
        "header-bar search button tooltip must be non-empty so the icon-only button retains a screen-reader label",
    );
}

#[test]
fn format_app_menu_button_icon_name_returns_open_menu_symbolic() {
    // The `AppModel`'s header-bar primary `gtk::MenuButton`'s
    // `set_icon_name` attribute is populated from this helper.
    // The icon (`"open-menu-symbolic"`) is the freedesktop-
    // standard glyph for a hamburger / primary-menu button —
    // resolving through the system icon theme so the wordless
    // icon matches every other GNOME app's primary-menu
    // header-bar affordance. The `-symbolic` suffix is required
    // by the libadwaita HIG for header-bar icons so the glyph
    // recolors with the theme. Pinning the icon name through a
    // helper keeps the string in one place shared by the widget
    // binding and the pure-logic tests.
    //
    // No TUI parity: the TUI is text-only and exposes the same
    // actions through `:` command-mode rather than a menu icon.
    // Third sibling of `format_app_add_button_icon_name` and
    // `format_app_search_button_icon_name` on the header-bar-
    // icon side; together they pin all three wordless header-bar
    // affordances against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_button_icon_name;

    assert_eq!(
        format_app_menu_button_icon_name(),
        "open-menu-symbolic",
        "header-bar primary menu button icon uses the freedesktop-standard hamburger glyph",
    );
}

#[test]
fn format_app_menu_button_icon_name_ends_with_symbolic_suffix() {
    // The libadwaita HIG requires header-bar icons to be symbolic
    // so they recolor with the theme; the icon-name contract is to
    // end with `-symbolic`. Pinning a suffix assertion alongside
    // the full-string assertion guards against an accidental
    // rename to a non-symbolic glyph.
    use paladin_gtk::app::model::format_app_menu_button_icon_name;

    let icon = format_app_menu_button_icon_name();
    assert!(
        icon.ends_with("-symbolic"),
        "header-bar menu icon name must end with `-symbolic` for HIG-conformant theming; got {icon:?}",
    );
}

#[test]
fn format_app_menu_button_tooltip_returns_main_menu() {
    // The `AppModel`'s header-bar primary `gtk::MenuButton`'s
    // `set_tooltip_text` attribute is populated from this helper.
    // The wording (`"Main menu"`) names the surface the button
    // opens (the primary `gio::Menu` with Import…, Export…,
    // Passphrase…, Preferences, About Paladin, Quit) and matches
    // the GNOME-HIG convention used by every other GNOME app's
    // hamburger header-bar affordance. The tooltip is the user-
    // visible label for an icon-only button that otherwise shows
    // only `open-menu-symbolic`, so pinning the wording through
    // a helper guards the accessibility surface (screen-readers
    // read tooltips) against silent copy drift.
    //
    // Pure — returns a `'static str` without allocating. Third
    // sibling of `format_app_add_button_tooltip` and
    // `format_app_search_button_tooltip` on the header-bar-
    // tooltip side; together they pin all three icon-only-button
    // labels against a single source of truth. No TUI parity:
    // the TUI exposes the same actions through `:` command-mode
    // rather than tooltips.
    use paladin_gtk::app::model::format_app_menu_button_tooltip;

    assert_eq!(
        format_app_menu_button_tooltip(),
        "Main menu",
        "header-bar primary menu button tooltip uses the GNOME-HIG primary-menu wording",
    );
}

#[test]
fn format_app_menu_button_tooltip_is_non_empty() {
    // Defense-in-depth against an accidental empty tooltip
    // landing here: an icon-only button without a tooltip strips
    // a screen-reader's only label for the affordance, breaking
    // the accessibility contract that `set_tooltip_text` is meant
    // to satisfy. Pinning a non-empty invariant alongside the
    // full-string assertion guards against an accidental empty-
    // string regression.
    use paladin_gtk::app::model::format_app_menu_button_tooltip;

    let tooltip = format_app_menu_button_tooltip();
    assert!(
        !tooltip.is_empty(),
        "header-bar menu button tooltip must be non-empty so the icon-only button retains a screen-reader label",
    );
}

#[test]
fn format_app_menu_import_label_returns_import_with_ellipsis() {
    // The `AppModel`'s primary `gio::Menu` "Import…" entry's
    // label is populated from this helper. The wording
    // (`"Import…"`) names the surface the entry opens
    // (`ImportDialog`) and uses the GNOME-HIG horizontal-ellipsis
    // character (U+2026) — not three ASCII periods — to indicate
    // the action opens a sub-dialog requiring further input
    // before committing. The trailing ellipsis is the GNOME-HIG
    // convention for any menu entry that opens a dialog rather
    // than completing the action immediately.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of the other primary-menu entries (Export…, Passphrase…,
    // Preferences, About Paladin, Quit) which will land in
    // follow-up commits with the same `format_app_menu_*_label`
    // naming. The Import / Export / Passphrase / Preferences
    // entries are gated to `Unlocked` per §"libadwaita usage";
    // the label wording is identical across states so the
    // tooltip does not need to change when the menu re-opens.
    use paladin_gtk::app::model::format_app_menu_import_label;

    assert_eq!(
        format_app_menu_import_label(),
        "Import\u{2026}",
        "primary menu Import entry uses the HIG horizontal-ellipsis (U+2026) suffix",
    );
}

#[test]
fn format_app_menu_import_label_ends_with_ellipsis() {
    // The GNOME-HIG menu-entry contract is that an entry opening
    // a dialog ends with the horizontal-ellipsis character
    // (U+2026), not three ASCII periods. Pinning a suffix-and-
    // not-`...` invariant alongside the full-string assertion
    // guards against an accidental rename to ASCII periods that
    // would otherwise render slightly wider and break visual
    // alignment with the rest of the GNOME app menus.
    use paladin_gtk::app::model::format_app_menu_import_label;

    let label = format_app_menu_import_label();
    assert!(
        label.ends_with('\u{2026}'),
        "Import menu label must end with the horizontal-ellipsis character (U+2026); got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "Import menu label must not use three ASCII periods; the GNOME HIG requires U+2026 instead; got {label:?}",
    );
}

#[test]
fn format_app_menu_export_label_returns_export_with_ellipsis() {
    // The `AppModel`'s primary `gio::Menu` "Export…" entry's
    // label is populated from this helper. The wording
    // (`"Export…"`) names the surface the entry opens
    // (`ExportDialog`) and uses the GNOME-HIG horizontal-ellipsis
    // character (U+2026) — not three ASCII periods — to indicate
    // the action opens a sub-dialog requiring further input
    // before committing. The trailing ellipsis is the GNOME-HIG
    // convention for any menu entry that opens a dialog rather
    // than completing the action immediately.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_import_label` on the import/export
    // menu-entry side; together they pin the two file-IO entries
    // against a single source of truth. The Export entry is
    // gated to `Unlocked` per §"libadwaita usage" but the label
    // wording is identical across states so the menu does not
    // need to re-render when re-opened.
    use paladin_gtk::app::model::format_app_menu_export_label;

    assert_eq!(
        format_app_menu_export_label(),
        "Export\u{2026}",
        "primary menu Export entry uses the HIG horizontal-ellipsis (U+2026) suffix",
    );
}

#[test]
fn format_app_menu_export_label_ends_with_ellipsis() {
    // The GNOME-HIG menu-entry contract is that an entry opening
    // a dialog ends with the horizontal-ellipsis character
    // (U+2026), not three ASCII periods. Pinning a suffix-and-
    // not-`...` invariant alongside the full-string assertion
    // guards against an accidental rename to ASCII periods that
    // would otherwise render slightly wider and break visual
    // alignment with the rest of the GNOME app menus.
    use paladin_gtk::app::model::format_app_menu_export_label;

    let label = format_app_menu_export_label();
    assert!(
        label.ends_with('\u{2026}'),
        "Export menu label must end with the horizontal-ellipsis character (U+2026); got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "Export menu label must not use three ASCII periods; the GNOME HIG requires U+2026 instead; got {label:?}",
    );
}

#[test]
fn format_app_menu_passphrase_label_returns_passphrase_with_ellipsis() {
    // The `AppModel`'s primary `gio::Menu` "Passphrase…" entry's
    // label is populated from this helper. The wording
    // (`"Passphrase…"`) names the surface the entry opens
    // (`PassphraseDialog` with the sub-flow gated by
    // `Vault::is_encrypted()`) and uses the GNOME-HIG horizontal-
    // ellipsis character (U+2026) — not three ASCII periods — to
    // indicate the action opens a sub-dialog requiring further
    // input before committing.
    //
    // Pure — returns a `'static str` without allocating. The
    // Passphrase entry is gated to `Unlocked` per §"libadwaita
    // usage" but the label wording is identical across the
    // set / change / remove sub-flows so the menu does not need
    // to re-render when re-opened — `PassphraseDialog` does the
    // sub-flow routing internally against `Vault::is_encrypted()`.
    use paladin_gtk::app::model::format_app_menu_passphrase_label;

    assert_eq!(
        format_app_menu_passphrase_label(),
        "Passphrase\u{2026}",
        "primary menu Passphrase entry uses the HIG horizontal-ellipsis (U+2026) suffix",
    );
}

#[test]
fn format_app_menu_passphrase_label_ends_with_ellipsis() {
    // The GNOME-HIG menu-entry contract is that an entry opening
    // a dialog ends with the horizontal-ellipsis character
    // (U+2026), not three ASCII periods. Pinning a suffix-and-
    // not-`...` invariant alongside the full-string assertion
    // guards against an accidental rename to ASCII periods.
    use paladin_gtk::app::model::format_app_menu_passphrase_label;

    let label = format_app_menu_passphrase_label();
    assert!(
        label.ends_with('\u{2026}'),
        "Passphrase menu label must end with the horizontal-ellipsis character (U+2026); got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "Passphrase menu label must not use three ASCII periods; the GNOME HIG requires U+2026 instead; got {label:?}",
    );
}

#[test]
fn format_app_menu_preferences_label_returns_preferences_without_ellipsis() {
    // The `AppModel`'s primary `gio::Menu` "Preferences" entry's
    // label is populated from this helper. The wording
    // (`"Preferences"`) names the surface the entry opens
    // (`SettingsComponent`'s `AdwPreferencesDialog`) and uses
    // the bare label — no trailing horizontal-ellipsis — because
    // the modern GNOME HIG drops the ellipsis from preferences
    // entries: the dialog is live-apply (each toggle / spinner
    // change drives a `Vault::mutate_and_save` per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage") rather
    // than collecting input behind an Apply / Cancel button, so
    // the affordance is not a request for further input before
    // committing. The dialog-opening entries (Import, Export,
    // Passphrase) keep the ellipsis because they collect input
    // before committing; Preferences does not.
    //
    // Pure — returns a `'static str` without allocating. Distinct
    // from the dialog-opening primary-menu entries
    // (`format_app_menu_import_label`,
    // `format_app_menu_export_label`,
    // `format_app_menu_passphrase_label`) which carry the
    // ellipsis; matches the ellipsis-less convention used by
    // every other modern GNOME app's Preferences entry.
    use paladin_gtk::app::model::format_app_menu_preferences_label;

    assert_eq!(
        format_app_menu_preferences_label(),
        "Preferences",
        "primary menu Preferences entry uses the bare label (no ellipsis) per the modern GNOME HIG",
    );
}

#[test]
fn format_app_menu_preferences_label_does_not_carry_ellipsis() {
    // The modern GNOME HIG drops the ellipsis from Preferences
    // entries because live-apply preferences are not a request
    // for further input before committing. Pinning a no-ellipsis
    // invariant alongside the full-string assertion guards
    // against an accidental rename that would otherwise drift
    // back to the older HIG style.
    use paladin_gtk::app::model::format_app_menu_preferences_label;

    let label = format_app_menu_preferences_label();
    assert!(
        !label.ends_with('\u{2026}'),
        "Preferences menu label must not end with the horizontal-ellipsis character (U+2026); the live-apply preferences contract does not require it; got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "Preferences menu label must not end with three ASCII periods either; got {label:?}",
    );
}

#[test]
fn format_app_menu_about_label_returns_about_paladin() {
    // The `AppModel`'s primary `gio::Menu` "About Paladin" entry's
    // label is populated from this helper. The wording
    // (`"About Paladin"`) names the surface the entry opens
    // (`AdwAboutDialog` per §"libadwaita usage", populated from
    // Cargo package metadata embedded at compile time) and matches
    // the GNOME-HIG convention used by every other GNOME app's
    // primary-menu About entry — the application name is included
    // verbatim so the user can confirm the running binary's
    // identity before opening the dialog. The trailing "Paladin"
    // matches the bare application name pinned by
    // `format_app_window_title`.
    //
    // Pure — returns a `'static str` without allocating. No
    // trailing ellipsis: the About dialog is an informational
    // surface (program metadata + license) rather than a request
    // for input, so the GNOME-HIG ellipsis convention does not
    // apply — same reasoning as `format_app_menu_preferences_label`.
    use paladin_gtk::app::model::format_app_menu_about_label;

    assert_eq!(
        format_app_menu_about_label(),
        "About Paladin",
        "primary menu About entry includes the application name verbatim per the GNOME HIG",
    );
}

#[test]
fn format_app_menu_about_label_carries_application_name() {
    // Defense-in-depth against an accidental rename to a generic
    // `"About"` (which would drop the application-name
    // disambiguation) or a rebranded application name. Pinning
    // a "must contain the bare application name" invariant
    // against `format_app_window_title()` keeps the About menu
    // entry and the window-list entry from drifting apart.
    use paladin_gtk::app::model::{format_app_menu_about_label, format_app_window_title};

    let label = format_app_menu_about_label();
    let app_name = format_app_window_title();
    assert!(
        label.contains(app_name),
        "About menu label must contain the bare application name {app_name:?} per the GNOME HIG; got {label:?}",
    );
}

#[test]
fn format_app_menu_about_label_does_not_carry_ellipsis() {
    // The About dialog is an informational surface (program
    // metadata + license) rather than a request for input, so
    // the GNOME-HIG ellipsis convention does not apply.
    // Pinning a no-ellipsis invariant alongside the full-string
    // assertion guards against an accidental drift.
    use paladin_gtk::app::model::format_app_menu_about_label;

    let label = format_app_menu_about_label();
    assert!(
        !label.ends_with('\u{2026}'),
        "About menu label must not end with the horizontal-ellipsis character (U+2026); the informational dialog does not require input before committing; got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "About menu label must not end with three ASCII periods either; got {label:?}",
    );
}

#[test]
fn format_app_menu_quit_label_returns_quit() {
    // The `AppModel`'s primary `gio::Menu` "Quit" entry's label
    // is populated from this helper. The wording (`"Quit"`) names
    // the action the entry dispatches (the `Quit` standard action
    // that triggers application shutdown after any in-flight vault
    // worker returns, per §"In-flight effect ownership") and
    // matches the GNOME-HIG convention used by every other GNOME
    // app's primary-menu Quit entry. No trailing ellipsis: Quit
    // is a commit-now action that does not collect further input
    // (the destructive-confirmation-on-pending-work gate, if any,
    // lives in the §"In-flight effect ownership" worker-deferral
    // logic, not in this label).
    //
    // Pure — returns a `'static str` without allocating. The Quit
    // entry stays enabled in every `AppState` per §"libadwaita
    // usage" — unlike Import / Export / Passphrase / Preferences
    // which are gated to `Unlocked` — so the label wording does
    // not need to change across state transitions.
    use paladin_gtk::app::model::format_app_menu_quit_label;

    assert_eq!(
        format_app_menu_quit_label(),
        "Quit",
        "primary menu Quit entry uses the bare GNOME-HIG quit-action wording",
    );
}

#[test]
fn format_app_menu_quit_label_does_not_carry_ellipsis() {
    // Quit is a commit-now action (deferred only by the in-flight
    // vault worker per §"In-flight effect ownership"), not a
    // dialog-opening surface, so the GNOME-HIG ellipsis convention
    // does not apply. Pinning a no-ellipsis invariant alongside
    // the full-string assertion guards against an accidental
    // rename that would otherwise suggest the affordance opens a
    // sub-dialog.
    use paladin_gtk::app::model::format_app_menu_quit_label;

    let label = format_app_menu_quit_label();
    assert!(
        !label.ends_with('\u{2026}'),
        "Quit menu label must not end with the horizontal-ellipsis character (U+2026); Quit is a commit-now action, not a dialog-opening entry; got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "Quit menu label must not end with three ASCII periods either; got {label:?}",
    );
}

#[test]
fn format_app_menu_import_action_returns_app_import() {
    // The `AppModel`'s primary `gio::Menu` "Import…" entry's
    // `detailed_action_name` is populated from this helper. The
    // wording (`"app.import"`) is the fully-qualified action
    // target the `gio::Menu` resolves against the
    // `gio::ApplicationWindow`'s `app` action group — the same
    // pattern `account_list.rs` uses with its `row.rename` /
    // `row.remove` targets resolved against the per-row
    // `gio::SimpleActionGroup`. The `"app."` prefix names the
    // group; `"import"` names the action.
    //
    // Pure — returns a `'static str` without allocating. The
    // matching `gio::SimpleAction` (`"import"`) is registered on
    // the application's action group in a follow-up commit; the
    // helper is pinned first so the menu wiring lands against a
    // single source of truth shared by both halves of the
    // contract (the `gio::Menu` reference and the action
    // registration).
    use paladin_gtk::app::model::format_app_menu_import_action;

    assert_eq!(
        format_app_menu_import_action(),
        "app.import",
        "primary menu Import entry targets the app.import action on the application's action group",
    );
}

#[test]
fn format_app_menu_import_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group (e.g. `row.import` or bare `import`).
    // `gio::Menu::append`'s `detailed_action_name` argument
    // expects a fully-qualified `<group>.<action>` target; a
    // bare action name silently no-ops at activation time. The
    // matching `gio::SimpleAction` will be registered on the
    // application's action group ("app") so the menu and the
    // action registration must agree on the group prefix.
    use paladin_gtk::app::model::format_app_menu_import_action;

    let action = format_app_menu_import_action();
    assert!(
        action.starts_with("app."),
        "primary menu Import action target must start with the `app.` group prefix so `gio::Menu` resolves it against the application action group; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_menu_export_action_returns_app_export() {
    // The `AppModel`'s primary `gio::Menu` "Export…" entry's
    // `detailed_action_name` is populated from this helper. The
    // wording (`"app.export"`) is the fully-qualified action
    // target the `gio::Menu` resolves against the application's
    // `app` action group. The `"app."` prefix names the group;
    // `"export"` names the action.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_export_label` on the menu-entry-
    // contract side; together they pin both halves (visible
    // label + action target) against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_export_action;

    assert_eq!(
        format_app_menu_export_action(),
        "app.export",
        "primary menu Export entry targets the app.export action on the application's action group",
    );
}

#[test]
fn format_app_menu_export_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group. `gio::Menu::append`'s `detailed_action_name`
    // argument expects a fully-qualified `<group>.<action>`
    // target; a bare action name silently no-ops at activation
    // time.
    use paladin_gtk::app::model::format_app_menu_export_action;

    let action = format_app_menu_export_action();
    assert!(
        action.starts_with("app."),
        "primary menu Export action target must start with the `app.` group prefix so `gio::Menu` resolves it against the application action group; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_menu_passphrase_action_returns_app_passphrase() {
    // The `AppModel`'s primary `gio::Menu` "Passphrase…" entry's
    // `detailed_action_name` is populated from this helper. The
    // wording (`"app.passphrase"`) is the fully-qualified action
    // target the `gio::Menu` resolves against the application's
    // `app` action group. The `"app."` prefix names the group;
    // `"passphrase"` names the action. The single `passphrase`
    // action dispatches the set / change / remove sub-flow gating
    // internally per `Vault::is_encrypted()` rather than carrying
    // three distinct menu entries.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_passphrase_label` on the menu-entry-
    // contract side; together they pin both halves (visible
    // label + action target) against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_passphrase_action;

    assert_eq!(
        format_app_menu_passphrase_action(),
        "app.passphrase",
        "primary menu Passphrase entry targets the app.passphrase action on the application's action group",
    );
}

#[test]
fn format_app_menu_passphrase_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group.
    use paladin_gtk::app::model::format_app_menu_passphrase_action;

    let action = format_app_menu_passphrase_action();
    assert!(
        action.starts_with("app."),
        "primary menu Passphrase action target must start with the `app.` group prefix so `gio::Menu` resolves it against the application action group; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_menu_preferences_action_returns_app_preferences() {
    // The `AppModel`'s primary `gio::Menu` "Preferences" entry's
    // `detailed_action_name` is populated from this helper. The
    // wording (`"app.preferences"`) is the fully-qualified action
    // target the `gio::Menu` resolves against the application's
    // `app` action group. The `"app."` prefix names the group;
    // `"preferences"` names the action.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_preferences_label` on the menu-entry-
    // contract side; together they pin both halves (visible
    // label + action target) against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_preferences_action;

    assert_eq!(
        format_app_menu_preferences_action(),
        "app.preferences",
        "primary menu Preferences entry targets the app.preferences action on the application's action group",
    );
}

#[test]
fn format_app_menu_preferences_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group.
    use paladin_gtk::app::model::format_app_menu_preferences_action;

    let action = format_app_menu_preferences_action();
    assert!(
        action.starts_with("app."),
        "primary menu Preferences action target must start with the `app.` group prefix so `gio::Menu` resolves it against the application action group; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_menu_about_action_returns_app_about() {
    // The `AppModel`'s primary `gio::Menu` "About Paladin"
    // entry's `detailed_action_name` is populated from this
    // helper. The wording (`"app.about"`) is the fully-qualified
    // action target the `gio::Menu` resolves against the
    // application's `app` action group. The `"app."` prefix
    // names the group; `"about"` names the action — bare
    // `"about"` rather than `"about_paladin"` so the action name
    // does not need to track an application rename if one ever
    // lands.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_about_label` on the menu-entry-
    // contract side; together they pin both halves (visible
    // label + action target) against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_about_action;

    assert_eq!(
        format_app_menu_about_action(),
        "app.about",
        "primary menu About entry targets the app.about action on the application's action group",
    );
}

#[test]
fn format_app_menu_about_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group.
    use paladin_gtk::app::model::format_app_menu_about_action;

    let action = format_app_menu_about_action();
    assert!(
        action.starts_with("app."),
        "primary menu About action target must start with the `app.` group prefix so `gio::Menu` resolves it against the application action group; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_menu_quit_action_returns_app_quit() {
    // The `AppModel`'s primary `gio::Menu` "Quit" entry's
    // `detailed_action_name` is populated from this helper. The
    // wording (`"app.quit"`) is the fully-qualified action target
    // the `gio::Menu` resolves against the application's `app`
    // action group. The `"app."` prefix names the group;
    // `"quit"` names the action. The matching `gio::SimpleAction`
    // dispatches the standard `Quit` shutdown path, deferring the
    // close until any in-flight vault worker returns per §"In-
    // flight effect ownership".
    //
    // Pure — returns a `'static str` without allocating. Final
    // sibling of the primary-menu action-target set
    // (`format_app_menu_import_action`,
    // `format_app_menu_export_action`,
    // `format_app_menu_passphrase_action`,
    // `format_app_menu_preferences_action`,
    // `format_app_menu_about_action`); together they pin all six
    // primary-menu entries' action targets against a single
    // source of truth, paired with the matching `_label`
    // helpers.
    use paladin_gtk::app::model::format_app_menu_quit_action;

    assert_eq!(
        format_app_menu_quit_action(),
        "app.quit",
        "primary menu Quit entry targets the app.quit action on the application's action group",
    );
}

#[test]
fn format_app_menu_quit_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group.
    use paladin_gtk::app::model::format_app_menu_quit_action;

    let action = format_app_menu_quit_action();
    assert!(
        action.starts_with("app."),
        "primary menu Quit action target must start with the `app.` group prefix so `gio::Menu` resolves it against the application action group; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_action_group_name_returns_app() {
    // The `AppModel`'s primary `gio::Menu` resolves every entry
    // target against the application's `app` action group. The
    // six `format_app_menu_*_action` helpers each spell the
    // fully-qualified `app.<action>` form; this helper names the
    // shared group prefix on its own so the matching
    // `gio::SimpleAction` registrations on
    // `gio::ApplicationWindow::insert_action_group(...)` (and the
    // future `app.<action>` accelerator wiring) read the prefix
    // from a single source of truth.
    //
    // Pure — returns a `'static str` without allocating.
    // Companion of the six primary-menu action-target helpers
    // (`format_app_menu_import_action`, …,
    // `format_app_menu_quit_action`); together they pin the
    // group prefix and every entry's action target against a
    // single source of truth.
    use paladin_gtk::app::model::format_app_action_group_name;

    assert_eq!(
        format_app_action_group_name(),
        "app",
        "primary menu action group is the bare `app` group registered on the application window",
    );
}

#[test]
fn format_app_action_group_name_has_no_separator_or_whitespace() {
    // Defense-in-depth: the group prefix must be a bare GLib
    // action-group name. A stray `.` would conflict with the
    // `<group>.<action>` separator used by the matching
    // `format_app_menu_*_action` helpers, and a stray space
    // would not survive `gio::ActionGroup`'s name validation.
    use paladin_gtk::app::model::format_app_action_group_name;

    let group = format_app_action_group_name();
    assert!(
        !group.contains('.'),
        "action group name must not embed the `<group>.<action>` separator; got {group:?}",
    );
    assert!(
        !group.contains(' '),
        "action group name must not contain whitespace; got {group:?}",
    );
    assert!(
        !group.is_empty(),
        "action group name must be non-empty; got {group:?}",
    );
}

#[test]
fn format_app_menu_import_action_name_returns_import() {
    // The `gio::SimpleAction::new("import", None)` registration on
    // the `AppModel`'s `app` action group reads its bare name from
    // this helper. The fully-qualified target spelled by
    // `format_app_menu_import_action` is the `format_app_action_group_name`
    // group prefix joined to this bare name via the `<group>.<action>`
    // separator, so the pair stays in lockstep when the `gio::Menu`
    // and the `gio::SimpleAction` are wired separately.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_import_action` on the fully-qualified
    // target side; together they pin both halves of the menu-
    // entry / SimpleAction contract against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_menu_import_action_name;

    assert_eq!(
        format_app_menu_import_action_name(),
        "import",
        "primary menu Import entry registers the bare `import` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_menu_import_action_name_has_no_separator_or_whitespace() {
    // Defense-in-depth: bare action names must not contain the
    // `<group>.<action>` separator (which would conflict with
    // `gio::Menu`'s detailed-action-name parsing) or whitespace
    // (which would not survive GLib's action-name validation).
    use paladin_gtk::app::model::format_app_menu_import_action_name;

    let action = format_app_menu_import_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_menu_import_action_name_round_trips_with_group_and_target() {
    // Cross-check: joining the shared group prefix from
    // `format_app_action_group_name` to the bare name from
    // `format_app_menu_import_action_name` must reproduce the
    // fully-qualified `detailed_action_name` spelled by
    // `format_app_menu_import_action`. Pins the three-way
    // contract so a rename of any one helper without updating
    // the others fails this test instead of silently desyncing
    // the `gio::Menu` from the `gio::SimpleAction` group.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_import_action,
        format_app_menu_import_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_menu_import_action_name(),
    );
    assert_eq!(
        joined,
        format_app_menu_import_action(),
        "`<group>.<action>` join must reproduce the fully-qualified Import menu action target",
    );
}

#[test]
fn format_app_menu_export_action_name_returns_export() {
    // The `gio::SimpleAction::new("export", None)` registration on
    // the `AppModel`'s `app` action group reads its bare name from
    // this helper. The fully-qualified target spelled by
    // `format_app_menu_export_action` is the `format_app_action_group_name`
    // group prefix joined to this bare name via the `<group>.<action>`
    // separator.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_export_action` on the fully-qualified
    // target side and `format_app_menu_export_label` on the
    // visible-label side; together they pin all three halves of
    // the menu-entry contract against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_export_action_name;

    assert_eq!(
        format_app_menu_export_action_name(),
        "export",
        "primary menu Export entry registers the bare `export` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_menu_export_action_name_has_no_separator_or_whitespace() {
    use paladin_gtk::app::model::format_app_menu_export_action_name;

    let action = format_app_menu_export_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_menu_export_action_name_round_trips_with_group_and_target() {
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_export_action,
        format_app_menu_export_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_menu_export_action_name(),
    );
    assert_eq!(
        joined,
        format_app_menu_export_action(),
        "`<group>.<action>` join must reproduce the fully-qualified Export menu action target",
    );
}

#[test]
fn format_app_menu_passphrase_action_name_returns_passphrase() {
    // The `gio::SimpleAction::new("passphrase", None)` registration
    // on the `AppModel`'s `app` action group reads its bare name
    // from this helper. The single `passphrase` action dispatches
    // the set / change / remove sub-flow gating internally per
    // `Vault::is_encrypted()` rather than carrying three distinct
    // menu entries (see §"Component tree"'s `PassphraseDialog`).
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_passphrase_action` on the fully-qualified
    // target side and `format_app_menu_passphrase_label` on the
    // visible-label side; together they pin all three halves of
    // the menu-entry contract against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_passphrase_action_name;

    assert_eq!(
        format_app_menu_passphrase_action_name(),
        "passphrase",
        "primary menu Passphrase entry registers the bare `passphrase` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_menu_passphrase_action_name_has_no_separator_or_whitespace() {
    use paladin_gtk::app::model::format_app_menu_passphrase_action_name;

    let action = format_app_menu_passphrase_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_menu_passphrase_action_name_round_trips_with_group_and_target() {
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_passphrase_action,
        format_app_menu_passphrase_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_menu_passphrase_action_name(),
    );
    assert_eq!(
        joined,
        format_app_menu_passphrase_action(),
        "`<group>.<action>` join must reproduce the fully-qualified Passphrase menu action target",
    );
}

#[test]
fn format_app_menu_preferences_action_name_returns_preferences() {
    // The `gio::SimpleAction::new("preferences", None)` registration
    // on the `AppModel`'s `app` action group reads its bare name
    // from this helper. The fully-qualified target spelled by
    // `format_app_menu_preferences_action` is the
    // `format_app_action_group_name` group prefix joined to this
    // bare name via the `<group>.<action>` separator.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_preferences_action` on the fully-
    // qualified target side and `format_app_menu_preferences_label`
    // on the visible-label side; together they pin all three halves
    // of the menu-entry contract against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_preferences_action_name;

    assert_eq!(
        format_app_menu_preferences_action_name(),
        "preferences",
        "primary menu Preferences entry registers the bare `preferences` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_menu_preferences_action_name_has_no_separator_or_whitespace() {
    use paladin_gtk::app::model::format_app_menu_preferences_action_name;

    let action = format_app_menu_preferences_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_menu_preferences_action_name_round_trips_with_group_and_target() {
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_preferences_action,
        format_app_menu_preferences_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_menu_preferences_action_name(),
    );
    assert_eq!(
        joined,
        format_app_menu_preferences_action(),
        "`<group>.<action>` join must reproduce the fully-qualified Preferences menu action target",
    );
}

#[test]
fn format_app_menu_about_action_name_returns_about() {
    // The `gio::SimpleAction::new("about", None)` registration on
    // the `AppModel`'s `app` action group reads its bare name from
    // this helper. The fully-qualified target spelled by
    // `format_app_menu_about_action` is the
    // `format_app_action_group_name` group prefix joined to this
    // bare name via the `<group>.<action>` separator. The bare
    // name is `"about"` rather than `"about_paladin"` so the
    // action does not need to track an application rename if one
    // ever lands.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_menu_about_action` on the fully-qualified
    // target side and `format_app_menu_about_label` on the visible-
    // label side; together they pin all three halves of the
    // menu-entry contract against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_about_action_name;

    assert_eq!(
        format_app_menu_about_action_name(),
        "about",
        "primary menu About entry registers the bare `about` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_menu_about_action_name_has_no_separator_or_whitespace() {
    use paladin_gtk::app::model::format_app_menu_about_action_name;

    let action = format_app_menu_about_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_menu_about_action_name_round_trips_with_group_and_target() {
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_about_action,
        format_app_menu_about_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_menu_about_action_name(),
    );
    assert_eq!(
        joined,
        format_app_menu_about_action(),
        "`<group>.<action>` join must reproduce the fully-qualified About menu action target",
    );
}

#[test]
fn format_app_menu_quit_action_name_returns_quit() {
    // The `gio::SimpleAction::new("quit", None)` registration on
    // the `AppModel`'s `app` action group reads its bare name from
    // this helper. The matching action dispatches the standard
    // `Quit` shutdown path, deferring the close until any in-
    // flight vault worker returns per §"In-flight effect
    // ownership".
    //
    // Pure — returns a `'static str` without allocating. Final
    // sibling of the bare-action-name set
    // (`format_app_menu_import_action_name`,
    // `format_app_menu_export_action_name`,
    // `format_app_menu_passphrase_action_name`,
    // `format_app_menu_preferences_action_name`,
    // `format_app_menu_about_action_name`); together they pin
    // all six primary-menu entries' bare SimpleAction names
    // against a single source of truth, paired with the matching
    // `_action` and `_label` helpers.
    use paladin_gtk::app::model::format_app_menu_quit_action_name;

    assert_eq!(
        format_app_menu_quit_action_name(),
        "quit",
        "primary menu Quit entry registers the bare `quit` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_menu_quit_action_name_has_no_separator_or_whitespace() {
    use paladin_gtk::app::model::format_app_menu_quit_action_name;

    let action = format_app_menu_quit_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_menu_quit_action_name_round_trips_with_group_and_target() {
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_quit_action, format_app_menu_quit_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_menu_quit_action_name(),
    );
    assert_eq!(
        joined,
        format_app_menu_quit_action(),
        "`<group>.<action>` join must reproduce the fully-qualified Quit menu action target",
    );
}

#[test]
fn every_primary_menu_action_name_round_trips_with_group_and_target() {
    // Final cross-check: for every primary-menu entry the
    // `<group>.<action_name>` join from the two helpers must
    // reproduce the fully-qualified `_action` target. Catches a
    // future rename of any one of the eighteen helpers without
    // updating its siblings.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_about_action,
        format_app_menu_about_action_name, format_app_menu_export_action,
        format_app_menu_export_action_name, format_app_menu_import_action,
        format_app_menu_import_action_name, format_app_menu_passphrase_action,
        format_app_menu_passphrase_action_name, format_app_menu_preferences_action,
        format_app_menu_preferences_action_name, format_app_menu_quit_action,
        format_app_menu_quit_action_name,
    };

    let group = format_app_action_group_name();
    for (label, bare, full) in [
        (
            "Import",
            format_app_menu_import_action_name(),
            format_app_menu_import_action(),
        ),
        (
            "Export",
            format_app_menu_export_action_name(),
            format_app_menu_export_action(),
        ),
        (
            "Passphrase",
            format_app_menu_passphrase_action_name(),
            format_app_menu_passphrase_action(),
        ),
        (
            "Preferences",
            format_app_menu_preferences_action_name(),
            format_app_menu_preferences_action(),
        ),
        (
            "About",
            format_app_menu_about_action_name(),
            format_app_menu_about_action(),
        ),
        (
            "Quit",
            format_app_menu_quit_action_name(),
            format_app_menu_quit_action(),
        ),
    ] {
        let joined = format!("{group}.{bare}");
        assert_eq!(
            joined, full,
            "`<group>.<action>` join must reproduce the {label} menu action target",
        );
    }
}

#[test]
fn format_app_add_button_action_returns_app_add() {
    // The header-bar `+` button's `detailed_action_name` is
    // populated from this helper. The wording (`"app.add"`) is
    // the fully-qualified action target the
    // `gtk::Button::set_action_name` call resolves against the
    // application's `app` action group. The `"app."` prefix names
    // the group; `"add"` names the action. The matching
    // `gio::SimpleAction` registered on the application's action
    // group opens `AddAccountComponent`. The `+` button shares the
    // `Unlocked` / `UnlockedBusy` gating with the four mutating
    // primary-menu entries per §"libadwaita usage".
    //
    // Pure — returns a `'static str` without allocating. Companion
    // of `format_app_add_button_icon_name` (header-bar glyph) and
    // `format_app_add_button_tooltip` (header-bar tooltip); together
    // they pin the visible button surface and its action wiring
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_add_button_action;

    assert_eq!(
        format_app_add_button_action(),
        "app.add",
        "header-bar + button targets the app.add action on the application's action group",
    );
}

#[test]
fn format_app_add_button_action_uses_app_group_prefix() {
    // Defense-in-depth against an accidental rename that would
    // drop the `app.` group prefix or move the action onto a
    // different group.
    use paladin_gtk::app::model::format_app_add_button_action;

    let action = format_app_add_button_action();
    assert!(
        action.starts_with("app."),
        "header-bar + button action target must start with the `app.` group prefix so the application's action group resolves it; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "action targets must not contain whitespace; got {action:?}",
    );
}

#[test]
fn format_app_add_button_action_name_returns_add() {
    // The `gio::SimpleAction::new("add", None)` registration on
    // the `AppModel`'s `app` action group reads its bare name from
    // this helper. The fully-qualified target spelled by
    // `format_app_add_button_action` is the
    // `format_app_action_group_name` group prefix joined to this
    // bare name via the `<group>.<action>` separator. The matching
    // action dispatches `AddAccountComponent` and shares the
    // `Unlocked` / `UnlockedBusy` gating with the four mutating
    // primary-menu entries per §"libadwaita usage".
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_add_button_action` on the fully-qualified
    // target side and `format_app_add_button_icon_name` /
    // `format_app_add_button_tooltip` on the header-bar visible
    // surface side; together they pin the bare action name and
    // its action wiring against a single source of truth.
    use paladin_gtk::app::model::format_app_add_button_action_name;

    assert_eq!(
        format_app_add_button_action_name(),
        "add",
        "header-bar + button registers the bare `add` SimpleAction on the application action group",
    );
}

#[test]
fn format_app_add_button_action_name_has_no_separator_or_whitespace() {
    use paladin_gtk::app::model::format_app_add_button_action_name;

    let action = format_app_add_button_action_name();
    assert!(
        !action.contains('.'),
        "bare action name must not embed the `<group>.<action>` separator; got {action:?}",
    );
    assert!(
        !action.contains(' '),
        "bare action name must not contain whitespace; got {action:?}",
    );
    assert!(
        !action.is_empty(),
        "bare action name must be non-empty; got {action:?}",
    );
}

#[test]
fn format_app_add_button_action_name_round_trips_with_group_and_target() {
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_add_button_action,
        format_app_add_button_action_name,
    };

    let joined = format!(
        "{}.{}",
        format_app_action_group_name(),
        format_app_add_button_action_name(),
    );
    assert_eq!(
        joined,
        format_app_add_button_action(),
        "`<group>.<action>` join must reproduce the fully-qualified header-bar + button action target",
    );
}

#[test]
fn format_app_primary_menu_entries_returns_six_entries_in_pinned_order() {
    // The `AppModel`'s primary `gio::Menu` is built by appending
    // each entry's (label, detailed-action-name) pair in the
    // §"libadwaita usage" sequence: Import, Export, Passphrase,
    // Preferences, About Paladin, Quit. This helper returns the
    // six pairs in order so the widget binding does not need to
    // hand-spell each `menu.append(...)` call against the
    // individual `format_app_menu_*_label` / `_action` helpers,
    // keeping the menu structure pinned to a single source of
    // truth.
    use paladin_gtk::app::model::{
        format_app_menu_about_action, format_app_menu_about_label, format_app_menu_export_action,
        format_app_menu_export_label, format_app_menu_import_action, format_app_menu_import_label,
        format_app_menu_passphrase_action, format_app_menu_passphrase_label,
        format_app_menu_preferences_action, format_app_menu_preferences_label,
        format_app_menu_quit_action, format_app_menu_quit_label, format_app_primary_menu_entries,
    };

    let entries = format_app_primary_menu_entries();
    assert_eq!(
        entries.len(),
        6,
        "primary menu must carry exactly six entries; got {}",
        entries.len(),
    );

    let expected: [(&'static str, &'static str); 6] = [
        (
            format_app_menu_import_label(),
            format_app_menu_import_action(),
        ),
        (
            format_app_menu_export_label(),
            format_app_menu_export_action(),
        ),
        (
            format_app_menu_passphrase_label(),
            format_app_menu_passphrase_action(),
        ),
        (
            format_app_menu_preferences_label(),
            format_app_menu_preferences_action(),
        ),
        (
            format_app_menu_about_label(),
            format_app_menu_about_action(),
        ),
        (format_app_menu_quit_label(), format_app_menu_quit_action()),
    ];
    assert_eq!(
        entries, expected,
        "primary menu entries must follow the pinned §\"libadwaita usage\" sequence (Import, Export, Passphrase, Preferences, About, Quit) and pair each label with its fully-qualified action target",
    );
}

#[test]
fn format_app_primary_menu_entries_uses_app_group_prefix_throughout() {
    // Defense-in-depth: every action target returned by
    // `format_app_primary_menu_entries` must start with the shared
    // `app.` group prefix. Catches a future bundling change that
    // accidentally swapped a `_label` and an `_action` argument so
    // the wrong slot of the pair carries the action target.
    use paladin_gtk::app::model::{format_app_action_group_name, format_app_primary_menu_entries};

    let group_prefix = format!("{}.", format_app_action_group_name());
    for (label, action) in format_app_primary_menu_entries() {
        assert!(
            action.starts_with(&group_prefix),
            "primary menu action target {action:?} for entry {label:?} must start with the shared group prefix {group_prefix:?}",
        );
        assert!(
            !label.is_empty(),
            "primary menu entry label must be non-empty; got {label:?} paired with {action:?}",
        );
        assert!(
            !label.starts_with(&group_prefix),
            "primary menu entry label {label:?} must not look like an action target — check that the (label, action) tuple slots are not swapped",
        );
    }
}

#[test]
fn build_app_primary_menu_model_appends_every_format_app_primary_menu_entries_pair() {
    // Per §"libadwaita usage" and §"Component tree": the header-bar
    // `gtk::MenuButton`'s `set_menu_model` slot is populated from
    // the `gio::Menu` returned by `build_app_primary_menu_model`,
    // which walks `format_app_primary_menu_entries` and appends one
    // entry per (label, action) pair in the §"libadwaita usage"
    // sequence (Import, Export, Passphrase, Preferences, About,
    // Quit). Centralizing the menu construction in one helper
    // means the labels and action targets stay sourced exclusively
    // from the pinned helpers — a drift between the widget binding
    // and the `format_app_menu_*` helpers cannot survive because
    // the widget reads the model through this single entry point
    // and the model walks the pinned array.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{build_app_primary_menu_model, format_app_primary_menu_entries};

    let menu = build_app_primary_menu_model();
    let entries = format_app_primary_menu_entries();
    let n_items = usize::try_from(menu.n_items()).expect("n_items fits in usize");
    assert_eq!(
        n_items,
        entries.len(),
        "build_app_primary_menu_model must append exactly one entry per format_app_primary_menu_entries pair; got {n_items} items vs {} pairs",
        entries.len(),
    );
    for (idx, (label, action)) in entries.iter().enumerate() {
        let position = i32::try_from(idx).expect("entry index fits in i32");
        let actual_label = menu
            .item_attribute_value(position, "label", None)
            .expect("primary menu entry has a label attribute")
            .str()
            .map(String::from)
            .expect("label attribute is a string variant");
        assert_eq!(
            &actual_label, label,
            "primary menu entry {idx}'s rendered label must match format_app_primary_menu_entries[{idx}].0",
        );
        let actual_action = menu
            .item_attribute_value(position, "action", None)
            .expect("primary menu entry has an action attribute")
            .str()
            .map(String::from)
            .expect("action attribute is a string variant");
        assert_eq!(
            &actual_action, action,
            "primary menu entry {idx}'s action target must match format_app_primary_menu_entries[{idx}].1",
        );
    }
}

#[test]
fn format_app_primary_menu_action_names_returns_six_bare_names_in_pinned_order() {
    // Companion to `format_app_primary_menu_entries`: the widget
    // binding registers a `gio::SimpleAction` for each primary-
    // menu entry on the application's `app` action group. This
    // helper returns the six bare action names in the §"libadwaita
    // usage" sequence (Import, Export, Passphrase, Preferences,
    // About, Quit), parallel to `format_app_primary_menu_entries`,
    // so the SimpleAction-registration loop and the
    // `gio::Menu::append` loop iterate over a single pinned
    // source of truth.
    use paladin_gtk::app::model::{
        format_app_menu_about_action_name, format_app_menu_export_action_name,
        format_app_menu_import_action_name, format_app_menu_passphrase_action_name,
        format_app_menu_preferences_action_name, format_app_menu_quit_action_name,
        format_app_primary_menu_action_names,
    };

    let names = format_app_primary_menu_action_names();
    assert_eq!(
        names.len(),
        6,
        "primary menu must register exactly six SimpleActions; got {}",
        names.len(),
    );
    assert_eq!(
        names,
        [
            format_app_menu_import_action_name(),
            format_app_menu_export_action_name(),
            format_app_menu_passphrase_action_name(),
            format_app_menu_preferences_action_name(),
            format_app_menu_about_action_name(),
            format_app_menu_quit_action_name(),
        ],
        "primary menu bare action names must follow the pinned §\"libadwaita usage\" sequence (Import, Export, Passphrase, Preferences, About, Quit)",
    );
}

#[test]
fn format_app_primary_menu_action_names_parallels_primary_menu_entries() {
    // Cross-check: zipping `format_app_primary_menu_action_names`
    // with the shared group prefix from
    // `format_app_action_group_name` and the `<group>.<action>`
    // separator must reproduce the fully-qualified action target
    // in the matching slot of `format_app_primary_menu_entries`.
    // Catches a future bundling change that drifted the action-
    // name array out of order with the (label, action) pair array.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_primary_menu_action_names,
        format_app_primary_menu_entries,
    };

    let group = format_app_action_group_name();
    let names = format_app_primary_menu_action_names();
    let entries = format_app_primary_menu_entries();
    assert_eq!(
        names.len(),
        entries.len(),
        "primary menu action-name array and entry-pair array must agree on length",
    );
    for (idx, (bare, (_label, full))) in names.iter().zip(entries.iter()).enumerate() {
        let joined = format!("{group}.{bare}");
        assert_eq!(
            &joined, full,
            "primary menu entry at index {idx}: `<group>.<action>` join must reproduce the fully-qualified action target paired with the visible label",
        );
        assert!(
            !bare.contains('.'),
            "bare action name {bare:?} at index {idx} must not embed the `<group>.<action>` separator",
        );
        assert!(
            !bare.is_empty(),
            "bare action name at index {idx} must be non-empty",
        );
    }
}

#[test]
fn format_app_primary_menu_action_sensitivities_disables_mutating_entries_off_unlocked() {
    // Per §"libadwaita usage": the Import / Export / Passphrase /
    // Preferences entries are disabled when `AppModel` is not in
    // `Unlocked` (so they are off in `Missing` / `Locked` /
    // `StartupError`) and disabled while `UnlockedBusy` is active
    // per §"In-flight effect ownership"; About and Quit stay
    // enabled in every state.
    use std::path::PathBuf;

    use paladin_gtk::app::model::format_app_primary_menu_action_sensitivities;
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    let path = PathBuf::from("/tmp/example/vault.bin");
    for state in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        AppState::StartupError {
            path: Some(path.clone()),
            error: StartupError {
                source: StartupErrorSource::Inspect,
                kind: paladin_core::ErrorKind::InvalidHeader,
                rendered: String::new(),
            },
        },
    ] {
        let sens = format_app_primary_menu_action_sensitivities(&state);
        assert_eq!(sens.len(), 6, "primary menu must carry exactly six entries");
        assert!(
            !sens[0],
            "Import must be disabled for state={state:?} (allows_mutating_menu == false)",
        );
        assert!(
            !sens[1],
            "Export must be disabled for state={state:?} (allows_mutating_menu == false)",
        );
        assert!(
            !sens[2],
            "Passphrase must be disabled for state={state:?} (allows_mutating_menu == false)",
        );
        assert!(
            !sens[3],
            "Preferences must be disabled for state={state:?} (allows_mutating_menu == false)",
        );
        assert!(
            sens[4],
            "About must stay enabled for state={state:?} per §\"libadwaita usage\"",
        );
        assert!(
            sens[5],
            "Quit must stay enabled for state={state:?} per §\"libadwaita usage\"",
        );
    }
}

#[test]
fn format_app_primary_menu_action_sensitivities_enables_mutating_entries_on_unlocked() {
    use std::path::PathBuf;

    use paladin_gtk::app::model::format_app_primary_menu_action_sensitivities;
    use paladin_gtk::app::state::AppState;

    let state = AppState::Unlocked {
        path: PathBuf::from("/tmp/example/vault.bin"),
    };
    let sens = format_app_primary_menu_action_sensitivities(&state);
    assert_eq!(
        sens, [true; 6],
        "every primary menu entry must be enabled when AppState is Unlocked",
    );
}

#[test]
fn format_app_primary_menu_action_sensitivities_mirrors_allows_mutating_menu_for_first_four_entries(
) {
    // Defense-in-depth: the four mutating entries (Import,
    // Export, Passphrase, Preferences) must read their
    // sensitivities from `AppState::allows_mutating_menu`
    // directly, not via a duplicated rule that could drift.
    use std::path::PathBuf;

    use paladin_gtk::app::model::format_app_primary_menu_action_sensitivities;
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    let path = PathBuf::from("/tmp/example/vault.bin");
    for state in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        AppState::StartupError {
            path: Some(path.clone()),
            error: StartupError {
                source: StartupErrorSource::Inspect,
                kind: paladin_core::ErrorKind::InvalidHeader,
                rendered: String::new(),
            },
        },
    ] {
        let sens = format_app_primary_menu_action_sensitivities(&state);
        let expected = state.allows_mutating_menu();
        for (idx, entry) in ["Import", "Export", "Passphrase", "Preferences"]
            .iter()
            .enumerate()
        {
            assert_eq!(
                sens[idx], expected,
                "{entry} sensitivity for state={state:?} must match AppState::allows_mutating_menu (got {sens:?})",
            );
        }
    }
}

#[test]
fn format_app_add_button_sensitive_disabled_off_unlocked() {
    // Per §"libadwaita usage": the header-bar `+` button is
    // disabled when `AppModel` is not in `Unlocked` (so it is off
    // in `Missing` / `Locked` / `StartupError`) and disabled
    // while `UnlockedBusy` is active per §"In-flight effect
    // ownership", matching the four mutating primary-menu entries.
    use std::path::PathBuf;

    use paladin_gtk::app::model::format_app_add_button_sensitive;
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    let path = PathBuf::from("/tmp/example/vault.bin");
    for state in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        AppState::StartupError {
            path: Some(path.clone()),
            error: StartupError {
                source: StartupErrorSource::Inspect,
                kind: paladin_core::ErrorKind::InvalidHeader,
                rendered: String::new(),
            },
        },
    ] {
        assert!(
            !format_app_add_button_sensitive(&state),
            "header-bar + button must be disabled for state={state:?} (allows_mutating_menu == false)",
        );
    }
}

#[test]
fn format_app_add_button_sensitive_enabled_on_unlocked() {
    use std::path::PathBuf;

    use paladin_gtk::app::model::format_app_add_button_sensitive;
    use paladin_gtk::app::state::AppState;

    let state = AppState::Unlocked {
        path: PathBuf::from("/tmp/example/vault.bin"),
    };
    assert!(
        format_app_add_button_sensitive(&state),
        "header-bar + button must be enabled when AppState is Unlocked",
    );
}

#[test]
fn format_app_add_button_sensitive_mirrors_allows_mutating_menu() {
    // Defense-in-depth: the + button's sensitivity must read
    // from `AppState::allows_mutating_menu` directly, not via
    // a duplicated rule that could drift. Asserts the mirroring
    // across all five `AppState` variants.
    use std::path::PathBuf;

    use paladin_gtk::app::model::format_app_add_button_sensitive;
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    let path = PathBuf::from("/tmp/example/vault.bin");
    for state in [
        AppState::Missing { path: path.clone() },
        AppState::Locked { path: path.clone() },
        AppState::Unlocked { path: path.clone() },
        AppState::UnlockedBusy { path: path.clone() },
        AppState::StartupError {
            path: Some(path.clone()),
            error: StartupError {
                source: StartupErrorSource::Inspect,
                kind: paladin_core::ErrorKind::InvalidHeader,
                rendered: String::new(),
            },
        },
    ] {
        assert_eq!(
            format_app_add_button_sensitive(&state),
            state.allows_mutating_menu(),
            "header-bar + button sensitivity for state={state:?} must match AppState::allows_mutating_menu",
        );
    }
}

#[test]
fn format_app_about_dialog_program_name_returns_paladin() {
    // Per §"libadwaita usage": the application menu's "About
    // Paladin" entry opens an `AdwAboutDialog` that pulls program
    // metadata from a single source of truth. This helper returns
    // the human-readable program name `"Paladin"` shown in the
    // dialog header, matching the §11.3 desktop entry's
    // `Name=Paladin` field so the launcher caption and the about
    // dialog header stay in lockstep.
    //
    // Pure — returns a `'static str` without allocating. Not the
    // same string as the §11.4 Flatpak / app-ID `APP_ID`
    // (`"org.tamx.Paladin.Gui"`), which is the reverse-DNS
    // identifier used by `RelmApp::new(...)`,
    // `StartupWMClass`, the icon-theme key, and the AppStream
    // `<id>`; the program name is for human display.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    assert_eq!(
        format_app_about_dialog_program_name(),
        "Paladin",
        "AdwAboutDialog program name must be the canonical display name `Paladin`, matching the §11.3 desktop entry `Name=Paladin`",
    );
}

#[test]
fn format_app_about_dialog_program_name_is_non_empty_and_not_app_id() {
    // Defense-in-depth: the program name must be non-empty so
    // `AdwAboutDialog` renders a header, and it must NOT be the
    // reverse-DNS `APP_ID` (which is for system identifiers, not
    // human display).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;
    use paladin_gtk::APP_ID;

    let name = format_app_about_dialog_program_name();
    assert!(
        !name.is_empty(),
        "AdwAboutDialog program name must be non-empty; got {name:?}",
    );
    assert_ne!(
        name, APP_ID,
        "AdwAboutDialog program name must be the human display name, not the reverse-DNS APP_ID (`{APP_ID}`)",
    );
    assert!(
        !name.contains('.'),
        "AdwAboutDialog program name must be a bare display name, not a reverse-DNS identifier; got {name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_matches_cargo_pkg_version() {
    // Per §"libadwaita usage": the application menu's "About
    // Paladin" entry's `AdwAboutDialog` pulls program metadata
    // from Cargo package metadata embedded at compile time. This
    // helper returns the version string the dialog displays,
    // sourced from `env!("CARGO_PKG_VERSION")` so the dialog
    // header version line and the release-tag version stay in
    // lockstep without manual updates.
    //
    // Pure — returns a `'static str` resolved at compile time.
    // Companion of `format_app_about_dialog_program_name` on
    // the AdwAboutDialog metadata side.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    assert_eq!(
        format_app_about_dialog_version(),
        env!("CARGO_PKG_VERSION"),
        "AdwAboutDialog version must source from Cargo metadata via env!(\"CARGO_PKG_VERSION\")",
    );
}

#[test]
fn format_app_about_dialog_version_is_non_empty_and_looks_like_semver() {
    // Defense-in-depth: the version must be non-empty (so
    // `AdwAboutDialog` renders a version line) and must contain
    // at least one `.` separator so it looks like a semver string
    // rather than something accidentally swapped from a different
    // metadata field.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.is_empty(),
        "AdwAboutDialog version must be non-empty; got {version:?}",
    );
    assert!(
        version.contains('.'),
        "AdwAboutDialog version must look like a semver string with at least one `.` separator; got {version:?}",
    );
    assert!(
        !version.contains(' '),
        "AdwAboutDialog version must not contain whitespace; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_matches_app_id() {
    // Per §"libadwaita usage" and §11.3: the `AdwAboutDialog`
    // header glyph is the application icon, looked up in the
    // system icon theme by name. The icon files install under
    // `/usr/share/icons/hicolor/<size>/apps/org.tamx.Paladin.Gui.*`
    // and the desktop entry sets `Icon=org.tamx.Paladin.Gui`, so
    // the icon-theme key the about dialog hands to
    // `AdwAboutDialog::set_application_icon` is the same
    // reverse-DNS app ID. This helper returns that key from the
    // same source of truth as the `RelmApp::new(APP_ID)`
    // identifier so the launcher icon, the desktop entry icon,
    // the AppStream icon, and the about dialog header glyph
    // resolve identically.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;
    use paladin_gtk::APP_ID;

    assert_eq!(
        format_app_about_dialog_application_icon_name(),
        APP_ID,
        "AdwAboutDialog application-icon must match `APP_ID` so the dialog header glyph resolves against the §11.3 hicolor icon install layout",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_is_reverse_dns() {
    // Defense-in-depth: the icon-theme key is the reverse-DNS
    // app identifier (`org.tamx.Paladin.Gui`), not the human
    // display name. Catches an accidental swap with
    // `format_app_about_dialog_program_name` which returns the
    // bare `Paladin` display string.
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_program_name,
    };

    let icon = format_app_about_dialog_application_icon_name();
    assert!(
        !icon.is_empty(),
        "AdwAboutDialog application-icon must be non-empty; got {icon:?}",
    );
    assert!(
        icon.contains('.'),
        "AdwAboutDialog application-icon must be a reverse-DNS identifier with at least one `.` separator; got {icon:?}",
    );
    assert!(
        !icon.contains(' '),
        "AdwAboutDialog application-icon must not contain whitespace; got {icon:?}",
    );
    assert_ne!(
        icon,
        format_app_about_dialog_program_name(),
        "AdwAboutDialog application-icon must be the reverse-DNS app identifier, not the human program-name display string",
    );
}

#[test]
fn format_app_about_dialog_developer_name_returns_the_paladin_contributors() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` developer-name slot attributes the
    // application. The workspace `Cargo.toml` deliberately omits
    // the `authors` field (AGPL-3.0-or-later project with an open
    // contributor pool), so the helper returns the canonical
    // collective attribution string rather than sourcing from
    // `env!("CARGO_PKG_AUTHORS")` (which would resolve to an
    // empty string). Pinning the literal here keeps the dialog
    // header attribution row stable across releases and across
    // native vs. Flatpak builds.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    assert_eq!(
        format_app_about_dialog_developer_name(),
        "The Paladin contributors",
        "AdwAboutDialog developer-name must be the canonical collective attribution string so the dialog header attribution row stays stable across releases",
    );
}

#[test]
fn format_app_about_dialog_developer_name_is_non_empty_and_distinct_from_program_name() {
    // Defense-in-depth: the developer name is the attribution
    // string, not the program name. Catches an accidental swap
    // with `format_app_about_dialog_program_name` (which returns
    // the bare `Paladin` display string) or with
    // `format_app_about_dialog_application_icon_name` (which
    // returns the reverse-DNS `org.tamx.Paladin.Gui` icon key).
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_developer_name,
        format_app_about_dialog_program_name,
    };

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.is_empty(),
        "AdwAboutDialog developer-name must be non-empty; got {developer:?}",
    );
    assert!(
        !developer.starts_with(char::is_whitespace),
        "AdwAboutDialog developer-name must not start with whitespace; got {developer:?}",
    );
    assert!(
        !developer.ends_with(char::is_whitespace),
        "AdwAboutDialog developer-name must not end with whitespace; got {developer:?}",
    );
    assert_ne!(
        developer,
        format_app_about_dialog_program_name(),
        "AdwAboutDialog developer-name must be distinct from the program-name display string",
    );
    assert_ne!(
        developer,
        format_app_about_dialog_application_icon_name(),
        "AdwAboutDialog developer-name must be the attribution string, not the reverse-DNS application-icon key",
    );
}

#[test]
fn format_app_about_dialog_copyright_returns_paladin_copyright_line() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` copyright slot displays the project's
    // copyright notice. Paladin is AGPL-3.0-or-later (DESIGN.md
    // §14) with an open contributor pool — the canonical notice
    // attributes the same collective spelled by
    // `format_app_about_dialog_developer_name` and carries the
    // `©` glyph so the dialog renders the proper legal mark
    // rather than the ASCII `(C)` fallback. Pinning the literal
    // here keeps the dialog footer copyright row stable across
    // releases without depending on a year-derived value (which
    // would silently drift on a future release without a
    // matching constant update).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    assert_eq!(
        format_app_about_dialog_copyright(),
        "© The Paladin contributors",
        "AdwAboutDialog copyright must be the canonical AGPL-3.0-or-later collective attribution line",
    );
}

#[test]
fn format_app_about_dialog_copyright_starts_with_copyright_glyph_and_contains_developer_name() {
    // Defense-in-depth: the copyright slot must render the legal
    // `©` mark (U+00A9) — not the ASCII `(C)` placeholder — and
    // must spell out the same attribution string returned by
    // `format_app_about_dialog_developer_name` so the dialog
    // header attribution row and footer copyright row reference
    // a single source of truth. Catches an accidental drift
    // between the developer-name and copyright strings.
    use paladin_gtk::app::model::{
        format_app_about_dialog_copyright, format_app_about_dialog_developer_name,
    };

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.is_empty(),
        "AdwAboutDialog copyright must be non-empty; got {copyright:?}",
    );
    assert!(
        copyright.starts_with('\u{00A9}'),
        "AdwAboutDialog copyright must start with the legal `©` (U+00A9) glyph, not the ASCII `(C)` placeholder; got {copyright:?}",
    );
    assert!(
        !copyright.contains("(C)") && !copyright.contains("(c)"),
        "AdwAboutDialog copyright must not embed the ASCII `(C)` placeholder once the `©` glyph is in place; got {copyright:?}",
    );
    assert!(
        copyright.contains(format_app_about_dialog_developer_name()),
        "AdwAboutDialog copyright must spell out the same attribution as `format_app_about_dialog_developer_name`; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_license_type_returns_agpl30_or_later() {
    // Per DESIGN.md §14 the project ships under AGPL-3.0-or-later
    // and the §"CLAUDE.md / License hygiene" workspace contract
    // pins every crate's `license = "AGPL-3.0-or-later"`. The
    // matching GTK license-type enum variant is `License::Agpl30`
    // (the `GTK_LICENSE_AGPL_3_0` value — the "or later" form,
    // not the `Agpl30Only` strict variant). Pinning the typed
    // enum value here keeps the `AdwAboutDialog::set_license_type`
    // call site free of SPDX-string-to-enum translation logic
    // and keeps the dialog footer license link rendering the
    // canonical AGPL-3.0-or-later text shipped with the dialog.
    use paladin_gtk::app::model::format_app_about_dialog_license_type;
    use relm4::gtk;

    assert_eq!(
        format_app_about_dialog_license_type(),
        gtk::License::Agpl30,
        "AdwAboutDialog license-type must be `gtk::License::Agpl30` (the AGPL-3.0-or-later variant)",
    );
}

#[test]
fn format_app_about_dialog_license_type_is_not_strict_agpl30_only_or_other_gpl_family() {
    // Defense-in-depth: catch an accidental swap with the strict
    // `Agpl30Only` variant (which would mis-state the license
    // boundary to users) or with the sibling `Gpl30` /
    // `Gpl30Only` / `Lgpl30` variants. The DESIGN.md §14 contract
    // is specifically AGPL-3.0-or-later, so anything other than
    // `Agpl30` would silently misrepresent the project license in
    // the dialog footer link.
    use paladin_gtk::app::model::format_app_about_dialog_license_type;
    use relm4::gtk;

    let license = format_app_about_dialog_license_type();
    assert_ne!(
        license,
        gtk::License::Agpl30Only,
        "AdwAboutDialog license-type must be the `or later` form `Agpl30`, not the strict `Agpl30Only` variant",
    );
    for forbidden in [
        gtk::License::Unknown,
        gtk::License::Custom,
        gtk::License::Gpl30,
        gtk::License::Gpl30Only,
        gtk::License::Lgpl30,
        gtk::License::Lgpl30Only,
    ] {
        assert_ne!(
            license, forbidden,
            "AdwAboutDialog license-type must be `Agpl30` (AGPL-3.0-or-later), not {forbidden:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_website_matches_cargo_pkg_homepage() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` website slot links to the project
    // homepage. The workspace `[workspace.package]` table sets
    // `homepage = "https://paladin.tamx.org"` so a workspace-
    // wide homepage change propagates here for free. Pinning the
    // helper to `env!("CARGO_PKG_HOMEPAGE")` keeps the dialog
    // footer website link and the §"License hygiene" /
    // §"package metadata" homepage field in lockstep without a
    // manual update.
    use paladin_gtk::app::model::format_app_about_dialog_website;

    assert_eq!(
        format_app_about_dialog_website(),
        env!("CARGO_PKG_HOMEPAGE"),
        "AdwAboutDialog website must source from `env!(\"CARGO_PKG_HOMEPAGE\")` so it tracks the workspace homepage field",
    );
}

#[test]
fn format_app_about_dialog_website_is_non_empty_https_url() {
    // Defense-in-depth: the dialog footer link must be a usable
    // URL, not an empty placeholder. The homepage MUST be HTTPS
    // (Paladin is a secrets-handling tool; an HTTP `about`
    // website link would expose users to MITM downgrades on the
    // canonical project page).
    use paladin_gtk::app::model::format_app_about_dialog_website;

    let website = format_app_about_dialog_website();
    assert!(
        !website.is_empty(),
        "AdwAboutDialog website must be non-empty; got {website:?}",
    );
    assert!(
        website.starts_with("https://"),
        "AdwAboutDialog website must be an HTTPS URL (Paladin handles secrets — never link the about dialog to an http:// page); got {website:?}",
    );
    assert!(
        !website.contains(' '),
        "AdwAboutDialog website must not contain whitespace; got {website:?}",
    );
}

#[test]
fn format_app_about_dialog_issue_url_appends_issues_to_cargo_pkg_repository() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` issue-url slot links to the project's
    // public issue tracker. The workspace `[workspace.package]`
    // table sets `repository = "https://github.com/FreedomBen/paladin"`
    // and `crates/paladin-gtk` inherits via `repository.workspace
    // = true`, so a workspace-wide repository change propagates
    // here for free. Pinning the helper to
    // `concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")` keeps the
    // dialog footer "Report an issue" link aligned with the
    // GitHub `<repo>/issues` URL convention without a manual
    // duplicate constant.
    use paladin_gtk::app::model::format_app_about_dialog_issue_url;

    assert_eq!(
        format_app_about_dialog_issue_url(),
        concat!(env!("CARGO_PKG_REPOSITORY"), "/issues"),
        "AdwAboutDialog issue-url must source from `env!(\"CARGO_PKG_REPOSITORY\") + \"/issues\"` so it tracks the workspace repository field",
    );
}

#[test]
fn format_app_about_dialog_issue_url_is_non_empty_https_url_distinct_from_website() {
    // Defense-in-depth: the issue-url must be a usable HTTPS URL
    // (Paladin handles secrets — an HTTP issue tracker link would
    // expose users to MITM downgrades on the canonical bug-
    // reporting page) and must be distinct from the website URL
    // so the dialog renders two separate footer links rather
    // than collapsing them.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_website,
    };

    let issue_url = format_app_about_dialog_issue_url();
    assert!(
        !issue_url.is_empty(),
        "AdwAboutDialog issue-url must be non-empty; got {issue_url:?}",
    );
    assert!(
        issue_url.starts_with("https://"),
        "AdwAboutDialog issue-url must be an HTTPS URL (Paladin handles secrets — never link the about dialog to an http:// page); got {issue_url:?}",
    );
    assert!(
        !issue_url.contains(' '),
        "AdwAboutDialog issue-url must not contain whitespace; got {issue_url:?}",
    );
    assert!(
        issue_url.ends_with("/issues"),
        "AdwAboutDialog issue-url must follow the `<repo>/issues` GitHub convention; got {issue_url:?}",
    );
    assert_ne!(
        issue_url,
        format_app_about_dialog_website(),
        "AdwAboutDialog issue-url must be distinct from the website URL so the dialog renders two separate footer links",
    );
}

#[test]
fn format_app_about_dialog_support_url_appends_discussions_to_cargo_pkg_repository() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` support-url slot links to the project's
    // "Where to find help" surface (community Q&A, not bug
    // reports — the latter live on `issue_url`). For a GitHub-
    // hosted project without an established Matrix/Discord
    // channel the canonical surface is the repo's Discussions
    // tab. Sourcing from `concat!(env!("CARGO_PKG_REPOSITORY"),
    // "/discussions")` keeps the dialog footer "Get support"
    // link aligned with the workspace repository field.
    use paladin_gtk::app::model::format_app_about_dialog_support_url;

    assert_eq!(
        format_app_about_dialog_support_url(),
        concat!(env!("CARGO_PKG_REPOSITORY"), "/discussions"),
        "AdwAboutDialog support-url must source from `env!(\"CARGO_PKG_REPOSITORY\") + \"/discussions\"` so it tracks the workspace repository field",
    );
}

#[test]
fn format_app_about_dialog_support_url_is_non_empty_https_url_distinct_from_issue_and_website() {
    // Defense-in-depth: the support-url must be HTTPS, non-empty,
    // and distinct from both the website and the issue-tracker
    // URLs — so the dialog footer renders three separate links
    // ("Website", "Get support", "Report an issue") rather than
    // collapsing the support entry into either neighbour.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    let support_url = format_app_about_dialog_support_url();
    assert!(
        !support_url.is_empty(),
        "AdwAboutDialog support-url must be non-empty; got {support_url:?}",
    );
    assert!(
        support_url.starts_with("https://"),
        "AdwAboutDialog support-url must be an HTTPS URL (Paladin handles secrets — never link the about dialog to an http:// page); got {support_url:?}",
    );
    assert!(
        !support_url.contains(' '),
        "AdwAboutDialog support-url must not contain whitespace; got {support_url:?}",
    );
    assert_ne!(
        support_url,
        format_app_about_dialog_issue_url(),
        "AdwAboutDialog support-url must be distinct from the issue-tracker URL — community Q&A and bug reports are separate footer surfaces",
    );
    assert_ne!(
        support_url,
        format_app_about_dialog_website(),
        "AdwAboutDialog support-url must be distinct from the website URL so the dialog renders two separate footer links",
    );
}

#[test]
fn format_app_about_dialog_comments_matches_cargo_pkg_description() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` comments slot renders the project's short
    // description directly under the program-name header. The
    // workspace `[workspace.package]` table sets
    // `description = "Paladin: Rust OTP authenticator (TOTP +
    // HOTP) with CLI, TUI, and GTK front-ends"` and
    // `crates/paladin-gtk` inherits via `description.workspace =
    // true`, so a workspace-wide description change propagates
    // here for free. Pinning the helper to
    // `env!("CARGO_PKG_DESCRIPTION")` keeps the dialog comments
    // row and the §"package metadata" description field in
    // lockstep without a manual duplicate.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    assert_eq!(
        format_app_about_dialog_comments(),
        env!("CARGO_PKG_DESCRIPTION"),
        "AdwAboutDialog comments must source from `env!(\"CARGO_PKG_DESCRIPTION\")` so it tracks the workspace description field",
    );
}

#[test]
fn format_app_about_dialog_comments_is_non_empty_single_line_distinct_from_program_name() {
    // Defense-in-depth: the comments slot must be non-empty (a
    // blank comments row would degrade the dialog header). It
    // must also be a single line (AdwAboutDialog renders
    // comments inline under the program name; embedded newlines
    // would break the header layout) and distinct from the
    // program-name display string so the dialog renders two
    // separate header rows rather than collapsing them.
    use paladin_gtk::app::model::{
        format_app_about_dialog_comments, format_app_about_dialog_program_name,
    };

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.is_empty(),
        "AdwAboutDialog comments must be non-empty; got {comments:?}",
    );
    assert!(
        !comments.contains('\n'),
        "AdwAboutDialog comments must be a single line (no embedded newlines); got {comments:?}",
    );
    assert!(
        !comments.starts_with(char::is_whitespace),
        "AdwAboutDialog comments must not start with whitespace; got {comments:?}",
    );
    assert!(
        !comments.ends_with(char::is_whitespace),
        "AdwAboutDialog comments must not end with whitespace; got {comments:?}",
    );
    assert_ne!(
        comments,
        format_app_about_dialog_program_name(),
        "AdwAboutDialog comments must be distinct from the program-name display string so the dialog header renders two separate rows",
    );
}

#[test]
fn format_app_about_dialog_developers_lists_benjamin_porter() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` developers slot populates the dialog's
    // "Credits" page contributor list. The current contributor
    // pool for the v0.2 release per `git log` is the single
    // founding developer; pinning the literal here keeps the
    // credits list stable across releases until a contributor
    // is explicitly added. Distinct from
    // `format_app_about_dialog_developer_name` (the single
    // header attribution string) which uses the collective
    // attribution because the workspace `Cargo.toml` deliberately
    // omits the `authors` field.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    assert_eq!(
        format_app_about_dialog_developers(),
        ["Benjamin Porter"],
        "AdwAboutDialog developers must be the pinned credits-page contributor list",
    );
}

#[test]
fn format_app_about_dialog_developers_is_non_empty_array_of_non_empty_single_line_names() {
    // Defense-in-depth: every entry in the credits-page
    // contributor list must be non-empty (a blank credit would
    // render an empty row in the dialog) and a single line (the
    // dialog renders one entry per row; embedded newlines would
    // break the layout). Catches an accidental empty literal or
    // a multi-line entry that drifted in.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    assert!(
        !developers.is_empty(),
        "AdwAboutDialog developers must be a non-empty contributor list",
    );
    for name in developers {
        assert!(
            !name.is_empty(),
            "AdwAboutDialog developers entry must be non-empty; got {name:?}",
        );
        assert!(
            !name.contains('\n'),
            "AdwAboutDialog developers entry must be a single line (no embedded newlines); got {name:?}",
        );
        assert!(
            !name.starts_with(char::is_whitespace),
            "AdwAboutDialog developers entry must not start with whitespace; got {name:?}",
        );
        assert!(
            !name.ends_with(char::is_whitespace),
            "AdwAboutDialog developers entry must not end with whitespace; got {name:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_documenters_is_empty_until_a_documenter_joins() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` documenters slot populates the dialog's
    // credits-page "Documentation" section. Paladin does not
    // yet have a separately-credited documenter — the project
    // `README.md`, `DESIGN.md`, and inline rustdoc are written
    // by the founding contributor in
    // `format_app_about_dialog_developers` — so the documenters
    // slot stays empty until a credited documenter joins. The
    // empty array makes `AdwAboutDialog` skip the credits-page
    // "Documentation" row entirely (per the libadwaita
    // convention), which is the correct rendering for an app
    // with no credited documenter.
    use paladin_gtk::app::model::format_app_about_dialog_documenters;

    let documenters: [&str; 0] = format_app_about_dialog_documenters();
    assert!(
        documenters.is_empty(),
        "AdwAboutDialog documenters must be empty until a separately-credited documenter joins so the credits-page Documentation row is suppressed",
    );
}

#[test]
fn format_app_about_dialog_documenters_is_distinct_type_from_developers() {
    // Defense-in-depth: even though both helpers populate
    // credits-page sections, the developers list returns a
    // non-empty `[&'static str; 1]` while the documenters list
    // returns the empty `[&'static str; 0]` — so the dialog
    // renders the "Developers" section but skips the
    // "Documentation" section. A drift that copy-pasted the
    // developers literal into the documenters helper would
    // surface as a duplicate contributor credit on the credits
    // page.
    use paladin_gtk::app::model::{
        format_app_about_dialog_developers, format_app_about_dialog_documenters,
    };

    let documenters = format_app_about_dialog_documenters();
    let developers = format_app_about_dialog_developers();
    assert!(
        documenters.is_empty(),
        "AdwAboutDialog documenters must be empty so the credits-page Documentation row is suppressed",
    );
    assert!(
        !developers.is_empty(),
        "AdwAboutDialog developers must be non-empty so the credits-page Developers row renders the founding contributor",
    );
}

#[test]
fn format_app_about_dialog_artists_is_empty_until_an_artist_joins() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` artists slot populates the dialog's
    // credits-page "Artists" section. Paladin does not yet have
    // a separately-credited artist — the application icon and
    // any auxiliary glyphs ship with the standard freedesktop /
    // Adwaita symbolic icon set (which carries its own upstream
    // credits) and the founding contributor in
    // `format_app_about_dialog_developers` owns the Paladin-
    // specific visual choices — so the artists slot stays empty
    // until a credited artist joins. The empty array makes
    // `AdwAboutDialog` skip the credits-page "Artists" row
    // entirely (per the libadwaita convention), which is the
    // correct rendering for an app with no credited artist.
    use paladin_gtk::app::model::format_app_about_dialog_artists;

    let artists: [&str; 0] = format_app_about_dialog_artists();
    assert!(
        artists.is_empty(),
        "AdwAboutDialog artists must be empty until a separately-credited artist joins so the credits-page Artists row is suppressed",
    );
}

#[test]
fn format_app_about_dialog_artists_is_distinct_type_from_developers() {
    // Defense-in-depth: even though both helpers populate
    // credits-page sections, the developers list returns a
    // non-empty `[&'static str; 1]` while the artists list
    // returns the empty `[&'static str; 0]` — so the dialog
    // renders the "Developers" section but skips the "Artists"
    // section. A drift that copy-pasted the developers literal
    // into the artists helper would surface as a duplicate
    // contributor credit on the credits page.
    use paladin_gtk::app::model::{
        format_app_about_dialog_artists, format_app_about_dialog_developers,
    };

    let artists = format_app_about_dialog_artists();
    let developers = format_app_about_dialog_developers();
    assert!(
        artists.is_empty(),
        "AdwAboutDialog artists must be empty so the credits-page Artists row is suppressed",
    );
    assert!(
        !developers.is_empty(),
        "AdwAboutDialog developers must be non-empty so the credits-page Developers row renders the founding contributor",
    );
}

#[test]
fn format_app_about_dialog_designers_is_empty_until_a_designer_joins() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` designers slot populates the dialog's
    // credits-page "Designers" section. Paladin does not yet
    // have a separately-credited designer — the founding
    // contributor in `format_app_about_dialog_developers` also
    // owns the GTK / HIG layout choices — so the designers slot
    // stays empty until a credited designer joins. The empty
    // array makes `AdwAboutDialog` skip the credits-page
    // "Designers" row entirely (per the libadwaita convention),
    // which is the correct rendering for an app with no credited
    // designer.
    use paladin_gtk::app::model::format_app_about_dialog_designers;

    let designers: [&str; 0] = format_app_about_dialog_designers();
    assert!(
        designers.is_empty(),
        "AdwAboutDialog designers must be empty until a separately-credited designer joins so the credits-page Designers row is suppressed",
    );
}

#[test]
fn format_app_about_dialog_designers_is_distinct_type_from_developers() {
    // Defense-in-depth: even though both helpers populate
    // credits-page sections, the developers list returns a
    // non-empty `[&'static str; 1]` and the designers list
    // returns the empty `[&'static str; 0]` — so the dialog
    // renders the "Developers" section but skips the "Designers"
    // section. A drift that copy-pasted the developers literal
    // into the designers helper would surface as a duplicate
    // contributor credit on the credits page.
    use paladin_gtk::app::model::{
        format_app_about_dialog_designers, format_app_about_dialog_developers,
    };

    let designers = format_app_about_dialog_designers();
    let developers = format_app_about_dialog_developers();
    assert!(
        designers.is_empty(),
        "AdwAboutDialog designers must be empty so the credits-page Designers row is suppressed",
    );
    assert!(
        !developers.is_empty(),
        "AdwAboutDialog developers must be non-empty so the credits-page Developers row renders the founding contributor",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_is_empty_until_translations_land() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` translator-credits slot is gated by the
    // libadwaita convention — when the value is empty,
    // `AdwAboutDialog` does NOT render the credits-page
    // "Translators" row, which is the correct rendering for an
    // app that has no translations yet. Paladin v0.2 ships
    // English-only without a gettext catalog (no `LINGUAS` /
    // `.po` files), so this helper returns the empty literal
    // until a translation lands. Once gettext is wired up, the
    // body should call `gettext("translator-credits")` so
    // translators populate the row via `.po` files; the
    // assertion here will be the canary that flags the swap.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    assert_eq!(
        format_app_about_dialog_translator_credits(),
        "",
        "AdwAboutDialog translator-credits must be empty until a gettext catalog lands so the credits-page Translators row is suppressed",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_is_single_line_when_non_empty() {
    // Defense-in-depth: once translations land and this helper
    // is wired to `gettext("translator-credits")`, a translator
    // could conceivably submit a `.po` entry with embedded
    // newlines. The dialog renders the credits row inline; an
    // embedded newline would break the layout. Asserting the
    // invariant unconditionally keeps the layout safe now and
    // when the gettext swap happens later.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let credits = format_app_about_dialog_translator_credits();
    if !credits.is_empty() {
        assert!(
            !credits.contains('\n'),
            "AdwAboutDialog translator-credits must be a single line (no embedded newlines) so the credits row layout stays intact; got {credits:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_release_notes_is_empty_until_v0_2_ships() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` release-notes slot populates the dialog's
    // "What's New" section, paired with the
    // `release-notes-version` label returned by
    // `format_app_about_dialog_release_notes_version`. Paladin
    // has not yet shipped a tagged release (the workspace is on
    // v0.0.1 pre-v0.2), so the body returns the empty literal
    // until v0.2 lands. `AdwAboutDialog` follows the libadwaita
    // convention of suppressing the "What's New" section
    // entirely when the body is empty, which is the correct
    // rendering for an app that has no release-notes copy to
    // surface yet. Once v0.2 ships the body should swap to the
    // matching release-notes markup; this assertion is the
    // canary that flags the swap so the helper is not silently
    // re-routed without also bumping
    // `format_app_about_dialog_release_notes_version` in
    // lockstep.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    assert_eq!(
        format_app_about_dialog_release_notes(),
        "",
        "AdwAboutDialog release-notes must be empty until v0.2 ships so the What's New section is suppressed",
    );
}

#[test]
fn format_app_about_dialog_release_notes_must_be_paired_with_a_non_empty_version_when_non_empty() {
    // Defense-in-depth: once the release-notes body is wired to
    // a non-empty markup string, it must be paired with a
    // matching non-empty
    // `format_app_about_dialog_release_notes_version` so the
    // "What's New" section header has a version label to render
    // beside the body. The libadwaita `release-notes-version`
    // slot is independent of the dialog's primary `version`
    // label and would be displayed as an empty string if the
    // helper returned an empty value alongside non-empty
    // release-notes markup. Pinning the invariant here keeps
    // the two helpers swap-aligned across the v0.2 cutover.
    use paladin_gtk::app::model::{
        format_app_about_dialog_release_notes, format_app_about_dialog_release_notes_version,
    };

    if !format_app_about_dialog_release_notes().is_empty() {
        assert!(
            !format_app_about_dialog_release_notes_version().is_empty(),
            "AdwAboutDialog release-notes body is non-empty so the release-notes-version label must also be non-empty for the What's New section header",
        );
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_matches_about_dialog_version() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` release-notes-version slot scopes the
    // "What's New" section that surfaces when the user opens
    // the dialog after an update. It must match the version
    // string returned by `format_app_about_dialog_version`
    // (which sources from `env!("CARGO_PKG_VERSION")` so a
    // workspace-wide version bump propagates here for free).
    // Pinning the two values to a single source of truth keeps
    // the dialog's release-notes header and the dialog's
    // version label in lockstep — a mismatch would surface
    // stale release notes to users who just upgraded.
    use paladin_gtk::app::model::{
        format_app_about_dialog_release_notes_version, format_app_about_dialog_version,
    };

    assert_eq!(
        format_app_about_dialog_release_notes_version(),
        format_app_about_dialog_version(),
        "AdwAboutDialog release-notes-version must match the dialog version label so the What's New section is scoped to the running release",
    );
}

#[test]
fn format_app_about_dialog_release_notes_version_matches_cargo_pkg_version() {
    // Defense-in-depth: the release-notes-version slot must
    // source from `env!("CARGO_PKG_VERSION")` directly (not
    // some derived or rounded value) so the workspace-wide
    // version bump propagates here without a manual update.
    // Catches an accidental hardcoded literal that drifted out
    // of sync with the workspace `[workspace.package].version`
    // field on a release.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    assert_eq!(
        format_app_about_dialog_release_notes_version(),
        env!("CARGO_PKG_VERSION"),
        "AdwAboutDialog release-notes-version must source from `env!(\"CARGO_PKG_VERSION\")` so it tracks the workspace version field",
    );
}

#[test]
fn format_app_about_dialog_debug_info_carries_program_name_version_and_app_id() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog` debug-info slot powers the dialog's
    // "Copy debug info" button — the text users paste into bug
    // reports. The minimum useful content is the program name,
    // the running version, and the reverse-DNS app ID; pinning
    // those three fields from the same single source of truth
    // helpers used by the rest of the about dialog keeps the
    // bug-report payload aligned with the dialog header / icon
    // / version slots without a drift-prone duplicate constant.
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_debug_info,
        format_app_about_dialog_program_name, format_app_about_dialog_version,
    };

    let debug = format_app_about_dialog_debug_info();
    assert!(
        debug.contains(format_app_about_dialog_program_name()),
        "AdwAboutDialog debug-info must carry the program-name display string so bug reports identify the app; got {debug:?}",
    );
    assert!(
        debug.contains(format_app_about_dialog_version()),
        "AdwAboutDialog debug-info must carry the running version so bug reports identify the release; got {debug:?}",
    );
    assert!(
        debug.contains(format_app_about_dialog_application_icon_name()),
        "AdwAboutDialog debug-info must carry the reverse-DNS app ID so bug reports identify the Flatpak / install variant; got {debug:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt() {
    // Per §"libadwaita usage" and §"About / help": the
    // `AdwAboutDialog::set_debug_info_filename` slot pins the
    // suggested filename `AdwAboutDialog` proposes in the
    // "Save debug info" file-save dialog. The libadwaita default
    // would be `<application-name>-debug-info.txt`; pinning the
    // slug `paladin` here keeps the suggested filename stable
    // even if a future `application-name` change drifts away
    // from the `paladin` slug used by the CLI / executable name.
    // The `.txt` extension matches the plain-text debug-info
    // payload built by `format_app_about_dialog_debug_info`.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    assert_eq!(
        format_app_about_dialog_debug_info_filename(),
        "paladin-debug-info.txt",
        "AdwAboutDialog debug-info filename pins the paladin slug + .txt extension matching the plain-text payload",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_is_non_empty_single_line_with_txt_extension() {
    // Defense-in-depth: the suggested filename must be a non-
    // empty single-line value with the `.txt` extension that
    // matches the plain-text payload built by
    // `format_app_about_dialog_debug_info`. A drift to e.g.
    // `.md` or `.json` would surface as a confusing file-save
    // dialog suggestion that does not match the actual payload
    // contents.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let name = format_app_about_dialog_debug_info_filename();
    assert!(
        !name.is_empty(),
        "AdwAboutDialog debug-info filename must be non-empty; got {name:?}",
    );
    assert!(
        !name.contains('\n'),
        "AdwAboutDialog debug-info filename must be a single line; got {name:?}",
    );
    assert!(
        std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt")),
        "AdwAboutDialog debug-info filename must end with `.txt` matching the plain-text payload; got {name:?}",
    );
    assert!(
        !name.contains('/') && !name.contains('\\'),
        "AdwAboutDialog debug-info filename must be a bare filename without path separators; got {name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_is_non_empty_text_with_no_trailing_whitespace() {
    // Defense-in-depth: the debug-info payload must be
    // non-empty (an empty payload would copy an empty string to
    // the clipboard on bug reports), must not have leading or
    // trailing whitespace (so paste targets render cleanly),
    // and must not embed carriage returns (LF-only newlines per
    // the GNOME stack convention).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug = format_app_about_dialog_debug_info();
    assert!(
        !debug.is_empty(),
        "AdwAboutDialog debug-info must be non-empty so the Copy debug info button hands users a usable bug-report payload",
    );
    assert!(
        !debug.starts_with(char::is_whitespace),
        "AdwAboutDialog debug-info must not start with whitespace; got {debug:?}",
    );
    assert!(
        !debug.ends_with(char::is_whitespace),
        "AdwAboutDialog debug-info must not end with whitespace; got {debug:?}",
    );
    assert!(
        !debug.contains('\r'),
        "AdwAboutDialog debug-info must use LF-only line endings (no embedded CR); got {debug:?}",
    );
}

#[test]
fn format_app_action_group_name_is_prefix_of_every_primary_menu_action() {
    // Cross-check: every `format_app_menu_*_action` target must
    // begin with `format_app_action_group_name() + "."`. This
    // catches a future rename that drifted one of the action
    // targets off the shared `app` group.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_about_action, format_app_menu_export_action,
        format_app_menu_import_action, format_app_menu_passphrase_action,
        format_app_menu_preferences_action, format_app_menu_quit_action,
    };

    let group = format_app_action_group_name();
    let prefix = format!("{group}.");
    for action in [
        format_app_menu_import_action(),
        format_app_menu_export_action(),
        format_app_menu_passphrase_action(),
        format_app_menu_preferences_action(),
        format_app_menu_about_action(),
        format_app_menu_quit_action(),
    ] {
        assert!(
            action.starts_with(&prefix),
            "primary menu action target {action:?} must start with the shared group prefix {prefix:?}",
        );
        let bare = &action[prefix.len()..];
        assert!(
            !bare.is_empty(),
            "primary menu action target {action:?} must carry a non-empty bare action name after the {prefix:?} prefix",
        );
        assert!(
            !bare.contains('.'),
            "primary menu action target {action:?} must not embed a second `.` separator after the {prefix:?} group prefix",
        );
    }
}
