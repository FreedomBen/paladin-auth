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
