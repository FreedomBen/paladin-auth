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
fn format_app_add_button_tooltip_is_non_empty() {
    // Defense-in-depth companion to
    // `format_app_add_button_tooltip_returns_add_account`: the
    // exact-value assertion catches a wholesale rename, but a
    // sibling defensive test catches the more nuanced regression
    // where someone replaces the wording with the empty string,
    // which would silently degrade the icon-only `+` button's
    // accessibility surface (screen-readers read tooltips) without
    // breaking compilation. Mirrors
    // `format_app_search_button_tooltip_is_non_empty` and
    // `format_app_menu_button_tooltip_is_non_empty` on the two
    // sibling header-bar buttons so all three icon-only
    // affordances share the same defensive coverage.
    use paladin_gtk::app::model::format_app_add_button_tooltip;

    let tooltip = format_app_add_button_tooltip();
    assert!(
        !tooltip.is_empty(),
        "header-bar add button tooltip must be non-empty so the icon-only affordance carries a screen-reader-readable label; got {tooltip:?}",
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
fn format_app_menu_preferences_accelerator_returns_control_comma() {
    // The primary menu's "Preferences" `gio::SimpleAction` is wired
    // to the `<Control>comma` keyboard accelerator per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Primary menu" — the canonical Preferences shortcut GNOME
    // applications register via
    // `gio::Application::set_accels_for_action("app.preferences",
    //  &["<Control>comma"])`. The widget binding hands this
    // accelerator string to that registration so the menu and any
    // future keyboard activation paths share one shortcut surface
    // against a single source of truth.
    //
    // Pairs with `format_app_menu_quit_accelerator` /
    // `format_app_add_button_accelerator` on the other pinned-
    // accelerator surfaces; together the trio is what a future
    // `wire_app_window_accelerators` helper iterates against
    // `[(<Control>n, app.add), (<Control>q, app.quit),
    //  (<Control>comma, app.preferences)]`.
    use paladin_gtk::app::model::format_app_menu_preferences_accelerator;

    assert_eq!(
        format_app_menu_preferences_accelerator(),
        "<Control>comma",
        "primary menu Preferences accelerator must be the gtk-rs `<Control>comma` form for `set_accels_for_action`",
    );
}

#[test]
fn format_app_menu_preferences_accelerator_is_non_empty_and_well_formed() {
    // Defensive: the accelerator string is consumed by
    // `gio::Application::set_accels_for_action`, which accepts
    // any non-empty gtk-rs accelerator spelling. An accidental
    // empty string or whitespace-leading entry would silently
    // unbind the shortcut at runtime without surfacing a
    // compile-time error — guard against that drift here so the
    // Preferences menu entry's `<Ctrl>,` shortcut stays wired.
    // Mirrors the structural assertions on
    // `format_app_add_button_accelerator_is_non_empty_and_well_formed`
    // / `format_app_menu_quit_accelerator_is_non_empty_and_well_formed`.
    use paladin_gtk::app::model::format_app_menu_preferences_accelerator;

    let accel = format_app_menu_preferences_accelerator();
    assert!(
        !accel.is_empty(),
        "accelerator must be non-empty; got {accel:?}",
    );
    assert!(
        !accel.starts_with(' ') && !accel.ends_with(' '),
        "accelerator must not have leading or trailing whitespace; got {accel:?}",
    );
    assert!(
        accel.contains('<') && accel.contains('>'),
        "accelerator must use the `<Modifier>key` form; got {accel:?}",
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
fn format_app_menu_quit_accelerator_returns_control_q() {
    // The primary menu's "Quit" `gio::SimpleAction` is wired to
    // the `<Control>q` keyboard accelerator per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Primary menu" — the canonical Quit shortcut GNOME
    // applications register via
    // `gio::Application::set_accels_for_action("app.quit",
    //  &["<Control>q"])`. The widget binding hands this
    // accelerator string to that registration so the menu and
    // any future keyboard activation paths share one shortcut
    // surface against a single source of truth.
    //
    // Mirrors `format_app_add_button_accelerator` on the header-
    // bar `+` button side; together they pin the two primary
    // keyboard surfaces (Add and Quit) against the same helper
    // shape, so a future `wire_app_window_accelerators` helper
    // can iterate `[(<Control>n, app.add), (<Control>q, app.quit), …]`
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_menu_quit_accelerator;

    assert_eq!(
        format_app_menu_quit_accelerator(),
        "<Control>q",
        "primary menu Quit accelerator must be the gtk-rs `<Control>q` form for `set_accels_for_action`",
    );
}

#[test]
fn format_app_menu_quit_accelerator_is_non_empty_and_well_formed() {
    // Defensive: the accelerator string is consumed by
    // `gio::Application::set_accels_for_action`, which accepts
    // any non-empty gtk-rs accelerator spelling. An accidental
    // empty string or whitespace-leading entry would silently
    // unbind the shortcut at runtime without surfacing a
    // compile-time error — guard against that drift here so the
    // Quit menu entry's `<Ctrl>Q` shortcut stays wired. Mirrors
    // the structural assertions on
    // `format_app_add_button_accelerator_is_non_empty_and_well_formed`.
    use paladin_gtk::app::model::format_app_menu_quit_accelerator;

    let accel = format_app_menu_quit_accelerator();
    assert!(
        !accel.is_empty(),
        "accelerator must be non-empty; got {accel:?}",
    );
    assert!(
        !accel.starts_with(' ') && !accel.ends_with(' '),
        "accelerator must not have leading or trailing whitespace; got {accel:?}",
    );
    assert!(
        accel.contains('<') && accel.contains('>'),
        "accelerator must use the `<Modifier>key` form; got {accel:?}",
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
fn format_app_add_button_accelerator_returns_control_n() {
    // The header-bar `+` button's `gio::SimpleAction` is wired
    // to the `<Control>n` keyboard accelerator per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Header bar > Add" and the existing `<Ctrl>N` docstring
    // references on `build_app_add_action` /
    // `build_app_window_action_group`. The widget binding hands
    // this accelerator string to
    // `gio::Application::set_accels_for_action(format_app_add_button_action(),
    //  &[format_app_add_button_accelerator()])` so the menu and
    // button-driven activation paths share the same shortcut
    // surface against a single source of truth. Pinning the
    // accelerator here keeps the docstring references and the
    // future wiring helper aligned without re-spelling the string
    // in two places.
    //
    // The `<Control>n` spelling is the gtk-rs `accels_for_action`
    // form (uppercase modifier in angle brackets, lowercase key
    // letter); `Primary` would also resolve on Linux but
    // `<Control>` matches the existing in-source documentation
    // (`build_app_add_action` references `<Control>n` verbatim)
    // so we keep the docstring and the helper in lockstep.
    //
    // Pure — returns a `'static str` without allocating. Sibling
    // of `format_app_add_button_action` (the fully-qualified action
    // target) and `format_app_add_button_action_name` (the bare
    // action name); together they pin the action target, its
    // bare name, and its keyboard accelerator against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_add_button_accelerator;

    assert_eq!(
        format_app_add_button_accelerator(),
        "<Control>n",
        "header-bar + button accelerator must be the gtk-rs `<Control>n` form for `set_accels_for_action`",
    );
}

#[test]
fn format_app_window_accelerator_bindings_returns_three_pinned_pairs_in_order() {
    // The application-window wiring iterates this array against
    // `gio::Application::set_accels_for_action(target, &[accel])`
    // for every pinned keyboard surface (Add, Quit, Preferences).
    // The order matches the pinned-accelerator helper sequence
    // (`format_app_add_button_accelerator`,
    //  `format_app_menu_quit_accelerator`,
    //  `format_app_menu_preferences_accelerator`) and each pair
    // sources its two slots from the matching `_accelerator` and
    // `_action` helpers so a future rename of any one helper
    // propagates through the bindings instead of drifting per-
    // entry.
    //
    // The widget binding consumes this array via a single
    // `for (accel, target) in
    //  format_app_window_accelerator_bindings()` loop, so the
    // wiring stays a single iteration over the pinned source of
    // truth instead of three hand-spelled
    // `set_accels_for_action` calls that could silently drift in
    // order or coverage.
    use paladin_gtk::app::model::{
        format_app_add_button_accelerator, format_app_add_button_action,
        format_app_menu_preferences_accelerator, format_app_menu_preferences_action,
        format_app_menu_quit_accelerator, format_app_menu_quit_action,
        format_app_window_accelerator_bindings,
    };

    let bindings = format_app_window_accelerator_bindings();
    assert_eq!(
        bindings.len(),
        3,
        "the three pinned keyboard surfaces (Add, Quit, Preferences) form the entire accelerator surface today",
    );
    assert_eq!(
        bindings[0],
        (
            format_app_add_button_accelerator(),
            format_app_add_button_action()
        ),
        "first binding must be the header-bar + button's `<Control>n` -> `app.add`",
    );
    assert_eq!(
        bindings[1],
        (
            format_app_menu_quit_accelerator(),
            format_app_menu_quit_action()
        ),
        "second binding must be the Quit menu entry's `<Control>q` -> `app.quit`",
    );
    assert_eq!(
        bindings[2],
        (
            format_app_menu_preferences_accelerator(),
            format_app_menu_preferences_action()
        ),
        "third binding must be the Preferences menu entry's `<Control>comma` -> `app.preferences`",
    );
}

#[test]
fn format_app_window_accelerator_bindings_targets_are_distinct() {
    // Defensive: `set_accels_for_action` overrides any prior
    // binding for the same target, so a duplicated target slot
    // in the bindings array would silently lose the earlier
    // accelerator without surfacing a compile-time error. Guard
    // against that drift here so the three pinned accelerator
    // surfaces (Add, Quit, Preferences) stay disjoint.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    let bindings = format_app_window_accelerator_bindings();
    let mut targets: Vec<&str> = bindings.iter().map(|(_, t)| *t).collect();
    targets.sort_unstable();
    let before_dedup = targets.len();
    targets.dedup();
    assert_eq!(
        before_dedup,
        targets.len(),
        "every action target in `format_app_window_accelerator_bindings` must be unique; got duplicates after dedup",
    );
}

#[test]
fn format_app_window_accelerator_bindings_parse_via_gtk_accelerator_parse() {
    // Every accelerator spelling returned by
    // `format_app_window_accelerator_bindings` is handed verbatim
    // to `gio::Application::set_accels_for_action`. A typo in
    // the helper — `"<Control>nn"`, `"<Ctrll>n"`, an unknown
    // keysym — would silently unbind the shortcut at runtime
    // rather than failing at compile time. Round-tripping each
    // string through `gtk4::accelerator_parse` here surfaces
    // any such drift with a concrete failure message naming
    // both the offending accelerator and the action target it
    // was paired with, so a future typo lands as a failed test
    // instead of as a silently-missing keyboard shortcut.
    //
    // `gtk4::accelerator_parse` returns `(keyval, modifiers)`
    // and produces a non-`None` result for valid spellings;
    // we treat any parse failure or `(0, _)` keyval as a typo.
    // `gtk4::init` is invoked defensively before parsing so the
    // GDK key-symbol table is loaded; CI runs under `xvfb-run`
    // and a dev environment without a display server skips the
    // assertions rather than failing (the `xvfb-run`-driven
    // `tests/gtk_smoke.rs` still covers the end-to-end
    // registration).
    use gtk4::glib::translate::IntoGlib;
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    if gtk4::init().is_err() {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
        return;
    }

    for (accel, target) in format_app_window_accelerator_bindings() {
        let parsed = gtk4::accelerator_parse(accel);
        assert!(
            parsed.is_some(),
            "accelerator {accel:?} for target {target:?} must parse via gtk::accelerator_parse",
        );
        let (keyval, _mods) = parsed.unwrap();
        assert_ne!(
            keyval.into_glib(),
            0,
            "accelerator {accel:?} for target {target:?} parsed but its keyval is 0 (unknown keysym); gtk::accelerator_parse treats unknown keysyms as a silent zero",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_are_distinct() {
    // Defensive companion to
    // `format_app_window_accelerator_bindings_targets_are_distinct`
    // on the accelerator side: two pinned surfaces sharing the
    // same accelerator (e.g. an accidental `<Control>n` on both
    // Add and Preferences) would create a runtime collision where
    // the keyboard shortcut fires whichever action gtk-rs
    // resolves second, masking the intent of the spec. The
    // assertion below catches that drift even when both
    // accelerator helpers exist and pass their individual return-
    // value checks.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    let bindings = format_app_window_accelerator_bindings();
    let mut accels: Vec<&str> = bindings.iter().map(|(a, _)| *a).collect();
    accels.sort_unstable();
    let before_dedup = accels.len();
    accels.dedup();
    assert_eq!(
        before_dedup,
        accels.len(),
        "every accelerator in `format_app_window_accelerator_bindings` must be unique; got duplicates after dedup",
    );
}

#[test]
fn wire_app_window_accelerators_signature_takes_application_reference() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application-window wiring registers every pinned
    // keyboard accelerator on the shared application via
    // `gio::Application::set_accels_for_action(target, &[accel])`
    // per `(accel, target)` pair returned by
    // `format_app_window_accelerator_bindings`. This helper
    // performs that registration in one place so the widget
    // binding does not hand-spell three `set_accels_for_action`
    // calls. The compile-only signature check below pins the
    // helper's shape — `fn(&gtk::Application)` — without
    // instantiating a second `gtk::Application` in the test
    // process (only one application instance per process is
    // permitted by glib). The `gtk::Application` parameter type
    // matches `relm4::main_application()`'s return type so the
    // widget binding can pass the shared application reference
    // directly without an explicit upcast; `adw::Application`
    // inherits from `gtk::Application` and would resolve through
    // `.upcast_ref()` if the project later switches to an
    // explicit adw application path. The end-to-end accelerator
    // registration is covered by the `xvfb-run`-driven
    // `tests/gtk_smoke.rs` mount.
    let _: fn(&gtk4::Application) = paladin_gtk::app::model::wire_app_window_accelerators;
}

#[test]
fn format_app_add_button_accelerator_is_non_empty_and_well_formed() {
    // Defensive: the accelerator string is consumed by
    // `gio::Application::set_accels_for_action`, which accepts
    // any non-empty gtk-rs accelerator spelling. An accidental
    // empty string or whitespace-leading entry would silently
    // unbind the shortcut at runtime without surfacing a
    // compile-time error — guard against that drift here so the
    // header-bar + button's `<Ctrl>N` shortcut stays wired.
    use paladin_gtk::app::model::format_app_add_button_accelerator;

    let accel = format_app_add_button_accelerator();
    assert!(
        !accel.is_empty(),
        "accelerator must be non-empty; got {accel:?}",
    );
    assert!(
        !accel.starts_with(' ') && !accel.ends_with(' '),
        "accelerator must not have leading or trailing whitespace; got {accel:?}",
    );
    assert!(
        accel.contains('<') && accel.contains('>'),
        "accelerator must use the `<Modifier>key` form; got {accel:?}",
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
#[allow(clippy::too_many_lines)]
fn build_app_about_dialog_threads_every_format_app_about_dialog_helper_through_a_setter() {
    // Per §"libadwaita usage" and §"About / help": the
    // application menu's "About Paladin" entry presents an
    // `adw::AboutDialog` whose every visible property is
    // sourced exclusively from a pinned
    // `format_app_about_dialog_*` helper. This helper builds
    // the dialog in one place so the widget binding cannot
    // accidentally bypass a format helper or hand-spell a
    // duplicate literal. The cross-check below reads each
    // property back off the dialog and asserts the value
    // matches the corresponding helper — a drift between the
    // builder and the helpers (or between the helpers and the
    // setters' actual property names) would surface here as a
    // failing assertion.
    use paladin_gtk::app::model::{
        build_app_about_dialog, format_app_about_dialog_application_icon_name,
        format_app_about_dialog_artists, format_app_about_dialog_comments,
        format_app_about_dialog_copyright, format_app_about_dialog_debug_info,
        format_app_about_dialog_debug_info_filename, format_app_about_dialog_designers,
        format_app_about_dialog_developer_name, format_app_about_dialog_developers,
        format_app_about_dialog_documenters, format_app_about_dialog_issue_url,
        format_app_about_dialog_license_type, format_app_about_dialog_program_name,
        format_app_about_dialog_release_notes, format_app_about_dialog_release_notes_version,
        format_app_about_dialog_support_url, format_app_about_dialog_translator_credits,
        format_app_about_dialog_version, format_app_about_dialog_website,
    };

    // `gtk::init` (and the libadwaita type registration it
    // performs) must run before `adw::AboutDialog::new()` will
    // construct successfully. CI installs `xvfb` (per the
    // §"Smoke test" entry of the Milestone 7 checklist) so this
    // init succeeds in CI; on a dev environment without a
    // display server we skip the assertions rather than fail —
    // the `xvfb-run`-driven `tests/gtk_smoke.rs` still covers
    // the end-to-end dialog mount.
    if gtk4::init().is_err() {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
        return;
    }

    let dialog = build_app_about_dialog();
    assert_eq!(
        dialog.application_name(),
        format_app_about_dialog_program_name(),
        "AdwAboutDialog application_name must be sourced from format_app_about_dialog_program_name",
    );
    assert_eq!(
        dialog.version(),
        format_app_about_dialog_version(),
        "AdwAboutDialog version must be sourced from format_app_about_dialog_version",
    );
    assert_eq!(
        dialog.application_icon(),
        format_app_about_dialog_application_icon_name(),
        "AdwAboutDialog application_icon must be sourced from format_app_about_dialog_application_icon_name",
    );
    assert_eq!(
        dialog.developer_name(),
        format_app_about_dialog_developer_name(),
        "AdwAboutDialog developer_name must be sourced from format_app_about_dialog_developer_name",
    );
    assert_eq!(
        dialog.copyright(),
        format_app_about_dialog_copyright(),
        "AdwAboutDialog copyright must be sourced from format_app_about_dialog_copyright",
    );
    assert_eq!(
        dialog.license_type(),
        format_app_about_dialog_license_type(),
        "AdwAboutDialog license_type must be sourced from format_app_about_dialog_license_type",
    );
    assert_eq!(
        dialog.website(),
        format_app_about_dialog_website(),
        "AdwAboutDialog website must be sourced from format_app_about_dialog_website",
    );
    assert_eq!(
        dialog.issue_url(),
        format_app_about_dialog_issue_url(),
        "AdwAboutDialog issue_url must be sourced from format_app_about_dialog_issue_url",
    );
    assert_eq!(
        dialog.support_url(),
        format_app_about_dialog_support_url(),
        "AdwAboutDialog support_url must be sourced from format_app_about_dialog_support_url",
    );
    assert_eq!(
        dialog.comments(),
        format_app_about_dialog_comments(),
        "AdwAboutDialog comments must be sourced from format_app_about_dialog_comments",
    );
    let developers_actual: Vec<String> = dialog
        .developers()
        .iter()
        .map(ToString::to_string)
        .collect();
    let developers_expected: Vec<String> = format_app_about_dialog_developers()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        developers_actual, developers_expected,
        "AdwAboutDialog developers must be sourced from format_app_about_dialog_developers",
    );
    let designers_actual: Vec<String> =
        dialog.designers().iter().map(ToString::to_string).collect();
    let designers_expected: Vec<String> = format_app_about_dialog_designers()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        designers_actual, designers_expected,
        "AdwAboutDialog designers must be sourced from format_app_about_dialog_designers",
    );
    let artists_actual: Vec<String> = dialog.artists().iter().map(ToString::to_string).collect();
    let artists_expected: Vec<String> = format_app_about_dialog_artists()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        artists_actual, artists_expected,
        "AdwAboutDialog artists must be sourced from format_app_about_dialog_artists",
    );
    let documenters_actual: Vec<String> = dialog
        .documenters()
        .iter()
        .map(ToString::to_string)
        .collect();
    let documenters_expected: Vec<String> = format_app_about_dialog_documenters()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        documenters_actual, documenters_expected,
        "AdwAboutDialog documenters must be sourced from format_app_about_dialog_documenters",
    );
    assert_eq!(
        dialog.translator_credits(),
        format_app_about_dialog_translator_credits(),
        "AdwAboutDialog translator_credits must be sourced from format_app_about_dialog_translator_credits",
    );
    assert_eq!(
        dialog.release_notes_version(),
        format_app_about_dialog_release_notes_version(),
        "AdwAboutDialog release_notes_version must be sourced from format_app_about_dialog_release_notes_version",
    );
    assert_eq!(
        dialog.release_notes(),
        format_app_about_dialog_release_notes(),
        "AdwAboutDialog release_notes must be sourced from format_app_about_dialog_release_notes",
    );
    assert_eq!(
        dialog.debug_info(),
        format_app_about_dialog_debug_info(),
        "AdwAboutDialog debug_info must be sourced from format_app_about_dialog_debug_info",
    );
    assert_eq!(
        dialog.debug_info_filename(),
        format_app_about_dialog_debug_info_filename(),
        "AdwAboutDialog debug_info_filename must be sourced from format_app_about_dialog_debug_info_filename",
    );
}

#[test]
fn format_app_add_button_visible_returns_true_when_a_vault_is_open() {
    // Per §"libadwaita usage" and §"Component tree": the
    // header-bar `+` button is hidden entirely before a vault
    // is open — `Missing` / `Locked` / `StartupError` — and
    // remains visible (but disabled) during `UnlockedBusy` so
    // the affordance does not disappear when a vault worker
    // spawns. The split matches `state.is_unlocked()` (true
    // for `Unlocked` and `UnlockedBusy`), distinct from the
    // sensitivity rule (`state.allows_mutating_menu()`, true
    // only for `Unlocked`). This helper pins the visibility
    // rule through one source of truth so the widget binding
    // does not hand-spell `state.is_unlocked()` inline.
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::format_app_add_button_visible;
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    for visible in [
        AppState::Unlocked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::UnlockedBusy {
            path: std::path::PathBuf::from("/dev/null"),
        },
    ] {
        assert!(
            format_app_add_button_visible(&visible),
            "{visible:?} must show the + button (vault is open)",
        );
    }

    for hidden in [
        AppState::Missing {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::Locked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::StartupError {
            path: None,
            error: StartupError {
                source: StartupErrorSource::PathResolution,
                kind: ErrorKind::IoError,
                rendered: String::from("resolve_failed"),
            },
        },
    ] {
        assert!(
            !format_app_add_button_visible(&hidden),
            "no-vault-open state must hide the + button per §\"libadwaita usage\"; got visible for {hidden:?}",
        );
    }
}

#[test]
fn format_app_add_button_visible_is_a_relaxation_of_format_app_add_button_sensitive() {
    // Cross-check: when the `+` button is sensitive (enabled),
    // it must also be visible — a `format_app_add_button_sensitive`
    // → `format_app_add_button_visible` implication. The
    // converse is allowed to fail (`UnlockedBusy` is visible
    // but not sensitive). A drift that inverted the implication
    // would surface a clickable `+` on a hidden button or a
    // permanently-disabled-and-hidden combination that has no
    // meaning in the §"libadwaita usage" rules.
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::{format_app_add_button_sensitive, format_app_add_button_visible};
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    for state in [
        AppState::Unlocked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::Missing {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::Locked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::UnlockedBusy {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::StartupError {
            path: None,
            error: StartupError {
                source: StartupErrorSource::PathResolution,
                kind: ErrorKind::IoError,
                rendered: String::from("resolve_failed"),
            },
        },
    ] {
        if format_app_add_button_sensitive(&state) {
            assert!(
                format_app_add_button_visible(&state),
                "format_app_add_button_sensitive returned true for {state:?} but format_app_add_button_visible returned false — every sensitive (enabled) state must also be a visible state",
            );
        }
    }
}

#[test]
fn apply_app_add_action_sensitivity_updates_existing_action_for_a_new_state() {
    // Per §"libadwaita usage" and §"Component tree": when
    // `AppModel` transitions between states (e.g. Unlocked →
    // Locked on auto-lock), the header-bar `+` button's
    // SimpleAction must toggle disabled. This helper applies
    // the new state's sensitivity to an existing action built
    // by `build_app_add_action` so the widget binding can
    // transition the affordance without re-creating the
    // action — mirrors `apply_app_primary_menu_sensitivities`
    // for the primary menu's mutating entries.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        apply_app_add_action_sensitivity, build_app_add_action, format_app_add_button_sensitive,
    };
    use paladin_gtk::app::state::AppState;

    let initial = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let action = build_app_add_action(&initial);
    assert!(
        action.is_enabled(),
        "initial Unlocked state must construct the Add action enabled per format_app_add_button_sensitive",
    );

    let next = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_add_action_sensitivity(&action, &next);
    assert_eq!(
        action.is_enabled(),
        format_app_add_button_sensitive(&next),
        "apply_app_add_action_sensitivity must apply format_app_add_button_sensitive for the new state",
    );
    assert!(
        !action.is_enabled(),
        "Locked state must disable the Add affordance per §\"libadwaita usage\"",
    );

    // Re-applying for Unlocked must re-enable the action so
    // the helper round-trips cleanly across state transitions.
    apply_app_add_action_sensitivity(&action, &initial);
    assert!(
        action.is_enabled(),
        "re-applying Unlocked state must re-enable the Add affordance via apply_app_add_action_sensitivity",
    );
}

#[test]
fn format_app_window_action_names_lists_the_six_primary_menu_entries_then_add() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application's `app` action group bundles the six
    // primary-menu bare action names (Import, Export,
    // Passphrase, Preferences, About, Quit) with the
    // header-bar `+` button's bare Add action name. This
    // helper returns all seven names in a fixed-size array so
    // the widget binding can iterate without allocating a
    // `Vec` per `init` call. The pinned order keeps the menu
    // entries first (matching the §"libadwaita usage" sequence)
    // and appends Add at the end so callers walking the array
    // can stop at index 5 for menu-only loops and the full
    // length for action-group loops.
    use paladin_gtk::app::model::{
        format_app_add_button_action_name, format_app_primary_menu_action_names,
        format_app_window_action_names,
    };

    let combined = format_app_window_action_names();
    let menu = format_app_primary_menu_action_names();
    let add = format_app_add_button_action_name();

    assert_eq!(
        combined.len(),
        menu.len() + 1,
        "format_app_window_action_names must return exactly one entry per primary menu action plus the Add action",
    );
    for (idx, name) in menu.iter().enumerate() {
        assert_eq!(
            combined[idx], *name,
            "format_app_window_action_names[{idx}] must match format_app_primary_menu_action_names[{idx}] in pinned order",
        );
    }
    assert_eq!(
        combined[menu.len()],
        add,
        "format_app_window_action_names must end with format_app_add_button_action_name",
    );
}

#[test]
fn dispatch_app_window_action_routes_add_to_open_add_dialog() {
    // Per §"libadwaita usage" and §"Component tree": the
    // header-bar `+` button's `"app.add"` activation
    // dispatches `AppMsg::OpenAddDialog`, whose handler
    // mounts a fresh `AddAccountComponent` seeded with the
    // resolved vault path. Routing the activation through the
    // shared `dispatch_app_window_action` table means the
    // button can use `gtk::Button::set_action_name("app.add")`
    // and inherit its enabled state from the SimpleAction,
    // instead of hand-spelling a `connect_clicked` handler
    // that bypasses the action group.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_add_button_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_add_button_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenAddDialog)),
        "dispatch_app_window_action must route the add bare action name to AppMsg::OpenAddDialog; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_routes_about_to_open_about_dialog() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's bare action names (`format_app_menu_*_action_name`)
    // are routed to `AppMsg` variants through a single dispatch
    // table so the widget binding's `connect_activate` handlers
    // share one source of truth. Activating the `"about"` action
    // dispatches `AppMsg::OpenAboutDialog`, whose handler
    // presents the `adw::AboutDialog` built by
    // `build_app_about_dialog`.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_about_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_about_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenAboutDialog)),
        "dispatch_app_window_action must route the about bare action name to AppMsg::OpenAboutDialog; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_routes_quit_to_quit() {
    // Per §"libadwaita usage": the application menu's Quit
    // entry dispatches `AppMsg::Quit`, whose handler tears
    // down the GTK main loop through
    // `relm4::main_application().quit()`. Quit is always
    // enabled, so this dispatch can arrive in every state.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_quit_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_quit_action_name());
    assert!(
        matches!(msg, Some(AppMsg::Quit)),
        "dispatch_app_window_action must route the quit bare action name to AppMsg::Quit; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_routes_preferences_to_open_preferences_dialog() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Preferences entry mounts the
    // `SettingsComponent` (an `AdwPreferencesDialog` exposing
    // the §4.7 auto-lock / clipboard-clear toggles + spinners).
    // The activation flows through `AppMsg::OpenPreferencesDialog`
    // so the widget binding wires `connect_activate` on the
    // `"preferences"` SimpleAction to
    // `sender.input(AppMsg::OpenPreferencesDialog)` and `update`
    // handles the variant by presenting the dialog parented at
    // the active `adw::ApplicationWindow`.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_preferences_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_preferences_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenPreferencesDialog)),
        "dispatch_app_window_action must route the preferences bare action name to AppMsg::OpenPreferencesDialog; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_routes_import_to_open_import_dialog() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Import entry mounts the
    // `ImportDialogComponent` (file picker + format +
    // on-conflict + bundle passphrase). The activation flows
    // through `AppMsg::OpenImportDialog` so the widget binding
    // wires `connect_activate` on the `"import"` SimpleAction
    // to `sender.input(AppMsg::OpenImportDialog)` and `update`
    // handles the variant by mounting the dialog parented at
    // the active `adw::ApplicationWindow`.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_import_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_import_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenImportDialog)),
        "dispatch_app_window_action must route the import bare action name to AppMsg::OpenImportDialog; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_routes_export_to_open_export_dialog() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Export entry mounts the
    // `ExportDialogComponent` (file picker + format +
    // overwrite + encrypted passphrase). The activation flows
    // through `AppMsg::OpenExportDialog` so the widget binding
    // wires `connect_activate` on the `"export"` SimpleAction
    // to `sender.input(AppMsg::OpenExportDialog)` and `update`
    // handles the variant by mounting the dialog parented at
    // the active `adw::ApplicationWindow`.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_export_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_export_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenExportDialog)),
        "dispatch_app_window_action must route the export bare action name to AppMsg::OpenExportDialog; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_routes_passphrase_to_open_passphrase_dialog() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Passphrase entry mounts the
    // `PassphraseDialogComponent` (set / change / remove
    // sub-flows). The activation flows through
    // `AppMsg::OpenPassphraseDialog` so the widget binding
    // wires `connect_activate` on the `"passphrase"`
    // SimpleAction to
    // `sender.input(AppMsg::OpenPassphraseDialog)` and `update`
    // handles the variant by mounting the dialog parented at
    // the active `adw::ApplicationWindow`.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_passphrase_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_passphrase_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenPassphraseDialog)),
        "dispatch_app_window_action must route the passphrase bare action name to AppMsg::OpenPassphraseDialog; got {msg:?}",
    );
}

#[test]
fn dispatch_app_window_action_covers_every_bundled_action_name() {
    // Defense-in-depth: every bare action name registered on
    // the application's `app` action group (via
    // `build_app_window_action_group`) must dispatch to a
    // concrete `AppMsg` variant. With every menu entry now
    // wired, the pending-set is empty; a future commit that
    // adds a new action to `format_app_window_action_names`
    // without also updating `dispatch_app_window_action` will
    // surface here as a failing assertion.
    use paladin_gtk::app::model::{dispatch_app_window_action, format_app_window_action_names};

    for name in format_app_window_action_names() {
        let dispatched = dispatch_app_window_action(name);
        assert!(
            dispatched.is_some(),
            "bundled action {name:?} must dispatch to a concrete AppMsg variant through dispatch_app_window_action",
        );
    }
}

#[test]
fn dispatch_app_window_action_returns_none_for_unknown_action_names() {
    // Defense-in-depth: a stray activation from a future
    // refactor that introduced an action name not yet covered
    // by the dispatch table must be a benign no-op rather than
    // a panic. The `connect_activate` handler discards the
    // `None` return without posting an AppMsg.
    use paladin_gtk::app::model::dispatch_app_window_action;

    assert!(
        dispatch_app_window_action("unknown_action").is_none(),
        "dispatch_app_window_action must return None for unknown bare action names",
    );
    assert!(
        dispatch_app_window_action("").is_none(),
        "dispatch_app_window_action must return None for the empty action name",
    );
}

#[test]
fn app_msg_carries_open_about_dialog_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's "About Paladin" entry mounts an
    // `adw::AboutDialog` built by `build_app_about_dialog`.
    // The activation flows through `AppMsg::OpenAboutDialog`
    // so the widget binding wires `connect_activate` on the
    // `"about"` SimpleAction to `sender.input(AppMsg::OpenAboutDialog)`
    // and `update` handles the variant by presenting the
    // dialog parented at the active `adw::ApplicationWindow`.
    // The compile-only check below pins the variant exists
    // and carries no payload so the action wiring can post it
    // without constructor arguments.
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::OpenAboutDialog;
}

#[test]
fn app_msg_carries_open_preferences_dialog_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Preferences entry mounts the
    // `SettingsComponent` (an `AdwPreferencesDialog` exposing
    // the §4.7 auto-lock / clipboard-clear toggles + spinners).
    // The activation flows through `AppMsg::OpenPreferencesDialog`
    // so the widget binding wires `connect_activate` on the
    // `"preferences"` SimpleAction to
    // `sender.input(AppMsg::OpenPreferencesDialog)` and `update`
    // handles the variant by presenting the dialog parented at
    // the active `adw::ApplicationWindow`. The compile-only
    // check below pins the variant exists and carries no
    // payload so the action wiring can post it without
    // constructor arguments.
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::OpenPreferencesDialog;
}

#[test]
fn app_msg_carries_open_import_dialog_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Import entry mounts the
    // `ImportDialogComponent` (file picker + format +
    // on-conflict + bundle passphrase). The activation flows
    // through `AppMsg::OpenImportDialog` so the widget binding
    // wires `connect_activate` on the `"import"` SimpleAction
    // to `sender.input(AppMsg::OpenImportDialog)` and `update`
    // handles the variant by mounting the dialog parented at
    // the active `adw::ApplicationWindow`. The compile-only
    // check below pins the variant exists and carries no
    // payload so the action wiring can post it without
    // constructor arguments.
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::OpenImportDialog;
}

#[test]
fn app_msg_carries_open_export_dialog_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Export entry mounts the
    // `ExportDialogComponent` (file picker + format +
    // overwrite + encrypted passphrase). The activation flows
    // through `AppMsg::OpenExportDialog` so the widget binding
    // wires `connect_activate` on the `"export"` SimpleAction
    // to `sender.input(AppMsg::OpenExportDialog)` and `update`
    // handles the variant by mounting the dialog parented at
    // the active `adw::ApplicationWindow`. The compile-only
    // check below pins the variant exists and carries no
    // payload so the action wiring can post it without
    // constructor arguments.
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::OpenExportDialog;
}

#[test]
fn app_msg_carries_open_passphrase_dialog_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Passphrase entry mounts the
    // `PassphraseDialogComponent` (set / change / remove
    // sub-flows). The activation flows through
    // `AppMsg::OpenPassphraseDialog` so the widget binding
    // wires `connect_activate` on the `"passphrase"`
    // SimpleAction to
    // `sender.input(AppMsg::OpenPassphraseDialog)` and `update`
    // handles the variant by mounting the dialog parented at
    // the active `adw::ApplicationWindow`. The compile-only
    // check below pins the variant exists and carries no
    // payload so the action wiring can post it without
    // constructor arguments.
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::OpenPassphraseDialog;
}

#[test]
fn wire_app_window_action_activations_signature_takes_group_and_input_sender() {
    // Per §"libadwaita usage" and §"Component tree": every
    // SimpleAction on the bundled action group routes its
    // activation through `dispatch_app_window_action` to a
    // concrete `AppMsg` variant. This helper installs the
    // `connect_activate` closures for every action returned
    // by `format_app_window_action_names`, sharing one
    // dispatch path across the seven actions so the widget
    // binding does not hand-spell the per-action closures in
    // `init`. The compile-only signature check below pins the
    // helper's shape — `fn(&gio::SimpleActionGroup,
    // relm4::Sender<AppMsg>)` — without instantiating a real
    // action group + relm4 sender in the test process; the
    // dispatch table coverage is pinned by
    // `dispatch_app_window_action_covers_every_bundled_action_name`.
    use paladin_gtk::app::model::{wire_app_window_action_activations, AppMsg};

    let _: fn(&libadwaita::gio::SimpleActionGroup, &relm4::Sender<AppMsg>) =
        wire_app_window_action_activations;
}

#[test]
fn wire_app_window_action_group_signature_takes_application_window_and_action_group() {
    // Per §"libadwaita usage" and §"Component tree": the
    // `app` action group built by
    // `build_app_window_action_group` is inserted on the root
    // [`adw::ApplicationWindow`] via
    // `insert_action_group(format_app_action_group_name(),
    // Some(&group))` so the menu targets spelled by
    // `format_app_primary_menu_entries` (`"app.import"`,
    // `"app.export"`, …, `"app.quit"`) and the header-bar
    // `+` button's `"app.add"` target all resolve through one
    // group inserted on the window. The compile-only signature
    // check here pins the helper's shape —
    // `fn(&adw::ApplicationWindow, &gio::SimpleActionGroup)` —
    // so the caller can wire each action's `connect_activate`
    // handler against the group reference before insert
    // without re-walking the inserted group. The `gtk_smoke.rs`
    // `xvfb-run` smoke test covers the end-to-end action-group
    // insertion by mounting the full `AppModel`, while the
    // per-action wiring is pinned by
    // `build_app_window_action_group_bundles_primary_actions_and_add_action`.
    let _: fn(&libadwaita::ApplicationWindow, &libadwaita::gio::SimpleActionGroup) =
        paladin_gtk::app::model::wire_app_window_action_group;
}

#[test]
fn wire_app_menu_button_menu_model_signature_takes_menu_button_reference() {
    // Per §"libadwaita usage" and §"Component tree": the
    // header-bar primary menu (`gtk::MenuButton` driven by
    // `gio::Menu`) carries the six pinned entries (Import,
    // Export, Passphrase, Preferences, About Paladin, Quit).
    // This helper attaches the menu model returned by
    // `build_app_primary_menu_model` to a
    // [`gtk::MenuButton::set_menu_model`] target so the widget
    // binding does not hand-spell a duplicate construction of
    // the menu in `init`. The compile-only signature check
    // here pins the helper's shape — `fn(&gtk::MenuButton)` —
    // without instantiating a second `gtk::MenuButton` widget
    // in the test process (creating multiple GTK widgets
    // across sibling tests in this binary destabilizes the
    // GTK type registration). The `gtk_smoke.rs` `xvfb-run`
    // smoke test covers the end-to-end menu model attachment
    // by mounting the full `AppModel`, while the per-item
    // wiring is pinned by
    // `build_app_primary_menu_model_appends_every_format_app_primary_menu_entries_pair`.
    let _: fn(&gtk4::MenuButton) = paladin_gtk::app::model::wire_app_menu_button_menu_model;
}

#[test]
fn apply_app_add_button_sensitive_updates_existing_button_for_a_new_state() {
    // Per §"libadwaita usage" and §"Component tree": when
    // `AppModel` transitions between states (e.g. Unlocked →
    // UnlockedBusy on a vault worker spawn), the header-bar
    // `+` button must toggle disabled even though it stays
    // visible. This helper applies the new state's sensitivity
    // to an existing `gtk::Button` so the widget binding can
    // transition the affordance without re-creating the button
    // — sibling of `apply_app_add_button_visibility` on the
    // visibility side and `apply_app_add_action_sensitivity`
    // for the SimpleAction companion.
    use libadwaita::prelude::*;
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::{
        apply_app_add_button_sensitive, format_app_add_button_sensitive,
    };
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    if gtk4::init().is_err() {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
        return;
    }

    let button = gtk4::Button::new();
    // Pre-set the button to the opposite of the starting
    // expectation so the assertion proves the helper applies
    // the rule rather than reading whatever the constructor
    // happened to default to.
    button.set_sensitive(false);

    let unlocked = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_add_button_sensitive(&button, &unlocked);
    assert_eq!(
        button.is_sensitive(),
        format_app_add_button_sensitive(&unlocked),
        "apply_app_add_button_sensitive must apply format_app_add_button_sensitive for the Unlocked state",
    );
    assert!(
        button.is_sensitive(),
        "Unlocked state must enable the + button per §\"libadwaita usage\"",
    );

    // Transitioning to UnlockedBusy (vault worker in flight)
    // must disable the affordance even though the button
    // stays visible — `format_app_add_button_visible`
    // continues to return true for `UnlockedBusy`.
    let busy = AppState::UnlockedBusy {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_add_button_sensitive(&button, &busy);
    assert_eq!(
        button.is_sensitive(),
        format_app_add_button_sensitive(&busy),
        "apply_app_add_button_sensitive must apply format_app_add_button_sensitive for the UnlockedBusy state",
    );
    assert!(
        !button.is_sensitive(),
        "UnlockedBusy state must disable the + button per §\"libadwaita usage\"",
    );

    // Locked / Missing / StartupError must also disable the
    // affordance per the four-non-Unlocked-states rule.
    for non_unlocked in [
        AppState::Locked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::Missing {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::StartupError {
            path: None,
            error: StartupError {
                source: StartupErrorSource::PathResolution,
                kind: ErrorKind::IoError,
                rendered: String::from("resolve_failed"),
            },
        },
    ] {
        apply_app_add_button_sensitive(&button, &non_unlocked);
        assert_eq!(
            button.is_sensitive(),
            format_app_add_button_sensitive(&non_unlocked),
            "apply_app_add_button_sensitive must apply format_app_add_button_sensitive for {non_unlocked:?}",
        );
        assert!(
            !button.is_sensitive(),
            "{non_unlocked:?} must disable the + button per §\"libadwaita usage\"",
        );
    }

    // Re-applying for Unlocked must re-enable the button so
    // the helper round-trips cleanly across state transitions.
    apply_app_add_button_sensitive(&button, &unlocked);
    assert!(
        button.is_sensitive(),
        "re-applying Unlocked state must re-enable the + button via apply_app_add_button_sensitive",
    );
}

#[test]
fn apply_app_add_button_visibility_updates_existing_button_for_a_new_state() {
    // Per §"libadwaita usage" and §"Component tree": when
    // `AppModel` transitions between states (e.g. Unlocked →
    // Locked on auto-lock, or Locked → Unlocked after a
    // successful unlock), the header-bar `+` button's
    // visibility must toggle accordingly — visible when a
    // vault is open (`Unlocked` / `UnlockedBusy`) and hidden
    // otherwise (`Missing` / `Locked` / `StartupError`). This
    // helper applies the new state's visibility to an existing
    // `gtk::Button` so the widget binding can transition the
    // affordance without re-creating the button — mirrors
    // `apply_app_add_action_sensitivity` on the
    // sensitivity-update side and
    // `apply_app_primary_menu_sensitivities` for the primary
    // menu's mutating entries.
    use libadwaita::prelude::*;
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::{apply_app_add_button_visibility, format_app_add_button_visible};
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    // `gtk::init` must run before `gtk::Button::new` will
    // construct successfully. On dev environments without a
    // display server we skip rather than fail — CI runs under
    // `xvfb-run` per the Milestone 7 checklist.
    if gtk4::init().is_err() {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
        return;
    }

    let button = gtk4::Button::new();
    // Pre-set the button to the opposite of the starting
    // expectation so the assertion proves the helper applies
    // the rule rather than reading whatever the constructor
    // happened to default to.
    button.set_visible(false);

    let unlocked = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_add_button_visibility(&button, &unlocked);
    assert_eq!(
        button.is_visible(),
        format_app_add_button_visible(&unlocked),
        "apply_app_add_button_visibility must apply format_app_add_button_visible for the Unlocked state",
    );
    assert!(
        button.is_visible(),
        "Unlocked state must show the + button per §\"libadwaita usage\"",
    );

    // Transitioning to Locked (auto-lock) must hide the
    // affordance so users cannot trigger an OpenAddDialog race
    // against a locked vault.
    let locked = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_add_button_visibility(&button, &locked);
    assert_eq!(
        button.is_visible(),
        format_app_add_button_visible(&locked),
        "apply_app_add_button_visibility must apply format_app_add_button_visible for the Locked state",
    );
    assert!(
        !button.is_visible(),
        "Locked state must hide the + button per §\"libadwaita usage\"",
    );

    // UnlockedBusy keeps the affordance visible (but disabled
    // — see apply_app_add_action_sensitivity) so the surface
    // does not re-flow when a vault worker spawns.
    let busy = AppState::UnlockedBusy {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_add_button_visibility(&button, &busy);
    assert_eq!(
        button.is_visible(),
        format_app_add_button_visible(&busy),
        "apply_app_add_button_visibility must apply format_app_add_button_visible for the UnlockedBusy state",
    );
    assert!(
        button.is_visible(),
        "UnlockedBusy state must keep the + button visible per §\"libadwaita usage\"",
    );

    // StartupError must hide the affordance — there is no
    // vault path open to add an account into.
    let errored = AppState::StartupError {
        path: None,
        error: StartupError {
            source: StartupErrorSource::PathResolution,
            kind: ErrorKind::IoError,
            rendered: String::from("resolve_failed"),
        },
    };
    apply_app_add_button_visibility(&button, &errored);
    assert_eq!(
        button.is_visible(),
        format_app_add_button_visible(&errored),
        "apply_app_add_button_visibility must apply format_app_add_button_visible for the StartupError state",
    );
    assert!(
        !button.is_visible(),
        "StartupError state must hide the + button per §\"libadwaita usage\"",
    );
}

#[test]
fn build_app_add_action_registers_add_with_pinned_sensitivity() {
    // Per §"libadwaita usage" and §"Component tree": the
    // header-bar `+` button's
    // [`gtk::Button::set_action_name`] target `"app.add"`
    // resolves through a parameter-less `gio::SimpleAction`
    // registered on the `app` action group. This helper
    // constructs that action from the pinned
    // `format_app_add_button_action_name` (the bare name
    // `"add"`) with the sensitivity returned by
    // `format_app_add_button_sensitive` for the supplied state.
    // Centralizing the construction in one helper means the
    // bare action name, its parameter shape, and its
    // sensitivity rule stay sourced exclusively from the
    // pinned helpers — a drift between the widget binding and
    // the format helpers cannot survive because the widget
    // reads the action through this single entry point.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        build_app_add_action, format_app_add_button_action_name, format_app_add_button_sensitive,
    };
    use paladin_gtk::app::state::AppState;

    let state = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let action = build_app_add_action(&state);
    assert_eq!(
        action.name().as_str(),
        format_app_add_button_action_name(),
        "build_app_add_action must register the bare action name returned by format_app_add_button_action_name",
    );
    assert!(
        action.parameter_type().is_none(),
        "Add action must take no parameter so the `app.add` menu / button target resolves through gio::SimpleAction::new(name, None)",
    );
    assert_eq!(
        action.is_enabled(),
        format_app_add_button_sensitive(&state),
        "build_app_add_action must apply format_app_add_button_sensitive to the constructed SimpleAction",
    );
}

#[test]
fn build_app_add_action_disables_in_non_unlocked_states() {
    // Defense-in-depth: the `+` Add affordance must be disabled
    // in every state except `Unlocked` per §"libadwaita usage"
    // — mirrors the four mutating primary-menu entries
    // (Import, Export, Passphrase, Preferences). Catches a
    // future bundling change that accidentally inverted the
    // sensitivity rule for the Add action.
    use libadwaita::prelude::*;
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::build_app_add_action;
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    for non_unlocked in [
        AppState::Missing {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::Locked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::StartupError {
            path: None,
            error: StartupError {
                source: StartupErrorSource::PathResolution,
                kind: ErrorKind::IoError,
                rendered: String::from("resolve_failed"),
            },
        },
    ] {
        let action = build_app_add_action(&non_unlocked);
        assert!(
            !action.is_enabled(),
            "build_app_add_action must disable the Add affordance outside Unlocked state; got enabled for {non_unlocked:?}",
        );
    }
}

#[test]
fn build_app_window_action_group_bundles_primary_actions_and_add_action() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application's `app` action group is the single group
    // inserted on the `adw::ApplicationWindow` via
    // `insert_action_group(format_app_action_group_name(),
    // Some(&group))`. It carries every menu target spelled by
    // `format_app_primary_menu_entries` (`"app.import"`,
    // `"app.export"`, …, `"app.quit"`) plus the header-bar
    // `+` button's `"app.add"` target so the `<Ctrl>N`
    // accelerator wired via
    // `gio::Application::set_accels_for_action("app.add",
    // &["<Control>n"])` resolves through this group.
    // Centralizing the construction in one helper means the
    // widget binding inserts a single group rather than two
    // (or hand-spelling the action names) so the bare action
    // names, parameter shapes, and sensitivity rules stay
    // sourced exclusively from the pinned helpers.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        build_app_window_action_group, format_app_add_button_action_name,
        format_app_add_button_sensitive, format_app_primary_menu_action_names,
        format_app_primary_menu_action_sensitivities,
    };
    use paladin_gtk::app::state::AppState;

    let state = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let group = build_app_window_action_group(&state);

    // Every primary menu action must be present with the
    // pinned sensitivity and no parameter shape.
    let names = format_app_primary_menu_action_names();
    let expected_sensitivities = format_app_primary_menu_action_sensitivities(&state);
    for (idx, name) in names.iter().enumerate() {
        let action = group
            .lookup_action(name)
            .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
            .unwrap_or_else(|| {
                panic!(
                    "build_app_window_action_group must register primary menu action {name:?}; missing at slot {idx}"
                )
            });
        assert_eq!(
            action.is_enabled(),
            expected_sensitivities[idx],
            "build_app_window_action_group must apply format_app_primary_menu_action_sensitivities[{idx}] to action {name:?}",
        );
        assert!(
            action.parameter_type().is_none(),
            "primary menu action {name:?} must take no parameter so the menu target `app.{name}` resolves through gio::SimpleAction::new(name, None)",
        );
    }

    // The Add action must be present with the pinned
    // sensitivity and no parameter shape, sharing the same
    // group as the menu actions so `app.add` resolves through
    // the single inserted action group.
    let add_name = format_app_add_button_action_name();
    let add_action = group
        .lookup_action(add_name)
        .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
        .expect(
            "build_app_window_action_group must register the Add action named format_app_add_button_action_name",
        );
    assert_eq!(
        add_action.is_enabled(),
        format_app_add_button_sensitive(&state),
        "build_app_window_action_group must apply format_app_add_button_sensitive to the Add action",
    );
    assert!(
        add_action.parameter_type().is_none(),
        "Add action must take no parameter so the `app.add` target resolves through gio::SimpleAction::new(name, None)",
    );
}

#[test]
fn build_app_window_action_group_disables_mutating_actions_in_non_unlocked_states() {
    // Defense-in-depth: the four mutating menu actions
    // (Import, Export, Passphrase, Preferences) and the Add
    // action must be disabled in every state except `Unlocked`
    // per §"libadwaita usage". About and Quit stay enabled
    // everywhere. Catches a future bundling change that
    // accidentally inverted the sensitivity rule for any of
    // the seven actions.
    use libadwaita::prelude::*;
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::{
        build_app_window_action_group, format_app_add_button_action_name,
        format_app_menu_about_action_name, format_app_menu_export_action_name,
        format_app_menu_import_action_name, format_app_menu_passphrase_action_name,
        format_app_menu_preferences_action_name, format_app_menu_quit_action_name,
    };
    use paladin_gtk::app::state::AppState;
    use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

    for non_unlocked in [
        AppState::Missing {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::Locked {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::UnlockedBusy {
            path: std::path::PathBuf::from("/dev/null"),
        },
        AppState::StartupError {
            path: None,
            error: StartupError {
                source: StartupErrorSource::PathResolution,
                kind: ErrorKind::IoError,
                rendered: String::from("resolve_failed"),
            },
        },
    ] {
        let group = build_app_window_action_group(&non_unlocked);
        for mutating_name in [
            format_app_menu_import_action_name(),
            format_app_menu_export_action_name(),
            format_app_menu_passphrase_action_name(),
            format_app_menu_preferences_action_name(),
            format_app_add_button_action_name(),
        ] {
            let action = group
                .lookup_action(mutating_name)
                .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
                .expect("mutating action registered");
            assert!(
                !action.is_enabled(),
                "build_app_window_action_group must disable mutating action {mutating_name:?} outside Unlocked state; got enabled for {non_unlocked:?}",
            );
        }
        for always_enabled in [
            format_app_menu_about_action_name(),
            format_app_menu_quit_action_name(),
        ] {
            let action = group
                .lookup_action(always_enabled)
                .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
                .expect("always-enabled action registered");
            assert!(
                action.is_enabled(),
                "build_app_window_action_group must keep action {always_enabled:?} enabled in {non_unlocked:?}",
            );
        }
    }
}

#[test]
fn apply_app_window_action_group_sensitivities_updates_every_action_for_a_new_state() {
    // Per §"libadwaita usage" and §"Component tree": when
    // `AppModel` transitions between states, every action on
    // the bundled `app` action group must toggle to the new
    // state's sensitivity in one call. This helper applies
    // both the four mutating primary-menu sensitivities
    // (Import, Export, Passphrase, Preferences) and the Add
    // action's sensitivity against an existing group built by
    // `build_app_window_action_group` so the widget binding
    // can transition every gated affordance through one entry
    // point — mirrors `build_app_window_action_group` on the
    // runtime-update side.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        apply_app_window_action_group_sensitivities, build_app_window_action_group,
        format_app_add_button_action_name, format_app_add_button_sensitive,
        format_app_primary_menu_action_names, format_app_primary_menu_action_sensitivities,
    };
    use paladin_gtk::app::state::AppState;

    let initial = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let group = build_app_window_action_group(&initial);
    let next = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_window_action_group_sensitivities(&group, &next);

    // Every primary menu action must reflect the new state's
    // pinned sensitivities.
    let names = format_app_primary_menu_action_names();
    let expected = format_app_primary_menu_action_sensitivities(&next);
    for (idx, name) in names.iter().enumerate() {
        let action = group
            .lookup_action(name)
            .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
            .expect("primary menu action registered");
        assert_eq!(
            action.is_enabled(),
            expected[idx],
            "apply_app_window_action_group_sensitivities must apply format_app_primary_menu_action_sensitivities[{idx}] to action {name:?} for the new state",
        );
    }

    // The Add action must also reflect the new state's
    // pinned sensitivity.
    let add_name = format_app_add_button_action_name();
    let add_action = group
        .lookup_action(add_name)
        .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
        .expect("add action registered");
    assert_eq!(
        add_action.is_enabled(),
        format_app_add_button_sensitive(&next),
        "apply_app_window_action_group_sensitivities must apply format_app_add_button_sensitive to the Add action for the new state",
    );

    // Re-applying for Unlocked must re-enable every action so
    // the helper round-trips cleanly across state transitions.
    apply_app_window_action_group_sensitivities(&group, &initial);
    let expected_initial = format_app_primary_menu_action_sensitivities(&initial);
    for (idx, name) in names.iter().enumerate() {
        let action = group
            .lookup_action(name)
            .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
            .expect("primary menu action registered");
        assert_eq!(
            action.is_enabled(),
            expected_initial[idx],
            "re-applying Unlocked state must restore the menu action {name:?} sensitivity",
        );
    }
    let add_action = group
        .lookup_action(add_name)
        .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
        .expect("add action registered");
    assert_eq!(
        add_action.is_enabled(),
        format_app_add_button_sensitive(&initial),
        "re-applying Unlocked state must re-enable the Add action via apply_app_window_action_group_sensitivities",
    );
}

#[test]
fn apply_app_window_action_group_sensitivities_is_a_noop_on_missing_actions() {
    // Defense-in-depth: if the widget binding hands a group
    // that does not contain every bundled action (e.g. a
    // future refactor that splits the actions across two
    // groups), the helper must skip the missing actions
    // silently rather than panic. The
    // build_app_window_action_group test surface already
    // asserts the canonical group has every action, so the
    // noop-on-missing behaviour here keeps the runtime path
    // resilient to a future bundling change.
    use paladin_gtk::app::model::apply_app_window_action_group_sensitivities;
    use paladin_gtk::app::state::AppState;

    let empty = libadwaita::gio::SimpleActionGroup::new();
    let state = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_window_action_group_sensitivities(&empty, &state);
    // The empty group still has no actions; the call did not panic.
}

#[test]
fn apply_app_primary_menu_sensitivities_updates_existing_group_for_a_new_state() {
    // Per §"libadwaita usage" and §"Component tree": when
    // `AppModel` transitions between states (e.g. Unlocked →
    // Locked on auto-lock, or Unlocked → UnlockedBusy when a
    // vault worker spawns), the four mutating primary-menu
    // entries (Import, Export, Passphrase, Preferences) must
    // toggle disabled and the About / Quit entries stay
    // enabled. This helper applies the new state's
    // sensitivities to an existing action group built by
    // `build_app_primary_action_group` so the widget binding
    // can transition the menu without re-creating the group.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        apply_app_primary_menu_sensitivities, build_app_primary_action_group,
        format_app_primary_menu_action_names, format_app_primary_menu_action_sensitivities,
    };
    use paladin_gtk::app::state::AppState;

    let initial = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let group = build_app_primary_action_group(&initial);
    let next = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_primary_menu_sensitivities(&group, &next);

    let names = format_app_primary_menu_action_names();
    let expected = format_app_primary_menu_action_sensitivities(&next);
    for (idx, name) in names.iter().enumerate() {
        let action = group
            .lookup_action(name)
            .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
            .expect("action registered by build_app_primary_action_group");
        assert_eq!(
            action.is_enabled(),
            expected[idx],
            "apply_app_primary_menu_sensitivities must apply format_app_primary_menu_action_sensitivities[{idx}] to action {name:?} for the new state",
        );
    }
}

#[test]
fn apply_app_primary_menu_sensitivities_is_a_noop_on_missing_actions() {
    // Defense-in-depth: if the widget binding hands a group
    // that does not contain every primary-menu action (e.g. a
    // future refactor that splits the menu actions across two
    // groups), the helper must skip the missing actions
    // silently rather than panic. The
    // build_app_primary_action_group test surface already
    // asserts the canonical group has every action, so the
    // noop-on-missing behaviour here keeps the runtime path
    // resilient to a future bundling change.
    use paladin_gtk::app::model::apply_app_primary_menu_sensitivities;
    use paladin_gtk::app::state::AppState;

    let empty = libadwaita::gio::SimpleActionGroup::new();
    let state = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    apply_app_primary_menu_sensitivities(&empty, &state);
    // The empty group still has no actions; the call did not panic.
}

#[test]
fn build_app_primary_action_group_registers_every_action_name_with_pinned_sensitivity() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application's `app` action group is constructed from the
    // pinned `format_app_primary_menu_action_names` array (the
    // bare action names) and applies the per-entry sensitivity
    // returned by `format_app_primary_menu_action_sensitivities`
    // for the supplied `state`. Centralizing the action-group
    // construction in one helper means the bare action names,
    // their parameter shape (no parameter), and their
    // sensitivity rule stay sourced exclusively from the pinned
    // helpers — a drift between the widget binding and the
    // `format_app_menu_*_action_name` /
    // `format_app_primary_menu_action_sensitivities` helpers
    // cannot survive because the widget reads the group through
    // this single entry point.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        build_app_primary_action_group, format_app_primary_menu_action_names,
        format_app_primary_menu_action_sensitivities,
    };
    use paladin_gtk::app::state::AppState;

    let state = AppState::Unlocked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let group = build_app_primary_action_group(&state);
    let names = format_app_primary_menu_action_names();
    let expected_sensitivities = format_app_primary_menu_action_sensitivities(&state);
    for (idx, name) in names.iter().enumerate() {
        assert!(
            group.lookup_action(name).is_some(),
            "build_app_primary_action_group must register a SimpleAction named {name:?}; missing at slot {idx}",
        );
        let action = group.lookup_action(name).expect("action just verified");
        let simple = action
            .downcast::<libadwaita::gio::SimpleAction>()
            .expect("primary menu actions must be SimpleActions so set_enabled works");
        assert_eq!(
            simple.is_enabled(),
            expected_sensitivities[idx],
            "build_app_primary_action_group must apply format_app_primary_menu_action_sensitivities[{idx}] to action {name:?}",
        );
        assert!(
            simple.parameter_type().is_none(),
            "primary menu action {name:?} must take no parameter so the menu target `app.{name}` resolves through gio::SimpleAction::new(name, None)",
        );
    }
}

#[test]
fn build_app_primary_action_group_disables_mutating_actions_in_non_unlocked_states() {
    // Defense-in-depth: the four mutating actions (Import,
    // Export, Passphrase, Preferences) must be disabled in every
    // state except `Unlocked` per §"libadwaita usage". About and
    // Quit stay enabled everywhere. Catches a future bundling
    // change that accidentally inverted the sensitivity rule for
    // any of the six actions.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        build_app_primary_action_group, format_app_menu_about_action_name,
        format_app_menu_export_action_name, format_app_menu_import_action_name,
        format_app_menu_passphrase_action_name, format_app_menu_preferences_action_name,
        format_app_menu_quit_action_name,
    };
    use paladin_gtk::app::state::AppState;

    let state = AppState::Locked {
        path: std::path::PathBuf::from("/dev/null"),
    };
    let group = build_app_primary_action_group(&state);
    for mutating_name in [
        format_app_menu_import_action_name(),
        format_app_menu_export_action_name(),
        format_app_menu_passphrase_action_name(),
        format_app_menu_preferences_action_name(),
    ] {
        let action = group
            .lookup_action(mutating_name)
            .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
            .expect("mutating action registered");
        assert!(
            !action.is_enabled(),
            "build_app_primary_action_group must disable mutating action {mutating_name:?} outside Unlocked state",
        );
    }
    for always_enabled in [
        format_app_menu_about_action_name(),
        format_app_menu_quit_action_name(),
    ] {
        let action = group
            .lookup_action(always_enabled)
            .and_then(|a| a.downcast::<libadwaita::gio::SimpleAction>().ok())
            .expect("always-enabled action registered");
        assert!(
            action.is_enabled(),
            "build_app_primary_action_group must keep action {always_enabled:?} enabled in every state per §\"libadwaita usage\"",
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

#[test]
fn format_app_window_accelerator_bindings_targets_are_bundled_action_names() {
    // Cross-consistency guard: every fully-qualified action
    // target in `format_app_window_accelerator_bindings`
    // (`app.add`, `app.quit`, `app.preferences`) must map to a
    // bare action name actually registered on the bundled
    // application-window action group, as enumerated by
    // `format_app_window_action_names`. Without this assertion an
    // accelerator could point to a non-existent action — for
    // example a future rename that touched
    // `format_app_menu_preferences_action_name` without updating
    // `format_app_menu_preferences_action`, or vice versa — and
    // the accelerator would silently no-op at runtime because
    // `gio::Application::set_accels_for_action` accepts any
    // string and binds it without verifying the target exists.
    //
    // The check strips the shared `format_app_action_group_name()
    // + "."` prefix from each binding's target and asserts the
    // bare remainder appears in `format_app_window_action_names`,
    // tying the accelerator surface to the action group's
    // membership in one place.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_window_accelerator_bindings,
        format_app_window_action_names,
    };

    let bindings = format_app_window_accelerator_bindings();
    let names = format_app_window_action_names();
    let prefix = format!("{}.", format_app_action_group_name());
    for (accel, target) in bindings {
        assert!(
            target.starts_with(&prefix),
            "accelerator binding target {target:?} (paired with {accel:?}) must start with the shared group prefix {prefix:?}",
        );
        let bare = &target[prefix.len()..];
        assert!(
            names.contains(&bare),
            "accelerator binding target {target:?} (paired with {accel:?}) strips to bare action name {bare:?}, which must appear in format_app_window_action_names ({names:?}); otherwise the accelerator binds to a non-existent action and silently no-ops at runtime",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_targets_dispatch_to_app_msg() {
    // Companion to
    // `format_app_window_accelerator_bindings_targets_are_bundled_action_names`:
    // that test asserts every accelerator target maps to a bare
    // action name registered on the bundled action group via
    // `format_app_window_action_names`; this test extends the
    // chain one step further so every accelerator target also
    // resolves through `dispatch_app_window_action` to a concrete
    // `AppMsg` variant. A future refactor that added an action
    // name to the bundled group + accelerator surface without
    // wiring a `dispatch_app_window_action` match arm would
    // otherwise activate a no-op at runtime — the accelerator
    // would fire its `SimpleAction`, the action's
    // `connect_activate` handler would route through
    // `dispatch_app_window_action`, the lookup would return
    // `None`, and the handler would silently exit. The
    // `dispatch_app_window_action_covers_every_bundled_action_name`
    // sibling already pins coverage of the full action group;
    // this assertion focuses the guarantee on the three
    // accelerator-bound targets so a drift specific to the
    // keyboard surface stays a failing test rather than a missing
    // shortcut.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_action_group_name,
        format_app_window_accelerator_bindings,
    };

    let bindings = format_app_window_accelerator_bindings();
    let prefix = format!("{}.", format_app_action_group_name());
    for (accel, target) in bindings {
        assert!(
            target.starts_with(&prefix),
            "accelerator binding target {target:?} (paired with {accel:?}) must start with the shared group prefix {prefix:?}",
        );
        let bare = &target[prefix.len()..];
        assert!(
            dispatch_app_window_action(bare).is_some(),
            "accelerator binding target {target:?} (paired with {accel:?}) strips to bare action name {bare:?}, which must route through dispatch_app_window_action to a concrete AppMsg variant; got None, so a keyboard activation of this accelerator would silently no-op at runtime",
        );
    }
}

#[test]
fn format_app_primary_menu_entries_targets_dispatch_to_app_msg() {
    // Direct defense-in-depth check on the primary-menu side
    // that mirrors `format_app_window_accelerator_bindings_targets_dispatch_to_app_msg`:
    // every (label, fully-qualified action target) pair in
    // `format_app_primary_menu_entries` must strip its
    // `format_app_action_group_name() + "."` prefix and route
    // through `dispatch_app_window_action` to a concrete `AppMsg`
    // variant. A future commit adding a new menu entry without
    // also wiring a `dispatch_app_window_action` match arm would
    // otherwise let the menu render the new item (because
    // `build_app_primary_menu_model` appends every pair) and
    // activate a no-op at runtime — the user clicks, the
    // `SimpleAction` fires, the `connect_activate` closure routes
    // through `dispatch_app_window_action`, the lookup returns
    // `None`, and the closure silently exits.
    //
    // `dispatch_app_window_action_covers_every_bundled_action_name`
    // and `format_app_primary_menu_action_names_parallels_primary_menu_entries`
    // already chain transitively to the same guarantee; this
    // direct assertion shortens the diagnostic path so a regression
    // in the dispatch table fails with a message that names the
    // visible menu label, not the bare action name.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_action_group_name, format_app_primary_menu_entries,
    };

    let entries = format_app_primary_menu_entries();
    let prefix = format!("{}.", format_app_action_group_name());
    for (label, target) in entries {
        assert!(
            target.starts_with(&prefix),
            "primary menu entry {label:?} target {target:?} must start with the shared group prefix {prefix:?}",
        );
        let bare = &target[prefix.len()..];
        assert!(
            dispatch_app_window_action(bare).is_some(),
            "primary menu entry {label:?} (target {target:?}) strips to bare action name {bare:?}, which must route through dispatch_app_window_action to a concrete AppMsg variant; got None, so a click on the menu entry would silently no-op at runtime",
        );
    }
}

#[test]
fn app_msg_carries_open_add_dialog_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // header-bar `+` button (and the `<Control>n` accelerator
    // bound to the same `"app.add"` `SimpleAction`) routes its
    // activation through `dispatch_app_window_action` to
    // `AppMsg::OpenAddDialog`, whose handler mounts a fresh
    // `AddAccountComponent` seeded with the resolved vault path.
    // The compile-only check below pins the variant exists and
    // carries no payload so the `connect_activate` closure can
    // post it without constructor arguments, mirroring the five
    // sibling `app_msg_carries_open_*_dialog_variant` pins for
    // the primary-menu entries (About / Preferences / Import /
    // Export / Passphrase).
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::OpenAddDialog;
}

#[test]
fn app_msg_carries_quit_variant() {
    // Per §"libadwaita usage" and §"Component tree": the
    // application menu's Quit entry (and the `<Control>q`
    // accelerator bound to the same `"app.quit"` `SimpleAction`)
    // routes its activation through `dispatch_app_window_action`
    // to `AppMsg::Quit`, whose handler calls
    // `relm4::main_application().quit()` so any pending `GLib`
    // sources unwind before the process exits. The same variant
    // is also posted by the headless smoke-test
    // `exit_after_startup` path so `tests/gtk_smoke.rs` can run
    // the app under `xvfb-run` and observe the startup state
    // markers before the application terminates. The compile-
    // only check below pins the variant exists and carries no
    // payload so the `connect_activate` closure and the smoke
    // path can post it without constructor arguments, rounding
    // out the dispatchable AppMsg surface alongside the six
    // sibling `app_msg_carries_open_*_dialog_variant` pins.
    use paladin_gtk::app::model::AppMsg;

    let _: AppMsg = AppMsg::Quit;
}

#[test]
fn format_app_window_title_is_non_empty_single_line_without_state_suffix() {
    // Defense-in-depth companion to
    // `format_app_window_title_returns_paladin`: the exact-value
    // assertion catches a wholesale rename, but a sibling
    // defensive test catches the more nuanced regression where
    // someone appends a state-leaking suffix like
    // `" — Locked"` / `" — Unlocked"` to the
    // `AdwApplicationWindow` title. The
    // `format_app_window_title` docstring explicitly calls this
    // out: "no state-specific suffixes … which would otherwise
    // leak the live vault state into the window-list across
    // application switches". A title that embedded a newline
    // would also break the desktop's window-list rendering, so
    // the single-line invariant is pinned here too. Mirrors the
    // `_is_non_empty_single_line_*` sibling tests on the
    // `format_app_about_dialog_*` helpers.
    use paladin_gtk::app::model::format_app_window_title;

    let title = format_app_window_title();
    assert!(
        !title.is_empty(),
        "ApplicationWindow title must be non-empty; got {title:?}",
    );
    assert!(
        !title.contains('\n'),
        "ApplicationWindow title must be a single line so the desktop's window-list renders one entry per window; got {title:?}",
    );
    for forbidden in [
        "Locked",
        "Unlocked",
        "Missing",
        "UnlockedBusy",
        "StartupError",
    ] {
        assert!(
            !title.contains(forbidden),
            "ApplicationWindow title must not embed vault-state name {forbidden:?}; the per-state UI surfaces inside the window already convey the state, and leaking it into the window-list would advertise the live vault status across application switches; got {title:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_program_name_matches_format_app_window_title() {
    // Cross-consistency: `format_app_window_title` populates the
    // `AdwApplicationWindow::set_title` slot (the window-list
    // entry and Wayland session-label string), while
    // `format_app_about_dialog_program_name` populates the
    // `AdwAboutDialog::set_application_name` slot (the dialog
    // header). Both must agree so the running binary's identity
    // shown on the desktop bar and the identity shown in the
    // About dialog header stay in lockstep — a drift would let
    // the title bar advertise one name while the About header
    // shows another. The format_app_menu_about_label docstring
    // already calls out this invariant ("if either renames in a
    // future version, both should move together so the menu
    // entry and window-list entry stay in lockstep"), and the
    // `format_app_menu_about_label_carries_application_name`
    // test ties the About menu *label* to
    // `format_app_window_title`; this assertion completes the
    // triangle by tying the About *dialog header* to the same
    // pinned source of truth.
    use paladin_gtk::app::model::{format_app_about_dialog_program_name, format_app_window_title};

    assert_eq!(
        format_app_about_dialog_program_name(),
        format_app_window_title(),
        "AdwAboutDialog application_name slot must match the AdwApplicationWindow title slot so the desktop bar and the About dialog header advertise the same running-binary identity",
    );
}

#[test]
fn format_app_action_group_name_is_prefix_of_format_app_add_button_action() {
    // Companion to
    // `format_app_action_group_name_is_prefix_of_every_primary_menu_action`:
    // that test verifies the six primary-menu action targets start
    // with `format_app_action_group_name() + "."`; this assertion
    // extends the coverage to the seventh action on the bundled
    // group — the header-bar `+` button's `app.add` target — so a
    // future rename of `format_app_action_group_name` lands as a
    // failing test for every action target on the bundled group,
    // not just the menu six.
    //
    // `format_app_add_button_action_uses_app_group_prefix` already
    // pins the `"app."` literal at the source level, but that
    // assertion hardcodes the prefix string and would not catch a
    // drift where `format_app_action_group_name` was renamed (the
    // primary-menu sibling would fail there, but the header-bar
    // button would silently continue to use the old literal). This
    // sibling closes that gap by routing through
    // `format_app_action_group_name` dynamically.
    use paladin_gtk::app::model::{format_app_action_group_name, format_app_add_button_action};

    let group = format_app_action_group_name();
    let prefix = format!("{group}.");
    let action = format_app_add_button_action();
    assert!(
        action.starts_with(&prefix),
        "header-bar + button action target {action:?} must start with the shared group prefix {prefix:?} so the bundled application action group resolves it alongside the six primary-menu entries",
    );
    let bare = &action[prefix.len()..];
    assert!(
        !bare.is_empty(),
        "header-bar + button action target {action:?} must carry a non-empty bare action name after the {prefix:?} prefix",
    );
    assert!(
        !bare.contains('.'),
        "header-bar + button action target {action:?} must not embed a second `.` separator after the {prefix:?} group prefix",
    );
}

#[test]
fn format_app_header_bar_button_icon_names_are_distinct() {
    // Defense-in-depth: the three header-bar buttons (`+` Add,
    // search-toggle, primary menu) each carry a freedesktop icon
    // name resolved through the system icon theme. The per-helper
    // `_returns_*` tests pin each icon to its expected wording
    // individually, but a future refactor that accidentally
    // copy-pasted the wrong sibling helper into one of the three
    // setters would leave the per-helper assertions intact while
    // rendering two identical glyphs on the header bar — visually
    // obvious during interactive testing but easy to miss in a
    // diff. Mirroring the
    // `format_app_window_accelerator_bindings_accelerators_are_distinct`
    // pattern, this assertion enforces the disjointness at the
    // pinned-helper layer so a drift surfaces as a failing test
    // rather than as a duplicated glyph the smoke test does not
    // inspect.
    use paladin_gtk::app::model::{
        format_app_add_button_icon_name, format_app_menu_button_icon_name,
        format_app_search_button_icon_name,
    };

    let add = format_app_add_button_icon_name();
    let search = format_app_search_button_icon_name();
    let menu = format_app_menu_button_icon_name();
    let mut icons = [add, search, menu];
    icons.sort_unstable();
    let before_dedup = icons.len();
    let mut deduped: Vec<&str> = icons.to_vec();
    deduped.dedup();
    assert_eq!(
        before_dedup,
        deduped.len(),
        "the three header-bar button icon names must be distinct (Add: {add:?}, search: {search:?}, menu: {menu:?}); a duplicate would render two identical glyphs on the header bar",
    );
}

#[test]
fn format_app_header_bar_button_tooltips_are_distinct() {
    // Defense-in-depth sibling of
    // `format_app_header_bar_button_icon_names_are_distinct`: the
    // three header-bar buttons (`+` Add, search-toggle, primary
    // menu) are icon-only, so the per-button tooltip is the only
    // textual cue an Orca / hover user gets for what each glyph
    // does. The per-helper `_returns_*` tests pin each tooltip to
    // its expected wording individually, but a future refactor
    // that accidentally copy-pasted the wrong sibling helper into
    // one of the three `set_tooltip_text:` slots would leave the
    // per-helper assertions intact while rendering two identical
    // tooltip strings on the header bar — collapsing the
    // accessibility hint for two of the three buttons. Mirroring
    // the `format_app_header_bar_button_icon_names_are_distinct`
    // pattern (which in turn mirrors
    // `format_app_window_accelerator_bindings_accelerators_are_distinct`),
    // this assertion enforces the disjointness at the pinned-
    // helper layer so a drift surfaces as a failing test rather
    // than as a duplicated tooltip the smoke test does not
    // inspect.
    use paladin_gtk::app::model::{
        format_app_add_button_tooltip, format_app_menu_button_tooltip,
        format_app_search_button_tooltip,
    };

    let add = format_app_add_button_tooltip();
    let search = format_app_search_button_tooltip();
    let menu = format_app_menu_button_tooltip();
    let mut tooltips = [add, search, menu];
    tooltips.sort_unstable();
    let before_dedup = tooltips.len();
    let mut deduped: Vec<&str> = tooltips.to_vec();
    deduped.dedup();
    assert_eq!(
        before_dedup,
        deduped.len(),
        "the three header-bar button tooltips must be distinct (Add: {add:?}, search: {search:?}, menu: {menu:?}); a duplicate would render two identical tooltip strings on the header bar and collapse the accessibility hint for the duplicated buttons",
    );
}

#[test]
fn format_app_primary_menu_entries_labels_are_distinct() {
    // Defense-in-depth sibling of
    // `format_app_header_bar_button_tooltips_are_distinct` and
    // `format_app_header_bar_button_icon_names_are_distinct`: the
    // six primary-menu entries returned by
    // `format_app_primary_menu_entries` (Import…, Export…,
    // Passphrase…, Preferences, About Paladin, Quit) each carry a
    // visible label that the libadwaita primary `gio::Menu`
    // renders as a row in the dropdown. The per-helper
    // `format_app_menu_*_label_returns_*` tests pin each label to
    // its expected wording individually, but a future refactor
    // that accidentally copy-pasted the wrong sibling helper into
    // one of the six slots of `format_app_primary_menu_entries`
    // would leave the per-helper assertions intact while
    // rendering two identical rows in the primary menu — a
    // regression that surfaces as a duplicated entry on hover but
    // is easy to miss in a diff. Mirroring the
    // `format_app_header_bar_button_icon_names_are_distinct` /
    // `_tooltips_are_distinct` / `_targets_are_distinct` /
    // `_accelerators_are_distinct` pattern, this assertion
    // enforces the disjointness at the pinned-helper layer so a
    // drift surfaces as a failing test rather than as a
    // duplicated menu row the smoke test does not inspect.
    use paladin_gtk::app::model::format_app_primary_menu_entries;

    let entries = format_app_primary_menu_entries();
    let mut labels: Vec<&str> = entries.iter().map(|(label, _)| *label).collect();
    let before_dedup = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        before_dedup,
        labels.len(),
        "the six primary-menu entry labels must be distinct (entries: {entries:?}); a duplicate would render two identical rows in the primary menu and collapse one of the six action slots into an unreachable duplicate",
    );
}

#[test]
fn format_app_primary_menu_entries_actions_are_distinct() {
    // Defense-in-depth sibling of
    // `format_app_primary_menu_entries_labels_are_distinct`: the
    // labels-side test guards against two rows rendering with the
    // same visible text, while this action-side companion guards
    // against the dual failure mode where two rows render with
    // distinct labels but route their `gio::Action::activate`
    // signal to the same `app.*` target — collapsing two
    // separate menu entries into a single dispatched
    // `AppMsg`. The per-helper
    // `format_app_menu_*_action_returns_app_*` tests pin each
    // action target to its expected wording individually, but a
    // future refactor that accidentally copy-pasted the wrong
    // sibling helper into one of the six slots of
    // `format_app_primary_menu_entries` would leave the per-helper
    // assertions intact while wiring two visible menu rows to the
    // same `gio::SimpleAction` — a regression that surfaces only
    // when the user activates the wrong-looking entry and sees
    // the wrong dialog open. Mirroring the
    // `format_app_window_accelerator_bindings_targets_are_distinct`
    // pattern, this assertion enforces the disjointness at the
    // pinned-helper layer so a drift surfaces as a failing test
    // rather than as a menu row that silently shares dispatch
    // with another row.
    use paladin_gtk::app::model::format_app_primary_menu_entries;

    let entries = format_app_primary_menu_entries();
    let mut actions: Vec<&str> = entries.iter().map(|(_, action)| *action).collect();
    let before_dedup = actions.len();
    actions.sort_unstable();
    actions.dedup();
    assert_eq!(
        before_dedup,
        actions.len(),
        "the six primary-menu entry action targets must be distinct (entries: {entries:?}); a duplicate would route two visible menu rows to the same gio::SimpleAction and dispatch the same AppMsg from both, collapsing one of the six menu actions into an unreachable duplicate",
    );
}

#[test]
fn format_app_window_action_names_are_distinct() {
    // Defense-in-depth: `format_app_window_action_names` returns
    // the seven bare action names that
    // `build_app_primary_action_group` registers on the bundled
    // `gio::SimpleActionGroup` — the six primary-menu actions
    // (`import`, `export`, `passphrase`, `preferences`, `about`,
    // `quit`) plus the header-bar `+` button's `add` action.
    // Each name becomes a `gio::SimpleAction` keyed by that bare
    // name inside the group; registering two actions with the
    // same name on the same `SimpleActionGroup` is a silent
    // overwrite at the gio layer (the second insertion wins),
    // collapsing two surface entries into a single dispatched
    // `AppMsg`. The pairwise sibling tests
    // `format_app_primary_menu_entries_actions_are_distinct`
    // (which guards the six menu actions only via their fully-
    // qualified `app.*` targets) and the
    // `format_app_window_action_names_lists_the_six_primary_menu_entries_then_add`
    // ordering test (which pins the slot layout) leave a gap
    // where the Add action's bare name could collide with one of
    // the six menu bare names — a regression that would silently
    // overwrite the Add `SimpleAction` registration. Mirroring
    // the `_are_distinct` pattern at the seven-name layer closes
    // that gap so the drift surfaces as a failing test rather
    // than as an Add button that silently fires the wrong
    // `AppMsg`.
    use paladin_gtk::app::model::format_app_window_action_names;

    let names = format_app_window_action_names();
    let before_dedup = names.len();
    let mut deduped: Vec<&str> = names.to_vec();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        before_dedup,
        deduped.len(),
        "the seven bare action names returned by format_app_window_action_names must be distinct (names: {names:?}); a duplicate would silently overwrite one of the gio::SimpleAction registrations on the bundled SimpleActionGroup at build time and collapse two visible surface entries into a single dispatched AppMsg",
    );
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_carry_modifier_prefix() {
    // Defense-in-depth sibling of
    // `format_app_window_accelerator_bindings_parse_via_gtk_accelerator_parse`
    // and `format_app_window_accelerator_bindings_accelerators_are_distinct`:
    // the parse test pins each accelerator spelling reaches a
    // valid `(keyval, modifiers)` pair via `gtk::accelerator_parse`,
    // but a parsed pair with an empty (zero) modifier set is
    // still a bare-keysym shortcut that would conflict with
    // text entry in the search bar and any dialog `gtk::Entry`
    // — typing `n`, `q`, or `comma` into the search field would
    // fire `app.add` / `app.quit` / `app.preferences` instead
    // of being inserted into the buffer. The three pinned
    // accelerators today all use the `<Control>` modifier
    // (`<Control>n`, `<Control>q`, `<Control>comma`), and the
    // GNOME-HIG accelerator convention for menu / header-bar
    // shortcuts requires at least one modifier key so the
    // shortcut does not steal a printable keysym. This
    // assertion enforces the modifier-prefix invariant at the
    // pinned-helper layer so a future regression that dropped
    // the `<…>` modifier block on one of the three accelerators
    // fails the test rather than silently rebinding the shortcut
    // to a bare keysym that intercepts text entry.
    //
    // The string-shape check below (every accel starts with `<`
    // and contains a matching `>` before the keysym name) is
    // intentional rather than calling `gtk::accelerator_parse`
    // again: the `_parse_via_gtk_accelerator_parse` sibling
    // already calls `gtk::init` to load the keysym table for its
    // assertion, and a second `gtk::init` call from a parallel
    // test worker thread would panic via gtk4-rs's "Attempted to
    // initialize GTK from two different threads" guard. Scoping
    // the modifier-presence check to a pure string-shape
    // invariant keeps this test parallel-safe with the parse
    // sibling without requiring a `#[gtk::test]` harness or a
    // `std::sync::Once`-gated init helper.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        assert!(
            accel.starts_with('<'),
            "accelerator {accel:?} for target {target:?} must start with a `<…>` modifier block (today `<Control>`); a bare keysym shortcut would intercept printable text entry from the search bar and dialog gtk::Entry rows",
        );
        let close = accel.find('>').unwrap_or_else(|| {
            panic!(
                "accelerator {accel:?} for target {target:?} opens a `<` modifier block but never closes it before the keysym; gtk::accelerator_parse would reject this at runtime",
            )
        });
        let modifier = &accel[1..close];
        assert!(
            !modifier.is_empty(),
            "accelerator {accel:?} for target {target:?} opens with `<>` (empty modifier block); the modifier name (e.g. `Control`) must be present so the shortcut carries an actual modifier key rather than parsing as a bare keysym",
        );
        let keysym = &accel[close + 1..];
        assert!(
            !keysym.is_empty(),
            "accelerator {accel:?} for target {target:?} carries the `<{modifier}>` modifier block but no keysym after it; gtk::accelerator_parse would reject this at runtime",
        );
    }
}

#[test]
fn format_app_about_dialog_program_name_is_segment_of_application_icon_name() {
    // Cross-consistency: the human-display program-name
    // `"Paladin"` (`AdwAboutDialog::set_program_name`) and the
    // reverse-DNS application-icon-name `"org.tamx.Paladin.Gui"`
    // (`AdwAboutDialog::set_application_icon` and the
    // `RelmApp::new(APP_ID)` identifier) are two views of the
    // same product identity. The
    // `format_app_about_dialog_program_name_is_non_empty_and_not_app_id`
    // test pins they are not equal (program-name must not be the
    // reverse-DNS form), and the
    // `format_app_about_dialog_application_icon_name_is_reverse_dns`
    // test pins the icon-name *is* reverse-DNS, but neither
    // assertion ties the two together — a rename of the program-
    // name to e.g. `"Vault"` without a matching `APP_ID` rename
    // to `"org.tamx.Vault.Gui"` would leave the desktop bar's
    // identity (`format_app_window_title` /
    // `format_app_about_dialog_program_name`) drifting from the
    // icon-theme lookup key on the launcher / about-dialog
    // header. Mirroring the
    // `format_app_about_dialog_program_name_matches_format_app_window_title`
    // and the `format_app_about_dialog_application_icon_name_matches_app_id`
    // cross-consistency pairs, this assertion ties the two views
    // together by requiring the bare program-name to appear
    // verbatim as a `.`-separated segment of the reverse-DNS
    // identifier so a unilateral rename on either side fails the
    // test rather than only surfacing when a user notices the
    // launcher icon does not match the about-dialog header.
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_program_name,
    };

    let program = format_app_about_dialog_program_name();
    let icon = format_app_about_dialog_application_icon_name();
    let segments: Vec<&str> = icon.split('.').collect();
    assert!(
        segments.contains(&program),
        "AdwAboutDialog program-name {program:?} must appear verbatim as a `.`-separated segment of the application-icon-name {icon:?} so the human display name and the reverse-DNS APP_ID identifier stay tied to the same brand string; if a future rename moves one, both must move together",
    );
}

#[test]
fn format_app_window_default_size_meets_gnome_hig_narrow_threshold() {
    // Defense-in-depth sibling of
    // `format_app_window_default_size_returns_640_by_480` (exact
    // pinned value) and `format_app_window_default_size_pair_is_positive`
    // (defensive positivity floor). Those two assertions catch
    // a wholesale rewrite and a zero / negative-dimension
    // regression, but a more nuanced regression that shrunk the
    // default to e.g. `(320, 240)` would still pass both — and
    // would collapse the `AccountListComponent`'s
    // `<issuer>:<label>` rows into an `AdwSqueezer` before
    // libadwaita has any chance to lay them out, and clip the
    // header bar's `+` button / search button / primary menu
    // glyphs against each other.
    //
    // The GNOME HIG's narrow-window adaptive floor for
    // libadwaita applications is 360px wide (the minimum width
    // a modern adaptive `AdwApplicationWindow` must remain
    // usable at), with 294px tall as the matching narrow-height
    // floor for the chrome-plus-content layout libadwaita ships.
    // The pinned (640, 480) default sits comfortably above both
    // floors; pinning the threshold here ensures a future
    // dimension regression that fell below either floor surfaces
    // as a failing test rather than as an initial window that
    // user-resizable libadwaita chrome cannot lay out cleanly.
    use paladin_gtk::app::model::format_app_window_default_size;

    const NARROW_WIDTH_FLOOR: i32 = 360;
    const NARROW_HEIGHT_FLOOR: i32 = 294;

    let (width, height) = format_app_window_default_size();
    assert!(
        width >= NARROW_WIDTH_FLOOR,
        "ApplicationWindow default width {width} must meet the GNOME HIG narrow-window adaptive floor ({NARROW_WIDTH_FLOOR}px) so the AccountListComponent rows lay out without an AdwSqueezer collapse and the header-bar buttons render side-by-side",
    );
    assert!(
        height >= NARROW_HEIGHT_FLOOR,
        "ApplicationWindow default height {height} must meet the GNOME HIG narrow-window adaptive floor ({NARROW_HEIGHT_FLOOR}px) so the chrome-plus-content layout (header bar + a useful run of account rows) renders without clipping the bottom of the list",
    );
}

#[test]
fn format_app_window_default_size_is_landscape_or_square_orientation() {
    // Defense-in-depth sibling of
    // `format_app_window_default_size_meets_gnome_hig_narrow_threshold`:
    // the narrow-threshold test pins both dimensions sit above
    // the libadwaita HIG floors, but a regression that swapped
    // the two slots — e.g. `(480, 640)` instead of the pinned
    // `(640, 480)` — would still pass both the threshold and
    // the positivity assertions while flipping the window into
    // a portrait orientation. The `AccountListComponent`'s
    // `<issuer>:<label>` rows render most cleanly when the
    // window is at least as wide as it is tall (landscape or
    // square), so the row text has horizontal room before
    // libadwaita's `AdwSqueezer` decides to ellipsize the
    // label. The docstring on `format_app_window_default_size`
    // explicitly orders the docs as "wide enough… tall enough",
    // pinning width as the primary axis. This assertion encodes
    // the orientation invariant at the pinned-helper layer so a
    // future regression that flipped the tuple surfaces as a
    // failing test rather than as an unfamiliar portrait-shaped
    // initial window the user has not yet resized.
    use paladin_gtk::app::model::format_app_window_default_size;

    let (width, height) = format_app_window_default_size();
    assert!(
        width >= height,
        "ApplicationWindow default size must be landscape or square (width >= height) so the AccountListComponent's `<issuer>:<label>` rows render with horizontal room before AdwSqueezer ellipsizes the label; got ({width}, {height}) which is portrait-oriented",
    );
}

#[test]
fn format_app_about_dialog_developers_does_not_contain_developer_name() {
    // Defense-in-depth cross-consistency: the AdwAboutDialog
    // header attribution row (`developer-name`) carries the
    // canonical collective attribution string
    // ("The Paladin contributors") because the workspace
    // `Cargo.toml` deliberately omits the `authors` field per
    // §"AGPL-3.0-or-later open contributor pool" so the dialog
    // does not name a single owner. The credits-page contributor
    // list (`developers`) carries individual contributors who
    // have committed against the project. A refactor that
    // accidentally seeded the collective attribution string into
    // the credits list (e.g. copy-pasted
    // `format_app_about_dialog_developer_name()` into the
    // `developers` literal) would render a credits row that
    // duplicates the header attribution row — confusing because
    // the credits page would now list a "contributor" with the
    // same name as the collective attribution. Mirroring the
    // `format_app_about_dialog_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    // pattern (which positively ties developer_name into a
    // related field), this assertion negatively ties the two
    // sides apart so the credits list and the header attribution
    // row carry semantically distinct strings.
    use paladin_gtk::app::model::{
        format_app_about_dialog_developer_name, format_app_about_dialog_developers,
    };

    let developer_name = format_app_about_dialog_developer_name();
    let developers = format_app_about_dialog_developers();
    for entry in developers {
        assert_ne!(
            entry, developer_name,
            "AdwAboutDialog developers credits-list entry {entry:?} must not duplicate the dialog-header collective attribution string {developer_name:?}; the credits list names individual contributors, while the header attribution names the collective",
        );
    }
}

#[test]
fn format_app_window_default_size_fits_typical_desktop_display() {
    // Defense-in-depth sibling of
    // `format_app_window_default_size_meets_gnome_hig_narrow_threshold`
    // (which pins the lower-bound dimensions) and
    // `format_app_window_default_size_is_landscape_or_square_orientation`
    // (which pins the orientation invariant). Those two
    // assertions catch dimensions that are too small or
    // portrait-flipped, but a regression that ballooned the
    // default to e.g. `(6400, 4800)` — still positive,
    // landscape, and above the narrow threshold — would still
    // pass all three companions while rendering an initial
    // window that overflows the user's screen before they have
    // any chance to resize. A common typo class is a trailing
    // zero (`640` -> `6400`) or a duplicated literal; pinning a
    // sane upper bound here catches that drift.
    //
    // The pinned ceiling is the typical 1920x1080 desktop
    // resolution (the FHD resolution that has been the most
    // common single-display layout across GNOME desktops for
    // years). The current (640, 480) pinned default sits well
    // below this ceiling; pinning the upper bound here ensures
    // a future dimension regression that exceeded the typical
    // FHD display fails the test rather than as an initial
    // window that does not fit on a standard 1080p screen.
    use paladin_gtk::app::model::format_app_window_default_size;

    const FHD_WIDTH_CEILING: i32 = 1920;
    const FHD_HEIGHT_CEILING: i32 = 1080;

    let (width, height) = format_app_window_default_size();
    assert!(
        width <= FHD_WIDTH_CEILING,
        "ApplicationWindow default width {width} must fit within the typical 1920x1080 FHD desktop display (ceiling {FHD_WIDTH_CEILING}px) so the initial window does not overflow a standard 1080p screen before the user has a chance to resize; a regression that appended a trailing zero to the pinned 640px width would fail the test",
    );
    assert!(
        height <= FHD_HEIGHT_CEILING,
        "ApplicationWindow default height {height} must fit within the typical 1920x1080 FHD desktop display (ceiling {FHD_HEIGHT_CEILING}px) so the initial window does not overflow a standard 1080p screen before the user has a chance to resize; a regression that appended a trailing zero to the pinned 480px height would fail the test",
    );
}

#[test]
fn format_app_about_dialog_debug_info_starts_with_program_name() {
    // Cross-consistency sibling of
    // `format_app_about_dialog_debug_info_carries_program_name_version_and_app_id`
    // which only requires `.contains()` matches anywhere in the
    // payload. That looser companion would still pass for a
    // future refactor that moved the program name to the end of
    // the payload — e.g. `"App ID: org.tamx.Paladin.Gui\nPaladin 0.1.0"` —
    // even though the bug-report payload that
    // `AdwAboutDialog::set_debug_info` hands to the "Copy debug
    // info" / "Save debug info" buttons should lead with the
    // human-readable program-name + version so the app
    // identification is obvious at first glance before the
    // reverse-DNS app ID line. This positional pin catches that
    // drift at the pinned layer rather than only being noticed
    // when a maintainer reading a bug-report paste has to scroll
    // past the machine-oriented app ID to find which app the
    // report is about.
    //
    // Anchoring the program name at the very start (no leading
    // whitespace or preamble) also pairs with the
    // `_is_non_empty_text_with_no_trailing_whitespace` companion
    // which forbids leading whitespace; together they pin the
    // payload to begin with the program-name display string.
    use paladin_gtk::app::model::{
        format_app_about_dialog_debug_info, format_app_about_dialog_program_name,
    };

    let debug = format_app_about_dialog_debug_info();
    let program_name = format_app_about_dialog_program_name();
    assert!(
        debug.starts_with(program_name),
        "AdwAboutDialog debug-info must start with the program-name display string {program_name:?} so the bug-report payload's first content is the human-readable app identification before the reverse-DNS app ID line; got {debug:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_app_id_appears_on_a_distinct_line_from_program_name() {
    // Cross-consistency sibling of
    // `format_app_about_dialog_debug_info_starts_with_program_name`
    // (which pins the leading content) and
    // `format_app_about_dialog_debug_info_carries_program_name_version_and_app_id`
    // (which only requires `.contains()` matches). Together those
    // two companions still allow a single-line debug-info layout
    // where the program-name, version, and reverse-DNS app ID
    // collapse onto one wrapping line — e.g.
    // `"Paladin 0.1.0 App ID: org.tamx.Paladin.Gui"` — which would
    // be harder for a bug-report reader to scan than the pinned
    // two-line layout where the human-readable program-name +
    // version sit on one line and the machine-oriented app ID
    // sits on a separate labeled line below it.
    //
    // The assertion here is the line-shape invariant: the
    // program-name segment and the reverse-DNS app ID segment
    // must land on distinct line indices of the debug-info
    // payload so the bug-report paste renders as a tidy
    // multi-line block rather than as one ambiguous wrapping
    // run. Pins the `\nApp ID: ` separator inside
    // `format_app_about_dialog_debug_info` at the test layer
    // without hardcoding the literal `"App ID:"` label so a
    // future re-labeling (e.g. localized prefix) still exercises
    // the line-shape contract.
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_debug_info,
        format_app_about_dialog_program_name,
    };

    let debug = format_app_about_dialog_debug_info();
    let program_name = format_app_about_dialog_program_name();
    let app_id = format_app_about_dialog_application_icon_name();

    let lines: Vec<&str> = debug.lines().collect();
    let program_name_line_idx = lines
        .iter()
        .position(|line| line.contains(program_name))
        .unwrap_or_else(|| {
            panic!(
                "AdwAboutDialog debug-info must have at least one line containing the program-name display string {program_name:?}; got {debug:?}"
            )
        });
    let app_id_line_idx = lines
        .iter()
        .position(|line| line.contains(app_id))
        .unwrap_or_else(|| {
            panic!(
                "AdwAboutDialog debug-info must have at least one line containing the reverse-DNS app ID {app_id:?}; got {debug:?}"
            )
        });
    assert_ne!(
        program_name_line_idx, app_id_line_idx,
        "AdwAboutDialog debug-info program-name and reverse-DNS app ID must land on distinct line indices so the bug-report paste renders as a tidy multi-line block rather than as one ambiguous wrapping run; both landed on line index {program_name_line_idx} of {debug:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_has_exactly_two_lines() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_app_id_appears_on_a_distinct_line_from_program_name`
    // which only pins the *distinct-lines* invariant between the
    // program-name and reverse-DNS App ID segments. That looser
    // companion would still pass for a future refactor that
    // ballooned the payload to three, four, or more lines —
    // e.g. by adding a feature-flag dump, a host-OS line, or a
    // crash-counter line — without first noting whether the
    // additional fields belong in the bug-report copy paste at
    // all. Pinning the exact line count to two here keeps the
    // payload deliberately minimal: a future addition has to
    // both update the implementation and bump this expected
    // count, which is a forcing function for an explicit
    // decision about whether the new field is worth adding to
    // the bug-report payload.
    //
    // The pinned two-line shape matches the docstring example
    // on `format_app_about_dialog_debug_info` which renders
    // `"Paladin <version>"` on line one and
    // `"App ID: org.tamx.Paladin.Gui"` on line two.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug = format_app_about_dialog_debug_info();
    let line_count = debug.lines().count();
    assert_eq!(
        line_count, 2,
        "AdwAboutDialog debug-info must contain exactly two lines so the bug-report payload stays deliberately minimal — program-name + version on line one, reverse-DNS App ID on line two — and a future addition forces an explicit decision; got {line_count} lines in {debug:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_is_a_single_line_without_embedded_newlines() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developer_name_is_non_empty_and_distinct_from_program_name`
    // which pins non-empty + no leading/trailing whitespace +
    // distinct from program-name / application-icon-name. That
    // companion still allows an embedded `\n` inside the
    // developer-name string — e.g. `"The Paladin\ncontributors"` —
    // which would render across two lines in the
    // `AdwAboutDialog` header attribution slot and break the
    // tidy single-line header layout `libadwaita` expects.
    //
    // The dialog's `developer-name` property is consumed as a
    // single-line attribution by the dialog header (a "by
    // <developer-name>" caption beneath the program name); a
    // multi-line value would push the dialog header taller than
    // its baseline layout and visually misalign the icon /
    // application-name / version cluster. Pinning the
    // single-line invariant here catches that drift at the
    // pinned layer rather than only being noticed when a user
    // opened the about dialog and saw a vertically-stretched
    // header.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\n'),
        "AdwAboutDialog developer-name must be a single line so the dialog header attribution renders as one tidy caption beneath the program name rather than as a vertically-stretched two-line block; got {developer:?}",
    );
    assert!(
        !developer.contains('\r'),
        "AdwAboutDialog developer-name must use LF-only conventions (no embedded CR), matching the GNOME stack's text expectation for a single-line attribution caption; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_year_token_so_it_does_not_drift_across_releases(
) {
    // Cross-consistency with the `format_app_about_dialog_copyright`
    // docstring which explicitly calls out: "Pinning the literal
    // here keeps the dialog footer copyright row stable across
    // releases without depending on a year-derived value (which
    // would silently drift on a future release without a matching
    // constant update)."
    //
    // The existing `_starts_with_copyright_glyph_and_contains_developer_name`
    // companion pins the `©` glyph and the attribution string but
    // leaves the year invariant ungated, so a future refactor
    // that copy-pasted a year token into the copyright literal —
    // e.g. `"© 2026 The Paladin contributors"` — would slip past
    // the existing assertions while quietly turning the footer
    // into a value that needs a manual bump every January.
    // Pinning the no-year invariant here catches that drift at
    // the pinned layer rather than only being noticed when the
    // year ticks over and a user files a bug that the copyright
    // is out of date.
    //
    // The assertion scans for any four-consecutive-ASCII-digit
    // substring inside the copyright payload. The legal `©`
    // glyph is U+00A9 (non-ASCII) so it cannot match this
    // pattern, and the canonical attribution string
    // `"The Paladin contributors"` contains no digit runs.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    let bytes = copyright.as_bytes();
    let has_four_digit_run = bytes
        .windows(4)
        .any(|window| window.iter().all(u8::is_ascii_digit));
    assert!(
        !has_four_digit_run,
        "AdwAboutDialog copyright must not contain a four-digit year token so the footer copyright row stays stable across releases without depending on a year-derived value that would silently drift on a future release without a matching constant update; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_are_distinct() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developers_is_non_empty_array_of_non_empty_single_line_names`
    // (which pins per-entry shape — non-empty, single-line, no
    // surrounding whitespace) and
    // `format_app_about_dialog_developers_lists_benjamin_porter`
    // (which positively pins the v0.2 founding-contributor entry).
    // Both companions leave the cross-entry distinctness invariant
    // ungated, so a future copy-paste regression that listed the
    // same name twice — e.g. `["Benjamin Porter", "Benjamin Porter"]`
    // when adding a second contributor row was meant — would slip
    // past the existing per-entry assertions while rendering a
    // duplicate row in the `AdwAboutDialog` credits page.
    //
    // Mirrors the established `_labels_are_distinct` /
    // `_actions_are_distinct` / `_icon_names_are_distinct` /
    // `_tooltips_are_distinct` sibling pattern used elsewhere in
    // the `format_app_*` suite where multi-entry pinned arrays
    // exposed the same duplicate-entry failure mode. Pinning the
    // invariant here even though the v0.2 array carries a single
    // entry today is a forcing function: the next contributor
    // added has to land alongside a distinct credit string
    // rather than slip in as a silent duplicate.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    let mut seen: Vec<&str> = Vec::with_capacity(developers.len());
    for entry in developers {
        assert!(
            !seen.contains(&entry),
            "AdwAboutDialog developers must list each contributor at most once so the credits-page renders one row per contributor rather than a duplicated row; entry {entry:?} appears more than once in {developers:?}",
        );
        seen.push(entry);
    }
}

#[test]
fn format_app_about_dialog_issue_url_and_support_url_share_cargo_pkg_repository_prefix() {
    // Cross-consistency sibling of the per-side
    // `_issue_url_appends_issues_to_cargo_pkg_repository` and
    // `_support_url_appends_discussions_to_cargo_pkg_repository`
    // companions which independently anchor each URL to
    // `env!("CARGO_PKG_REPOSITORY")` with the appropriate
    // GitHub suffix. Each existing companion validates one
    // side in isolation; this cross-check ties both sides to
    // the same repository prefix so a future refactor that
    // hand-spelled either URL against a different repository
    // base — e.g. moving `support_url` to a separate Discourse
    // forum while leaving `issue_url` on the workspace
    // repository — fails the test rather than silently
    // splitting the bug-reporting and community-Q&A surfaces
    // across two different project homes.
    //
    // Together with the `_issue_url_is_non_empty_https_url_distinct_from_website`
    // and `_support_url_is_non_empty_https_url_distinct_from_issue_and_website`
    // siblings (which pin pairwise distinctness) this completes
    // the triangle: both URLs are distinct from each other and
    // from the homepage, yet both still share the workspace
    // repository prefix.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
    };

    let repository_prefix = env!("CARGO_PKG_REPOSITORY");
    let issue_url = format_app_about_dialog_issue_url();
    let support_url = format_app_about_dialog_support_url();
    assert!(
        issue_url.starts_with(repository_prefix),
        "AdwAboutDialog issue-url must start with the workspace `CARGO_PKG_REPOSITORY` prefix {repository_prefix:?} so the bug-tracker link follows a workspace-wide repository move in lockstep; got {issue_url:?}",
    );
    assert!(
        support_url.starts_with(repository_prefix),
        "AdwAboutDialog support-url must start with the workspace `CARGO_PKG_REPOSITORY` prefix {repository_prefix:?} so the community-Q&A link follows a workspace-wide repository move in lockstep; got {support_url:?}",
    );
}

#[test]
fn format_app_header_bar_button_icon_names_are_valid_icon_theme_keys() {
    // Defense-in-depth sibling of the per-button
    // `_ends_with_symbolic_suffix` (HIG-conformant theming),
    // `_returns_X` (exact-value pin), and the cross-button
    // `format_app_header_bar_button_icon_names_are_distinct`
    // companions. Those existing tests catch the
    // wrong-suffix / wrong-value / duplicated-glyph regressions
    // but leave the broader icon-theme-key shape ungated.
    //
    // A `gtk::IconTheme::lookup_icon` consumer hands the icon
    // name verbatim to the theme; a regression that introduced
    // whitespace, a path separator, or a leading dot — e.g.
    // `"list add symbolic"` (space-separated), `"icons/list-add-symbolic"`
    // (path-style), or `".list-add-symbolic"` (hidden-file
    // prefix) — would silently fail the icon lookup at runtime
    // and fall back to the broken-image placeholder rather than
    // failing at compile or pinned-test time.
    //
    // The assertion loops over the three header-bar button
    // icon-name helpers (Add / search / menu) and pins each
    // value as non-empty, whitespace-free, and free of POSIX /
    // Windows path separators or dotfile prefixes so a future
    // regression in any of the three fails with a message that
    // names the offending button.
    use paladin_gtk::app::model::{
        format_app_add_button_icon_name, format_app_menu_button_icon_name,
        format_app_search_button_icon_name,
    };

    for (label, icon) in [
        ("Add", format_app_add_button_icon_name()),
        ("search", format_app_search_button_icon_name()),
        ("menu", format_app_menu_button_icon_name()),
    ] {
        assert!(
            !icon.is_empty(),
            "header-bar {label} button icon-name must be non-empty so `gtk::IconTheme::lookup_icon` resolves the symbolic glyph; got {icon:?}",
        );
        assert!(
            !icon.chars().any(char::is_whitespace),
            "header-bar {label} button icon-name must not contain whitespace; the icon-theme key is a single slug, not a multi-word phrase; got {icon:?}",
        );
        assert!(
            !icon.contains('/') && !icon.contains('\\'),
            "header-bar {label} button icon-name must not contain POSIX or Windows path separators; the icon-theme key is a bare slug, not a filesystem path; got {icon:?}",
        );
        assert!(
            !icon.starts_with('.'),
            "header-bar {label} button icon-name must not begin with a dot; a leading dot would mis-route the icon-theme lookup as a dotfile prefix; got {icon:?}",
        );
    }
}

#[test]
fn format_app_header_bar_button_tooltips_are_single_line_without_surrounding_whitespace() {
    // Cross-button defense-in-depth sibling of the per-button
    // `_is_non_empty` tooltip companions
    // (`format_app_add_button_tooltip_is_non_empty`,
    // `format_app_search_button_tooltip_is_non_empty`,
    // `format_app_menu_button_tooltip_is_non_empty`) and the
    // cross-button `format_app_header_bar_button_tooltips_are_distinct`
    // companion. Those tests guard the non-empty + distinct
    // invariants but leave the broader single-line / no-
    // surrounding-whitespace shape ungated.
    //
    // The `gtk::Button::set_tooltip_text` slot consumes the
    // string verbatim and renders it as a single-line tooltip
    // popover beneath the icon-only header-bar button (the
    // screen-reader-readable label, since the button has no
    // visible text label). A regression that introduced an
    // embedded newline — e.g. `"Add\naccount"` — would render
    // a vertically-stretched two-line tooltip and break the
    // visual alignment libadwaita expects. A leading or
    // trailing space — e.g. `" Add account"` — would shift the
    // popover content off the icon center and surface as a
    // confusing alignment glitch on tooltip render.
    //
    // The assertion loops over all three icon-only header-bar
    // button tooltip helpers (Add / search / menu) and pins
    // each value as single-line and surrounded by no
    // whitespace so a future regression in any of the three
    // fails with a message that names the offending button.
    // Mirrors the new
    // `format_app_header_bar_button_icon_names_are_valid_icon_theme_keys`
    // companion which pins the matching shape on the icon-name
    // side.
    use paladin_gtk::app::model::{
        format_app_add_button_tooltip, format_app_menu_button_tooltip,
        format_app_search_button_tooltip,
    };

    for (label, tooltip) in [
        ("Add", format_app_add_button_tooltip()),
        ("search", format_app_search_button_tooltip()),
        ("menu", format_app_menu_button_tooltip()),
    ] {
        assert!(
            !tooltip.contains('\n'),
            "header-bar {label} button tooltip must be a single line so the popover renders as one tidy caption rather than a vertically-stretched two-line block; got {tooltip:?}",
        );
        assert!(
            !tooltip.contains('\r'),
            "header-bar {label} button tooltip must use LF-only conventions (no embedded CR), matching the GNOME stack's text expectation for a single-line tooltip caption; got {tooltip:?}",
        );
        assert!(
            !tooltip.starts_with(char::is_whitespace),
            "header-bar {label} button tooltip must not start with whitespace; a leading space would shift the popover content off the icon center and surface as a confusing alignment glitch; got {tooltip:?}",
        );
        assert!(
            !tooltip.ends_with(char::is_whitespace),
            "header-bar {label} button tooltip must not end with whitespace; a trailing space would shift the popover content off the icon center and surface as a confusing alignment glitch; got {tooltip:?}",
        );
    }
}

#[test]
fn format_app_primary_menu_entries_labels_are_single_line_without_surrounding_whitespace() {
    // Cross-entry defense-in-depth sibling of the per-entry
    // `format_app_menu_X_label_returns_X` (exact-value pins),
    // `format_app_menu_X_label_ends_with_ellipsis` /
    // `_does_not_carry_ellipsis` (HIG suffix invariants), and
    // the cross-entry `format_app_primary_menu_entries_labels_are_distinct`
    // companion. Those existing tests catch the wrong-value /
    // wrong-suffix / collided-label regressions on a per-label
    // or cross-label basis but leave the broader single-line /
    // no-surrounding-whitespace shape ungated.
    //
    // The `gio::Menu::item_attribute_value(..., "label", ...)`
    // slot renders each entry as one row of the libadwaita
    // `PopoverMenu` opened off the header-bar `gtk::MenuButton`.
    // A regression that introduced an embedded newline — e.g.
    // `"Import\nfile…"` — would render across two rows of the
    // popover and break the tidy one-row-per-entry layout. A
    // leading or trailing space — e.g. `" Import…"` — would
    // shift the entry text inside the row and surface as a
    // confusing alignment glitch against its `gtk::Menu`
    // neighbours.
    //
    // The assertion walks every (label, action) pair returned
    // by `format_app_primary_menu_entries` so a regression in
    // any of the six entries (Import / Export / Passphrase /
    // Preferences / About / Quit) fails with a message that
    // names the offending entry's action target. Mirrors the
    // recent `format_app_header_bar_button_tooltips_are_single_line_without_surrounding_whitespace`
    // and `format_app_header_bar_button_icon_names_are_valid_icon_theme_keys`
    // siblings on the header-bar side.
    use paladin_gtk::app::model::format_app_primary_menu_entries;

    for (label, action) in format_app_primary_menu_entries() {
        assert!(
            !label.is_empty(),
            "primary menu entry label for action target {action:?} must be non-empty so the popover row renders; got {label:?}",
        );
        assert!(
            !label.contains('\n'),
            "primary menu entry label for action target {action:?} must be a single line so the popover renders one tidy row per entry rather than a vertically-stretched two-row block; got {label:?}",
        );
        assert!(
            !label.contains('\r'),
            "primary menu entry label for action target {action:?} must use LF-only conventions (no embedded CR), matching the GNOME stack's text expectation for a single-line menu-entry label; got {label:?}",
        );
        assert!(
            !label.starts_with(char::is_whitespace),
            "primary menu entry label for action target {action:?} must not start with whitespace; a leading space would shift the entry text inside the popover row and surface as an alignment glitch against its menu neighbours; got {label:?}",
        );
        assert!(
            !label.ends_with(char::is_whitespace),
            "primary menu entry label for action target {action:?} must not end with whitespace; a trailing space would shift the entry text inside the popover row and surface as an alignment glitch against its menu neighbours; got {label:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_application_icon_name_segments_are_non_empty() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_application_icon_name_matches_app_id`
    // (which pins the exact value against `APP_ID`) and
    // `format_app_about_dialog_application_icon_name_is_reverse_dns`
    // (which pins non-empty, contains-a-`.`, no whitespace,
    // distinct from program-name). Those existing companions
    // catch the wrong-value / wrong-shape / wrong-token
    // regressions but leave the per-segment shape ungated, so a
    // future refactor that introduced consecutive dots — e.g.
    // `"org..tamx.Paladin.Gui"` — or a leading or trailing dot —
    // e.g. `".org.tamx.Paladin.Gui"` / `"org.tamx.Paladin.Gui."` —
    // would slip past `_is_reverse_dns` (which just checks
    // `contains('.')`) while breaking the icon-theme-key /
    // desktop-entry / AppStream / Flatpak app-id contract.
    //
    // The libadwaita / GIO `g_application_id_is_valid` check
    // rejects identifiers with empty `.`-separated components,
    // so a regression here would surface as a runtime
    // `Application::new` panic / icon-theme miss / Flatpak
    // packaging failure rather than as a failing test. Pinning
    // the per-segment non-emptiness at the test layer catches
    // that drift before it ships.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon = format_app_about_dialog_application_icon_name();
    let segments: Vec<&str> = icon.split('.').collect();
    assert!(
        segments.len() >= 2,
        "AdwAboutDialog application-icon must be a reverse-DNS identifier with at least two `.`-separated segments so the icon-theme / Flatpak app-id contract holds; got only {} segment(s) in {icon:?}",
        segments.len(),
    );
    for (idx, segment) in segments.iter().enumerate() {
        assert!(
            !segment.is_empty(),
            "AdwAboutDialog application-icon reverse-DNS segment at position {idx} must be non-empty so the `g_application_id_is_valid` contract holds and the icon-theme / Flatpak app-id lookup resolves; consecutive or terminal `.` characters are not allowed; got {icon:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_use_control_modifier() {
    // Defense-in-depth sibling of
    // `format_app_window_accelerator_bindings_accelerators_carry_modifier_prefix`
    // which pins each accelerator starts with a non-empty
    // `<…>` modifier block followed by a keysym, but leaves the
    // *which* modifier ungated. A regression that swapped one
    // shortcut's modifier — e.g. `<Shift>n` for the Add button
    // or `<Alt>q` for Quit — would still pass the per-prefix
    // companion (the angle-bracket modifier block is still
    // present) while diverging from the GNOME convention that
    // primary application actions use the `<Control>` modifier
    // alone. `<Shift>` + a letter intercepts capital-letter
    // text entry in dialog `gtk::Entry` rows; `<Alt>` collides
    // with the GTK mnemonic-accelerator surface on labels.
    //
    // The assertion walks every bundled `(accel, target)` pair
    // and pins each accelerator to start with the `<Control>`
    // modifier block (the gtk-rs `accels_for_action` form;
    // GTK case-folds modifier names so we use the docstring's
    // `<Control>` spelling for the literal compare). Pins the
    // GNOME-convention choice at the test layer so a future
    // refactor that drifted any of the three primary shortcuts
    // off `<Control>` fails the test with a message naming the
    // offending action target rather than only being noticed
    // when a user pressed the shortcut and saw the wrong
    // surface open or no surface open at all.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        assert!(
            accel.starts_with("<Control>"),
            "format_app_window_accelerator_bindings accelerator for target {target:?} must begin with the `<Control>` modifier so primary application actions follow the GNOME convention (a `<Shift>`-modified letter would intercept capital-letter text entry in dialog gtk::Entry rows; an `<Alt>`-modified letter would collide with the GTK mnemonic-accelerator surface); got {accel:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_carry_exactly_one_modifier_block() {
    // Defense-in-depth sibling of
    // `format_app_window_accelerator_bindings_accelerators_use_control_modifier`
    // (which pins the leading `<Control>` modifier block) and
    // `format_app_window_accelerator_bindings_accelerators_carry_modifier_prefix`
    // (which pins each accelerator starts with a non-empty `<…>`
    // block followed by a keysym). Both companions guard the
    // single-block / `<Control>` invariants but leave the
    // exactly-one-modifier-block invariant ungated, so a future
    // refactor that compounded modifiers — e.g.
    // `"<Control><Shift>n"` or `"<Control><Alt>q"` — would slip
    // past the leading-prefix check while diverging from the
    // single-modifier GNOME convention and intercepting a
    // different keyboard shortcut surface than the docstring on
    // each per-accelerator helper claims.
    //
    // Mirrors the `gio::Application::set_accels_for_action` form
    // for the primary menu shortcuts: the GNOME convention is
    // one modifier per primary application action; compound
    // modifiers belong on power-user shortcuts (text-buffer
    // operations, IDE-style multi-modifier chords) which do not
    // currently appear in the application menu surface.
    //
    // The assertion counts the `<` and `>` ASCII bytes in each
    // accelerator: an exactly-one-block accelerator like
    // `"<Control>n"` has one `<` and one `>`. A compound
    // `"<Control><Shift>n"` would have two each. The keysym
    // segment (`"n"`, `"q"`, `"comma"`, etc.) contains no angle
    // brackets so the count maps directly to the modifier-block
    // count.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        let open_count = accel.bytes().filter(|&b| b == b'<').count();
        let close_count = accel.bytes().filter(|&b| b == b'>').count();
        assert_eq!(
            open_count, 1,
            "format_app_window_accelerator_bindings accelerator for target {target:?} must contain exactly one `<` ASCII byte so the single-modifier-block GNOME convention holds; compound modifiers like `<Control><Shift>n` belong on power-user shortcuts not primary application actions; got {open_count} `<` byte(s) in {accel:?}",
        );
        assert_eq!(
            close_count, 1,
            "format_app_window_accelerator_bindings accelerator for target {target:?} must contain exactly one `>` ASCII byte so the single-modifier-block GNOME convention holds; got {close_count} `>` byte(s) in {accel:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_have_a_non_empty_keysym_after_the_modifier_block(
) {
    // Defense-in-depth sibling of
    // `format_app_window_accelerator_bindings_accelerators_carry_exactly_one_modifier_block`
    // (which pins exactly one `<` and one `>` ASCII byte per
    // accelerator) and
    // `format_app_window_accelerator_bindings_accelerators_carry_modifier_prefix`
    // (which pins each accelerator starts with a non-empty `<…>`
    // block). Both companions guard the modifier-block shape but
    // leave the keysym-after-the-block invariant ungated, so a
    // future refactor that dropped the trailing keysym — e.g.
    // `"<Control>"` for any of the three primary surfaces — would
    // still have exactly one modifier block and the leading
    // `<Control>` prefix while binding no key at all, silently
    // unbinding the documented Add / Quit / Preferences shortcut
    // surface.
    //
    // Scoped to a pure string-shape check rather than a second
    // `gtk::accelerator_parse` call so it stays parallel-safe with
    // the gtk::init-using parse sibling
    // (`format_app_window_accelerator_bindings_parse_via_gtk_accelerator_parse`)
    // without an Once-gated init helper. The assertion finds the
    // closing `>` byte (already pinned to exactly one occurrence
    // by the `_carry_exactly_one_modifier_block` companion) and
    // checks that the substring after it is non-empty so a
    // regression that returned `"<Control>"` for any of the three
    // primary keyboard surfaces fails at the pinned layer rather
    // than only surfacing when a user pressed `Ctrl+N` and nothing
    // happened.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        let close_index = accel.bytes().position(|b| b == b'>').unwrap_or_else(|| {
            panic!(
                "format_app_window_accelerator_bindings accelerator for target {target:?} must contain a `>` ASCII byte closing the modifier block; got {accel:?}",
            )
        });
        let keysym = &accel[close_index + 1..];
        assert!(
            !keysym.is_empty(),
            "format_app_window_accelerator_bindings accelerator for target {target:?} must carry a non-empty keysym after the `<…>` modifier block so the documented keyboard surface actually binds a key; an accelerator like `<Control>` alone has a valid modifier block but binds no key and silently unbinds the documented shortcut surface; got keysym {keysym:?} in {accel:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_contain_no_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_window_accelerator_bindings_accelerators_have_a_non_empty_keysym_after_the_modifier_block`
    // (which pins a non-empty keysym suffix) and
    // `format_app_window_accelerator_bindings_accelerators_carry_exactly_one_modifier_block`
    // (which pins exactly one `<…>` block) and
    // `format_app_window_accelerator_bindings_parse_via_gtk_accelerator_parse`
    // (which round-trips each spelling through gtk::accelerator_parse
    // but skips without a display server).
    //
    // Both shape companions pin the modifier-block boundaries and
    // a non-empty trailing keysym but leave the embedded-whitespace
    // case ungated. A regression like `"<Control> n"` (a stray
    // space between the modifier and the keysym), `"<Control>n "`
    // (a trailing space), or `"<Control>\nn"` (an embedded
    // newline) would slip past the per-shape companions: the
    // outer block count and the non-empty keysym suffix both still
    // hold, while `gtk::accelerator_parse` would reject the
    // spelling at runtime — but the parse-side companion skips on
    // CI environments that lack a display server, so the pure
    // string-shape rule needs to hold independently.
    //
    // Scoped to a pure string-shape check rather than a second
    // `gtk::accelerator_parse` call so it stays parallel-safe
    // with the gtk::init-using parse sibling without an Once-gated
    // init helper. Pins the no-whitespace invariant against a
    // single source of truth so a future drift fails at the
    // pinned layer with a message naming the offending action
    // target rather than only surfacing on a display-equipped CI
    // run.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        assert!(
            !accel.chars().any(char::is_whitespace),
            "format_app_window_accelerator_bindings accelerator for target {target:?} must contain no whitespace so gtk::accelerator_parse accepts the spelling on every platform; an embedded space like `<Control> n`, a trailing space like `<Control>n `, or an embedded newline like `<Control>\\nn` would parse as a different keysym or fail to parse and silently unbind the documented shortcut surface; got {accel:?}",
        );
    }
}

#[test]
fn format_app_window_action_names_use_ascii_lowercase_only() {
    // Defense-in-depth sibling of
    // `format_app_window_action_names_are_distinct` (which pins
    // pairwise distinctness of the seven bare action names) and
    // `format_app_window_action_names_lists_the_six_primary_menu_entries_then_add`
    // (which pins the slot layout). Those companions catch the
    // duplicate-name and wrong-order regressions but leave the
    // case-folding edge case ungated.
    //
    // The libadwaita / GLib convention for `gio::SimpleAction`
    // names is lowercase ASCII, and the existing per-name
    // exact-value pins (`_returns_import` through `_returns_quit`,
    // plus `_add_button_action_name_returns_add`) lock each name
    // to a lowercase literal. The `dispatch_app_window_action`
    // helper is also case-sensitive on the bare name (per
    // `dispatch_app_window_action_is_case_sensitive`). A regression
    // that introduced an upper-case letter on the bundled-array
    // side — e.g. renaming `"add"` to `"Add"` while leaving the
    // per-name helper at `"add"` — would slip past the
    // distinctness / ordering companions while mis-routing the
    // `gio::SimpleAction` activation through the case-sensitive
    // dispatch helper at runtime.
    //
    // Pinning the cross-array all-lowercase invariant here closes
    // that gap so the casing regression surfaces as a failing
    // test with a message that names the offending bundled
    // index, not as a no-op SimpleAction activation. Mirrors the
    // recent `format_app_header_bar_button_icon_names_use_lowercase_kebab_case`
    // sibling on the icon-name side.
    use paladin_gtk::app::model::format_app_window_action_names;

    for (idx, name) in format_app_window_action_names().iter().enumerate() {
        for ch in name.chars() {
            assert!(
                ch.is_ascii_lowercase(),
                "format_app_window_action_names[{idx}] = {name:?} must use lowercase ASCII letters only so the dispatch_app_window_action case-sensitive lookup resolves; got disallowed character {ch:?} (libadwaita / GLib convention for SimpleAction names is lowercase, and the per-name exact-value pins lock each helper to a lowercase literal)",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_copyright_separates_glyph_and_attribution_with_a_single_space() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    // (which pins the leading `©` glyph and the embedded
    // developer-name attribution) and
    // `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    // (which pins the no-year invariant). Those companions catch
    // the wrong-glyph / wrong-attribution / drifting-year
    // regressions but leave the *glyph-attribution separator*
    // ungated.
    //
    // The libadwaita HIG (and GNOME copyright convention generally)
    // renders the legal `©` glyph and the attribution string with
    // a single space between them: `"© <attribution>"`. A
    // regression that dropped the space — `"©The Paladin contributors"` —
    // would still pass the existing companions (the `©` glyph is
    // still the leading char and the developer-name is still a
    // substring) while rendering as a visually-cramped footer
    // row where the glyph and attribution have no breathing
    // space. A regression that doubled the space —
    // `"©  The Paladin contributors"` — would slip past the
    // existing companions for the same reason while pushing the
    // attribution off the expected baseline alignment.
    //
    // The assertion checks the first two chars of the copyright
    // literal are exactly the `©` glyph followed by a single
    // ASCII space byte. Mirrors the per-character pin pattern
    // used by `_starts_with_copyright_glyph_and_contains_developer_name`
    // on the leading glyph alone.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    let mut chars = copyright.chars();
    let first = chars
        .next()
        .unwrap_or_else(|| panic!("AdwAboutDialog copyright must be non-empty; got {copyright:?}"));
    assert_eq!(
        first, '\u{00A9}',
        "AdwAboutDialog copyright must begin with the `©` (U+00A9) glyph; got {first:?} in {copyright:?}",
    );
    let second = chars.next().unwrap_or_else(|| {
        panic!(
            "AdwAboutDialog copyright must have content after the `©` glyph (one-space separator + attribution); got {copyright:?}",
        )
    });
    assert_eq!(
        second, ' ',
        "AdwAboutDialog copyright must use a single ASCII space between the `©` glyph and the attribution string so the footer row renders with GNOME-standard breathing space; a missing or doubled space would surface as a cramped or off-baseline footer alignment; got {second:?} in {copyright:?}",
    );
    let third = chars.next();
    assert!(
        third.is_some_and(|c| !c.is_whitespace()),
        "AdwAboutDialog copyright must have exactly one space between the `©` glyph and the attribution (a second whitespace char would double the separator and push the attribution off the baseline); got {third:?} in {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_ends_with_gui_segment() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_application_icon_name_matches_app_id`
    // (which pins the exact value against `APP_ID`),
    // `_is_reverse_dns` (which pins the `.`-separated shape), and
    // `_segments_are_non_empty` (which pins each `.`-separated
    // segment is non-empty). Those companions catch the
    // wrong-value / wrong-shape / empty-segment regressions but
    // leave the trailing `.Gui` segment ungated.
    //
    // The reverse-DNS app-id namespace `org.tamx.Paladin.*` is
    // shared between the GTK GUI (`org.tamx.Paladin.Gui`) and
    // any future surface — a CLI Flatpak would presumably use
    // `org.tamx.Paladin.Cli`, a daemon variant `org.tamx.Paladin.Daemon`,
    // and so on. The `.Gui` suffix is what distinguishes this
    // crate's Flatpak identity from those siblings; a regression
    // that dropped the suffix to `"org.tamx.Paladin"` or swapped
    // it to `"org.tamx.Paladin.Cli"` would still pass the
    // existing `_is_reverse_dns` and `_segments_are_non_empty`
    // companions (both invariants still hold) while colliding
    // with the surface name reserved for a different front-end
    // on Flathub / hicolor icon-theme / desktop-entry lookups.
    //
    // Pinning `.ends_with(".Gui")` here keeps the GUI's reverse-
    // DNS identity stable across releases and forces an explicit
    // decision if a future workspace rename moves the GUI off
    // the `.Gui` slot. Sibling of
    // `format_app_about_dialog_program_name_is_segment_of_application_icon_name`
    // (which ties the human program-name into the icon-name via
    // the brand-string segment); together they pin both the
    // brand-string and the front-end-distinguishing segment
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon = format_app_about_dialog_application_icon_name();
    assert!(
        icon.ends_with(".Gui"),
        "AdwAboutDialog application-icon must end with `.Gui` to distinguish this crate's reverse-DNS Flatpak identity from a future CLI / daemon front-end sharing the `org.tamx.Paladin.*` namespace; got {icon:?}",
    );
}

#[test]
fn format_app_header_bar_button_icon_names_use_lowercase_kebab_case() {
    // Defense-in-depth sibling of the recent
    // `format_app_header_bar_button_icon_names_are_valid_icon_theme_keys`
    // (which pins non-empty, no-whitespace, no path separators, no
    // dotfile prefix) and the per-button `_ends_with_symbolic_suffix`
    // (HIG-conformant theming) / `_returns_X` (exact-value pin)
    // companions. Those existing checks catch the obviously-broken
    // icon-theme-key shapes but leave the casing / separator
    // convention ungated.
    //
    // The freedesktop icon-theme spec requires icon names to use
    // lowercase ASCII letters, digits, and hyphens — the GNOME
    // stack's `gtk::IconTheme::lookup_icon` is case-sensitive on
    // the bare slug, so a regression like `"List-Add-Symbolic"`
    // (PascalCase) or `"list_add_symbolic"` (underscores instead
    // of hyphens) would silently fail the icon-theme lookup at
    // runtime and fall back to the broken-image placeholder rather
    // than failing at compile or pinned-test time, because the
    // existing companions only check for whitespace / path
    // separators / dotfile prefixes — none of which fire for an
    // upper-case or underscore-separated key.
    //
    // The assertion loops over the three header-bar button
    // icon-name helpers (Add / search / menu) and pins each
    // character as either an ASCII lowercase letter, an ASCII
    // digit, or a `-` byte so a regression in any of the three
    // fails with a message that names both the offending button
    // and the offending character.
    use paladin_gtk::app::model::{
        format_app_add_button_icon_name, format_app_menu_button_icon_name,
        format_app_search_button_icon_name,
    };

    for (label, icon) in [
        ("Add", format_app_add_button_icon_name()),
        ("search", format_app_search_button_icon_name()),
        ("menu", format_app_menu_button_icon_name()),
    ] {
        for ch in icon.chars() {
            assert!(
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-',
                "header-bar {label} button icon-name must use lowercase ASCII letters, digits, and `-` only (freedesktop icon-theme convention); got disallowed character {ch:?} in {icon:?}",
            );
        }
    }
}

#[test]
fn dispatch_app_window_action_is_case_sensitive() {
    // Defense-in-depth sibling of
    // `dispatch_app_window_action_returns_none_for_unknown_action_names`
    // (which pins that unknown / empty bare names resolve to `None`)
    // and `dispatch_app_window_action_covers_every_bundled_action_name`
    // (which pins that every bundled name resolves to `Some`).
    // Those companions guard the pinned / unknown ends but leave
    // the case-folding edge case ungated, so a regression that
    // re-wrote the dispatch table with `.eq_ignore_ascii_case` or
    // `.to_lowercase()` would still satisfy both companions while
    // accepting an off-case bare name from a `gio::SimpleActionGroup`
    // lookup that mis-bound an action under e.g. `"ADD"` or `"Quit"`.
    //
    // The libadwaita `gio::Action` infrastructure spells every
    // registered name lowercase per
    // [`format_app_menu_<X>_action_name_returns_<X>` exact-value
    // pins], and `gio::SimpleActionGroup::activate_action` is
    // case-sensitive on the bare name lookup. Pinning the
    // dispatch helper to mirror that case-sensitivity here
    // catches a future drift before it surfaces as a runtime
    // mismatch between the SimpleAction registered on the group
    // and the AppMsg variant routed off the activation.
    use paladin_gtk::app::model::dispatch_app_window_action;

    for bare in ["ADD", "Add", "ABOUT", "About", "Quit", "QUIT"] {
        assert!(
            dispatch_app_window_action(bare).is_none(),
            "dispatch_app_window_action must be case-sensitive so the off-case bare name {bare:?} resolves to None and stays a benign no-op rather than dispatching to the matching AppMsg variant a future case-folding regression would accept",
        );
    }
}

#[test]
fn format_app_primary_menu_action_names_are_distinct() {
    // Cross-name defense-in-depth sibling of the per-name
    // `format_app_menu_<X>_action_name_returns_<X>` exact-value
    // pins and the per-name `_has_no_separator_or_whitespace` /
    // `_round_trips_with_group_and_target` companions, plus the
    // cross-entry `format_app_primary_menu_entries_actions_are_distinct`
    // (fully-qualified target side) and `_entries_labels_are_distinct`
    // (visible label side) companions on the entry-pair array.
    //
    // The bundled `format_app_primary_menu_action_names` array
    // returns the six bare action names the widget binding hands
    // to `gio::SimpleAction::new(name, None)` per
    // §"libadwaita usage". Two bare names collapsing onto the same
    // string — e.g. a rename that left both `"import"` and
    // `"export"` pointing at `"import"` — would let the second
    // `SimpleAction::new` silently overwrite the first inside the
    // `gio::SimpleActionGroup` (it accepts duplicate inserts
    // without raising) and route both menu entries' activations
    // to the same `connect_activate` closure. Pinning the six
    // bare names as pairwise distinct here catches that drift at
    // the test layer with a message that names both colliding
    // entries instead of only surfacing when a user clicked the
    // second-registered entry and saw the first-registered
    // dialog open.
    //
    // The per-name exact-value pins (`_returns_<X>`) catch the
    // single-name wrong-value regression, and the cross-entry
    // distinctness pins on the entry-pair array catch the label
    // / target side; this assertion completes the bracket by
    // pinning the bare-name array on the same distinctness
    // invariant.
    use paladin_gtk::app::model::format_app_primary_menu_action_names;

    let names = format_app_primary_menu_action_names();
    for (i, name_i) in names.iter().enumerate() {
        for (j, name_j) in names.iter().enumerate().skip(i + 1) {
            assert_ne!(
                name_i, name_j,
                "format_app_primary_menu_action_names entries at indices {i} and {j} must be distinct so the bundled SimpleActionGroup does not silently overwrite one entry with another (gio::SimpleActionGroup::add_action accepts duplicate bare names without raising); got duplicate {name_i:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_debug_info_program_name_line_ends_with_the_version() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_app_id_line_ends_with_the_reverse_dns_app_id`
    // (which pins the trailing-token shape on the *machine-
    // oriented* App ID line) and
    // `format_app_about_dialog_debug_info_starts_with_program_name`
    // (which pins the leading content). Those companions guard
    // the App ID line's trailing shape and the very first byte of
    // the payload but leave the *human-readable* program-name
    // line's trailing shape ungated, so a regression like
    // `"Paladin 0.1.0 (Linux)"` (host OS appended), `"Paladin 0.1.0 — git: abcd"`
    // (build-info appended), or `"Paladin 0.1.0 "` (trailing
    // space) would slip past the existing companions while
    // quietly expanding the bug-report payload beyond the
    // deliberately minimal `"Paladin <version>"` shape the
    // `format_app_about_dialog_debug_info` docstring renders in
    // its example.
    //
    // Pinning `.ends_with(version)` on the program-name line
    // forces the line to terminate with the package version
    // string exactly, so a future commit that appended any
    // trailing tokens to the human-readable line — even a
    // trailing space — has to either drop the trailing content
    // or update this assertion in the same commit. Both outcomes
    // are fine; the forcing function is that the decision becomes
    // explicit rather than slipping in as a silent expansion of
    // the bug-report payload past its pinned minimum.
    //
    // Completes the bracket on both endpoints of the two-line
    // payload's interior shape alongside the App ID line sibling:
    // line 1 begins with the human program-name and ends with
    // the version; line 2 begins with the `App ID:` label and
    // ends with the reverse-DNS identifier.
    use paladin_gtk::app::model::{
        format_app_about_dialog_debug_info, format_app_about_dialog_program_name,
        format_app_about_dialog_version,
    };

    let debug = format_app_about_dialog_debug_info();
    let program_name = format_app_about_dialog_program_name();
    let version = format_app_about_dialog_version();
    let program_name_line = debug
        .lines()
        .find(|line| line.contains(program_name))
        .unwrap_or_else(|| {
            panic!(
                "AdwAboutDialog debug-info must have at least one line containing the program-name display string {program_name:?}; got {debug:?}",
            )
        });
    assert!(
        program_name_line.ends_with(version),
        "AdwAboutDialog debug-info program-name line must end with the package version {version:?} exactly (no trailing tokens like ` (Linux)` or ` — git: abcd`) so the bug-report payload stays deliberately minimal and a future expansion has to first update this pin; got {program_name_line:?} in {debug:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_app_id_line_ends_with_the_reverse_dns_app_id() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_app_id_appears_on_a_distinct_line_from_program_name`
    // (which pins that the App ID and program-name segments land on
    // distinct lines via `.contains()` matching) and
    // `format_app_about_dialog_debug_info_has_exactly_two_lines`
    // (which pins the overall line count). Those companions still
    // allow trailing tokens after the App ID on its line — e.g.
    // `"App ID: org.tamx.Paladin.Gui (Flatpak)"` or
    // `"App ID: org.tamx.Paladin.Gui — host: linux"` — which would
    // slip past the `.contains()` companion while quietly expanding
    // the bug-report payload beyond the deliberately minimal
    // `App ID: <reverse-dns>` shape the `format_app_about_dialog_debug_info`
    // docstring renders in its example.
    //
    // Pinning `.ends_with(app_id)` on the App ID line forces the
    // line to terminate with the reverse-DNS identifier exactly,
    // so a future commit that appended any trailing tokens to the
    // machine-oriented line — even a trailing space — has to
    // either update the implementation to drop the trailing
    // content or update this assertion in the same commit. Both
    // outcomes are fine; the forcing function is that the
    // decision becomes explicit rather than slipping in as a
    // silent expansion of the bug-report payload past its pinned
    // minimum.
    //
    // Sibling of `format_app_about_dialog_debug_info_starts_with_program_name`
    // on the leading-line side; together they pin both endpoints
    // of the two-line payload (line 1 begins with the human
    // program-name; line 2 ends with the machine app ID) against
    // a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_debug_info,
    };

    let debug = format_app_about_dialog_debug_info();
    let app_id = format_app_about_dialog_application_icon_name();
    let app_id_line = debug
        .lines()
        .find(|line| line.contains(app_id))
        .unwrap_or_else(|| {
            panic!(
                "AdwAboutDialog debug-info must have at least one line containing the reverse-DNS app ID {app_id:?}; got {debug:?}",
            )
        });
    assert!(
        app_id_line.ends_with(app_id),
        "AdwAboutDialog debug-info App ID line must end with the reverse-DNS app ID {app_id:?} exactly (no trailing tokens like ` (Flatpak)` or ` — host: linux`) so the bug-report payload stays deliberately minimal and a future expansion has to first update this pin; got {app_id_line:?} in {debug:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_contain_no_embedded_whitespace() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of *any* `char::is_whitespace` byte — not
    // just the bare ASCII space byte the per-URL
    // `_is_non_empty_https_url[*_distinct*]` companions already
    // check.
    //
    // The existing per-URL companions assert `!url.contains(' ')`
    // but leave embedded `\n`, `\t`, `\r`, and other Unicode
    // whitespace characters ungated. A regression like
    // `"https://paladin.tamx.org\n"` (trailing newline), an
    // accidental `"\thttps://github.com/.../issues"` (leading
    // tab), or `"https://github.com/.../discussions "`
    // (trailing space — caught by the existing check but
    // restated here so the rule is documented in one place)
    // would slip past the per-URL companions while still being
    // an invalid URL spelling that Adwaita would render as a
    // broken footer link.
    //
    // Sibling of `format_app_about_dialog_issue_url_and_support_url_share_cargo_pkg_repository_prefix`
    // (cross-URL prefix consistency) and the per-URL
    // `_is_non_empty_https_url[*_distinct*]` companions; together
    // they pin the full URL-shape contract across all three
    // footer link surfaces against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.chars().any(char::is_whitespace),
            "AdwAboutDialog {label} must contain no whitespace so Adwaita renders a valid footer link rather than a broken URL with an embedded `\\n`, `\\t`, or stray space; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_copyright_is_a_single_line_without_embedded_newlines() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_copyright_returns_paladin_copyright_line`
    // (exact-value pin),
    // `format_app_about_dialog_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    // (positive shape pin on the leading glyph + attribution),
    // and
    // `format_app_about_dialog_copyright_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    // (negative pin against year drift). Those companions catch
    // the wrong-value / wrong-prefix / drifting-year regressions
    // but leave the embedded-newline edge case ungated.
    //
    // The `AdwAboutDialog::copyright` property is consumed as a
    // single-line attribution in the dialog footer (one line
    // below the license-type chip and above the website / issue
    // links). A regression that put a `\n` inside the copyright
    // literal — e.g. `"© The Paladin\ncontributors"` — would
    // render as a vertically-stretched two-line block in the
    // dialog footer and visually misalign the footer cluster
    // against the website / issue-link rows beneath it. Mirror
    // of the `_developer_name_is_a_single_line_without_embedded_newlines`
    // companion on the dialog-header side; together they pin the
    // single-line shape on both the header attribution row and
    // the footer copyright row against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\n'),
        "AdwAboutDialog copyright must be a single line so the dialog footer renders as one tidy caption above the website / issue-link cluster rather than as a vertically-stretched two-line block; got {copyright:?}",
    );
    assert!(
        !copyright.contains('\r'),
        "AdwAboutDialog copyright must use LF-only conventions (no embedded CR), matching the GNOME stack's text expectation for a single-line attribution caption; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_end_with_a_period_per_libadwaita_convention() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_comments_matches_cargo_pkg_description`
    // (exact-value pin sourcing from `env!("CARGO_PKG_DESCRIPTION")`)
    // and
    // `format_app_about_dialog_comments_is_non_empty_single_line_distinct_from_program_name`
    // (positive shape pin on non-empty + single-line + distinct).
    // Those companions catch the wrong-source and wrong-shape
    // regressions but leave the trailing-punctuation edge case
    // ungated.
    //
    // The libadwaita / GNOME HIG convention for the
    // `AdwAboutDialog::comments` slot is a short single-sentence
    // fragment without trailing punctuation — the caption renders
    // directly under the program-name header where a stray
    // sentence-final period reads as a typographic awkwardness
    // (the surrounding header rows have no trailing punctuation
    // either, so a period on the comments row would visually
    // single-out that one caption). Peer GNOME apps (e.g.
    // GNOME Authenticator's "Two-Factor Authentication") follow
    // the same convention.
    //
    // The current workspace `[workspace.package].description`
    // value is `"Paladin: Rust OTP authenticator (TOTP + HOTP)
    // with CLI, TUI, and GTK front-ends"` — already periodless
    // and convention-compliant. A future workspace description
    // edit that added a trailing `.` (e.g. `"... front-ends."`)
    // would propagate through the `description.workspace = true`
    // inheritance chain into the `AdwAboutDialog` comments slot
    // without any per-helper change, slipping past the
    // `_matches_cargo_pkg_description` exact-value pin (which
    // tracks the upstream value) and the `_is_non_empty_single_line`
    // shape pin (which only checks non-emptiness and embedded
    // newlines). Pinning the no-trailing-period invariant here
    // is a forcing function so the next workspace-description
    // edit gets caught at the GTK layer rather than as a visual
    // HIG inconsistency surfacing only when a contributor opens
    // the About dialog.
    //
    // Mirror of the
    // `format_app_about_dialog_copyright_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    // companion on the footer side; both are negative pins
    // against drift-prone shape regressions on the
    // `AdwAboutDialog` header / footer caption surfaces.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.ends_with('.'),
        "AdwAboutDialog comments must not end with a sentence-final period per the libadwaita / GNOME HIG convention for short caption fragments under the program-name header; got {comments:?}",
    );
    assert!(
        !comments.ends_with('!'),
        "AdwAboutDialog comments must not end with `!` per the libadwaita / GNOME HIG convention for short caption fragments under the program-name header; got {comments:?}",
    );
    assert!(
        !comments.ends_with('?'),
        "AdwAboutDialog comments must not end with `?` per the libadwaita / GNOME HIG convention for short caption fragments under the program-name header; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_has_no_surrounding_whitespace_when_non_empty() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_translator_credits_is_empty_until_translations_land`
    // (exact-value pin to the empty literal) and
    // `format_app_about_dialog_translator_credits_is_single_line_when_non_empty`
    // (positive shape pin against embedded newlines once the
    // gettext swap lands). Those companions catch the wrong-value
    // and embedded-newline regressions but leave the
    // surrounding-whitespace edge case ungated.
    //
    // Once gettext is wired up and this helper is swapped to
    // `gettext("translator-credits")`, a translator could submit
    // a `.po` entry like `" Bob Smith\n"` or `"\tBob Smith"` —
    // a single space, tab, or trailing newline survives the
    // gettext lookup and propagates straight into the
    // `AdwAboutDialog::translator_credits` slot. The credits-page
    // "Translators" row renders the value inline, so a leading
    // space would push the name off the left baseline and a
    // trailing space would leave a hanging gap on the right.
    // The embedded-newline companion catches `"Bob\nSmith"`
    // (newline mid-string) but does not catch the leading-tab /
    // trailing-space case.
    //
    // Pinning the no-surrounding-whitespace invariant here is a
    // forcing function so the next contributor wires gettext
    // alongside the per-locale `.po` review that strips
    // accidental padding rather than letting the credit row
    // visually misalign on the credits page. The current empty-
    // literal state trivially passes (no surrounding whitespace
    // to strip), so the test stays green now and serves as a
    // canary on the gettext swap. Mirror of the
    // `_comments_is_non_empty_single_line_distinct_from_program_name`
    // companion which already pins the same no-surrounding-
    // whitespace invariant on the program-header caption side;
    // together they pin the no-padding shape on both the header
    // caption and the credits-page translator row against a
    // single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let credits = format_app_about_dialog_translator_credits();
    if !credits.is_empty() {
        assert!(
            !credits.starts_with(char::is_whitespace),
            "AdwAboutDialog translator-credits must not start with whitespace so the credits-page Translators row renders flush against the left baseline; got {credits:?}",
        );
        assert!(
            !credits.ends_with(char::is_whitespace),
            "AdwAboutDialog translator-credits must not end with whitespace so the credits-page Translators row does not leave a hanging gap on the right; got {credits:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_release_notes_has_no_surrounding_whitespace_when_non_empty() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_release_notes_is_empty_until_v0_2_ships`
    // (exact-value pin to the empty literal),
    // `format_app_about_dialog_release_notes_must_be_paired_with_a_non_empty_version_when_non_empty`
    // (cross-helper version-pairing pin), and the matching
    // `_release_notes_version_matches_*` companions. Those
    // companions catch the wrong-value, missing-version, and
    // wrong-version regressions but leave the
    // surrounding-whitespace edge case ungated.
    //
    // Once v0.2 ships and this helper swaps from the empty
    // literal to a non-empty Pango / AdwAbout markup body, a
    // contributor could accidentally embed leading or trailing
    // whitespace — e.g. a copy-paste from a draft `RELEASE_NOTES.md`
    // that brought along a leading blank line (`"\n<p>…</p>"`)
    // or a trailing newline before the closing literal
    // (`"<p>…</p>\n"`). `AdwAboutDialog` renders the "What's New"
    // body verbatim, so a leading newline pushes the first
    // paragraph off the top baseline (creating a visual gap
    // between the version header and the first bullet) and a
    // trailing newline pads the bottom of the section against
    // the dialog's next row.
    //
    // The libadwaita convention is that the body starts and
    // ends with a markup element (e.g. `<p>` / `</p>` or
    // `<ul>` / `</ul>`) with no surrounding whitespace — the
    // section's vertical rhythm is then driven by Adwaita's
    // baseline grid, not by accidental newlines in the literal.
    // Pinning the no-surrounding-whitespace invariant here is a
    // forcing function so the v0.2 release-notes copy lands
    // properly trimmed rather than as a visually misaligned
    // "What's New" section. The current empty-literal state
    // trivially passes (no whitespace to strip), so the test
    // stays green now and serves as a canary on the v0.2 swap.
    //
    // Mirror of the
    // `_translator_credits_has_no_surrounding_whitespace_when_non_empty`
    // sibling pinned on the credits-page Translators row;
    // together they pin the no-padding shape across the two
    // "empty until contributor lands content" `AdwAboutDialog`
    // sections (What's New and Translators) against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    if !release_notes.is_empty() {
        assert!(
            !release_notes.starts_with(char::is_whitespace),
            "AdwAboutDialog release-notes must not start with whitespace so the What's New section's first paragraph renders flush against the version-header baseline rather than with a leading vertical gap; got {release_notes:?}",
        );
        assert!(
            !release_notes.ends_with(char::is_whitespace),
            "AdwAboutDialog release-notes must not end with whitespace so the What's New section's final paragraph closes flush against the next dialog row rather than with trailing padding; got {release_notes:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_has_no_surrounding_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developer_name_returns_the_paladin_contributors`
    // (exact-value pin),
    // `format_app_about_dialog_developer_name_is_non_empty_and_distinct_from_program_name`
    // (positive shape pin on non-empty + distinct), and
    // `format_app_about_dialog_developer_name_is_a_single_line_without_embedded_newlines`
    // (negative pin on embedded newlines). Those companions
    // catch the wrong-value, empty, name-equals-program-name,
    // and mid-string newline regressions but leave the
    // surrounding-whitespace edge case ungated.
    //
    // The `AdwAboutDialog::developer_name` slot renders as the
    // attribution row directly under the program-name header
    // (one line below `program-name`, above the version label).
    // A regression that put a leading space or tab in the
    // literal — e.g. ` "The Paladin contributors"` from a copy-
    // paste import that brought along an indent — would push
    // the attribution off the centered baseline relative to the
    // program-name header above it. A trailing space (or worse,
    // a trailing newline that the embedded-newline companion
    // already catches because it looks for any `\n`) would
    // leave a hanging gap on the right edge of the attribution
    // row. The current `"The Paladin contributors"` literal is
    // trim-clean, so this test passes today and stays green
    // until a future contributor regresses the literal in a
    // way the existing companions don't catch.
    //
    // Mirror of the
    // `_translator_credits_has_no_surrounding_whitespace_when_non_empty`
    // and `_release_notes_has_no_surrounding_whitespace_when_non_empty`
    // siblings already pinned on the credits-page and What's
    // New sides; together they pin the no-padding shape on the
    // attribution row, the translator-credits row, and the
    // release-notes section against a single source of truth.
    // Sibling of the `_comments_is_non_empty_single_line_distinct_from_program_name`
    // companion which already pins the matching no-padding
    // invariant on the program-header comments-caption side;
    // together they pin the attribution-row + caption-row
    // header cluster as flush against its baseline grid.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        !developer_name.starts_with(char::is_whitespace),
        "AdwAboutDialog developer_name must not start with whitespace so the attribution row renders flush against the centered baseline below the program-name header; got {developer_name:?}",
    );
    assert!(
        !developer_name.ends_with(char::is_whitespace),
        "AdwAboutDialog developer_name must not end with whitespace so the attribution row does not leave a hanging gap on the right edge below the program-name header; got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_program_name_returns_paladin`
    // (exact-value pin),
    // `format_app_about_dialog_program_name_is_non_empty_and_not_app_id`
    // (positive shape pin on non-empty + distinct),
    // `format_app_about_dialog_program_name_matches_format_app_window_title`
    // (cross-consistency with the window title), and
    // `format_app_about_dialog_program_name_is_segment_of_application_icon_name`
    // (cross-consistency with the reverse-DNS icon name). Those
    // companions catch the wrong-value, empty, name-equals-app-id,
    // wrong-title, and not-a-segment regressions but leave the
    // Unicode-lookalike edge case ungated.
    //
    // The `AdwAboutDialog::program_name` slot renders as the
    // bold header text at the top of the dialog. A regression
    // that swapped a Latin character for a visually-similar
    // Unicode lookalike — e.g. `"Pаladin"` where the second `a`
    // is Cyrillic U+0430 (CYRILLIC SMALL LETTER A) — would
    // render identically in most fonts but fail any byte-level
    // comparison with the slug used by the CLI / executable
    // name (`paladin`) and the icon name's `Paladin` segment.
    // The existing `_is_segment_of_application_icon_name`
    // companion would catch this transitively (because the icon
    // name's `Paladin` segment is pure ASCII), but pinning the
    // ASCII-only invariant directly on the program-name side
    // surfaces the regression with a message that names the
    // offending non-ASCII byte rather than as a confusing
    // segment-membership failure.
    //
    // Pinning the ASCII-only invariant here also keeps the
    // header rendering stable on systems with limited Unicode
    // font fallback (a missing glyph for a non-ASCII character
    // would render as the tofu-box placeholder, degrading the
    // dialog's first impression). Mirror of the
    // `_window_action_names_use_ascii_lowercase_only` and the
    // `_header_bar_button_icon_names_use_lowercase_kebab_case`
    // companions which already pin ASCII-only invariants on
    // the GLib SimpleAction-names and icon-theme-keys sides;
    // together they pin the ASCII-shape contract across the
    // program-name header, the window action targets, and the
    // header-bar icon lookups against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    for (idx, ch) in program_name.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog program_name must use ASCII characters only so the bold dialog header renders stably on systems with limited Unicode font fallback (a missing glyph would render as a tofu-box) and is byte-identical to the lowercased `paladin` slug used by the CLI / executable name; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {program_name:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_application_icon_name_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_application_icon_name_matches_app_id`
    // (exact-value pin against `APP_ID`),
    // `format_app_about_dialog_application_icon_name_is_reverse_dns`
    // (positive shape pin on `.`-separated reverse-DNS form),
    // `format_app_about_dialog_application_icon_name_segments_are_non_empty`
    // (positive pin on each segment being non-empty), and
    // `format_app_about_dialog_application_icon_name_ends_with_gui_segment`
    // (cross-segment pin against the `.Gui` front-end suffix).
    // Those companions catch the wrong-value, wrong-shape,
    // empty-segment, and wrong-suffix regressions but leave the
    // non-ASCII-byte edge case ungated.
    //
    // The `AdwAboutDialog::application_icon_name` slot pins the
    // same reverse-DNS value used by
    // `gtk::Application::set_application_id` and the
    // freedesktop icon-theme lookup keyed at
    // `<icon-cache>/org.tamx.Paladin.Gui.svg` (per the §11
    // packaging plan). The GLib `g_application_id_is_valid` check
    // requires every byte of the application-id to be ASCII —
    // a non-ASCII byte would either fail the runtime validation
    // (preventing `gtk::Application::activate` from firing) or
    // mis-route the icon-theme lookup against a filename the
    // freedesktop spec doesn't honor (a non-ASCII byte in the
    // icon-cache key would render the broken-image placeholder
    // at runtime).
    //
    // A regression that swapped a Latin character for a visually-
    // similar Unicode lookalike on the `Paladin` segment of the
    // icon name — e.g. `"org.tamx.Pаladin.Gui"` where the second
    // `a` is Cyrillic U+0430 — would slip past the
    // `_matches_app_id` companion only if the `APP_ID` constant
    // were similarly corrupted (lookalike-in-lookalike), and
    // slip past the `_is_reverse_dns` / `_segments_are_non_empty`
    // / `_ends_with_gui_segment` companions which check shape
    // not byte composition. Pinning the ASCII-only invariant
    // directly here surfaces the regression with a message
    // naming the offending non-ASCII byte rather than as a
    // confusing runtime icon-lookup miss.
    //
    // Mirror of the
    // `_program_name_is_ascii_only`,
    // `_window_action_names_use_ascii_lowercase_only`, and
    // `_header_bar_button_icon_names_use_lowercase_kebab_case`
    // companions; together they pin the ASCII-shape contract
    // across the dialog program-name header, the dialog
    // application-icon-name + the matching `gtk::Application`
    // application_id, the window action targets, and the
    // header-bar icon lookups against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    for (idx, ch) in icon_name.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog application_icon_name must use ASCII characters only so the value stays byte-identical to the gtk::Application::set_application_id input (which `g_application_id_is_valid` rejects on any non-ASCII byte) and resolves cleanly against the freedesktop icon-theme lookup at `<icon-cache>/{icon_name}.svg`; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {icon_name:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_version_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_version_matches_cargo_pkg_version`
    // (exact-value pin sourcing from `env!("CARGO_PKG_VERSION")`)
    // and
    // `format_app_about_dialog_version_is_non_empty_and_looks_like_semver`
    // (positive shape pin on non-empty + contains `.` + no
    // ASCII-space). Those companions catch the wrong-source,
    // empty, missing-`.`, and embedded-space regressions but
    // leave the non-ASCII-byte edge case ungated.
    //
    // The `[workspace.package].version` value in `Cargo.toml`
    // is enforced by Cargo to follow the semver shape, which is
    // pure ASCII (digits, `.`, optional pre-release / build
    // metadata with hyphens, plus signs, and `.`). A hand-edit
    // that swapped an ASCII digit for a visually-similar Unicode
    // digit — e.g. `"0.0.1"` → `"0.0.١"` where the trailing
    // character is U+0661 ARABIC-INDIC DIGIT ONE — would
    // technically still parse as a string but fail any
    // byte-equality comparison against the canonical semver and
    // break Cargo's own version-comparison machinery on the
    // workspace side. The dialog version label would render
    // with the lookalike digit, which is a quiet UX regression
    // since the user has no easy way to spot the visual swap.
    //
    // Pinning the ASCII-only invariant here is a forcing
    // function so the Cargo-enforced semver shape stays visible
    // at the GTK dialog layer rather than as a confusing
    // version-comparison miss elsewhere. The current
    // `env!("CARGO_PKG_VERSION")` value is ASCII (Cargo
    // enforces it upstream), so this test trivially passes
    // today and serves as a canary on any hand-edited override
    // of the version helper.
    //
    // Mirror of the
    // `_program_name_is_ascii_only` and
    // `_application_icon_name_is_ascii_only` companions on the
    // dialog program-name and application-icon-name sides;
    // together they pin the ASCII-shape contract across the
    // three dialog header slots (program-name, version,
    // application-icon-name) against a single source of truth,
    // closing the Unicode-lookalike regression surface for the
    // visible dialog header cluster.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    for (idx, ch) in version.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog version must use ASCII characters only so the dialog version label stays byte-identical to the Cargo-enforced semver shape from `env!(\"CARGO_PKG_VERSION\")` (a Unicode digit lookalike like `1` -> `١` U+0661 would parse as text but fail byte-equality against the canonical semver); got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {version:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developer_name_returns_the_paladin_contributors`
    // (exact-value pin),
    // `format_app_about_dialog_developer_name_is_non_empty_and_distinct_from_program_name`
    // (positive shape pin on non-empty + distinct),
    // `format_app_about_dialog_developer_name_is_a_single_line_without_embedded_newlines`
    // (negative pin on embedded newlines), and the new
    // `_developer_name_has_no_surrounding_whitespace` sibling.
    // Those companions catch the wrong-value, empty,
    // name-equals-program-name, embedded-newline, and surrounding-
    // whitespace regressions but leave the non-ASCII-byte edge
    // case ungated.
    //
    // The `AdwAboutDialog::developer_name` slot is the
    // *collective* attribution rendered under the program-name
    // header — it deliberately does NOT track individual
    // contributor names (those flow through
    // `format_app_about_dialog_developers` which has its own
    // shape pins for the credits-page Developers list and is
    // free to carry non-ASCII contributor names that match the
    // upstream commit-author records). Pinning the collective
    // attribution to ASCII-only keeps the header rendering
    // stable on systems with limited Unicode font fallback (a
    // missing glyph would render as the tofu-box placeholder
    // beside the bold program name) without constraining the
    // contributor-credits list.
    //
    // A regression that swapped a Latin character in the
    // collective attribution for a visually-similar Unicode
    // lookalike — e.g. `"The Pаladin contributors"` where the
    // `a` in `Paladin` is Cyrillic U+0430 — would render
    // identically in most fonts but fail byte-equality against
    // the ASCII slug used by the program-name header and the
    // reverse-DNS icon-name segment, slipping past the
    // `_returns_the_paladin_contributors` exact-value pin only
    // if the canonical literal were similarly corrupted in a
    // lookalike-in-lookalike refactor.
    //
    // Mirror of the
    // `_program_name_is_ascii_only`,
    // `_application_icon_name_is_ascii_only`, and
    // `_version_is_ascii_only` companions; together they pin
    // the ASCII-shape contract across the four dialog header
    // slots (program-name, version, application-icon-name,
    // developer-name) against a single source of truth,
    // closing the Unicode-lookalike regression surface for the
    // entire visible dialog header cluster.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    for (idx, ch) in developer_name.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog developer_name must use ASCII characters only on the collective attribution (individual contributors flow through `format_app_about_dialog_developers` and may carry non-ASCII) so the dialog header below the program-name line renders stably on systems with limited Unicode font fallback; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {developer_name:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_debug_info_filename_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt`
    // (exact-value pin to the static literal
    // `"paladin-debug-info.txt"`) and
    // `format_app_about_dialog_debug_info_filename_is_non_empty_single_line_with_txt_extension`
    // (positive shape pin on non-empty + no embedded newline +
    // `.txt` extension + no path separators). Those companions
    // catch the wrong-value, empty, embedded-newline, wrong-
    // extension, and path-traversal regressions but leave the
    // non-ASCII-byte edge case ungated.
    //
    // The `AdwAboutDialog::debug_info_filename` slot pins the
    // suggested filename `AdwAboutDialog` hands to the
    // "Save debug info" `gtk::FileDialog`. The filename round-
    // trips through the user's locale-configured filesystem
    // and gets persisted into the destination directory once
    // the save action commits. A non-ASCII byte in the
    // filename — e.g. a Unicode-lookalike `paladin-debug-infо.txt`
    // where the `o` before `.txt` is Cyrillic U+043E — would
    // render identically in most fonts but produce a filename
    // that is silently *not* what the user expected. The user
    // would then later search their downloads folder for
    // `paladin-debug-info.txt` (ASCII) and miss the saved file
    // because the on-disk filename uses a Unicode lookalike
    // they cannot easily type or paste.
    //
    // Pinning the ASCII-only invariant here surfaces the
    // regression at the helper-source layer with a message
    // naming the offending non-ASCII byte rather than as a
    // confusing "I saved my bug report but can't find it"
    // user-support thread. Mirror of the new
    // `_program_name_is_ascii_only`,
    // `_application_icon_name_is_ascii_only`,
    // `_version_is_ascii_only`, and
    // `_developer_name_is_ascii_only` companions on the dialog
    // header-cluster sides; together they pin the ASCII-shape
    // contract across the four dialog header slots and the
    // debug-info file-save suggested name against a single
    // source of truth, closing the Unicode-lookalike regression
    // surface across the dialog header + debug-info save dialog
    // user surfaces.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    for (idx, ch) in filename.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog debug_info_filename must use ASCII characters only so the file-save dialog's suggested filename round-trips through the user's filesystem byte-identically — a Unicode lookalike like `paladin-debug-infо.txt` (Cyrillic `о` U+043E) would render identically but produce a silently-different on-disk filename the user cannot easily find later; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {filename:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_debug_info_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_carries_program_name_version_and_app_id`
    // (positive shape pin on the three tokens),
    // `format_app_about_dialog_debug_info_is_non_empty_text_with_no_trailing_whitespace`
    // (positive pin on non-empty + no trailing whitespace),
    // `format_app_about_dialog_debug_info_starts_with_program_name`
    // (positive pin on the leading token),
    // `format_app_about_dialog_debug_info_app_id_appears_on_a_distinct_line_from_program_name`
    // (positive pin on line layout),
    // `format_app_about_dialog_debug_info_has_exactly_two_lines`
    // (line-count pin),
    // `format_app_about_dialog_debug_info_program_name_line_ends_with_the_version`
    // (line-suffix pin on the program-name line), and
    // `format_app_about_dialog_debug_info_app_id_line_ends_with_the_reverse_dns_app_id`
    // (line-suffix pin on the App ID line). Those companions
    // catch the wrong-token, empty, leading-token, line-layout,
    // line-count, and line-suffix regressions but leave the
    // non-ASCII-byte edge case ungated.
    //
    // The `AdwAboutDialog` "Copy debug info" button hands the
    // body of this helper to the system clipboard for the user
    // to paste into a bug-report issue or chat message. The
    // clipboard handoff round-trips through `gdk::Clipboard`
    // and may traverse a heterogeneous mix of source / target
    // encodings (e.g. paste into a Discord chat normalizes via
    // utf-8, paste into a GitHub-issue text area preserves
    // bytes verbatim, paste into a terminal may render via the
    // terminal's locale). A non-ASCII byte in the payload —
    // a Unicode lookalike on `Paladin`, `App ID:`, or the
    // version digits inherited from `env!("CARGO_PKG_VERSION")` —
    // would round-trip differently depending on the paste
    // target, producing a bug-report payload that the maintainer
    // cannot trivially match against the workspace's canonical
    // `Cargo.toml` version field or the `APP_ID` constant
    // declared in `src/lib.rs`.
    //
    // The transitive ASCII guarantee provided by the
    // `_version_is_ascii_only` and `_application_icon_name_is_ascii_only`
    // companions — both of which feed into the debug-info
    // payload — covers the two embedded tokens, but does not
    // cover the surrounding literal text (`"Paladin "`,
    // `"\nApp ID: "`). Pinning the ASCII-only invariant
    // directly here closes that gap and keeps the clipboard
    // payload byte-stable across paste targets regardless of
    // future changes to the surrounding-literal layout.
    //
    // Mirror of the
    // `_program_name_is_ascii_only`,
    // `_application_icon_name_is_ascii_only`,
    // `_version_is_ascii_only`,
    // `_developer_name_is_ascii_only`, and
    // `_debug_info_filename_is_ascii_only` companions; together
    // they pin the ASCII-shape contract across the four dialog
    // header slots, the debug-info file-save suggested name,
    // and the debug-info clipboard payload against a single
    // source of truth, closing the Unicode-lookalike regression
    // surface for every dialog-routed string the user can read
    // or paste into a third-party tool.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug = format_app_about_dialog_debug_info();
    for (idx, ch) in debug.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog debug-info must use ASCII characters only so the Copy debug info button hands the clipboard a byte-stable payload that round-trips identically through gdk::Clipboard regardless of the paste target encoding (terminal, Discord chat, GitHub issue, etc.); got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {debug:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_debug_info_filename_extension_is_lowercase_txt() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt`
    // (exact-value pin to the static literal
    // `"paladin-debug-info.txt"`),
    // `format_app_about_dialog_debug_info_filename_is_non_empty_single_line_with_txt_extension`
    // (positive shape pin which uses
    // `ext.eq_ignore_ascii_case("txt")` and therefore would also
    // accept `.TXT` or `.Txt`), and the new
    // `_debug_info_filename_is_ascii_only` companion.
    //
    // The case-insensitive `.txt` check in the
    // `_is_non_empty_single_line_with_txt_extension` companion
    // is deliberately lenient on the extension casing because
    // freedesktop filesystems are case-sensitive but the
    // libadwaita / GIO file-save MIME-type dispatch is keyed
    // off case-folded extensions. That leniency leaves the
    // case-sensitive lower-case `.txt` convention ungated:
    // a regression that hand-spelled the helper as
    // `"paladin-debug-info.TXT"` (uppercase) or
    // `"paladin-debug-info.Txt"` (mixed case) would slip past
    // both companions while producing a file-save suggestion
    // that mis-matches the GNOME / freedesktop convention of
    // lowercase extensions and renders awkwardly in file
    // managers next to other text bug-report files (which
    // overwhelmingly use lowercase `.txt`).
    //
    // The current `"paladin-debug-info.txt"` literal is
    // lowercase-correct, so this test passes today and serves
    // as a forcing function so any future override of the
    // filename literal stays aligned with the convention. The
    // `_is_ascii_only` companion already pins the extension's
    // *characters* to the ASCII subset; this companion
    // additionally pins the extension's *casing* against
    // accidental upper-case drift that would also be
    // ASCII-valid. Together they pin the extension casing +
    // byte composition contract against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    // The case-sensitive `.txt` suffix check is exactly the point of this
    // pin — the `_is_non_empty_single_line_with_txt_extension` companion
    // already uses `eq_ignore_ascii_case`, leaving the casing-drift edge
    // case ungated. The clippy::case_sensitive_file_extension_comparisons
    // lint default-suggests an `eq_ignore_ascii_case` swap which would
    // collapse this pin into the lenient companion; allow the lint here.
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    {
        assert!(
            filename.ends_with(".txt"),
            "AdwAboutDialog debug_info_filename must end with a case-sensitive lower-case `.txt` extension matching the GNOME / freedesktop convention for plain-text bug-report files in file managers — the `_is_non_empty_single_line_with_txt_extension` companion uses `eq_ignore_ascii_case` and so would also accept `.TXT` or `.Txt`, leaving the casing-drift edge case ungated; got {filename:?}",
        );
    }
    let extension = std::path::Path::new(filename).extension().unwrap_or_else(|| {
        panic!(
            "AdwAboutDialog debug_info_filename must have an extension recognizable by `std::path::Path::extension`; got {filename:?}",
        )
    });
    assert_eq!(
        extension,
        "txt",
        "AdwAboutDialog debug_info_filename extension must be the case-sensitive lower-case literal `txt` matching the GNOME / freedesktop convention for plain-text files; got {extension:?} in {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_has_no_embedded_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_application_icon_name_matches_app_id`
    // (exact-value pin against `APP_ID`),
    // `format_app_about_dialog_application_icon_name_is_reverse_dns`
    // (positive shape pin on `.`-separated reverse-DNS form),
    // `format_app_about_dialog_application_icon_name_segments_are_non_empty`
    // (positive pin on each segment being non-empty),
    // `format_app_about_dialog_application_icon_name_ends_with_gui_segment`
    // (cross-segment pin against the `.Gui` front-end suffix),
    // and `format_app_about_dialog_application_icon_name_is_ascii_only`
    // (byte-composition pin against Unicode lookalikes).
    // Those companions catch the wrong-value, wrong-shape,
    // empty-segment, wrong-suffix, and non-ASCII-byte
    // regressions but leave the embedded-whitespace edge case
    // ungated.
    //
    // The `gtk::Application::set_application_id` input is
    // validated by `g_application_id_is_valid` which rejects any
    // whitespace byte — a space, tab, or embedded newline in
    // the application-id literal would either fail the runtime
    // validation (preventing `gtk::Application::activate` from
    // firing) or, depending on the libadwaita / GTK version,
    // silently coerce to an invalid icon-theme lookup key that
    // renders the broken-image placeholder. The reverse-DNS
    // shape pin (`_is_reverse_dns`) requires `.`-separated
    // segments but a `"org.tamx .Paladin.Gui"` (stray space
    // after `tamx`) would still split into the same segment
    // count under `.split('.')`, slipping past the
    // `_segments_are_non_empty` companion because every segment
    // is non-empty even with the embedded space.
    //
    // The new `_is_ascii_only` companion catches non-ASCII
    // whitespace (e.g. U+00A0 NO-BREAK SPACE, U+2003 EM SPACE)
    // because those are non-ASCII bytes, but does not catch
    // ASCII-space (U+0020), ASCII-tab (U+0009), or other ASCII
    // whitespace inside the literal — those are ASCII-valid
    // and would slip past every existing companion. Pinning
    // the no-embedded-whitespace invariant here closes that
    // remaining gap so a regression that hand-spelled the
    // helper with stray whitespace surfaces with a message
    // naming the offending whitespace character rather than
    // as a confusing runtime icon-lookup miss or
    // `gtk::Application::activate` no-op.
    //
    // Mirror of the `format_app_about_dialog_url_helpers_contain_no_embedded_whitespace`
    // sibling already pinned on the three AdwAboutDialog footer
    // URL helpers and the `_action_group_name_has_no_separator_or_whitespace`
    // companion on the `gio::ApplicationWindow::insert_action_group`
    // side; together they pin the no-whitespace invariant across
    // every dialog-routed identifier-shaped helper against a
    // single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.chars().any(char::is_whitespace),
        "AdwAboutDialog application_icon_name must contain no whitespace byte so the value passes `g_application_id_is_valid` cleanly (which rejects any whitespace) and resolves against the freedesktop icon-theme lookup without falling back to the broken-image placeholder; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_has_no_embedded_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_program_name_returns_paladin`
    // (exact-value pin against the static literal `"Paladin"`),
    // `format_app_about_dialog_program_name_is_non_empty_and_not_app_id`
    // (positive shape pin on non-empty + distinct from `APP_ID`),
    // `format_app_about_dialog_program_name_matches_format_app_window_title`
    // (cross-consistency with the window title),
    // `format_app_about_dialog_program_name_is_segment_of_application_icon_name`
    // (cross-consistency with the reverse-DNS icon name), and
    // `format_app_about_dialog_program_name_is_ascii_only`
    // (byte-composition pin against Unicode lookalikes).
    // Those companions catch the wrong-value, empty,
    // name-equals-app-id, wrong-title, not-a-segment, and
    // non-ASCII-byte regressions but leave the
    // embedded-ASCII-whitespace edge case ungated.
    //
    // The `AdwAboutDialog::program_name` slot renders as the
    // bold header text at the top of the dialog. The canonical
    // literal `"Paladin"` is a single word with no internal
    // whitespace — a regression that hand-spelled the helper as
    // `"Pal adin"` (stray space) or `"Pal\tadin"` (stray tab)
    // would slip past the existing pins because:
    //
    // * `_returns_paladin` only catches the case where the
    //   canonical literal is similarly corrupted in a
    //   lookalike-in-lookalike refactor.
    // * `_is_non_empty_and_not_app_id` only checks non-emptiness
    //   and distinctness from `APP_ID`, not byte composition.
    // * `_is_ascii_only` accepts ASCII-space (U+0020),
    //   ASCII-tab (U+0009), and other ASCII whitespace
    //   characters because they are all ASCII-valid bytes.
    // * `_is_segment_of_application_icon_name` would catch the
    //   embedded-whitespace regression transitively only because
    //   the canonical icon-name `"org.tamx.Paladin.Gui"` is
    //   whitespace-free; if both literals drifted together
    //   (e.g. `"Pal adin"` here paired with `"org.tamx.Pal adin.Gui"`
    //   on the icon-name side, which the recently-pinned
    //   `_application_icon_name_has_no_embedded_whitespace`
    //   companion would catch separately), this companion would
    //   continue to pass on a misleading match.
    //
    // Whitespace inside the program-name slot also breaks the
    // visual centering of the bold header text relative to the
    // surrounding header rows — `AdwAboutDialog` lays the header
    // out under the assumption that `program_name` is a single
    // tightly-set word rather than a multi-word phrase — and
    // would mis-render through any downstream consumer that
    // splits on whitespace (e.g. an automated bug-report tooling
    // pass that scrapes the program-name token out of the
    // `format_app_about_dialog_debug_info` payload).
    //
    // Pinning the no-embedded-whitespace invariant directly here
    // surfaces a regression with a message that names the
    // offending whitespace character at the byte offset rather
    // than as a confusing segment-membership failure on the
    // icon-name side or a quiet centering / scraping mismatch at
    // render / consumption time. Mirror of the
    // `format_app_about_dialog_application_icon_name_has_no_embedded_whitespace`
    // sibling on the reverse-DNS icon-name side and the
    // `format_app_about_dialog_url_helpers_contain_no_embedded_whitespace`
    // sibling on the three AdwAboutDialog footer URL helpers;
    // together they pin the no-whitespace invariant across every
    // dialog-routed identifier-shaped helper against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    for (idx, ch) in program_name.char_indices() {
        assert!(
            !ch.is_whitespace(),
            "AdwAboutDialog program_name must contain no embedded whitespace so the bold dialog header renders as a single tightly-set word matching libadwaita's program-name layout convention and stays byte-identical to the `Paladin` segment of the reverse-DNS application_icon_name and to any downstream consumer that splits on whitespace; got whitespace char {ch:?} (U+{:04X}) at byte offset {idx} in {program_name:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_version_has_no_embedded_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_version_matches_cargo_pkg_version`
    // (exact-value pin sourcing from `env!("CARGO_PKG_VERSION")`),
    // `format_app_about_dialog_version_is_non_empty_and_looks_like_semver`
    // (positive shape pin on non-empty + contains `.` + no
    // ASCII-space character `' '`), and
    // `format_app_about_dialog_version_is_ascii_only`
    // (byte-composition pin against Unicode lookalikes).
    // Those companions catch the wrong-source, empty,
    // missing-`.`, embedded-ASCII-space, and non-ASCII-byte
    // regressions but leave the embedded-ASCII-tab,
    // embedded-ASCII-newline, embedded-ASCII-carriage-return,
    // and other ASCII whitespace (vertical tab, form feed)
    // edge cases ungated:
    //
    // * `_is_non_empty_and_looks_like_semver` uses
    //   `!version.contains(' ')` which only matches the literal
    //   ASCII-space byte (U+0020) and would accept
    //   `"0.0\t1"` (embedded tab) or `"0.0\n1"` (embedded
    //   newline) untouched.
    // * `_is_ascii_only` only constrains the byte composition
    //   to the ASCII subset; ASCII tab (U+0009), ASCII newline
    //   (U+000A), ASCII carriage return (U+000D), ASCII
    //   vertical tab (U+000B), and ASCII form feed (U+000C)
    //   are all ASCII-valid and would slip past it.
    //
    // The canonical semver shape that Cargo enforces on the
    // `[workspace.package].version` value is whitespace-free
    // (digits, `.`, optional pre-release / build metadata with
    // hyphens, plus signs, and `.`), so the
    // `env!("CARGO_PKG_VERSION")` value is whitespace-free at
    // compile time. A hand-edit that overrode the helper to
    // return a literal containing stray whitespace — e.g.
    // `"0.0 .1"` (stray space, also caught by the existing
    // `_is_non_empty_and_looks_like_semver` companion) or
    // `"0.0\t1"` / `"0.0\n1"` (stray tab / newline, NOT
    // caught by either existing companion) — would slip
    // through and produce a dialog version label that
    // either wraps to two lines (newline) or renders with a
    // visible gap (tab) inside the version row, breaking the
    // visual alignment with the program-name header above
    // and the developer-name attribution row below. The same
    // value also propagates into the
    // `format_app_about_dialog_debug_info` two-line payload
    // (the program-name line ends with the version per
    // `_program_name_line_ends_with_the_version`); a stray
    // newline inside the version would inject a third line
    // into the debug-info payload, breaking the
    // `_has_exactly_two_lines` invariant and surfacing as a
    // confusing line-count mismatch rather than as a clear
    // whitespace-named regression.
    //
    // Pinning the no-embedded-whitespace invariant here
    // surfaces the regression with a message that names the
    // offending whitespace character at the byte offset
    // rather than as a cascade through the debug-info
    // line-count pin or as a quiet visual misrender at the
    // dialog version-row layer. Mirror of the
    // `_program_name_has_no_embedded_whitespace` and
    // `_application_icon_name_has_no_embedded_whitespace`
    // siblings on the dialog program-name and
    // application-icon-name sides plus the
    // `_url_helpers_contain_no_embedded_whitespace` companion
    // on the three AdwAboutDialog footer URL helpers;
    // together they pin the no-whitespace invariant across
    // every dialog-routed identifier-shaped helper against a
    // single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    for (idx, ch) in version.char_indices() {
        assert!(
            !ch.is_whitespace(),
            "AdwAboutDialog version must contain no embedded whitespace so the dialog version row renders as a single tightly-set semver token matching the whitespace-free shape Cargo enforces on `[workspace.package].version`, stays byte-identical to `env!(\"CARGO_PKG_VERSION\")`, and does not inject a stray newline into the two-line `format_app_about_dialog_debug_info` payload (breaking the `_has_exactly_two_lines` invariant); got whitespace char {ch:?} (U+{:04X}) at byte offset {idx} in {version:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_debug_info_filename_has_no_embedded_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt`
    // (exact-value pin against the static literal
    // `"paladin-debug-info.txt"`),
    // `format_app_about_dialog_debug_info_filename_is_non_empty_single_line_with_txt_extension`
    // (positive shape pin on non-empty + no `\n` + `.txt`
    // extension + no path separators),
    // `format_app_about_dialog_debug_info_filename_is_ascii_only`
    // (byte-composition pin against Unicode lookalikes),
    // and
    // `format_app_about_dialog_debug_info_filename_extension_is_lowercase_txt`
    // (case-sensitive lowercase pin on the `.txt` extension).
    // Those companions catch the wrong-value, empty,
    // embedded-newline, wrong-extension, path-separator,
    // non-ASCII-byte, and upper-case-extension regressions
    // but leave the embedded-ASCII-space, embedded-ASCII-tab,
    // embedded-ASCII-carriage-return, and other ASCII
    // whitespace (vertical tab, form feed) edge cases
    // ungated:
    //
    // * `_is_non_empty_single_line_with_txt_extension` uses
    //   `!name.contains('\n')` which only matches the literal
    //   ASCII-newline byte (U+000A) and would accept
    //   `"paladin debug-info.txt"` (embedded space) or
    //   `"paladin\tdebug-info.txt"` (embedded tab) untouched.
    // * `_is_ascii_only` only constrains the byte composition
    //   to the ASCII subset; ASCII space (U+0020), ASCII tab
    //   (U+0009), ASCII carriage return (U+000D), and other
    //   ASCII whitespace bytes are all ASCII-valid and would
    //   slip past it.
    //
    // A filename with stray ASCII whitespace inside —
    // e.g. `"paladin debug-info.txt"` (embedded space) —
    // renders awkwardly in file managers (the file appears
    // visually broken into two tokens which the file manager
    // does not understand as the same file) and forces users
    // who copy the filename into terminal commands (the GNOME
    // HIG flow for sharing a bug-report file with a project
    // maintainer over IRC / chat) to manually escape or quote
    // the whitespace — a paste like `cat paladin debug-info.txt`
    // would resolve to two separate path arguments which the
    // shell could not satisfy. Likewise an embedded tab
    // (`"paladin\tdebug-info.txt"`) would either render with a
    // visible gap in file managers or be normalized away by
    // some path-handling layers in the GIO / freedesktop chain,
    // producing a silently-different on-disk filename than the
    // user expected to type.
    //
    // Pinning the no-embedded-whitespace invariant directly
    // here surfaces the regression with a message that names
    // the offending whitespace character at the byte offset
    // rather than as a confusing
    // "I saved my bug report but my shell can't find it"
    // user-support thread or as a quiet file-manager
    // mis-render. Mirror of the
    // `_program_name_has_no_embedded_whitespace`,
    // `_application_icon_name_has_no_embedded_whitespace`,
    // and `_version_has_no_embedded_whitespace` siblings on
    // the dialog header-cluster sides plus the
    // `_url_helpers_contain_no_embedded_whitespace` companion
    // on the three AdwAboutDialog footer URL helpers;
    // together they pin the no-whitespace invariant across
    // every dialog-routed identifier-shaped helper (program-name,
    // version, application-icon-name, debug-info filename,
    // and the three footer URLs) against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    for (idx, ch) in filename.char_indices() {
        assert!(
            !ch.is_whitespace(),
            "AdwAboutDialog debug_info_filename must contain no embedded whitespace so the suggested file-save filename renders as a single token in file managers (rather than visually splitting into two tokens at the embedded space), can be pasted directly into terminal commands without manual escaping (a paste like `cat paladin debug-info.txt` would resolve to two path arguments under any POSIX shell), and stays byte-stable through any path-handling layer in the GIO / freedesktop chain that might normalize away a stray tab or carriage return; got whitespace char {ch:?} (U+{:04X}) at byte offset {idx} in {filename:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_url_helpers_are_ascii_only() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as ASCII characters only.
    //
    // Sibling of `format_app_about_dialog_url_helpers_contain_no_embedded_whitespace`
    // (cross-URL pin against any whitespace byte) and the per-URL
    // `_matches_cargo_pkg_*` (exact-value pin sourcing from
    // `env!(CARGO_PKG_*)`) and
    // `_is_non_empty_https_url[*_distinct*]` (positive shape pin
    // on non-empty + HTTPS + no ASCII space + distinct from
    // siblings) companions. Those companions catch the
    // wrong-source, empty, plain-`http://`, embedded-whitespace,
    // and same-as-sibling regressions but leave the
    // non-ASCII-byte edge case ungated.
    //
    // RFC 3986 §2.1 reserves the URI character set to a subset
    // of ASCII; non-ASCII characters in a URL must be
    // percent-encoded into their UTF-8 byte representation
    // before transport (e.g. the literal `é` is `%C3%A9`).
    // Likewise an internationalized-domain-name (IDN) label
    // must be encoded via Punycode (RFC 3492) into its
    // ASCII-compatible form (`xn--…`) before the DNS resolver
    // can route the request. A regression that hand-spelled a
    // URL helper with a raw non-ASCII byte — e.g.
    // `"https://раладин.example"` where the host label uses
    // Cyrillic-lookalike letters — would slip past the
    // `_is_non_empty_https_url[*_distinct*]` companions
    // (still non-empty, still starts with `https://`, still
    // distinct from siblings) and the
    // `_url_helpers_contain_no_embedded_whitespace` companion
    // (the lookalike bytes are non-whitespace) while either:
    //
    // * Failing DNS resolution at the click site because the
    //   resolver receives a non-ASCII hostname it can't route
    //   (modern browsers Punycode-encode IDN labels at the
    //   address-bar layer, but Adwaita's `AdwAboutDialog` hands
    //   the URL verbatim to `gtk_show_uri` / `xdg-open` which
    //   may or may not perform the encoding depending on the
    //   downstream URL-handler), surfacing as a confusing
    //   "page can't be found" rather than as a clear URL-shape
    //   regression at build time.
    // * Or — far worse — routing to a homograph-attack domain
    //   that visually mimics the canonical host but resolves to
    //   a different IP. Pinning ASCII-only here is a forcing
    //   function against this entire class of regression: any
    //   future maintainer who wants to use an IDN host must
    //   pre-encode the label to its Punycode form so the test
    //   continues to pass.
    //
    // The current `env!("CARGO_PKG_HOMEPAGE")` /
    // `env!("CARGO_PKG_REPOSITORY")` values are pure ASCII
    // (Cargo accepts non-ASCII characters in those fields but
    // the canonical Paladin workspace values are ASCII), so this
    // test passes today and serves as a forcing function so any
    // future hand-edit of the helpers — or any future workspace
    // homepage / repository field change — stays ASCII-compatible
    // for HTTP transport and DNS resolution. Mirror of the
    // `_program_name_is_ascii_only`, `_application_icon_name_is_ascii_only`,
    // `_version_is_ascii_only`, `_developer_name_is_ascii_only`,
    // `_debug_info_filename_is_ascii_only`, and
    // `_debug_info_is_ascii_only` siblings on the dialog header
    // / debug-info sides; together they pin the ASCII-shape
    // contract across every dialog-routed identifier-shaped /
    // identifier-routed helper against a single source of truth,
    // closing the Unicode-lookalike + homograph regression
    // surface for every dialog-routed string the user can
    // either read, click, or paste into a third-party tool.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        for (idx, ch) in url.char_indices() {
            assert!(
                ch.is_ascii(),
                "AdwAboutDialog {label} must use ASCII characters only so the URL stays valid per RFC 3986 §2.1 without any raw non-ASCII bytes that some downstream URL-handlers (gtk_show_uri / xdg-open) may not Punycode-encode at the click site — and so the canonical Paladin host cannot drift into a Unicode-lookalike homograph that resolves to a different domain than the user expects to visit; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {url:?}",
                ch as u32,
            );
        }
    }
}

#[test]
fn format_app_about_dialog_comments_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_comments_matches_cargo_pkg_description`
    // (exact-value pin sourcing from `env!("CARGO_PKG_DESCRIPTION")`),
    // `format_app_about_dialog_comments_is_non_empty_single_line_distinct_from_program_name`
    // (positive shape pin on non-empty + single-line + distinct
    // from the program-name slug), and
    // `format_app_about_dialog_comments_does_not_end_with_a_period_per_libadwaita_convention`
    // (HIG-convention pin against a sentence-terminating period).
    // Those companions catch the wrong-source, empty,
    // multi-line, comments-equals-program-name, and
    // trailing-period regressions but leave the
    // Unicode-lookalike / mojibake-byte edge case ungated.
    //
    // The `AdwAboutDialog::comments` slot renders as the short
    // caption directly under the bold program-name header,
    // immediately above the version row. The canonical Paladin
    // description sourced from the workspace
    // `[workspace.package].description` Cargo.toml field is
    // `"Paladin: Rust OTP authenticator (TOTP + HOTP) with CLI, TUI, and GTK front-ends"`
    // — pure ASCII (Latin letters, digits, parentheses, hyphens,
    // commas, spaces, and the `:` separator), matching the
    // program-name slug (`Paladin`) used by the CLI executable
    // name byte-for-byte. A regression that hand-edited the
    // workspace description to include a Unicode lookalike —
    // e.g. swapping the canonical ASCII `a` in `Paladin` for
    // Cyrillic U+0430 — would propagate verbatim through the
    // `description.workspace = true` inheritance chain into
    // `env!("CARGO_PKG_DESCRIPTION")` and into the AdwAboutDialog
    // comments row, slipping past:
    //
    // * `_matches_cargo_pkg_description` because the env value
    //   already carries the corrupted bytes (the pin tracks the
    //   value, not its composition).
    // * `_is_non_empty_single_line_distinct_from_program_name`
    //   because the corrupted string would still be non-empty,
    //   still single-line, and still distinct from the bare
    //   ASCII `Paladin` slug returned by
    //   `format_app_about_dialog_program_name`.
    // * `_does_not_end_with_a_period_per_libadwaita_convention`
    //   because the corruption inside the body has nothing to
    //   do with the trailing-punctuation invariant.
    //
    // The corrupted comments value would render with the
    // lookalike char in the dialog caption row, breaking
    // byte-equality against the ASCII `Paladin` token at the
    // top of the caption — the very token an automated
    // bug-report tooling pass might match against to confirm
    // the dialog metadata is consistent with the application
    // binary it is reporting on. Pinning the ASCII-only
    // invariant directly here surfaces the regression with a
    // message that names the offending non-ASCII byte at the
    // byte offset rather than as a confusing
    // byte-equality-with-program-name failure elsewhere or as
    // a quiet visual misrender at the caption-row layer.
    //
    // The current `env!("CARGO_PKG_DESCRIPTION")` value is
    // pure ASCII per the workspace `description` field, so
    // this test passes today and serves as a forcing function
    // so any future workspace-description field change stays
    // ASCII-compatible. Mirror of the
    // `_program_name_is_ascii_only`,
    // `_application_icon_name_is_ascii_only`,
    // `_version_is_ascii_only`,
    // `_developer_name_is_ascii_only`,
    // `_debug_info_filename_is_ascii_only`,
    // `_debug_info_is_ascii_only`, and the new
    // `_url_helpers_are_ascii_only` siblings on the dialog
    // header / debug-info / footer-URL sides; together they
    // pin the ASCII-shape contract across every dialog-routed
    // identifier-shaped / identifier-routed / human-readable
    // helper that ships to the user against a single source
    // of truth, closing the Unicode-lookalike regression
    // surface across the full AdwAboutDialog text surface.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    for (idx, ch) in comments.char_indices() {
        assert!(
            ch.is_ascii(),
            "AdwAboutDialog comments must use ASCII characters only so the dialog caption row stays byte-stable against the ASCII `Paladin` token at the top of the caption (the token any automated bug-report tooling pass might match against to confirm the dialog metadata is consistent with the binary), renders stably on systems with limited Unicode font fallback, and propagates byte-for-byte through the `description.workspace = true` inheritance chain from the workspace Cargo.toml `[workspace.package].description` field; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {comments:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_action_group_name_is_ascii_lowercase_only() {
    // Defense-in-depth sibling of
    // `format_app_action_group_name_returns_app` (exact-value
    // pin to the static literal `"app"`) and
    // `format_app_action_group_name_has_no_separator_or_whitespace`
    // (positive shape pin on non-empty + no `.` separator + no
    // ASCII-space byte). Those companions catch the
    // wrong-value, empty, embedded-`.`, and embedded-ASCII-space
    // regressions but leave the casing-drift, embedded-tab /
    // embedded-newline / embedded-other-ASCII-whitespace, and
    // non-ASCII-byte edge cases ungated:
    //
    // * `_returns_app` only catches the case where the canonical
    //   literal is similarly corrupted in a lookalike-in-lookalike
    //   refactor.
    // * `_has_no_separator_or_whitespace` uses
    //   `!group.contains(' ')` which only matches the literal
    //   ASCII-space byte (U+0020) and would accept embedded tab
    //   (U+0009), newline (U+000A), carriage return (U+000D),
    //   or any non-ASCII whitespace untouched.
    // * Neither companion constrains the byte composition
    //   beyond the absence of `.` and `' '`, so an upper-case
    //   regression like `"App"` (capital `A`) or a Unicode
    //   lookalike like `"аpp"` (Cyrillic `а` U+0430 followed
    //   by ASCII `pp`) would slip past both.
    //
    // The libadwaita / GLib convention for `gio::ActionGroup`
    // names — the prefix consumed by
    // `gio::ApplicationWindow::insert_action_group(name, group)`
    // and joined to per-action bare names via the `<group>.<action>`
    // separator — is lowercase ASCII matching the action-name
    // convention pinned on the
    // `format_app_window_action_names_use_ascii_lowercase_only`
    // sibling. Action targets are spelled
    // `<group>.<action>` (e.g. `"app.import"`,
    // `"app.add"`), so the group prefix and every action name
    // must share the same lowercase-ASCII byte composition for
    // the `dispatch_app_window_action` case-sensitive lookup
    // (`dispatch_app_window_action_is_case_sensitive`) to
    // resolve. A regression that introduced an upper-case
    // letter on the group-prefix side — e.g. renaming `"app"`
    // to `"App"` while leaving every per-action helper at the
    // lowercase form — would slip past both existing
    // companions while mis-routing every primary-menu
    // SimpleAction activation through the case-sensitive
    // dispatch helper at runtime, surfacing as a no-op menu
    // press rather than as a build-time identifier mismatch.
    //
    // The current `"app"` literal is lowercase-ASCII, so this
    // test passes today and serves as a forcing function so
    // any future override of the group-prefix helper stays
    // aligned with the action-name convention and the
    // `_window_action_names_use_ascii_lowercase_only`
    // companion already pinned on the per-action-name side.
    // Mirror of that companion plus the
    // `_header_bar_button_icon_names_use_lowercase_kebab_case`
    // sibling on the icon-theme-keys side; together they pin
    // the lowercase-ASCII shape contract across the GLib
    // action-group prefix, the GLib SimpleAction bare names,
    // and the freedesktop icon-theme keys against a single
    // source of truth, closing the casing-drift regression
    // surface across every GLib / freedesktop identifier the
    // `AppModel` registers at runtime.
    use paladin_gtk::app::model::format_app_action_group_name;

    let group = format_app_action_group_name();
    for (idx, ch) in group.char_indices() {
        assert!(
            ch.is_ascii_lowercase(),
            "format_app_action_group_name = {group:?} must use lowercase ASCII letters only so the gio::ActionGroup prefix shares the same case-folded byte composition as the per-action SimpleAction names pinned by `_window_action_names_use_ascii_lowercase_only` and the case-sensitive `dispatch_app_window_action` lookup resolves at runtime (an upper-case regression like `\"App\"` would mis-route every primary-menu SimpleAction activation as a no-op menu press rather than as a build-time identifier mismatch); got disallowed character {ch:?} (U+{:04X}) at byte offset {idx}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_header_bar_button_tooltips_are_ascii_only() {
    // Cross-button defense-in-depth sibling looping over the
    // three icon-only header-bar button tooltip helpers
    // (`format_app_add_button_tooltip`,
    // `format_app_search_button_tooltip`,
    // `format_app_menu_button_tooltip`) and pinning each value
    // as ASCII characters only.
    //
    // Sibling of the per-button `_returns_X` exact-value pins
    // (`format_app_add_button_tooltip_returns_add_account`, …)
    // and the per-button `_is_non_empty` shape pins
    // (`format_app_add_button_tooltip_is_non_empty`, …) plus
    // the cross-button
    // `format_app_header_bar_button_tooltips_are_distinct`
    // (pairwise-distinctness pin),
    // `format_app_header_bar_button_tooltips_are_single_line_without_surrounding_whitespace`
    // (cross-button shape pin on single-line + no padding).
    // Those companions catch the wrong-value, empty,
    // duplicate-tooltip, multi-line, and
    // surrounding-whitespace regressions but leave the
    // Unicode-lookalike / mojibake-byte edge case ungated.
    //
    // The `gtk::Button::set_tooltip_text` slot is the
    // screen-reader-readable label for the icon-only
    // header-bar buttons (Add / search / menu), since the
    // button has no visible text label. A regression that
    // swapped a Latin letter for a visually-similar Unicode
    // lookalike — e.g. `"Аdd account"` where the leading `A`
    // is Cyrillic U+0410 — would slip past the
    // `_returns_add_account` exact-value pin (only catches
    // the case where the canonical literal is similarly
    // corrupted in a lookalike-in-lookalike refactor) and
    // every shape companion (still non-empty, still
    // single-line, still distinct, still trim-clean), and
    // would propagate verbatim to the AT-SPI accessibility
    // bus where screen readers like Orca read the byte
    // sequence aloud — producing a tooltip whose ASCII
    // pronunciation might match the canonical literal but
    // whose byte sequence does not, breaking any keyboard
    // navigation tooling that match-keys off the tooltip
    // string. Likewise a mojibake byte pattern (e.g. an
    // accidentally double-UTF-8-encoded sequence) would
    // render as Unicode replacement characters or as the
    // tofu-box placeholder on systems with limited Unicode
    // font fallback.
    //
    // The current tooltip literals ("Add account",
    // "Search accounts", "Main menu") are pure ASCII, so
    // this test passes today and serves as a forcing
    // function so any future tooltip refactor stays
    // ASCII-compatible for both AT-SPI screen-reader
    // pronunciation and font-fallback stability on
    // limited-Unicode systems. Mirror of the
    // `format_app_about_dialog_url_helpers_are_ascii_only`
    // cross-helper sibling on the AdwAboutDialog footer URL
    // helpers and the `_program_name_is_ascii_only` /
    // `_application_icon_name_is_ascii_only` /
    // `_version_is_ascii_only` siblings on the
    // AdwAboutDialog header cluster; together they pin the
    // ASCII-shape contract across every visible / readable /
    // screen-reader-routed user-surface string against a
    // single source of truth, closing the Unicode-lookalike
    // regression surface for the entire AppModel UI.
    use paladin_gtk::app::model::{
        format_app_add_button_tooltip, format_app_menu_button_tooltip,
        format_app_search_button_tooltip,
    };

    for (label, tooltip) in [
        ("Add", format_app_add_button_tooltip()),
        ("search", format_app_search_button_tooltip()),
        ("menu", format_app_menu_button_tooltip()),
    ] {
        for (idx, ch) in tooltip.char_indices() {
            assert!(
                ch.is_ascii(),
                "header-bar {label} button tooltip must use ASCII characters only so the AT-SPI screen-reader pronunciation stays byte-stable (a Unicode lookalike like Cyrillic `А` U+0410 in `\"Аdd account\"` would slip past every exact-value / single-line / distinct companion while breaking any keyboard navigation tooling that match-keys off the tooltip string), and so the tooltip popover renders cleanly on systems with limited Unicode font fallback rather than collapsing the lookalike to the tofu-box placeholder; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {tooltip:?}",
                ch as u32,
            );
        }
    }
}

#[test]
fn format_app_window_title_is_ascii_only() {
    // Defense-in-depth sibling of
    // `format_app_window_title_returns_paladin` (exact-value
    // pin against the static literal `"Paladin"`),
    // `format_app_window_title_is_non_empty_single_line_without_state_suffix`
    // (positive shape pin on non-empty + single-line + no
    // vault-state suffix), and
    // `format_app_about_dialog_program_name_matches_format_app_window_title`
    // (cross-consistency pin with the AdwAboutDialog program-name
    // slot). Those companions catch the wrong-value, empty,
    // multi-line, state-leaking-suffix, and drift-from-program-name
    // regressions but leave the Unicode-lookalike edge case
    // ungated.
    //
    // The `format_app_window_title` value populates the
    // `AdwApplicationWindow::set_title` slot — the window-list
    // entry on Wayland's `xdg-toplevel` `app_id` / `title`
    // protocol slot and on X11's `_NET_WM_NAME` property — and
    // is read aloud by AT-SPI screen readers when the user
    // tabs into the window (Orca reads the window title as the
    // window-focus announcement). A regression that swapped a
    // Latin character for a visually-similar Unicode lookalike
    // — e.g. `"Pаladin"` where the second `a` is Cyrillic
    // U+0430 (CYRILLIC SMALL LETTER A) — would slip past:
    //
    // * `_returns_paladin` only if the canonical literal is
    //   similarly corrupted in a lookalike-in-lookalike refactor
    //   (the exact-value pin would catch a stand-alone swap but
    //   not a paired drift across the test and the helper).
    // * `_is_non_empty_single_line_without_state_suffix` because
    //   the corrupted string is still non-empty, still single-line,
    //   and does not match any of the literal vault-state strings
    //   (`"Locked"`, `"Unlocked"`, `"Missing"`, etc.) the
    //   companion enforces against.
    // * `_program_name_matches_format_app_window_title` only if
    //   the matching `format_app_about_dialog_program_name` helper
    //   stays at the canonical ASCII `"Paladin"` literal; if both
    //   helpers drift together (a paired regression), the
    //   cross-consistency companion would pass on a misleading
    //   match — though the `_program_name_is_ascii_only` companion
    //   already pinned on the program-name side would catch that
    //   drift on the dialog-program-name half of the pair, and
    //   the new pin here catches it on the window-title half.
    //
    // The window-title value also propagates into the desktop
    // window-list across application switches (the user picks
    // the running Paladin instance from a window-list popover by
    // matching the bare title against the visible label), so a
    // Unicode-lookalike title would render visually identical to
    // the canonical title but fail byte-equality against any
    // window-list tooling (window managers, screenshot
    // taskbar overlays, accessibility tools) that match-keys off
    // the title string. Pinning the ASCII-only invariant here
    // surfaces the regression with a message that names the
    // offending non-ASCII byte at the byte offset rather than
    // as a confusing window-list mis-match or AT-SPI
    // mispronunciation at runtime.
    //
    // Mirror of the `_program_name_is_ascii_only` companion on
    // the AdwAboutDialog program-name side, the
    // `_url_helpers_are_ascii_only` companion on the dialog
    // footer URLs, and the
    // `_header_bar_button_tooltips_are_ascii_only` companion on
    // the icon-only header-bar tooltips; together they pin the
    // ASCII-shape contract across every visible /
    // screen-reader-routed user-surface string in the
    // `AppModel` UI (window title, dialog header cluster,
    // header-bar tooltip captions, footer URL links) against a
    // single source of truth.
    use paladin_gtk::app::model::format_app_window_title;

    let title = format_app_window_title();
    for (idx, ch) in title.char_indices() {
        assert!(
            ch.is_ascii(),
            "ApplicationWindow title must use ASCII characters only so the desktop's window-list label stays byte-stable across application switches (a Unicode lookalike like Cyrillic `а` U+0430 in `\"Pаladin\"` would render visually identical to the canonical title but fail byte-equality against any window-list tooling that match-keys off the title string), and so AT-SPI screen-reader window-focus announcements pronounce the title from a stable byte sequence rather than a lookalike; got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in {title:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_window_title_has_no_embedded_whitespace() {
    // Defense-in-depth sibling of
    // `format_app_window_title_returns_paladin` (exact-value pin
    // to the static literal `"Paladin"`),
    // `format_app_window_title_is_non_empty_single_line_without_state_suffix`
    // (positive shape pin on non-empty + single-line + no
    // vault-state suffix), the just-added
    // `format_app_window_title_is_ascii_only` (byte-composition
    // pin against Unicode lookalikes), and
    // `format_app_about_dialog_program_name_matches_format_app_window_title`
    // (cross-consistency with the AdwAboutDialog program-name
    // slot which already has its own no-embedded-whitespace pin).
    // Those companions catch the wrong-value, empty,
    // embedded-newline (via the single-line check),
    // state-leaking-suffix, non-ASCII-byte, and
    // drift-from-program-name regressions but leave the
    // embedded-ASCII-space, embedded-ASCII-tab,
    // embedded-ASCII-carriage-return, and other ASCII whitespace
    // (vertical tab, form feed) edge cases ungated:
    //
    // * `_is_non_empty_single_line_without_state_suffix` uses
    //   `!title.contains('\n')` which only matches the literal
    //   ASCII-newline byte (U+000A) and would accept
    //   `"Pal adin"` (embedded space) or `"Pal\tadin"`
    //   (embedded tab) untouched.
    // * `_is_ascii_only` only constrains the byte composition
    //   to the ASCII subset; ASCII space (U+0020), ASCII tab
    //   (U+0009), ASCII carriage return (U+000D), and other
    //   ASCII whitespace bytes are all ASCII-valid and would
    //   slip past it.
    //
    // The canonical `"Paladin"` literal is a single word with
    // no internal whitespace. A regression that hand-spelled
    // the helper as `"Pal adin"` (stray space) or
    // `"Pal\tadin"` (stray tab) would render in the desktop
    // window-list across application switches as a two-token
    // title — the window manager / Wayland session-label
    // protocol does not interpret embedded whitespace as a
    // word break, but downstream tooling that splits the
    // title on whitespace (window-switcher overlays,
    // screenshot taskbar exporters, automation scripts) would
    // see two distinct tokens and either fail to match the
    // Paladin window or mis-route the match against the
    // canonical `"Paladin"` slug used by the CLI executable
    // name. Likewise an embedded carriage return or vertical
    // tab inside the title could disrupt some xdg-toplevel
    // title parsers that key off control-byte boundaries.
    //
    // The window-title byte composition also flows into the
    // `AdwAboutDialog::set_application_name` slot via the
    // cross-consistency pin with `format_app_about_dialog_program_name`,
    // so a stray whitespace in the window title would
    // propagate to the bold dialog header text (already
    // pinned no-whitespace on the program-name side by
    // `format_app_about_dialog_program_name_has_no_embedded_whitespace`)
    // and surface as a paired regression rather than as a
    // single source of truth pin.
    //
    // Pinning the no-embedded-whitespace invariant directly
    // here surfaces a regression with a message that names
    // the offending whitespace character at the byte offset
    // rather than as a downstream window-list mis-match or
    // a paired dialog-program-name failure. Mirror of the
    // `format_app_about_dialog_program_name_has_no_embedded_whitespace`,
    // `_application_icon_name_has_no_embedded_whitespace`,
    // `_version_has_no_embedded_whitespace`, and
    // `_debug_info_filename_has_no_embedded_whitespace`
    // siblings on the AdwAboutDialog identifier-shaped helper
    // sides; together they pin the no-whitespace invariant
    // across every dialog-routed identifier-shaped helper
    // and the ApplicationWindow title against a single source
    // of truth.
    use paladin_gtk::app::model::format_app_window_title;

    let title = format_app_window_title();
    for (idx, ch) in title.char_indices() {
        assert!(
            !ch.is_whitespace(),
            "ApplicationWindow title must contain no embedded whitespace so the desktop window-list renders the title as a single tightly-set word matching the canonical `Paladin` slug used by the CLI executable name byte-for-byte (downstream tooling that splits the title on whitespace — window-switcher overlays, screenshot taskbar exporters, automation scripts — would see two distinct tokens and either fail to match the Paladin window or mis-route the match against the canonical slug), and so the byte composition stays consistent with the `format_app_about_dialog_program_name` slot pinned by `_program_name_has_no_embedded_whitespace` on the AdwAboutDialog side; got whitespace char {ch:?} (U+{:04X}) at byte offset {idx} in {title:?}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_add_button_action_name_is_ascii_lowercase_only() {
    // Defense-in-depth sibling of
    // `format_app_add_button_action_name_returns_add` (exact-value
    // pin to the static literal `"add"`),
    // `format_app_add_button_action_name_has_no_separator_or_whitespace`
    // (positive shape pin on non-empty + no `.` separator + no
    // ASCII-space byte), and
    // `format_app_add_button_action_name_round_trips_with_group_and_target`
    // (cross-consistency with `format_app_action_group_name` and
    // `format_app_add_button_action`). Those companions catch
    // the wrong-value, empty, embedded-`.`, embedded-ASCII-space,
    // and round-trip-mismatch regressions but leave the
    // casing-drift, embedded-tab / embedded-newline /
    // embedded-other-ASCII-whitespace, and non-ASCII-byte edge
    // cases ungated:
    //
    // * `_returns_add` only catches the case where the canonical
    //   literal is similarly corrupted in a lookalike-in-lookalike
    //   refactor.
    // * `_has_no_separator_or_whitespace` uses
    //   `!action.contains(' ')` which only matches the literal
    //   ASCII-space byte (U+0020) and would accept embedded tab
    //   (U+0009), newline (U+000A), carriage return (U+000D),
    //   or any non-ASCII whitespace untouched.
    // * `_round_trips_with_group_and_target` composes the group
    //   + bare action via `<group>.<action>` and matches against
    //   `format_app_add_button_action`; if both helpers drift
    //   together (a paired regression), the round-trip companion
    //   would pass on a misleading match.
    //
    // The libadwaita / GLib convention for `gio::SimpleAction`
    // bare names is lowercase ASCII matching the action-group
    // prefix convention pinned on the new
    // `format_app_action_group_name_is_ascii_lowercase_only`
    // sibling and on the existing
    // `format_app_window_action_names_use_ascii_lowercase_only`
    // companion. The `format_app_add_button_action` target is
    // spelled `<group>.<action>` (i.e. `"app.add"`), so the
    // bare action name and the group prefix must share the same
    // lowercase-ASCII byte composition for the
    // `dispatch_app_window_action` case-sensitive lookup (per
    // `dispatch_app_window_action_is_case_sensitive`) to
    // resolve when the header-bar `+` button is clicked. A
    // regression that introduced an upper-case letter on the
    // bare-action side — e.g. renaming `"add"` to `"Add"` while
    // leaving the round-trip target at the lowercase form (or
    // letting both drift together past the round-trip pin) —
    // would slip past both existing companions while
    // mis-routing the header-bar `+` button activation through
    // the case-sensitive dispatch helper at runtime, surfacing
    // as a no-op `+` press rather than as a build-time
    // identifier mismatch.
    //
    // The current `"add"` literal is lowercase-ASCII, so this
    // test passes today and serves as a forcing function so
    // any future override of the bare-action helper stays
    // aligned with the action-name + group-prefix convention.
    // Mirror of the
    // `format_app_action_group_name_is_ascii_lowercase_only`
    // companion on the gio::ActionGroup prefix side and the
    // `format_app_window_action_names_use_ascii_lowercase_only`
    // companion on the bundled per-action-name array side;
    // together they pin the lowercase-ASCII shape contract
    // across the GLib action-group prefix, the bundled
    // per-action-name array, and the bare add-button action
    // name against a single source of truth, closing the
    // casing-drift regression surface across every GLib
    // identifier the `AppModel` registers at runtime.
    use paladin_gtk::app::model::format_app_add_button_action_name;

    let action = format_app_add_button_action_name();
    for (idx, ch) in action.char_indices() {
        assert!(
            ch.is_ascii_lowercase(),
            "format_app_add_button_action_name = {action:?} must use lowercase ASCII letters only so the bare action name shares the same case-folded byte composition as the gio::ActionGroup prefix pinned by `_action_group_name_is_ascii_lowercase_only` and the per-window-action-name array pinned by `_window_action_names_use_ascii_lowercase_only`, and the case-sensitive `dispatch_app_window_action` lookup resolves at runtime when the header-bar `+` button is clicked (an upper-case regression like `\"Add\"` would mis-route the header-bar `+` button activation as a no-op press rather than as a build-time identifier mismatch); got disallowed character {ch:?} (U+{:04X}) at byte offset {idx}",
            ch as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_release_notes_starts_and_ends_with_a_markup_element_when_non_empty() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_release_notes_is_empty_until_v0_2_ships`
    // (exact-value pin to the empty literal),
    // `format_app_about_dialog_release_notes_must_be_paired_with_a_non_empty_version_when_non_empty`
    // (cross-helper version-pairing pin), and
    // `format_app_about_dialog_release_notes_has_no_surrounding_whitespace_when_non_empty`
    // (no-surrounding-whitespace pin). Those companions catch
    // the wrong-value, missing-version-pairing, and leading /
    // trailing-whitespace regressions but leave the actual
    // markup-element-bracket invariant ungated — once the
    // helper swaps to a non-empty body the existing companions
    // do not force the body to actually be valid Pango / AdwAbout
    // markup as opposed to (e.g.) raw paragraph text without any
    // wrapping markup elements.
    //
    // The libadwaita convention for the
    // `AdwAboutDialog::set_release_notes` slot is that the body
    // is a restricted subset of Pango / AdwAbout markup
    // (typically `<p>…</p>` or `<ul><li>…</li></ul>` blocks). A
    // raw paragraph body without wrapping markup — e.g.
    // `"Added support for X."` — would render verbatim through
    // the markup parser as a flat run of text without the
    // baseline-aligned spacing libadwaita applies to wrapped
    // paragraph elements, surfacing as a visually-jammed
    // "What's New" section that does not match the surrounding
    // dialog rows' baseline grid. Worse, the markup parser
    // would silently accept raw text without raising any
    // build-time validation, leaving the visual misalignment to
    // surface only at first run when the section is opened.
    //
    // Pinning the markup-element-bracket invariant here is a
    // forcing function so the v0.2 release-notes copy lands as
    // properly-wrapped markup elements rather than as raw
    // paragraph text. The assertion checks the first byte is
    // `<` (opening a markup element) and the last byte is `>`
    // (closing a markup element) — this is a coarse-grained
    // shape pin that does not validate the full Pango grammar
    // (a `<p>raw text` body would still pass the leading-`<`
    // check but fail the trailing-`>` check; a fully-formed
    // `<p>…</p>` body passes both) but suffices to catch the
    // bare-paragraph regression at the test layer rather than
    // at first-render time.
    //
    // The current empty-literal state trivially passes (the
    // `if !release_notes.is_empty()` guard skips the
    // assertions), so this test stays green now and serves as
    // a canary on the v0.2 swap.
    //
    // Mirror of the
    // `_release_notes_has_no_surrounding_whitespace_when_non_empty`,
    // `_release_notes_must_be_paired_with_a_non_empty_version_when_non_empty`,
    // and `_release_notes_is_empty_until_v0_2_ships` siblings;
    // together they pin the "What's New" section's body shape
    // (empty until v0.2 ships, then version-paired,
    // whitespace-trimmed, and properly-bracketed markup
    // elements) against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    if !release_notes.is_empty() {
        assert!(
            release_notes.starts_with('<'),
            "AdwAboutDialog release-notes must start with a markup element bracket `<` so the What's New section renders through the libadwaita Pango / AdwAbout markup parser as a properly-wrapped paragraph or list block rather than as a flat run of raw text without the baseline-aligned spacing libadwaita applies to wrapped elements; got {release_notes:?}",
        );
        assert!(
            release_notes.ends_with('>'),
            "AdwAboutDialog release-notes must end with a markup element closing bracket `>` so the What's New section's final element closes properly through the libadwaita Pango / AdwAbout markup parser rather than dangling raw text after the last wrapped element; got {release_notes:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_keysym_is_ascii_only_after_the_modifier_block(
) {
    // Defense-in-depth sibling of
    // `format_app_window_accelerator_bindings_accelerators_have_a_non_empty_keysym_after_the_modifier_block`
    // (which pins the keysym suffix is non-empty),
    // `format_app_window_accelerator_bindings_accelerators_contain_no_whitespace`
    // (which pins the full accelerator is whitespace-free —
    // covering the keysym suffix too), and
    // `format_app_window_accelerator_bindings_parse_via_gtk_accelerator_parse`
    // (which round-trips each spelling through
    // `gtk::accelerator_parse` but skips without a display
    // server in CI environments without a synthetic X11
    // session). Those companions catch the empty,
    // embedded-whitespace, and runtime-parse-failure
    // regressions on the keysym suffix but leave the
    // non-ASCII-byte edge case ungated:
    //
    // * `_have_a_non_empty_keysym_after_the_modifier_block`
    //   only constrains the keysym suffix to be non-empty,
    //   not its byte composition.
    // * `_accelerators_contain_no_whitespace` only forbids
    //   whitespace bytes; a non-ASCII byte sequence with no
    //   whitespace would slip past it.
    // * `_parse_via_gtk_accelerator_parse` would reject a
    //   non-ASCII keysym at runtime, but the parse-side
    //   companion skips on CI environments that lack a
    //   display server (the `gtk::init` precondition fails
    //   without a synthetic X11 server), so the pure
    //   string-shape rule needs to hold independently.
    //
    // The X11 / GDK keysym vocabulary defined in
    // `gdkkeysyms.h` (`GDK_KEY_*` constants) and consumed
    // by `gtk::accelerator_parse` is pure ASCII: lowercase
    // letters (`a`-`z`), digits (`0`-`9`), and named keys
    // in camelCase ASCII (`Return`, `Escape`, `Tab`,
    // `Page_Up`, `Home`, etc.). A regression that hand-spelled
    // a keysym with a Unicode lookalike — e.g. swapping the
    // canonical ASCII `n` keysym in `<Control>n` for a Cyrillic
    // `п` U+043F lookalike or a fullwidth `ｎ` U+FF4E — would
    // slip past the non-empty / no-whitespace shape companions
    // while failing `gtk::accelerator_parse` at runtime and
    // silently unbinding the documented shortcut surface (the
    // Add / Quit / Preferences accelerator press would resolve
    // to no action). The current keysyms (`n`, `q`, `comma`)
    // are pure ASCII, so this test passes today and serves as
    // a forcing function so any future accelerator binding
    // override stays ASCII-compatible against the X11 / GDK
    // keysym vocabulary.
    //
    // The assertion locates the closing `>` byte (already
    // pinned to exactly one occurrence by the
    // `_carry_exactly_one_modifier_block` companion), slices
    // the suffix after it (the keysym portion), and walks each
    // char to surface a regression with a message naming the
    // offending non-ASCII byte at the byte offset within the
    // keysym and the offending action target. Scoped to a
    // pure string-shape check (no `gtk::accelerator_parse`
    // call) so it stays parallel-safe with the gtk::init-using
    // parse sibling without an Once-gated init helper. Mirror
    // of the `_accelerators_contain_no_whitespace` and
    // `_have_a_non_empty_keysym_after_the_modifier_block`
    // siblings; together they pin the keysym suffix's
    // non-empty + whitespace-free + ASCII-only byte
    // composition against a single source of truth on the
    // accelerator-bindings array.
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        let close_index = accel.bytes().position(|b| b == b'>').unwrap_or_else(|| {
            panic!(
                "format_app_window_accelerator_bindings accelerator for target {target:?} must contain a `>` ASCII byte closing the modifier block; got {accel:?}",
            )
        });
        let keysym = &accel[close_index + 1..];
        for (idx, ch) in keysym.char_indices() {
            assert!(
                ch.is_ascii(),
                "format_app_window_accelerator_bindings accelerator keysym for target {target:?} must use ASCII characters only so gtk::accelerator_parse resolves the keysym against the X11 / GDK keysym vocabulary defined in `gdkkeysyms.h` (which is pure ASCII — lowercase letters, digits, and camelCase named keys); a Unicode lookalike like Cyrillic `п` U+043F swapped for the canonical ASCII `n` would fail gtk::accelerator_parse at runtime and silently unbind the documented shortcut surface (the Add / Quit / Preferences accelerator press would resolve to no action); got non-ASCII char {ch:?} (U+{:04X}) at byte offset {idx} in keysym {keysym:?} from {accel:?}",
                ch as u32,
            );
        }
    }
}

#[test]
fn format_app_about_dialog_developers_does_not_contain_app_id() {
    // Defense-in-depth cross-helper sibling of
    // `format_app_about_dialog_developers_does_not_contain_developer_name`
    // (which negatively pins the developers credits-list against
    // the dialog-header collective attribution string returned by
    // `format_app_about_dialog_developer_name`),
    // `format_app_about_dialog_developers_lists_benjamin_porter`
    // (positive content pin), and
    // `format_app_about_dialog_developers_entries_are_distinct`
    // (pairwise-distinctness pin). Those companions catch the
    // developer-name-collision, wrong-value, and duplicate-entry
    // regressions but leave the icon-name-collision edge case
    // ungated.
    //
    // The `AdwAboutDialog` developers credits-list (which
    // surfaces individual contributors on the credits page) and
    // the dialog application-icon (a reverse-DNS identifier
    // shared with `gtk::Application::set_application_id` and the
    // freedesktop icon-theme lookup keyed at
    // `<icon-cache>/org.tamx.Paladin.Gui.svg`) live on opposite
    // ends of the dialog semantic space: the developers slot is
    // human-readable contributor names, while the
    // application-icon slot is a programmatic identifier the
    // freedesktop icon-theme machinery resolves. A copy-paste
    // regression that accidentally seeded the
    // `paladin_gtk::APP_ID` constant (or the equivalent string
    // from `format_app_about_dialog_application_icon_name`) into
    // the developers literal — e.g.
    // `["org.tamx.Paladin.Gui"]` — would render the credits page
    // with a contributor whose name is a reverse-DNS identifier,
    // a UX regression that confuses users reading the credits
    // page (who wonder why a contributor is named after the
    // application icon) and breaks any automated credits-scraping
    // tooling that match-keys off human-readable contributor
    // strings.
    //
    // The existing `_does_not_contain_developer_name` companion
    // negatively pins against the dialog-header attribution
    // string ("The Paladin contributors") so the credits list
    // and the header attribution row carry semantically distinct
    // strings. This new sibling additionally negatively pins the
    // developers credits-list against the reverse-DNS
    // application-icon identifier so the credits list and the
    // application-icon slot also carry semantically distinct
    // strings, mirroring the existing pattern at the
    // application-icon / credits cross-section.
    //
    // The current `["Benjamin Porter"]` literal is distinct from
    // the reverse-DNS `"org.tamx.Paladin.Gui"` identifier so
    // this test passes today and serves as a forcing function
    // so any future credits-list refactor stays semantically
    // distinct from the application-icon slot. Mirror of the
    // `_developers_does_not_contain_developer_name` companion
    // on the collective-attribution side; together they pin the
    // credits-list contents against both the dialog-header
    // attribution string and the reverse-DNS application-icon
    // identifier — the two most likely copy-paste sources a
    // future refactor might accidentally seed into the
    // developers literal — against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_application_icon_name, format_app_about_dialog_developers,
    };
    use paladin_gtk::APP_ID;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    let developers = format_app_about_dialog_developers();
    for entry in developers {
        assert_ne!(
            entry, application_icon_name,
            "AdwAboutDialog developers credits-list entry {entry:?} must not duplicate the dialog application-icon reverse-DNS identifier {application_icon_name:?}; the credits list surfaces human-readable contributor names while the application-icon slot surfaces a freedesktop icon-theme key, so a credits entry that matches the icon-name byte-for-byte indicates a copy-paste regression seeding the icon-name slot into the developers literal",
        );
        assert_ne!(
            entry, APP_ID,
            "AdwAboutDialog developers credits-list entry {entry:?} must not duplicate the workspace-wide `paladin_gtk::APP_ID` reverse-DNS constant {APP_ID:?}; the credits list surfaces human-readable contributor names while APP_ID is the GLib / freedesktop / Flatpak application identifier, so a credits entry that matches APP_ID byte-for-byte indicates a copy-paste regression seeding the APP_ID constant into the developers literal",
        );
    }
}

#[test]
fn format_app_about_dialog_developers_does_not_contain_program_name() {
    // Defense-in-depth cross-helper sibling of
    // `format_app_about_dialog_developers_does_not_contain_developer_name`
    // (which negatively pins the developers credits-list against
    // the dialog-header collective attribution string
    // "The Paladin contributors" returned by
    // `format_app_about_dialog_developer_name`) and
    // `format_app_about_dialog_developers_does_not_contain_app_id`
    // (which negatively pins the developers credits-list against
    // the reverse-DNS application-icon identifier
    // "org.tamx.Paladin.Gui" shared by
    // `paladin_gtk::APP_ID` and
    // `format_app_about_dialog_application_icon_name`). Those two
    // companions catch the collective-attribution and
    // application-icon copy-paste sources but leave the bare
    // program-name literal ungated.
    //
    // The bare program-name literal "Paladin" is shared by
    // `format_app_about_dialog_program_name` (the bold dialog
    // header) and `format_app_window_title` (the ApplicationWindow
    // title) and is the third common copy-paste source a future
    // refactor might accidentally seed into the developers
    // literal. A regression that landed `["Paladin"]` as the
    // developers literal would not match the
    // collective-attribution string "The Paladin contributors"
    // byte-for-byte (since the bare program name is a substring
    // not a duplicate of the attribution string) and would not
    // match the reverse-DNS identifier "org.tamx.Paladin.Gui"
    // byte-for-byte (since the bare program name is the
    // human-readable label not the GLib / freedesktop / Flatpak
    // identifier), so it would slip past both existing
    // `_does_not_contain_developer_name` and
    // `_does_not_contain_app_id` companions and render the
    // credits page with a contributor whose name is the
    // application's own bold dialog-header program-name — a UX
    // regression that confuses users reading the credits page
    // (who wonder why a contributor shares the application's
    // bold header label) and breaks any automated
    // credits-scraping tooling that match-keys off
    // human-readable contributor strings distinct from the
    // application name.
    //
    // The `_lists_benjamin_porter` exact-value pin only catches
    // a stand-alone swap to the program-name literal, not a
    // paired lookalike-in-lookalike refactor where both this
    // helper and the program-name helper drift together; the
    // `_is_non_empty_array_of_non_empty_single_line_names` shape
    // pin would still accept "Paladin" (non-empty, single-line);
    // the `_entries_are_distinct` pairwise-distinctness pin
    // would trivially pass for a single corrupted entry; and the
    // `_developer_name_starts_with_the_definite_article`
    // cross-helper pin only constrains the collective-attribution
    // side (the developer-name slot, not the credits-list slot)
    // — so the program-name copy-paste regression slips through
    // every neighbouring guard unless this sibling pins it
    // directly.
    //
    // The current `["Benjamin Porter"]` literal is distinct from
    // the bare `"Paladin"` program-name identifier so this test
    // passes today and serves as a forcing function so any
    // future credits-list refactor stays semantically distinct
    // from the program-name slot. Mirror of the
    // `_developers_does_not_contain_developer_name` companion
    // on the collective-attribution side and the
    // `_developers_does_not_contain_app_id` companion on the
    // reverse-DNS application-icon identifier side; together
    // they pin the credits-list contents against the three most
    // likely copy-paste sources a future refactor might
    // accidentally seed into the developers literal — the
    // dialog-header collective attribution string, the
    // reverse-DNS application-icon identifier, and the bare
    // program-name literal — against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_developers, format_app_about_dialog_program_name,
        format_app_window_title,
    };

    let program_name = format_app_about_dialog_program_name();
    let window_title = format_app_window_title();
    let developers = format_app_about_dialog_developers();
    for entry in developers {
        assert_ne!(
            entry, program_name,
            "AdwAboutDialog developers credits-list entry {entry:?} must not duplicate the bare dialog program-name literal {program_name:?} returned by `format_app_about_dialog_program_name`; the credits list surfaces human-readable contributor names while the program-name slot surfaces the bold dialog-header application identifier, so a credits entry that matches the program-name byte-for-byte indicates a copy-paste regression seeding the program-name into the developers literal",
        );
        assert_ne!(
            entry, window_title,
            "AdwAboutDialog developers credits-list entry {entry:?} must not duplicate the bare ApplicationWindow title literal {window_title:?} returned by `format_app_window_title`; the credits list surfaces human-readable contributor names while the window-title slot surfaces the desktop window-list label, so a credits entry that matches the window-title byte-for-byte indicates a copy-paste regression seeding the window-title into the developers literal (and since `format_app_about_dialog_program_name_matches_format_app_window_title` ties the two literals together, asserting against both here keeps the negative pin in lockstep even if the two literals drift apart in a future refactor)",
        );
    }
}

#[test]
fn format_app_about_dialog_application_icon_name_has_exactly_four_segments() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_application_icon_name_matches_app_id`
    // (which pins the exact value against `APP_ID`),
    // `_is_reverse_dns` (which pins `contains('.')` shape +
    // no-whitespace + distinct from program-name),
    // `_segments_are_non_empty` (which pins each
    // `.`-separated segment is non-empty),
    // `_ends_with_gui_segment` (which pins the trailing
    // `.Gui` suffix that distinguishes this crate's reverse-DNS
    // identity from a future CLI / daemon front-end),
    // `_is_ascii_only` (byte-composition pin), and
    // `_has_no_embedded_whitespace` (no-whitespace pin). Those
    // companions catch the wrong-value / wrong-shape /
    // empty-segment / wrong-suffix / non-ASCII / embedded-
    // whitespace regressions but leave the *segment count*
    // itself ungated, so a regression that doubled a segment
    // — e.g. `"org.org.tamx.Paladin.Gui"` (five segments) or
    // `"org.tamx.tamx.Paladin.Gui"` — or dropped a segment —
    // e.g. `"org.Paladin.Gui"` (three segments, with `tamx`
    // removed) — would slip past every neighbouring guard
    // (`_segments_are_non_empty` requires only `>= 2` so any
    // count in [2, ∞) passes; `_ends_with_gui_segment` still
    // holds since the trailing literal is preserved;
    // `_is_reverse_dns` still holds since `contains('.')` is
    // trivially true).
    //
    // The libadwaita / GIO / Flatpak app-id contract
    // (`g_application_id_is_valid`) accepts any reverse-DNS
    // identifier with two-or-more non-empty segments, but the
    // `org.tamx.Paladin.Gui` brand-string identity is
    // specifically a four-segment reverse-DNS — TLD `org`,
    // SLD `tamx`, brand `Paladin`, front-end-distinguishing
    // `Gui` — so a regression that drifted the segment count
    // up or down would not break the GIO / Flatpak runtime
    // contract but would silently break the Flathub /
    // hicolor icon-theme / desktop-entry / AppStream pinned
    // brand-string identity (the Flathub submission file the
    // `.deb` / `.rpm` / `.flatpak` artifacts at §11 ship is
    // keyed at `org.tamx.Paladin.Gui` and would mis-route a
    // segment-count-drifted regression to a different cache
    // / installation slot at install time, surfacing as an
    // icon-missing / desktop-entry-orphaned packaging bug
    // rather than as a failing test).
    //
    // Pinning the segment count at four directly here
    // surfaces the regression with a message naming the
    // offending count (and the offending segment array)
    // rather than as a downstream packaging / icon-theme /
    // desktop-entry mismatch at install time. Mirror of the
    // `_segments_are_non_empty` companion on the per-segment
    // non-emptiness side and the `_ends_with_gui_segment`
    // companion on the trailing-segment-identity side;
    // together they pin the reverse-DNS shape contract
    // across the per-segment non-emptiness invariant, the
    // trailing-`.Gui` identity, and the overall segment
    // count against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon = format_app_about_dialog_application_icon_name();
    let segments: Vec<&str> = icon.split('.').collect();
    assert_eq!(
        segments.len(),
        4,
        "AdwAboutDialog application-icon must be a four-segment reverse-DNS identifier matching the pinned `org.tamx.Paladin.Gui` brand-string identity (TLD `org`, SLD `tamx`, brand `Paladin`, front-end-distinguishing `Gui`) so the Flathub / hicolor icon-theme / desktop-entry / AppStream packaging artifacts at §11 resolve to the pinned cache / installation slot at install time; got {len} segment(s) in {icon:?} (segments: {segments:?})",
        len = segments.len(),
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_end_with_a_trailing_slash() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of a trailing `/` byte so a regression that
    // landed a slash-terminated URL — e.g.
    // `"https://paladin.tamx.org/"` (homepage trailing slash) or
    // `"https://github.com/FreedomBen/paladin/issues/"`
    // (issue-tracker trailing slash from a paste with the
    // browser address-bar trailing slash retained) — would fail
    // at the pinned layer rather than slip past the
    // `_is_non_empty_https_url` per-URL companion (which only
    // checks non-empty + `https://` prefix + no space byte),
    // the `_contain_no_embedded_whitespace` cross-URL companion
    // (no whitespace bytes anywhere), the `_are_ascii_only`
    // cross-URL companion (only constrains byte composition to
    // ASCII), the `_appends_issues_to_cargo_pkg_repository`
    // companion (which uses `concat!(env!("CARGO_PKG_REPOSITORY"),
    // "/issues")` — if `CARGO_PKG_REPOSITORY` itself drifted to
    // end with a slash, the concatenation would produce
    // `"…paladin//issues"` with a doubled separator, but the
    // existing exact-match companion would still pass since the
    // generated URL still appends `/issues` to whatever
    // `CARGO_PKG_REPOSITORY` resolves to), or the
    // `_issue_url_and_support_url_share_cargo_pkg_repository_prefix`
    // companion (still holds since both URLs share the doubled
    // prefix).
    //
    // The libadwaita `AdwAboutDialog::website` / `issue-url` /
    // `support-url` slots consume the URL verbatim and render
    // it as a clickable footer link; a trailing slash on a
    // URL like `"https://github.com/FreedomBen/paladin/issues/"`
    // would route through HTTP and GitHub's web stack to the
    // exact same destination as the slash-free form
    // (`"https://github.com/FreedomBen/paladin/issues"`) and so
    // would not break the click-through behaviour, but it
    // would silently break automated URL-canonicalization
    // tooling (analytics dedup, click-tracking, sitemap
    // generators, link-checking CI bots) that match-key off
    // the exact URL byte sequence and would treat the
    // slash-terminated form as a distinct URL — surfacing as
    // a dedup-failure or a duplicate-link CI warning rather
    // than as a build-time mismatch. A trailing slash on the
    // homepage URL (`"https://paladin.tamx.org/"`) would
    // similarly normalize at the HTTP layer but break the
    // analytics-canonicalization contract the bare
    // `"https://paladin.tamx.org"` form preserves.
    //
    // Pinning the no-trailing-slash invariant directly here
    // surfaces the regression with a message naming the
    // offending URL helper at build time rather than as a
    // downstream URL-canonicalization warning at click-through
    // time. Mirror of the `_url_helpers_contain_no_embedded_whitespace`
    // and `_url_helpers_are_ascii_only` cross-URL siblings;
    // together they pin the URL byte-composition contract
    // (no whitespace, ASCII-only, no terminal `/`) across all
    // three footer link surfaces against a single source of
    // truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.ends_with('/'),
            "AdwAboutDialog {label} must not end with a trailing `/` so the URL byte sequence matches the bare canonical form analytics / click-tracking / sitemap-generator / link-checking-CI tooling expects (a trailing slash is normalized at the HTTP layer but breaks URL-byte-sequence dedup match-keys); got {url:?}",
        );
    }
}

#[test]
fn format_app_primary_menu_entries_labels_start_with_an_uppercase_letter() {
    // Cross-entry defense-in-depth sibling of the per-entry
    // `format_app_menu_X_label_returns_X` exact-value pins
    // (`_returns_import_with_ellipsis`, `_returns_export_with_ellipsis`,
    // `_returns_passphrase_with_ellipsis`,
    // `_returns_preferences_without_ellipsis`,
    // `_returns_about_paladin`, `_returns_quit`), the per-entry
    // `_ends_with_ellipsis` / `_does_not_carry_ellipsis` HIG
    // suffix invariants, the cross-entry
    // `_labels_are_distinct` pairwise-distinctness pin, and the
    // cross-entry
    // `_labels_are_single_line_without_surrounding_whitespace`
    // shape pin. Those companions catch the wrong-value /
    // wrong-suffix / collided / multi-line / surrounding-
    // whitespace regressions but leave the *leading-character
    // case* ungated.
    //
    // The GNOME Human Interface Guidelines (HIG) §"Menu items"
    // pin menu-entry labels as "header-style capitalization"
    // (title case in American English, sentence case in British
    // English; both conventions agree that the first letter of
    // the first word is uppercase). A regression that landed a
    // lowercase-leading label — e.g. `"import…"` (typo from a
    // sentence-case shadow refactor) or `" import…"` (which
    // would also fail the surrounding-whitespace companion but
    // restates the rule here for the case where someone fixed
    // the leading-space regression but left the lowercase
    // letter) — would slip past the existing
    // `_labels_are_distinct` companion (`"import…"` is still
    // distinct from the other five labels), the
    // `_labels_are_single_line_without_surrounding_whitespace`
    // companion (no embedded newlines, no surrounding spaces),
    // and the `_ends_with_ellipsis` companion (the trailing `…`
    // glyph is preserved). The libadwaita `gio::Menu::item_attribute_value(..., "label", ...)`
    // slot consumes the label verbatim and renders it in the
    // header-bar `gtk::MenuButton` popover, so a lowercase-leading
    // label would render as a visually-inconsistent entry against
    // its title-cased neighbours in the same popover (and against
    // the GNOME stack's `gtk::MenuButton` default labels like
    // "Preferences", "About …", "Quit" elsewhere in the same
    // session).
    //
    // The assertion walks every (label, action) pair returned
    // by `format_app_primary_menu_entries` and pins the first
    // character of each label as an ASCII uppercase letter. The
    // current six labels — `"Import\u{2026}"`, `"Export\u{2026}"`,
    // `"Passphrase\u{2026}"`, `"Preferences"`, `"About Paladin"`,
    // `"Quit"` — all start with an uppercase ASCII letter so
    // this test passes today and serves as a forcing function
    // so any future menu-label refactor stays aligned with the
    // GNOME HIG header-style capitalization convention. Mirror
    // of the `_labels_are_single_line_without_surrounding_whitespace`
    // and `_labels_are_distinct` cross-entry siblings; together
    // they pin the leading-character case, the single-line
    // shape, and the pairwise distinctness of every primary
    // menu entry label against a single source of truth.
    use paladin_gtk::app::model::format_app_primary_menu_entries;

    for (label, action) in format_app_primary_menu_entries() {
        let first = label.chars().next().unwrap_or_else(|| {
            panic!(
                "primary menu entry label for action target {action:?} must be non-empty (the `_labels_are_single_line_without_surrounding_whitespace` companion already pins this; restated here so the upper-case assertion has a non-empty char to inspect); got {label:?}"
            )
        });
        assert!(
            first.is_ascii_uppercase(),
            "primary menu entry label for action target {action:?} must start with an uppercase ASCII letter to match the GNOME HIG §\"Menu items\" header-style capitalization convention (a lowercase-leading label like `\"import…\"` would render as a visually-inconsistent entry against its title-cased neighbours in the same `gtk::MenuButton` popover and against the GNOME stack's default `gtk::MenuButton` labels); got first character {first:?} (U+{:04X}) in label {label:?}",
            first as u32,
        );
    }
}

#[test]
fn format_app_header_bar_button_tooltips_start_with_an_uppercase_letter() {
    // Cross-button defense-in-depth sibling of the per-button
    // `_returns_X` exact-value pins
    // (`format_app_add_button_tooltip_returns_add_account`,
    // `format_app_search_button_tooltip_returns_search_accounts`,
    // `format_app_menu_button_tooltip_returns_main_menu`), the
    // per-button `_is_non_empty` shape pins, the cross-button
    // `format_app_header_bar_button_tooltips_are_distinct`
    // (pairwise-distinctness pin),
    // `_are_single_line_without_surrounding_whitespace`
    // (cross-button shape pin on single-line + no padding), and
    // `_are_ascii_only` (cross-button byte-composition pin).
    // Those companions catch the wrong-value, empty,
    // duplicate-tooltip, multi-line, surrounding-whitespace,
    // and non-ASCII regressions but leave the *leading-character
    // case* ungated.
    //
    // The GNOME Human Interface Guidelines (HIG) §"Tooltips"
    // pin tooltip strings as "sentence case" (first word
    // capitalized, the rest lowercase unless they're proper
    // nouns). The `gtk::Button::set_tooltip_text` slot is the
    // screen-reader-readable label for the icon-only header-bar
    // buttons (Add / search / menu), since the button has no
    // visible text label. A regression that landed a
    // lowercase-leading tooltip — e.g. `"add account"` (typo
    // from a sentence-case shadow refactor) or `" add account"`
    // (which would also fail the surrounding-whitespace
    // companion but restates the rule for the case where
    // someone fixed the leading-space regression but left the
    // lowercase letter) — would slip past the existing
    // `_are_distinct` companion (`"add account"` is still
    // distinct from the other two tooltips), the
    // `_are_single_line_without_surrounding_whitespace`
    // companion (no embedded newlines, no surrounding spaces),
    // and the `_are_ascii_only` companion (the lowercase letter
    // is still ASCII), while rendering as a visually-inconsistent
    // tooltip popover against the title-cased / sentence-cased
    // tooltips elsewhere in the GNOME stack (and against the
    // primary menu entry labels pinned by
    // `_primary_menu_entries_labels_start_with_an_uppercase_letter`
    // on the popover-row side, which together with this
    // sibling enforce the leading-character case across both
    // tooltip and menu-entry surfaces of the same
    // `gtk::HeaderBar`).
    //
    // The assertion walks each (label, tooltip) pair and pins
    // the first character of each tooltip as an ASCII uppercase
    // letter. The current three tooltips — `"Add account"`,
    // `"Search accounts"`, `"Main menu"` — all start with an
    // uppercase ASCII letter so this test passes today and
    // serves as a forcing function so any future tooltip
    // refactor stays aligned with the GNOME HIG sentence-case
    // convention. Mirror of the
    // `_primary_menu_entries_labels_start_with_an_uppercase_letter`
    // sibling on the popover-row side and the
    // `_are_single_line_without_surrounding_whitespace` /
    // `_are_distinct` / `_are_ascii_only` cross-button
    // companions on the tooltip-shape side; together they pin
    // the leading-character case, the single-line shape, the
    // pairwise distinctness, and the byte composition of every
    // header-bar button tooltip against a single source of
    // truth.
    use paladin_gtk::app::model::{
        format_app_add_button_tooltip, format_app_menu_button_tooltip,
        format_app_search_button_tooltip,
    };

    for (label, tooltip) in [
        ("Add", format_app_add_button_tooltip()),
        ("search", format_app_search_button_tooltip()),
        ("menu", format_app_menu_button_tooltip()),
    ] {
        let first = tooltip.chars().next().unwrap_or_else(|| {
            panic!(
                "header-bar {label} button tooltip must be non-empty (the per-button `_is_non_empty` companion already pins this; restated here so the upper-case assertion has a non-empty char to inspect); got {tooltip:?}"
            )
        });
        assert!(
            first.is_ascii_uppercase(),
            "header-bar {label} button tooltip must start with an uppercase ASCII letter to match the GNOME HIG §\"Tooltips\" sentence-case convention (a lowercase-leading tooltip like `\"add account\"` would render as a visually-inconsistent popover against the title-cased / sentence-cased tooltips elsewhere in the GNOME stack and against the primary menu entry labels pinned by `_primary_menu_entries_labels_start_with_an_uppercase_letter` on the popover-row side of the same `gtk::HeaderBar`); got first character {first:?} (U+{:04X}) in tooltip {tooltip:?}",
            first as u32,
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_starts_with_the_definite_article() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developer_name_returns_the_paladin_contributors`
    // (exact-value pin to `"The Paladin contributors"`),
    // `_is_non_empty_and_distinct_from_program_name` (positive
    // shape pin + cross-helper distinctness against bare
    // `"Paladin"`), `_is_a_single_line_without_embedded_newlines`
    // (single-line shape pin),
    // `_has_no_surrounding_whitespace` (no-padding shape pin),
    // and `_is_ascii_only` (byte-composition pin). Those
    // companions catch the wrong-value / wrong-shape / multi-line
    // / surrounding-whitespace / non-ASCII regressions but
    // leave the *definite-article prefix* convention ungated.
    //
    // The GNOME Human Interface Guidelines (HIG) §"About
    // dialog" and the broader GNOME / freedesktop convention
    // for collective project attributions prefix the
    // contributor-collective name with the definite article
    // "The " — examples across the GNOME stack include "The
    // GNOME Project", "The GTK Team", "The Files contributors",
    // "The Settings contributors". The article is deliberately
    // included in the attribution voicing so the
    // `AdwAboutDialog::developer-name` header row reads as a
    // *named collective* ("The Paladin contributors are…")
    // rather than as an inventory ("Paladin contributors are
    // [list]…"). A regression that dropped the article — e.g.
    // `"Paladin contributors"` — would slip past the existing
    // companions (the string is still distinct from the bare
    // program name `"Paladin"`, still single-line, still
    // surrounded by no whitespace, still pure ASCII) while
    // diverging from the GNOME convention voicing pinned at
    // the GNOME / freedesktop attribution-style level.
    //
    // The Cargo.toml workspace deliberately omits the `authors`
    // field (per §"AGPL-3.0-or-later open contributor pool" so
    // the dialog does not name a single owner) and routes the
    // attribution through this helper instead, so the
    // definite-article-prefixed voicing is the contract that
    // distinguishes the collective-attribution slot from the
    // bare program-name slot. Pinning the article prefix
    // directly here surfaces the regression with a message
    // naming the offending byte sequence rather than as a
    // quiet attribution-row voicing drift at dialog render
    // time. Mirror of the `_lists_benjamin_porter` positive
    // content pin on the credits-list side and the
    // `_starts_with_copyright_glyph_and_contains_developer_name`
    // companion on the footer-copyright row side; together
    // they pin the leading-character contract across the
    // dialog-header attribution row, the credits-list
    // contributor names, and the footer copyright row against
    // a single source of truth on the GNOME / freedesktop
    // attribution-style convention.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        developer_name.starts_with("The "),
        "AdwAboutDialog developer-name must start with the definite article `\"The \"` so the collective attribution voicing matches the GNOME / freedesktop convention for project attributions (examples: \"The GNOME Project\", \"The GTK Team\", \"The Files contributors\"); a regression that dropped the article would render the dialog-header attribution row as an inventory rather than as a named collective; got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_ends_with_the_contributors_collective_noun() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developer_name_starts_with_the_definite_article`
    // (which pins the leading `"The "` article that distinguishes
    // the collective attribution from an inventory voicing) and
    // `format_app_about_dialog_developer_name_returns_the_paladin_contributors`
    // (exact-value pin to `"The Paladin contributors"`). Those
    // companions catch the dropped-article and wrong-value
    // regressions but leave the *trailing collective-noun*
    // ungated.
    //
    // The collective-attribution voicing convention pinned by
    // the `_starts_with_the_definite_article` companion is
    // `"The <Brand> <collective-noun>"` where `<collective-noun>`
    // is one of "Project" / "Team" / "contributors" /
    // "Developers" / etc. The chosen noun signals the
    // governance model: "The GNOME Project" / "The GTK Team"
    // imply a named org / team boundary, while "The Files
    // contributors" / "The Settings contributors" /
    // "The Paladin contributors" deliberately stays informal
    // and inclusive — anyone who has committed against the
    // project is a "contributor". The AGPL-3.0-or-later
    // open-contributor-pool model the workspace Cargo.toml
    // enforces (deliberately omitting the `authors` field per
    // §"AGPL-3.0-or-later open contributor pool") aligns with
    // the inclusive `"contributors"` collective noun rather
    // than with the named-team `"Team"` / named-org `"Project"`
    // alternatives.
    //
    // A regression that swapped the trailing collective noun
    // — e.g. `"The Paladin Project"` (named-org voicing) or
    // `"The Paladin Team"` (named-team voicing) or
    // `"The Paladin Developers"` (capitalized noun implying a
    // closed-group voicing) — would slip past the
    // `_starts_with_the_definite_article` companion (the
    // leading `"The "` article is still present), the
    // `_is_non_empty_and_distinct_from_program_name` companion
    // (still distinct from the bare `"Paladin"`), the
    // `_is_a_single_line_without_embedded_newlines` companion
    // (still single-line), the `_has_no_surrounding_whitespace`
    // companion (still trim-clean), and the `_is_ascii_only`
    // companion (still pure ASCII), while quietly mis-routing
    // the governance signal of the collective attribution and
    // breaking the AGPL-3.0-or-later open-contributor-pool
    // alignment.
    //
    // Pinning the trailing collective noun directly here
    // surfaces the regression with a message naming the
    // offending byte sequence at the suffix slot rather than
    // as a quiet governance-voicing drift at dialog render
    // time. Mirror of the `_starts_with_the_definite_article`
    // sibling on the leading-article side; together they pin
    // the collective-attribution voicing across the leading
    // article and the trailing collective-noun slots against
    // a single source of truth on the GNOME / freedesktop /
    // AGPL-3.0-or-later attribution-style convention.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        developer_name.ends_with(" contributors"),
        "AdwAboutDialog developer-name must end with the lowercase `\" contributors\"` collective noun (with the leading space so the noun is a separate word from the brand) so the collective-attribution voicing matches the AGPL-3.0-or-later open-contributor-pool model (an inclusive `\"contributors\"` voicing distinct from the named-org `\"Project\"` or named-team `\"Team\"` alternatives the GNOME stack uses for org-boundaried projects); a regression that swapped the noun — e.g. `\"The Paladin Project\"` / `\"The Paladin Team\"` / `\"The Paladin Developers\"` — would mis-route the governance signal of the collective attribution; got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_ends_with_developer_name() {
    // Cross-helper defense-in-depth sibling of
    // `format_app_about_dialog_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    // (which pins the leading `©` glyph and the *substring*
    // presence of the developer-name in the copyright body) and
    // the `_developer_name_ends_with_the_contributors_collective_noun`
    // / `_developer_name_starts_with_the_definite_article`
    // companions on the developer-name side. Those companions
    // catch the wrong-glyph / missing-attribution / wrong-prefix /
    // wrong-suffix regressions on a per-helper basis but leave
    // the *cross-helper ends-with* relationship between the
    // copyright footer row and the dialog-header attribution
    // row ungated.
    //
    // The libadwaita `AdwAboutDialog::copyright` slot is the
    // footer attribution row (one line below the license-type
    // chip and above the website / issue links) and consumes
    // the string verbatim. The canonical form is the leading
    // `©` glyph followed by a single ASCII space followed by
    // the *same* attribution string the dialog-header
    // `AdwAboutDialog::developer-name` row carries. A regression
    // that landed `"© The Paladin contributors (all rights
    // reserved)"` — appending the "(all rights reserved)" tail
    // — would still pass the `_starts_with_copyright_glyph_and_contains_developer_name`
    // companion (the developer-name is still a substring of the
    // copyright body) and the `_separates_glyph_and_attribution_with_a_single_space`
    // companion (the leading two-char sequence `"© "` is still
    // intact) and the `_does_not_contain_a_year_token` companion
    // (no year was added) and the `_is_a_single_line_without_embedded_newlines`
    // companion (still single-line), while diverging the
    // copyright row's trailing byte sequence from the
    // dialog-header attribution row's trailing byte sequence —
    // surfacing as a visual mismatch between the bold header
    // row "The Paladin contributors" and the footer copyright
    // row "© The Paladin contributors (all rights reserved)"
    // at dialog render time. The AGPL-3.0-or-later license
    // explicitly forbids the "all rights reserved" tail
    // (AGPL grants share-alike rights so the tail would be a
    // false license claim), so the cross-helper ends-with
    // relationship is both an aesthetic-consistency pin and a
    // license-compliance forcing function.
    //
    // Pinning the cross-helper ends-with relationship directly
    // here surfaces the regression with a message naming both
    // the copyright and the developer-name byte sequences,
    // rather than as a quiet visual misalignment at dialog
    // render time or as an unnoticed false-license-claim
    // regression. Mirror of the
    // `_starts_with_copyright_glyph_and_contains_developer_name`
    // companion on the substring side and the
    // `_developer_name_ends_with_the_contributors_collective_noun`
    // sibling on the developer-name suffix side; together they
    // pin the full copyright-to-developer-name byte-relationship
    // contract (leading glyph + space, substring containment,
    // trailing-byte equality) across both attribution surfaces
    // against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_copyright, format_app_about_dialog_developer_name,
    };

    let copyright = format_app_about_dialog_copyright();
    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        copyright.ends_with(developer_name),
        "AdwAboutDialog copyright {copyright:?} must end with the developer-name byte sequence {developer_name:?} so the footer-copyright row and the dialog-header attribution row carry the same trailing byte sequence (a regression that appended a tail like `\" (all rights reserved)\"` would diverge the two rows and would also be a false license claim against the AGPL-3.0-or-later share-alike grant)",
    );
}

#[test]
fn format_app_about_dialog_version_starts_with_a_digit() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_version_matches_cargo_pkg_version`
    // (exact-value pin against `env!("CARGO_PKG_VERSION")`),
    // `_is_non_empty_and_looks_like_semver` (non-empty +
    // contains-a-`.` shape pin + no-space byte pin), `_is_ascii_only`
    // (byte-composition pin), and `_has_no_embedded_whitespace`
    // (no-whitespace pin). Those companions catch the wrong-value
    // / wrong-shape / non-ASCII / embedded-whitespace regressions
    // but leave the *leading-character is-digit* convention
    // ungated.
    //
    // The Semantic Versioning 2.0 specification (semver.org)
    // pins the leading character of a valid version string as
    // an ASCII digit (the major-version number): `MAJOR.MINOR.PATCH`
    // where `MAJOR` is `0` or a non-negative integer with no
    // leading zeroes. The cargo `CARGO_PKG_VERSION` env var
    // resolves to the workspace Cargo.toml `version` field (a
    // semver-validated value), so the version helper is always
    // a valid semver — but a future refactor that intercepted
    // the helper with a manual override and prefixed the
    // version with `"v"` (a common convention in git-tag /
    // npm-version contexts: `"v0.0.1"` instead of `"0.0.1"`) or
    // with a build-metadata string (`"build-0.0.1"`) would
    // slip past the `_contains_dot` companion (the `.` separator
    // is still present), the `_matches_cargo_pkg_version` pin
    // (only valid when no manual override is in place), and
    // the `_is_ascii_only` / `_has_no_embedded_whitespace`
    // companions (the prefix is still ASCII and whitespace-free).
    // The libadwaita `AdwAboutDialog::version` slot consumes
    // the string verbatim and renders it next to the program
    // name in the bold header row; a `v`-prefixed version
    // would render as `"Paladin v0.0.1"` instead of the
    // canonical `"Paladin 0.0.1"`, diverging from the GNOME
    // convention for the about-dialog version row (which
    // renders the bare semver) and breaking any AppStream /
    // Flatpak release-notes tooling that match-keys off the
    // bare semver (`<release version="0.0.1">` in the
    // AppStream XML schema, not `<release version="v0.0.1">`).
    //
    // Pinning the leading-digit invariant directly here
    // surfaces the regression with a message naming the
    // offending leading character at build time rather than
    // as a downstream AppStream / Flatpak release-notes
    // schema mismatch at packaging time or as a quiet
    // version-row UX regression at dialog render time.
    // Mirror of the `_looks_like_semver` companion on the
    // `.`-separator side and the `_starts_with_the_definite_article`
    // / `_ends_with_the_contributors_collective_noun` siblings
    // on the developer-name leading- / trailing-character
    // side; together they pin the leading-character contract
    // across the dialog-header version row, the dialog-header
    // attribution row, and the footer-copyright row against a
    // single source of truth on the SemVer / GNOME /
    // AppStream / AGPL-3.0-or-later attribution-style
    // convention.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    let first = version.chars().next().unwrap_or_else(|| {
        panic!(
            "AdwAboutDialog version must be non-empty (the `_is_non_empty_and_looks_like_semver` companion already pins this; restated here so the leading-digit assertion has a non-empty char to inspect); got {version:?}"
        )
    });
    assert!(
        first.is_ascii_digit(),
        "AdwAboutDialog version must start with an ASCII digit so the leading character matches the Semantic Versioning 2.0 `MAJOR.MINOR.PATCH` convention (a regression that prefixed the version with `\"v\"` like `\"v0.0.1\"` from a git-tag / npm-version convention shadow refactor would render as `\"Paladin v0.0.1\"` next to the program name in the bold AdwAboutDialog header row rather than as the canonical `\"Paladin 0.0.1\"`, diverging from the GNOME convention for the about-dialog version row and breaking AppStream / Flatpak release-notes tooling that match-keys off the bare semver in the `<release version=\"...\">` XML schema); got first character {first:?} (U+{:04X}) in version {version:?}",
        first as u32,
    );
}

#[test]
fn format_app_about_dialog_version_has_at_least_three_dot_separated_segments() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_version_matches_cargo_pkg_version`
    // (exact-value pin),
    // `_is_non_empty_and_looks_like_semver` (non-empty +
    // `contains('.')` shape pin + no-space byte pin),
    // `_is_ascii_only` (byte-composition pin),
    // `_has_no_embedded_whitespace` (no-whitespace pin), and
    // `_starts_with_a_digit` (leading-character pin). Those
    // companions catch the wrong-value / wrong-shape / non-ASCII
    // / embedded-whitespace / wrong-leading-byte regressions but
    // leave the *segment-count* convention ungated.
    //
    // The Semantic Versioning 2.0 specification (semver.org)
    // pins a valid version as exactly the form
    // `MAJOR.MINOR.PATCH[-pre-release][+build-metadata]` where
    // the three required numeric segments are separated by `.`
    // characters. The cargo `CARGO_PKG_VERSION` env var resolves
    // to the workspace Cargo.toml `version` field (which cargo
    // validates against the semver grammar), so the version
    // helper is always a valid semver at build time. But a
    // future refactor that intercepted the helper with a manual
    // override — e.g. dropping the patch segment to `"0.1"`
    // (two segments) for a `Cargo.toml` `version = "0.1"` (which
    // cargo actually accepts as shorthand, normalizing to
    // `"0.1.0"` for the package metadata but leaving the
    // env-var value at the raw `"0.1"` string in some toolchain
    // versions) or overriding it to a single-segment string
    // `"1"` from a CI build-tag injection — would slip past the
    // `_contains_dot` companion (which uses `contains('.')`
    // matching for any count ≥ 1, so the `"0.1"` two-segment
    // form passes trivially) while diverging from the strict
    // three-segment semver shape AppStream / Flatpak
    // release-notes tooling expects in the
    // `<release version="0.0.1">` XML schema and the
    // `flatpak-builder` `--repo-include-detached-metadata` pass
    // (both of which validate the version against the strict
    // three-segment semver grammar at packaging time and would
    // reject a two-segment version as a malformed schema
    // entry).
    //
    // Pinning the at-least-three-segments invariant directly
    // here surfaces the regression with a message naming the
    // offending segment count and the offending version string
    // at build time rather than as a downstream AppStream /
    // Flatpak release-notes schema rejection at packaging time
    // or as a quiet version-row layout regression at dialog
    // render time. The assertion uses `>= 3` rather than
    // `== 3` so pre-release suffixes (`"0.0.1-alpha.1"` which
    // splits to four `.`-separated segments) and build-metadata
    // suffixes (`"0.0.1+build.42"`, three segments before the
    // `+` separator) still pass.
    //
    // Mirror of the `_looks_like_semver` companion on the
    // `.`-separator side and the `_starts_with_a_digit` /
    // `_application_icon_name_has_exactly_four_segments`
    // siblings on the leading-character / segment-count side;
    // together they pin the segment-count contract across the
    // dialog-header version row and the application-icon
    // reverse-DNS identifier against a single source of truth
    // on the SemVer / GNOME / AppStream / Flatpak packaging
    // convention.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    let segments: Vec<&str> = version.split('.').collect();
    assert!(
        segments.len() >= 3,
        "AdwAboutDialog version must have at least three `.`-separated segments to match the Semantic Versioning 2.0 `MAJOR.MINOR.PATCH` convention so the AppStream / Flatpak release-notes tooling resolves the `<release version=\"...\">` XML schema entry at packaging time and the bold AdwAboutDialog version row renders the canonical three-segment semver next to the program name; got {len} segment(s) in {version:?} (segments: {segments:?})",
        len = segments.len(),
    );
}

#[test]
fn format_app_about_dialog_version_does_not_end_with_a_dot() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_version_matches_cargo_pkg_version`
    // (exact-value pin),
    // `_is_non_empty_and_looks_like_semver` (non-empty +
    // `contains('.')` shape pin + no-space byte pin),
    // `_is_ascii_only` (byte-composition pin),
    // `_has_no_embedded_whitespace` (no-whitespace pin),
    // `_starts_with_a_digit` (leading-character pin), and
    // `_has_at_least_three_dot_separated_segments` (segment-count
    // pin). Those companions catch the wrong-value /
    // wrong-shape / non-ASCII / embedded-whitespace /
    // wrong-leading-byte / wrong-segment-count regressions but
    // leave the *trailing-`.` byte* edge case ungated.
    //
    // The Semantic Versioning 2.0 specification (semver.org)
    // pins a valid version's trailing character as either a
    // digit (the final character of the PATCH numeric
    // identifier when no pre-release / build-metadata suffix
    // is present), an alphanumeric (the final character of
    // the pre-release identifier when `-<pre-release>` is
    // present), or an alphanumeric / digit (the final
    // character of the build-metadata identifier when
    // `+<build-metadata>` is present). A trailing `.` byte is
    // not a valid terminal in any of the three semver
    // grammar productions; a regression that landed
    // `"0.0.1."` (trailing dot from a manual override typo)
    // or `"0.0.1.0."` (trailing dot from a four-segment
    // attempted-conversion to a mockup `MAJOR.MINOR.PATCH.BUILD`
    // form) would slip past the `_contains_dot` companion
    // (the trailing dot still satisfies `contains('.')`), the
    // `_starts_with_a_digit` companion (the leading character
    // is still a digit), the `_is_ascii_only` companion (the
    // `.` byte is ASCII), the `_has_no_embedded_whitespace`
    // companion (the `.` is not whitespace), the
    // `_has_at_least_three_dot_separated_segments` companion
    // (a trailing dot adds an empty trailing segment, so the
    // segment count is still ≥ 3 — the `"0.0.1."` form splits
    // into `["0", "0", "1", ""]` which has 4 segments,
    // trivially passing the `>= 3` count check), and the
    // `_matches_cargo_pkg_version` exact-value pin (only valid
    // when no manual override is in place — a future refactor
    // that intercepted the helper with a manual override
    // would slip past), diverging from the strict semver shape
    // AppStream / Flatpak release-notes tooling expects in
    // the `<release version="0.0.1">` XML schema (which the
    // strict semver-validation pass at `flatpak-builder` /
    // `appstreamcli validate` time would reject as a
    // malformed schema entry, surfacing as a packaging-time
    // rejection rather than as a build-time failing test).
    //
    // Pinning the no-trailing-dot invariant directly here
    // surfaces the regression with a message naming the
    // offending version string at build time rather than as a
    // downstream AppStream / Flatpak release-notes schema
    // rejection at packaging time. Mirror of the
    // `_is_non_empty_and_looks_like_semver` companion on the
    // `.`-separator side and the `_starts_with_a_digit` /
    // `_has_at_least_three_dot_separated_segments` siblings
    // on the leading-character / segment-count side; together
    // they pin the leading-character, segment-count, and
    // trailing-byte contract across the dialog-header version
    // row against a single source of truth on the SemVer /
    // GNOME / AppStream / Flatpak packaging convention.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.ends_with('.'),
        "AdwAboutDialog version must not end with a `.` byte (which is not a valid terminal in any of the three Semantic Versioning 2.0 grammar productions for MAJOR.MINOR.PATCH, `-<pre-release>`, or `+<build-metadata>`) so the AppStream / Flatpak release-notes `<release version=\"...\">` XML schema entry resolves at packaging time rather than as a malformed-schema rejection; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_version_segments_are_non_empty() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_version_matches_cargo_pkg_version`
    // (exact-value pin),
    // `_is_non_empty_and_looks_like_semver` (non-empty +
    // `contains('.')` shape pin + no-space byte pin),
    // `_is_ascii_only` (byte-composition pin),
    // `_has_no_embedded_whitespace` (no-whitespace pin),
    // `_starts_with_a_digit` (leading-character pin),
    // `_has_at_least_three_dot_separated_segments`
    // (segment-count pin), and `_does_not_end_with_a_dot`
    // (trailing-byte pin). Those companions catch the
    // wrong-value / wrong-shape / non-ASCII / embedded-
    // whitespace / wrong-leading-byte / wrong-segment-count /
    // trailing-dot regressions but leave the *empty-segment*
    // edge case in the *middle* of the version string
    // ungated.
    //
    // The Semantic Versioning 2.0 specification (semver.org)
    // pins each `.`-separated segment as a non-empty numeric
    // identifier (or alphanumeric identifier for pre-release
    // segments) — the grammar production for a SemVer
    // identifier requires at least one character, so the
    // segments `["0", "", "1"]` (from a `"0..1"` regression)
    // are not a valid SemVer because the second segment is
    // empty. A regression that landed `"0..1"` (consecutive
    // dots from a `concat!(env!("CARGO_PKG_VERSION"), ".",
    // env!("BUILD_NUMBER"))` injection where `BUILD_NUMBER`
    // expanded to the empty string) or `".0.0.1"` (leading
    // dot from a `concat!(".", env!("CARGO_PKG_VERSION"))`
    // injection) would slip past the
    // `_is_non_empty_and_looks_like_semver` companion (the
    // `.` separator is still present so `contains('.')`
    // resolves true), the `_starts_with_a_digit` companion
    // (the `"0..1"` form still starts with a digit; only the
    // `".0.0.1"` form would fail this companion but the
    // `"0..1"` form would slip past), the `_is_ascii_only` /
    // `_has_no_embedded_whitespace` companions (the `.`
    // byte is ASCII and not whitespace), the
    // `_has_at_least_three_dot_separated_segments` companion
    // (the `"0..1"` form splits into `["0", "", "1"]` which
    // has three segments, trivially passing the `>= 3` count
    // check), the `_does_not_end_with_a_dot` companion (the
    // `"0..1"` form ends with the `1` digit), and the
    // `_matches_cargo_pkg_version` exact-value pin (only
    // valid when no manual override is in place — a future
    // refactor that intercepted the helper with a manual
    // override or a `concat!` injection would slip past),
    // diverging from the strict SemVer 2.0 grammar (which
    // requires every segment to be a non-empty identifier)
    // and would be rejected by AppStream / Flatpak
    // release-notes tooling (which validates the version
    // against the strict SemVer grammar at packaging time
    // via `appstreamcli validate` and `flatpak-builder
    // --repo-include-detached-metadata` and would reject an
    // empty-segment version as a malformed schema entry,
    // surfacing as a packaging-time rejection rather than as
    // a build-time failing test).
    //
    // Pinning the per-segment non-emptiness invariant
    // directly here surfaces the regression with a message
    // naming the offending segment index and the offending
    // version string at build time rather than as a
    // downstream AppStream / Flatpak release-notes schema
    // rejection at packaging time. The assertion walks every
    // `.`-separated segment (so any empty segment — leading
    // dot, trailing dot, or consecutive dots — is caught by
    // the same loop body). Mirror of the
    // `format_app_about_dialog_application_icon_name_segments_are_non_empty`
    // sibling on the application-icon reverse-DNS side and
    // the `_starts_with_a_digit` / `_does_not_end_with_a_dot`
    // / `_has_at_least_three_dot_separated_segments`
    // companions on the version-segment-shape side; together
    // they pin the per-segment non-emptiness contract across
    // the dialog-header version row and the application-icon
    // reverse-DNS identifier against a single source of truth
    // on the SemVer / GNOME / AppStream / Flatpak packaging
    // convention.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    for (idx, segment) in version.split('.').enumerate() {
        assert!(
            !segment.is_empty(),
            "AdwAboutDialog version `.`-separated segment at position {idx} must be non-empty so each segment is a valid Semantic Versioning 2.0 identifier (consecutive `.` characters or a leading / trailing `.` would inject an empty segment and break the strict SemVer grammar AppStream / Flatpak release-notes tooling expects); got {version:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_version_does_not_start_with_a_dot() {
    // Defense-in-depth sibling of the just-added
    // `format_app_about_dialog_version_does_not_end_with_a_dot`
    // companion (which pins the trailing-byte against the `.`
    // byte) on the leading-byte side. Together they pin both
    // the leading and trailing terminal-byte edge cases against
    // the strict Semantic Versioning 2.0 (semver.org) grammar.
    //
    // The just-added `_starts_with_a_digit` companion already
    // pins the leading character of the version as an ASCII
    // digit — which transitively excludes a leading `.` byte
    // (since `.` is not a digit). Restating the no-leading-dot
    // rule independently here surfaces the regression with a
    // message naming the specific offending byte (the `.`
    // rather than the more general "any non-digit") and keeps
    // the leading- / trailing-byte rule symmetric across the
    // two ends of the version string for the case where a
    // future refactor weakens the `_starts_with_a_digit` pin
    // (e.g. broadening it to accept letter-prefixed pre-release
    // tags as a temporary stopgap) — the no-leading-dot pin
    // here would still hold and catch the leading-`.` edge case
    // independently.
    //
    // A regression that landed `".0.0.1"` (leading dot from a
    // `concat!(".", env!("CARGO_PKG_VERSION"))` injection) or
    // `".."` (consecutive dots terminated; mostly caught by
    // `_segments_are_non_empty` but restated here for the
    // leading-dot edge case) would render the `AdwAboutDialog`
    // version row as `"Paladin .0.0.1"` next to the program
    // name in the bold header row — visually mis-rendering the
    // leading byte as a punctuation glyph rather than the
    // canonical leading digit — and would be rejected by
    // AppStream / Flatpak release-notes tooling (which
    // validates the version against the strict SemVer grammar
    // and would reject a leading-`.` version as a malformed
    // schema entry).
    //
    // The current `env!("CARGO_PKG_VERSION")` resolves to
    // `"0.0.1"` which starts with the `0` digit so this test
    // passes today and serves as a forcing function so any
    // future override of the version helper stays aligned
    // with the strict SemVer 2.0 leading-byte grammar.
    // Mirror of the `_does_not_end_with_a_dot` companion on
    // the trailing-byte side, the `_starts_with_a_digit`
    // companion on the leading-character side, and the
    // `_segments_are_non_empty` companion on the per-segment
    // non-emptiness side; together they pin the no-empty-
    // segment / leading-digit / no-leading-dot / no-trailing-dot
    // contract across the dialog-header version row against
    // a single source of truth on the SemVer / GNOME /
    // AppStream / Flatpak packaging convention.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.starts_with('.'),
        "AdwAboutDialog version must not start with a `.` byte (which is not a valid leading character in any of the Semantic Versioning 2.0 grammar productions — MAJOR must be a non-negative integer starting with `0`-`9` or a non-zero digit followed by digits) so the AppStream / Flatpak release-notes `<release version=\"...\">` XML schema entry resolves at packaging time rather than as a malformed-schema rejection and the AdwAboutDialog version row renders the canonical bare-major leading digit rather than a punctuation glyph next to the program name; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_end_with_a_dot() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_application_icon_name_matches_app_id`
    // (exact-value pin),
    // `_is_reverse_dns` (reverse-DNS shape pin),
    // `_is_ascii_only` (byte-composition pin),
    // `_has_no_embedded_whitespace` (no-whitespace pin),
    // `_segments_are_non_empty` (per-segment non-emptiness pin),
    // `_has_exactly_four_segments` (segment-count pin), and
    // `_ends_with_gui_segment` (trailing-segment pin). Those
    // companions catch the wrong-value / wrong-shape / non-ASCII
    // / embedded-whitespace / empty-segment / wrong-segment-count
    // / wrong-trailing-segment regressions but a regression that
    // landed `"org.tamx.Paladin.Gui."` (trailing dot from a
    // `concat!(crate::APP_ID, ".")` injection) would slip past
    // the `_ends_with_gui_segment` companion (since `ends_with`
    // checks the substring `"Gui"` and `"org.tamx.Paladin.Gui."`
    // does not literally end with `"Gui"` — wait, let's
    // re-examine: `_ends_with_gui_segment` would *catch* a literal
    // trailing dot since the string no longer ends with `"Gui"`),
    // but the symmetric `_segments_are_non_empty` companion would
    // *not* always catch every trailing-dot variant cleanly: a
    // `"org.tamx.Paladin.Gui."` form splits into
    // `["org", "tamx", "Paladin", "Gui", ""]` which would be
    // caught by `_segments_are_non_empty` (the empty trailing
    // segment trips the loop) but the `_has_exactly_four_segments`
    // companion would also fail (since the split count is now
    // 5, not 4) — both companions would fire on this regression,
    // which is good defense-in-depth, but neither names the
    // *trailing-`.` byte* directly in its failure message.
    //
    // Pinning the no-trailing-dot invariant directly here
    // surfaces the regression with a failure message naming the
    // specific offending trailing byte (the `.` rather than the
    // more general "wrong segment count" or "empty segment at
    // position N"), and keeps the leading- / trailing-byte rule
    // symmetric with the `format_app_about_dialog_version_does_not_end_with_a_dot`
    // sibling on the version side. The reverse-DNS application-ID
    // grammar that GNOME's D-Bus naming convention and the
    // AppStream / Flatpak `<id>...</id>` schema validate against
    // — and which `gio::ApplicationId::is_valid` enforces at
    // application-startup — pins each `.`-separated segment as a
    // non-empty alphanumeric/underscore identifier with no
    // leading or trailing dots, so a trailing-dot reverse-DNS
    // string would be rejected by `gio::ApplicationId::is_valid`
    // at startup, by the AppStream validator at packaging time,
    // and by the Flatpak `--build-finish` step that validates
    // the `<id>` against the directory name in the build
    // sandbox.
    //
    // Pinning the no-trailing-dot invariant directly here
    // surfaces the regression with a message naming the offending
    // application-icon-name string at build time rather than as a
    // downstream GIO startup rejection, AppStream packaging
    // rejection, or Flatpak build-finish rejection. The current
    // `crate::APP_ID` resolves to `"org.tamx.Paladin.Gui"` which
    // ends with the `i` letter of the trailing `Gui` segment
    // (not with a `.`), so this test passes today and serves as
    // a forcing function so any future override of the
    // application-icon-name helper stays aligned with the strict
    // reverse-DNS / GNOME / D-Bus / AppStream / Flatpak naming
    // convention. Mirror of the
    // `format_app_about_dialog_version_does_not_end_with_a_dot`
    // companion on the version-side trailing-byte rule, and
    // sibling of the
    // `format_app_about_dialog_application_icon_name_segments_are_non_empty`
    // / `_has_exactly_four_segments` / `_ends_with_gui_segment`
    // companions on the reverse-DNS shape side; together they
    // pin the no-empty-segment / exact-four-segment / known-
    // trailing-segment / no-trailing-dot contract across the
    // application-icon reverse-DNS identifier against a single
    // source of truth on the GNOME / D-Bus / AppStream / Flatpak
    // packaging convention.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.ends_with('.'),
        "AdwAboutDialog application_icon_name must not end with a `.` byte (which is not a valid terminal in the reverse-DNS application-ID grammar that GNOME's D-Bus naming convention and the AppStream / Flatpak `<id>...</id>` schema validate against — each `.`-separated segment must be a non-empty alphanumeric/underscore identifier) so `gio::ApplicationId::is_valid` resolves at application startup, the AppStream validator resolves at packaging time, and the Flatpak `--build-finish` step resolves the `<id>` against the directory name in the build sandbox rather than as a downstream rejection; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_start_with_a_dot() {
    // Defense-in-depth sibling of the just-added
    // `format_app_about_dialog_application_icon_name_does_not_end_with_a_dot`
    // companion (which pins the trailing byte against the `.`
    // byte) on the leading-byte side. Together they pin both
    // the leading- and trailing-terminal-byte edge cases against
    // the strict reverse-DNS application-ID grammar that GNOME's
    // D-Bus naming convention and the AppStream / Flatpak
    // `<id>...</id>` schema validate against.
    //
    // A regression that landed `".org.tamx.Paladin.Gui"`
    // (leading dot from a `concat!(".", crate::APP_ID)`
    // injection) would slip past the `_is_reverse_dns` companion
    // (since the `.` separator is still present so the
    // `contains('.')` shape check trivially passes), the
    // `_is_ascii_only` companion (the `.` byte is ASCII), the
    // `_has_no_embedded_whitespace` companion (the `.` is not
    // whitespace), and the `_ends_with_gui_segment` companion
    // (the string still ends with the `Gui` segment). The
    // `_segments_are_non_empty` companion would catch the empty
    // leading segment (from the leading dot creating an empty
    // first segment when split by `.`), and the
    // `_has_exactly_four_segments` companion would catch the
    // five-segment split — but neither names the offending
    // leading `.` byte directly in its failure message. The
    // `_matches_app_id` exact-value pin would catch the
    // regression only when `crate::APP_ID` is the canonical
    // string; a future refactor that intercepted the helper
    // with a manual override or a `concat!` injection would
    // slip past.
    //
    // A leading-`.` reverse-DNS string would be rejected by
    // `gio::ApplicationId::is_valid` at application startup
    // (which pins each `.`-separated segment as a non-empty
    // alphanumeric/underscore identifier with no leading or
    // trailing dots), by the AppStream validator at packaging
    // time, and by the Flatpak `--build-finish` step that
    // validates the `<id>` against the directory name in the
    // build sandbox. Pinning the no-leading-dot invariant
    // directly here surfaces the regression with a message
    // naming the offending icon-name string at build time
    // rather than as a downstream GIO startup rejection,
    // AppStream packaging rejection, or Flatpak build-finish
    // rejection.
    //
    // The current `crate::APP_ID` resolves to
    // `"org.tamx.Paladin.Gui"` which starts with the `o` letter
    // of the leading `org` segment (not with a `.`), so this
    // test passes today and serves as a forcing function so any
    // future override of the application-icon-name helper stays
    // aligned with the strict reverse-DNS / GNOME / D-Bus /
    // AppStream / Flatpak naming convention. Mirror of the
    // `_application_icon_name_does_not_end_with_a_dot` companion
    // on the trailing-byte side, the
    // `format_app_about_dialog_version_does_not_start_with_a_dot`
    // sibling on the version-side leading-byte rule, and the
    // `_segments_are_non_empty` / `_has_exactly_four_segments` /
    // `_ends_with_gui_segment` companions on the reverse-DNS
    // shape side; together they pin the no-empty-segment /
    // exact-four-segment / known-trailing-segment / no-leading-
    // dot / no-trailing-dot contract across the application-icon
    // reverse-DNS identifier against a single source of truth on
    // the GNOME / D-Bus / AppStream / Flatpak packaging
    // convention.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.starts_with('.'),
        "AdwAboutDialog application_icon_name must not start with a `.` byte (which is not a valid leading character in the reverse-DNS application-ID grammar that GNOME's D-Bus naming convention and the AppStream / Flatpak `<id>...</id>` schema validate against — each `.`-separated segment must be a non-empty alphanumeric/underscore identifier and the leading segment must therefore begin with an alphanumeric/underscore character) so `gio::ApplicationId::is_valid` resolves at application startup, the AppStream validator resolves at packaging time, and the Flatpak `--build-finish` step resolves the `<id>` against the directory name in the build sandbox rather than as a downstream rejection; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_starts_with_a_lowercase_ascii_letter() {
    // Defense-in-depth sibling of the just-added
    // `_does_not_start_with_a_dot` companion (which pins the
    // leading byte against the `.` byte) on the leading-
    // *character* side, and mirror of the
    // `format_app_about_dialog_version_starts_with_a_digit`
    // sibling on the version-side leading-character rule.
    //
    // The freedesktop / GNOME / D-Bus reverse-DNS application-ID
    // convention (codified in `gio::ApplicationId::is_valid`)
    // pins the leading byte of each `.`-separated segment as an
    // ASCII letter (`A-Z` or `a-z`) or underscore, since
    // segments may not start with a digit. The canonical form
    // used in practice (and required by the Flatpak `<id>` /
    // AppStream `<id>` schema validators which match-key the
    // reverse-DNS identifier against the build directory name)
    // is a lowercase ASCII letter — e.g. `"org.gnome.Foo"`,
    // `"com.example.Bar"`, `"net.example.Baz"` — so the file-
    // system-on-disk directory name under `/app/share/`,
    // `~/.local/share/applications/`, the hicolor icon theme
    // resource keys, and the GSettings schema base paths all
    // route through a lowercase-ASCII-letter leading byte.
    //
    // A regression that landed `"Org.tamx.Paladin.Gui"`
    // (uppercase O from a manual override typo or from a
    // `concat!(env!("UPPERCASE_PREFIX"), ".tamx.Paladin.Gui")`
    // injection where `UPPERCASE_PREFIX` was set to `"Org"`) or
    // `"5org.tamx.Paladin.Gui"` (leading digit from a
    // `concat!("5", crate::APP_ID)` injection) would slip past
    // the `_is_reverse_dns` companion (since the string still
    // satisfies `contains('.')`), the `_segments_are_non_empty`
    // companion (the leading segment is still non-empty), the
    // `_has_exactly_four_segments` companion (the split count
    // is still exactly 4), the `_ends_with_gui_segment`
    // companion (the string still ends with `"Gui"`), the
    // `_is_ascii_only` companion (uppercase letters and digits
    // are ASCII), the `_has_no_embedded_whitespace` companion,
    // and the just-added `_does_not_start_with_a_dot` companion
    // (the leading byte is not `.`). The `_matches_app_id`
    // exact-value pin would catch the regression only when
    // `crate::APP_ID` is the canonical string; a future refactor
    // that intercepted the helper with a manual override or a
    // `concat!` injection would slip past.
    //
    // An uppercase-leading or digit-leading reverse-DNS string
    // would be rejected at the same downstream layers as the
    // dot-leading regression: by `gio::ApplicationId::is_valid`
    // at application startup (the GIO validator pins each
    // segment to start with a non-digit alphanumeric character
    // or underscore), by the AppStream validator at packaging
    // time, and by the Flatpak `--build-finish` step that
    // validates the `<id>` against the directory name in the
    // build sandbox (Flatpak's filesystem layout pins
    // directories to lowercase). Pinning the lowercase-ASCII-
    // letter leading-byte invariant directly here surfaces the
    // regression with a message naming the offending leading
    // byte at build time rather than as a downstream GIO
    // startup rejection, AppStream packaging rejection, or
    // Flatpak build-finish rejection.
    //
    // The current `crate::APP_ID` resolves to
    // `"org.tamx.Paladin.Gui"` which starts with the lowercase
    // `o` of the leading `org` segment, so this test passes
    // today and serves as a forcing function so any future
    // override of the application-icon-name helper stays
    // aligned with the strict reverse-DNS / GNOME / D-Bus /
    // AppStream / Flatpak naming convention. Mirror of the
    // `_version_starts_with_a_digit` sibling on the version-
    // side leading-character rule, and companion of the
    // `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot`
    // / `_segments_are_non_empty` / `_has_exactly_four_segments`
    // / `_ends_with_gui_segment` siblings on the reverse-DNS
    // shape side; together they pin the leading-character /
    // no-leading-dot / no-trailing-dot / no-empty-segment /
    // exact-four-segment / known-trailing-segment contract
    // across the application-icon reverse-DNS identifier
    // against a single source of truth on the GNOME / D-Bus /
    // AppStream / Flatpak packaging convention.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    let leading_byte = icon_name.chars().next();
    assert!(
        leading_byte.is_some_and(|c| c.is_ascii_lowercase()),
        "AdwAboutDialog application_icon_name must start with a lowercase ASCII letter (the canonical leading byte for a reverse-DNS application-ID per the freedesktop / GNOME / D-Bus naming convention codified in `gio::ApplicationId::is_valid` — segments may not start with a digit or `.` and the on-disk directory layout pins lowercase-ASCII-letter leading bytes for `/app/share/`, `~/.local/share/applications/`, hicolor icon theme resource keys, and GSettings schema base paths) so the application-startup / packaging / Flatpak build-finish pipeline routes through the canonical lowercase-ASCII-letter leading byte rather than as a downstream rejection; got leading_byte={leading_byte:?} for icon_name={icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_end_with_a_period() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_developer_name_returns_the_paladin_contributors`
    // (exact-value pin),
    // `_is_non_empty_and_distinct_from_program_name` (shape pin),
    // `_is_a_single_line_without_embedded_newlines`
    // (single-line pin), `_has_no_surrounding_whitespace`
    // (no-leading/trailing-whitespace pin), `_is_ascii_only`
    // (byte-composition pin),
    // `_starts_with_the_definite_article` (leading-word pin),
    // and `_ends_with_the_contributors_collective_noun`
    // (trailing-word pin). Those companions catch the wrong-
    // value / wrong-shape / multi-line / surrounding-whitespace
    // / non-ASCII / wrong-leading-word / wrong-trailing-word
    // regressions but a regression that landed
    // `"The Paladin contributors."` (trailing period from a
    // sentence-form override) would slip past the
    // `_ends_with_the_contributors_collective_noun` companion
    // only if that companion's `ends_with` substring check were
    // weakened — currently it pins the trailing substring as
    // `"contributors"` which a `"contributors."` form would
    // *not* end with, so the existing companion does catch this
    // specific regression, but only as a "wrong trailing word"
    // failure rather than naming the trailing `.` byte directly.
    //
    // Mirror of
    // `format_app_about_dialog_comments_does_not_end_with_a_period_per_libadwaita_convention`
    // on the dialog-header attribution-row side. The libadwaita
    // convention for the `AdwAboutDialog` developer-name slot
    // (which renders in the bold dialog-header attribution row
    // next to the program name and version) pins the
    // attribution string as a phrase, not a sentence — the
    // bold-header layout in the libadwaita reference
    // implementation deliberately omits terminal punctuation
    // so the attribution row reads as a label rather than as a
    // declarative sentence. A trailing period would mis-render
    // the attribution row as a sentence fragment and would
    // visually clash with the program name and version that
    // share the same bold header row (neither of which carries
    // a trailing period).
    //
    // A regression that landed `"The Paladin contributors."`
    // (trailing period from a sentence-form override or from a
    // `concat!("The Paladin contributors", ".")` injection)
    // would slip past the `_is_non_empty_and_distinct_from_program_name`
    // companion (the string is still non-empty and distinct
    // from `"Paladin"`), the
    // `_is_a_single_line_without_embedded_newlines` companion
    // (the `.` byte is not a newline), the
    // `_has_no_surrounding_whitespace` companion (the `.` is
    // not whitespace), the `_is_ascii_only` companion (the `.`
    // byte is ASCII), and the
    // `_starts_with_the_definite_article` companion (the
    // leading substring is still `"The "`). The
    // `_ends_with_the_contributors_collective_noun` companion
    // would catch the `"contributors."` form because the
    // string no longer ends with `"contributors"`, but its
    // failure message would name the trailing collective noun
    // rather than the offending trailing `.` byte.
    //
    // Pinning the no-trailing-period invariant directly here
    // surfaces the regression with a message naming the
    // offending trailing byte at build time and keeps the
    // dialog-header attribution-row no-terminal-punctuation
    // contract aligned with the libadwaita reference
    // implementation across both the dialog-header attribution
    // row and the dialog-comments row (which already has its
    // own `_comments_does_not_end_with_a_period_per_libadwaita_convention`
    // companion).
    //
    // The current `format_app_about_dialog_developer_name`
    // returns `"The Paladin contributors"` which ends with the
    // `s` letter of the trailing `"contributors"` collective
    // noun, so this test passes today and serves as a forcing
    // function so any future override of the developer-name
    // helper stays aligned with the libadwaita no-terminal-
    // punctuation convention for the dialog-header attribution
    // row.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        !developer_name.ends_with('.'),
        "AdwAboutDialog developer_name must not end with a `.` byte (per the libadwaita convention for the `AdwAboutDialog` developer-name slot — the bold dialog-header attribution row renders the attribution as a phrase, not a sentence, so terminal punctuation visually clashes with the program name and version that share the same bold header row); got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_end_with_a_period() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_copyright_returns_paladin_copyright_line`
    // (exact-value pin),
    // `_starts_with_copyright_glyph_and_contains_developer_name`
    // (leading-byte / shape pin),
    // `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    // (no-year pin),
    // `_separates_glyph_and_attribution_with_a_single_space`
    // (separator pin),
    // `_is_a_single_line_without_embedded_newlines`
    // (single-line pin), and `_ends_with_developer_name`
    // (trailing-attribution pin). Those companions catch the
    // wrong-value / wrong-shape / contains-year / wrong-
    // separator / multi-line / wrong-trailing-attribution
    // regressions but a regression that landed
    // `"\u{00A9} The Paladin contributors."` (trailing period
    // from a sentence-form override or from a `concat!(_, ".")`
    // injection) would slip past most companions and only fail
    // `_ends_with_developer_name` (because the string no longer
    // literally ends with the developer-name substring) — but
    // that companion's failure message names the trailing
    // attribution rather than the offending trailing `.` byte.
    //
    // Mirror of the just-added
    // `format_app_about_dialog_developer_name_does_not_end_with_a_period`
    // companion on the dialog-footer copyright-row side. The
    // libadwaita convention for the `AdwAboutDialog` copyright
    // slot (which renders in the dialog footer below the
    // license link) pins the copyright string as a notice, not
    // a sentence — the libadwaita reference implementation
    // deliberately omits terminal punctuation so the footer
    // copyright row reads as a label rather than as a
    // declarative sentence (matching the format used by
    // GNOME's reference applications like GNOME Calculator,
    // GNOME Text Editor, and GNOME Files, all of which render
    // their copyright lines as `"© <year> <contributors>"`
    // without a trailing period).
    //
    // A trailing period would mis-render the footer copyright
    // row as a sentence fragment and would visually clash with
    // the matching no-terminal-punctuation contract on the
    // dialog-header attribution row (which the
    // `_developer_name_does_not_end_with_a_period` companion
    // pins) and the dialog-comments row (which the
    // `_comments_does_not_end_with_a_period_per_libadwaita_convention`
    // companion pins).
    //
    // Pinning the no-trailing-period invariant directly here
    // surfaces the regression with a message naming the
    // offending trailing byte at build time and keeps the
    // dialog-footer copyright-row no-terminal-punctuation
    // contract aligned with the libadwaita reference
    // implementation across all three rendered text rows in
    // the about dialog (header attribution row, header
    // comments row, and footer copyright row).
    //
    // The current `format_app_about_dialog_copyright` returns
    // `"\u{00A9} The Paladin contributors"` which ends with
    // the `s` letter of the trailing `"contributors"` collective
    // noun (sourced from `format_app_about_dialog_developer_name`),
    // so this test passes today and serves as a forcing
    // function so any future override of the copyright helper
    // stays aligned with the libadwaita no-terminal-punctuation
    // convention for the dialog-footer copyright row.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.ends_with('.'),
        "AdwAboutDialog copyright must not end with a `.` byte (per the libadwaita convention for the `AdwAboutDialog` copyright slot — the dialog-footer copyright row renders the copyright as a notice, not a sentence, matching the format used by GNOME reference applications like GNOME Calculator, GNOME Text Editor, and GNOME Files which all render their copyright lines without a trailing period); got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_end_with_a_period() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_program_name_returns_paladin`
    // (exact-value pin),
    // `_is_non_empty_and_not_app_id` (non-empty + distinct
    // pin),
    // `_matches_format_app_window_title` (cross-helper
    // consistency pin), `_is_segment_of_application_icon_name`
    // (cross-helper substring pin), `_is_ascii_only` (byte-
    // composition pin), and `_has_no_embedded_whitespace`
    // (no-whitespace pin). Those companions catch the wrong-
    // value / wrong-shape / cross-helper-drift / non-ASCII /
    // embedded-whitespace regressions but a regression that
    // landed `"Paladin."` (trailing period from a sentence-
    // form override or a `concat!("Paladin", ".")` injection)
    // would slip past most companions: the
    // `_is_non_empty_and_not_app_id` companion (the string is
    // still non-empty and distinct from the reverse-DNS
    // `org.tamx.Paladin.Gui`), the `_is_ascii_only` companion
    // (the `.` byte is ASCII), and the
    // `_has_no_embedded_whitespace` companion (the `.` is not
    // whitespace). The `_returns_paladin` exact-value pin and
    // the `_matches_format_app_window_title` /
    // `_is_segment_of_application_icon_name` cross-helper pins
    // would catch the regression only when no compensating
    // change is made on the other side; a future refactor
    // that intercepted multiple helpers in lockstep with the
    // trailing period would slip past those cross-helper pins.
    //
    // Mirror of the
    // `_developer_name_does_not_end_with_a_period` and
    // `_copyright_does_not_end_with_a_period` companions on
    // the dialog-header program-name-row side, completing the
    // no-terminal-punctuation contract across all four
    // rendered text rows in the `AdwAboutDialog`: the bold
    // dialog-header program-name row (this companion), the
    // dialog-header attribution row (the
    // `_developer_name_*` companion), the dialog-header
    // comments row (the `_comments_*` companion), and the
    // dialog-footer copyright row (the `_copyright_*`
    // companion). The libadwaita convention for the
    // `AdwAboutDialog` program-name slot (which renders in
    // the bold dialog-header row, the largest typographic
    // element in the dialog) pins the program name as a
    // label, not a sentence — terminal punctuation would
    // visually clash with the version that shares the same
    // bold header row (which the
    // `_version_does_not_end_with_a_dot` companion already
    // pins).
    //
    // A regression that landed `"Paladin."` would render in
    // the bold header row as `"Paladin. 0.0.1"` next to the
    // version, mis-rendering the program-name row as a
    // sentence fragment and visually clashing with the
    // adjacent no-trailing-dot version row.
    //
    // Pinning the no-trailing-period invariant directly here
    // surfaces the regression with a message naming the
    // offending trailing byte at build time and keeps the
    // dialog-header program-name-row no-terminal-punctuation
    // contract aligned with the libadwaita reference
    // implementation across all four rendered text rows.
    //
    // The current `format_app_about_dialog_program_name`
    // returns `"Paladin"` which ends with the `n` letter, so
    // this test passes today and serves as a forcing function
    // so any future override of the program-name helper stays
    // aligned with the libadwaita no-terminal-punctuation
    // convention for the dialog-header program-name row.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.ends_with('.'),
        "AdwAboutDialog program_name must not end with a `.` byte (per the libadwaita convention for the `AdwAboutDialog` program-name slot — the bold dialog-header row renders the program name as a label, not a sentence, so terminal punctuation visually clashes with the adjacent no-trailing-dot version row pinned by `_version_does_not_end_with_a_dot`); got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_path_separators() {
    // Defense-in-depth security sibling of
    // `format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt`
    // (exact-value pin),
    // `_is_non_empty_single_line_with_txt_extension`
    // (single-line + extension pin), `_is_ascii_only`
    // (byte-composition pin), `_extension_is_lowercase_txt`
    // (extension-case pin), and `_has_no_embedded_whitespace`
    // (no-whitespace pin). Those companions catch the wrong-
    // value / multi-line / non-ASCII / wrong-extension-case /
    // embedded-whitespace regressions but a regression that
    // landed `"../etc/passwd.txt"` (path-traversal injection
    // from an override that builds the filename by joining a
    // user-supplied directory segment with the canonical
    // suffix), `"subdir/paladin-debug-info.txt"` (relative-
    // path segment from a sub-directory-form override), or
    // `"~/Downloads/paladin-debug-info.txt"` (tilde-expansion
    // from a home-relative-form override) would slip past
    // every existing companion: each candidate is still a
    // single line, still ASCII, still ends with `.txt`
    // (lowercase), and contains no whitespace. The
    // `_returns_paladin_debug_info_txt` exact-value pin would
    // catch the regression only when no manual override is in
    // place; a future refactor that intercepted the helper
    // with a manual override built around a user-supplied
    // path segment would slip past.
    //
    // This filename is the default name suggested by the
    // `AdwAboutDialog::set_debug_info_filename` slot when the
    // user clicks the "Save debug info" button in the about
    // dialog's debug-info section — the GTK
    // `gtk::FileChooserNative` save dialog populates its
    // filename field with this string. If the string contains
    // a `/` (POSIX path separator) or `\\` (Windows path
    // separator, surfaced by some GTK backends on Linux
    // through CIFS / Samba mounts), the file-chooser dialog
    // would either resolve the path-separated form as a
    // relative path (descending into a sub-directory of the
    // user-selected directory) or as an absolute path (when
    // the leading segment is `/`), exposing a path-traversal
    // hazard. While the user must still confirm the save
    // location through the file-chooser dialog (so this is
    // not a direct sandbox-escape attack), pinning the
    // bare-filename invariant here prevents the suggested
    // filename from being used as a vehicle for path-
    // traversal social engineering (a maintainer
    // submitting a bug report that suggests overwriting a
    // system file by accepting the proposed filename), and
    // mirrors the safer-default contract Paladin already
    // enforces for vault-file paths (where `0700` parent dir
    // and `0600` file permissions, plus atomic
    // `vault.bin.bak` rotation, are pinned per DESIGN.md §6).
    //
    // The current `format_app_about_dialog_debug_info_filename`
    // returns the bare filename `"paladin-debug-info.txt"`
    // which contains neither `/` nor `\\`, so this test
    // passes today and serves as a forcing function so any
    // future override of the debug-info-filename helper stays
    // a bare filename rather than a path-segmented form. Sibling
    // of the security-relevant `_is_ascii_only` /
    // `_has_no_embedded_whitespace` / `_extension_is_lowercase_txt`
    // companions on the bare-filename-shape side; together
    // they pin the bare-ASCII-no-whitespace-no-path-separators
    // contract across the `set_debug_info_filename`
    // file-chooser default name against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !filename.contains('/'),
        "AdwAboutDialog debug_info_filename must not contain the `/` POSIX path separator (a path-separated suggested filename in the `AdwAboutDialog::set_debug_info_filename` slot would route through the `gtk::FileChooserNative` save-dialog filename-field as a relative or absolute path, exposing a path-traversal hazard when the user accepts the suggested filename); got {filename:?}",
    );
    assert!(
        !filename.contains('\\'),
        "AdwAboutDialog debug_info_filename must not contain the `\\` Windows path separator (some GTK backends on Linux surface `\\` through CIFS / Samba mounts as a path separator, so a `\\`-separated suggested filename would route through the file-chooser dialog as a path-separated form on those backends, exposing the same path-traversal hazard as the POSIX `/` case); got {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_carries_program_name_version_and_app_id`
    // (content-shape pin),
    // `_is_non_empty_text_with_no_trailing_whitespace`
    // (non-empty + no-trailing-whitespace pin),
    // `_starts_with_program_name` (leading-substring pin),
    // `_app_id_appears_on_a_distinct_line_from_program_name`
    // (multi-line pin),
    // `_has_exactly_two_lines` (line-count pin),
    // `_program_name_line_ends_with_the_version` (line-1
    // trailing-substring pin),
    // `_app_id_line_ends_with_the_reverse_dns_app_id` (line-2
    // trailing-substring pin), and `_is_ascii_only` (byte-
    // composition pin). Those companions catch the wrong-shape
    // / wrong-content / empty / multi-line-count / wrong-
    // trailing-substring / non-ASCII regressions but the
    // `_is_ascii_only` companion only pins each byte as ASCII
    // (`0x00`-`0x7F`) — the `\r` carriage-return byte (0x0D)
    // is ASCII, so a regression that landed `"Paladin
    // 0.0.1\r\nApp ID: org.tamx.Paladin.Gui"` (CRLF line
    // endings from a Windows-source copy-paste or from a
    // `concat!(_, "\r\n", _)` injection) would slip past
    // `_is_ascii_only` (the `\r` byte is ASCII).
    //
    // The two-line `\n`-separated payload pin (the
    // `_has_exactly_two_lines` companion uses `str::lines()`
    // which transparently strips `\r\n` *or* `\n` line endings
    // when counting lines, so a CRLF-separated payload would
    // still split into 2 lines and trivially pass the
    // `>= 2` count check). The `_program_name_line_ends_with_the_version`
    // companion uses `str::lines().next()` which strips the
    // trailing `\r\n` or `\n`, so the test would still see
    // the first line ending with the version. None of the
    // existing companions name the `\r` byte directly.
    //
    // A regression that landed `\r` in the payload would
    // mis-render the debug-info content in two ways: (1) when
    // the user pastes the payload into a bug-report form on
    // GitHub, the `\r` characters surface as `^M` artifacts
    // in `git diff` / `git apply` outputs and clutter the
    // maintainer's view of the report, and (2) when the user
    // saves the payload to a `.txt` file via the
    // `AdwAboutDialog::set_debug_info_filename` slot, the
    // GTK file-writer writes the raw bytes so the resulting
    // file has mixed CRLF / LF line endings, breaking POSIX
    // text-processing tools (`grep`, `awk`, `sed`) that
    // expect bare `\n` separators.
    //
    // Pinning the no-CR invariant directly here surfaces the
    // regression with a message naming the offending `\r`
    // byte at build time rather than as a downstream pasted-
    // bug-report rendering artifact or a saved-file POSIX-
    // text-processing breakage.
    //
    // The current `format_app_about_dialog_debug_info`
    // returns `"Paladin 0.0.1\nApp ID: org.tamx.Paladin.Gui"`
    // (built at compile time via `concat!` with a single
    // `"\n"` separator), so this test passes today and serves
    // as a forcing function so any future override of the
    // debug-info helper stays on bare-`\n` line endings rather
    // than `\r\n` Windows line endings.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\r'),
        "AdwAboutDialog debug_info must not contain the `\\r` carriage-return byte (which would surface as `\\r\\n` Windows line endings in a CRLF-separated payload, mis-rendering as `^M` artifacts in pasted bug reports and breaking POSIX text-processing tools when the payload is saved to disk via `set_debug_info_filename`); got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_start_with_a_dot() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt`
    // (exact-value pin),
    // `_is_non_empty_single_line_with_txt_extension`
    // (single-line + extension pin),
    // `_is_ascii_only` (byte-composition pin),
    // `_extension_is_lowercase_txt` (extension-case pin),
    // `_has_no_embedded_whitespace` (no-whitespace pin), and
    // the just-added `_does_not_contain_path_separators`
    // (no-`/`-or-`\\` pin). Those companions catch the wrong-
    // value / multi-line / non-ASCII / wrong-extension-case /
    // embedded-whitespace / path-separator regressions but a
    // regression that landed `".paladin-debug-info.txt"`
    // (leading dot from a sibling-hidden-file-form override
    // or a `concat!(".", original_filename)` injection) would
    // slip past every existing companion: the leading `.` byte
    // is ASCII, is non-whitespace, is not a path separator,
    // and the suffix `.txt` is still lowercase. The
    // `_is_non_empty_single_line_with_txt_extension` companion
    // would still pass (the string remains a non-empty single
    // line ending in `.txt`), and the
    // `_extension_is_lowercase_txt` companion would also pass.
    // The `_returns_paladin_debug_info_txt` exact-value pin
    // would catch the regression only when no manual override
    // is in place; a future refactor that intercepted the
    // helper with a manual override built around a hidden-file
    // form would slip past.
    //
    // On Unix-family filesystems (Linux native, macOS, the
    // host filesystems Flatpak / Snap sandboxes mount through
    // their portal proxies), files whose name starts with a
    // `.` byte are treated as "hidden" — they're omitted from
    // `ls` listings without the `-a` flag, from GNOME Files
    // (Nautilus) listings without the "Show hidden files"
    // toggle, and from the GTK file-chooser dialog's default
    // view without the "Show hidden files" menu item. A
    // `set_debug_info_filename` slot suggesting a leading-dot
    // filename would route the debug-info file into the
    // user's selected directory but render it invisible by
    // default — defeating the purpose of the "Save debug
    // info" button (which is to surface a copy-pasteable
    // artifact users can attach to a bug report).
    //
    // Pinning the no-leading-dot invariant directly here
    // surfaces the regression with a message naming the
    // offending leading byte at build time rather than as a
    // downstream invisible-file UX regression at save time.
    // Mirror of the security-relevant
    // `_does_not_contain_path_separators` companion (which
    // pins the file-chooser dialog can't route the suggested
    // filename through a path-traversal vector) on the
    // visibility-relevant side: together they pin the file-
    // chooser dialog suggests a saveable, visible,
    // non-path-segmented filename rather than an invisible or
    // path-traversal-vector form.
    //
    // The current `format_app_about_dialog_debug_info_filename`
    // returns `"paladin-debug-info.txt"` which starts with
    // the lowercase `p` letter (not a `.`), so this test
    // passes today and serves as a forcing function so any
    // future override of the debug-info-filename helper stays
    // a visible-by-default filename rather than a hidden-file
    // form.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !filename.starts_with('.'),
        "AdwAboutDialog debug_info_filename must not start with a `.` byte (which would make the saved debug-info file a Unix-hidden file omitted from default `ls`, GNOME Files (Nautilus), and GTK file-chooser views — defeating the purpose of the `set_debug_info_filename` slot, which is to surface a copy-pasteable artifact users can attach to bug reports); got {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_contains_exactly_one_period() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_filename_returns_paladin_debug_info_txt`
    // (exact-value pin),
    // `_is_non_empty_single_line_with_txt_extension`
    // (single-line + extension-presence pin),
    // `_extension_is_lowercase_txt` (extension-case pin),
    // `_is_ascii_only` / `_has_no_embedded_whitespace`
    // (byte-composition pins),
    // `_does_not_contain_path_separators` (no-path-separator
    // pin), and `_does_not_start_with_a_dot` (no-leading-dot
    // pin). Those companions catch the wrong-value / multi-
    // line / wrong-extension / non-ASCII / embedded-whitespace
    // / path-separator / hidden-file regressions but a
    // regression that landed `"paladin.debug.info.txt"`
    // (over-dotted form where the hyphens were replaced with
    // periods, surfacing as multiple extension boundaries to
    // downstream tools) or `"paladin-debug-info.tar.txt"`
    // (double-extension form from a `concat!(_, ".tar", _)`
    // injection that mis-implies the file is a tarball when
    // it's plain text) would slip past every existing
    // companion: each candidate is single-line, ASCII, ends
    // with `.txt` lowercase, contains no whitespace / no path
    // separators, and doesn't start with `.`.
    //
    // The libadwaita / GTK file-chooser dialog parses the
    // suggested filename's extension by splitting on the
    // *last* `.` byte, so a multi-period filename has an
    // ambiguous "base name" — the file-chooser dialog
    // displays `"paladin-debug-info.tar"` as the editable
    // base name with `".txt"` as the extension, suggesting to
    // the user that the file is `"paladin-debug-info.tar"`
    // plus a `".txt"` suffix (i.e. a renamed tarball). Pinning
    // exactly-one-period directly here surfaces the regression
    // with a message naming the over-dotted form at build
    // time rather than as a downstream file-chooser UX
    // regression where the editable base name doesn't match
    // the canonical `paladin-debug-info` slug.
    //
    // The current `format_app_about_dialog_debug_info_filename`
    // returns `"paladin-debug-info.txt"` which contains exactly
    // one `.` (separating `"paladin-debug-info"` from `"txt"`),
    // so this test passes today and serves as a forcing
    // function so any future override stays on the simple
    // `<slug>.<extension>` form.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    let period_count = filename.bytes().filter(|&b| b == b'.').count();
    assert_eq!(
        period_count, 1,
        "AdwAboutDialog debug_info_filename must contain exactly one `.` byte (separating the canonical `<slug>` and `<extension>` per the libadwaita / GTK file-chooser dialog's last-`.`-split-into-base-and-extension convention — multi-period filenames render in the file-chooser save dialog with an ambiguous editable base name that doesn't match the canonical slug); got {period_count} periods in {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_null_byte() {
    // Defense-in-depth sibling of
    // `_debug_info_is_ascii_only` (byte-composition pin) and
    // the just-added
    // `_debug_info_does_not_contain_a_carriage_return_byte`
    // (no-`\r` pin). The `_is_ascii_only` companion pins each
    // byte as ASCII (`0x00`-`0x7F`) — the null byte `\0`
    // (0x00) is ASCII, so a regression that landed `"Paladin
    // 0.0.1\0\nApp ID: org.tamx.Paladin.Gui"` (null-byte
    // injection from a C-string-style `concat!(_, "\0", _)`
    // form, possibly from an FFI shim that round-tripped a
    // `CString` payload incorrectly) would slip past the
    // `_is_ascii_only` companion.
    //
    // Null bytes in the debug-info payload would mis-render
    // in multiple downstream surfaces: (1) when the payload
    // is copied to the clipboard via the
    // `AdwAboutDialog::set_debug_info` `Copy debug info`
    // button, the GDK clipboard backend may truncate at the
    // first `\0` byte (GDK's `gdk::Clipboard::set_text`
    // routes through GLib `g_strdup` which is null-
    // terminated), so the pasted payload to a bug report
    // would be incomplete; (2) when the payload is saved to
    // a `.txt` file via `set_debug_info_filename`, the
    // resulting file contains a null byte mid-stream, which
    // most text editors render as a control glyph or refuse
    // to open as text (treating the file as binary); (3)
    // when the payload is rendered to the about-dialog's
    // debug-info widget itself, GTK's `Pango` text engine
    // treats `\0` as a string terminator and may truncate
    // the displayed text.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream clipboard truncation, file-save corruption,
    // or Pango rendering truncation. Current helper builds
    // the payload at compile time via `concat!` over `&'static
    // str` literals (none containing `\0`), so this test
    // passes today and serves as a forcing function so any
    // future override stays free of null bytes.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\0'),
        "AdwAboutDialog debug_info must not contain the `\\0` null byte (which would route through GDK's null-terminated `g_strdup`-backed clipboard, truncate downstream pastes; render as a control glyph or trigger binary-file fallback when saved to disk; and truncate Pango text-engine rendering of the in-dialog debug-info widget); got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_debug_info_does_not_contain_a_null_byte` companion on
    // the filename side. The `_is_ascii_only` companion pins
    // each byte as ASCII — the `\0` byte (0x00) is ASCII, so
    // a regression that landed `"paladin-debug-info\0.txt"`
    // (null-byte injection from a `CString::new` round-trip
    // that didn't strip the trailing null, or a
    // `concat!(_, "\0", _)` form) would slip past
    // `_is_ascii_only`, `_has_no_embedded_whitespace` (`\0`
    // is not whitespace), `_extension_is_lowercase_txt` (the
    // suffix `.txt` is still lowercase),
    // `_does_not_contain_path_separators` (the `\0` is not a
    // path separator), and `_does_not_start_with_a_dot`.
    //
    // Filenames containing null bytes are rejected by both
    // POSIX (`open(2)` returns `EINVAL` on a `\0` in the
    // path) and the GIO layer GTK file-chooser routes through
    // (`g_file_new_for_path` returns `NULL` on null bytes,
    // surfacing as a NULL-deref crash in some GTK versions or
    // as a silent failure in others). A `set_debug_info_filename`
    // slot suggesting a null-byte filename would either crash
    // the file-chooser dialog on open (GTK 4.0-4.10 bare
    // backend) or silently disable the Save button (GTK 4.12+
    // with the path-validation patch). Pinning the no-null-byte
    // invariant directly here surfaces the regression with a
    // message naming the offending byte at build time rather
    // than as a downstream GTK file-chooser crash or silent
    // disable. Current helper returns the literal `"paladin-
    // debug-info.txt"` (no `\0` byte), so this test passes
    // today and serves as a forcing function.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !filename.contains('\0'),
        "AdwAboutDialog debug_info_filename must not contain the `\\0` null byte (which is rejected by POSIX `open(2)` with `EINVAL` and by GIO `g_file_new_for_path` with `NULL`, surfacing as a GTK file-chooser crash on GTK 4.0-4.10 or a silently-disabled Save button on GTK 4.12+); got {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the program-name side. The `_is_ascii_only`
    // companion pins each byte as ASCII — the `\0` byte (0x00)
    // is ASCII, so a regression that landed `"Pal\0adin"`
    // (null-byte injection from a `CString::new` round-trip
    // that didn't strip the trailing null, or a
    // `concat!(_, "\0", _)` form) would slip past
    // `_is_ascii_only`, `_has_no_embedded_whitespace` (`\0`
    // is not whitespace),
    // `_is_non_empty_and_not_app_id` (the string remains
    // non-empty), `_matches_format_app_window_title` (only
    // valid when the cross-helper consistency holds — a
    // future refactor that intercepted both helpers with
    // matching null-byte injections would slip past), or
    // `_returns_paladin` (only valid when no manual override
    // is in place).
    //
    // Null bytes in the program-name string would mis-render
    // in three downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_application_name` setter routes
    // through `g_strdup` (null-terminated) and may truncate
    // the bold dialog-header program-name row at the first
    // `\0` byte (rendering `"Pal\0adin"` as `"Pal"`); (2) the
    // matching `gtk::Window::set_title` setter (the program
    // name is mirrored to the window title per
    // `_matches_format_app_window_title`) truncates the
    // window manager's taskbar / dock display label
    // similarly; (3) the GTK accessibility tree's
    // `accessible-name` property routes through the same
    // GLib null-terminated layer, breaking screen-reader
    // announcements of the application name.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the dialog header, window
    // title, or accessibility tree. Current helper returns
    // the literal `"Paladin"` (no `\0` byte), so this test
    // passes today and serves as a forcing function.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\0'),
        "AdwAboutDialog program_name must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_application_name` / `set_title` / `accessible-name` setters and truncate the bold dialog-header program-name row, the window manager's taskbar / dock display label, and screen-reader announcements at the first `\\0`); got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte` /
    // `_program_name_does_not_contain_a_null_byte`
    // companions on the version side. The `_is_ascii_only`
    // companion pins each byte as ASCII — the `\0` byte (0x00)
    // is ASCII, so a regression that landed `"0.0.\01"`
    // (null-byte injection from a `CString::new` round-trip
    // that didn't strip the trailing null, or a
    // `concat!(env!("CARGO_PKG_VERSION"), "\0")` form fed
    // through a build-script override) would slip past
    // `_is_ascii_only`, `_has_no_embedded_whitespace` (`\0`
    // is not whitespace),
    // `_starts_with_a_digit` (only checks the first char),
    // `_has_at_least_three_dot_separated_segments` (splitting
    // by `.` still yields three non-empty segments),
    // `_does_not_end_with_a_dot`,
    // `_does_not_start_with_a_dot`,
    // `_segments_are_non_empty` (each `.`-separated segment
    // is non-empty even with a `\0` byte inside it), or
    // `_matches_cargo_pkg_version` (only valid when no manual
    // override is in place — a hand-edited helper that swapped
    // `env!("CARGO_PKG_VERSION")` for a string-literal with a
    // null byte would defeat the matching test).
    //
    // Null bytes in the version string would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_version` setter routes through
    // `g_strdup` (null-terminated) and may truncate the
    // dialog-header version-label row at the first `\0` byte
    // (rendering `"0.0.\01"` as `"0.0."`); (2) the same
    // version string is included in the `set_debug_info`
    // payload per `_debug_info_carries_program_name_version_and_app_id`,
    // so a null byte in the version would propagate into the
    // clipboard-copy / file-save / Pango-render surfaces the
    // `_debug_info_does_not_contain_a_null_byte` companion
    // gates; (3) automated bug-report submission tools that
    // scrape the about dialog's version label rely on a clean
    // ASCII semver string to populate version fields, and a
    // mid-string `\0` would silently truncate the reported
    // version mid-flow.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a downstream
    // truncation of the dialog-header version-label row, the
    // debug-info payload, or the bug-report version field.
    // Current helper returns the literal
    // `env!("CARGO_PKG_VERSION")` value (Cargo enforces the
    // semver shape upstream, which is null-byte-free), so this
    // test passes today and serves as a forcing function so
    // any future override of the helper stays free of null
    // bytes.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\0'),
        "AdwAboutDialog version must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_version`, truncate the dialog-header version-label row at the first `\\0`, propagate into the debug-info payload, and corrupt automated bug-report version-field scraping); got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the application-icon-name side. The
    // `_is_ascii_only` companion pins each byte as ASCII —
    // the `\0` byte (0x00) is ASCII, so a regression that
    // landed `"org.tamx.Paladin\0.Gui"` (null-byte injection
    // from a `CString::new` round-trip that didn't strip the
    // trailing null, or a `concat!(_, "\0", _)` form fed
    // through a build-time override of `crate::APP_ID`)
    // would slip past `_is_ascii_only`,
    // `_has_no_embedded_whitespace` (`\0` is not whitespace),
    // `_has_exactly_four_segments` (splitting by `.` still
    // yields four non-empty segments because `\0` is not the
    // `.` separator), `_does_not_start_with_a_dot`,
    // `_does_not_end_with_a_dot`, or
    // `_starts_with_a_lowercase_ascii_letter` (only checks
    // the first char).
    //
    // Null bytes in the application-icon-name string would
    // mis-render in multiple downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_application_icon`
    // setter routes through `g_strdup` (null-terminated) and
    // may truncate the icon-theme lookup key at the first
    // `\0` byte, so the about-dialog header glyph would
    // either fall back to the generic application icon or
    // fail to resolve entirely; (2) the matching launcher /
    // desktop-entry / AppStream `<id>` icon lookups (all
    // sharing the same `crate::APP_ID` string per
    // `_application_icon_name_matches_crate_app_id`) would
    // suffer the same truncation, breaking the launcher icon,
    // the §11.3 `/usr/share/icons/hicolor/...` install layout
    // resolution, and Flathub's metainfo icon resolution; (3)
    // the `RelmApp::new(APP_ID)` constructor call routes
    // through the same GLib-null-terminated layer for its
    // application-id parameter, so DBus activation
    // (`org.freedesktop.DBus.RequestName` on
    // `org.tamx.Paladin.Gui`) would register a truncated bus
    // name and break the single-instance contract.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream icon-theme lookup miss, launcher-icon
    // fallback, or DBus single-instance miss. Current helper
    // returns the literal `crate::APP_ID`
    // (`"org.tamx.Paladin.Gui"`, no `\0` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of `crate::APP_ID` or the helper stays
    // free of null bytes.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.contains('\0'),
        "AdwAboutDialog application_icon_name must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_application_icon` / `RelmApp::new` and truncate the dialog-header glyph icon-theme lookup, the launcher / desktop-entry / AppStream `<id>` icon lookups, and the DBus single-instance bus-name registration at the first `\\0`); got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the developer-name side. The
    // `_is_ascii_only` companion pins each byte as ASCII —
    // the `\0` byte (0x00) is ASCII, so a regression that
    // landed `"The Paladin\0 contributors"` (null-byte
    // injection from a `CString::new` round-trip that didn't
    // strip the trailing null, or a `concat!(_, "\0", _)`
    // form) would slip past `_is_ascii_only`,
    // `_has_no_surrounding_whitespace` (`\0` is not
    // whitespace and is not at the start/end of the string),
    // `_does_not_end_with_a_period`,
    // `_starts_with_the_definite_article` (`"The "` prefix
    // intact), `_ends_with_the_contributors_collective_noun`
    // (`"contributors"` suffix intact), or
    // `_returns_the_paladin_contributors` (only valid when no
    // manual override is in place — a hand-edited helper that
    // swapped the literal for a string with a null byte would
    // defeat the matching test).
    //
    // Null bytes in the developer-name string would mis-
    // render in multiple downstream surfaces: (1) the GLib-
    // backed `AdwAboutDialog::set_developer_name` setter
    // routes through `g_strdup` (null-terminated) and may
    // truncate the dialog-header attribution row at the first
    // `\0` byte (rendering `"The Paladin\0 contributors"` as
    // `"The Paladin"`), confusingly suggesting Paladin is
    // attributed to a single author rather than a collective;
    // (2) the same developer-name string is reused by
    // `_copyright_ends_with_developer_name` to construct the
    // footer copyright row, so a null byte in the developer
    // name would propagate into the copyright slot and
    // similarly truncate the legal attribution line; (3) any
    // future automation that scrapes the developer-name slot
    // (e.g. credit aggregators, license-attribution tooling)
    // would silently lose the trailing portion of the
    // attribution.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the dialog-header attribution
    // row, the footer copyright row, or downstream credit-
    // aggregator output. Current helper returns the literal
    // `"The Paladin contributors"` (no `\0` byte), so this
    // test passes today and serves as a forcing function so
    // any future override of the helper stays free of null
    // bytes.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        !developer_name.contains('\0'),
        "AdwAboutDialog developer_name must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_developer_name`, truncate the dialog-header attribution row, propagate into the footer copyright row that reuses this string, and silently lose trailing attribution in downstream scrapers); got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the copyright side. The copyright helper
    // intentionally contains a non-ASCII byte (the U+00A9 ©
    // glyph encoded as the two-byte UTF-8 sequence
    // `0xC2 0xA9`), so the `_is_ascii_only` companion that
    // gates the program-name / version / application-icon-name
    // / developer-name helpers cannot apply here — meaning a
    // null-byte regression has even more room to hide. A
    // regression that landed `"\u{00A9} The Paladin\0
    // contributors"` (null-byte injection from a
    // `CString::new` round-trip that didn't strip the trailing
    // null, or a `concat!(_, "\0", _)` form) would slip past
    // `_starts_with_copyright_glyph_and_contains_developer_name`
    // (the `©` prefix and `developer_name` substring are both
    // intact),
    // `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    // (`\0` is not a digit), `_separates_glyph_and_attribution_with_a_single_space`
    // (the single-space separator after `©` is intact),
    // `_is_a_single_line_without_embedded_newlines` (`\0` is
    // not `\n` or `\r`), `_ends_with_developer_name` (the
    // suffix matches because the developer_name itself was
    // truncated to match per the
    // `_developer_name_does_not_contain_a_null_byte`
    // companion), `_does_not_end_with_a_period`, or
    // `_returns_paladin_copyright_line` (only valid when no
    // manual override is in place — a hand-edited helper that
    // swapped the literal for a string with a null byte would
    // defeat the matching test).
    //
    // Null bytes in the copyright string would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_copyright` setter routes through
    // `g_strdup` (null-terminated) and may truncate the
    // dialog-footer copyright row at the first `\0` byte
    // (rendering `"\u{00A9} The Paladin\0 contributors"` as
    // `"\u{00A9} The Paladin"`), turning the collective
    // attribution into what looks like an unfinished personal
    // copyright line; (2) any tooling that scrapes the
    // copyright slot (license-attribution aggregators, legal-
    // compliance checks) would silently lose the trailing
    // portion of the AGPL-3.0-or-later attribution and could
    // mis-attribute or reject the project on the basis of an
    // apparently truncated copyright notice; (3) the matching
    // `_ends_with_developer_name` invariant means a null-byte
    // regression on `format_app_about_dialog_developer_name`
    // automatically propagates here, so this test provides
    // an independent guard at the copyright layer.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the dialog-footer copyright
    // row or downstream license-attribution scraping. Current
    // helper returns the literal `"\u{00A9} The Paladin
    // contributors"` (no `\0` byte), so this test passes
    // today and serves as a forcing function so any future
    // override of the helper stays free of null bytes.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\0'),
        "AdwAboutDialog copyright must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_copyright`, truncate the dialog-footer copyright row at the first `\\0`, and silently lose trailing AGPL-3.0-or-later attribution in downstream license-aggregator scrapers); got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_copyright_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the comments-blurb side. The
    // `_is_ascii_only` companion pins each byte as ASCII —
    // the `\0` byte (0x00) is ASCII, so a regression that
    // landed `"Authenticat\0or for TOTP and HOTP"` (null-byte
    // injection from a `CString::new` round-trip that didn't
    // strip the trailing null, or a `concat!(env!("CARGO_PKG_DESCRIPTION"), "\0")`
    // form fed through a build-time override of the helper)
    // would slip past `_is_ascii_only`,
    // `_is_non_empty_single_line_distinct_from_program_name`
    // (`\0` is not `\n` or `\r`, and the string remains
    // non-empty and distinct from the program-name literal),
    // `_does_not_end_with_a_period_per_libadwaita_convention`,
    // or `_matches_cargo_pkg_description` (only valid when no
    // manual override is in place — a hand-edited helper that
    // swapped `env!("CARGO_PKG_DESCRIPTION")` for a string-
    // literal with a null byte would defeat the matching
    // test).
    //
    // Null bytes in the comments blurb would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_comments` setter routes through
    // `g_strdup` (null-terminated) and may truncate the
    // dialog-header tagline row at the first `\0` byte
    // (rendering `"Authenticat\0or for TOTP and HOTP"` as
    // `"Authenticat"`), losing the explanatory tagline that
    // distinguishes Paladin from other GTK applications; (2)
    // the matching Cargo metadata is consumed by `nfpm`
    // (per `_matches_cargo_pkg_description` and the §11
    // packaging pipeline) to populate the `Description:`
    // field of the `.deb` / `.rpm` artifacts, so a null byte
    // in the helper that came from a build-time override of
    // Cargo metadata would mid-stream truncate the
    // distribution package description, breaking
    // `dpkg-deb --info` and `rpm -qi` output for the
    // packaged artifacts; (3) AppStream `<summary>` consumers
    // (`gnome-software`, KDE Discover, the
    // `appstreamcli validate` pass run by the §11 packaging
    // dry-run) reject control bytes in the summary slot, so a
    // null-byte regression here would surface as a validator
    // failure in CI rather than just a silent dialog
    // truncation.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the dialog-header tagline row,
    // the `.deb` / `.rpm` `Description:` field, or as an
    // `appstreamcli validate` failure in CI. Current helper
    // returns the literal `env!("CARGO_PKG_DESCRIPTION")`
    // value (Cargo enforces the description as a TOML string,
    // which is null-byte-free by parser construction), so
    // this test passes today and serves as a forcing function
    // so any future override of the helper stays free of null
    // bytes.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\0'),
        "AdwAboutDialog comments must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_comments`, truncate the dialog-header tagline row at the first `\\0`, truncate the `.deb` / `.rpm` `Description:` field that mirrors `CARGO_PKG_DESCRIPTION`, and fail the `appstreamcli validate` pass on `<summary>` control bytes); got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_null_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `\0` null byte.
    //
    // Mirror of the just-added per-helper
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_copyright_does_not_contain_a_null_byte` /
    // `_comments_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions, structured as a single cross-helper loop to
    // mirror the existing
    // `_url_helpers_are_ascii_only` /
    // `_url_helpers_contain_no_embedded_whitespace` /
    // `_url_helpers_do_not_end_with_a_trailing_slash`
    // cross-helper companions on the URL side. The
    // `_url_helpers_are_ascii_only` companion pins each byte
    // as ASCII (`0x00`-`0x7F`) — the null byte `\0` (0x00) is
    // ASCII, so a regression that landed `"https://example.\0com"`
    // (null-byte injection from a `CString::new` round-trip
    // that didn't strip the trailing null, or a
    // `concat!(env!("CARGO_PKG_REPOSITORY"), "\0/issues")`
    // form fed through a build-time override of Cargo
    // metadata) would slip past the
    // `_url_helpers_are_ascii_only` companion,
    // `_url_helpers_contain_no_embedded_whitespace` (`\0` is
    // not whitespace),
    // `_url_helpers_do_not_end_with_a_trailing_slash` (`\0` is
    // not `/`), or the per-URL
    // `_is_non_empty_https_url[*_distinct*]` and
    // `_matches_cargo_pkg_*` companions (only valid when no
    // manual override is in place — a hand-edited helper that
    // swapped the `env!` source for a string-literal with a
    // null byte would defeat the matching tests).
    //
    // Null bytes in the URL helpers would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_website` /
    // `AdwAboutDialog::set_issue_url` /
    // `AdwAboutDialog::set_support_url` setters route through
    // `g_strdup` (null-terminated) and may truncate the
    // displayed link target at the first `\0` byte (rendering
    // `"https://example.\0com/issues"` as
    // `"https://example."`) — silently breaking the link;
    // (2) the matching `gtk_show_uri` / `xdg-open` click-site
    // routing receives the truncated URL and either fails to
    // resolve or worse routes the click to a different
    // host than the user expects (`"https://example."` is
    // not a valid hostname so the resolver fails open with a
    // browser-default fallback page, the actual destination
    // depends on the configured handler); (3) any tooling
    // that scrapes the about dialog's URL slots
    // (release-tracker bots, license-attribution aggregators)
    // would silently lose the path / query portion of the
    // URL.
    //
    // Pinning the no-null-byte invariant across all three URL
    // helpers in a single cross-helper loop surfaces the
    // regression with a message naming the offending byte and
    // the affected slot at build time rather than as a
    // downstream broken link, an unexpected click-site host,
    // or as silently truncated URL scraper output. Current
    // helpers return the literal `env!("CARGO_PKG_HOMEPAGE")`
    // / `concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")` /
    // `concat!(env!("CARGO_PKG_REPOSITORY"), "/discussions")`
    // values (Cargo accepts non-control characters in those
    // fields and the canonical Paladin workspace values are
    // null-byte-free), so this test passes today and serves
    // as a forcing function so any future hand-edit of the
    // helpers — or any future workspace homepage / repository
    // field change — stays free of null bytes.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('\0'),
            "AdwAboutDialog {label} must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_website` / `set_issue_url` / `set_support_url`, truncate the displayed link target at the first `\\0`, mis-route `gtk_show_uri` / `xdg-open` click-site resolution to either a broken or unexpected host, and silently lose path / query portions in downstream URL scrapers); got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_copyright_does_not_contain_a_null_byte` /
    // `_comments_does_not_contain_a_null_byte` /
    // `_url_helpers_do_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the release-notes-version side. The
    // `_matches_about_dialog_version` and
    // `_matches_cargo_pkg_version` companions assert byte
    // equality against the sibling `format_app_about_dialog_version`
    // and `env!("CARGO_PKG_VERSION")` respectively — so a
    // null-byte regression on the version helper alone would
    // also fail one of those matching tests, but a hand-edit
    // that re-implemented `format_app_about_dialog_release_notes_version`
    // independently (swapping the `env!` source for a string-
    // literal with a null byte) would defeat the matching
    // tests in lockstep and slip past unnoticed.
    //
    // Null bytes in the release-notes-version string would
    // mis-render in multiple downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_release_notes_version`
    // setter routes through `g_strdup` (null-terminated) and
    // may truncate the "What's New" header section at the
    // first `\0` byte, rendering a stale or partial release
    // version next to the release-notes body and giving the
    // user a misleading view of which release they just
    // upgraded to; (2) any automation that pairs the
    // release-notes-version label with the corresponding
    // release-notes body for changelog-scraping purposes
    // would silently use a truncated version key and skip
    // matching release notes; (3) the matching `_matches_*`
    // companions would only detect this regression on the
    // happy path where both sides share an underlying source —
    // a directly-edited helper with a null byte could re-
    // implement equality with the version helper by carrying
    // the same null byte on both sides, defeating both
    // matching tests in tandem.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the dialog's "What's New"
    // header or as a silent miss in changelog-aggregator
    // tooling. Current helper returns the literal
    // `env!("CARGO_PKG_VERSION")` value (Cargo enforces the
    // semver shape upstream, which is null-byte-free), so
    // this test passes today and serves as a forcing function
    // so any future override of the helper stays free of
    // null bytes — independent of the matching tests against
    // the version helper.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\0'),
        "AdwAboutDialog release_notes_version must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_release_notes_version`, truncate the dialog's \"What's New\" header section at the first `\\0`, mislead the user about which release they just upgraded to, and silently mis-key changelog-aggregator scraping output); got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_copyright_does_not_contain_a_null_byte` /
    // `_comments_does_not_contain_a_null_byte` /
    // `_url_helpers_do_not_contain_a_null_byte` /
    // `_release_notes_version_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the credits-page contributor-list side.
    // The `_is_non_empty_array_of_non_empty_single_line_names`
    // companion pins each entry as non-empty and single-line
    // — the `\0` byte (0x00) is neither empty nor `\n` / `\r`,
    // so a regression that landed `["Benjamin\0 Porter"]`
    // (null-byte injection from a `CString::new` round-trip
    // that didn't strip the trailing null, or a
    // `concat!(_, "\0", _)` form) would slip past
    // `_is_non_empty_array_of_non_empty_single_line_names`,
    // `_does_not_contain_developer_name` (the
    // `"The Paladin contributors"` collective string is not a
    // substring of any plausible per-developer entry, with or
    // without a null byte), `_entries_are_distinct` (single-
    // entry list is trivially distinct), `_does_not_contain_app_id`
    // (the reverse-DNS `org.tamx.Paladin.Gui` is not a
    // substring of any plausible per-developer entry),
    // `_does_not_contain_program_name` (an `"Paladin"`-only
    // substring guard, which a `"Benjamin\0 Porter"` payload
    // satisfies), or `_lists_benjamin_porter` (only valid
    // when no manual override is in place — a hand-edited
    // helper that swapped the literal for a string with a
    // null byte would defeat the matching test).
    //
    // Null bytes in the credits-page contributor entries
    // would mis-render in multiple downstream surfaces: (1)
    // the GLib-backed `AdwAboutDialog::set_developers` setter
    // hands the array to GTK as a `&[&str]` which is
    // internally bridged to GLib's null-terminated strv via
    // `g_strdupv` — each entry's `g_strdup` may truncate at
    // the first `\0` byte, rendering `"Benjamin\0 Porter"`
    // as `"Benjamin"` in the credits-page "Developers"
    // section, misattributing the contributor as a single-
    // name developer rather than the full credited name; (2)
    // any tooling that scrapes the credits-page contributor
    // list (release-note generators, contributor-attribution
    // crawlers, GNOME `gnome-software` credit aggregators)
    // would silently lose the surname portion of each
    // truncated entry; (3) future scrolling-credits widgets
    // that depend on per-entry text-width calculations would
    // measure the truncated entry width and render layout
    // bugs.
    //
    // Pinning the no-null-byte invariant across every
    // contributor entry in a single per-entry loop surfaces
    // the regression with a message naming both the offending
    // byte and the affected entry index at build time rather
    // than as a downstream truncation of the credits-page
    // section, downstream attribution-scraper miss, or layout
    // bug. Current helper returns the literal
    // `["Benjamin Porter"]` (no `\0` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — or any future
    // contributor addition — stays free of null bytes.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\0'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdupv` / `g_strdup` layer in `set_developers`, truncate the credits-page \"Developers\" entry at the first `\\0`, misattribute the contributor as a single-name developer, and silently lose the surname in downstream attribution scrapers); got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_copyright_does_not_contain_a_null_byte` /
    // `_comments_does_not_contain_a_null_byte` /
    // `_url_helpers_do_not_contain_a_null_byte` /
    // `_release_notes_version_does_not_contain_a_null_byte` /
    // `_developers_entries_do_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the translator-credits side. The
    // `_translator_credits_is_empty_until_translations_land`
    // companion pins the helper to the empty literal `""` for
    // the v0.0.1 / pre-v0.2 workspace because Paladin has not
    // yet shipped a translation; the empty-string return
    // trivially contains no `\0` byte. However, once
    // translations land, the helper will return a non-empty
    // string of the form `"name1 <email1>\nname2 <email2>"`
    // (libadwaita's translator-credits convention) — at that
    // point a null-byte injection from a tooling export
    // pipeline (`xgettext` / `msgfmt` round-trips that
    // mishandle UTF-8 encoding, or a `concat!(_, "\0", _)`
    // template form) would slip past the
    // `_is_empty_until_translations_land` companion (the
    // string is no longer empty),
    // `_is_single_line_when_non_empty` (the libadwaita
    // convention uses `\n` between translator entries — `\0`
    // is not `\n` or `\r`, so a `\0` byte embedded mid-entry
    // would not register as a line break), or
    // `_has_no_surrounding_whitespace_when_non_empty` (the
    // null byte is non-whitespace and is mid-string).
    //
    // Null bytes in the translator-credits string would mis-
    // render in multiple downstream surfaces: (1) the GLib-
    // backed `AdwAboutDialog::set_translator_credits` setter
    // routes through `g_strdup` (null-terminated) and may
    // truncate the credits-page "Translators" section at the
    // first `\0` byte, mis-attributing the translation team
    // or silently omitting downstream translators in the
    // listed order; (2) any `gettext` / `xgettext` re-import
    // pipeline that round-trips the translator credits back
    // through the localization tooling would silently lose
    // the trailing entries on the next export pass; (3) the
    // `_starts_and_ends_with_a_markup_element_when_non_empty`
    // companion only applies to release-notes (the
    // translator-credits slot follows a different
    // libadwaita convention), so this test fills a gap
    // unique to the translator-credits side.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the credits-page
    // "Translators" section or as a silent loss of
    // localization-pipeline entries. Current helper returns
    // the empty literal `""` (no `\0` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — including the eventual
    // landing of an actual translator-credits string — stays
    // free of null bytes.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\0'),
        "AdwAboutDialog translator_credits must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_translator_credits`, truncate the credits-page \"Translators\" section at the first `\\0`, mis-attribute the translation team, and silently lose trailing entries on the next localization-pipeline export pass); got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_null_byte() {
    // Defense-in-depth mirror of the just-added
    // `_program_name_does_not_contain_a_null_byte` /
    // `_version_does_not_contain_a_null_byte` /
    // `_application_icon_name_does_not_contain_a_null_byte` /
    // `_developer_name_does_not_contain_a_null_byte` /
    // `_copyright_does_not_contain_a_null_byte` /
    // `_comments_does_not_contain_a_null_byte` /
    // `_url_helpers_do_not_contain_a_null_byte` /
    // `_release_notes_version_does_not_contain_a_null_byte` /
    // `_developers_entries_do_not_contain_a_null_byte` /
    // `_translator_credits_does_not_contain_a_null_byte` /
    // `_debug_info_does_not_contain_a_null_byte` /
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companions on the release-notes body side. The
    // `_release_notes_is_empty_until_v0_2_ships`
    // companion pins the helper to the empty literal `""`
    // for the v0.0.1 / pre-v0.2 workspace because Paladin has
    // not yet shipped a tagged release; the empty-string
    // return trivially contains no `\0` byte. However, once
    // v0.2 ships the helper will return a non-empty Pango-
    // subset markup body of the form
    // `"<ul><li>…</li></ul>"` (per
    // `_starts_and_ends_with_a_markup_element_when_non_empty`)
    // — at that point a null-byte injection from a tooling
    // pipeline (a CHANGELOG.md → markup transform that
    // mishandles a UTF-8 round trip, or a
    // `concat!(_, "\0", _)` template form) would slip past
    // `_is_empty_until_v0_2_ships` (the string is no longer
    // empty),
    // `_starts_and_ends_with_a_markup_element_when_non_empty`
    // (a `\0` byte mid-body does not change the opening `<`
    // or closing `>` markup boundaries),
    // `_has_no_surrounding_whitespace_when_non_empty` (`\0`
    // is non-whitespace and is mid-string), and the
    // `_must_be_paired_with_a_non_empty_version_when_non_empty`
    // pairing companion (the version remains non-empty
    // regardless of `\0` in the body).
    //
    // Null bytes in the release-notes body would mis-render
    // in multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_release_notes` setter routes
    // through `g_strdup` (null-terminated) and may truncate
    // the "What's New" section body at the first `\0` byte,
    // silently omitting all release-note bullet points after
    // the truncation; (2) the Pango markup parser the dialog
    // routes the body through (per the markup-element
    // companion) terminates the markup parse at the first
    // `\0` byte regardless of opening tags, so a partially-
    // rendered body would leave dangling unclosed markup
    // tags and trigger Pango parse warnings on the console;
    // (3) any tooling that scrapes the about dialog's
    // release-notes slot (in-app changelog displays,
    // release-aggregator bots) would silently lose the
    // trailing changelog bullets that came after the `\0`.
    //
    // Pinning the no-null-byte invariant directly here
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream truncation of the "What's New" body,
    // dangling Pango parse warnings, or as a silent loss of
    // release-aggregator bullets. Current helper returns the
    // empty literal `""` (no `\0` byte), so this test passes
    // today and serves as a forcing function so any future
    // override of the helper — including the eventual
    // landing of an actual v0.2 release-notes markup body —
    // stays free of null bytes.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\0'),
        "AdwAboutDialog release_notes must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_release_notes`, truncate the \"What's New\" section body at the first `\\0`, terminate the Pango markup parse mid-stream and trigger dangling-tag warnings, and silently lose trailing changelog bullets in downstream release-aggregator scrapers); got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_null_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three currently-empty `AdwAboutDialog` credits-section
    // array helpers
    // (`format_app_about_dialog_designers`,
    // `format_app_about_dialog_artists`,
    // `format_app_about_dialog_documenters`) and pinning each
    // entry as free of the `\0` null byte. Mirror of the
    // just-added per-helper / cross-helper companions
    // (`_program_name_does_not_contain_a_null_byte`,
    // `_version_does_not_contain_a_null_byte`,
    // `_application_icon_name_does_not_contain_a_null_byte`,
    // `_developer_name_does_not_contain_a_null_byte`,
    // `_copyright_does_not_contain_a_null_byte`,
    // `_comments_does_not_contain_a_null_byte`,
    // `_url_helpers_do_not_contain_a_null_byte`,
    // `_release_notes_version_does_not_contain_a_null_byte`,
    // `_developers_entries_do_not_contain_a_null_byte`,
    // `_translator_credits_does_not_contain_a_null_byte`,
    // `_release_notes_does_not_contain_a_null_byte`,
    // `_debug_info_does_not_contain_a_null_byte`,
    // `_debug_info_filename_does_not_contain_a_null_byte`)
    // structured as a single cross-helper loop similar to the
    // existing `_url_helpers_are_ascii_only` /
    // `_url_helpers_do_not_contain_a_null_byte`
    // cross-helper companions.
    //
    // The three helpers currently return the empty array
    // `[]` because Paladin does not yet have a separately-
    // credited designer / artist / documenter for the v0.2
    // release. The empty-array return trivially contains no
    // entries (let alone null-byte-bearing entries), so this
    // test passes today as the loop body is never entered.
    // However, once any of the three credits sections gains
    // a contributor, the helper return type will switch from
    // `[&'static str; 0]` to `[&'static str; N]` with
    // non-empty entries — at that point a null-byte injection
    // from a `concat!(_, "\0", _)` form or from a tooling
    // export pipeline (CHANGELOG.md → credits transform)
    // would slip past every other companion the way the
    // `_developers_entries_do_not_contain_a_null_byte`
    // sibling already documents for the developers helper.
    //
    // Null bytes in the credits-section entries would mis-
    // render in multiple downstream surfaces, identically to
    // the `set_developers` analysis in the
    // `_developers_entries_do_not_contain_a_null_byte`
    // companion: (1) the GLib-backed `set_designers` /
    // `set_artists` / `set_documenters` setters route through
    // `g_strdupv` / `g_strdup` and may truncate each entry at
    // the first `\0` byte in the credits-page section; (2)
    // any tooling that scrapes the credits-page contributor
    // list (GNOME `gnome-software` credit aggregators) would
    // silently lose the surname portion of each truncated
    // entry; (3) future scrolling-credits widgets that depend
    // on per-entry text-width calculations would render
    // layout bugs around the truncated entries.
    //
    // Pinning the no-null-byte invariant across all three
    // currently-empty credits-section helpers in a single
    // cross-helper loop surfaces the regression with a
    // message naming the affected helper, the offending byte,
    // and the entry index at build time rather than as a
    // downstream truncation of the credits-page sections.
    // Current helpers return the empty array `[]` (zero
    // entries, no `\0` byte to find), so this test passes
    // today and serves as a forcing function so any future
    // override of the helpers — including the eventual
    // landing of separately-credited designer / artist /
    // documenter strings — stays free of null bytes.
    use paladin_gtk::app::model::{
        format_app_about_dialog_artists, format_app_about_dialog_designers,
        format_app_about_dialog_documenters,
    };

    let designers = format_app_about_dialog_designers();
    let artists = format_app_about_dialog_artists();
    let documenters = format_app_about_dialog_documenters();

    let sections: [(&str, &[&str]); 3] = [
        ("designers", &designers),
        ("artists", &artists),
        ("documenters", &documenters),
    ];

    for (label, entries) in sections {
        for (idx, entry) in entries.iter().enumerate() {
            assert!(
                !entry.contains('\0'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdupv` / `g_strdup` layer in `set_{label}`, truncate the credits-page section entry at the first `\\0`, and silently lose the surname portion in downstream attribution scrapers); got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth mirror of the just-added
    // `_debug_info_does_not_contain_a_carriage_return_byte`
    // companion on the translator-credits side. The
    // libadwaita translator-credits convention permits
    // embedded `\n` line breaks between translator entries
    // (the `_is_single_line_when_non_empty` companion only
    // asserts the empty-string case, so it does not gate
    // embedded newlines once a translation lands), so the
    // helper is one of only three about-dialog helpers
    // (alongside `format_app_about_dialog_debug_info` and
    // `format_app_about_dialog_release_notes`) where
    // embedded line breaks are legitimately expected. That
    // makes `\r` (0x0D CARRIAGE RETURN) a distinct
    // regression surface: it is NOT covered by
    // `_has_no_surrounding_whitespace_when_non_empty` (`\r`
    // mid-string is non-surrounding), it is NOT covered by
    // any per-entry single-line check (the helper itself is
    // explicitly multi-line per libadwaita convention), and
    // it would route through `g_strdup` without truncation
    // (since `\r` is not the null byte the `g_strdup`
    // null-terminator triggers on).
    //
    // A regression that landed `"name1 <email1>\r\nname2 <email2>"`
    // (CRLF line endings from a Windows-edited translation
    // file, a `xgettext` export from a CRLF-converting tool,
    // or a hand-edited helper using `\r\n` literals) would
    // mis-render in multiple downstream surfaces: (1)
    // libadwaita's credits-page parser splits the
    // translator-credits string on `\n` (LF) per the
    // documented convention, leaving a stray `\r` byte
    // at the end of each parsed entry; the GLib `g_utf8_*`
    // family treats `\r` as a stray control character so the
    // entry renders with a visible "?" or empty box on some
    // fontconfig setups; (2) any localization tooling that
    // round-trips the translator-credits string back through
    // `xgettext` would either silently dedupe the `\r\n`
    // pair to `\n` (data loss) or preserve the CRLF and
    // propagate the same rendering bug across every
    // downstream consumer of the .po / .mo file; (3) screen
    // readers that announce the credits-page contents read
    // the `\r` as a literal control character, breaking the
    // accessibility-tree announcement.
    //
    // Mirror of the existing
    // `_debug_info_does_not_contain_a_carriage_return_byte`
    // sibling on the debug-info side; together they pin the
    // no-`\r` invariant across every about-dialog helper
    // that legitimately ships embedded `\n` newlines,
    // leaving only `format_app_about_dialog_release_notes`
    // as a future candidate for the same gate (once that
    // helper gains a non-empty Pango-markup body).
    //
    // Pinning the no-CR invariant directly here surfaces
    // the regression with a message naming the offending
    // byte at build time rather than as a downstream credits-
    // page rendering bug, a stray `\r` byte in the .po
    // round trip, or a screen-reader announcement break.
    // Current helper returns the empty literal `""` (no
    // `\r` byte), so this test passes today and serves as a
    // forcing function so any future override of the helper
    // — including the eventual landing of an actual
    // translator-credits string — stays free of carriage
    // returns even when embedded `\n` line breaks are
    // intentionally present.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\r'),
        "AdwAboutDialog translator_credits must not contain the `\\r` carriage-return byte (0x0D); the libadwaita translator-credits convention splits on `\\n` (LF) only, so a stray `\\r` byte would leave each parsed entry trailing a control byte that fontconfig setups render as a visible `?` or empty box, would survive `xgettext` round trips as either silent data loss or CRLF preservation, and would break screen-reader credits-page announcements; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth mirror of the just-added
    // `_translator_credits_does_not_contain_a_carriage_return_byte` /
    // `_debug_info_does_not_contain_a_carriage_return_byte`
    // companions on the release-notes-body side. The
    // libadwaita release-notes convention permits embedded
    // `\n` line breaks between Pango markup elements
    // (`<li>` entries inside the wrapping `<ul>`, paragraph
    // breaks, etc.), so the helper is one of only three
    // about-dialog helpers (alongside
    // `format_app_about_dialog_debug_info` and
    // `format_app_about_dialog_translator_credits`) where
    // embedded line breaks are legitimately expected. That
    // makes `\r` (0x0D CARRIAGE RETURN) a distinct
    // regression surface: it is NOT covered by
    // `_has_no_surrounding_whitespace_when_non_empty` (`\r`
    // mid-string is non-surrounding), it is NOT covered by
    // `_starts_and_ends_with_a_markup_element_when_non_empty`
    // (the opening `<` and closing `>` markup boundaries are
    // independent of mid-body `\r` bytes), and it would
    // route through `g_strdup` without truncation (since
    // `\r` is not the null byte the `g_strdup` null-
    // terminator triggers on).
    //
    // A regression that landed `"<ul><li>foo</li>\r\n<li>bar</li></ul>"`
    // (CRLF line endings from a Windows-edited CHANGELOG.md,
    // a `pandoc` Markdown-to-HTML transform that preserved
    // CRLF source line endings, or a hand-edited helper
    // using `\r\n` literals between bullets) would mis-
    // render in multiple downstream surfaces: (1) Pango's
    // markup parser permits ASCII whitespace between
    // elements but renders `\r` as a literal control byte
    // unless explicitly suppressed; in the about-dialog
    // "What's New" body this would surface as visible
    // whitespace glyphs or empty boxes between bullets on
    // fontconfig setups that lack a glyph for U+000D; (2)
    // any in-app changelog display that reuses the release-
    // notes string outside the dialog (release-tracker bots,
    // copy-to-clipboard handlers) would propagate the stray
    // `\r` into the consumer's stream and trigger the same
    // rendering bug across every downstream surface; (3)
    // screen readers that announce the release-notes content
    // read the `\r` as a literal control character, breaking
    // the accessibility-tree announcement at every bullet
    // boundary.
    //
    // Mirror of the existing
    // `_debug_info_does_not_contain_a_carriage_return_byte`
    // and just-added
    // `_translator_credits_does_not_contain_a_carriage_return_byte`
    // siblings on the debug-info and translator-credits
    // sides; together they pin the no-`\r` invariant across
    // every about-dialog helper that legitimately ships
    // embedded `\n` newlines, closing the CRLF regression
    // surface for the entire multi-line helper cluster.
    //
    // Pinning the no-CR invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream "What's New"
    // body rendering bug, a stray `\r` byte in an external
    // changelog reuse, or a screen-reader announcement
    // break. Current helper returns the empty literal `""`
    // (no `\r` byte), so this test passes today and serves
    // as a forcing function so any future override of the
    // helper — including the eventual landing of an actual
    // v0.2 release-notes Pango markup body sourced from
    // CHANGELOG.md — stays free of carriage returns even
    // when embedded `\n` line breaks are intentionally
    // present.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\r'),
        "AdwAboutDialog release_notes must not contain the `\\r` carriage-return byte (0x0D); the Pango markup parser permits ASCII whitespace between elements but renders `\\r` as a control byte, so a stray `\\r` would surface as visible whitespace glyphs or empty boxes between bullets on fontconfig setups lacking a U+000D glyph, propagate the same rendering bug into any external changelog reuse, and break screen-reader bullet-boundary announcements; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_carriage_return_byte() {
    // Defense-in-depth mirror of the just-added
    // `_translator_credits_does_not_contain_a_carriage_return_byte` /
    // `_release_notes_does_not_contain_a_carriage_return_byte` /
    // `_debug_info_does_not_contain_a_carriage_return_byte`
    // companions on the credits-page contributor-list side,
    // and a per-entry-loop sibling of the
    // `_developers_entries_do_not_contain_a_null_byte`
    // companion on the same helper.
    //
    // The `_is_non_empty_array_of_non_empty_single_line_names`
    // companion already pins each entry as non-empty and
    // single-line — but its single-line check is implemented
    // as `!name.contains('\n')`, which says nothing about the
    // sibling `\r` carriage-return byte (0x0D). The
    // surrounding-whitespace guards (`!name.starts_with(char::is_whitespace)`
    // / `!name.ends_with(char::is_whitespace)`) reject a `\r`
    // only when it sits at the very first or last byte of the
    // entry — a mid-string `\r` (e.g. the second byte of a
    // hand-edited literal accidentally pasted from a Windows
    // CRLF source) is non-surrounding and slips past both
    // ends-with-whitespace guards. The
    // `_entries_do_not_contain_a_null_byte` sibling names the
    // `\0` byte specifically — `\r` is not `\0`. The
    // `_entries_are_distinct` /
    // `_does_not_contain_developer_name` /
    // `_does_not_contain_app_id` /
    // `_does_not_contain_program_name` /
    // `_lists_benjamin_porter` companions guard against
    // content-shape regressions but say nothing about the
    // `\r` byte. None of the existing companions name the
    // `\r` byte directly.
    //
    // A regression that landed `["Benjamin\r Porter"]` (a
    // CRLF-source copy-paste, a `concat!(_, "\r", _)` form,
    // a hand-edited helper that swapped the literal for a
    // string lifted from a Windows-edited CONTRIBUTORS file,
    // or a tooling export pipeline that preserved CRLF line
    // endings inside a single-name entry) would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_developers` setter hands the array
    // to GTK as a `&[&str]` which Pango renders one entry per
    // credits-page row — a stray `\r` byte in the middle of a
    // contributor name would render as a literal control
    // glyph or as a visible whitespace box on fontconfig
    // setups lacking a U+000D glyph, breaking the credits-
    // page contributor name layout; (2) any tooling that
    // scrapes the credits-page contributor list (release-note
    // generators, contributor-attribution crawlers, GNOME
    // `gnome-software` credit aggregators) would propagate
    // the stray `\r` byte into the consumer's stream and
    // trigger the same rendering bug across every downstream
    // surface; (3) screen readers that announce the credits-
    // page contributor names read the `\r` as a literal
    // control character, breaking the contributor-name
    // accessibility-tree announcement at the offending byte.
    //
    // Pinning the no-CR invariant across every contributor
    // entry in a single per-entry loop surfaces the
    // regression with a message naming both the offending
    // byte and the affected entry index at build time rather
    // than as a downstream credits-page rendering artifact,
    // attribution-scraper miss, or screen-reader
    // announcement break. Current helper returns the literal
    // `["Benjamin Porter"]` (no `\r` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — or any future
    // contributor addition — stays free of carriage returns.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\r'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\r` carriage-return byte (0x0D); a mid-string `\\r` slips past the `_is_non_empty_array_of_non_empty_single_line_names` `\\n`-only single-line check and past the starts/ends-with-whitespace guards (which only reject `\\r` at the boundaries), and would render as a literal control glyph in the credits-page \"Developers\" row, propagate into downstream attribution scrapers, and break screen-reader contributor-name announcements; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_carriage_return_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three currently-empty `AdwAboutDialog` credits-section
    // array helpers
    // (`format_app_about_dialog_designers`,
    // `format_app_about_dialog_artists`,
    // `format_app_about_dialog_documenters`) and pinning each
    // entry as free of the `\r` carriage-return byte. Mirror
    // of the just-added
    // `_developers_entries_do_not_contain_a_carriage_return_byte`
    // sibling on the populated-developers side and of the
    // `_empty_credits_section_entries_do_not_contain_a_null_byte`
    // sibling on the null-byte side, structured as a single
    // cross-helper loop similar to the existing
    // `_empty_credits_section_entries_do_not_contain_a_null_byte`
    // companion.
    //
    // The three helpers currently return the empty array
    // `[]` because Paladin does not yet have a separately-
    // credited designer / artist / documenter for the v0.2
    // release. The empty-array return trivially contains no
    // entries (let alone CR-bearing entries), so this test
    // passes today as the loop body is never entered.
    // However, once any of the three credits sections gains
    // a contributor, the helper return type will switch from
    // `[&'static str; 0]` to `[&'static str; N]` with
    // non-empty entries — at that point a `\r` injection from
    // a CRLF-source copy-paste (a hand-edited CONTRIBUTORS
    // file lifted from a Windows-edited source) or from a
    // tooling export pipeline (a `pandoc` Markdown-to-strv
    // transform that preserved CRLF source line endings)
    // would slip past every other companion the way the
    // `_developers_entries_do_not_contain_a_carriage_return_byte`
    // sibling already documents for the developers helper.
    //
    // Carriage returns in the credits-section entries would
    // mis-render in multiple downstream surfaces, identically
    // to the `set_developers` analysis in the
    // `_developers_entries_do_not_contain_a_carriage_return_byte`
    // companion: (1) the GLib-backed `set_designers` /
    // `set_artists` / `set_documenters` setters route through
    // `g_strdupv` / `g_strdup` and Pango renders each entry
    // as a credits-page row — a stray `\r` byte in the middle
    // of a contributor name would render as a literal control
    // glyph or a visible whitespace box on fontconfig setups
    // lacking a U+000D glyph; (2) any tooling that scrapes
    // the credits-page contributor list (GNOME `gnome-software`
    // credit aggregators) would propagate the stray `\r` byte
    // into the consumer's stream and trigger the same
    // rendering bug across every downstream surface; (3)
    // screen readers that announce the credits-page
    // contributor names read the `\r` as a literal control
    // character, breaking the contributor-name accessibility-
    // tree announcement at the offending byte.
    //
    // Pinning the no-CR invariant across all three currently-
    // empty credits-section helpers in a single cross-helper
    // loop surfaces the regression with a message naming the
    // affected helper, the offending byte, and the entry
    // index at build time rather than as a downstream
    // truncation of the credits-page sections. Current
    // helpers return the empty array `[]` (zero entries, no
    // `\r` byte to find), so this test passes today and
    // serves as a forcing function so any future override of
    // the helpers — including the eventual landing of
    // separately-credited designer / artist / documenter
    // strings — stays free of carriage returns.
    use paladin_gtk::app::model::{
        format_app_about_dialog_artists, format_app_about_dialog_designers,
        format_app_about_dialog_documenters,
    };

    let designers = format_app_about_dialog_designers();
    let artists = format_app_about_dialog_artists();
    let documenters = format_app_about_dialog_documenters();

    let sections: [(&str, &[&str]); 3] = [
        ("designers", &designers),
        ("artists", &artists),
        ("documenters", &documenters),
    ];

    for (label, entries) in sections {
        for (idx, entry) in entries.iter().enumerate() {
            assert!(
                !entry.contains('\r'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\r` carriage-return byte (0x0D); a mid-string `\\r` would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, propagate into downstream attribution scrapers, and break screen-reader contributor-name announcements; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_comments_matches_cargo_pkg_description`
    // (cross-source pin against `CARGO_PKG_DESCRIPTION`),
    // `format_app_about_dialog_comments_is_non_empty_single_line_distinct_from_program_name`
    // (positive shape pin: non-empty, no `\n`, no surrounding
    // whitespace, distinct from program-name),
    // `format_app_about_dialog_comments_does_not_end_with_a_period_per_libadwaita_convention`
    // (negative shape pin against a trailing `.`),
    // `format_app_about_dialog_comments_is_ascii_only` (byte-
    // composition pin), and
    // `format_app_about_dialog_comments_does_not_contain_a_null_byte`
    // (`\0` byte pin). Those companions catch the wrong-value,
    // wrong-shape, trailing-period, non-ASCII, and null-byte
    // regressions but leave the embedded-`\r` edge case
    // ungated.
    //
    // The `_is_non_empty_single_line_distinct_from_program_name`
    // companion implements its single-line check as
    // `!comments.contains('\n')` — it says nothing about the
    // sibling `\r` carriage-return byte (0x0D). The
    // surrounding-whitespace guards (`!comments.starts_with(char::is_whitespace)`
    // / `!comments.ends_with(char::is_whitespace)`) reject a
    // `\r` only at the very first or last byte — a mid-string
    // `\r` is non-surrounding and slips past both ends-with-
    // whitespace guards. The `_is_ascii_only` companion pins
    // each byte as ASCII (`0x00`-`0x7F`) — `\r` is ASCII, so a
    // regression that landed `"OTP authenticator\r for the
    // command line"` (a CRLF-source `Cargo.toml` description
    // copy-paste, a `concat!(_, "\r", _)` form, or a hand-
    // edited helper override that lifted the description from
    // a Windows-edited source) would slip past every existing
    // companion.
    //
    // A `\r` byte in the comments slot would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_comments` setter hands the string
    // to Pango for inline rendering beneath the program name
    // in the dialog header — a stray `\r` byte would render as
    // a literal control glyph or as a visible whitespace box
    // on fontconfig setups lacking a U+000D glyph, breaking
    // the inline-header layout; (2) the comments value is
    // sourced from `CARGO_PKG_DESCRIPTION` which propagates
    // into Cargo's `description` field in `Cargo.toml` —
    // tooling that scrapes this metadata (`cargo metadata`,
    // crates.io registry indexing, GNOME `gnome-software`
    // descriptions) would propagate the stray `\r` byte into
    // every consumer; (3) screen readers that announce the
    // dialog description read the `\r` as a literal control
    // character, breaking the description accessibility-tree
    // announcement.
    //
    // Pinning the no-CR invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-header
    // rendering bug, a tooling-scrape miss, or a screen-reader
    // announcement break. Current helper returns the value
    // sourced from `CARGO_PKG_DESCRIPTION` which has no `\r`
    // byte, so this test passes today and serves as a forcing
    // function so any future override of the helper — or any
    // future edit of the workspace `Cargo.toml` `description`
    // field — stays free of carriage returns.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\r'),
        "AdwAboutDialog comments must not contain the `\\r` carriage-return byte (0x0D); a mid-string `\\r` slips past the `_is_non_empty_single_line_distinct_from_program_name` `\\n`-only single-line check, past the starts/ends-with-whitespace guards (which only reject `\\r` at the boundaries), and past `_is_ascii_only` (because `\\r` is ASCII), and would render as a literal control glyph in the dialog-header description, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers, and break screen-reader description announcements; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth direct sibling of the existing
    // `format_app_about_dialog_release_notes_version_matches_about_dialog_version`
    // and
    // `format_app_about_dialog_release_notes_version_matches_cargo_pkg_version`
    // cross-source pins, and a per-helper sibling of the
    // `_release_notes_version_does_not_contain_a_null_byte`
    // null-byte companion.
    //
    // The two `_matches_*` companions transitively guarantee
    // `release_notes_version` shares its bytes with the
    // `version` helper (which in turn equals
    // `CARGO_PKG_VERSION`). The `version` helper is byte-
    // pinned by `_version_is_ascii_only`,
    // `_version_has_no_embedded_whitespace` (a
    // `char::is_whitespace()` check that catches `\r`),
    // `_version_starts_with_a_digit`,
    // `_version_has_at_least_three_dot_separated_segments`,
    // `_version_does_not_end_with_a_dot`,
    // `_version_segments_are_non_empty`,
    // `_version_does_not_start_with_a_dot`, and
    // `_version_does_not_contain_a_null_byte`. So a `\r` byte
    // in the active `release_notes_version` value is currently
    // protected *transitively* — through equality with
    // `version`, which is itself directly pinned against
    // embedded whitespace.
    //
    // But the transitive protection is brittle: a future
    // refactor that decoupled the two helpers (a separate
    // override constant for the "What's New" scope, a
    // workspace-vendoring split that lifted
    // `release_notes_version` out of the equality chain, or a
    // CHANGELOG.md-derived release-notes version that
    // intentionally lagged the binary version on a hotfix
    // cut) would silently drop the `\r` guard the moment the
    // `_matches_*` companions started skipping cases. The
    // `_does_not_contain_a_null_byte` sibling names `\0`
    // specifically — `\r` is not `\0`. None of the existing
    // companions name the `\r` byte directly on the
    // `release_notes_version` helper.
    //
    // A regression that landed `"0.0.1\r"` (a CRLF-source
    // copy-paste from a Windows-edited release-notes scope
    // constant, a `concat!(_, "\r", _)` form, or a hand-
    // edited helper override that lifted the version string
    // from a Windows-edited CHANGELOG.md heading) would mis-
    // render in multiple downstream surfaces, identically to
    // the analysis on the `version` helper: (1) the GLib-
    // backed `AdwAboutDialog::set_release_notes_version`
    // setter routes the value into Pango for inline rendering
    // as the "What's New in v<release_notes_version>" header
    // — a stray `\r` byte would render as a literal control
    // glyph in the section header; (2) the value scopes the
    // "What's New" body region inside the dialog — a
    // mismatched / mis-rendered scope key could prevent the
    // body from rendering at all on libadwaita versions that
    // expect a clean LF-only header key; (3) screen readers
    // that announce the "What's New" section header read the
    // `\r` as a literal control character, breaking the
    // section-header accessibility-tree announcement.
    //
    // Pinning the no-CR invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // decoupling that silently dropped the transitive
    // `version` guard. Current helper returns the value
    // sourced from `CARGO_PKG_VERSION` (no `\r` byte), so
    // this test passes today and serves as a forcing function
    // so any future decoupling override of the helper —
    // including the eventual landing of a separately-scoped
    // release-notes version derived from CHANGELOG.md
    // headings — stays free of carriage returns.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\r'),
        "AdwAboutDialog release_notes_version must not contain the `\\r` carriage-return byte (0x0D); the current value's `\\r`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version`, so a future decoupling override would silently drop the `\\r` guard — a stray `\\r` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that expect a clean LF-only header key, and break screen-reader section-header announcements; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth sibling of the existing
    // `format_app_about_dialog_developer_name_is_a_single_line_without_embedded_newlines`
    // (which checks `\n` AND `\r` but not `\t`),
    // `_developer_name_has_no_surrounding_whitespace` (which
    // only rejects whitespace at the boundaries),
    // `_developer_name_is_ascii_only` (which pins each byte as
    // ASCII — `\t` is ASCII (0x09) so it slips past),
    // `_developer_name_starts_with_the_definite_article`
    // (which checks `starts_with("The ")` — a literal `\t`
    // inserted *after* "The " satisfies this), and
    // `_developer_name_does_not_contain_a_null_byte` (which
    // names `\0` specifically — `\t` is not `\0`).
    //
    // None of the existing companions name the `\t` byte
    // directly. The current `_returns_the_paladin_contributors`
    // exact-value pin catches everything, but its protection
    // collapses the moment a contributor addition or a
    // workspace-vendoring split decouples the helper from the
    // pinned literal — at that point a `\t`-bearing override
    // would slip past every byte-level companion.
    //
    // A regression that landed `"The\tPaladin\tcontributors"`
    // or `"The Paladin\tcontributors"` (a tab-separated
    // attribution lifted from a TSV-style CONTRIBUTORS export,
    // a `concat!(_, "\t", _)` form, a hand-edited helper that
    // pasted from a markdown-table cell, or a tooling export
    // pipeline that preserved tab-separated column values)
    // would mis-render in multiple downstream surfaces: (1)
    // the GLib-backed `AdwAboutDialog::set_developer_name`
    // setter hands the string to Pango for inline rendering
    // beneath the program name in the dialog header — Pango's
    // default rendering of `\t` is implementation-defined and
    // typically renders as a wide horizontal gap or an empty
    // box, breaking the tidy single-line attribution layout;
    // (2) screen readers that announce the dialog attribution
    // read the `\t` as a literal control character, breaking
    // the attribution accessibility-tree announcement at the
    // tab boundary; (3) any downstream tooling that scrapes
    // the developer-name attribution (release-note generators,
    // contributor-attribution crawlers) would propagate the
    // stray `\t` byte into the consumer's stream and trigger
    // the same rendering bug across every downstream surface.
    //
    // Pinning the no-`\t` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-header
    // rendering bug or a screen-reader announcement break.
    // Current helper returns the literal `"The Paladin
    // contributors"` (no `\t` byte), so this test passes today
    // and serves as a forcing function so any future override
    // of the helper — including the eventual landing of a
    // multi-contributor attribution string — stays free of
    // horizontal-tab bytes.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\t'),
        "AdwAboutDialog developer-name must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past the starts/ends-with-whitespace guards (which only reject `\\t` at the boundaries), past `_is_ascii_only` (because `\\t` is ASCII), and past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the prefix and suffix); it would render as a wide horizontal gap in the dialog-header attribution row, break screen-reader announcements at the tab boundary, and propagate into downstream attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth sibling of the existing
    // `format_app_about_dialog_copyright_is_a_single_line_without_embedded_newlines`
    // (which checks `\n` AND `\r` but not `\t`),
    // `_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    // (which constrains the leading glyph and the developer-
    // name substring), `_copyright_separates_glyph_and_attribution_with_a_single_space`
    // (which constrains the space immediately after the `©`
    // glyph), `_copyright_ends_with_developer_name` (which
    // constrains the trailing substring),
    // `_copyright_does_not_end_with_a_period` (which constrains
    // the trailing byte), `_copyright_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    // (which scans for four-digit runs but `\t` is not a
    // digit), and `_copyright_does_not_contain_a_null_byte`
    // (which names `\0` specifically — `\t` is not `\0`).
    //
    // The copyright helper deliberately omits `_is_ascii_only`
    // because the canonical `©` U+00A9 (COPYRIGHT SIGN) is
    // non-ASCII — a strict-ASCII pin would have to be
    // expressed differently (e.g. "every byte is either ASCII
    // or the `©` glyph"), and no such variant exists today.
    // So `\t` is doubly slippable: even an `_is_ascii_only`
    // sibling would have allowed it as an ASCII byte.
    //
    // None of the existing companions name the `\t` byte
    // directly. The current `_returns_paladin_copyright_line`
    // exact-value pin catches everything, but its protection
    // collapses the moment a future override (e.g. a year-
    // pinned override at the v0.2 release cut, a workspace-
    // vendoring split that lifted the copyright literal, or a
    // hand-edited helper that swapped the literal for a
    // tab-separated multi-column credit line) replaces the
    // exact value.
    //
    // A regression that landed `"© The Paladin\tcontributors"`
    // (a tab-separated attribution lifted from a TSV-style
    // CONTRIBUTORS export, a `concat!(_, "\t", _)` form, or a
    // hand-edited helper that pasted from a markdown-table
    // cell) would mis-render in multiple downstream surfaces:
    // (1) the GLib-backed `AdwAboutDialog::set_copyright`
    // setter hands the string to Pango for inline rendering
    // in the dialog footer — Pango's default rendering of
    // `\t` is implementation-defined and typically renders as
    // a wide horizontal gap or an empty box, visually
    // misaligning the footer cluster against the website /
    // issue-link rows beneath it; (2) screen readers that
    // announce the dialog copyright footer read the `\t` as
    // a literal control character, breaking the copyright
    // accessibility-tree announcement at the tab boundary;
    // (3) any downstream tooling that scrapes the copyright
    // line (license-attribution crawlers, GNOME
    // `gnome-software` metadata aggregators) would propagate
    // the stray `\t` byte into the consumer's stream and
    // trigger the same rendering bug.
    //
    // Pinning the no-`\t` invariant directly here surfaces
    // the regression with a message naming the offending byte
    // at build time rather than as a downstream footer-
    // rendering bug or a screen-reader announcement break.
    // Current helper returns the literal
    // `"© The Paladin contributors"` (no `\t` byte), so this
    // test passes today and serves as a forcing function so
    // any future override of the helper stays free of
    // horizontal-tab bytes.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\t'),
        "AdwAboutDialog copyright must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past the no-year-token four-digit-run scan (`\\t` is not a digit), and past `_does_not_contain_a_null_byte` (because `\\t` is not `\\0`); it would render as a wide horizontal gap in the dialog-footer copyright row, visually misalign the footer cluster against the website / issue-link rows, break screen-reader announcements at the tab boundary, and propagate into downstream license-attribution scrapers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth sibling of the existing
    // `format_app_about_dialog_comments_matches_cargo_pkg_description`
    // (cross-source pin),
    // `_comments_is_non_empty_single_line_distinct_from_program_name`
    // (positive shape pin: non-empty, no `\n`, no surrounding
    // whitespace, distinct from program-name; says nothing
    // about `\t`),
    // `_comments_does_not_end_with_a_period_per_libadwaita_convention`
    // (negative shape pin against trailing `.`),
    // `_comments_is_ascii_only` (byte-composition pin — `\t`
    // is ASCII (0x09) so it slips past),
    // `_comments_does_not_contain_a_null_byte` (names `\0`
    // specifically — `\t` is not `\0`), and
    // `_comments_does_not_contain_a_carriage_return_byte`
    // (names `\r` specifically — `\t` is not `\r`).
    //
    // None of the existing companions name the `\t` byte
    // directly. The current `_matches_cargo_pkg_description`
    // cross-source pin transitively guards the value via
    // `CARGO_PKG_DESCRIPTION`, but its protection is brittle:
    // a future refactor that decoupled the helper from the
    // workspace `Cargo.toml` `description` field (a hand-
    // edited override for the libadwaita HIG-mandated
    // single-line summary, a workspace-vendoring split that
    // lifted comments out of the cross-source chain) would
    // silently drop the transitive guard the moment the
    // override path activates.
    //
    // A regression that landed `"OTP authenticator\tfor the
    // command line"` (a tab-separated description lifted
    // from a TSV-style metadata export, a `concat!(_, "\t",
    // _)` form, a hand-edited helper that pasted from a
    // markdown-table cell, or a tooling export pipeline that
    // preserved tab-separated column values) would mis-render
    // in multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_comments` setter hands the string
    // to Pango for inline rendering as the dialog header
    // description beneath the program name — Pango's default
    // rendering of `\t` is implementation-defined and
    // typically renders as a wide horizontal gap or an empty
    // box, breaking the tidy single-line description layout;
    // (2) the comments value is sourced from
    // `CARGO_PKG_DESCRIPTION` which propagates into Cargo's
    // `description` field in `Cargo.toml` — tooling that
    // scrapes this metadata (`cargo metadata`, crates.io
    // registry indexing, GNOME `gnome-software` descriptions)
    // would propagate the stray `\t` byte into every
    // consumer; (3) screen readers that announce the dialog
    // description read the `\t` as a literal control
    // character, breaking the description accessibility-tree
    // announcement at the tab boundary.
    //
    // Pinning the no-`\t` invariant directly here surfaces
    // the regression with a message naming the offending byte
    // at build time rather than as a downstream dialog-header
    // rendering bug, a tooling-scrape miss, or a screen-
    // reader announcement break. Current helper returns the
    // value sourced from `CARGO_PKG_DESCRIPTION` (no `\t`
    // byte), so this test passes today and serves as a
    // forcing function so any future override of the helper —
    // or any future edit of the workspace `Cargo.toml`
    // `description` field — stays free of horizontal-tab
    // bytes.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\t'),
        "AdwAboutDialog comments must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace), past `_is_ascii_only` (because `\\t` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_carriage_return_byte` (which name `\\0` and `\\r` specifically); it would render as a wide horizontal gap in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers, and break screen-reader description announcements at the tab boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth sibling of the just-added
    // `_developer_name_does_not_contain_a_horizontal_tab_byte`
    // companion on the singular dialog-header attribution
    // side, and a per-entry-loop sibling of the
    // `_developers_entries_do_not_contain_a_null_byte` /
    // `_developers_entries_do_not_contain_a_carriage_return_byte`
    // companions on the same array helper.
    //
    // The `_is_non_empty_array_of_non_empty_single_line_names`
    // companion already pins each entry as non-empty and
    // single-line — but its single-line check is implemented
    // as `!name.contains('\n')`, which says nothing about the
    // sibling `\t` horizontal-tab byte (0x09). The
    // surrounding-whitespace guards (`!name.starts_with(char::is_whitespace)`
    // / `!name.ends_with(char::is_whitespace)`) reject a `\t`
    // only at the very first or last byte — a mid-string `\t`
    // is non-surrounding and slips past both boundary guards.
    // The `_entries_do_not_contain_a_null_byte` /
    // `_entries_do_not_contain_a_carriage_return_byte`
    // siblings name `\0` and `\r` specifically — `\t` is
    // neither. The `_entries_are_distinct` /
    // `_does_not_contain_developer_name` /
    // `_does_not_contain_app_id` /
    // `_does_not_contain_program_name` /
    // `_lists_benjamin_porter` companions guard against
    // content-shape regressions but say nothing about the
    // `\t` byte. None of the existing companions name the
    // `\t` byte directly.
    //
    // A regression that landed `["Benjamin\tPorter"]` (a
    // tab-separated CONTRIBUTORS export, a `concat!(_, "\t",
    // _)` form, a hand-edited helper that pasted from a
    // markdown-table cell, or a tooling export pipeline that
    // preserved tab-separated column values inside a single-
    // name entry) would mis-render in multiple downstream
    // surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_developers` setter hands the array
    // to GTK and Pango renders each entry as a credits-page
    // row — a stray `\t` byte in the middle of a contributor
    // name would render as a wide horizontal gap or an empty
    // box on fontconfig setups, visually breaking the
    // credits-page contributor-name layout; (2) any tooling
    // that scrapes the credits-page contributor list (release-
    // note generators, contributor-attribution crawlers, GNOME
    // `gnome-software` credit aggregators) would propagate
    // the stray `\t` byte into the consumer's stream and
    // trigger the same rendering bug across every downstream
    // surface; (3) screen readers that announce the credits-
    // page contributor names read the `\t` as a literal
    // control character, breaking the contributor-name
    // accessibility-tree announcement at the tab boundary.
    //
    // Pinning the no-`\t` invariant across every contributor
    // entry in a single per-entry loop surfaces the
    // regression with a message naming both the offending
    // byte and the affected entry index at build time rather
    // than as a downstream credits-page rendering artifact,
    // attribution-scraper miss, or screen-reader
    // announcement break. Current helper returns the literal
    // `["Benjamin Porter"]` (no `\t` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — or any future
    // contributor addition — stays free of horizontal-tab
    // bytes.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\t'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n`), past the starts/ends-with-whitespace guards (which only reject `\\t` at the boundaries), past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_carriage_return_byte` (which name `\\0` and `\\r` specifically), and would render as a wide horizontal gap in the credits-page \"Developers\" row, propagate into downstream attribution scrapers, and break screen-reader contributor-name announcements; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three currently-empty `AdwAboutDialog` credits-section
    // array helpers
    // (`format_app_about_dialog_designers`,
    // `format_app_about_dialog_artists`,
    // `format_app_about_dialog_documenters`) and pinning each
    // entry as free of the `\t` horizontal-tab byte. Mirror
    // of the just-added
    // `_developers_entries_do_not_contain_a_horizontal_tab_byte`
    // sibling on the populated-developers side and of the
    // `_empty_credits_section_entries_do_not_contain_a_null_byte`
    // /
    // `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte`
    // siblings on the null-byte / CR-byte sides, structured
    // as a single cross-helper loop similar to those existing
    // companions.
    //
    // The three helpers currently return the empty array
    // `[]` because Paladin does not yet have a separately-
    // credited designer / artist / documenter for the v0.2
    // release. The empty-array return trivially contains no
    // entries (let alone `\t`-bearing entries), so this test
    // passes today as the loop body is never entered.
    // However, once any of the three credits sections gains
    // a contributor, the helper return type will switch from
    // `[&'static str; 0]` to `[&'static str; N]` with
    // non-empty entries — at that point a `\t` injection
    // from a tab-separated CONTRIBUTORS export, a `concat!(_,
    // "\t", _)` form, a hand-edited helper that pasted from
    // a markdown-table cell, or a tooling export pipeline
    // that preserved tab-separated column values inside a
    // single-name entry would slip past every other companion
    // the way the
    // `_developers_entries_do_not_contain_a_horizontal_tab_byte`
    // sibling already documents for the developers helper.
    //
    // Horizontal-tab bytes in the credits-section entries
    // would mis-render in multiple downstream surfaces,
    // identically to the `set_developers` analysis in the
    // `_developers_entries_do_not_contain_a_horizontal_tab_byte`
    // companion: (1) the GLib-backed `set_designers` /
    // `set_artists` / `set_documenters` setters route through
    // GTK and Pango renders each entry as a credits-page row
    // — a stray `\t` byte in the middle of a contributor name
    // would render as a wide horizontal gap or an empty box,
    // visually breaking the credits-page contributor-name
    // layout; (2) any tooling that scrapes the credits-page
    // contributor list (GNOME `gnome-software` credit
    // aggregators) would propagate the stray `\t` byte into
    // the consumer's stream and trigger the same rendering
    // bug across every downstream surface; (3) screen readers
    // that announce the credits-page contributor names read
    // the `\t` as a literal control character, breaking the
    // contributor-name accessibility-tree announcement at the
    // tab boundary.
    //
    // Pinning the no-`\t` invariant across all three
    // currently-empty credits-section helpers in a single
    // cross-helper loop surfaces the regression with a
    // message naming the affected helper, the offending byte,
    // and the entry index at build time rather than as a
    // downstream rendering artifact of the credits-page
    // sections. Current helpers return the empty array `[]`
    // (zero entries, no `\t` byte to find), so this test
    // passes today and serves as a forcing function so any
    // future override of the helpers — including the
    // eventual landing of separately-credited designer /
    // artist / documenter strings — stays free of horizontal-
    // tab bytes.
    use paladin_gtk::app::model::{
        format_app_about_dialog_artists, format_app_about_dialog_designers,
        format_app_about_dialog_documenters,
    };

    let designers = format_app_about_dialog_designers();
    let artists = format_app_about_dialog_artists();
    let documenters = format_app_about_dialog_documenters();

    let sections: [(&str, &[&str]); 3] = [
        ("designers", &designers),
        ("artists", &artists),
        ("documenters", &documenters),
    ];

    for (label, entries) in sections {
        for (idx, entry) in entries.iter().enumerate() {
            assert!(
                !entry.contains('\t'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` would render as a wide horizontal gap in the credits-page \"{label}\" row via `set_{label}`, propagate into downstream attribution scrapers, and break screen-reader contributor-name announcements at the tab boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_query_string() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of a `?` query-string-introducer byte so a
    // regression that landed a query-string-terminated URL —
    // e.g. `"https://paladin.tamx.org?utm_source=about"` (UTM-
    // tagged homepage from a marketing-link refactor),
    // `"https://github.com/FreedomBen/paladin/issues?q=is%3Aopen"`
    // (filtered issue-tracker view from a paste with the
    // browser address-bar query parameters retained), or
    // `"https://github.com/FreedomBen/paladin/discussions?discussions_q=is%3Aopen"`
    // (filtered discussions view) — would fail at the pinned
    // layer rather than slip past the
    // `_is_non_empty_https_url[_distinct_*]` per-URL companion
    // (which only checks non-empty + `https://` prefix + no
    // space byte), the `_contain_no_embedded_whitespace` /
    // `_are_ascii_only` cross-URL companions (no whitespace
    // bytes anywhere, only ASCII bytes — `?` is both non-
    // whitespace and ASCII, so it slips past both), the
    // `_appends_issues_to_cargo_pkg_repository` /
    // `_appends_discussions_to_cargo_pkg_repository`
    // companions (which use `concat!(env!("CARGO_PKG_REPOSITORY"),
    // "/issues")` — if `CARGO_PKG_REPOSITORY` itself drifted to
    // include a query suffix, the concatenation would produce
    // `"…paladin?param=value/issues"` — though that exact form
    // would actually break the path-after-host shape, a more
    // plausible drift like `CARGO_PKG_REPOSITORY="https://github.com/FreedomBen/paladin"`
    // becoming `"https://github.com/FreedomBen/paladin?tab=overview"`
    // would yield a `?`-bearing concatenation), the
    // `_issue_url_and_support_url_share_cargo_pkg_repository_prefix`
    // companion (still holds since both URLs share the same
    // `?`-bearing prefix), or the
    // `_url_helpers_do_not_end_with_a_trailing_slash` companion
    // (a `?`-terminated URL doesn't end with a slash).
    //
    // The libadwaita `AdwAboutDialog::website` / `issue-url` /
    // `support-url` slots consume the URL verbatim and render
    // it as a clickable footer link; a `?`-introducer on a URL
    // like `"https://github.com/FreedomBen/paladin/issues?q=is%3Aopen"`
    // would route through HTTP and GitHub's web stack to a
    // *pre-filtered* destination view rather than to the bare
    // issue-tracker landing page, surfacing as a confusing
    // first-impression UX where the issue list arrives pre-
    // narrowed to the maintainer's most recently saved filter.
    // Worse, a UTM-tagged homepage URL would leak the
    // referring application identity to analytics across every
    // about-dialog open — an anti-feature for a privacy-
    // focused authenticator, where the user's intent in
    // opening the dialog is to learn about the application
    // rather than to be tracked.
    //
    // Pinning the no-query-string invariant directly here
    // surfaces the regression with a message naming the
    // offending URL helper at build time rather than as a
    // downstream pre-filtered click-through landing or an
    // analytics-leak surface. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`, and
    // `_url_helpers_do_not_contain_a_null_byte` cross-URL
    // siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`,
    // no `\0`, no `?` query introducer) across all three
    // footer link surfaces against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('?'),
            "AdwAboutDialog {label} must not contain the `?` query-string-introducer byte so the URL byte sequence resolves to the bare canonical destination (the about-dialog footer is intended to surface the home / issue / support landing page, not a pre-filtered view) and so a UTM-tagged URL cannot leak the referring application identity to analytics on every dialog open; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_fragment_anchor() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of a `#` fragment-anchor-introducer byte
    // so a regression that landed an anchor-tagged URL — e.g.
    // `"https://paladin.tamx.org#features"` (an in-page anchor
    // dragged from a section-link refactor), or
    // `"https://github.com/FreedomBen/paladin/issues#issuecomment-12345"`
    // (a deep-link to a specific issue comment from a paste
    // with the browser address-bar anchor retained), or
    // `"https://github.com/FreedomBen/paladin/discussions#discussion-67890"`
    // (similar deep-link to a specific discussion thread) —
    // would fail at the pinned layer rather than slip past
    // the `_is_non_empty_https_url[_distinct_*]` per-URL
    // companion (which only checks non-empty + `https://`
    // prefix + no space byte), the
    // `_contain_no_embedded_whitespace` /
    // `_are_ascii_only` cross-URL companions (no whitespace
    // bytes, only ASCII bytes — `#` is both non-whitespace
    // and ASCII, so it slips past both), the
    // `_appends_issues_to_cargo_pkg_repository` /
    // `_appends_discussions_to_cargo_pkg_repository`
    // companions (which use `concat!(env!("CARGO_PKG_REPOSITORY"),
    // "/issues")` — if `CARGO_PKG_REPOSITORY` itself drifted to
    // include a fragment suffix, the concatenation would yield
    // a `#`-bearing prefix), the
    // `_issue_url_and_support_url_share_cargo_pkg_repository_prefix`
    // companion (still holds since both URLs share the same
    // `#`-bearing prefix), or the
    // `_url_helpers_do_not_end_with_a_trailing_slash` /
    // `_url_helpers_do_not_contain_a_query_string` companions
    // (a `#`-terminated URL doesn't end with a slash and a
    // fragment-anchor URL doesn't necessarily contain a `?`).
    //
    // The libadwaita `AdwAboutDialog::website` / `issue-url` /
    // `support-url` slots consume the URL verbatim and render
    // it as a clickable footer link; a `#`-anchor on a URL
    // like `"https://github.com/FreedomBen/paladin/issues#issuecomment-12345"`
    // would route through HTTP and GitHub's web stack to a
    // *scrolled-into-a-specific-thread* destination view
    // rather than to the bare issue-tracker landing page,
    // surfacing as a confusing first-impression UX where the
    // page scrolls past the user's expected landing position
    // straight to an arbitrary historical comment. A `#`-
    // anchor on the homepage URL
    // (`"https://paladin.tamx.org#features"`) would similarly
    // route the user to an in-page section rather than the
    // page's natural landing position.
    //
    // Pinning the no-fragment-anchor invariant directly here
    // surfaces the regression with a message naming the
    // offending URL helper at build time rather than as a
    // downstream scrolled-to-arbitrary-position click-through
    // landing. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`, and
    // `_url_helpers_do_not_contain_a_null_byte` cross-URL
    // siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`,
    // no `\0`, no `?` query introducer, no `#` fragment
    // anchor) across all three footer link surfaces against a
    // single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('#'),
            "AdwAboutDialog {label} must not contain the `#` fragment-anchor-introducer byte so the URL byte sequence resolves to the bare canonical destination landing position (the about-dialog footer is intended to surface the home / issue / support landing page, not a deep-link into an in-page section or a specific historical thread); got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_userinfo_at_sign() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `@` userinfo-separator byte. Per
    // RFC 3986 §3.2.1 the URI generic syntax permits a
    // userinfo component between the `https://` scheme and
    // the host (`scheme://userinfo@host/path`); a regression
    // that landed a URL like
    // `"https://github.com@malicious.example/FreedomBen/paladin/issues"`
    // (a phishing-style URL where the `github.com` prefix is
    // actually the userinfo and the real destination is
    // `malicious.example`), `"https://attacker@paladin.tamx.org"`
    // (a redirector exploit where the dialog renders the bare
    // bytes including the `@`-prefix), or a hand-edited helper
    // that swapped the literal for a userinfo-bearing URL
    // would slip past the
    // `_is_non_empty_https_url[_distinct_*]` per-URL companion
    // (which only checks non-empty + `https://` prefix + no
    // space byte), the `_contain_no_embedded_whitespace` /
    // `_are_ascii_only` cross-URL companions (no whitespace
    // bytes, only ASCII bytes — `@` is both non-whitespace
    // and ASCII, so it slips past both), and every other
    // existing companion. None of the existing companions
    // name the `@` byte directly.
    //
    // The libadwaita `AdwAboutDialog::website` / `issue-url` /
    // `support-url` slots consume the URL verbatim and Pango
    // renders it as a clickable footer link with the bare URL
    // bytes as the visible label. A user reading the rendered
    // label `"https://github.com@malicious.example/FreedomBen/paladin/issues"`
    // would scan the leading `github.com` and reasonably
    // expect the click-through to land on the canonical
    // GitHub issue tracker — but the browser would instead
    // route to `malicious.example` (`github.com` is parsed as
    // userinfo, not as the host) where the user could be
    // phished, fingerprinted, served drive-by exploits, or
    // mis-routed for credential theft. This is a security
    // concern: the about dialog is a trusted-application
    // surface for surfacing project links, and a userinfo-
    // bearing URL would silently turn it into an attacker-
    // controlled redirector.
    //
    // Pinning the no-userinfo invariant directly here surfaces
    // the regression with a message naming the offending URL
    // helper at build time rather than as a downstream
    // phishing surface or a user-visible mis-routed click-
    // through. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_do_not_contain_a_fragment_anchor`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`, and
    // `_url_helpers_do_not_contain_a_null_byte` cross-URL
    // siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`,
    // no `\0`, no `?` query, no `#` anchor, no `@` userinfo)
    // across all three footer link surfaces against a single
    // source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('@'),
            "AdwAboutDialog {label} must not contain the `@` userinfo-separator byte (a security-relevant invariant: per RFC 3986 §3.2.1, `scheme://userinfo@host/path` parses everything before the `@` as userinfo and the bytes after as the real host — so a URL like `https://github.com@malicious.example/...` would render with the misleading `github.com` prefix in the dialog footer label but route click-throughs to `malicious.example`, turning the trusted about-dialog footer into an attacker-controlled redirector for phishing, fingerprinting, drive-by exploits, or credential theft); got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_backslash() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `\` backslash byte. Per RFC 3986,
    // the canonical path-segment separator inside a URL is the
    // forward slash `/`; the backslash `\` is *not* a reserved
    // URI byte. But path-confusion attacks exploit the fact
    // that *some* downstream parsers (older Windows-derived
    // URL parsers, some embedded HTTP libraries, some CDN
    // edge-rewriting middleware, Pango's label-rendering when
    // a label is interpreted as Markdown via a future
    // libadwaita refactor that swapped to a Markdown-aware
    // label engine) silently rewrite `\` to `/` during
    // canonicalisation. A regression that landed a URL like
    // `"https://github.com\FreedomBen\paladin\issues"` (a
    // hand-edited Windows-path-style literal, a `concat!(_,
    // "\\", _)` form, or a literal lifted from a Windows
    // file-explorer breadcrumb) would render in the
    // about-dialog footer with the bare `\`-separated bytes
    // visible in the label, but the underlying click-through
    // routing depends on the browser's URL-parser leniency:
    // (a) on parsers that strictly per RFC 3986 treat `\` as
    // an unreserved byte, the click would route to a non-
    // existent path with literal `\` characters, surfacing as
    // a confusing 404; (b) on parsers that auto-rewrite `\`
    // to `/` (a documented behavior of WHATWG URL §4.5
    // implementations to align with browser real-world
    // behaviour), the click would route correctly but the
    // dialog label would mis-render with a `\`-segmented path
    // visible to the user, eroding the trusted-application
    // surface contract.
    //
    // A regression would slip past every existing companion:
    // the `_is_non_empty_https_url[_distinct_*]` per-URL
    // companion (which only checks non-empty + `https://`
    // prefix + no space byte), the `_contain_no_embedded_whitespace`
    // / `_are_ascii_only` cross-URL companions (`\` is both
    // non-whitespace and ASCII (0x5C), so it slips past
    // both), and every other byte-specific companion which
    // names different bytes specifically. None of the
    // existing companions name the `\` byte directly.
    //
    // Pinning the no-backslash invariant directly here
    // surfaces the regression with a message naming the
    // offending URL helper at build time rather than as a
    // downstream user-visible mis-rendered path label, a
    // confusing 404, or an inconsistent click-through-routing
    // surface across parser implementations. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_do_not_contain_a_fragment_anchor`,
    // `_url_helpers_do_not_contain_a_userinfo_at_sign`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`, and
    // `_url_helpers_do_not_contain_a_null_byte` cross-URL
    // siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`,
    // no `\0`, no `?` query, no `#` anchor, no `@` userinfo,
    // no `\` path-confusion byte) across all three footer
    // link surfaces against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('\\'),
            "AdwAboutDialog {label} must not contain the `\\\\` backslash byte (0x5C) — the canonical URL path-segment separator is `/` per RFC 3986; some downstream parsers (WHATWG URL §4.5 implementations, older Windows-derived URL parsers, embedded HTTP libraries) auto-rewrite `\\\\` to `/` during canonicalisation, but the bare-bytes rendering in the about-dialog footer label would still show the offending `\\\\`-segmented path to the user, eroding the trusted-application surface contract; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth direct sibling of the existing
    // `format_app_about_dialog_release_notes_version_matches_about_dialog_version`
    // and
    // `format_app_about_dialog_release_notes_version_matches_cargo_pkg_version`
    // cross-source pins, and a per-helper sibling of the
    // `_release_notes_version_does_not_contain_a_null_byte`
    // and
    // `_release_notes_version_does_not_contain_a_carriage_return_byte`
    // companions.
    //
    // The two `_matches_*` companions transitively guarantee
    // `release_notes_version` shares its bytes with the
    // `version` helper (which in turn equals
    // `CARGO_PKG_VERSION`). The `version` helper is byte-
    // pinned by `_version_is_ascii_only`,
    // `_version_has_no_embedded_whitespace` (a
    // `char::is_whitespace()` check that catches `\t`),
    // `_version_starts_with_a_digit`,
    // `_version_has_at_least_three_dot_separated_segments`,
    // `_version_does_not_end_with_a_dot`,
    // `_version_segments_are_non_empty`,
    // `_version_does_not_start_with_a_dot`, and
    // `_version_does_not_contain_a_null_byte`. So a `\t` byte
    // in the active `release_notes_version` value is currently
    // protected *transitively* — through equality with
    // `version`, which is itself directly pinned against
    // embedded whitespace.
    //
    // But the transitive protection is brittle: a future
    // refactor that decoupled the two helpers (a separate
    // override constant for the "What's New" scope, a
    // workspace-vendoring split that lifted
    // `release_notes_version` out of the equality chain, or a
    // CHANGELOG.md-derived release-notes version that
    // intentionally lagged the binary version on a hotfix
    // cut) would silently drop the `\t` guard the moment the
    // `_matches_*` companions started skipping cases. The
    // `_does_not_contain_a_null_byte` and
    // `_does_not_contain_a_carriage_return_byte` siblings
    // name `\0` and `\r` specifically — `\t` is neither.
    // None of the existing companions name the `\t` byte
    // directly on the `release_notes_version` helper.
    //
    // A regression that landed `"0.0.1\t"` or `"0\t.0\t.1"`
    // (a tab-separated copy-paste from a TSV-style CHANGELOG
    // column export, a `concat!(_, "\t", _)` form, or a
    // hand-edited helper override that lifted the version
    // string from a tab-indented YAML / Markdown table row)
    // would mis-render in multiple downstream surfaces,
    // identically to the analysis on the `version` helper:
    // (1) the GLib-backed
    // `AdwAboutDialog::set_release_notes_version` setter
    // routes the value into Pango for inline rendering as
    // the "What's New in v<release_notes_version>" header —
    // Pango's default rendering of `\t` is implementation-
    // defined and typically renders as a wide horizontal gap
    // or an empty box, breaking the tidy section-header
    // layout; (2) the value scopes the "What's New" body
    // region inside the dialog — a mismatched / mis-rendered
    // scope key could prevent the body from rendering at all
    // on libadwaita versions that strip whitespace when
    // computing the body-region lookup key; (3) screen
    // readers that announce the "What's New" section header
    // read the `\t` as a literal control character, breaking
    // the section-header accessibility-tree announcement at
    // the tab boundary.
    //
    // Pinning the no-`\t` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // decoupling that silently dropped the transitive
    // `version` guard. Current helper returns the value
    // sourced from `CARGO_PKG_VERSION` (no `\t` byte), so
    // this test passes today and serves as a forcing function
    // so any future decoupling override of the helper —
    // including the eventual landing of a separately-scoped
    // release-notes version derived from CHANGELOG.md
    // headings — stays free of horizontal-tab bytes.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\t'),
        "AdwAboutDialog release_notes_version must not contain the `\\t` horizontal-tab byte (0x09); the current value's `\\t`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version`, so a future decoupling override would silently drop the `\\t` guard — a stray `\\t` would render as a wide horizontal gap in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that strip whitespace when computing the body-region lookup key, and break screen-reader section-header announcements at the tab boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth mirror of the just-added
    // `_release_notes_version_does_not_contain_a_horizontal_tab_byte`
    // companion on the release-notes-body side, and a
    // per-helper sibling of the existing
    // `_release_notes_does_not_contain_a_null_byte` and
    // `_release_notes_does_not_contain_a_carriage_return_byte`
    // companions. The libadwaita release-notes convention
    // permits embedded `\n` line breaks between Pango markup
    // elements (`<li>` entries inside the wrapping `<ul>`,
    // paragraph breaks, etc.), so the helper is one of only
    // three about-dialog helpers (alongside
    // `format_app_about_dialog_debug_info` and
    // `format_app_about_dialog_translator_credits`) where
    // embedded line breaks are legitimately expected. That
    // makes `\t` (0x09 HORIZONTAL TAB) a distinct regression
    // surface: it is NOT covered by
    // `_has_no_surrounding_whitespace_when_non_empty` (`\t`
    // mid-string is non-surrounding), it is NOT covered by
    // `_starts_and_ends_with_a_markup_element_when_non_empty`
    // (the opening `<` and closing `>` markup boundaries are
    // independent of mid-body `\t` bytes), it slips past
    // `_does_not_contain_a_null_byte` (`\t` is not `\0`),
    // and it slips past
    // `_does_not_contain_a_carriage_return_byte` (`\t` is
    // not `\r`). None of the existing companions name the
    // `\t` byte directly on this helper.
    //
    // A regression that landed
    // `"<ul>\n\t<li>foo</li>\n\t<li>bar</li>\n</ul>"`
    // (tab-indented pretty-printed Pango markup lifted from
    // a `pandoc` Markdown-to-HTML transform with `--wrap=auto`
    // and `--columns=80`, a `concat!(_, "\t", _)` form
    // mirroring a CHANGELOG.md tab-indented bullet block, or
    // a hand-edited helper that pasted from a tab-indented
    // YAML / Markdown source list) would mis-render in
    // multiple downstream surfaces: (1) Pango's markup
    // parser permits ASCII whitespace between elements but
    // renders `\t` as a wide horizontal gap or an empty box
    // when no following character forces a tab-stop reset;
    // in the about-dialog "What's New" body this would
    // surface as visible gaps or boxes between the wrapping
    // `<ul>` and each `<li>` bullet element; (2) any in-app
    // changelog display that reuses the release-notes string
    // outside the dialog (release-tracker bots, copy-to-
    // clipboard handlers) would propagate the stray `\t`
    // into the consumer's stream and trigger the same
    // rendering bug across every downstream surface; (3)
    // screen readers that announce the release-notes content
    // read the `\t` as a literal control character, breaking
    // the accessibility-tree announcement at every bullet-
    // boundary indent.
    //
    // Mirror of the existing
    // `_developer_name_does_not_contain_a_horizontal_tab_byte`,
    // `_copyright_does_not_contain_a_horizontal_tab_byte`,
    // `_comments_does_not_contain_a_horizontal_tab_byte`,
    // `_developers_entries_do_not_contain_a_horizontal_tab_byte`,
    // `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte`,
    // and just-added
    // `_release_notes_version_does_not_contain_a_horizontal_tab_byte`
    // siblings; together they pin the no-`\t` invariant
    // across every about-dialog string helper, extending the
    // existing `\0`-byte and `\r`-byte coverage to the
    // horizontal-tab regression surface as well.
    //
    // Pinning the no-tab invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream "What's New"
    // body rendering bug, a stray `\t` byte in an external
    // changelog reuse, or a screen-reader announcement
    // break. Current helper returns the empty literal `""`
    // (no `\t` byte), so this test passes today and serves
    // as a forcing function so any future override of the
    // helper — including the eventual landing of an actual
    // v0.2 release-notes Pango markup body sourced from
    // CHANGELOG.md — stays free of horizontal tabs even
    // when embedded `\n` line breaks are intentionally
    // present.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\t'),
        "AdwAboutDialog release_notes must not contain the `\\t` horizontal-tab byte (0x09); the Pango markup parser permits ASCII whitespace between elements but renders `\\t` as a wide horizontal gap or empty box when no following character forces a tab-stop reset, so a stray `\\t` between the wrapping `<ul>` and each `<li>` bullet would surface as visible gaps or boxes in the dialog's What's New body, propagate the same rendering bug into any external changelog reuse, and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth mirror of the just-added
    // `_release_notes_does_not_contain_a_horizontal_tab_byte`
    // companion on the translator-credits side, and a
    // per-helper sibling of the existing
    // `_translator_credits_does_not_contain_a_null_byte` and
    // `_translator_credits_does_not_contain_a_carriage_return_byte`
    // companions. The libadwaita translator-credits convention
    // permits embedded `\n` line breaks between translator
    // entries (the `_is_single_line_when_non_empty` companion
    // only asserts the empty-string case, so it does not gate
    // embedded newlines once a translation lands), so the
    // helper is one of only three about-dialog helpers
    // (alongside `format_app_about_dialog_debug_info` and
    // `format_app_about_dialog_release_notes`) where embedded
    // line breaks are legitimately expected. That makes `\t`
    // (0x09 HORIZONTAL TAB) a distinct regression surface:
    // it is NOT covered by
    // `_has_no_surrounding_whitespace_when_non_empty` (`\t`
    // mid-string is non-surrounding), it is NOT covered by
    // any per-entry single-line check (the helper itself is
    // explicitly multi-line per libadwaita convention), it
    // slips past `_does_not_contain_a_null_byte` (`\t` is not
    // `\0`), and it slips past
    // `_does_not_contain_a_carriage_return_byte` (`\t` is not
    // `\r`). None of the existing companions name the `\t`
    // byte directly on this helper.
    //
    // A regression that landed
    // `"name1\t<email1>\nname2\t<email2>"` (tab-separated
    // `<name>\t<email>` rows lifted from a TSV-style
    // contributors export, an `xgettext` export pipeline that
    // preserved tab-separated column values, a `concat!(_,
    // "\t", _)` form mirroring a tab-aligned attribution
    // block, or a hand-edited helper that pasted from a tab-
    // indented YAML translator-credits source list) would
    // mis-render in multiple downstream surfaces: (1)
    // libadwaita's credits-page parser splits the translator-
    // credits string on `\n` (LF) per the documented
    // convention, leaving the embedded `\t` bytes inside each
    // parsed entry untouched; the GLib-backed Pango render
    // path treats `\t` as an implementation-defined wide
    // horizontal gap or an empty box, breaking the tidy two-
    // column `<name> <email>` attribution layout; (2) any
    // localization tooling that round-trips the translator-
    // credits string back through `xgettext` would either
    // silently dedupe the `\t` to a single space (data loss)
    // or preserve the `\t` and propagate the same rendering
    // bug across every downstream consumer of the .po / .mo
    // file; (3) screen readers that announce the credits-page
    // contents read the `\t` as a literal control character,
    // breaking the accessibility-tree announcement at every
    // attribution-row column boundary.
    //
    // Mirror of the existing
    // `_developer_name_does_not_contain_a_horizontal_tab_byte`,
    // `_copyright_does_not_contain_a_horizontal_tab_byte`,
    // `_comments_does_not_contain_a_horizontal_tab_byte`,
    // `_developers_entries_do_not_contain_a_horizontal_tab_byte`,
    // `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte`,
    // and just-added
    // `_release_notes_version_does_not_contain_a_horizontal_tab_byte`
    // and `_release_notes_does_not_contain_a_horizontal_tab_byte`
    // siblings; together they pin the no-`\t` invariant
    // across every about-dialog string helper, extending the
    // existing `\0`-byte and `\r`-byte coverage to the
    // horizontal-tab regression surface as well.
    //
    // Pinning the no-tab invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream credits-page
    // rendering bug, a stray `\t` byte in the .po round trip,
    // or a screen-reader announcement break. Current helper
    // returns the empty literal `""` (no `\t` byte), so this
    // test passes today and serves as a forcing function so
    // any future override of the helper — including the
    // eventual landing of an actual translator-credits string
    // — stays free of horizontal tabs even when embedded `\n`
    // line breaks are intentionally present.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\t'),
        "AdwAboutDialog translator_credits must not contain the `\\t` horizontal-tab byte (0x09); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\t` bytes inside each parsed entry untouched, so a stray `\\t` would render as a wide horizontal gap or empty box in the credits-page attribution column, would survive `xgettext` round trips as either silent dedupe to a single space or `\\t` preservation, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth sibling of
    // `format_app_about_dialog_debug_info_carries_program_name_version_and_app_id`
    // (content-shape pin),
    // `_is_non_empty_text_with_no_trailing_whitespace`
    // (non-empty + no-trailing-whitespace pin),
    // `_starts_with_program_name` (leading-substring pin),
    // `_app_id_appears_on_a_distinct_line_from_program_name`
    // (multi-line pin), `_has_exactly_two_lines` (line-count
    // pin), `_program_name_line_ends_with_the_version`
    // (line-1 trailing-substring pin),
    // `_app_id_line_ends_with_the_reverse_dns_app_id`
    // (line-2 trailing-substring pin), `_is_ascii_only`
    // (byte-composition pin),
    // `_does_not_contain_a_null_byte` (null-byte pin), and
    // `_does_not_contain_a_carriage_return_byte` (CR pin).
    // Those companions catch the wrong-shape / wrong-content
    // / empty / multi-line-count / wrong-trailing-substring
    // / non-ASCII / null-byte / CR-byte regressions but the
    // `_is_ascii_only` companion only pins each byte as
    // ASCII (`0x00`-`0x7F`) — the `\t` horizontal-tab byte
    // (0x09) is ASCII, so a regression that landed
    // `"Paladin\t0.0.1\nApp ID:\torg.tamx.Paladin.Gui"`
    // (tab-aligned columns from a `printf "%s\t%s"`-style
    // payload formatter, a `concat!(_, "\t", _)` injection,
    // or a hand-edited helper that lifted the payload from a
    // TSV-formatted debug dump) would slip past
    // `_is_ascii_only`, `_does_not_contain_a_null_byte`
    // (since `\t` is not `\0`), and
    // `_does_not_contain_a_carriage_return_byte` (since `\t`
    // is not `\r`).
    //
    // The line-count and trailing-substring companions would
    // also miss the regression: `_has_exactly_two_lines` uses
    // `str::lines()` which splits on `\n` only and is
    // indifferent to `\t` bytes inside any individual line,
    // `_program_name_line_ends_with_the_version` checks the
    // first line via `str::lines().next()` and only enforces
    // `.ends_with(version)` so a `\t` mid-line is invisible
    // to it, and `_app_id_line_ends_with_the_reverse_dns_app_id`
    // applies the same `.ends_with(app_id)` shape check to
    // line 2 with the same indifference. None of the
    // existing companions name the `\t` byte directly.
    //
    // A regression that landed `\t` in the payload would
    // mis-render the debug-info content in three ways: (1)
    // the GLib-backed `AdwAboutDialog::set_debug_info` setter
    // routes the value into Pango for rendering inside the
    // dialog's "Troubleshooting → Debugging Information" body
    // — Pango's default rendering of `\t` is implementation-
    // defined and typically renders as a wide horizontal gap
    // or an empty box, breaking the tidy single-column layout
    // expected by the AdwAboutDialog template; (2) when the
    // user pastes the payload into a bug-report form on
    // GitHub, the `\t` characters expand to inconsistent
    // widths depending on the receiver's tab-stop settings,
    // cluttering the maintainer's view of the report; (3)
    // when the user saves the payload to a `.txt` file via
    // the `AdwAboutDialog::set_debug_info_filename` slot, the
    // GTK file-writer writes the raw bytes so the resulting
    // file has tab-aligned columns that break POSIX text-
    // processing tools (`grep`, `awk`, `cut`) whose default
    // delimiter behaviour assumes single-space-separated
    // fields rather than tab-separated columns.
    //
    // Pinning the no-`\t` invariant directly here surfaces
    // the regression with a message naming the offending
    // `\t` byte at build time rather than as a downstream
    // dialog rendering bug, a pasted-bug-report column-width
    // drift artifact, or a saved-file POSIX-text-processing
    // breakage.
    //
    // The current `format_app_about_dialog_debug_info`
    // returns `"Paladin 0.0.1\nApp ID: org.tamx.Paladin.Gui"`
    // (built at compile time via `concat!` with single-space
    // separators between every column), so this test passes
    // today and serves as a forcing function so any future
    // override of the debug-info helper stays on bare-space
    // column separators rather than tab-aligned columns.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\t'),
        "AdwAboutDialog debug_info must not contain the `\\t` horizontal-tab byte (0x09); a `\\t` byte slips past `_is_ascii_only` (since `\\t` is ASCII), past `_does_not_contain_a_null_byte` (since `\\t` is not `\\0`), past `_does_not_contain_a_carriage_return_byte` (since `\\t` is not `\\r`), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and would render as a wide horizontal gap in the Troubleshooting dialog body, drift column widths in pasted bug reports, and break POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename`; got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth per-byte sibling completing the
    // developer-name byte triplet (null / horizontal-tab /
    // carriage-return) alongside the existing
    // `_developer_name_does_not_contain_a_null_byte` and
    // `_developer_name_does_not_contain_a_horizontal_tab_byte`
    // companions. The existing
    // `_developer_name_is_a_single_line_without_embedded_newlines`
    // companion does explicitly assert `!developer.contains('\r')`
    // alongside its `\n` check — so the developer-name
    // helper's `\r`-cleanliness is currently protected
    // *directly* by that one specific companion.
    //
    // But that direct coverage is *coupled* to the single-
    // line-attribution invariant: a future refactor that
    // intentionally allowed embedded `\n` line breaks in the
    // developer-name slot (a libadwaita upgrade that taught
    // the attribution row to wrap across two lines, a
    // multi-contributor attribution column layout that listed
    // each contributor on its own line, or a workspace-
    // vendoring split that lifted developer-name out of the
    // single-line constraint) would naturally relax the
    // `_is_a_single_line_without_embedded_newlines` companion
    // to drop the `\n` check — and the human author of that
    // refactor might reasonably drop the `\r` check at the
    // same time on the assumption that "if `\n` is now
    // allowed, then `\r` as a line-ending companion is also
    // allowed". That assumption is wrong: `\r` is never the
    // correct line-ending byte for a GNOME-stack string (the
    // GNOME stack uses LF-only conventions throughout), so
    // dropping the `\r` check alongside the `\n` check would
    // silently regress the no-`\r` invariant.
    //
    // The `_is_ascii_only` companion does not catch `\r`
    // (since `\r` is ASCII, 0x0D), the
    // `_has_no_surrounding_whitespace` companion does not
    // catch a mid-string `\r`, the
    // `_starts_with_the_definite_article` and
    // `_ends_with_the_contributors_collective_noun`
    // companions only constrain the prefix and suffix, the
    // `_does_not_contain_a_null_byte` companion only names
    // `\0` specifically, and the
    // `_does_not_contain_a_horizontal_tab_byte` companion
    // only names `\t` specifically. None of those names
    // `\r` directly on this helper — only the
    // `_is_a_single_line_without_embedded_newlines`
    // companion does, and that coupling is fragile.
    //
    // A regression that landed `"The Paladin\rcontributors"`
    // (CRLF copy-paste from a Windows-edited CONTRIBUTORS
    // file with the `\n` stripped during a manual
    // line-ending fix-up, a `concat!(_, "\r", _)` form, or a
    // hand-edited helper that lifted the attribution from a
    // CR-only Mac Classic-style text file) would mis-render
    // in multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_developer_name` setter routes the
    // value into Pango for inline rendering beneath the
    // program name in the dialog header — Pango's default
    // rendering of a bare `\r` byte is implementation-
    // defined and typically renders as a literal control
    // glyph or an empty box, breaking the tidy single-line
    // attribution layout; (2) the same developer-name string
    // is reused by `_copyright_ends_with_developer_name` to
    // construct the footer copyright row, so a `\r` byte in
    // the developer name would propagate into the copyright
    // slot and mis-render there too; (3) screen readers that
    // announce the dialog attribution read the `\r` as a
    // literal control character, breaking the attribution
    // accessibility-tree announcement.
    //
    // Pinning the no-`\r` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // single-line decoupling that silently dropped the `\r`
    // guard. Current helper returns the literal `"The
    // Paladin contributors"` (no `\r` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — including the eventual
    // landing of a multi-contributor attribution string —
    // stays free of carriage returns even when embedded `\n`
    // line breaks are intentionally introduced.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\r'),
        "AdwAboutDialog developer-name must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected by the `_is_a_single_line_without_embedded_newlines` companion's coupled `\\n`/`\\r` check, so a future refactor that intentionally allowed embedded `\\n` line breaks in the attribution slot might reasonably drop the `\\r` check alongside the `\\n` check on the assumption that both line-ending bytes are now allowed (an assumption that is wrong: GNOME-stack strings use LF-only conventions throughout); a stray `\\r` would render as a control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, and break screen-reader attribution announcements; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth per-byte sibling completing the
    // copyright byte triplet (null / horizontal-tab /
    // carriage-return) alongside the existing
    // `_copyright_does_not_contain_a_null_byte` and
    // `_copyright_does_not_contain_a_horizontal_tab_byte`
    // companions. The existing
    // `_copyright_is_a_single_line_without_embedded_newlines`
    // companion does explicitly assert `!copyright.contains('\r')`
    // alongside its `\n` check — so the copyright helper's
    // `\r`-cleanliness is currently protected *directly* by
    // that one specific companion.
    //
    // But that direct coverage is *coupled* to the single-
    // line-attribution invariant: a future refactor that
    // intentionally allowed embedded `\n` line breaks in the
    // copyright slot (a multi-line attribution including a
    // separate copyright-glyph row and contributor row, a
    // libadwaita upgrade that taught the footer copyright
    // row to wrap across two lines, or a workspace-vendoring
    // split that lifted copyright out of the single-line
    // constraint) would naturally relax the
    // `_is_a_single_line_without_embedded_newlines` companion
    // to drop the `\n` check — and the human author of that
    // refactor might reasonably drop the `\r` check at the
    // same time on the assumption that "if `\n` is now
    // allowed, then `\r` as a line-ending companion is also
    // allowed". That assumption is wrong: `\r` is never the
    // correct line-ending byte for a GNOME-stack string (the
    // GNOME stack uses LF-only conventions throughout), so
    // dropping the `\r` check alongside the `\n` check would
    // silently regress the no-`\r` invariant.
    //
    // The `_starts_with_copyright_glyph_and_contains_developer_name`,
    // `_ends_with_developer_name`,
    // `_separates_glyph_and_attribution_with_a_single_space`,
    // `_does_not_end_with_a_period`,
    // `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`,
    // and `_returns_paladin_copyright_line` exact-value /
    // shape companions only constrain the prefix, suffix,
    // glyph-attribution boundary, or full literal — none
    // catches a mid-string `\r`. The
    // `_does_not_contain_a_null_byte` companion only names
    // `\0` specifically and the
    // `_does_not_contain_a_horizontal_tab_byte` companion
    // only names `\t` specifically. None of those names `\r`
    // directly on this helper — only the
    // `_is_a_single_line_without_embedded_newlines` companion
    // does, and that coupling is fragile.
    //
    // A regression that landed `"© The Paladin\rcontributors"`
    // (CRLF copy-paste from a Windows-edited COPYRIGHT file
    // with the `\n` stripped during a manual line-ending
    // fix-up, a `concat!(_, "\r", _)` form, or a hand-edited
    // helper that lifted the literal from a CR-only Mac
    // Classic-style text file) would mis-render in multiple
    // downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_copyright` setter routes the value
    // into Pango for inline rendering in the dialog footer
    // — Pango's default rendering of a bare `\r` byte is
    // implementation-defined and typically renders as a
    // literal control glyph or an empty box, breaking the
    // tidy single-line copyright layout against the website /
    // issue-link rows beneath it; (2) the same copyright
    // string is the legal attribution surface for the dialog
    // — a `\r`-mis-rendered footer erodes the trusted-
    // application surface contract by surfacing a control-
    // byte glyph in the legal-attribution row; (3) screen
    // readers that announce the dialog copyright row read
    // the `\r` as a literal control character, breaking the
    // accessibility-tree announcement of the legal
    // attribution.
    //
    // Pinning the no-`\r` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // single-line decoupling that silently dropped the `\r`
    // guard. Current helper returns the literal `"© The
    // Paladin contributors"` (no `\r` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — including the eventual
    // landing of a multi-line copyright attribution — stays
    // free of carriage returns even when embedded `\n` line
    // breaks are intentionally introduced.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\r'),
        "AdwAboutDialog copyright must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected by the `_is_a_single_line_without_embedded_newlines` companion's coupled `\\n`/`\\r` check, so a future refactor that intentionally allowed embedded `\\n` line breaks in the copyright slot might reasonably drop the `\\r` check alongside the `\\n` check on the assumption that both line-ending bytes are now allowed (an assumption that is wrong: GNOME-stack strings use LF-only conventions throughout); a stray `\\r` would render as a control glyph in the dialog footer copyright row, erode the legal-attribution trusted-surface contract, and break screen-reader copyright-row announcements; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth per-byte sibling extending the
    // program-name byte coverage from the existing
    // `_program_name_does_not_contain_a_null_byte` companion
    // to the carriage-return byte. The existing
    // `_program_name_has_no_embedded_whitespace` companion
    // uses `char::is_whitespace()`, which returns true for
    // `\r` — so the program-name helper's `\r`-cleanliness
    // is currently protected *transitively* by that one
    // specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a single embedded space in
    // the program-name slot (a localized program-name string
    // like `"Paladin Auth"` or a workspace-vendoring split
    // that lifted program-name out of the no-whitespace
    // constraint) would naturally relax the
    // `_has_no_embedded_whitespace` companion — and the
    // human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, tab) without separately calling out
    // `\r` on the assumption that "ASCII whitespace is now
    // allowed". That assumption is wrong: `\r` is a control
    // byte, not a layout-friendly whitespace character, and
    // GNOME-stack strings use LF-only conventions
    // throughout, so dropping the `\r` check alongside the
    // space-relaxation would silently regress the no-`\r`
    // invariant.
    //
    // The `_is_ascii_only` companion does not catch `\r`
    // (since `\r` is ASCII, 0x0D), the
    // `_is_non_empty_and_not_app_id` companion only checks
    // non-empty + distinct-from-app-id, the
    // `_matches_format_app_window_title` cross-helper
    // companion only enforces equality with the window title
    // (so any `\r`-bearing override would slip past as long
    // as the window title helper had matching bytes), the
    // `_is_segment_of_application_icon_name` cross-helper
    // companion only checks segment containment, the
    // `_does_not_end_with_a_period` companion only constrains
    // the suffix, and the `_does_not_contain_a_null_byte`
    // companion only names `\0` specifically. None of those
    // names `\r` directly on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"Paladin\r"` (CRLF copy-
    // paste from a Windows-edited Cargo.toml `name` field
    // with the `\n` stripped during a manual line-ending
    // fix-up, a `concat!(_, "\r", _)` form, or a hand-edited
    // helper override that lifted the program name from a
    // CR-only Mac Classic-style text file) would mis-render
    // in three downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_application_name` setter routes
    // the value into Pango for inline rendering as the bold
    // program-name row at the dialog header — Pango's
    // default rendering of a bare `\r` byte is
    // implementation-defined and typically renders as a
    // literal control glyph or an empty box, breaking the
    // tidy bold-header layout; (2) the matching
    // `gtk::Window::set_title` setter (the program name is
    // mirrored to the window title per
    // `_matches_format_app_window_title`) renders the `\r`
    // in the window manager's taskbar / dock display label,
    // surfacing the control byte to every shell that lists
    // open windows; (3) the GTK accessibility tree's
    // `accessible-name` property routes through the same
    // Pango layer, breaking screen-reader announcements of
    // the application name at the `\r` boundary.
    //
    // Pinning the no-`\r` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped
    // the `\r` guard. Current helper returns the literal
    // `"Paladin"` (no `\r` byte), so this test passes today
    // and serves as a forcing function so any future
    // override of the helper — including the eventual
    // landing of a localized multi-word program name —
    // stays free of carriage returns.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\r'),
        "AdwAboutDialog program_name must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\r` guard alongside the space relaxation; a stray `\\r` would render as a control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label, and break screen-reader application-name announcements; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth per-byte sibling completing the
    // program-name byte triplet (null / carriage-return /
    // horizontal-tab) alongside the existing
    // `_program_name_does_not_contain_a_null_byte` and
    // just-added
    // `_program_name_does_not_contain_a_carriage_return_byte`
    // companions. The existing
    // `_program_name_has_no_embedded_whitespace` companion
    // uses `char::is_whitespace()`, which returns true for
    // `\t` — so the program-name helper's `\t`-cleanliness
    // is currently protected *transitively* by that one
    // specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a single embedded space in
    // the program-name slot (a localized program-name string
    // like `"Paladin Auth"` or a workspace-vendoring split
    // that lifted program-name out of the no-whitespace
    // constraint) would naturally relax the
    // `_has_no_embedded_whitespace` companion — and the
    // human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, carriage-return) without separately
    // calling out `\t` on the assumption that "ASCII
    // whitespace is now allowed". That assumption is wrong:
    // `\t` is a column-aligning control byte, not a layout-
    // friendly space, and the program-name slot is rendered
    // in a single-column bold-header row that has no tab-
    // stop semantics — so dropping the `\t` check alongside
    // the space-relaxation would silently regress the
    // no-`\t` invariant.
    //
    // The `_is_ascii_only` companion does not catch `\t`
    // (since `\t` is ASCII, 0x09), the
    // `_is_non_empty_and_not_app_id` companion only checks
    // non-empty + distinct-from-app-id, the
    // `_matches_format_app_window_title` cross-helper
    // companion only enforces equality with the window title
    // (so any `\t`-bearing override would slip past as long
    // as the window title helper had matching bytes), the
    // `_is_segment_of_application_icon_name` cross-helper
    // companion only checks segment containment, the
    // `_does_not_end_with_a_period` companion only constrains
    // the suffix, the `_does_not_contain_a_null_byte`
    // companion only names `\0` specifically, and the
    // `_does_not_contain_a_carriage_return_byte` companion
    // only names `\r` specifically. None of those names `\t`
    // directly on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"Paladin\t"` or `"Pal\tadin"`
    // (tab-aligned column from a `printf "%s\t%s"`-style
    // localized resource-bundle formatter, a `concat!(_,
    // "\t", _)` form mirroring a TSV-style localization
    // table, or a hand-edited helper override that lifted
    // the program name from a tab-indented YAML / Markdown
    // table cell) would mis-render in three downstream
    // surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_application_name` setter routes
    // the value into Pango for inline rendering as the bold
    // program-name row at the dialog header — Pango's
    // default rendering of `\t` is implementation-defined
    // and typically renders as a wide horizontal gap or an
    // empty box, breaking the tidy bold-header layout; (2)
    // the matching `gtk::Window::set_title` setter (the
    // program name is mirrored to the window title per
    // `_matches_format_app_window_title`) renders the `\t`
    // in the window manager's taskbar / dock display label,
    // where tab-stop semantics are shell-dependent and may
    // truncate or mis-align the label; (3) the GTK
    // accessibility tree's `accessible-name` property routes
    // through the same Pango layer, breaking screen-reader
    // announcements of the application name at the tab
    // boundary.
    //
    // Pinning the no-`\t` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped
    // the `\t` guard. Current helper returns the literal
    // `"Paladin"` (no `\t` byte), so this test passes today
    // and serves as a forcing function so any future
    // override of the helper — including the eventual
    // landing of a localized multi-word program name —
    // stays free of horizontal tabs.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\t'),
        "AdwAboutDialog program_name must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\t` guard alongside the space relaxation; a stray `\\t` would render as a wide horizontal gap in the bold dialog-header program-name row, mis-align the window manager's taskbar / dock display label under shell-dependent tab-stop semantics, and break screen-reader application-name announcements at the tab boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth per-byte sibling extending the
    // version-helper byte coverage from the existing
    // `_version_does_not_contain_a_null_byte` companion to
    // the carriage-return byte. The existing
    // `_version_has_no_embedded_whitespace` companion uses
    // `char::is_whitespace()`, which returns true for `\r`
    // — so the version helper's `\r`-cleanliness is
    // currently protected *transitively* by that one
    // specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a version-suffix separator
    // space (e.g. `"0.0.1 pre-release"` or `"0.0.1 +build"`)
    // would naturally relax the
    // `_has_no_embedded_whitespace` companion — and the
    // human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, tab) without separately calling out
    // `\r` on the assumption that "ASCII whitespace is now
    // allowed". That assumption is wrong: `\r` is a control
    // byte, not a layout-friendly whitespace character, and
    // the version slot is rendered as a single-line caption
    // beneath the program name in the dialog header that
    // has no CR-line-ending semantics — so dropping the
    // `\r` check alongside the space-relaxation would
    // silently regress the no-`\r` invariant.
    //
    // The `_is_ascii_only` companion does not catch `\r`
    // (since `\r` is ASCII, 0x0D), the
    // `_version_is_non_empty_and_looks_like_semver`
    // companion only enforces non-empty + semver shape, the
    // `_starts_with_a_digit` / `_does_not_start_with_a_dot`
    // / `_does_not_end_with_a_dot` companions only constrain
    // the boundary bytes, the
    // `_has_at_least_three_dot_separated_segments` /
    // `_segments_are_non_empty` companions only check
    // segment count and non-emptiness, the
    // `_matches_cargo_pkg_version` cross-helper companion
    // only enforces equality with `CARGO_PKG_VERSION` (so
    // any `\r`-bearing override would slip past as long as
    // Cargo's pinned version had matching bytes), and the
    // `_does_not_contain_a_null_byte` companion only names
    // `\0` specifically. None of those names `\r` directly
    // on this helper — only the `_has_no_embedded_whitespace`
    // companion catches it transitively, and that coupling
    // is fragile.
    //
    // A regression that landed `"0.0.1\r"` (CRLF copy-paste
    // from a Windows-edited Cargo.toml `version` field with
    // the `\n` stripped during a manual line-ending fix-up,
    // a `concat!(_, "\r", _)` form, or a hand-edited helper
    // override that lifted the version literal from a CR-
    // only Mac Classic-style text file) would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_version` setter routes the value
    // into Pango for inline rendering as the version caption
    // beneath the program name — Pango's default rendering
    // of a bare `\r` byte is implementation-defined and
    // typically renders as a literal control glyph or an
    // empty box, breaking the tidy version-caption layout;
    // (2) the same version string is reused by
    // `_release_notes_version_matches_about_dialog_version`
    // for the "What's New in v<version>" header — a `\r`
    // byte in the version would propagate into the release-
    // notes header and mis-render there too; (3) any
    // downstream tooling that scrapes the version slot
    // (release-tracker bots, update-check pings, crash-
    // report assemblers) would propagate the stray `\r`
    // byte and trigger the same rendering bug across every
    // downstream surface; (4) screen readers that announce
    // the version caption read the `\r` as a literal control
    // character, breaking the version-caption accessibility-
    // tree announcement.
    //
    // Pinning the no-`\r` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped
    // the `\r` guard. Current helper returns the value
    // sourced from `CARGO_PKG_VERSION` (no `\r` byte), so
    // this test passes today and serves as a forcing
    // function so any future override of the helper —
    // including the eventual landing of a build-metadata-
    // suffixed version string — stays free of carriage
    // returns.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\r'),
        "AdwAboutDialog version must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\r` guard alongside the space relaxation; a stray `\\r` would render as a control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, and break screen-reader version-caption announcements; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth per-byte sibling completing the
    // version-helper byte triplet (null / carriage-return /
    // horizontal-tab) alongside the existing
    // `_version_does_not_contain_a_null_byte` and just-added
    // `_version_does_not_contain_a_carriage_return_byte`
    // companions. The existing
    // `_version_has_no_embedded_whitespace` companion uses
    // `char::is_whitespace()`, which returns true for `\t`
    // — so the version helper's `\t`-cleanliness is
    // currently protected *transitively* by that one
    // specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a version-suffix separator
    // space (e.g. `"0.0.1 pre-release"` or `"0.0.1 +build"`)
    // would naturally relax the
    // `_has_no_embedded_whitespace` companion — and the
    // human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, carriage-return) without separately
    // calling out `\t` on the assumption that "ASCII
    // whitespace is now allowed". That assumption is wrong:
    // `\t` is a column-aligning control byte, not a layout-
    // friendly space, and the version slot is rendered as a
    // single-line caption beneath the program name in the
    // dialog header that has no tab-stop semantics — so
    // dropping the `\t` check alongside the space-relaxation
    // would silently regress the no-`\t` invariant.
    //
    // The `_is_ascii_only` companion does not catch `\t`
    // (since `\t` is ASCII, 0x09), the
    // `_version_is_non_empty_and_looks_like_semver`
    // companion only enforces non-empty + semver shape, the
    // `_starts_with_a_digit` / `_does_not_start_with_a_dot`
    // / `_does_not_end_with_a_dot` companions only constrain
    // the boundary bytes, the
    // `_has_at_least_three_dot_separated_segments` /
    // `_segments_are_non_empty` companions only check
    // segment count and non-emptiness (a mid-segment `\t`
    // does not change the segment count and a `\t`-only
    // segment is still non-empty), the
    // `_matches_cargo_pkg_version` cross-helper companion
    // only enforces equality with `CARGO_PKG_VERSION` (so
    // any `\t`-bearing override would slip past as long as
    // Cargo's pinned version had matching bytes), the
    // `_does_not_contain_a_null_byte` companion only names
    // `\0` specifically, and the
    // `_does_not_contain_a_carriage_return_byte` companion
    // only names `\r` specifically. None of those names `\t`
    // directly on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"0\t.0\t.1"` or `"0.0.1\t"`
    // (tab-aligned column from a `printf "%s\t%s"`-style
    // version formatter, a `concat!(_, "\t", _)` form
    // mirroring a TSV-style version-table cell, or a hand-
    // edited helper override that lifted the version literal
    // from a tab-indented YAML / Markdown table row) would
    // mis-render in multiple downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_version` setter
    // routes the value into Pango for inline rendering as
    // the version caption beneath the program name — Pango's
    // default rendering of `\t` is implementation-defined
    // and typically renders as a wide horizontal gap or an
    // empty box, breaking the tidy version-caption layout;
    // (2) the same version string is reused by
    // `_release_notes_version_matches_about_dialog_version`
    // for the "What's New in v<version>" header — a `\t`
    // byte in the version would propagate into the release-
    // notes header and render as a horizontal gap there too,
    // potentially shifting the body-region lookup key on
    // libadwaita versions that strip whitespace when
    // computing the lookup; (3) any downstream tooling that
    // scrapes the version slot (release-tracker bots,
    // update-check pings, crash-report assemblers) would
    // propagate the stray `\t` byte and trigger the same
    // rendering bug across every downstream surface; (4)
    // screen readers that announce the version caption read
    // the `\t` as a literal control character, breaking the
    // version-caption accessibility-tree announcement at the
    // tab boundary.
    //
    // Pinning the no-`\t` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped
    // the `\t` guard. Current helper returns the value
    // sourced from `CARGO_PKG_VERSION` (no `\t` byte), so
    // this test passes today and serves as a forcing
    // function so any future override of the helper —
    // including the eventual landing of a build-metadata-
    // suffixed version string — stays free of horizontal
    // tabs.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\t'),
        "AdwAboutDialog version must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\t` guard alongside the space relaxation; a stray `\\t` would render as a wide horizontal gap in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, and break screen-reader version-caption announcements at the tab boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth per-byte sibling extending the
    // application-icon-name byte coverage from the existing
    // `_application_icon_name_does_not_contain_a_null_byte`
    // companion to the carriage-return byte. The existing
    // `_application_icon_name_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns
    // true for `\r` — so the application-icon-name helper's
    // `\r`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace
    // check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a localized icon-name with
    // a single embedded space (a non-trivial scenario per
    // freedesktop.org icon-naming convention, which forbids
    // spaces in icon names — but a workspace-vendoring
    // refactor or a CI codegen step could relax the
    // `_has_no_embedded_whitespace` companion incorrectly)
    // would naturally drop the `\r` check at the same time
    // on the assumption that "ASCII whitespace is now
    // allowed". That assumption is wrong: `\r` is a control
    // byte, not a layout-friendly whitespace character, and
    // a `gtk::IconTheme::lookup_by_gicon` call with a `\r`-
    // bearing icon name lands in undefined territory across
    // GIO icon-loader implementations.
    //
    // The `_is_ascii_only` companion does not catch `\r`
    // (since `\r` is ASCII, 0x0D), the
    // `_is_reverse_dns` / `_has_exactly_four_segments` /
    // `_starts_with_a_lowercase_ascii_letter` companions
    // only constrain the segment-count and leading byte, the
    // `_ends_with_gui_segment` / `_does_not_end_with_a_dot`
    // / `_does_not_start_with_a_dot` companions only
    // constrain the suffix and dot-boundaries, the
    // `_segments_are_non_empty` companion only checks
    // segment non-emptiness, the `_matches_app_id` /
    // `_program_name_is_segment_of_application_icon_name`
    // cross-helper companions only enforce equality with the
    // app-id and segment containment with the program name,
    // and the `_does_not_contain_a_null_byte` companion only
    // names `\0` specifically. None of those names `\r`
    // directly on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"org.tamx.Paladin.Gui\r"`
    // (CRLF copy-paste from a Windows-edited
    // `_application_icon_name` helper override with the `\n`
    // stripped during a manual line-ending fix-up, a
    // `concat!(_, "\r", _)` form, or a hand-edited helper
    // override that lifted the icon name from a CR-only Mac
    // Classic-style text file or a `\r`-line-ending
    // freedesktop.org icon-spec source) would mis-render in
    // multiple downstream surfaces: (1) the `gtk::IconTheme`
    // lookup machinery treats the icon name as a key into
    // the icon cache — a `\r`-bearing key would silently
    // miss the cache and fall through to the placeholder
    // fallback icon, masking the bug as a missing-icon
    // surface rather than a malformed-icon-name surface;
    // (2) the matching `gtk::Window::set_icon_name` setter
    // (the icon name is mirrored onto the toplevel window's
    // icon property) routes through GLib's GVariant string-
    // marshalling layer and may surface as a malformed
    // window-icon-name property in the X11 / Wayland
    // protocol exchange, where some compositors silently
    // drop the icon and others render a broken-icon
    // placeholder; (3) the same icon name is mirrored to the
    // AppStream metainfo file's `<id>` field per the §11.4
    // app-id convention — a `\r`-bearing icon name would
    // propagate into the metainfo file and fail Flathub's
    // strict reverse-DNS-validating metainfo linter on the
    // next package submission.
    //
    // Pinning the no-`\r` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream icon-cache miss, a malformed-window-icon
    // protocol exchange, or a Flathub metainfo linter
    // failure. Current helper returns the literal
    // `"org.tamx.Paladin.Gui"` (no `\r` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — including the
    // eventual landing of a Flatpak app-id rename — stays
    // free of carriage returns.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\r'),
        "AdwAboutDialog application_icon_name must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\r` guard; a stray `\\r` would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange, and propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth per-byte sibling completing the
    // application-icon-name byte triplet (null / carriage-
    // return / horizontal-tab) alongside the existing
    // `_application_icon_name_does_not_contain_a_null_byte`
    // and just-added
    // `_application_icon_name_does_not_contain_a_carriage_return_byte`
    // companions. The existing
    // `_application_icon_name_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns
    // true for `\t` — so the application-icon-name helper's
    // `\t`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace
    // check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed an embedded space in the
    // icon-name slot (a non-trivial scenario per
    // freedesktop.org icon-naming convention, which forbids
    // spaces in icon names — but a workspace-vendoring
    // refactor or a CI codegen step could relax the
    // `_has_no_embedded_whitespace` companion incorrectly)
    // would naturally drop the `\t` check at the same time
    // on the assumption that "ASCII whitespace is now
    // allowed". That assumption is wrong: `\t` is a column-
    // aligning control byte, not a layout-friendly space,
    // and a `gtk::IconTheme::lookup_by_gicon` call with a
    // `\t`-bearing icon name lands in undefined territory
    // across GIO icon-loader implementations.
    //
    // The `_is_ascii_only` companion does not catch `\t`
    // (since `\t` is ASCII, 0x09), the
    // `_is_reverse_dns` / `_has_exactly_four_segments` /
    // `_starts_with_a_lowercase_ascii_letter` companions
    // only constrain the segment-count and leading byte, the
    // `_ends_with_gui_segment` / `_does_not_end_with_a_dot`
    // / `_does_not_start_with_a_dot` companions only
    // constrain the suffix and dot-boundaries, the
    // `_segments_are_non_empty` companion only checks
    // segment non-emptiness (a `\t`-only segment is still
    // non-empty as a byte sequence), the `_matches_app_id` /
    // `_program_name_is_segment_of_application_icon_name`
    // cross-helper companions only enforce equality with the
    // app-id and segment containment with the program name,
    // the `_does_not_contain_a_null_byte` companion only
    // names `\0` specifically, and the
    // `_does_not_contain_a_carriage_return_byte` companion
    // only names `\r` specifically. None of those names `\t`
    // directly on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"org\t.tamx.Paladin.Gui"`
    // or `"org.tamx.Paladin.Gui\t"` (tab-aligned column from
    // a `printf "%s\t%s"`-style app-id formatter, a
    // `concat!(_, "\t", _)` form mirroring a TSV-style
    // icon-table cell, or a hand-edited helper override that
    // lifted the icon name from a tab-indented YAML /
    // Markdown table row) would mis-render in multiple
    // downstream surfaces: (1) the `gtk::IconTheme` lookup
    // machinery treats the icon name as a key into the icon
    // cache — a `\t`-bearing key would silently miss the
    // cache and fall through to the placeholder fallback
    // icon, masking the bug as a missing-icon surface
    // rather than a malformed-icon-name surface; (2) the
    // matching `gtk::Window::set_icon_name` setter (the
    // icon name is mirrored onto the toplevel window's icon
    // property) routes through GLib's GVariant string-
    // marshalling layer and may surface as a malformed
    // window-icon-name property in the X11 / Wayland
    // protocol exchange, where some compositors silently
    // drop the icon and others render a broken-icon
    // placeholder; (3) the same icon name is mirrored to
    // the AppStream metainfo file's `<id>` field per the
    // §11.4 app-id convention — a `\t`-bearing icon name
    // would propagate into the metainfo file and fail
    // Flathub's strict reverse-DNS-validating metainfo
    // linter on the next package submission; (4) the same
    // icon name is the reverse-DNS app-id key for D-Bus
    // service registration via `gio::Application::set_application_id`
    // — a `\t`-bearing key fails the D-Bus well-known-name
    // validation regex (`[A-Za-z_][A-Za-z0-9_-]*` per
    // segment) and the GApplication instance fails to
    // register on the session bus, breaking single-instance
    // semantics.
    //
    // Pinning the no-`\t` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream icon-cache miss, a malformed-window-icon
    // protocol exchange, a Flathub metainfo linter failure,
    // or a D-Bus single-instance registration failure.
    // Current helper returns the literal
    // `"org.tamx.Paladin.Gui"` (no `\t` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — including the
    // eventual landing of a Flatpak app-id rename — stays
    // free of horizontal tabs.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\t'),
        "AdwAboutDialog application_icon_name must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\t` guard; a stray `\\t` would silently miss the `gtk::IconTheme` cache lookup, surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, and fail D-Bus well-known-name validation when `gio::Application::set_application_id` tries to register the single-instance bus name; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_carriage_return_byte() {
    // Defense-in-depth per-byte sibling extending the
    // debug-info-filename byte coverage from the existing
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // companion to the carriage-return byte. The existing
    // `_debug_info_filename_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns
    // true for `\r` — so the debug-info-filename helper's
    // `\r`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace
    // check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a localized filename with
    // a single embedded space (a non-trivial scenario per
    // freedesktop.org file-naming convention but feasible
    // if a localized "Debug information.txt" filename were
    // ever rendered to non-ASCII locales) would naturally
    // relax the `_has_no_embedded_whitespace` companion —
    // and the human author of that refactor might
    // reasonably restructure the check to only reject
    // specific control bytes (newline, tab) without
    // separately calling out `\r` on the assumption that
    // "ASCII whitespace is now allowed". That assumption is
    // wrong: `\r` is a control byte, not a layout-friendly
    // whitespace character, and a save-to-disk filename
    // with `\r` lands in undefined territory across POSIX
    // filesystem implementations (some kernel ports of
    // `open(2)` reject `\r` outright, some accept it but
    // render the file name un-listable via `ls` / `find`
    // tools that strip non-printable bytes).
    //
    // The `_is_ascii_only` companion does not catch `\r`
    // (since `\r` is ASCII, 0x0D), the
    // `_returns_paladin_debug_info_txt` exact-value pin only
    // holds while the literal is unchanged, the
    // `_does_not_contain_path_separators` /
    // `_does_not_start_with_a_dot` companions only constrain
    // the path-safety and leading-byte boundaries, the
    // `_contains_exactly_one_period` /
    // `_extension_is_lowercase_txt` companions only check
    // the dot-count and suffix, the
    // `_is_non_empty_single_line_with_txt_extension`
    // companion only checks non-empty + single-line + `.txt`
    // suffix shape (the single-line check uses
    // `str::lines().count() == 1` which transparently
    // collapses `\r\n` or `\r` line endings into a single
    // line by `str::lines()` semantics), and the
    // `_does_not_contain_a_null_byte` companion only names
    // `\0` specifically. None of those names `\r` directly
    // on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"paladin-debug-info.txt\r"`
    // (CRLF copy-paste from a Windows-edited filename
    // literal with the `\n` stripped during a manual line-
    // ending fix-up, a `concat!(_, "\r", _)` form, or a
    // hand-edited helper override that lifted the filename
    // from a CR-only Mac Classic-style text file) would
    // mis-render in three downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_debug_info_filename`
    // setter routes the value into the dialog's "Save
    // Debug Information…" file-chooser pre-fill — a `\r`-
    // bearing filename mis-renders in the GtkFileDialog's
    // filename entry as a literal control glyph and may
    // also surface in the suggested-filename display in the
    // file chooser's title bar; (2) when the user saves the
    // debug-info payload to disk, the filesystem `open(2)`
    // call routes the `\r`-bearing filename through the
    // kernel VFS layer — some POSIX-conformant kernels
    // (Linux, macOS, BSDs) accept `\r` in filenames but
    // many shell-tooling pipelines (`ls`, `find`, `tar`)
    // assume printable-only filenames and either silently
    // strip the `\r` or display the file as an un-readable
    // entry; (3) the saved file's filename surfaces in any
    // bug-tracker attachment URL or chat-attachment column
    // where the `\r` byte mis-renders as `^M` artifacts,
    // confusing the maintainer's triage workflow.
    //
    // Pinning the no-`\r` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream file-chooser mis-render, a shell-tooling
    // visibility break, or a chat-attachment column-render
    // artifact. Current helper returns the literal
    // `"paladin-debug-info.txt"` (no `\r` byte), so this
    // test passes today and serves as a forcing function so
    // any future override of the helper — including the
    // eventual landing of a localized filename — stays free
    // of carriage returns.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\r'),
        "AdwAboutDialog debug_info_filename must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\r` guard alongside the space relaxation; a stray `\\r` would mis-render as a control glyph in the GtkFileDialog filename entry pre-fill, surface as an un-listable file under shell-tooling pipelines (`ls`, `find`, `tar`) that strip non-printable bytes, and confuse maintainer triage with `^M` artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_horizontal_tab_byte() {
    // Defense-in-depth per-byte sibling completing the
    // debug-info-filename byte triplet (null / carriage-
    // return / horizontal-tab) alongside the existing
    // `_debug_info_filename_does_not_contain_a_null_byte`
    // and just-added
    // `_debug_info_filename_does_not_contain_a_carriage_return_byte`
    // companions. The existing
    // `_debug_info_filename_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns
    // true for `\t` — so the debug-info-filename helper's
    // `\t`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace
    // check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a localized filename with
    // a single embedded space (a non-trivial scenario per
    // freedesktop.org file-naming convention but feasible
    // if a localized "Debug information.txt" filename were
    // ever rendered to non-ASCII locales) would naturally
    // relax the `_has_no_embedded_whitespace` companion —
    // and the human author of that refactor might
    // reasonably restructure the check to only reject
    // specific control bytes (newline, carriage-return)
    // without separately calling out `\t` on the assumption
    // that "ASCII whitespace is now allowed". That
    // assumption is wrong: `\t` is a column-aligning
    // control byte, not a layout-friendly space, and a
    // save-to-disk filename with `\t` lands in undefined
    // territory across POSIX filesystem implementations
    // (some kernel ports of `open(2)` reject `\t` outright,
    // some accept it but render the file name as a tab-
    // expanded column under `ls -l` output that mis-aligns
    // every following column).
    //
    // The `_is_ascii_only` companion does not catch `\t`
    // (since `\t` is ASCII, 0x09), the
    // `_returns_paladin_debug_info_txt` exact-value pin only
    // holds while the literal is unchanged, the
    // `_does_not_contain_path_separators` /
    // `_does_not_start_with_a_dot` companions only constrain
    // the path-safety and leading-byte boundaries, the
    // `_contains_exactly_one_period` /
    // `_extension_is_lowercase_txt` companions only check
    // the dot-count and suffix, the
    // `_is_non_empty_single_line_with_txt_extension`
    // companion only checks non-empty + single-line + `.txt`
    // suffix shape (the single-line check uses
    // `str::lines().count() == 1` which is indifferent to
    // mid-string `\t` bytes since `\t` is not a line-
    // terminator under `str::lines()` semantics), the
    // `_does_not_contain_a_null_byte` companion only names
    // `\0` specifically, and the
    // `_does_not_contain_a_carriage_return_byte` companion
    // only names `\r` specifically. None of those names `\t`
    // directly on this helper — only the
    // `_has_no_embedded_whitespace` companion catches it
    // transitively, and that coupling is fragile.
    //
    // A regression that landed `"paladin\t-debug-info.txt"`
    // or `"paladin-debug-info.txt\t"` (tab-aligned column
    // from a `printf "%s\t%s"`-style filename formatter, a
    // `concat!(_, "\t", _)` form mirroring a TSV-style
    // filename-table cell, or a hand-edited helper override
    // that lifted the filename from a tab-indented YAML /
    // Markdown table row) would mis-render in three
    // downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_debug_info_filename` setter
    // routes the value into the dialog's "Save Debug
    // Information…" file-chooser pre-fill — a `\t`-bearing
    // filename mis-renders in the GtkFileDialog's filename
    // entry as a wide horizontal gap and may also surface
    // in the suggested-filename display in the file
    // chooser's title bar with shell-dependent tab-stop
    // semantics; (2) when the user saves the debug-info
    // payload to disk, the filesystem `open(2)` call routes
    // the `\t`-bearing filename through the kernel VFS
    // layer — some POSIX-conformant kernels (Linux, macOS,
    // BSDs) accept `\t` in filenames but `ls -l` output
    // expands `\t` to the next tab-stop column, mis-
    // aligning every following column in the directory
    // listing and breaking any pipeline parsers (`awk`,
    // `cut`) that assume single-space-separated columns;
    // (3) the saved file's filename surfaces in any bug-
    // tracker attachment URL or chat-attachment column
    // where the `\t` byte mis-renders inconsistently
    // depending on the receiver's tab-stop settings,
    // confusing the maintainer's triage workflow.
    //
    // Pinning the no-`\t` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a
    // downstream file-chooser mis-render, a shell-tooling
    // column-alignment break, or a chat-attachment column-
    // render inconsistency. Current helper returns the
    // literal `"paladin-debug-info.txt"` (no `\t` byte), so
    // this test passes today and serves as a forcing
    // function so any future override of the helper —
    // including the eventual landing of a localized
    // filename — stays free of horizontal tabs.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\t'),
        "AdwAboutDialog debug_info_filename must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\t` guard alongside the space relaxation; a stray `\\t` would mis-render as a wide horizontal gap in the GtkFileDialog filename entry pre-fill, mis-align every following column in `ls -l` output by expanding to the next tab-stop, and confuse maintainer triage with inconsistent tab-stop renders in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_carriage_return_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `\r` carriage-return byte (0x0D).
    // The existing `url_helpers_contain_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns
    // true for `\r` — so the URL-helpers' `\r`-cleanliness is
    // currently protected *transitively* by that one specific
    // companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a URL with a single
    // percent-encoded space (a non-trivial scenario per RFC
    // 3986, which forbids unencoded spaces in URLs but
    // permits `%20` percent-encoding for them — but a
    // workspace-vendoring refactor or a CI codegen step could
    // relax the `_contain_no_embedded_whitespace` companion
    // incorrectly when handling decoded percent-encoded
    // strings) would naturally drop the `\r` check at the
    // same time on the assumption that "ASCII whitespace is
    // now allowed". That assumption is wrong: `\r` is never
    // a valid byte inside a URL per RFC 3986 (the carriage-
    // return byte is not in any of the URL grammar's
    // production rules), so dropping the `\r` check alongside
    // the percent-encoded-space relaxation would silently
    // regress the no-`\r` invariant.
    //
    // A regression would slip past every existing companion:
    // the `_is_non_empty_https_url[_distinct_*]` per-URL
    // companion (which only checks non-empty + `https://`
    // prefix + no space byte — a `\r` byte mid-URL satisfies
    // all three), the `_are_ascii_only` cross-URL companion
    // (`\r` is ASCII 0x0D so it slips past), the
    // `_do_not_end_with_a_trailing_slash` companion (which
    // only constrains the final byte), the
    // `_do_not_contain_a_null_byte` companion (which only
    // names `\0` specifically), the
    // `_do_not_contain_a_query_string` /
    // `_do_not_contain_a_fragment_anchor` /
    // `_do_not_contain_a_userinfo_at_sign` /
    // `_do_not_contain_a_backslash` siblings (which each
    // name a different byte specifically). None of the
    // existing companions name the `\r` byte directly.
    //
    // A regression that landed
    // `"https://github.com\rFreedomBen/paladin"` (CRLF
    // copy-paste from a Windows-edited URL constant with the
    // `\n` stripped during a manual line-ending fix-up, a
    // `concat!(_, "\r", _)` form, or a hand-edited helper
    // override that lifted the URL from a CR-only Mac
    // Classic-style text file or a `\r`-line-ending API
    // response body) would mis-render in multiple downstream
    // surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_website` / `set_issue_url` /
    // `set_support_url` setters route the value into Pango
    // for inline rendering as the underlined link label in
    // the dialog footer — Pango's default rendering of a
    // bare `\r` byte is implementation-defined and typically
    // renders as a literal control glyph or an empty box,
    // breaking the trusted-application surface contract of
    // the link label; (2) when the user clicks the URL, GIO's
    // `gtk_show_uri_full` routes the value through the
    // session's `xdg-open` / portal layer where some URL
    // parsers (WHATWG URL §4.5 implementations) reject `\r`
    // outright with `InvalidUrl`, breaking the click-through
    // routing entirely, while others percent-encode the `\r`
    // as `%0D` and route to a non-existent URL with a
    // `Bad Request` response surfacing as a confusing
    // browser-level error; (3) screen readers that announce
    // the URL label read the `\r` as a literal control
    // character, breaking the link-label accessibility-tree
    // announcement.
    //
    // Pinning the no-CR invariant directly here surfaces the
    // regression with a message naming the offending URL
    // helper at build time rather than as a downstream user-
    // visible mis-rendered link label, a confusing browser-
    // level error on click-through, or an inconsistent URL-
    // parser-implementation routing surface. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_do_not_contain_a_fragment_anchor`,
    // `_url_helpers_do_not_contain_a_userinfo_at_sign`,
    // `_url_helpers_do_not_contain_a_backslash`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`, and
    // `_url_helpers_do_not_contain_a_null_byte` cross-URL
    // siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`,
    // no `\0`, no `\r`, no `?` query, no `#` anchor, no `@`
    // userinfo, no `\` path-confusion byte) across all three
    // footer link surfaces against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('\r'),
            "AdwAboutDialog {label} must not contain the `\\r` carriage-return byte (0x0D) — `\\r` is never a valid byte inside a URL per RFC 3986 (the carriage-return byte is not in any of the URL grammar's production rules); the current `\\r`-cleanliness is only protected transitively by `_url_helpers_contain_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future percent-encoded-space relaxation would silently drop the `\\r` guard; a stray `\\r` would mis-render as a control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%0D`-encoding implementations, and break screen-reader link-label announcements; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_horizontal_tab_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `\t` horizontal-tab byte (0x09).
    // The existing `url_helpers_contain_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns
    // true for `\t` — so the URL-helpers' `\t`-cleanliness
    // is currently protected *transitively* by that one
    // specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor
    // that intentionally allowed a URL with a single
    // percent-encoded space (a non-trivial scenario per RFC
    // 3986, which forbids unencoded spaces in URLs but
    // permits `%20` percent-encoding for them — but a
    // workspace-vendoring refactor or a CI codegen step
    // could relax the `_contain_no_embedded_whitespace`
    // companion incorrectly when handling decoded percent-
    // encoded strings) would naturally drop the `\t` check
    // at the same time on the assumption that "ASCII
    // whitespace is now allowed". That assumption is wrong:
    // `\t` is never a valid byte inside a URL per RFC 3986
    // (the horizontal-tab byte is not in any of the URL
    // grammar's production rules), so dropping the `\t`
    // check alongside the percent-encoded-space relaxation
    // would silently regress the no-`\t` invariant.
    //
    // A regression would slip past every existing companion:
    // the `_is_non_empty_https_url[_distinct_*]` per-URL
    // companion (which only checks non-empty + `https://`
    // prefix + no space byte — a `\t` byte mid-URL satisfies
    // all three since `\t` is not the literal U+0020 SPACE),
    // the `_are_ascii_only` cross-URL companion (`\t` is
    // ASCII 0x09 so it slips past), the
    // `_do_not_end_with_a_trailing_slash` companion (which
    // only constrains the final byte), the
    // `_do_not_contain_a_null_byte` companion (which only
    // names `\0` specifically), the
    // `_do_not_contain_a_carriage_return_byte` companion
    // (which names `\r` specifically), the
    // `_do_not_contain_a_query_string` /
    // `_do_not_contain_a_fragment_anchor` /
    // `_do_not_contain_a_userinfo_at_sign` /
    // `_do_not_contain_a_backslash` siblings (which each
    // name a different byte specifically). None of the
    // existing companions name the `\t` byte directly.
    //
    // A regression that landed
    // `"https://github.com\tFreedomBen/paladin"` (tab-aligned
    // column from a `printf "%s\t%s"`-style URL formatter, a
    // `concat!(_, "\t", _)` form mirroring a TSV-style URL-
    // table cell, or a hand-edited helper override that
    // lifted the URL from a tab-indented YAML / Markdown
    // table row or a TSV-formatted bookmarks export) would
    // mis-render in multiple downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_website` /
    // `set_issue_url` / `set_support_url` setters route the
    // value into Pango for inline rendering as the underlined
    // link label in the dialog footer — Pango's default
    // rendering of `\t` is implementation-defined and
    // typically renders as a wide horizontal gap or an empty
    // box, breaking the trusted-application surface contract
    // of the link label; (2) when the user clicks the URL,
    // GIO's `gtk_show_uri_full` routes the value through the
    // session's `xdg-open` / portal layer where some URL
    // parsers (WHATWG URL §4.5 implementations) reject `\t`
    // outright with `InvalidUrl`, breaking the click-through
    // routing entirely, while others percent-encode the `\t`
    // as `%09` and route to a non-existent URL with a
    // `Bad Request` response surfacing as a confusing
    // browser-level error; (3) screen readers that announce
    // the URL label read the `\t` as a literal control
    // character, breaking the link-label accessibility-tree
    // announcement at the tab boundary; (4) any downstream
    // tooling that scrapes the URL labels (link-checker
    // bots, broken-link auditors) would propagate the stray
    // `\t` byte into the consumer's stream and trigger the
    // same routing failure across every downstream surface.
    //
    // Pinning the no-tab invariant directly here surfaces
    // the regression with a message naming the offending URL
    // helper at build time rather than as a downstream user-
    // visible mis-rendered link label, a confusing browser-
    // level error on click-through, an inconsistent URL-
    // parser-implementation routing surface, or a link-
    // checker tooling failure. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_do_not_contain_a_fragment_anchor`,
    // `_url_helpers_do_not_contain_a_userinfo_at_sign`,
    // `_url_helpers_do_not_contain_a_backslash`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`,
    // `_url_helpers_do_not_contain_a_null_byte`, and just-
    // added `_url_helpers_do_not_contain_a_carriage_return_byte`
    // cross-URL siblings; together they pin the URL byte-
    // composition contract (no whitespace, ASCII-only, no
    // terminal `/`, no `\0`, no `\r`, no `\t`, no `?` query,
    // no `#` anchor, no `@` userinfo, no `\` path-confusion
    // byte) across all three footer link surfaces against a
    // single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('\t'),
            "AdwAboutDialog {label} must not contain the `\\t` horizontal-tab byte (0x09) — `\\t` is never a valid byte inside a URL per RFC 3986 (the horizontal-tab byte is not in any of the URL grammar's production rules); the current `\\t`-cleanliness is only protected transitively by `_url_helpers_contain_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future percent-encoded-space relaxation would silently drop the `\\t` guard; a stray `\\t` would mis-render as a wide horizontal gap in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%09`-encoding implementations, break screen-reader link-label announcements at the tab boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling beginning the next C0
    // control-byte cycle for the developer-name helper after
    // the just-completed `{null / horizontal-tab / carriage-
    // return}` triplet. The vertical-tab byte `\x0B` (0x0B)
    // sits one step above HT (0x09) and one step below CR
    // (0x0D) in the ASCII C0 block; like its siblings it is a
    // non-printable control byte that has no legitimate use
    // inside a human-readable GNOME dialog attribution string.
    //
    // None of the existing developer-name companions name the
    // `\x0B` byte directly:
    //   - `_developer_name_is_a_single_line_without_embedded_newlines`
    //     only checks `\n` and `\r` — `\x0B` is neither;
    //   - `_developer_name_is_ascii_only` pins each byte as
    //     ASCII — `\x0B` is ASCII so it slips past;
    //   - `_developer_name_has_no_surrounding_whitespace`
    //     uses `char::is_whitespace()`, which under Rust's
    //     Unicode definition returns true for U+000B VT, so
    //     this companion *does* reject a leading or trailing
    //     `\x0B` — but a mid-string `\x0B` (`"The Pa\x0Bladin
    //     contributors"`) sits between the boundaries and
    //     slips past;
    //   - `_developer_name_starts_with_the_definite_article`
    //     and `_ends_with_the_contributors_collective_noun`
    //     only constrain the literal prefix `"The "` and
    //     suffix `"contributors"`, so a mid-string `\x0B`
    //     between them satisfies both;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte`
    //     each name a different byte specifically.
    //
    // The current `_returns_the_paladin_contributors` exact-
    // value pin catches every byte today, but its protection
    // collapses the moment a contributor-list addition or a
    // workspace-vendoring split decouples the helper from the
    // pinned literal — at that point a `\x0B`-bearing override
    // would slip past every byte-level companion above (since
    // `char::is_whitespace` only catches the boundary `\x0B`,
    // not a mid-string one).
    //
    // A regression that landed `"The Paladin\x0Bcontributors"`
    // (vertical-tab byte lifted from a legacy plain-text
    // CONTRIBUTORS file authored on a mainframe terminal that
    // used `\x0B` as a vertical-spacing separator, a
    // `concat!(_, "\x0B", _)` form, or a hand-edited helper
    // that pasted from an EBCDIC-to-ASCII translation table
    // row preserving the original VT byte) would mis-render
    // in multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_developer_name` setter hands the
    // string to Pango for inline rendering beneath the program
    // name in the dialog header — Pango's default rendering of
    // a bare `\x0B` byte is implementation-defined and
    // typically renders as a literal control glyph (a hollow
    // box, a tofu-like placeholder, or an invisible column-
    // advance), breaking the tidy single-line attribution
    // layout; (2) the same developer-name string is reused by
    // `_copyright_ends_with_developer_name` to construct the
    // footer copyright row, so a `\x0B` byte in the developer
    // name would propagate into the copyright slot and mis-
    // render there too; (3) screen readers that announce the
    // dialog attribution read the `\x0B` as a literal control
    // character, breaking the attribution accessibility-tree
    // announcement at the byte boundary; (4) downstream
    // tooling that scrapes the developer-name attribution
    // (release-note generators, contributor-attribution
    // crawlers) would propagate the stray `\x0B` byte into the
    // consumer's stream and trigger the same rendering bug
    // across every downstream surface.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces
    // the regression with a message naming the offending byte
    // at build time rather than as a downstream dialog-header
    // rendering bug or a screen-reader announcement break.
    // Current helper returns the literal `"The Paladin
    // contributors"` (no `\x0B` byte), so this test passes
    // today and serves as a forcing function so any future
    // override of the helper — including the eventual landing
    // of a multi-contributor attribution string — stays free
    // of vertical-tab bytes. Begins the developer-name C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet so the
    // helper's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x0B'),
        "AdwAboutDialog developer-name must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x0B` is ASCII), past `_has_no_surrounding_whitespace` (which only rejects `\\x0B` at the boundaries via `char::is_whitespace()`), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the copyright
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the next C0
    // control byte. The vertical-tab byte `\x0B` (0x0B) sits one
    // step above HT (0x09) and one step below CR (0x0D) in the
    // ASCII C0 block; like its siblings it is a non-printable
    // control byte with no legitimate use inside a human-readable
    // GNOME dialog copyright string.
    //
    // None of the existing copyright companions name the `\x0B`
    // byte directly:
    //   - `_copyright_is_a_single_line_without_embedded_newlines`
    //     only checks `\n` and `\r` — `\x0B` is neither;
    //   - `_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    //     and `_copyright_ends_with_developer_name` only constrain
    //     the literal prefix (the `©` glyph + space) and the
    //     `"The Paladin contributors"` suffix, so a mid-string
    //     `\x0B` between them (`"© The Pa\x0Bladin contributors"`)
    //     satisfies both;
    //   - `_separates_glyph_and_attribution_with_a_single_space`
    //     only constrains the single byte immediately after the
    //     `©` glyph — a `\x0B` later in the string slips past;
    //   - `_does_not_end_with_a_period` only constrains the
    //     trailing byte;
    //   - `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    //     scans for four-digit runs — `\x0B` is not a digit;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` each name a
    //     different byte specifically.
    //
    // The `_returns_paladin_copyright_line` exact-value pin
    // catches every byte today, but its protection collapses the
    // moment a multi-line copyright-attribution refactor or a
    // workspace-vendoring split decouples the helper from the
    // pinned literal — at that point a `\x0B`-bearing override
    // would slip past every byte-level companion above.
    //
    // A regression that landed `"© The Paladin\x0Bcontributors"`
    // (vertical-tab byte lifted from a legacy COPYRIGHT file
    // authored on a line-printer terminal that used `\x0B` as a
    // vertical-spacing separator between the copyright glyph and
    // the attribution, a `concat!("© The Paladin", "\x0B",
    // "contributors")` form, or a hand-edited helper that pasted
    // from an EBCDIC-to-ASCII translation preserving the original
    // VT byte) would mis-render in multiple downstream surfaces:
    // (1) the GLib-backed `AdwAboutDialog::set_copyright` setter
    // hands the string to Pango for inline rendering in the
    // dialog footer — Pango's default rendering of a bare `\x0B`
    // byte is implementation-defined and typically renders as a
    // literal control glyph (a hollow box or a tofu-like
    // placeholder), breaking the tidy single-line copyright
    // layout against the website / issue-link rows beneath it;
    // (2) the copyright string is the legal attribution surface
    // for the dialog — a `\x0B`-mis-rendered footer erodes the
    // trusted-application surface contract by surfacing a control-
    // byte glyph in the legal-attribution row; (3) screen readers
    // that announce the dialog copyright row read the `\x0B` as a
    // literal control character, breaking the accessibility-tree
    // announcement of the legal attribution at the byte boundary;
    // (4) downstream tooling that scrapes the copyright string
    // (license-attribution aggregators, AGPL-3.0-or-later
    // compliance crawlers) would propagate the stray `\x0B` byte
    // into the consumer's stream and trigger the same rendering
    // bug across every downstream surface.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-footer
    // rendering bug or a screen-reader announcement break.
    // Current helper returns the literal `"© The Paladin
    // contributors"` (no `\x0B` byte), so this test passes today
    // and serves as a forcing function so any future override of
    // the helper — including the eventual landing of a multi-
    // line copyright attribution — stays free of vertical-tab
    // bytes. Continues the copyright C0 control-byte cycle past
    // the just-completed `{null / horizontal-tab / carriage-
    // return}` triplet so the helper's byte-composition contract
    // pins each forbidden control byte against a single source
    // of truth.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x0B'),
        "AdwAboutDialog copyright must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` (which only constrain the literal prefix and suffix), past `_separates_glyph_and_attribution_with_a_single_space` (which only constrains the single byte after the `©` glyph), past `_does_not_end_with_a_period` (which only constrains the trailing byte), past the no-year-token four-digit-run scan (`\\x0B` is not a digit), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-footer copyright row, erode the legal-attribution trusted-surface contract by surfacing a control-byte glyph in the legal row, break screen-reader copyright-row announcements at the byte boundary, and propagate into downstream license-attribution scrapers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the comments
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the next C0
    // control byte. The vertical-tab byte `\x0B` (0x0B) sits one
    // step above HT (0x09) and one step below CR (0x0D) in the
    // ASCII C0 block; like its siblings it is a non-printable
    // control byte with no legitimate use inside a human-readable
    // GNOME dialog description string.
    //
    // None of the existing comments companions name the `\x0B`
    // byte directly:
    //   - `_comments_is_non_empty_single_line_distinct_from_program_name`
    //     uses `comments.contains('\n')` to reject embedded
    //     newlines and a surrounding-whitespace `trim()` check —
    //     `\x0B` is not `\n` and, although `char::is_whitespace()`
    //     returns true for U+000B VT (so a *leading* or
    //     *trailing* `\x0B` would be trimmed out by the
    //     surrounding-whitespace guard), a mid-string `\x0B`
    //     (`"OTP authent\x0Bicator for the command line"`) sits
    //     between the boundaries and slips past;
    //   - `_comments_does_not_end_with_a_period_per_libadwaita_convention`
    //     only constrains the trailing byte;
    //   - `_comments_is_ascii_only` pins each byte as ASCII —
    //     `\x0B` is ASCII so it slips past;
    //   - `_comments_does_not_contain_a_null_byte` /
    //     `_comments_does_not_contain_a_horizontal_tab_byte` /
    //     `_comments_does_not_contain_a_carriage_return_byte`
    //     each name a different byte specifically;
    //   - `_comments_matches_cargo_pkg_description` transitively
    //     guards the value via the cross-source pin to
    //     `CARGO_PKG_DESCRIPTION`, but that protection is brittle:
    //     a future refactor that decoupled the helper from the
    //     workspace `Cargo.toml` `description` field (a hand-
    //     edited override for a libadwaita HIG-mandated single-
    //     line summary phrasing, or a workspace-vendoring split)
    //     would silently drop the transitive guard.
    //
    // A regression that landed `"OTP authent\x0Bicator for the
    // command line"` (a vertical-tab byte lifted from a legacy
    // plain-text DESCRIPTION file authored on a line-printer
    // terminal that used `\x0B` as a column-spacing separator, a
    // `concat!(_, "\x0B", _)` form, or a hand-edited helper that
    // pasted from an EBCDIC-to-ASCII translation preserving the
    // original VT byte) would mis-render in multiple downstream
    // surfaces: (1) the GLib-backed `AdwAboutDialog::set_comments`
    // setter hands the string to Pango for inline rendering as
    // the dialog header description beneath the program name —
    // Pango's default rendering of a bare `\x0B` byte is
    // implementation-defined and typically renders as a literal
    // control glyph (a hollow box or a tofu-like placeholder),
    // breaking the tidy single-line description layout against
    // the program-name row above it; (2) the comments value is
    // sourced from `CARGO_PKG_DESCRIPTION` which propagates into
    // Cargo's `description` field — tooling that scrapes this
    // metadata (`cargo metadata`, crates.io registry indexing,
    // GNOME `gnome-software` descriptions) would propagate the
    // stray `\x0B` byte into every consumer's stream; (3) screen
    // readers that announce the dialog description read the
    // `\x0B` as a literal control character, breaking the
    // description accessibility-tree announcement at the byte
    // boundary.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-header
    // rendering bug, a Cargo-metadata-scrape miss, or a screen-
    // reader announcement break. Current helper returns the
    // value sourced from `CARGO_PKG_DESCRIPTION` (no `\x0B`
    // byte), so this test passes today and serves as a forcing
    // function so any future override of the helper — or any
    // future edit of the workspace `Cargo.toml` `description`
    // field — stays free of vertical-tab bytes. Continues the
    // comments C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return}` triplet so the
    // helper's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x0B'),
        "AdwAboutDialog comments must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace, and although `char::is_whitespace()` matches U+000B VT it only rejects boundary occurrences), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_is_ascii_only` (because `\\x0B` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers and `gnome-software` description rows, and break screen-reader description announcements at the byte boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-entry-loop sibling of the just-added
    // `_developer_name_does_not_contain_a_vertical_tab_byte` and
    // `_copyright_does_not_contain_a_vertical_tab_byte`
    // companions on the same C0 control-byte cycle, extending
    // the developers-array byte-cleanliness contract past the
    // just-completed `{null / horizontal-tab / carriage-return}`
    // entry-triplet to the next C0 control byte. The vertical-
    // tab byte `\x0B` (0x0B) sits one step above HT (0x09) and
    // one step below CR (0x0D) in the ASCII C0 block; like its
    // siblings it is a non-printable control byte with no
    // legitimate use inside a human-readable GNOME credits-page
    // contributor-name entry.
    //
    // None of the existing developers companions name the `\x0B`
    // byte directly per entry:
    //   - `_is_non_empty_array_of_non_empty_single_line_names`
    //     pins each entry as non-empty and single-line via
    //     `!name.contains('\n')` — `\x0B` is not `\n`. The
    //     surrounding-whitespace guards
    //     (`!name.starts_with(char::is_whitespace)` and
    //     `!name.ends_with(char::is_whitespace)`) reject `\x0B`
    //     *only* at the boundary bytes (since `char::is_whitespace()`
    //     under Rust's Unicode definition matches U+000B VT) —
    //     but a mid-string `\x0B` (`"Benjamin\x0BPorter"`) sits
    //     between the boundaries and slips past both guards;
    //   - `_entries_are_distinct` / `_does_not_contain_developer_name`
    //     / `_does_not_contain_app_id` /
    //     `_does_not_contain_program_name` / `_lists_benjamin_porter`
    //     companions guard against content-shape regressions but
    //     say nothing about the `\x0B` byte;
    //   - `_entries_do_not_contain_a_null_byte` /
    //     `_entries_do_not_contain_a_horizontal_tab_byte` /
    //     `_entries_do_not_contain_a_carriage_return_byte`
    //     siblings each name a different byte specifically.
    //
    // A regression that landed `["Benjamin\x0BPorter"]` (a
    // vertical-tab byte lifted from a legacy CONTRIBUTORS file
    // authored on a line-printer terminal that used `\x0B` as a
    // vertical-spacing separator between first and last names,
    // a `concat!("Benjamin", "\x0B", "Porter")` form, or a hand-
    // edited helper that pasted from an EBCDIC-to-ASCII
    // translation preserving the original VT byte) would mis-
    // render in multiple downstream surfaces: (1) the GLib-
    // backed `AdwAboutDialog::set_developers` setter hands the
    // array to GTK and Pango renders each entry as a credits-
    // page row — a stray `\x0B` byte in the middle of a
    // contributor name would render as a literal control glyph
    // (a hollow box or tofu-like placeholder), breaking the
    // credits-page contributor-name layout; (2) any tooling
    // that scrapes the credits-page contributor list (release-
    // note generators, contributor-attribution crawlers, GNOME
    // `gnome-software` credit aggregators) would propagate the
    // stray `\x0B` byte into the consumer's stream; (3) screen
    // readers that announce the credits-page contributor names
    // read the `\x0B` as a literal control character, breaking
    // the contributor-name accessibility-tree announcement at
    // the byte boundary.
    //
    // Pinning the no-`\x0B` invariant across every contributor
    // entry in a single per-entry loop surfaces the regression
    // with a message naming both the offending byte and the
    // affected entry index at build time rather than as a
    // downstream credits-page rendering artifact, attribution-
    // scraper miss, or screen-reader announcement break.
    // Current helper returns the literal `["Benjamin Porter"]`
    // (no `\x0B` byte), so this test passes today and serves as
    // a forcing function so any future override of the helper —
    // or any future contributor addition — stays free of
    // vertical-tab bytes. Continues the developers-array C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet so each
    // entry's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x0B'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` and rejects boundary whitespace via `char::is_whitespace()` — boundary-only, not mid-string), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` (which name `\\0`, `\\t`, and `\\r` specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three currently-empty `AdwAboutDialog` credits-section
    // array helpers
    // (`format_app_about_dialog_designers`,
    // `format_app_about_dialog_artists`,
    // `format_app_about_dialog_documenters`) and pinning each
    // entry as free of the vertical-tab byte `\x0B` (0x0B).
    // Mirror of the just-added
    // `_developers_entries_do_not_contain_a_vertical_tab_byte`
    // sibling on the populated-developers side and of the
    // `_empty_credits_section_entries_do_not_contain_a_null_byte`
    // / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte`
    // / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte`
    // siblings on the prior C0 control-byte cycle, structured as
    // a single cross-helper loop matching those existing
    // companions.
    //
    // The vertical-tab byte sits one step above HT (0x09) and
    // one step below CR (0x0D) in the ASCII C0 block; like its
    // siblings it is a non-printable control byte with no
    // legitimate use inside a human-readable GNOME credits-page
    // contributor-name entry.
    //
    // The three helpers currently return the empty array `[]`
    // because Paladin does not yet have a separately-credited
    // designer / artist / documenter for the v0.2 release. The
    // empty-array return trivially contains no entries (let
    // alone `\x0B`-bearing entries), so this test passes today
    // as the loop body is never entered. However, once any of
    // the three credits sections gains a contributor, the helper
    // return type will switch from `[&'static str; 0]` to
    // `[&'static str; N]` with non-empty entries — at that point
    // a `\x0B` injection from a legacy CONTRIBUTORS file authored
    // on a line-printer terminal that used `\x0B` as a vertical-
    // spacing separator, a `concat!(_, "\x0B", _)` form, a hand-
    // edited helper that pasted from an EBCDIC-to-ASCII
    // translation preserving the original VT byte, or a tooling
    // export pipeline that preserved VT-separated column values
    // inside a single-name entry would slip past every other
    // companion the way the
    // `_developers_entries_do_not_contain_a_vertical_tab_byte`
    // sibling already documents for the developers helper.
    //
    // Vertical-tab bytes in the credits-section entries would
    // mis-render in multiple downstream surfaces, identically to
    // the `set_developers` analysis in the
    // `_developers_entries_do_not_contain_a_vertical_tab_byte`
    // companion: (1) the GLib-backed `set_designers` /
    // `set_artists` / `set_documenters` setters route through
    // GTK and Pango renders each entry as a credits-page row —
    // a stray `\x0B` byte in the middle of a contributor name
    // would render as a literal control glyph (a hollow box or
    // tofu-like placeholder), visually breaking the credits-
    // page contributor-name layout; (2) any tooling that scrapes
    // the credits-page contributor list (GNOME `gnome-software`
    // credit aggregators) would propagate the stray `\x0B` byte
    // into the consumer's stream and trigger the same rendering
    // bug across every downstream surface; (3) screen readers
    // that announce the credits-page contributor names read the
    // `\x0B` as a literal control character, breaking the
    // contributor-name accessibility-tree announcement at the
    // byte boundary.
    //
    // Pinning the no-`\x0B` invariant across all three currently-
    // empty credits-section helpers in a single cross-helper
    // loop surfaces the regression with a message naming the
    // affected helper, the offending byte, and the entry index
    // at build time rather than as a downstream rendering
    // artifact of the credits-page sections. Current helpers
    // return the empty array `[]` (zero entries, no `\x0B` byte
    // to find), so this test passes today and serves as a
    // forcing function so any future override of the helpers —
    // including the eventual landing of separately-credited
    // designer / artist / documenter strings — stays free of
    // vertical-tab bytes. Continues the empty-credits-section C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return}` entry-triplet so each
    // entry's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_artists, format_app_about_dialog_designers,
        format_app_about_dialog_documenters,
    };

    let designers = format_app_about_dialog_designers();
    let artists = format_app_about_dialog_artists();
    let documenters = format_app_about_dialog_documenters();

    let sections: [(&str, &[&str]); 3] = [
        ("designers", &designers),
        ("artists", &artists),
        ("documenters", &documenters),
    ];

    for (label, entries) in sections {
        for (idx, entry) in entries.iter().enumerate() {
            assert!(
                !entry.contains('\x0B'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the
    // release_notes_version byte-cleanliness contract past the
    // just-completed `{null / horizontal-tab / carriage-return}`
    // triplet to the next C0 control byte. The vertical-tab byte
    // `\x0B` (0x0B) sits one step above HT (0x09) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte with no legitimate use
    // inside a semver-shaped version string.
    //
    // The two existing `_matches_about_dialog_version` and
    // `_matches_cargo_pkg_version` cross-source pins transitively
    // guarantee `release_notes_version` shares its bytes with
    // the `version` helper (which in turn equals
    // `CARGO_PKG_VERSION`). The `version` helper is byte-pinned
    // by `_version_has_no_embedded_whitespace` (a
    // `char::is_whitespace()` check that catches `\x0B` under
    // Rust's Unicode definition, since U+000B VT is whitespace),
    // so a `\x0B` byte in the active `release_notes_version`
    // value is currently protected *transitively* — through
    // equality with `version`, which is itself directly pinned
    // against embedded whitespace.
    //
    // But the transitive protection is brittle: a future refactor
    // that decoupled the two helpers (a separate override
    // constant for the "What's New" scope, a workspace-vendoring
    // split that lifted `release_notes_version` out of the
    // equality chain, or a CHANGELOG.md-derived release-notes
    // version that intentionally lagged the binary version on a
    // hotfix cut) would silently drop the `\x0B` guard the
    // moment the `_matches_*` companions started skipping cases.
    // The `_does_not_contain_a_null_byte` /
    // `_does_not_contain_a_horizontal_tab_byte` /
    // `_does_not_contain_a_carriage_return_byte` siblings each
    // name a different byte specifically. None of the existing
    // companions name the `\x0B` byte directly on this helper.
    //
    // A regression that landed `"0.0.1\x0B"` or
    // `"0\x0B.0\x0B.1"` (a vertical-tab byte lifted from a
    // legacy CHANGELOG file authored on a line-printer terminal
    // that used `\x0B` as a column separator, a `concat!(_,
    // "\x0B", _)` form, or a hand-edited helper override that
    // lifted the version string from an EBCDIC-to-ASCII
    // translation preserving the original VT byte) would mis-
    // render in multiple downstream surfaces, identically to the
    // analysis on the `version` helper: (1) the GLib-backed
    // `AdwAboutDialog::set_release_notes_version` setter routes
    // the value into Pango for inline rendering as the "What's
    // New in v<release_notes_version>" header — Pango's default
    // rendering of a bare `\x0B` byte is implementation-defined
    // and typically renders as a literal control glyph (a hollow
    // box or tofu-like placeholder), breaking the tidy section-
    // header layout; (2) the value scopes the "What's New" body
    // region inside the dialog — a mismatched / mis-rendered
    // scope key could prevent the body from rendering at all on
    // libadwaita versions that strip whitespace when computing
    // the body-region lookup key; (3) screen readers that
    // announce the "What's New" section header read the `\x0B`
    // as a literal control character, breaking the section-
    // header accessibility-tree announcement at the byte
    // boundary.
    //
    // Pinning the no-`\x0B` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // decoupling that silently dropped the transitive `version`
    // guard. Current helper returns the value sourced from
    // `CARGO_PKG_VERSION` (no `\x0B` byte), so this test passes
    // today and serves as a forcing function so any future
    // decoupling override of the helper — including the
    // eventual landing of a separately-scoped release-notes
    // version derived from CHANGELOG.md headings — stays free of
    // vertical-tab bytes. Continues the release-notes-version C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet so the helper's
    // byte-composition contract pins each forbidden control byte
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x0B'),
        "AdwAboutDialog release_notes_version must not contain the `\\x0B` vertical-tab byte (0x0B); the current value's `\\x0B`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version` and the `version` helper's `_has_no_embedded_whitespace` check (which uses `char::is_whitespace()` and catches U+000B VT), so a future decoupling override would silently drop the `\\x0B` guard; a stray `\\x0B` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that strip whitespace when computing the body-region lookup key, and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth mirror of the just-added
    // `_release_notes_version_does_not_contain_a_vertical_tab_byte`
    // companion on the release-notes-body side, extending the
    // release_notes byte-cleanliness contract past the just-
    // completed `{null / horizontal-tab / carriage-return}`
    // triplet to the next C0 control byte. The vertical-tab byte
    // `\x0B` (0x0B) sits one step above HT (0x09) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte with no legitimate use
    // inside a Pango-markup release-notes body.
    //
    // The libadwaita release-notes convention permits embedded
    // `\n` line breaks between Pango markup elements (`<li>`
    // entries inside the wrapping `<ul>`, paragraph breaks,
    // etc.), so the helper is one of only three about-dialog
    // helpers (alongside `format_app_about_dialog_debug_info`
    // and `format_app_about_dialog_translator_credits`) where
    // embedded line breaks are legitimately expected. That makes
    // `\x0B` (0x0B VERTICAL TAB) a distinct regression surface:
    // it is NOT covered by `_has_no_surrounding_whitespace_when_non_empty`
    // (`\x0B` mid-string is non-surrounding), it is NOT covered
    // by `_starts_and_ends_with_a_markup_element_when_non_empty`
    // (the opening `<` and closing `>` markup boundaries are
    // independent of mid-body `\x0B` bytes), it slips past
    // `_does_not_contain_a_null_byte` (`\x0B` is not `\0`), it
    // slips past `_does_not_contain_a_horizontal_tab_byte`
    // (`\x0B` is not `\t`), and it slips past
    // `_does_not_contain_a_carriage_return_byte` (`\x0B` is not
    // `\r`). None of the existing companions name the `\x0B`
    // byte directly on this helper.
    //
    // A regression that landed
    // `"<ul>\n\x0B<li>foo</li>\n\x0B<li>bar</li>\n</ul>"`
    // (vertical-tab-indented pretty-printed Pango markup lifted
    // from a legacy pre-formatter that used `\x0B` as a "soft
    // indent" character on line-printer terminals, a `concat!(_,
    // "\x0B", _)` form mirroring a CHANGELOG.md VT-indented
    // bullet block, or a hand-edited helper that pasted from an
    // EBCDIC-to-ASCII translation preserving the original VT
    // byte) would mis-render in multiple downstream surfaces:
    // (1) Pango's markup parser permits ASCII whitespace between
    // elements but renders `\x0B` as a literal control glyph (a
    // hollow box or tofu-like placeholder) since `\x0B` is
    // technically whitespace but has no tab-stop semantics; in
    // the about-dialog "What's New" body this would surface as
    // visible boxes or placeholder glyphs between the wrapping
    // `<ul>` and each `<li>` bullet element; (2) any in-app
    // changelog display that reuses the release-notes string
    // outside the dialog (release-tracker bots, copy-to-
    // clipboard handlers) would propagate the stray `\x0B` into
    // the consumer's stream and trigger the same rendering bug
    // across every downstream surface; (3) screen readers that
    // announce the release-notes content read the `\x0B` as a
    // literal control character, breaking the accessibility-tree
    // announcement at every bullet-boundary indent.
    //
    // Mirror of the just-added
    // `_developer_name_does_not_contain_a_vertical_tab_byte`,
    // `_copyright_does_not_contain_a_vertical_tab_byte`,
    // `_comments_does_not_contain_a_vertical_tab_byte`,
    // `_developers_entries_do_not_contain_a_vertical_tab_byte`,
    // `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte`,
    // and `_release_notes_version_does_not_contain_a_vertical_tab_byte`
    // siblings; together they extend the about-dialog byte-
    // composition contract from the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the
    // vertical-tab regression surface as well.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream "What's New" body
    // rendering bug, a stray `\x0B` byte in an external
    // changelog reuse, or a screen-reader announcement break.
    // Current helper returns the empty literal `""` (no `\x0B`
    // byte), so this test passes today and serves as a forcing
    // function so any future override of the helper — including
    // the eventual landing of an actual v0.2 release-notes Pango
    // markup body sourced from CHANGELOG.md — stays free of
    // vertical tabs even when embedded `\n` line breaks are
    // intentionally present.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\x0B'),
        "AdwAboutDialog release_notes must not contain the `\\x0B` vertical-tab byte (0x0B); the Pango markup parser permits ASCII whitespace between elements but renders `\\x0B` as a literal control glyph (a hollow box or tofu-like placeholder) since `\\x0B` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics, so a stray `\\x0B` between the wrapping `<ul>` and each `<li>` bullet would surface as visible boxes in the dialog's What's New body, propagate the same rendering bug into any external changelog reuse, and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth mirror of the just-added
    // `_release_notes_does_not_contain_a_vertical_tab_byte`
    // companion on the translator-credits side, extending the
    // translator_credits byte-cleanliness contract past the
    // just-completed `{null / horizontal-tab / carriage-return}`
    // triplet to the next C0 control byte. The vertical-tab byte
    // `\x0B` (0x0B) sits one step above HT (0x09) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte with no legitimate use
    // inside a libadwaita-convention translator-credits string.
    //
    // The libadwaita translator-credits convention permits
    // embedded `\n` line breaks between translator entries (the
    // `_is_single_line_when_non_empty` companion only asserts
    // the empty-string case, so it does not gate embedded
    // newlines once a translation lands), so the helper is one
    // of only three about-dialog helpers (alongside
    // `format_app_about_dialog_debug_info` and
    // `format_app_about_dialog_release_notes`) where embedded
    // line breaks are legitimately expected. That makes `\x0B`
    // (0x0B VERTICAL TAB) a distinct regression surface: it is
    // NOT covered by `_has_no_surrounding_whitespace_when_non_empty`
    // (`\x0B` mid-string is non-surrounding), it is NOT covered
    // by any per-entry single-line check (the helper itself is
    // explicitly multi-line per libadwaita convention), it
    // slips past `_does_not_contain_a_null_byte` (`\x0B` is not
    // `\0`), it slips past `_does_not_contain_a_horizontal_tab_byte`
    // (`\x0B` is not `\t`), and it slips past
    // `_does_not_contain_a_carriage_return_byte` (`\x0B` is not
    // `\r`). None of the existing companions name the `\x0B`
    // byte directly on this helper.
    //
    // A regression that landed
    // `"name1\x0B<email1>\nname2\x0B<email2>"` (vertical-tab-
    // separated `<name>\x0B<email>` rows lifted from a legacy
    // contributors export pipeline that used `\x0B` as a column
    // separator on line-printer terminals, an `xgettext` export
    // that preserved VT-aligned column values, a `concat!(_,
    // "\x0B", _)` form mirroring a VT-aligned attribution block,
    // or a hand-edited helper that pasted from an EBCDIC-to-
    // ASCII translation preserving the original VT byte) would
    // mis-render in multiple downstream surfaces: (1) libadwaita's
    // credits-page parser splits the translator-credits string
    // on `\n` (LF) per the documented convention, leaving the
    // embedded `\x0B` bytes inside each parsed entry untouched;
    // the GLib-backed Pango render path treats `\x0B` as a
    // literal control glyph (a hollow box or tofu-like
    // placeholder) since `\x0B` is technically whitespace under
    // `char::is_whitespace()` but has no tab-stop semantics,
    // breaking the tidy two-column `<name> <email>` attribution
    // layout; (2) any localization tooling that round-trips the
    // translator-credits string back through `xgettext` would
    // either silently dedupe the `\x0B` to a single space (data
    // loss) or preserve the `\x0B` and propagate the same
    // rendering bug across every downstream consumer of the .po
    // / .mo file; (3) screen readers that announce the credits-
    // page contents read the `\x0B` as a literal control
    // character, breaking the accessibility-tree announcement
    // at every attribution-row column boundary.
    //
    // Mirror of the just-added
    // `_developer_name_does_not_contain_a_vertical_tab_byte`,
    // `_copyright_does_not_contain_a_vertical_tab_byte`,
    // `_comments_does_not_contain_a_vertical_tab_byte`,
    // `_developers_entries_do_not_contain_a_vertical_tab_byte`,
    // `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte`,
    // `_release_notes_version_does_not_contain_a_vertical_tab_byte`,
    // and `_release_notes_does_not_contain_a_vertical_tab_byte`
    // siblings; together they extend the about-dialog byte-
    // composition contract from the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the
    // vertical-tab regression surface as well.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream credits-page
    // rendering bug, a stray `\x0B` byte in the .po round trip,
    // or a screen-reader announcement break. Current helper
    // returns the empty literal `""` (no `\x0B` byte), so this
    // test passes today and serves as a forcing function so any
    // future override of the helper — including the eventual
    // landing of an actual translator-credits string — stays
    // free of vertical tabs even when embedded `\n` line breaks
    // are intentionally present.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x0B'),
        "AdwAboutDialog translator_credits must not contain the `\\x0B` vertical-tab byte (0x0B); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x0B` bytes inside each parsed entry untouched, and `\\x0B` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics so Pango renders it as a literal control glyph; a stray `\\x0B` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips as either silent dedupe to a single space or `\\x0B` preservation, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the debug_info
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the next C0
    // control byte. The vertical-tab byte `\x0B` (0x0B) sits one
    // step above HT (0x09) and one step below CR (0x0D) in the
    // ASCII C0 block; like its siblings it is a non-printable
    // control byte with no legitimate use inside a Troubleshooting
    // → Debugging Information payload.
    //
    // The existing `_carries_program_name_version_and_app_id`
    // (content-shape pin),
    // `_is_non_empty_text_with_no_trailing_whitespace` (non-empty
    // + no-trailing-whitespace pin; note that
    // `char::is_whitespace()` matches U+000B VT, so a *trailing*
    // `\x0B` is rejected by this companion — but a mid-payload
    // `\x0B` is non-trailing and slips past),
    // `_starts_with_program_name` (leading-substring pin),
    // `_app_id_appears_on_a_distinct_line_from_program_name`
    // (multi-line pin), `_has_exactly_two_lines` (line-count
    // pin), `_program_name_line_ends_with_the_version` (line-1
    // trailing-substring pin),
    // `_app_id_line_ends_with_the_reverse_dns_app_id` (line-2
    // trailing-substring pin), `_is_ascii_only` (byte-composition
    // pin), `_does_not_contain_a_null_byte` (null-byte pin),
    // `_does_not_contain_a_horizontal_tab_byte` (HT pin), and
    // `_does_not_contain_a_carriage_return_byte` (CR pin) catch
    // the wrong-shape / wrong-content / empty / multi-line-count
    // / wrong-trailing-substring / non-ASCII / `\0`-byte / `\t`-
    // byte / `\r`-byte regressions but a mid-payload `\x0B`
    // (`"Paladin\x0B0.0.1\nApp ID: org.tamx.Paladin.Gui"`)
    // slips past `_is_ascii_only` (since `\x0B` is ASCII), past
    // the per-byte siblings (which each name a different byte),
    // past the line-count and trailing-substring companions
    // (which split on `\n` and check only trailing substrings),
    // and past the `_is_non_empty_text_with_no_trailing_whitespace`
    // companion's boundary-only `\x0B` rejection.
    //
    // A regression that landed `\x0B` in the payload would mis-
    // render the debug-info content in three ways: (1) the GLib-
    // backed `AdwAboutDialog::set_debug_info` setter routes the
    // value into Pango for rendering inside the dialog's
    // "Troubleshooting → Debugging Information" body — Pango's
    // default rendering of a bare `\x0B` byte is implementation-
    // defined and typically renders as a literal control glyph
    // (a hollow box or tofu-like placeholder) since `\x0B` has
    // no tab-stop semantics, breaking the tidy single-column
    // layout expected by the AdwAboutDialog template; (2) when
    // the user pastes the payload into a bug-report form on
    // GitHub, the `\x0B` byte renders inconsistently across
    // browsers and font stacks (some show a hollow box, some
    // show a vertical-spacing artifact, some silently drop the
    // byte), cluttering the maintainer's view of the report
    // and degrading bug-report quality; (3) when the user saves
    // the payload to a `.txt` file via the
    // `AdwAboutDialog::set_debug_info_filename` slot, the GTK
    // file-writer writes the raw bytes so the resulting file
    // contains a stray VT byte that breaks POSIX text-processing
    // tools (`grep`, `awk`, `cut`) whose default field-
    // delimiter behaviour does not recognize `\x0B` as a
    // delimiter but also does not treat it as part of the field
    // payload.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces
    // the regression with a message naming the offending byte
    // at build time rather than as a downstream dialog rendering
    // bug, a pasted-bug-report cross-browser drift artifact, or
    // a saved-file POSIX-text-processing breakage. The current
    // `format_app_about_dialog_debug_info` returns `"Paladin
    // 0.0.1\nApp ID: org.tamx.Paladin.Gui"` (built at compile
    // time via `concat!` with single-space separators between
    // every column), so this test passes today and serves as a
    // forcing function so any future override of the debug-info
    // helper — including the eventual landing of additional
    // diagnostic fields (locale, Wayland vs X11 session type,
    // Flatpak vs native) — stays free of vertical-tab bytes.
    // Continues the debug-info C0 control-byte cycle past the
    // just-completed `{null / horizontal-tab / carriage-return}`
    // triplet so the helper's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\x0B'),
        "AdwAboutDialog debug_info must not contain the `\\x0B` vertical-tab byte (0x0B); a `\\x0B` byte slips past `_is_ascii_only` (since `\\x0B` is ASCII), past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and past `_is_non_empty_text_with_no_trailing_whitespace` (which rejects boundary `\\x0B` via `char::is_whitespace()` but not mid-payload occurrences), and would render as a literal control glyph in the Troubleshooting dialog body, drift across browsers and font stacks in pasted bug reports, and propagate a stray VT byte into POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename`; got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the
    // program-name byte coverage past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the next C0
    // control byte. The vertical-tab byte `\x0B` (0x0B) sits one
    // step above HT (0x09) and one step below CR (0x0D) in the
    // ASCII C0 block; like its siblings it is a non-printable
    // control byte with no legitimate use inside a GNOME
    // application program-name string.
    //
    // The existing `_program_name_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000B VT — so the program-name helper's `\x0B`-
    // cleanliness is currently protected *transitively* by that
    // one specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a single embedded space in the
    // program-name slot (a localized program-name string like
    // `"Paladin Auth"`, a workspace-vendoring split that lifted
    // program-name out of the no-whitespace constraint, or a
    // libadwaita HIG update that explicitly permitted a single
    // space in the bold-header program-name row) would naturally
    // relax the `_has_no_embedded_whitespace` companion — and
    // the human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, tab) without separately calling out `\x0B`
    // on the assumption that "ASCII whitespace is now allowed".
    // That assumption is wrong: `\x0B` is a control byte without
    // tab-stop semantics, not a layout-friendly whitespace
    // character, and the program-name slot is rendered as a
    // single bold header row with no vertical-spacing semantics
    // — so dropping the `\x0B` check alongside the space-
    // relaxation would silently regress the no-`\x0B` invariant.
    //
    // None of the existing companions name the `\x0B` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0B` is
    //     ASCII so it slips past;
    //   - `_is_non_empty_and_not_app_id` only checks non-empty
    //     + distinct-from-app-id;
    //   - `_matches_format_app_window_title` only enforces
    //     equality with the window title (so any `\x0B`-bearing
    //     override would slip past as long as the window title
    //     helper had matching bytes);
    //   - `_is_segment_of_application_icon_name` only checks
    //     segment containment;
    //   - `_does_not_end_with_a_period` only constrains the
    //     suffix;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"Pala\x0Bdin"` (vertical-tab
    // byte lifted from a legacy program-name registry authored
    // on a line-printer terminal that used `\x0B` as a vertical-
    // spacing separator inside a single-token name, a `concat!(_,
    // "\x0B", _)` form, or a hand-edited helper override that
    // lifted the program name from an EBCDIC-to-ASCII translation
    // preserving the original VT byte) would mis-render in three
    // downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_application_name` setter routes the
    // value into Pango for inline rendering as the bold program-
    // name row at the dialog header — Pango's default rendering
    // of a bare `\x0B` byte is implementation-defined and
    // typically renders as a literal control glyph (a hollow box
    // or tofu-like placeholder), breaking the tidy bold-header
    // layout; (2) the matching `gtk::Window::set_title` setter
    // (the program name is mirrored to the window title per
    // `_matches_format_app_window_title`) renders the `\x0B` in
    // the window manager's taskbar / dock display label,
    // surfacing the control byte to every shell that lists open
    // windows; (3) the GTK accessibility tree's `accessible-name`
    // property routes through the same Pango layer, breaking
    // screen-reader announcements of the application name at the
    // byte boundary.
    //
    // Pinning the no-`\x0B` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped the
    // `\x0B` guard. Current helper returns the literal `"Paladin"`
    // (no `\x0B` byte), so this test passes today and serves as
    // a forcing function so any future override of the helper —
    // including the eventual landing of a localized multi-word
    // program name — stays free of vertical tabs. Continues the
    // program-name C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return}` triplet so the
    // helper's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x0B'),
        "AdwAboutDialog program_name must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\x0B` guard alongside the space relaxation; a stray `\\x0B` would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the version-
    // helper byte coverage past the just-completed `{null /
    // horizontal-tab / carriage-return}` triplet to the next C0
    // control byte. The vertical-tab byte `\x0B` (0x0B) sits one
    // step above HT (0x09) and one step below CR (0x0D) in the
    // ASCII C0 block; like its siblings it is a non-printable
    // control byte with no legitimate use inside a semver-shaped
    // version string.
    //
    // The existing `_version_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000B VT — so the version helper's `\x0B`-cleanliness
    // is currently protected *transitively* by that one specific
    // companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a version-suffix separator space
    // (e.g. `"0.0.1 pre-release"` or `"0.0.1 +build"`) would
    // naturally relax the `_has_no_embedded_whitespace` companion
    // — and the human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, tab) without separately calling out `\x0B`
    // on the assumption that "ASCII whitespace is now allowed".
    // That assumption is wrong: `\x0B` is a control byte without
    // tab-stop semantics, not a layout-friendly whitespace
    // character, and the version slot is rendered as a single-
    // line caption beneath the program name in the dialog header
    // that has no vertical-spacing semantics — so dropping the
    // `\x0B` check alongside the space-relaxation would silently
    // regress the no-`\x0B` invariant.
    //
    // None of the existing companions name the `\x0B` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0B` is
    //     ASCII so it slips past;
    //   - `_is_non_empty_and_looks_like_semver` only enforces
    //     non-empty + semver shape;
    //   - `_starts_with_a_digit` / `_does_not_start_with_a_dot` /
    //     `_does_not_end_with_a_dot` only constrain the boundary
    //     bytes;
    //   - `_has_at_least_three_dot_separated_segments` /
    //     `_segments_are_non_empty` only check segment count and
    //     non-emptiness;
    //   - `_matches_cargo_pkg_version` only enforces equality
    //     with `CARGO_PKG_VERSION` (so any `\x0B`-bearing override
    //     would slip past as long as Cargo's pinned version had
    //     matching bytes);
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"0.0.1\x0B"` (vertical-tab byte
    // lifted from a legacy Cargo.toml-derived version registry
    // authored on a line-printer terminal that used `\x0B` as a
    // column separator between version and build-metadata
    // suffix, a `concat!(_, "\x0B", _)` form, or a hand-edited
    // helper override that lifted the version literal from an
    // EBCDIC-to-ASCII translation preserving the original VT
    // byte) would mis-render in multiple downstream surfaces:
    // (1) the GLib-backed `AdwAboutDialog::set_version` setter
    // routes the value into Pango for inline rendering as the
    // version caption beneath the program name — Pango's default
    // rendering of a bare `\x0B` byte is implementation-defined
    // and typically renders as a literal control glyph (a hollow
    // box or tofu-like placeholder), breaking the tidy version-
    // caption layout; (2) the same version string is reused by
    // `_release_notes_version_matches_about_dialog_version` for
    // the "What's New in v<version>" header — a `\x0B` byte in
    // the version would propagate into the release-notes header
    // and mis-render there too; (3) any downstream tooling that
    // scrapes the version slot (release-tracker bots, update-
    // check pings, crash-report assemblers) would propagate the
    // stray `\x0B` byte and trigger the same rendering bug
    // across every downstream surface; (4) screen readers that
    // announce the version caption read the `\x0B` as a literal
    // control character, breaking the version-caption
    // accessibility-tree announcement at the byte boundary.
    //
    // Pinning the no-`\x0B` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped the
    // `\x0B` guard. Current helper returns the value sourced from
    // `CARGO_PKG_VERSION` (no `\x0B` byte), so this test passes
    // today and serves as a forcing function so any future
    // override of the helper — including the eventual landing of
    // a build-metadata-suffixed version string — stays free of
    // vertical tabs. Continues the version C0 control-byte cycle
    // past the just-completed `{null / horizontal-tab /
    // carriage-return}` triplet so the helper's byte-composition
    // contract pins each forbidden control byte against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x0B'),
        "AdwAboutDialog version must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\x0B` guard alongside the space relaxation; a stray `\\x0B` would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the
    // application-icon-name byte coverage past the just-
    // completed `{null / horizontal-tab / carriage-return}`
    // triplet to the next C0 control byte. The vertical-tab byte
    // `\x0B` (0x0B) sits one step above HT (0x09) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte with no legitimate use
    // inside a freedesktop.org reverse-DNS icon-name string.
    //
    // The existing `_application_icon_name_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000B VT — so the application-icon-name helper's
    // `\x0B`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a localized icon-name with a single
    // embedded space (a non-trivial scenario per freedesktop.org
    // icon-naming convention, which forbids spaces in icon names
    // — but a workspace-vendoring refactor or a CI codegen step
    // could relax the `_has_no_embedded_whitespace` companion
    // incorrectly) would naturally drop the `\x0B` check at the
    // same time on the assumption that "ASCII whitespace is now
    // allowed". That assumption is wrong: `\x0B` is a control
    // byte without tab-stop semantics, not a layout-friendly
    // whitespace character, and a `gtk::IconTheme::lookup_by_gicon`
    // call with a `\x0B`-bearing icon name lands in undefined
    // territory across GIO icon-loader implementations.
    //
    // None of the existing companions name the `\x0B` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0B` is
    //     ASCII so it slips past;
    //   - `_is_reverse_dns` / `_has_exactly_four_segments` /
    //     `_starts_with_a_lowercase_ascii_letter` only constrain
    //     segment-count and leading byte;
    //   - `_ends_with_gui_segment` / `_does_not_end_with_a_dot`
    //     / `_does_not_start_with_a_dot` only constrain the
    //     suffix and dot-boundaries;
    //   - `_segments_are_non_empty` only checks segment non-
    //     emptiness;
    //   - `_matches_app_id` / `_program_name_is_segment_of_application_icon_name`
    //     only enforce equality with the app-id and segment
    //     containment with the program name;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"org.tamx.Paladin\x0B.Gui"`
    // (vertical-tab byte lifted from a legacy freedesktop.org
    // icon-spec registry authored on a line-printer terminal
    // that used `\x0B` as a column separator between reverse-DNS
    // segments, a `concat!(_, "\x0B", _)` form mirroring a
    // mainframe-era icon-name format, or a hand-edited helper
    // override that lifted the icon name from an EBCDIC-to-
    // ASCII translation preserving the original VT byte) would
    // mis-render in multiple downstream surfaces: (1) the
    // `gtk::IconTheme` lookup machinery treats the icon name as
    // a key into the icon cache — a `\x0B`-bearing key would
    // silently miss the cache and fall through to the placeholder
    // fallback icon, masking the bug as a missing-icon surface
    // rather than a malformed-icon-name surface; (2) the matching
    // `gtk::Window::set_icon_name` setter (the icon name is
    // mirrored onto the toplevel window's icon property) routes
    // through GLib's GVariant string-marshalling layer and may
    // surface as a malformed window-icon-name property in the
    // X11 / Wayland protocol exchange, where some compositors
    // silently drop the icon and others render a broken-icon
    // placeholder; (3) the same icon name is mirrored to the
    // AppStream metainfo file's `<id>` field per the §11.4
    // app-id convention — a `\x0B`-bearing icon name would
    // propagate into the metainfo file and fail Flathub's
    // strict reverse-DNS-validating metainfo linter on the next
    // package submission.
    //
    // Pinning the no-`\x0B` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a downstream
    // icon-cache miss, a malformed-window-icon protocol
    // exchange, or a Flathub metainfo linter failure. Current
    // helper returns the literal `"org.tamx.Paladin.Gui"` (no
    // `\x0B` byte), so this test passes today and serves as a
    // forcing function so any future override of the helper —
    // including the eventual landing of a Flatpak app-id rename
    // — stays free of vertical tabs. Continues the application-
    // icon-name C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return}` triplet so
    // the helper's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x0B'),
        "AdwAboutDialog application_icon_name must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\x0B` guard; a stray `\\x0B` would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, and propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_vertical_tab_byte() {
    // Defense-in-depth per-byte sibling extending the debug-
    // info-filename byte coverage past the just-completed
    // `{null / horizontal-tab / carriage-return}` triplet to
    // the next C0 control byte. The vertical-tab byte `\x0B`
    // (0x0B) sits one step above HT (0x09) and one step below
    // CR (0x0D) in the ASCII C0 block; like its siblings it is
    // a non-printable control byte with no legitimate use
    // inside a filesystem filename string.
    //
    // The existing `_debug_info_filename_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000B VT — so the debug-info-filename helper's
    // `\x0B`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a localized filename with a single
    // embedded space (a non-trivial scenario per freedesktop.org
    // file-naming convention but feasible if a localized "Debug
    // information.txt" filename were ever rendered to non-ASCII
    // locales) would naturally relax the
    // `_has_no_embedded_whitespace` companion — and the human
    // author of that refactor might reasonably restructure the
    // check to only reject specific control bytes (newline, tab)
    // without separately calling out `\x0B` on the assumption
    // that "ASCII whitespace is now allowed". That assumption is
    // wrong: `\x0B` is a control byte without tab-stop semantics,
    // not a layout-friendly whitespace character, and a save-
    // to-disk filename with `\x0B` lands in undefined territory
    // across POSIX filesystem implementations (most kernel ports
    // of `open(2)` accept VT in filenames but shell-tooling
    // pipelines and bug-tracker attachment URL renderers treat
    // the byte as either an un-printable control glyph or a
    // dropped byte).
    //
    // None of the existing companions name the `\x0B` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0B` is
    //     ASCII so it slips past;
    //   - `_returns_paladin_debug_info_txt` exact-value pin only
    //     holds while the literal is unchanged;
    //   - `_does_not_contain_path_separators` /
    //     `_does_not_start_with_a_dot` only constrain the path-
    //     safety and leading-byte boundaries;
    //   - `_contains_exactly_one_period` /
    //     `_extension_is_lowercase_txt` only check dot-count and
    //     suffix;
    //   - `_is_non_empty_single_line_with_txt_extension` only
    //     checks non-empty + single-line + `.txt` suffix shape
    //     (the single-line check uses `str::lines().count() == 1`
    //     which does not split on `\x0B`, so a `\x0B`-bearing
    //     filename like `"pala\x0Bdin-debug-info.txt"` slips
    //     past this companion entirely);
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` each name
    //     a different byte specifically.
    //
    // A regression that landed `"pala\x0Bdin-debug-info.txt"`
    // (vertical-tab byte lifted from a legacy filename registry
    // authored on a line-printer terminal that used `\x0B` as a
    // column separator inside a single-token filename, a
    // `concat!(_, "\x0B", _)` form, or a hand-edited helper
    // override that lifted the filename literal from an EBCDIC-
    // to-ASCII translation preserving the original VT byte)
    // would mis-render in three downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_debug_info_filename`
    // setter routes the value into the dialog's "Save Debug
    // Information…" file-chooser pre-fill — a `\x0B`-bearing
    // filename mis-renders in the GtkFileDialog's filename
    // entry as a literal control glyph (a hollow box or tofu-
    // like placeholder) since `\x0B` has no tab-stop semantics,
    // and may also surface in the suggested-filename display in
    // the file chooser's title bar; (2) when the user saves the
    // debug-info payload to disk, the filesystem `open(2)` call
    // routes the `\x0B`-bearing filename through the kernel VFS
    // layer — most POSIX-conformant kernels (Linux, macOS, BSDs)
    // accept `\x0B` in filenames but many shell-tooling
    // pipelines (`ls`, `find`, `tar`) assume printable-only
    // filenames and either silently strip the `\x0B` or display
    // the file as an un-readable entry; (3) the saved file's
    // filename surfaces in any bug-tracker attachment URL or
    // chat-attachment column where the `\x0B` byte mis-renders
    // as a literal control glyph, confusing the maintainer's
    // triage workflow.
    //
    // Pinning the no-`\x0B` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a downstream
    // file-chooser mis-render, a shell-tooling visibility
    // break, or a chat-attachment column-render artifact.
    // Current helper returns the literal `"paladin-debug-info.txt"`
    // (no `\x0B` byte), so this test passes today and serves as
    // a forcing function so any future override of the helper —
    // including the eventual landing of a localized filename —
    // stays free of vertical tabs. Continues the debug-info-
    // filename C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return}` triplet so
    // the helper's byte-composition contract pins each forbidden
    // control byte against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x0B'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\x0B` guard alongside the space relaxation; a stray `\\x0B` would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, surface as an un-listable file under shell-tooling pipelines (`ls`, `find`, `tar`) that strip non-printable bytes, and confuse maintainer triage with control-glyph artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_vertical_tab_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `\x0B` vertical-tab byte (0x0B).
    // Closes the about-dialog vertical-tab cycle started by the
    // `_developer_name_does_not_contain_a_vertical_tab_byte`
    // sibling and continued across every byte-pinned helper,
    // completing the URL-helpers' byte-composition contract past
    // the just-finished `{null / horizontal-tab / carriage-
    // return}` cross-URL triplet.
    //
    // The existing `url_helpers_contain_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000B VT — so the URL-helpers' `\x0B`-cleanliness is
    // currently protected *transitively* by that one specific
    // companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a URL with a single percent-encoded
    // space (a non-trivial scenario per RFC 3986, which forbids
    // unencoded spaces in URLs but permits `%20` percent-encoding
    // for them — but a workspace-vendoring refactor or a CI
    // codegen step could relax the
    // `_contain_no_embedded_whitespace` companion incorrectly
    // when handling decoded percent-encoded strings) would
    // naturally drop the `\x0B` check at the same time on the
    // assumption that "ASCII whitespace is now allowed". That
    // assumption is wrong: `\x0B` is never a valid byte inside a
    // URL per RFC 3986 (the vertical-tab byte is not in any of
    // the URL grammar's production rules), so dropping the
    // `\x0B` check alongside the percent-encoded-space
    // relaxation would silently regress the no-`\x0B` invariant.
    //
    // A regression would slip past every existing companion: the
    // `_is_non_empty_https_url[_distinct_*]` per-URL companion
    // (which only checks non-empty + `https://` prefix + no
    // space byte — a `\x0B` byte mid-URL satisfies all three
    // since `\x0B` is not the literal U+0020 SPACE), the
    // `_are_ascii_only` cross-URL companion (`\x0B` is ASCII so
    // it slips past), the `_do_not_end_with_a_trailing_slash`
    // companion (which only constrains the final byte), the
    // `_do_not_contain_a_null_byte` /
    // `_do_not_contain_a_horizontal_tab_byte` /
    // `_do_not_contain_a_carriage_return_byte` siblings (which
    // each name a different byte specifically), the
    // `_do_not_contain_a_query_string` /
    // `_do_not_contain_a_fragment_anchor` /
    // `_do_not_contain_a_userinfo_at_sign` /
    // `_do_not_contain_a_backslash` siblings (which each name a
    // different byte specifically). None of the existing
    // companions name the `\x0B` byte directly.
    //
    // A regression that landed
    // `"https://github.com\x0BFreedomBen/paladin"` (vertical-tab
    // byte lifted from a legacy URL registry authored on a line-
    // printer terminal that used `\x0B` as a column separator
    // between the host and path, a `concat!(_, "\x0B", _)` form
    // mirroring a VT-separated URL-table cell, or a hand-edited
    // helper override that lifted the URL from an EBCDIC-to-
    // ASCII translation preserving the original VT byte) would
    // mis-render in multiple downstream surfaces: (1) the GLib-
    // backed `AdwAboutDialog::set_website` / `set_issue_url` /
    // `set_support_url` setters route the value into Pango for
    // inline rendering as the underlined link label in the
    // dialog footer — Pango's default rendering of a bare
    // `\x0B` byte is implementation-defined and typically
    // renders as a literal control glyph (a hollow box or tofu-
    // like placeholder) since `\x0B` has no tab-stop semantics,
    // breaking the trusted-application surface contract of the
    // link label; (2) when the user clicks the URL, GIO's
    // `gtk_show_uri_full` routes the value through the session's
    // `xdg-open` / portal layer where some URL parsers (WHATWG
    // URL §4.5 implementations) reject `\x0B` outright with
    // `InvalidUrl`, breaking the click-through routing entirely,
    // while others percent-encode the `\x0B` as `%0B` and route
    // to a non-existent URL with a `Bad Request` response
    // surfacing as a confusing browser-level error; (3) screen
    // readers that announce the URL label read the `\x0B` as a
    // literal control character, breaking the link-label
    // accessibility-tree announcement at the byte boundary; (4)
    // any downstream tooling that scrapes the URL labels (link-
    // checker bots, broken-link auditors) would propagate the
    // stray `\x0B` byte into the consumer's stream and trigger
    // the same routing failure across every downstream surface.
    //
    // Pinning the no-`\x0B` invariant directly here surfaces the
    // regression with a message naming the offending URL helper
    // at build time rather than as a downstream user-visible
    // mis-rendered link label, a confusing browser-level error
    // on click-through, an inconsistent URL-parser-implementation
    // routing surface, or a link-checker tooling failure. Mirror
    // of the `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_do_not_contain_a_fragment_anchor`,
    // `_url_helpers_do_not_contain_a_userinfo_at_sign`,
    // `_url_helpers_do_not_contain_a_backslash`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`,
    // `_url_helpers_do_not_contain_a_null_byte`,
    // `_url_helpers_do_not_contain_a_carriage_return_byte`, and
    // `_url_helpers_do_not_contain_a_horizontal_tab_byte` cross-
    // URL siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`, no
    // `\0`, no `\r`, no `\t`, no `\x0B`, no `?` query, no `#`
    // anchor, no `@` userinfo, no `\` path-confusion byte)
    // across all three footer link surfaces against a single
    // source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('\x0B'),
            "AdwAboutDialog {label} must not contain the `\\x0B` vertical-tab byte (0x0B) — `\\x0B` is never a valid byte inside a URL per RFC 3986 (the vertical-tab byte is not in any of the URL grammar's production rules); the current `\\x0B`-cleanliness is only protected transitively by `_url_helpers_contain_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future percent-encoded-space relaxation would silently drop the `\\x0B` guard; a stray `\\x0B` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%0B`-encoding implementations, break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling beginning the next C0
    // control-byte cycle for the developer-name helper after
    // the just-completed `{null / horizontal-tab / carriage-
    // return / vertical-tab}` quadruple. The form-feed byte
    // `\x0C` (0x0C) sits one step above VT (0x0B) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte that has no
    // legitimate use inside a human-readable GNOME dialog
    // attribution string.
    //
    // None of the existing developer-name companions name the
    // `\x0C` byte directly:
    //   - `_developer_name_is_a_single_line_without_embedded_newlines`
    //     only checks `\n` and `\r` — `\x0C` is neither;
    //   - `_developer_name_is_ascii_only` pins each byte as
    //     ASCII — `\x0C` is ASCII so it slips past;
    //   - `_developer_name_has_no_surrounding_whitespace`
    //     uses `char::is_whitespace()`, which under Rust's
    //     Unicode definition returns true for U+000C FF, so
    //     this companion *does* reject a leading or trailing
    //     `\x0C` — but a mid-string `\x0C` (`"The Pa\x0Cladin
    //     contributors"`) sits between the boundaries and
    //     slips past;
    //   - `_developer_name_starts_with_the_definite_article`
    //     and `_ends_with_the_contributors_collective_noun`
    //     only constrain the literal prefix `"The "` and
    //     suffix `"contributors"`, so a mid-string `\x0C`
    //     between them satisfies both;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte`
    //     each name a different byte specifically.
    //
    // The current `_returns_the_paladin_contributors` exact-
    // value pin catches every byte today, but its protection
    // collapses the moment a contributor-list addition or a
    // workspace-vendoring split decouples the helper from the
    // pinned literal — at that point a `\x0C`-bearing override
    // would slip past every byte-level companion above (since
    // `char::is_whitespace` only catches the boundary `\x0C`,
    // not a mid-string one).
    //
    // A regression that landed `"The Paladin\x0Ccontributors"`
    // (form-feed byte lifted from a legacy plain-text
    // CONTRIBUTORS file authored on a line-printer terminal
    // that used `\x0C` to advance to the next page between
    // sections of a printed contributors list, a
    // `concat!(_, "\x0C", _)` form, a `pandoc`-generated text
    // dump that preserved `\x0C` page-break markers, or a
    // hand-edited helper that pasted from a page-broken text
    // file) would mis-render in multiple downstream surfaces:
    // (1) the GLib-backed `AdwAboutDialog::set_developer_name`
    // setter hands the string to Pango for inline rendering
    // beneath the program name in the dialog header — Pango's
    // default rendering of a bare `\x0C` byte is implementation-
    // defined and typically renders as a literal control glyph
    // (a hollow box, a tofu-like placeholder, or an invisible
    // page-advance), breaking the tidy single-line attribution
    // layout; (2) the same developer-name string is reused by
    // `_copyright_ends_with_developer_name` to construct the
    // footer copyright row, so a `\x0C` byte in the developer
    // name would propagate into the copyright slot and mis-
    // render there too; (3) screen readers that announce the
    // dialog attribution read the `\x0C` as a literal control
    // character or — on some implementations — as a section-
    // break announcement, breaking the attribution
    // accessibility-tree announcement at the byte boundary;
    // (4) downstream tooling that scrapes the developer-name
    // attribution (release-note generators, contributor-
    // attribution crawlers) would propagate the stray `\x0C`
    // byte into the consumer's stream and trigger the same
    // rendering bug across every downstream surface, with the
    // additional risk that text-paginator pipelines treat the
    // `\x0C` as a hard page break and split the attribution
    // mid-string in printed reports.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces
    // the regression with a message naming the offending byte
    // at build time rather than as a downstream dialog-header
    // rendering bug or a screen-reader announcement break.
    // Current helper returns the literal `"The Paladin
    // contributors"` (no `\x0C` byte), so this test passes
    // today and serves as a forcing function so any future
    // override of the helper — including the eventual landing
    // of a multi-contributor attribution string — stays free
    // of form-feed bytes. Begins the developer-name C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}`
    // quadruple so the helper's byte-composition contract
    // pins each forbidden control byte against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x0C'),
        "AdwAboutDialog developer-name must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x0C` is ASCII), past `_has_no_surrounding_whitespace` (which only rejects `\\x0C` at the boundaries via `char::is_whitespace()`), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers — text-paginator pipelines would additionally treat the `\\x0C` as a hard page break and split the attribution mid-string in printed reports; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the copyright
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}`
    // quadruple to the next C0 control byte. The form-feed byte
    // `\x0C` (0x0C) sits one step above VT (0x0B) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte with no legitimate use
    // inside a human-readable GNOME dialog copyright string.
    //
    // None of the existing copyright companions name the `\x0C`
    // byte directly:
    //   - `_copyright_is_a_single_line_without_embedded_newlines`
    //     only checks `\n` and `\r` — `\x0C` is neither;
    //   - `_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    //     and `_copyright_ends_with_developer_name` only
    //     constrain the literal prefix (the `©` glyph + space)
    //     and the `"The Paladin contributors"` suffix, so a
    //     mid-string `\x0C` between them (`"© The Pa\x0Cladin
    //     contributors"`) satisfies both;
    //   - `_separates_glyph_and_attribution_with_a_single_space`
    //     only constrains the single byte immediately after the
    //     `©` glyph — a `\x0C` later in the string slips past;
    //   - `_does_not_end_with_a_period` only constrains the
    //     trailing byte;
    //   - `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    //     scans for four-digit runs — `\x0C` is not a digit;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte` each name a
    //     different byte specifically.
    //
    // The `_returns_paladin_copyright_line` exact-value pin
    // catches every byte today, but its protection collapses the
    // moment a multi-line copyright-attribution refactor or a
    // workspace-vendoring split decouples the helper from the
    // pinned literal — at that point a `\x0C`-bearing override
    // would slip past every byte-level companion above.
    //
    // A regression that landed `"© The Paladin\x0Ccontributors"`
    // (form-feed byte lifted from a legacy COPYRIGHT file
    // authored on a line-printer terminal that used `\x0C` to
    // advance the printer to the next page between the copyright
    // glyph and the attribution, a `concat!("© The Paladin",
    // "\x0C", "contributors")` form, or a hand-edited helper
    // that pasted from a `pandoc`-generated text dump preserving
    // `\x0C` page-break markers between document sections) would
    // mis-render in multiple downstream surfaces: (1) the GLib-
    // backed `AdwAboutDialog::set_copyright` setter hands the
    // string to Pango for inline rendering in the dialog footer
    // — Pango's default rendering of a bare `\x0C` byte is
    // implementation-defined and typically renders as a literal
    // control glyph (a hollow box or tofu-like placeholder),
    // breaking the tidy single-line copyright layout against
    // the website / issue-link rows beneath it; (2) the
    // copyright string is the legal attribution surface for the
    // dialog — a `\x0C`-mis-rendered footer erodes the trusted-
    // application surface contract by surfacing a control-byte
    // glyph in the legal-attribution row; (3) screen readers
    // that announce the dialog copyright row read the `\x0C` as
    // a literal control character or — on some implementations
    // — as a section-break announcement, breaking the
    // accessibility-tree announcement of the legal attribution
    // at the byte boundary; (4) downstream tooling that scrapes
    // the copyright string (license-attribution aggregators,
    // AGPL-3.0-or-later compliance crawlers, text-paginator
    // pipelines) would propagate the stray `\x0C` byte into the
    // consumer's stream and trigger the same rendering bug
    // across every downstream surface, with the additional risk
    // that text-paginator pipelines treat the `\x0C` as a hard
    // page break and split the legal-attribution row mid-string
    // in printed reports.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-footer
    // rendering bug or a screen-reader announcement break.
    // Current helper returns the literal `"© The Paladin
    // contributors"` (no `\x0C` byte), so this test passes today
    // and serves as a forcing function so any future override of
    // the helper — including the eventual landing of a multi-
    // line copyright attribution — stays free of form-feed
    // bytes. Continues the copyright C0 control-byte cycle past
    // the just-completed `{null / horizontal-tab / carriage-
    // return / vertical-tab}` quadruple so the helper's byte-
    // composition contract pins each forbidden control byte
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x0C'),
        "AdwAboutDialog copyright must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` (which only constrain the literal prefix and suffix), past `_separates_glyph_and_attribution_with_a_single_space` (which only constrains the single byte after the `©` glyph), past `_does_not_end_with_a_period` (which only constrains the trailing byte), past the no-year-token four-digit-run scan (`\\x0C` is not a digit), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-footer copyright row, erode the legal-attribution trusted-surface contract by surfacing a control-byte glyph in the legal row, break screen-reader copyright-row announcements at the byte boundary, and propagate into downstream license-attribution scrapers — text-paginator pipelines would additionally treat the `\\x0C` as a hard page break and split the legal-attribution row mid-string in printed reports; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_backspace_byte() {
    // Defense-in-depth per-byte sibling extending the copyright
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab / form-
    // feed}` quintuple to the next C0 control byte. The backspace
    // byte `\x08` (0x08) sits one step below HT (0x09) in the
    // ASCII C0 block; like its siblings it is a non-printable
    // control byte with no legitimate use inside a human-readable
    // GNOME dialog copyright string, but it carries an additional
    // terminal-erase semantic — in any pipeline that streams the
    // copyright through a TTY (release-notes ingest into a CI log,
    // `paladin-gtk --about` debug-info dump piped to `less` or
    // `cat`, downstream license-attribution scraper output) a
    // `\x08` byte erases the previous glyph from the terminal
    // surface, opening a log-injection / display-spoofing surface
    // where the rendered legal attribution diverges from the
    // bytes on disk.
    //
    // None of the existing copyright companions name the `\x08`
    // byte directly:
    //   - `_copyright_is_a_single_line_without_embedded_newlines`
    //     only checks `\n` and `\r` — `\x08` is neither;
    //   - `_copyright_starts_with_copyright_glyph_and_contains_developer_name`
    //     and `_copyright_ends_with_developer_name` only
    //     constrain the literal prefix (the `©` glyph + space)
    //     and the `"The Paladin contributors"` suffix, so a
    //     mid-string `\x08` between them (`"© The Pa\x08ladin
    //     contributors"`) satisfies both;
    //   - `_separates_glyph_and_attribution_with_a_single_space`
    //     only constrains the single byte immediately after the
    //     `©` glyph — a `\x08` later in the string slips past;
    //   - `_does_not_end_with_a_period` only constrains the
    //     trailing byte;
    //   - `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases`
    //     scans for four-digit runs — `\x08` is not a digit;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte` /
    //     `_does_not_contain_a_form_feed_byte` each name a
    //     different byte specifically. Notably `\x08` is NOT
    //     matched by `char::is_whitespace()` (Unicode treats BS
    //     as a non-whitespace control byte), so the surrounding-
    //     whitespace trim guards used by sibling helpers
    //     (`_comments_*`, `_developer_name_has_no_surrounding_whitespace`)
    //     would not catch a leading or trailing `\x08` even on
    //     the boundary — making backspace strictly more
    //     dangerous than form-feed, which `char::is_whitespace()`
    //     does match at the boundary.
    //
    // The `_returns_paladin_copyright_line` exact-value pin
    // catches every byte today, but its protection collapses the
    // moment a multi-line copyright-attribution refactor or a
    // workspace-vendoring split decouples the helper from the
    // pinned literal — at that point a `\x08`-bearing override
    // would slip past every byte-level companion above.
    //
    // A regression that landed `"© The Paladin \x08contributors"`
    // (backspace byte lifted from a hand-edited helper that
    // pasted from a terminal session recording where `\x08` had
    // been emitted by an interactive editor's backspace key
    // between the copyright glyph and the attribution, a
    // `concat!("© The Paladin ", "\x08", "contributors")` form,
    // or a `pandoc`-generated text dump preserving raw `\x08`
    // edit-stream bytes between document sections) would mis-
    // render in multiple downstream surfaces: (1) the GLib-
    // backed `AdwAboutDialog::set_copyright` setter hands the
    // string to Pango for inline rendering in the dialog footer
    // — Pango's default rendering of a bare `\x08` byte is
    // implementation-defined and typically renders as a literal
    // control glyph (a hollow box or tofu-like placeholder),
    // breaking the tidy single-line copyright layout against
    // the website / issue-link rows beneath it; (2) the
    // copyright string is the legal attribution surface for the
    // dialog — a `\x08`-mis-rendered footer erodes the trusted-
    // application surface contract by surfacing a control-byte
    // glyph in the legal-attribution row; (3) when the dialog
    // copyright is reused as part of the §11.4 debug-info dump
    // and that dump is piped through a TTY, the `\x08` byte
    // erases the preceding glyph, so the rendered legal
    // attribution diverges from the bytes on disk and an
    // attacker who controlled the upstream copyright source
    // could craft a payload whose terminal-rendered form omits
    // or substitutes attribution text without altering the
    // underlying file bytes (a classic log-injection / display-
    // spoofing primitive); (4) screen readers that announce the
    // dialog copyright row read the `\x08` as a literal control
    // character or — on some implementations — as a delete-
    // previous announcement, breaking the accessibility-tree
    // announcement of the legal attribution at the byte
    // boundary; (5) downstream tooling that scrapes the
    // copyright string (license-attribution aggregators,
    // AGPL-3.0-or-later compliance crawlers) would propagate
    // the stray `\x08` byte into the consumer's stream and
    // trigger the same rendering bug across every downstream
    // surface.
    //
    // Pinning the no-`\x08` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-footer
    // rendering bug, a terminal-erase display-spoof, or a
    // screen-reader announcement break. Current helper returns
    // the literal `"© The Paladin contributors"` (no `\x08`
    // byte), so this test passes today and serves as a forcing
    // function so any future override of the helper — including
    // the eventual landing of a multi-line copyright
    // attribution — stays free of backspace bytes. Continues the
    // copyright C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return / vertical-tab /
    // form-feed}` quintuple so the helper's byte-composition
    // contract pins each forbidden control byte against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x08'),
        "AdwAboutDialog copyright must not contain the `\\x08` backspace byte (0x08); a mid-string `\\x08` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` (which only constrain the literal prefix and suffix), past `_separates_glyph_and_attribution_with_a_single_space` (which only constrains the single byte after the `©` glyph), past `_does_not_end_with_a_period` (which only constrains the trailing byte), past the no-year-token four-digit-run scan (`\\x08` is not a digit), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` (which each name a different byte specifically); `\\x08` is NOT matched by `char::is_whitespace()` so boundary trim guards do not catch it even on the leading or trailing byte (strictly more dangerous than form-feed which `char::is_whitespace()` does match at the boundary); it would render as a literal control glyph in the dialog-footer copyright row, erode the legal-attribution trusted-surface contract by surfacing a control-byte glyph in the legal row, enable terminal-erase display-spoofing when the copyright is dumped through a TTY in §11.4 debug-info pipelines (the rendered legal attribution diverges from the bytes on disk because `\\x08` erases the preceding glyph), break screen-reader copyright-row announcements at the byte boundary, and propagate into downstream license-attribution scrapers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the comments
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}` quadruple
    // to the next C0 control byte. The form-feed byte `\x0C`
    // (0x0C) sits one step above VT (0x0B) and one step below CR
    // (0x0D) in the ASCII C0 block; like its siblings it is a
    // non-printable control byte with no legitimate use inside a
    // human-readable GNOME dialog description string.
    //
    // None of the existing comments companions name the `\x0C`
    // byte directly:
    //   - `_comments_is_non_empty_single_line_distinct_from_program_name`
    //     uses `comments.contains('\n')` to reject embedded
    //     newlines and a surrounding-whitespace `trim()` check —
    //     `\x0C` is not `\n` and, although `char::is_whitespace()`
    //     returns true for U+000C FF (so a *leading* or *trailing*
    //     `\x0C` would be trimmed out by the surrounding-
    //     whitespace guard), a mid-string `\x0C` (`"OTP authent\x0Cicator
    //     for the command line"`) sits between the boundaries
    //     and slips past;
    //   - `_comments_does_not_end_with_a_period_per_libadwaita_convention`
    //     only constrains the trailing byte;
    //   - `_comments_is_ascii_only` pins each byte as ASCII —
    //     `\x0C` is ASCII so it slips past;
    //   - `_comments_does_not_contain_a_null_byte` /
    //     `_comments_does_not_contain_a_horizontal_tab_byte` /
    //     `_comments_does_not_contain_a_carriage_return_byte` /
    //     `_comments_does_not_contain_a_vertical_tab_byte` each
    //     name a different byte specifically;
    //   - `_comments_matches_cargo_pkg_description` transitively
    //     guards the value via the cross-source pin to
    //     `CARGO_PKG_DESCRIPTION`, but that protection is brittle:
    //     a future refactor that decoupled the helper from the
    //     workspace `Cargo.toml` `description` field (a hand-
    //     edited override for a libadwaita HIG-mandated single-
    //     line summary phrasing, or a workspace-vendoring split)
    //     would silently drop the transitive guard.
    //
    // A regression that landed `"OTP authent\x0Cicator for the
    // command line"` (a form-feed byte lifted from a legacy
    // plain-text DESCRIPTION file authored on a line-printer
    // terminal that used `\x0C` to advance to the next page
    // between sections of a printed description, a
    // `concat!(_, "\x0C", _)` form, a `pandoc`-generated text
    // dump that preserved `\x0C` page-break markers, or a hand-
    // edited helper that pasted from a page-broken text file)
    // would mis-render in multiple downstream surfaces: (1) the
    // GLib-backed `AdwAboutDialog::set_comments` setter hands the
    // string to Pango for inline rendering as the dialog header
    // description beneath the program name — Pango's default
    // rendering of a bare `\x0C` byte is implementation-defined
    // and typically renders as a literal control glyph (a hollow
    // box or a tofu-like placeholder), breaking the tidy single-
    // line description layout against the program-name row above
    // it; (2) the comments value is sourced from
    // `CARGO_PKG_DESCRIPTION` which propagates into Cargo's
    // `description` field — tooling that scrapes this metadata
    // (`cargo metadata`, crates.io registry indexing, GNOME
    // `gnome-software` descriptions) would propagate the stray
    // `\x0C` byte into every consumer's stream, with the
    // additional risk that text-paginator pipelines treat the
    // `\x0C` as a hard page break and split the description mid-
    // string in printed reports; (3) screen readers that announce
    // the dialog description read the `\x0C` as a literal control
    // character or — on some implementations — as a section-break
    // announcement, breaking the description accessibility-tree
    // announcement at the byte boundary.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream dialog-header
    // rendering bug, a Cargo-metadata-scrape miss, or a screen-
    // reader announcement break. Current helper returns the
    // value sourced from `CARGO_PKG_DESCRIPTION` (no `\x0C`
    // byte), so this test passes today and serves as a forcing
    // function so any future override of the helper — or any
    // future edit of the workspace `Cargo.toml` `description`
    // field — stays free of form-feed bytes. Continues the
    // comments C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return / vertical-tab}`
    // quadruple so the helper's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x0C'),
        "AdwAboutDialog comments must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace, and although `char::is_whitespace()` matches U+000C FF it only rejects boundary occurrences), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_is_ascii_only` (because `\\x0C` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers and `gnome-software` description rows (with text-paginator pipelines treating it as a hard page break), and break screen-reader description announcements at the byte boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-entry-loop sibling of the just-added
    // `_developer_name_does_not_contain_a_form_feed_byte`,
    // `_copyright_does_not_contain_a_form_feed_byte`, and
    // `_comments_does_not_contain_a_form_feed_byte` companions on
    // the same C0 control-byte cycle, extending the developers-
    // array byte-cleanliness contract past the just-completed
    // `{null / horizontal-tab / carriage-return / vertical-tab}`
    // entry-quadruple to the next C0 control byte. The form-feed
    // byte `\x0C` (0x0C) sits one step above VT (0x0B) and one
    // step below CR (0x0D) in the ASCII C0 block; like its
    // siblings it is a non-printable control byte with no
    // legitimate use inside a human-readable GNOME credits-page
    // contributor-name entry.
    //
    // None of the existing developers companions name the `\x0C`
    // byte directly per entry:
    //   - `_is_non_empty_array_of_non_empty_single_line_names`
    //     pins each entry as non-empty and single-line via
    //     `!name.contains('\n')` — `\x0C` is not `\n`. The
    //     surrounding-whitespace guards
    //     (`!name.starts_with(char::is_whitespace)` and
    //     `!name.ends_with(char::is_whitespace)`) reject `\x0C`
    //     *only* at the boundary bytes (since
    //     `char::is_whitespace()` under Rust's Unicode definition
    //     matches U+000C FF) — but a mid-string `\x0C`
    //     (`"Benjamin\x0CPorter"`) sits between the boundaries
    //     and slips past both guards;
    //   - `_entries_are_distinct` / `_does_not_contain_developer_name`
    //     / `_does_not_contain_app_id` /
    //     `_does_not_contain_program_name` / `_lists_benjamin_porter`
    //     companions guard against content-shape regressions but
    //     say nothing about the `\x0C` byte;
    //   - `_entries_do_not_contain_a_null_byte` /
    //     `_entries_do_not_contain_a_horizontal_tab_byte` /
    //     `_entries_do_not_contain_a_carriage_return_byte` /
    //     `_entries_do_not_contain_a_vertical_tab_byte` siblings
    //     each name a different byte specifically.
    //
    // A regression that landed `["Benjamin\x0CPorter"]` (a form-
    // feed byte lifted from a legacy CONTRIBUTORS file authored
    // on a line-printer terminal that used `\x0C` to advance to
    // the next page between sections of a printed contributors
    // list, a `concat!("Benjamin", "\x0C", "Porter")` form, a
    // `pandoc`-generated text dump that preserved `\x0C` page-
    // break markers, or a hand-edited helper that pasted from a
    // page-broken text file) would mis-render in multiple
    // downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_developers` setter hands the array to
    // GTK and Pango renders each entry as a credits-page row — a
    // stray `\x0C` byte in the middle of a contributor name
    // would render as a literal control glyph (a hollow box or
    // tofu-like placeholder), breaking the credits-page
    // contributor-name layout; (2) any tooling that scrapes the
    // credits-page contributor list (release-note generators,
    // contributor-attribution crawlers, GNOME `gnome-software`
    // credit aggregators) would propagate the stray `\x0C` byte
    // into the consumer's stream, with the additional risk that
    // text-paginator pipelines treat the `\x0C` as a hard page
    // break and split the contributor name mid-string in printed
    // reports; (3) screen readers that announce the credits-page
    // contributor names read the `\x0C` as a literal control
    // character or — on some implementations — as a section-break
    // announcement, breaking the contributor-name accessibility-
    // tree announcement at the byte boundary.
    //
    // Pinning the no-`\x0C` invariant across every contributor
    // entry in a single per-entry loop surfaces the regression
    // with a message naming both the offending byte and the
    // affected entry index at build time rather than as a
    // downstream credits-page rendering artifact, attribution-
    // scraper miss, or screen-reader announcement break.
    // Current helper returns the literal `["Benjamin Porter"]`
    // (no `\x0C` byte), so this test passes today and serves as
    // a forcing function so any future override of the helper —
    // or any future contributor addition — stays free of form-
    // feed bytes. Continues the developers-array C0 control-byte
    // cycle past the just-completed `{null / horizontal-tab /
    // carriage-return / vertical-tab}` quadruple so each entry's
    // byte-composition contract pins each forbidden control byte
    // against a single source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x0C'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` and rejects boundary whitespace via `char::is_whitespace()` — boundary-only, not mid-string), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` (which name `\\0`, `\\t`, `\\r`, and `\\x0B` specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, propagate into downstream attribution scrapers and `gnome-software` credit aggregators (with text-paginator pipelines treating it as a hard page break), and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_form_feed_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three currently-empty `AdwAboutDialog` credits-section
    // array helpers
    // (`format_app_about_dialog_designers`,
    // `format_app_about_dialog_artists`,
    // `format_app_about_dialog_documenters`) and pinning each
    // entry as free of the form-feed byte `\x0C` (0x0C). Mirror
    // of the just-added
    // `_developers_entries_do_not_contain_a_form_feed_byte`
    // sibling on the populated-developers side and of the
    // `_empty_credits_section_entries_do_not_contain_a_null_byte`
    // / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte`
    // / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte`
    // / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte`
    // siblings on the prior C0 control-byte cycle, structured as
    // a single cross-helper loop matching those existing
    // companions.
    //
    // The form-feed byte sits one step above VT (0x0B) and one
    // step below CR (0x0D) in the ASCII C0 block; like its
    // siblings it is a non-printable control byte with no
    // legitimate use inside a human-readable GNOME credits-page
    // contributor-name entry.
    //
    // The three helpers currently return the empty array `[]`
    // because Paladin does not yet have a separately-credited
    // designer / artist / documenter for the v0.2 release. The
    // empty-array return trivially contains no entries (let
    // alone `\x0C`-bearing entries), so this test passes today
    // as the loop body is never entered. However, once any of
    // the three credits sections gains a contributor, the helper
    // return type will switch from `[&'static str; 0]` to
    // `[&'static str; N]` with non-empty entries — at that point
    // a `\x0C` injection from a legacy CONTRIBUTORS file
    // authored on a line-printer terminal that used `\x0C` to
    // advance the printer to the next page between sections of
    // a printed contributors list, a `concat!(_, "\x0C", _)`
    // form, a `pandoc`-generated text dump that preserved `\x0C`
    // page-break markers between document sections, a hand-
    // edited helper that pasted from a page-broken text file, or
    // a tooling export pipeline that preserved FF-bearing values
    // inside a single-name entry would slip past every other
    // companion the way the
    // `_developers_entries_do_not_contain_a_form_feed_byte`
    // sibling already documents for the developers helper.
    //
    // Form-feed bytes in the credits-section entries would mis-
    // render in multiple downstream surfaces, identically to the
    // `set_developers` analysis in the
    // `_developers_entries_do_not_contain_a_form_feed_byte`
    // companion: (1) the GLib-backed `set_designers` /
    // `set_artists` / `set_documenters` setters route through
    // GTK and Pango renders each entry as a credits-page row —
    // a stray `\x0C` byte in the middle of a contributor name
    // would render as a literal control glyph (a hollow box or
    // tofu-like placeholder), visually breaking the credits-page
    // contributor-name layout; (2) any tooling that scrapes the
    // credits-page contributor list (GNOME `gnome-software`
    // credit aggregators) would propagate the stray `\x0C` byte
    // into the consumer's stream and trigger the same rendering
    // bug across every downstream surface, with the additional
    // risk that text-paginator pipelines treat the `\x0C` as a
    // hard page break and split the contributor name mid-string
    // in printed reports; (3) screen readers that announce the
    // credits-page contributor names read the `\x0C` as a
    // literal control character or — on some implementations —
    // as a section-break announcement, breaking the contributor-
    // name accessibility-tree announcement at the byte boundary.
    //
    // Pinning the no-`\x0C` invariant across all three
    // currently-empty credits-section helpers in a single cross-
    // helper loop surfaces the regression with a message naming
    // the affected helper, the offending byte, and the entry
    // index at build time rather than as a downstream rendering
    // artifact of the credits-page sections. Current helpers
    // return the empty array `[]` (zero entries, no `\x0C` byte
    // to find), so this test passes today and serves as a
    // forcing function so any future override of the helpers —
    // including the eventual landing of separately-credited
    // designer / artist / documenter strings — stays free of
    // form-feed bytes. Continues the empty-credits-section C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}` entry-
    // quadruple so each entry's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_artists, format_app_about_dialog_designers,
        format_app_about_dialog_documenters,
    };

    let designers = format_app_about_dialog_designers();
    let artists = format_app_about_dialog_artists();
    let documenters = format_app_about_dialog_documenters();

    let sections: [(&str, &[&str]); 3] = [
        ("designers", &designers),
        ("artists", &artists),
        ("documenters", &documenters),
    ];

    for (label, entries) in sections {
        for (idx, entry) in entries.iter().enumerate() {
            assert!(
                !entry.contains('\x0C'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, propagate into downstream attribution scrapers and `gnome-software` credit aggregators (with text-paginator pipelines treating it as a hard page break), and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the
    // release_notes_version byte-cleanliness contract past the
    // just-completed `{null / horizontal-tab / carriage-return /
    // vertical-tab}` quadruple to the next C0 control byte. The
    // form-feed byte `\x0C` (0x0C) sits one step above VT (0x0B)
    // and one step below CR (0x0D) in the ASCII C0 block; like
    // its siblings it is a non-printable control byte with no
    // legitimate use inside a semver-shaped version string.
    //
    // The two existing `_matches_about_dialog_version` and
    // `_matches_cargo_pkg_version` cross-source pins transitively
    // guarantee `release_notes_version` shares its bytes with
    // the `version` helper (which in turn equals
    // `CARGO_PKG_VERSION`). The `version` helper is byte-pinned
    // by `_version_has_no_embedded_whitespace` (a
    // `char::is_whitespace()` check that catches `\x0C` under
    // Rust's Unicode definition, since U+000C FF is whitespace),
    // so a `\x0C` byte in the active `release_notes_version`
    // value is currently protected *transitively* — through
    // equality with `version`, which is itself directly pinned
    // against embedded whitespace.
    //
    // But the transitive protection is brittle: a future refactor
    // that decoupled the two helpers (a separate override
    // constant for the "What's New" scope, a workspace-vendoring
    // split that lifted `release_notes_version` out of the
    // equality chain, or a CHANGELOG.md-derived release-notes
    // version that intentionally lagged the binary version on a
    // hotfix cut) would silently drop the `\x0C` guard the
    // moment the `_matches_*` companions started skipping cases.
    // The `_does_not_contain_a_null_byte` /
    // `_does_not_contain_a_horizontal_tab_byte` /
    // `_does_not_contain_a_carriage_return_byte` /
    // `_does_not_contain_a_vertical_tab_byte` siblings each name
    // a different byte specifically. None of the existing
    // companions name the `\x0C` byte directly on this helper.
    //
    // A regression that landed `"0.0.1\x0C"` or
    // `"0\x0C.0\x0C.1"` (a form-feed byte lifted from a legacy
    // CHANGELOG file authored on a line-printer terminal that
    // used `\x0C` to advance the printer to the next page
    // between sections of a printed changelog, a `concat!(_,
    // "\x0C", _)` form, a `pandoc`-generated text dump that
    // preserved `\x0C` page-break markers between CHANGELOG
    // entries, or a hand-edited helper override that lifted the
    // version string from a page-broken text file) would mis-
    // render in multiple downstream surfaces, identically to the
    // analysis on the `version` helper: (1) the GLib-backed
    // `AdwAboutDialog::set_release_notes_version` setter routes
    // the value into Pango for inline rendering as the "What's
    // New in v<release_notes_version>" header — Pango's default
    // rendering of a bare `\x0C` byte is implementation-defined
    // and typically renders as a literal control glyph (a hollow
    // box or tofu-like placeholder), breaking the tidy section-
    // header layout; (2) the value scopes the "What's New" body
    // region inside the dialog — a mismatched / mis-rendered
    // scope key could prevent the body from rendering at all on
    // libadwaita versions that strip whitespace when computing
    // the body-region lookup key, with the additional risk that
    // text-paginator pipelines treat the `\x0C` as a hard page
    // break and split the version header mid-string in printed
    // reports; (3) screen readers that announce the "What's New"
    // section header read the `\x0C` as a literal control
    // character or — on some implementations — as a section-
    // break announcement, breaking the section-header
    // accessibility-tree announcement at the byte boundary.
    //
    // Pinning the no-`\x0C` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // decoupling that silently dropped the transitive `version`
    // guard. Current helper returns the value sourced from
    // `CARGO_PKG_VERSION` (no `\x0C` byte), so this test passes
    // today and serves as a forcing function so any future
    // decoupling override of the helper — including the
    // eventual landing of a separately-scoped release-notes
    // version derived from CHANGELOG.md headings — stays free of
    // form-feed bytes. Continues the release-notes-version C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}`
    // quadruple so the helper's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x0C'),
        "AdwAboutDialog release_notes_version must not contain the `\\x0C` form-feed byte (0x0C); the current value's `\\x0C`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version` and the `version` helper's `_has_no_embedded_whitespace` check (which uses `char::is_whitespace()` and catches U+000C FF), so a future decoupling override would silently drop the `\\x0C` guard; a stray `\\x0C` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that strip whitespace when computing the body-region lookup key (with text-paginator pipelines treating it as a hard page break), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth mirror of the just-added
    // `_release_notes_version_does_not_contain_a_form_feed_byte`
    // companion on the release-notes-body side, extending the
    // release_notes byte-cleanliness contract past the just-
    // completed `{null / horizontal-tab / carriage-return /
    // vertical-tab}` quadruple to the next C0 control byte. The
    // form-feed byte `\x0C` (0x0C) sits one step above VT (0x0B)
    // and one step below CR (0x0D) in the ASCII C0 block; like
    // its siblings it is a non-printable control byte with no
    // legitimate use inside a Pango-markup release-notes body.
    //
    // The libadwaita release-notes convention permits embedded
    // `\n` line breaks between Pango markup elements (`<li>`
    // entries inside the wrapping `<ul>`, paragraph breaks,
    // etc.), so the helper is one of only three about-dialog
    // helpers (alongside `format_app_about_dialog_debug_info`
    // and `format_app_about_dialog_translator_credits`) where
    // embedded line breaks are legitimately expected. That makes
    // `\x0C` (0x0C FORM FEED) a distinct regression surface:
    // it is NOT covered by `_has_no_surrounding_whitespace_when_non_empty`
    // (`\x0C` mid-string is non-surrounding), it is NOT covered
    // by `_starts_and_ends_with_a_markup_element_when_non_empty`
    // (the opening `<` and closing `>` markup boundaries are
    // independent of mid-body `\x0C` bytes), it slips past
    // `_does_not_contain_a_null_byte` (`\x0C` is not `\0`), it
    // slips past `_does_not_contain_a_horizontal_tab_byte`
    // (`\x0C` is not `\t`), it slips past
    // `_does_not_contain_a_carriage_return_byte` (`\x0C` is not
    // `\r`), and it slips past
    // `_does_not_contain_a_vertical_tab_byte` (`\x0C` is not
    // `\x0B`). None of the existing companions name the `\x0C`
    // byte directly on this helper.
    //
    // A regression that landed
    // `"<ul>\n\x0C<li>foo</li>\n\x0C<li>bar</li>\n</ul>"`
    // (form-feed-indented pretty-printed Pango markup lifted from
    // a legacy pre-formatter that used `\x0C` to advance to the
    // next page between bullet entries on a line-printer
    // terminal, a `concat!(_, "\x0C", _)` form mirroring a
    // CHANGELOG.md FF-paginated bullet block, a `pandoc`-
    // generated text dump that preserved `\x0C` page-break
    // markers between document sections, or a hand-edited helper
    // that pasted from a page-broken text file) would mis-
    // render in multiple downstream surfaces: (1) Pango's markup
    // parser permits ASCII whitespace between elements but
    // renders `\x0C` as a literal control glyph (a hollow box or
    // tofu-like placeholder) since `\x0C` is technically
    // whitespace but has no tab-stop semantics; in the about-
    // dialog "What's New" body this would surface as visible
    // boxes or placeholder glyphs between the wrapping `<ul>`
    // and each `<li>` bullet element; (2) any in-app changelog
    // display that reuses the release-notes string outside the
    // dialog (release-tracker bots, copy-to-clipboard handlers)
    // would propagate the stray `\x0C` into the consumer's
    // stream and trigger the same rendering bug across every
    // downstream surface, with the additional risk that text-
    // paginator pipelines treat the `\x0C` as a hard page break
    // and split the bullet block mid-stream in printed reports;
    // (3) screen readers that announce the release-notes content
    // read the `\x0C` as a literal control character or — on
    // some implementations — as a section-break announcement,
    // breaking the accessibility-tree announcement at every
    // bullet-boundary indent.
    //
    // Mirror of the just-added
    // `_developer_name_does_not_contain_a_form_feed_byte`,
    // `_copyright_does_not_contain_a_form_feed_byte`,
    // `_comments_does_not_contain_a_form_feed_byte`,
    // `_developers_entries_do_not_contain_a_form_feed_byte`,
    // `_empty_credits_section_entries_do_not_contain_a_form_feed_byte`,
    // and `_release_notes_version_does_not_contain_a_form_feed_byte`
    // siblings; together they extend the about-dialog byte-
    // composition contract from the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}`
    // quadruple to the form-feed regression surface as well.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream "What's New" body
    // rendering bug, a stray `\x0C` byte in an external
    // changelog reuse, or a screen-reader announcement break.
    // Current helper returns the empty literal `""` (no `\x0C`
    // byte), so this test passes today and serves as a forcing
    // function so any future override of the helper — including
    // the eventual landing of an actual v0.2 release-notes Pango
    // markup body sourced from CHANGELOG.md — stays free of
    // form-feed bytes even when embedded `\n` line breaks are
    // intentionally present.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\x0C'),
        "AdwAboutDialog release_notes must not contain the `\\x0C` form-feed byte (0x0C); the Pango markup parser permits ASCII whitespace between elements but renders `\\x0C` as a literal control glyph (a hollow box or tofu-like placeholder) since `\\x0C` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics, so a stray `\\x0C` between the wrapping `<ul>` and each `<li>` bullet would surface as visible boxes in the dialog's What's New body, propagate the same rendering bug into any external changelog reuse (with text-paginator pipelines treating it as a hard page break), and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth mirror of the just-added
    // `_release_notes_does_not_contain_a_form_feed_byte`
    // companion on the translator-credits side, extending the
    // translator_credits byte-cleanliness contract past the
    // just-completed `{null / horizontal-tab / carriage-return /
    // vertical-tab}` quadruple to the next C0 control byte. The
    // form-feed byte `\x0C` (0x0C) sits one step above VT (0x0B)
    // and one step below CR (0x0D) in the ASCII C0 block; like
    // its siblings it is a non-printable control byte with no
    // legitimate use inside a libadwaita-convention translator-
    // credits string.
    //
    // The libadwaita translator-credits convention permits
    // embedded `\n` line breaks between translator entries (the
    // `_is_single_line_when_non_empty` companion only asserts
    // the empty-string case, so it does not gate embedded
    // newlines once a translation lands), so the helper is one
    // of only three about-dialog helpers (alongside
    // `format_app_about_dialog_debug_info` and
    // `format_app_about_dialog_release_notes`) where embedded
    // line breaks are legitimately expected. That makes `\x0C`
    // (0x0C FORM FEED) a distinct regression surface: it is NOT
    // covered by `_has_no_surrounding_whitespace_when_non_empty`
    // (`\x0C` mid-string is non-surrounding), it is NOT covered
    // by any per-entry single-line check (the helper itself is
    // explicitly multi-line per libadwaita convention), it slips
    // past `_does_not_contain_a_null_byte` (`\x0C` is not `\0`),
    // it slips past `_does_not_contain_a_horizontal_tab_byte`
    // (`\x0C` is not `\t`), it slips past
    // `_does_not_contain_a_carriage_return_byte` (`\x0C` is not
    // `\r`), and it slips past
    // `_does_not_contain_a_vertical_tab_byte` (`\x0C` is not
    // `\x0B`). None of the existing companions name the `\x0C`
    // byte directly on this helper.
    //
    // A regression that landed
    // `"name1\x0C<email1>\nname2\x0C<email2>"` (form-feed-
    // separated `<name>\x0C<email>` rows lifted from a legacy
    // contributors export pipeline that used `\x0C` to advance
    // to the next page between attribution rows on a line-
    // printer terminal, an `xgettext` export that preserved FF-
    // paginated values, a `concat!(_, "\x0C", _)` form mirroring
    // an FF-paginated attribution block, a `pandoc`-generated
    // text dump that preserved `\x0C` page-break markers between
    // attribution rows, or a hand-edited helper that pasted from
    // a page-broken text file) would mis-render in multiple
    // downstream surfaces: (1) libadwaita's credits-page parser
    // splits the translator-credits string on `\n` (LF) per the
    // documented convention, leaving the embedded `\x0C` bytes
    // inside each parsed entry untouched; the GLib-backed Pango
    // render path treats `\x0C` as a literal control glyph (a
    // hollow box or tofu-like placeholder) since `\x0C` is
    // technically whitespace under `char::is_whitespace()` but
    // has no tab-stop semantics, breaking the tidy two-column
    // `<name> <email>` attribution layout; (2) any localization
    // tooling that round-trips the translator-credits string
    // back through `xgettext` would either silently dedupe the
    // `\x0C` to a single space (data loss) or preserve the
    // `\x0C` and propagate the same rendering bug across every
    // downstream consumer of the .po / .mo file, with the
    // additional risk that text-paginator pipelines treat the
    // `\x0C` as a hard page break and split the attribution row
    // mid-stream in printed reports; (3) screen readers that
    // announce the credits-page contents read the `\x0C` as a
    // literal control character or — on some implementations —
    // as a section-break announcement, breaking the
    // accessibility-tree announcement at every attribution-row
    // column boundary.
    //
    // Mirror of the just-added
    // `_developer_name_does_not_contain_a_form_feed_byte`,
    // `_copyright_does_not_contain_a_form_feed_byte`,
    // `_comments_does_not_contain_a_form_feed_byte`,
    // `_developers_entries_do_not_contain_a_form_feed_byte`,
    // `_empty_credits_section_entries_do_not_contain_a_form_feed_byte`,
    // `_release_notes_version_does_not_contain_a_form_feed_byte`,
    // and `_release_notes_does_not_contain_a_form_feed_byte`
    // siblings; together they extend the about-dialog byte-
    // composition contract from the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}`
    // quadruple to the form-feed regression surface as well.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces the
    // regression with a message naming the offending byte at
    // build time rather than as a downstream credits-page
    // rendering bug, a stray `\x0C` byte in the .po round trip,
    // or a screen-reader announcement break. Current helper
    // returns the empty literal `""` (no `\x0C` byte), so this
    // test passes today and serves as a forcing function so any
    // future override of the helper — including the eventual
    // landing of an actual translator-credits string — stays
    // free of form-feed bytes even when embedded `\n` line
    // breaks are intentionally present.
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x0C'),
        "AdwAboutDialog translator_credits must not contain the `\\x0C` form-feed byte (0x0C); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x0C` bytes inside each parsed entry untouched, and `\\x0C` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics so Pango renders it as a literal control glyph; a stray `\\x0C` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips as either silent dedupe to a single space or `\\x0C` preservation (with text-paginator pipelines treating it as a hard page break), and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the debug_info
    // byte-cleanliness contract past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}` quadruple
    // to the next C0 control byte. The form-feed byte `\x0C`
    // (0x0C) sits one step above VT (0x0B) and one step below CR
    // (0x0D) in the ASCII C0 block; like its siblings it is a
    // non-printable control byte with no legitimate use inside a
    // Troubleshooting → Debugging Information payload.
    //
    // The existing `_carries_program_name_version_and_app_id`
    // (content-shape pin),
    // `_is_non_empty_text_with_no_trailing_whitespace` (non-empty
    // + no-trailing-whitespace pin; note that
    // `char::is_whitespace()` matches U+000C FF, so a *trailing*
    // `\x0C` is rejected by this companion — but a mid-payload
    // `\x0C` is non-trailing and slips past),
    // `_starts_with_program_name` (leading-substring pin),
    // `_app_id_appears_on_a_distinct_line_from_program_name`
    // (multi-line pin), `_has_exactly_two_lines` (line-count
    // pin), `_program_name_line_ends_with_the_version` (line-1
    // trailing-substring pin),
    // `_app_id_line_ends_with_the_reverse_dns_app_id` (line-2
    // trailing-substring pin), `_is_ascii_only` (byte-composition
    // pin), `_does_not_contain_a_null_byte` (null-byte pin),
    // `_does_not_contain_a_horizontal_tab_byte` (HT pin),
    // `_does_not_contain_a_carriage_return_byte` (CR pin), and
    // `_does_not_contain_a_vertical_tab_byte` (VT pin) catch the
    // wrong-shape / wrong-content / empty / multi-line-count /
    // wrong-trailing-substring / non-ASCII / `\0`-byte / `\t`-
    // byte / `\r`-byte / `\x0B`-byte regressions but a mid-
    // payload `\x0C` (`"Paladin\x0C0.0.1\nApp ID: org.tamx.Paladin.Gui"`)
    // slips past `_is_ascii_only` (since `\x0C` is ASCII), past
    // the per-byte siblings (which each name a different byte),
    // past the line-count and trailing-substring companions
    // (which split on `\n` and check only trailing substrings),
    // and past the `_is_non_empty_text_with_no_trailing_whitespace`
    // companion's boundary-only `\x0C` rejection.
    //
    // A regression that landed `\x0C` in the payload would mis-
    // render the debug-info content in three ways: (1) the GLib-
    // backed `AdwAboutDialog::set_debug_info` setter routes the
    // value into Pango for rendering inside the dialog's
    // "Troubleshooting → Debugging Information" body — Pango's
    // default rendering of a bare `\x0C` byte is implementation-
    // defined and typically renders as a literal control glyph
    // (a hollow box or tofu-like placeholder) since `\x0C` has
    // no tab-stop semantics, breaking the tidy single-column
    // layout expected by the AdwAboutDialog template; (2) when
    // the user pastes the payload into a bug-report form on
    // GitHub, the `\x0C` byte renders inconsistently across
    // browsers and font stacks (some show a hollow box, some
    // show a page-break artifact, some silently drop the byte),
    // cluttering the maintainer's view of the report and
    // degrading bug-report quality; (3) when the user saves the
    // payload to a `.txt` file via the
    // `AdwAboutDialog::set_debug_info_filename` slot, the GTK
    // file-writer writes the raw bytes so the resulting file
    // contains a stray FF byte that breaks POSIX text-processing
    // tools (`grep`, `awk`, `cut`) whose default field-delimiter
    // behaviour does not recognize `\x0C` as a delimiter but
    // also does not treat it as part of the field payload, and
    // text-paginator pipelines treat the `\x0C` as a hard page
    // break and split the saved payload mid-stream in printed
    // reports.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces
    // the regression with a message naming the offending byte
    // at build time rather than as a downstream dialog rendering
    // bug, a pasted-bug-report cross-browser drift artifact, or
    // a saved-file POSIX-text-processing breakage. The current
    // `format_app_about_dialog_debug_info` returns `"Paladin
    // 0.0.1\nApp ID: org.tamx.Paladin.Gui"` (built at compile
    // time via `concat!` with single-space separators between
    // every column), so this test passes today and serves as a
    // forcing function so any future override of the debug-info
    // helper — including the eventual landing of additional
    // diagnostic fields (locale, Wayland vs X11 session type,
    // Flatpak vs native) — stays free of form-feed bytes.
    // Continues the debug-info C0 control-byte cycle past the
    // just-completed `{null / horizontal-tab / carriage-return /
    // vertical-tab}` quadruple so the helper's byte-composition
    // contract pins each forbidden control byte against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\x0C'),
        "AdwAboutDialog debug_info must not contain the `\\x0C` form-feed byte (0x0C); a `\\x0C` byte slips past `_is_ascii_only` (since `\\x0C` is ASCII), past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and past `_is_non_empty_text_with_no_trailing_whitespace` (which rejects boundary `\\x0C` via `char::is_whitespace()` but not mid-payload occurrences), and would render as a literal control glyph in the Troubleshooting dialog body, drift across browsers and font stacks in pasted bug reports, and propagate a stray FF byte into POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename` (with text-paginator pipelines treating it as a hard page break); got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the
    // program-name byte coverage past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}` quadruple
    // to the next C0 control byte. The form-feed byte `\x0C`
    // (0x0C) sits one step above VT (0x0B) and one step below CR
    // (0x0D) in the ASCII C0 block; like its siblings it is a
    // non-printable control byte with no legitimate use inside a
    // GNOME application program-name string.
    //
    // The existing `_program_name_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000C FF — so the program-name helper's `\x0C`-
    // cleanliness is currently protected *transitively* by that
    // one specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a single embedded space in the
    // program-name slot (a localized program-name string like
    // `"Paladin Auth"`, a workspace-vendoring split that lifted
    // program-name out of the no-whitespace constraint, or a
    // libadwaita HIG update that explicitly permitted a single
    // space in the bold-header program-name row) would naturally
    // relax the `_has_no_embedded_whitespace` companion — and
    // the human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, tab) without separately calling out `\x0C`
    // on the assumption that "ASCII whitespace is now allowed".
    // That assumption is wrong: `\x0C` is a control byte without
    // tab-stop semantics, not a layout-friendly whitespace
    // character, and the program-name slot is rendered as a
    // single bold header row with no page-break semantics — so
    // dropping the `\x0C` check alongside the space-relaxation
    // would silently regress the no-`\x0C` invariant.
    //
    // None of the existing companions name the `\x0C` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0C` is
    //     ASCII so it slips past;
    //   - `_is_non_empty_and_not_app_id` only checks non-empty
    //     + distinct-from-app-id;
    //   - `_matches_format_app_window_title` only enforces
    //     equality with the window title (so any `\x0C`-bearing
    //     override would slip past as long as the window title
    //     helper had matching bytes);
    //   - `_is_segment_of_application_icon_name` only checks
    //     segment containment;
    //   - `_does_not_end_with_a_period` only constrains the
    //     suffix;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"Pala\x0Cdin"` (form-feed byte
    // lifted from a legacy program-name registry authored on a
    // line-printer terminal that used `\x0C` to advance to the
    // next page mid-token, a `concat!(_, "\x0C", _)` form, a
    // `pandoc`-generated text dump that preserved `\x0C` page-
    // break markers, or a hand-edited helper override that
    // pasted from a page-broken text file) would mis-render in
    // three downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_application_name` setter routes the
    // value into Pango for inline rendering as the bold program-
    // name row at the dialog header — Pango's default rendering
    // of a bare `\x0C` byte is implementation-defined and
    // typically renders as a literal control glyph (a hollow box
    // or tofu-like placeholder), breaking the tidy bold-header
    // layout; (2) the matching `gtk::Window::set_title` setter
    // (the program name is mirrored to the window title per
    // `_matches_format_app_window_title`) renders the `\x0C` in
    // the window manager's taskbar / dock display label,
    // surfacing the control byte to every shell that lists open
    // windows, with the additional risk that text-paginator
    // pipelines treat the `\x0C` as a hard page break and split
    // the window title mid-string in printed reports; (3) the
    // GTK accessibility tree's `accessible-name` property routes
    // through the same Pango layer, breaking screen-reader
    // announcements of the application name at the byte boundary.
    //
    // Pinning the no-`\x0C` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped the
    // `\x0C` guard. Current helper returns the literal `"Paladin"`
    // (no `\x0C` byte), so this test passes today and serves as
    // a forcing function so any future override of the helper —
    // including the eventual landing of a localized multi-word
    // program name — stays free of form-feed bytes. Continues
    // the program-name C0 control-byte cycle past the just-
    // completed `{null / horizontal-tab / carriage-return /
    // vertical-tab}` quadruple so the helper's byte-composition
    // contract pins each forbidden control byte against a single
    // source of truth.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x0C'),
        "AdwAboutDialog program_name must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\x0C` guard alongside the space relaxation; a stray `\\x0C` would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title` (with text-paginator pipelines treating it as a hard page break), and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the version-
    // helper byte coverage past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}` quadruple
    // to the next C0 control byte. The form-feed byte `\x0C`
    // (0x0C) sits one step above VT (0x0B) and one step below CR
    // (0x0D) in the ASCII C0 block; like its siblings it is a
    // non-printable control byte with no legitimate use inside a
    // semver-shaped version string.
    //
    // The existing `_version_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000C FF — so the version helper's `\x0C`-cleanliness
    // is currently protected *transitively* by that one specific
    // companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a version-suffix separator space
    // (e.g. `"0.0.1 pre-release"` or `"0.0.1 +build"`) would
    // naturally relax the `_has_no_embedded_whitespace` companion
    // — and the human author of that refactor might reasonably
    // restructure the check to only reject specific control
    // bytes (newline, tab) without separately calling out `\x0C`
    // on the assumption that "ASCII whitespace is now allowed".
    // That assumption is wrong: `\x0C` is a control byte without
    // tab-stop semantics, not a layout-friendly whitespace
    // character, and the version slot is rendered as a single-
    // line caption beneath the program name in the dialog header
    // that has no page-break semantics — so dropping the `\x0C`
    // check alongside the space-relaxation would silently regress
    // the no-`\x0C` invariant.
    //
    // None of the existing companions name the `\x0C` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0C` is
    //     ASCII so it slips past;
    //   - `_is_non_empty_and_looks_like_semver` only enforces
    //     non-empty + semver shape;
    //   - `_starts_with_a_digit` / `_does_not_start_with_a_dot` /
    //     `_does_not_end_with_a_dot` only constrain the boundary
    //     bytes;
    //   - `_has_at_least_three_dot_separated_segments` /
    //     `_segments_are_non_empty` only check segment count and
    //     non-emptiness;
    //   - `_matches_cargo_pkg_version` only enforces equality
    //     with `CARGO_PKG_VERSION` (so any `\x0C`-bearing override
    //     would slip past as long as Cargo's pinned version had
    //     matching bytes);
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"0.0.1\x0C"` (form-feed byte
    // lifted from a legacy Cargo.toml-derived version registry
    // authored on a line-printer terminal that used `\x0C` to
    // advance to the next page between version and build-
    // metadata suffix, a `concat!(_, "\x0C", _)` form, a
    // `pandoc`-generated text dump that preserved `\x0C` page-
    // break markers between CHANGELOG version entries, or a
    // hand-edited helper override that lifted the version
    // literal from a page-broken text file) would mis-render in
    // multiple downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_version` setter routes the value into
    // Pango for inline rendering as the version caption beneath
    // the program name — Pango's default rendering of a bare
    // `\x0C` byte is implementation-defined and typically
    // renders as a literal control glyph (a hollow box or tofu-
    // like placeholder), breaking the tidy version-caption
    // layout; (2) the same version string is reused by
    // `_release_notes_version_matches_about_dialog_version` for
    // the "What's New in v<version>" header — a `\x0C` byte in
    // the version would propagate into the release-notes header
    // and mis-render there too; (3) any downstream tooling that
    // scrapes the version slot (release-tracker bots, update-
    // check pings, crash-report assemblers) would propagate the
    // stray `\x0C` byte and trigger the same rendering bug
    // across every downstream surface, with the additional risk
    // that text-paginator pipelines treat the `\x0C` as a hard
    // page break and split the version caption mid-string in
    // printed reports; (4) screen readers that announce the
    // version caption read the `\x0C` as a literal control
    // character or — on some implementations — as a section-
    // break announcement, breaking the version-caption
    // accessibility-tree announcement at the byte boundary.
    //
    // Pinning the no-`\x0C` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than via a future
    // whitespace-relaxation refactor that silently dropped the
    // `\x0C` guard. Current helper returns the value sourced
    // from `CARGO_PKG_VERSION` (no `\x0C` byte), so this test
    // passes today and serves as a forcing function so any
    // future override of the helper — including the eventual
    // landing of a build-metadata-suffixed version string —
    // stays free of form-feed bytes. Continues the version C0
    // control-byte cycle past the just-completed `{null /
    // horizontal-tab / carriage-return / vertical-tab}`
    // quadruple so the helper's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x0C'),
        "AdwAboutDialog version must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\x0C` guard alongside the space relaxation; a stray `\\x0C` would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string (with text-paginator pipelines treating it as a hard page break), and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the
    // application-icon-name byte coverage past the just-
    // completed `{null / horizontal-tab / carriage-return /
    // vertical-tab}` quadruple to the next C0 control byte. The
    // form-feed byte `\x0C` (0x0C) sits one step above VT (0x0B)
    // and one step below CR (0x0D) in the ASCII C0 block; like
    // its siblings it is a non-printable control byte with no
    // legitimate use inside a freedesktop.org reverse-DNS icon-
    // name string.
    //
    // The existing `_application_icon_name_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000C FF — so the application-icon-name helper's
    // `\x0C`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a localized icon-name with a single
    // embedded space (a non-trivial scenario per freedesktop.org
    // icon-naming convention, which forbids spaces in icon names
    // — but a workspace-vendoring refactor or a CI codegen step
    // could relax the `_has_no_embedded_whitespace` companion
    // incorrectly) would naturally drop the `\x0C` check at the
    // same time on the assumption that "ASCII whitespace is now
    // allowed". That assumption is wrong: `\x0C` is a control
    // byte without tab-stop semantics, not a layout-friendly
    // whitespace character, and a `gtk::IconTheme::lookup_by_gicon`
    // call with a `\x0C`-bearing icon name lands in undefined
    // territory across GIO icon-loader implementations.
    //
    // None of the existing companions name the `\x0C` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0C` is
    //     ASCII so it slips past;
    //   - `_is_reverse_dns` / `_has_exactly_four_segments` /
    //     `_starts_with_a_lowercase_ascii_letter` only constrain
    //     segment-count and leading byte;
    //   - `_ends_with_gui_segment` / `_does_not_end_with_a_dot`
    //     / `_does_not_start_with_a_dot` only constrain the
    //     suffix and dot-boundaries;
    //   - `_segments_are_non_empty` only checks segment non-
    //     emptiness;
    //   - `_matches_app_id` / `_program_name_is_segment_of_application_icon_name`
    //     only enforce equality with the app-id and segment
    //     containment with the program name;
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"org.tamx.Paladin\x0C.Gui"`
    // (form-feed byte lifted from a legacy freedesktop.org icon-
    // spec registry authored on a line-printer terminal that
    // used `\x0C` to advance to the next page between reverse-
    // DNS segments, a `concat!(_, "\x0C", _)` form mirroring a
    // mainframe-era icon-name format, a `pandoc`-generated text
    // dump that preserved `\x0C` page-break markers between
    // icon-spec entries, or a hand-edited helper override that
    // pasted from a page-broken text file) would mis-render in
    // multiple downstream surfaces: (1) the `gtk::IconTheme`
    // lookup machinery treats the icon name as a key into the
    // icon cache — a `\x0C`-bearing key would silently miss the
    // cache and fall through to the placeholder fallback icon,
    // masking the bug as a missing-icon surface rather than a
    // malformed-icon-name surface; (2) the matching
    // `gtk::Window::set_icon_name` setter (the icon name is
    // mirrored onto the toplevel window's icon property) routes
    // through GLib's GVariant string-marshalling layer and may
    // surface as a malformed window-icon-name property in the
    // X11 / Wayland protocol exchange, where some compositors
    // silently drop the icon and others render a broken-icon
    // placeholder; (3) the same icon name is mirrored to the
    // AppStream metainfo file's `<id>` field per the §11.4
    // app-id convention — a `\x0C`-bearing icon name would
    // propagate into the metainfo file and fail Flathub's
    // strict reverse-DNS-validating metainfo linter on the next
    // package submission, with the additional risk that text-
    // paginator pipelines treat the `\x0C` as a hard page break
    // and split the metainfo `<id>` mid-string in printed
    // submission reports.
    //
    // Pinning the no-`\x0C` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a downstream
    // icon-cache miss, a malformed-window-icon protocol
    // exchange, or a Flathub metainfo linter failure. Current
    // helper returns the literal `"org.tamx.Paladin.Gui"` (no
    // `\x0C` byte), so this test passes today and serves as a
    // forcing function so any future override of the helper —
    // including the eventual landing of a Flatpak app-id rename
    // — stays free of form-feed bytes. Continues the application-
    // icon-name C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return / vertical-tab}`
    // quadruple so the helper's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x0C'),
        "AdwAboutDialog application_icon_name must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\x0C` guard; a stray `\\x0C` would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, and propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission (with text-paginator pipelines treating it as a hard page break); got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_form_feed_byte() {
    // Defense-in-depth per-byte sibling extending the debug-
    // info-filename byte coverage past the just-completed
    // `{null / horizontal-tab / carriage-return / vertical-tab}`
    // quadruple to the next C0 control byte. The form-feed byte
    // `\x0C` (0x0C) sits one step above VT (0x0B) and one step
    // below CR (0x0D) in the ASCII C0 block; like its siblings
    // it is a non-printable control byte with no legitimate use
    // inside a filesystem filename string.
    //
    // The existing `_debug_info_filename_has_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000C FF — so the debug-info-filename helper's
    // `\x0C`-cleanliness is currently protected *transitively*
    // by that one specific companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a localized filename with a single
    // embedded space (a non-trivial scenario per freedesktop.org
    // file-naming convention but feasible if a localized "Debug
    // information.txt" filename were ever rendered to non-ASCII
    // locales) would naturally relax the
    // `_has_no_embedded_whitespace` companion — and the human
    // author of that refactor might reasonably restructure the
    // check to only reject specific control bytes (newline, tab)
    // without separately calling out `\x0C` on the assumption
    // that "ASCII whitespace is now allowed". That assumption is
    // wrong: `\x0C` is a control byte without tab-stop semantics,
    // not a layout-friendly whitespace character, and a save-
    // to-disk filename with `\x0C` lands in undefined territory
    // across POSIX filesystem implementations (most kernel ports
    // of `open(2)` accept FF in filenames but shell-tooling
    // pipelines and bug-tracker attachment URL renderers treat
    // the byte as either an un-printable control glyph, a page-
    // break artifact, or a dropped byte).
    //
    // None of the existing companions name the `\x0C` byte
    // directly on this helper:
    //   - `_is_ascii_only` pins each byte as ASCII — `\x0C` is
    //     ASCII so it slips past;
    //   - `_returns_paladin_debug_info_txt` exact-value pin only
    //     holds while the literal is unchanged;
    //   - `_does_not_contain_path_separators` /
    //     `_does_not_start_with_a_dot` only constrain the path-
    //     safety and leading-byte boundaries;
    //   - `_contains_exactly_one_period` /
    //     `_extension_is_lowercase_txt` only check dot-count and
    //     suffix;
    //   - `_is_non_empty_single_line_with_txt_extension` only
    //     checks non-empty + single-line + `.txt` suffix shape
    //     (the single-line check uses `str::lines().count() == 1`
    //     which does not split on `\x0C`, so a `\x0C`-bearing
    //     filename like `"pala\x0Cdin-debug-info.txt"` slips
    //     past this companion entirely);
    //   - `_does_not_contain_a_null_byte` /
    //     `_does_not_contain_a_horizontal_tab_byte` /
    //     `_does_not_contain_a_carriage_return_byte` /
    //     `_does_not_contain_a_vertical_tab_byte` each name a
    //     different byte specifically.
    //
    // A regression that landed `"pala\x0Cdin-debug-info.txt"`
    // (form-feed byte lifted from a legacy filename registry
    // authored on a line-printer terminal that used `\x0C` to
    // advance to the next page mid-token, a `concat!(_, "\x0C",
    // _)` form, a `pandoc`-generated text dump that preserved
    // `\x0C` page-break markers between filename-spec entries,
    // or a hand-edited helper override that lifted the filename
    // literal from a page-broken text file) would mis-render in
    // three downstream surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_debug_info_filename` setter routes
    // the value into the dialog's "Save Debug Information…"
    // file-chooser pre-fill — a `\x0C`-bearing filename mis-
    // renders in the GtkFileDialog's filename entry as a literal
    // control glyph (a hollow box or tofu-like placeholder)
    // since `\x0C` has no tab-stop semantics, and may also
    // surface in the suggested-filename display in the file
    // chooser's title bar; (2) when the user saves the debug-
    // info payload to disk, the filesystem `open(2)` call routes
    // the `\x0C`-bearing filename through the kernel VFS layer —
    // most POSIX-conformant kernels (Linux, macOS, BSDs) accept
    // `\x0C` in filenames but many shell-tooling pipelines (`ls`,
    // `find`, `tar`) assume printable-only filenames and either
    // silently strip the `\x0C`, display the file as an un-
    // readable entry, or treat the `\x0C` as a hard page break
    // when echoing the listing to a paginator; (3) the saved
    // file's filename surfaces in any bug-tracker attachment
    // URL or chat-attachment column where the `\x0C` byte mis-
    // renders as a literal control glyph or page-break
    // artifact, confusing the maintainer's triage workflow.
    //
    // Pinning the no-`\x0C` invariant directly on this helper
    // surfaces the regression with a message naming the
    // offending byte at build time rather than as a downstream
    // file-chooser mis-render, a shell-tooling visibility
    // break, or a chat-attachment column-render artifact.
    // Current helper returns the literal `"paladin-debug-info.txt"`
    // (no `\x0C` byte), so this test passes today and serves as
    // a forcing function so any future override of the helper —
    // including the eventual landing of a localized filename —
    // stays free of form-feed bytes. Continues the debug-info-
    // filename C0 control-byte cycle past the just-completed
    // `{null / horizontal-tab / carriage-return / vertical-tab}`
    // quadruple so the helper's byte-composition contract pins
    // each forbidden control byte against a single source of
    // truth.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x0C'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\x0C` guard alongside the space relaxation; a stray `\\x0C` would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, surface as an un-listable file under shell-tooling pipelines (`ls`, `find`, `tar`) that strip non-printable bytes (with text-paginator pipelines treating it as a hard page break), and confuse maintainer triage with control-glyph artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_form_feed_byte() {
    // Cross-helper defense-in-depth sibling looping over the
    // three `AdwAboutDialog` footer URL helpers
    // (`format_app_about_dialog_website`,
    // `format_app_about_dialog_issue_url`,
    // `format_app_about_dialog_support_url`) and pinning each
    // value as free of the `\x0C` form-feed byte (0x0C). Closes
    // the about-dialog form-feed cycle started by the
    // `_developer_name_does_not_contain_a_form_feed_byte`
    // sibling and continued across every byte-pinned helper,
    // completing the URL-helpers' byte-composition contract
    // past the just-finished `{null / horizontal-tab / carriage-
    // return / vertical-tab}` cross-URL quadruple.
    //
    // The existing `url_helpers_contain_no_embedded_whitespace`
    // companion uses `char::is_whitespace()`, which returns true
    // for U+000C FF — so the URL-helpers' `\x0C`-cleanliness is
    // currently protected *transitively* by that one specific
    // companion's broad whitespace check.
    //
    // But that transitive protection is *bundled* with the
    // no-whitespace invariant as a whole: a future refactor that
    // intentionally allowed a URL with a single percent-encoded
    // space (a non-trivial scenario per RFC 3986, which forbids
    // unencoded spaces in URLs but permits `%20` percent-
    // encoding for them — but a workspace-vendoring refactor or
    // a CI codegen step could relax the
    // `_contain_no_embedded_whitespace` companion incorrectly
    // when handling decoded percent-encoded strings) would
    // naturally drop the `\x0C` check at the same time on the
    // assumption that "ASCII whitespace is now allowed". That
    // assumption is wrong: `\x0C` is never a valid byte inside a
    // URL per RFC 3986 (the form-feed byte is not in any of the
    // URL grammar's production rules), so dropping the `\x0C`
    // check alongside the percent-encoded-space relaxation
    // would silently regress the no-`\x0C` invariant.
    //
    // A regression would slip past every existing companion:
    // the `_is_non_empty_https_url[_distinct_*]` per-URL
    // companion (which only checks non-empty + `https://` prefix
    // + no space byte — a `\x0C` byte mid-URL satisfies all
    // three since `\x0C` is not the literal U+0020 SPACE), the
    // `_are_ascii_only` cross-URL companion (`\x0C` is ASCII so
    // it slips past), the `_do_not_end_with_a_trailing_slash`
    // companion (which only constrains the final byte), the
    // `_do_not_contain_a_null_byte` /
    // `_do_not_contain_a_horizontal_tab_byte` /
    // `_do_not_contain_a_carriage_return_byte` /
    // `_do_not_contain_a_vertical_tab_byte` siblings (which
    // each name a different byte specifically), the
    // `_do_not_contain_a_query_string` /
    // `_do_not_contain_a_fragment_anchor` /
    // `_do_not_contain_a_userinfo_at_sign` /
    // `_do_not_contain_a_backslash` siblings (which each name a
    // different byte specifically). None of the existing
    // companions name the `\x0C` byte directly.
    //
    // A regression that landed
    // `"https://github.com\x0CFreedomBen/paladin"` (form-feed
    // byte lifted from a legacy URL registry authored on a
    // line-printer terminal that used `\x0C` to advance to the
    // next page between the host and path, a `concat!(_,
    // "\x0C", _)` form mirroring an FF-paginated URL-table
    // cell, a `pandoc`-generated text dump that preserved
    // `\x0C` page-break markers between URL entries, or a
    // hand-edited helper override that pasted from a page-
    // broken text file) would mis-render in multiple downstream
    // surfaces: (1) the GLib-backed
    // `AdwAboutDialog::set_website` / `set_issue_url` /
    // `set_support_url` setters route the value into Pango for
    // inline rendering as the underlined link label in the
    // dialog footer — Pango's default rendering of a bare
    // `\x0C` byte is implementation-defined and typically
    // renders as a literal control glyph (a hollow box or tofu-
    // like placeholder) since `\x0C` has no tab-stop semantics,
    // breaking the trusted-application surface contract of the
    // link label; (2) when the user clicks the URL, GIO's
    // `gtk_show_uri_full` routes the value through the session's
    // `xdg-open` / portal layer where some URL parsers (WHATWG
    // URL §4.5 implementations) reject `\x0C` outright with
    // `InvalidUrl`, breaking the click-through routing
    // entirely, while others percent-encode the `\x0C` as `%0C`
    // and route to a non-existent URL with a `Bad Request`
    // response surfacing as a confusing browser-level error,
    // with the additional risk that text-paginator pipelines
    // treat the `\x0C` as a hard page break and split the URL
    // mid-token in printed reports; (3) screen readers that
    // announce the URL label read the `\x0C` as a literal
    // control character or — on some implementations — as a
    // section-break announcement, breaking the link-label
    // accessibility-tree announcement at the byte boundary; (4)
    // any downstream tooling that scrapes the URL labels (link-
    // checker bots, broken-link auditors) would propagate the
    // stray `\x0C` byte into the consumer's stream and trigger
    // the same routing failure across every downstream surface.
    //
    // Pinning the no-`\x0C` invariant directly here surfaces
    // the regression with a message naming the offending URL
    // helper at build time rather than as a downstream user-
    // visible mis-rendered link label, a confusing browser-
    // level error on click-through, an inconsistent URL-parser-
    // implementation routing surface, or a link-checker tooling
    // failure. Mirror of the
    // `_url_helpers_do_not_end_with_a_trailing_slash`,
    // `_url_helpers_do_not_contain_a_query_string`,
    // `_url_helpers_do_not_contain_a_fragment_anchor`,
    // `_url_helpers_do_not_contain_a_userinfo_at_sign`,
    // `_url_helpers_do_not_contain_a_backslash`,
    // `_url_helpers_contain_no_embedded_whitespace`,
    // `_url_helpers_are_ascii_only`,
    // `_url_helpers_do_not_contain_a_null_byte`,
    // `_url_helpers_do_not_contain_a_carriage_return_byte`,
    // `_url_helpers_do_not_contain_a_horizontal_tab_byte`, and
    // `_url_helpers_do_not_contain_a_vertical_tab_byte` cross-
    // URL siblings; together they pin the URL byte-composition
    // contract (no whitespace, ASCII-only, no terminal `/`, no
    // `\0`, no `\r`, no `\t`, no `\x0B`, no `\x0C`, no `?`
    // query, no `#` anchor, no `@` userinfo, no `\` path-
    // confusion byte) across all three footer link surfaces
    // against a single source of truth.
    use paladin_gtk::app::model::{
        format_app_about_dialog_issue_url, format_app_about_dialog_support_url,
        format_app_about_dialog_website,
    };

    for (label, url) in [
        ("website", format_app_about_dialog_website()),
        ("issue_url", format_app_about_dialog_issue_url()),
        ("support_url", format_app_about_dialog_support_url()),
    ] {
        assert!(
            !url.contains('\x0C'),
            "AdwAboutDialog {label} must not contain the `\\x0C` form-feed byte (0x0C) — `\\x0C` is never a valid byte inside a URL per RFC 3986 (the form-feed byte is not in any of the URL grammar's production rules); the current `\\x0C`-cleanliness is only protected transitively by `_url_helpers_contain_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future percent-encoded-space relaxation would silently drop the `\\x0C` guard; a stray `\\x0C` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%0C`-encoding implementations (with text-paginator pipelines treating it as a hard page break), break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}
