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
