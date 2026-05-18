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
