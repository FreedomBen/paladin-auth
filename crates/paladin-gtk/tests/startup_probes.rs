// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for `app::model::run_startup_probes` and the
//! shared `startup_state_marker` helper.
//!
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Vault interaction" pins the
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

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Sender};
use std::sync::{Mutex, OnceLock};
use std::thread;

use paladin_gtk::app::model::{run_startup_probes, startup_state_marker, StartupOutcome};
use paladin_gtk::app::state::AppState;
use paladin_gtk::startup_error::StartupErrorSource;

/// Run `f` on a single dedicated thread that owns `gtk4::init()`.
///
/// GTK is thread-pinned: every widget construction and method
/// invocation must happen on the thread that called `gtk_init()`.
/// Cargo's default test runner parallelizes `#[test]` functions
/// across multiple worker threads, so a `gtk_init()` call from the
/// first GTK test reaches success but subsequent GTK tests panic
/// with "GTK may only be used from the main thread" the moment
/// they touch a widget constructor.
///
/// This helper lazily spawns one dedicated `gtk-test-thread` on
/// first call, runs `gtk4::init()` there, and from then on every
/// GTK test ships its body to that thread via a channel. Panics
/// (typically `assert_eq!` / `assert!` failures) are caught and
/// re-raised on the calling test thread so failures show up under
/// the right test name with the right message.
///
/// Returns `false` when `gtk4::init()` failed — typically "no
/// display server" on a developer workstation outside an X / Wayland
/// session. Callers print a skip message and return; CI runs under
/// `xvfb-run` per the Milestone 7 checklist (`tests/gtk_smoke.rs`)
/// and `gtk_init` succeeds there.
fn run_on_gtk_thread<F>(f: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    type GtkJob = Box<dyn FnOnce() + Send>;

    static GTK_SENDER: OnceLock<Option<Mutex<Sender<GtkJob>>>> = OnceLock::new();
    let sender = GTK_SENDER.get_or_init(|| {
        let (job_tx, job_rx) = std::sync::mpsc::channel::<GtkJob>();
        let (ready_tx, ready_rx) = sync_channel::<bool>(0);
        thread::Builder::new()
            .name("gtk-test-thread".to_string())
            .spawn(move || {
                let ok = gtk4::init().is_ok();
                let _ = ready_tx.send(ok);
                if !ok {
                    return;
                }
                while let Ok(job) = job_rx.recv() {
                    job();
                }
            })
            .expect("failed to spawn dedicated GTK test thread");
        match ready_rx.recv() {
            Ok(true) => Some(Mutex::new(job_tx)),
            _ => None,
        }
    });

    let Some(sender) = sender else {
        return false;
    };

    let (done_tx, done_rx) = sync_channel::<thread::Result<()>>(0);
    let job: GtkJob = Box::new(move || {
        let result = catch_unwind(AssertUnwindSafe(f));
        let _ = done_tx.send(result);
    });
    sender
        .lock()
        .expect("dedicated GTK test thread sender mutex poisoned")
        .send(job)
        .expect("dedicated GTK test thread is gone");

    let result = done_rx
        .recv()
        .expect("dedicated GTK test thread dropped the job mid-flight");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    true
}

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
fn format_app_window_default_size_returns_1280_by_960() {
    // The `AppModel`'s `adw::ApplicationWindow::set_default_size`
    // tuple is populated from this helper. The (width, height)
    // pair `(1280, 960)` is double the libadwaita HIG's narrow-
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
        (1280, 960),
        "ApplicationWindow default size matches the doubled libadwaita HIG narrow-window pair",
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
    // referenced by `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Linux desktop integration". Pinning the title through a
    // helper keeps the wording in one place shared by the widget
    // binding and the pure-logic tests in `tests/startup_probes.rs`.
    //
    // No TUI parity: the TUI is a single-process terminal app and
    // has no window-list entry to mirror. Distinct from the in-
    // window dialog titles (`format_unlock_dialog_title`,
    // `format_init_dialog_title`, `format_edit_dialog_title`,
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
fn format_app_search_button_visible_returns_true_when_a_vault_is_open() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `AccountListComponent`: the search-toggle header-bar
    // affordance toggles the `gtk::SearchBar` inside
    // `AccountListComponent`, which is only mounted while the
    // vault is open. The toggle is therefore hidden in every
    // non-vault-open state — `Missing` / `Locked` /
    // `StartupError` — and stays visible during
    // `UnlockedBusy` so the affordance does not disappear when
    // a vault worker spawns. The split matches
    // `state.is_unlocked()` (true for `Unlocked` and
    // `UnlockedBusy`), mirroring the `+` button rule in
    // `format_app_add_button_visible`. This helper pins the
    // visibility rule through one source of truth so the
    // widget binding does not hand-spell `state.is_unlocked()`
    // inline.
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::format_app_search_button_visible;
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
            format_app_search_button_visible(&visible),
            "{visible:?} must show the search-toggle button (vault is open)",
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
            !format_app_search_button_visible(&hidden),
            "no-vault-open state must hide the search-toggle button per §\"Component tree\" > AccountListComponent; got visible for {hidden:?}",
        );
    }
}

#[test]
fn format_app_search_button_visible_matches_format_app_add_button_visible() {
    // Cross-check: the search-toggle and `+` button share one
    // visibility rule — both are header-bar affordances tied
    // to the vault-open state. A drift between the two would
    // surface a half-visible header bar in `UnlockedBusy` (or
    // in `Locked`) which has no meaning in the §"libadwaita
    // usage" rules. Pinning the equivalence guards against
    // an accidental divergence (e.g. someone tightening one
    // to `allows_mutating_menu` without the other).
    use paladin_core::ErrorKind;
    use paladin_gtk::app::model::{
        format_app_add_button_visible, format_app_search_button_visible,
    };
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
        assert_eq!(
            format_app_search_button_visible(&state),
            format_app_add_button_visible(&state),
            "search-toggle and `+` button must share one visibility rule for {state:?}",
        );
    }
}

#[test]
fn apply_app_search_button_visibility_updates_existing_button_for_a_new_state() {
    // Per §"libadwaita usage" and §"Component tree": when
    // `AppModel` transitions between states the search-toggle
    // header-bar affordance must hide/reveal in lockstep with
    // `format_app_search_button_visible`. This helper covers
    // the runtime-update side: a `gtk::ToggleButton` already
    // mounted in the header bar gets `set_visible` called
    // with the new state's value without re-creating the
    // widget. Mirrors `apply_app_add_button_visibility` on
    // the `+` button side.
    if !run_on_gtk_thread(|| {
        use libadwaita::prelude::*;
        use paladin_core::ErrorKind;
        use paladin_gtk::app::model::{
            apply_app_search_button_visibility, format_app_search_button_visible,
        };
        use paladin_gtk::app::state::AppState;
        use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

        let button = gtk4::ToggleButton::new();
        // Pre-set the button to the opposite of the starting
        // expectation so the assertion proves the helper applies
        // the rule rather than reading whatever the constructor
        // happened to default to.
        button.set_visible(false);

        let unlocked = AppState::Unlocked {
            path: std::path::PathBuf::from("/dev/null"),
        };
        apply_app_search_button_visibility(&button, &unlocked);
        assert_eq!(
            button.is_visible(),
            format_app_search_button_visible(&unlocked),
            "apply_app_search_button_visibility must apply format_app_search_button_visible for the Unlocked state",
        );
        assert!(
            button.is_visible(),
            "Unlocked state must show the search-toggle button per §\"Component tree\" > AccountListComponent",
        );

        let locked = AppState::Locked {
            path: std::path::PathBuf::from("/dev/null"),
        };
        apply_app_search_button_visibility(&button, &locked);
        assert_eq!(
            button.is_visible(),
            format_app_search_button_visible(&locked),
            "apply_app_search_button_visibility must apply format_app_search_button_visible for the Locked state",
        );
        assert!(
            !button.is_visible(),
            "Locked state must hide the search-toggle button per §\"Component tree\" > AccountListComponent",
        );

        let busy = AppState::UnlockedBusy {
            path: std::path::PathBuf::from("/dev/null"),
        };
        apply_app_search_button_visibility(&button, &busy);
        assert_eq!(
            button.is_visible(),
            format_app_search_button_visible(&busy),
            "apply_app_search_button_visibility must apply format_app_search_button_visible for the UnlockedBusy state",
        );
        assert!(
            button.is_visible(),
            "UnlockedBusy state must keep the search-toggle button visible — the SearchBar filter is non-mutating",
        );

        let errored = AppState::StartupError {
            path: None,
            error: StartupError {
                source: StartupErrorSource::PathResolution,
                kind: ErrorKind::IoError,
                rendered: String::from("resolve_failed"),
            },
        };
        apply_app_search_button_visibility(&button, &errored);
        assert_eq!(
            button.is_visible(),
            format_app_search_button_visible(&errored),
            "apply_app_search_button_visibility must apply format_app_search_button_visible for the StartupError state",
        );
        assert!(
            !button.is_visible(),
            "StartupError state must hide the search-toggle button — no vault is open to search",
        );
    }) {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
    }
}

#[test]
fn format_app_search_toggle_msg_active_emits_set_search_mode_enabled_true() {
    // The header-bar `gtk::ToggleButton::connect_toggled`
    // handler is wired to dispatch through this helper so the
    // active-flag → `AccountListMsg::SetSearchModeEnabled`
    // mapping stays in pure logic. When the user toggles the
    // header-bar button on, the SearchBar inside
    // `AccountListComponent` must reveal — i.e. `set_search_mode(true)`
    // — and vice versa. Pinning the mapping in a helper means
    // the widget binding does not hand-spell the
    // `active → AccountListMsg::SetSearchModeEnabled` projection
    // inline.
    use paladin_gtk::account_list::AccountListMsg;
    use paladin_gtk::app::model::format_app_search_toggle_msg;

    assert_eq!(
        format_app_search_toggle_msg(true),
        AccountListMsg::SetSearchModeEnabled(true),
        "toggling the search-toggle button on must dispatch SetSearchModeEnabled(true) to reveal the SearchBar",
    );
    assert_eq!(
        format_app_search_toggle_msg(false),
        AccountListMsg::SetSearchModeEnabled(false),
        "toggling the search-toggle button off must dispatch SetSearchModeEnabled(false) to hide the SearchBar",
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
    // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage") rather
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
    // `format_app_menu_keyboard_shortcuts_action`,
    // `format_app_menu_about_action`); together they pin all seven
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
    // Companion of the seven primary-menu action-target helpers
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
    // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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
    // `[(<Control><Shift>n, app.add), (<Control>q, app.quit),
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
    // `format_app_menu_keyboard_shortcuts_action_name`,
    // `format_app_menu_about_action_name`); together they pin
    // all seven primary-menu entries' bare SimpleAction names
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
    // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
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
    // can iterate `[(<Control><Shift>n, app.add), (<Control>q, app.quit), …]`
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
fn format_app_menu_keyboard_shortcuts_label_returns_keyboard_shortcuts() {
    // The `AppModel`'s primary `gio::Menu` "Keyboard Shortcuts"
    // entry's label is populated from this helper. The wording
    // (`"Keyboard Shortcuts"`) names the surface the entry opens
    // (the `gtk::ShortcutsWindow` built by
    // `shortcuts_window::build_app_shortcuts_window`) and uses the
    // bare label — no trailing horizontal-ellipsis — because the
    // shortcuts window is informational rather than a request for
    // input (same convention as `Preferences` and `About`).
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_label;

    assert_eq!(
        format_app_menu_keyboard_shortcuts_label(),
        "Keyboard Shortcuts",
        "primary menu Keyboard Shortcuts entry uses the GNOME-canonical bare label (no ellipsis)",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_label_does_not_carry_ellipsis() {
    // The shortcuts window is informational, so the GNOME-HIG
    // ellipsis convention (reserved for entries that collect
    // further input before committing) does not apply. Pinning a
    // no-ellipsis invariant alongside the full-string assertion
    // guards against an accidental rename that would drift back
    // to an older HIG style.
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_label;

    let label = format_app_menu_keyboard_shortcuts_label();
    assert!(
        !label.ends_with('\u{2026}'),
        "Keyboard Shortcuts menu label must not end with the horizontal-ellipsis character (U+2026); got {label:?}",
    );
    assert!(
        !label.ends_with("..."),
        "Keyboard Shortcuts menu label must not end with three ASCII periods either; got {label:?}",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_action_returns_app_shortcuts() {
    // The `AppModel`'s primary `gio::Menu` "Keyboard Shortcuts"
    // entry's `detailed_action_name` is populated from this
    // helper. The wording (`"app.shortcuts"`) is the fully-
    // qualified action target the `gio::Menu` resolves against
    // the application's `app` action group, parallel to
    // `app.preferences` / `app.about` / `app.quit`.
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_action;

    assert_eq!(
        format_app_menu_keyboard_shortcuts_action(),
        "app.shortcuts",
        "primary menu Keyboard Shortcuts entry uses the `app.shortcuts` action target so the menu resolves against the bundled SimpleActionGroup",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_action_uses_app_group_prefix() {
    // Defense-in-depth: the action target must start with the
    // shared `app.` group prefix returned by
    // `format_app_action_group_name`. Catches a future rename of
    // the helper or the prefix that would otherwise silently
    // unbind the menu activation.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_keyboard_shortcuts_action,
    };

    let prefix = format!("{}.", format_app_action_group_name());
    let action = format_app_menu_keyboard_shortcuts_action();
    assert!(
        action.starts_with(&prefix),
        "Keyboard Shortcuts action target {action:?} must start with the shared group prefix {prefix:?}",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_action_name_returns_shortcuts() {
    // The widget binding hands this bare name to
    // `gio::SimpleAction::new(name, None)` so the action joins
    // the bundled `app` action group. The wording
    // (`"shortcuts"`) is the bare single-word name parallel to
    // `"preferences"`, `"about"`, and `"quit"` — chosen over the
    // GTK-canonical `"show-help-overlay"` so this entry stays
    // uniform with the rest of the primary menu.
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_action_name;

    assert_eq!(
        format_app_menu_keyboard_shortcuts_action_name(),
        "shortcuts",
        "Keyboard Shortcuts bare action name must be the single-word `shortcuts`",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_action_name_has_no_separator_or_whitespace() {
    // The bare name is consumed by `gio::SimpleAction::new`,
    // which treats embedded `.` as a group/action separator and
    // would reject whitespace. Guard against a future rename
    // that accidentally spelled the bare name with the prefix or
    // surrounding whitespace.
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_action_name;

    let bare = format_app_menu_keyboard_shortcuts_action_name();
    assert!(
        !bare.contains('.'),
        "bare action name {bare:?} must not embed the `<group>.<action>` separator",
    );
    assert!(
        !bare.chars().any(char::is_whitespace),
        "bare action name {bare:?} must not contain whitespace",
    );
    assert!(!bare.is_empty(), "bare action name must be non-empty");
}

#[test]
fn format_app_menu_keyboard_shortcuts_action_name_round_trips_with_group_and_target() {
    // Cross-check: joining the shared group prefix with the bare
    // name must reproduce the fully-qualified action target.
    // Catches a future rename of any one of the three helpers
    // without updating its siblings.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_keyboard_shortcuts_action,
        format_app_menu_keyboard_shortcuts_action_name,
    };

    let group = format_app_action_group_name();
    let bare = format_app_menu_keyboard_shortcuts_action_name();
    let full = format_app_menu_keyboard_shortcuts_action();
    assert_eq!(
        format!("{group}.{bare}"),
        full,
        "`<group>.<action_name>` join must reproduce the fully-qualified Keyboard Shortcuts action target",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_accelerator_returns_control_question() {
    // The widget binding hands this accelerator string to
    // `gio::Application::set_accels_for_action("app.shortcuts",
    // &["<Control>question"])`. The `<Control>question` spelling
    // is the GNOME-HIG canonical "show keyboard shortcuts"
    // shortcut every modern GNOME app uses; the bare `question`
    // keysym (lowercase, gtk's bare key name for `?`) matches
    // `gtk::accelerator_parse`'s recognised spelling.
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_accelerator;

    assert_eq!(
        format_app_menu_keyboard_shortcuts_accelerator(),
        "<Control>question",
        "Keyboard Shortcuts accelerator must be the GNOME-canonical `<Control>question`",
    );
}

#[test]
fn format_app_menu_keyboard_shortcuts_accelerator_is_non_empty_and_well_formed() {
    // Defensive: the accelerator string is consumed by
    // `gio::Application::set_accels_for_action`, which accepts
    // any non-empty gtk-rs accelerator spelling. An accidental
    // empty string or whitespace-leading entry would silently
    // unbind the shortcut at runtime — guard against that drift
    // here so the `<Ctrl>?` shortcut stays wired. Mirrors the
    // structural assertions on
    // `format_app_menu_quit_accelerator_is_non_empty_and_well_formed`.
    use paladin_gtk::app::model::format_app_menu_keyboard_shortcuts_accelerator;

    let accel = format_app_menu_keyboard_shortcuts_accelerator();
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
    // future rename of any one of the per-entry helpers without
    // updating its siblings.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_menu_about_action,
        format_app_menu_about_action_name, format_app_menu_export_action,
        format_app_menu_export_action_name, format_app_menu_import_action,
        format_app_menu_import_action_name, format_app_menu_keyboard_shortcuts_action,
        format_app_menu_keyboard_shortcuts_action_name, format_app_menu_passphrase_action,
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
            "Keyboard Shortcuts",
            format_app_menu_keyboard_shortcuts_action_name(),
            format_app_menu_keyboard_shortcuts_action(),
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
fn format_app_add_button_accelerator_returns_control_shift_n() {
    // The header-bar `+` button's `gio::SimpleAction` is wired
    // to the `<Control><Shift>n` keyboard accelerator per
    // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"libadwaita usage" >
    // "Header bar > Add" — the GNOME-HIG "New X" pattern (e.g.
    // Files' "New Folder"). The single-modifier slot `<Control>n`
    // is reserved for the account-list "move one row down" mirror
    // in `account_list::dispatch_list_box_nav` /
    // `account_list::dispatch_search_entry_to_list_nav`, so Add
    // lives on the compound `<Control><Shift>` slot instead. The
    // widget binding hands this accelerator string to
    // `gio::Application::set_accels_for_action(format_app_add_button_action(),
    //  &[format_app_add_button_accelerator()])` so the menu and
    // button-driven activation paths share the same shortcut
    // surface against a single source of truth. Pinning the
    // accelerator here keeps the docstring references and the
    // wiring helper aligned without re-spelling the string in two
    // places.
    //
    // The `<Control><Shift>n` spelling is the gtk-rs
    // `accels_for_action` form (uppercase modifier names in angle
    // brackets, lowercase key letter); `Primary` would also resolve
    // on Linux but `<Control>` matches the existing in-source
    // documentation so we keep the docstring and the helper in
    // lockstep.
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
        "<Control><Shift>n",
        "header-bar + button accelerator must be the gtk-rs `<Control><Shift>n` form for `set_accels_for_action`",
    );
}

#[test]
fn format_app_window_accelerator_bindings_returns_five_pinned_pairs_in_order() {
    // The application-window wiring iterates this array against
    // `gio::Application::set_accels_for_action(target, &[accel])`
    // for every pinned keyboard surface (Add, Quit, Preferences,
    // Keyboard Shortcuts, Copy Next Code). The order matches the
    // pinned-accelerator helper sequence
    // (`format_app_add_button_accelerator`,
    //  `format_app_menu_quit_accelerator`,
    //  `format_app_menu_preferences_accelerator`,
    //  `format_app_menu_keyboard_shortcuts_accelerator`,
    //  `format_app_copy_next_code_accelerator`) and each pair
    // sources its two slots from the matching `_accelerator` and
    // `_action` helpers so a future rename of any one helper
    // propagates through the bindings instead of drifting per-
    // entry.
    //
    // The widget binding consumes this array via a single
    // `for (accel, target) in
    //  format_app_window_accelerator_bindings()` loop, so the
    // wiring stays a single iteration over the pinned source of
    // truth instead of five hand-spelled
    // `set_accels_for_action` calls that could silently drift in
    // order or coverage.
    use paladin_gtk::app::model::{
        format_app_add_button_accelerator, format_app_add_button_action,
        format_app_copy_next_code_accelerator, format_app_copy_next_code_action,
        format_app_menu_keyboard_shortcuts_accelerator, format_app_menu_keyboard_shortcuts_action,
        format_app_menu_preferences_accelerator, format_app_menu_preferences_action,
        format_app_menu_quit_accelerator, format_app_menu_quit_action,
        format_app_window_accelerator_bindings,
    };

    let bindings = format_app_window_accelerator_bindings();
    assert_eq!(
        bindings.len(),
        5,
        "the five pinned keyboard surfaces (Add, Quit, Preferences, Keyboard Shortcuts, Copy Next Code) form the entire accelerator surface today",
    );
    assert_eq!(
        bindings[0],
        (
            format_app_add_button_accelerator(),
            format_app_add_button_action()
        ),
        "first binding must be the header-bar + button's `<Control><Shift>n` -> `app.add`",
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
    assert_eq!(
        bindings[3],
        (
            format_app_menu_keyboard_shortcuts_accelerator(),
            format_app_menu_keyboard_shortcuts_action()
        ),
        "fourth binding must be the Keyboard Shortcuts menu entry's `<Control>question` -> `app.shortcuts`",
    );
    assert_eq!(
        bindings[4],
        (
            format_app_copy_next_code_accelerator(),
            format_app_copy_next_code_action()
        ),
        "fifth binding must be the Copy Next Code accelerator's `<Control><Shift>c` -> `app.copy-next-code`",
    );
}

#[test]
fn format_app_copy_next_code_accelerator_returns_control_shift_c() {
    // Pins the gtk-rs accelerator spelling
    // `"<Control><Shift>c"`. The widget binding hands this
    // verbatim to `gio::Application::set_accels_for_action`
    // through the `format_app_window_accelerator_bindings`
    // iteration, so a typo here would silently unbind the
    // shortcut at runtime. The
    // `format_app_window_accelerator_bindings_parse_via_gtk_accelerator_parse`
    // test additionally rounds the spelling through
    // `gtk::accelerator_parse` to catch unknown-keysym typos.
    use paladin_gtk::app::model::format_app_copy_next_code_accelerator;

    assert_eq!(
        format_app_copy_next_code_accelerator(),
        "<Control><Shift>c",
        "Ctrl+Shift+C accelerator must use the gtk-rs `<Control><Shift>c` spelling per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §\"Next-code column implementation\"",
    );
}

#[test]
fn format_app_copy_next_code_action_returns_app_copy_next_code() {
    // Pins the fully-qualified `"app.copy-next-code"` action
    // target. The widget binding hands this verbatim to
    // `gio::Application::set_accels_for_action` through the
    // `format_app_window_accelerator_bindings` iteration; the
    // `"app."` prefix names the bundled application action
    // group (`format_app_action_group_name`) the action is
    // registered on by `build_app_window_action_group`.
    use paladin_gtk::app::model::format_app_copy_next_code_action;

    assert_eq!(
        format_app_copy_next_code_action(),
        "app.copy-next-code",
        "Ctrl+Shift+C action target must be the fully-qualified `app.copy-next-code` form so `set_accels_for_action` and the menu/action-group wiring resolve through the same group",
    );
}

#[test]
fn format_app_copy_next_code_action_name_returns_copy_next_code() {
    // Pins the bare `"copy-next-code"` action name passed to
    // `gio::SimpleAction::new(..., None)` by
    // `build_app_copy_next_code_action`. The fully-qualified
    // `"app.copy-next-code"` returned by
    // `format_app_copy_next_code_action` is the
    // `format_app_action_group_name` group prefix joined to
    // this bare name via the `<group>.<action>` separator.
    use paladin_gtk::app::model::format_app_copy_next_code_action_name;

    assert_eq!(
        format_app_copy_next_code_action_name(),
        "copy-next-code",
        "Ctrl+Shift+C bare action name must be `copy-next-code` so the `gio::SimpleAction::new(..., None)` registration matches the fully-qualified `app.copy-next-code` target",
    );
}

#[test]
fn format_app_copy_next_code_action_name_matches_action_after_group_prefix_strip() {
    // Cross-helper invariant: the bare action name must equal
    // the fully-qualified action target with the `"app."`
    // group-prefix stripped. Guards against a future rename
    // updating one helper without the other, which would
    // silently break the `app.copy-next-code` action-group
    // resolution.
    use paladin_gtk::app::model::{
        format_app_action_group_name, format_app_copy_next_code_action,
        format_app_copy_next_code_action_name,
    };

    let prefix = format!("{}.", format_app_action_group_name());
    let stripped = format_app_copy_next_code_action()
        .strip_prefix(&prefix)
        .expect("`format_app_copy_next_code_action` must start with the `app.` group prefix");
    assert_eq!(
        stripped,
        format_app_copy_next_code_action_name(),
        "the bare action name (`copy-next-code`) must equal the fully-qualified target (`app.copy-next-code`) minus the `app.` group prefix",
    );
}

#[test]
fn format_app_window_accelerator_bindings_targets_are_distinct() {
    // Defensive: `set_accels_for_action` overrides any prior
    // binding for the same target, so a duplicated target slot
    // in the bindings array would silently lose the earlier
    // accelerator without surfacing a compile-time error. Guard
    // against that drift here so the four pinned accelerator
    // surfaces (Add, Quit, Preferences, Keyboard Shortcuts) stay
    // disjoint.
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
    if !run_on_gtk_thread(|| {
        use gtk4::glib::translate::IntoGlib;
        use paladin_gtk::app::model::format_app_window_accelerator_bindings;

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
    }) {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_are_distinct() {
    // Defensive companion to
    // `format_app_window_accelerator_bindings_targets_are_distinct`
    // on the accelerator side: two pinned surfaces sharing the
    // same accelerator (e.g. an accidental `<Control>q` on both
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
fn format_app_primary_menu_entries_returns_seven_entries_in_pinned_order() {
    // The `AppModel`'s primary `gio::Menu` is built by appending
    // each entry's (label, detailed-action-name) pair in the
    // §"libadwaita usage" sequence: Import, Export, Passphrase,
    // Preferences, Keyboard Shortcuts, About Paladin, Quit. This
    // helper returns the seven pairs in order so the widget
    // binding does not need to hand-spell each `menu.append(...)`
    // call against the individual `format_app_menu_*_label` /
    // `_action` helpers, keeping the menu structure pinned to a
    // single source of truth.
    use paladin_gtk::app::model::{
        format_app_menu_about_action, format_app_menu_about_label, format_app_menu_export_action,
        format_app_menu_export_label, format_app_menu_import_action, format_app_menu_import_label,
        format_app_menu_keyboard_shortcuts_action, format_app_menu_keyboard_shortcuts_label,
        format_app_menu_passphrase_action, format_app_menu_passphrase_label,
        format_app_menu_preferences_action, format_app_menu_preferences_label,
        format_app_menu_quit_action, format_app_menu_quit_label, format_app_primary_menu_entries,
    };

    let entries = format_app_primary_menu_entries();
    assert_eq!(
        entries.len(),
        7,
        "primary menu must carry exactly seven entries; got {}",
        entries.len(),
    );

    let expected: [(&'static str, &'static str); 7] = [
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
            format_app_menu_keyboard_shortcuts_label(),
            format_app_menu_keyboard_shortcuts_action(),
        ),
        (
            format_app_menu_about_label(),
            format_app_menu_about_action(),
        ),
        (format_app_menu_quit_label(), format_app_menu_quit_action()),
    ];
    assert_eq!(
        entries, expected,
        "primary menu entries must follow the pinned §\"libadwaita usage\" sequence (Import, Export, Passphrase, Preferences, Keyboard Shortcuts, About, Quit) and pair each label with its fully-qualified action target",
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
    if !run_on_gtk_thread(|| {
        use paladin_gtk::app::model::{
            build_app_about_dialog, format_app_about_dialog_application_icon_name,
            format_app_about_dialog_artists, format_app_about_dialog_comments,
            format_app_about_dialog_copyright, format_app_about_dialog_debug_info,
            format_app_about_dialog_debug_info_filename, format_app_about_dialog_designers,
            format_app_about_dialog_developer_name, format_app_about_dialog_developers,
            format_app_about_dialog_documenters, format_app_about_dialog_issue_url,
            format_app_about_dialog_license_markup, format_app_about_dialog_license_type,
            format_app_about_dialog_program_name, format_app_about_dialog_release_notes,
            format_app_about_dialog_release_notes_version, format_app_about_dialog_support_url,
            format_app_about_dialog_translator_credits, format_app_about_dialog_version,
            format_app_about_dialog_website,
        };

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
            dialog.license(),
            format_app_about_dialog_license_markup().as_str(),
            "AdwAboutDialog license body must be sourced from format_app_about_dialog_license_markup (the markup-safe escape of the gresource-bundled AGPL-3.0-or-later text) so the dialog footer renders without a Pango markup parse failure",
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
        let artists_actual: Vec<String> =
            dialog.artists().iter().map(ToString::to_string).collect();
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
    }) {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
    }
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
fn format_app_window_action_names_lists_the_seven_primary_menu_entries_then_add_then_copy_next_code(
) {
    // Per §"libadwaita usage" / §"Component tree" /
    // §"Next-code column implementation": the application's
    // `app` action group bundles the seven primary-menu bare
    // action names (Import, Export, Passphrase, Preferences,
    // Keyboard Shortcuts, About, Quit) with the header-bar `+`
    // button's bare Add action name and the `Ctrl+Shift+C`
    // "copy selected row's next code" bare action name. This
    // helper returns all nine names in a fixed-size array so
    // the widget binding can iterate without allocating a
    // `Vec` per `init` call. The pinned order keeps the menu
    // entries first (matching the §"libadwaita usage" sequence),
    // appends Add, and ends with Copy Next Code so callers
    // walking the array can stop at index 6 for menu-only
    // loops and the full length for action-group loops.
    use paladin_gtk::app::model::{
        format_app_add_button_action_name, format_app_copy_next_code_action_name,
        format_app_primary_menu_action_names, format_app_window_action_names,
    };

    let combined = format_app_window_action_names();
    let menu = format_app_primary_menu_action_names();
    let add = format_app_add_button_action_name();
    let copy_next = format_app_copy_next_code_action_name();

    assert_eq!(
        combined.len(),
        menu.len() + 2,
        "format_app_window_action_names must return exactly one entry per primary menu action plus the Add action plus the Copy Next Code action",
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
        "format_app_window_action_names[menu.len()] must be format_app_add_button_action_name",
    );
    assert_eq!(
        combined[menu.len() + 1],
        copy_next,
        "format_app_window_action_names must end with format_app_copy_next_code_action_name",
    );
}

#[test]
fn dispatch_app_window_action_routes_copy_next_code_to_copy_next_code_accelerator() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Next-code
    // column implementation": the `Ctrl+Shift+C` accelerator
    // and the bundled `"copy-next-code"` `gio::SimpleAction`
    // both activate the bare action name
    // `format_app_copy_next_code_action_name()` =
    // `"copy-next-code"`, which the dispatch table routes to
    // `AppMsg::CopyNextCodeAccelerator`. The handler resolves
    // the live `AccountListComponent`'s selection / kind /
    // Next-column-visibility triple and (on a TOTP row)
    // re-dispatches `AppMsg::AccountListAction(CopyNextCode(id))`
    // — the same pipeline the per-row Next cell click already
    // uses. The action is always enabled so this dispatch can
    // arrive in every `AppState`; the runtime gate
    // (HOTP rejection / no selection / hidden Next column /
    // unmounted controller all collapse to silent no-op) lives
    // in the `update` arm.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_copy_next_code_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_copy_next_code_action_name());
    assert!(
        matches!(msg, Some(AppMsg::CopyNextCodeAccelerator)),
        "dispatch_app_window_action must route the copy-next-code bare action name to AppMsg::CopyNextCodeAccelerator; got {msg:?}",
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
fn dispatch_app_window_action_routes_keyboard_shortcuts_to_open_keyboard_shortcuts() {
    // Per `docs/DESIGN.md` §7 and `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Keyboard Shortcuts window": the application menu's
    // "Keyboard Shortcuts" entry and the `<Control>question`
    // accelerator both activate the bare action name
    // `format_app_menu_keyboard_shortcuts_action_name()` =
    // `"shortcuts"`, which the dispatch table routes to
    // `AppMsg::OpenKeyboardShortcuts`. The handler then builds and
    // presents a fresh `gtk::ShortcutsWindow` via
    // `shortcuts_window::build_app_shortcuts_window`. Keyboard
    // Shortcuts is always enabled, so this dispatch can arrive in
    // every `AppState`.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, format_app_menu_keyboard_shortcuts_action_name, AppMsg,
    };

    let msg = dispatch_app_window_action(format_app_menu_keyboard_shortcuts_action_name());
    assert!(
        matches!(msg, Some(AppMsg::OpenKeyboardShortcuts)),
        "dispatch_app_window_action must route the keyboard-shortcuts bare action name to AppMsg::OpenKeyboardShortcuts; got {msg:?}",
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
    if !run_on_gtk_thread(|| {
        use libadwaita::prelude::*;
        use paladin_core::ErrorKind;
        use paladin_gtk::app::model::{
            apply_app_add_button_sensitive, format_app_add_button_sensitive,
        };
        use paladin_gtk::app::state::AppState;
        use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

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
    }) {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
    }
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
    if !run_on_gtk_thread(|| {
        use libadwaita::prelude::*;
        use paladin_core::ErrorKind;
        use paladin_gtk::app::model::{
            apply_app_add_button_visibility, format_app_add_button_visible,
        };
        use paladin_gtk::app::state::AppState;
        use paladin_gtk::startup_error::{StartupError, StartupErrorSource};

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
    }) {
        println!("skipping: gtk::init failed (no display server); CI covers this under xvfb-run");
    }
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
    // `+` button's `"app.add"` target so the `<Ctrl><Shift>N`
    // accelerator wired via
    // `gio::Application::set_accels_for_action("app.add",
    // &["<Control><Shift>n"])` resolves through this group.
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
    // state except `Unlocked` per §"libadwaita usage". Keyboard
    // Shortcuts, About, and Quit stay enabled everywhere. Catches
    // a future bundling change that accidentally inverted the
    // sensitivity rule for any of the seven actions.
    use libadwaita::prelude::*;
    use paladin_gtk::app::model::{
        build_app_primary_action_group, format_app_menu_about_action_name,
        format_app_menu_export_action_name, format_app_menu_import_action_name,
        format_app_menu_keyboard_shortcuts_action_name, format_app_menu_passphrase_action_name,
        format_app_menu_preferences_action_name, format_app_menu_quit_action_name,
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
        format_app_menu_keyboard_shortcuts_action_name(),
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
fn format_app_primary_menu_action_names_returns_seven_bare_names_in_pinned_order() {
    // Companion to `format_app_primary_menu_entries`: the widget
    // binding registers a `gio::SimpleAction` for each primary-
    // menu entry on the application's `app` action group. This
    // helper returns the seven bare action names in the
    // §"libadwaita usage" sequence (Import, Export, Passphrase,
    // Preferences, Keyboard Shortcuts, About, Quit), parallel to
    // `format_app_primary_menu_entries`, so the SimpleAction-
    // registration loop and the `gio::Menu::append` loop iterate
    // over a single pinned source of truth.
    use paladin_gtk::app::model::{
        format_app_menu_about_action_name, format_app_menu_export_action_name,
        format_app_menu_import_action_name, format_app_menu_keyboard_shortcuts_action_name,
        format_app_menu_passphrase_action_name, format_app_menu_preferences_action_name,
        format_app_menu_quit_action_name, format_app_primary_menu_action_names,
    };

    let names = format_app_primary_menu_action_names();
    assert_eq!(
        names.len(),
        7,
        "primary menu must register exactly seven SimpleActions; got {}",
        names.len(),
    );
    assert_eq!(
        names,
        [
            format_app_menu_import_action_name(),
            format_app_menu_export_action_name(),
            format_app_menu_passphrase_action_name(),
            format_app_menu_preferences_action_name(),
            format_app_menu_keyboard_shortcuts_action_name(),
            format_app_menu_about_action_name(),
            format_app_menu_quit_action_name(),
        ],
        "primary menu bare action names must follow the pinned §\"libadwaita usage\" sequence (Import, Export, Passphrase, Preferences, Keyboard Shortcuts, About, Quit)",
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
    // per §"In-flight effect ownership"; Keyboard Shortcuts, About,
    // and Quit stay enabled in every state.
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
        assert_eq!(
            sens.len(),
            7,
            "primary menu must carry exactly seven entries"
        );
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
            "Keyboard Shortcuts must stay enabled for state={state:?} per §\"libadwaita usage\"",
        );
        assert!(
            sens[5],
            "About must stay enabled for state={state:?} per §\"libadwaita usage\"",
        );
        assert!(
            sens[6],
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
        sens, [true; 7],
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
    // copyright notice. Paladin is AGPL-3.0-or-later (docs/DESIGN.md
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
fn format_app_about_dialog_license_type_returns_custom() {
    // Per docs/IMPLEMENTATION_PLAN_04_GTK.md §"Milestone 7 checklist"
    // → "About dialog": the AGPL-3.0-or-later license text is
    // shipped in the gresource bundle and surfaced through
    // `AdwAboutDialog::license-type` set to `Custom` with the
    // bundled text. Pinning `License::Custom` here keeps the
    // dialog wired to the bundled text (via the companion
    // `format_app_about_dialog_license_text` helper) rather than
    // letting the toolkit render the generic GTK-shipped
    // `Agpl30` boilerplate, so the dialog footer license panel
    // shows the verbatim project LICENSE file from the repo
    // root.
    use paladin_gtk::app::model::format_app_about_dialog_license_type;
    use relm4::gtk;

    assert_eq!(
        format_app_about_dialog_license_type(),
        gtk::License::Custom,
        "AdwAboutDialog license-type must be `gtk::License::Custom` so the bundled AGPL-3.0-or-later text from `format_app_about_dialog_license_text` is the visible license body",
    );
}

#[test]
fn format_app_about_dialog_license_type_is_not_one_of_the_toolkit_shipped_gpl_family_variants() {
    // Defense-in-depth: catch an accidental swap with any of the
    // toolkit-shipped license-text variants (`Agpl30` /
    // `Agpl30Only` / `Gpl30` / `Gpl30Only` / `Lgpl30` /
    // `Lgpl30Only`). Each of those tells `AdwAboutDialog` to
    // render the boilerplate text shipped with the toolkit
    // rather than the bundled `format_app_about_dialog_license_text`
    // body. The docs/IMPLEMENTATION_PLAN_04_GTK.md §"Milestone 7" /
    // "About dialog" contract specifically calls for the
    // bundled LICENSE text — anything other than `Custom` would
    // bypass the gresource-bundled license body.
    use paladin_gtk::app::model::format_app_about_dialog_license_type;
    use relm4::gtk;

    let license = format_app_about_dialog_license_type();
    for forbidden in [
        gtk::License::Unknown,
        gtk::License::Agpl30,
        gtk::License::Agpl30Only,
        gtk::License::Gpl30,
        gtk::License::Gpl30Only,
        gtk::License::Lgpl30,
        gtk::License::Lgpl30Only,
    ] {
        assert_ne!(
            license, forbidden,
            "AdwAboutDialog license-type must be `Custom` so the bundled LICENSE body is the visible license; got {forbidden:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_license_text_matches_repository_license_file() {
    // Per docs/IMPLEMENTATION_PLAN_04_GTK.md §"Milestone 7 checklist"
    // → "About dialog" — "Ship the AGPL-3.0-or-later license
    // text in the gresource bundle and surface it through
    // `AdwAboutDialog::license-type` set to `Custom` with the
    // bundled text." The helper must return the verbatim text
    // of the repo-root `LICENSE` file so the dialog license body
    // and the AGPL-3.0-or-later source-of-truth stay in lockstep
    // without a manual duplicate. `include_str!` on the source
    // tree's `LICENSE` file is the canonical channel for the
    // body; the matching gresource entry under
    // `format_app_about_dialog_license_resource_path()` ships
    // the same bytes for inspectors that walk the bundle.
    use paladin_gtk::app::model::format_app_about_dialog_license_text;

    let expected = include_str!("../../../LICENSE");
    assert_eq!(
        format_app_about_dialog_license_text(),
        expected,
        "AdwAboutDialog license text must match the repo-root LICENSE file verbatim",
    );
}

#[test]
fn format_app_about_dialog_license_text_starts_with_the_gnu_affero_general_public_license_header() {
    // Sanity check: the AGPL-3.0-or-later body shipped by the
    // FSF opens with the canonical
    // "GNU AFFERO GENERAL PUBLIC LICENSE" header. Asserting the
    // header is present here catches an accidental swap with a
    // GPL / LGPL body or a corrupted LICENSE file before the
    // visible dialog shows the wrong license to users.
    use paladin_gtk::app::model::format_app_about_dialog_license_text;

    let text = format_app_about_dialog_license_text();
    assert!(
        text.contains("GNU AFFERO GENERAL PUBLIC LICENSE"),
        "AdwAboutDialog license text must contain the canonical FSF AGPL header; got first 120 chars: {:?}",
        text.chars().take(120).collect::<String>(),
    );
}

#[test]
fn format_app_about_dialog_license_text_carries_version_3_marker() {
    // Defense-in-depth: AGPL-3.0-or-later — the body must be
    // the version-3 license, not an accidental swap with v1 or
    // v2 of the AGPL or GPL. The FSF AGPLv3 body's preamble
    // line "Version 3, 19 November 2007" is the canonical
    // marker; asserting it is present catches a regression
    // where the LICENSE file is replaced with a wrong-version
    // body.
    use paladin_gtk::app::model::format_app_about_dialog_license_text;

    let text = format_app_about_dialog_license_text();
    assert!(
        text.contains("Version 3, 19 November 2007"),
        "AdwAboutDialog license text must carry the AGPLv3 preamble version marker; got first 200 chars: {:?}",
        text.chars().take(200).collect::<String>(),
    );
}

#[test]
fn format_app_about_dialog_license_text_is_non_empty() {
    // A blank license body would render an empty footer panel
    // — worse than rendering the toolkit boilerplate, since the
    // user would see "License: (nothing)". Pin the body as
    // non-empty so a future regression that nukes the LICENSE
    // file or swaps the helper to `""` surfaces here as a
    // failing test.
    use paladin_gtk::app::model::format_app_about_dialog_license_text;

    assert!(
        !format_app_about_dialog_license_text().is_empty(),
        "AdwAboutDialog license text must be non-empty",
    );
}

#[test]
fn format_app_about_dialog_license_text_does_not_contain_a_null_byte() {
    // Defense-in-depth: GTK / GObject string properties are
    // NUL-terminated. A NUL byte embedded in the license body
    // would truncate the rendered text mid-license. The
    // upstream FSF AGPLv3 body is plain ASCII and contains no
    // NULs; pinning the absence catches a regression where the
    // LICENSE file is replaced with a binary blob (e.g. a
    // gzipped or DER-encoded copy) before users see a truncated
    // license footer.
    use paladin_gtk::app::model::format_app_about_dialog_license_text;

    assert!(
        !format_app_about_dialog_license_text().contains('\u{0}'),
        "AdwAboutDialog license text must not contain a NUL byte",
    );
}

#[test]
fn format_app_about_dialog_license_markup_parses_as_valid_pango_markup() {
    // `adw::AboutDialog::set_license` feeds its input through
    // Pango markup. The raw AGPL-3.0-or-later body contains
    // URLs in `<https://…>` form (e.g. `<https://fsf.org/>`)
    // that the markup parser rejects ("Odd character '/',
    // expected a '>' …"), which makes the dialog drop the
    // visible license body and emit a `Gtk-WARNING`.
    // `format_app_about_dialog_license_markup` is the escaping
    // shim the dialog now consumes; pinning it as
    // `pango::parse_markup`-clean catches a regression that
    // bypasses the escape (or breaks the escape impl) before
    // users see the empty license footer.
    use paladin_gtk::app::model::format_app_about_dialog_license_markup;
    use relm4::gtk::pango;

    let markup = format_app_about_dialog_license_markup();
    let parsed = pango::parse_markup(&markup, '\0');
    assert!(
        parsed.is_ok(),
        "format_app_about_dialog_license_markup must round-trip through pango::parse_markup; error: {:?}",
        parsed.err(),
    );
}

#[test]
fn format_app_about_dialog_license_markup_preserves_the_raw_license_body_after_unescape() {
    // The escaped markup must render *exactly* the raw
    // `LICENSE` body when Pango unescapes the entities — the
    // visible license footer must not gain or lose characters
    // because of the escape pass. `pango::parse_markup`'s
    // second tuple element is the plain text the markup
    // resolves to (entities replaced, tags stripped); the raw
    // body has no markup tags, only entities (`&lt;`/`&gt;`
    // for the URLs), so the round-trip must equal the source
    // bytes verbatim.
    use paladin_gtk::app::model::{
        format_app_about_dialog_license_markup, format_app_about_dialog_license_text,
    };
    use relm4::gtk::pango;

    let markup = format_app_about_dialog_license_markup();
    let (_attrs, text, _accel) = pango::parse_markup(&markup, '\0')
        .expect("license markup must parse cleanly as Pango markup");
    assert_eq!(
        text.as_str(),
        format_app_about_dialog_license_text(),
        "Pango-unescaped license markup must equal the raw LICENSE body verbatim",
    );
}

#[test]
fn format_app_about_dialog_license_markup_escapes_the_fsf_url_angle_brackets() {
    // Sanity check on the specific tokens that caused the
    // crash: the FSF URL `<https://fsf.org/>` and the GNU
    // license URL `<https://www.gnu.org/licenses/>` must
    // appear in the markup as escaped entities, not as raw
    // angle brackets that Pango would mis-parse as XML tags.
    use paladin_gtk::app::model::format_app_about_dialog_license_markup;

    let markup = format_app_about_dialog_license_markup();
    assert!(
        !markup.contains("<https://"),
        "license markup must escape `<https://…>` URLs so Pango does not parse them as tags",
    );
    assert!(
        markup.contains("&lt;https://fsf.org/&gt;"),
        "license markup must carry the escaped FSF URL `&lt;https://fsf.org/&gt;`",
    );
}

#[test]
fn format_app_about_dialog_license_resource_path_returns_paladin_gui_license_path() {
    // Per docs/IMPLEMENTATION_PLAN_04_GTK.md §"Milestone 7 checklist"
    // → "About dialog" — the AGPL-3.0-or-later license text is
    // shipped in the gresource bundle under the
    // `/org/tamx/Paladin/Gui` prefix (matching the
    // `APP_ID`-derived prefix used by `style.css` and the
    // bundled icon theme). Pinning the exact gresource path
    // here keeps `data/paladin-gtk.gresource.xml`'s
    // `<file alias="LICENSE">` entry and any consumer that
    // looks up the bundled text by path in lockstep without a
    // duplicated literal.
    use paladin_gtk::app::model::format_app_about_dialog_license_resource_path;

    assert_eq!(
        format_app_about_dialog_license_resource_path(),
        "/org/tamx/Paladin/Gui/LICENSE",
        "AdwAboutDialog license resource path must match the gresource manifest alias under the APP_ID prefix",
    );
}

#[test]
fn format_app_about_dialog_license_resource_path_uses_app_id_prefix() {
    // Defense-in-depth: the resource path must live under the
    // same `/org/tamx/Paladin/Gui` prefix as `style.css`
    // (`format_app_style_css_resource_path`) and the bundled
    // icon theme (`format_app_icon_theme_resource_path`) so the
    // gresource pool stays namespaced by reverse-DNS APP_ID
    // and a swap that drops the prefix (which would leak the
    // bare `/LICENSE` path into the process-wide pool) surfaces
    // here as a failing test.
    use paladin_gtk::app::model::format_app_about_dialog_license_resource_path;

    let path = format_app_about_dialog_license_resource_path();
    assert!(
        path.starts_with("/org/tamx/Paladin/Gui/"),
        "AdwAboutDialog license resource path must live under the APP_ID-derived prefix; got {path:?}",
    );
    assert!(
        path.ends_with("/LICENSE"),
        "AdwAboutDialog license resource path must terminate at the LICENSE entry; got {path:?}",
    );
}

#[test]
fn format_app_about_dialog_license_resource_path_does_not_end_with_a_trailing_slash() {
    // A trailing slash on a `gio::resources_lookup_data` key
    // resolves to a directory listing, not the file body —
    // `set_license` would then receive an empty / garbage body.
    // Pin the absence of a trailing slash so a regression that
    // changes the helper to `"/org/tamx/Paladin/Gui/LICENSE/"`
    // surfaces here as a failing test before the dialog renders
    // an empty license panel.
    use paladin_gtk::app::model::format_app_about_dialog_license_resource_path;

    let path = format_app_about_dialog_license_resource_path();
    assert!(
        !path.ends_with('/'),
        "AdwAboutDialog license resource path must not end with a trailing slash; got {path:?}",
    );
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
    // Pins the credits-page contributor list against accidental drift; new
    // contributors must be added explicitly.
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
    // `README.md`, `docs/DESIGN.md`, and inline rustdoc are written
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
    // Empty value tells AdwAboutDialog to suppress the Translators credits
    // row; canary that flags the swap once gettext is wired up.
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
    // Empty body tells AdwAboutDialog to suppress the What's New section;
    // canary so the swap to non-empty markup forces a paired bump of
    // `format_app_about_dialog_release_notes_version`.
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    assert_eq!(
        format_app_about_dialog_release_notes(),
        "",
        "AdwAboutDialog release-notes must be empty so the What's New section is suppressed",
    );
}

#[test]
fn format_app_about_dialog_release_notes_must_be_paired_with_a_non_empty_version_when_non_empty() {
    // If release_notes() becomes non-empty, release_notes_version() must
    // also be non-empty so AdwAboutDialog has a label to render beside the
    // What's New section.
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
    // header-bar `+` button (and the `<Control><Shift>n` accelerator
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
    // Pin: `window title` is non-empty — empty value would render an unlabeled UI slot or
    // cause libadwaita to suppress the row entirely.
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
    // Pin: `about dialog program name` stays consistent with `format app window title` — guards against drift between two surfaces
    // that must render the same value.
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
    // that test verifies the seven primary-menu action targets
    // start with `format_app_action_group_name() + "."`; this
    // assertion extends the coverage to the eighth action on the
    // bundled group — the header-bar `+` button's `app.add` target
    // — so a future rename of `format_app_action_group_name` lands
    // as a failing test for every action target on the bundled
    // group, not just the menu seven.
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
        "header-bar + button action target {action:?} must start with the shared group prefix {prefix:?} so the bundled application action group resolves it alongside the seven primary-menu entries",
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
    // Pin: `header bar button icon names` are pairwise distinct so a copy-paste regression in one slot does
    // not collapse multiple UI elements to identical strings without a failing test.
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
    // Pin: `header bar button tooltips` are pairwise distinct so a copy-paste regression in one slot does
    // not collapse multiple UI elements to identical strings without a failing test.
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
    // Pin: `primary menu entries labels` are pairwise distinct so a copy-paste regression in one slot does
    // not collapse multiple UI elements to identical strings without a failing test.
    use paladin_gtk::app::model::format_app_primary_menu_entries;

    let entries = format_app_primary_menu_entries();
    let mut labels: Vec<&str> = entries.iter().map(|(label, _)| *label).collect();
    let before_dedup = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(
        before_dedup,
        labels.len(),
        "the seven primary-menu entry labels must be distinct (entries: {entries:?}); a duplicate would render two identical rows in the primary menu and collapse one of the seven action slots into an unreachable duplicate",
    );
}

#[test]
fn format_app_primary_menu_entries_actions_are_distinct() {
    // Pin: `primary menu entries actions` are pairwise distinct so a copy-paste regression in one slot does
    // not collapse multiple UI elements to identical strings without a failing test.
    use paladin_gtk::app::model::format_app_primary_menu_entries;

    let entries = format_app_primary_menu_entries();
    let mut actions: Vec<&str> = entries.iter().map(|(_, action)| *action).collect();
    let before_dedup = actions.len();
    actions.sort_unstable();
    actions.dedup();
    assert_eq!(
        before_dedup,
        actions.len(),
        "the seven primary-menu entry action targets must be distinct (entries: {entries:?}); a duplicate would route two visible menu rows to the same gio::SimpleAction and dispatch the same AppMsg from both, collapsing one of the seven menu actions into an unreachable duplicate",
    );
}

#[test]
fn format_app_window_action_names_are_distinct() {
    // Pin: `window action names` are pairwise distinct so a copy-paste regression in one slot does
    // not collapse multiple UI elements to identical strings without a failing test.
    use paladin_gtk::app::model::format_app_window_action_names;

    let names = format_app_window_action_names();
    let before_dedup = names.len();
    let mut deduped: Vec<&str> = names.to_vec();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        before_dedup,
        deduped.len(),
        "the eight bare action names returned by format_app_window_action_names must be distinct (names: {names:?}); a duplicate would silently overwrite one of the gio::SimpleAction registrations on the bundled SimpleActionGroup at build time and collapse two visible surface entries into a single dispatched AppMsg",
    );
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_carry_modifier_prefix() {
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
    // Pin: `about dialog program name` is a substring of `application icon name` — keeps the reverse-DNS app ID and the program name
    // aligned so the dialog and packaging metadata agree on the brand token.
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
    use paladin_gtk::app::model::format_app_window_default_size;

    let (width, height) = format_app_window_default_size();
    assert!(
        width >= height,
        "ApplicationWindow default size must be landscape or square (width >= height) so the AccountListComponent's `<issuer>:<label>` rows render with horizontal room before AdwSqueezer ellipsizes the label; got ({width}, {height}) which is portrait-oriented",
    );
}

#[test]
fn format_app_about_dialog_developers_does_not_contain_developer_name() {
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
    use paladin_gtk::app::model::format_app_window_default_size;

    const FHD_WIDTH_CEILING: i32 = 1920;
    const FHD_HEIGHT_CEILING: i32 = 1080;

    let (width, height) = format_app_window_default_size();
    assert!(
        width <= FHD_WIDTH_CEILING,
        "ApplicationWindow default width {width} must fit within the typical 1920x1080 FHD desktop display (ceiling {FHD_WIDTH_CEILING}px) so the initial window does not overflow a standard 1080p screen before the user has a chance to resize; a regression that appended a trailing zero to the pinned 1280px width would fail the test",
    );
    assert!(
        height <= FHD_HEIGHT_CEILING,
        "ApplicationWindow default height {height} must fit within the typical 1920x1080 FHD desktop display (ceiling {FHD_HEIGHT_CEILING}px) so the initial window does not overflow a standard 1080p screen before the user has a chance to resize; a regression that appended a trailing zero to the pinned 960px height would fail the test",
    );
}

#[test]
fn format_app_about_dialog_debug_info_starts_with_program_name() {
    // Pin: `about dialog debug info` boundary character (`program name`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
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
    // Pin: program-name segment and reverse-DNS App ID land on distinct line indices so
    // the bug-report paste renders as a tidy multi-line block instead of one wrapping run.
    // Avoids hardcoding the literal `"App ID:"` so future re-labeling still exercises it.
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
    // Pin: copyright does not contain a year token so it does not drift across releases.
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
    // Pin: `about dialog developers entries` are pairwise distinct so a copy-paste regression in one slot does
    // not collapse multiple UI elements to identical strings without a failing test.
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
    // Pin: both URLs derive from the same `env!("CARGO_PKG_REPOSITORY")` base so a future
    // refactor cannot silently split bug reporting and community Q&A across two project homes.
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
    // any of the seven entries (Import / Export / Passphrase /
    // Preferences / Keyboard Shortcuts / About / Quit) fails
    // with a message that names the offending entry's action
    // target. Mirrors the
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
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        assert!(
            accel.starts_with("<Control>"),
            "format_app_window_accelerator_bindings accelerator for target {target:?} must begin with the `<Control>` modifier so primary application actions follow the GNOME convention (a `<Shift>`-modified letter would intercept capital-letter text entry in dialog gtk::Entry rows; an `<Alt>`-modified letter would collide with the GTK mnemonic-accelerator surface); got {accel:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_carry_one_or_two_modifier_blocks() {
    use paladin_gtk::app::model::format_app_window_accelerator_bindings;

    for (accel, target) in format_app_window_accelerator_bindings() {
        let open_count = accel.bytes().filter(|&b| b == b'<').count();
        let close_count = accel.bytes().filter(|&b| b == b'>').count();
        assert!(
            (1..=2).contains(&open_count),
            "format_app_window_accelerator_bindings accelerator for target {target:?} must contain one or two `<` ASCII bytes so the GNOME single-modifier convention (or the documented `<Control><Shift>` compound for the Add \"New X\" accelerator) holds; three-or-more modifier chords belong on power-user shortcuts not primary application actions; got {open_count} `<` byte(s) in {accel:?}",
        );
        assert_eq!(
            open_count, close_count,
            "format_app_window_accelerator_bindings accelerator for target {target:?} must have balanced `<` and `>` ASCII bytes; got {open_count} `<` and {close_count} `>` in {accel:?}",
        );
    }
}

#[test]
fn format_app_window_accelerator_bindings_accelerators_have_a_non_empty_keysym_after_the_modifier_block(
) {
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
    use paladin_gtk::app::model::format_app_window_action_names;

    for (idx, name) in format_app_window_action_names().iter().enumerate() {
        for ch in name.chars() {
            // ASCII lowercase letters plus the ASCII hyphen are
            // the GLib `g_action_name_is_valid`-accepted character
            // set the bundled names use: single-word entries like
            // `"add"`, `"quit"`, `"about"`, `"import"`,
            // `"shortcuts"` and the kebab-case
            // `"copy-next-code"` introduced by §"Next-code
            // column implementation". Digits / dots / uppercase
            // letters are excluded so a regression that
            // introduced an upper-case letter on the bundled-array
            // side — e.g. renaming `"add"` to `"Add"` — still
            // surfaces here (the `dispatch_app_window_action`
            // helper is case-sensitive on the bare name, so an
            // upper-case slip would mis-route the
            // `gio::SimpleAction` activation at runtime).
            assert!(
                ch.is_ascii_lowercase() || ch == '-',
                "format_app_window_action_names[{idx}] = {name:?} must use lowercase ASCII letters and ASCII hyphens only so the dispatch_app_window_action case-sensitive lookup resolves; got disallowed character {ch:?} (libadwaita / GLib `g_action_name_is_valid` accepts `[A-Za-z0-9.-]` but the bundled names additionally pin the lowercase ASCII + hyphen subset for kebab-case)",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_copyright_separates_glyph_and_attribution_with_a_single_space() {
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
    // Pin: `about dialog application icon name` boundary character (`gui segment`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon = format_app_about_dialog_application_icon_name();
    assert!(
        icon.ends_with(".Gui"),
        "AdwAboutDialog application-icon must end with `.Gui` to distinguish this crate's reverse-DNS Flatpak identity from a future CLI / daemon front-end sharing the `org.tamx.Paladin.*` namespace; got {icon:?}",
    );
}

#[test]
fn format_app_header_bar_button_icon_names_use_lowercase_kebab_case() {
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
    // returns the seven bare action names the widget binding hands
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
    // Pin: program-name line ends with the package version exactly, so appending trailing
    // content (host OS, build info, trailing space) becomes an explicit decision instead of a
    // silent expansion of the bug-report payload past its minimal `"Paladin <version>"` shape.
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
    // Pin: `about dialog debug info app id line` boundary character (`the reverse dns app id`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
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
    // Pin: `about dialog comments` does not have a a period per libadwaita convention boundary — guards the GNOME convention that
    // labels are not sentences and renders consistently with adjacent rows.
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
    // Pin: `about dialog translator credits` has the has no surrounding whitespace when non empty invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: release-notes body has no leading/trailing whitespace once non-empty so AdwAboutDialog's
    // What's New section keeps its baseline rhythm. Empty-literal state trivially passes today.
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
    // Pin: `about dialog developer name` has the has no surrounding whitespace invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog program name` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog application icon name` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: version is ASCII-only — guards against Unicode-lookalike-digit hand-edits that
    // would render but break byte-equality and Cargo's version-comparison machinery.
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
    // Pin: `about dialog developer name` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog debug info filename` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog debug info` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog application icon name` has the has no embedded whitespace invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.chars().any(char::is_whitespace),
        "AdwAboutDialog application_icon_name must contain no whitespace byte so the value passes `g_application_id_is_valid` cleanly (which rejects any whitespace) and resolves against the freedesktop icon-theme lookup without falling back to the broken-image placeholder; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_has_no_embedded_whitespace() {
    // Pin: `about dialog program name` has the has no embedded whitespace invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog version` has the has no embedded whitespace invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog debug info filename` has the has no embedded whitespace invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `about dialog comments` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `window title` has the is ascii only invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: `window title` has the has no embedded whitespace invariant — guards against Unicode lookalikes,
    // stray whitespace, or other byte-composition regressions in the rendered string.
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
    // Pin: non-empty release-notes body brackets with markup elements (`<...>`) so it parses
    // as Pango/AdwAbout markup rather than raw paragraph text. Empty-literal passes today.
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
    // Pin: `about dialog developer name` boundary character (`the definite article`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        developer_name.starts_with("The "),
        "AdwAboutDialog developer-name must start with the definite article `\"The \"` so the collective attribution voicing matches the GNOME / freedesktop convention for project attributions (examples: \"The GNOME Project\", \"The GTK Team\", \"The Files contributors\"); a regression that dropped the article would render the dialog-header attribution row as an inventory rather than as a named collective; got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_ends_with_the_contributors_collective_noun() {
    // Pin: `about dialog developer name` boundary character (`the contributors collective noun`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        developer_name.ends_with(" contributors"),
        "AdwAboutDialog developer-name must end with the lowercase `\" contributors\"` collective noun (with the leading space so the noun is a separate word from the brand) so the collective-attribution voicing matches the AGPL-3.0-or-later open-contributor-pool model (an inclusive `\"contributors\"` voicing distinct from the named-org `\"Project\"` or named-team `\"Team\"` alternatives the GNOME stack uses for org-boundaried projects); a regression that swapped the noun — e.g. `\"The Paladin Project\"` / `\"The Paladin Team\"` / `\"The Paladin Developers\"` — would mis-route the governance signal of the collective attribution; got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_ends_with_developer_name() {
    // Pin: `about dialog copyright` boundary character (`developer name`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
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
    // Pin: leading character is an ASCII digit so a manual override that prefixes a leading
    // `v` or attaches build metadata fails at the test layer rather than at AppStream
    // release-notes validation or as a quiet dialog version-row UX regression.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    let first = version.chars().next().unwrap_or_else(|| {
        panic!(
            "AdwAboutDialog version must be non-empty (the `_is_non_empty_and_looks_like_semver` companion already pins this; restated here so the leading-digit assertion has a non-empty char to inspect); got {version:?}"
        )
    });
    assert!(
        first.is_ascii_digit(),
        "AdwAboutDialog version must start with an ASCII digit so the leading character matches the Semantic Versioning 2.0 `MAJOR.MINOR.PATCH` convention (a regression that prefixed the version with `\"v\"` from a git-tag / npm-version convention shadow refactor would diverge from the GNOME about-dialog version row and break AppStream / Flatpak release-notes tooling that match-keys off the bare semver in the `<release version=\"...\">` XML schema); got first character {first:?} (U+{:04X}) in version {version:?}",
        first as u32,
    );
}

#[test]
fn format_app_about_dialog_version_has_at_least_three_dot_separated_segments() {
    // Pin: version has ≥3 dot-separated segments to match the SemVer `MAJOR.MINOR.PATCH` shape
    // AppStream/Flatpak release-notes tooling expects. `>= 3` so pre-release (`-alpha.1`) and
    // build-metadata (`+build.42`) suffixes still pass.
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
    // Pin: no trailing `.` — a typo override like `"0.0.1."` would slip past most companions
    // (contains-dot, starts-with-digit, ASCII-only, ≥3 segments) while breaking AppStream's
    // strict SemVer validation at packaging time.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.ends_with('.'),
        "AdwAboutDialog version must not end with a `.` byte (which is not a valid terminal in any of the three Semantic Versioning 2.0 grammar productions for MAJOR.MINOR.PATCH, `-<pre-release>`, or `+<build-metadata>`) so the AppStream / Flatpak release-notes `<release version=\"...\">` XML schema entry resolves at packaging time rather than as a malformed-schema rejection; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_version_segments_are_non_empty() {
    // Pin: every `.`-separated segment is non-empty — catches `"0..1"` or `".0.0.1"` regressions
    // from `concat!` injections that would slip past contains-dot / starts-with-digit pins but
    // fail AppStream's strict SemVer grammar.
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
    // Pin: no leading `.` — restated independently of `_starts_with_a_digit` so a future
    // weakening of that pin (to allow letter-prefixed pre-release tags) still catches the
    // leading-dot edge case with a specific message naming the offending byte.
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.starts_with('.'),
        "AdwAboutDialog version must not start with a `.` byte (which is not a valid leading character in any of the Semantic Versioning 2.0 grammar productions — MAJOR must be a non-negative integer starting with `0`-`9` or a non-zero digit followed by digits) so the AppStream / Flatpak release-notes `<release version=\"...\">` XML schema entry resolves at packaging time rather than as a malformed-schema rejection and the AdwAboutDialog version row renders the canonical bare-major leading digit rather than a punctuation glyph next to the program name; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_end_with_a_dot() {
    // Pin: `about dialog application icon name` does not have a a dot boundary — guards the GNOME convention that
    // labels are not sentences and renders consistently with adjacent rows.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.ends_with('.'),
        "AdwAboutDialog application_icon_name must not end with a `.` byte (which is not a valid terminal in the reverse-DNS application-ID grammar that GNOME's D-Bus naming convention and the AppStream / Flatpak `<id>...</id>` schema validate against — each `.`-separated segment must be a non-empty alphanumeric/underscore identifier) so `gio::ApplicationId::is_valid` resolves at application startup, the AppStream validator resolves at packaging time, and the Flatpak `--build-finish` step resolves the `<id>` against the directory name in the build sandbox rather than as a downstream rejection; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_start_with_a_dot() {
    // Pin: `about dialog application icon name` does not have a a dot boundary — guards the GNOME convention that
    // labels are not sentences and renders consistently with adjacent rows.
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.starts_with('.'),
        "AdwAboutDialog application_icon_name must not start with a `.` byte (which is not a valid leading character in the reverse-DNS application-ID grammar that GNOME's D-Bus naming convention and the AppStream / Flatpak `<id>...</id>` schema validate against — each `.`-separated segment must be a non-empty alphanumeric/underscore identifier and the leading segment must therefore begin with an alphanumeric/underscore character) so `gio::ApplicationId::is_valid` resolves at application startup, the AppStream validator resolves at packaging time, and the Flatpak `--build-finish` step resolves the `<id>` against the directory name in the build sandbox rather than as a downstream rejection; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_starts_with_a_lowercase_ascii_letter() {
    // Pin: `about dialog application icon name` boundary character (`a lowercase ascii letter`) so a regression on the leading or
    // trailing token of the rendered string fails the test rather than slipping silently.
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
    // Pin: `about dialog developer name` does not have a a period boundary — guards the GNOME convention that
    // labels are not sentences and renders consistently with adjacent rows.
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        !developer_name.ends_with('.'),
        "AdwAboutDialog developer_name must not end with a `.` byte (per the libadwaita convention for the `AdwAboutDialog` developer-name slot — the bold dialog-header attribution row renders the attribution as a phrase, not a sentence, so terminal punctuation visually clashes with the program name and version that share the same bold header row); got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_end_with_a_period() {
    // Pin: `about dialog copyright` does not have a a period boundary — guards the GNOME convention that
    // labels are not sentences and renders consistently with adjacent rows.
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.ends_with('.'),
        "AdwAboutDialog copyright must not end with a `.` byte (per the libadwaita convention for the `AdwAboutDialog` copyright slot — the dialog-footer copyright row renders the copyright as a notice, not a sentence, matching the format used by GNOME reference applications like GNOME Calculator, GNOME Text Editor, and GNOME Files which all render their copyright lines without a trailing period); got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_end_with_a_period() {
    // Pin: program-name renders as a label, not a sentence — no trailing period so it does not
    // visually clash with the version sharing the same bold AdwAboutDialog header row.
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.ends_with('.'),
        "AdwAboutDialog program_name must not end with a `.` byte (per the libadwaita convention for the `AdwAboutDialog` program-name slot — the bold dialog-header row renders the program name as a label, not a sentence, so terminal punctuation visually clashes with the adjacent no-trailing-dot version row pinned by `_version_does_not_end_with_a_dot`); got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_path_separators() {
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
    // Pin: `debug_info` payload must not contain a carriage return control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\r'),
        "AdwAboutDialog debug_info must not contain the `\\r` carriage-return byte (which would surface as `\\r\\n` Windows line endings in a CRLF-separated payload, mis-rendering as `^M` artifacts in pasted bug reports and breaking POSIX text-processing tools when the payload is saved to disk via `set_debug_info_filename`); got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_start_with_a_dot() {
    // Pin: `about dialog debug info filename` does not have a a dot boundary — guards the GNOME convention that
    // labels are not sentences and renders consistently with adjacent rows.
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !filename.starts_with('.'),
        "AdwAboutDialog debug_info_filename must not start with a `.` byte (which would make the saved debug-info file a Unix-hidden file omitted from default `ls`, GNOME Files (Nautilus), and GTK file-chooser views — defeating the purpose of the `set_debug_info_filename` slot, which is to surface a copy-pasteable artifact users can attach to bug reports); got {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_contains_exactly_one_period() {
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
    // Pin: `debug_info` payload must not contain a null control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\0'),
        "AdwAboutDialog debug_info must not contain the `\\0` null byte (which would route through GDK's null-terminated `g_strdup`-backed clipboard, truncate downstream pastes; render as a control glyph or trigger binary-file fallback when saved to disk; and truncate Pango text-engine rendering of the in-dialog debug-info widget); got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_null_byte() {
    // Pin: `debug_info_filename` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !filename.contains('\0'),
        "AdwAboutDialog debug_info_filename must not contain the `\\0` null byte (which is rejected by POSIX `open(2)` with `EINVAL` and by GIO `g_file_new_for_path` with `NULL`, surfacing as a GTK file-chooser crash on GTK 4.0-4.10 or a silently-disabled Save button on GTK 4.12+); got {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_null_byte() {
    // Pin: `program_name` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\0'),
        "AdwAboutDialog program_name must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_application_name` / `set_title` / `accessible-name` setters and truncate the bold dialog-header program-name row, the window manager's taskbar / dock display label, and screen-reader announcements at the first `\\0`); got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_null_byte() {
    // Pin: `version` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\0'),
        "AdwAboutDialog version must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_version`, truncate the dialog-header version-label row at the first `\\0`, propagate into the debug-info payload, and corrupt automated bug-report version-field scraping); got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_null_byte() {
    // Pin: `application_icon_name` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.contains('\0'),
        "AdwAboutDialog application_icon_name must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_application_icon` / `RelmApp::new` and truncate the dialog-header glyph icon-theme lookup, the launcher / desktop-entry / AppStream `<id>` icon lookups, and the DBus single-instance bus-name registration at the first `\\0`); got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_null_byte() {
    // Pin: `developer_name` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer_name = format_app_about_dialog_developer_name();
    assert!(
        !developer_name.contains('\0'),
        "AdwAboutDialog developer_name must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_developer_name`, truncate the dialog-header attribution row, propagate into the footer copyright row that reuses this string, and silently lose trailing attribution in downstream scrapers); got {developer_name:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_null_byte() {
    // Pin: `copyright` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\0'),
        "AdwAboutDialog copyright must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_copyright`, truncate the dialog-footer copyright row at the first `\\0`, and silently lose trailing AGPL-3.0-or-later attribution in downstream license-aggregator scrapers); got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_null_byte() {
    // Pin: `comments` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\0'),
        "AdwAboutDialog comments must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_comments`, truncate the dialog-header tagline row at the first `\\0`, truncate the `.deb` / `.rpm` `Description:` field that mirrors `CARGO_PKG_DESCRIPTION`, and fail the `appstreamcli validate` pass on `<summary>` control bytes); got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_null_byte() {
    // Pin: `url_helpers` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `release_notes_version` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\0'),
        "AdwAboutDialog release_notes_version must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_release_notes_version`, truncate the dialog's \"What's New\" header section at the first `\\0`, mislead the user about which release they just upgraded to, and silently mis-key changelog-aggregator scraping output); got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_null_byte() {
    // Pin: `developers_entries` payload must not contain a null control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `translator_credits` payload must not contain a null control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\0'),
        "AdwAboutDialog translator_credits must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_translator_credits`, truncate the credits-page \"Translators\" section at the first `\\0`, mis-attribute the translation team, and silently lose trailing entries on the next localization-pipeline export pass); got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_null_byte() {
    // Pin: `release_notes` payload must not contain a null control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\0'),
        "AdwAboutDialog release_notes must not contain the `\\0` null byte (which would route through GLib's null-terminated `g_strdup` layer in `set_release_notes`, truncate the \"What's New\" section body at the first `\\0`, terminate the Pango markup parse mid-stream and trigger dangling-tag warnings, and silently lose trailing changelog bullets in downstream release-aggregator scrapers); got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_null_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a null control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `translator_credits` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\r'),
        "AdwAboutDialog translator_credits must not contain the `\\r` carriage-return byte (0x0D); the libadwaita translator-credits convention splits on `\\n` (LF) only, so a stray `\\r` byte would leave each parsed entry trailing a control byte that fontconfig setups render as a visible `?` or empty box, would survive `xgettext` round trips as either silent data loss or CRLF preservation, and would break screen-reader credits-page announcements; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_carriage_return_byte() {
    // Pin: `release_notes` payload must not contain a carriage return control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\r'),
        "AdwAboutDialog release_notes must not contain the `\\r` carriage-return byte (0x0D); the Pango markup parser permits ASCII whitespace between elements but renders `\\r` as a control byte, so a stray `\\r` would surface as visible whitespace glyphs or empty boxes between bullets on fontconfig setups lacking a U+000D glyph, propagate the same rendering bug into any external changelog reuse, and break screen-reader bullet-boundary announcements; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_carriage_return_byte() {
    // Pin: `developers_entries` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `empty_credits_section_entries` payload must not contain a carriage return control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `comments` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\r'),
        "AdwAboutDialog comments must not contain the `\\r` carriage-return byte (0x0D); a mid-string `\\r` slips past the `_is_non_empty_single_line_distinct_from_program_name` `\\n`-only single-line check, past the starts/ends-with-whitespace guards (which only reject `\\r` at the boundaries), and past `_is_ascii_only` (because `\\r` is ASCII), and would render as a literal control glyph in the dialog-header description, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers, and break screen-reader description announcements; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_carriage_return_byte() {
    // Pin: `release_notes_version` payload must not contain a carriage return control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\r'),
        "AdwAboutDialog release_notes_version must not contain the `\\r` carriage-return byte (0x0D); the current value's `\\r`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version`, so a future decoupling override would silently drop the `\\r` guard — a stray `\\r` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that expect a clean LF-only header key, and break screen-reader section-header announcements; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `developer_name` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\t'),
        "AdwAboutDialog developer-name must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past the starts/ends-with-whitespace guards (which only reject `\\t` at the boundaries), past `_is_ascii_only` (because `\\t` is ASCII), and past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the prefix and suffix); it would render as a wide horizontal gap in the dialog-header attribution row, break screen-reader announcements at the tab boundary, and propagate into downstream attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `copyright` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\t'),
        "AdwAboutDialog copyright must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past the no-year-token four-digit-run scan (`\\t` is not a digit), and past `_does_not_contain_a_null_byte` (because `\\t` is not `\\0`); it would render as a wide horizontal gap in the dialog-footer copyright row, visually misalign the footer cluster against the website / issue-link rows, break screen-reader announcements at the tab boundary, and propagate into downstream license-attribution scrapers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `comments` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\t'),
        "AdwAboutDialog comments must not contain the `\\t` horizontal-tab byte (0x09); a mid-string `\\t` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace), past `_is_ascii_only` (because `\\t` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_carriage_return_byte` (which name `\\0` and `\\r` specifically); it would render as a wide horizontal gap in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers, and break screen-reader description announcements at the tab boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_horizontal_tab_byte() {
    // Pin: `developers_entries` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `empty_credits_section_entries` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `release_notes_version` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\t'),
        "AdwAboutDialog release_notes_version must not contain the `\\t` horizontal-tab byte (0x09); the current value's `\\t`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version`, so a future decoupling override would silently drop the `\\t` guard — a stray `\\t` would render as a wide horizontal gap in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that strip whitespace when computing the body-region lookup key, and break screen-reader section-header announcements at the tab boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `release_notes` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\t'),
        "AdwAboutDialog release_notes must not contain the `\\t` horizontal-tab byte (0x09); the Pango markup parser permits ASCII whitespace between elements but renders `\\t` as a wide horizontal gap or empty box when no following character forces a tab-stop reset, so a stray `\\t` between the wrapping `<ul>` and each `<li>` bullet would surface as visible gaps or boxes in the dialog's What's New body, propagate the same rendering bug into any external changelog reuse, and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `translator_credits` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\t'),
        "AdwAboutDialog translator_credits must not contain the `\\t` horizontal-tab byte (0x09); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\t` bytes inside each parsed entry untouched, so a stray `\\t` would render as a wide horizontal gap or empty box in the credits-page attribution column, would survive `xgettext` round trips as either silent dedupe to a single space or `\\t` preservation, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `debug_info` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\t'),
        "AdwAboutDialog debug_info must not contain the `\\t` horizontal-tab byte (0x09); a `\\t` byte slips past `_is_ascii_only` (since `\\t` is ASCII), past `_does_not_contain_a_null_byte` (since `\\t` is not `\\0`), past `_does_not_contain_a_carriage_return_byte` (since `\\t` is not `\\r`), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and would render as a wide horizontal gap in the Troubleshooting dialog body, drift column widths in pasted bug reports, and break POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename`; got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_carriage_return_byte() {
    // Pin: `developer_name` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\r'),
        "AdwAboutDialog developer-name must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected by the `_is_a_single_line_without_embedded_newlines` companion's coupled `\\n`/`\\r` check, so a future refactor that intentionally allowed embedded `\\n` line breaks in the attribution slot might reasonably drop the `\\r` check alongside the `\\n` check on the assumption that both line-ending bytes are now allowed (an assumption that is wrong: GNOME-stack strings use LF-only conventions throughout); a stray `\\r` would render as a control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, and break screen-reader attribution announcements; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_carriage_return_byte() {
    // Pin: `copyright` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\r'),
        "AdwAboutDialog copyright must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected by the `_is_a_single_line_without_embedded_newlines` companion's coupled `\\n`/`\\r` check, so a future refactor that intentionally allowed embedded `\\n` line breaks in the copyright slot might reasonably drop the `\\r` check alongside the `\\n` check on the assumption that both line-ending bytes are now allowed (an assumption that is wrong: GNOME-stack strings use LF-only conventions throughout); a stray `\\r` would render as a control glyph in the dialog footer copyright row, erode the legal-attribution trusted-surface contract, and break screen-reader copyright-row announcements; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_carriage_return_byte() {
    // Pin: `program_name` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\r'),
        "AdwAboutDialog program_name must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\r` guard alongside the space relaxation; a stray `\\r` would render as a control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label, and break screen-reader application-name announcements; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `program_name` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\t'),
        "AdwAboutDialog program_name must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\t` guard alongside the space relaxation; a stray `\\t` would render as a wide horizontal gap in the bold dialog-header program-name row, mis-align the window manager's taskbar / dock display label under shell-dependent tab-stop semantics, and break screen-reader application-name announcements at the tab boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_carriage_return_byte() {
    // Pin: `version` payload must not contain a carriage return control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\r'),
        "AdwAboutDialog version must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\r` guard alongside the space relaxation; a stray `\\r` would render as a control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, and break screen-reader version-caption announcements; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `version` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\t'),
        "AdwAboutDialog version must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\t` guard alongside the space relaxation; a stray `\\t` would render as a wide horizontal gap in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, and break screen-reader version-caption announcements at the tab boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_carriage_return_byte() {
    // Pin: `application_icon_name` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\r'),
        "AdwAboutDialog application_icon_name must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\r` guard; a stray `\\r` would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange, and propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `application_icon_name` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\t'),
        "AdwAboutDialog application_icon_name must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\t` guard; a stray `\\t` would silently miss the `gtk::IconTheme` cache lookup, surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, and fail D-Bus well-known-name validation when `gio::Application::set_application_id` tries to register the single-instance bus name; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_carriage_return_byte() {
    // Pin: `debug_info_filename` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\r'),
        "AdwAboutDialog debug_info_filename must not contain the `\\r` carriage-return byte (0x0D); the current `\\r`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\r` guard alongside the space relaxation; a stray `\\r` would mis-render as a control glyph in the GtkFileDialog filename entry pre-fill, surface as an un-listable file under shell-tooling pipelines (`ls`, `find`, `tar`) that strip non-printable bytes, and confuse maintainer triage with `^M` artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_horizontal_tab_byte() {
    // Pin: `debug_info_filename` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\t'),
        "AdwAboutDialog debug_info_filename must not contain the `\\t` horizontal-tab byte (0x09); the current `\\t`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check, so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\t` guard alongside the space relaxation; a stray `\\t` would mis-render as a wide horizontal gap in the GtkFileDialog filename entry pre-fill, mis-align every following column in `ls -l` output by expanding to the next tab-stop, and confuse maintainer triage with inconsistent tab-stop renders in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_carriage_return_byte() {
    // Pin: `url_helpers` payload must not contain a carriage return control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `url_helpers` payload must not contain a horizontal tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `developer_name` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x0B'),
        "AdwAboutDialog developer-name must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x0B` is ASCII), past `_has_no_surrounding_whitespace` (which only rejects `\\x0B` at the boundaries via `char::is_whitespace()`), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_vertical_tab_byte() {
    // Pin: `copyright` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x0B'),
        "AdwAboutDialog copyright must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` (which only constrain the literal prefix and suffix), past `_separates_glyph_and_attribution_with_a_single_space` (which only constrains the single byte after the `©` glyph), past `_does_not_end_with_a_period` (which only constrains the trailing byte), past the no-year-token four-digit-run scan (`\\x0B` is not a digit), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-footer copyright row, erode the legal-attribution trusted-surface contract by surfacing a control-byte glyph in the legal row, break screen-reader copyright-row announcements at the byte boundary, and propagate into downstream license-attribution scrapers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_vertical_tab_byte() {
    // Pin: `comments` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x0B'),
        "AdwAboutDialog comments must not contain the `\\x0B` vertical-tab byte (0x0B); a mid-string `\\x0B` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace, and although `char::is_whitespace()` matches U+000B VT it only rejects boundary occurrences), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_is_ascii_only` (because `\\x0B` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers and `gnome-software` description rows, and break screen-reader description announcements at the byte boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_vertical_tab_byte() {
    // Pin: `developers_entries` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `empty_credits_section_entries` payload must not contain a vertical tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `release_notes_version` payload must not contain a vertical tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x0B'),
        "AdwAboutDialog release_notes_version must not contain the `\\x0B` vertical-tab byte (0x0B); the current value's `\\x0B`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version` and the `version` helper's `_has_no_embedded_whitespace` check (which uses `char::is_whitespace()` and catches U+000B VT), so a future decoupling override would silently drop the `\\x0B` guard; a stray `\\x0B` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that strip whitespace when computing the body-region lookup key, and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_vertical_tab_byte() {
    // Pin: `release_notes` payload must not contain a vertical tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\x0B'),
        "AdwAboutDialog release_notes must not contain the `\\x0B` vertical-tab byte (0x0B); the Pango markup parser permits ASCII whitespace between elements but renders `\\x0B` as a literal control glyph (a hollow box or tofu-like placeholder) since `\\x0B` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics, so a stray `\\x0B` between the wrapping `<ul>` and each `<li>` bullet would surface as visible boxes in the dialog's What's New body, propagate the same rendering bug into any external changelog reuse, and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_vertical_tab_byte() {
    // Pin: `translator_credits` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x0B'),
        "AdwAboutDialog translator_credits must not contain the `\\x0B` vertical-tab byte (0x0B); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x0B` bytes inside each parsed entry untouched, and `\\x0B` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics so Pango renders it as a literal control glyph; a stray `\\x0B` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips as either silent dedupe to a single space or `\\x0B` preservation, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_vertical_tab_byte() {
    // Pin: `debug_info` payload must not contain a vertical tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\x0B'),
        "AdwAboutDialog debug_info must not contain the `\\x0B` vertical-tab byte (0x0B); a `\\x0B` byte slips past `_is_ascii_only` (since `\\x0B` is ASCII), past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` (which each name a different byte), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and past `_is_non_empty_text_with_no_trailing_whitespace` (which rejects boundary `\\x0B` via `char::is_whitespace()` but not mid-payload occurrences), and would render as a literal control glyph in the Troubleshooting dialog body, drift across browsers and font stacks in pasted bug reports, and propagate a stray VT byte into POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename`; got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_vertical_tab_byte() {
    // Pin: `program_name` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x0B'),
        "AdwAboutDialog program_name must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\x0B` guard alongside the space relaxation; a stray `\\x0B` would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_vertical_tab_byte() {
    // Pin: `version` payload must not contain a vertical tab control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x0B'),
        "AdwAboutDialog version must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\x0B` guard alongside the space relaxation; a stray `\\x0B` would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_vertical_tab_byte() {
    // Pin: `application_icon_name` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x0B'),
        "AdwAboutDialog application_icon_name must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\x0B` guard; a stray `\\x0B` would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, and propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_vertical_tab_byte() {
    // Pin: `debug_info_filename` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x0B'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x0B` vertical-tab byte (0x0B); the current `\\x0B`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000B VT), so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\x0B` guard alongside the space relaxation; a stray `\\x0B` would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, surface as an un-listable file under shell-tooling pipelines (`ls`, `find`, `tar`) that strip non-printable bytes, and confuse maintainer triage with control-glyph artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_vertical_tab_byte() {
    // Pin: `url_helpers` payload must not contain a vertical tab control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
    // Pin: `developer_name` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x0C'),
        "AdwAboutDialog developer-name must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x0C` is ASCII), past `_has_no_surrounding_whitespace` (which only rejects `\\x0C` at the boundaries via `char::is_whitespace()`), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers — text-paginator pipelines would additionally treat the `\\x0C` as a hard page break and split the attribution mid-string in printed reports; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_backspace_byte() {
    // Pin: `developer_name` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x08'),
        "AdwAboutDialog developer-name must not contain the `\\x08` backspace byte (0x08); a mid-string `\\x08` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x08` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0008 BS so this companion does NOT reject `\\x08` even at the boundaries, strictly weaker coverage than form-feed), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, enable terminal-erase display-spoofing when the developer-name is dumped through a TTY (the rendered attribution diverges from the bytes on disk because `\\x08` erases the preceding glyph), break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_form_feed_byte() {
    // Pin: `copyright` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x0C'),
        "AdwAboutDialog copyright must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` (which only constrain the literal prefix and suffix), past `_separates_glyph_and_attribution_with_a_single_space` (which only constrains the single byte after the `©` glyph), past `_does_not_end_with_a_period` (which only constrains the trailing byte), past the no-year-token four-digit-run scan (`\\x0C` is not a digit), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-footer copyright row, erode the legal-attribution trusted-surface contract by surfacing a control-byte glyph in the legal row, break screen-reader copyright-row announcements at the byte boundary, and propagate into downstream license-attribution scrapers — text-paginator pipelines would additionally treat the `\\x0C` as a hard page break and split the legal-attribution row mid-string in printed reports; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_backspace_byte() {
    // Pin: `copyright` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x08'),
        "AdwAboutDialog copyright must not contain the `\\x08` backspace byte (0x08); a mid-string `\\x08` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` (which only constrain the literal prefix and suffix), past `_separates_glyph_and_attribution_with_a_single_space` (which only constrains the single byte after the `©` glyph), past `_does_not_end_with_a_period` (which only constrains the trailing byte), past the no-year-token four-digit-run scan (`\\x08` is not a digit), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` (which each name a different byte specifically); `\\x08` is NOT matched by `char::is_whitespace()` so boundary trim guards do not catch it even on the leading or trailing byte (strictly more dangerous than form-feed which `char::is_whitespace()` does match at the boundary); it would render as a literal control glyph in the dialog-footer copyright row, erode the legal-attribution trusted-surface contract by surfacing a control-byte glyph in the legal row, enable terminal-erase display-spoofing when the copyright is dumped through a TTY in §11.4 debug-info pipelines (the rendered legal attribution diverges from the bytes on disk because `\\x08` erases the preceding glyph), break screen-reader copyright-row announcements at the byte boundary, and propagate into downstream license-attribution scrapers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_form_feed_byte() {
    // Pin: `comments` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x0C'),
        "AdwAboutDialog comments must not contain the `\\x0C` form-feed byte (0x0C); a mid-string `\\x0C` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace, and although `char::is_whitespace()` matches U+000C FF it only rejects boundary occurrences), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_is_ascii_only` (because `\\x0C` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers and `gnome-software` description rows (with text-paginator pipelines treating it as a hard page break), and break screen-reader description announcements at the byte boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_backspace_byte() {
    // Pin: `comments` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x08'),
        "AdwAboutDialog comments must not contain the `\\x08` backspace byte (0x08); a mid-string `\\x08` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and surrounding whitespace — `char::is_whitespace()` returns false for U+0008 BS so the surrounding-whitespace guard does NOT reject `\\x08` even at the boundaries, strictly weaker coverage than form-feed), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_is_ascii_only` (because `\\x08` is ASCII), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header description row, propagate via `CARGO_PKG_DESCRIPTION` into Cargo metadata scrapers and `gnome-software` description rows, enable terminal-erase display-spoofing when `cargo metadata` is piped through a TTY (the rendered description diverges from the bytes on disk because `\\x08` erases the preceding glyph), and break screen-reader description announcements at the byte boundary; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_form_feed_byte() {
    // Pin: `developers_entries` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
fn format_app_about_dialog_developers_entries_do_not_contain_a_backspace_byte() {
    // Pin: `developers_entries` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x08'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x08` backspace byte (0x08); a mid-string `\\x08` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — `char::is_whitespace()` returns false for U+0008 BS, so the boundary guards do NOT reject `\\x08` even at the leading or trailing byte, strictly weaker coverage than form-feed), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, enable terminal-erase display-spoofing when the credits are dumped through a TTY (the rendered contributor name diverges from the bytes on disk because `\\x08` erases the preceding glyph), propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_form_feed_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a form feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_backspace_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a backspace control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x08'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x08` backspace byte (0x08); a mid-string `\\x08` would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, enable terminal-erase display-spoofing when the credits are dumped through a TTY (the rendered contributor name diverges from the bytes on disk because `\\x08` erases the preceding glyph), propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_form_feed_byte() {
    // Pin: `release_notes_version` payload must not contain a form feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x0C'),
        "AdwAboutDialog release_notes_version must not contain the `\\x0C` form-feed byte (0x0C); the current value's `\\x0C`-cleanliness is only protected transitively via `_matches_about_dialog_version` and `_matches_cargo_pkg_version` and the `version` helper's `_has_no_embedded_whitespace` check (which uses `char::is_whitespace()` and catches U+000C FF), so a future decoupling override would silently drop the `\\x0C` guard; a stray `\\x0C` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, could prevent the What's New body from rendering on libadwaita versions that strip whitespace when computing the body-region lookup key (with text-paginator pipelines treating it as a hard page break), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_backspace_byte() {
    // Pin: `release_notes_version` payload must not contain a backspace control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x08'),
        "AdwAboutDialog release_notes_version must not contain the `\\x08` backspace byte (0x08); unlike form-feed, the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x08` (because `char::is_whitespace()` returns false for U+0008 BS), so every byte of `\\x08`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x08` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, enable terminal-erase display-spoofing when the version is dumped through a TTY (the rendered header diverges from the bytes on disk because `\\x08` erases the preceding glyph), could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_form_feed_byte() {
    // Pin: `release_notes` payload must not contain a form feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\x0C'),
        "AdwAboutDialog release_notes must not contain the `\\x0C` form-feed byte (0x0C); the Pango markup parser permits ASCII whitespace between elements but renders `\\x0C` as a literal control glyph (a hollow box or tofu-like placeholder) since `\\x0C` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics, so a stray `\\x0C` between the wrapping `<ul>` and each `<li>` bullet would surface as visible boxes in the dialog's What's New body, propagate the same rendering bug into any external changelog reuse (with text-paginator pipelines treating it as a hard page break), and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_release_notes_does_not_contain_a_backspace_byte() {
    // Pin: `release_notes` payload must not contain a backspace control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes;

    let release_notes = format_app_about_dialog_release_notes();
    assert!(
        !release_notes.contains('\x08'),
        "AdwAboutDialog release_notes must not contain the `\\x08` backspace byte (0x08); Pango does NOT classify `\\x08` as whitespace under any permissive whitespace mode so the bytes pass through to the renderer as literal control bytes (a hollow box or tofu-like placeholder), `_has_no_surrounding_whitespace_when_non_empty` does NOT reject leading or trailing `\\x08` (because `char::is_whitespace()` returns false for U+0008 BS, strictly weaker coverage than form-feed), `_starts_and_ends_with_a_markup_element_when_non_empty` is independent of mid-body `\\x08`, and the per-byte siblings each name a different byte specifically; a stray `\\x08` between the wrapping `<ul>` and each `<li>` bullet would surface as visible boxes in the dialog's What's New body, enable terminal-erase display-spoofing when the changelog is dumped through a TTY (the rendered changelog diverges from the bytes on disk because `\\x08` erases the preceding glyph), and break screen-reader bullet-boundary announcements at every indent; got {release_notes:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_form_feed_byte() {
    // Pin: `translator_credits` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x0C'),
        "AdwAboutDialog translator_credits must not contain the `\\x0C` form-feed byte (0x0C); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x0C` bytes inside each parsed entry untouched, and `\\x0C` is technically whitespace under `char::is_whitespace()` but has no tab-stop semantics so Pango renders it as a literal control glyph; a stray `\\x0C` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips as either silent dedupe to a single space or `\\x0C` preservation (with text-paginator pipelines treating it as a hard page break), and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_backspace_byte() {
    // Pin: `translator_credits` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x08'),
        "AdwAboutDialog translator_credits must not contain the `\\x08` backspace byte (0x08); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x08` bytes inside each parsed entry untouched, `\\x08` is NOT classified as whitespace under any permissive whitespace mode (strictly more dangerous than form-feed which `char::is_whitespace()` does match at the boundary) so Pango renders it as a literal control glyph; a stray `\\x08` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would enable terminal-erase display-spoofing when the po-file is dumped through a TTY (the rendered attribution diverges from the bytes on disk because `\\x08` erases the preceding glyph), and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_form_feed_byte() {
    // Pin: `debug_info` payload must not contain a form feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\x0C'),
        "AdwAboutDialog debug_info must not contain the `\\x0C` form-feed byte (0x0C); a `\\x0C` byte slips past `_is_ascii_only` (since `\\x0C` is ASCII), past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` (which each name a different byte), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and past `_is_non_empty_text_with_no_trailing_whitespace` (which rejects boundary `\\x0C` via `char::is_whitespace()` but not mid-payload occurrences), and would render as a literal control glyph in the Troubleshooting dialog body, drift across browsers and font stacks in pasted bug reports, and propagate a stray FF byte into POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename` (with text-paginator pipelines treating it as a hard page break); got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_does_not_contain_a_backspace_byte() {
    // Pin: `debug_info` payload must not contain a backspace control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info;

    let debug_info = format_app_about_dialog_debug_info();
    assert!(
        !debug_info.contains('\x08'),
        "AdwAboutDialog debug_info must not contain the `\\x08` backspace byte (0x08); a `\\x08` byte slips past `_is_ascii_only` (since `\\x08` is ASCII), past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` (which each name a different byte), past `_has_exactly_two_lines` / `_program_name_line_ends_with_the_version` / `_app_id_line_ends_with_the_reverse_dns_app_id` (which split on `\\n` and only check trailing substrings), and past `_is_non_empty_text_with_no_trailing_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0008 BS so this companion does NOT reject `\\x08` even at the trailing byte, strictly weaker coverage than form-feed), and would render as a literal control glyph in the Troubleshooting dialog body, drift across browsers and font stacks in pasted bug reports, enable terminal-erase display-spoofing when the payload is pasted into a terminal-rendered bug-report preview or `cat`-ted from the saved `.txt` file (the rendered debug-info diverges from the bytes on disk because `\\x08` erases the preceding glyph), and propagate a stray BS byte into POSIX text-processing tools (`grep`, `awk`, `cut`) when the payload is saved to disk via `set_debug_info_filename`; got {debug_info:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_form_feed_byte() {
    // Pin: `program_name` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x0C'),
        "AdwAboutDialog program_name must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant to allow a localized multi-word program name might silently drop the `\\x0C` guard alongside the space relaxation; a stray `\\x0C` would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title` (with text-paginator pipelines treating it as a hard page break), and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_backspace_byte() {
    // Pin: `program_name` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x08'),
        "AdwAboutDialog program_name must not contain the `\\x08` backspace byte (0x08); unlike form-feed, `_has_no_embedded_whitespace` does NOT catch `\\x08` because `char::is_whitespace()` returns false for U+0008 BS (strictly weaker coverage than form-feed, which the whitespace companion does catch transitively); a stray `\\x08` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, enable terminal-erase display-spoofing on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps (the rendered window title diverges from the bytes a window manager exposes because `\\x08` erases the preceding glyph), and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_form_feed_byte() {
    // Pin: `version` payload must not contain a form feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x0C'),
        "AdwAboutDialog version must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant to allow a build-metadata-suffixed version like `\"0.0.1 +build\"` might silently drop the `\\x0C` guard alongside the space relaxation; a stray `\\x0C` would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string (with text-paginator pipelines treating it as a hard page break), and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_backspace_byte() {
    // Pin: `version` payload must not contain a backspace control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x08'),
        "AdwAboutDialog version must not contain the `\\x08` backspace byte (0x08); unlike form-feed, `_has_no_embedded_whitespace` does NOT catch `\\x08` because `char::is_whitespace()` returns false for U+0008 BS (strictly weaker coverage than form-feed which the whitespace companion does catch transitively); a stray `\\x08` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, enable terminal-erase display-spoofing on update-check or release-tracker dumps piped to `less` (the rendered version diverges from the bytes on disk because `\\x08` erases the preceding glyph), and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_form_feed_byte() {
    // Pin: `application_icon_name` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x0C'),
        "AdwAboutDialog application_icon_name must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant might silently drop the `\\x0C` guard; a stray `\\x0C` would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, and propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission (with text-paginator pipelines treating it as a hard page break); got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_backspace_byte() {
    // Pin: `application_icon_name` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x08'),
        "AdwAboutDialog application_icon_name must not contain the `\\x08` backspace byte (0x08); unlike form-feed, `_has_no_embedded_whitespace` does NOT catch `\\x08` because `char::is_whitespace()` returns false for U+0008 BS (strictly weaker coverage than form-feed which the whitespace companion does catch transitively); a stray `\\x08` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, and enable terminal-erase display-spoofing when Flathub linter diagnostics are dumped through a TTY (the rendered linter error diverges from the bytes on disk because `\\x08` erases the preceding glyph); got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_form_feed_byte() {
    // Pin: `debug_info_filename` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x0C'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x0C` form-feed byte (0x0C); the current `\\x0C`-cleanliness is only protected transitively by `_has_no_embedded_whitespace`'s broad `char::is_whitespace()` check (which matches U+000C FF), so a future refactor that relaxed the no-whitespace invariant to allow a localized filename like `\"Debug information.txt\"` might silently drop the `\\x0C` guard alongside the space relaxation; a stray `\\x0C` would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, surface as an un-listable file under shell-tooling pipelines (`ls`, `find`, `tar`) that strip non-printable bytes (with text-paginator pipelines treating it as a hard page break), and confuse maintainer triage with control-glyph artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_backspace_byte() {
    // Pin: `debug_info_filename` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x08'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x08` backspace byte (0x08); unlike form-feed, `_has_no_embedded_whitespace` does NOT catch `\\x08` because `char::is_whitespace()` returns false for U+0008 BS (strictly weaker coverage than form-feed which the whitespace companion does catch transitively); a stray `\\x08` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x08`) and the per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, enable terminal-erase display-spoofing in `ls` / `find` / `tar` output piped to a terminal (the rendered listing diverges from the on-disk filename because `\\x08` erases the preceding glyph — a historical primitive for hiding malicious files behind visually-similar legitimate filenames), and confuse maintainer triage with control-glyph artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_form_feed_byte() {
    // Pin: `url_helpers` payload must not contain a form feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_backspace_byte() {
    // Pin: `url_helpers` payload must not contain a backspace control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x08'),
            "AdwAboutDialog {label} must not contain the `\\x08` backspace byte (0x08) — `\\x08` is never a valid byte inside a URL per RFC 3986 (the backspace byte is not in any of the URL grammar's production rules); unlike form-feed, `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x08` because `char::is_whitespace()` returns false for U+0008 BS (strictly weaker coverage than form-feed which the whitespace companion does catch transitively); a stray `\\x08` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%08`-encoding implementations, enable a terminal-erase phishing primitive on URL-label dumps piped through a TTY (the rendered URL points to a legitimate-looking host while the actual click-target bytes go to a malicious host because `\\x08` erases the preceding glyph), break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_line_feed_byte() {
    // Pin: `developer_name` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\n'),
        "AdwAboutDialog developer-name must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected by the `_is_a_single_line_without_embedded_newlines` companion's coupled `\\n`/`\\r` check, so a future refactor that intentionally allowed embedded line breaks (a multi-contributor attribution column layout or a libadwaita upgrade that taught the attribution row to wrap across two lines) would naturally relax that companion to drop the `\\n` check entirely; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the attribution onto two lines (pushing the dialog header taller than its baseline layout and visually misaligning the icon / application-name / version cluster below), propagate into the footer copyright row that reuses this string and break the single-line footer copyright layout there too, break log-grep queries that search for the prefix `\"The Paladin\"` and miss the trailing `\"contributors\"` token, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; the `_has_no_surrounding_whitespace` companion does reject a leading or trailing `\\n` (since `char::is_whitespace()` returns true for U+000A LF) but the more dangerous mid-string `\\n` slips past; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_line_feed_byte() {
    // Pin: `copyright` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\n'),
        "AdwAboutDialog copyright must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected by the `_is_a_single_line_without_embedded_newlines` companion's coupled `\\n`/`\\r` check, so a future refactor that intentionally allowed embedded line breaks in the copyright slot (a multi-line attribution including a separate copyright-glyph row and contributor row, or a libadwaita upgrade that taught the footer copyright row to wrap across two lines) would naturally relax that companion to drop the `\\n` check entirely; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the copyright onto two lines (pushing the dialog footer taller than its baseline layout and visually misaligning the website / issue-link rows beneath), erode the trusted-application legal-attribution surface contract, break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators that might split input on `\\n` and interpret the second line as a separate copyright entry; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_line_feed_byte() {
    // Pin: `comments` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\n'),
        "AdwAboutDialog comments must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected by the `_comments_is_non_empty_single_line_distinct_from_program_name` companion's coupled multi-part single-line check, so a future refactor that intentionally allowed embedded line breaks in the comments slot (a libadwaita upgrade that taught the comments row to wrap across two lines, a multi-paragraph package-description that lifted comments out of the single-line constraint, or a workspace-vendoring split that decoupled comments from the `env!(\"CARGO_PKG_DESCRIPTION\")` single-line source) would naturally relax that companion to drop the `\\n` check entirely; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the comments onto two lines (pushing the dialog header taller than its baseline layout), erode the tidy single-line elevator-pitch summary GNOME HIG calls for, break log-grep queries that search for the description by a single token, break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_line_feed_byte() {
    // Pin: `developers_entries` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\n'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected by the `_is_non_empty_array_of_non_empty_single_line_names` companion's coupled per-entry single-line check, so a future refactor that intentionally allowed embedded line breaks in contributor entries (a multi-line attribution listing a contributor's role beneath their name, or a libadwaita upgrade that taught the credits-page contributor row to wrap across two lines) would naturally relax that companion to drop the `\\n` check entirely; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the contributor name onto two lines in the credits-page \"Developers\" row, propagate into downstream attribution scrapers and `gnome-software` credit aggregators that might split input on `\\n` and interpret the contributor as two separate entries, break screen-reader contributor-name announcements at the byte boundary, and break log-grep queries for the contributor name prefix; the surrounding-whitespace boundary guards inside the single-line companion do reject a leading or trailing `\\n` (since `char::is_whitespace()` returns true for U+000A LF) but the more dangerous mid-string `\\n` slips past; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_line_feed_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a line feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\n'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\n` line-feed byte (0x0A); a mid-string `\\n` would cause Pango to interpret the byte as a hard line break and wrap the contributor name onto two lines in the credits-page \"{label}\" row via `set_{label}`, propagate into downstream attribution scrapers and `gnome-software` credit aggregators (with naive aggregators splitting input on `\\n` and treating the contributor as two separate entries), and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_line_feed_byte() {
    // Pin: `release_notes_version` payload must not contain a line feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\n'),
        "AdwAboutDialog release_notes_version must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected transitively via the `_matches_about_dialog_version` equality pin against the version helper's `_has_no_embedded_whitespace` companion (which uses `char::is_whitespace()` and returns true for U+000A LF), so a future refactor that decoupled `release_notes_version` from `version` (a multi-release release-notes header that landed a distinct release-notes version) or that relaxed the version helper's no-embedded-whitespace guard (a multi-line SemVer build-meta suffix) would naturally drop the transitive `\\n` guard; a stray `\\n` would cause Pango to interpret the byte as a hard line break in the \"What's New\" section header, break the tidy single-line caption layout, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\n` production), trigger Flatpak `appstream-builder` rejection when generating the release-notes index, break screen-reader section-header announcements at the byte boundary, and propagate into downstream changelog aggregators; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_line_feed_byte() {
    // Pin: `translator_credits` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let credits = format_app_about_dialog_translator_credits();
    assert!(
        !credits.contains('\n'),
        "AdwAboutDialog translator_credits must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected conditionally by the `_translator_credits_is_single_line_when_non_empty` companion's `if !credits.is_empty()` gate plus its inner `!credits.contains('\\n')` assertion, so a future refactor that landed a non-empty `gettext(\"translator-credits\")` value with embedded line breaks (the GTK historical convention of `\\n`-separated translator pairs) and either flipped the `is_empty` gate or relaxed the inner single-line check would naturally drop the `\\n` guard; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the credits row taller than its baseline layout, erode the libadwaita single-line credits-row contract per Paladin's explicit `_is_single_line_when_non_empty` invariant, break screen-reader credits-row announcements at the byte boundary, and propagate into downstream localization-attribution aggregators; the `_has_no_surrounding_whitespace_when_non_empty` companion does reject a leading or trailing `\\n` (since `char::is_whitespace()` returns true for U+000A LF) but the more dangerous mid-string `\\n` slips past; got {credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_line_feed_byte() {
    // Pin: `program_name` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\n'),
        "AdwAboutDialog program_name must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected transitively via the `_program_name_has_no_embedded_whitespace` companion (which uses `char::is_whitespace()` and returns true for U+000A LF), so a future refactor that relaxed the no-embedded-whitespace invariant (a libadwaita upgrade that taught the dialog header program-name row to wrap across two lines, or a workspace-vendoring split that lifted program-name out of the single-line constraint) would naturally drop the `\\n` guard; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the program name onto two lines (pushing the dialog header taller than its baseline layout), propagate into the application window title that reuses this string, break screen-reader program-name announcements at the byte boundary, propagate into downstream desktop-file readers and AppStream `<name>` extractors, and trigger AppStream `<name>` validation rejection at packaging time; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_line_feed_byte() {
    // Pin: `version` payload must not contain a line feed control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\n'),
        "AdwAboutDialog version must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected transitively via the `_version_has_no_embedded_whitespace` companion (which uses `char::is_whitespace()` and returns true for U+000A LF), so a future refactor that relaxed the no-embedded-whitespace invariant (a multi-line SemVer build-meta suffix, a `concat!` injection, or a workspace-vendoring split that lifted version out of the strict SemVer grammar) would naturally drop the `\\n` guard; a stray `\\n` would cause Pango to interpret the byte as a hard line break and wrap the version onto two lines (pushing the dialog header taller than its baseline layout), propagate into `release_notes_version` via the equality pin and break the \"What's New\" caption layout, propagate into `debug_info` via the `concat!` composition and break the `_debug_info_has_exactly_two_lines` invariant, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\n` production), break screen-reader version announcements at the byte boundary, and propagate into downstream changelog aggregators; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_line_feed_byte() {
    // Pin: `application_icon_name` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !icon_name.contains('\n'),
        "AdwAboutDialog application_icon_name must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is only protected transitively via the `_application_icon_name_has_no_embedded_whitespace` companion (which uses `char::is_whitespace()` and returns true for U+000A LF), so a future refactor that relaxed the no-embedded-whitespace invariant (a workspace-vendoring split or a `concat!` injection between reverse-DNS segments) would naturally drop the `\\n` guard; a stray `\\n` would fail the `gtk::IconTheme` lookup for the dialog header icon (no installed icon is keyed by a `\\n`-bearing name) and fall through to the placeholder, propagate into the desktop file's `Icon=` key / AppStream `<id>` / Flatpak `app-id` / `StartupWMClass` surfaces and trigger desktop-file / AppStream / Flatpak validation rejection at packaging time (each surface requires a single-line reverse-DNS value), break window-class detection for the running process, and break screen-reader icon-name announcements at the byte boundary; got {icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_line_feed_byte() {
    // Pin: `debug_info_filename` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !filename.contains('\n'),
        "AdwAboutDialog debug_info_filename must not contain the `\\n` line-feed byte (0x0A); the current `\\n`-cleanliness is protected by two coupled companions (`_is_non_empty_single_line_with_txt_extension` which explicitly checks `\\n`, and `_has_no_embedded_whitespace` which transitively catches `\\n` via `char::is_whitespace()`), so a future refactor that relaxed both invariants together (a workspace-vendoring split that lifted the filename out of the strict single-line constraint, or a `concat!` injection that introduced a line break between filename segments) would naturally drop both `\\n` guards; a stray `\\n` would either be rejected by the file-chooser at the operating-system layer (most file systems reject `\\n` in filenames) or saved with an embedded line break in the filename, break the file-chooser dialog-title layout, break screen-reader file-chooser announcements at the byte boundary, and propagate into downstream bug-report parsers and telemetry collectors that expect a single-line filename token; got {filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_line_feed_byte() {
    // Pin: `url_helpers` payload must not contain a line feed control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\n'),
            "AdwAboutDialog {label} must not contain the `\\n` line-feed byte (0x0A); `\\n` is never a valid byte inside a URL per RFC 3986 (no URL grammar production rule allows `\\n`); the current `\\n`-cleanliness is only protected transitively via the `_url_helpers_contain_no_embedded_whitespace` companion (which uses `char::is_whitespace()` and returns true for U+000A LF), so a future refactor that relaxed the no-embedded-whitespace invariant (a workspace-vendoring split or a `concat!` injection between URL segments) would naturally drop the `\\n` guard; a stray `\\n` would mis-render the link label as a multi-line entry in the dialog footer (breaking the tidy single-line link row layout), fail or mis-route the click-through to the browser (most browsers reject `\\n`-bearing URLs per WHATWG URL §4.5 or strip the byte before resolving), trigger AppStream / Flatpak URL validation rejection at packaging time, break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling that might split input on `\\n` and treat the URL as two separate link entries; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_bell_byte() {
    // Pin: `developer_name` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x07'),
        "AdwAboutDialog developer-name must not contain the `\\x07` bell byte (0x07); a mid-string `\\x07` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x07` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0007 BEL so this companion does NOT reject `\\x07` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, ring the terminal bell when the developer-name is dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_bell_byte() {
    // Pin: `copyright` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x07'),
        "AdwAboutDialog copyright must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover BEL — making the bell byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x07` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, ring the terminal bell when the copyright is dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_bell_byte() {
    // Pin: `comments` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x07'),
        "AdwAboutDialog comments must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover BEL; a mid-string `\\x07` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x07`), past `_is_ascii_only` (because `\\x07` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x07` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, ring the terminal bell when the comments are dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_bell_byte() {
    // Pin: `developers_entries` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x07'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so a mid-string `\\x07` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x07`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, ring the terminal bell when the credits are dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_bell_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a bell control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x07'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so a mid-string `\\x07` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, ring the terminal bell when the credits are dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_bell_byte() {
    // Pin: `release_notes_version` payload must not contain a bell control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x07'),
        "AdwAboutDialog release_notes_version must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x07`; every byte of `\\x07`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x07` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, ring the terminal bell when the version is dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x07` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_bell_byte() {
    // Pin: `translator_credits` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x07'),
        "AdwAboutDialog translator_credits must not contain the `\\x07` bell byte (0x07); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x07` bytes inside each parsed entry untouched, `\\x07` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as backspace, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x07` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would ring the terminal bell when the po-file is dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_bell_byte() {
    // Pin: `program_name` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x07'),
        "AdwAboutDialog program_name must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so `_has_no_embedded_whitespace` does NOT catch `\\x07` — strictly as dangerous as backspace here, neither caught by the whitespace companion; a stray `\\x07` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, ring the terminal bell on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps (an audible-alert injection / covert side-channel primitive in shared CI environments), and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_bell_byte() {
    // Pin: `version` payload must not contain a bell control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x07'),
        "AdwAboutDialog version must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so `_has_no_embedded_whitespace` does NOT catch `\\x07` — strictly as dangerous as backspace here, neither caught by the whitespace companion; a stray `\\x07` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, ring the terminal bell on update-check or release-tracker dumps piped to `less` (an audible-alert injection / covert side-channel primitive in shared CI environments), and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_bell_byte() {
    // Pin: `application_icon_name` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x07'),
        "AdwAboutDialog application_icon_name must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so `_has_no_embedded_whitespace` does NOT catch `\\x07` — strictly as dangerous as backspace here, neither caught by the whitespace companion; a stray `\\x07` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, and ring the terminal bell when Flathub linter diagnostics are dumped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments); got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_bell_byte() {
    // Pin: `debug_info_filename` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x07'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x07` bell byte (0x07); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so `_has_no_embedded_whitespace` does NOT catch `\\x07` — strictly as dangerous as backspace here, neither caught by the whitespace companion; a stray `\\x07` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x07`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, ring the terminal bell on `ls` / `find` / `tar` output piped to a terminal (an audible-alert injection / covert side-channel primitive in shared CI environments that process the saved debug-info payload), and confuse maintainer triage with control-glyph / bell artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_bell_byte() {
    // Pin: `url_helpers` payload must not contain a bell control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x07'),
            "AdwAboutDialog {label} must not contain the `\\x07` bell byte (0x07) — `\\x07` is never a valid byte inside a URL per RFC 3986 (the bell byte is not in any of the URL grammar's production rules); like BS, BEL is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0007 BEL), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x07` — strictly as dangerous as backspace here, neither caught by the whitespace companion; a stray `\\x07` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%07`-encoding implementations, ring the terminal bell on URL-label dumps piped through a TTY (an audible-alert injection / covert side-channel primitive in shared CI environments), break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_an_acknowledge_byte() {
    // Pin: `developer_name` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x06'),
        "AdwAboutDialog developer-name must not contain the `\\x06` acknowledge byte (0x06); a mid-string `\\x06` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x06` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0006 ACK so this companion does NOT reject `\\x06` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the developer-name is dumped through a serial-bridged TTY, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_an_acknowledge_byte() {
    // Pin: `copyright` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x06'),
        "AdwAboutDialog copyright must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover ACK — making the acknowledge byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x06` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the copyright is dumped through a serial-bridged TTY, break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_an_acknowledge_byte() {
    // Pin: `comments` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x06'),
        "AdwAboutDialog comments must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover ACK; a mid-string `\\x06` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x06`), past `_is_ascii_only` (because `\\x06` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x06` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the comments are dumped through a serial-bridged TTY, break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_an_acknowledge_byte() {
    // Pin: `developers_entries` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x06'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so a mid-string `\\x06` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x06`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` / `_entries_do_not_contain_a_bell_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the credits are dumped through a serial-bridged TTY, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_an_acknowledge_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a acknowledge control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x06'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so a mid-string `\\x06` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_bell_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the credits are dumped through a serial-bridged TTY, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_an_acknowledge_byte() {
    // Pin: `release_notes_version` payload must not contain a acknowledge control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x06'),
        "AdwAboutDialog release_notes_version must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x06`; every byte of `\\x06`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x06` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the version is dumped through a serial-bridged TTY, could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x06` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_an_acknowledge_byte() {
    // Pin: `translator_credits` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x06'),
        "AdwAboutDialog translator_credits must not contain the `\\x06` acknowledge byte (0x06); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x06` bytes inside each parsed entry untouched, `\\x06` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as backspace and bell, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x06` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator when the po-file is dumped through a serial-bridged TTY, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_an_acknowledge_byte() {
    // Pin: `program_name` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x06'),
        "AdwAboutDialog program_name must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so `_has_no_embedded_whitespace` does NOT catch `\\x06` — strictly as dangerous as backspace and bell here, neither caught by the whitespace companion; a stray `\\x06` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps through a serial-bridged TTY, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_an_acknowledge_byte() {
    // Pin: `version` payload must not contain a acknowledge control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x06'),
        "AdwAboutDialog version must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so `_has_no_embedded_whitespace` does NOT catch `\\x06` — strictly as dangerous as backspace and bell here, neither caught by the whitespace companion; a stray `\\x06` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator on update-check or release-tracker dumps piped through a serial-bridged TTY, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_an_acknowledge_byte() {
    // Pin: `application_icon_name` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x06'),
        "AdwAboutDialog application_icon_name must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so `_has_no_embedded_whitespace` does NOT catch `\\x06` — strictly as dangerous as backspace and bell here, neither caught by the whitespace companion; a stray `\\x06` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, and confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator on Flathub linter diagnostics piped through a serial-bridged TTY; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_an_acknowledge_byte() {
    // Pin: `debug_info_filename` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x06'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x06` acknowledge byte (0x06); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so `_has_no_embedded_whitespace` does NOT catch `\\x06` — strictly as dangerous as backspace and bell here, neither caught by the whitespace companion; a stray `\\x06` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x06`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator on `ls` / `find` / `tar` output piped to a serial-bridged TTY in a shared CI environment that processes the saved debug-info payload, and confuse maintainer triage with control-glyph / ACK-frame artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_an_acknowledge_byte() {
    // Pin: `url_helpers` payload must not contain a acknowledge control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x06'),
            "AdwAboutDialog {label} must not contain the `\\x06` acknowledge byte (0x06) — `\\x06` is never a valid byte inside a URL per RFC 3986 (the acknowledge byte is not in any of the URL grammar's production rules); like BEL and BS, ACK is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0006 ACK), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x06` — strictly as dangerous as backspace and bell here, neither caught by the whitespace companion; a stray `\\x06` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%06`-encoding implementations, confuse serial-protocol-bridging tooling that treats `\\x06` as an ACK-frame indicator on URL-label dumps piped through a serial-bridged TTY (a covert side-channel primitive in shared CI environments), break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_an_enquiry_byte() {
    // Pin: `developer_name` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x05'),
        "AdwAboutDialog developer-name must not contain the `\\x05` enquiry byte (0x05); a mid-string `\\x05` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x05` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0005 ENQ so this companion does NOT reject `\\x05` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the developer-name is dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_an_enquiry_byte() {
    // Pin: `copyright` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x05'),
        "AdwAboutDialog copyright must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover ENQ — making the enquiry byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x05` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the copyright is dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_an_enquiry_byte() {
    // Pin: `comments` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x05'),
        "AdwAboutDialog comments must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover ENQ; a mid-string `\\x05` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x05`), past `_is_ascii_only` (because `\\x05` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x05` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the comments are dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_an_enquiry_byte() {
    // Pin: `developers_entries` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x05'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so a mid-string `\\x05` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x05`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` / `_entries_do_not_contain_a_bell_byte` / `_entries_do_not_contain_an_acknowledge_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the credits are dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_an_enquiry_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a enquiry control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x05'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so a mid-string `\\x05` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_bell_byte` / `_empty_credits_section_entries_do_not_contain_an_acknowledge_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the credits are dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_an_enquiry_byte() {
    // Pin: `release_notes_version` payload must not contain a enquiry control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x05'),
        "AdwAboutDialog release_notes_version must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x05`; every byte of `\\x05`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x05` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the version is dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x05` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_an_enquiry_byte() {
    // Pin: `translator_credits` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x05'),
        "AdwAboutDialog translator_credits must not contain the `\\x05` enquiry byte (0x05); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x05` bytes inside each parsed entry untouched, `\\x05` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as acknowledge, backspace, and bell, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x05` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry when the po-file is dumped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_an_enquiry_byte() {
    // Pin: `program_name` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x05'),
        "AdwAboutDialog program_name must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so `_has_no_embedded_whitespace` does NOT catch `\\x05` — strictly as dangerous as acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x05` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_an_enquiry_byte() {
    // Pin: `version` payload must not contain a enquiry control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x05'),
        "AdwAboutDialog version must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so `_has_no_embedded_whitespace` does NOT catch `\\x05` — strictly as dangerous as acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x05` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry on update-check or release-tracker dumps piped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end), and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_an_enquiry_byte() {
    // Pin: `application_icon_name` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x05'),
        "AdwAboutDialog application_icon_name must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so `_has_no_embedded_whitespace` does NOT catch `\\x05` — strictly as dangerous as acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x05` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, and confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry on Flathub linter diagnostics piped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end); got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_an_enquiry_byte() {
    // Pin: `debug_info_filename` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x05'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x05` enquiry byte (0x05); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so `_has_no_embedded_whitespace` does NOT catch `\\x05` — strictly as dangerous as acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x05` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x05`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry on `ls` / `find` / `tar` output piped to a serial-bridged TTY in a shared CI environment that processes the saved debug-info payload (eliciting an unsolicited ACK response from the receiving end), and confuse maintainer triage with control-glyph / ENQ-frame artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_an_enquiry_byte() {
    // Pin: `url_helpers` payload must not contain a enquiry control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x05'),
            "AdwAboutDialog {label} must not contain the `\\x05` enquiry byte (0x05) — `\\x05` is never a valid byte inside a URL per RFC 3986 (the enquiry byte is not in any of the URL grammar's production rules); like ACK and BEL, ENQ is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0005 ENQ), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x05` — strictly as dangerous as acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x05` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%05`-encoding implementations, confuse serial-protocol-bridging tooling that treats `\\x05` as an ENQ-frame inquiry on URL-label dumps piped through a serial-bridged TTY (eliciting an unsolicited ACK response from the receiving end — a covert side-channel primitive in shared CI environments), break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `developer_name` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x04'),
        "AdwAboutDialog developer-name must not contain the `\\x04` end-of-transmission byte (0x04); a mid-string `\\x04` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x04` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0004 EOT so this companion does NOT reject `\\x04` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the attribution mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the attribution through a canonical-mode terminal, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `copyright` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x04'),
        "AdwAboutDialog copyright must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover EOT — making the end-of-transmission byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x04` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the copyright mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the legal-attribution footer through a canonical-mode terminal, break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `comments` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x04'),
        "AdwAboutDialog comments must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover EOT; a mid-string `\\x04` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x04`), past `_is_ascii_only` (because `\\x04` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x04` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the comments mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the elevator-pitch through a canonical-mode terminal, break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_an_end_of_transmission_byte() {
    // Pin: `developers_entries` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x04'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so a mid-string `\\x04` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x04`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` / `_entries_do_not_contain_a_bell_byte` / `_entries_do_not_contain_an_acknowledge_byte` / `_entries_do_not_contain_an_enquiry_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the contributor name mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the credits-page through a canonical-mode terminal, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_an_end_of_transmission_byte(
) {
    // Pin: `empty_credits_section_entries` payload must not contain a end of transmission control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x04'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so a mid-string `\\x04` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_bell_byte` / `_empty_credits_section_entries_do_not_contain_an_acknowledge_byte` / `_empty_credits_section_entries_do_not_contain_an_enquiry_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the contributor name mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the credits-page through a canonical-mode terminal, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `release_notes_version` payload must not contain a end of transmission control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x04'),
        "AdwAboutDialog release_notes_version must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x04`; every byte of `\\x04`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x04` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the version mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the section header through a canonical-mode terminal, could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x04` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `translator_credits` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x04'),
        "AdwAboutDialog translator_credits must not contain the `\\x04` end-of-transmission byte (0x04); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x04` bytes inside each parsed entry untouched, `\\x04` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as enquiry, acknowledge, backspace, and bell, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x04` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte (truncating the attribution mid-string), would trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the po-file through a canonical-mode terminal, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `program_name` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x04'),
        "AdwAboutDialog program_name must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so `_has_no_embedded_whitespace` does NOT catch `\\x04` — strictly as dangerous as enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x04` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps (truncating the dump mid-entry), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing window-list output through a canonical-mode terminal, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `version` payload must not contain a end of transmission control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x04'),
        "AdwAboutDialog version must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so `_has_no_embedded_whitespace` does NOT catch `\\x04` — strictly as dangerous as enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x04` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte on update-check or release-tracker dumps (truncating the version mid-string), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing `cargo metadata` output through a canonical-mode terminal, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `application_icon_name` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x04'),
        "AdwAboutDialog application_icon_name must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so `_has_no_embedded_whitespace` does NOT catch `\\x04` — strictly as dangerous as enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x04` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte on Flathub linter diagnostics (truncating the diagnostic mid-output), and trigger pty-cooked-mode EOF-truncation surprises in tooling capturing the Flathub submission workflow through a canonical-mode terminal; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_an_end_of_transmission_byte() {
    // Pin: `debug_info_filename` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x04'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x04` end-of-transmission byte (0x04); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so `_has_no_embedded_whitespace` does NOT catch `\\x04` — strictly as dangerous as enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x04` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x04`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte on `ls` / `find` / `tar` output piped through a serial-bridged TTY (truncating the directory listing mid-entry), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing directory listings through a canonical-mode terminal in a shared CI environment that processes the saved debug-info payload, and confuse maintainer triage with control-glyph / EOT-frame artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_an_end_of_transmission_byte() {
    // Pin: `url_helpers` payload must not contain a end of transmission control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x04'),
            "AdwAboutDialog {label} must not contain the `\\x04` end-of-transmission byte (0x04) — `\\x04` is never a valid byte inside a URL per RFC 3986 (the end-of-transmission byte is not in any of the URL grammar's production rules); like ENQ, ACK, and BEL, EOT is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0004 EOT), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x04` — strictly as dangerous as enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x04` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%04`-encoding implementations, prematurely terminate in-flight transmissions if dumped through a serial-bridged TTY treating `\\x04` as an EOT framing byte on URL-label dumps (truncating the dump mid-stream — a covert session-truncator primitive in shared CI environments), trigger pty-cooked-mode EOF-truncation surprises in tooling capturing URL-label dumps through a canonical-mode terminal, break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_an_end_of_text_byte() {
    // Pin: `developer_name` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x03'),
        "AdwAboutDialog developer-name must not contain the `\\x03` end-of-text byte (0x03); a mid-string `\\x03` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x03` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0003 ETX so this companion does NOT reject `\\x03` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the attribution at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the attribution through a pty in raw mode, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_an_end_of_text_byte() {
    // Pin: `copyright` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x03'),
        "AdwAboutDialog copyright must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover ETX — making the end-of-text byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x03` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the copyright at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the legal-attribution footer through a pty in raw mode, break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_an_end_of_text_byte() {
    // Pin: `comments` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x03'),
        "AdwAboutDialog comments must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover ETX; a mid-string `\\x03` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x03`), past `_is_ascii_only` (because `\\x03` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x03` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the comments at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the elevator-pitch through a pty in raw mode, break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_an_end_of_text_byte() {
    // Pin: `developers_entries` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x03'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so a mid-string `\\x03` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x03`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` / `_entries_do_not_contain_a_bell_byte` / `_entries_do_not_contain_an_acknowledge_byte` / `_entries_do_not_contain_an_enquiry_byte` / `_entries_do_not_contain_an_end_of_transmission_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the contributor name at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the credits-page through a pty in raw mode, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_an_end_of_text_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a end of text control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x03'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so a mid-string `\\x03` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_bell_byte` / `_empty_credits_section_entries_do_not_contain_an_acknowledge_byte` / `_empty_credits_section_entries_do_not_contain_an_enquiry_byte` / `_empty_credits_section_entries_do_not_contain_an_end_of_transmission_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the contributor name at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the credits-page through a pty in raw mode, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_an_end_of_text_byte() {
    // Pin: `release_notes_version` payload must not contain a end of text control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x03'),
        "AdwAboutDialog release_notes_version must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x03`; every byte of `\\x03`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x03` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the version mid-string), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the section header through a pty in raw mode, could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x03` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_an_end_of_text_byte() {
    // Pin: `translator_credits` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x03'),
        "AdwAboutDialog translator_credits must not contain the `\\x03` end-of-text byte (0x03); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x03` bytes inside each parsed entry untouched, `\\x03` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as end-of-transmission, enquiry, acknowledge, backspace, and bell, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x03` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY (truncating the attribution at the byte boundary), would trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the po-file through a pty in raw mode, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_an_end_of_text_byte() {
    // Pin: `program_name` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x03'),
        "AdwAboutDialog program_name must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so `_has_no_embedded_whitespace` does NOT catch `\\x03` — strictly as dangerous as end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x03` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps (truncating the dump at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing window-list output through a pty in raw mode, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_an_end_of_text_byte() {
    // Pin: `version` payload must not contain a end of text control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x03'),
        "AdwAboutDialog version must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so `_has_no_embedded_whitespace` does NOT catch `\\x03` — strictly as dangerous as end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x03` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY on update-check or release-tracker dumps (truncating the version at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing `cargo metadata` output through a pty in raw mode, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_an_end_of_text_byte() {
    // Pin: `application_icon_name` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x03'),
        "AdwAboutDialog application_icon_name must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so `_has_no_embedded_whitespace` does NOT catch `\\x03` — strictly as dangerous as end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x03` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY on Flathub linter diagnostics (truncating the diagnostic at the byte boundary), and trigger SIGINT-byte (`^C`) tty surprises in tooling capturing the Flathub submission workflow through a pty in raw mode; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_an_end_of_text_byte() {
    // Pin: `debug_info_filename` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x03'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x03` end-of-text byte (0x03); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so `_has_no_embedded_whitespace` does NOT catch `\\x03` — strictly as dangerous as end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x03` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x03`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY on `ls` / `find` / `tar` output piped through a serial-bridged TTY (truncating the directory listing at the byte boundary), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing directory listings through a pty in raw mode in a shared CI environment that processes the saved debug-info payload, and confuse maintainer triage with control-glyph / ETX-frame artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_an_end_of_text_byte() {
    // Pin: `url_helpers` payload must not contain a end of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x03'),
            "AdwAboutDialog {label} must not contain the `\\x03` end-of-text byte (0x03) — `\\x03` is never a valid byte inside a URL per RFC 3986 (the end-of-text byte is not in any of the URL grammar's production rules); like EOT, ENQ, ACK, and BEL, ETX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0003 ETX), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x03` — strictly as dangerous as end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x03` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%03`-encoding implementations, confuse serial-protocol-bridging tooling that treats `\\x03` as an ETX text-segment terminator if dumped through a serial-bridged TTY on URL-label dumps (truncating the dump at the byte boundary — a covert text-segment-truncator primitive in shared CI environments), trigger SIGINT-byte (`^C`) tty surprises in tooling capturing URL-label dumps through a pty in raw mode, break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_start_of_text_byte() {
    // Pin: `developer_name` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x02'),
        "AdwAboutDialog developer-name must not contain the `\\x02` start-of-text byte (0x02); a mid-string `\\x02` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x02` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0002 STX so this companion does NOT reject `\\x02` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` / `_does_not_contain_an_end_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the attribution at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing the attribution through a pty with the default Emacs keymap, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_start_of_text_byte() {
    // Pin: `copyright` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x02'),
        "AdwAboutDialog copyright must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover STX — making the start-of-text byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x02` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` / `_does_not_contain_an_end_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the copyright at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing the legal-attribution footer through a pty with the default Emacs keymap, break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_start_of_text_byte() {
    // Pin: `comments` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x02'),
        "AdwAboutDialog comments must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover STX; a mid-string `\\x02` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x02`), past `_is_ascii_only` (because `\\x02` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x02` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` / `_does_not_contain_an_end_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the comments at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing the elevator-pitch through a pty with the default Emacs keymap, break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_start_of_text_byte() {
    // Pin: `developers_entries` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x02'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so a mid-string `\\x02` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x02`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` / `_entries_do_not_contain_a_bell_byte` / `_entries_do_not_contain_an_acknowledge_byte` / `_entries_do_not_contain_an_enquiry_byte` / `_entries_do_not_contain_an_end_of_transmission_byte` / `_entries_do_not_contain_an_end_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the contributor name at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing the credits-page through a pty with the default Emacs keymap, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_start_of_text_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a start of text control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x02'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so a mid-string `\\x02` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_bell_byte` / `_empty_credits_section_entries_do_not_contain_an_acknowledge_byte` / `_empty_credits_section_entries_do_not_contain_an_enquiry_byte` / `_empty_credits_section_entries_do_not_contain_an_end_of_transmission_byte` / `_empty_credits_section_entries_do_not_contain_an_end_of_text_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the contributor name at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing the credits-page through a pty with the default Emacs keymap, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_start_of_text_byte() {
    // Pin: `release_notes_version` payload must not contain a start of text control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x02'),
        "AdwAboutDialog release_notes_version must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x02`; every byte of `\\x02`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x02` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the version at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing the section header through a pty with the default Emacs keymap, could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x02` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_start_of_text_byte() {
    // Pin: `translator_credits` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x02'),
        "AdwAboutDialog translator_credits must not contain the `\\x02` start-of-text byte (0x02); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x02` bytes inside each parsed entry untouched, `\\x02` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x02` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY (splicing the attribution at the byte boundary into an unexpected follow-on block), would trigger readline `^B` cursor-jump surprises in interactive shells capturing the po-file through a pty with the default Emacs keymap, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_start_of_text_byte() {
    // Pin: `program_name` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x02'),
        "AdwAboutDialog program_name must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so `_has_no_embedded_whitespace` does NOT catch `\\x02` — strictly as dangerous as end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x02` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps (splicing the dump at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in interactive shells capturing window-list output through a pty with the default Emacs keymap, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_start_of_text_byte() {
    // Pin: `version` payload must not contain a start of text control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x02'),
        "AdwAboutDialog version must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so `_has_no_embedded_whitespace` does NOT catch `\\x02` — strictly as dangerous as end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x02` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY on update-check or release-tracker dumps (splicing the version at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in tooling capturing `cargo metadata` output through a pty with the default Emacs keymap, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_start_of_text_byte() {
    // Pin: `application_icon_name` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x02'),
        "AdwAboutDialog application_icon_name must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so `_has_no_embedded_whitespace` does NOT catch `\\x02` — strictly as dangerous as end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x02` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY on Flathub linter diagnostics (splicing the diagnostic at the byte boundary into an unexpected follow-on block), and trigger readline `^B` cursor-jump surprises in tooling capturing the Flathub submission workflow through a pty with the default Emacs keymap; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_start_of_text_byte() {
    // Pin: `debug_info_filename` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x02'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x02` start-of-text byte (0x02); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so `_has_no_embedded_whitespace` does NOT catch `\\x02` — strictly as dangerous as end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x02` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x02`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY on `ls` / `find` / `tar` output piped through a serial-bridged TTY (splicing the directory listing at the byte boundary into an unexpected follow-on block), trigger readline `^B` cursor-jump surprises in tooling capturing directory listings through a pty with the default Emacs keymap in a shared CI environment that processes the saved debug-info payload, and confuse maintainer triage with control-glyph / STX-frame artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_start_of_text_byte() {
    // Pin: `url_helpers` payload must not contain a start of text control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x02'),
            "AdwAboutDialog {label} must not contain the `\\x02` start-of-text byte (0x02) — `\\x02` is never a valid byte inside a URL per RFC 3986 (the start-of-text byte is not in any of the URL grammar's production rules); like ETX, EOT, ENQ, ACK, and BEL, STX is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0002 STX), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x02` — strictly as dangerous as end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x02` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%02`-encoding implementations, confuse serial-protocol-bridging tooling that treats `\\x02` as a STX text-segment opener if dumped through a serial-bridged TTY on URL-label dumps (splicing the dump at the byte boundary into an unexpected follow-on block — a covert text-segment-opener primitive in shared CI environments), trigger readline `^B` cursor-jump surprises in tooling capturing URL-label dumps through a pty with the default Emacs keymap, break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_developer_name_does_not_contain_a_start_of_heading_byte() {
    // Pin: `developer_name` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developer_name;

    let developer = format_app_about_dialog_developer_name();
    assert!(
        !developer.contains('\x01'),
        "AdwAboutDialog developer-name must not contain the `\\x01` start-of-heading byte (0x01); a mid-string `\\x01` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_is_ascii_only` (because `\\x01` is ASCII), past `_has_no_surrounding_whitespace` (which uses `char::is_whitespace()` — Unicode returns false for U+0001 SOH so this companion does NOT reject `\\x01` even at the boundaries, strictly weaker coverage than form-feed / line-feed / vertical-tab / horizontal-tab / carriage-return), past `_starts_with_the_definite_article` / `_ends_with_the_contributors_collective_noun` (which only constrain the literal prefix and suffix), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` / `_does_not_contain_an_end_of_text_byte` / `_does_not_contain_a_start_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog-header attribution row, propagate into the footer copyright row that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the attribution at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the attribution through a pty with the default Emacs keymap, break screen-reader attribution announcements at the byte boundary, and propagate into downstream contributor-attribution scrapers; got {developer:?}",
    );
}

#[test]
fn format_app_about_dialog_copyright_does_not_contain_a_start_of_heading_byte() {
    // Pin: `copyright` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_copyright;

    let copyright = format_app_about_dialog_copyright();
    assert!(
        !copyright.contains('\x01'),
        "AdwAboutDialog copyright must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so the copyright helper's transitive whitespace-boundary / single-line protections from the cluster bytes do NOT cover SOH — making the start-of-heading byte strictly more dangerous than the cluster bytes for this helper; a mid-string `\\x01` slips past `_is_a_single_line_without_embedded_newlines` (which only checks `\\n` and `\\r`), past `_starts_with_copyright_glyph_and_contains_developer_name` / `_ends_with_developer_name` / `_separates_glyph_and_attribution_with_a_single_space` (which only constrain the literal prefix, suffix, and the single byte after the © glyph), past `_does_not_end_with_a_period` / `_does_not_contain_a_year_token_so_it_does_not_drift_across_releases` (which only constrain the trailing byte or scan for digits), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` / `_does_not_contain_an_end_of_text_byte` / `_does_not_contain_a_start_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog footer copyright row, erode the trusted-application legal-attribution surface contract, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the copyright at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the legal-attribution footer through a pty with the default Emacs keymap, break screen-reader copyright announcements at the byte boundary, and propagate into downstream license-attribution aggregators and AGPL-3.0-or-later compliance crawlers; got {copyright:?}",
    );
}

#[test]
fn format_app_about_dialog_comments_does_not_contain_a_start_of_heading_byte() {
    // Pin: `comments` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_comments;

    let comments = format_app_about_dialog_comments();
    assert!(
        !comments.contains('\x01'),
        "AdwAboutDialog comments must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so the comments helper's transitive whitespace-boundary / single-line protections do NOT cover SOH; a mid-string `\\x01` slips past `_is_non_empty_single_line_distinct_from_program_name` (which only checks `\\n` and uses `char::is_whitespace()` for boundary checks — neither catches `\\x01`), past `_is_ascii_only` (because `\\x01` is ASCII), past `_does_not_end_with_a_period_per_libadwaita_convention` (which only constrains the trailing byte), past `_matches_cargo_pkg_description` (a future workspace description that introduced `\\x01` would propagate the byte and this equality pin would still pass), and past `_does_not_contain_a_null_byte` / `_does_not_contain_a_horizontal_tab_byte` / `_does_not_contain_a_carriage_return_byte` / `_does_not_contain_a_vertical_tab_byte` / `_does_not_contain_a_form_feed_byte` / `_does_not_contain_a_backspace_byte` / `_does_not_contain_a_line_feed_byte` / `_does_not_contain_a_bell_byte` / `_does_not_contain_an_acknowledge_byte` / `_does_not_contain_an_enquiry_byte` / `_does_not_contain_an_end_of_transmission_byte` / `_does_not_contain_an_end_of_text_byte` / `_does_not_contain_a_start_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the dialog header comments row, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the comments at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the elevator-pitch through a pty with the default Emacs keymap, break screen-reader comments announcements at the byte boundary, propagate into downstream changelog aggregators and AppStream `<summary>` extractors, and trigger AppStream `<summary>` validation rejection at packaging time; got {comments:?}",
    );
}

#[test]
fn format_app_about_dialog_developers_entries_do_not_contain_a_start_of_heading_byte() {
    // Pin: `developers_entries` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_developers;

    let developers = format_app_about_dialog_developers();
    for (idx, entry) in developers.iter().enumerate() {
        assert!(
            !entry.contains('\x01'),
            "AdwAboutDialog developers entry at index {idx} must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so a mid-string `\\x01` slips past `_is_non_empty_array_of_non_empty_single_line_names` (which only checks `\\n` per entry and uses `char::is_whitespace()` for boundary checks — neither catches `\\x01`), past `_entries_are_distinct` / `_does_not_contain_developer_name` / `_does_not_contain_app_id` / `_does_not_contain_program_name` / `_lists_benjamin_porter` (which only constrain content shape), and past `_entries_do_not_contain_a_null_byte` / `_entries_do_not_contain_a_horizontal_tab_byte` / `_entries_do_not_contain_a_carriage_return_byte` / `_entries_do_not_contain_a_vertical_tab_byte` / `_entries_do_not_contain_a_form_feed_byte` / `_entries_do_not_contain_a_backspace_byte` / `_entries_do_not_contain_a_line_feed_byte` / `_entries_do_not_contain_a_bell_byte` / `_entries_do_not_contain_an_acknowledge_byte` / `_entries_do_not_contain_an_enquiry_byte` / `_entries_do_not_contain_an_end_of_transmission_byte` / `_entries_do_not_contain_an_end_of_text_byte` / `_entries_do_not_contain_a_start_of_text_byte` (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"Developers\" row, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the contributor name at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the credits-page through a pty with the default Emacs keymap, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
        );
    }
}

#[test]
fn format_app_about_dialog_empty_credits_section_entries_do_not_contain_a_start_of_heading_byte() {
    // Pin: `empty_credits_section_entries` payload must not contain a start of heading control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
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
                !entry.contains('\x01'),
                "AdwAboutDialog {label} entry at index {idx} must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so a mid-string `\\x01` slips past any future surrounding-whitespace boundary guards on the {label} helper and past the prior `_empty_credits_section_entries_do_not_contain_a_null_byte` / `_empty_credits_section_entries_do_not_contain_a_horizontal_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_carriage_return_byte` / `_empty_credits_section_entries_do_not_contain_a_vertical_tab_byte` / `_empty_credits_section_entries_do_not_contain_a_form_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_backspace_byte` / `_empty_credits_section_entries_do_not_contain_a_line_feed_byte` / `_empty_credits_section_entries_do_not_contain_a_bell_byte` / `_empty_credits_section_entries_do_not_contain_an_acknowledge_byte` / `_empty_credits_section_entries_do_not_contain_an_enquiry_byte` / `_empty_credits_section_entries_do_not_contain_an_end_of_transmission_byte` / `_empty_credits_section_entries_do_not_contain_an_end_of_text_byte` / `_empty_credits_section_entries_do_not_contain_a_start_of_text_byte` siblings (which each name a different byte specifically); it would render as a literal control glyph in the credits-page \"{label}\" row via `set_{label}`, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the contributor name at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the credits-page through a pty with the default Emacs keymap, propagate into downstream attribution scrapers and `gnome-software` credit aggregators, and break screen-reader contributor-name announcements at the byte boundary; got {entry:?}",
            );
        }
    }
}

#[test]
fn format_app_about_dialog_release_notes_version_does_not_contain_a_start_of_heading_byte() {
    // Pin: `release_notes_version` payload must not contain a start of heading control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_release_notes_version;

    let release_notes_version = format_app_about_dialog_release_notes_version();
    assert!(
        !release_notes_version.contains('\x01'),
        "AdwAboutDialog release_notes_version must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so the `version` helper's transitive `_has_no_embedded_whitespace` guard does NOT catch `\\x01`; every byte of `\\x01`-cleanliness depends solely on the upstream `CARGO_PKG_VERSION` bytes — not screened by Cargo or by any CI gate; a stray `\\x01` would render as a literal control glyph in the dialog's \"What's New in v<release_notes_version>\" section header, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the version at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the section header through a pty with the default Emacs keymap, could prevent the What's New body from rendering on libadwaita versions that strip control bytes when computing the body-region lookup key, trigger AppStream `appstreamcli validate` rejection at packaging time (the strict SemVer grammar has no `\\x01` production), and break screen-reader section-header announcements at the byte boundary; got {release_notes_version:?}",
    );
}

#[test]
fn format_app_about_dialog_translator_credits_does_not_contain_a_start_of_heading_byte() {
    // Pin: `translator_credits` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_translator_credits;

    let translator_credits = format_app_about_dialog_translator_credits();
    assert!(
        !translator_credits.contains('\x01'),
        "AdwAboutDialog translator_credits must not contain the `\\x01` start-of-heading byte (0x01); the libadwaita translator-credits convention splits on `\\n` (LF) only and leaves embedded `\\x01` bytes inside each parsed entry untouched, `\\x01` is NOT classified as whitespace under any permissive whitespace mode (strictly as dangerous as start-of-text, end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell, neither caught by `char::is_whitespace()`) so Pango renders it as a literal control glyph; a stray `\\x01` would render as a hollow box or tofu-like placeholder in the credits-page attribution column, would survive `xgettext` round trips and propagate into every consumer of the .po / .mo file, would confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY (splicing the attribution at the byte boundary into an unexpected header-followed-by-text sequence), would trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing the po-file through a pty with the default Emacs keymap, and would break screen-reader announcements at every attribution-row column boundary; got {translator_credits:?}",
    );
}

#[test]
fn format_app_about_dialog_program_name_does_not_contain_a_start_of_heading_byte() {
    // Pin: `program_name` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_program_name;

    let program_name = format_app_about_dialog_program_name();
    assert!(
        !program_name.contains('\x01'),
        "AdwAboutDialog program_name must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so `_has_no_embedded_whitespace` does NOT catch `\\x01` — strictly as dangerous as start-of-text, end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x01` slips past `_is_ascii_only` / `_is_non_empty_and_not_app_id` / `_matches_format_app_window_title` / `_is_segment_of_application_icon_name` / `_does_not_end_with_a_period` and the prior per-byte siblings, would render as a literal control glyph in the bold dialog-header program-name row, surface in the window manager's taskbar / dock display label via `_matches_format_app_window_title`, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY on `wmctrl -l` / `swaymsg -t get_tree` window-list dumps (splicing the dump at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in interactive shells capturing window-list output through a pty with the default Emacs keymap, and break screen-reader application-name announcements at the byte boundary; got {program_name:?}",
    );
}

#[test]
fn format_app_about_dialog_version_does_not_contain_a_start_of_heading_byte() {
    // Pin: `version` payload must not contain a start of heading control byte —
    // AdwAboutDialog routes through Pango/clipboard/serializer pipelines that
    // mis-handle raw C0 controls (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_version;

    let version = format_app_about_dialog_version();
    assert!(
        !version.contains('\x01'),
        "AdwAboutDialog version must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so `_has_no_embedded_whitespace` does NOT catch `\\x01` — strictly as dangerous as start-of-text, end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x01` slips past `_is_ascii_only` / `_is_non_empty_and_looks_like_semver` / `_starts_with_a_digit` / `_does_not_start_with_a_dot` / `_does_not_end_with_a_dot` / `_has_at_least_three_dot_separated_segments` / `_segments_are_non_empty` / `_matches_cargo_pkg_version` and the prior per-byte siblings, would render as a literal control glyph in the version caption beneath the program name, propagate into the \"What's New in v<version>\" release-notes header that reuses this string, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY on update-check or release-tracker dumps (splicing the version at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in tooling capturing `cargo metadata` output through a pty with the default Emacs keymap, and break screen-reader version-caption announcements at the byte boundary; got {version:?}",
    );
}

#[test]
fn format_app_about_dialog_application_icon_name_does_not_contain_a_start_of_heading_byte() {
    // Pin: `application_icon_name` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_application_icon_name;

    let application_icon_name = format_app_about_dialog_application_icon_name();
    assert!(
        !application_icon_name.contains('\x01'),
        "AdwAboutDialog application_icon_name must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so `_has_no_embedded_whitespace` does NOT catch `\\x01` — strictly as dangerous as start-of-text, end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x01` slips past `_is_ascii_only` / `_is_reverse_dns` / `_has_exactly_four_segments` / `_starts_with_a_lowercase_ascii_letter` / `_ends_with_gui_segment` / `_does_not_end_with_a_dot` / `_does_not_start_with_a_dot` / `_segments_are_non_empty` / `_matches_app_id` / `_program_name_is_segment_of_application_icon_name` and the prior per-byte siblings, would silently miss the `gtk::IconTheme` cache lookup (masking the bug as a placeholder-icon fallback), surface as a malformed window-icon-name property in the X11 / Wayland protocol exchange via `set_icon_name`, propagate into the AppStream metainfo `<id>` field where Flathub's strict reverse-DNS linter would fail the next package submission, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY on Flathub linter diagnostics (splicing the diagnostic at the byte boundary into an unexpected header-followed-by-text sequence), and trigger readline `^A` beginning-of-line cursor-jump surprises in tooling capturing the Flathub submission workflow through a pty with the default Emacs keymap; got {application_icon_name:?}",
    );
}

#[test]
fn format_app_about_dialog_debug_info_filename_does_not_contain_a_start_of_heading_byte() {
    // Pin: `debug_info_filename` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
    use paladin_gtk::app::model::format_app_about_dialog_debug_info_filename;

    let debug_info_filename = format_app_about_dialog_debug_info_filename();
    assert!(
        !debug_info_filename.contains('\x01'),
        "AdwAboutDialog debug_info_filename must not contain the `\\x01` start-of-heading byte (0x01); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so `_has_no_embedded_whitespace` does NOT catch `\\x01` — strictly as dangerous as start-of-text, end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x01` slips past `_is_ascii_only` / `_returns_paladin_debug_info_txt` / `_does_not_contain_path_separators` / `_does_not_start_with_a_dot` / `_contains_exactly_one_period` / `_extension_is_lowercase_txt` / `_is_non_empty_single_line_with_txt_extension` (`str::lines().count() == 1` does not split on `\\x01`) and the prior per-byte siblings, would mis-render as a literal control glyph in the GtkFileDialog filename entry pre-fill, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY on `ls` / `find` / `tar` output piped through a serial-bridged TTY (splicing the directory listing at the byte boundary into an unexpected header-followed-by-text sequence), trigger readline `^A` beginning-of-line cursor-jump surprises in tooling capturing directory listings through a pty with the default Emacs keymap in a shared CI environment that processes the saved debug-info payload, and confuse maintainer triage with control-glyph / SOH-frame artifacts in chat-attachment column renders; got {debug_info_filename:?}",
    );
}

#[test]
fn format_app_about_dialog_url_helpers_do_not_contain_a_start_of_heading_byte() {
    // Pin: `url_helpers` payload must not contain a start of heading control byte —
    // AdwAboutDialog/Pango/clipboard pipelines mis-handle raw C0 controls
    // (truncation, control-glyph rendering, markup breakage).
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
            !url.contains('\x01'),
            "AdwAboutDialog {label} must not contain the `\\x01` start-of-heading byte (0x01) — `\\x01` is never a valid byte inside a URL per RFC 3986 (the start-of-heading byte is not in any of the URL grammar's production rules); like STX, ETX, EOT, ENQ, ACK, and BEL, SOH is NOT matched by `char::is_whitespace()` (Unicode returns false for U+0001 SOH), so `_url_helpers_contain_no_embedded_whitespace` does NOT catch `\\x01` — strictly as dangerous as start-of-text, end-of-text, end-of-transmission, enquiry, acknowledge, backspace, and bell here, neither caught by the whitespace companion; a stray `\\x01` would mis-render as a literal control glyph in the dialog footer link label, fail or mis-route the click-through routing across WHATWG URL §4.5 implementations vs `%01`-encoding implementations, confuse serial-protocol-bridging tooling that treats `\\x01` as a SOH header-block opener if dumped through a serial-bridged TTY on URL-label dumps (splicing the dump at the byte boundary into an unexpected header-followed-by-text sequence — a covert header-block-opener primitive in shared CI environments), trigger readline `^A` beginning-of-line cursor-jump surprises in tooling capturing URL-label dumps through a pty with the default Emacs keymap, break screen-reader link-label announcements at the byte boundary, and propagate into downstream link-checker tooling; got {url:?}",
        );
    }
}

// ---- Window shell & toast surface (Milestone 7 — docs/IMPLEMENTATION_PLAN_04_GTK.md
// §"Window shell and toast surface") ------------------------------------------
//
// These tests pin the gresource paths, the bundled `data/style.css`
// payload, the toast-overlay binding name, and the runtime-side
// `wire_app_css_provider` / `register_app_gresource_bundle` helper
// signatures. The end-to-end CSS provider attach + toast-overlay
// mount live behind GTK initialization and are covered by the
// `xvfb-run` smoke test in `tests/gtk_smoke.rs`; the pure-logic
// assertions below run without a display.

#[test]
fn format_app_style_css_resource_path_returns_org_tamx_paladin_gui_style_css() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Window shell and toast
    // surface", Paladin-specific CSS layers on Adwaita defaults via
    // a `gtk::CssProvider` that loads `data/style.css` from the
    // bundled gresource. The path must match the gresource XML's
    // `<file>` entry exactly, and the prefix carries the reverse-
    // DNS app ID so the resource pool does not collide with other
    // gresource-shipping apps in the same process.
    use paladin_gtk::app::model::format_app_style_css_resource_path;

    assert_eq!(
        format_app_style_css_resource_path(),
        "/org/tamx/Paladin/Gui/style.css",
        "gresource path for the Paladin-specific CSS provider stays in lockstep with `data/paladin-gtk.gresource.xml` and the `wire_app_css_provider` runtime call site",
    );
}

#[test]
fn format_app_style_css_resource_path_is_an_absolute_gresource_path() {
    // gresource paths used by `gtk::CssProvider::load_from_resource`
    // / `gio::resources_lookup_data` are rooted at `/`. A relative
    // form would silently mis-route the lookup at runtime.
    use paladin_gtk::app::model::format_app_style_css_resource_path;

    let path = format_app_style_css_resource_path();
    assert!(
        path.starts_with('/'),
        "gresource path must be rooted at `/`; got {path:?}",
    );
}

#[test]
fn format_app_style_css_resource_path_ends_with_style_css() {
    // The bundled CSS file is shipped at `data/style.css`; the
    // gresource path therefore terminates with `/style.css` so the
    // CssProvider resolves the correct payload.
    use paladin_gtk::app::model::format_app_style_css_resource_path;

    assert!(
        format_app_style_css_resource_path().ends_with("/style.css"),
        "gresource path must end with `/style.css` so the bundled CSS payload is the one the CssProvider loads",
    );
}

#[test]
fn format_app_style_css_resource_path_carries_app_id_segments() {
    // The path prefix mirrors `crate::APP_ID` (`org.tamx.Paladin.Gui`)
    // segmented on `.`, so the resource pool namespaces by reverse-
    // DNS app ID. A drift here would collide with other gresource-
    // shipping apps loaded in the same process.
    use paladin_gtk::app::model::format_app_style_css_resource_path;

    let path = format_app_style_css_resource_path();
    for segment in ["/org/", "/tamx/", "/Paladin/", "/Gui/"] {
        assert!(
            path.contains(segment),
            "gresource path must carry the `{segment}` segment derived from `crate::APP_ID`; got {path:?}",
        );
    }
}

#[test]
fn data_style_css_file_is_shipped_in_the_crate() {
    // `data/style.css` must exist in the crate root so the build-
    // time `glib-build-tools::compile_resources` invocation can
    // bundle it. Without this file the runtime CssProvider load
    // would silently no-op.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/style.css");
    assert!(
        path.is_file(),
        "expected the bundled CSS payload at {}; ensure `crates/paladin-gtk/data/style.css` is committed alongside the gresource XML per docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Crate layout\"",
        path.display(),
    );
}

#[test]
fn data_gresource_xml_is_shipped_in_the_crate() {
    // `data/paladin-gtk.gresource.xml` is the source-of-truth
    // manifest the build script feeds to
    // `glib-build-tools::compile_resources`. Without it the build
    // script has nothing to compile.
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/paladin-gtk.gresource.xml");
    assert!(
        path.is_file(),
        "expected the gresource manifest at {}; ensure `crates/paladin-gtk/data/paladin-gtk.gresource.xml` is committed per docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Crate layout\"",
        path.display(),
    );
}

#[test]
fn data_gresource_xml_references_style_css_under_app_prefix() {
    // The gresource manifest must declare both the `data/style.css`
    // payload and the `/org/tamx/Paladin/Gui` prefix consumed by
    // `format_app_style_css_resource_path` so the bundle compiled
    // by build.rs and the runtime CssProvider load resolve to the
    // same path.
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/paladin-gtk.gresource.xml");
    let xml = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        xml.contains("style.css"),
        "gresource manifest at {} must reference the bundled style.css payload",
        path.display(),
    );
    assert!(
        xml.contains("/org/tamx/Paladin/Gui"),
        "gresource manifest at {} must declare the `/org/tamx/Paladin/Gui` prefix matching `crate::APP_ID`",
        path.display(),
    );
}

#[test]
fn register_app_gresource_bundle_signature_is_zero_argument_unit() {
    // `register_app_gresource_bundle` is the once-per-process
    // bootstrap that hands the compiled gresource bytes to
    // `gio::resources_register`. Calling it before
    // `wire_app_css_provider` is what lets the CssProvider find the
    // `/org/tamx/Paladin/Gui/style.css` payload. Pinning the
    // signature here keeps the call site in `lib.rs::run` stable
    // (`paladin_gtk::app::model::register_app_gresource_bundle()`).
    let _: fn() = paladin_gtk::app::model::register_app_gresource_bundle;
}

#[test]
fn wire_app_css_provider_signature_takes_display_reference() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Window shell and toast
    // surface", `wire_app_css_provider` attaches the Paladin-
    // specific `gtk::CssProvider` (loading `data/style.css` from
    // the gresource bundle) to the supplied display, layered on
    // top of the Adwaita defaults via
    // `gtk::STYLE_PROVIDER_PRIORITY_APPLICATION`. The compile-only
    // signature check pins
    // `fn(&gtk::gdk::Display)` so the smoke-test and runtime call
    // sites stay in lockstep.
    let _: fn(&relm4::gtk::gdk::Display) = paladin_gtk::app::model::wire_app_css_provider;
}

// ---- Bundled placeholder icon (Milestone 7 — docs/IMPLEMENTATION_PLAN_04_GTK.md
// §"Icon resolution") ---------------------------------------------------------
//
// The placeholder `dialog-password-symbolic` icon must ride inside the
// gresource bundle so the lookup resolves identically in native and
// Flatpak builds even when the sandboxed icon theme omits the system
// `dialog-password-symbolic`. The tests below pin the gresource path
// shape, the bundled SVG payload, and the runtime-side
// `wire_app_icon_theme_resource_path` helper signature. The actual
// `IconTheme::add_resource_path` attach lives behind GTK initialization
// and is covered by the `xvfb-run` smoke test in `tests/gtk_smoke.rs`;
// the pure-logic assertions below run without a display.

#[test]
fn format_app_icon_theme_resource_path_returns_org_tamx_paladin_gui_icons() {
    // The icon-theme root sits under the same reverse-DNS app-id
    // prefix as the CSS payload so the gresource pool namespaces by
    // `crate::APP_ID` and never collides with other gresource-shipping
    // apps. The `icons` segment follows the standard icon-theme
    // directory layout consumed by `gtk::IconTheme::add_resource_path`,
    // which expects `<root>/<size>/<context>/<name>.svg` underneath.
    use paladin_gtk::app::model::format_app_icon_theme_resource_path;

    assert_eq!(
        format_app_icon_theme_resource_path(),
        "/org/tamx/Paladin/Gui/icons",
        "gresource path for the Paladin-bundled icon theme stays in lockstep with `data/paladin-gtk.gresource.xml` and the `wire_app_icon_theme_resource_path` runtime call site",
    );
}

#[test]
fn format_app_icon_theme_resource_path_is_an_absolute_gresource_path() {
    // gresource paths handed to `IconTheme::add_resource_path` are
    // rooted at `/`; a relative form would silently mis-route the
    // lookup at runtime.
    use paladin_gtk::app::model::format_app_icon_theme_resource_path;

    let path = format_app_icon_theme_resource_path();
    assert!(
        path.starts_with('/'),
        "gresource path must be rooted at `/`; got {path:?}",
    );
}

#[test]
fn format_app_icon_theme_resource_path_carries_app_id_segments() {
    // The path prefix mirrors `crate::APP_ID` (`org.tamx.Paladin.Gui`)
    // segmented on `.`, so the icon-theme namespace is isolated from
    // every other gresource-shipping app loaded in the same process.
    use paladin_gtk::app::model::format_app_icon_theme_resource_path;

    let path = format_app_icon_theme_resource_path();
    for segment in ["/org/", "/tamx/", "/Paladin/", "/Gui/"] {
        assert!(
            path.contains(segment),
            "gresource path must carry the `{segment}` segment derived from `crate::APP_ID`; got {path:?}",
        );
    }
}

#[test]
fn format_app_placeholder_icon_resource_path_ends_with_dialog_password_symbolic_svg() {
    // The bundled SVG is named after `icon_resolution::PLACEHOLDER_ICON_NAME`
    // so the icon theme resolves the placeholder by the exact key
    // `bind_row_icon` looks up. A drift between the constant and the
    // bundle path would cause a silent fall-through to the system
    // theme (which may not ship the icon in a Flatpak sandbox).
    use paladin_gtk::app::model::format_app_placeholder_icon_resource_path;

    assert!(
        format_app_placeholder_icon_resource_path().ends_with("/dialog-password-symbolic.svg"),
        "placeholder icon must be bundled under its `PLACEHOLDER_ICON_NAME` filename so `IconTheme` resolves it by that key",
    );
}

#[test]
fn format_app_placeholder_icon_resource_path_lives_under_icon_theme_root() {
    // `IconTheme::add_resource_path(root)` resolves icons relative to
    // the root in the standard hicolor layout; the placeholder must
    // therefore live below the root the runtime registers.
    use paladin_gtk::app::model::{
        format_app_icon_theme_resource_path, format_app_placeholder_icon_resource_path,
    };

    let placeholder = format_app_placeholder_icon_resource_path();
    let root = format_app_icon_theme_resource_path();
    let prefix = format!("{root}/");
    assert!(
        placeholder.starts_with(&prefix),
        "placeholder path {placeholder:?} must live below the icon-theme root {root:?}",
    );
}

#[test]
fn format_app_placeholder_icon_resource_path_follows_scalable_actions_layout() {
    // `gtk::IconTheme` discovers symbolic SVGs under
    // `<root>/scalable/actions/<name>.svg` per the freedesktop icon
    // theme spec. Pinning the directory shape here protects against
    // silent drift to a non-discoverable path inside the bundle.
    use paladin_gtk::app::model::format_app_placeholder_icon_resource_path;

    let path = format_app_placeholder_icon_resource_path();
    assert!(
        path.contains("/scalable/actions/"),
        "placeholder gresource path must follow the freedesktop `scalable/actions/<name>.svg` layout so `IconTheme` discovers it; got {path:?}",
    );
}

#[test]
fn data_placeholder_icon_file_is_shipped_in_the_crate() {
    // `data/icons/scalable/actions/dialog-password-symbolic.svg`
    // must exist in the crate root so the build-time
    // `glib-build-tools::compile_resources` invocation can bundle it.
    // Without this file the runtime `IconTheme` lookup would silently
    // fall back to the system theme — which the Flatpak sandbox may
    // not provide — leaving rows iconless.
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("data/icons/scalable/actions/dialog-password-symbolic.svg");
    assert!(
        path.is_file(),
        "expected the bundled placeholder icon at {}; ensure the SVG is committed alongside the gresource XML per docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Crate layout\"",
        path.display(),
    );
}

#[test]
fn data_gresource_xml_references_placeholder_icon_under_scalable_actions() {
    // The gresource manifest must declare both the
    // `icons/scalable/actions/dialog-password-symbolic.svg` payload
    // and the `/org/tamx/Paladin/Gui` prefix consumed by
    // `format_app_placeholder_icon_resource_path` so the bundle
    // compiled by build.rs and the runtime `IconTheme` lookup resolve
    // to the same path.
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/paladin-gtk.gresource.xml");
    let xml = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert!(
        xml.contains("dialog-password-symbolic.svg"),
        "gresource manifest at {} must reference the placeholder SVG payload",
        path.display(),
    );
    assert!(
        xml.contains("icons/scalable/actions/"),
        "gresource manifest at {} must place the placeholder under the freedesktop `scalable/actions/` layout so the icon theme discovers it",
        path.display(),
    );
}

#[test]
fn wire_app_icon_theme_resource_path_signature_takes_display_reference() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Icon resolution",
    // `wire_app_icon_theme_resource_path` adds the gresource icon
    // root to `gtk::IconTheme::for_display(display)` so the bundled
    // placeholder is discoverable. The compile-only signature check
    // pins `fn(&gtk::gdk::Display)` so the smoke-test and runtime
    // call sites stay in lockstep.
    let _: fn(&relm4::gtk::gdk::Display) =
        paladin_gtk::app::model::wire_app_icon_theme_resource_path;
}

#[test]
fn format_app_toast_overlay_widget_name_returns_toast_overlay() {
    // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Window shell and toast
    // surface", every active screen (`InitDialog`,
    // `UnlockComponent`, `StartupErrorComponent`,
    // `AccountListComponent`) is appended into the
    // `adw::ToastOverlay` so state transitions never lose pending
    // toasts. The view! macro names the overlay binding with the
    // string returned here so the post-init handler that posts
    // `AdwToast`s reads the same name from a single source of
    // truth.
    use paladin_gtk::app::model::format_app_toast_overlay_widget_name;

    assert_eq!(
        format_app_toast_overlay_widget_name(),
        "toast_overlay",
        "the AdwToastOverlay widget binding in `AppModel`'s view! macro is named through this helper",
    );
}

#[test]
fn format_app_toast_overlay_widget_name_has_no_separator_or_whitespace() {
    // Widget binding names are bare identifiers; a stray `.` or
    // whitespace would refuse to compile inside the `#[name = "…"]`
    // attribute used in the view! macro.
    use paladin_gtk::app::model::format_app_toast_overlay_widget_name;

    let name = format_app_toast_overlay_widget_name();
    assert!(
        !name.contains('.'),
        "widget binding name must not contain `.`; got {name:?}"
    );
    assert!(
        !name.chars().any(char::is_whitespace),
        "widget binding name must not contain whitespace; got {name:?}",
    );
    assert!(!name.is_empty(), "widget binding name must be non-empty");
}
