// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic startup-error tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/startup_error_logic.rs`"
//! checklist in `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * `default_vault_path` failure routes to `StartupErrorComponent`
//!   without mutating disk.
//! * `inspect` failure routes to `StartupErrorComponent`.
//! * Open failure other than wrong passphrase
//!   (`unsafe_permissions`, `wrong_vault_lock`, `invalid_header`,
//!   `invalid_payload`, `unsupported_format_version`,
//!   `kdf_params_out_of_bounds`, `io_error`) routes to
//!   `StartupErrorComponent`.
//! * `unsafe_permissions` rendering uses the `Some(text)` from
//!   `paladin_core::format_unsafe_permissions(&err)`, falling back to
//!   the generic error text only when the formatter returns `None`.
//! * Retry from `StartupErrorComponent` re-runs vault-path resolution
//!   + `inspect`.

use std::cell::Cell;
use std::io;
use std::path::{Path, PathBuf};

use paladin_core::{
    format_unsafe_permissions, ErrorKind, PaladinError, PermissionSubject, VaultMode, VaultStatus,
};

use paladin_gtk::startup_error::{
    classify_open_error, format_startup_error_marker, render_startup_error, retry,
    OpenErrorRouting, StartupError, StartupErrorSource, STARTUP_ERROR_MARKER_PREFIX,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn unsafe_perms_err() -> PaladinError {
    PaladinError::UnsafePermissions {
        path: PathBuf::from("/home/test/.local/share/paladin/vault.bin"),
        subject: PermissionSubject::VaultFile,
        actual_mode: "0644".to_string(),
        expected_mode: "0600".to_string(),
    }
}

fn wrong_vault_lock_err() -> PaladinError {
    PaladinError::WrongVaultLock {
        expected: VaultMode::Encrypted,
        actual: VaultMode::Plaintext,
    }
}

fn invalid_header_err() -> PaladinError {
    PaladinError::InvalidHeader
}

fn invalid_payload_err() -> PaladinError {
    PaladinError::InvalidPayload {
        reason: "trailing_bytes",
    }
}

fn unsupported_format_version_err() -> PaladinError {
    PaladinError::UnsupportedFormatVersion { format_ver: 99 }
}

fn kdf_oob_err() -> PaladinError {
    PaladinError::KdfParamsOutOfBounds {
        m_kib: 4,
        t: 1,
        p: 1,
    }
}

fn io_err() -> PaladinError {
    PaladinError::IoError {
        operation: "read_vault",
        source: io::Error::new(io::ErrorKind::PermissionDenied, "no access"),
    }
}

fn decrypt_failed_err() -> PaladinError {
    PaladinError::DecryptFailed
}

fn invalid_passphrase_err() -> PaladinError {
    PaladinError::InvalidPassphrase {
        reason: "zero_length",
    }
}

// ---------------------------------------------------------------------------
// `default_vault_path` failure → StartupErrorComponent
// ---------------------------------------------------------------------------

#[test]
fn path_resolution_failure_sources_to_path_resolution() {
    // Per the §"Vault interaction" routing: `default_vault_path` failure
    // routes to `StartupErrorComponent` without mutating disk. The pure-
    // logic helper builds a `StartupError` whose source is
    // `PathResolution` and whose rendering uses the typed error display.
    let err = PaladinError::IoError {
        operation: "resolve_default_vault_path",
        source: io::Error::new(io::ErrorKind::NotFound, "no platform home"),
    };
    let routed = StartupError::from_path_resolution(&err);
    assert_eq!(routed.source, StartupErrorSource::PathResolution);
    assert!(
        routed.rendered.contains("resolve_default_vault_path"),
        "rendered text should include the operation tag: {:?}",
        routed.rendered
    );
}

// ---------------------------------------------------------------------------
// `inspect` failure → StartupErrorComponent
// ---------------------------------------------------------------------------

#[test]
fn inspect_failure_sources_to_inspect() {
    let err = invalid_header_err();
    let routed = StartupError::from_inspect(&err);
    assert_eq!(routed.source, StartupErrorSource::Inspect);
}

#[test]
fn inspect_failure_unsafe_permissions_uses_formatter_output() {
    let err = unsafe_perms_err();
    let routed = StartupError::from_inspect(&err);
    assert_eq!(routed.source, StartupErrorSource::Inspect);
    // Wording must match the core formatter verbatim — same text the
    // CLI / TUI surface.
    let expected = format_unsafe_permissions(&err).expect("UnsafePermissions has formatter text");
    assert_eq!(routed.rendered, expected);
}

// ---------------------------------------------------------------------------
// Open errors other than wrong-passphrase route to StartupErrorComponent
// ---------------------------------------------------------------------------

#[test]
fn open_unsafe_permissions_routes_to_startup() {
    let err = unsafe_perms_err();
    match classify_open_error(&err) {
        OpenErrorRouting::Startup(routed) => {
            assert_eq!(routed.source, StartupErrorSource::Open);
            // Uses the core formatter, not the bare `Display`.
            let expected = format_unsafe_permissions(&err).expect("formatter text");
            assert_eq!(routed.rendered, expected);
        }
        OpenErrorRouting::InlinePassphrase => {
            panic!("unsafe_permissions must route to StartupErrorComponent");
        }
    }
}

#[test]
fn open_wrong_vault_lock_routes_to_startup() {
    let err = wrong_vault_lock_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::Startup(_)
    ));
}

#[test]
fn open_invalid_header_routes_to_startup() {
    let err = invalid_header_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::Startup(_)
    ));
}

#[test]
fn open_invalid_payload_routes_to_startup() {
    let err = invalid_payload_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::Startup(_)
    ));
}

#[test]
fn open_unsupported_format_version_routes_to_startup() {
    let err = unsupported_format_version_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::Startup(_)
    ));
}

#[test]
fn open_kdf_params_out_of_bounds_routes_to_startup() {
    let err = kdf_oob_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::Startup(_)
    ));
}

#[test]
fn open_io_error_routes_to_startup() {
    let err = io_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::Startup(_)
    ));
}

#[test]
fn open_decrypt_failed_stays_inline() {
    // §"Vault interaction": "Wrong passphrase surfaces inline."
    // `DecryptFailed` is the AEAD-authentication failure surfaced for an
    // incorrect passphrase against the encrypted vault.
    let err = decrypt_failed_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::InlinePassphrase
    ));
}

#[test]
fn open_invalid_passphrase_stays_inline() {
    // Empty / pre-KDF-rejected passphrases also stay inline at the
    // UnlockComponent (mirrors CLI / TUI which never escalate empty
    // passphrase entry to a startup-error transition).
    let err = invalid_passphrase_err();
    assert!(matches!(
        classify_open_error(&err),
        OpenErrorRouting::InlinePassphrase
    ));
}

// ---------------------------------------------------------------------------
// `unsafe_permissions` rendering: format_unsafe_permissions returns Some,
// fallback to Display when None.
// ---------------------------------------------------------------------------

#[test]
fn render_unsafe_permissions_uses_formatter_output() {
    let err = unsafe_perms_err();
    let rendered = render_startup_error(&err);
    let expected = format_unsafe_permissions(&err).expect("formatter text");
    assert_eq!(rendered, expected);
    // Sanity-check the formatter output names the chmod hint so the
    // wording really does match the CLI / TUI rendering.
    assert!(rendered.contains("chmod 0600"));
}

#[test]
fn render_non_unsafe_permissions_falls_back_to_display() {
    // For any non-`UnsafePermissions` variant, the formatter returns
    // `None` and `render_startup_error` falls back to the typed
    // `Display` text. We assert exact equality to the `to_string()` so
    // the fallback path is locked in.
    let err = invalid_header_err();
    assert!(format_unsafe_permissions(&err).is_none());
    let rendered = render_startup_error(&err);
    assert_eq!(rendered, err.to_string());
}

#[test]
fn classify_open_unsafe_permissions_rendering_is_formatter_text() {
    let err = unsafe_perms_err();
    let OpenErrorRouting::Startup(routed) = classify_open_error(&err) else {
        panic!("expected Startup routing");
    };
    let expected = format_unsafe_permissions(&err).expect("formatter text");
    assert_eq!(routed.rendered, expected);
}

#[test]
fn classify_open_io_error_falls_back_to_display() {
    let err = io_err();
    let OpenErrorRouting::Startup(routed) = classify_open_error(&err) else {
        panic!("expected Startup routing");
    };
    assert_eq!(routed.rendered, err.to_string());
}

// ---------------------------------------------------------------------------
// Retry re-runs vault-path resolution + inspect.
// ---------------------------------------------------------------------------

#[test]
fn retry_invokes_resolve_then_inspect_in_order() {
    let calls: Cell<Vec<&'static str>> = Cell::new(Vec::new());
    let observed_path: Cell<Option<PathBuf>> = Cell::new(None);

    let resolve = || {
        let mut log = calls.take();
        log.push("resolve");
        calls.set(log);
        Ok(PathBuf::from("/tmp/test-vault.bin"))
    };
    let inspect = |path: &Path| {
        let mut log = calls.take();
        log.push("inspect");
        calls.set(log);
        observed_path.set(Some(path.to_path_buf()));
        Ok(VaultStatus::Encrypted)
    };

    let outcome = retry(resolve, inspect).expect("retry succeeds");
    assert_eq!(outcome.0, PathBuf::from("/tmp/test-vault.bin"));
    assert_eq!(outcome.1, VaultStatus::Encrypted);

    let log = calls.take();
    assert_eq!(
        log,
        vec!["resolve", "inspect"],
        "retry must call resolve, then inspect"
    );
    assert_eq!(
        observed_path.take(),
        Some(PathBuf::from("/tmp/test-vault.bin")),
        "inspect must be passed the resolved path"
    );
}

#[test]
fn retry_resolve_failure_does_not_call_inspect() {
    let inspect_called: Cell<bool> = Cell::new(false);
    let resolve = || {
        Err(PaladinError::IoError {
            operation: "resolve_default_vault_path",
            source: io::Error::new(io::ErrorKind::NotFound, "no platform home"),
        })
    };
    let inspect = |_: &Path| -> Result<VaultStatus, PaladinError> {
        inspect_called.set(true);
        Ok(VaultStatus::Missing)
    };

    let err = retry(resolve, inspect).expect_err("resolve failure surfaces");
    assert_eq!(err.source, StartupErrorSource::PathResolution);
    assert_eq!(err.kind, ErrorKind::IoError);
    assert!(
        !inspect_called.get(),
        "inspect must not run after resolve failure"
    );
}

#[test]
fn retry_inspect_failure_routes_to_inspect_source() {
    let resolve = || Ok(PathBuf::from("/tmp/x"));
    let inspect = |_: &Path| -> Result<VaultStatus, PaladinError> { Err(invalid_header_err()) };

    let err = retry(resolve, inspect).expect_err("inspect failure surfaces");
    assert_eq!(err.source, StartupErrorSource::Inspect);
    assert_eq!(err.kind, ErrorKind::InvalidHeader);
}

#[test]
fn retry_inspect_unsafe_permissions_routes_with_formatter_text() {
    // `inspect()` itself bypasses the §4.3 permission check (the §4.7
    // note on `inspect` calls it out explicitly), but other surfaces
    // can still return `UnsafePermissions` and the retry path must
    // render the formatter wording.
    let unsafe_err = unsafe_perms_err();
    let expected = format_unsafe_permissions(&unsafe_err).expect("formatter text");
    let resolve = || Ok(PathBuf::from("/tmp/x"));
    let inspect = |_: &Path| -> Result<VaultStatus, PaladinError> { Err(unsafe_perms_err()) };

    let err = retry(resolve, inspect).expect_err("inspect failure surfaces");
    assert_eq!(err.source, StartupErrorSource::Inspect);
    assert_eq!(err.rendered, expected);
}

// ---------------------------------------------------------------------------
// `format_startup_error_marker` — stdout contract for the smoke test
// ---------------------------------------------------------------------------

#[test]
fn startup_error_marker_prefix_is_paladin_gtk_namespaced() {
    // Every smoke-test marker `paladin-gtk` emits under
    // `--exit-after-startup` shares the `paladin-gtk: ` prefix so
    // tests can grep for the namespace and tell our lines apart from
    // GTK / libadwaita warnings on the same stream.
    assert!(
        STARTUP_ERROR_MARKER_PREFIX.starts_with("paladin-gtk: "),
        "STARTUP_ERROR_MARKER_PREFIX must share the paladin-gtk namespace: {STARTUP_ERROR_MARKER_PREFIX:?}",
    );
    assert!(
        STARTUP_ERROR_MARKER_PREFIX.ends_with('='),
        "STARTUP_ERROR_MARKER_PREFIX must end with `=` so the body \
         appears immediately after: {STARTUP_ERROR_MARKER_PREFIX:?}",
    );
}

#[test]
fn format_startup_error_marker_inlines_rendered_text() {
    // Single-line variant: the entire rendered body fits on one line,
    // so the marker is the prefix followed by the rendered text verbatim.
    let err = invalid_header_err();
    let routed = StartupError::from_inspect(&err);
    let marker = format_startup_error_marker(&routed);
    assert_eq!(
        marker,
        format!("{STARTUP_ERROR_MARKER_PREFIX}{}", routed.rendered),
    );
}

#[test]
fn format_startup_error_marker_replaces_newlines_with_pipes() {
    // The `UnsafePermissions` formatter produces a multi-line body so
    // the user sees the chmod hint on its own line. The smoke-test
    // marker is single-line so test assertions can grep with
    // `stdout.contains(&...)`; we collapse embedded `\n` to `|` which
    // does not appear in any error renderer.
    let err = unsafe_perms_err();
    let routed = StartupError::from_open(&err);
    let marker = format_startup_error_marker(&routed);
    assert!(
        !marker.contains('\n'),
        "marker must be single-line: {marker:?}",
    );
    assert!(
        marker.starts_with(STARTUP_ERROR_MARKER_PREFIX),
        "marker must start with the namespaced prefix: {marker:?}",
    );
    // Sanity: the chmod hint and `expected_mode` from the formatter
    // both survive the newline collapse, so the marker is still a
    // faithful projection of `rendered` (just on one line).
    assert!(
        marker.contains("chmod 0600"),
        "marker should retain the chmod hint from format_unsafe_permissions: {marker:?}",
    );
    assert!(
        marker.contains("0644"),
        "marker should retain the actual mode from format_unsafe_permissions: {marker:?}",
    );
}

#[test]
fn format_startup_error_marker_is_stable_across_sources() {
    // The marker reads from `rendered` only; identical rendered text
    // with different `StartupErrorSource` tags produces identical
    // marker lines (the source is a routing field, not a display field).
    let err = invalid_header_err();
    let from_inspect = format_startup_error_marker(&StartupError::from_inspect(&err));
    let from_open = format_startup_error_marker(&StartupError::from_open(&err));
    assert_eq!(from_inspect, from_open);
}

// ---------------------------------------------------------------------------
// Structural assertions
// ---------------------------------------------------------------------------

#[test]
fn startup_error_carries_kind_for_consumers() {
    // The component layer reads `kind` to decide whether to surface a
    // retry CTA or quit-only chrome. Lock in the field on every
    // constructor so that contract holds.
    let err = unsafe_perms_err();
    assert_eq!(
        StartupError::from_inspect(&err).kind,
        ErrorKind::UnsafePermissions
    );
    let err = invalid_header_err();
    assert_eq!(
        StartupError::from_inspect(&err).kind,
        ErrorKind::InvalidHeader
    );
}

#[test]
fn format_startup_error_icon_name_returns_dialog_error_symbolic() {
    // The `StartupErrorComponent`'s `adw::StatusPage::set_icon_name`
    // attribute is populated from this helper. The icon
    // (`"dialog-error-symbolic"`) is the freedesktop-standard
    // glyph for an error surface shipped by `adwaita-icon-theme`
    // — resolving through the system icon theme so the wordless
    // glyph matches every other GNOME app's error surface. The
    // `-symbolic` suffix is required by the libadwaita HIG for
    // `AdwStatusPage` icons so the glyph recolors with the theme.
    // Pinning the icon name through a helper keeps the string in
    // one place shared by the widget binding and the pure-logic
    // tests.
    //
    // No TUI parity: the TUI is text-only and has no icon to
    // mirror. Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_icon_name`
    // and
    // `paladin_gtk::init_dialog::format_init_dialog_icon_name`
    // on the dialog-status-icon side; together they pin every
    // first-mount dialog's freedesktop glyph against a single
    // source of truth.
    use paladin_gtk::startup_error::format_startup_error_icon_name;

    assert_eq!(
        format_startup_error_icon_name(),
        "dialog-error-symbolic",
        "AdwStatusPage icon uses the freedesktop-standard error glyph",
    );
}

#[test]
fn format_startup_error_icon_name_ends_with_symbolic_suffix() {
    // The libadwaita HIG requires `AdwStatusPage` icons to be
    // symbolic so they recolor with the theme; the icon-name
    // contract is to end with `-symbolic`. Pinning a suffix
    // assertion alongside the full-string assertion guards
    // against an accidental rename to a non-symbolic glyph.
    use paladin_gtk::startup_error::format_startup_error_icon_name;

    let icon = format_startup_error_icon_name();
    assert!(
        icon.ends_with("-symbolic"),
        "AdwStatusPage icon name must end with `-symbolic` for HIG-conformant theming; got {icon:?}",
    );
}

#[test]
fn format_startup_error_title_returns_startup_error() {
    // The `StartupErrorComponent`'s `adw::StatusPage::set_title`
    // attribute is populated from this helper. The wording
    // (`"Startup error"`) names the error class without
    // restating the specific failure — the per-error rendered
    // text lives in the StatusPage's description body, sourced
    // from the typed `PaladinError::Display` impl through
    // `StartupError::rendered`. Pinning the title through a
    // helper keeps the wording in one place shared by the widget
    // binding and the pure-logic tests in
    // `tests/startup_error_logic.rs`.
    //
    // No TUI parity: the TUI renders the equivalent surface as
    // its own block-titled view (`"Startup error"` is the GTK
    // wording chosen to match the dialog-header convention used
    // by every other dialog title in this crate). Sibling of
    // `paladin_gtk::unlock_dialog::format_unlock_dialog_title`,
    // `paladin_gtk::init_dialog::format_init_dialog_title`,
    // `paladin_gtk::rename_dialog::format_rename_dialog_title`,
    // and `paladin_gtk::add_account::format_add_dialog_title`
    // on the dialog-header-title side; together they pin every
    // dialog's titled surface against a single source of truth.
    use paladin_gtk::startup_error::format_startup_error_title;

    assert_eq!(
        format_startup_error_title(),
        "Startup error",
        "AdwStatusPage title uses the dialog-header-style wording for the error class",
    );
}

#[test]
fn format_startup_error_retry_label_returns_retry() {
    // Per §"Vault interaction": the `StartupErrorComponent`
    // surfaces a Retry action that re-runs the
    // path-resolution-then-inspect probe (the `retry` helper in
    // the same module). The HIG-aligned label for the action
    // button is the bare `"Retry"` verb — the same wording the
    // GNOME stack uses for analogous probe re-runs on
    // `AdwStatusPage` surfaces. Pinning the wording through a
    // helper keeps the button label in one place shared by the
    // widget binding and the pure-logic tests in
    // `tests/startup_error_logic.rs`.
    use paladin_gtk::startup_error::format_startup_error_retry_label;

    assert_eq!(
        format_startup_error_retry_label(),
        "Retry",
        "AdwStatusPage retry button label uses the HIG-aligned bare verb wording",
    );
}

#[test]
fn format_startup_error_retry_label_is_non_empty_single_line_distinct_from_title() {
    // Defense-in-depth: the retry button label must be non-empty
    // (an empty label would render a blank button), must be a
    // single line (the action button caption is rendered
    // inline), and must be distinct from the status-page title
    // so the action button caption and the surface title are
    // visually separable rather than rendering the same string
    // twice.
    use paladin_gtk::startup_error::{
        format_startup_error_retry_label, format_startup_error_title,
    };

    let label = format_startup_error_retry_label();
    assert!(
        !label.is_empty(),
        "AdwStatusPage retry button label must be non-empty; got {label:?}",
    );
    assert!(
        !label.contains('\n'),
        "AdwStatusPage retry button label must be a single line (no embedded newlines); got {label:?}",
    );
    assert!(
        !label.starts_with(char::is_whitespace),
        "AdwStatusPage retry button label must not start with whitespace; got {label:?}",
    );
    assert!(
        !label.ends_with(char::is_whitespace),
        "AdwStatusPage retry button label must not end with whitespace; got {label:?}",
    );
    assert_ne!(
        label,
        format_startup_error_title(),
        "AdwStatusPage retry button label must be distinct from the surface title so the action button caption and the title are visually separable",
    );
}

#[test]
fn format_startup_error_quit_label_returns_quit() {
    // Per §"Vault interaction": the `StartupErrorComponent`
    // surfaces a Quit action alongside Retry; pressing it tears
    // the application down via the primary `app.quit` action so
    // the user can exit without resolving the startup error.
    // The HIG-aligned label for that secondary action button is
    // the bare verb `"Quit"` — the same wording the primary
    // menu's Quit entry uses (see
    // `format_app_menu_quit_label`) so the application's
    // quit-action vocabulary stays consistent across surfaces.
    use paladin_gtk::startup_error::format_startup_error_quit_label;

    assert_eq!(
        format_startup_error_quit_label(),
        "Quit",
        "AdwStatusPage quit button label uses the HIG-aligned bare verb wording matching the primary menu Quit entry",
    );
}

#[test]
fn format_startup_error_quit_label_matches_primary_menu_quit_label() {
    // Cross-check: the startup-error Quit button and the
    // primary menu's Quit entry should render the exact same
    // wording so the application's quit-action vocabulary stays
    // consistent across surfaces. A drift between the two
    // would surface as a confusing "Quit" vs "Exit" inconsistency
    // when the same action is reached from two different
    // surfaces.
    use paladin_gtk::app::model::format_app_menu_quit_label;
    use paladin_gtk::startup_error::format_startup_error_quit_label;

    assert_eq!(
        format_startup_error_quit_label(),
        format_app_menu_quit_label(),
        "AdwStatusPage quit button label must match the primary menu Quit entry so the application's quit-action vocabulary stays consistent",
    );
}

#[test]
fn format_startup_error_quit_label_is_non_empty_single_line_distinct_from_retry() {
    // Defense-in-depth: the quit button label must be non-empty
    // (an empty label would render a blank button), must be a
    // single line, and must be distinct from the retry button
    // label so the two action buttons read as separate options
    // rather than rendering the same caption twice.
    use paladin_gtk::startup_error::{
        format_startup_error_quit_label, format_startup_error_retry_label,
    };

    let label = format_startup_error_quit_label();
    assert!(
        !label.is_empty(),
        "AdwStatusPage quit button label must be non-empty; got {label:?}",
    );
    assert!(
        !label.contains('\n'),
        "AdwStatusPage quit button label must be a single line (no embedded newlines); got {label:?}",
    );
    assert!(
        !label.starts_with(char::is_whitespace),
        "AdwStatusPage quit button label must not start with whitespace; got {label:?}",
    );
    assert!(
        !label.ends_with(char::is_whitespace),
        "AdwStatusPage quit button label must not end with whitespace; got {label:?}",
    );
    assert_ne!(
        label,
        format_startup_error_retry_label(),
        "AdwStatusPage quit button label must be distinct from the retry button label so the two action buttons read as separate options",
    );
}
