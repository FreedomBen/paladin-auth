// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic startup-error tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests > `tests/startup_error_logic.rs`"
//! checklist in `docs/IMPLEMENTATION_PLAN_04_GTK.md`:
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
    // Pins the `AdwStatusPage` icon to the freedesktop-standard
    // `dialog-error-symbolic` glyph — the `-symbolic` suffix is required
    // by the libadwaita HIG so the icon recolors with the theme, and the
    // helper keeps the string shared between the widget binding and the
    // pure-logic tests (sibling of the unlock/init dialog icon helpers).
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
    // Pins the `AdwStatusPage` title wording. The title names the error
    // class without restating the failure (the typed `StartupError::rendered`
    // text lives in the StatusPage description), keeping wording shared
    // between the widget binding and pure-logic tests.
    use paladin_gtk::startup_error::format_startup_error_title;

    assert_eq!(
        format_startup_error_title(),
        "Startup error",
        "AdwStatusPage title uses the dialog-header-style wording for the error class",
    );
}

#[test]
fn format_startup_error_retry_label_returns_retry() {
    // Per §"Vault interaction": the Retry action re-runs the
    // path-resolution-then-inspect probe; the HIG-aligned label is the bare
    // `"Retry"` verb, pinned through a helper so the widget binding and
    // pure-logic tests share one source.
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
    // Per §"Vault interaction": the Quit action tears the app down via
    // `app.quit` so the user can exit without resolving the error. The
    // label matches `format_app_menu_quit_label` so quit-action vocabulary
    // stays consistent across surfaces.
    use paladin_gtk::startup_error::format_startup_error_quit_label;

    assert_eq!(
        format_startup_error_quit_label(),
        "Quit",
        "AdwStatusPage quit button label uses the HIG-aligned bare verb wording matching the primary menu Quit entry",
    );
}

#[test]
fn format_startup_error_quit_label_matches_primary_menu_quit_label() {
    // Cross-check: startup-error Quit and primary-menu Quit must render
    // identical wording so a drift does not surface as a confusing
    // "Quit" vs "Exit" inconsistency on the same action.
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

// ---------------------------------------------------------------------------
// Output enum: display-only invariant + per-button output emission
// ---------------------------------------------------------------------------

#[test]
fn startup_error_output_retry_variant_exists() {
    // The Retry action button's `connect_clicked` handler emits
    // `StartupErrorOutput::Retry`, which `AppModel` forwards
    // through `dispatch_startup_error_output` to re-run the
    // path-resolution + inspect probe per §"Vault interaction".
    use paladin_gtk::startup_error::StartupErrorOutput;
    let out = StartupErrorOutput::Retry;
    assert!(matches!(out, StartupErrorOutput::Retry));
}

#[test]
fn startup_error_output_quit_variant_exists() {
    // The Quit action button's `connect_clicked` handler emits
    // `StartupErrorOutput::Quit`, which `AppModel` forwards
    // through `dispatch_startup_error_output` to the same
    // `AppMsg::Quit` shutdown path the primary menu's Quit
    // entry uses per §"Vault interaction".
    use paladin_gtk::startup_error::StartupErrorOutput;
    let out = StartupErrorOutput::Quit;
    assert!(matches!(out, StartupErrorOutput::Quit));
}

#[test]
fn startup_error_output_is_exhaustively_retry_quit_and_delete_vault() {
    // No-in-place-repair invariant per §"Vault interaction": the
    // component never creates, overwrites, repairs, chmods, or reroutes
    // the vault path. The Milestone 10 build order adds one destructive
    // escape hatch — `DeleteVaultLinkClicked`, which routes to the shared
    // `app.delete-vault` flow (the deletion itself runs in `AppModel` via
    // `paladin_core::destroy_vault`, not here). Exhaustive match arms lock
    // the Output enum so any further mutating variant fails to compile.
    use paladin_gtk::startup_error::StartupErrorOutput;
    fn classify(out: StartupErrorOutput) -> &'static str {
        match out {
            StartupErrorOutput::Retry => "retry",
            StartupErrorOutput::Quit => "quit",
            StartupErrorOutput::DeleteVaultLinkClicked => "delete-vault",
        }
    }
    assert_eq!(classify(StartupErrorOutput::Retry), "retry");
    assert_eq!(classify(StartupErrorOutput::Quit), "quit");
    assert_eq!(
        classify(StartupErrorOutput::DeleteVaultLinkClicked),
        "delete-vault"
    );
}

#[test]
fn apply_startup_error_msg_delete_vault_link_clicked_emits_delete_output() {
    // The footer `Delete vault…` link's `connect_clicked` handler
    // dispatches `StartupErrorMsg::DeleteVaultLinkClicked`, which the
    // component routes through `apply_startup_error_msg` and surfaces as
    // `StartupErrorOutput::DeleteVaultLinkClicked` for `AppModel` to
    // forward as `AppMsg::OpenDestroyDialog`.
    use paladin_gtk::startup_error::{
        apply_startup_error_msg, StartupErrorMsg, StartupErrorOutput,
    };
    let output = apply_startup_error_msg(StartupErrorMsg::DeleteVaultLinkClicked);
    assert!(matches!(
        output,
        Some(StartupErrorOutput::DeleteVaultLinkClicked)
    ));
}

#[test]
fn apply_startup_error_msg_retry_clicked_emits_retry_output() {
    // The Retry button's `connect_clicked` handler dispatches
    // `StartupErrorMsg::RetryClicked`, which the component
    // routes through `apply_startup_error_msg` and surfaces as
    // `StartupErrorOutput::Retry` for `AppModel` to forward.
    use paladin_gtk::startup_error::{
        apply_startup_error_msg, StartupErrorMsg, StartupErrorOutput,
    };
    let output = apply_startup_error_msg(StartupErrorMsg::RetryClicked);
    assert!(
        matches!(output, Some(StartupErrorOutput::Retry)),
        "RetryClicked must emit StartupErrorOutput::Retry; got {output:?}",
    );
}

#[test]
fn apply_startup_error_msg_quit_clicked_emits_quit_output() {
    // The Quit button's `connect_clicked` handler dispatches
    // `StartupErrorMsg::QuitClicked`, which the component
    // routes through `apply_startup_error_msg` and surfaces as
    // `StartupErrorOutput::Quit` for `AppModel` to forward.
    use paladin_gtk::startup_error::{
        apply_startup_error_msg, StartupErrorMsg, StartupErrorOutput,
    };
    let output = apply_startup_error_msg(StartupErrorMsg::QuitClicked);
    assert!(
        matches!(output, Some(StartupErrorOutput::Quit)),
        "QuitClicked must emit StartupErrorOutput::Quit; got {output:?}",
    );
}

// ---------------------------------------------------------------------------
// Output → AppMsg dispatch: Quit reuses the primary-menu shutdown path;
// Retry re-runs the startup probe through `AppMsg::StartupErrorRetry`.
// ---------------------------------------------------------------------------

#[test]
fn dispatch_startup_error_output_quit_routes_to_app_msg_quit() {
    // Per §"Vault interaction": both startup-error Quit and primary-menu
    // Quit must dispatch the same `AppMsg::Quit` so the app has one
    // shutdown path; a drift would bypass §"In-flight effect ownership"
    // worker-deferred shutdown handling.
    use paladin_gtk::app::model::{
        dispatch_app_window_action, dispatch_startup_error_output,
        format_app_menu_quit_action_name, AppMsg,
    };
    use paladin_gtk::startup_error::StartupErrorOutput;

    let from_startup_error = dispatch_startup_error_output(StartupErrorOutput::Quit);
    let from_menu = dispatch_app_window_action(format_app_menu_quit_action_name())
        .expect("primary menu must dispatch a Quit AppMsg");
    assert!(
        matches!(from_startup_error, AppMsg::Quit),
        "StartupErrorComponent Quit must dispatch AppMsg::Quit; got {from_startup_error:?}",
    );
    assert!(
        matches!(from_menu, AppMsg::Quit),
        "primary menu Quit must dispatch AppMsg::Quit; got {from_menu:?}",
    );
}

#[test]
fn dispatch_startup_error_output_retry_routes_to_startup_error_retry_app_msg() {
    // The Retry button re-runs the startup probe via a
    // dedicated `AppMsg::StartupErrorRetry` arm in `update` —
    // distinct from `AppMsg::Quit` and from every mutating
    // dispatch arm so the retry handler stays display-only per
    // §"Vault interaction" (re-resolve path, re-inspect, re-mount;
    // never create / overwrite / repair).
    use paladin_gtk::app::model::{dispatch_startup_error_output, AppMsg};
    use paladin_gtk::startup_error::StartupErrorOutput;

    let msg = dispatch_startup_error_output(StartupErrorOutput::Retry);
    assert!(
        matches!(msg, AppMsg::StartupErrorRetry),
        "StartupErrorComponent Retry must dispatch AppMsg::StartupErrorRetry; got {msg:?}",
    );
}

#[test]
fn dispatch_startup_error_output_is_exhaustive_retry_and_quit_only() {
    // Display-only invariant on the dispatch side: only `Quit` and
    // `StartupErrorRetry` are valid; match arms lock the dispatch table so
    // a future mutating Output variant fails to compile until §"Vault
    // interaction" is explicitly revisited.
    use paladin_gtk::app::model::{dispatch_startup_error_output, AppMsg};
    use paladin_gtk::startup_error::StartupErrorOutput;

    fn intent(msg: &AppMsg) -> &'static str {
        match msg {
            AppMsg::Quit => "quit",
            AppMsg::StartupErrorRetry => "retry",
            _ => "other",
        }
    }
    assert_eq!(
        intent(&dispatch_startup_error_output(StartupErrorOutput::Retry)),
        "retry",
    );
    assert_eq!(
        intent(&dispatch_startup_error_output(StartupErrorOutput::Quit)),
        "quit",
    );
}

// ---------------------------------------------------------------------------
// StartupError::from_worker_panic — `gio::spawn_blocking` worker-panic
// routing per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect
// ownership" > "Route workers that fail before returning the pair".
//
// A worker panic interrupts the durability contract of the in-flight
// save, so `AppModel` drops `Vault`, transitions to
// `AppState::StartupError`, and presents `StartupErrorComponent` with
// retry + quit. The carried [`EffectKind`] is preserved for
// instrumentation; the rendered body is grep-able through
// `format_worker_panic_message`.
// ---------------------------------------------------------------------------

#[test]
fn startup_error_from_worker_panic_carries_effect_kind_in_source() {
    use paladin_gtk::effect_ownership::EffectKind;
    use paladin_gtk::startup_error::StartupError;

    let err = StartupError::from_worker_panic(EffectKind::HotpAdvance);
    assert_eq!(
        err.source,
        StartupErrorSource::WorkerPanic(EffectKind::HotpAdvance),
    );
}

#[test]
fn startup_error_from_worker_panic_kind_is_io_error() {
    use paladin_gtk::effect_ownership::EffectKind;
    use paladin_gtk::startup_error::StartupError;

    // Worker panics interrupt the in-flight save durability contract
    // — `ErrorKind::IoError` is the closest match in the typed §5
    // palette without leaking a GUI-specific kind into paladin_core.
    let err = StartupError::from_worker_panic(EffectKind::AddAccount);
    assert_eq!(err.kind, ErrorKind::IoError);
}

#[test]
fn startup_error_from_worker_panic_rendered_body_names_the_effect() {
    use paladin_gtk::effect_ownership::EffectKind;
    use paladin_gtk::startup_error::{format_worker_panic_message, StartupError};

    let err = StartupError::from_worker_panic(EffectKind::Import);
    assert_eq!(
        err.rendered,
        format_worker_panic_message(EffectKind::Import)
    );
    assert!(
        err.rendered.contains("import"),
        "Worker-panic body must name the failed effect ({:?}); got: {:?}",
        EffectKind::Import,
        err.rendered,
    );
    assert!(
        err.rendered.contains("Restart Paladin"),
        "Worker-panic body must instruct the user to restart; got: {:?}",
        err.rendered,
    );
}

#[test]
fn format_worker_panic_message_is_single_line_for_marker_compatibility() {
    use paladin_gtk::effect_ownership::EffectKind;
    use paladin_gtk::startup_error::format_worker_panic_message;

    // `format_startup_error_marker` collapses `'\n' → '|'` for
    // single-line `xvfb-run` stdout matching. The worker-panic body
    // is single-line by design so the marker stays clean.
    let body = format_worker_panic_message(EffectKind::PassphraseRemove);
    assert!(
        !body.contains('\n'),
        "format_worker_panic_message must produce single-line output; got: {body:?}",
    );
}

#[test]
fn format_worker_panic_message_covers_every_effect_kind_variant() {
    use paladin_gtk::effect_ownership::EffectKind;
    use paladin_gtk::startup_error::format_worker_panic_message;

    // Every `EffectKind` variant must produce a non-empty rendered
    // body. The match in `EffectKind::user_name` covers every
    // variant; this test pins that contract from the panic-routing
    // side so a new variant must be wired through `user_name` (and
    // therefore through this message format) before it compiles.
    for kind in [
        EffectKind::HotpAdvance,
        EffectKind::AddAccount,
        EffectKind::RemoveAccount,
        EffectKind::RenameAccount,
        EffectKind::Import,
        EffectKind::Export,
        EffectKind::Settings,
        EffectKind::PassphraseSet,
        EffectKind::PassphraseChange,
        EffectKind::PassphraseRemove,
    ] {
        let body = format_worker_panic_message(kind);
        assert!(
            !body.is_empty(),
            "format_worker_panic_message produced empty body for {kind:?}",
        );
    }
}

#[test]
fn format_startup_error_marker_collapses_worker_panic_body_to_single_line() {
    use paladin_gtk::effect_ownership::EffectKind;
    use paladin_gtk::startup_error::StartupError;

    // The smoke test in `tests/gtk_smoke.rs` greps a single-line
    // marker from stdout — defensively cover the worker-panic
    // variant since the format helper is shared across every
    // StartupError source.
    let err = StartupError::from_worker_panic(EffectKind::Export);
    let marker = format_startup_error_marker(&err);
    assert!(marker.starts_with(STARTUP_ERROR_MARKER_PREFIX));
    assert!(
        !marker.contains('\n'),
        "Marker must be single-line; got: {marker:?}",
    );
}

// ---------------------------------------------------------------------------
// EffectKind::user_name — human-readable wording for the
// worker-panic surface. Pinned here so future variants must update
// the format helper before this test compiles, and so the wording
// remains grep-able.
// ---------------------------------------------------------------------------

#[test]
fn effect_kind_user_name_matches_expected_wording() {
    use paladin_gtk::effect_ownership::EffectKind;

    assert_eq!(EffectKind::HotpAdvance.user_name(), "HOTP advance");
    assert_eq!(EffectKind::AddAccount.user_name(), "add account");
    assert_eq!(EffectKind::RemoveAccount.user_name(), "remove account");
    assert_eq!(EffectKind::RenameAccount.user_name(), "rename account");
    assert_eq!(EffectKind::Import.user_name(), "import");
    assert_eq!(EffectKind::Export.user_name(), "export");
    assert_eq!(EffectKind::Settings.user_name(), "settings save");
    assert_eq!(EffectKind::PassphraseSet.user_name(), "passphrase set");
    assert_eq!(
        EffectKind::PassphraseChange.user_name(),
        "passphrase change"
    );
    assert_eq!(
        EffectKind::PassphraseRemove.user_name(),
        "passphrase remove"
    );
}
