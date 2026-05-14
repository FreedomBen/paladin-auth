// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic `otpauth://`-paste tests for `paladin-gtk`.
//!
//! Tracks the §"Tests > Pure-logic unit tests >
//! `tests/otpauth_uri_paste_logic.rs`" checklist in
//! `IMPLEMENTATION_PLAN_04_GTK.md`:
//!
//! * Successful URI parse routes through
//!   [`paladin_core::parse_otpauth`] and shares the manual path's
//!   duplicate-detection logic (the validated account threads
//!   through the same [`crate::secret_fields::AddSecretState::pending`]
//!   slot used by the manual flow).
//! * Parse errors for malformed URIs, unsupported scheme,
//!   unsupported `type=`, and `validation_error` stay inline without
//!   mutating vault state.
//! * Inline error messages may name the failing field or reason but
//!   never echo the URI text.
//! * Duplicate "add anyway" consumes the pending
//!   [`paladin_core::ValidatedAccount`] on the duplicate-allowed
//!   path.
//! * URI entry buffer zeroizes on submit / cancel / dialog close and
//!   is never carried in `AppMsg` or `AppOutput`. The helper takes a
//!   borrowed `&str` so the caller's
//!   [`crate::secret_fields::SecretEntry`] retains ownership of the
//!   `Zeroizing<String>` and wipes it on drop; the helper's output
//!   types do not carry the URI bytes.
//!
//! The module under test (`paladin_gtk::otpauth_uri_paste`) is the
//! pure-logic state machine the GTK URI sub-path of
//! `AddAccountComponent` shadows. It owns no widgets; the widget
//! layer drives [`classify_uri_submit`] on the typed text and
//! [`classify_uri_add_error`] on the post-save worker outcome.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use paladin_core::{
    AccountKindSummary, Algorithm, ErrorKind, PaladinError, ValidatedAccount, ValidationWarning,
};

use paladin_gtk::otpauth_uri_paste::{
    classify_uri_add_error, classify_uri_submit, InlineError, InlineWarning, UriAddErrorOutcome,
    UriSubmitOutcome,
};
use paladin_gtk::secret_fields::AddSecretState;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// 20-byte Base32 secret used in `parse_otpauth`'s own tests; valid
/// length per §4.1, no padding required.
const SECRET_20_B32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// Distinctive label substring used by URI fixtures so a test can
/// assert that the [`InlineError`]'s rendered body does not echo the
/// URI text back. Picked deliberately so it does not collide with
/// any [`paladin_core::PaladinError`] Display string.
const URI_LABEL_MARKER: &str = "ZZ-uri-label-marker-ZZ";

/// Distinctive issuer substring with the same rationale as
/// [`URI_LABEL_MARKER`].
const URI_ISSUER_MARKER: &str = "QQ-uri-issuer-marker-QQ";

fn now_for_tests() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn save_not_committed_no_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    }
}

fn save_not_committed_with_backup() -> PaladinError {
    PaladinError::SaveNotCommitted {
        committed: true,
        backup_path: Some(PathBuf::from("/tmp/vault.bin.bak")),
    }
}

// ---------------------------------------------------------------------------
// classify_uri_submit — successful parse routes through `parse_otpauth`
// ---------------------------------------------------------------------------

#[test]
fn classify_uri_submit_valid_totp_uri_proceeds() {
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::Proceed(validated) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    // Shape parity with `parse_otpauth`: issuer is reconciled from
    // the label-path and the query string; label is the post-colon
    // account part.
    let account = &validated.account;
    assert_eq!(account.issuer(), Some("Acme"));
    assert_eq!(account.label(), "alice");
    assert_eq!(account.summary().kind, AccountKindSummary::Totp);
    assert_eq!(account.summary().algorithm, Algorithm::Sha1);
}

#[test]
fn classify_uri_submit_valid_hotp_uri_proceeds() {
    let uri = format!("otpauth://hotp/alice?secret={SECRET_20_B32}&counter=7");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::Proceed(validated) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    let summary = validated.account.summary();
    assert_eq!(summary.kind, AccountKindSummary::Hotp);
    assert_eq!(summary.counter, Some(7));
    assert_eq!(summary.period, None);
}

#[test]
fn classify_uri_submit_threads_secret_warning_through_validated_account() {
    // A short (< 80-bit) Base32 secret is decoded but produces a
    // `ShortSecret` warning. The pure-logic helper must surface the
    // warnings vector unchanged so the widget can render them inline
    // alongside the successful add — matching the manual path's
    // `validate_manual` warning surface.
    //
    // "JBSWY3DPEHPK3PXP" decodes to 10 bytes — at the §4.1 hard
    // minimum (`SECRET_MIN_BYTES`) but below the recommended
    // `SHORT_SECRET_THRESHOLD_BYTES` of 16 bytes, so validation
    // succeeds while producing a `ShortSecret` warning.
    let uri = "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP";
    let outcome = classify_uri_submit(uri, now_for_tests());
    let UriSubmitOutcome::Proceed(validated) = outcome else {
        panic!("expected Proceed, got {outcome:?}");
    };
    assert!(
        validated
            .warnings
            .iter()
            .any(|w| matches!(w, ValidationWarning::ShortSecret { .. })),
        "expected ShortSecret warning, got {:?}",
        validated.warnings
    );
}

// ---------------------------------------------------------------------------
// classify_uri_submit — successful parse threads through duplicate-detection
// ---------------------------------------------------------------------------

#[test]
fn proceed_validated_account_threads_through_add_secret_state_pending() {
    // The URI-paste helper shares the manual path's duplicate-
    // detection logic by handing its `ValidatedAccount` to the same
    // `AddSecretState::pending` slot the manual path uses. The
    // widget stages the pending account on a `find_duplicate`
    // collision and consumes it on the "add anyway" confirmation.
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::Proceed(validated) = outcome else {
        panic!("expected Proceed");
    };
    let pending_id = validated.account.id();

    let mut state = AddSecretState::new();
    let prior = state.replace_pending(validated);
    assert!(prior.is_none(), "no prior pending expected");

    // ---- Duplicate "add anyway" consumes the pending ValidatedAccount.
    let consumed = state.consume_pending().expect("pending was staged");
    assert_eq!(
        consumed.account.id(),
        pending_id,
        "consume_pending must return the URI-derived ValidatedAccount unchanged"
    );
    // After consume, the slot is empty so a follow-up consume yields None.
    assert!(state.consume_pending().is_none());
}

// ---------------------------------------------------------------------------
// classify_uri_submit — parse errors stay inline
// ---------------------------------------------------------------------------

#[test]
fn classify_uri_submit_malformed_uri_rejects_inline() {
    // Has the `otpauth:` scheme but the URL parser cannot build the
    // structured form (unterminated IPv6 literal). parse_otpauth
    // maps this to validation_error { field: "uri", reason: "malformed" }.
    let outcome = classify_uri_submit("otpauth://[unterminated", now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("uri"));
    assert!(inline.rendered.contains("malformed"));
}

#[test]
fn classify_uri_submit_unsupported_scheme_rejects_inline() {
    // `mailto:`, `https://`, `paladin://` and friends are not
    // accepted — parse_otpauth's scheme guard rejects them before
    // the URL parse so the user gets the §5 typed
    // validation_error { field: "uri", reason: "invalid_scheme" }
    // wire code rather than an opaque url-crate error.
    let outcome = classify_uri_submit(
        "https://example.com/totp/alice?secret=ABCD",
        now_for_tests(),
    );
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("invalid_scheme"));
}

#[test]
fn classify_uri_submit_missing_scheme_rejects_inline() {
    let outcome = classify_uri_submit("totp/alice?secret=ABCD", now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("missing_scheme"));
}

#[test]
fn classify_uri_submit_unsupported_type_rejects_inline() {
    // Host other than `totp` / `hotp` (case-insensitive). parse_otpauth
    // surfaces this as validation_error { field: "type", reason: "invalid" }.
    let uri = format!("otpauth://foo/alice?secret={SECRET_20_B32}");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("type"));
    assert!(inline.rendered.contains("invalid"));
}

#[test]
fn classify_uri_submit_validation_error_missing_secret_rejects_inline() {
    // `secret=` query parameter missing. parse_otpauth surfaces this
    // as validation_error { field: "secret", reason: "missing" }.
    let outcome = classify_uri_submit("otpauth://totp/alice", now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("secret"));
    assert!(inline.rendered.contains("missing"));
}

#[test]
fn classify_uri_submit_validation_error_empty_label_rejects_inline() {
    // Path component is empty after percent-decode. parse_otpauth
    // surfaces this as validation_error { field: "label", reason: "empty" }.
    let uri = format!("otpauth://totp/?secret={SECRET_20_B32}");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
    assert!(inline.rendered.contains("label"));
    assert!(inline.rendered.contains("empty"));
}

// ---------------------------------------------------------------------------
// classify_uri_submit — Inline error never echoes the URI text
// ---------------------------------------------------------------------------

#[test]
fn inline_error_does_not_echo_uri_label_or_issuer() {
    // Build a URI that fails validation late enough that label and
    // issuer have been seen by the parser, then assert the rendered
    // error body does not contain either substring. §5 wire codes
    // alone identify the failure to the user; URI text (which embeds
    // the user's Base32 secret) must never appear in the inline body
    // because the inline body crosses into `AppMsg` / `AppOutput`
    // for logging / telemetry.
    let uri = format!("otpauth://totp/{URI_ISSUER_MARKER}:{URI_LABEL_MARKER}?secret=NOT_BASE32!");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert!(
        !inline.rendered.contains(URI_LABEL_MARKER),
        "inline body must not echo URI label text, got {:?}",
        inline.rendered
    );
    assert!(
        !inline.rendered.contains(URI_ISSUER_MARKER),
        "inline body must not echo URI issuer text, got {:?}",
        inline.rendered
    );
}

#[test]
fn inline_error_does_not_echo_uri_secret_text() {
    // A bad Base32 secret triggers a validation_error on the secret
    // field. The rendered body must not contain the bogus secret
    // bytes — those would otherwise reach logs and the
    // `paladin_core::PaladinError` JSON serialization layer.
    let bogus_secret = "ABCDEFG-ZZZ-not-base32-XYZ";
    let uri = format!("otpauth://totp/alice?secret={bogus_secret}");
    let outcome = classify_uri_submit(&uri, now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert!(
        !inline.rendered.contains(bogus_secret),
        "inline body must not echo URI secret text, got {:?}",
        inline.rendered
    );
}

#[test]
fn inline_error_does_not_echo_full_uri_text() {
    // Even on a scheme failure, the rendered body must not include
    // the raw URI string. Otherwise the failing `https://` URI from
    // a paste — which a user might assume is harmless — leaks into
    // log surfaces along with any embedded query parameters.
    let uri = "https://example.com/totp/alice?secret=ABCD";
    let outcome = classify_uri_submit(uri, now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError, got {outcome:?}");
    };
    assert!(
        !inline.rendered.contains(uri),
        "inline body must not echo full URI, got {:?}",
        inline.rendered
    );
}

// ---------------------------------------------------------------------------
// classify_uri_add_error — post-save routing
// ---------------------------------------------------------------------------

#[test]
fn classify_uri_add_error_save_not_committed_restores_prior_inline() {
    // `save_not_committed` after `Vault::mutate_and_save` left the
    // in-memory vault unchanged — the dialog stays open with the
    // inline rejection so the user can retry without losing the
    // typed URI buffer.
    let err = save_not_committed_no_backup();
    let outcome = classify_uri_add_error(&err);
    let UriAddErrorOutcome::Inline(inline) = outcome else {
        panic!("expected Inline, got {outcome:?}");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

#[test]
fn classify_uri_add_error_save_not_committed_with_backup_restores_prior_inline() {
    // The `committed` / `backup_path` discriminator inside
    // `save_not_committed` does not change the routing decision —
    // both arms keep the dialog open with the inline error.
    let err = save_not_committed_with_backup();
    let outcome = classify_uri_add_error(&err);
    let UriAddErrorOutcome::Inline(inline) = outcome else {
        panic!("expected Inline");
    };
    assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
}

#[test]
fn classify_uri_add_error_save_durability_unconfirmed_keeps_success_with_warning() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let outcome = classify_uri_add_error(&err);
    let UriAddErrorOutcome::KeepWithWarning(warning) = outcome else {
        panic!("expected KeepWithWarning, got {outcome:?}");
    };
    assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
    assert!(!warning.rendered.is_empty());
}

#[test]
fn classify_uri_add_error_validation_error_stays_inline() {
    // Defensive: `Vault::add` does not re-validate, so this only
    // fires if a downstream stage adds new rejections. The dialog
    // must still show it inline rather than rolling out.
    let err = PaladinError::ValidationError {
        field: "label",
        reason: "too_long".into(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let outcome = classify_uri_add_error(&err);
    let UriAddErrorOutcome::Inline(inline) = outcome else {
        panic!("expected Inline");
    };
    assert_eq!(inline.kind, ErrorKind::ValidationError);
}

#[test]
fn classify_uri_add_error_io_error_stays_inline() {
    // Generic IO failures during save fall through to the same
    // inline rejection surface as save_not_committed; the dialog
    // stays open and the worker outcome is shown verbatim.
    let err = PaladinError::IoError {
        operation: "write_vault",
        source: std::io::Error::other("disk full"),
    };
    let outcome = classify_uri_add_error(&err);
    let UriAddErrorOutcome::Inline(inline) = outcome else {
        panic!("expected Inline");
    };
    assert_eq!(inline.kind, ErrorKind::IoError);
}

// ---------------------------------------------------------------------------
// URI entry buffer zeroizes — type / shape contracts
// ---------------------------------------------------------------------------

#[test]
fn classify_uri_submit_signature_takes_borrowed_str_so_caller_retains_buffer() {
    // The helper borrows the URI text — it never takes ownership and
    // therefore cannot extend the lifetime of the buffer past the
    // caller's `SecretEntry::take` / `Zeroizing<String>` scope.
    // Assigning the function pointer to a typed `fn(&str, …)` makes
    // that signature explicit at compile time; switching to an owned
    // `String` parameter would break the type-check below.
    const _SUBMIT_API: fn(&str, SystemTime) -> UriSubmitOutcome = classify_uri_submit;
}

#[test]
fn uri_submit_outcome_carries_only_validated_account_or_inline_error() {
    // Exhaustively destructure the outcome to prove no third arm
    // exists that could carry the raw URI bytes. The
    // `UriSubmitOutcome::Proceed` arm holds only a `ValidatedAccount`
    // (which itself never stores the URI text), and the
    // `InlineError` carries the typed §5 discriminator plus a
    // pre-rendered body produced by `PaladinError::Display`. Neither
    // shape can be threaded into `AppMsg` / `AppOutput` as a URI
    // echo.
    fn assert_carries_only_validated_account_or_inline_error(o: UriSubmitOutcome) {
        match o {
            UriSubmitOutcome::Proceed(v) => {
                let bound: ValidatedAccount = v;
                let _ = bound;
            }
            UriSubmitOutcome::InlineError(inline) => {
                let kind: ErrorKind = inline.kind;
                let rendered: String = inline.rendered;
                let _ = kind;
                let _ = rendered;
            }
        }
    }
    let uri = format!("otpauth://totp/alice?secret={SECRET_20_B32}");
    assert_carries_only_validated_account_or_inline_error(classify_uri_submit(
        &uri,
        now_for_tests(),
    ));
}

#[test]
fn inline_error_clones_freely_for_reactive_state() {
    // The dialog stores the inline error in its reactive state and
    // re-uses it across re-renders; the type must implement `Clone`
    // without dropping any fields.
    let outcome = classify_uri_submit("otpauth://", now_for_tests());
    let UriSubmitOutcome::InlineError(inline) = outcome else {
        panic!("expected InlineError");
    };
    let cloned: InlineError = inline.clone();
    assert_eq!(cloned.kind, inline.kind);
    assert_eq!(cloned.rendered, inline.rendered);
}

#[test]
fn inline_warning_clones_freely_for_reactive_state() {
    let warning = InlineWarning::from_error(&PaladinError::SaveDurabilityUnconfirmed);
    let cloned: InlineWarning = warning.clone();
    assert_eq!(cloned.kind, warning.kind);
    assert_eq!(cloned.rendered, warning.rendered);
}
