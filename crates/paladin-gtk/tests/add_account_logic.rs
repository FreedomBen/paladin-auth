// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic Add Account manual-path tests for `paladin-gtk`.
//!
//! Tracks the §"Component tree" > `AddAccountComponent` rules in
//! `IMPLEMENTATION_PLAN_04_GTK.md` for the *manual* input sub-path:
//!
//! * Empty issuer maps to `None`; non-empty issuer threads through.
//! * Period / counter are kind-conditional (TOTP carries period, HOTP
//!   carries counter) so `validate_manual`'s kind cross-checks never
//!   fire for well-formed widget input.
//! * Icon-hint widget mode is normalized through
//!   [`paladin_core::parse_icon_hint_token`] so `""`,
//!   `"none"` (any case), and explicit slugs match the CLI / TUI add
//!   modals exactly. Malformed slugs reject inline without mutating
//!   the vault.
//! * `validate_manual` warnings (e.g. [`ValidationWarning::ShortSecret`])
//!   thread through on the `Proceed` arm so the dialog can render them
//!   alongside the success outcome via
//!   [`paladin_core::format_validation_warning`].
//! * Field-level parse errors (invalid Base32, empty label, out-of-range
//!   digits / period, malformed icon-hint slug) plus any core-returned
//!   `validation_error` reject inline without mutating the vault.
//! * Duplicate detection routes `None` existing → `Proceed`,
//!   `Some(summary)` → `AwaitConfirmation` carrying the existing
//!   summary plus the pending [`ValidatedAccount`]. The pending value
//!   is staged in [`crate::secret_fields::AddSecretState::pending`]
//!   for the "add anyway" confirmation round trip.
//! * Post-effect routing on `Vault::mutate_and_save` failures matches
//!   the URI sub-path: `save_durability_unconfirmed` →
//!   `KeepWithWarning`; everything else (`save_not_committed`,
//!   `io_error`, `validation_error`, …) → `Inline`.
//!
//! The module under test (`paladin_gtk::add_account`) is the
//! pure-logic state machine the manual sub-path of
//! `AddAccountComponent` shadows. It owns no widgets; the widget
//! layer drives [`classify_manual_submit`] on the typed buffers and
//! [`classify_duplicate`] on the [`paladin_core::Vault::find_duplicate`]
//! result, then [`classify_add_post_effect_error`] on the post-save
//! worker outcome.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use paladin_core::{
    AccountId, AccountKindInput, AccountKindSummary, AccountSummary, Algorithm, ErrorKind,
    PaladinError, Store, ValidationWarning, Vault, VaultInit, VaultLock,
};
use secrecy::SecretString;

fn validation_error(field: &'static str, reason: &str) -> PaladinError {
    PaladinError::ValidationError {
        field,
        reason: reason.to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    }
}

use paladin_gtk::add_account::{
    classify_add_post_effect_error, classify_duplicate, classify_manual_submit, run_add_worker,
    AddPostEffectOutcome, AddWorkerCompletion, AddWorkerEffect, AddWorkerInput, DuplicateOutcome,
    InlineError, InlineWarning, ManualFields, ManualSubmitOutcome,
};
use paladin_gtk::secret_fields::AddSecretState;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// 32-character Base32 = 20-byte secret. Above the §4.1
/// `SHORT_SECRET_THRESHOLD_BYTES` (16) ceiling so no short-secret
/// warning fires.
const SECRET_20_B32: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// 16-character Base32 = 10-byte secret. Below the §4.1 threshold so
/// `validate_manual` emits a [`ValidationWarning::ShortSecret`] on
/// the `Proceed` arm.
const SHORT_SECRET_B32: &str = "JBSWY3DPEHPK3PXP";

/// Distinctive label substring used by manual fixtures so the
/// [`InlineError`]-leak tests can assert that the rendered body does
/// not echo widget input. Picked deliberately so it does not collide
/// with any [`PaladinError`] Display string.
const MANUAL_LABEL_MARKER: &str = "ZZ-manual-label-marker-ZZ";

/// Distinctive issuer substring with the same rationale.
const MANUAL_ISSUER_MARKER: &str = "QQ-manual-issuer-marker-QQ";

fn now_for_tests() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn manual_totp_defaults() -> ManualFields {
    ManualFields {
        label: "alice".to_string(),
        issuer: "Acme".to_string(),
        secret: SecretString::from(SECRET_20_B32.to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: 30,
        counter: 0,
        icon_hint_text: String::new(),
    }
}

fn manual_hotp_defaults() -> ManualFields {
    ManualFields {
        label: "alice".to_string(),
        issuer: "Acme".to_string(),
        secret: SecretString::from(SECRET_20_B32.to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Hotp,
        period_secs: 30,
        counter: 7,
        icon_hint_text: String::new(),
    }
}

fn dummy_existing_summary() -> AccountSummary {
    AccountSummary {
        id: AccountId::new(),
        issuer: Some("Acme".to_string()),
        label: "alice".to_string(),
        kind: AccountKindSummary::Totp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: Some(30),
        counter: None,
        icon_hint: None,
        created_at: 1,
        updated_at: 1,
    }
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
// classify_manual_submit — successful manual TOTP / HOTP
// ---------------------------------------------------------------------------

#[test]
fn classify_manual_submit_totp_defaults_proceeds() {
    let outcome = classify_manual_submit(manual_totp_defaults(), now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(validated) => {
            let summary = validated.account.summary();
            assert_eq!(summary.label, "alice");
            assert_eq!(summary.issuer.as_deref(), Some("Acme"));
            assert_eq!(summary.digits, 6);
            assert_eq!(summary.kind, AccountKindSummary::Totp);
            assert!(validated.warnings.is_empty());
        }
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed, got InlineError({err:?})")
        }
    }
}

#[test]
fn classify_manual_submit_hotp_with_counter_proceeds() {
    let outcome = classify_manual_submit(manual_hotp_defaults(), now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(validated) => {
            let summary = validated.account.summary();
            assert_eq!(summary.kind, AccountKindSummary::Hotp);
            assert_eq!(summary.counter, Some(7));
            assert_eq!(summary.period, None);
        }
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed, got InlineError({err:?})")
        }
    }
}

#[test]
fn classify_manual_submit_empty_issuer_maps_to_none() {
    let mut fields = manual_totp_defaults();
    fields.issuer = String::new();
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(validated) => {
            let summary = validated.account.summary();
            assert!(
                summary.issuer.is_none(),
                "expected None issuer, got {:?}",
                summary.issuer,
            );
        }
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed, got InlineError({err:?})")
        }
    }
}

#[test]
fn classify_manual_submit_period_secs_ignored_on_hotp_kind() {
    // Widget defaults seed period_secs even when the user picked
    // HOTP; the wrapper must drop it so `validate_manual`'s
    // `rejected_on_hotp` cross-check never fires.
    let mut fields = manual_hotp_defaults();
    fields.period_secs = 60;
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(_) => {}
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed (period should be dropped on HOTP), got {err:?}")
        }
    }
}

#[test]
fn classify_manual_submit_counter_ignored_on_totp_kind() {
    // Symmetric: counter defaults seed even when the user picked
    // TOTP; the wrapper must drop it.
    let mut fields = manual_totp_defaults();
    fields.counter = 42;
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(_) => {}
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed (counter should be dropped on TOTP), got {err:?}")
        }
    }
}

// ---------------------------------------------------------------------------
// classify_manual_submit — icon-hint normalization
// ---------------------------------------------------------------------------

#[test]
fn classify_manual_submit_empty_icon_hint_defaults_from_issuer() {
    let outcome = classify_manual_submit(manual_totp_defaults(), now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(validated) => {
            // Issuer is "Acme" so the default-from-issuer slug
            // resolves through `slug::derive_default_from_issuer`.
            assert_eq!(validated.account.icon_hint(), Some("acme"));
        }
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed, got InlineError({err:?})")
        }
    }
}

#[test]
fn classify_manual_submit_none_token_clears_icon_hint() {
    for token in ["none", "NONE", "None", "  none  "] {
        let mut fields = manual_totp_defaults();
        fields.icon_hint_text = token.to_string();
        let outcome = classify_manual_submit(fields, now_for_tests());
        match outcome {
            ManualSubmitOutcome::Proceed(validated) => {
                assert!(
                    validated.account.icon_hint().is_none(),
                    "token {token:?} should clear icon_hint, got {:?}",
                    validated.account.icon_hint(),
                );
            }
            ManualSubmitOutcome::InlineError(err) => {
                panic!("expected Proceed for token {token:?}, got InlineError({err:?})")
            }
        }
    }
}

#[test]
fn classify_manual_submit_explicit_slug_stored_verbatim() {
    let mut fields = manual_totp_defaults();
    fields.icon_hint_text = "github".to_string();
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(validated) => {
            assert_eq!(validated.account.icon_hint(), Some("github"));
        }
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed, got InlineError({err:?})")
        }
    }
}

#[test]
fn classify_manual_submit_malformed_slug_rejects_inline() {
    // Uppercase ASCII is rejected by the §4.1 slug grammar
    // (lowercase ASCII + digits + `-` only).
    let mut fields = manual_totp_defaults();
    fields.icon_hint_text = "GITHUB".to_string();
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::InlineError(err) => {
            assert_eq!(err.kind, ErrorKind::ValidationError);
        }
        ManualSubmitOutcome::Proceed(_) => {
            panic!("expected InlineError for malformed icon-hint slug")
        }
    }
}

// ---------------------------------------------------------------------------
// classify_manual_submit — `validate_manual` warnings thread through
// ---------------------------------------------------------------------------

#[test]
fn classify_manual_submit_threads_short_secret_warning_through_validated_account() {
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from(SHORT_SECRET_B32.to_string());
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::Proceed(validated) => {
            assert!(
                validated
                    .warnings
                    .iter()
                    .any(|w| matches!(w, ValidationWarning::ShortSecret { .. })),
                "expected ShortSecret warning, got {:?}",
                validated.warnings,
            );
        }
        ManualSubmitOutcome::InlineError(err) => {
            panic!("expected Proceed with warning, got InlineError({err:?})")
        }
    }
}

// ---------------------------------------------------------------------------
// classify_manual_submit — field-level parse errors stay inline
// ---------------------------------------------------------------------------

#[test]
fn classify_manual_submit_invalid_base32_secret_rejects_inline() {
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from("not-base32!!".to_string());
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::InlineError(err) => {
            assert_eq!(err.kind, ErrorKind::ValidationError);
        }
        ManualSubmitOutcome::Proceed(_) => {
            panic!("expected InlineError for invalid Base32 secret")
        }
    }
}

#[test]
fn classify_manual_submit_empty_secret_rejects_inline() {
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from(String::new());
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::InlineError(err) => {
            assert_eq!(err.kind, ErrorKind::ValidationError);
        }
        ManualSubmitOutcome::Proceed(_) => panic!("expected InlineError for empty secret"),
    }
}

#[test]
fn classify_manual_submit_empty_label_rejects_inline() {
    let mut fields = manual_totp_defaults();
    fields.label = String::new();
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::InlineError(err) => {
            assert_eq!(err.kind, ErrorKind::ValidationError);
        }
        ManualSubmitOutcome::Proceed(_) => panic!("expected InlineError for empty label"),
    }
}

#[test]
fn classify_manual_submit_out_of_range_digits_rejects_inline() {
    let mut fields = manual_totp_defaults();
    fields.digits = 5; // valid range is 6..=8
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::InlineError(err) => {
            assert_eq!(err.kind, ErrorKind::ValidationError);
        }
        ManualSubmitOutcome::Proceed(_) => panic!("expected InlineError for digits=5"),
    }
}

#[test]
fn classify_manual_submit_out_of_range_period_on_totp_rejects_inline() {
    let mut fields = manual_totp_defaults();
    fields.period_secs = 0; // valid range is 1..=300
    let outcome = classify_manual_submit(fields, now_for_tests());
    match outcome {
        ManualSubmitOutcome::InlineError(err) => {
            assert_eq!(err.kind, ErrorKind::ValidationError);
        }
        ManualSubmitOutcome::Proceed(_) => panic!("expected InlineError for period=0"),
    }
}

// ---------------------------------------------------------------------------
// classify_manual_submit — InlineError body invariants
// ---------------------------------------------------------------------------

#[test]
fn inline_error_does_not_echo_label_or_issuer_markers() {
    let mut fields = manual_totp_defaults();
    fields.label = format!("{MANUAL_LABEL_MARKER}-but-also-empty");
    fields.issuer = MANUAL_ISSUER_MARKER.to_string();
    // Force an unrelated rejection (out-of-range digits) so the
    // failing-field codes do not name `label` or `issuer`. The
    // rendered body must still avoid echoing widget input.
    fields.digits = 5;
    let outcome = classify_manual_submit(fields, now_for_tests());
    let ManualSubmitOutcome::InlineError(err) = outcome else {
        panic!("expected InlineError")
    };
    assert!(
        !err.rendered.contains(MANUAL_LABEL_MARKER),
        "rendered body leaked label marker: {}",
        err.rendered,
    );
    assert!(
        !err.rendered.contains(MANUAL_ISSUER_MARKER),
        "rendered body leaked issuer marker: {}",
        err.rendered,
    );
}

#[test]
fn inline_error_does_not_echo_manual_secret_text() {
    let secret_marker = "WW-secret-marker-WW";
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from(secret_marker.to_string());
    let outcome = classify_manual_submit(fields, now_for_tests());
    let ManualSubmitOutcome::InlineError(err) = outcome else {
        panic!("expected InlineError")
    };
    assert!(
        !err.rendered.contains(secret_marker),
        "rendered body leaked secret marker: {}",
        err.rendered,
    );
}

// ---------------------------------------------------------------------------
// classify_duplicate — None passes through; Some(existing) parks for confirm
// ---------------------------------------------------------------------------

#[test]
fn classify_duplicate_none_proceeds() {
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let outcome = classify_duplicate(validated, None);
    match outcome {
        DuplicateOutcome::Proceed(_) => {}
        DuplicateOutcome::AwaitConfirmation { .. } => {
            panic!("expected Proceed when no duplicate exists")
        }
    }
}

#[test]
fn classify_duplicate_some_parks_for_confirmation() {
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let existing = dummy_existing_summary();
    let existing_id = existing.id;
    let outcome = classify_duplicate(validated, Some(existing));
    match outcome {
        DuplicateOutcome::AwaitConfirmation {
            existing,
            validated,
        } => {
            assert_eq!(existing.id, existing_id);
            assert_eq!(validated.account.label(), "alice");
        }
        DuplicateOutcome::Proceed(_) => {
            panic!("expected AwaitConfirmation when duplicate exists")
        }
    }
}

#[test]
fn await_confirmation_threads_validated_through_add_secret_state_pending() {
    // The widget stages the validated account in
    // `AddSecretState::pending` after the duplicate-collision branch
    // rejects; the "add anyway" confirmation consumes it via
    // `consume_pending`. The pure-logic flow here just hands the
    // validated account back to the widget; this test wires that hand-off
    // through the real pending slot so accidental shape changes that
    // break the slot bytecode show up in CI.
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let existing = dummy_existing_summary();
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(existing))
    else {
        panic!("expected AwaitConfirmation")
    };

    let mut state = AddSecretState::new();
    let prior = state.replace_pending(validated);
    assert!(prior.is_none());
    assert!(state.pending.is_some());

    // Consume should hand the validated account back and wipe buffers.
    let consumed = state.consume_pending();
    assert!(
        consumed.is_some(),
        "consume_pending should return the staged validated account"
    );
    assert!(state.pending.is_none());
}

// ---------------------------------------------------------------------------
// classify_add_post_effect_error — durability vs. inline routing
// ---------------------------------------------------------------------------

#[test]
fn classify_add_post_effect_error_save_durability_unconfirmed_keeps_success_with_warning() {
    let err = PaladinError::SaveDurabilityUnconfirmed;
    match classify_add_post_effect_error(&err) {
        AddPostEffectOutcome::KeepWithWarning(warning) => {
            assert_eq!(warning.kind, ErrorKind::SaveDurabilityUnconfirmed);
            assert!(!warning.rendered.is_empty());
        }
        AddPostEffectOutcome::Inline(inline) => {
            panic!("expected KeepWithWarning, got Inline({inline:?})")
        }
    }
}

#[test]
fn classify_add_post_effect_error_save_not_committed_no_backup_stays_inline() {
    let err = save_not_committed_no_backup();
    match classify_add_post_effect_error(&err) {
        AddPostEffectOutcome::Inline(inline) => {
            assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
        }
        AddPostEffectOutcome::KeepWithWarning(w) => {
            panic!("expected Inline, got KeepWithWarning({w:?})")
        }
    }
}

#[test]
fn classify_add_post_effect_error_save_not_committed_with_backup_stays_inline() {
    let err = save_not_committed_with_backup();
    match classify_add_post_effect_error(&err) {
        AddPostEffectOutcome::Inline(inline) => {
            assert_eq!(inline.kind, ErrorKind::SaveNotCommitted);
        }
        AddPostEffectOutcome::KeepWithWarning(w) => {
            panic!("expected Inline, got KeepWithWarning({w:?})")
        }
    }
}

#[test]
fn classify_add_post_effect_error_io_error_stays_inline() {
    let err = PaladinError::IoError {
        operation: "save",
        source: std::io::ErrorKind::PermissionDenied.into(),
    };
    match classify_add_post_effect_error(&err) {
        AddPostEffectOutcome::Inline(inline) => {
            assert_eq!(inline.kind, ErrorKind::IoError);
        }
        AddPostEffectOutcome::KeepWithWarning(w) => {
            panic!("expected Inline, got KeepWithWarning({w:?})")
        }
    }
}

#[test]
fn classify_add_post_effect_error_validation_error_stays_inline() {
    let err = validation_error("label", "empty");
    match classify_add_post_effect_error(&err) {
        AddPostEffectOutcome::Inline(inline) => {
            assert_eq!(inline.kind, ErrorKind::ValidationError);
        }
        AddPostEffectOutcome::KeepWithWarning(w) => {
            panic!("expected Inline, got KeepWithWarning({w:?})")
        }
    }
}

// ---------------------------------------------------------------------------
// Shape invariants
// ---------------------------------------------------------------------------

#[test]
fn manual_submit_outcome_carries_only_validated_account_or_inline_error() {
    // Documented invariant: `Proceed` carries a `ValidatedAccount`
    // (whose `Account` and `warnings` are the only post-validate
    // shape the widget needs) and `InlineError` carries the typed
    // discriminator + rendered body. No widget-shaped extra payload.
    fn assert_carries_only_validated_account_or_inline_error(o: ManualSubmitOutcome) {
        match o {
            ManualSubmitOutcome::Proceed(_validated) => {}
            ManualSubmitOutcome::InlineError(_inline) => {}
        }
    }
    assert_carries_only_validated_account_or_inline_error(classify_manual_submit(
        manual_totp_defaults(),
        now_for_tests(),
    ));
}

#[test]
fn inline_error_clones_freely_for_reactive_state() {
    let mut fields = manual_totp_defaults();
    fields.label = String::new();
    let ManualSubmitOutcome::InlineError(inline) = classify_manual_submit(fields, now_for_tests())
    else {
        panic!("expected InlineError")
    };
    let cloned: InlineError = inline.clone();
    assert_eq!(cloned.kind, inline.kind);
    assert_eq!(cloned.rendered, inline.rendered);
}

#[test]
fn inline_warning_clones_freely_for_reactive_state() {
    let AddPostEffectOutcome::KeepWithWarning(warning) =
        classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed)
    else {
        panic!("expected KeepWithWarning")
    };
    let cloned: InlineWarning = warning.clone();
    assert_eq!(cloned.kind, warning.kind);
    assert_eq!(cloned.rendered, warning.rendered);
}

// ---------------------------------------------------------------------------
// run_add_worker — `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(...))`
//
// The worker is the synchronous body of the add-account worker fired
// by `AppModel::update` from
// `AppMsg::AddAccountAction(AddAccountOutput::Submit{Manual,Uri})`.
// It consumes the live `(Vault, Store)` pair by value so the busy
// gate can reinstall whichever pair the worker returns — success,
// `save_durability_unconfirmed`, or pre-commit rollback. Extracting
// the worker body as a pure function lets `AppModel::update`'s
// closure stay a thin `gio::spawn_blocking(move || run_add_worker(
// input))` while the real `mutate_and_save` call stays unit-testable
// here against tempfile-backed plaintext vaults — no GTK /
// libadwaita main loop required.
// ---------------------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir for add-worker fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) =
        Store::create(path, VaultInit::Plaintext).expect("create plaintext vault on disk");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext vault")
}

fn validate_manual_totp(label: &str, issuer: Option<&str>) -> paladin_core::ValidatedAccount {
    let mut fields = manual_totp_defaults();
    fields.label = label.to_string();
    fields.issuer = issuer.unwrap_or_default().to_string();
    match classify_manual_submit(fields, now_for_tests()) {
        ManualSubmitOutcome::Proceed(validated) => validated,
        ManualSubmitOutcome::InlineError(inline) => {
            panic!("manual TOTP fixture must validate, got InlineError {inline:?}")
        }
    }
}

#[test]
fn run_add_worker_plaintext_add_succeeds_and_returns_live_pair_with_account_id() {
    // Happy path: insert a fresh TOTP account on a plaintext vault and
    // verify the worker reports Success carrying the inserted
    // `AccountId`, the new account is in the returned vault, and the
    // `(Vault, Store)` pair survives the worker so `AppModel::update`
    // can reinstall it.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let validated = validate_manual_totp("alice", Some("Acme"));
    let expected_id = validated.account.id();

    let completion = run_add_worker(AddWorkerInput {
        vault,
        store,
        account: validated.account,
    });

    let AddWorkerCompletion {
        effect,
        vault,
        store: _,
    } = completion;
    match effect {
        AddWorkerEffect::Success { account_id } => {
            assert_eq!(
                account_id, expected_id,
                "Success must surface the AccountId stamped on the Account before insertion",
            );
        }
        other @ AddWorkerEffect::Failure(_) => {
            panic!("plaintext add must surface AddWorkerEffect::Success, got {other:?}")
        }
    }
    let summary = vault
        .summaries()
        .find(|s| s.id == expected_id)
        .expect("added account is visible in the returned vault");
    assert_eq!(summary.label, "alice");
    assert_eq!(summary.issuer.as_deref(), Some("Acme"));
}

#[test]
fn run_add_worker_persists_added_account_to_disk() {
    // The worker must not just mutate the in-memory vault — it goes
    // through `mutate_and_save` so the new account survives a reopen.
    // This pins the round trip through the §4.3 atomic-write pipeline
    // without exercising the GTK loop.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let validated = validate_manual_totp("bob", None);
    let expected_id = validated.account.id();

    let completion = run_add_worker(AddWorkerInput {
        vault,
        store,
        account: validated.account,
    });
    assert!(matches!(completion.effect, AddWorkerEffect::Success { .. }));
    drop(completion);

    let (reopened, _store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let summary = reopened
        .summaries()
        .find(|s| s.id == expected_id)
        .expect("added account survives reopen");
    assert_eq!(summary.label, "bob");
    assert!(summary.issuer.is_none());
}

#[test]
fn run_add_worker_appends_after_existing_accounts() {
    // Insertion order matters for §5 row ordering. The worker must
    // append the new account after existing ones (`Vault::add` pushes
    // onto the back) so the returned vault preserves insertion order
    // for the visible row list.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let first = validate_manual_totp("alice", Some("Acme"));
    let first_id = first.account.id();
    vault.add(first.account);
    vault.save(&store).expect("commit pre-existing account");

    let second = validate_manual_totp("bob", None);
    let second_id = second.account.id();
    let completion = run_add_worker(AddWorkerInput {
        vault,
        store,
        account: second.account,
    });

    assert!(matches!(
        completion.effect,
        AddWorkerEffect::Success { account_id } if account_id == second_id,
    ));
    let ids: Vec<AccountId> = completion.vault.summaries().map(|s| s.id).collect();
    assert_eq!(
        ids,
        vec![first_id, second_id],
        "Vault::add must append; the second account follows the first",
    );
}

#[cfg(unix)]
#[test]
fn run_add_worker_save_failure_routes_inline_and_returns_pair() {
    // Defensive: when `Vault::mutate_and_save` returns a typed save
    // failure that is not `save_durability_unconfirmed`, the worker
    // routes through `classify_add_post_effect_error` to
    // `AddPostEffectOutcome::Inline` and still returns the live
    // `(Vault, Store)` pair so `AppModel::update` can reinstall it
    // before applying the inline error.
    //
    // We force the failure by removing the parent dir between
    // `Store::open` and the worker call — `Vault::save`'s atomic
    // tempfile write then surfaces an `io_error`, which
    // `mutate_and_save` rolls back snapshot-style and the worker
    // routes inline. Unix-gated because the tempdir uses Unix
    // permissions and the failure mode depends on POSIX semantics.
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, store) = open_plaintext_pair(&path);
    let validated = validate_manual_totp("alice", Some("Acme"));

    // Drop the tempdir to delete the parent directory; the next save
    // attempt fails because the atomic tempfile cannot be created.
    drop(dir);

    let completion = run_add_worker(AddWorkerInput {
        vault,
        store,
        account: validated.account,
    });

    match completion.effect {
        AddWorkerEffect::Failure(AddPostEffectOutcome::Inline(inline)) => {
            // The exact ErrorKind depends on what `Vault::save` raises
            // when the parent dir vanishes (`SaveNotCommitted` or
            // `IoError` depending on which atomic-write step fails),
            // but the routing must stay on the `Inline` arm — never
            // on `KeepWithWarning`, which is reserved for
            // `save_durability_unconfirmed`.
            assert_ne!(
                inline.kind,
                ErrorKind::SaveDurabilityUnconfirmed,
                "missing-parent save failure must not route to KeepWithWarning",
            );
        }
        other => panic!("expected Failure(Inline) when save fails, got {other:?}"),
    }
    // The live (Vault, Store) pair returns regardless of the typed
    // failure so the busy gate can reinstall it. The exact in-memory
    // vault state after rollback depends on which `Vault::save` step
    // failed (snapshot-restored for `save_not_committed`,
    // post-mutation for any other error) — that contract is owned by
    // `Vault::mutate_and_save` per DESIGN.md §4.3, so the worker test
    // asserts only that the pair survives and the dispatch routes
    // `Inline` rather than re-deriving rollback semantics here.
    let _ = completion.vault;
    let _ = completion.store;
}

// ---------------------------------------------------------------------------
// AddAccountComponent skeleton — marker + Cancel routing
// ---------------------------------------------------------------------------
//
// Symmetric partner of `rename_dialog::format_rename_dialog_marker`
// / `RENAME_DIALOG_MARKER_PREFIX`. The smoke test in
// `tests/gtk_smoke.rs` will grep for the prefix to prove the dialog
// mounted; locking the literal here keeps the pure-logic projection
// and the smoke marker aligned.
//
// `apply_msg(AddAccountMsg::Cancel)` is the Component-side entry
// point for the Cancel button — the only inbound message the
// skeleton's view! handles in this commit. Submit / draft-changed /
// duplicate-confirm variants land in follow-up commits alongside
// the editable form widgets.

#[test]
fn add_dialog_marker_prefix_is_stable_grep_anchor() {
    use paladin_gtk::add_account::ADD_DIALOG_MARKER_PREFIX;

    assert_eq!(ADD_DIALOG_MARKER_PREFIX, "paladin-gtk: add_dialog_path=");
}

#[test]
fn format_add_dialog_marker_renders_vault_path() {
    use paladin_gtk::add_account::{format_add_dialog_marker, ADD_DIALOG_MARKER_PREFIX};

    let path = PathBuf::from("/home/test/.local/share/paladin/vault.bin");
    let marker = format_add_dialog_marker(&path);
    assert!(
        marker.starts_with(ADD_DIALOG_MARKER_PREFIX),
        "marker `{marker}` should start with `{ADD_DIALOG_MARKER_PREFIX}`",
    );
    assert!(
        marker.contains("/home/test/.local/share/paladin/vault.bin"),
        "marker `{marker}` should contain the vault path",
    );
}

#[test]
fn add_account_init_clones_for_reactive_state() {
    use paladin_gtk::add_account::AddAccountInit;

    let init = AddAccountInit {
        vault_path: PathBuf::from("/home/test/.local/share/paladin/vault.bin"),
    };
    let cloned = init.clone();
    assert_eq!(cloned.vault_path, init.vault_path);
}

#[test]
fn apply_msg_cancel_routes_to_cancel_output() {
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddAccountOutput};

    let output = apply_msg(AddAccountMsg::Cancel);
    assert!(
        matches!(output, Some(AddAccountOutput::Cancel)),
        "Cancel must route to AddAccountOutput::Cancel, got {output:?}",
    );
}

#[test]
fn apply_msg_worker_failed_emits_no_output() {
    // `WorkerFailed` is consumed by the dialog to re-render the
    // inline error / durability warning; it never bubbles back to
    // `AppModel`. Pinned so a future `apply_msg` refactor cannot
    // forward it past the Component boundary.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, AddAccountMsg, AddPostEffectOutcome,
    };

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let output = apply_msg(AddAccountMsg::WorkerFailed(outcome));
    assert!(
        output.is_none(),
        "WorkerFailed must not bubble back to AppModel, got {output:?}",
    );
}
