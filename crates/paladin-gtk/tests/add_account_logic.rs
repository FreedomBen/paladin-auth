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
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddAccountOutput, AddDialogState};

    let mut state = AddDialogState::new();
    let output = apply_msg(&mut state, AddAccountMsg::Cancel);
    assert!(
        matches!(output, Some(AddAccountOutput::Cancel)),
        "Cancel must route to AddAccountOutput::Cancel, got {output:?}",
    );
}

#[test]
fn apply_msg_cancel_wipes_secret_state_buffers() {
    // DESIGN §8 mandates secret fields clear on cancel. Relying on
    // `AddSecretState`'s `Drop` would leave the secrets live between
    // the `Cancel` output and the controller drop by `AppModel`; an
    // explicit `clear_for(ClearReason::Cancel)` in the arm closes
    // that window. Pin both the manual Base32 buffer and the URI
    // shadow so a future refactor cannot accidentally wipe only one.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("JBSWY3DPEHPK3PXP".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged(
            "otpauth://totp/Issuer:label?secret=JBSWY3DPEHPK3PXP&issuer=Issuer".to_string(),
        ),
    );
    assert!(
        !state.secret_state().manual_secret.is_empty(),
        "precondition: manual buffer is non-empty before Cancel",
    );
    assert!(
        !state.secret_state().uri_text.is_empty(),
        "precondition: URI buffer is non-empty before Cancel",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::Cancel);

    assert!(
        state.secret_state().manual_secret.is_empty(),
        "Cancel must wipe the manual Base32 buffer",
    );
    assert!(
        state.secret_state().uri_text.is_empty(),
        "Cancel must wipe the URI shadow buffer",
    );
}

#[test]
fn apply_msg_worker_failed_emits_no_output_and_stores_outcome() {
    // `WorkerFailed` is consumed by the dialog to re-render the
    // inline error / durability warning; it never bubbles back to
    // `AppModel`. Pinned so a future `apply_msg` refactor cannot
    // forward it past the Component boundary. The typed outcome
    // is stored on `AddDialogState::worker_outcome` so the widget
    // view can route `Inline` / `KeepWithWarning` into the dialog
    // body without re-deriving the routing decision (mirror of the
    // `RenameDialogState::worker_outcome` contract).
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, AddAccountMsg, AddDialogState,
        AddPostEffectOutcome,
    };

    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let outcome = classify_add_post_effect_error(&err);
    assert!(matches!(outcome, AddPostEffectOutcome::Inline(_)));
    let mut state = AddDialogState::new();
    let output = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));
    assert!(
        output.is_none(),
        "WorkerFailed must not bubble back to AppModel, got {output:?}",
    );
    let stored = state
        .worker_outcome()
        .expect("Inline outcome should be stored on the state");
    assert!(matches!(stored, AddPostEffectOutcome::Inline(_)));
}

#[test]
fn apply_msg_worker_failed_keep_with_warning_stores_outcome() {
    // `save_durability_unconfirmed` means `Vault::add` committed but
    // the parent fsync was not confirmed. The post-effect routing
    // returns `KeepWithWarning`, and the dialog stores it so the
    // view can attach the durability warning to the body. The
    // success-with-warning case keeps the dialog open at the Cancel-
    // only state so the user can see the warning before dismissing.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, AddAccountMsg, AddDialogState,
        AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)));
    let mut state = AddDialogState::new();
    let returned = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));
    assert!(
        returned.is_none(),
        "WorkerFailed must not emit an Output, got {returned:?}",
    );
    let stored = state
        .worker_outcome()
        .expect("KeepWithWarning outcome should be stored");
    assert!(matches!(stored, AddPostEffectOutcome::KeepWithWarning(_)));
}

#[test]
fn add_dialog_state_new_initializes_worker_outcome_to_none() {
    // No worker has run yet on a freshly-opened dialog, so the
    // body should not render any prior outcome. Mirror of
    // `RenameDialogState::new` — both dialogs share the no-prior-
    // outcome invariant at construction time.
    use paladin_gtk::add_account::AddDialogState;

    let state = AddDialogState::new();
    assert!(state.worker_outcome().is_none());
}

#[test]
fn add_dialog_state_default_matches_new() {
    // `AddDialogState::default()` and `::new()` agree, so reactive
    // state holders that derive `Default` get the same empty state
    // the explicit constructor returns.
    use paladin_gtk::add_account::AddDialogState;

    let default_state = AddDialogState::default();
    assert!(default_state.worker_outcome().is_none());
}

#[test]
fn apply_msg_submit_proceed_routes_to_submit_output() {
    // The widget runs `classify_manual_submit` /
    // `classify_uri_submit` then `classify_duplicate` on the main
    // thread and only emits `SubmitProceed { account }` once a
    // non-collision `Proceed(ValidatedAccount)` is in hand (or after
    // an "add anyway" confirmation consumes the pending duplicate).
    // `apply_msg` forwards that as `AddAccountOutput::Submit { account }`
    // so `AppModel::update` can take the live `(Vault, Store)` pair
    // and spawn the `gio::spawn_blocking Vault::mutate_and_save(|v|
    // v.add(account))` worker.
    use paladin_core::{validate_manual, AccountInput, IconHintInput};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddAccountOutput, AddDialogState};

    let input = AccountInput {
        label: "test-label".to_string(),
        issuer: Some("issuer".to_string()),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let expected_id = validated.account.id();
    let expected_label = validated.account.label().to_string();

    let mut state = AddDialogState::new();
    let output = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );
    match output {
        Some(AddAccountOutput::Submit { account }) => {
            assert_eq!(
                account.id(),
                expected_id,
                "Submit forwards the validated-time id without re-stamping"
            );
            assert_eq!(
                account.label(),
                expected_label,
                "Submit forwards the validated label byte-for-byte"
            );
        }
        other => panic!("expected Some(Submit), got {other:?}"),
    }
}

#[test]
fn apply_msg_submit_proceed_clears_prior_worker_outcome() {
    // After a `save_not_committed` failure, the user fixes the
    // underlying issue and retries. The stored worker outcome must
    // clear when SubmitProceed re-enters the worker so the body
    // does not render a stale post-effect error alongside the live
    // attempt. Mirror of the rename dialog's
    // `apply_msg_draft_changed_clears_prior_worker_outcome` contract,
    // adapted for the add dialog's submit-only retry surface.
    use paladin_core::{validate_manual, AccountInput, IconHintInput};
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let outcome = classify_add_post_effect_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));
    assert!(state.worker_outcome().is_some());

    let input = AccountInput {
        label: "retry-label".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );
    assert!(
        state.worker_outcome().is_none(),
        "SubmitProceed must clear any prior worker outcome before the new attempt",
    );
}

#[test]
fn apply_msg_submit_proceed_wipes_secret_state_buffers() {
    // DESIGN §8 mandates secret fields clear on submit. The validated
    // `Account` (with `Secret` already wrapped in `ZeroizeOnDrop`)
    // crosses the Component boundary in `AddAccountOutput::Submit`,
    // but the manual Base32 / URI shadow buffers in
    // `secret_state` are *also* secret-bearing and must wipe before
    // the worker spawns — they are not consumed by the output.
    // Symmetric partner of `apply_msg_cancel_wipes_secret_state_buffers`
    // for the success-path exit.
    use paladin_core::{validate_manual, AccountInput, IconHintInput};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("JBSWY3DPEHPK3PXP".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged(
            "otpauth://totp/Issuer:label?secret=JBSWY3DPEHPK3PXP&issuer=Issuer".to_string(),
        ),
    );
    assert!(
        !state.secret_state().manual_secret.is_empty(),
        "precondition: manual buffer is non-empty before SubmitProceed",
    );
    assert!(
        !state.secret_state().uri_text.is_empty(),
        "precondition: URI buffer is non-empty before SubmitProceed",
    );

    let input = AccountInput {
        label: "submit-label".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );

    assert!(
        state.secret_state().manual_secret.is_empty(),
        "SubmitProceed must wipe the manual Base32 buffer",
    );
    assert!(
        state.secret_state().uri_text.is_empty(),
        "SubmitProceed must wipe the URI shadow buffer",
    );
}

#[test]
fn add_dialog_state_new_initializes_secret_state_to_manual_path_with_empty_buffers() {
    // The freshly-opened dialog defaults to the manual sub-path with
    // empty secret buffers and no pending duplicate-add, matching
    // `AddSecretState::new()`. Pinning this in the dialog-level state
    // means a future view binding cannot accidentally surface a stale
    // path / buffer / pending value at mount time.
    use paladin_gtk::add_account::AddDialogState;
    use paladin_gtk::secret_fields::AddPath;

    let state = AddDialogState::new();
    let secret = state.secret_state();
    assert_eq!(
        secret.active_path,
        AddPath::Manual,
        "fresh dialog opens on the manual sub-path",
    );
    assert!(
        secret.manual_secret.is_empty(),
        "manual Base32 buffer starts empty",
    );
    assert!(secret.uri_text.is_empty(), "URI buffer starts empty");
    assert!(
        secret.pending.is_none(),
        "no pending duplicate before the user submits",
    );
}

#[test]
fn add_dialog_state_default_secret_state_matches_new() {
    // `Default` derivations on dialog-state holders must agree with
    // the explicit `::new` constructor so a `#[derive(Default)]`
    // wrapper cannot drift from the audited construction path.
    use paladin_gtk::add_account::AddDialogState;
    use paladin_gtk::secret_fields::AddPath;

    let state = AddDialogState::default();
    let secret = state.secret_state();
    assert_eq!(secret.active_path, AddPath::Manual);
    assert!(secret.manual_secret.is_empty());
    assert!(secret.uri_text.is_empty());
    assert!(secret.pending.is_none());
}

#[test]
fn apply_msg_switch_path_to_uri_flips_active_path_and_emits_no_output() {
    // The `AdwViewSwitcher` between the manual / URI sub-paths drives
    // `apply_msg` via `AddAccountMsg::SwitchPath`. The arm must
    // delegate to `AddSecretState::switch_path`, which is tested
    // exhaustively in `tests/secret_fields_logic.rs` for buffer-clear
    // / pending-drop. Here we pin the routing: the visible
    // `active_path` flips and no `AddAccountOutput` escapes the
    // dialog — path switches stay local until Submit is pressed.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    assert_eq!(
        state.secret_state().active_path,
        AddPath::Manual,
        "precondition: fresh dialog opens on Manual",
    );

    let output = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    assert!(
        output.is_none(),
        "SwitchPath is dialog-local; no output flows back to AppModel",
    );
    assert_eq!(
        state.secret_state().active_path,
        AddPath::Uri,
        "SwitchPath(Uri) advances the active path",
    );
}

#[test]
fn apply_msg_manual_secret_changed_shadows_into_secret_state() {
    // GTK `gtk::Editable::text` keystrokes on the manual Base32 entry
    // arrive as `String`s; the dialog shadows them into the Paladin-
    // owned `Zeroizing<String>` inside `secret_state.manual_secret`
    // so the cleartext never lives in long-lived `AppModel` state.
    // Mirror of `UnlockDialogMsg::PassphraseChanged` on the add path:
    // the message arm shadows then emits no output (Submit is the
    // first cross-component message that consumes the buffer).
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let output = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("JBSWY3DPEHPK3PXP".to_string()),
    );
    assert!(
        output.is_none(),
        "ManualSecretChanged shadows the buffer; no output flows back to AppModel",
    );
    assert_eq!(
        state.secret_state().manual_secret.text(),
        "JBSWY3DPEHPK3PXP",
        "manual Base32 keystrokes shadow into the Paladin-owned buffer",
    );
}

#[test]
fn apply_msg_uri_text_changed_shadows_into_secret_state() {
    // The `otpauth://` URI entry is secret-bearing (it embeds the
    // Base32 secret) so the §8 rule that holds for the manual Base32
    // secret holds here too: shadow the GTK keystrokes into the
    // Paladin-owned `Zeroizing<String>` and emit no output until the
    // user submits.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let output = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged(
            "otpauth://totp/Issuer:label?secret=JBSWY3DPEHPK3PXP&issuer=Issuer".to_string(),
        ),
    );
    assert!(
        output.is_none(),
        "UriTextChanged shadows the buffer; no output flows back to AppModel",
    );
    assert_eq!(
        state.secret_state().uri_text.text(),
        "otpauth://totp/Issuer:label?secret=JBSWY3DPEHPK3PXP&issuer=Issuer",
        "URI keystrokes shadow into the Paladin-owned buffer",
    );
}

#[test]
fn apply_msg_uri_text_changed_replaces_prior_shadow() {
    // Mirror of the manual-secret replacement contract: each keystroke
    // yields a fresh `gtk::Editable::text` value so successive shadows
    // must replace rather than append. Prior bytes zero out in place
    // via `Zeroizing<String>`'s Drop.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged("otpauth://totp/a?secret=A".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged("otpauth://totp/b?secret=B".to_string()),
    );
    assert_eq!(
        state.secret_state().uri_text.text(),
        "otpauth://totp/b?secret=B",
        "successive UriTextChanged messages replace the prior shadow",
    );
}

#[test]
fn apply_msg_manual_secret_changed_replaces_prior_shadow() {
    // Each keystroke produces a fresh `gtk::Editable::text` value,
    // not an append, so successive shadows must replace rather than
    // accumulate. The replaced bytes zero out in place via
    // `Zeroizing<String>`'s Drop — pinning the replacement semantics
    // here means a future refactor cannot accidentally append (which
    // would leave the prior cleartext live in memory).
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("first".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("second".to_string()),
    );
    assert_eq!(
        state.secret_state().manual_secret.text(),
        "second",
        "successive ManualSecretChanged messages replace the prior shadow",
    );
}

#[test]
fn apply_msg_switch_path_same_path_is_idempotent_noop() {
    // Idempotent re-entry on the active path must not erase buffers
    // or emit a stray output. Mirrors the
    // `AddSecretState::switch_path` same-path early-return guard in
    // `tests/secret_fields_logic.rs` lifted to the `apply_msg`
    // boundary.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let output = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Manual));
    assert!(output.is_none());
    assert_eq!(
        state.secret_state().active_path,
        AddPath::Manual,
        "same-path SwitchPath leaves active_path on Manual",
    );
}

#[test]
fn apply_msg_stage_pending_duplicate_parks_validated_account_in_secret_state() {
    // After `classify_duplicate` returns `AwaitConfirmation`, the
    // widget hands the validated account back to the dialog via
    // `AddAccountMsg::StagePendingDuplicate` so it parks in
    // `AddSecretState::pending` for the "add anyway?" confirmation
    // round trip. The arm emits no output — the duplicate-confirm
    // decision stays dialog-local; `AppModel` only sees the final
    // `SubmitProceed` once the user confirms (or nothing, on cancel).
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("expected AwaitConfirmation");
    };

    let output = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert!(
        output.is_none(),
        "StagePendingDuplicate stays dialog-local; no output flows to AppModel",
    );
    assert!(
        state.secret_state().pending.is_some(),
        "the validated account is parked in AddSecretState::pending",
    );
}

#[test]
fn apply_msg_stage_pending_duplicate_replaces_prior_pending() {
    // A second `StagePendingDuplicate` must replace (not stack) the
    // prior pending — the let-binding inside the arm drops the
    // returned `Option<Box<ValidatedAccount>>` so the prior secret
    // bytes zero out via `paladin_core::Secret`'s `ZeroizeOnDrop`
    // impl. Pin the replacement semantics here so a future refactor
    // cannot accidentally leak the prior pending into a stash.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let first = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: first.account,
            warnings: first.warnings,
            existing: dummy_existing_summary(),
        },
    );
    let second = match classify_manual_submit(manual_hotp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let second_label = second.account.label().to_string();

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: second.account,
            warnings: second.warnings,
            existing: dummy_existing_summary(),
        },
    );

    let pending = state
        .secret_state()
        .pending
        .as_ref()
        .expect("pending is populated after second StagePendingDuplicate");
    assert_eq!(
        pending.account.label(),
        second_label,
        "second StagePendingDuplicate replaces the prior pending",
    );
}

#[test]
fn apply_msg_confirm_add_anyway_routes_to_submit_with_pending_account() {
    // After `StagePendingDuplicate` parks the validated account, the
    // user clicks "Add anyway" and the widget dispatches
    // `AddAccountMsg::ConfirmAddAnyway`. `apply_msg` consumes the
    // parked `ValidatedAccount` out of `AddSecretState::pending` and
    // forwards it as `AddAccountOutput::Submit { account }` so
    // `AppModel::update` can spawn the
    // `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(...))`
    // worker. Mirror of the CLI `--allow-duplicate` and TUI
    // `Effect::AddAnyway` follow-up paths.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddAccountOutput, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("expected AwaitConfirmation");
    };
    let expected_id = validated.account.id();
    let expected_label = validated.account.label().to_string();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    let output = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);
    match output {
        Some(AddAccountOutput::Submit { account }) => {
            assert_eq!(
                account.id(),
                expected_id,
                "ConfirmAddAnyway forwards the validated-time id without re-stamping",
            );
            assert_eq!(
                account.label(),
                expected_label,
                "ConfirmAddAnyway forwards the pending label byte-for-byte",
            );
        }
        other => panic!("expected Some(Submit), got {other:?}"),
    }
}

#[test]
fn apply_msg_confirm_add_anyway_clears_pending_slot() {
    // The pending slot must drain when the user confirms "Add anyway"
    // so a follow-up worker failure cannot accidentally re-emit a
    // stale pending into a second submit. `consume_pending` takes
    // the value out of the slot; pin the resulting state here.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("expected AwaitConfirmation");
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        state.secret_state().pending.is_some(),
        "precondition: pending is parked before ConfirmAddAnyway",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        state.secret_state().pending.is_none(),
        "ConfirmAddAnyway drains the pending slot via consume_pending",
    );
}

#[test]
fn apply_msg_confirm_add_anyway_wipes_secret_state_buffers() {
    // `AddSecretState::consume_pending` wipes both the manual Base32
    // and `otpauth://` URI shadow buffers alongside taking the
    // pending. The duplicate-confirm path must honor that contract —
    // the worker spawns with empty secret buffers per DESIGN §8.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged(
            "otpauth://totp/Issuer:label?secret=JBSWY3DPEHPK3PXP&issuer=Issuer".to_string(),
        ),
    );
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("expected AwaitConfirmation");
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        !state.secret_state().manual_secret.is_empty(),
        "precondition: manual buffer is non-empty before ConfirmAddAnyway",
    );
    assert!(
        !state.secret_state().uri_text.is_empty(),
        "precondition: URI buffer is non-empty before ConfirmAddAnyway",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        state.secret_state().manual_secret.is_empty(),
        "ConfirmAddAnyway must wipe the manual Base32 buffer",
    );
    assert!(
        state.secret_state().uri_text.is_empty(),
        "ConfirmAddAnyway must wipe the URI shadow buffer",
    );
}

#[test]
fn apply_msg_confirm_add_anyway_clears_prior_worker_outcome() {
    // After a `save_not_committed` on a non-duplicate submit, the
    // user might re-trigger the manual path, hit a duplicate, and
    // confirm "Add anyway". The prior worker outcome must clear when
    // ConfirmAddAnyway re-enters the worker so the body does not
    // render a stale post-effect error alongside the live attempt.
    // Mirror of `apply_msg_submit_proceed_clears_prior_worker_outcome`
    // for the duplicate-confirm path.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let outcome = classify_add_post_effect_error(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));
    assert!(state.worker_outcome().is_some());

    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(err) => panic!("fixture failed: {err:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("expected AwaitConfirmation");
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        state.worker_outcome().is_none(),
        "ConfirmAddAnyway must clear any prior worker outcome before the new attempt",
    );
}

#[test]
fn apply_msg_manual_label_changed_shadows_into_manual_draft() {
    // Per-keystroke label entry text routes through
    // `AddAccountMsg::ManualLabelChanged(String)` and shadows into
    // `ManualDraftState::label` so the widget view's `#[watch]`
    // projection and `classify_manual_submit` at Save time both see
    // the live draft. The arm emits no output — label edits are
    // dialog-local until Save.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().label, "");

    let output = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("my-label".to_string()),
    );

    assert!(
        output.is_none(),
        "ManualLabelChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().label,
        "my-label",
        "ManualLabelChanged shadows the entry text into ManualDraftState::label",
    );
}

#[test]
fn apply_msg_manual_label_changed_replaces_prior_shadow() {
    // A second keystroke replaces (does not append) the prior label
    // shadow so the draft stays in lockstep with the visible entry
    // text. Mirror of the existing
    // `apply_msg_manual_secret_changed_replaces_prior_shadow` /
    // `apply_msg_uri_text_changed_replaces_prior_shadow` contracts
    // on the non-secret field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("first".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("second".to_string()),
    );

    assert_eq!(
        state.manual_draft().label,
        "second",
        "second ManualLabelChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_label_changed_preserves_other_draft_fields() {
    // The label keystroke must not disturb the rest of the manual
    // draft — issuer / algorithm / digits / kind / period / counter /
    // icon-hint stay on their CLI defaults so a stray label edit
    // does not silently reset the form.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("only-label".to_string()),
    );

    let draft = state.manual_draft();
    assert_eq!(draft.label, "only-label");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 30);
    assert_eq!(draft.counter, 0);
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_issuer_changed_shadows_into_manual_draft() {
    // Per-keystroke issuer entry text routes through
    // `AddAccountMsg::ManualIssuerChanged(String)` and shadows into
    // `ManualDraftState::issuer` so the widget view's `#[watch]`
    // projection and `classify_manual_submit` at Save time both see
    // the live draft. The arm emits no output — issuer edits are
    // dialog-local until Save. Mirror of the existing
    // `apply_msg_manual_label_changed_shadows_into_manual_draft`
    // contract on the sibling non-secret field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().issuer, "");

    let output = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("Acme Co.".to_string()),
    );

    assert!(
        output.is_none(),
        "ManualIssuerChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().issuer,
        "Acme Co.",
        "ManualIssuerChanged shadows the entry text into ManualDraftState::issuer",
    );
}

#[test]
fn apply_msg_manual_issuer_changed_replaces_prior_shadow() {
    // A second keystroke replaces (does not append) the prior issuer
    // shadow so the draft stays in lockstep with the visible entry
    // text. Mirror of the existing
    // `apply_msg_manual_label_changed_replaces_prior_shadow` contract
    // on the sibling non-secret field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("first".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("second".to_string()),
    );

    assert_eq!(
        state.manual_draft().issuer,
        "second",
        "second ManualIssuerChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_issuer_changed_preserves_other_draft_fields() {
    // The issuer keystroke must not disturb the rest of the manual
    // draft — label / algorithm / digits / kind / period / counter /
    // icon-hint stay on their CLI defaults so a stray issuer edit
    // does not silently reset the form.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("only-issuer".to_string()),
    );

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "only-issuer");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 30);
    assert_eq!(draft.counter, 0);
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_algorithm_changed_shadows_into_manual_draft() {
    // Algorithm dropdown selection routes through
    // `AddAccountMsg::ManualAlgorithmChanged(Algorithm)` and shadows
    // into `ManualDraftState::algorithm` so the widget view's
    // `#[watch]` projection and `classify_manual_submit` at Save time
    // both see the live draft. The arm emits no output — algorithm
    // changes are dialog-local until Save. Mirror of the existing
    // `apply_msg_manual_label_changed_shadows_into_manual_draft`
    // contract on the sibling dropdown field.
    use paladin_core::Algorithm;
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().algorithm, Algorithm::Sha1);

    let output = apply_msg(
        &mut state,
        AddAccountMsg::ManualAlgorithmChanged(Algorithm::Sha256),
    );

    assert!(
        output.is_none(),
        "ManualAlgorithmChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().algorithm,
        Algorithm::Sha256,
        "ManualAlgorithmChanged shadows the dropdown choice into ManualDraftState::algorithm",
    );
}

#[test]
fn apply_msg_manual_algorithm_changed_replaces_prior_shadow() {
    // A second selection replaces (does not accumulate) the prior
    // algorithm shadow so the draft stays in lockstep with the
    // dropdown's current value. Mirror of the existing
    // `apply_msg_manual_label_changed_replaces_prior_shadow` contract
    // on the sibling dropdown field.
    use paladin_core::Algorithm;
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualAlgorithmChanged(Algorithm::Sha256),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualAlgorithmChanged(Algorithm::Sha512),
    );

    assert_eq!(
        state.manual_draft().algorithm,
        Algorithm::Sha512,
        "second ManualAlgorithmChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_algorithm_changed_preserves_other_draft_fields() {
    // The algorithm dropdown selection must not disturb the rest of
    // the manual draft — label / issuer / digits / kind / period /
    // counter / icon-hint stay on their CLI defaults so a stray
    // algorithm change does not silently reset the form.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualAlgorithmChanged(Algorithm::Sha512),
    );

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha512);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 30);
    assert_eq!(draft.counter, 0);
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_digits_changed_shadows_into_manual_draft() {
    // OTP digit spinner value routes through
    // `AddAccountMsg::ManualDigitsChanged(u8)` and shadows into
    // `ManualDraftState::digits` so the widget view's `#[watch]`
    // projection and `classify_manual_submit` at Save time both see
    // the live draft. The arm emits no output — digits changes are
    // dialog-local until Save. Mirror of the existing
    // `apply_msg_manual_algorithm_changed_shadows_into_manual_draft`
    // contract on the sibling typed-value field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().digits, 6);

    let output = apply_msg(&mut state, AddAccountMsg::ManualDigitsChanged(8));

    assert!(
        output.is_none(),
        "ManualDigitsChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().digits,
        8,
        "ManualDigitsChanged shadows the spinner value into ManualDraftState::digits",
    );
}

#[test]
fn apply_msg_manual_digits_changed_replaces_prior_shadow() {
    // A second spinner step replaces (does not accumulate) the prior
    // digits shadow so the draft stays in lockstep with the spinner's
    // current value. Mirror of the existing
    // `apply_msg_manual_algorithm_changed_replaces_prior_shadow`
    // contract on the sibling typed-value field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualDigitsChanged(7));
    let _ = apply_msg(&mut state, AddAccountMsg::ManualDigitsChanged(8));

    assert_eq!(
        state.manual_draft().digits,
        8,
        "second ManualDigitsChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_digits_changed_preserves_other_draft_fields() {
    // The digits spinner step must not disturb the rest of the
    // manual draft — label / issuer / algorithm / kind / period /
    // counter / icon-hint stay on their CLI defaults so a stray
    // digits change does not silently reset the form.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualDigitsChanged(8));

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 8);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 30);
    assert_eq!(draft.counter, 0);
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_digits_changed_preserves_out_of_range_for_validate_manual() {
    // The spinner's GTK widget clamps to 6..=8 by configuration, but
    // `apply_msg` must not silently re-clamp — if the dispatch ever
    // carries an out-of-range value (e.g. a test driver or a misuse
    // path), the draft preserves it verbatim so `validate_manual` at
    // Save time can surface the typed `digits` inline error against
    // the spinner. Mirrors the §"Secret entry handling" contract that
    // dispatch arms shadow live state and defer validation to submit.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualDigitsChanged(9));

    assert_eq!(
        state.manual_draft().digits,
        9,
        "apply_msg preserves the spinner value verbatim — clamping lives in the widget",
    );
}

#[test]
fn apply_msg_manual_kind_changed_shadows_into_manual_draft() {
    // TOTP / HOTP switcher routes through
    // `AddAccountMsg::ManualKindChanged(AccountKindInput)` and
    // shadows into `ManualDraftState::kind` so the widget view's
    // `#[watch]` projection can swap the period spinner for the
    // counter spinner (and vice versa) and `classify_manual_submit`
    // at Save time sees the live draft. The arm emits no output —
    // kind changes are dialog-local until Save. Mirror of the
    // existing
    // `apply_msg_manual_algorithm_changed_shadows_into_manual_draft`
    // contract on the sibling typed-enum field.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().kind, AccountKindInput::Totp);

    let output = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );

    assert!(
        output.is_none(),
        "ManualKindChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().kind,
        AccountKindInput::Hotp,
        "ManualKindChanged shadows the switcher choice into ManualDraftState::kind",
    );
}

#[test]
fn apply_msg_manual_kind_changed_round_trips_between_totp_and_hotp() {
    // Toggling the switcher must reach the other variant on every
    // dispatch — a stuck `Totp` after a `Hotp` round trip would
    // freeze the form's visible period / counter row. Mirror of the
    // existing
    // `apply_msg_manual_algorithm_changed_replaces_prior_shadow`
    // contract on the kind switcher, but framed as a round trip so
    // both directions are exercised.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );
    assert_eq!(state.manual_draft().kind, AccountKindInput::Hotp);

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Totp),
    );
    assert_eq!(
        state.manual_draft().kind,
        AccountKindInput::Totp,
        "second ManualKindChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_kind_changed_preserves_other_draft_fields_including_period_and_counter() {
    // The kind switcher must not silently zero out the period or
    // counter buffers — `classify_manual_submit` drops the irrelevant
    // value at Save time based on `kind`, so the draft can keep both
    // populated and the user's prior typing is preserved if they
    // toggle the switcher and toggle back. Mirror of the existing
    // `apply_msg_manual_algorithm_changed_preserves_other_draft_fields`
    // contract on the kind switcher, with extra emphasis on the
    // period_secs / counter pair.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Hotp);
    assert_eq!(
        draft.period_secs, 30,
        "kind switcher must not clear the TOTP period buffer",
    );
    assert_eq!(
        draft.counter, 0,
        "kind switcher must not clear the HOTP counter buffer",
    );
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_period_changed_shadows_into_manual_draft() {
    // TOTP period spinner value routes through
    // `AddAccountMsg::ManualPeriodChanged(u32)` and shadows into
    // `ManualDraftState::period_secs` so the widget view's `#[watch]`
    // projection and `classify_manual_submit` at Save time both see
    // the live draft. The arm emits no output — period changes are
    // dialog-local until Save. Mirror of the existing
    // `apply_msg_manual_digits_changed_shadows_into_manual_draft`
    // contract on the sibling numeric-spinner field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().period_secs, 30);

    let output = apply_msg(&mut state, AddAccountMsg::ManualPeriodChanged(60));

    assert!(
        output.is_none(),
        "ManualPeriodChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().period_secs,
        60,
        "ManualPeriodChanged shadows the spinner value into ManualDraftState::period_secs",
    );
}

#[test]
fn apply_msg_manual_period_changed_replaces_prior_shadow() {
    // A second spinner step replaces (does not accumulate) the prior
    // period shadow so the draft stays in lockstep with the
    // spinner's current value. Mirror of the existing
    // `apply_msg_manual_digits_changed_replaces_prior_shadow`
    // contract on the sibling numeric-spinner field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualPeriodChanged(45));
    let _ = apply_msg(&mut state, AddAccountMsg::ManualPeriodChanged(60));

    assert_eq!(
        state.manual_draft().period_secs,
        60,
        "second ManualPeriodChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_period_changed_preserves_other_draft_fields_including_counter() {
    // The period spinner step must not disturb the rest of the
    // manual draft — and in particular must not clear the sibling
    // HOTP counter buffer so a `Kind::Hotp -> Kind::Totp -> tweak
    // period -> Kind::Hotp` round trip preserves the user's prior
    // counter value.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualPeriodChanged(60));

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 60);
    assert_eq!(
        draft.counter, 0,
        "period spinner step must not clear the HOTP counter buffer",
    );
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_period_changed_preserves_out_of_range_for_validate_manual() {
    // The spinner's GTK widget clamps to the §5 valid range by
    // configuration, but `apply_msg` must not silently re-clamp — if
    // dispatch ever carries an out-of-range value (e.g. a test driver
    // or a misuse path), the draft preserves it verbatim so
    // `validate_manual` at Save time can surface the typed
    // `period_secs` inline error. Mirrors the existing
    // `apply_msg_manual_digits_changed_preserves_out_of_range_for_validate_manual`
    // contract on the period field — both numeric spinners defer
    // validation to submit.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualPeriodChanged(0));

    assert_eq!(
        state.manual_draft().period_secs,
        0,
        "apply_msg preserves the spinner value verbatim — clamping lives in the widget",
    );
}

#[test]
fn apply_msg_manual_counter_changed_shadows_into_manual_draft() {
    // HOTP counter spinner value routes through
    // `AddAccountMsg::ManualCounterChanged(u64)` and shadows into
    // `ManualDraftState::counter` so the widget view's `#[watch]`
    // projection and `classify_manual_submit` at Save time both see
    // the live draft. The arm emits no output — counter changes are
    // dialog-local until Save. Sibling of the existing
    // `apply_msg_manual_period_changed_shadows_into_manual_draft`
    // contract on the HOTP counter spinner.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().counter, 0);

    let output = apply_msg(&mut state, AddAccountMsg::ManualCounterChanged(42));

    assert!(
        output.is_none(),
        "ManualCounterChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().counter,
        42,
        "ManualCounterChanged shadows the spinner value into ManualDraftState::counter",
    );
}

#[test]
fn apply_msg_manual_counter_changed_replaces_prior_shadow() {
    // A second spinner step replaces (does not accumulate) the prior
    // counter shadow so the draft stays in lockstep with the
    // spinner's current value. Sibling of the existing
    // `apply_msg_manual_period_changed_replaces_prior_shadow` contract
    // on the HOTP counter spinner.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualCounterChanged(7));
    let _ = apply_msg(&mut state, AddAccountMsg::ManualCounterChanged(13));

    assert_eq!(
        state.manual_draft().counter,
        13,
        "second ManualCounterChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_counter_changed_preserves_other_draft_fields_including_period() {
    // The counter spinner step must not disturb the rest of the
    // manual draft — and in particular must not clear the sibling
    // TOTP period buffer so a `Kind::Totp -> Kind::Hotp -> tweak
    // counter -> Kind::Totp` round trip preserves the user's prior
    // period value.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualCounterChanged(99));

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(
        draft.period_secs, 30,
        "counter spinner step must not clear the TOTP period buffer",
    );
    assert_eq!(draft.counter, 99);
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn apply_msg_manual_counter_changed_accepts_u64_max() {
    // The HOTP counter is `u64`; `apply_msg` must accept any value
    // the spinner produces verbatim — the spinner's GTK widget
    // configuration constrains the visible range, but a test driver
    // or future misuse path could carry `u64::MAX` and the draft
    // must preserve it for `validate_manual` at Save time. Mirrors
    // the sibling defensive contract on the period / digits
    // spinners.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::ManualCounterChanged(u64::MAX));

    assert_eq!(
        state.manual_draft().counter,
        u64::MAX,
        "apply_msg preserves the spinner value verbatim — clamping lives in the widget",
    );
}

#[test]
fn apply_msg_manual_icon_hint_changed_shadows_into_manual_draft() {
    // Per-keystroke icon-hint entry text routes through
    // `AddAccountMsg::ManualIconHintChanged(String)` and shadows into
    // `ManualDraftState::icon_hint_text` so the widget view's
    // `#[watch]` projection and `classify_manual_submit` at Save time
    // (which calls `parse_icon_hint_token`) both see the live draft.
    // The arm emits no output — icon-hint edits are dialog-local
    // until Save. Mirror of the existing
    // `apply_msg_manual_label_changed_shadows_into_manual_draft`
    // contract on the sibling non-secret free-form text field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    assert_eq!(state.manual_draft().icon_hint_text, "");

    let output = apply_msg(
        &mut state,
        AddAccountMsg::ManualIconHintChanged("github".to_string()),
    );

    assert!(
        output.is_none(),
        "ManualIconHintChanged stays dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.manual_draft().icon_hint_text,
        "github",
        "ManualIconHintChanged shadows the entry text into ManualDraftState::icon_hint_text",
    );
}

#[test]
fn apply_msg_manual_icon_hint_changed_replaces_prior_shadow() {
    // A second keystroke replaces (does not append) the prior icon-
    // hint shadow so the draft stays in lockstep with the visible
    // entry text. Mirror of the existing
    // `apply_msg_manual_label_changed_replaces_prior_shadow` contract
    // on the sibling free-form text field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIconHintChanged("github".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIconHintChanged("gitlab".to_string()),
    );

    assert_eq!(
        state.manual_draft().icon_hint_text,
        "gitlab",
        "second ManualIconHintChanged replaces the prior shadow",
    );
}

#[test]
fn apply_msg_manual_icon_hint_changed_preserves_other_draft_fields() {
    // The icon-hint keystroke must not disturb the rest of the
    // manual draft — label / issuer / algorithm / digits / kind /
    // period / counter stay on their CLI defaults so a stray icon-
    // hint edit does not silently reset the form.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIconHintChanged("only-icon-hint".to_string()),
    );

    let draft = state.manual_draft();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 30);
    assert_eq!(draft.counter, 0);
    assert_eq!(draft.icon_hint_text, "only-icon-hint");
}

#[test]
fn apply_msg_manual_icon_hint_changed_preserves_verbatim_for_parse_icon_hint_token() {
    // Parsing of `"none"` / explicit slugs lives in
    // `parse_icon_hint_token` at submit time inside
    // `classify_manual_submit`. `apply_msg` therefore preserves the
    // typed text verbatim — including whitespace and arbitrary case
    // of `"None"` / `"NONE"` — so the parse happens once, at the
    // boundary the CLI / TUI also use. A premature normalization in
    // the dispatch arm would silently shift the cursor and diverge
    // from the CLI / TUI add modals.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIconHintChanged("  NoNe  ".to_string()),
    );

    assert_eq!(
        state.manual_draft().icon_hint_text,
        "  NoNe  ",
        "apply_msg preserves the entry text verbatim — parsing happens at Save time",
    );
}

#[test]
fn manual_draft_state_default_matches_cli_manual_add_defaults() {
    // The `AdwPreferencesGroup` body of `AddAccountComponent` opens
    // with the same defaults the CLI interactive prompts use (DESIGN
    // §5 / `paladin-cli/src/commands/add.rs`): TOTP, SHA1, 6 digits,
    // 30 s period, HOTP counter 0, and empty label / issuer /
    // icon-hint text (which collapses to `IconHintInput::Default`
    // through `paladin_core::parse_icon_hint_token`).
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::ManualDraftState;

    let draft = ManualDraftState::default();
    assert_eq!(draft.label, "");
    assert_eq!(draft.issuer, "");
    assert_eq!(draft.algorithm, Algorithm::Sha1);
    assert_eq!(draft.digits, 6);
    assert_eq!(draft.kind, AccountKindInput::Totp);
    assert_eq!(draft.period_secs, 30);
    assert_eq!(draft.counter, 0);
    assert_eq!(draft.icon_hint_text, "");
}

#[test]
fn manual_draft_state_new_matches_default() {
    // Mirror of `AddDialogState::new()`'s parity with `default()`:
    // `ManualDraftState::new()` is the named constructor the widget
    // calls when the dialog opens, and it must match the `Default`
    // impl so future construction sites do not drift.
    use paladin_gtk::add_account::ManualDraftState;

    let from_new = ManualDraftState::new();
    let from_default = ManualDraftState::default();
    assert_eq!(from_new.label, from_default.label);
    assert_eq!(from_new.issuer, from_default.issuer);
    assert_eq!(from_new.algorithm, from_default.algorithm);
    assert_eq!(from_new.digits, from_default.digits);
    assert_eq!(from_new.kind, from_default.kind);
    assert_eq!(from_new.period_secs, from_default.period_secs);
    assert_eq!(from_new.counter, from_default.counter);
    assert_eq!(from_new.icon_hint_text, from_default.icon_hint_text);
}

#[test]
fn manual_draft_state_clones_freely_for_reactive_state() {
    // Reactive `#[watch]` projections in the relm4 view rely on
    // `Clone` for the projected fields. The non-secret manual draft
    // is plain data, so the struct as a whole must `Clone` cheaply
    // for the widget binders.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::ManualDraftState;

    let draft = ManualDraftState {
        label: "my-label".to_string(),
        issuer: "my-issuer".to_string(),
        algorithm: Algorithm::Sha256,
        digits: 8,
        kind: AccountKindInput::Hotp,
        period_secs: 60,
        counter: 42,
        icon_hint_text: "slack".to_string(),
    };
    let cloned = draft.clone();
    assert_eq!(cloned.label, draft.label);
    assert_eq!(cloned.issuer, draft.issuer);
    assert_eq!(cloned.algorithm, draft.algorithm);
    assert_eq!(cloned.digits, draft.digits);
    assert_eq!(cloned.kind, draft.kind);
    assert_eq!(cloned.period_secs, draft.period_secs);
    assert_eq!(cloned.counter, draft.counter);
    assert_eq!(cloned.icon_hint_text, draft.icon_hint_text);
}

#[test]
fn add_dialog_state_new_initializes_manual_draft_to_defaults() {
    // The freshly-opened add dialog must start the manual form on
    // the CLI defaults so the view's first frame already matches the
    // documented behavior. Mirror of
    // `add_dialog_state_new_initializes_secret_state_to_manual_path_with_empty_buffers`
    // for the non-secret half of the manual sub-path.
    use paladin_gtk::add_account::{AddDialogState, ManualDraftState};

    let state = AddDialogState::new();
    let expected = ManualDraftState::default();
    let draft = state.manual_draft();
    assert_eq!(draft.label, expected.label);
    assert_eq!(draft.issuer, expected.issuer);
    assert_eq!(draft.algorithm, expected.algorithm);
    assert_eq!(draft.digits, expected.digits);
    assert_eq!(draft.kind, expected.kind);
    assert_eq!(draft.period_secs, expected.period_secs);
    assert_eq!(draft.counter, expected.counter);
    assert_eq!(draft.icon_hint_text, expected.icon_hint_text);
}

#[test]
fn add_dialog_state_default_manual_draft_matches_new() {
    // The implicit `Default` impl must construct the same manual
    // draft the named `new()` constructor does. Mirror of
    // `add_dialog_state_default_secret_state_matches_new`.
    use paladin_gtk::add_account::AddDialogState;

    let from_new = AddDialogState::new();
    let from_default = AddDialogState::default();
    assert_eq!(
        from_new.manual_draft().label,
        from_default.manual_draft().label
    );
    assert_eq!(
        from_new.manual_draft().issuer,
        from_default.manual_draft().issuer
    );
    assert_eq!(
        from_new.manual_draft().algorithm,
        from_default.manual_draft().algorithm
    );
    assert_eq!(
        from_new.manual_draft().digits,
        from_default.manual_draft().digits
    );
    assert_eq!(
        from_new.manual_draft().kind,
        from_default.manual_draft().kind
    );
    assert_eq!(
        from_new.manual_draft().period_secs,
        from_default.manual_draft().period_secs
    );
    assert_eq!(
        from_new.manual_draft().counter,
        from_default.manual_draft().counter
    );
    assert_eq!(
        from_new.manual_draft().icon_hint_text,
        from_default.manual_draft().icon_hint_text
    );
}

#[test]
fn compose_manual_fields_maps_every_draft_field_and_secret_text_verbatim() {
    // The widget builds `ManualFields` at submit time by combining
    // the live non-secret `ManualDraftState` shadow with the
    // Paladin-owned `crate::secret_fields::SecretEntry` text. The
    // composed bundle must carry every draft field verbatim so
    // `classify_manual_submit` sees the same values the user typed.
    // The secret arrives as a borrowed `&str` (so the caller can
    // pass `secret_state.manual_secret.text()` without an extra
    // allocation) and lands inside a `SecretString` whose
    // `ZeroizeOnDrop` impl wipes the bytes once the call returns.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{compose_manual_fields, ManualDraftState};
    use secrecy::ExposeSecret;

    let draft = ManualDraftState {
        label: "GitHub".to_string(),
        issuer: "github.com".to_string(),
        algorithm: Algorithm::Sha256,
        digits: 8,
        kind: AccountKindInput::Hotp,
        period_secs: 60,
        counter: 42,
        icon_hint_text: "github".to_string(),
    };
    let secret_text = "JBSWY3DPEHPK3PXP";

    let fields = compose_manual_fields(&draft, secret_text);

    assert_eq!(fields.label, "GitHub");
    assert_eq!(fields.issuer, "github.com");
    assert_eq!(fields.algorithm, Algorithm::Sha256);
    assert_eq!(fields.digits, 8);
    assert_eq!(fields.kind, AccountKindInput::Hotp);
    assert_eq!(fields.period_secs, 60);
    assert_eq!(fields.counter, 42);
    assert_eq!(fields.icon_hint_text, "github");
    assert_eq!(fields.secret.expose_secret(), secret_text);
}

#[test]
fn compose_manual_fields_preserves_draft_so_retry_keeps_typing() {
    // Borrowing the draft keeps the dialog state intact so a retry
    // after a failed worker (e.g. `save_not_committed`) does not
    // wipe the user's typing. Mirror of the `SubmitProceed` arm in
    // `apply_msg`, which only clears the secret-bearing buffers —
    // the non-secret manual draft persists until the controller
    // itself is dropped.
    use paladin_core::{AccountKindInput, Algorithm};
    use paladin_gtk::add_account::{compose_manual_fields, ManualDraftState};

    let draft = ManualDraftState {
        label: "Acme".to_string(),
        issuer: "issuer".to_string(),
        algorithm: Algorithm::Sha512,
        digits: 7,
        kind: AccountKindInput::Totp,
        period_secs: 45,
        counter: 99,
        icon_hint_text: "slack".to_string(),
    };
    let before = draft.clone();

    let _fields = compose_manual_fields(&draft, "JBSWY3DPEHPK3PXP");

    assert_eq!(
        draft, before,
        "compose_manual_fields must not mutate the draft"
    );
}

#[test]
fn compose_manual_fields_with_empty_secret_yields_empty_secret_string() {
    // Empty secret text is the live state at the moment the dialog
    // opens. `compose_manual_fields` must not synthesize any bytes
    // — `validate_manual` at submit time owns the empty-secret
    // rejection path, so the composer threads through the empty
    // buffer untouched.
    use paladin_gtk::add_account::{compose_manual_fields, ManualDraftState};
    use secrecy::ExposeSecret;

    let draft = ManualDraftState::default();

    let fields = compose_manual_fields(&draft, "");

    assert_eq!(fields.secret.expose_secret(), "");
}

#[test]
fn compose_manual_fields_threads_through_classify_manual_submit_proceed() {
    // End-to-end: the composed `ManualFields` from the dialog's
    // default state plus a valid Base32 secret must drive
    // `classify_manual_submit` to `Proceed`. Pins the contract
    // that the composer's output is shape-compatible with the
    // existing submit pipeline so the widget can chain
    // `compose_manual_fields → classify_manual_submit` without
    // an intermediate re-pack.
    use paladin_gtk::add_account::{
        classify_manual_submit, compose_manual_fields, ManualDraftState, ManualSubmitOutcome,
    };

    let draft = ManualDraftState {
        label: "alice".to_string(),
        ..ManualDraftState::default()
    };

    let fields = compose_manual_fields(&draft, SECRET_20_B32);
    let outcome = classify_manual_submit(fields, now_for_tests());

    assert!(
        matches!(outcome, ManualSubmitOutcome::Proceed(_)),
        "default draft + valid secret should classify as Proceed",
    );
}

#[test]
fn compose_manual_submit_outcome_with_valid_state_proceeds() {
    // The widget Save handler chains
    // `compose_manual_fields → classify_manual_submit` against the
    // live `AddDialogState`. With a non-empty label shadowed into
    // the manual draft and a valid Base32 secret in
    // `secret_state.manual_secret`, the chained call must classify
    // as `Proceed` so the widget can hand the validated account to
    // `Vault::find_duplicate` next.
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_submit_outcome, AddAccountMsg, AddDialogState,
        ManualSubmitOutcome,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );

    let outcome = compose_manual_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, ManualSubmitOutcome::Proceed(_)),
        "valid label + secret should chain through to Proceed",
    );
}

#[test]
fn compose_manual_submit_outcome_with_default_state_rejects_inline() {
    // The freshly-opened dialog has an empty label / empty secret.
    // `validate_manual` rejects on the `label` field; the chained
    // call must surface the typed inline error rather than the
    // `Proceed` path so the widget can render the rejection
    // without mutating the vault.
    use paladin_gtk::add_account::{
        compose_manual_submit_outcome, AddDialogState, ManualSubmitOutcome,
    };

    let state = AddDialogState::new();

    let outcome = compose_manual_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, ManualSubmitOutcome::InlineError(_)),
        "default state has no label / secret and must reject inline",
    );
}

#[test]
fn compose_manual_submit_outcome_reads_secret_state_manual_secret_text() {
    // The helper must source the secret from
    // `secret_state.manual_secret.text()` — *not* from a stray
    // reuse of the URI buffer — so the manual sub-path stays
    // isolated from the URI sub-path's text. Drive the
    // `ManualSecretChanged` shadow, leave the URI buffer empty,
    // and assert that the chained call still proceeds.
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_submit_outcome, AddAccountMsg, AddDialogState,
        ManualSubmitOutcome,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );
    assert!(
        state.secret_state().uri_text.is_empty(),
        "URI buffer must stay empty for this scenario",
    );

    let outcome = compose_manual_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, ManualSubmitOutcome::Proceed(_)),
        "helper must source the secret from secret_state.manual_secret, not uri_text",
    );
}

#[test]
fn compose_manual_submit_outcome_preserves_state_so_retry_keeps_typing() {
    // The helper borrows the state so the dialog can re-call it on
    // every Save click after a typed-but-inline-rejected attempt —
    // the user fixes the failing field, re-submits, and the prior
    // typing is still live. Mirror of
    // `compose_manual_fields_preserves_draft_so_retry_keeps_typing`
    // at the chained-call layer.
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_submit_outcome, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );
    let draft_before = state.manual_draft().clone();
    let secret_before = state.secret_state().manual_secret.text().to_string();

    let _outcome = compose_manual_submit_outcome(&state, now_for_tests());

    assert_eq!(state.manual_draft(), &draft_before);
    assert_eq!(state.secret_state().manual_secret.text(), secret_before);
}

#[test]
fn compose_uri_submit_outcome_with_valid_uri_proceeds() {
    // Parallel of `compose_manual_submit_outcome_with_valid_state_proceeds`
    // on the URI sub-path. With a valid `otpauth://` URI shadowed
    // into `secret_state.uri_text`, the chained call must classify
    // as `Proceed` so the widget can hand the validated account to
    // `Vault::find_duplicate` next.
    use paladin_gtk::add_account::{apply_msg, compose_uri_submit_outcome, AddAccountMsg};
    use paladin_gtk::otpauth_uri_paste::UriSubmitOutcome;

    let mut state = paladin_gtk::add_account::AddDialogState::new();
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    let outcome = compose_uri_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, UriSubmitOutcome::Proceed(_)),
        "valid otpauth URI in secret_state.uri_text should chain through to Proceed",
    );
}

#[test]
fn compose_uri_submit_outcome_with_default_state_rejects_inline() {
    // The freshly-opened dialog has an empty `uri_text`. The
    // chained call must surface the typed inline error rather than
    // the `Proceed` path so the widget can render the rejection
    // without mutating the vault.
    use paladin_gtk::add_account::{compose_uri_submit_outcome, AddDialogState};
    use paladin_gtk::otpauth_uri_paste::UriSubmitOutcome;

    let state = AddDialogState::new();

    let outcome = compose_uri_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, UriSubmitOutcome::InlineError(_)),
        "default state has no URI and must reject inline",
    );
}

#[test]
fn compose_uri_submit_outcome_reads_secret_state_uri_text() {
    // The helper must source the URI from
    // `secret_state.uri_text.text()` — *not* from a stray reuse of
    // the manual-secret buffer — so the URI sub-path stays isolated
    // from the manual sub-path's text. Drive `UriTextChanged`,
    // leave the manual_secret buffer empty, and assert that the
    // chained call still proceeds.
    use paladin_gtk::add_account::{apply_msg, compose_uri_submit_outcome, AddAccountMsg};
    use paladin_gtk::otpauth_uri_paste::UriSubmitOutcome;

    let mut state = paladin_gtk::add_account::AddDialogState::new();
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));
    assert!(
        state.secret_state().manual_secret.is_empty(),
        "manual_secret buffer must stay empty for this scenario",
    );

    let outcome = compose_uri_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, UriSubmitOutcome::Proceed(_)),
        "helper must source the URI from secret_state.uri_text, not manual_secret",
    );
}

#[test]
fn compose_uri_submit_outcome_preserves_state_so_retry_keeps_typing() {
    // The helper borrows the state so the dialog can re-call it on
    // every Save click after a typed-but-inline-rejected attempt —
    // the user fixes the malformed URI, re-submits, and the prior
    // typing is still live. Mirror of
    // `compose_manual_submit_outcome_preserves_state_so_retry_keeps_typing`
    // on the URI sub-path.
    use paladin_gtk::add_account::{apply_msg, compose_uri_submit_outcome, AddAccountMsg};

    let mut state = paladin_gtk::add_account::AddDialogState::new();
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri.clone()));
    let uri_before = state.secret_state().uri_text.text().to_string();

    let _outcome = compose_uri_submit_outcome(&state, now_for_tests());

    assert_eq!(state.secret_state().uri_text.text(), uri_before);
    assert_eq!(uri_before, uri);
}

#[test]
fn apply_msg_confirm_add_anyway_with_no_pending_is_defensive_noop() {
    // Defensive: the widget should only dispatch ConfirmAddAnyway
    // after a `StagePendingDuplicate` parks a value. A stray dispatch
    // with no pending stays dialog-local — emit no output and leave
    // state alone — so the worker boundary cannot be entered without
    // a validated account in hand.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();

    let output = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        output.is_none(),
        "ConfirmAddAnyway with no pending must not bubble Submit up to AppModel",
    );
    assert!(
        state.secret_state().pending.is_none(),
        "pending stays empty when there was nothing to consume",
    );
}

#[test]
fn compose_submit_outcome_manual_path_with_valid_state_proceeds() {
    // The widget Save handler chains the path-aware
    // `compose_submit_outcome` against the live `AddDialogState`.
    // With `active_path == Manual` (the default), a non-empty label
    // shadowed into the manual draft, and a valid Base32 secret in
    // `secret_state.manual_secret`, the unified composer must route
    // through `compose_manual_submit_outcome` and surface `Proceed`
    // so the widget can hand the validated account to
    // `Vault::find_duplicate` next.
    use paladin_gtk::add_account::{
        apply_msg, compose_submit_outcome, AddAccountMsg, AddDialogState, SubmitOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    assert_eq!(
        state.secret_state().active_path,
        AddPath::Manual,
        "fresh state defaults to the manual sub-path",
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );

    let outcome = compose_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, SubmitOutcome::Proceed(_)),
        "manual path with valid label + secret should chain through to Proceed",
    );
}

#[test]
fn compose_submit_outcome_uri_path_with_valid_uri_proceeds() {
    // Mirror of `compose_submit_outcome_manual_path_with_valid_state_proceeds`
    // on the URI sub-path. After `SwitchPath(Uri)` the unified
    // composer must route through `compose_uri_submit_outcome` and
    // surface `Proceed` for a well-formed `otpauth://` URI.
    use paladin_gtk::add_account::{
        apply_msg, compose_submit_outcome, AddAccountMsg, AddDialogState, SubmitOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    let outcome = compose_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, SubmitOutcome::Proceed(_)),
        "URI path with valid otpauth URI should chain through to Proceed",
    );
}

#[test]
fn compose_submit_outcome_manual_path_default_state_rejects_inline() {
    // The freshly-opened dialog has an empty label / empty secret
    // and the default `active_path == Manual`. The unified composer
    // must route through `compose_manual_submit_outcome` and surface
    // the typed inline error rather than `Proceed`.
    use paladin_gtk::add_account::{compose_submit_outcome, AddDialogState, SubmitOutcome};

    let state = AddDialogState::new();

    let outcome = compose_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, SubmitOutcome::InlineError(_)),
        "default manual-path state has no label / secret and must reject inline",
    );
}

#[test]
fn compose_submit_outcome_uri_path_default_state_rejects_inline() {
    // After `SwitchPath(Uri)` the URI buffer is empty (the switch
    // wipes the leaving manual_secret buffer; the URI buffer starts
    // empty too). The unified composer must route through
    // `compose_uri_submit_outcome` and surface the typed inline
    // error rather than `Proceed`.
    use paladin_gtk::add_account::{
        apply_msg, compose_submit_outcome, AddAccountMsg, AddDialogState, SubmitOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    let outcome = compose_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, SubmitOutcome::InlineError(_)),
        "default URI-path state has no URI text and must reject inline",
    );
}

#[test]
fn compose_submit_outcome_routes_by_active_path_not_by_buffer_contents() {
    // Routing decision keys off `active_path`, not "which buffer
    // happens to be populated". Seed the URI buffer with a valid
    // otpauth URI but leave `active_path == Manual` (the default).
    // The unified composer must still route through the manual
    // composer — which rejects because the manual label is empty —
    // rather than peeking at the URI buffer and proceeding.
    use paladin_gtk::add_account::{
        apply_msg, compose_submit_outcome, AddAccountMsg, AddDialogState, SubmitOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    assert_eq!(state.secret_state().active_path, AddPath::Manual);
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    let outcome = compose_submit_outcome(&state, now_for_tests());

    assert!(
        matches!(outcome, SubmitOutcome::InlineError(_)),
        "active_path == Manual must drive routing; a populated URI buffer is irrelevant",
    );
}

#[test]
fn compose_submit_outcome_preserves_state_so_retry_keeps_typing() {
    // The helper borrows the state so the dialog can re-call it on
    // every Save click after a typed-but-inline-rejected attempt —
    // the user fixes the failing field, re-submits, and the prior
    // typing is still live. Mirror of
    // `compose_manual_submit_outcome_preserves_state_so_retry_keeps_typing`
    // at the unified path-aware layer.
    use paladin_gtk::add_account::{
        apply_msg, compose_submit_outcome, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );
    let draft_before = state.manual_draft().clone();
    let secret_before = state.secret_state().manual_secret.text().to_string();
    let active_path_before = state.secret_state().active_path;

    let _outcome = compose_submit_outcome(&state, now_for_tests());

    assert_eq!(state.manual_draft(), &draft_before);
    assert_eq!(state.secret_state().manual_secret.text(), secret_before);
    assert_eq!(state.secret_state().active_path, active_path_before);
}

#[test]
fn compose_save_click_outcome_manual_proceeds_when_no_duplicate() {
    // The Save handler chains `compose_submit_outcome` and
    // `classify_duplicate` against the live `(AddDialogState, Vault)`.
    // With a valid manual draft and an *empty* vault (no
    // collision), the unified composer must surface `Proceed` so
    // the widget can dispatch `AddAccountMsg::SubmitProceed`.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_click_outcome, AddAccountMsg, AddDialogState, SaveClickOutcome,
    };

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("Acme".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );

    let outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    match outcome {
        SaveClickOutcome::Proceed(validated) => {
            assert_eq!(validated.account.label(), "alice");
            assert_eq!(validated.account.issuer(), Some("Acme"));
        }
        other => panic!("expected Proceed against an empty vault, got {other:?}"),
    }
}

#[test]
fn compose_save_click_outcome_manual_await_confirmation_on_duplicate() {
    // The Save handler chains `compose_submit_outcome` and
    // `classify_duplicate` against the live `(AddDialogState, Vault)`.
    // With a valid manual draft whose `(secret, issuer, label)`
    // triple matches an existing account in the vault, the unified
    // composer must surface `AwaitConfirmation` carrying the
    // existing summary plus the pending validated account so the
    // widget can dispatch `AddAccountMsg::StagePendingDuplicate`.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_click_outcome, AddAccountMsg, AddDialogState, SaveClickOutcome,
    };

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let existing = validate_manual_totp("alice", Some("Acme"));
    let existing_id = existing.account.id();
    vault.add(existing.account);
    vault.save(&store).expect("seed pre-existing duplicate");

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("Acme".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );

    let outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    match outcome {
        SaveClickOutcome::AwaitConfirmation {
            existing,
            validated,
        } => {
            assert_eq!(
                existing.id, existing_id,
                "existing summary must point at the seeded duplicate",
            );
            assert_eq!(existing.label, "alice");
            assert_eq!(existing.issuer.as_deref(), Some("Acme"));
            assert_eq!(validated.account.label(), "alice");
            assert_eq!(validated.account.issuer(), Some("Acme"));
        }
        other => panic!("expected AwaitConfirmation for a duplicate row, got {other:?}"),
    }
}

#[test]
fn compose_save_click_outcome_inline_error_short_circuits_before_duplicate_check() {
    // The freshly-opened dialog has an empty label / empty secret
    // and the default `active_path == Manual`. The unified Save-
    // click composer must surface the typed inline error from
    // `compose_submit_outcome` without ever consulting
    // `Vault::find_duplicate` — a vault with a matching seeded
    // account would still reject inline because the validation
    // pipeline rejects first.
    use paladin_gtk::add_account::{compose_save_click_outcome, AddDialogState, SaveClickOutcome};

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let seeded = validate_manual_totp("alice", Some("Acme"));
    vault.add(seeded.account);
    vault.save(&store).expect("seed vault");

    let state = AddDialogState::new();

    let outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    assert!(
        matches!(outcome, SaveClickOutcome::InlineError(_)),
        "default state must reject inline before any duplicate check",
    );
}

#[test]
fn compose_save_click_outcome_uri_path_proceeds_when_no_duplicate() {
    // Mirror of the manual `proceeds_when_no_duplicate` case on the
    // URI sub-path. After `SwitchPath(Uri)` and a well-formed
    // `otpauth://` URI, the unified composer must route through
    // `compose_uri_submit_outcome` and surface `Proceed` against an
    // empty vault.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_click_outcome, AddAccountMsg, AddDialogState, SaveClickOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    let outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    match outcome {
        SaveClickOutcome::Proceed(validated) => {
            assert_eq!(validated.account.label(), "alice");
            assert_eq!(validated.account.issuer(), Some("Acme"));
        }
        other => panic!("expected URI-path Proceed against empty vault, got {other:?}"),
    }
}

#[test]
fn compose_save_click_outcome_uri_path_await_confirmation_on_duplicate() {
    // Mirror of `manual_await_confirmation_on_duplicate` on the URI
    // sub-path. The URI's parsed `(secret, issuer, label)` triple
    // collides with the seeded account; the unified composer must
    // route through `compose_uri_submit_outcome` and surface
    // `AwaitConfirmation`.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_click_outcome, AddAccountMsg, AddDialogState, SaveClickOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);
    let existing = validate_manual_totp("alice", Some("Acme"));
    let existing_id = existing.account.id();
    vault.add(existing.account);
    vault.save(&store).expect("seed pre-existing duplicate");

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    let outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    match outcome {
        SaveClickOutcome::AwaitConfirmation {
            existing,
            validated,
        } => {
            assert_eq!(existing.id, existing_id);
            assert_eq!(validated.account.label(), "alice");
            assert_eq!(validated.account.issuer(), Some("Acme"));
        }
        other => panic!("expected URI-path AwaitConfirmation for a duplicate row, got {other:?}"),
    }
}

#[test]
fn compose_save_click_outcome_routes_by_active_path_not_by_buffer_contents() {
    // Routing decision keys off `active_path`, not "which buffer
    // happens to be populated". Seed the URI buffer with a valid
    // otpauth URI but leave `active_path == Manual` (the default).
    // The unified Save-click composer must still route through the
    // manual composer — which rejects because the manual label is
    // empty — rather than peeking at the URI buffer and proceeding.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_click_outcome, AddAccountMsg, AddDialogState, SaveClickOutcome,
    };
    use paladin_gtk::secret_fields::AddPath;

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let mut state = AddDialogState::new();
    assert_eq!(state.secret_state().active_path, AddPath::Manual);
    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    let outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    assert!(
        matches!(outcome, SaveClickOutcome::InlineError(_)),
        "active_path == Manual must drive routing; a populated URI buffer is irrelevant",
    );
}

#[test]
fn compose_save_click_outcome_preserves_state_so_retry_keeps_typing() {
    // The helper borrows the state so the dialog can re-call it on
    // every Save click after a typed-but-inline-rejected attempt —
    // the user fixes the failing field, re-submits, and the prior
    // typing is still live. Mirror of
    // `compose_submit_outcome_preserves_state_so_retry_keeps_typing`
    // extended to cover the chained duplicate-detection layer.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_click_outcome, AddAccountMsg, AddDialogState,
    };

    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );
    let draft_before = state.manual_draft().clone();
    let secret_before = state.secret_state().manual_secret.text().to_string();
    let active_path_before = state.secret_state().active_path;

    let _outcome = compose_save_click_outcome(&state, &vault, now_for_tests());

    assert_eq!(state.manual_draft(), &draft_before);
    assert_eq!(state.secret_state().manual_secret.text(), secret_before);
    assert_eq!(state.secret_state().active_path, active_path_before);
}

#[test]
fn add_dialog_state_new_inline_error_is_none() {
    // A freshly-opened dialog has no Save-click outcome to render
    // yet, so the inline-error slot starts empty. Mirror of
    // `add_dialog_state_new_initializes_manual_draft_to_defaults`
    // on the inline-error slot.
    use paladin_gtk::add_account::AddDialogState;

    let state = AddDialogState::new();
    assert!(
        state.inline_error().is_none(),
        "fresh AddDialogState has no inline error to render",
    );
}

#[test]
fn add_dialog_state_default_inline_error_matches_new() {
    // The implicit `Default` impl must construct the same inline-
    // error slot the named `new()` constructor does. Mirror of
    // `add_dialog_state_default_manual_draft_matches_new`.
    use paladin_gtk::add_account::AddDialogState;

    let from_new = AddDialogState::new();
    let from_default = AddDialogState::default();
    assert_eq!(
        from_new.inline_error().is_none(),
        from_default.inline_error().is_none(),
    );
}

#[test]
fn apply_msg_render_inline_error_stores_in_state() {
    // The widget computes `compose_save_click_outcome` on every Save
    // click; on `SaveClickOutcome::InlineError` it dispatches
    // `AddAccountMsg::RenderInlineError` so the dialog body can
    // render the typed §5 error against the failing field. The
    // routing layer stays in `apply_msg` so the rendering side is
    // exercisable without GTK.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let mut state = AddDialogState::new();

    let output = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err.clone()));

    assert!(
        output.is_none(),
        "RenderInlineError stays dialog-local; no AddAccountOutput escapes",
    );
    let stored = state
        .inline_error()
        .expect("RenderInlineError stores the projection into AddDialogState");
    assert_eq!(stored.kind, err.kind);
    assert_eq!(stored.rendered, err.rendered);
}

#[test]
fn apply_msg_render_inline_error_replaces_prior() {
    // A second Save click after a typed-but-rejected attempt
    // overwrites the prior projection so the dialog never shows
    // stale text from a previous click. Mirror of the rename
    // dialog's `last_validation`-replaces-prior semantics.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let first = InlineError::from_error(&validation_error("label", "empty"));
    let second = InlineError::from_error(&validation_error("secret", "bad base32"));
    let mut state = AddDialogState::new();

    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(first));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(second.clone()));

    let stored = state
        .inline_error()
        .expect("second RenderInlineError still leaves a projection in state");
    assert_eq!(
        stored.kind, second.kind,
        "later RenderInlineError replaces the prior projection",
    );
    assert_eq!(stored.rendered, second.rendered);
}

#[test]
fn save_click_outcome_to_msg_proceed_returns_submit_proceed() {
    // The widget computes `compose_save_click_outcome` on every
    // Save click and routes the result through this dispatch
    // helper to keep the per-variant `AddAccountMsg` construction
    // a one-shot match rather than scattered through the widget
    // body. `SaveClickOutcome::Proceed(validated)` must map to
    // `AddAccountMsg::SubmitProceed { account: validated.account }`
    // — the `warnings` are dropped on this arm because the dialog
    // dismisses on success and the post-save toast renders the
    // validation warnings via
    // `paladin_core::format_validation_warning` off the
    // `AddAccountOutput::Submit` boundary instead.
    use paladin_gtk::add_account::{save_click_outcome_to_msg, AddAccountMsg, SaveClickOutcome};

    let validated = validate_manual_totp("alice", Some("Acme"));
    let expected_id = validated.account.id();
    let expected_label = validated.account.label().to_string();

    let msg = save_click_outcome_to_msg(SaveClickOutcome::Proceed(validated));

    match msg {
        AddAccountMsg::SubmitProceed { account } => {
            assert_eq!(
                account.id(),
                expected_id,
                "dispatch helper threads the validated id without re-stamping",
            );
            assert_eq!(
                account.label(),
                expected_label,
                "dispatch helper threads the validated label byte-for-byte",
            );
        }
        other => panic!("expected SubmitProceed, got {other:?}"),
    }
}

#[test]
fn save_click_outcome_to_msg_await_confirmation_returns_stage_pending_duplicate() {
    // `SaveClickOutcome::AwaitConfirmation { existing, validated }`
    // must map to `AddAccountMsg::StagePendingDuplicate { account,
    // warnings, existing }` so both halves of the duplicate-
    // collision projection (`pending` + `pending_duplicate_existing`)
    // land in state via the existing apply_msg arm.
    use paladin_gtk::add_account::{save_click_outcome_to_msg, AddAccountMsg, SaveClickOutcome};

    let validated = validate_manual_totp("alice", Some("Acme"));
    let warnings_clone = validated.warnings.clone();
    let expected_account_id = validated.account.id();
    let expected_account_label = validated.account.label().to_string();
    let existing = dummy_existing_summary();
    let expected_existing_id = existing.id;
    let expected_existing_label = existing.label.clone();

    let msg = save_click_outcome_to_msg(SaveClickOutcome::AwaitConfirmation {
        existing,
        validated,
    });

    match msg {
        AddAccountMsg::StagePendingDuplicate {
            account,
            warnings,
            existing,
        } => {
            assert_eq!(account.id(), expected_account_id);
            assert_eq!(account.label(), expected_account_label);
            assert_eq!(warnings, warnings_clone);
            assert_eq!(existing.id, expected_existing_id);
            assert_eq!(existing.label, expected_existing_label);
        }
        other => panic!("expected StagePendingDuplicate, got {other:?}"),
    }
}

#[test]
fn save_click_outcome_to_msg_inline_error_returns_render_inline_error() {
    // `SaveClickOutcome::InlineError(err)` must map to
    // `AddAccountMsg::RenderInlineError(err)` so the typed §5
    // body lands in `AddDialogState::inline_error` via the existing
    // apply_msg arm.
    use paladin_gtk::add_account::{save_click_outcome_to_msg, AddAccountMsg, SaveClickOutcome};

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let expected_kind = err.kind;
    let expected_rendered = err.rendered.clone();

    let msg = save_click_outcome_to_msg(SaveClickOutcome::InlineError(err));

    match msg {
        AddAccountMsg::RenderInlineError(stored) => {
            assert_eq!(stored.kind, expected_kind);
            assert_eq!(stored.rendered, expected_rendered);
        }
        other => panic!("expected RenderInlineError, got {other:?}"),
    }
}

#[test]
fn apply_msg_cancel_drains_pending_duplicate_existing() {
    // Cancel drops the entire dialog state via
    // `secret_state.clear_for(ClearReason::Cancel)` — that already
    // drains `pending`. The paired colliding-summary slot must
    // drop with it so a follow-up open does not render a stale
    // existing summary against a fresh empty `pending`.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        state.pending_duplicate_existing().is_some(),
        "precondition: colliding summary parked before Cancel",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::Cancel);

    assert!(
        state.pending_duplicate_existing().is_none(),
        "Cancel drains pending_duplicate_existing alongside the pending slot",
    );
}

#[test]
fn apply_msg_switch_path_drains_pending_duplicate_existing() {
    // SwitchPath drops the pending duplicate via
    // `secret_state.switch_path`. The paired colliding-summary
    // slot must drop with it on every actual transition.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(state.pending_duplicate_existing().is_some(), "precondition");

    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    assert!(
        state.pending_duplicate_existing().is_none(),
        "SwitchPath drains pending_duplicate_existing alongside the pending slot",
    );
}

#[test]
fn apply_msg_switch_path_same_path_does_not_drain_pending_duplicate_existing() {
    // Same-path SwitchPath is an idempotent no-op — the pending /
    // colliding-summary state survives. Symmetric with
    // `apply_msg_switch_path_same_path_does_not_clear_inline_error`
    // on the colliding-summary slot.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let existing = dummy_existing_summary();
    let expected_id = existing.id;
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing,
        },
    );

    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Manual));

    let stored = state
        .pending_duplicate_existing()
        .expect("same-path SwitchPath is idempotent; pending_duplicate_existing survives");
    assert_eq!(stored.id, expected_id);
}

#[test]
fn apply_msg_submit_proceed_drains_pending_duplicate_existing() {
    // SubmitProceed wipes the secret-bearing buffers and the pending
    // slot via `secret_state.clear_for(ClearReason::Submit)`. The
    // paired colliding-summary slot must drop with it so a
    // follow-up open does not render a stale existing summary.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(state.pending_duplicate_existing().is_some(), "precondition");

    // SubmitProceed takes a fresh validated account (not the parked
    // one) — the typical widget flow when the user fixed something
    // and re-submitted without going through the "Add anyway"
    // prompt.
    let fresh = validate_manual_totp("alice", Some("Acme"));
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: fresh.account,
        },
    );

    assert!(
        state.pending_duplicate_existing().is_none(),
        "SubmitProceed drains pending_duplicate_existing alongside the pending slot",
    );
}

#[test]
fn apply_msg_confirm_add_anyway_drains_pending_duplicate_existing() {
    // ConfirmAddAnyway consumes the pending via `consume_pending`
    // and forwards `AddAccountOutput::Submit`. The paired
    // colliding-summary slot must drop with it so the post-confirm
    // state has neither half of the duplicate-collision projection.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(state.pending_duplicate_existing().is_some(), "precondition");

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        state.pending_duplicate_existing().is_none(),
        "ConfirmAddAnyway drains pending_duplicate_existing alongside the pending slot",
    );
}

#[test]
fn apply_msg_stage_pending_duplicate_stores_existing_summary() {
    // The widget dispatches `StagePendingDuplicate` after
    // `SaveClickOutcome::AwaitConfirmation` returned the colliding
    // existing summary alongside the pending validated account.
    // Both halves must land in state so the "Add anyway?" prompt
    // can render the colliding account's display label / issuer
    // alongside the pending validated account in
    // `secret_state.pending`. Mirror of
    // `apply_msg_render_inline_error_stores_in_state` on the
    // duplicate-collision slot.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let existing = dummy_existing_summary();
    let expected_existing_id = existing.id;
    let expected_existing_label = existing.label.clone();
    let expected_existing_issuer = existing.issuer.clone();

    let output = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing,
        },
    );

    assert!(
        output.is_none(),
        "StagePendingDuplicate is dialog-local; no output flows to AppModel",
    );
    let stored = state
        .pending_duplicate_existing()
        .expect("StagePendingDuplicate populates the colliding-summary slot");
    assert_eq!(stored.id, expected_existing_id);
    assert_eq!(stored.label, expected_existing_label);
    assert_eq!(stored.issuer, expected_existing_issuer);
}

#[test]
fn add_dialog_state_new_pending_duplicate_existing_is_none() {
    // A freshly-opened dialog has not yet seen a Save click that
    // observed a duplicate collision, so the
    // `pending_duplicate_existing` slot starts empty. Mirror of
    // `add_dialog_state_new_inline_error_is_none` on the
    // duplicate-collision slot.
    use paladin_gtk::add_account::AddDialogState;

    let state = AddDialogState::new();
    assert!(
        state.pending_duplicate_existing().is_none(),
        "fresh AddDialogState has no colliding summary to render",
    );
}

#[test]
fn add_dialog_state_default_pending_duplicate_existing_matches_new() {
    // The implicit `Default` impl must initialize the same empty
    // slot the named `new()` constructor does. Mirror of
    // `add_dialog_state_default_inline_error_matches_new` on the
    // duplicate-collision slot.
    use paladin_gtk::add_account::AddDialogState;

    let from_new = AddDialogState::new();
    let from_default = AddDialogState::default();
    assert_eq!(
        from_new.pending_duplicate_existing().is_none(),
        from_default.pending_duplicate_existing().is_none(),
    );
}

#[test]
fn apply_msg_submit_proceed_clears_prior_inline_error() {
    // The widget only dispatches `SubmitProceed` once
    // `compose_save_click_outcome` returned a non-collision
    // `Proceed(ValidatedAccount)` — by definition the validation
    // pipeline succeeded, so any prior inline_error from an earlier
    // rejected Save click is stale. Defensive clearing keeps the
    // dialog body from rendering stale text alongside the live
    // worker attempt. Symmetric with the prior-worker-outcome
    // clearing already wired into this arm.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let validated = validate_manual_totp("alice", Some("Acme"));
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );

    assert!(
        state.inline_error().is_none(),
        "SubmitProceed clears the stale inline_error before the worker spawns",
    );
}

#[test]
fn apply_msg_stage_pending_duplicate_clears_prior_inline_error() {
    // `StagePendingDuplicate` arrives after `classify_duplicate`
    // returned `AwaitConfirmation` — meaning validation already
    // succeeded (the pending account is validated) and the
    // duplicate-detection pipeline ran. Any prior inline_error
    // staged by an earlier validation failure is therefore stale —
    // drop it so the "Add anyway?" prompt renders cleanly without
    // a stale validation rejection bleeding through.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("fixture: expected AwaitConfirmation");
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert!(
        state.inline_error().is_none(),
        "StagePendingDuplicate clears the stale inline_error so the duplicate prompt renders cleanly",
    );
}

#[test]
fn apply_msg_confirm_add_anyway_clears_prior_inline_error() {
    // `ConfirmAddAnyway` consumes the parked pending duplicate and
    // forwards `AddAccountOutput::Submit`. By construction the
    // pending was staged after a validation pass, so any prior
    // inline_error is stale — drop it defensively before the
    // submit boundary. Symmetric with the worker-outcome clearing
    // already wired into this arm.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    // Stage a pending duplicate first so ConfirmAddAnyway has
    // something to consume; otherwise the arm is a defensive no-op.
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let DuplicateOutcome::AwaitConfirmation {
        existing: _,
        validated,
    } = classify_duplicate(validated, Some(dummy_existing_summary()))
    else {
        panic!("fixture: expected AwaitConfirmation");
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    // Restage an inline error after StagePendingDuplicate (which
    // would itself clear inline_error) to set the precondition for
    // this test cleanly.
    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        state.inline_error().is_none(),
        "ConfirmAddAnyway clears the stale inline_error before the worker spawns",
    );
}

#[test]
fn apply_msg_manual_label_changed_clears_prior_inline_error() {
    // Retyping the manual label after a Save click rejected it
    // (e.g. `field: "label"` from validate_manual) means the prior
    // rejection is no longer applicable to the live buffer — drop
    // the inline error. Mirror of
    // `apply_msg_manual_secret_changed_clears_prior_inline_error`
    // on the non-secret label field.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );

    assert!(
        state.inline_error().is_none(),
        "ManualLabelChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_issuer_changed_clears_prior_inline_error() {
    // Retyping the issuer after a Save click rejected it (e.g. a
    // `field: "issuer"` defensive rejection from
    // `validate_manual`'s issuer-length cross-check) means the
    // rejection is no longer applicable to the live buffer.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("issuer", "too long"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIssuerChanged("Acme".to_string()),
    );

    assert!(
        state.inline_error().is_none(),
        "ManualIssuerChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_algorithm_changed_clears_prior_inline_error() {
    // Selecting a different algorithm after a Save click rejection
    // means the user is editing the form — drop the stale inline
    // error so the dialog body stops rendering it.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualAlgorithmChanged(Algorithm::Sha256),
    );

    assert!(
        state.inline_error().is_none(),
        "ManualAlgorithmChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_digits_changed_clears_prior_inline_error() {
    // Bumping the digit count after a Save click rejection (e.g.
    // `field: "digits"` if a test driver slipped an out-of-range
    // value through) means the user is editing — drop the stale
    // inline error.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("digits", "out of range"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(&mut state, AddAccountMsg::ManualDigitsChanged(8));

    assert!(
        state.inline_error().is_none(),
        "ManualDigitsChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_kind_changed_clears_prior_inline_error() {
    // Toggling TOTP / HOTP after a Save click rejection means the
    // user is editing — drop the stale inline error. Kind-cross-
    // check rejections (e.g. a HOTP-without-counter case slipped
    // through) become especially stale when the kind itself
    // changes.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("counter", "required for HOTP"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );

    assert!(
        state.inline_error().is_none(),
        "ManualKindChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_period_changed_clears_prior_inline_error() {
    // Tweaking the TOTP period after a Save click rejection (e.g.
    // `field: "period_secs"` if a test driver slipped an
    // out-of-range value through) means the user is editing — drop
    // the stale inline error.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("period_secs", "out of range"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(&mut state, AddAccountMsg::ManualPeriodChanged(60));

    assert!(
        state.inline_error().is_none(),
        "ManualPeriodChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_counter_changed_clears_prior_inline_error() {
    // Tweaking the HOTP counter after a Save click rejection means
    // the user is editing — drop the stale inline error.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("counter", "invalid"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(&mut state, AddAccountMsg::ManualCounterChanged(42));

    assert!(
        state.inline_error().is_none(),
        "ManualCounterChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_icon_hint_changed_clears_prior_inline_error() {
    // Retyping the icon-hint slug after a Save click rejected it
    // (e.g. `field: "icon_hint"` from `parse_icon_hint_token`)
    // means the prior rejection is no longer applicable to the
    // live buffer — drop the inline error.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("icon_hint", "malformed slug"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualIconHintChanged("github".to_string()),
    );

    assert!(
        state.inline_error().is_none(),
        "ManualIconHintChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_manual_secret_changed_clears_prior_inline_error() {
    // Retyping the manual Base32 secret after a Save click rejected
    // it (e.g. `field: "secret"`) means the prior rejection is no
    // longer applicable to the live buffer — drop the inline error
    // so the dialog body stops rendering the stale message. Mirror
    // of `unlock_dialog_state_set_passphrase_clears_prior_inline_error`
    // on the secret-bearing add path.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("secret", "bad base32"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(
        state.inline_error().is_some(),
        "precondition: inline error is staged before retype",
    );

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );

    assert!(
        state.inline_error().is_none(),
        "ManualSecretChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_uri_text_changed_clears_prior_inline_error() {
    // Retyping the `otpauth://` URI after a Save click rejected it
    // (e.g. malformed URI, unsupported scheme) means the prior
    // rejection is no longer applicable — drop the inline error
    // so the dialog body stops rendering the stale message. Mirror
    // of `apply_msg_manual_secret_changed_clears_prior_inline_error`
    // on the URI sub-path.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("uri", "malformed"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(state.inline_error().is_some(), "precondition");

    let uri = format!("otpauth://totp/Acme:alice?secret={SECRET_20_B32}&issuer=Acme");
    let _ = apply_msg(&mut state, AddAccountMsg::UriTextChanged(uri));

    assert!(
        state.inline_error().is_none(),
        "UriTextChanged clears the stale inline_error",
    );
}

#[test]
fn apply_msg_switch_path_clears_prior_inline_error() {
    // A typed §5 rejection from `SaveClickOutcome::InlineError` is
    // always specific to the sub-path that was active when the
    // user pressed Save (manual label / secret / icon-hint, or
    // URI text). Switching sub-paths is the user's signal that
    // they're starting fresh on a different input surface — the
    // rejection from the prior path is no longer applicable.
    // Symmetric with the pending-duplicate drop already wired into
    // `secret_state.switch_path`: cross-path state must not survive
    // a switch.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(
        state.inline_error().is_some(),
        "precondition: inline error is staged before SwitchPath",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    assert!(
        state.inline_error().is_none(),
        "SwitchPath clears the prior inline_error so the new path starts fresh",
    );
}

#[test]
fn apply_msg_switch_path_same_path_does_not_clear_inline_error() {
    // Same-path re-entry is idempotent — it must not erase the
    // inline error any more than it erases the buffers. Mirror of
    // `apply_msg_switch_path_same_path_is_idempotent_noop` on the
    // inline-error slot. Guards against a regression where the
    // arm naively clears `inline_error` before the early-return
    // path checks `active_path == to`.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err.clone()));

    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Manual));

    let stored = state.inline_error().expect(
        "same-path SwitchPath is idempotent; the inline_error survives because nothing changed",
    );
    assert_eq!(stored.kind, err.kind);
    assert_eq!(stored.rendered, err.rendered);
}

#[test]
fn apply_msg_render_inline_error_preserves_other_state() {
    // The inline-error slot is independent of the manual draft, the
    // secret-bearing buffers, and the duplicate-collision pending
    // slot — a Save-click rejection must not stomp on the user's
    // typing or drop a parked pending. Mirror of the per-keystroke
    // shadow tests that preserve sibling draft fields.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("alice".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged(SECRET_20_B32.to_string()),
    );
    let draft_before = state.manual_draft().clone();
    let secret_before = state.secret_state().manual_secret.text().to_string();
    let active_path_before = state.secret_state().active_path;

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));

    assert_eq!(state.manual_draft(), &draft_before);
    assert_eq!(state.secret_state().manual_secret.text(), secret_before);
    assert_eq!(state.secret_state().active_path, active_path_before);
}

#[test]
fn format_duplicate_confirm_body_renders_issuer_colon_label() {
    // The widget binds the AdwAlertDialog body of the "Add anyway?"
    // confirmation to this helper, fed by
    // `AddDialogState::pending_duplicate_existing()`. Wording mirrors
    // the CLI's `duplicate_account` text — `"account already exists
    // with the same (secret, issuer, label): <label>"` — but omits
    // the front-end-specific action hint (the AdwAlertDialog button
    // label "Add anyway" supplies that). The carried `AccountSummary`
    // routes through the `account_row::display_label` `<issuer>:<label>`
    // projection so the colliding row's display name matches what the
    // user already sees in the account list.
    use paladin_gtk::add_account::format_duplicate_confirm_body;

    let existing = dummy_existing_summary();

    let body = format_duplicate_confirm_body(&existing);

    assert_eq!(
        body,
        "account already exists with the same (secret, issuer, label): Acme:alice",
    );
}

#[test]
fn format_duplicate_confirm_body_collapses_empty_issuer_to_bare_label() {
    // `Some("")` for the issuer collapses to the no-issuer form so
    // the body never renders a dangling `: :alice` colon — mirror of
    // the `account_row::display_label` rule pinned by
    // `display_label_collapses_empty_issuer_to_bare_label` in
    // `tests/account_row_logic.rs`. The helper must thread through
    // the same projection so the duplicate-collision prompt does not
    // diverge from the visible row label.
    use paladin_gtk::add_account::format_duplicate_confirm_body;

    let mut existing = dummy_existing_summary();
    existing.issuer = Some(String::new());

    let body = format_duplicate_confirm_body(&existing);

    assert_eq!(
        body,
        "account already exists with the same (secret, issuer, label): alice",
    );
}

#[test]
fn format_duplicate_confirm_body_renders_bare_label_when_issuer_is_none() {
    // `None` issuer renders the bare label without a leading colon —
    // mirror of the `account_row::display_label` rule pinned by
    // `display_label_renders_bare_label_when_issuer_is_none` in
    // `tests/account_row_logic.rs`. Same rationale as the empty-string
    // case above: the helper must thread through the
    // `account_row::display_label` projection so the body cannot
    // diverge from the visible row label.
    use paladin_gtk::add_account::format_duplicate_confirm_body;

    let mut existing = dummy_existing_summary();
    existing.issuer = None;

    let body = format_duplicate_confirm_body(&existing);

    assert_eq!(
        body,
        "account already exists with the same (secret, issuer, label): alice",
    );
}

#[test]
fn format_duplicate_confirm_body_omits_action_hint() {
    // The body must not embed a front-end-specific action hint —
    // the CLI's `"(re-run with --allow-duplicate to add anyway)"`
    // and the TUI's `"(press Enter to add anyway)"` are presentation
    // text owned by each front end, not the colliding-summary
    // projection. The GTK AdwAlertDialog button label "Add anyway"
    // is what supplies the action on the GUI side, so the body
    // stays neutral and can be reused regardless of which gesture
    // a future GTK theme binds to the confirm action.
    use paladin_gtk::add_account::format_duplicate_confirm_body;

    let body = format_duplicate_confirm_body(&dummy_existing_summary());

    assert!(
        !body.contains("--allow-duplicate"),
        "body must not echo the CLI's action hint: {body:?}",
    );
    assert!(
        !body.contains("press Enter"),
        "body must not echo the TUI's action hint: {body:?}",
    );
    assert!(
        !body.contains("Add anyway"),
        "body must not echo the GTK button label: {body:?}",
    );
}

#[test]
fn format_pending_warnings_body_returns_empty_string_when_no_warnings() {
    // The widget concatenates this helper's output beneath
    // `format_duplicate_confirm_body(existing)` in the "Add anyway?"
    // AdwAlertDialog body. With no warnings parked in the pending
    // `ValidatedAccount`, the helper must return an empty string so
    // the widget's `if body.is_empty() { … }` guard can skip the
    // extra body line entirely — the AdwAlertDialog body otherwise
    // renders a stray trailing newline if a "warning:" prefix lands
    // against an empty warnings slice.
    use paladin_gtk::add_account::format_pending_warnings_body;

    let body = format_pending_warnings_body(&[]);

    assert!(
        body.is_empty(),
        "empty warnings slice must collapse to an empty body so the widget can skip the line: {body:?}",
    );
}

#[test]
fn format_pending_warnings_body_renders_single_short_secret_warning() {
    // The widget binds the AdwAlertDialog body's secondary line to
    // this helper, fed by `AddDialogState::secret_state().pending`'s
    // `warnings` slice. Each `ValidationWarning` routes through
    // `paladin_core::format_validation_warning` so the wording stays
    // in sync with the CLI / TUI verbatim, then receives a
    // `"warning: "` prefix so the dialog body labels the line as a
    // warning rather than another statement of fact alongside the
    // duplicate body. Mirror of the TUI's
    // `format!("Added {display}. warning: {rendered}")` pattern in
    // `paladin-tui/src/app/reducer.rs` — the "warning: " prefix
    // tracks the same wording.
    use paladin_core::{format_validation_warning, ValidationWarning};
    use paladin_gtk::add_account::format_pending_warnings_body;

    let warnings = vec![ValidationWarning::ShortSecret {
        decoded_len: 10,
        recommended_min: 16,
    }];

    let body = format_pending_warnings_body(&warnings);

    let expected = format!("warning: {}", format_validation_warning(&warnings[0]));
    assert_eq!(body, expected);
}

#[test]
fn format_pending_warnings_body_renders_one_line_per_warning() {
    // Multiple warnings land one-per-line so the AdwAlertDialog body
    // stays readable in the multi-line modal context (in contrast
    // with the TUI status-line `; ` join, which is forced single-
    // line by the status-bar widget). Each line carries its own
    // `"warning: "` prefix so a future scan / screenshot of the
    // body cannot misread a continuation line as a fact statement.
    use paladin_core::{format_validation_warning, ValidationWarning};
    use paladin_gtk::add_account::format_pending_warnings_body;

    let warnings = vec![
        ValidationWarning::ShortSecret {
            decoded_len: 10,
            recommended_min: 16,
        },
        ValidationWarning::ShortSecret {
            decoded_len: 8,
            recommended_min: 16,
        },
    ];

    let body = format_pending_warnings_body(&warnings);

    let expected = format!(
        "warning: {}\nwarning: {}",
        format_validation_warning(&warnings[0]),
        format_validation_warning(&warnings[1]),
    );
    assert_eq!(body, expected);
}

#[test]
fn format_pending_warnings_body_threads_through_format_validation_warning() {
    // The helper must not re-render the warning body — it routes
    // through `paladin_core::format_validation_warning` so the
    // wording, decoded-length, and recommended-minimum copy stay in
    // sync with the CLI / TUI verbatim. Asserting that the rendered
    // text contains the exact `format_validation_warning` output
    // (rather than a hand-rolled substring) pins the helper to the
    // shared text projection rather than a local re-implementation.
    use paladin_core::{format_validation_warning, ValidationWarning};
    use paladin_gtk::add_account::format_pending_warnings_body;

    let warning = ValidationWarning::ShortSecret {
        decoded_len: 7,
        recommended_min: 16,
    };
    let rendered_shared = format_validation_warning(&warning);

    let body = format_pending_warnings_body(std::slice::from_ref(&warning));

    assert!(
        body.contains(&rendered_shared),
        "body must route through paladin_core::format_validation_warning verbatim: \
         body={body:?} shared_text={rendered_shared:?}",
    );
}

#[test]
fn format_duplicate_alert_body_returns_confirm_body_when_no_warnings() {
    // The widget binds the AdwAlertDialog body of the "Add anyway?"
    // confirmation to this composer, fed by both
    // `AddDialogState::pending_duplicate_existing()` and
    // `AddDialogState::secret_state().pending`'s `warnings`. With no
    // warnings parked in the pending `ValidatedAccount`, the
    // composer must produce exactly `format_duplicate_confirm_body`
    // output so the modal body matches the no-warning case verbatim
    // — adding a blank-line separator with no second line below it
    // would leave a stray trailing newline in the AdwAlertDialog
    // body. Mirror of the `format_pending_warnings_body` empty-
    // slice collapse rule applied at the composer level.
    use paladin_gtk::add_account::{format_duplicate_alert_body, format_duplicate_confirm_body};

    let existing = dummy_existing_summary();

    let body = format_duplicate_alert_body(&existing, &[]);

    assert_eq!(body, format_duplicate_confirm_body(&existing));
}

#[test]
fn format_duplicate_alert_body_joins_confirm_and_warnings_with_blank_line() {
    // With warnings parked alongside the duplicate-collision pending
    // value, the AdwAlertDialog body renders the duplicate-confirm
    // statement above a blank line above the per-warning lines.
    // The blank-line separator stops the warnings from running on
    // visually as a continuation of the duplicate body, which would
    // misread `"…label: Acme:alice\nwarning: …"` as one statement
    // — the `AdwAlertDialog` body is multi-line, but the
    // discrimination between the duplicate statement and the
    // warning lines still matters for readability.
    use paladin_core::ValidationWarning;
    use paladin_gtk::add_account::{
        format_duplicate_alert_body, format_duplicate_confirm_body, format_pending_warnings_body,
    };

    let existing = dummy_existing_summary();
    let warnings = vec![ValidationWarning::ShortSecret {
        decoded_len: 10,
        recommended_min: 16,
    }];

    let body = format_duplicate_alert_body(&existing, &warnings);

    let expected = format!(
        "{}\n\n{}",
        format_duplicate_confirm_body(&existing),
        format_pending_warnings_body(&warnings),
    );
    assert_eq!(body, expected);
}

#[test]
fn format_duplicate_alert_body_threads_through_existing_summary_projection() {
    // The composer must thread the carried `AccountSummary` through
    // `format_duplicate_confirm_body` (which itself routes through
    // `account_row::display_label`) so the colliding row's display
    // name matches what the user already sees in the account list.
    // An `issuer = None` existing renders the bare label form
    // without a leading colon — mirror of the
    // `format_duplicate_confirm_body_renders_bare_label_when_issuer_is_none`
    // rule applied at the composer level.
    use paladin_gtk::add_account::format_duplicate_alert_body;

    let mut existing = dummy_existing_summary();
    existing.issuer = None;

    let body = format_duplicate_alert_body(&existing, &[]);

    assert_eq!(
        body,
        "account already exists with the same (secret, issuer, label): alice",
    );
}

#[test]
fn add_dialog_state_new_pending_validation_warnings_is_empty() {
    // A freshly-opened dialog has not yet seen a `StagePendingDuplicate`
    // dispatch, so `secret_state.pending` is `None` and the
    // accessor must return an empty slice (not panic, not allocate).
    // Mirror of `add_dialog_state_new_pending_duplicate_existing_is_none`
    // on the warnings-projection side: the widget binds a
    // `#[watch]` over the slice to feed `format_pending_warnings_body`,
    // which collapses an empty slice to the empty string so the
    // duplicate-confirm modal body does not render a stray
    // `"warning:"` line out of the gate.
    use paladin_gtk::add_account::AddDialogState;

    let state = AddDialogState::new();

    assert!(
        state.pending_validation_warnings().is_empty(),
        "fresh dialog has no pending → no warnings: {:?}",
        state.pending_validation_warnings(),
    );
}

#[test]
fn apply_msg_stage_pending_duplicate_exposes_warnings_via_pending_validation_warnings() {
    // After `StagePendingDuplicate` parks the validated account
    // alongside its non-fatal `ValidationWarning`s, the accessor
    // must return those same warnings so the widget can feed them
    // into `format_pending_warnings_body` /
    // `format_duplicate_alert_body` without reaching across the
    // `secret_state` boundary. The fixture seeds a short-secret
    // input so `validate_manual` emits a `ValidationWarning::ShortSecret`,
    // which is the only non-fatal warning currently produced — the
    // accessor must thread the slice verbatim.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddDialogState};

    let mut state = AddDialogState::new();
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from(SHORT_SECRET_B32.to_string());
    let validated = match classify_manual_submit(fields, now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    assert!(
        !validated.warnings.is_empty(),
        "fixture precondition: short-secret input emits ShortSecret warning",
    );
    let expected_warnings = validated.warnings.clone();

    let output = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert!(
        output.is_none(),
        "StagePendingDuplicate is dialog-local; no output flows to AppModel",
    );
    assert_eq!(
        state.pending_validation_warnings(),
        expected_warnings.as_slice(),
        "pending_validation_warnings exposes the warnings staged alongside the pending validated account",
    );
}

#[test]
fn apply_msg_confirm_add_anyway_drains_pending_validation_warnings() {
    // ConfirmAddAnyway consumes the pending validated account out
    // of `secret_state.pending`, so the warnings-projection must
    // drain to an empty slice in lockstep with the duplicate-
    // confirm modal closing. Mirror of
    // `apply_msg_confirm_add_anyway_drains_pending_duplicate_existing`
    // on the warnings-projection side: both halves of the
    // duplicate-confirm projection drain together once the user
    // confirms past the prompt.
    use paladin_gtk::add_account::{apply_msg, AddAccountMsg, AddAccountOutput, AddDialogState};

    let mut state = AddDialogState::new();
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from(SHORT_SECRET_B32.to_string());
    let validated = match classify_manual_submit(fields, now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let staged = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        staged.is_none(),
        "precondition: StagePendingDuplicate is dialog-local"
    );
    assert!(
        !state.pending_validation_warnings().is_empty(),
        "precondition: pending warnings staged",
    );

    let confirmed = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        matches!(confirmed, Some(AddAccountOutput::Submit { .. })),
        "ConfirmAddAnyway forwards Submit when a pending is parked: {confirmed:?}",
    );
    assert!(
        state.pending_validation_warnings().is_empty(),
        "ConfirmAddAnyway drains pending_validation_warnings alongside the pending slot",
    );
}

#[test]
fn format_duplicate_alert_body_threads_through_pending_warnings_projection() {
    // The composer must thread the carried warnings through
    // `format_pending_warnings_body` so each line carries its own
    // `"warning: "` prefix and the multi-warning case lays out one
    // per line — mirror of the `format_pending_warnings_body_renders_one_line_per_warning`
    // rule applied at the composer level. Asserting the full
    // `\n\n`-joined render against the two underlying helpers pins
    // the composer to the shared projections rather than a local
    // re-implementation that could drift.
    use paladin_core::ValidationWarning;
    use paladin_gtk::add_account::{
        format_duplicate_alert_body, format_duplicate_confirm_body, format_pending_warnings_body,
    };

    let existing = dummy_existing_summary();
    let warnings = vec![
        ValidationWarning::ShortSecret {
            decoded_len: 10,
            recommended_min: 16,
        },
        ValidationWarning::ShortSecret {
            decoded_len: 8,
            recommended_min: 16,
        },
    ];

    let body = format_duplicate_alert_body(&existing, &warnings);

    let expected_top = format_duplicate_confirm_body(&existing);
    let expected_bottom = format_pending_warnings_body(&warnings);
    assert_eq!(body, format!("{expected_top}\n\n{expected_bottom}"));
}

#[test]
fn compose_pending_duplicate_alert_body_with_no_pending_returns_none() {
    // A freshly-opened dialog has not yet seen a duplicate-collision
    // Save click, so the state-driven composer must collapse to
    // `None` — the widget binds a `#[watch]` over the projection so
    // an `AdwAlertDialog` body is only rendered while a pending
    // collision is staged. Mirror of
    // `add_dialog_state_new_pending_duplicate_existing_is_none` on
    // the alert-body projection side.
    use paladin_gtk::add_account::{compose_pending_duplicate_alert_body, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_pending_duplicate_alert_body(&state).is_none(),
        "fresh dialog has no pending duplicate → no alert body",
    );
}

#[test]
fn compose_pending_duplicate_alert_body_with_staged_pending_returns_formatted_body() {
    // After `StagePendingDuplicate` parks the colliding existing
    // summary and the pending validated account, the composer must
    // return `Some(format_duplicate_alert_body(existing, warnings))`
    // — the widget binds a `#[watch]` over the projection so the
    // `AdwAlertDialog` body matches the dialog state without the
    // widget reaching across both `pending_duplicate_existing()` and
    // `pending_validation_warnings()` separately.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_body, format_duplicate_alert_body,
        AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let mut fields = manual_totp_defaults();
    fields.secret = SecretString::from(SHORT_SECRET_B32.to_string());
    let validated = match classify_manual_submit(fields, now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let existing = dummy_existing_summary();
    let expected_body = format_duplicate_alert_body(&existing, validated.warnings.as_slice());

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing,
        },
    );

    assert_eq!(
        compose_pending_duplicate_alert_body(&state).as_deref(),
        Some(expected_body.as_str()),
        "staged pending → composer renders the full alert body",
    );
}

#[test]
fn compose_pending_duplicate_alert_body_drains_after_confirm_add_anyway() {
    // ConfirmAddAnyway consumes the pending validated account and
    // drains the colliding-summary projection in lockstep, so the
    // state-driven composer must collapse back to `None` — the
    // widget binds a `#[watch]` over the projection so the
    // `AdwAlertDialog` body disappears once the user confirms past
    // the prompt. Mirror of
    // `apply_msg_confirm_add_anyway_drains_pending_duplicate_existing`
    // on the alert-body projection side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_body, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_body(&state).is_some(),
        "precondition: StagePendingDuplicate populates the alert body",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        compose_pending_duplicate_alert_body(&state).is_none(),
        "ConfirmAddAnyway drains the alert-body projection alongside the pending slot",
    );
}

#[test]
fn compose_post_effect_warning_body_with_no_outcome_returns_none() {
    // A freshly-opened dialog has not yet seen a worker completion,
    // so the durability-warning projection must collapse to `None`
    // — the widget binds a `#[watch]` over the projection so the
    // warning row stays hidden until a `KeepWithWarning` outcome
    // is parked. Mirror of
    // `compose_pending_duplicate_alert_body_with_no_pending_returns_none`
    // on the post-effect-warning projection side.
    use paladin_gtk::add_account::{compose_post_effect_warning_body, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_post_effect_warning_body(&state).is_none(),
        "fresh dialog has no worker outcome → no durability warning",
    );
}

#[test]
fn compose_post_effect_warning_body_with_inline_outcome_returns_none() {
    // `Inline(InlineError)` is the typed §5 inline-error variant of
    // the post-effect routing — a pre-commit `save_not_committed`
    // (or any non-durability failure) keeps the dialog open with
    // the form populated for retry. The durability-warning
    // projection must collapse to `None` for this variant so the
    // widget does not render the warning row alongside the inline
    // error. Pins the projection to the `KeepWithWarning` variant
    // only.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_warning_body, AddAccountMsg,
        AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&save_not_committed_no_backup());
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "fixture precondition: save_not_committed routes to Inline",
    );
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert!(
        compose_post_effect_warning_body(&state).is_none(),
        "Inline outcome → no durability warning to render",
    );
}

#[test]
fn compose_post_effect_warning_body_with_keep_with_warning_returns_rendered() {
    // `save_durability_unconfirmed` routes to `KeepWithWarning`,
    // and the widget binds a `#[watch]` over the projection to
    // attach the rendered warning beneath the post-add counts
    // panel. The composer must thread the carried
    // `InlineWarning::rendered` string verbatim so the body wording
    // stays in sync with the CLI / TUI `Display` impl on
    // `PaladinError::SaveDurabilityUnconfirmed`.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_warning_body, AddAccountMsg,
        AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    let expected = match &outcome {
        AddPostEffectOutcome::KeepWithWarning(warning) => warning.rendered.clone(),
        AddPostEffectOutcome::Inline(inline) => {
            panic!("fixture precondition: KeepWithWarning, got Inline({inline:?})")
        }
    };
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert_eq!(
        compose_post_effect_warning_body(&state),
        Some(expected.as_str()),
        "KeepWithWarning → composer renders the carried warning body verbatim",
    );
}

#[test]
fn compose_post_effect_inline_error_body_with_no_outcome_returns_none() {
    // A freshly-opened dialog has not yet seen a worker completion,
    // so the inline-error projection must collapse to `None` —
    // the widget binds a `#[watch]` over the projection so the
    // post-effect inline-error row stays hidden until an `Inline`
    // outcome is parked. Mirror of
    // `compose_post_effect_warning_body_with_no_outcome_returns_none`
    // on the inline-error projection side.
    use paladin_gtk::add_account::{compose_post_effect_inline_error_body, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_post_effect_inline_error_body(&state).is_none(),
        "fresh dialog has no worker outcome → no post-effect inline error",
    );
}

#[test]
fn compose_post_effect_inline_error_body_with_keep_with_warning_returns_none() {
    // `KeepWithWarning(InlineWarning)` is the durability-warning
    // variant — the add committed to disk but the parent fsync was
    // not confirmed. The inline-error projection must collapse to
    // `None` for this variant so the widget does not render the
    // inline-error row alongside the success-with-warning panel.
    // Pins the projection to the `Inline` variant only.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_inline_error_body,
        AddAccountMsg, AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "fixture precondition: save_durability_unconfirmed routes to KeepWithWarning",
    );
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert!(
        compose_post_effect_inline_error_body(&state).is_none(),
        "KeepWithWarning outcome → no inline-error to render",
    );
}

#[test]
fn compose_post_effect_inline_error_body_with_inline_returns_rendered() {
    // `save_not_committed` (or any non-durability post-effect
    // failure) routes to `Inline(InlineError)`, and the widget binds
    // a `#[watch]` over the projection to attach the rendered error
    // beneath the form for retry. The composer must thread the
    // carried `InlineError::rendered` string verbatim so the body
    // wording stays in sync with the CLI / TUI `Display` impl on
    // the underlying `PaladinError`.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_inline_error_body,
        AddAccountMsg, AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&save_not_committed_no_backup());
    let expected = match &outcome {
        AddPostEffectOutcome::Inline(inline) => inline.rendered.clone(),
        AddPostEffectOutcome::KeepWithWarning(w) => {
            panic!("fixture precondition: Inline, got KeepWithWarning({w:?})")
        }
    };
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert_eq!(
        compose_post_effect_inline_error_body(&state),
        Some(expected.as_str()),
        "Inline → composer renders the carried inline-error body verbatim",
    );
}

#[test]
fn compose_inline_error_body_with_no_inline_error_returns_none() {
    // A freshly-opened dialog has not yet seen a rejected Save
    // click, so the pre-effect inline-error projection must
    // collapse to `None` — the widget binds a `#[watch]` over the
    // projection so the inline-error row stays hidden until a
    // `RenderInlineError` parks a typed §5 rejection. Mirror of
    // `compose_post_effect_inline_error_body_with_no_outcome_returns_none`
    // on the pre-effect side.
    use paladin_gtk::add_account::{compose_inline_error_body, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_inline_error_body(&state).is_none(),
        "fresh dialog has no inline_error → no pre-effect inline error",
    );
}

#[test]
fn compose_inline_error_body_with_inline_error_returns_rendered() {
    // The widget dispatches `RenderInlineError` on every Save click
    // that produced `SaveClickOutcome::InlineError`. The composer
    // must thread the carried `InlineError::rendered` string verbatim
    // so the body wording stays in sync with the CLI / TUI `Display`
    // impl on the underlying `PaladinError`. Symmetric partner of
    // `compose_post_effect_inline_error_body_with_inline_returns_rendered`
    // on the pre-effect side.
    use paladin_gtk::add_account::{
        apply_msg, compose_inline_error_body, AddAccountMsg, AddDialogState,
    };

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let expected = err.rendered.clone();
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));

    assert_eq!(
        compose_inline_error_body(&state),
        Some(expected.as_str()),
        "RenderInlineError → composer exposes the carried rendered body verbatim",
    );
}

#[test]
fn compose_inline_error_body_drains_after_submit_proceed() {
    // SubmitProceed clears the pre-effect inline_error so the
    // dialog cannot render stale text alongside a successful
    // retry. The composer must collapse back to `None` once the
    // retry boundary is crossed — the widget binds a `#[watch]`
    // over the projection so the inline-error row disappears the
    // moment the user's next valid Save click goes through.
    use paladin_gtk::add_account::{
        apply_msg, compose_inline_error_body, AddAccountMsg, AddDialogState,
    };

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(
        compose_inline_error_body(&state).is_some(),
        "precondition: RenderInlineError populated the projection",
    );

    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );

    assert!(
        compose_inline_error_body(&state).is_none(),
        "SubmitProceed drains the inline-error projection alongside the worker_outcome slot",
    );
}

#[test]
fn compose_inline_error_revealed_with_no_inline_error_is_false() {
    // A freshly-opened dialog has not yet seen a rejected Save
    // click, so the pre-effect inline-error revealed projection
    // must be `false` — the widget binds a `#[watch]` over the
    // projection to drive the inline-error row's
    // `AdwBanner::set_revealed:` (or equivalent reveal) so the row
    // stays hidden until a `RenderInlineError` parks a typed §5
    // rejection. Sibling of
    // `compose_inline_error_body_with_no_inline_error_returns_none`
    // on the revealed-bool side and of
    // `compose_post_effect_warning_revealed_with_no_outcome_is_false`
    // on the post-effect-revealed side.
    use paladin_gtk::add_account::{compose_inline_error_revealed, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        !compose_inline_error_revealed(&state),
        "fresh dialog has no inline_error → inline-error row is not revealed",
    );
}

#[test]
fn compose_inline_error_revealed_with_inline_error_is_true() {
    // The widget dispatches `RenderInlineError` on every Save click
    // that produced `SaveClickOutcome::InlineError`. The revealed
    // projection must flip to `true` in lockstep with
    // `compose_inline_error_body` returning `Some(_)`, so the two
    // `#[watch]`-driven properties (revealed bool + body text) flip
    // together on the same `RenderInlineError` dispatch. Mirror of
    // `compose_post_effect_warning_revealed_with_keep_with_warning_is_true`
    // on the post-effect side.
    use paladin_gtk::add_account::{
        apply_msg, compose_inline_error_revealed, AddAccountMsg, AddDialogState,
    };

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));

    assert!(
        compose_inline_error_revealed(&state),
        "RenderInlineError → composer reveals the inline-error row",
    );
}

#[test]
fn compose_inline_error_revealed_drains_after_submit_proceed() {
    // `SubmitProceed` clears the pre-effect `inline_error` slot so
    // the dialog cannot keep the inline-error row revealed
    // alongside a successful retry. The revealed projection must
    // collapse back to `false` once the retry boundary is crossed
    // — the widget binds a `#[watch]` over the projection so the
    // inline-error row animates back out the moment the user's
    // next valid Save click goes through. Sibling lockstep with
    // `compose_inline_error_body_drains_after_submit_proceed`,
    // which also collapses on the same `SubmitProceed` dispatch.
    use paladin_gtk::add_account::{
        apply_msg, compose_inline_error_revealed, AddAccountMsg, AddDialogState,
    };

    let err = InlineError::from_error(&validation_error("label", "empty"));
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::RenderInlineError(err));
    assert!(
        compose_inline_error_revealed(&state),
        "precondition: RenderInlineError reveals the inline-error row",
    );

    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );

    assert!(
        !compose_inline_error_revealed(&state),
        "SubmitProceed drains the revealed projection alongside the inline_error slot",
    );
}

#[test]
fn compose_active_path_fresh_dialog_returns_manual() {
    // The `AdwViewSwitcher` between the manual / URI sub-paths binds
    // a `#[watch]` over the active-path projection to drive which
    // sub-stack page is visible. A fresh dialog opens on the manual
    // sub-path per the CLI / TUI `add` defaults, so the projection
    // must return `AddPath::Manual` before any `SwitchPath` dispatch
    // lands. Mirror of `AddSecretState::new` returning
    // `active_path == AddPath::Manual`, surfaced through the
    // composer so the widget never reaches across `secret_state()`
    // accessors inline.
    use paladin_gtk::add_account::{compose_active_path, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let state = AddDialogState::new();

    assert_eq!(
        compose_active_path(&state),
        AddPath::Manual,
        "fresh dialog opens on Manual; composer surfaces it for the widget #[watch]",
    );
}

#[test]
fn compose_active_path_after_switch_to_uri_returns_uri() {
    // `apply_msg(AddAccountMsg::SwitchPath(AddPath::Uri))` advances
    // the active path through `AddSecretState::switch_path`. The
    // composer must observe the post-switch value so the
    // `AdwViewSwitcher` body flips to the URI sub-stack page in
    // lockstep with the secret-buffer drain the path switch
    // triggers. Sibling of
    // `apply_msg_switch_path_to_uri_flips_active_path_and_emits_no_output`
    // — that test pins the routing through the accessor; this one
    // pins it through the projection the widget binds.
    use paladin_gtk::add_account::{apply_msg, compose_active_path, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let output = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    assert!(
        output.is_none(),
        "precondition: SwitchPath is dialog-local; no output flows back to AppModel",
    );
    assert_eq!(
        compose_active_path(&state),
        AddPath::Uri,
        "SwitchPath(Uri) drives the projection to AddPath::Uri",
    );
}

#[test]
fn compose_active_path_round_trip_back_to_manual_returns_manual() {
    // A user toggling the `AdwViewSwitcher` between sub-paths must
    // see the projection follow each `SwitchPath`, not latch on the
    // first transition. The drain semantics for the secret-bearing
    // buffers are tested exhaustively in
    // `tests/secret_fields_logic.rs`; here we pin only that the
    // active-path projection round-trips so the widget's
    // `#[watch]`-driven sub-stack switch stays bidirectional.
    use paladin_gtk::add_account::{apply_msg, compose_active_path, AddAccountMsg, AddDialogState};
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    assert_eq!(
        compose_active_path(&state),
        AddPath::Uri,
        "precondition: first SwitchPath(Uri) advanced the projection",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Manual));

    assert_eq!(
        compose_active_path(&state),
        AddPath::Manual,
        "SwitchPath back to Manual drives the projection back to AddPath::Manual",
    );
}

#[test]
fn format_duplicate_alert_heading_returns_add_anyway_question() {
    // The `AdwAlertDialog` heading is the question the user is being
    // asked: "Add anyway?". The wording is fixed (no state input) so
    // the widget can bind it as a constant string when the modal is
    // presented. Partner of `format_duplicate_alert_body`, which
    // renders the descriptive body beneath the heading.
    use paladin_gtk::add_account::format_duplicate_alert_heading;

    assert_eq!(
        format_duplicate_alert_heading(),
        "Add anyway?",
        "duplicate-alert heading is the fixed AdwAlertDialog question",
    );
}

#[test]
fn compose_pending_duplicate_alert_heading_with_no_pending_returns_none() {
    // A freshly-opened dialog has not yet seen a duplicate-collision
    // Save click, so the heading projection must collapse to `None`
    // — the widget binds a `#[watch]` over the projection so the
    // `AdwAlertDialog` heading region only renders while a pending
    // collision is staged. Mirror of
    // `compose_pending_duplicate_alert_body_with_no_pending_returns_none`
    // on the heading projection side.
    use paladin_gtk::add_account::{compose_pending_duplicate_alert_heading, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_pending_duplicate_alert_heading(&state).is_none(),
        "fresh dialog has no pending duplicate → no alert heading",
    );
}

#[test]
fn compose_pending_duplicate_alert_heading_with_staged_pending_returns_heading() {
    // After `StagePendingDuplicate` parks the colliding existing
    // summary, the heading projection must return
    // `Some(format_duplicate_alert_heading())` so the widget can
    // bind a single `#[watch]` over the projection to drive both
    // visibility and text of the `AdwAlertDialog` heading. Partner
    // of `compose_pending_duplicate_alert_body_with_staged_pending_returns_formatted_body`
    // on the heading side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_heading, format_duplicate_alert_heading,
        AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert_eq!(
        compose_pending_duplicate_alert_heading(&state),
        Some(format_duplicate_alert_heading()),
        "staged pending → composer surfaces the heading verbatim",
    );
}

#[test]
fn compose_pending_duplicate_alert_heading_drains_after_confirm_add_anyway() {
    // `ConfirmAddAnyway` consumes the pending validated account and
    // drains the colliding-summary slot in lockstep, so the heading
    // projection must collapse back to `None` — the widget binds a
    // `#[watch]` over the projection so the `AdwAlertDialog` heading
    // disappears once the user confirms past the prompt. Mirror of
    // `compose_pending_duplicate_alert_body_drains_after_confirm_add_anyway`
    // on the heading projection side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_heading, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_heading(&state).is_some(),
        "precondition: StagePendingDuplicate populates the alert heading",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        compose_pending_duplicate_alert_heading(&state).is_none(),
        "ConfirmAddAnyway drains the alert-heading projection alongside the pending slot",
    );
}

#[test]
fn format_duplicate_alert_confirm_label_returns_add_anyway() {
    // The `AdwAlertDialog` confirm button is the destructive
    // affordance that consumes the parked
    // [`paladin_core::ValidatedAccount`] and forwards
    // `AddAccountOutput::Submit` to the worker. The label wording is
    // fixed at "Add anyway" — surfaced through this helper so the
    // string lives in one place shared by the widget binding, the
    // dialog body's docstrings (which reference the wording
    // verbatim), and the snapshot tests.
    use paladin_gtk::add_account::format_duplicate_alert_confirm_label;

    assert_eq!(
        format_duplicate_alert_confirm_label(),
        "Add anyway",
        "duplicate-alert confirm button label is the fixed CLI / TUI parity wording",
    );
}

#[test]
fn compose_pending_duplicate_alert_confirm_label_with_no_pending_returns_none() {
    // A freshly-opened dialog has not yet seen a duplicate-collision
    // Save click, so the confirm-button projection must collapse to
    // `None` — the widget binds a `#[watch]` over the projection so
    // the `AdwAlertDialog` "Add anyway" button only exists while a
    // pending collision is staged. Mirror of
    // `compose_pending_duplicate_alert_heading_with_no_pending_returns_none`
    // on the confirm-label projection side.
    use paladin_gtk::add_account::{compose_pending_duplicate_alert_confirm_label, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_pending_duplicate_alert_confirm_label(&state).is_none(),
        "fresh dialog has no pending duplicate → no confirm-button label",
    );
}

#[test]
fn compose_pending_duplicate_alert_confirm_label_with_staged_pending_returns_label() {
    // After `StagePendingDuplicate` parks the colliding existing
    // summary, the confirm-button projection must return
    // `Some(format_duplicate_alert_confirm_label())` so the widget
    // can bind a single `#[watch]` over the projection to drive both
    // visibility and text of the `AdwAlertDialog` confirm button.
    // Partner of `compose_pending_duplicate_alert_heading_with_staged_pending_returns_heading`
    // on the confirm-button side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_confirm_label,
        format_duplicate_alert_confirm_label, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert_eq!(
        compose_pending_duplicate_alert_confirm_label(&state),
        Some(format_duplicate_alert_confirm_label()),
        "staged pending → composer surfaces the confirm-button label verbatim",
    );
}

#[test]
fn compose_pending_duplicate_alert_confirm_label_drains_after_confirm_add_anyway() {
    // `ConfirmAddAnyway` consumes the pending validated account and
    // drains the colliding-summary slot in lockstep, so the
    // confirm-button projection must collapse back to `None` — the
    // widget binds a `#[watch]` over the projection so the
    // `AdwAlertDialog` confirm button disappears once the user
    // confirms past the prompt. Mirror of
    // `compose_pending_duplicate_alert_heading_drains_after_confirm_add_anyway`
    // on the confirm-button side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_confirm_label, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_confirm_label(&state).is_some(),
        "precondition: StagePendingDuplicate populates the confirm-button label",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        compose_pending_duplicate_alert_confirm_label(&state).is_none(),
        "ConfirmAddAnyway drains the confirm-button projection alongside the pending slot",
    );
}

#[test]
fn format_duplicate_alert_cancel_label_returns_cancel() {
    // The `AdwAlertDialog` cancel button is the non-destructive
    // affordance the user clicks to back out of the duplicate-
    // collision prompt without submitting the parked
    // [`paladin_core::ValidatedAccount`]. The label wording is the
    // fixed GNOME-convention "Cancel" — surfaced through this helper
    // so the string lives in one place shared by the widget binding,
    // the dialog body's docstrings, and the snapshot tests, in
    // lockstep with the partner `format_duplicate_alert_heading` /
    // `format_duplicate_alert_confirm_label` helpers.
    use paladin_gtk::add_account::format_duplicate_alert_cancel_label;

    assert_eq!(
        format_duplicate_alert_cancel_label(),
        "Cancel",
        "duplicate-alert cancel button label is the fixed GNOME-convention wording",
    );
}

#[test]
fn compose_pending_duplicate_alert_cancel_label_with_no_pending_returns_none() {
    // A freshly-opened dialog has not yet seen a duplicate-collision
    // Save click, so the cancel-button projection must collapse to
    // `None` — the widget binds a `#[watch]` over the projection so
    // the `AdwAlertDialog` "Cancel" button only exists while a
    // pending collision is staged. Mirror of
    // `compose_pending_duplicate_alert_confirm_label_with_no_pending_returns_none`
    // on the cancel-label projection side.
    use paladin_gtk::add_account::{compose_pending_duplicate_alert_cancel_label, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_pending_duplicate_alert_cancel_label(&state).is_none(),
        "fresh dialog has no pending duplicate → no cancel-button label",
    );
}

#[test]
fn compose_pending_duplicate_alert_cancel_label_with_staged_pending_returns_label() {
    // After `StagePendingDuplicate` parks the colliding existing
    // summary, the cancel-button projection must return
    // `Some(format_duplicate_alert_cancel_label())` so the widget
    // can bind a single `#[watch]` over the projection to drive both
    // visibility and text of the `AdwAlertDialog` cancel button.
    // Partner of `compose_pending_duplicate_alert_confirm_label_with_staged_pending_returns_label`
    // on the cancel-button side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_cancel_label,
        format_duplicate_alert_cancel_label, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert_eq!(
        compose_pending_duplicate_alert_cancel_label(&state),
        Some(format_duplicate_alert_cancel_label()),
        "staged pending → composer surfaces the cancel-button label verbatim",
    );
}

#[test]
fn compose_pending_duplicate_alert_cancel_label_drains_after_confirm_add_anyway() {
    // `ConfirmAddAnyway` consumes the pending validated account and
    // drains the colliding-summary slot in lockstep, so the
    // cancel-button projection must collapse back to `None` — the
    // widget binds a `#[watch]` over the projection so the
    // `AdwAlertDialog` cancel button disappears once the user
    // confirms past the prompt. Mirror of
    // `compose_pending_duplicate_alert_confirm_label_drains_after_confirm_add_anyway`
    // on the cancel-button side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_cancel_label, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_cancel_label(&state).is_some(),
        "precondition: StagePendingDuplicate populates the cancel-button label",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        compose_pending_duplicate_alert_cancel_label(&state).is_none(),
        "ConfirmAddAnyway drains the cancel-button projection alongside the pending slot",
    );
}

#[test]
fn compose_pending_duplicate_alert_cancel_label_drains_after_cancel() {
    // `Cancel` drains every half of the duplicate-collision
    // projection in lockstep, so the cancel-button projection must
    // collapse back to `None` even though the user dismissed via
    // the dialog's outer Cancel rather than the modal — once the
    // pending validated account drains, no `AdwAlertDialog` lives.
    // Confirms the lockstep drain semantics carry across the second
    // drainage trigger documented on `pending_duplicate_existing`.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_cancel_label, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_cancel_label(&state).is_some(),
        "precondition: StagePendingDuplicate populates the cancel-button label",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::Cancel);

    assert!(
        compose_pending_duplicate_alert_cancel_label(&state).is_none(),
        "Cancel drains the cancel-button projection alongside the pending slot",
    );
}

#[test]
fn compose_manual_period_secs_visible_default_state_is_true() {
    // The manual sub-path defaults to `AccountKindInput::Totp` (CLI
    // parity, see `ManualDraftState::default`), so a freshly-opened
    // dialog must expose the period spinbutton row — the widget
    // binds a `#[watch]` over the projection to drive the row's
    // `set_visible:` so the TOTP-specific row only renders when the
    // user has selected TOTP. Mirror of `compose_active_path` on the
    // kind-specific row-visibility side.
    use paladin_gtk::add_account::{compose_manual_period_secs_visible, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        compose_manual_period_secs_visible(&state),
        "fresh dialog defaults to TOTP, so the period row is visible",
    );
}

#[test]
fn compose_manual_period_secs_visible_after_kind_hotp_is_false() {
    // Selecting HOTP from the kind dropdown drives the projection to
    // `false` so the widget hides the period spinbutton row. The
    // partner `compose_manual_counter_visible` projection (which
    // lands in a follow-up commit) takes over for the HOTP-specific
    // counter row.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_period_secs_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );

    assert!(
        !compose_manual_period_secs_visible(&state),
        "ManualKindChanged(Hotp) hides the TOTP period spinbutton row",
    );
}

#[test]
fn compose_manual_period_secs_visible_round_trips_back_to_totp() {
    // Toggling the kind dropdown back to TOTP after HOTP must drive
    // the projection back to `true` — the row must not latch on the
    // first transition, so the widget's `#[watch]`-driven row
    // visibility stays bidirectional. Mirror of
    // `compose_active_path_round_trip_back_to_manual_returns_manual`
    // on the kind-specific row-visibility side.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_period_secs_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );
    assert!(
        !compose_manual_period_secs_visible(&state),
        "precondition: HOTP hid the period row",
    );

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Totp),
    );

    assert!(
        compose_manual_period_secs_visible(&state),
        "ManualKindChanged(Totp) re-reveals the period spinbutton row",
    );
}

#[test]
fn compose_manual_counter_visible_default_state_is_false() {
    // The manual sub-path defaults to `AccountKindInput::Totp` (CLI
    // parity, see `ManualDraftState::default`), so a freshly-opened
    // dialog must hide the HOTP counter spinbutton row — the widget
    // binds a `#[watch]` over the projection to drive the row's
    // `set_visible:` so the HOTP-specific row only renders when the
    // user has selected HOTP. Sibling of
    // `compose_manual_period_secs_visible_default_state_is_true` on
    // the counter-row side.
    use paladin_gtk::add_account::{compose_manual_counter_visible, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        !compose_manual_counter_visible(&state),
        "fresh dialog defaults to TOTP, so the counter row is hidden",
    );
}

#[test]
fn compose_manual_counter_visible_after_kind_hotp_is_true() {
    // Selecting HOTP from the kind dropdown drives the projection to
    // `true` so the widget reveals the HOTP counter spinbutton row.
    // The partner `compose_manual_period_secs_visible` projection
    // flips to `false` in lockstep so the user only sees the kind-
    // specific row that matches their dropdown selection.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_counter_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );

    assert!(
        compose_manual_counter_visible(&state),
        "ManualKindChanged(Hotp) reveals the HOTP counter spinbutton row",
    );
}

#[test]
fn compose_manual_counter_visible_round_trips_back_to_totp() {
    // Toggling the kind dropdown back to TOTP after HOTP must drive
    // the counter projection back to `false` — the row must not
    // latch on the first transition, so the widget's
    // `#[watch]`-driven row visibility stays bidirectional. Mirror
    // of `compose_manual_period_secs_visible_round_trips_back_to_totp`
    // on the counter-row side.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_counter_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );
    assert!(
        compose_manual_counter_visible(&state),
        "precondition: HOTP revealed the counter row",
    );

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Totp),
    );

    assert!(
        !compose_manual_counter_visible(&state),
        "ManualKindChanged(Totp) re-hides the counter spinbutton row",
    );
}

#[test]
fn compose_manual_period_and_counter_visibility_are_mutually_exclusive() {
    // Exactly one of the two kind-specific rows is visible at any
    // given moment: TOTP shows the period row and hides the counter
    // row; HOTP shows the counter row and hides the period row. The
    // widget relies on this invariant to lay out the form without an
    // empty gap or two rows competing for the same slot. Pin both
    // states explicitly so a future refactor of either projection
    // cannot drift them out of lockstep.
    use paladin_core::AccountKindInput;
    use paladin_gtk::add_account::{
        apply_msg, compose_manual_counter_visible, compose_manual_period_secs_visible,
        AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    assert!(
        compose_manual_period_secs_visible(&state) ^ compose_manual_counter_visible(&state),
        "fresh dialog (TOTP default): exactly one of the kind-specific rows is visible",
    );

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Hotp),
    );
    assert!(
        compose_manual_period_secs_visible(&state) ^ compose_manual_counter_visible(&state),
        "after HOTP: exactly one of the kind-specific rows is visible",
    );

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualKindChanged(AccountKindInput::Totp),
    );
    assert!(
        compose_manual_period_secs_visible(&state) ^ compose_manual_counter_visible(&state),
        "after TOTP round-trip: exactly one of the kind-specific rows is visible",
    );
}

#[test]
fn compose_save_button_sensitive_fresh_dialog_is_false() {
    // A freshly-opened dialog defaults to the manual sub-path with
    // empty label / secret buffers, so the Save button must be
    // greyed out — the widget binds `#[watch] set_sensitive:` over
    // the projection so a totally-empty form cannot reach the
    // validation pipeline. Mirror of the `UnlockDialogState::
    // submit_button_sensitive()` empty-passphrase short-circuit on
    // the add path.
    use paladin_gtk::add_account::{compose_save_button_sensitive, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        !compose_save_button_sensitive(&state),
        "fresh dialog (manual path, empty buffers) → Save button is greyed out",
    );
}

#[test]
fn compose_save_button_sensitive_manual_label_only_is_false() {
    // The manual sub-path requires *both* a non-empty label and a
    // non-empty secret to be submittable: label alone is not enough,
    // since the duplicate / validation pipeline cannot run without a
    // secret. Pin the asymmetry so the projection cannot drift to a
    // weaker "any field non-empty" check.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_button_sensitive, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("Work".to_string()),
    );

    assert!(
        !compose_save_button_sensitive(&state),
        "manual path with label but empty secret → Save button is greyed out",
    );
}

#[test]
fn compose_save_button_sensitive_manual_secret_only_is_false() {
    // Symmetric partner of the label-only test: a non-empty secret
    // alone without a label is also not submittable.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_button_sensitive, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("JBSWY3DPEHPK3PXP".to_string()),
    );

    assert!(
        !compose_save_button_sensitive(&state),
        "manual path with secret but empty label → Save button is greyed out",
    );
}

#[test]
fn compose_save_button_sensitive_manual_label_and_secret_is_true() {
    // The minimum-submittable case on the manual sub-path: both
    // label and secret are non-empty. The button enables and the
    // user's click reaches the validation pipeline, which may still
    // surface an inline error for typed-but-invalid Base32 or
    // length-cap violations — those rejections render through
    // `compose_inline_error_body`, not through gating.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_button_sensitive, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("Work".to_string()),
    );
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualSecretChanged("JBSWY3DPEHPK3PXP".to_string()),
    );

    assert!(
        compose_save_button_sensitive(&state),
        "manual path with non-empty label and secret → Save button is sensitive",
    );
}

#[test]
fn compose_save_button_sensitive_uri_path_empty_is_false() {
    // Switching to the URI sub-path with no URI text → the Save
    // button is greyed out. The manual buffers are not consulted on
    // the URI path, so any pre-existing manual label / secret
    // populated before the path switch must not lift the URI path's
    // gate.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_button_sensitive, AddAccountMsg, AddDialogState,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::ManualLabelChanged("Work".to_string()),
    );
    // The label survives a path switch (only the leaving path's
    // secret buffer wipes), but the URI path's gate looks at
    // `uri_text` rather than the manual draft, so the button
    // remains greyed out.
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    assert!(
        !compose_save_button_sensitive(&state),
        "URI path with empty URI text → Save button is greyed out (manual label irrelevant)",
    );
}

#[test]
fn compose_save_button_sensitive_uri_path_with_text_is_true() {
    // The URI sub-path's minimum-submittable case: non-empty URI
    // text. The button enables and the user's click reaches
    // `compose_uri_submit_outcome`, which may still surface
    // `parse_otpauth` errors inline for malformed input — those
    // rejections render through `compose_inline_error_body`, not
    // through gating.
    use paladin_gtk::add_account::{
        apply_msg, compose_save_button_sensitive, AddAccountMsg, AddDialogState,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::UriTextChanged(
            "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example".to_string(),
        ),
    );

    assert!(
        compose_save_button_sensitive(&state),
        "URI path with non-empty URI text → Save button is sensitive",
    );
}

#[test]
fn format_add_path_label_manual_returns_manual() {
    // The `AdwViewSwitcher` page title for the manual sub-path is
    // the fixed label "Manual". Surfacing the wording through a
    // helper rather than a bare string literal keeps it in one
    // place shared by the widget binding (page title + active-path
    // text projection) and the snapshot tests in
    // `tests/add_account_logic.rs`.
    use paladin_gtk::add_account::format_add_path_label;
    use paladin_gtk::secret_fields::AddPath;

    assert_eq!(
        format_add_path_label(AddPath::Manual),
        "Manual",
        "manual sub-path page label is the fixed CLI / TUI parity wording",
    );
}

#[test]
fn format_add_path_label_uri_returns_uri() {
    // The `AdwViewSwitcher` page title for the URI sub-path is the
    // fixed label "URI". Partner of `format_add_path_label(Manual)`
    // on the URI sub-path side.
    use paladin_gtk::add_account::format_add_path_label;
    use paladin_gtk::secret_fields::AddPath;

    assert_eq!(
        format_add_path_label(AddPath::Uri),
        "URI",
        "URI sub-path page label is the fixed CLI / TUI parity wording",
    );
}

#[test]
fn compose_active_path_label_fresh_dialog_returns_manual() {
    // A freshly-opened dialog defaults to the manual sub-path (CLI
    // parity), so the active-path label projection must return
    // `"Manual"` — the widget binds a `#[watch]` over the projection
    // anywhere it names the current sub-path (e.g. a header subtitle
    // or page title beside the switcher). Mirror of
    // `compose_active_path_fresh_dialog_returns_manual` on the
    // display-label side.
    use paladin_gtk::add_account::{
        compose_active_path_label, format_add_path_label, AddDialogState,
    };
    use paladin_gtk::secret_fields::AddPath;

    let state = AddDialogState::new();

    assert_eq!(
        compose_active_path_label(&state),
        format_add_path_label(AddPath::Manual),
        "fresh dialog → composer surfaces the manual sub-path label verbatim",
    );
}

#[test]
fn compose_active_path_label_after_switch_to_uri_returns_uri() {
    // `SwitchPath(Uri)` drives the active-path label projection to
    // `"URI"` in lockstep with `compose_active_path` flipping to
    // `AddPath::Uri`. The widget's `#[watch]`-driven display label
    // follows the switcher selection.
    use paladin_gtk::add_account::{
        apply_msg, compose_active_path_label, format_add_path_label, AddAccountMsg, AddDialogState,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    assert_eq!(
        compose_active_path_label(&state),
        format_add_path_label(AddPath::Uri),
        "SwitchPath(Uri) → composer surfaces the URI sub-path label",
    );
}

#[test]
fn compose_active_path_label_round_trips_back_to_manual() {
    // Toggling the switcher back to the manual sub-path after the
    // URI sub-path must drive the active-path label projection back
    // to `"Manual"` — the projection must not latch on the first
    // transition, so the widget's `#[watch]`-driven display label
    // stays bidirectional. Mirror of
    // `compose_active_path_round_trip_back_to_manual_returns_manual`
    // on the display-label side.
    use paladin_gtk::add_account::{
        apply_msg, compose_active_path_label, format_add_path_label, AddAccountMsg, AddDialogState,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));
    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Manual));

    assert_eq!(
        compose_active_path_label(&state),
        format_add_path_label(AddPath::Manual),
        "SwitchPath back to Manual → composer surfaces the manual sub-path label",
    );
}

#[test]
fn compose_pending_duplicate_alert_visible_fresh_dialog_is_false() {
    // A freshly-opened dialog has not yet seen a duplicate-collision
    // Save click, so the alert-visibility projection must be `false`
    // — the widget binds a `#[watch]` over the projection to drive
    // the `AdwAlertDialog`'s `set_visible:` / `.present()` /
    // `.close()` transition without reaching across
    // `pending_duplicate_existing()` inline. Sibling of the four
    // `compose_pending_duplicate_alert_*_label` / `_body` /
    // `_heading` projections that already cover the alert content;
    // this bool drives the dialog's existence on screen.
    use paladin_gtk::add_account::{compose_pending_duplicate_alert_visible, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        !compose_pending_duplicate_alert_visible(&state),
        "fresh dialog has no pending duplicate → alert is not visible",
    );
}

#[test]
fn compose_pending_duplicate_alert_visible_with_staged_pending_is_true() {
    // After `StagePendingDuplicate` parks the colliding existing
    // summary, the alert-visibility projection must return `true`
    // so the widget can `#[watch]` it to drive the
    // `AdwAlertDialog`'s presentation in lockstep with the four
    // content projections (heading / body / confirm-label /
    // cancel-label). Mirror of
    // `compose_pending_duplicate_alert_cancel_label_with_staged_pending_returns_label`
    // on the visibility side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };

    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );

    assert!(
        compose_pending_duplicate_alert_visible(&state),
        "staged pending → composer reports the alert as visible",
    );
}

#[test]
fn compose_pending_duplicate_alert_visible_drains_after_confirm_add_anyway() {
    // `ConfirmAddAnyway` consumes the pending validated account and
    // drains the colliding-summary slot in lockstep with every
    // alert-content projection, so the visibility projection must
    // collapse back to `false` — the widget binds a `#[watch]` over
    // the projection so the `AdwAlertDialog` closes once the user
    // confirms past the prompt. Mirror of
    // `compose_pending_duplicate_alert_cancel_label_drains_after_confirm_add_anyway`
    // on the visibility side.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_visible(&state),
        "precondition: StagePendingDuplicate makes the alert visible",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::ConfirmAddAnyway);

    assert!(
        !compose_pending_duplicate_alert_visible(&state),
        "ConfirmAddAnyway drains the visibility projection alongside the pending slot",
    );
}

#[test]
fn compose_pending_duplicate_alert_visible_drains_after_cancel() {
    // `Cancel` drains every half of the duplicate-collision
    // projection in lockstep, so the visibility projection must
    // collapse back to `false` even though the user dismissed via
    // the dialog's outer Cancel rather than the modal — once the
    // pending validated account drains, no `AdwAlertDialog` lives.
    // Confirms the lockstep drain semantics carry across the
    // second drainage trigger documented on
    // `pending_duplicate_existing`.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_visible, AddAccountMsg, AddDialogState,
    };

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_visible(&state),
        "precondition: StagePendingDuplicate makes the alert visible",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::Cancel);

    assert!(
        !compose_pending_duplicate_alert_visible(&state),
        "Cancel drains the visibility projection alongside the pending slot",
    );
}

#[test]
fn compose_pending_duplicate_alert_visible_drains_after_switch_path() {
    // `SwitchPath` drains the pending duplicate-collision state per
    // `AddSecretState::switch_path` (the parked validated account
    // and the colliding summary are tied to the path the user just
    // left), so the visibility projection must collapse back to
    // `false` whenever the user moves to a different sub-path. The
    // widget binds a `#[watch]` over the projection so the
    // `AdwAlertDialog` closes the moment the user picks the URI sub-
    // path instead of dismissing through the modal itself. Same
    // lockstep behavior the body / heading / label projections rely
    // on.
    use paladin_gtk::add_account::{
        apply_msg, compose_pending_duplicate_alert_visible, AddAccountMsg, AddDialogState,
    };
    use paladin_gtk::secret_fields::AddPath;

    let mut state = AddDialogState::new();
    let validated = match classify_manual_submit(manual_totp_defaults(), now_for_tests()) {
        ManualSubmitOutcome::Proceed(v) => v,
        ManualSubmitOutcome::InlineError(e) => panic!("fixture failed: {e:?}"),
    };
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::StagePendingDuplicate {
            account: validated.account,
            warnings: validated.warnings,
            existing: dummy_existing_summary(),
        },
    );
    assert!(
        compose_pending_duplicate_alert_visible(&state),
        "precondition: StagePendingDuplicate makes the alert visible",
    );

    let _ = apply_msg(&mut state, AddAccountMsg::SwitchPath(AddPath::Uri));

    assert!(
        !compose_pending_duplicate_alert_visible(&state),
        "SwitchPath drains the visibility projection alongside the pending slot",
    );
}

#[test]
fn compose_post_effect_warning_revealed_with_no_outcome_is_false() {
    // A freshly-opened dialog has not yet seen a worker completion,
    // so the durability-warning revealed projection must be `false`
    // — the widget binds a `#[watch]` over the projection to drive
    // the `AdwBanner::set_revealed:` transition so the banner stays
    // hidden until a `KeepWithWarning` outcome is parked. Sibling
    // of `compose_post_effect_warning_body_with_no_outcome_returns_none`
    // on the revealed-bool side.
    use paladin_gtk::add_account::{compose_post_effect_warning_revealed, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        !compose_post_effect_warning_revealed(&state),
        "fresh dialog has no worker outcome → durability warning is not revealed",
    );
}

#[test]
fn compose_post_effect_warning_revealed_with_inline_outcome_is_false() {
    // `Inline(InlineError)` is the typed §5 inline-error variant of
    // the post-effect routing — a pre-commit `save_not_committed`
    // (or any non-durability failure) keeps the dialog open with
    // the form populated for retry. The durability-warning revealed
    // projection must be `false` for this variant so the
    // `AdwBanner` does not animate in alongside the inline error.
    // Pins the projection to the `KeepWithWarning` variant only,
    // matching the body projection's partitioning of
    // [`AddPostEffectOutcome`] across the two dialog regions.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_warning_revealed,
        AddAccountMsg, AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&save_not_committed_no_backup());
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "fixture precondition: save_not_committed routes to Inline",
    );
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert!(
        !compose_post_effect_warning_revealed(&state),
        "Inline outcome → durability warning stays hidden",
    );
}

#[test]
fn compose_post_effect_warning_revealed_with_keep_with_warning_is_true() {
    // `save_durability_unconfirmed` routes to `KeepWithWarning`,
    // and the widget binds a `#[watch]` over the projection to
    // animate the `AdwBanner` in alongside the rendered warning
    // body. The revealed projection must return `true` for this
    // variant in lockstep with `compose_post_effect_warning_body`
    // returning `Some(_)`, so the two `#[watch]`-driven properties
    // (revealed bool + body text) flip together on the same
    // `WorkerFailed` dispatch.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_warning_revealed,
        AddAccountMsg, AddDialogState,
    };

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert!(
        compose_post_effect_warning_revealed(&state),
        "KeepWithWarning → composer reveals the durability warning banner",
    );
}

#[test]
fn compose_post_effect_warning_revealed_drains_after_submit_proceed() {
    // Retrying via `SubmitProceed` clears `AddDialogState::worker_outcome`
    // before the new worker runs (see
    // `apply_msg_submit_proceed_clears_prior_worker_outcome`), so the
    // durability-warning revealed projection must collapse back to
    // `false` — the widget binds a `#[watch]` over the projection so
    // the `AdwBanner` animates back out the moment the user resubmits.
    // Sibling lockstep with `compose_post_effect_warning_body`, which
    // also collapses on the same `SubmitProceed` dispatch.
    use paladin_core::{validate_manual, AccountInput, IconHintInput};
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_warning_revealed,
        AddAccountMsg, AddDialogState,
    };

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));
    assert!(
        compose_post_effect_warning_revealed(&state),
        "precondition: KeepWithWarning reveals the banner",
    );

    let input = AccountInput {
        label: "retry-label".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );

    assert!(
        !compose_post_effect_warning_revealed(&state),
        "SubmitProceed drains the revealed projection alongside the worker_outcome slot",
    );
}

#[test]
fn compose_post_effect_inline_error_revealed_with_no_outcome_is_false() {
    // A freshly-opened dialog has not yet seen a worker completion,
    // so the post-effect inline-error revealed projection must be
    // `false` — the widget binds a `#[watch]` over the projection
    // to drive the inline-error row's reveal so it stays hidden
    // until an `Inline` outcome is parked. Sibling of
    // `compose_post_effect_inline_error_body_with_no_outcome_returns_none`
    // on the revealed-bool side and mirror of
    // `compose_post_effect_warning_revealed_with_no_outcome_is_false`
    // on the durability-warning side.
    use paladin_gtk::add_account::{compose_post_effect_inline_error_revealed, AddDialogState};

    let state = AddDialogState::new();

    assert!(
        !compose_post_effect_inline_error_revealed(&state),
        "fresh dialog has no worker outcome → post-effect inline error is not revealed",
    );
}

#[test]
fn compose_post_effect_inline_error_revealed_with_keep_with_warning_is_false() {
    // `KeepWithWarning(InlineWarning)` is the durability-warning
    // variant — the add committed to disk but the parent fsync was
    // not confirmed. The post-effect inline-error revealed
    // projection must be `false` for this variant so the widget
    // does not render the inline-error row alongside the
    // success-with-warning panel. Pins the projection to the
    // `Inline` variant only, matching the body projection's
    // partitioning of [`AddPostEffectOutcome`] across the two
    // dialog regions.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_inline_error_revealed,
        AddAccountMsg, AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(
        matches!(outcome, AddPostEffectOutcome::KeepWithWarning(_)),
        "fixture precondition: save_durability_unconfirmed routes to KeepWithWarning",
    );
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert!(
        !compose_post_effect_inline_error_revealed(&state),
        "KeepWithWarning outcome → post-effect inline-error row stays hidden",
    );
}

#[test]
fn compose_post_effect_inline_error_revealed_with_inline_outcome_is_true() {
    // `save_not_committed` (or any non-durability post-effect
    // failure) routes to `Inline(InlineError)`, and the widget
    // binds a `#[watch]` over the projection to attach the row
    // beneath the form for retry. The revealed projection must
    // return `true` for this variant in lockstep with
    // `compose_post_effect_inline_error_body` returning `Some(_)`,
    // so the two `#[watch]`-driven properties (revealed bool +
    // body text) flip together on the same `WorkerFailed` dispatch.
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_inline_error_revealed,
        AddAccountMsg, AddDialogState, AddPostEffectOutcome,
    };

    let outcome = classify_add_post_effect_error(&save_not_committed_no_backup());
    assert!(
        matches!(outcome, AddPostEffectOutcome::Inline(_)),
        "fixture precondition: save_not_committed routes to Inline",
    );
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));

    assert!(
        compose_post_effect_inline_error_revealed(&state),
        "Inline → composer reveals the post-effect inline-error row",
    );
}

#[test]
fn compose_post_effect_inline_error_revealed_drains_after_submit_proceed() {
    // Retrying via `SubmitProceed` clears `AddDialogState::worker_outcome`
    // before the new worker runs (see
    // `apply_msg_submit_proceed_clears_prior_worker_outcome`), so the
    // post-effect inline-error revealed projection must collapse back
    // to `false` — the widget binds a `#[watch]` over the projection
    // so the inline-error row animates back out the moment the user
    // resubmits. Sibling lockstep with
    // `compose_post_effect_inline_error_body`, which also collapses
    // on the same `SubmitProceed` dispatch, and mirror of
    // `compose_post_effect_warning_revealed_drains_after_submit_proceed`
    // on the durability-warning side.
    use paladin_core::{validate_manual, AccountInput, IconHintInput};
    use paladin_gtk::add_account::{
        apply_msg, classify_add_post_effect_error, compose_post_effect_inline_error_revealed,
        AddAccountMsg, AddDialogState,
    };

    let outcome = classify_add_post_effect_error(&save_not_committed_no_backup());
    let mut state = AddDialogState::new();
    let _ = apply_msg(&mut state, AddAccountMsg::WorkerFailed(outcome));
    assert!(
        compose_post_effect_inline_error_revealed(&state),
        "precondition: Inline reveals the post-effect inline-error row",
    );

    let input = AccountInput {
        label: "retry-label".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated =
        validate_manual(input, SystemTime::UNIX_EPOCH).expect("totp account input validates");
    let _ = apply_msg(
        &mut state,
        AddAccountMsg::SubmitProceed {
            account: validated.account,
        },
    );

    assert!(
        !compose_post_effect_inline_error_revealed(&state),
        "SubmitProceed drains the revealed projection alongside the worker_outcome slot",
    );
}
