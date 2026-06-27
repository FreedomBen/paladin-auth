// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase M: per-account metadata edit (docs/DESIGN.md §4.7 / Milestone 9).
//
// Covers:
//   * `AccountEdit` + `validate_account_edit` per-field validation
//     (label / issuer / icon_hint independently and combined,
//     first-failure-wins ordering).
//   * `validate_icon_hint_slug` slug-only wrapper around the §4.1
//     `[a-z0-9_-]+` grammar.
//   * `Vault::edit_account_metadata`: empty-edit rejection, per-field
//     happy paths, the issuer "leave untouched" tri-state, the
//     `IconHintInput::Default` re-derivation against the post-edit
//     issuer, the no-op-but-non-empty `updated_at` bump,
//     trim-on-write normalization, pre-check ordering, and
//     validation rejection preserving the prior `Account`
//     byte-for-byte.
//   * `Vault::find_duplicate_after_edit`: self-skip, unknown-id,
//     label-only / issuer-clear / issuer-set / combined-edit
//     collisions, case-sensitive parity with `find_duplicate`,
//     candidate-normalization both directions, and NFC vs NFD
//     byte-equality.
//   * Post-refactor `Vault::rename` error-shape lock: byte-identical
//     `validation_error` / `time_range` / `invalid_state` envelopes
//     compared with the pre-M9 implementation.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_auth_core::{
    parse_otpauth, validate_account_edit, validate_icon_hint_slug, Account, AccountEdit, AccountId,
    IconHintInput, PaladinAuthError, Store, TimeRangeKind, Vault, VaultInit,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn later_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_001_000)
}

const SECRET_A: &str = "JBSWY3DPEHPK3PXP";
const SECRET_B: &str = "GEZDGNBVGY3TQOJQ";

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret={SECRET_A}");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn make_account_with_secret(label: &str, issuer: Option<&str>, secret_b32: &str) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret={secret_b32}");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn empty_plaintext_vault() -> Vault {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    vault
}

fn plaintext_vault_persisted() -> (Vault, Store, std::path::PathBuf) {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");
    std::mem::forget(dir);
    let (vault, store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    (vault, store, path)
}

// ---------------------------------------------------------------------------
// AccountEdit + validate_account_edit
// ---------------------------------------------------------------------------

#[test]
fn account_edit_default_has_all_fields_none() {
    let edit = AccountEdit::default();
    assert!(edit.label.is_none());
    assert!(edit.issuer.is_none());
    assert!(edit.icon_hint.is_none());
}

#[test]
fn validate_account_edit_accepts_empty_edit_without_error() {
    // The validator deliberately does NOT reject empty drafts; the
    // mutator owns the "no field set" rejection. Front ends call
    // the validator on every keystroke and need an empty draft to
    // remain a valid intermediate state.
    let prior = make_account("alice", Some("Acme"));
    validate_account_edit(&AccountEdit::default(), &prior, later_now())
        .expect("empty edit must be accepted by the validator");
}

#[test]
fn validate_account_edit_label_happy_path() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        label: Some("alice-prime".to_string()),
        ..Default::default()
    };
    validate_account_edit(&edit, &prior, later_now()).expect("valid label");
}

#[test]
fn validate_account_edit_label_empty_rejected() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        label: Some(String::new()),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "label");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(label/empty), got {other:?}"),
    }
}

#[test]
fn validate_account_edit_label_overlong_rejected() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        label: Some("a".repeat(129)),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "label");
            assert_eq!(reason, "too_long");
        }
        other => panic!("expected validation_error(label/too_long), got {other:?}"),
    }
}

#[test]
fn validate_account_edit_issuer_set_happy_path() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        issuer: Some(Some("NewCorp".to_string())),
        ..Default::default()
    };
    validate_account_edit(&edit, &prior, later_now()).expect("valid issuer set");
}

#[test]
fn validate_account_edit_issuer_clear_accepted() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        issuer: Some(None),
        ..Default::default()
    };
    validate_account_edit(&edit, &prior, later_now()).expect("issuer clear must validate");
}

#[test]
fn validate_account_edit_issuer_overlong_rejected() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        issuer: Some(Some("a".repeat(129))),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "issuer");
            assert_eq!(reason, "too_long");
        }
        other => panic!("expected validation_error(issuer/too_long), got {other:?}"),
    }
}

#[test]
fn validate_account_edit_icon_hint_default_accepted() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Default),
        ..Default::default()
    };
    validate_account_edit(&edit, &prior, later_now())
        .expect("IconHintInput::Default needs no slug validation");
}

#[test]
fn validate_account_edit_icon_hint_clear_accepted() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Clear),
        ..Default::default()
    };
    validate_account_edit(&edit, &prior, later_now()).expect("IconHintInput::Clear validates");
}

#[test]
fn validate_account_edit_icon_hint_slug_happy_path() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Slug("github".to_string())),
        ..Default::default()
    };
    validate_account_edit(&edit, &prior, later_now()).expect("valid slug");
}

#[test]
fn validate_account_edit_icon_hint_slug_invalid_rejected() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Slug("GitHub!".to_string())),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "icon_hint");
            assert_eq!(reason, "invalid_chars");
        }
        other => panic!("expected validation_error(icon_hint/invalid_chars), got {other:?}"),
    }
}

#[test]
fn validate_account_edit_icon_hint_slug_empty_rejected() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Slug(String::new())),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "icon_hint");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(icon_hint/empty), got {other:?}"),
    }
}

#[test]
fn validate_account_edit_combined_happy_path() {
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        label: Some("alice-prime".to_string()),
        issuer: Some(Some("NewCorp".to_string())),
        icon_hint: Some(IconHintInput::Slug("newcorp".to_string())),
    };
    validate_account_edit(&edit, &prior, later_now()).expect("all three valid");
}

#[test]
fn validate_account_edit_first_failure_wins_label_before_issuer() {
    // Label fails first (empty) — even though issuer would also fail.
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        label: Some(String::new()),
        issuer: Some(Some("a".repeat(129))),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, .. }) => {
            assert_eq!(field, "label", "label must fire before issuer");
        }
        other => panic!("expected validation_error(label/…), got {other:?}"),
    }
}

#[test]
fn validate_account_edit_first_failure_wins_issuer_before_icon_hint() {
    // No label edit; issuer overlong + icon_hint invalid → issuer fires
    // first because the per-field walk is [label, issuer, icon_hint].
    let prior = make_account("alice", Some("Acme"));
    let edit = AccountEdit {
        issuer: Some(Some("a".repeat(129))),
        icon_hint: Some(IconHintInput::Slug("GitHub!".to_string())),
        ..Default::default()
    };
    match validate_account_edit(&edit, &prior, later_now()) {
        Err(PaladinAuthError::ValidationError { field, .. }) => {
            assert_eq!(field, "issuer", "issuer must fire before icon_hint");
        }
        other => panic!("expected validation_error(issuer/…), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// validate_icon_hint_slug
// ---------------------------------------------------------------------------

#[test]
fn validate_icon_hint_slug_returns_slug_arm_on_success() {
    let result = validate_icon_hint_slug("github").expect("valid slug");
    match result {
        IconHintInput::Slug(s) => assert_eq!(s, "github"),
        other => panic!("expected IconHintInput::Slug, got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_accepts_grammar() {
    for slug in ["github", "google-cloud", "aws_cli", "a1-b2_c3"] {
        let result = validate_icon_hint_slug(slug).expect("grammar member");
        match result {
            IconHintInput::Slug(s) => assert_eq!(s, slug),
            other => panic!("expected IconHintInput::Slug, got {other:?}"),
        }
    }
}

#[test]
fn validate_icon_hint_slug_default_keyword_rounds_trip_as_slug() {
    // The literal slug "default" must round-trip as an
    // `IconHintInput::Slug("default")` — `validate_icon_hint_slug`
    // does NOT reroute it to `IconHintInput::Default` (that's
    // `parse_icon_hint_token`'s job).
    let result = validate_icon_hint_slug("default").expect("literal slug");
    match result {
        IconHintInput::Slug(s) => assert_eq!(s, "default"),
        other => panic!("expected IconHintInput::Slug(\"default\"), got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_none_keyword_rounds_trip_as_slug() {
    // Similarly, "none" must NOT reroute to IconHintInput::Clear.
    let result = validate_icon_hint_slug("none").expect("literal slug");
    match result {
        IconHintInput::Slug(s) => assert_eq!(s, "none"),
        other => panic!("expected IconHintInput::Slug(\"none\"), got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_rejects_empty() {
    match validate_icon_hint_slug("") {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "icon_hint");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(icon_hint/empty), got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_rejects_uppercase() {
    match validate_icon_hint_slug("GitHub") {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "icon_hint");
            assert_eq!(reason, "invalid_chars");
        }
        other => panic!("expected validation_error(icon_hint/invalid_chars), got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_rejects_whitespace_no_trim() {
    // No trim: any whitespace is rejected as `invalid_chars`.
    match validate_icon_hint_slug("  github  ") {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "icon_hint");
            assert_eq!(reason, "invalid_chars");
        }
        other => panic!("expected validation_error(icon_hint/invalid_chars), got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_64_byte_boundary_accepts() {
    let exactly_64 = "a".repeat(64);
    let result = validate_icon_hint_slug(&exactly_64).expect("64 bytes accepted");
    match result {
        IconHintInput::Slug(s) => assert_eq!(s, exactly_64),
        other => panic!("expected IconHintInput::Slug, got {other:?}"),
    }
}

#[test]
fn validate_icon_hint_slug_65_byte_boundary_rejects() {
    let too_long = "a".repeat(65);
    match validate_icon_hint_slug(&too_long) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "icon_hint");
            assert_eq!(reason, "too_long");
        }
        other => panic!("expected validation_error(icon_hint/too_long), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Vault::edit_account_metadata
// ---------------------------------------------------------------------------

#[test]
fn edit_account_metadata_account_not_found() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    let edit = AccountEdit {
        label: Some("alice-prime".to_string()),
        ..Default::default()
    };
    match vault.edit_account_metadata(unknown, edit, later_now()) {
        Err(PaladinAuthError::InvalidState { operation, state }) => {
            assert_eq!(operation, "edit_account_metadata");
            assert_eq!(state, "account_not_found");
        }
        other => {
            panic!("expected invalid_state(edit_account_metadata/account_not_found), got {other:?}")
        }
    }
}

#[test]
fn edit_account_metadata_rejects_empty_edit() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    match vault.edit_account_metadata(id, AccountEdit::default(), later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "edit");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(edit/empty), got {other:?}"),
    }
    // No mutation occurred.
    assert_eq!(vault.get(id).unwrap().label(), "alice");
    assert_eq!(vault.get(id).unwrap().updated_at(), 1_700_000_000);
}

#[test]
fn edit_account_metadata_label_only_applies_and_bumps_updated_at() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let original_created = vault.get(id).unwrap().created_at();
    let edit = AccountEdit {
        label: Some("alice-prime".to_string()),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.label(), "alice-prime");
    assert_eq!(after.issuer(), Some("Acme"));
    assert_eq!(after.created_at(), original_created);
    assert_eq!(after.updated_at(), 1_700_001_000);
}

#[test]
fn edit_account_metadata_issuer_set_only_applies() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        issuer: Some(Some("NewCorp".to_string())),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.issuer(), Some("NewCorp"));
    assert_eq!(after.label(), "alice");
    // icon_hint is left untouched (no IconHintInput::Default re-derive
    // unless explicitly requested).
    assert_eq!(after.icon_hint(), Some("acme"));
}

#[test]
fn edit_account_metadata_issuer_clear_applies() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        issuer: Some(None),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.issuer(), None);
    assert_eq!(after.label(), "alice");
    // icon_hint stays whatever it was (no Default re-derive requested).
    assert_eq!(after.icon_hint(), Some("acme"));
}

#[test]
fn edit_account_metadata_issuer_untouched_when_none() {
    // None on the outer Option leaves issuer alone.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("alice-prime".to_string()),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.issuer(), Some("Acme"));
}

#[test]
fn edit_account_metadata_icon_hint_slug_applies() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Slug("github".to_string())),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().icon_hint(), Some("github"));
}

#[test]
fn edit_account_metadata_icon_hint_clear_applies() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Clear),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().icon_hint(), None);
}

#[test]
fn edit_account_metadata_icon_hint_default_rederives_from_post_edit_issuer() {
    // Edit issuer + ask for IconHintInput::Default in the same call —
    // the slug must be re-derived from the NEW issuer, not the prior.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        issuer: Some(Some("GitHub".to_string())),
        icon_hint: Some(IconHintInput::Default),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.issuer(), Some("GitHub"));
    assert_eq!(after.icon_hint(), Some("github"));
}

#[test]
fn edit_account_metadata_icon_hint_default_rederives_from_prior_when_issuer_untouched() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    // Set a custom slug first so we can tell whether Default kicked in.
    let setup = AccountEdit {
        icon_hint: Some(IconHintInput::Slug("custom".to_string())),
        ..Default::default()
    };
    vault.edit_account_metadata(id, setup, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().icon_hint(), Some("custom"));

    // Now ask for Default without editing the issuer — must re-derive
    // from the prior issuer "Acme".
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Default),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().icon_hint(), Some("acme"));
}

#[test]
fn edit_account_metadata_icon_hint_default_yields_none_when_post_edit_issuer_none() {
    // Issuer cleared + Default → derived slug is None.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        issuer: Some(None),
        icon_hint: Some(IconHintInput::Default),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.issuer(), None);
    assert_eq!(after.icon_hint(), None);
}

#[test]
fn edit_account_metadata_combined_happy_path() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("alice-prime".to_string()),
        issuer: Some(Some("NewCorp".to_string())),
        icon_hint: Some(IconHintInput::Slug("newcorp".to_string())),
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.label(), "alice-prime");
    assert_eq!(after.issuer(), Some("NewCorp"));
    assert_eq!(after.icon_hint(), Some("newcorp"));
    assert_eq!(after.updated_at(), 1_700_001_000);
}

#[test]
fn edit_account_metadata_no_op_but_non_empty_bumps_updated_at() {
    // Every field set to its prior value still bumps updated_at.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let prior_label = vault.get(id).unwrap().label().to_string();
    let prior_issuer = vault.get(id).unwrap().issuer().unwrap().to_string();
    let prior_icon = vault.get(id).unwrap().icon_hint().unwrap().to_string();
    let edit = AccountEdit {
        label: Some(prior_label.clone()),
        issuer: Some(Some(prior_issuer.clone())),
        icon_hint: Some(IconHintInput::Slug(prior_icon.clone())),
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    let after = vault.get(id).unwrap();
    assert_eq!(after.label(), prior_label);
    assert_eq!(after.issuer(), Some(prior_issuer.as_str()));
    assert_eq!(after.icon_hint(), Some(prior_icon.as_str()));
    assert_eq!(after.updated_at(), 1_700_001_000);
}

#[test]
fn edit_account_metadata_trims_label_on_write() {
    // AccountEdit { label: Some("  Foo  "), .. } lands on disk as "Foo".
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("  Foo  ".to_string()),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().label(), "Foo");
}

#[test]
fn edit_account_metadata_trims_issuer_on_write() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        issuer: Some(Some("  NewCorp  ".to_string())),
        ..Default::default()
    };
    vault.edit_account_metadata(id, edit, later_now()).unwrap();
    assert_eq!(vault.get(id).unwrap().issuer(), Some("NewCorp"));
}

#[test]
fn edit_account_metadata_validation_rejection_preserves_account_byte_for_byte() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let before = vault.get(id).unwrap().clone();
    let edit = AccountEdit {
        label: Some(String::new()),
        ..Default::default()
    };
    let _err = vault
        .edit_account_metadata(id, edit, later_now())
        .unwrap_err();
    let after = vault.get(id).unwrap().clone();
    assert_eq!(after, before, "rejected edit must not mutate the account");
}

#[test]
fn edit_account_metadata_pre_check_empty_fires_before_id_resolution() {
    // missing id + empty edit + valid time → validation_error(edit/empty)
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    match vault.edit_account_metadata(unknown, AccountEdit::default(), later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "edit");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(edit/empty), got {other:?}"),
    }
}

#[test]
fn edit_account_metadata_pre_check_label_fires_before_id_resolution() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    let edit = AccountEdit {
        label: Some(String::new()),
        ..Default::default()
    };
    match vault.edit_account_metadata(unknown, edit, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "label");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(label/empty), got {other:?}"),
    }
}

#[test]
fn edit_account_metadata_pre_check_time_fires_before_id_resolution() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    let edit = AccountEdit {
        label: Some("ok".to_string()),
        ..Default::default()
    };
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
    match vault.edit_account_metadata(unknown, edit, pre_epoch) {
        Err(PaladinAuthError::TimeRange { operation, kind }) => {
            assert_eq!(operation, "edit_account_metadata");
            assert_eq!(kind, TimeRangeKind::PreEpoch);
        }
        other => panic!("expected time_range(edit_account_metadata/pre_epoch), got {other:?}"),
    }
}

#[test]
fn edit_account_metadata_year_9999_cap_rejects() {
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("ok".to_string()),
        ..Default::default()
    };
    let beyond = UNIX_EPOCH + Duration::from_secs(253_402_300_800);
    match vault.edit_account_metadata(id, edit, beyond) {
        Err(PaladinAuthError::TimeRange { operation, kind }) => {
            assert_eq!(operation, "edit_account_metadata");
            assert_eq!(kind, TimeRangeKind::OutOfRange);
        }
        other => {
            panic!("expected time_range(edit_account_metadata/out_of_range), got {other:?}")
        }
    }
}

#[test]
fn edit_account_metadata_persists_through_mutate_and_save() {
    let (mut vault, store, path) = plaintext_vault_persisted();
    let id = vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).unwrap();

    vault
        .mutate_and_save(&store, |v| -> Result<(), PaladinAuthError> {
            let edit = AccountEdit {
                label: Some("alice-prime".to_string()),
                ..Default::default()
            };
            v.edit_account_metadata(id, edit, later_now())
        })
        .unwrap();

    drop(vault);
    drop(store);
    let (reopened, _store) = Store::open(&path, paladin_auth_core::VaultLock::Plaintext).unwrap();
    assert_eq!(reopened.get(id).unwrap().label(), "alice-prime");
    assert_eq!(reopened.get(id).unwrap().updated_at(), 1_700_001_000);
}

// ---------------------------------------------------------------------------
// Vault::rename byte-identical error-shape lock
//
// Pin the post-refactor `rename` path's full error surface so the
// operation tag / kinds / reasons stay byte-identical against a
// regression where the refactor accidentally lets
// `edit_account_metadata`'s operation tag leak through, or reorders
// pre-checks ahead of label-validation / time-validation.
// ---------------------------------------------------------------------------

#[test]
fn rename_lock_validation_error_fires_before_id_resolution() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    match vault.rename(unknown, "", later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "label");
            assert_eq!(reason, "empty");
        }
        other => panic!("expected validation_error(label/empty), got {other:?}"),
    }
}

#[test]
fn rename_lock_time_range_fires_before_id_resolution() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
    match vault.rename(unknown, "ok", pre_epoch) {
        Err(PaladinAuthError::TimeRange { operation, kind }) => {
            assert_eq!(operation, "rename");
            assert_eq!(kind, TimeRangeKind::PreEpoch);
        }
        other => panic!("expected time_range(rename/pre_epoch), got {other:?}"),
    }
}

#[test]
fn rename_lock_account_not_found_carries_rename_operation_tag() {
    let mut vault = empty_plaintext_vault();
    vault.add(make_account("alice", Some("Acme")));
    let unknown = AccountId::new();
    match vault.rename(unknown, "ok", later_now()) {
        Err(PaladinAuthError::InvalidState { operation, state }) => {
            assert_eq!(
                operation, "rename",
                "the refactored rename must not leak edit_account_metadata's operation tag"
            );
            assert_eq!(state, "account_not_found");
        }
        other => panic!("expected invalid_state(rename/account_not_found), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Vault::find_duplicate_after_edit
// ---------------------------------------------------------------------------

#[test]
fn find_duplicate_after_edit_unknown_id_returns_none() {
    let vault = empty_plaintext_vault();
    let unknown = AccountId::new();
    let edit = AccountEdit {
        label: Some("alice".to_string()),
        ..Default::default()
    };
    assert!(vault.find_duplicate_after_edit(unknown, &edit).is_none());
}

#[test]
fn find_duplicate_after_edit_self_skip_returns_none_when_no_other_account() {
    // Only the account at `id` exists; a no-op edit self-compares —
    // must NOT report a collision (the skip handles this).
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("alice".to_string()),
        ..Default::default()
    };
    assert!(vault.find_duplicate_after_edit(id, &edit).is_none());
}

#[test]
fn find_duplicate_after_edit_self_skip_handles_untouched_edit() {
    // An edit that leaves both label and issuer untouched still
    // returns None because the self-skip covers the unchanged case.
    let mut vault = empty_plaintext_vault();
    let id = vault.add(make_account("alice", Some("Acme")));
    // Two non-self-colliding entries
    vault.add(make_account_with_secret("bob", Some("Other"), SECRET_B));
    let edit = AccountEdit {
        icon_hint: Some(IconHintInput::Slug("github".to_string())),
        ..Default::default()
    };
    // icon_hint isn't part of the duplicate key — and self is skipped.
    assert!(vault.find_duplicate_after_edit(id, &edit).is_none());
}

#[test]
fn find_duplicate_after_edit_label_only_edit_collides_with_other_account() {
    let mut vault = empty_plaintext_vault();
    // Stored bob with secret SECRET_A.
    let _bob = vault.add(make_account("bob", Some("Acme")));
    // Stored alice with the SAME secret + issuer; we'll rename to "bob"
    // and try to collide.
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("bob".to_string()),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(alice_id, &edit)
        .expect("expected collision");
    assert_eq!(hit.label(), "bob");
    assert_eq!(hit.issuer(), Some("Acme"));
}

#[test]
fn find_duplicate_after_edit_issuer_clear_collides_with_existing_no_issuer() {
    let mut vault = empty_plaintext_vault();
    let _no_issuer = vault.add(make_account("alice", None));
    let has_issuer = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        issuer: Some(None),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(has_issuer, &edit)
        .expect("issuer-clear must collide with the issuer-None twin");
    assert_eq!(hit.label(), "alice");
    assert_eq!(hit.issuer(), None);
}

#[test]
fn find_duplicate_after_edit_issuer_set_collides() {
    let mut vault = empty_plaintext_vault();
    // Two accounts with the same secret + label but different issuers.
    let _stored = vault.add(make_account("alice", Some("Foo")));
    let other = vault.add(make_account("alice", Some("Bar")));
    let edit = AccountEdit {
        issuer: Some(Some("Foo".to_string())),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(other, &edit)
        .expect("issuer-set to existing issuer must collide");
    assert_eq!(hit.issuer(), Some("Foo"));
    assert_eq!(hit.label(), "alice");
}

#[test]
fn find_duplicate_after_edit_combined_label_and_issuer_collides() {
    let mut vault = empty_plaintext_vault();
    let _bob_foo = vault.add(make_account("bob", Some("Foo")));
    let alice_bar = vault.add(make_account("alice", Some("Bar")));
    let edit = AccountEdit {
        label: Some("bob".to_string()),
        issuer: Some(Some("Foo".to_string())),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(alice_bar, &edit)
        .expect("combined edit must collide");
    assert_eq!(hit.label(), "bob");
    assert_eq!(hit.issuer(), Some("Foo"));
}

#[test]
fn find_duplicate_after_edit_case_sensitive_mismatch_returns_none() {
    // Stored issuer "Acme" vs candidate "acme" → not a duplicate.
    let mut vault = empty_plaintext_vault();
    let _stored = vault.add(make_account("alice", Some("Acme")));
    let id = vault.add(make_account("alice", Some("Bar")));
    let edit = AccountEdit {
        issuer: Some(Some("acme".to_string())),
        ..Default::default()
    };
    assert!(vault.find_duplicate_after_edit(id, &edit).is_none());
}

#[test]
fn find_duplicate_after_edit_normalizes_whitespace_padded_label_for_comparison() {
    // A candidate label of "  bob  " must collide with a stored "bob"
    // because the per-field validator trims before comparison.
    let mut vault = empty_plaintext_vault();
    let _bob = vault.add(make_account("bob", Some("Acme")));
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("  bob  ".to_string()),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(alice_id, &edit)
        .expect("whitespace-padded label must normalize and collide");
    assert_eq!(hit.label(), "bob");
}

#[test]
fn find_duplicate_after_edit_normalizes_whitespace_padded_issuer_for_comparison() {
    let mut vault = empty_plaintext_vault();
    let _foo = vault.add(make_account("alice", Some("Foo")));
    let alice_bar = vault.add(make_account("alice", Some("Bar")));
    let edit = AccountEdit {
        issuer: Some(Some("  Foo  ".to_string())),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(alice_bar, &edit)
        .expect("whitespace-padded issuer must normalize and collide");
    assert_eq!(hit.issuer(), Some("Foo"));
}

#[test]
fn find_duplicate_after_edit_returns_none_when_candidate_label_fails_normalization() {
    // Overlong label past LABEL_MAX_BYTES → None (NOT a spurious
    // collision). Front ends are expected to call validate_account_edit
    // first; an invalid candidate is a pending validation error.
    let mut vault = empty_plaintext_vault();
    let _bob = vault.add(make_account("bob", Some("Acme")));
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("a".repeat(129)),
        ..Default::default()
    };
    assert!(vault.find_duplicate_after_edit(alice_id, &edit).is_none());

    // The matching call to edit_account_metadata surfaces the typed
    // validation_error for the same input.
    let edit2 = AccountEdit {
        label: Some("a".repeat(129)),
        ..Default::default()
    };
    match vault.edit_account_metadata(alice_id, edit2, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "label");
            assert_eq!(reason, "too_long");
        }
        other => panic!("expected validation_error(label/too_long), got {other:?}"),
    }
}

#[test]
fn find_duplicate_after_edit_returns_none_when_candidate_issuer_fails_normalization() {
    let mut vault = empty_plaintext_vault();
    let _foo = vault.add(make_account("alice", Some("Foo")));
    let alice_bar = vault.add(make_account("alice", Some("Bar")));
    let edit = AccountEdit {
        issuer: Some(Some("a".repeat(129))),
        ..Default::default()
    };
    assert!(vault.find_duplicate_after_edit(alice_bar, &edit).is_none());

    let edit2 = AccountEdit {
        issuer: Some(Some("a".repeat(129))),
        ..Default::default()
    };
    match vault.edit_account_metadata(alice_bar, edit2, later_now()) {
        Err(PaladinAuthError::ValidationError { field, reason, .. }) => {
            assert_eq!(field, "issuer");
            assert_eq!(reason, "too_long");
        }
        other => panic!("expected validation_error(issuer/too_long), got {other:?}"),
    }
}

#[test]
fn find_duplicate_after_edit_nfc_vs_nfd_label_does_not_collide() {
    // NFC label "é" (U+00E9) candidate vs stored NFD "é" (U+0065 U+0301)
    // — the per-field walk trims but does NOT Unicode-normalize.
    // DESIGN.md §4.7 pins byte-equality as the only equality
    // (no NFC/NFD collapsing).
    let nfd = "\u{0065}\u{0301}"; // 'e' + combining acute
    let mut vault = empty_plaintext_vault();
    let _stored = vault.add(make_account(nfd, Some("Acme")));
    let alice_id = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("\u{00E9}".to_string()), // NFC composed
        ..Default::default()
    };
    assert!(
        vault.find_duplicate_after_edit(alice_id, &edit).is_none(),
        "NFC vs NFD label must NOT collide — byte-equality only"
    );
}

#[test]
fn find_duplicate_after_edit_nfc_vs_nfd_issuer_does_not_collide() {
    let nfd_issuer = "\u{0065}\u{0301}"; // 'e' + combining acute
    let mut vault = empty_plaintext_vault();
    let _stored = vault.add(make_account("alice", Some(nfd_issuer)));
    let alice_other = vault.add(make_account("alice", Some("Other")));
    let edit = AccountEdit {
        issuer: Some(Some("\u{00E9}".to_string())), // NFC composed
        ..Default::default()
    };
    assert!(
        vault
            .find_duplicate_after_edit(alice_other, &edit)
            .is_none(),
        "NFC vs NFD issuer must NOT collide — byte-equality only"
    );
}

#[test]
fn find_duplicate_after_edit_skips_only_the_source_id() {
    // If two accounts already have identical (secret, issuer, label) —
    // shouldn't normally happen but can via append imports — the
    // candidate at id can still see the OTHER one as a collision even
    // though they are themselves byte-identical.
    let mut vault = empty_plaintext_vault();
    let stored = vault.add(make_account("alice", Some("Acme")));
    let other = vault.add(make_account("alice", Some("Acme")));
    let edit = AccountEdit {
        label: Some("alice".to_string()),
        ..Default::default()
    };
    let hit = vault
        .find_duplicate_after_edit(other, &edit)
        .expect("self-skip is on `other` only — `stored` is a collision");
    assert_eq!(hit.id(), stored);
}
