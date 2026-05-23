// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase G: `Vault::import_accounts` (docs/DESIGN.md §4.7 `impl Vault`).
//
// Phase G owns the merge-flow types (`ImportConflict`,
// `ImportWarning`, `ImportReport`) and the `Vault` method that
// applies the §5 `--on-conflict` policy against pre-validated
// `ValidatedAccount` rows. Phase I will land the format-specific
// importers (`otpauth`, `aegis`, `qr`, `paladin`) and exercise this
// method through the public import facade; the coverage here is the
// Phase G smoke tests of the merge / report / warnings contract.

mod common;

use common::test_tempdir;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, AccountKindSummary, ImportConflict, ImportReport, ImportWarning, Store,
    ValidatedAccount, ValidationWarning, Vault, VaultInit,
};

// 10-byte (16-char base32) secret — triggers ShortSecret because it
// is below SHORT_SECRET_THRESHOLD_BYTES (16). Used to verify that
// warnings ride along through `Vault::import_accounts` even when the
// row is later skipped under `ImportConflict::Skip`.
const SHORT_SECRET_B32: &str = "JBSWY3DPEHPK3PXP";
// 20-byte (32-char base32) secret — at SHA1's recommended minimum,
// no ShortSecret warning. The default for the merge-policy fixtures.
const LONG_SECRET_A: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const LONG_SECRET_B: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const LONG_SECRET_C: &str = "MFRGGZDFMZTWQ2LKMFRGGZDFMZTWQ2LK";
const LONG_SECRET_D: &str = "NBSWY3DPO5XXE3DENBSWY3DPO5XXE3DE";

const FIXTURE_NOW_SECS: u64 = 1_700_000_000;
const IMPORT_NOW_SECS: u64 = 1_700_001_000;

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(FIXTURE_NOW_SECS)
}

fn import_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(IMPORT_NOW_SECS)
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

/// Build a `ValidatedAccount` via `parse_otpauth`. Goes through the
/// real parser so the warning-collection path is shape-identical to
/// the actual format importers (Phase I).
fn validated_totp(label: &str, issuer: Option<&str>, secret_b32: &str) -> ValidatedAccount {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret={secret_b32}");
    parse_otpauth(&uri, fixture_now()).unwrap()
}

fn validated_hotp(
    label: &str,
    issuer: Option<&str>,
    secret_b32: &str,
    counter: u64,
) -> ValidatedAccount {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://hotp/{issuer_part}{label}?secret={secret_b32}&counter={counter}");
    parse_otpauth(&uri, fixture_now()).unwrap()
}

// ---- empty / no-op ------------------------------------------------

#[test]
fn import_accounts_empty_vec_returns_zero_report() {
    let mut vault = empty_plaintext_vault();
    let report = vault
        .import_accounts(Vec::new(), ImportConflict::Skip, import_now())
        .expect("import");
    assert_eq!(
        report,
        ImportReport {
            imported: 0,
            skipped: 0,
            replaced: 0,
            appended: 0,
            accounts: Vec::new(),
            warnings: Vec::new(),
        }
    );
    assert_eq!(vault.iter().count(), 0);
}

// ---- non-collision (imported) -------------------------------------

#[test]
fn import_accounts_non_collision_inserts_with_fresh_id_and_increments_imported() {
    let mut vault = empty_plaintext_vault();
    let alice = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let source_id = alice.account.id();

    let report = vault
        .import_accounts(vec![alice], ImportConflict::Skip, import_now())
        .expect("import");

    assert_eq!(report.imported, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.replaced, 0);
    assert_eq!(report.appended, 0);
    assert_eq!(report.accounts.len(), 1);
    let stored_id = report.accounts[0];
    // Per docs/DESIGN.md §4.6, non-colliding rows receive fresh UUIDv4 IDs
    // at merge time so a Paladin bundle's source IDs cannot leak.
    assert_ne!(
        stored_id, source_id,
        "import_accounts must regenerate the AccountId at merge time"
    );

    assert_eq!(vault.iter().count(), 1);
    let stored = vault.get(stored_id).expect("inserted");
    assert_eq!(stored.label(), "alice");
    assert_eq!(stored.issuer(), Some("Acme"));
    assert_eq!(stored.kind(), AccountKindSummary::Totp);
}

#[test]
fn import_accounts_imported_count_matches_input_size_for_no_collisions() {
    let mut vault = empty_plaintext_vault();
    let report = vault
        .import_accounts(
            vec![
                validated_totp("alice", Some("Acme"), LONG_SECRET_A),
                validated_totp("bob", Some("Acme"), LONG_SECRET_B),
                validated_hotp("carol", Some("Acme"), LONG_SECRET_A, 0),
            ],
            ImportConflict::Skip,
            import_now(),
        )
        .expect("import");
    assert_eq!(report.imported, 3);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.accounts.len(), 3);
    assert_eq!(vault.iter().count(), 3);
}

// ---- Skip on collision --------------------------------------------

#[test]
fn import_accounts_skip_on_collision_keeps_existing_and_omits_id_from_report() {
    let mut vault = empty_plaintext_vault();
    let stored = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let stored_id = vault.add(stored.account);

    let report = vault
        .import_accounts(
            vec![validated_totp("alice", Some("Acme"), LONG_SECRET_A)],
            ImportConflict::Skip,
            import_now(),
        )
        .expect("import");

    assert_eq!(report.imported, 0);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.replaced, 0);
    assert_eq!(report.appended, 0);
    assert!(
        report.accounts.is_empty(),
        "skipped rows must not appear in ImportReport.accounts"
    );

    assert_eq!(vault.iter().count(), 1);
    let kept = vault.get(stored_id).expect("kept");
    assert_eq!(kept.id(), stored_id, "existing id preserved on Skip");
}

// ---- Replace on collision -----------------------------------------

#[test]
fn import_accounts_replace_preserves_destination_id_and_created_at() {
    let mut vault = empty_plaintext_vault();
    let stored = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let stored_id = vault.add(stored.account);
    let stored_created_at = vault.get(stored_id).unwrap().created_at();
    assert_eq!(stored_created_at, FIXTURE_NOW_SECS);

    // Same (secret, issuer, label) triple — collides — but a fresh
    // `parse_otpauth` produces a different inner `AccountId`.
    let incoming = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let incoming_id = incoming.account.id();
    assert_ne!(incoming_id, stored_id);

    let report = vault
        .import_accounts(vec![incoming], ImportConflict::Replace, import_now())
        .expect("import");

    assert_eq!(report.replaced, 1);
    assert_eq!(report.imported, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.appended, 0);
    assert_eq!(report.accounts, vec![stored_id]);

    assert_eq!(vault.iter().count(), 1);
    let after = vault.get(stored_id).expect("still present");
    assert_eq!(after.id(), stored_id, "destination id preserved");
    assert_eq!(
        after.created_at(),
        stored_created_at,
        "destination created_at preserved"
    );
    assert_eq!(
        after.updated_at(),
        IMPORT_NOW_SECS,
        "updated_at = import_time"
    );
}

#[test]
fn import_accounts_replace_hotp_to_hotp_preserves_existing_counter() {
    let mut vault = empty_plaintext_vault();
    let existing = validated_hotp("alice", Some("Acme"), LONG_SECRET_A, 42);
    let stored_id = vault.add(existing.account);
    assert_eq!(vault.get(stored_id).unwrap().counter(), Some(42));

    // Incoming has a different counter (7) but collides on
    // (secret, issuer, label). Per §5, HOTP-to-HOTP Replace must
    // preserve the existing counter (42), not adopt the source's 7.
    let incoming = validated_hotp("alice", Some("Acme"), LONG_SECRET_A, 7);
    let report = vault
        .import_accounts(vec![incoming], ImportConflict::Replace, import_now())
        .expect("import");

    assert_eq!(report.replaced, 1);
    let after = vault.get(stored_id).expect("still present");
    assert_eq!(after.counter(), Some(42), "existing HOTP counter preserved");
    assert_eq!(after.kind(), AccountKindSummary::Hotp);
}

#[test]
fn import_accounts_replace_cross_kind_swaps_kind_keeping_id_and_created_at() {
    let mut vault = empty_plaintext_vault();
    let totp = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let stored_id = vault.add(totp.account);
    let stored_created_at = vault.get(stored_id).unwrap().created_at();
    assert_eq!(
        vault.get(stored_id).unwrap().kind(),
        AccountKindSummary::Totp
    );

    // Incoming is HOTP with the same (secret, issuer, label). Replace
    // swaps the whole kind — the destination becomes HOTP — while
    // keeping the existing id and created_at.
    let incoming = validated_hotp("alice", Some("Acme"), LONG_SECRET_A, 5);
    let report = vault
        .import_accounts(vec![incoming], ImportConflict::Replace, import_now())
        .expect("import");

    assert_eq!(report.replaced, 1);
    let after = vault.get(stored_id).expect("still present");
    assert_eq!(after.id(), stored_id);
    assert_eq!(after.created_at(), stored_created_at);
    assert_eq!(after.updated_at(), IMPORT_NOW_SECS);
    assert_eq!(after.kind(), AccountKindSummary::Hotp);
    assert_eq!(after.counter(), Some(5));
    assert_eq!(after.period(), None);
}

// ---- Append on collision ------------------------------------------

#[test]
fn import_accounts_append_on_collision_inserts_with_fresh_id() {
    let mut vault = empty_plaintext_vault();
    let stored = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let stored_id = vault.add(stored.account);

    let incoming = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let incoming_id = incoming.account.id();

    let report = vault
        .import_accounts(vec![incoming], ImportConflict::Append, import_now())
        .expect("import");

    assert_eq!(report.appended, 1);
    assert_eq!(report.imported, 0);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.replaced, 0);
    assert_eq!(report.accounts.len(), 1);
    let appended_id = report.accounts[0];

    assert_ne!(
        appended_id, stored_id,
        "appended row must receive an id distinct from the existing collision"
    );
    assert_ne!(
        appended_id, incoming_id,
        "appended row must receive a fresh id at merge time, not reuse the source's"
    );

    assert_eq!(vault.iter().count(), 2);
    assert!(vault.get(stored_id).is_some());
    assert!(vault.get(appended_id).is_some());
}

// ---- mixed-policy report partition --------------------------------

#[test]
fn import_accounts_report_accounts_lists_imported_replaced_appended_in_source_order() {
    let mut vault = empty_plaintext_vault();
    // Pre-populate one account so that the second incoming row collides.
    let collider = validated_totp("alice", Some("Acme"), LONG_SECRET_A);
    let collider_id = vault.add(collider.account);

    // Source rows: imported (no collision), replaced (collision), imported.
    let report = vault
        .import_accounts(
            vec![
                validated_totp("bob", Some("Acme"), LONG_SECRET_B),
                validated_totp("alice", Some("Acme"), LONG_SECRET_A),
                validated_hotp("carol", Some("Acme"), LONG_SECRET_A, 0),
            ],
            ImportConflict::Replace,
            import_now(),
        )
        .expect("import");

    assert_eq!(report.imported, 2);
    assert_eq!(report.replaced, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.appended, 0);
    assert_eq!(report.accounts.len(), 3);
    // Source order: bob (new id), alice (collider_id, replaced), carol (new id).
    assert_eq!(report.accounts[1], collider_id);
    assert_ne!(report.accounts[0], collider_id);
    assert_ne!(report.accounts[2], collider_id);
}

// ---- warnings preservation ----------------------------------------

#[test]
fn import_accounts_warnings_collected_before_merge_policy_with_source_index() {
    let mut vault = empty_plaintext_vault();
    // Pre-populate the alice row that the second source row will collide with.
    vault.add(validated_totp("alice", Some("Acme"), SHORT_SECRET_B32).account);

    // Three source rows. Index 0 is short-secret (warns) and unique
    // (different label), so it imports. Index 1 is short-secret AND
    // collides with the existing alice row → it is skipped under
    // `Skip`, but its warning must still be in the report. Index 2
    // has a long secret (no warning) and is unique.
    let report = vault
        .import_accounts(
            vec![
                validated_totp("dave", Some("Acme"), SHORT_SECRET_B32),
                validated_totp("alice", Some("Acme"), SHORT_SECRET_B32),
                validated_totp("carol", Some("Acme"), LONG_SECRET_B),
            ],
            ImportConflict::Skip,
            import_now(),
        )
        .expect("import");

    assert_eq!(report.imported, 2);
    assert_eq!(report.skipped, 1);
    assert_eq!(report.warnings.len(), 2);
    let expected = ValidationWarning::ShortSecret {
        decoded_len: 10,
        recommended_min: 16,
    };
    assert_eq!(
        report.warnings[0],
        ImportWarning {
            source_index: 0,
            warning: expected.clone(),
        }
    );
    assert_eq!(
        report.warnings[1],
        ImportWarning {
            source_index: 1,
            warning: expected,
        },
        "warning from a SKIPPED row must still be reported"
    );
}

// ---- Skip with multiple collisions in one batch -------------------

#[test]
fn import_accounts_skip_collects_all_collisions_in_skipped_count() {
    // Pre-populate three TOTP accounts, each with a distinct secret.
    let mut vault = empty_plaintext_vault();
    let a_id = vault.add(validated_totp("a", Some("X"), LONG_SECRET_A).account);
    let b_id = vault.add(validated_totp("b", Some("X"), LONG_SECRET_B).account);
    let c_id = vault.add(validated_totp("c", Some("X"), LONG_SECRET_C).account);
    let a_updated_pre = vault.get(a_id).unwrap().updated_at();
    let b_updated_pre = vault.get(b_id).unwrap().updated_at();
    let c_updated_pre = vault.get(c_id).unwrap().updated_at();

    // Batch: three exact `(secret, issuer, label)` duplicates in mixed
    // source order plus one fresh row.
    let batch = vec![
        validated_totp("c", Some("X"), LONG_SECRET_C),
        validated_totp("a", Some("X"), LONG_SECRET_A),
        validated_totp("d", Some("X"), LONG_SECRET_D),
        validated_totp("b", Some("X"), LONG_SECRET_B),
    ];

    let report = vault
        .import_accounts(batch, ImportConflict::Skip, import_now())
        .expect("import");

    assert_eq!(report.skipped, 3);
    assert_eq!(report.imported, 1);
    assert_eq!(report.replaced, 0);
    assert_eq!(report.appended, 0);
    assert_eq!(report.accounts.len(), 1);

    // Vault now has 4 accounts: original 3 + the fresh `d`.
    assert_eq!(vault.iter().count(), 4);

    // The single ID in `report.accounts` must point to the fresh row.
    let fresh_id = report.accounts[0];
    let fresh = vault.get(fresh_id).expect("fresh row stored");
    assert_eq!(fresh.label(), "d");
    assert_eq!(fresh.issuer(), Some("X"));

    // Originals: IDs and updated_at timestamps unchanged.
    assert_eq!(vault.get(a_id).unwrap().updated_at(), a_updated_pre);
    assert_eq!(vault.get(b_id).unwrap().updated_at(), b_updated_pre);
    assert_eq!(vault.get(c_id).unwrap().updated_at(), c_updated_pre);
}
