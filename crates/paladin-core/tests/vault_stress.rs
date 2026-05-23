// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K stress coverage — docs/DESIGN.md §4.7 / §6.
//
// `vault_lifecycle.rs` covers small-vault save/reopen round-trips and
// the over-the-16-MiB-cap rejection path. This file pins the
// under-the-cap side of the same invariant at 10,000 accounts: the
// vault must encode below the cap, reopen with insertion-order
// preserved, every field equal to the source rows, and re-saving the
// reopened vault must produce byte-identical primary bytes (bincode
// determinism at scale).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::test_tempdir;
use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, AccountKindSummary, Algorithm,
    IconHintInput, Store, VaultInit, VaultLock,
};
use secrecy::SecretString;

const FIXTURE_SECRET_B32: &str = "JBSWY3DPEHPK3PXP";
const ACCOUNT_COUNT: usize = 10_000;
const PAYLOAD_CAP_BYTES: u64 = 16 * 1024 * 1024;

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn account_input(i: usize) -> AccountInput {
    AccountInput {
        label: format!("acct-{i:05}"),
        issuer: Some(format!("issuer-{}", i % 50)),
        secret: SecretString::from(FIXTURE_SECRET_B32.to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: Some(30),
        counter: None,
        icon_hint: IconHintInput::Default,
    }
}

#[derive(Debug, PartialEq, Eq)]
struct AccountRow {
    label: String,
    issuer: Option<String>,
    kind: AccountKindSummary,
    algorithm: Algorithm,
    digits: u8,
    period_secs: Option<u32>,
}

#[test]
fn large_plaintext_vault_round_trips_through_save_and_reopen() {
    let dir = test_tempdir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("chmod tempdir 0700");
    let path = dir.path().join("vault.bin");

    let (mut vault, store) = Store::create(&path, VaultInit::Plaintext).expect("create");
    let mut expected_ids: Vec<AccountId> = Vec::with_capacity(ACCOUNT_COUNT);
    let mut expected_rows: Vec<AccountRow> = Vec::with_capacity(ACCOUNT_COUNT);
    let import = import_time();
    for i in 0..ACCOUNT_COUNT {
        let validated =
            validate_manual(account_input(i), import).expect("fixture input must validate");
        let account = validated.account;
        expected_rows.push(AccountRow {
            label: account.label().to_string(),
            issuer: account.issuer().map(str::to_string),
            kind: account.kind(),
            algorithm: account.algorithm(),
            digits: account.digits(),
            period_secs: account.period(),
        });
        expected_ids.push(vault.add(account));
    }
    vault.save(&store).expect("save 10k vault");
    let first_bytes = std::fs::read(&path).expect("read primary");
    assert!(
        (first_bytes.len() as u64) < PAYLOAD_CAP_BYTES,
        "primary file {} bytes must be < {} (Phase E cap)",
        first_bytes.len(),
        PAYLOAD_CAP_BYTES,
    );

    drop(vault);
    drop(store);

    let (reopened, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen 10k vault");
    let reopened_accounts: Vec<_> = reopened.iter().collect();
    assert_eq!(
        reopened_accounts.len(),
        ACCOUNT_COUNT,
        "reopened account count mismatch",
    );
    for (i, account) in reopened_accounts.iter().enumerate() {
        assert_eq!(
            account.id(),
            expected_ids[i],
            "id at index {i} must match insertion order",
        );
        let actual = AccountRow {
            label: account.label().to_string(),
            issuer: account.issuer().map(str::to_string),
            kind: account.kind(),
            algorithm: account.algorithm(),
            digits: account.digits(),
            period_secs: account.period(),
        };
        assert_eq!(actual, expected_rows[i], "row {i} mismatch after reopen");
    }

    reopened.save(&store).expect("re-save reopened vault");
    let second_bytes = std::fs::read(&path).expect("read primary after re-save");
    assert_eq!(
        first_bytes, second_bytes,
        "re-saved bytes must be byte-identical (bincode determinism at scale)",
    );
}
