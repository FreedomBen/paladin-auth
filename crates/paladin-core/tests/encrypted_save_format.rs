// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Regular-save format invariants for encrypted vaults
// (DESIGN.md §4.3 + §4.4).
//
// Pin the on-disk encrypted-vault format properties that survive a
// regular `Vault::save`:
//
//   * Argon2 cost params and `salt` are preserved verbatim across
//     saves; only the AEAD `nonce` and ciphertext rotate.
//   * Each save draws a fresh 24-byte CSPRNG nonce, so two consecutive
//     saves of the same vault produce byte-distinct
//     ciphertext-and-tag regions while still re-opening to the same
//     account contents.
//   * The `m_kib`, `t`, `p` header fields are encoded little-endian
//     regardless of host byte order, so encrypted vaults round-trip
//     across architectures.
//
// Together these pin §4.3 wire format and §4.4 fresh-nonce-per-save
// against silent regressions.

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    parse_otpauth, Account, Argon2Params, EncryptionOptions, Store, VaultInit, VaultLock,
};
use secrecy::SecretString;
use tempfile::TempDir;

// On-disk header offsets (DESIGN.md §4.3). Mirrored from the tamper
// matrix so a refactor of one keeps the other honest.
const ENCRYPTED_HEADER_LEN: usize = 64;
const M_KIB_RANGE: std::ops::Range<usize> = 11..15;
const T_RANGE: std::ops::Range<usize> = 15..19;
const P_RANGE: std::ops::Range<usize> = 19..23;
const SALT_RANGE: std::ops::Range<usize> = 23..39;
const NONCE_RANGE: std::ops::Range<usize> = 40..64;

fn fixture_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn make_account(label: &str, issuer: Option<&str>) -> Account {
    let issuer_part = issuer.map(|i| format!("{i}:")).unwrap_or_default();
    let uri = format!("otpauth://totp/{issuer_part}{label}?secret=JBSWY3DPEHPK3PXP");
    parse_otpauth(&uri, fixture_now()).unwrap().account
}

fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
    dir
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(pp(passphrase), cheap_params())
        .expect("cheap_params are in §4.4 bounds and the passphrase is non-empty")
}

#[test]
fn regular_save_preserves_argon2_params_and_salt_across_n_saves() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    vault.add(make_account("alice", Some("Acme")));
    vault.save(&store).expect("initial save");

    let baseline = fs::read(&path).expect("read baseline vault");
    let baseline_salt = baseline[SALT_RANGE.clone()].to_vec();
    let baseline_m_kib = baseline[M_KIB_RANGE.clone()].to_vec();
    let baseline_t = baseline[T_RANGE.clone()].to_vec();
    let baseline_p = baseline[P_RANGE.clone()].to_vec();

    let mut observed_nonces: HashSet<Vec<u8>> = HashSet::new();
    observed_nonces.insert(baseline[NONCE_RANGE.clone()].to_vec());

    // 64 total saves of the same vault; key cache means Argon2id runs
    // exactly once during create, so the loop is fast enough.
    for i in 1..64 {
        vault
            .save(&store)
            .unwrap_or_else(|e| panic!("save {i}: {e:?}"));
        let bytes = fs::read(&path).expect("read vault after save");

        assert_eq!(
            bytes[SALT_RANGE.clone()],
            baseline_salt[..],
            "salt must be byte-identical across saves (save {i})"
        );
        assert_eq!(
            bytes[M_KIB_RANGE.clone()],
            baseline_m_kib[..],
            "m_kib must be preserved (save {i})"
        );
        assert_eq!(
            bytes[T_RANGE.clone()],
            baseline_t[..],
            "t must be preserved (save {i})"
        );
        assert_eq!(
            bytes[P_RANGE.clone()],
            baseline_p[..],
            "p must be preserved (save {i})"
        );

        let nonce = bytes[NONCE_RANGE.clone()].to_vec();
        assert!(
            observed_nonces.insert(nonce),
            "nonce must be pairwise distinct across saves (save {i})"
        );
    }
    assert_eq!(observed_nonces.len(), 64, "all 64 nonces are distinct");

    // Final round-trip: the last on-disk vault still opens with the
    // same passphrase and yields the inserted account.
    drop(vault);
    drop(store);
    let (reopened, _store) =
        Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("reopen");
    assert_eq!(reopened.accounts().len(), 1);
    assert_eq!(reopened.accounts()[0].label(), "alice");
}

#[test]
fn two_consecutive_saves_produce_byte_distinct_ciphertext_and_tag() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    vault.add(make_account("bob", Some("Acme")));
    vault.save(&store).expect("first save");
    let first = fs::read(&path).expect("read first save");

    vault.save(&store).expect("second save");
    let second = fs::read(&path).expect("read second save");

    assert_eq!(first.len(), second.len(), "vault size unchanged");
    assert_eq!(
        first[SALT_RANGE.clone()],
        second[SALT_RANGE.clone()],
        "salt is preserved across saves"
    );
    assert_ne!(
        first[NONCE_RANGE.clone()],
        second[NONCE_RANGE.clone()],
        "nonce rotates per save"
    );

    let first_body = &first[ENCRYPTED_HEADER_LEN..];
    let second_body = &second[ENCRYPTED_HEADER_LEN..];
    assert_ne!(
        first_body, second_body,
        "ciphertext + AEAD tag must differ between saves under fresh nonce"
    );

    // Both files re-open to the same account contents (proving the
    // underlying VaultPayload is unchanged across saves).
    drop(vault);
    drop(store);

    let (v1, _s1) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("reopen first");
    let id1 = v1.accounts()[0].id();
    let label1 = v1.accounts()[0].label().to_string();
    let issuer1 = v1.accounts()[0].issuer().map(str::to_string);
    drop(v1);

    fs::write(&path, &second).expect("rewrite second bytes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
    let (v2, _s2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("reopen second");
    assert_eq!(v2.accounts().len(), 1);
    assert_eq!(v2.accounts()[0].id(), id1);
    assert_eq!(v2.accounts()[0].label(), label1);
    assert_eq!(v2.accounts()[0].issuer().map(str::to_string), issuer1);
}

#[test]
fn header_writes_argon2_params_in_little_endian_for_default_cost() {
    // §4.4 default params: m_kib = 65_536, t = 3, p = 1.
    // Expected little-endian byte patterns regardless of host
    // architecture.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let opts = EncryptionOptions::with_params(
        pp("hunter2"),
        Argon2Params {
            m_kib: 65_536,
            t: 3,
            p: 1,
        },
    )
    .expect("default-shaped params are in bounds");
    let (_v, _s) = Store::create(&path, VaultInit::Encrypted(opts)).expect("create");
    let bytes = fs::read(&path).expect("read vault");

    assert_eq!(
        &bytes[M_KIB_RANGE.clone()],
        &[0x00, 0x00, 0x01, 0x00],
        "m_kib = 65_536 little-endian"
    );
    assert_eq!(
        &bytes[T_RANGE.clone()],
        &[0x03, 0x00, 0x00, 0x00],
        "t = 3 little-endian"
    );
    assert_eq!(
        &bytes[P_RANGE.clone()],
        &[0x01, 0x00, 0x00, 0x00],
        "p = 1 little-endian"
    );
}

#[test]
fn header_writes_argon2_params_in_little_endian_for_floor_m_kib() {
    // Second fixture: m_kib at the §4.4 acceptance floor (8_192).
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (_v, _s) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    let bytes = fs::read(&path).expect("read vault");

    assert_eq!(
        &bytes[M_KIB_RANGE.clone()],
        &[0x00, 0x20, 0x00, 0x00],
        "m_kib = 8_192 little-endian"
    );
    assert_eq!(
        &bytes[T_RANGE.clone()],
        &[0x01, 0x00, 0x00, 0x00],
        "t = 1 little-endian"
    );
    assert_eq!(
        &bytes[P_RANGE.clone()],
        &[0x01, 0x00, 0x00, 0x00],
        "p = 1 little-endian"
    );
}
