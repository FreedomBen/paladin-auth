// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pre-/post-AEAD plaintext zeroization (DESIGN.md §4.4 / Phase F.14).
//
// Pins the §4.4 invariant that the bincode-serialized `VaultPayload`
// fed into `crypto::aead::aead_encrypt`, and the plaintext returned
// from `crypto::aead::aead_decrypt`, are both held in a wrapper whose
// `Drop` impl wipes the bytes *before* the underlying `Vec<u8>`
// deallocates. The wipe is observed via the `test-zeroize-witness`
// feature-gated witness in `crypto::zeroize_witness`.
//
// Three sub-cases:
//
// * encrypt path — `Store::create(path, VaultInit::Encrypted(_))`
//   serializes the freshly-created `VaultPayload`, hands it to the
//   `ZeroizingBytes` wrapper, and AEAD-encrypts the result. The
//   wrapper drops at end of `build_encrypted_on_disk`. The witness
//   records an `EncryptPreAead` site with `all_zero == true`.
// * decrypt success path — `Store::open` decrypts, decodes, and
//   drops the wrapper at end of `open_encrypted`. The witness
//   records a `DecryptPostAead` site with `all_zero == true`.
// * decrypt failure path — `_testing_write_encrypted_with_raw_plaintext`
//   produces a vault file whose AEAD authenticates but whose
//   post-AEAD plaintext is not a valid bincode `VaultPayload`. The
//   subsequent `Store::open` runs `decode_vault_payload` and fails
//   with `invalid_payload`; the wrapper still wipes its bytes via
//   the same scope-exit Drop. The witness records a
//   `DecryptPostAead` site with `all_zero == true`.

#![cfg(feature = "test-zeroize-witness")]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use paladin_core::zeroize_witness::{
    clear_observations, take_observations, Observation, WitnessSite,
};
use paladin_core::{
    Argon2Params, EncryptionOptions, ErrorKind, PaladinError, Store, VaultInit, VaultLock,
    _testing_write_encrypted_with_raw_plaintext,
};
use secrecy::SecretString;
use tempfile::TempDir;

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

fn cheap_params() -> Argon2Params {
    Argon2Params {
        m_kib: 8_192,
        t: 1,
        p: 1,
    }
}

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(pp(passphrase), cheap_params())
        .expect("cheap_params are in §4.4 bounds and the passphrase is non-empty")
}

fn vault_test_dir() -> TempDir {
    let dir = TempDir::new().expect("create tempdir");
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).expect("chmod tempdir 0700");
    dir
}

fn first_observation(obs: &[Observation], site: WitnessSite) -> &Observation {
    obs.iter()
        .find(|o| o.site == site)
        .unwrap_or_else(|| panic!("expected at least one {site:?} observation, got {obs:?}"))
}

#[test]
fn encrypted_create_zeroizes_pre_aead_payload_buffer() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");

    clear_observations();
    let (_vault, _store) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("create encrypted vault");

    let obs = take_observations();
    let o = first_observation(&obs, WitnessSite::EncryptPreAead);
    assert!(
        o.original_len > 0,
        "non-empty bincode payload (was {} bytes)",
        o.original_len
    );
    assert!(
        o.all_zero,
        "pre-AEAD plaintext buffer was not zeroized before deallocation: {o:?}"
    );
    // The bincode-encoded `VaultPayload` is bounded by the §4.3
    // 16 MiB cap.
    assert!(o.original_len <= 16 * 1024 * 1024);
    assert!(o.capacity >= o.original_len);
}

#[test]
fn encrypted_open_zeroizes_post_aead_plaintext_on_success() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");

    let (_vault, _store) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("create encrypted vault");

    clear_observations();
    let (_vault, _store) =
        Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("open encrypted vault");

    let obs = take_observations();
    let o = first_observation(&obs, WitnessSite::DecryptPostAead);
    assert!(
        o.original_len > 0,
        "decrypted plaintext was non-empty (was {} bytes)",
        o.original_len
    );
    assert!(
        o.all_zero,
        "post-AEAD plaintext buffer was not zeroized before deallocation on the \
         success path: {o:?}"
    );
}

#[test]
fn encrypted_open_zeroizes_post_aead_plaintext_on_decode_failure() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");

    // Garbage plaintext: not a valid bincode `VaultPayload`. The
    // helper AEAD-encrypts these bytes under the same passphrase /
    // cheap_params that the open path will derive, so AEAD
    // authenticates and the failure surfaces from
    // `decode_vault_payload`.
    let garbage: Vec<u8> = (0..256u32).map(|i| (i as u8) ^ 0xA5).collect();
    _testing_write_encrypted_with_raw_plaintext(&path, &pp("hunter2"), cheap_params(), &garbage)
        .expect("write encrypted vault with garbage plaintext");

    clear_observations();
    let err = Store::open(&path, VaultLock::Encrypted(pp("hunter2")))
        .expect_err("decode_vault_payload must reject the garbage payload");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidPayload,
        "expected invalid_payload (decode failed), got {err:?}"
    );
    if let PaladinError::InvalidPayload { reason } = &err {
        // `decode_failed`, `trailing_bytes`, and `exceeds_size_limit`
        // are all valid post-AEAD bincode failure modes the garbage
        // payload could provoke. The witness assertion below is what
        // actually matters — the wrapper must wipe its bytes
        // regardless of which reason fires.
        assert!(
            matches!(
                *reason,
                "decode_failed" | "trailing_bytes" | "exceeds_size_limit"
            ),
            "unexpected invalid_payload reason: {reason}"
        );
    }

    let obs = take_observations();
    let o = first_observation(&obs, WitnessSite::DecryptPostAead);
    assert_eq!(
        o.original_len,
        garbage.len(),
        "decrypted plaintext length matches the garbage we encrypted"
    );
    assert!(
        o.all_zero,
        "post-AEAD plaintext buffer was not zeroized before deallocation on the \
         decode-failure path: {o:?}"
    );

    // Sanity: no encrypt-side observation fired during a read-only open.
    assert!(
        obs.iter().all(|o| o.site != WitnessSite::EncryptPreAead),
        "open path must not fire EncryptPreAead observations"
    );
}
