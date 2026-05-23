// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Regular-save format invariants for encrypted vaults
// (docs/DESIGN.md §4.3 + §4.4).
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

mod common;

use common::test_tempdir;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use paladin_core::{
    inspect, parse_otpauth, Account, Argon2Params, EncryptionOptions, Store, VaultInit, VaultLock,
    VaultStatus,
};
use secrecy::SecretString;
use tempfile::TempDir;

// On-disk header offsets (docs/DESIGN.md §4.3). Mirrored from the tamper
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
    let dir = test_tempdir();
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

#[test]
fn header_round_trips_custom_argon2_params_across_in_range_triples() {
    // §4.4 round-trip — for several in-range parameter triples,
    // create with custom params, drop the `Vault`, re-open, and then
    // re-save. The bytes after the second save reflect the in-memory
    // header that was reconstructed from disk during `open`, so a
    // bit-identical match against the input triple proves the
    // `(m_kib, t, p)` fields survive write → header → read
    // losslessly. The successful re-open additionally proves the
    // parsed params re-derive the same AEAD key — any silent
    // narrowing (e.g. u16 instead of u32 for m_kib) or endianness
    // flip would surface here as `decrypt_failed` on re-open or a
    // mismatched LE byte block after re-save.
    //
    // Pins the §4.4 contract that an encrypted vault opened on a
    // different machine derives the same key. Triples cover the
    // §4.4 acceptance floor, default, mid-high, and ceiling — the
    // ceiling case in particular exercises the upper `m_kib` bytes
    // that no fixed-cost test exercises.
    let triples = [
        (8_192u32, 1u32, 1u32),
        (65_536, 3, 1),
        (262_144, 4, 2),
        (1_048_576, 10, 4),
    ];
    for (m_kib, t, p) in triples {
        let triple = (m_kib, t, p);
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let opts = EncryptionOptions::with_params(pp("hunter2"), Argon2Params { m_kib, t, p })
            .expect("triple is in §4.4 bounds");
        let (vault, store) = Store::create(&path, VaultInit::Encrypted(opts)).expect("create");

        // Sanity: the initial create wrote the requested params.
        let bytes_after_create = fs::read(&path).expect("read vault after create");
        assert_eq!(
            &bytes_after_create[M_KIB_RANGE.clone()],
            &m_kib.to_le_bytes(),
            "create-time m_kib LE encoding for {triple:?}",
        );
        assert_eq!(
            &bytes_after_create[T_RANGE.clone()],
            &t.to_le_bytes(),
            "create-time t LE encoding for {triple:?}",
        );
        assert_eq!(
            &bytes_after_create[P_RANGE.clone()],
            &p.to_le_bytes(),
            "create-time p LE encoding for {triple:?}",
        );

        drop(vault);
        drop(store);

        // Re-open parses the header into the in-memory `Store`. A
        // successful open additionally proves the parsed params
        // re-derive the same AEAD key (otherwise `decrypt_failed`).
        let (vault, store) = Store::open(&path, VaultLock::Encrypted(pp("hunter2")))
            .expect("re-open succeeds with the persisted params");

        // Re-save writes the in-memory params back to disk; bytes
        // after this save reflect the parsed in-memory state, not
        // the original create-time write.
        vault.save(&store).expect("re-save");
        let bytes_after_resave = fs::read(&path).expect("read vault after re-save");
        assert_eq!(
            &bytes_after_resave[M_KIB_RANGE.clone()],
            &m_kib.to_le_bytes(),
            "in-memory m_kib bit-identical after re-open + re-save for {triple:?}",
        );
        assert_eq!(
            &bytes_after_resave[T_RANGE.clone()],
            &t.to_le_bytes(),
            "in-memory t bit-identical after re-open + re-save for {triple:?}",
        );
        assert_eq!(
            &bytes_after_resave[P_RANGE.clone()],
            &p.to_le_bytes(),
            "in-memory p bit-identical after re-open + re-save for {triple:?}",
        );
    }
}

#[test]
fn create_generates_fresh_salt_and_nonce_across_n_creates() {
    // F.12 — `Store::create` must draw a fresh CSPRNG `salt` and a
    // fresh `nonce` per creation. With the same passphrase, payload
    // (empty after create), and Argon2 params, two creates that
    // collide on `salt` would derive the same AEAD key — defeating
    // the §4.4 contract that each new encrypted vault has independent
    // crypto material — and two creates that collide on `nonce` would
    // expose related-message attacks if any future regression caused
    // a key collision. Both must be pairwise distinct, separately
    // from the regular-save nonce-rotation property pinned in
    // `regular_save_preserves_argon2_params_and_salt_across_n_saves`
    // (which fixes the salt and rotates only the nonce). Each
    // resulting vault is also re-opened to prove the freshly written
    // header is self-consistent (no bytes off-by-offset).
    const N: usize = 64;
    let mut observed_salts: HashSet<Vec<u8>> = HashSet::with_capacity(N);
    let mut observed_nonces: HashSet<Vec<u8>> = HashSet::with_capacity(N);
    for i in 0..N {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (_v, _s) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2")))
            .unwrap_or_else(|e| panic!("create iteration {i}: {e:?}"));
        let bytes = fs::read(&path).expect("read vault");
        let salt = bytes[SALT_RANGE.clone()].to_vec();
        let nonce = bytes[NONCE_RANGE.clone()].to_vec();
        assert!(
            observed_salts.insert(salt),
            "salt collision at iteration {i}: §4.4 fresh-material contract violated",
        );
        assert!(
            observed_nonces.insert(nonce),
            "nonce collision at iteration {i}: §4.4 fresh-material contract violated",
        );
        let (_v2, _s2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2")))
            .unwrap_or_else(|e| panic!("re-open iteration {i}: {e:?}"));
    }
    assert_eq!(observed_salts.len(), N);
    assert_eq!(observed_nonces.len(), N);
}

#[test]
fn create_force_generates_fresh_salt_and_nonce_across_n_creates() {
    // F.12 — same fresh-material contract for the staged-clobber
    // entry point. Each iteration uses a fresh tempdir with no prior
    // primary so this exercises `create_force`'s own randomness path
    // rather than reusing the `Store::create` material covered above.
    const N: usize = 64;
    let mut observed_salts: HashSet<Vec<u8>> = HashSet::with_capacity(N);
    let mut observed_nonces: HashSet<Vec<u8>> = HashSet::with_capacity(N);
    for i in 0..N {
        let dir = vault_test_dir();
        let path = dir.path().join("vault.bin");
        let (_v, _s) = Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2")))
            .unwrap_or_else(|e| panic!("create_force iteration {i}: {e:?}"));
        let bytes = fs::read(&path).expect("read vault");
        let salt = bytes[SALT_RANGE.clone()].to_vec();
        let nonce = bytes[NONCE_RANGE.clone()].to_vec();
        assert!(
            observed_salts.insert(salt),
            "salt collision at iteration {i}: §4.4 fresh-material contract violated",
        );
        assert!(
            observed_nonces.insert(nonce),
            "nonce collision at iteration {i}: §4.4 fresh-material contract violated",
        );
        let (_v2, _s2) = Store::open(&path, VaultLock::Encrypted(pp("hunter2")))
            .unwrap_or_else(|e| panic!("re-open iteration {i}: {e:?}"));
    }
    assert_eq!(observed_salts.len(), N);
    assert_eq!(observed_nonces.len(), N);
}

#[test]
fn create_force_writes_custom_argon2_params_to_header_with_no_prior_file() {
    // F.11 — `Store::create_force` accepts custom validated Argon2
    // params via `EncryptionOptions::with_params` and persists them
    // verbatim into the on-disk header. The `create` side is pinned
    // by `header_round_trips_custom_argon2_params_across_in_range_triples`;
    // without a parallel `create_force` assertion, the staged-clobber
    // entry point could silently fall back to defaults. `cheap_params`
    // differs from §4.4 defaults (`65_536, 3, 1`), so a fall-back
    // surfaces as a mismatching `m_kib` / `t` byte block.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    assert!(!path.exists(), "no prior primary present");
    let params = cheap_params();
    let (_v, _s) = Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("create_force");
    let bytes = fs::read(&path).expect("read vault");
    assert_eq!(
        &bytes[M_KIB_RANGE.clone()],
        &params.m_kib.to_le_bytes(),
        "create_force-time m_kib LE encoding"
    );
    assert_eq!(
        &bytes[T_RANGE.clone()],
        &params.t.to_le_bytes(),
        "create_force-time t LE encoding"
    );
    assert_eq!(
        &bytes[P_RANGE.clone()],
        &params.p.to_le_bytes(),
        "create_force-time p LE encoding"
    );
    // Re-open with the parsed in-header params re-derives the same
    // AEAD key — silent narrowing or an endianness flip would surface
    // here as `decrypt_failed`.
    let (_v2, _s2) =
        Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("re-open succeeds");
}

#[test]
fn create_force_writes_custom_argon2_params_to_header_when_clobbering_existing_primary() {
    // F.11 — clobber path: a plaintext primary already exists at the
    // vault path; `create_force` replaces it with an encrypted vault
    // built from custom validated Argon2 params. The post-clobber
    // on-disk header bytes must reflect the supplied params, not the
    // prior plaintext file (which had no Argon2 cost) and not the
    // §4.4 defaults.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (pv, ps) = Store::create(&path, VaultInit::Plaintext).expect("seed plaintext primary");
    pv.save(&ps).expect("plaintext save");
    assert!(path.exists(), "plaintext primary staged");

    let params = cheap_params();
    let (_v, _s) = Store::create_force(&path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("create_force clobber");
    let bytes = fs::read(&path).expect("read vault after clobber");
    assert_eq!(
        &bytes[M_KIB_RANGE.clone()],
        &params.m_kib.to_le_bytes(),
        "post-clobber m_kib LE encoding"
    );
    assert_eq!(
        &bytes[T_RANGE.clone()],
        &params.t.to_le_bytes(),
        "post-clobber t LE encoding"
    );
    assert_eq!(
        &bytes[P_RANGE.clone()],
        &params.p.to_le_bytes(),
        "post-clobber p LE encoding"
    );
    let (_v2, _s2) =
        Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("re-open succeeds");
}

#[test]
fn encrypted_header_lays_out_24_byte_nonce_slot_at_offset_40() {
    // §4.4 AEAD output shape — XChaCha20-Poly1305 uses a 24-byte
    // nonce, not the IETF ChaCha20-Poly1305 12-byte construct. Pin
    // the on-disk layout so a swap to a different AEAD construct
    // (which would shorten the header) fails this test instead of
    // silently re-shaping the file format.
    //
    // §4.3 encrypted-mode header layout (10 + 54 = 64 bytes):
    //   magic(8) format_ver(1) mode(1)            → offsets  0..10
    //   kdf_id(1)                                 → offset  10..11
    //   m_kib(4) t(4) p(4)                        → offsets 11..23
    //   salt(16)                                  → offsets 23..39
    //   aead_id(1)                                → offset  39..40
    //   nonce(24)                                 → offsets 40..64
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (_v, _s) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    let bytes = fs::read(&path).expect("read vault");

    assert_eq!(ENCRYPTED_HEADER_LEN, 64, "encrypted header length is 64");
    assert_eq!(NONCE_RANGE.start, 40, "nonce slot starts at byte 40");
    assert_eq!(
        NONCE_RANGE.end, 64,
        "nonce slot ends at byte 64 (exclusive)"
    );
    assert_eq!(
        NONCE_RANGE.end - NONCE_RANGE.start,
        24,
        "XChaCha20-Poly1305 nonce slot is exactly 24 bytes wide"
    );

    // The on-disk file must include at least the full encrypted
    // header so the nonce slot is fully present.
    assert!(
        bytes.len() >= ENCRYPTED_HEADER_LEN,
        "encrypted vault file must be at least {ENCRYPTED_HEADER_LEN} bytes (header), got {}",
        bytes.len()
    );
    let nonce_slot = &bytes[NONCE_RANGE];
    assert_eq!(nonce_slot.len(), 24, "on-disk nonce slot is 24 bytes wide");
}

/// §4.3 wire format — a freshly written encrypted vault places its
/// 64-byte encrypted-mode header (10-byte plaintext header + KDF/AEAD
/// trailer) at offsets `0..64`, with the AEAD ciphertext+tag starting
/// at byte 64. Mirrors the plaintext-header layout test in
/// `vault_lifecycle.rs` and complements
/// `encrypted_save_writes_body_equal_to_payload_plus_aead_tag` by
/// pinning the header/ciphertext boundary independently of the body
/// shape assertion.
#[test]
fn encrypted_save_writes_exact_64_byte_header_then_ciphertext() {
    const PLAINTEXT_HEADER_LEN: usize = 10;
    const AEAD_TAG_LEN: usize = 16;

    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (_v, _s) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).expect("create");
    let bytes = fs::read(&path).expect("read encrypted vault");

    // The encrypted header is exactly 64 bytes: 10-byte plaintext
    // header + 54-byte KDF/AEAD trailer.
    assert!(
        bytes.len() >= ENCRYPTED_HEADER_LEN,
        "encrypted vault must contain at least the 64-byte header, got {} bytes",
        bytes.len()
    );
    // First 8 bytes are the magic, byte 8 is format_ver, byte 9 is mode.
    assert_eq!(&bytes[0..8], b"PALADIN\0", "magic at bytes 0..8");
    assert_eq!(bytes[8], 1, "format_ver=1 at byte 8");
    assert_eq!(bytes[9], 1, "mode=1 (encrypted) at byte 9");
    assert_eq!(
        bytes[..PLAINTEXT_HEADER_LEN].len(),
        PLAINTEXT_HEADER_LEN,
        "plaintext header occupies bytes 0..10"
    );
    // Byte 10 is the kdf_id (= Argon2id = 1).
    assert_eq!(bytes[10], 1, "kdf_id=Argon2id at byte 10");
    // Byte 39 is the aead_id (= XChaCha20-Poly1305 = 1).
    assert_eq!(bytes[39], 1, "aead_id=XChaCha20-Poly1305 at byte 39");
    // The AEAD ciphertext+tag begins at byte 64.
    assert!(
        bytes.len() >= ENCRYPTED_HEADER_LEN + AEAD_TAG_LEN,
        "file must contain at least the 16-byte AEAD tag past the header"
    );
    let ct_and_tag = &bytes[ENCRYPTED_HEADER_LEN..];
    assert!(
        !ct_and_tag.is_empty(),
        "ciphertext+tag region after the 64-byte header must not be empty"
    );
}

/// §4.3 on-disk size cap — any encrypted vault file whose total size
/// exceeds `ENCRYPTED_HEADER_LEN + 16 MiB + 16-byte AEAD tag` is
/// rejected with `invalid_payload` / `exceeds_size_limit` *before*
/// the header parse, KDF derivation, or AEAD decryption runs. The
/// pre-KDF guarantee is asserted by feeding the same oversized file
/// to `Store::open` with the *wrong* passphrase: a regression that
/// moved the cap below the header parse or after the AEAD step would
/// surface `invalid_header`, `kdf_params_out_of_bounds`, or
/// `decrypt_failed` instead.
#[test]
fn encrypted_open_rejects_file_above_on_disk_size_cap_before_kdf_and_aead() {
    use paladin_core::ErrorKind;

    const AEAD_TAG_LEN: usize = 16;
    const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

    // Build a real encrypted header so the only failure axis is the
    // file size, not the header bytes themselves.
    let header_dir = vault_test_dir();
    let header_path = header_dir.path().join("vault.bin");
    let (_v, _s) = Store::create(&header_path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("seed encrypted header");
    let real_bytes = fs::read(&header_path).expect("read seed vault");
    assert!(
        real_bytes.len() >= ENCRYPTED_HEADER_LEN,
        "seed vault must include the full 64-byte encrypted header"
    );
    let real_header: [u8; ENCRYPTED_HEADER_LEN] = real_bytes[..ENCRYPTED_HEADER_LEN]
        .try_into()
        .expect("first 64 bytes of seed vault");

    // Construct an oversized file: header + 16 MiB + 17 bytes (the
    // smallest possible value > the cap). The body is filler — no
    // valid AEAD payload — but that should not matter because the
    // size check fires before AEAD ever sees the bytes.
    let oversize_len = ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + AEAD_TAG_LEN + 1;
    let mut oversize = vec![0u8; oversize_len];
    oversize[..ENCRYPTED_HEADER_LEN].copy_from_slice(&real_header);

    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    fs::write(&path, &oversize).expect("write oversize encrypted vault");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("0600 vault perms");

    // Right passphrase — must surface invalid_payload before any KDF
    // or AEAD work.
    let err_right = Store::open(&path, VaultLock::Encrypted(pp("hunter2")))
        .expect_err("oversized file must not open even with the right passphrase");
    assert_eq!(
        err_right.kind(),
        ErrorKind::InvalidPayload,
        "oversize file must surface invalid_payload, got {err_right:?}"
    );

    // Wrong passphrase — must surface the same error code, proving
    // the size check fires before any KDF/AEAD work (otherwise we'd
    // see decrypt_failed here).
    let err_wrong = Store::open(&path, VaultLock::Encrypted(pp("not-the-right-one")))
        .expect_err("oversized file must not open with wrong passphrase either");
    assert_eq!(
        err_wrong.kind(),
        ErrorKind::InvalidPayload,
        "oversize file must reject before AEAD; got {err_wrong:?}"
    );
    assert_eq!(
        err_right.kind(),
        err_wrong.kind(),
        "right and wrong passphrase must hit the same pre-KDF size guard"
    );

    // Boundary check: a file exactly at the cap (header + 16 MiB +
    // 16 tag) is accepted by the on-disk cap and proceeds past the
    // size guard. The body is still garbage so the open will fail
    // later — we just need it NOT to be invalid_payload, proving the
    // cap is `>` not `>=`.
    let at_cap_len = ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + AEAD_TAG_LEN;
    let mut at_cap = vec![0u8; at_cap_len];
    at_cap[..ENCRYPTED_HEADER_LEN].copy_from_slice(&real_header);
    let dir2 = vault_test_dir();
    let path2 = dir2.path().join("vault.bin");
    fs::write(&path2, &at_cap).expect("write at-cap encrypted vault");
    fs::set_permissions(&path2, fs::Permissions::from_mode(0o600)).expect("0600 vault perms");
    let err_at_cap = Store::open(&path2, VaultLock::Encrypted(pp("hunter2")))
        .expect_err("at-cap file with garbage body must still fail to open");
    assert_ne!(
        err_at_cap.kind(),
        ErrorKind::InvalidPayload,
        "at-cap file must clear the on-disk size guard; failure should come from AEAD or decode, not invalid_payload (got {err_at_cap:?})"
    );
}

// AEAD `ciphertext.len() == plaintext.len() + 16` invariant at the
// smallest possible plaintext: a vault with zero accounts and the
// default `VaultSettings`. Independent of any account-bearing test:
// pins the boundary case the `AEAD output shape` test in
// `src/crypto/aead.rs` only covers via property tests, and pins that
// the pre-AEAD plaintext-payload buffer is still wiped when the
// payload is the minimum bincode-encoded `VaultPayload`.
#[test]
fn encrypted_save_empty_vault_ciphertext_is_exactly_tag_length() {
    // bincode v2 layout for an empty `VaultPayload` (fixed-int LE):
    //   accounts: Vec<Account> empty  → u64 LE len = 0       (8 bytes)
    //   settings: VaultSettings::default()
    //     auto_lock_enabled = false   → u8 = 0               (1 byte)
    //     auto_lock_timeout_secs = 300 → u32 LE              (4 bytes)
    //     clipboard_clear_enabled = false → u8 = 0           (1 byte)
    //     clipboard_clear_secs = 20   → u32 LE               (4 bytes)
    // Sum: 18 bytes plaintext, followed by the 16-byte Poly1305 tag,
    // preceded by the 64-byte §4.3 encrypted header.
    const EMPTY_PAYLOAD_LEN: usize = 8 + 1 + 4 + 1 + 4;
    const AEAD_TAG_LEN: usize = 16;

    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");

    #[cfg(feature = "test-zeroize-witness")]
    paladin_core::zeroize_witness::clear_observations();

    let (vault, store) = Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2")))
        .expect("create empty encrypted vault");
    vault.save(&store).expect("save empty encrypted vault");

    let bytes = fs::read(&path).expect("read encrypted vault");
    assert_eq!(
        bytes.len(),
        ENCRYPTED_HEADER_LEN + EMPTY_PAYLOAD_LEN + AEAD_TAG_LEN,
        "empty-payload AEAD file size must equal 64 (header) + {EMPTY_PAYLOAD_LEN} (bincode payload) + 16 (Poly1305 tag); got {bytes_len}",
        bytes_len = bytes.len(),
    );

    #[cfg(feature = "test-zeroize-witness")]
    {
        use paladin_core::zeroize_witness::{take_observations, WitnessSite};
        let obs = take_observations();
        let pre_aead: Vec<_> = obs
            .iter()
            .filter(|o| o.site == WitnessSite::EncryptPreAead)
            .collect();
        assert!(
            !pre_aead.is_empty(),
            "expected at least one EncryptPreAead witness on the empty-payload write path"
        );
        assert!(
            pre_aead.iter().any(|o| o.all_zero),
            "EncryptPreAead observation must report all_zero == true even for an empty-payload bincode encoding"
        );
    }

    drop(vault);
    drop(store);

    let (reopened, _store) =
        Store::open(&path, VaultLock::Encrypted(pp("hunter2"))).expect("reopen");
    assert_eq!(
        reopened.iter().count(),
        0,
        "reopened vault has zero accounts"
    );
    assert_eq!(
        inspect(&path).expect("inspect"),
        VaultStatus::Encrypted,
        "inspect reports Encrypted for the round-tripped empty vault"
    );
}
