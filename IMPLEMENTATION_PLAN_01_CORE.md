# Implementation Plan 01 — `paladin-core`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4, §10, §11 (Milestones 1–3).
Status: pre-implementation. This plan stays grounded in DESIGN.md and does not
invent any path, type, or API beyond what is specified there.

## Scope

`paladin-core` is the shared library all three binaries depend on. It owns:

- The domain model (§4.1).
- OTP generation (§4.2).
- On-disk vault format and the `Store` persistence handle (§4.3).
- Crypto module: Argon2id KDF + XChaCha20-Poly1305 AEAD (§4.4).
- Passphrase management transitions (§4.5).
- Import / export (§4.6).
- The public API sketched in §4.7.

Binaries depend **only** on `paladin-core`. Anything reused across two front-ends
must live here, not in a sibling crate.

## Crate layout

```
crates/paladin-core/
├── Cargo.toml            # license = "AGPL-3.0-or-later"
├── src/
│   ├── lib.rs            # re-exports public surface from §4.7
│   ├── error.rs          # PaladinError + Result alias; JSON-stable error_kind tags
│   ├── domain/
│   │   ├── mod.rs        # Account, AccountId, Algorithm, OtpKind, Code
│   │   ├── secret.rs     # Secret newtype with Zeroize + Drop
│   │   ├── validation.rs # Shared Account validation (labels, secrets, periods…)
│   │   └── slug.rs       # icon_hint slug rules + issuer-derived defaulting
│   ├── otp/
│   │   ├── mod.rs        # pure OTP primitives (compute_totp, compute_hotp)
│   │   ├── totp.rs       # RFC 6238
│   │   └── hotp.rs       # RFC 4226
│   ├── otpauth/
│   │   ├── mod.rs        # otpauth:// parser + emitter
│   │   └── tests.rs      # round-trip + edge cases
│   ├── storage/
│   │   ├── mod.rs        # Store, atomic-write pipeline, .bak rotation
│   │   ├── header.rs     # PALADIN\0 magic, format_ver, mode, KDF/AEAD ids, AAD
│   │   ├── payload.rs    # bincode v2 VaultPayload encode/decode (16 MiB cap)
│   │   ├── perms_unix.rs # 0600/0700 enforcement (Linux v0.1)
│   │   └── perms_other.rs# Stubs for non-Unix targets
│   ├── crypto/
│   │   ├── mod.rs        # KDF + AEAD facades
│   │   ├── argon2.rs     # Argon2id with header-tunable params + bounds check
│   │   └── aead.rs       # XChaCha20-Poly1305 with header-AAD wiring
│   ├── vault.rs          # Vault impl: add/remove/iter/rename/totp_code/hotp_*
│   ├── settings.rs       # VaultSettings (auto-lock, clipboard) + setters
│   ├── passphrase.rs     # set / change / remove transitions, rollback
│   ├── import/
│   │   ├── mod.rs        # detect(), facade
│   │   ├── otpauth.rs    # URI / line-list / JSON-array (handles Gnome plaintext)
│   │   ├── aegis.rs      # plaintext JSON; encrypted returns unsupported error
│   │   ├── paladin.rs    # encrypted Paladin bundle
│   │   └── qr.rs         # rqrr + image
│   ├── export/
│   │   ├── mod.rs        # facade
│   │   ├── otpauth.rs    # JSON array of otpauth:// URIs
│   │   └── encrypted.rs  # Paladin encrypted bundle
│   └── time.rs           # SystemTime helpers (epoch math, overflow rejection)
└── tests/
    ├── rfc_vectors.rs    # RFC 6238 App. B, RFC 4226 App. D
    ├── otpauth_roundtrip.rs
    ├── vault_roundtrip.rs   # both modes
    ├── tamper.rs            # AAD-bound header byte-flip matrix
    ├── perms.rs             # 0600/0700 + unsafe_permissions rejection
    ├── passphrase.rs        # all three transitions + rollback
    ├── import_otpauth.rs
    ├── import_aegis.rs
    ├── import_paladin.rs
    ├── import_qr.rs
    └── zeroize.rs           # drop-then-poke assertions
```

## Milestone sequencing (TDD: red → green → refactor)

Each step lands as its own commit. Tests come first.

### Phase A — Scaffolding

- [ ] Create virtual workspace `Cargo.toml` (members: `paladin-core` only at this
  point; binaries added in their own plans).
- [ ] Create `crates/paladin-core/Cargo.toml` with `license`,
  `rust-version` (MSRV decision: pin to current stable at scaffold time and
  record it in CLAUDE.md).
- [ ] Add SPDX header to every source file.
- [ ] Wire `cargo deny` policy: deny `tokio`, `reqwest`, `hyper`, anything that
  pulls a network stack — enforces the §4.4 / §13 "no network" rule.
- [ ] CI workflow stub: `fmt --check`, `clippy -- -D warnings`, `test --all`,
  `cargo deny check`, `cargo audit`.

### Phase B — Domain model + validation (Milestone 1, part 1)

- [ ] Tests: `domain/validation.rs` covering every branch in §4.1 (digits range,
  TOTP period bounds, HOTP counter overflow, empty labels, malformed icon-hint
  slugs, mismatched otpauth issuers, invalid timestamps; short-secret warnings
  in 10–15 byte range).
- [ ] Implement `Account`, `AccountId` (UUIDv4 stored as 16 bytes, hyphenated
  canonical `Display`; the CLI computes any short-prefix disambiguator at
  render time since uniqueness depends on full vault contents the library
  doesn't curate), `Secret` newtype with `Zeroize + Drop`, `Algorithm`,
  `OtpKind`, `Code`.
- [ ] No `Debug` impls that print secret bytes — wire a derive-audit test that
  greps the build output for `impl Debug` on `Secret`/`SecretString` fields.
- [ ] Define `error.rs` `PaladinError` to carry only the core-returnable
  §5 kinds: `validation_error`, `invalid_passphrase`, `invalid_state`,
  `vault_missing`, `vault_exists`, `unsafe_permissions`, `wrong_vault_lock`,
  `decrypt_failed`, `invalid_header`, `invalid_payload`,
  `unsupported_format_version`, `kdf_params_out_of_bounds`,
  `unsupported_import_format`, `unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `no_entries_to_import`, `duplicate_account`, `counter_overflow`,
  `time_range`, `save_not_committed`, `save_durability_unconfirmed`, and
  `io_error`. The CLI-only kinds (`clipboard_write_failed`, `no_match`,
  `multiple_matches`) are owned by the CLI plan and never returned from
  core.

### Phase C — OTP generation (Milestone 1, part 2)

- [ ] Tests: RFC 6238 Appendix B vectors (SHA1/256/512); RFC 4226 Appendix D.
- [ ] Tests: TOTP boundary semantics — half-open `[valid_from, valid_until)`,
  `seconds_remaining ∈ 1..=period`, exact-boundary selects new counter and
  reports full period, pre-epoch rejection, `valid_until` overflow rejection.
- [ ] Implement pure OTP primitives in `otp/`: TOTP code given (secret,
  algorithm, period, digits, now); HOTP code given (secret, algorithm,
  digits, counter). These are state-free and never persist. The Vault
  methods `totp_code`, `hotp_peek`, and `hotp_advance` (Phase G) route
  through them; only `hotp_advance` mutates and persists.

### Phase D — `otpauth://` parser/emitter (Milestone 1, part 3)

- [ ] Tests: scheme/type case-insensitivity; required label trimming +
  percent-decoding; first-`:` issuer split + issuer-rule normalization;
  base32 RFC 4648 with optional `=` padding; algorithm/digits/period/counter
  defaults and ranges; rejection of `period` on HOTP and `counter` on TOTP;
  duplicate known parameters rejected; unknown parameters ignored.
- [ ] Round-trip: parse → emit → parse equals original.

### Phase E — Plaintext storage (Milestone 1, part 4)

- [ ] Tests: round-trip of `VaultPayload` through bincode v2 with the exact
  config from §4.3; full-input-consumption rejection; 16 MiB payload limit.
- [ ] Tests: file written `0600`, parent created `0700`, atomic write via
  same-directory tempfile + rename, `.bak` rotated on each save (one
  generation), `unsafe_permissions` rejection at `open` and `create` (parent
  directory + primary + backup). The typed `unsafe_permissions` error
  carries `path`, `subject` (one of `vault_dir`, `vault_file`,
  `backup_file`), `actual_mode`, and `expected_mode` (mode strings as
  four-digit octal, e.g. `"0644"`); chmod-command formatting is CLI plan
  scope.
- [ ] Implement `Store` (open/save), permissions module (Unix path; non-Unix
  stubs that compile but reject with a clear error), atomic-write pipeline.
- [ ] Implement `inspect(path)` (header probe, no decryption, no perms check).

### Phase F — Encrypted storage (Milestone 1, part 5)

- [ ] Tests: header byte layout (10-byte plaintext header, 64-byte encrypted
  header pre-ciphertext); on-disk size cap (`header_size + 16 MiB [+ 16-byte
  tag]`) before any KDF/AEAD work.
- [ ] Tests: AAD binding — flipping any byte in `format_ver`, `mode`,
  `kdf_id`, Argon2 params, `salt`, `aead_id`, or `nonce` causes decryption
  to fail; flipping a ciphertext byte fails; flipping the AEAD tag fails.
- [ ] Tests: Argon2 parameter bounds rejected before any KDF work.
- [ ] Tests: regular encrypted saves preserve the in-header Argon2 params
  and `salt`, and use a freshly generated random `nonce` per save (drawn
  from the OS CSPRNG).
- [ ] Tests: AEAD key caching — `open` derives the 32-byte key once into
  a `Zeroizing<[u8; 32]>` cached on `Vault` alongside the `SecretString`
  passphrase; subsequent saves reuse the cached key without re-running
  Argon2id (assert via Argon2 invocation counter or timing budget); both
  fields are zeroized when `Vault` drops. Plaintext vaults hold no cached
  key or passphrase.
- [ ] Implement `crypto::argon2` (defaults m=64 MiB, t=3, p=1 with bounds),
  `crypto::aead` (XChaCha20-Poly1305 with header bytes serialized as AAD),
  encrypted `Store` save/open paths, and the cached-key data model on
  `Vault`.

### Phase G — Vault behavior + settings (Milestone 1, part 6)

- [ ] Tests: `add` / `remove` / `iter` (insertion order) / `rename` semantics;
  `rename` updates `updated_at`; settings setters validate timeout ranges.
- [ ] Tests: `hotp_advance` rollback — inject a `Store` save error before
  primary commit point and assert in-memory counter and `updated_at` revert
  to pre-call values; durability-unconfirmed surfaced as a typed error after
  commit point.
- [ ] Implement `Vault` operations and `VaultSettings` setters per §4.7.

### Phase H — Passphrase management (Milestone 2)

- [ ] Tests: `set_passphrase` (plaintext → encrypted), `change_passphrase`
  (encrypted → encrypted), `remove_passphrase` (encrypted → plaintext); each
  uses fresh salt + nonce; `.bak` is re-encrypted under the new key (set /
  change) or written plaintext (remove).
- [ ] Tests: pre-commit failure leaves primary file untouched and rolls
  in-memory mode/key back; post-commit failure surfaces durability-unconfirmed.
- [ ] Tests: cached key/passphrase lifecycle — pre-commit failure leaves
  the cache matching the previous mode (prior key+passphrase for
  encrypted, no cache for plaintext); successful commit (or
  durability-unconfirmed) replaces the cache to match the new on-disk
  mode and zeroizes the old key bytes and old passphrase.
- [ ] Implement `set_passphrase`, `change_passphrase`, `remove_passphrase` on
  `Vault` going through the §4.3 atomic-write + backup pipeline.

### Phase I — Import / export (Milestone 3)

- [ ] Tests for `import::detect` content sniffing → `ImportFormat` for each
  of: single `otpauth://` URI (with surrounding whitespace), `otpauth://`
  line list (blank lines tolerated), JSON array of URIs, Aegis JSON
  (plaintext + encrypted shapes both return `Aegis`), Paladin encrypted
  bundle, QR image; non-matching inputs return `Unknown`. Detection
  inspects shape only and never rejects on emptiness.
- [ ] Tests for zero-account inputs rejected uniformly with
  `no_entries_to_import` at the importer call site: empty JSON `otpauth`
  array, blank otpauth file, Aegis with empty `entries`, image with no
  decoded QRs.
- [ ] Tests for `import::otpauth`, `import::aegis_plaintext` (encrypted
  Aegis → typed `unsupported_encrypted_aegis`; non-`totp`/`hotp` entry →
  `unsupported_aegis_entry_type` with `source_index`, batch rejected),
  `import::paladin` (encrypted bundle round-trip; plaintext-mode Paladin
  file → `unsupported_plaintext_vault`; source `VaultSettings` discarded),
  `import::qr_image` (decoded QRs that are not `otpauth://` URIs reject
  the batch with `validation_error` + `source_index`), including
  timestamps preserved for Paladin bundle imports and fresh IDs assigned
  for inserted/appended rows; replacements keep destination ID.
- [ ] Tests for merge policy `Skip` / `Replace` / `Append` against running
  state, including HOTP-to-HOTP `Replace` preserving `Hotp.counter` and
  cross-kind replace swapping the whole `kind`.
- [ ] Tests for batch atomicity: any validation failure aborts the batch;
  warnings do not.
- [ ] Tests for `export::otpauth_list` (infallible JSON array of URIs) and
  `export::encrypted` (round-trips with the importer; rejects empty
  passphrase).
- [ ] Implement `read_qr_image(path) -> Result<Vec<String>>` in
  `import/qr.rs` (loads the image, decodes every QR via `rqrr`, returns
  one URI string per decoded QR; empty `Vec` when the image contains no
  QRs — the wrapping `import::qr_image` is what turns that into
  `no_entries_to_import`). Re-exported at the crate root per §4.7
  alongside `parse_otpauth` and `validate_manual`.

### Phase J — Public API freeze + library polish

- [ ] Lock `lib.rs` re-exports to exactly the §4.7 surface; anything else is
  `pub(crate)`.
- [ ] Run `cargo public-api` (or equivalent) to capture the surface; commit
  the snapshot.
- [ ] Doc-comment every public item with a one-line summary and a link back to
  the relevant DESIGN.md section.

## Test inventory

This list is exhaustive per CLAUDE.md ("write exhaustive tests"). Every entry
is a separate `#[test]` or `cases![]` family.

- RFC 6238 Appendix B vectors — SHA1/256/512 across multiple counters.
- RFC 4226 Appendix D vectors.
- TOTP boundary math: `seconds_remaining` exact-boundary, mid-window,
  pre-epoch reject, overflow reject.
- `otpauth://` round-trip — TOTP and HOTP, with and without issuer prefix,
  case-insensitive scheme/algo/type, base32 padding/casing.
- Bincode payload contract — fixed v2 config, trailing-bytes reject, 16 MiB
  reject (plaintext and encrypted decoded).
- Vault round-trip in both modes.
- Header byte-flip matrix on encrypted vault — every AAD-bound byte → fail.
- Argon2 param bounds — out-of-range params rejected pre-KDF.
- File / dir permissions — post-save permissions, `unsafe_permissions`
  rejection on `open` and `create` (parent / primary / backup).
- Passphrase transitions: `set`, `change`, `remove`; pre-commit rollback;
  durability-unconfirmed post-commit.
- Account validation matrix — every branch in §4.1.
- Short-secret warning surfaces in `ValidatedAccount.warnings`.
- Importers: Aegis plaintext OK; Aegis encrypted → typed
  `unsupported_encrypted_aegis`; Aegis non-`totp`/`hotp` entry type →
  `unsupported_aegis_entry_type` with `source_index` (batch rejected);
  Paladin bundle round-trip with timestamps preserved and source
  `VaultSettings` discarded; plaintext-mode Paladin file →
  `unsupported_plaintext_vault`; QR image with N codes; non-otpauth QR
  payloads rejected with `validation_error` + `source_index`; URI-list
  trimming and blank-line handling; zero-account inputs rejected
  uniformly with `no_entries_to_import`.
- HOTP `hotp_peek` after a committed `hotp_advance` returns the code for
  the new (post-advance) counter.
- Merge policy: `Skip` / `Replace` / `Append` including running-state
  collisions and HOTP counter preservation.
- Zeroize-on-drop: post-drop memory-poke proves bytes were wiped (via a
  controlled `Box<Secret>` test).

## Dependencies (per §9)

`hmac`, `sha1`, `sha2`, `argon2`, `chacha20poly1305`, `secrecy`, `zeroize`,
`getrandom` (pinned explicitly so the salt/nonce CSPRNG source per §4.4
doesn't drift across transitive minor versions), `base32`, `url`,
`bincode` (v2), `serde`, `serde_json`, `directories`, `uuid`, `thiserror`,
`rqrr`, `image`. No `tokio`, no `reqwest`, no network-touching crate.

## Out of scope for this plan

CLI prompts, TUI, GTK GUI, clipboard helpers, `/dev/tty` interaction —
those live in their respective binary plans.

## Locked-by-design callouts (§8 "Approved 2026-05-04")

Sections §4.3, §4.4, §4.5, §4.6, and §8 are locked for v0.1. Any change to
file format, crypto choice, passphrase transitions, or import/export
semantics must be flagged to the user before implementation.

## Definition of done

- All tests above pass.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean in CI.
- Public API snapshot committed and matches §4.7.
- DESIGN.md unchanged by this work (or, if a contradiction surfaces during
  implementation, DESIGN.md is updated *first* and reviewed before code
  changes follow).
