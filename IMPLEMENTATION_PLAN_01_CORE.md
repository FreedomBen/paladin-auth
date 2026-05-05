# Implementation Plan 01 — `paladin-core`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4, §5 error taxonomy,
§8–§10, §12 Milestones 1–3, and §14.
Status: pre-implementation. This plan stays grounded in DESIGN.md and does not
invent any public crate, public type, or public API beyond what is specified
there. Internal module paths below are scoped implementation details.

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
│   │   └── perms_other.rs # Stubs for non-Unix targets
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
│   │   ├── paladin.rs    # Paladin bundle import; plaintext returns unsupported
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
    └── zeroize.rs           # controlled zeroize assertions
```

## Milestone sequencing (TDD: red → green → refactor)

Each step lands as its own commit. Tests come first.

### Phase A — Scaffolding

- [ ] Create virtual workspace `Cargo.toml` (members: `paladin-core` only at this
  point; binaries added in their own plans).
- [ ] Create `rust-toolchain.toml` and `crates/paladin-core/Cargo.toml` with
  `license`, `rust-version` (MSRV decision: pin to current stable at scaffold
  time and record it in CLAUDE.md).
- [ ] Add SPDX header to every source file.
- [ ] Wire `cargo deny` policy: deny known network-stack crates (`tokio`,
  `reqwest`, `hyper`, etc.) and document manual review for new dependencies.
  This supports the §8 "no network" rule; tests and code review cover runtime
  behavior.
- [ ] CI workflow stub: `fmt --check`, `clippy -- -D warnings`, `test --all`,
  `cargo deny check`, `cargo audit`.

### Phase B — Domain model + validation (Milestone 1, part 1)

- [ ] Tests: `domain/validation.rs` covering every branch in §4.1 (digits range,
  TOTP period bounds, HOTP counter bounds, empty labels, malformed icon-hint
  slugs, mismatched otpauth issuers, invalid timestamps; short-secret warnings
  in 10–15 byte range).
- [ ] Implement `Account`, `AccountId` (UUIDv4 stored as 16 bytes, hyphenated
  canonical `Display`; the CLI computes any short-prefix disambiguator at
  render time since uniqueness depends on full vault contents the library
  doesn't curate), `Secret` newtype with `Zeroize + Drop`, `Algorithm`,
  `OtpKind`, `Code`, `ValidationWarning`, `ValidatedAccount`,
  `AccountInput`, and the public `validate_manual(input, now)` entry
  point that routes manual flag-driven input through the same validation
  table as `parse_otpauth` and the importers.
- [ ] No `Debug` impls that print secret bytes — wire compile-fail coverage
  proving `Secret` cannot be formatted with `Debug`, plus runtime assertions
  that any public `Debug` output for secret-bearing types omits or redacts the
  secret bytes.
- [ ] Define `error.rs` `PaladinError` to carry only the core-returnable
  §5 kinds: `validation_error`, `invalid_passphrase`, `invalid_state`,
  `vault_missing`, `vault_exists`, `unsafe_permissions`, `wrong_vault_lock`,
  `decrypt_failed`, `invalid_header`, `invalid_payload`,
  `unsupported_format_version`, `kdf_params_out_of_bounds`,
  `unsupported_import_format`, `unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `no_entries_to_import`, `counter_overflow`,
  `time_range`, `save_not_committed`, `save_durability_unconfirmed`, and
  `io_error`. The CLI-only kinds (`clipboard_write_failed`, `no_match`,
  `multiple_matches`, `duplicate_account`) are owned by the CLI plan and
  never returned from core — `Vault::add` is infallible per §4.7, so the
  CLI performs `(secret, issuer, label)` collision detection itself via
  `Vault::iter` before calling `add`.

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
  base32 RFC 4648 with optional `=` padding; algorithm/digits/period defaults
  and ranges; ASCII whitespace inside `secret` rejected; HOTP `counter`
  required and range-checked; rejection of `period` on HOTP and `counter` on
  TOTP; duplicate known parameters rejected; unknown parameters ignored.
- [ ] Property tests (`proptest`): URI parser and base32 secret decoding
  round-trip valid generated cases and reject malformed generated cases without
  panics.
- [ ] Round-trip: parse → emit → parse yields the same normalized account.

### Phase E — Plaintext storage (Milestone 1, part 4)

- [ ] Tests: round-trip of `VaultPayload` through bincode v2 with the exact
  config from §4.3; full-input-consumption rejection; 16 MiB serialized payload
  limit; plaintext on-disk size cap rejected before bincode decode.
- [ ] Tests: primary, temp, and backup files written `0600`, parent created
  `0700`, atomic write via same-directory tempfile + rename, `.bak` rotated on
  each save after a primary exists (one generation), `unsafe_permissions`
  rejection at `open`
  (parent directory + primary + backup when present) and at `create`
  (parent directory only, since primary/backup do not yet exist). The
  typed `unsafe_permissions` error
  carries `path`, `subject` (one of `vault_dir`, `vault_file`,
  `backup_file`), `actual_mode`, and `expected_mode` (mode strings as
  four-digit octal, e.g. `"0644"`).
- [ ] Tests: leftover `vault.bin.tmp` / `vault.bin.bak.tmp` files from a prior
  partial save are unlinked by the next `open`; non-crash save errors unlink
  remaining temp files before returning; completed renames are not rolled back.
- [ ] Tests: `format_unsafe_permissions(&err)` returns `Some(text)` for
  `unsafe_permissions` errors and `None` for any other kind. The text
  names the failing path, the actual and expected modes, and the exact
  `chmod` command that would repair it (`0700` for directories, `0600`
  for files), so the CLI and GUI can render identical wording without
  re-implementing it.
- [ ] Tests: `inspect(path)` returns `Ok(Missing)` only when the primary file
  is absent, reports plaintext/encrypted mode from the header without
  decryption, returns an error for unrecognized magic, and deliberately skips
  permission checks.
- [ ] Tests: header version and ID handling — v0.1 writes `format_ver = 1`;
  unsupported versions return `unsupported_format_version`; unknown `mode`,
  `kdf_id`, or `aead_id` values return `invalid_header` before constructing a
  vault.
- [ ] Tests: `open` returns `vault_missing` when the primary file is
  absent; `create` returns `vault_exists` when the primary already
  exists (rotation belongs to `create_force`, see below).
- [ ] Tests: `create_force(path, lock)` staged clobber per §5 — writes
  `vault.bin.tmp` and `fsync`s it before moving any existing primary;
  staging-step failure leaves the old primary and `.bak` untouched;
  once staged, rotates an existing `vault.bin` → `vault.bin.bak`
  (overwriting any existing backup) verbatim and without re-encryption;
  renames new tmp into place; `fsync`s the parent. Pre-rename failure
  after backup rotation surfaces `save_not_committed` with `backup_path`
  set to `vault.bin.bak`; post-commit `fsync` failure surfaces
  `save_durability_unconfirmed`. With no existing primary at `path`,
  behaves identically to `create`. `create_force` reuses the
  parent-directory `unsafe_permissions` check from `create` and rejects
  before any staged write.
- [ ] Implement `Store` (open/save), permissions module (Unix path; non-Unix
  stubs that compile but reject `open` / `create` / `create_force` before
  touching vault content with `io_error` and
  `operation: "unsupported_platform_permissions"`),
  atomic-write pipeline.
- [ ] Implement `inspect(path)` (header probe, no decryption, no perms check).
- [ ] Implement `create_force(path, lock)` in `storage` per the §5 init
  clobber sequence.
- [ ] Implement `format_unsafe_permissions(&Error) -> Option<String>` per
  §4.7, sourcing all wording from the `unsafe_permissions` fields so CLI
  and GUI never diverge.

### Phase F — Encrypted storage (Milestone 1, part 5)

- [ ] Tests: header byte layout (10-byte plaintext header, 64-byte
  encrypted-mode header before ciphertext); on-disk size cap
  (`header_size + 16 MiB [+ 16-byte tag]`) before any KDF/AEAD work.
- [ ] Tests: AAD binding — flipping any byte in `format_ver`, `mode`,
  `kdf_id`, Argon2 params, `salt`, `aead_id`, or `nonce` causes `open` to
  fail without returning a vault; flipping a ciphertext byte fails; flipping
  the AEAD tag fails.
- [ ] Tests: Argon2 parameter bounds rejected before any KDF work (`m_kib`
  8192–1048576, `t` 1–10, `p` 1–4).
- [ ] Tests: regular encrypted saves preserve the in-header Argon2 params
  and `salt`, and use a freshly generated random `nonce` per save (drawn
  from the OS CSPRNG).
- [ ] Tests: AEAD key caching — `open` derives the 32-byte key once into
  a `Zeroizing<[u8; 32]>` cached on `Vault` alongside the `SecretString`
  passphrase; subsequent saves reuse the cached key without re-running
  Argon2id (assert via deterministic test instrumentation); both
  fields are zeroized when `Vault` drops. Plaintext vaults hold no cached
  key or passphrase.
- [ ] Tests: `open` rejects `VaultLock` mismatches with `wrong_vault_lock`
  before any KDF work — `VaultLock::Plaintext` against an encrypted file,
  and `VaultLock::Encrypted(_)` against a plaintext file.
- [ ] Implement `crypto::argon2` (defaults m=64 MiB, t=3, p=1 with the §4.4
  read bounds: `m_kib` 8192–1048576, `t` 1–10, `p` 1–4),
  `crypto::aead` (XChaCha20-Poly1305 with header bytes serialized as AAD),
  encrypted `Store` save/open paths, and the cached-key data model on
  `Vault`.

### Phase G — Vault behavior + settings (Milestone 1, part 6)

- [ ] Tests: `add` / `remove` / `iter` (insertion order) / `rename` semantics;
  `rename` updates `updated_at`; `VaultSettings` defaults are off with
  `auto_lock.timeout_secs = 300` and `clipboard.clear_secs = 20`; settings
  setters reject `auto_lock.timeout_secs < 30` and
  `clipboard.clear_secs < 5`.
- [ ] Tests: `hotp_advance` rollback — inject a `Store` save error before
  primary commit point and assert in-memory counter and `updated_at` revert
  to pre-call values; durability-unconfirmed surfaced as a typed error after
  commit point.
- [ ] Tests: `hotp_advance` at `u64::MAX` returns `counter_overflow` before
  mutating memory or attempting a save.
- [ ] Implement `Vault` operations and `VaultSettings` setters per §4.7.

### Phase H — Passphrase management (Milestone 2)

- [ ] Tests: `set_passphrase` (plaintext → encrypted), `change_passphrase`
  (encrypted → encrypted), `remove_passphrase` (encrypted → plaintext); each
  transition uses a fresh salt and primary nonce; encrypted `.bak` writes use
  their own fresh nonce under the new key (set / change), while remove writes
  `.bak` plaintext.
- [ ] Tests: pre-commit failure leaves primary file untouched and rolls
  in-memory mode/key back; post-commit failure surfaces durability-unconfirmed.
- [ ] Tests: cached key/passphrase lifecycle — pre-commit failure leaves
  the cache matching the previous mode (prior key+passphrase for
  encrypted, no cache for plaintext); successful commit (or
  durability-unconfirmed) replaces the cache to match the new on-disk
  mode and zeroizes the old key bytes and old passphrase.
- [ ] Tests: wrong-starting-state calls return `invalid_state` before
  generating new crypto material; `set_passphrase` and `change_passphrase`
  reject zero-length passphrases with `invalid_passphrase`.
- [ ] Implement `set_passphrase`, `change_passphrase`, `remove_passphrase` on
  `Vault` going through the §4.3 atomic-write + backup pipeline.

### Phase I — Import / export (Milestone 3)

- [ ] Tests for `import::detect` content sniffing → `ImportFormat` for each
  of: single `otpauth://` URI (with surrounding whitespace), `otpauth://`
  line list (blank lines tolerated), JSON array of URIs, Aegis JSON
  (plaintext + encrypted shapes both return `Aegis`), Paladin files by magic
  (plaintext + encrypted shapes both return `Paladin`), QR image;
  non-matching inputs return `Unknown`. Detection inspects shape only and
  never rejects on emptiness.
- [ ] Tests for zero-account inputs rejected uniformly with
  `no_entries_to_import` at the importer call site: empty JSON `otpauth`
  array, blank otpauth file, Aegis with empty `entries`, image with no
  decoded QRs.
- [ ] Tests for `import::otpauth`, `import::aegis_plaintext` (encrypted
  Aegis → typed `unsupported_encrypted_aegis`; non-`totp`/`hotp` entry →
  `unsupported_aegis_entry_type` with `source_index`, batch rejected; field
  mapping from `name`, `issuer`, `info.secret`, `info.algo`, `info.digits`,
  `info.period`, and `info.counter`; TOTP period defaulting to 30; HOTP
  counter required; missing required `name` or `info.secret` rejected with
  `validation_error` + `source_index`),
  `import::paladin` (encrypted bundle round-trip; plaintext-mode Paladin
  file → `unsupported_plaintext_vault`; source `VaultSettings` discarded),
  `import::qr_image` and `import::qr_image_bytes` (decoded QRs that are not
  `otpauth://` URIs reject the batch with `validation_error` +
  `source_index`; raw RGBA byte buffers reject zero dimensions, checked
  multiplication overflow, and length mismatches before decoding, then
  return `no_entries_to_import` when no QR decodes), including
  `otpauth`, QR, and Aegis imports setting `created_at = updated_at =
  import_time`; timestamps preserved for Paladin bundle imports and fresh IDs
  assigned for inserted/appended rows; replacements keep destination ID and
  `created_at` while setting `updated_at = import_time`.
- [ ] Tests for merge policy `Skip` / `Replace` / `Append` against running
  state, with collisions defined by the exact `(secret, issuer, label)` triple,
  including HOTP-to-HOTP `Replace` preserving `Hotp.counter` and cross-kind
  replace swapping the whole `kind`; `Replace` preserves the destination `id`
  and `created_at`.
- [ ] Tests for batch atomicity: any validation failure aborts the batch;
  warnings do not, and warnings are collected before merge-policy application
  so skipped rows can still report warnings.
- [ ] Tests for `export::otpauth_list` (infallible JSON array of URIs) and
  `export::encrypted` (wraps `VaultSettings::default()`, round-trips with the
  importer, and rejects empty passphrase).
- [ ] Implement `read_qr_image(path) -> Result<Vec<String>>` and
  `read_qr_image_bytes(width, height, rgba) -> Result<Vec<String>>` in
  `import/qr.rs`. The path form loads the image from disk; the byte form
  accepts raw RGBA8 clipboard/image buffers, rejects zero dimensions,
  rejects overflow in `width * height * 4`, and rejects any buffer length
  other than that exact byte count. Both decode every QR via `rqrr`, return
  one payload string per decoded QR, and return an empty `Vec` when the image
  contains no QRs — the wrapping `import::qr_image` /
  `import::qr_image_bytes` functions are what turn that into
  `no_entries_to_import`. Re-exported at the crate root per §4.7 alongside
  `parse_otpauth` and `validate_manual`.

### Phase J — Public API freeze + library polish

- [ ] Lock default `lib.rs` re-exports to exactly the §4.7 surface; anything
  else is `pub(crate)`.
- [ ] Run `cargo public-api` (or equivalent) to capture the surface; commit
  the snapshot.
- [ ] Doc-comment every public item with a one-line summary and a link back to
  the relevant DESIGN.md section.
- [ ] Add a `test-fault-injection` cargo feature (off by default) that
  exposes, only under `cfg(feature = "test-fault-injection")`, a `Store`
  constructor honoring the
  `PALADIN_FAULT_INJECT=pre_commit|post_commit` env var: `pre_commit`
  fails the save before the primary rename (surfaces
  `save_not_committed`); `post_commit` fails the parent-directory
  `fsync` after the primary rename (surfaces
  `save_durability_unconfirmed`). Both fault paths apply uniformly to
  the regular save pipeline, `create_force`, and the passphrase
  transitions. The feature is gated so production builds never link
  the hook; only the binary crates' test builds opt in. Internal
  `paladin-core` rollback/durability tests already exercise these
  paths in-process — this feature is the cross-crate surface so CLI
  and TUI integration tests can drive them end-to-end. The feature-gated
  constructor is excluded from the default public-API snapshot and is not part
  of the stable §4.7 surface.

## Test inventory

This list is exhaustive per CLAUDE.md ("write exhaustive tests"). Every entry
is a separate `#[test]` or `cases![]` family.

- RFC 6238 Appendix B vectors — SHA1/256/512 across multiple counters.
- RFC 4226 Appendix D vectors.
- TOTP boundary math: `seconds_remaining` exact-boundary, mid-window,
  pre-epoch reject, overflow reject.
- Account identity / secret hygiene: UUIDv4 bytes + canonical display,
  `Secret` zeroization, `Secret` non-`Debug` compile-fail coverage, and no
  secret bytes in any public `Debug` output for secret-bearing types.
- Account validation matrix — every branch in §4.1.
- Short-secret warning surfaces in `ValidatedAccount.warnings`.
- `otpauth://` round-trip — TOTP and HOTP, with and without issuer prefix,
  case-insensitive scheme/algo/type, base32 padding/casing, duplicate known
  parameter rejection, unknown parameter ignoring, secret whitespace rejection,
  and HOTP/TOTP-specific `counter`/`period` rejection.
- `proptest` property coverage for URI parsing and base32 secret decoding.
- Bincode payload contract — fixed v2 config, trailing-bytes reject, 16 MiB
  reject (plaintext on-disk and plaintext/encrypted decoded).
- Vault round-trip in both modes.
- `inspect(path)` header probe: missing primary returns `Missing`, plaintext
  and encrypted headers report the correct mode without decryption, invalid
  magic errors, permission checks skipped.
- Header version / ID errors: unsupported `format_ver`, unknown `mode`,
  unknown `kdf_id`, and unknown `aead_id`.
- Header byte-flip matrix on encrypted vault — every AAD-bound byte fails
  without returning a vault.
- Argon2 param bounds — out-of-range `m_kib`, `t`, or `p` rejected pre-KDF.
- Encrypted save invariants — size cap pre-KDF/AEAD, Argon2 params and salt
  preserved on regular saves, fresh nonce per save, ciphertext/tag tamper
  rejection.
- AEAD key caching — one Argon2id derivation at `open`, cached key reused on
  save, no cache for plaintext vaults, cached key/passphrase zeroized on drop.
- File / dir permissions — post-save permissions, `unsafe_permissions`
  rejection on `open` (parent / primary / backup when present) and on
  `create` (parent only, since primary/backup do not yet exist),
  first-save backup skip, later one-generation `.bak` rotation, leftover temp
  cleanup on `open`, and temp cleanup on non-crash save errors.
- `open` / `create` precondition errors — `vault_missing` for absent
  primary on `open`; `vault_exists` for existing primary on `create`;
  `wrong_vault_lock` on cross-mode `VaultLock` (both directions) before
  any KDF work.
- Vault behavior and settings: `add` / `remove` / `iter` insertion order /
  `rename` timestamp update; settings defaults and exact timeout minimums.
- HOTP `hotp_advance` rollback, durability-unconfirmed post-commit behavior,
  and `counter_overflow` at `u64::MAX` before mutation or save.
- HOTP `hotp_peek` after a committed `hotp_advance` returns the code for
  the new (post-advance) counter.
- Passphrase transitions: `set`, `change`, `remove`; pre-commit rollback;
  durability-unconfirmed post-commit; fresh salt/nonce behavior; backup
  rewritten under the target mode/key; cache lifecycle and old-material
  zeroization; wrong-starting-state `invalid_state`; zero-length new
  passphrase rejection.
- `import::detect`: Paladin magic, QR image magic, Aegis plaintext/encrypted
  shapes, single/list/JSON-array `otpauth://`, empty otpauth JSON array shape,
  and `Unknown`.
- Importers: Aegis plaintext field mapping, defaults, and required fields;
  Aegis encrypted → typed `unsupported_encrypted_aegis`; Aegis
  non-`totp`/`hotp` entry type →
  `unsupported_aegis_entry_type` with `source_index` (batch rejected);
  missing required Aegis fields reject with `validation_error` +
  `source_index`;
  Paladin bundle round-trip with timestamps preserved and source
  `VaultSettings` discarded; plaintext-mode Paladin file →
  `unsupported_plaintext_vault`; QR image path and raw RGBA byte buffer
  with N codes; raw RGBA zero dimensions, multiplication overflow, and length
  mismatch; non-otpauth QR payloads rejected with `validation_error` +
  `source_index`; URI-list trimming and blank-line handling; non-Paladin
  imports use `import_time`; zero-account inputs rejected uniformly with
  `no_entries_to_import`.
- Merge policy: `Skip` / `Replace` / `Append` including running-state
  collisions on the `(secret, issuer, label)` triple, destination `id` /
  `created_at` preservation on replace, HOTP counter preservation, cross-kind
  replacement, batch atomicity, and warnings retained even for skipped rows.
- Exporters: `otpauth_list` emits an infallible JSON array of URIs;
  `encrypted` wraps default settings, round-trips through the importer, and
  rejects empty passphrases.
- Zeroize-on-drop: drop-in-place in a controlled allocation proves bytes are
  wiped before deallocation for `Secret`, cached keys, and retained
  passphrases.

## Dependencies (per §4.4 / §9)

`hmac`, `sha1`, `sha2`, `argon2`, `chacha20poly1305`, `secrecy`, `zeroize`,
`getrandom` (pinned explicitly so the salt/nonce CSPRNG source per §4.4
doesn't drift across transitive minor versions), `base32`, `url`,
`bincode` (v2), `serde`, `serde_json`, `directories`, `uuid`, `thiserror`,
`rqrr`, `image`. No `tokio`, no `reqwest`, no network-touching crate.

Dev/test only: `proptest` (parser/base32 properties), `trybuild`
(`Secret` non-`Debug` compile-fail coverage), and `tempfile` (storage and
permission fixtures).

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
