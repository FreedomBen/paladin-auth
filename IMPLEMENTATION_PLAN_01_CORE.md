# Implementation Plan 01 — `paladin-core`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4, §5 error taxonomy,
§8–§11, §12 Milestones 0–3, and §14.
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
│   ├── error.rs          # PaladinError + Result alias; carries core-returnable §5 error_kind values verbatim so the CLI can emit them under --json without renaming or mapping
│   ├── domain/
│   │   ├── mod.rs        # Account, AccountId, AccountSummary, AccountKindSummary, Algorithm, OtpKind, Code
│   │   ├── secret.rs     # Secret newtype with Zeroize + Drop
│   │   ├── validation.rs # Shared Account validation (labels, secrets, periods…)
│   │   ├── view.rs       # Account::summary(), Vault::summaries(); non-secret account projection for all front ends
│   │   ├── match_key.rs  # account_match_key() + account_matches_search(); canonical "{issuer}:{label}" matching used by CLI / TUI / GUI
│   │   ├── query.rs      # parse_account_query(), Vault::matching_accounts(), Vault::shortest_unique_id_prefix()
│   │   └── slug.rs       # icon_hint slug rules + issuer-derived defaulting
│   ├── otp/
│   │   ├── mod.rs        # pure OTP primitives (compute_totp, compute_hotp)
│   │   ├── totp.rs       # RFC 6238
│   │   └── hotp.rs       # RFC 4226
│   ├── otpauth/
│   │   ├── mod.rs        # otpauth:// parser + emitter
│   │   └── tests.rs      # round-trip + edge cases
│   ├── storage/
│   │   ├── mod.rs        # Store, default_vault_path, atomic-write pipeline, .bak rotation, export secret-file writer
│   │   ├── header.rs     # PALADIN\0 magic, format_ver, mode, KDF/AEAD ids, AAD
│   │   ├── payload.rs    # bincode v2 VaultPayload encode/decode (16 MiB cap)
│   │   ├── path.rs       # ProjectDirs data_dir resolver + vault.bin filename
│   │   ├── secret_file.rs # write_secret_file_atomic (0600 export output; no .bak)
│   │   ├── perms_unix.rs # 0600/0700 enforcement (Linux v0.1)
│   │   └── perms_other.rs # Stubs for non-Unix targets
│   ├── crypto/
│   │   ├── mod.rs        # KDF + AEAD facades
│   │   ├── argon2.rs     # Argon2id params/options, defaults, bounds check
│   │   └── aead.rs       # XChaCha20-Poly1305 with header-AAD wiring
│   ├── vault.rs          # Vault impl: add/remove/iter/rename/import_accounts/totp_code/hotp_*; save/mutate_and_save; is_encrypted() mode getter
│   ├── shared_text.rs    # format_init_force_warning / format_plaintext_storage_warning / format_plaintext_export_warning / format_validation_warning helpers (CLI / TUI / GUI parity)
│   ├── settings.rs       # VaultSettings (auto-lock, clipboard), SettingKey / SettingPatch parsers, setters
│   ├── passphrase.rs     # set / change / remove transitions, rollback
│   ├── import/
│   │   ├── mod.rs        # detect(), from_file/from_bytes facade
│   │   ├── otpauth.rs    # URI / line-list / JSON-array (handles Gnome plaintext)
│   │   ├── aegis.rs      # plaintext JSON; encrypted returns unsupported error
│   │   ├── paladin.rs    # Paladin bundle import; plaintext returns unsupported
│   │   └── qr.rs         # rqrr + image
│   ├── export/
│   │   ├── mod.rs        # facade
│   │   ├── otpauth.rs    # JSON array of otpauth:// URIs
│   │   └── encrypted.rs  # Paladin encrypted bundle
│   ├── time.rs           # SystemTime helpers (epoch math, overflow rejection)
│   └── ui_contract.rs    # HOTP_REVEAL_SECS and other shared front-end constants
└── tests/
    ├── rfc_vectors.rs    # RFC 6238 App. B, RFC 4226 App. D
    ├── otpauth_roundtrip.rs
    ├── vault_roundtrip.rs   # both modes
    ├── tamper.rs            # AAD-bound header byte-flip matrix
    ├── perms.rs             # 0600/0700 + unsafe_permissions rejection
    ├── shared_text.rs       # format_init_force_warning / format_plaintext_storage_warning / format_plaintext_export_warning / format_validation_warning text fixtures
    ├── account_summary.rs   # AccountSummary and Code expose no secret bytes; Code is the core projection paired with AccountSummary by CLI CodeResult
    ├── match_key.rs         # account_match_key + account_matches_search behavior (empty issuer keeps colon; case preserved)
    ├── query.rs             # parse_account_query, matching_accounts, shortest_unique_id_prefix
    ├── settings_patch.rs    # parse_setting_key / parse_setting_patch + apply_setting_patch dotted key/value grammar
    ├── passphrase.rs        # all three transitions + rollback; Vault::is_encrypted reflects each transition outcome
    ├── import_otpauth.rs
    ├── import_aegis.rs
    ├── import_paladin.rs
    ├── import_qr.rs
    ├── export_writer.rs
    └── zeroize.rs           # controlled zeroize assertions
```

## Milestone sequencing (TDD: red → green → refactor)

Each step lands as its own commit. Tests come first.

### Phase A — Scaffolding (Milestone 0)

- [ ] Create virtual workspace `Cargo.toml` (members: `paladin-core` only at this
  point; binaries added in their own plans).
- [ ] Create `rust-toolchain.toml` and `crates/paladin-core/Cargo.toml` with
  `license`, `rust-version` (MSRV decision: pin to current stable at scaffold
  time and record it in CLAUDE.md).
- [ ] Extend `.gitignore` for the Rust workspace: ignore `/target` and any
  other build/test artifacts the repo will produce. The existing entries
  (`TODO.md`, `.claude/settings.local.json`, `.codex`) stay.
- [ ] Write `README.md` with build instructions covering the §10 CI gate
  (`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit`) — the §12 Milestone 0 README deliverable.
- [ ] Document that `default_vault_path()` uses
  `ProjectDirs::from("", "", "paladin")`, then appends `vault.bin` under the
  returned `data_dir()`.
- [ ] Add SPDX header to every source file.
- [ ] Wire `cargo deny` policy: deny known network-stack crates (`tokio`,
  `reqwest`, `hyper`, etc.) and document manual review for new dependencies.
  This supports the §8 "no network" rule; tests and code review cover runtime
  behavior.
- [ ] CI workflow stub: `fmt --check`, `clippy -- -D warnings`, `test --all`,
  `cargo deny check`, `cargo audit`.

### Phase B — Domain model + validation (Milestone 1, part 1)

- [ ] Tests: `domain/validation.rs` covering every branch in §4.1 (digits range,
  TOTP period bounds, HOTP counter bounds, label and issuer 128-byte caps,
  empty labels, manual Base32 secret decoding / ASCII-whitespace rejection,
  secret length rejection below 10 bytes and above 1024 bytes, malformed
  icon-hint slugs, mismatched otpauth issuers, invalid timestamps;
  short-secret warnings in 10–15 byte range).
- [ ] Implement `Account`, `AccountId` (UUIDv4 stored as 16 bytes, hyphenated
  canonical `Display`; shortest unique `id:<hex>` disambiguators are computed
  by `Vault::shortest_unique_id_prefix` because uniqueness depends on the
  full vault contents), `Secret` newtype with `Zeroize + Drop`, `Algorithm`,
  `OtpKind`, `Code`, `AccountKindSummary`, `AccountSummary`,
  `ValidationWarning`, `ValidatedAccount`,
  `AccountKindInput`, `AccountInput` (including the kind selector plus
  TOTP-only `period_secs` and HOTP-only `counter`, both optional so
  defaults are applied by `validate_manual`), and the public
  `validate_manual(input, now)` entry point that routes manual
  flag-driven input through the same validation table as `parse_otpauth`
  and the importers.
- [ ] Implement `Account::summary()` as the only public non-secret account
  projection. `AccountSummary` matches the §5 account shape exactly
  (`issuer` / `icon_hint` as `Option`, `period` and `counter` as
  mutually-exclusive options, no secret field) so CLI JSON output, TUI rows,
  GUI rows, duplicate-account presentation, and import reports never inspect
  private `Account` fields or risk serializing secret bytes.
- [ ] Implement `Code` as the §5 code projection: zero-padded `code`, TOTP
  validity fields as `Some` with `counter_used = None`, and HOTP
  `counter_used = Some(pre_advance_counter)` with validity fields `None`.
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
  `io_error`. Each included kind carries the stable extra fields from §5
  exactly, including field names, optionality, value formats,
  `unsupported_import_format.format` semantics, and the stable
  core-owned `io_error.operation` strings. The
  presentation-only kinds (`clipboard_write_failed`, `no_match`,
  `multiple_matches`, `duplicate_account`) are never returned from core.
  `duplicate_account` is emitted by front ends after they call
  `Vault::find_duplicate(&validated)`; core owns the secret-bearing
  `(secret, issuer, label)` comparison, while the presentation layer owns
  the user-facing error and any `--allow-duplicate` / "add anyway" policy.

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
- [ ] Implement `parse_otpauth(uri, import_time)` and the internal
  `otpauth://` emitter used by `export::otpauth_list`, with normalization
  exactly matching the parser tests.

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
  for files), so the CLI, TUI, and GUI can render identical wording without
  re-implementing it.
- [ ] Tests: `inspect(path)` returns `Ok(Missing)` only when the primary file
  is absent, reports plaintext/encrypted mode from the header without
  decryption, returns an error for unrecognized magic, and deliberately skips
  permission checks.
- [ ] Tests: `default_vault_path()` calls
  `ProjectDirs::from("", "", "paladin")`, appends `vault.bin` under the
  returned `data_dir()` location from §4.3, and surfaces `io_error` with
  `operation: "resolve_default_vault_path"` if the platform path cannot be
  resolved.
- [ ] Tests: header version and ID handling — v0.1 writes `format_ver = 1`;
  unsupported versions return `unsupported_format_version`; unknown `mode`,
  `kdf_id`, or `aead_id` values return `invalid_header` before constructing a
  vault.
- [ ] Tests: `open` returns `vault_missing` when the primary file is
  absent; `create` returns `vault_exists` when the primary already
  exists (rotation belongs to `create_force`, see below).
- [ ] Tests: `create_force(path, VaultInit::Plaintext)` staged clobber per
  §5: writes `vault.bin.tmp` and `fsync`s it before moving any existing primary;
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
- [ ] Tests: `write_secret_file_atomic(path, bytes)` creates the final file
  `0600`, writes through a same-directory tempfile, `fsync`s the temp file
  and parent directory, atomically renames into place, overwrites only when
  the caller has chosen to call it, and never creates or rotates `.bak`.
  Missing parents surface as `io_error`; injected write / fsync failures
  before rename surface as `save_not_committed` and do not leave the
  destination partially written; injected parent-fsync failures after rename
  surface as `save_durability_unconfirmed`.
- [ ] Tests: core-owned `io_error.operation` strings match the §5 table for
  default path resolution, permission metadata reads, vault reads/writes,
  import-file reads, image decoding, QR extraction, export writes, and
  unsupported non-Unix permission stubs.
- [ ] Implement `Store`, crate-root `open` / `create` storage facades,
  permissions module (Unix path; non-Unix stubs that compile but reject
  `open` / `create` / `create_force` before touching vault content with
  `io_error` and
  `operation: "unsupported_platform_permissions"`),
  atomic-write pipeline.
- [ ] Implement `default_vault_path()` in `storage::path` with
  `ProjectDirs::from("", "", "paladin")` so presentation crates do not
  duplicate `ProjectDirs` logic.
- [ ] Implement `inspect(path)` (header probe, no decryption, no perms check).
- [ ] Implement `create_force(path, init)` in `storage` per the §5 init
  clobber sequence.
- [ ] Implement `write_secret_file_atomic(path, bytes)` by factoring the
  vault save pipeline's tempfile / chmod `0600` / fsync / rename /
  parent-fsync pieces without the vault-specific header, permissions
  enforcement, or `.bak` rotation.
- [ ] Implement `format_unsafe_permissions(&PaladinError) -> Option<String>`
  per §4.7, sourcing all wording from the `unsafe_permissions` fields so
  CLI, TUI, and GUI never diverge.
- [ ] Tests: `format_init_force_warning(path)` returns text that names
  the supplied path, mentions `vault.bin.bak`, and warns that any
  prior backup will be overwritten — locked via fixture string compare
  so CLI `init --force` and the GUI `InitDialog` destructive gate stay
  byte-identical.
- [ ] Tests: `format_plaintext_storage_warning()` and
  `format_plaintext_export_warning()` return stable text — locked via
  fixture so CLI text-mode `passphrase remove`, the TUI Passphrase /
  Export modals, and the GUI `PassphraseDialog` / `InitDialog` /
  `ExportDialog` plaintext paths render identical wording.
- [ ] Implement `format_init_force_warning(&Path) -> String`,
  `format_plaintext_storage_warning() -> String`, and
  `format_plaintext_export_warning() -> String` per §4.7. Co-locate
  with `format_unsafe_permissions` so all front-end text helpers live
  in one module and presentation crates never re-implement the wording.
- [ ] Tests: `format_validation_warning(&ValidationWarning)` returns stable
  fixture text for `short_secret`, using decoded length and recommended
  minimum values from the warning.
- [ ] Implement `format_validation_warning(&ValidationWarning) -> String`
  in the same shared text module so CLI JSON/text warnings, TUI inline
  warnings, and GUI inline warnings share one message source.

### Phase F — Encrypted storage (Milestone 1, part 5)

- [ ] Tests: header byte layout (10-byte plaintext header, 64-byte
  encrypted-mode header before ciphertext); on-disk size cap
  (`header_size + 16 MiB [+ 16-byte tag]`) before any KDF/AEAD work; decrypted
  encrypted payloads above the 16 MiB payload limit are rejected before
  constructing a `Vault`.
- [ ] Tests: AAD binding — flipping any byte in `format_ver`, `mode`,
  `kdf_id`, Argon2 params, `salt`, `aead_id`, or `nonce` causes `open` to
  fail without returning a vault; flipping a ciphertext byte fails; flipping
  the AEAD tag fails.
- [ ] Tests: wrong encrypted-vault passphrase returns `decrypt_failed`
  without constructing a vault.
- [ ] Tests: Argon2 parameter bounds rejected before any KDF work (`m_kib`
  8192–1048576, `t` 1–10, `p` 1–4).
- [ ] Tests: `Argon2Params::default()` yields m=65536 KiB, t=3, p=1;
  `Argon2Params::validate` accepts in-range custom values and rejects
  out-of-range values with `kdf_params_out_of_bounds`; `EncryptionOptions`
  defaults to the default params and rejects zero-length passphrases on
  encrypted write paths with `invalid_passphrase`.
- [ ] Tests: regular encrypted saves preserve the in-header Argon2 params
  and `salt`, and use a freshly generated random `nonce` per save (drawn
  from the OS CSPRNG).
- [ ] Tests: encrypted `create` / `create_force`, `set_passphrase`,
  `change_passphrase`, and `export::encrypted` write custom validated Argon2
  params into the header when supplied through `EncryptionOptions`.
- [ ] Tests: AEAD key caching — `open` derives the 32-byte key once into
  a `Zeroizing<[u8; 32]>` cached on `Vault` alongside the `SecretString`
  passphrase; subsequent saves reuse the cached key without re-running
  Argon2id (assert via deterministic test instrumentation); both
  fields are zeroized when `Vault` drops. Plaintext vaults hold no cached
  key or passphrase.
- [ ] Tests: `open` rejects `VaultLock` mismatches with `wrong_vault_lock`
  before any KDF work — `VaultLock::Plaintext` against an encrypted file,
  and `VaultLock::Encrypted(_)` against a plaintext file.
- [ ] Tests: encrypted `create` and `create_force` through `VaultInit`
  follow the same precondition, parent-permission, staged-clobber,
  commit-point, and durability-error semantics as plaintext storage.
- [ ] Implement `crypto::argon2` with public `Argon2Params`,
  `EncryptionOptions`, and `VaultInit` support (defaults m=64 MiB, t=3, p=1
  with the §4.4 read/write bounds: `m_kib` 8192–1048576, `t` 1–10, `p` 1–4),
  `crypto::aead` (XChaCha20-Poly1305 with header bytes serialized as AAD),
  encrypted `Store` save/open/create/create_force paths, and the cached-key
  data model on `Vault`.

### Phase G — Vault behavior + settings (Milestone 1, part 6)

- [ ] Tests: `add` / `remove` / `iter` (insertion order) / `rename` semantics;
  `rename` updates `updated_at`; `find_duplicate` detects exact
  `(secret, issuer, label)` collisions and ignores non-colliding entries;
  `get` returns accounts by `AccountId`; `summaries` returns insertion-order
  `AccountSummary` values with no secret bytes; `VaultSettings` defaults are
  off with `auto_lock.timeout_secs = 300` and `clipboard.clear_secs = 20`;
  settings setters reject `auto_lock.timeout_secs < 30` and
  `clipboard.clear_secs < 5`.
- [ ] Tests: `hotp_advance` rollback — inject a `Store` save error before
  primary commit point and assert in-memory counter and `updated_at` revert
  to pre-call values; durability-unconfirmed surfaced as a typed error after
  commit point.
- [ ] Tests: `hotp_advance` at `u64::MAX` returns `counter_overflow` before
  mutating memory or attempting a save.
- [ ] Tests: `Vault::mutate_and_save` captures an internal snapshot, restores
  it when the mutation closure returns an error, restores it when
  `Vault::save` returns `save_not_committed`, leaves the mutated state in
  memory when save returns `save_durability_unconfirmed`, and returns the
  closure's success value unchanged on a clean save. The secret-bearing
  rollback snapshot is zeroized when dropped. Exercise add, remove, import
  merge (`skip` / `replace` / `append`), and settings changes so presentation
  crates do not need their own rollback machinery.
- [ ] Tests: `Vault::is_encrypted()` returns `false` for vaults opened
  with `VaultLock::Plaintext` / created with `VaultInit::Plaintext`,
  returns `true` for vaults opened with `VaultLock::Encrypted` / created with
  encrypted `VaultInit`, and tracks `set_passphrase` / `change_passphrase` /
  `remove_passphrase` outcomes (unchanged on `save_not_committed`,
  changed on a successful save or `save_durability_unconfirmed` —
  Phase H exercises the transition cases against this getter).
- [ ] Tests: `account_match_key(&Account)` returns `"{issuer}:{label}"`
  with the colon present even when issuer is empty, preserves the
  original casing, and round-trips equality for accounts that share an
  issuer/label pair. Cover ASCII, mixed case, and Unicode label
  characters so the helper does not silently apply `to_lowercase()` /
  Unicode normalization (callers do that at compare time per §5).
- [ ] Tests: `account_matches_search(&Account, query)` applies
  `str::to_lowercase()` to both the query and `account_match_key`, performs
  substring matching, matches the empty query, keeps empty-issuer colon
  behavior, and performs no Unicode normalization or locale-specific casing.
- [ ] Tests: `parse_account_query(query)` maps non-`id:` input to
  `AccountQuery::Search`, accepts `id:` prefixes of 8..=32 hex characters
  case-insensitively while normalizing the stored prefix to lowercase, and
  rejects short, long, or non-hex `id:` prefixes with `validation_error`
  (`field: "query"`). `Vault::matching_accounts` handles both search and
  id-prefix queries in insertion order.
- [ ] Tests: `Vault::shortest_unique_id_prefix(id)` returns the minimum
  `id:<hex>` disambiguator of at least 8 hex characters among current
  vault IDs, extends just far enough for collisions, returns the full
  32-character hex prefix when needed, and returns `None` for an ID not
  present in the vault.
- [ ] Tests: `parse_setting_key(key)` accepts exactly the four §5 dotted
  keys and rejects unknown keys with `validation_error`; `parse_setting_patch(key, value)`
  reuses that parser, accepts lowercase bool values (`true` / `false`) for
  toggle keys and base-10 `u32` values for timeout keys, and rejects malformed
  / below-minimum values with `validation_error`. `Vault::apply_setting_patch`
  routes through the same typed setters so direct setters and CLI-style
  dotted patches cannot diverge.
- [ ] Tests: `HOTP_REVEAL_SECS == 120`, locked as the shared TUI / GUI reveal
  duration so both front ends consume the same constant.
- [ ] Implement `Vault` operations, `Vault::save`, `Vault::get`,
  `Vault::summaries`, `Vault::find_duplicate`, `Vault::import_accounts`,
  `Vault::is_encrypted`, `VaultSettings` setters, `SettingKey`,
  `SettingPatch`, `parse_setting_key`, `parse_setting_patch`,
  `Vault::apply_setting_patch`, and
  `Vault::mutate_and_save` per §4.7. Implement `account_match_key`,
  `account_matches_search`, `parse_account_query`,
  `Vault::matching_accounts`, and `Vault::shortest_unique_id_prefix` in
  `domain/match_key.rs` / `domain/query.rs` and re-export them at the crate
  root so CLI selection plus TUI / GUI search all source matching semantics
  from core.

### Phase H — Passphrase management (Milestone 2)

- [ ] Tests: `set_passphrase` (plaintext → encrypted), `change_passphrase`
  (encrypted → encrypted), `remove_passphrase` (encrypted → plaintext); each
  encrypted transition takes `EncryptionOptions`, writes its default or custom
  Argon2 params, uses a fresh salt and primary nonce; encrypted `.bak` writes
  use their own fresh nonce under the new key (set / change), while remove
  writes `.bak` plaintext.
- [ ] Tests: pre-commit failure leaves primary file untouched and rolls
  in-memory mode/key back; post-commit failure surfaces durability-unconfirmed.
- [ ] Tests: cached key/passphrase lifecycle — pre-commit failure leaves
  the cache matching the previous mode (prior key+passphrase for
  encrypted, no cache for plaintext); successful commit (or
  durability-unconfirmed) replaces the cache to match the new on-disk
  mode and zeroizes the old key bytes and old passphrase.
- [ ] Tests: wrong-starting-state calls return `invalid_state` before
  generating new crypto material; `set_passphrase` and `change_passphrase`
  reject zero-length passphrases with `invalid_passphrase` and
  `reason: "zero_length"`; non-empty whitespace-only and Unicode passphrases
  are treated as bytes and are not trimmed or normalized.
- [ ] Implement `set_passphrase(options)`, `change_passphrase(options)`, and
  `remove_passphrase` on `Vault` going through the §4.3 atomic-write +
  backup pipeline.

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
  `unsupported_aegis_entry_type` with `source_index` and `entry_type`, batch
  rejected; field mapping from `name`, `issuer`, `info.secret`, `info.algo`,
  `info.digits`, `info.period`, and `info.counter`; TOTP period defaulting to
  30; HOTP counter required; missing required `name` or `info.secret`
  rejected with `validation_error` + `source_index`),
  `import::paladin` (encrypted bundle round-trip; plaintext-mode Paladin
  file → `unsupported_plaintext_vault`; wrong bundle passphrase →
  `decrypt_failed`; source `VaultSettings` discarded),
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
- [ ] Tests for `Vault::import_accounts` / `ImportReport`: imported, skipped,
  replaced, and appended counts match the merge outcome; `accounts` lists IDs
  for imported / replaced / appended rows only, never skipped rows; warnings
  retain zero-based `source_index` values collected before merge-policy
  application.
- [ ] Tests for batch atomicity: any validation failure aborts the batch;
  warnings do not, and warnings are collected before merge-policy application
  so skipped rows can still report warnings.
- [ ] Tests for `export::otpauth_list(&Vault)` (infallible JSON array of
  URIs), `export::encrypted(&Vault, EncryptionOptions)` (wraps
  `VaultSettings::default()`, writes default or custom Argon2 params,
  round-trips with the importer, and rejects empty passphrase), and
  front-end-style export writes that pass the resulting bytes through
  `write_secret_file_atomic`.
- [ ] Tests for import facade dispatch: `import::from_file` and
  `import::from_bytes` auto-detect with `format: None`, honor forced
  `ImportFormat` values, return `unsupported_import_format` for `Unknown`
  with `format: "unknown"` and for invalid forced/source combinations with
  `format` set to the requested forced format, decode encoded image bytes as QR
  input in `from_bytes`, use the path form for QR files in `from_file`,
  and return `invalid_state` with `operation: "import_paladin"` /
  `state: "missing_passphrase"` when Paladin dispatch lacks a bundle
  passphrase.
- [ ] Implement format-specific importers (`import::otpauth`,
  `import::aegis_plaintext`, `import::paladin`, `import::qr_image`, and
  `import::qr_image_bytes`) plus the `Vault::import_accounts` merge-policy
  engine that produces `ImportReport`.
- [ ] Implement `ImportOptions`, `import::from_file`, and
  `import::from_bytes` as the public facade over `detect` and the
  format-specific importers. `from_bytes` decodes image-format bytes with
  `image` to RGBA8 before routing through `read_qr_image_bytes`.
- [ ] Implement `export::otpauth_list(&Vault)` using the internal
  `otpauth://` emitter and `export::encrypted(&Vault, EncryptionOptions)`
  using the Paladin encrypted bundle format with default `VaultSettings`.
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
  exposes, only under `cfg(feature = "test-fault-injection")`, a test-only
  `Store` constructor and shared atomic-write fault hook honoring the
  `PALADIN_FAULT_INJECT=pre_commit|post_commit` env var: `pre_commit`
  fails the save before the primary rename (surfaces
  `save_not_committed`); `post_commit` fails the parent-directory
  `fsync` after the primary rename (surfaces
  `save_durability_unconfirmed`). Both fault paths apply uniformly to
  the regular save pipeline, `create_force`, passphrase transitions, and
  `write_secret_file_atomic`. The feature is gated so production builds
  never link the hook; only the binary crates' test builds opt in. Internal
  `paladin-core` rollback/durability tests already exercise these
  paths in-process — this feature is the cross-crate surface so CLI
  and TUI integration tests can drive them end-to-end. The feature-gated
  constructor and hook are excluded from the default public-API snapshot and are
  not part of the stable §4.7 surface.

## Test inventory

This list is exhaustive per CLAUDE.md ("write exhaustive tests"). Every entry
is a separate `#[test]` or table-driven case family.

- RFC 6238 Appendix B vectors — SHA1/256/512 across multiple counters.
- RFC 4226 Appendix D vectors.
- TOTP boundary math: `seconds_remaining` exact-boundary, mid-window,
  pre-epoch reject, overflow reject.
- Account identity / secret hygiene: UUIDv4 bytes + canonical display,
  `AccountSummary` and `Code` projections matching the §5 account/code fields
  with no secret bytes, `Secret` zeroization, `Secret` non-`Debug`
  compile-fail coverage, and no secret bytes in any public `Debug` output for
  secret-bearing types.
- Account validation matrix — every branch in §4.1, including secret length
  rejection at `<10` and `>1024` decoded bytes, label and issuer 128-byte
  caps, TOTP period bounds, HOTP counter bounds, digits range, icon-hint
  slug rules, and timestamp upper bound.
- Manual `AccountInput` validation — `AccountKindInput` TOTP/HOTP
  selection, TOTP period defaults / overrides, HOTP counter defaults /
  overrides, manual Base32 secret decoding / ASCII-whitespace rejection, and
  rejection of period-on-HOTP or counter-on-TOTP.
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
- `default_vault_path()` uses `ProjectDirs::from("", "", "paladin")`,
  returns the §4.3 `vault.bin` data path, or `io_error` with
  `operation: "resolve_default_vault_path"`.
- Header version / ID errors: unsupported `format_ver`, unknown `mode`,
  unknown `kdf_id`, and unknown `aead_id`.
- Header byte-flip matrix on encrypted vault — every AAD-bound byte fails
  without returning a vault.
- Wrong encrypted-vault passphrase returns `decrypt_failed` without
  returning a vault.
- Argon2 param bounds — out-of-range `m_kib`, `t`, or `p` rejected pre-KDF.
- Argon2 custom params — default m=65536 KiB / t=3 / p=1, in-range custom
  params accepted for encrypted create / create_force / passphrase set/change
  / encrypted export, and out-of-range custom params rejected before
  prompting for or accepting a new encrypted write.
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
- `format_unsafe_permissions` returns shared repair text for
  `unsafe_permissions` and `None` for every other error kind.
- `format_init_force_warning(path)`, `format_plaintext_storage_warning()`,
  `format_plaintext_export_warning()`, and `format_validation_warning()`
  return locked fixture text so
  CLI / TUI / GUI render identical wording for the §5 init clobber gate,
  the `passphrase remove` plaintext-storage advisory, and the
  unencrypted-export advisory / validation warnings respectively.
- `account_match_key(&Account)` produces the canonical
  `"{issuer}:{label}"` key (empty issuer keeps the colon, casing
  preserved) so CLI query resolution and TUI / GUI search filters
  share one match-key definition.
- `account_matches_search(&Account, query)`, `parse_account_query`,
  `Vault::matching_accounts`, and `Vault::shortest_unique_id_prefix`
  implement the shared selector pieces: case-insensitive substring
  matching with no Unicode normalization, `id:` prefix validation and
  matching, insertion-order match lists, and shortest-unique
  `id:<hex>` candidate disambiguators.
- `Vault::is_encrypted()` reflects the open lock mode / create init mode and
  every passphrase-transition outcome (unchanged on
  `save_not_committed`, changed on success and
  `save_durability_unconfirmed`).
- `open` / `create` precondition errors — `vault_missing` for absent
  primary on `open`; `vault_exists` for existing primary on `create`;
  `wrong_vault_lock` on cross-mode `VaultLock` during `open` (both
  directions) before any KDF work.
- `create_force` staged clobber — staging failure leaves existing primary and
  `.bak` untouched; after backup rotation, pre-commit failure reports
  `save_not_committed` with `backup_path`; post-commit parent `fsync` failure
  reports `save_durability_unconfirmed`; encrypted and plaintext locks share
  those semantics.
- Vault behavior and settings: `add` / `remove` / `iter` insertion order /
  `get` / `summaries` / `rename` timestamp update; `find_duplicate` exact
  collision behavior; settings defaults, exact timeout minimums,
  `parse_setting_key`, `parse_setting_patch`, and
  `Vault::apply_setting_patch`.
- `Vault::mutate_and_save`: rollback on closure error and
  `save_not_committed`, durability-unconfirmed leaves mutated state, and
  success returns the closure value; the rollback snapshot is zeroized.
- HOTP `hotp_advance` rollback, durability-unconfirmed post-commit behavior,
  and `counter_overflow` at `u64::MAX` before mutation or save.
- HOTP `hotp_peek` after a committed `hotp_advance` returns the code for
  the new (post-advance) counter.
- `HOTP_REVEAL_SECS == 120` exported as the shared TUI / GUI reveal-window
  duration.
- Passphrase transitions: `set`, `change`, `remove`; pre-commit rollback;
  durability-unconfirmed post-commit; default/custom Argon2 params for
  encrypted targets; fresh salt/nonce behavior; backup rewritten under the
  target mode/key; cache lifecycle and old-material zeroization;
  wrong-starting-state `invalid_state`; zero-length new passphrase rejection
  with `reason: "zero_length"`; no trimming or Unicode normalization of
  non-empty passphrase bytes.
- `import::detect`: Paladin magic, QR image magic, Aegis plaintext/encrypted
  shapes, single/list/JSON-array `otpauth://`, empty otpauth JSON array shape,
  and `Unknown`.
- Import facade: `from_file` / `from_bytes` auto-detect and forced-format
  dispatch, `unsupported_import_format` for unknown or invalid dispatch,
  `format` set to `"unknown"` for auto-detect failures and to the requested
  format for forced-format failures, missing Paladin bundle passphrase as
  `invalid_state`, and encoded image bytes routed through QR decoding.
- Importers: Aegis plaintext field mapping, defaults, and required fields;
  Aegis encrypted → typed `unsupported_encrypted_aegis`; Aegis
  non-`totp`/`hotp` entry type →
  `unsupported_aegis_entry_type` with `source_index` and `entry_type` (batch
  rejected);
  missing required Aegis fields reject with `validation_error` +
  `source_index`;
  Paladin bundle round-trip with timestamps preserved and source
  `VaultSettings` discarded; plaintext-mode Paladin file →
  `unsupported_plaintext_vault`; wrong bundle passphrase →
  `decrypt_failed`; QR image path and raw RGBA byte buffer with N codes;
  raw RGBA zero dimensions, multiplication overflow, and length mismatch;
  non-otpauth QR payloads rejected with `validation_error` + `source_index`;
  URI-list trimming and blank-line handling; non-Paladin imports use
  `import_time`; zero-account inputs rejected uniformly with
  `no_entries_to_import`.
- Merge policy: `Skip` / `Replace` / `Append` including running-state
  collisions on the `(secret, issuer, label)` triple, destination `id` /
  `created_at` preservation on replace, HOTP counter preservation, cross-kind
  replacement, `ImportReport` counts / account IDs, batch atomicity, and
  warnings retained even for skipped rows.
- Exporters: `otpauth_list(&Vault)` emits an infallible JSON array of URIs;
  `encrypted(&Vault, EncryptionOptions)` wraps default settings, writes
  default or custom Argon2 params, round-trips through the importer, and
  rejects empty passphrases; `write_secret_file_atomic` writes export bytes
  `0600` via tempfile / fsync / rename without `.bak` rotation and reports
  pre-rename vs post-rename failures as `save_not_committed` vs
  `save_durability_unconfirmed`.
- Core `io_error.operation` strings match the §5 stable operation table for
  storage, import, image, QR, export, and unsupported-platform failures.
- Zeroize-on-drop: drop-in-place in a controlled allocation proves bytes are
  wiped before deallocation for `Secret`, mutate-and-save rollback
  snapshots, cached keys, and retained
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

## Packaging support (per §11)

`paladin-core` is a library and is not itself a release artifact, but
the v0.1 / v0.2 packaging pipeline depends on the workspace shape it
defines. Implementation owes:

- **Cargo.toml metadata.** `crates/paladin-core/Cargo.toml` carries
  `description`, `repository`, `license = "AGPL-3.0-or-later"`, and
  pinned `rust-version`. Binary crates inherit consistent values via
  `package.workspace = true` so `nfpm` and Flathub manifests read
  one source.
- **Deterministic, vendor-friendly deps.** The §9 dep list above
  resolves cleanly under `cargo vendor`; pinning `getrandom`
  (already required for the §4.4 CSPRNG contract) plus
  `cargo build --locked` is sufficient for §11.6 reproducibility.
  No build-time codegen depends on system clock, hostname, or
  network.
- **Stable `error_kind` taxonomy.** `PaladinError` exposes the
  core-returnable §5 kinds verbatim (no internal renaming) so the
  `paladin` CLI can serialize them under `--json` and the strict-output
  rule in §5 holds without any mapping layer. Add a `serde::Serialize` impl
  guarded by an `error-serde` cargo feature, off by default, that the
  CLI opts into; `paladin-core` itself has no JSON output paths. The
  same feature flag also gates `serde::Serialize` for the public
  non-secret view/report types referenced from error variants and §5
  success envelopes (`AccountSummary`, `AccountKindSummary`, `AccountId`,
  `Algorithm`, `Code`, `ValidationWarning`, `ImportReport`,
  `ImportWarning`, `VaultSettings`) so the CLI can serialize shared
  pieces for `duplicate_account.account`, `multiple_matches.candidates`,
  `clipboard_write_failed.account`, `counter_overflow.account`, and the
  `add` / `import` / `show` / `peek` / `copy` / `list` success bodies
  without re-serializing those core types locally. `ImportReport.accounts`
  remains `Vec<AccountId>` per §4.7; CLI success envelopes resolve those
  IDs through `Vault::summaries` when they need `AccountSummary` objects.
  Do **not** implement
  `Serialize` for secret-bearing `Account` or `Secret`. The
  feature-gated impls are not part of the stable §4.7 surface.
- **No platform-specific build steps.** Linux is the only target in
  v0.1 (§2); the `perms_other.rs` stub keeps `cargo check
  --target=…` clean on non-Unix without changing release behavior.

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
- DESIGN.md is kept in sync with the implemented public API; if a
  contradiction surfaces during implementation, DESIGN.md is updated *first*
  and reviewed before code changes follow.
