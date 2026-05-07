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
│   │   ├── mod.rs        # Public: Account, AccountId, AccountSummary, AccountKindSummary, Algorithm, Code, IconHintInput, AccountKindInput, AccountInput, ValidatedAccount, ValidationWarning, AccountQuery. pub(crate): OtpKind.
│   │   ├── secret.rs     # Secret newtype with Zeroize + Drop
│   │   ├── validation.rs # Shared Account validation (labels, secrets, periods…)
│   │   ├── view.rs       # Account::summary(), Vault::summaries(); non-secret account projection for all front ends
│   │   ├── match_key.rs  # account_match_key() + account_matches_search(); canonical "{issuer}:{label}" matching used by CLI / TUI / GUI
│   │   ├── query.rs      # parse_account_query(), Vault::matching_accounts(), Vault::shortest_unique_id_prefix(), select_after_filter()
│   │   ├── slug.rs       # icon_hint slug rules + issuer-derived defaulting
│   │   └── prompt_input.rs # parse_icon_hint_token() prompt-grammar mapping shared by CLI add prompts and TUI / GUI add modals
│   ├── otp/
│   │   ├── mod.rs        # pure OTP primitives (compute_totp, compute_hotp)
│   │   ├── totp.rs       # RFC 6238
│   │   └── hotp.rs       # RFC 4226
│   ├── otpauth/
│   │   ├── mod.rs        # otpauth:// parser + emitter
│   │   └── tests.rs      # round-trip + edge cases
│   ├── storage/
│   │   ├── mod.rs        # Store, default_vault_path, atomic-write pipeline, .bak rotation, export secret-file writer, classify_init_precheck() + InitPrecheck enum shared by CLI init and GUI InitDialog
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
│   ├── policy/
│   │   ├── mod.rs        # Re-exports: IdlePolicy, ClipboardClearPolicy, ClipboardClearToken, hotp_reveal_deadline
│   │   ├── auto_lock.rs  # IdlePolicy: should_arm(is_encrypted, &VaultSettings), next_deadline(now, is_encrypted, &VaultSettings), is_expired(deadline, now). Pure timer math and encrypted-only gating; raw input handling stays in front ends.
│   │   ├── clipboard_clear.rs # ClipboardClearPolicy: schedule(now, &VaultSettings) → Option<(token, deadline)>, should_clear(captured_value, current_clipboard) → bool. Token issuance is monotonic; the only-if-unchanged decision is shared so TUI/GUI can drive arboard / gdk::Clipboard with identical semantics.
│   │   └── hotp_reveal.rs # hotp_reveal_deadline(now: Instant) -> Instant using HOTP_REVEAL_SECS; shared by TUI reveal countdown and GUI reveal countdown.
│   ├── vault.rs          # Vault impl: add/remove/iter/rename/import_accounts/totp_code/hotp_*; save/mutate_and_save; is_encrypted() mode getter
│   ├── shared_text.rs    # format_unsafe_permissions / format_init_force_warning / format_plaintext_storage_warning / format_plaintext_export_warning / format_validation_warning helpers (CLI / TUI / GUI parity)
│   ├── settings.rs       # VaultSettings (auto-lock, clipboard), SettingKey / SettingPatch parsers, setters
│   ├── passphrase.rs     # set / change / remove transitions, rollback
│   ├── import/
│   │   ├── mod.rs        # detect(), classify_paladin_import_precheck(), from_file/from_bytes facade
│   │   ├── otpauth.rs    # URI / line-list / JSON-array (handles Gnome plaintext)
│   │   ├── aegis.rs      # plaintext JSON; encrypted returns unsupported error
│   │   ├── paladin.rs    # Paladin bundle import; plaintext returns unsupported
│   │   └── qr.rs         # rqrr + image
│   ├── export/
│   │   ├── mod.rs        # facade
│   │   ├── otpauth.rs    # JSON array of otpauth:// URIs
│   │   └── encrypted.rs  # Paladin encrypted bundle
│   ├── time.rs           # SystemTime helpers (epoch math, overflow rejection)
│   └── ui_contract.rs    # HOTP_REVEAL_SECS, QR_RGBA_MAX_BYTES, TICK_INTERVAL_MS (250 ms TOTP gauge / clipboard-staleness tick shared by TUI + GTK), AUTO_LOCK_SECS_MIN/MAX (30 / 86_400), CLIPBOARD_CLEAR_SECS_MIN/MAX (5 / 600). All shared front-end constants live here so TUI / GUI never hard-code them.
└── tests/
    ├── rfc_vectors.rs    # RFC 6238 App. B (digits × algorithm cross-product), RFC 4226 App. D, HOTP counter-0 baseline, HOTP MAX-1 → MAX → overflow chain
    ├── otpauth_roundtrip.rs # parse / emit round-trip + non-string JSON elements + embedded-NUL rejection
    ├── vault_roundtrip.rs   # both modes
    ├── vault_lifecycle.rs   # inspect, default_vault_path, create_force, mutate_and_save, is_encrypted
    ├── init_precheck.rs     # classify_init_precheck mapping for §5 init flow
    ├── tamper.rs            # encrypted header / ciphertext / tag tamper matrix (per-field named cases)
    ├── crypto_vectors.rs    # Argon2id + XChaCha20-Poly1305 known-answer vectors
    ├── perms.rs             # 0600/0700 + unsafe_permissions rejection (per-subject discriminated)
    ├── shared_text.rs       # format_unsafe_permissions / format_init_force_warning / format_plaintext_storage_warning / format_plaintext_export_warning / format_validation_warning text fixtures
    ├── account_summary.rs   # AccountSummary and Code expose no secret bytes; Code is the core projection paired with AccountSummary by CLI show / peek / copy commands
    ├── match_key.rs         # account_match_key + account_matches_search behavior (empty issuer keeps colon; case preserved)
    ├── query.rs             # parse_account_query, matching_accounts, shortest_unique_id_prefix, select_after_filter
    ├── prompt_input.rs      # parse_icon_hint_token: empty → Default, case-insensitive `none` (Unicode-whitespace trim) → Clear, slug → Slug, invalid token → validation_error
    ├── ui_contract.rs       # HOTP_REVEAL_SECS / QR_RGBA_MAX_BYTES / TICK_INTERVAL_MS / AUTO_LOCK_SECS_MIN/MAX / CLIPBOARD_CLEAR_SECS_MIN/MAX lock-by-fixture
    ├── policy.rs            # IdlePolicy + ClipboardClearPolicy + hotp_reveal_deadline behavior
    ├── settings_patch.rs    # parse_setting_key / parse_setting_patch + apply_setting_patch dotted key/value grammar
    ├── passphrase.rs        # all three transitions + rollback; Vault::is_encrypted reflects each transition outcome; old cached-key buffer is zero post-transition
    ├── import_otpauth.rs
    ├── import_aegis.rs
    ├── import_paladin.rs
    ├── import_paladin_precheck.rs # shared CLI / TUI / GUI encrypted-bundle prompt classifier
    ├── import_qr.rs
    ├── export_writer.rs
    ├── error_matrix.rs      # one test per §5 core-returnable error_kind asserting kind + every stable extra field
    ├── send_assertions.rs   # static Send (and Sync where required) assertions for every public type that crosses a thread boundary
    ├── no_network.rs        # source / metadata guard proving production paladin-core has no network API or network-stack deps
    ├── fault_injection.rs   # cross-save-site coverage for the test-fault-injection feature
    └── zeroize.rs           # controlled zeroize assertions
```

## Milestone sequencing (TDD: red → green → refactor)

Each step lands as its own commit. Tests come first.

### Phase A — Scaffolding (Milestone 0)

- [x] Create virtual workspace `Cargo.toml` (members: `paladin-core` only at
  this point; binaries added in their own plans). Populate
  `[workspace.package]` with the shared metadata required by §11
  (`license = "AGPL-3.0-or-later"`, `edition`, `rust-version`,
  `repository = "https://github.com/FreedomBen/paladin"`,
  `homepage = "https://paladin.tamx.org"`, `description`) so binary crates
  added later can inherit it via per-field Cargo inheritance
  (`description.workspace = true`,
  `license.workspace = true`, `edition.workspace = true`,
  `rust-version.workspace = true`, `repository.workspace = true`,
  `homepage.workspace = true`).
- [x] Create `rust-toolchain.toml` and `crates/paladin-core/Cargo.toml`;
  the crate manifest pulls each shared metadata field from the
  workspace via per-field Cargo inheritance (`description.workspace = true`
  and the matching lines for `license`, `edition`, `rust-version`,
  `repository`, and `homepage`). (MSRV decision: pin to current stable
  at scaffold time and record it in CLAUDE.md.)
- [x] Extend `.gitignore` for the Rust workspace: ignore `/target` and any
  other build/test artifacts the repo will produce. The existing entries
  (`TODO.md`, `.claude/settings.local.json`, `.codex`) stay.
- [x] Write `README.md` with build instructions covering the §10 CI gate
  (`cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit`) — the §12 Milestone 0 README deliverable.
- [ ] Document that `default_vault_path()` uses
  `ProjectDirs::from("", "", "paladin")`, then appends `vault.bin` under the
  returned `data_dir()`.
- [x] Add SPDX header to every source file.
- [x] Wire `cargo deny` policy for dependency license / advisory checks and
  deny known network-stack crates (`tokio`, `reqwest`, `hyper`, etc.).
  Document manual review for new dependencies. This supports the §8
  "no network" rule; tests and code review cover runtime behavior.
- [x] Add `xtask/dev-tools.toml` as the workspace dev-tooling manifest and
  pin `cargo-public-api` there so CI and local API snapshots do not float to
  the latest released cargo subcommand.
- [x] CI workflow stub: `fmt --check`, `clippy -- -D warnings`, `test --all`,
  `cargo deny check`, `cargo audit`.

### Phase B — Domain model + validation (Milestone 1, part 1)

- [x] Tests: `domain/validation.rs` covering every branch in §4.1 (digits range,
  TOTP period bounds, HOTP counter bounds, label and issuer 128-byte caps,
  empty labels, manual Base32 secret decoding including lowercase input,
  optional `=` padding, malformed alphabet / padding, and ASCII-whitespace rejection,
  secret length rejection below 10 bytes and above 1024 bytes, malformed
  icon-hint slugs, issuer-derived icon-hint defaulting, empty / overlong
  derived icon hints staying `None`, mismatched otpauth issuers, invalid
  timestamps; short-secret warnings in 10–15 byte range). Boundary cases
  are explicit (not implied) — secret length at exactly `9` (reject),
  `10` (accept), `15` (warning), `16` (no warning), `1024` (accept),
  `1025` (reject); short-secret-warning fields (`decoded_len`,
  `recommended_min`) asserted; label and issuer at exactly `127` /
  `128` / `129` UTF-8 bytes including a multi-byte codepoint case where
  the 128th byte falls mid-codepoint (must reject without truncation);
  whitespace-only label rejected as `validation_error` distinct from a
  label containing internal whitespace that trims to non-empty; issuer
  of `"   "` (Unicode whitespace) becomes `None`; issuer slugifying to
  empty (e.g. `"!!!"`) yields `icon_hint = None`; icon-hint slug at
  exactly `64` / `65` bytes; mismatched otpauth issuer cases differing
  only by ASCII case rejected; `created_at` / `updated_at` at exactly
  `253402300799` (accept) and `253402300800` (reject).
  *(Note: mismatched-otpauth-issuer cases land in Phase D alongside the
  parser; everything else is exercised in `domain/validation.rs` /
  `domain/secret.rs` / `domain/slug.rs` unit tests.)*
- [x] Implement `Account`, `AccountId` (UUIDv4 stored as 16 bytes, hyphenated
  canonical `Display`; shortest unique `id:<hex>` disambiguators are computed
  by `Vault::shortest_unique_id_prefix` because uniqueness depends on the
  full vault contents), `Secret` newtype with `Zeroize + Drop`, `Algorithm`,
  `OtpKind`, `Code`, `AccountKindSummary`, `AccountSummary`,
  `ValidationWarning`, `ValidatedAccount`,
  `AccountKindInput`, `IconHintInput`, `AccountInput` (including the
  kind selector plus
  TOTP-only `period_secs` and HOTP-only `counter`, both optional so
  defaults are applied by `validate_manual`, and the icon-hint tri-state
  `Default` / `Clear` / `Slug`), and the public
  `validate_manual(input, now)` entry point that routes manual
  flag-driven input through the same validation table as `parse_otpauth`
  and the importers.
- [x] Implement `parse_icon_hint_token(token: &str) -> Result<IconHintInput>`
  in `domain/prompt_input.rs` and re-export from `lib.rs`. CLI prompts and
  TUI / GUI add modals call this helper instead of re-implementing the
  empty / `none` / slug grammar.
- [x] Implement `Account::summary()` as the only public non-secret account
  projection. `AccountSummary` matches the §5 account shape exactly
  (`issuer` / `icon_hint` as `Option`, `period` and `counter` as
  mutually-exclusive options, no secret field) so CLI JSON output, TUI rows,
  GUI rows, duplicate-account presentation, and import reports never inspect
  private `Account` fields or risk serializing secret bytes.
- [x] Implement `Code` as the §5 code projection: zero-padded `code`, TOTP
  validity fields as `Some` with `counter_used = None`, and HOTP
  `counter_used = Some(pre_advance_counter)` with validity fields `None`.
  *(Struct only; OTP module in Phase C populates it.)*
- [ ] No `Debug` impls that print secret bytes — wire compile-fail coverage
  proving `Secret` cannot be formatted with `Debug`, plus runtime assertions
  that any public `Debug` output for secret-bearing types omits or redacts the
  secret bytes. The enumerated secret-bearing types are: `Secret`,
  `Account`, `AccountInput`, `EncryptionOptions` (passphrase),
  `Vault` (cached key + cached passphrase),
  `ValidatedAccount`, and the rollback snapshot type used by
  `Vault::mutate_and_save`. For each type, either (a) a compile-fail
  test proves the type does not implement `Debug`, or (b) a runtime
  assertion proves its `Debug` output does not contain the literal
  decoded secret bytes for a fixture secret with a known unique
  byte pattern. `Serialize` audit: a `trybuild` compile-fail test
  proves `Account: !Serialize` and `Secret: !Serialize` even with the
  `error-serde` cargo feature enabled.
- [x] Tests: `parse_icon_hint_token(s)` returns `IconHintInput::Default`
  for `""` and for any input whose Unicode whitespace trim is empty;
  returns `IconHintInput::Clear` for the case-insensitive token `none`
  after Unicode-whitespace trim (`"none"`, `" NONE\t"`, `"None"`);
  returns `IconHintInput::Slug(slug)` for a valid trimmed slug after
  routing through `domain/slug.rs` validation; rejects malformed
  slugs with `validation_error` (`field: "icon_hint"`). Co-locate the
  test fixtures with `tests/prompt_input.rs` so CLI add prompts and
  TUI / GUI add modals share the same input grammar.
- [x] Define `error.rs` `PaladinError` to carry only the core-returnable
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
  `unsupported_import_format.format` semantics, stable core-owned
  `invalid_state.operation` / `state` pairs, and the stable core-owned
  `io_error.operation` strings. The
  presentation-only kinds (`clipboard_write_failed`, `no_match`,
  `multiple_matches`, `duplicate_account`) are never returned from core.
  `duplicate_account` is emitted by front ends after they call
  `Vault::find_duplicate(&validated)`; core owns the secret-bearing
  `(secret, issuer, label)` comparison, while the presentation layer owns
  the user-facing error and any `--allow-duplicate` / "add anyway" policy.

### Phase C — OTP generation (Milestone 1, part 2)

- [x] Tests: RFC 6238 Appendix B vectors (SHA1/256/512); RFC 4226 Appendix D.
  Coverage is the **explicit cross-product** of digits ∈ {6, 7, 8} ×
  algorithm ∈ {SHA1, SHA256, SHA512} for at least one TOTP vector, so
  zero-padding and HMAC truncation regressions are caught per algorithm.
- [x] Tests: HOTP counter-0 baseline against RFC 4226 Appendix D's
  `Count = 0` value; `hotp_advance` from `counter = 0` produces
  `counter_used = 0` and post-advance `counter = 1`.
  *(Counter-0 baseline tested here; the advance-and-persist behavior
  lands with `Vault::hotp_advance` in Phase G.)*
- [ ] Tests: HOTP overflow boundary chain — `counter = u64::MAX - 1`
  advances successfully to `u64::MAX` (the off-by-one fence post in the
  overflow check); a subsequent advance from `u64::MAX` returns
  `counter_overflow` with the §5 `account` summary before any mutation
  or save (re-asserted here for completeness because Phase G also tests
  this through `Vault::hotp_advance`).
- [x] Tests: TOTP boundary semantics — half-open `[valid_from, valid_until)`,
  `seconds_remaining ∈ 1..=period`, exact-boundary selects new counter and
  reports full period (i.e. at the exact boundary `seconds_remaining ==
  period`, never `period - 1`), pre-epoch rejection (returns `time_range`
  with the kind asserted), `valid_until` overflow rejection at the exact
  boundary where `valid_until` would equal `u64::MAX` (accept) and
  `u64::MAX + 1` (reject).
- [x] Implement pure OTP primitives in `otp/`: TOTP code given (secret,
  algorithm, period, digits, now); HOTP code given (secret, algorithm,
  digits, counter). These are state-free and never persist. The Vault
  methods `totp_code`, `hotp_peek`, and `hotp_advance` (Phase G) route
  through them; only `hotp_advance` mutates and persists.

### Phase D — `otpauth://` parser/emitter (Milestone 1, part 3)

- [x] Tests: scheme/type case-insensitivity; non-`otpauth://` schemes
  (e.g. `https://`, `mailto:`, `paladin://`) rejected with
  `validation_error` before any further parsing; required label trimming +
  percent-decoding; first-`:` issuer split + issuer-rule normalization;
  base32 RFC 4648 with optional `=` padding; algorithm/digits/period defaults
  and ranges; ASCII whitespace inside `secret` rejected; HOTP `counter`
  required and range-checked; rejection of `period` on HOTP and `counter` on
  TOTP; duplicate known parameters rejected; unknown parameters ignored.
- [ ] Tests: `import::otpauth` rejects JSON arrays containing non-string
  elements (`[123, "otpauth://..."]`) with `validation_error` +
  `source_index` rather than panicking on a type mismatch.
  *(Deferred to Phase I — `import::otpauth` does not yet exist. The
  underlying `parse_otpauth` rejection on bad inputs is covered at the
  parser boundary; the wrapper-level `source_index` surfacing will be
  tested when `import::otpauth` lands.)*
- [ ] Tests: `import::otpauth` rejects line-list input containing embedded
  NUL bytes (`b"otpauth://...\nfoo\x00bar\n..."`) with `validation_error`
  + `source_index` for the offending row, before secret decoding.
  *(Deferred to Phase I, same reason as above.)*
- [x] Property tests (`proptest`): URI parser and base32 secret decoding
  round-trip valid generated cases and reject malformed generated cases without
  panics.
- [x] Round-trip: parse → emit → parse yields the same normalized account.
- [x] Implement `parse_otpauth(uri, import_time)` and the internal
  `otpauth://` emitter used by `export::otpauth_list`, with normalization
  exactly matching the parser tests.

### Phase E — Plaintext storage (Milestone 1, part 4)

- [x] Tests: round-trip of `VaultPayload` through bincode v2 with the exact
  config from §4.3; full-input-consumption rejection; 16 MiB serialized payload
  limit; plaintext on-disk size cap rejected before bincode decode.
- [x] Tests: bincode encoding determinism — encoding the **same**
  `VaultPayload` value twice produces bit-identical bytes, and a fixture
  with a fixed account list + `VaultSettings::default()` matches a
  committed expected byte string. Pins the §4.3 wire format so a future
  swap of `Vec<Account>` for `HashMap<AccountId, Account>`, an unstable
  field reorder in `VaultPayload`, or any other non-deterministic
  encoding regression fails the test instead of silently corrupting AAD
  reproducibility.
- [ ] Tests: plaintext save → reopen preserves account insertion order —
  add accounts in order A, B, C, save, drop the `Vault`, `open` it
  again, and assert `iter()` and `summaries()` yield A, B, C in that
  order. Pins the on-disk `VaultPayload.accounts` field as an ordered
  `Vec<Account>` rather than an unordered collection.
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
  partial save are unlinked by the next `open` (per §4.3 step 2,
  `vault.bin.bak.tmp` is staged whenever a prior primary exists — regular
  saves stage a verbatim copy of the soon-to-be-replaced primary, and
  passphrase set/change transitions stage the backup re-encrypted under the
  new key — see Phase H); non-crash save errors unlink remaining temp files
  before returning; completed renames are not rolled back. Cover edge
  cases: leftover `vault.bin.tmp` is a directory (not a regular file)
  surfaces `io_error` with `operation: "cleanup_temp_file"` rather than
  silently deleting the directory; leftover symlink is unlinked (the
  link, not the target); a leftover regular file owned by a different
  uid is removed if and only if directory perms permit and otherwise
  surfaces `io_error` with the same operation. The first-ever save
  explicitly does **not** create `vault.bin.bak.tmp` (no prior primary
  to copy) — assert directory contents post-save contain neither
  `.tmp` nor `.bak` siblings.
- [ ] Tests: regular-save pre-commit recoverable state — inject a save
  error after step 3 (rename `vault.bin.bak.tmp` →
  `vault.bin.bak`) but before step 4 (rename `vault.bin.tmp` →
  `vault.bin`). On disk after the failure: the old primary remains
  authoritative at `vault.bin`, `vault.bin.bak` contains the same
  pre-save primary bytes, no temp files remain after cleanup, and a
  subsequent `open(path, lock)` reads the pre-save state. The returned
  error is `save_not_committed` with `committed: false` and no
  `backup_path`, because the user does not need backup-file recovery
  while the primary path still contains the old vault. The `init
  --force` / `create_force` clobber path, where backup rotation can leave
  no primary before the new primary rename, is covered separately below.
- [ ] Tests: post-commit success replay — after a successful regular save,
  a fresh `open(path, lock)` reads the new primary and the on-disk
  `nonce` differs from the pre-save value; `vault.bin.bak` contains the
  *previous* primary verbatim (or no `.bak` if this was the first save).
- [ ] Tests: post-commit durability-unconfirmed semantics — inject a
  parent-directory `fsync` failure after the primary rename. The error
  is `save_durability_unconfirmed` (`committed: true`); a fresh
  `open(path, lock)` succeeds and returns the *new* state because the
  primary rename did commit even though durability was unconfirmed.
- [ ] Tests: `.bak` is never read on the success path — corrupting
  `vault.bin.bak` to garbage bytes does not affect a clean `open(path,
  lock)`. The backup is recovery-only; `open` reads only the primary.
- [ ] Tests: `format_unsafe_permissions(&err)` returns `Some(text)` for
  `unsafe_permissions` errors and `None` for any other kind. The text
  names the failing path, the actual and expected modes, and the exact
  `chmod` command that would repair it (`0700` for directories, `0600`
  for files), so the CLI, TUI, and GUI can render identical wording without
  re-implementing it. The `actual_mode` / `expected_mode` strings on the
  error itself are exactly four-digit octal (e.g. `"0644"`, not `"644"`)
  and the test asserts that literal format.
- [ ] Tests: per-subject `unsafe_permissions` discriminator — three
  fixtures exercise each `subject` value end-to-end on `open`: bad
  parent-directory perms surface `subject: "vault_dir"`, bad primary
  perms surface `subject: "vault_file"`, bad backup perms (with both
  primary and backup present and the primary OK) surface
  `subject: "backup_file"`. A fourth fixture confirms `create` only
  inspects the parent directory.
- [ ] Tests: `inspect(path)` returns `Ok(Missing)` only when the primary file
  is absent, reports plaintext/encrypted mode from the header without
  decryption, returns an error for unrecognized magic and for other I/O
  errors (e.g. permission-denied opening the path), and deliberately skips
  the §4.3 permissions check.
- [ ] Tests: symbolic-link rejection on `open` / `create` / `create_force` —
  using `symlink_metadata` (so the probe never follows the link), a
  `vault.bin` that is a symlink is rejected with `io_error` and
  `operation: "vault_file_is_symlink"`, a `vault.bin.bak` that is a symlink
  at `open` time is rejected with `operation: "backup_file_is_symlink"`,
  and a parent data directory that is a symlink is rejected with
  `operation: "vault_dir_is_symlink"`. Each rejection happens before any
  read, write, or staged tempfile so a hostile symlink cannot redirect
  reads or writes to a chosen file. Cover the case where the parent
  directory has `0700` perms but a hostile symlink was nonetheless seeded:
  the symlink rejection still fires (defense in depth — perms enforcement
  is the primary guard, but symlink rejection is a backstop). On
  `create_force`, the symlink check applies to the *existing* `vault.bin`
  before staging the new tempfile so a hostile symlink at `vault.bin`
  cannot capture the rename target.
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
  and parent directory, atomically renames into place, replaces an existing
  destination only by virtue of the caller invoking it, implements no
  prompt / `--force` policy in core, and never creates or rotates `.bak`.
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
- [ ] Tests: `classify_init_precheck` truth table —
  `Ok(VaultStatus::Missing)` → `InitPrecheck::Clear`;
  `Ok(VaultStatus::Plaintext)`, `Ok(VaultStatus::Encrypted)`,
  `Err(invalid_header { .. })`, and
  `Err(unsupported_format_version { .. })` all → `InitPrecheck::Existing`
  (an init-conflicting on-disk file requiring `--force` confirmation);
  every other `Err(_)` → `InitPrecheck::Propagate(err)` so the front end
  bubbles the underlying error (e.g. `unsafe_permissions`,
  `io_error { operation: "open_vault_file", .. }`). The mapping is
  locked here so CLI init, GUI `InitDialog`, and any future init-capable
  front end share one truth table.
- [ ] Implement `classify_init_precheck(probe: Result<VaultStatus>) ->
  InitPrecheck` plus `pub enum InitPrecheck { Clear, Existing,
  Propagate(PaladinError) }` in `storage/mod.rs`. Re-export both at the
  crate root.
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
  fixture so CLI text-mode plaintext `init` and `passphrase remove`,
  the TUI Passphrase / Export modals, and the GUI `PassphraseDialog` /
  `InitDialog` / `ExportDialog` plaintext paths render identical wording.
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
  encrypted-mode header before ciphertext); encrypted on-disk size cap
  (`header_size + 16 MiB + 16-byte AEAD tag`) before any KDF/AEAD work;
  decrypted encrypted payloads above the 16 MiB payload limit are rejected
  before constructing a `Vault`.
- [ ] Tests: encrypted save → reopen preserves account insertion order —
  add accounts in order A, B, C to an encrypted vault, save, drop the
  `Vault`, re-`open` with the same passphrase, and assert `iter()` and
  `summaries()` yield A, B, C in that order. Mirrors the Phase E
  plaintext insertion-order assertion to pin that the bincode
  `VaultPayload.accounts` field is an ordered `Vec<Account>` for both
  vault modes.
- [ ] Tests: encrypted-file tamper matrix — table-driven per-field
  byte-flip coverage for header, AAD-bound fields, ciphertext, and tag.
  One named test row per region, each asserting `open` returns the
  discriminating error kind and never returns a vault. The expected kind
  per region:
  - `magic` (8 bytes, `PALADIN\0`): flip any byte → `invalid_header`
    (the magic is checked before AEAD decode, so this is a header
    rejection, not `decrypt_failed`).
  - `format_ver` (1 byte): flip to `0` or to a value `> 1` →
    `unsupported_format_version` (header decoded; version unsupported).
  - `mode` (1 byte): flip to a value other than `0` / `1` →
    `invalid_header`. Flip across the two valid values (e.g.
    plaintext-stored file with `mode = 1`) → `wrong_vault_lock`
    against the supplied `VaultLock`.
  - `kdf_id` (1 byte): unknown id → `invalid_header`.
  - `m_kib`, `t`, `p` (4 bytes each): flipping any byte that pushes
    the value out of §4.4 bounds → `kdf_params_out_of_bounds` with
    `m_kib`, `t`, `p` payload fields asserted; flipping any byte that
    keeps the value in bounds but changes it → `decrypt_failed` (AAD
    mismatch).
  - `salt` (16 bytes): named cases for byte 0 (first), byte 7
    (middle), byte 15 (last) → `decrypt_failed`.
  - `aead_id` (1 byte): unknown id → `invalid_header`; in-range flip
    to a hypothetical second valid id → `decrypt_failed`.
  - `nonce` (24 bytes): named cases for byte 0, byte 11, byte 23 →
    `decrypt_failed`.
  - `ciphertext` (variable): flip first byte, middle byte, last byte
    before the tag → `decrypt_failed`.
  - `aead_tag` (16 bytes): flip first byte, last byte → `decrypt_failed`.
- [ ] Tests: malformed ciphertext shorter than the 16-byte AEAD tag
  (i.e. truncated file where the body cannot form a valid tag)
  surfaces `invalid_payload` with `reason: "ciphertext_too_short"`,
  not a panic.
- [ ] Tests: published crypto known-answer vectors (KATs) — Argon2id
  derives the expected 32-byte AEAD key for a fixed passphrase / salt /
  parameter fixture using the exact crate configuration Paladin wires, and
  XChaCha20-Poly1305 encrypts/decrypts a fixed key / 24-byte nonce / AAD /
  plaintext fixture to the expected ciphertext and tag. Expected bytes are
  committed fixture constants from named external references (for example
  RFC 9106 Argon2id vectors and XChaCha20-Poly1305 vectors from the
  upstream `chacha20poly1305` / libsodium test corpus), with the source and
  license recorded beside the fixture. They are never values recomputed by
  the implementation under test. Negative rows mutate AAD and tag bytes and
  assert authentication failure.
- [ ] Tests: algorithm-choice locks — the same KAT inputs run through
  `argon2::Variant::Argon2i` and `argon2::Variant::Argon2d` produce keys
  that **differ** from the committed Argon2id key, and the same plaintext /
  key / nonce inputs run through `chacha20poly1305::ChaCha20Poly1305`
  (12-byte nonce IETF construct) produce ciphertext / tag that **differ**
  from the committed XChaCha20-Poly1305 fixture. Pins the Argon2id (not
  Argon2i / Argon2d) and XChaCha20-Poly1305 (not ChaCha20-Poly1305) choices
  against silent-misconfig regressions in the `crypto::argon2` /
  `crypto::aead` wrappers. The negative-variant rows are committed fixtures,
  not values recomputed at test time.
- [ ] Tests: AEAD output shape — the encrypted on-disk body length equals
  `plaintext_len + 16` (Poly1305 tag), and the in-header `nonce` slot is
  exactly 24 bytes. Asserted as named cases against a fresh encrypted
  vault so any future swap to a different AEAD construct (e.g. AES-GCM,
  ChaCha20-Poly1305) fails the test instead of silently re-encoding.
- [ ] Tests: KDF determinism — `argon2id_derive_key(passphrase, salt,
  &Argon2Params::default()) == argon2id_derive_key(passphrase, salt,
  &Argon2Params::default())` bit-for-bit for the same inputs across
  two derivations. Pin the §4.4 contract that the 32-byte AEAD key is
  a pure function of `(passphrase, salt, params)`.
- [ ] Tests: `kdf_params_out_of_bounds` carries `m_kib`, `t`, `p`
  fields populated with the offending values (one test per field; the
  other two carry whatever in-range value was supplied).
- [ ] Tests: `wrong_vault_lock` carries `expected` and `actual` fields
  with stable string values (`"plaintext"` / `"encrypted"`); both
  cross-mode directions exercised.
- [ ] Tests: `unsupported_format_version` carries the offending
  `format_ver` value as a §5 extra field.
- [ ] Tests: wrong encrypted-vault passphrase returns `decrypt_failed`
  without constructing a vault.
- [ ] Tests: Argon2 parameter bounds rejected before any KDF work (`m_kib`
  8192–1048576, `t` 1–10, `p` 1–4). **Explicit boundary table** —
  `m_kib` at exactly `8191` (reject), `8192` (accept), `1048576` (accept),
  `1048577` (reject); `t` at `0` (reject), `1` (accept), `10` (accept),
  `11` (reject); `p` at `0` (reject), `1` (accept), `4` (accept), `5`
  (reject). Every rejection returns `kdf_params_out_of_bounds` with
  the offending field populated.
- [ ] Tests: `Argon2Params::default()` yields `m_kib = 65536` (64 MiB),
  `t = 3`, `p = 1`; `Argon2Params::validate` accepts in-range custom
  values and rejects out-of-range values with
  `kdf_params_out_of_bounds`; `EncryptionOptions::new(passphrase)`
  returns `Ok` with `kdf_params = Argon2Params::default()`;
  `EncryptionOptions::with_params(passphrase, params)` accepts in-range
  custom params and propagates `kdf_params_out_of_bounds` when the
  supplied params fail `validate()`; encrypted write paths reject
  zero-length passphrases with `invalid_passphrase`.
- [ ] Tests: regular encrypted saves preserve the in-header Argon2 params
  and `salt`, and use a freshly generated random `nonce` per save (drawn
  from the OS CSPRNG). Property-style assertion — across `N = 64`
  consecutive saves of the same vault, all observed on-disk `nonce`
  values are pairwise distinct, all `salt` values are byte-identical
  to the original, and every save → open round-trip succeeds. After a
  passphrase set/change/remove transition, the next regular save also
  preserves the *new* salt (cross-checks Phase H) so transition + save
  do not silently regenerate state.
- [ ] Tests: two consecutive saves of an unmodified `Vault` produce
  byte-distinct ciphertext-and-tag regions (proves the per-save fresh
  nonce, not just the fresh salt) while both files re-open to the
  byte-identical `VaultPayload`. Pins the §4.4 "fresh nonce per save"
  contract with a positive assertion in addition to the
  pairwise-distinct nonce property.
- [ ] Tests: header endianness fixture — write a vault with
  `Argon2Params { m_kib: 65_536, t: 3, p: 1 }` and assert the exact
  little-endian bytes at the `m_kib` / `t` / `p` header offsets
  (`00 00 01 00`, `03 00 00 00`, `01 00 00 00`) regardless of host
  byte order. A second fixture covers `m_kib: 8_192` (`00 20 00 00`).
  Pins the §4.3 wire format so a regression to native endianness fails
  the test instead of silently producing vaults that fail to open on
  big-endian hosts.
- [ ] Tests: custom `Argon2Params` round-trip via the encrypted header —
  for several in-range parameter triples (e.g. `(8_192, 1, 1)`,
  `(65_536, 3, 1)`, `(262_144, 4, 2)`, `(1_048_576, 10, 4)`), call
  `create` (or `set_passphrase` / `change_passphrase` /
  `export::encrypted`) with the params, drop the `Vault`, re-`open`
  with the same passphrase, and assert the in-memory header reports
  the same `(m_kib, t, p)` triple bit-identical to what was written.
  Pins that custom KDF cost survives write → header → read so an
  encrypted vault opened on a different machine derives the same key.
- [ ] Tests: `EncryptionOptions::new` and `EncryptionOptions::with_params`
  reject zero-length passphrase with `invalid_passphrase` /
  `reason: "zero_length"`; `export::encrypted` independently rejects
  zero-length passphrase via the same path; non-empty whitespace-only
  passphrases (`"   "`, `"\u{3000}"`), Unicode-only passphrases
  (combining marks, RTL marks, zero-width joiners), and passphrases
  differing only in NFC vs NFD normalization derive **different** keys
  (i.e. byte-equality is the only equality; no trim, no normalize).
- [ ] Tests: encrypted `create` / `create_force`, `set_passphrase`,
  `change_passphrase`, and `export::encrypted` write custom validated Argon2
  params into the header when supplied through `EncryptionOptions`.
- [ ] Tests: encrypted `create` / `create_force` fresh-material generation —
  across `N = 64` creates with the same passphrase, payload, and Argon2
  params, every observed 16-byte `salt` and 24-byte primary `nonce` is
  pairwise distinct, and every resulting vault opens successfully. This
  catches accidental fixed salt/nonce use separately from the regular-save
  nonce-rotation tests above.
- [ ] Tests: AEAD key caching — `open` derives the 32-byte key once into
  a `Zeroizing<[u8; 32]>` cached on `Vault` alongside the `SecretString`
  passphrase; subsequent saves reuse the cached key without re-running
  Argon2id (assert via deterministic test instrumentation); both
  fields are zeroized when `Vault` drops. Plaintext vaults hold no cached
  key or passphrase.
- [ ] Tests: pre-AEAD plaintext-payload zeroization — the bincode-serialized
  `VaultPayload` buffer that is fed into `crypto::aead::encrypt` is held in
  a `Zeroizing<Vec<u8>>` (or equivalent) and its bytes are wiped before the
  buffer is freed. Byte-precise assertion: hold a raw pointer to the
  buffer's backing allocation through a `#[cfg(test)]` hook, run an
  encrypted save, and verify the bytes are all zero before deallocation.
  A "buffer dropped without zeroization" regression must fail this test.
  The same assertion runs for the symmetric decrypt path: the post-AEAD
  plaintext buffer that bincode decodes is wiped after decode (success
  path) and after decode failure.
- [ ] Tests: CSPRNG failure surfaces — inject a `getrandom::Error` through
  a `#[cfg(test)]` salt/nonce source override and assert encrypted
  `create` / `create_force` / `set_passphrase` / `change_passphrase` /
  `export::encrypted` / regular encrypted save each return `io_error` with
  `operation: "csprng_read"` (added to the §5 stable operation table) and
  do not write any partial vault file or leak intermediate plaintext.
- [ ] Tests: Argon2id allocation failure — inject an Argon2 memory-allocation
  failure after parameter bounds have already passed (via a `#[cfg(test)]`
  allocator hook) and assert encrypted-write paths
  surface `io_error` with `operation: "kdf_allocation"` (added to the §5
  stable operation table) without writing a partial vault file or panicking.
  Read paths route the same allocation failure through the same operation
  string so unlocking on a memory-constrained host fails cleanly instead of
  panicking.
- [ ] Tests: `open` rejects `VaultLock` mismatches with `wrong_vault_lock`
  before any KDF work — `VaultLock::Plaintext` against an encrypted file,
  and `VaultLock::Encrypted(_)` against a plaintext file.
- [ ] Tests: encrypted `create` and `create_force` through `VaultInit`
  follow the same precondition, parent-permission, staged-clobber,
  commit-point, and durability-error semantics as plaintext storage.
- [ ] Implement `crypto::argon2` with public `Argon2Params`,
  `EncryptionOptions`, and `VaultInit` support (defaults `m_kib = 65536`
  (64 MiB), `t = 3`, `p = 1`; §4.4 read/write bounds `m_kib` 8192–1048576,
  `t` 1–10, `p` 1–4), `crypto::aead` (XChaCha20-Poly1305 with header bytes
  serialized as AAD), encrypted `Store` save/open/create/create_force
  paths, and the cached-key data model on `Vault`.

### Phase G — Vault behavior + settings (Milestone 1, part 6)

- [ ] Tests: `add` / `remove` / `iter` (insertion order) / `rename` semantics;
  `rename` reuses label validation (trim, empty rejection, 128-byte cap),
  validates the supplied timestamp, and updates `updated_at`;
  `find_duplicate` returns
  `Option<&Account>` for exact `(secret, issuer, label)` collisions and
  returns `None` for non-colliding entries; `get` returns accounts by
  `AccountId`; `summaries` returns insertion-order `AccountSummary` values
  with no secret bytes; `Vault::settings` returns the live `&VaultSettings`
  and `VaultSettings` read-only getters return the stored values;
  `VaultSettings` defaults are off with `auto_lock.timeout_secs = 300`
  and `clipboard.clear_secs = 20`; settings setters reject
  `auto_lock.timeout_secs` outside `30..=86_400` (24 h) and
  `clipboard.clear_secs` outside `5..=600` (10 min).
- [ ] Tests: `hotp_advance` rollback — inject a `Store` save error before
  primary commit point and assert in-memory counter and `updated_at` revert
  to pre-call values; durability-unconfirmed surfaced as a typed error after
  commit point; invalid supplied timestamps return `time_range` before
  mutation or save.
- [ ] Tests: `hotp_advance` at `u64::MAX` returns `counter_overflow` with
  the §5 `account` summary before mutating memory or attempting a save.
- [ ] Tests: `Vault::hotp_peek` after a committed `Vault::hotp_advance`
  returns the code for the new (post-advance) counter; `Vault::totp_code`
  is read-only and never mutates the vault or touches the `Store`.
- [ ] Tests: account-ID method failures return stable `invalid_state`
  operation/state pairs from DESIGN §4.7: `rename` / `totp_code` /
  `hotp_peek` / `hotp_advance` use `account_not_found` for missing IDs,
  `totp_code` uses `not_totp` for HOTP accounts, and `hotp_peek` /
  `hotp_advance` use `not_hotp` for TOTP accounts.
- [ ] Tests: `Vault::mutate_and_save` captures an internal snapshot, restores
  it when the mutation closure returns an error, restores it when
  `Vault::save` returns `save_not_committed`, leaves the mutated state in
  memory when save returns `save_durability_unconfirmed`, and returns the
  closure's success value unchanged on a clean save. The secret-bearing
  rollback snapshot is zeroized when dropped. Exercise add, remove, import
  merge (`skip` / `replace` / `append`), and settings changes so presentation
  crates do not need their own rollback machinery.
- [ ] Tests: `Vault::mutate_and_save` rollback covers **both** accounts
  and `VaultSettings`. A closure that mutates accounts (e.g. adds an
  entry) **and** mutates settings (e.g. flips `auto_lock.enabled` and
  changes `clipboard.clear_secs`), then returns `Err`, restores both
  the accounts list and every `VaultSettings` field to its pre-mutation
  value. A separate row covers the `save_not_committed` path with the
  same cross-field rollback; a third row covers
  `save_durability_unconfirmed`, where both account and settings
  mutations remain in memory because the primary-file commit point may
  have been reached.
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
  `AccountQuery::Search`, accepts lowercase `id:` followed by 8..=32 hex
  characters, accepts uppercase `A`–`F` within the hex prefix while
  normalizing the stored prefix to lowercase, and rejects short, long, or
  non-hex `id:` prefixes with `validation_error`
  (`field: "query"`). `Vault::matching_accounts` handles both search and
  id-prefix queries in insertion order.
- [ ] Tests: `Vault::shortest_unique_id_prefix(id)` returns the minimum
  `id:<hex>` disambiguator of at least 8 hex characters among current
  vault IDs, extends just far enough for collisions, returns the full
  32-character hex prefix when needed, and returns `None` for an ID not
  present in the vault.
- [ ] Tests: `parse_setting_key(key)` accepts exactly the four §5 dotted
  keys (`auto_lock.enabled`, `auto_lock.timeout_secs`,
  `clipboard.clear_enabled`, `clipboard.clear_secs`) and rejects unknown
  keys with `validation_error`; `parse_setting_patch(key, value)`
  reuses that parser, accepts lowercase bool values (`true` / `false`) for
  the two toggle keys and base-10 `u32` values for the two timeout keys,
  and rejects malformed / below-minimum values with `validation_error`.
  `Vault::apply_setting_patch` routes through the same typed setters so
  direct setters and CLI-style dotted patches cannot diverge.
- [ ] Tests: `ui_contract` constants locked by fixture so neither TUI
  nor GUI hard-codes a divergent value:
  - `HOTP_REVEAL_SECS == 120`
  - `QR_RGBA_MAX_BYTES == 64 * 1024 * 1024`
  - `TICK_INTERVAL_MS == 250` (TOTP gauge cadence + clipboard
    staleness check tick used by both TUI and GUI)
  - `AUTO_LOCK_SECS_MIN == 30`, `AUTO_LOCK_SECS_MAX == 86_400`
  - `CLIPBOARD_CLEAR_SECS_MIN == 5`, `CLIPBOARD_CLEAR_SECS_MAX == 600`
  Each constant is `pub` re-exported at the crate root; the test
  asserts both the value and that it is reachable through
  `paladin_core::HOTP_REVEAL_SECS` etc. so a refactor that moves
  internal modules cannot silently drop the surface.
- [ ] Tests: `policy::auto_lock::IdlePolicy` —
  `IdlePolicy::should_arm(is_encrypted: bool, settings: &VaultSettings)`
  returns `true` iff `is_encrypted == true && settings.auto_lock_enabled()`;
  `IdlePolicy::next_deadline(now: Instant, is_encrypted: bool,
  settings: &VaultSettings)`
  returns `Some(now + Duration::from_secs(settings.auto_lock_timeout_secs()
  as u64))` when armed, `None` otherwise; `IdlePolicy::is_expired(deadline,
  now)` does monotonic comparison (`now >= deadline`). Negative case:
  plaintext vault returns `None` regardless of `auto_lock_enabled`;
  this pins the §6 / §7 plaintext no-op rule in core, not in front ends.
- [ ] Tests: `policy::clipboard_clear::ClipboardClearPolicy` —
  `schedule(now: Instant, settings: &VaultSettings)` returns
  `Some((ClipboardClearToken, deadline))` when `clipboard_clear_enabled`
  is true and `None` otherwise; tokens are monotonically issued
  (`token_n.successor() == token_{n+1}`) and stale tokens are detected
  via `token_a == token_b` comparison; `should_clear(captured: &[u8],
  current: &[u8])` returns `true` iff the byte slices are byte-equal
  (front ends pass the same secret bytes they wrote and the bytes
  currently in the clipboard). Pins the §6 / §7 only-if-unchanged
  protocol.
- [ ] Tests: `policy::hotp_reveal::deadline(now: Instant) -> Instant`
  returns `now + Duration::from_secs(HOTP_REVEAL_SECS)` exactly so
  TUI countdown and GUI countdown share one source.
- [ ] Tests: `domain::query::select_after_filter(prev: Option<AccountId>,
  filtered: &[AccountId]) -> Option<AccountId>` returns `prev` when
  `prev` appears in `filtered`, returns `Some(filtered[0])` when
  `prev` is `None` or missing and `filtered` is non-empty, and
  returns `None` for an empty `filtered`. Pins the §6 / §7
  search-selection preservation rule.
- [ ] Implement `Vault` operations, `Vault::save`, `Vault::get`,
  `Vault::summaries`, `Vault::find_duplicate`, `Vault::import_accounts`,
  `Vault::totp_code`, `Vault::hotp_peek`, `Vault::hotp_advance`,
  `Vault::is_encrypted`, `Vault::settings`, `VaultSettings` read-only
  getters and setters,
  `SettingKey`, `SettingPatch`, `parse_setting_key`, `parse_setting_patch`,
  `Vault::apply_setting_patch`, and
  `Vault::mutate_and_save` per §4.7. Implement `account_match_key`,
  `account_matches_search`, `parse_account_query`,
  `Vault::matching_accounts`, `Vault::shortest_unique_id_prefix`, and
  `select_after_filter` in
  `domain/match_key.rs` / `domain/query.rs` and re-export them at the crate
  root so CLI selection plus TUI / GUI search all source matching semantics
  from core.
- [ ] Implement the `policy` module per the test bullets above:
  `policy::auto_lock::IdlePolicy` (with `should_arm`, `next_deadline`,
  `is_expired`), `policy::clipboard_clear::ClipboardClearPolicy` (with
  `schedule`, `should_clear`, and a `ClipboardClearToken` newtype that is
  `Copy + Eq + Ord` and monotonically issued), and
  `policy::hotp_reveal::deadline`. Re-export every public symbol at the
  crate root.
- [ ] Implement the `ui_contract` constants per the test bullets above
  (`TICK_INTERVAL_MS`, `AUTO_LOCK_SECS_MIN/MAX`, `CLIPBOARD_CLEAR_SECS_MIN/MAX`).
  Wire `Vault::set_auto_lock_timeout_secs` and
  `Vault::set_clipboard_clear_secs` to use these constants as the
  rejection bounds so the §5 settings table and `ui_contract.rs`
  cannot drift.

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
  mode and zeroizes the old key bytes and old passphrase. The
  zeroization assertion is *byte-precise*: the test holds a raw
  pointer (or a `*const [u8; 32]`-style fixture exposed only under
  `#[cfg(test)]`) to the previous cached buffer's allocation and
  verifies, after the transition, that those bytes are all zero
  before the buffer is freed. A "buffer simply replaced by a new
  allocation while old bytes leak" regression must fail this test.
  The same assertion is run for the cached `SecretString`
  passphrase.
- [ ] Tests: wrong-starting-state calls return the stable DESIGN §4.7
  `invalid_state` operation/state pairs (`set_passphrase` /
  `already_encrypted`, `change_passphrase` / `not_encrypted`,
  `remove_passphrase` / `not_encrypted`) before generating new crypto
  material; `set_passphrase` and `change_passphrase` reject zero-length
  passphrases with `invalid_passphrase` and `reason: "zero_length"`;
  non-empty whitespace-only and Unicode passphrases are treated as bytes
  and are not trimmed or normalized.
- [ ] Implement `set_passphrase(store, options)`,
  `change_passphrase(store, options)`, and `remove_passphrase(store)` on
  `Vault` going through the §4.3 atomic-write + backup pipeline.

### Phase I — Import / export (Milestone 3)

- [ ] Tests for `import::detect` content sniffing in the fixed §4.6 order
  (Paladin magic, image magic, Aegis JSON shape, otpauth text/JSON, then
  `Unknown`) → `ImportFormat` for each
  of: single `otpauth://` URI (with surrounding whitespace), `otpauth://`
  line list (blank lines tolerated), JSON array of URIs, Aegis JSON
  (plaintext + encrypted shapes both return `Aegis`), Paladin files by magic
  (plaintext + encrypted shapes both return `Paladin`), QR image magic
  bytes (PNG, JPEG, GIF, BMP, WebP);
  non-matching inputs return `Unknown`. Detection inspects shape only and
  never rejects on emptiness — `detect(b"")` returns `Unknown` without
  erroring; the importer is what later returns `no_entries_to_import`.
- [ ] Tests for parser robustness against malformed inputs that must not
  panic: deeply nested JSON (`[[[[ ... ]]]]` 1000 levels) returns
  `validation_error` from the otpauth/aegis parsers without exhausting
  stack; truncated PNG (only the 8-byte magic) routed through
  `read_qr_image_bytes`-equivalent path returns `io_error` with
  `operation: "decode_image_bytes"` rather than a panic; image with two
  QR codes where one decodes to a non-otpauth string and the other to a
  valid `otpauth://` URI rejects the whole batch with `validation_error`
  + `source_index` for the offending code (not the otpauth one); QR
  image at exactly `QR_RGBA_MAX_BYTES` (accept, decode), at
  `QR_RGBA_MAX_BYTES + 1` (reject pre-decode with
  `validation_error { field: "qr_image", reason: "image_too_large" }`),
  and at dimensions where `width * height * 4` would overflow `usize`
  (reject with `reason: "dimensions_overflow"`).
- [ ] Fixture hygiene: any committed third-party import fixture (for example
  Aegis or authenticator-export samples) records source and license
  compatibility per §14; prefer synthetic fixtures when they cover the same
  parser behavior.
- [ ] Tests for zero-account inputs rejected uniformly with
  `no_entries_to_import` at the importer call site: empty JSON `otpauth`
  array, blank / whitespace-only otpauth file, Aegis with empty
  `entries`, Paladin bundle that decodes to zero accounts, and image with
  no decoded QRs.
- [ ] Tests for `import::otpauth`, `import::aegis_plaintext` (encrypted
  Aegis → typed `unsupported_encrypted_aegis`; non-`totp`/`hotp` entry →
  `unsupported_aegis_entry_type` with `source_index` and `entry_type`, batch
  rejected; field mapping from `name`, `issuer`, `info.secret`, `info.algo`,
  `info.digits`, `info.period`, and `info.counter`; TOTP period defaulting to
  30; HOTP counter required; missing required `name` or `info.secret`
  rejected with `validation_error` + `source_index`; Aegis icon fields ignored
  and `icon_hint` derived from issuer),
  `import::paladin` (encrypted bundle round-trip; plaintext-mode Paladin
  file → `unsupported_plaintext_vault`; wrong bundle passphrase →
  `decrypt_failed`; stored `icon_hint` values preserved; source
  `VaultSettings` discarded),
  `import::qr_image` and `import::qr_image_bytes` (decoded QRs that are not
  `otpauth://` URIs reject the batch with `validation_error` +
  `source_index`; raw RGBA byte buffers reject zero dimensions, checked
  multiplication overflow, length mismatches, and buffers larger than
  `QR_RGBA_MAX_BYTES` (64 MiB) before decoding, then return
  `no_entries_to_import` when no QR decodes), including
  `otpauth`, QR, and Aegis imports setting `created_at = updated_at =
  import_time`; timestamps preserved for Paladin bundle imports and fresh IDs
  assigned for inserted/appended rows; replacements keep destination ID and
  `created_at` while setting `updated_at = import_time`.
- [ ] Tests for `ImportConflict` policies (`Skip` / `Replace` / `Append`)
  against running state, with collisions defined by the exact
  `(secret, issuer, label)` triple, including HOTP-to-HOTP `Replace`
  preserving `Hotp.counter` and cross-kind replace swapping the whole
  `kind`; `Replace` preserves the destination `id` and `created_at`.
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
  `write_secret_file_atomic`. Cover the **wrong passphrase vs corrupt
  bundle** distinction: a bundle written with passphrase `A` opened
  with passphrase `B` returns `decrypt_failed`; a bundle written with
  passphrase `A` whose ciphertext byte is then flipped, opened with
  passphrase `A`, also returns `decrypt_failed` (AAD/AEAD mismatch);
  a bundle whose plaintext bincode payload is replaced with garbage
  (encrypted under the right key) and opened with the right passphrase
  returns `invalid_payload` with `reason: "decode_failed"`. The three
  failure modes are distinct from `unsupported_plaintext_vault`
  (plaintext-mode Paladin file detected and rejected without
  decrypting).
- [ ] Tests: plaintext-export → re-import round-trip — write
  `export::otpauth_list(&vault)` to bytes, route those bytes through
  `import::from_bytes` with `format: None`; `detect` returns
  `Otpauth`, the importer parses every URI, and the resulting
  `Vec<ValidatedAccount>` matches the source vault's accounts modulo
  the timestamp rule (`created_at = updated_at = import_time`).
- [ ] Tests: encrypted export fresh-material generation — across `N = 64`
  encrypted exports of the same vault with the same passphrase and Argon2
  params, every observed bundle `salt` and `nonce` is pairwise distinct,
  every bundle imports successfully with the passphrase, and the exported
  account set is identical. This catches fixed-salt / fixed-nonce regressions
  in the export-only crypto path, which is separate from `Store` saves.
- [ ] Tests for `classify_paladin_import_precheck(path, forced_format)`:
  forced `otpauth` / `aegis` / `qr` return `NoPrompt` without probing for a
  Paladin passphrase; auto-detect and forced `paladin` return
  `PromptForPassphrase` for encrypted Paladin headers; return
  `Reject(unsupported_plaintext_vault)` for plaintext Paladin headers;
  return `Reject(invalid_header)` / `Reject(unsupported_format_version)` for
  malformed Paladin headers that start with `PALADIN\0`; and return
  `NoPrompt` for missing files, unreadable files, and non-Paladin magic so
  `import::from_file` remains the owner of `read_import_file`,
  auto-detect, and `unsupported_import_format` errors.
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
- [ ] Implement `PaladinImportPrecheck` and
  `classify_paladin_import_precheck(path, forced_format)` in the import
  facade module, re-exported at the crate root. It reads only enough bytes to
  classify Paladin magic/header state and returns `NoPrompt`,
  `PromptForPassphrase`, or `Reject(PaladinError)` per the test table above
  so CLI / TUI / GUI import flows never duplicate Paladin bundle prompt logic.
- [ ] Implement `export::otpauth_list(&Vault)` using the internal
  `otpauth://` emitter and `export::encrypted(&Vault, EncryptionOptions)`
  using the Paladin encrypted bundle format with default `VaultSettings`.
- [ ] Implement `read_qr_image(path: &Path) -> Result<Vec<String>>` and
  `read_qr_image_bytes(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>>` in
  `import/qr.rs`. The path form loads the image from disk; the byte form
  accepts raw RGBA8 clipboard/image buffers, rejects zero dimensions,
  rejects overflow in `width * height * 4`, rejects any buffer length
  other than that exact byte count, and rejects buffers larger than
  `QR_RGBA_MAX_BYTES` (64 MiB) with `validation_error`
  (`field: "qr_image"`, `reason: "image_too_large"`). Both decode every QR
  via `rqrr`, return one payload string per decoded QR, and return an empty
  `Vec` when the image contains no QRs — the wrapping `import::qr_image` /
  `import::qr_image_bytes` functions are what turn that into
  `no_entries_to_import`. `QR_RGBA_MAX_BYTES` is re-exported at the crate
  root alongside the QR helpers so front ends can reject oversize clipboard
  images before allocation / decode.

### Phase J — Public API freeze + library polish

- [ ] Lock default `lib.rs` re-exports to exactly the §4.7 surface; anything
  else is `pub(crate)`. The §4.7 surface explicitly includes the
  Phase B / E / G / I additions: `parse_icon_hint_token`, `IconHintInput`
  (already), `classify_init_precheck`, `InitPrecheck`,
  `classify_paladin_import_precheck`, `PaladinImportPrecheck`,
  `select_after_filter`, `policy::auto_lock::IdlePolicy`,
  `policy::clipboard_clear::ClipboardClearPolicy`,
  `policy::clipboard_clear::ClipboardClearToken`,
  `policy::hotp_reveal::deadline`, `TICK_INTERVAL_MS`,
  `AUTO_LOCK_SECS_MIN`, `AUTO_LOCK_SECS_MAX`,
  `CLIPBOARD_CLEAR_SECS_MIN`, `CLIPBOARD_CLEAR_SECS_MAX`.
- [ ] Run `cargo public-api` (the `cargo-public-api` crate, pinned in
  `xtask/dev-tools.toml`) to capture the surface; commit the
  snapshot under `crates/paladin-core/public-api.txt` and gate it in CI
  so unintended surface changes fail the build.
- [ ] Tests: `tests/error_matrix.rs` produces every core-returnable §5
  `error_kind` at least once and asserts the kind plus every stable
  extra field. Coverage rows: `validation_error` (one per `field` /
  `reason` site — manual `add`, otpauth parse, aegis import, qr
  import, settings parse, query parse), `invalid_passphrase`
  (`zero_length`), every stable `invalid_state` operation/state pair
  from §4.7 (`set_passphrase / already_encrypted`, `change_passphrase
  / not_encrypted`, `remove_passphrase / not_encrypted`, `rename /
  account_not_found`, `totp_code / account_not_found`, `totp_code /
  not_totp`, `hotp_peek / account_not_found`, `hotp_peek / not_hotp`,
  `hotp_advance / account_not_found`, `hotp_advance / not_hotp`,
  `import_paladin / missing_passphrase`), `vault_missing`,
  `vault_exists`, `unsafe_permissions` (one row per subject:
  `vault_dir`, `vault_file`, `backup_file`),
  `wrong_vault_lock` (both directions), `decrypt_failed`,
  `invalid_header` (unknown `mode`, unknown `kdf_id`, unknown
  `aead_id`, magic mismatch), `invalid_payload` (one row per
  `reason`: `too_large`, `trailing_bytes`, `decode_failed`,
  `ciphertext_too_short`), `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `unsupported_import_format`
  (auto-detect failure with `format: "unknown"` and forced-format
  failure with `format` set to the requested format),
  `unsupported_plaintext_vault`, `unsupported_encrypted_aegis`,
  `unsupported_aegis_entry_type`, `no_entries_to_import`,
  `counter_overflow`, `time_range` (TOTP, `hotp_advance`, `rename`),
  `save_not_committed`, `save_durability_unconfirmed`, and
  `io_error` for **every** stable `operation` string in §5 (one row
  per operation). The matrix test intentionally duplicates coverage
  already in per-feature test files; its purpose is to catch
  regressions where an `error_kind` is renamed or an extra field is
  dropped from a JSON-relevant variant.
- [ ] Document and test that the public types front ends move across
  thread boundaries (notably `paladin-gtk` via `gio::spawn_blocking`,
  and `paladin-tui` via the import worker thread) are all `Send`.
  Static `Send` assertions (`fn _assert_send<T: Send>() {}` calls
  in `tests/send_assertions.rs`) gate the full set in CI so a
  future change introducing `Rc` or another non-`Send` field fails
  the build instead of silently breaking either front end. The
  asserted set is exhaustive over the worker-boundary contract:
  `Vault`, `Store`, `Account`, `AccountId`, `AccountSummary`,
  `AccountKindSummary`, `Algorithm`, `Code`, `ValidatedAccount`,
  `ValidationWarning`, `ImportReport`, `ImportWarning`,
  `ImportConflict`, `ImportFormat`, `ImportOptions<'_>`,
  `EncryptionOptions`, `Argon2Params`, `VaultLock`, `VaultInit`,
  `VaultStatus`, `VaultSettings`, `SettingKey`, `SettingPatch`,
  `AccountKindInput`, `IconHintInput`, `AccountInput`,
  `AccountQuery`, `InitPrecheck`, `PaladinImportPrecheck`, and
  `PaladinError`.
- [ ] Tests: `Sync` posture — pin which of the above types are
  `Sync` and which are not. The non-secret projection types
  (`AccountSummary`, `Code`, `ImportReport`, `ImportWarning`,
  `VaultStatus`, `VaultSettings`, `Algorithm`, `AccountKindSummary`,
  `Argon2Params`, `SettingKey`, `SettingPatch`, `IconHintInput`,
  `AccountKindInput`, `AccountQuery`, `InitPrecheck`, `AccountId`)
  are asserted `Sync`. `Vault`, `Store`, `Account`, `Secret`,
  `EncryptionOptions`, `AccountInput`, `ValidatedAccount`,
  `VaultLock`, `VaultInit`, and `PaladinError` are *not* asserted
  `Sync` (`SecretString` is `!Sync` in `secrecy`); the test
  module includes a comment locking that decision so a future
  change does not accidentally promote a secret-bearing type to
  `Sync` without review.
- [ ] Tests: `tests/no_network.rs` is a source-level guard that scans the
  `paladin-core` manifest and production source tree (`src/`) and fails
  on direct references to network APIs (`std::net`, `TcpStream`,
  `UdpSocket`, `ToSocketAddrs`, `tokio`, `reqwest`, `hyper`, and similar
  denylisted spellings). It also asserts via `cargo metadata` fixtures
  that no runtime dependency resolves to the workspace `cargo deny`
  network-stack denylist. This is
  defense-in-depth on top of dependency review; it is intentionally a
  concrete source scan rather than a vacuous missing-symbol compile-fail.
- [ ] Tests: fault-injection cross-save-site coverage table. With the
  `test-fault-injection` cargo feature enabled, a single integration
  test iterates over `(save_site, fault_phase)` ∈ `{ regular_save,
  create_force, set_passphrase, change_passphrase, remove_passphrase,
  write_secret_file_atomic } × { pre_commit, post_commit }`. Every
  cell either surfaces `save_not_committed` (pre_commit) or
  `save_durability_unconfirmed` (post_commit), proving the hook
  reaches every save site uniformly. A second test fires `pre_commit`
  twice in a row on the same `Store` and asserts the second failure
  does not leak state from the first (no half-applied mutation, no
  leftover `.tmp` from the first attempt).
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
  slug rules, issuer-derived icon-hint defaulting, and timestamp upper bound.
- Manual `AccountInput` validation — `AccountKindInput` TOTP/HOTP
  selection, TOTP period defaults / overrides, HOTP counter defaults /
  overrides, manual Base32 lowercase / padded decoding plus malformed
  alphabet / padding / ASCII-whitespace rejection, and
  rejection of period-on-HOTP or counter-on-TOTP; `IconHintInput::Default`
  derives from issuer, `IconHintInput::Clear` stores `None`, and
  `IconHintInput::Slug` validates and stores the supplied slug.
- Short-secret warning surfaces in `ValidatedAccount.warnings`.
- `otpauth://` round-trip — TOTP and HOTP, with and without issuer prefix,
  case-insensitive scheme/algo/type, base32 padding/casing, duplicate known
  parameter rejection, unknown parameter ignoring, secret whitespace rejection,
  and HOTP/TOTP-specific `counter`/`period` rejection.
- `proptest` property coverage for URI parsing and base32 secret decoding.
- Bincode payload contract — fixed v2 config, trailing-bytes reject, 16 MiB
  reject (plaintext on-disk and plaintext/encrypted decoded).
- Bincode encoding determinism — same `VaultPayload` value encodes to
  bit-identical bytes across two encodes; a fixture vault matches a
  committed expected byte string so a regression to a non-deterministic
  encoding (HashMap-based or otherwise) fails the test.
- Vault round-trip in both modes, including save → drop → reopen
  preservation of `Vec<Account>` insertion order in plaintext **and**
  encrypted modes.
- `inspect(path)` header probe: missing primary returns `Missing`, plaintext
  and encrypted headers report the correct mode without decryption, invalid
  magic errors, permission checks skipped.
- `default_vault_path()` uses `ProjectDirs::from("", "", "paladin")`,
  returns the §4.3 `vault.bin` data path, or `io_error` with
  `operation: "resolve_default_vault_path"`.
- Header version / ID errors: unsupported `format_ver`, unknown `mode`,
  unknown `kdf_id`, and unknown `aead_id`.
- Header / ciphertext byte-flip matrix on encrypted vault — magic and
  unsupported header IDs fail with discriminating header errors, and every
  AAD-bound field, ciphertext byte, and tag byte fails without returning a
  vault.
- Wrong encrypted-vault passphrase returns `decrypt_failed` without
  returning a vault.
- Argon2 param bounds — out-of-range `m_kib`, `t`, or `p` rejected pre-KDF.
- Argon2 custom params — default `m_kib = 65536` (64 MiB) / `t = 3` /
  `p = 1`, in-range custom params accepted for encrypted create /
  create_force / passphrase set/change / encrypted export, and
  out-of-range custom params rejected before prompting for or accepting a
  new encrypted write.
- Encrypted save invariants — size cap pre-KDF/AEAD, Argon2 params and salt
  preserved on regular saves, fresh nonce per save, ciphertext/tag tamper
  rejection.
- Sequential identical-content saves produce byte-distinct
  ciphertext-and-tag regions while both files re-open to byte-identical
  `VaultPayload` — pins per-save fresh nonce as a positive assertion.
- Header endianness fixture — encrypted vaults written with
  `Argon2Params { m_kib: 65_536, t: 3, p: 1 }` produce exact
  little-endian header bytes (`00 00 01 00`, `03 00 00 00`,
  `01 00 00 00`) regardless of host byte order; a second fixture
  pins `m_kib: 8_192` (`00 20 00 00`).
- Custom `Argon2Params` round-trip via the encrypted header — for
  several in-range triples (e.g. `(8_192, 1, 1)`, `(65_536, 3, 1)`,
  `(262_144, 4, 2)`, `(1_048_576, 10, 4)`), `(m_kib, t, p)` survive
  write → header → read bit-identically across `create` /
  `create_force` / `set_passphrase` / `change_passphrase` /
  `export::encrypted`.
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
  the plaintext `init` / `passphrase remove` storage advisory, and the
  unencrypted-export advisory / validation warnings respectively.
- `account_match_key(&Account)` produces the canonical
  `"{issuer}:{label}"` key (empty issuer keeps the colon, casing
  preserved) so CLI query resolution and TUI / GUI search filters
  share one match-key definition.
- `account_matches_search(&Account, query)`, `parse_account_query`,
  `Vault::matching_accounts`, and `Vault::shortest_unique_id_prefix`
  implement the shared selector pieces: case-insensitive substring
  matching with no Unicode normalization, lowercase `id:` prefix validation
  with uppercase hex digits normalized to lowercase, id-prefix matching,
  insertion-order match lists, and shortest-unique `id:<hex>` candidate
  disambiguators.
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
  `get` / `summaries` / `rename` label validation and timestamp update;
  `find_duplicate` exact
  collision behavior returning `Option<&Account>`; `Vault::settings`
  getter returning the live `&VaultSettings`; `VaultSettings` read-only
  getters; settings defaults, exact timeout minimums, `parse_setting_key`
  (the four §5 keys
  `auto_lock.enabled`, `auto_lock.timeout_secs`,
  `clipboard.clear_enabled`, `clipboard.clear_secs`),
  `parse_setting_patch`, and `Vault::apply_setting_patch`.
- `Vault::mutate_and_save`: rollback on closure error and
  `save_not_committed`, durability-unconfirmed leaves mutated state, and
  success returns the closure value; the rollback snapshot is zeroized.
- `Vault::mutate_and_save` cross-field rollback: a closure that mutates
  both accounts and `VaultSettings` then errors restores **both** the
  accounts list and every `VaultSettings` field to their pre-mutation
  values; the same cross-field restoration applies on
  `save_not_committed`; on `save_durability_unconfirmed` both account
  and settings mutations remain in memory because the primary-file
  commit point may have been reached.
- HOTP `hotp_advance` rollback, durability-unconfirmed post-commit behavior,
  and `counter_overflow` at `u64::MAX` with the §5 `account` summary before
  mutation or save; invalid supplied timestamps reject before mutation or save.
- Account-ID method failures return stable `invalid_state` operation/state
  pairs for missing IDs and wrong OTP kind, matching DESIGN §4.7.
- HOTP `hotp_peek` after a committed `hotp_advance` returns the code for
  the new (post-advance) counter.
- `HOTP_REVEAL_SECS == 120`, `QR_RGBA_MAX_BYTES == 64 * 1024 * 1024`,
  `TICK_INTERVAL_MS == 250`, `AUTO_LOCK_SECS_MIN == 30`,
  `AUTO_LOCK_SECS_MAX == 86_400`, `CLIPBOARD_CLEAR_SECS_MIN == 5`,
  `CLIPBOARD_CLEAR_SECS_MAX == 600` exported as shared TUI / GUI
  constants and lock-by-fixture'd in `tests/ui_contract.rs`.
- `policy::auto_lock::IdlePolicy` (should_arm / next_deadline /
  is_expired) — encrypted-and-enabled gating, plaintext no-op,
  monotonic-Instant comparison.
- `policy::clipboard_clear::ClipboardClearPolicy` (schedule / token
  monotonicity / should_clear byte-equality decision).
- `policy::hotp_reveal::deadline(now)` matches
  `now + Duration::from_secs(HOTP_REVEAL_SECS)`.
- `select_after_filter` selection-preservation rule shared by TUI / GUI
  search.
- `parse_icon_hint_token` empty / case-insensitive `none` / slug grammar
  shared by CLI prompts and TUI / GUI add modals.
- `classify_init_precheck` truth table (`Missing` → Clear; `Plaintext` /
  `Encrypted` / `invalid_header` / `unsupported_format_version` →
  Existing; everything else → Propagate).
- Passphrase transitions: `set`, `change`, `remove`; pre-commit rollback;
  durability-unconfirmed post-commit; default/custom Argon2 params for
  encrypted targets; fresh salt/nonce behavior; backup rewritten under the
  target mode/key; cache lifecycle and old-material zeroization;
  wrong-starting-state `invalid_state` operation/state pairs matching
  DESIGN §4.7; zero-length new passphrase rejection with
  `reason: "zero_length"`; no trimming or Unicode normalization of non-empty
  passphrase bytes.
- `import::detect`: fixed §4.6 detection order, Paladin magic, QR image
  magic (PNG, JPEG, GIF, BMP, WebP), Aegis plaintext/encrypted shapes,
  single/list/JSON-array `otpauth://`, empty otpauth JSON array shape, and
  `Unknown`.
- Import facade: `from_file` / `from_bytes` auto-detect and forced-format
  dispatch, `unsupported_import_format` for unknown or invalid dispatch,
  `format` set to `"unknown"` for auto-detect failures and to the requested
  format for forced-format failures, missing Paladin bundle passphrase as
  `invalid_state`, and encoded image bytes routed through QR decoding.
- `classify_paladin_import_precheck`: forced non-Paladin formats skip the
  prompt classifier; auto-detect / forced-Paladin encrypted headers return
  `PromptForPassphrase`; plaintext or malformed Paladin headers return
  `Reject(...)` with the typed core error; missing files, unreadable files,
  and non-Paladin magic return `NoPrompt` so the import facade owns final
  read/dispatch errors.
- Importers: Aegis plaintext field mapping, defaults, and required fields;
  Aegis encrypted → typed `unsupported_encrypted_aegis`; Aegis
  non-`totp`/`hotp` entry type →
  `unsupported_aegis_entry_type` with `source_index` and `entry_type` (batch
  rejected);
  missing required Aegis fields reject with `validation_error` +
  `source_index`; Aegis icon fields ignored and `icon_hint` derived from
  issuer; non-Paladin `otpauth` / QR imports derive `icon_hint` from issuer;
  Paladin bundle round-trip with timestamps and stored `icon_hint` values
  preserved and source `VaultSettings` discarded; plaintext-mode Paladin file →
  `unsupported_plaintext_vault`; wrong bundle passphrase →
  `decrypt_failed`; QR image path and raw RGBA byte buffer with N codes;
  raw RGBA zero dimensions, multiplication overflow, and length mismatch;
  non-otpauth QR payloads rejected with `validation_error` + `source_index`;
  URI-list trimming and blank-line handling; non-Paladin imports use
  `import_time`; zero-account inputs rejected uniformly with
  `no_entries_to_import`.
- `ImportConflict` policies (`Skip` / `Replace` / `Append`) including
  running-state collisions on the `(secret, issuer, label)` triple,
  destination `id` / `created_at` preservation on replace, HOTP counter
  preservation, cross-kind replacement, `ImportReport` counts /
  account IDs, batch atomicity, and warnings retained even for skipped rows.
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
  passphrases. Cached-key replacement on `change_passphrase` is
  byte-precisely zeroized (the previous buffer is all-zero before
  free, not just dropped) so a "replace pointer, leak old bytes"
  regression fails.
- Per-AAD-field byte-flip matrix: named cases per region (magic,
  format_ver, mode, kdf_id, m_kib, t, p, salt edges, aead_id, nonce
  edges, ciphertext, AEAD tag) with the discriminating error kind
  pinned per region (e.g. magic flip → `invalid_header`,
  unsupported `format_ver` → `unsupported_format_version`,
  in-bounds Argon2 param flip → `decrypt_failed`).
- Published crypto KATs: Argon2id fixed passphrase / salt / params →
  expected 32-byte key, and XChaCha20-Poly1305 fixed key / nonce /
  AAD / plaintext → expected ciphertext + tag, with mutated AAD/tag
  rows proving authentication failure.
- Algorithm-choice locks: same KAT inputs through Argon2i / Argon2d
  produce keys distinct from the committed Argon2id key, and same
  inputs through ChaCha20-Poly1305 (12-byte nonce IETF) produce
  ciphertext / tag distinct from the committed XChaCha20-Poly1305
  fixture — pinning Argon2id and XChaCha20-Poly1305 against silent
  swap regressions.
- AEAD output shape: ciphertext-body length equals `plaintext_len + 16`
  (Poly1305 tag) and the in-header `nonce` slot is exactly 24 bytes,
  asserted against a fresh encrypted vault.
- Pre-AEAD plaintext-payload zeroization (encrypt) and post-AEAD
  plaintext-payload zeroization (decrypt success and decode failure)
  proven byte-precisely via a `#[cfg(test)]` raw-pointer hook,
  matching the existing rollback-snapshot / cached-key zeroization
  posture.
- CSPRNG failure surfaces: injected `getrandom::Error` on every
  encrypted-write save site routes through `io_error` with
  `operation: "csprng_read"` and does not write a partial vault file.
- Argon2id allocation failure: injected memory-allocation failure on
  encrypted read and write paths surfaces `io_error` with
  `operation: "kdf_allocation"` without panic or partial write.
- Symbolic-link rejection on `open` / `create` / `create_force` for
  `vault.bin`, `vault.bin.bak`, and the parent data directory, using
  `symlink_metadata` so the probe never follows the link; the typed
  rejection fires even when permissions look correct (defense in
  depth).
- Argon2 param boundary table at exact accept/reject edges
  (`m_kib` 8191/8192/1048576/1048577, `t` 0/1/10/11, `p` 0/1/4/5)
  with `kdf_params_out_of_bounds` payload field assertions.
- KDF determinism: identical (passphrase, salt, params) inputs
  produce a bit-identical 32-byte AEAD key across two derivations.
- Fresh salt/nonce generation: repeated encrypted create/create_force
  operations and repeated encrypted exports over identical logical inputs
  produce pairwise-distinct salts and nonces while all outputs still
  open/import successfully.
- Malformed ciphertext shorter than the 16-byte AEAD tag returns
  `invalid_payload { reason: "ciphertext_too_short" }`, not a panic.
- Send / Sync matrix: every public type listed under Phase J is
  asserted `Send`; the non-secret projections are also asserted
  `Sync`; secret-bearing types are deliberately not `Sync` and the
  test pins that decision.
- `tests/no_network.rs` source / metadata guard proves production
  `paladin-core` has no direct network API use and no runtime
  network-stack dependencies.
- `tests/error_matrix.rs` produces every core-returnable §5
  `error_kind` at least once with full extra-field assertions.
- Fault injection cross-save-site coverage table covers
  `{ regular_save, create_force, set_passphrase, change_passphrase,
  remove_passphrase, write_secret_file_atomic } × { pre_commit,
  post_commit }` plus a back-to-back fault test proving no leaked
  half-state between two failures on the same `Store`.
- Pre-commit recoverable state: regular-save failure after backup commit
  but before primary commit leaves the old primary authoritative at
  `vault.bin`, leaves `vault.bin.bak` containing the old primary bytes,
  and cleans temp files; `create_force` failure after verbatim backup
  rotation but before primary commit is the separate clobber case where
  the primary path can be absent and `backup_path` is set. Post-commit
  success replay shows fresh nonce on disk and old primary moved verbatim
  to `.bak`; `.bak` corruption never affects success-path `open`.
- HOTP at counter `u64::MAX - 1` advances successfully to `MAX`; a
  subsequent advance returns `counter_overflow` before any mutation
  or save (off-by-one fence-post pin).
- TOTP digits × algorithm cross-product (digits ∈ {6, 7, 8} ×
  algorithm ∈ {SHA1, SHA256, SHA512}) for at least one vector each.
- Plaintext export → re-import round-trip via `import::from_bytes` /
  `detect == Otpauth` produces accounts that match the source vault
  modulo `created_at = updated_at = import_time`.
- Multi-QR mixed-payload image rejects the whole batch with
  `validation_error.source_index` for the non-otpauth payload.
- QR cap boundary: exactly `QR_RGBA_MAX_BYTES` accepts; one byte
  over rejects with
  `validation_error { field: "qr_image", reason: "image_too_large" }`;
  dimensions overflowing `usize` reject with
  `reason: "dimensions_overflow"`.
- Wrong-passphrase vs corrupt-bundle vs decode-failure distinction
  on encrypted Paladin imports (decrypt_failed on wrong key, decrypt_failed
  on AEAD/AAD tamper, invalid_payload on garbage-but-valid-ciphertext).

## Dependencies (per §4.4 / §9)

`hmac`, `sha1`, `sha2`, `argon2`, `chacha20poly1305`, `secrecy`, `zeroize`,
`getrandom` (pinned explicitly so the salt/nonce CSPRNG source per §4.4
doesn't drift across transitive minor versions), `base32`, `url`,
`bincode` (v2), `serde`, `serde_json`, `directories`, `uuid`, `thiserror`,
`rqrr`, `image`. No `tokio`, no `reqwest`, no network-touching crate.

Dev/test only: `proptest` (parser/base32 properties), `trybuild`
(compile-fail coverage for `Secret: !Debug`, `Account: !Serialize` /
`Secret: !Serialize` even with the `error-serde` feature on), and
`tempfile` (storage and permission fixtures). `tests/no_network.rs` uses
the standard library plus the already-present manifest / JSON tooling to
scan production source and metadata for network API or dependency drift.

## Packaging support (per §11)

`paladin-core` is a library and is not itself a release artifact, but
the v0.1 / v0.2 packaging pipeline depends on the workspace shape it
defines. Implementation owes:

- **Cargo.toml metadata.** `crates/paladin-core/Cargo.toml` carries
  `description`, `repository = "https://github.com/FreedomBen/paladin"`,
  `homepage = "https://paladin.tamx.org"`,
  `license = "AGPL-3.0-or-later"`, and
  pinned `rust-version`. Binary crates inherit consistent values via
  per-field Cargo inheritance (`description.workspace = true`,
  `repository.workspace = true`, `homepage.workspace = true`, and so on)
  so `nfpm` and Flathub manifests read one source.
- **Deterministic, vendor-friendly deps.** The §9 dep list above
  resolves cleanly under `cargo vendor`; pinning `getrandom`
  (already required for the §4.4 CSPRNG contract) plus
  `cargo build --locked` is sufficient for §11.6 reproducibility.
  No build-time codegen depends on system clock, hostname, or
  network.
- **Stable `error_kind` taxonomy.** `PaladinError` exposes the
  core-returnable §5 kinds verbatim (no internal renaming) so the
  `paladin` CLI can serialize them under `--json` and the strict-output
  rule in §5 holds without any mapping layer. The stable
  `invalid_state.operation` / `state` pairs from DESIGN §4.7 are part of
  that contract. Add a `serde::Serialize` impl guarded by an `error-serde`
  cargo feature, off by default, that the CLI opts into; `paladin-core`
  itself has no JSON output paths. The
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
