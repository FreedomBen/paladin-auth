# Paladin — Design Document

A Rust OTP authenticator (TOTP + HOTP) with CLI and TUI front-ends in v0.1,
plus a GTK4 GUI planned for v0.2, all sharing a common core. Status:
**approved 2026-05-04 / pre-implementation**.

## 1. Goals

- **Local-first.** All secrets live on the user's machine.
- **One core, many faces.** Domain logic, storage, and crypto live in a single
  library crate. The CLI, TUI, and planned GUI are thin presentation layers.
- **Compatible.** Read/write standard `otpauth://` URIs (RFC 6238 / RFC 4226 /
  Google Authenticator key-URI format). Import from QR images. Import from
  Aegis exports. (Gnome Authenticator's "Backup → Save in plain text"
  is already a list of `otpauth://` URIs and rides the same import
  path.) Export plaintext or encrypted.
- **Optional passphrase.** A vault may be passphrase-encrypted or stored in
  plaintext. The user chooses, and can change that choice at any time.
- **User-controlled hardening.** Auto-lock and clipboard auto-clear are
  **off by default** and opt-in. When enabled, timeouts are user-configurable.

## 2. Non-goals

- **Cloud sync, multi-device pairing, or accounts.** Permanently out of scope.
  Users who want sync can export an encrypted bundle and move it themselves.
- **Webcam-based QR scanning.** Image-file scanning yes; live camera no.
- **Mobile platforms.**
- **macOS and Windows.** v0.1 targets Linux; `directories::ProjectDirs`
  provides cross-platform paths, but CI, packaging, and clipboard/UI
  testing on those platforms are deferred to v0.2+.
- **Hardware-token (YubiKey HMAC-SHA1) backends.** Possible later.

## 3. Workspace layout

```
paladin/
├── Cargo.toml                # virtual workspace
├── DESIGN.md
├── README.md
├── crates/
│   ├── paladin-core/         # lib: domain, OTP, storage, crypto, import/export
│   ├── paladin-cli/          # bin: `paladin`
│   ├── paladin-tui/          # bin: `paladin-tui`
│   └── paladin-gtk/          # planned v0.2 bin: `paladin-gtk`
└── xtask/                    # optional: build/release helpers
```

Binaries depend only on `paladin-core`. They never reach into each other.

## 4. Core crate (`paladin-core`)

### 4.1 Domain model

| Type         | Purpose                                                                  |
| ------------ | ------------------------------------------------------------------------ |
| `Account`    | A single OTP entry: id (`AccountId`), label, issuer, secret, algo, digits, kind, icon_hint (see below), created/updated. |
| `AccountId`  | UUIDv4. Stored as 16 bytes in the vault; displayed in canonical hyphenated form. Short `id:<8 hex>` prefix is the usual CLI disambiguator; candidate lists extend beyond 8 hex chars when needed for uniqueness. |
| `Secret`     | Newtype wrapping `Vec<u8>`; implements `Zeroize` and `Drop`.             |
| `Algorithm`  | Enum: `Sha1` (default), `Sha256`, `Sha512`.                              |
| `OtpKind`    | Enum: `Totp { period: u32 }` (default 30s) or `Hotp { counter: u64 }`.   |
| `Vault`      | The decrypted in-memory collection of `Account`s + `VaultSettings`.      |
| `VaultSettings` | Per-vault user prefs (auto-lock on/off + timeout, clipboard clear on/off + timeout). Persisted **inside** the vault payload. |
| `Store`      | Persistence handle backed by a file on disk (plaintext or encrypted).    |
| `Code`       | A generated OTP: digits, validity window (TOTP) or counter (HOTP).       |

`VaultSettings` lives inside the encrypted/plaintext payload — never in the
file header — so settings can't be tampered with on an encrypted vault.

`Account.icon_hint` is an `Option<String>` icon-name slug. The slug
matches `[a-z0-9_-]+` (freedesktop icon-naming-spec convention) and is
at most 64 bytes. On `add` we default it from the issuer, when present, by
lowercasing and replacing each run of disallowed characters with a
single `-`, then trimming leading/trailing `-` (e.g. `"GitHub"` →
`"github"`, `"Google Cloud"` → `"google-cloud"`); if the result is
empty, exceeds 64 bytes, or if the issuer is `None`, the field stays
`None`. The user can
override or clear it. The slug is a hint, not a guarantee: GUIs resolve
it (§7); the CLI and TUI ignore the field. We deliberately do not store
icon bytes — that would
inflate the vault and complicate the bincode payload without offering
meaningful benefit over icon-theme lookup.

`Account` fields are private; manual entry, URI parsing, importers, and any
constructors all go through the same validation path:

| Field                      | Rule                                                                            |
| -------------------------- | ------------------------------------------------------------------------------- |
| `label`                    | Trim Unicode whitespace; reject empty; max 128 UTF-8 bytes.                     |
| `issuer`                   | Trim Unicode whitespace; empty becomes `None`; max 128 UTF-8 bytes when set.    |
| `secret`                   | 10 to 1024 decoded bytes. 10-15 bytes are accepted with a per-entry warning.    |
| `algorithm`                | `Sha1`, `Sha256`, or `Sha512`; default `Sha1`.                                  |
| `digits`                   | 6 to 8 inclusive; default 6. Codes are zero-padded to exactly this width.        |
| `Totp.period`              | 1 to 300 seconds inclusive; default 30.                                         |
| `Hotp.counter`             | 0 to `u64::MAX`; default 0 for manual `add` without an explicit value; `hotp_advance` errors before mutation at `u64::MAX`. |
| `icon_hint`                | `None`, or 1–64 bytes matching `[a-z0-9_-]+`.                                   |
| `created_at`, `updated_at` | UTC Unix seconds (`u64`), 0 to 253402300799 inclusive.                          |

For `otpauth://` imports, the path label and `issuer` query parameter are
percent-decoded, then normalized with the rules above. If both an issuer
prefix in the label (`Issuer:Account`) and an `issuer` query parameter are
present, they must be byte-equal after both are normalized
(case-sensitive), or the URI is rejected.

The `otpauth://` parser applies these rules:

- **Scheme and type:** scheme must be `otpauth` and type/host must be
  `totp` or `hotp`, all matched case-insensitively.
- **Label path:** required, non-empty after trimming, percent-decoded as
  UTF-8. If the decoded label contains `:`, split on the first `:` into
  issuer prefix and account label.
- **`issuer`:** optional, percent-decoded as UTF-8, and normalized with
  the issuer rule above. If also present as a label prefix, the two
  issuers must match after issuer normalization.
- **`secret`:** required. Base32 using the RFC 4648 alphabet,
  case-insensitive, with optional `=` padding. ASCII whitespace inside
  the value is rejected.
- **`algorithm`:** optional and defaults to `SHA1`. Accepted values are
  `SHA1`, `SHA256`, and `SHA512`, case-insensitive.
- **`digits`:** optional and defaults to `6`. Must be an unsigned decimal
  integer and pass the `digits` validation range above.
- **`period`:** TOTP-only, optional, and defaults to `30`. Must be an
  unsigned decimal integer and pass the TOTP period range above. Rejected
  on HOTP URIs.
- **`counter`:** HOTP-only and required. Must be an unsigned decimal
  integer and pass the HOTP counter range above. Rejected on TOTP URIs.
- **Duplicate parameters:** duplicate known parameters (`secret`,
  `issuer`, `algorithm`, `digits`, `period`, `counter`) are rejected.
- **Unknown parameters:** ignored after URL parsing; this keeps
  compatibility with authenticators that add non-standard metadata such as
  `image`.

`created_at` is stable after account creation; `updated_at` changes on any
account payload mutation, including HOTP counter advances. The timestamp
upper bound is `9999-12-31T23:59:59Z`.

Validation warnings are distinct from validation errors. A warning never
prevents account creation or import, but every caller that accepts new
account material must surface it. v0.1 has one warning kind:
`short_secret { decoded_len, recommended_min: 16 }`, emitted for decoded
secrets between 10 and 15 bytes inclusive.

### 4.2 OTP generation

- **TOTP:** RFC 6238, on top of `hmac` + `sha1` / `sha2`. Validate against
  RFC 6238 Appendix B test vectors. Generation is read-only — `totp_code`
  takes `&self` and never mutates the vault. The TOTP counter is
  `floor(now_unix / period)`. `valid_from = counter * period` and
  `valid_until = valid_from + period`, interpreted as the half-open window
  `[valid_from, valid_until)`. `seconds_remaining` is
  `valid_until - now_unix`; because `now_unix` selects the active counter,
  a successful call reports a value in `1..=period`, with an exact window
  boundary selecting the new counter and reporting the full period.
  `totp_code` rejects `SystemTime` values before the Unix epoch instead of
  saturating, and returns a time-range error if `valid_until` would overflow
  `u64`.
- **HOTP:** RFC 4226, same primitives. Validate against RFC 4226 Appendix D
  test vectors. Both entry points compute `HOTP(K, C)` for the current
  stored counter `C`; they differ only in whether they mutate state:
  - `hotp_peek` returns the code without advancing — used by UIs
    that want to render the code before the user commits to "use" it.
  - `hotp_advance` returns the same code, advances the stored counter
    to `C + 1`, sets `updated_at` to the supplied `now`, **and saves the
    vault atomically**. It takes `&Store`
    for that reason. If the save fails before the primary-file commit
    point (§4.3), the in-memory counter and `updated_at` are rolled back
    to their previous values and `hotp_advance` returns `Err`. If the
    save reaches the primary-file commit point but the final durability
    check fails, the in-memory counter remains advanced and the error is
    reported as durability-unconfirmed. A subsequent `hotp_peek` after a
    committed advance therefore returns the code for the new counter.

### 4.3 Storage

#### File format

```
[magic:        "PALADIN\0"   (8 bytes)]
[format_ver:   u8            ]
[mode:         u8            ]   // 0 = plaintext, 1 = encrypted
if mode == 1:
    [kdf_id:   u8            ]   // 1 = Argon2id (other IDs reserved)
    [argon2 params: m_kib u32, t u32, p u32  (little-endian, 12 bytes total)]
    [salt:     16 bytes      ]
    [aead_id:  u8            ]   // 1 = XChaCha20-Poly1305 (other IDs reserved)
    [nonce:    24 bytes      ]
    [ciphertext + tag]           // encrypted bincode(VaultPayload)
else:
    [bincode(VaultPayload)]
```

`VaultPayload` = `{ accounts: Vec<Account>, settings: VaultSettings }`.
It is encoded with bincode v2 using:

```rust
bincode::config::standard()
    .with_little_endian()
    .with_fixed_int_encoding()
    .with_limit::<16_777_216>()
```

Decode requires full input consumption: trailing bytes after the
`VaultPayload` are an `invalid_payload` error. The 16 MiB limit applies to the
serialized `VaultPayload` bytes, excluding the Paladin header and AEAD tag;
`open` rejects plaintext payloads and decrypted encrypted payloads that exceed
that limit before constructing a `Vault`. To bound resource use before
authentication, `open` also rejects vault files whose on-disk size exceeds
`header_size + 16 MiB` for plaintext mode, or `header_size + 16 MiB +
16 byte AEAD tag` for encrypted mode, with `invalid_payload` before any
decoding or KDF/AEAD work.

- **Location.** Resolved via `directories::ProjectDirs::data_dir()`,
  which on Linux follows the XDG Base Directory spec and on macOS /
  Windows follows the platform conventions baked into the
  `directories` crate. The vault is application data (a secrets
  store), not user-editable configuration, so it lives under
  `XDG_DATA_HOME` — **not** `XDG_CONFIG_HOME`. The latter is reserved
  for any future preferences file that ships separately from the
  vault.
  - Linux (v0.1 target):
    `${XDG_DATA_HOME:-~/.local/share}/paladin/vault.bin`.
  - macOS / Windows: whatever `ProjectDirs::data_dir()` returns under
    the platform conventions. The exact paths depend on the
    `ProjectDirs::from(qualifier, organization, application)`
    arguments chosen at instantiation and are exercised once v0.2
    adds those targets (§2).

  The filename is always `vault.bin`; the on-disk encoding is the
  private bincode format described above (it is binary regardless of
  mode and is not interop with any other tool). A `--vault <path>`
  flag on every binary overrides the resolved location for testing
  and for users who keep their vault on removable media.
- **Permissions.** File is created `0600` regardless of mode; temporary
  files and backups are also `0600`. The parent directory, if we create
  it, is `0700`. In plaintext mode these permissions are the *only*
  protection on the secrets, so we enforce them. On Linux v0.1, `open`
  rejects a vault before decoding if the parent directory grants any
  group/other permissions, or if the primary or backup file, when present,
  grants any group/other permissions. The CLI text error names the failing
  path, actual mode, expected repair mode, and the `chmod` command that
  would repair it; `--json` reports `unsafe_permissions` with `path`,
  `subject`, `actual_mode`, and `expected_mode` fields. Mode fields are
  four-digit octal strings such as `"0644"`, with expected repair modes
  `"0700"` for directories and `"0600"` for files. `subject` is one of
  `vault_dir`, `vault_file`, or `backup_file`.
- **Atomic writes.** Each save stages both the new primary and the new
  backup, then commits with renames:
  1. Write the new primary content to `vault.bin.tmp` and `fsync` it.
  2. Write the new backup content to `vault.bin.bak.tmp` and `fsync`
     it. Skipped, along with step 3, on a first-ever save when no
     prior content exists.
     For regular saves the backup content is the soon-to-be-replaced
     primary; for passphrase transitions (§4.5) it is reconstituted
     under the new mode/key.
  3. `rename` `vault.bin.bak.tmp` → `vault.bin.bak` (overwriting any
     existing backup).
  4. `rename` `vault.bin.tmp` → `vault.bin` (overwriting the prior
     primary).
  5. `fsync` the parent directory so the renames are durable across
     power loss.

  Step 4 is the primary-file commit point. A crash or error before step
  4 leaves the previous primary in place (or no primary at all on a
  first-ever save); a crash or error between steps 3 and 4 leaves the
  new `.bak` paired with the old primary. A crash or error after step 4
  may leave the new primary in place even if the save reports failure
  because durability could not be confirmed. The primary file is never
  partially written, but `.bak` is not transactionally rolled back: once
  step 3 succeeds it may remain rotated even if a later step fails.
  Recovery code treats `vault.bin` as authoritative and `vault.bin.bak`
  as a one-generation recovery file, not as a guarantee of rollback
  state. Any leftover `vault.bin.tmp` or `vault.bin.bak.tmp` from a
  partial save is overwritten on the next save and unlinked by the next
  `open`. On any non-crash error during a save, remaining `.tmp` files
  are unlinked before the call returns; completed renames are not undone.
- **Backups.** For normal saves and passphrase transitions, every
  successful write after a primary already exists keeps the previous primary
  payload available as `vault.bin.bak` (one generation). The backup is
  always written to match the mode and key of the **new** primary: for
  regular saves this is the same as the previous primary, and for passphrase
  transitions (§4.5) the rotated `.bak` is rewritten so it never preserves a
  superseded encryption state — re-encrypted under the new key for
  `set_passphrase` and `change_passphrase`, or written as plaintext for
  `remove_passphrase`. The explicit `paladin init --force` clobber path is
  the exception: it stages the new vault first, then rotates the old
  primary verbatim during its clobber commit sequence (§5), so it never
  rewrites the old payload under the new mode/key.
- **Versioning.** `format_ver` starts at `1` for v0.1 and is bumped on any
  breaking change to the header layout or `VaultPayload` schema. Old
  versions are read by an explicit migration path — never silently coerced.

### 4.4 Crypto (when mode == encrypted)

- **KDF:** Argon2id with sane defaults (m=64 MiB, t=3, p=1), tunable in the
  header so we can raise costs over time without breaking old vaults. The
  passphrase + salt deterministically derive the 32-byte AEAD key. Regular
  saves preserve the in-header Argon2 parameters, so an old vault opened on
  a faster machine does not silently inherit higher cost on its next write;
  raising costs requires an explicit `change_passphrase` (or a future
  dedicated upgrade command). To avoid attacker-controlled resource
  exhaustion before authentication, `open` rejects encrypted vaults whose
  header parameters are outside these bounds before running Argon2id:
  `m_kib` 8192 to 1048576 (8 MiB to 1 GiB), `t` 1 to 10, and `p` 1 to 4.
  The 8 MiB floor is deliberately well below the 64 MiB default and
  OWASP's 19 MiB Argon2id guidance: it is the minimum we will *accept on
  read* so that vaults written on memory-constrained hardware (small
  SBCs, low-RAM headless boxes) can still be opened. New
  vaults always pick the default unless the user opts into a custom
  cost. Future releases may widen those bounds only with an explicit
  format or policy update.
- **AEAD:** **XChaCha20-Poly1305** (24-byte nonce, simpler misuse story than
  AES-GCM). Header records the algorithm ID so we can migrate later. All
  header bytes after the magic — `format_ver`, `mode`, `kdf_id`, the Argon2
  params, `salt`, `aead_id`, and `nonce` — are passed as AEAD associated
  data, so tampering with any of them fails decryption. Each save uses a
  freshly generated random nonce; salt is preserved across regular saves and
  regenerated only on passphrase transitions (§4.5). Salt and nonce are
  drawn from the OS CSPRNG (`getrandom`).
- **Key handling:** for an encrypted vault, the 32-byte AEAD key is
  derived from `(passphrase, salt)` at `open` into a
  `Zeroizing<[u8; 32]>` and cached on the `Vault` for its lifetime,
  alongside the retained `SecretString` passphrase. Saves reuse the
  cached key rather than re-deriving — Argon2id at the default cost is
  hundreds of milliseconds, which would otherwise be paid per HOTP
  advance. Both the key and the passphrase are zeroized when the
  `Vault` is dropped, and replaced (with the old material zeroized)
  after a passphrase transition reaches the primary-file commit point.
  A transition that fails before that point leaves the cached key and
  passphrase in place so the vault remains usable under the previous
  state; a durability-unconfirmed failure after the commit point keeps
  the new cached material because the primary file has already switched
  modes/keys.
  Caching the key does not expand the threat model: an attacker with
  memory access to the running process could derive it from the
  retained passphrase regardless.
- **Passphrase prompt:** via `rpassword` for the CLI; via the host UI for the
  TUI/GUI.

### 4.5 Passphrase management

A vault's encryption state is mutable at runtime. The user can:

| Operation             | Starting state | Resulting state | Notes                                       |
| --------------------- | -------------- | --------------- | ------------------------------------------- |
| **Set passphrase**    | plaintext      | encrypted       | Generate fresh salt + nonce; derive key; encrypt. The rotated `.bak` is also encrypted under the new key (with its own fresh nonce) so it cannot retain the previous plaintext secrets. |
| **Change passphrase** | encrypted      | encrypted       | Decrypt with old; fresh salt + nonce; encrypt with new. The rotated `.bak` is re-encrypted under the new key (with its own fresh nonce) so the old key — which the user may be retiring because it was compromised — cannot recover prior contents from the backup. |
| **Remove passphrase** | encrypted      | plaintext       | Decrypt; write payload directly. The rotated `.bak` is also written as plaintext, so it remains accessible without the just-removed passphrase. Loud confirmation required. |

All three go through the same atomic-write + backup path as a normal save.
Each is a single-step transition with the primary-file commit point defined
in §4.3. A failure before that point leaves the primary file untouched and
rolls the in-memory vault back to its previous mode/key. A failure after
that point is reported as durability-unconfirmed: the primary may already
contain the new mode/key, `.bak` may already be rotated, and the in-memory
vault remains on the new mode/key so later saves do not overwrite the
committed transition with stale crypto material.
Calling an operation from the wrong starting state returns a typed
invalid-state error before prompting for a new passphrase or generating new
crypto material.
`set_passphrase` and `change_passphrase` reject zero-length passphrases (no
trimming or Unicode normalization is applied to passphrase bytes); users who
want plaintext storage must use `remove_passphrase`.

### 4.6 Import / Export

#### Export

Two formats, user picks per invocation:

- **Plaintext (otpauth URI list).** A JSON array of `otpauth://` URIs, one
  entry per account (HOTP entries carry their counter via the standard
  `counter` URI parameter, per the Google Authenticator key-URI format).
  This *is* the otpauth URI list format — there is no Paladin-specific
  plaintext envelope, and on import these files are read via the otpauth
  path. Cross-compatible with most authenticators that accept URI lists.
  **The CLI prints a clear warning** before writing unencrypted secrets to
  disk and refuses to write to a file that already exists unless `--force`
  is given.
- **Encrypted (Paladin bundle).** The same accounts encoded as
  `VaultPayload { accounts, settings: VaultSettings::default() }` and
  wrapped in Paladin's encrypted file format (§4.3) under a passphrase
  the user supplies at export time (independent of the vault's own
  passphrase). Empty passphrases are rejected: `export::encrypted`
  returns an error rather than silently producing a plaintext-equivalent
  bundle. The CLI refuses to write an encrypted export to a file that
  already exists unless `--force` is given, matching plaintext export.

#### Import

Auto-detect format by content sniffing, with `--format` to override:

- **`otpauth://` URI** (single line, one per nonblank line, or JSON array).
  This is also the format produced by Gnome Authenticator's *Backup →
  Save in plain text* action (FreeOTP+-compatible URI list), so Gnome
  exports import through this path with no dedicated handler. For text
  inputs, the importer trims leading/trailing Unicode whitespace around
  the whole input for single-URI detection, trims each line in line-list
  mode, and ignores blank lines. Inputs that decode to zero accounts
  (empty JSON array, blank file, whitespace-only) are rejected with the
  same "no entries to import" error as a QR image with no decoded QRs.
- **Paladin encrypted bundle** — round-trips with our encrypted exporter.
  Files with `PALADIN\0` magic but plaintext mode are rejected by the
  Paladin importer in v0.1; users should use `export --plaintext` to
  produce a portable `otpauth://` URI list instead. Plaintext exports are
  detected and read as `otpauth://` URI lists above (they share the same
  on-disk format).
- **Aegis** — JSON export. v0.1 supports the **plaintext export** out of
  the box; **encrypted Aegis backups** (scrypt + AES-256-GCM) are a stretch
  goal for v0.2 since they require implementing Aegis's KDF profile.
  Detection (below) returns `Aegis` for both shapes because they share
  the same top-level JSON layout, so v0.1 `import::aegis_plaintext`
  returns a typed unsupported-encrypted-aegis error when handed a
  backup whose `header` indicates encryption — without prompting for a
  passphrase. Aegis exports with an empty `entries` array are rejected
  with the same "no entries to import" error as the otpauth and QR
  paths. Plaintext Aegis entries are accepted only when `type` is `totp`
  or `hotp`; any other entry type rejects the whole batch with
  `unsupported_aegis_entry_type` and `source_index`, preserving import
  atomicity. Accepted entries map `name` → `label`, `issuer` → `issuer`
  (empty becomes `None`), `info.secret` → `secret`, `info.algo` →
  `algorithm`, `info.digits` → `digits`, `info.period` → `Totp.period`,
  and `info.counter` → `Hotp.counter`. `info.algo` defaults to `SHA1`
  and `info.digits` defaults to `6` if absent (matching §4.1). `name`
  and `info.secret` are required; missing either rejects the batch with
  `validation_error` carrying `source_index`. TOTP `period` defaults to
  30 if absent; HOTP `counter` is required. Aegis icon fields and other metadata
  are ignored in v0.1; `icon_hint` is derived from the issuer using the
  §4.1 slug rule.
- **QR image file** — one or more accounts (one per decoded QR);
  errors if no QRs are decoded. Uses `rqrr` to decode every QR in the
  image and feeds each resulting `otpauth://` URI through the URI
  parser. The GTK GUI also accepts a QR image pasted from the
  clipboard, decoded via the same path.

`detect` resolves the format in this fixed order, returning the first
match: file starts with the `PALADIN\0` magic → `Paladin`; image-format
magic bytes (PNG, JPEG, GIF, BMP, WebP) → `Qr`; UTF-8 text that parses
as JSON with Aegis's top-level `version` / `header` / `db` shape →
`Aegis`; UTF-8 that, after outer whitespace trim, either (a) starts with
`otpauth://` (single URI or newline-separated list whose nonblank
trimmed lines each start with `otpauth://`), or (b) parses as a JSON
array of strings each starting with `otpauth://` → `Otpauth`; otherwise
`Unknown`.
Plaintext exports land in the `Otpauth` branch by design — they share
the same on-disk format as a JSON `otpauth://` array.

Each importer is tested with sample fixture files committed under
`crates/paladin-core/tests/fixtures/`. The byte-oriented importers
(`aegis`, `otpauth`) take `&[u8]` plus `import_time` when the source
format does not carry timestamps; the encrypted Paladin importer
additionally takes a passphrase (`SecretString`), and the QR importer
takes a path plus `import_time` (it loads the image, decodes every QR via
`rqrr`, and feeds each resulting URI through `parse_otpauth`). When
`import::paladin` sees a valid Paladin header with `mode == 0`, it returns
a typed unsupported-plaintext-vault error without importing accounts.

Importer timestamps are deterministic by source format. `otpauth`, QR,
and Aegis imports set `created_at = updated_at = import_time` for each
new parsed account because those formats do not carry Paladin timestamps.
Paladin encrypted bundles preserve each account's stored timestamps for
inserted/appended rows. Source `AccountId`s from Paladin bundles are never
inserted into the destination vault: non-colliding rows and
`--on-conflict=append` rows receive fresh UUIDv4 IDs at merge time. Under
`--on-conflict=replace`, the existing entry keeps its `id` and
`created_at`, receives the incoming mutable account fields, and sets
`updated_at = import_time` regardless of source format. HOTP-to-HOTP
collisions additionally preserve the existing `Hotp.counter` (§5 merge
policy).

### 4.7 Public API sketch

```rust
pub enum VaultLock { Plaintext, Encrypted(SecretString) }
pub enum VaultStatus { Plaintext, Encrypted, Missing }
pub enum ValidationWarning { ShortSecret { decoded_len: usize, recommended_min: usize } }
pub struct ValidatedAccount { pub account: Account, pub warnings: Vec<ValidationWarning> }
pub enum ImportConflict { Skip, Replace, Append }
pub struct ImportWarning { pub source_index: usize, pub warning: ValidationWarning }

pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub replaced: usize,
    pub appended: usize,
    pub accounts: Vec<AccountId>,
    pub warnings: Vec<ImportWarning>,
}

pub fn inspect(path: &Path) -> Result<VaultStatus>;                       // header probe; no decryption. Ok(Missing) iff the file does not exist; other I/O errors and unrecognized magic are Err.
pub fn open(path: &Path, lock: VaultLock) -> Result<(Vault, Store)>;      // errors if `lock` doesn't match the file mode
pub fn create(path: &Path, lock: VaultLock) -> Result<(Vault, Store)>;    // errors if `path` already exists; caller is responsible for any rotation

impl Vault {
    pub fn add(&mut self, account: Account) -> AccountId;
    pub fn remove(&mut self, id: AccountId) -> Option<Account>;
    pub fn iter(&self) -> impl Iterator<Item = &Account>;                          // insertion order
    pub fn rename(&mut self, id: AccountId, label: &str, now: SystemTime) -> Result<()>;
    pub fn import_accounts(&mut self, accounts: Vec<ValidatedAccount>, policy: ImportConflict, now: SystemTime) -> Result<ImportReport>;  // applies the §5 merge policy
    pub fn totp_code(&self, id: AccountId, now: SystemTime) -> Result<Code>;       // TOTP only; errors on HOTP entries
    pub fn hotp_peek(&self, id: AccountId) -> Result<Code>;                        // HOTP only; does not advance
    pub fn hotp_advance(&mut self, store: &Store, id: AccountId, now: SystemTime) -> Result<Code>;  // HOTP only; advances counter, updates `updated_at`, and saves atomically
    pub fn settings(&self) -> &VaultSettings;
    pub fn set_auto_lock_enabled(&mut self, enabled: bool);
    pub fn set_auto_lock_timeout_secs(&mut self, secs: u32) -> Result<()>;
    pub fn set_clipboard_clear_enabled(&mut self, enabled: bool);
    pub fn set_clipboard_clear_secs(&mut self, secs: u32) -> Result<()>;

    // Passphrase management — each saves atomically.
    pub fn set_passphrase(&mut self, store: &Store, new: &SecretString) -> Result<()>;
    pub fn change_passphrase(&mut self, store: &Store, new: &SecretString) -> Result<()>;
    pub fn remove_passphrase(&mut self, store: &Store) -> Result<()>;

    pub fn save(&self, store: &Store) -> Result<()>;
}

pub fn parse_otpauth(uri: &str, import_time: SystemTime) -> Result<ValidatedAccount>;
pub fn read_qr_image(path: &Path) -> Result<Vec<String>>;                 // one URI per decoded QR; returns an empty Vec when the image contains no QRs (the `import::qr_image` wrapper turns that into an error)

/// Unvalidated manual input from the CLI's flag-driven `add` mode (or any
/// other caller that doesn't already have an `otpauth://` URI). `secret`
/// is base32 text; decoding and length-checking happen inside
/// `validate_manual`, which routes through the same validation table as
/// `parse_otpauth` and the importers.
pub struct AccountInput {
    pub label: String,
    pub issuer: Option<String>,
    pub secret: SecretString,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub kind: OtpKind,
    pub icon_hint: Option<String>,
}

pub fn validate_manual(input: AccountInput, now: SystemTime) -> Result<ValidatedAccount>;

pub mod import {
    pub enum ImportFormat { Otpauth, Aegis, Paladin, Qr, Unknown }
    pub fn otpauth(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;  // single URI, line-list, or JSON array of URIs; errors when the input decodes to zero accounts (empty array, blank file, etc.)
    pub fn aegis_plaintext(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;
    pub fn paladin(bytes: &[u8], passphrase: &SecretString) -> Result<Vec<ValidatedAccount>>;  // encrypted Paladin bundle only
    pub fn qr_image(path: &Path, import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;
    pub fn detect(bytes: &[u8]) -> ImportFormat;
}

pub mod export {
    pub fn otpauth_list(accounts: &[Account]) -> Vec<u8>;                              // JSON array of `otpauth://` URIs (infallible: validated `Account`s always serialize)
    pub fn encrypted(accounts: &[Account], passphrase: &SecretString) -> Result<Vec<u8>>;  // Paladin encrypted bundle. Wraps `VaultPayload { accounts, settings: VaultSettings::default() }`; `import::paladin` discards the settings field.
}
```

Because `Account` fields are private, presentation crates use `Vault`
mutators for CLI-level changes such as rename and import merge. Those
mutators reuse the same validation path as account construction, update
`updated_at` on account payload changes, and leave persistence to the
caller unless the method explicitly says it saves. `VaultSettings` fields
are private for the same reason: settings changes go through validated
setters so timeout minimums cannot be bypassed.

## 5. CLI (`paladin`)

Built with `clap` (derive). Commands:

| Command                                     | Behavior                                                         |
| ------------------------------------------- | ---------------------------------------------------------------- |
| `paladin init [--force]`                    | Create a new vault. Prompts: passphrase? (empty = plaintext). Refuses to clobber an existing vault unless `--force` (which stages the new vault first, then rotates the old file to `vault.bin.bak`, overwriting any existing backup). The rotated `.bak` is preserved verbatim — a plaintext-to-encrypted clobber leaves plaintext secrets in `.bak` until the user removes it manually. |
| `paladin add`                               | Add an account interactively (or via flags / URI).               |
| `paladin add --qr <path>`                   | Add by scanning a QR image file. Every decoded QR in the image is added (errors if none decode); collisions use the default `import` merge policy (`skip`). For other policies, use `import --format=qr`. |
| `paladin list`                              | List accounts (no codes).                                        |
| `paladin show <query>`                      | Print the current code. **Advances HOTP counter.**               |
| `paladin peek <query>`                      | Print the current code without advancing the HOTP counter; for TOTP, identical to `show`. |
| `paladin copy <query>`                      | Copy code to clipboard. For HOTP, advances and saves before attempting the clipboard write. (Auto-clear is TUI/GUI-only — the CLI ignores `clipboard.clear_enabled`; see security consideration 6.) |
| `paladin remove <query>`                    | Remove an account. Prompts for confirmation; `--yes` skips the prompt. Required under `--json` (no TTY prompt available). |
| `paladin rename <query> <label>`            | Rename an account.                                               |
| `paladin passphrase set`                    | Encrypt a plaintext vault under a new passphrase.                |
| `paladin passphrase change`                 | Re-encrypt under a new passphrase.                               |
| `paladin passphrase remove`                 | Decrypt to plaintext. Requires `--yes-i-know` to skip the warning. Required under `--json` (no TTY prompt available). |
| `paladin export --plaintext <out>`          | Write JSON `otpauth://` array. Warns; refuses overwrite without `--force`. |
| `paladin export --encrypted <out>`          | Write Paladin-format encrypted bundle. Refuses overwrite without `--force`. |
| `paladin import [--on-conflict=<mode>] <path>` | Auto-detect format and merge into the vault. Conflict mode: `skip` (default), `replace`, `append`. See merge policy below. |
| `paladin import --format=<fmt> <path>`      | Force format: `otpauth`, `aegis`, `paladin` (encrypted bundle only), `qr`.               |
| `paladin settings get [key]`                | Show vault settings (auto-lock, clipboard-clear).                |
| `paladin settings set <key> <value>`        | Edit vault settings.                                             |
| `paladin tui`                               | Convenience wrapper: execs `paladin-tui` (resolved via `PATH`), forwarding all global flags (e.g. `--vault`, `--no-color`) verbatim. `--json` is rejected at parse time because the TUI has no JSON mode. If `paladin-tui` is not on `PATH`, exits non-zero with `io_error` (`operation: "exec_paladin_tui"`). Keeps the §3 "binaries don't reach into each other" rule intact. |

Global flags: `--vault <path>`, `--no-color`, `--json` (for scripting).

Passphrase prompts always read from `/dev/tty` via `rpassword`, not from
stdin/stdout, in both text and `--json` modes. Existing vault passphrases
and encrypted Paladin bundle import passphrases are prompted once. New
passphrases (`init` when the first entry is non-empty, `passphrase set`,
`passphrase change`, and `export --encrypted`) are prompted twice and must
match. For `init`, an empty first entry selects plaintext storage and skips
confirmation; every other empty new passphrase is rejected with
`invalid_passphrase` (`reason: "zero_length"`). Confirmation mismatch exits
before mutation with `invalid_passphrase` (`reason: "confirmation_mismatch"`).
If `/dev/tty` is unavailable, the CLI exits with `io_error` and operation
`"passphrase_prompt"`.

`paladin add` supports exactly one input mode per invocation:
interactive prompts (no account-definition flags), `--uri <otpauth-uri>`,
manual flags, or `--qr <path>`. Manual mode requires `--label` and `--secret`; optional
fields are `--issuer`, `--algorithm sha1|sha256|sha512`, `--digits 6|7|8`,
`--kind totp|hotp`, `--period <secs>`, `--counter <u64>`, and
`--icon-hint <slug>`. Manual mode defaults to TOTP, SHA1, 6 digits, and a
30-second period. HOTP manual entries default to counter 0 when `--counter`
is omitted. Manual `--secret` is Base32 text using the same rules as the
`otpauth://` `secret` parameter; the decoded bytes must pass the §4.1 secret
validation. `--period` is TOTP-only, `--counter` is HOTP-only, and
`--icon-hint` must pass the §4.1 slug validation; when omitted, `icon_hint`
is derived from the issuer using the §4.1 defaulting rule. All add modes use
the shared account validation path and return validation warnings in the
success payload. A single-entry `add` rejects an existing
`(secret, issuer, label)` collision with `duplicate_account` and the existing
`account` summary unless `--allow-duplicate` is supplied, in which case it
appends a new account. `add --qr` remains the multi-entry exception and uses
the import merge path with fixed `--on-conflict=skip`; `--allow-duplicate`
is mutually exclusive with `--qr` and is rejected at parse time.

`init --force` uses a dedicated clobber path. It writes the new vault to
`vault.bin.tmp` and `fsync`s it before moving any existing primary. If that
staging step fails, the old primary and `.bak` are untouched. Once staging
succeeds, if an existing primary is present, it renames `vault.bin` →
`vault.bin.bak` (overwriting any existing backup). It then renames
`vault.bin.tmp` → `vault.bin` and `fsync`s the parent directory. The
primary rename is the primary-file commit point. A failure after backup
rotation but before the primary rename leaves the old vault available at
`vault.bin.bak`; the CLI error names that path so the user can restore it.
A failure after the primary rename is reported as durability-unconfirmed,
matching the normal save semantics.

All mutating CLI commands call the atomic save path before returning
success. If save fails, the command exits non-zero. The primary vault file
is never partially written: a pre-commit save failure leaves the previous
primary authoritative, while a durability-unconfirmed failure after the
primary-file commit point may leave the new primary in place. In both
cases `.bak` may have rotated as described in §4.3, so CLI error text and
JSON include whether the primary commit point was reached. Imports of
encrypted Paladin bundles prompt
for the bundle passphrase, which is independent of the vault passphrase.
For files with `PALADIN\0` magic, the CLI probes the mode first: `mode == 0`
returns the unsupported-plaintext-vault error without a passphrase prompt,
and `mode == 1` prompts for the bundle passphrase.

`copy` has a deliberate HOTP side-effect order: resolve account, generate
code, call `hotp_advance` (which saves), then write to the clipboard. If
the HOTP save fails before the primary commit point, no clipboard write is
attempted and the counter is not advanced. If the clipboard write fails
after a committed HOTP advance, Paladin does **not** roll the counter back
because the code may already have been exposed to the clipboard provider;
the command exits non-zero with `clipboard_write_failed`, `account`, and
`counter_used` in the error payload; for HOTP, the `account` summary
reflects the persisted post-advance counter. TOTP clipboard failures use
the same error kind with `counter_used: null`.

With `--json`, commands write one JSON document to stdout on success and
one JSON document to stderr on failure. `code` values are strings so
leading zeroes are preserved. The common account shape is:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "issuer": "GitHub",
  "label": "ben@example.com",
  "kind": "totp",
  "algorithm": "sha1",
  "digits": 6,
  "period": 30,
  "counter": null,
  "icon_hint": "github",
  "created_at": 1777939200,
  "updated_at": 1777939200
}
```

For HOTP entries, `kind` is `"hotp"`, `period` is `null`, and
`counter` carries the stored counter value (e.g. `42`). For TOTP
entries, `period` carries the configured TOTP period and `counter` is
`null`. `issuer` and `icon_hint` are `null` when unset (a missing
issuer is `null`, never `""`).

Success shapes:

| Command family                | JSON shape                                                                      |
| ----------------------------- | ------------------------------------------------------------------------------- |
| `list`                        | `{ "accounts": [AccountSummary] }`                                              |
| `show`, `peek`                | `{ "codes": [CodeResult] }`                                                     |
| `copy`                        | `{ "copied": true, "account": AccountSummary, "counter_used": number_or_null }` |
| `add` (single)                | `{ "account": AccountSummary, "warnings": [Warning] }`                          |
| `rename`                      | `{ "account": AccountSummary }`                                                 |
| `add --qr`                    | Same shape as `import` (a `--qr` add can decode multiple URIs and uses a fixed `--on-conflict=skip`). |
| `remove`                      | `{ "removed": AccountSummary }`                                                 |
| `import`                      | `{ "imported": n, "skipped": n, "replaced": n, "appended": n, "accounts": [AccountSummary], "warnings": [Warning] }` |
| `export`                      | `{ "written": "/path/to/out", "format": "otpauth_or_paladin" }`                |
| `settings get`, `settings set` | `{ "settings": VaultSettings }` (always full settings; `[key]` on `get` only filters text-mode display, never the JSON shape) |
| `init`, `passphrase *`        | `{ "ok": true, "status": "plaintext_or_encrypted" }`                           |

Pseudo-values such as `number_or_null` and `plaintext_or_encrypted`
document allowed values; concrete output uses actual numbers, `null`, or
enum strings. For `import`, every input row falls into exactly one of
four buckets: `imported` counts non-colliding rows written as new
entries, `skipped` counts collisions kept under `--on-conflict=skip`,
`replaced` counts collisions overwritten under `--on-conflict=replace`,
and `appended` counts collisions inserted as additional entries under
`--on-conflict=append`. `accounts` lists every entry the import added or
modified — i.e. the union of `imported`, `replaced`, and `appended`, but
not `skipped`. `warnings` lists validation warnings collected before the
merge policy is applied, so a short-secret warning is still reported even
if that source row is later skipped as a duplicate.

`CodeResult` always contains `account` (an `AccountSummary`) and
`code` (a string of digits, zero-padded to the entry's `digits`
width). Account summaries in command results reflect persisted state
after the command succeeds. For HOTP `show` and `copy`, that means
`account.counter` is the stored post-advance counter while `counter_used`
is the integer counter that produced the code (the pre-advance counter).
`CodeResult` also carries kind-specific timing fields, with the unused
fields set to `null`: TOTP entries include `valid_from` and
`valid_until` as Unix seconds plus `seconds_remaining` as an integer
duration, and have `counter_used: null`; HOTP entries have `valid_from`,
`valid_until`, and `seconds_remaining` set to `null`.
`Warning` objects use stable snake_case `kind` values. The v0.1 warning
shape is `{ "kind": "short_secret", "message": "...", "source_index": 0,
"decoded_len": 10, "recommended_min": 16 }`; `source_index` is zero-based
and omitted for single-entry `add`. Text-mode commands print warnings to
stderr while still exiting zero on success.
`VaultSettings` JSON is nested by category: `{ "auto_lock": { "enabled":
bool, "timeout_secs": number }, "clipboard": { "clear_enabled": bool,
"clear_secs": number } }`. The dotted `<category>.<field>` form is for
CLI arguments only and never appears in JSON output.
Errors use stable snake_case `kind` values:

```json
{
  "error": {
    "kind": "multiple_matches",
    "message": "query matched multiple accounts",
    "candidates": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "issuer": "GitHub",
        "label": "ben@example.com",
        "kind": "totp",
        "algorithm": "sha1",
        "digits": 6,
        "period": 30,
        "counter": null,
        "icon_hint": "github",
        "created_at": 1777939200,
        "updated_at": 1777939200,
        "disambiguator": "id:550e8400"
      },
      {
        "id": "a1b2c3d4-e5f6-47a8-9b0c-111213141516",
        "issuer": "GitLab",
        "label": "ben@example.com",
        "kind": "totp",
        "algorithm": "sha1",
        "digits": 6,
        "period": 30,
        "counter": null,
        "icon_hint": "gitlab",
        "created_at": 1777939200,
        "updated_at": 1777939200,
        "disambiguator": "id:a1b2c3d4"
      }
    ]
  }
}
```

`candidates` is present only for ambiguity errors. Each entry is an
`AccountSummary` extended with a `disambiguator` string field carrying the
shortest-unique `id:<hex>` form (the same prefix shown in the text-mode
candidate list, ≥8 hex chars), so JSON consumers can re-query by exact id
without recomputing the prefix. Errors may include additional stable fields
when they affect recovery or side effects: `save_durability_unconfirmed`
includes `"committed": true`; `save_not_committed` includes
`"committed": false` and, for `init --force` failures that moved the old
primary to `.bak`, `backup_path`; and `clipboard_write_failed` includes
`account` plus `counter_used` (`null` for TOTP).

v0.1 error kinds and stable fields:

| `kind`                          | Meaning                                      | Stable extra fields                        |
| ------------------------------- | -------------------------------------------- | ------------------------------------------ |
| `validation_error`              | Input or imported data failed validation.    | `field`, `reason`, optional `source_index` |
| `invalid_passphrase`            | New passphrase is not acceptable.            | `reason`                                   |
| `invalid_state`                 | Operation is invalid for vault state.        | `operation`, `state`                       |
| `vault_missing`                 | Selected vault path does not exist.          | `path`                                     |
| `vault_exists`                  | Creation refused to overwrite a vault.       | `path`                                     |
| `unsafe_permissions`            | Vault path permissions are too broad.        | `path`, `subject`, `actual_mode`, `expected_mode` |
| `wrong_vault_lock`              | Supplied lock mode does not match file.      | `expected`, `actual`                       |
| `decrypt_failed`                | Encrypted vault/bundle failed auth.          | none                                       |
| `invalid_header`                | Paladin header is malformed/unknown.         | optional `path`                            |
| `invalid_payload`               | Bincode payload is invalid or too large.     | `reason`, optional `path`                  |
| `unsupported_format_version`    | Paladin `format_ver` has no migration.       | `format_ver`                               |
| `kdf_params_out_of_bounds`      | Argon2 header params exceed policy.          | `m_kib`, `t`, `p`                          |
| `unsupported_import_format`     | Detected/forced import format is invalid.    | `format`                                   |
| `unsupported_plaintext_vault`   | Import saw a plaintext Paladin vault.        | none                                       |
| `unsupported_encrypted_aegis`   | Aegis import saw an encrypted backup.        | none                                       |
| `unsupported_aegis_entry_type`  | Aegis entry is not `totp` or `hotp`.         | `source_index`, `entry_type`               |
| `no_entries_to_import`          | Import/QR input decoded zero accounts.       | none                                       |
| `duplicate_account`             | `add` collided without `--allow-duplicate`.  | `account`                                  |
| `no_match`                      | Query matched no accounts.                   | none                                       |
| `multiple_matches`              | Query matched too many accounts.             | `candidates`                               |
| `counter_overflow`              | HOTP advance would exceed `u64::MAX`.        | `account`                                  |
| `time_range`                    | Time is before epoch or overflows TOTP.      | none                                       |
| `save_not_committed`            | Save failed before primary commit.           | `committed: false`, optional `backup_path` |
| `save_durability_unconfirmed`   | Save committed but durability is unclear.    | `committed: true`                          |
| `clipboard_write_failed`        | Clipboard write failed after generation.     | `account`, `counter_used`                  |
| `io_error`                      | Filesystem/image/terminal I/O failed.        | `operation`, optional `path`               |

Vault settings keys (subject to extension):

| Key                       | Type             | Default | Effect                                       |
| ------------------------- | ---------------- | ------- | -------------------------------------------- |
| `auto_lock.enabled`       | bool             | `false` | Whether TUI/GUI lock on idle.                |
| `auto_lock.timeout_secs`  | u32              | `300`   | Idle timeout when enabled.                   |
| `clipboard.clear_enabled` | bool             | `false` | TUI/GUI: schedule a clipboard wipe after copy. (CLI ignores.) |
| `clipboard.clear_secs`    | u32              | `20`    | Wipe timeout when enabled.                   |

Minimum values: `auto_lock.timeout_secs >= 30`, `clipboard.clear_secs
>= 5`. `VaultSettings` fields are private; `settings set` and the core
settings setters reject lower values with a validation error.

### Query resolution

`<query>` is a case-insensitive substring match against `"{issuer}:{label}"`
(empty issuer is allowed; the colon is still present in the match key).
Matching compares `str::to_lowercase()` output for the query and match key;
Paladin applies no Unicode normalization and no locale-specific casing, so
visually equivalent but differently normalized strings may not match.

- `show` prints **all** matching entries when every match is TOTP. If any
  matched entry is HOTP, `show` requires a single match — the same rule
  as `copy`/`remove`/`rename` below — so a substring query cannot
  silently advance multiple HOTP counters.
- `peek` prints **all** matching entries unconditionally (no state mutation).
- `copy`, `remove`, and `rename` require a single match. On multiple
  matches they exit non-zero and list the candidates, each prefixed with
  the shortest unique `id:<hex>` form taken from the UUID, with a minimum
  length of 8 hex chars. The user can re-run with that exact-id form
  (e.g. `paladin copy id:a1b2c3d4`).
- A query with no matches exits non-zero and prints a concise "no matching
  account" error (`--json` error `kind: "no_match"`, parallel to
  `multiple_matches`).
- A query starting with `id:` is treated as a prefix match against the
  UUID's de-hyphenated 32-char hex form (e.g. `id:a1b2c3d4` matches any
  UUID starting with `a1b2c3d4`), never as a substring match. If the
  prefix matches multiple entries, the same single-match rule above
  applies for `copy`/`remove`/`rename`. `id:` is reserved as a query
  prefix; the prefix after `id:` must be 8 to 32 hex chars, and invalid
  or shorter prefixes are validation errors. An account whose
  `issuer:label` happens to start with `id:` is still reachable by any
  other substring of that key.

### Import merge policy

Two entries collide when their **(secret, issuer, label) triple is
identical**. Behavior on collision is controlled by `--on-conflict`:

- `skip` *(default)* — keep the existing entry; print a one-line warning
  for each skipped import.
- `replace` — overwrite the existing entry's mutable fields (algo,
  digits, kind, icon_hint, `updated_at`). The `id` is preserved.
  **HOTP-to-HOTP collisions additionally preserve the existing
  `Hotp.counter`**: `replace` swaps in the incoming algo / digits /
  icon_hint but never rewinds the counter, so an import cannot reissue
  HOTP codes the user has already advanced past. (Cross-kind
  collisions — HOTP-to-TOTP or TOTP-to-HOTP — replace the entire
  `kind` because there is no comparable counter on one side.)
- `append` — always insert as a new entry, even if it's an exact dupe.

The collision check runs against the *running* import state, so
duplicates within a single input are themselves subject to
`--on-conflict`: `skip` keeps the first, `replace` is last-wins, and
`append` keeps every copy.

Non-colliding entries are always inserted. Imports are atomic at the
batch level: if any entry fails validation (see security consideration 9),
no entries are added. Validation warnings do not break atomicity; they are
attached to the import report and surfaced to the user.

## 6. TUI (`paladin-tui`)

Library: **ratatui** + **crossterm**. Helpers: `tui-input` (text fields).

Layout (single-screen MVP):

```
┌ Paladin ─────────────────────────────────────────────────┐
│ Search: ____________                                     │
├──────────────────────────────────────────────────────────┤
│ ▶ GitHub (ben@…)        123 456   ████████░░  18s        │
│   AWS prod              987 654   ████░░░░░░   8s        │
│   AWS-HOTP (#42)        ▸ press n to advance             │
├──────────────────────────────────────────────────────────┤
│ [↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find│
└──────────────────────────────────────────────────────────┘
```

- TOTP rows: live `Gauge` countdown, re-render on a 250 ms tick.
- HOTP rows: code is hidden until the user presses `n` (advances counter
  and saves); after a 120-second reveal window, returns to the hidden
  state. `n` **always** advances and re-reveals — it is the "give me
  the next code" key — so pressing `n` again during an open reveal
  window advances to the next counter rather than no-op'ing on the
  already-visible code. Copying a hidden HOTP row is rejected with a
  status message. Copying during the reveal window copies the visible
  code and does not advance the counter again.
- Modal dialogs for add / remove / passphrase / settings.
- **Auto-lock:** **off by default.** When `auto_lock.enabled = true`, the TUI
  clears the in-memory vault after `auto_lock.timeout_secs` of no input and
  shows the unlock screen for encrypted vaults. For plaintext vaults,
  auto-lock is a no-op because there is no credential to require; the
  setting remains persisted so it takes effect if the vault is encrypted
  later.
- **Clipboard auto-clear:** **off by default.** When
  `clipboard.clear_enabled = true`, copying a code schedules a wipe after
  `clipboard.clear_secs` — and the wipe only fires if the clipboard still
  holds the value we wrote (so we never stomp something the user copied
  afterwards).
- Single event loop: `crossterm` events ↔ tick events via `mpsc`.

## 7. GUI (`paladin-gtk`)

Library: **Relm4** on **GTK4**. Component tree:

- `AppModel` — owns the unlocked `Vault` (or `Locked` state).
- `UnlockComponent` — passphrase entry, shown only when the vault is encrypted.
  Skipped entirely for plaintext vaults.
- `AccountListComponent` — `gtk::ListView` with a custom row factory.
- `AccountRowComponent` — label, code, progress (TOTP) / "next" button (HOTP),
  copy button. HOTP rows hide their code until the user activates "next"
  (advances counter and saves); after a 120-second reveal window the code
  returns to the hidden state, matching the TUI. Copying a hidden HOTP row
  is disabled; copying during the reveal window copies the visible code and
  does not advance again.
- `AddAccountComponent` — manual fields + "scan from clipboard image".
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts.

Auto-lock and clipboard auto-clear behave the same as the TUI, including the
opt-in default and the plaintext-vault auto-lock no-op.

Icons: `AccountRowComponent` resolves `Account.icon_hint` against the
system icon theme via `gtk::IconTheme`, falling back to a generic
placeholder when the slug is `None` or unresolved. The CLI and TUI
ignore the field entirely.

## 8. Security considerations  ⚠️

This app stores authentication factors. Mistakes here defeat 2FA for the user.
Concrete obligations and explicit user-controlled tradeoffs:

1. **At-rest encryption is opt-in but recommended.** Plaintext vaults are a
   first-class supported mode because some users keep their device under
   full-disk encryption and don't want a second passphrase. The CLI surfaces
   this clearly at `init` and at `passphrase remove`. We never *silently*
   downgrade a vault to plaintext — every transition is an explicit command.
2. **Plaintext mode protections.** Even without encryption: file is created
   `0600`, parent directory is `0700`, atomic writes, backups also `0600`.
   These are the *only* protections in plaintext mode and we enforce them in
   tests.
3. **Encrypted mode.** Argon2id KDF (tunable, header-versioned) +
   authenticated AEAD. Tampering with any byte of an encrypted vault must
   fail decryption — asserted in tests.
4. **Memory hygiene.** All secret material (`Secret`, derived keys,
   passphrases) goes through `Zeroize` / `secrecy::SecretString`. No `Debug`
   impls leak secret bytes — assert this with `#[derive]` audits in tests.
5. **No swap leakage** *(best-effort).* Document `mlockall` on Linux as a
   recommendation; do not require it.
6. **Clipboard hygiene is opt-in (TUI/GUI only).** Default behavior is to
   leave the clipboard alone — many users have clipboard managers and
   would lose data if we wiped silently. When `clipboard.clear_enabled` is
   true, the TUI/GUI schedules a wipe and only runs it if the clipboard
   *still contains the code we wrote* (compare before clearing). The CLI
   never schedules a wipe — CLI commands do not hold state after they
   exit, so users who want auto-clear from the CLI should pipe through
   their own tooling.
7. **Auto-lock is opt-in.** Default behavior is to keep the unlocked vault
   resident as long as the TUI/GUI is open. When enabled, auto-lock only
   locks encrypted vaults; for plaintext vaults it is a no-op because no
   unlock credential exists. CLI commands always open → operate → close,
   never holding state, regardless of settings.
8. **Plaintext export warns loudly.** The CLI prints a multi-line warning,
   refuses to overwrite an existing file without `--force`, and writes the
   output `0600`.
9. **Imports are fully validated.** Each importer parses into validated
   account values without trusting the source's claimed structure — secrets are
   length-checked (rejected if shorter than 10 bytes / 80 bits or longer
   than 1024 bytes; entries between 10 and 15 bytes inclusive — under
   the RFC 4226 §4 minimum of 16 bytes / 128 bits — are accepted with a
   per-entry warning), base32 is validated, algorithms must be in our
   enum, and OTP parameters must pass the §4.1 validation table.
10. **No telemetry, no network calls.** Enforced by code review and tests;
    `cargo deny` covers dependency license/advisory policy, not runtime
    network behavior.
11. **Reproducible builds.** Pin `rust-toolchain.toml`. Lock all deps.
12. **Threat model documented separately** in `SECURITY.md` before v1.

> **Approved 2026-05-04.** All decisions in §4.3, §4.4, §4.5, §4.6, and §8
> are locked in for v0.1. Tests in `paladin-core` will assert round-trip
> properties for both modes, tamper detection, file-permission enforcement,
> and passphrase-transition commit-point behavior so regressions are caught
> in CI.

## 9. Key dependencies (proposed)

| Crate                              | Use                              |
| ---------------------------------- | -------------------------------- |
| `ratatui`                          | TUI rendering                    |
| `crossterm`                        | TUI backend                      |
| `tui-input`                        | TUI text input widget            |
| `relm4`, `gtk4`                    | GUI (v0.2)                       |
| `clap`                             | CLI parsing                      |
| `serde`, `serde_json`, `bincode` (v2) | Vault and JSON I/O             |
| `hmac`, `sha1`, `sha2`             | TOTP / HOTP primitives           |
| `chacha20poly1305`                 | AEAD (XChaCha20-Poly1305)        |
| `argon2`                           | KDF                              |
| `secrecy`, `zeroize`               | Memory hygiene                   |
| `rpassword`                        | CLI passphrase prompt            |
| `arboard`                          | Clipboard (cross-platform)       |
| `rqrr`, `image`                    | QR decode from image files       |
| `qrcode`                           | (Optional) display QR for setup  |
| `directories`                      | XDG / platform paths             |
| `thiserror`, `anyhow`              | Error types                      |
| `base32`                           | Secret encoding                  |
| `url`                              | `otpauth://` URI parsing         |

## 10. Testing strategy

- **Unit tests** in `paladin-core`:
  - RFC 6238 (TOTP) and RFC 4226 (HOTP) test vectors.
  - TOTP time-window boundaries, including pre-Unix-epoch rejection,
    exact-boundary counter rollover with `seconds_remaining = period`,
    and far-future overflow rejection.
  - `otpauth://` parser round-trip (TOTP and HOTP), including duplicate
    known parameters, ignored unknown parameters, case-insensitive
    algorithm/type handling, base32 padding/casing, and HOTP/TOTP-specific
    `counter`/`period` rules, plus trimmed single-URI input and blank-line
    handling in URI lists.
  - Vault round-trip in **both** modes (plaintext and encrypted).
  - Bincode payload contract: fixed v2 config, full-input-consumption
    rejection, and 16 MiB payload-limit rejection for plaintext and
    encrypted vaults.
  - Tamper detection on encrypted vault: flip a ciphertext byte → fail;
    flip any byte in the AAD-bound header (`format_ver`, `mode`, `kdf_id`,
    Argon2 params, `salt`, `aead_id`, `nonce`) → fail.
  - Argon2 parameter bounds reject headers outside the v0.1 limits before
    KDF work begins.
  - File-permission enforcement (`0600` on primary, backup, and temp files;
    `0700` on dir) post-save and during staged writes, plus rejection of
    unsafe existing primary/backup/directory paths with `unsafe_permissions`.
  - Passphrase set/change/remove transitions, including pre-commit rollback
    and durability-unconfirmed failures after the primary-file commit point.
  - HOTP counter advances on `hotp_advance`, not on `hotp_peek` or
    `totp_code`; `hotp_advance` also updates `updated_at` and persists the
    new counter to disk before returning.
  - Account validation rejects out-of-range digits, TOTP periods, HOTP
    counter overflow, empty labels, malformed icon hints, mismatched
    otpauth issuers, and invalid timestamps; short secrets in the 10-15
    byte range produce `short_secret` warnings.
  - Zeroize-on-drop assertions for `Secret` and `SecretString`.
  - Importers: Aegis plaintext TOTP/HOTP mapping, unsupported Aegis entry
    type rejection, our own export round-trip with fresh destination IDs,
    plaintext Paladin vault rejection, encrypted-Aegis rejection, and QR
    image decode (single-QR and multi-QR images) — fixture files in
    `tests/fixtures/`. Also covers the "zero accounts" rejection path
    (empty JSON array, blank otpauth file, empty Aegis `entries`,
    image with no decodable QRs).
- **Property tests** (`proptest`) for the URI parser and base32 secret
  decoding.
- **Integration tests** for each shipped binary using `assert_cmd` (CLI)
  and golden-snapshot tests (`insta`) for TUI rendering.
  - CLI `--json` success/error shapes, warning payloads, durability error
    fields, HOTP post-advance account summaries, clipboard-write failure
    behavior, passphrase no-TTY / confirmation-mismatch failures, and export
    overwrite guards.
  - CLI `add` input modes, mutual-exclusion errors, duplicate-account
    rejection, and `--allow-duplicate`.
  - CLI query resolution, including `str::to_lowercase()` matching,
    no-normalization Unicode behavior, and `id:` prefix validation.
  - TUI HOTP copy behavior: hidden rows do not copy, revealed rows copy
    without advancing again.
  - Plaintext-vault auto-lock is a no-op in TUI state handling now, with
    GUI parity when the GUI ships.
- **CI:** `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test --all`, `cargo deny check`, `cargo audit`.

## 11. Roadmap & checklist

### Milestone 0 — Skeleton *(v0.1)*
- [ ] Initialize workspace `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`.
- [ ] Create `paladin-core`, `paladin-cli`, `paladin-tui`, and a placeholder `paladin-gtk` crate for v0.2.
- [ ] CI: fmt + clippy + test on Linux.
- [ ] `README.md` with build instructions.

### Milestone 1 — Core OTP + storage *(v0.1)*
- [ ] `Account`, `Secret`, `Algorithm`, `OtpKind`, `Vault`, `VaultSettings` types with `Zeroize`.
- [ ] Shared `Account` validation for labels, issuers, secrets, OTP parameters, timestamps, and icon hints.
- [ ] RFC 6238 (TOTP) implementation + Appendix B vectors.
- [ ] RFC 4226 (HOTP) implementation + Appendix D vectors.
- [ ] `otpauth://` parser + base32 secret handling (TOTP and HOTP URIs).
- [ ] **Plaintext** vault format with atomic writes + `0600` file / `0700` parent-dir enforcement.
- [ ] **Encrypted** vault format: Argon2id + AEAD with header versioning and KDF parameter bounds.
- [ ] One-generation `.bak` preserved across all writes.
- [ ] Tamper-detection and round-trip tests for both modes.

### Milestone 2 — Passphrase management *(v0.1)*
- [ ] `set_passphrase`, `change_passphrase`, `remove_passphrase` on `Vault`.
- [ ] Atomic transition with pre-commit rollback and durability-unconfirmed
  handling for post-commit failures.
- [ ] Tests covering all three transitions, pre-commit rollback, and
  durability-unconfirmed post-commit failures.

### Milestone 3 — Import / Export *(v0.1)*
- [ ] Plaintext export (JSON `otpauth://` array) with overwrite guard + `0600`.
- [ ] Encrypted export bundle (Paladin format) with overwrite guard.
- [ ] Importer: `otpauth://` URIs (single + list).
- [ ] Importer: Paladin encrypted bundle; plaintext Paladin vault files return an unsupported-format error.
- [ ] Importer: Aegis plaintext export.
- [ ] Importer: QR image files (`rqrr`).
- [ ] Auto-detect with explicit `--format` override.
- [ ] Fixture-based tests for each importer.

### Milestone 4 — CLI *(v0.1)*
- [ ] `init` (with optional passphrase), `add`, `list`, `show`, `peek`, `remove`, `rename`.
- [ ] `copy` (clipboard copy only; no CLI auto-clear).
- [ ] `passphrase set / change / remove`.
- [ ] `export --plaintext / --encrypted`, `import [--format]`.
- [ ] `settings get / set`.
- [ ] `--json` output for scripting using the schemas in §5.
- [ ] `assert_cmd` integration tests.

### Milestone 5 — TUI *(v0.1)*
- [ ] Single-screen list view with TOTP gauges and HOTP "advance" key.
- [ ] Search/filter input.
- [ ] Add / remove / passphrase / settings modals.
- [ ] Conditional unlock screen (only when vault is encrypted).
- [ ] Opt-in auto-lock and clipboard-clear honoring vault settings, with plaintext auto-lock as a no-op.
- [ ] HOTP reveal/copy behavior: hidden rows do not copy; revealed rows copy without advancing again.
- [ ] Snapshot tests for rendering.

### Milestone 6 — Hardening & release *(v0.1)*
- [ ] `SECURITY.md` with threat model covering both vault modes.
- [ ] `cargo deny` + `cargo audit` clean in CI.
- [ ] Reproducible release builds; signed checksums.
- [ ] v0.1.0 tag.

### Milestone 7 — GUI *(v0.2)*
- [ ] Relm4 component tree (Unlock / List / Row / Add / Settings).
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Clipboard + auto-lock parity with TUI (opt-in).
- [ ] Linux desktop file + icon.
- [ ] Manual test plan documented.

## 12. Open questions

**Decided at sign-off (2026-05-04):**
- AEAD = **XChaCha20-Poly1305** (24-byte nonce, AEAD ID 1).
- Vault encoding = **bincode v2** with the fixed config and 16 MiB payload
  limit in §4.3 (private format, not for interop).
- HOTP CLI semantics: `show` and `copy` **advance** the counter; `peek`
  does not.
- Aegis **encrypted** backups deferred to v0.2 (plaintext export supported
  in v0.1).
- Aegis v0.1 support is limited to plaintext TOTP/HOTP entries; unsupported
  entry types reject the batch with a typed error.
- GUI deferred to v0.2; **TUI ships in v0.1**.
- TUI runtime = plain threads + `mpsc` (no `tokio` — a local TUI doesn't
  need async I/O).
- **Icon hints:** name-only `Option<String>` slug (§4.1, §7).
  User-supplied icon bytes rejected to keep the vault payload small.
- Account validation ranges are fixed in §4.1, including OTP digits,
  TOTP period, HOTP counter overflow, timestamp format, and issuer/label
  normalization.
- Argon2 header parameters are bounded before KDF work (§4.4).
- Plaintext Paladin vault files are not an import format in v0.1; use
  plaintext export for portable URI-list import/export (§4.6).
- Paladin encrypted bundle imports preserve timestamps but assign fresh IDs
  for inserted/appended rows; replacements keep the destination ID.
- CLI `add` input modes, duplicate behavior, and `--allow-duplicate` are
  fixed in §5.
- v0.1 JSON error kinds and stable fields are fixed in §5.
- Plaintext auto-lock is a no-op; HOTP copy in TUI/GUI only copies an
  already revealed HOTP code and never advances a second time.
- Both plaintext and encrypted CLI exports refuse overwrite without `--force`.
- Unsafe existing vault permissions are rejected with a typed error that
  tells the user which path and mode to fix (§4.3, §5).
- `init --force` stages the new vault before rotating the old primary
  verbatim into `.bak` (§5).
- CLI passphrase prompts use `/dev/tty`; new passphrases are confirmed,
  and no-TTY / mismatch failures are typed (§5).
- HOTP JSON command results report post-advance account state and preserve
  the pre-advance counter in `counter_used` (§5).
- Query case-insensitivity uses `str::to_lowercase()` with no Unicode
  normalization or locale-specific casing (§5).
- `otpauth://` text imports trim outer whitespace and ignore blank lines
  in URI-list mode (§4.6).

No open questions remain.

## 13. License

This project is licensed under **AGPL-3.0-or-later**. The canonical text
lives in [`LICENSE`](LICENSE) at the repo root.

- All workspace crates set `license = "AGPL-3.0-or-later"` in their
  `Cargo.toml`.
- New source files should carry the standard SPDX header
  (`// SPDX-License-Identifier: AGPL-3.0-or-later`).
- Vendored code, fixture files imported from other projects (e.g.,
  Aegis export samples used as test fixtures), and any third-party
  assets must be vetted for license compatibility before
  inclusion. AGPL-3.0-or-later can be combined with GPL-3.0-or-later
  under the AGPL/GPLv3 compatibility terms, and common permissive
  licenses such as MIT, BSD, ISC, and Apache-2.0 are generally compatible
  with AGPL-3.0-or-later. Earlier-GPL-only code is not compatible.

Practical note for an OTP authenticator: the AGPL §13 "remote network
interaction" clause is largely inert for v0.1 since Paladin runs locally
and offers no network service. The clause becomes load-bearing only if a
downstream user wraps Paladin into a hosted service, in which case they
must offer source to network users.
