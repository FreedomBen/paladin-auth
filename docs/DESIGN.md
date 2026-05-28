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
├── packaging/                # .deb / .rpm / Flatpak / AppImage metadata (§11)
└── xtask/                    # build/release helpers, incl. `cargo xtask package` (§11)
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
at most 64 bytes. Manual account construction uses the tri-state
`IconHintInput`: `Default` derives a slug from the issuer, when present,
by lowercasing and replacing each run of disallowed characters with a
single `-`, then trimming leading/trailing `-` (e.g. `"GitHub"` →
`"github"`, `"Google Cloud"` → `"google-cloud"`); if the result is
empty, exceeds 64 bytes, or if the issuer is `None`, the field stays
`None`. `Slug(value)` validates and stores the supplied slug. `Clear`
stores `None` even when the issuer could have produced a default. Importers
that do not carry a Paladin-native `icon_hint` use the defaulting rule;
Paladin bundle imports preserve the stored value. The slug is a hint, not
a guarantee: GUIs resolve it (§7); the CLI and TUI ignore the field. We
deliberately do not store icon bytes — that would inflate the vault and
complicate the bincode payload without offering meaningful benefit over
icon-theme lookup.

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
- **TOTP next-code:** `totp_next_code` returns the code for the next
  window — counter `floor(now_unix / period) + 1`. It pins `now` to the
  next window's start (`((now_unix / period) + 1) * period`) and delegates
  to the same primitive as `totp_code`, so RFC 6238 coverage, the
  pre-epoch rejection, and the `u64` overflow guard apply identically.
  At an exact window boundary the result is the code for the window
  immediately after the boundary, never two windows ahead. Used by the
  TUI / GTK "Next" column (§6 / §7); the CLI never calls it.
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
decoding or KDF/AEAD work. `header_size` is **10 bytes** in plaintext mode
(8-byte magic + `format_ver` + `mode`) and **64 bytes** in encrypted mode
(the plaintext header plus `kdf_id`, 12 bytes of Argon2 params, 16-byte
salt, `aead_id`, and 24-byte nonce).

- **Location.** Resolved by `paladin-core` through
  `default_vault_path()`, which uses
  `directories::ProjectDirs::from("", "", "paladin")` and then
  `ProjectDirs::data_dir()`. On Linux this follows the XDG Base Directory
  spec; on macOS / Windows it follows the platform conventions baked into
  the `directories` crate. The vault is
  application data (a secrets store), not user-editable configuration,
  so it lives under `XDG_DATA_HOME` — **not** `XDG_CONFIG_HOME`. The
  latter is reserved for any future preferences file that ships
  separately from the vault.
  - Linux (v0.1 target):
    `${XDG_DATA_HOME:-~/.local/share}/paladin/vault.bin`.
  - macOS / Windows: whatever
    `ProjectDirs::from("", "", "paladin").data_dir()` returns under
    the platform conventions; those targets are exercised once v0.2
    adds them (§2).

  The filename is always `vault.bin`; the on-disk encoding is the
  private bincode format described above (it is binary regardless of
  mode and is not interop with any other tool). A `--vault <path>`
  flag on every binary overrides the core-resolved location for testing
  and for users who keep their vault on removable media. Presentation
  crates never duplicate `ProjectDirs` logic; when `--vault` is absent
  they call `default_vault_path()` and propagate its `io_error`
  (`operation: "resolve_default_vault_path"`) if the platform path
  cannot be resolved.
- **Permissions.** File is created `0600` regardless of mode; temporary
  files and backups are also `0600`. The parent directory is `0700`
  whenever `create` / `create_force` brings it into existence. In
  plaintext mode these permissions are the *only* protection on the
  secrets, so we enforce them. On Linux v0.1, `open` rejects a vault
  before decoding if the parent directory grants any group/other
  permissions, or if the primary or backup file, when present, grants
  any group/other permissions. `create` / `create_force` `mkdir -p` a
  missing parent at `0700` (with an explicit `chmod 0700` on the leaf so
  a permissive umask cannot widen the final mode) before any other
  work, then apply the same symlink + perms gate as `open` to confirm
  the result. An existing parent is checked but never silently
  tightened: a loose parent is rejected with `unsafe_permissions` and a
  `0700` parent is left at `0700`. This invariant means `paladin init`
  needn't pre-create the data dir and cannot leave a freshly-created
  vault in a directory that the next `open` would refuse. `open` does
  **not** auto-create a missing parent — a missing parent on `open`
  surfaces as `io_error { operation: "stat_vault_dir" }`; `mkdir`
  failures on the `create` side surface as
  `io_error { operation: "create_vault_dir" }`. The CLI text error
  names the failing path, actual mode, expected repair mode, and the
  `chmod` command that would repair it; `--json` reports
  `unsafe_permissions` with `path`, `subject`, `actual_mode`, and
  `expected_mode` fields. Mode fields are four-digit octal strings such
  as `"0644"`, with expected repair modes `"0700"` for directories and
  `"0600"` for files. `subject` is one of `vault_dir`, `vault_file`, or
  `backup_file`.
  As defense in depth alongside the permissions check, `open`, `create`,
  and `create_force` also reject any of the three storage paths
  (`vault.bin`, `vault.bin.bak`, parent data directory) being a symbolic
  link, regardless of target. The probe uses `symlink_metadata` so it
  never follows the link, and rejection happens before any read, write, or
  staged tempfile so a hostile symlink cannot redirect the vault save to a
  chosen file. Rejection surfaces as `io_error` with one of the stable
  operations `vault_file_is_symlink`, `backup_file_is_symlink`, or
  `vault_dir_is_symlink` from §5.
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
  raising costs requires an explicit encrypted-write operation that supplies
  custom `Argon2Params`: vault creation, `set_passphrase`,
  `change_passphrase`, or encrypted export. v0.1 exposes these knobs in
  `paladin-core`, and the CLI exposes them as advanced flags on those
  encrypted-write commands. To avoid attacker-controlled resource exhaustion
  before authentication, `open` rejects encrypted vaults whose header
  parameters are outside these bounds before running Argon2id:
  `m_kib` 8192 to 1048576 (8 MiB to 1 GiB), `t` 1 to 10, and `p` 1 to 4.
  The 8 MiB floor is deliberately well below the 64 MiB default and
  OWASP's 19 MiB Argon2id guidance: it is the minimum we will *accept on
  read* so that vaults written on memory-constrained hardware (small
  SBCs, low-RAM headless boxes) can still be opened. New encrypted
  material always uses the default unless the caller supplies a custom
  `Argon2Params` value that passes the same bounds. Future releases may
  widen those bounds only with an explicit format or policy update.
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
  Plaintext vaults hold no cached key or passphrase, so "the cache" is
  empty in that state. A transition that fails before the commit point
  leaves the cache matching the previous mode (the prior key+passphrase
  for an encrypted starting state, no cache for plaintext), so the vault
  remains usable under the previous state. A durability-unconfirmed
  failure after the commit point updates the cache to match the new
  on-disk mode (the new key+passphrase for an encrypted target, cleared
  cache for plaintext), because the primary file has already switched
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

Three formats, user picks per invocation:

- **Plaintext (otpauth URI list).** A newline-separated list of
  `otpauth://` URIs, one URI per line, terminated by a trailing
  newline — the exact shape Gnome Authenticator's
  *Backup → Save in plain text* writes. HOTP entries carry their
  counter via the standard `counter` URI parameter, per the Google
  Authenticator key-URI format. There is no Paladin-specific
  plaintext envelope, and on import these files are read via the
  otpauth path. An empty vault writes an empty (zero-byte) file.
  Cross-compatible with Gnome Authenticator, FreeOTP+, and other
  authenticators that accept URI lists.
  **The CLI prints a clear warning** before writing unencrypted secrets to
  disk and refuses to write to a file that already exists unless `--force`
  is given. The output file is written with
  `write_secret_file_atomic`, so it is created `0600` via a
  same-directory tempfile, rename, and parent-directory `fsync`.
- **Encrypted (Paladin bundle).** The same accounts encoded as
  `VaultPayload { accounts, settings: VaultSettings::default() }` and
  wrapped in Paladin's encrypted file format (§4.3) under a passphrase
  the user supplies at export time (independent of the vault's own
  passphrase). Empty passphrases are rejected: `export::encrypted`
  takes `EncryptionOptions` and returns an error rather than silently
  producing a plaintext-equivalent bundle. Custom Argon2id costs can be
  supplied through those options; omitted options use the §4.4 defaults.
  The CLI refuses to write an encrypted export to a file that already
  exists unless `--force` is given, matching plaintext export.
  The output file is written through `write_secret_file_atomic` and is
  created `0600`.
- **QR code (per account).** Renders a single account's `otpauth://`
  URI as a QR code, the same URI that would land in a plaintext URI
  list export but for one row. The QR encoding is standard
  `otpauth://` per the Google Authenticator key-URI format, so any
  scanner that imports otpauth URIs can consume it; Paladin does not
  define its own QR payload. Multi-account / vault-migration QR
  payloads (e.g. the Google Authenticator `otpauth-migration://`
  protobuf) are explicitly out of scope. HOTP exports encode the
  *current* stored counter in the URI's `counter` parameter and **do
  not** advance it; semantically a QR export is a `peek`, not a
  `show`, so a user who scans the QR into a second device and then
  continues using the original loses no codes to a phantom advance.
  The CLI / TUI / GUI all render this warning verbatim, sourced from
  `paladin_core::format_plaintext_qr_export_warning()`, before any
  pixel of the QR is shown or written: the QR encodes the account
  secret, anyone who sees or photographs it can clone the OTP, and
  the user should treat it like the plaintext URI list above.
  Three render targets are supported and all three live in
  `paladin-core` so the front ends stay thin:
    * **PNG bytes** — written to disk through `write_secret_file_atomic`
      (CLI, TUI save action, GUI save action) or pushed to the GDK
      clipboard (GUI only). The CLI / TUI refuse to overwrite a target
      file without `--force` and the GUI runs the same inline overwrite
      gate `ExportDialog` uses; saved files are `0600`.
    * **SVG text** — same write contract as PNG. Useful for sharp
      printing and for users who want a vector copy.
    * **Unicode half-block QR** — `qrcode::render::unicode::Dense1x2`
      rendering for terminals (CLI default when no file output is
      selected, TUI modal body). The body is plain UTF-8 text using
      only the `' '`, `'▀'`, `'▄'`, `'█'`, and `'\n'` glyphs — no ANSI
      colour / style escape sequences — so `--no-color`, `NO_COLOR`,
      and non-TTY stdout do not change the rendered bytes. (The
      half-blocks are described as "ANSI" only colloquially because
      they target ANSI-capable terminals; nothing about the encoding
      depends on ANSI escapes.)
  Render parameters are bounded so a malformed `QrRenderOptions` value
  cannot blow up the encoder: `module_size_px` is 1 to 64 inclusive
  (default 8), `quiet_zone` is bool (default `true`), and the QR
  error-correction level is fixed to **M** (the §9 `qrcode` crate
  default). `QrRenderOptions` is consumed by the PNG and SVG render
  paths only; the half-block path takes no options because terminal
  cell size is fixed by the renderer and the quiet zone is always
  emitted for scannability. Encoder failures return `validation_error`
  with `field: "qr_render"` and `reason` set to the encoder's stable
  rejection slug (e.g. `data_too_long` if a far-future account format
  somehow exceeds the largest QR version); today's `otpauth://` URIs
  fit comfortably inside QR version 10 with M-level ECC, so production
  payloads never trip the size cap. The QR pipeline is read-only: it
  never calls into storage, never advances a counter, and never
  mutates `updated_at`.

`write_secret_file_atomic` is the shared export-writer primitive for the CLI,
TUI, and GUI. It writes caller-supplied bytes to an arbitrary destination path
using a same-directory temporary file, `0600` permissions, file `fsync`,
atomic rename, and parent-directory `fsync`. Failures before the final rename
return `save_not_committed`; failures after the final rename return
`save_durability_unconfirmed`. It does **not** create a `.bak` file and does
not enforce the overwrite prompt / `--force` policy; each front-end gates
overwrite before calling it so user-facing confirmation text stays local to
that front-end.

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
- **QR image** — one or more accounts (one per decoded QR); errors if
  no QRs are decoded. File imports load an image from disk. UI clipboard
  imports pass raw RGBA bytes plus width/height. The raw-RGBA path rejects
  zero dimensions and buffers whose length is not exactly
  `width * height * 4` bytes, using overflow-checked multiplication. It
  also rejects buffers larger than `QR_RGBA_MAX_BYTES` (64 MiB) before
  decode with `validation_error` (`field: "qr_image"`,
  `reason: "image_too_large"`). Front ends that allocate clipboard RGBA
  buffers themselves check the same cap before allocation. Both paths use
  `rqrr` to decode every QR and feed each resulting payload through the
  `otpauth://` URI parser. Decoded QRs that are not valid `otpauth://` URIs
  reject the whole batch via `validation_error` with `source_index`,
  matching the import atomicity rule below. The TUI and GTK GUI accept a QR
  image pasted from the clipboard, decoded via the raw-RGBA path.

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
`crates/paladin-core/tests/fixtures/`. Presentation crates normally call
the import facade, `import::from_file` for path-backed imports or
`import::from_bytes` for already-loaded encoded content. The facade
accepts an optional `ImportFormat`: `None` auto-detects with `detect`,
while `Some(format)` forces the dispatch. An unknown detected format or
an invalid forced/source combination returns `unsupported_import_format`
with a single `format` field: for auto-detect failures it is the detected
format (`"unknown"`), and for forced-format failures it is the requested
forced format. When dispatch selects `Paladin`, callers must supply the
encrypted bundle passphrase in `ImportOptions`; omitting it returns
`invalid_state` (`operation: "import_paladin"`,
`state: "missing_passphrase"`). Front ends that need to decide whether to
prompt before calling the facade use `classify_paladin_import_precheck(path,
forced_format)`. That helper owns the shared Paladin-header decision table:
encrypted Paladin headers prompt, plaintext Paladin headers reject with
`unsupported_plaintext_vault`, malformed Paladin headers reject with the
typed header/version error, and non-Paladin or unreadable files fall through
so `import::from_file` owns the final read/dispatch error. The lower-level
byte-oriented importers (`aegis_plaintext`, `otpauth`) remain available for
tests and specialized callers; they take `&[u8]` plus `import_time` when the
source format does not carry timestamps. The encrypted Paladin importer
additionally takes a passphrase (`SecretString`). QR import exposes path,
encoded-image bytes through the facade, and a raw-RGBA byte form for
clipboard/image buffers; all decode every QR via `rqrr` and feed each
resulting URI through `parse_otpauth`. When `import::paladin` sees a valid
Paladin header with `mode == 0`, it returns a typed
unsupported-plaintext-vault error without importing accounts.

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
pub enum PaladinError { /* core-returnable §5 error kinds */ }
pub enum ErrorKind { /* stable §5 `error_kind` discriminator (1:1 with PaladinError) */ }
pub enum PermissionSubject { VaultDir, VaultFile, BackupFile } // §5 unsafe_permissions field
pub enum TimeRangeKind { PreEpoch, Overflow, OutOfRange }      // §5 time_range field
pub enum VaultMode { Plaintext, Encrypted }                    // §5 wrong_vault_lock fields
pub type Result<T> = std::result::Result<T, PaladinError>;
pub enum VaultLock { Plaintext, Encrypted(SecretString) }
pub enum VaultInit { Plaintext, Encrypted(EncryptionOptions) }
pub enum VaultStatus { Plaintext, Encrypted, Missing }
pub struct Argon2Params { pub m_kib: u32, pub t: u32, pub p: u32 }
pub struct EncryptionOptions { pub passphrase: SecretString, pub kdf_params: Argon2Params }
pub struct QrRenderOptions { pub module_size_px: u32, pub quiet_zone: bool }
pub enum ValidationWarning { ShortSecret { decoded_len: usize, recommended_min: usize } }
pub struct ValidatedAccount { pub account: Account, pub warnings: Vec<ValidationWarning> }
pub enum ImportConflict { Skip, Replace, Append }
pub struct ImportWarning { pub source_index: usize, pub warning: ValidationWarning }
pub enum AccountKindInput { Totp, Hotp }
pub enum AccountKindSummary { Totp, Hotp }
pub enum IconHintInput { Default, Clear, Slug(String) }
pub enum InitPrecheck { Clear, Existing, Propagate(PaladinError) }
pub enum PaladinImportPrecheck { NoPrompt, PromptForPassphrase, Reject(PaladinError) }
pub const HOTP_REVEAL_SECS: u64 = 120;
pub const QR_RGBA_MAX_BYTES: usize = 64 * 1024 * 1024;
/// QR-export render bounds, mirrored on the CLI `--module-size-px` flag and
/// the GUI render path. The QR error-correction level is fixed at M for
/// the v0.2 surface and is not exposed as an option.
pub const QR_MODULE_SIZE_PX_MIN: u32 = 1;
pub const QR_MODULE_SIZE_PX_MAX: u32 = 64;
pub const QR_MODULE_SIZE_PX_DEFAULT: u32 = 8;
/// Shared TUI / GUI tick cadence for TOTP gauge refresh and clipboard
/// staleness checks. 250 ms keeps the TOTP "seconds remaining" display
/// honest without burning CPU. Front ends consume this constant; they
/// never hard-code a different value.
pub const TICK_INTERVAL_MS: u64 = 250;
/// `Vault::set_auto_lock_timeout_secs` rejection bounds; mirrored on the
/// CLI / TUI / GUI settings widgets.
pub const AUTO_LOCK_SECS_MIN: u32 = 30;
pub const AUTO_LOCK_SECS_MAX: u32 = 86_400;
/// `Vault::set_clipboard_clear_secs` rejection bounds; mirrored on the
/// CLI / TUI / GUI settings widgets.
pub const CLIPBOARD_CLEAR_SECS_MIN: u32 = 5;
pub const CLIPBOARD_CLEAR_SECS_MAX: u32 = 600;

/// Non-secret account projection used by all presentation crates for list
/// rows, duplicate-account errors, JSON output, and import reports. This is
/// the public way to inspect an account; raw secret bytes are never exposed.
pub struct AccountSummary {
    pub id: AccountId,
    pub issuer: Option<String>,
    pub label: String,
    pub kind: AccountKindSummary,
    pub algorithm: Algorithm,
    pub digits: u8,
    pub period: Option<u32>,
    pub counter: Option<u64>,
    pub icon_hint: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Generated OTP projection used by CLI output and TUI / GUI rows.
/// `code` is zero-padded to the account's digit width. For TOTP, the
/// validity fields are `Some` and `counter_used` is `None`; for HOTP, the
/// validity fields are `None` and `counter_used` is the counter that produced
/// the visible code.
pub struct Code {
    pub code: String,
    pub valid_from: Option<u64>,
    pub valid_until: Option<u64>,
    pub seconds_remaining: Option<u64>,
    pub counter_used: Option<u64>,
}

pub enum AccountQuery {
    Search(String),                 // issuer:label substring search
    IdPrefix { hex_prefix: String } // validated 8..=32 lowercase hex chars
}

pub enum SettingKey {
    AutoLockEnabled,
    AutoLockTimeoutSecs,
    ClipboardClearEnabled,
    ClipboardClearSecs,
}

pub enum SettingPatch {
    AutoLockEnabled(bool),
    AutoLockTimeoutSecs(u32),
    ClipboardClearEnabled(bool),
    ClipboardClearSecs(u32),
}

pub struct VaultSettings { /* private fields */ }

pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub replaced: usize,
    pub appended: usize,
    pub accounts: Vec<AccountId>,
    pub warnings: Vec<ImportWarning>,
}

impl Default for Argon2Params { /* m_kib = 65536, t = 3, p = 1 */ }
impl Argon2Params {
    pub fn validate(&self) -> Result<()>;                                  // enforces §4.4 bounds, returns kdf_params_out_of_bounds
}

impl EncryptionOptions {
    pub fn new(passphrase: SecretString) -> Result<Self>;                  // default Argon2Params; rejects zero-length passphrases
    pub fn with_params(passphrase: SecretString, kdf_params: Argon2Params) -> Result<Self>;
}

impl Default for QrRenderOptions { /* module_size_px = QR_MODULE_SIZE_PX_DEFAULT, quiet_zone = true */ }
impl QrRenderOptions {
    pub fn validate(&self) -> Result<()>;                                  // enforces §4.6 QR bounds, returns validation_error with field "qr_render"
}

impl VaultSettings {
    pub fn auto_lock_enabled(&self) -> bool;
    pub fn auto_lock_timeout_secs(&self) -> u32;
    pub fn clipboard_clear_enabled(&self) -> bool;
    pub fn clipboard_clear_secs(&self) -> u32;
}

pub fn default_vault_path() -> Result<PathBuf>;                           // shared §4.3 path resolver; appends vault.bin under ProjectDirs::from("", "", "paladin").data_dir()
pub fn inspect(path: &Path) -> Result<VaultStatus>;                       // header probe; no decryption. Ok(Missing) iff the file does not exist; other I/O errors and unrecognized magic are Err. Deliberately does **not** enforce the §4.3 permissions check — only `open`, `create`, and `create_force` do — so callers can probe a vault's mode before fixing perms.
pub fn open(path: &Path, lock: VaultLock) -> Result<(Vault, Store)>;      // errors if `lock` doesn't match the file mode
pub fn create(path: &Path, init: VaultInit) -> Result<(Vault, Store)>;    // errors if `path` already exists; encrypted init uses `EncryptionOptions` default or custom Argon2 params; for the `init --force` clobber semantics use `create_force`
pub fn create_force(path: &Path, init: VaultInit) -> Result<(Vault, Store)>;  // §5 `init --force` staged clobber: stages the new vault to `vault.bin.tmp` and `fsync`s it; if staging succeeds and a primary already exists, renames `vault.bin` → `vault.bin.bak` verbatim (overwriting any existing backup) without re-encryption; renames `vault.bin.tmp` → `vault.bin`; `fsync`s the parent directory. Pre-rename failures leave the previous primary recoverable — when failure occurs after backup rotation, the old vault is at `vault.bin.bak` and the error is `save_not_committed` with `backup_path` set. Post-commit failures surface as `save_durability_unconfirmed`. Identical to `create` when no primary exists at `path`.

/// Format the human-readable §4.3 `unsafe_permissions` text — failing
/// path, `subject`, `actual_mode`, `expected_mode`, and the `chmod`
/// repair command. Returns `None` for any other error kind. Lives in
/// `paladin-core` so the CLI, TUI, and GUI render identical wording
/// without re-implementing it.
pub fn format_unsafe_permissions(err: &PaladinError) -> Option<String>;

/// Format the `init --force` / `vault_exists` clobber warning text —
/// names the existing vault path, calls out the `vault.bin.bak` rotation,
/// and warns that any prior backup is overwritten. Lives in
/// `paladin-core` so the CLI confirmation prompt and the GUI
/// `InitDialog` destructive gate render identical wording.
pub fn format_init_force_warning(existing_vault: &Path) -> String;

/// Format the plaintext-storage warning shown by CLI `init` when the first
/// passphrase entry is empty, by `passphrase remove` (CLI / TUI / GUI), and
/// by the GUI `InitDialog`'s plaintext path.
/// Static text — no parameters — so all three front ends share a
/// single source.
pub fn format_plaintext_storage_warning() -> String;

/// Format the plaintext-export warning shown by CLI `export
/// --plaintext`, the TUI Export modal's plaintext path, and the GUI
/// `ExportDialog` plaintext path before unencrypted secrets are
/// written. Static text.
pub fn format_plaintext_export_warning() -> String;

/// Format the per-account QR-export warning shown by the CLI `qr`
/// command, the TUI QR modal, and the GUI `ExportQrDialog` before
/// the QR is rendered, written, or copied. Static text — calls out
/// that the QR encodes the account secret, anyone who sees or
/// photographs it can clone the OTP, and saved QR files should be
/// treated like a plaintext export. Lives in `paladin-core` so all
/// three front ends share one source.
pub fn format_plaintext_qr_export_warning() -> String;

/// Format a validation warning's stable human-readable message. JSON output
/// includes this message, and text / UI surfaces use it verbatim so warning
/// copy does not drift between front ends.
pub fn format_validation_warning(warning: &ValidationWarning) -> String;

/// Compute the canonical `{issuer}:{label}` match key used by CLI
/// query resolution (§5) and by TUI / GUI search filters (§6, §7).
/// Empty issuer keeps the leading colon so the match key is the same
/// shape across every account. Callers apply `str::to_lowercase()` to
/// both sides for case-insensitive matching; this helper does not
/// lower-case so the original casing remains available for display.
pub fn account_match_key(account: &Account) -> String;

/// Shared case-insensitive substring predicate for issuer/label search.
/// It compares `str::to_lowercase()` output for the query and
/// `account_match_key(account)`, with no Unicode normalization or
/// locale-specific casing. An empty query matches every account.
pub fn account_matches_search(account: &Account, query: &str) -> bool;

/// Format an account's display label used by CLI status text, the TUI
/// QR modal caption, the GTK `ExportQrDialog` caption, and the GTK
/// rename / remove dialog subtitles. Renders `"{issuer}:{label}"` when
/// `issuer` is `Some(s)` and `s.trim().is_empty()` is false; renders
/// the bare label otherwise (so accounts without an issuer, or with
/// an empty or whitespace-only issuer, display as just the label —
/// not a stray leading colon). Lives in `paladin-core` so CLI, TUI,
/// and GUI render identical wording without re-implementing it.
pub fn summary_display_label(s: &AccountSummary) -> String;

/// Parse the CLI query grammar's shared account-selector syntax. Plain text
/// becomes `AccountQuery::Search`; `id:` selectors are validated here so the
/// 8..=32 hex rule is not reimplemented in the CLI. Invalid `id:` selectors
/// return `validation_error` with `field: "query"`.
pub fn parse_account_query(query: &str) -> Result<AccountQuery>;

/// Parse a §5 dotted settings key without a value. Used by `settings get` and
/// by `parse_setting_patch`; unknown keys return `validation_error`.
pub fn parse_setting_key(key: &str) -> Result<SettingKey>;

/// Parse a §5 dotted settings key/value pair into a typed patch. The parser
/// owns the stable dotted key list and the CLI's lowercase `true` / `false`
/// plus base-10 `u32` value grammar. Unknown keys and invalid values return
/// `validation_error`.
pub fn parse_setting_patch(key: &str, value: &str) -> Result<SettingPatch>;

/// Parse the prompt-grammar token used by the CLI `add` interactive
/// prompt and the TUI / GUI add-account modals when collecting an
/// optional `icon_hint`. Empty input (after Unicode-whitespace trim)
/// becomes `IconHintInput::Default`; a case-insensitive `none` token
/// becomes `IconHintInput::Clear`; any other input is validated as a
/// slug per §4.1 and becomes `IconHintInput::Slug`. Invalid slugs
/// return `validation_error` with `field: "icon_hint"`.
pub fn parse_icon_hint_token(token: &str) -> Result<IconHintInput>;

/// Slug-only validator for callers that have already committed to
/// the `IconHintInput::Slug` arm at the UI layer — used by the TUI
/// Edit modal's *Slug:* row (§6) and the v0.2 GTK EditDialog's
/// equivalent slug input. Runs the §4.1 `[a-z0-9_-]+` check
/// without the `parse_icon_hint_token` reserved-token grammar, so
/// literal `default` / `none` return `IconHintInput::Slug` rather
/// than collapsing to `Default` / `Clear` (those tri-state
/// outcomes are reachable only via the dedicated selector
/// affordances those UIs provide). Invalid slugs return
/// `validation_error` with `field: "icon_hint"`,
/// `reason: "invalid_slug"`, matching the error site
/// `parse_icon_hint_token` emits for slug-shape failures.
pub fn validate_icon_hint_slug(slug: &str) -> Result<IconHintInput>;

/// Classify the result of `inspect(path)` for the §5 init flow shared by
/// CLI `init` and GUI `InitDialog`. `VaultStatus::Missing`
/// → `InitPrecheck::Clear`; an existing primary file in any decodable shape
/// (`Plaintext`, `Encrypted`, `invalid_header`,
/// `unsupported_format_version`) → `InitPrecheck::Existing`, requiring the
/// caller to confirm the destructive `init --force` (or equivalent) gate;
/// any other error (e.g. `unsafe_permissions`, `io_error`) →
/// `InitPrecheck::Propagate(err)` so the front end can bubble the
/// underlying cause without misclassifying it as "vault exists."
pub fn classify_init_precheck(probe: Result<VaultStatus>) -> InitPrecheck;

/// Shared pre-prompt classifier for imports that may be Paladin bundles.
/// Front ends call this before asking for an encrypted-bundle passphrase.
/// Forced non-Paladin formats return `NoPrompt`; auto-detect or forced
/// Paladin probes read only enough of the file to classify a Paladin header.
/// Encrypted Paladin headers return `PromptForPassphrase`; plaintext Paladin
/// headers, malformed Paladin headers, and unsupported Paladin format
/// versions return `Reject(err)` with the exact core error the front end should
/// surface. Missing files, unreadable files, and non-Paladin magic return
/// `NoPrompt` so `import::from_file` remains the owner of
/// `read_import_file`, auto-detect, and `unsupported_import_format` errors.
pub fn classify_paladin_import_precheck(
    path: &Path,
    forced_format: Option<import::ImportFormat>,
) -> PaladinImportPrecheck;

/// Decide which account should be selected after a TUI / GUI search
/// filter narrows the visible list. Returns `prev` when it appears in
/// `filtered`; otherwise the first id in `filtered`; otherwise `None`.
/// Pins the §6 / §7 selection-preservation rule so both front ends
/// behave identically.
pub fn select_after_filter(prev: Option<AccountId>, filtered: &[AccountId]) -> Option<AccountId>;

pub mod policy {
    /// Auto-lock idle-deadline math shared by TUI and GUI. The
    /// front ends own raw input handling and timer plumbing; the
    /// policy module owns the encrypted-only gating, the next-deadline
    /// arithmetic, and the monotonic expiry comparison.
    pub mod auto_lock {
        pub struct IdlePolicy;
        impl IdlePolicy {
            pub fn should_arm(is_encrypted: bool, settings: &VaultSettings) -> bool;
            pub fn next_deadline(now: std::time::Instant, is_encrypted: bool, settings: &VaultSettings) -> Option<std::time::Instant>;
            pub fn is_expired(deadline: std::time::Instant, now: std::time::Instant) -> bool;
        }
    }

    /// Clipboard auto-clear policy shared by TUI and GUI. Front ends
    /// own the OS clipboard surface (`arboard`, `gdk::Clipboard`); the
    /// policy module owns the schedule decision, monotonic token issuance,
    /// and the only-if-unchanged byte-equality decision.
    pub mod clipboard_clear {
        #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
        pub struct ClipboardClearToken(/* private monotonic counter */);
        pub struct ClipboardClearPolicy;
        impl ClipboardClearPolicy {
            pub fn schedule(now: std::time::Instant, settings: &VaultSettings) -> Option<(ClipboardClearToken, std::time::Instant)>;
            pub fn should_clear(captured: &[u8], current: &[u8]) -> bool;
        }
    }

    /// HOTP reveal countdown deadline. Computes `now +
    /// Duration::from_secs(HOTP_REVEAL_SECS)` so TUI and GUI countdowns
    /// share one source.
    pub mod hotp_reveal {
        pub fn deadline(now: std::time::Instant) -> std::time::Instant;
    }
}

impl Account {
    pub fn summary(&self) -> AccountSummary;
}

impl Vault {
    pub fn get(&self, id: AccountId) -> Option<&Account>;
    pub fn add(&mut self, account: Account) -> AccountId;
    pub fn remove(&mut self, id: AccountId) -> Option<Account>;
    pub fn iter(&self) -> impl Iterator<Item = &Account>;                          // insertion order
    pub fn summaries(&self) -> impl Iterator<Item = AccountSummary>;                // insertion order, non-secret projections
    pub fn rename(&mut self, id: AccountId, label: &str, now: SystemTime) -> Result<()>;
    pub fn edit_account_metadata(&mut self, id: AccountId, edit: AccountEdit, now: SystemTime) -> Result<()>;  // Multi-field non-cryptographic edit (label / issuer / icon_hint). See `AccountEdit` below. Reuses §4.1 validation per supplied field. `rename` is the label-only shorthand; both bump `updated_at` and route through `mutate_and_save`.
    pub fn find_duplicate(&self, account: &ValidatedAccount) -> Option<&Account>;  // exact (secret, issuer, label) collision helper for single-entry add flows
    pub fn find_duplicate_after_edit(&self, id: AccountId, edit: &AccountEdit) -> Option<&Account>;  // companion to `find_duplicate` for edit flows: projects the would-be post-edit (secret, issuer, label) for `id` (secret is never edited) and runs the same byte-for-byte / case-sensitive comparison, skipping the account at `id` so an unchanged self-comparison never reports a collision. Returns `None` for unknown `id`. Used by CLI `paladin edit`, TUI Edit modal, and GUI `EditDialog` to render `duplicate_account` before submission.
    pub fn import_accounts(&mut self, accounts: Vec<ValidatedAccount>, policy: ImportConflict, now: SystemTime) -> Result<ImportReport>;  // applies the §5 merge policy
    pub fn totp_code(&self, id: AccountId, now: SystemTime) -> Result<Code>;       // TOTP only; errors on HOTP entries
    pub fn totp_next_code(&self, id: AccountId, now: SystemTime) -> Result<Code>;  // TOTP only; code for the next window (`((now/period)+1)*period`); errors on HOTP entries
    pub fn hotp_peek(&self, id: AccountId) -> Result<Code>;                        // HOTP only; does not advance
    pub fn hotp_advance(&mut self, store: &Store, id: AccountId, now: SystemTime) -> Result<Code>;  // HOTP only; advances counter, updates `updated_at`, and saves atomically
    pub fn export_qr_png(&self, id: AccountId, options: QrRenderOptions) -> Result<Zeroizing<Vec<u8>>>;  // §4.6 QR export → PNG bytes; pure read, no counter advance, options validated
    pub fn export_qr_svg(&self, id: AccountId, options: QrRenderOptions) -> Result<Zeroizing<String>>;   // §4.6 QR export → SVG text; pure read, no counter advance, options validated
    pub fn export_qr_ansi(&self, id: AccountId) -> Result<Zeroizing<String>>;                            // §4.6 QR export → Unicode half-block render for terminals; pure read, no counter advance, no QrRenderOptions (terminal cells are fixed size)
    pub fn matching_accounts(&self, query: &AccountQuery) -> Vec<&Account>;         // shared selector matching; callers apply command-specific cardinality rules
    pub fn shortest_unique_id_prefix(&self, id: AccountId) -> Option<String>;       // minimum 8 hex chars; used in CLI candidate lists
    pub fn settings(&self) -> &VaultSettings;
    pub fn is_encrypted(&self) -> bool;                                            // current vault lock mode (false = plaintext, true = encrypted). Tracks passphrase transitions so TUI / GUI can gate `passphrase set` vs `passphrase change` / `remove`, decide whether to arm auto-lock, and update the visible vault-mode flag without re-inspecting the file.
    pub fn set_auto_lock_enabled(&mut self, enabled: bool);
    pub fn set_auto_lock_timeout_secs(&mut self, secs: u32) -> Result<()>;
    pub fn set_clipboard_clear_enabled(&mut self, enabled: bool);
    pub fn set_clipboard_clear_secs(&mut self, secs: u32) -> Result<()>;
    pub fn apply_setting_patch(&mut self, patch: SettingPatch) -> Result<()>;

    // Passphrase management — each saves atomically.
    pub fn set_passphrase(&mut self, store: &Store, options: EncryptionOptions) -> Result<()>;
    pub fn change_passphrase(&mut self, store: &Store, options: EncryptionOptions) -> Result<()>;
    pub fn remove_passphrase(&mut self, store: &Store) -> Result<()>;

    pub fn save(&self, store: &Store) -> Result<()>;
    pub fn mutate_and_save<T, F>(&mut self, store: &Store, f: F) -> Result<T>
    where
        F: FnOnce(&mut Vault) -> Result<T>;  // captures a zeroized internal rollback snapshot, applies `f` under `catch_unwind(AssertUnwindSafe)`, saves, restores on closure errors / panics / `save_not_committed`, resumes the unwind after a closure panic, leaves mutated state on `save_durability_unconfirmed`
}

pub fn write_secret_file_atomic(path: &Path, bytes: &[u8]) -> Result<()>;  // shared export writer: same-directory tempfile, 0600, file fsync, rename, parent fsync; no .bak; save_not_committed before rename, save_durability_unconfirmed after rename; caller handles overwrite policy
pub fn parse_otpauth(uri: &str, import_time: SystemTime) -> Result<ValidatedAccount>;
pub fn read_qr_image(path: &Path) -> Result<Vec<String>>;                 // one URI per decoded QR; returns an empty Vec when the image contains no QRs (the `import::qr_image` wrapper turns that into an error)
pub fn read_qr_image_bytes(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<String>>;  // raw RGBA8 clipboard/image buffer; validates nonzero dimensions, exact byte length, and QR_RGBA_MAX_BYTES; returns an empty Vec when the image contains no QRs

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
    pub kind: AccountKindInput,
    pub period_secs: Option<u32>,  // TOTP-only; None defaults to 30 seconds
    pub counter: Option<u64>,      // HOTP-only; None defaults to 0
    pub icon_hint: IconHintInput,  // Default derives from issuer; Clear stores None; Slug validates §4.1
}

pub fn validate_manual(input: AccountInput, now: SystemTime) -> Result<ValidatedAccount>;

/// Multi-field metadata edit for `Vault::edit_account_metadata`.
///
/// Only non-cryptographic metadata is editable: `label`, `issuer`,
/// `icon_hint`. OTP-affecting fields (`secret`, `algorithm`, `digits`,
/// `kind`, `period`, `counter`) are intentionally out of scope —
/// changing them invalidates already-issued codes and is better
/// expressed as remove + re-add. Each top-level field uses `Option`
/// for "leave untouched" semantics; the inner `Option` on `issuer`
/// distinguishes "clear" (`Some(None)`) from "set" (`Some(Some(_))`).
/// All present fields run through the same §4.1 validation as
/// `AccountInput`; invalid values surface as `validation_error`
/// without touching the vault. `edit_account_metadata` bumps
/// `updated_at` whenever at least one field is present, even when the
/// resulting value equals the prior value — same-as-prior submits
/// behave identically to `rename`'s same-label-still-bumps contract.
/// An `AccountEdit` with every field `None` is rejected at the core
/// boundary as `validation_error` (`field: "edit"`, `reason: "empty"`)
/// so the front ends do not silently no-op behind the user's back.
pub struct AccountEdit {
    pub label: Option<String>,             // Some(new) replaces; None leaves.
    pub issuer: Option<Option<String>>,    // Some(Some(s)) sets; Some(None) clears; None leaves.
    pub icon_hint: Option<IconHintInput>,  // Some(...) applies the IconHintInput tri-state (Default re-derives from the post-edit issuer; Clear stores None; Slug validates §4.1); None leaves the prior slug untouched.
}

pub fn validate_account_edit(edit: &AccountEdit, prior: &Account, now: SystemTime) -> Result<()>;  // pure-logic pre-flight validator routing the present fields through `validate_label`, `validate_issuer`, and the §4.1 slug-shape check (the same `[a-z0-9_-]+` rule `validate_icon_hint_slug` enforces) on the `IconHintInput::Slug(_)` arm; `IconHintInput::Default` / `Clear` carry no slug text so they need no validator. No mutation. Returns `validation_error` with the offending field on first failure. `Vault::edit_account_metadata` calls this internally; the front ends may also call it directly to drive inline per-field error rendering before the user submits.

pub mod import {
    pub enum ImportFormat { Otpauth, Aegis, Paladin, Qr, Unknown }
    pub struct ImportOptions<'a> {
        pub format: Option<ImportFormat>,  // None = auto-detect
        pub import_time: SystemTime,
        pub paladin_passphrase: Option<&'a SecretString>,
    }
    pub fn from_file(path: &Path, options: ImportOptions<'_>) -> Result<Vec<ValidatedAccount>>;  // facade: reads/detects path content, dispatches to the matching importer, and supports QR image files
    pub fn from_bytes(bytes: &[u8], options: ImportOptions<'_>) -> Result<Vec<ValidatedAccount>>;  // facade for already-loaded encoded content; image-format bytes are decoded and treated as QR input
    pub fn otpauth(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;  // single URI, line-list, or JSON array of URIs; errors when the input decodes to zero accounts (empty array, blank file, etc.)
    pub fn aegis_plaintext(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;
    pub fn paladin(bytes: &[u8], passphrase: &SecretString) -> Result<Vec<ValidatedAccount>>;  // encrypted Paladin bundle only
    pub fn qr_image(path: &Path, import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;
    pub fn qr_image_bytes(width: u32, height: u32, rgba: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>>;
    pub fn detect(bytes: &[u8]) -> ImportFormat;
}

pub mod export {
    pub fn otpauth_list(vault: &Vault) -> String;                               // newline-separated `otpauth://` URIs, one per line with trailing newline; empty vault → empty string. Infallible.
    pub fn encrypted(vault: &Vault, options: EncryptionOptions) -> Result<Vec<u8>>;  // Paladin encrypted bundle. Wraps `VaultPayload { accounts, settings: VaultSettings::default() }`; uses default or custom Argon2 params from `options`; `import::paladin` discards the settings field.
    pub fn qr_png(account: &Account, options: QrRenderOptions) -> Result<Zeroizing<Vec<u8>>>;  // §4.6 QR PNG bytes for one account's `otpauth://` URI. Validates `options`; encoder failures return `validation_error` (`field: "qr_render"`).
    pub fn qr_svg(account: &Account, options: QrRenderOptions) -> Result<Zeroizing<String>>;   // §4.6 QR SVG text for one account's `otpauth://` URI. Same validation contract as `qr_png`.
    pub fn qr_ansi(account: &Account) -> Result<Zeroizing<String>>;                            // §4.6 Unicode half-block QR for one account's `otpauth://` URI. Terminal output; no options because cell size is fixed by the renderer.
}
```

`VaultLock` is the unlock type for existing vaults, so `open` always treats
the encrypted file header as authoritative for KDF parameters. `VaultInit` is
used only when creating a new primary through `create` / `create_force`;
encrypted initialization carries `EncryptionOptions` so callers can choose the
default Argon2id cost or a validated custom cost. Passphrase set/change and
encrypted export also take `EncryptionOptions` because they create new
encrypted material. Plaintext paths never carry KDF parameters.

Every public type that a front end may move across a thread boundary
is `Send`. The CI-gated `Send` set covers `Vault`, `Store`, `Account`,
`AccountId`, `AccountSummary`, `AccountKindSummary`, `Algorithm`,
`Code`, `ValidatedAccount`, `ValidationWarning`, `ImportReport`,
`ImportWarning`, `ImportConflict`, `ImportFormat`, `ImportOptions<'_>`,
`EncryptionOptions`, `Argon2Params`, `QrRenderOptions`, `VaultLock`,
`VaultInit`, `VaultStatus`, `VaultSettings`, `SettingKey`,
`SettingPatch`, `AccountKindInput`, `IconHintInput`, `AccountInput`,
`AccountEdit`, `AccountQuery`, `InitPrecheck`, `PaladinImportPrecheck`,
and `PaladinError` — so
`paladin-gtk` can drive
encrypted `open` / `create` / `create_force` and any save-bearing
operation inside `gio::spawn_blocking`, and `paladin-tui` can drive
QR / image import on a worker thread. Static assertions in CI gate
the full set so a future change introducing a non-`Send` field fails
the build instead of silently breaking either front end.

The non-secret projection types (`AccountSummary`, `Code`,
`ImportReport`, `ImportWarning`, `VaultStatus`, `VaultSettings`,
`Algorithm`, `AccountKindSummary`, `Argon2Params`, `QrRenderOptions`,
`SettingKey`, `SettingPatch`, `IconHintInput`, `AccountKindInput`,
`AccountEdit`, `AccountQuery`, `InitPrecheck`, `AccountId`) are also
`Sync` — `AccountEdit` carries no secret bytes (only `label` /
`issuer` / `icon_hint` projections), so it sits with the non-secret
projection types here. Secret-bearing types
(`Vault`, `Store`, `Account`, `Secret`, `EncryptionOptions`,
`AccountInput`, `ValidatedAccount`, `VaultLock`, `VaultInit`,
`PaladinError`) are deliberately *not* asserted `Sync` — `SecretString`
is `!Sync` in `secrecy` and core does not promote any secret-bearing
type past that posture. CI also pins this decision so a future change
cannot accidentally promote a secret-bearing type to `Sync` without
review.

Because `Account` fields are private, presentation crates use
`Account::summary` / `Vault::summaries` for non-secret display data and
`Vault` mutators for CLI-level changes such as rename and import merge. Those
mutators reuse the same validation path as account construction, update
`updated_at` on account payload changes, and leave persistence to the
caller unless the method explicitly says it saves. Presentation crates
that need "mutate then save" semantics without hand-written rollback use
`Vault::mutate_and_save`: core captures the pre-mutation state, runs the
caller closure under `catch_unwind(AssertUnwindSafe(...))`, saves, restores
the snapshot when the closure fails, panics, or the save returns
`save_not_committed`, and leaves the mutated in-memory state in place when
the save returns `save_durability_unconfirmed` because the primary-file
commit point may have been reached. On a closure panic the unwind is
resumed after the snapshot is restored, so callers that catch the unwind
further up observe the pre-mutation state. The rollback snapshot is
secret-bearing and is zeroized when dropped.

Account selection and settings edits are split so core owns reusable
semantics while front ends own presentation policy. `parse_account_query`,
`Vault::matching_accounts`, `account_matches_search`,
`Vault::shortest_unique_id_prefix`, and `select_after_filter` implement
the shared §5 selector, issuer/label matching, and TUI / GUI search
selection-preservation rules; the CLI still decides which command
cardinality rules produce `no_match` or `multiple_matches`, and the
TUI / GUI use only the substring predicate plus `select_after_filter`
for search bars. `parse_setting_key`, `parse_setting_patch`, and
`Vault::apply_setting_patch` own the dotted settings grammar used by
the CLI, while TUI / GUI controls may call the typed setters directly.
`VaultSettings` fields are private for the same reason: readers use
`Vault::settings()` plus the read-only `VaultSettings` getters, and
settings changes go through validated setters or patches so timeout
minimums cannot be bypassed.

Add-account input, init-precheck logic, and Paladin-bundle import prompt
classification are shared too.
`parse_icon_hint_token` is the single source for the empty-default /
case-insensitive `none` / slug grammar that CLI prompts and TUI / GUI
add modals all collect. `classify_init_precheck` is the truth table
that maps `inspect()` results onto the §5 init flow: `Missing`
clears, `Plaintext` / `Encrypted` / `invalid_header` /
`unsupported_format_version` are existing-vault decisions requiring
the `init --force` confirmation gate, and any other error propagates
verbatim. `classify_paladin_import_precheck` is the shared pre-prompt
truth table for path-backed Paladin imports: it decides whether an
encrypted-bundle passphrase is needed, whether a plaintext or malformed
Paladin header should be rejected immediately, or whether the import
facade should handle the file normally. Front ends never reimplement
these grammars or header-probe decisions.

The `policy` module shares the timer math and decision protocols that
the TUI and GUI both need but that depend only on `VaultSettings` and
`Instant`: `policy::auto_lock::IdlePolicy` owns the encrypted-only
gating, idle-deadline arithmetic, and monotonic-expiry comparison;
`policy::clipboard_clear::ClipboardClearPolicy` owns the schedule
decision, monotonic `ClipboardClearToken` issuance, and the
only-if-unchanged byte-equality decision used to avoid clobbering a
clipboard the user has since changed; `policy::hotp_reveal::deadline`
owns the `now + HOTP_REVEAL_SECS` computation. Front ends still own
raw input event handling, timer plumbing (`gio::timeout_add_local`
or crossterm tick polling), and the OS clipboard adapters
(`arboard`, `gdk::Clipboard`).

Core methods that accept an `AccountId` return stable `invalid_state`
operation/state pairs for account-state failures; presentation crates still
own query cardinality errors such as `no_match` and `multiple_matches` before
calling these methods:

| Operation      | State               | Meaning                         |
| -------------- | ------------------- | ------------------------------- |
| `rename`       | `account_not_found` | No account exists for the ID.   |
| `edit_account_metadata` | `account_not_found` | No account exists for the ID. |
| `totp_code`    | `account_not_found` | No account exists for the ID.   |
| `totp_code`    | `not_totp`          | The account is HOTP.            |
| `totp_next_code` | `account_not_found` | No account exists for the ID. |
| `totp_next_code` | `not_totp`        | The account is HOTP.            |
| `hotp_peek`    | `account_not_found` | No account exists for the ID.   |
| `hotp_peek`    | `not_hotp`          | The account is TOTP.            |
| `hotp_advance` | `account_not_found` | No account exists for the ID.   |
| `hotp_advance` | `not_hotp`          | The account is TOTP.            |
| `export_qr_png`  | `account_not_found` | No account exists for the ID. |
| `export_qr_svg`  | `account_not_found` | No account exists for the ID. |
| `export_qr_ansi` | `account_not_found` | No account exists for the ID. |

Other core-owned `invalid_state` operation/state pairs are also stable:

| Operation           | State                 | Meaning                         |
| ------------------- | --------------------- | ------------------------------- |
| `set_passphrase`    | `already_encrypted`   | The vault is already encrypted. |
| `change_passphrase` | `not_encrypted`       | The vault is plaintext.         |
| `remove_passphrase` | `not_encrypted`       | The vault is plaintext.         |
| `import_paladin`    | `missing_passphrase`  | No bundle passphrase supplied.  |

## 5. CLI (`paladin`)

Built with `clap` (derive). Commands:

| Command                                     | Behavior                                                         |
| ------------------------------------------- | ---------------------------------------------------------------- |
| `paladin init [--force]`                    | Create a new vault. Without `--force`, checks for an existing primary and returns `vault_exists` before prompting for a new-vault passphrase. Prompts: passphrase? (empty = plaintext; text mode prints the plaintext-storage warning). Refuses to clobber an existing vault unless `--force` (which stages the new vault first, then rotates the old file to `vault.bin.bak`, overwriting any existing backup). The rotated `.bak` is preserved verbatim — a plaintext-to-encrypted clobber leaves plaintext secrets in `.bak` until the user removes it manually. |
| `paladin add`                               | Add an account interactively (or via flags / URI).               |
| `paladin add --qr <path>`                   | Add by scanning a QR image file. Every decoded QR in the image is added (errors if none decode); collisions use the default `import` merge policy (`skip`). For other policies, use `import --format=qr`. |
| `paladin list`                              | List accounts with the current TOTP code, seconds remaining in the current TOTP window, and the next TOTP code (matching the TUI/GTK list view). HOTP rows render the code columns as dashes in text mode and `null` under `--json` — `list` never advances or peeks an HOTP counter. |
| `paladin show <query>`                      | Print the current code. **Advances HOTP counter.**               |
| `paladin peek <query>`                      | Print the current code without advancing the HOTP counter; for TOTP, identical to `show`. |
| `paladin copy <query>`                      | Copy code to clipboard. For HOTP, advances and saves before attempting the clipboard write. (Auto-clear is TUI/GUI-only — the CLI ignores `clipboard.clear_enabled`; see security consideration 6.) |
| `paladin remove <query>`                    | Remove an account. Prompts for confirmation; `--yes` skips the prompt. Required under `--json` (no confirmation prompt available). |
| `paladin rename <query> <label>`            | Rename an account.                                               |
| `paladin edit <query> [--label <label>] [--issuer <issuer> \| --no-issuer] [--icon-hint <slug> \| --no-icon-hint] [--allow-duplicate]` | Edit an account's non-cryptographic metadata: label, issuer, and/or icon hint. Requires at least one of `--label` / `--issuer` / `--no-issuer` / `--icon-hint` / `--no-icon-hint`; a no-flag invocation is rejected at parse time as `validation_error` (`field: "argv"`, `reason: "no_edit_fields"`). `--issuer` and `--no-issuer` are mutually exclusive; `--icon-hint` and `--no-icon-hint` are mutually exclusive. Single-match cardinality (like `copy` / `remove` / `rename` / `qr`). After per-field validation, calls `Vault::find_duplicate_after_edit(id, &edit)` and rejects a `(secret, issuer, label)` collision with `duplicate_account` (the existing collision's `account` summary in the envelope) unless `--allow-duplicate` is supplied — mirroring `paladin add`'s collision path. Routes through `Vault::edit_account_metadata` inside `Vault::mutate_and_save`; bumps `updated_at`. Read-only on the secret bytes — never advances HOTP counters and never re-derives a slug from secret content. The narrower `paladin rename <query> <label>` stays as the label-only positional shorthand. |
| `paladin passphrase set`                    | Encrypt a plaintext vault under a new passphrase.                |
| `paladin passphrase change`                 | Re-encrypt under a new passphrase.                               |
| `paladin passphrase remove`                 | Decrypt to plaintext. Warns and prompts for destructive confirmation unless `--yes` is passed. Required under `--json` (no confirmation prompt available). |
| `paladin export --plaintext <out>`          | Write a newline-separated list of `otpauth://` URIs, one per line (Gnome Authenticator–compatible). Warns; refuses overwrite without `--force`; creates output `0600`. |
| `paladin export --encrypted <out>`          | Write Paladin-format encrypted bundle. Refuses overwrite without `--force`; creates output `0600`. |
| `paladin qr <query>`                        | Render one account's `otpauth://` URI as a QR code (§4.6). Resolves `<query>` with the same single-match cardinality as `copy`/`remove`/`rename`. Prints the QR-export warning (sourced from `paladin_core::format_plaintext_qr_export_warning()`) before any pixel is rendered or written. With `--out <path>`, writes the QR to disk through `write_secret_file_atomic` (0600, refuses overwrite without `--force`); without `--out`, renders ANSI Unicode half-blocks to stdout. `--format png\|svg\|ansi` selects the encoding (default `png` when `--out` is set, `ansi` when it is not). `--module-size-px <n>` (default 8) sets PNG/SVG pixels per QR module within `QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX`. Read-only: never advances a HOTP counter, never mutates `updated_at`. |
| `paladin import [--on-conflict=<mode>] <path>` | Auto-detect format and merge into the vault. Conflict mode: `skip` (default), `replace`, `append`. See merge policy below. |
| `paladin import --format=<fmt> <path>`      | Force format: `otpauth`, `aegis`, `paladin` (encrypted bundle only), `qr`.               |
| `paladin settings get [key]`                | Show vault settings (auto-lock, clipboard-clear).                |
| `paladin settings set <key> <value>`        | Edit vault settings.                                             |
| `paladin tui`                               | Convenience wrapper: execs `paladin-tui` (resolved via `PATH`), forwarding all global flags (e.g. `--vault`, `--no-color`) verbatim. `--json` is rejected at parse time because the TUI has no JSON mode. If `paladin-tui` is not on `PATH`, exits non-zero with `io_error` (`operation: "exec_paladin_tui"`). Keeps the §3 "binaries don't reach into each other" rule intact. |

Global flags: `--vault <path>`, `--no-color`, `--json` (for scripting).
`--vault` and `--no-color` are accepted by every binary in the workspace
(`paladin`, `paladin-tui`, and the v0.2 `paladin-gtk`); `--json` is
`paladin`-only — `paladin-tui` and `paladin-gtk` reject it at parse time.
For terminal front ends, `--no-color` disables ANSI/styled output. The CLI
also disables ANSI when stdout is not a TTY, and both the CLI and TUI honor
the `NO_COLOR` environment variable.

Encrypted-write CLI commands accept the advanced Argon2id flags
`--kdf-memory-mib <mib>`, `--kdf-time <iterations>`, and
`--kdf-parallelism <lanes>`: `init`, `passphrase set`,
`passphrase change`, and `export --encrypted`. Omitted flags use the §4.4
defaults (`64`, `3`, `1`). Supplied values are converted to `Argon2Params`
(`m_kib = mib * 1024`) and validated against the §4.4 bounds before
inspecting, opening, or unlocking a vault, before wrong-state checks, before
any prompt, and before salt/nonce generation. Invalid KDF input therefore wins
over `vault_missing`, `invalid_state`, unlock passphrase prompts, and
new-passphrase prompts. Out-of-range values return `kdf_params_out_of_bounds`;
invalid integers or
`mib * 1024` overflow return `validation_error` with the corresponding flag as
`field`. For `init`, the KDF flags are parsed and validated before the
existence pre-check and before the first passphrase prompt. If the user then
enters an empty passphrase to select plaintext storage, valid custom KDF values
are accepted but unused.

All interactive CLI prompts read from `/dev/tty`, never from stdin/stdout, in
both text and `--json` modes. Passphrase prompts use `rpassword`. Existing
vault passphrases and encrypted Paladin bundle import passphrases are prompted
once. New passphrases (`init` when the first entry is non-empty,
`passphrase set`, `passphrase change`, and `export --encrypted`) are prompted
twice and must match. For `init`, an empty first entry selects plaintext
storage and skips confirmation; any already-validated KDF flags are unused in
that plaintext path. Every other empty new passphrase is rejected with
`invalid_passphrase` (`reason: "zero_length"`). Confirmation mismatch exits
before mutation with `invalid_passphrase`
(`reason: "confirmation_mismatch"`). If `/dev/tty` is unavailable for a
passphrase prompt, the CLI exits with `io_error` and operation
`"passphrase_prompt"`. If `/dev/tty` is unavailable for interactive account
entry, it exits with `io_error` and operation `"account_prompt"`. If
`/dev/tty` is unavailable for a destructive confirmation prompt, it exits with
`io_error` and operation `"confirmation_prompt"`. Destructive confirmations
require the exact string `yes` after trimming surrounding Unicode whitespace;
any other response exits before mutation with `validation_error`
(`field: "confirmation"`, `reason: "declined"`). The CLI does not reprompt.

`paladin add` supports exactly one input mode per invocation:
interactive prompts (no account-definition flags), `--uri <otpauth-uri>`,
manual flags, or `--qr <path>`. Combining input modes (e.g. `--uri`
together with manual flags or `--qr`, or `--qr` together with manual
flags) is rejected at parse time. Under `--json`, interactive mode is rejected
at parse time: one of `--uri`, `--qr`, or the manual flags must be supplied.
Interactive mode prompts once for the same fields as manual mode, with
required label and hidden secret entry, optional issuer, and the same defaults
and constraints for algorithm, digits, kind, period, counter, and icon-hint.
After collecting the form once, the CLI builds `AccountInput` and calls
`paladin_core::validate_manual(input, now)`. Any validation error exits with
that `validation_error`; the CLI does not loop, reprompt, or partially save.
Manual mode requires `--label` and `--secret`; optional
fields are `--issuer`, `--algorithm sha1|sha256|sha512`, `--digits 6|7|8`,
`--kind totp|hotp`, `--period <secs>`, `--counter <u64>`, and optionally
one of `--icon-hint <slug>` or `--no-icon-hint`. Manual mode defaults to
TOTP, SHA1, 6 digits, and a 30-second period. HOTP manual entries default to
counter 0 when `--counter` is omitted. Manual `--secret` is Base32 text using
the same rules as the `otpauth://` `secret` parameter; the decoded bytes must
pass the §4.1 secret validation. `--period` is TOTP-only, `--counter` is
HOTP-only. `--icon-hint` and `--no-icon-hint` are mutually exclusive. When
neither is present, `AccountInput.icon_hint = IconHintInput::Default` derives
from the issuer using the §4.1 defaulting rule. `--icon-hint <slug>` routes
through `paladin_core::parse_icon_hint_token` so flag-mode and
interactive-mode `add` share one grammar with `paladin edit --icon-hint`:
an empty token (after Unicode-whitespace trim) maps to
`IconHintInput::Default`; a case-insensitive `none` maps to
`IconHintInput::Clear`; any other token validates as a §4.1 slug
(`[a-z0-9_-]+` up to 64 bytes) and maps to `IconHintInput::Slug`.
`--no-icon-hint` maps to `IconHintInput::Clear`. All add modes use the shared account validation path
and return validation warnings in the success payload. A single-entry `add`
rejects an existing
`(secret, issuer, label)` collision with `duplicate_account` and the existing
`account` summary unless `--allow-duplicate` is supplied, in which case it
appends a new account. The collision check uses
`Vault::find_duplicate(&validated)` so the exact secret-bearing comparison
lives in core even though `duplicate_account` remains a CLI/TUI/GUI-facing
presentation error. `add --qr` remains the multi-entry exception and uses the
import merge path with fixed `--on-conflict=skip`; `--allow-duplicate` is
mutually exclusive with `--qr` and is rejected at parse time.

`init` checks for an existing primary before prompting for a new-vault
passphrase when `--force` is absent; an existing primary returns
`vault_exists` without touching `/dev/tty`. `init --force` uses a dedicated
clobber path. It writes the new vault to `vault.bin.tmp` and `fsync`s it
before moving any existing primary. If that staging step fails, the old
primary and `.bak` are untouched. Once staging succeeds, if an existing
primary is present, it renames `vault.bin` → `vault.bin.bak` (overwriting any
existing backup). It then renames `vault.bin.tmp` → `vault.bin` and `fsync`s
the parent directory. The primary rename is the primary-file commit point. A
failure after backup rotation but before the primary rename leaves the old
vault available at `vault.bin.bak`; the CLI error names that path so the user
can restore it. A failure after the primary rename is reported as
durability-unconfirmed, matching the normal save semantics.

All mutating CLI commands call the atomic save path before returning
success. If save fails, the command exits non-zero. The primary vault file
is never partially written: a pre-commit save failure leaves the previous
primary authoritative, while a durability-unconfirmed failure after the
primary-file commit point may leave the new primary in place. In both
cases `.bak` may have rotated as described in §4.3, so CLI error text and
JSON include whether the primary commit point was reached. Imports of
encrypted Paladin bundles prompt for the bundle passphrase, which is
independent of the vault passphrase. Before prompting, the CLI calls
`paladin_core::classify_paladin_import_precheck(path, forced_format)` so the
shared core classifier owns the Paladin-header decision: encrypted bundles
prompt, plaintext Paladin vaults return `unsupported_plaintext_vault` without
a passphrase prompt, malformed Paladin headers return the typed
header/version error, and non-Paladin or unreadable files continue through
`import::from_file` so the import facade owns the final read/dispatch error.

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

`qr` is read-only and never advances a HOTP counter, so the
HOTP-export rule is "encode the current stored counter" — a user
scanning the QR onto a second device and continuing to use the first
loses no codes to a phantom advance, matching the §4.6 contract.
Query cardinality is the same as `copy`/`remove`/`rename`: a single
match is required, and multiple matches exit non-zero with the
candidate list. With `--out <path>` the QR is rendered via
`Vault::export_qr_png` or `Vault::export_qr_svg` (selected by
`--format`, default `png`), written through `write_secret_file_atomic`
(0600), and refused on an existing target without `--force`. Without
`--out`, the QR is rendered via `Vault::export_qr_ansi` to stdout;
`--format=png` or `--format=svg` without `--out` is rejected at parse
time as `validation_error` (`field: "out"`, `reason: "required_for_binary_format"`)
because binary blobs to a terminal are unhelpful. Conversely,
`--format=ansi` together with `--out` is rejected at parse time as
`validation_error` (`field: "format"`, `reason: "ansi_requires_no_out"`)
because the Unicode half-block render is a terminal-only surface; file
output is PNG or SVG. Under `--json`, an ANSI render to stdout is also
rejected at parse time
(`field: "out"`, `reason: "required_under_json"`) so the strict-mode
"only the JSON envelope on stdout" rule (§5) is preserved. Render
parameters are validated before the warning text is printed and
before the account is resolved: `--module-size-px` outside
`QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX` returns
`validation_error` (`field: "module_size_px"`). `--module-size-px`
on `--format=ansi` is accepted but ignored — terminal cell size is
fixed by the renderer. The QR-export plaintext warning is rendered
in text mode and suppressed in `--json` mode (parallel to the
`init --force`, plaintext-export, and `passphrase remove --yes`
advisories), since the user opting into `--out <path>` plus
`--json` has already opted into machine-readable output.

`paladin edit <query>` is the multi-field metadata edit. It requires
at least one of `--label <label>`, `--issuer <issuer>`, `--no-issuer`,
`--icon-hint <slug>`, or `--no-icon-hint`; a no-flag invocation is
rejected at parse time as `validation_error` (`field: "argv"`,
`reason: "no_edit_fields"`) before the query is resolved. `--issuer`
and `--no-issuer` are mutually exclusive, as are `--icon-hint` and
`--no-icon-hint`; either collision is rejected at parse time as
`validation_error` (`field: "argv"`, `reason: "mutually_exclusive"`).
Supplied values map onto `paladin_core::AccountEdit`: `--label`
populates `label = Some(value)`, `--issuer` populates
`issuer = Some(Some(value))` after the §4.1 issuer normalization (so
`--issuer ""` normalizes to `Some(None)` and is functionally
equivalent to `--no-issuer`),
`--no-issuer` populates `issuer = Some(None)`, `--icon-hint <slug>`
parses through `paladin_core::parse_icon_hint_token(slug)` (so the
empty / case-insensitive `none` / explicit-slug grammar matches
`add`) and populates `icon_hint`, and `--no-icon-hint` populates
`icon_hint = Some(IconHintInput::Clear)`. The CLI resolves the
query with the same single-match cardinality as `copy` / `remove` /
`rename` / `qr`. After per-field validation succeeds and before the
mutator runs, the CLI calls `Vault::find_duplicate_after_edit(id,
&edit)` and rejects a non-`None` result with `duplicate_account`
(the existing collision's `AccountSummary` in the envelope's
`account` field) unless `--allow-duplicate` is supplied — mirroring
the `paladin add` collision path. The helper projects the would-be
post-edit `(secret, issuer, label)` triple — applying §4.1
normalization to issuer and label — and skips the account at `id`
so an unchanged self-edit never reports a collision. The mutation
itself runs inside `Vault::mutate_and_save` so pre-commit failures
restore the pre-edit account state; `save_durability_unconfirmed`
leaves the edit visible with the standard durability warning.
`paladin edit` is read-only on the secret bytes — it never advances
HOTP counters, never decodes the stored secret, and never re-derives
a slug from secret content. `paladin rename <query> <label>` stays
as the single-positional shorthand for the label-only path and is
implemented on top of the same `Vault::edit_account_metadata`
mutator.

With `--json`, commands write one JSON document to stdout on success and
one JSON document to stderr on failure. To keep the CLI scriptable,
`paladin` pre-scans argv for an exact `--json` token before clap parsing;
when present, syntax/usage failures also render the JSON error envelope
to stderr instead of clap's text diagnostics. Those parse failures keep
clap's normal syntax-error exit code and use `kind: "validation_error"`;
when no more specific parser-side validation field is available, they use
`field: "argv"` and `reason: "usage"`. Help and version requests are success
terminal requests, not syntax failures: when `--json` is present, `--help`
/ `-h` / subcommand help write the JSON help shape to stdout with exit code
0, and `--version` / `-V` writes the JSON version shape to stdout with exit
code 0. Text mode keeps clap's normal help/version rendering. This JSON
parse-error and help/version behavior is only for the `paladin` binary;
`paladin-tui` and `paladin-gtk` reject `--json` without implementing JSON
output (their rejection is plain text — there is no JSON envelope). `code`
values are strings so leading zeroes are preserved.

Under `--json`, `paladin` writes **only** the JSON envelope: the success
document to stdout, the failure document to stderr, and no other bytes
on either stream. The strict-mode rule covers every output path: text-
mode validation warnings (`short_secret`) flow into the success envelope's
`warnings` array for `add` and `import`; import skip warnings are represented
by the `skipped` count; the `init --force`, plaintext `init`,
`passphrase remove --yes`, and plaintext-export advisories are suppressed
because the caller opted in via `--force`, an empty `init` passphrase, `--yes`,
or `--plaintext`; clap diagnostics are rerouted via the argv pre-scan above;
help/version text is wrapped in JSON success documents; and progress or
status text is never emitted. Interactive `add` is
rejected at parse time under `--json`, so account-entry prompt strings cannot
appear on stdout or stderr. Confirmation flags (`remove --yes`,
`passphrase remove --yes`) are required under `--json` since no interactive
confirmation channel is available, and missing
confirmations reject at parse time as `validation_error`. Passphrase prompts
continue to read from `/dev/tty` via `rpassword`; the prompt string is written
to `/dev/tty`, never to stdout or stderr, so a script that redirects both
streams sees only the JSON envelope. This rule is the script contract — JSON
consumers can `parse(stdout)` on exit 0 and `parse(stderr)` on non-zero exit
without filtering.

The common account shape is `paladin_core::AccountSummary` serialized by the
CLI's `error-serde` build. It is also the read-only projection used by TUI and
GUI list rows:

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
| `list`                        | `{ "accounts": [AccountSummary + { "code", "seconds_remaining", "next_code" }] }` — each row is an `AccountSummary` flattened with three optional fields. TOTP rows fill `code` (string), `seconds_remaining` (integer 1..=period), and `next_code` (string); HOTP rows set all three to `null` (`list` does not advance or peek an HOTP counter). |
| `show`, `peek`                | `{ "codes": [CodeResult] }`                                                     |
| `copy`                        | `{ "copied": true, "account": AccountSummary, "counter_used": number_or_null }` |
| `add` (single)                | `{ "account": AccountSummary, "warnings": [Warning] }`                          |
| `rename`                      | `{ "account": AccountSummary }`                                                 |
| `edit`                        | `{ "account": AccountSummary }` (the post-edit `AccountSummary`, including the bumped `updated_at`)                                                 |
| `add --qr`                    | Same shape as `import` (a `--qr` add can decode multiple URIs and uses a fixed `--on-conflict=skip`). |
| `remove`                      | `{ "removed": AccountSummary }`                                                 |
| `import`                      | `{ "imported": n, "skipped": n, "replaced": n, "appended": n, "accounts": [AccountSummary], "warnings": [Warning] }` |
| `export`                      | `{ "written": "/path/to/out", "format": "otpauth_or_paladin" }`                |
| `qr`                          | With `--out`: `{ "written": "/path/to/out", "format": "qr_png_or_qr_svg", "account": AccountSummary }`. Without `--out`: rejected at parse time under `--json` because ANSI stdout output cannot share the JSON envelope; `--json` callers must pass `--out`. |
| `settings get`, `settings set` | `{ "settings": VaultSettings }` (always full settings; `[key]` on `get` only filters text-mode display, never the JSON shape) |
| `init`, `passphrase *`        | `{ "ok": true, "status": "plaintext_or_encrypted" }`                           |
| `--help` / subcommand help    | `{ "help": { "command": "paladin ...", "text": "..." } }`                      |
| `--version`                   | `{ "version": { "name": "paladin", "version": "x.y.z" } }`                     |

Pseudo-values such as `number_or_null` and `plaintext_or_encrypted`
document allowed values; concrete output uses actual numbers, `null`, or
enum strings. For help requests, `command` is the clap command path whose help
was requested (for example `"paladin"` or `"paladin add"`) and `text` is the
same generated help text that text mode would print for that command. For
version requests, `name` and `version` come from Cargo package metadata. For
`import`, every input row falls into exactly one of four buckets:
`imported` counts non-colliding rows written as new
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
and omitted for single-entry `add`. The `message` string is produced by
`paladin_core::format_validation_warning`, and text-mode commands / UI
surfaces use the same helper. Text-mode commands print warnings to stderr
while still exiting zero on success.
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
`"committed": false` and, for vault writes such as `init --force` failures
that moved the old primary to `.bak`, `backup_path`; and
`clipboard_write_failed` includes
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
| `kdf_params_out_of_bounds`      | Argon2 params exceed policy.                 | `m_kib`, `t`, `p`                          |
| `unsupported_import_format`     | Detected/forced import format is invalid.    | `format`                                   |
| `unsupported_plaintext_vault`   | Import saw a plaintext Paladin vault.        | none                                       |
| `unsupported_encrypted_aegis`   | Aegis import saw an encrypted backup.        | none                                       |
| `unsupported_aegis_entry_type`  | Aegis entry is not `totp` or `hotp`.         | `source_index`, `entry_type`               |
| `no_entries_to_import`          | Import/QR input decoded zero accounts.       | none                                       |
| `duplicate_account`             | `add` or `edit` collided without `--allow-duplicate`. | `account`                                  |
| `no_match`                      | Query matched no accounts.                   | none                                       |
| `multiple_matches`              | Query matched too many accounts.             | `candidates`                               |
| `counter_overflow`              | HOTP advance would exceed `u64::MAX`.        | `account`                                  |
| `time_range`                    | Time is before epoch or overflows TOTP.      | none                                       |
| `save_not_committed`            | Atomic save/export failed before final rename. | `committed: false`, optional `backup_path` |
| `save_durability_unconfirmed`   | Atomic save/export renamed final output but durability is unclear. | `committed: true` |
| `clipboard_write_failed`        | Clipboard write failed after generation.     | `account`, `counter_used`                  |
| `io_error`                      | Filesystem/image/terminal I/O failed.        | `operation`, optional `path`               |

For `unsupported_import_format`, the `format` field is a lowercase
`ImportFormat` string. Auto-detect failures report the detected value
(`"unknown"`). Forced-format failures report the requested forced format,
even when content sniffing found a different shape.

Core-returned `io_error.operation` values are stable strings:

| Operation                           | Meaning                                                   |
| ----------------------------------- | --------------------------------------------------------- |
| `resolve_default_vault_path`        | `ProjectDirs` could not resolve a data directory.         |
| `unsupported_platform_permissions`  | Non-Unix target cannot enforce v0.1 permissions safely.   |
| `create_vault_dir`                 | Creating the vault parent directory failed.               |
| `stat_vault_dir`                   | Reading vault parent-directory metadata failed.           |
| `stat_vault_file`                  | Reading primary vault metadata failed.                    |
| `stat_backup_file`                 | Reading backup vault metadata failed.                     |
| `read_vault_file`                  | Reading the primary vault file failed.                    |
| `write_vault_tmp`                  | Writing the staged primary vault file failed.             |
| `write_backup_tmp`                 | Writing the staged backup file failed.                    |
| `fsync_temp_file`                  | Syncing a staged temp file failed.                        |
| `rename_backup`                    | Moving content to `vault.bin.bak` failed.                 |
| `rename_primary`                   | Moving staged content to the final primary path failed.   |
| `fsync_vault_dir`                  | Syncing the vault parent directory failed.                |
| `cleanup_temp_file`                | Removing a leftover temp file failed.                     |
| `read_import_file`                 | Reading an import source file failed.                     |
| `read_qr_image`                    | Loading a QR image file failed.                           |
| `decode_image_bytes`               | Decoding encoded image bytes failed.                      |
| `decode_qr_image`                  | QR extraction failed after an image was loaded.           |
| `write_secret_file_tmp`            | Writing the export/secret staged file failed.             |
| `fsync_secret_file_tmp`            | Syncing the export/secret staged file failed.             |
| `rename_secret_file`               | Moving export/secret bytes to the final path failed.      |
| `fsync_secret_file_dir`            | Syncing the export/secret parent directory failed.        |
| `csprng_read`                      | OS CSPRNG read for salt or nonce generation failed.       |
| `kdf_allocation`                   | Argon2id memory allocation failed (read or write path).   |
| `vault_file_is_symlink`            | `vault.bin` exists at the resolved path as a symlink and is rejected before any read or write. |
| `backup_file_is_symlink`           | `vault.bin.bak` exists at the resolved path as a symlink and is rejected before any read or write. |
| `vault_dir_is_symlink`             | The vault parent directory is a symlink and is rejected before any read or write. |

Binary crates may add presentation-specific operations such as
`passphrase_prompt`, `account_prompt`, `confirmation_prompt`, and
`exec_paladin_tui`, but they do not rename core operations.

The CLI owns JSON envelope rendering, but `paladin-core` exposes
`serde::Serialize` for `PaladinError` only behind an off-by-default
`error-serde` cargo feature so the CLI can serialize the shared
`error_kind` taxonomy without a mapping layer. The same feature may serialize
non-secret view types such as `AccountSummary`, `Code`, warnings, reports, and
settings, but never secret-bearing `Account` / `Secret`. `paladin-core` itself
has no JSON output paths, and the feature-gated serialization impl is not part
of the stable §4.7 API surface.

Vault settings keys (subject to extension):

| Key                       | Type             | Default | Effect                                       |
| ------------------------- | ---------------- | ------- | -------------------------------------------- |
| `auto_lock.enabled`       | bool             | `false` | Whether TUI/GUI lock on idle.                |
| `auto_lock.timeout_secs`  | u32              | `300`   | Idle timeout when enabled.                   |
| `clipboard.clear_enabled` | bool             | `false` | TUI/GUI: schedule a clipboard wipe after copy. (CLI ignores.) |
| `clipboard.clear_secs`    | u32              | `20`    | Wipe timeout when enabled.                   |

Bounds: `30 <= auto_lock.timeout_secs <= 86_400` (24 h),
`5 <= clipboard.clear_secs <= 600` (10 min). `VaultSettings` fields are private;
`settings set` and the core settings setters reject out-of-range values with a
validation error. The CLI's
dotted key/value grammar is parsed by `paladin_core::parse_setting_patch`
so key names, lowercase bool parsing, base-10 `u32` parsing, and minimum
checks stay in core. `parse_setting_key` is the same key-name source for
`settings get [key]`. TUI and GUI controls may call the typed setters
directly, but they use the same setter validation and persist through
`Vault::mutate_and_save`.

### Query resolution

`<query>` is a case-insensitive substring match against `"{issuer}:{label}"`
(empty issuer is allowed; the colon is still present in the match key).
Matching compares `str::to_lowercase()` output for the query and match key;
Paladin applies no Unicode normalization and no locale-specific casing, so
visually equivalent but differently normalized strings may not match. The
substring predicate is `paladin_core::account_matches_search`; CLI query
resolution, TUI search, and GUI search all use that helper rather than
reimplementing the comparison.

- `show` prints **all** matching entries when every match is TOTP. If any
  matched entry is HOTP, `show` requires a single match — the same rule
  as `copy`/`remove`/`rename`/`qr` below — so a substring query cannot
  silently advance multiple HOTP counters.
- `peek` prints **all** matching entries unconditionally (no state mutation).
- `copy`, `remove`, `rename`, `edit`, and `qr` require a single match. On multiple
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
  applies for `copy`/`remove`/`rename`/`qr`. `id:` is reserved as a query
  prefix; the prefix after `id:` must be 8 to 32 hex chars, and invalid
  or shorter prefixes are validation errors. An account whose
  `issuer:label` happens to start with `id:` is still reachable by any
  other substring of that key. `paladin_core::parse_account_query` owns
  the `id:` validation, `Vault::matching_accounts` owns the actual match
  collection, and `Vault::shortest_unique_id_prefix` owns candidate
  disambiguator computation. The CLI owns only the command-specific
  cardinality policy and output error rendering.

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
┌ Paladin ──────────────────────────────────────────────────────────────┐
│ Search: ____________                                                  │
├───────────────────────────────────────────────────────────────────────┤
│ ▶ GitHub (ben@…)        123 456   ████████░░  18s   ↪ 482 913        │
│   AWS prod              987 654   ████░░░░░░   8s   ↪ 391 044        │
│   AWS-HOTP (#42)        ▸ press n to advance                          │
├───────────────────────────────────────────────────────────────────────┤
│ [↑↓] move  [enter] copy  [C] copy-next  [n] next-HOTP  [a] add [/]find│
└───────────────────────────────────────────────────────────────────────┘
```

- TOTP rows: live `Gauge` countdown, re-render on a 250 ms tick.
- **Next code column** (TOTP rows only): rendered to the right of the
  countdown (mirroring the GTK `ColumnView` order), the code for the
  next 30-second window is prefixed with `↪ ` and styled with
  `Style::default().add_modifier(Modifier::DIM)`.
  The dim styling plus the `↪` glyph signal "upcoming, not the live one"
  without requiring the user to read the column header. Computed via
  `paladin_core::Vault::totp_next_code(id, now)` so the boundary math
  (next window start = `((now_secs / period) + 1) * period`) lives in
  core. HOTP rows leave this cell blank — HOTP has no time-based "next";
  the next code only exists after a deliberate counter advance. The
  column is shown whenever any visible row is TOTP and hidden entirely
  in HOTP-only vaults (parity with the existing progress / countdown
  columns). Pressing `C` (shift-c) on the selected row copies the next
  code to the clipboard and emits a status-line confirmation of the form
  `next code copied, valid in 18s` (where the seconds value is the
  remainder of the current window). `C` on a HOTP row is rejected with
  a status-line message (`no next code for HOTP accounts`); the next
  code itself is held in a `SecretString` and zeroized after the copy
  effect resolves, matching the §6 secret-handling rules for the
  current code.
- HOTP rows: code is hidden until the user presses `n` (advances counter
  and saves); after the shared `paladin_core::HOTP_REVEAL_SECS`
  reveal window (120 seconds), returns to the hidden
  state. `n` **always** advances and re-reveals — it is the "give me
  the next code" key — so pressing `n` again during an open reveal
  window advances to the next counter rather than no-op'ing on the
  already-visible code. Hidden HOTP rows show the stored next counter in
  the row label. Revealed rows show the counter that produced the visible
  code (`Code.counter_used`, the pre-advance counter) until the reveal expires;
  after expiry, the hidden row returns to showing the stored next counter.
  Copying a hidden HOTP row is rejected with a status message. Copying
  during the reveal window copies the visible code and does not advance
  the counter again.
- Startup calls `inspect(path)`: plaintext vaults open directly to the
  list; encrypted vaults show the unlock screen; missing vaults open
  the in-app **create-vault** flow described below. The CLI's
  `paladin init` remains available as an out-of-band alternative
  (and is the only way to set custom Argon2id `--kdf` cost
  parameters), but a user can now create a vault entirely from
  within the TUI without leaving the terminal.
- **Create-vault flow** (shown on `VaultStatus::Missing`): a two-step
  wizard built on the same `paladin_core::create(path, init)` call
  the CLI uses. Defaults-only — Argon2id cost parameters are taken
  from `Argon2Params::default()` (§4.4); KDF tuning remains a CLI
  feature.
  1. **Choose mode** — two options: *Encrypted* (recommended,
     default selection) and *Plaintext* (insecure). `↑` / `↓` /
     `j` / `k` move the selection; `Enter` advances; `Esc` or
     `q` quits.
  2a. *Encrypted* → **Enter passphrase** with a `passphrase` and
     `confirmation` masked field (`•` per char, exactly like the
     unlock screen). `Tab` / arrows switch focus; `Enter` on the
     `passphrase` field moves focus to `confirmation`; `Enter` on
     `confirmation` validates byte-for-byte equality and calls
     `paladin_core::create(path, VaultInit::Encrypted(
     EncryptionOptions::new(passphrase)))`. Empty passphrase or
     mismatch surfaces an inline error and re-focuses the failing
     field with the prior typed bytes zeroized. `Esc` returns to
     Choose-mode (both buffers zeroized).
  2b. *Plaintext* → **Confirm plaintext** screen rendering the
     plaintext-storage warning from
     `format_plaintext_storage_warning()`; `Enter` confirms and
     calls `paladin_core::create(path, VaultInit::Plaintext)`,
     `Esc` returns to Choose-mode.
  On success the app transitions straight to `Unlocked` with an
  empty account list — the user lands on the same screen they
  would after `paladin init` + relaunch. On failure (any
  `paladin_core::create` / `Vault::save` error, including
  `unsafe_permissions` rendered via
  `format_unsafe_permissions`) the user stays in the
  create-vault flow with an inline error and the typed
  passphrase bytes zeroized; `Ctrl-C` always quits and zeroizes.
  The flow never writes to disk before the user confirms in the
  final step, and never silently downgrades an encrypted choice
  to plaintext.
- Modal dialogs for add / remove / rename / edit / import / export / qr /
  passphrase / settings. Add supports manual entry, paste of an `otpauth://` URI
  (decoded via `paladin_core::parse_otpauth`), and QR scan from
  clipboard image bytes; manual and URI duplicates use
  `Vault::find_duplicate` and reject with the existing account, while
  QR imports use `ImportConflict::Skip` and report
  imported/skipped/warning counts. Rename calls `Vault::rename(id,
  new_label, now)` inside `Vault::mutate_and_save`; issuer is not
  editable here (parity with `paladin rename`). Edit (opened with
  `Shift+E` on the focused account row) opens an `AccountEdit`-bearing
  modal pre-populated from the current `AccountSummary`: a `tui-input`
  row for the label, a `tui-input` row for the issuer, and a
  four-option segmented icon-hint selector (*Leave unchanged* /
  *Default from issuer* / *No icon* / *Slug:*) with a sibling
  `tui-input` slug row that activates when the selector is on *Slug:*.
  The *Leave unchanged* default keeps the prior `icon_hint`
  untouched; the other three options map 1:1 to the three
  `IconHintInput` variants the Add modal collects through
  `parse_icon_hint_token`. The *Slug:* row routes its buffer
  through `validate_icon_hint_slug` so a user who types literal
  `default` or `none` saves those as slugs rather than collapsing
  them into the `Default` / `Clear` tri-state. Submit routes
  through `Vault::edit_account_metadata` inside
  `Vault::mutate_and_save`, bumping `updated_at` and surfacing
  per-field validation errors inline without closing. The Rename modal stays for muscle-memory continuity
  as the label-only shorthand; the Edit modal is the full surface and
  is the one the GUI's `EditDialog` (§7) mirrors. OTP-affecting fields
  (`secret`, `algorithm`, `digits`, `kind`, `period`, `counter`) are
  intentionally absent — changing them invalidates already-issued
  codes and the user is directed to remove + re-add. Import takes a file path and
  optional explicit format, calls `classify_paladin_import_precheck` before
  any Paladin bundle passphrase prompt, prompts only for encrypted-Paladin
  sources, applies a user-selected on-conflict
  policy (`skip` / `replace` / `append`), and reports
  imported/skipped/replaced/appended/warning counts. Export writes
  either a newline-separated list of plaintext `otpauth://` URIs
  (one per line, Gnome Authenticator–compatible; with an explicit
  unencrypted-secrets warning before the write) or an encrypted
  Paladin bundle (passphrase prompted twice and matched), refuses
  overwrite without explicit confirmation, and surfaces the resulting
  `0600` output path inline. Mutating modal actions use
  `Vault::mutate_and_save` so pre-commit save failures restore the
  pre-attempt vault state in memory; durability-unconfirmed failures leave
  the committed state visible with an inline warning.
  Manual Add, URI Add, Remove, Rename, Export, Passphrase, and Settings
  close on confirmed success with a status-line confirmation. Import and
  clipboard-QR Add remain on a post-success counts panel so the
  imported/skipped/replaced/appended/warning counts stay visible until the
  user dismisses them.
  The **QR modal** (opened with `Q` on the focused account row) renders
  the §4.6 per-account QR via `Vault::export_qr_ansi(id)` after the user
  acknowledges the QR-export warning sourced from
  `paladin_core::format_plaintext_qr_export_warning()`. The modal body
  shows the warning + ack gate first; on ack, the same modal switches
  to the Unicode half-block QR plus the account's `summary_display_label`
  caption (CLI / GUI parity) and two save actions, `Save as PNG…` and
  `Save as SVG…`, both routed through `Vault::export_qr_png` /
  `export_qr_svg` and `write_secret_file_atomic` (0600). Save targets
  prompt for a destination path inside the modal, refuse overwrite
  without an inline `--force`-equivalent confirmation, and surface the
  resulting path inline on success. `Esc` closes the modal and drops
  the rendered `Zeroizing` buffers. The modal opens regardless of OTP
  kind (TOTP and HOTP rows both qualify — §4.6 is read-only, so HOTP
  rows do not need the hidden-code reveal gate that `show` / `copy`
  use); the only defensive rejection is a focused row that carries no
  decoded `Account` value, which cannot occur in normal `Unlocked`
  state. Auto-lock during the modal lifecycle drops the rendered
  buffers before switching to the unlock screen.
- `?` from list focus opens a read-only Help overlay listing every
  keybinding; `Esc` closes it. The overlay never mutates state and is
  not bound on the unlock, create-vault, or startup-error screens.
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
- Effect failures leave the current screen/modal open and update visible
  state only after the underlying mutation succeeds; errors surface inline
  in the active modal or in the status line.
- Single event loop: `crossterm` events ↔ tick events via `mpsc`.

## 7. GUI (`paladin-gtk`)

Library: **Relm4** on **GTK4**. Component tree:

- `AppModel` — owns the resolved vault path plus the `Missing` /
  `Locked` / `Unlocked` / `StartupError` state. Startup runs
  `paladin_core::inspect(path)`: plaintext vaults open directly to the
  list, encrypted vaults show `UnlockComponent`, and missing vaults
  open `InitDialog` so the user can create a vault from inside the
  app. Default-path, inspect, or non-authentication open failures render
  a non-mutating startup-error view with retry and quit actions.
- `InitDialog` — in-app vault initialization for the GUI (v0.2). The
  TUI ships its own §6 create-vault flow with the same defaults-only
  contract; the CLI continues to use `paladin init`. Two passphrase fields
  (twice-confirmed; both fields empty select plaintext, with the same
  unencrypted-storage warning used by `passphrase remove`) plus an
  explicit "create vault" confirmation. Calls
  `paladin_core::create(path, init)` on `gio::spawn_blocking`
  (encrypted creation runs the §4.4 Argon2id KDF) and on success
  transitions the app to `Unlocked` with the returned `(Vault, Store)`,
  routing to the account list. `vault_exists` (if a vault appeared
  between `inspect` and `create`) opens an in-dialog destructive
  confirmation explaining that the existing vault will be rotated to
  `vault.bin.bak` and a new one created in its place; on confirm the
  dialog re-runs the create with `paladin_core::create_force(path,
  init)` on `gio::spawn_blocking`, applying the §5 staged-clobber
  semantics. `unsafe_permissions`, `invalid_passphrase`
  (`reason: "confirmation_mismatch"`), `save_not_committed`, and
  `save_durability_unconfirmed` surface inline; the dialog never
  silently fails.
- `UnlockComponent` — passphrase entry, shown only when the vault is encrypted.
  Skipped entirely for plaintext vaults.
- `AccountListComponent` — `gtk::ListView` with a custom row factory.
  Optional issuer grouping: when the per-user `show-section-headers`
  GSettings key (schema `org.tamx.Paladin.Gui`, **default `false`**)
  is enabled, each run of consecutive rows that share an issuer gets
  a small inline header above its first row (issuer text verbatim;
  the literal `Other` for rows whose issuer is `None` / empty). Vault
  insertion order is preserved — rows are never reordered for
  grouping, so a vault that interleaves issuers surfaces multiple
  headers for the same issuer text. The toggle lives in the
  Preferences dialog's "Display" group and is per-user (not
  per-vault); it is GUI-only and is never persisted inside the
  vault payload.
- `AccountRowComponent` — label, code, next code (TOTP), progress (TOTP) /
  "next" button (HOTP), copy button. HOTP rows hide their code until the
  user activates "next" (advances counter and saves); after the shared
  `paladin_core::HOTP_REVEAL_SECS` reveal window (120 seconds) the code
  returns to the hidden state, matching the TUI. Hidden rows show the stored
  next counter; revealed rows show the counter that produced the visible
  code until the reveal expires. Copying a hidden HOTP row is disabled;
  copying during the reveal window copies the visible code and does not
  advance again.
- **Next code column** (GTK `gtk::ColumnView`, header `Next`): inserted
  to the right of the existing `Time` column (the countdown is the
  user's primary urgency cue for the current code, so Next renders
  after it as a quieter "what's coming" affordance). TOTP rows render the
  upcoming 30-second-window code (computed via
  `paladin_core::Vault::totp_next_code(id, now)`) prefixed with `↪ ` and
  the `.dim-label` CSS class applied to the `gtk::Label`, mirroring the
  TUI's dim styling so the cell visually reads as "upcoming, not live."
  HOTP rows leave the cell empty (the `gtk::Label` text is `""` with no
  glyph). Column visibility is controlled by the per-user
  `show-next-code-column` GSettings key (schema `org.tamx.Paladin.Gui`,
  **default `true`**, exposed in the Preferences "Display" group); when
  the key is enabled the column is additionally auto-hidden in
  HOTP-only vaults via the same `column_view::any_totp(&rows)` check that
  gates the `Time` column. Clicking a populated Next cell copies the
  next code through the shared
  `prepare_copy_bytes` / `gdk::Clipboard::set_text` /
  `schedule_copy` pipeline used by the Copy column, and a
  `gtk::Toast` is added to the `adw::ToastOverlay` reading
  `Next code copied, valid in 18s` (seconds = remainder of the current
  window). The clicked cell never advances any counter and is inert on
  HOTP rows. The next-code `Code` is held in a `SecretString` for the
  lifetime of the bind and zeroized when the cell is unbound or the row
  re-renders, matching the §7 secret-handling rules for the current code.
- `AddAccountComponent` — manual fields + paste of an `otpauth://` URI
  (decoded via `paladin_core::parse_otpauth`) + "scan from clipboard
  image" decoded through the core raw-RGBA QR import path. URI and
  manual entries share the same validation, duplicate-detection, and
  `Vault::mutate_and_save` paths. Switching input paths clears hidden
  secret-bearing fields and any pending duplicate override state.
- `RemoveDialog` — confirmation gate before `Vault::remove` + save.
- `EditDialog` — supersedes the v0.2-foundation `RenameDialog` as the
  per-account metadata editor. Three editable `AdwEntryRow` widgets —
  *Label*, *Issuer*, *Icon hint slug* — pre-populated from the focused
  account's `AccountSummary`. Submit routes through
  `Vault::edit_account_metadata` inside `Vault::mutate_and_save`,
  bumps `updated_at`, and surfaces per-field validation errors inline
  without closing. Before the effect dispatches, the dialog calls
  `Vault::find_duplicate_after_edit(account_id, &edit)` and surfaces
  any `Some(other)` collision inline as `duplicate_account` beside
  the offending row without mutating the vault; the user must resolve
  the collision before Save re-enables (no "edit anyway" override).
  The Issuer row exposes an explicit "clear" affordance (an inline
  `gtk::Button` mounted in the `AdwEntryRow` suffix area) that empties
  the row's text in one click; the projection from the resulting
  buffer onto `AccountEdit::issuer` follows the TUI Edit modal's
  what-you-see-is-what-you-save rules — empty-buffer-on-prior-`Some`
  maps to `Some(None)` (clear), buffer byte-equal to the prior issuer
  maps to `None` (leave untouched), and any other non-empty buffer
  maps to `Some(Some(_))`. The Icon hint row's empty / `none` /
  explicit-slug grammar is parsed through
  `paladin_core::parse_icon_hint_token` so the GTK editor matches the
  Add dialog's icon-hint behavior verbatim; the same WYSIWYS layout
  applies (buffer byte-equal to the pre-fill maps to `None`,
  empty-on-prior-`Some` maps to `Some(IconHintInput::Default)` for
  implicit re-derive, `none` to `Clear`, any other slug to `Slug`).
  OTP-affecting fields (`secret`, `algorithm`, `digits`, `kind`,
  `period`, `counter`) are intentionally absent — the dialog body
  carries a short footnote pointing users at remove + re-add for
  secret rotation or OTP parameter changes. The dialog is disabled
  on `UnlockedBusy` per the shared `RenameDialog`-era
  effect-ownership contract.
- **Row context menu and per-row kebab** — every account row exposes
  a context menu with four entries in this order: *Copy code* /
  *Edit…* / *Export QR…* / *Delete…*. The same `gio::MenuModel` is
  bound to the row's kebab `gtk::MenuButton` and to a row-body
  `gtk::GestureClick` configured for the secondary mouse button
  (and to the GNOME-canonical `Menu` key / `Shift+F10` keyboard
  equivalent via a `gtk::ShortcutController` on the row container —
  the GTK4 idiom that replaces the deprecated `popup-menu` signal),
  so right-click, keyboard, and kebab click all converge on the
  same actions. The menu is rendered as a `gtk::PopoverMenu` anchored at
  the pointer for right-click / keyboard events and at the kebab
  button for kebab clicks; only one row popover may be mounted at a
  time, and dismissing it returns focus to the row that raised it.
  Section header rows are non-selectable and do not raise the menu.
  *Copy code* is disabled on hidden HOTP rows (parity with the
  inline copy button via the shared `RowDisplay::copy_enabled`
  projection); *Edit…*, *Export QR…*, and *Delete…* are
  unconditional on account rows. Every menu entry targets a
  `gio::SimpleAction` in the per-row `gio::SimpleActionGroup` —
  `row.copy`, `row.edit`, `row.show-qr`, `row.remove` —
  so the existing `dispatch_row_action` table extends with the new
  `edit` action and the existing `copy` action becomes menu-visible
  alongside the inline copy button.
- `ImportDialog` — `gtk::FileDialog` for the source path, format
  selector (auto-detect or explicit `otpauth` / `aegis` / `paladin` /
  `qr`), on-conflict policy (`skip` / `replace` / `append`), and a
  passphrase prompt for encrypted Paladin bundles gated by
  `classify_paladin_import_precheck`. Reports
  imported/skipped/replaced/appended/warning counts on success.
- `ExportDialog` — format selector (plaintext `otpauth://` URI list
  — newline-separated, Gnome Authenticator–compatible — or encrypted
  Paladin bundle), `gtk::FileDialog` for the
  destination path, overwrite confirmation, twice-entered passphrase
  for the encrypted variant, and an explicit unencrypted-secrets
  warning before plaintext writes. Writes through
  `write_secret_file_atomic` and surfaces the `0600` output path on
  success.
- `ExportQrDialog` — per-account QR export (§4.6). Opened from the
  account row's kebab menu via a new `Show QR…` entry placed
  between `Rename…` and `Remove…`. The dialog opens on a warning
  page rendered verbatim from
  `paladin_core::format_plaintext_qr_export_warning()` with an
  `AdwSwitchRow` ack gate alongside two footer buttons — `Cancel`
  (always sensitive) and `Show QR` (`suggested-action`,
  sensitive only while the ack switch is on). Toggling the ack on
  arms the Show-QR button but does **not** itself render the QR;
  the QR is rendered only after the user presses `Show QR`, so a
  misclick on the ack switch or a closing-window glimpse cannot
  expose the secret. On `Show QR` press the body switches to a
  `gtk::Picture` bound to the PNG bytes returned by
  `Vault::export_qr_png(id, QrRenderOptions::default())` (decoded
  via `gdk::Texture::from_bytes`) plus the account's
  `summary_display_label` caption and four actions:
  *Save as PNG…*, *Save as SVG…*, *Copy image*, and *Done*. Save
  actions open a `gtk::FileDialog::save`, run the same inline
  overwrite gate `ExportDialog` uses, and write through
  `write_secret_file_atomic` (0600) via
  `Vault::export_qr_png` / `Vault::export_qr_svg` on
  `gio::spawn_blocking` (the encoders are sub-millisecond; the
  thread hop exists to keep `write_secret_file_atomic`'s `fsync`
  chain off the main loop). *Copy image* pushes the PNG bytes onto
  `gdk::Clipboard` via `gdk::ContentProvider::for_value` with MIME
  type `image/png`. No auto-clear schedule arms for QR image
  copies — `clipboard.clear_enabled` covers the code-copy path
  only, so QR image copies persist on the clipboard until the user
  replaces or clears them (the dialog body calls out the
  clipboard-history risk in line with §8 bullet 6). The dialog
  never mutates the vault — QR export is read-only — so there is
  no `mutate_and_save` path and no save-rollback to consider. PNG
  bytes, SVG text, and the rendered `gdk::Texture` are dropped
  (and zeroized at the core boundary) when the dialog closes,
  when the ack is toggled off, or when auto-lock fires. The dialog
  is disabled on `UnlockedBusy` for parity with other dialog
  surfaces.
- `PassphraseDialog` — `set` / `change` / `remove` sub-flows mirroring the
  CLI; `set` is enabled only on plaintext vaults, `change` and `remove`
  only on encrypted vaults.
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts.

Auto-lock and clipboard auto-clear behave the same as the TUI, including the
opt-in default and the plaintext-vault auto-lock no-op.
Mutating dialogs use `Vault::mutate_and_save` for the same rollback behavior
as the TUI.

Keyboard shortcuts. The GTK front-end exposes the following bindings; each
(action, accelerator, label) triple is sourced from a single pinned
`format_app_*` helper so the primary menu, the `GtkShortcutsWindow`
contents, and the `gio::Application::set_accels_for_action` wiring stay in
lockstep.

| Shortcut          | Scope              | Action                                                                       |
| ----------------- | ------------------ | ---------------------------------------------------------------------------- |
| `Ctrl+Shift+N`    | Window             | Open the Add Account dialog (mirrors the header-bar `+`; GNOME-HIG "New X"). |
| `Ctrl+,`          | Window             | Open Preferences.                                                            |
| `Ctrl+?`          | Window             | Open the Keyboard Shortcuts window (GNOME-canonical accelerator).            |
| `Ctrl+Q`          | Window             | Quit.                                                                        |
| `/` or `Ctrl+L`   | Window             | Reveal the search bar, focus the entry, and select its contents.             |
| Printable key     | Window             | "Type to search": reveals the search bar and forwards the keystroke.         |
| `Up` / `Down`     | Account list       | Move selection one row (bare arrows; no wrap).                               |
| `Ctrl+K` / `Ctrl+J` | Account list     | Vim-style previous / next row (mirrors `Up` / `Down`).                       |
| `Ctrl+P` / `Ctrl+N` | Account list     | Readline-style previous / next row (mirrors `Up` / `Down`).                  |
| `Up` / `Ctrl+K` / `Ctrl+P` at first row | Account list | Hands focus back to the search entry and re-selects its contents.            |
| `Down` / `Ctrl+J` / `Ctrl+N` | Search entry | Hands focus to the first row of the filtered list.                           |
| `Enter` (or single click on the row body) | TOTP row, or HOTP row with a visible code | Copy the code to the clipboard. The Next, Copy, and kebab cell buttons capture their own clicks, so activating those buttons does not also fire this action. |
| `Enter` (or single click on the row body) | HOTP row with a hidden code | Advance the counter, reveal the new code, then copy it.                      |
| Click on Next cell        | TOTP row (Next column enabled) | Copy the next code; toast reads `Next code copied, valid in Xs`. Inert on HOTP rows. |
| `Ctrl+Shift+C`            | TOTP row (Next column enabled) | Keyboard mirror of clicking the Next cell on the selected row.            |
| `Esc`             | Dialog             | Dismiss the dialog (bare press; no Ctrl / Shift / Alt / Super / Hyper / Meta).|
| `Enter`           | Dialog             | Activate the default button.                                                 |
| `Tab` / `Shift+Tab` | Window or dialog | Standard GTK focus traversal.                                                |

The single-modifier `Ctrl+N` slot is reserved for readline-style row
navigation, which is why Add uses `Ctrl+Shift+N`. `Ctrl+K` is intentionally
not a focus-search accelerator — it doubles as the vim-style "move up"
mirror inside the list. Bare `j` / `k` / `n` / `p` keep bubbling so the
type-to-search path keeps working, and arrow keys combined with `Ctrl`
(`Ctrl+Up` / `Ctrl+Down`) are left to the platform. All other GTK / Adwaita
affordances apply unchanged.

Icons: `AccountRowComponent` resolves `AccountSummary.icon_hint` against the
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
   output `0600`. Encrypted exports also refuse overwrite and create output
   `0600`. **Per-account QR exports** (§4.6) carry a parallel warning
   sourced from `paladin_core::format_plaintext_qr_export_warning()` and
   ride the same `write_secret_file_atomic` + `--force` / inline-gate path,
   because a QR is a plaintext encoding of an account secret — anyone who
   can see or photograph it can clone the OTP. QR export is also
   *read-only* (HOTP counters are encoded at their current value and
   never advanced) so the original device retains code parity with a
   second device that scanned the QR.
9. **Imports are fully validated.** Each importer parses into validated
   account values without trusting the source's claimed structure — secrets are
   length-checked (rejected if shorter than 10 bytes / 80 bits or longer
   than 1024 bytes; entries between 10 and 15 bytes inclusive — under
   the RFC 4226 §4 minimum of 16 bytes / 128 bits — are accepted with a
   per-entry warning), base32 is validated, algorithms must be in our
   enum, and OTP parameters must pass the §4.1 validation table.
10. **No telemetry, no network calls.** Enforced by code review and tests;
    `cargo deny` covers dependency license/advisory policy, not runtime
    network behavior. The deny list bans async runtimes and network stacks
    (`tokio`, `reqwest`, `hyper`, …) from `paladin-core`, `paladin-cli`, and
    `paladin-tui`, asserted by the lockfile-subtree guard in
    `crates/paladin-core/tests/no_network.rs`. `paladin-gtk` is granted a
    single carve-out: `tokio` is permitted when it reaches the lockfile
    transitively through `relm4` (its GUI framework, which uses `tokio`'s
    mpsc channels as a structured-concurrency primitive). GTK's main loop
    remains the executor and `gio::spawn_blocking` runs the long work, so
    no sockets are opened. The carve-out is locked down at three layers:
    (a) `paladin-core` source / manifest / lockfile-subtree guards keep the
    security-sensitive subtree tokio-free; (b) `deny.toml` admits `tokio`
    only when its direct wrapper is `relm4`; and (c) a source-level guard
    in `paladin-gtk` forbids direct `use tokio` / `tokio::` references so
    the GUI never reaches around `relm4` to use `tokio` as a runtime.
11. **Reproducible builds.** Pin `rust-toolchain.toml`. Lock all deps.
12. **Threat model documented separately** in `SECURITY.md` before v1.

> **Approved 2026-05-04.** All decisions in §4.3, §4.4, §4.5, §4.6, and §8
> are locked in for v0.1. Tests in `paladin-core` will assert round-trip
> properties for both modes, tamper detection, file-permission enforcement,
> and passphrase-transition commit-point behavior so regressions are caught
> in CI.

## 9. Key dependencies (proposed)

| Crate                                  | Use                                                                                                                               |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `ratatui`                              | TUI rendering                                                                                                                     |
| `crossterm`                            | TUI backend                                                                                                                       |
| `tui-input`                            | TUI text input widget                                                                                                             |
| `relm4`, `gtk4`, `gdk4`, `libadwaita`  | GUI (v0.2) — Adwaita widgets, HIG dialogs, toasts, clipboard                                                                      |
| `clap`                                 | CLI parsing                                                                                                                       |
| `serde`, `serde_json`, `bincode` (v2)  | Vault and JSON I/O                                                                                                                |
| `hmac`, `sha1`, `sha2`                 | TOTP / HOTP primitives                                                                                                            |
| `chacha20poly1305`                     | AEAD (XChaCha20-Poly1305)                                                                                                         |
| `argon2`                               | KDF                                                                                                                               |
| `secrecy`, `zeroize`                   | Memory hygiene                                                                                                                    |
| `rpassword`                            | CLI passphrase prompt                                                                                                             |
| `arboard`                              | CLI / TUI clipboard where needed; GUI uses GDK clipboard                                                                          |
| `rqrr`, `image`                        | QR decode from files/buffers                                                                                                      |
| `qrcode`                               | Per-account QR export (§4.6) — PNG / SVG / ANSI rendering inside `paladin-core` so front ends stay thin                          |
| `directories`                          | XDG / platform paths                                                                                                              |
| `thiserror`, `anyhow`                  | Error types                                                                                                                       |
| `base32`                               | Secret encoding                                                                                                                   |
| `url`                                  | `otpauth://` URI parsing                                                                                                          |
| `uuid`                                 | `AccountId` (UUIDv4) generation and display                                                                                       |
| `getrandom`                            | CSPRNG source for §4.4 salts and nonces; pinned in `paladin-core` so the random source does not drift across transitive minor versions |

`paladin-core` also pulls in dev-only dependencies that are not part of
the runtime supply chain: `proptest` for property tests against the
`otpauth://` parser and base32 secret decoding, `trybuild` for `Secret`
non-`Debug` compile-fail coverage, and `tempfile` for storage and
permission fixtures. Binary crates additionally use `assert_cmd` and
`insta` (§10).

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
  - Bincode encoding determinism: the same `VaultPayload` value encodes
    to bit-identical bytes across two encodes; a fixture vault matches
    a committed expected byte string.
  - Vault save → reopen preserves account insertion order in plaintext
    and encrypted modes (pins `VaultPayload.accounts` as an ordered
    `Vec<Account>`).
  - Header endianness fixture: encrypted vaults written with default
    Argon2 params produce exact little-endian header bytes regardless
    of host byte order.
  - Custom `Argon2Params` round-trip via the encrypted header — several
    in-range `(m_kib, t, p)` triples survive write → header → read
    bit-identically across `create` / `create_force` / `set_passphrase`
    / `change_passphrase` / `export::encrypted`.
  - Tamper detection on encrypted vault: flip a ciphertext byte → fail;
    flip any byte in the AAD-bound header (`format_ver`, `mode`, `kdf_id`,
    Argon2 params, `salt`, `aead_id`, `nonce`) → fail.
  - Sequential encrypted saves of identical content produce
    byte-distinct ciphertext-and-tag regions while both files re-open
    to the byte-identical `VaultPayload`, pinning per-save fresh nonce
    as a positive assertion.
  - Published crypto known-answer vectors: Argon2id derives the expected
    32-byte key for a fixed passphrase / salt / parameter fixture, and
    XChaCha20-Poly1305 encrypts/decrypts a fixed key / nonce / AAD /
    plaintext fixture to the expected ciphertext and tag. The expected bytes
    are committed fixtures from named external references with source and
    license notes recorded beside the fixture, not values recomputed by the
    implementation under test.
  - Algorithm-choice locks: the same KAT inputs run through Argon2i /
    Argon2d produce keys distinct from the committed Argon2id key, and
    the same inputs run through ChaCha20-Poly1305 (12-byte nonce IETF
    construct) produce ciphertext and tag distinct from the committed
    XChaCha20-Poly1305 fixture, so a silent swap of variant or AEAD
    construct fails the test instead of regressing the format.
  - AEAD output shape: encrypted-body length equals `plaintext_len + 16`
    (Poly1305 tag) and the in-header `nonce` slot is exactly 24 bytes.
  - Pre-AEAD plaintext-payload zeroization on encrypt and post-AEAD
    plaintext-payload zeroization on decrypt (success and decode failure)
    proven byte-precisely, matching the existing zeroization posture for
    `Secret`, mutate-and-save rollback snapshots, cached AEAD keys, and
    retained passphrases.
  - CSPRNG failure surfaces as `io_error` with
    `operation: "csprng_read"` on every encrypted-write site without a
    partial vault file on disk; Argon2id allocation failure surfaces as
    `io_error` with `operation: "kdf_allocation"` on encrypted read and
    write paths without panic or partial write.
  - Symbolic-link rejection on `open` / `create` / `create_force` for
    `vault.bin`, `vault.bin.bak`, and the parent data directory using
    `symlink_metadata` so the probe never follows the link.
  - Argon2 parameter bounds reject headers outside the v0.1 limits before
    KDF work begins.
  - Argon2 custom write params: defaults, accepted in-range values, rejected
    out-of-range values, and headers written by encrypted create /
    `create_force` / passphrase set/change / encrypted export.
  - Fresh crypto material: repeated encrypted creates, `create_force`
    operations, passphrase transitions, and encrypted exports with identical
    logical inputs produce fresh salts and nonces where §4.4 / §4.5 require
    them, while regular encrypted saves preserve salt and rotate only nonce.
  - No-network guard: a source-level `paladin-core` test scans the core
    production source tree (`src/`) and manifest for direct network API
    spellings such as `std::net`, `TcpStream`, `UdpSocket`,
    `ToSocketAddrs`, `tokio`, `reqwest`, and `hyper`, and a metadata
    fixture checks resolved runtime dependencies against the `cargo deny`
    network-stack denylist.
  - File-permission enforcement (`0600` on primary, backup, and temp files;
    `0700` on dir) post-save and during staged writes, plus rejection of
    unsafe existing primary/backup/directory paths with `unsafe_permissions`.
  - `default_vault_path()` uses `ProjectDirs::from("", "", "paladin")`,
    resolves the §4.3 data path, and reports `io_error` with
    `operation: "resolve_default_vault_path"` if the platform data path
    cannot be resolved.
  - Core `io_error.operation` strings match the stable §5 table.
  - `write_secret_file_atomic` export writes: `0600`, same-directory
    tempfile, pre-rename `save_not_committed`, post-rename
    `save_durability_unconfirmed`, and no `.bak` rotation.
  - `Vault::mutate_and_save` rollback on mutation closure failure and
    pre-commit save failure, plus durability-unconfirmed state retention.
    Cross-field rollback covers both accounts and `VaultSettings`: a
    closure that mutates both then errors restores both to the
    pre-mutation snapshot.
  - Passphrase set/change/remove transitions, including pre-commit rollback
    and durability-unconfirmed failures after the primary-file commit point.
  - HOTP counter advances on `hotp_advance`, not on `hotp_peek` or
    `totp_code`; `hotp_advance` also updates `updated_at` and persists the
    new counter to disk before returning. Account-ID methods return stable
    `invalid_state` operation/state pairs for missing accounts and wrong OTP
    kind.
  - `Vault::find_duplicate` detects exact `(secret, issuer, label)`
    collisions for single-entry add flows without exposing secret bytes to
    presentation crates.
  - Account validation rejects out-of-range digits, TOTP periods, HOTP
    counter overflow, empty labels, malformed icon hints, mismatched
    otpauth issuers, and invalid timestamps; short secrets in the 10-15
    byte range produce `short_secret` warnings. Manual `AccountInput`
    tests cover the `AccountKindInput` selector plus period/counter
    defaults and kind-specific rejection, and the `IconHintInput`
    `Default` / `Clear` / `Slug` branches.
  - Zeroize-on-drop assertions for `Secret` and `SecretString`.
  - Importers: Aegis plaintext TOTP/HOTP mapping, unsupported Aegis entry
    type rejection, our own export round-trip with fresh destination IDs,
    plaintext Paladin vault rejection, encrypted-Aegis rejection, and QR
    image decode (single-QR and multi-QR image files plus raw RGBA buffers,
    including the `QR_RGBA_MAX_BYTES` rejection path)
    — fixture files in `tests/fixtures/`. Also covers the "zero accounts"
    rejection path (empty JSON array, blank otpauth file, empty Aegis
    `entries`, image with no decodable QRs). The `import::from_file` /
    `from_bytes` facade is tested for auto-detect, forced-format dispatch,
    unknown/invalid dispatch, `unsupported_import_format.format` semantics,
    missing Paladin bundle passphrases, and encoded-image QR bytes.
  - `classify_paladin_import_precheck` covers auto-detect and forced-format
    cases so CLI / TUI / GUI import dialogs share the same decision about
    whether to prompt for a Paladin bundle passphrase, reject a plaintext or
    malformed Paladin header, or continue through `import::from_file`.
  - QR export (§4.6): `Vault::export_qr_png` / `export_qr_svg` /
    `export_qr_ansi` and the parallel `export::qr_*` free functions
    encode the same `otpauth://` URI that `export::otpauth_list`
    emits for that account. PNG output is round-tripped through
    `rqrr` and asserted equal to the URI; SVG output is asserted
    well-formed (starts with `<?xml` / `<svg` and passes an XML
    well-formedness check — the SVG path catches encoder regressions
    even though `rqrr` cannot decode vector graphics);
    Unicode half-block output is asserted to consist only of the
    `Dense1x2` glyph alphabet (`' '`, `'▀'`, `'▄'`, `'█'`, `'\n'`).
    Render operations are pure reads: the HOTP counter is not
    advanced, `updated_at` is not bumped, and the on-disk vault is
    byte-identical before and after every render. `QrRenderOptions`
    validation rejects `module_size_px` outside
    `QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX` with
    `validation_error` (`field: "qr_render"`). Account-not-found
    returns `invalid_state` with the matching `operation`. The
    returned `Zeroizing<Vec<u8>>` / `Zeroizing<String>` zeroizes
    its inner bytes on drop (asserted byte-precisely, matching the
    existing zeroization posture). `format_plaintext_qr_export_warning`
    returns non-empty static text.
- **Property tests** (`proptest`) for the URI parser and base32 secret
  decoding.
- **Integration tests** for each shipped binary using `assert_cmd` (CLI)
  and golden-snapshot tests (`insta`) for TUI rendering.
  Binary integration tests that need process-level filesystem failure
  coverage enable `paladin-core`'s off-by-default
  `test-fault-injection` cargo feature. Under that feature, core exposes
  a test-only `Store` constructor and shared atomic-write fault hook that
  honor `PALADIN_FAULT_INJECT=pre_commit|post_commit`; the two fault modes
  exercise `save_not_committed` before the primary/final rename and
  `save_durability_unconfirmed` after the parent-directory `fsync` fails.
  The hook applies uniformly to regular saves, `create_force`, passphrase
  transitions, and `write_secret_file_atomic`, is not linked into
  production builds, and is excluded from the stable §4.7 API surface.
  - CLI `--json` success/error shapes, warning payloads, durability error
    fields, help/version JSON success shapes, HOTP post-advance account
    summaries, clipboard-write failure behavior, passphrase no-TTY /
    confirmation-mismatch failures, export overwrite guards, Argon2id
    custom-cost flags for encrypted writes (including `init` validating
    before the first prompt and accepting-but-ignoring valid custom params on
    the plaintext path), and export writer durability failures.
  - CLI `add` input modes, mutual-exclusion errors, duplicate-account
    rejection, and `--allow-duplicate`.
  - CLI query resolution, including `str::to_lowercase()` matching,
    no-normalization Unicode behavior, and `id:` prefix validation.
  - CLI `qr <query>` (§4.6): single-match cardinality (multiple
    matches exit non-zero with the candidate list, no-match exits
    `no_match`), HOTP counter is not advanced across a render,
    `--out <path>` writes PNG / SVG bytes via
    `write_secret_file_atomic` (0600, `--force` overwrite gate),
    stdout-default renders ANSI text, `--format=png|svg` without
    `--out` rejects at parse time (`field: "out"`,
    `reason: "required_for_binary_format"`), `--json` without
    `--out` rejects at parse time (`field: "out"`,
    `reason: "required_under_json"`),
    `--module-size-px` outside the §4.7 bounds returns
    `validation_error` (`field: "module_size_px"`), and the JSON
    success shape carries `written` / `format` / `account`.
  - TUI HOTP copy behavior: hidden rows do not copy, revealed rows copy
    without advancing again, and revealed rows display the counter that
    produced the visible code rather than the stored post-advance counter.
  - TUI create-vault state: covers ChooseMode toggling, advancing to
    `EnterPassphrase` on Encrypted vs `ConfirmPlaintext` on Plaintext,
    passphrase + confirmation matching, plaintext-warning confirmation,
    `Ctrl-C` / `Esc` cancellation with zeroized passphrase buffers, on-
    success transition to `Unlocked` with an empty list, and inline
    error retention on `Store::create` / `Vault::save` failures.
  - GUI missing-vault state: opens `InitDialog`; covers plaintext
    (both passphrase fields empty + unencrypted-storage warning) and encrypted
    (twice-confirm) creation, `vault_exists` triggering the in-dialog
    `create_force` clobber confirmation (with `vault.bin` rotated to
    `vault.bin.bak`), `unsafe_permissions` rendered via
    `format_unsafe_permissions`, and pre-commit /
    durability-unconfirmed save errors. v0.2.
  - GUI rename + add-via-URI: rename round-trip via `Vault::rename`,
    paste-`otpauth://`-URI Add route through
    `paladin_core::parse_otpauth` with shared duplicate / validation
    / `mutate_and_save` rules, and inline rejection of malformed URIs
    and validation failures. v0.2.
  - TUI add-via-URI + rename: paste-`otpauth://`-URI Add route through
    `paladin_core::parse_otpauth` with the same duplicate /
    validation behavior as manual mode; rename modal round-trips
    through `Vault::rename`, including unchanged labels so `updated_at`
    matches CLI behavior, with prior-label restore on `save_not_committed`.
  - TUI QR modal (§6, §4.6): `Q` on the focused row opens the modal
    on the warning page; rendering / save actions are disabled until
    the user acks the warning; ANSI body matches `Vault::export_qr_ansi`
    output; Save-as-PNG / Save-as-SVG actions write through
    `write_secret_file_atomic` with the inline overwrite gate; the
    HOTP counter and `updated_at` are unchanged after the modal opens
    and closes; `Esc` and auto-lock drop the rendered buffers.
  - GUI QR dialog (§7, §4.6): `Show QR…` kebab entry opens
    `ExportQrDialog`; the dialog opens on the warning page with the
    ack `AdwSwitchRow` off, the `Show QR` button insensitive, and
    the QR `gtk::Picture` hidden; toggling ack on enables the
    `Show QR` button but does not itself render; pressing
    `Show QR` renders the QR from `Vault::export_qr_png` bytes via
    `gdk::Texture::from_bytes`; Save-as-PNG / Save-as-SVG run on
    `gio::spawn_blocking`, surface the resulting 0600 path, and apply
    the inline overwrite gate; `Copy image` pushes PNG bytes through
    `gdk::ContentProvider::for_value` with MIME `image/png`; the
    dialog never enters `Vault::mutate_and_save` (QR export is
    read-only); dialog close, ack-off, and auto-lock drop the
    rendered bytes. v0.2.
  - Plaintext-vault auto-lock is a no-op in TUI state handling now, with
    GUI parity when the GUI ships.
- **CI:** `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test --all`, `cargo deny check`, `cargo audit`.

## 11. Packaging & distribution

Linux-only in v0.1, consistent with §2. Each shipped front-end is published in
four artifact formats: a Debian package (`.deb`), an RPM package (`.rpm`),
a Flatpak, and an AppImage. v0.1 ships artifacts for `paladin` (CLI) and
`paladin-tui`; `paladin-gtk` joins the matrix in v0.2 alongside the GUI.

### 11.1 Artifact matrix

| Front-end       | `.deb` | `.rpm` | Flatpak | AppImage | Ships in |
| --------------- | :----: | :----: | :-----: | :------: | -------- |
| `paladin` (CLI) |   ✓    |   ✓    |    ✓    |    ✓     | v0.1     |
| `paladin-tui`   |   ✓    |   ✓    |    ✓    |    ✓     | v0.1     |
| `paladin-gtk`   |   ✓    |   ✓    |    ✓    |    ✓     | v0.2     |

All artifacts are `x86_64` in v0.1; `aarch64` is added when CI gains an
`aarch64` runner. macOS and Windows packaging stays out of scope (§2).

### 11.2 Repository layout

Packaging metadata lives at the workspace root, parallel to `crates/`:

```
paladin/
├── crates/
├── packaging/
│   ├── deb/          # nfpm config, one file per front-end
│   ├── rpm/          # nfpm config, one file per front-end
│   ├── flatpak/      # one manifest per front-end
│   └── appimage/     # AppDir recipes + linuxdeploy invocations
└── xtask/            # `cargo xtask package` orchestrates all four formats
```

`xtask` owns the orchestration so a release engineer runs a single
`cargo xtask package --frontend <name>` per front-end and gets all four
artifacts side by side.

### 11.3 Native packages (`.deb` and `.rpm`)

- **Tooling.** [`nfpm`](https://nfpm.goreleaser.com/) is the unified
  producer for both formats so per-front-end metadata is written once.
- **Per-front-end packages.** One package per front-end keeps install size
  small for headless servers (CLI) and minimal desktop installs (TUI):
  - `paladin` — installs `/usr/bin/paladin` and a man page at
    `/usr/share/man/man1/paladin.1.gz`.
  - `paladin-tui` — installs `/usr/bin/paladin-tui` and
    `/usr/share/man/man1/paladin-tui.1.gz`.
  - `paladin-gtk` *(v0.2)* — installs `/usr/bin/paladin-gtk`, a desktop
    entry at `/usr/share/applications/`, AppStream metadata under
    `/usr/share/metainfo/`, and the hicolor app icon set under
    `/usr/share/icons/hicolor/`.
- **Dependencies.**
  - `paladin` and `paladin-tui` depend only on `libc6` (Debian) /
    `glibc` (Fedora). The Rust binaries are otherwise statically linked
    where possible — no OpenSSL, no libsqlite, no libcurl.
  - `paladin-gtk` declares `libgtk-4-1 (>= 4.16)` and
    `libadwaita-1-0 (>= 1.6)` on Debian, with the matching `gtk4` /
    `libadwaita` packages on Fedora. The 1.6 floor is set so the GUI
    uses the current Adwaita widget set (`AdwAlertDialog` from
    libadwaita 1.5; `AdwAboutDialog` from libadwaita 1.6) without a
    deprecated-widget compatibility shim; distributions whose stable
    channel ships older GTK / libadwaita cannot install
    `paladin-gtk` until their baseline rises.
- **Maintainer scripts.** Narrowly scoped: `paladin-gtk` ships a
  `postinstall` and a `postremove` scriptlet that refresh
  `/usr/share/applications/mimeinfo.cache` (via
  `update-desktop-database`) and `/usr/share/icons/hicolor/icon-theme.cache`
  (via `gtk-update-icon-cache`) so a freshly installed `.deb` /
  `.rpm` desktop entry and application icon appear in GNOME Shell,
  KDE, XFCE, and other freedesktop-aware launchers without requiring
  the user to log out and back in. The scripts touch only
  system-owned caches under `/usr/share`; the vault under
  `$XDG_DATA_HOME/paladin/` is never created or altered by package
  install or removal. Identical script bodies ship on `.deb` and
  `.rpm` (single source of truth at
  `packaging/scripts/paladin-gtk-postinstall.sh` and
  `packaging/scripts/paladin-gtk-postremove.sh`) so cross-format
  drift is impossible. `paladin` (CLI) and `paladin-tui` ship no
  maintainer scripts — they install no desktop entries or hicolor
  icons, so no cache rebuild is required.
- **Conflicts / replaces.** The three packages coexist; they do not
  shadow each other's binaries, and a user can install any subset.
- **License metadata.** Every control file declares
  `License: AGPL-3.0-or-later` (Debian `Copyright`, RPM spec `License`),
  matching §13 of this document.

### 11.4 Flatpak

- **App IDs** (reverse-DNS):
  `org.tamx.Paladin.Cli`, `org.tamx.Paladin.Tui`,
  `org.tamx.Paladin.Gui`. Derived from the project domain
  `paladin.tamx.org`; the homepage URL `https://paladin.tamx.org`
  is also the value of the `homepage` Cargo workspace metadata field.
  The repository URL `https://github.com/FreedomBen/paladin` is the value
  of the `repository` Cargo workspace metadata field.
- **Runtimes.**
  - CLI and TUI: `org.freedesktop.Platform` 23.08 (small, no GUI bits).
  - GUI: `org.gnome.Platform` 47 with the matching SDK (bundles
    GTK 4.16 and libadwaita 1.6, matching the §11.3 packaging
    baseline).
- **Sandbox permissions.** No `--share=network` for any front-end (§8 / §2).
  - CLI and TUI: filesystem access scoped to `xdg-data/paladin:create`
    (vault) and `xdg-config/paladin:create` (settings). Both inherit the
    host terminal's stdio when launched via `flatpak run`. Because
    `paladin copy` and the TUI clipboard copy / QR-from-clipboard flows are
    in scope for v0.1, both CLI and TUI Flatpaks also grant
    `--socket=wayland`, `--socket=fallback-x11`, and `--share=ipc` for the
    display clipboard path. They do not request `--socket=session-bus` or
    `--socket=system-bus`; Flatpak's filtered portal bus access remains the
    default.
  - GUI: the same vault and settings paths plus `--socket=wayland`,
    `--socket=fallback-x11`, and `--share=ipc` for GTK display and
    clipboard integration.
- **Build.** `flatpak-builder` consuming
  `packaging/flatpak/<frontend>.yml`. Source is pulled from the tagged
  release tarball with vendored Cargo dependencies (see §11.6) so
  Flathub builds reproducibly without network access at build time.
- **Publication.** Flathub. Each front-end is its own Flathub submission
  with its own review thread and update cadence.

### 11.5 AppImage

- **Tooling.** [`linuxdeploy`](https://github.com/linuxdeploy/linuxdeploy)
  assembles the AppDir; `appimagetool` seals it. The
  `linuxdeploy-plugin-gtk` is used for `paladin-gtk` only.
- **Naming.** `paladin-<version>-x86_64.AppImage`,
  `paladin-tui-<version>-x86_64.AppImage`,
  `paladin-gtk-<version>-x86_64.AppImage`.
- **Update channel.** Each AppImage embeds `AppImageUpdate` `zsync`
  metadata pointing at the GitHub Releases feed so users update in place
  without reinstalling.
- **CLI / TUI AppImages.** Unusual but supported: the AppImage is invoked
  exactly like the bare binary, and the embedded `AppRun` forwards argv
  unchanged. Headless users on FUSE-less hosts can run them with
  `--appimage-extract-and-run`.

### 11.6 Build, signing, and publication

- **Reproducible builds.** Toolchain pinned via `rust-toolchain.toml`,
  `SOURCE_DATE_EPOCH` exported from the release tag, `cargo build
  --locked`, and a frozen vendored dependency tree (`cargo vendor` into
  `vendor/`). Re-running the release pipeline on a clean checkout of the
  same tag must produce byte-identical `.deb`, `.rpm`, and AppImage
  artifacts; Flatpak reproducibility is delegated to Flathub's pipeline.
- **Signatures.** All GitHub-hosted artifacts (`.deb`, `.rpm`, AppImage)
  are signed with [`minisign`](https://jedisct1.github.io/minisign/);
  the signature plus the project's published public key are uploaded
  alongside each artifact. Flatpak releases inherit Flathub's signing,
  and we ship an SHA-256 manifest covering the source tarball Flathub
  consumes.
- **CI.** A tag-driven release workflow runs the full §10 gate
  (`cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test --all`, `cargo deny check`, `cargo audit`), then invokes
  `cargo xtask package --frontend <name>` for each front-end shipped in
  that release. Artifact upload to GitHub Releases is scripted; Flathub
  publication is a manual review step after the GitHub release lands.
  CI-installed cargo subcommands are pinned in `xtask/dev-tools.toml`;
  v0.1 pins `cargo-public-api` there for the core public API snapshot gate.

## 12. Roadmap & checklist

### Milestone 0 — Skeleton *(v0.1)*
- [ ] Initialize workspace `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`.
- [ ] Create the `paladin-core` crate scaffold (binary crates are added in
  Milestones 4 / 5 / 7 alongside the work that owns them).
- [ ] CI: fmt + clippy + test on Linux.
- [ ] `README.md` with build instructions.

### Milestone 1 — Core OTP + storage *(v0.1)*
- [ ] `Account`, non-secret `AccountSummary`, `Secret`, `Algorithm`,
  `OtpKind`, `Vault`, `VaultSettings`, and shared settings/query helper
  types with `Zeroize` where secret-bearing.
- [ ] Shared `Account` validation for labels, issuers, secrets, OTP parameters, timestamps, and icon hints.
- [ ] Shared account display/search/query helpers and validation-warning
  formatting used by CLI/TUI/GUI.
- [ ] RFC 6238 (TOTP) implementation + Appendix B vectors.
- [ ] RFC 4226 (HOTP) implementation + Appendix D vectors.
- [ ] `otpauth://` parser + base32 secret handling (TOTP and HOTP URIs).
- [ ] **Plaintext** vault format with atomic writes + `0600` file / `0700` parent-dir enforcement.
- [ ] **Encrypted** vault format: Argon2id + AEAD with header versioning, KDF parameter bounds, and custom encrypted-write costs.
- [ ] One-generation `.bak` preserved across all writes.
- [ ] Tamper-detection and round-trip tests for both modes.

### Milestone 2 — Passphrase management *(v0.1)*
- [ ] `set_passphrase`, `change_passphrase`, `remove_passphrase` on `Vault`, with custom Argon2id params for encrypted target states.
- [ ] Atomic transition with pre-commit rollback and durability-unconfirmed
  handling for post-commit failures.
- [ ] Tests covering all three transitions, pre-commit rollback, and
  durability-unconfirmed post-commit failures.

### Milestone 3 — Import / Export *(v0.1)*
- [ ] Plaintext export (newline-separated `otpauth://` URI list, Gnome Authenticator–compatible) with overwrite guard + `0600`.
- [ ] Encrypted export bundle (Paladin format) with overwrite guard + `0600`.
- [ ] Shared `write_secret_file_atomic` export writer used by CLI/TUI/GUI.
- [ ] Importer: `otpauth://` URIs (single + list).
- [ ] Importer: Paladin encrypted bundle; plaintext Paladin vault files return an unsupported-format error.
- [ ] Importer: Aegis plaintext export.
- [ ] Importer: QR image files and raw RGBA clipboard buffers (`rqrr`).
- [ ] Auto-detect with explicit `--format` override.
- [ ] Fixture-based tests for each importer.

### Milestone 4 — CLI *(v0.1)*
- [ ] Add the `paladin-cli` crate to the workspace.
- [ ] `init` (with optional passphrase), `add`, `list`, `show`, `peek`, `remove`, `rename`.
- [ ] `copy` (clipboard copy only; no CLI auto-clear).
- [ ] `passphrase set / change / remove`.
- [ ] `export --plaintext / --encrypted`, `import [--format]`.
- [ ] `settings get / set`.
- [ ] `--json` output for scripting using the schemas in §5, including
  JSON envelopes for syntax/usage failures when `paladin` receives
  `--json`.
- [ ] `assert_cmd` integration tests.

### Milestone 5 — TUI *(v0.1)*
- [ ] Add the `paladin-tui` crate to the workspace.
- [ ] Single-screen list view with TOTP gauges and HOTP "advance" key.
- [ ] Search/filter input.
- [ ] Add / remove / rename / import / export / passphrase / settings modals; Add covers manual fields, `otpauth://` URI paste, and QR scan from clipboard image.
- [ ] Conditional unlock screen (only when vault is encrypted).
- [ ] In-app create-vault flow on `VaultStatus::Missing` (two-step
  wizard: choose Encrypted/Plaintext, then passphrase + confirmation
  or plaintext confirmation; defaults-only Argon2id; success
  transitions to `Unlocked`).
- [ ] Opt-in auto-lock and clipboard-clear honoring vault settings, with plaintext auto-lock as a no-op.
- [ ] HOTP reveal/copy behavior: hidden rows do not copy; revealed rows copy
  without advancing again and show the counter used.
- [ ] Snapshot tests for rendering.

### Milestone 6 — Hardening & release *(v0.1)*
- [ ] `SECURITY.md` with threat model covering both vault modes.
- [ ] `cargo deny` + `cargo audit` clean in CI.
- [ ] Reproducible release builds; signed checksums (§11.6).
- [ ] `packaging/` tree (`deb/`, `rpm/`, `flatpak/`, `appimage/`) and
  `cargo xtask package` orchestration per §11.2.
- [ ] `.deb`, `.rpm`, Flatpak, and AppImage artifacts for `paladin` and
  `paladin-tui`, signed with `minisign` and uploaded to GitHub Releases
  per §11.3–§11.6.
- [ ] Flathub submissions filed for the `paladin` and `paladin-tui`
  Flatpaks (§11.4).
- [ ] v0.1.0 tag.

### Milestone 7 — GUI *(v0.2)*
- [ ] Add the `paladin-gtk` crate to the workspace (placeholder for v0.2 work).
- [ ] Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
  Rename / Import / Export / ExportQr / Passphrase / Settings /
  StartupError).
- [ ] In-app vault initialization (`InitDialog`) for missing vaults —
  plaintext + encrypted paths, explicit confirmation, in-dialog
  `create_force` clobber confirmation when a vault already exists.
- [ ] In-app account rename (`RenameDialog`) and Add-from-`otpauth://`-URI
  paste path (parity with CLI `rename` and `add --uri`).
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Clipboard + auto-lock parity with TUI (opt-in).
- [ ] Per-account QR export (`ExportQrDialog`) reachable from the row
  kebab menu — warning-ack gate, on-screen render via
  `Vault::export_qr_png`, Save-as-PNG / Save-as-SVG via
  `Vault::export_qr_png` / `Vault::export_qr_svg` +
  `write_secret_file_atomic`, Copy image to GDK clipboard. Read-only:
  HOTP counters never advance.
- [ ] Linux desktop file + icon (consumed by the §11.3 native packages
  and the §11.4 Flatpak manifest).
- [x] `.deb`, `.rpm`, Flatpak, and AppImage artifacts for `paladin-gtk`,
  signed and published per §11.3–§11.6; Flathub submission filed.
- [ ] Manual test plan documented.

### Milestone 8 — Cross-front-end QR export *(v0.2)*
- [x] `paladin-core` QR rendering API: `QrRenderOptions`,
  `Vault::export_qr_png` / `export_qr_svg` / `export_qr_ansi`,
  free functions `export::qr_png` / `qr_svg` / `qr_ansi`,
  `format_plaintext_qr_export_warning`, and the
  `QR_MODULE_SIZE_PX_*` constants. `qrcode` promoted from optional /
  dev-only to a regular dependency of `paladin-core`; the public-api
  snapshot is updated to match.
- [x] CLI `paladin qr <query>` command with `--out` / `--format` /
  `--module-size-px` / `--force` flags, ANSI stdout default,
  parse-time rejection of binary formats without `--out`, and the
  JSON `{ "written", "format", "account" }` success shape gated on
  `--out` per §5.
- [x] TUI QR modal opened with `Q` on the focused row — warning-ack
  gate, ANSI body from `Vault::export_qr_ansi`, Save-as-PNG /
  Save-as-SVG via `write_secret_file_atomic` with the inline
  overwrite gate; auto-lock and `Esc` drop the rendered buffers.
- [ ] GTK `ExportQrDialog` per Milestone 7's bullet.
- [ ] Tests covering core rendering, CLI command, TUI modal, GUI
  dialog, and the read-only invariant (HOTP counters and `updated_at`
  are unchanged across every render path).

### Milestone 9 — Per-account metadata edit *(v0.2)*
- [ ] `paladin-core`: `AccountEdit` struct, `Vault::edit_account_metadata`,
  and `validate_account_edit` per §4.7. Tests cover label-only /
  issuer-only / icon-hint-only / multi-field paths, the "leave
  untouched" tri-state on `issuer`, validation rejection for each
  field, `updated_at` bump on no-op-but-non-empty submits, empty
  `AccountEdit` rejection (`validation_error` (`field: "edit"`,
  `reason: "empty"`)), and `mutate_and_save` pre-commit rollback
  preserving the prior `Account` byte-for-byte.
- [ ] CLI `paladin edit <query>` with the flag grammar per §5 and the
  success / error JSON shapes. Tests in `tests/cli_edit.rs` covering
  each editable field independently, the `--no-issuer` /
  `--no-icon-hint` clear paths, the parse-time
  mutually-exclusive-flag rejection, the no-flag rejection, the
  single-match cardinality, and the `paladin rename` shorthand
  routing through the same core mutator.
- [ ] TUI Edit modal opened with `Shift+E`: three pre-populated text
  rows, inline validation, save-effect plumbing parity with the
  Rename modal. Snapshot test for the modal layout; logic tests for
  the state machine.
- [ ] GTK `EditDialog` superseding `RenameDialog`: three editable
  rows (Label / Issuer + clear button / Icon hint slug), inline
  validation, save-effect plumbing per §7. Row context menu (and
  `Menu` / `Shift+F10` keyboard equivalent) bound to the same
  `gio::MenuModel` as the per-row kebab, four entries in order
  *Copy code* / *Edit…* / *Export QR…* / *Delete…*. Pure-logic
  tests for the new menu model, the `AccountEdit` projection, the
  per-field clear/leave-untouched semantics, and the right-click
  gesture / popover-menu wiring; integration test for the menu /
  dialog round-trip and for the single-popover-at-a-time invariant.

## 13. Open questions

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
  already revealed HOTP code and never advances a second time; during the
  reveal window, TUI/GUI rows show the counter that produced the visible
  code, then return to the stored next counter when hidden.
- Both plaintext and encrypted CLI exports refuse overwrite without `--force`
  and create output `0600`.
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

**Decided during plan review (2026-05-05):**
- Core exposes `Vault::mutate_and_save` so front ends do not hand-roll
  rollback for add / remove / import / settings mutations.
- Core `AccountInput` uses an `AccountKindInput` selector, optional
  TOTP `period_secs` and HOTP `counter` fields, and an `IconHintInput`
  tri-state (`Default`, `Clear`, `Slug`) for manual add flows.
- Core exposes `default_vault_path()` so presentation crates do not
  duplicate `ProjectDirs` vault-location logic.
- Core exposes `Vault::find_duplicate(&ValidatedAccount)` so single-entry
  add flows do not duplicate secret-bearing `(secret, issuer, label)`
  collision comparison in presentation crates.
- Core exposes `format_unsafe_permissions(&PaladinError)` so permission
  repair wording consumes the concrete shared error type.
- Core exposes an import facade (`import::from_file` / `from_bytes`) so
  auto-detect and forced-format dispatch, including
  `unsupported_import_format`, live in one place.
- TUI Flatpak grants the minimal display clipboard permissions needed for
  clipboard copy and QR-from-clipboard.
- Core exposes `write_secret_file_atomic` for plaintext and encrypted export
  files across all front ends.
- Core exposes `AccountSummary`, public `Code` projections, and
  feature-gated serialization for those non-secret view types so CLI/TUI/GUI
  can render accounts and codes without accessing private secret-bearing
  `Account` fields.
- Core exposes `account_matches_search`, `parse_account_query`,
  `Vault::matching_accounts`, and `Vault::shortest_unique_id_prefix` so
  issuer/label matching, `id:` prefix validation, and candidate
  disambiguators are not reimplemented in presentation crates.
- Core exposes `parse_setting_key`, `parse_setting_patch`, and
  `Vault::apply_setting_patch` so the CLI's dotted settings grammar shares
  the same validation as TUI / GUI typed settings controls.
- Core exposes `format_validation_warning`, `HOTP_REVEAL_SECS`, and
  `QR_RGBA_MAX_BYTES` so warning text, the TUI / GUI HOTP reveal duration,
  and raw-RGBA QR clipboard limits cannot drift.

**Decided during core plan review (2026-05-05):**
- Core exposes a feature-gated `test-fault-injection` hook for binary
  integration tests to drive pre-commit and post-commit storage failures
  end-to-end without linking fault-injection code into production builds.
- Core exposes feature-gated `PaladinError` serialization under
  `error-serde`, off by default, so the CLI can serialize shared error
  kinds without renaming or mapping them locally.
- Core resolves the default vault path with
  `ProjectDirs::from("", "", "paladin")`, then appends `vault.bin`.
- v0.1 supports custom Argon2id costs for encrypted writes through
  `Argon2Params` / `EncryptionOptions`; CLI advanced flags expose the same
  controls for init, passphrase set/change, and encrypted export.
- Core-owned `io_error.operation` strings and
  `unsupported_import_format.format` semantics are stable and enumerated in
  §5.
- Core-owned `invalid_state.operation` / `state` pairs are stable for
  account-ID method failures, passphrase wrong-state failures, and missing
  Paladin import passphrases.

**Decided during core plan follow-up (2026-05-06):**
- `VaultSettings` keeps private fields but exposes read-only getters for
  each persisted setting.
- Cargo workspace metadata uses `repository =
  "https://github.com/FreedomBen/paladin"` and `homepage =
  "https://paladin.tamx.org"`.
- CI-installed cargo subcommands are pinned in `xtask/dev-tools.toml`;
  v0.1 pins `cargo-public-api` there for the public API snapshot gate.

**Decided during CLI plan review (2026-05-06):**
- Interactive `paladin add` prompts mirror manual flags, collect the form once,
  and return validation errors without reprompt loops.
- Text-mode destructive confirmations accept only exact `yes` after trimming
  surrounding Unicode whitespace; any other response exits before mutation.
- Encrypted-write KDF flags are validated before vault inspection, unlock
  prompts, wrong-state checks, or command-specific prompts.

**Decided during QR-export planning (2026-05-26):**
- Per-account QR export is the v0.2 scope; multi-account / vault-
  migration QR formats (Google Authenticator `otpauth-migration://`
  protobuf) are explicitly out of scope.
- QR rendering lives in `paladin-core` (`Vault::export_qr_*` plus
  `export::qr_*`) so the thinness contract on `paladin-gtk` (no
  direct `image` / `rqrr` / `qrcode` use) stays intact. The CLI
  and TUI also call core's renderers, even though they could pull
  `qrcode` themselves, so render parameters, secret-handling, and
  warning text cannot drift across front ends.
- QR export is **read-only**: `Vault::export_qr_*` is `&self`, the
  HOTP counter is encoded at its current value, and `updated_at` is
  not bumped. Semantically a QR export is a `peek`, not a `show`.
- Three render targets, locked at the core boundary: PNG bytes
  (returned `Zeroizing<Vec<u8>>`), SVG text
  (returned `Zeroizing<String>`), and Unicode half-block text
  (returned `Zeroizing<String>`). QR error-correction level is fixed
  to **M** for the v0.2 surface; `QrRenderOptions` exposes only
  `module_size_px` (bounded 1..=64, default 8) and `quiet_zone`
  (default `true`), and is consumed by the PNG / SVG renderers only —
  the half-block renderer takes no options and always emits the quiet
  zone.
- Warning text is shared via
  `paladin_core::format_plaintext_qr_export_warning()`. CLI / TUI /
  GUI all render it verbatim before any pixel of the QR is shown,
  written, or copied.
- The CLI surfaces the feature as a new top-level command
  `paladin qr <query>` rather than overloading `paladin export`,
  so the dual-positional `<query> + <out>` shape stays parseable
  and the `--out` / `--format` / `--module-size-px` / `--force`
  flags read naturally.
- Under `--json`, an ANSI render to stdout is rejected at parse
  time; the user must pass `--out` so the JSON envelope owns
  stdout. Binary formats without `--out` are also rejected at
  parse time, and `--format=ansi` with `--out` is rejected
  because the half-block render is terminal-only.
- The GTK dialog opens on a two-step warning-ack gate: toggling
  the ack `AdwSwitchRow` on enables a separate `Show QR` button
  (`suggested-action`), and the QR is rendered only after the user
  presses that button. The two-step shape mitigates accidental
  reveal from a misclick on the switch or a closing-window glimpse.
  Dialog close, ack-off, and auto-lock all drop the rendered bytes.
- The kebab menu order becomes Rename… / Show QR… / Remove…,
  inserting `Show QR…` between the existing entries.

**Decided during final implementation-plan review (2026-05-07):**
- `EncryptionOptions::new` returns `Result<Self>` and validates the same
  zero-length passphrase rejection as `with_params`, so all default-cost
  encrypted-write paths have one core-owned validation gate.
- `IdlePolicy::next_deadline` takes the current encrypted/plaintext mode,
  not only `VaultSettings`, so the plaintext-vault auto-lock no-op is
  enforced in core instead of by front-end convention.
- Regular-save pre-commit failures after backup commit but before primary
  commit leave the old primary authoritative at `vault.bin`; the
  no-primary recoverable state is specific to the `create_force` clobber
  sequence after verbatim backup rotation.
- The no-network hardening test is a concrete source / metadata guard over
  production `paladin-core`, complementing `cargo deny` instead of relying
  on a missing-symbol compile-fail.

**Decided during row context menu and EditDialog planning (2026-05-26):**
- Per-account metadata editing is added as a v0.2 follow-on driven by
  the GUI row-context-menu work. Scope is strictly non-cryptographic:
  `label`, `issuer`, and `icon_hint` only. OTP-affecting fields
  (`secret`, `algorithm`, `digits`, `kind`, `period`, `counter`)
  stay remove + re-add — changing them invalidates already-issued
  codes, and the user-visible distinction between "rename my GitHub
  to GitHub-prod" and "rotate my GitHub secret" needs the bigger
  hammer of a destructive add. v1 of edit explicitly defers all
  cryptographic mutation paths; this scope is the locked contract
  for the v0.2 surface.
- Core exposes one multi-field mutator (`Vault::edit_account_metadata`
  taking an `AccountEdit` value) rather than per-field setters so
  every editable field routes through a single atomic
  `mutate_and_save` call and a single rollback snapshot. `AccountEdit`
  uses `Option` for "leave untouched" semantics, with an inner
  `Option<String>` on `issuer` to distinguish "clear" from "set".
  An empty `AccountEdit` (every field `None`) is rejected at the
  core boundary as `validation_error` (`field: "edit"`,
  `reason: "empty"`) rather than silently no-op'd. Same-as-prior
  submits bump `updated_at` to match `rename`'s same-label contract.
- CLI `paladin rename <query> <label>` stays available as the
  label-only positional shorthand and is reimplemented on top of
  `Vault::edit_account_metadata`. CLI `paladin edit <query>` covers
  the multi-field grammar (`--label` / `--issuer` / `--no-issuer` /
  `--icon-hint` / `--no-icon-hint`) and rejects the no-flag /
  mutually-exclusive cases at parse time.
- `paladin edit` enforces the same `(secret, issuer, label)`
  collision rejection as `paladin add`: after per-field validation,
  the CLI calls `Vault::find_duplicate_after_edit(id, &edit)` and
  rejects a non-`None` result with `duplicate_account` (carrying
  the existing collision's `AccountSummary`) unless
  `--allow-duplicate` is supplied. The opt-out flag mirrors `add`'s
  surface for symmetry. The TUI Edit modal and GTK `EditDialog`
  call the same helper before submission so all three front ends
  surface `duplicate_account` consistently.
- `paladin add --icon-hint <slug>` flag mode routes through
  `paladin_core::parse_icon_hint_token`, matching the interactive
  `add` prompt and the new `paladin edit --icon-hint <slug>` flag —
  one grammar across every CLI icon-hint surface (empty token →
  `IconHintInput::Default`; case-insensitive `none` →
  `IconHintInput::Clear`; otherwise a §4.1 slug →
  `IconHintInput::Slug`).
- `paladin edit --issuer ""` normalizes through §4.1 issuer
  normalization (Unicode whitespace trim; empty becomes `None`) and
  is therefore functionally equivalent to `--no-issuer`. The CLI
  does not special-case it at parse time; core's
  `validate_account_edit` produces the cleared-issuer outcome.
- TUI gains a sibling Edit modal opened with `Shift+E`. The existing
  Rename modal (`Shift+R`) stays for muscle-memory continuity as the
  label-only shorthand; both modals route through the same core
  mutator.
- GTK replaces `RenameDialog` with `EditDialog`. There is no GUI
  muscle-memory cost because the v0.2 GUI is the first per-account
  edit surface — the v0.2-foundation `RenameDialog` ships only as a
  scaffolding milestone toward `EditDialog`.
- The GTK row context menu is the user-visible surface that
  motivates this work. The kebab `gio::MenuModel` (v0.2 foundation:
  *Rename…* / *Show QR…* / *Remove…*) is replaced by the four-entry
  shared model *Copy code* / *Edit…* / *Export QR…* / *Delete…*,
  and a right-click `gtk::GestureClick` on the row body binds the
  same model. The `Menu` key / `Shift+F10` keyboard equivalent is
  routed through the same path via a `gtk::ShortcutController` on
  the row container (the GTK4 idiom that replaces the deprecated
  `popup-menu` signal) so keyboard users get parity. Only one row
  popover may be mounted at a time, and section header rows do not
  raise the menu.

No open questions remain.

## 14. License

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
