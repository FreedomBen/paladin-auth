# Paladin — Design Document

A Rust OTP authenticator (TOTP + HOTP) with CLI, TUI, and GTK4 GUI front-ends
sharing a common core. Status: **approved 2026-05-04 / pre-implementation**.

## 1. Goals

- **Local-first.** All secrets live on the user's machine.
- **One core, many faces.** Domain logic, storage, and crypto live in a single
  library crate. The CLI, TUI, and GUI are thin presentation layers.
- **Compatible.** Read/write standard `otpauth://` URIs (RFC 6238 / RFC 4226 /
  Google Authenticator key-URI format). Import from QR images. Import from
  Aegis and Gnome Authenticator exports. Export plaintext or encrypted.
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
│   └── paladin-gtk/          # bin: `paladin-gtk`
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

`Account.icon_hint` is an `Option<String>` icon-name slug — lowercase
ASCII, no whitespace, max 64 chars. On `add` we default it from the
issuer (e.g. `"GitHub"` → `"github"`) when one is provided; the user
can override or clear it. The slug is a hint, not a guarantee: GUIs
resolve it (§7), the CLI and TUI ignore the field. We deliberately do
not store icon bytes — that would inflate the vault and complicate the
bincode payload without offering meaningful benefit over icon-theme
lookup.

`Account` fields are private; manual entry, URI parsing, importers, and any
future constructors all go through the same validation path:

| Field                      | Rule                                                                            |
| -------------------------- | ------------------------------------------------------------------------------- |
| `label`                    | Trim Unicode whitespace; reject empty; max 128 UTF-8 bytes.                     |
| `issuer`                   | Trim Unicode whitespace; empty becomes `None`; max 128 UTF-8 bytes when set.    |
| `secret`                   | 10 to 1024 decoded bytes. 10-15 bytes are accepted with a per-entry warning.    |
| `algorithm`                | `Sha1`, `Sha256`, or `Sha512`; default `Sha1`.                                  |
| `digits`                   | 6 to 8 inclusive; default 6. Codes are zero-padded to exactly this width.        |
| `Totp.period`              | 1 to 300 seconds inclusive; default 30.                                         |
| `Hotp.counter`             | 0 to `u64::MAX`; `hotp_advance` errors before mutation at `u64::MAX`.           |
| `icon_hint`                | `None` or the slug format above.                                                |
| `created_at`, `updated_at` | UTC Unix seconds (`u64`), 0 to 253402300799 inclusive.                          |

For `otpauth://` imports, the path label and `issuer` query parameter are
percent-decoded, then normalized with the rules above. If both an issuer
prefix in the label (`Issuer:Account`) and an `issuer` query parameter are
present, they must match after trimming or the URI is rejected.

`created_at` is stable after account creation; `updated_at` changes on any
account payload mutation, including HOTP counter advances. The timestamp
upper bound is `9999-12-31T23:59:59Z`.

### 4.2 OTP generation

- **TOTP:** RFC 6238, on top of `hmac` + `sha1` / `sha2`. Validate against
  RFC 6238 Appendix B test vectors. Generation is read-only — `totp_code`
  takes `&self` and never mutates the vault.
- **HOTP:** RFC 4226, same primitives. Validate against RFC 4226 Appendix D
  test vectors. Both entry points compute `HOTP(K, C)` for the current
  stored counter `C`; they differ only in whether they mutate state:
  - `hotp_peek` returns the code without advancing — used by UIs
    that want to render the code before the user commits to "use" it.
  - `hotp_advance` returns the same code, advances the stored counter
    to `C + 1`, **and saves the vault atomically** (so an in-memory
    advance can never silently desync from the on-disk file). It takes
    `&Store` for that reason. If the save fails, the in-memory counter is
    rolled back to `C` and `hotp_advance` returns `Err`. A subsequent
    `hotp_peek` after a successful advance therefore returns the code for
    the new counter.

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
    [ciphertext + tag]           // bincode(VaultPayload)
else:
    [bincode(VaultPayload)]
```

`VaultPayload` = `{ accounts: Vec<Account>, settings: VaultSettings }`.

- **Location.** `directories::ProjectDirs` →
  Linux: `~/.local/share/paladin/vault.bin` (XDG).
- **Permissions.** File is created `0600` regardless of mode; temporary
  files and backups are also `0600`. The parent directory, if we create
  it, is `0700`. In plaintext mode these permissions are the *only*
  protection on the secrets, so we enforce them.
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

  A crash before step 4 leaves the previous primary in place; a crash
  between steps 3 and 4 leaves the new `.bak` paired with the old
  primary plus a leftover `vault.bin.tmp` that the next `open` deletes.
  On any error, remaining `.tmp` files are unlinked.
- **Backups.** On every successful write, keep the previous `vault.bin` as
  `vault.bin.bak` (one generation). The backup is always written to match
  the mode and key of the **new** primary: for regular saves this is the same
  as the previous primary, and for passphrase transitions (§4.5) the rotated
  `.bak` is rewritten so it never preserves a superseded encryption state —
  re-encrypted under the new key for `set_passphrase` and
  `change_passphrase`, or written as plaintext for `remove_passphrase`.
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
  Future releases may widen those bounds only with an explicit format or
  policy update.
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
  `Vault` is dropped or at any passphrase transition (after which a
  fresh key is derived from the new passphrase and a fresh salt).
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
Each is a single-step transition that either fully succeeds or leaves the
files untouched (the `.tmp` files are rolled back). On failure, the existing
`.bak` is left in place, so the user always has at least one recovery point.
`set_passphrase` and `change_passphrase` reject empty passphrases; users who
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

- **`otpauth://` URI** (single line, or one per line, or JSON array).
- **Paladin encrypted bundle** — round-trips with our encrypted exporter.
  Files with `PALADIN\0` magic but plaintext mode are rejected by the
  Paladin importer in v0.1; users should use `export --plaintext` to
  produce a portable `otpauth://` URI list instead. Plaintext exports are
  detected and read as `otpauth://` URI lists above (they share the same
  on-disk format).
- **Aegis** — JSON export. v0.1 supports the **plaintext export** out of
  the box; **encrypted Aegis backups** (scrypt + AES-256-GCM) are a stretch
  goal for v0.2 since they require implementing Aegis's KDF profile.
- **Gnome Authenticator** — JSON export produced by its
  *Backup → Save in plain text* action.
- **QR image file** — one or more accounts (one per decoded QR);
  errors if no QRs are decoded. Uses `rqrr` to decode every QR in the
  image and feeds each resulting `otpauth://` URI through the URI
  parser. The GTK GUI also accepts a QR image pasted from the
  clipboard, decoded via the same path.

`detect` resolves the format in this fixed order, returning the first
match: file starts with the `PALADIN\0` magic → `Paladin`; image-format
magic bytes (PNG, JPEG, GIF, BMP, WebP) → `Qr`; UTF-8 text that parses
as JSON with Aegis's top-level `version` / `header` / `db` shape →
`Aegis`; JSON matching Gnome Authenticator's exported shape → `Gnome`;
UTF-8 either (a) starting with `otpauth://` (single URI or newline-
separated list of such URIs), or (b) parsing as a JSON array of strings
each starting with `otpauth://` → `Otpauth`; otherwise `Unknown`.
Plaintext exports land in the `Otpauth` branch by design — they share
the same on-disk format as a JSON `otpauth://` array.

Each importer is tested with sample fixture files committed under
`crates/paladin-core/tests/fixtures/`. The byte-oriented importers
(`aegis`, `gnome`, `otpauth`) take `&[u8]`; the encrypted Paladin
importer additionally takes a passphrase (`SecretString`), and the
QR importer takes a path (it loads the image, decodes every QR via
`rqrr`, and feeds each resulting URI through `parse_otpauth`). When
`import::paladin` sees a valid Paladin header with `mode == 0`, it returns
a typed unsupported-plaintext-vault error without importing accounts.

### 4.7 Public API sketch

```rust
pub enum VaultLock { Plaintext, Encrypted(SecretString) }
pub enum VaultStatus { Plaintext, Encrypted, Missing }

pub fn inspect(path: &Path) -> Result<VaultStatus>;                       // header probe; no decryption. Ok(Missing) iff the file does not exist; other I/O errors and unrecognized magic are Err.
pub fn open(path: &Path, lock: VaultLock) -> Result<(Vault, Store)>;      // errors if `lock` doesn't match the file mode
pub fn create(path: &Path, lock: VaultLock) -> Result<(Vault, Store)>;    // errors if `path` already exists; caller is responsible for any rotation

impl Vault {
    pub fn add(&mut self, account: Account) -> AccountId;
    pub fn remove(&mut self, id: AccountId) -> Option<Account>;
    pub fn iter(&self) -> impl Iterator<Item = &Account>;                          // insertion order
    pub fn totp_code(&self, id: AccountId, now: SystemTime) -> Result<Code>;       // TOTP only; errors on HOTP entries
    pub fn hotp_peek(&self, id: AccountId) -> Result<Code>;                        // HOTP only; does not advance
    pub fn hotp_advance(&mut self, store: &Store, id: AccountId) -> Result<Code>;  // HOTP only; advances counter and saves atomically
    pub fn settings(&self) -> &VaultSettings;
    pub fn settings_mut(&mut self) -> &mut VaultSettings;

    // Passphrase management — each saves atomically.
    pub fn set_passphrase(&mut self, store: &Store, new: &SecretString) -> Result<()>;
    pub fn change_passphrase(&mut self, store: &Store, new: &SecretString) -> Result<()>;
    pub fn remove_passphrase(&mut self, store: &Store) -> Result<()>;

    pub fn save(&self, store: &Store) -> Result<()>;
}

pub fn parse_otpauth(uri: &str) -> Result<Account>;
pub fn read_qr_image(path: &Path) -> Result<Vec<String>>;                 // one URI per decoded QR in the image

pub mod import {
    pub enum ImportFormat { Otpauth, Aegis, Gnome, Paladin, Qr, Unknown }
    pub fn otpauth(bytes: &[u8]) -> Result<Vec<Account>>;          // single URI, line-list, or JSON array of URIs
    pub fn aegis_plaintext(bytes: &[u8]) -> Result<Vec<Account>>;
    pub fn gnome_authenticator(bytes: &[u8]) -> Result<Vec<Account>>;
    pub fn paladin(bytes: &[u8], passphrase: &SecretString) -> Result<Vec<Account>>;  // encrypted Paladin bundle only
    pub fn qr_image(path: &Path) -> Result<Vec<Account>>;
    pub fn detect(bytes: &[u8]) -> ImportFormat;
}

pub mod export {
    pub fn otpauth_list(accounts: &[Account]) -> Vec<u8>;                              // JSON array of `otpauth://` URIs (infallible: validated `Account`s always serialize)
    pub fn encrypted(accounts: &[Account], passphrase: &SecretString) -> Result<Vec<u8>>;  // Paladin encrypted bundle. Wraps `VaultPayload { accounts, settings: VaultSettings::default() }`; `import::paladin` discards the settings field.
}
```

## 5. CLI (`paladin`)

Built with `clap` (derive). Commands:

| Command                                     | Behavior                                                         |
| ------------------------------------------- | ---------------------------------------------------------------- |
| `paladin init [--force]`                    | Create a new vault. Prompts: passphrase? (empty = plaintext). Refuses to clobber an existing vault unless `--force` (which rotates the old file to `vault.bin.bak` first, overwriting any existing backup). The rotated `.bak` is preserved verbatim — a plaintext-to-encrypted clobber leaves plaintext secrets in `.bak` until the user removes it manually. |
| `paladin add`                               | Add an account interactively (or via flags / URI).               |
| `paladin add --qr <path>`                   | Add by scanning a QR image file. Every decoded QR in the image is added (errors if none decode); collisions use the default `import` merge policy (`skip`). For other policies, use `import --format=qr`. |
| `paladin list`                              | List accounts (no codes).                                        |
| `paladin show <query>`                      | Print the current code. **Advances HOTP counter.**               |
| `paladin peek <query>`                      | Print the current code without advancing the HOTP counter; for TOTP, identical to `show`. |
| `paladin copy <query>`                      | Copy code to clipboard. **Advances HOTP counter.** (Auto-clear is TUI/GUI-only — the CLI ignores `clipboard.clear_enabled`; see security consideration 6.) |
| `paladin remove <query>`                    | Remove an account (with confirmation).                           |
| `paladin rename <query> <label>`            | Rename an account.                                               |
| `paladin passphrase set`                    | Encrypt a plaintext vault under a new passphrase.                |
| `paladin passphrase change`                 | Re-encrypt under a new passphrase.                               |
| `paladin passphrase remove`                 | Decrypt to plaintext. Requires `--yes-i-know` to skip the warning. |
| `paladin export --plaintext <out>`          | Write JSON `otpauth://` array. Warns; refuses overwrite without `--force`. |
| `paladin export --encrypted <out>`          | Write Paladin-format encrypted bundle. Refuses overwrite without `--force`. |
| `paladin import [--on-conflict=<mode>] <path>` | Auto-detect format and merge into the vault. Conflict mode: `skip` (default), `replace`, `append`. See merge policy below. |
| `paladin import --format=<fmt> <path>`      | Force format: `otpauth`, `aegis`, `gnome`, `paladin` (encrypted bundle only), `qr`.      |
| `paladin settings get [key]`                | Show vault settings (auto-lock, clipboard-clear).                |
| `paladin settings set <key> <value>`        | Edit vault settings.                                             |
| `paladin tui`                               | Convenience wrapper: execs `paladin-tui` with the same args. Keeps the §3 "binaries don't reach into each other" rule intact. |

Global flags: `--vault <path>`, `--no-color`, `--json` (for scripting).

All mutating CLI commands save atomically before returning success. If the
save fails, the command exits non-zero and the in-memory change is rolled
back before the process exits. Imports of encrypted Paladin bundles prompt
for the bundle passphrase, which is independent of the vault passphrase.
For files with `PALADIN\0` magic, the CLI probes the mode first: `mode == 0`
returns the unsupported-plaintext-vault error without a passphrase prompt,
and `mode == 1` prompts for the bundle passphrase.

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

Success shapes:

| Command family                | JSON shape                                                                      |
| ----------------------------- | ------------------------------------------------------------------------------- |
| `list`                        | `{ "accounts": [AccountSummary] }`                                              |
| `show`, `peek`                | `{ "codes": [CodeResult] }`                                                     |
| `copy`                        | `{ "copied": true, "account": AccountSummary, "counter_used": number_or_null }` |
| `add`, `rename`               | `{ "account": AccountSummary }`                                                 |
| `remove`                      | `{ "removed": AccountSummary }`                                                 |
| `import`                      | `{ "imported": n, "skipped": n, "replaced": n, "accounts": [AccountSummary] }`  |
| `export`                      | `{ "written": "/path/to/out", "format": "otpauth_or_paladin" }`                |
| `settings get`, `settings set` | `{ "settings": VaultSettings }`                                                 |
| `init`, `passphrase *`        | `{ "ok": true, "status": "plaintext_or_encrypted" }`                           |

Pseudo-values such as `number_or_null` and `plaintext_or_encrypted`
document allowed values; concrete output uses actual numbers, `null`, or
enum strings.

`CodeResult` contains `account`, `code`, and either TOTP timing
(`valid_from` and `valid_until` as Unix seconds, plus
`seconds_remaining` as an integer duration) or HOTP `counter_used`.
Errors use stable snake_case `kind` values:

```json
{
  "error": {
    "kind": "multiple_matches",
    "message": "query matched multiple accounts",
    "candidates": []
  }
}
```

`candidates` is present only for ambiguity errors and contains
`AccountSummary` objects.

Vault settings keys (subject to extension):

| Key                       | Type             | Default | Effect                                       |
| ------------------------- | ---------------- | ------- | -------------------------------------------- |
| `auto_lock.enabled`       | bool             | `false` | Whether TUI/GUI lock on idle.                |
| `auto_lock.timeout_secs`  | u32              | `300`   | Idle timeout when enabled.                   |
| `clipboard.clear_enabled` | bool             | `false` | TUI/GUI: schedule a clipboard wipe after copy. (CLI ignores.) |
| `clipboard.clear_secs`    | u32              | `20`    | Wipe timeout when enabled.                   |

Minimum values: `auto_lock.timeout_secs >= 30`, `clipboard.clear_secs
>= 5`. `settings set` rejects lower values with a validation error.

### Query resolution

`<query>` is a case-insensitive substring match against `"{issuer}:{label}"`
(empty issuer is allowed; the colon is still present in the match key).

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
  account" error.
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
  digits, kind, icon_hint, updated). The `id` is preserved.
- `append` — always insert as a new entry, even if it's an exact dupe.

The collision check runs against the *running* import state, so
duplicates within a single input are themselves subject to
`--on-conflict`: `skip` keeps the first, `replace` is last-wins, and
`append` keeps every copy.

Non-colliding entries are always inserted. Imports are atomic at the
batch level: if any entry fails validation (see security consideration 9),
no entries are added.

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
- HOTP rows: code is hidden until the user presses `n` (advances counter and
  saves); after a 120-second reveal window, returns to the hidden state.
  Copying a hidden HOTP row is rejected with a status message. Copying
  during the reveal window copies the visible code and does not advance
  the counter again.
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
9. **Imports are fully validated.** Each importer parses into `Account`
   values without trusting the source's claimed structure — secrets are
   length-checked (rejected if shorter than 10 bytes / 80 bits or longer
   than 1024 bytes; entries shorter than 16 bytes / 128 bits — the RFC
   4226 §4 minimum — are accepted with a per-entry warning), base32 is
   validated, algorithms must be in our enum, and OTP parameters must
   pass the §4.1 validation table.
10. **No telemetry, no network calls.** Enforced by code review and tests;
    `cargo deny` covers dependency license/advisory policy, not runtime
    network behavior.
11. **Reproducible builds.** Pin `rust-toolchain.toml`. Lock all deps.
12. **Threat model documented separately** in `SECURITY.md` before v1.

> **Approved 2026-05-04.** All decisions in §4.3, §4.4, §4.5, §4.6, and §8
> are locked in for v0.1. Tests in `paladin-core` will assert round-trip
> properties for both modes, tamper detection, file-permission enforcement,
> and passphrase-transition rollback so regressions are caught in CI.

## 9. Key dependencies (proposed)

| Crate                              | Use                              |
| ---------------------------------- | -------------------------------- |
| `ratatui`                          | TUI rendering                    |
| `crossterm`                        | TUI backend                      |
| `tui-input`                        | TUI text input widget            |
| `relm4`, `gtk4`                    | GUI                              |
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
  - `otpauth://` parser round-trip (TOTP and HOTP).
  - Vault round-trip in **both** modes (plaintext and encrypted).
  - Tamper detection on encrypted vault: flip a ciphertext byte → fail;
    flip any byte in the AAD-bound header (`format_ver`, `mode`, `kdf_id`,
    Argon2 params, `salt`, `aead_id`, `nonce`) → fail.
  - Argon2 parameter bounds reject headers outside the v0.1 limits before
    KDF work begins.
  - File-permission enforcement (`0600` on primary, backup, and temp files;
    `0700` on dir) post-save and during staged writes.
  - Passphrase set/change/remove transitions, including failure-rollback
    (simulate write failure mid-transition → original file unchanged).
  - HOTP counter advances on `hotp_advance`, not on `hotp_peek` or `totp_code`; `hotp_advance` also persists the new counter to disk before returning.
  - Account validation rejects out-of-range digits, TOTP periods, HOTP
    counter overflow, empty labels, malformed icon hints, mismatched
    otpauth issuers, and invalid timestamps.
  - Zeroize-on-drop assertions for `Secret` and `SecretString`.
  - Importers: Aegis plaintext, Gnome Authenticator, our own export
    round-trip, and plaintext Paladin vault rejection — fixture files in
    `tests/fixtures/`.
- **Property tests** (`proptest`) for the URI parser and base32 secret
  decoding.
- **Integration tests** per binary using `assert_cmd` (CLI) and
  golden-snapshot tests (`insta`) for TUI rendering.
  - CLI `--json` success/error shapes and export overwrite guards.
  - TUI HOTP copy behavior: hidden rows do not copy, revealed rows copy
    without advancing again.
  - Plaintext-vault auto-lock is a no-op in TUI/GUI state handling.
- **CI:** `cargo fmt --check`, `cargo clippy -- -D warnings`,
  `cargo test --all`, `cargo deny check`, `cargo audit`.

## 11. Roadmap & checklist

### Milestone 0 — Skeleton *(v0.1)*
- [ ] Initialize workspace `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`.
- [ ] Create `paladin-core`, `paladin-cli`, `paladin-tui`, `paladin-gtk` crates.
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
- [ ] Atomic transition with rollback on write failure.
- [ ] Tests covering all three transitions and the failure-rollback path.

### Milestone 3 — Import / Export *(v0.1)*
- [ ] Plaintext export (JSON `otpauth://` array) with overwrite guard + `0600`.
- [ ] Encrypted export bundle (Paladin format) with overwrite guard.
- [ ] Importer: `otpauth://` URIs (single + list).
- [ ] Importer: Paladin encrypted bundle; plaintext Paladin vault files return an unsupported-format error.
- [ ] Importer: Aegis plaintext export.
- [ ] Importer: Gnome Authenticator plaintext export.
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

### Milestone 6 — GUI *(v0.2)*
- [ ] Relm4 component tree (Unlock / List / Row / Add / Settings).
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Clipboard + auto-lock parity with TUI (opt-in).
- [ ] Linux desktop file + icon.
- [ ] Manual test plan documented.

### Milestone 7 — Hardening & release *(v0.1)*
- [ ] `SECURITY.md` with threat model covering both vault modes.
- [ ] `cargo deny` + `cargo audit` clean in CI.
- [ ] Reproducible release builds; signed checksums.
- [ ] v0.1.0 tag.

## 12. Open questions

**Decided at sign-off (2026-05-04):**
- AEAD = **XChaCha20-Poly1305** (24-byte nonce, AEAD ID 1).
- Vault encoding = **bincode** (private format, not for interop).
- HOTP CLI semantics: `show` and `copy` **advance** the counter; `peek` does not.
- Aegis **encrypted** backups deferred to v0.2 (plaintext export supported in v0.1).
- GUI deferred to v0.2; **TUI ships in v0.1**.
- TUI runtime = plain threads + `mpsc` (no `tokio` — a local TUI doesn't need async I/O).
- **Icon hints:** name-only `Option<String>` slug (§4.1, §7). User-supplied icon bytes rejected to keep the vault payload small.
- Account validation ranges are fixed in §4.1, including OTP digits,
  TOTP period, HOTP counter overflow, timestamp format, and issuer/label
  normalization.
- Argon2 header parameters are bounded before KDF work (§4.4).
- Plaintext Paladin vault files are not an import format in v0.1; use
  plaintext export for portable URI-list import/export (§4.6).
- Plaintext auto-lock is a no-op; HOTP copy in TUI/GUI only copies an
  already revealed HOTP code and never advances a second time.
- Both plaintext and encrypted CLI exports refuse overwrite without `--force`.

No open questions remain.

## 13. License

This project is licensed under **AGPL-3.0-or-later**. The canonical text
lives in [`LICENSE`](LICENSE) at the repo root.

- All workspace crates set `license = "AGPL-3.0-or-later"` in their
  `Cargo.toml`.
- New source files should carry the standard SPDX header
  (`// SPDX-License-Identifier: AGPL-3.0-or-later`).
- Vendored code, fixture files imported from other projects (e.g., Aegis or
  Gnome Authenticator export samples used as test fixtures), and any
  third-party assets must be vetted for license compatibility before
  inclusion. AGPL-3.0-or-later can be combined with GPL-3.0-or-later
  under the AGPL/GPLv3 compatibility terms, and common permissive
  licenses such as MIT, BSD, ISC, and Apache-2.0 are generally compatible
  with AGPL-3.0-or-later. Earlier-GPL-only code is not compatible.

Practical note for an OTP authenticator: the AGPL §13 "remote network
interaction" clause is largely inert for v0.1 since Paladin runs locally
and offers no network service. The clause becomes load-bearing only if a
downstream user wraps Paladin into a hosted service, in which case they
must offer source to network users.
