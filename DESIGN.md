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
| `Account`    | A single OTP entry: id (`AccountId`), label, issuer, secret, algo, digits, kind, icon hint, created/updated. |
| `AccountId`  | UUIDv4. Stored as 16 bytes in the vault; displayed in canonical hyphenated form. Short `id:<8 hex>` prefix is the CLI disambiguator. |
| `Secret`     | Newtype wrapping `Vec<u8>`; implements `Zeroize` and `Drop`.             |
| `Algorithm`  | Enum: `Sha1` (default), `Sha256`, `Sha512`.                              |
| `OtpKind`    | Enum: `Totp { period: u32 }` (default 30s) or `Hotp { counter: u64 }`.   |
| `Vault`      | The decrypted in-memory collection of `Account`s + `VaultSettings`.      |
| `VaultSettings` | Per-vault user prefs (auto-lock on/off + timeout, clipboard clear on/off + timeout). Persisted **inside** the vault payload. |
| `Store`      | Persistence handle backed by a file on disk (plaintext or encrypted).    |
| `Code`       | A generated OTP: digits, validity window (TOTP) or counter (HOTP).       |

`VaultSettings` lives inside the encrypted/plaintext payload — never in the
file header — so settings can't be tampered with on an encrypted vault.

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
- **Permissions.** File is created `0600` regardless of mode. In plaintext
  mode this is the *only* protection on the secrets, so we enforce it.
- **Atomic writes.** Write to `vault.bin.tmp`, `fsync` the temp file,
  `rename` over the target, then `fsync` the parent directory so the
  rename is durable across power loss.
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
  dedicated upgrade command).
- **AEAD:** **XChaCha20-Poly1305** (24-byte nonce, simpler misuse story than
  AES-GCM). Header records the algorithm ID so we can migrate later. All
  header bytes after the magic — `format_ver`, `mode`, `kdf_id`, the Argon2
  params, `salt`, `aead_id`, and `nonce` — are passed as AEAD associated
  data, so tampering with any of them fails decryption. Each save uses a
  freshly generated random nonce; salt is preserved across regular saves and
  regenerated only on passphrase transitions (§4.5). Salt and nonce are
  drawn from the OS CSPRNG (`getrandom`).
- **Key handling:** derived key lives in a `Zeroizing<[u8; 32]>` and is
  dropped as soon as the encrypt/decrypt op returns. The passphrase
  itself (a `SecretString`) is retained by the `Vault` between `open`
  and the next `save` or passphrase transition so saves don't re-prompt;
  each save re-derives the key from `(passphrase, salt)` at the
  in-header Argon2id parameters and drops it again on return.
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
file untouched (the `.tmp` is rolled back). On failure, the existing `.bak`
is left in place, so the user always has at least one recovery point.

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
- **Encrypted (Paladin bundle).** Same payload wrapped in Paladin's
  encrypted file format (§4.3) under a passphrase the user supplies at
  export time (independent of the vault's own passphrase). Empty
  passphrases are rejected: `export::encrypted` returns an error rather
  than silently producing a plaintext-equivalent bundle.

#### Import

Auto-detect format by content sniffing, with `--format` to override:

- **`otpauth://` URI** (single line, or one per line, or JSON array).
- **Paladin encrypted bundle** — round-trips with our encrypted exporter.
  Plaintext Paladin exports are detected and read as `otpauth://` URI
  lists above (they share the same on-disk format).
- **Aegis** — JSON export. v0.1 supports the **plaintext export** out of
  the box; **encrypted Aegis backups** (scrypt + AES-256-GCM) are a stretch
  goal for v0.2 since they require implementing Aegis's KDF profile.
- **Gnome Authenticator** — JSON export produced by its
  *Backup → Save in plain text* action.
- **QR image file** — one or more accounts (one per decoded QR); uses
  `rqrr` to decode every QR in the image and feeds each resulting
  `otpauth://` URI through the URI parser. The GTK GUI also accepts a QR
  image pasted from the clipboard, decoded via the same path.

`detect` resolves the format in this fixed order, returning the first
match: file starts with the `PALADIN\0` magic → `Paladin`; image-format
magic bytes (PNG, JPEG, GIF, BMP, WebP) → `Qr`; UTF-8 text that parses
as JSON with Aegis's top-level `version` / `header` / `db` shape →
`Aegis`; JSON matching Gnome Authenticator's exported shape → `Gnome`;
UTF-8 starting with `otpauth://` (single, line-list, or JSON array of
such URIs) → `Otpauth`; otherwise `Unknown`. Plaintext Paladin exports
land in the `Otpauth` branch by design — they share the same on-disk
format as a JSON `otpauth://` array.

Each importer is tested with sample fixture files committed under
`crates/paladin-core/tests/fixtures/`. The byte-oriented importers
(`aegis`, `gnome`, `otpauth`) take `&[u8]`; the encrypted Paladin
importer additionally takes a passphrase (`SecretString`), and the
QR importer takes a path (it loads the image, decodes every QR via
`rqrr`, and feeds each resulting URI through `parse_otpauth`).

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
| `paladin init [--force]`                    | Create a new vault. Prompts: passphrase? (empty = plaintext). Refuses to clobber an existing vault unless `--force` (which rotates the old file to `vault.bin.bak` first, overwriting any existing backup). |
| `paladin add`                               | Add an account interactively (or via flags / URI).               |
| `paladin add --qr <path>`                   | Add by scanning a QR image file. Every decoded QR in the image is added; collisions use the default `import` merge policy (`skip`). For other policies, use `import --format=qr`. |
| `paladin list`                              | List accounts (no codes).                                        |
| `paladin show <query>`                      | Print the current code. **Advances HOTP counter.**               |
| `paladin peek <query>`                      | Print the current code without advancing the HOTP counter; for TOTP, identical to `show`. |
| `paladin copy <query>`                      | Copy code to clipboard. **Advances HOTP counter.** (Auto-clear is TUI/GUI-only — the CLI ignores `clipboard.clear_enabled`; see §8.6.) |
| `paladin remove <query>`                    | Remove an account (with confirmation).                           |
| `paladin rename <query> <label>`            | Rename an account.                                               |
| `paladin passphrase set`                    | Encrypt a plaintext vault under a new passphrase.                |
| `paladin passphrase change`                 | Re-encrypt under a new passphrase.                               |
| `paladin passphrase remove`                 | Decrypt to plaintext. Requires `--yes-i-know` to skip the warning. |
| `paladin export --plaintext <out>`          | Write JSON `otpauth://` array. Warns; refuses overwrite without `--force`. |
| `paladin export --encrypted <out>`          | Write Paladin-format encrypted bundle.                           |
| `paladin import [--on-conflict=<mode>] <path>` | Auto-detect format and merge into the vault. Conflict mode: `skip` (default), `replace`, `append`. See merge policy below. |
| `paladin import --format=<fmt> <path>`      | Force format: `otpauth`, `aegis`, `gnome`, `paladin` (encrypted bundle only), `qr`.      |
| `paladin settings get [key]`                | Show vault settings (auto-lock, clipboard-clear).                |
| `paladin settings set <key> <value>`        | Edit vault settings.                                             |
| `paladin tui`                               | Convenience wrapper: execs `paladin-tui` with the same args. Keeps the §3 "binaries don't reach into each other" rule intact. |

Global flags: `--vault <path>`, `--no-color`, `--json` (for scripting).

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
  a short `id:<8 hex>` form taken from the UUID. The user can re-run with
  that exact-id form (e.g. `paladin copy id:a1b2c3d4`).
- A query starting with `id:` is treated as a prefix match against the
  UUID's de-hyphenated 32-char hex form (e.g. `id:a1b2c3d4` matches any
  UUID starting with `a1b2c3d4`), never as a substring match. If the
  prefix matches multiple entries, the same single-match rule above
  applies for `copy`/`remove`/`rename`.

### Import merge policy

Two entries collide when their **(secret, issuer, label) triple is
identical**. Behavior on collision is controlled by `--on-conflict`:

- `skip` *(default)* — keep the existing entry; print a one-line warning
  for each skipped import.
- `replace` — overwrite the existing entry's mutable fields (algo,
  digits, kind, icon hint, updated). The `id` is preserved.
- `append` — always insert as a new entry, even if it's an exact dupe.

The collision check runs against the *running* import state, so
duplicates within a single input are themselves subject to
`--on-conflict`: `skip` keeps the first, `replace` is last-wins, and
`append` keeps every copy.

Non-colliding entries are always inserted. Imports are atomic at the
batch level: if any entry fails validation (§8.9), no entries are added.

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
- Modal dialogs for add / remove / passphrase / settings.
- **Auto-lock:** **off by default.** When `auto_lock.enabled = true`, the TUI
  clears the in-memory vault after `auto_lock.timeout_secs` of no input and
  shows the unlock screen.
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
  returns to the hidden state, matching the TUI.
- `AddAccountComponent` — manual fields + "scan from clipboard image".
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts.

Auto-lock and clipboard auto-clear behave the same as the TUI, including the
opt-in default.

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
   never schedules a wipe — per §8.7 it doesn't hold state, so users who
   want auto-clear from the CLI should pipe through their own tooling.
7. **Auto-lock is opt-in.** Default behavior is to keep the unlocked vault
   resident as long as the TUI/GUI is open. CLI commands always
   open → operate → close, never holding state, regardless of settings.
8. **Plaintext export warns loudly.** The CLI prints a multi-line warning,
   refuses to overwrite an existing file without `--force`, and writes the
   output `0600`.
9. **Imports are fully validated.** Each importer parses into `Account`
   values without trusting the source's claimed structure — secrets are
   length-checked (rejected if shorter than 10 bytes / 80 bits; entries
   shorter than 16 bytes / 128 bits — the RFC 4226 §4 minimum — are
   accepted with a per-entry warning), base32 is validated, algorithms
   must be in our enum.
10. **No telemetry, no network calls.** Verified by `cargo deny` policy.
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
  - File-permission enforcement (`0600` on file, `0700` on dir) post-save.
  - Passphrase set/change/remove transitions, including failure-rollback
    (simulate write failure mid-transition → original file unchanged).
  - HOTP counter advances on `hotp_advance`, not on `hotp_peek` or `totp_code`; `hotp_advance` also persists the new counter to disk before returning.
  - Zeroize-on-drop assertions for `Secret` and `SecretString`.
  - Importers: Aegis plaintext, Gnome Authenticator, our own export
    round-trip — fixture files in `tests/fixtures/`.
- **Property tests** (`proptest`) for the URI parser and base32 secret
  decoding.
- **Integration tests** per binary using `assert_cmd` (CLI) and
  golden-snapshot tests (`insta`) for TUI rendering.
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
- [ ] RFC 6238 (TOTP) implementation + Appendix B vectors.
- [ ] RFC 4226 (HOTP) implementation + Appendix D vectors.
- [ ] `otpauth://` parser + base32 secret handling (TOTP and HOTP URIs).
- [ ] **Plaintext** vault format with atomic writes + `0600` file / `0700` parent-dir enforcement.
- [ ] **Encrypted** vault format: Argon2id + AEAD with header versioning.
- [ ] One-generation `.bak` preserved across all writes.
- [ ] Tamper-detection and round-trip tests for both modes.

### Milestone 2 — Passphrase management *(v0.1)*
- [ ] `set_passphrase`, `change_passphrase`, `remove_passphrase` on `Vault`.
- [ ] Atomic transition with rollback on write failure.
- [ ] Tests covering all three transitions and the failure-rollback path.

### Milestone 3 — Import / Export *(v0.1)*
- [ ] Plaintext export (JSON `otpauth://` array) with overwrite guard + `0600`.
- [ ] Encrypted export bundle (Paladin format).
- [ ] Importer: `otpauth://` URIs (single + list).
- [ ] Importer: Paladin encrypted bundle (plaintext exports are read via the otpauth importer above).
- [ ] Importer: Aegis plaintext export.
- [ ] Importer: Gnome Authenticator plaintext export.
- [ ] Importer: QR image files (`rqrr`).
- [ ] Auto-detect with explicit `--format` override.
- [ ] Fixture-based tests for each importer.

### Milestone 4 — CLI *(v0.1)*
- [ ] `init` (with optional passphrase), `add`, `list`, `show`, `peek`, `remove`, `rename`.
- [ ] `copy` (clipboard wipe gated on settings).
- [ ] `passphrase set / change / remove`.
- [ ] `export --plaintext / --encrypted`, `import [--format]`.
- [ ] `settings get / set`.
- [ ] `--json` output for scripting.
- [ ] `assert_cmd` integration tests.

### Milestone 5 — TUI *(v0.1)*
- [ ] Single-screen list view with TOTP gauges and HOTP "advance" key.
- [ ] Search/filter input.
- [ ] Add / remove / passphrase / settings modals.
- [ ] Conditional unlock screen (only when vault is encrypted).
- [ ] Opt-in auto-lock and clipboard-clear honoring vault settings.
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

**Still open (do not block v0.1 start):**

1. **Icon hints:** store an `issuer`-derived icon name and let GUIs resolve
   it, or embed user-supplied icon bytes in the vault? Lean: name-only.

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
  inclusion. AGPL-3.0-or-later is one-way compatible with GPL-3.0-or-later
  but not with permissive-only or earlier-GPL-only code.

Practical note for an OTP authenticator: the AGPL §13 "remote network
interaction" clause is largely inert for v0.1 since Paladin runs locally
and offers no network service. The clause becomes load-bearing only if a
downstream user wraps Paladin into a hosted service, in which case they
must offer source to network users.
