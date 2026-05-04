# Paladin — Design Document

A Rust OTP authenticator (TOTP + HOTP) with CLI, TUI, and GTK4 GUI front-ends
sharing a common core. Status: **draft / pre-implementation**.

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
| `Account`    | A single OTP entry: id, label, issuer, secret, algo, digits, kind, icon hint, created/updated. |
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
  RFC 6238 Appendix B test vectors.
- **HOTP:** RFC 4226, same primitives. Validate against RFC 4226 Appendix D
  test vectors.
- Generating an HOTP code **advances the stored counter and saves the vault**.
  A separate `peek` operation returns the next code without advancing — used
  by UIs that want to render before the user commits to "use" the code.

### 4.3 Storage

#### File format

```
[magic:        "PALADIN\0"   (8 bytes)]
[format_ver:   u8            ]
[mode:         u8            ]   // 0 = plaintext, 1 = encrypted
if mode == 1:
    [kdf_id:   u8            ]   // 1 = Argon2id
    [argon2 params: m, t, p  ]
    [salt:     16 bytes      ]
    [aead_id:  u8            ]   // 1 = AES-256-GCM, 2 = XChaCha20-Poly1305
    [nonce:    12 or 24 bytes]
    [ciphertext + tag]           // bincode(VaultPayload)
else:
    [bincode(VaultPayload)]
```

`VaultPayload` = `{ accounts: Vec<Account>, settings: VaultSettings }`.

- **Location.** `directories::ProjectDirs` →
  Linux: `~/.local/share/paladin/vault.bin` (XDG).
- **Permissions.** File is created `0600` regardless of mode. In plaintext
  mode this is the *only* protection on the secrets, so we enforce it.
- **Atomic writes.** Write to `vault.bin.tmp`, `fsync`, `rename`.
- **Backups.** On every successful write, keep the previous `vault.bin` as
  `vault.bin.bak` (one generation). Backup inherits the mode of the file it
  replaces (no plaintext leak from a previously-encrypted vault).

### 4.4 Crypto (when mode == encrypted)

- **KDF:** Argon2id with sane defaults (m=64 MiB, t=3, p=1), tunable in the
  header so we can raise costs over time without breaking old vaults. The
  passphrase + salt deterministically derive the 32-byte AEAD key.
- **AEAD:** AES-256-GCM **or** XChaCha20-Poly1305 (decided in §12). Header
  records which algorithm was used so we can migrate later.
- **Key handling:** derived key lives in a `Zeroizing<[u8; 32]>` and is
  dropped as soon as the encrypt/decrypt op returns.
- **Passphrase prompt:** via `rpassword` for the CLI; via the host UI for the
  TUI/GUI.

### 4.5 Passphrase management

A vault's encryption state is mutable at runtime. The user can:

| Operation             | Starting state | Resulting state | Notes                                       |
| --------------------- | -------------- | --------------- | ------------------------------------------- |
| **Set passphrase**    | plaintext      | encrypted       | Generate fresh salt + nonce; derive key; encrypt. |
| **Change passphrase** | encrypted      | encrypted       | Decrypt with old; fresh salt + nonce; encrypt with new. |
| **Remove passphrase** | encrypted      | plaintext       | Decrypt; write payload directly. Loud confirmation required. |

All three go through the same atomic-write + backup path as a normal save.
Each is a single-step transition that either fully succeeds or leaves the
file untouched (the `.tmp` is rolled back). The previous `.bak` is preserved
across the transition so the user has at least one recovery point.

### 4.6 Import / Export

#### Export

Two formats, user picks per invocation:

- **Plaintext.** A JSON array of `otpauth://` URIs, one entry per account,
  plus per-account counter for HOTP. Cross-compatible with most authenticators
  that accept URI lists. **The CLI prints a clear warning** before writing
  unencrypted secrets to disk and refuses to write to a file that already
  exists unless `--force` is given.
- **Encrypted.** Same payload wrapped in Paladin's encrypted file format
  (§4.3) under a passphrase the user supplies at export time (independent of
  the vault's own passphrase).

#### Import

Auto-detect format by content sniffing, with `--format` to override:

- **`otpauth://` URI** (single line, or one per line, or JSON array).
- **Paladin export** (plaintext or encrypted) — round-trips with our exporter.
- **Aegis** — JSON export. v1 supports the **plaintext export** out of the
  box; **encrypted Aegis backups** (scrypt + AES-256-GCM) are a stretch goal
  for v0.2 since they require implementing Aegis's KDF profile.
- **Gnome Authenticator** — JSON export produced by its
  *Backup → Save in plain text* action.
- **QR image file** — single account; uses `rqrr` to decode then feeds the
  resulting `otpauth://` URI through the URI parser.

Each importer is a pure `&[u8] -> Result<Vec<Account>>` function, tested with
sample fixture files committed under `crates/paladin-core/tests/fixtures/`.

### 4.7 Public API sketch

```rust
pub enum VaultLock { Plaintext, Encrypted(SecretString) }

pub fn open(path: &Path, lock: VaultLock) -> Result<Vault>;
pub fn create(path: &Path, lock: VaultLock) -> Result<Vault>;

impl Vault {
    pub fn add(&mut self, account: Account) -> AccountId;
    pub fn remove(&mut self, id: AccountId) -> Option<Account>;
    pub fn iter(&self) -> impl Iterator<Item = &Account>;
    pub fn code(&mut self, id: AccountId, now: SystemTime) -> Result<Code>;  // advances HOTP
    pub fn peek(&self, id: AccountId, now: SystemTime) -> Result<Code>;      // does not advance
    pub fn settings(&self) -> &VaultSettings;
    pub fn settings_mut(&mut self) -> &mut VaultSettings;

    // Passphrase management — each saves atomically.
    pub fn set_passphrase(&mut self, store: &Store, new: &SecretString) -> Result<()>;
    pub fn change_passphrase(&mut self, store: &Store, new: &SecretString) -> Result<()>;
    pub fn remove_passphrase(&mut self, store: &Store) -> Result<()>;

    pub fn save(&self, store: &Store) -> Result<()>;
}

pub fn parse_otpauth(uri: &str) -> Result<Account>;
pub fn read_qr_image(path: &Path) -> Result<String>;

pub mod import {
    pub fn aegis_plaintext(bytes: &[u8]) -> Result<Vec<Account>>;
    pub fn gnome_authenticator(bytes: &[u8]) -> Result<Vec<Account>>;
    pub fn paladin(bytes: &[u8], lock: VaultLock) -> Result<Vec<Account>>;
    pub fn detect(bytes: &[u8]) -> ImportFormat;
}

pub mod export {
    pub fn plaintext(accounts: &[Account]) -> Vec<u8>;
    pub fn encrypted(accounts: &[Account], passphrase: &SecretString) -> Result<Vec<u8>>;
}
```

## 5. CLI (`paladin`)

Built with `clap` (derive). Commands:

| Command                                     | Behavior                                                         |
| ------------------------------------------- | ---------------------------------------------------------------- |
| `paladin init`                              | Create a new vault. Prompts: passphrase? (empty = plaintext).    |
| `paladin add`                               | Add an account interactively (or via flags / URI).               |
| `paladin add --qr <path>`                   | Add by scanning a QR image file.                                 |
| `paladin list`                              | List accounts (no codes).                                        |
| `paladin show <query>`                      | Print the current code. **Advances HOTP counter.**               |
| `paladin peek <query>`                      | Print the next code without advancing (HOTP) / same as show (TOTP). |
| `paladin copy <query>`                      | Copy code to clipboard. Auto-clear only if enabled in settings.  |
| `paladin remove <query>`                    | Remove an account (with confirmation).                           |
| `paladin rename <query> <label>`            | Rename an account.                                               |
| `paladin passphrase set`                    | Encrypt a plaintext vault under a new passphrase.                |
| `paladin passphrase change`                 | Re-encrypt under a new passphrase.                               |
| `paladin passphrase remove`                 | Decrypt to plaintext. Requires `--yes-i-know` to skip the warning. |
| `paladin export --plaintext <out>`          | Write JSON `otpauth://` array. Warns; refuses overwrite without `--force`. |
| `paladin export --encrypted <out>`          | Write Paladin-format encrypted bundle.                           |
| `paladin import <path>`                     | Auto-detect format and merge into the vault.                     |
| `paladin import --format=<fmt> <path>`      | Force format: `otpauth`, `aegis`, `gnome`, `paladin`, `qr`.      |
| `paladin settings get [key]`                | Show vault settings (auto-lock, clipboard-clear).                |
| `paladin settings set <key> <value>`        | Edit vault settings.                                             |
| `paladin tui`                               | Launch the TUI (convenience; same as `paladin-tui`).             |

Global flags: `--vault <path>`, `--no-color`, `--json` (for scripting).

Vault settings keys (subject to extension):

| Key                       | Type             | Default | Effect                                       |
| ------------------------- | ---------------- | ------- | -------------------------------------------- |
| `auto_lock.enabled`       | bool             | `false` | Whether TUI/GUI lock on idle.                |
| `auto_lock.timeout_secs`  | u32              | `300`   | Idle timeout when enabled.                   |
| `clipboard.clear_enabled` | bool             | `false` | Whether `copy` schedules a clipboard wipe.   |
| `clipboard.clear_secs`    | u32              | `20`    | Wipe timeout when enabled.                   |

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
  saves); after a brief reveal window, returns to the hidden state.
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
  copy button.
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
6. **Clipboard hygiene is opt-in.** Default behavior is to leave the
   clipboard alone — many users have clipboard managers and would lose data
   if we wiped silently. When `clipboard.clear_enabled` is true, the wipe
   only runs if the clipboard *still contains the code we wrote* (compare
   before clearing).
7. **Auto-lock is opt-in.** Default behavior is to keep the unlocked vault
   resident as long as the TUI/GUI is open. CLI commands always
   open → operate → close, never holding state, regardless of settings.
8. **Plaintext export warns loudly.** The CLI prints a multi-line warning,
   refuses to overwrite an existing file without `--force`, and writes the
   output `0600`.
9. **Imports are fully validated.** Each importer parses into `Account`
   values without trusting the source's claimed structure — secrets are
   length-checked, base32 is validated, algorithms must be in our enum.
10. **No telemetry, no network calls.** Verified by `cargo deny` policy.
11. **Reproducible builds.** Pin `rust-toolchain.toml`. Lock all deps.
12. **Threat model documented separately** in `SECURITY.md` before v1.

> **Confirmation needed before implementation.** The choices above
> (Argon2id defaults, AEAD selection, vault file format with mode byte,
> opt-in auto-lock and clipboard-clear, plaintext mode as a supported state,
> plaintext export with `--force` semantics) have real security
> consequences. Please review §4.3, §4.4, §4.5, §4.6, and §8 and confirm or
> push back before code is written. Tests in `paladin-core` will assert
> round-trip properties for both modes (plaintext and encrypted), tamper
> detection, and file-permission enforcement, so regressions are caught
> in CI.

## 9. Key dependencies (proposed)

| Crate                              | Use                              |
| ---------------------------------- | -------------------------------- |
| `ratatui`                          | TUI rendering                    |
| `crossterm`                        | TUI backend                      |
| `tui-input`                        | TUI text input widget            |
| `relm4`, `gtk4`                    | GUI                              |
| `clap`                             | CLI parsing                      |
| `serde`, `serde_json`, `bincode`   | Vault and JSON I/O               |
| `hmac`, `sha1`, `sha2`             | TOTP / HOTP primitives           |
| `aes-gcm` *or* `chacha20poly1305`  | AEAD                             |
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
  - Tamper detection on encrypted vault (flip a ciphertext byte → fail).
  - File-permission enforcement (`0600` on file, `0700` on dir) post-save.
  - Passphrase set/change/remove transitions, including failure-rollback
    (simulate write failure mid-transition → original file unchanged).
  - HOTP counter advances on `code()`, not on `peek()`.
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

### Milestone 0 — Skeleton
- [ ] Initialize workspace `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`.
- [ ] Create `paladin-core`, `paladin-cli`, `paladin-tui`, `paladin-gtk` crates.
- [ ] CI: fmt + clippy + test on Linux.
- [ ] `README.md` with build instructions.

### Milestone 1 — Core OTP + storage
- [ ] `Account`, `Secret`, `Algorithm`, `OtpKind`, `Vault`, `VaultSettings` types with `Zeroize`.
- [ ] RFC 6238 (TOTP) implementation + Appendix B vectors.
- [ ] RFC 4226 (HOTP) implementation + Appendix D vectors.
- [ ] `otpauth://` parser + base32 secret handling (TOTP and HOTP URIs).
- [ ] **Plaintext** vault format with atomic writes + `0600` enforcement.
- [ ] **Encrypted** vault format: Argon2id + AEAD with header versioning.
- [ ] One-generation `.bak` preserved across all writes.
- [ ] Tamper-detection and round-trip tests for both modes.

### Milestone 2 — Passphrase management
- [ ] `set_passphrase`, `change_passphrase`, `remove_passphrase` on `Vault`.
- [ ] Atomic transition with rollback on write failure.
- [ ] Tests covering all three transitions and the failure-rollback path.

### Milestone 3 — Import / Export
- [ ] Plaintext export (JSON `otpauth://` array) with overwrite guard + `0600`.
- [ ] Encrypted export bundle (Paladin format).
- [ ] Importer: `otpauth://` URIs (single + list).
- [ ] Importer: Paladin export (plaintext + encrypted).
- [ ] Importer: Aegis plaintext export.
- [ ] Importer: Gnome Authenticator plaintext export.
- [ ] Importer: QR image files (`rqrr`).
- [ ] Auto-detect with explicit `--format` override.
- [ ] Fixture-based tests for each importer.

### Milestone 4 — CLI
- [ ] `init` (with optional passphrase), `add`, `list`, `show`, `peek`, `remove`, `rename`.
- [ ] `copy` (clipboard wipe gated on settings).
- [ ] `passphrase set / change / remove`.
- [ ] `export --plaintext / --encrypted`, `import [--format]`.
- [ ] `settings get / set`.
- [ ] `--json` output for scripting.
- [ ] `assert_cmd` integration tests.

### Milestone 5 — TUI
- [ ] Single-screen list view with TOTP gauges and HOTP "advance" key.
- [ ] Search/filter input.
- [ ] Add / remove / passphrase / settings modals.
- [ ] Conditional unlock screen (only when vault is encrypted).
- [ ] Opt-in auto-lock and clipboard-clear honoring vault settings.
- [ ] Snapshot tests for rendering.

### Milestone 6 — GUI
- [ ] Relm4 component tree (Unlock / List / Row / Add / Settings).
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Clipboard + auto-lock parity with TUI (opt-in).
- [ ] Linux desktop file + icon.
- [ ] Manual test plan documented.

### Milestone 7 — Hardening & release
- [ ] `SECURITY.md` with threat model covering both vault modes.
- [ ] `cargo deny` + `cargo audit` clean in CI.
- [ ] Aegis **encrypted** import (stretch).
- [ ] Reproducible release builds; signed checksums.
- [ ] v0.1.0 tag.

## 12. Open questions

1. **AEAD choice:** AES-256-GCM (hardware-accelerated, ubiquitous) vs.
   XChaCha20-Poly1305 (larger nonce, simpler misuse story). Lean: XChaCha20.
2. **Vault encoding:** `bincode` (compact, Rust-only) vs. CBOR (interop). Lean:
   `bincode` for v1, since the format is private to us.
3. **TUI runtime:** plain threads + `mpsc` vs. `tokio`. Lean: plain threads —
   simpler, and we don't need async I/O for a local TUI.
4. **Icon hints:** store an `issuer`-derived icon name and let GUIs resolve
   it, or embed user-supplied icon bytes in the vault? Lean: name-only.
5. **HOTP show semantics in CLI:** should `paladin show` advance the counter,
   or should advancement require the explicit `paladin next` / a flag? Lean:
   `show` advances (matches "I asked for a code, I'm using it"); `peek` is
   the non-advancing escape hatch.
6. **Aegis encrypted backups:** ship in v0.1 (extra crypto work) or defer to
   v0.2? Lean: defer.
7. **GUI in v0.1?** Recommend: TUI in v0.1, GUI in v0.2.
