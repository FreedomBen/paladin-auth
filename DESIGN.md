# Paladin — Design Document

A Rust TOTP authenticator with CLI, TUI, and GTK4 GUI front-ends sharing a
common core. Status: **draft / pre-implementation**.

## 1. Goals

- **Local-first.** All secrets live on the user's machine. No sync server in
  v1. (Optional encrypted-export sync may come later.)
- **One core, many faces.** Domain logic, storage, and crypto live in a single
  library crate. The CLI, TUI, and GUI are thin presentation layers.
- **Compatible.** Read/write standard `otpauth://` URIs (RFC 6238 / Google
  Authenticator key-URI format). Import from QR images. Optional export.
- **Safe by default.** Secrets are always encrypted at rest. Clipboard copies
  auto-clear. The TUI/GUI auto-lock on idle.

## 2. Non-goals (v1)

- HOTP (counter-based). TOTP only for v1; HOTP is a follow-up.
- Cloud sync, multi-device pairing, or accounts.
- Webcam-based QR scanning. (Image-file scanning yes; live camera no.)
- Mobile platforms.
- Hardware-token (YubiKey HMAC-SHA1) backends. Possible later.

## 3. Workspace layout

```
paladin/
├── Cargo.toml                # virtual workspace
├── DESIGN.md
├── README.md
├── crates/
│   ├── paladin-core/         # lib: domain, TOTP, storage, crypto
│   ├── paladin-cli/          # bin: `paladin`
│   ├── paladin-tui/          # bin: `paladin-tui`
│   └── paladin-gtk/          # bin: `paladin-gtk`
└── xtask/                    # optional: build/release helpers
```

Binaries depend only on `paladin-core`. They never reach into each other.

## 4. Core crate (`paladin-core`)

### 4.1 Domain model

| Type        | Purpose                                                          |
| ----------- | ---------------------------------------------------------------- |
| `Account`   | A single TOTP entry: id, label, issuer, secret, algo, digits, period, icon hint, created/updated. |
| `Secret`    | Newtype wrapping `Vec<u8>`; implements `Zeroize` and `Drop`.     |
| `Algorithm` | Enum: `Sha1` (default), `Sha256`, `Sha512`.                      |
| `Vault`     | The decrypted in-memory collection of `Account`s + metadata.     |
| `Store`     | Persistence handle backed by an encrypted file on disk.          |
| `Code`      | A generated TOTP: digits, valid-from, valid-until, remaining ms. |

### 4.2 TOTP

Implement RFC 6238 directly on top of `hmac` + `sha1` / `sha2`. It's ~50 lines
and avoids pulling in a higher-level crate that we'd have to wrap anyway.
Validate against RFC 6238 Appendix B test vectors in unit tests.

### 4.3 Storage

- **Format.** `[magic][version][argon2 params][nonce][ciphertext]` in a single
  file. Ciphertext is `bincode` (or CBOR) of the `Vault`.
- **Location.** `directories::ProjectDirs` →
  Linux: `~/.local/share/paladin/vault.bin` (XDG).
- **Atomic writes.** Write to `vault.bin.tmp`, `fsync`, `rename`.
- **Backups.** On every successful write, keep the previous `vault.bin` as
  `vault.bin.bak` (one generation).

### 4.4 Crypto

- **KDF:** Argon2id with sane defaults (m=64 MiB, t=3, p=1), tunable in the
  header so we can raise costs over time without breaking old vaults.
- **AEAD:** AES-256-GCM (or XChaCha20-Poly1305 — decide before v1).
- **Key handling:** derived key lives in a `Zeroizing<[u8; 32]>` and is
  dropped as soon as the encrypt/decrypt op returns.
- **Passphrase prompt:** via `rpassword` for the CLI; via the host UI for the
  TUI/GUI.

### 4.5 Public API sketch

```rust
pub fn open(path: &Path, passphrase: &SecretString) -> Result<Vault>;
pub fn create(path: &Path, passphrase: &SecretString) -> Result<Vault>;
impl Vault {
    pub fn add(&mut self, account: Account) -> AccountId;
    pub fn remove(&mut self, id: AccountId) -> Option<Account>;
    pub fn iter(&self) -> impl Iterator<Item = &Account>;
    pub fn code(&self, id: AccountId, now: SystemTime) -> Result<Code>;
    pub fn save(&self, store: &Store) -> Result<()>;
}
pub fn parse_otpauth(uri: &str) -> Result<Account>;
pub fn read_qr_image(path: &Path) -> Result<String>; // returns the otpauth URI
```

## 5. CLI (`paladin`)

Built with `clap` (derive). Commands:

| Command                          | Behavior                                            |
| -------------------------------- | --------------------------------------------------- |
| `paladin init`                   | Create a new vault; prompt for passphrase.          |
| `paladin add`                    | Add an account interactively (or via flags / URI).  |
| `paladin add --qr <path>`        | Add by scanning a QR image file.                    |
| `paladin list`                   | List accounts (no codes).                           |
| `paladin show <query>`           | Print the current code for a matching account.      |
| `paladin copy <query>`           | Copy code to clipboard; auto-clear after N seconds. |
| `paladin remove <query>`         | Remove an account (with confirmation).              |
| `paladin rename <query> <label>` | Rename an account.                                  |
| `paladin export`                 | Export to encrypted bundle (passphrase-wrapped).    |
| `paladin import <path>`          | Import an encrypted bundle.                         |
| `paladin tui`                    | Launch the TUI (convenience; same as `paladin-tui`).|

Global flags: `--vault <path>`, `--no-color`, `--json` (for scripting).

## 6. TUI (`paladin-tui`)

Library: **ratatui** + **crossterm**. Helpers: `tui-input` (text fields),
`tui-textarea` (if needed for longer input).

Layout (single-screen MVP):

```
┌ Paladin ─────────────────────────────────────────────────┐
│ Search: ____________                                     │
├──────────────────────────────────────────────────────────┤
│ ▶ GitHub (ben@…)        123 456   ████████░░  18s        │
│   AWS prod              987 654   ████░░░░░░   8s        │
│   Cloudflare            …                                │
├──────────────────────────────────────────────────────────┤
│ [↑↓] move  [enter] copy  [a] add  [d] del  [/] search    │
└──────────────────────────────────────────────────────────┘
```

- Per-row `Gauge` showing time remaining in the 30 s window.
- Live re-render on a 250 ms tick.
- Modal dialogs for add / remove / passphrase prompt.
- Idle auto-lock (default 60 s) clears the in-memory vault and re-prompts.
- Single event loop: `crossterm` events ↔ tick events via `mpsc`.

## 7. GUI (`paladin-gtk`)

Library: **Relm4** on **GTK4**. Component tree:

- `AppModel` — owns the unlocked `Vault` (or `Locked` state).
- `UnlockComponent` — passphrase entry, shown when locked.
- `AccountListComponent` — `gtk::ListView` with a custom row factory.
- `AccountRowComponent` — label, code, progress, copy button.
- `AddAccountComponent` — manual fields + "scan from clipboard image".

Auto-lock and clipboard auto-clear behave the same as the TUI.

## 8. Security considerations  ⚠️

This app stores authentication factors. Mistakes here defeat 2FA for the user.
Concrete obligations we are committing to:

1. **At-rest encryption.** Vault file is unreadable without the passphrase.
   Argon2id KDF; authenticated encryption (AEAD).
2. **Memory hygiene.** All secret material (`Secret`, derived keys,
   passphrases) goes through `Zeroize` / `secrecy::SecretString`. No `Debug`
   impls leak secret bytes — assert this with `#[derive]` audits in tests.
3. **No swap leakage** *(best-effort).* Document `mlockall` on Linux as a
   recommendation; do not require it in v1.
4. **Clipboard hygiene.** Codes copied to clipboard auto-clear after a
   configurable timeout (default 20 s). Only the most recent copy is cleared
   — we do not stomp on unrelated clipboard contents that arrived after ours.
5. **Idle auto-lock.** TUI and GUI clear the in-memory vault after N seconds
   of inactivity. CLI commands open → operate → close, never holding state.
6. **No telemetry, no network calls.** Verified by `cargo deny` policy.
7. **Reproducible builds.** Pin `rust-toolchain.toml`. Lock all deps.
8. **Threat model documented separately** in `SECURITY.md` before v1.

> **Confirmation needed before implementation.** The choices above (Argon2id
> defaults, AEAD selection, vault file format, auto-lock defaults) have real
> security consequences. Please review §4.4 and §8 and confirm or push back
> before code is written. Tests in `paladin-core` will assert the round-trip
> properties (encrypt → decrypt, tamper detection, KDF cost) so a regression
> is caught in CI.

## 9. Key dependencies (proposed)

| Crate            | Use                              |
| ---------------- | -------------------------------- |
| `ratatui`        | TUI rendering                    |
| `crossterm`      | TUI backend                      |
| `tui-input`      | TUI text input widget            |
| `relm4`, `gtk4`  | GUI                              |
| `clap`           | CLI parsing                      |
| `serde`, `serde_bytes`, `bincode` | Vault serialization |
| `hmac`, `sha1`, `sha2` | TOTP primitives            |
| `aes-gcm` *or* `chacha20poly1305` | AEAD             |
| `argon2`         | KDF                              |
| `secrecy`, `zeroize` | Memory hygiene               |
| `rpassword`      | CLI passphrase prompt            |
| `arboard`        | Clipboard (cross-platform)       |
| `rqrr`, `image`  | QR decode from image files       |
| `qrcode`         | (Optional) display QR for setup  |
| `directories`    | XDG / platform paths             |
| `thiserror`, `anyhow` | Error types                 |
| `tokio` *or* plain threads | TUI/GUI tick loop      |

## 10. Testing strategy

- **Unit tests** in `paladin-core`: RFC 6238 vectors, `otpauth://` parser
  round-trip, vault encrypt/decrypt round-trip, tamper detection (flip a
  ciphertext byte → must fail), zeroize-on-drop assertions.
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

### Milestone 1 — Core (TOTP + storage)
- [ ] `Account`, `Secret`, `Algorithm`, `Vault` types with `Zeroize`.
- [ ] RFC 6238 TOTP implementation + Appendix B test vectors.
- [ ] `otpauth://` parser + base32 secret handling.
- [ ] Argon2id KDF + AEAD vault format with header versioning.
- [ ] Atomic file writes with one-generation backup.
- [ ] Tamper-detection and round-trip tests.

### Milestone 2 — CLI
- [ ] `init`, `add` (manual + URI), `list`, `show`, `remove`, `rename`.
- [ ] `copy` with clipboard auto-clear.
- [ ] `add --qr <image>` via `rqrr`.
- [ ] `--json` output for scripting.
- [ ] `assert_cmd` integration tests.

### Milestone 3 — TUI
- [ ] Single-screen list view with live countdown gauges.
- [ ] Search/filter input.
- [ ] Add / remove modals.
- [ ] Passphrase unlock screen + idle auto-lock.
- [ ] Snapshot tests for rendering.

### Milestone 4 — GUI
- [ ] Relm4 component tree (Unlock / List / Row / Add).
- [ ] Clipboard + auto-lock parity with TUI.
- [ ] Linux desktop file + icon.
- [ ] Manual test plan documented.

### Milestone 5 — Hardening & release
- [ ] `SECURITY.md` with threat model.
- [ ] `cargo deny` + `cargo audit` clean in CI.
- [ ] Encrypted import/export bundle format.
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
5. **Does the GUI need feature parity with the TUI for v1, or can it ship
   later?** Recommend: TUI in v0.1, GUI in v0.2.
