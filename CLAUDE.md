# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Agent Instructions

- `DESIGN.md` is the source of truth for how the application and library should work.  If the user requests a change that conflicts, update DESIGN.md so it stays in sync.
- Write exhaustive tests that cover base functionality and any edge cases, particularly for the core shared library.

## Project status

**Pre-implementation.** The design was approved 2026-05-04. There is no source tree, `Cargo.toml`, or tests yet — only `DESIGN.md` and `LICENSE`. Until code exists, `DESIGN.md` is the source of truth; do not invent file paths, types, or APIs that aren't grounded in it. When scaffolding work begins, follow the workspace layout in `DESIGN.md` §3 verbatim.

## What this is

A Rust OTP authenticator (TOTP + HOTP) with three front-ends — CLI (`paladin`), TUI (`paladin-tui`), and GTK4 GUI (`paladin-gtk`) — sharing a common `paladin-core` library. AGPL-3.0-or-later.

## Architectural rules (locked in by design)

- **Cargo workspace, four crates:** `paladin-core` (lib: domain, OTP, storage, crypto, import/export) and three binaries. **Binaries depend only on `paladin-core` — they never reach into each other.** `paladin tui` is a thin exec wrapper around `paladin-tui`, not a re-implementation.
- **Two vault modes are first-class:** plaintext and encrypted. Mode transitions are always explicit user commands; never silently downgrade. Plaintext mode still enforces `0600` file / `0700` parent dir / atomic writes / `.bak` preservation.
- **Encrypted vault:** Argon2id (m=64 MiB, t=3, p=1 defaults, header-tunable) → 32-byte key → XChaCha20-Poly1305 AEAD. Every header byte after the magic (`format_ver`, `mode`, `kdf_id`, Argon2 params, `salt`, `aead_id`, `nonce`) is bound as AEAD AAD. Vault encoding is `bincode` (private format, not for interop).
- **HOTP CLI semantics:** `show` and `copy` **advance** the counter and persist to disk before returning. `peek` does not advance. Mirror this in `paladin-core`: `hotp_advance` persists, `hotp_peek` and `totp_code` do not mutate.
- **CLI is stateless:** open → operate → close, every command. Auto-lock and clipboard-clear are TUI/GUI-only and **opt-in**. The CLI ignores `clipboard.clear_enabled`.
- **Memory hygiene:** all secrets through `Zeroize` / `secrecy::SecretString`. No `Debug` impls that leak bytes — assert with derive audits.
- **No network, no telemetry.** Enforced via `cargo deny` policy.
- **Imports validate fully** — never trust source structure. Length-check secrets, validate base32, enum-check algorithms. Import batches are atomic.

## License hygiene

AGPL-3.0-or-later. New source files carry `// SPDX-License-Identifier: AGPL-3.0-or-later`. All workspace crates set `license = "AGPL-3.0-or-later"`. Vet vendored code and test fixtures (Aegis, Gnome Authenticator samples) for license compatibility before adding.

## Commands (will apply once code lands)

CI gates per `DESIGN.md` §10: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`, `cargo deny check`, `cargo audit`. Tests must cover RFC 6238 / RFC 4226 vectors, both-mode vault round-trip, AAD tamper detection (flip any header byte → fail), file-permission enforcement, passphrase transition rollback, and zeroize-on-drop. Use `assert_cmd` for CLI integration and `insta` golden snapshots for TUI.

## When in doubt

Re-read the relevant `DESIGN.md` section. The "Approved 2026-05-04" callout in §8 means §4.3, §4.4, §4.5, §4.6, and §8 are locked for v0.1 — flag any deviation to the user before implementing it.
