# Paladin Auth

A Rust OTP authenticator (TOTP + HOTP) with three front-ends sharing a
common core library. Local-first, no telemetry, no network.

| Crate          | Kind | Purpose                                                               |
| -------------- | ---- | --------------------------------------------------------------------- |
| `paladin-auth-core` | lib  | Domain types, OTP primitives, vault storage, crypto, import/export    |
| `paladin-auth`      | bin  | CLI front-end (`crates/paladin-auth-cli`)                                  |
| `paladin-auth-tui`  | bin  | Terminal UI (`crates/paladin-auth-tui`) — `ratatui` + `crossterm`          |
| `paladin-auth-gtk`  | bin  | GTK4 + libadwaita GUI (`crates/paladin-auth-gtk`) — `relm4`                |

Binaries depend only on `paladin-auth-core` — they never reach into each
other. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design; it remains the
source of truth for behavior and APIs.

## Status

Paladin Auth is currently under active development.  It's usable but may contain many bugs.  You're welcome to try it out, but always ensure you have a backup of your vault.  Once we're ready for beta testing, version number will increment to v0.1.x.

## Features

- **TOTP (RFC 6238)** and **HOTP (RFC 4226)** with SHA-1 / SHA-256 / SHA-512.
- **Two vault modes**, chosen explicitly and switchable any time:
  - **Plaintext** — `0600` file, `0700` parent dir, atomic writes, `.bak`.
  - **Encrypted** — Argon2id → 32-byte key → XChaCha20-Poly1305 AEAD,
    every header byte bound as AAD.
- **Standards-friendly imports:** `otpauth://` URIs (single or list),
  QR images (file or RGBA clipboard buffer), Aegis plaintext exports,
  Paladin Auth encrypted bundles. Imports validate fully and are atomic.
- **Exports:** plaintext URI-list JSON or Paladin Auth encrypted bundle, both
  refusing overwrite without `--force` and written `0600`.
- **Opt-in hardening:** auto-lock and clipboard auto-clear, off by
  default and configurable per vault. CLI is stateless and never
  auto-clears.
- **Memory hygiene:** all secrets through `Zeroize` / `secrecy`. Secret
  types are `!Serialize` and lack leaky `Debug` impls (compile-time
  audits enforce this).
- **No network, no telemetry.** Enforced via `cargo deny` policy.

v0.1 targets Linux. macOS and Windows are deferred to v0.2+
(see [`docs/DESIGN.md` §2](docs/DESIGN.md)).

## Quick start

```sh
# Create a new vault (empty passphrase prompt = plaintext mode).
paladin-auth init

# Add an account from an otpauth URI (or use --qr for an image, or
# `paladin-auth add` with no flags for an interactive prompt).
paladin-auth add --uri 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'

# List, show the current code, or copy it to the clipboard.
paladin-auth list
paladin-auth show GitHub
paladin-auth copy GitHub

# HOTP semantics: `show` and `copy` advance the counter and persist;
# `peek` reads without mutating.
paladin-auth peek MyHotpAccount

# Manage passphrase, settings, import / export.
paladin-auth passphrase set
paladin-auth settings set auto_lock.seconds 300
paladin-auth export --plaintext accounts.json
paladin-auth import accounts.json

# Launch the TUI (execs `paladin-auth-tui` with shared flags).
paladin-auth tui
```

`paladin-auth --help` and `paladin-auth <command> --help` document every flag.
`--json` emits stable JSON envelopes per [`docs/DESIGN.md` §5](docs/DESIGN.md) for
scripting; `--no-color` disables ANSI styling; `--vault <PATH>`
overrides the default location.

The default vault path follows XDG via `directories::ProjectDirs`
(typically `~/.local/share/paladin-auth/vault.bin` on Linux).

## Using `paladin-auth-core` as a library

`paladin-auth-core` holds all of the domain logic: OTP generation
(TOTP / HOTP), vault storage in both plaintext and encrypted modes,
Argon2id + XChaCha20-Poly1305 crypto, and the import / export
pipelines. The three front-ends — `paladin-auth`, `paladin-auth-tui`, and
`paladin-auth-gtk` — are thin interfaces that delegate every operation to
it; they hold no domain logic of their own, and the workspace enforces
that they never reach into each other.

This makes `paladin-auth-core` a usable foundation for building alternative
front-ends — a daemon, a browser-extension host, a different
toolkit — without re-implementing OTP, vault storage, or crypto. The
public API is snapshot-tested in
[`crates/paladin-auth-core/public-api.txt`](crates/paladin-auth-core/public-api.txt)
and CI fails the build on any unreviewed diff, so downstream consumers
get a stable surface to build against. See
[`docs/DESIGN.md`](docs/DESIGN.md) for the full type and module
breakdown.

## Build dependencies

Paladin Auth needs a Rust toolchain plus a few system packages — `gcc`,
`pkg-config`, `openssl-devel`, and (for `paladin-auth-gtk`) GTK4 ≥ 4.16 and
libadwaita ≥ 1.6 development headers. The CI gate
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) builds inside a
`fedora:42` container, which is the reference environment.

On Fedora 42+:

```sh
scripts/install-fedora-deps.sh           # all build + test + packaging deps
scripts/install-fedora-deps.sh --no-gtk  # CLI / TUI only (skip GTK + Xvfb)
scripts/install-fedora-deps.sh --help    # see all flags
```

The script mirrors the `dnf install` blocks in CI and bootstraps `rustup`
if it isn't already on `PATH`. The pinned toolchain in
[`rust-toolchain.toml`](rust-toolchain.toml) is fetched automatically on
the first `cargo` invocation.

On Debian / Ubuntu, install the equivalent packages manually — see the
package names in
[`docs/DESIGN.md` §11](docs/DESIGN.md) (`libgtk-4-dev (>= 4.16)`,
`libadwaita-1-dev (>= 1.6)`, plus `gcc`, `pkg-config`, `libssl-dev`).
Note that distributions whose stable channel ships GTK / libadwaita
older than the 4.16 / 1.6 floor cannot build `paladin-auth-gtk`.

## Building

```sh
# Build everything in the workspace.
cargo build --workspace

# Run the full test suite (unit + integration across all crates).
cargo test --workspace
```

Per-crate builds:

```sh
cargo run -p paladin-auth-cli -- --help
cargo run -p paladin-auth-tui
cargo run -p paladin-auth-gtk     # requires GTK4 >= 4.16, libadwaita >= 1.6
```

## CI gate

Per [`docs/DESIGN.md` §10](docs/DESIGN.md) and
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), every change
must clear:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
cargo audit
```

`cargo deny` and `cargo audit` are pinned in
[`xtask/dev-tools.toml`](xtask/dev-tools.toml). CI also runs
`cargo public-api -p paladin-auth-core --simplified` and fails the build on
any diff against
[`crates/paladin-auth-core/public-api.txt`](crates/paladin-auth-core/public-api.txt).

## Project layout

```
.
├── crates/
│   ├── paladin-auth-core/   # library: domain, OTP, storage, crypto, import/export
│   ├── paladin-auth-cli/    # `paladin-auth` binary (stateless CLI)
│   ├── paladin-auth-tui/    # `paladin-auth-tui` binary (ratatui)
│   └── paladin-auth-gtk/    # `paladin-auth-gtk` binary (relm4 + libadwaita)
├── xtask/              # workspace tooling (pinned dev-tools, package orchestration)
├── docs/DESIGN.md           # source of truth (locked sections approved 2026-05-04)
├── docs/IMPLEMENTATION_PLAN_01_CORE.md
├── docs/IMPLEMENTATION_PLAN_02_CLI.md
├── docs/IMPLEMENTATION_PLAN_03_TUI.md
└── docs/IMPLEMENTATION_PLAN_04_GTK.md
```

## Contributing

Patches welcome. Before opening a PR:

- Re-read the relevant `docs/DESIGN.md` section; sections §4.3–§4.6 and §8
  are locked for v0.1 — flag any deviation in the PR description.
- When changing the CLI / TUI / GTK, update the corresponding
  `IMPLEMENTATION_PLAN_0X_*.md` first so design and code stay aligned.
- Follow TDD where there is existing test infrastructure: failing tests
  first, then implementation.
- `cargo fmt` and `cargo clippy` clean; new source files carry
  `// SPDX-License-Identifier: AGPL-3.0-or-later`.

## License

AGPL-3.0-or-later. See [`LICENSE`](LICENSE) for the full text.
