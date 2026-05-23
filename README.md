# Paladin

A Rust OTP authenticator (TOTP + HOTP) with three front-ends sharing a
common core library. Local-first, no telemetry, no network.

| Crate          | Kind | Purpose                                                               |
| -------------- | ---- | --------------------------------------------------------------------- |
| `paladin-core` | lib  | Domain types, OTP primitives, vault storage, crypto, import/export    |
| `paladin`      | bin  | CLI front-end (`crates/paladin-cli`)                                  |
| `paladin-tui`  | bin  | Terminal UI (`crates/paladin-tui`) — `ratatui` + `crossterm`          |
| `paladin-gtk`  | bin  | GTK4 + libadwaita GUI (`crates/paladin-gtk`) — `relm4`                |

Binaries depend only on `paladin-core` — they never reach into each
other. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design; it remains the
source of truth for behavior and APIs.

## Status

Implementation in progress. Design approved 2026-05-04.

| Milestone               | Plan                                                     | State       |
| ----------------------- | -------------------------------------------------------- | ----------- |
| 1–3 Core OTP + storage  | [`docs/IMPLEMENTATION_PLAN_01_CORE.md`](docs/IMPLEMENTATION_PLAN_01_CORE.md) | Complete    |
| 4 CLI (`paladin`)       | [`docs/IMPLEMENTATION_PLAN_02_CLI.md`](docs/IMPLEMENTATION_PLAN_02_CLI.md)   | Complete    |
| 5 TUI (`paladin-tui`)   | [`docs/IMPLEMENTATION_PLAN_03_TUI.md`](docs/IMPLEMENTATION_PLAN_03_TUI.md)   | Active      |
| 7 GUI (`paladin-gtk`)   | [`docs/IMPLEMENTATION_PLAN_04_GTK.md`](docs/IMPLEMENTATION_PLAN_04_GTK.md)   | Active (v0.2 target) |

The CLI and core are usable today; the TUI and GTK GUI are
under active development and ship pure-logic tests ahead of UI wiring.

## Features

- **TOTP (RFC 6238)** and **HOTP (RFC 4226)** with SHA-1 / SHA-256 / SHA-512.
- **Two vault modes**, chosen explicitly and switchable any time:
  - **Plaintext** — `0600` file, `0700` parent dir, atomic writes, `.bak`.
  - **Encrypted** — Argon2id → 32-byte key → XChaCha20-Poly1305 AEAD,
    every header byte bound as AAD.
- **Standards-friendly imports:** `otpauth://` URIs (single or list),
  QR images (file or RGBA clipboard buffer), Aegis plaintext exports,
  Paladin encrypted bundles. Imports validate fully and are atomic.
- **Exports:** plaintext URI-list JSON or Paladin encrypted bundle, both
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
paladin init

# Add an account from an otpauth URI (or use --qr for an image, or
# `paladin add` with no flags for an interactive prompt).
paladin add --uri 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub'

# List, show the current code, or copy it to the clipboard.
paladin list
paladin show GitHub
paladin copy GitHub

# HOTP semantics: `show` and `copy` advance the counter and persist;
# `peek` reads without mutating.
paladin peek MyHotpAccount

# Manage passphrase, settings, import / export.
paladin passphrase set
paladin settings set auto_lock.seconds 300
paladin export --plaintext accounts.json
paladin import accounts.json

# Launch the TUI (execs `paladin-tui` with shared flags).
paladin tui
```

`paladin --help` and `paladin <command> --help` document every flag.
`--json` emits stable JSON envelopes per [`docs/DESIGN.md` §5](docs/DESIGN.md) for
scripting; `--no-color` disables ANSI styling; `--vault <PATH>`
overrides the default location.

The default vault path follows XDG via `directories::ProjectDirs`
(typically `~/.local/share/paladin/vault.bin` on Linux).

## Building

```sh
# Build everything in the workspace.
cargo build --workspace

# Run the full test suite (unit + integration across all crates).
cargo test --workspace
```

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml);
`rustup` will install the matching toolchain on first invocation.

Per-crate builds:

```sh
cargo run -p paladin-cli -- --help
cargo run -p paladin-tui
cargo run -p paladin-gtk     # requires GTK4 >= 4.16, libadwaita >= 1.6
```

`paladin-gtk` additionally needs GTK4 and libadwaita development headers
at the versions declared in
[`docs/IMPLEMENTATION_PLAN_04_GTK.md`](docs/IMPLEMENTATION_PLAN_04_GTK.md).

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
`cargo public-api -p paladin-core --simplified` and fails the build on
any diff against
[`crates/paladin-core/public-api.txt`](crates/paladin-core/public-api.txt).

## Project layout

```
.
├── crates/
│   ├── paladin-core/   # library: domain, OTP, storage, crypto, import/export
│   ├── paladin-cli/    # `paladin` binary (stateless CLI)
│   ├── paladin-tui/    # `paladin-tui` binary (ratatui)
│   └── paladin-gtk/    # `paladin-gtk` binary (relm4 + libadwaita)
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
