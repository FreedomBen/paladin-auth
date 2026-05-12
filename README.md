# Paladin

A Rust OTP authenticator (TOTP + HOTP) with three front-ends sharing a common
core library:

| Crate          | Kind  | Purpose                                                            |
| -------------- | ----- | ------------------------------------------------------------------ |
| `paladin-core` | lib   | Domain types, OTP primitives, vault storage, crypto, import/export |
| `paladin`      | bin   | CLI front-end (`crates/paladin-cli`)                               |
| `paladin-tui`  | bin   | TUI front-end (`crates/paladin-tui`)                               |
| `paladin-gtk`  | bin   | GTK4 + libadwaita GUI (deferred to v0.2; see Implementation Plan 04) |

Binaries depend only on `paladin-core` — they never reach into each other.
See `DESIGN.md` for the full design.

## Status

Implementation in progress. `paladin-core` and `paladin` (CLI) are
complete per `IMPLEMENTATION_PLAN_01_CORE.md` and
`IMPLEMENTATION_PLAN_02_CLI.md`; `paladin-tui` is the active workstream
(`IMPLEMENTATION_PLAN_03_TUI.md`). The GTK4 GUI is deferred to v0.2 per
`DESIGN.md` §13. `DESIGN.md` remains the source of truth for behavior
and APIs.

## Building

```sh
# Build everything in the workspace.
cargo build --workspace

# Run the test suite (each crate's unit + integration tests).
cargo test --workspace
```

The toolchain is pinned in `rust-toolchain.toml`; `rustup` will install the
matching toolchain on first invocation.

## CI gate

Per `DESIGN.md` §10, every change must clear the following gate before
merging:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo deny check
cargo audit
```

`cargo deny` and `cargo audit` are pinned in `xtask/dev-tools.toml`. CI
additionally runs `cargo public-api -p paladin-core --simplified` and
fails the build on any diff against `crates/paladin-core/public-api.txt`.

## License

AGPL-3.0-or-later. See `LICENSE` for the full text.
