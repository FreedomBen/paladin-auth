# Paladin

A Rust OTP authenticator (TOTP + HOTP) with three front-ends sharing a common
core library:

| Crate          | Kind  | Purpose                                                            |
| -------------- | ----- | ------------------------------------------------------------------ |
| `paladin-core` | lib   | Domain types, OTP primitives, vault storage, crypto, import/export |
| `paladin`      | bin   | CLI front-end (planned in Implementation Plan 02)                  |
| `paladin-tui`  | bin   | TUI front-end (planned in Implementation Plan 03)                  |
| `paladin-gtk`  | bin   | GTK4 + libadwaita GUI (planned in Implementation Plan 04)          |

Binaries depend only on `paladin-core` — they never reach into each other.
See `DESIGN.md` for the full design.

## Status

Pre-implementation. The core crate is being built first; binary front-ends
follow. `DESIGN.md` is the source of truth for behavior and APIs.

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
cargo test --workspace
cargo deny check
cargo audit
```

`cargo deny` and `cargo audit` are pinned in `xtask/dev-tools.toml`.

## License

AGPL-3.0-or-later. See `LICENSE` for the full text.
