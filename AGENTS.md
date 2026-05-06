# Repository Guidelines

## Agent Instructions

- For commit messages, use clear subjects without `feat:` or `bug:` prefixes. Add a body that explains what changed and why.  Use lists with - markers when appropriate.  Do not create or switch branches unless asked, and never push from an agent session.  Respect the conventional line length of 72 characters for commit message bodies.
- `DESIGN.md` is the source of truth for how the application and library should work.  If the user requests a change that conflicts, update DESIGN.md so it stays in sync.
- Write exhaustive tests that cover base functionality and any edge cases, particularly for the core shared library.
- Use a Test Driven Development (TDD) approach: write failing tests before implementing features, then implement the code to make the tests pass.
- Commit after making changes.  Do not push.
- For containers, use Containerfile and compose.yaml and always build and run with rootless podman unless explicitly told otherwise.

## Project Structure & Module Organization

Paladin is currently pre-implementation: the approved design lives in
`DESIGN.md`, with staged plans in `IMPLEMENTATION_PLAN_01_CORE.md`,
`IMPLEMENTATION_PLAN_02_CLI.md`, `IMPLEMENTATION_PLAN_03_TUI.md`, and
`IMPLEMENTATION_PLAN_04_GTK.md`. Follow `DESIGN.md` as the source of truth.
When scaffolding begins, use the planned Cargo workspace exactly:

```text
crates/paladin-core/  # shared domain, OTP, storage, crypto, import/export
crates/paladin-cli/   # `paladin` command
crates/paladin-tui/   # terminal UI
crates/paladin-gtk/   # planned GTK4 GUI
xtask/                # optional build/release helpers
```

## Build, Test, and Development Commands

No build system exists yet. Once the Rust workspace lands, expected gates are:

- `cargo fmt --check` - verify Rust formatting.
- `cargo clippy -- -D warnings` - fail on lints.
- `cargo test --all` - run all workspace tests.
- `cargo deny check` - enforce dependency policy, including no network stack.
- `cargo audit` - check Rust dependency advisories.

## Coding Style & Naming Conventions

Use idiomatic Rust with `rustfmt`. New source files must include
`// SPDX-License-Identifier: AGPL-3.0-or-later`, and every crate must set
`license = "AGPL-3.0-or-later"`. Keep binaries thin: front ends may depend on
`paladin-core`, but not on each other. Route shared behavior into
`paladin-core`.

Protect secrets with `Zeroize` and `secrecy::SecretString`; never add `Debug`
output that can expose secret bytes.

## Testing Guidelines

Use TDD for code changes: write failing tests first, then implement. Core
coverage should include RFC 6238 and RFC 4226 vectors, vault round trips in
plaintext and encrypted modes, AAD tamper failures, file permission checks,
passphrase rollback, import validation, and zeroize behavior. Use `assert_cmd`
for CLI integration tests and `insta` snapshots for TUI output.

## Commit & Pull Request Guidelines

Use clear commit subjects without `feat:` or `bug:` prefixes. Add a body that
explains what changed and why. Do not add Claude as a co-author, do not create
or switch branches unless asked, and never push from an agent session.

Pull requests should include a concise summary, relevant test results, linked
issues when available, and screenshots or terminal captures for UI-facing CLI,
TUI, or GTK changes.

## Agent-Specific Instructions

Do not read `TODO.md` or any TODO files. Update documentation whenever behavior
or commands change, and add tests for code changes when test infrastructure
exists. If a request conflicts with `DESIGN.md`, update the design document so
the repository remains consistent.
