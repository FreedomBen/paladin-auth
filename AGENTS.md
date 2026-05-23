# Repository Guidelines

## Agent Instructions

- `docs/DESIGN.md` is the source of truth for how the application and library should work.  If the user requests a change that conflicts, update docs/DESIGN.md so it stays in sync.
- When changing the CLI, TUI, or GTK, update the relevant `IMPLEMENTATION_PLAN_0X_*.md` with the new behavior and API details before implementing it.  This keeps design and implementation aligned.
- Write exhaustive tests that cover base functionality and any edge cases, particularly for the core shared library.
- Use a Test Driven Development (TDD) approach: write failing tests before implementing features, then implement the code to make the tests pass.
- After changing code, format and lint it with `cargo fmt` and `cargo clippy`, ensuring no warnings remain.
- Commit after making changes.  Do not push.
- For containers, use Containerfile and compose.yaml and always build and run with rootless podman unless explicitly told otherwise.
- Commit messages should respect git conventions: The first line should be a subject line of 50 characters or less (though go up to 80 if needed), followed by a blank line, and then a body that provides more detail about the change.
- Multiple agents may be working in this repository simultaneously.  Serialize commits with a simple lock file at `commit.lock`.  Use three separate shell commands so failures at any step stay visible — do **not** bundle creation, commit, and removal into one chained command:
  1. **Acquire**: check the lock does not exist and create it.  Run `[ ! -e commit.lock ] && touch commit.lock` as its own command.  If the file already exists, another agent is mid-commit — wait briefly and retry rather than overwriting it.
  2. **Commit**: `git add <files> && git commit -m "<msg>"` as its own command.
  3. **Release**: `rm commit.lock` as its own command, only after the commit step has returned.
  Keeping these as three discrete commands minimizes the window where a created lock could be paired with a failed-but-unobserved commit, and lets you see at each step what state the working tree is in.  If you find a stale lock from a crashed prior agent (no commit in flight per `git status` / `git log`), remove it before proceeding.

## Project Structure & Module Organization

The approved design lives in `docs/DESIGN.md`, with staged plans in
`docs/IMPLEMENTATION_PLAN_01_CORE.md`, `docs/IMPLEMENTATION_PLAN_02_CLI.md`,
`docs/IMPLEMENTATION_PLAN_03_TUI.md`, and `docs/IMPLEMENTATION_PLAN_04_GTK.md`.
Follow `docs/DESIGN.md` as the source of truth. The Cargo workspace currently
contains three members; `paladin-gtk` is deferred to v0.2:

```text
crates/paladin-core/  # shared domain, OTP, storage, crypto, import/export
crates/paladin-cli/   # `paladin` command
crates/paladin-tui/   # terminal UI
crates/paladin-gtk/   # planned GTK4 GUI (v0.2; not yet scaffolded)
xtask/                # dev-tool version pins (dev-tools.toml)
```

## Build, Test, and Development Commands

The Rust toolchain is pinned in `rust-toolchain.toml`; `rustup` installs
the matching version on first invocation. The CI gates in
`.github/workflows/ci.yml` are:

- `cargo fmt --all -- --check` - verify Rust formatting.
- `cargo clippy --workspace --all-targets -- -D warnings` - fail on lints.
- `cargo test --workspace --all-targets` - run all workspace tests.
- `cargo deny check` - enforce dependency policy, including no network stack.
- `cargo audit` - check Rust dependency advisories.
- `cargo public-api -p paladin-core --simplified` - diff against the
  committed `crates/paladin-core/public-api.txt` snapshot.

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
exists. If a request conflicts with `docs/DESIGN.md`, update the design document so
the repository remains consistent.
