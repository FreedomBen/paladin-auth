# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Agent Instructions

- `DESIGN.md` is the source of truth for how the application and library should work.  If the user requests a change that conflicts, update DESIGN.md so it stays in sync.
- When changing the CLI, TUI, or GTK, update the relevant `IMPLEMENTATION_PLAN_0X_*.md` with the new behavior and API details before implementing it.  This keeps design and implementation aligned.
- Write exhaustive tests that cover base functionality and any edge cases, particularly for the core shared library.
- Use a Test Driven Development (TDD) approach: write failing tests before implementing features, then implement the code to make the tests pass.
- After changing code, format and lint it with `cargo fmt` and `cargo clippy`, ensuring no warnings remain.
- Commit after making changes.  Do not push.
- For containers, use Containerfile and compose.yaml and always build and run with rootless podman unless explicitly told otherwise.
- Commit messages should respect git conventions: The first line should be a subject line of 50 characters or less (though go up to 80 if needed), followed by a blank line, and then a body that provides more detail about the change.
- When asked to verify things in CI, us the Github CLI tool `gh`
- Multiple agents may be working in this repository simultaneously.  Serialize commits with a simple lock file at `commit.lock`.  Use three separate shell commands so failures at any step stay visible — do **not** bundle creation, commit, and removal into one chained command:
  1. **Acquire**: check the lock does not exist and create it.  Run `[ ! -e commit.lock ] && touch commit.lock` as its own command.  If the file already exists, another agent is mid-commit — wait briefly and retry rather than overwriting it.
  2. **Commit**: `git add <files> && git commit -m "<msg>"` as its own command.
  3. **Release**: `rm commit.lock` as its own command, only after the commit step has returned.
  Keeping these as three discrete commands minimizes the window where a created lock could be paired with a failed-but-unobserved commit, and lets you see at each step what state the working tree is in.  If you find a stale lock from a crashed prior agent (no commit in flight per `git status` / `git log`), remove it before proceeding.

## Project status

**Implementation in progress.** The design was approved 2026-05-04. The workspace is live with four members (`crates/paladin-core`, `crates/paladin-cli`, `crates/paladin-tui`, `crates/paladin-gtk`). `IMPLEMENTATION_PLAN_01_CORE.md` and `IMPLEMENTATION_PLAN_02_CLI.md` are complete; `IMPLEMENTATION_PLAN_03_TUI.md` (v0.1) and `IMPLEMENTATION_PLAN_04_GTK.md` (v0.2 Milestone 7) are both active workstreams. The GTK release target remains v0.2 per `DESIGN.md` §13, but pure-logic scaffolding for it lands incrementally so the workspace shape and `paladin-core` API contract stay aligned. `DESIGN.md` remains the source of truth for behavior and APIs; do not invent file paths, types, or APIs that aren't grounded in it.

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

## Commands

CI gates per `DESIGN.md` §10 and `.github/workflows/ci.yml`: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, `cargo deny check`, `cargo audit`. CI also runs a `cargo public-api` snapshot diff against `crates/paladin-core/public-api.txt`. Tests must cover RFC 6238 / RFC 4226 vectors, both-mode vault round-trip, AAD tamper detection (flip any header byte → fail), file-permission enforcement, passphrase transition rollback, and zeroize-on-drop. Use `assert_cmd` for CLI integration and `insta` golden snapshots for TUI.

## When in doubt

Re-read the relevant `DESIGN.md` section. The "Approved 2026-05-04" callout in §8 means §4.3, §4.4, §4.5, §4.6, and §8 are locked for v0.1 — flag any deviation to the user before implementing it.

# context-mode — MANDATORY routing rules

You have context-mode MCP tools available. These rules are NOT optional — they protect your context window from flooding. A single unrouted command can dump 56 KB into context and waste the entire session.

## BLOCKED commands — do NOT attempt these

### curl / wget — BLOCKED
Any Bash command containing `curl` or `wget` is intercepted and replaced with an error message. Do NOT retry.
Instead use:
- `ctx_fetch_and_index(url, source)` to fetch and index web pages
- `ctx_execute(language: "javascript", code: "const r = await fetch(...)")` to run HTTP calls in sandbox

### Inline HTTP — BLOCKED
Any Bash command containing `fetch('http`, `requests.get(`, `requests.post(`, `http.get(`, or `http.request(` is intercepted and replaced with an error message. Do NOT retry with Bash.
Instead use:
- `ctx_execute(language, code)` to run HTTP calls in sandbox — only stdout enters context

### WebFetch — BLOCKED
WebFetch calls are denied entirely. The URL is extracted and you are told to use `ctx_fetch_and_index` instead.
Instead use:
- `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` to query the indexed content

## REDIRECTED tools — use sandbox equivalents

### Bash (>20 lines output)
Bash is ONLY for: `git`, `mkdir`, `rm`, `mv`, `cd`, `ls`, `npm install`, `pip install`, and other short-output commands.
For everything else, use:
- `ctx_batch_execute(commands, queries)` — run multiple commands + search in ONE call
- `ctx_execute(language: "shell", code: "...")` — run in sandbox, only stdout enters context

### Read (for analysis)
If you are reading a file to **Edit** it → Read is correct (Edit needs content in context).
If you are reading to **analyze, explore, or summarize** → use `ctx_execute_file(path, language, code)` instead. Only your printed summary enters context. The raw file content stays in the sandbox.

### Grep (large results)
Grep results can flood context. Use `ctx_execute(language: "shell", code: "grep ...")` to run searches in sandbox. Only your printed summary enters context.

## Tool selection hierarchy

1. **GATHER**: `ctx_batch_execute(commands, queries)` — Primary tool. Runs all commands, auto-indexes output, returns search results. ONE call replaces 30+ individual calls.
2. **FOLLOW-UP**: `ctx_search(queries: ["q1", "q2", ...])` — Query indexed content. Pass ALL questions as array in ONE call.
3. **PROCESSING**: `ctx_execute(language, code)` | `ctx_execute_file(path, language, code)` — Sandbox execution. Only stdout enters context.
4. **WEB**: `ctx_fetch_and_index(url, source)` then `ctx_search(queries)` — Fetch, chunk, index, query. Raw HTML never enters context.
5. **INDEX**: `ctx_index(content, source)` — Store content in FTS5 knowledge base for later search.

## Subagent routing

When spawning subagents (Agent/Task tool), the routing block is automatically injected into their prompt. Bash-type subagents are upgraded to general-purpose so they have access to MCP tools. You do NOT need to manually instruct subagents about context-mode.

## Output constraints

- Keep responses under 500 words.
- Write artifacts (code, configs, PRDs) to FILES — never return them as inline text. Return only: file path + 1-line description.
- When indexing content, use descriptive source labels so others can `ctx_search(source: "label")` later.

## ctx commands

| Command | Action |
|---------|--------|
| `ctx stats` | Call the `ctx_stats` MCP tool and display the full output verbatim |
| `ctx doctor` | Call the `ctx_doctor` MCP tool, run the returned shell command, display as checklist |
| `ctx upgrade` | Call the `ctx_upgrade` MCP tool, run the returned shell command, display as checklist |
