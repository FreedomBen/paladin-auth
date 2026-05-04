# Implementation Plan 02 — `paladin-cli` (`paladin`)

Source of truth: [DESIGN.md](DESIGN.md) §3, §5, §10, §11 (Milestone 4).
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

## Scope

Stateless CLI binary `paladin` that opens a vault, performs one operation,
and exits. Per CLAUDE.md: auto-lock and clipboard-clear are TUI/GUI-only —
the CLI ignores `clipboard.clear_enabled`. The CLI also forwards `paladin tui`
as a thin `exec` wrapper around the `paladin-tui` binary.

## Crate layout

```
crates/paladin-cli/
├── Cargo.toml            # license = "AGPL-3.0-or-later"; bin name = "paladin"
├── src/
│   ├── main.rs           # entry: parse, dispatch, exit code map
│   ├── cli.rs            # clap derive: GlobalArgs + Command enum
│   ├── output/
│   │   ├── mod.rs        # selects text vs json; no-color handling
│   │   ├── text.rs       # human renderers per command
│   │   └── json.rs       # stable JSON envelopes per §5
│   ├── prompt.rs         # /dev/tty passphrase prompts (rpassword)
│   ├── exec_tui.rs       # `paladin tui` → execvp paladin-tui w/ flags
│   ├── commands/
│   │   ├── init.rs
│   │   ├── add.rs
│   │   ├── list.rs
│   │   ├── show.rs       # advances HOTP
│   │   ├── peek.rs       # never advances
│   │   ├── copy.rs       # advances HOTP; clipboard via arboard; no auto-clear
│   │   ├── remove.rs
│   │   ├── rename.rs
│   │   ├── passphrase.rs # set / change / remove subcommands
│   │   ├── import.rs     # --format auto/otpauth/aegis/paladin/qr; --on-conflict
│   │   ├── export.rs     # --plaintext / --encrypted; refuse overwrite w/o --force
│   │   └── settings.rs   # get / set
│   └── select.rs         # query → AccountId disambiguation (label, id:<8 hex>…)
└── tests/
    ├── cli_init.rs
    ├── cli_add.rs
    ├── cli_show_peek_copy.rs
    ├── cli_remove_rename.rs
    ├── cli_passphrase.rs
    ├── cli_import_export.rs
    ├── cli_settings.rs
    ├── cli_global_flags.rs    # --vault, --no-color, --json
    ├── cli_exec_tui.rs        # `paladin tui` shells out
    ├── cli_errors_json.rs     # error envelope per error_kind
    └── golden/                # snapshot fixtures for --json outputs
```

## Global flags (per §5)

- `--vault <path>` — overrides the resolved vault path.
- `--no-color` — disables ANSI in text output.
- `--json` — emits the §5 stable JSON schema. Rejected by `paladin-tui` /
  `paladin-gtk`.

`--vault` and `--no-color` are accepted by every binary; `--json` is
`paladin`-only.

## Commands (per §5 table)

| Command                                                | Notes |
|--------------------------------------------------------|-------|
| `init [--force]`                                       | Stages new vault, then rotates old primary verbatim into `.bak`. |
| `add` (interactive / `--uri` / manual flags / `--qr`)  | Exactly one input mode; combinations rejected at parse time. |
| `list`                                                 | Account metadata only — no codes. |
| `show <query>`                                         | Advances HOTP; persists before printing. |
| `peek <query>`                                         | Never advances. |
| `copy <query>`                                         | Advances HOTP; copies to clipboard via `arboard`. **No auto-clear.** |
| `remove <query>`                                       | Confirmation prompt unless `--force`. |
| `rename <query> <new-label>`                           | Updates `updated_at`. |
| `passphrase set | change | remove`                     | Loud confirmation on `remove`. |
| `import <path> [--format <fmt>] [--on-conflict <p>]`   | `auto`/`otpauth`/`aegis`/`paladin`/`qr`; `skip`/`replace`/`append`. |
| `export --plaintext <path> | --encrypted <path>`       | Refuses overwrite without `--force`. |
| `settings get | set`                                   | CLI ignores `clipboard.clear_enabled`. |
| `tui [...]`                                            | `execvp` `paladin-tui`; rejects `--json`; forwards `--vault` / `--no-color`. |

## Add modes (per §5)

`paladin add` accepts exactly one of:

1. **Interactive** — no account-definition flags; prompts the user.
2. `--uri <otpauth-uri>` — single URI parsed by `paladin_core::otpauth`.
3. **Manual flags** — `--label` and `--secret` required; optional
   `--issuer`, `--algorithm sha1|sha256|sha512`, `--digits 6|7|8`,
   `--kind totp|hotp`, `--period <secs>` (TOTP-only), `--counter <u64>`
   (HOTP-only, default 0), `--icon-hint <slug>`. Defaults: TOTP, SHA1, 6,
   30s.
4. `--qr <path>` — every decoded QR added; collisions use the default
   `import` policy (`skip`); errors if no QR decodes.

Combining input modes rejects at parse time. Single-entry `add` rejects an
existing `(secret, issuer, label)` collision with `duplicate_account`
unless `--allow-duplicate` is passed.

## Passphrase prompts

- All passphrase I/O goes through `rpassword` reading **from `/dev/tty`** in
  both text and `--json` modes. Never from stdin/stdout.
- Prompted **once**: existing-vault unlock, encrypted-Paladin-bundle import.
- Prompted **twice (must match)**: `init` with non-empty first entry,
  `passphrase set`, `passphrase change` new passphrase, `export --encrypted`.
- Empty new passphrase on the first `init` entry selects plaintext storage
  and skips confirmation. Any other empty new passphrase rejects with
  `invalid_passphrase` `reason: "zero_length"`.
- Confirmation mismatch exits before mutation with `invalid_passphrase`
  `reason: "confirmation_mismatch"`.
- If `/dev/tty` is unavailable, exit with `io_error` and `operation:
  "passphrase_prompt"`.

## Output

- Text mode is the default. ANSI styling honors `--no-color`; also disables
  when stdout is not a TTY or `NO_COLOR` is set.
- `--json` emits the stable schema from §5 to stdout. Errors emit a JSON
  envelope with the v0.1 `error_kind` taxonomy:
  - `invalid_passphrase` (with `reason`)
  - `unsafe_permissions` (with `path`, `subject`, `actual_mode`,
    `expected_mode` — modes are 4-digit octal strings like `"0644"`)
  - `io_error` (with `operation`)
  - `invalid_payload`
  - `duplicate_account`
  - `not_found`
  - `unsupported_format`
  - `vault_locked` / `wrong_mode` / `kdf_params_out_of_range` /
    `validation_error` / `import_atomic_failure`
  - …plus any other tag the public API surfaces. The JSON schema is
    captured in golden snapshots so additions are an explicit, reviewable
    change.

Exit codes: `0` success, non-zero per error class. `--json` does not change
exit codes; the JSON envelope carries the same information.

## `paladin tui` exec wrapper

- Resolves `paladin-tui` via `PATH` and `execvp`s it, forwarding all global
  flags verbatim (`--vault`, `--no-color`, etc).
- `--json` is rejected at parse time (TUI has no JSON mode).
- If `paladin-tui` is not on `PATH`, exit non-zero with `io_error`,
  `operation: "exec_paladin_tui"`.
- Keeps the §3 "binaries don't reach into each other" rule intact — no
  in-process re-implementation of the TUI.

## Vault interaction pattern (CLI is stateless per CLAUDE.md)

Every command:

1. Resolve vault path (`--vault` or `directories::ProjectDirs::data_dir()`).
2. `paladin_core::inspect(path)` to learn the mode (or `Missing` for `init`).
3. If encrypted, prompt once via `/dev/tty`.
4. `paladin_core::open(path, lock)` — propagates `unsafe_permissions` with
   the human-readable `chmod` repair string.
5. Perform the operation. For `show`/`copy` on HOTP, call `hotp_advance`
   (which persists before returning). For `peek` on HOTP, call `hotp_peek`.
6. Drop the `Vault` (zeroizes secrets on drop).
7. Exit.

## Tests (`assert_cmd` + temp dirs + insta golden where useful)

Test invariants matter more than command count. Each test creates a fresh
temp dir, sets `--vault` to a path inside it, and asserts both stdout and
exit code.

- **`init`**: empty passphrase → plaintext file, mode `0600`, dir `0700`.
  Non-empty passphrase → encrypted; second invocation refuses to clobber;
  `--force` rotates old primary verbatim into `.bak`.
- **`init` + unsafe parent dir** → `unsafe_permissions` with `chmod` hint.
- **`add --uri`** → account appears in `list`. **`add` interactive** with
  scripted `/dev/tty` (via `script` or `pty-process` test helper).
- **`add` mode-combination rejection** (e.g. `--uri` + `--qr`).
- **`add --qr`** with synthetic QR image.
- **`show` vs `peek` on HOTP** — `show` persists counter advance (verified
  by re-opening and re-running `peek`); `peek` does not.
- **`copy` writes to clipboard** — gated behind a `#[cfg]` test flag because
  CI may not have a clipboard server; otherwise dry-run via a
  `PALADIN_CLIPBOARD_DRYRUN=1` env var observed by `arboard` test shim.
  Asserts the CLI **never** schedules an auto-clear regardless of
  `clipboard.clear_enabled` in the vault.
- **`remove`** with and without `--force`.
- **`rename`** updates `updated_at` (compared via `--json` snapshot).
- **`passphrase set/change/remove`** end-to-end against an open vault, plus
  durability-unconfirmed surfaced when the post-commit fsync fails (use a
  fault-injection `Store` available from `paladin-core` tests-only).
- **`import`** for each format with each `--on-conflict` policy. Atomic
  failure on any invalid entry.
- **`export --plaintext` / `--encrypted`** refuses overwrite without
  `--force`. Encrypted export round-trips through `import`.
- **`settings get/set`**.
- **`--json` schema snapshots** for every command success and every
  `error_kind`. Locked via `insta`.
- **`--no-color`** disables ANSI; `NO_COLOR` env var honored.
- **`paladin tui`** → spawns `paladin-tui` (a stub binary placed on `PATH`
  for the test asserts argv). `paladin tui --json` → rejected at parse
  time. Missing `paladin-tui` → `io_error` with `operation:
  "exec_paladin_tui"`.

## Definition of done

- All command behaviors from §5 implemented and tested via `assert_cmd`.
- `--json` schema golden-locked.
- `cargo fmt --check`, `clippy -- -D warnings`, `test --all`, `deny check`,
  `audit` clean.
- CLI **never** schedules a clipboard auto-clear. Verified by test.
- DESIGN.md unchanged unless a contradiction surfaces; in that case
  DESIGN.md is updated first.
