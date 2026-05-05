# Implementation Plan 02 — `paladin-cli` (`paladin`)

Source of truth: [DESIGN.md](DESIGN.md) §3, §5, §10, §12 (Milestone 4).
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

## Scope

Stateless CLI binary `paladin` that opens a vault, performs one operation,
and exits. Per DESIGN.md §5 and §8, auto-lock and clipboard-clear are
TUI/GUI-only — the CLI ignores `clipboard.clear_enabled`. The CLI also
forwards `paladin tui` as a thin `exec` wrapper around the `paladin-tui`
binary.

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
│   ├── prompt.rs         # /dev/tty passphrase + interactive `add` prompts (rpassword)
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
│   │   ├── import.rs     # --format otpauth/aegis/paladin/qr; --on-conflict
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
| `init [--force]`                                       | Without `--force`, calls `paladin_core::create` and surfaces `vault_exists` if a primary already exists. With `--force`, calls `paladin_core::create_force` (which performs the §5 staged clobber: stages the new vault, then rotates the old primary verbatim to `.bak`, overwriting any existing backup). |
| `add` (interactive / `--uri` / manual flags / `--qr`)  | Exactly one input mode; combinations rejected at parse time. Under `--json`, interactive mode is rejected at parse time — one of `--uri`, `--qr`, or the manual flags must be supplied. |
| `list`                                                 | Account metadata only — no codes. |
| `show <query>`                                         | Advances HOTP; persists before printing. Matching queries print all matches when every match is TOTP; if any match is HOTP, requires a single match. |
| `peek <query>`                                         | Never advances. Prints all matches unconditionally. |
| `copy <query>`                                         | Advances HOTP; copies to clipboard via `arboard`. **No auto-clear.** Single-match required. |
| `remove <query>`                                       | Confirmation prompt unless `--yes`. `--yes` is required under `--json` (no TTY prompt). Single-match required. |
| `rename <query> <new-label>`                           | Updates `updated_at`. Single-match required. |
| `passphrase set | change | remove`                     | `passphrase remove` requires `--yes-i-know` to skip the warning; required under `--json`. |
| `import <path> [--format <fmt>] [--on-conflict <p>]`   | Auto-detects when `--format` is omitted; forced formats are `otpauth`/`aegis`/`paladin` (encrypted bundle only)/`qr`; conflict policies are `skip` (default)/`replace`/`append`. |
| `export --plaintext <path> | --encrypted <path>`       | Refuses overwrite without `--force`; both modes write through `paladin_core::write_secret_file_atomic` and create output `0600`; plaintext export prints a clear warning before writing unencrypted secrets. |
| `settings get [key] | set <key> <value>`               | CLI persists `clipboard.clear_enabled` for TUI/GUI to honor but **ignores it at runtime** for `paladin copy`. `get [key]` filters text-mode display only; the `--json` shape is always the full `VaultSettings`. |
| `tui`                                                  | `execvp` `paladin-tui`; rejects `--json`; forwards `--vault` / `--no-color`. |

## Add modes (per §5)

`paladin add` accepts exactly one of:

1. **Interactive** — no account-definition flags; prompts the user.
2. `--uri <otpauth-uri>` — single URI parsed by
   `paladin_core::parse_otpauth`.
3. **Manual flags** — `--label` and `--secret` required; optional
   `--issuer`, `--algorithm sha1|sha256|sha512`, `--digits 6|7|8`,
   `--kind totp|hotp`, `--period <secs>` (TOTP-only), `--counter <u64>`
   (HOTP-only, default 0), `--icon-hint <slug>` (when omitted, derived
   from issuer per §4.1). Defaults: TOTP, SHA1, 6, 30s. Manual fields
   use §4.1 validation: `--period` is 1..=300 seconds, `--icon-hint`
   matches `[a-z0-9_-]+` up to 64 bytes, and `--secret` is Base32 text.
4. `--qr <path>` — every decoded QR added; collisions use a fixed
   `--on-conflict=skip`; errors if no QR decodes.

Combining input modes rejects at parse time. Interactive prompts
(label, issuer, secret, etc.) read from `/dev/tty` like passphrase
prompts, never from stdin/stdout. Under `--json`, interactive mode is
additionally rejected at parse time — one of `--uri`, `--qr`, or the
manual flags must be supplied — mirroring the no-prompt rule on
`remove --json` and `passphrase remove --json`. Single-entry `add`
rejects an existing `(secret, issuer, label)` collision with
`duplicate_account` unless `--allow-duplicate` is passed.
`--allow-duplicate` is mutually exclusive with `--qr` and is rejected at
parse time.

## Settings keys

`settings set` accepts the §5 dotted keys only:

| Key                       | Type | Default | Minimum |
| ------------------------- | ---- | ------- | ------- |
| `auto_lock.enabled`       | bool | `false` | n/a     |
| `auto_lock.timeout_secs`  | u32  | `300`   | `30`    |
| `clipboard.clear_enabled` | bool | `false` | n/a     |
| `clipboard.clear_secs`    | u32  | `20`    | `5`     |

Text-mode `settings get [key]` may filter to one dotted key. `--json`
always returns the full nested `VaultSettings` object, and dotted key names
never appear in JSON output. Boolean values are accepted only as lowercase
`true` or `false`; numeric settings are accepted only as base-10 `u32`
strings, then validated against the minimums above.

## Passphrase prompts

- All passphrase I/O goes through `rpassword` reading **from `/dev/tty`** in
  both text and `--json` modes. Never from stdin/stdout.
- Prompted **once per prompt target**: existing-vault unlock,
  encrypted-Paladin-bundle import.
- For Paladin-bundle imports the CLI calls
  `paladin_core::inspect(import_path)` before prompting: plaintext-mode
  bundles reject with
  `unsupported_plaintext_vault` immediately (no passphrase prompt), and
  only encrypted-mode bundles trigger the bundle-passphrase prompt before
  the call to `paladin_core::import::paladin`.
- Prompted **twice (must match)**: `init` with a non-empty first
  passphrase entry, `passphrase set`, `passphrase change` new passphrase,
  `export --encrypted`.
- Empty new passphrase on the first `init` passphrase entry selects
  plaintext storage and skips confirmation. Any other empty new passphrase
  rejects with `invalid_passphrase` `reason: "zero_length"`.
- Confirmation mismatch exits before mutation with `invalid_passphrase`
  `reason: "confirmation_mismatch"`.
- Wrong starting states for `passphrase set`, `passphrase change`, and
  `passphrase remove` surface `invalid_state` before any new-passphrase
  prompt, destructive confirmation, or crypto material generation.
- If `/dev/tty` is unavailable, exit with `io_error` and `operation:
  "passphrase_prompt"`.

## Output

- Text mode is the default. ANSI styling honors `--no-color`; also disables
  when stdout is not a TTY or `NO_COLOR` is set.
- `--json` emits the stable schema from §5 to stdout on success and one
  JSON document to stderr on failure. The `code` field is a string so
  leading zeroes are preserved.
- To keep scripting predictable, the CLI pre-scans argv for an exact
  `--json` token before clap parsing. If present, syntax/usage failures
  also render the JSON error envelope to stderr instead of clap's text
  diagnostics. They keep clap's normal syntax-error exit code and use
  `kind: "validation_error"`; when no more specific parser-side field is
  available, use `field: "argv"` and `reason: "usage"`.
- The error envelope uses the full v0.1 `kind` taxonomy from §5 verbatim —
  the CLI never invents new kinds or renames existing ones:
  `validation_error`, `invalid_passphrase`, `invalid_state`,
  `vault_missing`, `vault_exists`, `unsafe_permissions`, `wrong_vault_lock`,
  `decrypt_failed`, `invalid_header`, `invalid_payload`,
  `unsupported_format_version`, `kdf_params_out_of_bounds`,
  `unsupported_import_format`, `unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `no_entries_to_import`, `duplicate_account`, `no_match`,
  `multiple_matches`, `counter_overflow`, `time_range`,
  `save_not_committed`, `save_durability_unconfirmed`,
  `clipboard_write_failed`, and `io_error`. Stable extra fields match §5
  exactly; recovery-critical fields called out for CLI coverage are:
  - `unsafe_permissions`: `path`, `subject` (one of `vault_dir`,
    `vault_file`, `backup_file`), `actual_mode`, `expected_mode` —
    mode fields are four-digit octal strings like `"0644"` per §4.3.
  - `multiple_matches`: `candidates`, each an `AccountSummary` plus a
    `disambiguator` `id:<hex>` string (≥8 hex chars).
  - `clipboard_write_failed`: `account`, `counter_used` (`null` for TOTP);
    for HOTP, the `account` summary reflects the persisted post-advance
    counter per §5.
  - `save_not_committed`: `committed: false`, optional `backup_path`
    (set when `init --force` rotated the old primary to `.bak`).
  - `save_durability_unconfirmed`: `committed: true`.
- The JSON schema (success and error envelopes) is captured in golden
  snapshots so additions are an explicit, reviewable change.
- Under `--json`, `paladin` writes **only** the JSON envelope: the
  success document to stdout, the failure document to stderr, and no
  other bytes on either stream. This is the script contract per §5 —
  JSON consumers can `parse(stdout)` on exit 0 and `parse(stderr)` on
  non-zero exit without filtering. The strict-mode rule applies to
  every output path: short-secret validation warnings flow into the
  `warnings` array of the `add` / `import` success envelope; the
  plaintext-export advisory is suppressed because the caller opted in
  via `--plaintext`; clap diagnostics are rerouted by the argv
  pre-scan above; status / progress text is never emitted; and
  passphrase prompts read from `/dev/tty` via `rpassword` so prompt
  strings never reach stdout or stderr. Missing confirmation flags
  (`remove --yes`, `passphrase remove --yes-i-know`) reject at parse
  time as `validation_error` rather than silently blocking on a
  prompt.
- Text-mode warnings (`short_secret`, the plaintext-export advisory) are
  written to stderr in **text mode only**; under `--json` they are
  routed into the success envelope's `warnings` array (`add` /
  `import`) or suppressed (plaintext-export advisory) per the rule
  above.

Exit codes: `0` success; clap's default usage/parse exit for syntax errors;
`1` for Paladin runtime errors. `--json` does not change exit codes; it only
changes the error renderer for syntax/usage failures and lets the JSON
envelope carry the detailed `kind`.

## `paladin tui` exec wrapper

- Resolves `paladin-tui` via `PATH` and `execvp`s it, forwarding `--vault`
  and `--no-color` verbatim.
- `--json` is rejected at parse time (TUI has no JSON mode).
- If `paladin-tui` is not on `PATH`, exit non-zero with `io_error`,
  `operation: "exec_paladin_tui"`.
- Keeps the §3 "binaries don't reach into each other" rule intact — no
  in-process re-implementation of the TUI.

## Vault interaction pattern (CLI is stateless per DESIGN.md §8)

Every vault-opening command except `init`:

1. Resolve vault path (`--vault` or
   `directories::ProjectDirs::data_dir()/vault.bin`).
2. `paladin_core::inspect(path)` to learn the mode.
3. If encrypted, prompt once via `/dev/tty`.
4. `paladin_core::open(path, lock)` — propagates `unsafe_permissions`;
   text mode renders the human-readable `chmod` repair string via
   `paladin_core::format_unsafe_permissions(&err)` so the CLI and GUI
   share a single source of wording.
5. Perform the operation. For `show`/`copy` on HOTP, call `hotp_advance`
   (which persists before returning). For `peek` on HOTP, call `hotp_peek`.
   Other mutating vault operations use `Vault::mutate_and_save` so
   pre-commit save failures restore the in-memory pre-attempt state before
   the command renders its error.
   Passphrase transitions (`set_passphrase`, `change_passphrase`,
   `remove_passphrase`) save themselves through `&Store` and do not require
   a follow-up `Vault::save`.
6. Drop the `Vault` (zeroizes secrets on drop).
7. Exit.

`init` resolves the same path, prompts for the new-vault passphrase, and
uses `paladin_core::create`; `init --force` calls
`paladin_core::create_force` (which owns the §5 staged clobber sequence)
without opening or decrypting the old primary.

## Implementation checklist

- [ ] Scaffold `crates/paladin-cli` with clap parsing, global flags, and
  command dispatch.
- [ ] Ensure new Rust source files include
  `// SPDX-License-Identifier: AGPL-3.0-or-later`.
- [ ] Implement `/dev/tty` passphrase prompting and no-TTY error handling.
- [ ] Implement account selection and `id:<hex>` disambiguation.
- [ ] Implement `init`, account CRUD, `show`/`peek`/`copy`, passphrase,
  import/export, and settings commands per §5.
- [ ] Implement text and JSON output renderers with stable success/error
  envelopes and stderr warnings.
- [ ] Implement `paladin tui` as an `execvp` wrapper.
- [ ] Wire the `paladin-core` `test-fault-injection` cargo feature into
  the test build of the `paladin` binary so process-level integration
  tests can drive pre-commit and post-commit save failures via the
  `PALADIN_FAULT_INJECT` env var.
- [ ] Add the CLI integration tests and JSON golden snapshots below.
- [ ] Run the definition-of-done checks.

## Tests (`assert_cmd` + temp dirs + insta golden where useful)

Test invariants matter more than command count. Each test creates a fresh
temp dir, sets `--vault` to a path inside it, and asserts stdout, stderr
where relevant, and exit code.

- **`init`**: empty passphrase → plaintext file, mode `0600`, dir `0700`.
  Non-empty passphrase → encrypted; second invocation refuses to clobber;
  `--force` rotates old primary verbatim into `.bak`.
- **`init` + unsafe parent dir** → `unsafe_permissions` with `chmod` hint.
- **`add --uri`** → account appears in `list`. **`add` interactive** with
  scripted `/dev/tty` (via `script` or `pty-process` test helper).
- **`add` mode-combination rejection** (e.g. `--uri` + `--qr`,
  `--qr` + `--allow-duplicate`); also `add --json` without an input
  flag (no `--uri` / `--qr` / manual flags) rejects at parse time with a
  JSON error envelope.
- **`add --qr`** with synthetic QR image (multi-entry path uses fixed
  `--on-conflict=skip`).
- **`add` duplicate behavior** — `(secret, issuer, label)` collision
  rejects with `duplicate_account` and the existing `account` summary
  unless `--allow-duplicate` is passed.
- **`show` vs `peek` on HOTP** — `show` persists counter advance (verified
  by re-opening and re-running `peek`); `peek` does not. `show` on a
  multi-match query containing any HOTP entry rejects with
  `multiple_matches`; multi-match TOTP-only `show` prints all matches.
- **Query resolution** — `id:<hex>` prefix routes to UUID match, never
  substring; prefixes shorter than 8 hex chars, longer than 32 hex chars,
  or containing non-hex characters reject with `validation_error`.
- **`copy` writes to clipboard** — gated behind a test-only build cfg/feature
  because CI may not have a clipboard server; otherwise dry-run via a
  `PALADIN_CLIPBOARD_DRYRUN=1` env var honored only by the test build before
  the CLI clipboard adapter calls `arboard`.
  Asserts the CLI **never** schedules an auto-clear regardless of
  `clipboard.clear_enabled` in the vault. Clipboard failure after a
  committed HOTP advance returns `clipboard_write_failed` and leaves the
  persisted counter advanced; pre-commit HOTP save failure does not attempt
  a clipboard write.
- **`remove`** with and without `--yes`; `--json` without `--yes` rejects at
  parse time (no TTY prompt). `multiple_matches` includes `candidates`
  with `disambiguator` `id:<hex>` strings.
- **`rename`** updates `updated_at` (compared via `--json` snapshot).
- **`passphrase set/change/remove`** end-to-end against an open vault.
  `passphrase remove` requires `--yes-i-know`; `--json` without
  `--yes-i-know` rejects at parse time. No-TTY prompt failures surface as
  `io_error` with `operation: "passphrase_prompt"`; confirmation mismatch
  surfaces as `invalid_passphrase` with
  `reason: "confirmation_mismatch"`. Wrong starting states (`set` on
  encrypted, `change`/`remove` on plaintext) surface `invalid_state`
  before new-passphrase prompts or mutation. Durability-unconfirmed is
  surfaced as `save_durability_unconfirmed` (with `committed: true`) when
  the post-commit fsync fails; pre-commit failure surfaces as
  `save_not_committed` with `committed: false`. Process-level CLI tests
  opt the test build of the `paladin` binary into the `paladin-core`
  `test-fault-injection` cargo feature; the env var
  `PALADIN_FAULT_INJECT=pre_commit|post_commit` selects which `Store`
  failure path fires so `save_not_committed` and
  `save_durability_unconfirmed` envelopes can be exercised end-to-end.
- **`import`** for each format with each `--on-conflict` policy; omitting
  `--on-conflict` defaults to `skip`. Atomic failure on any invalid entry.
- **`export --plaintext` / `--encrypted`** refuses overwrite without
  `--force` and writes output `0600` through
  `paladin_core::write_secret_file_atomic`. Plaintext export prints the
  unencrypted-secrets warning; encrypted export round-trips through
  `import`; injected writer failures surface `save_not_committed` before
  the final rename and `save_durability_unconfirmed` after the final
  rename.
- **`settings get/set`** covers default values, every dotted key, bool/u32
  value parsing, minimum-value validation, text-mode filtering, and full
  `VaultSettings` JSON output.
- **`--json` schema snapshots** for every command success, every
  `error_kind`, and representative syntax/usage failures rendered as
  JSON when `--json` is present. Locked via `insta`.
- **`--json` stream cleanliness** — for every covered command, success
  and error: assert stdout is exactly the success JSON document plus
  one trailing newline (or empty on error) and stderr is exactly the
  failure JSON document plus one trailing newline (or empty on
  success). Specifically asserts no `short_secret` or plaintext-export
  text appears on either stream when `--json` is set, no clap
  diagnostics appear, and a `passphrase set` invocation under `--json`
  with `/dev/tty` rerouted to the test harness keeps stdout/stderr
  byte-clean (the prompt is consumed via `/dev/tty` only). One test
  per output path (success-with-warnings via `add --uri` of a
  short-secret URI; error-with-extra-fields via
  `multiple_matches`; clap-rerouted via an unknown subcommand;
  parse-time confirmation rejection via `remove --json` without
  `--yes`).
- **`--no-color`** disables ANSI; `NO_COLOR` env var honored.
- **`paladin tui`** → spawns `paladin-tui` (a stub binary placed on `PATH`
  for the test asserts argv) and forwards `--vault` / `--no-color` in both
  accepted global-flag positions. `paladin tui --json` and `paladin --json
  tui` → rejected at parse time with JSON error envelopes. Missing
  `paladin-tui` → `io_error` with `operation: "exec_paladin_tui"`.

## Packaging (per §11)

The CLI ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.1
(§11.1). Implementation owes the release pipeline:

- **Man page.** Generate `paladin.1` from clap via `clap_mangen`,
  driven by `cargo xtask man` (or a `build.rs` step) so the page
  always tracks the live argument tree. The packaging configs ship
  it gzipped at `/usr/share/man/man1/paladin.1.gz` per §11.3.
- **Cargo.toml metadata.** `crates/paladin-cli/Cargo.toml` sets
  `description`, `homepage`, `repository`, `keywords`, `categories`,
  and `license = "AGPL-3.0-or-later"`. `nfpm` reads these directly
  when building `.deb` / `.rpm` so the per-format configs in
  `packaging/deb/paladin.yaml` and `packaging/rpm/paladin.yaml`
  stay minimal. The Debian one-line description is short enough for
  the 60-char limit; the long form is sourced from README.
- **Flatpak.** `packaging/flatpak/paladin.yml` declares
  `org.freedesktop.Platform//23.08`, no `--share=network`, and only
  `xdg-data/paladin:create` plus `xdg-config/paladin:create`. No
  D-Bus or session-bus access is requested. `flatpak run io.…Cli`
  inherits the invoking terminal's stdin / stdout / stderr so
  `--json` scripting works end-to-end via the Flatpak entry point.
- **AppImage.** `linuxdeploy` assembles the AppDir; the bundled
  `AppRun` forwards argv unchanged so the AppImage is a drop-in for
  the bare binary. `paladin-<version>-x86_64.AppImage` per §11.5.
  `--appimage-extract-and-run` is the documented fallback for
  FUSE-less hosts (e.g. CI runners, headless servers).
- **Reproducible builds.** The CLI binary is part of the workspace
  build that consumes vendored deps under `vendor/` (§11.6) with
  `cargo build --locked` and `SOURCE_DATE_EPOCH` exported from the
  release tag. No build-time codegen depends on system clock,
  hostname, or network.
- **Signing.** `.deb`, `.rpm`, and AppImage artifacts are signed
  with `minisign`; the signature plus the project's published
  public key are uploaded alongside each artifact (§11.6).

## Definition of done

- All command behaviors from §5 implemented and tested via `assert_cmd`.
- `--json` schema golden-locked.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
- CLI **never** schedules a clipboard auto-clear. Verified by test.
- DESIGN.md unchanged unless a contradiction surfaces; in that case
  DESIGN.md is updated first.
