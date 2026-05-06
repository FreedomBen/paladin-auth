# Implementation Plan 02 — `paladin-cli` (`paladin`)

Source of truth: [DESIGN.md](DESIGN.md) §3-§5, §8, §10-§12
(Milestone 4), and §14 (License / SPDX header rule).
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
├── Cargo.toml            # inherits workspace metadata via per-field Cargo inheritance (description, repository, homepage, license, edition, rust-version); bin name = "paladin"
├── src/
│   ├── main.rs           # entry: parse, dispatch, exit code map
│   ├── cli.rs            # clap derive: GlobalArgs + Command enum
│   ├── output/
│   │   ├── mod.rs        # selects text vs json; no-color handling
│   │   ├── text.rs       # human renderers per command
│   │   └── json.rs       # stable JSON envelopes per §5
│   ├── prompt.rs         # /dev/tty passphrases, account prompts, and confirmations
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
│   └── select.rs         # thin wrapper around paladin_core::parse_account_query, Vault::matching_accounts, and Vault::shortest_unique_id_prefix; CLI owns only command-specific cardinality errors and rendering.
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
- `--no-color` — disables ANSI in text output; `NO_COLOR` does the same
  when the flag is absent, and ANSI is also disabled when stdout is not a TTY.
- `--json` — emits the §5 stable JSON schema. Rejected by `paladin-tui` /
  `paladin-gtk`.

`--vault` and `--no-color` are accepted by every binary; `--json` is
`paladin`-only.

## Encrypted-write KDF flags (per §5)

Commands that create new encrypted material accept the advanced Argon2id
flags from §5:

- `--kdf-memory-mib <mib>`
- `--kdf-time <iterations>`
- `--kdf-parallelism <lanes>`

They apply to `init`, `passphrase set`, `passphrase change`, and
`export --encrypted`. Omitted flags use the §4.4 defaults (`64`, `3`, `1`).
Supplied values are converted to `paladin_core::Argon2Params`
(`m_kib = mib * 1024`) and validated before the CLI inspects, opens, or
unlocks a vault, before wrong-state checks, before any prompt, and before salt
/ nonce generation. Invalid KDF input therefore wins over `vault_missing`,
`invalid_state`, unlock passphrase prompts, and new-passphrase prompts.
Out-of-range values return
`kdf_params_out_of_bounds`; invalid integers or `mib * 1024` overflow return
`validation_error` with `field` set to the hyphenated flag name without
leading dashes (`"kdf-memory-mib"`, `"kdf-time"`, or
`"kdf-parallelism"`). The `reason` is `"invalid_integer"` for parse
failures and `"overflow"` for `mib * 1024` overflow. For `init`, validation
happens before the existence pre-check and before the first passphrase prompt.
If the user then enters an empty passphrase to select plaintext storage,
valid custom KDF values are accepted but unused.

## Commands (per §5 table)

| Command                                                | Notes |
|--------------------------------------------------------|-------|
| `init [--force]`                                       | The pre-check uses `paladin_core::inspect(path)` and maps outcomes as follows: `Ok(Missing)` is a clear path; `Ok(Plaintext)`, `Ok(Encrypted)`, `Err(invalid_header)`, and `Err(unsupported_format_version)` are existing files; any other `Err(...)` (notably `io_error` from probe failures such as permission-denied) propagates verbatim rather than being reinterpreted as `vault_exists`. Without `--force`, an existing-file pre-check surfaces `vault_exists` before prompting for the new-vault passphrase. With `--force`, prints `paladin_core::format_init_force_warning(path)` in text mode before any prompt whenever the pre-check sees an existing file (Paladin or not), then calls `paladin_core::create_force` (which performs the §5 staged clobber: stages the new vault, then rotates the old file verbatim to `.bak`, overwriting any existing backup). The verbatim rotation matches `create_force`'s file-type-agnostic semantics. Accepts and validates the KDF flags above before prompting; valid custom KDF values are used only when the new-vault passphrase is non-empty. If the first passphrase entry is empty, text mode prints `paladin_core::format_plaintext_storage_warning()` before creating the plaintext vault. |
| `add` (interactive / `--uri` / manual flags / `--qr`)  | Exactly one input mode; combinations rejected at parse time. Under `--json`, interactive mode is rejected at parse time — one of `--uri`, `--qr`, or a complete manual flag set (`--label` and `--secret`, plus optional manual fields) must be supplied. |
| `list`                                                 | Account metadata only — no codes. |
| `show <query>`                                         | Advances HOTP; persists before printing. Matching queries print all matches when every match is TOTP; if any match is HOTP, requires a single match. |
| `peek <query>`                                         | Never advances. Prints all matches unconditionally. |
| `copy <query>`                                         | Advances HOTP; copies to clipboard via `arboard`. **No auto-clear.** Single-match required. |
| `remove <query>`                                       | Confirmation prompt unless `--yes`. `--yes` is required under `--json` (no confirmation prompt). Single-match required. |
| `rename <query> <new-label>`                           | Updates `updated_at`. Single-match required. |
| `passphrase set | change | remove`                     | `set` and `change` accept the KDF flags above. `passphrase remove` first verifies that the vault is encrypted. In text mode, it then prints `paladin_core::format_plaintext_storage_warning()` and confirms unless `--yes` is passed; `--yes` skips only the confirmation. `--yes` is required under `--json`. |
| `import <path> [--format <fmt>] [--on-conflict <p>]`   | Auto-detects when `--format` is omitted; forced formats are `otpauth`/`aegis`/`paladin` (encrypted bundle only)/`qr`; conflict policies are `skip` (default)/`replace`/`append`. |
| `export --plaintext <path> | --encrypted <path>`       | Refuses overwrite without `--force`; both modes write through `paladin_core::write_secret_file_atomic` and create output `0600`; plaintext export prints `paladin_core::format_plaintext_export_warning()` before writing unencrypted secrets; encrypted export accepts the KDF flags above. |
| `settings get [key] | set <key> <value>`               | CLI persists `clipboard.clear_enabled` for TUI/GUI to honor but **ignores it at runtime** for `paladin copy`. `get [key]` filters text-mode display only. The `--json` shape is always the full nested `VaultSettings`: `get` returns the current settings, and `set` returns the post-mutation settings after `apply_setting_patch` commits. |
| `tui`                                                  | `execvp` `paladin-tui`; rejects `--json`; forwards `--vault` / `--no-color`. |

## Add modes (per §5)

`paladin add` accepts exactly one of:

1. **Interactive** — no account-definition flags; prompts the user once for
   the same fields as manual mode. Label and secret are required; issuer is
   optional. The secret prompt uses hidden terminal input. Algorithm, digits,
   kind, period, and counter prompts offer the same defaults and constraints
   as the manual flags. The icon-hint prompt uses the same slug validation,
   but reserves prompt-specific tokens: it accepts an empty line to mean
   default-derive (`IconHintInput::Default`), the literal
   token `none` (case-insensitive, after Unicode-whitespace trim) to mean
   clear (`IconHintInput::Clear`), or a slug matching `[a-z0-9_-]+` up to
   64 bytes (`IconHintInput::Slug`); any other input is rejected by
   `validate_manual`. After collecting the form once, the CLI
   builds `AccountInput` and calls `paladin_core::validate_manual(input,
   now)`. Any validation error exits with that `validation_error`; the CLI
   does not loop, reprompt, or partially save.
2. `--uri <otpauth-uri>` — single URI parsed by
   `paladin_core::parse_otpauth`.
3. **Manual flags** — `--label` and `--secret` required; optional
   `--issuer`, `--algorithm sha1|sha256|sha512`, `--digits 6|7|8`,
   `--kind totp|hotp`, `--period <secs>` (TOTP-only), `--counter <u64>`
   (HOTP-only, default 0), and optionally one of `--icon-hint <slug>` or
   `--no-icon-hint` (when both are omitted, derived from issuer per §4.1).
   Defaults: TOTP, SHA1, 6, 30s. Manual fields use §4.1 validation:
   `--period` is 1..=300 seconds, `--icon-hint` matches `[a-z0-9_-]+`
   up to 64 bytes, `--icon-hint` and `--no-icon-hint` are mutually
   exclusive, and `--secret` is Base32 text.
   `--kind` is **not** inferred from `--period` or `--counter`: passing
   `--counter` without `--kind hotp` defaults to TOTP and rejects with
   `validation_error`. Passing `--period` without `--kind` is valid because
   TOTP is the default; passing `--period` with `--kind hotp` rejects.
   Explicit HOTP selection avoids silently classifying an account based on
   which optional flag the caller happened to pass.
4. `--qr <path>` — every decoded QR added; collisions use a fixed
   `--on-conflict=skip`; errors if no QR decodes.

Combining input modes rejects at parse time. Interactive prompts read from
`/dev/tty` like passphrase prompts, never from stdin/stdout. If `/dev/tty` is
unavailable for interactive account entry, exit with `io_error` and
`operation: "account_prompt"`. Under `--json`, interactive mode is
additionally rejected at parse time — one of `--uri`, `--qr`, or a complete
manual flag set (`--label` and `--secret`, plus optional manual fields) must
be supplied — mirroring the no-prompt rule on `remove --json` and
`passphrase remove --json`. Single-entry `add` rejects an existing
`(secret, issuer, label)` collision with `duplicate_account` unless
`--allow-duplicate` is passed. The collision check calls
`Vault::find_duplicate(&validated)` after parsing / validation and before
`Vault::add`, so core owns the exact secret-bearing comparison while the CLI
owns the user-facing error. `--allow-duplicate` is mutually exclusive with
`--qr` and is rejected at parse time.

## Query resolution (per §5)

`<query>` matching delegates to core. `paladin_core::parse_account_query`
parses either a case-insensitive issuer/label substring search or a validated
`id:` prefix selector; `Vault::matching_accounts` returns matching accounts in
insertion order. The substring branch uses
`paladin_core::account_matches_search`, which compares
`str::to_lowercase()` output for the query and canonical `"{issuer}:{label}"`
match key, with no Unicode normalization or locale-specific casing.

A query starting with `id:` is never treated as a substring match. It matches
against the account UUID's de-hyphenated 32-character hex form, and the prefix
after `id:` must be 8 to 32 hex characters. Shorter, longer, or non-hex
prefixes reject with the `validation_error` returned by
`paladin_core::parse_account_query`.

Candidate lists use the shortest unique `id:<hex>` form, with a minimum
prefix length of 8 hex characters, computed by
`Vault::shortest_unique_id_prefix`. `show` returns every match only when all
matches are TOTP; if any match is HOTP, it requires a single match so one
command cannot silently advance multiple HOTP counters. `peek` returns every
match unconditionally. `copy`, `remove`, and `rename` always require a single
match. The CLI owns the `no_match` / `multiple_matches` presentation errors;
core owns parsing, matching, and candidate disambiguators.

## Settings keys

`settings set` accepts the §5 dotted keys only:

| Key                       | Type | Default | Range          |
| ------------------------- | ---- | ------- | -------------- |
| `auto_lock.enabled`       | bool | `false` | n/a            |
| `auto_lock.timeout_secs`  | u32  | `300`   | `30..=86_400`  |
| `clipboard.clear_enabled` | bool | `false` | n/a            |
| `clipboard.clear_secs`    | u32  | `20`    | `5..=600`      |

Text-mode `settings get [key]` may filter to one dotted key. `--json`
always returns the full nested `VaultSettings` object — `get` returns the
current settings, and `set` returns the post-mutation settings after
`apply_setting_patch` commits — and dotted key names never appear in JSON
output. Boolean values are accepted only as lowercase `true` or `false`;
numeric settings are accepted only as base-10 `u32` strings, then validated
against the bounds above. `settings set` parses
and validates key/value pairs through `paladin_core::parse_setting_patch` and
applies the result through `Vault::apply_setting_patch` inside
`Vault::mutate_and_save`; text-mode `settings get [key]` uses
`paladin_core::parse_setting_key` for key validation. An unrecognized
dotted key (any value not in the table above) rejects with `validation_error`
(`field: "key"`, `reason: "unknown_setting"`) in both text and `--json`
modes — applies to `settings get <key>` and `settings set <key> <value>`
alike, and is enforced before any value parsing.

## Passphrase prompts

- All passphrase I/O goes through `rpassword` reading **from `/dev/tty`** in
  both text and `--json` modes. Never from stdin/stdout.
- Passphrase bytes are not trimmed, case-folded, or Unicode-normalized; only
  the line ending consumed by the terminal prompt is removed.
- Prompted **once per prompt target**: existing-vault unlock,
  encrypted-Paladin-bundle import.
- For Paladin-bundle imports the CLI calls
  `paladin_core::inspect(import_path)` before prompting: plaintext-mode
  bundles reject with
  `unsupported_plaintext_vault` immediately (no passphrase prompt), and
  only encrypted-mode bundles trigger the bundle-passphrase prompt before
  the call to `paladin_core::import::from_file`. Probe results that are not
  encrypted Paladin bundles do not consume a passphrase: a plaintext Paladin
  header returns the typed unsupported error above, while missing files,
  non-Paladin content, and forced-format mismatches continue through
  `import::from_file` so the import facade owns `read_import_file`,
  auto-detect, and `unsupported_import_format` behavior.
- Prompted **twice (must match)**: `init` with a non-empty first
  passphrase entry, `passphrase set`, `passphrase change` new passphrase,
  `export --encrypted`.
- The `export --encrypted` passphrase protects only the exported Paladin
  bundle. It is independent of the selected vault's own passphrase, which is
  still prompted once during vault unlock when the vault is encrypted.
- KDF flags for encrypted-write commands are parsed and validated before
  new-passphrase confirmation prompts or crypto material generation. For
  `init`, this happens before the first passphrase prompt; if the first entry
  is empty, the validated custom KDF values are accepted but unused.
- Empty new passphrase on the first `init` passphrase entry selects
  plaintext storage, skips confirmation, and in text mode prints
  `paladin_core::format_plaintext_storage_warning()` before creating the
  plaintext vault. Any other empty new passphrase rejects with
  `invalid_passphrase` `reason: "zero_length"`.
- Confirmation mismatch exits before mutation with `invalid_passphrase`
  `reason: "confirmation_mismatch"`.
- After any applicable KDF validation succeeds and after the selected vault
  mode has been inspected, wrong starting states for `passphrase set`,
  `passphrase change`, and `passphrase remove` surface `invalid_state` before
  the plaintext-storage warning, any new-passphrase prompt, destructive
  confirmation, or crypto material generation.
- `passphrase remove` in text mode prints the plaintext-storage warning to
  stderr only after confirming an encrypted starting state, then requires
  destructive confirmation unless `--yes` is passed. Under `--json`, `--yes`
  is required at parse time because the command must not block on a
  confirmation prompt, and the plaintext-storage advisory is suppressed
  because the caller opted in with `--yes`.
- If `/dev/tty` is unavailable for a passphrase prompt, exit with `io_error`
  and `operation: "passphrase_prompt"`.

## Non-passphrase TTY prompts

- Interactive `add` account-entry prompts read from `/dev/tty`. If `/dev/tty`
  is unavailable, exit with `io_error` and `operation: "account_prompt"`.
- Text-mode destructive confirmations (`remove` without `--yes` and
  `passphrase remove` without `--yes`) read from `/dev/tty`. If
  `/dev/tty` is unavailable, exit with `io_error` and `operation:
  "confirmation_prompt"`.
- Destructive confirmations require the exact string `yes` after trimming
  surrounding Unicode whitespace. Any other response exits before mutation
  with `validation_error` (`field: "confirmation"`,
  `reason: "declined"`). The CLI does not reprompt.
- Under `--json`, interactive `add` and missing destructive confirmation
  flags reject at parse time as `validation_error` and do not attempt to open
  `/dev/tty`.

## Import merge details

The CLI delegates content sniffing and forced-format dispatch to
`paladin_core::import::from_file`. `--format` becomes
`ImportOptions::format = Some(format)`; omitted `--format` uses `None` so the
facade auto-detects in the §4.6 fixed order: Paladin magic, image magic, Aegis
JSON shape, `otpauth://` URI text or JSON string array, then unknown.

Each import parses and validates the full input before mutating the vault. Any
invalid entry rejects the whole batch with the core error kind and
`source_index` when available. Validation warnings are collected before merge
policy is applied, so warnings for entries later skipped as duplicates still
appear in the success envelope.

Collision policy follows §5 exactly:

- `skip` keeps the existing entry and counts the source row as skipped.
- `replace` preserves the existing entry's `id` and `created_at`, replaces
  mutable fields, sets `updated_at = import_time`, and preserves the existing
  HOTP counter for HOTP-to-HOTP collisions.
- `append` inserts a new account even for an exact duplicate.

The collision check runs against the running import state, so duplicates within
one input obey the same policy. Paladin encrypted bundles preserve source
timestamps for inserted/appended rows but never insert source `AccountId`s;
non-colliding and appended Paladin rows receive fresh UUIDv4 IDs at merge time.
`Vault::import_accounts` returns `ImportReport.accounts` as `AccountId`s; the
CLI resolves those IDs back through the post-merge vault and emits §5
`AccountSummary` objects in the `import` / `add --qr` JSON success envelope.

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
- Help and version requests are success terminal paths, not syntax failures.
  With `--json`, `--help` / `-h` / subcommand help render
  `{ "help": { "command": "paladin ...", "text": "..." } }` to stdout and
  exit 0; `--version` / `-V` renders
  `{ "version": { "name": "paladin", "version": "x.y.z" } }` to stdout and
  exit 0. Text mode keeps clap's normal help/version rendering. The `help`
  `command` field is the resolved subcommand path (`"paladin"`,
  `"paladin add"`, `"paladin tui"`, and so on) with no flags and no
  trailing `--help`; the `text` field is the generated clap help text for
  that command path. Both fields are locked via insta golden snapshots so
  additions are reviewable.
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
  `init --force`, plaintext `init`, `passphrase remove --yes`, and
  plaintext-export advisories are suppressed because the caller opted in via
  `--force`, an empty `init` passphrase, `--yes`, or `--plaintext`; clap
  diagnostics are rerouted by the argv pre-scan above; help/version text is
  wrapped in JSON success documents;
  status / progress text is never emitted; and passphrase prompts read from
  `/dev/tty` via `rpassword` so prompt strings never reach stdout or stderr.
  Missing required `--yes`
  confirmation flags for `remove` and `passphrase remove` reject at
  parse time as `validation_error` rather than silently blocking on a
  prompt.
- Text-mode warnings and advisories (`short_secret`, import-collision skips,
  the `init --force` clobber advisory, the plaintext `init` advisory, the
  `passphrase remove` plaintext-storage advisory, and the plaintext-export
  advisory) are written to stderr in **text mode only**;
  under `--json`, validation warnings are routed into the success envelope's
  `warnings` array (`add` / `import`), skipped collisions are represented by
  the `skipped` count, and destructive / plaintext advisories are suppressed
  because the caller opted in with `--force`, `--yes`, or `--plaintext` per
  the rule above. `short_secret` warning messages in both text and JSON are
  rendered with `paladin_core::format_validation_warning()`.

Exit codes: `0` success; clap's default usage/parse exit for syntax errors;
`1` for Paladin runtime errors. `--json` does not change exit codes; it only
changes the error renderer for syntax/usage failures and lets the JSON
envelope carry the detailed `kind`.

## `paladin tui` exec wrapper

- Resolves `paladin-tui` via `PATH` and `execvp`s it, forwarding `--vault`
  and `--no-color` verbatim.
- `--json` is rejected at parse time when the wrapper would execute the TUI
  (TUI has no JSON mode). Help/version terminal paths are handled first by
  the CLI output rules above, so `paladin --json tui --help` emits the JSON
  help envelope instead of trying to exec `paladin-tui`.
- If `paladin-tui` is not on `PATH`, exit non-zero with `io_error`,
  `operation: "exec_paladin_tui"`.
- Flatpak limitation: the §11.4 publication ships `paladin` and
  `paladin-tui` as separate Flatpak apps
  (`org.tamx.Paladin.Cli` vs `org.tamx.Paladin.Tui`) with no
  shared `PATH` between sandboxes, so `paladin tui` inside the CLI
  Flatpak always exits with the `exec_paladin_tui` `io_error`. Flatpak
  users invoke the TUI directly via `flatpak run
  org.tamx.Paladin.Tui`. The CLI does not attempt to dispatch to
  the TUI app via `flatpak-spawn` or any portal call.
- Keeps the §3 "binaries don't reach into each other" rule intact — no
  in-process re-implementation of the TUI.

## Vault interaction pattern (CLI is stateless per DESIGN.md §8)

Every vault-opening command except `init`:

1. Resolve vault path (`--vault` or `paladin_core::default_vault_path()`).
2. `paladin_core::inspect(path)` to learn the mode.
3. If `inspect` returns `Missing`, return `vault_missing` immediately
   without prompting. If `inspect` returns any other `Err(...)` (e.g.
   `invalid_header`, `unsupported_format_version`, `io_error`, or a future
   `unsafe_permissions` once `inspect` probes permissions), propagate it
   verbatim without prompting — the CLI never falls through to step 4 with
   a known-broken file. For passphrase transition commands, the inspected
   mode is also the wrong-state gate: `passphrase set` on `Encrypted` and
   `passphrase change` / `passphrase remove` on `Plaintext` return
   `invalid_state` here, before any unlock prompt. Otherwise, if
   `Encrypted`, prompt once via `/dev/tty`. If `Plaintext`, fall through
   without prompting.
4. `paladin_core::open(path, lock)` — propagates `unsafe_permissions`;
   text mode renders the human-readable `chmod` repair string via
   `paladin_core::format_unsafe_permissions(&err)` so the CLI, TUI, and GUI
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

Commands that accept encrypted-write KDF flags (`passphrase set`,
`passphrase change`, and `export --encrypted`) run the KDF parse / conversion /
validation step after resolving the selected vault path and before step 2. A
malformed or out-of-policy KDF flag returns its KDF error before vault
existence checks, unlock prompts, wrong-state checks, or command-specific
prompts.

`init` resolves the same path. The existence pre-check calls
`paladin_core::inspect(path)` and maps outcomes as follows: `Ok(Missing)` is
the "clear path" result; `Ok(Plaintext)`, `Ok(Encrypted)`,
`Err(invalid_header)`, and `Err(unsupported_format_version)` are treated as
existing files; any other `Err(...)` (e.g. `io_error` from a probe failure
such as permission-denied, or `unsafe_permissions` if a future release adds
permission probing) propagates verbatim rather than being reinterpreted as
`vault_exists`. Without `--force`, an existing-file pre-check returns
`vault_exists` before prompting for the new-vault passphrase. When the
pre-check is clear, it prompts for the new-vault passphrase and uses
`paladin_core::create`.

`init --force` runs the same pre-check. When the pre-check sees an existing
file (Paladin header or not), text mode prints
`paladin_core::format_init_force_warning(path)` before any prompt. The
warning text names the path and `vault.bin.bak` and warns that any prior
backup will be overwritten — wording that applies uniformly because
`create_force` rotates the old file verbatim into `vault.bin.bak`
regardless of its content. The CLI then prompts for the new-vault
passphrase and calls `paladin_core::create_force` (which owns the §5
staged clobber sequence) without opening or decrypting the old file.

## Clipboard copy side effects

`copy` resolves exactly one account before generating a code. For TOTP, it
generates the current code and then attempts the clipboard write. For HOTP, it
calls `Vault::hotp_advance(store, id, now)` first, so the code is generated,
the counter is advanced, `updated_at` is set, and the vault save reaches the
primary-file commit point before the clipboard adapter receives the code. If
that save returns `save_not_committed`, no clipboard write is attempted and the
counter remains unchanged. If the clipboard write fails after a committed HOTP
advance, the CLI does not roll the counter back because the code may already
have been exposed to the clipboard provider; it exits with
`clipboard_write_failed`, including the post-advance `account` summary and the
pre-advance `counter_used`. TOTP clipboard failures use the same error kind
with `counter_used: null`.

## Implementation checklist

- [ ] Scaffold `crates/paladin-cli` with clap parsing, global flags, and
  command dispatch.
- [ ] Ensure new Rust source files include
  `// SPDX-License-Identifier: AGPL-3.0-or-later`.
- [ ] Depend on `paladin-core` with the off-by-default `error-serde`
  feature enabled so the CLI can serialize shared error kinds and the
  account-shape types referenced from §5 success / error envelopes
  (`AccountSummary`, `AccountKindSummary`, `AccountId`, `Algorithm`, `Code`,
  `ImportReport`, `ValidationWarning`, `ImportWarning`, `VaultSettings`)
  without a hand-written mapping layer for those core types. The CLI still
  builds command envelopes around them; for `import` / `add --qr`, it resolves
  `ImportReport.accounts` IDs to `AccountSummary` objects per §5. The CLI
  never serializes secret-bearing `Account` or `Secret`.
- [ ] Use `paladin_core::parse_account_query`, `Vault::matching_accounts`,
  and `Vault::shortest_unique_id_prefix` in `select.rs`; keep only the
  command-specific cardinality decisions (`show` all-TOTP vs single,
  `peek` all, `copy` / `remove` / `rename` single) and text / JSON error
  rendering in the CLI.
- [ ] Source human-facing destructive / advisory text from
  `paladin_core::format_init_force_warning(path)`,
  `paladin_core::format_plaintext_storage_warning()`, and
  `paladin_core::format_plaintext_export_warning()`; source the
  `unsafe_permissions` `chmod` repair string from
  `paladin_core::format_unsafe_permissions(&err)`; and source
  validation-warning messages from
  `paladin_core::format_validation_warning()` so the CLI cannot drift from
  the TUI / GUI wording.
- [ ] Implement `/dev/tty` passphrase, account-entry, and confirmation
  prompting with no-TTY error handling.
- [ ] Parse and validate encrypted-write KDF flags for `init`,
  `passphrase set`, `passphrase change`, and `export --encrypted`, producing
  `Argon2Params` / `EncryptionOptions` for the core calls.
- [ ] Implement the thin `select.rs` wrapper that applies CLI cardinality
  policy to the core account-query matches and converts candidates to
  `AccountSummary` plus core-computed disambiguators.
- [ ] Implement `init`, account CRUD, `show`/`peek`/`copy`, passphrase,
  import/export, and settings commands per §5. Manual-flag `add` builds
  an `AccountInput` from the parsed flags and routes it through
  `paladin_core::validate_manual(input, now)` so §4.1 validation
  (label / issuer / secret / digits / period / counter / icon-hint)
  lives in core; omitted icon flags map to `IconHintInput::Default`,
  `--icon-hint <slug>` maps to `IconHintInput::Slug`, and
  `--no-icon-hint` maps to `IconHintInput::Clear`; `--uri` routes
  through `paladin_core::parse_otpauth`;
  `--qr` routes through `paladin_core::import::from_file` with a fixed
  `ImportConflict::Skip` policy. The CLI never re-implements §4.1
  validation.
- [ ] Implement text and JSON output renderers with stable success/error
  envelopes and stderr warnings. Text rendering honors `--no-color`,
  `NO_COLOR`, and non-TTY stdout.
- [ ] Implement `paladin tui` as an `execvp` wrapper.
- [ ] Add a `paladin-cli/test-hooks` cargo feature that is **off by default**
  in production builds and enabled only by the test build of the `paladin`
  binary. `paladin-cli/test-hooks` transitively enables
  `paladin-core/test-fault-injection` so process-level integration tests
  can drive pre-commit and post-commit save failures via the
  `PALADIN_FAULT_INJECT` env var.
- [ ] Wire a test-build-only `PALADIN_CLIPBOARD_DRYRUN=1` short-circuit
  in the CLI clipboard adapter that bypasses `arboard` and records the
  intended payload, gated behind the same `paladin-cli/test-hooks` feature
  so production builds never link the hook. Lets CI exercise `copy`
  end-to-end (including the post-`hotp_advance` ordering and the
  never-schedules-auto-clear invariant) without a clipboard server. The
  env var is honored only when `paladin-cli/test-hooks` is enabled.
- [ ] Add the CLI integration tests and JSON golden snapshots below.
- [ ] Run the definition-of-done checks.

## Tests (`assert_cmd` + temp dirs + insta golden where useful)

Test invariants matter more than command count. Each test creates a fresh
temp dir, sets `--vault` to a path inside it, and asserts stdout, stderr
where relevant, and exit code.

- **`init`**: empty passphrase → plaintext file, mode `0600`, dir `0700`,
  with the plaintext-storage warning emitted in text mode.
  Non-empty passphrase → encrypted; second invocation refuses to clobber with
  `vault_exists` before prompting for a new passphrase, including when the
  existing file at the vault path is non-Paladin (unrecognized magic) — the
  pre-check treats `Ok(Plaintext)`, `Ok(Encrypted)`, `Err(invalid_header)`,
  and `Err(unsupported_format_version)` as existing. Probe failures with
  `Err(io_error)` (e.g. permission-denied reading the candidate path) are
  propagated as the underlying `io_error` instead of being reinterpreted as
  `vault_exists`. `--force` rotates the old file verbatim into `.bak` for
  both Paladin-format and non-Paladin existing files; text-mode `--force`
  emits the clobber warning whenever the pre-check sees an existing file
  (regardless of whether it is a recognized Paladin header) and skips the
  warning only when the path is clear. Custom KDF flags write the requested in-range
  Argon2 params for encrypted init; invalid / out-of-range values reject with
  the §5 error kinds before the first passphrase prompt, including stable
  `validation_error` `field` / `reason` values for invalid integer and
  overflow cases, and valid custom KDF values are accepted but unused when an
  empty passphrase selects plaintext.
  With the `paladin-cli/test-hooks` feature wired into the test build (see
  the passphrase bullet), `init --force` under `PALADIN_FAULT_INJECT=pre_commit`
  surfaces `save_not_committed` with `backup_path` set to `vault.bin.bak`
  after backup rotation, and under `PALADIN_FAULT_INJECT=post_commit`
  surfaces `save_durability_unconfirmed` with `committed: true` — covering
  the `backup_path` field called out in the JSON envelope above.
- **`init` + unsafe parent dir** → `unsafe_permissions` with `chmod` hint.
- **`add --uri`** → account appears in `list`. **`add` interactive** with
  scripted `/dev/tty` (via `script` or `pty-process` test helper), plus
  no-TTY failure as `io_error` with `operation: "account_prompt"`. Interactive
  add covers the manual-mode defaults, hidden secret entry, one-shot
  validation through `validate_manual`, and no reprompt on invalid input.
- **`add` mode-combination rejection** (e.g. `--uri` + `--qr`,
  `--qr` + `--allow-duplicate`) plus manual kind-specific validation
  (`--period` on HOTP and `--counter` on TOTP reject with
  `validation_error`) and icon-hint validation (`--icon-hint` malformed
  rejects; `--icon-hint` plus `--no-icon-hint` rejects at parse time);
  also `add --json` without an input mode (no `--uri`, no `--qr`, and no
  complete manual flag set) rejects at parse time with a JSON error envelope.
- **`add --qr`** with synthetic QR image (multi-entry path uses fixed
  `--on-conflict=skip`).
- **`add` duplicate behavior** — `Vault::find_duplicate(&validated)`
  detects `(secret, issuer, label)` collisions; the CLI rejects with
  `duplicate_account` and the existing `account` summary unless
  `--allow-duplicate` is passed.
- **`show` vs `peek` on HOTP** — `show` persists counter advance (verified
  by re-opening and re-running `peek`); `peek` does not. `show` on a
  multi-match query containing any HOTP entry rejects with
  `multiple_matches`; multi-match TOTP-only `show` prints all matches.
  `show` and `copy` on an HOTP account already at `u64::MAX` reject with
  `counter_overflow`, including the stable `account` field, before any
  save or clipboard write.
- **Query resolution** — `select.rs` delegates parsing, substring matching,
  ID-prefix matching, and shortest-unique disambiguators to
  `paladin-core`; CLI tests cover the command cardinality policy on top:
  case-insensitive `issuer:label` substring matching, empty-issuer match
  keys with the colon present, and no Unicode normalization. `id:<hex>`
  prefix routes to UUID match, never substring; prefixes shorter than 8
  hex chars, longer than 32 hex chars, or containing non-hex characters
  reject with `validation_error`.
- **`copy` writes to clipboard** — gated behind the
  `paladin-cli/test-hooks` feature because CI may not have a clipboard
  server; otherwise dry-run via a `PALADIN_CLIPBOARD_DRYRUN=1` env var
  honored only by the test build before the CLI clipboard adapter calls
  `arboard`.
  Asserts the CLI **never** schedules an auto-clear regardless of
  `clipboard.clear_enabled` in the vault. Clipboard failure after a
  committed HOTP advance returns `clipboard_write_failed` and leaves the
  persisted counter advanced; pre-commit HOTP save failure does not attempt
  a clipboard write.
- **`remove`** with and without `--yes`; no-TTY confirmation failure as
  `io_error` with `operation: "confirmation_prompt"`; `--json` without
  `--yes` rejects at parse time (no confirmation prompt). Confirmation input
  accepts only exact `yes` after whitespace trimming; any other response exits
  before mutation with `validation_error` (`field: "confirmation"`,
  `reason: "declined"`). `multiple_matches` includes `candidates` with
  `disambiguator` `id:<hex>` strings.
- **`rename`** updates `updated_at` (compared via `--json` snapshot).
- **`passphrase set/change/remove`** end-to-end against an open vault.
  `passphrase remove` covers the text-mode warning confirmation, no-TTY
  confirmation failure as `io_error` with `operation: "confirmation_prompt"`,
  and the `--yes` bypass; `--json` without
  `--yes` rejects at parse time. No-TTY prompt failures surface as
  `io_error` with `operation: "passphrase_prompt"`; confirmation mismatch
  surfaces as `invalid_passphrase` with
  `reason: "confirmation_mismatch"`. Wrong starting states (`set` on
  encrypted, `change`/`remove` on plaintext) surface the stable
  DESIGN §4.7 `invalid_state` operation/state pair before the
  unlock prompt, plaintext-storage warning, new-passphrase prompts,
  destructive confirmations, or mutation. `set` and `change` cover default
  and custom KDF params plus invalid / out-of-range flag errors, including
  stable `validation_error` `field` / `reason` values for invalid integer and
  overflow cases, and precedence cases where invalid KDF input wins before
  vault unlock prompts and wrong-state checks.
  Durability-unconfirmed is surfaced as `save_durability_unconfirmed` (with
  `committed: true`) when the post-commit fsync fails; pre-commit failure
  surfaces as `save_not_committed` with `committed: false`. Process-level CLI
  tests opt the test build of the `paladin` binary into the
  `paladin-cli/test-hooks` cargo feature (which transitively enables
  `paladin-core/test-fault-injection`); the env var
  `PALADIN_FAULT_INJECT=pre_commit|post_commit` selects which `Store`
  failure path fires so `save_not_committed` and
  `save_durability_unconfirmed` envelopes can be exercised end-to-end.
- **`import`** for each format with each `--on-conflict` policy; omitting
  `--on-conflict` defaults to `skip`. Covers auto-detection order, forced
  format errors, encrypted-Aegis unsupported errors, no-entry inputs, warning
  propagation for skipped duplicates, encrypted Paladin bundle passphrase
  prompting, plaintext Paladin vault rejection without a bundle-passphrase
  prompt, text-mode skip warnings for `--on-conflict=skip`, Paladin bundle
  fresh-ID behavior, and HOTP-to-HOTP counter preservation under `replace`.
  Atomic failure on any invalid entry.
- **`export --plaintext` / `--encrypted`** refuses overwrite without
  `--force` and writes output `0600` through
  `paladin_core::write_secret_file_atomic`. Plaintext export prints the
  unencrypted-secrets warning; encrypted export round-trips through
  `import` with an export-bundle passphrase independent of the vault unlock
  passphrase, covers default and custom KDF params, and rejects invalid /
  out-of-range KDF flags before vault existence checks, vault unlock, or
  export crypto material is generated; injected writer failures surface
  `save_not_committed` before the final rename and
  `save_durability_unconfirmed` after the final rename. Invalid integer and
  overflow cases assert the same stable KDF `validation_error` `field` /
  `reason` payloads as `init` and passphrase commands.
- **`settings get/set`** covers default values, every dotted key through
  `paladin_core::parse_setting_key` / `parse_setting_patch`, bool/u32 value
  parsing, range validation at both bounds, text-mode filtering, full
  `VaultSettings` JSON output for both `get` (current settings) and `set`
  (post-mutation settings), and
  unknown-dotted-key rejection with
  `validation_error` (`field: "key"`, `reason: "unknown_setting"`) for both
  `settings get <key>` and `settings set <key> <value>`.
- **`--json` schema snapshots** for every command success, help/version
  terminal success, every `error_kind`, and representative syntax/usage
  failures rendered as JSON when `--json` is present. Locked via `insta`.
- **`--json` stream cleanliness** — for every covered command, success
  and error: assert stdout is exactly the success JSON document plus
  one trailing newline (or empty on error) and stderr is exactly the
  failure JSON document plus one trailing newline (or empty on
  success). Specifically asserts no `short_secret` or plaintext-export
  text appears on either stream when `--json` is set, no plaintext `init`,
  `init --force`, or `passphrase remove --yes` advisory text appears under
  `--json`, no clap diagnostics appear, and a `passphrase set` invocation under
  `--json` with `/dev/tty` rerouted to the test harness keeps
  stdout/stderr byte-clean (the prompt is consumed via `/dev/tty`
  only). One test per output path (success-with-warnings via `add --uri`
  of a short-secret URI; help/version success; error-with-extra-fields
  via `multiple_matches`; clap-rerouted via an unknown subcommand;
  parse-time confirmation rejection via `remove --json` without
  `--yes`).
- **`--no-color`** disables ANSI; `NO_COLOR` env var honored; ANSI also
  disabled when stdout is not a TTY (covers the third trigger named in the
  Output section).
- **`paladin tui`** → spawns `paladin-tui` (a stub binary placed on `PATH`
  for the test asserts argv) and forwards `--vault` / `--no-color` in both
  accepted global-flag positions. `paladin tui --json` and `paladin --json
  tui` → rejected at parse time with JSON error envelopes; `paladin --json
  tui --help` emits the JSON help envelope and does not inspect `PATH`.
  Missing `paladin-tui` → `io_error` with `operation: "exec_paladin_tui"`.

## Packaging (per §11)

The CLI ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.1
(§11.1). Implementation owes the release pipeline:

- **Man page.** Generate `paladin.1` from clap via `clap_mangen`,
  driven by `cargo xtask man` so the page always tracks the live
  argument tree. The packaging configs ship it gzipped at
  `/usr/share/man/man1/paladin.1.gz` per §11.3.
- **Cargo.toml metadata.** `crates/paladin-cli/Cargo.toml` inherits
  `description`, `repository`, `homepage`, `license` (set to
  `"AGPL-3.0-or-later"` at the workspace), `edition`, and
  `rust-version` from the workspace's `[workspace.package]` table
  (defined per IMPLEMENTATION_PLAN_01_CORE.md Phase A) via per-field
  Cargo inheritance (`description.workspace = true`,
  `repository.workspace = true`, `homepage.workspace = true`, and so on)
  so `nfpm` and Flathub manifests read one source. It additionally sets
  the binary-specific `keywords` and `categories` fields locally. The
  packaging pipeline sources these values from Cargo metadata when
  building `.deb` / `.rpm` so the per-format configs in
  `packaging/deb/paladin.yaml` and `packaging/rpm/paladin.yaml`
  stay minimal. The Debian one-line description fits the conventional
  ~60-character synopsis display width (Debian Policy §5.6.13 caps the
  synopsis under 80); the long form is sourced from README.
- **Flatpak.** `packaging/flatpak/paladin.yml` declares
  `org.freedesktop.Platform//23.08`, no `--share=network`,
  filesystem access scoped to `xdg-data/paladin:create` plus
  `xdg-config/paladin:create`, and the display clipboard permissions
  required by `paladin copy`: `--socket=wayland`,
  `--socket=fallback-x11`, and `--share=ipc`. No direct D-Bus or
  session-bus access is requested.
  `flatpak run org.tamx.Paladin.Cli` inherits the invoking
  terminal's stdin / stdout / stderr so `--json` scripting works
  end-to-end via the Flatpak entry point.
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
- DESIGN.md is kept in sync with implemented CLI-visible behavior; if a
  contradiction surfaces, DESIGN.md is updated first.
