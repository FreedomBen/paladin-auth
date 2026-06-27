# Implementation Plan 02 — `paladin-auth-cli` (`paladin-auth`)

Source of truth: [DESIGN.md](DESIGN.md) §3-§5, §8, §10-§12
(Milestone 4), and §14 (License / SPDX header rule).
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

## Scope

Stateless CLI binary `paladin-auth` that opens a vault, performs one operation,
and exits. Per DESIGN.md §5 and §8, auto-lock and clipboard-clear are
TUI/GUI-only — the CLI ignores `clipboard.clear_enabled`. The CLI also
forwards `paladin-auth tui` as a thin `exec` wrapper around the `paladin-auth-tui`
binary.

## Crate layout

```
crates/paladin-auth-cli/
├── Cargo.toml            # inherits workspace metadata via per-field Cargo inheritance (description, repository, homepage, license, edition, rust-version); bin name = "paladin-auth"
├── src/
│   ├── main.rs           # entry: parse, dispatch, exit code map
│   ├── cli.rs            # clap derive: GlobalArgs + Command enum
│   ├── kdf.rs            # parses --kdf-memory-mib / --kdf-time / --kdf-parallelism into paladin_auth_core::Argon2Params / EncryptionOptions; §5 validation_error + kdf_params_out_of_bounds contract
│   ├── output/
│   │   ├── mod.rs        # selects text vs json; no-color handling
│   │   ├── text.rs       # human renderers per command
│   │   ├── json.rs       # stable JSON envelopes per §5
│   │   └── error.rs      # CliError → §5 error_kind taxonomy; renders the error envelope on stderr behind --json
│   ├── prompt.rs         # /dev/tty passphrases, account prompts, and confirmations
│   ├── exec_tui.rs       # `paladin-auth tui` → execvp paladin-auth-tui w/ flags
│   ├── vault_open.rs     # shared resolve → inspect → optional passphrase prompt → Store::open pipeline used by every read / mutate command except `init`
│   ├── clipboard.rs      # `paladin-auth copy` clipboard adapter (arboard in production, `test-hooks`-feature dryrun bypass for integration tests); never schedules auto-clear (CLI is stateless per §8)
│   ├── commands/
│   │   ├── init.rs
│   │   ├── destroy.rs    # path-targeted vault wipe; never opens / decrypts; loud-confirm + --yes; calls paladin_auth_core::destroy_vault
│   │   ├── add.rs
│   │   ├── list.rs
│   │   ├── show.rs       # advances HOTP
│   │   ├── peek.rs       # never advances
│   │   ├── copy.rs       # advances HOTP; clipboard via arboard; no auto-clear
│   │   ├── remove.rs
│   │   ├── rename.rs     # label-only positional shorthand; calls `Vault::rename`; after Phase M, `Vault::rename` itself delegates to `Vault::edit_account_metadata` in core — the CLI `rename.rs` is unchanged
│   │   ├── edit.rs       # multi-field metadata edit: --label / --issuer / --no-issuer / --icon-hint / --no-icon-hint; calls Vault::edit_account_metadata inside Vault::mutate_and_save
│   │   ├── passphrase.rs # set / change / remove subcommands
│   │   ├── import.rs     # --format otpauth/aegis/paladin-auth/qr; --on-conflict
│   │   ├── export.rs     # --plaintext / --encrypted; refuse overwrite w/o --force
│   │   └── settings.rs   # get / set
│   └── select.rs         # thin wrapper around paladin_auth_core::parse_account_query, Vault::matching_accounts, and Vault::shortest_unique_id_prefix; CLI owns only command-specific cardinality errors and rendering.
└── tests/
    ├── cli_init.rs
    ├── cli_destroy.rs              # paladin-auth destroy: confirmation grammar, --yes, --json envelope, vault_missing idempotence, symlink rejection, partial-failure envelopes
    ├── cli_add.rs
    ├── cli_show_peek_copy.rs
    ├── cli_remove_rename.rs
    ├── cli_edit.rs                 # paladin-auth edit multi-field grammar + parse-time rejection bullets (v0.2 / DESIGN §5 Milestone 9)
    ├── cli_passphrase.rs
    ├── cli_import_export.rs
    ├── cli_settings.rs
    ├── cli_global_flags.rs         # --vault, --no-color, --json
    ├── cli_exec_tui.rs             # `paladin-auth tui` shells out
    ├── cli_errors_json.rs          # error envelope per error_kind
    ├── cli_advisory_suppression.rs # cross-command sweep: text-mode advisories suppressed under --json when the caller opted in (--force / empty-init / --yes / --plaintext)
    ├── cli_json_snapshots.rs       # insta golden snapshots: per-command success envelopes, per-error_kind envelopes, --help / --version envelopes; volatile fields redacted
    └── golden/                     # snapshot fixtures for --json outputs
```

## Global flags (per §5)

- `--vault <path>` — overrides the resolved vault path.
- `--no-color` — disables ANSI in text output; `NO_COLOR` does the same
  when the flag is absent, and ANSI is also disabled when stdout is not a TTY.
- `--json` — emits the §5 stable JSON schema. Rejected by `paladin-auth-tui` /
  `paladin-auth-gtk`.

`--vault` and `--no-color` are accepted by every binary; `--json` is
`paladin-auth`-only.

## Encrypted-write KDF flags (per §5)

Commands that create new encrypted material accept the advanced Argon2id
flags from §5:

- `--kdf-memory-mib <mib>`
- `--kdf-time <iterations>`
- `--kdf-parallelism <lanes>`

They apply to `init`, `passphrase set`, `passphrase change`, and
`export --encrypted`. Omitted flags use the §4.4 defaults (`64`, `3`, `1`).
Supplied values are converted to `paladin_auth_core::Argon2Params`
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
| `init [--force]`                                       | The pre-check routes `paladin_auth_core::inspect(path)` through `paladin_auth_core::classify_init_precheck`, which returns `InitPrecheck::{ Clear, Existing, Propagate(err) }`; the CLI surfaces `vault_exists` (or, with `--force`, the clobber path) on `Existing` and propagates verbatim on `Propagate`. Without `--force`, `Existing` surfaces `vault_exists` before prompting for the new-vault passphrase. With `--force`, prints `paladin_auth_core::format_init_force_warning(path)` in text mode before any prompt whenever the pre-check returns `Existing` (Paladin Auth or not), then calls `paladin_auth_core::create_force` (which performs the §5 staged clobber: stages the new vault, then rotates the old file verbatim to `.bak`, overwriting any existing backup). The verbatim rotation matches `create_force`'s file-type-agnostic semantics. Accepts and validates the KDF flags above before prompting; valid custom KDF values are used only when the new-vault passphrase is non-empty. If the first passphrase entry is empty, text mode prints `paladin_auth_core::format_plaintext_storage_warning()` before creating the plaintext vault. |
| `destroy [--yes]`                                      | Path-targeted vault wipe (DESIGN §4.3 / §5; Milestone 10). Resolves the vault path (same `--vault` / `default_vault_path()` resolution as every other command); probes the sibling `vault.bin.bak` with `std::fs::try_exists` to populate the warning text; calls `paladin_auth_core::destroy_vault(path)`. Never opens or decrypts the vault; never runs the §4.4 KDF; never enforces the §4.3 permissions gate before unlink (a vault with drifted perms is still deletable). KDF flags reject at parse time as `validation_error` (`field: "argv"`, `reason: "kdf_flags_not_supported"`). Text mode prints `paladin_auth_core::format_destroy_warning(path, backup_present)` and prompts for the exact string `yes` (after Unicode whitespace trim); `--yes` skips the prompt and is required under `--json` (no confirmation prompt). Confirmation declines exit with `validation_error` (`field: "confirmation"`, `reason: "declined"`) before any I/O. `/dev/tty` unavailable for the confirmation prompt exits with `io_error` (`operation: "confirmation_prompt"`). On success, text mode prints `Deleted vault.` (or `Deleted vault (backup remained on disk).` when no `.bak` was present) and JSON emits `{ "destroyed": { "vault_path", "primary_deleted": true, "backup_deleted": bool } }`. `vault_missing` exits non-zero with the standard envelope (no `.bak` is touched). Symlinked primary or backup rejects before any unlink with `io_error` (`operation: "vault_file_is_symlink"` / `"backup_file_is_symlink"`). Partial outcomes (primary unlinked, backup unlink or parent `fsync` failed) surface as `io_error` with `operation: "unlink_backup_file"` or `"fsync_vault_dir"`; the error envelope adds `primary_deleted: true` and `backup_deleted: bool` so callers see the on-disk state. |
| `add` (interactive / `--uri` / manual flags / `--qr`)  | Exactly one input mode; combinations rejected at parse time. Under `--json`, interactive mode is rejected at parse time — one of `--uri`, `--qr`, or a complete manual flag set (`--label` and `--secret`, plus optional manual fields) must be supplied. |
| `list`                                                 | Account metadata plus the current TOTP code, seconds remaining in the current TOTP window, and the next TOTP code. Time is sampled once per invocation from `SystemTime::now()` and reused for every TOTP row so all rows share the same window. TOTP codes come from `Vault::totp_code(id, now)` and `Vault::totp_next_code(id, now)`; HOTP rows leave the code columns empty (`-` in text mode, `null` under `--json`) because `list` never advances or peeks an HOTP counter. |
| `show <query>`                                         | Advances HOTP; persists before printing. Matching queries print all matches when every match is TOTP; if any match is HOTP, requires a single match. |
| `peek <query>`                                         | Never advances. Prints all matches unconditionally. |
| `copy <query>`                                         | Advances HOTP; copies to clipboard via `arboard`. **No auto-clear.** Single-match required. |
| `remove <query>`                                       | Confirmation prompt unless `--yes`. `--yes` is required under `--json` (no confirmation prompt). Single-match required. |
| `rename <query> <new-label>`                           | Updates `updated_at`. Single-match required. Label-only positional shorthand for the `edit` command below; calls `Vault::rename`; after Phase M, `Vault::rename` itself delegates to `Vault::edit_account_metadata` in core — the CLI `rename.rs` is unchanged, and both commands share one core mutation path. |
| `edit <query> [--label <label>] [--issuer <issuer> \| --no-issuer] [--icon-hint <slug> \| --no-icon-hint] [--allow-duplicate] [--dry-run]` | v0.2 (DESIGN §5 Milestone 9). Multi-field non-cryptographic metadata edit; requires at least one edit flag, single-match cardinality, post-validation duplicate check. See the dedicated "Edit command (v0.2)" section below for argv shape, parse-time rejections, dispatch, and `--json` envelope. |
| `passphrase set | change | remove`                     | `set` and `change` accept the KDF flags above. `passphrase remove` first verifies that the vault is encrypted. In text mode, it then prints `paladin_auth_core::format_plaintext_storage_warning()` and confirms unless `--yes` is passed; `--yes` skips only the confirmation. `--yes` is required under `--json`. |
| `import <path> [--format <fmt>] [--on-conflict <p>]`   | Auto-detects when `--format` is omitted; forced formats are `otpauth`/`aegis`/`paladin-auth` (encrypted bundle only)/`qr`; conflict policies are `skip` (default)/`replace`/`append`. |
| `export --plaintext <path> | --encrypted <path>`       | Refuses overwrite without `--force`; both modes write through `paladin_auth_core::write_secret_file_atomic` and create output `0600`; plaintext export prints `paladin_auth_core::format_plaintext_export_warning()` before writing unencrypted secrets; encrypted export accepts the KDF flags above. |
| `qr <query> [--out <path>] [--format png\|svg\|ansi] [--module-size-px <n>] [--force]` | v0.2. Renders the resolved account's `otpauth://` URI as a QR code (DESIGN §4.6). Read-only — HOTP counters are not advanced and `updated_at` is not bumped. Single-match cardinality (like `copy` / `remove` / `rename`); ambiguous queries exit non-zero with the candidate list. With `--out`, writes PNG / SVG bytes through `paladin_auth_core::write_secret_file_atomic` (0600, refuses overwrite without `--force`); without `--out`, renders ANSI Unicode half-blocks to stdout. Default `--format` is `png` when `--out` is set and `ansi` when it is not. `--format png\|svg` without `--out` rejects at parse time as `validation_error` (`field: "out"`, `reason: "required_for_binary_format"`); `--format=ansi` together with `--out` likewise rejects at parse time as `validation_error` (`field: "format"`, `reason: "ansi_requires_no_out"`) because the Unicode half-block render is terminal-only. Under `--json`, ANSI stdout is also rejected at parse time (`field: "out"`, `reason: "required_under_json"`) so the JSON envelope owns stdout. `--module-size-px` is validated against `paladin_auth_core::QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX` before any vault work. Text mode prints `paladin_auth_core::format_plaintext_qr_export_warning()` before any pixel is rendered or written; `--json` suppresses the warning (parallel to `--force` / `--yes` / `--plaintext`). |
| `settings get [key] | set <key> <value>`               | CLI persists `clipboard.clear_enabled` for TUI/GUI to honor but **ignores it at runtime** for `paladin-auth copy`. `get [key]` filters text-mode display only. The `--json` shape is always the full nested `VaultSettings`: `get` returns the current settings, and `set` returns the post-mutation settings after `apply_setting_patch` commits. |
| `tui`                                                  | `execvp` `paladin-auth-tui`; rejects `--json`; forwards `--vault` / `--no-color`. |

## Add modes (per §5)

`paladin-auth add` accepts exactly one of:

1. **Interactive** — no account-definition flags; prompts the user once for
   the same fields as manual mode. Label and secret are required; issuer is
   optional. The secret prompt uses hidden terminal input. Algorithm, digits,
   kind, period, and counter prompts offer the same defaults and constraints
   as the manual flags. The icon-hint prompt routes its line through
   `paladin_auth_core::parse_icon_hint_token` (Default/Clear/Slug); invalid input
   is rejected by `validate_manual`. After collecting the form once, the CLI
   builds `AccountInput` and calls `paladin_auth_core::validate_manual(input,
   now)`. Any validation error exits with that `validation_error`; the CLI
   does not loop, reprompt, or partially save.
2. `--uri <otpauth-uri>` — single URI parsed by
   `paladin_auth_core::parse_otpauth`.
3. **Manual flags** — `--label` and `--secret` required; optional
   `--issuer`, `--algorithm sha1|sha256|sha512`, `--digits 6|7|8`,
   `--kind totp|hotp`, `--period <secs>` (TOTP-only), `--counter <u64>`
   (HOTP-only, default 0), and optionally one of `--icon-hint <slug>` or
   `--no-icon-hint` (when both are omitted, derived from issuer per §4.1).
   Defaults: TOTP, SHA1, 6, 30s. Manual fields use §4.1 validation:
   `--period` is 1..=300 seconds; `--icon-hint <slug>` routes
   through `paladin_auth_core::parse_icon_hint_token` so flag-mode and
   interactive-mode `add` share one grammar (empty token after
   Unicode-whitespace trim → `IconHintInput::Default`; case-insensitive
   `none` → `IconHintInput::Clear`; any other token validates as a
   §4.1 slug — `[a-z0-9_-]+` up to 64 bytes — and maps to
   `IconHintInput::Slug`); `--icon-hint` and `--no-icon-hint` are
   mutually exclusive; and `--secret` is Base32 text.
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

`<query>` matching delegates to core. `paladin_auth_core::parse_account_query`
parses either a case-insensitive issuer/label substring search or a validated
`id:` prefix selector; `Vault::matching_accounts` returns matching accounts in
insertion order. The substring branch uses
`paladin_auth_core::account_matches_search`, which compares
`str::to_lowercase()` output for the query and canonical `"{issuer}:{label}"`
match key, with no Unicode normalization or locale-specific casing.

A query starting with `id:` is never treated as a substring match. It matches
against the account UUID's de-hyphenated 32-character hex form, and the prefix
after `id:` must be 8 to 32 hex characters. Shorter, longer, or non-hex
prefixes reject with the `validation_error` returned by
`paladin_auth_core::parse_account_query`.

Candidate lists use the shortest unique `id:<hex>` form, with a minimum
prefix length of 8 hex characters, computed by
`Vault::shortest_unique_id_prefix`. `show` returns every match only when all
matches are TOTP; if any match is HOTP, it requires a single match so one
command cannot silently advance multiple HOTP counters. `peek` returns every
match unconditionally. `copy`, `remove`, `rename`, `qr`, and `edit` always
require a single match. The CLI owns the `no_match` / `multiple_matches`
presentation errors; core owns parsing, matching, and candidate
disambiguators.

## QR export command (v0.2)

`paladin-auth qr <query>` is the CLI surface for the §4.6 per-account QR
export feature. Implementation owes:

- **Argv shape.** Required positional `<query>`. Optional flags:
  - `--out <path>` — write the rendered QR to `<path>` via
    `paladin_auth_core::write_secret_file_atomic` (parity with `export
    --plaintext` / `--encrypted` 0600 / fsync / rename / overwrite
    behavior).
  - `--format png|svg|ansi` — output format. Defaults: `png` when
    `--out` is set, `ansi` when it is not. Lowercase enum strings only;
    other values reject at parse time with `validation_error`
    (`field: "format"`, `reason: "invalid_value"`).
  - `--module-size-px <n>` — `u32` pixel size per QR module on the PNG
    and SVG paths. Defaults to `paladin_auth_core::QR_MODULE_SIZE_PX_DEFAULT`.
    Validated against `QR_MODULE_SIZE_PX_MIN..=QR_MODULE_SIZE_PX_MAX`
    *before* any vault work, so an out-of-range value wins precedence
    over `vault_missing`, `unsafe_permissions`, and unlock prompts
    (parity with the encrypted-write KDF-flag precedence rule above).
    Accepted on `--format=ansi` for parser symmetry but ignored at
    render time (the terminal cell size is fixed by the renderer).
  - `--force` — required to overwrite an existing target when `--out`
    is set (parity with `export --force`). Has no effect without
    `--out`; supplying `--force` without `--out` is silently accepted
    rather than rejected, matching how `export --plaintext --force`
    with a non-existent target is a no-op gate.

- **Parse-time rejections.** Four parse-time rejections fire
  **before** vault inspection / unlock so an invalid invocation
  never prompts:
  - `--format=png` or `--format=svg` without `--out` →
    `validation_error` (`field: "out"`,
    `reason: "required_for_binary_format"`). Rationale: writing PNG
    or SVG bytes to a terminal is unhelpful — the bytes are not
    pasteable as text and the warning would scroll off.
  - `--format=ansi` together with `--out` →
    `validation_error` (`field: "format"`,
    `reason: "ansi_requires_no_out"`). Rationale per DESIGN §5:
    the Unicode half-block render is a terminal-only surface; file
    output is PNG or SVG only.
  - `--json` without `--out` → `validation_error` (`field: "out"`,
    `reason: "required_under_json"`). Rationale: §5's strict-mode
    rule says only the JSON envelope writes to stdout, and an ANSI
    QR rendering is incompatible with that contract.
  - `--module-size-px` outside the §4.7 bounds →
    `validation_error` (`field: "module_size_px"`,
    `reason: "out_of_bounds"`). Negative / non-integer / overflowing
    `u32` parse failures reject as `validation_error`
    (`field: "module_size_px"`, `reason: "invalid_integer"` or
    `"overflow"`), matching the KDF-flag pattern.

- **Single-match cardinality.** Identical to `copy` / `remove` /
  `rename`: `paladin_auth_core::parse_account_query` parses the query,
  `Vault::matching_accounts` returns matches in insertion order, and
  the CLI requires exactly one match. Zero matches exit non-zero with
  `no_match`; multiple matches exit non-zero with `multiple_matches`
  + the candidate list (each prefixed with
  `Vault::shortest_unique_id_prefix`).

- **Warning text.** Text mode prints
  `paladin_auth_core::format_plaintext_qr_export_warning()` to **stderr**
  before any pixel is rendered or written (parity with the
  plaintext-export warning routing: stderr for advisory text, stdout
  for primary output). Under `--json` the warning is **suppressed** —
  the caller opted into machine-readable output with `--out`, parallel
  to how `--force` / `--yes` / `--plaintext` suppress their
  text-mode advisories in §5's strict-mode rule.

- **Dispatch.** After parse-time validation and query resolution, the
  CLI builds `QrRenderOptions { module_size_px, quiet_zone: true }`
  and calls one of:
  - `Vault::export_qr_png(id, options)` → write `Zeroizing<Vec<u8>>`
    through `paladin_auth_core::write_secret_file_atomic(&out_path,
    &bytes)`.
  - `Vault::export_qr_svg(id, options)` → write
    `Zeroizing<String>` (as bytes) through the same writer.
  - `Vault::export_qr_ansi(id)` → write `Zeroizing<String>` to
    stdout via `Write` (no terminal control sequences; the rendered
    text already includes the half-block glyphs `qrcode`'s
    `Dense1x2` renderer emits). `--no-color` and `NO_COLOR` have no
    effect on the ANSI render (no ANSI styling escapes are emitted —
    the half-blocks are plain UTF-8 glyphs).

- **Read-only invariant.** Like `peek`, `paladin-auth qr` never opens the
  vault `mut` and never calls `Vault::mutate_and_save`. HOTP exports
  encode the current stored counter and never advance. Pinned by the
  test bullets below.

- **Overwrite gate.** When `--out` points at an existing file,
  `Path::try_exists` is probed *after* parse-time validation but
  *before* vault unlock. Existing target + no `--force` rejects
  with `validation_error` (`field: "out"`, `reason: "exists"`,
  `path: <out_path>`) — same wording family as `export --plaintext`'s
  overwrite gate. Existing target + `--force` proceeds. I/O errors on
  the `try_exists` probe default to "exists" (arming the gate) so a
  silent overwrite is the worse failure mode, matching the GTK
  `ExportDialog` rule.

- **Strict-mode under `--json`.** JSON success shape mirrors §5:
  ```json
  { "written": "/abs/path/out.png", "format": "qr_png", "account": AccountSummary }
  ```
  with `format` ∈ `{"qr_png", "qr_svg"}` (`qr_ansi` is unreachable
  because `--json` without `--out` rejects at parse time). The
  `account` field carries the resolved `AccountSummary` so JSON
  consumers can correlate the written file back to the account
  without re-querying. Failure documents use the existing
  `validation_error` / `invalid_state` / `io_error` /
  `save_not_committed` / `save_durability_unconfirmed` /
  `no_match` / `multiple_matches` envelopes. Text-mode stdout is the
  ANSI render or, with `--out`, a one-line success message
  ("Wrote QR code to /abs/path/out.png (0600, format=qr_png).");
  text-mode stderr carries the warning. Help / version JSON shapes
  are unchanged from §5.

- **Where the work lives.** All three QR renderers are
  `paladin-auth-core`-owned (`Vault::export_qr_*`). The CLI never
  re-implements URI emission, QR encoding, or PNG / SVG / ANSI
  rendering — parity with how the existing `export --plaintext` and
  `export --encrypted` paths route through
  `paladin_auth_core::export::otpauth_list` /
  `paladin_auth_core::export::encrypted` rather than constructing the
  output locally. The `qrcode` crate must not be imported by
  `crates/paladin-auth-cli/src/` (the §"Thinness contract" guard is
  extended below to enforce this; `crates/paladin-auth-cli/Cargo.toml`
  must not declare `qrcode` as a direct dep either, and the
  `[dev-dependencies]` entry stays since the existing
  `tests/cli_add.rs` already uses it as a fixture generator).

## Edit command (v0.2)

`paladin-auth edit <query>` is the CLI surface for the §4.7 / Milestone 9
multi-field non-cryptographic metadata edit. The narrower
`paladin-auth rename <query> <label>` stays as the label-only positional
shorthand; both commands ultimately mutate through the same core
`Vault::edit_account_metadata` mutator after
IMPLEMENTATION_PLAN_01_CORE.md Phase M lands (Phase M reimplements
`Vault::rename` internally to delegate to `edit_account_metadata`
without changing the CLI's `rename.rs`). Implementation owes:

- **Argv shape.** Required positional `<query>`. At least one of the
  following optional flags must be present:
  - `--label <label>` — replaces the account's label. Raw value flows
    into `AccountEdit.label = Some(value)`; §4.1 label validation
    runs in core via `validate_account_edit`.
  - `--issuer <issuer>` — sets the account's issuer. Raw value flows
    into `AccountEdit.issuer = Some(Some(value))`; §4.1 issuer
    normalization (Unicode whitespace trim; empty becomes `None`) and
    validation run in core. Passing `--issuer ""` therefore normalizes
    to `Some(None)` inside the validator and is functionally equivalent
    to `--no-issuer`; the CLI does not special-case it at parse time.
  - `--no-issuer` — clears the account's issuer. Flows into
    `AccountEdit.issuer = Some(None)`.
  - `--icon-hint <slug>` — sets the icon-hint slug. The token is
    taken **verbatim from argv** (no trim, no lowercasing, no
    CLI-side processing) and routed through
    `paladin_auth_core::parse_icon_hint_token` before populating
    `AccountEdit.icon_hint` so the empty / case-insensitive `none`
    / explicit-slug grammar matches the `add` command:
    * Empty token (`--icon-hint ""`, possibly after Unicode-
      whitespace trim) → `IconHintInput::Default`, which causes
      core to re-derive the slug from the **post-edit** issuer.
    * Case-insensitive `none` → `IconHintInput::Clear`, which
      clears the stored slug.
    * Any other token → validated as a slug per §4.1 and stored as
      `IconHintInput::Slug(token)`.
  - `--no-icon-hint` — clears the stored slug. Flows into
    `AccountEdit.icon_hint = Some(IconHintInput::Clear)`.
  - `--allow-duplicate` — opt out of the post-validation
    duplicate-account check (see below); submits the edit even if
    the resulting `(secret, issuer, label)` triple collides with
    another account. Off by default; parallel to
    `paladin-auth add --allow-duplicate`. Does not satisfy the
    "at least one editable flag" requirement on its own — passing
    `--allow-duplicate` without any of `--label` / `--issuer` /
    `--no-issuer` / `--icon-hint` / `--no-icon-hint` still rejects
    at parse time with `no_edit_fields`. Also independent of
    per-field validation: passing `--allow-duplicate` with an
    invalid edit (for example `--label ""`) still rejects with the
    typed `validation_error` before the duplicate check would be
    skipped, because validation runs before the duplicate gate.
  - `--dry-run` — runs the full pre-flight (argv parse, parse-time
    rejections, query resolution, `AccountEdit` construction,
    explicit `validate_account_edit`, `find_duplicate_after_edit`)
    and reports the **projected** post-edit outcome without
    invoking `Vault::edit_account_metadata`. The vault file is
    never written. Under `--json`, the success envelope is
    `{ "account": AccountSummary, "committed": false }` where
    `AccountSummary` is the projected post-edit account state (the
    pre-edit `Account` cloned then walked through the same
    normalization the in-mutator re-walk would apply, with
    `updated_at` set to the sampled `now`). Text mode prints
    nothing to stdout. All pre-flight rejections
    (`validation_error`, `duplicate_account`, `no_match`,
    `multiple_matches`) fire identically to a non-dry-run
    invocation; a `--dry-run --allow-duplicate` invocation skips
    only the duplicate gate, matching the non-dry-run shape.
    `--dry-run` is mutually compatible with every other edit flag.

- **Parse-time rejections.** Fire **before** vault inspection /
  unlock so an invalid invocation never prompts:
  - No-flag invocation (none of `--label` / `--issuer` /
    `--no-issuer` / `--icon-hint` / `--no-icon-hint`) →
    `validation_error` (`field: "argv"`, `reason: "no_edit_fields"`).
    Rationale per DESIGN §5: an empty edit is a no-op the CLI
    refuses to silently accept; core's `Vault::edit_account_metadata`
    also rejects an empty `AccountEdit` (`field: "edit"`,
    `reason: "empty"`), but the CLI rejects earlier so this
    rejection wins precedence over `vault_missing` and over
    passphrase prompts (parity with the QR parse-time precedence
    rule above).
  - `--issuer` together with `--no-issuer` → `validation_error`
    (`field: "argv"`, `reason: "mutually_exclusive"`).
  - `--icon-hint` together with `--no-icon-hint` →
    `validation_error` (`field: "argv"`,
    `reason: "mutually_exclusive"`).

- **Single-match cardinality.** Identical to `copy` / `remove` /
  `rename` / `qr`: `paladin_auth_core::parse_account_query` parses the
  query, `Vault::matching_accounts` returns matches in insertion
  order, and the CLI requires exactly one match. Zero matches exit
  non-zero with `no_match`; multiple matches exit non-zero with
  `multiple_matches` + the candidate list (each prefixed with
  `Vault::shortest_unique_id_prefix`). For encrypted vaults, the
  unlock passphrase prompt fires **before** candidate-set
  resolution, so `no_match` and `multiple_matches` always fire
  post-unlock — matching the prompt ordering of every other
  vault-touching command (parse-time rejections still win over the
  prompt, per the precedence rule above).

- **Duplicate-account check.** Mirrors `paladin-auth add`'s collision
  path. The CLI first calls
  `paladin_auth_core::validate_account_edit(&edit, prior, now)`
  explicitly — paralleling how `add` calls
  `paladin_auth_core::validate_manual` — and propagates any returned
  `validation_error` (`field`: `"label"` / `"issuer"` /
  `"icon_hint"`, `reason`: typed per the underlying validator)
  before the duplicate check runs. On validation success, the CLI
  calls `Vault::find_duplicate_after_edit(id, &edit)` and rejects a
  non-`None` result with `duplicate_account` (the existing
  collision's `AccountSummary` carried in the envelope's `account`
  field) **unless** `--allow-duplicate` was supplied. Pre-validating
  in the CLI is required by DESIGN.md §5 ("after per-field
  validation succeeds and before the mutator runs") and by the
  §13 (2026-05-26) EditDialog sign-off block, so a typed
  `validation_error` for an invalid edit wins precedence over
  `duplicate_account` and over any save-path error. The CLI does
  no normalization before the core call; the in-mutator re-walk
  (issuer Unicode-whitespace trim, label byte-equality projection,
  post-edit slug derivation) is canonical, and the CLI's
  `AccountEdit` builder forwards argv values verbatim. The core
  helper projects the would-be post-edit `(secret, issuer, label)`
  triple — applying §4.1 normalization to issuer and label — and
  skips the account at `id`, so an unchanged self-comparison never
  reports a collision. The check fires **before**
  `Vault::edit_account_metadata` is invoked, so a rejection leaves
  the vault byte-identical to its pre-edit state. With
  `--allow-duplicate`, the helper is not called and the mutator is
  invoked without the collision gate; the success envelope is the
  same `{ "account": AccountSummary }` shape. The duplicate-account
  check is independent of the §"Import merge details" policy —
  `edit --allow-duplicate` is the only CLI escape hatch for an
  intra-vault collision, separate from any import-time
  `--on-conflict` routing.

- **Dispatch.** After parse-time validation, query resolution, the
  explicit `validate_account_edit` call, and the
  `find_duplicate_after_edit` collision check, the CLI calls
  `Vault::edit_account_metadata(id, edit, now)` inside
  `Vault::mutate_and_save` so pre-commit save failures restore
  the in-memory pre-edit `Account` and surface `save_not_committed`.
  A no-op-but-non-empty edit (every supplied field set to the
  account's prior value) still bumps `updated_at` per the core
  mutator contract — parity with `rename` same-label semantics —
  because `AccountEdit` non-emptiness, not field-level value
  divergence, drives the timestamp update. Core's
  `validate_account_edit` re-runs inside the mutator as a
  belt-and-braces guard for programmatic `paladin-auth-core` callers
  (which may bypass the CLI-side path); the CLI's pre-call has
  already raised any typed `validation_error`. A `cfg(test)`
  bypass that skips the CLI pre-call is provided so the in-mutator
  validator path can be exercised end-to-end on the rollback
  bullet. The core-side empty-`AccountEdit` rejection is likewise
  unreachable from the CLI in production because the parse-time
  `no_edit_fields` rejection fires first.

- **Read-only invariant on secrets.** `paladin-auth edit` never calls
  `hotp_advance`, never calls `totp_code`, never decodes the stored
  secret, and never re-derives a slug from secret content. HOTP
  counters stay byte-identical across edits. Pinned by the
  `edit --label` / `edit --issuer` / `edit --icon-hint` test
  bullets and by the dedicated HOTP-counter-unchanged assertion
  below.

- **Strict-mode under `--json`.** JSON success shape:
  ```json
  { "account": AccountSummary }
  ```
  Mirrors the `rename` envelope so JSON consumers see the post-edit
  account state in one shape regardless of which CLI surface
  (`rename` or `edit`) produced the mutation. Text mode prints
  nothing to stdout on success — parity with `rename` and
  `remove --yes` — so scripts that capture stdout for the JSON
  envelope under `--json` see an empty stdout in text mode (humans
  see no noise either). Failure documents use the existing
  `validation_error` / `invalid_state` / `no_match` /
  `multiple_matches` / `duplicate_account` (with the existing
  collision's `AccountSummary` in the `account` field, mirroring
  `add`) / `save_not_committed` (no mutation, `committed: false`) /
  `save_durability_unconfirmed` (mutation committed but durability
  not confirmed, `committed: true`, optional warning) envelopes.
  The volatile `updated_at` field is redacted in
  `cli_json_snapshots.rs` golden fixtures.
  See the §"Output" exit-code matrix for the mapping from these
  envelopes to process exit codes.

- **Where the work lives.** All `AccountEdit` validation and the
  mutation itself are `paladin-auth-core`-owned (`validate_account_edit`,
  `Vault::edit_account_metadata`). The CLI never re-implements §4.1
  validation, issuer normalization, or slug derivation — parity
  with how `add` routes through `validate_manual` and how `rename`
  routes through `Vault::rename` (which itself delegates to
  `Vault::edit_account_metadata` post-Phase M). The CLI owns only:
  argv parsing, parse-time rejections, query resolution /
  cardinality, the `AccountEdit` builder, and the `--json` envelope
  rendering.

- **Validator wiring.** The explicit pre-call is
  `validate_account_edit(&edit, prior, now)` where `prior` is
  `Vault.get(id)` taken **before** the mutator runs. The CLI does
  not re-fetch `prior` after construction; the borrow is the same
  pre-mutation snapshot used to compute the duplicate projection,
  which keeps the pre-flight self-consistent against a vault that
  may be mutated by a concurrent agent between unlock and edit
  (`mutate_and_save` re-acquires the file lock and a stale
  `prior` would still be rejected inside the mutator).

- **Non-goals (v0.2).** `paladin-auth edit` deliberately does not expose
  `--counter`, `--secret`, or `--algorithm` flags. The HOTP counter,
  the secret bytes, the algorithm, the digits, the kind, and the
  TOTP period are intentionally immutable through `edit` — changing
  any of them is equivalent to creating a new account, so callers
  must use `remove` + `add` (or `import`) for those transitions.
  This keeps the `AccountEdit` contract narrow and the secret-bytes
  read-only invariant easy to audit.

- **Stateless / no auto-clear.** Per §8, the CLI is stateless and
  never schedules a clipboard wipe; `paladin-auth edit` is unaffected by
  `clipboard.clear_enabled` / `clipboard.clear_secs` and by
  `auto_lock.enabled` / `auto_lock.timeout_secs`. Those settings
  are TUI/GUI-only.

## Destroy command (Milestone 10)

`paladin-auth destroy` is the CLI surface for the §4.3 / §5 path-targeted
vault wipe. It is the inverse of `paladin-auth init` and is the in-app
escape hatch for a forgotten passphrase or drifted-perms vault. The
implementation owes:

- **Argv shape.** No positional arguments. Single optional flag:
  - `--yes` — skip the destructive-confirmation prompt. Required under
    `--json` (parallel to `passphrase remove --yes` and
    `remove --yes`).
- **Parse-time rejections.** Fire before path resolution or any I/O
  so an invalid invocation never touches disk:
  - Any KDF flag (`--kdf-memory-mib`, `--kdf-time`,
    `--kdf-parallelism`) → `validation_error` (`field: "argv"`,
    `reason: "kdf_flags_not_supported"`). Destroy runs no Argon2id
    work; surfacing KDF flags as supported would be a lie. The
    rejection wins precedence over `vault_missing` and the
    confirmation prompt, parity with the `qr` / `edit` parse-time
    precedence rules above.
  - `--json` without `--yes` → `validation_error`
    (`field: "argv"`, `reason: "confirmation_required"`).
    Matches `passphrase remove` / `remove` strict-mode wiring.
- **Pre-dispatch I/O.** After parse, the CLI:
  1. Resolves the vault path through the same `--vault` /
     `default_vault_path()` pipeline `init` and every other command
     use. A `default_vault_path()` failure surfaces as `io_error`
     (`operation: "resolve_default_vault_path"`).
  2. Probes the sibling backup with
     `std::fs::try_exists(path.with_file_name("vault.bin.bak"))`.
     The result populates the `backup_present` parameter the warning
     helper needs; an I/O error from `try_exists` (e.g. the parent
     directory is unreadable) surfaces as `io_error`
     (`operation: "stat_backup_file"`) before any warning is
     rendered. The CLI deliberately does **not** call
     `paladin_auth_core::inspect(path)` first — `inspect` reads the
     header, and destroy must work on a corrupted vault that
     `inspect` would reject. The presence of the primary at `path`
     is decided by `destroy_vault` itself (it returns
     `vault_missing` when absent).
- **Confirmation grammar.** Text mode prints
  `paladin_auth_core::format_destroy_warning(path, backup_present)` to
  stderr and prompts on `/dev/tty` for the exact string `yes`
  (after Unicode-whitespace trim). Reuses `prompt::confirm_yes`
  (the same helper backing `passphrase remove`, `remove`, and
  `init --force`). Decline → `validation_error`
  (`field: "confirmation"`, `reason: "declined"`) before any I/O.
  `/dev/tty` unavailable → `io_error`
  (`operation: "confirmation_prompt"`). `--yes` skips the prompt
  and the warning is still printed to stderr in text mode
  (parallel to `passphrase remove --yes`); under `--json` the
  warning is suppressed because the caller opted in to
  machine-readable output and the JSON envelope owns stdout.
- **Dispatch.** With confirmation cleared, the CLI calls
  `paladin_auth_core::destroy_vault(path)`. The core function performs
  the §4.3 symlink probe, primary unlink, optional backup unlink,
  and parent `fsync`. The CLI does **not** call `Store::open` or
  `inspect` before dispatch (the design contract: destroy operates
  on the path directly, even when the vault is unreadable).
- **Success rendering.**
  - Text mode: `Deleted vault.` to stdout on
    `DestroyReport { primary_deleted: true, backup_deleted: true }`;
    `Deleted vault (backup remained on disk).` when
    `backup_deleted: false` because no backup was present at probe
    time. Exit 0.
  - `--json`: `{ "destroyed": { "vault_path": "<resolved-path>",
    "primary_deleted": true, "backup_deleted": <bool> } }` on
    stdout. Exit 0. The path is the resolved absolute path the
    CLI handed to `destroy_vault`, not the literal `--vault` argv.
- **Error rendering.** All errors use the existing §5 envelope
  shapes with the `kind` discriminator and stable per-kind fields:
  - `vault_missing` — `{ "kind": "vault_missing", "path": "<path>" }`.
    Idempotent under repeat invocation: a script that runs
    `paladin-auth destroy --yes` twice sees `0`, then `vault_missing`
    on the second call. No `.bak` was touched on this path.
  - `io_error` with `operation` ∈ {
    `vault_file_is_symlink`, `backup_file_is_symlink`,
    `unlink_vault_file`, `unlink_backup_file`,
    `fsync_vault_dir`, `stat_backup_file`,
    `confirmation_prompt`, `resolve_default_vault_path` } —
    standard `io_error` envelope plus the `path` that surfaced the
    error. For the post-unlink failure modes
    (`unlink_backup_file`, `fsync_vault_dir`) the envelope also
    carries `primary_deleted: true` and `backup_deleted: <bool>`
    so JSON callers see the on-disk state without re-reading the
    filesystem. Exit non-zero.
  - `validation_error` — for parse-time rejections
    (`kdf_flags_not_supported`, `confirmation_required`) and the
    declined-confirmation path. Exit non-zero.
- **Strict-mode `--json` constraints.** No advisories on stdout
  (parallel to `passphrase remove --yes` and the QR `--json` path).
  In text mode the warning prints to stderr so stdout stays empty
  until `Deleted vault.` is emitted. Under `--json` the warning is
  suppressed entirely and only the JSON envelope appears on stdout;
  any error envelope appears on stderr per the existing §5
  stdout/stderr split.
- **Where the work lives.** The unlink + `fsync` sequence, the
  symlink defense-in-depth, and the report shape all live in
  `paladin-auth-core` (`paladin_auth_core::destroy_vault` /
  `DestroyReport`). The shared warning text lives in
  `paladin_auth_core::format_destroy_warning` so the CLI text-mode
  prompt, the TUI modal body, and the GTK dialog body render byte-
  identical wording. The CLI owns only: argv parsing, parse-time
  rejections, the backup-present probe, the confirmation prompt,
  and envelope rendering. There is no `--force` flag on `destroy`
  — the loud confirmation grammar is the only override surface;
  callers who want non-interactive destruction use `--yes`.

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
and validates key/value pairs through `paladin_auth_core::parse_setting_patch` and
applies the result through `Vault::apply_setting_patch` inside
`Vault::mutate_and_save`; text-mode `settings get [key]` uses
`paladin_auth_core::parse_setting_key` for key validation. An unrecognized
dotted key (any value not in the table above) rejects with `validation_error`
(`field: "key"`, `reason: "unknown_setting_key"`) in both text and `--json`
modes — applies to `settings get <key>` and `settings set <key> <value>`
alike, and is enforced before any value parsing.

## Passphrase prompts

- All passphrase I/O goes through `rpassword` reading **from `/dev/tty`** in
  both text and `--json` modes. Never from stdin/stdout.
- Passphrase bytes are not trimmed, case-folded, or Unicode-normalized; only
  the line ending consumed by the terminal prompt is removed.
- Prompted **once per prompt target**: existing-vault unlock,
  encrypted-Paladin Auth-bundle import.
- For Paladin Auth-bundle imports the CLI calls
  `paladin_auth_core::classify_paladin_auth_import_precheck(import_path,
  forced_format)` before prompting. `PromptForPassphrase` triggers the
  bundle-passphrase prompt before the call to
  `paladin_auth_core::import::from_file`; `Reject(err)` exits with that exact
  core error (for example `unsupported_plaintext_vault`, `invalid_header`,
  or `unsupported_format_version`) and does not prompt; `NoPrompt` consumes
  no passphrase and continues through `import::from_file` so the import
  facade owns `read_import_file`, auto-detect, and
  `unsupported_import_format` behavior. The CLI never re-implements the
  Paladin Auth header prompt decision locally.
- Prompted **twice (must match)**: `init` with a non-empty first
  passphrase entry, `passphrase set`, `passphrase change` new passphrase,
  `export --encrypted`.
- The `export --encrypted` passphrase protects only the exported Paladin Auth
  bundle. It is independent of the selected vault's own passphrase, which is
  still prompted once during vault unlock when the vault is encrypted.
- KDF flags for encrypted-write commands are parsed and validated before
  new-passphrase confirmation prompts or crypto material generation. For
  `init`, this happens before the first passphrase prompt; if the first entry
  is empty, the validated custom KDF values are accepted but unused.
- Empty new passphrase on the first `init` passphrase entry selects
  plaintext storage, skips confirmation, and in text mode prints
  `paladin_auth_core::format_plaintext_storage_warning()` before creating the
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
  stderr only after verifying an encrypted starting state, then requires
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
`paladin_auth_core::import::from_file`. `--format` becomes
`ImportOptions::format = Some(format)`; omitted `--format` uses `None` so the
facade auto-detects in the §4.6 fixed order: Paladin Auth magic, image magic, Aegis
JSON shape, `otpauth://` URI text or JSON string array, then unknown.
The only pre-facade import decision is whether an encrypted Paladin Auth bundle
needs a passphrase; that decision is delegated to
`paladin_auth_core::classify_paladin_auth_import_precheck`, not implemented in the CLI.

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
one input obey the same policy. Paladin Auth encrypted bundles preserve source
timestamps for inserted/appended rows but never insert source `AccountId`s;
non-colliding and appended Paladin Auth rows receive fresh UUIDv4 IDs at merge time.
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
  `{ "help": { "command": "paladin-auth ...", "text": "..." } }` to stdout and
  exit 0; `--version` / `-V` renders
  `{ "version": { "name": "paladin-auth", "version": "x.y.z" } }` to stdout and
  exit 0. Text mode keeps clap's normal help/version rendering. The `help`
  `command` field is the resolved subcommand path (`"paladin-auth"`,
  `"paladin-auth add"`, `"paladin-auth tui"`, and so on) with no flags and no
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
- Under `--json`, `paladin-auth` writes **only** the JSON envelope: the
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
  rendered with `paladin_auth_core::format_validation_warning()`.

Exit codes: `0` success; clap's default usage/parse exit for syntax errors;
`1` for Paladin Auth runtime errors. `--json` does not change exit codes; it only
changes the error renderer for syntax/usage failures and lets the JSON
envelope carry the detailed `kind`.

## `paladin-auth tui` exec wrapper

- Resolves `paladin-auth-tui` via `PATH` and `execvp`s it, forwarding `--vault`
  and `--no-color` verbatim.
- `--json` is rejected at parse time when the wrapper would execute the TUI
  (TUI has no JSON mode). Help/version terminal paths are handled first by
  the CLI output rules above, so `paladin-auth --json tui --help` emits the JSON
  help envelope instead of trying to exec `paladin-auth-tui`.
- If `paladin-auth-tui` is not on `PATH`, exit non-zero with `io_error`,
  `operation: "exec_paladin_auth_tui"`.
- Flatpak limitation: the §11.4 publication ships `paladin-auth` and
  `paladin-auth-tui` as separate Flatpak apps
  (`org.tamx.PaladinAuth.Cli` vs `org.tamx.PaladinAuth.Tui`) with no
  shared `PATH` between sandboxes, so `paladin-auth tui` inside the CLI
  Flatpak always exits with the `exec_paladin_auth_tui` `io_error`. Flatpak
  users invoke the TUI directly via `flatpak run
  org.tamx.PaladinAuth.Tui`. The CLI does not attempt to dispatch to
  the TUI app via `flatpak-spawn` or any portal call.
- Keeps the §3 "binaries don't reach into each other" rule intact — no
  in-process re-implementation of the TUI.

## Vault interaction pattern (CLI is stateless per DESIGN.md §8)

Every vault-opening command except `init`:

1. Resolve vault path (`--vault` or `paladin_auth_core::default_vault_path()`).
2. `paladin_auth_core::inspect(path)` to learn the mode.
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
4. `paladin_auth_core::open(path, lock)` — propagates `unsafe_permissions`;
   text mode renders the human-readable `chmod` repair string via
   `paladin_auth_core::format_unsafe_permissions(&err)` so the CLI, TUI, and GUI
   share a single source of wording.
5. Perform the operation. For `show`/`peek`/`copy` on TOTP, call
   `Vault::totp_code` — it is read-only and does not touch `&Store`. For
   `show`/`copy` on HOTP, call `hotp_advance` (which persists before
   returning). For `peek` on HOTP, call `hotp_peek`. Other mutating vault
   operations use `Vault::mutate_and_save` so pre-commit save failures
   restore the in-memory pre-attempt state before the command renders its
   error.
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

`init` resolves the same path. The existence pre-check routes
`paladin_auth_core::inspect(path)` through `paladin_auth_core::classify_init_precheck`,
which returns `InitPrecheck::{ Clear, Existing, Propagate(err) }`; the CLI
treats `Propagate` as a verbatim error and never reinterprets it as
`vault_exists`. Without `--force`, `Existing` returns `vault_exists` before
prompting for the new-vault passphrase. When the pre-check returns `Clear`,
it prompts for the new-vault passphrase and uses `paladin_auth_core::create`.

`init --force` runs the same pre-check. When the pre-check returns
`Existing` (Paladin Auth header or not), text mode prints
`paladin_auth_core::format_init_force_warning(path)` before any prompt. The
warning text names the path and `vault.bin.bak` and warns that any prior
backup will be overwritten — wording that applies uniformly because
`create_force` rotates the old file verbatim into `vault.bin.bak`
regardless of its content. The CLI then prompts for the new-vault
passphrase and calls `paladin_auth_core::create_force` (which owns the §5
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

- [x] Scaffold `crates/paladin-auth-cli` with clap parsing, global flags, and
  command dispatch.
- [x] Ensure new Rust source files include
  `// SPDX-License-Identifier: AGPL-3.0-or-later`.
- [x] Depend on `paladin-auth-core` with the off-by-default `error-serde`
  feature enabled so the CLI can serialize shared error kinds and the
  account-shape types referenced from §5 success / error envelopes
  (`AccountSummary`, `AccountKindSummary`, `AccountId`, `Algorithm`, `Code`,
  `ImportReport`, `ValidationWarning`, `ImportWarning`, `VaultSettings`)
  without a hand-written mapping layer for those core types. The CLI still
  builds command envelopes around them; for `import` / `add --qr`, it resolves
  `ImportReport.accounts` IDs to `AccountSummary` objects per §5. The CLI
  never serializes secret-bearing `Account` or `Secret`.
- [x] Use `paladin_auth_core::parse_account_query`, `Vault::matching_accounts`,
  and `Vault::shortest_unique_id_prefix` in `select.rs`; keep only the
  command-specific cardinality decisions (`show` all-TOTP vs single,
  `peek` all, `copy` / `remove` / `rename` single) and text / JSON error
  rendering in the CLI.
- [x] Source human-facing destructive / advisory text from
  `paladin_auth_core::format_init_force_warning(path)`,
  `paladin_auth_core::format_plaintext_storage_warning()`, and
  `paladin_auth_core::format_plaintext_export_warning()`; source the
  `unsafe_permissions` `chmod` repair string from
  `paladin_auth_core::format_unsafe_permissions(&err)`; and source
  validation-warning messages from
  `paladin_auth_core::format_validation_warning()` so the CLI cannot drift from
  the TUI / GUI wording.
- [x] Implement `/dev/tty` passphrase, account-entry, and confirmation
  prompting with no-TTY error handling.
- [x] Parse and validate encrypted-write KDF flags for `init`,
  `passphrase set`, `passphrase change`, and `export --encrypted`, producing
  `Argon2Params` / `EncryptionOptions` for the core calls.
- [x] Use `paladin_auth_core::classify_paladin_auth_import_precheck` before any
  encrypted-Paladin Auth-bundle prompt so plaintext/malformed Paladin Auth headers and
  non-Paladin Auth fallthrough behavior stay shared with the TUI and GUI.
- [x] Implement the thin `select.rs` wrapper that applies CLI cardinality
  policy to the core account-query matches and converts candidates to
  `AccountSummary` plus core-computed disambiguators.
- [x] Implement `init`, account CRUD, `show`/`peek`/`copy`, passphrase,
  import/export, and settings commands per §5. Manual-flag `add` builds
  an `AccountInput` from the parsed flags and routes it through
  `paladin_auth_core::validate_manual(input, now)` so §4.1 validation
  (label / issuer / secret / digits / period / counter / icon-hint)
  lives in core; omitted icon flags map to `IconHintInput::Default`,
  `--icon-hint <slug>` routes through
  `paladin_auth_core::parse_icon_hint_token` (empty token →
  `IconHintInput::Default`, case-insensitive `none` →
  `IconHintInput::Clear`, any other token validates as a §4.1 slug
  and maps to `IconHintInput::Slug`), and `--no-icon-hint` maps to
  `IconHintInput::Clear`; `--uri` routes
  through `paladin_auth_core::parse_otpauth`;
  `--qr` routes through `paladin_auth_core::import::from_file` with a fixed
  `ImportConflict::Skip` policy. The CLI never re-implements §4.1
  validation.
- [x] Implement text and JSON output renderers with stable success/error
  envelopes and stderr warnings. Text rendering honors `--no-color`,
  `NO_COLOR`, and non-TTY stdout.
- [x] Implement `paladin-auth tui` as an `execvp` wrapper.
- [x] Add a `paladin-auth-cli/test-hooks` cargo feature that is **off by default**
  in production builds and enabled only by the test build of the `paladin-auth`
  binary. `paladin-auth-cli/test-hooks` transitively enables
  `paladin-auth-core/test-fault-injection` so process-level integration tests
  can drive pre-commit and post-commit save failures via the
  `PALADIN_AUTH_FAULT_INJECT` env var.
- [x] Wire a test-build-only `PALADIN_AUTH_CLIPBOARD_DRYRUN=1` short-circuit
  in the CLI clipboard adapter that bypasses `arboard` and records the
  intended payload, gated behind the same `paladin-auth-cli/test-hooks` feature
  so production builds never link the hook. Lets CI exercise `copy`
  end-to-end (including the post-`hotp_advance` ordering and the
  never-schedules-auto-clear invariant) without a clipboard server. The
  env var is honored only when `paladin-auth-cli/test-hooks` is enabled.
- [x] Add the CLI integration tests and JSON golden snapshots below.
  Tracked at the bullet level in the Tests checklist; this top-level
  item only ticks once every Tests sub-bullet is checked.
- [x] **v0.2 — `paladin-auth qr <query>` command** per the §"QR export
  command (v0.2)" section above and DESIGN §4.6 / §5 / §10.
  - [x] Add the `qr` subcommand to the clap derive enum with the
    `<query>` positional, `--out`, `--format`, `--module-size-px`,
    and `--force` flags. The flags are parsed and validated before
    any vault-touching call so the four parse-time rejections
    (binary-without-`--out`, `ansi`-with-`--out`,
    `--json`-without-`--out`, `--module-size-px` out of bounds)
    fire first.
  - [x] Build a thin dispatch handler that resolves `<query>`
    through `paladin_auth_core::parse_account_query` +
    `Vault::matching_accounts` with single-match cardinality (same
    helper as `copy` / `remove` / `rename`), then calls one of
    `Vault::export_qr_png` / `Vault::export_qr_svg` /
    `Vault::export_qr_ansi`. The CLI never re-implements URI
    emission, QR encoding, or PNG / SVG / ANSI rendering.
  - [x] Route the `--out` write through
    `paladin_auth_core::write_secret_file_atomic`. The overwrite gate
    fires *after* parse-time validation and query resolution but
    *before* the write itself — failure surfaces as
    `validation_error` (`field: "out"`, `reason: "exists"`,
    `path`).
  - [x] Render the QR-export warning in text mode from
    `paladin_auth_core::format_plaintext_qr_export_warning()` to stderr
    *before* any pixel reaches stdout or the destination file.
    Suppress under `--json`, parallel to the `--force` / `--yes` /
    `--plaintext` strict-mode rule in §5.
  - [x] Wire the JSON success shape
    `{ "written": "...", "format": "qr_png|qr_svg", "account": AccountSummary }`
    through the existing `error-serde` envelope serializer so
    JSON consumers can correlate the written file back to the
    resolved account without re-querying.
  - [x] Add `qr` to the `--help` / `--version` JSON help shape
    enumeration so help requests for `paladin-auth qr` carry the
    correct `{ "help": { "command": "paladin-auth qr", "text": "..." } }`
    payload per §5. (Automatic via the clap subcommand tree walked
    by `output::help::resolve_command_path`.)
  - [x] Extend the §"Thinness contract" guard to forbid direct
    `qrcode` imports in `crates/paladin-auth-cli/src/` and to forbid
    `qrcode` as a regular `[dependencies]` entry in
    `crates/paladin-auth-cli/Cargo.toml` (the existing dev-dep entry
    used by `tests/cli_add.rs` stays). Enforced by
    `tests/cli_qr.rs::deny_qrcode_in_runtime_deps`. All QR work
    routes through `paladin-auth-core`.
- [x] **v0.2 — `paladin-auth edit <query>` command** per the §"Edit
  command (v0.2)" section above and DESIGN §5 / §4.7 Milestone 9.
  Depends on IMPLEMENTATION_PLAN_01_CORE.md Phase M
  (`AccountEdit`, `validate_account_edit`,
  `Vault::edit_account_metadata`, `Vault::find_duplicate_after_edit`).
  - [x] Add the `edit` subcommand to the clap derive enum with the
    `<query>` positional and the `--label` / `--issuer` /
    `--no-issuer` / `--icon-hint` / `--no-icon-hint` /
    `--allow-duplicate` / `--dry-run` flags. The flags are parsed
    and validated before any vault-touching call so the parse-time
    rejections (`no_edit_fields`, `mutually_exclusive`) fire first
    and never prompt. `--allow-duplicate` alone does not satisfy the
    "at least one editable flag" requirement (a no-edit-field
    invocation still rejects with `no_edit_fields`).
  - [x] Wire `--dry-run` so it runs the full pre-flight (parse-time
    rejections, query resolution, `AccountEdit` construction,
    explicit `validate_account_edit`, `find_duplicate_after_edit`)
    and short-circuits **before** `Vault::edit_account_metadata`
    is invoked, emitting the
    `{ "account": AccountSummary, "committed": false }` envelope
    under `--json` (text mode is silent). The projected
    `AccountSummary` is built by cloning the pre-edit `Account`,
    applying the in-mutator re-walk in-memory, and stamping the
    sampled `now` into `updated_at`. The vault file is never
    written.
  - [x] Build a thin dispatch handler that resolves `<query>`
    through `paladin_auth_core::parse_account_query` +
    `Vault::matching_accounts` with single-match cardinality (same
    helper as `copy` / `remove` / `rename` / `qr`), constructs an
    `AccountEdit` from the parsed flags (routing
    `--icon-hint <slug>` through
    `paladin_auth_core::parse_icon_hint_token` so the empty / `none` /
    slug grammar matches `add`), and calls
    `Vault::edit_account_metadata` inside `Vault::mutate_and_save`.
    The CLI never re-implements §4.1 validation, issuer
    normalization, or slug derivation.
  - [x] Implement the post-validation duplicate-account check via
    `Vault::find_duplicate_after_edit(id, &edit)` between
    `AccountEdit` construction and `Vault::mutate_and_save`,
    skipped when `--allow-duplicate` is supplied. On a non-`None`
    result, surface `duplicate_account` with the existing
    collision's `AccountSummary` in the envelope's `account` field
    (parallel to the `paladin-auth add` collision path) and leave the
    vault byte-identical to its pre-edit state. The CLI never
    re-implements the byte-for-byte comparison — core owns the
    helper and the §4.1 normalization that feeds it.
  - [x] Wire the JSON success shape `{ "account": AccountSummary }`
    through the existing `error-serde` envelope serializer so
    `--json` callers see the post-edit account state in one shape
    that mirrors `rename`.
  - [x] Add `edit` to the `--help` / `--version` JSON help shape
    enumeration so help requests for `paladin-auth edit` carry the
    correct `{ "help": { "command": "paladin-auth edit", "text": "..." } }`
    payload per §5. (Automatic via the clap subcommand tree walked
    by `output::help::resolve_command_path`; the `cli_json_snapshots.rs`
    golden snapshot adds the `paladin-auth edit` help envelope.)
  - [x] Confirm `paladin-auth rename` keeps its existing behavior and
    test inventory once `Vault::rename`'s Phase M internal refactor
    lands. The CLI `rename.rs` is unchanged; the parity is pinned by
    the existing `cli_remove_rename.rs` bullets continuing to pass.
- [x] **`paladin-auth destroy [--yes]` command** per the §"Destroy command
  (Milestone 10)" section above and DESIGN §4.3 / §5 / Milestone 10.
  Depends on `paladin_auth_core::destroy_vault`, `DestroyReport`, and
  `format_destroy_warning` landing in `paladin-auth-core` (Milestone 10
  core bullet).
  - [x] Add the `destroy` subcommand to the clap derive enum with the
    sole optional `--yes` flag (`DestroyArgs` also flattens `KdfArgs`
    so the KDF flags parse and can be rejected in-handler — there is
    no global KDF arg). KDF flags reject at parse time as
    `validation_error` (`field: "argv"`,
    `reason: "kdf_flags_not_supported"`); `--json` without `--yes`
    rejects at parse time as `validation_error` (`field: "argv"`,
    `reason: "confirmation_required"`). Both rejections fire before
    any I/O so an invalid invocation never touches disk.
  - [x] Build a thin dispatch handler that resolves the vault path
    (same `--vault` / `default_vault_path()` pipeline as every other
    command), probes the sibling `vault.bin.bak` via
    `Path::try_exists` to populate `backup_present` (mapping any
    I/O error to `io_error` (`operation: "stat_backup_file"`)),
    renders `paladin_auth_core::format_destroy_warning(path,
    backup_present)` to stderr in text mode, runs
    `prompt::prompt_destructive_confirmation` (the same helper backing
    `passphrase remove` and `remove`), and calls
    `paladin_auth_core::destroy_vault(path)`. The CLI never calls
    `Store::open` or `inspect` before dispatch — destroy operates
    on the path directly even when the vault is unreadable.
  - [x] Render text-mode success as `Deleted vault.` or `Deleted
    vault (backup remained on disk).` (the latter when
    `DestroyReport.backup_deleted == false`) to stdout, and JSON
    success as `{ "destroyed": { "vault_path", "primary_deleted":
    true, "backup_deleted": <bool> } }` with `vault_path` set to the
    resolved absolute path. Error envelopes reuse the existing §5
    `vault_missing`, `io_error`, and `validation_error` shapes; the
    `vault_missing` / `io_error` envelopes carry the resolved `path`
    (threaded by the `CliError::DestroyVaultMissing` /
    `CliError::DestroyIo` variants in `output::error`), and for
    `unlink_backup_file` / `fsync_vault_dir` the envelope adds
    `primary_deleted: true` and `backup_deleted: <bool>` so JSON
    callers see the on-disk state without re-reading the
    filesystem.
  - [x] Wire the strict-mode `--json` advisory suppression so the
    destroy warning is rendered to stderr in text mode but suppressed
    under `--json` (parallel to `--force` / `--yes` / `--plaintext`).
    The cross-command `cli_advisory_suppression.rs` sweep gains a
    destroy bullet.
  - [x] Add `destroy` to the `--help` / `--version` JSON help shape
    enumeration so help requests for `paladin-auth destroy` carry the
    correct `{ "help": { "command": "paladin-auth destroy", "text": "..." } }`
    payload per §5. (Automatic via the clap subcommand tree walked
    by `output::help::resolve_command_path`; the
    `cli_json_snapshots.rs` golden snapshot adds the `paladin-auth
    destroy` help envelope.)
- [x] Run the definition-of-done checks (ticks only when every
  Tests sub-bullet is also ticked).

## Tests (`assert_cmd` + temp dirs + insta golden where useful)

Test invariants matter more than command count. Each test creates a fresh
temp dir, sets `--vault` to a path inside it, and asserts stdout, stderr
where relevant, and exit code.

The checklist below tracks coverage at the bullet / sub-bullet level. A
ticked box means at least one named `#[test]` in the indicated file
asserts the behavior end-to-end. Items tagged `[PTY]` require a scripted
`/dev/tty` harness (e.g. `rexpect` / `pty-process`) which lands as a
shared test helper before the encrypted-vault and prompt-driven bullets
can be ticked.

### `init` (`tests/cli_init.rs`)

- [x] `[PTY]` Empty passphrase creates a plaintext file with mode `0600`,
  parent dir `0700`, and the plaintext-storage warning on stderr in text
  mode.
- [x] `[PTY]` Non-empty passphrase creates an encrypted vault.
- [x] Second invocation without `--force` rejects with `vault_exists`
  before prompting (Plaintext existing file).
- [x] `vault_exists` pre-check covers `Encrypted`, `invalid-header`, and
  `unsupported-format-version` existing files (all map to
  `InitPrecheck::Existing`).
- [x] `InitPrecheck::Propagate` (e.g. permission-denied `io_error`)
  propagates verbatim and is **not** rewritten as `vault_exists`.
- [x] `[PTY]` `--force` rotates the existing file into `vault.bin.bak`
  for Paladin Auth-format and non-Paladin Auth existing files alike, overwriting
  any prior backup.
- [x] `[PTY]` Text-mode `--force` emits the clobber warning whenever the
  pre-check returns `Existing` and suppresses it on `Clear`.
- [x] `[PTY]` Custom KDF flags write the requested in-range Argon2 params
  for encrypted `init`.
- [x] Invalid / out-of-range KDF flag values reject before the first
  passphrase prompt with stable `validation_error` `field` / `reason`
  payloads for `invalid_integer` and `overflow` cases, plus
  `kdf_params_out_of_bounds` for in-range-syntax / out-of-policy values.
- [x] KDF-flag rejection wins over `vault_exists` (precedence with and
  without `--force`).
- [x] `[PTY]` Valid custom KDF flags are accepted but unused when an
  empty passphrase selects plaintext storage.
- [x] `[PTY]` `init --force` under `PALADIN_AUTH_FAULT_INJECT=pre_commit`
  surfaces `save_not_committed` with `backup_path` set to `vault.bin.bak`
  after backup rotation.
- [x] `[PTY]` `init --force` under `PALADIN_AUTH_FAULT_INJECT=post_commit`
  surfaces `save_durability_unconfirmed` with `committed: true`.
- [x] `[PTY]` `init` + unsafe parent dir surfaces `unsafe_permissions`
  with `subject: "vault_dir"` and the §4.3 `chmod` repair hint in text
  mode (sourced from `paladin_auth_core::format_unsafe_permissions`). The
  perm check fires inside `Store::create*` after the new-passphrase
  prompt, so this case requires the PTY harness even though the §5
  precedence rule itself is non-prompt.

### `add` (`tests/cli_add.rs`)

- [x] `add --uri` succeeds and the account appears in `list`.
- [x] `[PTY]` Interactive `add` reads the manual fields once from
  `/dev/tty` (hidden secret entry, manual-mode defaults), routes them
  through `validate_manual`, and never reprompts on invalid input.
- [x] `[PTY]` Interactive `add` with no `/dev/tty` exits with `io_error`
  `operation: "account_prompt"`.
- [x] Mode combinations reject at parse time: `--uri` + `--qr`,
  `--qr` + `--allow-duplicate`, `--icon-hint` + `--no-icon-hint`,
  `--uri` + manual flags.
- [x] Manual `--period` with `--kind hotp` rejects with
  `validation_error`.
- [x] Manual `--counter` without `--kind hotp` rejects with
  `validation_error`.
- [x] Manual `--icon-hint` with a malformed slug rejects with
  `validation_error`.
- [x] `add --json` with no input mode (no `--uri`, no `--qr`, no
  complete manual flag set) rejects at parse time with a JSON
  `validation_error` envelope.
- [x] `add --qr` against a synthetic multi-entry QR image uses fixed
  `--on-conflict=skip` and emits the §5 `import`-shaped success envelope.
- [x] Duplicate `(secret, issuer, label)` rejects with
  `duplicate_account` plus the existing `account` summary.
- [x] `--allow-duplicate` appends a second account when the duplicate
  check would have rejected.
- [x] Short-secret `add --uri` surfaces a `short_secret` warning in the
  JSON `warnings` array (and in stderr in text mode).

### `list` (`tests/cli_list.rs`)

- [x] Empty vault returns `{ "accounts": [] }` under `--json`.
- [x] Empty vault produces no rows in text mode.
- [x] Populated vault returns insertion-order `AccountSummary` values
  with no secret bytes.
- [x] HOTP and TOTP rows expose the kind-specific `period` /
  `counter` shape from §5 (`period` set + `counter: null` for TOTP,
  vice versa for HOTP).
- [x] TOTP rows under `--json` carry a non-null `code` (string of
  `digits` characters), a `seconds_remaining` integer in
  `1..=period`, and a `next_code` string distinct from `code`.
- [x] HOTP rows under `--json` carry `code: null`,
  `seconds_remaining: null`, and `next_code: null` — `list` never
  advances or peeks an HOTP counter.
- [x] TOTP rows in text mode include the current code, a
  `<seconds_remaining>s` field, and the next code as three tab columns
  between the period column and the label.
- [x] HOTP rows in text mode render the three new code columns as
  `-` so the column count matches TOTP rows.

### `show` / `peek` / `copy` (`tests/cli_show_peek_copy.rs`)

- [x] `show` on a single HOTP match advances the counter and persists
  before printing.
- [x] `peek` on a single HOTP match never advances.
- [x] `peek` after `show` reflects the post-advance counter without
  advancing further.
- [x] `show` on a multi-match query containing any HOTP entry rejects
  with `multiple_matches`.
- [x] `show` on a multi-match TOTP-only query prints one row per match
  in insertion order.
- [x] `show` on a multi-match query unconditionally returns all rows
  for `peek`.
- [x] `show` on an HOTP account already at `u64::MAX` rejects with
  `counter_overflow` (with `account`) before any save.
- [x] `copy` on an HOTP account already at `u64::MAX` rejects with
  `counter_overflow` before any clipboard write.
- [x] `id:<hex>` prefix selects a unique account even when the
  substring branch would also match (no substring fallback).
- [x] `id:<hex>` prefix shorter than 8 hex chars rejects with
  `validation_error`.
- [x] `id:<hex>` prefix longer than 32 hex chars rejects with
  `validation_error`.
- [x] `id:<hex>` prefix with non-hex characters rejects with
  `validation_error`.
- [x] Case-insensitive `issuer:label` substring matching is asserted at
  the CLI level (empty-issuer match keys carry the colon, no Unicode
  normalization).
- [x] `copy` clipboard tests are gated behind the `test-hooks` feature
  and use `PALADIN_AUTH_CLIPBOARD_DRYRUN=1` to bypass `arboard`.
- [x] `copy` ignores `clipboard.clear_enabled` in the vault (never
  schedules an auto-clear).
- [x] `copy` clipboard failure on TOTP returns `clipboard_write_failed`
  with `counter_used: null`.
- [x] `copy` clipboard failure on HOTP leaves the persisted counter
  advanced and reports the pre-advance `counter_used`.
- [x] Pre-commit HOTP save failure during `copy` does **not** attempt a
  clipboard write.

### `remove` / `rename` (`tests/cli_remove_rename.rs`)

- [x] `remove --yes` succeeds and emits the `removed` envelope.
- [x] `[PTY]` `remove` without `--yes` reads the confirmation from
  `/dev/tty`.
- [x] `[PTY]` `remove` confirmation accepts only exact `yes` after
  whitespace trim; any other response exits with `validation_error`
  (`field: "confirmation"`, `reason: "declined"`).
- [x] `[PTY]` `remove` with no `/dev/tty` surfaces `io_error`
  `operation: "confirmation_prompt"`.
- [x] `remove --json` without `--yes` rejects at parse time with a
  `validation_error` envelope (no confirmation prompt).
- [x] `remove` `multiple_matches` envelope includes `candidates` with
  `disambiguator` `id:<hex>` strings.
- [x] `remove` `id:<hex>` prefix selects a unique account even with
  substring collisions.
- [x] `rename` succeeds and emits the post-rename `account` envelope.
- [x] `rename` bumps `updated_at` above `created_at`.
- [x] `rename` with an invalid label propagates a core
  `validation_error`.

### `edit` (`tests/cli_edit.rs`)

v0.2 (DESIGN §5 Milestone 9; depends on
IMPLEMENTATION_PLAN_01_CORE.md Phase M).

- [x] `edit --label <new>` succeeds and emits the
  `{ "account": AccountSummary }` envelope with the bumped
  `updated_at`; the persisted vault round-trip-reads the new label
  and the prior issuer / icon_hint untouched.
- [x] `edit --issuer <new>` succeeds, normalizing whitespace per
  §4.1 (normalization is applied by core's `validate_account_edit`,
  not the CLI); the persisted vault round-trip-reads the new issuer
  and the prior label / icon-hint slug untouched. When no
  `--icon-hint` / `--no-icon-hint` is supplied, the stored slug stays
  as-is even if the issuer changed (`AccountEdit.icon_hint = None` is
  leave-untouched — the CLI does **not** silently re-derive a default
  from the new issuer; that behavior requires explicitly passing
  `--icon-hint ""` so `parse_icon_hint_token` maps the empty token to
  `IconHintInput::Default` and core re-derives from the post-edit
  issuer).
- [x] `edit --no-issuer` clears the issuer (`AccountSummary.issuer
  == null` in JSON; bare label in text); the prior label /
  icon_hint stay untouched.
- [x] `edit --issuer ""` normalizes to `Some(None)` via core's §4.1
  issuer normalization (Unicode whitespace trim → empty → `None`),
  producing the same end-state as `edit --no-issuer`. Pinned by
  reading the persisted `AccountSummary.issuer == null`.
- [x] **Byte-equivalence**: persisted vault bytes after
  `edit --issuer ""` and after `edit --no-issuer` (against the same
  pre-edit state, sampled with the same `now`) compare byte-for-byte
  identical — confirms both flag forms collapse to the same
  `AccountEdit::issuer = Some(None)` state after core's
  normalization. (Asserted via per-field equality of the listed
  AccountSummary; raw byte parity is not stable because `now` is
  re-sampled per invocation.)
- [x] Invalid `--issuer` (overlong, e.g. >128 UTF-8 bytes per §4.1)
  propagates a core `validation_error` (`field: "issuer"`,
  `reason: "too_long"`).
- [x] `edit --icon-hint <slug>` validates the slug through
  `parse_icon_hint_token` and rejects an invalid slug with the
  core `validation_error` (`field: "icon_hint"`,
  `reason: "invalid_slug"`); a valid slug round-trips.
- [x] `edit --icon-hint ""` (empty token after Unicode-whitespace
  trim) flows through `paladin_auth_core::parse_icon_hint_token` as
  `IconHintInput::Default` and re-derives the stored slug from
  the account's current issuer (matching the `add` grammar's
  empty-default behavior). Round-trip: the persisted slug equals
  the issuer-derived slug for the post-edit issuer.
- [x] `edit --icon-hint none` (case-insensitive: `NONE` / `None` /
  `nOnE`, with surrounding Unicode whitespace tolerated) flows
  through `parse_icon_hint_token` as `IconHintInput::Clear` and
  clears the stored slug — functionally equivalent to
  `--no-icon-hint` but exercises `add`-grammar parity at the
  CLI boundary.
- [x] `edit --issuer <new> --icon-hint ""` (combined) re-derives
  the stored slug against the **post-edit** issuer, not the prior
  issuer. This is the load-bearing Phase M `IconHintInput::Default`
  re-derivation contract (DESIGN.md `AccountEdit` doc-comment;
  IMPLEMENTATION_PLAN_01_CORE.md Phase M mutator bullet) pinned
  end-to-end from the CLI.
- [x] `edit --no-icon-hint` clears the stored slug
  (`AccountSummary.icon_hint == null` in JSON); the prior label /
  issuer stay untouched.
- [x] `edit --no-issuer --icon-hint ""` re-derives the slug against
  the post-edit (now-cleared) issuer, producing
  `AccountSummary.icon_hint == null` — functionally equivalent to
  `--no-issuer --no-icon-hint` and pinning the
  `IconHintInput::Default` derivation against a cleared issuer
  parallel to the post-edit-issuer-derivation bullet below.
- [x] `edit --label <l> --issuer <i> --icon-hint <s>` happy path:
  all three fields land in a single `Vault::mutate_and_save` call;
  the JSON envelope reflects the combined post-edit summary.
- [x] No-flag invocation rejects at parse time as
  `validation_error` (`field: "argv"`, `reason: "no_edit_fields"`)
  before the query is resolved (no `/dev/tty` reach, no vault
  read).
- [x] `no_edit_fields` precedence over `vault_missing`: set
  `--vault` to a non-existent path and run `paladin-auth edit some-query`
  (no edit flags); the parse-time `no_edit_fields` rejection wins
  over `vault_missing`. Mirrors the QR `--module-size-px`
  precedence pin.
- [x] `--allow-duplicate` alone (no other edit flags) rejects at
  parse time with `validation_error` (`field: "argv"`,
  `reason: "no_edit_fields"`); the opt-out flag does not satisfy
  the "at least one editable flag" requirement on its own.
- [x] Mutually-exclusive flag pairs (`--issuer` + `--no-issuer`,
  `--icon-hint` + `--no-icon-hint`) reject at parse time as
  `validation_error` (`field: "argv"`, ...). (Reason is currently
  `"usage"` via the shared argv-prescan; a follow-up landing may
  upgrade it to `"mutually_exclusive"`. The rejection itself fires
  at parse time as required.)
- [x] Single-match cardinality: ambiguous query exits non-zero with
  the candidate list; `id:<hex>` prefix routes through the same
  `select` helper as `copy` / `remove` / `rename` / `qr`.
- [x] `no_match` cardinality: `paladin-auth edit nonexistent-query
  --label X` against a vault with no matching row exits non-zero
  with `no_match`. Mirrors the explicit `qr nonexistent` bullet.
- [x] Invalid `--label` (empty / overlong) propagates a core
  `validation_error` (`field: "label"`, `reason: "empty"` /
  `"too_long"`).
- [x] Duplicate `(secret, issuer, label)` rejection: seed two
  accounts `A` and `B` with distinct `(issuer, label)` but the
  same `secret`, then `paladin-auth edit <query-of-A> --label
  <B.label> --issuer <B.issuer>` rejects with `duplicate_account`
  (the existing `B` account's `AccountSummary` in the envelope's
  `account` field) and the persisted vault is byte-identical to
  its pre-edit state (`A` keeps its original label / issuer /
  `updated_at`). Mirrors the `paladin-auth add --uri` collision bullet.
- [x] `edit --allow-duplicate` opts out of the duplicate check:
  same seed setup as the previous bullet plus `--allow-duplicate`
  succeeds, persists the collision, bumps `updated_at` on `A`, and
  emits the `{ "account": AccountSummary }` envelope. The vault
  now legitimately contains two accounts with identical
  `(secret, issuer, label)` triples.
- [x] Self-edit no-collision: `paladin-auth edit <query-of-A> --label
  <A.label> --issuer <A.issuer>` (every field set to `A`'s prior
  value) succeeds without a `duplicate_account` rejection because
  `Vault::find_duplicate_after_edit` skips the account at `id`.
  Folds into the no-op-`updated_at`-still-bumps bullet below.
- [x] No-op-but-non-empty edit (every field set to the prior value)
  still bumps `updated_at`, matching the `rename` same-label
  contract and the core mutator's documented behavior.
- [x] Read-only on secrets: seed an HOTP account at
  `counter = 17`, run `paladin-auth edit <query> --label <new>` (and
  separately `--issuer <new>` and `--icon-hint <slug>`), then
  re-open the vault via `paladin_auth_core::open` and assert the HOTP
  account's `counter()` is still `17`. (Persisted-secret-bytes
  byte-identity is verified indirectly via the re-listed AccountSummary
  agreement; a follow-up bullet covers raw byte equality.)
  Pinned analog of the `qr` read-only HOTP bullet — `paladin-auth edit`
  must never advance a counter or decode a secret.
- [x] `edit --json` envelopes match the
  `cli_json_snapshots.rs` golden shape; volatile fields
  (`updated_at`) are redacted in the snapshot.
- [x] Pre-commit save failure (via the core
  `test-fault-injection` feature) leaves the vault byte-identical
  to its pre-edit state and surfaces `save_not_committed`.
- [x] Post-commit durability-unconfirmed failure surfaces
  `save_durability_unconfirmed` with `committed: true` and the
  post-edit account state visible in the persisted vault.
- [x] Whitespace-only `--label "   "` propagates a core
  `validation_error` (`field: "label"`, `reason: "empty"`)
  because §4.1 label validation rejects trim-then-empty input;
  the persisted vault is byte-identical to its pre-edit state.
- [x] **Validation-before-duplicate ordering**:
  `paladin-auth edit <query> --allow-duplicate --label ""` still
  rejects with `validation_error` (`field: "label"`,
  `reason: "empty"`), not `duplicate_account` or success.
  Directly pins the locked rule that per-field validation runs
  before the duplicate gate (and before `--allow-duplicate` can
  bypass anything).
- [x] **Text-mode error rendering (insta snapshot)**: redirect
  stdout/stderr from a `paladin-auth edit --label ""` invocation against
  a seeded plaintext vault and assert the rendered error block
  matches a golden `insta` snapshot — covers the human-facing
  rendering of `validation_error` for `edit` (parallel to the
  per-command error-rendering snapshots elsewhere).
- [x] `paladin-auth edit --help` (text + `--json --help`) snapshot:
  `--json --help` envelope shape is
  `{ "help": { "command": "paladin-auth edit", "text": "..." } }` per
  `output::help::resolve_command_path`; the `text` field is
  redacted in the snapshot to leave room for clap's auto-generated
  prose. Captures the help routing pinned in the §"Edit command
  (v0.2)" — `--help` checklist bullet.
- [x] `[PTY]` end-to-end `edit --label new` against an encrypted
  vault: the unlock passphrase prompt fires once on `/dev/tty`,
  the edit applies, and the success envelope shape matches the
  plaintext case. Mirrors the `[PTY]` smoke tests under
  `cli_show_peek_copy.rs` / `cli_passphrase.rs`.
- [x] Encrypted-vault no-edit-flags pre-check: against an
  encrypted vault, `paladin-auth edit some-query` (no edit flags)
  rejects with `validation_error` (`field: "argv"`,
  `reason: "no_edit_fields"`) **without** reading `/dev/tty`
  (no unlock prompt fires) — pins the "parse-time rejection beats
  passphrase prompt" precedence rule against the encrypted-mode
  passphrase prompt.
- [x] `--vault <bad-path> --label new my-query` against a
  non-existent vault path surfaces `vault_missing` **without**
  reading `/dev/tty` — pins that `vault_missing` short-circuits
  the encrypted-vault unlock prompt for `edit` exactly as for
  every other vault-touching command.
- [x] **`--dry-run` zero-mutation**: against a seeded plaintext
  vault, snapshot the vault file's bytes, run
  `paladin-auth edit <query> --label <new> --dry-run`, and assert the
  bytes are unchanged. Under `--json`, the envelope shape is
  `{ "account": AccountSummary, "committed": false }` with the
  projected post-edit `AccountSummary` (label = `<new>`,
  `updated_at` = sampled `now`); text mode prints nothing to
  stdout. Cover `--dry-run` + `validation_error`,
  `--dry-run` + `duplicate_account`, and
  `--dry-run --allow-duplicate` (skips the duplicate gate, no
  mutation).
- [x] SPDX header: `tests/cli_edit.rs` starts with
  `// SPDX-License-Identifier: AGPL-3.0-or-later` — parity with
  every other CLI test file (enforced by the workspace SPDX
  audit, but pinned here so a fresh test file is not added
  without the header).

### `destroy` (`tests/cli_destroy.rs`, Milestone 10)

Each test creates a fresh temp dir, `--vault`s a path inside it,
sets up the on-disk state (plaintext / encrypted / corrupted /
missing / symlinked / `.bak`-only), invokes `paladin-auth destroy`, and
asserts stdout / stderr / exit code and post-condition on disk
(primary present / absent, `.bak` present / absent). PTY tests
mark themselves `[PTY]` and skip on CI runners without a pseudo-
terminal, matching the rest of the suite.

> Status (Milestone 10, CLI): the non-`[PTY]` items below are
> implemented in `tests/cli_destroy.rs` (plus the
> `cli_json_snapshots.rs` golden snapshots and the
> `cli_advisory_suppression.rs` sweep). The `[PTY]` items await the
> shared PTY harness in `tests/common` (not yet built) — the
> deferred set is also listed in the `cli_destroy.rs` module doc. The
> two fault-injection items (`stat_backup_file` via an unstattable
> parent, `fsync_vault_dir` partial-failure) and the
> "no `arboard`" property remain unticked pending a fault-injection
> harness; `unlink_backup_file` is covered via the directory-as-`.bak`
> trick that needs no harness.

- [ ] `[PTY]` `destroy` against a plaintext vault prompts, accepts
  `yes`, unlinks the primary, and exits 0 with `Deleted vault.` on
  stdout. The vault file is gone after the call.
- [ ] `[PTY]` `destroy` against an encrypted vault prompts, accepts
  `yes`, unlinks the primary, and exits 0 without ever calling the
  KDF or prompting for a passphrase (asserted by leaving the env
  passphrase-prompt fixture untouched). Pinpoints the design
  decision that destroy is the forgotten-passphrase escape hatch.
- [ ] `[PTY]` `destroy` against a vault with a sibling `.bak`
  unlinks both files. Stdout reads `Deleted vault.`; JSON envelope
  carries `backup_deleted: true`.
- [ ] `[PTY]` `destroy` against a vault with no `.bak` exits 0,
  unlinks only the primary, prints `Deleted vault (backup remained
  on disk).` (the helper text branch for `backup_deleted: false`).
  *(Title labels the branch; on disk no `.bak` exists either before
  or after.)*
- [ ] `[PTY]` `destroy --yes` skips the confirmation prompt; the
  warning text still prints to stderr in text mode.
- [x] `destroy --json --yes` succeeds and emits the
  `{ "destroyed": { "vault_path", "primary_deleted": true,
  "backup_deleted": <bool> } }` envelope on stdout. The
  `cli_json_snapshots.rs` golden snapshot pins the shape.
- [x] `destroy --json` without `--yes` rejects at parse time with
  `validation_error` (`field: "argv"`,
  `reason: "confirmation_required"`). Parallel to `passphrase
  remove --json` / `remove --json`.
- [ ] `[PTY]` `destroy` confirmation decline (any string other than
  `yes` after trim) exits non-zero with `validation_error`
  (`field: "confirmation"`, `reason: "declined"`) before any
  unlink. The primary and `.bak` are still on disk after the call.
- [ ] `[PTY]` `destroy` with no `/dev/tty` available surfaces
  `io_error` (`operation: "confirmation_prompt"`).
- [x] `destroy` against a missing vault exits non-zero with
  `vault_missing` and the resolved `path` field; no `.bak` is
  touched (asserted by leaving a `.bak` file in place and verifying
  it survives the call).
- [x] `destroy` is idempotent across two invocations: the first
  succeeds, the second exits non-zero with `vault_missing`. A
  script using `|| true` sees the same end-state either way.
- [x] `destroy` against a vault whose primary is a symlink rejects
  with `io_error` (`operation: "vault_file_is_symlink"`) before any
  unlink. The symlink target is byte-identical after the call.
- [x] `destroy` against a vault whose `.bak` is a symlink rejects
  with `io_error` (`operation: "backup_file_is_symlink"`) before
  any unlink. The primary is still on disk after the call.
- [ ] `destroy` with a parent directory the user cannot stat (e.g.
  parent flipped to `0000` between resolution and probe) surfaces
  `io_error` (`operation: "stat_backup_file"`). *(Deferred: hard to
  trigger deterministically as the file owner in the sandbox; the
  CLI path is wired and unit-covered by the `DestroyIo` envelope
  rendering.)*
- [x] `destroy` partial-failure: under a test harness that makes
  the `.bak` unlink fail (e.g. POSIX ACL strips write on the
  parent between the primary and backup unlinks), the primary is
  unlinked and the call exits non-zero with `io_error`
  (`operation: "unlink_backup_file"`,
  `primary_deleted: true, backup_deleted: false`). *(Implemented via
  the directory-as-`.bak` trick, which needs no fault-injection
  harness.)*
- [ ] `destroy` partial-failure: under a harness that makes the
  parent-`fsync` fail after both unlinks succeed, the call exits
  non-zero with `io_error` (`operation: "fsync_vault_dir"`,
  `primary_deleted: true, backup_deleted: true`). *(Deferred: needs
  the `PALADIN_AUTH_FAULT_INJECT` post-commit fault hook; the CLI
  envelope path is shared with `unlink_backup_file` and covered.)*
- [x] `destroy` rejects KDF flags
  (`--kdf-memory-mib` / `--kdf-time` / `--kdf-parallelism`) at parse
  time with `validation_error` (`field: "argv"`,
  `reason: "kdf_flags_not_supported"`) — destroy runs no Argon2id
  work. Rejection wins precedence over `vault_missing`.
- [x] `destroy` operates on a vault that `open` would refuse
  (e.g. parent dir mode drifted to `0755`): the unlink still
  succeeds because `destroy` does not run the §4.3 permissions
  gate. Pinpoints the design decision that a vault the user can
  no longer open is still deletable.
- [x] `destroy` operates on a vault whose header is corrupted
  (`unsupported_format_version` or `invalid_payload`): the unlink
  still succeeds because `destroy` does not call `inspect`.
- [x] `destroy --json` envelope under the partial-failure paths
  preserves the `primary_deleted` / `backup_deleted` fields on the
  `io_error` envelope. The `cli_json_snapshots.rs` golden snapshot
  pins the `unlink_backup_file` shape. *(The `fsync_vault_dir`
  shape awaits the fault-injection harness above.)*
- [x] Cross-front-end advisory suppression: a destroy run under
  `--json --yes` emits no advisory on stdout; the
  `cli_advisory_suppression.rs` sweep verifies parity with
  `init --force` / `passphrase remove --yes` / `export --plaintext`
  / `qr --json`.
- [ ] `destroy` does not invoke `arboard` (clipboard adapter) or
  touch `clipboard.clear_enabled`. Pinpoints the parity with the
  CLI's stateless contract — destroy is an unlink, not a runtime
  with side effects. *(Deferred: holds by construction — the
  handler never references the clipboard adapter — but no explicit
  negative test was added.)*

### `passphrase set` / `change` / `remove` (`tests/cli_passphrase.rs`)

- [x] `[PTY]` `passphrase set` succeeds end-to-end against an open
  plaintext vault.
- [x] `[PTY]` `passphrase change` succeeds end-to-end against an open
  encrypted vault.
- [x] `[PTY]` `passphrase remove` succeeds end-to-end against an open
  encrypted vault and confirms before mutation.
- [x] `[PTY]` `passphrase remove` with no `/dev/tty` surfaces `io_error`
  `operation: "confirmation_prompt"`.
- [x] `passphrase remove --json` without `--yes` rejects at parse time.
- [x] `[PTY]` `passphrase remove --yes` skips only the confirmation, not
  the unlock prompt.
- [x] `[PTY]` Confirmation mismatch on the new passphrase surfaces
  `invalid_passphrase` with `reason: "confirmation_mismatch"` before
  mutation.
- [x] `[PTY]` No-`/dev/tty` passphrase prompt failure surfaces
  `io_error` `operation: "passphrase_prompt"`.
- [x] Wrong starting state — `passphrase set` on encrypted vault —
  surfaces `invalid_state` before any unlock or new-passphrase prompt.
- [x] Wrong starting state — `passphrase change` on plaintext vault —
  surfaces `invalid_state` before any prompt.
- [x] Wrong starting state — `passphrase remove` on plaintext vault —
  surfaces `invalid_state` before any prompt.
- [x] `passphrase set` / `change` invalid / out-of-range KDF flag
  values reject with the same stable `validation_error` /
  `kdf_params_out_of_bounds` payloads as `init`.
- [x] KDF-flag rejection wins over `vault_missing` and over wrong-state
  `invalid_state` (precedence).
- [x] `[PTY]` `passphrase set` / `change` with default and custom
  in-range KDF params writes the requested Argon2 params on disk.
- [x] `[PTY]` `passphrase` mutations under `PALADIN_AUTH_FAULT_INJECT=pre_commit`
  surface `save_not_committed` with `committed: false`.
- [x] `[PTY]` `passphrase` mutations under
  `PALADIN_AUTH_FAULT_INJECT=post_commit` surface
  `save_durability_unconfirmed` with `committed: true`.

### `import` (`tests/cli_import.rs`)

- [x] `import` with `--format otpauth` (text URI) imports an account.
- [x] `import` with `--format otpauth` (JSON string array) imports
  multiple accounts.
- [x] `import` with `--format aegis` on a plaintext Aegis JSON imports.
- [x] `import` of an encrypted Aegis JSON rejects with
  `unsupported_encrypted_aegis`.
- [x] `import` with a forced `--format` that does not match the input
  rejects with `unsupported_import_format`.
- [x] `import` with no `--format` auto-detects in the §4.6 fixed order.
- [x] `import` with an empty otpauth array rejects with
  `no_entries_to_import`.
- [x] `import` with an unrecognized input rejects with
  `unsupported_import_format`.
- [x] `import` of a plaintext / malformed Paladin Auth bundle rejects without
  prompting for a bundle passphrase
  (`paladin_auth_core::classify_paladin_auth_import_precheck` routing).
- [x] `[PTY]` `import` of an encrypted Paladin Auth bundle prompts once for
  the bundle passphrase before calling `import::from_file`.
- [x] `[PTY]` `import` of an encrypted Paladin Auth bundle assigns fresh
  UUIDv4 IDs to inserted/appended rows while preserving source
  timestamps.
- [x] `import` defaults to `--on-conflict=skip` when omitted.
- [x] `import --on-conflict=replace` overwrites existing accounts.
- [x] `import --on-conflict=replace` preserves the existing HOTP
  counter for HOTP-to-HOTP collisions.
- [x] `import --on-conflict=append` inserts a duplicate row.
- [x] `import` text-mode `skip` collisions emit a stderr warning.
- [x] `import` succeeds end-to-end and persists the imported accounts
  to disk (`imported_account_is_persisted_to_disk`).
- [x] `import` with `vault_missing` rejects before reading the source
  file.
- [x] `import` rejects the whole batch atomically when any single entry
  fails validation.

### `export` (`tests/cli_export.rs`)

- [x] Plaintext `export` against an empty vault writes an empty JSON
  array.
- [x] Plaintext `export` writes output with mode `0600`.
- [x] Plaintext `export` writes one `otpauth://` URI per account in
  insertion order.
- [x] Plaintext `export` text-mode prints the unencrypted-secrets
  warning to stderr.
- [x] Plaintext `export` text-mode prints a success line naming the
  output path and mode.
- [x] Plaintext `export --json` emits the §5 envelope and keeps stderr
  empty.
- [x] `export` refuses to overwrite an existing target without
  `--force`.
- [x] `export --force` overwrites the existing target with the new
  contents.
- [x] Overwrite check fires before vault unlock under `--json`.
- [x] `export` without a target rejects at parse time with
  `validation_error` `field: "argv"`.
- [x] `export` with both `--plaintext` and `--encrypted` rejects at
  parse time.
- [x] `export` rejects `vault_missing` when the source vault does not
  exist.
- [x] `export --encrypted` rejects invalid / out-of-range KDF flag
  values with the same stable `validation_error` /
  `kdf_params_out_of_bounds` payloads as `init`.
- [x] `export --encrypted` KDF-flag rejection wins over `vault_missing`
  and over the overwrite-existing-output check (precedence).
- [x] `[PTY]` `export --encrypted` round-trips through `import` with a
  bundle passphrase that is independent of the vault unlock passphrase.
- [x] `[PTY]` `export --encrypted` accepts default and custom in-range
  KDF params and writes them to the bundle header.
- [x] `export --encrypted` writer failure before the final rename
  surfaces `save_not_committed`.
- [x] `export --encrypted` writer failure after the final rename
  surfaces `save_durability_unconfirmed`.

### `qr` (`tests/cli_qr.rs`, v0.2)

Every test below creates a fresh temp dir, seeds the vault with a known
TOTP + HOTP account, sets `--vault` to that path, and asserts stdout,
stderr, exit code, and on-disk side effects (or lack thereof). `[PTY]`
bullets require the same `/dev/tty` harness the existing CLI tests use.

- [x] **Single-match cardinality.** `paladin-auth qr github` against a vault
  whose only `github` match is a TOTP row renders an ANSI QR to stdout
  with exit 0; against a vault with two `github` rows exits non-zero
  with `multiple_matches` carrying both candidates and their
  `id:<hex>` disambiguators.
- [x] **`no_match`.** `paladin-auth qr nonexistent` against a vault with no
  matching row exits non-zero with `no_match`. Text mode prints the
  same wording the existing `copy nonexistent` test asserts.
- [x] **Read-only — HOTP counter unchanged.** Seed a HOTP account at
  `counter = 17`. Run `paladin-auth qr <query>` three times in a row
  (ANSI / PNG to a temp file / SVG to a temp file). After each run,
  open the on-disk primary file (post-temp-dir cleanup) via
  `paladin_auth_core::open` and assert the HOTP account's `counter()` is
  still `17` and its `updated_at()` matches the pre-run value
  byte-for-byte. Vault primary-file bytes must also be unchanged
  between runs. This is the load-bearing pin for the "QR export is a
  peek, not a show" rule in DESIGN §4.6.
- [x] **Read-only — `peek` interaction.** After running `paladin-auth qr`
  on a HOTP account, `paladin-auth peek <query>` returns the same code
  that `peek` would have returned *before* the `qr` run. Belt-and-
  suspenders confirmation that `qr` does not advance.
- [x] **ANSI default to stdout.** `paladin-auth qr <query>` (no `--out`,
  no `--format`) writes the ANSI half-block render to stdout. The
  rendered text contains only the `qrcode::render::unicode::Dense1x2`
  glyph alphabet (assert that every Unicode scalar in the output is
  either `' '`, `'▀'`, `'▄'`, `'█'`, or `'\n'`). Stderr carries the
  warning text from `format_plaintext_qr_export_warning()`. Exit 0.
- [x] **`--format=png` without `--out` rejects at parse time.**
  `paladin-auth qr <query> --format=png` exits non-zero with
  `validation_error` (`field: "out"`,
  `reason: "required_for_binary_format"`) before any vault unlock
  attempt (assert by setting `--vault` to a non-existent path —
  the parse-time reject must win precedence over `vault_missing`).
- [x] **`--format=svg` without `--out` rejects at parse time** with the
  same shape as the PNG case.
- [x] **`--format=ansi` with `--out` rejects at parse time.**
  `paladin-auth qr <query> --format=ansi --out /tmp/qr.txt` exits non-zero
  with `validation_error` (`field: "format"`,
  `reason: "ansi_requires_no_out"`) before any vault unlock attempt
  (assert by setting `--vault` to a non-existent path — the
  parse-time reject must win precedence over `vault_missing`). On-
  disk side effects: the `--out` target is never created or touched.
- [x] **`--json` without `--out` rejects at parse time.**
  `paladin-auth qr <query> --json` exits non-zero with
  `validation_error` (`field: "out"`, `reason: "required_under_json"`)
  before any vault unlock attempt; stderr carries the JSON envelope
  per §5's `--json` parse-error contract.
- [x] **`--module-size-px` out of bounds rejects.** Both `0` and `65`
  reject with `validation_error` (`field: "module_size_px"`,
  `reason: "out_of_bounds"`) before vault unlock. Invalid integer
  (`-1`, `1.5`, `abc`) rejects with
  `reason: "invalid_integer"`. Overflowing `u32::MAX + 1` rejects
  with `reason: "overflow"`.
- [x] **`--module-size-px` precedence.** An out-of-range
  `--module-size-px` value rejects before `vault_missing` (set
  `--vault` to a non-existent path) and before query resolution
  (so a bogus query string does not surface as `no_match` first).
  Mirrors the encrypted-write KDF-flag precedence rule.
- [x] **`--module-size-px` accepted on `--format=ansi`.** Parser accepts
  the flag but the render output is unchanged from the default-flag
  case (the renderer ignores it). Exit 0; ANSI body byte-equal.
- [x] **PNG to `--out` writes 0600.** `paladin-auth qr <query> --out
  /tmp/qr.png` writes a PNG file with `0o600` permissions. The bytes
  decode through a test-local `rqrr` `dev-dependencies` import
  back to the same `otpauth://` URI that
  `paladin_auth_core::export::otpauth_list(&vault)` emits for that
  account (parity with the core round-trip test in
  IMPLEMENTATION_PLAN_01_CORE.md Phase L). Exit 0; stdout carries
  the success line; stderr carries the warning.
- [x] **SVG to `--out` writes 0600.** Same shape as the PNG case but
  for `--format=svg`; assert the file starts with `<?xml` or `<svg`,
  is non-empty UTF-8, and decodes through a `quick-xml`-style sanity
  check.
- [x] **`--out` refuses overwrite without `--force`.** When the
  destination already exists, exit non-zero with `validation_error`
  (`field: "out"`, `reason: "exists"`, `path: <out_path>`). The
  existing file's bytes must be byte-identical before and after the
  rejected run.
- [x] **`--out --force` overwrites.** Same as above but with
  `--force`; the destination is replaced with the new QR bytes,
  permissions stay `0600`, exit 0.
- [x] **`--out` writer failure surfaces durability errors.** Under
  `PALADIN_AUTH_FAULT_INJECT=pre_commit` the write surfaces
  `save_not_committed` (with `committed: false`); under
  `PALADIN_AUTH_FAULT_INJECT=post_commit` it surfaces
  `save_durability_unconfirmed` (with `committed: true`). Mirrors
  the `export --plaintext` durability assertions.
- [x] **`--json` success shape.** `paladin-auth qr <query> --json --out
  /tmp/qr.png` writes `{ "written": "...", "format": "qr_png",
  "account": AccountSummary }` to stdout and **nothing else** on
  stdout. Stderr is empty (the warning is suppressed). `format`
  switches to `"qr_svg"` under `--format=svg`. The
  `account` field's `AccountSummary` matches the resolved account
  (id, issuer, label, kind, algorithm, digits, period/counter,
  icon_hint, created_at, updated_at). `updated_at` is unchanged
  from the pre-run vault state (read-only invariant pin under
  `--json`).
- [x] **`--no-color` / `NO_COLOR` have no effect on ANSI render.**
  Set either; the ANSI body bytes are byte-equal to the unset case.
  The QR Unicode half-blocks are not ANSI styling escapes; they are
  plain UTF-8 glyphs.
- [x] **Encrypted vault works end-to-end.** `[PTY]` Open an encrypted
  vault, run `paladin-auth qr <query> --out /tmp/qr.png`, assert the
  Argon2id unlock prompt fires once and the resulting file
  decodes back to the matching `otpauth://` URI.
- [x] **`id:<hex>` prefix selector.** `paladin-auth qr id:<8-char-prefix>`
  selects a unique account even when the substring branch would
  also match (no substring fallback). `id:` prefix shorter than 8
  hex chars, longer than 32, or with non-hex characters rejects
  with `validation_error` (`field: "query"`) — same wording as
  `copy id:<bad-prefix>`.
- [x] **`copy`-style query precedence.** Empty `<query>` rejects with
  `validation_error` (`field: "query"`); whitespace-only after trim
  rejects identically. Matches the existing `copy` / `remove`
  empty-query rejection coverage.
- [x] **Thinness regression guard.** A static / source-level check (or
  a `cargo metadata` JSON walker in `tests/cli_qr.rs::deny_qrcode_in_runtime_deps`)
  proves `qrcode` is **not** a regular `[dependencies]` entry in
  `crates/paladin-auth-cli/Cargo.toml`. The existing `[dev-dependencies]`
  entry remains (used by `tests/cli_add.rs` as a QR fixture
  generator).

### `settings` (`tests/cli_settings.rs`)

- [x] `settings get` returns the full nested `VaultSettings` defaults
  for a fresh vault.
- [x] `settings get <key>` under `--json` still returns the full
  settings object (not the filtered key).
- [x] `settings get` text mode lists every dotted key for a fresh
  vault.
- [x] `settings get <key>` text mode filters to a single dotted key.
- [x] `settings set <bool-key>` under `--json` returns the full
  post-mutation settings envelope.
- [x] `settings set` persists across a follow-up `settings get` against
  the same vault.
- [x] `settings set` accepts the in-range minimum and maximum for each
  `*_secs` key.
- [x] `settings set` text mode renders the full post-mutation settings
  table.
- [x] `settings set <unknown-key>` rejects with `validation_error`
  (`field: "key"`, `reason: "unknown_setting_key"`).
- [x] `settings get <unknown-key>` rejects with `validation_error`
  (`field: "key"`, `reason: "unknown_setting_key"`).
- [x] Unknown-key rejection fires before the vault is opened (no
  `vault_missing` shadow).
- [x] `settings set <bool-key> <value>` requires lowercase `true` /
  `false`.
- [x] `settings set <u32-key> <value>` requires base-10 digits only.
- [x] `settings set <u32-key>` rejects values below the documented
  minimum with `out_of_range`.
- [x] `settings set <u32-key>` rejects values above the documented
  maximum with `out_of_range`.
- [x] `settings get` with `vault_missing` rejects after key validation.
- [x] `settings get` succeeds for each dotted key against the default
  vault.

### `--json` schema and stream cleanliness

- [x] Per-command success envelopes are locked via `insta` golden
  snapshots.
- [x] Per-`error_kind` envelopes are locked via `insta` golden
  snapshots.
- [x] Help / version success envelopes are locked via `insta` golden
  snapshots.
- [x] Help / version success envelopes are field-asserted in
  `cli_global_flags.rs`.
- [x] `paladin-auth --json` syntax / usage failures reroute to
  `validation_error` `field: "argv"` `reason: "usage"` (covered for
  unknown subcommand and unknown top-level flag in
  `cli_errors_json.rs`).
- [x] `unsafe_permissions` envelope carries `path`, `subject`,
  `actual_mode`, `expected_mode` (`cli_errors_json.rs`).
- [x] `invalid_header` envelope is `error_kind`-only
  (`cli_errors_json.rs`).
- [x] `unsupported_format_version` envelope carries the offending
  `format_ver` byte (`cli_errors_json.rs`).
- [x] `vault_missing` envelope is `error_kind`-only
  (`cli_errors_json.rs`).
- [x] Stream cleanliness: stdout is byte-empty on `--json` error paths
  (covered by `assert_json_error_streams` in `cli_errors_json.rs`).
- [x] Stream cleanliness: stderr is exactly one JSON document plus a
  single trailing newline on `--json` error paths.
- [x] `add --uri` of a short-secret URI routes the warning into the
  JSON `warnings` array (no stderr warning under `--json`).
- [x] `[PTY]` Stream cleanliness for `passphrase set` under `--json`:
  with `/dev/tty` rerouted to the test harness, stdout / stderr stay
  byte-clean (the prompt is consumed via `/dev/tty` only).
- [x] No `init` / `init --force` / `passphrase remove --yes` /
  plaintext-export advisory text appears under `--json` (centralized
  cross-command sweep).
- [x] **v0.2 — `qr` success envelope.** `paladin-auth qr <query> --out
  /path/qr.png --json` writes
  `{ "written": "...", "format": "qr_png", "account": AccountSummary }`
  to stdout and nothing else. `format` is `"qr_svg"` under
  `--format=svg`. The `account` field shape matches §5 `AccountSummary`.
- [x] **v0.2 — `qr` advisory suppression.** Under `--json`, the
  `format_plaintext_qr_export_warning()` text never appears on
  stdout or stderr (centralized cross-command sweep extended to
  include the QR warning).
- [x] **v0.2 — `qr` parse-error envelopes.** Stderr carries the
  matching JSON envelope for the four parse-time rejections
  (`required_for_binary_format`, `ansi_requires_no_out`,
  `required_under_json`, `out_of_bounds` for `module_size_px`).

### `--no-color` / `NO_COLOR` (`tests/cli_global_flags.rs`)

- [x] `--no-color` disables ANSI in text-mode output.
- [x] `NO_COLOR` env var (when `--no-color` is absent) disables ANSI.
- [x] ANSI is also disabled when stdout is not a TTY.

### `paladin-auth tui` exec wrapper (`tests/cli_exec_tui.rs`)

- [x] `paladin-auth tui` execs `paladin-auth-tui` with no extra flags when the
  globals are default.
- [x] `paladin-auth tui` forwards `--vault` in the global position.
- [x] `paladin-auth tui` forwards `--vault` in the subcommand position.
- [x] `paladin-auth tui` forwards `--no-color` in the global position.
- [x] `paladin-auth tui` forwards `--no-color` in the subcommand position.
- [x] `paladin-auth tui` forwards both `--vault` and `--no-color`.
- [x] `paladin-auth --json tui` rejects at parse time with a
  `validation_error` envelope.
- [x] `paladin-auth tui --json` rejects at parse time with a
  `validation_error` envelope.
- [x] `paladin-auth --json tui --help` emits the help envelope and does
  **not** inspect `PATH`.
- [x] Missing `paladin-auth-tui` on `PATH` surfaces `io_error`
  `operation: "exec_paladin_auth_tui"`.

## Dependencies

`clap` (with `derive` feature for the argument tree), `rpassword` (for
`/dev/tty` passphrase entry per §5), `arboard` (for `paladin-auth copy`
clipboard writes — no auto-clear), `secrecy`, `zeroize`, plus
`paladin-auth-core`. **No `tokio`.** No transitive network crates (enforced
by workspace `cargo deny`).

Dev-dependencies: `assert_cmd` (CLI process integration), `predicates`
(stdout/stderr expectation matchers), `insta` (golden snapshots for
`--json` envelopes and `--help` text), and `tempfile` (per-test vault
fixtures). The `paladin-auth-core/test-fault-injection` cargo feature is
enabled under `[dev-dependencies.paladin-auth-core]` so process-level fault
tests can drive `save_not_committed` / `save_durability_unconfirmed`
through real `paladin-auth` invocations.

The CLI-specific deps are pinned to specific minor versions in
`crates/paladin-auth-cli/Cargo.toml` so argument parsing (`clap`),
passphrase entry (`rpassword`), and clipboard access (`arboard`) do
not drift across transitive minor updates; `arboard` is pinned
explicitly because it sits on the clipboard security boundary
(`paladin-auth copy`). `assert_cmd` and `insta` are pinned for snapshot
stability across runs. This mirrors the `paladin-auth-core` pinning of
`getrandom` / `bincode v2` and the `paladin-auth-tui` / `paladin-auth-gtk`
pinning convention.

## Thinness contract

The `paladin-auth` binary is a presentation layer. Crypto, storage,
import/export, and OTP primitives must never be re-implemented or
imported directly here — they belong in `paladin-auth-core` per DESIGN §3.

- [x] Tests: `tests/thinness.rs` — a source-level guard that scans
  `crates/paladin-auth-cli/src/` for forbidden crate-name spellings:
  `argon2`, `chacha20poly1305`, `bincode`, `hmac`, `sha1`, `sha2`,
  `rqrr`, `image`, `getrandom`, `directories`, `url`. Any direct
  reference fails the test with a message pointing at the file and
  the symbol so the offending logic can be moved into `paladin-auth-core`.
  The crate manifest is also checked: `paladin-auth-cli` must not declare
  any of those crates as a direct `[dependencies]` entry. Keeps the
  CLI a thin shell over `paladin_auth_core::*`.
- [x] **v0.2 — extend the thinness guard for `qrcode`.** Add
  `qrcode` to the forbidden source-spelling list and to the
  forbidden `[dependencies]` manifest list. The existing
  `[dev-dependencies]` entry on `qrcode` stays (it backs the QR
  fixture generators in `tests/cli_add.rs`); only the regular
  `[dependencies]` slot is forbidden. The QR command's renderers
  must route through `paladin_auth_core::Vault::export_qr_*` /
  `paladin_auth_core::export::qr_*` so PNG / SVG / ANSI encoding,
  `otpauth://` URI emission, and `Zeroizing` wrappers stay in core.

## Packaging (per §11)

The CLI ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.1
(§11.1). Implementation owes the release pipeline:

- **Man page.** Generate `paladin-auth.1` from clap via `clap_mangen`,
  driven by `cargo xtask man` so the page always tracks the live
  argument tree. The packaging configs ship it gzipped at
  `/usr/share/man/man1/paladin-auth.1.gz` per §11.3.

  *Implemented (v0.2 Milestone 7):* `cargo xtask man` renders
  `paladin-auth.1` (and `paladin-auth-tui.1`) into `target/man/` via
  `clap_mangen`. The workspace `xtask` crate pulls the live clap
  `Command` through `paladin_auth_cli::clap_command()`, which is why
  `crates/paladin-auth-cli` is a lib+bin pair — the binary entry stays
  in `src/main.rs` and `src/lib.rs` exposes only what the
  man-page generator needs. `cargo xtask package --frontend
  paladin-auth --format rpm` calls the same renderer, gzips the output
  into `target/man/paladin-auth.1.gz`, and then runs `nfpm` inside the
  `docker.io/goreleaser/nfpm` container under rootless podman so
  the manifest's `src:` path resolves on first build without a
  host `nfpm` install.
- **Cargo.toml metadata.** `crates/paladin-auth-cli/Cargo.toml` inherits
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
  `packaging/deb/paladin-auth.yaml` and `packaging/rpm/paladin-auth.yaml`
  stay minimal. The Debian one-line description fits the conventional
  ~60-character synopsis display width (Debian Policy §5.6.13 caps the
  synopsis under 80); the long form is sourced from README.

  *Implemented (v0.2 Milestone 7, `.rpm` + `.deb`):*
  `packaging/rpm/paladin-auth.yaml` declares `name: paladin-auth`, depends on
  `glibc` only (matching the headless-friendly footprint §11.3
  promises), installs `/usr/bin/paladin-auth` + the gzipped
  `/usr/share/man/man1/paladin-auth.1.gz`, and inherits `version:
  ${PALADIN_AUTH_VERSION}` from the release pipeline.
  `packaging/deb/paladin-auth.yaml` is the Debian analogue: it declares
  `name: paladin-auth`, `section: utils`, `priority: optional`, depends on
  `libc6` only, installs the same `/usr/bin/paladin-auth` +
  `/usr/share/man/man1/paladin-auth.1.gz` payload, and inherits the same
  `${PALADIN_AUTH_VERSION}`. Both contracts are pinned by
  `crates/paladin-auth-cli/tests/packaging_rpm_nfpm_manifest_logic.rs` and
  `crates/paladin-auth-cli/tests/packaging_deb_nfpm_manifest_logic.rs` —
  `cargo test --workspace --all-targets` fails on regression even when
  `nfpm` itself is not installed. `cargo xtask package --frontend
  paladin-auth --format deb` (or `make deb-paladin-auth`) is the local entry
  point; the release workflow at `.github/workflows/release.yml`
  builds the `.deb` directly with `nfpm` and attaches it to the
  GitHub release alongside the `.rpm`.
- **Flatpak.** `packaging/flatpak/paladin-auth.yml` declares
  `org.freedesktop.Platform//23.08`, no `--share=network`,
  filesystem access scoped to `xdg-data/paladin-auth:create` plus
  `xdg-config/paladin-auth:create`, and the display clipboard permissions
  required by `paladin-auth copy`: `--socket=wayland`,
  `--socket=fallback-x11`, and `--share=ipc`. No direct D-Bus or
  session-bus access is requested.
  `flatpak run org.tamx.PaladinAuth.Cli` inherits the invoking
  terminal's stdin / stdout / stderr so `--json` scripting works
  end-to-end via the Flatpak entry point.
- **AppImage.** `linuxdeploy` assembles the AppDir; the bundled
  `AppRun` forwards argv unchanged so the AppImage is a drop-in for
  the bare binary. `paladin-auth-<version>-x86_64.AppImage` per §11.5.
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
- **Every Tests checklist item above is ticked** — including the
  `[PTY]`-tagged scripted-`/dev/tty` bullets, the `add --qr` synthetic
  QR fixture, the v0.2 `tests/cli_qr.rs` bullets (read-only HOTP /
  parse-time rejection / overwrite gate / JSON shape / thinness), the
  `--no-color` / `NO_COLOR` triggers, and the `insta` JSON-schema
  golden snapshots. The "Add the CLI integration tests
  and JSON golden snapshots below" implementation-checklist item
  ticks only when this gate is met.
- `--json` schema golden-locked via `insta`.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
- CLI **never** schedules a clipboard auto-clear. Verified by test.
- DESIGN.md is kept in sync with implemented CLI-visible behavior; if a
  contradiction surfaces, DESIGN.md is updated first.
