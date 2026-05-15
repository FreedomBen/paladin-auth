# Implementation Plan 03 — `paladin-tui`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4.1, §4.2, §4.3, §4.4,
§4.5, §4.6, §4.7, §5 (global flags / `paladin tui`), §6, §8, §9,
§10, §11, §12 (Milestone 5), §13, and §14 (license).
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).
The final `paladin tui` integration check also depends on
[`IMPLEMENTATION_PLAN_02_CLI.md`](IMPLEMENTATION_PLAN_02_CLI.md).

## Scope

Standalone binary `paladin-tui`. Single-screen MVP per §6: search bar,
account list with live TOTP gauges and HOTP reveal-on-`n`, status line, and
modal dialogs for add / remove / rename / import / export / passphrase / settings.
Auto-lock and clipboard auto-clear are **opt-in** per `VaultSettings`. In
native/shared-`PATH` installs, the TUI is also reachable via `paladin tui`
which `execvp`s this binary.

Runtime model (§13): plain threads + `mpsc`. **No `tokio`** — local TUIs
don't need async I/O.

## Crate layout

```
crates/paladin-tui/
├── Cargo.toml             # license = "AGPL-3.0-or-later"; bin = "paladin-tui"
├── src/
│   ├── main.rs            # parse args (clap), reject --json (text-only diagnostic — TUI has no JSON mode), hand off to app::run
│   ├── cli.rs             # GlobalArgs (--vault, --no-color; --json rejected at parse time with clap's text diagnostic)
│   ├── app/
│   │   ├── mod.rs         # App state machine + run loop
│   │   ├── state.rs       # AppState variants + vault/store ownership
│   │   ├── event.rs       # AppEvent enum (Input, Tick, EffectResult, ClipboardClear)
│   │   ├── input.rs       # crossterm event → AppEvent translation
│   │   ├── ticker.rs      # `paladin_core::TICK_INTERVAL_MS` tick thread, sleeps, mpsc producer
│   │   └── reducer.rs     # pure (state, event) → (state, side_effects)
│   ├── ui/
│   │   ├── mod.rs         # ratatui draw entry; routes to screen
│   │   ├── unlock.rs      # passphrase entry screen
│   │   ├── list.rs        # search + account list (TOTP gauge / HOTP reveal)
│   │   ├── status.rs      # bottom status / shortcut bar
│   │   └── modals/
│   │       ├── add.rs
│   │       ├── remove.rs
│   │       ├── rename.rs       # label edit; calls Vault::rename inside Vault::mutate_and_save
│   │       ├── import.rs       # path + format + on-conflict + (optional) bundle passphrase
│   │       ├── export.rs       # format + path + overwrite + (encrypted) twice-confirmed passphrase
│   │       ├── passphrase.rs   # set/change/remove sub-flows
│   │       └── settings.rs     # auto_lock + clipboard toggles + timeouts
│   ├── search.rs          # incremental filter over Vault::iter() (§4.7 public surface, yielding &Account in insertion order) using paladin_core::account_matches_search; rows render AccountSummary projections via Account::summary()
│   ├── clipboard.rs       # arboard writer; schedule + only-if-unchanged decisions route through `paladin_core::policy::clipboard_clear::ClipboardClearPolicy`
│   ├── auto_lock.rs       # crossterm tick plumbing; idle-deadline math routes through `paladin_core::policy::auto_lock::IdlePolicy` (encrypted-only gating + timer math owned by core)
│   ├── hotp_reveal.rs     # reveal window per row using `paladin_core::policy::hotp_reveal::deadline(now)`
│   ├── terminal.rs        # raw mode / alternate-screen guard; restores terminal on exit
│   ├── theme.rs           # color palette; --no-color / NO_COLOR disables styling
│   └── prompt.rs          # shared zeroizing passphrase-input widget reused by unlock.rs, modals/passphrase.rs, modals/import.rs (encrypted Paladin bundle), and modals/export.rs (twice-confirmed encrypted bundle)
└── tests/
    ├── reducer_tests.rs
    ├── search_tests.rs
    ├── auto_lock_tests.rs
    ├── clipboard_tests.rs
    ├── hotp_reveal_tests.rs
    ├── terminal_tests.rs
    └── snapshots/         # insta golden frames for every screen + modal
```

Every new Rust source file carries the standard SPDX header
`// SPDX-License-Identifier: AGPL-3.0-or-later`.

## Event loop (per §6)

Single thread runs the reducer. Events arrive on `mpsc<AppEvent>` from two
long-lived producer threads plus effect-owned clipboard timer threads:

- **Input thread** — `crossterm::event::read()` in a loop, maps to
  `AppEvent::Input(KeyEvent | ResizeEvent | …)`.
- **Ticker thread** — sleeps `paladin_core::TICK_INTERVAL_MS`, emits
  `AppEvent::Tick { wall_clock, monotonic }`; TOTP generation uses
  `SystemTime` (`wall_clock`), while UI deadlines such as HOTP reveal
  expiry use monotonic `Instant` values.
- **Timer side effects** — clipboard auto-clear effects spawn one-shot
  timer threads that later send
  `AppEvent::ClipboardClear { token, value }`. Auto-lock does not spawn
  timer threads; the reducer stores an `idle_deadline: Option<Instant>`
  obtained from `paladin_core::policy::auto_lock::IdlePolicy::next_deadline`
  and checks expiry via `IdlePolicy::is_expired` on each `Tick`.

The reducer is a pure function over `(state, event) → (state, Vec<Effect>)`
so it is unit-testable without a terminal. Effects are executed by `app::run`,
which is the only boundary that may call impure core / clipboard / writer
functions. Save-bearing effects mutate the current `Vault` only through core
APIs (`mutate_and_save`, `hotp_advance`, or passphrase transitions), then send
an `AppEvent::EffectResult(...)` back through the same `mpsc` channel. The
reducer owns all non-core visible state updates (status text, reveal windows,
modal close/count panels, and inline errors) from that result, while trusting
core rollback semantics for the `Vault` value. Clipboard timer effects are
the only effects that send delayed non-result events (`ClipboardClear`).
`app::run` owns terminal setup and teardown: enable raw mode, enter the
alternate screen, install a drop guard before the first draw, and always
restore raw mode / alternate-screen state on normal exit, startup failure
after terminal setup, `Ctrl-C`, and panic unwind.

## Startup / vault modes

Startup mirrors the CLI's vault inspection path:

1. Resolve vault path (`--vault` or `paladin_core::default_vault_path()`).
2. Call `paladin_core::inspect(path)`.
3. `VaultStatus::Missing` opens a non-mutating missing-vault screen with a
   status message telling the user to run `paladin init`; v0.1 TUI does not
   create vaults.
4. `VaultStatus::Plaintext` calls `open(path, VaultLock::Plaintext)` and
   opens directly to the list view.
5. `VaultStatus::Encrypted` opens the unlock screen and prompts inside the
   TUI; wrong passphrases (`decrypt_failed`) keep the user on the unlock
   screen with an inline error.
6. Any error from vault-path resolution (`default_vault_path`), or any
   other error from `inspect` (e.g. `invalid_header` from unrecognized
   magic, or `io_error`) or from `open`
   (`vault_missing`, `unsafe_permissions`, `invalid_header`, `invalid_payload`,
   `unsupported_format_version`, `kdf_params_out_of_bounds`,
   `wrong_vault_lock`, `io_error`) renders a non-mutating
   startup-error screen with the error text and quits on `Esc`, `q`, or
   `Ctrl-C`. `unsafe_permissions` errors render the `Some(text)` from
   `paladin_core::format_unsafe_permissions(&err)` so all front ends
   show identical wording, falling back to the generic error text only if
   the formatter unexpectedly returns `None`. The unlock screen handles only
   `decrypt_failed` inline; every other `open` error replaces the
   unlock screen with the startup-error screen.

`Unlocked` state keeps both the `Vault` and `Store` returned by `open` so
save-bearing effects can call `Vault::mutate_and_save`, `Vault::hotp_advance`,
and passphrase-transition methods without reconstructing persistence state.
`Locked` state keeps the resolved vault path and pending clipboard-clear state,
but no `Vault`, `Store`, cached key, passphrase, HOTP reveal, or modal-local
secret state; both initial encrypted startup and later auto-lock unlock attempts
call `open(path, VaultLock::Encrypted(secret))` from that state.

**Argon2id parameters: defaults only.** Encrypted-write paths reachable
from the TUI — passphrase `set` / `change` inside the Passphrase modal
and encrypted-bundle Export — call `EncryptionOptions::new(secret)`,
which validates non-empty passphrases and uses the §4.4 defaults
(m=64 MiB, t=3, p=1), and surface no UI for
`--kdf-memory-mib` / `--kdf-time` / `--kdf-parallelism`. Power users
wanting custom KDF tuning use the CLI. Vaults the TUI opens that were
created with custom params still read those params from the on-disk
header per §4.4, so opening is unaffected.

## Layout (per §6)

```
┌ Paladin ─────────────────────────────────────────────────┐
│ Search: ____________                                     │
├──────────────────────────────────────────────────────────┤
│ ▶ GitHub (ben@…)        123 456   ████████░░  18s        │
│   AWS prod              987 654   ████░░░░░░   8s        │
│   AWS-HOTP (#42)        ▸ press n to advance             │
├──────────────────────────────────────────────────────────┤
│ [↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find│
└──────────────────────────────────────────────────────────┘
```

- TOTP rows render a live `Gauge` countdown; re-rendered on every `paladin_core::TICK_INTERVAL_MS` tick.
- HOTP rows: when hidden, the code area shows the prompt
  `▸ press n to advance` and the row's `(#counter)` is shown in the
  label-suffix slot using the stored next counter (matching DESIGN §6).
  Pressing `n` calls
  `Vault::hotp_advance` (advances counter and saves) and reveals the
  generated code in place of the prompt for the shared
  `paladin_core::HOTP_REVEAL_SECS` window (120 seconds); the row's
  monotonic expiry is computed via
  `paladin_core::policy::hotp_reveal::deadline(now)`, after
  which the row returns to the hidden state. Reveal expiry is detected
  on the next `paladin_core::TICK_INTERVAL_MS` `Tick` event (no separate
  timer thread or `AppEvent` variant; the reveal's `deadline(now)` value
  is checked against the tick's `Instant`). `n` always advances and
  re-reveals (it's the "give me the next code" key) — pressing `n` again
  during an open reveal advances to the next counter rather than
  no-op'ing. During the reveal window, the label-suffix counter switches
  to the `Code.counter_used` that produced the visible code (the pre-advance
  counter), even though the stored vault counter has already advanced.
  When the reveal expires, the row returns to the hidden prompt and the
  label suffix returns to the stored next counter. `n` is a no-op when the
  selected row is TOTP (TOTP codes are always visible).
- Copying a hidden HOTP row is **rejected** with a status-line message.
  Copying during the reveal window copies the visible code and does not
  advance again.
- The list scrolls its viewport so the selected row stays visible.
  `↑` / `↓` and `j` / `k` move by one row, `PgUp` / `PgDn` and
  `Ctrl-B` / `Ctrl-F` move by viewport height, `Home` / `End` and
  `gg` / `G` jump to the first / last row of the filtered set,
  `Ctrl-U` / `Ctrl-D` move by half a viewport, and `zz` recenters
  the viewport so the selected row sits in the middle (all
  vim-style). `gg` and `zz` are two-press chords: the first press
  sets a pending-leader state in the reducer, a matching second
  press executes the action, and any other key — including a
  non-matching letter, a focus change, modal open, or auto-lock —
  clears the pending state. There is no timeout; the chord is
  committed by the next keypress, matching vim's `nottimeout`
  semantics. Selection clamps to the bounds of the filtered result
  set and never goes off-list. With an empty filtered set, every
  list-navigation key (including the vim chords) is a silent no-op.

## Focus model

Focus alternates between the search bar and the account list. On
list-view entry, focus starts on the account list; on the unlock
screen, focus starts on the passphrase entry. `/` focuses the search
bar; typing narrows the filtered list in place. `Tab` and `Shift-Tab`
cycle focus between the search bar and the account list, preserving
the active query when leaving the search bar (modals have their own
trapped focus, see below). While the search bar is focused, `↑`/`↓`
still move the list selection and `Enter` copies the selected entry —
the selection is always navigable so the user does not need to
unfocus the search to act on a result. The other list-navigation keys
(`PgUp`, `PgDn`, `Home`, `End`, `Ctrl-B`, `Ctrl-F`, `Ctrl-D`,
`Ctrl-U`) likewise pass through to the list while the search bar
has focus; they are navigation, not text editing, so the TUI's
input router dispatches them to the list before they reach
`tui-input`'s key handler (which would otherwise treat `Home` /
`End` as cursor moves, `Ctrl-U` as delete-to-start-of-line, and
`Ctrl-F` / `Ctrl-B` as forward / back-char cursor moves). The
bare-letter vim navigation keys (`j`, `k`, `g`, `G`, `z`) do
**not** pass through and are consumed by the search field as
character input when it has focus, matching the treatment of the
action keys.
Other keys, including the action keys `a` / `r` / `R` / `i` /
`e` / `n` / `p` / `s` / `?` and the bare-letter vim navigation keys
`j` / `k` / `g` / `G` / `z`, the search-focus key `/`, and the quit key `q`,
are routed to the search field as character input while it has focus;
the user must defocus the search (`Tab` to preserve the query or
`Esc` to clear it) to use them as actions. `Ctrl-C` is the exception and
always quits. `Esc` clears the search query and returns focus to the list;
on the list, `Esc` only clears pending vim chord state and is otherwise a
no-op. Modal dialogs trap focus while open and intercept `Esc` to close
themselves. The missing-vault and startup-error screens accept `Esc` / `q` /
`Ctrl-C` to quit (the screens are read-only dead-ends with no input or state
to discard, so all three keys behave identically). The unlock screen accepts
character input (passphrase) and `Enter` (submit), and quits on `Esc` or
`Ctrl-C` (`q` is a valid passphrase character, so it is not bound to quit
there).

When the filter changes, the new selection is computed via
`paladin_core::select_after_filter(prev, &filtered)` (preserve by `AccountId`
if still present, otherwise the first match, `None` if empty). Empty result
sets render an empty-state row and have no selection. With no selection, `Enter`,
`n`, `r`, and `R` produce a status-line "no account selected" error and no effect;
Add / Import / Export / Passphrase / Settings remain available from list
focus.

## Modals (per §6)

All passphrase-entry fields (unlock, encrypted Paladin import, encrypted
export, passphrase set/change) and the Add modal's secret-bearing
fields (manual-secret field and the URI-mode entry) keep typed bytes in
zeroizing buffers, convert to `secrecy::SecretString` only for core
calls, and zeroize on submit, cancel, modal close, and auto-lock.
The Add modal also zeroizes hidden secret-bearing fields when the user
switches input modes, so stale manual secrets or `otpauth://` URI text are
not retained behind the active mode.
Passphrase buffers preserve the typed bytes exactly: no trimming,
case-folding, or Unicode normalization is applied before constructing the
`SecretString`; an empty passphrase means zero bytes. If
Add submit reaches a duplicate-account gate, the modal keeps the
already validated account in secret-bearing pending-add state so "add
anyway" can proceed after the typed input buffers are zeroized; that
pending-add state is zeroized on add-anyway, cancel, modal close, and
auto-lock. Any OTP code retained after generation (HOTP reveal state and
clipboard auto-clear values) is also kept in zeroizing storage and zeroized
when replaced, cleared, expired, or dropped.

Modal-local navigation is consistent across Add / Remove / Rename / Import /
Export / Passphrase / Settings: `Tab` and `Ctrl-N` move to the next
control, `Shift-Tab` and `Ctrl-P` move to the previous control
(vim insert-mode parity), `Enter` activates the focused
button or the modal's default confirm action, `Space` toggles the focused
checkbox / toggle, `←` /
`→` change segmented selectors, and `↑` / `↓` adjust spinners or move within
multi-line field groups. `Ctrl-N` / `Ctrl-P` are field-navigation
aliases only; spinner increment / decrement stays bound to `↑` /
`↓`, and they have no effect on a post-success counts panel
(which has no fields to focus and closes only on `Esc`). Text fields consume printable characters and standard
editing keys. `Esc` cancels the modal and discards pending modal-local edits
unless the modal is showing a post-success counts panel, where `Esc` simply
closes it.

Successful modal outcomes are consistent: manual Add, URI Add, Remove,
Rename, Export, Passphrase, and Settings close the modal and publish a
status-line confirmation (unless Settings Confirm found no changes, which
closes without saving). Import and clipboard-QR Add stay in the modal on a
post-success counts panel so imported/skipped/replaced/appended/warning
counts and any validation-warning messages remain visible; `Esc` closes that
panel. Durability-unconfirmed outcomes are not treated as success closes: the
modal stays open and surfaces the warning inline so the user can retry or
dismiss deliberately.

- **Add** — three input modes selected via a segmented header inside
  the modal: manual fields, paste of an `otpauth://` URI, and a
  focused "scan from clipboard image" control (CLI parity with `add`
  interactive / `--uri` / `--qr`). Switching modes clears the hidden
  secret-bearing fields for the modes being left: the manual Base32
  secret, the URI text, and any pending duplicate/add-anyway state.
  Manual mode collects label, issuer, secret
  (Base32 RFC 4648, case-insensitive, optional `=` padding), algorithm
  (`sha1` / `sha256` / `sha512`), digits (6 / 7 / 8), kind (`totp` or
  `hotp`), period (TOTP-only) or counter (HOTP-only), and optional
  icon-hint mode (`Default from issuer`, `No icon`, or explicit slug);
  defaults follow the CLI manual-add defaults in DESIGN §5 (TOTP, SHA1,
  6 digits, 30 s period, HOTP counter 0, icon-hint defaulted from the
  issuer per §4.1). Each submit captures one `submit_time` used for
  account validation/import timestamps. The icon-hint field accepts a
  free-form token parsed by `paladin_core::parse_icon_hint_token` (shared
  with the CLI add prompts); the resulting `IconHintInput` variants are
  `IconHintInput::Default`, `IconHintInput::Clear`, and
  `IconHintInput::Slug`. Manual entries route through
  `paladin_core::validate_manual(input, submit_time)`. URI mode is a
  single text field; on submit the entered string is passed to
  `paladin_core::parse_otpauth(uri, submit_time)`, and on success
  the resulting `ValidatedAccount` shares the manual path's
  duplicate-detection, "add anyway" override, and
  `Vault::mutate_and_save` insertion.
  Parser errors (`unsupported_import_format`, `validation_error`)
  stay in the modal as inline errors and never mutate the vault. The
  URI text field is treated as a secret-bearing buffer and zeroized on
  submit, cancel, modal close, and auto-lock because the URI embeds
  the Base32 secret. Clipboard images are read
  through `arboard::Clipboard::get_image()`, whose `ImageData` already
  carries raw RGBA8 bytes plus width/height; the TUI calls
  `paladin_core::import::qr_image_bytes(width, height, rgba_bytes, submit_time)`
  per the §4.7 signature, which takes `import_time` directly rather than
  the `ImportOptions` accepted by `import::from_file` /
  `import::from_bytes`. Per DESIGN §4.6, the Add modal checks
  `width * height * 4` against `paladin_core::QR_RGBA_MAX_BYTES`
  before allocating or copying the clipboard buffer and surfaces the
  same `validation_error` (`field: "qr_image"`,
  `reason: "image_too_large"`) inline that the core decoder would
  return for an oversized buffer.
  Validation warnings are rendered with
  `paladin_core::format_validation_warning()` and do not block creation:
  manual / URI additions include them in the status-line confirmation, while
  clipboard-QR additions include them in the post-success counts panel.
  Because `Vault::add` is infallible and duplicate
  presentation policy is owned by the front ends, manual and URI duplicate
  collisions call `Vault::find_duplicate(&validated)` before mutation. A
  collision initially rejects with the existing account in the modal and
  offers an "add anyway" confirmation that inserts the pending validated
  account on the duplicate-allowed path (CLI parity with
  `--allow-duplicate`, appending a new account that shares the
  `(secret, issuer, label)` triple). QR imports
  call `Vault::import_accounts` with
  `ImportConflict::Skip` and report imported/skipped/warning counts plus any
  warning messages in the post-success counts panel.
  Successful additions are wrapped in `Vault::mutate_and_save`, which
  runs the `Vault::add` / `Vault::import_accounts` mutation and save
  under core-owned rollback. If save fails before the primary-file
  commit point (`save_not_committed`), core restores the pre-attempt
  in-memory vault so memory matches disk and the modal stays open with
  the inline error. Durability-unconfirmed saves leave the new accounts
  in memory (matching the committed on-disk state) and surface the
  warning inline.
- **Remove** — confirmation modal. On confirm, wraps `Vault::remove` in
  `Vault::mutate_and_save`. If the save fails before the primary-file
  commit point, core restores the removed account and its previous
  iteration position so memory matches disk and the modal stays open
  with the inline error. Durability-unconfirmed saves leave the account
  removed in memory (matching the committed on-disk state) and surface
  the warning inline.
- **Rename** — single text field pre-populated with the selected
  account's current label. Confirm wraps
  `Vault::rename(id, new_label, now)` in `Vault::mutate_and_save` with
  the trimmed input regardless of whether it equals the current label;
  same label validation as Add (non-empty, §4.1 length limits). Same-label
  renames still call `Vault::rename`, save, and bump `updated_at`, matching
  the CLI. Issuer is **not** editable here — parity with the CLI's
  `rename` taking only `<new-label>`; deeper edits use Remove + Add.
  Pre-commit save failures (`save_not_committed`) restore the prior label so
  memory matches disk and the modal stays open with the inline error;
  durability-unconfirmed saves leave the new label in memory and
  surface the warning inline. Rename does not handle secret material;
  the label buffer is cleared on submit, cancel, modal close, and
  auto-lock alongside the other modal-local state.
- **Import** — text field for the source path, a format selector
  (auto-detect or explicit `otpauth` / `aegis` / `paladin` / `qr`),
  and an on-conflict selector (`skip` / `replace` / `append`).
  Before any Paladin-bundle passphrase prompt, the TUI calls
  `paladin_core::classify_paladin_import_precheck(path, forced_format)` so
  it shares the CLI / GUI prompt decision table. `PromptForPassphrase`
  prompts for the bundle passphrase inside the modal before invoking the
  importer; `Reject(err)` surfaces that exact core error inline without a
  passphrase prompt (for example `unsupported_plaintext_vault`,
  `invalid_header`, or `unsupported_format_version`); and `NoPrompt`
  consumes no passphrase and continues through
  `paladin_core::import::from_file` so the import facade owns `io_error`,
  `unsupported_import_format`, and format-specific validation errors.
  Explicit non-`paladin` forced formats are therefore a core-classified
  `NoPrompt` path rather than local TUI branching. The selected
  `paladin_core::import::from_file` call returns `Vec<ValidatedAccount>`; on
  success, `Vault::import_accounts(accounts, conflict, import_time)` is called
  inside `Vault::mutate_and_save` with the user's policy and the same
  `import_time` passed to `ImportOptions`. The modal reports
  imported/skipped/replaced/appended/warning counts plus validation-warning
  messages rendered through `paladin_core::format_validation_warning()` in a
  post-success counts panel.
  Pre-commit save failures (`save_not_committed`) restore
  core's pre-attempt snapshot so memory matches disk and
  the modal stays open with the inline error; durability-unconfirmed
  saves leave the merged accounts in memory (matching the committed
  on-disk state) and surface the warning. Importer errors
  (`unsupported_import_format`, `unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `validation_error`, `no_entries_to_import`, `decrypt_failed`,
  `invalid_header`, `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`) stay in the modal as inline
  errors and never mutate
  vault state.
- **Export** — format selector (plaintext `otpauth://` JSON list or
  encrypted Paladin bundle) and a destination path field. Overwriting
  an existing file is rejected unless the user confirms an inline
  overwrite gate (parity with CLI `--force`). Encrypted exports
  prompt twice for the bundle passphrase and reject mismatch with
  inline `invalid_passphrase` (`reason: "confirmation_mismatch"`) or
  empty entry with `reason: "zero_length"`. Plaintext exports render
  `paladin_core::format_plaintext_export_warning()` verbatim and the
  user must confirm before the write proceeds. Writes go through
  `paladin_core::write_secret_file_atomic`. On success the modal
  closes with a status-line confirmation showing the written path;
  `io_error`, `save_not_committed`, `save_durability_unconfirmed`,
  `invalid_passphrase`, and the refused overwrite gate stay in the
  modal as inline errors. Export does not mutate the vault, so there
  is no rollback path.
- **Passphrase** — three sub-flows mirroring CLI's
  `passphrase set / change / remove`. The available sub-flow is gated
  by `Vault::is_encrypted()`: `set` is offered only on plaintext
  vaults (plaintext → encrypted), and `change` / `remove` are offered
  only on encrypted vaults. The modal opens to the sub-flow set
  available for the current vault mode; sub-flows that do not match
  the current mode are not selectable. The `remove` sub-flow renders
  `paladin_core::format_plaintext_storage_warning()` verbatim so the
  TUI shares wording with the CLI / GUI.
  New passphrases (`set`, `change`) are prompted twice and confirmed;
  mismatch returns to the modal with an inline `invalid_passphrase`
  (`reason: "confirmation_mismatch"`) error. Empty new passphrases are
  rejected with `invalid_passphrase` (`reason: "zero_length"`).
  `remove` shows the plaintext-storage warning and requires explicit
  confirmation before mutation. The transition methods
  (`set_passphrase` / `change_passphrase` / `remove_passphrase`) save
  themselves through `&Store` and handle their own pre-commit
  rollback per DESIGN §4.5 (the in-memory mode/key reverts to its
  previous state on `save_not_committed` and is replaced on
  `save_durability_unconfirmed`); the TUI surfaces both failure
  classes inline, re-reads `Vault::is_encrypted()` to refresh its
  visible vault-mode flag (unchanged on `save_not_committed`, changed on
  `save_durability_unconfirmed`), and otherwise leaves the in-memory vault
  as the core left it.
- **Settings** — toggles for `auto_lock.enabled` and
  `clipboard.clear_enabled`, spinners for `auto_lock.timeout_secs` and
  `clipboard.clear_secs`. The spinners clamp to the shared core bounds
  (`paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`,
  `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`). The
  modal accumulates pending edits in modal-local state and only commits
  on Confirm: pending values are applied through the same setters
  (`set_auto_lock_*`, `set_clipboard_clear_*`) inside a single
  `Vault::mutate_and_save` transaction. (This Confirm-gated commit is
  intentional and diverges from the GTK plan's per-control live-apply
  semantics; in a keyboard-only UI, modal-local Confirm + `Esc` gives
  a cleaner cancel path than per-toggle persistence.) The UI controls
  clamp to valid
  ranges, but any defensive setter validation failure restores the
  pre-attempt settings snapshot, surfaces inline against the offending
  field, and blocks the save. Closing the modal with `Esc` discards
  pending edits without invoking setters or save. If the save fails
  before the primary-file commit point, core restores the prior settings
  values so memory matches disk and the modal stays open with the inline
  error; the user can adjust and retry. Durability-unconfirmed saves
  leave the new settings in memory (matching the committed on-disk
  state) and surface the warning inline. If no fields changed, Confirm
  closes without invoking save.

## Help overlay

`?` from list focus opens a read-only Help overlay listing every
keybinding from the table below; `Esc` closes the overlay and
restores list focus. The overlay has no inputs and never mutates
vault state. While the search bar is focused or any modal is open,
`?` is consumed as character input by text fields (parity with the
other action keys); the overlay is list-focus-only. The unlock,
missing-vault, and startup-error screens do not bind `?`. The
overlay's content is generated from the same keybindings table that
the workspace `cargo xtask man` target appends into the man page
(after the clap-derived synopsis) so the two cannot drift.

## Auto-lock (per §6)

- **Off by default.** When `auto_lock.enabled = true`, the TUI clears the
  in-memory vault and store (`AppState::Locked`) after
  `auto_lock.timeout_secs` of no input, retaining only the resolved vault path
  and pending clipboard-clear state needed for unlock / scheduled clear, and
  shows the unlock screen for encrypted vaults.
- Encrypted-only gating, idle-deadline math, and expiry checking route
  through `paladin_core::policy::auto_lock::IdlePolicy` (`should_arm`,
  `next_deadline`, `is_expired`). Plaintext vaults are a no-op because
  both `should_arm` and `next_deadline(now, is_encrypted, settings)` take
  the current vault mode; the setting is still persisted so it takes effect
  if the vault is later encrypted via `passphrase set`.
- Idle is reset by any `AppEvent::Input`. The reducer owns the
  `idle_deadline: Option<Instant>` slot, the input event source, and the
  `Locked` transition; on input it refreshes the slot with
  `IdlePolicy::next_deadline(now, vault.is_encrypted(), settings)`, and on each
  `paladin_core::TICK_INTERVAL_MS` `Tick` it asks
  `IdlePolicy::is_expired(deadline, now)` before transitioning. No
  background auto-lock timer threads or stale auto-lock tokens accumulate.
- Locking discards all secret-bearing UI state alongside the vault except
  pending clipboard auto-clear state: any open HOTP reveal window is
  closed and its in-memory code zeroized, the search query is cleared,
  and any modal is closed. The clipboard auto-clear token/value is
  preserved in zeroizing storage across lock so that a copy made just
  before lock still gets wiped at its scheduled time, but lock itself
  does not pre-emptively wipe (per DESIGN §6 "only-if-unchanged"). The
  pending clipboard value is zeroized when its timer fires, is superseded,
  or is dropped.

## Clipboard auto-clear (per §6)

- **Off by default.** When `clipboard.clear_enabled = true`, copying a code
  schedules a wipe after `clipboard.clear_secs`.
- Schedule decision, monotonic token issuance, and the only-if-unchanged
  byte-equality check route through
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy`
  (`schedule(now, settings) -> Option<(ClipboardClearToken, Instant)>` and
  `should_clear(captured, current) -> bool`). The TUI keeps the `arboard`
  reads/writes and the timer that wakes the policy decision: at copy time
  it stores the latest `ClipboardClearToken` plus the captured bytes in UI
  state; on wake, it ignores stale tokens, reads the current clipboard,
  asks `ClipboardClearPolicy::should_clear`, and writes empty when the
  policy returns `true`.

## Effect errors

Effects update visible state only after the underlying mutation succeeds or
reaches the primary-file commit point with durability still uncertain:

- HOTP `n`: the effect first calls `Vault::hotp_peek` to stage the
  would-be visible `Code` (whose `counter_used` is the pre-advance counter)
  in zeroizing pending state, then calls `Vault::hotp_advance` to advance
  and save. It publishes the staged code to the reveal slot only if the
  advance succeeds or returns `save_durability_unconfirmed`; this avoids
  requiring the error type to carry a `Code`.
  Pre-commit save failures (`save_not_committed`) leave the in-memory
  counter and reveal state unchanged (per DESIGN §4.2 rollback), zeroize
  the staged code, and surface a status-line error.
  Durability-unconfirmed failures (`save_durability_unconfirmed`) reveal the
  new code and `Code.counter_used` label and report the
  committed-but-uncertain status
  in the status line — the user has the new code in hand even though
  durability is in question. All other failures show a status-line error
  and leave the previous reveal state unchanged (hidden if no reveal was
  open), zeroizing the staged code before returning.
- Copy: show a status-line error if clipboard write fails; do not schedule
  auto-clear.
- Add / remove / rename / settings saves: validation and setter failures happen
  inside or before `Vault::mutate_and_save`; core restores its
  pre-attempt snapshot on closure errors and no save is attempted.
  Pre-commit save failures (`save_not_committed`) are rolled back by
  `Vault::mutate_and_save` so memory matches disk (Add removes the
  just-inserted account(s); Remove restores the removed account at its
  previous position; Rename restores the prior label; Settings restores
  the prior values), and the modal stays open with the inline error so
  the user can retry. Durability-unconfirmed save errors leave the new
  state in memory (matching the committed on-disk state) and are shown
  as committed-but-uncertain, matching the core error.
- Passphrase set/change/remove: pre-commit and durability-unconfirmed
  handling lives in `Vault` itself per DESIGN §4.5 — the in-memory
  mode/key reverts on `save_not_committed` and is replaced on
  `save_durability_unconfirmed`. The TUI surfaces the typed error
  inline and otherwise trusts the core's rollback.
- QR clipboard import: no clipboard image, image decode failure, zero
  decoded QRs, and invalid QR payloads all stay in the Add modal with an
  inline error.
- Import: importer errors (`unsupported_import_format`,
  `unsupported_plaintext_vault`, `unsupported_encrypted_aegis`,
  `unsupported_aegis_entry_type`, `validation_error`,
  `no_entries_to_import`, `decrypt_failed`,
  `invalid_header`, `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`) stay in the Import modal as
  inline errors and never mutate vault state. Save errors follow the
  Add/Remove/Rename/Settings rule:
  pre-commit (`save_not_committed`) restores the
  `Vault::mutate_and_save` snapshot; durability-unconfirmed leaves the
  merged accounts and surfaces the warning.
- Export: writer errors (`io_error`, `save_not_committed`,
  `save_durability_unconfirmed`, `invalid_passphrase`) and the refused
  overwrite gate stay in the Export modal as inline errors. Export does
  not mutate the vault, so save-error rollback does not apply.

## Keybindings (initial v0.1)

| Key                                | Action                                                                                                |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `↑` `↓` / `j` `k`                  | Move selection up / down (vim-style `j` / `k`)                                                        |
| `PgUp` `PgDn` / `Ctrl-B` `Ctrl-F`  | Page up / page down by viewport height (vim-style `Ctrl-B` / `Ctrl-F`)                                |
| `Home` `End` / `gg` `G`            | Jump to first / last row of the filtered set (vim-style `gg` two-press chord and `G`)                 |
| `Ctrl-U` `Ctrl-D`                  | Half-page up / down (vim-style)                                                                       |
| `zz`                               | Recenter viewport on selected row (vim-style two-press chord)                                         |
| `Enter`                            | Copy selected code (TOTP: current; HOTP: visible only)                                                |
| `n`                                | HOTP next-code (advances + reveals `HOTP_REVEAL_SECS`)                                                |
| `a`                                | Open Add modal                                                                                        |
| `r`                                | Open Remove confirmation                                                                              |
| `R`                                | Open Rename modal (Shift+R; `r` stays bound to Remove)                                                |
| `i`                                | Open Import modal                                                                                     |
| `e`                                | Open Export modal                                                                                     |
| `/`                                | Focus search bar                                                                                      |
| `Tab` `Shift-Tab`                  | Cycle focus between search bar and list (preserves active query when leaving search)                  |
| `Ctrl-N` `Ctrl-P`                  | In modals: next / previous control (aliases for `Tab` / `Shift-Tab`); no effect outside modals        |
| `p`                                | Open Passphrase modal                                                                                 |
| `s`                                | Open Settings modal                                                                                   |
| `?`                                | Open Help overlay (lists all keybindings); `Esc` closes                                               |
| `Esc`                              | Close modal / clear search; close Help overlay; clear pending vim chord; quit on unlock, missing-vault, startup-error screens |
| `q`                                | Quit from list, missing-vault, and startup-error screens; text input in text fields                   |
| `Ctrl-C`                           | Quit (any screen)                                                                                     |

## Tests

Reducer/state-machine logic is pure and tested directly. Rendered frames are
captured with `insta` golden snapshots using `ratatui::backend::TestBackend`.

The checklist below tracks coverage at the bullet level. A ticked box means
at least one named `#[test]` in the indicated file asserts the behavior
end-to-end.

### Reducer (`tests/reducer_tests.rs`)

- [x] Every keybinding maps to the expected state transition.
- [x] Search filter narrows the visible list in place.
- [x] Selection navigation moves correctly under `↑` / `↓` / `j` / `k`,
  `PgUp` / `PgDn` / `Ctrl-B` / `Ctrl-F`, `Ctrl-U` / `Ctrl-D`, and
  `Home` / `End`.
- [x] Modal open / close transitions for every modal.
- [x] HOTP `n` triggers a `HotpAdvance` effect.
- [x] `AppEvent::EffectResult(...)` is the only path by which effect
  outcomes change non-core UI state (status text, reveal windows, modal
  close / counts panels, inline errors). *(Reducer-level emission paths
  covered by the `emit_*_preserves_*` tests for `Effect::Unlock` /
  `Effect::HotpAdvance` / `Effect::CopyCode`; modal-close /
  counts-panel payloads land alongside the modal slices.)*
- [x] Pre-commit effect failures leave visible state unchanged and
  surface inline / status-line errors. *(Reducer-level
  `EffectResult::HotpAdvance` Err handling sets a status-line error
  via `render_error_message` while preserving any prior reveal slot,
  and a successful follow-up advance clears the prior status-line
  note. Modal-side save-error rollback rides with each modal slice in
  "Pre-commit save rollback".)*
- [x] Durability-unconfirmed failures follow the committed-state
  behavior in "Effect errors". *(Reducer-level
  `EffectResult::HotpAdvance` `Err(SaveDurabilityUnconfirmed)` carries
  a `staged_code: Option<Box<Code>>` produced by the executor's
  pre-advance `Vault::hotp_peek`; the reducer opens / replaces the
  reveal slot from that staged code AND surfaces the
  committed-but-uncertain status in the status line, while a
  `staged_code: None` defensive fallback and the
  `SaveNotCommitted`-with-staged-code defensive guard keep the prior
  reveal unchanged. Modal-side durability-unconfirmed coverage lands
  alongside each modal slice.)*
- [x] Modal-local navigation covers `Tab` / `Shift-Tab`, the
  `Ctrl-N` / `Ctrl-P` aliases, `Enter`, `Space`, arrows, text-field
  editing, and `Esc` cancel / close behavior for every modal. *(Add /
  Settings modals route Tab / Shift-Tab / Ctrl-N / Ctrl-P / Enter /
  Space / arrows / Char / Backspace through dedicated focus-cycling
  paths covered in the "Add modal" and "Settings modal — field focus"
  slices; Remove / Rename single-field modals add explicit
  `*_modal_{tab,shift_tab,space,up,down,left,right}_arrow_is_silent_noop`
  tests with Rename's Space (`Char(' ')`) appending to the draft;
  Import / Export / Passphrase unit-variant stubs land
  `{import,export,passphrase}_modal_navigation_keys_are_silent_no_op`
  loops that pass Tab / Shift-Tab / Enter / Space / four arrows /
  printable Char / Backspace through `assert_ctrl_modal_alias_is_silent_no_op`;
  Esc-close coverage lives in
  `pressing_esc_on_unlocked_with_open_*_modal_closes_the_modal`.)*

### Vim-style navigation (`tests/reducer_tests.rs`)

- [x] `j` / `k` mirror `↓` / `↑`.
- [x] `Ctrl-F` / `Ctrl-B` mirror `PgDn` / `PgUp`.
- [x] `G` mirrors `End`.
- [x] `gg` two-press chord jumps to the first row of the filtered set.
- [x] `zz` two-press chord recenters the viewport on the selected row.
- [x] Pending-leader chord state is held by the reducer, committed on
  the matching second press, and cleared by any non-matching key,
  focus change, modal open, `Esc`, or auto-lock.
- [x] Search-focus pass-through routes `PgUp` / `PgDn` / `Home` / `End`
  / `Ctrl-B` / `Ctrl-F` / `Ctrl-D` / `Ctrl-U` to the list before
  `tui-input` sees them.
- [x] Bare-letter vim keys (`j`, `k`, `g`, `G`, `z`) are consumed by the
  search field as text input and never trigger chord state from the
  search field.
- [x] Empty filtered set: every list-navigation key including the
  chords is a silent no-op.
- [x] `Ctrl-N` / `Ctrl-P` inside modals advance / retreat focus the
  same as `Tab` / `Shift-Tab` — for every modal variant, symmetry
  with `Tab` / `Shift-Tab` is locked in, and at the top level the
  pair is unbound so they cannot leak into List ↔ Search focus
  cycling. *(Add modal Manual-mode focus cycle covered by
  `tab_in_add_modal_manual_mode_advances_focus_through_all_fields_with_wrap`
  and its `BackTab` / `Ctrl-N` / `Ctrl-P` siblings; Uri / Qr modes
  treat the same keys as silent no-ops so `manual_focus` stays
  sticky.)*
- [x] `Ctrl-N` / `Ctrl-P` inside modals have no effect on a
  post-success counts panel — lands alongside the counts panel
  payload (Add / Import / Export). *(Add modal covered now that
  `AddModal::counts_panel` exists: `route_add_modal_input` short-
  circuits to a silent no-op when `counts_panel.is_some()` and
  the key is `is_modal_focus_next` / `is_modal_focus_prev`, so
  neither the Manual focus ring nor the Uri text buffer nor the
  Qr-mode dispatch is reachable while the panel is up. Asserted
  by `ctrl_n_with_counts_panel_set_in_{qr,manual,uri}_mode_…`
  and the matching `ctrl_p_…` siblings. Import / Export modals
  will hook into the same early-out as their counts-panel
  payloads land.)*
- [x] `Ctrl-N` / `Ctrl-P` inside modals do not override `↑` / `↓`
  spinner adjustments — lands alongside the spinner payload
  (Settings). *(Reducer routes `Ctrl-N` / `Ctrl-P` through
  `is_modal_focus_next` / `is_modal_focus_prev` before the
  spinner-adjust path runs, so pressing either chord while focus
  rests on `AutoLockTimeoutSecs` or `ClipboardClearSecs` advances /
  retreats `SettingsFocus` without mutating
  `auto_lock_timeout_secs` / `clipboard_clear_secs`. Asserted by
  `ctrl_n_on_auto_lock_timeout_spinner_focus_advances_focus_without_changing_value`,
  `ctrl_p_on_auto_lock_timeout_spinner_focus_retreats_focus_without_changing_value`,
  `ctrl_n_on_clipboard_clear_secs_spinner_focus_advances_focus_without_changing_value`,
  and
  `ctrl_p_on_clipboard_clear_secs_spinner_focus_retreats_focus_without_changing_value`
  in `tests/reducer_tests.rs`.)*

### Search (`tests/search_tests.rs`)

- [x] Case-insensitive substring match through
  `paladin_core::account_matches_search` (same base match key as CLI
  query resolution in DESIGN §5; empty issuer allowed and the colon is
  still present in the match key); no Unicode normalization.
- [x] Insertion order is preserved among matches.
- [x] Filter changes route through `paladin_core::select_after_filter`:
  preserve the selected `AccountId` when still visible, otherwise the
  first match, `None` when empty.
- [x] Empty result sets have no selection; action keys that require a
  selected row surface the "no account selected" status-line error.
- [x] The `id:` prefix form is CLI-only and is **not** honored by the
  TUI search.

### Auto-lock (`tests/auto_lock_tests.rs`)

- [x] `idle_deadline` is set via
  `paladin_core::policy::auto_lock::IdlePolicy::next_deadline(now,
  vault.is_encrypted(), settings)` on `Unlocked` + `enabled` +
  encrypted (i.e. `IdlePolicy::should_arm` is `true`).
- [x] `idle_deadline` resets on any `AppEvent::Input`.
- [x] Transition to `Locked` fires when a
  `paladin_core::TICK_INTERVAL_MS` `Tick` observes
  `IdlePolicy::is_expired`.
- [x] No-op for plaintext vaults (deadline stays `None`).
- [x] Setting persists across saves.
- [x] Locking discards the `Vault` / `Store`, open HOTP reveal windows,
  the search query, and any modal while retaining the resolved vault
  path for the next unlock attempt.
- [x] A clipboard auto-clear timer scheduled before lock survives lock
  and still fires only-if-unchanged.

### Clipboard auto-clear (`tests/clipboard_tests.rs`)

- [x] Copy schedules a clear via
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`.
  *(Reducer-level: `EffectResult::CopyCode { result: Ok(value), … }`
  on `Unlocked` routes through
  `ClipboardClearPolicy::schedule(completed_at, vault.settings())`
  and seeds `pending_clipboard_clear`; the schedule returns `None`
  when `clipboard_clear_enabled = false` and the reducer leaves
  `pending_clipboard_clear` untouched. `Err(())` surfaces the
  `clipboard_write_failed` status-line error per "Effect errors"
  without scheduling. The executor-side `arboard` write that
  produces the `Ok(value)` lands with the clipboard-adapter slice.)*
- [x] Stale tokens are ignored on wake.
  *(Reducer-level: `AppEvent::ClipboardClear { token, .. }` on
  `AppState::Locked` with a `Some(pending)` slot whose `token !=
  event_token` short-circuits to a state-preserving no-op with no
  `Effect::ClearClipboard` dispatched. A `None` pending slot on
  `Locked` is also a no-op so a duplicate wake after the matching-
  token branch already cleared the slot drops cleanly. The
  Unlocked-wake branch lands alongside the clipboard adapter / copy
  slice.)*
- [x] "Only-if-unchanged" honored when an external copy mutates the
  clipboard between copy and wake. *(Executor-level: the
  `Effect::ClearClipboard` arm of `paladin_tui::app::effect::execute`
  reads the live clipboard via `paladin_tui::clipboard::read_text`,
  feeds the captured bytes plus the live `current` bytes into
  `paladin_core::ClipboardClearPolicy::should_clear`, and only calls
  `clipboard::write_text("")` when the byte comparison returns `true`.
  A read failure (e.g. `arboard` unavailable, or
  `PALADIN_CLIPBOARD_DRYRUN=fail`) is a silent no-op so the executor
  cannot clobber unrelated bytes when it cannot verify the
  invariant. Asserted by
  `executor_only_if_unchanged::execute_clear_clipboard_writes_empty_when_live_clipboard_still_matches`,
  `…_preserves_clipboard_when_external_copy_intervenes`,
  `…_preserves_clipboard_when_live_is_empty`, and
  `…_noop_when_clipboard_read_fails` in `tests/clipboard_tests.rs`.)*
- [x] Pending copied values are zeroized after the clear attempt or
  stale-token drop. *(`PendingClipboardClear.value`,
  `AppEvent::ClipboardClear.value`, `Effect::ClearClipboard.value`, and
  `EffectResult::CopyCode.result`'s `Ok` payload are all
  `Zeroizing<Vec<u8>>` so `Drop` wipes the bytes before the backing
  allocation is freed — covers the "after the clear attempt"
  executor-drop path and the "stale-token drop" reducer-drop path.)*
- [x] Clipboard flows are exercised through the
  `PALADIN_CLIPBOARD_DRYRUN=1` adapter hook so they run without a
  clipboard server. *(`paladin-tui/src/clipboard.rs` mirrors the
  `paladin-cli` adapter: under `cfg(feature = "test-hooks")`,
  `PALADIN_CLIPBOARD_DRYRUN=1` routes `read_text` / `write_text`
  through an in-process `Mutex<String>` fake addressable via
  `seed_test_clipboard` / `read_test_clipboard`, and
  `PALADIN_CLIPBOARD_DRYRUN=fail` collapses both calls to `Err(())`
  so the `clipboard_write_failed` / read-failure branches stay
  covered. A `test_clipboard_lock()` mutex serializes env-var
  manipulation across the `cargo test` thread pool. Asserted by
  `dryrun_adapter_round_trip_writes_and_reads_in_process_fake` and
  `dryrun_adapter_fail_mode_returns_err_for_both_read_and_write`,
  and exercised end-to-end by every
  `executor_only_if_unchanged::execute_clear_clipboard_*` test in
  `tests/clipboard_tests.rs`.)*

### Terminal lifecycle (`tests/terminal_tests.rs`)

- [x] Terminal setup uses a guard that restores raw mode and
  alternate-screen state on normal exit, startup failure after setup,
  `Ctrl-C`, and panic unwind.

### Global args (`tests/reducer_tests.rs`)

- [x] `--vault` selects the inspected / opened vault path.
- [x] `--no-color` disables ratatui styling.
- [x] `NO_COLOR` (when `--no-color` is absent) disables ratatui
  styling.
- [x] `--json` is rejected at parse time with clap's text diagnostic
  and no JSON envelope.

### Add modal (`tests/reducer_tests.rs`)

- [x] Manual duplicate collision is detected through
  `Vault::find_duplicate(&validated)` and rejects with the existing
  account.
  *(Executor wires `validate_manual` + `Vault::find_duplicate` and
  emits `EffectResult::Add { Err(AddFailure::Duplicate { existing,
  pending }) }`; reducer stashes the pending `ValidatedAccount` in
  `AddModal::pending_duplicate_add` and surfaces the inline
  `duplicate_account` message via `format_duplicate_account_message`.
  Asserted by
  `execute_add_with_duplicate_emits_duplicate_failure_and_does_not_mutate_vault`
  in `tests/effect_tests.rs` and
  `effect_result_add_duplicate_stashes_pending_and_sets_inline_error`
  + discard-path siblings in `tests/reducer_tests.rs`.)*
- [x] URI duplicate collision is detected through
  `Vault::find_duplicate(&validated)` and rejects with the existing
  account.
  *(Reducer's URI-mode Enter handler emits a new `Effect::AddFromUri
  { path, uri }` carrying the typed bytes taken (and zeroized) from
  `AddModal::uri_text`; the executor calls `paladin_core::parse_otpauth`
  + `Vault::find_duplicate` and emits the same `EffectResult::Add
  { Err(AddFailure::Duplicate { existing, pending }) }` channel
  the Manual-mode path already uses, so the reducer's pending-stash
  + inline `duplicate_account` rendering covers Manual and URI alike.
  Asserted by
  `execute_add_from_uri_with_duplicate_emits_duplicate_failure_and_does_not_mutate_vault`
  and `execute_add_from_uri_with_invalid_uri_emits_validation_failure`
  in `tests/effect_tests.rs`;
  `enter_in_uri_mode_emits_add_from_uri_effect_with_typed_bytes`
  + `enter_in_uri_mode_with_empty_buffer_still_emits_effect_to_surface_parse_error`
  in `tests/reducer_tests.rs`.)*
- [x] The follow-up "add anyway" confirmation inserts the pending
  validated account on the duplicate-allowed path with a fresh ID.
  *(Reducer's `route_add_modal_input` short-circuits Enter to emit a
  new `Effect::AddAnyway { path, validated }` whenever
  `AddModal::pending_duplicate_add.is_some()`, taking the pending
  state and clearing the inline duplicate error before the
  mode-specific Manual / URI submit paths run. The executor wraps
  `Vault::add(validated.account)` in `Vault::mutate_and_save`, so
  `Vault::add` assigns a fresh `AccountId` distinct from the
  colliding entry and the on-disk primary is committed atomically;
  the outcome rides the shared `EffectResult::Add` channel as
  `Ok(AddSuccess { summary, warnings })` with the warnings carried
  from the pre-validated account. The reducer's `Ok` arm now closes
  `Modal::Add` so the user returns to the list view — status-line
  confirmation wording (and validation-warning text) lands with the
  dedicated "Manual / URI Add status-line confirmations include
  validation warning text" slice. Asserted by
  `execute_add_anyway_inserts_validated_account_with_fresh_id_and_persists`
  and `execute_add_anyway_with_mismatched_path_is_silently_dropped`
  in `tests/effect_tests.rs`, and by
  `enter_with_pending_duplicate_add_in_manual_mode_emits_add_anyway_effect`,
  `enter_with_pending_duplicate_add_in_uri_mode_emits_add_anyway_effect`,
  and `effect_result_add_ok_closes_modal` in `tests/reducer_tests.rs`.)*
- [x] Clipboard QR import uses `ImportConflict::Skip` and reports
  imported / skipped counts.
  *(Executor's `Effect::AddFromClipboardQr` arm in
  `crates/paladin-tui/src/app/effect.rs` calls
  `Vault::import_accounts(_, ImportConflict::Skip, _)` after the
  shared QR-decode path, and the reducer mirrors the resulting
  `ImportReport.imported` / `skipped` totals into
  `AddModal::counts_panel`. Asserted by
  `effect_result_qr_import_ok_populates_counts_panel_with_imported_and_skipped_counts`
  and the skip-only sibling
  `effect_result_qr_import_ok_with_only_skips_still_populates_counts_panel`
  in `tests/reducer_tests.rs`.)*
- [x] QR-add validation warnings are rendered through
  `paladin_core::format_validation_warning()` in the post-success
  counts panel.
  *(`reduce_qr_import_result`'s `Ok` arm maps each
  `ImportReport.warnings` entry through
  `paladin_core::format_validation_warning(&w.warning)` into
  `AddModal::counts_panel.warnings` while preserving source order.
  Asserted by
  `effect_result_qr_import_ok_renders_warnings_through_format_validation_warning`,
  `effect_result_qr_import_ok_preserves_warning_order_across_multiple_warnings`,
  and the empty-list sibling
  `effect_result_qr_import_ok_with_no_warnings_yields_empty_warnings_list`
  in `tests/reducer_tests.rs`.)*
- [x] Manual / URI Add status-line confirmations include validation
  warning text.
  *(`reduce_add_result`'s `Ok` arm composes
  `Added <format_account_display_label>.` plus a
  `warning: <format_validation_warning(w); …>` trailer for any
  `AddSuccess::warnings`, joining multiple rendered warnings with
  `; ` so the status line stays single-line and matches the CLI's
  `paladin: warning: <text>` advisory wording. Asserted by
  `effect_result_add_ok_sets_status_line_confirmation_with_display_label`,
  `effect_result_add_ok_includes_validation_warning_text_in_confirmation`,
  and
  `effect_result_add_ok_joins_multiple_validation_warnings_with_separator`
  in `tests/reducer_tests.rs`.)*
- [x] No-image, no-QR, and invalid-QR cases reject inline.
  *(Every `EffectResult::QrImport { Err(QrImportFailure::*) }`
  variant lands in `AddModal::error` via
  `format_qr_import_failure` / `render_error_message` and leaves
  the modal in `AddMode::Qr` with no status-line confirmation.
  Asserted by
  `effect_result_qr_import_no_clipboard_image_sets_inline_error_and_keeps_modal_open`
  (no-image),
  `effect_result_qr_import_image_decode_failure_sets_inline_error_and_keeps_modal_open`
  (decode failure — no readable QR),
  `effect_result_qr_import_no_qrs_decoded_sets_inline_error_via_render_error_message`
  (image decoded but no QR payload via
  `PaladinError::NoEntriesToImport`),
  `effect_result_qr_import_invalid_qr_payload_sets_inline_error_via_render_error_message`
  and
  `effect_result_qr_import_oversized_rgba_buffer_sets_inline_error_via_render_error_message`
  (invalid-QR variants), with discard / state-isolation siblings
  `effect_result_qr_import_err_does_not_close_modal_or_publish_status_line`,
  `effect_result_qr_import_err_does_not_perturb_other_modal_state`,
  and the `not Unlocked` / `no modal` / `different modal` discard
  trio, all in `tests/reducer_tests.rs`.)*

### Import modal (`tests/reducer_tests.rs`)

- [x] Format auto-detect routes through
  `paladin_core::import::from_file`.
  *(Reducer's Import-modal Enter handler emits
  `Effect::Import { format: None, conflict: Skip, paladin_passphrase:
  None, .. }` keyed off the default
  `ImportFormatSelector::Auto`; the executor builds
  `paladin_core::ImportOptions { format: None, .. }` and calls
  `paladin_core::import::from_file`, then commits the resulting
  `Vec<ValidatedAccount>` through `Vault::import_accounts` wrapped in
  `Vault::mutate_and_save`. Asserted by
  `execute_import_with_auto_format_routes_through_import_from_file_for_otpauth_payload_and_persists_via_mutate_and_save`
  in `tests/effect_tests.rs` and
  `enter_in_import_modal_with_default_state_emits_import_effect_with_auto_format_and_skip_conflict`
  in `tests/reducer_tests.rs`, with the path-guard sibling
  `execute_import_with_mismatched_path_is_silently_dropped` and the
  io_error sibling
  `execute_import_with_missing_source_file_emits_io_error_failure_and_leaves_vault_untouched`.)*
- [x] Explicit format overrides (`otpauth` / `aegis` / `paladin` /
  `qr`) route through `paladin_core::import::from_file`.
  *(Reducer side:
  `enter_in_import_modal_with_otpauth_selector_emits_import_effect_with_some_otpauth`,
  `enter_in_import_modal_with_aegis_selector_emits_import_effect_with_some_aegis`,
  `enter_in_import_modal_with_paladin_selector_emits_import_effect_with_some_paladin`,
  and
  `enter_in_import_modal_with_qr_selector_emits_import_effect_with_some_qr_image`
  in `tests/reducer_tests.rs` assert each `ImportFormatSelector` variant
  translates to the matching `Some(ImportFormat)` payload on
  `Effect::Import` via `ImportFormatSelector::forced()`. A companion
  test
  `enter_in_import_modal_with_paladin_selector_still_carries_none_passphrase_at_submit`
  documents that the forced-Paladin override carries
  `paladin_passphrase: None` at this slice — the precheck / prompt
  slice lives in the next checklist item. Executor side:
  `execute_import_with_forced_aegis_format_routes_through_import_from_file_for_aegis_payload_and_persists_via_mutate_and_save`
  in `tests/effect_tests.rs` proves forced `Some(ImportFormat::Aegis)`
  over Aegis-shaped JSON dispatches to `aegis_plaintext` inside
  `paladin_core::import::from_file` and commits via
  `Vault::mutate_and_save`;
  `execute_import_with_forced_format_mismatch_returns_unsupported_import_format_without_mutation`
  proves a forced/detected mismatch surfaces
  `PaladinError::UnsupportedImportFormat { format: "aegis" }` inline
  with no live-vault or on-disk mutation.)*
- [x] Pre-prompt Paladin decision routes through
  `paladin_core::classify_paladin_import_precheck`, prompting only on
  `PromptForPassphrase`.
  *(Reducer's Import-modal `Enter` handler now calls
  `classify_paladin_import_precheck(&source_path, forced_format)` and
  branches on the result. `PromptForPassphrase` seeds
  `import.paladin_passphrase = Some(PassphraseBuffer::new())` and
  emits no effect; the next `Enter` consumes the typed buffer via
  `PassphraseBuffer::take` and emits `Effect::Import` with
  `paladin_passphrase: Some(_)`. Asserted by
  `enter_in_import_modal_with_encrypted_paladin_path_transitions_to_passphrase_phase_without_emitting_effect`
  and
  `enter_in_import_modal_passphrase_phase_emits_import_effect_with_typed_passphrase`
  in `tests/reducer_tests.rs`.)*
- [x] `Reject(err)` from the precheck surfaces inline without a
  passphrase prompt.
  *(Both `Reject(UnsupportedPlaintextVault)` and the malformed-header
  arms — `Reject(UnsupportedFormatVersion)`, `Reject(InvalidHeader)`
  — render through `render_error_message` into `import.error` while
  the modal stays in path-entry phase. Asserted by
  `enter_in_import_modal_with_plaintext_paladin_path_surfaces_unsupported_plaintext_vault_inline`,
  `enter_in_import_modal_with_unsupported_paladin_format_version_surfaces_inline`,
  and `enter_in_import_modal_with_invalid_paladin_header_surfaces_inline`.)*
- [x] `NoPrompt` from the precheck continues through the import facade.
  *(Auto-detect over non-Paladin payloads, missing files, and
  forced-non-Paladin formats over a Paladin bundle all emit
  `Effect::Import` with `paladin_passphrase: None`. Asserted by
  `enter_in_import_modal_with_non_paladin_file_proceeds_to_import_effect_with_none_passphrase`,
  `enter_in_import_modal_with_missing_source_file_proceeds_to_import_effect_with_none_passphrase`,
  and the
  `enter_in_import_modal_with_forced_{otpauth,aegis,qr}_format_over_encrypted_paladin_emits_import_with_none_passphrase`
  trio.)*
- [x] Coverage spans encrypted Paladin, plaintext Paladin,
  malformed/unsupported Paladin headers, missing files, non-Paladin
  content, and forced-format mismatches through the shared helper.
  *(See the tests listed above plus
  `enter_in_import_modal_with_forced_paladin_format_over_encrypted_paladin_transitions_to_passphrase_phase`
  and
  `enter_in_import_modal_with_forced_paladin_format_over_plaintext_paladin_surfaces_unsupported_plaintext_vault`
  for forced-Paladin coverage on both header shapes.)*
- [x] On-conflict policy (`skip` / `replace` / `append`) is forwarded
  to `Vault::import_accounts` and reflected in the report counts.
  *(Reducer side: `import.conflict` rides verbatim onto
  `Effect::Import.conflict` — `Skip` is locked by the existing
  `enter_in_import_modal_with_default_state_emits_import_effect_with_auto_format_and_skip_conflict`,
  and the new
  `enter_in_import_modal_with_replace_conflict_emits_import_effect_with_replace`
  and
  `enter_in_import_modal_with_append_conflict_emits_import_effect_with_append`
  in `tests/reducer_tests.rs` lock the other two variants via a
  shared `import_conflict_after_enter_with_policy` helper. Executor
  side: three siblings in `tests/effect_tests.rs` —
  `execute_import_with_skip_conflict_over_colliding_account_records_skip_and_leaves_vault_unchanged`,
  `execute_import_with_replace_conflict_over_colliding_account_preserves_id_and_persists`,
  and
  `execute_import_with_append_conflict_over_colliding_account_inserts_fresh_id_and_persists`
  — seed a single TOTP account whose `(secret, issuer=None, label)`
  triple collides with an `otpauth://totp/{label}?secret=JBSWY3DPEHPK3PXP`
  source payload, then drive each `ImportConflict` through
  `Effect::Import` and assert the matching `ImportReport` count
  (`skipped` / `replaced` / `appended`) increments, the other three
  counts stay at zero, and the live + on-disk vault reflect the
  chosen merge action: Skip keeps the original ID, Replace preserves
  the existing `AccountId` in `ImportReport.accounts`, and Append
  emits a fresh `AccountId` distinct from the existing one. The
  non-colliding `Skip` happy path remains covered by
  `execute_import_with_auto_format_routes_through_import_from_file_for_otpauth_payload_and_persists_via_mutate_and_save`.)*
- [x] Validation warnings are rendered through
  `paladin_core::format_validation_warning()`.
  *(Reducer's `reduce_import_result` Ok arm renders each
  `ImportReport::warnings` entry through
  `paladin_core::format_validation_warning` and seeds
  `ImportModal::counts_panel.warnings`, mirroring the QR-add post-success
  panel. Asserted by
  `effect_result_import_ok_renders_warnings_through_format_validation_warning`,
  `effect_result_import_ok_preserves_warning_order_across_multiple_warnings`,
  and `effect_result_import_ok_with_no_warnings_yields_empty_warnings_list`
  in `tests/reducer_tests.rs`.)*
- [x] Importer errors (`unsupported_import_format`,
  `unsupported_plaintext_vault`, `unsupported_encrypted_aegis`,
  `unsupported_aegis_entry_type`, `validation_error`,
  `no_entries_to_import`, `decrypt_failed`, `invalid_header`,
  `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`) surface inline without
  mutation.
  *(Reducer's `reduce_import_result` Err arm renders the carried
  `PaladinError` through `render_error_message` and stashes it in
  `ImportModal::error`, leaving the modal open. The `counts_panel` slot
  stays unset on Err, and the in-memory vault is not mutated. One
  reducer test per error variant —
  `effect_result_import_err_unsupported_import_format_renders_inline`,
  `effect_result_import_err_unsupported_plaintext_vault_renders_inline`,
  `effect_result_import_err_unsupported_encrypted_aegis_renders_inline`,
  `effect_result_import_err_unsupported_aegis_entry_type_renders_inline`,
  `effect_result_import_err_validation_error_renders_inline`,
  `effect_result_import_err_no_entries_to_import_renders_inline`,
  `effect_result_import_err_decrypt_failed_renders_inline`,
  `effect_result_import_err_invalid_header_renders_inline`,
  `effect_result_import_err_invalid_payload_renders_inline`,
  `effect_result_import_err_unsupported_format_version_renders_inline`,
  `effect_result_import_err_kdf_params_out_of_bounds_renders_inline`,
  `effect_result_import_err_io_error_renders_inline` — plus
  `effect_result_import_err_keeps_modal_open` in
  `tests/reducer_tests.rs`.)*
- [x] Successful imports persist via `Vault::mutate_and_save`.
  *(Reducer Ok-arm coverage:
  `effect_result_import_ok_populates_counts_panel_with_all_four_counts`
  asserts the four `ImportReport` merge totals
  (`imported`/`skipped`/`replaced`/`appended`) flow into
  `ImportModal::counts_panel`;
  `effect_result_import_ok_does_not_close_modal`,
  `effect_result_import_ok_clears_prior_inline_error`, and
  `effect_result_import_ok_does_not_perturb_vault_state` lock the
  rest of the Ok contract. The executor-side `mutate_and_save` route
  is already locked by
  `execute_import_with_auto_format_routes_through_import_from_file_for_otpauth_payload_and_persists_via_mutate_and_save`
  in `tests/effect_tests.rs`.)*
- [x] A `save_not_committed` failure restores the core snapshot so
  `Vault::iter()` matches its pre-attempt state.
  *(Reducer side:
  `effect_result_import_err_save_not_committed_renders_inline_and_leaves_vault_unchanged`
  asserts the Err arm renders the inline error and does not perturb
  the in-memory vault. Executor side: the fault-injection test
  `import_save_not_committed::execute_import_with_save_not_committed_failure_rolls_back_live_vault_to_pre_attempt_snapshot`
  in `tests/effect_tests.rs` (gated on `--features test-hooks`) drives
  `Effect::Import` with `PALADIN_FAULT_INJECT=pre_commit` so
  `Vault::mutate_and_save` exercises its snapshot-restore path; both
  the live `vault.iter()` order/count and the on-disk vault match the
  pre-attempt snapshot.)*

### Export modal (`tests/reducer_tests.rs`)

- [x] Plaintext format selector routes to
  `paladin_core::export::otpauth_list`.
  *(Executor-side coverage:
  `execute_export_with_plaintext_format_routes_through_otpauth_list_and_writes_via_write_secret_file_atomic`
  in `tests/effect_tests.rs` constructs an `Effect::Export` with
  `ExportFormat::Plaintext`, asserts the written file's bytes equal
  `paladin_core::export::otpauth_list(&vault).into_bytes()` exactly,
  and asserts `EffectResult::Export { result: Ok(()) }` rides back on
  the channel.)*
- [x] Encrypted format selector routes to
  `paladin_core::export::encrypted`.
  *(Executor-side coverage:
  `execute_export_with_encrypted_format_routes_through_export_encrypted_and_writes_via_write_secret_file_atomic`
  in `tests/effect_tests.rs` constructs an `Effect::Export` with
  `ExportFormat::Encrypted` and `Some(SecretString)`, then pins
  three routing axes that only `core_export::encrypted` →
  `write_secret_file_atomic` can satisfy together:
  (1) the written bytes carry the §4.3 header — `PALADIN\0` magic,
  `format_ver = 1`, `mode = 1` (encrypted);
  (2) `paladin_core::import::paladin` decrypts the bundle with the
  same passphrase and recovers the source vault's labels in order;
  (3) under `#[cfg(unix)]` the destination file's permission bits
  land at `0o600`. The test also re-asserts the §4.6 non-mutation
  invariant for Export — both the in-memory iteration order and
  the re-opened on-disk source vault match the pre-export account
  snapshot, since the executor never calls `Vault::save` on the
  export path.)*
- [x] Refused overwrite gate rejects without writing.
  *(`enter_in_export_modal_with_existing_destination_refuses_without_emitting_export_effect`
  in `tests/reducer_tests.rs` seeds a pre-existing destination file,
  opens `Modal::Export` with that path pre-populated, presses Enter,
  and asserts no `Effect::Export` is emitted, the modal stays open,
  the rendered `ValidationError { field: "path", reason:
  "output_exists" }` lands inline on `ExportModal::error`, and the
  seeded destination is byte-for-byte unchanged. Mirrors the CLI's
  `refuse_existing_overwrite` gate (DESIGN.md §5) and the GTK
  `overwrite_gate_needs_reset` flow.)*
- [x] Encrypted export prompts twice and rejects mismatch with
  `confirmation_mismatch`.
  *(`enter_in_encrypted_export_modal_with_mismatched_passphrases_refuses_with_confirmation_mismatch`
  in `tests/reducer_tests.rs` opens `Modal::Export` with
  `format = ExportFormat::Encrypted`, a fresh destination path that
  the overwrite gate accepts, and two `PassphraseBuffer`s carrying
  divergent bytes (`"hunter2"` / `"hunter3"`). Pressing Enter asserts
  no `Effect::Export` is emitted, the modal stays open, the rendered
  `InvalidPassphrase { reason: "confirmation_mismatch" }` lands inline
  on `ExportModal::error`, the format selector stays on `Encrypted`,
  no status-line spill occurs, and the destination remains absent on
  disk. Mirrors the CLI's `prompt_new_passphrase` (DESIGN.md §5) and
  the GTK `SubmitRejection::ConfirmationMismatch` wire code so the
  user-facing reason stays stable across all three front-ends.)*
- [x] Encrypted export rejects empty new passphrase with `zero_length`.
  *(`enter_in_encrypted_export_modal_with_empty_new_passphrase_refuses_with_zero_length`
  in `tests/reducer_tests.rs` opens `Modal::Export` with
  `format = ExportFormat::Encrypted`, a fresh destination path that
  the overwrite gate accepts, and two empty `PassphraseBuffer`s (so
  the byte-for-byte mismatch gate slips past — both buffers are
  equal). Pressing Enter asserts no `Effect::Export` is emitted, the
  modal stays open, the rendered
  `InvalidPassphrase { reason: "zero_length" }` lands inline on
  `ExportModal::error`, the format selector stays on `Encrypted`, no
  status-line spill occurs, and the destination remains absent on
  disk. Gate ordering matches the CLI's `prompt_new_passphrase`
  (mismatch first, then `zero_length`, DESIGN.md §5) and the GTK
  `SubmitRejection::ZeroLength` wire code so the user-facing reason
  stays stable across all three front-ends.)*
- [x] Plaintext export requires the unencrypted-secrets confirmation
  before writing.
  *(`enter_in_plaintext_export_modal_without_confirmation_refuses_with_plaintext_warning`
  in `tests/reducer_tests.rs` opens `Modal::Export` with
  `format = ExportFormat::Plaintext`, a fresh destination path that
  the overwrite gate accepts, and `plaintext_confirmed = false`.
  Pressing Enter asserts no `Effect::Export` is emitted, the modal
  stays open, `paladin_core::format_plaintext_export_warning()` lands
  verbatim on `ExportModal::error`, the format selector stays on
  `Plaintext`, the acknowledgement flag is not flipped by the gate
  itself, no status-line spill occurs, and the destination remains
  absent on disk. Wording parity with the CLI's stderr advisory
  (`paladin-cli/src/commands/export.rs`, DESIGN.md §4.6 / §6) and the
  GTK `ExportDialog`'s `plaintext_warning_body()` checkbox label so
  the unencrypted-secrets warning stays in lockstep across all three
  front-ends.)*
- [x] Output is written through
  `paladin_core::write_secret_file_atomic` with mode `0600`.
  *(Locked alongside the plaintext-routing test: the same
  `execute_export_with_plaintext_format_routes_through_otpauth_list_and_writes_via_write_secret_file_atomic`
  test stats the written file under `#[cfg(unix)]` and asserts the
  permissions land at `0o600`, which the executor inherits by handing
  bytes to `paladin_core::write_secret_file_atomic`.)*
- [x] Writer `io_error`, `save_not_committed`, and
  `save_durability_unconfirmed` surface inline and the modal stays
  open.
  *(Three sibling reducer tests in `tests/reducer_tests.rs` —
  `effect_result_export_err_io_error_surfaces_inline_and_keeps_modal_open`,
  `effect_result_export_err_save_not_committed_surfaces_inline_and_keeps_modal_open`,
  and
  `effect_result_export_err_save_durability_unconfirmed_surfaces_inline_and_keeps_modal_open`
  — each drive `AppEvent::EffectResult(EffectResult::Export { result:
  Err(...) })` through `reduce` while `Modal::Export` is open and
  assert (1) the rendered `PaladinError` lands on
  `ExportModal::error` byte-for-byte through `render_error_message`,
  (2) the Export modal stays open with no follow-up effects, and (3)
  the status line stays clear so every writer / save error stays
  inline on the modal. Wired via `reduce_export_result`'s Err arm in
  `src/app/reducer.rs`.)*
- [x] Export performs no `Vault::save` and leaves vault state
  unchanged across success and failure.
  *(All three Err-arm tests above plus
  `effect_result_export_ok_leaves_vault_iter_unchanged` seed the
  fixture vault with two TOTP accounts (`"alpha"`, `"bravo"`),
  snapshot the `Vault::iter()` labels through
  `vault_label_snapshot`, drive the reducer with both `Ok(())` and
  every `Err(...)` variant, and assert the post-reduce label list
  is byte-identical to the pre-attempt snapshot. The §4.6
  non-mutation invariant is structurally enforced by
  `reduce_export_result` never touching `vault` — the Err arm only
  writes to `ExportModal::error`, and the executor-side
  `execute_export` in `src/app/effect.rs` never calls
  `Vault::save`.)*

### Settings modal (`tests/reducer_tests.rs`)

- [x] Pending edits are buffered until Confirm.
  *(`settings_modal_space_and_arrow_edits_buffer_pending_until_confirm`
  in `tests/reducer_tests.rs` interleaves Tab / Space / ↑ presses
  across all four pending fields and asserts that `vault.settings()`
  is byte-identical before and after the edit flurry; only the
  modal's pending slots change. Sister-tests `space_*` and `arrow_*`
  cover per-key buffering.)*
- [x] `Esc` discards pending edits without invoking setters or save.
  *(`settings_modal_esc_discards_pending_edits_without_invoking_save`
  applies pending edits, presses Esc, and asserts the modal closes,
  no effects are emitted, and `vault.settings()` reflects the
  pre-edit values.)*
- [x] Confirm runs every changed setter inside one
  `Vault::mutate_and_save` transaction.
  *(Reducer side:
  `settings_modal_enter_with_changes_emits_apply_settings_effect_with_diff_patches`
  and `settings_modal_enter_with_single_field_change_emits_one_patch`
  in `tests/reducer_tests.rs` assert that Enter diffs the modal's
  pending fields against the live `VaultSettings` and emits a single
  `Effect::ApplySettings { path, patches }` carrying exactly the
  changed `SettingPatch`es in `SettingsFocus` declaration order;
  the modal stays open until the `EffectResult::Settings` arrives.
  Executor side:
  `execute_apply_settings_with_single_patch_applies_and_sends_ok`
  and
  `execute_apply_settings_with_multiple_patches_applies_atomically_and_sends_ok`
  in `tests/effect_tests.rs` assert the four patches commit through
  `Vault::mutate_and_save` → `Vault::apply_setting_patch` inside
  one transaction, the live `(Vault, Store)` reflects every change
  in memory, and re-opening the on-disk primary surfaces the
  committed values; companion tests
  (`execute_apply_settings_on_non_unlocked_state_is_silently_dropped`,
  `execute_apply_settings_with_mismatched_path_is_silently_dropped`,
  `execute_apply_settings_with_dropped_receiver_does_not_panic`)
  cover the off-`Unlocked` / path-mismatch drop paths and
  channel-resilience.)*
- [x] A defensive setter validation failure restores the pre-attempt
  settings, surfaces inline, blocks the save, and keeps the modal
  open.
  *(Reducer side:
  `effect_result_settings_validation_error_keeps_modal_open_with_inline_error`
  asserts a `PaladinError::ValidationError` outcome stashes the
  rendered error on `SettingsModal.error` and the modal stays open.
  Executor side:
  `execute_apply_settings_with_out_of_range_patch_returns_validation_error`
  asserts an out-of-range `SettingPatch` rejects through
  `apply_setting_patch`'s §4.7 bound check, `Vault::mutate_and_save`
  rolls back to the pre-attempt `auto_lock_timeout_secs`, and the
  reducer receives `EffectResult::Settings { Err(ValidationError) }`.)*
- [x] A pre-commit save failure restores the prior settings values in
  memory and keeps the modal open with the inline error.
  *(`effect_result_settings_save_not_committed_keeps_modal_open_with_inline_error`
  asserts the modal stays open with the rendered
  `save_not_committed` error stashed in `SettingsModal.error`, and
  `vault.settings()` reflects the rolled-back pre-attempt values.
  The on-disk rollback semantics belong to
  `Vault::mutate_and_save` in `paladin-core`.)*
- [x] A durability-unconfirmed save leaves the new values in memory
  and surfaces the warning inline.
  *(`effect_result_settings_save_durability_unconfirmed_keeps_modal_open_with_inline_error`
  asserts the modal stays open with the rendered durability warning
  and `vault.settings()` reflects the committed new values. Other
  save-error paths share the surfacing via
  `effect_result_settings_io_error_keeps_modal_open_with_inline_error`;
  off-`Unlocked` and stale-modal deliveries are discarded by
  `effect_result_settings_on_locked_state_is_discarded` and
  `effect_result_settings_on_non_settings_modal_is_discarded`.)*
- [x] Confirm with no changes closes the modal without invoking save.
  *(`settings_modal_enter_with_no_changes_closes_modal_without_emitting_effect`
  opens the Settings modal on a fresh vault, presses Enter without
  edits, and asserts no effect is emitted, the modal closes, and
  `vault.settings()` is unchanged.)*

### Rename modal (`tests/reducer_tests.rs`)

- [x] Opens with the selected account's current label pre-populated.
  *(`pressing_shift_r_opens_rename_modal_prepopulated_with_selected_label`
  in `tests/reducer_tests.rs` asserts the reducer snapshots
  `account_id` and seeds `draft` from `Account::label()` at modal
  open. Text editing, submit, validation, and save-effect wiring
  land in subsequent slices.)*
- [x] Non-empty trimmed input routes through `Vault::rename` inside
  `Vault::mutate_and_save`, including when the trimmed input equals
  the current label so `updated_at` still matches CLI behavior.
  *(Reducer-level emission covered by
  `rename_modal_enter_with_valid_draft_emits_rename_effect`,
  `rename_modal_enter_with_same_label_still_emits_rename_effect`,
  and `effect_result_rename_ok_closes_modal_and_sets_status_confirmation`
  in `tests/reducer_tests.rs`: Enter on `Modal::Rename` validates via
  `paladin_core::validate_label` and emits `Effect::Rename { path,
  account_id, new_label: trimmed }`; the `Ok(())` outcome closes the
  modal and publishes `StatusLine::Confirmation("Renamed to {label}")`.
  Executor-side coverage lives in `tests/effect_tests.rs`:
  `execute_rename_with_valid_label_renames_account_and_sends_ok`
  asserts `Vault::mutate_and_save` → `Vault::rename` flows through
  the live `(Vault, Store)` carried in `AppState::Unlocked`, mutates
  the in-memory label, commits the new label to the on-disk primary,
  and posts back `EffectResult::Rename { Ok }`;
  `execute_rename_with_same_label_still_bumps_updated_at` asserts the
  same-label path still advances `Account::updated_at` to match CLI
  behavior. Companion tests
  (`execute_rename_with_unknown_account_id_sends_account_not_found_err`,
  `execute_rename_on_non_unlocked_state_is_silently_dropped`,
  `execute_rename_with_mismatched_path_is_silently_dropped`,
  `execute_rename_with_dropped_receiver_does_not_panic`) cover the
  unknown-account error surface, the off-`Unlocked` / path-mismatch
  drop paths, and channel-resilience. `HotpAdvance` / `CopyCode`
  remain on the placeholder side of the run-loop boundary.)*
- [x] Pre-commit `save_not_committed` restores the prior label and
  keeps the modal open with the inline error.
  *(`effect_result_rename_save_not_committed_keeps_modal_open_with_inline_error`
  asserts the modal stays open with the rendered
  `save_not_committed` error stashed in `RenameModal.error`, the
  draft is preserved for retry, and `Vault::iter()` reflects the
  rolled-back pre-attempt label. The on-disk rollback semantics
  belong to `Vault::mutate_and_save` in `paladin-core`.)*
- [x] `save_durability_unconfirmed` leaves the new label in memory and
  surfaces the warning.
  *(`effect_result_rename_save_durability_unconfirmed_keeps_modal_open_with_inline_error`
  asserts the modal stays open with the rendered durability warning,
  and `Vault::iter()` reflects the committed new label. Other
  save-error paths share the surfacing via
  `effect_result_rename_io_error_keeps_modal_open_with_inline_error`;
  off-`Unlocked`, stale-modal, and mismatched-`account_id`
  deliveries are discarded by
  `effect_result_rename_on_locked_state_is_discarded`,
  `effect_result_rename_on_non_rename_modal_is_discarded`, and
  `effect_result_rename_with_mismatched_account_id_is_discarded`.)*
- [x] Empty / out-of-range labels surface inline validation errors and
  never invoke the setter.
  *(`rename_modal_enter_with_empty_draft_sets_inline_error_no_effect`,
  `rename_modal_enter_with_whitespace_only_draft_sets_inline_error_no_effect`,
  and `rename_modal_enter_with_overlong_draft_sets_inline_error_no_effect`
  cover the §4.1 `label` / `empty` and `label` / `too_long` rejection
  paths. The reducer routes through `paladin_core::validate_label`
  and stores the rendered error on `RenameModal.error` without
  emitting `Effect::Rename`. Companion tests
  (`rename_modal_typing_char_appends_to_draft`,
  `rename_modal_backspace_pops_last_char_from_draft`,
  `rename_modal_backspace_on_empty_draft_is_a_silent_noop`,
  `rename_modal_typing_clears_inline_error`) lock the text-editing
  contract a draft must satisfy before submit.)*

### Pre-commit save rollback (`tests/reducer_tests.rs`)

- [x] Add modal `save_not_committed` leaves `Vault::iter()` matching
  its pre-attempt snapshot and the modal stays open with the typed
  inline error; `save_durability_unconfirmed` leaves the new state in
  memory while surfacing the warning.
  *(`effect_result_add_save_not_committed_keeps_modal_open_with_inline_error`
  asserts the rolled-back single-account vault and the inline
  `save_not_committed` wording; the durability sibling
  (`effect_result_add_save_durability_unconfirmed_keeps_modal_open_with_inline_error`)
  asserts the committed two-account vault and the inline
  `durability` wording. Both run through the shared
  `Validation | Save` arm in `reduce_add_result` and leave the
  status line untouched.)*
- [x] Remove modal: same coverage as Add, asserted on `Vault::iter()`.
  *(`effect_result_remove_save_not_committed_keeps_modal_open_with_inline_error`
  asserts the rolled-back single-account vault via `Vault::iter()`
  with the inline `save_not_committed` wording; the durability
  sibling
  `effect_result_remove_save_durability_unconfirmed_keeps_modal_open_with_inline_error`
  asserts the committed empty vault via `Vault::iter().count()`
  with the inline `durability` wording. Both run through the
  shared `Validation | Save` arm in `reduce_remove_result` and
  leave the status line untouched.)*
- [x] Rename modal: same coverage as Add, asserted on `Vault::iter()`.
  *(`effect_result_rename_save_not_committed_keeps_modal_open_with_inline_error`
  asserts the rolled-back original label via `Vault::iter()` with
  the inline `save_not_committed` wording; the durability sibling
  `effect_result_rename_save_durability_unconfirmed_keeps_modal_open_with_inline_error`
  asserts the committed new label via `Vault::iter()` with the
  inline `durability` wording. Both run through the shared
  `Validation | Save` arm in `reduce_rename_result` and leave the
  status line untouched.)*
- [x] Import modal: same coverage as Add, asserted on `Vault::iter()`.
  *(`effect_result_import_save_not_committed_keeps_modal_open_with_inline_error`
  asserts the rolled-back pre-attempt label list (just `"github"`)
  via `Vault::iter()` with the inline `save_not_committed` wording;
  the durability sibling
  `effect_result_import_save_durability_unconfirmed_keeps_modal_open_with_inline_error`
  seeds the merged accounts (`"github"`, `"imported_one"`,
  `"imported_two"`) before injecting the failure and asserts the
  committed iter via `Vault::iter()` with the inline `durability`
  wording. Both run through `reduce_import_result`'s Err arm and
  leave the status line untouched.)*
- [x] Settings modal: same coverage as Add, asserted on
  `Vault::settings()`.
  *(`effect_result_settings_save_not_committed_keeps_modal_open_with_inline_error`
  and
  `effect_result_settings_save_durability_unconfirmed_keeps_modal_open_with_inline_error`
  in `tests/reducer_tests.rs` assert the rollback semantics via
  `vault.settings()` for both save-error variants. Validation /
  I/O / mismatched-modal coverage lives in companion tests.)*
- [x] Passphrase modal: the inline error surfaces and the TUI's
  visible vault-mode flag (sourced from `Vault::is_encrypted()`)
  tracks the transition outcome without inspecting private key /
  cache material. (End-to-end passphrase rollback is exercised in the
  `paladin-core` plan.)
  *(Two sibling reducer tests in `tests/reducer_tests.rs` —
  `effect_result_passphrase_save_not_committed_keeps_modal_open_with_inline_error_and_preserves_is_encrypted`
  and
  `effect_result_passphrase_save_durability_unconfirmed_keeps_modal_open_with_inline_error_and_reflects_committed_is_encrypted`
  — each seed an encrypted vault, open `Modal::Passphrase` in the
  `Change` sub-flow, drive
  `AppEvent::EffectResult(EffectResult::Passphrase { result: Err(...) })`
  through `reduce` for both failure classes, and assert (1) the
  rendered error lands on `PassphraseModal::error` byte-for-byte
  through `render_error_message`, (2) the modal stays open with no
  follow-up effects, (3) the status line stays clear, and (4) the
  visible vault-mode flag is observed only through
  `Vault::is_encrypted()` — the single public accessor — without
  inspecting private key / cache material. Wired via
  `reduce_passphrase_result`'s Err arm in `src/app/reducer.rs`, which
  does not mutate vault state on either failure class (core owns the
  rollback on `save_not_committed` and the commit-then-warn on
  `save_durability_unconfirmed` per DESIGN §4.5). End-to-end mode/key
  transition rollback lives in the `paladin-core` plan.)*

### HOTP reveal window (`tests/hotp_reveal_tests.rs`)

- [x] Reveal closes after the deadline returned by
  `paladin_core::policy::hotp_reveal::deadline(now)`
  (`paladin_core::HOTP_REVEAL_SECS` measured on a monotonic clock).
- [x] `n` during an open reveal advances again (does not no-op).
- [x] Hidden rows show the stored next counter.
  *(`list_view_renders_hidden_hotp_row_with_stored_next_counter_and_press_n_prompt`
  in `tests/hotp_reveal_tests.rs` drives an `AppState::Unlocked` with
  an HOTP account at stored counter 42 and `hotp_reveal: None`
  through the production `view::render` pipeline via
  `ratatui::backend::TestBackend`. Asserts the rendered grid
  contains `(#42)` and `press n to advance`, and — as a security
  invariant — that the next-counter code from `hotp_peek` does NOT
  appear; the renderer composes the row via `render_hotp_row` and
  never calls into the OTP layer for a hidden row.)*
- [x] Revealed rows show the `Code.counter_used` that produced the
  visible code until expiry.
  *(`list_view_renders_revealed_hotp_row_with_counter_used_and_visible_code_until_expiry`
  in `tests/hotp_reveal_tests.rs` seeds an HOTP account at counter
  41, calls `Vault::hotp_advance` to land the stored counter at 42
  with `Code.counter_used = 41`, opens a `HotpReveal` pinned to that
  `Code`, renders, and asserts the grid contains `(#41)` and the
  formatted visible code while NOT containing `(#42)` or the
  `press n to advance` prompt. `render_hotp_row` reads the counter
  label from `reveal.counter_used` rather than `summary.counter`
  whenever a reveal is open for the row's account.)*

### Sensitive UI buffers (`tests/reducer_tests.rs`)

- [x] Unlock passphrase buffer zeroizes on submit, cancel, and
  auto-lock.
- [x] Encrypted Paladin import passphrase buffer zeroizes on submit,
  cancel, modal close, and auto-lock.
  *(`ImportModal::paladin_passphrase` is an `Option<PassphraseBuffer>`
  wrapping `Zeroizing<String>`, so `take()` wipes in place and
  `Drop` wipes on modal teardown. Submit is covered by
  `enter_in_import_modal_passphrase_phase_emits_import_effect_with_typed_passphrase`
  (Enter takes the buffer into a `SecretString`); cancel by
  `import_modal_esc_with_typed_paladin_passphrase_closes_modal_and_drops_buffer`
  (`Esc` clears `modal` to `None` so the typed bytes drop with the
  modal); modal close (post-success) by
  `effect_result_import_ok_keeps_modal_open_with_drained_paladin_passphrase_buffer`
  (Enter `take()` drains the buffer, `EffectResult::Import Ok` keeps
  the modal open with `paladin_passphrase = Some(empty)` so no
  resurrected bytes leak, and a follow-up `Esc` drops the
  now-drained modal cleanly); auto-lock by
  `tick_past_idle_deadline_with_open_import_modal_typed_paladin_passphrase_locks_and_drops_buffer`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `ImportModal`). All in
  `tests/reducer_tests.rs`.)*
- [x] Encrypted export passphrase buffer zeroizes on submit, cancel,
  modal close, and auto-lock.
  *(`ExportModal::new_passphrase` and `ExportModal::confirm_passphrase`
  are `PassphraseBuffer`s wrapping `Zeroizing<String>`, so
  `clear()` / `take()` wipe in place and `Drop` wipes on modal
  teardown. Submit is covered by
  `enter_in_encrypted_export_modal_with_matching_passphrases_emits_effect_and_zeroizes_passphrase_buffers`
  (Enter past every gate `take()`s `new_passphrase` into the
  `SecretString` carried by `Effect::Export` and `clear()`s
  `confirm_passphrase`); cancel by
  `export_modal_esc_with_typed_passphrases_closes_modal_and_drops_passphrase_buffers`
  (`Esc` clears `modal` to `None` so the typed bytes drop with the
  modal); modal close (success) by
  `effect_result_export_ok_closes_modal_and_publishes_status_line_confirmation`
  (Enter drains both buffers, then `EffectResult::Export Ok` drops
  the now-empty `ExportModal` while publishing the
  `StatusLine::Confirmation`); auto-lock by
  `tick_past_idle_deadline_with_open_export_modal_typed_passphrases_locks_and_drops_passphrase_buffers`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `ExportModal`). The
  companion plaintext-path emission contract is locked alongside by
  `enter_in_plaintext_export_modal_with_confirmation_emits_effect_without_passphrase`
  (Enter past the unencrypted-secrets gate emits `Effect::Export`
  with `passphrase = None`). All in `tests/reducer_tests.rs`.)*
- [x] Passphrase set / change buffers zeroize on submit, cancel, modal
  close, and auto-lock.
  *(`PassphraseModal::new_passphrase` and `PassphraseModal::confirm_passphrase`
  are `PassphraseBuffer`s wrapping `Zeroizing<String>`, so
  `clear()` / `take()` wipe in place and `Drop` wipes on modal
  teardown. Submit is covered by
  `enter_in_passphrase_modal_set_subflow_with_matching_passphrases_emits_effect_passphrase_set_and_zeroizes_buffers`
  and
  `enter_in_passphrase_modal_change_subflow_with_matching_passphrases_emits_effect_passphrase_change_and_zeroizes_buffers`
  (Enter past every gate `take()`s `new_passphrase` into the
  `SecretString` carried by `Effect::PassphraseSet` /
  `Effect::PassphraseChange` and `clear()`s `confirm_passphrase`);
  cancel by
  `passphrase_modal_esc_with_typed_buffers_closes_modal_and_drops_buffers`
  (`Esc` clears `modal` to `None` so the typed bytes drop with the
  `Modal::Passphrase(PassphraseModal)`); modal close (success) by
  `effect_result_passphrase_ok_closes_modal_and_publishes_status_line_confirmation`
  (`EffectResult::Passphrase Ok` drops the now-empty
  `PassphraseModal` while publishing a `StatusLine::Confirmation`);
  auto-lock by
  `tick_past_idle_deadline_with_open_passphrase_modal_typed_buffers_locks_and_drops_buffers`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `PassphraseModal`). All in
  `tests/reducer_tests.rs`. Confirmation-mismatch / zero-length
  validation gates are locked alongside by
  `enter_in_passphrase_modal_set_with_mismatched_new_and_confirm_surfaces_confirmation_mismatch_inline_no_effect`,
  `enter_in_passphrase_modal_change_with_mismatched_new_and_confirm_surfaces_confirmation_mismatch_inline_no_effect`,
  and
  `enter_in_passphrase_modal_set_with_empty_new_passphrase_surfaces_zero_length_inline_no_effect`;
  the `Remove` sub-flow's Effect emission is locked by
  `enter_in_passphrase_modal_remove_subflow_emits_effect_passphrase_remove`.)*
- [x] Add modal manual-secret field zeroizes on submit, cancel, modal
  close, mode switch, and auto-lock.
  *(`AddModal::manual_secret` is a `PassphraseBuffer` wrapping
  `Zeroizing<String>`, so `clear()` / `take()` wipe in place and
  `Drop` wipes on modal teardown. Submit is covered by
  `enter_in_add_modal_manual_mode_consumes_manual_secret_buffer`
  (Enter takes the buffer into a `SecretString`); mode-switch by
  `right_from_manual_mode_wipes_manual_secret` and
  `left_from_manual_mode_wipes_manual_secret`; cancel by
  `add_modal_esc_with_typed_manual_secret_closes_modal_and_drops_buffer`
  (`Esc` clears `modal` to `None` so the typed bytes drop with the
  modal); modal close (success) by
  `effect_result_add_ok_closes_modal_with_already_taken_manual_secret`
  (Enter `take()` then `EffectResult::Add Ok` drops the now-empty
  `AddModal`); auto-lock by
  `tick_past_idle_deadline_with_open_add_modal_typed_manual_secret_locks_and_drops_buffer`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `AddModal`). All in
  `tests/reducer_tests.rs`.)*
- [x] Add URI-mode entry zeroizes on submit, cancel, modal close, mode
  switch, and auto-lock.
  *(`AddModal::uri_text` is a `PassphraseBuffer` wrapping
  `Zeroizing<String>`, so `clear()` / `take()` wipe in place and
  `Drop` wipes on modal teardown. Submit is covered by
  `enter_in_add_modal_uri_mode_consumes_uri_text_buffer` (Enter
  `take()`s the buffer into the `SecretString` carried by
  `Effect::AddFromUri`); mode-switch by
  `right_from_uri_mode_wipes_uri_text` and
  `left_from_uri_mode_wipes_uri_text` (both `→` and `←` route
  through `AddModal::switch_mode` which `clear()`s `uri_text` when
  leaving Uri); the negative mode-switch case is locked by
  `cycling_away_from_manual_or_qr_preserves_uri_text` (Manual ↔ Qr
  cycles never touch `uri_text`); cancel by
  `add_modal_esc_with_typed_uri_text_closes_modal_and_drops_buffer`
  (`Esc` clears `modal` to `None` so the typed bytes drop with the
  modal); modal close (success) by
  `effect_result_add_ok_closes_modal_with_already_taken_uri_text`
  (Enter `take()` then `EffectResult::Add Ok` drops the now-empty
  `AddModal`); auto-lock by
  `tick_past_idle_deadline_with_open_add_modal_typed_uri_text_locks_and_drops_buffer`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `AddModal`). All in
  `tests/reducer_tests.rs`.)*
- [x] Pending duplicate-add validated accounts zeroize on add-anyway,
  cancel, modal close, and auto-lock.
  *(`AddModal::pending_duplicate_add` is
  `Option<Box<PendingDuplicateAdd>>`; the boxed
  `Box<ValidatedAccount>` carries a `Secret` whose `ZeroizeOnDrop`
  wipes the bytes when the option drops. Add-anyway is covered by
  `enter_with_pending_duplicate_add_in_manual_mode_emits_add_anyway_effect`
  and
  `enter_with_pending_duplicate_add_in_uri_mode_emits_add_anyway_effect`
  (Enter `take()`s the `Option`, moving the `Box<ValidatedAccount>`
  into the emitted `Effect::AddAnyway` and leaving the modal-local
  slot `None`); cancel by
  `add_modal_esc_with_pending_duplicate_add_closes_modal_and_drops_pending`
  (`Esc` clears `modal` to `None` so the pending state drops with
  the modal); modal close (success) by
  `effect_result_add_ok_with_pending_duplicate_add_closes_modal_and_drops_pending`
  (the Ok arm sets `*modal = None` unconditionally so even a stale
  pending slot drops with the modal); auto-lock by
  `tick_past_idle_deadline_with_open_add_modal_pending_duplicate_add_locks_and_drops_pending`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `AddModal`). All in
  `tests/reducer_tests.rs`.)*
- [x] HOTP reveal state zeroizes on expiry, replacement, drop, and
  auto-lock.
  *(`HotpReveal::code` is a [`secrecy::SecretString`] whose `Drop`
  impl runs `Zeroize` on the inner bytes; the reveal struct has no
  `Drop` of its own and no `clear()` — zeroization rides entirely
  on `SecretString`'s drop chain. Expiry is covered by
  `tick_past_reveal_deadline_with_open_hotp_reveal_typed_code_drops_reveal_via_secret_string_drop`
  (Tick past `hotp_reveal_deadline` runs
  `maybe_close_expired_hotp_reveal`, which sets `*hotp_reveal = None`
  and drops the prior `HotpReveal`); replacement by
  `effect_result_hotp_advance_ok_with_open_prior_reveal_replaces_and_drops_prior_via_secret_string_drop`
  (a fresh `EffectResult::HotpAdvance Ok` assigns
  `*slot = Some(HotpReveal { .. })`, dropping the prior reveal as
  the assignment overwrites it); drop by
  `hotp_reveal_drop_chain_zeroizes_code_via_secret_string_drop`
  (a direct construct-and-`drop` exercises the `SecretString` drop
  chain end-to-end as a regression sentinel against future
  refactors that swap the field type away from a zeroizing wrapper);
  auto-lock by
  `tick_past_idle_deadline_with_open_hotp_reveal_typed_code_locks_and_drops_reveal_via_secret_string_drop`
  (Tick past `idle_deadline` transitions to `Locked`, dropping the
  whole `Unlocked` arm including the open `hotp_reveal`). All in
  `tests/hotp_reveal_tests.rs`.)*
- [x] Pending clipboard-clear buffers survive lock until the scheduled
  clear attempt, stale-token drop, replacement, or app shutdown, then
  zeroize.
  *(`PendingClipboardClear::value` is a [`zeroize::Zeroizing<Vec<u8>>`]
  whose `Drop` runs `Zeroize::zeroize` on the inner `Vec<u8>` — the
  contract is exercised directly by `zeroizing_vec_zeroize_empties_buffer`
  and pinned at every wrapper site by the type-binding tests in the
  same file. Lock-survival is covered by
  `auto_lock_carries_pending_clipboard_clear_into_locked_preserving_zeroizing_bytes`
  (Tick past `idle_deadline` transitions `Unlocked → Locked` via
  `maybe_auto_lock`, which moves `pending_clipboard_clear` onto the
  resulting `Locked` arm byte-for-byte with the wrapper intact);
  scheduled clear attempt by
  `matching_token_wake_on_locked_clears_pending_slot_post_state` and
  `matching_token_wake_hands_clear_clipboard_effect_zeroizing_bytes`
  (the wake consumes the pending slot to `None` and hands the bytes
  off as `Effect::ClearClipboard`, whose `Zeroizing<Vec<u8>>` drops
  after the executor's wipe); stale-token drop by
  `stale_token_wake_drops_event_zeroizing_bytes_and_preserves_pending`
  (the stale wake event's `Zeroizing<Vec<u8>>` is consumed by
  `reduce` and dropped on the rejection path while the fresher
  pending slot stays intact); replacement by
  `replacement_copy_drops_prior_pending_value_via_zeroizing_drop`
  (a second `EffectResult::CopyCode` overwrites the prior pending
  slot, dropping the prior `PendingClipboardClear` and its zeroizing
  buffer in place); app shutdown by
  `pending_clipboard_clear_drop_chain_zeroizes_value_via_zeroizing_drop`
  (a direct construct-and-`drop` exercises the
  `PendingClipboardClear → Zeroizing<Vec<u8>> → Zeroize::zeroize`
  chain end-to-end as a regression sentinel against future refactors
  that swap the field type away from a zeroizing wrapper). All in
  `tests/clipboard_tests.rs`.)*

### Vault modes and startup (`tests/reducer_tests.rs`)

- [x] Plaintext vault opens directly to the list (no unlock screen).
- [x] Encrypted vault opens to the unlock screen.
- [x] Encrypted vault wrong passphrase shows inline `decrypt_failed`
  and stays on the unlock screen.
- [x] Encrypted vault correct passphrase advances to the list.
- [x] Missing vault opens the missing-vault screen and does not create
  or mutate files.
- [ ] Vault-path resolution failures from `default_vault_path` open
  the non-mutating startup-error screen and do not create or mutate
  files. (Deferred: `build_initial_state` calls `default_vault_path`
  directly with no injectable resolver, and the resolver only fails
  when `ProjectDirs::from` returns `None` — not portably forceable
  from a test. Lands alongside a refactor that takes a resolver.)
- [x] Non-`decrypt_failed` errors from `inspect` / `open` (including
  `unsafe_permissions`) open the non-mutating startup-error screen
  and do not create or mutate files.
- [x] `unsafe_permissions` rendering uses the `Some(text)` from
  `format_unsafe_permissions` verbatim.

### Insta snapshots (`tests/snapshots/`)

Layout / list views:

- [x] Empty vault list view.
  *(`crates/paladin-tui/src/view/list.rs` renders the §6 single-screen
  list layout — a bordered `Paladin` block holding the `Search:`
  line, a horizontal divider, the rows pane, a second divider, and
  the `[↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find`
  hint flush with the bottom border. When `vault.iter()` is empty the
  rows pane shows a centered `No accounts. Press `a` to add one.`
  prompt so a user landing on a fresh vault sees the add keybinding.
  `snapshot_list_view_empty` in `tests/view_snapshots.rs` constructs
  the state from a temp-backed plaintext vault (`secure_test_tempdir`
  + `Store::create(_, VaultInit::Plaintext)`) and locks the rendered
  grid in
  `tests/snapshots/view_snapshots__snapshot_list_view_empty.snap`;
  the vault path itself is not rendered on the list view, so the
  tempdir-backed path stays out of the snapshot grid and the
  snapshot stays deterministic across hosts.)*
- [x] Single-TOTP list view.
  *(`crates/paladin-tui/src/view/list.rs` now renders one row per
  `AccountSummary`: selection marker (`▶` for `state.selected`,
  space otherwise), a 32-char issuer/label column truncated with
  `…`, the `Code.code` digits split on the width midpoint, a
  10-cell `█`/`░` period-progress gauge, and the
  `Code.seconds_remaining` suffix. `view::render` now takes
  `now: SystemTime` (forwarded to `Vault::totp_code`) so the
  rendered code/gauge/seconds tuple is a pure function of the
  tick's wall-clock; the event-loop slice feeds it the latest
  `AppEvent::Tick.wall_clock` and tests pin it via the new
  `snapshot_now()` helper. `snapshot_list_view_single_totp` in
  `tests/view_snapshots.rs` builds an `Unlocked` state with a
  single TOTP account at `SNAPSHOT_NOW_SECS = 1_500_000_012`
  (12 s into a 30-s window so 18 s remain and the gauge is 60%
  full), and locks the rendered grid in
  `tests/snapshots/view_snapshots__snapshot_list_view_single_totp.snap`.
  HOTP rows still fall back to the shared `{marker} {title}`
  prefix until the mixed-kind slice lands.)*
- [x] Mixed TOTP / HOTP list view with hidden + revealed rows.
  *(`crates/paladin-tui/tests/view_snapshots.rs` adds
  `push_hotp_account` (mirrors `push_totp_account` with
  `AccountKindInput::Hotp` + a stored `counter`) and the new
  `snapshot_list_view_mixed_totp_hotp_hidden_and_revealed` test —
  insertion order TOTP / hidden HOTP / revealed HOTP places one row
  of each distinct shape into the snapshot grid. The hidden HOTP row
  carries `(#0)` (the *stored next* counter from
  `summary.counter`) plus the `▸ press n to advance` prompt; the
  revealed HOTP row carries `(#41)` (the *pre-advance*
  `HotpReveal.counter_used` while the stored next counter is `42`)
  plus the `format_code_digits`-formatted reveal code in the
  right-side column. The revealed HOTP is the selected row so the
  `▶` marker lands on a HOTP row — a regression that ever stops
  painting selection on HOTP rows surfaces as a diff. The reveal
  `deadline` uses `hotp_reveal_deadline(Instant::now())` —
  host-clock-derived but never read by the renderer, so the
  snapshot stays deterministic. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_mixed_totp_hotp_hidden_and_revealed.snap`.)*
- [x] Search-active list view.
  *(`crates/paladin-tui/src/view/list.rs` now respects
  `state.search_query`: `render` builds the matching-account
  `HashSet<AccountId>` via the existing
  `paladin_tui::search::filtered_account_ids` helper — same
  predicate (`paladin_core::account_matches_search`) the reducer's
  incremental-search slice uses — and `render_rows` filters
  `Vault::iter()` against it so only matching rows paint, in
  insertion order. The empty-vault prompt branch stays bound to
  the unfiltered `vault.iter().next().is_none()` check, so a
  populated vault whose filter happens to yield zero rows leaves
  the rows pane blank instead of swapping in the "Press `a` to add
  one." add-flow prompt. `snapshot_list_view_search_active` in
  `tests/view_snapshots.rs` drives an `Unlocked` state with three
  inserted accounts (TOTP `GitHub (ben@example.com)`, TOTP
  `GitLab (ben@example.com)`, hidden HOTP `Bank (savings)`),
  `search_query = "git"`, `focus = Focus::Search`, and
  `selected = Some(github_id)`; the locked grid in
  `tests/snapshots/view_snapshots__snapshot_list_view_search_active.snap`
  pins the `Search: git` line, the two surviving rows with their
  TOTP codes / 60%-full gauge / `18s` suffix, and the `▶` marker
  landing on the first match — regressions that ever stop
  painting the query into the search bar, stop honoring the
  filter, or paint the marker on a filtered-out row each surface
  as a diff.)*
- [x] List view after a `zz` recenter (selected row in viewport
  middle). *(`snapshot_list_view_after_zz_recenter` in
  `crates/paladin-tui/tests/view_snapshots.rs` builds a vault with
  twelve TOTP accounts (`Acct01 (u01)` .. `Acct12 (u12)`) so the
  list overflows the 6-row rows pane in an 80×12 terminal. The state
  is constructed with `selected = Acct09` (insertion-order index 8)
  and `viewport_offset = 5` — the value `recenter_viewport` would
  commit from `sel_pos.saturating_sub(viewport_height / 2)` for a
  centered viewport on that row. The locked grid in
  `tests/snapshots/view_snapshots__snapshot_list_view_after_zz_recenter.snap`
  pins `Acct06`..`Acct11` in the rows pane with the `▶` marker
  landing on `Acct09` (the 4th of 6 visible rows); the renderer's
  `render_rows` was extended in the same slice to
  `.skip(viewport_offset)` post-filter so a regression that ever
  stops applying the offset shifts the window back to
  `Acct01`..`Acct06` and drops the marker, surfacing as a diff.)*
- [ ] `--no-color` variants of the list-view snapshots above.
  (Deferred: `tests/view_snapshots.rs::buffer_to_text` already
  serializes cell symbols only, dropping foreground / background /
  modifier attributes — so a no-color snapshot is byte-identical to
  its styled twin until either (a) a styled-grid harness lands that
  preserves attributes in the body, or (b) the renderer starts
  emitting different symbols in no-color mode. The harness's
  module-level doc already notes this matrix lands "when the list
  view's search highlighting needs it"; this task tracks that future
  slice rather than locking in identical-snapshot duplicates today.)

Modals and overlays:

- [x] Add modal. *(`snapshot_add_modal_default` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state with an empty plaintext vault and
  `modal = Some(Modal::Add(AddModal::default()))`, then renders
  through `view::render` at 80×20 — the new
  `crates/paladin-tui/src/view/add.rs` paints a 64×16 centered
  `Clear`-then-bordered ` Add account ` block over the list-view
  backdrop, with the segmented `Mode: ▶ Manual ◀   URI   QR`
  selector on top, the eight Manual-mode fields (`Label`, `Issuer`,
  `Secret`, `Algorithm`, `Digits`, `Kind`, `Period (s)` / `Counter`,
  `Icon hint`) at their `DESIGN.md` §5 defaults, and a centered
  `Tab cycles fields · Enter submit · Esc cancel` keybinding hint at
  the bottom. The `Secret:` row renders the typed character count as
  `•` bullets so the snapshot pins that the renderer never paints
  the secret bytes; an empty buffer renders as `[ ]`. The
  `Period (s)` / `Counter` row is fed by `modal.kind` so a
  regression that ever swaps the TOTP / HOTP branches surfaces as a
  diff. `view::render` was extended in the same slice to dispatch
  open modals through a private `render_modal` table; the
  non-Add variants are explicit no-ops that pin "list view alone
  shows underneath" until their own snapshot slice lands.)*
- [x] Remove modal. *(`snapshot_remove_modal_default` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state holding a single TOTP account (the
  `GitHub` / `ben@example.com` issuer/label pair shared with the
  single-TOTP list-view snapshot) and
  `modal = Some(Modal::Remove(RemoveModal { account_id, error: None }))`,
  then renders through `view::render` at 80×20 — the new
  `crates/paladin-tui/src/view/remove.rs` paints a 64×10 centered
  `Clear`-then-bordered ` Remove account ` block over the list-view
  backdrop, with the `Remove the following account?` prompt on the
  first inner line, the targeted account's display label on line
  three (resolved via the shared
  `format_account_display_label(&summary)` — same wording as the
  duplicate-account inline error and the CLI's `display_label`), a
  flexible spacer, and a centered `Enter confirms  ·  Esc cancels`
  hint near the bottom border. `view::render` was extended in the
  same slice to thread `&Vault` through `render_modal` so each
  modal renderer can resolve its `AccountId` against the same
  in-memory vault the list view paints; the Add-modal renderer
  needs none of that vault metadata yet, so its signature is
  unchanged. `centered_rect` moved from `view/add.rs` to
  `view/mod.rs` as a shared `pub(super)` helper — both modal
  renderers now share a single source of centering math, so a
  regression that ever drifts one overlay off-center surfaces
  symmetrically. Locked in
  `tests/snapshots/view_snapshots__snapshot_remove_modal_default.snap`.
  Inline `save_not_committed` / `save_durability_unconfirmed`
  variants of this modal land alongside their own checklist rows
  below.)*
- [x] Rename modal. *(`snapshot_rename_modal_default` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state holding a single TOTP account (the same
  `GitHub` / `ben@example.com` issuer/label pair shared with the
  Remove modal snapshot) and
  `modal = Some(Modal::Rename(RenameModal { account_id, draft, error: None }))`
  with `draft` pre-populated from the account's current label, then
  renders through `view::render` at 80×20 — the new
  `crates/paladin-tui/src/view/rename.rs` paints a 64×10 centered
  `Clear`-then-bordered ` Rename account ` block over the list-view
  backdrop, with the `Renaming the following account:` prompt on the
  first inner line, the targeted account's display label on line two
  (resolved via the shared `format_account_display_label(&summary)` —
  same wording as the duplicate-account inline error, the Remove
  modal, and the CLI's `display_label`), a blank, the editable
  `New label:` text-input row carrying the `RenameModal::draft`
  buffer in `[ ... ]` brackets (mirrors the Add modal's
  `text_field_line` so an empty draft renders as `[ ]` rather than
  blank), a flexible spacer, and a centered `Enter submit  ·  Esc
  cancel` hint near the bottom border. `view::render`'s `render_modal`
  dispatch was extended in the same slice to route `Modal::Rename`
  to the new module — Import / Export / Passphrase / Settings remain
  the explicit no-op branch until their own snapshot slices land.
  Locked in
  `tests/snapshots/view_snapshots__snapshot_rename_modal_default.snap`.
  Inline `save_not_committed` / `save_durability_unconfirmed`
  variants of this modal land alongside their own checklist rows
  below.)*
- [x] Import modal. *(`snapshot_import_modal_default` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state with an empty plaintext vault and
  `modal = Some(Modal::Import(ImportModal::default()))`, then renders
  through `view::render` at 80×20 — the new
  `crates/paladin-tui/src/view/import.rs` paints a 72×12 centered
  `Clear`-then-bordered ` Import accounts ` block over the list-view
  backdrop. The 8-cell width bump over the 64-wide Remove / Rename
  overlays gives the segmented `Format:` selector room for all five
  [`ImportFormatSelector`] variants (`Auto` / `Otpauth` / `Aegis` /
  `Paladin` / `QR`) without truncating the last segment under the
  `▶ … ◀` active-variant markers. The body holds an editable
  `Source:` text-input row carrying the `ImportModal::path_text`
  buffer in `[ ... ]` brackets (mirrors the Add / Rename modals'
  `text_field_line` so empty input renders as `[ ]`), the segmented
  `Format:` selector wired to `modal.format`, the segmented
  `On conflict:` selector wired to `modal.conflict` over the three
  [`paladin_core::ImportConflict`] variants in the CLI's documented
  `skip` / `replace` / `append` order, a flexible spacer, and a
  centered `Tab cycles fields  ·  Enter submit  ·  Esc cancel` hint
  near the bottom border. `view::render`'s `render_modal` dispatch
  was extended in the same slice to route `Modal::Import` to the new
  module — Export / Passphrase / Settings remain the explicit no-op
  branch until their own snapshot slices land. Locked in
  `tests/snapshots/view_snapshots__snapshot_import_modal_default.snap`.
  Inline-error / encrypted-Paladin passphrase sub-phase / post-import
  counts panel variants of this modal land alongside their own
  checklist rows below.)*
- [x] Export modal. *(`snapshot_export_modal_default` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state with an empty plaintext vault and
  `modal = Some(Modal::Export(ExportModal::default()))`, then renders
  through `view::render` at 80×20 — the new
  `crates/paladin-tui/src/view/export.rs` paints a 72×10 centered
  `Clear`-then-bordered ` Export accounts ` block over the list-view
  backdrop. The body holds an editable `Destination:` text-input row
  carrying the `ExportModal::path_text` buffer in `[ ... ]` brackets
  (mirrors the Add / Rename / Import modals' `text_field_line` so
  empty input renders as `[ ]`), the segmented `Format:` selector
  wired to `modal.format` over the two
  [`paladin_core::ExportFormat`] variants (`▶ Plaintext ◀
  Encrypted`), a flexible spacer, and a centered `Tab cycles fields
  ·  Enter submit  ·  Esc cancel` hint near the bottom border. The
  72-cell width matches the Import modal so the segmented selectors
  line up across the two flows. `view::render`'s `render_modal`
  dispatch was extended in the same slice to route `Modal::Export`
  to the new module — Passphrase / Settings remain the explicit
  no-op branch until their own snapshot slices land. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_default.snap`.
  The plaintext-export warning rendering and the `[ ]` / `[x]`
  acknowledgement gate, the encrypted twice-confirm passphrase
  prompts, refused-overwrite gate, `confirmation_mismatch` /
  `zero_length` validation gates, and writer-failure /
  `save_not_committed` / `save_durability_unconfirmed` inline-error
  variants land alongside their own checklist rows below.)*
- [x] Passphrase modal — `set` sub-flow.
  *(`snapshot_passphrase_modal_set_default` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state with an empty plaintext vault and
  `modal = Some(Modal::Passphrase(PassphraseModal { sub_flow: PassphraseSubFlow::Set, ..PassphraseModal::default() }))`,
  then renders through `view::render` at 80×20 — the new
  `crates/paladin-tui/src/view/passphrase.rs` paints a 64×10
  centered `Clear`-then-bordered ` Set passphrase ` block over the
  list-view backdrop. The body holds a one-line intent description
  (`Encrypts this vault under a new passphrase.` — wording mirrors
  the CLI `paladin passphrase set` command help), a blank spacer,
  the masked `Passphrase:` row, the masked `Confirm:` row, a
  flexible spacer, and a centered `Enter submit  ·  Esc cancel`
  hint near the bottom border. Both passphrase rows render the
  typed character count as `•` bullets so the snapshot pins that
  the renderer never paints the secret bytes — mirrors the Add
  modal's `Secret:` field's `masked_field_line`; an empty buffer
  renders as `[  ]`. The bordered block's title is sub-flow-aware
  (` Set passphrase ` / ` Change passphrase ` / ` Remove
  passphrase `) so a regression that ever opens the wrong
  sub-flow surfaces as a diff. `view::render`'s `render_modal`
  dispatch was extended in the same slice to route
  `Modal::Passphrase` to the new module — Settings remains the
  explicit no-op branch until its own snapshot slice lands. Locked
  in `tests/snapshots/view_snapshots__snapshot_passphrase_modal_set_default.snap`.
  The `change` and `remove` sub-flow snapshots land alongside their
  own checklist rows below; the `remove` sub-flow's
  plaintext-storage warning body fans out from the same renderer
  in its own slice. Inline `confirmation_mismatch` / `zero_length`
  validation gates and `save_not_committed` /
  `save_durability_unconfirmed` variants of this modal land
  alongside their own
  [`PassphraseModal::error`](crate::app::state::PassphraseModal::error)
  rendering slices below.)*
- [x] Passphrase modal — `change` sub-flow.
  *(`snapshot_passphrase_modal_change_default` in
  `tests/view_snapshots.rs` drives `view::render` against the
  `Unlocked` state with `Modal::Passphrase(PassphraseModal {
  sub_flow: PassphraseSubFlow::Change, ..default() })`, locking
  the renderer's encrypted-vault re-key baseline — bordered block
  title flips to ` Change passphrase `, the one-line intent
  reads `Re-encrypts this vault under a new passphrase.`, and
  the masked `Passphrase:` / `Confirm:` rows plus the centered
  `Enter submit  ·  Esc cancel` hint match the `set` body shape
  so a regression that ever swaps the sub-flow wording (or paints
  the `set` intent on a `change` modal) surfaces as a diff.
  Locked in
  `tests/snapshots/view_snapshots__snapshot_passphrase_modal_change_default.snap`.
  The renderer doesn't gate on vault state (the gate is enforced
  upstream by the modal-open reducer per the design's "available
  sub-flow is gated by `Vault::is_encrypted()`" rule); a
  plaintext-vault background therefore matches the `set` test
  and keeps this snapshot focused on the renderer's contract.)*
- [x] Passphrase modal — `remove` sub-flow.
  *(`snapshot_passphrase_modal_remove_default` in
  `tests/view_snapshots.rs` drives `view::render` against the
  `Unlocked` state with `Modal::Passphrase(PassphraseModal {
  sub_flow: PassphraseSubFlow::Remove, ..default() })`, locking
  the renderer's encrypted → plaintext baseline. The same slice
  fans out the `remove` sub-flow's body in
  `crates/paladin-tui/src/view/passphrase.rs`: the bordered block
  grows taller (14 rows vs the twice-confirm sub-flows' 10), the
  masked `Passphrase:` / `Confirm:` input rows drop away entirely
  (the sub-flow takes no new secret), and the body is replaced by
  the wrapped plaintext-storage warning sourced verbatim from
  [`paladin_core::format_plaintext_storage_warning`] — so the TUI
  wording stays byte-identical to the CLI `passphrase remove` /
  GTK `PassphraseDialog::remove_warning_body` paths. The hint
  shifts to `Enter confirm  ·  Esc cancel` to flag the destructive
  mutation. A regression that ever paints the twice-confirm body
  on a `remove` modal (or drifts the warning wording from core)
  surfaces as a diff. Locked in
  `tests/snapshots/view_snapshots__snapshot_passphrase_modal_remove_default.snap`.
  The renderer doesn't gate on vault state (the gate is enforced
  upstream by the modal-open reducer per the design's "available
  sub-flow is gated by `Vault::is_encrypted()`" rule); a
  plaintext-vault background therefore matches the `set` / `change`
  tests and keeps the snapshot focused on the renderer's contract.)*
- [x] Settings modal.
  *(`crates/paladin-tui/src/view/settings.rs` paints the
  freshly-opened Settings modal as a 64×12 bordered `Settings`
  block with four labeled value rows in reading order — the
  `Auto-lock:` toggle, the indented `Timeout (s):` spinner, a
  blank spacer, the `Clipboard-clear:` toggle, and the indented
  `Timeout (s):` spinner — plus the centered `Tab cycles fields
  ·  Enter submit  ·  Esc cancel` hint. Toggles render as
  `[ ✓ ]` / `[   ]` and spinners as `[ {value} ]` so a regression
  that ever drifts the glyphs, the row order, or the indent of
  the timeout rows under their parent toggles surfaces as a diff.
  `view::render`'s `render_modal` dispatch was extended in the
  same slice to route `Modal::Settings` to the new module.
  `snapshot_settings_modal_default` in
  `tests/view_snapshots.rs` drives the snapshot seeded with the
  `paladin_core::VaultSettings::default()` values (both toggles
  off, `auto_lock.timeout_secs = 300`, `clipboard.clear_secs =
  20`) so the snapshot mirrors what the production modal-open
  path produces against a freshly initialized vault rather than
  the doc-only `SettingsModal::default()` placeholder. Locked in
  `tests/snapshots/view_snapshots__snapshot_settings_modal_default.snap`.
  Per-field focus painting and the inline
  `save_not_committed` / `save_durability_unconfirmed` variants
  of this modal land alongside their own slices per the plan's
  later checklist rows.)*
- [x] Help overlay.
  *(`crates/paladin-tui/src/view/help.rs` paints the read-only Help
  overlay as a 78-wide bordered `Help — keybindings` block centered
  inside the frame on top of the underlying list view, with a single
  `Read-only — keys are listed for reference.` intro row, one body
  line per row in `paladin_tui::keybindings::KEYBINDINGS`, and the
  centered `Esc closes` hint flush near the bottom. The block height
  scales with the rendered body so adding or removing a keybinding
  adjusts the overlay automatically. Long actions wrap to a
  continuation line indented under the action column so the
  longest row (`Esc → Close modal / overlay / search; quit
  dead-end screens`) stays fully readable without horizontal
  truncation. `view::render` was extended in the same slice to
  paint `help::render` last (after any open modal) when
  `AppState::Unlocked { help_open: true, .. }`, so the dismiss-hint
  stays visible even if a future reducer bug ever lets help and a
  modal coexist. The single-source-of-truth keybindings table lives
  in `crates/paladin-tui/src/keybindings.rs` so the future
  `cargo xtask man` target can read the same constant when it
  appends the "Keybindings" section to `paladin-tui.1` and the two
  cannot drift; the module ships two unit tests asserting that no
  row has an empty `keys` / `action` and that the `?` / `Esc` /
  `q` / `Ctrl-C` rows are present so a regression that drops one
  surfaces in cargo test rather than only in the rendered snapshot.
  `snapshot_help_overlay` in `tests/view_snapshots.rs` drives the
  overlay through `TestBackend(80, 30)` against a plaintext-vault
  background (matching the modal-default snapshots above) so the
  rendered frame stays deterministic. Locked in
  `tests/snapshots/view_snapshots__snapshot_help_overlay.snap`.)*
- [x] Unlock screen.
  *(`crates/paladin-tui/src/view/unlock.rs` renders a bordered
  `Paladin — unlock` block with the bolded vault path, a masked
  passphrase line (`•` per typed character, never the typed bytes),
  the optional inline `error`, and the Enter / Esc / Ctrl-C
  hint. `snapshot_unlock_screen` in `tests/view_snapshots.rs`
  drives the no-error empty-buffer baseline.)*
- [x] Missing-vault screen.
  *(`crates/paladin-tui/src/view/missing_vault.rs` renders the
  non-mutating guidance screen — a bordered `Paladin` block with
  the inspected vault path and the "Run `paladin init` to create
  one" prompt — and `snapshot_missing_vault_screen` in
  `tests/view_snapshots.rs` drives it through
  `ratatui::backend::TestBackend` (80×12) into
  `tests/snapshots/view_snapshots__snapshot_missing_vault_screen.snap`.
  The `view_snapshots.rs` harness (`render_to_text` /
  `buffer_to_text`) is shared by every subsequent view-rendering
  snapshot test.)*

Inline `save_not_committed` / `save_durability_unconfirmed`:

- [x] Add modal `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_add_modal_save_not_committed`
  drives `view::render` against an `AppState::Unlocked` carrying
  `Modal::Add(AddModal { error: Some(render_error_message(
  &PaladinError::SaveNotCommitted { committed: false, backup_path:
  None })), .. })`. The renderer's new `render_inline_error` helper
  in `crates/paladin-tui/src/view/add.rs` paints the error one blank
  row below the icon-hint field, foreground red, mirroring the
  unlock screen's `decrypt_failed` styling so all inline-error
  surfaces in the TUI read the same way. The
  `snapshot_add_modal_default` baseline is unchanged — the
  conditional render fires only when `modal.error.is_some()`.)*
- [x] Add modal `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_add_modal_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed`; per the plan's
  "Durability-unconfirmed failures follow the committed-state path"
  contract this surfaces in the inline error slot identically to the
  pre-commit failure.)*
- [x] Remove modal `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_remove_modal_save_not_committed`
  drives `view::render` against an `AppState::Unlocked` carrying
  `Modal::Remove(RemoveModal { error: Some(render_error_message(
  &PaladinError::SaveNotCommitted { committed: false, backup_path:
  None })), .. })`. The renderer's new `render_inline_error` helper
  in `crates/paladin-tui/src/view/remove.rs` paints the error one
  blank row below the account-label row, foreground red, mirroring
  the Add modal's inline-error slot so all inline-error surfaces in
  the TUI read the same way. The `snapshot_remove_modal_default`
  baseline is unchanged — the conditional render fires only when
  `modal.error.is_some()`.)*
- [x] Remove modal `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_remove_modal_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed`; per the plan's
  "Durability-unconfirmed failures follow the committed-state path"
  contract this surfaces in the inline error slot identically to the
  pre-commit failure.)*
- [x] Rename modal `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_rename_modal_save_not_committed`
  drives `view::render` against an `AppState::Unlocked` carrying
  `Modal::Rename(RenameModal { error: Some(render_error_message(
  &PaladinError::SaveNotCommitted { committed: false, backup_path:
  None })), .. })`. The renderer's new `render_inline_error` helper
  in `crates/paladin-tui/src/view/rename.rs` paints the error one
  blank row below the draft-field row, foreground red, mirroring
  the Add / Remove modals' inline-error slots so all inline-error
  surfaces in the TUI read the same way. The
  `snapshot_rename_modal_default` baseline is unchanged — the
  conditional render fires only when `modal.error.is_some()`.)*
- [x] Rename modal `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_rename_modal_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed`; per the plan's
  "Durability-unconfirmed failures follow the committed-state path"
  contract this surfaces in the inline error slot identically to the
  pre-commit failure.)*
- [x] Import modal `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_import_modal_save_not_committed`
  drives `view::render` against an `AppState::Unlocked` carrying
  `Modal::Import(ImportModal { error: Some(render_error_message(
  &PaladinError::SaveNotCommitted { committed: false, backup_path:
  None })), ..ImportModal::default() })`. The renderer's new
  `render_inline_error` helper in
  `crates/paladin-tui/src/view/import.rs` paints the error one blank
  row below the conflict-selector row, foreground red, mirroring the
  Add / Remove / Rename modals' inline-error slots so all
  inline-error surfaces in the TUI read the same way. The
  `snapshot_import_modal_default` baseline is unchanged — the
  conditional render fires only when `modal.error.is_some()`.)*
- [x] Import modal `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_import_modal_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed`; per the plan's
  "Durability-unconfirmed failures follow the committed-state path"
  contract this surfaces in the inline error slot identically to the
  pre-commit failure.)*
- [x] Passphrase set `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_passphrase_modal_set_save_not_committed`
  drives `view::render` against an `AppState::Unlocked` carrying
  `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
  Some(render_error_message(&PaladinError::SaveNotCommitted {
  committed: false, backup_path: None })), .. })`. The renderer's
  new `render_inline_error` helper in
  `crates/paladin-tui/src/view/passphrase.rs` paints the error one
  blank row below the `Confirm:` row, foreground red, inside the
  twice-confirm sub-flow's spacer — mirroring the Add / Remove /
  Rename / Import modals' inline-error slots so every inline-error
  surface in the TUI reads the same way. The
  `snapshot_passphrase_modal_set_default` baseline is unchanged —
  the conditional render fires only when `modal.error.is_some()`.)*
- [x] Passphrase set `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_passphrase_modal_set_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed`; per the plan's
  "Durability-unconfirmed failures follow the committed-state path"
  contract this surfaces in the inline error slot identically to the
  pre-commit failure.)*
- [x] Passphrase change `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_passphrase_modal_change_save_not_committed`
  drives the same rendering path as the `set` save_not_committed
  test but with `sub_flow: PassphraseSubFlow::Change`; the
  bordered-block title flips to ` Change passphrase ` and the
  intent line reads `Re-encrypts this vault under a new passphrase.`
  while the error row, the masked `Passphrase:` / `Confirm:` rows,
  and the surrounding list-view chrome all match the `set` baseline
  so the snapshot pins that the inline-error slot reads identically
  across the twice-confirm sub-flows.)*
- [x] Passphrase change `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_passphrase_modal_change_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed` for the `change`
  sub-flow; per the plan's "Durability-unconfirmed failures follow
  the committed-state path" contract this surfaces identically to
  the pre-commit failure.)*
- [x] Passphrase remove `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_passphrase_modal_remove_save_not_committed`
  pins the inline-error row for the encrypted → plaintext
  transition. The `render_remove_warning` body in
  `crates/paladin-tui/src/view/passphrase.rs` gained a dedicated
  `Length(1)` error row sandwiched between the wrapped
  plaintext-storage warning (sourced verbatim from
  [`paladin_core::format_plaintext_storage_warning`]) and the
  `Enter confirm  ·  Esc cancel` hint so the destructive-mutation
  verb remains visible alongside the save failure. The
  `snapshot_passphrase_modal_remove_default` baseline is unchanged —
  the conditional render fires only when `modal.error.is_some()`.)*
- [x] Passphrase remove `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_passphrase_modal_remove_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed` for the `remove`
  sub-flow; per the plan's "Durability-unconfirmed failures follow
  the committed-state path" contract this surfaces identically to
  the pre-commit failure.)*
- [x] Settings modal `save_not_committed`.
  *(`tests/view_snapshots.rs::snapshot_settings_modal_save_not_committed`
  drives `view::render` against an `AppState::Unlocked` carrying
  `Modal::Settings(SettingsModal { error: Some(render_error_message(
  &PaladinError::SaveNotCommitted { committed: false, backup_path:
  None })), .. })`. The renderer's new `render_inline_error` helper
  in `crates/paladin-tui/src/view/settings.rs` paints the error one
  blank row below the clipboard-spinner row, foreground red, inside
  the modal's `Min(0)` spacer — mirroring the Add / Remove / Rename
  / Import / Passphrase modals' inline-error slots so every
  inline-error surface in the TUI reads the same way. The
  `snapshot_settings_modal_default` baseline is unchanged — the
  conditional render fires only when `modal.error.is_some()`.)*
- [x] Settings modal `save_durability_unconfirmed`.
  *(`tests/view_snapshots.rs::snapshot_settings_modal_save_durability_unconfirmed`
  pins the same rendering path against
  `PaladinError::SaveDurabilityUnconfirmed`; per the plan's
  "Durability-unconfirmed failures follow the committed-state path"
  contract this surfaces in the inline error slot identically to the
  pre-commit failure.)*

Import error and counts states:

- [x] Import modal with each importer error kind.
  *(`crates/paladin-tui/tests/view_snapshots.rs` adds the shared
  `render_import_modal_with_inline_error` helper and twelve thin
  `snapshot_import_modal_*` tests — one per `PaladinError` variant
  the reducer's `reduce_import_result` Err arm surfaces:
  `unsupported_import_format`, `unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `validation_error`, `no_entries_to_import`, `decrypt_failed`,
  `invalid_header`, `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`. Each pins the
  `render_error_message`-formatted wording inside the spacer area
  between the conflict-selector row and the footer hint — same
  rendering path as the pre-commit / durability-unconfirmed
  snapshots — and the helper guards the rendered grid with a
  per-variant substring assertion before the snapshot lands so a
  regression that ever drops the inline error or strips the
  rendered wording surfaces as the assertion message rather than a
  silent snapshot diff. The matrix is 1:1 with the reducer tests'
  `effect_result_import_err_*_renders_inline` coverage in
  `tests/reducer_tests.rs`, so adding or renaming a variant in
  either lane stays visible in the other. Locked in
  `tests/snapshots/view_snapshots__snapshot_import_modal_{unsupported_import_format,unsupported_plaintext_vault,unsupported_encrypted_aegis,unsupported_aegis_entry_type,validation_error,no_entries_to_import,decrypt_failed,invalid_header,invalid_payload,unsupported_format_version,kdf_params_out_of_bounds,io_error}.snap`.)*
- [x] Import modal post-import counts panel.
  *(`crates/paladin-tui/src/view/import.rs::render` branches on
  `ImportModal::counts_panel`: when `Some`, the input layout
  (Source / Format / On conflict / footer hint) is replaced with the
  new `render_counts_panel` helper, which paints `Import complete.`
  in the top row, the four `ImportReport` merge totals in
  `Imported:` / `Skipped:` / `Replaced:` / `Appended:` rows aligned
  in the same `LABEL_COL_WIDTH` left-hand column as the path-entry
  rows, and an `Enter or Esc to close` centered footer hint —
  switching the modal cleanly from editable submission mode to
  read-only summary mode. The reducer's `reduce_import_result` Ok
  arm (`crates/paladin-tui/src/app/reducer.rs:917`) already seeds
  `counts_panel` from `paladin_core::ImportReport`, so no reducer
  changes were needed for this slice.
  `snapshot_import_modal_counts_panel` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs the panel
  with deliberately distinct counts (3 / 1 / 2 / 4) so a regression
  that ever swaps two counts surfaces as a diff rather than staying
  silent under identical values, and guards the rendered grid with
  per-row substring assertions before the snapshot lands. Locked in
  `tests/snapshots/view_snapshots__snapshot_import_modal_counts_panel.snap`.
  Validation-warning rendering inside the panel landed in the
  follow-up checklist row below.)*
- [x] Import counts panel with validation-warning messages.
  *(`crates/paladin-tui/src/view/import.rs::render_counts_panel`
  now lays out the carried `CountsPanel::warnings` strings — each
  one already pre-rendered by the reducer through
  `paladin_core::format_validation_warning()` (see
  `reduce_import_result`'s `Ok` arm at
  `crates/paladin-tui/src/app/reducer.rs:917`) — as one `Line`
  apiece inside a single `Paragraph` wrapped with
  `Wrap { trim: false }`, painted into a dedicated row band sitting
  between the four count rows and the footer hint. A blank separator
  row sits above the warnings band so the count rows and the
  warnings region read as two distinct sections of the same panel.
  When the carried warnings are non-empty the modal grows vertically
  so the wrapped warning rows stay fully visible at the standard
  80-column terminal width instead of being truncated at the right
  border; pre-flighting the wrapped row count via the new
  `wrapped_row_count` helper (greedy ASCII word wrap matching
  ratatui's `Wrap { trim: false }` behavior on the
  `format_validation_warning` output) keeps the modal-rect
  computation in `modal_height_for` aligned with the layout work in
  `render_counts_panel`. The no-warnings branches — both the
  no-counts-panel case and `CountsPanel { warnings: [], .. }` —
  short-circuit back to the pinned `MODAL_BASE_HEIGHT = 12`, so the
  `snapshot_import_modal_default` and
  `snapshot_import_modal_counts_panel` baselines stay locked.
  `snapshot_import_modal_counts_panel_with_validation_warnings` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs two
  `ValidationWarning::ShortSecret` warnings with distinct
  `decoded_len` values (5, 1) — routed through
  `paladin_core::format_validation_warning` so the snapshot binds to
  the core wording rather than a hand-typed string — and asserts
  that both warning texts plus the `Imported: 2` row remain visible
  before the snapshot lands. Locked in
  `tests/snapshots/view_snapshots__snapshot_import_modal_counts_panel_with_validation_warnings.snap`.)*

Export error states:

- [x] Export modal refused overwrite gate.
  *(`snapshot_export_modal_refused_overwrite_gate` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with
  `error: Some(render_error_message(&PaladinError::ValidationError { field: "path", reason: "output_exists".to_string(), .. }))` —
  binding the snapshot to the core `Display` wording rather than a
  hand-typed string — and renders through `view::render` at 80×20.
  `crates/paladin-tui/src/view/export.rs` now paints the
  [`ExportModal::error`] slot inside the spacer between the segmented
  `Format:` selector row and the footer hint, foreground red,
  mirroring the unlock screen's `decrypt_failed` styling and the Add
  / Remove / Rename modals' inline-error slots. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_refused_overwrite_gate.snap`
  so any future wording change in core's `validation_error` /
  `output_exists` surfaces here as a diff.)*
- [x] Export modal `confirmation_mismatch`.
  *(`snapshot_export_modal_confirmation_mismatch` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with `format: ExportFormat::Encrypted` and
  `error: Some(render_error_message(&PaladinError::InvalidPassphrase { reason: "confirmation_mismatch" }))` —
  binding the snapshot to the core `Display` wording rather than a
  hand-typed string — and renders through `view::render` at 80×20.
  Reuses the inline-error rendering branch in
  `crates/paladin-tui/src/view/export.rs` introduced by the
  refused-overwrite gate slice above. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_confirmation_mismatch.snap`
  so any future wording change in core's `invalid_passphrase` /
  `confirmation_mismatch` surfaces here as a diff.)*
- [ ] Export modal `zero_length`.
- [ ] Export modal plaintext-export warning.
- [ ] Export modal `io_error` writer failure.
- [ ] Export modal `save_not_committed`.
- [ ] Export modal `save_durability_unconfirmed`.

Add (QR) error and counts states:

- [ ] Add modal QR-import inline error: no clipboard image.
- [ ] Add modal QR-import inline error: image decode failure.
- [ ] Add modal QR-import inline error: zero decoded QRs.
- [ ] Add modal QR-import inline error: oversized raw RGBA buffer.
- [ ] Add modal QR-import inline error: invalid QR payload.
- [ ] Add modal post-QR-import counts panel.
- [ ] Add modal `duplicate_account`.
- [ ] Add modal "add anyway" confirmation.
- [ ] QR-add counts panel with validation-warning messages.

Passphrase inline errors:

- [ ] Passphrase modal `confirmation_mismatch` inline error.
- [ ] Passphrase modal `zero_length` inline error.

Status-line states:

- [ ] Status-line error after rejected copy.
- [ ] Status-line `save_durability_unconfirmed` after HOTP `n`.
- [ ] Status-line `clipboard_write_failed` after a failed copy.
- [x] Unlock screen with inline wrong-passphrase error.
  *(`snapshot_unlock_screen_with_wrong_passphrase_error` in
  `tests/view_snapshots.rs` sets
  `error: Some(PaladinError::DecryptFailed.to_string())` —
  binding the snapshot to the core `Display` wording rather than
  a hand-typed string — and locks the rendered grid in
  `tests/snapshots/view_snapshots__snapshot_unlock_screen_with_wrong_passphrase_error.snap`.)*
- [ ] Status-line confirmation after manual Add.
- [ ] Status-line confirmation after URI Add.
- [ ] Status-line confirmation after Remove.
- [ ] Status-line confirmation after Rename.
- [ ] Status-line confirmation after Export.
- [ ] Status-line confirmation after Passphrase set.
- [ ] Status-line confirmation after Passphrase change.
- [ ] Status-line confirmation after Passphrase remove.
- [ ] Status-line confirmation after Settings save.
- [ ] Manual Add status-line confirmation with validation warnings.
- [ ] URI Add status-line confirmation with validation warnings.

Startup error:

- [x] Startup-error screen rendered with `unsafe_permissions` (the
  `Some(text)` from `format_unsafe_permissions`).
  *(`crates/paladin-tui/src/view/startup_error.rs` renders a bordered
  `Paladin — startup error` block with an optional bolded vault path,
  the pre-rendered message split on `\n`, and the quit-keys hint;
  `Paragraph::wrap(Wrap { trim: false })` keeps long verbatim core
  text and long paths fully visible at narrow widths.
  `snapshot_startup_error_unsafe_permissions` in
  `tests/view_snapshots.rs` constructs the error via
  `PaladinError::UnsafePermissions { ... }`, threads it through
  `paladin_core::format_unsafe_permissions`, and locks the rendered
  grid in
  `tests/snapshots/view_snapshots__snapshot_startup_error_unsafe_permissions.snap`
  so any future wording change in core surfaces as a diff here.)*

## Dependencies

`ratatui`, `crossterm`, `tui-input`, `clap` (for arg parsing only),
`arboard`, `secrecy`, `zeroize`, plus `paladin-core`.
**No `tokio`.** No transitive network crates (enforced by workspace
`cargo deny`).

Dev-dependencies: `insta` for golden snapshots.

The TUI-specific deps are pinned to specific minor versions in
`crates/paladin-tui/Cargo.toml` so terminal rendering (`ratatui`),
key/event handling (`crossterm`), the search-bar widget (`tui-input`),
and clipboard access (`arboard`) do not drift across transitive minor
updates; `arboard` is pinned explicitly because it sits on the
clipboard security boundary (copy + image-import paths). `crossterm`
is pinned alongside `ratatui` so direct input/event handling and the
terminal backend are tested as a compatible pair. `insta` is similarly
pinned for snapshot stability across runs. This mirrors the
`paladin-core` pinning of `getrandom` /
`bincode v2` and the `paladin-cli` pinning convention.

## Thinness contract

`paladin-tui` is a presentation layer. Crypto, storage, import/export,
and OTP primitives must never be re-implemented or imported directly
here — they belong in `paladin-core` per DESIGN §3.

- [x] Tests: `tests/thinness.rs` — a source-level guard that scans
  `crates/paladin-tui/src/` for forbidden crate-name spellings:
  `argon2`, `chacha20poly1305`, `bincode`, `hmac`, `sha1`, `sha2`,
  `rqrr`, `image`, `getrandom`, `directories`, `url`. Any direct
  reference fails the test with a message pointing at the file and
  the symbol so the offending logic can be moved into `paladin-core`.
  The crate manifest is also checked: `paladin-tui` must not declare
  any of those crates as a direct `[dependencies]` entry. Keeps the
  TUI a thin shell over `paladin_core::*`.
  *(`paladin_tui_source_tree_does_not_reference_forbidden_crates`
  walks `src/` recursively and flags any of the three
  `use {name}` / `{name}::` / `extern crate {name}` patterns with
  the offending file path and line number;
  `paladin_tui_manifest_does_not_declare_forbidden_dependency`
  walks `Cargo.toml` table-by-table and flags either
  `name = ...` entries inside `[dependencies]` or
  `[dependencies.name]` sub-tables, leaving `[dev-dependencies]` /
  `[build-dependencies]` / `[features]` alone. Mirrors
  `crates/paladin-cli/tests/thinness.rs` and
  `crates/paladin-core/tests/no_network.rs`.)*

## Global flags

`--vault <path>` and `--no-color` are accepted (parity with siblings).
`--no-color` disables ratatui styling; the `NO_COLOR` environment variable
does the same when `--no-color` is absent, matching CLI text-output behavior.
`--json` is rejected at parse time with clap's standard text
diagnostic — `paladin-tui` has no JSON output mode and never emits a
JSON envelope, mirroring DESIGN §5. This rejection is text-only and
goes to stderr at clap's normal usage exit code; there is no argv
pre-scan equivalent of the CLI's strict-mode behavior because the TUI
is never expected to be scripted.

## Packaging (per §11)

`paladin-tui` ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.1
(§11.1). Implementation owes the release pipeline:

- **Man page.** Generate the argument synopsis for `paladin-tui.1` from
  clap via `clap_mangen`, and append maintained sections for keybindings,
  modal behavior, and the §6 missing-vault / startup-error screens, driven
  by the workspace `cargo xtask man` target. The packaging configs ship it
  gzipped at `/usr/share/man/man1/paladin-tui.1.gz` per §11.3.
- **Cargo.toml metadata.** `crates/paladin-tui/Cargo.toml` inherits
  `description`, `repository`, `homepage`, `license` (set to
  `"AGPL-3.0-or-later"` at the workspace), `edition`, and
  `rust-version` from `[workspace.package]` via per-field
  Cargo inheritance (`description.workspace = true`,
  `repository.workspace = true`, `homepage.workspace = true`, and so on)
  so `nfpm` and Flathub manifests read one source. It additionally sets
  the binary-specific `keywords` and `categories` fields locally. The
  packaging pipeline sources these values from Cargo metadata when
  building `.deb` / `.rpm` so the per-format configs in
  `packaging/deb/paladin-tui.yaml` and `packaging/rpm/paladin-tui.yaml`
  stay minimal. The Debian one-line description fits the conventional
  ~60-character synopsis display width (Debian Policy §5.6.13 caps the
  synopsis under 80); the long form is sourced from README.
- **No desktop entry.** The TUI is launched from a terminal and does
  not register a `.desktop` file (§11.3 only ships one for
  `paladin-gtk`). No icon assets are required.
- **Flatpak.** `packaging/flatpak/paladin-tui.yml` declares
  `org.freedesktop.Platform//23.08`, no `--share=network`,
  `xdg-data/paladin:create` plus `xdg-config/paladin:create`, and the
  minimal display clipboard permissions needed for `arboard`:
  `--socket=wayland`, `--socket=fallback-x11`, and `--share=ipc`.
  It does not request `--socket=session-bus` or `--socket=system-bus`;
  Flatpak's filtered portal bus access remains the default.
  `flatpak run org.tamx.Paladin.Tui` inherits the invoking
  terminal's stdin / stdout / stderr so `crossterm` raw mode and ANSI
  rendering work end-to-end against the host TTY while clipboard copy
  and clipboard image import work through the granted display socket.
- **AppImage.** `linuxdeploy` assembles the AppDir; the `AppRun`
  forwards argv unchanged so `paladin-tui-<version>-x86_64.AppImage`
  acts as a drop-in for the bare binary. The
  `linuxdeploy-plugin-gtk` is **not** used (TUI has no GTK
  dependency). `--appimage-extract-and-run` is the documented
  fallback for FUSE-less hosts.
- **Reproducible builds.** Same workspace pipeline as the CLI:
  vendored deps, `cargo build --locked`, `SOURCE_DATE_EPOCH` from
  the release tag (§11.6).
- **Signing.** `.deb`, `.rpm`, and AppImage artifacts are signed
  with `minisign`; the signature plus the project's published public
  key are uploaded alongside each artifact (§11.6). Flatpak releases
  inherit Flathub's signing.
- **`paladin tui` interaction.** The `paladin` CLI's `tui` subcommand
  resolves `paladin-tui` via `PATH` and `execvp`s it. Native `.deb` /
  `.rpm` installs put both binaries in `/usr/bin/`. Flatpak entry
  points are separate apps; the CLI Flatpak has no shared `PATH` to the
  TUI Flatpak, so `paladin tui` inside the CLI Flatpak returns the
  documented `exec_paladin_tui` `io_error` and users invoke the TUI
  directly via its Flatpak app ID. AppImage builds ship separate
  AppImages, so AppImage-only users invoke `paladin-tui` directly.

## Implementation checklist

- [ ] Scaffold `paladin-tui` crate, workspace membership, binary entry, and
  SPDX headers.
- [ ] Implement CLI args, vault path resolution, encrypted unlock,
  plaintext direct-open, missing-vault, and startup-error flows
  (including `format_unsafe_permissions` rendering).
- [ ] Implement terminal raw-mode / alternate-screen lifecycle with guarded
  restoration on exit, error, `Ctrl-C`, and panic unwind.
- [ ] Implement reducer, event producers, effect execution, clipboard
  timer tokens (issued by
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`),
  and auto-lock idle deadlines (computed by
  `paladin_core::policy::auto_lock::IdlePolicy::next_deadline`).
- [ ] Implement list layout from `AccountSummary` projections, search,
  TOTP gauges, HOTP reveal/copy behavior,
  HOTP `Code.counter_used` labels, and status-line errors.
- [ ] Implement vim-style list navigation (`j` / `k`, `Ctrl-F` /
  `Ctrl-B`, `G`, plus `gg` and `zz` two-press chords) in the
  reducer. Hold pending-chord state with no timeout; clear it on any
  non-matching key, focus change to search, modal open, `Esc`, or
  auto-lock. Add `Ctrl-B` / `Ctrl-F` to the search-focus
  pass-through list alongside the existing `Ctrl-D` / `Ctrl-U` /
  `PgUp` / `PgDn` / `Home` / `End`. Add `Ctrl-N` / `Ctrl-P` as
  modal-local `Tab` / `Shift-Tab` aliases.
- [ ] Implement add / remove / rename / import / export / passphrase / settings modals
  with persistence through `Vault::mutate_and_save` where the core owns
  rollback. Source the `passphrase remove` warning from
  `paladin_core::format_plaintext_storage_warning()` and the
  plaintext-export warning from
  `paladin_core::format_plaintext_export_warning()` so wording stays
  identical to the CLI / GUI; gate `set` vs `change` / `remove`
  sub-flows on `Vault::is_encrypted()` and feed the same getter into
  `paladin_core::policy::auto_lock::IdlePolicy::should_arm` to maintain
  or clear the auto-lock idle deadline.
- [ ] Implement the read-only Help overlay (`?` from list focus,
  `Esc` to close); render its content from the same keybindings table
  used to generate the man page so the two stay in sync; suppress
  `?` on the unlock, missing-vault, and startup-error screens.
  *(Reducer slice done — `help_open: bool` on `AppState::Unlocked`,
  `?` opener from list focus with `modal == None`, `Esc`-close
  precedence above modal-close / search-clear, all other keys are
  silent no-ops while open, `Ctrl-C` still quits, auto-lock
  discards the slot. View-level rendering of the keybindings table
  rides with the view slice.)*
- [ ] Use `paladin_core::account_matches_search` for `search.rs` substring
  filtering so the TUI shares issuer/label matching semantics with the CLI
  and GUI.
- [ ] Use `paladin_core::classify_paladin_import_precheck` before any
  encrypted-Paladin-bundle import prompt so the TUI does not duplicate the
  CLI / GUI Paladin header decision table.
- [ ] Route export writes through `paladin_core::write_secret_file_atomic`.
- [ ] Implement clipboard wrapper (arboard reads/writes), QR image
  import from clipboard bytes, and only-if-unchanged auto-clear via
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::should_clear`.
- [ ] Add reducer, search, auto-lock, clipboard, HOTP reveal, terminal
  lifecycle, sensitive-buffer, and snapshot coverage. Tracked at the
  bullet level in the Tests checklist; this top-level item only ticks
  once every Tests sub-bullet is checked.
- [ ] Add a `paladin-tui/test-hooks` cargo feature that is **off by
  default** in production builds and enabled only by the test build of
  the `paladin-tui` binary. `paladin-tui/test-hooks` transitively
  enables `paladin-core/test-fault-injection` so reducer / effect-layer
  integration tests can drive pre-commit and durability-unconfirmed
  save failures via the `PALADIN_FAULT_INJECT` env var.
- [ ] Wire a test-build-only `PALADIN_CLIPBOARD_DRYRUN=1` short-circuit
  in the TUI clipboard adapter that bypasses `arboard` and records the
  intended copy payload plus the auto-clear schedule, gated behind the
  same `paladin-tui/test-hooks` feature so production builds never link
  the hook. Lets CI exercise the copy → schedule → only-if-unchanged
  auto-clear loop end-to-end without a clipboard server.
- [ ] Add a TUI-side smoke test that spawns `paladin tui` (CLI) and
  asserts it execs `paladin-tui` on shared-`PATH` installs; the
  Flatpak `exec_paladin_tui` failure mode is exercised by the CLI
  plan's tests.

## Definition of done

- All keybindings + modals from §6 implemented.
- **Every Tests checklist item above is ticked** — including the
  reducer, vim-style navigation, search, auto-lock, clipboard
  auto-clear, terminal lifecycle, global args, every modal (Add,
  Import, Export, Settings, Rename), pre-commit save rollback, HOTP
  reveal window, sensitive UI buffers, vault modes / startup, and
  every insta snapshot. The "Add reducer, search, auto-lock,
  clipboard, HOTP reveal, terminal lifecycle, sensitive-buffer, and
  snapshot coverage" implementation-checklist item ticks only when
  this gate is met.
- Auto-lock + clipboard-clear are off by default and behave per §6 when
  enabled, including the plaintext-vault no-op.
- HOTP reveal rows show the counter used for the visible code, then return
  to the stored next counter when hidden.
- Insta snapshots locked for every screen state.
- `paladin tui` (CLI exec wrapper) launches this binary successfully in
  native/shared-`PATH` installs and has the documented Flatpak failure mode.
- Missing vaults show the non-mutating `paladin init` guidance screen.
- Vault-path resolution failures and non-`decrypt_failed` `inspect` /
  `open` errors surface on the non-mutating startup-error screen, with
  `unsafe_permissions` rendered via `format_unsafe_permissions`.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
