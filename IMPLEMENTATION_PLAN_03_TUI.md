# Implementation Plan 03 — `paladin-tui`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4.1, §4.2, §4.4, §4.5,
§5 (global flags / `paladin tui`), §6, §8, §9, §10, §11, §12 (Milestone 5),
§13, §14.
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
│   │   ├── event.rs       # AppEvent enum (Input, Tick, EffectResult, ClipboardClear, AutoLock)
│   │   ├── input.rs       # crossterm event → AppEvent translation
│   │   ├── ticker.rs      # 250ms tick thread, sleeps, mpsc producer
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
│   ├── search.rs          # incremental filter over Vault::iter() using paladin_core::account_matches_search; rows render AccountSummary projections
│   ├── clipboard.rs       # arboard wrapper + scheduled clear (only-if-unchanged)
│   ├── auto_lock.rs       # idle-timer; encrypted-only; plaintext is no-op
│   ├── hotp_reveal.rs     # reveal window per row using paladin_core::HOTP_REVEAL_SECS
│   ├── terminal.rs        # raw mode / alternate-screen guard; restores terminal on exit
│   ├── theme.rs           # color palette; --no-color / NO_COLOR disables styling
│   └── prompt.rs          # shared zeroizing passphrase-input widget reused by unlock.rs and modals/passphrase.rs
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
long-lived producer threads plus effect-owned one-shot timer threads:

- **Input thread** — `crossterm::event::read()` in a loop, maps to
  `AppEvent::Input(KeyEvent | ResizeEvent | …)`.
- **Ticker thread** — sleeps 250 ms, emits `AppEvent::Tick(now)`.
- **Timer side effects** — clipboard auto-clear and auto-lock effects spawn
  one-shot timer threads that later send
  `AppEvent::ClipboardClear { token, value }` /
  `AppEvent::AutoLock { token }`.

The reducer is a pure function over `(state, event) → (state, Vec<Effect>)`
so it is unit-testable without a terminal. Effects are executed by `app::run`,
which is the only boundary that may call impure core / clipboard / writer
functions. Save-bearing effects mutate the current `Vault` only through core
APIs (`mutate_and_save`, `hotp_advance`, or passphrase transitions), then send
an `AppEvent::EffectResult(...)` back through the same `mpsc` channel. The
reducer owns all non-core visible state updates (status text, reveal windows,
modal close/count panels, and inline errors) from that result, while trusting
core rollback semantics for the `Vault` value. Timer effects remain the only
effects that send delayed non-result events (`ClipboardClear` / `AutoLock`).
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
and encrypted-bundle Export — build `EncryptionOptions::new(secret)` with
the §4.4 defaults (m=64 MiB, t=3, p=1) and surface no UI for
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

- TOTP rows render a live `Gauge` countdown; re-rendered on every 250 ms tick.
- HOTP rows: when hidden, the code area shows the prompt
  `▸ press n to advance` and the row's `(#counter)` is shown in the
  label-suffix slot using the stored next counter (matching DESIGN §6).
  Pressing `n` calls
  `Vault::hotp_advance` (advances counter and saves) and reveals the
  generated code in place of the prompt for the shared
  `paladin_core::HOTP_REVEAL_SECS` window (120 seconds), after
  which the row returns to the hidden state. Reveal expiry is detected
  on the next 250 ms `Tick` event (no separate timer thread or
  `AppEvent` variant; the reveal carries a deadline timestamp checked
  at tick time). `n` always advances and
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
  `PgUp` / `PgDn` move by viewport height, `Home` / `End` jump to the
  first / last row of the filtered set, and `Ctrl-D` / `Ctrl-U` move
  by half a viewport (vim-style). Selection clamps to the bounds of
  the filtered result set and never goes off-list.

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
(`PgUp`, `PgDn`, `Home`, `End`, `Ctrl-D`, `Ctrl-U`) likewise pass
through to the list while the search bar has focus; they are
navigation, not text editing, and `tui-input` does not consume them.
Other keys, including the action keys `a` / `r` / `R` / `i` /
`e` / `n` / `p` / `s` / `?`, the search-focus key `/`, and the quit key `q`,
are routed to the search field as character input while it has focus;
the user must defocus the search (`Esc` to clear) to use them as actions. `Ctrl-C` is the exception and
always quits. `Esc` clears the search query and returns focus to the list;
on the list, `Esc` is a no-op. Modal dialogs trap focus while open
and intercept `Esc` to close themselves. The missing-vault and
startup-error screens accept `Esc` / `q` / `Ctrl-C` to quit (the
screens are read-only dead-ends with no input or state to discard, so
all three keys behave identically). The unlock screen accepts character
input (passphrase) and `Enter` (submit), and quits on `Esc` or
`Ctrl-C` (`q` is a valid passphrase character, so it is not bound to
quit there).

When the filter changes, preserve the selected account by `AccountId` if it
is still present; otherwise select the first matching row. Empty result sets
render an empty-state row and have no selection. With no selection, `Enter`,
`n`, `r`, and `R` produce a status-line "no account selected" error and no effect;
Add / Import / Export / Passphrase / Settings remain available from list
focus.

## Modals (per §6)

All passphrase-entry fields (unlock, encrypted Paladin import, encrypted
export, passphrase set/change) and the Add modal's secret-bearing
fields (manual-secret field and the URI-mode entry) keep typed bytes in
zeroizing buffers, convert to `secrecy::SecretString` only for core
calls, and zeroize on submit, cancel, modal close, and auto-lock.
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
Export / Passphrase / Settings: `Tab` moves to the next control,
`Shift-Tab` moves to the previous control, `Enter` activates the focused
button or the modal's default confirm action, `Space` toggles the focused
checkbox / toggle, `←` /
`→` change segmented selectors, and `↑` / `↓` adjust spinners or move within
multi-line field groups. Text fields consume printable characters and standard
editing keys. `Esc` cancels the modal and discards pending modal-local edits
unless the modal is showing a post-success counts panel, where `Esc` simply
closes it.

Successful modal outcomes are consistent: manual Add, URI Add, Remove,
Rename, Export, Passphrase, and Settings close the modal and publish a
status-line confirmation (unless Settings Confirm found no changes, which
closes without saving). Import and clipboard-QR Add stay in the modal on a
post-success counts panel so imported/skipped/replaced/appended/warning
counts remain visible; `Esc` closes that panel. Durability-unconfirmed
outcomes are not treated as success closes: the modal stays open and surfaces
the warning inline so the user can retry or dismiss deliberately.

- **Add** — three input modes selected via a segmented header inside
  the modal: manual fields, paste of an `otpauth://` URI, and a
  focused "scan from clipboard image" control (CLI parity with `add`
  interactive / `--uri` / `--qr`).
  Manual mode collects label, issuer, secret
  (Base32 RFC 4648, case-insensitive, optional `=` padding), algorithm
  (`sha1` / `sha256` / `sha512`), digits (6 / 7 / 8), kind (`totp` or
  `hotp`), period (TOTP-only) or counter (HOTP-only), and optional
  icon-hint mode (`Default from issuer`, `No icon`, or explicit slug);
  defaults follow the CLI manual-add defaults in DESIGN §5 (TOTP, SHA1,
  6 digits, 30 s period, HOTP counter 0, icon-hint defaulted from the
  issuer per §4.1). Each submit captures one `submit_time` used for
  account validation/import timestamps. The modes map to
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
  per the §14 signature, which takes `import_time` directly rather than
  the `ImportOptions` accepted by `import::from_file` /
  `import::from_bytes`.
  Validation warnings are shown inline with
  `paladin_core::format_validation_warning()` and do
  not block creation. Because `Vault::add` is infallible and duplicate
  presentation policy is owned by the front ends, manual and URI duplicate
  collisions call `Vault::find_duplicate(&validated)` before mutation. A
  collision initially rejects with the existing account in the modal and
  offers an "add anyway" confirmation that inserts the pending validated
  account on the duplicate-allowed path (CLI parity with
  `--allow-duplicate`, appending a new account that shares the
  `(secret, issuer, label)` triple). QR imports
  call `Vault::import_accounts` with
  `ImportConflict::Skip` and report imported/skipped/warning counts in the
  post-success counts panel.
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
  the trimmed input; same label validation as Add (non-empty, §4.1
  length limits). A no-op rename (trimmed input equals the current
  label) closes the modal without invoking `mutate_and_save`. Issuer
  is **not** editable here — parity with the CLI's `rename` taking
  only `<new-label>`; deeper edits use Remove + Add. Pre-commit save
  failures (`save_not_committed`) restore the prior label so memory
  matches disk and the modal stays open with the inline error;
  durability-unconfirmed saves leave the new label in memory and
  surface the warning inline. Rename does not handle secret material;
  the label buffer is cleared on submit, cancel, modal close, and
  auto-lock alongside the other modal-local state.
- **Import** — text field for the source path, a format selector
  (auto-detect or explicit `otpauth` / `aegis` / `paladin` / `qr`),
  and an on-conflict selector (`skip` / `replace` / `append`).
  Before any Paladin-bundle passphrase prompt, the TUI mirrors the CLI's
  import probe from DESIGN §5. When the selected format is auto-detect
  or explicit `paladin`, `paladin_core::inspect(path)` is used only to
  decide whether a bundle passphrase is needed:
  encrypted bundles (`VaultStatus::Encrypted`) prompt for the bundle
  passphrase inside the modal before invoking the importer, and
  plaintext Paladin headers (`VaultStatus::Plaintext`) surface
  `unsupported_plaintext_vault` without a passphrase prompt. Explicit
  non-`paladin` forced formats skip this passphrase path entirely. Missing
  files, non-Paladin content, and probe errors that do not identify an
  encrypted/plaintext Paladin bundle do not consume a passphrase; the
  modal continues through
  `paladin_core::import::from_file` so the import facade owns `io_error`,
  `unsupported_import_format`, and any format-specific `invalid_header`
  errors. The selected
  `paladin_core::import::from_file` call returns `Vec<ValidatedAccount>`; on
  success, `Vault::import_accounts(accounts, conflict, import_time)` is called
  inside `Vault::mutate_and_save` with the user's policy and the same
  `import_time` passed to `ImportOptions`. The modal reports
  imported/skipped/replaced/appended/warning counts in a post-success counts
  panel.
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
  only on encrypted vaults; opening the modal in a state with no
  available sub-flow surfaces an inline message instead of mutation
  controls. The `remove` sub-flow renders
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
  `clipboard.clear_secs`. The spinners clamp to the §5 bounds
  (`30 <= auto_lock.timeout_secs <= 86_400`,
  `5 <= clipboard.clear_secs <= 600`). The
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
- **Plaintext vaults are a no-op** — there's no credential to require, so
  the timer is not even armed. The setting is still persisted so it takes
  effect if the vault is later encrypted via `passphrase set`.
- Idle is reset by any `AppEvent::Input`. Timer is implemented as a
  monotonic token + timer thread; on wake, stale `AutoLock { token }`
  events are ignored by the reducer.
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
- The wipe **only fires if the clipboard still holds the value we wrote** —
  we never stomp something the user copied afterwards. Implementation: at
  copy time, capture `(token, value)` and store the latest token in UI
  state; on wake, ignore stale tokens first, then read current clipboard,
  and if it equals `value`, write empty; otherwise no-op.

## Effect errors

Effects update visible state only after the underlying mutation succeeds or
reaches the primary-file commit point with durability still uncertain:

- HOTP `n`: the effect calls `Vault::hotp_advance`, stages the returned
  `Code` (whose `counter_used` is the pre-advance counter) in zeroizing
  pending state, and publishes it to the reveal slot only if the call
  succeeds or returns `save_durability_unconfirmed`.
  Pre-commit save failures (`save_not_committed`) leave the in-memory
  counter and reveal state unchanged (per DESIGN §4.2 rollback) and
  surface a status-line error. Durability-unconfirmed failures
  (`save_durability_unconfirmed`) reveal the new code and
  `Code.counter_used` label and report the committed-but-uncertain status
  in the status line — the user has the new code in hand even though
  durability is in question. All other failures show a status-line error
  and leave the previous reveal state unchanged (hidden if no reveal was
  open).
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

| Key                 | Action                                                                                  |
| ------------------- | --------------------------------------------------------------------------------------- |
| `↑` `↓`             | Move selection                                                                          |
| `PgUp` `PgDn`       | Page up / page down (viewport height)                                                   |
| `Home` `End`        | Jump to first / last row of the filtered set                                            |
| `Ctrl-D` `Ctrl-U`   | Half-page down / up (vim-style)                                                         |
| `Enter`             | Copy selected code (TOTP: current; HOTP: visible only)                                  |
| `n`                 | HOTP next-code (advances + reveals `HOTP_REVEAL_SECS`)                                  |
| `a`                 | Open Add modal                                                                          |
| `r`                 | Open Remove confirmation                                                                |
| `R`                 | Open Rename modal (Shift+R; `r` stays bound to Remove)                                  |
| `i`                 | Open Import modal                                                                       |
| `e`                 | Open Export modal                                                                       |
| `/`                 | Focus search bar                                                                        |
| `Tab` `Shift-Tab`   | Cycle focus between search bar and list (commits active query when leaving search)      |
| `p`                 | Open Passphrase modal                                                                   |
| `s`                 | Open Settings modal                                                                     |
| `?`                 | Open Help overlay (lists all keybindings); `Esc` closes                                 |
| `Esc`               | Close modal / clear search; close Help overlay; quit on unlock, missing-vault, startup-error screens |
| `q`                 | Quit from list, missing-vault, and startup-error screens; text input in text fields     |
| `Ctrl-C`            | Quit (any screen)                                                                       |

## Tests

Reducer/state-machine logic is pure and tested directly. Rendered frames are
captured with `insta` golden snapshots using `ratatui::backend::TestBackend`.

- **Reducer**: every keybinding maps to the expected state transition.
  Search filter; selection navigation; modal open/close; HOTP `n` triggers a
  `HotpAdvance` effect; `AppEvent::EffectResult(...)` variants are the only
  path for effect outcomes to change non-core UI state; pre-commit effect
  failures leave visible state unchanged and surface inline/status-line
  errors, while durability-unconfirmed failures follow the committed-state
  behavior in "Effect errors". Modal-local navigation covers `Tab` / `Shift-Tab`,
  `Enter`, `Space`, arrows, text-field editing, and `Esc` cancel / close
  behavior for every modal.
- **Search**: case-insensitive substring through
  `paladin_core::account_matches_search` (using the same base match key as
  CLI query resolution in DESIGN §5; empty issuer is allowed and the colon is
  still present in the match key), with no Unicode normalization; insertion
  order preserved among matches. Filter changes
  preserve the selected `AccountId` when it remains visible, otherwise
  select the first match; empty result sets have no selection and action
  keys that require a selected row surface the "no account selected"
  status-line error. The `id:` prefix form is CLI-only and is **not**
  honored by the TUI search.
- **Auto-lock**: timer arms on `Unlocked` + `enabled` + encrypted; resets
  on input; transitions to `Locked` on expiry; **no-op** for plaintext
  vaults (timer never arms); stale timer tokens are ignored. Setting
  persists across saves. Locking discards the `Vault` / `Store`, open HOTP
  reveal windows, the search query, and any modal while retaining the
  resolved vault path for the next unlock attempt; a clipboard auto-clear
  timer scheduled before lock survives lock and still fires only-if-unchanged.
- **Clipboard auto-clear**: timer schedules; stale tokens are ignored;
  "only-if-unchanged" honored when an external copy mutates the clipboard
  between copy and wake; pending copied values are zeroized after the clear
  attempt or stale-token drop. CI tests drive these flows through the
  `PALADIN_CLIPBOARD_DRYRUN=1` adapter hook so they run without a
  clipboard server.
- **Terminal lifecycle**: terminal setup uses a guard that restores raw mode
  and alternate-screen state on normal exit, startup failure after setup,
  `Ctrl-C`, and panic unwind.
- **Global args**: `--vault` selects the inspected/opened vault path,
  `--no-color` and `NO_COLOR` disable styling, and `--json` is rejected at
  parse time with clap's text diagnostic and no JSON envelope.
- **Add modal**: manual and URI duplicate collisions are detected through
  `Vault::find_duplicate(&validated)`, reject with the existing account,
  and the follow-up "add anyway" confirmation inserts the pending validated
  account on the duplicate-allowed path so the new entry is appended with a
  fresh ID;
  clipboard QR import uses `ImportConflict::Skip`, reports imported/skipped
  counts, handles validation warnings rendered through
  `paladin_core::format_validation_warning()`, and rejects no-image /
  no-QR / invalid-QR cases inline.
- **Import modal**: format auto-detect and explicit format overrides route
  through `paladin_core::import::from_file`; the pre-prompt Paladin probe
  only prompts when auto-detect or explicit `paladin` sees an encrypted
  Paladin bundle; plaintext-Paladin path returns
  `unsupported_plaintext_vault` without prompting; missing files,
  non-Paladin content, and forced-format mismatches do not consume a
  passphrase and surface through the import facade; malformed Paladin headers
  surface `invalid_header` inline; on-conflict policy
  (`skip` / `replace` / `append`) is forwarded to
  `Vault::import_accounts` and reflected in the report counts;
  importer error kinds listed under "Effect errors", including
  `unsupported_import_format`, surface inline without mutation;
  successful imports persist via `Vault::mutate_and_save`
  and a `save_not_committed` failure restores the core snapshot so
  `Vault::iter()` matches its pre-attempt state.
- **Export modal**: format selector routes to
  `paladin_core::export::otpauth_list` or
  `paladin_core::export::encrypted`; refused overwrite rejects without
  writing; encrypted export prompts twice and rejects mismatch with
  `confirmation_mismatch` and empty entry with `zero_length`;
  plaintext export requires the unencrypted-secrets confirmation
  before writing; output is written through
  `paladin_core::write_secret_file_atomic` with mode `0600`; writer
  `io_error`, `save_not_committed`, and `save_durability_unconfirmed`
  surface inline and the modal stays open. Export performs no `Vault::save`
  and leaves vault state unchanged across success and failure.
- **Settings modal**: pending edits are buffered until Confirm; `Esc`
  discards them without invoking setters or save; Confirm runs every
  changed setter inside one `Vault::mutate_and_save` transaction; a
  defensive setter validation failure restores the pre-attempt settings,
  surfaces inline, blocks the save, and keeps the modal open; a pre-commit
  save failure restores the prior settings values in memory and keeps the
  modal open with the inline error; a durability-unconfirmed save leaves the
  new values in memory; Confirm with no changes closes without saving.
- **Rename modal**: opens with the selected account's current label
  pre-populated; trimmed-equal input short-circuits without calling
  `Vault::rename` or `Vault::mutate_and_save`; non-empty trimmed
  changes route through `Vault::rename` inside
  `Vault::mutate_and_save`; pre-commit `save_not_committed` restores
  the prior label and the modal stays open with the inline error;
  `save_durability_unconfirmed` leaves the new label in memory and
  surfaces the warning. Empty / out-of-range labels surface inline
  validation errors and never invoke the setter.
- **Pre-commit save rollback**: Add, Remove, Rename, Import, and Settings modals
  route mutations through `Vault::mutate_and_save`. Each case verifies
  that a `save_not_committed` failure leaves `Vault::iter()` (or
  `Vault::settings()`) matching its pre-attempt snapshot, the modal stays
  open with the typed inline error, and `save_durability_unconfirmed`
  leaves the new state in memory while still surfacing the warning.
  Passphrase rollback is exercised in the `paladin-core` plan; the TUI
  test asserts that the inline error surfaces and that the TUI's
  visible vault-mode flag (sourced from `Vault::is_encrypted()`) tracks
  the transition outcome without inspecting private key/cache material.
- **HOTP reveal window**: reveal closes after
  `paladin_core::HOTP_REVEAL_SECS`; `n` during an open
  reveal advances again (does not no-op); hidden rows show the stored next
  counter, while revealed rows show the counter that produced the visible
  code until expiry.
- **Sensitive UI buffers**: unlock, encrypted Paladin import, encrypted export,
  passphrase set/change, the Add modal's manual-secret field, the Add
  URI-mode entry, pending duplicate-add validated accounts, HOTP reveal,
  and pending clipboard-clear buffers zeroize on submit, cancel, modal close,
  expiry, replacement, drop, and auto-lock as applicable. Pending
  clipboard-clear buffers are the auto-lock exception: they survive lock
  only until the scheduled clear attempt, stale-token drop, replacement, or
  app shutdown, and are zeroized at that point.
- **Insta snapshots** for every screen state: empty vault, single TOTP,
  mixed TOTP/HOTP with hidden + revealed rows, search-active, every modal
  (Add / Remove / Rename / Import / Export / Passphrase set/change/remove /
  Settings), Help overlay, unlock screen, missing-vault screen, status-line error
  after rejected copy, `--no-color` variants. Error-state snapshots:
  inline `save_not_committed` and `save_durability_unconfirmed`
  rendered in each mutating modal (Add, Remove, Rename, Import, Passphrase
  set/change/remove, Settings); Import modal with each importer error
  kind and the post-import counts panel; Export modal with the refused
  overwrite gate, `confirmation_mismatch`, `zero_length`, plaintext-export
  warning, `io_error` writer failure, `save_not_committed`, and
  `save_durability_unconfirmed`; status-line
  `save_durability_unconfirmed` after HOTP `n`; status-line
  `clipboard_write_failed` after a failed copy; unlock screen with
  inline wrong-passphrase error; Add modal with QR-import inline
  errors (no clipboard image, image decode failure, zero decoded QRs,
  invalid QR payload) plus the post-QR-import counts panel; Add modal with
  `duplicate_account` and the
  follow-up "add anyway" confirmation; Passphrase modal with
  `confirmation_mismatch` and `zero_length` inline errors;
  status-line confirmations after manual Add, URI Add, Remove, Rename,
  Export, Passphrase set/change/remove, and Settings save;
  startup-error screen rendered with `unsafe_permissions` (the `Some(text)`
  from `format_unsafe_permissions`).
- **Plaintext vault**: opens directly to list (no unlock screen).
- **Encrypted vault**: opens to unlock screen; wrong passphrase shows
  inline error; correct passphrase advances to list.
- **Missing vault**: opens the missing-vault screen and does not create or
  mutate files.
- **Startup errors**: vault-path resolution failures and
  non-`decrypt_failed` errors from `inspect` / `open` (including
  `unsafe_permissions`) open the non-mutating startup-error screen and do
  not create or mutate files;
  `unsafe_permissions` rendering uses the `Some(text)` from
  `format_unsafe_permissions` verbatim.

## Dependencies

`ratatui`, `crossterm`, `tui-input`, `clap` (for arg parsing only),
`arboard`, `secrecy`, `zeroize`, plus `paladin-core`.
**No `tokio`.** No transitive network crates (enforced by workspace
`cargo deny`).

Dev-dependencies: `insta` for golden snapshots.

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
  `description`, `repository`, `license = "AGPL-3.0-or-later"`,
  `edition`, and `rust-version` from `[workspace.package]` via per-field
  Cargo inheritance (`description.workspace = true`,
  `repository.workspace = true`, and so on) so `nfpm` and Flathub
  manifests read one source. It additionally sets the binary-specific
  `homepage`, `keywords`, and `categories` fields locally. The
  packaging pipeline sources these values from Cargo metadata when
  building `.deb` / `.rpm` so the per-format configs in
  `packaging/deb/paladin-tui.yaml` and `packaging/rpm/paladin-tui.yaml`
  stay minimal. The Debian one-line description is short enough for
  the 60-char limit; the long form is sourced from README.
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
  `flatpak run io.github.paladin_otp.Tui` inherits the invoking
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
- [ ] Implement reducer, event producers, effect execution, and timer tokens.
- [ ] Implement list layout from `AccountSummary` projections, search,
  TOTP gauges, HOTP reveal/copy behavior,
  HOTP `Code.counter_used` labels, and status-line errors.
- [ ] Implement add / remove / rename / import / export / passphrase / settings modals
  with persistence through `Vault::mutate_and_save` where the core owns
  rollback. Source the `passphrase remove` warning from
  `paladin_core::format_plaintext_storage_warning()` and the
  plaintext-export warning from
  `paladin_core::format_plaintext_export_warning()` so wording stays
  identical to the CLI / GUI; gate `set` vs `change` / `remove`
  sub-flows on `Vault::is_encrypted()` and use the same getter to
  arm or skip the auto-lock timer.
- [ ] Implement the read-only Help overlay (`?` from list focus,
  `Esc` to close); render its content from the same keybindings table
  used to generate the man page so the two stay in sync; suppress
  `?` on the unlock, missing-vault, and startup-error screens.
- [ ] Use `paladin_core::account_matches_search` for `search.rs` substring
  filtering so the TUI shares issuer/label matching semantics with the CLI
  and GUI.
- [ ] Route export writes through `paladin_core::write_secret_file_atomic`.
- [ ] Implement clipboard wrapper, QR image import from clipboard bytes, and
  only-if-unchanged auto-clear.
- [ ] Add reducer, search, auto-lock, clipboard, HOTP reveal, terminal
  lifecycle, sensitive-buffer, and snapshot coverage.
- [ ] Wire the `paladin-core` `test-fault-injection` cargo feature into
  the test build of the `paladin-tui` binary so reducer / effect-layer
  integration tests can drive pre-commit and durability-unconfirmed
  save failures via the `PALADIN_FAULT_INJECT` env var.
- [ ] Wire a test-build-only `PALADIN_CLIPBOARD_DRYRUN=1` short-circuit
  in the TUI clipboard adapter that bypasses `arboard` and records the
  intended copy payload plus the auto-clear schedule, gated behind a
  test cargo feature so production builds never link the hook. Lets CI
  exercise the copy → schedule → only-if-unchanged auto-clear loop
  end-to-end without a clipboard server.
- [ ] Add a TUI-side smoke test that spawns `paladin tui` (CLI) and
  asserts it execs `paladin-tui` on shared-`PATH` installs; the
  Flatpak `exec_paladin_tui` failure mode is exercised by the CLI
  plan's tests.

## Definition of done

- All keybindings + modals from §6 implemented.
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
