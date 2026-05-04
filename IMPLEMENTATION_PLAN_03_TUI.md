# Implementation Plan 03 — `paladin-tui`

Source of truth: [DESIGN.md](DESIGN.md) §3, §5 (global flags / `paladin tui`),
§6, §10, §11 (Milestone 5), §12, §13.
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

## Scope

Standalone binary `paladin-tui`. Single-screen MVP per §6: search bar,
account list with live TOTP gauges and HOTP reveal-on-`n`, status line, and
modal dialogs for add / remove / passphrase / settings. Auto-lock and
clipboard auto-clear are **opt-in** per `VaultSettings`. The TUI is also
reachable via `paladin tui` which `execvp`s this binary.

Runtime model (§12): plain threads + `mpsc`. **No `tokio`** — local TUIs
don't need async I/O.

## Crate layout

```
crates/paladin-tui/
├── Cargo.toml             # license = "AGPL-3.0-or-later"; bin = "paladin-tui"
├── src/
│   ├── main.rs            # parse args (clap), reject --json, hand off to app::run
│   ├── cli.rs             # GlobalArgs (--vault, --no-color; --json rejected)
│   ├── app/
│   │   ├── mod.rs         # App state machine + run loop
│   │   ├── state.rs       # AppState: Missing / Locked / Unlocked { vault, ui, modals }
│   │   ├── event.rs       # AppEvent enum (Input, Tick, ClipboardClear, AutoLock)
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
│   │       ├── passphrase.rs   # set/change/remove sub-flows
│   │       └── settings.rs     # auto_lock + clipboard toggles + timeouts
│   ├── search.rs          # incremental filter over Vault::iter()
│   ├── clipboard.rs       # arboard wrapper + scheduled clear (only-if-unchanged)
│   ├── auto_lock.rs       # idle-timer; encrypted-only; plaintext is no-op
│   ├── hotp_reveal.rs     # 120s reveal window per row
│   ├── theme.rs           # color palette; --no-color disables styling
│   └── prompt.rs          # passphrase prompt inside the TUI (modal, not /dev/tty)
└── tests/
    ├── reducer_tests.rs
    ├── search_tests.rs
    ├── auto_lock_tests.rs
    ├── clipboard_tests.rs
    ├── hotp_reveal_tests.rs
    └── snapshots/         # insta golden frames for every screen + modal
```

Every new Rust source file carries the standard SPDX header
`// SPDX-License-Identifier: AGPL-3.0-or-later`.

## Event loop (per §6)

Single thread runs the reducer. Two long-lived producer threads feed
`mpsc<AppEvent>`:

- **Input thread** — `crossterm::event::read()` in a loop, maps to
  `AppEvent::Input(KeyEvent | ResizeEvent | …)`.
- **Ticker thread** — sleeps 250 ms, emits `AppEvent::Tick(now)`.
- **Timer side effects** — clipboard auto-clear and auto-lock effects spawn
  one-shot timer threads that later send
  `AppEvent::ClipboardClear { token, value }` / `AppEvent::AutoLock`.

The reducer is a pure function over `(state, event) → (state, Vec<Effect>)`
so it is unit-testable without a terminal. Effects are executed by `app::run`.

## Startup / vault modes

Startup mirrors the CLI's vault inspection path:

1. Resolve vault path (`--vault` or `directories::ProjectDirs::data_dir()`).
2. Call `paladin_core::inspect(path)`.
3. `VaultStatus::Missing` opens a non-mutating missing-vault screen with a
   status message telling the user to run `paladin init`; v0.1 TUI does not
   create vaults.
4. `VaultStatus::Plaintext` opens directly to the list view.
5. `VaultStatus::Encrypted` opens the unlock screen and prompts inside the
   TUI; wrong passphrases keep the user on the unlock screen with an inline
   error.

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
  label-suffix slot (matching DESIGN §6). Pressing `n` calls
  `Vault::hotp_advance` (advances counter and saves) and reveals the
  generated code in place of the prompt for a 120-second window, after
  which the row returns to the hidden state. `n` always advances and
  re-reveals (it's the "give me the next code" key) — pressing `n` again
  during an open reveal advances to the next counter rather than
  no-op'ing. `n` is a no-op when the selected row is TOTP (TOTP codes
  are always visible).
- Copying a hidden HOTP row is **rejected** with a status-line message.
  Copying during the reveal window copies the visible code and does not
  advance again.

## Focus model

Focus alternates between the search bar and the account list. `/`
focuses the search bar; typing narrows the filtered list in place.
While the search bar is focused, `↑`/`↓` still move the list selection
and `Enter` copies the selected entry — the selection is always
navigable so the user does not need to unfocus the search to act on a
result. `Esc` clears the search query and returns focus to the list;
on the list, `Esc` is a no-op. Modal dialogs trap focus while open and
intercept `Esc` to close themselves. The unlock and missing-vault
screens accept `q` / `Ctrl-C` to quit; the unlock screen additionally
accepts character input (passphrase) and `Enter` (submit).

## Modals (per §6)

- **Add** — manual fields and "scan from clipboard image" (triggered by
  an in-modal action key). Manual mode collects label, issuer, secret
  (Base32 RFC 4648, case-insensitive, optional `=` padding), algorithm
  (`sha1` / `sha256` / `sha512`), digits (6 / 7 / 8), kind (`totp` or
  `hotp`), period (TOTP-only) or counter (HOTP-only), and optional
  icon-hint slug; defaults follow the CLI manual-add defaults in
  DESIGN §5 (TOTP, SHA1, 6 digits, 30 s period, HOTP counter 0,
  icon-hint defaulted from the issuer per §4.1). Manual entries route
  through `paladin_core::validate_manual`; clipboard images are read
  through `arboard`, converted to raw RGBA8 bytes, and passed to
  `paladin_core::import::qr_image_bytes`. Validation warnings are shown
  inline and do not block creation. Manual duplicate collisions
  initially reject with the existing account in the modal and offer an
  "add anyway" confirmation that re-submits the same input on the
  duplicate-allowed path (CLI parity with `--allow-duplicate`,
  appending a new account that shares the `(secret, issuer, label)`
  triple). QR imports call `Vault::import_accounts` with
  `ImportConflict::Skip` and report imported/skipped/warning counts.
  Successful additions call `Vault::save(&Store)` after the validated
  accounts are inserted.
- **Remove** — confirmation modal. On confirm, calls `Vault::remove`, then
  `Vault::save(&Store)`.
- **Passphrase** — three sub-flows mirroring CLI's
  `passphrase set / change / remove`. The available sub-flow is gated
  by vault mode: `set` is offered only on plaintext vaults
  (plaintext → encrypted), and `change` / `remove` are offered only on
  encrypted vaults; opening the modal in a state with no available
  sub-flow surfaces an inline message instead of mutation controls.
  New passphrases (`set`, `change`) are prompted twice and confirmed;
  mismatch returns to the modal with an inline `invalid_passphrase`
  (`reason: "confirmation_mismatch"`) error. Empty new passphrases are
  rejected with `invalid_passphrase` (`reason: "zero_length"`).
  `remove` shows the plaintext-storage warning and requires explicit
  confirmation before mutation. The transition methods
  (`set_passphrase` / `change_passphrase` / `remove_passphrase`) save
  themselves through `&Store`; the TUI surfaces pre-commit and
  durability-unconfirmed failures inline per DESIGN §4.5.
- **Settings** — toggles for `auto_lock.enabled` and
  `clipboard.clear_enabled`, spinners for `auto_lock.timeout_secs` and
  `clipboard.clear_secs`. The spinners clamp to the §5 minimums
  (`auto_lock.timeout_secs >= 30`, `clipboard.clear_secs >= 5`). The
  modal accumulates pending edits in modal-local state and only commits
  on Confirm: pending values are validated against the same setters
  (`set_auto_lock_*`, `set_clipboard_clear_*`), then a single
  `Vault::save(&Store)` persists the batch. Setters that fail
  validation surface inline against the offending field and block the
  commit; closing the modal with `Esc` discards pending edits without
  invoking setters or save. Save errors are shown inline and the modal
  stays open so the user can retry. If no fields changed, Confirm
  closes without invoking save.

## Auto-lock (per §6)

- **Off by default.** When `auto_lock.enabled = true`, the TUI clears the
  in-memory vault (`AppState::Locked`) after `auto_lock.timeout_secs` of no
  input and shows the unlock screen for encrypted vaults.
- **Plaintext vaults are a no-op** — there's no credential to require, so
  the timer is not even armed. The setting is still persisted so it takes
  effect if the vault is later encrypted via `passphrase set`.
- Idle is reset by any `AppEvent::Input`. Timer is implemented as a
  cancel-token + timer thread; on cancellation, the next scheduled wake is
  ignored.
- Locking discards all secret-bearing UI state alongside the vault: any
  open HOTP reveal window is closed and its in-memory code dropped, the
  search query is cleared, and any modal is closed. The clipboard
  auto-clear timer is preserved across lock so that a copy made just
  before lock still gets wiped at its scheduled time, but lock itself
  does not pre-emptively wipe (per DESIGN §6 "only-if-unchanged").

## Clipboard auto-clear (per §6)

- **Off by default.** When `clipboard.clear_enabled = true`, copying a code
  schedules a wipe after `clipboard.clear_secs`.
- The wipe **only fires if the clipboard still holds the value we wrote** —
  we never stomp something the user copied afterwards. Implementation: at
  copy time, capture `(token, value)` and store the latest token in UI
  state; on wake, ignore stale tokens first, then read current clipboard,
  and if it equals `value`, write empty; otherwise no-op.

## Effect errors

Effects update visible state only after the underlying mutation succeeds:

- HOTP `n`: pre-commit save failures (`save_not_committed`) leave the
  in-memory counter and reveal state unchanged (per DESIGN §4.4
  rollback) and surface a status-line error. Durability-unconfirmed
  failures (`save_durability_unconfirmed`) reveal the new code and
  report the committed-but-uncertain status in the status line — the
  user has the new code in hand even though durability is in question.
  All other failures show a status-line error and leave the row hidden.
- Copy: show a status-line error if clipboard write fails; do not schedule
  auto-clear.
- Add / remove / settings saves: keep the modal open with an inline error
  when validation or save fails. Durability-unconfirmed save errors are
  shown as committed-but-uncertain, matching the core error.
- QR clipboard import: no clipboard image, image decode failure, zero
  decoded QRs, and invalid QR payloads all stay in the Add modal with an
  inline error.

## Keybindings (initial v0.1)

| Key       | Action                                                  |
| --------- | ------------------------------------------------------- |
| `↑` `↓`   | Move selection                                          |
| `Enter`   | Copy selected code (TOTP: current; HOTP: visible only)  |
| `n`       | HOTP next-code (advances + reveals 120s)                |
| `a`       | Open Add modal                                          |
| `r`       | Open Remove confirmation                                |
| `/`       | Focus search bar                                        |
| `p`       | Open Passphrase modal                                   |
| `s`       | Open Settings modal                                     |
| `Esc`     | Close modal / clear search                              |
| `q`       | Quit                                                    |

## Tests

Reducer/state-machine logic is pure and tested directly. Rendered frames are
captured with `insta` golden snapshots using `ratatui::backend::TestBackend`.

- **Reducer**: every keybinding maps to the expected state transition.
  Search filter; selection navigation; modal open/close; HOTP `n` triggers a
  `HotpAdvance` effect; effect failures leave visible state unchanged and
  surface inline/status-line errors.
- **Search**: case-insensitive substring against the
  `{issuer}:{label}` match key (matching CLI query resolution in
  DESIGN §5; empty issuer is allowed and the colon is still present in
  the match key) using `str::to_lowercase()` with no Unicode
  normalization; insertion order preserved among matches. The `id:`
  prefix form is CLI-only and is **not** honored by the TUI search.
- **Auto-lock**: timer arms on `Unlocked` + `enabled` + encrypted; resets
  on input; transitions to `Locked` on expiry; **no-op** for plaintext
  vaults (timer never arms). Setting persists across saves. Locking
  discards open HOTP reveal windows, the search query, and any modal;
  a clipboard auto-clear timer scheduled before lock survives lock and
  still fires only-if-unchanged.
- **Clipboard auto-clear**: timer schedules; stale tokens are ignored;
  "only-if-unchanged" honored when an external copy mutates the clipboard
  between copy and wake.
- **Add modal**: manual duplicate collision rejects with existing
  account, and the follow-up "add anyway" confirmation re-submits the
  same input on the duplicate-allowed path so the new entry is appended
  with a fresh ID; clipboard QR import uses `ImportConflict::Skip`,
  reports imported/skipped counts, handles validation warnings, and
  rejects no-image / no-QR / invalid-QR cases inline.
- **Settings modal**: pending edits are buffered until Confirm; `Esc`
  discards them without invoking setters or save; Confirm runs every
  changed setter and persists with one `Vault::save(&Store)`; setter
  validation failure surfaces inline and blocks the save; a save
  failure keeps the modal open with the inline error; Confirm with no
  changes closes without saving.
- **HOTP reveal window**: reveal closes after 120 s; `n` during an open
  reveal advances again (does not no-op).
- **Insta snapshots** for every screen state: empty vault, single TOTP,
  mixed TOTP/HOTP with hidden + revealed rows, search-active, every modal
  (Add / Remove / Passphrase set/change/remove / Settings), unlock screen,
  missing-vault screen, status-line error after rejected copy, `--no-color`
  variants. Error-state snapshots: inline `save_not_committed` and
  `save_durability_unconfirmed` rendered in each mutating modal (Add,
  Remove, Passphrase set/change/remove, Settings); status-line
  `save_durability_unconfirmed` after HOTP `n`; status-line
  `clipboard_write_failed` after a failed copy; unlock screen with
  inline wrong-passphrase error; Add modal with QR-import inline
  errors (no clipboard image, image decode failure, zero decoded QRs,
  invalid QR payload); Add modal with `duplicate_account` and the
  follow-up "add anyway" confirmation; Passphrase modal with
  `confirmation_mismatch` and `zero_length` inline errors.
- **Plaintext vault**: opens directly to list (no unlock screen).
- **Encrypted vault**: opens to unlock screen; wrong passphrase shows
  inline error; correct passphrase advances to list.
- **Missing vault**: opens the missing-vault screen and does not create or
  mutate files.

## Dependencies

`ratatui`, `crossterm`, `tui-input`, `clap` (for arg parsing only),
`arboard`, `directories`, plus `paladin-core`. **No `tokio`.** No
transitive network crates (enforced by workspace `cargo deny`).

Dev-dependencies: `insta` for golden snapshots.

## Implementation checklist

- [ ] Scaffold `paladin-tui` crate, workspace membership, binary entry, and
  SPDX headers.
- [ ] Implement CLI args, vault path resolution, encrypted unlock, and
  plaintext direct-open / missing-vault flows.
- [ ] Implement reducer, event producers, effect execution, and timer tokens.
- [ ] Implement list layout, search, TOTP gauges, HOTP reveal/copy behavior,
  and status-line errors.
- [ ] Implement add / remove / passphrase / settings modals with persistence.
- [ ] Implement clipboard wrapper, QR image import from clipboard bytes, and
  only-if-unchanged auto-clear.
- [ ] Add reducer, search, auto-lock, clipboard, HOTP reveal, and snapshot
  coverage.
- [ ] Verify the `paladin tui` wrapper launches `paladin-tui` successfully.

## Definition of done

- All keybindings + modals from §6 implemented.
- Auto-lock + clipboard-clear are off by default and behave per §6 when
  enabled, including the plaintext-vault no-op.
- Insta snapshots locked for every screen state.
- `paladin tui` (CLI exec wrapper) launches this binary successfully.
- Missing vaults show the non-mutating `paladin init` guidance screen.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
