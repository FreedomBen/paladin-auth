# Implementation Plan 03 — `paladin-tui`

Source of truth: [DESIGN.md](DESIGN.md) §3, §6, §10, §11 (Milestone 5).
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
│   ├── cli.rs             # GlobalArgs (--vault, --no-color)
│   ├── app/
│   │   ├── mod.rs         # App state machine + run loop
│   │   ├── state.rs       # AppState: Locked / Unlocked { vault, ui, modals }
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

## Event loop (per §6)

Single thread runs the reducer; two producer threads feed `mpsc<AppEvent>`:

- **Input thread** — `crossterm::event::read()` in a loop, maps to
  `AppEvent::Input(KeyEvent | ResizeEvent | …)`.
- **Ticker thread** — sleeps 250 ms, emits `AppEvent::Tick(now)`.
- **Side-effect channel** — clipboard auto-clear and auto-lock schedule
  `AppEvent::ClipboardClear { token, value }` / `AppEvent::AutoLock` with
  delayed delivery via timer threads.

The reducer is a pure function over `(state, event) → (state, Vec<Effect>)`
so it is unit-testable without a terminal. Effects are executed by `app::run`.

## Layout (per §6)

```
┌ Paladin ─────────────────────────────────────────────────┐
│ Search: ____________                                     │
├──────────────────────────────────────────────────────────┤
│ ▶ GitHub (ben@…)        123 456   ████████░░  18s        │
│   AWS prod              987 654   ███░░░░░░░   6s        │
│   Backup HOTP (●●●●)    [press n]                        │
├──────────────────────────────────────────────────────────┤
│ [↑↓] move  [enter] copy  [n] next-HOTP  [a] add  [/] find│
└──────────────────────────────────────────────────────────┘
```

- TOTP rows render a live `Gauge` countdown; re-rendered on every 250 ms tick.
- HOTP rows: code is hidden (`●●●●`) until the user presses `n`, which
  calls `Vault::hotp_advance` (advances counter and saves). After a
  120-second reveal window the code returns to the hidden state. `n` always
  advances and re-reveals (it's the "give me the next code" key) — pressing
  `n` again during an open reveal advances to the next counter rather than
  no-op'ing.
- Copying a hidden HOTP row is **rejected** with a status-line message.
  Copying during the reveal window copies the visible code and does not
  advance again.

## Modals (per §6)

- **Add** — manual fields and "scan from clipboard image". Reuses
  `paladin_core::otpauth` + `paladin_core::import::qr_image` + the shared
  account validation path.
- **Remove** — confirmation modal.
- **Passphrase** — three sub-flows mirroring CLI: `set` / `change` /
  `remove`. New passphrases prompted twice and confirmed; mismatch returns
  to the modal with an inline error.
- **Settings** — toggles for `auto_lock.enabled` and
  `clipboard.clear_enabled`, spinners for `auto_lock.timeout_secs` and
  `clipboard.clear_secs`. Persisted via the corresponding `Vault` setters
  (which save atomically through `Store`).

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

## Clipboard auto-clear (per §6)

- **Off by default.** When `clipboard.clear_enabled = true`, copying a code
  schedules a wipe after `clipboard.clear_secs`.
- The wipe **only fires if the clipboard still holds the value we wrote** —
  we never stomp something the user copied afterwards. Implementation: at
  copy time, capture `(token, value)`; on wake, read current clipboard, and
  if it equals `value`, write empty; otherwise no-op.

## Keybindings (initial v0.1)

| Key       | Action                                        |
|-----------|-----------------------------------------------|
| `↑` `↓`   | Move selection                                |
| `Enter`   | Copy selected code (TOTP: current; HOTP: visible only) |
| `n`       | HOTP next-code (advances + reveals 120s)      |
| `a`       | Open Add modal                                |
| `r`       | Open Remove confirmation                      |
| `/`       | Focus search bar                              |
| `p`       | Open Passphrase modal                         |
| `s`       | Open Settings modal                           |
| `Esc`     | Close modal / clear search                    |
| `q`       | Quit                                          |

## Tests

Reducer/state-machine logic is pure and tested directly. Rendered frames are
captured with `insta` golden snapshots using `ratatui::backend::TestBackend`.

- **Reducer**: every keybinding maps to the expected state transition.
  Search filter; selection navigation; modal open/close; HOTP `n` triggers a
  `HotpAdvance` effect.
- **Search**: case-insensitive substring across label / issuer; insertion
  order preserved among matches.
- **Auto-lock**: timer arms on `Unlocked` + `enabled` + encrypted; resets
  on input; transitions to `Locked` on expiry; **no-op** for plaintext
  vaults (timer never arms). Setting persists across saves.
- **Clipboard auto-clear**: timer schedules; "only-if-unchanged" honored
  when an external paste mutates the clipboard between copy and wake.
- **HOTP reveal window**: reveal closes after 120 s; `n` during an open
  reveal advances again (does not no-op).
- **Insta snapshots** for every screen state: empty vault, single TOTP,
  mixed TOTP/HOTP with hidden + revealed rows, search-active, every modal
  (Add / Remove / Passphrase set/change/remove / Settings), unlock screen,
  status-line error after rejected copy, `--no-color` variants.
- **Plaintext vault**: opens directly to list (no unlock screen).
- **Encrypted vault**: opens to unlock screen; wrong passphrase shows
  inline error; correct passphrase advances to list.

## Dependencies

`ratatui`, `crossterm`, `tui-input`, `clap` (for arg parsing only),
`arboard`, plus `paladin-core`. **No `tokio`.** No transitive network
crates (enforced by workspace `cargo deny`).

## Definition of done

- All keybindings + modals from §6 implemented.
- Auto-lock + clipboard-clear are off by default and behave per §6 when
  enabled, including the plaintext-vault no-op.
- Insta snapshots locked for every screen state.
- `paladin tui` (CLI exec wrapper) launches this binary successfully.
- `cargo fmt --check`, `clippy -- -D warnings`, `test --all`, `deny check`,
  `audit` clean.
