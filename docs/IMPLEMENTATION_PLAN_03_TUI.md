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
modal dialogs for add / remove / rename / import / export / qr / passphrase / settings.
Auto-lock and clipboard auto-clear are **opt-in** per `VaultSettings`. In
native/shared-`PATH` installs, the TUI is also reachable via `paladin tui`
which `execvp`s this binary.

Runtime model (§13): plain threads + `mpsc`. **No `tokio`** — local TUIs
don't need async I/O.

## Crate layout

```
crates/paladin-tui/
├── Cargo.toml             # license = "AGPL-3.0-or-later"; declares both [lib] (so integration tests can reach internal modules) and [[bin]] (name = "paladin-tui")
├── src/
│   ├── main.rs            # thin shim that hands off to `lib.rs::run`
│   ├── lib.rs             # public library surface (`run`, `run_with_components`) so integration tests in tests/ can drive the composition without a TTY
│   ├── cli.rs             # clap derive: GlobalArgs (--vault, --no-color; --json rejected at parse time with clap's text diagnostic)
│   ├── app/
│   │   ├── mod.rs         # app submodule namespace; re-exports the reducer / dispatch / effect / render / run surfaces
│   │   ├── state.rs       # AppState variants + vault/store ownership; owns the auto-lock idle deadline and HOTP-reveal window state populated by paladin_core policy modules
│   │   ├── event.rs       # AppEvent enum (Input, Tick, EffectResult, ClipboardClear, AutoLockFired, HotpRevealExpired)
│   │   ├── input.rs       # crossterm event → AppEvent translation
│   │   ├── ticker.rs      # `paladin_core::TICK_INTERVAL_MS` tick thread, sleeps, mpsc producer
│   │   ├── reducer.rs     # pure (state, event) → (state, Vec<Effect>); routes auto_lock / hotp_reveal through paladin_core::policy
│   │   ├── dispatch.rs    # pure event-loop glue: terminal-free inner loop that drives reducer → effect::execute → render closure on each AppEvent
│   │   ├── effect.rs      # Effect executor (the only impure boundary); save-bearing effects mutate Vault through core APIs then post EffectResult back through the mpsc channel
│   │   ├── render.rs      # one-line adapter from `dispatch`'s render closure to `ratatui::Terminal::draw(crate::view::render)`; locked by `render_tests.rs`
│   │   └── run.rs         # production composers: `run_event_loop` (terminal-free, fake-producer-friendly) and `run_with_terminal_guard` (wraps the TerminalGuard around the inner loop)
│   ├── view/              # ratatui rendering surface; each AppState variant routes through one `view::<screen>` sub-module
│   │   ├── mod.rs         # `render` entry: dispatches the current AppState to the correct screen module
│   │   ├── theme.rs       # shared color palette; --no-color / NO_COLOR funnels through here so styled cells degrade to monochrome-but-legible
│   │   ├── unlock.rs      # encrypted-vault passphrase entry screen
│   │   ├── startup_error.rs # non-mutating startup / open error view
│   │   ├── create_vault.rs  # two-step in-app create-vault wizard (ChooseMode → EnterPassphrase | ConfirmPlaintext)
│   │   ├── list.rs        # search + account list (TOTP gauge / HOTP reveal label / Next-code column)
│   │   ├── help.rs        # read-only help overlay, populated from `keybindings::KEYBINDINGS`
│   │   ├── add.rs
│   │   ├── remove.rs
│   │   ├── rename.rs        # label-only shorthand modal (Shift+R); calls Vault::rename inside Vault::mutate_and_save
│   │   ├── edit.rs          # v0.2 multi-field edit modal (Shift+E): label / issuer / icon_hint; calls Vault::edit_account_metadata inside Vault::mutate_and_save
│   │   ├── import.rs        # path + format + on-conflict + (optional) bundle passphrase
│   │   ├── export.rs        # format + path + overwrite + (encrypted) twice-confirmed passphrase
│   │   ├── qr.rs            # v0.2 per-account QR Export modal: warning-ack page → ANSI body + Save-as-PNG / Save-as-SVG sub-flow (read-only — never routes through Vault::mutate_and_save)
│   │   ├── passphrase.rs    # set / change / remove sub-flows
│   │   ├── destroy.rs       # Milestone 10 path-targeted vault wipe modal: warning body via format_destroy_warning → `yes`-literal confirm field → calls paladin_core::destroy_vault (no Vault::mutate_and_save; destroy is the commit). Opens from any AppState via Ctrl+Shift+D and from a footer hint on Locked / StartupError / Missing screens.
│   │   └── settings.rs      # auto_lock + clipboard toggles + timeouts
│   ├── search.rs          # incremental filter over Vault::iter() (§4.7 public surface, yielding &Account in insertion order) using paladin_core::account_matches_search; rows render AccountSummary projections via Account::summary()
│   ├── clipboard.rs       # arboard writer; schedule + only-if-unchanged decisions route through `paladin_core::policy::clipboard_clear::ClipboardClearPolicy`; `test-hooks`-feature dryrun bypass for reducer/effect integration tests
│   ├── keybindings.rs     # `const KEYBINDINGS: &[KeyBindingRow]` — single source of truth for the help overlay (`view::help`) and the future `cargo xtask man` target so the overlay and man page cannot drift
│   ├── terminal.rs        # raw mode / alternate-screen guard; restores terminal on normal exit, startup failure, Ctrl-C, and panic unwind
│   └── prompt.rs          # shared zeroizing passphrase-input widget reused by view::unlock, view::passphrase, view::import (encrypted Paladin bundle), and view::export (twice-confirmed encrypted bundle)
└── tests/
    ├── common/mod.rs       # shared test helpers (tempdirs, fixture builders) — referenced via `mod common;` from every integration test
    ├── reducer_tests.rs    # pure (state, event) → (state, Vec<Effect>) coverage
    ├── dispatch_tests.rs   # terminal-free event-loop glue: reducer → effect::execute → render closure on each AppEvent; quit + channel-disconnect exit paths
    ├── effect_tests.rs     # Effect executor coverage (CreateVault, OpenVault, CopyCode, ClearClipboard, AddFromClipboardQr, …) with the test-hooks dryrun clipboard
    ├── run_tests.rs        # production composer: `run_event_loop` with fake input/ticker spawners drives the channel synchronously without a TTY
    ├── render_tests.rs     # `app::render` adapter is a no-op around `view::render` — regression guard so the closure cannot drift away from the view layer
    ├── view_snapshots.rs   # insta golden frames for every screen + modal via `ratatui::backend::TestBackend`
    ├── search_tests.rs
    ├── auto_lock_tests.rs
    ├── clipboard_tests.rs
    ├── hotp_reveal_tests.rs
    ├── create_vault_tests.rs   # in-app create-vault wizard (ChooseMode / EnterPassphrase / ConfirmPlaintext) reducer + executor coverage
    ├── destroy_tests.rs        # Milestone 10 Destroy modal reducer + executor coverage: Ctrl+Shift+D open from every AppState, yes-confirm gate, DestroyReport routing, error envelope rendering, sensitive-buffer wipe on success
    ├── help_tests.rs           # help-overlay open / close / Esc precedence / keybindings-table parity
    ├── input_tests.rs          # crossterm event → AppEvent translation, including key chords and resize
    ├── ticker_tests.rs         # TICK_INTERVAL_MS producer + monotonic-vs-wall-clock contract
    ├── terminal_tests.rs       # raw-mode / alternate-screen guard rollback on drop / panic
    ├── no_color_tests.rs       # --no-color / NO_COLOR chokepoint via view::theme
    ├── tui_exec_wrapper.rs     # smoke test: real `paladin` CLI binary execs into the real `paladin-tui` binary on a shared-PATH install
    └── thinness.rs             # crate boundary contract: paladin-tui Cargo.toml does not pull in crypto/storage deps that belong to paladin-core
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
3. `VaultStatus::Missing` opens the in-app **create-vault** flow
   (`AppState::CreateVault { path, step, error }`). The flow is a two-
   step wizard:
   - `CreateVaultStep::ChooseMode { selection }` (default
     `CreateVaultMode::Encrypted`): two radio-style options
     (*Encrypted (recommended)* / *Plaintext (insecure)*). `↑` / `↓`
     / `j` / `k` toggle the selection; `Enter` advances; `q` / `Esc`
     quit (no disk writes).
   - Advancing on *Encrypted* moves to
     `CreateVaultStep::EnterPassphrase { passphrase, confirmation,
     focus }` (both [`PassphraseBuffer`]s, `focus` initially
     `Passphrase`). `Tab` and arrows switch focus; `Enter` on
     `Passphrase` moves focus to `Confirmation`; `Enter` on
     `Confirmation` dispatches `Effect::CreateVault { path,
     init: CreateVaultInit::Encrypted(secret) }`. Empty passphrase
     or byte-for-byte mismatch surfaces an inline error, zeroizes
     the failing buffer, and re-focuses it. `Esc` returns to
     ChooseMode (both buffers zeroized).
   - Advancing on *Plaintext* moves to
     `CreateVaultStep::ConfirmPlaintext`, rendering the body of
     `paladin_core::format_plaintext_storage_warning()`. `Enter`
     dispatches `Effect::CreateVault { path, init:
     CreateVaultInit::Plaintext }`; `Esc` returns to ChooseMode.
   - The executor calls `paladin_core::EncryptionOptions::new`
     (defaults-only Argon2id; KDF tuning is a CLI feature), then
     `paladin_core::Store::create(path, init)` and
     `Vault::save(&store)`. On success the state transitions to
     `Unlocked` with an empty account list (the user lands on the
     same screen they would after `paladin init` + relaunch). On
     failure (`unsafe_permissions`, `io_error`, post-write
     `save_not_committed` / `save_durability_unconfirmed`, or an
     `EncryptionOptions::new` validation error) the user stays in
     `CreateVault` with `error: Some(text)` populated (rendered
     using the same `format_unsafe_permissions` helper as
     startup-error) and the typed passphrase buffer zeroized.
   - `Ctrl-C` always quits and zeroizes any in-flight passphrase
     buffers, mirroring the Unlock screen.
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
┌ Paladin ──────────────────────────────────────────────────────────────┐
│ Search: ____________                                                  │
├───────────────────────────────────────────────────────────────────────┤
│ ▶ GitHub (ben@…)        123 456   ████████░░  18s   ↪ 482 913        │
│   AWS prod              987 654   ████░░░░░░   8s   ↪ 391 044        │
│   AWS-HOTP (#42)        ▸ press n to advance                          │
├───────────────────────────────────────────────────────────────────────┤
│ [↑↓] move  [enter] copy  [C] copy-next  [n] next-HOTP  [a] add [/]find│
└───────────────────────────────────────────────────────────────────────┘
```

- TOTP rows render a live `Gauge` countdown; re-rendered on every `paladin_core::TICK_INTERVAL_MS` tick.
- **Next-code column** (TOTP rows only, per DESIGN §6): rendered to the
  right of the seconds-remaining countdown (matching the GTK
  `ColumnView` order) as `↪ NNN NNN` with
  `Style::default().add_modifier(Modifier::DIM)`. Resolved at render
  time via `Vault::totp_next_code(id, now)` so the boundary math
  stays in core; the row holds the resulting `Code` only for the
  duration of the render pass and never copies it into application
  state (the `Code`'s `SecretString` zeroizes on drop at the end of
  `draw_frame`). HOTP rows leave the cell empty — HOTP has no
  time-based "next code." The column reserves a fixed width
  (`" ↪ NNN NNN"` ≈ 11 cells with single-space digit grouping) and
  collapses to zero width when the visible filter contains no TOTP
  rows, mirroring how the gauge column is suppressed in HOTP-only
  states. Render is exercised by an `insta` golden snapshot
  (`tests/snapshots/`) covering mixed-kind, TOTP-only, and HOTP-only
  vaults.
- **Copy-next (`C`)**: pressing `Shift+C` while the list has focus and
  the selected row is TOTP dispatches an `Effect::CopyCode`
  variant scoped to the next-window code (executor calls
  `Vault::totp_next_code(id, now)` instead of `Vault::totp_code`),
  routes through the same `paladin_tui::clipboard::write_text`
  pipeline as `Enter` / `c`, and on success surfaces a status-line
  confirmation of the form `next code copied, valid in 18s` —
  seconds = `period - (now_unix % period)`. Pressing `C` on a HOTP row
  is rejected with the status-line message
  `no next code for HOTP accounts` (no `Effect` dispatched, no
  vault read). The `pending_clipboard_clear` / `ClipboardClearPolicy`
  arming behaviour is identical to `Enter` / `c`; the executor's
  `EffectResult::CopyCode` arm distinguishes "current" vs "next"
  only for the status-line message text. `C` is suppressed (silent
  no-op) when the search bar has focus or any modal is open, matching
  the existing letter-keybind suppression rules.
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
themselves. The startup-error screen is a read-only dead-end and accepts
`Esc` / `q` / `Ctrl-C` to quit (all three behave identically). The unlock
screen accepts character input (passphrase) and `Enter` (submit), and quits
on `Esc` or `Ctrl-C` (`q` is a valid passphrase character, so it is not
bound to quit there). The create-vault flow is multi-step: `ChooseMode`
accepts `Esc` / `q` / `Ctrl-C` to quit; `ConfirmPlaintext` accepts `Enter`
(confirm + create), `Esc` (back to ChooseMode), `Ctrl-C` (quit), and `q`
quits as well since the screen has no text input; `EnterPassphrase` accepts
character input into the focused field, `Tab` / arrows for focus, `Enter`
to advance or submit, `Esc` to return to ChooseMode (zeroizing both
buffers), and `Ctrl-C` to quit (`q` is a valid passphrase character there
and is not bound to quit).

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

Modal-local navigation is consistent across Add / Remove / Rename / Edit /
Import / Export / Passphrase / Settings: `Tab` and `Ctrl-N` move to the next
control, `Shift-Tab` and `Ctrl-P` move to the previous control
(vim insert-mode parity), `Enter` activates the focused
button or the modal's default confirm action, `Space` toggles the focused
checkbox / toggle, `←` /
`→` change segmented selectors, and `↑` / `↓` adjust spinners or move within
multi-line field groups. `Ctrl-N` / `Ctrl-P` are field-navigation
aliases inside modals only; spinner increment / decrement stays bound
to `↑` / `↓`, and they have no effect on a post-success counts panel
(which has no fields to focus and closes only on `Esc`). At the top
level (no modal open) `Ctrl-N` / `Ctrl-P` mean readline-style next /
previous row in the account list, not field cycling — they share the
list-navigation pass-through with `Ctrl-D` / `Ctrl-U` so they work
from both List and Search focus without being consumed by the search
field. Text fields consume printable characters and standard
editing keys. `Esc` cancels the modal and discards pending modal-local edits
unless the modal is showing a post-success counts panel, where `Esc` simply
closes it.

Successful modal outcomes are consistent: manual Add, URI Add, Remove,
Rename, Edit, Export, Passphrase, and Settings close the modal and publish a
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
  `rename` taking only `<new-label>`; deeper edits use the Edit modal
  below (or Remove + Add for OTP-affecting changes). The Rename and
  Edit modals coexist as separate dialogs sharing `Vault::mutate_and_save`
  through distinct mutators (`Vault::rename` for Rename, `Vault::edit_account_metadata`
  for Edit) — the two are independently invokable and the cross-modal
  rejection tests below pin that opening one while the other is open
  is silently rejected.
  Pre-commit save failures (`save_not_committed`) restore the prior label so
  memory matches disk and the modal stays open with the inline error;
  durability-unconfirmed saves leave the new label in memory and
  surface the warning inline. Rename does not handle secret material;
  the label buffer is cleared on submit, cancel, modal close, and
  auto-lock alongside the other modal-local state.
- **Edit** *(v0.2 / DESIGN §6 Milestone 9)* — opened with `Shift+E`
  on the focused account row. Render is independent of `AccountKind`:
  HOTP and TOTP accounts open the same three controls; no counter row
  (or any other OTP-affecting field) is rendered here, and HOTP read-only
  fields are *omitted from the form* (not display-disabled). On modal
  open, focus is pinned to the **Label** row; `Tab` / `Shift+Tab`
  cycle from there. Three focusable controls pre-populated from the
  selected account's `AccountSummary`:
  * *Label* — `tui-input` row, required, trimmed and §4.1
    length-validated *post-submit* (no client-side length clamp; an
    over-long buffer surfaces `validation_error { field: "label",
    reason: "too_long" }` only on submit). Buffer byte-equal to the
    prior label maps to `AccountEdit.label = None` ("leave
    untouched"); any divergence (including same-text-after-retrim)
    maps to `Some(trimmed)`. An all-whitespace label buffer is
    treated identically to an empty buffer after §4.1 trim — the
    projection surfaces `validation_error { field: "label",
    reason: "empty" }` inline beside the row, never `Some("")`.
  * *Issuer* — `tui-input` row, optional. Submit projects the
    buffer onto `AccountEdit.issuer` with **what-you-see-is-what-you-save**
    semantics, applied after §4.1 issuer normalization (trim
    Unicode whitespace; an all-whitespace buffer is therefore
    treated the same as an empty buffer so the user cannot pick
    up surprising validation errors by emptying with spaces
    instead of backspace):
    - normalized-empty buffer AND prior issuer was `None` →
      `None` (leave untouched);
    - normalized-empty buffer AND prior issuer was `Some(_)` →
      `Some(None)` (implicit clear — matches CLI `--no-issuer`);
    - normalized buffer equals the prior issuer → `None`;
    - any other non-empty normalized buffer →
      `Some(Some(normalized))` and flows through `validate_issuer`
      for §4.1 rejection.
    `Ctrl+U` is an inline convenience that **wholesale clears** the
    issuer row buffer in one keystroke regardless of the current
    cursor position (it is not a kill-to-beginning-of-line — the
    entire buffer is replaced with the empty string); it carries
    no separate "explicit-clear marker" — the normalized-empty-
    buffer rules above determine the projection.
  * *Icon hint* — segmented selector (cycled with `←` / `→` per the
    modal-local navigation rules) with four mutually exclusive
    options. The *Leave unchanged* default is unique to Edit; the
    other three options map 1:1 to the three `IconHintInput`
    variants the Add modal's `parse_icon_hint_token` produces, so
    the resulting on-disk `icon_hint` value is reachable through
    either surface:
    1. *Leave unchanged* (default at modal open) →
       `AccountEdit.icon_hint = None`;
    2. *Default from issuer* →
       `Some(IconHintInput::Default)` (re-derives the slug from the
       post-edit issuer via the §4.1 derivation rules);
    3. *No icon* →
       `Some(IconHintInput::Clear)`;
    4. *Slug: <text>* — a sibling `tui-input` row, pre-populated at
       modal open with the prior `icon_hint` slug (or the empty
       string when the prior value was `None`) and kept disabled
       until *Slug:* becomes the active selector option. Submit
       routes through `paladin_core::validate_icon_hint_slug(slug)`
       — a slug-only validator that runs the §4.1 `[a-z0-9_-]+`
       check without the `parse_icon_hint_token` reserved-token
       collapse, so a user who picks *Slug:* and types literal
       `default` or `none` gets a real slug stored rather than
       being silently rerouted to `IconHintInput::Default` /
       `Clear` (those tri-state outcomes are reachable only via
       the dedicated selector options above). Invalid slugs
       surface inline as `validation_error` (`field: "icon_hint"`,
       `reason: "invalid_slug"`); uppercase or out-of-grammar
       input (e.g. `"Acme"`, `"foo bar"`, `"foo.bar"`) surfaces
       `validation_error { field: "icon_hint", reason:
       "invalid_chars" }` — the buffer is **never** auto-lowercased
       or otherwise mutated on the user's behalf, matching the
       §4.7 no-trim/no-mutation contract. A successfully saved
       slug round-trips losslessly into the buffer the next time
       the user opens the modal (invalid input that never reached
       core is discarded on modal close along with the other row
       buffers).
    The selector always defaults to *Leave unchanged* on open so the
    user must affirmatively pick a different mode to mutate
    `icon_hint`; this prevents the pre-fill from silently re-deriving
    a slug for accounts whose prior `icon_hint` was `None`. Toggling
    the selector **to** *Slug:* moves focus into the now-enabled slug
    row in the same reducer step; toggling **away** from *Slug:*
    returns focus to the selector itself, so the user is never left
    focused on a disabled control.

  `Tab` / `Shift+Tab` traverse the focusable controls in document
  order. When the icon-hint selector is on *Leave unchanged* /
  *Default from issuer* / *No icon* the cycle is three stops
  (Label → Issuer → Icon hint); when the selector is on *Slug:*
  the sibling slug `tui-input` row joins the cycle as a fourth
  stop (Label → Issuer → Icon hint → Slug), with wrap-around in
  both directions. Toggling the selector off *Slug:* skips the
  now-disabled slug row on the next traversal and preserves the
  slug buffer's text per the round-trip rule above. `Enter`
  submits, running the assembled `AccountEdit` through
  `validate_account_edit` and surfacing the first failing field's
  typed `validation_error` inline beside its row without closing.
  Before emitting `Effect::EditAccountMetadata`, the reducer calls
  `Vault::find_duplicate_after_edit(id, &edit)` against the live
  `Vault` carried in `AppState::Unlocked` (the same in-memory
  source used for the preceding `validate_account_edit` pre-flight,
  since neither call mutates state — the Add modal puts its
  `Vault::find_duplicate` in the executor because `validate_manual`
  needs to consume the `SecretString` atomically there, a constraint
  the secret-free Edit modal does not share); a hit rejects with
  the inline `duplicate_account` message rendered via
  `format_duplicate_account_message(&existing_summary)` (parity
  with the Add modal's duplicate channel) and the modal stays open
  with row buffers intact. There is no "edit anyway" override:
  DESIGN does not define one for the edit flow, so the user must
  alter the projected `(issuer, label)` tuple (the secret is never
  edited) before the modal will dispatch the effect.
  Successful submit wraps the assembled `AccountEdit` in
  `Vault::mutate_and_save` → `Vault::edit_account_metadata`, bumps
  `updated_at` even when every field equals its prior value (same
  contract as the Rename modal), and posts
  `StatusLine::Confirmation(format!("Edited {}.", summary_display_label(&summary)))`
  on `Ok`, where `summary` is the post-edit `AccountSummary` carried
  by the `EffectResult::EditAccountMetadata` Ok-arm.
  **Status-line lifecycle:** opening the Edit modal does not clear
  the status line; the only close-paths that touch the status line
  are the successful-submit Ok arm (replaces with the confirmation
  above) and the durability-warning arm. `Esc` cancel and
  auto-lock-driven dismissal both leave the status line untouched.
  Because
  `Vault::edit_account_metadata` returns `Result<()>`, the executor
  builds the summary itself with a post-save
  `Vault::get(id).map(Account::summary)` projection and ships it on
  the channel — same shape the Add / Remove channels already use
  for their `summary_display_label`-driven status lines. An
  empty `AccountEdit` (every control projects to `None` per the
  rules above — label byte-equal to prior, issuer either matching
  prior or empty-on-prior-`None`, and icon-hint selector still on
  *Leave unchanged*) is rejected by an **explicit reducer-side**
  empty check (the validator does not reject emptiness; it
  deliberately leaves that to the mutator), matching the core
  mutator's contract. Because the `field: "edit"` error carries
  no per-row attachment, it renders inline in the modal body
  (the same body slot the duplicate-account message uses), not
  beside any individual row.

  **Pre-check order (mirrors the mutator):** the reducer runs
  `[reject-empty, validate_account_edit, find_duplicate_after_edit]`
  in that exact order; the first failure short-circuits and no
  later check runs. **Error-routing map:**

  | Error                                                       | Render slot                                  |
  | ----------------------------------------------------------- | -------------------------------------------- |
  | `validation_error { field: "label" \| "issuer" \| "icon_hint" }` | Inline beside the matching row               |
  | `validation_error { field: "edit", reason: "empty" }`       | Body slot (no per-row attachment)            |
  | `duplicate_account`                                         | Body slot (parity with the Add modal)        |

  OTP-affecting fields (`secret`, `algorithm`, `digits`, `kind`,
  `period`, `counter`) are intentionally absent — the modal
  header footnote redirects users to Remove + Add for those
  changes. Pre-commit save failures restore the pre-edit
  `Account` byte-for-byte (delegated to
  `Vault::mutate_and_save`) and keep the modal open with the
  inline error; durability-unconfirmed saves leave the new state
  in memory and surface the warning inline. No secret material is
  handled — the row buffers are cleared on submit, cancel, modal
  close, and auto-lock alongside the other modal-local state.
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
- **Export** — format selector (plaintext newline-separated
  `otpauth://` URI list — Gnome Authenticator–compatible — or
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
- **QR Export** (v0.2; DESIGN §4.6 / §6) — single-account QR
  modal opened with `Q` (Shift-q) on the focused list row. The
  modal is a small two-page state machine:
  * **Page 1 — Warning ack.** The modal opens on the warning
    body rendered verbatim from
    `paladin_core::format_plaintext_qr_export_warning()` (sourced
    through the same helper the CLI / GUI use), a `[ ]` ack
    `Checkbox` (default off, initial focus), and a `Cancel`
    button. Toggling the checkbox on (Space) immediately
    advances the modal to Page 2; toggling it back off returns
    to Page 1 and drops the Page-2 buffers (matching DESIGN §6
    "on ack, the same modal switches"). Pressing `Cancel` (or
    `Esc`) closes the modal. The ANSI QR is **not** rendered on
    this page so a closing-terminal glimpse cannot expose the
    secret.
  * **Page 2 — QR + save actions.** Mounted only after the user
    toggles the Page-1 ack on. The body renders the Unicode half-block QR
    via `paladin_core::Vault::export_qr_ansi(id)`, with the
    account's `summary_display_label` caption on the line above
    the QR (CLI / GUI parity). Two save buttons sit below the QR:
    `Save as PNG…` and `Save as SVG…`, each routed through the
    matching `Vault::export_qr_png` / `Vault::export_qr_svg` call
    and `paladin_core::write_secret_file_atomic` (0600, tempfile
    / fsync / rename). Both save calls pass
    `QrRenderOptions::default()` — the TUI does not expose
    `module_size_px` editing; users who need to tune PNG/SVG
    pixel sizing reach for the CLI `paladin qr --module-size-px`. The
    save sub-flow prompts inline for a destination path; an
    existing destination triggers an inline overwrite gate
    (parity with the existing Export modal — confirmation
    toggle inside the modal body). On successful write the
    modal body surfaces the resulting `0600` path inline (DESIGN
    §6 "surface the resulting path inline on success") — the
    modal stays open so the user can also save the other
    encoding. The displayed path is the most recent success only
    — a second successful save (e.g. SVG after PNG) replaces the
    PNG path with the SVG path in the inline slot, rather than
    accumulating both. (Reducer state: one
    `last_save_path: Option<PathBuf>` slot, not a per-format
    map.) A `Done` button closes the modal. `Esc` while
    focus is inside the destination-path sub-flow (text field
    or overwrite-gate confirmation) cancels just that sub-flow
    and returns to the Page-2 QR body, zeroizing the typed path
    buffer; `Esc` from the Page-2 root closes the entire modal
    (parity with how the Export modal's `Esc` unwinds its inner
    overwrite gate before closing).
  Read-only contract — the modal **never** routes through
  `Vault::mutate_and_save`, the HOTP counter never advances, and
  `updated_at` is never bumped. Saving never happens until the
  user confirms the destination plus any overwrite gate; the
  ANSI render lives only in the modal body. The PNG /
  SVG / ANSI buffers returned by core are `Zeroizing<Vec<u8>>` /
  `Zeroizing<String>`; the modal holds them only for the duration
  the body is rendered (or the save worker is in flight) and
  drops them on submit / cancel / `Esc` / modal close /
  auto-lock. Toggling the Page-1 ack back off also drops the
  Page-2 buffers and returns the body to Page 1; the buffer
  drop on ack-off matches the GTK `ExportQrDialog` behavior
  (GTK does not auto-advance on ack-on, so the navigation
  diverges, but both surfaces zeroize the rendered bytes the
  moment the user un-acks the warning). Save failures
  (`save_not_committed`, `save_durability_unconfirmed`,
  `io_error`) stay inline in the modal as the existing Export
  modal handles them. `validation_error` (`field: "qr_render"`)
  is also handled inline as a defensive path — the modal hard-pins
  `QrRenderOptions::default()` so `QrRenderOptions::validate`
  never trips, but the `qrcode` encoder can return
  `data_too_long` on a payload past QR version 40 (today's
  `otpauth://` URIs fit comfortably in version 10 with M-level
  ECC). Both validation reasons render inline rather than crashing.
  The modal opens regardless of vault mode (plaintext or
  encrypted) and regardless of OTP kind: TOTP and HOTP rows
  both qualify because §4.6 is read-only, so HOTP rows do not
  need the hidden-code reveal gate that `show` / `copy` use
  (DESIGN §6). QR export does not require the vault to be in
  any particular mode beyond `Unlocked`. The list-focus `Q`
  keybinding is silently no-op'd while any modal is open
  (including the Help overlay) so the modal cannot be opened on
  top of another modal, and is also a silent no-op when the
  filtered set is empty so there is no focused row to render
  (parity with `Enter` on an empty list).
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
- **Destroy** *(Milestone 10; DESIGN §4.3 / §6)* — opened with
  `Ctrl+Shift+D` from any `AppState` (`Missing`, `Locked`,
  `StartupError`, `Unlocked`, and during any open modal — see
  the keybinding precedence note below). The binding is intentionally
  a chord (not a bare letter) so the loudest action in the app cannot
  be triggered by a stray keystroke. The unlock, startup-error, and
  create-vault screens additionally render a footer hint of the form
  `Ctrl+Shift+D delete vault` so the forgot-passphrase user discovers
  the escape hatch without dropping to the shell. The modal body
  renders `paladin_core::format_destroy_warning(path, backup_present)`
  verbatim — the same helper the CLI text mode prints — names the
  primary and `.bak` paths, and exposes one focused field: a
  confirmation `tui-input` that the user must fill with the literal
  `yes` (after Unicode-whitespace trim) to enable the destructive
  action. The two action buttons are *Cancel* (default focus on
  open; `Esc` dismisses) and *Delete vault* (`Enter`, sensitive
  only while the confirmation field reads `yes`; never the default
  focus). On submit the reducer emits an
  `Effect::DestroyVault { path }` that the effect executor runs by
  calling `paladin_core::destroy_vault(path)` on the worker thread,
  then posts an `EffectResult::DestroyVault(DestroyReport)` (or
  the typed error) back through the mpsc channel. The reducer
  treats `destroy_vault` as **the** commit point — there is no
  `Vault::mutate_and_save` wrapper because the operation does not
  open the vault. On success:
  * The held `Vault` and `Store` (if any) are dropped and their
    `Zeroize`-bearing fields wiped per the existing auto-lock
    teardown contract.
  * The reducer wipes every secret-bearing UI buffer in lockstep:
    passphrase fields (unlock, set/change/remove), the URI text
    in Add, the Base32 secret in Add, any pending duplicate /
    add-anyway state, the search query, the HOTP reveal window
    plus its in-memory code, any pending clipboard auto-clear
    value, and the QR modal's rendered ANSI / PNG / SVG buffers.
    The wipe goes through the same zeroizing-buffer routine
    `AppState::Locked` uses on auto-lock so it cannot drift.
  * The reducer transitions to `AppState::Missing` and routes to
    the create-vault flow (same screen `VaultStatus::Missing`
    shows at first launch). A status-line note reads `Vault
    deleted.` when `DestroyReport.backup_deleted == true` or no
    backup was present, and `Vault deleted (backup remained on
    disk).` when an `unlink_backup_file` partial failure left the
    `.bak` behind.
  On `vault_missing` (the on-disk vault disappeared between modal
  open and submit) the modal closes with a status-line `Vault
  already gone.` and the app transitions to `Missing`. On
  `io_error` (`vault_file_is_symlink` / `backup_file_is_symlink` /
  `unlink_vault_file` / `unlink_backup_file` / `fsync_vault_dir`),
  the modal stays open with an inline error label that names the
  failing path and surfaces the partial `DestroyReport`
  (`primary_deleted` / `backup_deleted`) so the user can decide
  whether to retry or quit and drop to a shell. Auto-lock firing
  during the modal's lifetime closes the modal, zeroizes any
  partial confirmation buffer, and locks (or transitions to
  `Missing` if the destroy already committed).
  Keybinding precedence: `Ctrl+Shift+D` is the only chord that
  fires from *any* state — including with another modal open —
  parallel to how `Ctrl+C` is universally quit. When pressed
  while another modal is open, the active modal's pending input
  is zeroized first (so e.g. a passphrase being typed in the
  Unlock modal does not survive), the active modal closes, and
  the Destroy modal opens. Pressing the chord while the Destroy
  modal is already open is a no-op (parity with `?` on the Help
  overlay). The chord is listed in the Help overlay's keybindings
  table sourced from `keybindings::KEYBINDINGS` so the binding,
  scope, and label cannot drift.
  Where the work lives: `paladin-core` owns the unlink + `fsync`
  (`destroy_vault`), the symlink defense-in-depth, the report
  shape (`DestroyReport`), and the warning text
  (`format_destroy_warning`). The TUI owns only: the modal layout,
  the confirmation field, the chord wiring, the `Effect::DestroyVault`
  dispatch, the sensitive-buffer wipe in lockstep with the vault
  drop, and the post-success transition to `Missing` /
  create-vault. The CLI text mode and the GTK `DestroyDialog`
  render the same warning text and same confirmation grammar.
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
create-vault, and startup-error screens do not bind `?`. The
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

## Keybindings

The table below lists every binding for both v0.1 and v0.2 surfaces;
v0.2-only rows are marked inline.

| Key                                | Action                                                                                                |
| ---------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `↑` `↓` / `j` `k`                  | Move selection up / down (vim-style `j` / `k`)                                                        |
| `PgUp` `PgDn` / `Ctrl-B` `Ctrl-F`  | Page up / page down by viewport height (vim-style `Ctrl-B` / `Ctrl-F`)                                |
| `Home` `End` / `gg` `G`            | Jump to first / last row of the filtered set (vim-style `gg` two-press chord and `G`)                 |
| `Ctrl-U` `Ctrl-D`                  | Half-page up / down (vim-style)                                                                       |
| `Ctrl-P` `Ctrl-N`                  | Previous / next row (readline-style mirrors of `↑` / `↓`)                                             |
| `zz`                               | Recenter viewport on selected row (vim-style two-press chord)                                         |
| `Enter`                            | Copy selected code (TOTP: current; HOTP: visible only)                                                |
| `C` (Shift-c)                      | Copy selected row's **next** code (TOTP only; rejected on HOTP with status-line message)              |
| `n`                                | HOTP next-code (advances + reveals `HOTP_REVEAL_SECS`)                                                |
| `a`                                | Open Add modal                                                                                        |
| `r`                                | Open Remove confirmation                                                                              |
| `R`                                | Open Rename modal (Shift+R; `r` stays bound to Remove)                                                |
| `E`                                | Open Edit modal for the focused row (Shift+E; `e` stays bound to Export); v0.2; multi-field label / issuer / icon-hint editor; always enabled on both HOTP and TOTP rows; rejected silently while any other modal is open |
| `i`                                | Open Import modal                                                                                     |
| `e`                                | Open Export modal                                                                                     |
| `Q` (Shift-q)                      | Open QR Export modal for the focused row (v0.2; warning-ack gate, ANSI body, Save-as-PNG / Save-as-SVG); rejected silently while any other modal is open |
| `/`                                | Focus search bar                                                                                      |
| `Tab` `Shift-Tab`                  | Cycle focus between search bar and list (preserves active query when leaving search)                  |
| `Ctrl-N` `Ctrl-P`                  | In modals: next / previous control (aliases for `Tab` / `Shift-Tab`); outside modals: see list-navigation row above |
| `p`                                | Open Passphrase modal                                                                                 |
| `s`                                | Open Settings modal                                                                                   |
| `?`                                | Open Help overlay (lists all keybindings); `Esc` closes                                               |
| `Esc`                              | Close modal / clear search; close Help overlay; clear pending vim chord; quit on unlock, startup-error, and create-vault `ChooseMode`; return to `ChooseMode` from `ConfirmPlaintext` / `EnterPassphrase` (zeroizing buffers) |
| `q`                                | Quit from list, startup-error, and create-vault `ChooseMode` / `ConfirmPlaintext`; text input in text fields (including the create-vault passphrase field)                   |
| `Ctrl-C`                           | Quit (any screen)                                                                                     |
| `Ctrl-Shift-D`                     | Open Destroy modal — path-targeted vault wipe (Milestone 10). Universal binding: fires from `Missing`, `Locked`, `StartupError`, `Unlocked`, and from any open modal (closes the active modal and zeroizes its in-flight input first). Footer hint on the unlock, startup-error, and create-vault screens advertises the binding so the forgot-passphrase escape hatch is discoverable. No bare-letter alternative is offered. |

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
  `PgUp` / `PgDn` / `Ctrl-B` / `Ctrl-F`, `Ctrl-U` / `Ctrl-D`,
  `Ctrl-P` / `Ctrl-N`, and `Home` / `End`.
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
  / `Ctrl-B` / `Ctrl-F` / `Ctrl-D` / `Ctrl-U` / `Ctrl-N` / `Ctrl-P`
  to the list before `tui-input` sees them.
- [x] Bare-letter vim keys (`j`, `k`, `g`, `G`, `z`) are consumed by the
  search field as text input and never trigger chord state from the
  search field.
- [x] Empty filtered set: every list-navigation key including the
  chords is a silent no-op.
- [x] `Ctrl-N` / `Ctrl-P` inside modals advance / retreat focus the
  same as `Tab` / `Shift-Tab` — for every modal variant, symmetry
  with `Tab` / `Shift-Tab` is locked in. At the top level (no modal
  open) the same chords bind to readline-style list navigation
  (mirrors of `↓` / `↑`) rather than to focus cycling, so they
  cannot leak into List ↔ Search focus toggling. *(Add modal
  Manual-mode focus cycle covered by
  `tab_in_add_modal_manual_mode_advances_focus_through_all_fields_with_wrap`
  and its `BackTab` / `Ctrl-N` / `Ctrl-P` siblings; Uri / Qr modes
  treat the same keys as silent no-ops so `manual_focus` stays
  sticky. Top-level list-nav coverage lands in
  `pressing_ctrl_{n,p}_at_top_level_{list,search}_focus_*` plus
  empty-vault / empty-filtered-set / chord-clear / clamp siblings.)*
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
  without scheduling. Executor-level: the `Effect::CopyCode` arm of
  `paladin_tui::app::effect::execute` confirms the live `Unlocked`
  state still owns the carried vault path (silent drop on
  non-`Unlocked` / path-mismatch), resolves the code via
  `Vault::totp_code(id, now)` for TOTP or the live `hotp_reveal`
  slot's `SecretString` for HOTP (defensively re-gated on
  `account_id`), writes through `paladin_tui::clipboard::write_text`,
  samples `Instant::now()` after the write returns, and posts back
  `EffectResult::CopyCode { account_id, result, completed_at }`
  with `Ok(Zeroizing<Vec<u8>>)` carrying the bytes written or
  `Err(())` on `arboard` failure. Asserted by
  `copy_code::execute_copy_code_totp_writes_code_to_clipboard_and_sends_ok`,
  `…_hotp_with_matching_reveal_writes_visible_code_and_sends_ok`,
  `…_clipboard_write_failure_sends_err`, and the four
  silent-drop / dropped-receiver siblings in
  `tests/effect_tests.rs`.)*
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

### Ticker thread (`tests/ticker_tests.rs`)

- [x] Ticker thread emits `AppEvent::Tick { wall_clock, monotonic }`
  events on a `paladin_core::TICK_INTERVAL_MS` cadence, sampling both
  the wall-clock (`SystemTime::now`) and the monotonic clock
  (`Instant::now`) at each tick, and exits on the next iteration after
  the receiver is dropped (channel hangup).
  *(`paladin_tui::app::ticker::spawn(sender)` returns a `JoinHandle<()>`
  for a named OS thread `paladin-tui-ticker`; the thread loop is
  *sleep first, then emit* so a startup tick never races the
  initial render or the auto-lock idle accounting. Asserted by three
  tests in `crates/paladin-tui/tests/ticker_tests.rs`:
  `spawn_emits_tick_events_with_advancing_wall_and_monotonic_clocks`
  consumes two ticks, pins each as `AppEvent::Tick` (not `Input` /
  `EffectResult` / `ClipboardClear`), and asserts the monotonic
  sample advances strictly while the wall-clock gap is at least
  `TICK_INTERVAL_MS - 50 ms` (50 ms of cadence slack so a busy CI
  host whose `thread::sleep` undershoots its interval does not
  flake the assertion); `spawn_thread_exits_when_receiver_is_dropped`
  consumes the first tick, drops the `Receiver`, and watchdogs the
  `JoinHandle::join` from a helper thread that signals over a bounded
  `mpsc` so a regression that fails to terminate on hangup surfaces
  as a `recv_timeout` error rather than a hung suite;
  `spawn_first_tick_is_not_emitted_synchronously` consumes within
  50 ms of spawn and asserts a `RecvTimeoutError::Timeout`, pinning
  the *sleep first, then emit* ordering against a refactor that
  ever inverts it. The thread does not poll any other shutdown
  signal — `Sender::send` failing on a hung-up receiver is the only
  way the ticker learns the reducer has gone away, so the production
  shutdown path is the same on `Effect::Quit`, `Ctrl-C`, and panic
  unwind.)*

### Input thread (`tests/input_tests.rs`)

- [x] Input thread reads `crossterm::event::Event` values in a loop
  and emits each one as `AppEvent::Input { event, at }` with `at`
  sampled from `Instant::now()` after the blocking read returns, then
  exits cleanly on receiver hangup (`Sender::send` failure) and on
  read error (terminal disconnect / `crossterm::event::read` `Err`).
  *(`paladin_tui::app::input::spawn(sender)` is the production entry —
  it wraps `crossterm::event::read` as its read source and returns a
  `JoinHandle<()>` for a named OS thread `paladin-tui-input`. The
  test seam is `paladin_tui::app::input::spawn_with(sender, read)`
  which takes any `FnMut() -> io::Result<crossterm::event::Event> +
  Send + 'static` so the fake reader in
  `crates/paladin-tui/tests/input_tests.rs` can drive the loop
  without a real terminal. Three tests pin the contract:
  `spawn_with_emits_app_event_input_for_each_crossterm_event` feeds
  a `KeyEvent` and a `Resize` through the fake reader, consumes two
  `AppEvent::Input` values off the channel, and pins the carried
  `event` is byte-identical and the `at` instants advance strictly
  between reads (so a regression that ever samples `at` before the
  read returns surfaces here); `spawn_with_thread_exits_when_receiver_is_dropped`
  consumes one event, drops the `Receiver`, signals the fake reader
  to return one more event, and watchdogs the `JoinHandle::join`
  from a helper thread on a bounded `mpsc` so a regression that
  fails to terminate on hangup surfaces as a `recv_timeout` rather
  than a hung suite; `spawn_with_thread_exits_when_read_returns_error`
  feeds an `io::ErrorKind::BrokenPipe` from the fake reader and
  watchdogs the join, pinning the terminal-disconnect shutdown path
  the production loop hits when `crossterm::event::read` returns
  `Err` on a closed terminal. The thread does not poll any other
  shutdown signal — `Sender::send` failure and `read()` `Err` are
  the only ways the loop learns to exit, matching the ticker's
  shutdown shape.)*

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
  `Added <summary_display_label>.` plus a
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

### QR Export modal (`tests/reducer_tests.rs`, v0.2)

The QR Export modal is the v0.2 entry point for DESIGN §4.6 per-account
QR rendering from the TUI. It is read-only — neither the reducer nor
the executor ever calls a mutating `Vault::*` method — so the test
surface here is smaller than Export / Settings / Add. Reducer-slice,
`EffectResult` routing, and snapshot bullets are listed below; the
write-side executor coverage (the `Save as PNG…` / `Save as SVG…`
sub-flows that actually call `Vault::export_qr_png` /
`Vault::export_qr_svg` + `write_secret_file_atomic`) rides with
`tests/effect_tests.rs`'s `execute_qr_export_*` family enumerated
alongside the existing `execute_export_*` family.

- [x] `Q` from list focus opens the modal with the warning-ack page
  active (`QrExportModal::page = WarningAck`, `ack = false`). Pinned
  by `pressing_q_from_list_focus_opens_qr_export_modal_on_warning_ack_page`.
- [x] `Q` from list focus while any other modal is open is a silent
  no-op (`pressing_q_with_*_modal_open_is_silent_no_op` per modal
  variant, mirroring the existing `pressing_a_with_*_modal_open_*`
  family).
  *(Per-modal fan-out lands as
  `pressing_q_with_{add,remove,rename,import,export,passphrase,settings,qr_export}_modal_open_is_silent_no_op`
  in `tests/reducer_tests.rs`, routed through a shared
  [`assert_q_with_modal_open_is_silent_no_op`] helper that asserts
  (a) no effects, (b) the modal variant is preserved (text-field
  modals may consume `Q` as a character into their internal buffer,
  so per-modal field equality is intentionally not asserted — the
  gate's contract is the variant, not the contents). The QR Export
  self re-open guard is opened through the reducer (rather than
  constructed directly) so the account-id wiring matches the
  production opener path; it pins `account_id`, `page`,
  `ack`, and `staged_ansi` byte-identical across the second
  press. A companion
  `pressing_q_with_help_overlay_open_is_silent_no_op` covers the
  read-only Help overlay gate (`*help_open` short-circuit in
  `reduce_unlocked_input`) so `Q` cannot punch through to open the
  QR Export modal while help is up.)*
- [x] `Q` while the search bar is focused is consumed as text input
  by the search field (parity with how `r` / `R` / `i` / `e` / etc.
  are handled from search focus). Pinned by
  `pressing_q_with_search_focus_appends_to_search_query_without_opening_qr_export_modal`.
- [x] `Q` on the unlock, create-vault, and startup-error screens is
  not bound (matches the help-overlay / list-action gating). Pinned
  by `pressing_q_on_{unlock,create_vault,startup_error}_screen_is_silent_no_op`.
  *(Foundation slice covers unlock + startup_error; create_vault
  binding is unreachable because `Q` is not in
  `reduce_create_vault_input`'s match — covered by the existing
  `unrecognized_key_on_create_vault_yields_no_effect` test.)*
- [x] `Q` from list focus with an empty filtered set is a silent
  no-op (no modal opens, no status-line spill). Pinned by
  `pressing_q_with_empty_filtered_set_is_silent_no_op`.
- [x] Pre-ack, the QR body is not rendered — assert that the modal
  body string does not contain the half-block glyph alphabet
  (`'▀'`, `'▄'`, `'█'`) before the ack is checked, even after the
  user opens the modal. Pinned by
  `qr_export_modal_pre_ack_body_does_not_render_qr_glyphs`.
  *(Foundation slice pins this at the state layer with
  `qr_export_modal_pre_ack_body_does_not_stage_qr` — `staged_ansi`
  is `None` pre-ack so the renderer has no glyph source. The
  rendered-frame assertion lands with the insta snapshot
  `qr_export_modal_warning_ack_unchecked`.)*
- [x] Toggling the ack on (Space on the focused checkbox) advances
  the modal to `Page::QrAndActions`; toggling it back off returns
  to `Page::WarningAck` and **drops the rendered ANSI string** from
  modal state. Pinned by
  `qr_export_modal_ack_toggle_off_drops_rendered_qr` and
  `qr_export_modal_ack_toggle_off_returns_to_warning_ack_page`.
  *(Foundation slice consolidates both assertions into
  `qr_export_modal_ack_toggle_off_drops_rendered_qr_and_returns_to_page1`.)*
- [x] The cached ANSI render in modal state
  (`QrExportModal::staged_ansi`, populated on ack-toggle-on)
  byte-matches `paladin_core::Vault::export_qr_ansi(id)` against
  the same fixture vault. The test compares the *stored buffer*,
  not the rendered terminal frame — the modal body also carries
  the `summary_display_label` caption above the QR, so a
  full-body equality would not hold. Frame-level appearance is
  pinned by the insta snapshots below. Pinned by
  `qr_export_modal_rendered_qr_slot_matches_export_qr_ansi_byte_for_byte`.
  *(Foundation slice pins the byte-for-byte equality inside
  `qr_export_modal_ack_toggle_on_advances_to_page2_and_stages_ansi`.)*
- [x] Read-only contract — opening the modal, toggling the ack on
  and off, and `Esc`-closing it leave the HOTP counter and
  `updated_at` byte-identical to the pre-open state. Pinned by
  `qr_export_modal_open_and_close_does_not_advance_hotp_counter`.
  Specifically: seed a vault with one HOTP account at a non-zero
  counter, open the modal, toggle ack on, render the QR, toggle
  ack off, close with `Esc`. After close, `vault.iter()` shows
  the HOTP `counter()` and `updated_at()` unchanged, and the
  on-disk primary file bytes are unchanged.
- [x] The warning body matches
  `paladin_core::format_plaintext_qr_export_warning()` verbatim,
  pinned by `qr_export_modal_warning_text_matches_paladin_core_verbatim`
  (the same fixture-text approach the existing
  `format_plaintext_storage_warning_matches_fixture` and
  `format_plaintext_export_warning_matches_fixture` tests use; CLI /
  TUI / GUI share one source).
- [x] `Save as PNG…` from Page 2 opens the inline destination-path
  sub-flow (modal state moves to a `Save { format: Png, .. }`
  variant); the save effect itself is not dispatched until the
  user presses Confirm with a non-empty path that either does
  not exist or passes the overwrite gate. Empty path on Confirm
  rejects inline (pure reducer check, no effect emitted).
  Existing destination on Confirm flips the modal into the
  inline overwrite gate (rather than dispatching the save
  effect). Pinned by
  `pressing_save_as_png_button_opens_destination_prompt`,
  `qr_export_modal_save_with_empty_destination_path_rejects_inline`,
  and
  `qr_export_modal_save_with_existing_destination_shows_overwrite_gate`.
- [x] Reducer routes a synthetic `EffectResult::QrExport(Err(io_error))`
  (the variant the executor returns when
  `write_secret_file_atomic` fails on a missing parent
  directory, ENOSPC, EACCES, etc.) inline in the modal body and
  leaves the modal open. Pinned by
  `effect_result_qr_export_err_io_error_surfaces_inline_and_keeps_modal_open`.
  (The fs-level production of `io_error` is covered executor-side
  in `tests/effect_tests.rs` by
  `execute_qr_export_png_with_missing_parent_dir_returns_io_error`.)
- [x] Overwrite gate — typing a destination that already exists,
  toggling overwrite ack on, and pressing Confirm writes the file
  through `paladin_core::write_secret_file_atomic`. Bytes match
  what `Vault::export_qr_png` returns; permissions are `0600`.
  (Executor-side coverage in `tests/effect_tests.rs`:
  `execute_qr_export_png_with_overwrite_ack_writes_bytes_matching_export_qr_png_at_0600`.)
- [x] Overwrite gate — destination exists, overwrite ack off, Confirm
  rejects inline with a wording that points at the gate. The
  existing file is byte-unchanged. Pinned by
  `qr_export_modal_save_overwrite_ack_off_rejects_inline_and_leaves_existing_file_unchanged`.
- [x] `Save as SVG…` mirrors the PNG save path through
  `Vault::export_qr_svg` and `write_secret_file_atomic`. The
  resulting file is non-empty UTF-8 starting with `<?xml` / `<svg`.
  (Executor-side coverage in `tests/effect_tests.rs`:
  `execute_qr_export_svg_writes_bytes_matching_export_qr_svg_at_0600`.)
- [x] Inline success-path slot is replace-only — a successful PNG
  save followed by a successful SVG save leaves
  `QrExportModal::last_save_path` set to the SVG path (and vice
  versa); the prior path is not preserved. Pinned by
  `qr_export_modal_second_successful_save_replaces_inline_success_path`.
- [x] Save effect failure routing —
  `PALADIN_FAULT_INJECT=pre_commit` surfaces `save_not_committed`
  inline in the modal body; `=post_commit` surfaces
  `save_durability_unconfirmed`. The modal stays open in both
  cases so the user can retry or cancel. Pinned by
  `effect_result_qr_export_err_save_not_committed_surfaces_inline_and_keeps_modal_open`
  and
  `effect_result_qr_export_err_save_durability_unconfirmed_surfaces_inline_and_keeps_modal_open`.
- [x] `Esc` from Page 1 closes the modal; `Esc` from the Page-2
  root closes the modal *and* drops the rendered ANSI / any
  in-flight PNG / SVG buffers from modal state without
  auto-saving. Pinned by
  `qr_export_modal_esc_drops_rendered_buffers`.
  *(Foundation slice pins both the Page-1 and Page-2 close paths
  with `qr_export_modal_esc_closes_modal`; the rendered-buffer
  drop is structural — closing the modal drops the
  `Modal::QrExport(_)` value and its zeroizing `staged_ansi`
  payload with it. The in-flight PNG / SVG buffer drop lands
  alongside the save sub-flow.)*
- [x] Pressing the Page-1 `Cancel` button (Enter on the focused
  button or click) closes the modal without advancing to Page 2.
  (The ack auto-advances on toggle-on, so the cancel button is
  only reachable while `ack == false` — pressing Tab from the
  unchecked checkbox to focus the button and pressing Enter is
  the canonical path. Pinned by
  `qr_export_modal_page1_cancel_button_closes_modal_without_advance`.)
  *(Foundation slice pins this with
  `qr_export_modal_enter_on_cancel_button_closes_modal`.)*
- [x] Pressing the Page-2 `Done` button (Enter on the focused
  button) closes the modal and drops the rendered ANSI / any
  in-flight PNG / SVG buffers (parity with `Esc` from Page-2
  root). Pinned by
  `qr_export_modal_page2_done_button_closes_modal_and_drops_rendered_buffers`.
  *(Foundation slice pins this with
  `qr_export_modal_enter_on_done_button_closes_modal`.)*
- [x] `Esc` while focus is inside the Page-2 destination-path
  sub-flow (text field or overwrite-gate confirmation) cancels
  only the sub-flow: the modal returns to the Page-2 QR body,
  the typed path buffer is zeroized, and the rendered ANSI body
  survives so the user can re-attempt a save. Pinned by
  `qr_export_modal_esc_in_destination_prompt_cancels_save_subflow_and_preserves_page2`
  and
  `qr_export_modal_esc_in_overwrite_gate_cancels_save_subflow_and_preserves_page2`.
- [x] Auto-lock (encrypted vaults only, per `IdlePolicy::should_arm`)
  with the QR Export modal open drops the modal, the rendered
  ANSI / any in-flight PNG / SVG buffers, **and** the in-memory
  vault, then re-presents the unlock screen. Pinned by
  `auto_lock_with_qr_export_modal_open_drops_modal_and_rendered_buffers`
  in `tests/auto_lock_tests.rs` (the rest of this section lives
  in `tests/reducer_tests.rs`; this bullet rides alongside the
  other modal auto-lock coverage in the auto-lock test file for
  fixture-sharing).
- [x] HOTP account QR export — assert the PNG that the
  `Save as PNG…` worker writes for a HOTP row decodes back through
  `rqrr` (gated behind the existing `qrcode` / `rqrr` dev-dependency
  that the other QR tests use) to an `otpauth://hotp/...&counter=N`
  URI whose `counter` equals the *current* stored counter (i.e. the
  pre-open counter — read-only contract). (TOTP rows decode to
  `otpauth://totp/...` with the matching algorithm / digits / period
  / secret.) `rqrr` decodes images, not the on-screen half-block
  render, so this test exercises the save path; the half-block
  round-trip is asserted at the core layer in `tests/export_qr.rs`
  against the URI string directly. Pinned by
  `qr_export_modal_png_save_for_hotp_row_decodes_to_otpauth_uri_with_current_counter`
  and
  `qr_export_modal_png_save_for_totp_row_decodes_to_otpauth_uri_with_matching_params`
  in `tests/effect_tests.rs`.
- [x] Insta snapshots — render the modal at each state:
  `qr_export_modal_warning_ack_unchecked` (Page 1 on open, ack
  off, Cancel-button reachable via Tab),
  `qr_export_modal_page2_totp` (Page 2 with a TOTP account's QR
  rendered, captured immediately after ack-toggle-on),
  `qr_export_modal_page2_hotp` (Page 2 with a HOTP account),
  `qr_export_modal_save_destination_prompt`,
  `qr_export_modal_save_overwrite_gate`,
  `qr_export_modal_save_succeeded`,
  `qr_export_modal_save_failed_pre_commit`, and
  `qr_export_modal_save_failed_durability_unconfirmed`. Locked
  via `insta::assert_snapshot!` per the existing modal-snapshot
  pattern.
  *(All eight snapshots landed in
  `crates/paladin-tui/tests/view_snapshots.rs` as
  `snapshot_qr_export_modal_*` tests rendering an 80x32
  `TestBackend` so the 72x24 centered modal fits with list-view
  chrome around it. The Page-1 / Page-2 / destination-prompt /
  succeeded / save-failed snapshots drive the reducer (`Q` → Space
  → Enter → typed path → injected `EffectResult::QrExport`); the
  overwrite-gate snapshot patches the `QrSaveSubFlow` slot
  directly to avoid baking the tempdir's random suffix into the
  snapshot — the gate's reducer behavior is locked separately by
  `reducer_tests.rs::qr_export_modal_save_with_existing_destination_shows_overwrite_gate`.)*

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

### Edit modal (`tests/reducer_tests.rs`)

v0.2 (DESIGN §6 Milestone 9). All bullets are red until Phase M
ships in `paladin-core` and the TUI Edit modal lands.

- [x] `Shift+E` on the focused row opens the Edit modal with all
  three controls pre-populated: label buffer = prior label, issuer
  buffer = prior issuer (`None` rendered as empty), icon-hint
  selector defaulted to *Leave unchanged* with the sibling slug
  buffer pre-populated from the prior `icon_hint` slug (empty
  string when the prior value was `None`). The reducer test
  asserts initial focus is on the **Label** row on modal open
  (asserted via the `focus` field on the `EditModal` state).
- [x] Render-independence-from-`AccountKind`: opening Edit on a
  HOTP account produces the same three-control layout as a TOTP
  account, with no counter row and no kind-specific OTP fields.
  Optional companion snapshot
  (`tests/view_snapshots.rs::snapshot_edit_modal_hotp_account`)
  asserts the byte-equal layout against
  `snapshot_edit_modal_default` (the TOTP baseline).
- [x] Issuer pre-population from prior `None`: opening Edit on an
  account whose prior `issuer` is `None` produces an **empty**
  issuer buffer (not the literal string `"None"` and not the
  prior account's label) and the reducer asserts the buffer's
  `len() == 0` on the post-open frame.
- [x] `label_buffer_byte_equal_to_prior_projects_to_none`: with
  the label buffer left untouched (byte-equal to the prior label,
  including identical trailing whitespace), submit projects to
  `AccountEdit.label = None` rather than `Some(prior.clone())`.
  Companion: typing one character then deleting it (so the buffer
  is byte-equal again) also lands on `None`.
- [x] `Tab` / `Shift+Tab` cycle focus across the focusable controls
  in document order. With the icon-hint selector on *Leave
  unchanged* / *Default from issuer* / *No icon* the cycle is three
  stops (Label → Issuer → Icon hint); with the selector on *Slug:*
  the sibling slug `tui-input` row joins as a fourth stop (Label →
  Issuer → Icon hint → Slug). Two reducer tests cover the wrap-
  around in each direction for both cycle lengths, plus a third
  asserts that toggling the selector off *Slug:* on the next
  traversal skips the now-disabled slug row without losing the
  slug buffer's text. `Enter` submits; on any of the four
  modal-close triggers (successful submit, `Esc` cancel, programmatic
  modal close, auto-lock) every modal-local buffer (label, issuer,
  icon-hint slug) and the icon-hint selector are dropped together,
  matching the four-trigger contract pinned in the modal-spec
  section above. `Enter` with a failing pre-check (any of the
  three: explicit reducer-side empty check, `validate_account_edit`,
  or `Vault::find_duplicate_after_edit`) keeps the modal open with
  row buffers and selector intact so the user can revise (covered
  by the empty-edit, validation-error, and duplicate-account
  reducer tests below).
- [x] `Shift+E` while any other modal is open is silently
  rejected — the existing modal stays open, the Edit modal does
  not mount, and no effect is emitted. Mirrors the `Q` QR-Export
  test shape (`shift_q_while_other_modal_open_is_silently_rejected`).
- [x] Cross-modal symmetry between Rename and Edit:
  (a) `Shift+E` pressed while the Rename modal is open is
  silently rejected — the Rename modal stays open with its label
  buffer intact, the Edit modal does not mount, and no effect
  is emitted;
  (b) `Shift+R` pressed while the Edit modal is open is
  silently rejected — the Edit modal stays open with all three
  row buffers and the icon-hint selector intact, the Rename
  modal does not mount, and no effect is emitted. Asserted as
  `shift_e_while_rename_modal_open_is_silently_rejected` and
  `shift_r_while_edit_modal_open_is_silently_rejected`.
- [x] Per-field text editing routes through the shared
  `apply_modal_text_edit` text-edit helper (printable-`Char` append
  + `Backspace` pop over the row's `String` buffer, mirroring the
  Rename modal's buffer model rather than the `tui-input` widget);
  typing into a row clears the modal's inline error. `←` / `→` on
  the icon-hint selector cycles its four options without affecting
  the sibling slug buffer.
  *(`edit_modal_typing_routes_to_focused_label_row` /
  `…_issuer_row` / `…_slug_row`,
  `edit_modal_typing_clears_inline_error`,
  `edit_modal_arrow_keys_cycle_selector_without_touching_slug_buffer`.)*
- [x] Typing in the slug row while the selector is on *Leave
  unchanged* / *Default from issuer* / *No icon* (i.e. the row
  is disabled and not focusable) is a **no-op**: the slug buffer
  remains byte-identical to its pre-keystroke value, no inline
  error fires, and no effect is emitted. Asserted across all
  three disabled-selector positions to guard against accidental
  buffer mutation when focus state leaks.
  *(`edit_modal_typing_in_disabled_slug_row_is_noop` loops the
  three disabled selector positions.)*
- [x] Submit with at least one control diverging from its prior
  value emits `Effect::EditAccountMetadata { path, account_id,
  edit: AccountEdit }` carrying only the changed fields populated;
  unchanged controls map to `None`.
- [x] Pre-submit duplicate check (reducer side): when the projected
  `AccountEdit` would land the focused account on the same
  `(secret, issuer, label)` tuple as another account in the vault,
  the reducer surfaces the inline `duplicate_account` message
  rendered through `format_duplicate_account_message(&existing_summary)`
  and emits no effect; the modal stays open with row buffers and
  the icon-hint selector intact so the user can revise. The
  reducer test snapshots all three row buffers (label, issuer,
  icon-hint slug) and the selector option **byte-identically**
  pre- and post-duplicate rejection — any divergence is a
  regression.
  Companion reducer tests cover both projection sources (label
  divergence vs issuer divergence) and assert that an unchanged
  self-comparison never fires (per
  `Vault::find_duplicate_after_edit` skipping `id`).
- [x] No-edit-anyway regression guard: with the modal in the
  duplicate-rejected state, the reducer is fed every plausible
  "allow"-coded key event (`A`, `Shift+A`, `Ctrl+A`,
  `Alt+Enter`, the `'y'` / `'Y'` confirm keys, and any other
  key the Add modal's `--allow-duplicate` toast surfaces under
  CLI) and the test asserts each one is a **no-op** — no
  `Effect::EditAccountMetadata` is emitted, the
  `duplicate_account` body message remains rendered, and the
  row buffers stay byte-identical. There is no edit-anyway
  override.
- [x] Pre-submit duplicate check (executor side): an executor-side
  test in `tests/effect_tests.rs` exercises the live
  `Vault::find_duplicate_after_edit` wiring against a fixture vault
  that contains a colliding sibling account, asserts the Effect is
  short-circuited before `Vault::mutate_and_save`, and asserts the
  on-disk vault is byte-identical before and after the rejected
  edit. The test also asserts via the `PALADIN_FAULT_INJECT`
  sink (the same call-counting hook the Add / Rename executor
  tests already use) that **zero** `Vault::mutate_and_save`
  invocations occurred during the rejected effect — pinning the
  short-circuit at the pre-flight boundary, not at the mutator
  re-validation boundary.
- [x] `EffectResult::EditAccountMetadata` Ok-arm: when the executor
  reports success, the reducer closes the Edit modal and publishes
  `StatusLine::Confirmation(format!("Edited {}.", summary_display_label(&summary)))`
  against the post-edit `AccountSummary` carried in the Ok payload
  (built by the executor via a post-save `Vault::get(id).map(Account::summary)`
  projection). Asserted by
  `effect_result_edit_ok_closes_modal_with_status_line_confirmation`,
  matching the Add (`effect_result_add_ok_sets_status_line_confirmation_with_display_label`)
  and Remove status-line shape. A companion snapshot
  `tests/view_snapshots.rs::snapshot_edit_modal_status_line_confirmation`
  pins the post-close list-view frame with the confirmation text
  visible in the status line.
- [x] Empty-edit submit (label buffer byte-equal to prior label,
  issuer buffer projects to `None` per the WYSIWYS rules, icon-hint
  selector still on *Leave unchanged*) surfaces the inline
  `validation_error` (`field: "edit"`, `reason: "empty"`) via the
  reducer's **explicit empty check** (the validator does not
  reject emptiness; the reducer mirrors the mutator-side guard),
  rendered in the modal body slot, without emitting an effect.
- [x] Whitespace-only label buffer surfaces the inline
  `validation_error { field: "label", reason: "empty" }` beside
  the label row (post-§4.1-trim the buffer is empty, so the
  required-field check fires); the test exercises both a
  pure-ASCII-space buffer (`"   "`) and a mix of Unicode
  whitespace (`"\u{00A0}\u{2003}\t"`) to lock the trim semantics.
  *(`edit_modal_whitespace_only_label_surfaces_label_empty_validation_error`.)*
- [x] Pre-check ordering: with a draft that would fail all three
  checks (empty `AccountEdit`, invalid icon-hint slug under
  *Slug:*, and a duplicate-bearing label/issuer projection), the
  reducer surfaces **only** the first failure (`field: "edit"`,
  `reason: "empty"`) and never invokes
  `Vault::find_duplicate_after_edit`. Two follow-up tests reuse
  the same fixture: dropping the empty trigger surfaces only the
  icon-hint `validation_error`; dropping both empty and slug
  triggers surfaces only the `duplicate_account` body message.
  Pins the locked `[reject-empty, validate_account_edit,
  find_duplicate_after_edit]` order from the modal spec.
- [x] Label-only submit emits `Effect::EditAccountMetadata` with
  `AccountEdit { label: Some(trimmed), issuer: None, icon_hint:
  None }`. A companion executor-side test (rename + edit fixture
  using the same starting `Account` and identical post-edit label)
  asserts both surfaces produce *equivalent post-execute vault
  state* — same on-disk label, same `updated_at` bump, same
  rollback behavior on `save_not_committed` — verifying the two
  surfaces share one mutation path (`Vault::edit_account_metadata`)
  even though they emit distinct Effect variants.
- [x] Issuer WYSIWYS projection — covered by five reducer tests:
  empty buffer with prior `None` → `None`; empty buffer with prior
  `Some(_)` → `Some(None)`; whitespace-only buffer with prior
  `Some(_)` → `Some(None)` (proves an all-whitespace buffer
  collapses to the same implicit-clear outcome as the empty
  buffer after §4.1 normalization); buffer byte-equal to
  normalized prior → `None`; non-empty divergent buffer →
  `Some(Some(normalized))`. A sixth test asserts `Ctrl+U` on the
  issuer row empties the buffer in one keystroke and that the
  projection then follows the same rules (i.e. `Ctrl+U` over a
  prior `Some(_)` lands on `Some(None)`).
  *(`edit_modal_issuer_empty_buffer_prior_none_projects_none`,
  `edit_modal_issuer_some_to_none_projects_clear`,
  `edit_modal_issuer_whitespace_buffer_prior_some_projects_clear`,
  `edit_modal_issuer_byte_equal_prior_projects_none`,
  `edit_modal_issuer_divergent_buffer_projects_some_some`,
  `edit_modal_ctrl_u_on_issuer_row_clears_buffer_and_projects_clear`.
  `Ctrl-U` is routed to the Edit modal via the new
  `is_modal_clear_line` dispatch gate and applied by
  `apply_modal_text_edit`.)*
- [ ] Icon-hint selector — four reducer tests, one per option:
  *Leave unchanged* → `AccountEdit.icon_hint = None`;
  *Default from issuer* → `Some(IconHintInput::Default)`;
  *No icon* → `Some(IconHintInput::Clear)`;
  *Slug: <text>* with a valid slug → `Some(IconHintInput::Slug(...))`
  (routed through `paladin_core::validate_icon_hint_slug`, not
  `parse_icon_hint_token`). A fifth test asserts an invalid slug
  under *Slug:* surfaces the inline `validation_error`
  (`field: "icon_hint"`, `reason: "invalid_slug"`) and emits no
  effect. A sixth test asserts that switching the selector away
  from *Slug:* and back preserves the slug buffer's text (so the
  user does not lose typed input by toggling modes). A seventh
  test pins the slug-only semantics: with the selector on *Slug:*
  and the buffer containing literal `default` or `none`, submit
  emits `Some(IconHintInput::Slug("default"))` /
  `Some(IconHintInput::Slug("none"))` rather than collapsing to
  `Default` / `Clear` — proving the reserved-token grammar of
  `parse_icon_hint_token` does not leak into this row. An eighth
  test pins the uppercase / out-of-grammar policy: with the
  selector on *Slug:* and the buffer containing `"Acme"`,
  `"foo bar"`, or `"foo.bar"`, submit surfaces
  `validation_error { field: "icon_hint", reason:
  "invalid_chars" }` inline and emits no effect — the buffer is
  byte-identical before and after the rejected submit (no
  auto-lowercasing, no character stripping), pinning the §4.7
  no-mutation contract.
- [ ] Opening Edit on an account whose prior `icon_hint` is `None`
  with a non-empty issuer, then pressing `Enter` without touching
  the selector, emits an effect whose `AccountEdit.icon_hint`
  equals `None` — proving the modal does **not** silently
  re-derive a slug for the "leave untouched" path. (Regression
  guard against the prior text-row design.)
- [ ] Same-as-prior submit on at least one field still bumps
  `updated_at` (matches the core mutator's no-op-but-non-empty
  contract); covered by an executor-side test that asserts the
  post-edit `Account::updated_at` strictly exceeds the pre-edit
  value.
- [ ] Icon-hint same-as-prior edge case: opening Edit on an
  account whose prior `icon_hint` is a slug already derived from
  the current issuer (e.g. prior `Some("acme")` with issuer
  `Some("Acme")`), then picking *Default from issuer* without
  touching any other control, emits an effect carrying
  `AccountEdit.icon_hint = Some(IconHintInput::Default)` and the
  executor-side companion asserts the post-edit
  `Account.icon_hint` remains `Some("acme")` while `updated_at`
  still bumps. Proves the *Some-projection but identical
  post-edit state* boundary holds for `icon_hint` specifically,
  parallel to the label / issuer same-as-prior cases above.
- [ ] Icon-hint prior-differs-from-derived edge case (symmetric
  to the above): opening Edit on an account whose prior
  `icon_hint` is a slug that does **not** match the issuer's
  derived default (e.g. prior `Some("legacy-co")` with issuer
  `Some("Acme")` whose derived default is `"acme"`), then
  picking *Default from issuer* without touching any other
  control, emits an effect carrying
  `AccountEdit.icon_hint = Some(IconHintInput::Default)` and the
  executor-side companion asserts the post-edit
  `Account.icon_hint` is now `Some("acme")` (the on-disk slug
  **changed**) while `updated_at` bumps. Pins the symmetric
  side of the *Some-projection* contract: *Default from issuer*
  always re-derives, even when the prior slug was user-typed.
- [x] Pre-commit `save_not_committed` restores the pre-edit
  account byte-for-byte and keeps the modal open with the inline
  error; the draft is preserved for retry. (Mirrors the existing
  Rename rollback test shape.)
- [ ] `save_durability_unconfirmed` leaves the new account state
  in memory and surfaces the warning. (Mirrors the existing
  Rename durability test shape.)
- [x] Off-`Unlocked` / mismatched-path / stale-modal
  `EffectResult::EditAccountMetadata` deliveries are silently
  discarded, matching the rename test shape. Three separate
  reducer-test arms enumerate the branches inline:
  (a) the app is currently in `AppState::Locked` or
  `AppState::StartupError` (off-`Unlocked`);
  (b) the result's `path` does not match the live vault's path
  (mismatched-path, e.g. unlock-then-relock-different-vault
  race);
  (c) the modal stack no longer carries `Modal::Edit` (the user
  closed it before the executor finished, or another modal
  pushed on top — though the latter cannot happen given
  single-modal stack semantics, the arm still asserts
  graceful-discard for forward compat).
- [x] Auto-lock with the Edit modal open drops the modal and
  every modal-local buffer (label, issuer, icon-hint slug) and
  resets the selector to *Leave unchanged* before re-presenting
  the unlock screen. The dismissal is **silent**: no toast
  fires, no status-line message is posted, and no other user-
  visible feedback surfaces — matching Add and Rename auto-lock
  behavior. Pinned by
  `auto_lock_with_edit_modal_open_drops_modal_and_buffers` in
  `tests/auto_lock_tests.rs`, matching the QR Export auto-lock
  test shape.
- [x] `?` from the list focus opens the help overlay including
  the new `Shift+E` row; the `keybindings::KEYBINDINGS` table is
  the single source so the overlay cannot drift from the
  bindings. Covered by re-locking the existing
  `snapshot_help_overlay` insta fixture with the `TestBackend`
  height bumped from **32 to 33 rows** (the post-`Shift+Q`
  baseline gains exactly one row for the new `Shift+E`
  binding), the same way the QR Export `Q` row was added.
- [x] Snapshot test for the Edit modal default layout
  (`tests/view_snapshots.rs::snapshot_edit_modal_default`),
  matching the Rename snapshot conventions (centered region,
  three labeled controls, footer hint line). The icon-hint
  selector renders with `▶ Leave unchanged ◀` active markers
  parallel to other segmented selectors in this plan.
  **Accessibility note:** the `▶` / `◀` active markers are
  character-only (no color or style differentiation) so the
  modal renders identically under `NO_COLOR`, monochrome
  terminals, and high-contrast color schemes. This is
  intentional — the selector's active option is conveyed by
  glyph, never by color alone, satisfying the §13 contrast/
  color-independence rule for the TUI surface.
- [ ] **No save-in-flight snapshot needed:** TUI save is
  reducer-synchronous (the `Effect::EditAccountMetadata` round-
  trip completes within the executor's single
  `Vault::mutate_and_save` call before the next reducer arm
  runs, with no intermediate "saving…" frame rendered). This
  is documented here in lieu of a
  `snapshot_edit_modal_save_in_flight` fixture; if a future
  refactor introduces an async save path, this bullet flips to
  a real snapshot.
- [ ] Snapshot test for the validation-error variant
  (`tests/view_snapshots.rs::snapshot_edit_modal_validation_error`)
  with an invalid icon-hint slug entered under *Slug:* so the
  inline `validation_error` (`field: "icon_hint"`,
  `reason: "invalid_slug"`) text renders beside the selector.
- [ ] Snapshot test for the durability-warning variant
  (`tests/view_snapshots.rs::snapshot_edit_modal_durability_warning`)
  with `EffectResult::EditAccountMetadata`
  `Err(SaveDurabilityUnconfirmed)` injected so the inline warning
  text renders, mirroring the Rename durability snapshot.
- [ ] Snapshot test for the *Slug:* mode active
  (`tests/view_snapshots.rs::snapshot_edit_modal_icon_hint_slug_mode`)
  so the slug input row is captured as enabled and focused,
  visually distinguishing it from the disabled state under the
  other three selector options.
- [x] Snapshot test for the duplicate-account variant
  (`tests/view_snapshots.rs::snapshot_edit_modal_duplicate_account`)
  with the pre-submit `Vault::find_duplicate_after_edit` check
  rejecting the projected edit, so the inline
  `format_duplicate_account_message(&existing_summary)` text
  renders in the modal body parallel to the Add modal's
  `snapshot_add_modal_duplicate_account` fixture.

### Destroy modal (`tests/destroy_tests.rs`, Milestone 10)

Reducer + executor coverage for the path-targeted vault wipe.
Each test sets up an `AppState`, drives the
`Ctrl-Shift-D` chord (and follow-up confirmation input), and
asserts the resulting state, effect dispatch (or absence of one),
and any sensitive-buffer wipes. Where the executor is invoked,
the test uses a real on-disk vault fixture in a temp dir and a
core `paladin_core::destroy_vault` call (no mocks) so the unlink
+ `fsync` semantics are end-to-end. Snapshot bullets live in
`tests/view_snapshots.rs` and are listed under the
implementation-checklist bullet above.

- [ ] `Ctrl-Shift-D` from `Unlocked` with no modal open transitions
  to `Modal::Destroy` with the confirmation buffer empty, the
  focused action defaulting to *Cancel*, `backup_present` correctly
  set from the on-disk `.bak` probe, and the warning body sourced
  via `paladin_core::format_destroy_warning(path, backup_present)`.
- [ ] `Ctrl-Shift-D` from `Locked` opens the Destroy modal without
  unlocking the vault. The held passphrase buffer (if any) is
  zeroized before the modal opens.
- [ ] `Ctrl-Shift-D` from `StartupError` opens the Destroy modal
  even though the vault failed to open (e.g. corrupted header,
  unsafe perms). The error state stays in place under the modal
  so a cancel returns the user to the same startup-error view.
- [ ] `Ctrl-Shift-D` from `Missing` create-vault flow opens the
  Destroy modal. Submitting the destroy against an absent primary
  routes through the `vault_missing` branch (the more common case
  here is that the user is on Missing because they wanted to
  destroy + recreate, and the chord on Missing is a no-op-with-
  guidance — see the `vault_missing` test below).
- [ ] `Ctrl-Shift-D` while another modal is open (Add, Edit,
  Passphrase, etc.) zeroizes the active modal's in-flight
  secret-bearing buffers, closes the active modal, and opens the
  Destroy modal. Asserted for the Passphrase modal (passphrase
  buffer zeroized), the Add modal (Base32 secret and URI buffers
  zeroized), and the Unlock screen's passphrase entry.
- [ ] `Ctrl-Shift-D` while the Destroy modal is already open is a
  silent no-op (the modal state is unchanged; no effect is emitted).
- [ ] The confirmation field disables the *Delete vault* action
  until it reads exactly `yes` after Unicode-whitespace trim.
  Partial input (`y`, `ye`, `yes ` with trailing whitespace) is
  trimmed and compared; the action becomes sensitive only on
  byte-equal `yes`.
- [ ] `Esc` (or focusing *Cancel* + `Enter`) closes the modal,
  zeroizes the confirmation buffer, and returns to the caller
  state.
- [ ] Submit (`Enter` on *Delete vault* with confirmation `yes`)
  emits `Effect::DestroyVault { path }` with the resolved primary
  path. No other state mutates until the executor result returns.
- [ ] Executor: `EffectResult::DestroyVault(Ok(DestroyReport {
  primary_deleted: true, backup_deleted: true }))` drops the
  held `(Vault, Store)`, zeroizes every sensitive UI buffer
  (passphrase, URI, manual secret, pending duplicate state,
  search query, HOTP reveal + in-memory code, pending clipboard
  auto-clear value, QR render bytes), transitions to
  `AppState::Missing` + create-vault `ChooseMode`, and emits
  status-line `Vault deleted.`.
- [ ] Executor: `Ok(DestroyReport { primary_deleted: true,
  backup_deleted: false })` (no `.bak` on disk at probe time)
  transitions identically but emits status-line
  `Vault deleted (backup remained on disk).`. *(The wording
  branches off `backup_deleted == false` regardless of the
  reason; both "no backup at probe time" and "backup-unlink
  failed" map to the same status line, mirroring the CLI.)*
- [ ] Executor: `Err(vault_missing)` (the on-disk vault
  disappeared between modal open and submit) closes the modal,
  drops any held vault, emits status-line `Vault already gone.`,
  and transitions to `Missing` + create-vault.
- [ ] Executor: `Err(io_error { operation: "vault_file_is_symlink",
  path })` keeps the modal open with an inline error label that
  names the failing path. The on-disk primary (the symlink) is
  byte-identical after the call.
- [ ] Executor: `Err(io_error { operation: "backup_file_is_symlink",
  path })` keeps the modal open with the named-path inline error.
  Neither file is unlinked.
- [ ] Executor: `Err(io_error { operation: "unlink_backup_file",
  path, primary_deleted: true, backup_deleted: false })` keeps
  the modal open with an inline error reading
  `Primary deleted; backup unlink failed:` + the path. The
  reducer does **not** transition to `Missing` on this
  partial-failure path (the user may want to retry or quit and
  inspect the backup); a follow-up bullet asserts the user can
  close the modal manually and the app stays on the same screen
  it opened from. *(Implementation note: the held `Vault` /
  `Store` should be dropped here because the primary is gone;
  the reducer transitions to a `StartupError` analog or to
  `Missing` with a sticky inline note. The exact branch is left
  to the implementation but the test pins the observable: no
  open vault, modal open, inline error visible.)*
- [ ] Executor: `Err(io_error { operation: "fsync_vault_dir",
  path, primary_deleted: true, backup_deleted: <bool> })` keeps
  the modal open with an inline error reading
  `Vault unlinked but durability unconfirmed:` + the path.
  Same drop-vault behavior as the backup-unlink failure since
  the primary is unlinked.
- [ ] Auto-lock firing while the Destroy modal is open and no
  effect has dispatched: the confirmation buffer is zeroized,
  the modal closes, and the app locks (or transitions to
  `Missing` if the vault is plaintext / already locked /
  startup-errored).
- [ ] Auto-lock firing after the destroy effect has dispatched
  but before its result returns: the result is processed
  normally (the channel is not torn down); the destroy success
  branch transitions to `Missing` and the auto-lock idle deadline
  is reset because there is no longer a vault to lock.
- [ ] The Destroy modal never emits a `Vault::mutate_and_save`
  effect. Pinpoints the design contract that `destroy_vault` is
  the commit point — verified by an effect-emission audit on the
  reducer arms reachable from `Modal::Destroy`.
- [ ] HOTP counters never advance across the modal lifecycle.
  A fixture vault with one HOTP account at counter 42 has its
  primary unlinked through the modal; before the destroy, the
  in-memory counter is still 42; after the destroy the on-disk
  file is absent. (Belt-and-braces guard that the destroy path
  does not accidentally trigger a save through `mutate_and_save`.)
- [ ] `Ctrl-Shift-D` is listed in the help overlay under the
  universal scope; `tests/help_tests.rs` asserts the row is
  present in `KEYBINDINGS` and that the overlay snapshot picks
  up the new entry.
- [ ] The unlock, startup-error, and create-vault screens render
  the footer hint `Ctrl+Shift+D delete vault` sourced from the
  shared `keybindings::KEYBINDINGS` row's label; the list and
  modal screens do not render the footer hint. Snapshot tests
  (`snapshot_unlock_footer_hint`,
  `snapshot_startup_error_footer_hint`) pin the placement.

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
- [ ] Edit modal *(v0.2)*: `save_not_committed` restores the
  pre-edit `Account` byte-for-byte (asserted via
  `Vault::get(id)` against the pre-attempt snapshot) and keeps
  the modal open with the inline `save_not_committed` wording;
  `save_durability_unconfirmed` leaves the post-edit state in
  memory while surfacing the `durability` warning. Bullets live
  under the Edit modal reducer-tests section above
  (`effect_result_edit_save_not_committed_*` /
  `effect_result_edit_save_durability_unconfirmed_*`) — this
  entry is the rollup parity bullet so the dedicated rollback
  rollup matches the per-modal sections of Add / Remove / Rename.

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
- [x] Missing vault opens the in-app create-vault flow
  (`AppState::CreateVault { path, step: ChooseMode { selection:
  Encrypted }, error: None }`) and does not create or mutate files
  until the user confirms in the final step. Reducer drives the
  full state machine:
  - ChooseMode selection toggles between `Encrypted` and `Plaintext`
    via `↑` / `↓` / `j` / `k`, `Enter` advances to
    `EnterPassphrase` on Encrypted or `ConfirmPlaintext` on
    Plaintext, `q` / `Esc` quit, `Ctrl-C` quits.
  - ConfirmPlaintext: `Enter` dispatches `Effect::CreateVault {
    init: CreateVaultInit::Plaintext }`, `Esc` returns to
    ChooseMode (selection preserved at Plaintext), `q` / `Ctrl-C`
    quit.
  - EnterPassphrase: typed chars append to the focused buffer,
    `Tab` / arrows switch focus, `Backspace` deletes from the
    focused buffer, `Enter` on `Passphrase` moves focus to
    `Confirmation`, `Enter` on `Confirmation` validates that
    `passphrase.as_str() == confirmation.as_str()` and dispatches
    `Effect::CreateVault { init: CreateVaultInit::Encrypted(...) }`
    on match. Empty passphrase or mismatch sets `error: Some(...)`
    and zeroizes the failing buffer; `Esc` returns to ChooseMode
    with both buffers zeroized; `Ctrl-C` quits and zeroizes.
- [x] `Effect::CreateVault` executor calls
  `paladin_core::EncryptionOptions::new` (defaults-only Argon2id;
  encrypted only), then `paladin_core::Store::create(path, init)`
  followed by `Vault::save(&store)`. On success transitions to
  `AppState::Unlocked` with an empty account list, the same
  `Vault` + `Store` handles a `paladin init` would produce, and
  the standard idle-deadline / clipboard / search / modal /
  HOTP-reveal initial slots. On failure (`EncryptionOptions::new`
  validation, `Store::create`, or `Vault::save`) the state stays
  `CreateVault` with `error: Some(text)` populated and the typed
  passphrase buffer zeroized.
- [x] `format_unsafe_permissions` is honored for `unsafe_permissions`
  errors surfaced from `Vault::save` in the create-vault flow,
  matching the startup-error screen's behavior.
- [x] Vault-path resolution failures from `default_vault_path` open
  the non-mutating startup-error screen and do not create or mutate
  files.
  *(`crates/paladin-tui/src/app/state.rs::build_initial_state` now
  delegates to a sibling `build_initial_state_with_resolver(vault,
  resolver)` that accepts an injectable resolver
  (`FnOnce() -> paladin_core::Result<PathBuf>`); the production entry
  point wires `paladin_core::default_vault_path` as the resolver.
  `build_initial_state_resolver_failure_yields_startup_error_with_no_path_and_no_file_mutation`
  in `tests/reducer_tests.rs` drives the resolver-failure branch by
  passing a closure that returns the same `io_error` shape
  `default_vault_path` produces when `ProjectDirs::from` returns
  `None` — the test asserts the returned `AppState::StartupError`
  carries `path: None` and the verbatim rendered message, and reads
  `test_tempdir()` before / after to lock in the no-file-creation /
  no-file-mutation guarantee. A companion
  `build_initial_state_resolver_skipped_when_vault_override_supplied`
  test pins the override-vs-resolver precedence by passing a
  `panic!`ing resolver alongside a `Some(path)` override.)*
- [x] Non-`decrypt_failed` errors from `inspect` / `open` (including
  `unsafe_permissions`) open the non-mutating startup-error screen
  and do not create or mutate files.
- [x] `unsafe_permissions` rendering uses the `Some(text)` from
  `format_unsafe_permissions` verbatim.

### Next-code column (`tests/reducer_tests.rs`, `tests/effect_tests.rs`, `tests/snapshots/`)

Coverage for the §6 "Next code column" feature. Boundary math lives in
`Vault::totp_next_code`; the TUI is responsible for rendering the
dim-styled `↪ NNN NNN` cell, dispatching the `C` keybind, and
producing the `next code copied, valid in Xs` status-line message.

- [x] `C` on the list with a selected TOTP row dispatches the
  `Effect::CopyNextCode` variant; reducer leaves
  `pending_clipboard_clear` untouched until the executor reports
  `Ok`. *(`pressing_shift_c_with_totp_account_selected_emits_copy_next_code_effect`
  in `tests/reducer_tests.rs`)*
- [x] `C` on the list with a selected HOTP row surfaces the
  `no next code for HOTP accounts` status-line message and dispatches
  no `Effect`. *(`pressing_shift_c_with_hotp_account_selected_rejects_with_no_next_code_status_line`)*
- [x] `C` with no selection surfaces the `no account selected` gate
  per DESIGN §6; `C` with a modal open does not emit
  `Effect::CopyNextCode`; `C` with `Focus::Search` types `C` into
  the search query and emits no `Effect::CopyNextCode`. The
  empty-filtered-set case shares the no-selection arm (the search
  slice clears `selected` when the filter empties).
  *(`pressing_shift_c_with_no_selection_sets_no_account_selected_status_line`,
  `pressing_shift_c_with_modal_open_does_not_emit_copy_next_code`,
  `pressing_shift_c_on_search_focus_types_into_search_and_does_not_emit_copy_next_code`)*
- [x] Executor's `Effect::CopyNextCode` arm resolves the code via
  `Vault::totp_next_code(id, now)`, writes through
  `paladin_tui::clipboard::write_text`, and posts
  `EffectResult::CopyNextCode { account_id, result: Ok(..),
  seconds_until_valid: Some(_) , .. }`. The reducer's success arm
  seeds the status line with
  `next code copied, valid in {seconds_until_valid}s` and arms
  `pending_clipboard_clear` identically to the current-code path.
  *(`execute_copy_next_code_totp_writes_next_code_and_sends_ok_with_seconds`
  in `tests/effect_tests.rs`;
  `effect_result_copy_next_code_ok_publishes_status_line_confirmation_with_seconds`
  in `tests/reducer_tests.rs`)*
- [x] `arboard` write failure surfaces the existing
  `clipboard_write_failed` status-line error without scheduling
  auto-clear. *(`effect_result_copy_next_code_err_sets_status_line_clipboard_write_failed`)*
- [x] Executor silently drops `Effect::CopyNextCode` aimed at an HOTP
  account (defensive — the reducer gate prevents the emission, so
  reaching the executor means a routing bug; surfacing
  `clipboard_write_failed` here would be misleading).
  *(`execute_copy_next_code_silently_drops_on_hotp_account`)*
- [x] Render snapshot covers a mixed TOTP+HOTP vault: TOTP rows show
  `↪ NNN NNN` in dim style, HOTP rows leave the cell blank, and the
  full row fits in an 80-column terminal.
  *(`view_snapshots__snapshot_list_view_mixed_totp_hotp_hidden_and_revealed.snap`
  plus the `_no_color` styled sibling that pins the `DIM` modifier
  on the next-code span)*
- [x] Render snapshot covers an HOTP-only vault: no `↪` glyph
  appears anywhere in the rendered grid, asserting that the
  next-code projection is skipped on HOTP rows.
  *(`view_snapshots__snapshot_list_view_hotp_only_vault_omits_next_code_column.snap`
  plus the in-test `assert!(!rendered.contains('↪'))` guard)*
- [x] The `Code` returned by `Vault::totp_next_code` is dropped at
  the end of the render pass; no copy persists in `AppState`
  between ticks. *(Renderer reads the `Code` into a local for
  `format_code_digits` and drops it before returning the `Line`;
  `AppState::Unlocked` carries no cached next-code field — see
  `crates/paladin-tui/src/view/list.rs::render_totp_row` and
  `crates/paladin-tui/src/app/state.rs::AppState`.)*

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
- [x] `--no-color` variants of the list-view snapshots above.
  *(`tests/view_snapshots.rs` grows a styled-grid serializer
  `buffer_to_styled_text` that emits the symbol grid (identical to
  the existing `buffer_to_text` body) followed by a deterministic
  style annotation section listing each run-length-compressed run of
  cells whose `(fg, bg, modifier)` triple differs from the default
  `(Color::Reset, Color::Reset, Modifier::empty())`; rows with no
  styled cells emit a `(none)` sentinel. The companion
  `render_to_styled_text(state, now, no_color, w, h)` helper threads
  the `no_color` bool through `view::render`. Every list-view
  `snapshot_*` test grows a matching `assert_snapshot!(
  "<name>_no_color", render_to_styled_text(.., true, ..))` companion,
  producing nineteen `.snap` files in `tests/snapshots/` whose styles
  section is `(none)` because the renderer drops the bottom-line
  `StatusLine::Error` / `Confirmation` foreground under
  `no_color = true`. A regression that ever leaks color into the
  no-color path adds entries to the section, surfacing as a diff in
  whichever list-view snapshot exercises the affected status-line.
  Eight unit tests `styled_serializer_tests::*` cover the
  serializer itself: default-style sentinel detection, empty-modifier
  rendering as `NONE`, modifier captured via Debug, `(none)` marker
  for unstyled buffers, run-length compaction for `Color::Red` cells,
  new-run start when style changes, `Modifier::BOLD` capture, and
  byte-identical grid prefix vs `buffer_to_text` above the section
  header. The companion styled-mode contract — `Color::Red` /
  `Color::Green` foreground actually applied to the bottom-line
  cells when `no_color = false` — stays pinned by the per-cell
  assertions in `tests/no_color_tests.rs`, so the snapshot-variant
  matrix and the per-cell matrix together cover both halves of the
  `--no-color` × styled-color contract.)*

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
  `summary_display_label(&summary)` — same wording as the
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
  (resolved via the shared `summary_display_label(&summary)` —
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
  *(Superseded by the create-vault snapshots below once the
  in-app create-vault flow lands; the old `missing_vault.rs`
  module and its snapshot file are retired in the same slice.)*
- [x] Create-vault Choose-mode screen (Encrypted selected — default).
- [x] Create-vault Choose-mode screen (Plaintext selected).
- [x] Create-vault Confirm-plaintext screen (plaintext-storage
  warning rendered via `paladin_core::format_plaintext_storage_warning`).
- [x] Create-vault Enter-passphrase screen (both fields empty,
  focus on Passphrase).
- [x] Create-vault Enter-passphrase screen (Passphrase has typed
  characters, focus on Confirmation, mask renders one `•` per
  char).
- [x] Create-vault Enter-passphrase mismatch error (inline
  `passphrases do not match` style error, focused buffer
  zeroized).
- [x] Create-vault inline create error (e.g.,
  `unsafe_permissions` rendered via
  `format_unsafe_permissions`, passphrase buffer zeroized).

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
- [x] Export modal `zero_length`.
  *(`snapshot_export_modal_zero_length` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with `format: ExportFormat::Encrypted` and
  `error: Some(render_error_message(&PaladinError::InvalidPassphrase { reason: "zero_length" }))` —
  binding the snapshot to the core `Display` wording rather than a
  hand-typed string — and renders through `view::render` at 80×20.
  Reuses the inline-error rendering branch in
  `crates/paladin-tui/src/view/export.rs` exercised by the
  `confirmation_mismatch` slice above; the format selector reads
  `Encrypted` so the snapshot reads as an encrypted-path delta from
  the `snapshot_export_modal_default` baseline. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_zero_length.snap`
  so any future wording change in core's `invalid_passphrase` /
  `zero_length` surfaces here as a diff.)*
- [x] Export modal plaintext-export warning.
  *(`snapshot_export_modal_plaintext_export_warning` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with `format: ExportFormat::Plaintext` and
  `error: Some(format_plaintext_export_warning())` — binding the
  snapshot to the core helper rather than a hand-typed string — and
  renders through `view::render` at 80×20. The warning surfaces via
  the same `render_inline_error` branch the refused-overwrite,
  `confirmation_mismatch`, and `zero_length` snapshots exercise; the
  format selector reads `Plaintext` so the snapshot reads as a
  plaintext-path delta from the `snapshot_export_modal_default`
  baseline. `view/export.rs::render_inline_error` paints a single
  line per `Paragraph::new(Line::from(...))` (no `Wrap`), so the
  snapshot also pins the truncation behavior — a regression that
  ever swaps the slot for a multi-line `Wrap` widget surfaces here
  as a diff. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_plaintext_export_warning.snap`
  so any future wording change in core's
  `format_plaintext_export_warning` surfaces here as a diff.)*
- [x] Export modal `io_error` writer failure.
  *(`snapshot_export_modal_io_error` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with
  `error: Some(render_error_message(&PaladinError::IoError { operation: "write_secret_file_atomic", source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic-denied") }))` —
  binding the snapshot to the core `Display` wording (`I/O error
  during write_secret_file_atomic: synthetic-denied`) rather than a
  hand-typed string — and renders through `view::render` at 80×20.
  Operation tag and underlying `ErrorKind` mirror the reducer-side
  fixture
  (`effect_result_export_err_io_error_surfaces_inline_and_keeps_modal_open`
  in `tests/reducer_tests.rs`) so the view-snapshot matrix stays 1:1
  with the reducer matrix. Reuses the inline-error rendering branch
  in `crates/paladin-tui/src/view/export.rs` exercised by the
  preceding refused-overwrite / `confirmation_mismatch` /
  `zero_length` / plaintext-export-warning slices; the format
  selector stays at the `Plaintext` default. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_io_error.snap`
  so any future wording change in core's `io_error` `Display`
  surfaces here as a diff.)*
- [x] Export modal `save_not_committed`.
  *(`snapshot_export_modal_save_not_committed` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with
  `error: Some(render_error_message(&PaladinError::SaveNotCommitted { committed: false, backup_path: None }))` —
  binding the snapshot to the core `Display` wording (`save not
  committed (committed=false)`) rather than a hand-typed string —
  and renders through `view::render` at 80×20. The
  `committed: false, backup_path: None` shape mirrors the
  reducer-side fixture
  (`effect_result_export_err_save_not_committed_surfaces_inline_and_keeps_modal_open`
  in `tests/reducer_tests.rs`) and the pre-rename failure path
  documented in `DESIGN.md` §4.3 / §5 — the staging file never
  reached the destination, no `.bak` rotation ran — so the
  view-snapshot matrix stays 1:1 with the reducer matrix. Reuses
  the inline-error rendering branch in
  `crates/paladin-tui/src/view/export.rs` exercised by the
  preceding refused-overwrite / `confirmation_mismatch` /
  `zero_length` / plaintext-export-warning / `io_error` slices;
  the format selector stays at the `Plaintext` default. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_save_not_committed.snap`
  so any future wording change in core's `save_not_committed`
  `Display` surfaces here as a diff.)*
- [x] Export modal `save_durability_unconfirmed`.
  *(`snapshot_export_modal_save_durability_unconfirmed` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `ExportModal` with
  `error: Some(render_error_message(&PaladinError::SaveDurabilityUnconfirmed))` —
  binding the snapshot to the core `Display` wording (`save
  durability unconfirmed`) rather than a hand-typed string — and
  renders through `view::render` at 80×20. The unit variant
  mirrors the §4.3 contract — the destination file is in place on
  disk; only the parent-directory metadata sync is unconfirmed —
  so this slice differs from `save_not_committed` (pre-rename
  failure with `committed` / `backup_path` discriminators) in the
  rendered wording even though both surface inline through the
  same modal slot. Mirrors the reducer-side fixture
  (`effect_result_export_err_save_durability_unconfirmed_surfaces_inline_and_keeps_modal_open`
  in `tests/reducer_tests.rs`) so the view-snapshot matrix stays
  1:1 with the reducer matrix. Reuses the inline-error rendering
  branch in `crates/paladin-tui/src/view/export.rs` exercised by
  the preceding refused-overwrite / `confirmation_mismatch` /
  `zero_length` / plaintext-export-warning / `io_error` /
  `save_not_committed` slices; the format selector stays at the
  `Plaintext` default. Locked in
  `tests/snapshots/view_snapshots__snapshot_export_modal_save_durability_unconfirmed.snap`
  so any future wording change in core's
  `save_durability_unconfirmed` `Display` surfaces here as a
  diff.)*

Add (QR) error and counts states:

- [x] Add modal QR-import inline error: no clipboard image.
  *(`snapshot_add_modal_qr_no_clipboard_image` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with
  `mode: AddMode::Qr,
  error: Some(format_qr_import_failure(&QrImportFailure::NoClipboardImage))`
  — binding the snapshot to the shared TUI helper wording (`QR
  import failed: clipboard does not contain an image (copy a QR
  image first).`) rather than a hand-typed string — and renders
  through `view::render` at 80×20. The view-snapshot mirrors the
  reducer-side fixture
  (`effect_result_qr_import_no_clipboard_image_sets_inline_error_and_keeps_modal_open`
  in `tests/reducer_tests.rs`) so the matrix stays 1:1. Snapshot
  reads as a delta from `snapshot_add_modal_default` on two cells:
  the segmented mode-selector wraps `QR` in `▶ … ◀` instead of
  `Manual`, and the inline-error row appears in the spacer above
  the footer hint via the same `render_inline_error` branch the
  Add modal's `save_not_committed` /
  `save_durability_unconfirmed` slices exercise. The assertion
  pins the leading `QR import failed: clipboard does not contain
  an image` substring — the full message exceeds the inline-error
  slot's ~60-col width and is truncated by
  `Paragraph::new(Line::from(...))` in
  `view/add.rs::render_inline_error`, mirroring the truncation pin
  the plaintext-export-warning snapshot exercises. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_no_clipboard_image.snap`
  so any future rewording in `format_qr_import_failure` for the
  `NoClipboardImage` arm surfaces here as a diff.)*
- [x] Add modal QR-import inline error: image decode failure.
  *(`snapshot_add_modal_qr_image_decode_failure` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with
  `mode: AddMode::Qr,
  error: Some(format_qr_import_failure(&QrImportFailure::ImageDecodeFailure))`
  — binding the snapshot to the shared TUI helper wording (`QR
  import failed: clipboard image could not be decoded.`) rather
  than a hand-typed string — and renders through `view::render` at
  80×20. The view-snapshot mirrors the reducer-side fixture
  (`effect_result_qr_import_image_decode_failure_sets_inline_error_and_keeps_modal_open`
  in `tests/reducer_tests.rs`) so the matrix stays 1:1. The
  `ImageDecodeFailure` arm's 56-char message fits the ~60-col
  inline-error slot without truncation, unlike the longer
  `NoClipboardImage` companion slice — so this snapshot doubles as
  a regression guard that the renderer surfaces the full
  single-line message when it does fit, complementing the
  truncation pin in
  `snapshot_add_modal_qr_no_clipboard_image`. Reuses the
  `render_inline_error` branch in `view/add.rs` exercised by the
  Add modal's `save_not_committed` / `save_durability_unconfirmed`
  / `no_clipboard_image` slices; the segmented mode-selector wraps
  `QR` in `▶ … ◀`. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_image_decode_failure.snap`
  so any future rewording in `format_qr_import_failure` for the
  `ImageDecodeFailure` arm surfaces here as a diff.)*
- [x] Add modal QR-import inline error: zero decoded QRs.
  *(`snapshot_add_modal_qr_no_qrs_decoded` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with
  `mode: AddMode::Qr,
  error: Some(format_qr_import_failure(&QrImportFailure::Import(PaladinError::NoEntriesToImport)))`
  — binding the snapshot to the core `Display` wording (`no
  entries to import`) routed through the shared TUI helper's
  `Import(err)` arm rather than a hand-typed string — and renders
  through `view::render` at 80×20. View-snapshot mirrors the
  reducer-side fixture
  (`effect_result_qr_import_no_qrs_decoded_sets_inline_error_via_render_error_message`
  in `tests/reducer_tests.rs`) so the matrix stays 1:1.
  `NoEntriesToImport` is the §4.6 / §5 discriminator
  `paladin_core::import::qr_image_bytes` returns when it decodes
  the clipboard raster but finds zero QR payloads in it. Routing
  through `format_qr_import_failure` (rather than
  `render_error_message` directly) pins that the `Import` arm
  continues to forward `PaladinError` wording verbatim — a
  regression that ever wraps the core wording in a "QR import
  failed:" prefix on this arm surfaces here as a diff,
  distinguishing it from the bespoke `NoClipboardImage` and
  `ImageDecodeFailure` arms above. The 20-char core wording fits
  the ~60-col inline-error slot without truncation. Reuses the
  `render_inline_error` branch in `view/add.rs` exercised by the
  Add modal's `save_not_committed` / `save_durability_unconfirmed`
  / `no_clipboard_image` / `image_decode_failure` slices; the
  segmented mode-selector wraps `QR` in `▶ … ◀`. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_no_qrs_decoded.snap`
  so any future wording change in core's `no_entries_to_import`
  `Display` or in `format_qr_import_failure`'s `Import` arm
  surfaces here as a diff.)*
- [x] Add modal QR-import inline error: oversized raw RGBA buffer.
  *(`snapshot_add_modal_qr_oversized_rgba_buffer` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with
  `mode: AddMode::Qr,
  error: Some(format_qr_import_failure(&QrImportFailure::Import(
      paladin_core::import::qr_image_bytes(5000, 5000, &[], snapshot_now())
          .expect_err(...))))` — routing the error through the real
  public-API call rather than constructing the `PaladinError`
  directly binds the snapshot to the contract that
  `paladin_core::import::qr_image_bytes` rejects oversized RGBA
  buffers (dimensions whose `width * height * 4` exceeds
  `paladin_core::QR_RGBA_MAX_BYTES`) with `validation_error
  { field: "qr_image", reason: "image_too_large" }` per
  `DESIGN.md` §4.6. Mirrors the reducer-side fixture's trigger
  (`effect_result_qr_import_oversized_rgba_buffer_sets_inline_error_via_render_error_message`
  in `tests/reducer_tests.rs`) so the view-snapshot matrix stays
  1:1 with the reducer matrix. Routing through
  `format_qr_import_failure`'s `Import(err)` arm — which
  delegates to `render_error_message` and binds to the core
  `Display` impl (`validation error: qr_image: image_too_large`)
  — pins that this arm forwards `PaladinError` wording verbatim
  without a "QR import failed:" prefix, matching the
  `NoEntriesToImport` companion slice. The 43-char core wording
  fits the ~60-col inline-error slot without truncation. Reuses
  the `render_inline_error` branch in `view/add.rs` exercised by
  the Add modal's `save_not_committed` /
  `save_durability_unconfirmed` / `no_clipboard_image` /
  `image_decode_failure` / `no_qrs_decoded` slices; the
  segmented mode-selector wraps `QR` in `▶ … ◀`. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_oversized_rgba_buffer.snap`
  so any future wording change in core's `validation_error`
  `Display`, in the `qr_image_bytes` size-rejection path's
  `field` / `reason` codes, or in `format_qr_import_failure`'s
  `Import` arm surfaces here as a diff.)*
- [x] Add modal QR-import inline error: invalid QR payload.
  *(`snapshot_add_modal_qr_invalid_qr_payload` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with
  `mode: AddMode::Qr,
  error: Some(format_qr_import_failure(&QrImportFailure::Import(
      PaladinError::ValidationError { field: "qr_image",
      reason: "non_otpauth_payload".to_string(),
      source_index: Some(0), .. })))` — pinning the wording
  emitted by `payloads_to_accounts` in
  `crates/paladin-core/src/import/qr.rs:87` when
  `paladin_core::import::qr_image_bytes` decodes a QR whose
  payload is not an `otpauth://` URI (`validation_error
  { field: "qr_image", reason: "non_otpauth_payload" }` per
  `DESIGN.md` §4.6 / §5). Mirrors the reducer-side fixture
  (`effect_result_qr_import_invalid_qr_payload_sets_inline_error_via_render_error_message`
  in `tests/reducer_tests.rs`) so the view-snapshot matrix stays
  1:1 with the reducer matrix. Constructing the `ValidationError`
  variant directly (rather than driving a real non-otpauth QR
  through `qr_image_bytes`) keeps the snapshot self-contained —
  the field / reason codes are stable per §5, and
  `crates/paladin-core/tests/import_qr.rs`'s
  `qr_image_bytes_with_non_otpauth_payload_rejects_with_source_index`
  already binds the real-API path. Routing through
  `format_qr_import_failure`'s `Import(err)` arm — which
  delegates to `render_error_message` and binds to the core
  `Display` impl (`validation error: qr_image:
  non_otpauth_payload`) — pins that this arm forwards
  `PaladinError` wording verbatim without a "QR import failed:"
  prefix, matching the `NoEntriesToImport` and oversized-RGBA
  companion slices. The 47-char core wording fits the ~60-col
  inline-error slot without truncation. The `source_index: Some(0)`
  slot is locked here to document the attribution
  `payloads_to_accounts` tags on the offending payload; the
  `Display` impl ignores the field, so this slot does not influence
  the rendered text. Reuses the `render_inline_error` branch in
  `view/add.rs` exercised by the Add modal's `save_not_committed` /
  `save_durability_unconfirmed` / `no_clipboard_image` /
  `image_decode_failure` / `no_qrs_decoded` / `oversized_rgba_buffer`
  slices; the segmented mode-selector wraps `QR` in `▶ … ◀`.
  Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_invalid_qr_payload.snap`
  so any future wording change in core's `validation_error`
  `Display`, in the `non_otpauth_payload` reason code emitted by
  `payloads_to_accounts`, or in `format_qr_import_failure`'s
  `Import` arm surfaces here as a diff.)*
- [x] Add modal post-QR-import counts panel.
  *(`snapshot_add_modal_qr_counts_panel` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with `mode: AddMode::Qr, counts_panel: Some(CountsPanel
  { imported: 2, skipped: 1, replaced: 0, appended: 0, warnings: vec![] })`
  so the snapshot pins the post-success summary panel — the four
  `ImportReport` merge totals
  (`imported`/`skipped`/`replaced`/`appended`) the reducer seeds
  from `paladin_core::ImportReport` per `DESIGN.md` §6's "The modal
  reports imported/skipped/replaced/appended/warning counts plus
  validation-warning messages rendered through
  `paladin_core::format_validation_warning()` in a post-success
  counts panel" contract and the `IMPLEMENTATION_PLAN_03_TUI.md`
  "Modals (per §6) > Add" checklist row: *"Clipboard QR import uses
  `ImportConflict::Skip` and reports imported / skipped counts."*
  Implements the rendering in `crates/paladin-tui/src/view/add.rs`'s
  new `render_counts_panel` / `modal_height_for` helpers, which
  mirror the matching helpers in `view/import.rs` so the QR-add and
  file-import counts panels paint identical labels
  (`Imported:` / `Skipped:` / `Replaced:` / `Appended:`) at the same
  13-cell column (`COUNTS_LABEL_COL_WIDTH`) and share the
  `Enter or Esc to close` post-success hint — a regression that ever
  drifts the two columns surfaces as a diff across the matched
  snapshot pair. Per `AddModal::counts_panel`, the clipboard-QR flow
  always runs with `ImportConflict::Skip`, so `replaced` and
  `appended` are always `0` on this path; the rows still render so
  the surface reads identically to the Import modal's counts panel,
  and a regression that ever hides the always-zero rows for the
  QR-add path (or paints a different label) surfaces as a diff. The
  carried counts (`imported: 2, skipped: 1`) are distinct from the
  Import modal's no-warnings (3 / 1 / 2 / 4) and warnings (2 / 0 /
  0 / 0) snapshots so the three counts-panel snapshots read as
  deltas across the three flows; a regression that ever swaps two
  counts surfaces as a diff rather than staying silent under
  identical values. The `warnings` slot is empty here; the
  warnings-included variant lands in its own snapshot per the
  plan's "QR-add counts panel with validation-warning messages"
  checklist row below. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_counts_panel.snap`
  so any future change to the counts panel labels, column width,
  or post-success hint surfaces here as a diff.)*
- [x] Add modal `duplicate_account`.
  *(`snapshot_add_modal_duplicate_account` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives an `Unlocked`
  state holding a plaintext vault with one TOTP account labelled
  `github` and `Modal::Add(AddModal { error:
  Some(format_duplicate_account_message(&existing_summary)), ..
  AddModal::default() })`. Routing the wording through the shared
  `format_duplicate_account_message` formatter (rather than a
  hand-typed string) binds the snapshot to the reducer-side renderer
  exercised by
  `effect_result_add_duplicate_stashes_pending_and_sets_inline_error`
  in `tests/reducer_tests.rs`, so any future rewording in
  `crates/paladin-tui/src/app/state.rs` surfaces as a diff in both
  the inline error and the snapshot grid. The full template runs
  ~97 chars — `account already exists with the same (secret, issuer,
  label): github (press Enter to add anyway)` — and exceeds the
  modal's ~60-cell inline-error slot, so the rendered row truncates
  to `account already exists with the same (secret, issuer, label)`,
  mirroring the truncation pin the
  `snapshot_add_modal_qr_no_clipboard_image` snapshot exercises. The
  `pending_duplicate_add` slot is intentionally left `None` because
  only the `error` field reaches the renderer (see
  `crates/paladin-tui/src/view/add.rs:167`); the matching pending-
  state coverage lives on the reducer side. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_duplicate_account.snap`
  so any future change to the inline-error template, the modal's
  spacer layout, or the segmented mode selector surfaces as a diff.)*
- [x] Add modal "add anyway" confirmation.
  *(`snapshot_add_modal_add_anyway_confirmation` in
  `crates/paladin-tui/tests/view_snapshots.rs` constructs an
  `AddModal` with both `error: Some(format_duplicate_account_message(
  &existing_summary))` and
  `pending_duplicate_add: Some(Box::new(PendingDuplicateAdd { ... }))`
  populated — mirroring the reducer state established by
  `effect_result_add_duplicate_stashes_pending_and_sets_inline_error`
  and consumed by
  `enter_with_pending_duplicate_add_in_manual_mode_emits_add_anyway_effect`
  / `enter_with_pending_duplicate_add_in_uri_mode_emits_add_anyway_effect`
  — and renders through `view::render` at 80×20. The pending
  `ValidatedAccount` is built from the same `(secret, issuer,
  label)` triple as the existing entry (the shape exercised by
  `make_duplicate_validated` in `tests/reducer_tests.rs`).
  `crates/paladin-tui/src/view/add.rs` now branches the footer hint
  on `modal.pending_duplicate_add.is_some()`: the editable-modal
  default (`Tab cycles fields  ·  Enter submit  ·  Esc cancel`) is
  replaced with the confirmation form
  (`Enter add anyway  ·  Esc cancel`), since Tab-cycling fields no
  longer applies — the next Enter commits the stashed pending
  account via `Effect::AddAnyway` (per the reducer's `Enter`
  short-circuit on `pending_duplicate_add.take()`), and Esc drops
  the stash. The truncated inline-error row from the
  `snapshot_add_modal_duplicate_account` sibling is unchanged, so
  the snapshot reads as a one-line footer-swap delta and surfaces
  as a regression if the renderer ever stops branching on
  `pending_duplicate_add` or if the confirmation wording changes.
  Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_add_anyway_confirmation.snap`.)*
- [x] QR-add counts panel with validation-warning messages.
  *(`snapshot_add_modal_qr_counts_panel_with_validation_warnings`
  in `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state holding
  `Modal::Add(AddModal { mode: AddMode::Qr, counts_panel:
  Some(CountsPanel { imported: 1, skipped: 1, replaced: 0,
  appended: 0, warnings: vec![short, shortest] }), .. })`. Each
  warning is built through `paladin_core::format_validation_warning`
  with distinct `decoded_len` values (5 / 1) so the snapshot binds
  to the core wording and a regression that ever swaps two
  warnings or collapses them onto a single line surfaces as a diff.
  The carried counts (`imported: 1`, `skipped: 1`) are distinct
  from the no-warnings QR-add snapshot (`imported: 2`,
  `skipped: 1`) so the two snapshots read as deltas of the same
  panel — a future renderer change that ever hides the counts in
  the presence of warnings is caught; `replaced` and `appended`
  stay pinned to `0` per the clipboard-QR
  [`ImportConflict::Skip`] contract. The renderer's existing
  `render_counts_panel` band in `crates/paladin-tui/src/view/add.rs`
  (which mirrors `super::import::render_counts_panel`) already
  paints the warnings band above the `Enter or Esc to close`
  footer; `modal_height_for` grew the modal vertically so both
  warning strings fit fully below the four count rows inside an
  80×24 [`TestBackend`]. Locked in
  `tests/snapshots/view_snapshots__snapshot_add_modal_qr_counts_panel_with_validation_warnings.snap`.)*

Passphrase inline errors:

- [x] Passphrase modal `confirmation_mismatch` inline error.
  *(`snapshot_passphrase_modal_confirmation_mismatch` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state holding
  `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
  Some(render_error_message(&PaladinError::InvalidPassphrase {
  reason: "confirmation_mismatch" })), .. })`. Routing the wording
  through `render_error_message` binds the snapshot to the core
  `Display` impl (`invalid passphrase: confirmation_mismatch`)
  rather than a hand-typed string, keeping the surfaced text in
  lockstep with the CLI's `prompt_new_passphrase` and the GTK
  `SubmitRejection::ConfirmationMismatch` wire code. The carried
  sub-flow is `Set` so the snapshot reads as an inline-error delta
  from `snapshot_passphrase_modal_set_default`: the error line
  appears inside the spacer between the masked `Confirm:` row and
  the centered `Enter submit · Esc cancel` footer hint, sharing
  the same `error` slot the `save_not_committed` /
  `save_durability_unconfirmed` snapshots exercise. Locked in
  `tests/snapshots/view_snapshots__snapshot_passphrase_modal_confirmation_mismatch.snap`.)*
- [x] Passphrase modal `zero_length` inline error.
  *(`snapshot_passphrase_modal_zero_length` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state holding
  `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
  Some(render_error_message(&PaladinError::InvalidPassphrase {
  reason: "zero_length" })), .. })`. Routing the wording through
  `render_error_message` binds the snapshot to the core `Display`
  impl (`invalid passphrase: zero_length`), keeping the surfaced
  text in lockstep with the CLI's `prompt_new_passphrase` (mismatch
  first, then `zero_length`) and the GTK
  `SubmitRejection::ZeroLength` wire code. The `Set` sub-flow
  reads as an inline-error delta from
  `snapshot_passphrase_modal_set_default` and shares the renderer
  branch the `confirmation_mismatch` snapshot above exercises;
  the `change` sub-flow runs the same branch so a single `Set`
  carrier covers both twice-confirm flows. Locked in
  `tests/snapshots/view_snapshots__snapshot_passphrase_modal_zero_length.snap`.)*

Status-line states:

- [x] Status-line error after rejected copy.
  *(`snapshot_list_view_status_line_error_after_rejected_copy` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state holding
  `status_line: Some(StatusLine::Error(NO_ACCOUNT_SELECTED.to_string()))`.
  Routing through the `NO_ACCOUNT_SELECTED` constant binds the
  snapshot to the source-of-truth wording the reducer publishes for
  the selection-gated rejection fan-out (`n` / `r` / `R`, and
  `Enter`-as-copy by the same gate). `crates/paladin-tui/src/view/list.rs`
  now routes the bottom row through a `bottom_line` helper: when
  `status_line` is `Some(StatusLine::Error(msg))` the published
  prose takes over the keybinding-hint slot (red-tinted for live
  terminals; the snapshot harness drops styling), and when `None`
  the default `[↑↓] move … [/] find` hint is unchanged from
  `snapshot_list_view_single_totp`. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_error_after_rejected_copy.snap`.)*
- [x] Status-line `save_durability_unconfirmed` after HOTP `n`.
  *(`snapshot_list_view_status_line_save_durability_unconfirmed_after_hotp_advance`
  in `crates/paladin-tui/tests/view_snapshots.rs` drives
  `view::render` against an `Unlocked` state mirroring the reducer's
  post-advance "committed-but-uncertain" shape from
  `reduce_hotp_advance_result`: the selected HOTP account has an
  open `HotpReveal` (the staged code survives the
  durability-unconfirmed failure per the reducer body) and
  `status_line` carries `StatusLine::Error(render_error_message(
    &PaladinError::SaveDurabilityUnconfirmed))`. Routing the wording
  through `render_error_message` binds the snapshot to the core
  `Display` impl (`save durability unconfirmed`) rather than a
  hand-typed string, keeping the surfaced text in lockstep with the
  CLI's `save_durability_unconfirmed` envelope key and the GTK
  equivalent surface. The HotpReveal is seeded so the rows pane
  shows the revealed code under the pre-advance `(#41)` counter,
  pinning that the renderer paints the reveal alongside the
  durability warning rather than collapsing back to the hidden
  prompt. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_save_durability_unconfirmed_after_hotp_advance.snap`.)*
- [x] Status-line `clipboard_write_failed` after a failed copy.
  *(`snapshot_list_view_status_line_clipboard_write_failed_after_failed_copy`
  in `crates/paladin-tui/tests/view_snapshots.rs` drives
  `view::render` against an `Unlocked` state whose `status_line`
  carries `StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string())` —
  the exact wording `reduce_copy_code_result` publishes on the
  `EffectResult::CopyCode { result: Err(()), .. }` branch when the
  executor's `arboard` write fails. Routing through the
  `CLIPBOARD_WRITE_FAILED` constant binds the snapshot to the
  source-of-truth string so a future rewording stays in sync with
  the reducer-level `clipboard_write_failed` assertion. Reads as a
  bottom-row delta from the `rejected_copy` sibling — both share
  the `StatusLine::Error` renderer branch — pinning that the
  message content is the only difference. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_clipboard_write_failed_after_failed_copy.snap`.)*
- [x] Unlock screen with inline wrong-passphrase error.
  *(`snapshot_unlock_screen_with_wrong_passphrase_error` in
  `tests/view_snapshots.rs` sets
  `error: Some(PaladinError::DecryptFailed.to_string())` —
  binding the snapshot to the core `Display` wording rather than
  a hand-typed string — and locks the rendered grid in
  `tests/snapshots/view_snapshots__snapshot_unlock_screen_with_wrong_passphrase_error.snap`.)*
- [x] Status-line confirmation after manual Add.
  *(`snapshot_list_view_status_line_after_manual_add` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state whose `status_line` carries
  `StatusLine::Confirmation(format!("Added {}.", summary_display_label(&summary)))`
  — the exact wording `reduce_add_result` publishes on the
  no-warnings Ok-arm of `EffectResult::Add`. Routing through
  `summary_display_label` binds the snapshot to the shared
  CLI / TUI label-formatting source of truth so any wording change
  in `issuer:label` rendering surfaces here. Reads as a bottom-row
  delta from the `StatusLine::Error` siblings above — both share
  the renderer's `bottom_line` slot but route through the
  `Confirmation` branch (green-tinted on live terminals; the
  harness drops styling). Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_manual_add.snap`.)*
- [x] Status-line confirmation after URI Add.
  *(`snapshot_list_view_status_line_after_uri_add` in
  `crates/paladin-tui/tests/view_snapshots.rs` follows the same
  pattern as the manual-add sibling: the URI add flow shares
  `reduce_add_result`, so the published wording is the same
  `Added {display}.` template against
  `summary_display_label`. A separate snapshot anchors the
  URI entry point against a future reducer divergence in wording
  per `AddMode`. The just-added account uses an issuer / label
  combination typical of an
  `otpauth://totp/Example:alice@example.com?issuer=Example` payload
  so the bottom-row text differs visibly from the manual sibling
  without invoking a different renderer branch. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_uri_add.snap`.)*
- [x] Status-line confirmation after Remove.
  *(`snapshot_list_view_status_line_after_remove` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state whose `status_line` carries
  `StatusLine::Confirmation(format!("Removed {}.", summary_display_label(&summary)))`
  — the exact wording `reduce_remove_result` publishes on the
  Ok-arm of `EffectResult::Remove`. The reducer plugs the carried
  display-label `String` directly into the format template; that
  string is built by the executor via `summary_display_label`
  in the `effect.rs` Remove closure, so the snapshot is bound to
  the shared label-formatting source of truth. To keep the
  snapshot a pure view test with no effect plumbing, the vault
  keeps the captured account live and `selected = None` — visually
  representing "the user navigated away after a successful remove"
  rather than the literal post-remove vault contents. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_remove.snap`.)*
- [x] Status-line confirmation after Rename.
  *(`snapshot_list_view_status_line_after_rename` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state whose `status_line` carries
  `StatusLine::Confirmation(format!("Renamed to {label}"))` —
  the exact wording `reduce_rename_result` publishes on the
  Ok-arm, where `label` is the post-rename `a.label()` (just the
  bare label, NOT the issuer-prefixed display label). The vault
  is populated with the account already carrying its post-rename
  label `"ben-personal@example.com"`, then the test extracts the
  label off `Vault::iter` the same way the reducer does, binding
  the snapshot to the live vault state rather than a hand-typed
  literal. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_rename.snap`.)*
- [x] Status-line confirmation after Export.
  *(`snapshot_list_view_status_line_after_export` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state whose `status_line` carries
  `StatusLine::Confirmation(format!("Exported to {display}."))`
  — the exact wording `reduce_export_result` publishes on the
  Ok-arm, where `display` is the user-supplied
  `ExportModal::path_text.trim()`. The Export effect does not
  mutate the vault, so the rows pane stays identical to its
  pre-export state — only the bottom row reflects the
  confirmation. The path string is a tilde-style relative path
  (`~/exports/paladin-export.json`) that stays host-independent
  so the snapshot is deterministic across systems. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_export.snap`.)*
- [x] Status-line confirmation after Passphrase set.
  *(`snapshot_list_view_status_line_after_passphrase_set` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state whose `status_line` carries
  `StatusLine::Confirmation("Passphrase updated.")` — the exact
  wording `reduce_passphrase_result` publishes on the Ok-arm. All
  three passphrase sub-flows (`Set`, `Change`, `Remove`) share
  the same Ok-arm string, so this snapshot and its `change` /
  `remove` siblings are byte-identical in the rendered body until
  / unless the reducer diverges the wording per sub-flow — at
  which point only the affected snapshot needs updating, giving
  each entry point its own regression sentinel. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_passphrase_set.snap`.)*
- [x] Status-line confirmation after Passphrase change.
  *(`snapshot_list_view_status_line_after_passphrase_change` —
  sibling of `..._after_passphrase_set`. The `Change` sub-flow
  shares the same `reduce_passphrase_result` Ok-arm wording
  (`"Passphrase updated."`), so the rendered body is byte-identical
  until a future reducer divergence makes them differ. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_passphrase_change.snap`.)*
- [x] Status-line confirmation after Passphrase remove.
  *(`snapshot_list_view_status_line_after_passphrase_remove` —
  sibling of `..._after_passphrase_set` /
  `..._after_passphrase_change`. The `Remove` sub-flow shares the
  same Ok-arm wording. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_passphrase_remove.snap`.)*
- [x] Status-line confirmation after Settings save.
  *(`snapshot_list_view_status_line_after_settings_save` in
  `crates/paladin-tui/tests/view_snapshots.rs` drives `view::render`
  against an `Unlocked` state whose `status_line` carries
  `StatusLine::Confirmation("Settings updated.")` — the exact
  wording `reduce_settings_result` publishes on the Ok-arm of
  `EffectResult::ApplySettings`. The settings save closes the
  modal and leaves the rows pane unchanged; only the bottom row
  reflects the confirmation. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_settings_save.snap`.)*
- [x] Manual Add status-line confirmation with validation warnings.
  *(`snapshot_list_view_status_line_after_manual_add_with_warnings`
  in `crates/paladin-tui/tests/view_snapshots.rs` drives
  `view::render` against an `Unlocked` state whose `status_line`
  carries the warning-appended confirmation `reduce_add_result`
  publishes when `success.warnings` is non-empty:
  `Added {display}. warning: {rendered}` where `rendered` is the
  `; `-joined output of `format_validation_warning` over the
  carried warnings. A `ValidationWarning::ShortSecret { decoded_len:
  8, recommended_min: 16 }` seeds the warnings list so the
  snapshot is bound to `format_validation_warning` — any wording
  change in the core warning text surfaces here. At 80-col
  snapshot width the warning text overflows the bottom row and
  ratatui truncates without wrapping; the truncation point itself
  is a useful regression sentinel against prefix / join-literal
  changes. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_manual_add_with_warnings.snap`.)*
- [x] URI Add status-line confirmation with validation warnings.
  *(`snapshot_list_view_status_line_after_uri_add_with_warnings`
  — sibling of `..._manual_add_with_warnings`. The URI add flow
  shares `reduce_add_result`, so the warning-appended confirmation
  template is identical. A separate snapshot anchors the URI
  entry point against a future reducer divergence in wording per
  `AddMode`. Locked in
  `tests/snapshots/view_snapshots__snapshot_list_view_status_line_after_uri_add_with_warnings.snap`.)*

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

### Color palette (`view::theme`)

Every styled cell routes through `view::theme` so the resolved
`no_color` bool has a single chokepoint. When `no_color` is `true` the
helpers drop foreground / background attributes but preserve modifiers
(`BOLD`, `DIM`, `REVERSED`, `UNDERLINED`) so the visual hierarchy
degrades to a monochrome-but-still-legible rendering rather than a
flat wall of text. Named ratatui ANSI colors (not RGB triples) so the
user's terminal theme decides exact hues:

- `ACCENT` (Blue) — bordered-block borders + bold titles on every
  full-screen view and modal except destructive ones.
- `ERROR` (Red) — Remove modal border + title, every inline error
  line (`decrypt_failed`, `save_not_committed`, etc.), the
  startup-error screen border + title, and the `StatusLine::Error`
  bottom-row tint.
- `SUCCESS` (Green) — `StatusLine::Confirmation` bottom-row tint.
- `CODE` (Cyan, bold) — TOTP code digits and HOTP revealed-code
  digits. Stable across the rotation window so the user has a calm
  visual anchor while scanning rows; urgency is encoded by the
  period gauge, not the digits.
- `CODE_CALM` (Green) — period-gauge fill when more than 15
  seconds remain in the rotation window.
- `WARN` (Yellow) — period-gauge fill when 6–15 seconds remain in
  the rotation window, search-hit highlight (bold + underlined) on
  the title column, plaintext-mode chip in the list view title
  (`[plaintext]`, bold), HOTP `▸ press n to advance` prompt (dim),
  plaintext-storage warning text in the create-vault wizard and the
  passphrase-remove modal.
- `URGENT` (Red) — period-gauge fill in the final 5 seconds of the
  rotation window. Gauge thresholds are absolute seconds matching
  `paladin-gtk`'s `progress_urgency` so a 30 s and 60 s TOTP
  transition at the same wall-clock moment.
- `KEY_HINT` (Cyan) — Help overlay key column (bold).

Selected list-view rows render with `Modifier::REVERSED + BOLD` on
the paragraph style so the highlight works regardless of the user's
terminal theme and survives `--no-color`.

## Packaging (per §11)

`paladin-tui` ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.1
(§11.1). Implementation owes the release pipeline:

- **Man page.** Generate the argument synopsis for `paladin-tui.1` from
  clap via `clap_mangen`, and append maintained sections for keybindings,
  modal behavior, and the §6 create-vault / startup-error screens, driven
  by the workspace `cargo xtask man` target. The packaging configs ship it
  gzipped at `/usr/share/man/man1/paladin-tui.1.gz` per §11.3.

  *Implemented (v0.2 Milestone 7, partial):* `cargo xtask man`
  renders the clap-derived argument synopsis for `paladin-tui.1`
  via `clap_mangen`, pulling the live `Command` through
  `paladin_tui::clap_command()`. `cargo xtask package --frontend
  paladin-tui --format rpm` gzips the result into
  `target/man/paladin-tui.1.gz` before running `nfpm`.
  **Deferred:** the maintained keybindings / modal-behavior /
  create-vault / startup-error sections this bullet promises are
  not yet appended — `xtask::man` only emits the clap synopsis. A
  follow-up commit adds those handwritten sections (likely sourced
  from in-tree templates so they stay diffable) and re-renders
  through the same pipeline.
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

  *Implemented (v0.2 Milestone 7, `.rpm` + `.deb`):*
  `packaging/rpm/paladin-tui.yaml` declares `name: paladin-tui`,
  depends on `glibc` only (the TUI is terminal-only and never
  links GTK / libadwaita), installs `/usr/bin/paladin-tui` + the
  gzipped `/usr/share/man/man1/paladin-tui.1.gz`, and inherits
  `version: ${PALADIN_VERSION}` from the release pipeline.
  `packaging/deb/paladin-tui.yaml` is the Debian analogue: it
  declares `name: paladin-tui`, `section: utils`,
  `priority: optional`, depends on `libc6` only (a guard in
  `packaging_deb_nfpm_manifest_logic.rs` rejects any stray GTK /
  libadwaita dep), installs the same payload, and inherits the same
  `${PALADIN_VERSION}`. Both contracts are pinned by
  `crates/paladin-tui/tests/packaging_rpm_nfpm_manifest_logic.rs`
  and
  `crates/paladin-tui/tests/packaging_deb_nfpm_manifest_logic.rs`.
  `cargo xtask package --frontend paladin-tui --format deb` (or
  `make deb-paladin-tui`) is the local entry point; the release
  workflow builds the `.deb` directly with `nfpm` and attaches it
  to the GitHub release alongside the `.rpm`.
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

- [x] Scaffold `paladin-tui` crate, workspace membership, binary entry, and
  SPDX headers.
- [x] Implement CLI args, vault path resolution, encrypted unlock,
  plaintext direct-open, missing-vault, and startup-error flows
  (including `format_unsafe_permissions` rendering).
- [x] Replace the read-only missing-vault guidance screen with the
  in-app create-vault flow: rename `AppState::MissingVault` to
  `AppState::CreateVault { path, step, error }`, add
  `CreateVaultStep` / `CreateVaultMode` / `PassphraseFieldFocus`,
  add `Effect::CreateVault` + `CreateVaultInit` plus its executor,
  add `crates/paladin-tui/src/view/create_vault.rs`, retire
  `crates/paladin-tui/src/view/missing_vault.rs`, update the view
  dispatcher / KEYBINDINGS table / Help overlay text, and migrate
  `build_initial_state_with_resolver` to land on `CreateVault` for
  `VaultStatus::Missing`. Tests cover ChooseMode toggling,
  per-step `Esc` / `q` / `Ctrl-C` semantics, passphrase entry
  (mismatch handling, zeroize on cancel / quit), executor success
  (Plaintext and Encrypted both land in `Unlocked` with an empty
  list), executor failure (`unsafe_permissions`, generic `io_error`,
  `EncryptionOptions::new` validation), and insta snapshots for
  every step (`choose_mode_encrypted`, `choose_mode_plaintext`,
  `confirm_plaintext`, `enter_passphrase_empty`,
  `enter_passphrase_typing`, `enter_passphrase_mismatch_error`,
  `create_error`).
- [x] Implement terminal raw-mode / alternate-screen lifecycle with guarded
  restoration on exit, error, `Ctrl-C`, and panic unwind.
- [x] Implement reducer, event producers, effect execution, clipboard
  timer tokens (issued by
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`),
  and auto-lock idle deadlines (computed by
  `paladin_core::policy::auto_lock::IdlePolicy::next_deadline`).
- [x] Implement list layout from `AccountSummary` projections, search,
  TOTP gauges, HOTP reveal/copy behavior,
  HOTP `Code.counter_used` labels, and status-line errors.
- [x] Implement vim-style list navigation (`j` / `k`, `Ctrl-F` /
  `Ctrl-B`, `G`, plus `gg` and `zz` two-press chords) in the
  reducer. Hold pending-chord state with no timeout; clear it on any
  non-matching key, focus change to search, modal open, `Esc`, or
  auto-lock. Add `Ctrl-B` / `Ctrl-F` to the search-focus
  pass-through list alongside the existing `Ctrl-D` / `Ctrl-U` /
  `PgUp` / `PgDn` / `Home` / `End`. `Ctrl-N` / `Ctrl-P` serve two
  scopes: inside modals they are `Tab` / `Shift-Tab` field-cycling
  aliases, and at the top level they are readline-style next /
  previous row mirrors of `↓` / `↑` that share the search-focus
  pass-through with the half-page / page chords.
- [x] Implement add / remove / rename / import / export / passphrase / settings modals
  with persistence through `Vault::mutate_and_save` where the core owns
  rollback. Source the `passphrase remove` warning from
  `paladin_core::format_plaintext_storage_warning()` and the
  plaintext-export warning from
  `paladin_core::format_plaintext_export_warning()` so wording stays
  identical to the CLI / GUI; gate `set` vs `change` / `remove`
  sub-flows on `Vault::is_encrypted()` and feed the same getter into
  `paladin_core::policy::auto_lock::IdlePolicy::should_arm` to maintain
  or clear the auto-lock idle deadline.
- [x] Implement the read-only Help overlay (`?` from list focus,
  `Esc` to close); render its content from the same keybindings table
  used to generate the man page so the two stay in sync; suppress
  `?` on the unlock, create-vault, and startup-error screens.
  *(Reducer slice + view slice both done. Reducer:
  `help_open: bool` on `AppState::Unlocked`, `?` opener from list
  focus with `modal == None`, `Esc`-close precedence above
  modal-close / search-clear, all other keys are silent no-ops while
  open, `Ctrl-C` still quits, auto-lock discards the slot. View:
  `crates/paladin-tui/src/view/help.rs` paints a centered bordered
  overlay whose body iterates the shared
  `crates/paladin-tui/src/keybindings.rs::KEYBINDINGS` table — the
  same `const` the future `cargo xtask man` target will read when
  it appends the "Keybindings" section to `paladin-tui.1`, so the
  overlay and the man page cannot drift. Locked by the
  `snapshot_help_overlay` snapshot.)*
- [x] Use `paladin_core::account_matches_search` for `search.rs` substring
  filtering so the TUI shares issuer/label matching semantics with the CLI
  and GUI.
- [x] Use `paladin_core::classify_paladin_import_precheck` before any
  encrypted-Paladin-bundle import prompt so the TUI does not duplicate the
  CLI / GUI Paladin header decision table.
- [x] Route export writes through `paladin_core::write_secret_file_atomic`.
- [x] Implement clipboard wrapper (arboard reads/writes), QR image
  import from clipboard bytes, and only-if-unchanged auto-clear via
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::should_clear`.
  *(Adapter primitives live in `crates/paladin-tui/src/clipboard.rs`
  as methods on a long-lived [`ClipboardSession`] —
  `read_text(&mut self) -> Result<String, ()>` /
  `write_text(&mut self, &str) -> Result<(), ()>` /
  `read_image(&mut self) -> Result<ClipboardImage, ImageReadError>` —
  that lazily initialize one cached `arboard::Clipboard` and reuse it
  for every read / write over the lifetime of the
  `paladin-tui` process. The executor borrows the session as `&mut`
  through `crate::app::dispatch::dispatch` (which `crate::app::run::run_event_loop`
  constructs once and threads in alongside the `mpsc` sender). Reusing
  one `arboard::Clipboard` instance fixes two related problems that the
  earlier "construct-drop per call" shape exhibited on Linux X11:
  clipboard managers (clipman, parcellite, gpaste, …) could miss the
  contents because the X11 selection owner went away within
  milliseconds of `set_text`; and `arboard` 3.x in `debug_assertions`
  builds prints `"Clipboard was dropped very quickly after writing …"`
  to stderr when the `Clipboard` is dropped < 100 ms after a write
  *and* stderr is a TTY (which it always is under the TUI), mangling
  the alternate-screen render. A session-scoped instance keeps the
  X11 selection alive for the duration of the app and pushes the
  `Clipboard` drop past the 100 ms threshold so neither failure mode
  is reachable in normal operation. The third primitive `read_image`
  wraps `arboard::Clipboard::get_image()` and re-shapes the result
  into the adapter-owned `ClipboardImage { width, height, rgba }`
  type so the `arboard` dependency does not leak through the adapter
  boundary. Errors collapse to a two-variant `ImageReadError`
  (`NoImage` from `arboard::Error::ContentNotAvailable`,
  `DecodeFailure` from everything else) so the executor can route to
  the matching `QrImportFailure::{NoClipboardImage, ImageDecodeFailure}`
  for the two distinct user-facing wordings the reducer renders. The
  `paladin-tui/test-hooks` env-var protocol grows to cover images:
  `PALADIN_CLIPBOARD_DRYRUN=1` returns the in-process seeded image
  (or `NoImage` when not seeded, via the new
  `seed_test_clipboard_image` / `clear_test_clipboard_image` helpers);
  `=fail` returns `DecodeFailure` so both error variants are reachable
  from CI. The executor side lands in
  `crates/paladin-tui/src/app/effect.rs::execute_add_from_clipboard_qr`
  — `Effect::AddFromClipboardQr { path }` calls `read_image`, hands
  the RGBA buffer to `paladin_core::import::qr_image_bytes` (which
  re-validates dimensions and rejects oversized buffers with the
  `image_too_large` validation surface), then commits the resulting
  `ValidatedAccount` batch through `Vault::import_accounts(_,
  ImportConflict::Skip, _)` wrapped in `Vault::mutate_and_save` and
  posts back `EffectResult::QrImport { result: ... }`. The
  only-if-unchanged auto-clear was wired earlier with the clipboard
  scheduling slice (`Effect::ClearClipboard` reads the live clipboard
  through `read_text` and writes empty only when
  `ClipboardClearPolicy::should_clear` returns `true`). Coverage:
  `tests/clipboard_tests.rs::adapter_read_image` pins the new
  primitive's DRYRUN protocol (round-trip seeded image, `NoImage` on
  unseeded, `DecodeFailure` on `=fail`, seed-overwrite, clear);
  `tests/effect_tests.rs::add_from_clipboard_qr` pins the executor —
  happy-path import + persistence, `NoClipboardImage` /
  `ImageDecodeFailure` routing, `NoEntriesToImport` on a blank image,
  `image_too_large` on oversized dimensions, `Skip` conflict on
  re-import, and silent-drop on path-mismatch / non-Unlocked. Real
  QR fixtures are rendered through `qrcode` + `image` dev-deps that
  mirror `paladin-core`'s `tests/import_qr.rs::make_qr_rgba`.)*
- [x] Add reducer, search, auto-lock, clipboard, HOTP reveal, terminal
  lifecycle, sensitive-buffer, and snapshot coverage. Tracked at the
  bullet level in the Tests checklist; this top-level item only ticks
  once every Tests sub-bullet is checked.
- [x] Add a `paladin-tui/test-hooks` cargo feature that is **off by
  default** in production builds and enabled only by the test build of
  the `paladin-tui` binary. `paladin-tui/test-hooks` transitively
  enables `paladin-core/test-fault-injection` so reducer / effect-layer
  integration tests can drive pre-commit and durability-unconfirmed
  save failures via the `PALADIN_FAULT_INJECT` env var.
- [x] Wire a test-build-only `PALADIN_CLIPBOARD_DRYRUN=1` short-circuit
  in the TUI clipboard adapter that bypasses `arboard` and records the
  intended copy payload plus the auto-clear schedule, gated behind the
  same `paladin-tui/test-hooks` feature so production builds never link
  the hook. Lets CI exercise the copy → schedule → only-if-unchanged
  auto-clear loop end-to-end without a clipboard server.
- [x] Add a TUI-side smoke test that spawns `paladin tui` (CLI) and
  asserts it execs `paladin-tui` on shared-`PATH` installs; the
  Flatpak `exec_paladin_tui` failure mode is exercised by the CLI
  plan's tests.
  *(`crates/paladin-tui/tests/tui_exec_wrapper.rs` adds two tests that
  use the real `paladin-tui` binary via `env!("CARGO_BIN_EXE_paladin-tui")`,
  set `PATH` to the directory containing it (the shared-`PATH`
  install shape), then invoke the real `paladin` CLI binary via
  `assert_cmd::Command::cargo_bin("paladin")` with the `tui`
  subcommand.
  `paladin_tui_subcommand_execs_real_paladin_tui_on_shared_path` is
  the bare-args smoke test; the companion
  `paladin_tui_subcommand_forwards_vault_to_real_paladin_tui_on_shared_path`
  re-verifies the wrapper-to-binary handoff with `--vault` in the
  argv so the forwarded bytes survive the chain. Both assert
  `success()` and that stderr does not surface the wrapper's
  `exec_paladin_tui` failure tag — its absence after a successful
  exit proves `execvp` resolved `paladin-tui` on the controlled
  `PATH` and the real binary ran to completion. The companion stub-
  based suite in `crates/paladin-cli/tests/cli_exec_tui.rs` continues
  to own the precise argv-forwarding contract and the Flatpak
  `exec_paladin_tui` failure mode. `assert_cmd = "2.0"` is added to
  `crates/paladin-tui/Cargo.toml` `[dev-dependencies]`, matching the
  pin already in `paladin-cli`.)*
- [x] **v0.2 — QR Export modal** per the §"Modals (per §6)"
  `QR Export` entry and DESIGN §4.6 / §6 / §10.
  *(All foundation + save sub-flow + auto-lock + insta-snapshot
  sub-items below ticked. Effect-test PALADIN_FAULT_INJECT bleed
  fixed by hoisting `ENV_LOCK` to file scope as
  `crates/paladin-tui/tests/effect_tests.rs::env_lock`; helpers
  that call `vault.save()` (`create_plaintext_vault`,
  `create_encrypted_vault`, `add_totp_account`,
  `unlocked_with_one_totp`, qr_export's `unlocked_with_one_hotp`,
  copy_code's HOTP helpers) acquire the lock through the
  shared `with_save_env_lock` helper so the fault-injection
  module's env-var toggling can no longer race a clean save.)*
  - [x] Add a new `QrExportModal` variant to the modal enum,
    holding `page: Page::{WarningAck, QrAndActions}`, `ack: bool`,
    `staged_buffers: Option<{ ansi: Zeroizing<String>, png:
    Option<Zeroizing<Vec<u8>>>, svg: Option<Zeroizing<String>> }>`
    (PNG / SVG are populated lazily when the user invokes the
    matching save action), and `last_save_path: Option<PathBuf>`
    (replace-only — a second successful save overwrites the slot,
    per the inline-success contract in §"Modals (per §6)"). Wire
    the `Q` (Shift-q) keybinding from list focus to the reducer
    arm that opens the modal on `Page::WarningAck` against the
    focused account ID.
    *(Foundation slice lands `QrExportPage` / `QrExportFocus` /
    `QrExportModal` in `crates/paladin-tui/src/app/state.rs` plus
    the `Modal::QrExport(_)` variant. The staged-buffer slot is
    collapsed to a single `staged_ansi: Option<Zeroizing<String>>`
    field for the foundation — the lazy `png` / `svg` siblings
    land alongside the save sub-flow slice. `Q` is threaded
    through `pending_qr_export_for_char` and
    `dispatch_unlocked_char` so the binding opens the modal on
    Page 1 against the focused account ID, with the standard
    selection-gated silent no-op on empty filtered sets.)*
  - [x] Render the warning body verbatim from
    `paladin_core::format_plaintext_qr_export_warning()` on Page 1
    and the ANSI body from
    `paladin_core::Vault::export_qr_ansi(id)` on Page 2; gate the
    Page 2 mount on `ack == true` so a closing-terminal glimpse
    cannot expose the secret.
    *(`crates/paladin-tui/src/view/qr.rs` renders Page 1 (warning
    + ack checkbox + Cancel button) and Page 2 (caption + cached
    ANSI body + Save PNG / Save SVG / Done button row). The Page
    2 mount is gated on the reducer's `staged_ansi` cache, which
    is populated by [`toggle_qr_export_ack`] only when
    `ack: false → true`. The page-state machine is locked by
    `qr_export_modal_pre_ack_body_does_not_stage_qr`,
    `qr_export_modal_ack_toggle_on_advances_to_page2_and_stages_ansi`,
    and `qr_export_modal_ack_toggle_off_drops_rendered_qr_and_returns_to_page1`.)*
  - [x] Wire `Save as PNG…` and `Save as SVG…` actions through
    `paladin_core::Vault::export_qr_png` /
    `paladin_core::Vault::export_qr_svg` and
    `paladin_core::write_secret_file_atomic` (0600); reuse the
    existing inline overwrite-gate UX from the Export modal so the
    wording stays consistent.
    *(Save sub-flow slice: `QrSaveSubFlow` / `QrSaveFormat` /
    `QrSaveStep` / `QrSaveFocus` types land in
    `crates/paladin-tui/src/app/state.rs`; reducer arms
    (`route_qr_save_sub_flow_input` / `submit_qr_save_sub_flow`)
    own the destination-prompt / overwrite-gate state machine;
    `Effect::QrExport` and `EffectResult::QrExport` carry the
    `Result<PathBuf, PaladinError>` round-trip through
    `execute_qr_export` (which never calls `Vault::save` — both
    `export_qr_png` and `export_qr_svg` take `&self`). View slice
    in `crates/paladin-tui/src/view/qr.rs` paints the destination
    prompt + overwrite gate + inline error / inline success rows
    on Page 2.)*
  - [x] Drop staged ANSI / PNG / SVG buffers on submit, cancel,
    `Esc`, modal close, ack-toggle-off, and auto-lock per
    §"Modals (per §6)". The buffers live in `Zeroizing` wrappers
    so the drop zeroes the bytes in place.
    *(Foundation slice covers ANSI drop on `Esc`, modal close
    (Cancel / Done), and ack-toggle-off — locked by
    `qr_export_modal_esc_closes_modal`,
    `qr_export_modal_enter_on_cancel_button_closes_modal`,
    `qr_export_modal_enter_on_done_button_closes_modal`, and
    `qr_export_modal_ack_toggle_off_drops_rendered_qr_and_returns_to_page1`.
    Save sub-flow slice adds: sub-flow drops on `Esc` inside the
    sub-flow / modal close / ack-toggle-off — locked by
    `qr_export_modal_esc_in_destination_prompt_cancels_save_subflow_and_preserves_page2`,
    `qr_export_modal_esc_in_overwrite_gate_cancels_save_subflow_and_preserves_page2`,
    and `qr_export_modal_ack_toggle_off_drops_save_sub_flow`.
    Auto-lock drop covered by
    `auto_lock_with_qr_export_modal_open_drops_modal_and_rendered_buffers`
    in `tests/auto_lock_tests.rs`. The in-flight PNG / SVG buffer
    is owned by the executor across one `execute_qr_export` call
    and drops when the call returns — no modal state holds the
    bytes.)*
  - [x] Read-only invariant — the reducer's `QrExport`-related
    arms never call any `&mut Vault` method, the executor's
    `execute_qr_*` workers never call `Vault::save`, and the
    save-action workers only call `write_secret_file_atomic` (not
    `Vault::mutate_and_save`). Confirm via the
    `qr_export_modal_open_and_close_does_not_advance_hotp_counter`
    test below.
    *(`route_qr_export_modal_input` and `toggle_qr_export_ack`
    borrow the `Vault` immutably (`&Vault`) for
    `export_qr_ansi`; no `&mut Vault` arm exists for QR Export.
    The save-action executors land in a follow-up slice and will
    inherit the same `&Vault` discipline.)*
  - [x] Add `Q` to the shared keybindings table that backs the
    Help overlay and (per the existing implementation-checklist
    item) the `cargo xtask man` man page generator so the
    keybinding surfaces consistently across all three surfaces.
    *(`crates/paladin-tui/src/keybindings.rs` gets the `Q` row;
    the Help-overlay insta snapshot
    `view_snapshots__snapshot_help_overlay.snap` is updated and
    the `TestBackend` height bumped from 31 to 32 rows to
    accommodate the additional row.)*
  - [x] All `tests/reducer_tests.rs::qr_export_modal_*` bullets
    ticked, the `tests/effect_tests.rs::execute_qr_export_*`
    bullets ticked, and the insta snapshots listed in the
    §"QR Export modal" Tests block locked.
    *(Reducer / effect tests landed across the foundation and
    Save-sub-flow slices; the eight insta snapshots
    (`snapshot_qr_export_modal_*` in
    `crates/paladin-tui/tests/view_snapshots.rs`) lock the
    modal's per-state rendering and pin a regression guard on the
    inline `save_not_committed` / `save_durability_unconfirmed`
    wording so any future change in `render_error_message`
    surfaces here as a diff.)*
- [ ] **v0.2 — Edit modal** per the §"Modals (per §6)" `Edit`
  entry and DESIGN §4.7 / §6 / §10 Milestone 9. Lands the
  `Shift+E` keybinding, the `EditModal` state variant
  (label / issuer / icon-hint controls with the four-option
  segmented icon-hint selector and its sibling slug row),
  `Effect::EditAccountMetadata` + executor wiring through
  `Vault::mutate_and_save` → `Vault::edit_account_metadata`,
  the reducer-side `Vault::find_duplicate_after_edit` pre-flight
  with inline `duplicate_account` rendering (no edit-anyway
  override), the slug-only `validate_icon_hint_slug` path for the
  *Slug:* row, and the `EffectResult::EditAccountMetadata`
  Ok-arm status-line confirmation
  (`format!("Edited {}.", summary_display_label(&summary))`).
  - [x] Add an `EditModal` variant to the modal enum holding the
    label buffer (`tui-input`), issuer buffer (`tui-input`),
    icon-hint selector (four-option segmented), sibling slug
    buffer (`tui-input`; pre-populated at open, enabled only
    when the selector is on *Slug:*), per-row inline-error
    slots, and the focus-cycle cursor; depends on the
    `crates/paladin-tui/src/view/edit.rs` view module landing
    in parallel.
  - [x] Wire `Shift+E` from list focus to the reducer arm that
    opens `EditModal` against the focused `AccountSummary`;
    silently reject `Shift+E` while any other modal is open
    (mirrors the QR Export `Shift+Q` gate). Update
    `crates/paladin-tui/src/keybindings.rs::KEYBINDINGS` and
    re-lock the `snapshot_help_overlay` insta fixture so the
    overlay picks up the new row, bumping the `TestBackend`
    height from 32 to 33 rows to accommodate it (parity with the
    31 → 32 bump the QR-Export `Q` row added).
  - [x] Wire `Effect::EditAccountMetadata { path, account_id,
    edit }` and its executor through
    `Vault::mutate_and_save` → `Vault::edit_account_metadata`,
    routing `Ok` / `save_not_committed` /
    `save_durability_unconfirmed` / `account_not_found` /
    `validation_error` arms into
    `EffectResult::EditAccountMetadata` with the post-edit
    `AccountSummary` carried on the Ok-arm (built by the
    executor via `Vault::get(id).map(Account::summary)` since
    `edit_account_metadata` returns `Result<()>`). The
    `validation_error` arm is defensive — the reducer's
    pre-flight (`[reject-empty, validate_account_edit,
    find_duplicate_after_edit]` in that order) should already
    block any invalid `AccountEdit`, but core re-runs the
    validator and the empty-check inside `edit_account_metadata`
    and the executor must surface the error inline rather than
    panic if the two ever diverge. Note: `validate_account_edit`
    itself does **not** reject the empty `AccountEdit`; the
    empty-rejection is the mutator's responsibility on the
    core side and the reducer's explicit pre-check on the TUI
    side.
  - [ ] All `tests/reducer_tests.rs::edit_modal_*` bullets
    ticked, the executor-side bullets in
    `tests/effect_tests.rs::execute_edit_*` ticked, and the
    Edit-modal insta snapshots
    (`snapshot_edit_modal_default`,
    `snapshot_edit_modal_validation_error`,
    `snapshot_edit_modal_durability_warning`,
    `snapshot_edit_modal_icon_hint_slug_mode`,
    `snapshot_edit_modal_duplicate_account`,
    `snapshot_edit_modal_status_line_confirmation`) locked in
    `crates/paladin-tui/tests/view_snapshots.rs`.
- [ ] **Destroy modal** per the §"Modals (per §6)" `Destroy`
  entry and DESIGN §4.3 / §6 / §12 Milestone 10. Depends on
  `paladin_core::destroy_vault`, `DestroyReport`, and
  `format_destroy_warning` landing in `paladin-core`. Lands the
  `Ctrl-Shift-D` chord, the `DestroyModal` state variant
  (warning body + confirmation `tui-input`),
  `Effect::DestroyVault { path }` + executor wiring through
  `paladin_core::destroy_vault` (no `Vault::mutate_and_save`;
  destroy operates on the path directly), the
  `EffectResult::DestroyVault` arm that drops the held `(Vault,
  Store)` and transitions to `AppState::Missing` /
  create-vault flow with the secret-buffer wipe.
  - [ ] Add a `DestroyModal` variant to the modal enum holding
    the resolved vault path, the resolved `.bak` probe
    (`backup_present: bool`), the warning body string
    (sourced once via `format_destroy_warning` at open time),
    the confirmation `tui-input` buffer, the focused-action
    cursor (defaults to *Cancel*), and the per-modal inline-error
    slot for the partial-failure / symlink paths. The variant
    is reachable from every `AppState` so the modal renders
    over `Missing`, `Locked`, `Unlocked`, and `StartupError`
    alike — depends on the `crates/paladin-tui/src/view/destroy.rs`
    view module landing in parallel.
  - [ ] Wire the `Ctrl-Shift-D` chord into the reducer as a
    universal opener: from `Unlocked` with no modal open, from
    `Locked`, from `StartupError`, from `Missing` /
    create-vault `ChooseMode` / `EnterPassphrase` /
    `ConfirmPlaintext`, and from any other open modal. When
    fired with another modal open, the reducer zeroizes the
    active modal's in-flight secret-bearing buffers (passphrase
    fields, Add URI / secret fields, edit / rename buffers,
    QR ack state, pending duplicate / add-anyway state),
    closes the active modal, and then opens the Destroy modal.
    A second `Ctrl-Shift-D` while the Destroy modal is already
    open is a silent no-op. Update
    `crates/paladin-tui/src/keybindings.rs::KEYBINDINGS` with
    the new row (universal scope) and re-lock the
    `snapshot_help_overlay` insta fixture so the overlay picks
    up the new entry.
  - [ ] Render the unlock, startup-error, and create-vault
    screens' footer hint (`Ctrl+Shift+D delete vault`) sourced
    from the shared `keybindings::KEYBINDINGS` row's label so
    the binding and the hint cannot drift; the list / modal
    screens do not render the footer hint.
  - [ ] Wire `Effect::DestroyVault { path }` and its executor
    through `paladin_core::destroy_vault(path)` directly (the
    executor is the only `paladin-tui` effect arm that does
    **not** go through `Vault::mutate_and_save` — destroy is
    the commit). The executor posts an
    `EffectResult::DestroyVault(Result<DestroyReport,
    PaladinError>)` back through the mpsc channel; the reducer
    routes:
    * `Ok(report)` → drop held `(Vault, Store)`, zeroize every
      secret-bearing UI buffer (passphrase, URI, manual secret,
      pending duplicate state, search query, HOTP reveal +
      in-memory code, pending clipboard auto-clear value, QR
      render bytes), transition to `AppState::Missing` +
      create-vault, and emit a status-line note of
      `Vault deleted.` or
      `Vault deleted (backup remained on disk).` based on
      `report.backup_deleted`.
    * `Err(vault_missing)` → close the modal, status-line
      `Vault already gone.`, transition to `Missing` +
      create-vault.
    * `Err(io_error)` for `vault_file_is_symlink` /
      `backup_file_is_symlink` / `unlink_vault_file` /
      `unlink_backup_file` / `fsync_vault_dir` → keep the modal
      open with an inline error label naming the failing path
      and the partial `DestroyReport`
      (`primary_deleted` / `backup_deleted`) so the user can
      decide whether to retry or quit.
    * Any other error → keep the modal open with the inline
      error and the `format_unsafe_permissions`-style rendering
      already used elsewhere.
  - [ ] Wire auto-lock interaction: if the auto-lock idle
    deadline fires while the Destroy modal is open and the
    destroy effect has **not** dispatched, the reducer
    zeroizes the partial confirmation buffer, closes the
    modal, and transitions to `Locked` (or `Missing` if the
    vault is plaintext). If the destroy effect has already
    dispatched, the auto-lock fires after the
    `EffectResult::DestroyVault` is processed (the executor
    posts the result before the channel is dropped); the
    reducer state on receipt is whichever the result-routing
    branch dictates.
  - [ ] All `tests/destroy_tests.rs` bullets ticked (see the
    Destroy-modal test section), the executor-side bullets in
    `tests/effect_tests.rs::execute_destroy_vault_*` ticked, and
    the Destroy-modal insta snapshots
    (`snapshot_destroy_modal_default`,
    `snapshot_destroy_modal_confirmation_filled`,
    `snapshot_destroy_modal_no_backup`,
    `snapshot_destroy_modal_partial_failure_backup`,
    `snapshot_destroy_modal_partial_failure_fsync`,
    `snapshot_destroy_modal_symlink_rejection`,
    `snapshot_unlock_footer_hint`,
    `snapshot_startup_error_footer_hint`,
    `snapshot_status_line_vault_deleted`,
    `snapshot_status_line_vault_deleted_backup_remained`) locked
    in `crates/paladin-tui/tests/view_snapshots.rs`.

## Definition of done

- All keybindings + modals from §6 implemented.
- **Every Tests checklist item above is ticked** — including the
  reducer, vim-style navigation, search, auto-lock, clipboard
  auto-clear, terminal lifecycle, global args, every modal (Add,
  Import, Export, **QR Export** (v0.2), **Edit** (v0.2), Settings,
  Rename), pre-commit save rollback, HOTP reveal window, sensitive
  UI buffers, vault modes / startup, and every insta snapshot. The
  "Add reducer, search, auto-lock, clipboard, HOTP reveal,
  terminal lifecycle, sensitive-buffer, and snapshot coverage"
  implementation-checklist item ticks only when this gate is met.
- **v0.2 — QR Export modal:** `Q` from list focus opens the modal,
  the warning-ack gate prevents pre-ack rendering, the ANSI body
  matches `Vault::export_qr_ansi(id)`, Save-as-PNG / Save-as-SVG
  route through `write_secret_file_atomic` (0600) with the inline
  overwrite gate, HOTP counters and `updated_at` are unchanged
  across modal open / close / save, and auto-lock drops the
  rendered buffers alongside the in-memory vault.
- **v0.2 — Edit modal:** `Shift+E` from list focus opens the modal
  with Label / Issuer / Icon-hint controls pre-populated from the
  selected `AccountSummary`; submit runs the pre-check sequence
  `[reject-empty, validate_account_edit,
  find_duplicate_after_edit]` (in that exact order, first failure
  short-circuits) and (on a clean pre-flight) dispatches
  `Effect::EditAccountMetadata` which wraps
  `Vault::edit_account_metadata` inside `Vault::mutate_and_save`.
  Empty edits and duplicate collisions reject inline without
  mutating the vault; successful saves close the modal and post
  `StatusLine::Confirmation(format!("Edited {}.",
  summary_display_label(&summary)))`. The acceptance criteria
  for this milestone are the five outcomes:
  (1) the four-case issuer WYSIWYS projection from §6
  round-trips cleanly across the reducer;
  (2) the five-case icon-hint projection (incl. literal
  `default` / `none` slug under *Slug:*) round-trips cleanly;
  (3) the locked pre-check ordering above is asserted by a
  `tests/reducer_tests.rs` arm that pins all-three-failing →
  empty fires first;
  (4) the explicit reducer-side empty rejection is asserted
  with the body-slot `validation_error { field: "edit",
  reason: "empty" }`;
  (5) the modal closes only on the Ok-arm of
  `EffectResult::EditAccountMetadata` — every failing arm
  (`save_not_committed`, `save_durability_unconfirmed`,
  `validation_error`, `duplicate_account`) keeps the modal
  open with row buffers intact. HOTP counters and the
  account's secret bytes are unchanged across modal open / close
  / save (the modal exposes no OTP-affecting fields, render is
  independent of `AccountKind`, HOTP read-only fields are
  *omitted* not display-disabled), and auto-lock silently drops
  the modal and its row buffers alongside the in-memory vault.
- Auto-lock + clipboard-clear are off by default and behave per §6 when
  enabled, including the plaintext-vault no-op.
- HOTP reveal rows show the counter used for the visible code, then return
  to the stored next counter when hidden.
- Insta snapshots locked for every screen state.
- `paladin tui` (CLI exec wrapper) launches this binary successfully in
  native/shared-`PATH` installs and has the documented Flatpak failure mode.
- Missing vaults open the in-app create-vault flow; the flow walks
  the user through mode choice and (for encrypted) passphrase entry
  with confirmation, calls `paladin_core::create` + `Vault::save`,
  lands on `Unlocked` with an empty list on success, and stays on
  the create-vault screen with an inline error (and zeroized
  passphrase buffer) on failure — without mutating files before the
  final confirmation.
- Vault-path resolution failures and non-`decrypt_failed` `inspect` /
  `open` errors surface on the non-mutating startup-error screen, with
  `unsafe_permissions` rendered via `format_unsafe_permissions`.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
