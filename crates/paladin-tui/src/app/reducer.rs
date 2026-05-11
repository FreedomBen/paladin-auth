// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure reducer: `(state, event) → (state, Vec<Effect>)`.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" this
//! function is the only place the TUI's state transitions live, so
//! every transition is unit-testable without a terminal. Impure
//! side effects are returned as [`Effect`] values and executed by
//! the `run` boundary; the reducer itself never touches the
//! filesystem, clipboard, or core save paths.

use std::time::Instant;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_core::{AccountId, ClipboardClearToken, IdlePolicy, PaladinError, Store, Vault};

use crate::app::event::{AppEvent, Effect, EffectResult};
use crate::app::state::{
    compute_idle_deadline, initial_selection, render_error_message, AppState, ChordLeader, Focus,
    Modal,
};
use crate::search::{filtered_account_ids, select_after_search};

/// Apply one event to the current state and return the new state plus
/// any side effects.
///
/// This slice covers the global quit keybindings, the Unlock screen's
/// passphrase-input handling, and the [`EffectResult::Unlock`] outcome
/// from `IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)",
/// "Focus model", and "Startup / vault modes":
///
/// * `Ctrl-C` quits on any screen.
/// * `Esc` quits on `MissingVault`, `StartupError`, and `Unlock`.
/// * `q` quits on `MissingVault` and `StartupError`; on `Unlock` it
///   is a valid passphrase character and is appended to the buffer.
/// * On `Unlock`, printable characters (no Ctrl/Alt modifier) append
///   to the passphrase buffer, `Backspace` pops the last character,
///   and `Enter` with a non-empty buffer emits a single
///   [`Effect::Unlock`] and clears the buffer in place.
/// * [`EffectResult::Unlock`] on `Unlock` transitions to `Unlocked` on
///   success, surfaces `decrypt_failed` inline on `Err(DecryptFailed)`,
///   and transitions to `StartupError` for any other open error.
///   Results delivered while not on `Unlock` (e.g. auto-locked between
///   submit and result) are discarded and the carried `(Vault, Store)`
///   drops.
///
/// `AppEvent::Tick` additionally drives the auto-lock `Unlocked →
/// Locked` transition when the current `Unlocked` state carries an
/// `idle_deadline` and [`paladin_core::IdlePolicy::is_expired`]
/// returns `true` for the tick's `monotonic` instant — per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)". The carried
/// `Vault` / `Store` drop in place on the transition. Ticks with no
/// deadline, before the deadline, or on non-`Unlocked` screens are
/// passthrough.
///
/// [`AppEvent::ClipboardClear`] on [`AppState::Locked`] with a
/// matching-token `pending_clipboard_clear` hands the wipe off as an
/// [`Effect::ClearClipboard`] and clears the pending slot — per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
/// *"A clipboard auto-clear timer scheduled before lock survives
/// lock and still fires only-if-unchanged."* Stale-token wakes,
/// `None`-pending wakes, and wakes on non-`Locked` states are
/// passthrough at this slice; the `Unlocked` branch lands alongside
/// the clipboard adapter / copy slice.
///
/// `AppEvent::Input` additionally rebases the auto-lock idle deadline
/// on the event's `at` timestamp when the post-dispatch state is
/// `Unlocked`, per `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
/// *"Idle is reset by any `AppEvent::Input`."* The rebase delegates to
/// [`compute_idle_deadline`] so the plaintext / disabled `None` cases
/// fall out of [`paladin_core::IdlePolicy::should_arm`] rather than a
/// local copy of the rule.
#[must_use]
pub fn reduce(state: AppState, event: AppEvent) -> (AppState, Vec<Effect>) {
    match event {
        AppEvent::Input { event: input, at } => {
            let (state, effects) = reduce_input(state, &input);
            (refresh_idle_deadline_on_input(state, at), effects)
        }
        AppEvent::EffectResult(result) => reduce_effect_result(state, result),
        AppEvent::Tick { monotonic, .. } => (maybe_auto_lock(state, monotonic), Vec::new()),
        AppEvent::ClipboardClear { token, .. } => reduce_clipboard_clear_wake(state, token),
    }
}

/// Transition `Unlocked → Locked` when the auto-lock idle deadline has
/// expired at `now`. Other states and `Unlocked` with no / unexpired
/// deadline pass through unchanged. The expiry decision delegates to
/// [`paladin_core::IdlePolicy::is_expired`] so the TUI shares
/// monotonic-clock comparison semantics with the GUI.
///
/// On lock the `Vault`, `Store`, search query, open HOTP reveal
/// window, open modal, and idle deadline drop in place through the
/// variant change; any pending clipboard auto-clear is carried onto
/// the resulting [`AppState::Locked`] so the timer thread's wake
/// event still finds pending state to act on. Per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
/// *"Locking discards the Vault / Store, open HOTP reveal windows,
/// the search query, and any modal while retaining the resolved
/// vault path…"* and *"A clipboard auto-clear timer scheduled before
/// lock survives lock and still fires only-if-unchanged."*
fn maybe_auto_lock(state: AppState, now: Instant) -> AppState {
    let AppState::Unlocked {
        idle_deadline: Some(deadline),
        ..
    } = &state
    else {
        return state;
    };
    if !IdlePolicy::is_expired(*deadline, now) {
        return state;
    }
    let AppState::Unlocked {
        path,
        pending_clipboard_clear,
        ..
    } = state
    else {
        unreachable!("variant checked immediately above");
    };
    AppState::Locked {
        path,
        pending_clipboard_clear,
    }
}

/// Handle a delayed [`AppEvent::ClipboardClear`] wake from a one-shot
/// timer thread.
///
/// On [`AppState::Locked`] with a matching-token
/// `pending_clipboard_clear`, hands the wipe off to the executor as
/// [`Effect::ClearClipboard`] carrying the captured bytes from state
/// and clears `pending_clipboard_clear` so a duplicate wake is a
/// no-op. The live-clipboard read and
/// [`paladin_core::ClipboardClearPolicy::should_clear`] decision live
/// in the executor — per `IMPLEMENTATION_PLAN_03_TUI.md`
/// "Clipboard auto-clear (per §6)": *"on wake, it ignores stale
/// tokens, reads the current clipboard, asks
/// `ClipboardClearPolicy::should_clear`, and writes empty when the
/// policy returns `true`."*
///
/// Stale tokens (a fresher copy has issued a new token and replaced
/// the pending state) and a `None` pending state are both no-ops:
/// state unchanged, no effect.
///
/// The pre-lock (`Unlocked`) branch lands alongside the clipboard
/// adapter / copy slice; this slice only covers the `Locked` path so
/// the lock-survival contract of bullet 7 holds end-to-end.
fn reduce_clipboard_clear_wake(
    state: AppState,
    event_token: ClipboardClearToken,
) -> (AppState, Vec<Effect>) {
    let AppState::Locked {
        path,
        pending_clipboard_clear: Some(pending),
    } = state
    else {
        return (state, Vec::new());
    };
    if pending.token != event_token {
        return (
            AppState::Locked {
                path,
                pending_clipboard_clear: Some(pending),
            },
            Vec::new(),
        );
    }
    (
        AppState::Locked {
            path,
            pending_clipboard_clear: None,
        },
        vec![Effect::ClearClipboard {
            value: pending.value,
        }],
    )
}

/// Rebase [`AppState::Unlocked::idle_deadline`] on `at` when the
/// post-Input state is `Unlocked`. No-op for every other variant —
/// non-`Unlocked` screens carry no idle deadline.
fn refresh_idle_deadline_on_input(mut state: AppState, at: Instant) -> AppState {
    if let AppState::Unlocked {
        ref mut idle_deadline,
        ref vault,
        ..
    } = state
    {
        *idle_deadline = compute_idle_deadline(at, vault);
    }
    state
}

/// Apply an `EffectResult` delivered by the `run` boundary.
fn reduce_effect_result(state: AppState, result: EffectResult) -> (AppState, Vec<Effect>) {
    match result {
        EffectResult::Unlock { result, opened_at } => {
            reduce_unlock_result(state, result, opened_at)
        }
    }
}

/// Handle the outcome of an [`Effect::Unlock`].
///
/// Only `AppState::Unlock` accepts the result; any other state means
/// the user navigated away (auto-lock, quit-in-flight, …) and the
/// late result is dropped. The carried `(Vault, Store)` zeroizes on
/// drop, so discarding is safe.
///
/// On `Ok`, the auto-lock idle deadline is seeded from the executor's
/// `opened_at` instant via [`compute_idle_deadline`] (which delegates
/// to [`paladin_core::IdlePolicy::next_deadline`]).
fn reduce_unlock_result(
    state: AppState,
    open: Result<(Vault, Store), PaladinError>,
    opened_at: Instant,
) -> (AppState, Vec<Effect>) {
    match state {
        AppState::Unlock {
            path, passphrase, ..
        } => match open {
            Ok((vault, store)) => {
                let idle_deadline = compute_idle_deadline(opened_at, &vault);
                let selected = initial_selection(&vault);
                (
                    AppState::Unlocked {
                        path,
                        vault,
                        store,
                        search_query: String::new(),
                        idle_deadline,
                        pending_clipboard_clear: None,
                        hotp_reveal: None,
                        modal: None,
                        selected,
                        pending_chord_leader: None,
                        viewport_height: 0,
                        viewport_offset: 0,
                        focus: Focus::List,
                    },
                    Vec::new(),
                )
            }
            Err(PaladinError::DecryptFailed) => (
                AppState::Unlock {
                    path,
                    error: Some(render_error_message(&PaladinError::DecryptFailed)),
                    passphrase,
                },
                Vec::new(),
            ),
            Err(err) => (
                AppState::StartupError {
                    path: Some(path),
                    message: render_error_message(&err),
                },
                Vec::new(),
            ),
        },
        other => (other, Vec::new()),
    }
}

/// Apply a `crossterm` input event.
fn reduce_input(state: AppState, event: &Event) -> (AppState, Vec<Effect>) {
    let Event::Key(key) = event else {
        // Resize / focus / paste / mouse events are passthrough at
        // this slice; specific handlers (e.g. resize-driven viewport
        // recompute) land with their state slices.
        return (state, Vec::new());
    };

    if is_ctrl_c(key) {
        return (state, vec![Effect::Quit]);
    }

    if matches!(key.code, KeyCode::Esc) && quits_on_esc(&state) {
        return (state, vec![Effect::Quit]);
    }

    if matches!(state, AppState::Unlock { .. }) {
        return reduce_unlock_input(state, key);
    }

    if matches!(state, AppState::Unlocked { .. }) {
        return reduce_unlocked_input(state, key);
    }

    match key.code {
        KeyCode::Char('q') if quits_on_q(&state) => (state, vec![Effect::Quit]),
        _ => (state, Vec::new()),
    }
}

/// Handle a key event on the Unlocked (main list) screen.
///
/// Three transitions land in this slice, all from
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)":
///
/// * **Modal openers** (seven bare-letter keys):
///
///   | Key | Modal              |
///   | --- | ------------------ |
///   | `a` | [`Modal::Add`]     |
///   | `i` | [`Modal::Import`]  |
///   | `e` | [`Modal::Export`]  |
///   | `r` | [`Modal::Remove`]  |
///   | `R` | [`Modal::Rename`]  |
///   | `p` | [`Modal::Passphrase`] |
///   | `s` | [`Modal::Settings`] |
///
///   All seven fire only when no Ctrl / Alt modifier is held — the
///   corresponding Ctrl- chords are unbound and must not silently
///   open dialogs. Shift is allowed through because the `r` / `R`
///   split relies on the resolved upper-case character. The modal
///   opens only when no modal is currently open; once a modal
///   payload exists, the bare letter inside an open modal is
///   consumed by the modal-local input path. Routing into
///   modal-local input lands alongside each modal's payload slice;
///   at this slice the open-modal case is a no-op so the slot stays
///   unchanged.
///
/// * **`Esc` close-modal / clear-search / clear-chord**: precedence
///   order is `modal-close > search-clear > chord-clear`. With a
///   modal open, `Esc` clears the modal slot to `None` and leaves
///   `focus` / `search_query` untouched — the modal traps focus, so
///   the user returns to the same focus surface that was active
///   before the modal opened. With no modal open and
///   `focus == Focus::Search`, `Esc` clears the search query buffer
///   and returns `focus` to `Focus::List`. With no modal open and
///   `focus == Focus::List`, `Esc` is otherwise a silent no-op —
///   `Unlocked` is intentionally not in `quits_on_esc`'s "no
///   dismissable affordance" set, so the user is never one stray
///   `Esc` away from losing the unlocked session. In every case,
///   any pending vim chord leader is cleared. `Esc` is accepted
///   regardless of modifier so terminals that report Ctrl-Esc or
///   kitty-style augmented Esc still dismiss the modal /
///   search-focus.
///
/// * **`gg` two-press chord** (vim mirror of `Home`): with no modal
///   open, lower-case `g` either sets
///   `pending_chord_leader = Some(ChordLeader::G)` on the first press
///   or commits a jump-to-first on the matching second press
///   (clearing the pending state). Any other key on `Unlocked`,
///   any Ctrl/Alt-modifier press, `Esc`, or a modal open also
///   clears the pending state. There is no time-based clear —
///   vim's `nottimeout` semantics. The chord never engages while
///   a modal is open. The `zz` recenter chord lands alongside the
///   viewport-tracking slice.
fn reduce_unlocked_input(mut state: AppState, key: &KeyEvent) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref path,
        ref mut modal,
        ref mut pending_chord_leader,
        ref mut focus,
        ref mut search_query,
        ref vault,
        ref mut selected,
        ..
    } = state
    else {
        // Caller ensures we're in Unlocked; defensive fall-through
        // keeps the reducer total.
        return (state, Vec::new());
    };

    if matches!(key.code, KeyCode::Esc) {
        // Modifier-agnostic: any Esc clears pending chord state and
        // then dispatches to the highest-precedence dismissable
        // affordance — modal close, then search clear. The modal
        // traps focus, so closing it leaves `focus` / `search_query`
        // intact and the user returns to the same focus surface.
        // With no modal open and `Focus::Search`, Esc clears the
        // query buffer and swings focus back to the list. On
        // `Focus::List` with no modal, Esc is otherwise a silent
        // no-op (chord clear above is the only state change).
        *pending_chord_leader = None;
        if modal.is_some() {
            *modal = None;
        } else if *focus == Focus::Search {
            *focus = Focus::List;
            search_query.clear();
        }
        return (state, Vec::new());
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        // `Ctrl-F` / `Ctrl-B` are the vim mirrors of `PgDn` / `PgUp`
        // and `Ctrl-D` / `Ctrl-U` are the vim half-page bindings
        // (move by `viewport_height / 2` rows, integer division)
        // when no modal is open. All four route through the same
        // [`move_selection`] path, so `viewport_height = 0` and the
        // empty filtered set stay silent no-ops, and the chord
        // leader is cleared before the page step runs. The
        // half-page variants additionally no-op on
        // `viewport_height = 1` (half = 0). Strict equality on
        // `KeyModifiers::CONTROL` keeps Ctrl-Shift-* / Ctrl-Alt-*
        // out (mirroring the existing `Ctrl-Shift-G is unbound`
        // convention) — only the bare Ctrl chord engages. With a
        // modal open, these keys mirror the modal-routing no-op of
        // `PgDn` / `PgUp`. All other Ctrl/Alt-modifier presses are
        // unbound at this slice but still clear any pending chord
        // state — chord commitment requires a bare second press.
        *pending_chord_leader = None;
        if modal.is_none() && key.modifiers == KeyModifiers::CONTROL {
            match key.code {
                KeyCode::Char('f') => return move_selection(state, ListStep::PageDown),
                KeyCode::Char('b') => return move_selection(state, ListStep::PageUp),
                KeyCode::Char('d') => return move_selection(state, ListStep::HalfPageDown),
                KeyCode::Char('u') => return move_selection(state, ListStep::HalfPageUp),
                _ => {}
            }
        }
        return (state, Vec::new());
    }

    if modal.is_some() {
        // A modal is open: bare-letter keys belong to the
        // modal-local input path (handled in later slices) and
        // any pending chord state is cleared.
        *pending_chord_leader = None;
        return (state, Vec::new());
    }

    // Modal is None below here.

    if *focus == Focus::Search {
        *pending_chord_leader = None;
        if route_search_focus_char(search_query, selected, vault, key) {
            return (state, Vec::new());
        }
    }

    // `gg` chord: first press sets pending leader, matching second
    // press commits jump-to-first. Handled before list-step / modal
    // openers so the bare `g` is consumed by the chord path. `z` on a
    // pending `g` cross-clears `g` and arms `z` — handled below by
    // the symmetric `z` branch.
    if matches!(key.code, KeyCode::Char('g')) {
        let was_pending = matches!(*pending_chord_leader, Some(ChordLeader::G));
        *pending_chord_leader = None;
        if was_pending {
            return move_selection(state, ListStep::First);
        }
        if let AppState::Unlocked {
            pending_chord_leader,
            ..
        } = &mut state
        {
            *pending_chord_leader = Some(ChordLeader::G);
        }
        return (state, Vec::new());
    }

    // `zz` chord (vim recenter): first press sets pending leader,
    // matching second press commits a viewport recenter on the
    // selected row. A pending `z` followed by any non-`z` key
    // (including `g`) cross-clears the leader; `g` then re-arms its
    // own leader through the `g` branch above. The recenter
    // resolves `sel_pos = vault.iter().position(selected)` and sets
    // `viewport_offset = (sel_pos - viewport_height / 2)` with
    // `saturating_sub` so near-the-top selections clamp to `0`.
    // Empty filtered set, `selected = None`, and `viewport_height
    // = 0` are silent no-ops; the chord leader is still cleared.
    if matches!(key.code, KeyCode::Char('z')) {
        let was_pending = matches!(*pending_chord_leader, Some(ChordLeader::Z));
        *pending_chord_leader = None;
        if was_pending {
            return recenter_viewport(state);
        }
        if let AppState::Unlocked {
            pending_chord_leader,
            ..
        } = &mut state
        {
            *pending_chord_leader = Some(ChordLeader::Z);
        }
        return (state, Vec::new());
    }

    // Any other key on the list (matching or not) clears the
    // pending chord state before its own action runs.
    *pending_chord_leader = None;

    if let Some(step) = list_step_for_key(key.code) {
        return move_selection(state, step);
    }

    if let KeyCode::Char(c) = key.code {
        let n_effects = if c == 'n' {
            hotp_advance_effect(path, vault, *selected)
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        return dispatch_unlocked_char(state, c, n_effects);
    }

    (state, Vec::new())
}

/// Dispatch the post-chord-clear bare-letter Char handling on
/// Unlocked / `Focus::List` (modal-already-open is filtered out
/// upstream).
///
/// Owns the small terminal-letter table: `q` → quit, `/` → focus the
/// search bar, `n` → emit the precomputed HOTP-advance effects, and
/// the `modal_opener_for_char` table (`a`/`i`/`e`/`r`/`R`/`p`/`s`).
/// `n_effects` carries the [`Effect::HotpAdvance`] list precomputed by
/// the caller (empty when the binding is a silent no-op — TOTP
/// selection, no selection, or selection missing from the vault) so
/// this helper never needs to touch the still-borrowed vault.
fn dispatch_unlocked_char(
    mut state: AppState,
    c: char,
    n_effects: Vec<Effect>,
) -> (AppState, Vec<Effect>) {
    // `q` quits Unlocked when no modal is open. (Once the search bar
    // can take focus, `q` is text input on the search surface too;
    // that gating lands with the focus-state slice.)
    if c == 'q' {
        return (state, vec![Effect::Quit]);
    }
    // `/` focuses the search bar from the list per the §6 "Focus
    // model" rule. The modal guard above already short-circuits when
    // a modal traps focus, and the chord leader was cleared just
    // above this Char block, so the only remaining work is the
    // `Focus::List -> Focus::Search` transition. Pressing `/` while
    // already in `Focus::Search` is a silent no-op at this slice —
    // character routing into the search field (which would type `/`
    // literally) lands alongside the search-focus typing pass-through.
    if c == '/' {
        if let AppState::Unlocked { focus, .. } = &mut state {
            *focus = Focus::Search;
        }
        return (state, Vec::new());
    }
    if c == 'n' {
        return (state, n_effects);
    }
    if let Some(opened) = modal_opener_for_char(c) {
        if let AppState::Unlocked { modal, .. } = &mut state {
            *modal = Some(opened);
        }
        return (state, Vec::new());
    }
    (state, Vec::new())
}

/// Build the [`Effect::HotpAdvance`] for the selected account, or
/// `None` when the binding is a silent no-op.
///
/// Returns `Some(Effect::HotpAdvance { path, account_id })` only when
/// (a) `selected` resolves to a vault account and (b) the account's
/// kind is [`AccountKindSummary::Hotp`]. TOTP accounts, an empty
/// selection, and a selected id missing from the vault all yield
/// `None` so the reducer surfaces no effect — the status-line "not an
/// HOTP account" hint and "no account selected" hint land with the
/// status-line slice, never with the reducer.
fn hotp_advance_effect(
    path: &std::path::Path,
    vault: &Vault,
    selected: Option<AccountId>,
) -> Option<Effect> {
    let id = selected?;
    let account = vault.iter().find(|a| a.id() == id)?;
    if account.kind() != paladin_core::AccountKindSummary::Hotp {
        return None;
    }
    Some(Effect::HotpAdvance {
        path: path.to_path_buf(),
        account_id: id,
    })
}

/// Step direction for list selection navigation.
///
/// `Up` / `Down` are single-row adjacency steps. `First` / `Last` are
/// absolute jumps to the head / tail of `Vault::iter()` (insertion
/// order), used by `Home` and `End`. `PageUp` / `PageDown` walk by
/// `AppState::Unlocked::viewport_height` rows (insertion order),
/// clamping at the head / tail when fewer rows remain — used by `PgUp`
/// / `PgDn` and their `Ctrl-B` / `Ctrl-F` vim mirrors.
/// `HalfPageUp` / `HalfPageDown` walk by
/// `AppState::Unlocked::viewport_height / 2` rows (integer division),
/// with the same clamp behavior — used by the vim-style `Ctrl-U` /
/// `Ctrl-D` half-page bindings. A `viewport_height` of `0` or `1`
/// (half = 0 by integer division) is a silent no-op for the half-page
/// variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListStep {
    Up,
    Down,
    First,
    Last,
    PageUp,
    PageDown,
    HalfPageUp,
    HalfPageDown,
}

/// Map a list-navigation key to its step direction.
///
/// `↑` / `↓` and the vim mirrors `k` / `j` step the selection by one
/// row. `Home` / `End` jump to the first / last row of `Vault::iter()`
/// (insertion order); upper-case `G` (Shift+g — crossterm reports the
/// resolved `KeyCode::Char('G')`, with or without `KeyModifiers::SHIFT`
/// depending on the terminal) is the vim mirror of `End`. `PgUp` /
/// `PgDn` walk by [`AppState::Unlocked::viewport_height`] rows,
/// clamping at the first / last row of the iteration. Returns `None`
/// for keys that are not list navigation; the `gg` chord leader
/// (lower-case `g`) is consumed before this dispatch and the
/// `Ctrl-B` / `Ctrl-F` page mirrors plus `Ctrl-U` / `Ctrl-D`
/// half-page bindings are routed through the Ctrl/Alt guard in
/// [`reduce_unlocked_input`] (so they reuse the
/// [`ListStep::PageDown`] / [`ListStep::PageUp`] /
/// [`ListStep::HalfPageDown`] / [`ListStep::HalfPageUp`] steps from
/// here). The `zz` recenter chord lands in a later slice.
fn list_step_for_key(code: KeyCode) -> Option<ListStep> {
    match code {
        KeyCode::Down | KeyCode::Char('j') => Some(ListStep::Down),
        KeyCode::Up | KeyCode::Char('k') => Some(ListStep::Up),
        KeyCode::Home => Some(ListStep::First),
        KeyCode::End | KeyCode::Char('G') => Some(ListStep::Last),
        KeyCode::PageDown => Some(ListStep::PageDown),
        KeyCode::PageUp => Some(ListStep::PageUp),
        _ => None,
    }
}

/// Move the Unlocked list selection per `step`.
///
/// All step variants walk the **filtered** insertion-order set derived
/// from `search_query` via [`filtered_account_ids`], not the unfiltered
/// `Vault::iter()`, so navigation honors the active search filter per
/// the §6 "Search filter narrows the visible list in place" rule. For
/// `Up` / `Down`, picks the row adjacent to the currently selected
/// `AccountId` within the filtered set; clamping at top / bottom leaves
/// the selection unchanged. For `First` / `Last`, assigns the head /
/// tail of the filtered set directly. For `PageUp` / `PageDown`, walks
/// the filtered set by `viewport_height` rows, clamping at head / tail
/// when fewer filtered rows remain. A `viewport_height` of `0`
/// (pre-resize seed) is a silent no-op. An empty filtered set
/// (`selected = None`, no rows match) is a silent no-op in every
/// direction. The reducer never emits effects for navigation — these
/// are pure state updates.
fn move_selection(mut state: AppState, step: ListStep) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref vault,
        ref search_query,
        ref mut selected,
        viewport_height,
        viewport_offset: 0,
        ..
    } = state
    else {
        return (state, Vec::new());
    };
    let ids = filtered_account_ids(vault, search_query);
    match step {
        ListStep::Up | ListStep::Down => {
            if let Some(current) = *selected {
                if let Some(next) = adjacent_in_filtered(&ids, current, step) {
                    *selected = Some(next);
                }
            }
        }
        ListStep::First => {
            *selected = ids.first().copied();
        }
        ListStep::Last => {
            *selected = ids.last().copied();
        }
        ListStep::PageDown | ListStep::PageUp => {
            if let Some(current) = *selected {
                if let Some(next) = step_n_rows(&ids, current, step, viewport_height as usize) {
                    *selected = Some(next);
                }
            }
        }
        ListStep::HalfPageDown | ListStep::HalfPageUp => {
            if let Some(current) = *selected {
                // Half-page uses integer division: viewport_height = 1
                // yields n = 0 (no-op) which matches vim's
                // behavior — half-page is undefined on a one-row
                // viewport.
                let n = (viewport_height as usize) / 2;
                if let Some(next) = step_n_rows(&ids, current, step, n) {
                    *selected = Some(next);
                }
            }
        }
    }
    (state, Vec::new())
}

/// Commit a `zz` recenter: set [`AppState::Unlocked::viewport_offset`]
/// so the selected row sits in the middle of the viewport.
///
/// Computes `sel_pos` as the position of the selection within the
/// **filtered** insertion-order set (`filtered_account_ids`) so the
/// offset matches the rendered list when a search query is active, then
/// assigns `viewport_offset = sel_pos.saturating_sub(viewport_height / 2)`.
/// The lower-bound saturation keeps near-the-top selections at offset
/// `0`; the renderer is responsible for any upper-bound clamping when
/// the resize-driven viewport slice lands. Silent no-op when
/// `selected = None`, the selected id is not present in the filtered
/// set, or `viewport_height = 0` — `viewport_offset` is unchanged in
/// every no-op case.
fn recenter_viewport(mut state: AppState) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked {
        ref vault,
        ref search_query,
        selected,
        viewport_height,
        ref mut viewport_offset,
        ..
    } = state
    else {
        return (state, Vec::new());
    };
    if viewport_height == 0 {
        return (state, Vec::new());
    }
    let Some(current) = selected else {
        return (state, Vec::new());
    };
    let ids = filtered_account_ids(vault, search_query);
    let Some(pos) = ids.iter().position(|id| *id == current) else {
        return (state, Vec::new());
    };
    let half = viewport_height / 2;
    let sel_pos: u16 = u16::try_from(pos).unwrap_or(u16::MAX);
    *viewport_offset = sel_pos.saturating_sub(half);
    (state, Vec::new())
}

/// Return the account adjacent to `current` in the filtered
/// insertion-order set `ids`, or `None` when `current` is at the end
/// of the set in the requested direction (clamp signal) or is absent
/// from the filtered set entirely.
///
/// Only `ListStep::Up` and `ListStep::Down` are valid here; the
/// absolute-jump and page-step variants are handled directly in
/// [`move_selection`].
fn adjacent_in_filtered(
    ids: &[AccountId],
    current: AccountId,
    step: ListStep,
) -> Option<AccountId> {
    let pos = ids.iter().position(|id| *id == current)?;
    match step {
        ListStep::Down => ids.get(pos + 1).copied(),
        ListStep::Up => {
            if pos == 0 {
                None
            } else {
                Some(ids[pos - 1])
            }
        }
        ListStep::First
        | ListStep::Last
        | ListStep::PageDown
        | ListStep::PageUp
        | ListStep::HalfPageDown
        | ListStep::HalfPageUp => {
            unreachable!(
                "First/Last/PageUp/PageDown/HalfPageUp/HalfPageDown are absolute / page jumps handled in move_selection"
            )
        }
    }
}

/// Walk the filtered insertion-order set `ids` by `n` rows up or down
/// from `current`, clamping at the head / tail when fewer rows remain.
///
/// Returns the new `AccountId` when the selection moves, or `None` when
/// the walk would be a no-op (n == 0, `current` already at the
/// boundary in the requested direction, or `current` not found in the
/// filtered set). Used by `ListStep::PageUp` / `ListStep::PageDown`
/// with `n = viewport_height` and by `ListStep::HalfPageUp` /
/// `ListStep::HalfPageDown` with `n = viewport_height / 2`.
fn step_n_rows(
    ids: &[AccountId],
    current: AccountId,
    step: ListStep,
    n: usize,
) -> Option<AccountId> {
    if n == 0 {
        return None;
    }
    let pos = ids.iter().position(|id| *id == current)?;
    let target = match step {
        ListStep::PageDown | ListStep::HalfPageDown => (pos + n).min(ids.len().saturating_sub(1)),
        ListStep::PageUp | ListStep::HalfPageUp => pos.saturating_sub(n),
        ListStep::Up | ListStep::Down | ListStep::First | ListStep::Last => {
            unreachable!("step_n_rows only handles page steps")
        }
    };
    if target == pos {
        None
    } else {
        Some(ids[target])
    }
}

/// Append a typed character to the search-query buffer and recompute
/// the surviving list selection.
///
/// Returns `true` when the key was consumed (printable Char while
/// `Focus::Search`); `false` when the caller should fall through to
/// list-step dispatch — non-Char keys (`↑` / `↓` / `Home` / `End` /
/// `PgUp` / `PgDn`) pass through to the list per the §6 / "Focus
/// model" rule that *"the selection is always navigable so the user
/// does not need to unfocus the search to act on a result"*.
///
/// Ctrl / Alt-modified Chars are returned-early by the Ctrl/Alt
/// guard in [`reduce_unlocked_input`], so this helper only sees bare
/// or Shift-modified Chars (e.g. `KeyCode::Char('G')` with
/// `KeyModifiers::SHIFT`). The chord leader is **not** cleared here —
/// the caller clears it before invoking this routing, mirroring
/// the unconditional-clear pattern used by the Ctrl/Alt guard.
///
/// Selection is recomputed via [`select_after_search`] (composing
/// [`paladin_core::select_after_filter`] with the case-insensitive
/// issuer/label substring filter from
/// [`paladin_core::account_matches_search`]). The prev selection
/// survives if still in the filtered set; otherwise the first match
/// in [`Vault::iter`] insertion order; otherwise `None` when the
/// filtered set is empty.
fn route_search_focus_char(
    search_query: &mut String,
    selected: &mut Option<AccountId>,
    vault: &Vault,
    key: &KeyEvent,
) -> bool {
    if let KeyCode::Char(c) = key.code {
        search_query.push(c);
        *selected = select_after_search(vault, search_query, *selected);
        return true;
    }
    false
}

/// Map a bare-letter Unlocked-screen keybinding to the modal it opens,
/// or `None` if the character is not a modal-open binding.
///
/// Mirrors `IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)"
/// — `r` (lower-case) opens Remove confirmation while `R`
/// (upper-case, via Shift+R) opens Rename. Crossterm reports the
/// resolved character for shifted keys, so the upper-case match arm
/// works for both terminals that forward the Shift modifier and
/// those that swallow it into the case conversion.
fn modal_opener_for_char(c: char) -> Option<Modal> {
    Some(match c {
        'a' => Modal::Add,
        'i' => Modal::Import,
        'e' => Modal::Export,
        'r' => Modal::Remove,
        'R' => Modal::Rename,
        'p' => Modal::Passphrase,
        's' => Modal::Settings,
        _ => return None,
    })
}

/// Handle a key event on the Unlock screen.
///
/// Printable Char input (no Ctrl/Alt modifier) appends to the
/// passphrase buffer. Backspace pops the last char. Enter on a
/// non-empty buffer emits [`Effect::Unlock`] and clears the buffer in
/// place; Enter on an empty buffer is a no-op. Any other key is a
/// no-op.
fn reduce_unlock_input(mut state: AppState, key: &KeyEvent) -> (AppState, Vec<Effect>) {
    let AppState::Unlock {
        ref path,
        ref mut passphrase,
        ..
    } = state
    else {
        // Caller ensures we're in Unlock; defensive fall-through keeps
        // the reducer total.
        return (state, Vec::new());
    };

    match key.code {
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            passphrase.push(c);
            (state, Vec::new())
        }
        KeyCode::Backspace => {
            passphrase.pop();
            (state, Vec::new())
        }
        KeyCode::Enter if !passphrase.is_empty() => {
            let secret = passphrase.take();
            let effect = Effect::Unlock {
                path: path.clone(),
                passphrase: secret,
            };
            (state, vec![effect])
        }
        _ => (state, Vec::new()),
    }
}

/// `Ctrl-C` — quits on any screen.
fn is_ctrl_c(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('c')) && key.modifiers.contains(KeyModifiers::CONTROL)
}

/// `Esc` quits on `Unlock`, `MissingVault`, and `StartupError` screens.
///
/// (Once modals / search / vim chords exist, `Esc` on `Unlocked` will
/// close those first; the always-quit-on-`Esc` set never grows
/// beyond these three "screen with no dismissable affordance"
/// states.)
fn quits_on_esc(state: &AppState) -> bool {
    matches!(
        state,
        AppState::MissingVault { .. } | AppState::StartupError { .. } | AppState::Unlock { .. }
    )
}

/// `q` quits on `MissingVault` and `StartupError`. On `Unlock` it is
/// text input. On `Unlocked` the quit fires from
/// [`reduce_unlocked_input`] under its modal / focus guards; this
/// fallback predicate is only consulted for the remaining "no
/// dedicated handler" states.
fn quits_on_q(state: &AppState) -> bool {
    matches!(
        state,
        AppState::MissingVault { .. } | AppState::StartupError { .. }
    )
}
