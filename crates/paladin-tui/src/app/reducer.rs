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

use paladin_core::{ClipboardClearToken, IdlePolicy, PaladinError, Store, Vault};

use crate::app::event::{AppEvent, Effect, EffectResult};
use crate::app::state::{
    compute_idle_deadline, initial_selection, render_error_message, AppState, Modal,
};

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
/// Two transitions land in this slice, both from
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
/// * **`Esc` close-modal**: with a modal open, `Esc` clears the slot
///   to `None`. With no modal open, `Esc` on `Unlocked` is a silent
///   no-op — `Unlocked` is intentionally not in `quits_on_esc`'s
///   "no dismissable affordance" set, so the user is never one
///   stray `Esc` away from losing the unlocked session. `Esc` is
///   accepted regardless of modifier so terminals that report
///   Ctrl-Esc or kitty-style augmented Esc still dismiss the modal.
///   Search-clear and vim-chord clear are listed under the same
///   `Esc` key in the keybindings table and wire alongside their
///   own slices.
fn reduce_unlocked_input(mut state: AppState, key: &KeyEvent) -> (AppState, Vec<Effect>) {
    let AppState::Unlocked { ref mut modal, .. } = state else {
        // Caller ensures we're in Unlocked; defensive fall-through
        // keeps the reducer total.
        return (state, Vec::new());
    };

    if matches!(key.code, KeyCode::Esc) {
        // Modifier-agnostic: any Esc dismisses an open modal.
        // Search-clear / vim-chord clear are no-ops at this slice;
        // they layer on without disturbing the close-modal contract.
        if modal.is_some() {
            *modal = None;
        }
        return (state, Vec::new());
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return (state, Vec::new());
    }

    if let KeyCode::Char(c) = key.code {
        if modal.is_none() {
            // `q` quits Unlocked when no modal is open. (With a
            // modal open, `q` belongs to the modal-local input
            // path. Once the search bar can take focus, `q` is
            // text input on the search surface too; that gating
            // lands with the focus-state slice.)
            if c == 'q' {
                return (state, vec![Effect::Quit]);
            }
            if let Some(opened) = modal_opener_for_char(c) {
                *modal = Some(opened);
                return (state, Vec::new());
            }
        }
    }

    (state, Vec::new())
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
