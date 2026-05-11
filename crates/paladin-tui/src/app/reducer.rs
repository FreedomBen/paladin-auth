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

use paladin_core::{IdlePolicy, PaladinError, Store, Vault};

use crate::app::event::{AppEvent, Effect, EffectResult};
use crate::app::state::{compute_idle_deadline, render_error_message, AppState};

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
/// Clipboard-clear events are passthrough in this slice; their
/// behavior fills in alongside the clipboard auto-clear slice.
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
        AppEvent::ClipboardClear { .. } => (state, Vec::new()),
    }
}

/// Transition `Unlocked → Locked` when the auto-lock idle deadline has
/// expired at `now`. Other states and `Unlocked` with no / unexpired
/// deadline pass through unchanged. The expiry decision delegates to
/// [`paladin_core::IdlePolicy::is_expired`] so the TUI shares
/// monotonic-clock comparison semantics with the GUI.
///
/// On lock the `Vault`, `Store`, search query, open HOTP reveal
/// window, and idle deadline drop in place through the variant
/// change; any pending clipboard auto-clear is carried onto the
/// resulting [`AppState::Locked`] so the timer thread's wake event
/// still finds pending state to act on. Per
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
                (
                    AppState::Unlocked {
                        path,
                        vault,
                        store,
                        search_query: String::new(),
                        idle_deadline,
                        pending_clipboard_clear: None,
                        hotp_reveal: None,
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

    match key.code {
        KeyCode::Char('q') if quits_on_q(&state) => (state, vec![Effect::Quit]),
        _ => (state, Vec::new()),
    }
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

/// `q` quits on `MissingVault`, `StartupError`, and (once focus
/// state is wired) `Unlocked` with the list focused. On `Unlock` it
/// is text input; on `Unlocked` with the search bar or a modal
/// focused it is text input.
///
/// This slice covers the two terminal screens; the list-focus path
/// lands with the list / focus slice.
fn quits_on_q(state: &AppState) -> bool {
    matches!(
        state,
        AppState::MissingVault { .. } | AppState::StartupError { .. }
    )
}
