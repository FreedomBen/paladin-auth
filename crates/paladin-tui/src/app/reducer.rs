// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure reducer: `(state, event) → (state, Vec<Effect>)`.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)" this
//! function is the only place the TUI's state transitions live, so
//! every transition is unit-testable without a terminal. Impure
//! side effects are returned as [`Effect`] values and executed by
//! the `run` boundary; the reducer itself never touches the
//! filesystem, clipboard, or core save paths.

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_core::{PaladinError, Store, Vault};

use crate::app::event::{AppEvent, Effect, EffectResult};
use crate::app::state::{render_error_message, AppState};

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
/// Tick and clipboard-clear events are passthrough in terminal
/// screens; their behavior fills in alongside the corresponding
/// state slices (HOTP reveal expiry, auto-lock, clipboard auto-clear).
#[must_use]
pub fn reduce(state: AppState, event: AppEvent) -> (AppState, Vec<Effect>) {
    match event {
        AppEvent::Input(input) => reduce_input(state, &input),
        AppEvent::EffectResult(result) => reduce_effect_result(state, result),
        AppEvent::Tick { .. } | AppEvent::ClipboardClear { .. } => (state, Vec::new()),
    }
}

/// Apply an `EffectResult` delivered by the `run` boundary.
fn reduce_effect_result(state: AppState, result: EffectResult) -> (AppState, Vec<Effect>) {
    match result {
        EffectResult::Unlock(open) => reduce_unlock_result(state, open),
    }
}

/// Handle the outcome of an [`Effect::Unlock`].
///
/// Only `AppState::Unlock` accepts the result; any other state means
/// the user navigated away (auto-lock, quit-in-flight, …) and the
/// late result is dropped. The carried `(Vault, Store)` zeroizes on
/// drop, so discarding is safe.
fn reduce_unlock_result(
    state: AppState,
    open: Result<(Vault, Store), PaladinError>,
) -> (AppState, Vec<Effect>) {
    match state {
        AppState::Unlock {
            path, passphrase, ..
        } => match open {
            Ok((vault, store)) => (AppState::Unlocked { path, vault, store }, Vec::new()),
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
