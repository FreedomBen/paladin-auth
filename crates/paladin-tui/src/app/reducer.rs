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

use crate::app::event::{AppEvent, Effect};
use crate::app::state::AppState;

/// Apply one event to the current state and return the new state plus
/// any side effects.
///
/// This slice covers the global quit keybindings from
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Keybindings (initial v0.1)":
///
/// * `Ctrl-C` quits on any screen.
/// * `Esc` quits on `MissingVault`, `StartupError`, and `Unlock`.
/// * `q` quits on `MissingVault` and `StartupError`; on `Unlock` it
///   will route into the passphrase field once that field exists, so
///   the reducer must currently treat it as a no-op there rather
///   than a quit.
///
/// Tick and clipboard-clear events are passthrough in terminal
/// screens; their behavior fills in alongside the corresponding
/// state slices (HOTP reveal expiry, auto-lock, clipboard auto-clear).
#[must_use]
pub fn reduce(state: AppState, event: AppEvent) -> (AppState, Vec<Effect>) {
    match event {
        AppEvent::Input(input) => reduce_input(state, &input),
        AppEvent::Tick { .. } | AppEvent::ClipboardClear { .. } => (state, Vec::new()),
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

    match key.code {
        KeyCode::Esc if quits_on_esc(&state) => (state, vec![Effect::Quit]),
        KeyCode::Char('q') if quits_on_q(&state) => (state, vec![Effect::Quit]),
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
