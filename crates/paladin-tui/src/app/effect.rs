// SPDX-License-Identifier: AGPL-3.0-or-later

//! Effect executor: the only impure boundary between the pure reducer
//! and `paladin-core` / OS resources.
//!
//! Per `IMPLEMENTATION_PLAN_03_TUI.md` "Event loop (per §6)":
//!
//! > The reducer is a pure function over
//! > `(state, event) → (state, Vec<Effect>)` so it is unit-testable
//! > without a terminal. Effects are executed by `app::run`, which is
//! > the only boundary that may call impure core / clipboard / writer
//! > functions. Save-bearing effects mutate the current `Vault` only
//! > through core APIs ... then send an `AppEvent::EffectResult(...)`
//! > back through the same `mpsc` channel.
//!
//! [`execute`] is the per-effect dispatcher: the run loop calls it for
//! each [`Effect`] the reducer returned. Variants land here in lockstep
//! with the corresponding [`Effect`] variants.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::{Instant, SystemTime};

use paladin_core::{
    parse_icon_hint_token, validate_manual, AccountInput, PaladinError, SettingPatch, Store,
    VaultLock,
};

use crate::app::event::{AddFailure, AppEvent, Effect, EffectResult};
use crate::app::state::AppState;

/// Outcome of executing a single [`Effect`].
///
/// `Quit` is special: it carries no `AppEvent` because the run loop
/// uses the return value to break out of its dispatch loop and drive
/// terminal teardown (raw mode + alternate-screen restoration via the
/// [`crate::terminal::TerminalGuard`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectOutcome {
    /// The run loop should keep dispatching events.
    Continue,
    /// The run loop should exit cleanly. The teardown path is shared
    /// with normal exit, startup failure, `Ctrl-C`, and panic unwind.
    Quit,
}

/// Execute a single effect.
///
/// Save-bearing effects send an [`AppEvent::EffectResult`] back to the
/// reducer through `sender`; [`Effect::Quit`] returns
/// [`EffectOutcome::Quit`] without emitting an `AppEvent`.
///
/// `state` is the run loop's live [`AppState`]. Effects whose target
/// requires the live `(Vault, Store)` — `Rename`, and later
/// `HotpAdvance` / `CopyCode` — read it from
/// [`AppState::Unlocked`]; effects whose target is independent of UI
/// state (`Quit`, `Unlock`, `ClearClipboard`) ignore it.
///
/// If the receiver has already been dropped (the run loop is tearing
/// down), the send is silently ignored. The carried result — including
/// any `(Vault, Store)` pair — drops cleanly, which zeroizes the
/// derived AEAD key inside the `Store` and frees the in-memory vault.
// The dispatcher's body grows linearly with the `Effect` enum; each
// variant adds an inline match arm. The body is structurally trivial
// (one short delegation per variant), so allowing the line budget on
// the dispatcher is cleaner than further splitting it into per-variant
// trampolines.
#[allow(clippy::too_many_lines)]
pub fn execute(effect: Effect, state: &mut AppState, sender: &Sender<AppEvent>) -> EffectOutcome {
    match effect {
        Effect::Quit => EffectOutcome::Quit,
        Effect::Unlock { path, passphrase } => {
            let result = Store::open(&path, VaultLock::Encrypted(passphrase));
            // Sample `opened_at` immediately after `Store::open`
            // so the reducer can seed the auto-lock idle deadline
            // off the same monotonic clock the `Tick` thread uses.
            let opened_at = Instant::now();
            // `send` only fails if the receiver is gone; in that case
            // the app is already tearing down, so dropping the result
            // is correct.
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Unlock {
                result,
                opened_at,
            }));
            EffectOutcome::Continue
        }
        Effect::ClearClipboard { value: _ } => {
            // Placeholder: the live-clipboard read and
            // `ClipboardClearPolicy::should_clear` decision land with
            // the clipboard adapter slice (see
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Implementation
            // checklist": *"Implement clipboard wrapper (arboard
            // reads/writes) … only-if-unchanged auto-clear via
            // `ClipboardClearPolicy::should_clear`."*). For now the
            // captured bytes are dropped here — the reducer has
            // already cleared `pending_clipboard_clear` before this
            // executor arm runs.
            //
            // No `AppEvent` is sent back: clipboard wipe is fire-and-
            // forget at this layer.
            let _ = sender;
            EffectOutcome::Continue
        }
        Effect::HotpAdvance {
            path: _,
            account_id: _,
        } => {
            // Placeholder: the `Vault::hotp_advance` call lands with
            // the run-loop slice that gives the executor access to the
            // live `(Vault, Store)` carried in `AppState::Unlocked`.
            // The reducer side of the round trip is already in place:
            // `EffectResult::HotpAdvance { account_id, result,
            // completed_at }` opens (or replaces) the
            // `AppState::Unlocked::hotp_reveal` slot on `Ok(code)`
            // and is a no-op on `Err(...)` / non-`Unlocked` states.
            // Until the executor wiring lands, the emit is exercised
            // by reducer-level tests
            // (`pressing_n_with_hotp_account_selected_emits_hotp_advance_effect`,
            // `effect_result_hotp_advance_*`) and the executor
            // consumes the variant without emitting an `AppEvent`.
            let _ = sender;
            EffectOutcome::Continue
        }
        Effect::CopyCode {
            path: _,
            account_id: _,
        } => {
            // Placeholder: the `arboard` clipboard write and
            // `ClipboardClearPolicy::schedule` wiring land with the
            // clipboard adapter slice (see
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear":
            // *"Copy schedules a clear via
            // `ClipboardClearPolicy::schedule`."*). The executor
            // needs access to the live `(Vault, Store)` carried in
            // `AppState::Unlocked` to compute the TOTP code or read
            // the HOTP reveal value. Until that wiring lands the
            // reducer emit is exercised by reducer-level tests
            // (`pressing_enter_*_emits_copy_code_effect`, etc.) and
            // the executor consumes the variant without emitting an
            // `AppEvent`.
            let _ = sender;
            EffectOutcome::Continue
        }
        Effect::Remove { path, account_id } => {
            // Run `Vault::remove` inside `Vault::mutate_and_save` so a
            // pre-commit failure (`save_not_committed`) snaps the
            // removed account back to its prior iteration position
            // while post-commit `save_durability_unconfirmed` leaves
            // the account removed in memory matching the on-disk
            // primary, per `IMPLEMENTATION_PLAN_03_TUI.md`
            // "Effect errors" >
            // "Add / remove / rename / settings saves".
            //
            // The closure captures the removed Account's display
            // label (`issuer:label` if issuer is set, else `label`)
            // and returns it through the result; the reducer surfaces
            // this string verbatim in `StatusLine::Confirmation`,
            // mirroring the CLI's "Removed {label}." idiom. `Account`
            // is dropped at the end of the closure — the label is
            // already a `String` owned by the result, so secrets do
            // not leak across the boundary.
            //
            // The path check protects against a stale effect emitted
            // before an auto-lock or vault switch: if the live state
            // is no longer `Unlocked` against the same path, drop the
            // effect silently — the reducer would discard the
            // corresponding `EffectResult::Remove` anyway, and
            // posting back would just synthesize an artificial
            // mutation attempt against unrelated state.
            //
            // A missing `account_id` (defensive — never happens in
            // practice because the reducer snapshots it at modal-open
            // time) becomes
            // `invalid_state { operation: "remove",
            //                 state: "account_not_found" }`, matching
            // the `Vault::rename` not-found shape.
            if let AppState::Unlocked {
                path: state_path,
                vault,
                store,
                ..
            } = state
            {
                if *state_path == path {
                    let result = vault.mutate_and_save(store, |v| {
                        let account = v.remove(account_id).ok_or(PaladinError::InvalidState {
                            operation: "remove",
                            state: "account_not_found",
                        })?;
                        let label = match account.issuer().filter(|i| !i.is_empty()) {
                            Some(issuer) => format!("{issuer}:{}", account.label()),
                            None => account.label().to_string(),
                        };
                        Ok(label)
                    });
                    let _ = sender.send(AppEvent::EffectResult(EffectResult::Remove {
                        account_id,
                        result,
                    }));
                }
            }
            EffectOutcome::Continue
        }
        Effect::ApplySettings { path, patches } => {
            execute_apply_settings(&path, &patches, state, sender)
        }
        Effect::Rename {
            path,
            account_id,
            new_label,
        } => {
            // Run `Vault::rename` inside `Vault::mutate_and_save` so a
            // pre-commit failure (`save_not_committed`) snaps the
            // in-memory label back to its pre-rename value while
            // post-commit `save_durability_unconfirmed` leaves the
            // new label in memory matching the on-disk primary, per
            // `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" >
            // "Add / remove / rename / settings saves".
            //
            // The path check protects against a stale effect emitted
            // before an auto-lock or vault switch: if the live state
            // is no longer `Unlocked` against the same path, drop the
            // effect silently — the reducer would discard the
            // corresponding `EffectResult::Rename` anyway, and posting
            // back would just synthesize an artificial mutation
            // attempt against unrelated state.
            if let AppState::Unlocked {
                path: state_path,
                vault,
                store,
                ..
            } = state
            {
                if *state_path == path {
                    let result = vault.mutate_and_save(store, |v| {
                        v.rename(account_id, &new_label, SystemTime::now())
                    });
                    let _ = sender.send(AppEvent::EffectResult(EffectResult::Rename {
                        account_id,
                        result,
                    }));
                }
            }
            EffectOutcome::Continue
        }
        Effect::Add {
            path,
            label,
            issuer,
            secret,
            algorithm,
            digits,
            kind,
            period_secs,
            counter,
            icon_hint_text,
        } => execute_add(
            &path,
            label,
            issuer,
            secret,
            algorithm,
            digits,
            kind,
            period_secs,
            counter,
            &icon_hint_text,
            state,
            sender,
        ),
    }
}

/// Execute an [`Effect::Add`] for a Manual-mode submit.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
///
/// 1. Build a [`paladin_core::AccountInput`] from the carried form
///    fields, mapping the empty issuer string to `None` and parsing
///    the icon-hint token via
///    [`paladin_core::parse_icon_hint_token`].
/// 2. Call [`paladin_core::validate_manual`] over the input with one
///    `SystemTime::now()` sample (the submit time used for the
///    account's `created_at` / `updated_at`).
/// 3. Call [`paladin_core::Vault::find_duplicate`] over the validated
///    candidate. A collision returns an existing account's
///    [`paladin_core::AccountSummary`] alongside the validated
///    pending account so the reducer can render the
///    `duplicate_account` rejection and stash pending state.
/// 4. (Subsequent slice) wrap [`paladin_core::Vault::add`] in
///    [`paladin_core::Vault::mutate_and_save`] on the non-duplicate
///    path.
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Add`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
#[allow(clippy::too_many_arguments)]
fn execute_add(
    path: &std::path::Path,
    label: String,
    issuer: String,
    secret: secrecy::SecretString,
    algorithm: paladin_core::Algorithm,
    digits: u8,
    kind: paladin_core::AccountKindInput,
    period_secs: u32,
    counter: u64,
    icon_hint_text: &str,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let icon_hint = match parse_icon_hint_token(icon_hint_text) {
        Ok(h) => h,
        Err(err) => {
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Add {
                result: Err(AddFailure::Validation(err)),
            }));
            return EffectOutcome::Continue;
        }
    };

    let input = AccountInput {
        label,
        issuer: if issuer.is_empty() {
            None
        } else {
            Some(issuer)
        },
        secret,
        algorithm,
        digits,
        kind,
        period_secs: match kind {
            paladin_core::AccountKindInput::Totp => Some(period_secs),
            paladin_core::AccountKindInput::Hotp => None,
        },
        counter: match kind {
            paladin_core::AccountKindInput::Hotp => Some(counter),
            paladin_core::AccountKindInput::Totp => None,
        },
        icon_hint,
    };

    let validated = match validate_manual(input, SystemTime::now()) {
        Ok(v) => v,
        Err(err) => {
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Add {
                result: Err(AddFailure::Validation(err)),
            }));
            return EffectOutcome::Continue;
        }
    };

    if let Some(existing) = vault.find_duplicate(&validated) {
        let existing_summary = existing.summary();
        let _ = sender.send(AppEvent::EffectResult(EffectResult::Add {
            result: Err(AddFailure::Duplicate {
                existing: existing_summary,
                pending: Box::new(validated),
            }),
        }));
        return EffectOutcome::Continue;
    }

    // Success path (`Vault::add` inside `Vault::mutate_and_save`)
    // lands with the next slice; for now drop the validated account
    // without posting back so the secret zeroizes on this stack
    // frame.
    drop(validated);
    EffectOutcome::Continue
}

/// Apply every staged [`SettingPatch`] inside one
/// [`Vault::mutate_and_save`](paladin_core::Vault::mutate_and_save) so
/// the rollback semantics from `paladin-core` cover the batch: a
/// pre-commit failure snaps every pending value back to its
/// pre-attempt state, while `save_durability_unconfirmed` leaves them
/// all committed in memory matching the on-disk primary — per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" > "Add / remove /
/// rename / settings saves".
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Settings`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
///
/// The defensive empty-`patches` case is treated as a no-op `Ok(())`
/// so the reducer still observes a result. The reducer-side emit only
/// produces this effect with a non-empty list, but the executor stays
/// total against future callers.
fn execute_apply_settings(
    path: &PathBuf,
    patches: &[SettingPatch],
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    if let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    {
        if state_path == path {
            let result = vault.mutate_and_save(store, |v| {
                for patch in patches {
                    v.apply_setting_patch(*patch)?;
                }
                Ok(())
            });
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Settings { result }));
        }
    }
    EffectOutcome::Continue
}
