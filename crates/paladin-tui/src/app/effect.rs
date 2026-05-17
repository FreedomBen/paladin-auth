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

use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;
use std::time::{Instant, SystemTime};

use paladin_core::{
    export as core_export, import as core_import, parse_icon_hint_token, parse_otpauth,
    validate_manual, write_secret_file_atomic, Account, AccountInput, ClipboardClearPolicy,
    EncryptionOptions, ImportConflict, ImportFormat, ImportOptions, PaladinError, SettingPatch,
    Store, ValidatedAccount, Vault, VaultInit, VaultLock,
};

use crate::app::event::{
    AddFailure, AddSuccess, AppEvent, CreateVaultInit, Effect, EffectResult, ImportFailure,
    ImportSuccess, QrImportFailure, QrImportSuccess,
};
use crate::app::state::{AppState, ExportFormat};

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
        Effect::CreateVault { path, init } => {
            let result = execute_create_vault(&path, init);
            // Sample `opened_at` immediately after the create + save
            // returned so the reducer can seed the auto-lock idle
            // deadline off the same monotonic clock the `Tick`
            // thread uses (same shape as `Effect::Unlock`).
            let opened_at = Instant::now();
            let _ = sender.send(AppEvent::EffectResult(EffectResult::CreateVault {
                result,
                opened_at,
            }));
            EffectOutcome::Continue
        }
        Effect::ClearClipboard { value } => {
            // Per `IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear
            // (per §6)": *"on wake, it ignores stale tokens, reads the
            // current clipboard, asks
            // `ClipboardClearPolicy::should_clear`, and writes empty
            // when the policy returns `true`."* The reducer has already
            // filtered stale-token / no-pending wakes — the matching-
            // token dispatch reaches us here with the captured bytes
            // still wrapped in `Zeroizing<Vec<u8>>`, which wipes on
            // drop regardless of which branch runs below.
            //
            // A read failure (e.g. arboard unavailable, or
            // `PALADIN_CLIPBOARD_DRYRUN=fail` under `test-hooks`) is a
            // silent no-op — without a live `current` we cannot honor
            // the only-if-unchanged contract, and writing empty
            // anyway would risk clobbering an unrelated value the
            // user pasted in the interim.
            //
            // No `AppEvent` is sent back: clipboard wipe is fire-and-
            // forget at this layer.
            let _ = sender;
            if let Ok(current) = crate::clipboard::read_text() {
                if ClipboardClearPolicy::should_clear(&value, current.as_bytes()) {
                    let _ = crate::clipboard::write_text("");
                }
            }
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
        Effect::AddFromUri { path, uri } => execute_add_from_uri(&path, &uri, state, sender),
        Effect::AddAnyway { path, validated } => {
            execute_add_anyway(&path, *validated, state, sender)
        }
        Effect::AddFromClipboardQr { path } => execute_add_from_clipboard_qr(&path, state, sender),
        Effect::Import {
            path,
            source_path,
            format,
            conflict,
            paladin_passphrase,
        } => execute_import(
            &path,
            &source_path,
            format,
            conflict,
            paladin_passphrase,
            state,
            sender,
        ),
        Effect::Export {
            path,
            target_path,
            format,
            passphrase,
        } => execute_export(&path, &target_path, format, passphrase, state, sender),
        Effect::PassphraseSet {
            path,
            new_passphrase,
        } => execute_passphrase_set(&path, new_passphrase, state, sender),
        Effect::PassphraseChange {
            path,
            new_passphrase,
        } => execute_passphrase_change(&path, new_passphrase, state, sender),
        Effect::PassphraseRemove { path } => execute_passphrase_remove(&path, state, sender),
    }
}

/// Execute an [`Effect::CreateVault`] dispatch.
///
/// Builds the `paladin_core::VaultInit` from the front-end
/// [`CreateVaultInit`] — encrypted variants derive
/// [`EncryptionOptions::new`] with defaults — then calls
/// [`Store::create`] followed by [`Vault::save`]. The save commits
/// the empty vault to disk so the subsequent
/// [`crate::app::state::AppState::Unlocked`] transition can call
/// the standard save-bearing operations against a real on-disk
/// `vault.bin`.
///
/// Any error from `EncryptionOptions::new`, `Store::create`, or
/// `Vault::save` propagates to the caller, which surfaces it
/// through [`EffectResult::CreateVault`].
fn execute_create_vault(
    path: &Path,
    init: CreateVaultInit,
) -> Result<(Vault, Store), PaladinError> {
    let core_init = match init {
        CreateVaultInit::Plaintext => VaultInit::Plaintext,
        CreateVaultInit::Encrypted(passphrase) => {
            VaultInit::Encrypted(EncryptionOptions::new(passphrase)?)
        }
    };
    let (vault, store) = Store::create(path, core_init)?;
    vault.save(&store)?;
    Ok((vault, store))
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
        store,
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

    let _ = sender.send(AppEvent::EffectResult(EffectResult::Add {
        result: commit_validated_add(vault, store, validated),
    }));
    EffectOutcome::Continue
}

/// Execute an [`Effect::AddFromUri`] for a URI-mode submit.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add:
/// *"URI mode is a single text field; on submit the entered string is
/// passed to `paladin_core::parse_otpauth(uri, submit_time)`, and on
/// success the resulting `ValidatedAccount` shares the manual path's
/// duplicate-detection, 'add anyway' override, and
/// `Vault::mutate_and_save` insertion."*
///
/// 1. Call [`paladin_core::parse_otpauth`] over the carried URI bytes
///    with one `SystemTime::now()` sample (the submit time used for
///    the account's `created_at` / `updated_at`).
/// 2. Call [`paladin_core::Vault::find_duplicate`] over the parsed
///    candidate. A collision returns an existing account's
///    [`paladin_core::AccountSummary`] alongside the parsed pending
///    account so the reducer can render the `duplicate_account`
///    rejection and stash pending state on the shared
///    [`crate::app::state::AddModal::pending_duplicate_add`] slot.
/// 3. (Subsequent slice) wrap [`paladin_core::Vault::add`] in
///    [`paladin_core::Vault::mutate_and_save`] on the non-duplicate
///    path.
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Add`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
fn execute_add_from_uri(
    path: &std::path::Path,
    uri: &secrecy::SecretString,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let validated =
        match parse_otpauth(secrecy::ExposeSecret::expose_secret(uri), SystemTime::now()) {
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

    let _ = sender.send(AppEvent::EffectResult(EffectResult::Add {
        result: commit_validated_add(vault, store, validated),
    }));
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

/// Execute an [`Effect::AddAnyway`] for the "add anyway" follow-up
/// confirmation on the duplicate-allowed path.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add: *"A
/// collision initially rejects with the existing account in the modal
/// and offers an 'add anyway' confirmation that inserts the pending
/// validated account on the duplicate-allowed path (CLI parity with
/// `--allow-duplicate`, appending a new account that shares the
/// `(secret, issuer, label)` triple)."*
///
/// The carried [`ValidatedAccount`] was previously produced by the
/// duplicate-detection executor arm and stashed on
/// [`crate::app::state::AddModal::pending_duplicate_add`]; this
/// executor wraps [`paladin_core::Vault::add`] in
/// [`paladin_core::Vault::mutate_and_save`] so the new account is
/// committed atomically. `Vault::add` assigns a fresh
/// [`paladin_core::AccountId`] so the inserted account is distinct
/// from the colliding existing entry.
///
/// On `save_not_committed` core rolls back the in-memory snapshot so
/// the freshly-added account vanishes (memory matches the on-disk
/// primary); on `save_durability_unconfirmed` the new account remains
/// in memory matching the committed primary and the reducer surfaces
/// the warning inline. Both failure modes deliver as
/// `EffectResult::Add { Err(AddFailure::Save(_)) }`.
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Add`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
fn execute_add_anyway(
    path: &std::path::Path,
    validated: ValidatedAccount,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let _ = sender.send(AppEvent::EffectResult(EffectResult::Add {
        result: commit_validated_add(vault, store, validated),
    }));
    EffectOutcome::Continue
}

/// Wrap `Vault::add` in `Vault::mutate_and_save` so the freshly
/// inserted account commits atomically to the on-disk primary alongside
/// the live in-memory vault, then build the matching
/// [`Result<AddSuccess, AddFailure>`] for delivery on the
/// [`EffectResult::Add`] channel.
///
/// Shared by `Effect::Add` (Manual mode), `Effect::AddFromUri` (URI
/// mode), and `Effect::AddAnyway` (duplicate-allowed follow-up) — all
/// three paths reach this helper once their input has been validated
/// and any duplicate gate has been resolved. The validation warnings
/// ride through unchanged so the reducer can render them in the
/// status-line confirmation.
///
/// Pre-commit save failures (`save_not_committed`) and
/// durability-unconfirmed saves both deliver as
/// [`AddFailure::Save`]; the reducer surfaces either inline per
/// `IMPLEMENTATION_PLAN_03_TUI.md` "Effect errors" >
/// "Add / remove / rename / settings saves".
fn commit_validated_add(
    vault: &mut paladin_core::Vault,
    store: &Store,
    validated: ValidatedAccount,
) -> Result<AddSuccess, AddFailure> {
    let ValidatedAccount { account, warnings } = validated;
    let result = vault.mutate_and_save(store, move |v| {
        let id = v.add(account);
        let summary = v
            .iter()
            .find(|a| a.id() == id)
            .map(Account::summary)
            .expect("freshly inserted account must be present in the vault");
        Ok(summary)
    });
    match result {
        Ok(summary) => Ok(AddSuccess { summary, warnings }),
        Err(err) => Err(AddFailure::Save(err)),
    }
}

/// Execute an [`Effect::AddFromClipboardQr`] for an Add-modal QR submit.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Add: *"QR
/// imports call `Vault::import_accounts` with `ImportConflict::Skip`
/// and report imported/skipped/warning counts plus any warning
/// messages in the post-success counts panel."*
///
/// 1. Read the live clipboard image via
///    [`crate::clipboard::read_image`]. The two
///    [`crate::clipboard::ImageReadError`] variants route to the
///    matching [`QrImportFailure`] inline-error variants
///    (`NoClipboardImage` / `ImageDecodeFailure`) and post back
///    immediately without ever calling
///    [`paladin_core::import::qr_image_bytes`] — the reducer renders
///    each with its own user-facing wording.
/// 2. Hand the RGBA buffer to
///    [`paladin_core::import::qr_image_bytes`], which re-validates
///    dimensions (`zero_dimensions`, `dimensions_overflow`,
///    `image_too_large`, `buffer_length_mismatch`), decodes every QR
///    via `rqrr`, and feeds each payload through
///    [`paladin_core::parse_otpauth`]. Errors map to
///    [`QrImportFailure::Import`] so the reducer renders through
///    [`crate::app::state::render_error_message`].
/// 3. Commit the resulting `ValidatedAccount` batch through
///    [`paladin_core::Vault::import_accounts`] wrapped in
///    [`paladin_core::Vault::mutate_and_save`] with the same
///    `import_time`, always under `ImportConflict::Skip` (clipboard QR
///    imports never replace or append). Save errors
///    (`save_not_committed`, `save_durability_unconfirmed`,
///    `io_error`) ride the same `QrImportFailure::Import` channel; the
///    reducer surfaces them inline per the plan's "Effect errors" >
///    "Add / remove / rename / settings saves" rule (pre-commit
///    rollback inside core).
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::QrImport`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
fn execute_add_from_clipboard_qr(
    path: &std::path::Path,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let image = match crate::clipboard::read_image() {
        Ok(img) => img,
        Err(crate::clipboard::ImageReadError::NoImage) => {
            let _ = sender.send(AppEvent::EffectResult(EffectResult::QrImport {
                result: Err(QrImportFailure::NoClipboardImage),
            }));
            return EffectOutcome::Continue;
        }
        Err(crate::clipboard::ImageReadError::DecodeFailure) => {
            let _ = sender.send(AppEvent::EffectResult(EffectResult::QrImport {
                result: Err(QrImportFailure::ImageDecodeFailure),
            }));
            return EffectOutcome::Continue;
        }
    };

    let import_time = SystemTime::now();
    let accounts =
        match core_import::qr_image_bytes(image.width, image.height, &image.rgba, import_time) {
            Ok(v) => v,
            Err(err) => {
                let _ = sender.send(AppEvent::EffectResult(EffectResult::QrImport {
                    result: Err(QrImportFailure::Import(err)),
                }));
                return EffectOutcome::Continue;
            }
        };

    let result = vault.mutate_and_save(store, move |v| {
        v.import_accounts(accounts, ImportConflict::Skip, import_time)
    });
    let mapped = match result {
        Ok(report) => Ok(QrImportSuccess { report }),
        Err(err) => Err(QrImportFailure::Import(err)),
    };
    let _ = sender.send(AppEvent::EffectResult(EffectResult::QrImport {
        result: mapped,
    }));
    EffectOutcome::Continue
}

/// Execute an [`Effect::Import`] for an Import-modal submit.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Import:
///
/// 1. Build a [`paladin_core::ImportOptions`] from the carried
///    `format` (`None` runs auto-detect via
///    [`paladin_core::detect`] inside the facade, [`Some`] forces the
///    matching format and lets the facade sanity-check the input
///    shape) and `paladin_passphrase` (consumed only when the facade
///    dispatches to [`ImportFormat::Paladin`]).
/// 2. Call [`paladin_core::import::from_file`] over `source_path` with
///    one `SystemTime::now()` sample as `import_time`; importer /
///    format-facade errors map to [`ImportFailure`] and surface inline.
/// 3. On a successful parse commit the resulting
///    [`paladin_core::ValidatedAccount`] batch through
///    [`paladin_core::Vault::import_accounts`] wrapped in
///    [`paladin_core::Vault::mutate_and_save`] with the same
///    `import_time`. Save errors (`save_not_committed`,
///    `save_durability_unconfirmed`, `io_error`) ride the same
///    [`ImportFailure`] channel; the reducer surfaces them inline per
///    the plan's "Effect errors" > "Add / remove / rename / settings
///    saves" rule (pre-commit failures are rolled back inside core).
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Import`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
fn execute_import(
    path: &std::path::Path,
    source_path: &std::path::Path,
    format: Option<ImportFormat>,
    conflict: ImportConflict,
    paladin_passphrase: Option<secrecy::SecretString>,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let import_time = SystemTime::now();
    let options = ImportOptions {
        format,
        paladin_passphrase,
    };
    let accounts = match core_import::from_file(source_path, options, import_time) {
        Ok(v) => v,
        Err(err) => {
            let _ = sender.send(AppEvent::EffectResult(EffectResult::Import {
                result: Err(ImportFailure(err)),
            }));
            return EffectOutcome::Continue;
        }
    };

    let result = vault.mutate_and_save(store, move |v| {
        v.import_accounts(accounts, conflict, import_time)
    });
    let mapped = match result {
        Ok(report) => Ok(ImportSuccess { report }),
        Err(err) => Err(ImportFailure(err)),
    };
    let _ = sender.send(AppEvent::EffectResult(EffectResult::Import {
        result: mapped,
    }));
    EffectOutcome::Continue
}

/// Execute an [`Effect::Export`] for an Export-modal submit.
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" > Export:
///
/// 1. Render the live vault's bytes:
///    [`ExportFormat::Plaintext`] routes through
///    [`paladin_core::export::otpauth_list`] (a JSON array of
///    `otpauth://` URIs); [`ExportFormat::Encrypted`] routes through
///    [`paladin_core::export::encrypted`] with the user-supplied
///    twice-confirmed bundle passphrase.
/// 2. Hand the bytes to [`paladin_core::write_secret_file_atomic`],
///    which writes through a tmpfile + rename and enforces mode
///    `0600` on the final file.
/// 3. Post the outcome back through
///    [`EffectResult::Export`](crate::app::event::EffectResult::Export).
///
/// Export does not mutate the vault, so the executor never calls
/// `Vault::save` — `Vault::mutate_and_save` is not on this path per the
/// plan's "Effect errors" > Export rule: *"Export does not mutate the
/// vault, so save-error rollback does not apply."*
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Export`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
fn execute_export(
    path: &std::path::Path,
    target_path: &std::path::Path,
    format: ExportFormat,
    passphrase: Option<secrecy::SecretString>,
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

    let bytes_result: Result<Vec<u8>, PaladinError> = match format {
        ExportFormat::Plaintext => Ok(core_export::otpauth_list(vault).into_bytes()),
        ExportFormat::Encrypted => {
            // `passphrase` must be Some on the encrypted path; the
            // reducer's twice-prompt gate guarantees this.
            let secret =
                passphrase.expect("ExportFormat::Encrypted requires a passphrase from the reducer");
            EncryptionOptions::new(secret)
                .and_then(|options| core_export::encrypted(vault, options))
        }
    };

    let result = bytes_result.and_then(|bytes| write_secret_file_atomic(target_path, &bytes));
    let _ = sender.send(AppEvent::EffectResult(EffectResult::Export { result }));
    EffectOutcome::Continue
}

/// Execute an [`Effect::PassphraseSet`] for a `Set` sub-flow submit
/// (plaintext → encrypted).
///
/// Per `IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)" >
/// Passphrase: *"The transition methods (`set_passphrase` /
/// `change_passphrase` / `remove_passphrase`) save themselves through
/// `&Store` and handle their own pre-commit rollback per DESIGN §4.5
/// ..."* — this function wraps the typed `new_passphrase` in
/// [`EncryptionOptions::new`] (default §4.4 Argon2 params) and calls
/// [`paladin_core::Vault::set_passphrase`]. The outcome is sent back
/// through [`EffectResult::Passphrase`] for the reducer to surface.
///
/// The path check protects against a stale effect emitted before an
/// auto-lock or vault switch: if the live state is no longer
/// `Unlocked` against the same path, drop the effect silently — the
/// reducer would discard the corresponding `EffectResult::Passphrase`
/// anyway, and posting back would just synthesize an artificial
/// mutation attempt against unrelated state.
fn execute_passphrase_set(
    path: &std::path::Path,
    new_passphrase: secrecy::SecretString,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let result = EncryptionOptions::new(new_passphrase)
        .and_then(|options| vault.set_passphrase(store, options));
    let _ = sender.send(AppEvent::EffectResult(EffectResult::Passphrase { result }));
    EffectOutcome::Continue
}

/// Execute an [`Effect::PassphraseChange`] for a `Change` sub-flow
/// submit (encrypted → encrypted with a new key).
///
/// Mirrors [`execute_passphrase_set`] but routes through
/// [`paladin_core::Vault::change_passphrase`]; core handles the
/// pre-commit rollback (DESIGN §4.5) and the outcome is surfaced
/// through [`EffectResult::Passphrase`].
fn execute_passphrase_change(
    path: &std::path::Path,
    new_passphrase: secrecy::SecretString,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let result = EncryptionOptions::new(new_passphrase)
        .and_then(|options| vault.change_passphrase(store, options));
    let _ = sender.send(AppEvent::EffectResult(EffectResult::Passphrase { result }));
    EffectOutcome::Continue
}

/// Execute an [`Effect::PassphraseRemove`] for a `Remove` sub-flow
/// submit (encrypted → plaintext).
///
/// Routes through [`paladin_core::Vault::remove_passphrase`]; the
/// cached key in core decrypts the existing payload before the
/// plaintext rewrite. Core handles the pre-commit rollback (DESIGN
/// §4.5) and the outcome is surfaced through
/// [`EffectResult::Passphrase`].
fn execute_passphrase_remove(
    path: &std::path::Path,
    state: &mut AppState,
    sender: &Sender<AppEvent>,
) -> EffectOutcome {
    let AppState::Unlocked {
        path: state_path,
        vault,
        store,
        ..
    } = state
    else {
        return EffectOutcome::Continue;
    };
    if state_path != path {
        return EffectOutcome::Continue;
    }

    let result = vault.remove_passphrase(store);
    let _ = sender.send(AppEvent::EffectResult(EffectResult::Passphrase { result }));
    EffectOutcome::Continue
}
