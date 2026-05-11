// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AppState` — the TUI's top-level state machine — plus the pure
//! startup-decision functions that map `inspect` / `open` outcomes
//! onto initial states.
//!
//! See `DESIGN.md` §6 and `IMPLEMENTATION_PLAN_03_TUI.md`
//! "Startup / vault modes" + "Auto-lock (per §6)".

use std::path::{Path, PathBuf};
use std::time::Instant;

use paladin_core::{
    format_unsafe_permissions, ClipboardClearToken, IdlePolicy, PaladinError, Store, Vault,
    VaultLock, VaultStatus,
};

use crate::prompt::PassphraseBuffer;

/// A clipboard auto-clear scheduled by an earlier copy effect and
/// awaiting either its wake-deadline (at which point the bytes are
/// wiped if they still match the system clipboard) or a stale-token
/// supersession.
///
/// Held on [`AppState::Unlocked`] while the user is active and on
/// [`AppState::Locked`] when an idle-expiry transition arrives before
/// the wake fires — per `IMPLEMENTATION_PLAN_03_TUI.md`
/// "Auto-lock (per §6)": *"A clipboard auto-clear timer scheduled
/// before lock survives lock and still fires only-if-unchanged."*
///
/// `value` is the bytes that were written to the clipboard; the
/// reducer compares them to the current clipboard contents via
/// [`paladin_core::ClipboardClearPolicy::should_clear`] when the wake
/// event arrives so a later external copy is preserved. The bytes are
/// non-secret-token-bearing on their own but reflect a code that was
/// just exposed to the user, so the same zeroization discipline as
/// other typed buffers applies; the field is exposed as `Vec<u8>` for
/// now and tightens to a zeroizing wrapper alongside the
/// "Sensitive UI buffers" coverage slice.
#[derive(Debug)]
pub struct PendingClipboardClear {
    /// Monotonic token returned by
    /// [`paladin_core::ClipboardClearPolicy::schedule`]. A later
    /// schedule on the same vault settings supersedes this one.
    pub token: ClipboardClearToken,
    /// The bytes the copy effect wrote to the clipboard. Compared
    /// byte-equal against the current clipboard contents when the
    /// wake fires; only-if-unchanged.
    pub value: Vec<u8>,
    /// Monotonic wake-deadline; the timer thread sleeps until this
    /// instant and then sends an `AppEvent::ClipboardClear`.
    pub deadline: Instant,
}

/// Top-level UI state.
///
/// Variants other than [`AppState::Unlocked`] are deliberately
/// `Vault`/`Store`-free so the TUI cannot mutate vault data from
/// non-unlocked screens (per the plan's "non-mutating missing-vault /
/// startup-error" guarantee).
#[derive(Debug)]
pub enum AppState {
    /// Vault file does not exist; the TUI shows a non-mutating
    /// guidance screen telling the user to run `paladin init`.
    /// v0.1 TUI does not create vaults.
    MissingVault {
        /// The vault path that was inspected.
        path: PathBuf,
    },

    /// Encrypted vault: the unlock screen is shown and the user is
    /// prompted for the passphrase inside the TUI. A
    /// `decrypt_failed` from a previous attempt is held in `error`
    /// for inline display; every other `open` error replaces this
    /// state with [`AppState::StartupError`]. Typed passphrase bytes
    /// live in `passphrase`, a zeroizing buffer cleared on submit per
    /// `IMPLEMENTATION_PLAN_03_TUI.md` "Tests > Sensitive UI buffers".
    Unlock {
        /// The vault path being unlocked.
        path: PathBuf,
        /// Inline error (most recently `decrypt_failed`), if any.
        error: Option<String>,
        /// Typed passphrase characters; zeroized on submit, cancel,
        /// modal close, and auto-lock.
        passphrase: PassphraseBuffer,
    },

    /// Auto-locked: an encrypted vault that was previously unlocked
    /// but has timed out per the auto-lock idle policy. Keeps only
    /// the resolved path plus pending clipboard-clear state needed
    /// for re-unlock and scheduled clear; the previous `Vault`,
    /// `Store`, cached key, and any modal-local secret state are
    /// discarded.
    Locked {
        /// The vault path; same as the previously unlocked state's.
        path: PathBuf,
        /// Clipboard auto-clear that was scheduled while the vault
        /// was still unlocked. Carried across the
        /// `Unlocked → Locked` transition so the timer thread's
        /// `AppEvent::ClipboardClear` wake still finds a target
        /// pending state. Per `IMPLEMENTATION_PLAN_03_TUI.md`
        /// "Auto-lock (per §6)": *"A clipboard auto-clear timer
        /// scheduled before lock survives lock and still fires
        /// only-if-unchanged."*
        pending_clipboard_clear: Option<PendingClipboardClear>,
    },

    /// Unlocked: the main list view is active. Owns the `Vault` and
    /// `Store` so save-bearing effects can call
    /// `Vault::mutate_and_save`, `Vault::hotp_advance`, and
    /// passphrase-transition methods directly.
    Unlocked {
        /// The vault path the `Store` reads/writes.
        path: PathBuf,
        /// The decrypted in-memory vault.
        vault: Vault,
        /// Persistence handle for the vault file.
        store: Store,
        /// Active search-bar text used to filter the visible
        /// account list. Empty when no filter is set. Discarded on
        /// auto-lock alongside the `Vault` / `Store` per
        /// `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)":
        /// "the search query is cleared". Held in plain `String`
        /// because issuer / label text is non-secret (DESIGN §5);
        /// only secrets live in zeroizing storage.
        search_query: String,
        /// Auto-lock idle deadline (monotonic clock).
        ///
        /// `Some(now + timeout)` when
        /// [`paladin_core::IdlePolicy::should_arm`] holds for the
        /// current vault (encrypted **and** `auto_lock_enabled`);
        /// `None` otherwise — plaintext vaults always stay `None`
        /// per the §6 / §7 plaintext-no-op rule, and encrypted
        /// vaults with auto-lock disabled also stay `None`.
        ///
        /// Re-set on every `AppEvent::Input` and checked against
        /// monotonic `Tick` instants for the `Locked` transition.
        /// See `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)".
        idle_deadline: Option<Instant>,
        /// Clipboard auto-clear that was scheduled by an earlier
        /// copy effect and is still waiting for its wake-deadline.
        /// On the `Unlocked → Locked` transition this field moves
        /// onto [`AppState::Locked`] verbatim so the timer thread's
        /// wake event can still find pending state to act on. See
        /// `IMPLEMENTATION_PLAN_03_TUI.md` "Auto-lock (per §6)".
        pending_clipboard_clear: Option<PendingClipboardClear>,
    },

    /// Non-mutating startup-error screen. Used when vault-path
    /// resolution fails or `inspect` / `open` returns anything other
    /// than `decrypt_failed`. Quits on `Esc` / `q` / `Ctrl-C`.
    StartupError {
        /// Vault path, if it was resolved before the failure.
        /// `None` if `default_vault_path` itself failed.
        path: Option<PathBuf>,
        /// Pre-rendered error text. `unsafe_permissions` uses the
        /// `Some(text)` from
        /// [`paladin_core::format_unsafe_permissions`] verbatim so
        /// all front ends share identical wording.
        message: String,
    },
}

/// Map a `paladin_core::inspect` result onto the corresponding initial
/// [`AppState`].
///
/// Returns `None` for [`VaultStatus::Plaintext`]: the caller must
/// follow up with `Store::open(path, VaultLock::Plaintext)` and feed
/// the outcome into [`decide_state_from_open`]. This split keeps the
/// pure decision logic separate from the impure `open` call so each
/// branch is unit-testable without touching the filesystem.
#[must_use]
pub fn decide_state_from_inspect(
    path: &Path,
    inspect: Result<VaultStatus, PaladinError>,
) -> Option<AppState> {
    match inspect {
        Ok(VaultStatus::Missing) => Some(AppState::MissingVault {
            path: path.to_path_buf(),
        }),
        Ok(VaultStatus::Encrypted) => Some(AppState::Unlock {
            path: path.to_path_buf(),
            error: None,
            passphrase: PassphraseBuffer::new(),
        }),
        Ok(VaultStatus::Plaintext) => None,
        Err(err) => Some(AppState::StartupError {
            path: Some(path.to_path_buf()),
            message: render_error_message(&err),
        }),
    }
}

/// Map a `Store::open` result onto the corresponding initial
/// [`AppState`].
///
/// `now` is the monotonic instant sampled at the boundary (right
/// after `Store::open` returns) and is used to compute the auto-lock
/// [`AppState::Unlocked::idle_deadline`] via
/// [`compute_idle_deadline`]. It is unused on the error branch.
#[must_use]
pub fn decide_state_from_open(
    now: Instant,
    path: PathBuf,
    open: Result<(Vault, Store), PaladinError>,
) -> AppState {
    match open {
        Ok((vault, store)) => {
            let idle_deadline = compute_idle_deadline(now, &vault);
            AppState::Unlocked {
                path,
                vault,
                store,
                search_query: String::new(),
                idle_deadline,
                pending_clipboard_clear: None,
            }
        }
        Err(err) => AppState::StartupError {
            path: Some(path),
            message: render_error_message(&err),
        },
    }
}

/// Compute the auto-lock idle deadline for the given vault at `now`.
///
/// Thin wrapper around [`paladin_core::IdlePolicy::next_deadline`]
/// that pulls `is_encrypted` and `settings()` off the [`Vault`] so
/// every Unlocked-entry site uses the same call shape. Returns
/// `None` for plaintext vaults (the §6 / §7 plaintext-no-op rule)
/// and for encrypted vaults whose `auto_lock_enabled` setting is
/// `false`; otherwise returns `Some(now + timeout)`.
#[must_use]
pub fn compute_idle_deadline(now: Instant, vault: &Vault) -> Option<Instant> {
    IdlePolicy::next_deadline(now, vault.is_encrypted(), vault.settings())
}

/// Render an error for the startup-error screen.
///
/// `unsafe_permissions` errors use the `Some(text)` from
/// [`paladin_core::format_unsafe_permissions`] verbatim so the CLI,
/// TUI, and GUI surface identical wording; every other error falls
/// back to the error's `Display` implementation.
#[must_use]
pub fn render_error_message(error: &PaladinError) -> String {
    format_unsafe_permissions(error).unwrap_or_else(|| error.to_string())
}

/// Build the TUI's initial state from the optional `--vault`
/// command-line override.
///
/// Mirrors `IMPLEMENTATION_PLAN_03_TUI.md` "Startup / vault modes":
///
/// 1. Resolve the vault path (`--vault` overrides `default_vault_path`).
/// 2. Call [`paladin_core::inspect`].
/// 3. Branch on [`VaultStatus`]; plaintext vaults are opened
///    immediately, encrypted vaults defer to the unlock screen,
///    missing vaults open the guidance screen, and any error from
///    path resolution / `inspect` / plaintext `open` lands on the
///    non-mutating startup-error screen.
pub fn build_initial_state(vault: Option<PathBuf>) -> AppState {
    let path: PathBuf = match vault {
        Some(p) => p,
        None => match paladin_core::default_vault_path() {
            Ok(p) => p,
            Err(err) => {
                return AppState::StartupError {
                    path: None,
                    message: render_error_message(&err),
                };
            }
        },
    };

    let inspect = paladin_core::inspect(&path);
    if let Some(state) = decide_state_from_inspect(&path, inspect) {
        return state;
    }
    // `VaultStatus::Plaintext` — open immediately, no passphrase prompt.
    let open = Store::open(&path, VaultLock::Plaintext);
    // Sample `now` at the boundary so the auto-lock deadline math
    // sees the same instant the open completed at. For plaintext
    // vaults the deadline is always `None`; the sample is still
    // taken to keep the call shape uniform with encrypted unlock.
    let now = Instant::now();
    decide_state_from_open(now, path, open)
}
