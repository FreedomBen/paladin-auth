// SPDX-License-Identifier: AGPL-3.0-or-later

//! Secret-bearing widget state for `paladin-gtk`.
//!
//! Per `DESIGN.md` §8 and `IMPLEMENTATION_PLAN_04_GTK.md`
//! §"Secret entry handling", passphrase fields, manual-secret fields,
//! and the `AddAccountComponent`'s `otpauth://` URI entry are kept
//! out of `AppModel`, `AppMsg`, and `AppOutput`. The GTK
//! `gtk::EntryBuffer` is the unavoidable UI boundary; this module
//! owns the *Paladin-owned* shadow copy of each buffer, wrapped in
//! [`Zeroizing<String>`] so dropping the value zeros its bytes in
//! place.
//!
//! Two modal-local zeroizing pending slots cover the confirmation
//! round trips that need to survive a destructive-gate prompt:
//!
//! * [`AddSecretState::pending`] holds the duplicate-collision
//!   [`paladin_core::ValidatedAccount`] across the "add anyway"
//!   confirmation.
//! * [`InitSecretState::pending`] holds the
//!   [`paladin_core::VaultInit`] across the `vault_exists`
//!   destructive-confirmation gate.
//!
//! Both slots drop their carried value on cancel, close, replacement,
//! and auto-lock — and the carried values zeroize on drop via
//! [`paladin_core::Secret`]'s `ZeroizeOnDrop` impl and
//! [`paladin_core::EncryptionOptions`]'s `SecretString` passphrase.

use zeroize::{Zeroize, Zeroizing};

use paladin_core::{ValidatedAccount, VaultInit};

/// Why a secret-bearing buffer or pending slot is being cleared.
///
/// All variants flow through [`SecretEntry::clear`] and the
/// `clear_for` helpers below; the reason exists so call sites in the
/// component layer can be self-documenting (and so future logging /
/// metrics can disambiguate without changing the call signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearReason {
    /// The dialog's submit button accepted the input. Buffers and
    /// pending slots are wiped after the validated value has been
    /// handed to the worker.
    Submit,
    /// The user cancelled the dialog explicitly (Esc / Cancel button).
    Cancel,
    /// The dialog was closed (window-close / parent navigation /
    /// modal dismissal) without an explicit Submit or Cancel.
    Close,
    /// An auto-lock event reached the component; secret state must
    /// be dropped before the app transitions to `Locked`.
    AutoLock,
    /// A pending slot is being overwritten with a fresh value (the
    /// prior is returned to the caller for Drop).
    Replace,
    /// The Add dialog's path selector switched between Manual /
    /// URI inputs. Only the leaving path's hidden buffer is wiped;
    /// see [`AddSecretState::switch_path`].
    PathSwitch,
}

/// Paladin-owned shadow copy of a secret-bearing GTK entry buffer.
///
/// The component layer shadows every keystroke into this struct so
/// the cleartext bytes live in Paladin-owned memory wrapped in
/// [`Zeroizing<String>`]. Submit calls [`SecretEntry::take`], hands
/// the returned [`Zeroizing<String>`] to `SecretString::from(...)`
/// for the core call, and drops it after the worker returns —
/// zeroizing the bytes in place.
///
/// `SecretEntry` deliberately does not derive `Debug` so a stray
/// `dbg!` cannot leak the buffer through the error log.
#[derive(Default)]
pub struct SecretEntry {
    value: Zeroizing<String>,
}

impl SecretEntry {
    /// Construct an empty entry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an entry initialized to `text`.
    #[must_use]
    pub fn from(text: &str) -> Self {
        Self {
            value: Zeroizing::new(text.to_string()),
        }
    }

    /// Replace the stored value with `text`.
    pub fn set(&mut self, text: &str) {
        // Replace the inner `String` in place so the prior contents
        // are zeroized when the temporary `Zeroizing<String>` drops.
        self.value = Zeroizing::new(text.to_string());
    }

    /// Borrow the stored value as a `&str`.
    #[must_use]
    pub fn text(&self) -> &str {
        self.value.as_str()
    }

    /// True iff the stored value is the empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Wipe the stored value in place. Leaves the buffer empty.
    pub fn clear(&mut self) {
        self.value.zeroize();
    }

    /// Move the stored value out, leaving the entry empty.
    ///
    /// Returns the value wrapped in [`Zeroizing<String>`] so the
    /// caller can hand it to `SecretString::from(...)` and let the
    /// wrapper drop after the core call — zeroizing the bytes in
    /// place.
    #[must_use]
    pub fn take(&mut self) -> Zeroizing<String> {
        core::mem::take(&mut self.value)
    }
}

// `Zeroizing<String>` already implements `Drop`; the impl below is
// here so the trait surface stays `zeroize`-aware in case the inner
// field is refactored to a wrapper type that does not auto-derive
// `Drop` from `Zeroizing`.
//
// `Zeroizing<String>` ensures the bytes are wiped on drop; no manual
// `impl Drop for SecretEntry` is needed.

/// The two paths the `AddAccountComponent` exposes for entering a
/// new account: filling the manual Base32 / metadata fields, or
/// pasting an `otpauth://` URI that
/// [`paladin_core::parse_otpauth`] decodes into a
/// [`ValidatedAccount`].
///
/// The QR-image clipboard path is a third input source but is
/// dispatched directly without a per-buffer state machine; the
/// raw RGBA bytes flow through
/// [`paladin_core::import::qr_image_bytes`] without leaving a
/// long-lived buffer here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddPath {
    /// Manual Base32 secret + metadata fields.
    Manual,
    /// Pasted `otpauth://` URI.
    Uri,
}

/// Secret-bearing state owned by the `AddAccountComponent`.
///
/// Tracks the active input path, the two secret-bearing buffers
/// (manual Base32 and `otpauth://` URI text), and the
/// duplicate-collision pending [`ValidatedAccount`] held across the
/// "add anyway" confirmation.
///
/// `pending` is `Box<ValidatedAccount>` so the common no-pending case
/// stays a single null pointer (mirroring the TUI's `AddModal`).
pub struct AddSecretState {
    /// Currently-active input path. Defaults to [`AddPath::Manual`].
    pub active_path: AddPath,
    /// Hidden when `active_path == AddPath::Uri`. Holds the
    /// Paladin-owned shadow of the manual Base32 secret entry.
    pub manual_secret: SecretEntry,
    /// Hidden when `active_path == AddPath::Manual`. Holds the
    /// Paladin-owned shadow of the pasted `otpauth://` URI.
    pub uri_text: SecretEntry,
    /// Duplicate-collision pending slot. Set when
    /// [`paladin_core::Vault::find_duplicate`] reports a collision
    /// and the user has not yet acknowledged "add anyway". Dropped
    /// on cancel / close / replacement / auto-lock / path-switch.
    pub pending: Option<Box<ValidatedAccount>>,
}

impl Default for AddSecretState {
    fn default() -> Self {
        Self::new()
    }
}

impl AddSecretState {
    /// Construct a fresh state on the [`AddPath::Manual`] path with
    /// empty buffers and no pending duplicate-add.
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_path: AddPath::Manual,
            manual_secret: SecretEntry::new(),
            uri_text: SecretEntry::new(),
            pending: None,
        }
    }

    /// Switch the active input path.
    ///
    /// * Same-path call is a no-op: buffers and pending are left
    ///   untouched so idempotent re-entries don't accidentally erase
    ///   typed input.
    /// * Otherwise wipes only the *leaving* path's buffer (the now-
    ///   hidden Manual or URI text) and drops any pending duplicate-
    ///   add state. The new path's pre-existing buffer is preserved
    ///   so the user can return to it without re-typing.
    ///
    /// Returns the prior pending duplicate-add (if any) so the
    /// caller can decide whether to drop or display a status; either
    /// way the carried [`ValidatedAccount`]'s secret bytes are
    /// wiped via [`paladin_core::Secret`]'s `ZeroizeOnDrop` impl
    /// when the returned `Box` is dropped.
    pub fn switch_path(&mut self, to: AddPath) -> Option<Box<ValidatedAccount>> {
        if self.active_path == to {
            return None;
        }
        match self.active_path {
            AddPath::Manual => self.manual_secret.clear(),
            AddPath::Uri => self.uri_text.clear(),
        }
        self.active_path = to;
        self.pending.take()
    }

    /// Stage a fresh duplicate-collision [`ValidatedAccount`]. Returns
    /// the prior pending (if any). Drop the return to wipe the
    /// prior secret bytes; mirror the call sites in
    /// `paladin-tui::reducer` which let-bind the return so the
    /// compiler emits the `Drop` automatically.
    pub fn replace_pending(
        &mut self,
        validated: ValidatedAccount,
    ) -> Option<Box<ValidatedAccount>> {
        self.pending.replace(Box::new(validated))
    }

    /// Consume the pending duplicate-add (returning it to the caller)
    /// and wipe both secret buffers. Called from the "add anyway"
    /// confirmation path: the validated account is handed to the
    /// vault worker and the buffers are wiped before the worker
    /// spawns.
    pub fn consume_pending(&mut self) -> Option<Box<ValidatedAccount>> {
        let taken = self.pending.take();
        self.manual_secret.clear();
        self.uri_text.clear();
        taken
    }

    /// Clear both secret buffers and drop any pending duplicate-add.
    ///
    /// Covers Submit / Cancel / Close / `AutoLock` / Replace — every
    /// trigger in DESIGN §8 that requires wiping the unguarded
    /// secret-bearing slots. The returned `Option` lets the caller
    /// drop the prior pending explicitly (or via end-of-scope Drop)
    /// so the zeroize trail is auditable.
    ///
    /// [`ClearReason::PathSwitch`] is a documented input for
    /// completeness; the canonical path-switch flow goes through
    /// [`switch_path`] which preserves the new path's existing
    /// buffer.
    pub fn clear_for(&mut self, _reason: ClearReason) -> Option<Box<ValidatedAccount>> {
        self.manual_secret.clear();
        self.uri_text.clear();
        self.pending.take()
    }
}

/// Secret-bearing state owned by the `InitDialog`.
///
/// Holds the two passphrase confirmation entries and the pending
/// [`VaultInit`] carried across the `vault_exists`
/// destructive-confirmation gate.
pub struct InitSecretState {
    /// First passphrase entry. Empty for the plaintext-init path.
    pub passphrase: SecretEntry,
    /// Confirmation passphrase entry. Must match `passphrase` before
    /// the dialog's submit button arms.
    pub confirm: SecretEntry,
    /// Pending [`VaultInit`] held across the `vault_exists`
    /// destructive gate. [`VaultInit::Encrypted`] carries an
    /// [`paladin_core::EncryptionOptions`] whose `SecretString`
    /// passphrase wipes on drop; [`VaultInit::Plaintext`] is a
    /// zero-byte enum variant. Dropping the value on cancel /
    /// close / replacement / auto-lock zeroizes the secret in either
    /// case.
    pub pending: Option<VaultInit>,
}

impl Default for InitSecretState {
    fn default() -> Self {
        Self::new()
    }
}

impl InitSecretState {
    /// Construct a fresh state with empty passphrase fields and no
    /// pending init.
    #[must_use]
    pub fn new() -> Self {
        Self {
            passphrase: SecretEntry::new(),
            confirm: SecretEntry::new(),
            pending: None,
        }
    }

    /// Stage a fresh pending [`VaultInit`]. Returns the prior pending
    /// (if any) so the caller can drop it explicitly.
    pub fn replace_pending(&mut self, init: VaultInit) -> Option<VaultInit> {
        self.pending.replace(init)
    }

    /// Consume the pending [`VaultInit`] and wipe both passphrase
    /// buffers. Called from the `vault_exists` confirmation: the
    /// pending init is handed to the vault worker
    /// ([`paladin_core::Store::create_force`] for the destructive
    /// path) and the passphrase fields are wiped before the worker
    /// spawns.
    pub fn consume_pending(&mut self) -> Option<VaultInit> {
        let taken = self.pending.take();
        self.passphrase.clear();
        self.confirm.clear();
        taken
    }

    /// Wipe both passphrase fields and drop any pending
    /// [`VaultInit`]. Covers Submit / Cancel / Close / `AutoLock` /
    /// Replace — same DESIGN §8 invariant the Add path obeys.
    pub fn clear_for(&mut self, _reason: ClearReason) -> Option<VaultInit> {
        self.passphrase.clear();
        self.confirm.clear();
        self.pending.take()
    }
}
