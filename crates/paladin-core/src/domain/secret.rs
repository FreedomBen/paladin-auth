// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Newtype wrapper around the raw OTP shared secret. Implements
// `Zeroize` + `ZeroizeOnDrop` so the bytes are wiped from memory when
// the value goes out of scope.
//
// `Secret` deliberately does **not** derive `Debug`, `Display`, or
// `serde::Serialize`. The vault payload encoder is written by hand
// (bincode v2) so it can serialize the inner bytes without exposing them
// through the public surface; see DESIGN.md §8.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Raw OTP shared secret (the decoded base32 bytes). Zeroized on drop.
///
/// This newtype is the only way to hold secret bytes in
/// `paladin-core`. It must never be printed, formatted with `Debug`,
/// or serialized — see the `trybuild` audits in
/// `crates/paladin-core/tests/`.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Wrap the supplied bytes. Caller is responsible for length and
    /// content validation; see `domain::validation` for the
    /// canonical entry points (manual `validate_manual`, otpauth
    /// parser, importers).
    #[must_use]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the secret bytes for OTP computation. The borrow must
    /// not outlive the `Secret`; callers must not copy the bytes
    /// into a non-zeroizing buffer.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Length of the underlying byte buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True iff the buffer is empty. Validation rejects empty
    /// secrets, so this should never return true for an `Account`'s
    /// secret in practice.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        // Equality on secret bytes is needed for duplicate-account
        // detection (`Vault::find_duplicate`). Constant-time comparison
        // is not required here because we are comparing against
        // already-stored secrets the caller controls; an attacker
        // capable of mounting a timing attack can already read the
        // process memory holding the secret.
        self.0 == other.0
    }
}

impl Eq for Secret {}

impl Zeroize for Secret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_secret_returns_inner_bytes() {
        let s = Secret::from_bytes(vec![0x01, 0x02, 0x03]);
        assert_eq!(s.expose_secret(), &[0x01, 0x02, 0x03]);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
    }

    #[test]
    fn empty_secret_is_empty() {
        let s = Secret::from_bytes(vec![]);
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn equality_compares_bytes() {
        // `Secret` deliberately has no `Debug`, so `assert_eq!` /
        // `assert_ne!` cannot be used — those macros render the
        // operands via `Debug` on failure.
        let a = Secret::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let b = Secret::from_bytes(vec![0xde, 0xad, 0xbe, 0xef]);
        let c = Secret::from_bytes(vec![0xde, 0xad, 0xbe, 0xee]);
        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn explicit_zeroize_clears_buffer() {
        // `zeroize` on `Vec<u8>` wipes the bytes *and* truncates the
        // length, matching the upstream contract. Either side of the
        // pair is acceptable evidence that the secret bytes are gone.
        let mut s = Secret::from_bytes(vec![1, 2, 3, 4]);
        s.zeroize();
        assert!(
            s.is_empty(),
            "expected len=0 after zeroize, got {}",
            s.len()
        );
    }

    #[test]
    fn clone_creates_independent_buffer() {
        let mut a = Secret::from_bytes(vec![1, 2, 3]);
        let b = a.clone();
        a.zeroize();
        // Clearing `a` must not affect `b`.
        assert_eq!(b.expose_secret(), &[1, 2, 3]);
    }
}
