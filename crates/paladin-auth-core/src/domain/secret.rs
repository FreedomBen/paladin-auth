// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Newtype wrapper around the raw OTP shared secret. Implements
// `Zeroize` + `ZeroizeOnDrop` so the bytes are wiped from memory when
// the value goes out of scope.
//
// `Secret` deliberately does **not** derive `Debug`, `Display`, or
// `serde::Serialize`. The vault payload encoder is written by hand
// (bincode v2) so it can serialize the inner bytes without exposing them
// through the public surface; see docs/DESIGN.md §8.

use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{BorrowDecode, Decode, Encode};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Raw OTP shared secret (the decoded base32 bytes). Zeroized on drop.
///
/// This newtype is the only way to hold secret bytes in
/// `paladin-auth-core`. It must never be printed, formatted with `Debug`,
/// or serialized — see the `trybuild` audits in
/// `crates/paladin-auth-core/tests/`.
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
    ///
    /// Crate-private: keeps the OTP secret byte projection inside the
    /// crate so front ends cannot reach past `AccountSummary`.
    #[must_use]
    pub(crate) fn expose_secret(&self) -> &[u8] {
        &self.0
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

// Hand-rolled bincode codecs so the secret bytes never flow through a
// public `Debug` / `Display` / `serde::Serialize` impl. The encoded form
// matches `Vec<u8>` (length-prefix + bytes) under the §4.3 vault config.
impl Encode for Secret {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Encode::encode(&self.0, encoder)
    }
}

impl<C> Decode<C> for Secret {
    fn decode<D: Decoder<Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let bytes: Vec<u8> = Decode::decode(decoder)?;
        Ok(Self(bytes))
    }
}

impl<'de, C> BorrowDecode<'de, C> for Secret {
    fn borrow_decode<D: BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Decode::decode(decoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_secret_returns_inner_bytes() {
        let s = Secret::from_bytes(vec![0x01, 0x02, 0x03]);
        assert_eq!(s.expose_secret(), &[0x01, 0x02, 0x03]);
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
        let bytes = s.expose_secret();
        assert!(
            bytes.is_empty(),
            "expected len=0 after zeroize, got {}",
            bytes.len()
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
