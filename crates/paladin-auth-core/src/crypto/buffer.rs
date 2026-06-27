// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pre-AEAD / post-AEAD plaintext buffer (docs/DESIGN.md §4.4 / Phase F.14).
//
// `ZeroizingBytes` wraps the secret-plaintext `Vec<u8>` that the
// encrypted-storage paths hand to / receive from `crypto::aead`:
//
// * encrypt side — the bincode-serialized `VaultPayload` going into
//   `aead_encrypt`, held in a `ZeroizingBytes` from the moment
//   `encode_vault_payload` returns until the surrounding function
//   scope ends.
// * decrypt side — the plaintext `Vec<u8>` coming out of
//   `aead_decrypt`, held in a `ZeroizingBytes` until the surrounding
//   function scope ends. The wrapper drops on success *and* on the
//   `decode_vault_payload` failure path because both exit through
//   the same scope.
//
// `Drop` runs `<[u8] as Zeroize>::zeroize` over the initialized
// region (volatile-zero, in place, length preserved), fires the
// test-only `crypto::zeroize_witness::observe` hook (no-op in
// production), and then the inner `Vec<u8>` deallocates — in that
// order, so a "buffer dropped without zeroization" regression is
// caught directly by the explicit zeroize-witness tests.

use core::ops::Deref;

use zeroize::Zeroize;

use super::zeroize_witness::{observe, WitnessSite};

/// A `Vec<u8>` whose initialized contents are wiped on drop
/// (docs/DESIGN.md §4.4).
///
/// Deliberately does not derive `Debug`: the payload is plaintext
/// vault material and §4.7's "no debug impls that leak bytes" rule
/// applies.
pub(crate) struct ZeroizingBytes {
    bytes: Vec<u8>,
    site: WitnessSite,
}

impl ZeroizingBytes {
    /// Wrap `bytes` so its initialized region is zeroized at drop.
    pub(crate) fn from_vec(bytes: Vec<u8>, site: WitnessSite) -> Self {
        Self { bytes, site }
    }
}

impl Deref for ZeroizingBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        // Volatile-zero the initialized region in place. Equivalent
        // in security to `<Vec<u8> as Zeroize>::zeroize` minus the
        // trailing `clear()` — we keep `len` intact so the witness
        // hook can observe the post-zeroize state through a safe
        // `&[u8]` borrow. The inner `Vec`'s auto-drop runs after
        // this Drop returns and frees the (now-zeroed) allocation.
        let slice: &mut [u8] = &mut self.bytes;
        slice.zeroize();
        let capacity = self.bytes.capacity();
        observe(self.site, &self.bytes, capacity);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::zeroize_witness::{clear_observations, take_observations};

    #[test]
    fn drop_zeroizes_and_witness_records_all_zero() {
        clear_observations();
        let secret = b"super-secret-vault-payload-bytes".to_vec();
        let secret_len = secret.len();
        let buf = ZeroizingBytes::from_vec(secret, WitnessSite::EncryptPreAead);
        drop(buf);
        let obs = take_observations();
        assert_eq!(obs.len(), 1, "exactly one observation");
        let o = &obs[0];
        assert_eq!(o.site, WitnessSite::EncryptPreAead);
        assert_eq!(o.original_len, secret_len);
        assert!(o.all_zero, "bytes were zeroized before observation");
    }

    #[test]
    fn empty_buffer_records_all_zero_trivially() {
        clear_observations();
        let buf = ZeroizingBytes::from_vec(Vec::new(), WitnessSite::DecryptPostAead);
        drop(buf);
        let obs = take_observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].original_len, 0);
        assert!(obs[0].all_zero);
    }

    #[test]
    fn deref_exposes_initialized_bytes() {
        clear_observations();
        let secret = vec![0xAA, 0xBB, 0xCC];
        let buf = ZeroizingBytes::from_vec(secret, WitnessSite::EncryptPreAead);
        assert_eq!(&*buf, &[0xAA, 0xBB, 0xCC]);
        drop(buf);
        let _ = take_observations();
    }
}
