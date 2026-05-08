// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Crypto primitives (DESIGN.md §4.4).
//
// Phase F.1 lands the Argon2id wrapper plus `Argon2Params` and
// `EncryptionOptions`. Phase F.2 will add the XChaCha20-Poly1305 AEAD
// wrapper that consumes the derived 32-byte key.

pub(crate) mod aead;
pub(crate) mod kdf;

pub use kdf::{Argon2Params, EncryptionOptions};

#[cfg(feature = "test-fault-injection")]
pub use kdf::argon2_derivation_count;

#[allow(unused_imports)] // Wired into encrypted save/open in later F-series commits.
pub(crate) use aead::{aead_decrypt, aead_encrypt, AEAD_NONCE_LEN, AEAD_TAG_LEN};
#[allow(unused_imports)] // Wired into encrypted save/open in later F-series commits.
pub(crate) use kdf::{argon2id_derive_key, AEAD_KEY_LEN};
