// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Crypto primitives (docs/DESIGN.md §4.4).
//
// Phase F.1 lands the Argon2id wrapper plus `Argon2Params` and
// `EncryptionOptions`. Phase F.2 added the XChaCha20-Poly1305 AEAD
// wrapper that consumes the derived 32-byte key. Phase F.14 adds the
// `ZeroizingBytes` plaintext buffer wrapper (with its zeroize witness)
// that the encrypted-storage paths hold around the bincode payload
// going into AEAD encrypt and around the plaintext coming out of AEAD
// decrypt.

pub(crate) mod aead;
pub(crate) mod buffer;
pub(crate) mod kdf;
/// Test-only zeroization witness instrumentation (`test-zeroize-witness` feature, docs/DESIGN.md §4.4 / Phase F.14).
pub mod zeroize_witness;

pub use kdf::{Argon2Params, EncryptionOptions};

#[cfg(feature = "test-fault-injection")]
pub use kdf::argon2_derivation_count;

#[allow(unused_imports)] // Wired into encrypted save/open in later F-series commits.
pub(crate) use aead::{aead_decrypt, aead_encrypt, AEAD_NONCE_LEN, AEAD_TAG_LEN};
pub(crate) use buffer::ZeroizingBytes;
#[allow(unused_imports)] // Wired into encrypted save/open in later F-series commits.
pub(crate) use kdf::{argon2id_derive_key, AEAD_KEY_LEN};
pub(crate) use zeroize_witness::WitnessSite;
