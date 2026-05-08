// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Argon2id key-derivation wrapper (DESIGN.md §4.4).
//
// The KDF derives a 32-byte AEAD key from `(passphrase, salt, params)`
// using Argon2id v1.3 at the cost defined by [`Argon2Params`].
// `validate()` enforces the §4.4 acceptance bounds — `m_kib`
// 8192..=1048576, `t` 1..=10, `p` 1..=4 — so `open` rejects
// attacker-tunable cost before running the KDF.
//
// Defaults (§4.4): `m_kib = 65_536` (64 MiB), `t = 3`, `p = 1`.

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::error::{PaladinError, Result};

/// §4.4 Argon2id memory floor (KiB).
pub(crate) const M_KIB_MIN: u32 = 8_192;
/// §4.4 Argon2id memory ceiling (KiB).
pub(crate) const M_KIB_MAX: u32 = 1_048_576;
/// §4.4 Argon2id time-cost floor.
pub(crate) const T_MIN: u32 = 1;
/// §4.4 Argon2id time-cost ceiling.
pub(crate) const T_MAX: u32 = 10;
/// §4.4 Argon2id parallelism floor.
pub(crate) const P_MIN: u32 = 1;
/// §4.4 Argon2id parallelism ceiling.
pub(crate) const P_MAX: u32 = 4;

/// AEAD key length in bytes (XChaCha20-Poly1305).
#[allow(dead_code)] // Wired into encrypted save/open in later F-series commits.
pub(crate) const AEAD_KEY_LEN: usize = 32;

/// Argon2id cost parameters embedded in the encrypted vault header.
///
/// Defaults to `m_kib = 65_536`, `t = 3`, `p = 1` per §4.4. Pass
/// custom values to encrypted-write entry points
/// ([`EncryptionOptions::with_params`]) to raise costs over time.
/// `open` validates the in-header values against the §4.4 bounds
/// before running Argon2id, so attacker-controlled headers cannot
/// trigger denial-of-service via excessive cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_kib: 65_536,
            t: 3,
            p: 1,
        }
    }
}

impl Argon2Params {
    /// Reject params outside the §4.4 acceptance bounds with
    /// [`PaladinError::KdfParamsOutOfBounds`]. The error payload
    /// always carries the supplied `m_kib`, `t`, and `p` so callers
    /// can render the offending values directly.
    pub fn validate(&self) -> Result<()> {
        if !(M_KIB_MIN..=M_KIB_MAX).contains(&self.m_kib)
            || !(T_MIN..=T_MAX).contains(&self.t)
            || !(P_MIN..=P_MAX).contains(&self.p)
        {
            return Err(PaladinError::KdfParamsOutOfBounds {
                m_kib: self.m_kib,
                t: self.t,
                p: self.p,
            });
        }
        Ok(())
    }
}

/// Caller-supplied passphrase plus the Argon2id parameters new
/// encrypted material will be written under.
///
/// Constructed via [`EncryptionOptions::new`] (default cost) or
/// [`EncryptionOptions::with_params`] (custom validated cost). Both
/// constructors reject empty passphrases with
/// [`PaladinError::InvalidPassphrase`] (no trimming, no Unicode
/// normalization).
pub struct EncryptionOptions {
    pub passphrase: SecretString,
    pub kdf_params: Argon2Params,
}

impl EncryptionOptions {
    /// Construct with default Argon2 cost. Rejects zero-length
    /// passphrases.
    pub fn new(passphrase: SecretString) -> Result<Self> {
        Self::ensure_non_empty(&passphrase)?;
        Ok(Self {
            passphrase,
            kdf_params: Argon2Params::default(),
        })
    }

    /// Construct with caller-supplied Argon2 cost. Rejects zero-length
    /// passphrases and out-of-range `kdf_params`.
    pub fn with_params(passphrase: SecretString, kdf_params: Argon2Params) -> Result<Self> {
        Self::ensure_non_empty(&passphrase)?;
        kdf_params.validate()?;
        Ok(Self {
            passphrase,
            kdf_params,
        })
    }

    fn ensure_non_empty(passphrase: &SecretString) -> Result<()> {
        if passphrase.expose_secret().is_empty() {
            return Err(PaladinError::InvalidPassphrase { reason: "empty" });
        }
        Ok(())
    }
}

// `Debug` is omitted so a stray `dbg!(opts)` cannot leak the
// passphrase. The compile-fail audit in Phase B asserts this.

/// Derive a 32-byte AEAD key from `passphrase`, `salt`, and `params`.
///
/// Pure function: equal inputs always produce equal outputs. Output
/// is wrapped in [`Zeroizing`] so the buffer is wiped when dropped.
///
/// Callers that consume header-supplied parameters MUST run
/// [`Argon2Params::validate`] first; this function does not enforce
/// §4.4 acceptance bounds (KAT vectors live below the floor and need
/// to exercise the wrapper directly).
#[allow(dead_code)] // Wired into encrypted save/open in later F-series commits.
pub(crate) fn argon2id_derive_key(
    passphrase: &SecretString,
    salt: &[u8; 16],
    params: &Argon2Params,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let argon_params =
        Params::new(params.m_kib, params.t, params.p, Some(AEAD_KEY_LEN)).map_err(|_| {
            PaladinError::KdfParamsOutOfBounds {
                m_kib: params.m_kib,
                t: params.t,
                p: params.p,
            }
        })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    argon2
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            salt,
            out.as_mut_slice(),
        )
        .map_err(|_| PaladinError::KdfParamsOutOfBounds {
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
        })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn pp(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn default_params_match_section_4_4_recommendation() {
        let d = Argon2Params::default();
        assert_eq!(d.m_kib, 65_536);
        assert_eq!(d.t, 3);
        assert_eq!(d.p, 1);
    }

    #[test]
    fn validate_accepts_default_params() {
        Argon2Params::default().validate().expect("default valid");
    }

    #[test]
    fn validate_accepts_min_and_max_bounds() {
        for (m, t, p) in [
            (M_KIB_MIN, T_MIN, P_MIN),
            (M_KIB_MAX, T_MAX, P_MAX),
            (65_536, 3, 1),
            (262_144, 4, 2),
        ] {
            Argon2Params { m_kib: m, t, p }
                .validate()
                .unwrap_or_else(|_| panic!("expected ({m}, {t}, {p}) valid"));
        }
    }

    #[test]
    fn validate_rejects_m_kib_below_floor() {
        let err = Argon2Params {
            m_kib: M_KIB_MIN - 1,
            t: 3,
            p: 1,
        }
        .validate()
        .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
        match err {
            PaladinError::KdfParamsOutOfBounds { m_kib, t, p } => {
                assert_eq!(m_kib, M_KIB_MIN - 1);
                assert_eq!(t, 3);
                assert_eq!(p, 1);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_m_kib_above_ceiling() {
        let err = Argon2Params {
            m_kib: M_KIB_MAX + 1,
            t: 3,
            p: 1,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 1_048_577,
                t: 3,
                p: 1
            }
        ));
    }

    #[test]
    fn validate_rejects_t_below_floor() {
        let err = Argon2Params {
            m_kib: 65_536,
            t: 0,
            p: 1,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 65_536,
                t: 0,
                p: 1
            }
        ));
    }

    #[test]
    fn validate_rejects_t_above_ceiling() {
        let err = Argon2Params {
            m_kib: 65_536,
            t: 11,
            p: 1,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 65_536,
                t: 11,
                p: 1
            }
        ));
    }

    #[test]
    fn validate_rejects_p_below_floor() {
        let err = Argon2Params {
            m_kib: 65_536,
            t: 3,
            p: 0,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 65_536,
                t: 3,
                p: 0
            }
        ));
    }

    #[test]
    fn validate_rejects_p_above_ceiling() {
        let err = Argon2Params {
            m_kib: 65_536,
            t: 3,
            p: 5,
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            err,
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 65_536,
                t: 3,
                p: 5
            }
        ));
    }

    #[test]
    fn boundary_table_for_m_kib() {
        // 8191 reject, 8192 accept, 1048576 accept, 1048577 reject.
        assert!(matches!(
            Argon2Params {
                m_kib: 8_191,
                t: 3,
                p: 1
            }
            .validate()
            .unwrap_err(),
            PaladinError::KdfParamsOutOfBounds { m_kib: 8_191, .. }
        ));
        Argon2Params {
            m_kib: 8_192,
            t: 3,
            p: 1,
        }
        .validate()
        .expect("8192 accepted");
        Argon2Params {
            m_kib: 1_048_576,
            t: 3,
            p: 1,
        }
        .validate()
        .expect("1048576 accepted");
        assert!(matches!(
            Argon2Params {
                m_kib: 1_048_577,
                t: 3,
                p: 1
            }
            .validate()
            .unwrap_err(),
            PaladinError::KdfParamsOutOfBounds {
                m_kib: 1_048_577,
                ..
            }
        ));
    }

    #[test]
    fn boundary_table_for_t() {
        assert!(matches!(
            Argon2Params {
                m_kib: 65_536,
                t: 0,
                p: 1
            }
            .validate()
            .unwrap_err(),
            PaladinError::KdfParamsOutOfBounds { t: 0, .. }
        ));
        Argon2Params {
            m_kib: 65_536,
            t: 1,
            p: 1,
        }
        .validate()
        .expect("t=1 accepted");
        Argon2Params {
            m_kib: 65_536,
            t: 10,
            p: 1,
        }
        .validate()
        .expect("t=10 accepted");
        assert!(matches!(
            Argon2Params {
                m_kib: 65_536,
                t: 11,
                p: 1
            }
            .validate()
            .unwrap_err(),
            PaladinError::KdfParamsOutOfBounds { t: 11, .. }
        ));
    }

    #[test]
    fn boundary_table_for_p() {
        assert!(matches!(
            Argon2Params {
                m_kib: 65_536,
                t: 3,
                p: 0
            }
            .validate()
            .unwrap_err(),
            PaladinError::KdfParamsOutOfBounds { p: 0, .. }
        ));
        Argon2Params {
            m_kib: 65_536,
            t: 3,
            p: 1,
        }
        .validate()
        .expect("p=1 accepted");
        Argon2Params {
            m_kib: 65_536,
            t: 3,
            p: 4,
        }
        .validate()
        .expect("p=4 accepted");
        assert!(matches!(
            Argon2Params {
                m_kib: 65_536,
                t: 3,
                p: 5
            }
            .validate()
            .unwrap_err(),
            PaladinError::KdfParamsOutOfBounds { p: 5, .. }
        ));
    }

    #[test]
    fn encryption_options_new_uses_default_params() {
        let opts = EncryptionOptions::new(pp("hunter2")).expect("non-empty accepted");
        assert_eq!(opts.kdf_params, Argon2Params::default());
        assert_eq!(opts.passphrase.expose_secret(), "hunter2");
    }

    #[test]
    fn encryption_options_new_rejects_empty_passphrase() {
        match EncryptionOptions::new(pp("")) {
            Ok(_) => panic!("expected InvalidPassphrase"),
            Err(PaladinError::InvalidPassphrase { reason }) => assert_eq!(reason, "empty"),
            Err(other) => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn encryption_options_with_params_accepts_custom_in_range() {
        let custom = Argon2Params {
            m_kib: 262_144,
            t: 4,
            p: 2,
        };
        let opts = EncryptionOptions::with_params(pp("hunter2"), custom)
            .expect("custom in-range accepted");
        assert_eq!(opts.kdf_params, custom);
    }

    #[test]
    fn encryption_options_with_params_rejects_out_of_range() {
        let bad = Argon2Params {
            m_kib: 7_000,
            t: 3,
            p: 1,
        };
        match EncryptionOptions::with_params(pp("hunter2"), bad) {
            Ok(_) => panic!("expected KdfParamsOutOfBounds"),
            Err(PaladinError::KdfParamsOutOfBounds { m_kib, t, p }) => {
                assert_eq!((m_kib, t, p), (7_000, 3, 1));
            }
            Err(other) => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn encryption_options_with_params_rejects_empty_before_bounds() {
        // Even if params would also fail, we report the empty-passphrase
        // error first so the caller sees the user-facing reason.
        let bad = Argon2Params {
            m_kib: 0,
            t: 0,
            p: 0,
        };
        match EncryptionOptions::with_params(pp(""), bad) {
            Ok(_) => panic!("expected InvalidPassphrase"),
            Err(PaladinError::InvalidPassphrase { .. }) => {}
            Err(other) => panic!("unexpected variant: {other:?}"),
        }
    }

    /// Cheapest in-range cost (8192 KiB / t=1 / p=1) so the suite stays
    /// fast. The §4.4 acceptance floor requires `m_kib` >= 8192 anyway.
    fn cheap_params() -> Argon2Params {
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        }
    }

    #[test]
    fn argon2id_derive_key_is_deterministic() {
        let salt = [0x05u8; 16];
        let a = argon2id_derive_key(&pp("correct horse"), &salt, &cheap_params()).unwrap();
        let b = argon2id_derive_key(&pp("correct horse"), &salt, &cheap_params()).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn argon2id_derive_key_is_pure_function_of_inputs() {
        // Different passphrase changes the output.
        let salt = [0x05u8; 16];
        let a = argon2id_derive_key(&pp("alpha"), &salt, &cheap_params()).unwrap();
        let b = argon2id_derive_key(&pp("beta"), &salt, &cheap_params()).unwrap();
        assert_ne!(a.as_slice(), b.as_slice());

        // Different salt changes the output.
        let salt2 = [0x06u8; 16];
        let c = argon2id_derive_key(&pp("alpha"), &salt2, &cheap_params()).unwrap();
        assert_ne!(a.as_slice(), c.as_slice());

        // Different params change the output.
        let bumped = Argon2Params {
            m_kib: 8_192,
            t: 2,
            p: 1,
        };
        let d = argon2id_derive_key(&pp("alpha"), &salt, &bumped).unwrap();
        assert_ne!(a.as_slice(), d.as_slice());
    }

    /// Self-pinned KAT — pins the exact crate configuration Paladin
    /// wires (Argon2id v1.3, 32-byte output) so a drop-in algorithm
    /// or version change cannot silently re-derive keys.
    #[test]
    fn argon2id_derive_key_known_answer_self_pinned() {
        let passphrase = pp("paladin-test-passphrase");
        let salt = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let key = argon2id_derive_key(&passphrase, &salt, &cheap_params()).unwrap();
        // Pinned bytes captured from the Argon2id v1.3 implementation
        // wired in `Cargo.toml` (`argon2 = "0.5"`) at parameters
        // (m_kib=8192, t=1, p=1) with the salt and passphrase above.
        let expected: [u8; 32] = [
            0x7C, 0x90, 0xAC, 0x83, 0x75, 0x4D, 0xEF, 0x82, 0x07, 0x44, 0xC1, 0x97, 0xAB, 0x78,
            0xF5, 0x7B, 0xC5, 0x56, 0xB4, 0x73, 0x8B, 0x50, 0x95, 0x23, 0x1E, 0xC9, 0xEC, 0x88,
            0x65, 0xDC, 0x0C, 0x80,
        ];
        assert_eq!(
            *key, expected,
            "Argon2id KAT mismatch (drop-in regression?)"
        );
    }
}
