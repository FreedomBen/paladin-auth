// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K coverage — `EncryptionOptions::with_params` rejects
// out-of-§4.4-bounds `Argon2Params` at construction time
// (docs/DESIGN.md §4.4 / §4.7).
//
// Existing tests cover the empty-passphrase reject path. They also
// cover header-tamper out-of-bounds paths (where the bad params come
// from a malicious vault file). This file pins the third entry
// point: a *caller* (CLI / TUI / GUI) handing under- or over-cost
// params straight to `with_params` must be rejected before any
// crypto runs, with the exact offending values surfaced in the
// `KdfParamsOutOfBounds` error payload.

use paladin_core::{Argon2Params, EncryptionOptions, ErrorKind, PaladinError};
use secrecy::SecretString;

#[test]
fn new_rejects_empty_passphrase_with_zero_length_reason() {
    // `EncryptionOptions::new` is the default-Argon2-cost
    // constructor (separate code path from `with_params`). It must
    // also reject an empty passphrase with the stable
    // `InvalidPassphrase { reason: "zero_length" }` shape so CLI /
    // TUI / GUI callers that pick the simpler entry point still
    // surface the same error.
    let err = EncryptionOptions::new(SecretString::from(String::new())).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPassphrase);
    let PaladinError::InvalidPassphrase { reason } = err else {
        panic!("expected InvalidPassphrase")
    };
    assert_eq!(reason, "zero_length");
}

#[test]
fn new_accepts_non_empty_passphrase_with_default_params() {
    let opts = EncryptionOptions::new(SecretString::from("hunter2".to_string()))
        .expect("non-empty pass accepted");
    assert_eq!(opts.kdf_params, Argon2Params::default());
}

fn pp(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

#[test]
fn with_params_rejects_m_kib_below_floor_and_surfaces_offending_values() {
    let params = Argon2Params {
        m_kib: 4096,
        t: 3,
        p: 1,
    };
    let err = EncryptionOptions::with_params(pp("hunter2"), params).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
    let PaladinError::KdfParamsOutOfBounds { m_kib, t, p } = err else {
        panic!("expected KdfParamsOutOfBounds")
    };
    assert_eq!((m_kib, t, p), (4096, 3, 1));
}

#[test]
fn with_params_rejects_m_kib_above_ceiling() {
    let params = Argon2Params {
        m_kib: 2_097_152,
        t: 3,
        p: 1,
    };
    let err = EncryptionOptions::with_params(pp("hunter2"), params).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn with_params_rejects_t_below_floor() {
    let params = Argon2Params {
        m_kib: 65_536,
        t: 0,
        p: 1,
    };
    let err = EncryptionOptions::with_params(pp("hunter2"), params).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn with_params_rejects_t_above_ceiling() {
    let params = Argon2Params {
        m_kib: 65_536,
        t: 11,
        p: 1,
    };
    let err = EncryptionOptions::with_params(pp("hunter2"), params).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn with_params_rejects_p_below_floor() {
    let params = Argon2Params {
        m_kib: 65_536,
        t: 3,
        p: 0,
    };
    let err = EncryptionOptions::with_params(pp("hunter2"), params).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn with_params_rejects_p_above_ceiling() {
    let params = Argon2Params {
        m_kib: 65_536,
        t: 3,
        p: 5,
    };
    let err = EncryptionOptions::with_params(pp("hunter2"), params).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::KdfParamsOutOfBounds);
}

#[test]
fn with_params_accepts_section_4_4_default_params() {
    // Sanity check that the §4.4 defaults pass — pin against a
    // regression that tightens the floor/ceiling past the documented
    // defaults.
    let params = Argon2Params::default();
    let opts =
        EncryptionOptions::with_params(pp("hunter2"), params).expect("default params accepted");
    assert_eq!(opts.kdf_params, params);
}
