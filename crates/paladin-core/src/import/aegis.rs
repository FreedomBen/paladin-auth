// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `import::aegis_plaintext` (DESIGN.md §4.6 / §4.7).
//
// Aegis Authenticator JSON exports come in two top-level shapes:
//
//   - Plaintext: `db` is a JSON object whose `entries[]` array holds
//     individual TOTP/HOTP entries.
//   - Encrypted: `db` is a base64-encoded ciphertext string. v0.1
//     surfaces these uniformly as `unsupported_encrypted_aegis`.
//
// Per-entry mapping (only `totp` and `hotp` types are supported):
//
//   - `name`              → `label` (required)
//   - `issuer`            → `issuer` (optional)
//   - `info.secret`       → secret (required, base32 RFC 4648)
//   - `info.algo`         → algorithm (default SHA1, case-insensitive)
//   - `info.digits`       → digits (default 6)
//   - `info.period`       → TOTP period (default 30)
//   - `info.counter`      → HOTP counter (required for HOTP)
//   - `note` / `icon`     → ignored; `icon_hint` derives from issuer
//
// Per the Phase I spec, an unsupported `type` aborts the entire batch
// with `unsupported_aegis_entry_type` carrying the offending row's
// `source_index` and raw `entry_type`.

use std::time::SystemTime;

use serde::Deserialize;

use crate::domain::validation::{
    decode_and_validate_secret, validate_digits, validate_issuer, validate_label,
    validate_totp_period, ParsedAccount, DIGITS_DEFAULT, TOTP_PERIOD_DEFAULT,
};
use crate::domain::{Algorithm, IconHintInput, OtpKind, ValidatedAccount, ValidationWarning};
use crate::error::{PaladinError, Result};
use crate::otpauth::parse_algorithm;

#[derive(Deserialize)]
struct AegisExport {
    #[serde(default)]
    db: serde_json::Value,
}

#[derive(Deserialize)]
struct AegisDb {
    #[serde(default)]
    entries: Vec<AegisEntry>,
}

#[derive(Deserialize)]
struct AegisEntry {
    #[serde(rename = "type")]
    entry_type: Option<String>,
    name: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    info: Option<AegisInfo>,
}

#[derive(Deserialize)]
struct AegisInfo {
    secret: Option<String>,
    algo: Option<String>,
    digits: Option<u8>,
    period: Option<u32>,
    counter: Option<u64>,
}

/// Parse an Aegis plaintext JSON export into validated accounts.
pub fn aegis_plaintext(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>> {
    let export: AegisExport = serde_json::from_slice(bytes)
        .map_err(|e| PaladinError::validation("input", format!("invalid_json: {e}")))?;

    let db_value = export.db;
    if db_value.is_null() {
        return Err(PaladinError::validation("db", "missing"));
    }
    if db_value.is_string() {
        return Err(PaladinError::UnsupportedEncryptedAegis);
    }
    if !db_value.is_object() {
        return Err(PaladinError::validation("db", "expected_object_or_string"));
    }
    let db: AegisDb = serde_json::from_value(db_value)
        .map_err(|e| PaladinError::validation("db", format!("invalid_db: {e}")))?;

    if db.entries.is_empty() {
        return Err(PaladinError::NoEntriesToImport);
    }

    let mut out = Vec::with_capacity(db.entries.len());
    for (idx, entry) in db.entries.into_iter().enumerate() {
        let va = build_account(entry, import_time, idx)?;
        out.push(va);
    }
    Ok(out)
}

fn build_account(
    entry: AegisEntry,
    import_time: SystemTime,
    idx: usize,
) -> Result<ValidatedAccount> {
    let entry_type = entry
        .entry_type
        .ok_or_else(|| PaladinError::validation("type", "missing").tag_source_index(idx))?;
    let kind_token = entry_type.to_ascii_lowercase();
    let is_hotp = match kind_token.as_str() {
        "totp" => false,
        "hotp" => true,
        _ => {
            return Err(PaladinError::UnsupportedAegisEntryType {
                source_index: idx,
                entry_type,
            });
        }
    };

    let name = entry
        .name
        .ok_or_else(|| PaladinError::validation("name", "missing").tag_source_index(idx))?;
    let label = validate_label(&name).map_err(|e| e.tag_source_index(idx))?;

    let issuer = validate_issuer(entry.issuer.as_deref()).map_err(|e| e.tag_source_index(idx))?;

    let info = entry
        .info
        .ok_or_else(|| PaladinError::validation("info", "missing").tag_source_index(idx))?;

    let secret_text = info
        .secret
        .ok_or_else(|| PaladinError::validation("secret", "missing").tag_source_index(idx))?;
    let (secret, secret_warning) =
        decode_and_validate_secret(&secret_text).map_err(|e| e.tag_source_index(idx))?;

    let algorithm = match info.algo.as_deref() {
        None => Algorithm::Sha1,
        Some(s) => parse_algorithm(s).map_err(|e| e.tag_source_index(idx))?,
    };

    let digits = validate_digits(info.digits.unwrap_or(DIGITS_DEFAULT), DIGITS_DEFAULT)
        .map_err(|e| e.tag_source_index(idx))?;

    let kind = if is_hotp {
        let counter = info
            .counter
            .ok_or_else(|| PaladinError::validation("counter", "missing").tag_source_index(idx))?;
        OtpKind::Hotp { counter }
    } else {
        let period = validate_totp_period(info.period.unwrap_or(TOTP_PERIOD_DEFAULT))
            .map_err(|e| e.tag_source_index(idx))?;
        OtpKind::Totp { period }
    };

    let icon_hint = IconHintInput::Default
        .resolve(issuer.as_deref())
        .map_err(|e| e.tag_source_index(idx))?;

    let parsed = ParsedAccount {
        label,
        issuer,
        secret,
        algorithm,
        digits,
        kind,
        icon_hint,
    };
    let warnings: Vec<ValidationWarning> = secret_warning.into_iter().collect();
    parsed
        .into_validated(import_time, warnings)
        .map_err(|e| e.tag_source_index(idx))
}
