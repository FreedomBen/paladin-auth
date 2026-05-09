// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `import::otpauth` — single URI / line list / JSON array of URIs
// (DESIGN.md §4.6 / §4.7).
//
// Behavior:
//   - Bytes must be valid UTF-8; otherwise `validation_error`
//     (`field: "input"`, `reason: "invalid_utf8"`).
//   - Surrounding ASCII whitespace tolerated.
//   - JSON-array input: each element must be a string. Non-string
//     elements abort the batch with `validation_error`
//     (`field: "uri"`, `reason: "expected_string"`) tagged with the
//     element's zero-based `source_index`.
//   - Line-list input: blank lines tolerated; any line containing an
//     embedded NUL byte aborts the batch with `validation_error`
//     (`field: "uri"`, `reason: "embedded_nul"`) tagged with the
//     non-blank-row index *before* attempting to decode the secret.
//   - Each candidate URI is parsed via `parse_otpauth(uri,
//     import_time)`; per-URI parse errors are tagged with the row's
//     `source_index` and abort the batch (per Phase I "batch
//     atomicity: any validation failure aborts the batch").
//   - Empty input (after whitespace stripping / empty JSON array)
//     returns `no_entries_to_import`.

use std::time::SystemTime;

use crate::domain::ValidatedAccount;
use crate::error::{PaladinError, Result};
use crate::otpauth::parse_otpauth;

/// Wrapper accepting bytes from a single URI text, a newline-separated
/// list of URIs, or a JSON array of URI strings; produces a
/// `Vec<ValidatedAccount>` ready for [`crate::Vault::import_accounts`].
pub fn otpauth(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PaladinError::validation("input", "invalid_utf8"))?;
    let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.is_empty() {
        return Err(PaladinError::NoEntriesToImport);
    }

    let candidates = if trimmed.starts_with('[') {
        collect_json_array(trimmed)?
    } else {
        collect_line_list(trimmed)?
    };

    if candidates.is_empty() {
        return Err(PaladinError::NoEntriesToImport);
    }

    let mut out = Vec::with_capacity(candidates.len());
    for (idx, uri) in candidates.into_iter().enumerate() {
        let va = parse_otpauth(&uri, import_time).map_err(|e| e.tag_source_index(idx))?;
        out.push(va);
    }
    Ok(out)
}

fn collect_json_array(trimmed: &str) -> Result<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| PaladinError::validation("input", format!("invalid_json: {e}")))?;
    let serde_json::Value::Array(arr) = value else {
        return Err(PaladinError::validation("input", "expected_array"));
    };
    let mut out = Vec::with_capacity(arr.len());
    for (idx, item) in arr.into_iter().enumerate() {
        match item {
            serde_json::Value::String(s) => out.push(s),
            _ => {
                return Err(PaladinError::validation("uri", "expected_string").tag_source_index(idx))
            }
        }
    }
    Ok(out)
}

fn collect_line_list(trimmed: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for line in trimmed.split('\n') {
        let line = line.trim_end_matches('\r');
        let row = line.trim_matches(|c: char| c.is_ascii_whitespace());
        if row.is_empty() {
            continue;
        }
        let idx = out.len();
        if row.as_bytes().contains(&0) {
            return Err(PaladinError::validation("uri", "embedded_nul").tag_source_index(idx));
        }
        out.push(row.to_string());
    }
    Ok(out)
}
