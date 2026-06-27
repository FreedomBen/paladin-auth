// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `classify_paladin_auth_import_precheck` (docs/DESIGN.md §4.6 / §4.7).
//
// Front-ends call this helper *before* invoking
// [`crate::import::from_file`] so they know whether to prompt for a
// Paladin Auth bundle passphrase. The helper inspects only the file
// header — it never decrypts and never falls through to the other
// importers' parsers, so its result is independent of bundle size or
// payload contents.
//
// Behavior table:
//
//   - Forced format ∈ {Otpauth, Aegis, QrImage, Unknown} →
//     [`PaladinAuthImportPrecheck::NoPrompt`] without reading the file
//     (file may not even exist; the actual importer surfaces that).
//   - Forced format = Paladin Auth or auto-detect (None):
//       - Missing / unreadable file / empty file → `NoPrompt`
//         (`from_file` is the owner of `read_import_file` errors).
//       - Non-`PALAUTH\0` magic → `NoPrompt` (the input is not a
//         Paladin Auth bundle).
//       - `PALAUTH\0` + `format_ver` ≠ current →
//         `Reject(unsupported_format_version)`.
//       - `PALAUTH\0` + valid `format_ver` + plaintext mode →
//         `Reject(unsupported_plaintext_vault)`.
//       - `PALAUTH\0` + valid `format_ver` + unknown mode (or
//         truncated header that starts with `PALAUTH\0`) →
//         `Reject(invalid_header)`.
//       - `PALAUTH\0` + valid `format_ver` + encrypted mode →
//         [`PaladinAuthImportPrecheck::PromptForPassphrase`].

use std::path::Path;

use crate::error::PaladinAuthError;
use crate::storage::header::{parse_header, ParsedHeader, MAGIC as PALADIN_AUTH_MAGIC};

use super::ImportFormat;

/// Result of [`classify_paladin_auth_import_precheck`].
///
/// Used by CLI / TUI / GUI import flows to decide whether to prompt
/// the user for a Paladin Auth bundle passphrase before invoking the
/// importer.
#[derive(Debug)]
pub enum PaladinAuthImportPrecheck {
    /// Skip the Paladin Auth passphrase prompt. The input is either not a
    /// Paladin Auth bundle, the path is unreadable / missing (the importer
    /// will surface the IO error), or the forced format pre-empts the
    /// Paladin Auth path entirely.
    NoPrompt,
    /// Encrypted Paladin Auth header detected. Front-ends should collect a
    /// passphrase before calling [`crate::import::from_file`] /
    /// [`crate::import::from_bytes`].
    PromptForPassphrase,
    /// Header is recognizably a Paladin Auth bundle but cannot be
    /// imported. The carried error matches what the importer itself
    /// would return so the front end can surface a single error
    /// without having to call the importer afterwards.
    Reject(PaladinAuthError),
}

/// Inspect `path` enough to decide whether the Paladin Auth import path
/// will need a passphrase prompt.
#[must_use]
pub fn classify_paladin_auth_import_precheck(
    path: &Path,
    forced_format: Option<ImportFormat>,
) -> PaladinAuthImportPrecheck {
    match forced_format {
        Some(
            ImportFormat::Otpauth
            | ImportFormat::Aegis
            | ImportFormat::QrImage
            | ImportFormat::Unknown,
        ) => return PaladinAuthImportPrecheck::NoPrompt,
        Some(ImportFormat::PaladinAuth) | None => {}
    }

    // Read just enough bytes to classify the header. We pass through
    // the same parser the importer uses so the verdict is byte-stable
    // with the actual decrypt path.
    let Ok(bytes) = std::fs::read(path) else {
        return PaladinAuthImportPrecheck::NoPrompt;
    };

    if !bytes.starts_with(&PALADIN_AUTH_MAGIC) {
        return PaladinAuthImportPrecheck::NoPrompt;
    }

    match parse_header(&bytes) {
        Ok(ParsedHeader::Encrypted(_)) => PaladinAuthImportPrecheck::PromptForPassphrase,
        Ok(ParsedHeader::Plaintext) => {
            PaladinAuthImportPrecheck::Reject(PaladinAuthError::UnsupportedPlaintextVault)
        }
        Err(err) => PaladinAuthImportPrecheck::Reject(err),
    }
}
