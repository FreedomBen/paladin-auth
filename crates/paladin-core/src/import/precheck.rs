// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `classify_paladin_import_precheck` (DESIGN.md §4.6 / §4.7).
//
// Front-ends call this helper *before* invoking
// [`crate::import::from_file`] so they know whether to prompt for a
// Paladin bundle passphrase. The helper inspects only the file
// header — it never decrypts and never falls through to the other
// importers' parsers, so its result is independent of bundle size or
// payload contents.
//
// Behavior table:
//
//   - Forced format ∈ {Otpauth, Aegis, QrImage, Unknown} →
//     [`PaladinImportPrecheck::NoPrompt`] without reading the file
//     (file may not even exist; the actual importer surfaces that).
//   - Forced format = Paladin or auto-detect (None):
//       - Missing / unreadable file / empty file → `NoPrompt`
//         (`from_file` is the owner of `read_import_file` errors).
//       - Non-`PALADIN\0` magic → `NoPrompt` (the input is not a
//         Paladin bundle).
//       - `PALADIN\0` + `format_ver` ≠ current →
//         `Reject(unsupported_format_version)`.
//       - `PALADIN\0` + valid `format_ver` + plaintext mode →
//         `Reject(unsupported_plaintext_vault)`.
//       - `PALADIN\0` + valid `format_ver` + unknown mode (or
//         truncated header that starts with `PALADIN\0`) →
//         `Reject(invalid_header)`.
//       - `PALADIN\0` + valid `format_ver` + encrypted mode →
//         [`PaladinImportPrecheck::PromptForPassphrase`].

use std::path::Path;

use crate::error::PaladinError;
use crate::storage::header::{parse_header, ParsedHeader, MAGIC as PALADIN_MAGIC};

use super::ImportFormat;

/// Result of [`classify_paladin_import_precheck`].
///
/// Used by CLI / TUI / GUI import flows to decide whether to prompt
/// the user for a Paladin bundle passphrase before invoking the
/// importer.
#[derive(Debug)]
pub enum PaladinImportPrecheck {
    /// Skip the Paladin passphrase prompt. The input is either not a
    /// Paladin bundle, the path is unreadable / missing (the importer
    /// will surface the IO error), or the forced format pre-empts the
    /// Paladin path entirely.
    NoPrompt,
    /// Encrypted Paladin header detected. Front-ends should collect a
    /// passphrase before calling [`crate::import::from_file`] /
    /// [`crate::import::from_bytes`].
    PromptForPassphrase,
    /// Header is recognizably a Paladin bundle but cannot be
    /// imported. The carried error matches what the importer itself
    /// would return so the front end can surface a single error
    /// without having to call the importer afterwards.
    Reject(PaladinError),
}

/// Inspect `path` enough to decide whether the Paladin import path
/// will need a passphrase prompt.
#[must_use]
pub fn classify_paladin_import_precheck(
    path: &Path,
    forced_format: Option<ImportFormat>,
) -> PaladinImportPrecheck {
    match forced_format {
        Some(
            ImportFormat::Otpauth
            | ImportFormat::Aegis
            | ImportFormat::QrImage
            | ImportFormat::Unknown,
        ) => return PaladinImportPrecheck::NoPrompt,
        Some(ImportFormat::Paladin) | None => {}
    }

    // Read just enough bytes to classify the header. We pass through
    // the same parser the importer uses so the verdict is byte-stable
    // with the actual decrypt path.
    let Ok(bytes) = std::fs::read(path) else {
        return PaladinImportPrecheck::NoPrompt;
    };

    if !bytes.starts_with(&PALADIN_MAGIC) {
        return PaladinImportPrecheck::NoPrompt;
    }

    match parse_header(&bytes) {
        Ok(ParsedHeader::Encrypted(_)) => PaladinImportPrecheck::PromptForPassphrase,
        Ok(ParsedHeader::Plaintext) => {
            PaladinImportPrecheck::Reject(PaladinError::UnsupportedPlaintextVault)
        }
        Err(err) => PaladinImportPrecheck::Reject(err),
    }
}
