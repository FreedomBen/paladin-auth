// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Public import facade — `ImportOptions`, `from_bytes`, `from_file`
// (DESIGN.md §4.6 / §4.7).
//
// Auto-detection runs `detect(bytes)` to choose an `ImportFormat`.
// Forced formats override auto-detection but are still sanity-checked
// against the input shape: if `detect` returns a *different* concrete
// format than the forced one, the facade returns
// `unsupported_import_format` carrying the forced format token. A
// detected `Unknown` is permissive under a forced override (the
// importer itself does the parsing).
//
// The `paladin_passphrase` field on [`ImportOptions`] is only
// consulted when dispatching the Paladin format; absence there returns
// `invalid_state { operation: "import_paladin", state: "missing_passphrase" }`.

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use crate::domain::ValidatedAccount;
use crate::error::{PaladinError, Result};

use super::{aegis_plaintext, detect, otpauth, paladin, qr_image, qr_image_bytes, ImportFormat};

/// Caller-supplied controls for [`from_bytes`] / [`from_file`].
#[derive(Debug, Default)]
pub struct ImportOptions {
    /// `None` runs auto-detection via [`detect`]. `Some(format)`
    /// overrides detection but is sanity-checked against the input
    /// shape.
    pub format: Option<ImportFormat>,
    /// Bundle passphrase, required when the dispatch resolves to
    /// [`ImportFormat::Paladin`]. Otherwise ignored.
    pub paladin_passphrase: Option<SecretString>,
}

/// Import bytes from memory (text, JSON, image bytes, or Paladin
/// bundle bytes).
pub fn from_bytes(
    bytes: &[u8],
    options: ImportOptions,
    import_time: SystemTime,
) -> Result<Vec<ValidatedAccount>> {
    let format = resolve_format(bytes, options.format)?;
    match format {
        ImportFormat::Otpauth => otpauth(bytes, import_time),
        ImportFormat::Aegis => aegis_plaintext(bytes, import_time),
        ImportFormat::Paladin => dispatch_paladin_bytes(bytes, options.paladin_passphrase),
        ImportFormat::QrImage => dispatch_qr_bytes(bytes, import_time),
        ImportFormat::Unknown => Err(unsupported(ImportFormat::Unknown)),
    }
}

/// Import from a file path (text, JSON, image, or Paladin bundle).
pub fn from_file(
    path: &Path,
    options: ImportOptions,
    import_time: SystemTime,
) -> Result<Vec<ValidatedAccount>> {
    let bytes = std::fs::read(path).map_err(|err| PaladinError::IoError {
        operation: "read_import_file",
        source: err,
    })?;
    let format = resolve_format(&bytes, options.format)?;
    match format {
        ImportFormat::Otpauth => otpauth(&bytes, import_time),
        ImportFormat::Aegis => aegis_plaintext(&bytes, import_time),
        ImportFormat::Paladin => dispatch_paladin_bytes(&bytes, options.paladin_passphrase),
        // QR file → use the path form so the on-disk image is
        // decoded from disk rather than a buffer copy.
        ImportFormat::QrImage => qr_image(path, import_time),
        ImportFormat::Unknown => Err(unsupported(ImportFormat::Unknown)),
    }
}

fn resolve_format(bytes: &[u8], forced: Option<ImportFormat>) -> Result<ImportFormat> {
    let detected = detect(bytes);
    match forced {
        None => {
            if matches!(detected, ImportFormat::Unknown) {
                return Err(unsupported(ImportFormat::Unknown));
            }
            Ok(detected)
        }
        Some(force) => {
            if matches!(detected, ImportFormat::Unknown) || detected == force {
                Ok(force)
            } else {
                Err(unsupported(force))
            }
        }
    }
}

fn dispatch_paladin_bytes(
    bytes: &[u8],
    passphrase: Option<SecretString>,
) -> Result<Vec<ValidatedAccount>> {
    let pp = passphrase.ok_or(PaladinError::InvalidState {
        operation: "import_paladin",
        state: "missing_passphrase",
    })?;
    paladin(bytes, pp)
}

fn dispatch_qr_bytes(bytes: &[u8], import_time: SystemTime) -> Result<Vec<ValidatedAccount>> {
    let img = image::load_from_memory(bytes).map_err(|err| PaladinError::IoError {
        operation: "decode_image_bytes",
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()),
    })?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    let raw = rgba.into_raw();
    qr_image_bytes(w, h, &raw, import_time)
}

fn unsupported(format: ImportFormat) -> PaladinError {
    PaladinError::UnsupportedImportFormat {
        format: format.as_str().to_string(),
    }
}
