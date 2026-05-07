// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Vault storage (DESIGN.md §4.3).
//
// Phase E ships the in-memory `VaultPayload` + bincode v2 codec
// (little-endian, fixed-int, 16 MiB cap, full-input consumption), the
// on-disk header parser, the default vault-path resolver, the
// `inspect` header probe, the `classify_init_precheck` truth table,
// and the plaintext-mode `Store` lifecycle (`open` / `create` /
// atomic-write save with `.bak` rotation and leftover-tmp cleanup).
//
// Phase E.2 layers the §4.3 permissions enforcement on top
// (`unsafe_permissions` with `vault_dir` / `vault_file` /
// `backup_file` discriminator); E.3 adds the `init --force` staged
// clobber (`Store::create_force`), symbolic-link rejection on the
// three storage paths, and propagation of `cleanup_temp_file` errors
// when a leftover `vault.bin.tmp` / `vault.bin.bak.tmp` is something
// `fs::remove_file` cannot handle (e.g. a directory). Phase F adds the
// encrypted variants of `VaultLock` / `VaultInit` and the AEAD
// save/open paths.
//
// Public surface from this module (re-exported at the crate root via
// `lib.rs`):
//
// * `default_vault_path`
// * `inspect`
// * `VaultStatus`
// * `VaultSettings` (already published from `payload`)
// * `InitPrecheck` + `classify_init_precheck`
// * `Store` + `VaultLock` + `VaultInit`

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::{PaladinError, Result, VaultMode};

pub(crate) mod header;
pub mod path;
pub mod payload;
#[cfg(not(unix))]
mod perms_other;
#[cfg(unix)]
mod perms_unix;

pub use path::default_vault_path;
pub use payload::VaultSettings;
pub(crate) use payload::{decode_vault_payload, encode_vault_payload, VaultPayload};

use header::{parse_header, ParsedHeader, ENCRYPTED_HEADER_LEN, PLAINTEXT_HEADER_LEN};
use payload::MAX_PAYLOAD_BYTES;

#[cfg(not(unix))]
use perms_other::{enforce_dir_perms, enforce_file_perms_from_meta};
#[cfg(unix)]
use perms_unix::{enforce_dir_perms, enforce_file_perms_from_meta};

use crate::error::PermissionSubject;

/// Result of the `inspect()` header probe (DESIGN.md §4.7).
///
/// `Missing` reflects an absent primary file — distinct from any I/O
/// error (which is propagated as `io_error`) and from an unrecognized
/// header (`invalid_header`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus {
    /// Plaintext vault file present at the path.
    Plaintext,
    /// Encrypted vault file present at the path.
    Encrypted,
    /// No primary file at the path.
    Missing,
}

/// Read the header of `path` and report the vault mode without
/// decrypting the payload.
///
/// * `Ok(Missing)` iff the primary file does not exist.
/// * `Ok(Plaintext)` / `Ok(Encrypted)` for a valid v0.1 header.
/// * `Err(invalid_header)` for unknown magic / mode / KDF id / AEAD id.
/// * `Err(unsupported_format_version)` for `format_ver != 1`.
/// * `Err(io_error { operation: "read_vault_file" })` for any other
///   filesystem failure (e.g. permission denied).
///
/// `inspect` deliberately does **not** enforce the §4.3 permissions
/// check — only `open`, `create`, and `create_force` do — so callers
/// can probe a vault's mode before fixing perms.
pub fn inspect(path: &Path) -> Result<VaultStatus> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VaultStatus::Missing);
        }
        Err(err) => {
            return Err(PaladinError::IoError {
                operation: "read_vault_file",
                source: err,
            });
        }
    };

    // We only need up to ENCRYPTED_HEADER_LEN bytes to classify the
    // file. Reading more would be wasteful, and reading less would
    // mishandle encrypted vaults whose trailer extends to byte 64.
    let mut buf = [0u8; ENCRYPTED_HEADER_LEN];
    let n = read_up_to(&mut file, &mut buf)?;
    match parse_header(&buf[..n])? {
        ParsedHeader::Plaintext => Ok(VaultStatus::Plaintext),
        ParsedHeader::Encrypted(_) => Ok(VaultStatus::Encrypted),
    }
}

/// Read up to `buf.len()` bytes from `f`, returning the number actually
/// filled. Short files are not an error; a read error becomes an
/// `io_error` with `operation: "read_vault_file"`.
fn read_up_to(f: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => (),
            Err(err) => {
                return Err(PaladinError::IoError {
                    operation: "read_vault_file",
                    source: err,
                });
            }
        }
    }
    Ok(filled)
}

/// Init-flow precheck classification (DESIGN.md §5).
///
/// CLI `init` and GUI `InitDialog` share this truth table so they
/// agree on when an existing vault must be confirmed-clobbered with
/// `--force` and when a non-init error should bubble verbatim.
#[derive(Debug)]
pub enum InitPrecheck {
    /// No conflicting file exists; init can proceed.
    Clear,
    /// A conflicting file (or a header indicating one used to exist)
    /// is present; init must require `--force` to clobber.
    Existing,
    /// A non-init failure occurred (e.g. unsafe perms, transient I/O
    /// error). Front ends propagate it verbatim.
    Propagate(PaladinError),
}

/// Map a `Result<VaultStatus>` from `inspect` (or any equivalent probe)
/// to an init-flow decision.
///
/// `Missing` → `Clear`. `Plaintext`, `Encrypted`, `invalid_header`, and
/// `unsupported_format_version` all signal "something is on disk; user
/// must confirm clobber" → `Existing`. Every other error becomes
/// `Propagate(err)`.
pub fn classify_init_precheck(probe: Result<VaultStatus>) -> InitPrecheck {
    match probe {
        Ok(VaultStatus::Missing) => InitPrecheck::Clear,
        Ok(VaultStatus::Plaintext | VaultStatus::Encrypted) => InitPrecheck::Existing,
        Err(PaladinError::InvalidHeader | PaladinError::UnsupportedFormatVersion) => {
            InitPrecheck::Existing
        }
        Err(other) => InitPrecheck::Propagate(other),
    }
}

// ---------- Store + VaultLock + VaultInit (DESIGN.md §4.7) ----------

/// Caller-supplied lock used by [`Store::open`] to assert the on-disk
/// vault mode the caller expects. A mismatch surfaces
/// `wrong_vault_lock` before any payload work.
///
/// The encrypted variant — which carries the user passphrase — lands
/// in Phase F and is intentionally elided here so the v0.1 plaintext
/// build cannot accidentally type-check against a stub passphrase
/// API.
#[non_exhaustive]
#[derive(Debug)]
pub enum VaultLock {
    /// Plaintext-mode vault.
    Plaintext,
}

/// Caller-supplied initialization mode for [`Store::create`] /
/// [`Store::create_force`]. The encrypted variant (passphrase +
/// optional Argon2 overrides) lands in Phase F.
#[non_exhaustive]
#[derive(Debug)]
pub enum VaultInit {
    /// Initialize a plaintext-mode vault.
    Plaintext,
}

/// Per-vault filesystem context.
///
/// Created by [`Store::open`] / [`Store::create`] and consumed by
/// `Vault::save`. Holds the on-disk vault path and the negotiated
/// mode; Phase F extends it with cached crypto material (Argon2 salt
/// / params + derived AEAD key) for encrypted vaults.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    mode: VaultMode,
}

impl Store {
    /// Open an existing vault at `path`.
    ///
    /// * `vault_missing` if the primary file is absent.
    /// * `wrong_vault_lock` if the file mode does not match `lock`
    ///   (e.g. encrypted file opened with `VaultLock::Plaintext`).
    /// * `invalid_header` / `unsupported_format_version` /
    ///   `invalid_payload` for malformed files.
    /// * `io_error { operation: "read_vault_file" }` for any other
    ///   filesystem failure.
    ///
    /// On success, leftover `vault.bin.tmp` / `vault.bin.bak.tmp`
    /// from a prior partial save are unlinked (best-effort) before
    /// returning, per §4.3.
    // `lock` is taken by value so the encrypted variant (Phase F)
    // can move its passphrase `SecretString` into the call without an
    // extra clone or borrow gymnastics.
    #[allow(clippy::needless_pass_by_value)]
    pub fn open(path: &Path, lock: VaultLock) -> Result<(crate::Vault, Self)> {
        match lock {
            VaultLock::Plaintext => open_plaintext(path),
        }
    }

    /// Create a brand-new vault at `path`.
    ///
    /// Returns `vault_exists` when a primary file is already present
    /// (use `create_force` for the §5 `init --force` clobber path).
    /// The actual file is not written until the caller invokes
    /// `Vault::save`.
    // Same rationale as `open`: encrypted `VaultInit` (Phase F) carries
    // a `SecretString` passphrase that we want to move, not clone.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create(path: &Path, init: VaultInit) -> Result<(crate::Vault, Self)> {
        match init {
            VaultInit::Plaintext => create_plaintext(path),
        }
    }

    /// `init --force` staged clobber per DESIGN.md §5.
    ///
    /// Stages the new vault to `vault.bin.tmp` and `fsync`s it before
    /// touching any existing primary. If staging succeeds and a
    /// primary already exists, the primary is renamed verbatim to
    /// `vault.bin.bak` (overwriting any prior backup), then the staged
    /// new primary is renamed into place and the parent directory is
    /// `fsync`ed. With no existing primary at `path`, behaves
    /// identically to `create` followed by an immediate save.
    ///
    /// Pre-rename failures leave the prior primary recoverable:
    /// after backup rotation but before primary rename surfaces
    /// `save_not_committed` with `backup_path` set; post-commit
    /// `fsync` failure surfaces `save_durability_unconfirmed`.
    /// Symbolic-link rejection on the existing `vault.bin` happens
    /// before any staged write so a hostile symlink cannot capture the
    /// rename target.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_force(path: &Path, init: VaultInit) -> Result<(crate::Vault, Self)> {
        match init {
            VaultInit::Plaintext => create_force_plaintext(path),
        }
    }

    /// Encode `payload` and run the §4.3 atomic-write pipeline against
    /// this `Store`'s path. Crate-private; called via `Vault::save`.
    pub(crate) fn save_payload(&self, payload: &VaultPayload) -> Result<()> {
        match self.mode {
            VaultMode::Plaintext => save_plaintext(&self.path, payload),
            VaultMode::Encrypted => Err(PaladinError::IoError {
                operation: "save_encrypted",
                source: io::Error::new(
                    io::ErrorKind::Unsupported,
                    "encrypted save lands in Phase F",
                ),
            }),
        }
    }
}

fn create_plaintext(path: &Path) -> Result<(crate::Vault, Store)> {
    // §4.3: parent dir mode must not grant any group / other perms
    // before we ever stage a vault here. (The primary doesn't yet
    // exist, so vault_file / backup_file checks are skipped.)
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            enforce_dir_perms(parent)?;
        }
    }
    if path.exists() {
        return Err(PaladinError::VaultExists);
    }
    Ok((
        crate::Vault::empty(),
        Store {
            path: path.to_path_buf(),
            mode: VaultMode::Plaintext,
        },
    ))
}

fn open_plaintext(path: &Path) -> Result<(crate::Vault, Store)> {
    // §4.3 perms enforcement — runs before any decode work, before
    // even reading the primary's bytes, so unsafe_permissions wins
    // over invalid_payload / wrong_vault_lock when the on-disk perms
    // are wrong. `vault_missing` still wins over `unsafe_permissions`
    // on the primary itself: a missing primary surfaces as
    // `vault_missing` even when the parent dir is unsafe-… wait, no:
    // the parent-dir check runs first, then the primary stat. So a
    // bad parent dir surfaces as `unsafe_permissions { vault_dir }`
    // even when the primary is absent. That matches the §4.3 intent
    // ("fix the perms before doing anything else"). `vault_missing`
    // surfaces only when parent perms are clean and the primary
    // simply isn't there yet.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            enforce_dir_perms(parent)?;
        }
    }

    let primary_meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Err(PaladinError::VaultMissing);
        }
        Err(err) => {
            return Err(PaladinError::IoError {
                operation: "stat_vault_file",
                source: err,
            });
        }
    };
    enforce_file_perms_from_meta(path, &primary_meta, PermissionSubject::VaultFile)?;

    // Backup is optional; check perms only when present.
    let bak = append_suffix(path, ".bak");
    match fs::symlink_metadata(&bak) {
        Ok(meta) => enforce_file_perms_from_meta(&bak, &meta, PermissionSubject::BackupFile)?,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(PaladinError::IoError {
                operation: "stat_backup_file",
                source: err,
            });
        }
    }

    let bytes = fs::read(path).map_err(|err| PaladinError::IoError {
        operation: "read_vault_file",
        source: err,
    })?;

    // §4.3 on-disk size cap, applied before any decoding.
    if bytes.len() > PLAINTEXT_HEADER_LEN + MAX_PAYLOAD_BYTES {
        return Err(PaladinError::InvalidPayload {
            reason: "exceeds_size_limit",
        });
    }

    match parse_header(&bytes)? {
        ParsedHeader::Plaintext => {}
        ParsedHeader::Encrypted(_) => {
            return Err(PaladinError::WrongVaultLock {
                expected: VaultMode::Plaintext,
                actual: VaultMode::Encrypted,
            });
        }
    }

    let payload_bytes = &bytes[PLAINTEXT_HEADER_LEN..];
    let payload = decode_vault_payload(payload_bytes)?;

    // §4.3: any leftover `.tmp` / `.bak.tmp` from a prior partial save
    // is unlinked by the next successful open. Best-effort for the
    // happy paths (regular file or symlink → unlink), but a leftover
    // that is a directory or that errors on stat surfaces
    // `io_error { operation: "cleanup_temp_file" }` so a misconfigured
    // sibling cannot silently linger.
    cleanup_leftover_temp(&append_suffix(path, ".tmp"))?;
    cleanup_leftover_temp(&append_suffix(path, ".bak.tmp"))?;

    Ok((
        crate::Vault::from_payload(payload),
        Store {
            path: path.to_path_buf(),
            mode: VaultMode::Plaintext,
        },
    ))
}

/// §4.3 atomic write pipeline for a plaintext vault.
///
/// Steps:
/// 1. write new primary content to `vault.bin.tmp` + fsync
/// 2. (skipped on first-ever save) stage existing primary's bytes
///    into `vault.bin.bak.tmp` + fsync
/// 3. rename `vault.bin.bak.tmp` → `vault.bin.bak`
/// 4. rename `vault.bin.tmp` → `vault.bin` (commit point)
/// 5. fsync parent directory
fn save_plaintext(path: &Path, payload: &VaultPayload) -> Result<()> {
    let parent = path.parent().ok_or_else(|| PaladinError::IoError {
        operation: "resolve_vault_parent",
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault path has no parent directory",
        ),
    })?;

    let payload_bytes = encode_vault_payload(payload)?;
    let mut on_disk = Vec::with_capacity(PLAINTEXT_HEADER_LEN + payload_bytes.len());
    header::write_plaintext_header(&mut on_disk);
    on_disk.extend_from_slice(&payload_bytes);

    let primary_tmp = append_suffix(path, ".tmp");
    let bak_path = append_suffix(path, ".bak");
    let bak_tmp = append_suffix(path, ".bak.tmp");

    // Step 1: stage new primary.
    if let Err(err) = stage_temp_file(&primary_tmp, &on_disk, "write_vault_tmp") {
        let _ = fs::remove_file(&primary_tmp);
        return Err(err);
    }

    // Steps 2-3: rotate backup if an old primary exists at `path`.
    let primary_existed = path.exists();
    if primary_existed {
        let primary_bytes = match fs::read(path) {
            Ok(b) => b,
            Err(err) => {
                let _ = fs::remove_file(&primary_tmp);
                return Err(PaladinError::IoError {
                    operation: "read_vault_file",
                    source: err,
                });
            }
        };
        if let Err(err) = stage_temp_file(&bak_tmp, &primary_bytes, "write_backup_tmp") {
            let _ = fs::remove_file(&primary_tmp);
            let _ = fs::remove_file(&bak_tmp);
            return Err(err);
        }
        if let Err(err) = fs::rename(&bak_tmp, &bak_path) {
            let _ = fs::remove_file(&primary_tmp);
            let _ = fs::remove_file(&bak_tmp);
            return Err(PaladinError::IoError {
                operation: "rename_backup",
                source: err,
            });
        }
    }

    // Step 4: commit point.
    if fs::rename(&primary_tmp, path).is_err() {
        let _ = fs::remove_file(&primary_tmp);
        return Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: if primary_existed {
                Some(bak_path)
            } else {
                None
            },
        });
    }

    // Step 5: durability fence on the parent directory.
    if fsync_dir(parent).is_err() {
        return Err(PaladinError::SaveDurabilityUnconfirmed);
    }

    Ok(())
}

/// Open `path` as a fresh tempfile, write `content`, and fsync. The
/// file is opened with `0600` mode on Unix targets so secrets are
/// never world-readable, even transiently.
///
/// `write_op` selects the §5 `io_error.operation` discriminator for
/// write failures: `"write_vault_tmp"` when staging the new primary,
/// `"write_backup_tmp"` when staging the rotated backup. fsync
/// failures share the single §5 `"fsync_temp_file"` op so the
/// durability-vs-encoding distinction stays clear.
fn stage_temp_file(path: &Path, content: &[u8], write_op: &'static str) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).map_err(|err| PaladinError::IoError {
        operation: write_op,
        source: err,
    })?;
    f.write_all(content).map_err(|err| PaladinError::IoError {
        operation: write_op,
        source: err,
    })?;
    f.sync_all().map_err(|err| PaladinError::IoError {
        operation: "fsync_temp_file",
        source: err,
    })?;
    Ok(())
}

/// fsync the directory file descriptor so renames inside it become
/// durable across power loss (Linux semantics).
fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Append `suffix` to the full path string.
///
/// `Path::with_extension` would drop the existing `.bin` extension —
/// not what we want for the `.tmp` / `.bak` / `.bak.tmp` siblings of
/// `vault.bin`.
fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Unlink a single leftover tempfile per §4.3.
///
/// * Regular file or symbolic link → unlink (`fs::remove_file` removes
///   the symlink itself, not its target — confirmed by the
///   integration test `open_cleanup_unlinks_leftover_symlink_*`).
/// * Directory → surfaces `io_error { operation: "cleanup_temp_file" }`
///   rather than silently leaving it (and `remove_file` would have
///   errored anyway with `EISDIR`); the operator must investigate
///   before reopening.
/// * Absent → success.
fn cleanup_leftover_temp(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(PaladinError::IoError {
                operation: "cleanup_temp_file",
                source: err,
            });
        }
    };
    if meta.file_type().is_dir() {
        return Err(PaladinError::IoError {
            operation: "cleanup_temp_file",
            source: io::Error::other("leftover temp file is a directory"),
        });
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(PaladinError::IoError {
            operation: "cleanup_temp_file",
            source: err,
        }),
    }
}

fn create_force_plaintext(path: &Path) -> Result<(crate::Vault, Store)> {
    // §4.3: parent dir checks (symlink + perms) fire before we ever
    // touch the file — same gate as `create`.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            enforce_dir_perms(parent)?;
        }
    }
    // Symlink rejection on the existing primary, if any. We deliberately
    // do *not* enforce the §4.3 perms check on the existing primary
    // here: `create_force` is going to clobber the file regardless of
    // its current mode, and the user already said `--force`. The
    // symlink check is the load-bearing gate — without it a hostile
    // symlink at `vault.bin` could capture the rename target.
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(PaladinError::IoError {
                    operation: "vault_file_is_symlink",
                    source: io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vault file is a symbolic link",
                    ),
                });
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(PaladinError::IoError {
                operation: "stat_vault_file",
                source: err,
            });
        }
    }

    // The post-clobber state is an empty plaintext vault. Encode it now
    // and run the §5 staged-clobber pipeline.
    let vault = crate::Vault::empty();
    let payload = vault.snapshot_payload();
    save_plaintext_clobber(path, &payload)?;

    Ok((
        vault,
        Store {
            path: path.to_path_buf(),
            mode: VaultMode::Plaintext,
        },
    ))
}

/// §5 `init --force` clobber pipeline.
///
/// Differs from the regular save path: there is no `.bak.tmp` step —
/// the existing primary is renamed verbatim to `.bak` (overwriting any
/// prior backup) only after the new primary has been staged and
/// `fsync`ed. Failure between backup rotation and the primary commit
/// leaves the previous vault recoverable at `vault.bin.bak`.
fn save_plaintext_clobber(path: &Path, payload: &VaultPayload) -> Result<()> {
    let parent = path.parent().ok_or_else(|| PaladinError::IoError {
        operation: "resolve_vault_parent",
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault path has no parent directory",
        ),
    })?;

    let payload_bytes = encode_vault_payload(payload)?;
    let mut on_disk = Vec::with_capacity(PLAINTEXT_HEADER_LEN + payload_bytes.len());
    header::write_plaintext_header(&mut on_disk);
    on_disk.extend_from_slice(&payload_bytes);

    let primary_tmp = append_suffix(path, ".tmp");
    let bak_path = append_suffix(path, ".bak");

    // Step 1: stage new primary + fsync.
    if let Err(err) = stage_temp_file(&primary_tmp, &on_disk, "write_vault_tmp") {
        let _ = fs::remove_file(&primary_tmp);
        return Err(err);
    }

    // Step 2: rotate the existing primary verbatim → .bak (overwriting
    // any existing backup) only if a primary actually exists.
    let primary_existed = path.exists();
    if primary_existed {
        if let Err(err) = fs::rename(path, &bak_path) {
            let _ = fs::remove_file(&primary_tmp);
            return Err(PaladinError::IoError {
                operation: "rename_backup",
                source: err,
            });
        }
    }

    // Step 3: commit point — rename staged primary into place.
    if fs::rename(&primary_tmp, path).is_err() {
        let _ = fs::remove_file(&primary_tmp);
        return Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: if primary_existed {
                Some(bak_path)
            } else {
                None
            },
        });
    }

    // Step 4: durability fence.
    if fsync_dir(parent).is_err() {
        return Err(PaladinError::SaveDurabilityUnconfirmed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    /// `stage_temp_file` must surface its caller-supplied write op
    /// string verbatim so `save_plaintext` / `create_force_plaintext`
    /// / Phase F's encrypted save paths each map to the correct §5
    /// op discriminator. Triggered by writing into a non-existent
    /// directory so `OpenOptions::open` fails with `ENOENT`.
    #[test]
    fn stage_temp_file_surfaces_caller_supplied_write_op_string() {
        let dir = TempDir::new().unwrap();
        let unreachable = dir.path().join("missing_subdir").join("file.tmp");

        let err = stage_temp_file(&unreachable, b"x", "write_vault_tmp").unwrap_err();
        match err {
            PaladinError::IoError { operation, .. } => assert_eq!(operation, "write_vault_tmp"),
            other => panic!("expected IoError, got {other:?}"),
        }

        let err = stage_temp_file(&unreachable, b"x", "write_backup_tmp").unwrap_err();
        match err {
            PaladinError::IoError { operation, .. } => assert_eq!(operation, "write_backup_tmp"),
            other => panic!("expected IoError, got {other:?}"),
        }
    }

    fn write_bytes(dir: &TempDir, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = dir.path().join(name);
        let mut f = fs::File::create(&p).expect("create test file");
        f.write_all(bytes).expect("write test bytes");
        p
    }

    fn plaintext_header() -> Vec<u8> {
        let mut v = Vec::new();
        header::write_plaintext_header(&mut v);
        v
    }

    fn encrypted_header() -> Vec<u8> {
        let mut v = Vec::new();
        header::write_encrypted_header(
            &mut v,
            &header::EncryptedHeaderTrailer {
                kdf_id: header::KDF_ID_ARGON2ID,
                m_kib: 65_536,
                t: 3,
                p: 1,
                salt: [0; 16],
                aead_id: header::AEAD_ID_XCHACHA20_POLY1305,
                nonce: [0; 24],
            },
        );
        v
    }

    #[test]
    fn inspect_returns_missing_for_absent_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.bin");
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Missing);
    }

    #[test]
    fn inspect_returns_plaintext_for_plaintext_header() {
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", &plaintext_header());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
    }

    #[test]
    fn inspect_returns_encrypted_for_encrypted_header() {
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", &encrypted_header());
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Encrypted);
    }

    #[test]
    fn inspect_ignores_payload_bytes_after_header() {
        let dir = TempDir::new().unwrap();
        let mut bytes = plaintext_header();
        bytes.extend_from_slice(&[0xAA; 1024]);
        let path = write_bytes(&dir, "vault.bin", &bytes);
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
    }

    #[test]
    fn inspect_rejects_unrecognized_magic() {
        let dir = TempDir::new().unwrap();
        let mut bad = plaintext_header();
        bad[0] = b'X';
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_unsupported_format_version() {
        let dir = TempDir::new().unwrap();
        let mut bad = plaintext_header();
        bad[8] = 99;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(
            inspect(&path).unwrap_err().kind(),
            ErrorKind::UnsupportedFormatVersion
        );
    }

    #[test]
    fn inspect_rejects_unknown_mode() {
        let dir = TempDir::new().unwrap();
        let mut bad = plaintext_header();
        bad[9] = 0x42;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_unknown_kdf_id() {
        let dir = TempDir::new().unwrap();
        let mut bad = encrypted_header();
        bad[10] = 99;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_unknown_aead_id() {
        let dir = TempDir::new().unwrap();
        let mut bad = encrypted_header();
        bad[39] = 99;
        let path = write_bytes(&dir, "vault.bin", &bad);
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_rejects_truncated_file() {
        // Anything shorter than the 10-byte plaintext header is
        // invalid_header (not Missing).
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", b"PALAD");
        assert_eq!(inspect(&path).unwrap_err().kind(), ErrorKind::InvalidHeader);
    }

    #[test]
    fn inspect_skips_permissions_check() {
        // §4.7 explicitly says inspect does not enforce permissions.
        // Write the vault file with a wide-open mode and confirm we
        // get a clean classification rather than `unsafe_permissions`.
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = write_bytes(&dir, "vault.bin", &plaintext_header());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        // Parent dir mode also wide open (would fail an open() perms
        // check).
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(inspect(&path).unwrap(), VaultStatus::Plaintext);
    }

    #[test]
    fn classify_init_precheck_truth_table() {
        // Missing → Clear
        assert!(matches!(
            classify_init_precheck(Ok(VaultStatus::Missing)),
            InitPrecheck::Clear
        ));

        // Plaintext / Encrypted → Existing
        assert!(matches!(
            classify_init_precheck(Ok(VaultStatus::Plaintext)),
            InitPrecheck::Existing
        ));
        assert!(matches!(
            classify_init_precheck(Ok(VaultStatus::Encrypted)),
            InitPrecheck::Existing
        ));

        // InvalidHeader / UnsupportedFormatVersion → Existing
        assert!(matches!(
            classify_init_precheck(Err(PaladinError::InvalidHeader)),
            InitPrecheck::Existing
        ));
        assert!(matches!(
            classify_init_precheck(Err(PaladinError::UnsupportedFormatVersion)),
            InitPrecheck::Existing
        ));

        // Other errors → Propagate
        match classify_init_precheck(Err(PaladinError::VaultMissing)) {
            InitPrecheck::Propagate(PaladinError::VaultMissing) => {}
            other => panic!("expected Propagate(VaultMissing), got {other:?}"),
        }
        match classify_init_precheck(Err(PaladinError::IoError {
            operation: "read_vault_file",
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        })) {
            InitPrecheck::Propagate(PaladinError::IoError { operation, .. }) => {
                assert_eq!(operation, "read_vault_file");
            }
            other => panic!("expected Propagate(IoError), got {other:?}"),
        }
        match classify_init_precheck(Err(PaladinError::DecryptFailed)) {
            InitPrecheck::Propagate(PaladinError::DecryptFailed) => {}
            other => panic!("expected Propagate(DecryptFailed), got {other:?}"),
        }
    }
}
