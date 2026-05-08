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

use secrecy::SecretString;

use crate::crypto::{
    aead_decrypt, aead_encrypt, argon2id_derive_key, Argon2Params, EncryptionOptions, AEAD_KEY_LEN,
    AEAD_NONCE_LEN,
};
use crate::error::{PaladinError, Result, VaultMode};

pub(crate) mod header;
pub mod path;
pub mod payload;
#[cfg(not(unix))]
mod perms_other;
#[cfg(unix)]
mod perms_unix;

// Save-pipeline fault injection. Compiles to no-op stubs unless the
// `test-fault-injection` cargo feature is enabled (DESIGN.md §10 /
// Phase E.7). The two checks are wired into every atomic-write site
// in this module so the hook reaches them uniformly.
mod fault;

pub use path::default_vault_path;
pub use payload::VaultSettings;
pub(crate) use payload::{decode_vault_payload, encode_vault_payload, VaultPayload};

use header::{
    parse_header, write_encrypted_header, EncryptedHeaderTrailer, ParsedHeader,
    AEAD_ID_XCHACHA20_POLY1305, ENCRYPTED_HEADER_LEN, KDF_ID_ARGON2ID, PLAINTEXT_HEADER_LEN,
};
use payload::MAX_PAYLOAD_BYTES;

#[cfg(not(unix))]
use perms_other::{enforce_dir_perms, enforce_file_perms_from_meta};
#[cfg(unix)]
use perms_unix::{enforce_dir_perms, enforce_file_perms_from_meta};

use crate::error::PermissionSubject;

/// Argon2 salt length in bytes (matches the encrypted header `salt`).
const SALT_LEN: usize = 16;

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
        Err(PaladinError::InvalidHeader | PaladinError::UnsupportedFormatVersion { .. }) => {
            InitPrecheck::Existing
        }
        Err(other) => InitPrecheck::Propagate(other),
    }
}

// ---------- Store + VaultLock + VaultInit (DESIGN.md §4.7) ----------

/// Caller-supplied lock used by [`Store::open`] to assert the on-disk
/// vault mode the caller expects. A mismatch surfaces
/// `wrong_vault_lock` before any payload work.
#[non_exhaustive]
#[derive(Debug)]
pub enum VaultLock {
    /// Plaintext-mode vault.
    Plaintext,
    /// Encrypted-mode vault, unlocked with the supplied passphrase.
    Encrypted(SecretString),
}

/// Caller-supplied initialization mode for [`Store::create`] /
/// [`Store::create_force`].
#[non_exhaustive]
#[derive(Debug)]
pub enum VaultInit {
    /// Initialize a plaintext-mode vault.
    Plaintext,
    /// Initialize an encrypted-mode vault with the supplied
    /// passphrase + Argon2id parameters.
    Encrypted(EncryptionOptions),
}

/// Crypto state preserved across regular encrypted saves
/// (DESIGN.md §4.4): Argon2id `salt` and cost `params` are reused; the
/// nonce is regenerated per save and lives in the encrypted header.
/// Reset on passphrase transitions (Phase H).
#[derive(Debug, Clone)]
pub(crate) struct EncryptedSaveContext {
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) params: Argon2Params,
}

/// Per-vault filesystem context.
///
/// Created by [`Store::open`] / [`Store::create`] and consumed by
/// `Vault::save`. Holds the on-disk vault path and the negotiated
/// mode; the encrypted variant additionally carries the in-header
/// Argon2 `salt` + cost `params` so regular saves preserve them
/// (§4.4).
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    mode: VaultMode,
    encrypted_context: Option<EncryptedSaveContext>,
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
            VaultLock::Encrypted(passphrase) => open_encrypted(path, passphrase),
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
            VaultInit::Encrypted(opts) => create_encrypted(path, opts),
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
            VaultInit::Encrypted(opts) => create_force_encrypted(path, opts),
        }
    }

    /// Encode `payload` and run the §4.3 atomic-write pipeline against
    /// this `Store`'s path. Crate-private; called via `Vault::save`.
    ///
    /// `cached_key` MUST be `Some` for encrypted vaults (the AEAD key
    /// derived once at `open` / `create` and held on the [`Vault`])
    /// and `None` for plaintext vaults; a mismatch is a programmer
    /// error and panics.
    pub(crate) fn save_payload(
        &self,
        payload: &VaultPayload,
        cached_key: Option<&[u8; AEAD_KEY_LEN]>,
    ) -> Result<()> {
        match (self.mode, cached_key, self.encrypted_context.as_ref()) {
            (VaultMode::Plaintext, None, None) => save_plaintext(&self.path, payload),
            (VaultMode::Encrypted, Some(key), Some(ctx)) => {
                save_encrypted(&self.path, payload, &ctx.salt, ctx.params, key)
            }
            _ => unreachable!(
                "Vault mode / cached-key / encrypted-context tuple is invariant: \
                 plaintext stores carry no key or context; encrypted stores carry both"
            ),
        }
    }
}

/// Test-only `Store` constructor (DESIGN.md §10 / Phase E.7).
///
/// Builds a `Store` directly from `path` and `mode` without performing
/// any filesystem I/O — bypasses the `open` / `create` / `create_force`
/// paths so binary integration tests can drive `Vault::save` against a
/// synthetic vault layout and exercise the shared fault-injection hook
/// in `storage::fault` end-to-end. Excluded from the stable §4.7 API:
/// only compiled in under `#[cfg(feature = "test-fault-injection")]`,
/// which is off by default and never enabled in production builds.
#[cfg(feature = "test-fault-injection")]
impl Store {
    /// Construct a `Store` for fault-injection tests. The caller is
    /// responsible for ensuring `path`'s parent directory exists with
    /// permissions appropriate for the test scenario; this constructor
    /// does no validation. `mode = VaultMode::Encrypted` is rejected
    /// — encrypted save tests use the real `Store::create` path so
    /// fresh salt + params live in the `Store` correctly.
    #[must_use]
    pub fn for_test_fault_injection(path: PathBuf, mode: VaultMode) -> Self {
        assert!(
            matches!(mode, VaultMode::Plaintext),
            "fault-injection harness only constructs plaintext Stores"
        );
        Self {
            path,
            mode,
            encrypted_context: None,
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
            encrypted_context: None,
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
            encrypted_context: None,
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

    // Step 4: commit point. The fault hook short-circuits the rename
    // when `PALADIN_FAULT_INJECT=pre_commit` so the failure is
    // indistinguishable from a real rename error: the old primary is
    // still authoritative at `vault.bin`, primary_tmp is cleaned up
    // best-effort, and the typed error is `save_not_committed` with
    // `backup_path: None` per DESIGN.md §5 — `backup_path` is only
    // populated for save sites where the old primary was rotated away
    // (see `save_plaintext_clobber` for `init --force`).
    if fault::pre_commit_should_fail() || fs::rename(&primary_tmp, path).is_err() {
        let _ = fs::remove_file(&primary_tmp);
        return Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        });
    }

    // Step 5: durability fence on the parent directory. The fault
    // hook fires after the rename so the typed error matches a real
    // post-commit fsync failure: primary in place but durability not
    // confirmed.
    if fault::post_commit_should_fail() || fsync_dir(parent).is_err() {
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
            encrypted_context: None,
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

    // Step 3: commit point — rename staged primary into place. Fault
    // hook short-circuits the rename for `PALADIN_FAULT_INJECT=pre_commit`
    // so the surface is identical to a real rename failure.
    if fault::pre_commit_should_fail() || fs::rename(&primary_tmp, path).is_err() {
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

    // Step 4: durability fence. Fault hook fires after the commit so
    // `save_durability_unconfirmed` matches a real parent-fsync failure.
    if fault::post_commit_should_fail() || fsync_dir(parent).is_err() {
        return Err(PaladinError::SaveDurabilityUnconfirmed);
    }

    Ok(())
}

/// Atomically write `content` to `path` with a same-directory tempfile,
/// fsync, rename, and parent-directory fsync (DESIGN.md §4.3 / §4.7).
/// On Unix targets the final file is `0600`. This is the shared writer
/// used by export and other secret-file surfaces; it does **not**
/// enforce the §4.3 directory permissions check, does **not** reject an
/// existing destination, and does **not** create or rotate `.bak`. Each
/// front end (CLI `--force`, GUI `ExportDialog`) gates overwrite policy
/// before calling this helper so user-facing confirmation wording stays
/// local to that front end.
///
/// Errors:
/// * `path` has no parent component: `io_error` with
///   `operation: "resolve_secret_file_parent"`.
/// * Any pre-commit failure — tempfile open, write, fsync, or the
///   rename into place — returns
///   `save_not_committed { committed: false, backup_path: None }`. The
///   destination at `path` is left untouched and any leftover tempfile
///   is best-effort unlinked.
/// * Post-commit parent-directory fsync failure returns
///   `save_durability_unconfirmed`. The destination is in place but may
///   not survive a power loss until the next durable write to that
///   directory.
///
/// Stable §5 op strings reserved for this surface
/// (`write_secret_file_tmp`, `fsync_secret_file_tmp`,
/// `rename_secret_file`, `fsync_secret_file_dir`) are intentionally
/// **not** returned by this helper today: pre-commit failures collapse
/// into the typed `save_not_committed` discriminator so callers can
/// reason about commit state without inspecting the source error, and
/// post-commit fsync failures collapse into `save_durability_unconfirmed`
/// for the same reason. The op strings remain in the §5 table as
/// reserved labels for future fault-injection diagnostics (Phase E.7).
pub fn write_secret_file_atomic(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| PaladinError::IoError {
            operation: "resolve_secret_file_parent",
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret file path has no parent directory",
            ),
        })?;

    let tmp = append_suffix(path, ".tmp");

    if !stage_secret_tempfile(&tmp, content) {
        let _ = cleanup_leftover_temp(&tmp);
        return Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        });
    }

    // Pre-commit injection point: fault hook short-circuits the rename
    // for `PALADIN_FAULT_INJECT=pre_commit` so the surface is identical
    // to a real rename failure. `backup_path` is always `None` here —
    // this writer never rotates a `.bak`, by §4.7 contract.
    if fault::pre_commit_should_fail() || fs::rename(&tmp, path).is_err() {
        let _ = cleanup_leftover_temp(&tmp);
        return Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        });
    }

    // Post-commit injection point: fault hook fires after the rename so
    // `save_durability_unconfirmed` matches a real parent-fsync failure.
    if fault::post_commit_should_fail() || fsync_dir(parent).is_err() {
        return Err(PaladinError::SaveDurabilityUnconfirmed);
    }

    Ok(())
}

/// Stage `content` into `tmp` with `0600` mode and an `fsync`. Returns
/// `false` on any open / write / fsync failure so the caller can wrap
/// the result in `save_not_committed` without losing track of which
/// step failed (the source `io::Error` is intentionally dropped — the
/// commit-state guarantee is what matters to callers).
fn stage_secret_tempfile(tmp: &Path, content: &[u8]) -> bool {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let Ok(mut f) = opts.open(tmp) else {
        return false;
    };
    if f.write_all(content).is_err() {
        return false;
    }
    f.sync_all().is_ok()
}

// ---------- Encrypted-mode lifecycle (DESIGN.md §4.3 + §4.4) ----------

fn create_encrypted(path: &Path, opts: EncryptionOptions) -> Result<(crate::Vault, Store)> {
    create_encrypted_internal(path, opts, /* allow_clobber */ false)
}

fn create_force_encrypted(path: &Path, opts: EncryptionOptions) -> Result<(crate::Vault, Store)> {
    // §4.3 parent-dir check + §5 staged-clobber path. Symlink rejection
    // on the existing primary mirrors the plaintext clobber path.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            enforce_dir_perms(parent)?;
        }
    }
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
    create_encrypted_internal(path, opts, /* allow_clobber */ true)
}

/// Shared helper for `create_encrypted` / `create_force_encrypted`.
/// Generates fresh salt, derives the AEAD key once, builds an empty
/// `Vault` + `Store`, and immediately writes the initial encrypted
/// vault to disk so the on-disk file is left consistent with the
/// returned in-memory state.
fn create_encrypted_internal(
    path: &Path,
    opts: EncryptionOptions,
    allow_clobber: bool,
) -> Result<(crate::Vault, Store)> {
    if !allow_clobber {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                enforce_dir_perms(parent)?;
            }
        }
        if path.exists() {
            return Err(PaladinError::VaultExists);
        }
    }

    // §4.4: bounds re-check on opts.kdf_params is already enforced by
    // `EncryptionOptions::with_params`, but `EncryptionOptions::new`
    // uses the validated default. Validate once more here so any
    // hand-rolled construction (e.g. a future direct field
    // initialization within the crate) cannot bypass the bound.
    opts.kdf_params.validate()?;

    let salt = generate_salt()?;
    let key = argon2id_derive_key(&opts.passphrase, &salt, &opts.kdf_params)?;
    let context = EncryptedSaveContext {
        salt,
        params: opts.kdf_params,
    };
    let store = Store {
        path: path.to_path_buf(),
        mode: VaultMode::Encrypted,
        encrypted_context: Some(context.clone()),
    };
    let vault = crate::Vault::empty_encrypted(opts.passphrase, key.clone());

    if allow_clobber {
        let payload = vault.snapshot_payload();
        save_encrypted_clobber(path, &payload, &context.salt, context.params, &key)?;
    } else {
        let payload = vault.snapshot_payload();
        save_encrypted(path, &payload, &context.salt, context.params, &key)?;
    }
    Ok((vault, store))
}

/// §4.3 on-disk size cap for encrypted vaults. The maximum admissible
/// file size is `ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + AEAD_TAG_LEN`
/// (64 + 16 MiB + 16 bytes); anything larger is rejected with
/// `invalid_payload` / `exceeds_size_limit` *before* any header parse,
/// KDF, or AEAD work runs.
fn enforce_on_disk_encrypted_size_cap(bytes_len: usize) -> Result<()> {
    if bytes_len > ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + 16 {
        return Err(PaladinError::InvalidPayload {
            reason: "exceeds_size_limit",
        });
    }
    Ok(())
}

/// §4.3 decrypted-plaintext cap. After AEAD decryption succeeds, the
/// recovered plaintext must still fit within the 16 MiB payload limit
/// before bincode decode and `Vault` construction. Returns
/// `invalid_payload` / `exceeds_size_limit` when exceeded.
fn enforce_decrypted_payload_cap(plaintext_len: usize) -> Result<()> {
    if plaintext_len > MAX_PAYLOAD_BYTES {
        return Err(PaladinError::InvalidPayload {
            reason: "exceeds_size_limit",
        });
    }
    Ok(())
}

fn open_encrypted(path: &Path, passphrase: SecretString) -> Result<(crate::Vault, Store)> {
    // §4.3 perms gate (parent dir, primary, optional backup). Mirrors
    // open_plaintext so unsafe_permissions wins over decrypt_failed
    // when the on-disk perms are wrong.
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

    // §4.3 on-disk size cap, applied before any AEAD/KDF work.
    enforce_on_disk_encrypted_size_cap(bytes.len())?;

    // Header parse + cross-mode lock check.
    let trailer = match parse_header(&bytes)? {
        ParsedHeader::Plaintext => {
            return Err(PaladinError::WrongVaultLock {
                expected: VaultMode::Encrypted,
                actual: VaultMode::Plaintext,
            });
        }
        ParsedHeader::Encrypted(t) => t,
    };

    // §4.4 Argon2 bounds re-check before running the KDF.
    let params = Argon2Params {
        m_kib: trailer.m_kib,
        t: trailer.t,
        p: trailer.p,
    };
    params.validate()?;

    // Derive the AEAD key. The `EncryptedHeaderTrailer` salt /
    // nonce live in the on-disk header.
    let key = argon2id_derive_key(&passphrase, &trailer.salt, &params)?;

    // AAD: every header byte after the magic (§4.4).
    let aad = &bytes[8..ENCRYPTED_HEADER_LEN];
    let ct_and_tag = &bytes[ENCRYPTED_HEADER_LEN..];
    let plaintext = aead_decrypt(&key, &trailer.nonce, aad, ct_and_tag)?;

    // Decoded payload still bounded by the §4.3 16 MiB cap. Defensive
    // belt-and-suspenders against the on-disk cap above: AEAD is
    // length-preserving so this branch is unreachable through the
    // normal open path, but it is unit-tested directly to pin the
    // invariant if a future construct ever decoupled them.
    enforce_decrypted_payload_cap(plaintext.len())?;

    let payload = decode_vault_payload(&plaintext)?;

    cleanup_leftover_temp(&append_suffix(path, ".tmp"))?;
    cleanup_leftover_temp(&append_suffix(path, ".bak.tmp"))?;

    let store = Store {
        path: path.to_path_buf(),
        mode: VaultMode::Encrypted,
        encrypted_context: Some(EncryptedSaveContext {
            salt: trailer.salt,
            params,
        }),
    };
    Ok((
        crate::Vault::from_payload_encrypted(payload, passphrase, key),
        store,
    ))
}

/// Generate a 16-byte Argon2 salt from the OS CSPRNG. Failures
/// surface as `io_error { operation: "csprng_read" }`.
fn generate_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| PaladinError::IoError {
        operation: "csprng_read",
        source: io::Error::other("CSPRNG read failed"),
    })?;
    Ok(salt)
}

/// Generate a 24-byte XChaCha20-Poly1305 nonce from the OS CSPRNG.
fn generate_nonce() -> Result<[u8; AEAD_NONCE_LEN]> {
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| PaladinError::IoError {
        operation: "csprng_read",
        source: io::Error::other("CSPRNG read failed"),
    })?;
    Ok(nonce)
}

/// Build the on-disk encrypted bytes (64-byte header + ciphertext+tag)
/// from a payload + crypto context. Fresh nonce per call.
fn build_encrypted_on_disk(
    payload: &VaultPayload,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
    key: &[u8; AEAD_KEY_LEN],
) -> Result<Vec<u8>> {
    let payload_bytes = encode_vault_payload(payload)?;
    // `encode_vault_payload` already enforces the 16 MiB plaintext
    // cap, so the AEAD encrypt below is well within the practical
    // limit.
    let nonce = generate_nonce()?;
    let trailer = EncryptedHeaderTrailer {
        kdf_id: KDF_ID_ARGON2ID,
        m_kib: params.m_kib,
        t: params.t,
        p: params.p,
        salt: *salt,
        aead_id: AEAD_ID_XCHACHA20_POLY1305,
        nonce,
    };
    let mut header_bytes = Vec::with_capacity(ENCRYPTED_HEADER_LEN);
    write_encrypted_header(&mut header_bytes, &trailer);
    debug_assert_eq!(header_bytes.len(), ENCRYPTED_HEADER_LEN);
    let aad = header_bytes[8..].to_vec();
    let ct_and_tag = aead_encrypt(key, &nonce, &aad, &payload_bytes);
    let mut on_disk = Vec::with_capacity(ENCRYPTED_HEADER_LEN + ct_and_tag.len());
    on_disk.extend_from_slice(&header_bytes);
    on_disk.extend_from_slice(&ct_and_tag);
    Ok(on_disk)
}

/// §4.3 atomic write pipeline for an encrypted vault. Mirrors
/// `save_plaintext` step-for-step; the only difference is the on-disk
/// byte construction (encrypted header + AEAD ciphertext-and-tag
/// instead of the 10-byte plaintext header + bincode payload).
fn save_encrypted(
    path: &Path,
    payload: &VaultPayload,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
    key: &[u8; AEAD_KEY_LEN],
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| PaladinError::IoError {
        operation: "resolve_vault_parent",
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault path has no parent directory",
        ),
    })?;

    let on_disk = build_encrypted_on_disk(payload, salt, params, key)?;

    let primary_tmp = append_suffix(path, ".tmp");
    let bak_path = append_suffix(path, ".bak");
    let bak_tmp = append_suffix(path, ".bak.tmp");

    if let Err(err) = stage_temp_file(&primary_tmp, &on_disk, "write_vault_tmp") {
        let _ = fs::remove_file(&primary_tmp);
        return Err(err);
    }

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

    if fault::pre_commit_should_fail() || fs::rename(&primary_tmp, path).is_err() {
        let _ = fs::remove_file(&primary_tmp);
        return Err(PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        });
    }

    if fault::post_commit_should_fail() || fsync_dir(parent).is_err() {
        return Err(PaladinError::SaveDurabilityUnconfirmed);
    }

    Ok(())
}

/// §5 `init --force` clobber pipeline for an encrypted vault. Mirrors
/// `save_plaintext_clobber`: stage new primary, rotate the existing
/// primary verbatim to `.bak` (overwriting any prior backup), then
/// commit + fsync.
fn save_encrypted_clobber(
    path: &Path,
    payload: &VaultPayload,
    salt: &[u8; SALT_LEN],
    params: Argon2Params,
    key: &[u8; AEAD_KEY_LEN],
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| PaladinError::IoError {
        operation: "resolve_vault_parent",
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "vault path has no parent directory",
        ),
    })?;

    let on_disk = build_encrypted_on_disk(payload, salt, params, key)?;

    let primary_tmp = append_suffix(path, ".tmp");
    let bak_path = append_suffix(path, ".bak");

    if let Err(err) = stage_temp_file(&primary_tmp, &on_disk, "write_vault_tmp") {
        let _ = fs::remove_file(&primary_tmp);
        return Err(err);
    }

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

    if fault::pre_commit_should_fail() || fs::rename(&primary_tmp, path).is_err() {
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

    if fault::post_commit_should_fail() || fsync_dir(parent).is_err() {
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
            classify_init_precheck(Err(PaladinError::UnsupportedFormatVersion {
                format_ver: 99
            })),
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

    /// §4.4 AEAD output shape — the on-disk encrypted body is
    /// **exactly** the bincode-serialized `VaultPayload` plus the
    /// 16-byte Poly1305 tag. Pins XChaCha20-Poly1305 (24-byte nonce,
    /// 16-byte tag) end-to-end so a swap to a different AEAD construct
    /// (e.g. AES-GCM, IETF ChaCha20-Poly1305) fails this assertion
    /// before silent re-encoding can ship.
    #[test]
    fn encrypted_save_writes_body_equal_to_payload_plus_aead_tag() {
        use crate::crypto::AEAD_TAG_LEN;
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("vault.bin");

        let cheap = Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        let opts = EncryptionOptions::with_params(
            secrecy::SecretString::from("hunter2".to_string()),
            cheap,
        )
        .expect("cheap params and non-empty passphrase are valid");
        let (vault, _store) = Store::create(&path, VaultInit::Encrypted(opts)).unwrap();

        let bytes = fs::read(&path).expect("read encrypted primary");
        let payload = vault.snapshot_payload();
        let encoded = encode_vault_payload(&payload).expect("encode VaultPayload");

        assert_eq!(
            bytes.len(),
            header::ENCRYPTED_HEADER_LEN + encoded.len() + AEAD_TAG_LEN,
            "on-disk file should equal 64-byte header + bincode-serialized payload + 16-byte AEAD tag"
        );
    }

    /// §4.4 AEAD output shape — adding plaintext bytes grows the
    /// encrypted body by exactly the same number of bytes
    /// (`XChaCha20` is a stream cipher, so
    /// `ciphertext_len == plaintext_len`). A regression to a
    /// block-cipher AEAD with padding (e.g. AES-CBC plus HMAC) would
    /// round the body up to a block boundary and fail this delta
    /// assertion.
    #[test]
    fn encrypted_save_body_grows_one_byte_per_plaintext_byte() {
        use crate::crypto::AEAD_TAG_LEN;
        use crate::otpauth::parse_otpauth;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, UNIX_EPOCH};
        let dir = TempDir::new().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("vault.bin");

        let cheap = Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        };
        let opts = EncryptionOptions::with_params(
            secrecy::SecretString::from("hunter2".to_string()),
            cheap,
        )
        .expect("cheap params and non-empty passphrase are valid");
        let (mut vault, store) = Store::create(&path, VaultInit::Encrypted(opts)).unwrap();

        let baseline_encoded =
            encode_vault_payload(&vault.snapshot_payload()).expect("encode baseline payload");
        let baseline_file = fs::read(&path).expect("read baseline primary");
        assert_eq!(
            baseline_file.len(),
            header::ENCRYPTED_HEADER_LEN + baseline_encoded.len() + AEAD_TAG_LEN,
            "baseline shape: header + plaintext + tag"
        );

        // Add an account, save, and re-check the shape. The on-disk
        // body should grow by exactly the bincode encoding delta.
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let parsed = parse_otpauth(
            "otpauth://totp/Acme:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme",
            now,
        )
        .expect("parse otpauth fixture");
        vault.add(parsed.account);
        vault.save(&store).expect("encrypted save with one account");

        let bumped_encoded =
            encode_vault_payload(&vault.snapshot_payload()).expect("encode payload+account");
        let bumped_file = fs::read(&path).expect("read bumped primary");

        let plaintext_delta = bumped_encoded.len() - baseline_encoded.len();
        assert!(
            plaintext_delta > 0,
            "adding an account must grow the bincode-encoded payload"
        );
        assert_eq!(
            bumped_file.len() - baseline_file.len(),
            plaintext_delta,
            "encrypted body delta must equal plaintext delta (stream cipher, no padding)"
        );
        assert_eq!(
            bumped_file.len(),
            header::ENCRYPTED_HEADER_LEN + bumped_encoded.len() + AEAD_TAG_LEN,
            "post-add shape: header + plaintext + tag"
        );
    }

    /// §4.3 on-disk size cap helper accepts any file at or below
    /// the threshold (`ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + 16`,
    /// i.e. header + 16 MiB + Poly1305 tag) and rejects anything
    /// strictly larger with `invalid_payload` / `exceeds_size_limit`.
    #[test]
    fn enforce_on_disk_encrypted_size_cap_accepts_at_and_below_threshold() {
        let cap = header::ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + 16;
        enforce_on_disk_encrypted_size_cap(0).expect("zero-length accepted");
        enforce_on_disk_encrypted_size_cap(header::ENCRYPTED_HEADER_LEN)
            .expect("bare header accepted");
        enforce_on_disk_encrypted_size_cap(cap - 1).expect("one byte under cap accepted");
        enforce_on_disk_encrypted_size_cap(cap).expect("exactly-at-cap accepted");
    }

    #[test]
    fn enforce_on_disk_encrypted_size_cap_rejects_one_byte_over_threshold() {
        let cap = header::ENCRYPTED_HEADER_LEN + MAX_PAYLOAD_BYTES + 16;
        let err = enforce_on_disk_encrypted_size_cap(cap + 1)
            .expect_err("one byte over cap must be rejected");
        match err {
            PaladinError::InvalidPayload { reason } => assert_eq!(reason, "exceeds_size_limit"),
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }

    /// §4.3 decrypted-plaintext cap helper accepts plaintexts at or
    /// below 16 MiB and rejects anything larger with `invalid_payload`
    /// / `exceeds_size_limit`. Pins the post-AEAD guard against a
    /// future regression where the on-disk cap is loosened or a
    /// non-length-preserving construct is wired in.
    #[test]
    fn enforce_decrypted_payload_cap_accepts_at_and_below_max_payload() {
        enforce_decrypted_payload_cap(0).expect("zero-length plaintext accepted");
        enforce_decrypted_payload_cap(MAX_PAYLOAD_BYTES - 1).expect("one byte under max accepted");
        enforce_decrypted_payload_cap(MAX_PAYLOAD_BYTES).expect("exactly-at-max accepted");
    }

    #[test]
    fn enforce_decrypted_payload_cap_rejects_one_byte_over_max_payload() {
        let err = enforce_decrypted_payload_cap(MAX_PAYLOAD_BYTES + 1)
            .expect_err("one byte over max must be rejected");
        match err {
            PaladinError::InvalidPayload { reason } => assert_eq!(reason, "exceeds_size_limit"),
            other => panic!("expected InvalidPayload, got {other:?}"),
        }
    }
}
