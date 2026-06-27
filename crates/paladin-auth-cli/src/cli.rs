// SPDX-License-Identifier: AGPL-3.0-or-later

//! Clap argument tree for the `paladin-auth` binary. See docs/DESIGN.md §5 and
//! `docs/IMPLEMENTATION_PLAN_02_CLI.md` for the authoritative command surface.

// Items in this module are clap argument-tree definitions. They are
// public because the library surface (`src/lib.rs`) re-exposes the
// root `Cli` so `xtask` can call `Cli::command()` for man-page
// rendering, but the individual fields / variants are internal clap
// scaffolding that derive their semantics from clap attributes — not
// from rustdoc. Suppressing `missing_docs` here keeps the lib-level
// `#![warn(missing_docs)]` (set in `src/lib.rs`) honest for the
// genuinely-public surface without forcing rustdoc on every clap
// arg.
#![allow(missing_docs)]

use std::path::PathBuf;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "paladin-auth",
    version,
    about = "Paladin Auth: Rust OTP authenticator (TOTP + HOTP)",
    propagate_version = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Path to vault file (overrides the default location).
    #[arg(long, value_name = "PATH", global = true)]
    pub vault: Option<PathBuf>,

    /// Disable ANSI color in text output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Emit stable JSON envelopes per docs/DESIGN.md §5 instead of human text.
    #[arg(long, global = true)]
    pub json: bool,
}

/// Argon2id KDF flags shared by every encrypted-write command.
///
/// Captured as raw strings so the CLI can route integer-parse failures
/// through the §5 `validation_error` envelope with the hyphenated flag
/// name as `field` (`"kdf-memory-mib"`, `"kdf-time"`,
/// `"kdf-parallelism"`) instead of clap's text diagnostic. See
/// `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Encrypted-write KDF flags" and
/// [`crate::kdf::parse_argon2_params`].
#[derive(Debug, Args)]
#[allow(clippy::struct_field_names)]
pub struct KdfArgs {
    /// Argon2id memory cost, in MiB (default: 64).
    #[arg(long, value_name = "MIB")]
    pub kdf_memory_mib: Option<String>,
    /// Argon2id time cost / iterations (default: 3).
    #[arg(long, value_name = "ITERATIONS")]
    pub kdf_time: Option<String>,
    /// Argon2id parallelism / lanes (default: 1).
    #[arg(long, value_name = "LANES")]
    pub kdf_parallelism: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a new vault.
    Init(InitArgs),
    /// Add an account (interactive, --uri, manual flags, or --qr).
    Add(AddArgs),
    /// List accounts with the current TOTP code, seconds remaining,
    /// and the next TOTP code (HOTP rows render the code columns as
    /// dashes / `null`).
    List,
    /// Print the current code (advances HOTP and persists before printing).
    Show(QueryArgs),
    /// Print the current code without advancing HOTP.
    Peek(QueryArgs),
    /// Copy the code to the clipboard (advances HOTP; no auto-clear).
    Copy(QueryArgs),
    /// Remove an account.
    Remove(RemoveArgs),
    /// Rename an account.
    Rename(RenameArgs),
    /// Edit an account's non-cryptographic metadata (label, issuer, icon-hint).
    Edit(EditArgs),
    /// Manage the vault passphrase.
    Passphrase {
        #[command(subcommand)]
        action: PassphraseCommand,
    },
    /// Import accounts from a file (auto-detect or forced format).
    Import(ImportArgs),
    /// Export the vault to a file.
    Export(ExportArgs),
    /// Render an account's `otpauth://` URI as a QR code (v0.2).
    Qr(QrArgs),
    /// Read or modify vault settings.
    Settings {
        #[command(subcommand)]
        action: SettingsCommand,
    },
    /// Permanently delete the vault file (and its `.bak`) from disk.
    Destroy(DestroyArgs),
    /// Launch the TUI by exec'ing `paladin-auth-tui` with shared flags.
    Tui,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite an existing vault (rotates the old file to `<vault>.bak`).
    #[arg(long)]
    pub force: bool,

    #[command(flatten)]
    pub kdf: KdfArgs,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Add from an `otpauth://` URI.
    #[arg(
        long,
        value_name = "URI",
        conflicts_with_all = [
            "qr", "label", "secret", "issuer", "algorithm",
            "digits", "kind", "period", "counter",
            "icon_hint", "no_icon_hint",
        ],
    )]
    pub uri: Option<String>,

    /// Add by scanning a QR-code image file (every decoded QR is added; uses --on-conflict=skip).
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = [
            "uri", "label", "secret", "issuer", "algorithm",
            "digits", "kind", "period", "counter",
            "icon_hint", "no_icon_hint",
        ],
    )]
    pub qr: Option<PathBuf>,

    /// Manual: account label.
    #[arg(long)]
    pub label: Option<String>,

    /// Manual: base32-encoded shared secret.
    #[arg(long)]
    pub secret: Option<String>,

    /// Manual: issuer.
    #[arg(long)]
    pub issuer: Option<String>,

    /// Manual: HMAC algorithm.
    #[arg(long, value_enum)]
    pub algorithm: Option<AlgorithmArg>,

    /// Manual: digit count (6, 7, or 8).
    #[arg(long)]
    pub digits: Option<u32>,

    /// Manual: TOTP or HOTP.
    #[arg(long, value_enum)]
    pub kind: Option<KindArg>,

    /// Manual: TOTP period in seconds (1..=300).
    #[arg(long)]
    pub period: Option<u32>,

    /// Manual: HOTP counter (default 0).
    #[arg(long)]
    pub counter: Option<u64>,

    /// Manual: icon-hint slug.
    #[arg(long, value_name = "SLUG", conflicts_with = "no_icon_hint")]
    pub icon_hint: Option<String>,

    /// Manual: clear the icon hint.
    #[arg(long, conflicts_with = "icon_hint")]
    pub no_icon_hint: bool,

    /// Append a new account even when an existing entry has the same
    /// `(secret, issuer, label)`. Mutually exclusive with `--qr`.
    #[arg(long, conflicts_with = "qr")]
    pub allow_duplicate: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum AlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum KindArg {
    Totp,
    Hotp,
}

#[derive(Debug, Args)]
pub struct QueryArgs {
    /// Account query (label, issuer:label substring, or `id:<hex>` prefix).
    pub query: String,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub query: String,
    /// Skip the destructive-confirmation prompt (required under `--json`).
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RenameArgs {
    pub query: String,
    pub new_label: String,
}

/// `paladin-auth destroy [--yes]` argv shape per
/// `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Destroy command (Milestone 10)".
///
/// `destroy` runs no Argon2id work, so the flattened [`KdfArgs`] exist
/// only so any KDF flag parses and can be rejected in-handler with
/// `validation_error` (`field: "argv"`, `reason: "kdf_flags_not_supported"`)
/// before any I/O — surfacing them as supported would be a lie. There
/// is no global KDF arg, so the flatten is the only way the flags reach
/// the parser.
#[derive(Debug, Args)]
pub struct DestroyArgs {
    /// Skip the destructive-confirmation prompt (required under `--json`).
    #[arg(long)]
    pub yes: bool,

    #[command(flatten)]
    pub kdf: KdfArgs,
}

/// `paladin-auth edit <query>` argv shape per
/// `docs/IMPLEMENTATION_PLAN_02_CLI.md` "Edit command (v0.2)".
///
/// Mutual-exclusion pairs (`--issuer` / `--no-issuer`,
/// `--icon-hint` / `--no-icon-hint`) are enforced by clap via
/// `conflicts_with`; the "at least one editable flag" requirement is
/// enforced in `commands::edit::run` before any vault I/O so the
/// no-flag rejection wins over `vault_missing` and the encrypted-mode
/// passphrase prompt.
//
// `struct_excessive_bools` is suppressed here because the bool fields
// are independent argv toggles (clap-driven mutual-exclusion pairs +
// `--allow-duplicate` + `--dry-run`); a state-machine refactor would
// fight clap's derive ergonomics without buying anything.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Args)]
pub struct EditArgs {
    /// Account query (label, issuer:label substring, or `id:<hex>` prefix).
    pub query: String,

    /// Replace the account's label. Raw value routes through
    /// `paladin_auth_core::validate_account_edit`; §4.1 label validation
    /// (trim, empty rejection, 128-byte cap) lives in core.
    #[arg(long)]
    pub label: Option<String>,

    /// Replace the account's issuer. `--issuer ""` normalizes to
    /// `Some(None)` inside the validator and is equivalent to
    /// `--no-issuer`.
    #[arg(long, conflicts_with = "no_issuer")]
    pub issuer: Option<String>,

    /// Clear the account's issuer.
    #[arg(long, conflicts_with = "issuer")]
    pub no_issuer: bool,

    /// Set the icon-hint. Token is taken verbatim from argv and
    /// routed through `paladin_auth_core::parse_icon_hint_token`: empty →
    /// `IconHintInput::Default`; case-insensitive `none` →
    /// `IconHintInput::Clear`; otherwise validated as a §4.1 slug.
    #[arg(long, value_name = "SLUG", conflicts_with = "no_icon_hint")]
    pub icon_hint: Option<String>,

    /// Clear the stored icon-hint slug.
    #[arg(long, conflicts_with = "icon_hint")]
    pub no_icon_hint: bool,

    /// Submit the edit even if the post-edit `(secret, issuer, label)`
    /// triple collides with another account. Off by default; does
    /// **not** satisfy the "at least one editable flag" requirement.
    #[arg(long)]
    pub allow_duplicate: bool,

    /// Run the full pre-flight (validation + duplicate check) and
    /// report the projected post-edit account without invoking
    /// `Vault::edit_account_metadata`. The vault file is never
    /// written.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum PassphraseCommand {
    /// Encrypt a plaintext vault under a new passphrase.
    Set {
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Re-encrypt the vault under a new passphrase.
    Change {
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Decrypt the vault to plaintext.
    Remove {
        /// Skip the destructive-confirmation prompt (required under `--json`).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum ImportFormatArg {
    Otpauth,
    Aegis,
    PaladinAuth,
    Qr,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum OnConflictArg {
    Skip,
    Replace,
    Append,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Path to the source file.
    pub path: PathBuf,
    /// Force a specific source format (otherwise content-sniffed).
    #[arg(long, value_enum)]
    pub format: Option<ImportFormatArg>,
    /// Conflict policy when an imported entry collides with an existing account.
    #[arg(long, value_enum)]
    pub on_conflict: Option<OnConflictArg>,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("export_target")
        .required(true)
        .args(["plaintext", "encrypted"])
))]
pub struct ExportArgs {
    /// Write a JSON `otpauth://` array (output mode 0600).
    #[arg(long, value_name = "PATH")]
    pub plaintext: Option<PathBuf>,
    /// Write a Paladin Auth-format encrypted bundle (output mode 0600).
    #[arg(long, value_name = "PATH")]
    pub encrypted: Option<PathBuf>,
    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
    #[command(flatten)]
    pub kdf: KdfArgs,
}

#[derive(Debug, Args)]
pub struct QrArgs {
    /// Account query (label, issuer:label substring, or `id:<hex>` prefix).
    pub query: String,
    /// Write the rendered QR code to PATH (0600). Without --out, the
    /// ANSI half-block render is printed to stdout.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Output format. Defaults to png when --out is set, ansi otherwise.
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: Option<QrFormatArg>,
    /// Per-module pixel size for PNG / SVG output (default 8, range 1..=64).
    /// Accepted but ignored for the ansi render.
    #[arg(long, value_name = "PIXELS")]
    pub module_size_px: Option<String>,
    /// Overwrite an existing --out target.
    #[arg(long)]
    pub force: bool,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum QrFormatArg {
    Png,
    Svg,
    Ansi,
}

#[derive(Debug, Subcommand)]
pub enum SettingsCommand {
    /// Display vault settings (optionally filtered by dotted key in text mode).
    Get { key: Option<String> },
    /// Set a vault setting (`<key> <value>`).
    Set { key: String, value: String },
}
