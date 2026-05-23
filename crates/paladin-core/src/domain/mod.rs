// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Domain model for Paladin (docs/DESIGN.md §4.1, §4.7).
//
// `Account` and friends are intentionally constructed only through the
// validation entry points (`validate_manual`, `parse_otpauth`, the
// importers). All public field projections go through
// `AccountSummary`; raw secret bytes never leave the crate.

pub mod import;
pub mod match_key;
pub mod prompt_input;
pub mod query;
pub mod secret;
pub mod settings;
pub mod slug;
pub mod validation;

pub use import::{ImportConflict, ImportReport, ImportWarning};
pub use match_key::{account_match_key, account_matches_search};
pub use prompt_input::parse_icon_hint_token;
pub use query::{parse_account_query, select_after_filter, AccountQuery};
pub use secret::Secret;
pub use settings::{parse_setting_key, parse_setting_patch, SettingKey, SettingPatch};
pub use validation::{validate_label, validate_manual, ValidatedAccount, ValidationWarning};

use std::fmt;
use std::time::SystemTime;

use bincode::de::{BorrowDecoder, Decoder};
use bincode::enc::Encoder;
use bincode::error::{DecodeError, EncodeError};
use bincode::{BorrowDecode, Decode, Encode};
use uuid::Uuid;

/// HMAC algorithm used for OTP code generation. `Sha1` is the default
/// per docs/DESIGN.md §4.1 / RFC 6238.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Encode, Decode)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "lowercase"))]
pub enum Algorithm {
    /// HMAC-SHA1 (default per RFC 6238).
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl Algorithm {
    /// Stable lowercase token used in JSON output, otpauth URI, and
    /// Aegis import.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// OTP kind discriminator. `Totp` carries the `period` (seconds);
/// `Hotp` carries the next counter value to use.
///
/// Crate-private: front ends inspect accounts via `AccountSummary` /
/// `AccountKindSummary` (see `view`), which exposes the same fields
/// in a public, non-secret-bearing shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub(crate) enum OtpKind {
    Totp { period: u32 },
    Hotp { counter: u64 },
}

/// Public projection of `OtpKind` for non-secret presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "error-serde", serde(rename_all = "lowercase"))]
pub enum AccountKindSummary {
    /// Time-based OTP (RFC 6238).
    Totp,
    /// HMAC-based OTP (RFC 4226).
    Hotp,
}

/// Manual-input kind selector.
///
/// [`Default`] is [`AccountKindInput::Totp`] to match the CLI
/// manual-add default per `docs/DESIGN.md` §5 (TOTP unless `--hotp`);
/// front-end modals snapshot this default at modal-open time.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AccountKindInput {
    /// Caller is adding a TOTP account.
    #[default]
    Totp,
    /// Caller is adding an HOTP account.
    Hotp,
}

/// Manual-input icon-hint tri-state.
///
/// - `Default`: derive a slug from the issuer per `slug::derive_default_from_issuer`.
/// - `Clear`: store `None` even when the issuer would have produced a default.
/// - `Slug(value)`: validate and store the supplied slug.
#[derive(Clone, PartialEq, Eq)]
pub enum IconHintInput {
    /// Derive a slug from the issuer (`slug::derive_default_from_issuer`).
    Default,
    /// Force-store `None`, overriding any issuer-derived default.
    Clear,
    /// Validate and store the supplied slug verbatim.
    Slug(String),
}

impl IconHintInput {
    pub(crate) fn resolve(
        self,
        issuer: Option<&str>,
    ) -> Result<Option<String>, crate::error::PaladinError> {
        match self {
            Self::Default => Ok(slug::derive_default_from_issuer(issuer)),
            Self::Clear => Ok(None),
            Self::Slug(value) => slug::validate_slug(&value).map(Some),
        }
    }
}

// IconHintInput's Debug omits the slug content to avoid leaking the
// user-supplied value in ad-hoc debug output. The slug is not a
// secret, but the precedent is to keep input grammar opaque.
impl fmt::Debug for IconHintInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("IconHintInput::Default"),
            Self::Clear => f.write_str("IconHintInput::Clear"),
            Self::Slug(_) => f.write_str("IconHintInput::Slug(<redacted>)"),
        }
    }
}

/// Stable account identifier (`UUIDv4`, 16 bytes on disk, hyphenated
/// canonical Display).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountId(Uuid);

#[cfg(feature = "error-serde")]
impl serde::Serialize for AccountId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(&self.0.as_hyphenated())
    }
}

impl AccountId {
    /// Generate a fresh `AccountId` (`UUIDv4`).
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// The 16 raw bytes stored in the vault payload.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Reconstruct an `AccountId` from its 16 raw bytes (used by the
    /// vault decoder).
    #[must_use]
    #[allow(dead_code)] // Wired up by storage::payload (Phase E).
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Hyphenated canonical UUID display (the §4.1 "displayed in
    /// canonical hyphenated form" rule).
    #[must_use]
    pub fn to_hyphenated(&self) -> String {
        self.0.as_hyphenated().to_string()
    }

    /// Lowercase hex prefix of the requested byte length (max 32).
    /// Used by `Vault::shortest_unique_id_prefix` to compute
    /// disambiguators for CLI / TUI selection.
    #[must_use]
    #[allow(dead_code)] // Wired up by Vault::shortest_unique_id_prefix.
    pub(crate) fn hex_prefix(&self, hex_chars: usize) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(32);
        for byte in self.0.as_bytes() {
            let _ = write!(s, "{byte:02x}");
        }
        s.truncate(hex_chars.min(32));
        s
    }
}

impl Default for AccountId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hyphenated())
    }
}

impl fmt::Debug for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccountId({})", self.to_hyphenated())
    }
}

// Encoded as the 16 raw UUID bytes — fixed-width and stable across
// rebuilds, matching the §4.1 "16 bytes on disk" rule.
impl Encode for AccountId {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
        Encode::encode(self.as_bytes(), encoder)
    }
}

impl<C> Decode<C> for AccountId {
    fn decode<D: Decoder<Context = C>>(decoder: &mut D) -> Result<Self, DecodeError> {
        let bytes: [u8; 16] = Decode::decode(decoder)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl<'de, C> BorrowDecode<'de, C> for AccountId {
    fn borrow_decode<D: BorrowDecoder<'de, Context = C>>(
        decoder: &mut D,
    ) -> Result<Self, DecodeError> {
        Decode::decode(decoder)
    }
}

/// A fully validated OTP account. Constructable only through the
/// validation entry points; raw secret bytes are not exposed.
///
/// `Account` does **not** implement `serde::Serialize`. The vault
/// payload (docs/DESIGN.md §4.3) is encoded via the bincode-driven
/// `storage::payload` codec, which has explicit, audited access to
/// the private fields.
#[derive(Clone, PartialEq, Eq, Encode, Decode)]
pub struct Account {
    pub(crate) id: AccountId,
    pub(crate) label: String,
    pub(crate) issuer: Option<String>,
    pub(crate) secret: Secret,
    pub(crate) algorithm: Algorithm,
    pub(crate) digits: u8,
    pub(crate) kind: OtpKind,
    pub(crate) icon_hint: Option<String>,
    pub(crate) created_at: u64,
    pub(crate) updated_at: u64,
}

impl Account {
    /// Stable identifier.
    #[must_use]
    pub fn id(&self) -> AccountId {
        self.id
    }

    /// Account label (the user-facing name).
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Optional issuer (the service the account belongs to).
    #[must_use]
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Borrow the secret bytes for OTP computation. Callers must not
    /// copy these bytes into a non-zeroizing buffer.
    ///
    /// Crate-private: front ends inspect accounts through
    /// [`AccountSummary`] / [`Account::summary`]; the OTP secret never
    /// leaves the crate via the public API.
    #[must_use]
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    /// HMAC algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// OTP digit width (6, 7, or 8).
    #[must_use]
    pub fn digits(&self) -> u8 {
        self.digits
    }

    /// Public (non-secret) projection of the OTP kind.
    #[must_use]
    pub fn kind(&self) -> AccountKindSummary {
        match self.kind {
            OtpKind::Totp { .. } => AccountKindSummary::Totp,
            OtpKind::Hotp { .. } => AccountKindSummary::Hotp,
        }
    }

    /// TOTP period (seconds), or `None` for HOTP accounts.
    #[must_use]
    pub fn period(&self) -> Option<u32> {
        match self.kind {
            OtpKind::Totp { period } => Some(period),
            OtpKind::Hotp { .. } => None,
        }
    }

    /// HOTP counter, or `None` for TOTP accounts.
    #[must_use]
    pub fn counter(&self) -> Option<u64> {
        match self.kind {
            OtpKind::Totp { .. } => None,
            OtpKind::Hotp { counter } => Some(counter),
        }
    }

    /// Optional icon-name slug.
    #[must_use]
    pub fn icon_hint(&self) -> Option<&str> {
        self.icon_hint.as_deref()
    }

    /// Unix-seconds creation timestamp.
    #[must_use]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Unix-seconds timestamp of the most recent payload mutation,
    /// including HOTP counter advances.
    #[must_use]
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Public, non-secret projection.
    #[must_use]
    pub fn summary(&self) -> AccountSummary {
        AccountSummary {
            id: self.id,
            issuer: self.issuer.clone(),
            label: self.label.clone(),
            kind: self.kind(),
            algorithm: self.algorithm,
            digits: self.digits,
            period: self.period(),
            counter: self.counter(),
            icon_hint: self.icon_hint.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }

    /// Bumps `updated_at`. Used by HOTP advances (Phase G).
    #[allow(dead_code)] // Wired up by Vault::hotp_advance.
    pub(crate) fn touch(&mut self, now: SystemTime) -> Result<(), crate::error::PaladinError> {
        self.updated_at = validation::system_time_to_secs(now)?;
        Ok(())
    }
}

// `Account`'s Debug deliberately omits the secret bytes. The label,
// issuer, algorithm, kind, and timestamp are not secret, but the
// secret newtype must never appear.
impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("issuer", &self.issuer)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("kind", &self.kind)
            .field("icon_hint", &self.icon_hint)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            // secret intentionally omitted
            .finish_non_exhaustive()
    }
}

/// Public, non-secret projection of an `Account`. Used by all
/// presentation crates for list rows, JSON output, duplicate-account
/// errors, and import reports. See docs/DESIGN.md §4.1 / §5.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
pub struct AccountSummary {
    /// Stable account identifier (`UUIDv4`).
    pub id: AccountId,
    /// Optional issuer string (max 128 bytes).
    pub issuer: Option<String>,
    /// Account label (max 128 bytes).
    pub label: String,
    /// `Totp` or `Hotp`.
    pub kind: AccountKindSummary,
    /// HMAC algorithm (SHA-1, SHA-256, SHA-512).
    pub algorithm: Algorithm,
    /// Number of OTP digits (6, 7, or 8).
    pub digits: u8,
    /// TOTP period in seconds; `None` for HOTP accounts.
    pub period: Option<u32>,
    /// HOTP counter value; `None` for TOTP accounts.
    pub counter: Option<u64>,
    /// Optional icon-hint slug (issuer-derived or user-supplied).
    pub icon_hint: Option<String>,
    /// Account creation timestamp (Unix seconds).
    pub created_at: u64,
    /// Last-modified timestamp (Unix seconds).
    pub updated_at: u64,
}

/// Generated OTP, projected for non-secret presentation.
///
/// For TOTP, `valid_from`, `valid_until`, and `seconds_remaining` are
/// `Some` and `counter_used` is `None`. For HOTP, the validity fields
/// are `None` and `counter_used` carries the pre-advance counter.
///
/// `code` is zero-padded to the account's digit width.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "error-serde", derive(serde::Serialize))]
pub struct Code {
    /// OTP digits, zero-padded to the account's `digits` width.
    pub code: String,
    /// TOTP window start (Unix seconds); `None` for HOTP.
    pub valid_from: Option<u64>,
    /// TOTP window end (Unix seconds); `None` for HOTP.
    pub valid_until: Option<u64>,
    /// Seconds remaining in the current TOTP window; `None` for HOTP.
    pub seconds_remaining: Option<u32>,
    /// HOTP counter that produced this code; `None` for TOTP.
    pub counter_used: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_canonical_display_is_36_chars_with_4_hyphens() {
        let id = AccountId::new();
        let s = id.to_string();
        assert_eq!(s.len(), 36, "{s}");
        assert_eq!(s.bytes().filter(|&b| b == b'-').count(), 4);
    }

    #[test]
    fn account_id_round_trips_bytes() {
        let id = AccountId::new();
        let bytes = *id.as_bytes();
        let reconstructed = AccountId::from_bytes(bytes);
        assert_eq!(id, reconstructed);
        assert_eq!(id.to_hyphenated(), reconstructed.to_hyphenated());
    }

    #[test]
    fn account_id_hex_prefix_lowercase_8_chars() {
        let id = AccountId::from_bytes([
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        assert_eq!(id.hex_prefix(8), "abcdef01");
        assert_eq!(id.hex_prefix(4), "abcd");
        assert_eq!(id.hex_prefix(32).len(), 32);
        assert_eq!(id.hex_prefix(40).len(), 32, "clamps to 32 hex chars");
    }

    #[test]
    fn algorithm_default_is_sha1() {
        assert_eq!(Algorithm::default(), Algorithm::Sha1);
        assert_eq!(Algorithm::Sha1.as_str(), "SHA1");
        assert_eq!(Algorithm::Sha256.as_str(), "SHA256");
        assert_eq!(Algorithm::Sha512.as_str(), "SHA512");
    }

    #[test]
    fn icon_hint_input_resolve_default_derives_from_issuer() {
        let resolved = IconHintInput::Default.resolve(Some("GitHub")).unwrap();
        assert_eq!(resolved.as_deref(), Some("github"));

        let resolved = IconHintInput::Default.resolve(None).unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn icon_hint_input_resolve_clear_returns_none_even_with_issuer() {
        let resolved = IconHintInput::Clear.resolve(Some("GitHub")).unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn icon_hint_input_resolve_slug_validates() {
        let resolved = IconHintInput::Slug("github".into())
            .resolve(Some("ignored"))
            .unwrap();
        assert_eq!(resolved.as_deref(), Some("github"));

        let err = IconHintInput::Slug("Invalid Slug".into())
            .resolve(None)
            .unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::ValidationError);
    }

    #[test]
    fn icon_hint_input_debug_redacts_slug_content() {
        let dbg = format!("{:?}", IconHintInput::Slug("super-secret-name".into()));
        assert!(!dbg.contains("super-secret-name"));
        assert!(dbg.contains("redacted"));
    }
}
