// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared front-end contract constants (docs/DESIGN.md §6 / §7).
//
// All constants the TUI and GUI need to agree on live here so neither
// crate hard-codes a divergent value. The CLI is stateless and ignores
// `clipboard.clear_secs`, but the bound constants still apply when it
// validates `settings set` patches against the same grammar the TUI
// and GUI use.
//
// Pinned by fixture in `tests/ui_contract.rs`.

/// HOTP reveal countdown duration, in seconds (docs/DESIGN.md §6 / §7).
///
/// Both the TUI countdown and GUI reveal panel hide the displayed HOTP
/// code after this many seconds.
pub const HOTP_REVEAL_SECS: u64 = 120;

/// Maximum decoded RGBA buffer size accepted by the GUI QR scanner,
/// in bytes (docs/DESIGN.md §7). 64 MiB chosen to comfortably bound a 4096
/// × 4096 RGBA image (64 MiB exact) without forcing the scanner into
/// a partial-decode path.
pub const QR_RGBA_MAX_BYTES: usize = 64 * 1024 * 1024;

/// TUI / GUI redraw cadence, in milliseconds (docs/DESIGN.md §6 / §7).
///
/// Drives the TOTP countdown gauge and the clipboard staleness check
/// timer in both presentation crates so they refresh at the same rate.
pub const TICK_INTERVAL_MS: u64 = 250;

/// Inclusive lower bound for `Vault::set_auto_lock_timeout_secs`
/// (docs/DESIGN.md §4.7 / §5).
pub const AUTO_LOCK_SECS_MIN: u32 = 30;

/// Inclusive upper bound for `Vault::set_auto_lock_timeout_secs`
/// — 24 h (docs/DESIGN.md §4.7 / §5).
pub const AUTO_LOCK_SECS_MAX: u32 = 86_400;

/// Inclusive lower bound for `Vault::set_clipboard_clear_secs`
/// (docs/DESIGN.md §4.7 / §5).
pub const CLIPBOARD_CLEAR_SECS_MIN: u32 = 5;

/// Inclusive upper bound for `Vault::set_clipboard_clear_secs`
/// — 10 min (docs/DESIGN.md §4.7 / §5).
pub const CLIPBOARD_CLEAR_SECS_MAX: u32 = 600;

/// Inclusive lower bound for `QrRenderOptions::module_size_px`
/// (docs/DESIGN.md §4.6 / §7).
///
/// One module = one pixel; the renderer accepts the minimum but most
/// scanners need a few pixels per module to lock on. Front-ends should
/// surface `QR_MODULE_SIZE_PX_DEFAULT` as the user-facing default.
pub const QR_MODULE_SIZE_PX_MIN: u32 = 1;

/// Inclusive upper bound for `QrRenderOptions::module_size_px`
/// (docs/DESIGN.md §4.6 / §7).
///
/// 64 pixels per module is large enough for high-resolution print and
/// small enough that a fully-quiet-zoned QR for a typical `otpauth://`
/// URI stays well under a few megabytes of PNG even at QR version 10.
pub const QR_MODULE_SIZE_PX_MAX: u32 = 64;

/// Default value for `QrRenderOptions::module_size_px`
/// (docs/DESIGN.md §4.6 / §7).
///
/// Eight pixels per module is a comfortable scan size on a typical
/// laptop display while keeping the PNG byte count modest.
pub const QR_MODULE_SIZE_PX_DEFAULT: u32 = 8;
