// SPDX-License-Identifier: AGPL-3.0-or-later

//! TUI clipboard adapter — the only impure boundary between
//! [`crate::app::effect`] and the OS clipboard.
//!
//! Production routes through a long-lived [`ClipboardSession`] that
//! caches one [`arboard::Clipboard`] for the lifetime of
//! [`crate::app::run::run_event_loop`] and reuses it across copies,
//! auto-clear writes, and QR image reads. The session is owned by
//! the run boundary and threaded through [`crate::app::dispatch`] to
//! the executor; effects mutate it via the
//! [`ClipboardSession::write_text`] / [`ClipboardSession::read_text`]
//! / [`ClipboardSession::read_image`] methods.
//!
//! Holding the `arboard::Clipboard` across writes (instead of
//! constructing and dropping one per call) has two effects:
//!
//! * **Linux X11 ownership persistence.** On X11 the contents of
//!   the clipboard live in the process that wrote them; dropping the
//!   [`arboard::Clipboard`] immediately after a write can lose the
//!   contents before clipboard managers (clipman, parcellite,
//!   gpaste, …) have polled them. Reusing one session keeps the X11
//!   selection owner alive for the duration of the app.
//! * **No `arboard` debug warning on stderr.** `arboard` 3.x in
//!   `debug_assertions` builds prints
//!   `"Clipboard was dropped very quickly after writing …"` to
//!   stderr when the [`arboard::Clipboard`] is dropped < 100 ms
//!   after `set_text` *and* stderr is a TTY (which it always is
//!   under the TUI). The warning lands on the alternate screen and
//!   mangles the next ratatui render. Long-lived sessions guarantee
//!   the drop runs only at app exit — well past 100 ms after the
//!   final write — so the warning is never reached.
//!
//! Under the `paladin-tui/test-hooks` cargo feature the
//! `PALADIN_CLIPBOARD_DRYRUN` env-var bypass short-circuits each
//! method before it ever touches `arboard`, letting reducer /
//! effect tests exercise the copy → schedule →
//! only-if-unchanged auto-clear flows end-to-end without a system
//! clipboard server. The pattern mirrors
//! [`paladin-cli`'s `clipboard` adapter](../../../paladin-cli/src/clipboard.rs)
//! so the two front-ends share the same DRYRUN contract — see
//! `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Clipboard auto-clear" and
//! the `test-hooks` feature comment in `Cargo.toml`.
//!
//! All text-read / text-write error paths collapse to `Err(())`
//! because the underlying `arboard` error strings are not part of
//! the §6 status-line wire shape (the front-end surfaces
//! `clipboard_write_failed` unconditionally on write failure).
//!
//! Image reads (the QR-import path from the Add modal) collapse to
//! the two-variant [`ImageReadError`] so the executor can map them
//! onto the distinct user-facing wordings the reducer renders for
//! `QrImportFailure::NoClipboardImage` vs
//! `QrImportFailure::ImageDecodeFailure` (per
//! `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Add modal": *"No-image,
//! no-QR, and invalid-QR cases reject inline."*).

/// Raw RGBA8 image pulled off the OS clipboard, re-shaped into a stable
/// type so the `arboard` dependency does not leak through the adapter
/// boundary.
///
/// `width` × `height` × 4 must equal `rgba.len()` for an
/// `arboard`-sourced image; the executor passes the buffer straight
/// to [`paladin_core::import::qr_image_bytes`], which re-validates the
/// dimensions and rejects oversized buffers with the
/// `validation_error { field: "qr_image", reason: "image_too_large" }`
/// surface the reducer renders through `render_error_message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardImage {
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Raw RGBA8 pixel bytes, row-major, exactly `width * height * 4`
    /// bytes long.
    pub rgba: Vec<u8>,
}

/// Why a [`ClipboardSession::read_image`] call could not return a
/// usable buffer.
///
/// Two variants instead of one so the executor can route to the
/// matching `crate::app::event::QrImportFailure` variant — the
/// reducer renders different inline-error wording for each per
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Add modal".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageReadError {
    /// The clipboard does not currently hold an image (the active
    /// target is text-only, empty, or the platform reported
    /// `ContentNotAvailable`).
    NoImage,
    /// An image is present but cannot be decoded into a usable RGBA8
    /// raster (the platform reported a backend / conversion failure,
    /// or `arboard` itself failed to initialize).
    DecodeFailure,
}

/// A long-lived OS clipboard handle.
///
/// Owns one lazily-initialized [`arboard::Clipboard`] which is
/// created on the first method call that needs it and reused for
/// every subsequent read / write. Lazy creation means a session
/// that never copies does not open an X11 / Wayland connection.
/// Reuse means we keep the X11 selection owner alive across the
/// app's lifetime, fixing the "clipboard managers may not have
/// seen the contents" problem and silencing `arboard`'s
/// debug-build "dropped too quickly" warning that would otherwise
/// land on stderr and mangle the alternate-screen render.
///
/// Owned by [`crate::app::run::run_event_loop`] and threaded
/// through [`crate::app::dispatch`] to the executor as
/// `&mut ClipboardSession` — there is one session per running TUI
/// process. Dropping the session (at app exit) drops the cached
/// `arboard::Clipboard`, which at that point has been alive for
/// well over the 100 ms threshold the debug warning checks, so no
/// warning prints during normal shutdown either.
#[derive(Default)]
pub struct ClipboardSession {
    inner: Option<arboard::Clipboard>,
}

impl std::fmt::Debug for ClipboardSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `arboard::Clipboard` does not implement `Debug`, so we
        // surface only whether the cached handle has been
        // initialized yet. Tests that need richer assertions inspect
        // observable side-effects (the in-process fake) instead.
        f.debug_struct("ClipboardSession")
            .field("initialized", &self.inner.is_some())
            .finish()
    }
}

impl ClipboardSession {
    /// Construct an empty session. The underlying `arboard::Clipboard`
    /// is allocated on the first read / write that actually needs it.
    #[must_use]
    pub fn new() -> Self {
        Self { inner: None }
    }

    /// Lazily initialize the cached [`arboard::Clipboard`] and return
    /// a mutable reference to it.
    ///
    /// If the cache is empty this calls [`arboard::Clipboard::new`]
    /// and stores the result on success. On failure the cache stays
    /// empty so the next call retries — transient failures (no
    /// display server yet, X11 hiccup) recover on the next attempt
    /// without forcing the session to be recreated.
    fn ensure(&mut self) -> Result<&mut arboard::Clipboard, arboard::Error> {
        if self.inner.is_none() {
            self.inner = Some(arboard::Clipboard::new()?);
        }
        // `unwrap`-via-`expect` is sound: the `if` branch above is
        // the only path that can leave `inner` `None`, and it always
        // populates `inner` before falling through here.
        Ok(self
            .inner
            .as_mut()
            .expect("`ensure` just populated `inner`"))
    }

    /// Read the current clipboard text contents.
    ///
    /// Production (`#[cfg(not(feature = "test-hooks"))]`) routes
    /// through the cached [`arboard::Clipboard::get_text`]. Errors
    /// collapse to `Err(())` for parity with the §6 status-line wire
    /// shape.
    #[cfg(not(feature = "test-hooks"))]
    #[allow(clippy::result_unit_err)]
    pub fn read_text(&mut self) -> Result<String, ()> {
        self.ensure()
            .and_then(arboard::Clipboard::get_text)
            .map_err(|_| ())
    }

    /// Write `text` to the system clipboard.
    ///
    /// Production (`#[cfg(not(feature = "test-hooks"))]`) routes
    /// through the cached [`arboard::Clipboard::set_text`]. Errors
    /// collapse to `Err(())` for parity with the §6 status-line wire
    /// shape.
    #[cfg(not(feature = "test-hooks"))]
    #[allow(clippy::result_unit_err)]
    pub fn write_text(&mut self, text: &str) -> Result<(), ()> {
        self.ensure()
            .and_then(|cb| cb.set_text(text.to_string()))
            .map_err(|_| ())
    }

    /// Read the current clipboard image as raw RGBA8 bytes.
    ///
    /// Production (`#[cfg(not(feature = "test-hooks"))]`) routes
    /// through the cached [`arboard::Clipboard::get_image`] and
    /// re-shapes the result into the adapter-owned [`ClipboardImage`]
    /// type. The two error variants — [`ImageReadError::NoImage`]
    /// for "clipboard does not hold an image" and
    /// [`ImageReadError::DecodeFailure`] for everything else
    /// (backend init failure, conversion failure, dimension
    /// overflow) — let the QR-import executor surface the two
    /// distinct inline-error wordings the reducer renders from
    /// `QrImportFailure::NoClipboardImage` /
    /// `QrImportFailure::ImageDecodeFailure`.
    #[cfg(not(feature = "test-hooks"))]
    pub fn read_image(&mut self) -> Result<ClipboardImage, ImageReadError> {
        let cb = self.ensure().map_err(|err| map_image_err(&err))?;
        let img = cb.get_image().map_err(|err| map_image_err(&err))?;
        let width = u32::try_from(img.width).map_err(|_| ImageReadError::DecodeFailure)?;
        let height = u32::try_from(img.height).map_err(|_| ImageReadError::DecodeFailure)?;
        Ok(ClipboardImage {
            width,
            height,
            rgba: img.bytes.into_owned(),
        })
    }

    /// Read the current clipboard text contents.
    ///
    /// Test-hooks build: honors `PALADIN_CLIPBOARD_DRYRUN` —
    /// `=1` routes to the in-process fake (returning the bytes set
    /// by [`seed_test_clipboard`] / written by the gated
    /// `write_text`), `=fail` returns `Err(())`, any other value
    /// (or unset) falls through to the cached `arboard` backend.
    /// Errors collapse to `Err(())` for parity with the production
    /// signature.
    #[cfg(feature = "test-hooks")]
    #[allow(clippy::result_unit_err)]
    pub fn read_text(&mut self) -> Result<String, ()> {
        use std::ffi::OsStr;
        if let Some(v) = std::env::var_os("PALADIN_CLIPBOARD_DRYRUN") {
            if v == OsStr::new("1") {
                return Ok(FAKE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone());
            }
            if v == OsStr::new("fail") {
                return Err(());
            }
        }
        self.ensure()
            .and_then(arboard::Clipboard::get_text)
            .map_err(|_| ())
    }

    /// Write `text` to the system clipboard.
    ///
    /// Test-hooks build: honors `PALADIN_CLIPBOARD_DRYRUN` —
    /// `=1` routes to the in-process fake so the bytes are
    /// observable through [`read_test_clipboard`], `=fail` returns
    /// `Err(())`, any other value (or unset) falls through to the
    /// cached `arboard` backend. Errors collapse to `Err(())` for
    /// parity with the production signature.
    #[cfg(feature = "test-hooks")]
    #[allow(clippy::result_unit_err)]
    pub fn write_text(&mut self, text: &str) -> Result<(), ()> {
        use std::ffi::OsStr;
        if let Some(v) = std::env::var_os("PALADIN_CLIPBOARD_DRYRUN") {
            if v == OsStr::new("1") {
                *FAKE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = text.to_string();
                return Ok(());
            }
            if v == OsStr::new("fail") {
                return Err(());
            }
        }
        self.ensure()
            .and_then(|cb| cb.set_text(text.to_string()))
            .map_err(|_| ())
    }

    /// Read the current clipboard image.
    ///
    /// Test-hooks build: honors `PALADIN_CLIPBOARD_DRYRUN` —
    /// `=1` routes to the in-process fake (returning the image set
    /// by [`seed_test_clipboard_image`], or
    /// `Err(ImageReadError::NoImage)` when no seed is active),
    /// `=fail` returns `Err(ImageReadError::DecodeFailure)`, any
    /// other value (or unset) falls through to the cached `arboard`
    /// backend.
    #[cfg(feature = "test-hooks")]
    pub fn read_image(&mut self) -> Result<ClipboardImage, ImageReadError> {
        use std::ffi::OsStr;
        if let Some(v) = std::env::var_os("PALADIN_CLIPBOARD_DRYRUN") {
            if v == OsStr::new("1") {
                return FAKE_IMAGE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                    .ok_or(ImageReadError::NoImage);
            }
            if v == OsStr::new("fail") {
                return Err(ImageReadError::DecodeFailure);
            }
        }
        let cb = self.ensure().map_err(|err| map_image_err(&err))?;
        let img = cb.get_image().map_err(|err| map_image_err(&err))?;
        let width = u32::try_from(img.width).map_err(|_| ImageReadError::DecodeFailure)?;
        let height = u32::try_from(img.height).map_err(|_| ImageReadError::DecodeFailure)?;
        Ok(ClipboardImage {
            width,
            height,
            rgba: img.bytes.into_owned(),
        })
    }
}

/// Map an `arboard::Error` onto the two-variant adapter error.
///
/// `arboard::Error::ContentNotAvailable` is the only path that means
/// "no image present"; every other `arboard` failure (conversion
/// failure, backend init failure, clipboard occupied, unknown) folds
/// into `DecodeFailure` so the executor reaches the
/// `QrImportFailure::ImageDecodeFailure` branch.
fn map_image_err(err: &arboard::Error) -> ImageReadError {
    match err {
        arboard::Error::ContentNotAvailable => ImageReadError::NoImage,
        _ => ImageReadError::DecodeFailure,
    }
}

// ---------------------------------------------------------------------------
// Test-build fake-clipboard storage (gated on `paladin-tui/test-hooks`).
//
// Honors `PALADIN_CLIPBOARD_DRYRUN` so reducer / effect tests can
// exercise copy → schedule → only-if-unchanged auto-clear without a
// system clipboard server:
//
//   * `PALADIN_CLIPBOARD_DRYRUN=1` → bypass arboard, route reads and
//     writes through an in-process fake addressable through
//     [`seed_test_clipboard`] / [`read_test_clipboard`].
//   * `PALADIN_CLIPBOARD_DRYRUN=fail` → bypass arboard, return
//     `Err(())` for both `read_text` and `write_text` so the
//     `clipboard_write_failed` / read-failure branches stay covered.
//   * any other value (or unset) → fall through to the real arboard
//     backend.
//
// The in-process fake lives in a process-global `Mutex<String>` so
// every adapter call sees the same state regardless of which thread
// it runs on. A second mutex ([`test_clipboard_lock`]) serializes
// test functions that touch the env var, since `std::env::set_var`
// is process-wide and the `cargo test` binary runs tests in
// parallel by default.
// ---------------------------------------------------------------------------

#[cfg(feature = "test-hooks")]
use std::sync::{Mutex, MutexGuard};

#[cfg(feature = "test-hooks")]
static FAKE: Mutex<String> = Mutex::new(String::new());

#[cfg(feature = "test-hooks")]
static FAKE_IMAGE: Mutex<Option<ClipboardImage>> = Mutex::new(None);

#[cfg(feature = "test-hooks")]
static TEST_GUARD: Mutex<()> = Mutex::new(());

/// Acquire the process-wide test-clipboard lock. Holding this guard
/// serializes any test that touches `PALADIN_CLIPBOARD_DRYRUN` or the
/// in-process fake clipboard so the env-var manipulation does not
/// race with parallel-running tests.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
pub fn test_clipboard_lock() -> MutexGuard<'static, ()> {
    // `PoisonError::into_inner` lets a test continue after a peer
    // test panicked mid-section — the panic is already surfaced by
    // the test runner, and re-poisoning here would just mask the
    // failure of the still-running test.
    TEST_GUARD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Seed the in-process fake clipboard with `text`. The next
/// `PALADIN_CLIPBOARD_DRYRUN=1`-gated [`ClipboardSession::read_text`]
/// call returns exactly these bytes.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
pub fn seed_test_clipboard(text: impl Into<String>) {
    *FAKE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = text.into();
}

/// Read the current in-process fake clipboard contents. Mirrors what
/// a `PALADIN_CLIPBOARD_DRYRUN=1`-gated
/// [`ClipboardSession::read_text`] would return.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
#[must_use]
pub fn read_test_clipboard() -> String {
    FAKE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Seed the in-process fake clipboard image. The next
/// `PALADIN_CLIPBOARD_DRYRUN=1`-gated
/// [`ClipboardSession::read_image`] call returns exactly these
/// dimensions and bytes.
///
/// Each call replaces any prior seed; pair with
/// [`clear_test_clipboard_image`] to reach the
/// `ImageReadError::NoImage` branch under `PALADIN_CLIPBOARD_DRYRUN=1`.
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
pub fn seed_test_clipboard_image(width: u32, height: u32, rgba: Vec<u8>) {
    *FAKE_IMAGE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ClipboardImage {
        width,
        height,
        rgba,
    });
}

/// Clear the in-process fake clipboard image so the next
/// `PALADIN_CLIPBOARD_DRYRUN=1`-gated
/// [`ClipboardSession::read_image`] returns
/// [`ImageReadError::NoImage`].
///
/// Available only under `cfg(feature = "test-hooks")`.
#[cfg(feature = "test-hooks")]
pub fn clear_test_clipboard_image() {
    *FAKE_IMAGE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
}
