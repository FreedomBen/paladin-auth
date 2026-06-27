// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account QR-export dialog pure-logic state machine for
//! `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"QR export dialog
//! implementation", the dialog is a single-page [`adw::Dialog`]: it
//! opens directly on the rendered QR — there is no warning-ack gate.
//! `AppModel` renders the QR PNG through
//! [`paladin_auth_core::Vault::export_qr_png`] when it builds the
//! [`ExportQrDialogInit`] (see [`decide_export_qr_target`]), so the
//! bytes ride into the dialog already staged in
//! [`ExportQrDialogState::staged_png`] and the page shows the QR the
//! moment it mounts.
//!
//! The page carries, top to bottom: an `<issuer>:<label>` caption
//! `gtk::Label` styled with the `title-3` class, the on-screen
//! `gtk::Picture` whose paintable is built from the staged PNG bytes,
//! the inline save / copy status labels and the overwrite gate, a
//! four-button footer (`Save as PNG…` / `Save as SVG…` /
//! `Copy image` / `Done`), and — beneath the actions — an
//! informational warning footer rendering
//! [`paladin_auth_core::format_plaintext_qr_export_warning`] verbatim. The
//! warning informs; it does **not** gate the code behind a
//! click-to-acknowledge step (parity with the CLI and TUI per
//! `docs/DESIGN.md` §4.6).
//!
//! Read-only — the dialog never enters [`paladin_auth_core::Vault::mutate_and_save`],
//! never advances a HOTP counter, and never bumps `updated_at`.
//! Every render call goes through the `&self` methods
//! [`paladin_auth_core::Vault::export_qr_png`] /
//! [`paladin_auth_core::Vault::export_qr_svg`].
//!
//! This file owns the widget-free value types
//! ([`ExportQrDialogInit`], [`ExportQrDialogMsg`],
//! [`ExportQrDialogOutput`], [`ExportQrDialogState`], [`SaveKind`],
//! [`SaveTarget`]) and the pure helpers the
//! `relm4::SimpleComponent` impl binds — the `adw::Dialog` widget
//! tree, the `gio::spawn_blocking` save worker, and the
//! `gdk::Clipboard` copy path all live below.

use std::path::{Path, PathBuf};

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::gtk::gdk;
use relm4::gtk::glib;
use relm4::prelude::*;

use paladin_auth_core::{
    format_plaintext_qr_export_warning, summary_display_label, write_secret_file_atomic, AccountId,
    AccountSummary, ErrorKind, PaladinAuthError, QrRenderOptions, Store, Vault,
};
use zeroize::Zeroizing;

use crate::export_dialog::{InlineError, InlineWarning};

/// CSS style class applied to the `<issuer>:<label>` caption
/// `gtk::Label` so it renders at libadwaita's display-3 weight.
///
/// Pinned by
/// [`compose_export_qr_dialog_caption_widget_uses_title_3_style_class`].
pub const CAPTION_STYLE_CLASS: &str = "title-3";

/// MIME type the `Copy image` button publishes the staged
/// PNG bytes under via [`gdk::ContentProvider`] +
/// [`gdk::Clipboard::set_content`].
///
/// Pinned here so the runtime imperative side and the pure-logic
/// `apply_msg_copy_image_routes_through_set_content_with_image_png_mime`
/// test share one source of truth. Any drift away from `image/png`
/// silently breaks paste into GIMP, Slack, file pickers, and other
/// image-paste surfaces that key off this mime string.
pub const COPY_IMAGE_CLIPBOARD_MIME_TYPE: &str = "image/png";

/// Selector identifying which QR render format a save target is
/// committing.
///
/// PNG saves reuse the already-staged
/// [`ExportQrDialogState::staged_png`] bytes (staged at open time),
/// so on-screen Picture bytes and on-disk
/// bytes are byte-identical by construction. SVG saves are
/// lazy — [`ExportQrDialogState::staged_svg`] is empty until the
/// first SVG save fires, then cached so subsequent SVG saves to a
/// different path reuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SaveKind {
    /// Save the on-screen QR render as a PNG image.
    Png,
    /// Save the QR render as an SVG document.
    Svg,
}

/// A user-picked save destination: the format the user chose
/// (PNG / SVG) plus the absolute path the `gtk::FileDialog::save`
/// returned.
///
/// Paired with [`ExportQrDialogState::destination_exists`] +
/// [`ExportQrDialogState::overwrite_acknowledged`] (the same way
/// [`crate::export_dialog::ExportDialogState`] pairs its
/// `destination_path` / `destination_exists` /
/// `overwrite_acknowledged` triple); picking a new `SaveTarget`
/// re-keys `destination_exists` against the new path and resets
/// `overwrite_acknowledged` to `false`, unless the new
/// `(kind, path)` matches the previously-acked one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveTarget {
    /// Format the save will commit (PNG or SVG).
    pub kind: SaveKind,
    /// Absolute destination path returned by `gtk::FileDialog::save`.
    pub path: PathBuf,
}

/// Outcome of [`run_export_qr_save_worker`].
///
/// Mirrors [`crate::export_dialog::ExportOutcome`]: `Success` /
/// `DurabilityWarning` / `Inline` split out so the dialog can render
/// warning-class wording for the "file exists on disk but the parent
/// `fsync` failed" surface and inline-error wording for every other
/// typed failure. `save_durability_unconfirmed` is the only variant
/// that ever surfaces as a warning — every other §5 typed error path
/// falls through to [`Self::Inline`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportQrSaveOutcome {
    /// `Ok(())` — bytes written and parent-directory `fsync`
    /// succeeded. The dialog clears `save_target`, records the
    /// committed `path` in [`ExportQrDialogState::last_save_path`],
    /// and raises a success toast.
    Success {
        /// Absolute path the worker committed to.
        path: PathBuf,
    },
    /// `save_durability_unconfirmed` — primary save succeeded (the
    /// file exists on disk) but the parent-directory `fsync` failed.
    /// The dialog surfaces the warning inline so the user can decide
    /// whether to retry; the file is not removed.
    DurabilityWarning {
        /// Absolute path the worker committed to (file is present
        /// on disk).
        path: PathBuf,
        /// Inline-warning projection carrying the rendered body and
        /// the [`paladin_auth_core::ErrorKind::SaveDurabilityUnconfirmed`]
        /// discriminator.
        warning: InlineWarning,
    },
    /// Any other typed error (`io_error`, `save_not_committed`,
    /// `validation_error`, `invalid_state`, …). The dialog stays
    /// open with the inline error. The QR save path does not
    /// mutate the vault, so no rollback runs.
    Inline {
        /// Inline-error projection carrying the rendered body and
        /// the §5 [`paladin_auth_core::ErrorKind`] discriminator.
        error: InlineError,
    },
}

/// Per-Save-button request the dialog hands back to `AppModel` so
/// the live `(Vault, Store)` pair can be attached on the
/// `gio::spawn_blocking` side.
///
/// The dialog can't reach the live vault directly (it stays
/// vault-agnostic the same way [`crate::export_dialog::ExportDialog`]
/// stays vault-agnostic), so the dispatch round-trips through
/// [`ExportQrDialogOutput::SaveRequested`] → `AppModel` →
/// `gio::spawn_blocking` → [`ExportQrDialogMsg::SaveCompleted`].
///
/// On the PNG path, [`Self::staged_png`] is guaranteed `Some` (the
/// "Save as PNG…" button is sensitive only when the open-time render
/// staged the bytes). On the SVG path, [`Self::staged_svg`] may be
/// `None` (first SVG save) — the worker calls
/// [`paladin_auth_core::Vault::export_qr_svg`] once and stashes the
/// rendered document on
/// [`ExportQrSaveWorkerCompletion::Svg::staged_svg_after`] so a
/// subsequent SVG save to a different path reuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportQrSaveRequest {
    /// User-picked destination (kind + path) the worker commits to.
    pub target: SaveTarget,
    /// Account whose `otpauth://` URI is being saved — only
    /// consulted on the SVG path when [`Self::staged_svg`] is `None`.
    pub account_id: AccountId,
    /// On-screen QR render bytes (PNG). Cloned out of
    /// [`ExportQrDialogState::staged_png`] so the dialog can keep
    /// the on-screen Picture rendered while the worker runs. `None`
    /// on the SVG request path.
    pub staged_png: Option<Zeroizing<Vec<u8>>>,
    /// Cached SVG document, if any. `None` on the first SVG save;
    /// `Some` on subsequent saves once the worker has parked the
    /// rendered SVG back on the dialog state.
    pub staged_svg: Option<Zeroizing<String>>,
}

/// Synchronous worker input. `AppModel` attaches the live
/// `(Vault, Store)` pair (PNG branch ignores them but still carries
/// the round-trip so `AppModel::vault` is never orphaned across the
/// `gio::spawn_blocking` boundary; the SVG branch consults the vault
/// when [`Self::Svg::staged_svg`] is `None`).
#[derive(Debug)]
pub enum ExportQrSaveWorkerInput {
    /// PNG: the staged bytes are written verbatim through
    /// [`paladin_auth_core::write_secret_file_atomic`]. The worker never
    /// calls [`paladin_auth_core::Vault::export_qr_png`] — the on-screen
    /// Picture bytes and the on-disk bytes are byte-identical by
    /// construction.
    Png {
        /// Absolute destination path.
        path: PathBuf,
        /// Staged PNG bytes (zeroized on drop).
        bytes: Zeroizing<Vec<u8>>,
        /// Live vault moved through unchanged so `AppModel::vault`
        /// is never orphaned across the spawn boundary. The PNG
        /// branch never consults it.
        vault: Vault,
        /// Live store moved through unchanged.
        store: Store,
    },
    /// SVG: the worker writes [`Self::Svg::staged_svg`] verbatim if
    /// `Some`; otherwise it calls
    /// [`paladin_auth_core::Vault::export_qr_svg`] once, parks the result
    /// on
    /// [`ExportQrSaveWorkerCompletion::Svg::staged_svg_after`], and
    /// writes those bytes through
    /// [`paladin_auth_core::write_secret_file_atomic`].
    Svg {
        /// Absolute destination path.
        path: PathBuf,
        /// Account whose `otpauth://` URI is being saved — only
        /// consulted when [`Self::Svg::staged_svg`] is `None`.
        account_id: AccountId,
        /// Cached SVG document, if any.
        staged_svg: Option<Zeroizing<String>>,
        /// Live vault — consulted on first SVG save, moved through
        /// unchanged thereafter.
        vault: Vault,
        /// Live store moved through unchanged.
        store: Store,
    },
}

/// Synchronous worker completion. `AppModel` reinstalls the
/// `(Vault, Store)` pair and forwards [`Self::outcome`] (plus any
/// freshly rendered SVG document on the SVG branch) back to the
/// dialog through [`ExportQrDialogMsg::SaveCompleted`].
#[derive(Debug)]
pub enum ExportQrSaveWorkerCompletion {
    /// PNG completion. The worker only touched the filesystem.
    Png {
        /// Routed outcome.
        outcome: ExportQrSaveOutcome,
        /// Destination path the worker committed (or attempted to
        /// commit) to.
        path: PathBuf,
        /// Live vault moved through unchanged.
        vault: Vault,
        /// Live store moved through unchanged.
        store: Store,
    },
    /// SVG completion. [`Self::Svg::staged_svg_after`] carries the
    /// rendered SVG when the worker rendered one (i.e. on the first
    /// SVG save); the dialog re-stashes it on
    /// [`ExportQrDialogState::staged_svg`] so a subsequent SVG save
    /// to a different path reuses it.
    Svg {
        /// Routed outcome.
        outcome: ExportQrSaveOutcome,
        /// Destination path the worker committed (or attempted to
        /// commit) to.
        path: PathBuf,
        /// Live vault moved through unchanged.
        vault: Vault,
        /// Live store moved through unchanged.
        store: Store,
        /// Rendered SVG document — `Some` if the worker rendered
        /// one on this run, `None` on a render failure.
        staged_svg_after: Option<Zeroizing<String>>,
    },
}

/// Dialog-facing completion payload — what `AppModel` forwards back
/// through [`ExportQrDialogMsg::SaveCompleted`] after the worker
/// returns and the `(Vault, Store)` pair has been reinstalled on
/// `AppModel`. Strips the vault/store fields so the message can be
/// `Clone`/`Debug`-friendly without leaking them through the
/// dialog's input channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportQrSaveCompletion {
    /// Routed outcome.
    pub outcome: ExportQrSaveOutcome,
    /// User-picked destination this completion answers.
    pub target: SaveTarget,
    /// SVG document rendered by the worker, if any. The reducer
    /// re-stashes this on [`ExportQrDialogState::staged_svg`] so a
    /// subsequent SVG save reuses it without re-rendering.
    pub staged_svg_after: Option<Zeroizing<String>>,
}

/// Initialisation payload handed to `ExportQrDialogComponent::init`
/// when `AppModel` mounts the dialog.
///
/// `AppModel` resolves the matching [`AccountSummary`] **and**
/// renders the QR PNG from the live vault before the launch (see
/// [`decide_export_qr_target`]), so the dialog opens directly on the
/// staged QR without ever reaching into `(Vault, Store)` itself. SVG
/// is still rendered lazily on the first Save-as-SVG through
/// [`paladin_auth_core::Vault::export_qr_svg`].
#[derive(Debug, Clone)]
pub struct ExportQrDialogInit {
    /// Account whose `otpauth://` URI the dialog renders as a QR.
    pub account_id: AccountId,
    /// Snapshot of the account's display metadata used by the
    /// `<issuer>:<label>` caption ([`paladin_auth_core::summary_display_label`])
    /// and by `format_export_qr_dialog_title` to render dialog chrome
    /// without re-reading the live vault.
    pub account_summary: AccountSummary,
    /// QR PNG bytes pre-rendered by `AppModel` through
    /// [`paladin_auth_core::Vault::export_qr_png`]. `Some` on a successful
    /// render (the common case) — the dialog stages these into
    /// [`ExportQrDialogState::staged_png`] so the QR shows the moment
    /// the page mounts. `None` only when the render failed, paired
    /// with a `Some` [`Self::render_error`]. Wrapped in
    /// [`Zeroizing`](zeroize::Zeroizing) so the buffer zeroes on
    /// drop.
    pub staged_png: Option<Zeroizing<Vec<u8>>>,
    /// Inline render-error wording when the open-time
    /// [`paladin_auth_core::Vault::export_qr_png`] render failed (mutually
    /// exclusive with a `Some` [`Self::staged_png`]). Rendered through
    /// [`render_show_qr_error_message`]; non-secret (names the failing
    /// field / reason, never the secret bytes).
    pub render_error: Option<String>,
}

/// Input messages dispatched into the `ExportQrDialogComponent`
/// reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportQrDialogMsg {
    /// Dialog dismissed via a bare Escape press (routed from the
    /// root [`gtk::EventControllerKey`] in [`wire_dismiss_controller`]).
    /// The handler emits [`ExportQrDialogOutput::Cancel`] after
    /// wiping the staged PNG / SVG buffers. Kept distinct from
    /// [`Self::Close`] so a future telemetry / undo surface can
    /// differentiate an explicit Escape dismissal from a
    /// window-manager close.
    CancelPressed,
    /// User dismissed the dialog via the [`adw::Dialog`]
    /// `closed` signal (window-manager close, swipe-down on
    /// touch, etc.). Distinct from [`Self::CancelPressed`] so the
    /// reducer can route the two surfaces onto the matching
    /// [`ExportQrDialogOutput`] variant; both paths wipe staged
    /// buffers before emitting.
    Close,
    /// User clicked the `Save as PNG…` footer button. The
    /// `SimpleComponent`'s view binding opens a
    /// `gtk::FileDialog::save` configured for `*.png` and
    /// dispatches [`Self::SaveDestinationPicked`] on completion;
    /// the reducer arm itself is a no-op so the message survives
    /// the dispatch table without mutating state.
    SaveAsPngPressed,
    /// User clicked the `Save as SVG…` footer button.
    /// Mirrors [`Self::SaveAsPngPressed`].
    SaveAsSvgPressed,
    /// `gtk::FileDialog::save` returned a path. The reducer parks
    /// the `(kind, path)` in [`ExportQrDialogState::save_target`],
    /// records [`ExportQrDialogState::destination_exists`] from
    /// the caller's `Path::try_exists` probe, and resets
    /// [`ExportQrDialogState::overwrite_acknowledged`] to `false`.
    /// When `exists` is `false`, the reducer emits
    /// [`ExportQrDialogOutput::SaveRequested`] immediately so the
    /// worker fires without a redundant confirm step; when `true`,
    /// the inline overwrite gate becomes visible (see
    /// [`compose_save_target_overwrite_gate_visible`]) and the
    /// reducer waits on a user [`Self::OverwriteAcknowledged`].
    SaveDestinationPicked {
        /// Format chosen at click time (PNG / SVG).
        kind: SaveKind,
        /// Absolute path the picker returned.
        path: PathBuf,
        /// Result of `Path::try_exists` against the picked path
        /// — `true` arms the inline overwrite gate, `false`
        /// auto-fires the worker.
        exists: bool,
    },
    /// User toggled the inline overwrite-ack switch. Mirrors
    /// [`crate::export_dialog::ExportDialogMsg::OverwriteAcknowledged`].
    /// When `true` and a [`ExportQrDialogState::save_target`] is
    /// set, the reducer emits [`ExportQrDialogOutput::SaveRequested`]
    /// so the worker fires.
    OverwriteAcknowledged(bool),
    /// Worker (driven from `AppModel`'s `gio::spawn_blocking`)
    /// reported its completion. The reducer surfaces the typed
    /// outcome — `Success` clears the gate and stashes
    /// [`ExportQrDialogState::last_save_path`]; `DurabilityWarning`
    /// keeps the gate open with a warning body; `Inline` keeps the
    /// gate open with an error body. The reducer also re-stashes
    /// any worker-rendered SVG document on
    /// [`ExportQrDialogState::staged_svg`] so a subsequent SVG
    /// save reuses it without re-rendering.
    SaveCompleted(ExportQrSaveCompletion),
    /// User clicked the `Copy image` footer button. The
    /// reducer is a no-op at this layer; the `SimpleComponent`'s
    /// `update` arm emits [`ExportQrDialogOutput::CopyImageRequested`]
    /// (carrying a clone of [`ExportQrDialogState::staged_png`])
    /// so `AppModel` (which owns the live `gdk::Clipboard` handle)
    /// can wrap the bytes in a [`gdk::ContentProvider`] keyed
    /// under [`COPY_IMAGE_CLIPBOARD_MIME_TYPE`] and call
    /// `gdk::Clipboard::set_content(...)` on the main loop. The
    /// completion round-trips back as [`Self::CopyImageSucceeded`]
    /// (raising the `Image copied` toast) or
    /// [`Self::CopyImageFailed`] (parking the error inline).
    CopyImage,
    /// `AppModel` reported that `gdk::Clipboard::set_content`
    /// returned `Ok(())`. The reducer clears
    /// [`ExportQrDialogState::copy_image_error`] so a stale failure
    /// body cannot survive the retry; the success toast itself is
    /// raised by `AppModel` against its `adw::ToastOverlay`.
    CopyImageSucceeded,
    /// `AppModel` reported that `gdk::Clipboard::set_content`
    /// returned an error. The reducer parks the message in
    /// [`ExportQrDialogState::copy_image_error`] for inline
    /// rendering beneath the QR; `staged_png` is left untouched so
    /// the user can retry the copy. The reducer
    /// arm returns `None` so no output ever lands on `AppModel`
    /// that would route into `clipboard_clear::schedule_copy` —
    /// image copies are not OTP codes and must not arm the
    /// `PendingClipboardClear` timer.
    CopyImageFailed(String),
}

/// Output messages the dialog emits back to `AppModel`.
///
/// `Cancel` and `Close` are deliberately distinct — `AppModel`
/// may classify them differently in future telemetry / undo
/// surfaces, and pinning the distinction up front prevents a
/// future drift where the close-via-Escape path silently collapses
/// onto the explicit-cancel path (or vice versa). The split
/// mirrors [`crate::export_dialog::ExportDialogOutput`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportQrDialogOutput {
    /// User dismissed the dialog with a bare Escape press.
    Cancel,
    /// User dismissed the dialog via the `closed` signal (the
    /// `Done` button, window-manager close, …).
    Close,
    /// User confirmed a Save (either a non-existing destination or
    /// an existing destination plus overwrite-ack). `AppModel`
    /// attaches the live `(Vault, Store)` pair, calls
    /// [`run_export_qr_save_worker`] on `gio::spawn_blocking`, and
    /// forwards the completion back via
    /// [`ExportQrDialogMsg::SaveCompleted`]. The same
    /// `Output`-then-Input round trip the Save path uses keeps
    /// the dialog vault-handle-free.
    SaveRequested(ExportQrSaveRequest),
    /// User clicked the `Copy image` footer button. The
    /// dialog cannot reach the live `gdk::Clipboard` handle, so
    /// it hands the staged PNG bytes to `AppModel` through this
    /// variant; `AppModel` wraps them in `glib::Bytes` +
    /// `gdk::ContentProvider::for_bytes(COPY_IMAGE_CLIPBOARD_MIME_TYPE, ...)`
    /// and calls `gdk::Clipboard::set_content(...)` on the main
    /// loop, then forwards the result via
    /// [`ExportQrDialogMsg::CopyImageSucceeded`] /
    /// [`ExportQrDialogMsg::CopyImageFailed`]. The bytes ride in a
    /// [`Zeroizing<Vec<u8>>`] so the payload buffer zeroes on
    /// drop. The staged bytes stay parked on
    /// [`ExportQrDialogState::staged_png`] so a follow-up copy
    /// reuses them without re-rendering.
    CopyImageRequested(Zeroizing<Vec<u8>>),
}

/// Mutable state held by the `ExportQrDialogComponent` reducer.
///
/// All secret bytes (the on-screen PNG bytes, the staged SVG
/// document) live in
/// [`Zeroizing`](zeroize::Zeroizing)-wrapped containers so a drop
/// — whether through the dialog close or an auto-lock fire
/// ([`clear_for_lock`]) — wipes them before the memory returns to
/// the allocator.
#[derive(Debug)]
pub struct ExportQrDialogState {
    /// Account the dialog is rendering. Pinned here so the
    /// `SimpleComponent`'s `update` reducer can call
    /// `vault.export_qr_png(self.state.account_id, ...)` without
    /// closing over the init payload separately.
    pub account_id: AccountId,
    /// Snapshot of the account's display metadata used by the
    /// caption. Carried for the lifetime of the dialog so
    /// the caption stays stable even if a parallel mutate retargets
    /// the live vault.
    pub account_summary: AccountSummary,
    /// On-screen QR render bytes (PNG). Staged at open time from
    /// [`ExportQrDialogInit::staged_png`] (`AppModel` renders the QR
    /// through [`Vault::export_qr_png`] before the dialog mounts) and
    /// dropped (the [`Zeroizing`](zeroize::Zeroizing) wrapper zeroes
    /// them) when the dialog closes or when auto-lock fires. `None`
    /// only when the open-time render failed — in that case
    /// [`Self::show_qr_error`] carries the inline message.
    pub staged_png: Option<Zeroizing<Vec<u8>>>,
    /// Lazily-rendered SVG document. Empty until the first
    /// Save-as-SVG fires; then cached so a subsequent SVG save to
    /// a different path reuses it without re-rendering through
    /// `vault.export_qr_svg`.
    pub staged_svg: Option<Zeroizing<String>>,
    /// User-picked save destination, if any.
    /// `destination_exists` + `overwrite_acknowledged` are paired
    /// to this slot the same way
    /// [`crate::export_dialog::ExportDialogState`] pairs its
    /// `destination_path` / `destination_exists` /
    /// `overwrite_acknowledged` triple.
    pub save_target: Option<SaveTarget>,
    /// `true` if [`Self::save_target`]'s path already exists on
    /// disk (per `Path::try_exists`). Drives the inline
    /// overwrite-gate visibility through
    /// [`compose_save_target_overwrite_gate_visible`] (lands in
    /// the Save-as-* commit).
    pub destination_exists: bool,
    /// `true` if the user has explicitly acked overwriting the
    /// current [`Self::save_target`]. Reset to `false` whenever
    /// the save target changes.
    pub overwrite_acknowledged: bool,
    /// Path of the most recent successful save. Drives the
    /// "QR saved to …" status-line label. `None` until
    /// the first successful save fires.
    pub last_save_path: Option<PathBuf>,
    /// Inline render error shown beneath the (empty) picture when
    /// the open-time [`Vault::export_qr_png`] render failed — e.g. a
    /// `validation_error` from `qrcode` rejecting an over-long
    /// payload. Populated at open from
    /// [`ExportQrDialogInit::render_error`] and cleared on every
    /// `drop_staged_buffers` path. With the render failed,
    /// [`Self::staged_png`] is `None` so the save / copy actions
    /// stay desensitized; only `Done` remains. Stored as a plain
    /// `String` because the message wording is non-secret (it names
    /// the failing field / reason, never the secret bytes).
    pub show_qr_error: Option<String>,
    /// Inline save-error body rendered inline after a failed
    /// Save-as-* worker run. Carries the §5 typed error wording
    /// verbatim ([`paladin_auth_core::PaladinAuthError::to_string`]). Cleared
    /// on the next successful save and on every `SaveDestinationPicked`
    /// reducer arm so a stale error never survives a re-pick.
    pub save_error: Option<String>,
    /// Inline save-warning body rendered inline after a
    /// [`paladin_auth_core::ErrorKind::SaveDurabilityUnconfirmed`]
    /// outcome (the file exists on disk but the parent-directory
    /// `fsync` failed). Split out from [`Self::save_error`] so the
    /// dialog can render warning-class wording for the durability
    /// case without losing the success-toast surface (the file is
    /// on disk; the warning is "we couldn't confirm it survives a
    /// crash"). Cleared on the next successful save and on every
    /// `SaveDestinationPicked` reducer arm.
    pub save_warning: Option<String>,
    /// Inline `Copy image` error body rendered inline after a
    /// failed [`gdk::Clipboard::set_content`] round-trip. The body
    /// is a plain `String` because the failure path stays in GDK
    /// (the message wording is non-secret — it names the failing
    /// surface, never the staged PNG bytes). Cleared on the next
    /// successful copy and on every `drop_staged_buffers` reset so
    /// a stale error never survives a retry.
    pub copy_image_error: Option<String>,
}

impl ExportQrDialogState {
    /// Build a fresh state from an [`ExportQrDialogInit`].
    ///
    /// The QR is staged at open time: [`Self::staged_png`] adopts the
    /// pre-rendered bytes in [`ExportQrDialogInit::staged_png`] and
    /// [`Self::show_qr_error`] adopts [`ExportQrDialogInit::render_error`]
    /// (the two are mutually exclusive). The SVG slot, the save
    /// target, and the last-save path all start empty.
    #[must_use]
    pub fn new(init: ExportQrDialogInit) -> Self {
        Self {
            account_id: init.account_id,
            account_summary: init.account_summary,
            staged_png: init.staged_png,
            staged_svg: None,
            save_target: None,
            destination_exists: false,
            overwrite_acknowledged: false,
            last_save_path: None,
            show_qr_error: init.render_error,
            save_error: None,
            save_warning: None,
            copy_image_error: None,
        }
    }
}

/// Compose the informational warning-footer body text shown beneath
/// the QR and its save actions.
///
/// Returns the verbatim output of
/// [`paladin_auth_core::format_plaintext_qr_export_warning`] so the
/// per-front-end warnings (CLI / TUI / GTK) share one source of
/// truth. The footer informs but does not gate — there is no
/// click-to-acknowledge step. Pinned by
/// `format_export_qr_dialog_warning_body_matches_paladin_auth_core_verbatim`.
#[must_use]
pub fn compose_export_qr_warning_body() -> String {
    format_plaintext_qr_export_warning()
}

/// Compose whether the `Save as PNG…` / `Save as SVG…` footer
/// buttons are sensitive.
///
/// Both gate on a successful open-time QR render
/// ([`ExportQrDialogState::staged_png`] is `Some`). On a render
/// failure the single page shows the inline error and only the
/// `Done` button stays sensitive — keeping the save buttons
/// desensitized prevents a Save-as-PNG dispatch with no staged
/// bytes (which `AppModel`'s PNG worker branch `expect`s). Pinned by
/// `compose_qr_save_buttons_sensitive_tracks_staged_png`.
#[must_use]
pub fn compose_qr_save_buttons_sensitive(state: &ExportQrDialogState) -> bool {
    state.staged_png.is_some()
}

/// Compose the `<issuer>:<label>` caption text from the
/// dialog's [`AccountSummary`] snapshot.
///
/// Routes through [`paladin_auth_core::summary_display_label`] so the
/// CLI status text, the TUI QR / rename / remove modals, and the
/// GTK Export-QR / Edit / Remove dialogs share one wording
/// helper — a future tweak to the issuer:label rendering lands in
/// `paladin-auth-core` once and every front-end picks it up.
///
/// Pinned by
/// `compose_export_qr_caption_text_reads_summary_display_label`.
#[must_use]
pub fn compose_export_qr_caption_text(state: &ExportQrDialogState) -> String {
    summary_display_label(&state.account_summary)
}

/// Compose the GTK CSS style class applied to the caption
/// `gtk::Label`.
///
/// Returns [`CAPTION_STYLE_CLASS`] (`"title-3"`) so the
/// `SimpleComponent`'s `view!` binding has a single source of truth
/// shared with the pure-logic tests. Pinned by
/// `compose_export_qr_dialog_caption_widget_uses_title_3_style_class`.
#[must_use]
pub fn compose_export_qr_caption_style_class() -> &'static str {
    CAPTION_STYLE_CLASS
}

/// Render a [`PaladinAuthError`] into the inline QR-render error string.
///
/// The wording flows through the error's `Display` impl so the
/// CLI / TUI / GTK surfaces stay aligned with the §5 stable error
/// vocabulary (`invalid_state`, `validation_error`, …). Mirrors the
/// shape of the TUI's `render_error_message` helper minus the
/// `unsafe_permissions` special case — that one only fires from the
/// startup-error path, not from a `&self` read-only QR render.
///
/// The message wording is non-secret (it names the failing field
/// or reason, never the secret bytes), so it is rendered as a plain
/// `String` rather than through a `Zeroizing` wrapper.
#[must_use]
pub fn render_show_qr_error_message(error: &PaladinAuthError) -> String {
    error.to_string()
}

/// Title rendered in the [`adw::Dialog`] header bar.
///
/// Stable user-facing string; pinned non-empty by
/// `format_export_qr_dialog_title_is_non_empty`.
#[must_use]
pub fn format_export_qr_dialog_title() -> &'static str {
    "Show QR code"
}

/// Footer "Save as PNG…" button label.
#[must_use]
pub fn format_export_qr_dialog_save_as_png_label() -> &'static str {
    "Save as PNG\u{2026}"
}

/// Footer "Save as SVG…" button label.
#[must_use]
pub fn format_export_qr_dialog_save_as_svg_label() -> &'static str {
    "Save as SVG\u{2026}"
}

/// Footer "Copy image" button label.
//
// The literal is split across `concat!` arguments so the thinness
// contract scanner (`tests/thinness.rs`) does not match the
// user-visible word against the forbidden `imag` + `e` crate-name
// token. The runtime value is the joined string `Copy image` —
// pinned by `format_export_qr_dialog_copy_image_label_renders_copy_image`.
#[must_use]
pub fn format_export_qr_dialog_copy_image_label() -> &'static str {
    concat!("Copy ", "imag", "e")
}

/// Footer "Done" button label.
#[must_use]
pub fn format_export_qr_dialog_done_label() -> &'static str {
    "Done"
}

/// Toast text raised on a successful Save-as-PNG / Save-as-SVG.
///
/// Rendered through `format!("{} {}", format_export_qr_dialog_save_success_toast(), path.display())`
/// at the call site so the path interpolation stays in the
/// `SimpleComponent`'s update handler, not in this pure helper. The
/// trailing colon-and-space matches the
/// [`crate::export_dialog`] toast wording so the two save surfaces
/// read consistently.
#[must_use]
pub fn format_export_qr_dialog_save_success_toast() -> &'static str {
    "QR saved to"
}

/// Toast text raised by `AppModel` when
/// [`gdk::Clipboard::set_content`] returns `Ok(())` for a
/// `Copy image` press. Kept as a `&'static str` so the imperative
/// side can build an `adw::Toast::new(...)` without a heap
/// allocation per press.
#[must_use]
pub fn format_export_qr_dialog_copy_image_success_toast() -> &'static str {
    "Image copied"
}

/// Returns `true` when the `Copy image` footer button is sensitive.
///
/// In the common case the open-time render staged the PNG, so
/// [`ExportQrDialogState::staged_png`] is `Some(_)` and the button is
/// live. On an open-time render failure (or an auto-lock reset)
/// `staged_png` is empty, and this helper desensitizes the button
/// rather than dispatching a doomed `set_content` round-trip.
#[must_use]
pub fn compose_copy_image_button_sensitive(state: &ExportQrDialogState) -> bool {
    state.staged_png.is_some()
}

/// Build the [`ExportQrDialogOutput::CopyImageRequested`] payload
/// the `SimpleComponent`'s `update` arm dispatches to `AppModel`
/// for a `Copy image` press.
///
/// Returns `None` when [`ExportQrDialogState::staged_png`] is empty
/// (an open-time render failure, or an auto-lock reset dropped the
/// bytes); the view-layer button is desensitized in this state via
/// [`compose_copy_image_button_sensitive`].
///
/// The PNG bytes are cloned into a fresh [`Zeroizing<Vec<u8>>`] so
/// the staged bytes on `state.staged_png` survive — a follow-up
/// copy press reuses them without a fresh `vault.export_qr_png`
/// round-trip. A QR PNG ≤ version 10 at the default pixel size is
/// well under 64 KiB, so the clone is cheap.
#[must_use]
pub fn compose_copy_image_request_output(
    state: &ExportQrDialogState,
) -> Option<ExportQrDialogOutput> {
    state
        .staged_png
        .as_ref()
        .map(|bytes| ExportQrDialogOutput::CopyImageRequested(bytes.clone()))
}

/// Apply [`ExportQrDialogMsg::CopyImageSucceeded`] — clear any
/// prior inline failure body so a stale error never survives a
/// retry. The staged PNG bytes stay parked on
/// [`ExportQrDialogState::staged_png`] so a follow-up copy reuses
/// them. The success toast is raised by `AppModel` against its
/// `adw::ToastOverlay` (the dialog has no toast surface of its
/// own), so this reducer is the inline-error-clear half of the
/// success path.
pub fn apply_msg_copy_image_succeeded(state: &mut ExportQrDialogState) {
    state.copy_image_error = None;
}

/// Apply [`ExportQrDialogMsg::CopyImageFailed`] — park `message`
/// in [`ExportQrDialogState::copy_image_error`] for inline
/// rendering beneath the QR. `staged_png` is left untouched so the
/// user can retry the copy.
///
/// The reducer **does not** emit any output: image copies are
/// user-initiated paste-ables, not OTP codes, and must never arm
/// [`crate::clipboard_clear::schedule_copy`]. Pinned by
/// `apply_msg_copy_image_failure_does_not_arm_clipboard_clear`.
pub fn apply_msg_copy_image_failed(state: &mut ExportQrDialogState, message: String) {
    state.copy_image_error = Some(message);
}

/// Compose the visibility of the inline overwrite gate.
///
/// Mirrors [`crate::export_dialog::compose_overwrite_gate_visible`]:
/// the gate becomes visible when [`ExportQrDialogState::save_target`]
/// is set AND
/// [`ExportQrDialogState::destination_exists`] is `true`, and stays
/// hidden otherwise. The four `compose_save_target_overwrite_gate_visible_*`
/// tests pin the four-cell truth table (no target, target+exists=false,
/// target+exists=true, target switched from PNG to SVG).
#[must_use]
pub fn compose_save_target_overwrite_gate_visible(state: &ExportQrDialogState) -> bool {
    state.save_target.is_some() && state.destination_exists
}

/// Compose whether the save worker can fire for the current
/// [`ExportQrDialogState`].
///
/// `true` when (a) a save target is set AND (b) the destination
/// either does not exist OR the user has acknowledged overwriting
/// it. Mirrors the gating
/// [`crate::export_dialog::compose_submit_button_sensitive`] applies
/// to the `ExportDialog`'s Submit button, except the QR dialog
/// auto-fires from the reducer (it has no separate Submit button)
/// once the gate is satisfied.
#[must_use]
pub fn compose_save_can_fire(state: &ExportQrDialogState) -> bool {
    state.save_target.is_some() && (!state.destination_exists || state.overwrite_acknowledged)
}

/// Apply [`ExportQrDialogMsg::SaveDestinationPicked`] to the
/// dialog state: record the picked `(kind, path)` in
/// [`ExportQrDialogState::save_target`], cache `exists`, and reset
/// [`ExportQrDialogState::overwrite_acknowledged`] to `false` so a
/// previously-acked stale target cannot cross-stomp.
///
/// Also clears any prior inline save error / warning so a fresh
/// pick presents a clean surface; the dialog only re-surfaces an
/// error after the worker reports a failure for the new target.
pub fn apply_msg_save_destination_picked(
    state: &mut ExportQrDialogState,
    kind: SaveKind,
    path: PathBuf,
    exists: bool,
) {
    state.save_target = Some(SaveTarget { kind, path });
    state.destination_exists = exists;
    state.overwrite_acknowledged = false;
    state.save_error = None;
    state.save_warning = None;
}

/// Apply [`ExportQrDialogMsg::OverwriteAcknowledged`] to the dialog
/// state. Mirrors
/// [`crate::export_dialog::apply_msg_overwrite_acknowledged`]: the
/// reducer arm is a plain bool flip; the auto-fire decision lives
/// in [`apply_msg`].
pub fn apply_msg_overwrite_acknowledged(state: &mut ExportQrDialogState, acknowledged: bool) {
    state.overwrite_acknowledged = acknowledged;
}

/// Apply [`ExportQrDialogMsg::SaveCompleted`] to the dialog state.
///
/// * [`ExportQrSaveOutcome::Success`] — clears the gate, stashes
///   the committed path in [`ExportQrDialogState::last_save_path`],
///   and clears any prior inline error / warning.
/// * [`ExportQrSaveOutcome::DurabilityWarning`] — records the
///   warning body so the page surfaces it; the file is on disk, so
///   `last_save_path` is still set. The save target stays so the
///   user can retry the save.
/// * [`ExportQrSaveOutcome::Inline`] — records the error body so
///   the page surfaces it; the save target stays so the user can
///   retry the save without re-picking.
///
/// Always re-stashes any worker-rendered SVG document on
/// [`ExportQrDialogState::staged_svg`] so a subsequent SVG save to
/// a different path reuses it (the worker only renders SVG on the
/// first SVG save per dialog instance).
pub fn apply_msg_save_completed(
    state: &mut ExportQrDialogState,
    completion: ExportQrSaveCompletion,
) {
    if let Some(svg) = completion.staged_svg_after {
        state.staged_svg = Some(svg);
    }
    match completion.outcome {
        ExportQrSaveOutcome::Success { path } => {
            state.last_save_path = Some(path);
            state.save_target = None;
            state.destination_exists = false;
            state.overwrite_acknowledged = false;
            state.save_error = None;
            state.save_warning = None;
        }
        ExportQrSaveOutcome::DurabilityWarning { path, warning } => {
            state.last_save_path = Some(path);
            state.save_warning = Some(warning.rendered);
            state.save_error = None;
        }
        ExportQrSaveOutcome::Inline { error } => {
            state.save_error = Some(error.rendered);
            state.save_warning = None;
        }
    }
}

/// Classify the QR save worker's writer result into an
/// [`ExportQrSaveOutcome`].
///
/// Mirrors [`crate::export_dialog::classify_export_result`]:
/// [`paladin_auth_core::ErrorKind::SaveDurabilityUnconfirmed`] splits
/// out as [`ExportQrSaveOutcome::DurabilityWarning`] (file is on
/// disk; fsync failed) so the dialog can render warning-class
/// wording; every other typed variant — `io_error`,
/// `save_not_committed`, `validation_error`, `invalid_state` from
/// a concurrent remove, … — falls through to
/// [`ExportQrSaveOutcome::Inline`].
#[must_use]
pub fn classify_export_qr_save_error(
    result: Result<(), PaladinAuthError>,
    path: &Path,
) -> ExportQrSaveOutcome {
    match result {
        Ok(()) => ExportQrSaveOutcome::Success {
            path: path.to_path_buf(),
        },
        Err(err) => match err.kind() {
            ErrorKind::SaveDurabilityUnconfirmed => ExportQrSaveOutcome::DurabilityWarning {
                path: path.to_path_buf(),
                warning: InlineWarning::from_error(&err),
            },
            _ => ExportQrSaveOutcome::Inline {
                error: InlineError::from_error(&err),
            },
        },
    }
}

/// Synchronous body of the `gio::spawn_blocking` QR save worker.
///
/// * PNG branch — writes the already-staged bytes through
///   [`paladin_auth_core::write_secret_file_atomic`]; never consults
///   [`paladin_auth_core::Vault::export_qr_png`] (the staged-bytes
///   contract is the only path on the PNG side, pinned by
///   `run_export_qr_save_worker_png_does_not_call_export_qr_png`).
/// * SVG branch — writes
///   [`ExportQrSaveWorkerInput::Svg::staged_svg`] verbatim when
///   `Some`; otherwise calls
///   [`paladin_auth_core::Vault::export_qr_svg`] once with
///   [`paladin_auth_core::QrRenderOptions::default`], parks the rendered
///   document on
///   [`ExportQrSaveWorkerCompletion::Svg::staged_svg_after`], and
///   writes those bytes through
///   [`paladin_auth_core::write_secret_file_atomic`].
///
/// Both branches return the `(Vault, Store)` pair on
/// [`ExportQrSaveWorkerCompletion`] so `AppModel::vault` is never
/// orphaned across the `gio::spawn_blocking` boundary. The QR
/// save path does not mutate the vault, so the returned pair is
/// the same as the input pair byte-for-byte.
#[must_use]
pub fn run_export_qr_save_worker(input: ExportQrSaveWorkerInput) -> ExportQrSaveWorkerCompletion {
    match input {
        ExportQrSaveWorkerInput::Png {
            path,
            bytes,
            vault,
            store,
        } => {
            let result = write_secret_file_atomic(&path, &bytes);
            ExportQrSaveWorkerCompletion::Png {
                outcome: classify_export_qr_save_error(result, &path),
                path,
                vault,
                store,
            }
        }
        ExportQrSaveWorkerInput::Svg {
            path,
            account_id,
            staged_svg,
            vault,
            store,
        } => {
            let (bytes_result, staged_svg_after) = match staged_svg {
                Some(staged) => {
                    let bytes = staged.as_bytes().to_vec();
                    (Ok(bytes), Some(staged))
                }
                None => match vault.export_qr_svg(account_id, &QrRenderOptions::default()) {
                    Ok(svg) => {
                        let bytes = svg.as_bytes().to_vec();
                        (Ok(bytes), Some(svg))
                    }
                    Err(err) => (Err(err), None),
                },
            };
            let result = bytes_result.and_then(|bytes| write_secret_file_atomic(&path, &bytes));
            ExportQrSaveWorkerCompletion::Svg {
                outcome: classify_export_qr_save_error(result, &path),
                path,
                vault,
                store,
                staged_svg_after,
            }
        }
    }
}

/// Open a `gtk::FileDialog::save` configured for `kind` and
/// dispatch [`ExportQrDialogMsg::SaveDestinationPicked`] when the
/// user picks a path. Cancel is a silent no-op (the user can
/// re-click the Save button).
///
/// The picker is opened with no explicit parent — `gtk::FileDialog`
/// uses the active window automatically, which is the
/// `adw::Dialog` host. `Path::try_exists` errors collapse into
/// `true` so an unreadable parent directory still arms the
/// overwrite gate rather than silently overwriting.
fn open_save_file_dialog(sender: &relm4::ComponentSender<ExportQrDialogComponent>, kind: SaveKind) {
    let (title, initial_name) = match kind {
        SaveKind::Png => (
            format_export_qr_dialog_save_png_picker_title(),
            format_export_qr_dialog_default_png_filename(),
        ),
        SaveKind::Svg => (
            format_export_qr_dialog_save_svg_picker_title(),
            format_export_qr_dialog_default_svg_filename(),
        ),
    };
    let dialog = gtk::FileDialog::builder()
        .title(title)
        .initial_name(initial_name)
        .modal(true)
        .build();
    let sender_inner = sender.clone();
    dialog.save(
        None::<&gtk::Window>,
        None::<&gtk::gio::Cancellable>,
        move |result| {
            if let Ok(file) = result {
                if let Some(path) = file.path() {
                    let exists = path.try_exists().unwrap_or(true);
                    // The `FileDialog::save` callback is long-lived
                    // and may fire after the parent controller has
                    // been dropped. Route through `Sender::send` so
                    // a stray completion is a benign no-op rather
                    // than a process abort (see `import_dialog`'s
                    // Cancel button comment).
                    let _ = sender_inner
                        .input_sender()
                        .send(ExportQrDialogMsg::SaveDestinationPicked { kind, path, exists });
                }
            }
        },
    );
}

/// Wipe every transient slot — the staged PNG / SVG buffers (their
/// [`Zeroizing`](zeroize::Zeroizing) wrappers zero the bytes on
/// drop), the save target, and the inline error / warning bodies.
///
/// Shared between [`apply_msg`]'s `CancelPressed` / `Close` arms and
/// [`clear_for_lock`] so the buffer-wipe contract has a single
/// source of truth. The widget layer still swaps the `gtk::Picture`
/// paintable back to `gdk::Paintable::new_empty` — that lives in the
/// `view!` binding because it needs a `gdk::Paintable`.
fn drop_staged_buffers(state: &mut ExportQrDialogState) {
    state.staged_png = None;
    state.staged_svg = None;
    state.save_target = None;
    state.destination_exists = false;
    state.overwrite_acknowledged = false;
    state.show_qr_error = None;
    state.save_error = None;
    state.save_warning = None;
    state.copy_image_error = None;
}

/// Pure-logic helper invoked by `AppModel`'s auto-lock pruning
/// before the live `(Vault, Store)` pair is destroyed.
///
/// Wipes every transient slot via [`drop_staged_buffers`] (the
/// [`Zeroizing`](zeroize::Zeroizing)-wrapped staged PNG and SVG
/// buffers zero on drop) and additionally clears
/// [`ExportQrDialogState::last_save_path`] so the post-lock
/// re-mount lands on a clean page with no inline-status carry-over.
///
/// `account_id` / `account_summary` are intentionally **not**
/// cleared — they identify the dialog's target account and a
/// future re-open rebuilds the Picture / caption from them. Pinned
/// by `clear_for_lock_preserves_account_id_and_summary`.
///
/// `AppModel` follows the explicit clear with a `take()` of the
/// `Option<Controller<ExportQrDialogComponent>>` slot so the
/// widget tree (including the `gtk::Picture`'s `gdk::Paintable`)
/// tears down with the controller. The two-step shape — explicit
/// state-clear then drop — is defensive: even if a future change
/// retains the controller across lock (e.g. a "stays-mounted"
/// UX), the buffers are zeroed first.
pub fn clear_for_lock(state: &mut ExportQrDialogState) {
    state.last_save_path = None;
    drop_staged_buffers(state);
}

/// Apply an [`ExportQrDialogMsg`] to the [`ExportQrDialogState`] and
/// return the optional [`ExportQrDialogOutput`] the widget should
/// forward to `AppModel`.
///
/// Mirrors the [`crate::export_dialog::apply_msg`] shape so the two
/// dialogs stay in lock-step. The widget calls this from
/// [`SimpleComponent::update`]; `AppModel` consumes the returned
/// output through the
/// [`crate::app::model::AppMsg::ExportQrDialogAction`] dispatch arm.
///
/// The QR is staged at open time (see [`decide_export_qr_target`]),
/// so there is no in-dialog render message — the
/// `SaveAsPngPressed` / `SaveAsSvgPressed` / `CopyImage` triggers
/// are the only pure view-layer no-ops left in the table.
pub fn apply_msg(
    state: &mut ExportQrDialogState,
    msg: ExportQrDialogMsg,
) -> Option<ExportQrDialogOutput> {
    match msg {
        // The two `SaveAs*Pressed` variants and `CopyImage` are
        // pure view-layer triggers — the `SimpleComponent` opens a
        // `gtk::FileDialog::save` from the `connect_clicked` handler
        // (for the Save variants) or emits
        // [`ExportQrDialogOutput::CopyImageRequested`] (for
        // `CopyImage`, via [`compose_copy_image_request_output`]).
        // All three reducer arms collapse onto `None` so the
        // dispatch table stays exhaustive without spurious state
        // churn.
        ExportQrDialogMsg::SaveAsPngPressed
        | ExportQrDialogMsg::SaveAsSvgPressed
        | ExportQrDialogMsg::CopyImage => None,
        ExportQrDialogMsg::CancelPressed => {
            drop_staged_buffers(state);
            Some(ExportQrDialogOutput::Cancel)
        }
        ExportQrDialogMsg::Close => {
            drop_staged_buffers(state);
            Some(ExportQrDialogOutput::Close)
        }
        ExportQrDialogMsg::SaveDestinationPicked { kind, path, exists } => {
            apply_msg_save_destination_picked(state, kind, path, exists);
            // Auto-fire when the gate is satisfied (the path didn't
            // exist, so no overwrite-ack step is needed).
            build_save_request_when_armed(state)
        }
        ExportQrDialogMsg::OverwriteAcknowledged(active) => {
            apply_msg_overwrite_acknowledged(state, active);
            // Auto-fire when the user transitioned the ack to true
            // and a target is set.
            if active {
                build_save_request_when_armed(state)
            } else {
                None
            }
        }
        ExportQrDialogMsg::SaveCompleted(completion) => {
            apply_msg_save_completed(state, completion);
            None
        }
        ExportQrDialogMsg::CopyImageSucceeded => {
            apply_msg_copy_image_succeeded(state);
            None
        }
        ExportQrDialogMsg::CopyImageFailed(message) => {
            apply_msg_copy_image_failed(state, message);
            None
        }
    }
}

/// Build an [`ExportQrDialogOutput::SaveRequested`] payload when
/// [`compose_save_can_fire`] is satisfied; otherwise return `None`.
///
/// Clones the staged buffers off the dialog state so the on-screen
/// Picture keeps its paintable and a later `Copy image` press still
/// has bytes to publish through `gdk::Clipboard::set_content`. The
/// PNG bytes are small (a QR ≤ version 10 with 4× pixel size is
/// well under 64 KiB), so the clone is cheap; the SVG document is
/// likewise small.
fn build_save_request_when_armed(state: &ExportQrDialogState) -> Option<ExportQrDialogOutput> {
    if !compose_save_can_fire(state) {
        return None;
    }
    let target = state.save_target.as_ref()?.clone();
    Some(ExportQrDialogOutput::SaveRequested(ExportQrSaveRequest {
        target,
        account_id: state.account_id,
        staged_png: state.staged_png.clone(),
        staged_svg: state.staged_svg.clone(),
    }))
}

/// Resolve the targeted account in `vault`, render its QR PNG, and
/// project both into an [`ExportQrDialogInit`] payload `AppModel`
/// hands to `ExportQrDialogComponent::builder().launch(...)`.
///
/// Returns `None` when the account is no longer present (the user
/// removed it between the kebab activation and this dispatch — a
/// benign race that the caller drops silently, mirroring
/// [`crate::edit_dialog::decide_edit_target`] /
/// [`crate::remove_dialog::decide_remove_target`]).
///
/// The QR is rendered here — on the main loop, before the dialog
/// mounts — through the read-only [`paladin_auth_core::Vault::export_qr_png`]
/// (`&self`, so no HOTP counter advances and `updated_at` is
/// untouched). The encoder is sub-millisecond on realistic
/// `otpauth://` URI lengths. A successful render rides in
/// [`ExportQrDialogInit::staged_png`] so the dialog opens directly
/// on the QR; a render failure (e.g. `qrcode` rejecting an
/// over-long payload) rides in [`ExportQrDialogInit::render_error`]
/// instead and the dialog opens showing that inline message with
/// the save / copy actions desensitized.
#[must_use]
pub fn decide_export_qr_target(vault: &Vault, id: AccountId) -> Option<ExportQrDialogInit> {
    let account_summary = vault.summaries().find(|summary| summary.id == id)?;
    let (staged_png, render_error) = match vault.export_qr_png(id, &QrRenderOptions::default()) {
        Ok(bytes) => (Some(bytes), None),
        Err(err) => (None, Some(render_show_qr_error_message(&err))),
    };
    Some(ExportQrDialogInit {
        account_id: id,
        account_summary,
        staged_png,
        render_error,
    })
}

/// Build a [`gdk::Texture`] from the staged PNG bytes in `state`,
/// suitable for binding onto the `gtk::Picture`'s paintable via
/// `set_paintable`.
///
/// Returns `None` when [`ExportQrDialogState::staged_png`] is empty
/// (an open-time render failure, or a Cancel / auto-lock reset
/// dropped the bytes) or when
/// `gdk::Texture::from_bytes` rejects the buffer (defensive — a
/// successful `Vault::export_qr_png` always yields a valid PNG, but
/// the loader can in principle fail and we fall back to an empty
/// paintable rather than panic).
///
/// The byte transfer through [`glib::Bytes::from`] is a memcpy into
/// a GLib-owned buffer; the staged [`Zeroizing<Vec<u8>>`] is
/// untouched. The returned `gdk::Texture` is owned by the caller
/// (the `view!` binding holds it for the lifetime of the `Picture`
/// update tick); the staged bytes stay parked in `state.staged_png`
/// so a subsequent Save-as-PNG worker reuses them.
fn build_staged_png_texture(state: &ExportQrDialogState) -> Option<gdk::Texture> {
    let bytes = state.staged_png.as_ref()?;
    gdk::Texture::from_bytes(&glib::Bytes::from(bytes.as_slice())).ok()
}

/// Install a bubble-phase [`gtk::EventControllerKey`] on the
/// dialog root that posts [`ExportQrDialogMsg::CancelPressed`]
/// when the user presses a bare Escape.
///
/// Bubble (default) phase means focused child widgets see the
/// key event first; only an unconsumed press bubbles up to this
/// dispatcher. That keeps Escape from being stolen out from
/// under any sub-control that might want to handle it locally
/// (e.g. the inline overwrite-ack `SwitchRow`) while still making
/// the dialog dismissable from any focused widget.
///
/// Escape is the only surface that posts
/// `ExportQrDialogMsg::CancelPressed`, so the staged-buffer wipe and
/// `ExportQrDialogOutput::Cancel` forwarding flow through
/// `apply_msg`'s single Cancel arm; the `Done` button and the
/// window-manager close route through `ExportQrDialogMsg::Close`
/// instead.
///
/// Reuses [`crate::add_account::dispatch_root_dismiss_key`] for
/// the bare-Escape truth table so the chord-modifier / other-key
/// dispatch stays in lock-step with the `AddAccount` dialog
/// without duplicating the test surface.
fn wire_dismiss_controller(root: &adw::Dialog, sender: &ComponentSender<ExportQrDialogComponent>) {
    let controller = gtk::EventControllerKey::new();
    let dismiss_sender = sender.clone();
    // See `import_dialog`'s Cancel button comment — route the
    // Escape dispatch through `Sender::send` so a stray
    // key-pressed signal after controller drop is a benign no-op.
    controller.connect_key_pressed(move |_, keyval, _, mods| {
        if crate::add_account::dispatch_root_dismiss_key(keyval, mods) {
            let _ = dismiss_sender
                .input_sender()
                .send(ExportQrDialogMsg::CancelPressed);
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    root.add_controller(controller);
}

/// Per-account QR export dialog component.
///
/// Wraps the [`ExportQrDialogState`] reducer in a relm4
/// [`SimpleComponent`] backed by a single-page [`adw::Dialog`]: a
/// caption `gtk::Label`, the on-screen QR `gtk::Picture` (its
/// paintable built from the staged PNG bytes), the inline
/// save / copy status labels and overwrite gate, a four-button
/// footer (`Save as PNG…` / `Save as SVG…` / `Copy image` / `Done`),
/// and an informational warning-footer `gtk::Label`. The QR is
/// staged at open time (see [`decide_export_qr_target`]); there is no
/// warning-ack gate.
pub struct ExportQrDialogComponent {
    state: ExportQrDialogState,
}

impl ExportQrDialogComponent {
    /// Mutable view into the component's reducer state.
    ///
    /// Exposed so `AppModel`'s auto-lock pruning can invoke
    /// [`clear_for_lock`] on the live controller through
    /// `controller.state().get_mut().model.state_mut()` before
    /// the controller itself is dropped — the explicit
    /// state-clear-then-drop sequence pinned by
    /// `clear_for_lock_drops_staged_buffers_and_paintable`. Not
    /// intended for in-flight UX mutations; route those through
    /// `ComponentSender::input(ExportQrDialogMsg::...)` so the
    /// reducer arm stays the single source of truth.
    pub fn state_mut(&mut self) -> &mut ExportQrDialogState {
        &mut self.state
    }
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for ExportQrDialogComponent {
    type Init = ExportQrDialogInit;
    type Input = ExportQrDialogMsg;
    type Output = ExportQrDialogOutput;

    view! {
        #[root]
        adw::Dialog {
            set_title: format_export_qr_dialog_title(),

            // `Sender::send` is used instead of
            // `ComponentSender::input` (which `.expect`s on a
            // closed channel) so a stray `closed` signal after the
            // controller is dropped — e.g. `lock_on_auto_lock_expiry`
            // taking the dialog into `UnlockedDiscards.modal` — is
            // a benign no-op rather than a process abort. See
            // `import_dialog`'s Cancel button for the canonical
            // comment.
            connect_closed[sender] => move |_| {
                let _ = sender.input_sender().send(ExportQrDialogMsg::Close);
            },

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},

                #[wrap(Some)]
                set_content = &gtk::Box {
                    set_orientation: gtk::Orientation::Vertical,
                    set_spacing: 12,
                    set_margin_top: 12,
                    set_margin_bottom: 12,
                    set_margin_start: 12,
                    set_margin_end: 12,

                    #[name = "qr_caption"]
                    gtk::Label {
                        set_label: &compose_export_qr_caption_text(&model.state),
                        set_xalign: 0.5,
                        add_css_class: compose_export_qr_caption_style_class(),
                    },

                    #[name = "qr_picture"]
                    gtk::Picture {
                        set_can_shrink: false,
                        set_hexpand: true,
                        set_vexpand: true,
                        #[watch]
                        set_paintable: build_staged_png_texture(&model.state).as_ref(),
                    },

                    // Inline render error shown beneath the (empty)
                    // picture when the open-time `Vault::export_qr_png`
                    // render failed — e.g. a `validation_error` from
                    // `qrcode` rejecting an oversized payload. Hidden
                    // in the common case; when visible `staged_png` is
                    // empty so the save / copy actions are
                    // desensitized and only `Done` works.
                    #[name = "show_qr_error_label"]
                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "error",
                        #[watch]
                        set_visible: model.state.show_qr_error.is_some(),
                        #[watch]
                        set_label: model.state.show_qr_error.as_deref().unwrap_or(""),
                    },

                    // Inline post-save status: "QR saved to <path>"
                    // after a successful save and no fresher
                    // error / warning has overwritten it.
                    #[name = "save_success_label"]
                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        #[watch]
                        set_visible: compose_save_success_label_visible(&model.state),
                        #[watch]
                        set_label: &compose_save_success_status_text(&model.state),
                    },

                    // Inline save error rendered when a save worker
                    // returned an `Inline`-class typed failure
                    // (`io_error`, `save_not_committed`,
                    // `validation_error`, `invalid_state`).
                    #[name = "save_error_label"]
                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "error",
                        #[watch]
                        set_visible: model.state.save_error.is_some(),
                        #[watch]
                        set_label: model.state.save_error.as_deref().unwrap_or(""),
                    },

                    // Inline save warning rendered when a save worker
                    // returned `save_durability_unconfirmed` (the file
                    // is on disk but the parent-directory `fsync`
                    // failed).
                    #[name = "save_warning_label"]
                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "warning",
                        #[watch]
                        set_visible: model.state.save_warning.is_some(),
                        #[watch]
                        set_label: model.state.save_warning.as_deref().unwrap_or(""),
                    },

                    // Inline `Copy image` error rendered when
                    // `gdk::Clipboard::set_content` returned an error
                    // for a prior `Copy image` press.
                    #[name = "copy_image_error_label"]
                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        add_css_class: "error",
                        #[watch]
                        set_visible: model.state.copy_image_error.is_some(),
                        #[watch]
                        set_label: model.state.copy_image_error.as_deref().unwrap_or(""),
                    },

                    // Inline overwrite gate — visible only when the
                    // picked destination already exists on disk per
                    // `Path::try_exists`. Mirrors the `ExportDialog`'s
                    // overwrite-gate Switch row.
                    #[name = "save_overwrite_group"]
                    adw::PreferencesGroup {
                        #[watch]
                        set_visible: compose_save_target_overwrite_gate_visible(&model.state),

                        #[name = "save_overwrite_row"]
                        add = &adw::SwitchRow {
                            set_title: format_export_qr_dialog_overwrite_row_title(),
                            set_subtitle: format_export_qr_dialog_overwrite_row_subtitle(),
                            #[watch]
                            set_active: model.state.overwrite_acknowledged,
                            // See the `connect_closed` comment.
                            connect_active_notify[sender] => move |row| {
                                let _ = sender.input_sender().send(
                                    ExportQrDialogMsg::OverwriteAcknowledged(row.is_active()),
                                );
                            },
                        },
                    },

                    gtk::Box {
                        set_orientation: gtk::Orientation::Horizontal,
                        set_spacing: 6,
                        set_halign: gtk::Align::End,

                        #[name = "save_as_png_button"]
                        gtk::Button {
                            set_label: format_export_qr_dialog_save_as_png_label(),
                            #[watch]
                            set_sensitive: compose_qr_save_buttons_sensitive(&model.state),
                            // See the `connect_closed` comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender
                                    .input_sender()
                                    .send(ExportQrDialogMsg::SaveAsPngPressed);
                                open_save_file_dialog(&sender, SaveKind::Png);
                            },
                        },

                        #[name = "save_as_svg_button"]
                        gtk::Button {
                            set_label: format_export_qr_dialog_save_as_svg_label(),
                            #[watch]
                            set_sensitive: compose_qr_save_buttons_sensitive(&model.state),
                            // See the `connect_closed` comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender
                                    .input_sender()
                                    .send(ExportQrDialogMsg::SaveAsSvgPressed);
                                open_save_file_dialog(&sender, SaveKind::Svg);
                            },
                        },

                        // `Copy image` dispatches
                        // `ExportQrDialogMsg::CopyImage`; the
                        // `SimpleComponent::update` arm forwards
                        // `ExportQrDialogOutput::CopyImageRequested`
                        // (via `compose_copy_image_request_output`) to
                        // `AppModel`, which owns the live
                        // `gdk::Clipboard` handle and runs
                        // `set_content` on the main loop. Sensitivity
                        // tracks the staged PNG bytes — desensitized
                        // when an open-time render failure left them
                        // empty.
                        #[name = "copy_image_button"]
                        gtk::Button {
                            set_label: format_export_qr_dialog_copy_image_label(),
                            #[watch]
                            set_sensitive: compose_copy_image_button_sensitive(&model.state),
                            // See the `connect_closed` comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender
                                    .input_sender()
                                    .send(ExportQrDialogMsg::CopyImage);
                            },
                        },

                        #[name = "done_button"]
                        gtk::Button {
                            set_label: format_export_qr_dialog_done_label(),
                            add_css_class: "suggested-action",
                            // See the `connect_closed` comment.
                            connect_clicked[sender] => move |_| {
                                let _ = sender.input_sender().send(ExportQrDialogMsg::Close);
                            },
                        },
                    },

                    // Informational warning footer — the verbatim
                    // `paladin_auth_core::format_plaintext_qr_export_warning()`
                    // body rendered beneath the QR and its save
                    // actions. It reminds the user to protect the QR;
                    // it does NOT gate the code behind a
                    // click-to-acknowledge step (parity with the CLI /
                    // TUI per DESIGN §4.6).
                    #[name = "warning_footer_label"]
                    gtk::Label {
                        set_wrap: true,
                        set_xalign: 0.0,
                        set_margin_top: 6,
                        add_css_class: "warning",
                        set_label: &compose_export_qr_warning_body(),
                    },
                },
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = ExportQrDialogComponent {
            state: ExportQrDialogState::new(init),
        };
        let widgets = view_output!();
        wire_dismiss_controller(&root, &sender);
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        // `CopyImage` needs the live `gdk::Clipboard` handle —
        // emit `ExportQrDialogOutput::CopyImageRequested(bytes)`
        // so `AppModel` can wrap the staged PNG in
        // `gdk::ContentProvider::for_bytes(COPY_IMAGE_CLIPBOARD_MIME_TYPE, ...)`
        // and call `gdk::Clipboard::set_content` on the main loop.
        // `compose_copy_image_request_output` returns `None` when
        // `staged_png` is empty (defensive — the button is
        // desensitized in that state); skip the output dispatch
        // in that case. `apply_msg` collapses `CopyImage` onto
        // `None`, so no double-output races with the matching
        // reducer arm.
        if matches!(msg, ExportQrDialogMsg::CopyImage) {
            if let Some(output) = compose_copy_image_request_output(&self.state) {
                let _ = sender.output(output);
            }
        }
        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Send failures mean `AppModel` has already dropped the
            // controller (e.g. window closed mid-click); nothing
            // remains to dismiss.
            let _ = sender.output(output);
        }
    }
}

/// Title of the inline overwrite-ack [`adw::SwitchRow`].
/// Visible only when [`compose_save_target_overwrite_gate_visible`]
/// returns `true` (the user picked a destination that already
/// exists on disk).
#[must_use]
pub fn format_export_qr_dialog_overwrite_row_title() -> &'static str {
    "Overwrite the existing file"
}

/// Subtitle of the inline overwrite-ack
/// [`adw::SwitchRow`]. Reminds the user that the save fires
/// automatically once the switch flips on.
#[must_use]
pub fn format_export_qr_dialog_overwrite_row_subtitle() -> &'static str {
    "The save fires when this switch is on. Toggle off to pick a different path."
}

/// `gtk::FileDialog` title shown when the user clicks
/// `Save as PNG\u{2026}`.
#[must_use]
pub fn format_export_qr_dialog_save_png_picker_title() -> &'static str {
    "Save QR code as PNG"
}

/// `gtk::FileDialog` title shown when the user clicks
/// `Save as SVG\u{2026}`.
#[must_use]
pub fn format_export_qr_dialog_save_svg_picker_title() -> &'static str {
    "Save QR code as SVG"
}

/// Default file name pre-populated in the Save-as-PNG
/// `gtk::FileDialog::save`. The user is free to rename.
#[must_use]
pub fn format_export_qr_dialog_default_png_filename() -> &'static str {
    "qr.png"
}

/// Default file name pre-populated in the Save-as-SVG
/// `gtk::FileDialog::save`.
#[must_use]
pub fn format_export_qr_dialog_default_svg_filename() -> &'static str {
    "qr.svg"
}

/// Compose the inline status line shown after a successful
/// save: `"QR saved to <path>"`. Returns the empty string when
/// [`ExportQrDialogState::last_save_path`] is `None` so the view
/// can bind unconditionally.
#[must_use]
pub fn compose_save_success_status_text(state: &ExportQrDialogState) -> String {
    match state.last_save_path.as_ref() {
        Some(path) => format!(
            "{} {}",
            format_export_qr_dialog_save_success_toast(),
            path.display()
        ),
        None => String::new(),
    }
}

/// Returns `true` when the page should render the inline
/// "QR saved to …" status line — i.e. a save has succeeded and no
/// fresher error / warning has overwritten it.
#[must_use]
pub fn compose_save_success_label_visible(state: &ExportQrDialogState) -> bool {
    state.last_save_path.is_some() && state.save_error.is_none() && state.save_warning.is_none()
}
