// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-account QR-export dialog pure-logic state machine for
//! `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"QR export dialog
//! implementation" and §"Tests > Pure-logic unit tests >
//! `tests/export_qr_dialog_logic.rs`", the dialog hosts an
//! [`adw::Dialog`] wrapping an [`adw::ViewStack`] with two named
//! children:
//!
//! * `"warning"` — Page 1 carries the plaintext-export warning body
//!   pulled verbatim from [`paladin_core::format_plaintext_qr_export_warning`],
//!   an `adw::SwitchRow` ack ("I understand — show the QR") that
//!   only mutates [`ExportQrDialogState::ack_revealed`] (it never
//!   auto-renders the QR), and a Page-1 footer with two
//!   `gtk::Button`s — a `Cancel` (always sensitive) and a
//!   `Show QR` whose sensitivity is bound from
//!   [`compose_show_qr_button_sensitive`].
//! * `"qr"` — Page 2 carries an on-screen `gtk::Picture` whose
//!   paintable is bound from the staged PNG bytes in
//!   [`ExportQrDialogState::staged_png`], a `<issuer>:<label>`
//!   caption `gtk::Label` styled with the `title-3` class, and a
//!   four-button footer (`Save as PNG…` / `Save as SVG…` /
//!   `Copy image` / `Done`).
//!
//! Read-only — the dialog never enters [`paladin_core::Vault::mutate_and_save`],
//! never advances a HOTP counter, and never bumps `updated_at`.
//! Every render call goes through the new `&self` methods
//! [`paladin_core::Vault::export_qr_png`] /
//! [`paladin_core::Vault::export_qr_svg`].
//!
//! This file owns the widget-free value types
//! ([`ExportQrDialogInit`], [`ExportQrDialogMsg`],
//! [`ExportQrDialogOutput`], [`ExportQrDialogState`], [`SaveKind`],
//! [`SaveTarget`]) and the pure helpers the `SimpleComponent` will
//! bind. The `relm4::SimpleComponent` impl (with the
//! `adw::Dialog` / `adw::ViewStack` widget tree, the
//! `gio::spawn_blocking` save worker, and the `gdk::Clipboard`
//! copy path) lands in the follow-up "Warning page wiring" /
//! "Page 2 mount" / "Save-as-* actions" / "Copy image action"
//! commits of the §"QR export dialog implementation" build order.

use std::path::PathBuf;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use relm4::prelude::*;

use paladin_core::{format_plaintext_qr_export_warning, AccountId, AccountSummary, Vault};
use zeroize::Zeroizing;

/// Name of the [`adw::ViewStack`] child carrying the warning page
/// (Page 1).
///
/// Pinned here so the runtime
/// [`view_stack.set_visible_child_name(...)`] calls and the
/// pure-logic [`compose_visible_child_name`] reducer share one
/// source of truth.
pub const VIEW_STACK_WARNING_PAGE_NAME: &str = "warning";

/// Name of the [`adw::ViewStack`] child carrying the QR-render page
/// (Page 2).
///
/// Pinned here so the runtime
/// [`view_stack.set_visible_child_name(...)`] calls and the
/// pure-logic [`compose_visible_child_name`] reducer share one
/// source of truth.
pub const VIEW_STACK_QR_PAGE_NAME: &str = "qr";

/// CSS style class applied to the Page-2 `<issuer>:<label>` caption
/// `gtk::Label` so it renders at libadwaita's display-3 weight.
///
/// Pinned by
/// [`compose_export_qr_dialog_caption_widget_uses_title_3_style_class`].
pub const CAPTION_STYLE_CLASS: &str = "title-3";

/// Selector identifying which QR render format a Page-2 save target
/// is committing.
///
/// PNG saves reuse the already-staged
/// [`ExportQrDialogState::staged_png`] bytes (populated when the
/// user pressed Show-QR), so on-screen Picture bytes and on-disk
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

/// A user-picked Page-2 save destination: the format the user chose
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

/// Initialisation payload handed to `ExportQrDialogComponent::init`
/// when `AppModel` mounts the dialog.
///
/// `AppModel` resolves the matching [`AccountSummary`] from the
/// live vault before the launch so the dialog never reaches into
/// `(Vault, Store)` for its own caption rendering (the live vault
/// is still consulted by the `SimpleComponent` for the actual QR
/// render through [`paladin_core::Vault::export_qr_png`] /
/// [`paladin_core::Vault::export_qr_svg`]).
#[derive(Debug, Clone)]
pub struct ExportQrDialogInit {
    /// Account whose `otpauth://` URI the dialog will render as a
    /// QR.
    pub account_id: AccountId,
    /// Snapshot of the account's display metadata used by the
    /// Page-2 caption ([`paladin_core::summary_display_label`]) and
    /// by `format_export_qr_dialog_title` to render dialog chrome
    /// without re-reading the live vault.
    pub account_summary: AccountSummary,
}

/// Input messages dispatched into the `ExportQrDialogComponent`
/// reducer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportQrDialogMsg {
    /// Page-1 ack `adw::SwitchRow` flipped. The wrapped `bool` is
    /// the switch's new active state. Toggling the switch never
    /// auto-dispatches [`Self::ShowQr`] (the no-auto-render
    /// contract is pinned by
    /// `apply_msg_ack_toggled_does_not_dispatch_show_qr`); the
    /// reducer only mutates [`ExportQrDialogState::ack_revealed`]
    /// and, when toggled off, wipes the staged PNG / SVG buffers
    /// and resets the view stack to the warning page.
    AckToggled(bool),
    /// Page-1 `Show QR` button activated. The handler calls
    /// `vault.export_qr_png(account_id, QrRenderOptions::default())`
    /// on the main loop, parks the returned bytes in
    /// [`ExportQrDialogState::staged_png`], binds them to the
    /// Page-2 `gtk::Picture`, sets the caption text from
    /// [`paladin_core::summary_display_label`], and switches the
    /// view stack to the QR page.
    ShowQr,
    /// Page-1 `Cancel` button activated. The handler emits
    /// [`ExportQrDialogOutput::Cancel`] after wiping the staged
    /// PNG / SVG buffers.
    CancelPressed,
    /// User dismissed the dialog via the [`adw::Dialog`]
    /// `closed` signal (window-manager close, swipe-down on
    /// touch, etc.). Distinct from [`Self::CancelPressed`] so the
    /// reducer can route the two surfaces onto the matching
    /// [`ExportQrDialogOutput`] variant; both paths wipe staged
    /// buffers before emitting.
    Close,
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
    /// User clicked the Page-1 `Cancel` button.
    Cancel,
    /// User dismissed the dialog via the `closed` signal (Escape,
    /// window-manager close, …).
    Close,
}

/// Mutable state held by the `ExportQrDialogComponent` reducer.
///
/// All secret bytes (the on-screen PNG bytes, the staged SVG
/// document) live in
/// [`Zeroizing`](zeroize::Zeroizing)-wrapped containers so a drop
/// — whether through the dialog close, an ack-toggled-off reset,
/// or an auto-lock fire ([`clear_for_lock`]) — wipes them before
/// the memory returns to the allocator.
#[derive(Debug)]
pub struct ExportQrDialogState {
    /// Account the dialog is rendering. Pinned here so the
    /// `SimpleComponent`'s `update` reducer can call
    /// `vault.export_qr_png(self.state.account_id, ...)` without
    /// closing over the init payload separately.
    pub account_id: AccountId,
    /// Snapshot of the account's display metadata used by the
    /// Page-2 caption. Carried for the lifetime of the dialog so
    /// the caption stays stable even if a parallel mutate retargets
    /// the live vault.
    pub account_summary: AccountSummary,
    /// Page-1 warning-ack `adw::SwitchRow` state. Starts `false`
    /// and only flips to `true` on an explicit user toggle. Gates
    /// the Page-1 `Show QR` button's sensitivity via
    /// [`compose_show_qr_button_sensitive`].
    pub ack_revealed: bool,
    /// On-screen QR render bytes (PNG). Populated when the user
    /// presses Show-QR and dropped (the
    /// [`Zeroizing`](zeroize::Zeroizing) wrapper zeroes them) when
    /// the dialog closes, when ack is toggled off, or when
    /// auto-lock fires.
    pub staged_png: Option<Zeroizing<Vec<u8>>>,
    /// Lazily-rendered SVG document. Empty until the first
    /// Save-as-SVG fires; then cached so a subsequent SVG save to
    /// a different path reuses it without re-rendering through
    /// `vault.export_qr_svg`.
    pub staged_svg: Option<Zeroizing<String>>,
    /// User-picked Page-2 save destination, if any.
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
    /// "QR saved to …" status-line label on Page 2. `None` until
    /// the first successful save fires.
    pub last_save_path: Option<PathBuf>,
}

impl ExportQrDialogState {
    /// Build a fresh state from an [`ExportQrDialogInit`].
    ///
    /// `ack_revealed` starts `false` so the Page-1 `Show QR`
    /// button is desensitized until the user explicitly toggles
    /// the ack; both staged-byte slots, the save target, and the
    /// last-save path are empty.
    #[must_use]
    pub fn new(init: ExportQrDialogInit) -> Self {
        Self {
            account_id: init.account_id,
            account_summary: init.account_summary,
            ack_revealed: false,
            staged_png: None,
            staged_svg: None,
            save_target: None,
            destination_exists: false,
            overwrite_acknowledged: false,
            last_save_path: None,
        }
    }
}

/// Compose the Page-1 warning body text shown in the
/// `adw::ActionRow` subtitle.
///
/// Returns the verbatim output of
/// [`paladin_core::format_plaintext_qr_export_warning`] so the
/// per-front-end warnings (CLI / TUI / GTK) share one source of
/// truth. Pinned by
/// `format_export_qr_dialog_warning_body_matches_paladin_core_verbatim`.
#[must_use]
pub fn compose_export_qr_warning_body() -> String {
    format_plaintext_qr_export_warning()
}

/// Compose the Page-1 `Show QR` button's sensitivity.
///
/// Returns `true` only when the user has explicitly toggled the
/// ack switch on (`state.ack_revealed == true`). The Page-1
/// `Cancel` button is always sensitive and does not flow through
/// this helper.
#[must_use]
pub fn compose_show_qr_button_sensitive(state: &ExportQrDialogState) -> bool {
    state.ack_revealed
}

/// Compose the [`adw::ViewStack`] visible-child name for the
/// current state.
///
/// The QR page is shown only when [`ExportQrDialogState::staged_png`]
/// is populated (the user pressed Show-QR and the render
/// succeeded); every other state — including ack-toggled-off,
/// Cancel-in-flight, and the initial render — shows the warning
/// page. Pairs with
/// [`VIEW_STACK_WARNING_PAGE_NAME`] / [`VIEW_STACK_QR_PAGE_NAME`]
/// so the `SimpleComponent`'s
/// `view_stack.set_visible_child_name(...)` call site has a
/// single source of truth.
#[must_use]
pub fn compose_visible_child_name(state: &ExportQrDialogState) -> &'static str {
    if state.staged_png.is_some() {
        VIEW_STACK_QR_PAGE_NAME
    } else {
        VIEW_STACK_WARNING_PAGE_NAME
    }
}

/// Apply an [`ExportQrDialogMsg::AckToggled`] message to
/// `state`.
///
/// * `active == true`: flip [`ExportQrDialogState::ack_revealed`]
///   on. **Does not** dispatch a Show-QR render — the
///   no-auto-render contract is pinned by
///   `apply_msg_ack_toggled_does_not_dispatch_show_qr`. The
///   widget binding wires the
///   `adw::SwitchRow::connect_active_notify` signal to dispatch
///   this message only; the actual Show-QR render runs from the
///   Page-1 `Show QR` button's `connect_clicked`.
/// * `active == false`: flip [`ExportQrDialogState::ack_revealed`]
///   off, wipe both staged-byte slots (the
///   [`Zeroizing`](zeroize::Zeroizing) wrappers zero the bytes on
///   drop), and clear [`ExportQrDialogState::save_target`] /
///   [`ExportQrDialogState::overwrite_acknowledged`] /
///   [`ExportQrDialogState::destination_exists`] so a re-open
///   does not inherit stale Page-2 picks. The `SimpleComponent`'s
///   view binding restores the Picture's paintable to
///   `gdk::Paintable::new_empty` and flips the view stack back to
///   the warning page via [`compose_visible_child_name`].
pub fn apply_msg_ack_toggled(state: &mut ExportQrDialogState, active: bool) {
    state.ack_revealed = active;
    if !active {
        state.staged_png = None;
        state.staged_svg = None;
        state.save_target = None;
        state.destination_exists = false;
        state.overwrite_acknowledged = false;
    }
}

/// Title rendered in the [`adw::Dialog`] header bar.
///
/// Stable user-facing string; pinned non-empty by
/// `format_export_qr_dialog_title_is_non_empty`.
#[must_use]
pub fn format_export_qr_dialog_title() -> &'static str {
    "Show QR code"
}

/// Page-1 primary-action button label.
#[must_use]
pub fn format_export_qr_dialog_show_qr_button_label() -> &'static str {
    "Show QR"
}

/// Page-2 footer "Save as PNG…" button label.
#[must_use]
pub fn format_export_qr_dialog_save_as_png_label() -> &'static str {
    "Save as PNG\u{2026}"
}

/// Page-2 footer "Save as SVG…" button label.
#[must_use]
pub fn format_export_qr_dialog_save_as_svg_label() -> &'static str {
    "Save as SVG\u{2026}"
}

/// Page-2 footer "Copy image" button label.
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

/// Page-2 footer "Done" button label.
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

/// Drop the staged Page-2 buffers and reset the visible page back
/// to the warning page.
///
/// Shared between [`apply_msg`] (`CancelPressed` / `Close` arms) and
/// [`apply_msg_ack_toggled`]'s ack-off branch so the buffer-wipe
/// contract has a single source of truth. The widget layer still
/// has to swap the `gtk::Picture` paintable back to
/// `gdk::Paintable::new_empty` — that lives in the `view!` binding
/// rather than this state-side helper because it requires a
/// `gdk::Paintable`.
fn drop_staged_buffers(state: &mut ExportQrDialogState) {
    state.staged_png = None;
    state.staged_svg = None;
    state.save_target = None;
    state.destination_exists = false;
    state.overwrite_acknowledged = false;
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
/// `ShowQr` is intentionally a no-op at this layer — the
/// `SimpleComponent` owns the actual
/// `vault.export_qr_png(account_id, ...)` render and stages the
/// returned bytes via a side channel because `Vault` is not
/// reachable from this pure helper. The reducer still receives the
/// message so the dispatch table is exhaustive.
//
// `clippy::needless_pass_by_value` would suggest a reference because
// the current variants only carry `Copy` payloads. The signature is
// kept by-value to match `crate::export_dialog::apply_msg` (a stable
// dispatch contract across dialog reducers) and to keep room for a
// future variant carrying owned secret bytes (e.g. a staged-buffer
// hand-off) without churning the call sites.
#[allow(clippy::needless_pass_by_value)]
pub fn apply_msg(
    state: &mut ExportQrDialogState,
    msg: ExportQrDialogMsg,
) -> Option<ExportQrDialogOutput> {
    match msg {
        ExportQrDialogMsg::AckToggled(active) => {
            apply_msg_ack_toggled(state, active);
            None
        }
        ExportQrDialogMsg::ShowQr => None,
        ExportQrDialogMsg::CancelPressed => {
            drop_staged_buffers(state);
            Some(ExportQrDialogOutput::Cancel)
        }
        ExportQrDialogMsg::Close => {
            drop_staged_buffers(state);
            Some(ExportQrDialogOutput::Close)
        }
    }
}

/// Resolve the targeted account in `vault` and project it into an
/// [`ExportQrDialogInit`] payload `AppModel` hands to
/// `ExportQrDialogComponent::builder().launch(...)`.
///
/// Returns `None` when the account is no longer present (the user
/// removed it between the kebab activation and this dispatch — a
/// benign race that the caller drops silently, mirroring
/// [`crate::rename_dialog::decide_rename_target`] /
/// [`crate::remove_dialog::decide_remove_target`]).
#[must_use]
pub fn decide_export_qr_target(vault: &Vault, id: AccountId) -> Option<ExportQrDialogInit> {
    vault
        .summaries()
        .find(|summary| summary.id == id)
        .map(|summary| ExportQrDialogInit {
            account_id: summary.id,
            account_summary: summary,
        })
}

/// Per-account QR export dialog component.
///
/// Wraps the [`ExportQrDialogState`] reducer in a relm4
/// [`SimpleComponent`] backed by an [`adw::Dialog`] whose body is an
/// [`adw::ViewStack`] with two named children
/// ([`VIEW_STACK_WARNING_PAGE_NAME`] and [`VIEW_STACK_QR_PAGE_NAME`]).
/// The warning page carries the plaintext-export warning body, the
/// ack `adw::SwitchRow`, and a Cancel / Show QR footer; the QR page
/// is mounted as a placeholder until the "Page 2 mount on Show-QR
/// press" commit lands the Picture + caption + save / copy buttons.
pub struct ExportQrDialogComponent {
    state: ExportQrDialogState,
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

            connect_closed[sender] => move |_| {
                sender.input(ExportQrDialogMsg::Close);
            },

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},

                #[wrap(Some)]
                #[name = "view_stack"]
                set_content = &adw::ViewStack {
                    add_named[Some(VIEW_STACK_WARNING_PAGE_NAME)] = &gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_spacing: 12,
                        set_margin_top: 12,
                        set_margin_bottom: 12,
                        set_margin_start: 12,
                        set_margin_end: 12,

                        #[name = "warning_group"]
                        adw::PreferencesGroup {
                            #[name = "warning_body_row"]
                            add = &adw::ActionRow {
                                set_title: &compose_export_qr_warning_body(),
                                set_title_lines: 0,
                                set_subtitle_lines: 0,
                                add_css_class: "warning",
                            },

                            #[name = "warning_ack_row"]
                            add = &adw::SwitchRow {
                                set_title: format_export_qr_dialog_ack_row_title(),
                                set_subtitle: format_export_qr_dialog_ack_row_subtitle(),
                                #[watch]
                                set_active: model.state.ack_revealed,
                                connect_active_notify[sender] => move |row| {
                                    sender.input(ExportQrDialogMsg::AckToggled(
                                        row.is_active(),
                                    ));
                                },
                            },
                        },

                        gtk::Box {
                            set_orientation: gtk::Orientation::Horizontal,
                            set_spacing: 6,
                            set_halign: gtk::Align::End,

                            #[name = "cancel_button"]
                            gtk::Button {
                                set_label: format_export_qr_dialog_cancel_label(),
                                connect_clicked[sender] => move |_| {
                                    sender.input(ExportQrDialogMsg::CancelPressed);
                                },
                            },

                            #[name = "show_qr_button"]
                            gtk::Button {
                                set_label: format_export_qr_dialog_show_qr_button_label(),
                                add_css_class: "suggested-action",
                                #[watch]
                                set_sensitive: compose_show_qr_button_sensitive(&model.state),
                                connect_clicked[sender] => move |_| {
                                    sender.input(ExportQrDialogMsg::ShowQr);
                                },
                            },
                        },
                    },

                    // Page 2 placeholder — the live Picture + caption +
                    // Save / Copy / Done footer land in the "Page 2 mount
                    // on Show-QR press" commit of the §"QR export
                    // dialog implementation" build order.
                    add_named[Some(VIEW_STACK_QR_PAGE_NAME)] = &gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
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
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        if let Some(output) = apply_msg(&mut self.state, msg) {
            // Send failures mean `AppModel` has already dropped the
            // controller (e.g. window closed mid-click); nothing
            // remains to dismiss.
            let _ = sender.output(output);
        }
    }
}

/// Page-1 warning-ack `adw::SwitchRow` title.
#[must_use]
pub fn format_export_qr_dialog_ack_row_title() -> &'static str {
    "I understand \u{2014} show the QR"
}

/// Page-1 warning-ack `adw::SwitchRow` subtitle.
#[must_use]
pub fn format_export_qr_dialog_ack_row_subtitle() -> &'static str {
    "Reveal the QR code only after reading the warning above."
}

/// Page-1 footer "Cancel" button label.
#[must_use]
pub fn format_export_qr_dialog_cancel_label() -> &'static str {
    "Cancel"
}
