// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AccountRowComponent` pure-logic projection for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountRowComponent`, each row in `AccountListComponent`'s
//! `gtk::ListView` shows the `<issuer>:<label>` display string, the
//! current code (or a hidden placeholder for HOTP rows that have
//! not been revealed), a TOTP progress indicator or HOTP "next"
//! button, a copy button, and a kebab menu. This module owns the
//! pure-logic shadow widgets bind to, so the row-factory routing
//! rules are exercised in `tests/account_row_logic.rs` without
//! spinning up GTK / libadwaita.
//!
//! The functions here are widget-free and `(Vault, Store)`-free —
//! the widget layer threads the live [`Code`] (computed externally
//! by `Vault::totp_code` per tick or by the active HOTP reveal)
//! through [`project_row`] and binds the resulting [`RowDisplay`]
//! to the row's children.
//!
//! Display-label rendering matches the CLI / TUI body shape: an
//! issuer of `Some(non_empty)` renders as `<issuer>:<label>`;
//! everything else (`None` or `Some("")`) renders as the bare
//! `<label>` so the body never carries a dangling `:label` colon.
//! [`summary_display_label`] is the canonical helper for this rule;
//! [`crate::remove_dialog::summary_display_label`] re-exports it so
//! the row factory and the `RemoveDialog` body share one source of
//! truth.
//!
//! Copy / "next" gating follows the plan §"Component tree" >
//! `AccountRowComponent` rules:
//!
//! * TOTP rows expose the progress indicator and never the
//!   "next" button; copy is always enabled.
//! * HOTP rows expose the "next" button and never the progress
//!   indicator; copy is enabled only while a visible reveal
//!   [`Code`] is in hand.
//!
//! Counter rendering tracks the same hidden / revealed split:
//! hidden HOTP rows show the stored `AccountSummary.counter`
//! ([`CounterText::Stored`]); during reveal the row shows the
//! `Code.counter_used` that produced the visible code
//! ([`CounterText::Used`]). TOTP rows render no counter.

use relm4::factory::{DynamicIndex, FactoryComponent, FactorySender};
use relm4::gtk;
use relm4::gtk::gio;
use relm4::gtk::prelude::*;
use relm4::Sender;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Code};

use crate::icon_resolution::{resolve_display_icon, PLACEHOLDER_ICON_NAME};

/// Horizontal spacing (in pixels) between cells of one row and of
/// the column-header strip.  Shared so [`build_row_widget`] and
/// [`build_column_header_strip`] cannot drift.
pub const ROW_COLUMN_SPACING: i32 = 12;

/// Display title for the "Account" column in the column-header
/// strip.  Pure-string accessor so unit tests in
/// `tests/account_row_logic.rs` can pin the wording without
/// constructing widgets.
#[must_use]
pub fn format_account_column_title() -> &'static str {
    "Account"
}

/// Display title for the "Code" column in the column-header strip.
#[must_use]
pub fn format_code_column_title() -> &'static str {
    "Code"
}

/// Render the row's display-label string.
///
/// Returns `<issuer>:<label>` when `summary.issuer` is
/// `Some(non_empty)` and the bare `<label>` otherwise (CLI / TUI
/// parity; `Some("")` collapses to the no-issuer form so the row
/// never renders `:label`).
///
/// Canonical helper for the row's `<issuer>:<label>` body shape;
/// [`crate::remove_dialog::summary_display_label`] re-exports this
/// function so the list row and the `RemoveDialog` confirmation body
/// never drift.
#[must_use]
pub fn summary_display_label(summary: &AccountSummary) -> String {
    match summary.issuer.as_deref().filter(|i| !i.is_empty()) {
        Some(issuer) => format!("{issuer}:{}", summary.label),
        None => summary.label.clone(),
    }
}

/// Whether the row exposes its "next" button.
///
/// HOTP rows always expose the button (activating it advances the
/// counter and opens the shared reveal window — see
/// [`crate::hotp_reveal`]); TOTP rows never do.
#[must_use]
pub fn next_button_visible(kind: AccountKindSummary) -> bool {
    matches!(kind, AccountKindSummary::Hotp)
}

/// Whether the row exposes its TOTP progress indicator.
///
/// TOTP rows always expose the indicator (driven by
/// [`Code::seconds_remaining`]); HOTP rows never do.
#[must_use]
pub fn progress_visible(kind: AccountKindSummary) -> bool {
    matches!(kind, AccountKindSummary::Totp)
}

/// Whether the row exposes its kebab `MenuButton`.
///
/// Every row exposes the kebab (Rename… / Remove…) unconditionally
/// per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`. The kind argument is taken so the helper
/// reads symmetrically alongside [`next_button_visible`] /
/// [`progress_visible`]; the projection itself does not depend on it.
#[must_use]
pub fn kebab_visible(_kind: AccountKindSummary) -> bool {
    true
}

/// Intrinsic clickability of the row's "next" button.
///
/// Mirrors [`next_button_visible`] (HOTP rows only — TOTP rows have
/// no "next" affordance), exposed as a distinct projection so the
/// per-component busy mask in [`apply_busy_mask`] can dim the
/// button while `AppModel` is `UnlockedBusy` per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership"
/// without flipping the row's visibility.
#[must_use]
pub fn next_button_enabled(kind: AccountKindSummary) -> bool {
    matches!(kind, AccountKindSummary::Hotp)
}

/// Intrinsic clickability of the row's kebab `MenuButton`.
///
/// Always `true` for parity with [`kebab_visible`]; the busy mask in
/// [`apply_busy_mask`] dims it while `AppModel` is `UnlockedBusy`.
#[must_use]
pub fn kebab_enabled() -> bool {
    true
}

/// Whether the row's copy button is enabled.
///
/// TOTP rows: always enabled.
/// HOTP rows: enabled only while a visible reveal [`Code`] is in
/// hand. Copying a hidden HOTP row is explicitly disabled per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`.
#[must_use]
pub fn copy_enabled(kind: AccountKindSummary, has_visible_code: bool) -> bool {
    match kind {
        AccountKindSummary::Totp => true,
        AccountKindSummary::Hotp => has_visible_code,
    }
}

/// Clamp the three mutating-row affordances in a [`RowDisplay`] when
/// the parent `AppModel` is in `AppState::UnlockedBusy`.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership"
/// / §"Component tree" > `AccountRowComponent` ("Disable mutating row
/// controls (copy, 'next', kebab) while `AppModel` is `UnlockedBusy`"),
/// the row factory routes every binding through this mask so the
/// gating contract is uniform regardless of which effect is in
/// flight. When `busy == true`, `copy_enabled`, `next_button_enabled`,
/// and `kebab_enabled` collapse to `false`; visibility, the visible
/// code, the counter, and the progress projection are untouched so
/// the row keeps rendering what the user can already see while the
/// worker is in flight.
///
/// When `busy == false`, the mask is a no-op — the intrinsic
/// projections from [`project_row`] reach the widget layer unchanged.
pub fn apply_busy_mask(display: &mut RowDisplay, busy: bool) {
    if !busy {
        return;
    }
    display.copy_enabled = false;
    display.next_button_enabled = false;
    display.kebab_enabled = false;
}

/// HOTP counter text displayed alongside the row.
///
/// The widget binds this through a single label whose text shifts
/// between the stored next counter (when the reveal window is
/// closed) and the counter that produced the visible code (during
/// the reveal window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterText {
    /// Hidden HOTP row: show `AccountSummary.counter` (the next
    /// counter that will be used by the worker on "next").
    Stored(u64),
    /// Revealed HOTP row: show `Code.counter_used` (the counter
    /// the visible code was generated against, before the advance
    /// landed).
    Used(u64),
}

/// Compute the row's counter projection.
///
/// Returns `None` for TOTP rows (no counter widget). For HOTP rows:
///
/// * `visible_code = None` → [`CounterText::Stored`] of
///   `AccountSummary.counter` (defaulting to `0` if the summary
///   somehow carries a `None` counter — that shape never escapes
///   `paladin_core::Vault` validation today).
/// * `visible_code = Some(code)` → [`CounterText::Used`] of
///   `Code.counter_used` (defaulting to `0` if the code somehow
///   carries `None` — same defensive note).
#[must_use]
pub fn counter_display(
    summary: &AccountSummary,
    visible_code: Option<&Code>,
) -> Option<CounterText> {
    match summary.kind {
        AccountKindSummary::Totp => None,
        AccountKindSummary::Hotp => Some(match visible_code {
            Some(code) => CounterText::Used(code.counter_used.unwrap_or(0)),
            None => CounterText::Stored(summary.counter.unwrap_or(0)),
        }),
    }
}

/// Per-row TOTP gauge projection.
///
/// Carries the data the widget layer needs to drive a continuous
/// progress bar (or any equivalent indicator) without re-reading the
/// live `(Vault, Code)` pair on every bind. Only the period and the
/// remaining-seconds count cross the projection boundary, so the
/// gauge stays a pure-logic decision pinned by
/// `tests/account_row_logic.rs`.
///
/// HOTP rows never produce a [`ProgressDisplay`] — the per-tick
/// refresh skips them entirely and the row factory hides the bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressDisplay {
    /// TOTP period in seconds (from [`AccountSummary::period`]).
    pub period_secs: u32,
    /// Seconds remaining in the current TOTP window (from
    /// [`Code::seconds_remaining`]; `paladin_core` pins this to
    /// `1..=period_secs` per `crates/paladin-core/src/otp/totp.rs`).
    pub seconds_remaining: u32,
}

/// Compute the TOTP gauge projection for a row.
///
/// Returns `None` for HOTP rows and for TOTP rows that have no
/// visible [`Code`] yet (initial mount before the first per-tick
/// compute). Otherwise returns `Some(ProgressDisplay { … })` with
/// the row's period and the code's remaining-seconds count so the
/// widget layer can drive a continuous gauge through
/// [`progress_fraction`].
///
/// Defensive: a TOTP summary with `period: None` or a TOTP code with
/// `seconds_remaining: None` both yield `None` — `paladin_core` never
/// produces either shape today, but keeping the projection total lets
/// the row factory avoid `unwrap_or` patterns at bind time.
#[must_use]
pub fn progress_display(
    summary: &AccountSummary,
    visible_code: Option<&Code>,
) -> Option<ProgressDisplay> {
    match summary.kind {
        AccountKindSummary::Hotp => None,
        AccountKindSummary::Totp => {
            let period_secs = summary.period?;
            let seconds_remaining = visible_code?.seconds_remaining?;
            Some(ProgressDisplay {
                period_secs,
                seconds_remaining,
            })
        }
    }
}

/// Render a [`ProgressDisplay`] as a `gtk::ProgressBar` fraction
/// (in `0.0..=1.0`).
///
/// The fraction is `seconds_remaining / period_secs`, clamped to
/// `1.0` if `seconds_remaining > period_secs` (defensive — the
/// `paladin_core` invariant pins it to `1..=period`) and to `0.0`
/// when `period_secs == 0` (defensive — `paladin_core::validation`
/// rejects a zero period upstream). A full window renders a full
/// bar; one remaining second still renders the matching sliver.
///
/// Keeping this in pure logic so the gauge math is exercised by
/// `tests/account_row_logic.rs` without spinning up GTK.
#[must_use]
pub fn progress_fraction(progress: &ProgressDisplay) -> f64 {
    if progress.period_secs == 0 {
        return 0.0;
    }
    let remaining = progress.seconds_remaining.min(progress.period_secs);
    f64::from(remaining) / f64::from(progress.period_secs)
}

/// Adwaita CSS style classes [`bind_row`] toggles on the row's
/// `gtk::ProgressBar` to color the fill by remaining-window urgency.
///
/// Indexed by the [`ProgressUrgency`] variant order so [`bind_row`]
/// can wipe all three before adding the active one — the row never
/// carries a stale urgency class between binds.  Using Adwaita's
/// semantic classes (`success` / `warning` / `error`) rather than
/// hardcoded hex keeps the bar themable (light / dark / high-contrast)
/// and accessible.
pub const PROGRESS_URGENCY_CSS_CLASSES: [&str; 3] = ["success", "warning", "error"];

/// Urgency band of a TOTP gauge, used by [`bind_row`] to color the
/// row's `gtk::ProgressBar` fill.
///
/// Bands are absolute seconds-remaining rather than fractions of the
/// period — the user-visible meaning is "how much time you have to
/// read and copy the code," which is the same regardless of the
/// account's period.  TOTP accounts with periods shorter than a
/// threshold simply mount in the matching band.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgressUrgency {
    /// More than 15 seconds remain.  Renders via the Adwaita
    /// `.success` style class (green in default themes).
    Plenty,
    /// 6..=15 seconds remain.  Renders via the Adwaita `.warning`
    /// style class (yellow in default themes).
    Warning,
    /// 0..=5 seconds remain — the window is about to rotate.
    /// Renders via the Adwaita `.error` style class (red in default
    /// themes).
    Critical,
}

impl ProgressUrgency {
    /// Returns the Adwaita CSS style class that colors the
    /// `gtk::ProgressBar` fill for this urgency band.
    ///
    /// One of [`PROGRESS_URGENCY_CSS_CLASSES`]; the slice is the
    /// canonical wipe-set [`bind_row`] strips before adding the
    /// active class.
    #[must_use]
    pub fn css_class(self) -> &'static str {
        match self {
            Self::Plenty => PROGRESS_URGENCY_CSS_CLASSES[0],
            Self::Warning => PROGRESS_URGENCY_CSS_CLASSES[1],
            Self::Critical => PROGRESS_URGENCY_CSS_CLASSES[2],
        }
    }
}

/// Classify a [`ProgressDisplay`] into a [`ProgressUrgency`] band.
///
/// Thresholds, in seconds remaining (clamped to `period_secs` so a
/// defensively over-large `seconds_remaining` never escapes the
/// projection): `>15` → [`ProgressUrgency::Plenty`], `6..=15` →
/// [`ProgressUrgency::Warning`], `<=5` → [`ProgressUrgency::Critical`].
///
/// A zero `period_secs` clamps remaining to zero and lands in
/// [`ProgressUrgency::Critical`] defensively — `paladin_core::validation`
/// rejects a zero period upstream, so this path never fires in
/// practice but keeps the helper total.
#[must_use]
pub fn progress_urgency(progress: &ProgressDisplay) -> ProgressUrgency {
    let remaining = progress.seconds_remaining.min(progress.period_secs);
    if remaining > 15 {
        ProgressUrgency::Plenty
    } else if remaining > 5 {
        ProgressUrgency::Warning
    } else {
        ProgressUrgency::Critical
    }
}

/// Body for the row's code label.
///
/// The widget renders [`CodeDisplay::Hidden`] as the row's hidden
/// placeholder text and [`CodeDisplay::Visible`] as the cleartext
/// code. The string is owned so the row factory does not have to
/// borrow back into the projection on every binding update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeDisplay {
    /// No visible code — render the hidden placeholder. HOTP rows
    /// land here before "next" is activated and after the reveal
    /// window expires; TOTP rows land here defensively when the
    /// widget has not yet seen the first per-tick compute.
    Hidden,
    /// Cleartext code to display.
    Visible(String),
}

/// Compute the row's code projection.
///
/// Returns [`CodeDisplay::Visible`] whenever `visible_code` is
/// `Some` and [`CodeDisplay::Hidden`] otherwise. The kind argument
/// is taken so the function reads symmetrically alongside the
/// other helpers; the projection itself does not depend on it.
#[must_use]
pub fn code_display(_kind: AccountKindSummary, visible_code: Option<&Code>) -> CodeDisplay {
    match visible_code {
        Some(code) => CodeDisplay::Visible(code.code.clone()),
        None => CodeDisplay::Hidden,
    }
}

/// Bundle of every projection a row factory needs to bind a single
/// row's widgets.
///
/// Produced by [`project_row`]; the widget layer reads each field
/// into the corresponding child (label `gtk::Label`, code
/// `gtk::Label`, optional counter `gtk::Label`, copy `gtk::Button`,
/// progress `gtk::ProgressBar`, "next" `gtk::Button`). Carrying the
/// projections as a single struct means the row factory cannot
/// silently skip a helper and let the label / code / counter drift.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowDisplay {
    /// Result of [`summary_display_label`].
    pub label: String,
    /// Account kind (echoed back for downstream widget routing —
    /// HOTP rows reach for the "next" button, TOTP rows for the
    /// progress indicator).
    pub kind: AccountKindSummary,
    /// Result of [`code_display`].
    pub code: CodeDisplay,
    /// Result of [`counter_display`].
    pub counter: Option<CounterText>,
    /// Result of [`copy_enabled`]; dimmed by [`apply_busy_mask`] while
    /// `AppModel` is `UnlockedBusy`.
    pub copy_enabled: bool,
    /// Result of [`next_button_visible`].
    pub next_button_visible: bool,
    /// Result of [`next_button_enabled`]; dimmed by
    /// [`apply_busy_mask`] while `AppModel` is `UnlockedBusy`.
    pub next_button_enabled: bool,
    /// Result of [`progress_visible`].
    pub progress_visible: bool,
    /// Result of [`progress_display`]. `Some(_)` for TOTP rows once
    /// a visible code is in hand; `None` for HOTP rows and TOTP rows
    /// before the first per-tick compute. The widget layer feeds this
    /// through [`progress_fraction`] to drive the row's `gtk::ProgressBar`.
    pub progress: Option<ProgressDisplay>,
    /// Result of [`kebab_visible`].
    pub kebab_visible: bool,
    /// Result of [`kebab_enabled`]; dimmed by [`apply_busy_mask`]
    /// while `AppModel` is `UnlockedBusy`.
    pub kebab_enabled: bool,
}

/// Bundle every row projection together.
///
/// Composes [`summary_display_label`], [`code_display`],
/// [`counter_display`], [`copy_enabled`], [`next_button_visible`],
/// [`next_button_enabled`], [`progress_visible`], [`kebab_visible`],
/// and [`kebab_enabled`] into a [`RowDisplay`]. The widget layer
/// reads `Some(&Code)` from either the TOTP per-tick compute slot or
/// the HOTP reveal slot and passes it through; the helpers all
/// agree on `None ⇒ hidden`.
///
/// The returned [`RowDisplay`] carries the *intrinsic* enabled state
/// for the three mutating-row controls; the widget layer routes it
/// through [`apply_busy_mask`] before binding so the
/// `UnlockedBusy` gating contract from `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"In-flight effect ownership" stays a single hook.
#[must_use]
pub fn project_row(summary: &AccountSummary, visible_code: Option<&Code>) -> RowDisplay {
    let has_visible_code = visible_code.is_some();
    RowDisplay {
        label: summary_display_label(summary),
        kind: summary.kind,
        code: code_display(summary.kind, visible_code),
        counter: counter_display(summary, visible_code),
        copy_enabled: copy_enabled(summary.kind, has_visible_code),
        next_button_visible: next_button_visible(summary.kind),
        next_button_enabled: next_button_enabled(summary.kind),
        progress_visible: progress_visible(summary.kind),
        progress: progress_display(summary, visible_code),
        kebab_visible: kebab_visible(summary.kind),
        kebab_enabled: kebab_enabled(),
    }
}

/// Name of the per-row [`gio::SimpleActionGroup`] installed on each
/// row container.
///
/// Must match the prefix used by [`build_kebab_menu_model`] for the
/// `row.rename` / `row.remove` menu targets — otherwise the kebab
/// items dispatch into the void at activation time.
pub const ROW_ACTION_GROUP_NAME: &str = "row";

/// Action name within [`ROW_ACTION_GROUP_NAME`] that opens the
/// `RenameDialog` for the row's account.
pub const ROW_RENAME_ACTION_NAME: &str = "rename";

/// Action name within [`ROW_ACTION_GROUP_NAME`] that opens the
/// `RemoveDialog` for the row's account.
pub const ROW_REMOVE_ACTION_NAME: &str = "remove";

/// Action name within [`ROW_ACTION_GROUP_NAME`] activated by the
/// HOTP row's "next" button.
pub const ROW_NEXT_ACTION_NAME: &str = "next";

/// Action name within [`ROW_ACTION_GROUP_NAME`] activated by the
/// per-row copy `gtk::Button`.
pub const ROW_COPY_ACTION_NAME: &str = "copy";

/// Construction parameters for [`AccountRowComponent`].
///
/// Carries everything the row needs to render itself for the first
/// frame without consulting the parent: the stable [`AccountId`] for
/// its action group, the intrinsic [`RowDisplay`] the parent has
/// already projected (cache hit or [`crate::account_list::hidden_row_display`]
/// fallback), the optional icon-hint slug, and the parent's current
/// busy flag. The row applies the busy mask on top of
/// `initial_display` itself, so the parent does not have to fork its
/// projection per row.
#[derive(Debug, Clone)]
pub struct AccountRowInit {
    /// Stable account identifier the row's kebab + copy + "next"
    /// dispatches carry back up through [`AccountRowOutput`].
    pub account_id: AccountId,
    /// Intrinsic per-row display the row binds at mount time, before
    /// applying the busy mask. Typically the cache hit from the most
    /// recent [`crate::ticker::tick`] or
    /// [`crate::account_list::hidden_row_display`] for a row that
    /// has not yet ticked.
    pub initial_display: RowDisplay,
    /// Icon-hint slug from the row's
    /// [`crate::account_list::AccountRowModel::icon_hint`]. `None` /
    /// empty / unresolved slugs fall back to
    /// [`PLACEHOLDER_ICON_NAME`] through [`bind_row_icon`].
    pub initial_icon_hint: Option<String>,
    /// Parent's `AppState::is_busy()` value at mount time. The row
    /// applies the busy mask via [`apply_busy_mask`] on top of
    /// `initial_display` before binding.
    pub initial_busy: bool,
    /// Per-column [`gtk::SizeGroup`] bundle the row registers its
    /// children with so the column-header strip
    /// ([`build_column_header_strip`]) stays aligned with the row's
    /// cells.  Cloning is cheap — each member is a `GObject`-
    /// reference count bump that shares the same backing
    /// [`gtk::SizeGroup`] across every row + the header strip.
    pub column_size_groups: ColumnSizeGroups,
}

/// Messages handled by [`AccountRowComponent`].
///
/// `Clone` so [`relm4::factory::FactoryVecDeque::broadcast`] can fan
/// the same message out to every row (used by
/// `AccountListComponent` on busy-flag transitions).
#[derive(Debug, Clone)]
pub enum AccountRowMsg {
    /// Replace the intrinsic per-row [`RowDisplay`] with `display`
    /// and re-bind. Sent by `AccountListComponent` on per-tick TOTP
    /// refresh, on HOTP reveal start/expiry, and on full-list
    /// refreshes. The busy mask is re-applied on top inside the row.
    Rebind(RowDisplay),
    /// Replace the row's icon-hint slug and re-resolve the icon name
    /// against the live `gtk::IconTheme`. Sent by
    /// `AccountListComponent` on full-list refreshes that change a
    /// row's [`crate::account_list::AccountRowModel::icon_hint`]
    /// (e.g. a follow-up rename / icon-hint edit). `None` collapses
    /// to [`PLACEHOLDER_ICON_NAME`] via [`bind_row_icon`].
    RebindIcon(Option<String>),
    /// Flip the row's busy flag and re-bind. Sent by
    /// `AccountListComponent` via
    /// [`relm4::factory::FactoryVecDeque::broadcast`] on parent
    /// `UnlockedBusy` entry / exit per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect
    /// ownership". The intrinsic display is preserved so the row
    /// keeps rendering its visible code while the worker is in
    /// flight; only copy / "next" / kebab sensitivity dims.
    SetBusy(bool),
}

/// Messages emitted by [`AccountRowComponent`] for
/// `AccountListComponent` to forward up to `AppModel`.
///
/// Each variant carries the row's [`AccountId`] so the
/// `AccountListComponent` `FactoryVecDeque::forward` mapper can route
/// it onto the matching `AccountListOutput::*` variant
/// (`OpenRenameDialog`, `OpenRemoveDialog`, `CopyCode`,
/// `AdvanceHotp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountRowOutput {
    /// Row's kebab-menu "Rename…" entry activated.
    RequestRename(AccountId),
    /// Row's kebab-menu "Remove…" entry activated.
    RequestRemove(AccountId),
    /// Row's per-row copy `gtk::Button` activated. Hidden HOTP rows
    /// dim the button through [`copy_enabled`], so this output never
    /// fires before a reveal opens.
    RequestCopy(AccountId),
    /// Row's HOTP "next" `gtk::Button` activated. TOTP rows hide the
    /// button via [`next_button_visible`], so this output only fires
    /// for HOTP rows.
    RequestAdvance(AccountId),
}

/// Dispatch table mapping a row-level action name onto the typed
/// [`AccountRowOutput`] the row emits.
///
/// Returns [`Some`] for [`ROW_RENAME_ACTION_NAME`],
/// [`ROW_REMOVE_ACTION_NAME`], [`ROW_NEXT_ACTION_NAME`], and
/// [`ROW_COPY_ACTION_NAME`]; [`None`] for every other input. The row
/// installs exactly those four actions so an unrecognized name
/// signals a wiring drift (typo in the action group, stale kebab
/// menu target, …) and stays a silent no-op rather than crashing the
/// row.
#[must_use]
pub fn dispatch_row_action(name: &str, id: AccountId) -> Option<AccountRowOutput> {
    match name {
        ROW_RENAME_ACTION_NAME => Some(AccountRowOutput::RequestRename(id)),
        ROW_REMOVE_ACTION_NAME => Some(AccountRowOutput::RequestRemove(id)),
        ROW_NEXT_ACTION_NAME => Some(AccountRowOutput::RequestAdvance(id)),
        ROW_COPY_ACTION_NAME => Some(AccountRowOutput::RequestCopy(id)),
        _ => None,
    }
}

/// Build the kebab `gio::Menu` shared by every row.
///
/// Two entries — "Rename…" → `row.rename`, "Remove…" → `row.remove` —
/// matching the per-row [`gio::SimpleActionGroup`] installed by
/// [`install_row_action_group`].
#[must_use]
pub fn build_kebab_menu_model() -> gio::Menu {
    let menu = gio::Menu::new();
    menu.append(
        Some("Rename\u{2026}"),
        Some(&format!("{ROW_ACTION_GROUP_NAME}.{ROW_RENAME_ACTION_NAME}")),
    );
    menu.append(
        Some("Remove\u{2026}"),
        Some(&format!("{ROW_ACTION_GROUP_NAME}.{ROW_REMOVE_ACTION_NAME}")),
    );
    menu
}

/// Per-row [`FactoryComponent`] mounted as one
/// [`relm4::factory::FactoryVecDeque`] entry on the
/// `AccountListComponent`'s `gtk::ListBox`.
///
/// Each instance owns its widget bundle for the row's lifetime;
/// per-tick TOTP updates, HOTP reveal transitions, full-list
/// refreshes, and busy-flag changes all route through
/// [`AccountRowMsg`] without rebuilding the row's widget tree. This
/// is the contract that fixes the "buttons flicker every tick"
/// regression that the prior
/// `gio::ListStore` + `SignalListItemFactory` setup hit on every
/// `splice` call.
pub struct AccountRowComponent {
    account_id: AccountId,
    intrinsic_display: RowDisplay,
    icon_hint: Option<String>,
    busy: bool,
    column_size_groups: ColumnSizeGroups,
}

/// Typed widget handle bundle returned by
/// [`AccountRowComponent::init_widgets`] so subsequent
/// [`AccountRowComponent::update_view`] calls can re-bind the row
/// without re-walking the widget tree.
pub struct AccountRowWidgets {
    container: gtk::Box,
}

impl AccountRowComponent {
    /// Apply the busy mask to the intrinsic display.
    ///
    /// Cloning is cheap (a fixed-size struct plus a couple of owned
    /// `String`s); doing the mask here rather than in
    /// `AccountListComponent` means the parent never has to fork its
    /// projection per row when the busy flag flips.
    fn current_display(&self) -> RowDisplay {
        let mut display = self.intrinsic_display.clone();
        apply_busy_mask(&mut display, self.busy);
        display
    }
}

impl FactoryComponent for AccountRowComponent {
    type ParentWidget = gtk::ListBox;
    type CommandOutput = ();
    type Input = AccountRowMsg;
    type Output = AccountRowOutput;
    type Init = AccountRowInit;
    type Root = gtk::ListBoxRow;
    type Widgets = AccountRowWidgets;
    type Index = DynamicIndex;

    fn init_model(init: Self::Init, _index: &DynamicIndex, _sender: FactorySender<Self>) -> Self {
        AccountRowComponent {
            account_id: init.account_id,
            intrinsic_display: init.initial_display,
            icon_hint: init.initial_icon_hint,
            busy: init.initial_busy,
            column_size_groups: init.column_size_groups,
        }
    }

    fn init_root(&self) -> Self::Root {
        gtk::ListBoxRow::builder()
            .selectable(true)
            .activatable(true)
            .build()
    }

    fn init_widgets(
        &mut self,
        _index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &gtk::ListBoxRow,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let container = build_row_widget();
        root.set_child(Some(&container));
        bind_row(&container, &self.current_display());
        bind_row_icon(&container, self.icon_hint.as_deref());
        register_row_size_groups(&container, &self.column_size_groups);
        install_row_action_group(&container, self.account_id, sender.output_sender());
        AccountRowWidgets { container }
    }

    fn update(&mut self, msg: Self::Input, _sender: FactorySender<Self>) {
        match msg {
            AccountRowMsg::Rebind(display) => self.intrinsic_display = display,
            AccountRowMsg::RebindIcon(hint) => self.icon_hint = hint,
            AccountRowMsg::SetBusy(busy) => self.busy = busy,
        }
    }

    fn update_view(&self, widgets: &mut Self::Widgets, _sender: FactorySender<Self>) {
        bind_row(&widgets.container, &self.current_display());
        bind_row_icon(&widgets.container, self.icon_hint.as_deref());
    }
}

// ---------------------------------------------------------------------------
// Row body widget construction.
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
// `AccountListComponent`, the `gtk::ListBox` mounted by
// `AccountListComponent` is driven by a
// `relm4::factory::FactoryVecDeque<AccountRowComponent>`. The
// list-level wiring (the `gtk::ListBox`, the factory `forward`
// mapper from `AccountRowOutput` to `AccountListOutput`, the search
// bar, the selection plumbing) lives in `account_list.rs`, but the
// row body — the per-row `gtk::Box`, the bind walk, the icon theme
// resolve, and the per-row `gio::SimpleActionGroup` install — lives
// here so the `AccountRowComponent` module is the canonical owner of
// row body construction. The `FactoryComponent::init_widgets`
// callback drives these four helpers so all row-widget code shares
// one source of truth.
// ---------------------------------------------------------------------------

/// Placeholder rendered in the code column whenever the row's
/// projection carries [`CodeDisplay::Hidden`].
///
/// TOTP rows land here before the first per-tick compute; HOTP
/// rows land here before "next" and after the reveal window
/// expires. A fixed six-bullet glyph keeps the column width
/// stable across hidden / revealed transitions for the common
/// six-digit code without reaching into per-account `digits`.
pub const HIDDEN_CODE_PLACEHOLDER: &str = "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}";

/// Render a [`CounterText`] into the `#N` label the row binds.
///
/// The HOTP row never distinguishes `Stored` vs `Used` in the
/// rendered text; the source of the counter is captured in the
/// projection so future per-row diagnostics can branch on it
/// without re-reading the row.
fn format_counter_label(counter: CounterText) -> String {
    let n = match counter {
        CounterText::Stored(n) | CounterText::Used(n) => n,
    };
    format!("#{n}")
}

/// Construct one row's widget bundle.
///
/// The container is a horizontal `gtk::Box` whose children are
/// appended in the order `icon → display label → HOTP counter → code
/// label → TOTP progress bar → copy button → HOTP next button →
/// kebab menu`. The label expands to claim the row's free space so the
/// icon, counter / code labels, and the trailing affordances stay
/// edge-aligned and the column edges line up across rows. [`bind_row`]
/// walks the children in this same order to apply the projection.
///
/// The TOTP progress bar uses a fixed width and is hidden for HOTP
/// rows via [`bind_row`]; per-tick refresh updates its `fraction`
/// from [`progress_fraction`].
///
/// The leading `gtk::Image` is seeded with
/// [`crate::icon_resolution::PLACEHOLDER_ICON_NAME`] so a row that
/// is mounted before [`bind_row_icon`] resolves the live theme still
/// shows the freedesktop fallback rather than an empty slot.
/// [`AccountRowComponent::init_widgets`] re-resolves the icon name
/// from the row's `AccountRowModel::icon_hint` against the live
/// `gtk::IconTheme` and calls [`bind_row_icon`] to publish the
/// result.
///
/// The kebab `gtk::MenuButton` carries a `view-more-symbolic` icon,
/// the `.flat` style class for the row-trailing affordance look, and
/// a `gio::Menu` model built by [`build_kebab_menu_model`] with the
/// Rename… / Remove… entries described in
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`.
///
/// The trailing "next" button is bound to the per-row
/// `row.next` action (the same action group the kebab menu targets),
/// so clicks fire [`dispatch_row_action`] →
/// [`AccountRowOutput::RequestAdvance`] without an extra
/// `connect_clicked` closure. The parent `AccountListComponent`
/// forwards that output as `AccountListOutput::AdvanceHotp` via its
/// `FactoryVecDeque::forward` mapper. HOTP-only visibility is
/// enforced at bind time by [`bind_row`] reading
/// [`next_button_visible`]; TOTP rows hide the button outright so
/// the action is unreachable for them even though the per-row action
/// group still carries the entry.
#[must_use]
pub fn build_row_widget() -> gtk::Box {
    let container = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(ROW_COLUMN_SPACING)
        .hexpand(true)
        .build();
    let icon = gtk::Image::builder()
        .icon_name(PLACEHOLDER_ICON_NAME)
        .valign(gtk::Align::Center)
        .pixel_size(24)
        .build();
    let label = gtk::Label::builder()
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    let counter = gtk::Label::builder()
        .halign(gtk::Align::End)
        .xalign(1.0)
        .build();
    counter.add_css_class("dim-label");
    let code = gtk::Label::builder()
        .halign(gtk::Align::End)
        .xalign(1.0)
        .build();
    code.add_css_class("numeric");
    let progress = gtk::ProgressBar::builder()
        .valign(gtk::Align::Center)
        .width_request(96)
        .show_text(false)
        .build();
    let copy = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy code")
        .valign(gtk::Align::Center)
        .action_name(format!("{ROW_ACTION_GROUP_NAME}.{ROW_COPY_ACTION_NAME}"))
        .build();
    copy.add_css_class("flat");
    let next = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Reveal next HOTP code")
        .valign(gtk::Align::Center)
        .action_name(format!("{ROW_ACTION_GROUP_NAME}.{ROW_NEXT_ACTION_NAME}"))
        .build();
    next.add_css_class("flat");
    let kebab = gtk::MenuButton::builder()
        .icon_name("view-more-symbolic")
        .tooltip_text("More actions")
        .valign(gtk::Align::Center)
        .menu_model(&build_kebab_menu_model())
        .build();
    kebab.add_css_class("flat");
    container.append(&icon);
    container.append(&label);
    container.append(&counter);
    container.append(&code);
    container.append(&progress);
    container.append(&copy);
    container.append(&next);
    container.append(&kebab);
    container
}

/// Install (or replace) the per-row [`gio::SimpleActionGroup`] that
/// routes kebab Rename… / Remove…, copy, and HOTP "next" activations
/// through [`dispatch_row_action`] and out via `output_sender` as
/// [`AccountRowOutput`].
///
/// Called from [`AccountRowComponent::init_widgets`] once per row.
/// The row's widget tree is owned by the `FactoryVecDeque` entry for
/// the row's lifetime, so the action group is installed exactly once
/// per push and never re-installed under the row mid-frame the way
/// the prior `SignalListItemFactory::connect_bind` setup did.
pub fn install_row_action_group(
    container: &gtk::Box,
    id: AccountId,
    output_sender: &Sender<AccountRowOutput>,
) {
    let actions = gio::SimpleActionGroup::new();

    for action_name in [
        ROW_RENAME_ACTION_NAME,
        ROW_REMOVE_ACTION_NAME,
        ROW_NEXT_ACTION_NAME,
        ROW_COPY_ACTION_NAME,
    ] {
        let action = gio::SimpleAction::new(action_name, None);
        let sender = output_sender.clone();
        action.connect_activate(move |_, _| {
            if let Some(out) = dispatch_row_action(action_name, id) {
                let _ = sender.send(out);
            }
        });
        actions.add_action(&action);
    }

    container.insert_action_group(ROW_ACTION_GROUP_NAME, Some(&actions));
}

/// Bind a [`RowDisplay`] onto the child widgets of a
/// previously-constructed row container.
///
/// The children are reached by walking `first_child` / `next_sibling`
/// in the same order [`build_row_widget`] appended them so the
/// factory never has to stash typed widget handles on the row.
///
/// * The copy button's sensitive state mirrors
///   [`RowDisplay::copy_enabled`]: TOTP rows are always sensitive;
///   HOTP rows are sensitive only while a visible reveal code is in
///   hand, matching the `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component
///   tree" > `AccountRowComponent` rule that copying a hidden HOTP
///   row is disabled. While `AppModel` is `UnlockedBusy`,
///   [`AccountRowComponent::update_view`] feeds the projection
///   through [`apply_busy_mask`] before calling [`bind_row`] so this
///   bit flips off and the row's copy action no longer fires.
/// * The HOTP "next" button's visibility mirrors
///   [`RowDisplay::next_button_visible`]: HOTP rows show it (the
///   user activates it to advance the counter and open a reveal
///   window); TOTP rows hide it. Its sensitive state mirrors
///   [`RowDisplay::next_button_enabled`], which is dimmed by
///   [`apply_busy_mask`] while `UnlockedBusy` so the worker holds
///   the `(Vault, Store)` pair uncontested per
///   §"In-flight effect ownership".
/// * The kebab `MenuButton`'s visibility mirrors
///   [`RowDisplay::kebab_visible`]: every row exposes the
///   Rename… / Remove… menu unconditionally. The visibility bind is
///   kept for parity with the other affordances so a future
///   per-row override stays a one-line projection change. Its
///   sensitive state mirrors [`RowDisplay::kebab_enabled`], dimmed
///   by [`apply_busy_mask`] while `UnlockedBusy`.
pub fn bind_row(container: &gtk::Box, display: &RowDisplay) {
    let Some(icon) = container.first_child().and_downcast::<gtk::Image>() else {
        return;
    };
    let Some(label) = icon.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(counter) = label.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(code) = counter.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(progress) = code.next_sibling().and_downcast::<gtk::ProgressBar>() else {
        return;
    };
    let Some(copy) = progress.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };
    let Some(next) = copy.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };
    let Some(kebab) = next.next_sibling().and_downcast::<gtk::MenuButton>() else {
        return;
    };

    label.set_label(&display.label);

    if let Some(c) = display.counter {
        counter.set_label(&format_counter_label(c));
        counter.set_visible(true);
    } else {
        counter.set_label("");
        counter.set_visible(false);
    }

    let code_text = match &display.code {
        CodeDisplay::Hidden => HIDDEN_CODE_PLACEHOLDER.to_string(),
        CodeDisplay::Visible(c) => c.clone(),
    };
    code.set_label(&code_text);

    progress.set_visible(display.progress_visible);
    for class in PROGRESS_URGENCY_CSS_CLASSES {
        progress.remove_css_class(class);
    }
    match display.progress {
        Some(p) => {
            progress.set_fraction(progress_fraction(&p));
            progress.add_css_class(progress_urgency(&p).css_class());
        }
        None => progress.set_fraction(0.0),
    }

    copy.set_sensitive(display.copy_enabled);
    next.set_visible(display.next_button_visible);
    next.set_sensitive(display.next_button_enabled);
    kebab.set_visible(display.kebab_visible);
    kebab.set_sensitive(display.kebab_enabled);
}

/// Resolve the row's icon against the live `gtk::IconTheme` and
/// publish the result onto the leading `gtk::Image` child built by
/// [`build_row_widget`].
///
/// The icon-name decision routes through
/// [`crate::icon_resolution::resolve_display_icon`] so the
/// `None` / empty / unresolved-slug fallback to
/// [`crate::icon_resolution::PLACEHOLDER_ICON_NAME`] matches the
/// pure-logic contract pinned by `tests/icon_resolution.rs`. The
/// closure forwarded to `resolve_display_icon` is the live
/// `gtk::IconTheme::has_icon` membership probe scoped to the
/// container's display, so distribution / Flatpak theme differences
/// are respected at bind time without baking a slug allowlist into
/// `paladin_core`.
///
/// Called from the row factory's `connect_bind` callback after
/// [`bind_row`] so the per-tick rebind path (which re-splices the
/// same rows into the `gio::ListStore`) keeps the icon in lockstep
/// with any future `AccountRowModel::icon_hint` change (rename
/// today; explicit icon-hint edit lands with the manual-edit row in
/// a follow-up commit).
pub fn bind_row_icon(container: &gtk::Box, icon_hint: Option<&str>) {
    let Some(icon_widget) = container.first_child().and_downcast::<gtk::Image>() else {
        return;
    };
    let icon_theme = gtk::IconTheme::for_display(&gtk::prelude::WidgetExt::display(container));
    let icon_name = resolve_display_icon(icon_hint, |slug| icon_theme.has_icon(slug));
    icon_widget.set_icon_name(Some(icon_name));
}

// ---------------------------------------------------------------------------
// Column-header strip + per-column SizeGroups.
//
// Goal: a single non-scrolling header strip mounted above the row
// list that labels the visible columns (currently “Account” and
// “Code”).  Alignment with the rows is guaranteed by a bundle of
// per-column `gtk::SizeGroup`s ([`ColumnSizeGroups`]) — each row's
// cell and the matching header cell are registered in the same
// `SizeGroup`, so width changes propagate symmetrically.  The
// header strip never scrolls because it lives outside the
// `gtk::ScrolledWindow` that wraps the `gtk::ListBox`.

/// Per-column [`gtk::SizeGroup`] bundle that the row factory and the
/// column-header strip share so each header cell sits over the
/// corresponding row cell.
///
/// One [`gtk::SizeGroup::Mode::Horizontal`] group per slot in the
/// row's child order (see [`build_row_widget`]):
///
/// ```text
///   icon → label → counter → code → progress → copy → next → kebab
/// ```
///
/// Cloning the bundle is a refcount bump on each member, so
/// [`AccountListComponent`](crate::account_list::AccountListComponent)
/// can hold one `ColumnSizeGroups` and clone it cheaply into every
/// new [`AccountRowInit`].
#[derive(Debug, Clone)]
pub struct ColumnSizeGroups {
    /// Width sync for the leading [`gtk::Image`] icon column.
    pub icon: gtk::SizeGroup,
    /// Width sync for the expanding `<issuer>:<label>` display
    /// [`gtk::Label`] column.
    pub label: gtk::SizeGroup,
    /// Width sync for the (HOTP-only) counter [`gtk::Label`] column.
    pub counter: gtk::SizeGroup,
    /// Width sync for the code [`gtk::Label`] column.
    pub code: gtk::SizeGroup,
    /// Width sync for the (TOTP-only) progress [`gtk::ProgressBar`]
    /// column.
    pub progress: gtk::SizeGroup,
    /// Width sync for the copy [`gtk::Button`] column.
    pub copy: gtk::SizeGroup,
    /// Width sync for the HOTP "next" [`gtk::Button`] column.
    pub next: gtk::SizeGroup,
    /// Width sync for the kebab [`gtk::MenuButton`] column.
    pub kebab: gtk::SizeGroup,
}

impl Default for ColumnSizeGroups {
    fn default() -> Self {
        Self::new()
    }
}

impl ColumnSizeGroups {
    /// Construct a fresh bundle of [`gtk::SizeGroup::Mode::Horizontal`]
    /// `SizeGroup`s, one per row column.
    ///
    /// Each `gtk::SizeGroup` starts empty; [`register_row_size_groups`]
    /// adds row cells and [`build_column_header_strip`] adds header
    /// cells.
    #[must_use]
    pub fn new() -> Self {
        let new_group = || gtk::SizeGroup::new(gtk::SizeGroupMode::Horizontal);
        Self {
            icon: new_group(),
            label: new_group(),
            counter: new_group(),
            code: new_group(),
            progress: new_group(),
            copy: new_group(),
            next: new_group(),
            kebab: new_group(),
        }
    }
}

/// Register the eight children of a row container (in
/// [`build_row_widget`] order) with the matching members of
/// `groups`.
///
/// The walk mirrors [`bind_row`]'s `first_child`/`next_sibling`
/// chain, so additions to the row template must update both
/// functions in lockstep.  The function is a no-op if the row's
/// child types do not match the expected layout — defensive against
/// a future row-template refactor that ships before this helper is
/// updated.
pub fn register_row_size_groups(row: &gtk::Box, groups: &ColumnSizeGroups) {
    let Some(icon) = row.first_child().and_downcast::<gtk::Image>() else {
        return;
    };
    let Some(label) = icon.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(counter) = label.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(code) = counter.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(progress) = code.next_sibling().and_downcast::<gtk::ProgressBar>() else {
        return;
    };
    let Some(copy) = progress.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };
    let Some(next) = copy.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };
    let Some(kebab) = next.next_sibling().and_downcast::<gtk::MenuButton>() else {
        return;
    };
    groups.icon.add_widget(&icon);
    groups.label.add_widget(&label);
    groups.counter.add_widget(&counter);
    groups.code.add_widget(&code);
    groups.progress.add_widget(&progress);
    groups.copy.add_widget(&copy);
    groups.next.add_widget(&next);
    groups.kebab.add_widget(&kebab);
}

/// Build the column-header strip — a horizontal [`gtk::Box`] whose
/// children mirror the row's eight-cell template ([`build_row_widget`])
/// but only carry text in the "Account" and "Code" slots.  Each cell
/// is added to the matching member of `groups` so its width tracks
/// the row's corresponding column.
///
/// Empty spacer cells (icon, counter, progress, copy, next, kebab)
/// are zero-width [`gtk::Label`]s — they contribute nothing to the
/// `SizeGroup` and let the row's natural column width win.
///
/// Visibility of the returned strip is controlled by the caller
/// (typically the per-user `show-column-headers` `GSettings` key);
/// this helper does not gate it.
#[must_use]
pub fn build_column_header_strip(groups: &ColumnSizeGroups) -> gtk::Box {
    let container = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(ROW_COLUMN_SPACING)
        .hexpand(true)
        .margin_start(12)
        .margin_end(12)
        .margin_top(6)
        .margin_bottom(2)
        .build();
    container.add_css_class("paladin-column-headers");

    let icon_spacer = gtk::Label::new(None);
    let account_label = gtk::Label::builder()
        .label(format_account_column_title())
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    account_label.add_css_class("dim-label");
    account_label.add_css_class("caption-heading");

    let counter_spacer = gtk::Label::new(None);

    let code_label = gtk::Label::builder()
        .label(format_code_column_title())
        .halign(gtk::Align::End)
        .xalign(1.0)
        .build();
    code_label.add_css_class("dim-label");
    code_label.add_css_class("caption-heading");

    let progress_spacer = gtk::Label::new(None);
    let copy_spacer = gtk::Label::new(None);
    let next_spacer = gtk::Label::new(None);
    let kebab_spacer = gtk::Label::new(None);

    container.append(&icon_spacer);
    container.append(&account_label);
    container.append(&counter_spacer);
    container.append(&code_label);
    container.append(&progress_spacer);
    container.append(&copy_spacer);
    container.append(&next_spacer);
    container.append(&kebab_spacer);

    groups.icon.add_widget(&icon_spacer);
    groups.label.add_widget(&account_label);
    groups.counter.add_widget(&counter_spacer);
    groups.code.add_widget(&code_label);
    groups.progress.add_widget(&progress_spacer);
    groups.copy.add_widget(&copy_spacer);
    groups.next.add_widget(&next_spacer);
    groups.kebab.add_widget(&kebab_spacer);

    container
}
