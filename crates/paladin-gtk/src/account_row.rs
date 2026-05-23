// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-row pure-logic projection for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountRowComponent` and Appendix A §A.8, each row in
//! `AccountListComponent`'s `gtk::ColumnView` shows the
//! `<issuer>:<label>` display string, the current code (or a hidden
//! placeholder for HOTP rows that have not been revealed), a TOTP
//! progress indicator or HOTP "next" button, a copy button, and a
//! kebab menu. The widget construction (per-column cell factory
//! `setup` / `bind` / `unbind` walkers, the per-cell
//! `gio::SimpleActionGroup`) lives in [`crate::column_view`]; this
//! module owns the pure-logic shadow those factories bind, so the
//! row-factory routing rules are exercised in
//! `tests/account_row_logic.rs` without spinning up GTK /
//! libadwaita.
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

use relm4::gtk::gio;

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Code};

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

/// Per-row activation kind decoded by [`dispatch_row_action`] from
/// the action name fired by the kebab `gio::MenuModel` or the
/// inline "next" / copy buttons.
///
/// Each variant carries the row's [`AccountId`] so the cell
/// factories in [`crate::column_view`] can route it onto the
/// matching [`crate::account_list::AccountListOutput`] variant
/// (`OpenRenameDialog`, `OpenRemoveDialog`, `CopyCode`,
/// `AdvanceHotp`) directly.
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

// ---------------------------------------------------------------------------
// Pure-logic helpers consumed by the cell factories in
// `crate::column_view`.
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.8, the
// `AccountListComponent` widget tree is a `gtk::ColumnView` driven
// by a `gio::ListStore<crate::row_item::RowItem>`. The legacy
// per-row `gtk::Box` builder / bind walker / per-row
// `gio::SimpleActionGroup` installer have been folded into the
// per-column `gtk::SignalListItemFactory` builders in
// `crate::column_view`; the helpers below — kebab menu model,
// counter formatter, hidden-code placeholder, urgency CSS classes,
// and the row-action dispatch table — are the shared pure-logic
// surface those factories consume.
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
/// without re-reading the row. Consumed by the `gtk::ColumnView`
/// cell factories in [`crate::column_view`].
#[must_use]
pub fn format_counter_label(counter: CounterText) -> String {
    let n = match counter {
        CounterText::Stored(n) | CounterText::Used(n) => n,
    };
    format!("#{n}")
}
