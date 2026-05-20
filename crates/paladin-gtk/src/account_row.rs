// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AccountRowComponent` pure-logic projection for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::prelude::*;

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
/// per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership"
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
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership"
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
/// `UnlockedBusy` gating contract from `IMPLEMENTATION_PLAN_04_GTK.md`
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

/// Construction parameters for [`AccountRowComponent`].
///
/// Each row identifies itself by its stable [`paladin_core::AccountId`]
/// so the row's kebab-menu dispatches ([`AccountRowOutput::RequestRename`] /
/// [`AccountRowOutput::RequestRemove`]) can carry the ID up to
/// `AppModel` without re-projecting the live [`AccountSummary`]
/// through the row controller boundary. Mirrors the
/// `AccountListOutput::OpenRenameDialog(AccountId)` /
/// `AccountListOutput::OpenRemoveDialog(AccountId)` shape that the
/// `SignalListItemFactory` binding in `account_list.rs` already
/// uses, so a follow-up migration from `SignalListItemFactory` to
/// `relm4::factory::FactoryVecDeque<AccountRowComponent>` does not
/// need to widen the per-row payload.
#[derive(Debug, Clone)]
pub struct AccountRowInit {
    /// Stable account identifier the row's kebab-menu dispatches
    /// carry back up to `AppModel`. Captured from the
    /// [`AccountRowModel::id`](crate::account_list::AccountRowModel)
    /// the parent factory iterates so the row never holds a live
    /// `(Vault, Store)` reference across the controller boundary.
    pub account_id: AccountId,
}

/// Messages handled by [`AccountRowComponent`].
///
/// This milestone scaffolds the read-only row controller surface;
/// the visible-code refresh / HOTP reveal / copy-button / progress-
/// tick transitions described in `IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Component tree" > `AccountRowComponent` land alongside the
/// migration of `AccountListComponent` from `SignalListItemFactory`
/// to `relm4::factory::FactoryVecDeque<AccountRowComponent>`. The
/// empty enum is the deliberate v0.2 starting point — relm4
/// requires the associated `Input` type to exist even when no
/// inbound messages are wired yet.
#[derive(Debug)]
pub enum AccountRowMsg {}

/// Messages emitted by [`AccountRowComponent`] for the parent
/// factory / `AccountListComponent` to consume.
///
/// Mirrors the
/// `AccountListOutput::OpenRenameDialog(AccountId)` /
/// `AccountListOutput::OpenRemoveDialog(AccountId)` shape that the
/// existing `SignalListItemFactory` binding already forwards up to
/// `AppModel`, so the follow-up migration from
/// `SignalListItemFactory` to `FactoryVecDeque<AccountRowComponent>`
/// can re-use the same `AppModel` dispatch arms. Submit / copy /
/// HOTP-advance outputs land in the same follow-up commits that add
/// the matching [`AccountRowMsg`] variants.
#[derive(Debug, Clone)]
pub enum AccountRowOutput {
    /// Row's kebab-menu "Rename…" entry activated. Carries the
    /// [`AccountId`] of the row's account so the parent can look up
    /// the current label and mount the `RenameDialog`.
    RequestRename(AccountId),
    /// Row's kebab-menu "Remove…" entry activated. Carries the
    /// [`AccountId`] of the row's account so the parent can look up
    /// the current label and mount the `RemoveDialog`.
    RequestRemove(AccountId),
}

/// Widget-bearing controller surface for a single account row.
///
/// Per DESIGN.md §7 and `IMPLEMENTATION_PLAN_04_GTK.md` §"Component
/// tree" > `AccountRowComponent`, each row in
/// `AccountListComponent`'s `gtk::ListView` shows the
/// `<issuer>:<label>` display string, the current code (or a hidden
/// placeholder for HOTP rows that have not been revealed), a TOTP
/// progress indicator or HOTP "next" button, a copy button, and a
/// kebab `gtk::MenuButton` whose `gio::Menu` exposes Rename… /
/// Remove… entries.
///
/// Today `AccountListComponent` binds these row children through a
/// `SignalListItemFactory` against the pure-logic helpers
/// ([`project_row`], [`display_label`], etc.) earlier in this
/// module, and forwards its row-level kebab dispatches up to
/// `AppModel` via
/// `AccountListOutput::OpenRenameDialog(AccountId)` /
/// `AccountListOutput::OpenRemoveDialog(AccountId)`. The widget body
/// here is a read-only scaffold at this milestone (an empty
/// `gtk::Box`), so the controller surface compiles cleanly without
/// yet replacing the `SignalListItemFactory` binding. Follow-up
/// commits migrate `AccountListComponent` to a
/// `relm4::factory::FactoryVecDeque<AccountRowComponent>` and
/// attach the real widgets that drive the pure-logic helpers.
pub struct AccountRowComponent {
    /// Stable identifier the row's kebab dispatches carry. Kept on
    /// `self` so the upcoming Rename… / Remove… click handlers can
    /// forward the ID without re-plumbing through every signal. The
    /// pure-logic round-trip is asserted by
    /// `tests/account_row_logic.rs`.
    #[allow(dead_code)]
    account_id: AccountId,
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for AccountRowComponent {
    type Init = AccountRowInit;
    type Input = AccountRowMsg;
    type Output = AccountRowOutput;

    view! {
        #[root]
        adw::ActionRow {
            // The display-label / code / progress / kebab children
            // land alongside the `FactoryVecDeque` migration; until
            // then the row's `title` is left blank so the existing
            // `SignalListItemFactory` binding in
            // `AccountListComponent` remains the single source of
            // truth for the visible row body.
            set_title: "",
        },
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        _sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = AccountRowComponent {
            account_id: init.account_id,
        };
        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `AccountRowMsg` doc comment for the upcoming visible-code
        // refresh / HOTP reveal / copy / progress-tick transitions
        // that land alongside the `FactoryVecDeque` migration.
    }
}
