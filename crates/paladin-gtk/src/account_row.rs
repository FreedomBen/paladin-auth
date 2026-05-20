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
//! The same rule lives in [`crate::remove_dialog::summary_display_label`];
//! both call sites use the same projection helper here.
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
#[must_use]
pub fn display_label(summary: &AccountSummary) -> String {
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
    /// Result of [`display_label`].
    pub label: String,
    /// Account kind (echoed back for downstream widget routing —
    /// HOTP rows reach for the "next" button, TOTP rows for the
    /// progress indicator).
    pub kind: AccountKindSummary,
    /// Result of [`code_display`].
    pub code: CodeDisplay,
    /// Result of [`counter_display`].
    pub counter: Option<CounterText>,
    /// Result of [`copy_enabled`].
    pub copy_enabled: bool,
    /// Result of [`next_button_visible`].
    pub next_button_visible: bool,
    /// Result of [`progress_visible`].
    pub progress_visible: bool,
    /// Result of [`kebab_visible`].
    pub kebab_visible: bool,
}

/// Bundle every row projection together.
///
/// Composes [`display_label`], [`code_display`], [`counter_display`],
/// [`copy_enabled`], [`next_button_visible`], [`progress_visible`],
/// and [`kebab_visible`] into a [`RowDisplay`]. The widget layer
/// reads `Some(&Code)` from either the TOTP per-tick compute slot or
/// the HOTP reveal slot and passes it through; the helpers all agree
/// on `None ⇒ hidden`.
#[must_use]
pub fn project_row(summary: &AccountSummary, visible_code: Option<&Code>) -> RowDisplay {
    let has_visible_code = visible_code.is_some();
    RowDisplay {
        label: display_label(summary),
        kind: summary.kind,
        code: code_display(summary.kind, visible_code),
        counter: counter_display(summary, visible_code),
        copy_enabled: copy_enabled(summary.kind, has_visible_code),
        next_button_visible: next_button_visible(summary.kind),
        progress_visible: progress_visible(summary.kind),
        kebab_visible: kebab_visible(summary.kind),
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
