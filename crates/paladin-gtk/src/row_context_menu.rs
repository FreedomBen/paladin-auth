// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic shadows for the row-body right-click + keyboard
//! context-menu surface (Milestone 9 slice 5).
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Row context menu and
//! `EditDialog` implementation" > "Design contract" and `docs/DESIGN.md`
//! §7, the account list raises the shared row context `gio::Menu`
//! (built by [`crate::account_row::build_row_context_menu_model`]) from
//! three surfaces against one per-row `gio::SimpleActionGroup`:
//!
//! * the kebab `gtk::MenuButton` (slice 3),
//! * a row-body right-click `gtk::GestureClick` (secondary button), and
//! * a keyboard `gtk::ShortcutController` (`Menu` / `Shift+F10` pop the
//!   shared popover; `Shift+E` activates `row.edit` for TUI parity).
//!
//! Section header rows ([`crate::row_item::RowItem::is_section`])
//! never raise the menu and never install the controllers.
//!
//! The functions here are widget-free so the gesture / controller /
//! single-popover decisions are pinned by
//! `tests/row_context_menu_logic.rs` without spinning up GTK or a
//! display server. The widget layer in [`crate::column_view`] /
//! [`crate::account_list`] calls into them and binds the result to the
//! real `gtk::GestureClick`, `gtk::ShortcutController`, and
//! `gtk::PopoverMenu` objects.

/// Which kind of row a context-menu decision is being computed for.
///
/// A row is either a non-selectable section header
/// ([`Self::Section`]) or a real account row ([`Self::Account`]).
/// Mirrors the [`crate::row_item::RowKind`] split the widget layer
/// reads off the bound `RowItem`, projected down to the single bit
/// the context-menu decisions care about: section rows suppress the
/// menu entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowMenuKind {
    /// A section-header row. The context menu is always suppressed
    /// and no controllers are installed.
    Section,
    /// A real account row. The context menu pops and the gesture /
    /// keyboard controllers are installed.
    Account,
}

impl RowMenuKind {
    /// Project a raw `is_section` flag onto a [`RowMenuKind`].
    ///
    /// `true` → [`RowMenuKind::Section`], `false` →
    /// [`RowMenuKind::Account`]. Lets the widget layer thread the
    /// `RowItem::is_section()` bool straight into the decisions
    /// without re-deriving the enum at each call site.
    #[must_use]
    pub fn from_is_section(is_section: bool) -> Self {
        if is_section {
            Self::Section
        } else {
            Self::Account
        }
    }

    /// `true` for [`Self::Section`].
    #[must_use]
    pub fn is_section(self) -> bool {
        matches!(self, Self::Section)
    }
}

/// Decision for popping the shared row context menu against a row.
///
/// Produced by [`pop_row_context_menu_decision`]; the widget layer in
/// [`crate::column_view`] reads it before mounting the
/// `gtk::PopoverMenu` so the suppress-on-section and per-state
/// enablement rules live in one tested place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopRowContextMenuDecision {
    /// The row is a section header — never raise the menu. The
    /// `busy` / `hidden_hotp` inputs are irrelevant in this arm.
    Suppress,
    /// Pop the shared menu, applying the per-state enablement to the
    /// menu entries.
    Pop {
        /// `Copy code` is sensitive iff the row is not a hidden HOTP
        /// row (`!hidden_hotp`). A hidden HOTP row has no visible
        /// code to copy, mirroring [`crate::account_row::copy_enabled`].
        copy_sensitive: bool,
        /// `Edit…` / `Show QR…` / `Remove…` are sensitive iff the
        /// parent `AppModel` is not `UnlockedBusy` (`!busy`),
        /// mirroring [`crate::account_row::apply_busy_mask`].
        actions_sensitive: bool,
    },
}

/// Decide whether (and how) the shared row context menu pops for a
/// row.
///
/// Section rows return [`PopRowContextMenuDecision::Suppress`]
/// regardless of `busy` / `hidden_hotp`. Account rows return
/// [`PopRowContextMenuDecision::Pop`] with `copy_sensitive =
/// !hidden_hotp` (a hidden HOTP row dims `Copy code`) and
/// `actions_sensitive = !busy` (a worker in flight dims
/// `Edit…` / `Show QR…` / `Remove…`).
///
/// Mirrors the existing `RowDisplay` gating
/// ([`crate::account_row::copy_enabled`] +
/// [`crate::account_row::apply_busy_mask`]) so the right-click /
/// keyboard popover dims its entries identically to the kebab and
/// the inline copy button.
#[must_use]
pub fn pop_row_context_menu_decision(
    row_kind: RowMenuKind,
    busy: bool,
    hidden_hotp: bool,
) -> PopRowContextMenuDecision {
    if row_kind.is_section() {
        return PopRowContextMenuDecision::Suppress;
    }
    PopRowContextMenuDecision::Pop {
        copy_sensitive: !hidden_hotp,
        actions_sensitive: !busy,
    }
}

/// One keyboard / pointer trigger the row's context-menu controller
/// set carries.
///
/// Descriptor (not a real `gtk::ShortcutTrigger` /
/// `gtk::GestureClick`) so [`install_row_context_menu_controllers_decision`]
/// stays widget-free and unit-testable. The widget layer maps each
/// variant onto the matching GTK object:
///
/// * [`Self::SecondaryClick`] → a `gtk::GestureClick` configured for
///   `gtk::gdk::BUTTON_SECONDARY`.
/// * [`Self::Menu`] / [`Self::ShiftF10`] → a `gtk::Shortcut` whose
///   `gtk::CallbackAction` pops the shared popover anchored to the
///   row's content rect.
/// * [`Self::ShiftE`] → a `gtk::Shortcut` whose
///   `gtk::NamedAction::new("row.edit")` activates the row's edit
///   action (TUI parity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowMenuTrigger {
    /// Secondary (right) mouse-button press via `gtk::GestureClick`.
    SecondaryClick,
    /// The dedicated `Menu` key.
    Menu,
    /// `Shift+F10` (the keyboard context-menu fallback).
    ShiftF10,
    /// `Shift+E` — activates `row.edit` (TUI parity).
    ShiftE,
}

impl RowMenuTrigger {
    /// The `gtk::ShortcutTrigger::parse_string` spelling for the
    /// keyboard triggers, or `None` for [`Self::SecondaryClick`]
    /// (a pointer gesture, not a keyboard shortcut).
    ///
    /// Pinned here so the widget layer parses the exact same strings
    /// the tests assert, keeping the `gtk::Shortcut` triggers and
    /// this descriptor from drifting.
    #[must_use]
    pub fn shortcut_trigger_string(self) -> Option<&'static str> {
        match self {
            Self::SecondaryClick => None,
            Self::Menu => Some("Menu"),
            Self::ShiftF10 => Some("<Shift>F10"),
            Self::ShiftE => Some("<Shift>e"),
        }
    }
}

/// The controller set installed on a row container for the
/// context-menu surface.
///
/// Produced by [`install_row_context_menu_controllers_decision`].
/// Section rows get the empty set
/// (`gesture_click == false`, no shortcut triggers); account rows get
/// the secondary `gtk::GestureClick` plus one `gtk::ShortcutController`
/// carrying the [`RowMenuTrigger::Menu`] / [`RowMenuTrigger::ShiftF10`] /
/// [`RowMenuTrigger::ShiftE`] triggers.
///
/// Descriptor only — the widget layer builds the real controllers
/// from it; the struct exists so the install rule is pinned by
/// `tests/row_context_menu_logic.rs` without a display server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerSet {
    /// Whether a secondary-button `gtk::GestureClick` is installed.
    pub gesture_click: bool,
    /// The keyboard triggers carried by the single
    /// `gtk::ShortcutController`. Empty for section rows; the
    /// `Menu` / `Shift+F10` / `Shift+E` set for account rows.
    pub shortcut_triggers: Vec<RowMenuTrigger>,
}

impl ControllerSet {
    /// The empty controller set installed on (i.e. withheld from) a
    /// section row: no gesture, no shortcuts.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            gesture_click: false,
            shortcut_triggers: Vec::new(),
        }
    }

    /// `true` when no controllers are installed (section rows).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.gesture_click && self.shortcut_triggers.is_empty()
    }
}

/// Decide which event controllers the row body installs for the
/// context-menu surface.
///
/// Account rows ⇒ a secondary-button `gtk::GestureClick`
/// (`gesture_click == true`) plus one `gtk::ShortcutController`
/// carrying [`RowMenuTrigger::Menu`], [`RowMenuTrigger::ShiftF10`],
/// and [`RowMenuTrigger::ShiftE`] in that order. Section rows ⇒
/// [`ControllerSet::empty`] (no controllers; the menu is suppressed
/// per [`pop_row_context_menu_decision`]).
///
/// The widget layer in [`crate::column_view::build_account_column_factory`]
/// calls this on every `bind`, installing the controllers for an
/// account row and removing them for a reused cell that now renders a
/// section header.
#[must_use]
pub fn install_row_context_menu_controllers_decision(is_section: bool) -> ControllerSet {
    if is_section {
        return ControllerSet::empty();
    }
    ControllerSet {
        gesture_click: true,
        shortcut_triggers: vec![
            RowMenuTrigger::Menu,
            RowMenuTrigger::ShiftF10,
            RowMenuTrigger::ShiftE,
        ],
    }
}

/// What to do with any prior `gtk::PopoverMenu` before mounting a
/// fresh one (or when a refresh / lock invalidates the row).
///
/// Returned by [`prior_popover_disposition`]; the widget layer reads
/// it to decide whether to `unparent` + drop the previously-mounted
/// popover. Modelled as an explicit enum (rather than a bare `bool`)
/// so the single-popover invariant reads the same at the pop site,
/// the refresh handler, and the lock-transition path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorPopoverDisposition {
    /// There was no prior popover — nothing to unparent.
    Nothing,
    /// A prior popover is mounted — `unparent` it and drop it before
    /// proceeding.
    UnparentPrior,
}

impl PriorPopoverDisposition {
    /// `true` when the prior popover must be unparented + dropped.
    #[must_use]
    pub fn should_unparent(self) -> bool {
        matches!(self, Self::UnparentPrior)
    }
}

/// The event that is asking the single-popover invariant to run.
///
/// All three events drive the *same* decision in
/// [`prior_popover_disposition`]: if a prior popover exists it is
/// unparented + dropped. Carrying the cause as an enum keeps the
/// three call sites ([`crate::account_list`]'s pop path, the
/// `AccountListMsg::Refresh` handler, and the lock-transition
/// teardown) provably aligned in `tests/row_context_menu_logic.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PopoverInvalidation {
    /// A fresh popover is about to be mounted (right-click / keyboard
    /// pop). The single-popover invariant drops any prior one first.
    Pop,
    /// `AccountListMsg::Refresh` spliced the store — the prior
    /// popover's row `RowItem` may have been replaced, so drop it.
    Refresh,
    /// The `(Vault, Store)` pair is being torn down on auto-lock /
    /// lock — a popover must never outlive its row, so drop it.
    Lock,
}

/// Decide whether to unparent + drop a prior popover.
///
/// The single-popover invariant: at most one row `gtk::PopoverMenu`
/// is mounted at a time, and it never outlives its row or the
/// `(Vault, Store)` pair. Whenever a fresh popover is popped
/// ([`PopoverInvalidation::Pop`]), or a refresh splices the store
/// ([`PopoverInvalidation::Refresh`]), or a lock tears down the vault
/// ([`PopoverInvalidation::Lock`]), any prior popover is unparented +
/// dropped. The cause does not change the decision — it is captured
/// only so the three widget call sites stay provably aligned.
///
/// Returns [`PriorPopoverDisposition::UnparentPrior`] iff
/// `has_prior` is `true`, else [`PriorPopoverDisposition::Nothing`].
#[must_use]
pub fn prior_popover_disposition(
    _cause: PopoverInvalidation,
    has_prior: bool,
) -> PriorPopoverDisposition {
    if has_prior {
        PriorPopoverDisposition::UnparentPrior
    } else {
        PriorPopoverDisposition::Nothing
    }
}

/// Decision for the `Shift+E` row-edit keyboard shortcut.
///
/// `Shift+E` activates `row.edit` (TUI parity) only when the row is
/// an account row **and** no modal `adw::Dialog` is open. While a
/// modal dialog is open the open dialog's focus capture consumes the
/// key before the row controller sees it, so no new `OpenEditDialog`
/// is emitted; this enum pins that contract in pure logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowEditShortcutDecision {
    /// Activate the `row.edit` action (emit `OpenEditDialog`).
    ActivateEdit,
    /// Do nothing — either the row is a section header, or a modal
    /// dialog is already open and has captured the key.
    Reject,
}

impl RowEditShortcutDecision {
    /// `true` for [`Self::ActivateEdit`].
    #[must_use]
    pub fn activates(self) -> bool {
        matches!(self, Self::ActivateEdit)
    }
}

/// Decide whether the `Shift+E` shortcut activates `row.edit`.
///
/// Returns [`RowEditShortcutDecision::ActivateEdit`] iff the row is
/// an account row (`!is_section`) and no modal dialog is open
/// (`!modal_open`). A section row never installs the controller (so
/// the trigger cannot fire from it), and an open modal `adw::Dialog`
/// captures the keystroke before the row controller — both collapse
/// to [`RowEditShortcutDecision::Reject`], emitting no new
/// `OpenEditDialog`.
#[must_use]
pub fn row_edit_shortcut_decision(is_section: bool, modal_open: bool) -> RowEditShortcutDecision {
    if is_section || modal_open {
        RowEditShortcutDecision::Reject
    } else {
        RowEditShortcutDecision::ActivateEdit
    }
}
