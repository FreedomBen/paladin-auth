// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for the row-body right-click + keyboard
//! context-menu surface (Milestone 9 slice 5).
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Row context menu and
//! `EditDialog` implementation" > "Design contract" and `docs/DESIGN.md`
//! §7, the account list raises the shared row context `gio::Menu`
//! from three surfaces — the kebab `gtk::MenuButton`, a row-body
//! secondary-button `gtk::GestureClick`, and a keyboard
//! `gtk::ShortcutController` (`Menu` / `Shift+F10` pop the popover,
//! `Shift+E` activates `row.edit`) — all against one per-row
//! `gio::SimpleActionGroup`. Section header rows never raise the menu
//! and never install the controllers, and at most one
//! `gtk::PopoverMenu` is mounted at a time (dropped on pop / refresh /
//! lock).
//!
//! These tests pin the widget-free decision shadows in
//! [`paladin_gtk::row_context_menu`] (plus the shared menu model and
//! the row-action dispatch table) so the contract runs without a
//! display server; the parallel `tests/gtk_smoke.rs` exercises the
//! mounted widgets end-to-end under `xvfb-run` in CI.

use paladin_core::AccountId;
use paladin_gtk::account_list::AccountListOutput;
use paladin_gtk::account_row::{
    build_row_context_menu_model, dispatch_row_action, AccountRowOutput, ROW_ACTION_GROUP_NAME,
    ROW_COPY_ACTION_NAME, ROW_EDIT_ACTION_NAME, ROW_REMOVE_ACTION_NAME, ROW_SHOW_QR_ACTION_NAME,
};
use paladin_gtk::row_context_menu::{
    install_row_context_menu_controllers_decision, pop_row_context_menu_decision,
    prior_popover_disposition, row_edit_shortcut_decision, ControllerSet,
    PopRowContextMenuDecision, PopoverInvalidation, PriorPopoverDisposition,
    RowEditShortcutDecision, RowMenuKind, RowMenuTrigger,
};
use relm4::gtk::gio::prelude::*;

// ---------------------------------------------------------------------------
// Shared route mirror — the kebab `gio::SimpleActionGroup`'s activation
// closures map a fired action name through `dispatch_row_action` onto an
// `AccountRowOutput`, then onto the `AccountListOutput` forwarded to
// `AppModel` (see `column_view::build_kebab_action_group`). The row-body
// right-click / keyboard popover targets the *same* per-row group, so the
// same route applies. Mirrored here so the action-target tests assert the
// end-to-end mapping without spinning up GTK.
// ---------------------------------------------------------------------------

fn route(out: &AccountRowOutput) -> AccountListOutput {
    match *out {
        AccountRowOutput::RequestEdit(id) => AccountListOutput::OpenEditDialog(id),
        AccountRowOutput::RequestExportQr(id) => AccountListOutput::OpenExportQrDialog(id),
        AccountRowOutput::RequestRemove(id) => AccountListOutput::OpenRemoveDialog(id),
        AccountRowOutput::RequestCopy(id) => AccountListOutput::CopyCode(id),
        AccountRowOutput::RequestAdvance(id) => AccountListOutput::AdvanceHotp(id),
    }
}

/// Map a fired `row.*` action name through the full kebab/popover
/// route onto the `AccountListOutput` `AppModel` receives, or `None`
/// for an unrecognized action (the dispatch table's silent no-op).
fn route_action(name: &str, id: AccountId) -> Option<AccountListOutput> {
    dispatch_row_action(name, id).map(|out| route(&out))
}

// ===========================================================================
// 1. Shared menu model: four entries in canonical order.
// ===========================================================================

#[test]
fn build_row_context_menu_model_has_four_entries_in_order() {
    // The single model bound by the kebab, the right-click
    // `gtk::PopoverMenu`, and the keyboard `gtk::ShortcutController`
    // (slice 5) carries exactly four entries in order:
    // "Copy code" → `row.copy`, "Edit…" → `row.edit`,
    // "Show QR…" → `row.show-qr`, "Remove…" → `row.remove`. The
    // labels are deliberately "Show QR…" / "Remove…" (NOT
    // "Export QR…" / "Delete…"). Table-driven over `n_items` + each
    // position's (label, action) so drift in any cell surfaces here.
    let menu = build_row_context_menu_model();
    assert_eq!(menu.n_items(), 4, "row menu carries exactly four items");

    let expected = [
        (
            0i32,
            "Copy code",
            format!("{ROW_ACTION_GROUP_NAME}.{ROW_COPY_ACTION_NAME}"),
        ),
        (
            1,
            "Edit\u{2026}",
            format!("{ROW_ACTION_GROUP_NAME}.{ROW_EDIT_ACTION_NAME}"),
        ),
        (
            2,
            "Show QR\u{2026}",
            format!("{ROW_ACTION_GROUP_NAME}.{ROW_SHOW_QR_ACTION_NAME}"),
        ),
        (
            3,
            "Remove\u{2026}",
            format!("{ROW_ACTION_GROUP_NAME}.{ROW_REMOVE_ACTION_NAME}"),
        ),
    ];

    for (index, label, action) in expected {
        let got_label: String = menu
            .item_attribute_value(index, "label", None)
            .and_then(|v| v.get())
            .unwrap_or_else(|| panic!("menu item {index} carries a label attribute"));
        assert_eq!(got_label, label, "menu item {index} label");

        let got_action: String = menu
            .item_attribute_value(index, "action", None)
            .and_then(|v| v.get())
            .unwrap_or_else(|| panic!("menu item {index} carries an action attribute"));
        assert_eq!(got_action, action, "menu item {index} action");
    }
}

// ===========================================================================
// 2. `pop_row_context_menu_decision`.
// ===========================================================================

#[test]
fn pop_decision_suppresses_for_section_rows_across_all_inputs() {
    // Section rows never raise the menu, regardless of busy / hidden
    // HOTP state — walk the irrelevant inputs to pin that they do not
    // flip the decision off `Suppress`.
    for busy in [false, true] {
        for hidden_hotp in [false, true] {
            assert_eq!(
                pop_row_context_menu_decision(RowMenuKind::Section, busy, hidden_hotp),
                PopRowContextMenuDecision::Suppress,
                "section row suppresses (busy={busy}, hidden_hotp={hidden_hotp})",
            );
        }
    }
}

#[test]
fn pop_decision_for_account_rows_walks_all_four_cells() {
    // Account rows pop with `copy_sensitive = !hidden_hotp` and
    // `actions_sensitive = !busy`. Walk the full (busy, hidden_hotp)
    // truth table so both gates are pinned independently.
    let cases = [
        (false, false, true, true),
        (false, true, false, true),
        (true, false, true, false),
        (true, true, false, false),
    ];
    for (busy, hidden_hotp, want_copy, want_actions) in cases {
        assert_eq!(
            pop_row_context_menu_decision(RowMenuKind::Account, busy, hidden_hotp),
            PopRowContextMenuDecision::Pop {
                copy_sensitive: want_copy,
                actions_sensitive: want_actions,
            },
            "account row (busy={busy}, hidden_hotp={hidden_hotp})",
        );
    }
}

#[test]
fn row_menu_kind_from_is_section_maps_both_ways() {
    // The widget layer threads `RowItem::is_section()` straight in.
    assert_eq!(RowMenuKind::from_is_section(true), RowMenuKind::Section);
    assert_eq!(RowMenuKind::from_is_section(false), RowMenuKind::Account);
    assert!(RowMenuKind::Section.is_section());
    assert!(!RowMenuKind::Account.is_section());
}

// ===========================================================================
// 3. Controller-set shadow.
// ===========================================================================

#[test]
fn account_row_installs_gesture_plus_three_keyboard_triggers() {
    // An account row installs the secondary `gtk::GestureClick` plus
    // ONE `gtk::ShortcutController` carrying Menu, Shift+F10, Shift+E
    // (in that order).
    let set = install_row_context_menu_controllers_decision(false);
    assert_eq!(
        set,
        ControllerSet {
            gesture_click: true,
            shortcut_triggers: vec![
                RowMenuTrigger::Menu,
                RowMenuTrigger::ShiftF10,
                RowMenuTrigger::ShiftE,
            ],
        },
    );
    assert!(!set.is_empty());
}

#[test]
fn section_row_installs_no_controllers() {
    // Section rows install neither the gesture nor the shortcut
    // controller — the menu is suppressed entirely.
    let set = install_row_context_menu_controllers_decision(true);
    assert_eq!(set, ControllerSet::empty());
    assert!(set.is_empty());
    assert!(!set.gesture_click);
    assert!(set.shortcut_triggers.is_empty());
}

#[test]
fn keyboard_trigger_strings_match_gtk_parse_spelling() {
    // The descriptor's `gtk::ShortcutTrigger::parse_string` spellings
    // must match what the widget layer parses, and the pointer
    // gesture carries no keyboard spelling.
    assert_eq!(
        RowMenuTrigger::SecondaryClick.shortcut_trigger_string(),
        None
    );
    assert_eq!(RowMenuTrigger::Menu.shortcut_trigger_string(), Some("Menu"));
    assert_eq!(
        RowMenuTrigger::ShiftF10.shortcut_trigger_string(),
        Some("<Shift>F10"),
    );
    assert_eq!(
        RowMenuTrigger::ShiftE.shortcut_trigger_string(),
        Some("<Shift>e"),
    );
}

// ===========================================================================
// 4. Shift+E on a focused account row activates `row.edit`.
// ===========================================================================

#[test]
fn shift_e_on_account_row_activates_edit_and_routes_to_open_edit_dialog() {
    // The `Shift+E` shortcut targets `gtk::NamedAction("row.edit")`,
    // which fires the same `row.edit` action the kebab "Edit…" entry
    // does. Exercising the dispatch + route mirrors the per-row
    // action group: it must yield `OpenEditDialog(id)`.
    let id = AccountId::new();

    // The shortcut is only installed on account rows, and (no modal
    // open) it activates.
    assert_eq!(
        row_edit_shortcut_decision(false, false),
        RowEditShortcutDecision::ActivateEdit,
    );

    // Firing `row.edit` routes to `OpenEditDialog(id)`.
    assert_eq!(
        route_action(ROW_EDIT_ACTION_NAME, id),
        Some(AccountListOutput::OpenEditDialog(id)),
    );
}

#[test]
fn section_row_does_not_install_shift_e_controller() {
    // Section rows install no shortcut controller, so the `Shift+E`
    // trigger can never fire from a section row. The controller-set
    // shadow carries no triggers, and the edit-shortcut decision
    // rejects on a section row even if the key somehow reached it.
    let set = install_row_context_menu_controllers_decision(true);
    assert!(!set.shortcut_triggers.contains(&RowMenuTrigger::ShiftE));
    assert_eq!(
        row_edit_shortcut_decision(true, false),
        RowEditShortcutDecision::Reject,
    );
}

// ===========================================================================
// 5. Shift+E silently rejected while a modal dialog is open.
// ===========================================================================

#[test]
fn shift_e_rejected_while_modal_dialog_open() {
    // While a modal `adw::Dialog` is open it captures the keystroke
    // before the row controller, so no new `OpenEditDialog` is
    // emitted. Pin that the decision rejects on `modal_open == true`
    // for an account row, and that no output is produced.
    let decision = row_edit_shortcut_decision(false, true);
    assert_eq!(decision, RowEditShortcutDecision::Reject);
    assert!(!decision.activates());

    // The guard short-circuits before any `row.edit` dispatch, so the
    // emitted output set is empty.
    let id = AccountId::new();
    let emitted: Option<AccountListOutput> = if decision.activates() {
        route_action(ROW_EDIT_ACTION_NAME, id)
    } else {
        None
    };
    assert_eq!(emitted, None, "no OpenEditDialog while a modal is open");
}

#[test]
fn shift_e_decision_truth_table() {
    // Full (is_section, modal_open) truth table: activate only for an
    // account row with no modal open.
    assert_eq!(
        row_edit_shortcut_decision(false, false),
        RowEditShortcutDecision::ActivateEdit,
    );
    assert_eq!(
        row_edit_shortcut_decision(false, true),
        RowEditShortcutDecision::Reject,
    );
    assert_eq!(
        row_edit_shortcut_decision(true, false),
        RowEditShortcutDecision::Reject,
    );
    assert_eq!(
        row_edit_shortcut_decision(true, true),
        RowEditShortcutDecision::Reject,
    );
}

// ===========================================================================
// 6. Single-popover invariant: pop / refresh / lock all drop a prior.
// ===========================================================================

#[test]
fn single_popover_invariant_drops_prior_on_pop_refresh_and_lock() {
    // The single-popover invariant: whenever a fresh popover is
    // popped, or a refresh splices the store, or a lock tears down
    // the vault, any prior popover is unparented + dropped. With a
    // prior present, all three causes return `UnparentPrior`.
    for cause in [
        PopoverInvalidation::Pop,
        PopoverInvalidation::Refresh,
        PopoverInvalidation::Lock,
    ] {
        assert_eq!(
            prior_popover_disposition(cause, true),
            PriorPopoverDisposition::UnparentPrior,
            "cause {cause:?} with a prior popover unparents it",
        );
        assert!(prior_popover_disposition(cause, true).should_unparent());
    }
}

#[test]
fn single_popover_invariant_no_op_without_prior() {
    // With no prior popover, every cause is a no-op (nothing to
    // unparent) — popping the first popover does not try to drop a
    // non-existent one.
    for cause in [
        PopoverInvalidation::Pop,
        PopoverInvalidation::Refresh,
        PopoverInvalidation::Lock,
    ] {
        assert_eq!(
            prior_popover_disposition(cause, false),
            PriorPopoverDisposition::Nothing,
            "cause {cause:?} without a prior popover is a no-op",
        );
        assert!(!prior_popover_disposition(cause, false).should_unparent());
    }
}

// ===========================================================================
// 7. Per-row action targets resolve to the same group as the kebab.
// ===========================================================================

#[test]
fn row_body_action_targets_route_identically_to_kebab() {
    // The right-click / keyboard popover targets the SAME per-row
    // `gio::SimpleActionGroup` the kebab installs, so activating
    // `row.copy` / `row.edit` / `row.show-qr` / `row.remove` routes
    // to `CopyCode` / `OpenEditDialog` / `OpenExportQrDialog` /
    // `OpenRemoveDialog` with the row's `AccountId` — identical to
    // the kebab's `build_kebab_action_group` closures.
    let id = AccountId::new();
    assert_eq!(
        route_action(ROW_COPY_ACTION_NAME, id),
        Some(AccountListOutput::CopyCode(id)),
    );
    assert_eq!(
        route_action(ROW_EDIT_ACTION_NAME, id),
        Some(AccountListOutput::OpenEditDialog(id)),
    );
    assert_eq!(
        route_action(ROW_SHOW_QR_ACTION_NAME, id),
        Some(AccountListOutput::OpenExportQrDialog(id)),
    );
    assert_eq!(
        route_action(ROW_REMOVE_ACTION_NAME, id),
        Some(AccountListOutput::OpenRemoveDialog(id)),
    );
}

#[test]
fn row_body_unknown_action_is_silent_no_op() {
    // An unrecognized action name on the shared group is a silent
    // no-op (the dispatch table returns `None`), so a stale popover
    // target never crashes the row.
    let id = AccountId::new();
    assert_eq!(route_action("nope", id), None);
    assert_eq!(route_action("", id), None);
    assert_eq!(route_action("row.rename", id), None);
}
