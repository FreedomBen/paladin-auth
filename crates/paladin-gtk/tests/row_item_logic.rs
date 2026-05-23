// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic tests for `paladin_gtk::row_item::RowItem`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.2.2 / §A.2.5, the
//! unlocked vault list is driven by a `gio::ListStore<RowItem>` rather
//! than a `FactoryVecDeque`. Per-tick TOTP refreshes mutate the
//! existing `RowItem`'s display through [`RowItem::set_display`],
//! which must emit a `display-changed` signal so cell factories rebind
//! their widgets against the new values without the store calling
//! `splice` (the historical "rebind every visible row mid-frame and
//! drop clicks" bug).
//!
//! These tests cover the `GObject` subclass without spinning up GTK —
//! `glib::Object::new::<RowItem>()` registers the type lazily and the
//! `display-changed` signal fires on the local main context, so no
//! display server is required.

use std::cell::Cell;
use std::rc::Rc;

use paladin_core::{AccountId, AccountKindSummary};
use paladin_gtk::account_list::{hidden_row_display, AccountRowModel};
use paladin_gtk::account_row::{CodeDisplay, RowDisplay};
use paladin_gtk::row_item::{RowItem, RowKind, ROW_ITEM_DISPLAY_CHANGED_SIGNAL};

use relm4::gtk::glib::prelude::*;

fn totp_model() -> AccountRowModel {
    AccountRowModel {
        id: AccountId::new(),
        display_label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
        icon_hint: Some("acme".to_string()),
        issuer: Some("Acme".to_string()),
    }
}

fn visible_totp_display(label: &str) -> RowDisplay {
    RowDisplay {
        label: label.to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Visible("123456".to_string()),
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        next_button_enabled: false,
        progress_visible: true,
        progress: None,
        kebab_visible: true,
        kebab_enabled: true,
    }
}

#[test]
fn from_row_model_seeds_id_icon_hint_and_hidden_display() {
    let model = totp_model();
    let expected_id = model.id;
    let expected_display = hidden_row_display(&model);

    let item = RowItem::from_row_model(&model);

    assert_eq!(item.account_id(), Some(expected_id));
    assert_eq!(item.icon_hint(), Some("acme".to_string()));
    assert_eq!(item.display(), expected_display);
    assert!(!item.busy());
}

#[test]
fn from_row_model_with_no_icon_hint_returns_none() {
    let mut model = totp_model();
    model.icon_hint = None;

    let item = RowItem::from_row_model(&model);

    assert_eq!(item.icon_hint(), None);
}

#[test]
fn set_display_replaces_stored_display() {
    let model = totp_model();
    let item = RowItem::from_row_model(&model);

    let new_display = visible_totp_display(&model.display_label);
    item.set_display(new_display.clone());

    assert_eq!(item.display(), new_display);
}

#[test]
fn set_display_emits_display_changed_signal() {
    let model = totp_model();
    let item = RowItem::from_row_model(&model);

    let counter = Rc::new(Cell::new(0u32));
    let counter_c = counter.clone();
    let _handler_id = item.connect_local(ROW_ITEM_DISPLAY_CHANGED_SIGNAL, false, move |_args| {
        counter_c.set(counter_c.get() + 1);
        None
    });

    item.set_display(visible_totp_display(&model.display_label));
    assert_eq!(
        counter.get(),
        1,
        "set_display must fire display-changed once"
    );

    item.set_display(visible_totp_display(&model.display_label));
    assert_eq!(
        counter.get(),
        2,
        "every set_display call must re-fire display-changed",
    );
}

#[test]
fn set_busy_updates_value_and_emits_display_changed() {
    let model = totp_model();
    let item = RowItem::from_row_model(&model);

    let counter = Rc::new(Cell::new(0u32));
    let counter_c = counter.clone();
    let _handler_id = item.connect_local(ROW_ITEM_DISPLAY_CHANGED_SIGNAL, false, move |_args| {
        counter_c.set(counter_c.get() + 1);
        None
    });

    item.set_busy(true);
    assert!(item.busy());
    assert_eq!(counter.get(), 1);

    // Idempotent — repeating the same value does not re-emit so the
    // cell-factory rebind loop is not spuriously woken.
    item.set_busy(true);
    assert_eq!(counter.get(), 1);

    item.set_busy(false);
    assert!(!item.busy());
    assert_eq!(counter.get(), 2);
}

#[test]
fn default_row_item_has_no_account_id() {
    let item = RowItem::default();
    assert_eq!(item.account_id(), None);
    assert_eq!(item.icon_hint(), None);
    assert!(!item.busy());
}

// ---------------------------------------------------------------------------
// RowKind — section header rows interleaved into the store.
// ---------------------------------------------------------------------------

#[test]
fn from_row_model_creates_account_kind() {
    let model = totp_model();
    let item = RowItem::from_row_model(&model);
    assert_eq!(item.kind(), RowKind::Account);
    assert_eq!(item.section_title(), None);
}

#[test]
fn section_constructor_creates_section_kind() {
    let item = RowItem::section("Acme");
    assert_eq!(item.kind(), RowKind::Section("Acme".to_string()));
    assert_eq!(item.section_title(), Some("Acme".to_string()));
    assert_eq!(item.account_id(), None);
    assert_eq!(item.icon_hint(), None);
    assert!(!item.busy());
}

#[test]
fn default_row_item_kind_is_account_placeholder() {
    let item = RowItem::default();
    assert_eq!(item.kind(), RowKind::Account);
}

#[test]
fn is_section_distinguishes_kinds() {
    assert!(RowItem::section("Other").is_section());
    assert!(!RowItem::from_row_model(&totp_model()).is_section());
}
