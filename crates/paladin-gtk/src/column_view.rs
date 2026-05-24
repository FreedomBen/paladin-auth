// SPDX-License-Identifier: AGPL-3.0-or-later

//! `gtk::ColumnView` helpers for the unlocked account list.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A, the unlocked
//! vault list is migrating from a `gtk::ListBox` + `FactoryVecDeque`
//! to a `gtk::ColumnView` driven by a `gio::ListStore<RowItem>` +
//! `gtk::SingleSelection`. The minimal-churn diff helpers here drive
//! `Refresh` / search-filter updates against the store without
//! tearing down `RowItem`s for accounts that survive the refresh.
//!
//! The diff layer is split into a pure-logic [`splice_plan`] (so the
//! op table is exercised without a `gio::ListStore`) and an apply
//! driver [`apply_splice_plan`] that calls `gio::ListStore::splice`.
//! Matching is by `AccountId`; reordering — which the vault's
//! insertion-order contract in `docs/DESIGN.md` rules out — falls
//! back to a tail rebuild rather than tracking moves.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::rc::Rc;

use paladin_core::AccountId;
use relm4::gtk;
use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;
use relm4::gtk::glib;
use relm4::gtk::pango;
use relm4::gtk::prelude::*;
use relm4::Sender;

use crate::account_list::{row_section_header, AccountListOutput, AccountRowModel};
use crate::account_row::{
    build_kebab_menu_model, dispatch_row_action, format_counter_label, format_seconds_remaining,
    progress_fraction, progress_urgency, AccountRowOutput, CodeDisplay, HIDDEN_CODE_PLACEHOLDER,
    PROGRESS_URGENCY_CSS_CLASSES, ROW_ACTION_GROUP_NAME, ROW_COPY_ACTION_NAME,
    ROW_NEXT_ACTION_NAME, ROW_REMOVE_ACTION_NAME, ROW_RENAME_ACTION_NAME,
};
use crate::icon_resolution::{resolve_display_icon, PLACEHOLDER_ICON_NAME};
use crate::row_item::{RowItem, RowKind, ROW_ITEM_DISPLAY_CHANGED_SIGNAL};

/// Stable identity for a row in the `gtk::ColumnView`'s store.
///
/// Account rows are keyed by their `AccountId`; section header rows
/// are keyed by their heading text (issuer name, which is unique
/// within the list per the section-grouping contract in
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2.4). The
/// diff layer in [`splice_plan`] / [`apply_splice_plan`] operates
/// on this key so a section toggle preserves account-row identity
/// across the rebuild.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum RowKey {
    /// Account row keyed by its stable `AccountId`.
    Account(AccountId),
    /// Section header row keyed by its heading text.
    Section(String),
}

impl RowKey {
    /// Extract the [`RowKey`] of a live `RowItem` in the store, or
    /// `None` for a freshly default-constructed item that has not
    /// yet been seeded.
    #[must_use]
    pub fn from_row_item(item: &RowItem) -> Option<Self> {
        match item.kind() {
            RowKind::Section(title) => Some(Self::Section(title)),
            RowKind::Account => item.account_id().map(Self::Account),
        }
    }
}

/// One position in the interleaved (section + account) row sequence.
///
/// `Account` carries the index into the source `Vec<AccountRowModel>`
/// (cheap and stable; the caller resolves it back to the model).
/// `Section` carries the heading text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterleavedRow {
    /// A section heading; the inner text is the heading from
    /// [`crate::account_list::issuer_group_header`].
    Section(String),
    /// An account row, indexed by position in the source
    /// `AccountRowModel` slice.
    Account(usize),
}

/// Interleave section headers among account rows for the
/// `gtk::ColumnView`'s store.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2.4, the
/// `gtk::ColumnView` migration moves section grouping out of
/// `gtk::ListBox::set_header_func` and into the model: section
/// headers become `RowItem`s interleaved with account rows. The
/// section dispatch rule is the same as the existing
/// [`row_section_header`] predicate so user-visible grouping is
/// preserved.
///
/// When `show_section_headers` is `false`, returns one
/// [`InterleavedRow::Account`] per input row in order. When `true`,
/// emits an [`InterleavedRow::Section`] before each account-row run
/// whose issuer differs from the previous row.
#[must_use]
pub fn interleave_section_headers(
    rows: &[AccountRowModel],
    show_section_headers: bool,
) -> Vec<InterleavedRow> {
    if !show_section_headers {
        return (0..rows.len()).map(InterleavedRow::Account).collect();
    }
    let mut out = Vec::with_capacity(rows.len() * 2);
    for (i, row) in rows.iter().enumerate() {
        let prev = if i == 0 { None } else { Some(&rows[i - 1]) };
        if let Some(title) = row_section_header(prev, row) {
            out.push(InterleavedRow::Section(title.to_string()));
        }
        out.push(InterleavedRow::Account(i));
    }
    out
}

/// A single `gio::ListStore::splice` operation.
///
/// Positions are interpreted against the store as it stands *after*
/// applying every prior op in the same plan — the diff walker tracks
/// the cursor so consumers do not need to track running offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpliceOp {
    /// Remove `n_remove` consecutive items at `position`.
    Remove {
        /// Position in the running store state.
        position: u32,
        /// Number of consecutive items to remove.
        n_remove: u32,
    },
    /// Insert items at `position`. `indices` are positions in the
    /// `new_rows` slice supplied to [`apply_splice_plan`] from which
    /// to take fresh `AccountRowModel`s for the new `RowItem`s.
    Insert {
        /// Position in the running store state at which to insert.
        position: u32,
        /// Indices into the caller's `new_rows` slice.
        indices: Vec<usize>,
    },
}

/// Compute a minimal sequence of `SpliceOp`s that transforms a store
/// holding `old` (`AccountId`s in order) into one holding `new`.
///
/// Matching is by `AccountId`. The walker emits one coalesced
/// `Remove` per run of items not present in `new` and one coalesced
/// `Insert` per run of items not present in `old`. For the common
/// "subset of vault insertion order" case (search filter,
/// add/remove), this produces optimal output. A genuine reordering
/// — where some `id` is in both inputs but at different positions
/// such that neither a pure remove nor a pure insert advances the
/// cursor — falls back to a tail rebuild from the first divergent
/// position. The vault's insertion-order contract in
/// `docs/DESIGN.md` makes that fallback unreachable in practice;
/// the walker keeps it as a defensive guard so the helper stays
/// total.
#[must_use]
pub fn splice_plan<K: Hash + Eq + Clone>(old: &[K], new: &[K]) -> Vec<SpliceOp> {
    let new_set: HashSet<K> = new.iter().cloned().collect();
    let old_set: HashSet<K> = old.iter().cloned().collect();

    let mut ops = Vec::new();
    let mut o = 0usize;
    let mut n = 0usize;
    let mut pos: u32 = 0;

    loop {
        // Skip the matching prefix at the cursor.
        while o < old.len() && n < new.len() && old[o] == new[n] {
            o += 1;
            n += 1;
            pos += 1;
        }

        if o == old.len() && n == new.len() {
            break;
        }

        // Run of removes: `old` items at `o..` not present in `new` at all.
        let mut remove_count = 0usize;
        while o + remove_count < old.len() && !new_set.contains(&old[o + remove_count]) {
            remove_count += 1;
        }
        if remove_count > 0 {
            ops.push(SpliceOp::Remove {
                position: pos,
                #[allow(clippy::cast_possible_truncation)]
                n_remove: remove_count as u32,
            });
            o += remove_count;
            continue;
        }

        // Run of inserts: `new` items at `n..` not present in `old` at all.
        let mut insert_count = 0usize;
        while n + insert_count < new.len() && !old_set.contains(&new[n + insert_count]) {
            insert_count += 1;
        }
        if insert_count > 0 {
            let indices: Vec<usize> = (n..n + insert_count).collect();
            ops.push(SpliceOp::Insert {
                position: pos,
                indices,
            });
            n += insert_count;
            #[allow(clippy::cast_possible_truncation)]
            {
                pos += insert_count as u32;
            }
            continue;
        }

        // Genuine reorder: both old[o] and new[n] are present in the
        // other input but at different positions. Tail rebuild from
        // here so the helper stays total.
        let tail_old = u32::try_from(old.len() - o).unwrap_or(u32::MAX);
        let tail_new: Vec<usize> = (n..new.len()).collect();
        if tail_old > 0 {
            ops.push(SpliceOp::Remove {
                position: pos,
                n_remove: tail_old,
            });
        }
        if !tail_new.is_empty() {
            ops.push(SpliceOp::Insert {
                position: pos,
                indices: tail_new,
            });
        }
        break;
    }

    ops
}

/// Apply a [`splice_plan`] to a real `gio::ListStore<RowItem>`.
///
/// Snapshots the store's current `AccountId` order, computes the
/// plan against `new_rows`, then walks the ops applying each as a
/// `gio::ListStore::splice` call. Existing `RowItem` instances are
/// reused for accounts that appear in both the prior and new sets so
/// per-row state (the per-tick `RowDisplay` cache, signal
/// connections set up in cell-factory `bind`) survives the refresh.
///
/// Pure-logic regressions in [`splice_plan`] are pinned by
/// `tests/column_view_logic.rs`; the apply layer's behavior against
/// a real store is exercised there too.
pub fn apply_splice_plan(store: &gio::ListStore, new_rows: &[AccountRowModel]) {
    let n_old = store.n_items();

    // Snapshot existing AccountIds in store order.
    let mut old_ids: Vec<AccountId> = Vec::with_capacity(n_old as usize);
    let mut by_id: HashMap<AccountId, RowItem> = HashMap::with_capacity(n_old as usize);
    for i in 0..n_old {
        let Some(obj) = store.item(i) else { continue };
        let Ok(item) = obj.downcast::<RowItem>() else {
            continue;
        };
        if let Some(id) = item.account_id() {
            old_ids.push(id);
            by_id.insert(id, item);
        }
    }

    let new_ids: Vec<AccountId> = new_rows.iter().map(|m| m.id).collect();
    let plan = splice_plan(&old_ids, &new_ids);

    for op in plan {
        match op {
            SpliceOp::Remove { position, n_remove } => {
                let nothing: &[glib::Object] = &[];
                store.splice(position, n_remove, nothing);
            }
            SpliceOp::Insert { position, indices } => {
                let items: Vec<glib::Object> = indices
                    .into_iter()
                    .map(|i| {
                        let model = &new_rows[i];
                        by_id
                            .remove(&model.id)
                            .unwrap_or_else(|| RowItem::from_row_model(model))
                            .upcast()
                    })
                    .collect();
                store.splice(position, 0, &items);
            }
        }
    }
}

/// Apply an [`interleave_section_headers`] result against a real
/// `gio::ListStore<RowItem>`.
///
/// Snapshots the store's current [`RowKey`] order, computes the
/// minimal plan against the interleaved sequence, then applies it.
/// `RowItem` identity (account rows) and section-row reuse are both
/// preserved across the diff so the live `gtk::SingleSelection`
/// position survives a section-header toggle (when the toggle does
/// not change which account rows are present).
pub fn apply_interleaved_splice_plan(
    store: &gio::ListStore,
    new_rows: &[AccountRowModel],
    show_section_headers: bool,
) {
    let n_old = store.n_items();

    let mut old_keys: Vec<RowKey> = Vec::with_capacity(n_old as usize);
    let mut by_key: HashMap<RowKey, RowItem> = HashMap::with_capacity(n_old as usize);
    for i in 0..n_old {
        let Some(obj) = store.item(i) else { continue };
        let Ok(item) = obj.downcast::<RowItem>() else {
            continue;
        };
        if let Some(key) = RowKey::from_row_item(&item) {
            old_keys.push(key.clone());
            by_key.insert(key, item);
        }
    }

    let interleaved = interleave_section_headers(new_rows, show_section_headers);
    let new_keys: Vec<RowKey> = interleaved
        .iter()
        .map(|row| match row {
            InterleavedRow::Section(title) => RowKey::Section(title.clone()),
            InterleavedRow::Account(idx) => RowKey::Account(new_rows[*idx].id),
        })
        .collect();
    let plan = splice_plan(&old_keys, &new_keys);

    for op in plan {
        match op {
            SpliceOp::Remove { position, n_remove } => {
                let nothing: &[glib::Object] = &[];
                store.splice(position, n_remove, nothing);
            }
            SpliceOp::Insert { position, indices } => {
                let items: Vec<glib::Object> = indices
                    .into_iter()
                    .map(|i| {
                        let row = &interleaved[i];
                        let key = match row {
                            InterleavedRow::Section(title) => RowKey::Section(title.clone()),
                            InterleavedRow::Account(idx) => RowKey::Account(new_rows[*idx].id),
                        };
                        let existing = by_key.remove(&key);
                        existing
                            .unwrap_or_else(|| match row {
                                InterleavedRow::Section(title) => RowItem::section(title),
                                InterleavedRow::Account(idx) => {
                                    RowItem::from_row_model(&new_rows[*idx])
                                }
                            })
                            .upcast()
                    })
                    .collect();
                store.splice(position, 0, &items);
            }
        }
    }
}

// ===========================================================================
// Cell factories for `gtk::ColumnView`.
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2 / §A.4 the
// five columns ("Account", "Code", "Time", "Copy", "Kebab") are each
// driven by a `gtk::SignalListItemFactory`. Cells are recycled across
// row positions: each factory's `setup` builds the widget tree once
// per pool entry, `bind` wires the current `RowItem` to those widgets
// (and subscribes to the `display-changed` signal so per-tick
// refreshes flow through), and `unbind` tears the subscription down.
//
// Subscription tracking uses a shared `Rc<RefCell<HashMap>>` keyed by
// `gtk::ListItem` pointer — the crate forbids `unsafe`, so we can't
// stash a `SignalHandlerId` directly on the `ListItem` via the
// (unsafe) glib data-attachment API. The `as_ptr` round-trip is safe
// for the lifetime of the `ListItem`, which is what we need.
// ===========================================================================

/// Per-factory map of `gtk::ListItem` → live `display-changed`
/// signal handler on the bound `RowItem`. `unbind` looks the entry
/// up and disconnects it so the cell never receives stale updates
/// for a row it is no longer rendering.
type HandlerMap = Rc<RefCell<HashMap<usize, glib::SignalHandlerId>>>;

fn list_item_key(list_item: &gtk::ListItem) -> usize {
    list_item.as_ptr() as usize
}

fn cast_list_item(obj: &glib::Object) -> gtk::ListItem {
    obj.downcast_ref::<gtk::ListItem>()
        .expect("SignalListItemFactory item is a gtk::ListItem")
        .clone()
}

fn try_row_item(list_item: &gtk::ListItem) -> Option<RowItem> {
    list_item.item()?.downcast::<RowItem>().ok()
}

/// Disconnect the prior `display-changed` handler for `list_item`,
/// if any. Called from every cell-factory `unbind`.
fn drop_handler(handlers: &HandlerMap, list_item: &gtk::ListItem) {
    let key = list_item_key(list_item);
    let removed = handlers.borrow_mut().remove(&key);
    if let Some(handler) = removed {
        if let Some(item) = try_row_item(list_item) {
            item.disconnect(handler);
        }
    }
}

/// Subscribe `rebind` to the current `RowItem`'s
/// [`ROW_ITEM_DISPLAY_CHANGED_SIGNAL`] and stash the handler id in
/// `handlers` keyed by `list_item` so the matching `unbind` can drop
/// it. `rebind` is also called once immediately so the initial state
/// of the widget reflects the bound row.
fn install_display_subscription<F>(
    handlers: &HandlerMap,
    list_item: &gtk::ListItem,
    item: &RowItem,
    rebind: F,
) where
    F: Fn(&RowItem) + 'static,
{
    rebind(item);
    let item_for_signal = item.clone();
    let handler = item.connect_local(ROW_ITEM_DISPLAY_CHANGED_SIGNAL, false, move |_args| {
        rebind(&item_for_signal);
        None
    });
    handlers
        .borrow_mut()
        .insert(list_item_key(list_item), handler);
}

/// Build the cell factory for the "Account" column.
///
/// Cell layout (account row): leading icon (24 px) + ellipsized
/// `<issuer>:<label>` `gtk::Label` (`hexpand`). Section rows render
/// the heading text in a single bold-dim label and hide the icon.
#[must_use]
pub fn build_account_column_factory() -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    let handlers: HandlerMap = Rc::new(RefCell::new(HashMap::new()));

    factory.connect_setup(|_, item| {
        let list_item = cast_list_item(item);
        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(8)
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
            .ellipsize(pango::EllipsizeMode::End)
            .build();
        container.append(&icon);
        container.append(&label);
        list_item.set_child(Some(&container));
    });

    let handlers_b = Rc::clone(&handlers);
    factory.connect_bind(move |_, item| {
        let list_item = cast_list_item(item);
        let Some(row_item) = try_row_item(&list_item) else {
            return;
        };
        let Some(container) = list_item.child().and_downcast::<gtk::Box>() else {
            return;
        };

        // Section rows are non-selectable; account rows are selectable.
        list_item.set_selectable(!row_item.is_section());

        let container_for_rebind = container.clone();
        install_display_subscription(&handlers_b, &list_item, &row_item, move |item| {
            bind_account_cell(&container_for_rebind, item);
        });
    });

    let handlers_u = Rc::clone(&handlers);
    factory.connect_unbind(move |_, item| {
        let list_item = cast_list_item(item);
        drop_handler(&handlers_u, &list_item);
    });

    factory
}

fn bind_account_cell(container: &gtk::Box, item: &RowItem) {
    let Some(icon) = container.first_child().and_downcast::<gtk::Image>() else {
        return;
    };
    let Some(label) = icon.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    match item.kind() {
        RowKind::Section(title) => {
            icon.set_visible(false);
            label.set_label(&title);
            label.remove_css_class("body");
            label.add_css_class("dim-label");
            label.add_css_class("heading");
            container.set_tooltip_text(None);
        }
        RowKind::Account => {
            icon.set_visible(true);
            label.remove_css_class("dim-label");
            label.remove_css_class("heading");
            let display = item.display();
            label.set_label(&display.label);
            let icon_theme =
                gtk::IconTheme::for_display(&gtk::prelude::WidgetExt::display(container));
            let icon_hint = item.icon_hint();
            let icon_name =
                resolve_display_icon(icon_hint.as_deref(), |slug| icon_theme.has_icon(slug));
            icon.set_icon_name(Some(icon_name));
            container.set_tooltip_text(Some(ROW_BODY_COPY_TOOLTIP));
        }
    }
}

/// Build the cell factory for the "Code" column.
///
/// Cell layout (account row): right-aligned `numeric`-class
/// `gtk::Label` showing the visible code (or
/// [`HIDDEN_CODE_PLACEHOLDER`] for hidden HOTP rows), an inline
/// HOTP "next" `gtk::Button` immediately adjacent per §A.6 decision
/// 4, and an optional `#N` counter `gtk::Label` for HOTP rows.
/// Section rows render nothing.
///
/// The "next" button's `connect_clicked` closure is re-installed on
/// each `bind` so it always closes over the *current* `RowItem`'s
/// `AccountId`. The closure emits
/// [`AccountListOutput::AdvanceHotp`] through the supplied sender.
#[must_use]
pub fn build_code_column_factory(sender: Sender<AccountListOutput>) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    let handlers: HandlerMap = Rc::new(RefCell::new(HashMap::new()));
    let click_handlers: Rc<RefCell<HashMap<usize, glib::SignalHandlerId>>> =
        Rc::new(RefCell::new(HashMap::new()));

    factory.connect_setup(|_, item| {
        let list_item = cast_list_item(item);
        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(6)
            .halign(gtk::Align::End)
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
        let next = gtk::Button::builder()
            .icon_name("view-refresh-symbolic")
            .tooltip_text("Reveal next HOTP code")
            .valign(gtk::Align::Center)
            .build();
        next.add_css_class("flat");
        container.append(&counter);
        container.append(&code);
        container.append(&next);
        list_item.set_child(Some(&container));
    });

    let handlers_b = Rc::clone(&handlers);
    let click_handlers_b = Rc::clone(&click_handlers);
    factory.connect_bind(move |_, item| {
        let list_item = cast_list_item(item);
        let Some(row_item) = try_row_item(&list_item) else {
            return;
        };
        let Some(container) = list_item.child().and_downcast::<gtk::Box>() else {
            return;
        };
        let Some(next_button) = container.last_child().and_downcast::<gtk::Button>() else {
            return;
        };

        let container_for_rebind = container.clone();
        install_display_subscription(&handlers_b, &list_item, &row_item, move |item| {
            bind_code_cell(&container_for_rebind, item);
        });

        // Wire the inline HOTP "next" button on every bind so it
        // closes over the *current* `RowItem`'s `AccountId`. Drop
        // any prior handler first so reused cells don't accumulate
        // closures.
        let key = list_item_key(&list_item);
        if let Some(prev) = click_handlers_b.borrow_mut().remove(&key) {
            next_button.disconnect(prev);
        }
        if let Some(id) = row_item.account_id() {
            let sender_c = sender.clone();
            let handler = next_button.connect_clicked(move |_| {
                let _ = sender_c.send(AccountListOutput::AdvanceHotp(id));
            });
            click_handlers_b.borrow_mut().insert(key, handler);
        }
    });

    let handlers_u = Rc::clone(&handlers);
    let click_handlers_u = Rc::clone(&click_handlers);
    factory.connect_unbind(move |_, item| {
        let list_item = cast_list_item(item);
        drop_handler(&handlers_u, &list_item);
        let key = list_item_key(&list_item);
        if let Some(handler) = click_handlers_u.borrow_mut().remove(&key) {
            if let Some(button) = list_item
                .child()
                .and_then(|c| c.downcast::<gtk::Box>().ok())
                .and_then(|c| c.last_child())
                .and_then(|c| c.downcast::<gtk::Button>().ok())
            {
                button.disconnect(handler);
            }
        }
    });

    factory
}

fn bind_code_cell(container: &gtk::Box, item: &RowItem) {
    let Some(counter) = container.first_child().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(code) = counter.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(next) = code.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };

    if item.is_section() {
        counter.set_visible(false);
        code.set_visible(false);
        next.set_visible(false);
        container.set_tooltip_text(None);
        return;
    }

    let mut display = item.display();
    crate::account_row::apply_busy_mask(&mut display, item.busy());

    container.set_tooltip_text(Some(ROW_BODY_COPY_TOOLTIP));
    code.set_visible(true);
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

    next.set_visible(display.next_button_visible);
    next.set_sensitive(display.next_button_enabled);
}

/// Glyph prefix the "Next" column cell prepends to the upcoming
/// TOTP digits.
///
/// `↪` (U+21AA RIGHTWARDS ARROW WITH HOOK) signals "this row's
/// follow-up code" without competing with the current code's
/// visual weight.  Sourced as a `pub const` so the cell factory,
/// the snapshot tests, and the per-row reducer tests all agree on
/// the exact byte sequence (the existing TUI commit pins the same
/// glyph in `paladin-tui/src/view/list.rs`).
pub const NEXT_CODE_PREFIX: &str = "↪ ";

/// Tooltip text installed on the non-button cells of an account
/// row (account, code, time) so a hover surfaces the consequence
/// of `single_click_activate(true)` activation: the click copies
/// the current code.  Parallels the Next column button's
/// `"Copy upcoming code"` wording so the two click-targets read
/// as a verb-led pair.  Section rows clear the tooltip in their
/// bind branch since they are non-selectable.
pub const ROW_BODY_COPY_TOOLTIP: &str = "Copy current code";

/// Build the cell factory for the "Next" column.
///
/// Cell layout: a single flat [`gtk::Button`] (carrying the
/// `.flat` libadwaita class) wrapping a [`gtk::Label`] (carrying
/// the `.dim-label` and `.numeric` stock GTK4 / libadwaita
/// classes).  Clicking the button emits
/// [`AccountListOutput::CopyNextCode`] for the bound row's
/// [`AccountId`]; the visual treatment makes the cell read as
/// text while staying click-targetable.
///
/// Per-row rendering:
///
/// * TOTP rows with a populated [`RowDisplay::next_code`] →
///   label is `"↪ <digits>"`, button is sensitive.
/// * TOTP rows whose ticker has not yet landed the first
///   `Vault::totp_next_code` (`next_code = None`) → label is
///   empty, button is `sensitive = false`.
/// * HOTP rows → projection answers `None` per
///   [`crate::account_row::next_code_display`]; label empty,
///   button insensitive (the affordance carries the rejection
///   signal so a separate toast is unnecessary per
///   `docs/IMPLEMENTATION_PLAN_04_GTK.md` "Next-code column
///   implementation" → Click target).
/// * Section rows → the cell hides the button entirely (mirrors
///   the existing copy / kebab cells' section-row handling).
///
/// While the parent `AppModel` is `UnlockedBusy`, the row's busy
/// latch dims the button via the same per-control busy mask the
/// `Copy` cell honors — a transient mutation must not let the
/// user enqueue a follow-up clipboard write.
///
/// Click handlers are re-installed on every `bind` so each cell
/// closes over the *current* row's `AccountId`.  `unbind`
/// disconnects both the `display-changed` subscription and the
/// click closure so cell recycling cannot carry stale ids forward
/// (mirrors `build_copy_column_factory`).
#[must_use]
pub fn build_next_code_column_factory(
    sender: Sender<AccountListOutput>,
) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    let handlers: HandlerMap = Rc::new(RefCell::new(HashMap::new()));
    let click_handlers: Rc<RefCell<HashMap<usize, glib::SignalHandlerId>>> =
        Rc::new(RefCell::new(HashMap::new()));

    factory.connect_setup(|_, item| {
        let list_item = cast_list_item(item);
        let label = gtk::Label::builder()
            .halign(gtk::Align::End)
            .xalign(1.0)
            .build();
        label.add_css_class("numeric");
        label.add_css_class("dim-label");
        let button = gtk::Button::builder()
            .child(&label)
            .tooltip_text("Copy upcoming code")
            .valign(gtk::Align::Center)
            .halign(gtk::Align::End)
            .build();
        button.add_css_class("flat");
        list_item.set_child(Some(&button));
    });

    let handlers_b = Rc::clone(&handlers);
    let click_handlers_b = Rc::clone(&click_handlers);
    factory.connect_bind(move |_, item| {
        let list_item = cast_list_item(item);
        let Some(row_item) = try_row_item(&list_item) else {
            return;
        };
        let Some(button) = list_item.child().and_downcast::<gtk::Button>() else {
            return;
        };

        let button_for_rebind = button.clone();
        install_display_subscription(&handlers_b, &list_item, &row_item, move |item| {
            bind_next_code_cell(&button_for_rebind, item);
        });

        let key = list_item_key(&list_item);
        if let Some(prev) = click_handlers_b.borrow_mut().remove(&key) {
            button.disconnect(prev);
        }
        if let Some(id) = row_item.account_id() {
            let sender_c = sender.clone();
            let handler = button.connect_clicked(move |_| {
                let _ = sender_c.send(AccountListOutput::CopyNextCode(id));
            });
            click_handlers_b.borrow_mut().insert(key, handler);
        }
    });

    let handlers_u = Rc::clone(&handlers);
    let click_handlers_u = Rc::clone(&click_handlers);
    factory.connect_unbind(move |_, item| {
        let list_item = cast_list_item(item);
        drop_handler(&handlers_u, &list_item);
        let key = list_item_key(&list_item);
        if let Some(handler) = click_handlers_u.borrow_mut().remove(&key) {
            if let Some(button) = list_item.child().and_downcast::<gtk::Button>() {
                button.disconnect(handler);
            }
        }
    });

    factory
}

fn bind_next_code_cell(button: &gtk::Button, item: &RowItem) {
    let Some(label) = button.child().and_downcast::<gtk::Label>() else {
        return;
    };

    if item.is_section() {
        button.set_visible(false);
        return;
    }
    button.set_visible(true);

    let display = item.display();
    if let Some(digits) = display.next_code.as_deref() {
        label.set_label(&format!("{NEXT_CODE_PREFIX}{digits}"));
        // While busy, dim the button — a transient mutation
        // must not let the user enqueue a follow-up clipboard
        // write through the next-code path either.  Mirrors
        // the `apply_busy_mask` gating on `copy_enabled`.
        button.set_sensitive(!item.busy());
    } else {
        label.set_label("");
        button.set_sensitive(false);
    }
}

/// Build the cell factory for the "Time" column.
///
/// Cell layout (account row): a horizontal [`gtk::Box`] holding a
/// centered [`gtk::ProgressBar`] (96 px wide) followed by a numeric
/// [`gtk::Label`] showing the seconds remaining in the active TOTP
/// window (e.g. `18s`). The seconds suffix mirrors the TUI's
/// gauge + countdown layout so the two front-ends read alike. Both
/// children bind from [`RowDisplay::progress`]. Section rows render
/// an empty placeholder; HOTP account rows render an empty
/// placeholder (no progress, no time window). The parent
/// `AccountListComponent` toggles the column itself off when no
/// account row carries a TOTP kind so vaults with only HOTP
/// accounts hide the column entirely.
#[must_use]
pub fn build_time_column_factory() -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    let handlers: HandlerMap = Rc::new(RefCell::new(HashMap::new()));

    factory.connect_setup(|_, item| {
        let list_item = cast_list_item(item);
        let container = gtk::Box::builder()
            .orientation(gtk::Orientation::Horizontal)
            .spacing(6)
            .valign(gtk::Align::Center)
            .build();
        let progress = gtk::ProgressBar::builder()
            .valign(gtk::Align::Center)
            .width_request(96)
            .show_text(false)
            .build();
        let secs = gtk::Label::builder()
            .valign(gtk::Align::Center)
            .xalign(1.0)
            .width_chars(3)
            .build();
        secs.add_css_class("numeric");
        secs.add_css_class("dim-label");
        container.append(&progress);
        container.append(&secs);
        list_item.set_child(Some(&container));
    });

    let handlers_b = Rc::clone(&handlers);
    factory.connect_bind(move |_, item| {
        let list_item = cast_list_item(item);
        let Some(row_item) = try_row_item(&list_item) else {
            return;
        };
        let Some(container) = list_item.child().and_downcast::<gtk::Box>() else {
            return;
        };
        let Some(progress) = container
            .first_child()
            .and_then(|w| w.downcast::<gtk::ProgressBar>().ok())
        else {
            return;
        };
        let Some(secs) = progress
            .next_sibling()
            .and_then(|w| w.downcast::<gtk::Label>().ok())
        else {
            return;
        };

        let container_for_rebind = container.clone();
        let progress_for_rebind = progress.clone();
        let secs_for_rebind = secs.clone();
        install_display_subscription(&handlers_b, &list_item, &row_item, move |item| {
            bind_time_cell(
                &container_for_rebind,
                &progress_for_rebind,
                &secs_for_rebind,
                item,
            );
        });
    });

    let handlers_u = Rc::clone(&handlers);
    factory.connect_unbind(move |_, item| {
        let list_item = cast_list_item(item);
        drop_handler(&handlers_u, &list_item);
    });

    factory
}

fn bind_time_cell(
    container: &gtk::Box,
    progress: &gtk::ProgressBar,
    secs: &gtk::Label,
    item: &RowItem,
) {
    for class in PROGRESS_URGENCY_CSS_CLASSES {
        progress.remove_css_class(class);
    }
    if item.is_section() {
        container.set_visible(false);
        progress.set_visible(false);
        secs.set_visible(false);
        progress.set_fraction(0.0);
        secs.set_label("");
        container.set_tooltip_text(None);
        return;
    }
    container.set_tooltip_text(Some(ROW_BODY_COPY_TOOLTIP));
    let display = item.display();
    container.set_visible(display.progress_visible);
    progress.set_visible(display.progress_visible);
    secs.set_visible(display.progress_visible);
    if let Some(p) = display.progress {
        progress.set_fraction(progress_fraction(&p));
        progress.add_css_class(progress_urgency(&p).css_class());
        secs.set_label(&format_seconds_remaining(&p));
    } else {
        progress.set_fraction(0.0);
        secs.set_label("");
    }
}

/// Build the cell factory for the "Copy" column.
///
/// A single flat `gtk::Button` (`edit-copy-symbolic`) whose
/// sensitive state mirrors [`RowDisplay::copy_enabled`] (busy mask
/// already applied) and whose `connect_clicked` closure emits
/// [`AccountListOutput::CopyCode`] for the bound row's `AccountId`.
/// Re-installed on every `bind` so reused cells always close over
/// the current row.
#[must_use]
pub fn build_copy_column_factory(sender: Sender<AccountListOutput>) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    let handlers: HandlerMap = Rc::new(RefCell::new(HashMap::new()));
    let click_handlers: Rc<RefCell<HashMap<usize, glib::SignalHandlerId>>> =
        Rc::new(RefCell::new(HashMap::new()));

    factory.connect_setup(|_, item| {
        let list_item = cast_list_item(item);
        let button = gtk::Button::builder()
            .icon_name("edit-copy-symbolic")
            .tooltip_text("Copy code")
            .valign(gtk::Align::Center)
            .build();
        button.add_css_class("flat");
        list_item.set_child(Some(&button));
    });

    let handlers_b = Rc::clone(&handlers);
    let click_handlers_b = Rc::clone(&click_handlers);
    factory.connect_bind(move |_, item| {
        let list_item = cast_list_item(item);
        let Some(row_item) = try_row_item(&list_item) else {
            return;
        };
        let Some(button) = list_item.child().and_downcast::<gtk::Button>() else {
            return;
        };

        let button_for_rebind = button.clone();
        install_display_subscription(&handlers_b, &list_item, &row_item, move |item| {
            bind_copy_cell(&button_for_rebind, item);
        });

        let key = list_item_key(&list_item);
        if let Some(prev) = click_handlers_b.borrow_mut().remove(&key) {
            button.disconnect(prev);
        }
        if let Some(id) = row_item.account_id() {
            let sender_c = sender.clone();
            let handler = button.connect_clicked(move |_| {
                let _ = sender_c.send(AccountListOutput::CopyCode(id));
            });
            click_handlers_b.borrow_mut().insert(key, handler);
        }
    });

    let handlers_u = Rc::clone(&handlers);
    let click_handlers_u = Rc::clone(&click_handlers);
    factory.connect_unbind(move |_, item| {
        let list_item = cast_list_item(item);
        drop_handler(&handlers_u, &list_item);
        let key = list_item_key(&list_item);
        if let Some(handler) = click_handlers_u.borrow_mut().remove(&key) {
            if let Some(button) = list_item.child().and_downcast::<gtk::Button>() {
                button.disconnect(handler);
            }
        }
    });

    factory
}

fn bind_copy_cell(button: &gtk::Button, item: &RowItem) {
    if item.is_section() {
        button.set_visible(false);
        return;
    }
    button.set_visible(true);
    let mut display = item.display();
    crate::account_row::apply_busy_mask(&mut display, item.busy());
    button.set_sensitive(display.copy_enabled);
}

/// Build the cell factory for the "Kebab" (per-row overflow menu)
/// column.
///
/// A single flat `gtk::MenuButton` (`view-more-symbolic`) carrying
/// the shared [`build_kebab_menu_model`]. The per-row
/// `gio::SimpleActionGroup` is installed on every `bind` so the
/// "rename" / "remove" handlers close over the *current* row's id.
/// Sensitive/visible state mirrors [`RowDisplay::kebab_visible`] /
/// [`RowDisplay::kebab_enabled`] (busy mask already applied);
/// section rows hide the button.
#[must_use]
pub fn build_kebab_column_factory(sender: Sender<AccountListOutput>) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    let handlers: HandlerMap = Rc::new(RefCell::new(HashMap::new()));

    factory.connect_setup(|_, item| {
        let list_item = cast_list_item(item);
        let kebab = gtk::MenuButton::builder()
            .icon_name("view-more-symbolic")
            .tooltip_text("More actions")
            .valign(gtk::Align::Center)
            .menu_model(&build_kebab_menu_model())
            .build();
        kebab.add_css_class("flat");
        list_item.set_child(Some(&kebab));
    });

    let handlers_b = Rc::clone(&handlers);
    factory.connect_bind(move |_, item| {
        let list_item = cast_list_item(item);
        let Some(row_item) = try_row_item(&list_item) else {
            return;
        };
        let Some(kebab) = list_item.child().and_downcast::<gtk::MenuButton>() else {
            return;
        };

        // Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2.6
        // the kebab needs a per-cell `gio::SimpleActionGroup` because
        // its `gio::MenuModel` activates named gio actions. Install a
        // fresh group on every `bind` so handlers close over the
        // current row's `AccountId`. Reused cells replace the action
        // group wholesale via `insert_action_group(..., Some)`.
        if let Some(id) = row_item.account_id() {
            let group = build_kebab_action_group(id, &sender);
            kebab.insert_action_group(ROW_ACTION_GROUP_NAME, Some(&group));
        } else {
            kebab.insert_action_group(ROW_ACTION_GROUP_NAME, gio::ActionGroup::NONE);
        }

        let kebab_for_rebind = kebab.clone();
        install_display_subscription(&handlers_b, &list_item, &row_item, move |item| {
            bind_kebab_cell(&kebab_for_rebind, item);
        });
    });

    let handlers_u = Rc::clone(&handlers);
    factory.connect_unbind(move |_, item| {
        let list_item = cast_list_item(item);
        drop_handler(&handlers_u, &list_item);
        if let Some(kebab) = list_item.child().and_downcast::<gtk::MenuButton>() {
            kebab.insert_action_group(ROW_ACTION_GROUP_NAME, gio::ActionGroup::NONE);
        }
    });

    factory
}

fn bind_kebab_cell(kebab: &gtk::MenuButton, item: &RowItem) {
    if item.is_section() {
        kebab.set_visible(false);
        return;
    }
    kebab.set_visible(true);
    let mut display = item.display();
    crate::account_row::apply_busy_mask(&mut display, item.busy());
    kebab.set_sensitive(display.kebab_enabled);
}

/// Construct the per-row `gio::SimpleActionGroup` that the kebab's
/// `gio::MenuModel` activations target. Holds one action per
/// [`ROW_RENAME_ACTION_NAME`] / [`ROW_REMOVE_ACTION_NAME`] /
/// [`ROW_NEXT_ACTION_NAME`] / [`ROW_COPY_ACTION_NAME`]; each closure
/// captures `id` and `sender` so an activation maps through
/// [`dispatch_row_action`] onto the matching [`AccountRowOutput`],
/// then onto an [`AccountListOutput`] for `AppModel`.
fn build_kebab_action_group(
    id: AccountId,
    sender: &Sender<AccountListOutput>,
) -> gio::SimpleActionGroup {
    let actions = gio::SimpleActionGroup::new();
    for action_name in [
        ROW_RENAME_ACTION_NAME,
        ROW_REMOVE_ACTION_NAME,
        ROW_NEXT_ACTION_NAME,
        ROW_COPY_ACTION_NAME,
    ] {
        let action = gio::SimpleAction::new(action_name, None);
        let sender = sender.clone();
        action.connect_activate(move |_, _| {
            let Some(out) = dispatch_row_action(action_name, id) else {
                return;
            };
            let routed = match out {
                AccountRowOutput::RequestRename(id) => AccountListOutput::OpenRenameDialog(id),
                AccountRowOutput::RequestRemove(id) => AccountListOutput::OpenRemoveDialog(id),
                AccountRowOutput::RequestCopy(id) => AccountListOutput::CopyCode(id),
                AccountRowOutput::RequestAdvance(id) => AccountListOutput::AdvanceHotp(id),
            };
            let _ = sender.send(routed);
        });
        actions.add_action(&action);
    }
    actions
}

/// `true` if any row in `rows` is a TOTP account.
///
/// Used by `AccountListComponent` to decide whether to show the
/// "Time" `ColumnViewColumn` — HOTP-only vaults hide it entirely
/// per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.6
/// decision 5. Pure helper so the predicate is testable without a
/// `ColumnView`.
#[must_use]
pub fn any_totp(rows: &[AccountRowModel]) -> bool {
    rows.iter()
        .any(|row| matches!(row.kind, paladin_core::AccountKindSummary::Totp))
}

/// Case-folded `(issuer, display_label)` sort key for the "Account"
/// `gtk::ColumnViewColumn`.
///
/// Used by `AccountListComponent` to back a `gtk::CustomSorter`
/// that orders the column by `(issuer, label)` case-insensitive
/// when the user clicks the column header.  The default unsorted
/// view still preserves the vault insertion order from
/// `docs/DESIGN.md` §"listing-order"; clicking the header is a
/// user-initiated override and does not persist across restarts —
/// see `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.4 "Sortable columns".
///
/// Pure projection: identical inputs always return identical
/// outputs, which is the contract `gtk::Sorter` relies on when it
/// re-evaluates the key after a model mutation.
///
/// Rows whose `issuer` is `None` collate before all named issuers
/// because the projection maps `None -> ""`.  This keeps
/// unnamed-issuer rows visible at the top of an ascending sort
/// rather than buried mid-list under an implicit fallback bucket.
#[must_use]
pub fn account_column_sort_key(model: &AccountRowModel) -> (String, String) {
    let issuer = model
        .issuer
        .as_deref()
        .map(str::to_lowercase)
        .unwrap_or_default();
    let label = model.display_label.to_lowercase();
    (issuer, label)
}

/// Build a `gtk::CustomSorter` that compares two [`RowItem`]s by
/// the case-folded `(issuer, display_label)` tuple, mirroring
/// [`account_column_sort_key`] on the live `gio::ListStore<RowItem>`.
///
/// Attached to the "Account" `gtk::ColumnViewColumn` by
/// `AccountListComponent::init` so clicking the column header toggles
/// the sort direction.  Default unsorted preserves vault insertion
/// order per `docs/DESIGN.md` §"listing-order"; sorting is a
/// user-initiated override and does not persist across restarts —
/// see `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.4 "Sortable columns".
///
/// Section rows compare `Equal` to each other and to themselves so
/// their position is stable under the sort.  In practice section
/// rows are non-selectable and the rendered list never asks the
/// sorter to reorder them across account rows.
/// Compare two [`RowItem`]s by their case-folded
/// `(issuer, display_label)` sort key.
///
/// Pure helper extracted from [`build_account_column_sorter`] so
/// the comparison contract can be pinned by tests without spinning
/// up GTK (the `gtk::CustomSorter` wrapper requires `gtk::init()`,
/// which depends on a display server).  Section rows always
/// compare `Equal` so a sort never reorders them across account
/// rows; in practice they are `set_selectable(false)` and the
/// rendered list never asks the sorter to reorder them.
#[must_use]
pub fn compare_account_row_items(
    a: &crate::row_item::RowItem,
    b: &crate::row_item::RowItem,
) -> std::cmp::Ordering {
    if a.is_section() || b.is_section() {
        return std::cmp::Ordering::Equal;
    }
    let key_a = (
        a.issuer().unwrap_or_default().to_lowercase(),
        a.display().label.to_lowercase(),
    );
    let key_b = (
        b.issuer().unwrap_or_default().to_lowercase(),
        b.display().label.to_lowercase(),
    );
    key_a.cmp(&key_b)
}

/// Build a `gtk::CustomSorter` that compares two [`RowItem`]s
/// via [`compare_account_row_items`].
///
/// Attached to the "Account" `gtk::ColumnViewColumn` by
/// `AccountListComponent::init` so clicking the column header toggles
/// the sort direction.  Default unsorted preserves vault insertion
/// order per `docs/DESIGN.md` §"listing-order"; sorting is a
/// user-initiated override and does not persist across restarts —
/// see `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.4 "Sortable columns".
///
/// Requires `gtk::init()` (the underlying `gtk::CustomSorter::new`
/// asserts on the GTK type registration), so this constructor must
/// be called from a thread that has already initialized GTK — the
/// `AccountListComponent::init` path satisfies that.
#[must_use]
pub fn build_account_column_sorter() -> gtk::CustomSorter {
    gtk::CustomSorter::new(|a, b| {
        let row_a = a.downcast_ref::<crate::row_item::RowItem>();
        let row_b = b.downcast_ref::<crate::row_item::RowItem>();
        match (row_a, row_b) {
            (Some(a), Some(b)) => compare_account_row_items(a, b).into(),
            _ => gtk::Ordering::Equal,
        }
    })
}
