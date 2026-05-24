// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic tests for `paladin_gtk::column_view`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.4, the
//! `gtk::ColumnView` migration replaces a `splice(0, n_old, n_new)`
//! rebuild with a minimal sequence of `gio::ListStore::splice` ops
//! keyed by `AccountId`. The plan is computed by [`splice_plan`] and
//! applied by [`apply_splice_plan`]; this file pins both layers.
//!
//! The plan layer is fully pure logic so the operation table is
//! exercised without a `gio::ListStore`; the apply layer is a thin
//! driver tested against a real `gio::ListStore<RowItem>` (`GObject`
//! type registration does not require a display server).

use paladin_core::{AccountId, AccountKindSummary};
use paladin_gtk::account_list::AccountRowModel;
use paladin_gtk::column_view::{
    account_column_sort_key, apply_splice_plan, compare_account_row_items,
    interleave_section_headers, splice_plan, InterleavedRow, RowKey, SpliceOp,
};
use paladin_gtk::row_item::RowItem;

use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;
use relm4::gtk::glib;

fn model_for(id: AccountId, label: &str) -> AccountRowModel {
    AccountRowModel {
        id,
        display_label: label.to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
        icon_hint: None,
        issuer: None,
    }
}

fn ids(n: usize) -> Vec<AccountId> {
    (0..n).map(|_| AccountId::new()).collect()
}

// ---------------------------------------------------------------------------
// splice_plan — pure logic
// ---------------------------------------------------------------------------

#[test]
fn splice_plan_no_change_emits_nothing() {
    let ids = ids(3);
    assert_eq!(splice_plan(&ids, &ids), Vec::<SpliceOp>::new());
}

#[test]
fn splice_plan_append_emits_single_insert_at_end() {
    let ids = ids(4);
    let mut new = ids.clone();
    new.push(AccountId::new());
    let plan = splice_plan(&ids, &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Insert {
            position: 4,
            indices: vec![4],
        }],
    );
}

#[test]
fn splice_plan_prepend_emits_single_insert_at_zero() {
    let ids = ids(3);
    let head = AccountId::new();
    let mut new = vec![head];
    new.extend(ids.iter().copied());
    let plan = splice_plan(&ids, &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Insert {
            position: 0,
            indices: vec![0],
        }],
    );
}

#[test]
fn splice_plan_remove_middle_emits_single_remove() {
    let ids = ids(5);
    let new: Vec<AccountId> = ids
        .iter()
        .enumerate()
        .filter_map(|(i, id)| (i != 2).then_some(*id))
        .collect();
    let plan = splice_plan(&ids, &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Remove {
            position: 2,
            n_remove: 1,
        }],
    );
}

#[test]
fn splice_plan_remove_consecutive_run_coalesces() {
    let ids = ids(6);
    let new: Vec<AccountId> = ids
        .iter()
        .enumerate()
        .filter_map(|(i, id)| (!(2..=4).contains(&i)).then_some(*id))
        .collect();
    let plan = splice_plan(&ids, &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Remove {
            position: 2,
            n_remove: 3,
        }],
    );
}

#[test]
fn splice_plan_insert_consecutive_run_coalesces() {
    let ids = ids(2);
    let new_ids: Vec<AccountId> = (0..3).map(|_| AccountId::new()).collect();
    let mut new = vec![ids[0]];
    new.extend(new_ids.iter().copied());
    new.push(ids[1]);
    let plan = splice_plan(&ids, &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Insert {
            position: 1,
            indices: vec![1, 2, 3],
        }],
    );
}

#[test]
fn splice_plan_clear_emits_single_remove_full() {
    let ids = ids(4);
    let plan = splice_plan(&ids, &[]);
    assert_eq!(
        plan,
        vec![SpliceOp::Remove {
            position: 0,
            n_remove: 4,
        }],
    );
}

#[test]
fn splice_plan_populate_from_empty_emits_single_insert() {
    let new = ids(3);
    let plan = splice_plan(&[], &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Insert {
            position: 0,
            indices: vec![0, 1, 2],
        }],
    );
}

#[test]
fn splice_plan_mixed_insert_and_remove() {
    // old = [A, B, C, D, E], new = [A, B, X, D, E, F]
    let ids = ids(5);
    let x = AccountId::new();
    let f = AccountId::new();
    let new = vec![ids[0], ids[1], x, ids[3], ids[4], f];
    let plan = splice_plan(&ids, &new);
    assert_eq!(
        plan,
        vec![
            SpliceOp::Remove {
                position: 2,
                n_remove: 1,
            },
            SpliceOp::Insert {
                position: 2,
                indices: vec![2],
            },
            SpliceOp::Insert {
                position: 5,
                indices: vec![5],
            },
        ],
    );
}

#[test]
fn splice_plan_swap_emits_remove_plus_insert() {
    // old = [A, B], new = [B, A] is a pure reorder. The plan falls
    // back to a tail rebuild rather than tracking moves: the simple
    // insert/remove scheme cannot express moves, and pure reorderings
    // do not arise in the vault's insertion-order contract.
    let ids = ids(2);
    let new = vec![ids[1], ids[0]];
    let plan = splice_plan(&ids, &new);
    // Tail rebuild from position 0.
    assert_eq!(
        plan,
        vec![
            SpliceOp::Remove {
                position: 0,
                n_remove: 2,
            },
            SpliceOp::Insert {
                position: 0,
                indices: vec![0, 1],
            },
        ],
    );
}

// ---------------------------------------------------------------------------
// apply_splice_plan — exercises a real gio::ListStore<RowItem>.
// ---------------------------------------------------------------------------

fn collect_ids(store: &gio::ListStore) -> Vec<AccountId> {
    (0..store.n_items())
        .filter_map(|i| store.item(i))
        .filter_map(|obj| obj.downcast::<RowItem>().ok())
        .filter_map(|item| item.account_id())
        .collect()
}

fn seed_store(ids: &[AccountId]) -> gio::ListStore {
    let store = gio::ListStore::new::<RowItem>();
    let items: Vec<glib::Object> = ids
        .iter()
        .map(|id| RowItem::from_row_model(&model_for(*id, "seed")).upcast())
        .collect();
    store.splice(0, 0, &items);
    store
}

#[test]
fn apply_no_op_when_old_matches_new() {
    let ids = ids(3);
    let store = seed_store(&ids);
    let new: Vec<AccountRowModel> = ids.iter().map(|id| model_for(*id, "new")).collect();
    apply_splice_plan(&store, &new);
    assert_eq!(collect_ids(&store), ids);
}

#[test]
fn apply_preserves_row_item_identity_for_matched_rows() {
    let ids = ids(3);
    let store = seed_store(&ids);

    // Capture the GObject pointer addresses (via Object::as_ptr) for the
    // existing items. apply_splice_plan should reuse these for matched
    // AccountIds.
    let original_ptrs: Vec<usize> = (0..store.n_items())
        .filter_map(|i| store.item(i))
        .map(|o| o.as_ptr() as usize)
        .collect();

    // New rows: same ids, fresh AccountRowModels.
    let new: Vec<AccountRowModel> = ids.iter().map(|id| model_for(*id, "new")).collect();
    apply_splice_plan(&store, &new);

    let updated_ptrs: Vec<usize> = (0..store.n_items())
        .filter_map(|i| store.item(i))
        .map(|o| o.as_ptr() as usize)
        .collect();
    assert_eq!(
        updated_ptrs, original_ptrs,
        "matched rows should keep their RowItem identity across a refresh",
    );
}

#[test]
fn apply_inserts_appended_row() {
    let mut ids = ids(2);
    let store = seed_store(&ids);
    let appended = AccountId::new();
    ids.push(appended);
    let new: Vec<AccountRowModel> = ids.iter().map(|id| model_for(*id, "new")).collect();
    apply_splice_plan(&store, &new);
    assert_eq!(collect_ids(&store), ids);
}

#[test]
fn apply_removes_middle_row() {
    let ids = ids(5);
    let store = seed_store(&ids);
    let new: Vec<AccountRowModel> = ids
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, id)| model_for(*id, "new"))
        .collect();
    apply_splice_plan(&store, &new);
    let expected: Vec<AccountId> = ids
        .iter()
        .enumerate()
        .filter_map(|(i, id)| (i != 2).then_some(*id))
        .collect();
    assert_eq!(collect_ids(&store), expected);
}

#[test]
fn apply_clear_makes_store_empty() {
    let ids = ids(3);
    let store = seed_store(&ids);
    apply_splice_plan(&store, &[]);
    assert_eq!(store.n_items(), 0);
}

#[test]
fn apply_populate_from_empty_seeds_full_set() {
    let store = gio::ListStore::new::<RowItem>();
    let new_ids = ids(4);
    let new: Vec<AccountRowModel> = new_ids.iter().map(|id| model_for(*id, "new")).collect();
    apply_splice_plan(&store, &new);
    assert_eq!(collect_ids(&store), new_ids);
}

// ---------------------------------------------------------------------------
// interleave_section_headers — pure logic
// ---------------------------------------------------------------------------

fn account_model(label: &str, issuer: Option<&str>) -> AccountRowModel {
    AccountRowModel {
        id: AccountId::new(),
        display_label: match issuer {
            Some(i) if !i.is_empty() => format!("{i}:{label}"),
            _ => label.to_string(),
        },
        kind: AccountKindSummary::Totp,
        counter: None,
        icon_hint: None,
        issuer: issuer.map(str::to_string),
    }
}

#[test]
fn interleave_disabled_returns_only_account_rows() {
    let rows = vec![
        account_model("alice", Some("Acme")),
        account_model("bob", Some("Acme")),
        account_model("carol", Some("Zenith")),
    ];
    let interleaved = interleave_section_headers(&rows, false);
    assert_eq!(
        interleaved,
        vec![
            InterleavedRow::Account(0),
            InterleavedRow::Account(1),
            InterleavedRow::Account(2),
        ],
    );
}

#[test]
fn interleave_enabled_inserts_section_header_at_each_issuer_change() {
    let rows = vec![
        account_model("alice", Some("Acme")),
        account_model("bob", Some("Acme")),
        account_model("carol", Some("Zenith")),
        account_model("dan", None),
    ];
    let interleaved = interleave_section_headers(&rows, true);
    assert_eq!(
        interleaved,
        vec![
            InterleavedRow::Section("Acme".to_string()),
            InterleavedRow::Account(0),
            InterleavedRow::Account(1),
            InterleavedRow::Section("Zenith".to_string()),
            InterleavedRow::Account(2),
            InterleavedRow::Section("Other".to_string()),
            InterleavedRow::Account(3),
        ],
    );
}

#[test]
fn interleave_empty_input_yields_empty_output() {
    assert!(interleave_section_headers(&[], true).is_empty());
    assert!(interleave_section_headers(&[], false).is_empty());
}

// ---------------------------------------------------------------------------
// splice_plan generalized over RowKey (account ids + section titles).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// account_column_sort_key — pure logic
// ---------------------------------------------------------------------------

fn model_with(issuer: Option<&str>, label: &str) -> AccountRowModel {
    AccountRowModel {
        id: AccountId::new(),
        display_label: label.to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
        icon_hint: None,
        issuer: issuer.map(str::to_string),
    }
}

#[test]
fn sort_key_is_case_insensitive_on_issuer() {
    // Two rows with the same issuer modulo case must compare equal
    // on the primary key so the secondary (label) breaks the tie.
    let a = account_column_sort_key(&model_with(Some("Acme"), "Acme:alice"));
    let b = account_column_sort_key(&model_with(Some("acme"), "acme:bob"));
    assert_eq!(
        a.0, b.0,
        "issuer comparison must fold case so `Acme` and `acme` group together"
    );
}

#[test]
fn sort_key_is_case_insensitive_on_label() {
    // Within an issuer, label comparison must also fold case so
    // `Alice` and `alice` collate next to each other rather than
    // bisecting the issuer's run.
    let a = account_column_sort_key(&model_with(Some("Acme"), "Acme:Alice"));
    let b = account_column_sort_key(&model_with(Some("Acme"), "acme:alice"));
    assert_eq!(a.1, b.1);
}

#[test]
fn sort_key_missing_issuer_collates_with_empty_string() {
    // Rows whose issuer is `None` project to the empty string so
    // they collate before all named issuers when ascending — a
    // stable placement the user can see in one glance rather than
    // surprises buried mid-list.
    let key = account_column_sort_key(&model_with(None, "bare-label"));
    assert_eq!(key.0, "");
}

#[test]
fn sort_key_orders_rows_alphabetically() {
    // Spot-check a stable sort against the pure key — this is the
    // contract the `gtk::Sorter` attached to the Account column
    // will preserve in the live ColumnView.
    let mut rows = [
        model_with(Some("Github"), "Github:zoe"),
        model_with(Some("Acme"), "Acme:bob"),
        model_with(Some("acme"), "Acme:alice"),
        model_with(None, "loose"),
        model_with(Some("github"), "Github:adam"),
    ];
    rows.sort_by_key(account_column_sort_key);
    let labels: Vec<&str> = rows.iter().map(|r| r.display_label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "loose",       // None < anything named
            "Acme:alice",  // case-insensitive issuer sort: acme/Acme
            "Acme:bob",    // …then by case-folded label
            "Github:adam", // github sorts after acme
            "Github:zoe",
        ],
    );
}

#[test]
fn sort_key_is_stable_across_clones() {
    // The key function must be a pure projection — calling it
    // twice on the same model returns the same key.  This is the
    // contract the gtk::Sorter wrapper relies on (`gtk::Sorter`
    // can re-evaluate the sort key any time the model changes).
    let row = model_with(Some("Issuer"), "Issuer:Label");
    let a = account_column_sort_key(&row);
    let b = account_column_sort_key(&row);
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// build_account_column_sorter — wraps account_column_sort_key in a
// `gtk::CustomSorter` so the Account ColumnViewColumn can attach it.
// ---------------------------------------------------------------------------

#[test]
fn compare_row_items_orders_by_case_insensitive_issuer_then_label() {
    let acme_alice = RowItem::from_row_model(&model_with(Some("Acme"), "Acme:alice"));
    let acme_bob = RowItem::from_row_model(&model_with(Some("acme"), "Acme:bob"));
    let github_adam = RowItem::from_row_model(&model_with(Some("Github"), "Github:adam"));
    assert_eq!(
        compare_account_row_items(&acme_alice, &acme_bob),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_account_row_items(&acme_bob, &acme_alice),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_account_row_items(&acme_alice, &github_adam),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_account_row_items(&acme_alice, &acme_alice),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn compare_row_items_treats_missing_issuer_as_empty_string() {
    let none_issuer = RowItem::from_row_model(&model_with(None, "loose"));
    let acme = RowItem::from_row_model(&model_with(Some("Acme"), "Acme:alice"));
    // `None` issuer projects to "" which sorts before any named
    // issuer.  Mirrors the pure-helper contract pinned in
    // `sort_key_missing_issuer_collates_with_empty_string`.
    assert_eq!(
        compare_account_row_items(&none_issuer, &acme),
        std::cmp::Ordering::Less
    );
}

#[test]
fn compare_row_items_returns_equal_for_section_rows() {
    // Section rows aren't selectable, but the sorter still needs to
    // produce a stable comparison for them — return Equal so the
    // section's position in the store is preserved by the sort.
    let section_a = RowItem::section("Acme");
    let section_b = RowItem::section("Github");
    assert_eq!(
        compare_account_row_items(&section_a, &section_b),
        std::cmp::Ordering::Equal
    );
}

// ---------------------------------------------------------------------------
// splice_plan generalized over RowKey (account ids + section titles).
// ---------------------------------------------------------------------------

#[test]
fn splice_plan_handles_mixed_account_and_section_keys() {
    let id_a = AccountId::new();
    let id_b = AccountId::new();
    let old: Vec<RowKey> = vec![
        RowKey::Section("Acme".to_string()),
        RowKey::Account(id_a),
        RowKey::Account(id_b),
    ];
    let new: Vec<RowKey> = vec![RowKey::Account(id_a), RowKey::Account(id_b)];
    // Removing the leading section header is a single 1-item remove.
    let plan = splice_plan(&old, &new);
    assert_eq!(
        plan,
        vec![SpliceOp::Remove {
            position: 0,
            n_remove: 1,
        }],
    );
}
