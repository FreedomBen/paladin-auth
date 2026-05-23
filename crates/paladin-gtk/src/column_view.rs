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

use std::collections::HashMap;

use paladin_core::AccountId;
use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;
use relm4::gtk::glib;

use crate::account_list::AccountRowModel;
use crate::row_item::RowItem;

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
pub fn splice_plan(old: &[AccountId], new: &[AccountId]) -> Vec<SpliceOp> {
    let new_set: std::collections::HashSet<AccountId> = new.iter().copied().collect();
    let old_set: std::collections::HashSet<AccountId> = old.iter().copied().collect();

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
