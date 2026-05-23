# Column Headers via `gtk::ColumnView` — Archived Implementation Plan

Status: **archived (not implemented)**. Captured 2026-05-23 as the
fallback design we may revisit if the SizeGroup-aligned header strip
(the option we actually shipped — see
`docs/IMPLEMENTATION_PLAN_04_GTK.md`) becomes insufficient and we
decide a real columnar widget is worth the rewrite cost.

This plan covers replacing the unlocked-vault list view's
`gtk::ListBox` + `relm4::factory::FactoryVecDeque` with a
`gtk::ColumnView` driven by a `gio::ListStore` of `glib::Object`
wrappers around `AccountRowModel`, with one `gtk::ColumnViewColumn`
per visible field. Native column headers come for free; sortable
columns and per-column resize become tractable.

Source of truth for everything else stays
`docs/DESIGN.md` — this document does **not** change observable
behavior beyond the column headers themselves.

---

## 1. Motivation

The shipped Option 1 (a pinned `gtk::Box` header strip above the
`ScrolledWindow`, widths aligned via per-column `gtk::SizeGroup`) is
the lowest-disruption path to column headers. It has three
shortcomings we accept today but might want to revisit later:

1. **Header widths are best-effort, not authoritative.** A SizeGroup
   gives every member the maximum of all members' preferred widths.
   If the header label is wider than every row in a column, the
   column visibly stretches at runtime — and there is no way to
   make the header narrower than the natural row width.
2. **No native column affordances.** Sortable headers, per-column
   resize, column visibility menus, and the libadwaita "compact /
   default density" toggles all want `gtk::ColumnView`.
3. **Two layout templates to keep in sync.** `build_row_widget` in
   `crates/paladin-gtk/src/account_row.rs` and the header-strip
   builder must remain bit-for-bit aligned in column order, spacing,
   and per-cell visibility logic. The contract is enforced by the
   shared `ColumnSizeGroups` registration code, but it is still two
   builders walking the same column list.

`gtk::ColumnView` collapses all three into one widget. The cost is a
substantial rewrite — every cross-cutting bit of the unlocked view
that touches the `gtk::ListBox` today (selection, search filter,
HOTP reveal wiring, section grouping, per-tick TOTP updates, busy-
mask broadcast) needs to be re-expressed against
`gio::ListStore` + `gtk::SignalListItemFactory` + `gtk::ColumnView`.
Notably the project moved **away** from `gtk::ListView` +
`SignalListItemFactory` once before — see the rationale doc-comment
on `AccountListComponent` — because per-tick `splice` calls fired
`items-changed(0, N, N)` which rebound every visible row mid-frame
and dropped clicks. Any return to that family must solve the rebind
problem.

---

## 2. Target architecture

### 2.1 Widget tree

```
adw::ApplicationWindow
└─ content gtk::Box (vertical)
   └─ AccountListComponent root gtk::Box (vertical, hexpand+vexpand)
      ├─ gtk::SearchBar (unchanged)
      └─ gtk::ScrolledWindow
         └─ gtk::ColumnView                       ← was gtk::ListBox
            ├─ ColumnViewColumn "Account"
            │   └─ SignalListItemFactory          ← icon + label cell
            ├─ ColumnViewColumn "Code"
            │   └─ SignalListItemFactory          ← code label cell (numeric)
            ├─ ColumnViewColumn "Time"  (optional)
            │   └─ SignalListItemFactory          ← progress bar cell
            ├─ ColumnViewColumn ""      (no header text)
            │   └─ SignalListItemFactory          ← copy button cell
            └─ ColumnViewColumn ""      (no header text)
                └─ SignalListItemFactory          ← kebab menu cell
```

The optional "Time" column is shown only when at least one TOTP
account is present in the live row set (we currently use the same
predicate to decide whether to install the ticker). HOTP-only
vaults hide it, which matches today's behavior where the column
would be visually empty.

### 2.2 Item model

The store carries `RowItem` GObjects wrapping `AccountRowModel`.
Per-tick TOTP code updates flow through a mutable `Cell<RowDisplay>`
on the `RowItem` (or via `glib::Properties` so individual cell
factories can `bind_property` against the changed-notify signal),
**not** through a `splice`. This is the key invariant we lost the
last time we used a list-model-driven widget; document it loudly in
the rewrite.

```rust
glib::wrapper! {
    pub struct RowItem(ObjectSubclass<imp::RowItem>);
}

mod imp {
    use std::cell::RefCell;
    use paladin_gtk::account_row::RowDisplay;
    use paladin_core::AccountId;

    #[derive(Default)]
    pub struct RowItem {
        pub id: Cell<Option<AccountId>>,
        pub display: RefCell<RowDisplay>,
        pub icon_hint: RefCell<Option<String>>,
        pub busy: Cell<bool>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RowItem {
        const NAME: &'static str = "PaladinRowItem";
        type Type = super::RowItem;
    }

    impl ObjectImpl for RowItem { /* #[glib::derived_properties] */ }
}
```

Per-tick updates set the changed properties on the existing
`RowItem`; `bind_property` on each cell factory propagates the new
value into the cell widget. The store's row count is **only**
changed by Add / Remove / search-filter — not by ticks.

### 2.3 Selection and search

* `gtk::SingleSelection` wraps the store and becomes the
  `ColumnView`'s `set_model`. The current
  `AccountListComponent` selection logic (which uses `select_row`
  on the `ListBox` because `FactoryVecDeque` has no `ListModel`)
  collapses to `selection.set_selected(position)`.
* The search filter remains in `AppModel` — `AccountRowModel`s for
  the current query are recomputed there and the new vec is
  diff'd against the live store via
  `store.splice_diff(old, new, |a, b| a.id == b.id)` (small helper)
  so per-tick rebinds never touch the store.

### 2.4 Section grouping (issuer headers between rows)

`gtk::ColumnView` has no `set_header_func` equivalent for in-list
section headers — those are a `ListBox`-only feature. Two paths:

1. **Drop in-list section headers** when ColumnView lands. The
   `show-section-headers` preference becomes a no-op (or is
   removed). This is the simplest path and may be acceptable: real
   column headers arguably subsume the visual grouping benefit.
2. **Render group rows as styled `RowItem`s.** Add a `kind: enum
   RowKind { Section(String), Account(AccountSummary) }` field to
   `RowItem`. The "Account" cell factory branches on kind: section
   rows render as a single-cell heading spanning all columns; account
   rows render the existing icon+label. Per-column factories for
   non-account cells render empty for section rows. Selectability
   is suppressed via a custom `gtk::SelectionFilterModel` upstream
   of `gtk::SingleSelection`.

Decision deferred. Path 1 is the default unless the user wants to
preserve issuer grouping.

### 2.5 Per-tick update path

The flicker-free contract from the existing
`AccountRowComponent` setup must be preserved. Per-tick TOTP
refreshes today route through
`factory.send(index, AccountRowMsg::Rebind(display))` — the row's
widget tree is built once and re-bound in place.

Under ColumnView, the equivalent is:

```rust
for (id, display) in tick_dispatch_plan { 
    let item = store.row_item_for_id(id)?; // pure lookup
    item.set_display(display);             // glib::Property notify
    // Cell factories' bind_property targets pick up the change.
}
```

The crucial guarantee: never call `store.splice(...)` from a tick
handler. Only Add/Remove/Refresh/SearchFilter touch the store.

### 2.6 Action plumbing

Each row's copy button / kebab menu / HOTP next button currently
goes through a per-row `gio::SimpleActionGroup` named
`ROW_ACTION_GROUP_NAME`. With `gtk::ColumnView`, action groups have
to be installed on the **cell** widget (since cells are recycled),
or — more cleanly — the cell factory's `bind` step looks up the
`RowItem` and uses `gtk_callback`-style closures that capture the
row's `AccountId` from the bound item. Either works; recommend the
latter because it survives cell recycling without re-installing
action groups per bind.

---

## 3. Files affected

| File | Change |
|---|---|
| `crates/paladin-gtk/src/account_list.rs` | Substantial rewrite. `gtk::ListBox` → `gtk::ColumnView`. `FactoryVecDeque<AccountRowComponent>` → `gio::ListStore<RowItem>` + `gtk::SignalListItemFactory` per column. Selection moves to `gtk::SingleSelection`. The in-list section-header dispatch table (`precompute_section_headers`, `install_section_header_func`, `build_section_header_label`, `row_section_header`, `issuer_group_header`) either deletes (Path 1) or migrates to `RowKind::Section` rendering (Path 2). |
| `crates/paladin-gtk/src/account_row.rs` | The factory-component machinery (`AccountRowComponent`, `AccountRowInit`, `AccountRowMsg`, `AccountRowOutput`, `AccountRowWidgets`, `build_row_widget`, `bind_row`, `install_row_action_group`) is **deleted**. The pure projection helpers (`project_row`, `progress_display`, `progress_urgency`, `code_display`, `counter_display`, `apply_busy_mask`, `next_button_visible`, `progress_visible`, `kebab_visible`, `copy_enabled`) survive — the ColumnView cell factories consume the same `RowDisplay` values. |
| **new** `crates/paladin-gtk/src/row_item.rs` | `RowItem` `GObject` subclass + `glib::Properties` derive macro + `set_display` mutator. |
| **new** `crates/paladin-gtk/src/column_view.rs` (or fold into `account_list.rs`) | Cell factory builders: `build_account_column_factory`, `build_code_column_factory`, `build_time_column_factory`, `build_copy_column_factory`, `build_kebab_column_factory`. Each returns a `gtk::SignalListItemFactory` whose `setup` builds the cell widget tree and whose `bind` reads from the `RowItem`'s properties. |
| `crates/paladin-gtk/src/app/model.rs` | `AccountListInit` field names change (`rows: Vec<AccountRowModel>` → unchanged), `initial_selection` semantics unchanged. `AppMsg::ShowSectionHeadersChanged` becomes either a no-op (Path 1) or remains wired to the ColumnView model (Path 2). Per-tick dispatch helpers (`tick_dispatch_plan`, `forward_row_output`) need re-routing since `AccountRowOutput` no longer exists — actions emit `AccountListOutput` directly from the cell-factory closures. |
| `crates/paladin-gtk/src/data/org.tamx.Paladin.Gui.gschema.xml` | `show-column-headers` key — required if we make column-header visibility opt-out. Otherwise headers are always shown by `gtk::ColumnView` (the natural default). |
| `crates/paladin-gtk/src/settings.rs` | Preferences row for `show-column-headers` (if added). Section-headers row is removed or re-purposed depending on the Path 1/2 decision. |
| `crates/paladin-gtk/tests/account_list_logic.rs` | Tests that bind directly to `AccountRowComponent` re-target to the new factory builders. Selection / search / busy-mask broadcast tests stay structurally similar but call into ColumnView APIs (`SingleSelection::selected`, `gio::ListStore::n_items`). |
| `crates/paladin-gtk/tests/account_row_logic.rs` | Pure projection helpers (`project_row` et al.) stay; widget-bind tests delete with `bind_row`. |
| `docs/IMPLEMENTATION_PLAN_04_GTK.md` | Update §"Component tree" → describe ColumnView. Update §"libadwaita usage" if the row's CSS classes change. Note the section-header decision. |
| `docs/DESIGN.md` | If user-visible behavior around section headers changes (Path 1), the relevant paragraph updates here. |

---

## 4. Implementation checklist

Track progress against this list when the rewrite begins.

### Foundation
- [ ] Decide section-headers Path 1 (drop) vs Path 2 (preserve via `RowKind::Section`). Default Path 1.
- [ ] Decide whether column-header visibility is gated (`show-column-headers` GSettings) or always shown. Default always shown.
- [ ] Decide whether to keep the "Time" column visible on HOTP-only vaults. Default hide.

### `RowItem` GObject
- [ ] Define `RowItem` in `crates/paladin-gtk/src/row_item.rs` with `id`, `display`, `icon_hint`, `busy` properties.
- [ ] Wire `glib::Properties` derive (Rust GObject crate) and the per-property setters.
- [ ] Add `RowItem::from_row_model(&AccountRowModel) -> Self`.
- [ ] Add `RowItem::set_display(&self, RowDisplay)` and verify it fires `notify::display`.
- [ ] Unit-test: setter fires the `notify::display` signal.

### Store + selection
- [ ] Replace `FactoryVecDeque<AccountRowComponent>` with `gio::ListStore::new::<RowItem>()`.
- [ ] Build `gtk::SingleSelection::new(Some(store))`; bind to `ColumnView::set_model`.
- [ ] Replace `apply_list_box_selection` with a `SingleSelection::set_selected(position)` helper.
- [ ] Build `splice_diff` helper that, given an old and new `Vec<AccountRowModel>`, computes the minimum (insert, remove) ops against the store keyed by `AccountId` — never `splice(0, N, N)`.

### Cell factories
- [ ] `build_account_column_factory` — icon (24px) + ellipsized label (hexpand).
- [ ] `build_code_column_factory` — `numeric` CSS class label; bind to `display.code`.
- [ ] `build_time_column_factory` — `gtk::ProgressBar` (width_request 96); bind to `display.progress_fraction` + urgency CSS class.
- [ ] `build_copy_column_factory` — `gtk::Button` "edit-copy-symbolic"; activate emits `AccountListOutput::CopyCode(item.id())`. Sensitive bound to `display.copy_enabled`.
- [ ] `build_kebab_column_factory` — `gtk::MenuButton` "view-more-symbolic"; menu model built once at setup time; per-cell action group rebound on each `bind` so the closures capture the current item's `AccountId`.
- [ ] HOTP "next" affordance: decide whether it stays inline in the "Code" cell (so it's adjacent to the code, like today) or moves to its own ColumnView column. Recommend inline.

### Per-tick update path
- [ ] Rewrite `AccountListMsg::Tick` handler to walk `tick_dispatch_plan`, look up the matching `RowItem` in the store via an `AccountId → position` index, and call `item.set_display(new_display)`.
- [ ] Verify no `splice` is called from the Tick handler.
- [ ] Stress test: 50 TOTP accounts, 1s tick, observe no flicker / no dropped clicks across 60s.

### Search / filter
- [ ] `AppModel` recomputes `filtered_row_models_from_vault(...)`, then asks the live `AccountListComponent` to `splice_diff` the new vec into its store.
- [ ] Cursor / selection survives a query change as today.

### Section headers (Path 1)
- [ ] Delete `precompute_section_headers`, `install_section_header_func`, `build_section_header_label`, `row_section_header`, `issuer_group_header`.
- [ ] Delete `show-section-headers` schema key (and its tests, preferences row, AppMsg variant, signal wiring).
- [ ] Note the user-facing removal in `docs/DESIGN.md` and the GTK plan.

### Section headers (Path 2 — alternative)
- [ ] Add `RowKind` enum on `RowItem`; `RowItem::section(text) -> Self`.
- [ ] Compute the interleaved row list (section + account rows) inside `AppModel` from `AccountRowModel` per the existing `row_section_header` predicate, gated by `show-section-headers`.
- [ ] Add a `gtk::SelectionFilterModel` over the store that filters out section rows from selection.
- [ ] Cell factories branch on kind: section row renders a single full-width label, all other columns render empty.
- [ ] Tests: section rows are non-selectable; toggling the GSettings rebuilds the row list without resetting the live selection.

### Preferences (if column-header visibility is gated)
- [ ] `show-column-headers` schema key, default `true`.
- [ ] `crate::gsettings::{show_column_headers, set_show_column_headers, SHOW_COLUMN_HEADERS_KEY}`.
- [ ] `AppMsg::ShowColumnHeadersChanged(bool)` + `changed::show-column-headers` signal wiring.
- [ ] `AccountListMsg::SetShowColumnHeaders(bool)` → `column_view.set_show_column_separators(...)` and individual column `set_visible(false)` toggles on the header widgets (ColumnView itself can hide all headers via `set_show_column_separators` + ad-hoc CSS, or per-column via `set_visible` on the column header widget).
- [ ] Preferences row in `settings.rs` Display group with title/subtitle helper fns.

### Docs sync
- [ ] `docs/IMPLEMENTATION_PLAN_04_GTK.md` — rewrite §"Component tree" to describe the ColumnView + RowItem + factories. Update the "we migrated away from ListView once" rationale with the new flicker-free contract.
- [ ] `docs/DESIGN.md` — only if user-visible behavior changes (e.g. section headers removed under Path 1).
- [ ] `CLAUDE.md` — no changes required.

### CI gates
- [ ] `cargo fmt --all -- --check` clean.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [ ] `cargo test --workspace --all-targets` green.
- [ ] `cargo public-api` diff reviewed (the public surface of `paladin-gtk` changes meaningfully).
- [ ] `cargo deny check` and `cargo audit` clean.

---

## 5. Migration risk register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Per-tick `splice` regression returns dropped-click bug | Medium | High | Enforce in code review and add a regression test asserting `store.n_items()` is unchanged across a Tick. |
| Section-header removal upsets users who turned the pref on | Low | Medium | Path 2 preserves the feature; otherwise call it out in release notes. |
| Cell recycling breaks per-row action group identity | Medium | Medium | Bind action groups inside cell-factory `bind`, not `setup`; tests cover Copy + Rename through 100 sequential rebinds. |
| HOTP "next" button placement gets awkward | Low | Low | Inline it in the "Code" cell; matches today's visual layout. |
| Search filter performance under ColumnView differs | Low | Low | The `splice_diff` helper holds n_items steady across query changes by id-matching. |
| `cargo public-api` snapshot churn | Certain | Low | Regenerate the snapshot and review the diff carefully. |
| `gtk::ColumnView` styling drift from libadwaita "navigation-sidebar" look | Medium | Low | Apply `add_css_class("rich-list")` or the libadwaita "boxed-list" classes that match the rest of the app. |

---

## 6. Decision points (must resolve before starting)

1. **Section headers**: drop them (Path 1) or preserve them as styled section rows (Path 2)?
2. **Column-header visibility**: always shown, or gated by a per-user `show-column-headers` GSettings key (mirroring `show-section-headers`)?
3. **Sortable columns**: enabled by default per column, or v0.next? `ColumnView` makes this nearly free, but cross-cuts with the vault-insertion-order contract in `docs/DESIGN.md`.
4. **HOTP "next" button placement**: inline in the "Code" cell (recommended, matches today) or its own column?
5. **"Time" column visibility on HOTP-only vaults**: hide the entire column (recommended) or render it empty?

Each of these defaults to the conservative answer above; flip any of them in the v0.next decision pass if requirements change.

---

## 7. Estimated scope

Rough sizing for a single-engineer pass, assuming Path 1 + always-shown headers + inline HOTP-next + hidden Time column for HOTP-only:

* ~600–800 lines of new Rust across `row_item.rs`, the ColumnView builders, and the rewired `account_list.rs`.
* ~400–500 lines deleted from `account_row.rs` (the factory machinery).
* ~6–8 new tests in `account_list_logic.rs`; ~4–6 tests deleted that bound to factory internals.
* `docs/IMPLEMENTATION_PLAN_04_GTK.md` updates: 1–2 sections rewritten.
* `cargo public-api` snapshot regenerated.

Realistic effort: **3–5 days** of focused work for a developer
familiar with relm4 and GObject subclassing in Rust, **plus**
~1 day of manual QA against a populated vault (50+ accounts, TOTP +
HOTP mix, active search, busy state, etc.).
