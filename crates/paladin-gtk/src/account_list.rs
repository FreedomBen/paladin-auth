// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AccountListComponent` for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountListComponent`, the unlocked view is a `gtk::ListView`
//! with a custom row factory bound to a `gio::ListStore` of
//! [`AccountRowModel`] entries built from
//! `paladin_core::AccountSummary` projections (no secret bytes).
//!
//! This module has two layers:
//!
//! * The pure-logic projection — [`AccountRowModel`],
//!   [`row_models_from_vault`], and [`format_rendered_marker`] —
//!   which the integration tests in `tests/account_list_logic.rs`
//!   exercise without a display server.
//! * The widget binding [`AccountListComponent`], which owns the
//!   `gio::ListStore` plus the `gtk::SignalListItemFactory` that
//!   maps each [`AccountRowModel`] onto a row label. The widget
//!   layer never reaches for the live `Account` — it only reads
//!   the already-projected [`AccountRowModel`].

use relm4::gtk;
use relm4::gtk::gio;
use relm4::gtk::glib;
use relm4::gtk::prelude::*;
use relm4::prelude::*;

use paladin_core::{select_after_filter, AccountId, AccountKindSummary, Vault};

use crate::account_row::{
    copy_enabled, display_label, kebab_visible, next_button_visible, progress_visible, CodeDisplay,
    CounterText, RowDisplay,
};
use crate::search::filtered_account_ids;

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the [`AccountListComponent`] has bound rows from the live vault.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix,
/// and the pure-logic test in `tests/account_list_logic.rs` pins
/// the format. Centralizing the literal here keeps test +
/// implementation aligned.
pub const ACCOUNT_LIST_RENDERED_MARKER_PREFIX: &str = "paladin-gtk: account_list_rows=";

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the per-row widget bundle has been bound for every row.
///
/// The marker pipe-joins one entry per row, where each entry
/// fingerprints the visible per-row affordance states (the copy
/// button's sensitivity, the HOTP "next" button's visibility, and
/// the kebab menu's mount). This is what makes the per-row widget
/// bundle observable from the smoke test without driving widget
/// signals.
pub const ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX: &str =
    "paladin-gtk: account_list_widget_states=";

/// Name of the per-row [`gio::SimpleActionGroup`] installed on each
/// row container.
///
/// Must match the prefix used by [`build_kebab_menu_model`] for the
/// `row.rename` / `row.remove` menu targets — otherwise the kebab
/// items dispatch into the void at activation time. Pinned by
/// `tests/account_list_logic.rs` so a future rename forces the
/// action-group install site and the menu-target string into
/// lockstep.
pub const ROW_ACTION_GROUP_NAME: &str = "row";

/// Action name within [`ROW_ACTION_GROUP_NAME`] that opens the
/// `RenameDialog` for the row's account.
///
/// Dispatch through [`dispatch_row_action`] routes this to
/// [`AccountListOutput::OpenRenameDialog`] carrying the row's
/// [`AccountId`].
pub const ROW_RENAME_ACTION_NAME: &str = "rename";

/// Action name within [`ROW_ACTION_GROUP_NAME`] that opens the
/// `RemoveDialog` for the row's account.
///
/// Dispatch through [`dispatch_row_action`] routes this to
/// [`AccountListOutput::OpenRemoveDialog`] carrying the row's
/// [`AccountId`].
pub const ROW_REMOVE_ACTION_NAME: &str = "remove";

/// Output forwarded from [`AccountListComponent`] up to `AppModel`
/// in response to a row-level user intent or a search-query change.
///
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`, the row kebab menu carries Rename… /
/// Remove… entries whose action targets dispatch through the
/// per-row [`gio::SimpleActionGroup`] installed by [`bind_row`]. The
/// activation callback maps the fired action name onto one of these
/// variants via [`dispatch_row_action`] and forwards it through
/// `relm4::Sender::output` so `AppModel` can open the corresponding
/// dialog widget against the row's [`AccountId`].
///
/// The [`QueryChanged`](AccountListOutput::QueryChanged) variant
/// is emitted whenever the embedded `gtk::SearchEntry`'s
/// `search-changed` signal fires, so `AppModel` can recompute the
/// filtered row set via
/// [`filtered_row_models_from_vault`] /
/// [`selected_row_after_refresh`] and feed the result back through
/// [`AccountListMsg::Refresh`]. Pushing the filter through `AppModel`
/// keeps `paladin_core::account_matches_search` the single source of
/// truth for the substring match (`AccountListComponent` never
/// reaches for the live `Vault`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountListOutput {
    /// User asked to rename the account identified by the inner
    /// [`AccountId`]. `AppModel` reaches into its live `Vault` to
    /// look up the current label and opens `RenameDialog`.
    OpenRenameDialog(AccountId),
    /// User asked to remove the account identified by the inner
    /// [`AccountId`]. `AppModel` opens `RemoveDialog` (the destructive
    /// confirmation per §"Component tree" > `RemoveDialog`).
    OpenRemoveDialog(AccountId),
    /// User changed the search-bar query. `AppModel` recomputes the
    /// filtered row set against the live `Vault` and sends a
    /// matching [`AccountListMsg::Refresh`] back so the
    /// `gio::ListStore` reflects the new filter.
    QueryChanged(String),
}

/// Dispatch table mapping a row-level action name onto the typed
/// [`AccountListOutput`] forwarded to `AppModel`.
///
/// Returns [`Some`] for [`ROW_RENAME_ACTION_NAME`] /
/// [`ROW_REMOVE_ACTION_NAME`] and [`None`] for every other input —
/// the widget layer installs exactly two actions on each row, so an
/// unrecognized name signals a wiring drift (typo in the action
/// group, stale kebab menu target, …) and stays a silent no-op
/// rather than crashing the row.
#[must_use]
pub fn dispatch_row_action(name: &str, id: AccountId) -> Option<AccountListOutput> {
    match name {
        ROW_RENAME_ACTION_NAME => Some(AccountListOutput::OpenRenameDialog(id)),
        ROW_REMOVE_ACTION_NAME => Some(AccountListOutput::OpenRemoveDialog(id)),
        _ => None,
    }
}

/// Non-secret projection of a single account into the form the
/// row factory binds onto its widgets.
///
/// Built from `paladin_core::AccountSummary` (which itself carries
/// no secret material), so the `gio::ListStore` of these models can
/// safely live on the GTK main loop. The widget layer reads
/// [`AccountRowModel::display_label`] verbatim for the row's
/// `<issuer>:<label>` heading; [`AccountRowModel::kind`] /
/// [`AccountRowModel::counter`] are echoed forward so a future
/// commit's per-row factory (copy button, HOTP "next" button,
/// progress indicator) can branch on them without re-reading the
/// underlying account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRowModel {
    /// Stable account identifier — also the row's "key" when the
    /// widget layer needs to round-trip an action (copy, kebab
    /// menu, …) back to `paladin_core::Vault`.
    pub id: AccountId,
    /// Pre-formatted `<issuer>:<label>` heading per
    /// [`crate::account_row::display_label`]. Empty / missing
    /// issuer collapses to the bare label so the row never carries
    /// a dangling `:label` colon (parity with TUI / CLI).
    pub display_label: String,
    /// TOTP vs. HOTP. Lets the widget layer pick the right
    /// trailing controls without going back to the vault.
    pub kind: AccountKindSummary,
    /// HOTP "next counter that will be used" projection, mirroring
    /// `AccountSummary::counter`. `None` for TOTP rows and for any
    /// HOTP row whose summary did not carry a counter (defensive —
    /// `paladin_core::Vault::summaries` always supplies one for
    /// HOTP).
    pub counter: Option<u64>,
}

/// Project every account in `vault` into an [`AccountRowModel`].
///
/// Preserves `Vault::summaries()` insertion order so the
/// `gio::ListStore` reflects the on-disk order. The projection is
/// `AccountSummary`-driven, so no secret bytes leave `paladin_core`
/// — the row models can be cloned, stored in `BoxedAnyObject`, and
/// logged under `--exit-after-startup` without risking leakage.
#[must_use]
pub fn row_models_from_vault(vault: &Vault) -> Vec<AccountRowModel> {
    vault
        .summaries()
        .map(|summary| AccountRowModel {
            id: summary.id,
            display_label: display_label(&summary),
            kind: summary.kind,
            counter: summary.counter,
        })
        .collect()
}

/// Project a single account in `vault` into an [`AccountRowModel`].
///
/// Mirrors [`row_models_from_vault`] for one [`AccountId`] so
/// `AppModel` can re-derive the updated [`AccountRowModel`] after a
/// successful vault mutation (rename, HOTP advance, settings save)
/// without re-projecting every row. Returns `None` when `id` is not
/// present in `vault.summaries()` — the caller treats that as a
/// no-op rather than a defensive failure since a stray dispatch
/// against a freshly-removed id can race with the worker outcome.
///
/// Field shape matches [`row_models_from_vault`] verbatim so the
/// single-row and bulk projections never drift. The projection is
/// `AccountSummary`-driven, so no secret bytes leave `paladin_core`.
#[must_use]
pub fn row_model_for_account(vault: &Vault, id: AccountId) -> Option<AccountRowModel> {
    vault
        .summaries()
        .find(|summary| summary.id == id)
        .map(|summary| AccountRowModel {
            id: summary.id,
            display_label: display_label(&summary),
            kind: summary.kind,
            counter: summary.counter,
        })
}

/// Project every account in `vault` whose `<issuer>:<label>` match
/// key contains `query` (case-insensitive) into an
/// [`AccountRowModel`], preserving vault insertion order among
/// matches.
///
/// Composes [`crate::search::filtered_account_ids`] with
/// [`row_model_for_account`] so the GUI's incremental search filter
/// shares the case-insensitive substring contract used by
/// `paladin_core::account_matches_search` (and therefore by the CLI
/// / TUI search). Empty `query` matches every account.
///
/// The projection is `AccountSummary`-driven via
/// [`row_model_for_account`], so no secret bytes leave
/// `paladin_core`.
#[must_use]
pub fn filtered_row_models_from_vault(vault: &Vault, query: &str) -> Vec<AccountRowModel> {
    filtered_account_ids(vault, query)
        .into_iter()
        .filter_map(|id| row_model_for_account(vault, id))
        .collect()
}

/// Pick the selected row id after the `AccountListComponent`'s
/// `gio::ListStore` has been spliced with a fresh `rows` set.
///
/// Wraps [`paladin_core::select_after_filter`] against the row
/// models the list binds so the GUI's selection-preservation rule
/// matches the CLI / TUI search-selection contract (DESIGN §6 / §7):
///
/// * `prev = Some(id)` survives iff `id` is still in `rows`;
/// * otherwise the first id in `rows` wins (vault insertion order);
/// * an empty `rows` returns `None`, so the list view clears its
///   `SingleSelection` rather than pointing at a stale id.
#[must_use]
pub fn selected_row_after_refresh(
    prev: Option<AccountId>,
    rows: &[AccountRowModel],
) -> Option<AccountId> {
    let ids: Vec<AccountId> = rows.iter().map(|row| row.id).collect();
    select_after_filter(prev, &ids)
}

/// Project an [`AccountRowModel`] onto the no-visible-code
/// [`RowDisplay`] the row factory binds at mount time.
///
/// The widget layer holds no live `Code` before the first per-tick
/// TOTP compute, and HOTP rows stay hidden until the user activates
/// "next". The row factory therefore binds every row through this
/// helper, which mirrors `account_row::project_row(summary, None)`
/// but works off the already-projected summary (`AccountRowModel`)
/// instead of the raw `AccountSummary`. Pairing the two helpers in
/// one place keeps the hidden and revealed projections from
/// drifting.
///
/// For HOTP rows whose `counter` is `None`, the helper defensively
/// renders [`CounterText::Stored`]`(0)` so the row factory never
/// has to branch on a missing summary counter — same fallback as
/// `account_row::counter_display`.
#[must_use]
pub fn hidden_row_display(model: &AccountRowModel) -> RowDisplay {
    let counter = match model.kind {
        AccountKindSummary::Totp => None,
        AccountKindSummary::Hotp => Some(CounterText::Stored(model.counter.unwrap_or(0))),
    };
    RowDisplay {
        label: model.display_label.clone(),
        kind: model.kind,
        code: CodeDisplay::Hidden,
        counter,
        copy_enabled: copy_enabled(model.kind, false),
        next_button_visible: next_button_visible(model.kind),
        progress_visible: progress_visible(model.kind),
        kebab_visible: kebab_visible(model.kind),
    }
}

/// Format the §"Smoke test" stdout marker line for the currently
/// rendered row set.
///
/// The shape is `paladin-gtk: account_list_rows=<labels>` where
/// `<labels>` is the pipe-joined list of
/// [`AccountRowModel::display_label`] entries in render order.
/// Pipe is chosen because `:` is already used inside
/// `<issuer>:<label>`, and pipes are not used by any other
/// `display_label` projection (validated upstream in
/// `account_row::display_label`).
#[must_use]
pub fn format_rendered_marker(rows: &[AccountRowModel]) -> String {
    let labels: Vec<&str> = rows.iter().map(|r| r.display_label.as_str()).collect();
    format!("{ACCOUNT_LIST_RENDERED_MARKER_PREFIX}{}", labels.join("|"))
}

/// Format the per-row widget-state stdout marker line.
///
/// The shape is
/// `paladin-gtk: account_list_widget_states=<entries>` where
/// `<entries>` is the pipe-joined per-row state in render order.
/// Each entry encodes comma-separated key/value pairs:
///
/// * `copy:on` / `copy:off` — driven by
///   [`crate::account_row::RowDisplay::copy_enabled`].
/// * `next:on` / `next:off` — driven by
///   [`crate::account_row::RowDisplay::next_button_visible`]; the
///   HOTP "next" button is exposed on HOTP rows and hidden on TOTP
///   rows.
/// * `kebab:on` / `kebab:off` — driven by
///   [`crate::account_row::RowDisplay::kebab_visible`]; every row
///   exposes the Rename… / Remove… kebab menu unconditionally, so
///   this key renders `on` in practice. Pinning the entry keeps
///   "the bundle mounted the kebab" an explicit invariant.
///
/// Pipe matches [`format_rendered_marker`]; colon separates key
/// from value and comma separates key/value pairs within a row,
/// because none of those tokens show up inside any value today.
#[must_use]
pub fn format_widget_states_marker(displays: &[RowDisplay]) -> String {
    let entries: Vec<String> = displays
        .iter()
        .map(|d| {
            format!(
                "copy:{},next:{},kebab:{}",
                if d.copy_enabled { "on" } else { "off" },
                if d.next_button_visible { "on" } else { "off" },
                if d.kebab_visible { "on" } else { "off" },
            )
        })
        .collect();
    format!(
        "{ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX}{}",
        entries.join("|"),
    )
}

/// Construction parameters for [`AccountListComponent`].
#[derive(Debug, Clone)]
pub struct AccountListInit {
    /// Row models projected from the live vault by
    /// [`row_models_from_vault`] (when `initial_query` is empty) or
    /// by [`filtered_row_models_from_vault`] (when the parent is
    /// preserving a non-empty query across a controller rebuild).
    /// Cloned into the `gio::ListStore` at mount time; subsequent
    /// updates flow through [`AccountListMsg::Refresh`].
    pub rows: Vec<AccountRowModel>,
    /// Search-bar query the component restores on mount.
    ///
    /// Defaults to the empty string for a fresh launch. The parent
    /// passes the most recently observed
    /// [`AccountListOutput::QueryChanged`] value so the visible
    /// query survives a controller rebuild (e.g. after a successful
    /// passphrase transition that bounces through `Locked`).
    pub initial_query: String,
    /// Selection the component installs on the
    /// [`gtk::SingleSelection`] after seeding the store. `None`
    /// clears the selection (i.e. the sentinel
    /// `gtk::INVALID_LIST_POSITION` row index). Mirrors the
    /// [`AccountListMsg::Refresh`] `selection` field so the rebuild
    /// and the live refresh share one selection-application code
    /// path.
    pub initial_selection: Option<AccountId>,
}

/// Widget-bearing list view for the unlocked vault state.
///
/// Owns a `gio::ListStore` of `glib::BoxedAnyObject` items wrapping
/// [`AccountRowModel`] entries and a `gtk::SignalListItemFactory`
/// that maps each model onto a per-row widget bundle (display
/// label, HOTP counter, code label) driven by [`hidden_row_display`].
/// The factory does not touch the live `Account` or `Code` — it
/// only reads the already-projected [`AccountRowModel`], so the
/// row binding is secret-free.
///
/// The component additionally owns the `gtk::SearchBar` hosting a
/// `gtk::SearchEntry` and the `gtk::SingleSelection` driving row
/// selection. `current_query` mirrors the entry's text so the parent
/// can re-feed it via [`AccountListInit::initial_query`] on a
/// rebuild; `current_selection` mirrors the visible row id for the
/// same reason. The widget references are cached on `self` so the
/// [`SimpleComponent::update`] handler can drive
/// [`AccountListMsg::Refresh`] (splice the store + apply selection)
/// and [`AccountListMsg::SetSearchModeEnabled`] (toggle the
/// `search-mode-enabled` property) imperatively without round-tripping
/// through the relm4 `view!` macro on every refresh.
pub struct AccountListComponent {
    /// Backing `gio::ListStore` of `BoxedAnyObject<AccountRowModel>`.
    /// Spliced inside [`AccountListMsg::Refresh`] so add / remove /
    /// rename / settings refresh and search-filter refresh share one
    /// code path.
    model: gio::ListStore,
    /// `gtk::SingleSelection` wrapping [`Self::model`]. Selection is
    /// reapplied through [`apply_selection`] after every
    /// [`AccountListMsg::Refresh`] so the user's cursor follows the
    /// CLI / TUI selection-preservation rule
    /// ([`selected_row_after_refresh`]).
    selection: gtk::SingleSelection,
    /// `gtk::SearchBar` whose `search-mode-enabled` property is
    /// toggled by [`AccountListMsg::SetSearchModeEnabled`]. The
    /// header-bar search-toggle button (wired in `app/model.rs`)
    /// dispatches that message so the bar reveals / hides in
    /// lockstep with the toggle's `active` state.
    search_bar: gtk::SearchBar,
    /// `gtk::SearchEntry` nested inside [`Self::search_bar`]. Its
    /// `search-changed` signal fires [`AccountListMsg::SetQuery`],
    /// which the [`SimpleComponent::update`] handler mirrors into
    /// [`Self::current_query`] and bubbles up as
    /// [`AccountListOutput::QueryChanged`].
    #[allow(dead_code)]
    search_entry: gtk::SearchEntry,
    /// Last query the user typed into [`Self::search_entry`].
    /// Cached so [`AccountListMsg::Refresh`] can recompute the
    /// selection without rereading the entry buffer.
    current_query: String,
    /// Last selected row id surfaced to the parent. Updated by
    /// [`AccountListMsg::Refresh`] so a subsequent rebuild can pass
    /// it back through [`AccountListInit::initial_selection`].
    current_selection: Option<AccountId>,
}

/// Messages handled by [`AccountListComponent`].
///
/// * [`SetQuery`](AccountListMsg::SetQuery): emitted from the
///   `gtk::SearchEntry`'s `search-changed` signal. Caches the new
///   query and bubbles it up as
///   [`AccountListOutput::QueryChanged`] so `AppModel` recomputes
///   the filtered row set against the live `Vault`.
/// * [`Refresh`](AccountListMsg::Refresh): sent by `AppModel` after
///   a vault mutation or a search-filter recomputation. Splices the
///   `gio::ListStore` with the new row set and reapplies the
///   selection so the visible state matches the just-committed
///   `Vault`.
/// * [`SetSearchModeEnabled`](AccountListMsg::SetSearchModeEnabled):
///   sent by `AppModel` when the header-bar search-toggle button
///   flips. Drives the `gtk::SearchBar`'s `search-mode-enabled`
///   property so the bar reveals / hides in lockstep with the
///   toggle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountListMsg {
    /// New query text from the `gtk::SearchEntry`'s `search-changed`
    /// signal.
    SetQuery(String),
    /// New filtered row set (and selection) from `AppModel`.
    Refresh {
        /// Rows to render in vault insertion order. Empty when the
        /// vault has no matching accounts.
        rows: Vec<AccountRowModel>,
        /// Selection to install on the `gtk::SingleSelection`.
        /// `None` clears the selection.
        selection: Option<AccountId>,
    },
    /// Show / hide the `gtk::SearchBar`. Mirrors the header-bar
    /// search-toggle button's `active` state.
    SetSearchModeEnabled(bool),
}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for AccountListComponent {
    type Init = AccountListInit;
    type Input = AccountListMsg;
    type Output = AccountListOutput;

    view! {
        #[root]
        gtk::Box {
            set_orientation: gtk::Orientation::Vertical,
            set_hexpand: true,
            set_vexpand: true,

            append: &search_bar,

            gtk::ScrolledWindow {
                set_hexpand: true,
                set_vexpand: true,

                #[wrap(Some)]
                set_child = &gtk::ListView {
                    set_model: Some(&selection),
                    set_factory: Some(&factory),
                    add_css_class: "navigation-sidebar",
                },
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = gio::ListStore::new::<glib::BoxedAnyObject>();
        for row in &init.rows {
            model.append(&glib::BoxedAnyObject::new(row.clone()));
        }

        let selection = gtk::SingleSelection::new(Some(model.clone()));
        apply_selection(&selection, &init.rows, init.initial_selection);

        let factory = build_row_factory(sender.output_sender().clone());

        let search_entry = gtk::SearchEntry::builder()
            .placeholder_text("Search accounts")
            .build();
        if !init.initial_query.is_empty() {
            search_entry.set_text(&init.initial_query);
        }
        let entry_input = sender.input_sender().clone();
        search_entry.connect_search_changed(move |entry| {
            let text: String = entry.text().into();
            let _ = entry_input.send(AccountListMsg::SetQuery(text));
        });

        let search_bar = gtk::SearchBar::builder()
            .search_mode_enabled(false)
            .show_close_button(true)
            .build();
        search_bar.set_child(Some(&search_entry));
        search_bar.connect_entry(&search_entry);

        let widgets = view_output!();

        let component = AccountListComponent {
            model,
            selection,
            search_bar,
            search_entry,
            current_query: init.initial_query,
            current_selection: init.initial_selection,
        };
        ComponentParts {
            model: component,
            widgets,
        }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            AccountListMsg::SetQuery(query) => {
                if self.current_query == query {
                    return;
                }
                self.current_query.clone_from(&query);
                let _ = sender.output(AccountListOutput::QueryChanged(query));
            }
            AccountListMsg::Refresh { rows, selection } => {
                // Parent's `selection` is treated as the preferred
                // prior id: `Some(id)` is the explicit ask (e.g.
                // post-Add the new account should win),
                // `None` falls back to the component's
                // [`Self::current_selection`] so the user's cursor
                // survives a search-query refresh that does not
                // remove the selected row. The actual surviving id
                // is resolved by [`selected_row_after_refresh`] so
                // the §6 / §7 preservation rule lives in pure logic.
                let prev = selection.or(self.current_selection);
                let effective_selection = selected_row_after_refresh(prev, &rows);
                splice_rows(&self.model, &rows);
                apply_selection(&self.selection, &rows, effective_selection);
                self.current_selection = effective_selection;
            }
            AccountListMsg::SetSearchModeEnabled(enabled) => {
                self.search_bar.set_search_mode(enabled);
            }
        }
    }
}

/// Replace the `gio::ListStore`'s contents with `rows`.
///
/// `gio::ListStore::splice(position, n_removals, additions)` swaps
/// the entire model in one notify so the `gtk::ListView` emits a
/// single `items-changed` instead of one per row. Cloning the row
/// models into fresh `BoxedAnyObject`s keeps the store's elements
/// owned by the store (no shared references with the parent's
/// projection).
fn splice_rows(store: &gio::ListStore, rows: &[AccountRowModel]) {
    let additions: Vec<glib::Object> = rows
        .iter()
        .map(|row| glib::BoxedAnyObject::new(row.clone()).upcast::<glib::Object>())
        .collect();
    let n_removals = store.n_items();
    store.splice(0, n_removals, &additions);
}

/// Install `target` as the [`gtk::SingleSelection`]'s selected row.
///
/// Resolves the row id to its position in `rows`, falling back to
/// the sentinel `gtk::INVALID_LIST_POSITION` (no selection) when the
/// id is `None` or not present. The widget layer never picks the
/// selection itself; the choice flows from
/// [`selected_row_after_refresh`] / [`AccountListInit::initial_selection`]
/// so the filter-aware preservation rule stays in pure logic.
fn apply_selection(
    selection: &gtk::SingleSelection,
    rows: &[AccountRowModel],
    target: Option<AccountId>,
) {
    let position = target
        .and_then(|id| rows.iter().position(|row| row.id == id))
        .map_or(gtk::INVALID_LIST_POSITION, |idx| {
            u32::try_from(idx).unwrap_or(gtk::INVALID_LIST_POSITION)
        });
    selection.set_selected(position);
}

/// Placeholder rendered in the code column whenever the row's
/// projection carries [`CodeDisplay::Hidden`].
///
/// TOTP rows land here before the first per-tick compute; HOTP
/// rows land here before "next" and after the reveal window
/// expires. A fixed six-bullet glyph keeps the column width
/// stable across hidden / revealed transitions for the common
/// six-digit code without reaching into per-account `digits`.
const HIDDEN_CODE_PLACEHOLDER: &str = "••••••";

/// Render a [`CounterText`] into the `#N` label the row binds.
///
/// The HOTP row never distinguishes `Stored` vs `Used` in the
/// rendered text; the source of the counter is captured in the
/// projection so future per-row diagnostics can branch on it
/// without re-reading the row.
fn format_counter_label(counter: CounterText) -> String {
    let n = match counter {
        CounterText::Stored(n) | CounterText::Used(n) => n,
    };
    format!("#{n}")
}

/// Build the `gtk::SignalListItemFactory` that maps an
/// `AccountRowModel` (wrapped in `BoxedAnyObject`) onto the per-row
/// widget bundle (display label, HOTP counter, code label).
///
/// Each row binds [`hidden_row_display`] to drive the visible text;
/// the factory itself never reaches for the live `Account` or
/// `Code` — it only reads the already-projected
/// [`AccountRowModel`], so the row binding stays secret-free. The
/// per-row widget bundle expands incrementally; copy / "next" /
/// kebab affordances per §"Component tree" > `AccountRowComponent`
/// land in follow-up commits.
///
/// `output_sender` is cloned into each row's
/// [`gio::SimpleActionGroup`] activation closure so kebab Rename… /
/// Remove… activations route through [`dispatch_row_action`] and
/// forward typed [`AccountListOutput`] messages to `AppModel`.
fn build_row_factory(
    output_sender: relm4::Sender<AccountListOutput>,
) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let Some(list_item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        list_item.set_child(Some(&build_row_widget()));
    });
    factory.connect_bind(move |_, item| {
        let Some(list_item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let Some(child) = list_item.child() else {
            return;
        };
        let Ok(container) = child.downcast::<gtk::Box>() else {
            return;
        };
        let Some(obj) = list_item.item() else {
            return;
        };
        let Ok(boxed) = obj.downcast::<glib::BoxedAnyObject>() else {
            return;
        };
        let row: std::cell::Ref<AccountRowModel> = boxed.borrow();
        let display = hidden_row_display(&row);
        bind_row(&container, &display);
        install_row_action_group(&container, row.id, output_sender.clone());
    });
    factory
}

/// Construct one row's widget bundle.
///
/// The container is a horizontal `gtk::Box` whose children are
/// appended in the order `display label → HOTP counter → code
/// label → copy button → HOTP next button → kebab menu`. The label
/// expands to claim the row's free space so the counter / code
/// labels and the trailing affordances stay end-aligned and the
/// column edges line up across rows. [`bind_row`] walks the children
/// in this same order to apply the projection.
///
/// The kebab `gtk::MenuButton` carries a `view-more-symbolic` icon,
/// the `.flat` style class for the row-trailing affordance look, and
/// a `gio::Menu` model built by [`build_kebab_menu_model`] with the
/// Rename… / Remove… entries described in
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`. The action targets land in a follow-up
/// commit that wires `AccountListMsg::OpenRenameDialog` /
/// `OpenRemoveDialog` per row.
fn build_row_widget() -> gtk::Box {
    let container = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .hexpand(true)
        .build();
    let label = gtk::Label::builder()
        .halign(gtk::Align::Start)
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
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
    let copy = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy code")
        .valign(gtk::Align::Center)
        .build();
    copy.add_css_class("flat");
    let next = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Reveal next HOTP code")
        .valign(gtk::Align::Center)
        .build();
    next.add_css_class("flat");
    let kebab = gtk::MenuButton::builder()
        .icon_name("view-more-symbolic")
        .tooltip_text("More actions")
        .valign(gtk::Align::Center)
        .menu_model(&build_kebab_menu_model())
        .build();
    kebab.add_css_class("flat");
    container.append(&label);
    container.append(&counter);
    container.append(&code);
    container.append(&copy);
    container.append(&next);
    container.append(&kebab);
    container
}

/// Build the kebab `gio::Menu` shared by every row.
///
/// The menu carries two entries per
/// `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`:
///
/// * "Rename…" — opens `RenameDialog` for the row's account.
/// * "Remove…" — opens `RemoveDialog` for the row's account.
///
/// Each entry binds to a `row.rename` / `row.remove` action that
/// resolves against the per-row [`gio::SimpleActionGroup`] installed
/// by [`install_row_action_group`] in the row factory's bind step.
/// Centralizing the model here means the rows share a single
/// canonical menu shape and the labels stay in lockstep with the
/// smoke test.
fn build_kebab_menu_model() -> gio::Menu {
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

/// Install (or replace) the per-row [`gio::SimpleActionGroup`] that
/// dispatches kebab Rename… / Remove… activations through
/// [`dispatch_row_action`] back up to `AppModel`.
///
/// Called from the row factory's `connect_bind` callback because
/// `gtk::ListView` recycles row containers as the user scrolls —
/// each rebind re-captures the new row's [`AccountId`] in the
/// activation closure so the dispatched [`AccountListOutput`] always
/// targets the currently bound row.
///
/// The group name matches [`ROW_ACTION_GROUP_NAME`] so the menu
/// targets `row.rename` / `row.remove` built by
/// [`build_kebab_menu_model`] resolve correctly.
fn install_row_action_group(
    container: &gtk::Box,
    id: AccountId,
    output_sender: relm4::Sender<AccountListOutput>,
) {
    let actions = gio::SimpleActionGroup::new();

    let rename = gio::SimpleAction::new(ROW_RENAME_ACTION_NAME, None);
    let rename_sender = output_sender.clone();
    rename.connect_activate(move |_, _| {
        if let Some(out) = dispatch_row_action(ROW_RENAME_ACTION_NAME, id) {
            let _ = rename_sender.send(out);
        }
    });
    actions.add_action(&rename);

    let remove = gio::SimpleAction::new(ROW_REMOVE_ACTION_NAME, None);
    let remove_sender = output_sender;
    remove.connect_activate(move |_, _| {
        if let Some(out) = dispatch_row_action(ROW_REMOVE_ACTION_NAME, id) {
            let _ = remove_sender.send(out);
        }
    });
    actions.add_action(&remove);

    container.insert_action_group(ROW_ACTION_GROUP_NAME, Some(&actions));
}

/// Bind a [`RowDisplay`] onto the child widgets of a
/// previously-constructed row container.
///
/// The children are reached by walking `first_child` / `next_sibling`
/// in the same order [`build_row_widget`] appended them so the
/// factory never has to stash typed widget handles on the row.
///
/// * The copy button's sensitive state mirrors
///   [`RowDisplay::copy_enabled`]: TOTP rows are always sensitive;
///   HOTP rows are sensitive only while a visible reveal code is in
///   hand, matching the `IMPLEMENTATION_PLAN_04_GTK.md` §"Component
///   tree" > `AccountRowComponent` rule that copying a hidden HOTP
///   row is disabled.
/// * The HOTP "next" button's visibility mirrors
///   [`RowDisplay::next_button_visible`]: HOTP rows show it (the
///   user activates it to advance the counter and open a reveal
///   window); TOTP rows hide it.
/// * The kebab `MenuButton`'s visibility mirrors
///   [`RowDisplay::kebab_visible`]: every row exposes the
///   Rename… / Remove… menu unconditionally. The visibility bind is
///   kept for parity with the other affordances so a future
///   per-row override stays a one-line projection change.
fn bind_row(container: &gtk::Box, display: &RowDisplay) {
    let Some(label) = container.first_child().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(counter) = label.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(code) = counter.next_sibling().and_downcast::<gtk::Label>() else {
        return;
    };
    let Some(copy) = code.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };
    let Some(next) = copy.next_sibling().and_downcast::<gtk::Button>() else {
        return;
    };
    let Some(kebab) = next.next_sibling().and_downcast::<gtk::MenuButton>() else {
        return;
    };

    label.set_label(&display.label);

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

    copy.set_sensitive(display.copy_enabled);
    next.set_visible(display.next_button_visible);
    kebab.set_visible(display.kebab_visible);
}
