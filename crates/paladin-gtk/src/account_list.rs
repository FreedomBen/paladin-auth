// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AccountListComponent` for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountListComponent` and Appendix A §A.2 / §A.8, the unlocked
//! view is a `gtk::ColumnView` driven by a
//! `gio::ListStore<crate::row_item::RowItem>` and a
//! `gtk::SingleSelection`. Column cell rendering, the per-cell
//! `display-changed` subscriptions, and the per-row
//! `gio::SimpleActionGroup` install all live in
//! [`crate::column_view`]; this module owns the higher-level
//! component (store + selection + search bar + navigation
//! controllers) and the pure-logic projections feeding it.
//!
//! Per-tick TOTP refreshes flow through
//! [`crate::row_item::RowItem::set_display`] on the matching store
//! item — the store is **never** `splice`d from the tick handler so
//! cell-factory subscriptions survive the refresh and the
//! "buttons flicker every tick" regression that the prior
//! `gio::ListStore` + `SignalListItemFactory` setup hit on every
//! `splice` call stays fixed.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use relm4::gtk;
use relm4::gtk::gio;
use relm4::gtk::gio::prelude::*;
use relm4::gtk::glib;
use relm4::gtk::prelude::*;
use relm4::prelude::*;

use paladin_core::{select_after_filter, AccountId, AccountKindSummary, Vault};

use crate::account_row::{
    apply_busy_mask, copy_enabled, kebab_enabled, kebab_visible, next_button_enabled,
    next_button_visible, progress_visible, summary_display_label, CodeDisplay, CounterText,
    RowDisplay,
};
use crate::column_view::{
    any_totp, apply_interleaved_splice_plan, build_account_column_factory,
    build_account_column_sorter, build_code_column_factory, build_copy_column_factory,
    build_kebab_column_factory, build_next_code_column_factory, build_time_column_factory,
    drop_row_popover, RowPopoverSlot,
};
use crate::row_context_menu::PopoverInvalidation;
use crate::row_item::RowItem;
use crate::search::filtered_account_ids;

/// Resolve the per-row [`RowDisplay`] the row factory should bind
/// for a given [`AccountRowModel`].
///
/// Routes through the live-display cache first so per-tick TOTP /
/// HOTP-reveal updates pick up the most recent visible code without
/// re-deriving the projection from the vault. When the cache misses
/// (the initial mount before the first tick, the brief window
/// between [`AccountListMsg::Refresh`] and the next tick, or any
/// HOTP row outside its reveal window), falls back to
/// [`hidden_row_display`].
///
/// The helper is pure logic so the cache-then-hidden contract is
/// pinned by `tests/account_list_logic.rs` without spinning up GTK
/// or libadwaita. The widget layer uses it to seed each
/// [`crate::row_item::RowItem`]'s initial display when
/// [`AccountListMsg::Refresh`] inserts a fresh row, before any
/// per-tick driver has computed the first visible code.
#[must_use]
pub fn bind_display_for_row(
    live: Option<&RowDisplay>,
    model: &AccountRowModel,
    busy: bool,
) -> RowDisplay {
    let mut display = live.cloned().unwrap_or_else(|| hidden_row_display(model));
    apply_busy_mask(&mut display, busy);
    display
}

/// Prune cache entries whose [`AccountId`] no longer appears in
/// `rows`.
///
/// Called by [`AccountListMsg::Refresh`] so a Remove / search-filter
/// rebuild that drops accounts does not leave a stale live display
/// behind. Surviving entries are preserved so the user keeps seeing
/// the live code immediately after a non-removing refresh (Add,
/// Rename, settings change) without waiting for the next tick.
///
/// The renamed-account edge case is benign: the cache entry's
/// `RowDisplay.label` may be the old `<issuer>:<label>` text for at
/// most one tick interval after a rename, then the next tick
/// re-projects through [`crate::ticker::tick`] and overwrites the
/// entry with the fresh label.
pub fn prune_cache_to_rows<S: std::hash::BuildHasher>(
    cache: &mut HashMap<AccountId, RowDisplay, S>,
    rows: &[AccountRowModel],
) {
    let surviving: std::collections::HashSet<AccountId> = rows.iter().map(|r| r.id).collect();
    cache.retain(|id, _| surviving.contains(id));
}

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

/// Output forwarded from [`AccountListComponent`] up to `AppModel`
/// in response to a row-level user intent or a search-query change.
///
/// Per-row activations (Rename… / Remove… kebab entries, copy
/// button, HOTP "next" button) originate inside the cell factories
/// shipped in [`crate::column_view`]; those factories emit
/// [`AccountListOutput`] directly through the sender threaded into
/// [`build_code_column_factory`] /
/// [`build_copy_column_factory`] /
/// [`build_kebab_column_factory`], so no intermediate per-row
/// dispatch table is needed.
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
    /// User asked to edit the account identified by the inner
    /// [`AccountId`]. `AppModel` reaches into its live `Vault` to
    /// look up the current metadata and opens `EditDialog`.
    OpenEditDialog(AccountId),
    /// User asked to view the per-account `otpauth://` QR code for
    /// the account identified by the inner [`AccountId`].
    /// `AppModel` resolves the matching `AccountSummary` and mounts
    /// `ExportQrDialog` against the live `(Vault, Store)` pair per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"QR export dialog
    /// implementation". Read-only — the dialog never enters
    /// `Vault::mutate_and_save`, never advances an HOTP counter,
    /// and never bumps `updated_at`.
    OpenExportQrDialog(AccountId),
    /// User asked to remove the account identified by the inner
    /// [`AccountId`]. `AppModel` opens `RemoveDialog` (the destructive
    /// confirmation per §"Component tree" > `RemoveDialog`).
    OpenRemoveDialog(AccountId),
    /// User activated the HOTP row's "next" button. `AppModel`
    /// transitions to `UnlockedBusy { HotpAdvance, .. }` and spawns
    /// the `Vault::hotp_peek` + `Vault::hotp_advance` worker per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    /// `AccountRowComponent`. The reveal-window publication routes
    /// through [`crate::hotp_reveal::apply_advance_outcome`] once
    /// the worker returns.
    AdvanceHotp(AccountId),
    /// User clicked the per-row copy `gtk::Button`. `AppModel`
    /// reads the row's visible code via
    /// [`crate::clipboard_clear::prepare_copy_bytes`], writes the
    /// bytes through `gdk::Clipboard::set_text`, and (when the user
    /// has opted in via `clipboard.clear_enabled`) seeds the
    /// pending wipe through [`crate::clipboard_clear::schedule_copy`]
    /// per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    /// `AccountRowComponent`. Hidden HOTP rows ship a desensitized
    /// button via [`crate::account_row::copy_enabled`], so this
    /// variant never fires before a reveal opens.
    CopyCode(AccountId),
    /// User clicked the per-row "Next" cell button (or pressed
    /// `Ctrl+Shift+C` with a TOTP row selected).  `AppModel`
    /// resolves the upcoming code via
    /// `Vault::totp_next_code(id, now)`, writes the digits through
    /// the shared
    /// [`crate::clipboard_clear::prepare_copy_bytes`] /
    /// `gdk::Clipboard::set_text` /
    /// [`crate::clipboard_clear::schedule_copy`] pipeline (so the
    /// user's `clipboard.clear_enabled` opt-in arms a wipe), and
    /// raises an `adw::Toast` reading
    /// `Next code copied, valid in {seconds_until_valid}s` on the
    /// shared `adw::ToastOverlay`.  HOTP rows project
    /// `next_code = None` (see
    /// [`crate::account_row::next_code_display`]) and the cell
    /// button is `sensitive = false`, so this variant never fires
    /// for HOTP rows.
    CopyNextCode(AccountId),
    /// User pressed Enter on an un-revealed HOTP row (the row had
    /// no visible code at activation time). Emitted by
    /// [`default_row_activation`] for that one specific case;
    /// every other Enter-activation surface (TOTP rows, revealed
    /// HOTP rows) lands on [`Self::CopyCode`] instead.
    ///
    /// `AppModel` handles it by latching
    /// [`crate::app::model::AppModel::pending_copy_after_advance`]
    /// to the activated `AccountId` and dispatching the existing
    /// [`Self::AdvanceHotp`] path. The
    /// [`crate::app::model::AppMsg::HotpAdvanceWorkerCompleted`]
    /// handler reads the latch after publishing the reveal and
    /// re-dispatches a follow-up [`Self::CopyCode`], so the
    /// clipboard write lands through the same pipeline the per-row
    /// copy button uses.
    ActivateHotpAndCopy(AccountId),
    /// User changed the search-bar query. `AppModel` recomputes the
    /// filtered row set against the live `Vault` and sends a
    /// matching [`AccountListMsg::Refresh`] back so the
    /// `gio::ListStore` reflects the new filter.
    QueryChanged(String),
    /// The owned `gtk::SearchBar`'s `search-mode-enabled` property
    /// flipped. Emitted from the bar's `notify::search-mode-enabled`
    /// handler so `AppModel` can mirror the new state back onto the
    /// header-bar search-toggle `gtk::ToggleButton` — necessary
    /// because the bar can flip itself open via
    /// `set_key_capture_widget` (type-to-search) or
    /// [`AccountListMsg::FocusSearch`] (`/` / `Ctrl+L`), independent
    /// of the toggle click. The toggle's `active` is idempotent on
    /// re-assign so the round-trip (toggle click →
    /// `AppMsg::SearchToggled` → `AccountListMsg::SetSearchModeEnabled`
    /// → notify → here → `set_active`) does not loop.
    SearchModeChanged(bool),
}

/// Compute the per-row dispatch plan for a single
/// [`AccountListMsg::Tick`] payload.
///
/// Returns one `(AccountId, RowDisplay)` entry per
/// `(AccountId, RowDisplay)` in `displays` whose id appears in
/// `row_ids`. Rows whose id is **not** in `row_ids` are not in the
/// output: per the migration contract, the per-tick refresh path
/// must dispatch only to rows whose code changed, not rebuild every
/// visible row. Rows whose id has been removed from the visible row
/// set (e.g. a tick that races a search-filter refresh) are dropped
/// silently — the cache update still happens in the caller but the
/// stale id has no store entry to address.
///
/// Pure logic so `tests/account_list_logic.rs::tick_routes_only_to_changed_rows`
/// can pin the contract without spinning up GTK; the
/// [`AccountListComponent::update`] handler iterates the plan and
/// calls [`crate::row_item::RowItem::set_display`] on the matching
/// store item.
#[must_use]
pub fn tick_dispatch_plan<S: std::hash::BuildHasher>(
    displays: &[(AccountId, RowDisplay)],
    row_ids: &std::collections::HashSet<AccountId, S>,
) -> Vec<(AccountId, RowDisplay)> {
    displays
        .iter()
        .filter(|(id, _)| row_ids.contains(id))
        .cloned()
        .collect()
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
    /// [`crate::account_row::summary_display_label`]. Empty / missing
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
    /// Optional icon-hint slug from `AccountSummary::icon_hint`. The
    /// widget factory feeds this through
    /// [`crate::icon_resolution::resolve_display_icon`] against the
    /// live `gtk::IconTheme` to pick the row's icon, falling back to
    /// [`crate::icon_resolution::PLACEHOLDER_ICON_NAME`] on `None`,
    /// empty, or unresolved slugs. CLI / TUI ignore this field per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Icons".
    pub icon_hint: Option<String>,
    /// Issuer projected from `AccountSummary.issuer` with the
    /// [`crate::account_row::summary_display_label`] collapse rule
    /// applied: `Some(non_empty)` is preserved verbatim; `None` and
    /// `Some("")` both project to `None` so the row groups under the
    /// same "Other" bucket the display label already implies. Drives
    /// the interleaved section-header grouping in
    /// [`crate::column_view::apply_interleaved_splice_plan`] via
    /// [`issuer_group_header`] / [`row_section_header`].
    pub issuer: Option<String>,
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
            display_label: summary_display_label(&summary),
            kind: summary.kind,
            counter: summary.counter,
            icon_hint: summary.icon_hint.clone(),
            issuer: project_issuer(summary.issuer.as_deref()),
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
            display_label: summary_display_label(&summary),
            kind: summary.kind,
            counter: summary.counter,
            icon_hint: summary.icon_hint.clone(),
            issuer: project_issuer(summary.issuer.as_deref()),
        })
}

/// Header text used in place of an issuer for rows whose
/// `AccountRowModel.issuer` is `None`.
///
/// Pinned as a `pub const` so the §"Component tree" >
/// `AccountListComponent` > "Section headers" wording stays
/// consistent across the widget binding, the
/// `row_section_header` dispatch table, and the integration tests
/// in `tests/account_list_logic.rs`. Future locale work (DESIGN
/// §13) should swap this for a translated string in one place.
pub const SECTION_HEADER_FALLBACK: &str = "Other";

/// Apply the [`crate::account_row::summary_display_label`] collapse
/// rule to a raw issuer string projected off
/// `AccountSummary.issuer`: `Some(non_empty)` round-trips verbatim;
/// `None` and `Some("")` both collapse to `None`.
///
/// Pulled out so the bulk and single-row projections feed
/// [`AccountRowModel::issuer`] through the same rule the row's
/// display label already follows, keeping grouping and the
/// `<issuer>:<label>` body in lockstep.
fn project_issuer(issuer: Option<&str>) -> Option<String> {
    issuer.filter(|s| !s.is_empty()).map(str::to_string)
}

/// Display text for the section header above the first row of an
/// issuer group.
///
/// Returns the issuer string verbatim for rows whose
/// `AccountRowModel.issuer` is `Some(non_empty)`, and
/// [`SECTION_HEADER_FALLBACK`] (`"Other"`) for rows whose issuer is
/// `None`. Defensive against a hand-built `Some("")` (which
/// [`row_models_from_vault`] / [`row_model_for_account`] collapse to
/// `None` before this helper sees them): the empty string is
/// treated as `None` so a future projection path that forgets the
/// collapse cannot silently render a blank header.
///
/// Pure logic so `tests/account_list_logic.rs` pins the dispatch
/// table without spinning up GTK.
#[must_use]
pub fn issuer_group_header(model: &AccountRowModel) -> &str {
    model
        .issuer
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(SECTION_HEADER_FALLBACK)
}

/// Decide whether the section-header interleaver should emit a
/// section heading above `current`.
///
/// Returns `Some(header_text)` when `current` starts a new issuer
/// run — i.e. `prev` is `None` (this is the first row in the list)
/// or `prev`'s issuer differs from `current`'s — and `None` when
/// `current` continues an existing run. The header text is
/// [`issuer_group_header(current)`][issuer_group_header].
///
/// Equality is computed on the collapsed `Option<&str>` (so
/// `Some("")` and `None` group together, matching the projection
/// rule applied at the
/// [`row_models_from_vault`] / [`row_model_for_account`] boundary).
/// No case folding: `"GitHub"` and `"github"` form separate runs so
/// the user fixes drift by renaming, rather than the GUI silently
/// normalizing case.
///
/// Pure logic so the widget layer never duplicates the decision
/// table. Consumed by
/// [`crate::column_view::interleave_section_headers`] which feeds
/// the `gio::ListStore<crate::row_item::RowItem>`.
#[must_use]
pub fn row_section_header<'a>(
    prev: Option<&AccountRowModel>,
    current: &'a AccountRowModel,
) -> Option<&'a str> {
    let curr_issuer = current.issuer.as_deref().filter(|s| !s.is_empty());
    match prev {
        None => Some(issuer_group_header(current)),
        Some(prev_model) => {
            let prev_issuer = prev_model.issuer.as_deref().filter(|s| !s.is_empty());
            if prev_issuer == curr_issuer {
                None
            } else {
                Some(issuer_group_header(current))
            }
        }
    }
}

/// Precompute the per-row section-header dispatch table for the
/// current row set.
///
/// Returns a `Vec<Option<String>>` of the same length as `rows`,
/// where the entry at index `i` is `Some(header_text)` when row `i`
/// starts a new issuer run, and `None` when it continues the
/// previous run. Built by feeding each `(rows[i - 1], rows[i])`
/// pair through [`row_section_header`] (with `rows[-1]` treated as
/// `None` for the first row).
///
/// Kept as a pure-logic helper for `tests/account_list_logic.rs`
/// even though the widget layer now interleaves section rows
/// directly through
/// [`crate::column_view::interleave_section_headers`].
#[must_use]
pub fn precompute_section_headers(rows: &[AccountRowModel]) -> Vec<Option<String>> {
    rows.iter()
        .enumerate()
        .map(|(idx, current)| {
            let prev = if idx == 0 { None } else { rows.get(idx - 1) };
            row_section_header(prev, current).map(str::to_string)
        })
        .collect()
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
/// "next". The store therefore seeds every newly-inserted
/// [`crate::row_item::RowItem`] through this helper (via
/// [`crate::row_item::RowItem::from_row_model`]), which mirrors
/// `account_row::project_row(summary, None)` but works off the
/// already-projected summary (`AccountRowModel`) instead of the raw
/// `AccountSummary`. Pairing the two helpers in one place keeps the
/// hidden and revealed projections from drifting.
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
        next_code: None,
        counter,
        copy_enabled: copy_enabled(model.kind, false),
        next_button_visible: next_button_visible(model.kind),
        next_button_enabled: next_button_enabled(model.kind),
        progress_visible: progress_visible(model.kind),
        progress: None,
        kebab_visible: kebab_visible(model.kind),
        kebab_enabled: kebab_enabled(),
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
///   [`crate::account_row::RowDisplay::next_button_enabled`]; the
///   HOTP "next" button is enabled on HOTP rows and disabled (and
///   hidden) on TOTP rows. While `AppModel` is `UnlockedBusy` the
///   per-row [`apply_busy_mask`] flips this to `off`.
/// * `kebab:on` / `kebab:off` — driven by
///   [`crate::account_row::RowDisplay::kebab_enabled`]; every row
///   exposes the Rename… / Remove… kebab menu unconditionally, so
///   this key renders `on` in practice — except while `UnlockedBusy`,
///   when [`apply_busy_mask`] flips it to `off`.
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
                if d.next_button_enabled { "on" } else { "off" },
                if d.kebab_enabled { "on" } else { "off" },
            )
        })
        .collect();
    format!(
        "{ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX}{}",
        entries.join("|"),
    )
}

/// Decide which [`AccountListOutput`] a row-activation (Enter on
/// the focused list row, or any other surface routed through
/// [`AccountListMsg::ActivateRow`]) should emit.
///
/// * TOTP rows always emit [`AccountListOutput::CopyCode`] — the
///   code is intrinsically derivable from the wall clock, so
///   "copy the current code" is the unambiguous default action.
/// * HOTP rows with a visible code in hand (within the reveal
///   window — `has_visible_code == true`) also emit
///   [`AccountListOutput::CopyCode`]: Enter copies what the user
///   can already see, matching the per-row copy button.
/// * HOTP rows whose code is hidden emit
///   [`AccountListOutput::ActivateHotpAndCopy`]: Enter advances
///   the counter and copies the freshly revealed code in one
///   step. `AppModel` latches the follow-up copy through
///   [`crate::app::model::AppModel::pending_copy_after_advance`]
///   and re-dispatches a [`AccountListOutput::CopyCode`] after
///   the advance worker reports the reveal.
///
/// Pure logic so unit tests can pin the decision table without a
/// display server. The caller (the [`AccountListMsg::ActivateRow`]
/// handler in the `AccountListComponent` widget binding) reads
/// `kind` from [`AccountRowModel::kind`] and `has_visible_code` from
/// the live cache (`AccountListComponent::live_displays`).
#[must_use]
pub fn default_row_activation(
    kind: AccountKindSummary,
    has_visible_code: bool,
    id: AccountId,
) -> AccountListOutput {
    match (kind, has_visible_code) {
        (AccountKindSummary::Totp, _) | (AccountKindSummary::Hotp, true) => {
            AccountListOutput::CopyCode(id)
        }
        (AccountKindSummary::Hotp, false) => AccountListOutput::ActivateHotpAndCopy(id),
    }
}

/// Whether the "Next" `gtk::ColumnViewColumn` should be visible
/// for the current `(show_next_code_column, rows)` pair.
///
/// AND-gate per `docs/IMPLEMENTATION_PLAN_04_GTK.md` "Next-code
/// column implementation" → Visibility:
///
/// * The per-user `show-next-code-column` `GSettings` preference
///   must be `true`, *and*
/// * at least one rendered row must be a TOTP row (via
///   [`crate::column_view::any_totp`]).
///
/// Either latch off ⇒ column hidden.  Both on ⇒ column visible.
///
/// HOTP-only vaults always hide the column even when the user
/// preference is `true` — the column would otherwise sit
/// permanently empty because [`crate::account_row::next_code_display`]
/// answers `None` for every HOTP row.
///
/// Pure logic so reducer tests can pin the decision without
/// spinning up GTK / libadwaita.
#[must_use]
pub fn compute_next_code_column_visibility(
    show_next_code_column: bool,
    rows: &[AccountRowModel],
) -> bool {
    show_next_code_column && any_totp(rows)
}

/// Pure-logic decision table for the `Ctrl+Shift+C` "copy selected
/// row's next code" accelerator registered by the
/// `"app.copy-next-code"` `gio::SimpleAction`.
///
/// Returns `Some(AccountListOutput::CopyNextCode(id))` only when
/// every gate is satisfied:
///
/// * a row is currently selected (`selection` is `Some`), and
/// * the selected row is a TOTP account
///   ([`AccountKindSummary::Totp`]), and
/// * the per-user "Next" column is currently visible
///   (`next_code_column_visible == true`; the
///   [`compute_next_code_column_visibility`] AND-gate over the
///   `show-next-code-column` `GSettings` key and the
///   "any TOTP rows?" projection already collapsed the column
///   away on a HOTP-only vault, so this single bool covers both
///   the per-user preference and the "the column has no slot for
///   this row" structural rule).
///
/// Returns `None` (silent no-op) for HOTP-selected rows, an
/// empty selection, and a hidden Next column — matching the
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md` "Next-code column
/// implementation" → "HOTP rejection is silent at the
/// accelerator" / "no-selection rejection is silent" gates. The
/// per-cell click path is unaffected by these gates because the
/// cell button is `sensitive = false` for HOTP rows and the
/// column itself disappears when the gate above closes; the
/// accelerator is the only entry surface that needs the gate at
/// the action-activate site.
///
/// Pure logic so unit tests can pin the dispatch table without
/// spinning up a display server.
#[must_use]
pub fn dispatch_copy_next_code_accelerator(
    selection: Option<(AccountId, AccountKindSummary)>,
    next_code_column_visible: bool,
) -> Option<AccountListOutput> {
    if !next_code_column_visible {
        return None;
    }
    let (id, kind) = selection?;
    match kind {
        AccountKindSummary::Totp => Some(AccountListOutput::CopyNextCode(id)),
        AccountKindSummary::Hotp => None,
    }
}

/// Navigation intent decoded from a keyboard event inside the
/// account-list controller stack.
///
/// Returned by [`dispatch_list_box_nav`] to abstract over the
/// equivalent ways the user can request "move one row up" or
/// "move one row down": the literal arrow keys, the vim-style
/// Ctrl+K / Ctrl+J mirrors, and the readline-style Ctrl+P /
/// Ctrl+N mirrors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListNavIntent {
    /// Move one row earlier in the list (or, at the first row,
    /// hand focus back to the search entry with its query
    /// selected for replace-on-type).
    Up,
    /// Move one row later in the list (no wrap at the last row).
    Down,
}

/// Pure-logic key dispatcher for the `gtk::SearchEntry` capture-phase
/// controller installed by
/// [`wire_account_list_navigation_controllers`].
///
/// Returns `true` when `keyval` / `mods` describes a request to
/// hand keyboard focus from the search entry to the first row of
/// the account list — namely the bare Down arrow, Ctrl+J (vim-
/// style "move down" mirror), or Ctrl+N (readline-style "next"
/// mirror). Any press carrying ALT / SUPER / HYPER / META is
/// rejected (those compound chords are reserved for other
/// shortcuts), and bare `j` / `n` return `false` so the user can
/// still type those literals into the query. The Down arrow with
/// `CONTROL_MASK` also returns `false` so `Ctrl+Down` (a different
/// conventional shortcut on some platforms) is not stolen.
///
/// Ctrl+N additionally rejects `SHIFT_MASK` so the
/// `<Control><Shift>n` "Add account" app accelerator (see
/// [`crate::app::model::format_app_add_button_accelerator`])
/// propagates untouched. Ctrl+J keeps its existing
/// shift-tolerant behavior because no other accelerator currently
/// reserves `<Control><Shift>j`.
///
/// Pure logic so unit tests can pin the dispatch table without
/// spinning up a display server.
#[must_use]
pub fn dispatch_search_entry_to_list_nav(
    keyval: gtk::gdk::Key,
    mods: gtk::gdk::ModifierType,
) -> bool {
    let disallowed = gtk::gdk::ModifierType::ALT_MASK
        | gtk::gdk::ModifierType::SUPER_MASK
        | gtk::gdk::ModifierType::HYPER_MASK
        | gtk::gdk::ModifierType::META_MASK;
    if mods.intersects(disallowed) {
        return false;
    }
    let ctrl = mods.contains(gtk::gdk::ModifierType::CONTROL_MASK);
    let shift = mods.contains(gtk::gdk::ModifierType::SHIFT_MASK);
    match keyval {
        gtk::gdk::Key::Down if !ctrl => true,
        gtk::gdk::Key::j | gtk::gdk::Key::J if ctrl => true,
        gtk::gdk::Key::n | gtk::gdk::Key::N if ctrl && !shift => true,
        _ => false,
    }
}

/// Pure-logic key dispatcher for the `gtk::ColumnView` capture-phase
/// controller installed by
/// [`wire_account_list_navigation_controllers`].
///
/// Returns [`Some(ListNavIntent::Up)`][ListNavIntent::Up] for the
/// bare Up arrow, Ctrl+K (vim-style "move up" mirror), or
/// Ctrl+P (readline-style "previous" mirror), and
/// [`Some(ListNavIntent::Down)`][ListNavIntent::Down] for the bare
/// Down arrow, Ctrl+J, or Ctrl+N. Any press carrying ALT / SUPER /
/// HYPER / META is rejected, as are arrow-key presses combined with
/// CONTROL (`Ctrl+Up` / `Ctrl+Down` are different shortcuts on some
/// platforms and must not be stolen). Bare `j` / `k` / `n` / `p`
/// return `None` so they keep the typing-to-search path open at the
/// window-level `set_key_capture_widget`. Returns `None` for
/// everything else, letting `gtk::ColumnView`'s built-in `Home` /
/// `End` / `Page_Up` / `Page_Down` bindings keep working.
///
/// Ctrl+N additionally rejects `SHIFT_MASK` so the
/// `<Control><Shift>n` "Add account" app accelerator (see
/// [`crate::app::model::format_app_add_button_accelerator`])
/// propagates untouched. Ctrl+J / Ctrl+K / Ctrl+P keep their
/// shift-tolerant behavior because no other accelerator currently
/// reserves `<Control><Shift>j` / `<Control><Shift>k` /
/// `<Control><Shift>p`.
///
/// Pure logic so unit tests can pin the dispatch table without
/// spinning up a display server.
#[must_use]
pub fn dispatch_list_box_nav(
    keyval: gtk::gdk::Key,
    mods: gtk::gdk::ModifierType,
) -> Option<ListNavIntent> {
    let disallowed = gtk::gdk::ModifierType::ALT_MASK
        | gtk::gdk::ModifierType::SUPER_MASK
        | gtk::gdk::ModifierType::HYPER_MASK
        | gtk::gdk::ModifierType::META_MASK;
    if mods.intersects(disallowed) {
        return None;
    }
    let ctrl = mods.contains(gtk::gdk::ModifierType::CONTROL_MASK);
    let shift = mods.contains(gtk::gdk::ModifierType::SHIFT_MASK);
    match keyval {
        gtk::gdk::Key::Up if !ctrl => Some(ListNavIntent::Up),
        gtk::gdk::Key::Down if !ctrl => Some(ListNavIntent::Down),
        gtk::gdk::Key::k | gtk::gdk::Key::K | gtk::gdk::Key::p | gtk::gdk::Key::P if ctrl => {
            Some(ListNavIntent::Up)
        }
        gtk::gdk::Key::j | gtk::gdk::Key::J if ctrl => Some(ListNavIntent::Down),
        gtk::gdk::Key::n | gtk::gdk::Key::N if ctrl && !shift => Some(ListNavIntent::Down),
        _ => None,
    }
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
    /// Toplevel widget (the `adw::ApplicationWindow`) the embedded
    /// `gtk::SearchBar` registers as its
    /// [`set_key_capture_widget`][gtk::SearchBar::set_key_capture_widget]
    /// target so any printable keypress on the window that is not
    /// consumed by a focused entry reveals the bar and forwards the
    /// keystroke into the embedded `gtk::SearchEntry` ("type to
    /// search"). `None` skips the wiring — e.g. unit tests that
    /// construct an isolated component without a parent window.
    pub key_capture_widget: Option<gtk::Widget>,
    /// Initial value of the per-user `show-section-headers`
    /// `GSettings` key. When `false`, the interleaver in
    /// [`crate::column_view::apply_interleaved_splice_plan`]
    /// emits no section rows; when `true`, headers fire per
    /// [`row_section_header`]. Live updates from the
    /// `SettingsComponent` toggle flow through
    /// [`AccountListMsg::SetShowSectionHeaders`].
    pub show_section_headers: bool,
    /// Initial value of the per-user `show-column-headers`
    /// `GSettings` key.  When `false`, the
    /// [`COLUMN_VIEW_NO_HEADERS_CSS_CLASS`] CSS class is added to
    /// the `gtk::ColumnView` so the application stylesheet
    /// suppresses the header strip; when `true`, the column
    /// header row renders normally.  Live updates from the
    /// `SettingsComponent` toggle flow through
    /// [`AccountListMsg::SetShowColumnHeaders`].
    pub show_column_headers: bool,
    /// Initial value of the per-user `show-next-code-column`
    /// `GSettings` key.  Default `true` per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` "Next-code column
    /// implementation".  The column's *rendered* visibility ANDs
    /// this with [`crate::column_view::any_totp`] over
    /// [`Self::rows`], so a HOTP-only vault hides the column even
    /// when the user preference is `true`.  Live updates flow
    /// through [`AccountListMsg::SetShowNextCodeColumn`].
    pub show_next_code_column: bool,
}

/// Widget-bearing list view for the unlocked vault state.
///
/// Owns a `gio::ListStore<crate::row_item::RowItem>` that backs a
/// [`gtk::SingleSelection`] + [`gtk::ColumnView`] (mounted inside a
/// `gtk::ScrolledWindow`) per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// Appendix A §A.2 / §A.8. Per-tick TOTP / HOTP-reveal refreshes
/// route through [`crate::row_item::RowItem::set_display`] on the
/// matching store item so cell-factory subscriptions survive the
/// refresh; full refreshes (Add / Remove / Rename / search) run
/// through [`crate::column_view::apply_interleaved_splice_plan`]
/// which preserves account-row identity across the diff.
///
/// The component additionally owns the `gtk::SearchBar` hosting a
/// `gtk::SearchEntry`. Selection lives on the `gtk::SingleSelection`
/// installed on the `gtk::ColumnView`. `current_query` mirrors the
/// entry's text so the parent can re-feed it via
/// [`AccountListInit::initial_query`] on a rebuild;
/// `current_selection` mirrors the visible row id for the same
/// reason.
#[allow(clippy::struct_excessive_bools)]
pub struct AccountListComponent {
    /// Backing store of `RowItem`s the [`gtk::ColumnView`] reads.
    /// `Refresh` mutates this through
    /// [`crate::column_view::apply_interleaved_splice_plan`] so
    /// account-row identity survives section-header toggles. Per-tick
    /// updates iterate the store and call
    /// [`crate::row_item::RowItem::set_display`] on the matching item
    /// — **never** `splice`.
    store: gio::ListStore,
    /// Selection model wrapping [`Self::store`]. The cursor is
    /// installed via [`gtk::SingleSelection::set_selected`] on every
    /// refresh from the pure-logic [`selected_row_after_refresh`].
    selection: gtk::SingleSelection,
    /// "Time" column kept on `self` so its `set_visible` toggle can
    /// flip from the [`AccountListMsg::Refresh`] handler when the
    /// row set transitions between TOTP-bearing and HOTP-only.
    time_column: gtk::ColumnViewColumn,
    /// The [`gtk::ColumnView`] kept on `self` so
    /// [`AccountListMsg::SetShowColumnHeaders`] can add / remove the
    /// [`COLUMN_VIEW_NO_HEADERS_CSS_CLASS`] CSS class on it.
    column_view: gtk::ColumnView,
    /// `gtk::SearchBar` whose `search-mode-enabled` property is
    /// toggled by [`AccountListMsg::SetSearchModeEnabled`]. The
    /// header-bar search-toggle button (wired in `app/model.rs`)
    /// dispatches that message so the bar reveals / hides in
    /// lockstep with the toggle's `active` state.
    search_bar: gtk::SearchBar,
    /// `gtk::SearchEntry` nested inside [`Self::search_bar`]. Its
    /// `search-changed` signal fires [`AccountListMsg::SetQuery`].
    search_entry: gtk::SearchEntry,
    /// Last query the user typed into [`Self::search_entry`].
    /// Cached so [`AccountListMsg::Refresh`] can recompute the
    /// selection without rereading the entry buffer.
    current_query: String,
    /// Last selected row id surfaced to the parent. Updated by
    /// [`AccountListMsg::Refresh`] so a subsequent rebuild can pass
    /// it back through [`AccountListInit::initial_selection`].
    current_selection: Option<AccountId>,
    /// Most recent row set installed by
    /// [`AccountListMsg::Refresh`]. Kept on `self` so the cache
    /// pruning on the next refresh can run without re-asking
    /// `AppModel` for a fresh projection, and so
    /// [`AccountListMsg::ActivateRow`] can resolve a store position
    /// back to the activating row's `(id, kind)`.
    current_rows: Vec<AccountRowModel>,
    /// Per-row live [`RowDisplay`] cache. Updated on every
    /// [`AccountListMsg::Tick`] entry so the next
    /// [`AccountListMsg::Refresh`] can seed each newly pushed row's
    /// `initial_display` from the most recently observed visible
    /// code. The cache stores the *intrinsic* projection (no busy
    /// mask applied); the row applies the mask on top.
    live_displays: HashMap<AccountId, RowDisplay>,
    /// Most recent `AppState::is_busy()` value latched via
    /// [`AccountListMsg::SetBusy`]. The component fans the value out
    /// to every account row through
    /// [`crate::row_item::RowItem::set_busy`] so each cell factory
    /// re-applies the busy mask locally per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect
    /// ownership". Kept on `self` so subsequent
    /// [`AccountListMsg::Refresh`] inserts seed new rows' busy state
    /// from the cached value rather than asking `AppModel`.
    busy: bool,
    /// Per-user `show-section-headers` `GSettings` value latched at
    /// mount time and updated by
    /// [`AccountListMsg::SetShowSectionHeaders`]. Drives the
    /// `show_section_headers` argument to
    /// [`crate::column_view::apply_interleaved_splice_plan`] on
    /// every refresh.
    show_section_headers: bool,
    /// Per-user `show-column-headers` `GSettings` value latched at
    /// mount time and updated by
    /// [`AccountListMsg::SetShowColumnHeaders`].  Drives whether
    /// the [`COLUMN_VIEW_NO_HEADERS_CSS_CLASS`] CSS class is
    /// present on the [`Self::column_view`].
    show_column_headers: bool,
    /// Per-user `show-next-code-column` `GSettings` value latched
    /// at mount time and updated by
    /// [`AccountListMsg::SetShowNextCodeColumn`].  `AND`ed with
    /// [`crate::column_view::any_totp`] over [`Self::current_rows`]
    /// to drive [`Self::next_code_column`]'s `set_visible`.
    show_next_code_column: bool,
    /// "Next" column kept on `self` so its `set_visible` can be
    /// flipped both by [`AccountListMsg::SetShowNextCodeColumn`]
    /// (preference toggle) and by [`Self::handle_refresh`] (row
    /// set transitions between TOTP-bearing and HOTP-only).
    next_code_column: gtk::ColumnViewColumn,
    /// Single shared slot for the row-body context-menu
    /// `gtk::PopoverMenu` (Milestone 9 slice 5). Cloned into the
    /// "Account" column factory so the right-click / keyboard
    /// popover and the component share one
    /// `Option<gtk::PopoverMenu>`; popping a fresh one unparents +
    /// drops any prior. [`AccountListMsg::Refresh`] drops it (the
    /// row's `RowItem` may have been spliced), and dropping the whole
    /// controller on lock drops it with the component so a popover
    /// never outlives its row or the `(Vault, Store)` pair — see
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Row context menu …" >
    /// "Design contract" item 3.
    row_popover: crate::column_view::RowPopoverSlot,
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
///   `gio::ListStore<crate::row_item::RowItem>` to match the new row
///   set via [`crate::column_view::apply_interleaved_splice_plan`]
///   and reapplies the selection.
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
    /// Reveal the `gtk::SearchBar` and move keyboard focus onto the
    /// embedded `gtk::SearchEntry`. Posted by `AppModel` in response
    /// to the window-level `/` or `Ctrl+L` accelerator (and also by
    /// the up-arrow / Ctrl+K / Ctrl+P edge handler in
    /// [`wire_account_list_navigation_controllers`]) so the user
    /// can start refining the search query without first reaching
    /// for the mouse or the header-bar toggle. Existing query text
    /// is preserved (the user may have already typed something) but
    /// the entry's full contents are selected on focus so typing
    /// immediately replaces the prior query — an arrow key or
    /// pointer click clears the selection and moves the caret per
    /// default `gtk::Editable` behavior.
    FocusSearch,
    /// User activated the row at the given store position — Enter
    /// on the focused row, or a single click on the row body
    /// (cells without an inline `gtk::Button`; the Next, Copy, and
    /// kebab buttons capture their own clicks and never bubble to
    /// activate). Posted by the
    /// `column_view.connect_activate` closure installed in
    /// [`AccountListComponent::init`]. The handler resolves the
    /// store position to a `RowItem`, ignores section rows
    /// (defensive — they are non-selectable), then routes through
    /// [`default_row_activation`] against the live cache to emit
    /// the matching [`AccountListOutput`] (`CopyCode` for TOTP
    /// rows and revealed HOTP rows; `ActivateHotpAndCopy` for
    /// un-revealed HOTP rows). Out-of-range positions are a benign
    /// no-op (defensive against a stray dispatch racing a refresh).
    ActivateRow(u32),
    /// Per-tick TOTP refresh from the [`crate::ticker`] driver.
    ///
    /// `AppModel`'s per-tick `glib::timeout_add_local` callback
    /// projects the live `(Vault, Store)` pair through
    /// [`crate::ticker::tick`] and forwards the resulting
    /// `Vec<(AccountId, RowDisplay)>` here. The handler updates
    /// [`AccountListComponent::live_displays`] and calls
    /// [`crate::row_item::RowItem::set_display`] on each matching
    /// store item; rows whose code did not change in this tick are
    /// not contacted, so the widget tree stays untouched and the
    /// store row count is **never** mutated by a tick. Empty
    /// payload is a benign no-op (e.g. an HOTP-only vault — no TOTP
    /// refresh is needed).
    Tick(Vec<(AccountId, RowDisplay)>),
    /// Latch the parent `AppModel`'s `AppState::is_busy()` state and
    /// broadcast it to every account-row `RowItem` so the per-cell
    /// busy mask dims copy / "next" / kebab while a vault-touching
    /// worker is in flight per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership".
    ///
    /// `AppModel` sends `SetBusy(true)` on entry into
    /// `UnlockedBusy` and `SetBusy(false)` on the worker return /
    /// `Locked` / `StartupError` transitions. Idempotent — sending
    /// the same value twice is a benign no-op (no `RowItem::set_busy`
    /// fires the display-changed signal).
    SetBusy(bool),
    /// Live update for the per-user `show-section-headers`
    /// `GSettings` key. `AppModel` connects
    /// `changed::show-section-headers` on its `gio::Settings`
    /// clone and dispatches this message so a toggle from the
    /// `SettingsComponent` dialog re-runs the interleave splice
    /// against the current row set.
    ///
    /// Idempotent — sending the same value twice is a benign
    /// no-op.
    SetShowSectionHeaders(bool),
    /// Live update for the per-user `show-column-headers`
    /// `GSettings` key.  `AppModel` connects
    /// `changed::show-column-headers` on its `gio::Settings` clone
    /// and dispatches this message so a toggle from the
    /// `SettingsComponent` dialog adds or removes the
    /// [`COLUMN_VIEW_NO_HEADERS_CSS_CLASS`] CSS class on the
    /// `gtk::ColumnView`.  The CSS rule that hides the header
    /// strip when the class is present lives in
    /// `crates/paladin-gtk/data/style.css`.
    ///
    /// Idempotent — sending the same value twice is a benign
    /// no-op.
    SetShowColumnHeaders(bool),
    /// Live update for the per-user `show-next-code-column`
    /// `GSettings` key.  `AppModel` connects
    /// `changed::show-next-code-column` on its `gio::Settings`
    /// clone and dispatches this message so a toggle from the
    /// `SettingsComponent` dialog calls `set_visible` on the
    /// `gtk::ColumnViewColumn` held on
    /// [`AccountListComponent::next_code_column`].  The actual
    /// visibility is the AND of this value and
    /// [`crate::column_view::any_totp`] over the current rows —
    /// a HOTP-only vault hides the column even when this key is
    /// `true` so the column never sits empty.
    ///
    /// Idempotent — sending the same value twice is a benign
    /// no-op.
    SetShowNextCodeColumn(bool),
}

/// CSS class added to the [`gtk::ColumnView`] when the per-user
/// `show-column-headers` preference is `false`.
///
/// The application stylesheet (`crates/paladin-gtk/data/style.css`)
/// carries a rule that hides the header strip while this class is
/// present.  Pinned as a `pub const` so the toggle helper, the
/// style sheet, and the integration tests stay aligned on the
/// literal.
pub const COLUMN_VIEW_NO_HEADERS_CSS_CLASS: &str = "no-column-headers";

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
                set_child: Some(&column_view),
            },
        }
    }

    #[allow(clippy::too_many_lines)]
    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        // Construct the backing store + selection model + view. The
        // store is `gio::ListStore<RowItem>`; the selection model
        // wraps it; the column view reads from the selection model.
        let store = gio::ListStore::new::<RowItem>();
        let selection = gtk::SingleSelection::builder()
            .model(&store)
            .autoselect(false)
            .can_unselect(true)
            .build();
        let column_view = gtk::ColumnView::builder()
            .model(&selection)
            .show_row_separators(false)
            .show_column_separators(false)
            .single_click_activate(true)
            .build();

        // Construct the five columns. The cell factories live in
        // `crate::column_view` and emit `AccountListOutput` directly
        // through the sender threaded into them, so no per-row
        // forwarder is needed.
        let output_sender = sender.output_sender().clone();

        // Single shared slot for the row-body context-menu popover.
        // Cloned into the "Account" column factory so the right-click
        // / keyboard popover and the component's refresh / lock
        // teardown all address one `Option<gtk::PopoverMenu>`.
        let row_popover: RowPopoverSlot = Rc::new(RefCell::new(None));

        let account_column = gtk::ColumnViewColumn::builder()
            .title("Account")
            .factory(&build_account_column_factory(
                output_sender.clone(),
                Rc::clone(&row_popover),
            ))
            .expand(true)
            .resizable(true)
            .build();
        // Attach the case-insensitive (issuer, label) sorter so
        // clicking the "Account" column header toggles between
        // ascending and descending order.  The view defaults to
        // unsorted on mount, preserving the vault insertion-order
        // contract from `docs/DESIGN.md` §"listing-order"; sorting
        // is a user-initiated override and does not persist across
        // restarts.
        account_column.set_sorter(Some(&build_account_column_sorter()));
        let code_column = gtk::ColumnViewColumn::builder()
            .title("Code")
            .factory(&build_code_column_factory(output_sender.clone()))
            .build();
        let next_code_column = gtk::ColumnViewColumn::builder()
            .title("Next")
            .factory(&build_next_code_column_factory(output_sender.clone()))
            .build();
        let time_column = gtk::ColumnViewColumn::builder()
            .title("Time")
            .factory(&build_time_column_factory())
            .build();
        let copy_column = gtk::ColumnViewColumn::builder()
            .title("Copy")
            .factory(&build_copy_column_factory(output_sender.clone()))
            .build();
        let kebab_column = gtk::ColumnViewColumn::builder()
            .title("More")
            .factory(&build_kebab_column_factory(output_sender))
            .build();

        column_view.append_column(&account_column);
        column_view.append_column(&code_column);
        // "Next" sits to the right of "Time" per DESIGN §7 — the
        // countdown is the user's primary urgency cue for the
        // current code, so Next renders after it as a quieter
        // "what's coming" affordance.
        column_view.append_column(&time_column);
        column_view.append_column(&next_code_column);
        column_view.append_column(&copy_column);
        column_view.append_column(&kebab_column);

        // Seed the store with the initial row set, interleaving
        // section headers per the user preference. Time / Next
        // columns are visible only if any account row is TOTP and
        // (for Next) the per-user `show-next-code-column`
        // preference is also `true`.
        apply_interleaved_splice_plan(&store, &init.rows, init.show_section_headers);
        time_column.set_visible(any_totp(&init.rows));
        next_code_column.set_visible(compute_next_code_column_visibility(
            init.show_next_code_column,
            &init.rows,
        ));

        // Apply the per-user `show-column-headers` preference.
        // When `false`, the application stylesheet hides the
        // ColumnView header strip via the
        // `COLUMN_VIEW_NO_HEADERS_CSS_CLASS` selector.
        apply_show_column_headers_css(&column_view, init.show_column_headers);

        // Install the initial selection.
        let initial_selection = init.initial_selection;
        let initial_selected_pos =
            position_for_account(&store, initial_selection).unwrap_or(gtk::INVALID_LIST_POSITION);
        selection.set_selected(initial_selected_pos);

        // Search entry + bar.
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

        // Wire the cross-widget arrow-key navigation pair so Down /
        // Ctrl+J / Ctrl+N hands focus from the search entry into the
        // first row, Up / Ctrl+K / Ctrl+P at the first row hands
        // focus back to the entry (with its query selected for
        // replace-on-type), and Ctrl+J / Ctrl+K / Ctrl+N / Ctrl+P
        // mirror the bare arrow keys inside the list.
        wire_account_list_navigation_controllers(&search_entry, &column_view, &selection, &store);

        // `gtk::ColumnView::connect_activate` fires when the user
        // hits Enter on the focused row or single-clicks the row
        // body (the view is built with `single_click_activate(true)`
        // above). Inline `gtk::Button` widgets in the Next, Copy,
        // and kebab cells capture their own clicks via GTK's gesture
        // claim, so activating those buttons does not also bubble to
        // `connect_activate`. The closure forwards the row's position
        // back through `AccountListMsg::ActivateRow`, which resolves
        // the row's kind + visible-code state and emits the matching
        // `AccountListOutput::CopyCode` /
        // `AccountListOutput::ActivateHotpAndCopy` per
        // `default_row_activation`.
        let activate_input = sender.input_sender().clone();
        column_view.connect_activate(move |_, position| {
            let _ = activate_input.send(AccountListMsg::ActivateRow(position));
        });

        let search_bar = gtk::SearchBar::builder()
            .search_mode_enabled(false)
            .show_close_button(true)
            .build();
        search_bar.set_child(Some(&search_entry));
        search_bar.connect_entry(&search_entry);

        // Wire GTK's built-in "type to search" capture so any
        // printable keypress on the toplevel window that is not
        // consumed by a focused entry reveals the bar and forwards
        // the keystroke into `search_entry`. Skipped when the parent
        // did not supply a toplevel (e.g. an isolated unit test that
        // never mounts the component into a window).
        if let Some(capture_widget) = init.key_capture_widget.as_ref() {
            search_bar.set_key_capture_widget(Some(capture_widget));
        }

        // Mirror the bar's `search-mode-enabled` back to `AppModel`
        // so the header-bar search-toggle `gtk::ToggleButton` tracks
        // bar-initiated reveals (type-to-search,
        // `AccountListMsg::FocusSearch`, or the bar's own close
        // button) in addition to its own click. The toggle's
        // `set_active` is idempotent on a matching value, so the
        // round-trip toggle → set_search_mode → notify → set_active
        // settles in one cycle.
        let notify_output = sender.output_sender().clone();
        search_bar.connect_search_mode_enabled_notify(move |bar| {
            let _ = notify_output.send(AccountListOutput::SearchModeChanged(bar.is_search_mode()));
        });

        let widgets = view_output!();

        let component = AccountListComponent {
            store,
            selection,
            time_column,
            column_view,
            search_bar,
            search_entry,
            current_query: init.initial_query,
            current_selection: initial_selection,
            current_rows: init.rows,
            live_displays: HashMap::new(),
            busy: false,
            show_section_headers: init.show_section_headers,
            show_column_headers: init.show_column_headers,
            show_next_code_column: init.show_next_code_column,
            next_code_column,
            row_popover,
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
                self.handle_refresh(rows, selection);
            }
            AccountListMsg::SetSearchModeEnabled(enabled) => {
                self.search_bar.set_search_mode(enabled);
            }
            AccountListMsg::FocusSearch => {
                self.search_bar.set_search_mode(true);
                self.search_entry.grab_focus();
                // Select the entry's full contents so typing
                // immediately replaces any prior query; an arrow
                // key or pointer click clears the selection and
                // moves the caret per default `gtk::Editable`
                // behavior. `-1` is the "to end" sentinel.
                self.search_entry.select_region(0, -1);
            }
            AccountListMsg::ActivateRow(position) => {
                let Some(obj) = self.store.item(position) else {
                    return;
                };
                let Ok(item) = obj.downcast::<RowItem>() else {
                    return;
                };
                if item.is_section() {
                    return;
                }
                let Some(id) = item.account_id() else {
                    return;
                };
                let Some(model) = self.current_rows.iter().find(|r| r.id == id) else {
                    return;
                };
                let has_visible_code = self
                    .live_displays
                    .get(&id)
                    .is_some_and(|d| matches!(d.code, CodeDisplay::Visible(_)));
                let output = default_row_activation(model.kind, has_visible_code, id);
                let _ = sender.output(output);
            }
            AccountListMsg::Tick(displays) => {
                self.handle_tick(displays);
            }
            AccountListMsg::SetBusy(busy) => {
                if self.busy == busy {
                    return;
                }
                self.busy = busy;
                for i in 0..self.store.n_items() {
                    let Some(obj) = self.store.item(i) else {
                        continue;
                    };
                    let Ok(item) = obj.downcast::<RowItem>() else {
                        continue;
                    };
                    if item.is_section() {
                        continue;
                    }
                    item.set_busy(busy);
                }
            }
            AccountListMsg::SetShowColumnHeaders(enabled) => {
                if self.show_column_headers == enabled {
                    return;
                }
                self.show_column_headers = enabled;
                apply_show_column_headers_css(&self.column_view, enabled);
            }
            AccountListMsg::SetShowNextCodeColumn(enabled) => {
                if self.show_next_code_column == enabled {
                    return;
                }
                self.show_next_code_column = enabled;
                self.next_code_column
                    .set_visible(compute_next_code_column_visibility(
                        enabled,
                        &self.current_rows,
                    ));
            }
            AccountListMsg::SetShowSectionHeaders(enabled) => {
                if self.show_section_headers == enabled {
                    return;
                }
                self.show_section_headers = enabled;
                // Re-run the interleave so section rows appear /
                // disappear. Account-row identity is preserved
                // across the diff via `RowKey::Account`.
                apply_interleaved_splice_plan(
                    &self.store,
                    &self.current_rows,
                    self.show_section_headers,
                );
                // Reapply selection in case section-row insertions
                // shifted account positions.
                let target = position_for_account(&self.store, self.current_selection)
                    .unwrap_or(gtk::INVALID_LIST_POSITION);
                self.selection.set_selected(target);
            }
        }
    }
}

impl AccountListComponent {
    /// Resolve the currently selected row into the
    /// [`AccountListOutput`] the `Ctrl+Shift+C` accelerator's
    /// `gio::SimpleAction` (`"app.copy-next-code"`) should emit,
    /// or `None` if any gate fails.
    ///
    /// Reads the live `current_selection` / `current_rows` /
    /// `next_code_column.is_visible()` triple and feeds them
    /// through the pure-logic decision table in
    /// [`dispatch_copy_next_code_accelerator`]. The accessor lives
    /// here so the runtime widget gates (selection cursor, visible
    /// column) stay encapsulated inside `AccountListComponent`
    /// while the per-row kind / TOTP-vs-HOTP rule lives in the
    /// pure helper a unit test can pin without GTK init.
    ///
    /// Returns `Some(AccountListOutput::CopyNextCode(id))` only
    /// for a TOTP-selected row with a visible Next column; HOTP
    /// rows, no selection, and a hidden Next column collapse to
    /// `None` per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    /// "Next-code column implementation" > "HOTP rejection is
    /// silent at the accelerator".
    #[must_use]
    pub fn current_selection_copy_next_code_output(&self) -> Option<AccountListOutput> {
        let id = self.current_selection?;
        let kind = self
            .current_rows
            .iter()
            .find(|row| row.id == id)
            .map(|row| row.kind)?;
        dispatch_copy_next_code_accelerator(Some((id, kind)), self.next_code_column.is_visible())
    }

    /// Handle [`AccountListMsg::Refresh`] by splicing the store to
    /// match the new row set, re-seeding each surviving / inserted
    /// `RowItem`'s display from the live cache, and reapplying the
    /// selection through the [`gtk::SingleSelection`].
    ///
    /// Pulled out of the `update` arm so the cyclomatic complexity
    /// of the dispatcher stays under the clippy limit.
    fn handle_refresh(&mut self, rows: Vec<AccountRowModel>, selection: Option<AccountId>) {
        // Parent's `selection` is treated as the preferred prior id:
        // `Some(id)` is the explicit ask (e.g. post-Add the new
        // account should win), `None` falls back to
        // [`Self::current_selection`] so the user's cursor survives a
        // search-query refresh that does not remove the selected row.
        // The actual surviving id is resolved by
        // [`selected_row_after_refresh`] so the §6 / §7 preservation
        // rule lives in pure logic.
        let prev = selection.or(self.current_selection);
        let effective_selection = selected_row_after_refresh(prev, &rows);
        prune_cache_to_rows(&mut self.live_displays, &rows);

        // Drop any open row-body context-menu popover before the
        // splice: its row `RowItem` may be replaced, so the popover
        // must not outlive it (single-popover invariant,
        // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Row context menu …" >
        // "Design contract" item 3).
        drop_row_popover(&self.row_popover, PopoverInvalidation::Refresh);

        apply_interleaved_splice_plan(&self.store, &rows, self.show_section_headers);

        // After the splice, re-seed each freshly inserted (or reused)
        // RowItem's display from the cache. The splice helper
        // preserves account-row identity, but the per-row cache lives
        // here so we have to drive the read.
        for i in 0..self.store.n_items() {
            let Some(obj) = self.store.item(i) else {
                continue;
            };
            let Ok(item) = obj.downcast::<RowItem>() else {
                continue;
            };
            let Some(id) = item.account_id() else {
                continue;
            };
            if let Some(model) = rows.iter().find(|r| r.id == id) {
                let display = self
                    .live_displays
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| hidden_row_display(model));
                item.set_display(display);
                item.set_busy(self.busy);
            }
        }

        // Reapply selection through the SingleSelection so a refresh
        // that changes positions keeps the cursor on the right
        // account.
        let target = position_for_account(&self.store, effective_selection)
            .unwrap_or(gtk::INVALID_LIST_POSITION);
        self.selection.set_selected(target);

        // Toggle Time-column visibility for HOTP-only vaults.
        self.time_column.set_visible(any_totp(&rows));
        // Re-evaluate the Next column visibility AND-gate
        // (`show_next_code_column && any_totp(&rows)`) for the
        // refreshed row set; a vault flipping between TOTP-bearing
        // and HOTP-only must collapse the column the same way the
        // Time column already does.
        self.next_code_column
            .set_visible(compute_next_code_column_visibility(
                self.show_next_code_column,
                &rows,
            ));

        self.current_selection = effective_selection;
        self.current_rows = rows;
    }

    /// Handle [`AccountListMsg::Tick`] by updating the per-row live
    /// display cache and fanning each entry out to the matching
    /// store item through [`RowItem::set_display`] — **never** via
    /// `store.splice(...)`.
    fn handle_tick(&mut self, displays: Vec<(AccountId, RowDisplay)>) {
        if displays.is_empty() {
            return;
        }
        for (id, display) in &displays {
            self.live_displays.insert(*id, display.clone());
        }
        // Walk the store and dispatch each tick entry to the matching
        // RowItem.
        let mut by_id: HashMap<AccountId, RowDisplay> = HashMap::with_capacity(displays.len());
        for (id, display) in displays {
            by_id.insert(id, display);
        }
        for i in 0..self.store.n_items() {
            let Some(obj) = self.store.item(i) else {
                continue;
            };
            let Ok(item) = obj.downcast::<RowItem>() else {
                continue;
            };
            let Some(id) = item.account_id() else {
                continue;
            };
            if let Some(display) = by_id.remove(&id) {
                item.set_display(display);
            }
        }
    }
}

/// Walk `store` and return the position of the first
/// account-row `RowItem` whose `account_id` matches `target`, or
/// `None` if no such row is present.
///
/// `target == None` short-circuits to `None` so the caller can
/// substitute [`gtk::INVALID_LIST_POSITION`] and clear the
/// selection. Section rows (`RowItem::is_section() == true`) are
/// skipped — they carry no `AccountId` and cannot be the
/// `gtk::SingleSelection` cursor.
/// Add or remove the [`COLUMN_VIEW_NO_HEADERS_CSS_CLASS`] CSS class
/// on `column_view` based on `show`.
///
/// Mirrors the show / hide contract of the per-user
/// `show-column-headers` `GSettings` key.  The CSS rule that hides
/// the header strip when the class is present lives in
/// `crates/paladin-gtk/data/style.css`.
fn apply_show_column_headers_css(column_view: &gtk::ColumnView, show: bool) {
    if show {
        column_view.remove_css_class(COLUMN_VIEW_NO_HEADERS_CSS_CLASS);
    } else {
        column_view.add_css_class(COLUMN_VIEW_NO_HEADERS_CSS_CLASS);
    }
}

fn position_for_account(store: &gio::ListStore, target: Option<AccountId>) -> Option<u32> {
    let id = target?;
    let n = store.n_items();
    for i in 0..n {
        let Some(obj) = store.item(i) else { continue };
        let Ok(item) = obj.downcast::<RowItem>() else {
            continue;
        };
        if item.is_section() {
            continue;
        }
        if item.account_id() == Some(id) {
            return Some(i);
        }
    }
    None
}

/// Install the capture-phase `gtk::EventControllerKey` pair that
/// implements cross-widget arrow-key navigation between the
/// `gtk::SearchEntry` and the account-list `gtk::ColumnView`.
///
/// Two controllers cover four cases:
///
/// * On `search_entry`: pressing Down (or Ctrl+J / Ctrl+N) hands
///   keyboard focus to the first account row of `column_view`
///   (selecting it in the process). When the filtered list is empty
///   the press is propagated so it remains a benign no-op.
/// * On `column_view`: pressing Up (or Ctrl+K / Ctrl+P) while the
///   focused row is the first selectable row hands focus back to
///   `search_entry` and calls
///   [`gtk::Editable::select_region(0, -1)`][gtk::EditableExt::select_region]
///   so typing immediately replaces the prior query (matching the
///   `/` / Ctrl+L focus-search behavior). Up at any other row
///   moves the selection / focus one row earlier. Down (or
///   Ctrl+J / Ctrl+N) moves one row later, stopping at the last
///   row.
///
/// Both controllers run at
/// [`gtk::PropagationPhase::Capture`] so they fire before
/// `gtk::ColumnView`'s built-in Up / Down bindings, ensuring a
/// uniform navigation contract. Bare `j` / `k` are intentionally
/// left to bubble so the window-level "type to search" capture
/// installed by [`gtk::SearchBar::set_key_capture_widget`] still
/// receives them. `Home` / `End` / `Page_Up` / `Page_Down` — and every key
/// outside the dispatch tables in [`dispatch_search_entry_to_list_nav`]
/// and [`dispatch_list_box_nav`] — propagate untouched so
/// `gtk::ColumnView`'s built-in behaviors keep working.
///
/// Section rows are non-selectable per
/// [`crate::column_view::build_account_column_factory`], so the
/// "move selection by one" walk needs to skip them; this helper
/// uses [`next_selectable_position`] /
/// [`prev_selectable_position`] to step over section rows in either
/// direction.
fn wire_account_list_navigation_controllers(
    search_entry: &gtk::SearchEntry,
    column_view: &gtk::ColumnView,
    selection: &gtk::SingleSelection,
    store: &gio::ListStore,
) {
    let selection_for_entry = selection.clone();
    let store_for_entry = store.clone();
    let column_view_for_entry = column_view.clone();
    let entry_ctrl = gtk::EventControllerKey::new();
    entry_ctrl.set_propagation_phase(gtk::PropagationPhase::Capture);
    entry_ctrl.connect_key_pressed(move |_, keyval, _, mods| {
        if dispatch_search_entry_to_list_nav(keyval, mods) {
            if let Some(pos) = next_selectable_position(&store_for_entry, None) {
                selection_for_entry.set_selected(pos);
                column_view_for_entry.grab_focus();
                return glib::Propagation::Stop;
            }
        }
        glib::Propagation::Proceed
    });
    search_entry.add_controller(entry_ctrl);

    let search_entry_for_list = search_entry.clone();
    let selection_for_list = selection.clone();
    let store_for_list = store.clone();
    let column_view_for_list = column_view.clone();
    let list_ctrl = gtk::EventControllerKey::new();
    list_ctrl.set_propagation_phase(gtk::PropagationPhase::Capture);
    list_ctrl.connect_key_pressed(move |_, keyval, _, mods| {
        let Some(intent) = dispatch_list_box_nav(keyval, mods) else {
            return glib::Propagation::Proceed;
        };
        let current = match selection_for_list.selected() {
            gtk::INVALID_LIST_POSITION => None,
            pos => Some(pos),
        };
        match intent {
            ListNavIntent::Up => {
                let first = next_selectable_position(&store_for_list, None);
                if current.is_none() || current == first {
                    // At the first selectable row — hand focus back
                    // to the search entry.
                    search_entry_for_list.grab_focus();
                    search_entry_for_list.select_region(0, -1);
                    return glib::Propagation::Stop;
                }
                if let Some(prev) = prev_selectable_position(&store_for_list, current) {
                    selection_for_list.set_selected(prev);
                    column_view_for_list.grab_focus();
                }
                glib::Propagation::Stop
            }
            ListNavIntent::Down => {
                if let Some(next) = next_selectable_position(&store_for_list, current) {
                    selection_for_list.set_selected(next);
                    column_view_for_list.grab_focus();
                }
                glib::Propagation::Stop
            }
        }
    });
    column_view.add_controller(list_ctrl);
}

/// Find the next selectable (non-section) position in `store` after
/// `from`. If `from == None`, returns the first selectable position
/// in the store.
fn next_selectable_position(store: &gio::ListStore, from: Option<u32>) -> Option<u32> {
    let n = store.n_items();
    let start = match from {
        Some(p) => p.saturating_add(1),
        None => 0,
    };
    for i in start..n {
        let Some(obj) = store.item(i) else { continue };
        let Ok(item) = obj.downcast::<RowItem>() else {
            continue;
        };
        if !item.is_section() {
            return Some(i);
        }
    }
    None
}

/// Find the previous selectable (non-section) position in `store`
/// before `from`. Returns `None` if `from == None` or no earlier
/// selectable row exists.
fn prev_selectable_position(store: &gio::ListStore, from: Option<u32>) -> Option<u32> {
    let from = from?;
    if from == 0 {
        return None;
    }
    let mut i = from;
    while i > 0 {
        i -= 1;
        let Some(obj) = store.item(i) else { continue };
        let Ok(item) = obj.downcast::<RowItem>() else {
            continue;
        };
        if !item.is_section() {
            return Some(i);
        }
    }
    None
}
