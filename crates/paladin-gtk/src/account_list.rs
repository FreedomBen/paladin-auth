// SPDX-License-Identifier: AGPL-3.0-or-later

//! `AccountListComponent` for `paladin-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountListComponent`, the unlocked view is a `gtk::ListBox`
//! driven by a `relm4::factory::FactoryVecDeque<AccountRowComponent>`,
//! built from `paladin_core::AccountSummary` projections (no secret
//! bytes).
//!
//! This module has two layers:
//!
//! * The pure-logic projection — [`AccountRowModel`],
//!   [`row_models_from_vault`], and [`format_rendered_marker`] —
//!   which the integration tests in `tests/account_list_logic.rs`
//!   exercise without a display server.
//! * The widget binding [`AccountListComponent`], which owns the
//!   `FactoryVecDeque<AccountRowComponent>` (whose parent widget is
//!   a `gtk::ListBox`) plus the search bar / entry. Per-tick TOTP
//!   refresh routes through `factory.send(index, …)` so the row
//!   widget tree is never torn down or rebuilt mid-frame; full
//!   refreshes (add / remove / rename / search) clear and re-push
//!   the factory through one code path on `AccountListMsg::Refresh`.

use std::collections::HashMap;

use relm4::factory::FactoryVecDeque;
use relm4::gtk;
use relm4::gtk::prelude::*;
use relm4::prelude::*;

use paladin_core::{select_after_filter, AccountId, AccountKindSummary, Vault};

use crate::account_row::{
    apply_busy_mask, copy_enabled, kebab_enabled, kebab_visible, next_button_enabled,
    next_button_visible, progress_visible, summary_display_label, AccountRowComponent,
    AccountRowInit, AccountRowMsg, AccountRowOutput, CodeDisplay, CounterText, RowDisplay,
};
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
/// or libadwaita. The widget layer uses it to compute the
/// `initial_display` it hands to each new
/// [`crate::account_row::AccountRowComponent`] on
/// [`AccountListMsg::Refresh`].
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
/// button, HOTP "next" button) originate as
/// [`AccountRowOutput`] inside each row's
/// [`crate::account_row::AccountRowComponent`]; the parent
/// [`FactoryVecDeque::forward`] mapper installed by
/// [`AccountListComponent::init`] converts each
/// [`AccountRowOutput`] variant to the matching [`AccountListOutput`]
/// variant below before forwarding to `AppModel`.
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
/// Returns one `(factory_index, RowDisplay)` entry per
/// `(AccountId, RowDisplay)` in `displays` whose id appears in
/// `row_indices`. Rows whose id is **not** in `displays` are not in
/// the output: per the migration contract, the per-tick refresh path
/// must dispatch only to rows whose code changed, not rebuild every
/// visible row. Rows whose id has been removed from the visible row
/// set (e.g. a tick that races a search-filter refresh) are dropped
/// silently — the cache update still happens in the caller but the
/// stale id has no factory entry to address.
///
/// Pure logic so `tests/account_list_logic.rs::tick_routes_only_to_changed_rows`
/// can pin the contract without spinning up GTK; the
/// [`AccountListComponent::update`] handler iterates the plan and
/// forwards each entry through [`FactoryVecDeque::send`].
#[must_use]
pub fn tick_dispatch_plan<S: std::hash::BuildHasher>(
    displays: &[(AccountId, RowDisplay)],
    row_indices: &HashMap<AccountId, usize, S>,
) -> Vec<(usize, RowDisplay)> {
    displays
        .iter()
        .filter_map(|(id, display)| row_indices.get(id).map(|&idx| (idx, display.clone())))
        .collect()
}

/// Map an [`AccountRowOutput`] emitted by an
/// [`crate::account_row::AccountRowComponent`] onto the parent
/// [`AccountListOutput`] variant forwarded to `AppModel`.
///
/// Centralized so the [`FactoryVecDeque::forward`] mapper in
/// [`AccountListComponent::init`] is a one-liner and the per-row →
/// per-list dispatch table stays in pure logic. `tests/account_list_logic.rs`
/// pins the four-arm coverage so a stale row output (or a missing
/// list output variant) surfaces as a failing test rather than as a
/// silent no-op kebab item.
///
/// Takes [`AccountRowOutput`] by value because relm4's
/// `FactoryVecDeque::forward(sender, f)` requires `F: Fn(C::Output)
/// -> Msg`, i.e. an owned argument. The body only reads the inner
/// `AccountId` (which is `Copy`), so clippy's
/// `needless_pass_by_value` lint is muted at the function level
/// rather than at every call site.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn forward_row_output(output: AccountRowOutput) -> AccountListOutput {
    match output {
        AccountRowOutput::RequestRename(id) => AccountListOutput::OpenRenameDialog(id),
        AccountRowOutput::RequestRemove(id) => AccountListOutput::OpenRemoveDialog(id),
        AccountRowOutput::RequestCopy(id) => AccountListOutput::CopyCode(id),
        AccountRowOutput::RequestAdvance(id) => AccountListOutput::AdvanceHotp(id),
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
/// display server. The caller (the
/// `list_box.connect_row_activated` closure in the
/// `AccountListComponent` widget binding) reads `kind` from
/// [`AccountRowModel::kind`] and `has_visible_code` from the live
/// cache (`AccountListComponent::live_displays`).
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

/// Pure-logic key dispatcher for the `gtk::ListBox` capture-phase
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
/// everything else, letting `gtk::ListBox`'s built-in `Home` /
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
}

/// Widget-bearing list view for the unlocked vault state.
///
/// Owns a [`FactoryVecDeque<AccountRowComponent>`] whose parent
/// widget is a `gtk::ListBox` (mounted inside a
/// `gtk::ScrolledWindow`). Each [`AccountRowModel`] is pushed as one
/// persistent `AccountRowComponent` whose widget tree is constructed
/// once at push time and reused for the row's lifetime. The
/// migration from the previous `gtk::ListView` +
/// `gio::ListStore<BoxedAnyObject>` + `gtk::SignalListItemFactory`
/// setup was driven by the flicker / dropped-click regression that
/// came out of splicing the store on every tick: each splice fired
/// `items-changed(0, N, N)` and rebound every visible row mid-frame.
///
/// The component additionally owns the `gtk::SearchBar` hosting a
/// `gtk::SearchEntry`. Selection lives on the `gtk::ListBox` itself
/// (`selection_mode = Single`, `select_row(Some(&row))`) rather than
/// on a `gtk::SingleSelection`, because `FactoryVecDeque` doesn't
/// stand up a `gio::ListModel`. `current_query` mirrors the entry's
/// text so the parent can re-feed it via
/// [`AccountListInit::initial_query`] on a rebuild;
/// `current_selection` mirrors the visible row id for the same
/// reason.
pub struct AccountListComponent {
    /// Factory backing the `gtk::ListBox`. Per-tick TOTP updates
    /// route through `factory.send(index, AccountRowMsg::Rebind(…))`
    /// so the row widget tree is never torn down or rebuilt outside
    /// of an explicit [`AccountListMsg::Refresh`].
    factory: FactoryVecDeque<AccountRowComponent>,
    /// `AccountId` → factory index lookup, rebuilt on every
    /// [`AccountListMsg::Refresh`]. Used by
    /// [`AccountListMsg::Tick`] to route a per-row
    /// [`AccountRowMsg::Rebind`] to the correct row without
    /// iterating the factory.
    row_indices: HashMap<AccountId, usize>,
    /// `gtk::SearchBar` whose `search-mode-enabled` property is
    /// toggled by [`AccountListMsg::SetSearchModeEnabled`]. The
    /// header-bar search-toggle button (wired in `app/model.rs`)
    /// dispatches that message so the bar reveals / hides in
    /// lockstep with the toggle's `active` state.
    search_bar: gtk::SearchBar,
    /// `gtk::SearchEntry` nested inside [`Self::search_bar`]. Its
    /// `search-changed` signal fires [`AccountListMsg::SetQuery`].
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
    /// Most recent row set installed by
    /// [`AccountListMsg::Refresh`]. Kept on `self` so the cache
    /// pruning on the next refresh can run without re-asking
    /// `AppModel` for a fresh projection.
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
    /// to every row through [`FactoryVecDeque::broadcast`] so each
    /// `AccountRowComponent` applies the busy mask locally per
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect
    /// ownership". Kept on `self` so subsequent
    /// [`AccountListMsg::Refresh`] can seed new rows' `initial_busy`
    /// without re-asking `AppModel`.
    busy: bool,
}

/// Messages handled by [`AccountListComponent`].
///
/// * [`SetQuery`](AccountListMsg::SetQuery): emitted from the
///   `gtk::SearchEntry`'s `search-changed` signal. Caches the new
///   query and bubbles it up as
///   [`AccountListOutput::QueryChanged`] so `AppModel` recomputes
///   the filtered row set against the live `Vault`.
/// * [`Refresh`](AccountListMsg::Refresh): sent by `AppModel` after
///   a vault mutation or a search-filter recomputation. Clears and
///   re-pushes the factory with the new row set and reapplies the
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
        /// Selection to install on the `gtk::ListBox`. `None` clears
        /// the selection.
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
    /// User activated the `gtk::ListBoxRow` at the given factory
    /// index — Enter on the focused row, or a double-click. Posted
    /// by the `list_box.connect_row_activated` closure installed in
    /// [`AccountListComponent::init`]. The handler looks up
    /// [`AccountListComponent::current_rows`] for the row's
    /// `AccountId` / kind and
    /// [`AccountListComponent::live_displays`] for the visible-code
    /// state, then routes through [`default_row_activation`] to
    /// emit the matching [`AccountListOutput`] (`CopyCode` for TOTP
    /// rows and revealed HOTP rows; `ActivateHotpAndCopy` for
    /// un-revealed HOTP rows). Out-of-range indices are a benign
    /// no-op (defensive against a stray dispatch racing a refresh).
    ActivateRow(usize),
    /// Per-tick TOTP refresh from the [`crate::ticker`] driver.
    ///
    /// `AppModel`'s per-tick `glib::timeout_add_local` callback
    /// projects the live `(Vault, Store)` pair through
    /// [`crate::ticker::tick`] and forwards the resulting
    /// `Vec<(AccountId, RowDisplay)>` here. The handler updates
    /// [`AccountListComponent::live_displays`] and sends one
    /// targeted [`AccountRowMsg::Rebind`] per changed row through
    /// [`FactoryVecDeque::send`]; rows whose code did not change in
    /// this tick are not contacted, so the widget tree stays
    /// untouched. Empty payload is a benign no-op (e.g. an
    /// HOTP-only vault — no TOTP refresh is needed).
    Tick(Vec<(AccountId, RowDisplay)>),
    /// Latch the parent `AppModel`'s `AppState::is_busy()` state and
    /// broadcast it to every row so `AccountRowComponent::SetBusy`
    /// dims copy / "next" / kebab while a vault-touching worker is
    /// in flight per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight
    /// effect ownership".
    ///
    /// `AppModel` sends `SetBusy(true)` on entry into
    /// `UnlockedBusy` and `SetBusy(false)` on the worker return /
    /// `Locked` / `StartupError` transitions. Idempotent — sending
    /// the same value twice is a benign no-op (no broadcast fires).
    SetBusy(bool),
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
                set_child: Some(factory_widget),
            },
        }
    }

    fn init(
        init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let list_box = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .build();
        list_box.add_css_class("navigation-sidebar");

        let mut factory = FactoryVecDeque::<AccountRowComponent>::builder()
            .launch(list_box)
            .forward(sender.output_sender(), forward_row_output);

        let mut row_indices: HashMap<AccountId, usize> = HashMap::new();
        {
            let mut guard = factory.guard();
            for (idx, row) in init.rows.iter().enumerate() {
                guard.push_back(AccountRowInit {
                    account_id: row.id,
                    initial_display: hidden_row_display(row),
                    initial_icon_hint: row.icon_hint.clone(),
                    initial_busy: false,
                });
                row_indices.insert(row.id, idx);
            }
        }

        apply_list_box_selection(factory.widget(), &init.rows, init.initial_selection);

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
        wire_account_list_navigation_controllers(&search_entry, factory.widget());

        // Enter on the focused `gtk::ListBoxRow` (or a double-click)
        // fires `gtk::ListBox::row-activated`. The closure forwards
        // the row's factory index back through
        // `AccountListMsg::ActivateRow`, which resolves the row's
        // kind + visible-code state and emits the matching
        // `AccountListOutput::CopyCode` /
        // `AccountListOutput::ActivateHotpAndCopy` per
        // `default_row_activation`.
        let activate_input = sender.input_sender().clone();
        factory.widget().connect_row_activated(move |_, row| {
            if let Ok(idx) = usize::try_from(row.index()) {
                let _ = activate_input.send(AccountListMsg::ActivateRow(idx));
            }
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

        let factory_widget = factory.widget();
        let widgets = view_output!();

        let component = AccountListComponent {
            factory,
            row_indices,
            search_bar,
            search_entry,
            current_query: init.initial_query,
            current_selection: init.initial_selection,
            current_rows: init.rows,
            live_displays: HashMap::new(),
            busy: false,
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
                prune_cache_to_rows(&mut self.live_displays, &rows);
                self.row_indices.clear();
                {
                    let mut guard = self.factory.guard();
                    guard.clear();
                    for (idx, row) in rows.iter().enumerate() {
                        let initial_display = self
                            .live_displays
                            .get(&row.id)
                            .cloned()
                            .unwrap_or_else(|| hidden_row_display(row));
                        guard.push_back(AccountRowInit {
                            account_id: row.id,
                            initial_display,
                            initial_icon_hint: row.icon_hint.clone(),
                            initial_busy: self.busy,
                        });
                        self.row_indices.insert(row.id, idx);
                    }
                }
                apply_list_box_selection(self.factory.widget(), &rows, effective_selection);
                self.current_selection = effective_selection;
                self.current_rows = rows;
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
            AccountListMsg::ActivateRow(idx) => {
                if let Some(row) = self.current_rows.get(idx) {
                    let has_visible_code = self
                        .live_displays
                        .get(&row.id)
                        .is_some_and(|d| matches!(d.code, CodeDisplay::Visible(_)));
                    let output = default_row_activation(row.kind, has_visible_code, row.id);
                    let _ = sender.output(output);
                }
            }
            AccountListMsg::Tick(displays) => {
                if displays.is_empty() {
                    return;
                }
                for (id, display) in &displays {
                    self.live_displays.insert(*id, display.clone());
                }
                for (idx, display) in tick_dispatch_plan(&displays, &self.row_indices) {
                    self.factory.send(idx, AccountRowMsg::Rebind(display));
                }
            }
            AccountListMsg::SetBusy(busy) => {
                if self.busy == busy {
                    return;
                }
                self.busy = busy;
                self.factory.broadcast(AccountRowMsg::SetBusy(busy));
            }
        }
    }
}

/// Install `target` as the selected row on the `gtk::ListBox`.
///
/// Resolves the row id to its position in `rows`, looks up the
/// matching `gtk::ListBoxRow` via
/// [`gtk::ListBox::row_at_index`], and calls
/// [`gtk::ListBox::select_row`]. Falls back to
/// [`gtk::ListBox::unselect_all`] when `target` is `None` or not
/// present. The widget layer never picks the selection itself; the
/// choice flows from [`selected_row_after_refresh`] /
/// [`AccountListInit::initial_selection`] so the filter-aware
/// preservation rule stays in pure logic.
fn apply_list_box_selection(
    list_box: &gtk::ListBox,
    rows: &[AccountRowModel],
    target: Option<AccountId>,
) {
    if let Some(id) = target {
        if let Some(idx) = rows.iter().position(|row| row.id == id) {
            if let Ok(i32_idx) = i32::try_from(idx) {
                if let Some(row) = list_box.row_at_index(i32_idx) {
                    list_box.select_row(Some(&row));
                    return;
                }
            }
        }
    }
    list_box.unselect_all();
}

/// Install the capture-phase `gtk::EventControllerKey` pair that
/// implements cross-widget arrow-key navigation between the
/// `gtk::SearchEntry` and the account-list `gtk::ListBox`.
///
/// Two controllers cover four cases:
///
/// * On `search_entry`: pressing Down (or Ctrl+J / Ctrl+N) hands
///   keyboard focus to the first row of `list_box` (selecting it
///   in the process). When the filtered list is empty the press is
///   propagated so it remains a benign no-op.
/// * On `list_box`: pressing Up (or Ctrl+K / Ctrl+P) while the
///   focused row is the first row hands focus back to
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
/// `gtk::ListBox`'s built-in Up / Down bindings (and before any
/// per-row controller installed by the factory), ensuring a
/// uniform navigation contract. Bare `j` / `k` are intentionally
/// left to bubble so the window-level "type to search" capture
/// installed by [`gtk::SearchBar::set_key_capture_widget`] still
/// receives them. `Home` / `End` / `Page_Up` / `Page_Down` — and every key
/// outside the dispatch tables in [`dispatch_search_entry_to_list_nav`]
/// and [`dispatch_list_box_nav`] — propagate untouched so
/// `gtk::ListBox`'s built-in behaviors keep working.
///
/// Pure side-effect helper. The closures clone `search_entry` /
/// `list_box` so the caller does not need to retain handles to
/// the controllers themselves.
fn wire_account_list_navigation_controllers(
    search_entry: &gtk::SearchEntry,
    list_box: &gtk::ListBox,
) {
    let list_box_for_entry = list_box.clone();
    let entry_ctrl = gtk::EventControllerKey::new();
    entry_ctrl.set_propagation_phase(gtk::PropagationPhase::Capture);
    entry_ctrl.connect_key_pressed(move |_, keyval, _, mods| {
        if dispatch_search_entry_to_list_nav(keyval, mods) {
            if let Some(first_row) = list_box_for_entry.row_at_index(0) {
                list_box_for_entry.select_row(Some(&first_row));
                first_row.grab_focus();
                return gtk::glib::Propagation::Stop;
            }
        }
        gtk::glib::Propagation::Proceed
    });
    search_entry.add_controller(entry_ctrl);

    let search_entry_for_list = search_entry.clone();
    let list_box_for_list = list_box.clone();
    let list_ctrl = gtk::EventControllerKey::new();
    list_ctrl.set_propagation_phase(gtk::PropagationPhase::Capture);
    list_ctrl.connect_key_pressed(move |_, keyval, _, mods| {
        let Some(intent) = dispatch_list_box_nav(keyval, mods) else {
            return gtk::glib::Propagation::Proceed;
        };
        let current_idx = list_box_for_list.selected_row().map(|r| r.index());
        match intent {
            ListNavIntent::Up => match current_idx {
                Some(0) => {
                    search_entry_for_list.grab_focus();
                    search_entry_for_list.select_region(0, -1);
                    gtk::glib::Propagation::Stop
                }
                Some(idx) if idx > 0 => {
                    if let Some(target) = list_box_for_list.row_at_index(idx - 1) {
                        list_box_for_list.select_row(Some(&target));
                        target.grab_focus();
                    }
                    gtk::glib::Propagation::Stop
                }
                _ => {
                    if let Some(first) = list_box_for_list.row_at_index(0) {
                        list_box_for_list.select_row(Some(&first));
                        first.grab_focus();
                    }
                    gtk::glib::Propagation::Stop
                }
            },
            ListNavIntent::Down => {
                let target_idx = current_idx.map_or(0, |i| i + 1);
                if let Some(target) = list_box_for_list.row_at_index(target_idx) {
                    list_box_for_list.select_row(Some(&target));
                    target.grab_focus();
                }
                gtk::glib::Propagation::Stop
            }
        }
    });
    list_box.add_controller(list_ctrl);
}
