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

use paladin_core::{AccountId, AccountKindSummary, Vault};

use crate::account_row::{
    copy_enabled, display_label, kebab_visible, next_button_visible, progress_visible, CodeDisplay,
    CounterText, RowDisplay,
};

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
/// in response to a row-level user intent.
///
/// Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
/// `AccountRowComponent`, the row kebab menu carries Rename… /
/// Remove… entries whose action targets dispatch through the
/// per-row [`gio::SimpleActionGroup`] installed by [`bind_row`]. The
/// activation callback maps the fired action name onto one of these
/// variants via [`dispatch_row_action`] and forwards it through
/// `relm4::Sender::output` so `AppModel` can open the corresponding
/// dialog widget against the row's [`AccountId`].
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
    /// [`row_models_from_vault`]. Cloned into the `gio::ListStore`
    /// at mount time; subsequent commits will replace this single-
    /// shot init with a message-driven re-bind on add / remove /
    /// rename.
    pub rows: Vec<AccountRowModel>,
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
pub struct AccountListComponent {
    /// Backing `gio::ListStore` of `BoxedAnyObject<AccountRowModel>`.
    /// Retained on `self` so future messages (add / remove / rename)
    /// can `append` / `remove` / `splice` against it.
    #[allow(dead_code)]
    model: gio::ListStore,
}

/// Messages handled by [`AccountListComponent`].
///
/// This milestone delivers the read-only render path; subsequent
/// commits will add Add / Remove / Rename / Copy variants. The
/// empty enum is the deliberate v0.2 starting point — relm4
/// requires the associated `Input` type to exist even when no
/// inbound messages are wired yet.
#[derive(Debug)]
pub enum AccountListMsg {}

#[allow(missing_docs)]
#[relm4::component(pub)]
impl SimpleComponent for AccountListComponent {
    type Init = AccountListInit;
    type Input = AccountListMsg;
    type Output = AccountListOutput;

    view! {
        #[root]
        gtk::ScrolledWindow {
            set_hexpand: true,
            set_vexpand: true,

            #[wrap(Some)]
            set_child = &gtk::ListView {
                set_model: Some(&gtk::SingleSelection::new(Some(model.clone()))),
                set_factory: Some(&factory),
                add_css_class: "navigation-sidebar",
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

        let factory = build_row_factory(sender.output_sender().clone());
        let widgets = view_output!();

        let component = AccountListComponent { model };
        ComponentParts {
            model: component,
            widgets,
        }
    }

    fn update(&mut self, _msg: Self::Input, _sender: ComponentSender<Self>) {
        // No inbound messages handled at this milestone — see
        // `AccountListMsg` doc comment.
    }
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
