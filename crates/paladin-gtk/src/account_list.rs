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

use crate::account_row::display_label;

/// Stdout marker prefix emitted under `--exit-after-startup` once
/// the [`AccountListComponent`] has bound rows from the live vault.
///
/// The smoke test in `tests/gtk_smoke.rs` greps for this prefix,
/// and the pure-logic test in `tests/account_list_logic.rs` pins
/// the format. Centralizing the literal here keeps test +
/// implementation aligned.
pub const ACCOUNT_LIST_RENDERED_MARKER_PREFIX: &str = "paladin-gtk: account_list_rows=";

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
/// that maps each model onto a single-line label. The factory does
/// not touch the live `Account` — it only reads the already-
/// projected `AccountRowModel`, so the row binding is secret-free.
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
    type Output = ();

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
        _sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = gio::ListStore::new::<glib::BoxedAnyObject>();
        for row in &init.rows {
            model.append(&glib::BoxedAnyObject::new(row.clone()));
        }

        let factory = build_row_factory();
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

/// Build the `gtk::SignalListItemFactory` that maps an
/// `AccountRowModel` (wrapped in `BoxedAnyObject`) onto a single
/// `gtk::Label` showing `display_label`.
///
/// Subsequent commits will expand the row child into the full
/// per-row widget bundle (label, code, counter, copy button,
/// progress indicator, "next" button, kebab menu) per §"Component
/// tree" > `AccountRowComponent`. The factory still reads only the
/// already-projected `AccountRowModel`, so it stays secret-free.
fn build_row_factory() -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let label = gtk::Label::builder()
            .halign(gtk::Align::Start)
            .xalign(0.0)
            .build();
        if let Some(list_item) = item.downcast_ref::<gtk::ListItem>() {
            list_item.set_child(Some(&label));
        }
    });
    factory.connect_bind(|_, item| {
        let Some(list_item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        let Some(child) = list_item.child() else {
            return;
        };
        let Ok(label) = child.downcast::<gtk::Label>() else {
            return;
        };
        let Some(obj) = list_item.item() else {
            return;
        };
        let Ok(boxed) = obj.downcast::<glib::BoxedAnyObject>() else {
            return;
        };
        let row: std::cell::Ref<AccountRowModel> = boxed.borrow();
        label.set_label(&row.display_label);
    });
    factory
}
