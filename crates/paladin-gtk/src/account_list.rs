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
    copy_enabled, display_label, next_button_visible, progress_visible, CodeDisplay, CounterText,
    RowDisplay,
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
/// fingerprints the visible per-row affordance states (currently
/// just the copy button). This is what makes the addition of the
/// copy button observable from the smoke test without driving
/// widget signals. Future commits that wire the HOTP "next" button
/// or the kebab menu append additional key/value pairs to each
/// entry.
pub const ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX: &str =
    "paladin-gtk: account_list_widget_states=";

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
                "copy:{},next:{}",
                if d.copy_enabled { "on" } else { "off" },
                if d.next_button_visible { "on" } else { "off" },
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
fn build_row_factory() -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    factory.connect_setup(|_, item| {
        let Some(list_item) = item.downcast_ref::<gtk::ListItem>() else {
            return;
        };
        list_item.set_child(Some(&build_row_widget()));
    });
    factory.connect_bind(|_, item| {
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
    });
    factory
}

/// Construct one row's widget bundle.
///
/// The container is a horizontal `gtk::Box` whose children are
/// appended in the order `display label → HOTP counter → code
/// label → copy button`. The label expands to claim the row's free
/// space so the counter / code labels and the trailing copy button
/// stay end-aligned and the column edges line up across rows.
/// [`bind_row`] walks the children in this same order to apply the
/// projection. The copy button carries an `edit-copy-symbolic`
/// icon, the `.flat` style class for the row-trailing affordance
/// look, and its sensitive state is driven by
/// [`RowDisplay::copy_enabled`] in [`bind_row`]; the click handler
/// lands in a follow-up commit that introduces the
/// `AccountListMsg::CopyRow` round-trip.
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
    container.append(&label);
    container.append(&counter);
    container.append(&code);
    container.append(&copy);
    container.append(&next);
    container
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
}
