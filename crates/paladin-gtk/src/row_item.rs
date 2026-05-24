// SPDX-License-Identifier: AGPL-3.0-or-later

//! `RowItem` `GObject` — the `gio::ListStore` element backing
//! `AccountListComponent`'s `gtk::ColumnView`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2.2, the
//! unlocked vault list is driven by a `gio::ListStore<RowItem>` whose
//! row count is *only* changed by Add / Remove / search-filter. Per-tick
//! TOTP refreshes mutate the existing `RowItem`'s
//! [`crate::account_row::RowDisplay`] through [`RowItem::set_display`]
//! and fan out the [`ROW_ITEM_DISPLAY_CHANGED_SIGNAL`] signal so cell
//! factories rebind their widgets against the new values without the
//! store calling `splice`.
//!
//! This is the flicker-free invariant the previous `gtk::ListView`
//! attempt lost — see `crate::account_list::AccountListComponent`'s
//! doc-comment for the historical context. The contract is documented
//! in `tests/row_item_logic.rs` and re-asserted in
//! `tests/account_list_logic.rs`.

use paladin_core::AccountId;
use relm4::gtk::glib;
use relm4::gtk::glib::prelude::*;
use relm4::gtk::glib::subclass::prelude::*;

use crate::account_row::RowDisplay;

/// Name of the signal emitted by [`RowItem::set_display`] and
/// [`RowItem::set_busy`] when the bound display changes.
///
/// Cell factories `connect_local` to this name inside their `bind`
/// step (and disconnect inside `unbind`) so the per-tick refresh
/// path triggers a widget-level rebind without touching the
/// `gio::ListStore`'s row count.
pub const ROW_ITEM_DISPLAY_CHANGED_SIGNAL: &str = "display-changed";

/// Discriminator for the two row shapes the `gtk::ColumnView`
/// renders out of the same `gio::ListStore<RowItem>`.
///
/// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2.4,
/// section headers are interleaved into the store as `Section`
/// rows so the shipped `show-section-headers` user preference
/// survives the migration off `gtk::ListBox::set_header_func`. Cell
/// factories branch on `kind`: the "Account" column cell renders a
/// single full-width heading for sections; every other column
/// renders an empty placeholder. Selection is suppressed for
/// sections via `list_item.set_selectable(false)` in the bind step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKind {
    /// Section header row. The string is the heading text — typically
    /// the issuer name per
    /// [`crate::account_list::issuer_group_header`].
    Section(String),
    /// Account row. Per-row data lives in the wrapper's
    /// `account_id` / `display` / `icon_hint` fields; the kind enum
    /// itself carries nothing because the data is keyed by id.
    Account,
}

mod imp {
    use std::cell::{Cell, RefCell};
    use std::sync::OnceLock;

    use paladin_core::{AccountId, AccountKindSummary};
    use relm4::gtk::glib;
    use relm4::gtk::glib::subclass::prelude::*;
    use relm4::gtk::glib::subclass::Signal;

    use crate::account_row::{CodeDisplay, RowDisplay};

    pub struct RowItem {
        pub(super) kind: RefCell<super::RowKind>,
        pub(super) id: Cell<Option<AccountId>>,
        pub(super) display: RefCell<RowDisplay>,
        pub(super) icon_hint: RefCell<Option<String>>,
        pub(super) issuer: RefCell<Option<String>>,
        pub(super) busy: Cell<bool>,
    }

    impl Default for RowItem {
        fn default() -> Self {
            // `RowDisplay` carries an `AccountKindSummary` so it has
            // no derivable `Default`. Pick a placeholder that the
            // cell factories will visibly recognize as "not yet
            // initialized" (empty label, hidden code, every control
            // disabled). `RowItem::from_row_model` / `RowItem::section`
            // always replace this immediately; the default exists
            // only because `glib::Object::new` default-constructs the
            // imp.
            Self {
                kind: RefCell::new(super::RowKind::Account),
                id: Cell::new(None),
                display: RefCell::new(RowDisplay {
                    label: String::new(),
                    kind: AccountKindSummary::Totp,
                    code: CodeDisplay::Hidden,
                    next_code: None,
                    counter: None,
                    copy_enabled: false,
                    next_button_visible: false,
                    next_button_enabled: false,
                    progress_visible: false,
                    progress: None,
                    kebab_visible: false,
                    kebab_enabled: false,
                }),
                icon_hint: RefCell::new(None),
                issuer: RefCell::new(None),
                busy: Cell::new(false),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RowItem {
        const NAME: &'static str = "PaladinRowItem";
        type Type = super::RowItem;
    }

    impl ObjectImpl for RowItem {
        fn signals() -> &'static [Signal] {
            static SIGNALS: OnceLock<Vec<Signal>> = OnceLock::new();
            SIGNALS.get_or_init(|| {
                vec![Signal::builder(super::ROW_ITEM_DISPLAY_CHANGED_SIGNAL).build()]
            })
        }
    }
}

glib::wrapper! {
    /// GObject wrapper around the per-row state the
    /// `gtk::ColumnView` cell factories read.
    pub struct RowItem(ObjectSubclass<imp::RowItem>);
}

impl RowItem {
    /// Construct a fresh `RowItem` with the placeholder default
    /// state (no id, hidden display, no icon hint, not busy).
    ///
    /// Callers should prefer [`Self::from_row_model`] — the default
    /// exists for the `glib::Object::new` constructor's sake; the
    /// list store should never carry a `RowItem` whose
    /// [`Self::account_id`] is `None` in normal operation.
    #[must_use]
    pub fn new() -> Self {
        glib::Object::new()
    }

    /// Construct an account-row `RowItem` from an
    /// [`crate::account_list::AccountRowModel`].
    ///
    /// The display projection is seeded to the
    /// [`crate::account_list::hidden_row_display`] form so the cell
    /// factories render the row before the per-tick driver computes
    /// the first visible code. The per-tick driver replaces it via
    /// [`Self::set_display`] on the next tick.
    #[must_use]
    pub fn from_row_model(model: &crate::account_list::AccountRowModel) -> Self {
        let item: Self = Self::new();
        let imp = item.imp();
        imp.kind.replace(RowKind::Account);
        imp.id.set(Some(model.id));
        imp.icon_hint.replace(model.icon_hint.clone());
        imp.issuer.replace(model.issuer.clone());
        imp.display
            .replace(crate::account_list::hidden_row_display(model));
        item
    }

    /// Construct a section-header `RowItem` carrying the given
    /// heading text.
    ///
    /// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.2.4
    /// section headers are interleaved into the same store the
    /// `gtk::ColumnView` reads. Cell factories check
    /// [`Self::kind`] / [`Self::is_section`] in their `bind` step
    /// and render the "Account" column's cell as a single full-width
    /// heading; every other column renders empty for the section.
    /// `list_item.set_selectable(false)` is called on section rows
    /// so the `gtk::SingleSelection` cannot land on them.
    #[must_use]
    pub fn section(title: impl Into<String>) -> Self {
        let item: Self = Self::new();
        let imp = item.imp();
        imp.kind.replace(RowKind::Section(title.into()));
        item
    }

    /// The row's discriminator. Cell factories branch on this to
    /// pick the section-row vs account-row rendering path.
    #[must_use]
    pub fn kind(&self) -> RowKind {
        self.imp().kind.borrow().clone()
    }

    /// Convenience: `true` if the row is a [`RowKind::Section`].
    #[must_use]
    pub fn is_section(&self) -> bool {
        matches!(*self.imp().kind.borrow(), RowKind::Section(_))
    }

    /// The section heading text for a [`RowKind::Section`] row, or
    /// `None` for [`RowKind::Account`] / default rows.
    #[must_use]
    pub fn section_title(&self) -> Option<String> {
        match &*self.imp().kind.borrow() {
            RowKind::Section(title) => Some(title.clone()),
            RowKind::Account => None,
        }
    }

    /// The bound account id, or `None` for a freshly default-constructed
    /// `RowItem` that has not yet been seeded by [`Self::from_row_model`].
    #[must_use]
    pub fn account_id(&self) -> Option<AccountId> {
        self.imp().id.get()
    }

    /// A clone of the current display projection.
    ///
    /// Cell factories call this from their `display-changed`
    /// handlers to read the new values; the projection is small
    /// enough that cloning per refresh is not a hot-path concern.
    #[must_use]
    pub fn display(&self) -> RowDisplay {
        self.imp().display.borrow().clone()
    }

    /// The icon-hint slug from
    /// [`paladin_core::AccountSummary::icon_hint`], if any.
    #[must_use]
    pub fn icon_hint(&self) -> Option<String> {
        self.imp().icon_hint.borrow().clone()
    }

    /// The issuer string projected from
    /// [`crate::account_list::AccountRowModel::issuer`].  Read by
    /// the Account-column sorter
    /// (`column_view::build_account_column_sorter`) to back the
    /// case-insensitive `(issuer, label)` ordering pinned in
    /// `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.4 "Sortable
    /// columns".  `None` for section rows and for any account row
    /// whose `AccountRowModel.issuer` was `None`.
    #[must_use]
    pub fn issuer(&self) -> Option<String> {
        self.imp().issuer.borrow().clone()
    }

    /// The last busy value latched via [`Self::set_busy`].
    #[must_use]
    pub fn busy(&self) -> bool {
        self.imp().busy.get()
    }

    /// Replace the current display projection and emit
    /// [`ROW_ITEM_DISPLAY_CHANGED_SIGNAL`] so subscribed cell
    /// factories rebind their widgets in place.
    ///
    /// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §A.2.5 this is the
    /// per-tick TOTP refresh path — never call `store.splice(...)`
    /// from a tick handler. The signal fires unconditionally so cell
    /// factories can re-apply the busy mask even if the underlying
    /// `RowDisplay` is structurally equal to the prior one (the busy
    /// flag changing alone is enough to require a rebind).
    pub fn set_display(&self, display: RowDisplay) {
        self.imp().display.replace(display);
        self.emit_by_name::<()>(ROW_ITEM_DISPLAY_CHANGED_SIGNAL, &[]);
    }

    /// Latch the parent `AppModel`'s `is_busy()` value on this row.
    ///
    /// Idempotent — repeating the same value is a no-op (no signal
    /// fires) so the cell-factory rebind loop is not spuriously
    /// woken when `AppModel` broadcasts the same state to every
    /// row. Changing the value fires
    /// [`ROW_ITEM_DISPLAY_CHANGED_SIGNAL`].
    pub fn set_busy(&self, busy: bool) {
        if self.imp().busy.get() == busy {
            return;
        }
        self.imp().busy.set(busy);
        self.emit_by_name::<()>(ROW_ITEM_DISPLAY_CHANGED_SIGNAL, &[]);
    }
}

impl Default for RowItem {
    fn default() -> Self {
        Self::new()
    }
}
