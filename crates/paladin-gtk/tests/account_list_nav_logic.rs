// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for the cross-widget arrow-key navigation
//! dispatchers in `account_list`:
//!
//! * [`dispatch_search_entry_to_list_nav`] — capture-phase
//!   controller on the `gtk::SearchEntry` that hands focus to the
//!   first row of the account list when the user presses Down,
//!   Ctrl+J, or Ctrl+N.
//! * [`dispatch_list_box_nav`] — capture-phase controller on the
//!   `gtk::ListBox` that translates Up / Down / Ctrl+K / Ctrl+J /
//!   Ctrl+P / Ctrl+N into a [`ListNavIntent`], with the first-row
//!   edge transition handled by the widget wiring rather than the
//!   dispatcher itself.
//!
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Keyboard Shortcuts" pins the
//! mapping: bare arrow keys mirror their vim-style Ctrl+J / Ctrl+K
//! and readline-style Ctrl+N / Ctrl+P equivalents, any compound
//! chord carrying ALT / SUPER / HYPER / META is rejected, arrow
//! keys combined with CONTROL are left to bubble (`Ctrl+Down` /
//! `Ctrl+Up` are different platform shortcuts on some desktops),
//! and Ctrl+N with SHIFT also bubbles because
//! `<Control><Shift>n` is the "Add account" app accelerator.
//! These tests exercise the dispatch tables directly so the
//! assertions run without a display server.

use paladin_core::{AccountId, AccountKindSummary};
use paladin_gtk::account_list::{
    default_row_activation, dispatch_list_box_nav, dispatch_search_entry_to_list_nav,
    AccountListOutput, ListNavIntent,
};
use relm4::gtk::gdk;

fn fixture_id() -> AccountId {
    AccountId::new()
}

// -- search entry → first row ----------------------------------

#[test]
fn search_entry_down_arrow_dispatches_nav() {
    assert!(dispatch_search_entry_to_list_nav(
        gdk::Key::Down,
        gdk::ModifierType::empty()
    ));
}

#[test]
fn search_entry_down_arrow_with_control_does_not_dispatch() {
    assert!(
        !dispatch_search_entry_to_list_nav(gdk::Key::Down, gdk::ModifierType::CONTROL_MASK),
        "Ctrl+Down is a different platform shortcut; do not steal it",
    );
}

#[test]
fn search_entry_ctrl_j_dispatches_nav() {
    assert!(dispatch_search_entry_to_list_nav(
        gdk::Key::j,
        gdk::ModifierType::CONTROL_MASK
    ));
}

#[test]
fn search_entry_ctrl_uppercase_j_dispatches_nav() {
    assert!(
        dispatch_search_entry_to_list_nav(gdk::Key::J, gdk::ModifierType::CONTROL_MASK),
        "Ctrl+Shift+J (uppercase keyval) must also match",
    );
}

#[test]
fn search_entry_bare_j_does_not_dispatch() {
    assert!(
        !dispatch_search_entry_to_list_nav(gdk::Key::j, gdk::ModifierType::empty()),
        "bare `j` must not steal the typing-to-search path",
    );
}

#[test]
fn search_entry_ctrl_j_with_alt_does_not_dispatch() {
    assert!(!dispatch_search_entry_to_list_nav(
        gdk::Key::j,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    ));
}

#[test]
fn search_entry_ctrl_n_dispatches_nav() {
    assert!(
        dispatch_search_entry_to_list_nav(gdk::Key::n, gdk::ModifierType::CONTROL_MASK),
        "Ctrl+N is the readline-style \"next\" mirror of Down",
    );
}

#[test]
fn search_entry_ctrl_uppercase_n_dispatches_nav() {
    assert!(
        dispatch_search_entry_to_list_nav(gdk::Key::N, gdk::ModifierType::CONTROL_MASK),
        "Ctrl+N delivered as uppercase keyval (caps lock, some layouts) still matches when SHIFT is not in mods",
    );
}

#[test]
fn search_entry_ctrl_shift_n_does_not_dispatch() {
    assert!(
        !dispatch_search_entry_to_list_nav(
            gdk::Key::n,
            gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::SHIFT_MASK,
        ),
        "Ctrl+Shift+N is the `app.add` accelerator; do not steal it",
    );
    assert!(
        !dispatch_search_entry_to_list_nav(
            gdk::Key::N,
            gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::SHIFT_MASK,
        ),
        "Ctrl+Shift+N (uppercase keyval) is the `app.add` accelerator; do not steal it",
    );
}

#[test]
fn search_entry_bare_n_does_not_dispatch() {
    assert!(
        !dispatch_search_entry_to_list_nav(gdk::Key::n, gdk::ModifierType::empty()),
        "bare `n` must not steal the typing-to-search path",
    );
}

#[test]
fn search_entry_ctrl_n_with_alt_does_not_dispatch() {
    assert!(!dispatch_search_entry_to_list_nav(
        gdk::Key::n,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    ));
}

#[test]
fn search_entry_down_with_super_does_not_dispatch() {
    assert!(!dispatch_search_entry_to_list_nav(
        gdk::Key::Down,
        gdk::ModifierType::SUPER_MASK
    ));
}

#[test]
fn search_entry_up_arrow_does_not_dispatch() {
    assert!(
        !dispatch_search_entry_to_list_nav(gdk::Key::Up, gdk::ModifierType::empty()),
        "Up has no meaning in a single-line search entry",
    );
}

#[test]
fn search_entry_unrelated_keys_do_not_dispatch() {
    for keyval in [
        gdk::Key::a,
        gdk::Key::Return,
        gdk::Key::Escape,
        gdk::Key::Tab,
        gdk::Key::Home,
        gdk::Key::End,
    ] {
        assert!(
            !dispatch_search_entry_to_list_nav(keyval, gdk::ModifierType::empty()),
            "{keyval:?} must not trigger the search→list nav",
        );
    }
}

// -- list box up / down ---------------------------------------

#[test]
fn list_box_up_arrow_dispatches_up_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::Up, gdk::ModifierType::empty()),
        Some(ListNavIntent::Up),
    );
}

#[test]
fn list_box_down_arrow_dispatches_down_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::Down, gdk::ModifierType::empty()),
        Some(ListNavIntent::Down),
    );
}

#[test]
fn list_box_ctrl_k_dispatches_up_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::k, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Up),
    );
}

#[test]
fn list_box_ctrl_uppercase_k_dispatches_up_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::K, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Up),
        "Ctrl+Shift+K (uppercase keyval) must also mirror Up",
    );
}

#[test]
fn list_box_ctrl_j_dispatches_down_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::j, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Down),
    );
}

#[test]
fn list_box_ctrl_uppercase_j_dispatches_down_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::J, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Down),
    );
}

#[test]
fn list_box_ctrl_p_dispatches_up_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::p, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Up),
        "Ctrl+P is the readline-style \"previous\" mirror of Up",
    );
}

#[test]
fn list_box_ctrl_uppercase_p_dispatches_up_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::P, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Up),
        "Ctrl+Shift+P (uppercase keyval) must also mirror Up",
    );
}

#[test]
fn list_box_ctrl_n_dispatches_down_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::n, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Down),
        "Ctrl+N is the readline-style \"next\" mirror of Down",
    );
}

#[test]
fn list_box_ctrl_uppercase_n_dispatches_down_intent() {
    assert_eq!(
        dispatch_list_box_nav(gdk::Key::N, gdk::ModifierType::CONTROL_MASK),
        Some(ListNavIntent::Down),
        "Ctrl+N delivered as uppercase keyval (caps lock, some layouts) still matches when SHIFT is not in mods",
    );
}

#[test]
fn list_box_ctrl_shift_n_does_not_dispatch() {
    assert!(
        dispatch_list_box_nav(
            gdk::Key::n,
            gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::SHIFT_MASK,
        )
        .is_none(),
        "Ctrl+Shift+N is the `app.add` accelerator; do not steal it",
    );
    assert!(
        dispatch_list_box_nav(
            gdk::Key::N,
            gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::SHIFT_MASK,
        )
        .is_none(),
        "Ctrl+Shift+N (uppercase keyval) is the `app.add` accelerator; do not steal it",
    );
}

#[test]
fn list_box_bare_p_does_not_dispatch() {
    assert!(
        dispatch_list_box_nav(gdk::Key::p, gdk::ModifierType::empty()).is_none(),
        "bare `p` must not steal the typing-to-search path",
    );
}

#[test]
fn list_box_bare_n_does_not_dispatch() {
    assert!(
        dispatch_list_box_nav(gdk::Key::n, gdk::ModifierType::empty()).is_none(),
        "bare `n` must not steal the typing-to-search path",
    );
}

#[test]
fn list_box_bare_k_does_not_dispatch() {
    assert!(
        dispatch_list_box_nav(gdk::Key::k, gdk::ModifierType::empty()).is_none(),
        "bare `k` must not steal the typing-to-search path",
    );
}

#[test]
fn list_box_bare_j_does_not_dispatch() {
    assert!(
        dispatch_list_box_nav(gdk::Key::j, gdk::ModifierType::empty()).is_none(),
        "bare `j` must not steal the typing-to-search path",
    );
}

#[test]
fn list_box_ctrl_arrow_keys_do_not_dispatch() {
    assert!(
        dispatch_list_box_nav(gdk::Key::Up, gdk::ModifierType::CONTROL_MASK).is_none(),
        "Ctrl+Up is a different platform shortcut; do not steal it",
    );
    assert!(
        dispatch_list_box_nav(gdk::Key::Down, gdk::ModifierType::CONTROL_MASK).is_none(),
        "Ctrl+Down is a different platform shortcut; do not steal it",
    );
}

#[test]
fn list_box_alt_chords_do_not_dispatch() {
    assert!(dispatch_list_box_nav(
        gdk::Key::k,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    )
    .is_none());
    assert!(dispatch_list_box_nav(
        gdk::Key::j,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    )
    .is_none());
    assert!(dispatch_list_box_nav(
        gdk::Key::p,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    )
    .is_none());
    assert!(dispatch_list_box_nav(
        gdk::Key::n,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    )
    .is_none());
    assert!(dispatch_list_box_nav(gdk::Key::Up, gdk::ModifierType::ALT_MASK).is_none());
    assert!(dispatch_list_box_nav(gdk::Key::Down, gdk::ModifierType::ALT_MASK).is_none());
}

#[test]
fn list_box_super_chords_do_not_dispatch() {
    assert!(dispatch_list_box_nav(gdk::Key::Up, gdk::ModifierType::SUPER_MASK).is_none());
    assert!(dispatch_list_box_nav(
        gdk::Key::k,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::SUPER_MASK,
    )
    .is_none());
}

#[test]
fn list_box_unrelated_keys_do_not_dispatch() {
    for keyval in [
        gdk::Key::a,
        gdk::Key::Return,
        gdk::Key::Escape,
        gdk::Key::Tab,
        gdk::Key::Home,
        gdk::Key::End,
        gdk::Key::Page_Up,
        gdk::Key::Page_Down,
        gdk::Key::space,
    ] {
        assert!(
            dispatch_list_box_nav(keyval, gdk::ModifierType::empty()).is_none(),
            "{keyval:?} must keep its `gtk::ListBox` default behavior",
        );
    }
}

// -- default_row_activation ----------------------------------

#[test]
fn totp_rows_always_copy_regardless_of_visible_code() {
    let id = fixture_id();
    assert!(matches!(
        default_row_activation(AccountKindSummary::Totp, true, id),
        AccountListOutput::CopyCode(out) if out == id,
    ));
    assert!(
        matches!(
            default_row_activation(AccountKindSummary::Totp, false, id),
            AccountListOutput::CopyCode(out) if out == id,
        ),
        "TOTP rows have an intrinsically derivable code, so copy is safe even when the live cache has not yet been populated",
    );
}

#[test]
fn hotp_rows_with_visible_code_copy() {
    let id = fixture_id();
    assert!(matches!(
        default_row_activation(AccountKindSummary::Hotp, true, id),
        AccountListOutput::CopyCode(out) if out == id,
    ));
}

#[test]
fn hotp_rows_without_visible_code_activate_advance_and_copy() {
    let id = fixture_id();
    assert!(matches!(
        default_row_activation(AccountKindSummary::Hotp, false, id),
        AccountListOutput::ActivateHotpAndCopy(out) if out == id,
    ));
}
