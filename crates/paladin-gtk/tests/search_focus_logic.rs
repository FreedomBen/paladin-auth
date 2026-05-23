// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for `app::model::dispatch_app_window_search_focus_key`,
//! the keyval / modifier dispatch table behind the window-level
//! `/` and `Ctrl+L` accelerator that focuses the
//! `AccountListComponent`'s `gtk::SearchBar`.
//!
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Keyboard Shortcuts" pins the
//! type-to-search and focus-search wiring: any printable keypress
//! on the toplevel window reveals the bar via
//! `gtk::SearchBar::set_key_capture_widget`, and the dedicated
//! `/` / `Ctrl+L` accelerators additionally grab focus on the
//! `gtk::SearchEntry` without inserting the keystroke into the
//! entry's text buffer. `Ctrl+K` is intentionally absent here: it
//! doubles as the vim-style "move up" mirror for the account list
//! and is handled by `account_list::dispatch_list_box_nav`, so the
//! window-level dispatcher must return `None` for it. These tests
//! exercise the dispatch table directly so the assertions run
//! without a display server.

use paladin_gtk::app::model::{dispatch_app_window_search_focus_key, AppMsg};
use relm4::gtk::gdk;

#[test]
fn slash_without_modifier_dispatches_focus_search() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::slash, gdk::ModifierType::empty());
    assert!(matches!(msg, Some(AppMsg::FocusSearch)));
}

#[test]
fn slash_with_shift_modifier_still_dispatches_focus_search() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::slash, gdk::ModifierType::SHIFT_MASK);
    assert!(
        matches!(msg, Some(AppMsg::FocusSearch)),
        "Shift+/ (the keyboard combination producing `/` on layouts like German) must still match",
    );
}

#[test]
fn slash_with_control_modifier_does_not_dispatch() {
    let msg =
        dispatch_app_window_search_focus_key(gdk::Key::slash, gdk::ModifierType::CONTROL_MASK);
    assert!(
        msg.is_none(),
        "Ctrl+/ is a different conventional shortcut; do not steal it",
    );
}

#[test]
fn slash_with_alt_modifier_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::slash, gdk::ModifierType::ALT_MASK);
    assert!(msg.is_none(), "Alt+/ must not trigger the focus shortcut");
}

#[test]
fn lowercase_k_with_control_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::k, gdk::ModifierType::CONTROL_MASK);
    assert!(
        msg.is_none(),
        "Ctrl+K must NOT focus search — it is the vim-style \"move up\" mirror for the account list",
    );
}

#[test]
fn uppercase_k_with_control_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::K, gdk::ModifierType::CONTROL_MASK);
    assert!(
        msg.is_none(),
        "Ctrl+Shift+K (uppercase keyval) must NOT focus search either",
    );
}

#[test]
fn lowercase_k_without_control_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::k, gdk::ModifierType::empty());
    assert!(
        msg.is_none(),
        "bare `k` must not steal the typing-to-search path",
    );
}

#[test]
fn control_plus_k_with_alt_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(
        gdk::Key::k,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    );
    assert!(
        msg.is_none(),
        "Ctrl+Alt+K is a different compound chord; do not steal it",
    );
}

#[test]
fn lowercase_l_with_control_dispatches_focus_search() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::l, gdk::ModifierType::CONTROL_MASK);
    assert!(matches!(msg, Some(AppMsg::FocusSearch)));
}

#[test]
fn uppercase_l_with_control_dispatches_focus_search() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::L, gdk::ModifierType::CONTROL_MASK);
    assert!(
        matches!(msg, Some(AppMsg::FocusSearch)),
        "Ctrl+Shift+L (which delivers the uppercase keyval) must also match",
    );
}

#[test]
fn lowercase_l_without_control_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::l, gdk::ModifierType::empty());
    assert!(
        msg.is_none(),
        "bare `l` must not steal the typing-to-search path",
    );
}

#[test]
fn control_plus_l_with_alt_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(
        gdk::Key::l,
        gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::ALT_MASK,
    );
    assert!(
        msg.is_none(),
        "Ctrl+Alt+L is a different compound chord; do not steal it",
    );
}

#[test]
fn unrelated_keys_do_not_dispatch() {
    for keyval in [
        gdk::Key::a,
        gdk::Key::Return,
        gdk::Key::Escape,
        gdk::Key::space,
        gdk::Key::Tab,
    ] {
        assert!(
            dispatch_app_window_search_focus_key(keyval, gdk::ModifierType::empty()).is_none(),
            "{keyval:?} must not trigger the focus shortcut",
        );
        assert!(
            dispatch_app_window_search_focus_key(keyval, gdk::ModifierType::CONTROL_MASK).is_none(),
            "Ctrl+{keyval:?} must not trigger the focus shortcut",
        );
    }
}

#[test]
fn slash_with_super_modifier_does_not_dispatch() {
    let msg = dispatch_app_window_search_focus_key(gdk::Key::slash, gdk::ModifierType::SUPER_MASK);
    assert!(msg.is_none());
}
