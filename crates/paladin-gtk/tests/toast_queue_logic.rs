// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic tests for `paladin_gtk::toast_queue::ToastQueue`.
//!
//! Pins the newest-wins / minimum-visible-window dispatch table the
//! `AppModel` consumes via `AppModel::show_toast` /
//! `AppModel::commit_toast` / the
//! `AppMsg::ToastMinVisibleElapsed` arm. The GTK side owns the live
//! `adw::Toast` reference and the `glib::timeout_add_local_once`
//! source; the queue only answers "commit now vs stash" and "drain
//! the pending body".

use std::time::Duration;

use paladin_gtk::toast_queue::{ShowAction, ToastQueue, TOAST_MIN_VISIBLE};

#[test]
fn min_visible_is_one_second() {
    assert_eq!(
        TOAST_MIN_VISIBLE,
        Duration::from_millis(1000),
        "the constant the `AppModel` schedules its one-shot against \
         must stay locked to 1s — both the model wiring and the user \
         contract assume this exact figure"
    );
}

#[test]
fn first_show_commits_and_opens_window() {
    let mut q = ToastQueue::new();
    assert_eq!(q.on_show(String::from("first")), ShowAction::Commit);
    assert!(q.min_visible_active());
    assert_eq!(q.pending(), None);
}

#[test]
fn show_within_window_defers_and_stashes() {
    let mut q = ToastQueue::new();
    let _ = q.on_show(String::from("first"));
    assert_eq!(q.on_show(String::from("second")), ShowAction::Defer);
    assert!(q.min_visible_active());
    assert_eq!(q.pending(), Some("second"));
}

#[test]
fn newest_pending_wins_on_repeat_defer() {
    let mut q = ToastQueue::new();
    let _ = q.on_show(String::from("first"));
    let _ = q.on_show(String::from("second"));
    let _ = q.on_show(String::from("third"));
    assert_eq!(
        q.pending(),
        Some("third"),
        "the newest body must overwrite the previously-deferred one \
         so the user sees the latest action's outcome, not an \
         intermediate banner"
    );
}

#[test]
fn elapsed_with_empty_pending_drops_to_idle() {
    let mut q = ToastQueue::new();
    let _ = q.on_show(String::from("first"));
    assert_eq!(q.on_min_visible_elapsed(), None);
    assert!(!q.min_visible_active());
    assert_eq!(q.pending(), None);
}

#[test]
fn elapsed_with_pending_drains_and_reopens_window() {
    let mut q = ToastQueue::new();
    let _ = q.on_show(String::from("first"));
    let _ = q.on_show(String::from("second"));
    assert_eq!(
        q.on_min_visible_elapsed(),
        Some(String::from("second")),
        "the queued body must surface for the imperative side to commit"
    );
    assert!(
        q.min_visible_active(),
        "draining the pending body must open a new min-visible window \
         so a third back-to-back show is itself deferred"
    );
    assert_eq!(q.pending(), None);
}

#[test]
fn show_after_idle_commits_again() {
    let mut q = ToastQueue::new();
    let _ = q.on_show(String::from("first"));
    let _ = q.on_min_visible_elapsed();
    assert_eq!(
        q.on_show(String::from("second")),
        ShowAction::Commit,
        "once the min-visible window has closed and the queue is \
         idle, the next show must commit immediately rather than \
         buffer"
    );
    assert!(q.min_visible_active());
    assert_eq!(q.pending(), None);
}

#[test]
fn three_back_to_back_collapse_to_newest_then_idle() {
    let mut q = ToastQueue::new();
    assert_eq!(q.on_show(String::from("a")), ShowAction::Commit);
    assert_eq!(q.on_show(String::from("b")), ShowAction::Defer);
    assert_eq!(q.on_show(String::from("c")), ShowAction::Defer);
    assert_eq!(q.on_min_visible_elapsed(), Some(String::from("c")));
    assert_eq!(q.on_min_visible_elapsed(), None);
    assert!(!q.min_visible_active());
}

#[test]
fn full_sequence_alternating_show_and_elapse() {
    let mut q = ToastQueue::new();
    assert_eq!(q.on_show(String::from("a")), ShowAction::Commit);
    assert_eq!(q.on_min_visible_elapsed(), None);
    assert_eq!(q.on_show(String::from("b")), ShowAction::Commit);
    assert_eq!(q.on_show(String::from("c")), ShowAction::Defer);
    assert_eq!(q.on_min_visible_elapsed(), Some(String::from("c")));
    assert_eq!(q.on_show(String::from("d")), ShowAction::Defer);
    assert_eq!(q.on_show(String::from("e")), ShowAction::Defer);
    assert_eq!(q.on_min_visible_elapsed(), Some(String::from("e")));
    assert_eq!(q.on_min_visible_elapsed(), None);
}
