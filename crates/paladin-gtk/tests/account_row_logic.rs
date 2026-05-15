// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic `AccountRowComponent` tests for `paladin-gtk`.
//!
//! Tracks `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountRowComponent`:
//!
//! * Display label matches the CLI / TUI `<issuer>:<label>` body
//!   shape (with `Some("")` collapsing to the bare label).
//! * TOTP rows expose a progress indicator and never expose the
//!   "next" button; HOTP rows expose "next" and never expose
//!   progress.
//! * Copying a TOTP row is always enabled; copying a HOTP row is
//!   enabled only while a visible reveal `Code` is in hand.
//! * HOTP hidden rows show the stored `AccountSummary.counter`;
//!   during reveal, the row shows the `Code.counter_used` that
//!   produced the visible code. TOTP rows show no counter.
//! * `code_display` returns `Hidden` whenever the row has no
//!   visible code (HOTP before / after reveal) and `Visible(code)`
//!   otherwise.
//! * `project_row` bundles all four projections into a single
//!   widget-layer struct so the row factory does not call each
//!   helper individually and risk divergence.
//!
//! The module under test (`paladin_gtk::account_row`) is widget-free
//! and `(Vault, Store)`-free, so these tests run without spinning up
//! GTK / libadwaita and without constructing a real vault file.

use paladin_core::{AccountId, AccountKindSummary, AccountSummary, Algorithm, Code};

use paladin_gtk::account_row::{
    code_display, copy_enabled, counter_display, display_label, kebab_visible, next_button_visible,
    progress_visible, project_row, CodeDisplay, CounterText, RowDisplay,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn totp_summary(label: &str, issuer: Option<&str>) -> AccountSummary {
    AccountSummary {
        id: AccountId::new(),
        issuer: issuer.map(str::to_string),
        label: label.to_string(),
        kind: AccountKindSummary::Totp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: Some(30),
        counter: None,
        icon_hint: None,
        created_at: 0,
        updated_at: 0,
    }
}

fn hotp_summary(label: &str, issuer: Option<&str>, counter: u64) -> AccountSummary {
    AccountSummary {
        id: AccountId::new(),
        issuer: issuer.map(str::to_string),
        label: label.to_string(),
        kind: AccountKindSummary::Hotp,
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: None,
        counter: Some(counter),
        icon_hint: None,
        created_at: 0,
        updated_at: 0,
    }
}

fn totp_code(digits: &str, seconds_remaining: u32) -> Code {
    Code {
        code: digits.to_string(),
        valid_from: Some(0),
        valid_until: Some(30),
        seconds_remaining: Some(seconds_remaining),
        counter_used: None,
    }
}

fn hotp_code(digits: &str, counter_used: u64) -> Code {
    Code {
        code: digits.to_string(),
        valid_from: None,
        valid_until: None,
        seconds_remaining: None,
        counter_used: Some(counter_used),
    }
}

// ---------------------------------------------------------------------------
// `display_label` — CLI / TUI parity (issuer:label or bare label)
// ---------------------------------------------------------------------------

#[test]
fn display_label_renders_issuer_colon_label_when_issuer_set() {
    let s = totp_summary("alice", Some("Acme"));
    assert_eq!(display_label(&s), "Acme:alice");
}

#[test]
fn display_label_renders_bare_label_when_issuer_none() {
    let s = totp_summary("alice", None);
    assert_eq!(display_label(&s), "alice");
}

#[test]
fn display_label_collapses_empty_issuer_to_bare_label() {
    // `Some("")` must not render `":alice"` (parity with the
    // CLI / TUI / `remove_dialog::summary_display_label` rule).
    let s = totp_summary("alice", Some(""));
    assert_eq!(display_label(&s), "alice");
}

#[test]
fn display_label_handles_hotp_account_identically_to_totp() {
    let s = hotp_summary("bob", Some("Acme"), 7);
    assert_eq!(display_label(&s), "Acme:bob");
    let s = hotp_summary("bob", None, 7);
    assert_eq!(display_label(&s), "bob");
}

// ---------------------------------------------------------------------------
// `next_button_visible` — HOTP only
// ---------------------------------------------------------------------------

#[test]
fn next_button_visible_only_for_hotp() {
    assert!(!next_button_visible(AccountKindSummary::Totp));
    assert!(next_button_visible(AccountKindSummary::Hotp));
}

// ---------------------------------------------------------------------------
// `progress_visible` — TOTP only
// ---------------------------------------------------------------------------

#[test]
fn progress_visible_only_for_totp() {
    assert!(progress_visible(AccountKindSummary::Totp));
    assert!(!progress_visible(AccountKindSummary::Hotp));
}

// ---------------------------------------------------------------------------
// `kebab_visible` — always on (every row exposes the kebab menu)
// ---------------------------------------------------------------------------

#[test]
fn kebab_visible_always_on_for_totp_and_hotp() {
    // Every row in `AccountListComponent` exposes the kebab
    // `MenuButton` (Rename… / Remove…) per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `AccountRowComponent`. The projection returns `true`
    // unconditionally so the row factory can build the affordance
    // without branching on kind.
    assert!(kebab_visible(AccountKindSummary::Totp));
    assert!(kebab_visible(AccountKindSummary::Hotp));
}

// ---------------------------------------------------------------------------
// `copy_enabled` — TOTP always; HOTP only during reveal
// ---------------------------------------------------------------------------

#[test]
fn copy_enabled_totp_regardless_of_visible_code() {
    // TOTP rows always have a visible code computed externally; the
    // copy button is enabled regardless of whether the projection
    // sees the code yet (the widget reads it from its own slot).
    assert!(copy_enabled(AccountKindSummary::Totp, true));
    assert!(copy_enabled(AccountKindSummary::Totp, false));
}

#[test]
fn copy_enabled_hotp_only_with_visible_code() {
    // HOTP rows hide their code until the user activates "next" and
    // the reveal window is open; copying a hidden HOTP row is
    // explicitly disabled per `IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Component tree" > `AccountRowComponent`.
    assert!(!copy_enabled(AccountKindSummary::Hotp, false));
    assert!(copy_enabled(AccountKindSummary::Hotp, true));
}

// ---------------------------------------------------------------------------
// `counter_display` — HOTP stored vs used; TOTP None
// ---------------------------------------------------------------------------

#[test]
fn counter_display_totp_is_none_regardless_of_code() {
    let s = totp_summary("alice", Some("Acme"));
    assert_eq!(counter_display(&s, None), None);
    let code = totp_code("123456", 12);
    assert_eq!(counter_display(&s, Some(&code)), None);
}

#[test]
fn counter_display_hotp_hidden_shows_stored_next_counter() {
    let s = hotp_summary("bob", Some("Acme"), 7);
    assert_eq!(counter_display(&s, None), Some(CounterText::Stored(7)));
}

#[test]
fn counter_display_hotp_revealed_shows_counter_used() {
    let s = hotp_summary("bob", Some("Acme"), 8);
    // `counter_used = 7` even though `summary.counter = 8`: after
    // advancing from 7→8, the visible code is the one produced by
    // counter 7 and the stored next is 8. During reveal the row
    // tracks `counter_used`, not `summary.counter`.
    let code = hotp_code("123456", 7);
    assert_eq!(counter_display(&s, Some(&code)), Some(CounterText::Used(7)));
}

#[test]
fn counter_display_hotp_revealed_after_advance_tracks_new_counter_used() {
    let s = hotp_summary("bob", None, 9);
    // Activating "next" during an open reveal advances counter to 9
    // and the visible code is now the one produced by counter 8.
    let code = hotp_code("234567", 8);
    assert_eq!(counter_display(&s, Some(&code)), Some(CounterText::Used(8)));
}

#[test]
fn counter_display_hotp_with_summary_counter_zero_renders_stored_zero() {
    // Freshly imported HOTP accounts start at counter 0; the hidden
    // row must still show `Stored(0)` rather than collapse to None.
    let s = hotp_summary("bob", None, 0);
    assert_eq!(counter_display(&s, None), Some(CounterText::Stored(0)));
}

// ---------------------------------------------------------------------------
// `code_display` — Hidden vs Visible(code)
// ---------------------------------------------------------------------------

#[test]
fn code_display_hotp_without_visible_code_is_hidden() {
    let s = hotp_summary("bob", None, 0);
    assert_eq!(code_display(s.kind, None), CodeDisplay::Hidden);
}

#[test]
fn code_display_hotp_with_visible_code_is_visible() {
    let s = hotp_summary("bob", None, 1);
    let code = hotp_code("654321", 0);
    assert_eq!(
        code_display(s.kind, Some(&code)),
        CodeDisplay::Visible("654321".to_string())
    );
}

#[test]
fn code_display_totp_with_visible_code_is_visible() {
    let s = totp_summary("alice", Some("Acme"));
    let code = totp_code("111222", 18);
    assert_eq!(
        code_display(s.kind, Some(&code)),
        CodeDisplay::Visible("111222".to_string())
    );
}

#[test]
fn code_display_totp_without_visible_code_is_hidden_defensively() {
    // TOTP rows always have a code computed externally, but the
    // projection still answers `Hidden` defensively when the widget
    // has not yet seen the first compute.
    let s = totp_summary("alice", None);
    assert_eq!(code_display(s.kind, None), CodeDisplay::Hidden);
}

// ---------------------------------------------------------------------------
// `project_row` — bundles every projection together
// ---------------------------------------------------------------------------

#[test]
fn project_row_totp_with_visible_code() {
    let s = totp_summary("alice", Some("Acme"));
    let code = totp_code("111222", 18);
    let row = project_row(&s, Some(&code));
    let expected = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Visible("111222".to_string()),
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        kebab_visible: true,
    };
    assert_eq!(row, expected);
}

#[test]
fn project_row_hotp_hidden() {
    let s = hotp_summary("bob", None, 5);
    let row = project_row(&s, None);
    let expected = RowDisplay {
        label: "bob".to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Hidden,
        counter: Some(CounterText::Stored(5)),
        copy_enabled: false,
        next_button_visible: true,
        progress_visible: false,
        kebab_visible: true,
    };
    assert_eq!(row, expected);
}

#[test]
fn project_row_hotp_revealed() {
    let s = hotp_summary("bob", Some("Acme"), 6);
    let code = hotp_code("999000", 5);
    let row = project_row(&s, Some(&code));
    let expected = RowDisplay {
        label: "Acme:bob".to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Visible("999000".to_string()),
        counter: Some(CounterText::Used(5)),
        copy_enabled: true,
        next_button_visible: true,
        progress_visible: false,
        kebab_visible: true,
    };
    assert_eq!(row, expected);
}

#[test]
fn project_row_collapses_empty_issuer_to_bare_label() {
    let s = totp_summary("alice", Some(""));
    let code = totp_code("000111", 7);
    let row = project_row(&s, Some(&code));
    assert_eq!(row.label, "alice");
}
