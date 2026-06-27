// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic `AccountRowComponent` tests for `paladin-auth-gtk`.
//!
//! Tracks `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
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
//! The module under test (`paladin_auth_gtk::account_row`) is widget-free
//! and `(Vault, Store)`-free, so these tests run without spinning up
//! GTK / libadwaita and without constructing a real vault file.

use paladin_auth_core::{AccountId, AccountKindSummary, AccountSummary, Algorithm, Code};

use paladin_auth_gtk::account_row::{
    apply_busy_mask, code_display, copy_enabled, counter_display, format_seconds_remaining,
    kebab_enabled, kebab_visible, next_button_enabled, next_button_visible, progress_display,
    progress_fraction, progress_urgency, progress_visible, project_row, summary_display_label,
    CodeDisplay, CounterText, ProgressDisplay, ProgressUrgency, RowDisplay,
    PROGRESS_URGENCY_CSS_CLASSES,
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
// `summary_display_label` — CLI / TUI parity (issuer:label or bare label)
// ---------------------------------------------------------------------------

#[test]
fn summary_display_label_renders_issuer_colon_label_when_issuer_set() {
    let s = totp_summary("alice", Some("Acme"));
    assert_eq!(summary_display_label(&s), "Acme:alice");
}

#[test]
fn summary_display_label_renders_bare_label_when_issuer_none() {
    let s = totp_summary("alice", None);
    assert_eq!(summary_display_label(&s), "alice");
}

#[test]
fn summary_display_label_collapses_empty_issuer_to_bare_label() {
    // `Some("")` must not render `":alice"` (CLI / TUI parity;
    // the same rule applies to the re-export at
    // `remove_dialog::summary_display_label`).
    let s = totp_summary("alice", Some(""));
    assert_eq!(summary_display_label(&s), "alice");
}

#[test]
fn summary_display_label_handles_hotp_account_identically_to_totp() {
    let s = hotp_summary("bob", Some("Acme"), 7);
    assert_eq!(summary_display_label(&s), "Acme:bob");
    let s = hotp_summary("bob", None, 7);
    assert_eq!(summary_display_label(&s), "bob");
}

#[test]
fn summary_display_label_matches_remove_dialog_helper() {
    // Both modules must agree on the CLI / TUI body shape — the
    // row label rendered into the `gtk::ListView` factory and the
    // body rendered into `RemoveDialog`'s `AdwAlertDialog` should
    // never drift. `remove_dialog::summary_display_label` re-exports
    // the canonical helper from `account_row`, so calling either
    // module's name resolves to the same function.
    let s = totp_summary("alice", Some("Acme"));
    assert_eq!(
        summary_display_label(&s),
        paladin_auth_gtk::remove_dialog::summary_display_label(&s),
    );
    let s = totp_summary("alice", Some(""));
    assert_eq!(
        summary_display_label(&s),
        paladin_auth_gtk::remove_dialog::summary_display_label(&s),
    );
    let s = totp_summary("alice", None);
    assert_eq!(
        summary_display_label(&s),
        paladin_auth_gtk::remove_dialog::summary_display_label(&s),
    );
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
// `progress_display` — pure-logic gauge projection for the TOTP bar
// ---------------------------------------------------------------------------

#[test]
fn progress_display_hotp_is_none_regardless_of_code() {
    let s = hotp_summary("bob", None, 1);
    let code = hotp_code("123456", 1);
    assert_eq!(progress_display(&s, None), None);
    assert_eq!(progress_display(&s, Some(&code)), None);
}

#[test]
fn progress_display_totp_without_visible_code_is_none() {
    let s = totp_summary("alice", None);
    assert_eq!(progress_display(&s, None), None);
}

#[test]
fn progress_display_totp_with_visible_code_returns_period_and_remaining() {
    let s = totp_summary("alice", Some("Acme"));
    let code = totp_code("111222", 12);
    assert_eq!(
        progress_display(&s, Some(&code)),
        Some(ProgressDisplay {
            period_secs: 30,
            seconds_remaining: 12,
        })
    );
}

// ---------------------------------------------------------------------------
// `progress_fraction` — widget-bind fraction from a ProgressDisplay
// ---------------------------------------------------------------------------

#[test]
fn progress_fraction_full_period_returns_one() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 30,
    };
    assert!((progress_fraction(&p) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn progress_fraction_zero_seconds_remaining_returns_zero() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 0,
    };
    assert!(progress_fraction(&p).abs() < f64::EPSILON);
}

#[test]
fn progress_fraction_partial_window_returns_seconds_over_period() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 18,
    };
    let expected = 18.0_f64 / 30.0_f64;
    assert!((progress_fraction(&p) - expected).abs() < f64::EPSILON);
}

#[test]
fn progress_fraction_clamps_overflow_to_one() {
    // Defensive: paladin_auth_core invariant pins seconds_remaining to
    // 1..=period, but the widget binding should still saturate
    // rather than feed a >1.0 fraction into gtk::ProgressBar.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 60,
    };
    assert!((progress_fraction(&p) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn progress_fraction_zero_period_returns_zero_defensively() {
    let p = ProgressDisplay {
        period_secs: 0,
        seconds_remaining: 5,
    };
    assert!(progress_fraction(&p).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// `format_seconds_remaining` — the `Ns` suffix rendered right of the
// `gtk::ProgressBar` in the Time column, mirroring the TUI gauge +
// countdown layout.
// ---------------------------------------------------------------------------

#[test]
fn format_seconds_remaining_full_period() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 30,
    };
    assert_eq!(format_seconds_remaining(&p), "30s");
}

#[test]
fn format_seconds_remaining_partial_window() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 18,
    };
    assert_eq!(format_seconds_remaining(&p), "18s");
}

#[test]
fn format_seconds_remaining_single_digit_keeps_no_padding() {
    // Layout stability comes from the gtk::Label's width_chars(3)
    // + xalign(1.0), not from leading whitespace in the string.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 1,
    };
    assert_eq!(format_seconds_remaining(&p), "1s");
}

#[test]
fn format_seconds_remaining_clamps_overflow_to_period() {
    // Defensive: paladin_auth_core pins seconds_remaining to 1..=period,
    // but the widget binding should still saturate rather than
    // surface a value greater than period_secs to the user.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 60,
    };
    assert_eq!(format_seconds_remaining(&p), "30s");
}

// ---------------------------------------------------------------------------
// `progress_urgency` — TOTP gauge color band (`Plenty` / `Warning` / `Critical`)
// ---------------------------------------------------------------------------

#[test]
fn progress_urgency_full_window_is_plenty() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 30,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Plenty);
}

#[test]
fn progress_urgency_just_above_plenty_threshold_is_plenty() {
    // 16s remaining → still green.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 16,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Plenty);
}

#[test]
fn progress_urgency_at_plenty_threshold_flips_to_warning() {
    // 15s remaining → yellow.  "Green until 15 seconds remaining"
    // means the instant the bar shows 15, the user has flipped into
    // the warning band.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 15,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Warning);
}

#[test]
fn progress_urgency_just_above_critical_threshold_is_warning() {
    // 6s remaining → still yellow.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 6,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Warning);
}

#[test]
fn progress_urgency_at_critical_threshold_flips_to_critical() {
    // 5s remaining → red.  "Yellow until 5 seconds remaining"
    // means the instant the bar shows 5, the user has flipped into
    // the critical band.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 5,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Critical);
}

#[test]
fn progress_urgency_one_second_remaining_is_critical() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 1,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Critical);
}

#[test]
fn progress_urgency_zero_seconds_remaining_is_critical() {
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 0,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Critical);
}

#[test]
fn progress_urgency_clamps_overflow_to_period_then_classifies() {
    // `paladin_auth_core` pins seconds_remaining to `1..=period`, but the
    // helper clamps defensively — a >period value still classifies
    // by the clamped count, not the raw input.
    let p = ProgressDisplay {
        period_secs: 30,
        seconds_remaining: 999,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Plenty);
}

#[test]
fn progress_urgency_zero_period_is_critical_defensively() {
    // `paladin_auth_core::validation` rejects a zero period upstream;
    // the helper still returns a total result rather than panicking.
    let p = ProgressDisplay {
        period_secs: 0,
        seconds_remaining: 30,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Critical);
}

#[test]
fn progress_urgency_short_period_lands_in_matching_band() {
    // Short-period TOTP (rare but legal): a 10s period with 10s
    // remaining is fully fresh but still within the warning band,
    // because urgency is absolute seconds — the user-visible meaning
    // is "how much time you have to read + copy."
    let p = ProgressDisplay {
        period_secs: 10,
        seconds_remaining: 10,
    };
    assert_eq!(progress_urgency(&p), ProgressUrgency::Warning);
}

#[test]
fn progress_urgency_css_class_matches_canonical_slice() {
    // The `bind_row` "wipe all three, add the active one" pattern
    // relies on every urgency's class living in
    // `PROGRESS_URGENCY_CSS_CLASSES`.
    for urgency in [
        ProgressUrgency::Plenty,
        ProgressUrgency::Warning,
        ProgressUrgency::Critical,
    ] {
        assert!(
            PROGRESS_URGENCY_CSS_CLASSES.contains(&urgency.css_class()),
            "{urgency:?} css_class missing from PROGRESS_URGENCY_CSS_CLASSES",
        );
    }
}

#[test]
fn progress_urgency_css_classes_are_adwaita_semantics() {
    // Locks the three Adwaita semantic style classes the bind layer
    // toggles — these names must match Adwaita so the bar tracks the
    // user's theme rather than baking hex colors.
    assert_eq!(ProgressUrgency::Plenty.css_class(), "success");
    assert_eq!(ProgressUrgency::Warning.css_class(), "warning");
    assert_eq!(ProgressUrgency::Critical.css_class(), "error");
}

// ---------------------------------------------------------------------------
// `kebab_visible` — always on (every row exposes the kebab menu)
// ---------------------------------------------------------------------------

#[test]
fn kebab_visible_always_on_for_totp_and_hotp() {
    // Every row in `AccountListComponent` exposes the kebab
    // `MenuButton` (Rename… / Remove…) per
    // `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `AccountRowComponent`. The projection returns `true`
    // unconditionally so the row factory can build the affordance
    // without branching on kind.
    assert!(kebab_visible(AccountKindSummary::Totp));
    assert!(kebab_visible(AccountKindSummary::Hotp));
}

// ---------------------------------------------------------------------------
// `next_button_enabled` — intrinsic clickability; mirrors visibility (HOTP only)
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
// `AccountRowComponent`, the "next" button is rendered only on HOTP rows.
// The intrinsic-enabled projection mirrors that visibility — the widget
// layer feeds it into `gtk::Button::set_sensitive` and the per-component
// busy mask (see [`apply_busy_mask`]) flips it to `false` while
// `AppModel` is `UnlockedBusy` per §"In-flight effect ownership".
// ---------------------------------------------------------------------------

#[test]
fn next_button_enabled_only_for_hotp() {
    assert!(!next_button_enabled(AccountKindSummary::Totp));
    assert!(next_button_enabled(AccountKindSummary::Hotp));
}

// ---------------------------------------------------------------------------
// `kebab_enabled` — always on (every row exposes the kebab menu)
//
// Intrinsic clickability of the row kebab menu. Always `true` for parity
// with [`kebab_visible`]; the per-component busy mask flips it to `false`
// while `AppModel` is `UnlockedBusy`.
// ---------------------------------------------------------------------------

#[test]
fn kebab_enabled_always_on() {
    assert!(kebab_enabled());
}

// ---------------------------------------------------------------------------
// `apply_busy_mask` — clamp mutating-row affordances during `UnlockedBusy`
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"In-flight effect ownership" /
// §"Component tree" > `AccountRowComponent` ("Disable mutating row
// controls (copy, 'next', kebab) while `AppModel` is `UnlockedBusy`"),
// the row factory threads the current `AppState::is_busy()` flag through
// this mask before binding the row's widgets. When `busy == true`, the
// three mutating-affordance enabled flags collapse to `false`; visibility
// and the progress / counter projections are untouched so the row keeps
// rendering the code and gauge while the worker is in flight.
// ---------------------------------------------------------------------------

#[test]
fn apply_busy_mask_busy_true_clears_all_three_enabled_flags() {
    let s = hotp_summary("bob", Some("Acme"), 6);
    let code = hotp_code("999000", 5);
    let mut row = project_row(&s, Some(&code), None);
    apply_busy_mask(&mut row, true);
    assert!(!row.copy_enabled);
    assert!(!row.next_button_enabled);
    assert!(!row.kebab_enabled);
}

#[test]
fn apply_busy_mask_busy_false_is_noop() {
    let s = hotp_summary("bob", Some("Acme"), 6);
    let code = hotp_code("999000", 5);
    let row = project_row(&s, Some(&code), None);
    let mut masked = row.clone();
    apply_busy_mask(&mut masked, false);
    assert_eq!(masked, row);
}

#[test]
fn apply_busy_mask_preserves_visibility_and_progress() {
    // Busy must dim the controls without hiding them or wiping the
    // visible code / progress fields — the row keeps rendering while
    // the worker is in flight so the user sees what's still on screen.
    let s = totp_summary("alice", Some("Acme"));
    let code = totp_code("111222", 18);
    let original = project_row(&s, Some(&code), None);
    let mut masked = original.clone();
    apply_busy_mask(&mut masked, true);
    assert_eq!(masked.label, original.label);
    assert_eq!(masked.kind, original.kind);
    assert_eq!(masked.code, original.code);
    assert_eq!(masked.counter, original.counter);
    assert_eq!(masked.next_button_visible, original.next_button_visible);
    assert_eq!(masked.progress_visible, original.progress_visible);
    assert_eq!(masked.progress, original.progress);
    assert_eq!(masked.kebab_visible, original.kebab_visible);
}

#[test]
fn apply_busy_mask_busy_true_dims_totp_kebab_too() {
    // TOTP rows have `next_button_enabled = false` intrinsically, but
    // their kebab + copy controls must still be dimmed while busy.
    let s = totp_summary("alice", Some("Acme"));
    let code = totp_code("111222", 18);
    let mut row = project_row(&s, Some(&code), None);
    apply_busy_mask(&mut row, true);
    assert!(!row.copy_enabled);
    assert!(!row.next_button_enabled);
    assert!(!row.kebab_enabled);
}

#[test]
fn apply_busy_mask_busy_true_dims_hidden_hotp_row() {
    // Hidden HOTP rows already have `copy_enabled = false`; busy still
    // forces `next_button_enabled = false` and `kebab_enabled = false`.
    let s = hotp_summary("bob", None, 0);
    let mut row = project_row(&s, None, None);
    apply_busy_mask(&mut row, true);
    assert!(!row.copy_enabled);
    assert!(!row.next_button_enabled);
    assert!(!row.kebab_enabled);
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
    // explicitly disabled per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
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
// `next_code_display` — `Vault::totp_next_code` → `RowDisplay::next_code`
// ---------------------------------------------------------------------------

#[test]
fn next_code_display_totp_with_some_returns_raw_digits() {
    // TOTP + Some(code) ⇒ Some(code.code.clone()).  Stored raw —
    // the cell factory in `column_view.rs` applies the `↪ ` prefix
    // and the `numeric dim-label` styling.
    use paladin_auth_gtk::account_row::next_code_display;
    let code = totp_code("987654", 12);
    assert_eq!(
        next_code_display(AccountKindSummary::Totp, Some(&code)),
        Some("987654".to_string()),
    );
}

#[test]
fn next_code_display_totp_with_none_returns_none() {
    // Before the first `Vault::totp_next_code` lands the projection
    // answers `None`; the cell factory then renders an empty string.
    use paladin_auth_gtk::account_row::next_code_display;
    assert_eq!(next_code_display(AccountKindSummary::Totp, None), None);
}

#[test]
fn next_code_display_hotp_with_any_input_returns_none() {
    // HOTP rows never carry an "upcoming" code — even if a caller
    // passes a populated `Code` (e.g. the live reveal cache), the
    // projection answers `None` so the Next cell stays empty and
    // inert per the §"Next-code column implementation" visibility
    // contract.
    use paladin_auth_gtk::account_row::next_code_display;
    let hotp = hotp_code("000001", 1);
    assert_eq!(next_code_display(AccountKindSummary::Hotp, None), None);
    assert_eq!(
        next_code_display(AccountKindSummary::Hotp, Some(&hotp)),
        None
    );
}

#[test]
fn project_row_totp_passes_next_code_through_to_row_display() {
    // Pin the contract that the new third parameter to `project_row`
    // routes through to `RowDisplay::next_code` rather than being
    // silently dropped; covers the wiring the ticker depends on
    // when populating the Next column.
    let s = totp_summary("alice", Some("Acme"));
    let current = totp_code("111222", 18);
    let upcoming = totp_code("333444", 30);
    let row = project_row(&s, Some(&current), Some(&upcoming));
    assert_eq!(row.next_code, Some("333444".to_string()));
}

#[test]
fn project_row_hotp_drops_next_code_input() {
    // HOTP `project_row` must `None` out the next-code projection
    // even when a caller accidentally passes `Some(_)` (defensive —
    // mirrors `next_code_display_hotp_with_any_input_returns_none`).
    let s = hotp_summary("bob", Some("Acme"), 7);
    let visible = hotp_code("999888", 7);
    let upcoming = totp_code("000111", 30);
    let row = project_row(&s, Some(&visible), Some(&upcoming));
    assert_eq!(row.next_code, None);
}

// ---------------------------------------------------------------------------
// `project_row` — bundles every projection together
// ---------------------------------------------------------------------------

#[test]
fn project_row_totp_with_visible_code() {
    let s = totp_summary("alice", Some("Acme"));
    let code = totp_code("111222", 18);
    let row = project_row(&s, Some(&code), None);
    let expected = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Visible("111222".to_string()),
        next_code: None,
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        next_button_enabled: false,
        progress_visible: true,
        progress: Some(ProgressDisplay {
            period_secs: 30,
            seconds_remaining: 18,
        }),
        kebab_visible: true,
        kebab_enabled: true,
    };
    assert_eq!(row, expected);
}

#[test]
fn project_row_hotp_hidden() {
    let s = hotp_summary("bob", None, 5);
    let row = project_row(&s, None, None);
    let expected = RowDisplay {
        label: "bob".to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Hidden,
        next_code: None,
        counter: Some(CounterText::Stored(5)),
        copy_enabled: false,
        next_button_visible: true,
        next_button_enabled: true,
        progress_visible: false,
        progress: None,
        kebab_visible: true,
        kebab_enabled: true,
    };
    assert_eq!(row, expected);
}

#[test]
fn project_row_hotp_revealed() {
    let s = hotp_summary("bob", Some("Acme"), 6);
    let code = hotp_code("999000", 5);
    let row = project_row(&s, Some(&code), None);
    let expected = RowDisplay {
        label: "Acme:bob".to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Visible("999000".to_string()),
        next_code: None,
        counter: Some(CounterText::Used(5)),
        copy_enabled: true,
        next_button_visible: true,
        next_button_enabled: true,
        progress_visible: false,
        progress: None,
        kebab_visible: true,
        kebab_enabled: true,
    };
    assert_eq!(row, expected);
}

#[test]
fn project_row_collapses_empty_issuer_to_bare_label() {
    let s = totp_summary("alice", Some(""));
    let code = totp_code("000111", 7);
    let row = project_row(&s, Some(&code), None);
    assert_eq!(row.label, "alice");
}

// ---------------------------------------------------------------------------
// AccountRowOutput dispatch surface (consumed by ColumnView cell factories)
// ---------------------------------------------------------------------------
//
// Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` Appendix A §A.8, the
// per-row widget tree lives in the `gtk::SignalListItemFactory`
// builders in `crate::column_view`; this module no longer ships a
// `FactoryComponent`. The [`AccountRowOutput`] enum + the
// `dispatch_row_action` action-name table survive because the
// kebab `gio::SimpleActionGroup` installed by
// `build_kebab_action_group` in `column_view.rs` consumes them.

#[test]
fn account_row_output_request_edit_carries_account_id() {
    use paladin_auth_gtk::account_row::AccountRowOutput;

    let id = AccountId::new();
    let output = AccountRowOutput::RequestEdit(id);
    match output {
        AccountRowOutput::RequestEdit(carried) => assert_eq!(carried, id),
        AccountRowOutput::RequestExportQr(_)
        | AccountRowOutput::RequestRemove(_)
        | AccountRowOutput::RequestCopy(_)
        | AccountRowOutput::RequestAdvance(_) => panic!("expected RequestEdit({id:?})"),
    }
}

#[test]
fn account_row_output_request_export_qr_carries_account_id() {
    use paladin_auth_gtk::account_row::AccountRowOutput;

    let id = AccountId::new();
    let output = AccountRowOutput::RequestExportQr(id);
    match output {
        AccountRowOutput::RequestExportQr(carried) => assert_eq!(carried, id),
        AccountRowOutput::RequestEdit(_)
        | AccountRowOutput::RequestRemove(_)
        | AccountRowOutput::RequestCopy(_)
        | AccountRowOutput::RequestAdvance(_) => panic!("expected RequestExportQr({id:?})"),
    }
}

#[test]
fn account_row_output_request_remove_carries_account_id() {
    use paladin_auth_gtk::account_row::AccountRowOutput;

    let id = AccountId::new();
    let output = AccountRowOutput::RequestRemove(id);
    match output {
        AccountRowOutput::RequestRemove(carried) => assert_eq!(carried, id),
        AccountRowOutput::RequestEdit(_)
        | AccountRowOutput::RequestExportQr(_)
        | AccountRowOutput::RequestCopy(_)
        | AccountRowOutput::RequestAdvance(_) => panic!("expected RequestRemove({id:?})"),
    }
}

#[test]
fn account_row_output_request_copy_carries_account_id() {
    use paladin_auth_gtk::account_row::AccountRowOutput;

    let id = AccountId::new();
    let output = AccountRowOutput::RequestCopy(id);
    match output {
        AccountRowOutput::RequestCopy(carried) => assert_eq!(carried, id),
        AccountRowOutput::RequestEdit(_)
        | AccountRowOutput::RequestExportQr(_)
        | AccountRowOutput::RequestRemove(_)
        | AccountRowOutput::RequestAdvance(_) => panic!("expected RequestCopy({id:?})"),
    }
}

#[test]
fn account_row_output_request_advance_carries_account_id() {
    use paladin_auth_gtk::account_row::AccountRowOutput;

    let id = AccountId::new();
    let output = AccountRowOutput::RequestAdvance(id);
    match output {
        AccountRowOutput::RequestAdvance(carried) => assert_eq!(carried, id),
        AccountRowOutput::RequestEdit(_)
        | AccountRowOutput::RequestExportQr(_)
        | AccountRowOutput::RequestRemove(_)
        | AccountRowOutput::RequestCopy(_) => panic!("expected RequestAdvance({id:?})"),
    }
}

// ---------------------------------------------------------------------------
// Row widget construction lives in the per-column
// `gtk::SignalListItemFactory` builders in
// `paladin_auth_gtk::column_view`. These compile-only assertions pin
// those builders' public surface — a silent move back to
// `account_row.rs` surfaces as a hard-error import drift rather
// than as an undetected re-shuffle of widget ownership.
// ---------------------------------------------------------------------------

#[test]
fn column_view_cell_factory_builders_are_exposed() {
    use paladin_auth_gtk::account_list::AccountListOutput;
    use paladin_auth_gtk::column_view::RowPopoverSlot;
    use relm4::gtk;
    use relm4::Sender;

    // The "Account" factory gained a sender + shared popover slot in
    // Milestone 9 slice 5 so it can install the row-body right-click /
    // keyboard context-menu surface and enforce the single-popover
    // invariant.
    let _: fn(Sender<AccountListOutput>, RowPopoverSlot) -> gtk::SignalListItemFactory =
        paladin_auth_gtk::column_view::build_account_column_factory;
    let _: fn() -> gtk::SignalListItemFactory =
        paladin_auth_gtk::column_view::build_time_column_factory;
    let _: fn(Sender<AccountListOutput>) -> gtk::SignalListItemFactory =
        paladin_auth_gtk::column_view::build_code_column_factory;
    let _: fn(Sender<AccountListOutput>) -> gtk::SignalListItemFactory =
        paladin_auth_gtk::column_view::build_copy_column_factory;
    let _: fn(Sender<AccountListOutput>) -> gtk::SignalListItemFactory =
        paladin_auth_gtk::column_view::build_kebab_column_factory;
}
