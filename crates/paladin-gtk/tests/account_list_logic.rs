// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pure-logic coverage for `account_list::row_models_from_vault` and
//! the shared `account_list::format_rendered_marker` helper.
//!
//! `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
//! `AccountListComponent` pins the row factory to a `gio::ListStore`
//! built from `paladin_core::AccountSummary` projections — the
//! widget layer never touches secret bytes. These tests exercise
//! the projection layer directly so the assertions run without a
//! display server (the parallel `tests/gtk_smoke.rs` covers the same
//! path end-to-end under `xvfb-run` in CI).
//!
//! The `format_rendered_marker` helper is the source of truth for
//! the stdout marker `paladin-gtk` emits under `--exit-after-startup`
//! once the `AccountListComponent` has been bound. The smoke test in
//! `tests/gtk_smoke.rs` greps for that line, so the string format is
//! locked here.

use std::path::Path;
use std::time::SystemTime;

use secrecy::SecretString;

use paladin_core::{
    validate_manual, AccountId, AccountInput, AccountKindInput, AccountKindSummary, Algorithm,
    IconHintInput, Store, Vault, VaultInit, VaultLock,
};
use paladin_gtk::account_list::{
    format_rendered_marker, format_widget_states_marker, hidden_row_display, row_models_from_vault,
    AccountRowModel, ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX,
};
use paladin_gtk::account_row::{CodeDisplay, CounterText, RowDisplay};

// --- fixtures ----------------------------------------------------------------

fn secure_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir 0700");
    }
    dir
}

fn open_plaintext_pair(path: &Path) -> (Vault, Store) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create plaintext");
    vault.save(&store).expect("commit empty vault");
    drop(vault);
    drop(store);
    Store::open(path, VaultLock::Plaintext).expect("reopen plaintext")
}

fn add_totp(vault: &mut Vault, store: &Store, issuer: Option<&str>, label: &str) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

fn add_hotp(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
    counter: u64,
) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Hotp,
        period_secs: None,
        counter: Some(counter),
        icon_hint: IconHintInput::Default,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

// ---------------------------------------------------------------------------
// `row_models_from_vault`
// ---------------------------------------------------------------------------

#[test]
fn row_models_empty_vault_is_empty() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = open_plaintext_pair(&path);

    let rows = row_models_from_vault(&vault);
    assert!(
        rows.is_empty(),
        "an empty vault projects no rows, got: {rows:?}",
    );
}

#[test]
fn row_models_preserves_insertion_order() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let b = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let c = add_totp(&mut vault, &store, None, "solo");

    let rows = row_models_from_vault(&vault);
    let ids: Vec<AccountId> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![a, b, c],
        "row projection must follow Vault::summaries() insertion order",
    );
}

#[test]
fn row_models_carry_summary_and_label() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_hotp(&mut vault, &store, None, "solo", 7);

    let rows = row_models_from_vault(&vault);
    assert_eq!(rows.len(), 2);

    assert_eq!(rows[0].kind, AccountKindSummary::Totp);
    assert_eq!(rows[0].display_label, "GitHub:ben");

    assert_eq!(rows[1].kind, AccountKindSummary::Hotp);
    assert_eq!(rows[1].display_label, "solo");
    assert_eq!(rows[1].counter, Some(7));
}

#[test]
fn row_models_drop_empty_issuer_in_display_label() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    // Issuer-only-empty must collapse to the bare label so the row
    // never carries a dangling `:label` colon (parity with
    // `account_row::display_label` and `remove_dialog::summary_display_label`).
    add_totp(&mut vault, &store, Some(""), "alice");

    let rows = row_models_from_vault(&vault);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].display_label, "alice");
}

// ---------------------------------------------------------------------------
// `format_rendered_marker`
// ---------------------------------------------------------------------------

#[test]
fn marker_empty_list_emits_empty_suffix() {
    let rendered: Vec<AccountRowModel> = Vec::new();
    assert_eq!(
        format_rendered_marker(&rendered),
        "paladin-gtk: account_list_rows="
    );
}

#[test]
fn marker_pipe_joins_display_labels_in_order() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_totp(&mut vault, &store, Some("GitLab"), "alice");
    add_hotp(&mut vault, &store, None, "solo", 0);

    let rows = row_models_from_vault(&vault);
    assert_eq!(
        format_rendered_marker(&rows),
        "paladin-gtk: account_list_rows=GitHub:ben|GitLab:alice|solo",
    );
}

// ---------------------------------------------------------------------------
// `hidden_row_display` — projects an `AccountRowModel` onto the initial
// (no-visible-code) `RowDisplay` the row factory binds at mount time.
//
// The widget layer holds no live `Code` before the first per-tick TOTP
// compute and never before "next" for HOTP, so the row factory binds
// every row through this helper. Pairing the helper with
// `account_row::project_row` keeps the hidden / revealed projections in
// one place — any drift would surface here under TDD.
// ---------------------------------------------------------------------------

#[test]
fn hidden_row_display_totp_renders_hidden_code_and_no_counter() {
    let model = AccountRowModel {
        id: AccountId::new(),
        display_label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
    };
    let expected = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Hidden,
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        kebab_visible: true,
    };
    assert_eq!(hidden_row_display(&model), expected);
}

#[test]
fn hidden_row_display_hotp_renders_stored_counter_and_disabled_copy() {
    let model = AccountRowModel {
        id: AccountId::new(),
        display_label: "solo".to_string(),
        kind: AccountKindSummary::Hotp,
        counter: Some(7),
    };
    let expected = RowDisplay {
        label: "solo".to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Hidden,
        counter: Some(CounterText::Stored(7)),
        copy_enabled: false,
        next_button_visible: true,
        progress_visible: false,
        kebab_visible: true,
    };
    assert_eq!(hidden_row_display(&model), expected);
}

#[test]
fn hidden_row_display_hotp_with_missing_counter_defaults_to_zero() {
    // `Vault::summaries` always supplies a counter for HOTP, but the
    // helper must defensively render `0` if it ever sees `None`,
    // matching `counter_display`'s contract for revealed codes.
    let model = AccountRowModel {
        id: AccountId::new(),
        display_label: "solo".to_string(),
        kind: AccountKindSummary::Hotp,
        counter: None,
    };
    let display = hidden_row_display(&model);
    assert_eq!(display.counter, Some(CounterText::Stored(0)));
}

// ---------------------------------------------------------------------------
// `format_widget_states_marker` — single-line per-row widget state marker
// emitted under `--exit-after-startup` once the per-row widget bundle is
// bound. The smoke test in `tests/gtk_smoke.rs` greps for this prefix so
// the per-row affordance states are observable end-to-end without driving
// widget signals.
//
// Each row contributes a comma-separated key:value list (`copy:`, `next:`,
// `kebab:`) and rows are pipe-joined in order. The kebab key always renders
// `on` — every row exposes the Rename… / Remove… menu unconditionally —
// but pinning the entry here keeps "the bundle mounted the kebab" an
// explicit, observable invariant. Pinning the current shape so any future
// addition is an explicit test update.
// ---------------------------------------------------------------------------

fn totp_display(label: &str) -> RowDisplay {
    RowDisplay {
        label: label.to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Hidden,
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        kebab_visible: true,
    }
}

fn hotp_hidden_display(label: &str, counter: u64) -> RowDisplay {
    RowDisplay {
        label: label.to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Hidden,
        counter: Some(CounterText::Stored(counter)),
        copy_enabled: false,
        next_button_visible: true,
        progress_visible: false,
        kebab_visible: true,
    }
}

#[test]
fn widget_states_marker_prefix_is_pinned() {
    assert_eq!(
        ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX,
        "paladin-gtk: account_list_widget_states=",
    );
}

#[test]
fn widget_states_marker_empty_emits_empty_suffix() {
    let displays: Vec<RowDisplay> = Vec::new();
    assert_eq!(
        format_widget_states_marker(&displays),
        "paladin-gtk: account_list_widget_states=",
    );
}

#[test]
fn widget_states_marker_renders_copy_on_next_off_kebab_on_for_totp() {
    // TOTP rows enable copy (the code is always computed), never
    // expose the HOTP "next" button, and always show the kebab menu.
    let displays = vec![totp_display("Acme:alice")];
    assert_eq!(
        format_widget_states_marker(&displays),
        "paladin-gtk: account_list_widget_states=copy:on,next:off,kebab:on",
    );
}

#[test]
fn widget_states_marker_renders_copy_off_next_on_kebab_on_for_hidden_hotp() {
    // Hidden HOTP rows disable copy (no visible code yet), expose
    // the "next" button so the user can advance the counter, and
    // still show the kebab menu.
    let displays = vec![hotp_hidden_display("solo", 7)];
    assert_eq!(
        format_widget_states_marker(&displays),
        "paladin-gtk: account_list_widget_states=copy:off,next:on,kebab:on",
    );
}

#[test]
fn widget_states_marker_renders_kebab_off_when_projection_hides_it() {
    // Defensive: the `kebab_visible` field is a `bool`, so the
    // marker must still render `kebab:off` if a caller ever
    // constructs a row that hides the kebab. Today the projection
    // never produces this; pinning it keeps the encoding symmetric
    // with `copy:` and `next:`.
    let display = RowDisplay {
        label: "spy:row".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Hidden,
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        kebab_visible: false,
    };
    let displays = vec![display];
    assert_eq!(
        format_widget_states_marker(&displays),
        "paladin-gtk: account_list_widget_states=copy:on,next:off,kebab:off",
    );
}

#[test]
fn widget_states_marker_pipe_joins_in_order() {
    let displays = vec![
        totp_display("GitHub:ben"),
        hotp_hidden_display("solo", 0),
        totp_display("GitLab:alice"),
    ];
    assert_eq!(
        format_widget_states_marker(&displays),
        "paladin-gtk: account_list_widget_states=copy:on,next:off,kebab:on|copy:off,next:on,kebab:on|copy:on,next:off,kebab:on",
    );
}
