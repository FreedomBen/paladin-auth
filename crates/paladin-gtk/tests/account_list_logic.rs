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
    bind_display_for_row, dispatch_row_action, filtered_row_models_from_vault,
    format_rendered_marker, format_widget_states_marker, hidden_row_display, prune_cache_to_rows,
    row_model_for_account, row_models_from_vault, selected_row_after_refresh, AccountListOutput,
    AccountRowModel, ACCOUNT_LIST_WIDGET_STATES_MARKER_PREFIX, ROW_ACTION_GROUP_NAME,
    ROW_COPY_ACTION_NAME, ROW_NEXT_ACTION_NAME, ROW_REMOVE_ACTION_NAME, ROW_RENAME_ACTION_NAME,
};
use paladin_gtk::account_row::{CodeDisplay, CounterText, ProgressDisplay, RowDisplay};

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
    // never carries a dangling `:label` colon (parity with the
    // canonical `account_row::summary_display_label`, also re-exported
    // as `remove_dialog::summary_display_label`).
    add_totp(&mut vault, &store, Some(""), "alice");

    let rows = row_models_from_vault(&vault);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].display_label, "alice");
}

// Variant of `add_totp` that lets a test specify the icon-hint mode
// (Default / Clear / explicit Slug) — the default helpers above always
// pass `IconHintInput::Default`, which is the right contract for the
// label / counter / ordering tests but not for icon-hint coverage.
fn add_totp_with_icon(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
    icon_hint: IconHintInput,
) -> AccountId {
    let input = AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint,
    };
    let validated = validate_manual(input, SystemTime::now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

#[test]
fn row_models_carry_icon_hint_derived_from_issuer() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    // `IconHintInput::Default` (the helper default) slugifies the
    // issuer into a stable icon-theme slug. The row model must echo
    // that slug so the widget factory can feed it through
    // `icon_resolution::resolve_display_icon`.
    add_totp(&mut vault, &store, Some("GitHub"), "ben");

    let rows = row_models_from_vault(&vault);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].icon_hint.as_deref(),
        Some("github"),
        "default icon hint slugifies the issuer for the row's icon_hint",
    );
}

#[test]
fn row_models_carry_explicit_icon_hint_slug() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp_with_icon(
        &mut vault,
        &store,
        Some("GitHub"),
        "ben",
        IconHintInput::Slug("custom-slug".to_string()),
    );

    let rows = row_models_from_vault(&vault);
    assert_eq!(
        rows[0].icon_hint.as_deref(),
        Some("custom-slug"),
        "explicit Slug overrides the issuer-derived default",
    );
}

#[test]
fn row_models_icon_hint_is_none_for_no_issuer_default() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    // No issuer + `IconHintInput::Default` = no slug to derive.
    add_totp(&mut vault, &store, None, "solo");

    let rows = row_models_from_vault(&vault);
    assert!(
        rows[0].icon_hint.is_none(),
        "no issuer + default icon hint must not project a row icon hint, got: {:?}",
        rows[0].icon_hint,
    );
}

#[test]
fn row_models_icon_hint_is_none_when_cleared() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp_with_icon(
        &mut vault,
        &store,
        Some("GitHub"),
        "ben",
        IconHintInput::Clear,
    );

    let rows = row_models_from_vault(&vault);
    assert!(
        rows[0].icon_hint.is_none(),
        "explicit Clear suppresses any issuer-derived slug, got: {:?}",
        rows[0].icon_hint,
    );
}

// ---------------------------------------------------------------------------
// `row_model_for_account`
// ---------------------------------------------------------------------------
//
// Mirror of `row_models_from_vault` that targets a single account id
// so `AppModel` can re-derive the updated `AccountRowModel` after a
// successful rename / next / settings change without re-projecting
// every row in the vault. Coverage parallels the bulk projection so
// any drift between the two is caught here.

#[test]
fn row_model_for_account_missing_id_is_none() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let present = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    // Synthesise an id that is structurally valid but absent from the
    // vault — `AccountId::default()` is the all-zero sentinel and
    // does not collide with `Vault::add` issued ids.
    let absent = AccountId::default();
    assert_ne!(present, absent);

    assert!(
        row_model_for_account(&vault, absent).is_none(),
        "missing id projects to None, not a stale row",
    );
}

#[test]
fn row_model_for_account_returns_matching_totp_row() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("GitHub"), "ben");

    let model = row_model_for_account(&vault, id).expect("present id projects");
    assert_eq!(model.id, id);
    assert_eq!(model.display_label, "GitHub:ben");
    assert_eq!(model.kind, AccountKindSummary::Totp);
    assert_eq!(model.counter, None);
}

#[test]
fn row_model_for_account_returns_matching_hotp_row_with_counter() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_hotp(&mut vault, &store, None, "solo", 42);

    let model = row_model_for_account(&vault, id).expect("present id projects");
    assert_eq!(model.id, id);
    assert_eq!(model.display_label, "solo");
    assert_eq!(model.kind, AccountKindSummary::Hotp);
    assert_eq!(model.counter, Some(42));
}

#[test]
fn row_model_for_account_finds_id_in_any_position() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let first = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let middle = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let last = add_totp(&mut vault, &store, None, "solo");

    for (id, expected) in [
        (first, "GitHub:ben"),
        (middle, "GitLab:alice"),
        (last, "solo"),
    ] {
        let model = row_model_for_account(&vault, id).expect("present id projects");
        assert_eq!(model.id, id);
        assert_eq!(model.display_label, expected);
    }
}

#[test]
fn row_model_for_account_carries_icon_hint() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("GitHub"), "ben");

    let model = row_model_for_account(&vault, id).expect("present id projects");
    assert_eq!(
        model.icon_hint.as_deref(),
        Some("github"),
        "single-row projection echoes icon_hint so it stays in lockstep with `row_models_from_vault`",
    );
}

#[test]
fn row_model_for_account_drops_empty_issuer_in_display_label() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some(""), "alice");

    let model = row_model_for_account(&vault, id).expect("present id projects");
    assert_eq!(
        model.display_label, "alice",
        "empty issuer collapses to bare label (parity with `row_models_from_vault`)",
    );
}

#[test]
fn row_model_for_account_reflects_post_rename_label() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let id = add_totp(&mut vault, &store, Some("GitHub"), "ben");

    let before = row_model_for_account(&vault, id).expect("present id projects");
    assert_eq!(before.display_label, "GitHub:ben");

    vault
        .mutate_and_save(&store, |v| v.rename(id, "newname", SystemTime::now()))
        .expect("rename committed");

    let after = row_model_for_account(&vault, id).expect("present id projects");
    assert_eq!(
        after.display_label, "GitHub:newname",
        "post-rename projection reflects new `<issuer>:<label>` heading",
    );
    assert_eq!(after.id, id, "id remains stable across rename");
}

#[test]
fn row_model_for_account_matches_bulk_projection_for_same_id() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let b = add_hotp(&mut vault, &store, Some("GitLab"), "alice", 9);

    let bulk = row_models_from_vault(&vault);
    for id in [a, b] {
        let single = row_model_for_account(&vault, id).expect("present id projects");
        let bulk_row = bulk
            .iter()
            .find(|r| r.id == id)
            .expect("bulk projection has same id");
        assert_eq!(
            &single, bulk_row,
            "single-row projection must match bulk projection field-for-field",
        );
    }
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
        icon_hint: None,
    };
    let expected = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Hidden,
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        progress: None,
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
        icon_hint: None,
    };
    let expected = RowDisplay {
        label: "solo".to_string(),
        kind: AccountKindSummary::Hotp,
        code: CodeDisplay::Hidden,
        counter: Some(CounterText::Stored(7)),
        copy_enabled: false,
        next_button_visible: true,
        progress_visible: false,
        progress: None,
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
        icon_hint: None,
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
        progress: None,
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
        progress: None,
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
        progress: None,
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

// ---------------------------------------------------------------------------
// Row action wiring: action group name + per-row action names + dispatch
// table.
//
// The kebab `gio::Menu` produced by `account_list::build_kebab_menu_model`
// targets `row.rename` / `row.remove`; the widget layer installs a per-row
// `gio::SimpleActionGroup` named [`ROW_ACTION_GROUP_NAME`] whose actions
// match [`ROW_RENAME_ACTION_NAME`] / [`ROW_REMOVE_ACTION_NAME`]. The
// dispatch table [`dispatch_row_action`] maps a fired action name back to
// the typed [`AccountListOutput`] forwarded to `AppModel`. Pinning the
// names + the dispatch table here keeps the kebab-menu targets, the
// installed action group, and the typed output enum in lockstep — drift
// in any of the three would surface as a failing test rather than a
// silent no-op when the user clicks Rename… / Remove….
// ---------------------------------------------------------------------------

#[test]
fn row_action_group_name_is_row() {
    // The kebab menu items target `row.rename` / `row.remove`; the
    // group name installed on each row container must match the
    // prefix `row` so action lookup resolves at activation time.
    assert_eq!(ROW_ACTION_GROUP_NAME, "row");
}

#[test]
fn row_rename_action_name_is_rename() {
    // The `row.rename` menu target resolves to the action named
    // `rename` inside the `row` group.
    assert_eq!(ROW_RENAME_ACTION_NAME, "rename");
}

#[test]
fn row_remove_action_name_is_remove() {
    // The `row.remove` menu target resolves to the action named
    // `remove` inside the `row` group.
    assert_eq!(ROW_REMOVE_ACTION_NAME, "remove");
}

#[test]
fn row_next_action_name_is_next() {
    // The HOTP row's "next" button targets `row.next`, which
    // resolves to the action named `next` inside the `row` group.
    // Pinning the name here keeps the widget binding in
    // `build_row_widget` and the action installed by
    // [`install_row_action_group`] in lockstep with
    // [`dispatch_row_action`].
    assert_eq!(ROW_NEXT_ACTION_NAME, "next");
}

#[test]
fn row_copy_action_name_is_copy() {
    // The per-row copy `gtk::Button` targets `row.copy`, which
    // resolves to the action named `copy` inside the `row` group.
    // Pinning the name keeps the widget binding in
    // `build_row_widget` and the action installed by
    // [`install_row_action_group`] in lockstep with
    // [`dispatch_row_action`].
    assert_eq!(ROW_COPY_ACTION_NAME, "copy");
}

#[test]
fn dispatch_row_action_routes_rename_to_open_rename_dialog() {
    let id = AccountId::new();
    assert_eq!(
        dispatch_row_action(ROW_RENAME_ACTION_NAME, id),
        Some(AccountListOutput::OpenRenameDialog(id)),
    );
}

#[test]
fn dispatch_row_action_routes_remove_to_open_remove_dialog() {
    let id = AccountId::new();
    assert_eq!(
        dispatch_row_action(ROW_REMOVE_ACTION_NAME, id),
        Some(AccountListOutput::OpenRemoveDialog(id)),
    );
}

#[test]
fn dispatch_row_action_routes_next_to_advance_hotp() {
    // The HOTP "next" button's `row.next` activation resolves to
    // `AccountListOutput::AdvanceHotp(id)`. `AppModel` consumes that
    // output to spawn the `Vault::hotp_peek` / `Vault::hotp_advance`
    // worker per `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `AccountRowComponent`.
    let id = AccountId::new();
    assert_eq!(
        dispatch_row_action(ROW_NEXT_ACTION_NAME, id),
        Some(AccountListOutput::AdvanceHotp(id)),
    );
}

#[test]
fn dispatch_row_action_routes_copy_to_copy_code() {
    // The per-row copy button's `row.copy` activation resolves to
    // `AccountListOutput::CopyCode(id)`. `AppModel` consumes that
    // output to write the visible code into `gdk::Clipboard` and
    // schedule the clipboard auto-clear policy per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `AccountRowComponent`.
    let id = AccountId::new();
    assert_eq!(
        dispatch_row_action(ROW_COPY_ACTION_NAME, id),
        Some(AccountListOutput::CopyCode(id)),
    );
}

#[test]
fn dispatch_row_action_returns_none_for_unknown_action() {
    // Defensive: the widget layer only installs `rename` / `remove`
    // actions today, but the dispatch table is the single source of
    // truth — an unrecognized name must return `None` so a future
    // typo in the action group surfaces as a silent no-op the
    // widget layer can catch in `debug_assert!`.
    let id = AccountId::new();
    assert_eq!(dispatch_row_action("nope", id), None);
    assert_eq!(dispatch_row_action("", id), None);
    assert_eq!(dispatch_row_action("row.rename", id), None);
}

#[test]
fn account_list_output_carries_account_id_for_rename() {
    let id = AccountId::new();
    let out = AccountListOutput::OpenRenameDialog(id);
    let AccountListOutput::OpenRenameDialog(carried) = out else {
        panic!("OpenRenameDialog should round-trip its AccountId");
    };
    assert_eq!(carried, id);
}

#[test]
fn account_list_output_carries_account_id_for_remove() {
    let id = AccountId::new();
    let out = AccountListOutput::OpenRemoveDialog(id);
    let AccountListOutput::OpenRemoveDialog(carried) = out else {
        panic!("OpenRemoveDialog should round-trip its AccountId");
    };
    assert_eq!(carried, id);
}

#[test]
fn account_list_output_carries_account_id_for_advance_hotp() {
    let id = AccountId::new();
    let out = AccountListOutput::AdvanceHotp(id);
    let AccountListOutput::AdvanceHotp(carried) = out else {
        panic!("AdvanceHotp should round-trip its AccountId");
    };
    assert_eq!(carried, id);
}

#[test]
fn account_list_output_variants_are_distinct() {
    // Same id, different variants must compare unequal — the
    // dispatch table relies on the variant carrying the user's
    // intent (rename vs. remove vs. advance-hotp), not just the row
    // identity.
    let id = AccountId::new();
    assert_ne!(
        AccountListOutput::OpenRenameDialog(id),
        AccountListOutput::OpenRemoveDialog(id),
    );
    assert_ne!(
        AccountListOutput::OpenRenameDialog(id),
        AccountListOutput::AdvanceHotp(id),
    );
    assert_ne!(
        AccountListOutput::OpenRemoveDialog(id),
        AccountListOutput::AdvanceHotp(id),
    );
}

// ---------------------------------------------------------------------------
// `filtered_row_models_from_vault`
// ---------------------------------------------------------------------------
//
// Pure-logic projection of the live vault into the row models the
// search bar's incremental filter binds onto the `gio::ListStore`.
// Composes [`row_models_from_vault`] with `paladin_core::
// account_matches_search` (via `crate::search::filtered_account_ids`)
// so the GUI's filter contract matches the CLI / TUI search exactly:
// case-insensitive substring against `<issuer>:<label>`, insertion
// order preserved among matches, empty query matches every account.

#[test]
fn filtered_row_models_empty_query_returns_all_in_order() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let b = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let c = add_totp(&mut vault, &store, None, "solo");

    let rows = filtered_row_models_from_vault(&vault, "");
    let ids: Vec<AccountId> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![a, b, c],
        "empty query matches every account in insertion order",
    );
}

#[test]
fn filtered_row_models_case_insensitive_substring() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let github = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let _gitlab = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let _solo = add_totp(&mut vault, &store, None, "solo");

    // Substring `"hub"` (case-insensitive) appears only in the
    // GitHub row's `<issuer>:<label>` match key.
    let rows = filtered_row_models_from_vault(&vault, "HUB");
    let ids: Vec<AccountId> = rows.iter().map(|r| r.id).collect();
    assert_eq!(ids, vec![github]);
    assert_eq!(rows[0].display_label, "GitHub:ben");
}

#[test]
fn filtered_row_models_no_match_returns_empty() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_totp(&mut vault, &store, Some("GitLab"), "alice");

    let rows = filtered_row_models_from_vault(&vault, "nope");
    assert!(rows.is_empty(), "no-match query projects no rows");
}

#[test]
fn filtered_row_models_preserves_insertion_order_among_matches() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    // Insert non-matches between two matching rows to verify the
    // filter walks insertion order (not match order or alphabetical).
    let first = add_totp(&mut vault, &store, Some("Acme"), "alice");
    add_totp(&mut vault, &store, Some("Other"), "ben");
    let third = add_totp(&mut vault, &store, Some("Acme"), "carol");
    add_totp(&mut vault, &store, Some("Different"), "dan");

    let rows = filtered_row_models_from_vault(&vault, "acme");
    let ids: Vec<AccountId> = rows.iter().map(|r| r.id).collect();
    assert_eq!(
        ids,
        vec![first, third],
        "matches preserve vault insertion order",
    );
}

#[test]
fn filtered_row_models_match_key_keeps_colon_for_empty_issuer() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    // Empty issuer keeps the colon in the match key (parity with
    // `paladin_core::account_matches_search` and the parallel
    // `search_logic.rs` coverage) — querying `:` matches this row.
    let id = add_totp(&mut vault, &store, Some(""), "alice");

    let rows = filtered_row_models_from_vault(&vault, ":");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, id);
    // The row's display_label still collapses to the bare label
    // even though the match key retained the colon.
    assert_eq!(rows[0].display_label, "alice");
}

// ---------------------------------------------------------------------------
// `selected_row_after_refresh`
// ---------------------------------------------------------------------------
//
// Wraps `paladin_core::select_after_filter` against
// `&[AccountRowModel]` so the `AccountListComponent` can re-pick its
// selected row after every refresh (vault mutation, search query
// change) without re-deriving the filter rule the CLI / TUI already
// share. Coverage parallels `tests/search_logic.rs`'s
// `select_after_search_*` cases.

#[test]
fn selected_row_after_refresh_preserves_prev_when_still_present() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    let b = add_totp(&mut vault, &store, Some("GitLab"), "alice");
    let _c = add_totp(&mut vault, &store, None, "solo");

    let rows = row_models_from_vault(&vault);
    assert_eq!(
        selected_row_after_refresh(Some(b), &rows),
        Some(b),
        "prev selection survives when the row is still present",
    );
    // Sanity: a different prev id also survives if still present.
    assert_eq!(selected_row_after_refresh(Some(a), &rows), Some(a));
}

#[test]
fn selected_row_after_refresh_falls_back_to_first_when_prev_gone() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_totp(&mut vault, &store, Some("GitLab"), "alice");

    let rows = row_models_from_vault(&vault);
    let gone = AccountId::default();
    assert_eq!(
        selected_row_after_refresh(Some(gone), &rows),
        Some(a),
        "falls back to first row when prev is no longer in the set",
    );
}

#[test]
fn selected_row_after_refresh_returns_none_for_empty_rows() {
    // An empty post-filter set yields no selection — the
    // `AccountListComponent` clears its `SingleSelection` instead of
    // pointing at a stale id.
    let empty: Vec<AccountRowModel> = Vec::new();
    assert_eq!(selected_row_after_refresh(None, &empty), None);
    assert_eq!(
        selected_row_after_refresh(Some(AccountId::new()), &empty),
        None,
        "stale prev does not survive an empty refresh",
    );
}

#[test]
fn selected_row_after_refresh_returns_first_when_prev_is_none() {
    let dir = secure_tempdir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) = open_plaintext_pair(&path);

    let a = add_totp(&mut vault, &store, Some("GitHub"), "ben");
    add_totp(&mut vault, &store, Some("GitLab"), "alice");

    let rows = row_models_from_vault(&vault);
    assert_eq!(
        selected_row_after_refresh(None, &rows),
        Some(a),
        "fresh refresh with no prior selection picks the first row",
    );
}

// ---------------------------------------------------------------------------
// `bind_display_for_row` — live-cache lookup before hidden fallback
//
// The factory's `connect_bind` callback routes through this helper so the
// per-tick refresh path can publish a live visible code without rebuilding
// the `AccountRowModel` entries in the `gio::ListStore`. The contract:
//
// 1. When the live cache holds a [`RowDisplay`] for the row's
//    [`AccountId`], that display is returned verbatim (cloned, so the
//    factory and the cache do not alias the same heap allocation).
// 2. When the cache is empty / does not hold an entry for this row, the
//    fallback is [`hidden_row_display`] — the same default the factory
//    used before the live cache was introduced, so the row mount stays
//    backward-compatible.
//
// The follow-up commit that wires `AccountListMsg::Tick` updates the
// cache and forces a rebind via `gio::ListStore::splice`; the contract
// pinned here is what the factory call site needs in either path.
// ---------------------------------------------------------------------------

fn totp_model_for(id: AccountId, label: &str) -> AccountRowModel {
    AccountRowModel {
        id,
        display_label: label.to_string(),
        kind: AccountKindSummary::Totp,
        counter: None,
        icon_hint: None,
    }
}

fn hotp_model_for(id: AccountId, label: &str, counter: u64) -> AccountRowModel {
    AccountRowModel {
        id,
        display_label: label.to_string(),
        kind: AccountKindSummary::Hotp,
        counter: Some(counter),
        icon_hint: None,
    }
}

#[test]
fn bind_display_for_row_returns_live_clone_when_cache_hits() {
    let id = AccountId::new();
    let model = totp_model_for(id, "Acme:alice");
    let live = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Visible("123 456".to_string()),
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        progress: Some(ProgressDisplay {
            period_secs: 30,
            seconds_remaining: 18,
        }),
        kebab_visible: true,
    };
    let bound = bind_display_for_row(Some(&live), &model);
    assert_eq!(bound, live, "cache hit wins over hidden fallback");
}

#[test]
fn bind_display_for_row_falls_back_to_hidden_when_cache_misses() {
    let id = AccountId::new();
    let model = totp_model_for(id, "Acme:alice");
    let bound = bind_display_for_row(None, &model);
    assert_eq!(
        bound,
        hidden_row_display(&model),
        "cache miss falls back to hidden — initial mount, post-refresh window, or HOTP outside reveal",
    );
}

#[test]
fn bind_display_for_row_hidden_fallback_preserves_kind_specific_state() {
    // HOTP rows in the hidden state expose a visible stored counter
    // and the "next" button; TOTP rows hide the counter and show the
    // progress gauge. The fallback path must honor those rules.
    let totp_id = AccountId::new();
    let totp_model = totp_model_for(totp_id, "TOTPCo:alice");
    let totp_bound = bind_display_for_row(None, &totp_model);
    assert!(totp_bound.progress_visible);
    assert!(!totp_bound.next_button_visible);
    assert!(totp_bound.counter.is_none());

    let hotp_id = AccountId::new();
    let hotp_model = hotp_model_for(hotp_id, "HOTPCo:bob", 7);
    let hotp_bound = bind_display_for_row(None, &hotp_model);
    assert!(!hotp_bound.progress_visible);
    assert!(hotp_bound.next_button_visible);
    assert!(matches!(hotp_bound.counter, Some(CounterText::Stored(7))));
}

#[test]
fn bind_display_for_row_returned_clone_does_not_alias_cache() {
    // Mutating the returned display must not bleed back into the
    // cache entry — the factory consumes the display by value and
    // updates widget properties; the cache stays the canonical
    // record for the next bind round.
    let id = AccountId::new();
    let model = totp_model_for(id, "Acme:alice");
    let live = RowDisplay {
        label: "Acme:alice".to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Visible("111 222".to_string()),
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        progress: Some(ProgressDisplay {
            period_secs: 30,
            seconds_remaining: 12,
        }),
        kebab_visible: true,
    };
    let mut bound = bind_display_for_row(Some(&live), &model);
    bound.label = "scribbled".to_string();
    assert_eq!(
        live.label, "Acme:alice",
        "the original cache entry is not mutated through the returned clone",
    );
}

// ---------------------------------------------------------------------------
// `prune_cache_to_rows` — drop stale cache entries on refresh
//
// `AccountListMsg::Refresh` calls this helper so a Remove / search-filter
// rebuild that drops accounts does not leave a stale live display behind.
// Surviving entries stay in the cache so the user keeps seeing the live
// code across an Add / Rename / settings refresh without waiting for the
// next tick (max one tick interval of stale-label exposure on a Rename,
// which the next `tick(...)` call overwrites).
// ---------------------------------------------------------------------------

fn live_display(label: &str) -> RowDisplay {
    RowDisplay {
        label: label.to_string(),
        kind: AccountKindSummary::Totp,
        code: CodeDisplay::Visible("999 888".to_string()),
        counter: None,
        copy_enabled: true,
        next_button_visible: false,
        progress_visible: true,
        progress: Some(ProgressDisplay {
            period_secs: 30,
            seconds_remaining: 5,
        }),
        kebab_visible: true,
    }
}

#[test]
fn prune_cache_to_rows_keeps_entries_for_surviving_ids() {
    let surviving = AccountId::new();
    let rows = vec![totp_model_for(surviving, "Acme:alice")];

    let mut cache = std::collections::HashMap::new();
    cache.insert(surviving, live_display("Acme:alice"));

    prune_cache_to_rows(&mut cache, &rows);
    assert!(
        cache.contains_key(&surviving),
        "surviving id keeps its cached display so the user does not lose the live code mid-refresh",
    );
}

#[test]
fn prune_cache_to_rows_drops_entries_for_removed_ids() {
    let surviving = AccountId::new();
    let removed = AccountId::new();
    let rows = vec![totp_model_for(surviving, "Acme:alice")];

    let mut cache = std::collections::HashMap::new();
    cache.insert(surviving, live_display("Acme:alice"));
    cache.insert(removed, live_display("Acme:bob"));

    prune_cache_to_rows(&mut cache, &rows);
    assert!(
        !cache.contains_key(&removed),
        "removed id no longer in the cache"
    );
    assert!(cache.contains_key(&surviving), "surviving id still cached");
}

#[test]
fn prune_cache_to_rows_empty_rows_clears_cache_entirely() {
    // The all-rows-filtered-out case: a search query that matches no
    // account, an empty vault after Remove, …
    let alice = AccountId::new();
    let bob = AccountId::new();
    let mut cache = std::collections::HashMap::new();
    cache.insert(alice, live_display("Acme:alice"));
    cache.insert(bob, live_display("Acme:bob"));

    prune_cache_to_rows(&mut cache, &[]);
    assert!(cache.is_empty(), "empty row set drops every cache entry");
}

#[test]
fn prune_cache_to_rows_empty_cache_no_op() {
    let alice = AccountId::new();
    let rows = vec![totp_model_for(alice, "Acme:alice")];

    let mut cache: std::collections::HashMap<AccountId, RowDisplay> =
        std::collections::HashMap::new();
    prune_cache_to_rows(&mut cache, &rows);
    assert!(cache.is_empty(), "no entries to prune is a benign no-op");
}
