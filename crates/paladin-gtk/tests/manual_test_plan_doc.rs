// SPDX-License-Identifier: AGPL-3.0-or-later

//! Guard test for the §"Manual test plan" deliverable.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Tests > Manual test plan
//! (`tests/manual/MANUAL_TEST_PLAN.md`)" and the Milestone 7 checklist
//! entry "Manual test plan documented", `tests/manual/MANUAL_TEST_PLAN.md`
//! must exist and enumerate every required manual-QA item from the plan.
//! This test asserts:
//!
//! 1. The file exists.
//! 2. Every required item from the plan's §"Manual test plan" bullet
//!    list appears in the doc (whitespace-normalized substring match).
//! 3. The doc contains at least one tickable checkbox per required
//!    item so the manual QA pass can be checked off in-place.
//! 4. The Wayland + X11 sign-off requirement from the plan is called
//!    out in the doc.
//!
//! The required-item list lives here, not in the markdown file, so a
//! plan revision that adds a new manual-QA expectation forces a
//! matching doc update (the test fails until the doc is updated).

use std::fs;
use std::path::PathBuf;

/// Every required manual-QA bullet from `docs/IMPLEMENTATION_PLAN_04_GTK.md`
/// §"Tests > Manual test plan (`tests/manual/MANUAL_TEST_PLAN.md`)".
///
/// Entries are the unwrapped bullet text; the doc may wrap text across
/// lines freely because the assertion below normalizes whitespace
/// before substring-matching.
const REQUIRED_ITEMS: &[&str] = &[
    "Init plaintext vault: both passphrase fields empty + warning gate before submit is enabled.",
    "Init encrypted vault with twice-confirm.",
    "Init when a vault already exists at the path opens the destructive-confirmation gate; confirm runs `create_force` and rotates the prior vault to `vault.bin.bak`; cancel leaves the prior vault intact.",
    "Init under the §10 fault-injection hook surfaces `save_not_committed` and `save_durability_unconfirmed` inline.",
    "Unlock encrypted vault with the correct passphrase.",
    "Copy a TOTP code from a row.",
    "HOTP `next` reveals and copies while showing the counter used.",
    "HOTP reveal window expires and the row returns to hidden.",
    "Auto-lock fires after the configured idle interval (encrypted vault).",
    "Clipboard auto-clear honors the if-unchanged rule.",
    "Add via manual fields.",
    "Add via `otpauth://` URI paste — success path.",
    "Add via `otpauth://` URI paste — malformed-URI rejection stays inline.",
    "Add via `otpauth://` URI paste — duplicate \"add anyway\" round-trip.",
    "Switching Add paths clears hidden secret fields and pending duplicate state.",
    "Add via clipboard image — success path.",
    "Add via clipboard image — oversized-image rejection before download.",
    "Import otpauth JSON with each on-conflict policy; reported counts match.",
    "Import aegis plaintext with each on-conflict policy; reported counts match.",
    "Import encrypted Paladin bundle with each on-conflict policy; reported counts match.",
    "Import QR image file with each on-conflict policy; reported counts match.",
    "Export plaintext: warning + confirmation, `0600` output.",
    "Export encrypted Paladin bundle: twice-confirm, round-trip via Import.",
    "Refused overwrite without confirmation leaves the destination untouched.",
    "Rename an account via the row kebab menu: label persists on reopen.",
    "Rename an account via the row kebab menu: renaming to the same label still saves and bumps `updated_at`.",
    "Rename an account via the row kebab menu: pre-commit fault injection rolls the label back.",
    "Settings persist across restart.",
    "Passphrase `set` / `change` / `remove` flows complete end-to-end.",
    "Secret fields clear on cancel, submit, and auto-lock.",
    "Icon theme resolution + fallback work against the system theme.",
    "Destroy vault via primary-menu item.",
    "Destroy vault via unlock-dialog footer link.",
    "Destroy vault via startup-error footer link.",
    "Destroy vault via `Ctrl+Shift+Delete`.",
    "Cancel destroy at confirmation prompt; vault unchanged.",
    "Destroy vault with `.bak` present; both files unlinked, toast reads `Vault deleted.`.",
    "Destroy vault with no `.bak`; primary unlinked, toast reads `Vault deleted.`.",
    "Destroy vault while another dialog (Add, Edit, Passphrase) is open; that dialog closes and its sensitive buffers wipe.",
];

fn manual_plan_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("manual")
        .join("MANUAL_TEST_PLAN.md")
}

/// Collapse all runs of whitespace into a single space so that the
/// doc's line-wrapping does not break substring matches against
/// [`REQUIRED_ITEMS`].
fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn manual_test_plan_file_exists() {
    let path = manual_plan_path();
    assert!(
        path.is_file(),
        "tests/manual/MANUAL_TEST_PLAN.md is missing — Milestone 7 \
         deliverable per docs/IMPLEMENTATION_PLAN_04_GTK.md \
         §\"Tests > Manual test plan (`tests/manual/MANUAL_TEST_PLAN.md`)\". \
         Expected at: {}",
        path.display(),
    );
}

#[test]
fn manual_test_plan_covers_every_required_item() {
    let path = manual_plan_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = normalize_whitespace(&contents);

    let mut missing = Vec::new();
    for item in REQUIRED_ITEMS {
        let normalized_item = normalize_whitespace(item);
        if !normalized.contains(&normalized_item) {
            missing.push(*item);
        }
    }
    assert!(
        missing.is_empty(),
        "tests/manual/MANUAL_TEST_PLAN.md is missing one or more \
         required items from docs/IMPLEMENTATION_PLAN_04_GTK.md \
         §\"Manual test plan\". Add a tickable checkbox line for each \
         of the following:\n  - {}",
        missing.join("\n  - "),
    );
}

#[test]
fn manual_test_plan_has_enough_checkbox_lines() {
    let path = manual_plan_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));

    let checkbox_count = contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("- [ ]")
                || trimmed.starts_with("- [x]")
                || trimmed.starts_with("- [X]")
        })
        .count();

    assert!(
        checkbox_count >= REQUIRED_ITEMS.len(),
        "tests/manual/MANUAL_TEST_PLAN.md has {checkbox_count} checkbox \
         line(s); expected at least {} so each required item from \
         docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Manual test plan\" appears \
         as a tickable bullet.",
        REQUIRED_ITEMS.len(),
    );
}

#[test]
fn manual_test_plan_calls_out_wayland_and_x11_signoff() {
    let path = manual_plan_path();
    let contents =
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let normalized = normalize_whitespace(&contents);

    assert!(
        normalized.contains("Wayland") && normalized.contains("X11"),
        "tests/manual/MANUAL_TEST_PLAN.md must call out the plan's \
         sign-off requirement that every item is exercised cleanly on \
         both a Wayland and an X11 session — neither token was found \
         in the doc.",
    );
}
