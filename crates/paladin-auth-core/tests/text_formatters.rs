// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase K coverage — public-surface stability of the `text::format_*`
// helpers (docs/DESIGN.md §4.7 / §6 / §7).
//
// CLI, TUI, and GTK render these strings byte-identically. Internal
// unit tests cover the render logic; these tests pin the wording at
// the boundary external crates see so a refactor that reroutes one
// front end through an alternative formatter trips an integration
// failure immediately, not after a divergence in the next release.

use std::path::PathBuf;

use paladin_auth_core::{
    format_init_force_warning, format_plaintext_export_warning, format_plaintext_qr_export_warning,
    format_plaintext_storage_warning,
};

#[test]
fn format_plaintext_storage_warning_is_parameter_free_and_starts_with_warning() {
    let s = format_plaintext_storage_warning();
    assert!(
        s.starts_with("WARNING:"),
        "must start with the WARNING marker every front end aligns on, got {s:?}",
    );
    // Re-calling must produce byte-identical output: the helper is
    // parameter-free so the wording cannot drift between calls.
    assert_eq!(format_plaintext_storage_warning(), s);
}

#[test]
fn format_plaintext_export_warning_is_parameter_free_and_starts_with_warning() {
    let s = format_plaintext_export_warning();
    assert!(
        s.starts_with("WARNING:"),
        "must start with the WARNING marker every front end aligns on, got {s:?}",
    );
    assert_eq!(format_plaintext_export_warning(), s);
}

#[test]
fn format_plaintext_storage_and_export_warnings_are_distinct_strings() {
    // CLI emits both wordings in different contexts (`init` vs
    // `export --plaintext`); a refactor that merges them into one
    // shared string would silently change one of those call sites.
    assert_ne!(
        format_plaintext_storage_warning(),
        format_plaintext_export_warning(),
    );
}

#[test]
fn format_plaintext_qr_export_warning_is_parameter_free_and_starts_with_warning() {
    let s = format_plaintext_qr_export_warning();
    assert!(
        s.starts_with("WARNING:"),
        "must start with the WARNING marker every front end aligns on, got {s:?}",
    );
    assert_eq!(format_plaintext_qr_export_warning(), s);
}

#[test]
fn format_plaintext_qr_export_warning_is_distinct_from_other_plaintext_warnings() {
    // The CLI / TUI / GUI render this warning verbatim before any pixel
    // of a per-account QR is shown or written (docs/DESIGN.md §4.6 /
    // §6 / §7). A refactor that aliased it to either the storage or
    // export warning would silently degrade the QR confirmation flow.
    let qr = format_plaintext_qr_export_warning();
    assert_ne!(qr, format_plaintext_storage_warning());
    assert_ne!(qr, format_plaintext_export_warning());
}

#[test]
fn format_plaintext_qr_export_warning_mentions_qr_secret_and_counter() {
    // Wording is locked by the inline fixture in `src/text.rs`; this
    // test pins the topical content so a future reword cannot quietly
    // drop the QR / secret / counter callouts the modal flows depend
    // on for informed consent.
    let s = format_plaintext_qr_export_warning();
    assert!(s.contains("QR"), "QR callout missing: {s}");
    assert!(s.contains("secret"), "secret callout missing: {s}");
    assert!(s.contains("counter"), "HOTP counter callout missing: {s}");
}

#[test]
fn format_init_force_warning_includes_primary_and_backup_paths() {
    let primary = PathBuf::from("/home/alice/.vault.bin");
    let warning = format_init_force_warning(&primary);
    assert!(
        warning.contains("/home/alice/.vault.bin"),
        "primary path missing from warning: {warning}",
    );
    assert!(
        warning.contains("/home/alice/.vault.bin.bak"),
        ".bak rotation target missing from warning: {warning}",
    );
}

#[test]
fn format_init_force_warning_handles_non_default_basename() {
    // A `--vault custom.bin` invocation must surface the actual
    // basename in the warning, not the default `vault.bin`.
    let primary = PathBuf::from("/srv/secrets/custom.bin");
    let warning = format_init_force_warning(&primary);
    assert!(
        warning.contains("/srv/secrets/custom.bin"),
        "actual basename missing from warning: {warning}",
    );
    assert!(
        warning.contains("/srv/secrets/custom.bin.bak"),
        ".bak target derived from actual basename missing: {warning}",
    );
}
