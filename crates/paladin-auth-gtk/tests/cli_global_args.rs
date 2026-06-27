// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for `paladin_auth_gtk::cli::GlobalArgs`.
//!
//! Covers the contract from `docs/IMPLEMENTATION_PLAN_04_GTK.md` "Global
//! flags": `--vault <path>` and `--no-color` are accepted (parity with
//! siblings), `--no-color` is a parser-level no-op, `--json` is
//! rejected at parse time with clap's text diagnostic (never a JSON
//! envelope), and no positional file / URI arguments are accepted.
//! The hidden `--exit-after-startup` flag (used only by
//! `tests/gtk_smoke.rs`) parses but is intentionally absent from
//! `--help`.

use std::path::Path;

use clap::Parser;
use paladin_auth_gtk::cli::GlobalArgs;

// ---------------------------------------------------------------------------
// --vault
// ---------------------------------------------------------------------------

#[test]
fn vault_flag_selects_inspected_path() {
    let args = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--vault", "/tmp/v.bin"])
        .expect("--vault should parse");
    assert_eq!(args.vault.as_deref(), Some(Path::new("/tmp/v.bin")));
}

#[test]
fn default_leaves_vault_unset() {
    let args = GlobalArgs::try_parse_from(["paladin-auth-gtk"]).expect("no args should parse");
    assert!(args.vault.is_none());
}

// ---------------------------------------------------------------------------
// --no-color (parser-level no-op; accepted for parity with siblings)
// ---------------------------------------------------------------------------

#[test]
fn no_color_flag_is_accepted_for_parity() {
    let args = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--no-color"])
        .expect("--no-color should parse");
    assert!(args.no_color);
}

#[test]
fn default_no_color_is_false() {
    let args = GlobalArgs::try_parse_from(["paladin-auth-gtk"]).expect("no args should parse");
    assert!(!args.no_color);
}

// ---------------------------------------------------------------------------
// --json rejection (DESIGN §5 / plan "Global flags": text diagnostic, never
// a JSON envelope)
// ---------------------------------------------------------------------------

#[test]
fn json_flag_is_rejected_at_parse_time() {
    let err = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--json"])
        .expect_err("--json should reject");
    let rendered = err.to_string();
    assert!(
        rendered.contains("--json") || rendered.to_lowercase().contains("unexpected"),
        "expected clap text diagnostic mentioning --json or 'unexpected', got: {rendered}"
    );
}

#[test]
fn json_rejection_is_text_not_json_envelope() {
    let err = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--json"])
        .expect_err("--json should reject");
    let rendered = err.to_string();
    assert!(
        !rendered.trim_start().starts_with('{'),
        "GUI must not emit a JSON envelope for --json rejection, got: {rendered}"
    );
}

// No positional arguments: imports start from ImportDialog, not from CLI args.

#[test]
fn positional_file_argument_is_rejected() {
    let err = GlobalArgs::try_parse_from(["paladin-auth-gtk", "/tmp/some-import.json"])
        .expect_err("positional file argument should reject");
    let rendered = err.to_string();
    assert!(
        !rendered.trim_start().starts_with('{'),
        "positional-arg rejection must be text, not a JSON envelope: {rendered}"
    );
}

#[test]
fn positional_otpauth_uri_is_rejected() {
    let err = GlobalArgs::try_parse_from([
        "paladin-auth-gtk",
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP",
    ])
    .expect_err("positional otpauth URI should reject");
    let rendered = err.to_string();
    assert!(
        !rendered.trim_start().starts_with('{'),
        "positional-arg rejection must be text, not a JSON envelope: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// --help / --version remain clap-default text output (not JSON)
// ---------------------------------------------------------------------------

#[test]
fn help_flag_returns_clap_text_output() {
    let err = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--help"])
        .expect_err("--help exits via Err");
    let rendered = err.to_string();
    assert!(
        !rendered.trim_start().starts_with('{'),
        "--help output must be text, not a JSON envelope: {rendered}"
    );
}

#[test]
fn version_flag_returns_clap_text_output() {
    let err = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--version"])
        .expect_err("--version exits via Err");
    let rendered = err.to_string();
    assert!(
        !rendered.trim_start().starts_with('{'),
        "--version output must be text, not a JSON envelope: {rendered}"
    );
}

// ---------------------------------------------------------------------------
// --exit-after-startup (hidden testing flag wired by `tests/gtk_smoke.rs`)
// ---------------------------------------------------------------------------

#[test]
fn exit_after_startup_flag_is_accepted() {
    let args = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--exit-after-startup"])
        .expect("--exit-after-startup should parse");
    assert!(args.exit_after_startup);
}

#[test]
fn default_exit_after_startup_is_false() {
    let args = GlobalArgs::try_parse_from(["paladin-auth-gtk"]).expect("no args should parse");
    assert!(!args.exit_after_startup);
}

#[test]
fn exit_after_startup_flag_is_hidden_from_help() {
    let err = GlobalArgs::try_parse_from(["paladin-auth-gtk", "--help"])
        .expect_err("--help exits via Err");
    let rendered = err.to_string();
    assert!(
        !rendered.contains("--exit-after-startup"),
        "--exit-after-startup must be hidden from --help; got: {rendered}"
    );
}
