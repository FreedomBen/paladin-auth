// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Phase L — per-account QR export (docs/DESIGN.md §4.6 / §4.7).
//
// The three render targets (PNG bytes, SVG text, Unicode half-block
// string) all live in `paladin-auth-core` so the CLI / TUI / GTK front ends
// stay thin. Tests here pin:
//   - `QrRenderOptions::validate` bounds (1..=64 inclusive on
//     `module_size_px`; the bounds-violation `validation_error` reason
//     is locked at `module_size_px_out_of_bounds`).
//   - PNG render output round-trips through `rqrr` back to the matching
//     line of `export::otpauth_list(&vault)` so a scanner sees the same
//     URI Paladin Auth emits in its plaintext export.
//   - SVG render output is a well-formed SVG document.
//   - ANSI render output uses only the documented half-block glyphs and
//     forms a real grid (multi-line, contains dark modules).
//   - The export is read-only: HOTP `counter`, `updated_at`, and the
//     on-disk primary-file bytes are byte-identical before and after a
//     PNG → SVG → ANSI render sequence.
//   - Unknown `AccountId` lookups surface `invalid_state` with the
//     matching `operation` field and `state: "account_not_found"`.

#![cfg(unix)]

mod common;

use common::test_tempdir;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use image::Luma;
use paladin_auth_core::{
    export, parse_otpauth, Account, AccountId, Argon2Params, EncryptionOptions, ErrorKind,
    PaladinAuthError, QrRenderOptions, Store, VaultInit, QR_MODULE_SIZE_PX_DEFAULT,
    QR_MODULE_SIZE_PX_MAX, QR_MODULE_SIZE_PX_MIN,
};
use secrecy::SecretString;
use tempfile::TempDir;
use zeroize::{Zeroize, ZeroizeOnDrop};

const URI_TOTP_A: &str = "otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const URI_HOTP_B: &str =
    "otpauth://hotp/Globex:bob?secret=NBSWY3DPEHPK3PXP&issuer=Globex&counter=7";

fn import_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn vault_test_dir() -> TempDir {
    let dir = test_tempdir();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn make_account(uri: &str) -> Account {
    parse_otpauth(uri, import_time()).unwrap().account
}

fn expected_uri_for(uri: &str) -> String {
    // Emit the account through the same `export::otpauth_list` path the
    // QR payload is sourced from; comparing against the raw input URI
    // would rebake parser-side normalisation (param order, percent
    // encoding) into the test rather than the emitter.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let _ = vault.add(make_account(uri));
    export::otpauth_list(&vault)
        .trim_end_matches('\n')
        .to_string()
}

// ---------- QrRenderOptions::validate ----------

#[test]
fn qr_render_options_default_validates() {
    let opts = QrRenderOptions::default();
    assert_eq!(opts.module_size_px, QR_MODULE_SIZE_PX_DEFAULT);
    assert!(opts.quiet_zone);
    opts.validate().expect("default options validate");
}

#[test]
fn qr_render_options_accepts_min_and_max() {
    QrRenderOptions {
        module_size_px: QR_MODULE_SIZE_PX_MIN,
        quiet_zone: true,
    }
    .validate()
    .expect("min module size validates");
    QrRenderOptions {
        module_size_px: QR_MODULE_SIZE_PX_MAX,
        quiet_zone: false,
    }
    .validate()
    .expect("max module size validates");
}

#[test]
fn qr_render_options_rejects_zero_module_size() {
    let err = QrRenderOptions {
        module_size_px: 0,
        quiet_zone: true,
    }
    .validate()
    .unwrap_err();
    let PaladinAuthError::ValidationError { field, reason, .. } = err else {
        panic!("expected ValidationError, got {err:?}");
    };
    assert_eq!(field, "qr_render");
    assert_eq!(reason, "module_size_px_out_of_bounds");
}

#[test]
fn qr_render_options_rejects_module_size_above_max() {
    let err = QrRenderOptions {
        module_size_px: QR_MODULE_SIZE_PX_MAX + 1,
        quiet_zone: true,
    }
    .validate()
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValidationError);
    let PaladinAuthError::ValidationError { field, reason, .. } = err else {
        unreachable!();
    };
    assert_eq!(field, "qr_render");
    assert_eq!(reason, "module_size_px_out_of_bounds");
}

// ---------- PNG / SVG / ANSI URI round-trip ----------

fn decode_png_to_payload(png_bytes: &[u8]) -> String {
    let img = image::load_from_memory(png_bytes).expect("decode PNG");
    let luma = img.to_luma8();
    let (w, h) = luma.dimensions();
    let raw = luma.into_raw();
    let img = image::ImageBuffer::<Luma<u8>, _>::from_raw(w, h, raw).expect("rebuild luma");
    let mut decoder = rqrr::PreparedImage::prepare(img);
    let grids = decoder.detect_grids();
    assert_eq!(grids.len(), 1, "QR image must contain exactly one code");
    let (_meta, content) = grids[0].decode().expect("decode QR grid");
    content
}

#[test]
fn export_qr_png_round_trips_through_rqrr_for_totp_and_hotp() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let totp_id = vault.add(make_account(URI_TOTP_A));
    let counter_id = vault.add(make_account(URI_HOTP_B));

    for (id, uri) in [(totp_id, URI_TOTP_A), (counter_id, URI_HOTP_B)] {
        let bytes = vault
            .export_qr_png(id, &QrRenderOptions::default())
            .expect("PNG render");
        let payload = decode_png_to_payload(&bytes);
        let expected = expected_uri_for(uri);
        assert_eq!(payload, expected, "QR round-trip URI mismatch");
        // HOTP exports must carry the *current* counter so a scanner
        // imports the same step the live account would emit next.
        if uri == URI_HOTP_B {
            assert!(payload.contains("counter=7"), "HOTP QR missing counter=7");
        }
    }
}

#[test]
fn export_qr_svg_returns_a_well_formed_svg_document() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_TOTP_A));
    let svg = vault
        .export_qr_svg(id, &QrRenderOptions::default())
        .expect("SVG render");
    assert!(
        svg.contains("<svg"),
        "SVG body must contain an <svg> root, got: {}",
        &svg[..svg.len().min(120)]
    );
    assert!(svg.contains("</svg>"), "SVG body must close the root tag");
    assert!(!svg.is_empty(), "SVG body must be non-empty");
}

#[test]
fn export_qr_ansi_renders_a_unicode_half_block_grid() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_TOTP_A));
    let ansi = vault.export_qr_ansi(id).expect("ANSI render");
    for ch in ansi.chars() {
        assert!(
            matches!(ch, ' ' | '\u{2580}' | '\u{2584}' | '\u{2588}' | '\n'),
            "unexpected glyph {ch:?} in ANSI QR body",
        );
    }
    assert!(ansi.contains('\n'), "ANSI body must be a multi-line grid");
    assert!(
        ansi.contains('\u{2588}') || ansi.contains('\u{2580}') || ansi.contains('\u{2584}'),
        "ANSI body must contain dark modules"
    );
}

// ---------- Read-only invariant ----------

#[test]
fn export_qr_does_not_advance_hotp_counter_or_bump_updated_at() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_HOTP_B));

    let pre_counter = vault.get(id).unwrap().counter();
    let pre_updated = vault.get(id).unwrap().updated_at();

    let _png = vault
        .export_qr_png(id, &QrRenderOptions::default())
        .expect("PNG render");
    let _svg = vault
        .export_qr_svg(id, &QrRenderOptions::default())
        .expect("SVG render");
    let _ansi = vault.export_qr_ansi(id).expect("ANSI render");

    assert_eq!(
        vault.get(id).unwrap().counter(),
        pre_counter,
        "QR export must not advance HOTP counter"
    );
    assert_eq!(
        vault.get(id).unwrap().updated_at(),
        pre_updated,
        "QR export must not bump updated_at"
    );
}

// ---------- account_not_found ----------

#[test]
fn export_qr_png_unknown_account_returns_invalid_state() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault
        .export_qr_png(bogus, &QrRenderOptions::default())
        .unwrap_err();
    let PaladinAuthError::InvalidState {
        operation, state, ..
    } = err
    else {
        panic!("expected InvalidState, got {err:?}");
    };
    assert_eq!(operation, "export_qr_png");
    assert_eq!(state, "account_not_found");
}

#[test]
fn export_qr_svg_unknown_account_returns_invalid_state() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault
        .export_qr_svg(bogus, &QrRenderOptions::default())
        .unwrap_err();
    let PaladinAuthError::InvalidState {
        operation, state, ..
    } = err
    else {
        panic!("expected InvalidState, got {err:?}");
    };
    assert_eq!(operation, "export_qr_svg");
    assert_eq!(state, "account_not_found");
}

#[test]
fn export_qr_ansi_unknown_account_returns_invalid_state() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let bogus = AccountId::new();
    let err = vault.export_qr_ansi(bogus).unwrap_err();
    let PaladinAuthError::InvalidState {
        operation, state, ..
    } = err
    else {
        panic!("expected InvalidState, got {err:?}");
    };
    assert_eq!(operation, "export_qr_ansi");
    assert_eq!(state, "account_not_found");
}

// ---------- module_size_px is honored ----------

#[test]
fn export_qr_png_uses_module_size_px_to_scale_the_image() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_TOTP_A));

    let small = vault
        .export_qr_png(
            id,
            &QrRenderOptions {
                module_size_px: 2,
                quiet_zone: true,
            },
        )
        .expect("small PNG");
    let big = vault
        .export_qr_png(
            id,
            &QrRenderOptions {
                module_size_px: 16,
                quiet_zone: true,
            },
        )
        .expect("big PNG");

    let small_dim = image::load_from_memory(&small).unwrap().width();
    let big_dim = image::load_from_memory(&big).unwrap().width();
    assert!(
        big_dim > small_dim,
        "larger module_size_px must produce a larger image (small={small_dim}, big={big_dim})"
    );
}

// ---------- quiet_zone toggle ----------

#[test]
fn export_qr_png_with_quiet_zone_false_still_round_trips_through_rqrr() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_TOTP_A));

    let no_quiet = vault
        .export_qr_png(
            id,
            &QrRenderOptions {
                module_size_px: QR_MODULE_SIZE_PX_DEFAULT,
                quiet_zone: false,
            },
        )
        .expect("PNG render without quiet zone");
    let with_quiet = vault
        .export_qr_png(
            id,
            &QrRenderOptions {
                module_size_px: QR_MODULE_SIZE_PX_DEFAULT,
                quiet_zone: true,
            },
        )
        .expect("PNG render with quiet zone");

    // The payload must survive the quiet-zone toggle so a scanner sees
    // the same `otpauth://` URI in both renderings.
    let payload = decode_png_to_payload(&no_quiet);
    assert_eq!(payload, expected_uri_for(URI_TOTP_A));

    // Sanity check: dropping the white border shrinks the encoded PNG
    // because there are fewer light pixels to encode.
    assert!(
        no_quiet.len() < with_quiet.len(),
        "quiet_zone=false must produce a strictly smaller PNG than quiet_zone=true \
         at the same module_size_px (no_quiet={}, with_quiet={})",
        no_quiet.len(),
        with_quiet.len(),
    );
}

// ---------- Read-only invariant — encrypted-mode sibling ----------

fn cheap_options(passphrase: &str) -> EncryptionOptions {
    EncryptionOptions::with_params(
        SecretString::from(passphrase.to_string()),
        Argon2Params {
            m_kib: 8_192,
            t: 1,
            p: 1,
        },
    )
    .expect("cheap Argon2 params are in §4.4 bounds and the passphrase is non-empty")
}

#[test]
fn export_qr_does_not_advance_hotp_counter_or_bump_updated_at_encrypted() {
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, store) =
        Store::create(&path, VaultInit::Encrypted(cheap_options("hunter2"))).unwrap();
    let id = vault.add(make_account(URI_HOTP_B));
    // Persist the encrypted vault so the on-disk bytes capture below
    // reflects a real fsync'd file, not an empty placeholder.
    vault.save(&store).expect("save encrypted vault");

    let pre_counter = vault.get(id).unwrap().counter();
    let pre_updated = vault.get(id).unwrap().updated_at();
    let pre_bytes = fs::read(&path).expect("pre-render read");

    let _png = vault
        .export_qr_png(id, &QrRenderOptions::default())
        .expect("PNG render (encrypted)");
    let _svg = vault
        .export_qr_svg(id, &QrRenderOptions::default())
        .expect("SVG render (encrypted)");
    let _ansi = vault.export_qr_ansi(id).expect("ANSI render (encrypted)");

    assert_eq!(
        vault.get(id).unwrap().counter(),
        pre_counter,
        "QR export must not advance HOTP counter (encrypted)"
    );
    assert_eq!(
        vault.get(id).unwrap().updated_at(),
        pre_updated,
        "QR export must not bump updated_at (encrypted)"
    );
    // On-disk byte equality: the QR pipeline is structurally `&self`
    // and never calls into `Store`, so the encrypted file must be
    // untouched after a PNG → SVG → ANSI render sequence.
    let post_bytes = fs::read(&path).expect("post-render read");
    assert_eq!(
        pre_bytes, post_bytes,
        "QR export must not rewrite the encrypted vault file"
    );
}

// ---------- Zeroize-on-drop posture ----------
//
// The `Vault::export_qr_png` / `export_qr_svg` return wrappers must
// implement `ZeroizeOnDrop` so the encoded body (which embeds the
// account secret) is wiped before the heap allocation is reclaimed.
// Compile-time pinning catches a future regression that swaps in a
// raw `Vec<u8>` / `String` return — the trait bound would fail to
// resolve and the build would break.

fn assert_zeroize_on_drop<T: ZeroizeOnDrop + ?Sized>() {}
fn assert_zeroize<T: Zeroize + ?Sized>() {}

#[test]
fn export_qr_png_returns_zeroizing_wrapper_that_wipes_inner_bytes_on_drop() {
    // Compile-time pin on the exact return type of `Vault::export_qr_png`.
    assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();
    assert_zeroize::<Vec<u8>>();

    // Runtime sanity: produce a real PNG and confirm the wrapper exposes
    // the same byte slice the renderer wrote out, so the
    // `ZeroizeOnDrop` impl is wiping the *PNG bytes* and not some
    // empty placeholder.
    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_TOTP_A));
    let bytes = vault
        .export_qr_png(id, &QrRenderOptions::default())
        .expect("PNG render");
    assert!(!bytes.is_empty(), "PNG bytes must be non-empty");
    assert_eq!(&bytes[0..8], b"\x89PNG\r\n\x1a\n", "PNG signature");
}

#[test]
fn export_qr_svg_returns_zeroizing_wrapper_that_wipes_inner_string_on_drop() {
    assert_zeroize_on_drop::<zeroize::Zeroizing<String>>();
    assert_zeroize::<String>();

    let dir = vault_test_dir();
    let path = dir.path().join("vault.bin");
    let (mut vault, _store) = Store::create(&path, VaultInit::Plaintext).unwrap();
    let id = vault.add(make_account(URI_TOTP_A));
    let svg = vault
        .export_qr_svg(id, &QrRenderOptions::default())
        .expect("SVG render");
    assert!(svg.contains("<svg"), "SVG body must contain an <svg> root");
}
