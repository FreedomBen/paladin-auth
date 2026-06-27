// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-level guardrail for `docs/IMPLEMENTATION_PLAN_04_GTK.md`
//! §"Milestone 7 checklist" → "Secret-entry ownership and zeroization
//! guardrails".
//!
//! Per `docs/DESIGN.md` §8 and the plan's §"Secret entry handling", the
//! following secret-bearing values must never live in the long-lived
//! `AppModel`, `AppMsg`, dialog `*Output`, `AppInit`, or `AppState`
//! types — they must stay in modal-local
//! [`crate::secret_fields::SecretEntry`] /
//! [`zeroize::Zeroizing`] /
//! [`secrecy::SecretString`] / typed
//! [`paladin_auth_core`] wrappers ([`paladin_auth_core::VaultLock`],
//! [`paladin_auth_core::VaultInit`], [`paladin_auth_core::EncryptionOptions`],
//! [`paladin_auth_core::Account`], …) so the bytes zeroize on drop:
//!
//! * Passphrases
//! * Manual Base32 secrets
//! * `otpauth://` URI text
//! * HOTP reveal codes
//! * Pending clipboard-clear payloads
//! * Pending duplicate / create values
//!
//! Dialog-local `*Msg` types are explicitly allowed to carry `String`
//! at the unavoidable §8 keystroke boundary (e.g.
//! `InitDialogMsg::PassphraseChanged(String)`) — the bytes transit
//! the relm4 channel briefly before the handler shadows them into a
//! [`crate::secret_fields::SecretEntry`] and the local `String` drops.
//! This guard inspects `AppMsg` and the seven dialog `*Output` enums
//! (which cross into the long-lived `AppMsg::*Action` forwarder chain)
//! plus `AppModel` / `AppInit` / `AppState` fields, so the §8
//! boundary contract is enforced source-side.
//!
//! Pairs with `tests/secret_fields_logic.rs` (which exercises
//! lifecycle clearing of the zeroizing buffers themselves) and
//! `tests/thinness.rs` (which keeps crypto / OTP / storage primitives
//! out of the GTK crate). Together they pin the §8 invariants without
//! a display server.

use std::fs;
use std::path::{Path, PathBuf};

/// Files containing the long-lived types that must never carry raw
/// secret-bearing strings. Each `(path, types)` entry pins which
/// type declarations the scanner inspects in that file.
const LONG_LIVED_TYPES: &[(&str, &[&str])] = &[
    (
        "src/app/model.rs",
        &["AppMsg", "AppModel", "AppInit", "StartupOutcome"],
    ),
    ("src/app/state.rs", &["AppState"]),
];

/// Dialog `*Output` enums to scan. Outputs cross the dialog boundary
/// and are forwarded as `AppMsg::*Action(*Output)`, so they live in
/// the same long-lived state space as `AppMsg` itself.
const DIALOG_OUTPUT_ENUMS: &[(&str, &str)] = &[
    ("src/init_dialog.rs", "InitDialogOutput"),
    ("src/unlock_dialog.rs", "UnlockDialogOutput"),
    ("src/add_account.rs", "AddAccountOutput"),
    ("src/edit_dialog.rs", "EditDialogOutput"),
    ("src/remove_dialog.rs", "RemoveDialogOutput"),
    ("src/import_dialog.rs", "ImportDialogOutput"),
    ("src/export_dialog.rs", "ExportDialogOutput"),
    ("src/passphrase_dialog.rs", "PassphraseDialogOutput"),
];

/// Raw payload spellings that suggest a secret-bearing primitive
/// has leaked into a long-lived type. Pinned as a whole-word match
/// (see [`contains_forbidden_token`]) so legitimate uses like
/// `Option<PathBuf>` or `Box<dyn Trait>` stay clear.
const FORBIDDEN_RAW_TYPES: &[&str] = &["String", "Vec<u8>", "Box<str>", "&str"];

/// Per-type allowlist of trimmed field declarations that the
/// [`forbidden_token_in`] scan should skip when checking
/// [`FORBIDDEN_RAW_TYPES`]. Entries cover two vetted cases:
///
/// 1. Non-secret plaintext (typed user input that never names a
///    passphrase / Base32 secret / `otpauth://` URI / HOTP reveal
///    code / clipboard payload).
/// 2. Secret-bearing bytes that satisfy DESIGN §8 through an inner
///    wrapper (`zeroize::Zeroizing`, `secrecy::SecretString`) — the
///    literal source text still contains a `Vec<u8>` / `String`
///    substring that the dumb whole-word scanner cannot see through,
///    so the wrapped declaration is recorded here explicitly.
///
/// Each entry pairs the long-lived type name from [`LONG_LIVED_TYPES`]
/// with the complete `<field>: <type>,` declaration
/// (whitespace-trimmed). The match is exact so a future refactor
/// that changes the type or renames the field forces a fresh
/// review of the allowlist.
const KNOWN_NON_SECRET_LINES: &[(&str, &[&str])] = &[
    // `search_query` mirrors `AccountListComponent::current_query` —
    // the literal substring the user typed into the `gtk::SearchEntry`
    // that drives `paladin_auth_core::account_matches_search` against
    // issuer / label text. Per `docs/IMPLEMENTATION_PLAN_04_GTK.md`
    // §"Component tree" > `AccountListComponent` and DESIGN §8, the
    // search query is not one of the secret-bearing values that must
    // be wrapped in zeroizing storage.
    ("AppModel", &["search_query: String,"]),
    // `ClipboardWakeRead::current` carries the live `gdk::Clipboard`
    // text the per-tick wake just read. The buffer may itself be an
    // OTP (the user has not yet pasted), so the bytes are wrapped in
    // `zeroize::Zeroizing` per the
    // [`crate::clipboard_clear::PendingClipboardClear::value`]
    // contract — the message drops the wrapper on the next dispatch
    // and the bytes wipe in place. Pinned here because the inner
    // `Vec<u8>` substring trips the whole-word scanner.
    ("AppMsg", &["current: zeroize::Zeroizing<Vec<u8>>,"]),
];

/// Identifier substrings (case-insensitive) whose presence in a
/// variant declaration signals that the variant is conveying one of
/// the secret-bearing values DESIGN §8 enumerates: passphrases,
/// manual Base32 secrets, `otpauth://` URI text, HOTP reveal codes,
/// or pending clipboard-clear payloads. The
/// [`dialog_output_enums_carry_no_raw_secret_bearing_strings`] test
/// flags variants whose declaration contains one of these markers
/// alongside a [`FORBIDDEN_RAW_TYPES`] spelling.
///
/// Plain plaintext labels (account label, issuer, file path) are
/// *not* on the §8 list and are deliberately omitted so legitimate
/// variants like `AddAccountOutput::SubmitManual { label: String, .. }`
/// continue to pass.
const SECRET_NAME_MARKERS: &[&str] = &[
    "passphrase",
    "phrase",
    "secret",
    "cleartext",
    "otpauth",
    "uri",
    "clipboard",
    "hotpcode",
    "totpcode",
    "revealcode",
];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Read a source file with a helpful panic message on failure.
fn read_source(rel: &str) -> String {
    let path = crate_root().join(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read {} (relative to crate root): {err}", path.display()))
}

/// Strip an end-of-line `// …` comment from `line` (preserves leading
/// whitespace; treats `//!` and `///` the same — they're still
/// comments for the purpose of this scan).
fn strip_line_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

/// Walk braces in `source` starting from `open_idx` (which must point
/// at an `{`) and return the byte offset of the matching `}`.
///
/// Naïve match — does not handle `{` / `}` inside string literals or
/// comments, but the scanned blocks are Rust type bodies where literal
/// braces are vanishingly rare. The strip-line-comment pass above
/// already covers `// …` trailing comments, which is the only case
/// likely to appear in the inspected enums / structs.
fn matching_close_brace(source: &str, open_idx: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    assert_eq!(bytes[open_idx], b'{');
    let mut depth: i32 = 1;
    let mut i = open_idx + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Extract the `{ … }` body of a top-level `pub enum <name>` or
/// `pub struct <name>` declaration from `source`. Returns the byte
/// range of the body (without the surrounding braces) or `None` if
/// the type is not declared in `source`.
fn extract_type_body<'a>(source: &'a str, name: &str) -> Option<&'a str> {
    for prefix in [
        format!("pub enum {name} "),
        format!("pub enum {name}\n"),
        format!("pub enum {name}{{"),
        format!("pub struct {name} "),
        format!("pub struct {name}\n"),
        format!("pub struct {name}{{"),
    ] {
        if let Some(start) = source.find(prefix.as_str()) {
            let from = start + prefix.len() - 1;
            let open_idx = source[from..].find('{').map(|i| from + i)?;
            let close_idx = matching_close_brace(source, open_idx)?;
            return Some(&source[open_idx + 1..close_idx]);
        }
    }
    None
}

/// Whole-word match for `token` in `text` (Rust identifier rules:
/// no adjacent ASCII alphanumeric or `_`). Lets the scan ignore
/// substrings like `PathBuf` while still catching bare `String`.
fn contains_forbidden_token(text: &str, token: &str) -> bool {
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find(token) {
        let abs = search_from + rel;
        let before = text.as_bytes().get(abs.wrapping_sub(1));
        let after = text.as_bytes().get(abs + token.len());
        let before_ok = match before {
            None => true,
            Some(&b) => !(b.is_ascii_alphanumeric() || b == b'_'),
        };
        let after_ok = match after {
            None => true,
            Some(&b) => !(b.is_ascii_alphanumeric() || b == b'_'),
        };
        if before_ok && after_ok {
            return true;
        }
        search_from = abs + token.len();
    }
    false
}

/// Return the first forbidden raw-type token that appears in `text`,
/// scanning line-by-line so end-of-line `// …` comments are skipped.
///
/// `allowlist` carries trimmed field declarations that the scan
/// skips even when they contain a forbidden token, so vetted
/// non-secret plaintext fields (see [`KNOWN_NON_SECRET_LINES`]) do
/// not regress the test.
fn forbidden_token_in(text: &str, allowlist: &[&str]) -> Option<&'static str> {
    for raw_line in text.lines() {
        let code = strip_line_comment(raw_line);
        let trimmed = code.trim();
        if !trimmed.is_empty() && allowlist.contains(&trimmed) {
            continue;
        }
        for &token in FORBIDDEN_RAW_TYPES {
            if contains_forbidden_token(code, token) {
                return Some(token);
            }
        }
    }
    None
}

/// Case-insensitive substring search for one of [`SECRET_NAME_MARKERS`]
/// against `text` (already comment-stripped). Used by the dialog-
/// `*Output` scan to decide whether a `String`-bearing variant looks
/// like it conveys a §8 secret value vs. a legitimate plaintext field
/// (a label, an issuer, a file path).
fn contains_secret_marker(text: &str) -> Option<&'static str> {
    let lower = text.to_ascii_lowercase();
    SECRET_NAME_MARKERS
        .iter()
        .find(|marker| lower.contains(*marker))
        .copied()
}

/// Split an enum body into variant declarations. Each returned slice
/// covers one variant's complete declaration text (variant name plus
/// any tuple `(...)` or struct `{ ... }` payload), with trailing
/// commas trimmed. End-of-line `// …` comments are stripped so the
/// substring searches do not pick up doc-comment prose.
fn split_variants(body: &str) -> Vec<String> {
    // Concatenate the comment-stripped lines into a single buffer so
    // multi-line variant declarations (e.g.
    // `Submit { … account: Account, … },`) survive intact.
    let mut buf = String::new();
    for raw_line in body.lines() {
        buf.push_str(strip_line_comment(raw_line));
        buf.push('\n');
    }
    // Walk byte-by-byte, splitting on top-level commas only.
    let bytes = buf.as_bytes();
    let mut variants = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0i32;
    let mut brace_depth = 0i32;
    let mut angle_depth = 0i32;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => paren_depth += 1,
            b')' => paren_depth -= 1,
            b'{' => brace_depth += 1,
            b'}' => brace_depth -= 1,
            b'<' => angle_depth += 1,
            b'>' => angle_depth -= 1,
            b',' if paren_depth == 0 && brace_depth == 0 && angle_depth == 0 => {
                let variant = buf[start..i].trim();
                if !variant.is_empty() {
                    variants.push(variant.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let tail = buf[start..].trim();
    if !tail.is_empty() {
        variants.push(tail.to_string());
    }
    variants
}

#[test]
fn long_lived_types_carry_no_raw_secret_bearing_strings() {
    // The `AppModel`, `AppMsg`, `AppInit`, `StartupOutcome`, and
    // `AppState` types live for the duration of the GTK process and
    // are forwarded across `relm4::ComponentSender` channels. Any
    // `String` / `Vec<u8>` field in them would carry secret-bearing
    // bytes in non-zeroizing storage — exactly the leak DESIGN §8
    // forbids. Typed wrappers (`PathBuf`, `Option<PathBuf>`,
    // dialog-`*Output` enums, `paladin_auth_core` types) are the
    // allowed shape.
    let mut offenses = Vec::new();
    for (rel, type_names) in LONG_LIVED_TYPES {
        let source = read_source(rel);
        for name in *type_names {
            let body = extract_type_body(&source, name)
                .unwrap_or_else(|| panic!("expected to find pub enum/struct `{name}` in {rel}"));
            let allowlist = KNOWN_NON_SECRET_LINES
                .iter()
                .find(|(ty, _)| *ty == *name)
                .map_or(&[][..], |(_, lines)| *lines);
            if let Some(token) = forbidden_token_in(body, allowlist) {
                offenses.push(format!(
                    "{rel}: `{name}` carries forbidden raw type `{token}` — \
                     wrap secret-bearing bytes in \
                     `crate::secret_fields::SecretEntry`, `zeroize::Zeroizing`, \
                     `secrecy::SecretString`, or a typed `paladin_auth_core` value \
                     per docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Secret entry handling\""
                ));
            }
        }
    }
    assert!(
        offenses.is_empty(),
        "long-lived `AppModel` / `AppMsg` / `AppState` types must not carry \
         raw secret-bearing strings:\n{}",
        offenses.join("\n"),
    );
}

#[test]
fn dialog_output_enums_carry_no_raw_secret_bearing_strings() {
    // Dialog `*Output` enums cross into `AppMsg::*Action(*Output)`
    // forwarders and therefore live in the same long-lived state
    // space as `AppMsg` itself. Variants conveying one of the §8
    // secret values (passphrase, manual Base32 secret, `otpauth://`
    // URI, HOTP reveal code, clipboard payload) must carry typed
    // wrappers (`VaultLock`, `VaultInit`, `Account`, `SecretString`,
    // …) — never raw `String` / `Vec<u8>`.
    //
    // Variants conveying plain plaintext (a rename label, an account
    // issuer, a destination file path) are *not* on the §8 list and
    // pass even when they carry a `String` — the variant name has to
    // suggest a secret value before the test flags it.
    //
    // The matching dialog-local `*Msg` enums are *not* inspected here:
    // those carry `String` only at the unavoidable §8 keystroke
    // boundary (e.g. `InitDialogMsg::PassphraseChanged(String)`),
    // where the handler shadows the bytes into a
    // [`crate::secret_fields::SecretEntry`] before they outlive the
    // single `update` call.
    let mut offenses = Vec::new();
    for (rel, enum_name) in DIALOG_OUTPUT_ENUMS {
        let source = read_source(rel);
        let body = extract_type_body(&source, enum_name)
            .unwrap_or_else(|| panic!("expected to find pub enum `{enum_name}` in {rel}"));
        for variant in split_variants(body) {
            let (Some(marker), Some(token)) = (
                contains_secret_marker(&variant),
                forbidden_token_in(&variant, &[]),
            ) else {
                continue;
            };
            offenses.push(format!(
                "{rel}: `{enum_name}` variant `{variant}` looks like it \
                 conveys a §8 secret (marker `{marker}`) and carries \
                 forbidden raw type `{token}` — wrap the bytes in \
                 `secrecy::SecretString`, `zeroize::Zeroizing`, or a typed \
                 `paladin_auth_core` value per \
                 docs/IMPLEMENTATION_PLAN_04_GTK.md §\"Secret entry handling\""
            ));
        }
    }
    assert!(
        offenses.is_empty(),
        "dialog `*Output` enums must not carry raw secret-bearing strings:\n{}",
        offenses.join("\n"),
    );
}

#[test]
fn split_variants_handles_unit_tuple_and_struct_variants() {
    // Self-test: confirm the variant splitter recognises all three
    // Rust enum-variant shapes (unit, tuple, struct) and respects
    // brace / paren / angle-bracket nesting when looking for the
    // separating comma. Catches regressions if the byte walker loses
    // a depth counter.
    let body = "
        Cancel,
        Submit(Account),
        SubmitDetails {
            id: AccountId,
            label: String,
            now: SystemTime,
        },
    ";
    let variants = split_variants(body);
    assert_eq!(variants.len(), 3, "got {variants:?}");
    assert!(variants[0].starts_with("Cancel"));
    assert!(variants[1].starts_with("Submit(Account)"));
    assert!(variants[2].starts_with("SubmitDetails"));
    // The struct-variant body survived intact through the brace nesting.
    assert!(variants[2].contains("label: String"));
}

#[test]
fn contains_secret_marker_self_test() {
    // Self-test: confirm the marker lookup catches the §8 vocabulary
    // (case-insensitive) and ignores benign identifiers. A regression
    // here would silently let a "PassphraseSubmitted(String)" variant
    // slip past the dialog-output scan.
    assert!(contains_secret_marker("SubmitPassphrase(String)").is_some());
    assert!(contains_secret_marker("OtpauthUri { uri: String }").is_some());
    assert!(contains_secret_marker("ClipboardClear { payload: Vec<u8> }").is_some());
    // Plain plaintext fields stay clean.
    assert!(contains_secret_marker("SubmitLabel { label: String }").is_none());
    assert!(contains_secret_marker("PickFile { destination: PathBuf }").is_none());
}

#[test]
fn forbidden_token_scan_recognizes_string() {
    // Self-test: confirm the scanner actually rejects a synthetic
    // body that contains a bare `String`. Guards against a future
    // refactor accidentally short-circuiting the matcher.
    let synthetic = "    Passphrase(String),\n";
    assert_eq!(forbidden_token_in(synthetic, &[]), Some("String"));
}

#[test]
fn forbidden_token_scan_ignores_pathbuf_and_string_inside_identifiers() {
    // Self-test: confirm legitimate uses (`PathBuf`,
    // `format_string_helper`, `SecretString` re-export) do *not*
    // trip the scanner. Whole-word matching is the invariant.
    let synthetic = "    path: PathBuf,\n    helper: SecretString,\n";
    assert_eq!(forbidden_token_in(synthetic, &[]), None);
}

#[test]
fn forbidden_token_scan_skips_trailing_line_comments() {
    // Self-test: confirm a `// String` comment does not trip the
    // scanner. Otherwise documentation that mentions `String` in
    // prose would force noisy renames.
    let synthetic = "    pub path: PathBuf, // String would be wrong here\n";
    assert_eq!(forbidden_token_in(synthetic, &[]), None);
}

#[test]
fn forbidden_token_scan_skips_allowlisted_lines() {
    // Self-test: confirm the `allowlist` parameter lets vetted
    // non-secret fields through even when they contain a forbidden
    // token. The exact trimmed match is what
    // `long_lived_types_carry_no_raw_secret_bearing_strings` uses to
    // honor `KNOWN_NON_SECRET_LINES`.
    let synthetic = "    search_query: String,\n    other: String,\n";
    assert_eq!(
        forbidden_token_in(synthetic, &["search_query: String,"]),
        Some("String"),
        "allowlist must skip only the matching line — `other: String,` still trips the scan",
    );
    assert_eq!(
        forbidden_token_in("    search_query: String,\n", &["search_query: String,"],),
        None,
        "an isolated allowlisted line clears the scan",
    );
}

#[test]
fn extract_type_body_finds_enum_and_struct_declarations() {
    // Self-test: confirm the body extractor works against both the
    // `pub enum` and `pub struct` declaration shapes used by the
    // scan list. Catches regressions if the prefix table loses a
    // shape variant.
    let synthetic_enum = "pub enum Foo {\n    Bar,\n    Baz(u32),\n}\n";
    assert_eq!(
        extract_type_body(synthetic_enum, "Foo"),
        Some("\n    Bar,\n    Baz(u32),\n")
    );
    let synthetic_struct = "pub struct Foo {\n    a: u32,\n}\n";
    assert_eq!(
        extract_type_body(synthetic_struct, "Foo"),
        Some("\n    a: u32,\n")
    );
}

#[test]
fn long_lived_types_targets_exist() {
    // Self-test: confirm every entry in `LONG_LIVED_TYPES` and
    // `DIALOG_OUTPUT_ENUMS` points at a real source file. Catches
    // typos in the table that would otherwise silently skip a
    // scan target.
    for (rel, _) in LONG_LIVED_TYPES {
        let path: &Path = &crate_root().join(rel);
        assert!(
            path.exists(),
            "long-lived-types table references missing file {}",
            path.display()
        );
    }
    for (rel, _) in DIALOG_OUTPUT_ENUMS {
        let path: &Path = &crate_root().join(rel);
        assert!(
            path.exists(),
            "dialog-output table references missing file {}",
            path.display()
        );
    }
}
