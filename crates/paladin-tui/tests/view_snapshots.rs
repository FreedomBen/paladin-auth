// SPDX-License-Identifier: AGPL-3.0-or-later

//! ratatui rendering snapshots for `paladin-tui`.
//!
//! Each test drives one [`AppState`] variant through the view
//! pipeline using [`ratatui::backend::TestBackend`] (no real
//! terminal, no I/O), then converts the resulting [`Buffer`] into a
//! deterministic text grid and asserts it via `insta::assert_snapshot!`.
//! Insta stores accepted output in `tests/snapshots/` so any
//! regression shows up as a `git diff`-readable text change.
//!
//! Tracks the "Tests > Insta snapshots" checklist in
//! `docs/IMPLEMENTATION_PLAN_03_TUI.md`. Two parallel serializers cover
//! the rendered grid:
//!
//!   * [`buffer_to_text`] / [`render_to_text`] emit a symbol-only
//!     grid (foreground / background / modifiers are intentionally
//!     dropped). Used by the existing `snapshot_*` tests so the
//!     primary `.snap` files stay diff-readable.
//!   * [`buffer_to_styled_text`] / [`render_to_styled_text`] emit
//!     the same symbol grid followed by a deterministic style
//!     annotation section listing each consecutive run of cells
//!     whose `(fg, bg, modifier)` triple differs from the default
//!     `(Color::Reset, Color::Reset, Modifier::empty())`. Used by
//!     the list-view `_no_color` companion snapshots so a future
//!     regression that ever leaks color into the `no_color = true`
//!     path surfaces as new entries in the styles section.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ratatui::backend::TestBackend;
use ratatui::buffer::{Buffer, Cell};
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyModifiers};

use paladin_core::{
    format_plaintext_export_warning, format_unsafe_permissions, format_validation_warning,
    hotp_reveal_deadline, validate_manual, AccountId, AccountInput, AccountKindInput, Algorithm,
    IconHintInput, PaladinError, PermissionSubject, Store, ValidationWarning, Vault, VaultInit,
    VaultLock,
};
use paladin_tui::app::event::{AppEvent, EffectResult, QrImportFailure};
use paladin_tui::app::reducer::reduce;
use paladin_tui::app::state::{
    format_account_display_label, format_duplicate_account_message, format_qr_import_failure,
    render_error_message, AddModal, AddMode, AppState, CountsPanel, CreateVaultMode,
    CreateVaultStep, EditFocus, EditIconHintSelector, EditModal, EditPrior, ExportFormat,
    ExportModal, Focus, HotpReveal, ImportModal, Modal, PassphraseFieldFocus, PassphraseModal,
    PassphraseSubFlow, PendingDuplicateAdd, QrSaveFocus, QrSaveStep, RemoveModal, RenameModal,
    SettingsModal, StatusLine, CLIPBOARD_WRITE_FAILED, NO_ACCOUNT_SELECTED,
};
use paladin_tui::prompt::PassphraseBuffer;
use paladin_tui::view::render;
use secrecy::SecretString;

mod common;
use common::secure_test_tempdir;

/// Fixed wall-clock time threaded through every list-view snapshot so the
/// TOTP code / gauge / `seconds_remaining` cells stay deterministic across
/// hosts. `1_500_000_012 mod 30 == 12`, so for a 30-second TOTP window
/// the cursor sits 12 s in and 18 s remain — matching the
/// `docs/DESIGN.md` §6 mock's `18s` and yielding a 6-of-10-cell gauge.
const SNAPSHOT_NOW_SECS: u64 = 1_500_000_012;

fn snapshot_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(SNAPSHOT_NOW_SECS)
}

/// Draw `state` into an `width × height` [`TestBackend`] and return
/// the resulting text grid (one line per row, cell symbols only). The
/// `now` parameter is forwarded to the list-view renderer so TOTP
/// rows compute against a deterministic wall-clock instead of the
/// host's real time.
///
/// `no_color = false` is passed through unconditionally so the
/// existing symbol-only snapshots stay byte-identical regardless of
/// the renderer's `--no-color` gating; the `no_color = true` branch
/// is exercised in `tests/no_color_tests.rs`, which inspects the
/// cell fg/bg attributes that `buffer_to_text` deliberately strips.
fn render_to_text(state: &AppState, now: SystemTime, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal
        .draw(|frame| render(frame, state, now, false))
        .expect("draw frame");
    buffer_to_text(terminal.backend().buffer())
}

/// Serialize a ratatui [`Buffer`] as one line per terminal row.
///
/// Cell symbols are joined verbatim (multi-codepoint graphemes like
/// box-drawing characters are preserved); styling is intentionally
/// dropped so the snapshot diffs stay readable.
fn buffer_to_text(buffer: &Buffer) -> String {
    let area = buffer.area();
    let width = area.width;
    let height = area.height;
    let mut out = String::with_capacity((width as usize + 1) * height as usize);
    for y in 0..height {
        for x in 0..width {
            out.push_str(buffer[(x, y)].symbol());
        }
        // Trim trailing spaces so the snapshot file is friendlier to
        // diff and to editors with "strip-trailing-whitespace" hooks.
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    }
    out
}

/// Header that introduces the styles annotation section emitted by
/// [`buffer_to_styled_text`]. Pinned as a separate constant so the
/// unit tests below and the snapshot files share an exact byte
/// sequence; a rewording here drives a single update across both.
const STYLES_SECTION_HEADER: &str = "─── styles ───\n";

/// Sentinel written into the styles section when no cell in the
/// buffer carries a non-default `(fg, bg, modifier)` triple.
const STYLES_SECTION_EMPTY_MARKER: &str = "(none)\n";

/// `(fg, bg, modifier)` triple captured per cell by
/// [`buffer_to_styled_text`]. Cells whose signature equals
/// [`DEFAULT_STYLE_SIG`] are unstyled and skipped.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct StyleSig {
    fg: Color,
    bg: Color,
    modifier: Modifier,
}

const DEFAULT_STYLE_SIG: StyleSig = StyleSig {
    fg: Color::Reset,
    bg: Color::Reset,
    modifier: Modifier::empty(),
};

fn cell_style_signature(cell: &Cell) -> StyleSig {
    StyleSig {
        fg: cell.fg,
        bg: cell.bg,
        modifier: cell.modifier,
    }
}

fn format_style_signature(sig: StyleSig) -> String {
    let modifier_repr = if sig.modifier.is_empty() {
        "NONE".to_string()
    } else {
        format!("{:?}", sig.modifier)
    };
    format!("fg={:?} bg={:?} mod={modifier_repr}", sig.fg, sig.bg)
}

/// Serialize a ratatui [`Buffer`] as the symbol grid (identical to
/// [`buffer_to_text`]) followed by a deterministic style annotation
/// section. The styles section lists, in row-major order, each
/// consecutive run of cells whose `(fg, bg, modifier)` triple differs
/// from the default `(Color::Reset, Color::Reset, Modifier::empty())`;
/// cells with the default style are omitted. If no cell carries a
/// non-default style, the section is the [`STYLES_SECTION_EMPTY_MARKER`]
/// sentinel so the absence is still pinned.
///
/// Used by the list-view `_no_color` snapshot variants: under
/// `no_color = true` the renderer drops the foreground attribute on
/// status-line `Error` / `Confirmation` cells, so the styles section
/// of those snapshots is `(none)`. A regression that ever leaks
/// color into the no-color path adds entries to the section,
/// surfacing as a diff in the snapshot file. The companion symbol-
/// only snapshots locked by [`buffer_to_text`] / [`render_to_text`]
/// remain in place to pin the rendered text grid itself.
fn buffer_to_styled_text(buffer: &Buffer) -> String {
    use std::fmt::Write as _;

    let mut out = buffer_to_text(buffer);
    out.push_str(STYLES_SECTION_HEADER);

    let area = buffer.area();
    let width = area.width;
    let height = area.height;
    let mut any_styled = false;
    for y in 0..height {
        let mut x: u16 = 0;
        while x < width {
            let sig = cell_style_signature(&buffer[(x, y)]);
            if sig == DEFAULT_STYLE_SIG {
                x += 1;
                continue;
            }
            let start = x;
            let mut run_text = String::new();
            run_text.push_str(buffer[(x, y)].symbol());
            x += 1;
            while x < width && cell_style_signature(&buffer[(x, y)]) == sig {
                run_text.push_str(buffer[(x, y)].symbol());
                x += 1;
            }
            let end = x;
            let _ = writeln!(
                &mut out,
                "({start}..{end}, {y}) {run_text:?} {sig_repr}",
                sig_repr = format_style_signature(sig),
            );
            any_styled = true;
        }
    }
    if !any_styled {
        out.push_str(STYLES_SECTION_EMPTY_MARKER);
    }
    out
}

/// Drive `state` through the view pipeline with the supplied
/// `no_color` flag and serialize the resulting [`Buffer`] via
/// [`buffer_to_styled_text`]. Used by the `_no_color` list-view
/// snapshot variants to lock the no-color-mode style contract; see
/// [`render_to_text`] for the symbol-only sibling used by the
/// existing styled snapshots.
fn render_to_styled_text(
    state: &AppState,
    now: SystemTime,
    no_color: bool,
    width: u16,
    height: u16,
) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal
        .draw(|frame| render(frame, state, now, no_color))
        .expect("draw frame");
    buffer_to_styled_text(terminal.backend().buffer())
}

#[cfg(test)]
mod styled_serializer_tests {
    use super::{
        buffer_to_styled_text, format_style_signature, StyleSig, DEFAULT_STYLE_SIG,
        STYLES_SECTION_EMPTY_MARKER, STYLES_SECTION_HEADER,
    };
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use ratatui::style::{Color, Modifier, Style};

    fn styles_section(serialized: &str) -> &str {
        serialized
            .rsplit_once(STYLES_SECTION_HEADER)
            .expect("STYLES_SECTION_HEADER must appear exactly once")
            .1
    }

    #[test]
    fn default_style_sig_uses_reset_colors_and_empty_modifier() {
        // Pins the default contract `buffer_to_styled_text` keys
        // off so a future ratatui upgrade that changes `Cell`'s
        // default (e.g. swapping `Color::Reset` for a richer
        // "inherit" value) surfaces here rather than as a silently
        // populated styles section in every snapshot.
        assert_eq!(
            DEFAULT_STYLE_SIG,
            StyleSig {
                fg: Color::Reset,
                bg: Color::Reset,
                modifier: Modifier::empty(),
            },
        );
    }

    #[test]
    fn format_style_signature_renders_empty_modifier_as_none() {
        let sig = StyleSig {
            fg: Color::Red,
            bg: Color::Reset,
            modifier: Modifier::empty(),
        };
        assert_eq!(format_style_signature(sig), "fg=Red bg=Reset mod=NONE");
    }

    #[test]
    fn format_style_signature_renders_non_empty_modifier_via_debug() {
        let sig = StyleSig {
            fg: Color::Reset,
            bg: Color::Reset,
            modifier: Modifier::BOLD,
        };
        assert_eq!(format_style_signature(sig), "fg=Reset bg=Reset mod=BOLD");
    }

    #[test]
    fn buffer_to_styled_text_appends_none_marker_when_no_cell_is_styled() {
        let buf = Buffer::empty(Rect::new(0, 0, 3, 2));
        let out = buffer_to_styled_text(&buf);
        assert!(
            out.ends_with(&format!(
                "{STYLES_SECTION_HEADER}{STYLES_SECTION_EMPTY_MARKER}"
            )),
            "expected styles section to be `(none)` for an empty buffer, got:\n{out}",
        );
        assert_eq!(styles_section(&out), STYLES_SECTION_EMPTY_MARKER);
    }

    #[test]
    fn buffer_to_styled_text_lists_red_fg_cells_with_run_compaction() {
        // Build a 5x2 buffer; cells (0..3, 0) carry `Color::Red`,
        // every other cell stays default. The serializer must emit
        // exactly one run entry and no spurious row-1 entry.
        let mut buf = Buffer::empty(Rect::new(0, 0, 5, 2));
        buf.set_string(0, 0, "Err", Style::default().fg(Color::Red));
        let out = buffer_to_styled_text(&buf);
        assert_eq!(
            styles_section(&out),
            "(0..3, 0) \"Err\" fg=Red bg=Reset mod=NONE\n",
        );
    }

    #[test]
    fn buffer_to_styled_text_starts_a_new_run_when_style_changes() {
        // Two adjacent runs with differing fg colors must split
        // into two entries, with the second run's x-start aligned
        // to where the first run ended.
        let mut buf = Buffer::empty(Rect::new(0, 0, 6, 1));
        buf.set_string(0, 0, "Er", Style::default().fg(Color::Red));
        buf.set_string(2, 0, "Ok", Style::default().fg(Color::Green));
        let out = buffer_to_styled_text(&buf);
        assert_eq!(
            styles_section(&out),
            "(0..2, 0) \"Er\" fg=Red bg=Reset mod=NONE\n\
             (2..4, 0) \"Ok\" fg=Green bg=Reset mod=NONE\n",
        );
    }

    #[test]
    fn buffer_to_styled_text_captures_bold_modifier() {
        let mut buf = Buffer::empty(Rect::new(0, 0, 3, 1));
        buf.set_string(0, 0, "Hi", Style::default().add_modifier(Modifier::BOLD));
        let out = buffer_to_styled_text(&buf);
        assert_eq!(
            styles_section(&out),
            "(0..2, 0) \"Hi\" fg=Reset bg=Reset mod=BOLD\n",
        );
    }

    #[test]
    fn buffer_to_styled_text_keeps_symbol_grid_unchanged_above_section_header() {
        // A regression that ever reformats the symbol-grid portion
        // of the styled output would invalidate the existing
        // symbol-only `.snap` files. Pin that the prefix above
        // `STYLES_SECTION_HEADER` matches `buffer_to_text` byte-for-
        // byte.
        let mut buf = Buffer::empty(Rect::new(0, 0, 4, 1));
        buf.set_string(0, 0, "AB", Style::default().fg(Color::Red));
        let styled = buffer_to_styled_text(&buf);
        let grid_only = super::buffer_to_text(&buf);
        assert!(
            styled.starts_with(&grid_only),
            "expected styled output to start with the symbol grid, got:\n{styled}\nexpected prefix:\n{grid_only}",
        );
        // And the styles section sits immediately after the grid.
        assert_eq!(
            &styled[grid_only.len()..grid_only.len() + STYLES_SECTION_HEADER.len()],
            STYLES_SECTION_HEADER,
        );
    }
}

#[test]
fn snapshot_create_vault_screen() {
    let state = AppState::create_vault_initial(PathBuf::from("/var/lib/paladin/vault.bin"));
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_create_vault_choose_mode_plaintext_selected() {
    let state = AppState::CreateVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        step: CreateVaultStep::ChooseMode {
            selection: CreateVaultMode::Plaintext,
        },
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_create_vault_confirm_plaintext() {
    let state = AppState::CreateVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        step: CreateVaultStep::ConfirmPlaintext,
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 16));
}

#[test]
fn snapshot_create_vault_enter_passphrase_empty() {
    let state = AppState::CreateVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        step: CreateVaultStep::EnterPassphrase {
            passphrase: PassphraseBuffer::new(),
            confirmation: PassphraseBuffer::new(),
            focus: PassphraseFieldFocus::Passphrase,
        },
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_create_vault_enter_passphrase_typing() {
    let mut passphrase = PassphraseBuffer::new();
    for c in "hunter2".chars() {
        passphrase.push(c);
    }
    let state = AppState::CreateVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        step: CreateVaultStep::EnterPassphrase {
            passphrase,
            confirmation: PassphraseBuffer::new(),
            focus: PassphraseFieldFocus::Confirmation,
        },
        error: None,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_create_vault_enter_passphrase_mismatch_error() {
    let mut passphrase = PassphraseBuffer::new();
    for c in "hunter2".chars() {
        passphrase.push(c);
    }
    let state = AppState::CreateVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        step: CreateVaultStep::EnterPassphrase {
            passphrase,
            confirmation: PassphraseBuffer::new(),
            focus: PassphraseFieldFocus::Confirmation,
        },
        error: Some("passphrases do not match".to_string()),
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 16));
}

#[test]
fn snapshot_create_vault_create_error_unsafe_permissions() {
    let err = PaladinError::UnsafePermissions {
        path: PathBuf::from("/var/lib/paladin"),
        subject: PermissionSubject::VaultDir,
        actual_mode: "0755".to_string(),
        expected_mode: "0700".to_string(),
    };
    let state = AppState::CreateVault {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        step: CreateVaultStep::ChooseMode {
            selection: CreateVaultMode::Encrypted,
        },
        error: Some(render_error_message(&err)),
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 16));
}

#[test]
fn snapshot_unlock_screen() {
    // Plan L1731: "Unlock screen." — encrypted-vault first-attempt
    // state with no inline error and no typed bytes.
    let state = AppState::Unlock {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        error: None,
        passphrase: PassphraseBuffer::new(),
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

#[test]
fn snapshot_unlock_screen_with_wrong_passphrase_error() {
    // Plan L1791: "Unlock screen with inline wrong-passphrase error."
    // The reducer surfaces the `decrypt_failed` text via
    // `render_error_message(&PaladinError::DecryptFailed)`, which
    // falls back to `Display` for non-`unsafe_permissions` errors —
    // that path is exercised here so the snapshot is bound to the
    // core Display wording rather than a hand-typed string.
    let state = AppState::Unlock {
        path: PathBuf::from("/var/lib/paladin/vault.bin"),
        error: Some(PaladinError::DecryptFailed.to_string()),
        passphrase: PassphraseBuffer::new(),
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

/// Create an empty plaintext vault at `path` and commit it to disk so a
/// subsequent `Store::open(_, VaultLock::Plaintext)` reopens an
/// `Unlocked`-able vault. Mirrors the helper in
/// `crates/paladin-tui/tests/effect_tests.rs` — duplicated locally
/// because integration-test crates do not share helper code.
fn create_plaintext_vault(path: &Path) {
    let (vault, store) = Store::create(path, VaultInit::Plaintext).expect("create vault");
    vault.save(&store).expect("commit initial vault");
}

#[test]
fn snapshot_list_view_empty() {
    // Plan L1711: "Empty vault list view." Construct an `Unlocked`
    // AppState backed by a freshly-created empty plaintext vault so
    // the renderer exercises the no-accounts branch (an empty rows
    // pane) while still drawing the surrounding chrome — title bar,
    // search line, separators, bottom keybinding hint — per
    // `docs/DESIGN.md` §6's list-view layout.
    //
    // The vault path itself does not appear in the list view (per the
    // §6 mock), so the tempdir-backed path stays out of the rendered
    // snapshot grid and keeps the snapshot deterministic across hosts.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_empty_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

/// Insert a single TOTP account into `vault` and commit it to `store`.
/// The Base32 secret, algorithm, digits, and 30-second window mirror the
/// CLI manual-add defaults so the rendered code/gauge/seconds tuple is a
/// pure function of [`SNAPSHOT_NOW_SECS`].
fn push_totp_account(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
) -> paladin_core::AccountId {
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
    let validated = validate_manual(input, snapshot_now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

#[test]
fn snapshot_list_view_single_totp() {
    // Plan L1727: "Single-TOTP list view." Construct an `Unlocked`
    // AppState backed by a plaintext vault holding one TOTP account
    // (`GitHub (ben@example.com)`) so the renderer exercises the
    // populated-row branch: the selection marker, the issuer/label
    // pair, the formatted TOTP code, the period-progress gauge, and
    // the remaining-seconds suffix per `docs/DESIGN.md` §6's list-view
    // mock.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_single_totp_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

/// Insert a single HOTP account at `counter` into `vault` and commit
/// it to `store`. Mirrors [`push_totp_account`] for the HOTP fan-out
/// of the list-view snapshots: the secret/algorithm/digits are
/// identical so the only behavioral delta is the kind discriminant
/// and the stored next counter.
fn push_hotp_account(
    vault: &mut Vault,
    store: &Store,
    issuer: Option<&str>,
    label: &str,
    counter: u64,
) -> paladin_core::AccountId {
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
    let validated = validate_manual(input, snapshot_now()).expect("valid manual input");
    let id = vault.add(validated.account);
    vault.save(store).expect("commit added account");
    id
}

#[test]
fn snapshot_list_view_mixed_totp_hotp_hidden_and_revealed() {
    // Plan L1762: "Mixed TOTP / HOTP list view with hidden + revealed
    // rows." Drive `view::list` against a vault whose insertion order
    // (TOTP, hidden HOTP, revealed HOTP) places one row of each
    // distinct shape onto the screen so the snapshot exercises every
    // branch of `render_rows` in a single grid:
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let _totp_id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let _hidden_hotp_id = push_hotp_account(&mut vault, &store, Some("Bank"), "savings", 0);
    let revealed_hotp_id = push_hotp_account(&mut vault, &store, Some("VPN"), "work", 42);

    let reveal = HotpReveal {
        account_id: revealed_hotp_id,
        counter_used: 41,
        code: SecretString::from("654321".to_string()),
        // The reveal deadline is monotonic and only consulted by the
        // reducer's expiry tick — the renderer never reads it, so the
        // host-clock-derived `Instant::now()` cannot leak into the
        // rendered grid and the snapshot stays deterministic.
        deadline: hotp_reveal_deadline(Instant::now()),
    };

    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
        selected: Some(revealed_hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_mixed_totp_hotp_hidden_and_revealed_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_hotp_only_vault_omits_next_code_column() {
    // DESIGN §6 Next column: HOTP rows leave the Next slot blank —
    // HOTP has no time-based "next code." A vault whose visible
    // rows are all HOTP must therefore render no `↪` glyph at
    // all; the snapshot pins this invariant so a regression that
    // ever leaks a next-code projection (or a stray `↪` cell) into
    // HOTP rendering surfaces as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let _bank = push_hotp_account(&mut vault, &store, Some("Bank"), "savings", 0);
    let vpn = push_hotp_account(&mut vault, &store, Some("VPN"), "work", 42);

    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(vpn),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 12);
    assert!(
        !rendered.contains('↪'),
        "HOTP-only vault must not render the `↪` next-code glyph; got:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_list_view_search_active() {
    // Plan L1781: "Search-active list view." Drive `view::list` against a
    // vault holding three accounts where only two match a non-empty
    // search query (`"git"`) so the snapshot pins two contracts:
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let github_id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let _gitlab_id = push_totp_account(&mut vault, &store, Some("GitLab"), "ben@example.com");
    let _bank_id = push_hotp_account(&mut vault, &store, Some("Bank"), "savings", 0);

    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: "git".to_string(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(github_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::Search,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_search_active_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_after_zz_recenter() {
    // Plan L1806: "List view after a `zz` recenter (selected row in
    // viewport middle)." Drive `view::list` against a vault holding
    // twelve TOTP accounts (more than the 6-row rows pane in an
    // 80x12 terminal) with the selected row deep enough into the
    // list that a centered viewport requires a non-zero
    // `viewport_offset` — pinning that the renderer honors
    // `viewport_offset` to slice the visible window.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let mut ids = Vec::with_capacity(12);
    for i in 1..=12u8 {
        let issuer = format!("Acct{i:02}");
        let label = format!("u{i:02}");
        ids.push(push_totp_account(
            &mut vault,
            &store,
            Some(issuer.as_str()),
            &label,
        ));
    }
    let selected_index: usize = 8;
    let viewport_height: u16 = 6;
    let viewport_offset: u16 =
        u16::try_from(selected_index).expect("index fits u16") - viewport_height / 2;
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(ids[selected_index]),
        pending_chord_leader: None,
        viewport_height,
        viewport_offset,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_after_zz_recenter_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_error_after_rejected_copy() {
    // Plan L2827: "Status-line error after rejected copy." Drive
    // `view::render` against an `Unlocked` state whose `status_line`
    // carries `StatusLine::Error(NO_ACCOUNT_SELECTED.to_string())`.
    // The reducer publishes this exact wording when an action key
    // (`n` / `r` / `R`, and `Enter`-as-copy by the same gate) fires
    // with `selected = None`; routing through the
    // `NO_ACCOUNT_SELECTED` constant binds the snapshot to the
    // source-of-truth string rather than a hand-typed copy and
    // mirrors the reducer-level assertions in
    // `tests/reducer_tests.rs` (`expect a `selection_gated`
    // status-line error` fan-out).
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Error(NO_ACCOUNT_SELECTED.to_string())),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_error_after_rejected_copy_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_save_durability_unconfirmed_after_hotp_advance() {
    // Plan L2828: "Status-line `save_durability_unconfirmed` after
    // HOTP `n`." Drive `view::render` against an `Unlocked` state
    // mirroring the reducer's post-advance "committed-but-uncertain"
    // shape from `reduce_hotp_advance_result`: a `HotpReveal` is
    // open for the selected HOTP account (the staged code survives
    // the durability-unconfirmed failure per the reducer body) and
    // `status_line` carries
    // `StatusLine::Error(render_error_message(
    //   &PaladinError::SaveDurabilityUnconfirmed))`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let hotp_id = push_hotp_account(&mut vault, &store, Some("AWS"), "prod", 41);
    let reveal = HotpReveal {
        account_id: hotp_id,
        counter_used: 41,
        code: SecretString::from("123456".to_string()),
        // `Instant`-based deadline is irrelevant to the static
        // snapshot (the renderer never inspects it) but
        // `hotp_reveal_deadline` keeps the construction shape
        // identical to the reducer's `Ok` arm.
        deadline: hotp_reveal_deadline(Instant::now()),
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: Some(reveal),
        modal: None,
        selected: Some(hotp_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Error(render_error_message(
            &PaladinError::SaveDurabilityUnconfirmed,
        ))),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_save_durability_unconfirmed_after_hotp_advance_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_clipboard_write_failed_after_failed_copy() {
    // Plan L2829: "Status-line `clipboard_write_failed` after a
    // failed copy." Drive `view::render` against an `Unlocked` state
    // whose `status_line` carries
    // `StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string())` — the
    // exact wording `reduce_copy_code_result` publishes on the
    // `EffectResult::CopyCode { result: Err(()), .. }` branch when
    // the executor's `arboard` write fails. Routing through the
    // `CLIPBOARD_WRITE_FAILED` constant binds the snapshot to the
    // source-of-truth string so a future rewording stays in sync
    // with the reducer-level `effect_result_copy_code_err_publishes_
    // clipboard_write_failed_status_line` assertion.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Error(CLIPBOARD_WRITE_FAILED.to_string())),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_clipboard_write_failed_after_failed_copy_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_manual_add() {
    // Plan L2884: "Status-line confirmation after manual Add." Drive
    // `view::render` against an `Unlocked` state whose `status_line`
    // carries `StatusLine::Confirmation("Added {display}.")` — the
    // exact wording `reduce_add_result` publishes on the no-warnings
    // Ok-arm of `EffectResult::Add`. The display string is built
    // through `format_account_display_label` against the just-added
    // account's `AccountSummary`, so the snapshot is bound to the
    // shared CLI/TUI label-formatting source of truth rather than a
    // hand-typed `"issuer:label"` literal. Reads as a bottom-row
    // delta from the `StatusLine::Error` siblings above — both share
    // the renderer's `bottom_line` slot but route through the
    // `Confirmation` branch (green-tinted on live terminals; the
    // harness drops styling).
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let summary = vault
        .iter()
        .find(|a| a.id() == id)
        .expect("added account must be present in vault")
        .summary();
    let confirmation = format!("Added {}.", format_account_display_label(&summary));
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_manual_add_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_uri_add() {
    // Plan L2885: "Status-line confirmation after URI Add." The URI
    // add flow shares `reduce_add_result` with the manual flow, so
    // the published wording is the same `Added {display}.` template
    // — the bound source of truth is `format_account_display_label`
    // applied to whatever `ValidatedAccount` the URI parser produced.
    // Pinning a separate snapshot here gives a redundant sentinel
    // against the reducer ever diverging the wording per AddMode
    // (e.g. "Imported {display}." for the URI path), in which case
    // only this snapshot will need to update.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("Example"), "alice@example.com");
    let summary = vault
        .iter()
        .find(|a| a.id() == id)
        .expect("added account must be present in vault")
        .summary();
    let confirmation = format!("Added {}.", format_account_display_label(&summary));
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_uri_add_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_remove() {
    // Plan L2886: "Status-line confirmation after Remove." Drive
    // `view::render` against an `Unlocked` state whose `status_line`
    // carries `StatusLine::Confirmation("Removed {label}.")` — the
    // exact wording `reduce_remove_result` publishes on the Ok-arm
    // of `EffectResult::Remove`. The reducer plugs the carried
    // display-label `String` directly into the format template;
    // that string is built by the executor via
    // `format_account_display_label` over the to-be-removed
    // account's `AccountSummary` (see `effect.rs` Remove closure).
    // The test captures the summary off `vault.iter()` and builds
    // the confirmation through the same helper, binding the
    // snapshot to the shared label-formatting source of truth so
    // any wording change in `format_account_display_label`
    // surfaces here.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let summary = vault
        .iter()
        .find(|a| a.id() == id)
        .expect("account must be present in vault")
        .summary();
    let confirmation = format!("Removed {}.", format_account_display_label(&summary));
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_remove_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_rename() {
    // Plan L2887: "Status-line confirmation after Rename." Drive
    // `view::render` against an `Unlocked` state whose `status_line`
    // carries `StatusLine::Confirmation("Renamed to {label}")` — the
    // exact wording `reduce_rename_result` publishes on the Ok-arm,
    // where `label` is the post-rename `a.label()` (just the bare
    // label, NOT the issuer-prefixed display label). The vault is
    // populated with the account already carrying its post-rename
    // label, then the test extracts that label from
    // `Vault::iter` the same way the reducer does, so the snapshot
    // is bound to the live vault state rather than a hand-typed
    // literal.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(
        &mut vault,
        &store,
        Some("GitHub"),
        "ben-personal@example.com",
    );
    let label = vault
        .iter()
        .find(|a| a.id() == id)
        .expect("renamed account must be present in vault")
        .summary()
        .label;
    let confirmation = format!("Renamed to {label}");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_rename_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_export() {
    // Plan L2888: "Status-line confirmation after Export." Drive
    // `view::render` against an `Unlocked` state whose `status_line`
    // carries `StatusLine::Confirmation("Exported to {display}.")`
    // — the exact wording `reduce_export_result` publishes on the
    // Ok-arm, where `display` is the user-supplied
    // `ExportModal::path_text.trim()`. The Export effect does not
    // mutate the vault (per the modal's "Export does not mutate the
    // vault" doc in `reduce_export_result`), so the rows pane stays
    // identical to its pre-export state — only the bottom row
    // changes to show the confirmation.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let display = "~/exports/paladin-export.json";
    let confirmation = format!("Exported to {display}.");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_export_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_passphrase_set() {
    // Plan L2889: "Status-line confirmation after Passphrase set."
    // Drive `view::render` against an `Unlocked` state whose
    // `status_line` carries `StatusLine::Confirmation("Passphrase
    // updated.")` — the exact wording `reduce_passphrase_result`
    // publishes on the Ok-arm. All three passphrase sub-flows
    // (`Set`, `Change`, `Remove`) share the same Ok-arm string, so
    // this snapshot and its `change` / `remove` siblings will be
    // byte-identical in the rendered body until / unless the
    // reducer diverges the wording per sub-flow — at which point
    // only the affected snapshot needs updating, giving each entry
    // point its own regression sentinel.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation("Passphrase updated.".to_string())),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_passphrase_set_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_passphrase_change() {
    // Plan L2890: "Status-line confirmation after Passphrase change."
    // The `Change` sub-flow shares the same `reduce_passphrase_result`
    // Ok-arm wording, so the rendered body is byte-identical to the
    // `_set` sibling.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation("Passphrase updated.".to_string())),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_passphrase_change_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_passphrase_remove() {
    // Plan L2891: "Status-line confirmation after Passphrase remove."
    // The `Remove` sub-flow shares the same Ok-arm wording as
    // `_set` / `_change`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation("Passphrase updated.".to_string())),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_passphrase_remove_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_settings_save() {
    // Plan L2892: "Status-line confirmation after Settings save."
    // Drive `view::render` against an `Unlocked` state whose
    // `status_line` carries `StatusLine::Confirmation("Settings
    // updated.")` — the exact wording `reduce_settings_result`
    // publishes on the Ok-arm of `EffectResult::ApplySettings`.
    // The settings save closes the modal and leaves the rows pane
    // unchanged; only the bottom row reflects the confirmation.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation("Settings updated.".to_string())),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_settings_save_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_manual_add_with_warnings() {
    // Plan L2893: "Manual Add status-line confirmation with
    // validation warnings." Drive `view::render` against an
    // `Unlocked` state whose `status_line` carries the warning-
    // appended confirmation `reduce_add_result` publishes when
    // `success.warnings` is non-empty: `Added {display}. warning:
    // {rendered}` where `rendered` is the `; `-joined output of
    // `format_validation_warning` over the carried warnings. The
    // snapshot is bound to `format_validation_warning` so any
    // wording change in the core warning text surfaces here.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let summary = vault
        .iter()
        .find(|a| a.id() == id)
        .expect("added account must be present in vault")
        .summary();
    let warnings = [ValidationWarning::ShortSecret {
        decoded_len: 8,
        recommended_min: 16,
    }];
    let rendered = warnings
        .iter()
        .map(format_validation_warning)
        .collect::<Vec<_>>()
        .join("; ");
    let confirmation = format!(
        "Added {}. warning: {}",
        format_account_display_label(&summary),
        rendered
    );
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_manual_add_with_warnings_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_list_view_status_line_after_uri_add_with_warnings() {
    // Plan L2894: "URI Add status-line confirmation with validation
    // warnings." The URI add flow shares `reduce_add_result`, so the
    // warning-appended confirmation template is identical to the
    // `_manual_add_with_warnings` sibling; a separate snapshot
    // anchors the URI entry point against a future per-AddMode
    // divergence in wording.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("Example"), "alice@example.com");
    let summary = vault
        .iter()
        .find(|a| a.id() == id)
        .expect("added account must be present in vault")
        .summary();
    let warnings = [ValidationWarning::ShortSecret {
        decoded_len: 8,
        recommended_min: 16,
    }];
    let rendered = warnings
        .iter()
        .map(format_validation_warning)
        .collect::<Vec<_>>()
        .join("; ");
    let confirmation = format!(
        "Added {}. warning: {}",
        format_account_display_label(&summary),
        rendered
    );
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: Some(StatusLine::Confirmation(confirmation)),
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
    insta::assert_snapshot!(
        "snapshot_list_view_status_line_after_uri_add_with_warnings_no_color",
        render_to_styled_text(&state, snapshot_now(), true, 80, 12),
    );
}

#[test]
fn snapshot_add_modal_default() {
    // Plan L1835: "Add modal." Drive `view::render` against an
    // `Unlocked` state holding `Modal::Add(AddModal::default())` so
    // the snapshot pins the freshly-opened (Manual-mode, no inline
    // error, no pending duplicate-add, no counts panel) baseline of
    // the Add modal overlay rendered on top of the list view per
    // `docs/DESIGN.md` §6's "modal dialogs for add / remove / rename /
    // import / export / passphrase / settings" call-out and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Add"
    // contract.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(AddModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_add_modal_save_not_committed() {
    // Plan L2121: "Add modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { error: Some(render_error_message(
    // &PaladinError::SaveNotCommitted { .. })), .. })` so the snapshot
    // pins the inline-error row populated from a pre-commit save
    // failure per `docs/DESIGN.md` §5's `save_not_committed` discriminator
    // and the `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Pre-commit effect
    // failures leave visible state unchanged and surface the typed
    // error through `render_error_message`" contract. Routing the
    // wording through the shared helper means the inline text matches
    // the rest of the TUI's error surface.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        error: Some(render_error_message(&PaladinError::SaveNotCommitted {
            committed: false,
            backup_path: None,
        })),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // inline error field must fail this test even before the
    // human reads the snapshot diff.
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_save_durability_unconfirmed() {
    // Plan L2122: "Add modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        error: Some(render_error_message(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_no_clipboard_image() {
    // Plan L2447: "Add modal QR-import inline error: no clipboard
    // image." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::NoClipboardImage)),
    // .. })` so the snapshot pins the inline-error row populated
    // when `arboard::Clipboard::get_image()` reports the clipboard
    // does not hold an image — the no-image clipboard branch per
    // `docs/DESIGN.md` §6 and `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6) > Add": *"Scan a QR code from clipboard image bytes;
    // imported via the shared QR-decode path"*. The reducer's Err
    // arm (`reduce_qr_import_result` in `src/app/reducer.rs`) routes
    // the failure through `format_qr_import_failure` and parks the
    // wording on `AddModal::error` per the matching contract in
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests > Add modal": *"QR-
    // import inline errors (no clipboard image, image decode
    // failure, zero decoded QRs, oversized RGBA buffer, invalid QR
    // payload) surface inline and the modal stays open in
    // `AddMode::Qr`."*  The view-snapshot pins the post-reduce
    // rendering 1:1 with the reducer-side coverage from
    // `effect_result_qr_import_no_clipboard_image_sets_inline_error_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(format_qr_import_failure(&QrImportFailure::NoClipboardImage)),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // QR-import failure must fail this test even before the human
    // reads the snapshot diff. Bind the assertion to the leading
    // `QR import failed: clipboard does not contain an image`
    // substring — the full message (with the `(copy a QR image
    // first).` parenthetical hint) exceeds the inline-error slot's
    // ~60-col width and is truncated by `Paragraph::new(Line::from(...))`
    // in `view/add.rs::render_inline_error`, mirroring the
    // truncation pin the plaintext-export-warning snapshot exercises.
    assert!(
        rendered.contains("QR import failed: clipboard does not contain an image"),
        "expected inline no-clipboard-image wording prefix to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_image_decode_failure() {
    // Plan L2448: "Add modal QR-import inline error: image decode
    // failure." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::ImageDecodeFailure)),
    // .. })` so the snapshot pins the inline-error row populated
    // when `arboard` returned an image but the bytes could not be
    // decoded as a usable raster — the malformed-raster branch per
    // the `QrImportFailure::ImageDecodeFailure` discriminator
    // documented in `crates/paladin-tui/src/app/event.rs`. The
    // reducer's Err arm (`reduce_qr_import_result` in
    // `src/app/reducer.rs`) routes the failure through
    // `format_qr_import_failure` and parks the wording on
    // `AddModal::error`. The view-snapshot pins the post-reduce
    // rendering 1:1 with the reducer-side coverage from
    // `effect_result_qr_import_image_decode_failure_sets_inline_error_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(format_qr_import_failure(
            &QrImportFailure::ImageDecodeFailure,
        )),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = format_qr_import_failure(&QrImportFailure::ImageDecodeFailure);
    assert!(
        rendered.contains(&expected),
        "expected inline image-decode-failure wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_no_qrs_decoded() {
    // Plan L2449: "Add modal QR-import inline error: zero decoded
    // QRs." Drive `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::Import(
    //     PaladinError::NoEntriesToImport))), .. })` so the snapshot
    // pins the inline-error row populated when
    // `paladin_core::import::qr_image_bytes` decodes the clipboard
    // raster but finds zero QR payloads in it — the
    // `no_entries_to_import` discriminator per `docs/DESIGN.md` §4.6 / §5.
    // The reducer's Err arm (`reduce_qr_import_result` in
    // `src/app/reducer.rs`) routes the failure through
    // `format_qr_import_failure`, whose `Import(err)` arm delegates
    // to `render_error_message` and binds the wording to the core
    // `Display` impl (`no entries to import`). The view-snapshot
    // pins the post-reduce rendering 1:1 with the reducer-side
    // coverage from
    // `effect_result_qr_import_no_qrs_decoded_sets_inline_error_via_render_error_message`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(format_qr_import_failure(&QrImportFailure::Import(
            PaladinError::NoEntriesToImport,
        ))),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected =
        format_qr_import_failure(&QrImportFailure::Import(PaladinError::NoEntriesToImport));
    assert!(
        rendered.contains(&expected),
        "expected inline no-entries-to-import wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_oversized_rgba_buffer() {
    // Plan L2450: "Add modal QR-import inline error: oversized raw
    // RGBA buffer." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::Import(
    //     paladin_core::import::qr_image_bytes(5000, 5000, &[], _)
    //         .expect_err(...)))), .. })` so the snapshot pins the
    // inline-error row populated when
    // `paladin_core::import::qr_image_bytes` rejects oversized RGBA
    // buffers (dimensions whose `width * height * 4` exceeds
    // `paladin_core::QR_RGBA_MAX_BYTES`) with `validation_error
    // { field: "qr_image", reason: "image_too_large" }` per
    // `docs/DESIGN.md` §4.6. Routing through the real `qr_image_bytes`
    // call rather than constructing the error directly binds the
    // snapshot to the public API contract — the reducer-side
    // fixture
    // (`effect_result_qr_import_oversized_rgba_buffer_sets_inline_error_via_render_error_message`
    // in `tests/reducer_tests.rs`) uses the same trigger so the
    // view-snapshot matrix stays 1:1 with the reducer matrix.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let oversized_side: u32 = 5000;
    let core_err =
        paladin_core::import::qr_image_bytes(oversized_side, oversized_side, &[], snapshot_now())
            .expect_err("oversized RGBA dimensions must reject");
    let expected = format_qr_import_failure(&QrImportFailure::Import(core_err));
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(expected.clone()),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains(&expected),
        "expected inline oversized-rgba wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_invalid_qr_payload() {
    // Plan L2615: "Add modal QR-import inline error: invalid QR
    // payload." Drive `view::render` against an `Unlocked` state
    // holding `Modal::Add(AddModal { mode: AddMode::Qr, error:
    // Some(format_qr_import_failure(&QrImportFailure::Import(
    //     PaladinError::ValidationError { field: "qr_image", reason:
    //     "non_otpauth_payload", source_index: Some(0), .. }))), .. })`
    // so the snapshot pins the inline-error row populated when
    // `paladin_core::import::qr_image_bytes` decodes a QR whose
    // payload is not an `otpauth://` URI — the `non_otpauth_payload`
    // discriminator emitted by `payloads_to_accounts` per `docs/DESIGN.md`
    // §4.6 / §5 (see `crates/paladin-core/src/import/qr.rs:87`).
    // The reducer's Err arm (`reduce_qr_import_result` in
    // `src/app/reducer.rs`) routes the failure through
    // `format_qr_import_failure`, whose `Import(err)` arm delegates
    // to `render_error_message` and binds the wording to the core
    // `Display` impl (`validation error: qr_image: non_otpauth_payload`).
    // The view-snapshot pins the post-reduce rendering 1:1 with the
    // reducer-side coverage from
    // `effect_result_qr_import_invalid_qr_payload_sets_inline_error_via_render_error_message`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let core_err = PaladinError::ValidationError {
        field: "qr_image",
        reason: "non_otpauth_payload".to_string(),
        source_index: Some(0),
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    };
    let expected = format_qr_import_failure(&QrImportFailure::Import(core_err));
    let modal = AddModal {
        mode: AddMode::Qr,
        error: Some(expected.clone()),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains(&expected),
        "expected inline non-otpauth-payload wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_counts_panel() {
    // Plan L2616: "Add modal post-QR-import counts panel." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { mode: AddMode::Qr, counts_panel:
    // Some(CountsPanel { imported, skipped, replaced: 0, appended: 0,
    // warnings: vec![] }), .. })` so the snapshot pins the post-success
    // summary panel — the four `ImportReport` merge totals the reducer
    // seeds from `paladin_core::ImportReport` per `docs/DESIGN.md` §6's
    // "The modal reports imported/skipped/replaced/appended/warning
    // counts plus validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract and the `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Add" checklist row: *"Clipboard QR import
    // uses `ImportConflict::Skip` and reports imported / skipped
    // counts."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        counts_panel: Some(CountsPanel {
            imported: 2,
            skipped: 1,
            replaced: 0,
            appended: 0,
            warnings: Vec::new(),
        }),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("Imported:") && rendered.contains('2'),
        "expected 'Imported:' row with count 2 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Skipped:") && rendered.contains('1'),
        "expected 'Skipped:' row with count 1 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Replaced:") && rendered.contains('0'),
        "expected 'Replaced:' row with count 0 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Appended:"),
        "expected 'Appended:' row to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Enter or Esc to close"),
        "expected post-success hint to appear in counts panel:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_qr_counts_panel_with_validation_warnings() {
    // Plan L2759: "QR-add counts panel with validation-warning messages."
    // Drive `view::render` against an `Unlocked` state holding
    // `Modal::Add(AddModal { mode: AddMode::Qr, counts_panel:
    // Some(CountsPanel { ..., warnings: vec![...] }), .. })` so the
    // snapshot pins the post-success summary panel rendering each
    // `paladin_core::ImportWarning` through
    // `paladin_core::format_validation_warning()` per `docs/DESIGN.md` §6's
    // "The modal reports imported/skipped/replaced/appended/warning
    // counts plus validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract. The reducer seeds `CountsPanel::warnings`
    // from the carried `ImportReport::warnings` map through
    // `format_validation_warning`, so routing the strings through the
    // helper here binds the snapshot to the core wording rather than a
    // hand-typed string — a future revision of the warning phrasing
    // stays in sync without an extra snapshot edit.
    let warning_short = format_validation_warning(&ValidationWarning::ShortSecret {
        decoded_len: 5,
        recommended_min: 16,
    });
    let warning_shortest = format_validation_warning(&ValidationWarning::ShortSecret {
        decoded_len: 1,
        recommended_min: 16,
    });

    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = AddModal {
        mode: AddMode::Qr,
        counts_panel: Some(CountsPanel {
            imported: 1,
            skipped: 1,
            replaced: 0,
            appended: 0,
            warnings: vec![warning_short.clone(), warning_shortest.clone()],
        }),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 24);
    assert!(
        rendered.contains("decoded length 5 bytes"),
        "expected first warning's decoded_len text in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("decoded length 1 bytes"),
        "expected second warning's decoded_len text in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Imported:") && rendered.contains('1'),
        "expected 'Imported:' row with count 1 to remain visible above warnings:\n{rendered}"
    );
    assert!(
        rendered.contains("Skipped:") && rendered.contains('1'),
        "expected 'Skipped:' row with count 1 to remain visible above warnings:\n{rendered}"
    );
    assert!(
        rendered.contains("Enter or Esc to close"),
        "expected post-success hint to appear below warnings:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_duplicate_account() {
    // Plan L2702: "Add modal `duplicate_account`." Drive `view::render`
    // against an `Unlocked` state holding
    // `Modal::Add(AddModal { error: Some(format_duplicate_account_message(
    // &existing_summary)), .. })` so the snapshot pins the inline-error
    // row populated when `paladin_core::Vault::find_duplicate` matches
    // an existing entry on the `(secret, issuer, label)` triple. Per
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Add":
    // *"manual and URI duplicate collisions call
    // `Vault::find_duplicate(&validated)` before mutation. A collision
    // initially rejects with the existing account in the modal and
    // offers an 'add anyway' confirmation."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let existing_id = push_totp_account(&mut vault, &store, None, "github");
    let existing_summary = vault
        .iter()
        .find(|a| a.id() == existing_id)
        .expect("existing account must be present in vault")
        .summary();
    let expected = format_duplicate_account_message(&existing_summary);
    let modal = AddModal {
        error: Some(expected.clone()),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: Some(existing_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // duplicate rejection must fail this test even before the human
    // reads the snapshot diff. Bind the assertion to the leading
    // `account already exists with the same (secret, issuer, label)`
    // substring — the full message (with the `: github (press Enter
    // to add anyway)` tail) exceeds the inline-error slot's ~60-col
    // width and is truncated by `Paragraph::new(Line::from(...))` in
    // `view/add.rs::render_inline_error`, mirroring the truncation
    // pin the `snapshot_add_modal_qr_no_clipboard_image` snapshot
    // exercises.
    assert!(
        rendered.contains("account already exists with the same (secret, issuer, label)"),
        "expected leading duplicate_account wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_add_modal_add_anyway_confirmation() {
    // Plan L2729: "Add modal 'add anyway' confirmation." Drive
    // `view::render` against an `Unlocked` state holding the
    // follow-up confirmation form of the duplicate-rejection: both
    // `AddModal::error` (the `format_duplicate_account_message`
    // template) and `AddModal::pending_duplicate_add` are populated,
    // matching the reducer state established by
    // `effect_result_add_duplicate_stashes_pending_and_sets_inline_error`
    // (`tests/reducer_tests.rs`) and consumed by
    // `enter_with_pending_duplicate_add_in_manual_mode_emits_add_anyway_effect`
    // / `enter_with_pending_duplicate_add_in_uri_mode_emits_add_anyway_effect`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let existing_id = push_totp_account(&mut vault, &store, None, "github");
    let existing_summary = vault
        .iter()
        .find(|a| a.id() == existing_id)
        .expect("existing account must be present in vault")
        .summary();
    // Pending validated account uses the same (secret, issuer, label)
    // triple as the existing entry — the shape exercised by
    // `make_duplicate_validated` in `tests/reducer_tests.rs` — so the
    // state mirrors what the reducer stashes on
    // `AddFailure::Duplicate`.
    let pending_input = AccountInput {
        label: "github".to_string(),
        issuer: None,
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        kind: AccountKindInput::Totp,
        period_secs: None,
        counter: None,
        icon_hint: IconHintInput::Default,
    };
    let pending_validated =
        validate_manual(pending_input, snapshot_now()).expect("valid pending manual input");
    let modal = AddModal {
        error: Some(format_duplicate_account_message(&existing_summary)),
        pending_duplicate_add: Some(Box::new(PendingDuplicateAdd {
            existing: existing_summary.clone(),
            validated: Box::new(pending_validated),
        })),
        ..AddModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Add(modal)),
        selected: Some(existing_id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: the renderer must surface the duplicate
    // rejection alongside the confirmation footer so the user sees
    // *what* they are about to confirm.
    assert!(
        rendered.contains("account already exists with the same (secret, issuer, label)"),
        "expected leading duplicate_account wording to appear in modal:\n{rendered}"
    );
    // The confirmation footer hint replaces the editable-modal
    // default. Tab-cycling no longer applies (the next Enter commits
    // the stashed pending account), so the hint drops the
    // `Tab cycles fields` segment and renames `Enter submit` to
    // `Enter add anyway`.
    assert!(
        rendered.contains("Enter add anyway"),
        "expected confirmation footer hint to appear in modal:\n{rendered}"
    );
    assert!(
        !rendered.contains("Tab cycles fields"),
        "expected the editable-modal footer hint to be replaced in the confirmation form:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_remove_modal_default() {
    // Plan L1856: "Remove modal." Drive `view::render` against an
    // `Unlocked` state with one TOTP account and
    // `Modal::Remove(RemoveModal { account_id, error: None })` open
    // so the snapshot pins the freshly-opened (no inline save-error,
    // populated `account_id`) baseline of the Remove confirmation
    // modal overlay rendered on top of the list view per `docs/DESIGN.md`
    // §6's "modal dialogs for add / remove / rename / import /
    // export / passphrase / settings" call-out and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Remove"
    // contract — *"confirmation modal. On confirm, wraps
    // `Vault::remove` in `Vault::mutate_and_save`."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_remove_modal_save_not_committed() {
    // Plan L2140: "Remove modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Remove(RemoveModal { account_id, error: Some(
    // render_error_message(&PaladinError::SaveNotCommitted { .. })) })`
    // so the snapshot pins the inline-error row populated from a
    // pre-commit save failure per `docs/DESIGN.md` §5's
    // `save_not_committed` discriminator and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Pre-commit save rollback >
    // Remove modal: same coverage as Add, asserted on `Vault::iter()`"
    // contract. Routing the wording through the shared
    // `render_error_message` helper means the inline text matches
    // the rest of the TUI's error surface.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // inline error field must fail this test even before the
    // human reads the snapshot diff.
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_remove_modal_save_durability_unconfirmed() {
    // Plan L2141: "Remove modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Remove(RemoveModal {
            account_id: id,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_rename_modal_default() {
    // Plan L1885: "Rename modal." Drive `view::render` against an
    // `Unlocked` state with one TOTP account and
    // `Modal::Rename(RenameModal { account_id, draft, error: None })`
    // open so the snapshot pins the freshly-opened (draft pre-populated
    // with the selected account's current label, no inline save / validation
    // error) baseline of the Rename modal overlay rendered on top of the
    // list view per `docs/DESIGN.md` §6's "modal dialogs for add / remove /
    // rename / import / export / passphrase / settings" call-out and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Rename"
    // contract — *"single text field pre-populated with the selected
    // account's current label."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "ben@example.com".to_string(),
            error: None,
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_rename_modal_save_not_committed() {
    // Plan L2159: "Rename modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Rename(RenameModal { account_id, draft, error: Some(
    // render_error_message(&PaladinError::SaveNotCommitted { .. })) })`
    // so the snapshot pins the inline-error row populated from a
    // pre-commit save failure per `docs/DESIGN.md` §5's
    // `save_not_committed` discriminator. Routing the wording
    // through the shared `render_error_message` helper means the
    // inline text matches the rest of the TUI's error surface — the
    // unlock screen's `decrypt_failed` line, the Add modal's
    // inline-error slot, and the Remove modal's inline-error slot.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "ben@example.com".to_string(),
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // inline error field must fail this test even before the
    // human reads the snapshot diff.
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_rename_modal_save_durability_unconfirmed() {
    // Plan L2160: "Rename modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Rename(RenameModal {
            account_id: id,
            draft: "ben@example.com".to_string(),
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
        })),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

/// Build a fresh `AppState::Unlocked` carrying a pre-populated
/// [`EditModal`] over a single TOTP account. Used by the three Edit
/// modal snapshots.
fn fresh_edit_modal_state(
    label: &str,
    issuer: Option<&str>,
    selector: EditIconHintSelector,
    slug: &str,
    error: Option<String>,
    focus: EditFocus,
    kind_is_hotp: bool,
) -> AppState {
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = if kind_is_hotp {
        push_hotp_account(&mut vault, &store, issuer, label, 0)
    } else {
        push_totp_account(&mut vault, &store, issuer, label)
    };
    let prior_issuer = issuer.map(str::to_owned);
    let prior_icon_hint = vault
        .iter()
        .find(|a| a.id() == id)
        .and_then(|a| a.icon_hint().map(str::to_owned));
    let modal = EditModal {
        account_id: id,
        prior: EditPrior {
            label: label.to_string(),
            issuer: prior_issuer.clone(),
            icon_hint: prior_icon_hint,
        },
        label_buffer: label.to_string(),
        issuer_buffer: prior_issuer.unwrap_or_default(),
        icon_hint_selector: selector,
        icon_hint_slug: slug.to_string(),
        focus,
        error,
    };
    // tempdir intentionally leaked into the function-scope so the
    // vault file survives the snapshot rendering. We must keep `tmp`
    // alive: convert it into a path-owned form by leaking; tests
    // rebuild the world on every snapshot call so this drops on
    // process exit.
    std::mem::forget(tmp);
    AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Edit(modal)),
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    }
}

#[test]
fn snapshot_edit_modal_default() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Edit modal > snapshot
    // bullet: "Snapshot test for the Edit modal default layout
    // (`snapshot_edit_modal_default`), matching the Rename snapshot
    // conventions (centered region, three labeled controls, footer
    // hint line)." The icon-hint selector renders with `▶ Leave
    // unchanged ◀` active markers parallel to other segmented
    // selectors.
    let state = fresh_edit_modal_state(
        "ben@example.com",
        Some("GitHub"),
        EditIconHintSelector::LeaveUnchanged,
        "github",
        None,
        EditFocus::Label,
        false,
    );
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_edit_modal_hotp_account() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Edit modal > "Render-
    // independence-from-`AccountKind`": opening Edit on a HOTP
    // account produces the same three-control layout as a TOTP
    // account, with no counter row and no kind-specific OTP fields.
    let state = fresh_edit_modal_state(
        "ben@example.com",
        Some("GitHub"),
        EditIconHintSelector::LeaveUnchanged,
        "github",
        None,
        EditFocus::Label,
        true,
    );
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_edit_modal_duplicate_account() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Edit modal > snapshot
    // bullet: "Snapshot test for the duplicate-account variant
    // (`snapshot_edit_modal_duplicate_account`) with the pre-submit
    // `Vault::find_duplicate_after_edit` check rejecting the
    // projected edit, so the inline
    // `format_duplicate_account_message(&existing_summary)` text
    // renders in the modal body parallel to the Add modal's
    // `snapshot_add_modal_duplicate_account` fixture."
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let sibling = push_totp_account(&mut vault, &store, Some("GitHub"), "bob@example.com");
    let target = push_totp_account(&mut vault, &store, Some("GitHub"), "alice@example.com");
    let sibling_summary = vault
        .iter()
        .find(|a| a.id() == sibling)
        .expect("sibling")
        .summary();
    let dup_msg = format_duplicate_account_message(&sibling_summary);
    let modal = EditModal {
        account_id: target,
        prior: EditPrior {
            label: "alice@example.com".to_string(),
            issuer: Some("GitHub".to_string()),
            icon_hint: Some("github".to_string()),
        },
        label_buffer: "bob@example.com".to_string(),
        issuer_buffer: "GitHub".to_string(),
        icon_hint_selector: EditIconHintSelector::LeaveUnchanged,
        icon_hint_slug: "github".to_string(),
        focus: EditFocus::Label,
        error: Some(dup_msg),
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Edit(modal)),
        selected: Some(target),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("account already exists"),
        "expected duplicate-account wording, got:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_edit_modal_validation_error() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Edit modal > snapshot
    // bullet: validation-error variant with an invalid icon-hint slug
    // entered under *Slug:* so the inline `validation_error`
    // (`field: "icon_hint"`, `reason: "invalid_chars"`) renders beside
    // the selector. Drive the reducer's submit so the error is
    // populated through the real `validate_account_edit` path rather
    // than hand-built.
    let state = fresh_edit_modal_state(
        "ben@example.com",
        Some("GitHub"),
        EditIconHintSelector::Slug,
        "Bad Slug!",
        None,
        EditFocus::Slug,
        false,
    );
    let enter = AppEvent::Input {
        event: Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        at: Instant::now(),
    };
    let (state, _) = reduce(state, enter);
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("icon_hint") && rendered.contains("invalid_chars"),
        "expected icon_hint invalid_chars wording, got:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_edit_modal_durability_warning() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Edit modal > snapshot
    // bullet: durability-warning variant with
    // `EffectResult::EditAccountMetadata` `Err(SaveDurabilityUnconfirmed)`
    // surfaced as the inline warning, mirroring the Rename durability
    // snapshot. Both surfaces render the warning through
    // `render_error_message`.
    let state = fresh_edit_modal_state(
        "ben@example.com",
        Some("GitHub"),
        EditIconHintSelector::LeaveUnchanged,
        "github",
        Some(render_error_message(
            &PaladinError::SaveDurabilityUnconfirmed,
        )),
        EditFocus::Label,
        false,
    );
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.to_lowercase().contains("durability"),
        "expected durability warning wording, got:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_edit_modal_icon_hint_slug_mode() {
    // docs/IMPLEMENTATION_PLAN_03_TUI.md > Edit modal > snapshot
    // bullet: *Slug:* mode active so the slug input row is captured as
    // enabled and focused, visually distinguishing it from the
    // disabled state under the other three selector options.
    let state = fresh_edit_modal_state(
        "ben@example.com",
        Some("GitHub"),
        EditIconHintSelector::Slug,
        "github",
        None,
        EditFocus::Slug,
        false,
    );
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_import_modal_default() {
    // Plan L1886: "Import modal." Drive `view::render` against an
    // `Unlocked` state with `Modal::Import(ImportModal::default())`
    // open so the snapshot pins the freshly-opened (empty
    // `path_text`, `Auto` format selector, `Skip` on-conflict policy,
    // no inline error, no encrypted-Paladin passphrase sub-phase, no
    // post-success counts panel) baseline of the Import modal overlay
    // rendered on top of the list view per `docs/DESIGN.md` §6's "Import
    // takes a file path and optional explicit format … applies a
    // user-selected on-conflict policy (skip / replace / append), and
    // reports imported/skipped/replaced/appended/warning counts"
    // contract and the `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6) > Import" checklist row.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Import(ImportModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_import_modal_save_not_committed() {
    // Plan L2161: "Import modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Import(ImportModal { error: Some(render_error_message(
    // &PaladinError::SaveNotCommitted { .. })), .. })` so the
    // snapshot pins the inline-error row populated from a pre-commit
    // save failure per `docs/DESIGN.md` §5's `save_not_committed`
    // discriminator. Routing the wording through the shared
    // `render_error_message` helper means the inline text matches
    // the rest of the TUI's error surface — the unlock screen's
    // `decrypt_failed` line and the Add / Remove / Rename modals'
    // inline-error slots.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Import(ImportModal {
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_save_durability_unconfirmed() {
    // Plan L2162: "Import modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Import(ImportModal {
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

/// Render the Import modal overlay against a fresh `Unlocked` state
/// with the supplied `PaladinError` pre-rendered into
/// `ImportModal::error` via `render_error_message`, and return the
/// resulting text grid.
///
/// Mirrors the `snapshot_import_modal_save_not_committed` /
/// `snapshot_import_modal_save_durability_unconfirmed` setups so the
/// per-importer-error-kind snapshots below read as deltas from the
/// `snapshot_import_modal_default` baseline. The `expected_substring`
/// argument doubles as a guard that the rendered grid does carry the
/// rendered error wording before the snapshot lands — a regression
/// that ever drops the inline error or strips the rendered wording
/// surfaces as the assertion message rather than a silent snapshot
/// diff.
fn render_import_modal_with_inline_error(err: &PaladinError, expected_substring: &str) -> String {
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Import(ImportModal {
            error: Some(render_error_message(err)),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains(expected_substring),
        "expected inline error substring {expected_substring:?} to appear in modal:\n{rendered}"
    );
    rendered
}

// ---------------------------------------------------------------------------
// Import modal — per-importer-error-kind inline rendering
// (docs/IMPLEMENTATION_PLAN_03_TUI.md > Tests > Insta snapshots:
//  *"Import modal with each importer error kind."*)
// ---------------------------------------------------------------------------

#[test]
fn snapshot_import_modal_unsupported_import_format() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedImportFormat {
            format: "unknown".to_string(),
        },
        "unsupported import format",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_plaintext_vault() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedPlaintextVault,
        "Paladin import bundle is plaintext",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_encrypted_aegis() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedEncryptedAegis,
        "Aegis encrypted backups are not supported",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_aegis_entry_type() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedAegisEntryType {
            source_index: 2,
            entry_type: "steam".to_string(),
        },
        "Aegis entry type",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_validation_error() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::ValidationError {
            field: "secret",
            reason: "bad_base32".to_string(),
            source_index: Some(0),
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        },
        "validation error",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_no_entries_to_import() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::NoEntriesToImport,
        "no entries to import",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_decrypt_failed() {
    let rendered =
        render_import_modal_with_inline_error(&PaladinError::DecryptFailed, "decryption failed");
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_invalid_header() {
    let rendered =
        render_import_modal_with_inline_error(&PaladinError::InvalidHeader, "invalid vault header");
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_invalid_payload() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::InvalidPayload {
            reason: "decode_failed",
        },
        "invalid vault payload",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_unsupported_format_version() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::UnsupportedFormatVersion { format_ver: 99 },
        "unsupported vault format version",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_kdf_params_out_of_bounds() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::KdfParamsOutOfBounds {
            m_kib: 1,
            t: 0,
            p: 0,
        },
        "Argon2 KDF parameters out of bounds",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_io_error() {
    let rendered = render_import_modal_with_inline_error(
        &PaladinError::IoError {
            operation: "read_import_file",
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        },
        "I/O error during read_import_file",
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_counts_panel() {
    // Plan L2300: "Import modal post-import counts panel." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Import(ImportModal { counts_panel: Some(CountsPanel {
    // imported, skipped, replaced, appended, warnings: vec![] }), .. })`
    // so the snapshot pins the post-success summary panel — the four
    // `ImportReport` merge totals (`imported`/`skipped`/`replaced`/
    // `appended`) the reducer seeds from
    // `paladin_core::ImportReport` per `docs/DESIGN.md` §6's "The modal
    // reports imported/skipped/replaced/appended/warning counts plus
    // validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract and the `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Import" checklist row.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Import(ImportModal {
            counts_panel: Some(CountsPanel {
                imported: 3,
                skipped: 1,
                replaced: 2,
                appended: 4,
                warnings: Vec::new(),
            }),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("Imported:") && rendered.contains('3'),
        "expected 'Imported:' row with count 3 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Skipped:") && rendered.contains('1'),
        "expected 'Skipped:' row with count 1 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Replaced:") && rendered.contains('2'),
        "expected 'Replaced:' row with count 2 to appear in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Appended:") && rendered.contains('4'),
        "expected 'Appended:' row with count 4 to appear in counts panel:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_import_modal_counts_panel_with_validation_warnings() {
    // Plan L2323: "Import counts panel with validation-warning messages."
    // Drive `view::render` against an `Unlocked` state holding
    // `Modal::Import(ImportModal { counts_panel: Some(CountsPanel {
    // ..., warnings: vec![...] }), .. })` so the snapshot pins the
    // post-success counts panel rendering each
    // `paladin_core::ImportWarning` through
    // `paladin_core::format_validation_warning()` per `docs/DESIGN.md` §6's
    // "The modal reports imported/skipped/replaced/appended/warning
    // counts plus validation-warning messages rendered through
    // `paladin_core::format_validation_warning()` in a post-success
    // counts panel" contract. The reducer's `reduce_import_result` Ok
    // arm seeds `CountsPanel::warnings` from
    // `ImportReport::warnings.iter().map(format_validation_warning)`,
    // so the warnings strings flow through the same helper here —
    // binding the snapshot to the core wording rather than a
    // hand-typed string keeps the rendered text in sync with the core
    // library if the warning phrasing is ever revised.
    let warning_short = format_validation_warning(&ValidationWarning::ShortSecret {
        decoded_len: 5,
        recommended_min: 16,
    });
    let warning_shortest = format_validation_warning(&ValidationWarning::ShortSecret {
        decoded_len: 1,
        recommended_min: 16,
    });

    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Import(ImportModal {
            counts_panel: Some(CountsPanel {
                imported: 2,
                skipped: 0,
                replaced: 0,
                appended: 0,
                warnings: vec![warning_short.clone(), warning_shortest.clone()],
            }),
            ..ImportModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 22);
    assert!(
        rendered.contains("decoded length 5 bytes"),
        "expected first warning's decoded_len text in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("decoded length 1 bytes"),
        "expected second warning's decoded_len text in counts panel:\n{rendered}"
    );
    assert!(
        rendered.contains("Imported:") && rendered.contains('2'),
        "expected 'Imported:' row with count 2 to remain visible above warnings:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_default() {
    // Plan L1887: "Export modal." Drive `view::render` against an
    // `Unlocked` state with `Modal::Export(ExportModal::default())`
    // open so the snapshot pins the freshly-opened (empty
    // `path_text`, `ExportFormat::Plaintext` format selector, empty
    // twice-confirm passphrase buffers, `plaintext_confirmed: false`
    // acknowledgement gate, no inline error) baseline of the Export
    // modal overlay rendered on top of the list view per `docs/DESIGN.md`
    // §6's "Export writes either the plaintext `otpauth://` JSON list
    // (with an explicit unencrypted-secrets warning before the write)
    // or an encrypted Paladin bundle (passphrase prompted twice and
    // matched), refuses overwrite without explicit confirmation"
    // contract and the `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per
    // §6) > Export" checklist row.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(ExportModal::default())),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_export_modal_refused_overwrite_gate() {
    // Plan L2360: "Export modal refused overwrite gate." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error: Some(render_error_message(
    // &PaladinError::ValidationError { field: "path",
    // reason: "output_exists".to_string(), .. })), .. })` open so the
    // snapshot pins the inline-error row populated from the
    // refused-overwrite gate per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Export": *"Overwriting an existing file is
    // rejected unless the user confirms an inline overwrite gate
    // (parity with CLI `--force`)."* Routing the wording through
    // `render_error_message` binds the snapshot to the core
    // `PaladinError::ValidationError` `Display` impl
    // (`validation error: path: output_exists`) rather than a
    // hand-typed string so any future wording change in core surfaces
    // here as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        error: Some(render_error_message(&PaladinError::ValidationError {
            field: "path",
            reason: "output_exists".to_string(),
            source_index: None,
            decoded_len: None,
            recommended_min: None,
            entry_type: None,
        })),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // refused-overwrite gate's inline error must fail this test even
    // before the human reads the snapshot diff. Binds the assertion
    // to the core `Display` wording rather than a hand-typed string.
    let expected = render_error_message(&PaladinError::ValidationError {
        field: "path",
        reason: "output_exists".to_string(),
        source_index: None,
        decoded_len: None,
        recommended_min: None,
        entry_type: None,
    });
    assert!(
        rendered.contains(&expected),
        "expected inline refused-overwrite wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_confirmation_mismatch() {
    // Plan L2361: "Export modal `confirmation_mismatch`." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { format: ExportFormat::Encrypted,
    // error: Some(render_error_message(&PaladinError::InvalidPassphrase
    // { reason: "confirmation_mismatch" })), .. })` open so the
    // snapshot pins the inline-error row populated from the encrypted
    // twice-confirm passphrase mismatch gate per
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Export":
    // *"Encrypted exports prompt twice for the bundle passphrase ..."*
    // Mismatch surfaces a rendered `PaladinError::InvalidPassphrase`
    // with `reason: "confirmation_mismatch"` per docs/DESIGN.md §5,
    // matching the CLI's `prompt_new_passphrase` and the GTK
    // `SubmitRejection::ConfirmationMismatch` wire code. Routing the
    // wording through `render_error_message` binds the snapshot to the
    // core `Display` impl (`invalid passphrase: confirmation_mismatch`)
    // rather than a hand-typed string so any future wording change in
    // core surfaces here as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        format: ExportFormat::Encrypted,
        error: Some(render_error_message(&PaladinError::InvalidPassphrase {
            reason: "confirmation_mismatch",
        })),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    });
    assert!(
        rendered.contains(&expected),
        "expected inline confirmation_mismatch wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_zero_length() {
    // Plan L2388: "Export modal `zero_length`." Drive `view::render`
    // against an `Unlocked` state with
    // `Modal::Export(ExportModal { format: ExportFormat::Encrypted,
    // error: Some(render_error_message(&PaladinError::InvalidPassphrase
    // { reason: "zero_length" })), .. })` open so the snapshot pins the
    // inline-error row populated from the encrypted twice-confirm
    // empty-passphrase gate per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals
    // (per §6) > Export": *"Encrypted exports prompt twice for the
    // bundle passphrase and reject mismatch with inline
    // `invalid_passphrase` (`reason: "confirmation_mismatch"`) or
    // empty entry with `reason: "zero_length"`."*. When the encrypted
    // path is selected and both prompts are blank (so the mismatch
    // gate passes by both buffers being equal), the reducer surfaces
    // a rendered `PaladinError::InvalidPassphrase` with
    // `reason: "zero_length"` per docs/DESIGN.md §5, matching the CLI's
    // `prompt_new_passphrase` (mismatch first, then `zero_length`) and
    // the GTK `SubmitRejection::ZeroLength` wire code so the
    // user-facing reason stays stable across all three front-ends.
    // Routing the wording through `render_error_message` binds the
    // snapshot to the core `Display` impl
    // (`invalid passphrase: zero_length`) rather than a hand-typed
    // string so any future wording change in core surfaces here as a
    // diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        format: ExportFormat::Encrypted,
        error: Some(render_error_message(&PaladinError::InvalidPassphrase {
            reason: "zero_length",
        })),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::InvalidPassphrase {
        reason: "zero_length",
    });
    assert!(
        rendered.contains(&expected),
        "expected inline zero_length wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_plaintext_export_warning() {
    // Plan L2389: "Export modal plaintext-export warning." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { format: ExportFormat::Plaintext,
    // error: Some(format_plaintext_export_warning()),
    // plaintext_confirmed: false, .. })` open so the snapshot pins the
    // inline-error row populated from the plaintext unencrypted-secrets
    // acknowledgement gate per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals
    // (per §6) > Export": *"Plaintext exports render
    // `paladin_core::format_plaintext_export_warning()` verbatim and
    // the user must confirm before the write proceeds."*. Routing the
    // wording through `paladin_core::format_plaintext_export_warning`
    // binds the snapshot to the core helper rather than a hand-typed
    // string so wording stays in lockstep with the CLI's stderr
    // advisory (`paladin-cli/src/commands/export.rs`, docs/DESIGN.md §4.6 /
    // §6) and the GTK `ExportDialog`'s `plaintext_warning_body()`
    // checkbox label — any future wording change in core surfaces here
    // as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = ExportModal {
        format: ExportFormat::Plaintext,
        error: Some(format_plaintext_export_warning()),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    // Regression guard: a renderer that ever stops surfacing the
    // plaintext-export warning must fail this test even before the
    // human reads the snapshot diff. Bind the assertion to the leading
    // `WARNING: Plaintext export` substring (the full ~270-char
    // warning exceeds the inline-error slot's width and is truncated
    // by `Paragraph::new(Line::from(...))` per `view/export.rs`).
    assert!(
        rendered.contains("WARNING: Plaintext export"),
        "expected plaintext-export warning prefix to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_io_error() {
    // Plan L2390: "Export modal `io_error` writer failure." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error:
    // Some(render_error_message(&PaladinError::IoError { ... })), .. })`
    // open so the snapshot pins the inline-error row populated when
    // `paladin_core::write_secret_file_atomic` fails anywhere along
    // the staging / rename / parent-dir-fsync chain. The reducer's Err
    // arm (`reduce_export_result` in `src/app/reducer.rs`) routes the
    // error through `render_error_message` and parks the wording on
    // `ExportModal::error` per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests
    // > Export modal": *"Writer `io_error`, `save_not_committed`, and
    // `save_durability_unconfirmed` surface inline and the modal stays
    // open."* The view-snapshot pins the post-reduce rendering 1:1
    // with the reducer-side coverage from
    // `effect_result_export_err_io_error_surfaces_inline_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let err = PaladinError::IoError {
        operation: "write_secret_file_atomic",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic-denied"),
    };
    let modal = ExportModal {
        error: Some(render_error_message(&err)),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::IoError {
        operation: "write_secret_file_atomic",
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "synthetic-denied"),
    });
    assert!(
        rendered.contains(&expected),
        "expected inline io_error wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_save_not_committed() {
    // Plan L2442: "Export modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error:
    // Some(render_error_message(&PaladinError::SaveNotCommitted { .. })), .. })`
    // open so the snapshot pins the inline-error row populated when
    // `paladin_core::write_secret_file_atomic` fails before the
    // primary rename — the staging-file fsync / rename failure mode
    // per `docs/DESIGN.md` §4.3 / §5 `save_not_committed`. The reducer's
    // Err arm (`reduce_export_result` in `src/app/reducer.rs`) routes
    // the error through `render_error_message` and parks the wording
    // on `ExportModal::error` per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Tests > Export modal": *"Writer `io_error`,
    // `save_not_committed`, and `save_durability_unconfirmed` surface
    // inline and the modal stays open."* The view-snapshot pins the
    // post-reduce rendering 1:1 with the reducer-side coverage from
    // `effect_result_export_err_save_not_committed_surfaces_inline_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let modal = ExportModal {
        error: Some(render_error_message(&err)),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    });
    assert!(
        rendered.contains(&expected),
        "expected inline save_not_committed wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_export_modal_save_durability_unconfirmed() {
    // Plan L2443: "Export modal `save_durability_unconfirmed`." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Export(ExportModal { error:
    // Some(render_error_message(&PaladinError::SaveDurabilityUnconfirmed)), .. })`
    // open so the snapshot pins the inline-error row populated when
    // `paladin_core::write_secret_file_atomic`'s primary rename
    // succeeded but the parent-directory `fsync` failed — the
    // durability-unconfirmed failure mode per `docs/DESIGN.md` §4.3 / §5
    // `save_durability_unconfirmed`. The reducer's Err arm
    // (`reduce_export_result` in `src/app/reducer.rs`) routes the
    // error through `render_error_message` and parks the wording on
    // `ExportModal::error` per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Tests > Export modal": *"Writer `io_error`,
    // `save_not_committed`, and `save_durability_unconfirmed`
    // surface inline and the modal stays open."* The view-snapshot
    // pins the post-reduce rendering 1:1 with the reducer-side
    // coverage from
    // `effect_result_export_err_save_durability_unconfirmed_surfaces_inline_and_keeps_modal_open`
    // in `tests/reducer_tests.rs`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let modal = ExportModal {
        error: Some(render_error_message(&err)),
        ..ExportModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Export(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::SaveDurabilityUnconfirmed);
    assert!(
        rendered.contains(&expected),
        "expected inline save_durability_unconfirmed wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_set_default() {
    // Plan L1968: "Passphrase modal — `set` sub-flow." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase(PassphraseModal::default())` open so the
    // snapshot pins the freshly-opened (`PassphraseSubFlow::Set`,
    // empty `new_passphrase` / `confirm_passphrase` buffers, no
    // inline error) baseline of the Passphrase modal's `set`
    // sub-flow overlay rendered on top of the list view per
    // `docs/DESIGN.md` §6's "modal dialogs for add / remove / rename /
    // import / export / passphrase / settings" call-out and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) >
    // Passphrase" contract — *"three sub-flows mirroring CLI's
    // `passphrase set / change / remove`. … New passphrases (`set`,
    // `change`) are prompted twice and confirmed; mismatch returns
    // to the modal with an inline `invalid_passphrase`
    // (`reason: "confirmation_mismatch"`) error."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_passphrase_modal_change_default() {
    // Plan L2002: "Passphrase modal — `change` sub-flow." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase` open and `sub_flow: PassphraseSubFlow::Change`
    // so the snapshot pins the freshly-opened (empty `new_passphrase`
    // / `confirm_passphrase` buffers, no inline error) baseline of
    // the Passphrase modal's `change` sub-flow overlay. The `change`
    // sub-flow is the encrypted → encrypted re-key transition per
    // `docs/DESIGN.md` §6's "modal dialogs for add / remove / rename /
    // import / export / passphrase / settings" call-out and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Passphrase"
    // contract — *"three sub-flows mirroring CLI's `passphrase set /
    // change / remove`. … New passphrases (`set`, `change`) are
    // prompted twice and confirmed; mismatch returns to the modal
    // with an inline `invalid_passphrase` (`reason:
    // "confirmation_mismatch"`) error."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Change,
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_passphrase_modal_remove_default() {
    // Plan L2003: "Passphrase modal — `remove` sub-flow." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase` open and `sub_flow: PassphraseSubFlow::Remove`
    // so the snapshot pins the freshly-opened (no inline error,
    // unused `new_passphrase` / `confirm_passphrase` buffers)
    // baseline of the Passphrase modal's `remove` sub-flow overlay.
    // The `remove` sub-flow is the encrypted → plaintext transition
    // per `docs/DESIGN.md` §6 and the `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Passphrase" contract — *"`remove` shows the
    // plaintext-storage warning and requires explicit confirmation
    // before mutation. Source the `passphrase remove` warning from
    // `paladin_core::format_plaintext_storage_warning()`."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Remove,
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_passphrase_modal_confirmation_mismatch() {
    // Plan L2787: "Passphrase modal `confirmation_mismatch` inline error."
    // Drive `view::render` against an `Unlocked` state with
    // `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
    // Some(render_error_message(&PaladinError::InvalidPassphrase
    // { reason: "confirmation_mismatch" })), .. })` open so the
    // snapshot pins the inline-error row populated from the twice-confirm
    // mismatch gate per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6)
    // > Passphrase": *"New passphrases (`set`, `change`) are prompted
    // twice and confirmed; mismatch returns to the modal with an inline
    // `invalid_passphrase` (`reason: "confirmation_mismatch"`) error."*
    // The reducer's `Passphrase` arm in
    // `crates/paladin-tui/src/app/reducer.rs` surfaces the mismatch
    // through `PaladinError::InvalidPassphrase { reason:
    // "confirmation_mismatch" }`, matching the CLI's
    // `prompt_new_passphrase` and the GTK `SubmitRejection::
    // ConfirmationMismatch` wire code so the user-facing reason stays
    // stable across all three front-ends. Routing the wording through
    // the shared `render_error_message` helper binds the snapshot to
    // the core `Display` impl (`invalid passphrase: confirmation_mismatch`)
    // rather than a hand-typed string so any future wording change in
    // core surfaces here as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = PassphraseModal {
        sub_flow: PassphraseSubFlow::Set,
        error: Some(render_error_message(&PaladinError::InvalidPassphrase {
            reason: "confirmation_mismatch",
        })),
        ..PassphraseModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::InvalidPassphrase {
        reason: "confirmation_mismatch",
    });
    assert!(
        rendered.contains(&expected),
        "expected inline confirmation_mismatch wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_zero_length() {
    // Plan L2788: "Passphrase modal `zero_length` inline error." Drive
    // `view::render` against an `Unlocked` state with
    // `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
    // Some(render_error_message(&PaladinError::InvalidPassphrase
    // { reason: "zero_length" })), .. })` open so the snapshot pins
    // the inline-error row populated from the twice-confirm
    // empty-passphrase gate per `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Modals (per §6) > Passphrase": *"Empty passphrase entries are
    // rejected with an inline `invalid_passphrase` (`reason:
    // "zero_length"`) error."*. When both `new_passphrase` and
    // `confirm_passphrase` are empty (so the mismatch gate passes by
    // both buffers being equal), the reducer surfaces a rendered
    // `PaladinError::InvalidPassphrase` with `reason: "zero_length"`
    // per docs/DESIGN.md §5, matching the CLI's `prompt_new_passphrase`
    // (mismatch first, then `zero_length`) and the GTK
    // `SubmitRejection::ZeroLength` wire code so the user-facing
    // reason stays stable across all three front-ends. Routing the
    // wording through `render_error_message` binds the snapshot to
    // the core `Display` impl (`invalid passphrase: zero_length`)
    // rather than a hand-typed string so any future wording change in
    // core surfaces here as a diff.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let modal = PassphraseModal {
        sub_flow: PassphraseSubFlow::Set,
        error: Some(render_error_message(&PaladinError::InvalidPassphrase {
            reason: "zero_length",
        })),
        ..PassphraseModal::default()
    };
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(modal)),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    let expected = render_error_message(&PaladinError::InvalidPassphrase {
        reason: "zero_length",
    });
    assert!(
        rendered.contains(&expected),
        "expected inline zero_length wording {expected:?} to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_set_save_not_committed() {
    // Plan L2198: "Passphrase set `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Passphrase(PassphraseModal { sub_flow: Set, error:
    // Some(render_error_message(&PaladinError::SaveNotCommitted {
    // committed: false, backup_path: None })), .. })` so the
    // snapshot pins the inline-error row populated from a pre-commit
    // save failure per `docs/DESIGN.md` §5's `save_not_committed`
    // discriminator. Routing the wording through the shared
    // `render_error_message` helper means the inline text matches
    // the rest of the TUI's error surface — the unlock screen's
    // `decrypt_failed` line and the Add / Remove / Rename / Import
    // modals' inline-error slots.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_set_save_durability_unconfirmed() {
    // Plan L2199: "Passphrase set `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Set,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_change_save_not_committed() {
    // Plan L2200: "Passphrase change `save_not_committed`." Mirrors
    // the `set` save_not_committed test above with
    // `sub_flow: PassphraseSubFlow::Change` so the snapshot pins
    // that the inline-error slot lights up identically in the
    // encrypted → encrypted re-key transition. The bordered-block
    // title flips to ` Change passphrase ` and the intent line
    // reads `Re-encrypts this vault under a new passphrase.`; the
    // body shape, the error row placement, and the surrounding
    // list-view chrome all match the `set` baseline.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Change,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording in change modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_change_save_durability_unconfirmed() {
    // Plan L2201: "Passphrase change `save_durability_unconfirmed`."
    // Same rendering path as the `change` save_not_committed snapshot
    // above; typed against `PaladinError::SaveDurabilityUnconfirmed`
    // per the plan's "Durability-unconfirmed failures follow the
    // committed-state path" contract.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Change,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in change modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_remove_save_not_committed() {
    // Plan L2202: "Passphrase remove `save_not_committed`." Mirrors
    // the `set` / `change` save_not_committed tests but for the
    // encrypted → plaintext transition. The `remove` sub-flow's
    // body — wrapped plaintext-storage warning sourced verbatim
    // from [`paladin_core::format_plaintext_storage_warning`] — stays
    // intact above the inline error, and the inline error is painted
    // between the warning and the `Enter confirm  ·  Esc cancel`
    // hint so the destructive-mutation verb remains visible while
    // surfacing the save failure.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Remove,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording in remove modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_passphrase_modal_remove_save_durability_unconfirmed() {
    // Plan L2203: "Passphrase remove `save_durability_unconfirmed`."
    // Same rendering path as the `remove` save_not_committed
    // snapshot above; typed against
    // `PaladinError::SaveDurabilityUnconfirmed` per the plan's
    // "Durability-unconfirmed failures follow the committed-state
    // path" contract.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Passphrase(PassphraseModal {
            sub_flow: PassphraseSubFlow::Remove,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..PassphraseModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in remove modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_settings_modal_default() {
    // Plan L2004: "Settings modal." Drive `view::render` against an
    // `Unlocked` state with `Modal::Settings(SettingsModal { .. })`
    // open so the snapshot pins the freshly-opened (no inline error)
    // baseline of the Settings modal overlay rendered on top of the
    // list view per `docs/DESIGN.md` §6 and the
    // `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Modals (per §6) > Settings"
    // contract — *"toggles for `auto_lock.enabled` and
    // `clipboard.clear_enabled`, spinners for `auto_lock.timeout_secs`
    // and `clipboard.clear_secs`. … The modal accumulates pending
    // edits in modal-local state and only commits on Confirm."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            ..SettingsModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 20));
}

#[test]
fn snapshot_settings_modal_save_not_committed() {
    // Plan L2255: "Settings modal `save_not_committed`." Drive
    // `view::render` against an `Unlocked` state holding
    // `Modal::Settings(SettingsModal { error: Some(render_error_message(
    // &PaladinError::SaveNotCommitted { committed: false, backup_path:
    // None })), .. })` so the snapshot pins the inline-error row
    // populated from a pre-commit save failure per `docs/DESIGN.md` §5's
    // `save_not_committed` discriminator. Routing the wording through
    // the shared `render_error_message` helper means the inline text
    // matches the rest of the TUI's error surface — the unlock
    // screen's `decrypt_failed` line and the Add / Remove / Rename /
    // Import / Passphrase modals' inline-error slots.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            error: Some(render_error_message(&PaladinError::SaveNotCommitted {
                committed: false,
                backup_path: None,
            })),
            ..SettingsModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save not committed"),
        "expected inline save_not_committed wording in settings modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_settings_modal_save_durability_unconfirmed() {
    // Plan L2256: "Settings modal `save_durability_unconfirmed`." Same
    // rendering path as the `save_not_committed` snapshot above; the
    // typed error here is `PaladinError::SaveDurabilityUnconfirmed`,
    // which per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Durability-unconfirmed
    // failures follow the committed-state path" surfaces in the
    // modal's inline error slot identically to the pre-commit
    // failure — both paths run through `render_error_message`.
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: Some(Modal::Settings(SettingsModal {
            auto_lock_enabled: false,
            auto_lock_timeout_secs: 300,
            clipboard_clear_enabled: false,
            clipboard_clear_secs: 20,
            error: Some(render_error_message(
                &PaladinError::SaveDurabilityUnconfirmed,
            )),
            ..SettingsModal::default()
        })),
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    let rendered = render_to_text(&state, snapshot_now(), 80, 20);
    assert!(
        rendered.contains("save durability unconfirmed"),
        "expected inline save_durability_unconfirmed wording in settings modal:\n{rendered}"
    );
    insta::assert_snapshot!(rendered);
}

#[test]
fn snapshot_help_overlay() {
    // Plan L2071: "Help overlay." Drive `view::render` against an
    // `Unlocked` state with `help_open: true` so the snapshot pins
    // the read-only Help overlay rendered on top of the list view
    // per `docs/DESIGN.md` §6 and the `docs/IMPLEMENTATION_PLAN_03_TUI.md`
    // "Help overlay" contract — *"`?` from list focus opens a
    // read-only Help overlay listing every keybinding from the
    // table below; `Esc` closes the overlay and restores list
    // focus. The overlay has no inputs and never mutates vault
    // state."*
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let state = AppState::Unlocked {
        path,
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: None,
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: true,
    };
    // Bumped to 33 rows (was 32) for the v0.2 `Shift+E` Edit
    // keybind row that the Help overlay enumerates from
    // `keybindings::KEYBINDINGS`.
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 33));
}

#[test]
fn snapshot_startup_error_unsafe_permissions() {
    // Plan L1806: "Startup-error screen rendered with `unsafe_permissions`
    // (the `Some(text)` from `format_unsafe_permissions`)." Build the error
    // through the public core API so the snapshot binds the verbatim
    // wording from `paladin_core::format_unsafe_permissions`; any future
    // wording change in core is then surfaced as a diff in this snapshot.
    let path = PathBuf::from("/var/lib/paladin/vault.bin");
    let err = PaladinError::UnsafePermissions {
        path: path.clone(),
        subject: PermissionSubject::VaultDir,
        actual_mode: "0755".to_string(),
        expected_mode: "0700".to_string(),
    };
    let message = format_unsafe_permissions(&err).expect("unsafe_permissions text");
    let state = AppState::StartupError {
        path: Some(path),
        message,
    };
    insta::assert_snapshot!(render_to_text(&state, snapshot_now(), 80, 12));
}

// ---------------------------------------------------------------------------
// QR Export modal — insta snapshot coverage
//
// The modal is 72x24 (centered) per `crates/paladin-tui/src/view/qr.rs`, so
// each snapshot renders into an 80x32 TestBackend — wide enough to fit the
// modal plus the list-view chrome that paints underneath, tall enough to
// fit the modal's full inner body (warning paragraph wrap on Page 1, the
// half-block QR grid on Page 2). Tracks
// `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Tests > QR Export modal > Insta
// snapshots" bullets.
// ---------------------------------------------------------------------------

/// Build a [`KeyCode`]-only [`AppEvent::Input`] event with no modifiers.
/// Mirrors the `key(...)` helper used throughout `tests/reducer_tests.rs`
/// so the drive sequence (`Q` → Space → Enter → Tab → typing → Enter)
/// matches the reducer-side coverage byte-for-byte.
fn qr_key(code: KeyCode) -> AppEvent {
    AppEvent::Input {
        event: Event::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        at: Instant::now(),
    }
}

/// Drive a sequence of [`KeyCode`] events through the reducer, discarding
/// any emitted effects (the QR Export snapshot suite never asserts on
/// effects — that's reducer-test territory).
fn qr_drive(mut state: AppState, codes: &[KeyCode]) -> AppState {
    for code in codes {
        let (next, _effects) = reduce(state, qr_key(*code));
        state = next;
    }
    state
}

/// Type each character of `s` into the focused control via `KeyCode::Char`.
/// Same helper shape as `reducer_tests.rs::type_chars`.
fn qr_type_chars(mut state: AppState, s: &str) -> AppState {
    for ch in s.chars() {
        let (next, _) = reduce(state, qr_key(KeyCode::Char(ch)));
        state = next;
    }
    state
}

/// Build an [`AppState::Unlocked`] backed by a plaintext vault with one
/// TOTP account preselected. Mirrors `reducer_tests.rs::qr_unlocked_with_one_totp`
/// but uses the snapshot-suite tempdir helper so permissions match the rest of
/// the file's fixtures.
fn qr_unlocked_with_one_totp_snapshot() -> (AppState, AccountId, PathBuf, TempDirGuard) {
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_totp_account(&mut vault, &store, Some("GitHub"), "ben@example.com");
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (state, id, path, TempDirGuard::new(tmp))
}

/// Same as [`qr_unlocked_with_one_totp_snapshot`] but with a single HOTP
/// account at counter `0`. Used by `qr_export_modal_page2_hotp` so the QR
/// payload encodes `otpauth://hotp/...` instead of `otpauth://totp/...`.
fn qr_unlocked_with_one_hotp_snapshot() -> (AppState, AccountId, PathBuf, TempDirGuard) {
    let tmp = secure_test_tempdir();
    let path = tmp.path().join("vault.bin");
    create_plaintext_vault(&path);
    let (mut vault, store) = Store::open(&path, VaultLock::Plaintext).expect("reopen vault");
    let id = push_hotp_account(&mut vault, &store, Some("Bank"), "savings", 0);
    let state = AppState::Unlocked {
        path: path.clone(),
        vault,
        store,
        search_query: String::new(),
        idle_deadline: None,
        pending_clipboard_clear: None,
        hotp_reveal: None,
        modal: None,
        selected: Some(id),
        pending_chord_leader: None,
        viewport_height: 0,
        viewport_offset: 0,
        focus: Focus::List,
        status_line: None,
        help_open: false,
    };
    (state, id, path, TempDirGuard::new(tmp))
}

/// Holds a `TempDir` alive for the lifetime of one test so the vault path
/// the snapshot's reducer-driven QR effect references stays valid. Drops
/// (and removes) on test exit per `tempfile`'s usual contract.
struct TempDirGuard(#[allow(dead_code)] tempfile::TempDir);

impl TempDirGuard {
    fn new(tmp: tempfile::TempDir) -> Self {
        Self(tmp)
    }
}

#[test]
fn snapshot_qr_export_modal_warning_ack_unchecked() {
    // Plan: "Page 1 on open, ack off, Cancel-button reachable via Tab."
    // Drive `Q` from list focus to open the QR Export modal, then `Tab`
    // once so the Cancel-button focus is visible (the snapshot pins the
    // focus arrow on `Cancel` rather than the ack checkbox to make
    // tab-reachability visible in the grid).
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(state, &[KeyCode::Char('Q'), KeyCode::Tab]);
    insta::assert_snapshot!(
        "qr_export_modal_warning_ack_unchecked",
        render_to_text(&state, snapshot_now(), 80, 32)
    );
}

#[test]
fn snapshot_qr_export_modal_page2_totp() {
    // Plan: "Page 2 with a TOTP account's QR rendered, captured
    // immediately after ack-toggle-on." Drive `Q` → Space so the modal
    // advances to Page 2 with `staged_ansi` populated from
    // `Vault::export_qr_ansi(id)`.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(state, &[KeyCode::Char('Q'), KeyCode::Char(' ')]);
    insta::assert_snapshot!(
        "qr_export_modal_page2_totp",
        render_to_text(&state, snapshot_now(), 80, 32)
    );
}

#[test]
fn snapshot_qr_export_modal_page2_hotp() {
    // Plan: "Page 2 with a HOTP account." Same drive sequence as the
    // TOTP variant but seeded with a single HOTP account; the staged
    // ANSI body therefore encodes the HOTP `otpauth://hotp/...` URI.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_hotp_snapshot();
    let state = qr_drive(state, &[KeyCode::Char('Q'), KeyCode::Char(' ')]);
    insta::assert_snapshot!(
        "qr_export_modal_page2_hotp",
        render_to_text(&state, snapshot_now(), 80, 32)
    );
}

#[test]
fn snapshot_qr_export_modal_save_destination_prompt() {
    // Plan: "Page 2 + save sub-flow on EnterPath with a typed path."
    // Drive into Page 2, Enter on `Save as PNG…` to open the sub-flow,
    // then type a fixed path so the destination field is non-empty.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(
        state,
        &[KeyCode::Char('Q'), KeyCode::Char(' '), KeyCode::Enter],
    );
    let state = qr_type_chars(state, "/tmp/qr.png");
    insta::assert_snapshot!(
        "qr_export_modal_save_destination_prompt",
        render_to_text(&state, snapshot_now(), 80, 32)
    );
}

#[test]
fn snapshot_qr_export_modal_save_overwrite_gate() {
    // Plan: "Page 2 + save sub-flow on OverwriteGate." Drive the
    // reducer to Page 2 (so `staged_ansi` is populated by the real
    // ack-toggle path), then patch the modal's `save_sub_flow` slot
    // directly into the overwrite-gate shape with a deterministic
    // path. Driving the gate through the filesystem would bake the
    // tempdir's random suffix into the snapshot — the gate's behavior
    // is locked separately in
    // `reducer_tests.rs::qr_export_modal_save_with_existing_destination_shows_overwrite_gate`.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(state, &[KeyCode::Char('Q'), KeyCode::Char(' ')]);
    let state = patch_qr_modal(state, |qr| {
        qr.focus = paladin_tui::app::state::QrExportFocus::SavePngButton;
        qr.save_sub_flow = Some(paladin_tui::app::state::QrSaveSubFlow {
            format: paladin_tui::app::state::QrSaveFormat::Png,
            path_text: "/tmp/qr.png".to_string(),
            step: QrSaveStep::OverwriteGate,
            overwrite_ack: false,
            focus: QrSaveFocus::OverwriteAck,
            error: None,
        });
    });
    insta::assert_snapshot!(
        "qr_export_modal_save_overwrite_gate",
        render_to_text(&state, snapshot_now(), 80, 32)
    );
}

/// Apply `patch` to the open [`QrExportModal`] on an
/// [`AppState::Unlocked`]. Panics if the state is not on `Unlocked`
/// with a QR Export modal open — every caller drives the modal open
/// before calling this helper, so the panic is a programmer-error
/// guard rather than a recoverable path.
fn patch_qr_modal<F>(state: AppState, patch: F) -> AppState
where
    F: FnOnce(&mut paladin_tui::app::state::QrExportModal),
{
    match state {
        AppState::Unlocked {
            path,
            vault,
            store,
            search_query,
            idle_deadline,
            pending_clipboard_clear,
            hotp_reveal,
            modal,
            selected,
            pending_chord_leader,
            viewport_height,
            viewport_offset,
            focus,
            status_line,
            help_open,
        } => {
            let modal = match modal {
                Some(Modal::QrExport(mut qr)) => {
                    patch(&mut qr);
                    Some(Modal::QrExport(qr))
                }
                other => panic!("expected QR modal open, got modal={other:?}"),
            };
            AppState::Unlocked {
                path,
                vault,
                store,
                search_query,
                idle_deadline,
                pending_clipboard_clear,
                hotp_reveal,
                modal,
                selected,
                pending_chord_leader,
                viewport_height,
                viewport_offset,
                focus,
                status_line,
                help_open,
            }
        }
        other => panic!("expected AppState::Unlocked, got {other:?}"),
    }
}

#[test]
fn snapshot_qr_export_modal_save_succeeded() {
    // Plan: "Page 2 with last_save_path set + no active sub-flow."
    // Drive into the sub-flow, type a path, then inject a synthetic
    // `EffectResult::QrExport(Ok(path))` so the reducer closes the
    // sub-flow and stashes the path in `last_save_path` for the green
    // `Saved to …` row.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(
        state,
        &[KeyCode::Char('Q'), KeyCode::Char(' '), KeyCode::Enter],
    );
    let state = qr_type_chars(state, "/tmp/qr.png");
    let written = PathBuf::from("/tmp/qr.png");
    let (state, _effects) = reduce(
        state,
        AppEvent::EffectResult(EffectResult::QrExport {
            result: Ok(written.clone()),
        }),
    );
    // Sanity: the success result should have populated last_save_path.
    match &state {
        AppState::Unlocked {
            modal: Some(Modal::QrExport(qr)),
            ..
        } => {
            assert_eq!(qr.last_save_path.as_deref(), Some(written.as_path()));
            assert!(qr.save_sub_flow.is_none());
        }
        other => panic!("expected QR modal on Page 2, got {other:?}"),
    }
    insta::assert_snapshot!(
        "qr_export_modal_save_succeeded",
        render_to_text(&state, snapshot_now(), 80, 32)
    );
}

#[test]
fn snapshot_qr_export_modal_save_failed_pre_commit() {
    // Plan: "Page 2 + save sub-flow showing save_not_committed inline
    // error." Drive into the sub-flow, type a path, then inject a
    // synthetic `EffectResult::QrExport(Err(SaveNotCommitted { .. }))`
    // so the reducer parks the rendered wording on
    // `QrSaveSubFlow::error` for the inline-error row.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(
        state,
        &[KeyCode::Char('Q'), KeyCode::Char(' '), KeyCode::Enter],
    );
    let state = qr_type_chars(state, "/tmp/qr.png");
    let err = PaladinError::SaveNotCommitted {
        committed: false,
        backup_path: None,
    };
    let (state, _effects) = reduce(
        state,
        AppEvent::EffectResult(EffectResult::QrExport { result: Err(err) }),
    );
    let rendered = render_to_text(&state, snapshot_now(), 80, 32);
    // Regression guard mirrors the Export modal's inline-error guards.
    assert!(
        rendered.contains("save not committed") || rendered.contains("save_not_committed"),
        "expected inline save_not_committed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!("qr_export_modal_save_failed_pre_commit", rendered);
}

#[test]
fn snapshot_qr_export_modal_save_failed_durability_unconfirmed() {
    // Plan: same as `save_failed_pre_commit` but for
    // `SaveDurabilityUnconfirmed` — the primary rename succeeded but
    // the parent-directory fsync failed.
    let (state, _id, _path, _guard) = qr_unlocked_with_one_totp_snapshot();
    let state = qr_drive(
        state,
        &[KeyCode::Char('Q'), KeyCode::Char(' '), KeyCode::Enter],
    );
    let state = qr_type_chars(state, "/tmp/qr.png");
    let err = PaladinError::SaveDurabilityUnconfirmed;
    let (state, _effects) = reduce(
        state,
        AppEvent::EffectResult(EffectResult::QrExport { result: Err(err) }),
    );
    let rendered = render_to_text(&state, snapshot_now(), 80, 32);
    assert!(
        rendered.to_lowercase().contains("durability")
            || rendered.contains("save_durability_unconfirmed"),
        "expected inline save_durability_unconfirmed wording to appear in modal:\n{rendered}"
    );
    insta::assert_snapshot!(
        "qr_export_modal_save_failed_durability_unconfirmed",
        rendered
    );
}
