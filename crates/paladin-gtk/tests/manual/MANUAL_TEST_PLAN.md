<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# `paladin-gtk` Manual Test Plan

This document is the human-driven QA checklist for `paladin-gtk`. It
complements the pure-logic unit tests under
`crates/paladin-gtk/tests/*_logic.rs` and the headless `xvfb-run` smoke
test at `crates/paladin-gtk/tests/gtk_smoke.rs` by exercising paths the
automated suites cannot cover — real display servers, real clipboards,
real file dialogs, real icon themes, and real user interaction.

Authoritative source for the required-item list:
[`docs/IMPLEMENTATION_PLAN_04_GTK.md`](../../../../docs/IMPLEMENTATION_PLAN_04_GTK.md)
§"Tests > Manual test plan (`tests/manual/MANUAL_TEST_PLAN.md`)" and
the Milestone 7 checklist entry "Manual test plan documented".
`crates/paladin-gtk/tests/manual_test_plan_doc.rs` guards drift between
this file and the plan; if it fails, update this file rather than the
test.

## Sign-off requirements

Each item below must execute cleanly on **both a Wayland and an X11
session** before Milestone 7 sign-off. Run the full checklist twice —
once with `WAYLAND_DISPLAY` set (native Wayland under GNOME / KDE) and
once with `XDG_SESSION_TYPE=x11` (X11 fallback / Xorg session) — and
record both results in the release notes.

Some items also have CI-side coverage (pure-logic state machines, the
`xvfb-run` smoke test). Manual sign-off still applies because the
display-server and IPC integrations are out of scope for those.

## Preparation

Before running the plan:

1. Build the binary in release mode: `cargo build --release -p paladin-gtk`.
2. Pick a scratch `XDG_DATA_HOME` so the QA run never touches real data:
   `export XDG_DATA_HOME="$(mktemp -d)/paladin-qa"`.
3. Note which session type you are on:
   `echo "$XDG_SESSION_TYPE" "$WAYLAND_DISPLAY"`.
4. For the §10 fault-injection items, build with the fault-injection
   feature flag exposed by `paladin-core` (see `docs/DESIGN.md` §10) and
   note the toggle environment variable on each affected test result.
5. For the clipboard-image items, prepare both a valid `otpauth://` QR
   image and an intentionally oversized image (above
   `paladin_core::import::QR_IMAGE_MAX_BYTES`).

Conventions in this file:

* `- [ ]` is unchecked; tick on a successful Wayland + X11 pass.
* "Expected" describes the user-visible outcome. If reality diverges,
  do not tick the box — file a bug instead.
* "Tied to" cross-references the relevant pure-logic test or
  `docs/DESIGN.md` clause so a fix can be located quickly.

## 1. Vault initialization (`InitDialog`)

- [ ] Init plaintext vault: both passphrase fields empty + warning
  gate before submit is enabled.
  * Expected: the `format_plaintext_storage_warning()` text from
    `paladin-core` is rendered verbatim, the Submit button stays
    insensitive until the warning checkbox is ticked, and the
    resulting vault file lands at the configured path with
    `0600` permissions.
  * Tied to: `tests/init_dialog_logic.rs` plaintext routing,
    `docs/DESIGN.md` §4.5.
- [ ] Init encrypted vault with twice-confirm.
  * Expected: both passphrase rows accept input, the second row
    rejects mismatches inline, and a successful pair encrypts the
    new vault (`mode == encrypted` in the on-disk header).
- [ ] Init when a vault already exists at the path opens the
  destructive-confirmation gate; confirm runs `create_force` and
  rotates the prior vault to `vault.bin.bak`; cancel leaves the
  prior vault intact.
  * Expected: the destructive-confirmation dialog renders the
    `format_init_force_warning(existing_path)` text verbatim; on
    cancel, the prior vault's bytes are unchanged on disk; on
    confirm, the prior bytes appear at `vault.bin.bak` and the new
    vault overwrites `vault.bin`.
  * Tied to: `paladin_core::classify_init_precheck`,
    `paladin_core::create_force`.
- [ ] Init under the §10 fault-injection hook surfaces
  `save_not_committed` and `save_durability_unconfirmed` inline.
  * Expected: with the fault-injection toggle armed for each error,
    the dialog stays open with an inline error and the in-memory
    vault state is preserved (`save_not_committed`) or kept with a
    warning (`save_durability_unconfirmed`). Tested separately for
    `create` and `create_force` paths.

## 2. Vault unlock

- [ ] Unlock encrypted vault with the correct passphrase.
  * Expected: the unlock dialog accepts the passphrase, the
    auto-lock timer arms (if enabled in settings), and the account
    list renders. An incorrect passphrase rejects inline without
    leaking timing information beyond the standard Argon2id cost.

## 3. Code generation and HOTP reveal

- [ ] Copy a TOTP code from a row.
  * Expected: clicking the row's copy affordance places the current
    TOTP code on the system clipboard, the row briefly indicates
    success, and (if clipboard auto-clear is enabled) the value is
    cleared per the configured interval and if-unchanged rule.
- [ ] Single-click anywhere on the TOTP row body (account name,
  code cell, time cell) copies the current code.
  * Expected: the `ColumnView` is built with
    `single_click_activate(true)`, so a single click on any
    non-button cell of a TOTP row fires the same
    `AccountListOutput::CopyCode` path as the per-row Copy button.
    Clicking the Next cell button still copies the **next** code
    (toast `Next code copied, valid in Xs`) and never doubles up
    by also copying the current code. Clicking the Copy button
    or the kebab `⋮` button fires only that button's own action.
  * Tied to: `default_row_activation`, the
    `column_view.connect_activate` wiring in `account_list.rs`.
- [ ] Single-click on a hidden HOTP row body advances + copies.
  * Expected: clicking a hidden HOTP row body emits
    `AccountListOutput::ActivateHotpAndCopy(id)`; the counter
    advances exactly once on disk and the freshly revealed code
    lands on the clipboard via the `pending_copy_after_advance`
    latch. Clicking the row body again during the reveal window
    copies the visible code without advancing.
- [ ] HOTP `next` reveals and copies while showing the counter
  used.
  * Expected: activating `next` advances the on-disk counter
    exactly once, the visible counter label tracks
    `Code.counter_used`, and the code is copied to the clipboard.
    Activating `next` again during the reveal window advances the
    counter again and restarts the shared reveal window with the
    newly committed code.
  * Tied to: `tests/hotp_reveal_logic.rs`.
- [ ] HOTP reveal window expires and the row returns to hidden.
  * Expected: after `paladin_core::HOTP_REVEAL_SECS`, the row
    re-hides the code and reverts the visible counter to the
    stored next value.

## 4. Auto-lock and clipboard auto-clear

- [ ] Auto-lock fires after the configured idle interval (encrypted
  vault).
  * Expected: with the encrypted vault open and auto-lock enabled,
    leaving the app idle for the configured number of seconds
    drops `Vault`, switches the model to `Locked`, and presents the
    unlock dialog. Plaintext vaults must **not** arm auto-lock
    (encrypted-only per the plan).
  * Tied to: `tests/auto_lock_logic.rs`, `Vault::is_encrypted()`.
- [ ] Clipboard auto-clear honors the if-unchanged rule.
  * Expected: after a copy with auto-clear enabled, the clipboard
    is cleared only if the user has not replaced the captured
    value (the captured `Zeroizing<Vec<u8>>` is checked against
    the live clipboard before clear); replacing the value before
    the timer fires must leave the user's new content alone.
  * Tied to: `tests/clipboard_clear_logic.rs`.

## 5. Adding accounts

- [ ] Add via manual fields.
  * Expected: filling label / issuer / secret and selecting
    `totp` / `hotp` opens validation feedback; submitting commits
    via `Vault::add_account` inside `mutate_and_save`; cancel
    zeroizes the hidden Base32 secret buffer.
- [ ] Add via `otpauth://` URI paste — success path.
  * Expected: pasting a valid URI parses through
    `paladin_core::parse_otpauth`, fills the preview, and submits
    via the same `mutate_and_save` path as manual fields.
- [ ] Add via `otpauth://` URI paste — malformed-URI rejection
  stays inline.
  * Expected: malformed URI, unsupported scheme, unsupported
    `type=`, and validation errors render inline without
    transitioning out of the Add dialog. Error text may name the
    failing field or reason but **never echoes the URI text**.
  * Tied to: `tests/otpauth_uri_paste_logic.rs`.
- [ ] Add via `otpauth://` URI paste — duplicate "add anyway"
  round-trip.
  * Expected: a URI whose secret matches an existing account opens
    the duplicate confirmation; choosing "add anyway" consumes the
    pending `ValidatedAccount` and commits; cancelling discards it
    and zeroizes the pending state.
- [ ] Switching Add paths clears hidden secret fields and pending
  duplicate state.
  * Expected: toggling between manual, URI paste, and clipboard
    image tabs clears the hidden Base32 secret, the URI text, and
    any pending `ValidatedAccount` before the new path becomes
    active.
  * Tied to: `tests/secret_fields_logic.rs`.
- [ ] Add via clipboard image — success path.
  * Expected: a valid `otpauth://` QR image on the clipboard is
    decoded via `paladin_core::import::qr_image_bytes` (no `image`
    or `rqrr` reaches `paladin-gtk` directly), the resulting
    `ValidatedAccount` flows through the same submit path, and
    the source RGBA buffer is dropped before commit.
- [ ] Add via clipboard image — oversized-image rejection before
  download.
  * Expected: a clipboard image whose byte size exceeds
    `paladin_core::import::QR_IMAGE_MAX_BYTES` is rejected inline
    **before** the buffer is copied off the clipboard. No partial
    state is left in the Add dialog.
  * Tied to: `tests/qr_clipboard_logic.rs`.

## 6. Import / Export

For each import case, run the test three times — once with each
on-conflict policy (`skip`, `replace`, `append`) — and verify the
post-merge counts (`imported` / `skipped` / `replaced` / `appended`
/ `warnings`) reported in the dialog match the actual change to the
account list. Refer to `tests/import_dialog_logic.rs` for the
expected routing.

- [ ] Import otpauth JSON with each on-conflict policy; reported
  counts match.
- [ ] Import aegis plaintext with each on-conflict policy; reported
  counts match.
- [ ] Import encrypted Paladin bundle with each on-conflict policy;
  reported counts match.
  * Expected: the bundle-passphrase row is prompted only when
    `paladin_core::classify_paladin_import_precheck` returns
    `PromptForPassphrase`; `Reject(err)` shows inline; `NoPrompt`
    proceeds without prompting.
- [ ] Import QR image file with each on-conflict policy; reported
  counts match.
- [ ] Auto-lock fires while the Import dialog is open — the dialog's
  buttons must not abort the process when clicked afterwards.
  * Expected: with an encrypted vault, drop the auto-lock interval
    to the minimum, open the Import dialog (optionally pick a
    source file), leave the window idle until the timer fires.
    The vault locks and the unlock prompt appears. If the Import
    dialog widget is still visible on top, clicking its Cancel /
    Import / Choose file… buttons (or pressing Escape) is a benign
    no-op rather than a process abort, because the button closures
    route through `Sender::send` instead of
    `ComponentSender::input`. Same for the file-picker callback
    landing after lock.
  * Tied to: `crates/paladin-gtk/src/import_dialog.rs`
    `connect_clicked` closures, `crates/paladin-gtk/src/app/model.rs`
    `lock_on_auto_lock_expiry`.
- [ ] Cancel button dismisses the Import / Export / Show-QR /
  Settings dialog on the first click.
  * Expected: open the Import dialog from the application menu and
    click Cancel — the dialog disappears immediately. Repeat for
    the Export dialog, the per-row Show QR dialog (kebab → "Show
    QR code…"), and the Settings preferences dialog. Also verify
    the Import post-success `Dismiss` button (after a successful
    merge) and the Export post-success `Close` (after a successful
    export) tear the dialog down on the first click. Without the
    fix the controller dropped but the `adw::Dialog` widget stayed
    presented because the dialog host kept its reference, so the
    dialog appeared frozen.
  * Tied to: `crates/paladin-gtk/src/app/model.rs`
    `ImportDialogAction(Cancel|Close)`,
    `ExportDialogAction(Cancel|Close)`,
    `ExportQrDialogAction(Cancel|Close)`,
    `SettingsDialogAction(Close)` arms — all call
    `controller.widget().force_close()` before dropping, mirroring
    `PassphraseDialogAction(Close)`.

Exports:

- [ ] Export plaintext: warning + confirmation, `0600` output.
  * Expected: `format_plaintext_export_warning()` is rendered
    verbatim, the destination file lands with `0600`
    permissions, and refusing the warning leaves no output on
    disk.
- [ ] Export encrypted Paladin bundle: twice-confirm, round-trip
  via Import.
  * Expected: the second passphrase row rejects mismatch inline;
    a successful export round-trips through the Import path back
    to the original account set.
- [ ] Refused overwrite without confirmation leaves the destination
  untouched.
  * Expected: when the destination exists and the overwrite gate
    is **not** confirmed, the prior bytes on disk are unchanged
    (no truncate, no partial write).

## 7. Account management

- [ ] Rename an account via the row kebab menu: label persists on
  reopen.
  * Expected: opening the row's kebab menu surfaces "Edit…", the
    dialog edits the label only (issuer is not editable per CLI
    parity until the EditDialog widget lands), and the new label
    persists after closing and re-opening the vault.
  * Tied to: `tests/rename_dialog_logic.rs`.
- [ ] Rename an account via the row kebab menu: renaming to the
  same label still saves and bumps `updated_at`.
  * Expected: even a no-op label edit calls `Vault::rename` inside
    `mutate_and_save`; the on-disk `updated_at` bumps.
- [ ] Rename an account via the row kebab menu: pre-commit fault
  injection rolls the label back.
  * Expected: with `save_not_committed` armed, the dialog stays
    open with an inline error and the in-memory label reverts to
    the prior value.
- [ ] Settings persist across restart.
  * Expected: changes to auto-lock interval, clipboard-clear
    interval, and any preferences toggles persist after closing
    the app and re-opening the vault. The spinner clamps to
    `paladin_core::AUTO_LOCK_SECS_MIN..=AUTO_LOCK_SECS_MAX` and
    `CLIPBOARD_CLEAR_SECS_MIN..=CLIPBOARD_CLEAR_SECS_MAX`.

## 8. Passphrase management

- [ ] Passphrase `set` / `change` / `remove` flows complete
  end-to-end.
  * Expected: `set` is reachable only when `Vault::is_encrypted()`
    returns `false`; `change` and `remove` only when `true`.
    Each flow's twice-confirm match accepts; mismatch rejects
    inline. `remove` renders
    `format_plaintext_storage_warning()` verbatim and requires
    explicit confirmation before mutation.
  * Tied to: `tests/passphrase_dialog_logic.rs`.

## 9. Memory hygiene

- [ ] Secret fields clear on cancel, submit, and auto-lock.
  * Expected: passphrase entries, the hidden Base32 manual-secret
    buffer, and the `otpauth://` URI text are zeroized on each of
    cancel, submit, dialog close, and auto-lock. No secret state
    survives a lock event.
  * Tied to: `tests/secret_fields_logic.rs`.

## 10. Theming and icons

- [ ] Icon theme resolution + fallback work against the system
  theme.
  * Expected: rows render the resolved icon when the system icon
    theme provides one; missing or empty slugs route to the
    placeholder; `gtk::IconTheme` lookup failures also fall back
    to the placeholder without panicking. Verify against the
    GNOME default theme (Adwaita) and at least one third-party
    theme (e.g. `Papirus`) under both Wayland and X11.
  * Tied to: `tests/icon_resolution.rs`.

## 11. Next-code column (DESIGN §7)

- [ ] Click the Next cell on a TOTP row → clipboard holds the
  upcoming code and a toast reads
  `Next code copied, valid in Xs`.
  * Expected: the Next column's button on a TOTP row commits the
    upcoming code (computed via `Vault::totp_next_code`) to the
    system clipboard, the row briefly indicates success, and the
    in-window toast renders the
    `Next code copied, valid in Xs` text with `Xs` matching the
    seconds remaining in the current step. HOTP rows leave the
    Next cell `sensitive=false`; clicking it must no-op.
  * Tied to: `tests/account_list_logic.rs` Next-column routing,
    `paladin_core::Vault::totp_next_code`, `docs/DESIGN.md` §7.
- [ ] Press `Ctrl+Shift+C` with a TOTP row selected → same
  behavior as clicking the Next cell.
  * Expected: with a TOTP row selected in the account list,
    pressing `Ctrl+Shift+C` dispatches the `app.copy-next-code`
    action, copies the upcoming code to the clipboard, and
    renders the same `Next code copied, valid in Xs` toast as
    the Next-cell click path. The accelerator no-ops on HOTP
    rows (the Next cell already carries the rejection signal)
    and stays quiet while a modal dialog traps focus.
  * Tied to: `tests/account_list_logic.rs` accelerator routing,
    `format_app_copy_next_code_accelerator`.
- [ ] Toggle Preferences → Display → Show next code → the column
  hides / shows; the visible cells re-flow without flicker.
  * Expected: opening Preferences and toggling the **Show next
    code** row in the **Display** group flips the
    `show-next-code-column` GSettings key (default `true`); the
    `ColumnView`'s Next column hides on toggle-off and reveals
    on toggle-on, the remaining columns re-flow without flicker
    or row-height jump, and the preference persists across an
    app restart. The toggle is encrypted-mode-independent —
    plaintext vaults see the same behavior.
  * Tied to: `tests/gsettings_logic.rs`
    `show-next-code-column` coverage,
    `tests/account_list_logic.rs` column-visibility routing.

## 12. Per-account QR export (`ExportQrDialog`, DESIGN §4.6)

- [ ] Open the kebab menu on a TOTP row → `Show QR…` is the
  second entry between `Rename…` and `Remove…`; the dialog opens
  on the warning page with the ack switch off and the QR not
  visible.
  * Expected: the kebab menu lists three rows in the pinned order
    `Rename…` / `Show QR…` / `Remove…`. Selecting `Show QR…`
    presents an `adw::Dialog` titled `Show QR code`; the body
    starts on the `warning` page of the inner `AdwViewStack`
    carrying the verbatim
    `paladin_core::format_plaintext_qr_export_warning()` body,
    the `I understand — show the QR` ack switch is off, the
    `Cancel` button is sensitive, the `Show QR` button is
    desensitized, and no `gtk::Picture` is visible. Closing via
    the window-manager close button (or Escape) leaves the
    vault untouched.
  * Tied to: `tests/account_list_logic.rs`
    `build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`;
    `tests/export_qr_dialog_logic.rs`
    `compose_show_qr_button_sensitive_false_until_ack_revealed`,
    `format_export_qr_dialog_warning_body_matches_paladin_core_verbatim`.
- [ ] Toggle the ack switch on → the `Show QR` button becomes
  sensitive; press it → the dialog advances to Page 2 showing
  the rendered QR and the `<issuer>:<label>` caption. Scanning
  the QR with a second authenticator imports the same account.
  * Expected: flipping the ack `AdwSwitchRow` on enables the
    `Show QR` button; pressing it switches the view stack to
    the `qr` page, fills the `gtk::Picture` with a
    `gdk::Texture` rendered from `Vault::export_qr_png(id,
    &QrRenderOptions::default())`, displays the
    `<issuer>:<label>` caption in the `title-3` style class, and
    surfaces the four-button footer
    (`Save as PNG…` / `Save as SVG…` / `Copy image` / `Done`)
    with `Copy image` sensitive. A second authenticator scanning
    the rendered QR imports the same account (same secret,
    algorithm, digits). Toggling the ack back off drops the
    Picture paintable, wipes the staged bytes, and resets the
    view to the warning page.
  * Tied to: `tests/export_qr_dialog_logic.rs`
    `apply_msg_show_qr_button_press_calls_export_qr_png_with_default_options`,
    `apply_msg_show_qr_switches_visible_child_to_qr`,
    `apply_msg_ack_toggled_off_clears_staged_png_and_paintable_and_resets_visible_child`.
- [ ] Press `Save as PNG…` and `Save as SVG…` → both write
  `0600`-mode files at the chosen path; the inline status reads
  `QR saved to <path>` after each save. Reopening the PNG in an
  image viewer shows the QR; opening the SVG in a text editor
  shows an `<svg>…</svg>` document.
  * Expected: each Save button opens a `gtk::FileDialog::save`
    pre-populated with `qr.png` / `qr.svg`. On commit the file
    lands at the chosen path with mode `0600`, owned by the
    invoking user. The inline `QR saved to <path>` label appears
    on Page 2 and an `adw::Toast` echoes the same wording. A
    second save against an existing destination reveals the
    inline `Overwrite the existing file` switch; toggling it on
    fires the save without an extra confirm step. The HOTP
    counter, if applicable, is unchanged on disk (pinned by
    `export_qr_dialog_does_not_advance_hotp_counter`).
  * Tied to: `tests/export_qr_dialog_logic.rs`
    `run_export_qr_save_worker_plaintext_png_succeeds_and_writes_0600_file`,
    `run_export_qr_save_worker_plaintext_svg_succeeds_and_writes_0600_file`,
    `run_export_qr_save_worker_svg_reuses_staged_svg_on_second_save`,
    `compose_save_target_overwrite_gate_visible_visible_when_destination_exists`.
- [ ] Press `Copy image` → paste into an image editor → the QR
  shows up as a PNG image; the in-window toast reads
  `Image copied`. The clipboard is **not** auto-cleared (image
  copies are not OTP codes — `clipboard.clear_enabled` does not
  apply).
  * Expected: pressing `Copy image` builds a
    `gdk::ContentProvider::for_bytes("image/png", ...)` from the
    staged PNG bytes and calls
    `gdk::Clipboard::set_content(...)`. Pasting into an image
    editor (GIMP, Krita) or an image-paste-accepting chat
    (Slack, Signal) yields the QR PNG. The `Image copied` toast
    appears; the clipboard retains the image indefinitely and
    no `PendingClipboardClear` is armed (verify by waiting
    longer than the configured clipboard-clear timeout — the
    paste still works). Repeating the press works without a
    re-show.
  * Tied to: `tests/export_qr_dialog_logic.rs`
    `apply_msg_copy_image_routes_through_set_content_with_image_png_mime`,
    `apply_msg_copy_image_failure_does_not_arm_clipboard_clear`,
    `format_export_qr_dialog_copy_image_success_toast_renders_image_copied`.
- [ ] With the QR visible, wait for auto-lock to fire → the
  dialog disappears, the staged PNG / SVG buffers are dropped,
  and the post-lock unlock leaves no QR carry-over.
  * Expected: enable auto-lock (Preferences → Security → Auto-lock
    after) with a short timeout (e.g. 30 s), press `Show QR`,
    then leave the window idle. When auto-lock fires the QR
    dialog closes with the rest of the unlocked UI, the staged
    PNG / SVG `Zeroizing<...>` buffers are dropped (the Picture
    paintable disappears along with the widget tree), and the
    auto-lock landing page (unlock dialog for encrypted vaults
    / list view for plaintext) shows no QR remnants. Re-opening
    the QR dialog after unlock starts on the warning page with
    the ack off — never on Page 2 with a still-visible QR.
  * Tied to: `tests/export_qr_dialog_logic.rs`
    `clear_for_lock_drops_staged_buffers_and_paintable`,
    `clear_for_lock_preserves_account_id_and_summary`;
    `crates/paladin-gtk/src/app/model.rs` `lock_on_auto_lock_expiry`
    routing through `clear_for_lock` before the controller drop.

## Reporting

If a step fails, file a bug with:

* Session type (`echo $XDG_SESSION_TYPE $WAYLAND_DISPLAY`).
* Distro + version, GTK4 and `libadwaita` versions
  (`pkg-config --modversion gtk4 libadwaita-1`).
* `paladin-gtk --version` and the workspace commit hash.
* Steps to reproduce, expected vs. observed, screenshots if
  user-visible.

Do not paste secrets, vault contents, or screenshots that contain
codes into the bug report.
