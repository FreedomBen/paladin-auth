# Implementation Plan 04 — `paladin-gtk`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4.1–§4.7, §5–§14.
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

> **Status: deferred to v0.2.** Per §13, the GUI is deferred to v0.2; the
> TUI ships in v0.1. This plan describes the v0.2 work and is included in the
> initial planning batch so the workspace shape and API contract on
> `paladin-core` accommodate it.

## Scope

Standalone GTK4 binary `paladin-gtk` built with **Relm4** on **GTK4** per
§7, using `libadwaita` widgets per §9.
Exposes the same operations as the TUI: search/list of accounts, copy code,
HOTP `next` with reveal window, add account (manual, `otpauth://` URI
paste, or scan-from-clipboard image), remove account, import/export,
settings (auto-lock + clipboard-clear), passphrase set/change/remove.

Per DESIGN §3: depends only on `paladin-core`. Never reaches into
`paladin-cli` or `paladin-tui`.

## Crate layout

```
crates/paladin-gtk/
├── Cargo.toml             # license = "AGPL-3.0-or-later"; declares both [lib] and [[bin]] (name = "paladin-gtk") so tests/ can compile against internal modules
├── build.rs               # gresource bundle (icons, *.ui, *.css)
├── data/
│   ├── paladin-gtk.gresource.xml
│   ├── ui/                # *.ui templates
│   ├── icons/             # app icon + fallbacks
│   ├── metainfo/          # AppStream metadata; file is named `<app-id>.metainfo.xml` (`org.tamx.Paladin.Gui.metainfo.xml`) so Flathub's reproducible-build check matches; installs to `/usr/share/metainfo/<app-id>.metainfo.xml`
│   ├── style.css
│   └── org.tamx.Paladin.Gui.desktop  # named after the §11.4 app ID so the same file installs verbatim in native and Flatpak builds
├── src/
│   ├── lib.rs             # re-exports internal modules so integration tests in tests/ can reach them; binary entry stays in main.rs
│   ├── main.rs            # adw::init, register resources, RelmApp::new("org.tamx.Paladin.Gui").run(...) — ID matches the §11.4 Flatpak app ID and the desktop file's StartupWMClass
│   ├── cli.rs             # GlobalArgs (--vault, --no-color); reject --json
│   ├── app/
│   │   ├── mod.rs         # AppModel + AppMsg + AppOutput
│   │   └── state.rs       # AppState variants: Missing / Locked / Unlocked / UnlockedBusy / StartupError
│   ├── components/
│   │   ├── init.rs        # InitDialog — vault creation (incl. create_force clobber confirmation)
│   │   ├── unlock.rs      # UnlockComponent — encrypted vaults only
│   │   ├── startup_error.rs # non-mutating startup/open error view
│   │   ├── account_list.rs    # AccountListComponent (gtk::ListView + factory)
│   │   ├── account_row.rs     # AccountRowComponent (label, code, gauge/next, copy, kebab → rename / remove)
│   │   ├── add_account.rs     # AddAccountComponent (manual fields + otpauth:// URI paste + paste image)
│   │   ├── remove.rs          # RemoveDialog (confirmation gate)
│   │   ├── rename.rs          # RenameDialog (label edit; calls Vault::rename)
│   │   ├── import.rs          # ImportDialog (file picker + format + on-conflict + bundle passphrase)
│   │   ├── export.rs          # ExportDialog (file picker + format + overwrite + encrypted passphrase)
│   │   ├── passphrase.rs      # PassphraseDialog (set / change / remove flows)
│   │   └── settings.rs        # SettingsComponent (toggles + spinners)
│   ├── clipboard.rs       # gdk::Clipboard plumbing driving paladin_core::policy::clipboard_clear::ClipboardClearPolicy
│   ├── auto_lock.rs       # GLib idle/timeout plumbing driving paladin_core::policy::auto_lock::IdlePolicy (encrypted-only; plaintext no-op)
│   ├── hotp_reveal.rs     # per-row reveal window via paladin_core::policy::hotp_reveal::deadline (uses paladin_core::HOTP_REVEAL_SECS)
│   ├── icons.rs           # gtk::IconTheme lookup against AccountSummary.icon_hint
│   ├── secret_fields.rs   # extract/clear passphrase + manual-secret entries
│   ├── search.rs          # case-insensitive issuer/label filtering using paladin_core::account_matches_search (parity with CLI / TUI)
│   └── ticker.rs          # paladin_core::TICK_INTERVAL_MS timeout source for TOTP gauge updates and clipboard staleness checks
└── tests/
    ├── icon_resolution.rs
    ├── search_logic.rs
    ├── auto_lock_logic.rs        # pure logic; no display required
    ├── clipboard_clear_logic.rs  # pure logic; no display required
    ├── hotp_reveal_logic.rs
    ├── secret_fields_logic.rs
    ├── startup_error_logic.rs
    ├── qr_clipboard_logic.rs
    ├── init_dialog_logic.rs
    ├── rename_dialog_logic.rs
    ├── otpauth_uri_paste_logic.rs
    ├── import_dialog_logic.rs
    ├── export_dialog_logic.rs
    ├── passphrase_dialog_logic.rs
    ├── settings_logic.rs
    ├── effect_ownership_logic.rs
    ├── gtk_smoke.rs              # xvfb-run integration smoke test
    └── manual/MANUAL_TEST_PLAN.md
```

Every new Rust source file carries the standard SPDX header
`// SPDX-License-Identifier: AGPL-3.0-or-later`. Vendored desktop assets
(icons, `.desktop`, CSS) require license-compat vetting per §14 before
inclusion.

## Component tree (per §7)

- `AppModel` — owns the resolved vault path plus the `Missing`, `Locked`,
  `Unlocked`, `UnlockedBusy`, or `StartupError` state. Startup runs
  `paladin_core::inspect(path)` and
  routes the result: `VaultStatus::Plaintext` opens directly to
  `AccountListComponent`, `Encrypted` presents `UnlockComponent`, and
  `Missing` presents `InitDialog`. `default_vault_path`, `inspect`, or
  startup `open` failures that are not wrong-passphrase retries route to
  `StartupErrorComponent`, which never creates, overwrites, or repairs vault
  files; `unsafe_permissions` renders the `Some(text)` from
  `paladin_core::format_unsafe_permissions(&err)`, falling back to the
  generic error text only if the formatter unexpectedly returns `None`.
- `InitDialog` — only path that creates a vault from the GUI (v0.2;
  parity with DESIGN §6, §7). Two `AdwPasswordEntryRow` passphrase
  fields (twice-confirmed; both fields empty select plaintext) plus an
  explicit "create vault" confirmation button. Initial routing of the
  user-supplied path runs through `paladin_core::classify_init_precheck`
  (matching the CLI init flow and the core §5 truth table); the dialog
  renders the
  `InitPrecheck::Clear` case as the normal create path,
  `InitPrecheck::Existing` as the destructive-confirmation gate
  (see below), and `InitPrecheck::Propagate` as a non-mutating inline
  error. The plaintext path renders
  `paladin_core::format_plaintext_storage_warning()` verbatim — the
  same wording `PassphraseDialog`'s remove flow and the CLI / TUI use —
  and the user must tick the confirmation before submission is enabled.
  Encrypted submission requires two non-empty matching entries; one-empty
  or mismatched pairs reject inline with `invalid_passphrase`
  (`reason: "confirmation_mismatch"`). On submit, builds a
  `VaultInit` (`VaultInit::Plaintext` or
  `VaultInit::Encrypted(EncryptionOptions::new(secret)?)`) and calls
  `paladin_core::create(path, init)` on `gio::spawn_blocking` (the
  encrypted path validates the passphrase and runs the §4.4 Argon2id KDF).
  On success, swaps
  `AppModel` to `Unlocked` with the returned
  `(Vault, Store)` and routes to `AccountListComponent`. The dialog
  stays open and surfaces `unsafe_permissions` (rendered as the
  `Some(text)` from `paladin_core::format_unsafe_permissions(&err)`,
  falling back to the generic error text if it returns `None`),
  `save_not_committed`, and `save_durability_unconfirmed` inline.
  `vault_exists` (if a vault appeared between `inspect` and `create`,
  i.e. the precheck reported `Clear` but the race resolved to
  `Existing`) opens an in-dialog `AdwAlertDialog` with `destructive-action`
  styling whose body is rendered from
  `paladin_core::format_init_force_warning(existing_path)` so wording
  stays identical to the CLI `init --force` confirmation. On
  confirm, the dialog re-runs the operation with
  `paladin_core::create_force(path, init)` on `gio::spawn_blocking`,
  consuming the pending `VaultInit` created from the already-entered
  passphrase choice; on cancel, the
  destructive dialog closes and `InitDialog` returns to its
  `vault_exists` state without mutating the existing vault.
  `create_force` returns the same typed error kinds as `create`,
  with the additional create_force-only `backup_path` field on
  `save_not_committed` when the failure occurs after the existing
  vault has already been rotated to `vault.bin.bak`;
  `save_durability_unconfirmed` is reported after the primary
  rename. Both stay inline. Passphrase entries are zeroized on
  submit, cancel, destructive-confirmation cancel, and dialog close
  per §"Secret entry handling".
- `UnlockComponent` — passphrase entry, **shown only when the vault is
  encrypted**. Skipped entirely for plaintext vaults.
- `AccountListComponent` — `gtk::ListView` with a custom row factory bound
  to a `gio::ListStore` of `AccountRowModel` built from
  `paladin_core::AccountSummary` projections. Search uses a
  `gtk::SearchEntry` hosted inside a `gtk::SearchBar` whose
  `search-mode-enabled` is bound to the header bar's search-toggle button
  (see "libadwaita usage" below). Filtering rebuilds the list from
  `Vault::iter()` so it can call
  `paladin_core::account_matches_search(&Account, query)` before projecting
  matches to `AccountSummary`; the `gio::ListStore` never stores secret
  fields. The entry applies the same case-insensitive substring matching as
  §5 / §6; no Unicode normalization. Empty issuer is allowed and the colon
  is still present in the match key; insertion order is preserved among
  matches. After a filter rebuild, selection is computed by
  `paladin_core::select_after_filter(prev, filtered)` (preserve prior
  selection if still present, else first match) — parity with the TUI.
  The CLI's `id:` prefix form is **not** honored by the GUI search
  (parity with the TUI).
- `AccountRowComponent` — label, code, progress (TOTP) / "next" button
  (HOTP), copy button, and a kebab `gtk::MenuButton` whose `gio::Menu`
  exposes "Rename…" (opens `RenameDialog` for that row's account) and
  "Remove…" (opens `RemoveDialog`). HOTP rows hide their code until the user activates
  "next" (advances counter and saves); the reveal window deadline comes
  from `paladin_core::policy::hotp_reveal::deadline(now)` (built on the
  shared `paladin_core::HOTP_REVEAL_SECS`), and after expiry the code
  returns to the hidden state, matching the TUI. Activating "next"
  during an open reveal advances to the next counter and restarts the
  shared reveal window with the newly committed code (matches §6 —
  "next" is the "give me the next code" affordance, never a no-op). Hidden
  rows show the stored next counter; during reveal, the row shows the
  `Code.counter_used` that produced the visible code until expiry. Copying a
  hidden HOTP row is **disabled**; copying during the reveal window copies
  the visible code and does not advance again.
- `AddAccountComponent` — three input paths in a single dialog:
  manual fields, paste of an `otpauth://` URI, and "scan from clipboard
  image" (an `AdwViewStack` controlled by an `AdwViewSwitcher` selects the
  active path; operation parity with `add` interactive / `--uri` / QR add).
  Switching paths clears the hidden secret-bearing fields for the paths
  being left: the manual Base32 secret, the URI text, and any pending
  duplicate/add-anyway state.
  The URI path uses an `AdwEntryRow` for the URI string; on submit
  the entry is passed to `paladin_core::parse_otpauth` on the main
  thread (no I/O, cheap), the resulting `ValidatedAccount` shares the
  manual path's duplicate detection, "add anyway" override, and
  `Vault::mutate_and_save` insertion, and `validation_error` parser failures
  stay inline in the dialog without mutating the vault. The URI text is
  secret-bearing because it embeds the Base32 secret, so it is never carried
  in `AppMsg` /
  `AppOutput`; inline errors may name the failing field or reason but never
  echo the URI text. The entry buffer is zeroized on submit / cancel /
  dialog close. The "scan from clipboard image" path reads
  a `gdk::Texture` from the GDK clipboard, allocates an exact
  `width * height * 4` straight (non-premultiplied) RGBA8 buffer with
  overflow-checked multiplication, rejects sizes above
  `paladin_core::QR_RGBA_MAX_BYTES` before allocation / download, and downloads
  via a `gdk::TextureDownloader` set to `gdk::MemoryFormat::R8g8b8a8` with
  row stride `width * 4`. The default `Texture::download` path is avoided
  because it yields premultiplied pixels the QR decoder cannot consume.
  Width, height, bytes, and `import_time` are then passed to
  `paladin_core::import::qr_image_bytes`. Manual fields cover label,
  optional issuer, Base32 secret, algorithm, digits, kind, TOTP period,
  HOTP counter, and the icon-hint mode (`Default from issuer`, `No icon`,
  or explicit slug), matching `paladin_core::AccountInput` and
  `IconHintInput`; the icon-hint entry text is normalized through
  `paladin_core::parse_icon_hint_token` so the slug / `default` / `none`
  parsing matches the CLI/TUI add modals exactly. UI defaults match the CLI manual-add defaults in DESIGN
  §5: TOTP, SHA1, 6 digits, 30 s period, HOTP counter 0, and icon hint
  derived from issuer when the user leaves it unset. Manual entries use
  `paladin_core::validate_manual`; validation warnings show inline with
  `paladin_core::format_validation_warning()` and do
  not block creation, while field-level parse errors (invalid Base32,
  empty label, out-of-range digits / period / counter), plus any
  core-returned `validation_error`, block submission and stay inline
  without mutating the vault — same rule as the import dialog. Manual and URI
  duplicate collisions call
  `Vault::find_duplicate(&validated)` before mutation, initially reject with
  the existing account in the dialog, and offer an "add anyway" confirmation
  that consumes the pending `ValidatedAccount` on the duplicate-allowed path
  (CLI parity with `--allow-duplicate`, appending a new account that shares the
  `(secret, issuer, label)` triple). Clipboard QR imports always go through
  `paladin_core::import::qr_image_bytes` (which returns
  `Vec<ValidatedAccount>` regardless of QR count) with a fixed
  `ImportConflict::Skip` and report imported/skipped/warning counts (parity
  with §6); a single-QR clipboard image is the degenerate one-element case
  of that same path. Successful manual, URI, and QR additions run the
  insertions inside
  `Vault::mutate_and_save`.
- `RemoveDialog` — confirmation gate before calling `Vault::remove` inside
  `Vault::mutate_and_save`. Save errors surface inline.
- `RenameDialog` — single `AdwEntryRow` pre-populated with the
  account's current label, plus Save / Cancel buttons. Calls
  `Vault::rename(id, new_label, now)` inside `Vault::mutate_and_save`
  with the trimmed input regardless of whether the new label equals
  the current one — `Vault::rename` always bumps `updated_at`, so the
  GUI matches the CLI rename behavior rather than silently short-circuiting
  on a no-op rename. Same label validation as Add (non-empty,
  §4.1 length limits). Issuer is **not** editable here — parity with
  the CLI's `rename` taking only `<new-label>`; deeper edits use
  Remove + Add.
  Pre-commit save failures (`save_not_committed`) restore the prior
  label in memory and keep the dialog open with the inline error;
  durability-unconfirmed failures
  (`save_durability_unconfirmed`) leave the new label in memory and
  surface the warning. `RenameDialog` does not handle secret material,
  so no zeroize obligation beyond the standard widget-buffer reset on
  cancel / submit / close.
- `ImportDialog` — `gtk::FileDialog` (the GTK 4.10+ replacement for the
  deprecated `gtk::FileChooserNative`) for the source file, a format
  selector (auto-detect or explicit `otpauth` / `aegis` / `paladin` /
  `qr`), and an on-conflict selector (`skip` / `replace` / `append`).
  Before any Paladin-bundle passphrase prompt, the GUI calls
  `paladin_core::classify_paladin_import_precheck(path, forced_format)` so
  it shares the CLI / TUI prompt decision table. `PromptForPassphrase`
  prompts for the bundle passphrase inside the dialog; `Reject(err)`
  surfaces that exact core error inline without prompting (for example
  `unsupported_plaintext_vault`, `invalid_header`, or
  `unsupported_format_version`); and `NoPrompt` consumes no passphrase and
  continues through `paladin_core::import::from_file` so the import facade
  owns `io_error`, `unsupported_import_format`, and format-specific
  validation errors. If the source path or forced
  format changes after a bundle passphrase has been entered, the passphrase
  row is cleared and the probe / prompt flow starts over. The selected
  `paladin_core::import::from_file` call, the
  `Vault::import_accounts(accounts, conflict, import_time)` merge, and
  the surrounding `Vault::mutate_and_save` run as one serialized
  `gio::spawn_blocking` vault effect (the encrypted-Paladin variant runs
  Argon2id). The merge uses the user's policy and the same `import_time`
  used by `ImportOptions`;
  imported/skipped/replaced/appended/warning counts surface inline.
  Pre-commit save failures (`save_not_committed`) restore core's
  pre-attempt snapshot; durability-unconfirmed saves leave the merged
  accounts in memory and surface the warning inline.
  Importer errors (`unsupported_import_format`,
  `unsupported_plaintext_vault`, `unsupported_encrypted_aegis`,
  `unsupported_aegis_entry_type`, `validation_error`,
  `no_entries_to_import`, `decrypt_failed`, `invalid_header`,
  `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`) stay in the dialog as inline
  errors and never mutate vault state.
- `ExportDialog` — format selector (plaintext `otpauth://` JSON list or
  encrypted Paladin bundle) and `gtk::FileDialog` for the
  destination path. Overwriting an existing file is rejected unless
  the user confirms an inline overwrite gate (parity with CLI
  `--force`). Any overwrite gate is resolved before encrypted-bundle
  passphrase rows are accepted; if the destination or format changes
  after overwrite or plaintext-warning confirmation, those confirmations are
  reset; if either changes after passphrase entry, password rows are cleared
  and the user is re-prompted. Encrypted exports prompt twice for the
  bundle passphrase and reject mismatch (`invalid_passphrase`
  `reason: "confirmation_mismatch"`) or empty entry
  (`reason: "zero_length"`) inline; both the encrypted-bundle and
  plaintext writes run on `gio::spawn_blocking` (encrypted-bundle to
  keep the fresh-AEAD-key derivation off the main loop; plaintext for
  symmetry, since `write_secret_file_atomic` chains multiple `fsync`s).
  Plaintext exports render
  `paladin_core::format_plaintext_export_warning()` verbatim and the
  user must confirm before the write proceeds. Writes go through
  `paladin_core::write_secret_file_atomic`.
  On success the dialog closes and surfaces the written path in the main
  status/toast surface;
  `io_error`, `save_not_committed`, `save_durability_unconfirmed`,
  `invalid_passphrase`, and the refused overwrite gate stay in the
  dialog. Export does not mutate
  the vault, so there is no rollback path.
- `PassphraseDialog` — three sub-flows mirroring CLI/TUI: `set` / `change` /
  `remove`. New passphrases prompted twice; mismatch returns to the dialog
  with an inline error. `set` and `change` also reject zero-length new
  passphrases inline with `invalid_passphrase`
  (`reason: "zero_length"`). `remove` renders
  `paladin_core::format_plaintext_storage_warning()` verbatim and
  requires explicit confirmation before mutation. The available
  sub-flow is gated by `Vault::is_encrypted()`: `set` is enabled only
  when the getter returns `false`; `change` and `remove` only when it
  returns `true`. Switching sub-flows clears all passphrase rows and any
  pending plaintext-removal confirmation. Any stale invalid-state error stays
  in the dialog and does not mutate visible state.
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts. Spinners clamp to
  `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
  and
  `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`
  (the §5 bounds, sourced from `paladin_core::ui_contract`). Uses
  **live-apply** (each toggle change immediately invokes the matching
  setter inside `Vault::mutate_and_save`; spinner changes are debounced
  500 ms via `glib::timeout_add_local` so holding +/- does not fire one
  save per click — the most recent buffered value is the one that saves),
  diverging from the TUI's buffer-then-Confirm modal — `AdwSwitchRow`
  and `AdwSpinRow` are idiomatically immediate, and the §"Effect errors"
  pre-commit rollback reverts the visible widget value on
  `save_not_committed`. Setters validate but do not save themselves; the
  component owns the `mutate_and_save` call and surfaces any save error
  inline.

## Secret entry handling (per §8)

Passphrase fields, manual-secret fields, and the Add dialog's
`otpauth://` URI entry are kept out of `AppModel`, `AppMsg`,
`AppOutput`, and other long-lived component state. The GTK entry
buffer is the unavoidable UI boundary; Paladin-owned copies are created only
at submit time, immediately wrapped in `secrecy::SecretString` for core
calls, and zeroized when dropped. Submit, cancel, dialog close, and auto-lock
clear the relevant GTK entry widgets before the component returns to its idle
state. Switching Add paths also clears hidden manual-secret and URI entry
buffers before the new path becomes active. Two short-lived modal-local
exceptions are required for confirmation round trips:
`AddAccountComponent` keeps a duplicate-collision
`ValidatedAccount` in a zeroizing pending-add slot after clearing the input
buffers, and `InitDialog` keeps the pending `VaultInit` (secret-bearing only
for encrypted creation) in a zeroizing pending-create slot while the
`vault_exists` destructive-confirmation gate is open. The pending value is
consumed on "add anyway" / `create_force` and zeroized on cancel, close,
replacement, or auto-lock. HOTP reveal codes and pending clipboard-clear
values are likewise stored in Paladin-owned zeroizing buffers. GTK/GDK still
receive ordinary UI or clipboard copies at the display boundary; the
Paladin-owned buffers are cleared when expired, replaced, or dropped.
Validation/status messages never include secret values.

## Auto-lock and clipboard auto-clear (per §7)

Behave the same as the TUI, including **opt-in default** and the
**plaintext-vault auto-lock no-op**. GTK owns the idle-event sourcing
(`gtk::EventControllerKey`, motion controllers) and timer plumbing
(`glib::timeout_add_local` integrated with the GTK main loop); the
policy decisions route through `paladin-core`.

- Auto-lock: idle events sourced through `gtk::EventControllerKey` /
  pointer controllers wired at the `AppModel` root drive
  `paladin_core::policy::auto_lock::IdlePolicy`
  (`should_arm` / `next_deadline` / `is_expired`), which owns the
  encrypted-only gating and timer math. The deadline call passes
  `Vault::is_encrypted()` so plaintext vaults return `None` in core, not
  by GUI-side convention. On expiry, drop `Vault` and
  switch `AppModel` to `Locked`, re-presenting `UnlockComponent`.
  Locking discards open HOTP reveal windows, the search query, and any
  open dialog; a clipboard auto-clear timer scheduled before lock survives
  lock and still fires only-if-unchanged. The arm/disarm decision
  re-evaluates after any successful PassphraseDialog transition by
  re-asking `IdlePolicy::should_arm`, which reads `Vault::is_encrypted()`
  so the timer state tracks the on-disk vault mode without re-inspecting
  the file (plaintext vaults remain unarmed even though the setting still
  persists for the encrypted-later case).
- Clipboard auto-clear: mode-agnostic — runs in both plaintext and
  encrypted vaults. GTK owns the `gdk::Clipboard.read_text` / `set_text`
  calls; the only-if-unchanged decision routes through
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy`
  (`schedule` at copy time, `should_clear` on wake against the current
  clipboard text). Stale tokens are dropped first by the policy; pending
  copied values are zeroized after the clear attempt or stale-token drop.

## Icons (per §7)

`AccountRowComponent` resolves `AccountSummary.icon_hint` against the system icon
theme via `gtk::IconTheme`, falling back to a generic placeholder when the
slug is `None` or unresolved. The CLI and TUI ignore the field entirely.

## Global flags

`--vault <path>` and `--no-color` are accepted (parity with siblings).
`--no-color` is a parser-level no-op in the GUI: there is no ANSI palette
to disable, and theming is delegated to Adwaita / the system theme.
`--json` is rejected at parse time with clap's standard text
diagnostic — `paladin-gtk` has no JSON output mode and never emits a
JSON envelope, mirroring DESIGN §5. The rejection is text-only at
clap's normal usage exit code; there is no argv pre-scan equivalent of
the CLI's strict-mode behavior because the GUI is never expected to be
scripted. No positional file or URI arguments are accepted in v0.2; imports
start from `ImportDialog`.

## Vault interaction

- Resolve vault path from `--vault` or
  `paladin_core::default_vault_path()`, then call
  `paladin_core::inspect(path)` to resolve the mode.
- Plaintext → call `paladin_core::open(path, VaultLock::Plaintext)` directly
  on the GTK main loop (no Argon2; just bincode decode and the §4.3 perm
  check, fast enough that the spawn-blocking thread hop costs more than the
  call itself), then jump to `AccountListComponent`.
- Encrypted → present `UnlockComponent`. On submit, call
  `paladin_core::open(path, VaultLock::Encrypted(secret))` on
  `gio::spawn_blocking` so the §4.4 Argon2 KDF (m=64 MiB defaults) does not
  block the GTK main loop; the dialog shows a spinner until the join
  completes. Wrong passphrase surfaces inline. `unsafe_permissions` and other
  non-authentication open errors
  (`wrong_vault_lock`, `invalid_header`, `invalid_payload`,
  `unsupported_format_version`, `kdf_params_out_of_bounds`, `io_error`)
  transition to `StartupErrorComponent` with a retry action that re-runs
  vault-path resolution and `inspect`; `unsafe_permissions` renders the
  `Some(text)` from `paladin_core::format_unsafe_permissions(&err)` (§4.7),
  falling back to the generic error text if it returns `None`, so the
  wording matches the CLI and TUI exactly.
- Missing → present `InitDialog`. v0.2 GUI creates vaults in-app on
  explicit user confirmation (DESIGN §6, §7). Plaintext path: empty
  passphrase fields plus the unencrypted-storage warning. Encrypted
  path: twice-confirmed passphrase. Both go through
  `paladin_core::create` on `gio::spawn_blocking`. If `create` returns
  `vault_exists` (a vault appeared between `inspect` and `create`), the
  dialog opens an `AdwAlertDialog` destructive-confirmation gate
  worded the same as the CLI `init --force` warning; on confirm it
  re-runs the operation through `paladin_core::create_force` on
  `gio::spawn_blocking` (rotating the existing vault to `vault.bin.bak`
  per §5 staged clobber). Cancelling the destructive gate leaves the
  existing vault intact.
- Operations route through `Vault` and `Store` methods — no GUI-side
  duplication of OTP, validation, or import logic.
- Startup/open errors are non-mutating. `StartupErrorComponent` offers only
  retry and quit; choosing a different vault path is out of scope for v0.2
  because the global `--vault` flag is the only path-selection contract.
- **Argon2id parameters: defaults only.** Encrypted vault creation
  (`InitDialog`), passphrase set/change (`PassphraseDialog`), and
  encrypted-bundle export (`ExportDialog`) all call
  `EncryptionOptions::new(secret)`, which validates non-empty passphrases
  and uses the §4.4 defaults (m=64 MiB, t=3, p=1) — no GUI surface exposes
  `--kdf-memory-mib` / `--kdf-time` / `--kdf-parallelism`. Power
  users wanting custom KDF tuning use the CLI. Vaults the GUI opens
  that were created with custom params still read those params from
  the on-disk header per §4.4, so opening is unaffected.

## In-flight effect ownership

`AppModel` serializes all vault-touching blocking effects. While unlocked, the
model owns exactly one `(Vault, Store)` pair. When an effect needs that pair on
`gio::spawn_blocking` — HOTP `next`, add / remove / rename / import /
settings saves, passphrase transitions, and export flows that read the vault
before writing — the model moves `(Vault, Store)` into the worker and enters an
`UnlockedBusy { effect, ui_snapshot }` state.

While `UnlockedBusy` is active:

- No second vault-touching effect starts. Row `next` buttons, mutating dialog
  submit buttons, passphrase actions, import/export actions, and settings
  controls are disabled and show the active spinner / busy affordance for the
  current surface.
- Non-mutating navigation and already-rendered list display may remain
  responsive using `ui_snapshot`, but anything that would need fresh `Vault`
  access waits for the worker result. Quit / window-close requests are deferred
  until the worker returns, so Paladin does not intentionally abandon a
  save-bearing operation mid-flight.
- Settings live-apply never runs parallel saves. Spinner debouncing keeps only
  the latest value seen before a save starts; toggle changes that would overlap
  an active vault effect are not accepted until the control is re-enabled, at
  which point the visible value still reflects the last committed or rolled-back
  state.
- Dialog close/cancel is disabled for the surface that owns the in-flight
  mutation until the worker returns, so modal-local pending state cannot be
  dropped while core still owns the vault operation.
- If an auto-lock timer fires while `UnlockedBusy` is active, `AppModel` records
  a lock-after-effect request instead of trying to drop the vault out from under
  the worker. When the worker returns, the app applies the typed outcome, then
  locks only if the returned vault is still encrypted; if the operation changed
  the vault to plaintext, the plaintext auto-lock no-op rule discards the
  pending lock request. Pending clipboard-clear timers keep their existing
  only-if-unchanged behavior.

Every worker returns `(Vault, Store, EffectOutcome)` on both success and typed
failure. `AppModel` reinstalls the returned `(Vault, Store)` before applying
the UI outcome, so core's rollback / durability-unconfirmed semantics remain
authoritative. A worker that fails before it can return the pair is a fatal
startup-style error: the app drops back to `StartupErrorComponent` without
attempting to reconstruct in-memory vault state.

## Effect errors

Effects keep visible state consistent with the committed outcome. Most
mutations update visible state only after success; controls that move
optimistically because GTK/Adwaita owns the interaction, such as settings
switches and spin rows, are reverted on pre-commit failure:

- HOTP `next`: the worker first calls `hotp_peek` and keeps the would-be
  visible `Code` in a zeroizing pending slot, then calls
  `Vault::hotp_advance` to advance and save. The staged code is published
  to the reveal slot only if the advance succeeds or returns
  `save_durability_unconfirmed`, so the error type does not need to carry
  a `Code`. Pre-commit save failures (`save_not_committed`) leave the
  in-memory counter and reveal state unchanged (per DESIGN §4.2 rollback),
  zeroize the staged code, and surface an inline/status error.
  Durability-unconfirmed failures (`save_durability_unconfirmed`) reveal
  the new code with its `Code.counter_used` label and post an `AdwToast`
  carrying the committed-but-uncertain status — the user has the new code
  in hand even though durability is in question, and the toast is the
  surface that conveys the warning so the row stays usable. All other
  failures show an inline/status error, leave the previous reveal state
  unchanged (hidden if no reveal was open), and zeroize the staged code.
- Copy: if the GDK clipboard write fails, show an inline/status error and do
  not schedule clipboard auto-clear.
- Add / remove / rename / settings saves: validation and setter failures happen
  inside or before `Vault::mutate_and_save`; core restores its
  pre-attempt snapshot on closure errors and no save is attempted.
  Pre-commit save failures (`save_not_committed`) are rolled back by
  `Vault::mutate_and_save` so memory matches disk (Add removes the
  just-inserted account(s); Remove restores the removed account at its
  previous position; Rename restores the prior label; Settings restores
  the prior values), and the dialog stays open with the inline error
  so the user can retry. Durability-unconfirmed save errors leave the
  new state in memory (matching the committed on-disk state) and surface
  inline as a committed-but-uncertain warning the user explicitly
  dismisses: dialog-bearing operations (Add / Remove / Rename) keep the
  dialog open with the warning attached to the dialog body, and Settings
  (live-apply, no dialog) attaches the warning to the changed
  `AdwPreferencesGroup` row inside the `AdwPreferencesDialog`. The
  dialog does not auto-close on durability-unconfirmed; only HOTP `next`
  (above) uses an `AdwToast` instead, because the row stays usable and
  the user already has the new code in hand.
- Passphrase set/change/remove: pre-commit and durability-unconfirmed
  handling lives in `Vault` itself per DESIGN §4.5 — the in-memory mode/key
  reverts on `save_not_committed` and is replaced on
  `save_durability_unconfirmed`. The dialog stays open and surfaces both
  failure classes inline; on success, the visible vault mode updates before
  the dialog closes.
- QR clipboard import errors — no image, image decode failure, zero decoded
  QRs, and invalid QR payloads — stay in the Add dialog with an inline error.
- otpauth URI paste errors — empty input, malformed URI, unsupported
  scheme or `type=`, and `validation_error` — stay in the Add dialog
  with an inline error and never mutate vault state.
- Import / export: importer and exporter errors (the typed kinds listed
  in the component descriptions) stay in the active dialog as inline
  errors and never close it. Import save errors follow the
  Add/Remove/Settings rule: pre-commit (`save_not_committed`) restores the
  `Vault::mutate_and_save` snapshot; durability-unconfirmed leaves the
  merged accounts and surfaces the warning. Export writer errors
  (`io_error`, `save_not_committed`, `save_durability_unconfirmed`) stay
  inline; export does not mutate vault state, so save-error rollback does
  not apply.

## Linux desktop integration

- `data/org.tamx.Paladin.Gui.desktop` shipped at
  `/usr/share/applications/org.tamx.Paladin.Gui.desktop` per §11.3.
  Sets `Name=Paladin`, `Icon=org.tamx.Paladin.Gui` (the icon-theme
  name resolves to the app-ID-named files installed below),
  `StartupWMClass=org.tamx.Paladin.Gui`,
  `Categories=Utility;Security;`, and security/authenticator terms in
  `Keywords=`, and uses `Exec=paladin-gtk` with no file/URI placeholders.
  v0.2 does not register a MIME type or URI handler; imports start inside
  `ImportDialog`, matching the global-flag parser contract above. Both
  native (`.deb` / `.rpm`) and Flatpak builds install the desktop entry
  verbatim with this app-ID-based filename so AppStream's
  `<launchable type="desktop-id">org.tamx.Paladin.Gui.desktop</launchable>`
  resolves identically and a single metainfo file works in every
  packaging format.
- App icon at
  `/usr/share/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg`,
  named after the §11.4 app ID so the same files satisfy native and
  Flathub install-layout checks without per-format renaming. Symbolic
  variant at
  `…/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg` if the
  Adwaita-style symbolic palette warrants it; a `16`/`24`/`32`/`48`
  PNG fallback set named `org.tamx.Paladin.Gui.png` is shipped
  under `/usr/share/icons/hicolor/<size>/apps/` for non-SVG icon
  consumers. The packaging dry-run validates this layout in both the
  native and Flatpak builds.
- Adwaita-style CSS in `data/style.css`, scoped via `gtk::CssProvider`.

## Packaging (per §11)

`paladin-gtk` ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.2
(§11.1). Implementation owes the release pipeline:

- **Cargo.toml metadata.** `crates/paladin-gtk/Cargo.toml` inherits
  `description`, `repository`, `homepage`, `license` (set to
  `"AGPL-3.0-or-later"` at the workspace), `edition`, and
  `rust-version` from the workspace's `[workspace.package]` table
  (defined per IMPLEMENTATION_PLAN_01_CORE.md Phase A) via per-field
  Cargo inheritance (`description.workspace = true`,
  `repository.workspace = true`, and so on) so `nfpm` and Flathub
  manifests read one source. It additionally sets the binary-specific
  `keywords` and `categories` fields locally. The
  packaging pipeline sources these values from Cargo metadata when
  building `.deb` / `.rpm` so the per-format configs in
  `packaging/deb/paladin-gtk.yaml` and `packaging/rpm/paladin-gtk.yaml`
  stay minimal.
- **`.deb` / `.rpm` (via `nfpm`).** `packaging/deb/paladin-gtk.yaml`
  and `packaging/rpm/paladin-gtk.yaml` install
  `/usr/bin/paladin-gtk`, the desktop entry at
  `/usr/share/applications/`, the AppStream metainfo file at
  `/usr/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml`
  (same source file the Flatpak manifest exports), and the icon set
  under `/usr/share/icons/hicolor/`. Debian declares `libgtk-4-1
  (>= 4.16)` and `libadwaita-1-0 (>= 1.6)`; Fedora declares the
  matching `gtk4` and `libadwaita` package names.
  Distributions whose stable channel ships older GTK / libadwaita
  cannot install `paladin-gtk` until their baseline rises — this is
  intentional so the GUI uses the current Adwaita widget set
  (`AdwAlertDialog`, `AdwAboutDialog`, `AdwPreferencesDialog`) without
  a deprecated-widget shim. No maintainer
  scripts: packages do not create or alter vaults; vault files live under
  `$XDG_DATA_HOME/paladin/` when created by `paladin init` or by the
  GUI's `InitDialog`. The §11
  packaging pipeline validates the
  installed desktop entry with `desktop-file-validate`, validates the
  installed metainfo file with the AppStream validator (same check the
  Flatpak dry-run runs), and verifies the
  hicolor icon install layout; it does not add package-owned
  post-install hooks.
- **Flatpak.** `packaging/flatpak/paladin-gtk.yml` declares
  `org.gnome.Platform//47` (and the matching SDK) — that runtime
  bundles GTK 4.16 and libadwaita 1.6, matching the
  packaging baseline so the Adwaita widget set
  (`AdwAlertDialog`, `AdwAboutDialog`, `AdwPreferencesDialog`) is
  available identically in native and Flatpak builds. No `--share=network`, and the §11.4 sandbox
  permissions:
  `xdg-data/paladin:create`, `xdg-config/paladin:create`, plus the
  Wayland and X11 fallback clipboard path required for `gdk::Clipboard`
  (`--socket=wayland`, `--socket=fallback-x11`, `--share=ipc`). The
  Flatpak app ID is the §11.4 ID `org.tamx.Paladin.Gui`. The same
  string is passed to
  `RelmApp::new(...)` in `main.rs` and set as `StartupWMClass` in
  `data/org.tamx.Paladin.Gui.desktop`, so window-to-launcher
  mapping works identically in both Flatpak and native installs. The manifest exports
  `data/metainfo/org.tamx.Paladin.Gui.metainfo.xml` to
  `/usr/share/metainfo/` and validates it during the packaging dry-run.
  `flatpak-builder` consumes the
  tagged release tarball with vendored Cargo deps so Flathub builds
  reproducibly without network access at build time.
- **AppImage.** `linuxdeploy` plus
  `linuxdeploy-plugin-gtk` assemble the AppDir so GTK4 modules,
  schemas, and pixbuf loaders ship inside the bundle. The
  `AppRun` is the linuxdeploy default which exports
  `GTK_PATH` / `GDK_PIXBUF_MODULE_FILE` to the bundled paths
  before invoking `paladin-gtk`. Output is
  `paladin-gtk-<version>-x86_64.AppImage`; embedded `zsync` points
  at the GitHub Releases feed for in-place updates (§11.5).
- **Reproducible builds.** Same workspace pipeline as the CLI /
  TUI: vendored deps, `cargo build --locked`,
  `SOURCE_DATE_EPOCH` from the release tag. The `gresource`
  bundle is built deterministically by `glib-compile-resources`
  (input file order is fixed by `paladin-gtk.gresource.xml`).
  `linuxdeploy` runs after `cargo build` and does not re-link.
- **Signing.** `.deb`, `.rpm`, and AppImage are signed with
  `minisign` per §11.6; the public key plus signature ride
  alongside each artifact on GitHub Releases. Flatpak signing is
  inherited from Flathub.
- **CI sign-off.** Milestone 7 ships the
  `xvfb-run` smoke test green plus a packaging dry-run that
  produces `.deb`, `.rpm`, Flatpak, and AppImage artifacts and verifies
  `desktop-file-validate` passes on the installed `.desktop`
  entry.

### libadwaita decision (2026-05-05, baseline raised 2026-05-06)

Resolved: **adopt `libadwaita` for v0.2.** The build-time crate
dependency in §"Dependencies" below pins the libadwaita 1.6 baseline
to match the §11.3 runtime declaration (`libadwaita-1-0 (>= 1.6)`) and
the matching GTK 4.16 floor; the GUI uses Adwaita widgets where the
GNOME HIG calls for them (see §"libadwaita usage" below).

The 1.6 floor is set so the GUI uses the current widget set
(`AdwAlertDialog` and `AdwPreferencesDialog` from libadwaita 1.5;
`AdwAboutDialog` from libadwaita 1.6) without reaching for the
deprecated `AdwMessageDialog` / `AdwAboutWindow` /
`AdwPreferencesWindow` (the last of which is deprecated as of
libadwaita 1.6). Distributions whose stable channel ships older
GTK / libadwaita cannot install `paladin-gtk` until their baseline
rises — accepted as a deliberate trade-off rather than maintain a
deprecated-widget compatibility shim. Keep the build-time and
runtime-declared baselines aligned on any future bump.

## Tests

The GUI itself is hard to test without a display server. Tests are
split into pure-logic unit tests (no display required), an `xvfb-run`
smoke test, and a manual test plan.

The checklists below track coverage at the test-file level. A ticked
box means at least one named `#[test]` in the indicated file asserts
the listed behavior end-to-end. Every box must be ticked before the
Milestone 7 sign-off in §"Definition of done".

### Pure-logic unit tests

These run without a display server. Each lives under
`crates/paladin-gtk/tests/`.

#### `tests/icon_resolution.rs`

- [x] `None` / empty slug routes to the placeholder icon without
  invoking `gtk::IconTheme` (the actual lookup is exercised by the
  smoke test).
- [x] Failed `gtk::IconTheme` lookup falls back to the placeholder
  icon.
- [x] Icon-hint token parsing through
  `paladin_core::parse_icon_hint_token` (slug / `default` / `none`)
  matches the CLI / TUI add-modal behavior.

#### `tests/search_logic.rs`

- [x] Filtering routes through `paladin_core::account_matches_search`
  with the same case-insensitive substring rules as the CLI / TUI
  (empty issuer keeps the colon in the match key, no Unicode
  normalization).
- [x] Post-filter selection routes through
  `paladin_core::select_after_filter` (preserve prior selection if
  still present, else first match).
- [x] CLI's `id:<hex>` prefix form is **not** honored by the GUI
  search (parity with the TUI).

#### `tests/auto_lock_logic.rs`

- [x] Idle-event source feeds
  `paladin_core::policy::auto_lock::IdlePolicy::should_arm` /
  `next_deadline` / `is_expired` outcomes correctly for both
  encrypted and plaintext vaults (plaintext returns `None` from
  core, not via a GUI shortcut).
- [x] Re-arm decision after a successful `PassphraseDialog`
  transition re-asks `IdlePolicy::should_arm` against the new
  `Vault::is_encrypted()` value.
- [x] On expiry, the model drops `Vault`, switches to `Locked`, and
  discards open HOTP reveal windows, the search query, and any open
  dialog.

#### `tests/clipboard_clear_logic.rs`

- [x] Copy capture routes through
  `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`.
- [x] Wake routes through `should_clear` against the current
  `gdk::Clipboard` text (only-if-unchanged).
- [x] Stale tokens are dropped first by the policy.
- [x] Pending copied value is zeroized after a clear attempt or
  stale-token drop.
- [x] A clipboard auto-clear timer scheduled before lock survives
  lock and still fires only-if-unchanged.

#### `tests/hotp_reveal_logic.rs`

- [x] Reveal window timing routes through
  `paladin_core::policy::hotp_reveal::deadline` (uses
  `paladin_core::HOTP_REVEAL_SECS`).
- [x] Visible counter label tracks `Code.counter_used` during reveal;
  the row reverts to the stored next counter when hidden.
- [x] Activating "next" during an open reveal advances the counter
  again and restarts the shared reveal window with the newly
  committed code.
- [x] Staged code is published on success.
- [x] Staged code is published on `save_durability_unconfirmed` and
  surfaces an `AdwToast` warning.
- [x] Staged code is zeroized and prior reveal state is retained on
  `save_not_committed` and other failures.

#### `tests/secret_fields_logic.rs`

- [x] Secret-field clearing / redaction invariants for passphrase,
  manual-secret, and `otpauth://` URI entry buffers (submit, cancel,
  close, auto-lock).
- [x] Add path-switch clears the hidden Base32 manual secret, the
  URI text, and any pending duplicate-add state before the new path
  becomes active.
- [x] Pending `ValidatedAccount` (Add duplicate-collision) and
  pending `VaultInit` (Init `vault_exists` race) are zeroized on
  cancel, close, replacement, and auto-lock.

#### `tests/startup_error_logic.rs`

- [x] `default_vault_path` failure routes to
  `StartupErrorComponent` without mutating disk.
- [x] `inspect` failure routes to `StartupErrorComponent`.
- [x] Open failure other than wrong passphrase
  (`unsafe_permissions`, `wrong_vault_lock`, `invalid_header`,
  `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`) routes to
  `StartupErrorComponent`.
- [x] `unsafe_permissions` rendering uses the `Some(text)` from
  `paladin_core::format_unsafe_permissions(&err)`, falling back to
  the generic error text only when the formatter returns `None`.
- [x] Retry from `StartupErrorComponent` re-runs vault-path
  resolution + `inspect`.

#### `tests/qr_clipboard_logic.rs`

- [x] RGBA byte-length / stride preparation matches `width * 4`
  rows / `width * height * 4` total with overflow-checked
  multiplication.
- [x] Sizes above `paladin_core::QR_RGBA_MAX_BYTES` reject before
  allocation / download.
- [x] Decoded buffer is passed to
  `paladin_core::import::qr_image_bytes` with `ImportConflict::Skip`
  and reports imported / skipped / warning counts (parity with §6).

#### `tests/init_dialog_logic.rs`

- [x] Plaintext vs encrypted routing: both passphrase fields empty
  selects plaintext; non-empty selects encrypted.
- [x] Twice-confirm match accepts encrypted submission.
- [x] One-empty / mismatched encrypted entries reject inline with
  `invalid_passphrase` (`reason: "confirmation_mismatch"`).
- [x] Plaintext-warning gate must be ticked before submission is
  enabled; the rendered text matches
  `paladin_core::format_plaintext_storage_warning()` verbatim.
- [x] `paladin_core::classify_init_precheck` routing:
  `InitPrecheck::Clear` opens the normal create path,
  `InitPrecheck::Existing` opens the destructive-confirmation gate,
  `InitPrecheck::Propagate` shows an inline error.
- [x] `vault_exists` returned by `create` after a `Clear` precheck
  (race) opens the destructive-confirmation gate worded by
  `paladin_core::format_init_force_warning(existing_path)`.
- [x] Confirming the destructive gate routes through
  `paladin_core::create_force` and consumes the pending
  `VaultInit`.
- [x] Cancelling the destructive gate leaves the existing vault
  intact and zeroizes the pending `VaultInit`.
- [x] `unsafe_permissions` from `create` / `create_force` routes
  back to inline errors (does not transition out of the dialog).
- [x] `save_not_committed` and `save_durability_unconfirmed` from
  `create` / `create_force` stay inline; `save_not_committed`
  carries the `backup_path` field on the `create_force` path when
  the failure occurs after backup rotation.

#### `tests/rename_dialog_logic.rs`

- [x] Label validation (non-empty, §4.1 length limits) blocks
  submit inline.
- [x] Issuer is not editable (CLI parity with `rename <new-label>`).
- [x] Submitting with the new label equal to the current label
  still calls `Vault::rename` inside `Vault::mutate_and_save` (no
  silent short-circuit, so `updated_at` always bumps).
- [x] `save_not_committed` restores the prior label in memory and
  keeps the dialog open with the inline error.
- [x] `save_durability_unconfirmed` keeps the new label in memory
  and surfaces the warning attached to the dialog body.

#### `tests/otpauth_uri_paste_logic.rs`

- [x] Successful URI parse routes through
  `paladin_core::parse_otpauth` and shares the manual path's
  duplicate-detection logic.
- [x] Parse errors for malformed URIs, unsupported scheme,
  unsupported `type=`, and `validation_error` stay inline without
  mutating vault state.
- [x] Inline error messages may name the failing field or reason
  but never echo the URI text.
- [x] Duplicate "add anyway" consumes the pending
  `ValidatedAccount` on the duplicate-allowed path.
- [x] URI entry buffer zeroizes on submit / cancel / dialog close
  and is never carried in `AppMsg` or `AppOutput`.

#### `tests/import_dialog_logic.rs`

- [x] Format-selector routing (auto-detect / explicit `otpauth` /
  `aegis` / `paladin` / `qr`) reaches the correct
  `paladin_core::import::from_file` invocation.
- [x] On-conflict policy (`skip` / `replace` / `append`) threads
  through `Vault::import_accounts` and is reflected in the merge
  outcome.
- [x] `paladin_core::classify_paladin_import_precheck` routing for
  `PromptForPassphrase`, `Reject(err)`, and `NoPrompt` covers
  encrypted Paladin, plaintext Paladin, malformed / unsupported
  Paladin headers, missing files, non-Paladin content, and
  forced-format mismatches.
- [x] Bundle-passphrase row clears when the source path or forced
  format changes after entry, and the probe / prompt flow restarts.
- [x] Post-merge counts (`imported` / `skipped` / `replaced` /
  `appended` / `warnings`) map to inline display.
- [x] Importer errors stay inline and never mutate vault state:
  `unsupported_import_format`, `unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `validation_error`, `no_entries_to_import`, `decrypt_failed`,
  `invalid_header`, `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, `io_error`.
- [x] `save_not_committed` after a successful merge restores the
  `Vault::mutate_and_save` snapshot;
  `save_durability_unconfirmed` keeps the merged accounts and
  surfaces the warning inline.

#### `tests/export_dialog_logic.rs`

- [x] Overwrite gate resets when the destination or format changes.
- [x] Plaintext-warning gate resets when the destination or format
  changes; the rendered text matches
  `paladin_core::format_plaintext_export_warning()` verbatim.
- [x] Encrypted twice-confirm match accepts; mismatch rejects with
  `invalid_passphrase` (`reason: "confirmation_mismatch"`).
- [x] Empty encrypted passphrase rejects with `invalid_passphrase`
  (`reason: "zero_length"`).
- [x] Destination or format change after passphrase entry clears
  the password rows and re-prompts.
- [x] Export writer errors (`io_error`, `save_not_committed`,
  `save_durability_unconfirmed`) stay inline; export does not
  mutate the vault, so no rollback path runs.

#### `tests/passphrase_dialog_logic.rs`

- [x] Sub-flow gating against `Vault::is_encrypted()`: `set` is
  available only when the getter returns `false`; `change` and
  `remove` only when `true`.
- [x] `set` / `change` twice-confirm match accepts; mismatch
  rejects with `invalid_passphrase`
  (`reason: "confirmation_mismatch"`).
- [x] `set` / `change` reject zero-length new passphrases with
  `invalid_passphrase` (`reason: "zero_length"`).
- [x] `remove` renders
  `paladin_core::format_plaintext_storage_warning()` verbatim and
  requires explicit confirmation before mutation.
- [x] Switching sub-flows clears all passphrase rows and pending
  plaintext-removal confirmation.
- [x] Passphrase entry buffers zeroize on submit / cancel / dialog
  close.

#### `tests/settings_logic.rs`

- [ ] Live-apply path runs `Vault::mutate_and_save` once per
  accepted change.
- [ ] Spinners clamp to
  `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
  and
  `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`.
- [ ] 500 ms debounce coalesces repeated spinner changes so only
  the most recent buffered value reaches `mutate_and_save`.
- [ ] `save_not_committed` reverts the visible widget value to the
  last committed state.
- [ ] `save_durability_unconfirmed` keeps the new value visible and
  attaches the warning to the changed `AdwPreferencesGroup` row
  inside the `AdwPreferencesDialog`.

#### `tests/effect_ownership_logic.rs`

- [ ] Only one vault-touching worker is in flight at a time.
- [ ] Mutating controls (row `next`, dialog submit buttons,
  passphrase actions, import / export, settings) are disabled while
  `UnlockedBusy` is active.
- [ ] Quit / window-close requests are deferred until the worker
  returns.
- [ ] Auto-lock expiry while `UnlockedBusy` is active records a
  lock-after-effect request and only locks if the returned vault is
  still encrypted; if the operation changed the vault to plaintext,
  the pending lock is discarded.
- [ ] `(Vault, Store)` is reinstalled before UI outcome handling on
  both success and typed failure.
- [ ] Settings spinner debounce coalesces to the latest pre-save
  value when an effect is in flight.
- [ ] Toggle changes that would overlap an active vault effect are
  not accepted until the control is re-enabled.
- [ ] Worker that fails before returning the `(Vault, Store)` pair
  routes the app to `StartupErrorComponent` without trying to
  reconstruct in-memory vault state.

### Smoke test (`tests/gtk_smoke.rs`)

Required for Milestone 7 sign-off. Runs in CI under `xvfb-run`.

- [ ] `xvfb-run` launches `paladin-gtk` and the process exits
  cleanly.
- [ ] App opens a prepared plaintext vault.
- [ ] `AccountListComponent` renders the prepared accounts.

### Thinness contract (`tests/thinness.rs`)

Tracked under §"Thinness contract" above. The single checklist
item there gates Milestone 7 sign-off alongside the checklists in
this section.

### Manual test plan (`tests/manual/MANUAL_TEST_PLAN.md`)

Per Milestone 7. Each item executes cleanly on both a Wayland and
an X11 session before sign-off.

- [ ] Init plaintext vault: both passphrase fields empty + warning
  gate before submit is enabled.
- [ ] Init encrypted vault with twice-confirm.
- [ ] Init when a vault already exists at the path opens the
  destructive-confirmation gate; confirm runs `create_force` and
  rotates the prior vault to `vault.bin.bak`; cancel leaves the
  prior vault intact.
- [ ] Init under the §10 fault-injection hook surfaces
  `save_not_committed` and `save_durability_unconfirmed` inline.
- [ ] Unlock encrypted vault with the correct passphrase.
- [ ] Copy a TOTP code from a row.
- [ ] HOTP `next` reveals and copies while showing the counter
  used.
- [ ] HOTP reveal window expires and the row returns to hidden.
- [ ] Auto-lock fires after the configured idle interval (encrypted
  vault).
- [ ] Clipboard auto-clear honors the if-unchanged rule.
- [ ] Add via manual fields.
- [ ] Add via `otpauth://` URI paste — success path.
- [ ] Add via `otpauth://` URI paste — malformed-URI rejection
  stays inline.
- [ ] Add via `otpauth://` URI paste — duplicate "add anyway"
  round-trip.
- [ ] Switching Add paths clears hidden secret fields and pending
  duplicate state.
- [ ] Add via clipboard image — success path.
- [ ] Add via clipboard image — oversized-image rejection before
  download.
- [ ] Import otpauth JSON with each on-conflict policy; reported
  counts match.
- [ ] Import aegis plaintext with each on-conflict policy; reported
  counts match.
- [ ] Import encrypted Paladin bundle with each on-conflict policy;
  reported counts match.
- [ ] Import QR image file with each on-conflict policy; reported
  counts match.
- [ ] Export plaintext: warning + confirmation, `0600` output.
- [ ] Export encrypted Paladin bundle: twice-confirm, round-trip
  via Import.
- [ ] Refused overwrite without confirmation leaves the destination
  untouched.
- [ ] Rename an account via the row kebab menu: label persists on
  reopen.
- [ ] Rename an account via the row kebab menu: renaming to the
  same label still saves and bumps `updated_at`.
- [ ] Rename an account via the row kebab menu: pre-commit fault
  injection rolls the label back.
- [ ] Settings persist across restart.
- [ ] Passphrase `set` / `change` / `remove` flows complete
  end-to-end.
- [ ] Secret fields clear on cancel, submit, and auto-lock.
- [ ] Icon theme resolution + fallback work against the system
  theme.

## Milestone 7 checklist (expanded from §12)

- [ ] Add the `paladin-gtk` crate to the workspace.
- [ ] Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
  Rename / Import / Export / Passphrase / Settings / StartupError).
- [ ] In-app vault initialization (`InitDialog` for missing vaults;
  plaintext + encrypted paths; explicit confirmation; plaintext-path
  warning sourced from
  `paladin_core::format_plaintext_storage_warning()`; in-dialog
  destructive `create_force` clobber confirmation rendered from
  `paladin_core::format_init_force_warning(existing_path)` when a vault
  already exists at the path; pre-commit + durability-unconfirmed
  handling).
- [ ] In-app account rename (`RenameDialog` reachable from the row
  kebab menu; calls `Vault::rename` inside `Vault::mutate_and_save`).
- [ ] Add-via-`otpauth://`-URI paste path in `AddAccountComponent`,
  decoded via `paladin_core::parse_otpauth` and sharing the manual
  duplicate / validation paths.
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Header-bar `+` button and primary menu wired with the pinned
  entries (Import…, Export…, Passphrase…, Preferences, About Paladin,
  Quit) per §"libadwaita usage", with Unlocked / `UnlockedBusy` gating
  applied to the mutating entries.
- [ ] Clipboard + auto-lock parity with TUI (opt-in). Use
  `Vault::is_encrypted()` to decide whether to arm the auto-lock
  timer (encrypted only) and to track the visible vault-mode flag
  across passphrase transitions.
- [ ] Serialized in-flight vault effects: one vault-touching worker at a time,
  mutating controls disabled while busy, and worker results restore
  `(Vault, Store)` before UI state applies success / typed failure handling;
  quit and auto-lock requests are deferred until the worker returns.
- [ ] Use `paladin_core::account_matches_search` for `search.rs` filtering,
  `paladin_core::format_validation_warning()` for validation-warning
  messages, and `paladin_core::format_plaintext_export_warning()` for the
  `ExportDialog` plaintext path so the GUI never re-implements shared text
  or match-key logic.
- [ ] Use `paladin_core::classify_paladin_import_precheck` before any
  encrypted-Paladin-bundle import prompt so the GUI shares the CLI / TUI
  Paladin header decision table.
- [ ] Linux desktop file, AppStream metadata, and icon.
- [ ] `.deb`, `.rpm`, Flatpak, and AppImage artifacts for `paladin-gtk`,
  signed and published per §11.3–§11.6; Flathub submission filed.
- [ ] Manual test plan documented.
- [ ] `xvfb-run` headless smoke test green in CI (plaintext vault opens
  and renders the list).

## Dependencies (per §9)

`relm4`, `gtk4` (via the `gtk4` crate from gtk-rs, baseline 4.16 so
the libadwaita 1.6 floor below is satisfiable), `libadwaita` (via the
`libadwaita` crate from gtk-rs, baseline 1.6 to match the §11.3
Debian dep declaration and to make `AdwAlertDialog` and
`AdwAboutDialog` available without a compatibility shim), `glib`,
`gio`, `gdk4`, `clap`, `zeroize` (pinned to the same `1.8` version
used by `paladin-core` and `paladin-tui`, for the
`clipboard_clear::PendingClipboardClear { value: Zeroizing<Vec<u8>> }`
captured-bytes wrapper so the post-copy clipboard payload zeroes on
drop), plus `paladin-core`. GDK
clipboard is the canonical Wayland/X11 path; `arboard` is **not** a
hard dependency for v0.2 and is only added if GDK clipboard proves
insufficient during implementation. Build-time tooling includes
`glib-compile-resources` (via the GLib development package or an equivalent
Rust build helper such as `glib-build-tools`) for the gresource bundle and
AppStream validation tooling for the Flatpak/native metadata dry-run.

`libadwaita` is adopted for v0.2 (decision 2026-05-05; baseline
raised to 1.6 on 2026-05-06) so the GUI follows the GNOME HIG out
of the box and the §11.3 packaging declaration matches the actual
binary dependency. `data/style.css` (scoped via `gtk::CssProvider`)
carries only Paladin-specific tweaks on top of Adwaita defaults — it
never tries to recreate the Adwaita palette.

**No `tokio`.** GTK's main loop is the executor; long work runs on
`gio::spawn_blocking` with results delivered back to the main thread via
Relm4 messages. The `gio::spawn_blocking` worker contract types
(including `Vault`, `Store`, `Account`, `AccountId`, `AccountSummary`,
`AccountKindSummary`, `Algorithm`, `Code`, `ValidatedAccount`,
`ValidationWarning`, `ImportReport`, `ImportWarning`, `ImportConflict`,
`ImportFormat`, `ImportOptions`, `EncryptionOptions`, `Argon2Params`,
`VaultLock`, `VaultInit`, `VaultStatus`, `VaultSettings`, `SettingKey`,
`SettingPatch`, `AccountKindInput`, `IconHintInput`, `AccountInput`,
`AccountQuery`, `InitPrecheck`, `PaladinImportPrecheck`, and
`PaladinError`) are all part of the
§4.7 worker-boundary `Send` set that Phase J of the core plan asserts
via CI, so the GUI can move them across thread boundaries during
encrypted `open` / `create` / `create_force` and any save-bearing
dialog operation without re-asserting `Send` itself.

## Thinness contract

`paladin-gtk` is a presentation layer. Crypto, storage, import/export,
and OTP primitives must never be re-implemented or imported directly
here — they belong in `paladin-core` per DESIGN §3.

- [ ] Tests: `tests/thinness.rs` — a source-level guard that scans
  `crates/paladin-gtk/src/` for forbidden crate-name spellings:
  `argon2`, `chacha20poly1305`, `bincode`, `hmac`, `sha1`, `sha2`,
  `rqrr`, `image`, `getrandom`, `directories`, `url`. Any direct
  reference fails the test with a message pointing at the file and
  the symbol so the offending logic can be moved into `paladin-core`.
  The crate manifest is also checked: `paladin-gtk` must not declare
  any of those crates as a direct `[dependencies]` entry. (GUI image
  clipboard imports route raw RGBA buffers through
  `paladin_core::import::qr_image_bytes`, so neither `image` nor
  `rqrr` belong in the GTK crate.) Keeps the GUI a thin shell over
  `paladin_core::*` plus the GTK / Adwaita / GLib stack.

## libadwaita usage

Components map to Adwaita widgets where the HIG calls for them; the
list below pins the v0.2 choices so the implementation does not drift
back into vanilla GTK4 widgets where Adwaita is idiomatic:

- **Window shell.** `AppModel`'s root is an `AdwApplicationWindow`
  whose content is an `AdwToolbarView`: the top bar holds an
  `AdwHeaderBar`, and the content slot holds the `AdwToastOverlay`
  (see below) wrapping whichever screen is active (`InitDialog` /
  `UnlockComponent` / `StartupErrorComponent` /
  `AccountListComponent`). The header bar carries, at the start of
  the right-hand side, a primary "Add account" `+` button (icon
  `list-add-symbolic`, tooltip "Add account") that opens
  `AddAccountComponent`; followed by the search-toggle button (which
  toggles the `gtk::SearchBar` in `AccountListComponent`); followed by
  the primary menu (`gtk::MenuButton` driven by `gio::Menu`). The
  primary menu's entries are fixed: **Import…** (opens
  `ImportDialog`), **Export…** (opens `ExportDialog`), **Passphrase…**
  (opens `PassphraseDialog` with the sub-flow gated by
  `Vault::is_encrypted()`), **Preferences** (opens
  `SettingsComponent`'s `AdwPreferencesDialog`), **About Paladin**
  (opens `AdwAboutDialog`), and **Quit**. The `+` button and the
  Import / Export / Passphrase / Preferences entries are **disabled
  when `AppModel` is not in `Unlocked`** (so they are off in
  `Missing` / `Locked` / `StartupError`) and disabled while
  `UnlockedBusy` is active per §"In-flight effect ownership"; About
  and Quit stay enabled in every state. No custom title-bar drawing.
- **Toast surface.** `AppModel` wraps the main content in an
  `AdwToastOverlay`. Transient feedback that does not need a modal —
  copy confirmation, `save_durability_unconfirmed` after a HOTP
  advance, clipboard-clear-fired notice, settings-saved confirmation
  — is delivered via `AdwToast`. Status-line errors that block
  further interaction stay inline in the affected dialog.
- **Confirmation dialogs.** `InitDialog`'s `create_force` clobber gate,
  `RemoveDialog`, the plaintext-export consent step, and the export
  overwrite gate are `AdwAlertDialog`s with `destructive-action` styling on the
  destructive button. Shared warning text (for example the plaintext-export
  "this writes unencrypted secrets to disk" warning) is reused verbatim so the
  UX matches the TUI.
- **Preferences.** `SettingsComponent` renders inside an
  `AdwPreferencesDialog` with one `AdwPreferencesGroup` for
  auto-lock and one for clipboard-clear. `AdwPreferencesWindow` is
  the libadwaita 1.6-deprecated predecessor and is **not** used.
  Toggles use `AdwSwitchRow`; spinners use `AdwSpinRow`.
  Live-apply (per the existing component description) still drives a
  `Vault::mutate_and_save` per change; the prior
  validate-revert-on-failure behavior is preserved.
- **Startup/open errors.** `StartupErrorComponent` uses an
  `AdwStatusPage` inside the main window content, with Retry and Quit
  actions. It is a display-only state and never creates, overwrites, or
  chmods vault files.
- **Passphrase entry.** `UnlockComponent` and `PassphraseDialog`
  use `AdwPasswordEntryRow` for passphrase inputs, including the
  twice-confirmed entries on `set` / `change` and on
  `ExportDialog`'s encrypted bundle path. Inline validation errors
  (`confirmation_mismatch`, `zero_length`, `decrypt_failed`) attach
  to the row by adding the `error` CSS class plus a status-line label
  below the row.
- **About / help.** `AdwAboutDialog` is wired to the application
  menu and pulls program metadata from Cargo package metadata embedded
  at compile time; the AGPL-3.0-or-later license text ships in the
  gresource bundle.

GTK-only widgets (`gtk::ListView`, `gtk::SearchEntry`,
`gtk::FileDialog`, `gtk::IconTheme`, `gdk::Clipboard`) keep
their existing roles — Adwaita does not replace those. The component
tree section above remains the source of truth for behavior; this
section just pins which Adwaita class fills each role.

## Out of scope for the GUI plan

- Encrypted Aegis backup support unless the core v0.2 stretch in §4.6 lands
  separately; the GUI handles core's current `unsupported_encrypted_aegis`
  error inline and does not block the GUI release on that importer.
- Secret-service / OS keyring integration for passphrase caching — not in
  DESIGN.md, would require an explicit design update.
- macOS / Windows builds. Linux only for the v0.2 release.

## Definition of done

- Component tree above implemented.
- Plaintext vault opens to list directly; encrypted vault gates on
  unlock; missing vault opens `InitDialog` and can create plaintext or
  encrypted vaults on explicit user confirmation. `vault_exists`
  triggers an in-dialog destructive-confirmation gate that runs
  `create_force` on confirm. Startup/open failures render a non-mutating
  startup-error view. No implicit creation.
- Account rename available from the row kebab menu; URI paste available
  in Add. GUI users no longer need to drop to the CLI for `rename` or
  `add --uri`.
- Auto-lock and clipboard-clear are off by default; the plaintext-vault
  no-op rule applies to auto-lock only (clipboard-clear works in both modes).
- HOTP reveal rows show the counter used for the visible code, then return
  to the stored next counter when hidden.
- Icon resolution works against system theme with placeholder fallback.
- Desktop file, AppStream metadata, and icon assets validate in the packaging
  dry-run.
- **Every Tests checklist item above is ticked** — including each
  bullet in the per-file pure-logic checklists
  (`tests/icon_resolution.rs`, `tests/search_logic.rs`,
  `tests/auto_lock_logic.rs`, `tests/clipboard_clear_logic.rs`,
  `tests/hotp_reveal_logic.rs`, `tests/secret_fields_logic.rs`,
  `tests/startup_error_logic.rs`, `tests/qr_clipboard_logic.rs`,
  `tests/init_dialog_logic.rs`, `tests/rename_dialog_logic.rs`,
  `tests/otpauth_uri_paste_logic.rs`, `tests/import_dialog_logic.rs`,
  `tests/export_dialog_logic.rs`, `tests/passphrase_dialog_logic.rs`,
  `tests/settings_logic.rs`, `tests/effect_ownership_logic.rs`), the
  `tests/gtk_smoke.rs` smoke-test bullets, the `tests/thinness.rs`
  source guard tracked under §"Thinness contract", and every step in
  `tests/manual/MANUAL_TEST_PLAN.md`.
- `xvfb-run` headless smoke test green in CI.
- Manual test plan executes cleanly on a Wayland and an X11 session.
- `.deb`, `.rpm`, Flatpak, and AppImage artifacts build through the
  release pipeline; GitHub-hosted artifacts are signed with `minisign`
  and the Flathub submission is filed.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
- DESIGN.md is kept in sync with implemented GUI-visible behavior; if a
  contradiction surfaces, DESIGN.md is updated first.
