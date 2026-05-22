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
    ├── cli_global_args.rs
    ├── startup_probes.rs
    ├── app_state_logic.rs
    ├── auto_lock_logic.rs        # pure logic; no display required
    ├── clipboard_clear_logic.rs  # pure logic; no display required
    ├── hotp_reveal_logic.rs
    ├── secret_fields_logic.rs
    ├── startup_error_logic.rs
    ├── qr_clipboard_logic.rs
    ├── account_list_logic.rs
    ├── account_row_logic.rs
    ├── init_dialog_logic.rs
    ├── unlock_dialog_logic.rs
    ├── add_account_logic.rs
    ├── rename_dialog_logic.rs
    ├── remove_dialog_logic.rs
    ├── otpauth_uri_paste_logic.rs
    ├── import_dialog_logic.rs
    ├── export_dialog_logic.rs
    ├── passphrase_dialog_logic.rs
    ├── settings_logic.rs
    ├── effect_ownership_logic.rs
    ├── no_tokio_source.rs
    ├── thinness.rs
    ├── manual_test_plan_doc.rs
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
  `VaultInit::Encrypted(EncryptionOptions::new(secret)?)`) and
  dispatches `init_dialog::run_init_worker` on `gio::spawn_blocking`
  — the pure-logic worker body that calls
  `paladin_core::Store::create(path, init)` then `Vault::save(&store)`
  (the encrypted path validates the passphrase and runs the §4.4
  Argon2id KDF before save). The explicit save mirrors the CLI
  `paladin init` flow so the freshly created vault is durable on
  disk by the time the worker returns, even when the user never
  adds an account. `run_init_worker` routes failures through
  `classify_create_error` so the dispatch site receives
  `InitWorkerEffect::Success { vault, store }`,
  `InitWorkerEffect::DestructiveGate`, or
  `InitWorkerEffect::InlineError(InlineError)` without re-deriving
  the routing off the raw `PaladinError`.
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
  confirm, the dialog re-dispatches `run_init_worker` with
  `InitWorkerMode::CreateForce` so the worker calls
  `paladin_core::Store::create_force(path, init)` on
  `gio::spawn_blocking` (the §5 staged-clobber pipeline commits
  inline, no extra `Vault::save` step needed),
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

#### `tests/cli_global_args.rs`

- [x] `--vault <path>` parses and leaves the default path unresolved
  when omitted.
- [x] `--no-color` parses as a GUI no-op for CLI / TUI parity.
- [x] `--json` rejects with clap text output and never renders a JSON
  envelope.
- [x] Positional file paths and `otpauth://` URIs reject; imports
  start from `ImportDialog`.
- [x] Hidden `--exit-after-startup` parses for smoke tests and stays
  absent from `--help`.

#### `tests/startup_probes.rs`

- [x] `run_startup_probes` resolves the requested path, calls
  `paladin_core::inspect`, and opens plaintext vaults into
  `AppState::Unlocked` with the live `(Vault, Store)` pair.
- [x] Missing vaults route to `AppState::Missing` without creating a
  file; encrypted vaults route to `AppState::Locked` without running
  Argon2id.
- [x] Default-path, inspect, and plaintext-open failures route to
  `AppState::StartupError` without carrying a live vault.
- [x] `startup_state_marker` and the per-state smoke-test markers
  remain single-line and stable for `--exit-after-startup` assertions.
- [x] Header-menu and About-dialog pure-format helpers keep action
  labels, action sensitivity, icon names, and Cargo-derived metadata
  stable without requiring a display server.

#### `tests/app_state_logic.rs`

- [x] Startup state decisions map path-resolution / inspect / open
  outcomes to `Missing`, `Locked`, `Unlocked`, and `StartupError`.
- [x] Unlock submit / worker-result routing preserves inline
  passphrase failures, startup-routed failures, and success
  transitions.
- [x] Mutating dialog dispatch decisions for Add / Remove / Rename /
  Import / Export / Passphrase / Settings only start from
  `Unlocked` and enter `UnlockedBusy` consistently.
- [x] Worker completions reinstall the returned `(Vault, Store)` pair
  before applying UI success, inline-error, or warning outcomes.
- [x] Dialog-drop / keep-mounted decisions match the success,
  inline-failure, and durability-unconfirmed contracts for each
  mutating surface.

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
- [x] Retry helper for `StartupErrorComponent` re-runs vault-path
  resolution + `inspect`; widget action wiring is tracked in the
  Milestone 7 startup-routing checklist.

#### `tests/qr_clipboard_logic.rs`

- [x] RGBA byte-length / stride preparation matches `width * 4`
  rows / `width * height * 4` total with overflow-checked
  multiplication.
- [x] Sizes above `paladin_core::QR_RGBA_MAX_BYTES` reject before
  allocation / download.
- [x] Decoded buffer is passed to
  `paladin_core::import::qr_image_bytes` with `ImportConflict::Skip`
  and reports imported / skipped / warning counts (parity with §6).

#### `tests/account_list_logic.rs`

- [x] `row_models_from_vault` projects accounts through
  `paladin_core::AccountSummary` without exposing secret bytes.
- [x] Empty vaults render no rows; populated vaults preserve insertion
  order across TOTP and HOTP rows.
- [x] Empty issuer display collapses to the bare label instead of a
  dangling colon.
- [x] `format_rendered_marker` and widget-state markers stay stable
  for `tests/gtk_smoke.rs` assertions.
- [x] Row action dispatch carries the selected account ID for Rename
  and Remove without touching the vault.

#### `tests/account_row_logic.rs`

- [x] Row display labels match CLI / TUI summary formatting for
  issuer / label combinations.
- [x] TOTP rows show copy + progress controls; HOTP rows show copy
  only during reveal and expose the "next" action.
- [x] Hidden HOTP rows show the stored next counter; revealed rows
  show `Code.counter_used` until the reveal expires.
- [x] Row projections keep code / counter display decisions pure so
  widget factories do not need direct vault access.
- [x] Row output events carry the account ID for Rename / Remove
  dispatch.

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
- [x] `run_init_worker` end-to-end against tempfile-backed plaintext
  and (light-Argon2) encrypted vaults: `InitWorkerMode::Create`
  returns `InitWorkerEffect::Success { vault, store }` and commits
  the empty vault to disk (parity with the CLI `Store::create` +
  `Vault::save` pattern); `InitWorkerMode::Create` against a
  pre-existing seeded vault routes to
  `InitWorkerEffect::DestructiveGate`; `InitWorkerMode::CreateForce`
  against a pre-existing seeded vault returns `Success` and rotates
  the prior primary to `vault.bin.bak`; the post-success vault
  survives a `Store::open` round trip.

#### `tests/unlock_dialog_logic.rs`

- [x] Unlock view is required only for encrypted vaults and skipped
  for plaintext / missing vault statuses.
- [x] Empty passphrase submit rejects inline with
  `invalid_passphrase` (`reason: "zero_length"`); non-empty
  passphrases build `VaultLock::Encrypted(secret)`.
- [x] `decrypt_failed` and `invalid_passphrase` stay inline on
  `UnlockComponent`; `unsafe_permissions`, `wrong_vault_lock`,
  `invalid_header`, `invalid_payload`, `unsupported_format_version`,
  `kdf_params_out_of_bounds`, and `io_error` route to
  `StartupErrorComponent`.
- [x] Passphrase buffers zeroize on submit / clear and are wrapped in
  zeroizing values at the component boundary.
- [x] Inline errors clear when the user edits or clears the
  passphrase field.

#### `tests/add_account_logic.rs`

- [x] Manual Add maps widget fields onto
  `paladin_core::AccountInput`, including kind-conditional TOTP
  period / HOTP counter handling.
- [x] Icon-hint text normalizes through
  `paladin_core::parse_icon_hint_token` for slug / `default` /
  `none` parity with CLI / TUI add flows.
- [x] `paladin_core::validate_manual` warnings proceed with inline
  warning display; field parse errors and core `validation_error`
  reject inline without mutating the vault.
- [x] Duplicate detection returns the existing account and stages a
  pending `ValidatedAccount` for the add-anyway confirmation.
- [x] Post-effect routing maps `save_durability_unconfirmed` to
  keep-with-warning and all pre-commit / validation failures to
  inline failure.

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

#### `tests/remove_dialog_logic.rs`

- [x] `summary_display_label` renders `<issuer>:<label>` when the
  issuer is set and non-empty, and the bare label otherwise (CLI /
  TUI parity; `Some("")` collapses to the no-issuer form so the body
  never renders a dangling `:label` colon).
- [x] `account_not_found_error` builds the defensive §5
  `invalid_state { operation: "remove", state: "account_not_found" }`
  the `Vault::mutate_and_save` closure passes through when
  `Vault::remove` returns `None`.
- [x] `save_not_committed` (with and without a rotated `.bak` path)
  routes to `RestorePrior` — `Vault::mutate_and_save` restores the
  account at its previous position and the dialog stays open with
  the inline error so the user can retry.
- [x] `save_durability_unconfirmed` routes to
  `KeepRemovedWithWarning` — the account stays gone from in-memory
  state and the warning attaches to the dialog body.
- [x] Every other typed error (`invalid_state { state:
  "account_not_found" }`, `io_error`, defensive `validation_error`)
  stays inline and does not transition the dialog out.

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

- [x] Live-apply path runs `Vault::mutate_and_save` once per
  accepted change.
- [x] Spinners clamp to
  `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
  and
  `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`.
- [x] 500 ms debounce coalesces repeated spinner changes so only
  the most recent buffered value reaches `mutate_and_save`.
- [x] `save_not_committed` reverts the visible widget value to the
  last committed state.
- [x] `save_durability_unconfirmed` keeps the new value visible and
  attaches the warning to the changed `AdwPreferencesGroup` row
  inside the `AdwPreferencesDialog`.

#### `tests/effect_ownership_logic.rs`

- [x] Only one vault-touching worker is in flight at a time.
- [x] Mutating controls (row `next`, dialog submit buttons,
  passphrase actions, import / export, settings) are disabled while
  `UnlockedBusy` is active.
- [x] Quit / window-close requests are deferred until the worker
  returns.
- [x] Auto-lock expiry while `UnlockedBusy` is active records a
  lock-after-effect request and only locks if the returned vault is
  still encrypted; if the operation changed the vault to plaintext,
  the pending lock is discarded.
- [x] `(Vault, Store)` is reinstalled before UI outcome handling on
  both success and typed failure.
- [x] Settings spinner debounce coalesces to the latest pre-save
  value when an effect is in flight.
- [x] Toggle changes that would overlap an active vault effect are
  not accepted until the control is re-enabled.
- [x] Worker that fails before returning the `(Vault, Store)` pair
  routes the app to `StartupErrorComponent` without trying to
  reconstruct in-memory vault state.

### Smoke test (`tests/gtk_smoke.rs`)

Required for Milestone 7 sign-off. Runs in CI under `xvfb-run`.

- [x] `xvfb-run` launches `paladin-gtk` and the process exits
  cleanly. Asserted by
  `crates/paladin-gtk/tests/gtk_smoke.rs::xvfb_run_launches_paladin_gtk_and_process_exits`;
  `.github/workflows/ci.yml` provisions the `clippy` and `test` jobs
  inside a `fedora:42` container with `gtk4-devel`, `libadwaita-devel`,
  and (`test` only) `xorg-x11-server-Xvfb` so the test runs under a
  synthetic display instead of skipping. The container is required
  because `ubuntu-24.04` ships GTK 4.14 / libadwaita 1.5 — too old
  for the `v4_16` / `v1_6` feature gates in
  `crates/paladin-gtk/Cargo.toml`.
- [x] App opens a prepared plaintext vault. `AppModel::init` runs
  `app::model::run_startup_probes` (resolve path → `paladin_core::inspect`
  → `paladin_core::Store::open` with `VaultLock::Plaintext` for the
  plaintext branch) and seeds `AppModel::state` / `AppModel::vault`
  from the result. Under `--exit-after-startup`, the model prints
  `app::model::startup_state_marker(&state)` to stdout before quitting
  so the smoke test
  `crates/paladin-gtk/tests/gtk_smoke.rs::app_opens_prepared_plaintext_vault`
  asserts the resolved `AppState::Unlocked` variant via that line.
  Pure-logic coverage in `crates/paladin-gtk/tests/startup_probes.rs`
  exercises the `Unlocked` / `Missing` / `StartupError` branches plus
  the marker format without a display server.
- [x] `AccountListComponent` renders the prepared accounts. The
  unlocked `AppModel` builds a `Vec<AccountRowModel>` via
  `account_list::row_models_from_vault` (an `AccountSummary`-driven
  projection — no secret bytes leave `paladin_core`) and launches an
  `AccountListComponent` controller; the component binds a
  `gio::ListStore` of `BoxedAnyObject<AccountRowModel>` to a
  `gtk::ListView` through a `SignalListItemFactory` that reads only
  `AccountRowModel::display_label`. Under `--exit-after-startup`,
  `AppModel` emits a second stdout marker —
  `paladin-gtk: account_list_rows=<labels>` produced by
  `account_list::format_rendered_marker` — so the smoke test
  `crates/paladin-gtk/tests/gtk_smoke.rs::app_renders_prepared_accounts`
  asserts the rendered row set under `xvfb-run` without driving
  widgets. Pure-logic coverage in
  `crates/paladin-gtk/tests/account_list_logic.rs` exercises the
  projection (insertion-order preservation, empty-issuer collapse,
  TOTP / HOTP summary fields) and the marker format without a
  display server.
- [x] `StartupErrorComponent` renders the non-mutating error
  surface for the `StartupError` branch. When `run_startup_probes`
  routes `AppModel` to `AppState::StartupError`, `AppModel` launches
  a `StartupErrorComponent` controller whose `AdwStatusPage` body
  reads `StartupError::rendered` verbatim (the same text the CLI /
  TUI surface via `paladin_core::format_unsafe_permissions` or
  `PaladinError::Display`). Under `--exit-after-startup`, `AppModel`
  emits an additional stdout marker —
  `paladin-gtk: startup_error_body=<rendered>` produced by
  `startup_error::format_startup_error_marker` (newlines collapsed
  to `|` so the line stays single-line for `stdout.contains(...)`
  assertions) — exclusively from the `StartupError` branch, so its
  presence proves the widget actually mounted. The smoke test
  `crates/paladin-gtk/tests/gtk_smoke.rs::app_renders_startup_error_for_corrupt_vault`
  drives the path with a corrupt vault file that forces
  `paladin_core::inspect` into `InvalidHeader` and asserts on both
  the existing `startup_state=StartupError` line and the new body
  marker. Pure-logic coverage in
  `crates/paladin-gtk/tests/startup_error_logic.rs` pins the
  marker prefix, the rendered passthrough for single-line bodies,
  and the newline-collapse contract for the multi-line
  `UnsafePermissions` body.
- [x] `InitDialogComponent` renders the first-run / missing-vault
  surface for the `Missing` branch. When `run_startup_probes`
  routes `AppModel` to `AppState::Missing` (no vault at the resolved
  path), `AppModel` launches an `InitDialogComponent` controller
  whose `AdwStatusPage` body names the resolved path alongside the
  shared `paladin_core::format_plaintext_storage_warning()` copy
  (so warning wording stays in lockstep with the CLI and TUI). The
  full passphrase-field / destructive-`create_force` wiring described
  in the §"Component tree" and §"Milestone 7 checklist" entry for
  `InitDialog` lands in follow-up commits; this bullet covers the
  read-only mount only, mirroring the staged rollout that the
  `StartupErrorComponent` bullet uses. Under `--exit-after-startup`,
  `AppModel` emits an additional stdout marker —
  `paladin-gtk: init_dialog_path=<path>` produced by
  `init_dialog::format_init_dialog_marker` — exclusively from the
  `Missing` branch, so its presence proves the widget actually
  mounted. The smoke test
  `crates/paladin-gtk/tests/gtk_smoke.rs::app_renders_init_dialog_for_missing_vault`
  drives the path with a `0700`-mode tempdir entry that never gets
  created on disk and asserts on both the existing
  `startup_state=Missing` line and the new path marker, while also
  verifying that the unlocked / startup-error markers stay absent.
  Pure-logic coverage in
  `crates/paladin-gtk/tests/init_dialog_logic.rs` pins the marker
  prefix and the path-passthrough rendering.
- [x] `UnlockDialogComponent` renders the passphrase-entry surface
  for the `Locked` branch. When `run_startup_probes` routes
  `AppModel` to `AppState::Locked` (an encrypted vault at the
  resolved path), `AppModel` launches an `UnlockDialogComponent`
  controller whose `AdwStatusPage` body names the resolved path so
  the user can confirm the destination before typing a passphrase.
  The full passphrase-entry / `gio::spawn_blocking` `paladin_core::open`
  worker / inline-decrypt-failure wiring described in the
  §"Component tree" and §"Milestone 7 checklist" entry for
  `UnlockComponent` lands in follow-up commits; this bullet covers
  the read-only mount only, mirroring the staged rollout that the
  `StartupErrorComponent` and `InitDialogComponent` bullets use.
  Under `--exit-after-startup`, `AppModel` emits an additional
  stdout marker — `paladin-gtk: unlock_dialog_path=<path>` produced
  by `unlock_dialog::format_unlock_dialog_marker` — exclusively
  from the `Locked` branch, so its presence proves the widget
  actually mounted. The smoke test
  `crates/paladin-gtk/tests/gtk_smoke.rs::app_renders_unlock_dialog_for_encrypted_vault`
  drives the path with an encrypted vault built from light Argon2
  params (`m_kib=8192, t=1, p=1`) so the test stays fast, and
  asserts on both the existing `startup_state=Locked` line and the
  new path marker, while also verifying that the unlocked /
  startup-error / init-dialog markers stay absent. Pure-logic
  coverage in `crates/paladin-gtk/tests/unlock_dialog_logic.rs`
  pins the marker prefix and the path-passthrough rendering.

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

The order below follows implementation dependencies: crate and parser
foundation, startup/window routing, vault access, list/row behavior,
dialog flows, shared policy/effect plumbing, then desktop packaging and
sign-off.

- [x] Add the `paladin-gtk` crate to the workspace.
- [x] Relm4 component tree (Init / Unlock / List / Row / Add / Remove /
  Rename / Import / Export / Passphrase / Settings / StartupError).
  All twelve controllers mount with the same `<Name>Init` /
  `<Name>Msg` / `<Name>Output` plus `relm4::SimpleComponent` scaffold
  shape, with TDD coverage in the per-component
  `tests/<name>_logic.rs`. Row sits inside `AccountListComponent`'s
  `SignalListItemFactory` binding today rather than as a separate
  `Controller<AccountRowComponent>` on `AppModel`; the parallel
  `AccountRowComponent` controller surface is in place so a follow-
  up migration from `SignalListItemFactory` to
  `relm4::factory::FactoryVecDeque<AccountRowComponent>` has a
  stable public API to land against. The follow-up commits for each
  controller (full passphrase entry on `InitDialog` / `UnlockDialog`,
  full form widgets on `AddAccountComponent` / `ImportDialogComponent`
  / `ExportDialogComponent` / `PassphraseDialogComponent` /
  `SettingsComponent`, full row body migration) attach behavior on
  top of these mounts.
- [x] Global argument parser contract (`cli.rs`).
  - [x] Accept `--vault <path>` and plumb the optional override into
    `AppInit` so startup probes inspect that path instead of the default.
  - [x] Accept `--no-color` as a parser-level no-op for CLI / TUI
    parity; do not expose any GUI theme override from this flag.
  - [x] Reject `--json` at parse time with clap's standard text
    diagnostic; never emit a JSON envelope from `paladin-gtk`.
  - [x] Reject positional file / URI arguments; imports always start
    from `ImportDialog`.
  - [x] Keep the smoke-test-only `--exit-after-startup` flag hidden from
    `--help` while still parsing it for `tests/gtk_smoke.rs`.
- [x] Startup routing and non-mutating startup-error actions.
  - [x] Resolve the startup path from `--vault` or
    `paladin_core::default_vault_path()` before inspecting the vault.
  - [x] Route `VaultStatus::Plaintext` through
    `paladin_core::Store::open(..., VaultLock::Plaintext)` and seed
    `AppState::Unlocked` plus the live `(Vault, Store)` pair.
  - [x] Route `VaultStatus::Encrypted` to `AppState::Locked` and mount
    `UnlockComponent`; do not run Argon2id until the user submits a
    passphrase.
  - [x] Route `VaultStatus::Missing` to `AppState::Missing` and mount
    `InitDialog` without creating files before explicit confirmation.
  - [x] Route `default_vault_path`, `inspect`, and non-passphrase open
    failures to `StartupErrorComponent` with rendered text sourced from
    `paladin_core::format_unsafe_permissions(&err)` when available and
    `PaladinError::Display` otherwise.
  - [x] Wire the `StartupErrorComponent` Retry action to re-run path
    resolution plus `inspect` and then re-route to `Missing`, `Locked`,
    `Unlocked`, or `StartupError` from the fresh probe result.
  - [x] Wire the `StartupErrorComponent` Quit action through the same
    application quit path used by the primary menu.
  - [x] Keep `StartupErrorComponent` display-only: retry and quit are
    the only actions, and the component never creates, overwrites,
    repairs, chmods, or selects a different vault path in v0.2.
- [x] Window shell and toast surface (`AdwApplicationWindow` root,
  `AdwToolbarView`, `AdwToastOverlay`, scoped CSS).
  - [x] Build `AppModel`'s widget root as an `AdwApplicationWindow`
    whose content is an `AdwToolbarView` so the header bar sits in
    the top slot and the active screen sits in the content slot.
  - [x] Wrap the active screen in an `AdwToastOverlay` so transient
    feedback (copy confirmation, settings-saved, clipboard-clear-fired
    notice, HOTP `save_durability_unconfirmed` warning, export-success
    path) can be delivered via `AdwToast`.
  - [x] Load `data/style.css` from the gresource bundle via
    `gtk::CssProvider` so Paladin-specific tweaks layer on top of
    Adwaita defaults; never re-skin the Adwaita palette.
  - [x] Route every active screen (`InitDialog`, `UnlockComponent`,
    `StartupErrorComponent`, `AccountListComponent`) through the same
    overlay so state transitions never lose pending toasts.
- [x] In-app vault initialization (`InitDialog` for missing vaults;
  plaintext + encrypted paths; explicit confirmation; plaintext-path
  warning sourced from
  `paladin_core::format_plaintext_storage_warning()`; in-dialog
  destructive `create_force` clobber confirmation rendered from
  `paladin_core::format_init_force_warning(existing_path)` when a vault
  already exists at the path; pre-commit + durability-unconfirmed
  handling).
  - [x] Add two `AdwPasswordEntryRow` passphrase entries (passphrase +
    confirmation) to `InitDialogComponent`'s body, keeping the existing
    `Missing`-branch path label as the `AdwStatusPage` description.
  - [x] Render `paladin_core::format_plaintext_storage_warning()`
    verbatim alongside a confirmation tick; gate submission on the tick
    when both passphrase fields are empty (the plaintext path).
  - [x] Route plaintext vs encrypted on submit by the empty-vs-non-empty
    state of the passphrase fields (both empty → plaintext; non-empty →
    encrypted).
  - [x] Validate encrypted submissions: reject one-empty or mismatched
    pairs inline with `invalid_passphrase`
    (`reason: "confirmation_mismatch"`); accept twice-confirm match.
  - [x] Build a `VaultInit` from the accepted entries
    (`VaultInit::Plaintext` or
    `VaultInit::Encrypted(EncryptionOptions::new(secret)?)`) and stash
    it in the zeroizing pending-create slot before dispatch.
  - [x] Dispatch `init_dialog::run_init_worker` with
    `InitWorkerMode::Create` on `gio::spawn_blocking` so the §4.4
    Argon2id KDF stays off the main loop; surface a spinner / busy
    affordance while the join is pending.
  - [x] Handle `InitWorkerEffect::Success { vault, store }` by
    transitioning `AppModel` to `Unlocked` with the returned pair and
    closing the dialog.
  - [x] Handle `InitWorkerEffect::DestructiveGate` by opening an
    in-dialog `AdwAlertDialog` with `destructive-action` styling whose
    body is `paladin_core::format_init_force_warning(existing_path)`.
  - [x] On destructive-gate confirm, re-dispatch the worker with
    `InitWorkerMode::CreateForce`, consuming the pending `VaultInit`.
  - [x] On destructive-gate cancel, close the alert and return to the
    `vault_exists` state without mutating the existing vault, then
    zeroize the pending `VaultInit`.
  - [x] Handle `InitWorkerEffect::InlineError(InlineError)` rendering
    for `unsafe_permissions`, `save_not_committed` (carrying the
    `create_force`-only `backup_path` field when applicable),
    `save_durability_unconfirmed`, and any other typed error returned
    by `classify_create_error`.
  - [x] Render `unsafe_permissions` from the `Some(text)` of
    `paladin_core::format_unsafe_permissions(&err)`, falling back to
    the generic error text only when the formatter returns `None`.
  - [x] Zeroize passphrase-entry widget buffers and the pending
    `VaultInit` on submit, cancel, destructive-confirmation cancel,
    dialog close, and auto-lock per §"Secret entry handling".
- [x] Secret-entry ownership and zeroization guardrails.
  - [x] Keep passphrases, manual Base32 secrets, `otpauth://` URI
    text, HOTP reveal codes, pending clipboard-clear payloads, and
    pending duplicate / create values out of `AppModel`, `AppMsg`,
    `AppOutput`, and other long-lived non-zeroizing state. The
    source-level guard `tests/secret_message_boundaries.rs`
    (`long_lived_types_carry_no_raw_secret_bearing_strings` /
    `dialog_output_enums_carry_no_raw_secret_bearing_strings`) scans
    `AppMsg` / `AppModel` / `AppInit` / `StartupOutcome` / `AppState`
    plus every dialog `*Output` enum and fails on a raw
    `String` / `Vec<u8>` field whose name carries a §8 secret marker
    (`passphrase`, `secret`, `otpauth`, `uri`, `clipboard`,
    `cleartext`, `phrase`, HOTP / TOTP / reveal-code spellings) —
    plain plaintext fields (rename `label`, issuer, file path)
    stay clear.
  - [x] Wrap Paladin-owned secret copies in `SecretString` or
    `Zeroizing` immediately at submit / copy time, and drop them as
    soon as the core call or clipboard policy no longer needs them.
    `tests/secret_fields_logic.rs::secret_entry_take_returns_zeroizing_and_empties_self`
    and `secret_entry_drop_zeroizes_inner_bytes_structurally` pin
    that `SecretEntry::take` yields `Zeroizing<String>` and that
    the inner buffer zeroizes on drop; the unlock-dialog flow is
    covered end-to-end by
    `tests/unlock_dialog_logic.rs::unlock_dialog_state_take_passphrase_returns_zeroizing_and_empties_state`.
  - [x] Clear the relevant GTK entry widgets on submit, cancel,
    dialog close, auto-lock, and Add path switches. The
    `ClearReason::{Submit, Cancel, Close, AutoLock, Replace,
    PathSwitch}` variants and the `*SecretState::clear_for` /
    `switch_path` / `switch_sub_flow` helpers in
    `crates/paladin-gtk/src/secret_fields.rs` are exercised by
    `tests/secret_fields_logic.rs` (35+ tests covering Add / Init /
    Passphrase state machines).
  - [x] Ensure validation, duplicate, import, export, and status
    messages can name fields / reasons but never echo secret-bearing
    input values. Covered by
    `tests/otpauth_uri_paste_logic.rs::inline_error_does_not_echo_uri_*`,
    `tests/add_account_logic.rs::*manual_*_marker*`,
    `tests/init_dialog_logic.rs::submit_confirmation_mismatch_inline_error_does_not_echo_passphrase_or_confirm`,
    plus the source-level guard above which prevents
    `InlineError::from_error` signatures from accepting a
    passphrase / secret parameter (those formatters only take
    `&PaladinError`, which never carries the typed-in passphrase).
- [x] Conditional unlock view (encrypted vaults only).
- [x] `UnlockComponent` full implementation (passphrase entry,
  `paladin_core::open` on `gio::spawn_blocking`, inline-error
  handling).
  - [x] Add an `AdwPasswordEntryRow` to `UnlockComponent`'s body so
    the user can type a passphrase against the resolved encrypted
    vault.
  - [x] On submit, wrap the entered passphrase in
    `secrecy::SecretString` and dispatch
    `paladin_core::open(path, VaultLock::Encrypted(secret))` on
    `gio::spawn_blocking` so the §4.4 Argon2 KDF stays off the main
    loop; surface a spinner / busy affordance while the join is
    pending.
  - [x] On success, transition `AppModel` from `Locked` to
    `Unlocked` with the returned `(Vault, Store)` pair and route to
    `AccountListComponent`.
  - [x] Render wrong-passphrase / passphrase-validation failures
    (`decrypt_failed` and `invalid_passphrase`) inline on the dialog
    so the user can retry without leaving `Locked`.
  - [x] Transition to `StartupErrorComponent` for non-authentication
    open failures (`unsafe_permissions`, `wrong_vault_lock`,
    `invalid_header`, `invalid_payload`,
    `unsupported_format_version`, `kdf_params_out_of_bounds`,
    `io_error`); `unsafe_permissions` renders the `Some(text)` from
    `paladin_core::format_unsafe_permissions(&err)` with the generic
    error text fallback so wording matches the CLI / TUI exactly.
  - [x] Zeroize the passphrase widget buffer on submit / cancel /
    dialog close / auto-lock per §"Secret entry handling".
- [x] `AccountListComponent` full implementation (`gtk::ListView` +
  factory + `gio::ListStore`, search bar + entry, selection
  management).
  - [x] Build a `gio::ListStore<BoxedAnyObject<AccountRowModel>>`
    seeded from `Vault::iter()` projected through
    `paladin_core::AccountSummary` (no secret bytes leave
    `paladin_core`).
  - [x] Mount a `gtk::ListView` bound to the store via a
    `SignalListItemFactory` whose row body is the
    `AccountRowComponent` (see the row item below). The list-level
    wiring (the `gtk::ListView`, the `SignalListItemFactory`
    instantiation, the `gio::ListStore` splice, and the search bar)
    stays in `account_list.rs`; the row body — the per-row
    `gtk::Box` (`build_row_widget`), the bind walk (`bind_row`),
    the `gtk::IconTheme` resolve (`bind_row_icon`), and the per-row
    `gio::SimpleActionGroup` install (`install_row_action_group`) —
    lives in `account_row.rs` so the `AccountRowComponent` module
    is the canonical owner of row body construction. The
    `SignalListItemFactory::connect_setup` / `connect_bind`
    callbacks import those four helpers from
    `paladin_gtk::account_row`; the helper ownership is pinned by
    `tests/account_row_logic.rs::{build_row_widget_is_exposed_from_account_row_module,
    bind_row_is_exposed_from_account_row_module,
    bind_row_icon_is_exposed_from_account_row_module,
    install_row_action_group_is_exposed_from_account_row_module}`
    so a silent move back into `account_list.rs` surfaces as a
    hard-error import drift rather than as an undetected re-shuffle
    of widget ownership.
  - [x] Host a `gtk::SearchEntry` inside a `gtk::SearchBar` whose
    `search-mode-enabled` is bound to the header-bar search-toggle
    button.
  - [x] On query change, rebuild the list by calling
    `paladin_core::account_matches_search(&Account, query)` against
    `Vault::iter()` before projecting matches to `AccountSummary`;
    preserve insertion order among matches.
  - [x] After each filter rebuild, set the selected row from
    `paladin_core::select_after_filter(prev, filtered)` (preserve
    prior selection if still present, else first match) for parity
    with the TUI.
  - [x] Refresh the store after every vault mutation (Add / Remove /
    Rename / Import / settings change that toggles a row's
    presentation) without reordering surviving rows. `AppModel::
    refresh_account_list` re-projects via
    `filtered_row_models_from_vault` (which walks `Vault::iter()` in
    insertion order) and emits `AccountListMsg::Refresh`. The
    Add / Remove / Rename worker-completion handlers gate the call
    on `dispatch.refresh_list` (set by
    `should_refresh_list_after_{add,remove,rename}` for every
    committed outcome — Success or
    `save_durability_unconfirmed`-routed `KeepWithWarning`). The
    surviving-row ordering invariant is pinned by
    `tests/account_list_logic.rs::row_models_after_sequence_of_add_rename_remove_preserves_surviving_order`
    plus the per-mutation `row_models_after_vault_*` /
    `filtered_row_models_after_vault_*` siblings. Import plugs into
    the same helper once `ImportDialogComponent`'s full
    implementation (§"Milestone 7 checklist" >
    `ImportDialogComponent` > "On success, refresh
    `AccountListComponent` from the returned vault") lands. The
    `SettingsComponent` auto-lock / clipboard-clear toggles do not
    toggle row presentation, so no settings-driven refresh is
    needed today.
- [x] `AccountRowComponent` full body (label, icon, code, TOTP
  gauge / HOTP next, copy button, kebab menu).
  - [x] Render the display label via
    `summary_display_label(&AccountSummary)` (CLI / TUI parity:
    `<issuer>:<label>` when issuer is set, bare label otherwise;
    empty issuer collapses to the no-issuer form). `account_row.rs`
    owns the canonical helper; `remove_dialog.rs` re-exports it so
    the row factory (`row_models_from_vault` /
    `row_model_for_account` in `account_list.rs`) and the
    `RemoveDialog` body share one source of truth.
  - [x] Render the icon via `gtk::IconTheme` against
    `AccountSummary.icon_hint` with the placeholder fallback (see
    "Icon resolution" item below).
  - [x] Render a code label populated from
    `paladin_core::totp_code` for TOTP rows and from the hidden /
    reveal state for HOTP rows (see "HOTP reveal" item below).
    `account_list::bind_row` reads `RowDisplay::code` and writes
    the resulting text through `code.set_label(&code_text)` —
    `CodeDisplay::Hidden` renders the `HIDDEN_CODE_PLACEHOLDER`
    and `CodeDisplay::Visible(c)` renders the live code. For TOTP
    rows, the ticker (`crate::ticker::compute_tick_displays`)
    publishes `vault.totp_code(row.id, now)` through `project_row`
    on every `paladin_core::TICK_INTERVAL_MS` tick so the visible
    code stays in lockstep with `paladin_core`'s TOTP window;
    races against vault mutations or clock-skew failures fall
    through to leave the prior display in place, never blanking
    the row. For HOTP rows, `crate::hotp_reveal::project_row_with_code`
    renders `CodeDisplay::Visible` from the in-flight reveal `Code`
    and `crate::account_list::hidden_row_display` renders
    `CodeDisplay::Hidden` once the reveal window expires, matching
    the §"Component tree" > `AccountRowComponent` rules that
    hidden rows show the stored next counter and revealed rows
    show the `Code.counter_used` label.
  - [x] For TOTP rows, render a progress widget (gauge / level bar)
    that ticks against the shared `paladin_core::TICK_INTERVAL_MS`
    source (see "TOTP ticker" item below). The continuous
    `gtk::ProgressBar` is appended to each row by `build_row_widget`
    and bound by `bind_row` from
    `crate::account_row::progress_fraction(&ProgressDisplay)`; HOTP
    rows hide the bar via `progress_visible`. Per-tick refresh
    publishes a fresh `RowDisplay { progress: Some(_), .. }` through
    the existing `LiveDisplayCache`, so the bar updates in lockstep
    with the visible code without a separate signal.
  - [x] For HOTP rows, render the "next" button that activates the
    `hotp_peek` / `hotp_advance` reveal worker (see "HOTP reveal"
    item below). The `AccountListOutput::AdvanceHotp(AccountId)`
    dispatch routes through `AppMsg::AccountListAction` into the
    `gio::spawn_blocking` worker
    (`crate::hotp_reveal::run_hotp_advance_worker`) that stages the
    pre-advance code via `Vault::hotp_peek` and commits via
    `Vault::hotp_advance`.
  - [x] Add a copy button that copies the visible code to
    `gdk::Clipboard` and schedules clipboard auto-clear; disable
    copying on a hidden HOTP row. The copy `gtk::Button` built by
    `build_row_widget` is bound to the per-row `row.copy` action
    (constant `ROW_COPY_ACTION_NAME`); `bind_row` toggles the
    button's sensitivity through `RowDisplay::copy_enabled` so a
    hidden HOTP row never fires the action. The
    `AccountListOutput::CopyCode(AccountId)` dispatch routes through
    `AppMsg::AccountListAction` into the AppModel handler that
    resolves the visible code via
    `crate::clipboard_clear::prepare_copy_bytes`, writes through
    `gdk::Clipboard::set_text`, and arms the auto-clear policy via
    `schedule_copy` into `AppModel::pending_clipboard`.
  - [x] If a GDK clipboard write fails, surface an inline / status
    error and do not schedule clipboard auto-clear for that attempt.
    GTK4's `gdk::Clipboard::set_text` has no failure return — the
    write lands or no-ops at the GDK layer — so the "schedule only
    on success" rule is satisfied by routing through `set_text`
    directly. A future GDK with a fallible write surface would gate
    the `schedule_copy` call on the result without changing the
    surrounding pure-logic plumbing.
  - [x] Add a kebab `gtk::MenuButton` whose `gio::Menu` exposes
    "Rename…" (opens `RenameDialog` for that row) and "Remove…"
    (opens `RemoveDialog` for that row). The kebab
    `gtk::MenuButton` is built by
    `account_list::build_row_widget` with the
    `view-more-symbolic` icon and the `.flat` style class, and
    carries the `gio::Menu` returned by
    `account_list::build_kebab_menu_model` ("Rename…" →
    `row.rename`, "Remove…" → `row.remove`). The per-row
    `gio::SimpleActionGroup` installed by
    `install_row_action_group` registers both actions;
    activations route through `dispatch_row_action` into
    `AccountListOutput::OpenRenameDialog(AccountId)` /
    `AccountListOutput::OpenRemoveDialog(AccountId)`, which the
    `AppMsg::AccountListAction` arm in `app/model.rs` consumes
    to launch `RenameDialogComponent` / `RemoveDialogComponent`
    against the live `Vault`. The menu shape (item count,
    labels, action targets) is pinned by
    `tests/account_list_logic.rs::build_kebab_menu_model_exposes_rename_and_remove_in_order`
    so drift between the kebab UI, the per-row action group, and
    the dispatch table surfaces as a failing test.
  - [x] Disable mutating row controls (copy, "next", kebab) while
    `AppModel` is `UnlockedBusy` per §"In-flight effect ownership".
    `account_row::apply_busy_mask` flips `RowDisplay::copy_enabled`,
    `next_button_enabled`, and `kebab_enabled` to `false` when the
    parent is busy; `account_list::bind_display_for_row` runs the
    mask before binding, and `bind_row` writes the three bits onto
    `gtk::Button::set_sensitive` / `gtk::MenuButton::set_sensitive`.
    `AccountListMsg::SetBusy(bool)` latches a shared
    `Rc<Cell<bool>>` (`account_list::BusyFlag`) the factory's
    `connect_bind` closure reads on every rebind; the
    `AppModel::sync_account_list_busy` reconcile (peer of
    `apply_ticker_transition` / `prune_reveals_if_locked`) fires
    after every dispatch so any state transition flipping
    `AppState::is_busy()` propagates a debounced re-splice through
    the row factory.
- [x] TOTP ticker (`paladin_core::TICK_INTERVAL_MS` timeout source
  for gauge updates and clipboard staleness checks).
  - [x] Install a single `glib::timeout_add_local` source ticking
    at `paladin_core::TICK_INTERVAL_MS` while at least one TOTP row
    is visible.
  - [x] On each tick, recompute the TOTP gauge value and the
    visible code from `paladin_core::totp_code(account, now)` for
    every TOTP row in the current list view.
  - [x] On each tick, give the clipboard auto-clear policy a chance
    to wake against the current `gdk::Clipboard` text
    (only-if-unchanged) so stale copies clear even without explicit
    user activity. The pure-logic deadline check is wired through
    `ticker::tick`'s `clipboard_wake_due` field against
    `AppModel::pending_clipboard`; when the hint fires
    `AppModel::handle_tick` returns the issued
    `ClipboardClearToken` and the dispatch arm kicks off
    `gdk::Clipboard::read_text_async`. The async result lands as
    `AppMsg::ClipboardWakeRead { token, current }` whose handler
    routes through `crate::clipboard_clear::evaluate_wake` and acts
    on the `WakeDecision`: `Clear` writes empty text and drops the
    pending entry; `Mismatch` drops the pending entry untouched;
    `Stale` leaves it alone. The captured bytes are wrapped in
    `Zeroizing<Vec<u8>>` so drops wipe in place.
  - [x] Tear down the ticker on `Locked` / `StartupError`
    transitions and reinstall on `Unlocked` so plaintext and
    encrypted vaults share the same lifecycle.
- [x] HOTP reveal window behavior
  (`paladin_core::policy::hotp_reveal::deadline` driver,
  peek-stage-advance worker, restart-on-next semantics,
  hidden-state copy disabling).
  - [x] On row activation of "next", stage the would-be visible
    `Code` from `Vault::hotp_peek` into a zeroizing pending slot
    before calling `Vault::hotp_advance` inside the spawn-blocking
    worker. (Lives in
    `crate::hotp_reveal::run_hotp_advance_worker`; the worker
    captures the pre-advance code through `StagedCode::from_code`
    before calling `Vault::hotp_advance` so the staged bytes are
    available for the `save_durability_unconfirmed` publication
    path.)
  - [x] On worker success or `save_durability_unconfirmed`, publish
    the staged code to the row's reveal slot and start the reveal
    timer from `paladin_core::policy::hotp_reveal::deadline(now)`.
    (`apply_advance_outcome` → `apply_advance_decision` inserts the
    `RevealWindow` into `AppModel::reveal_windows` keyed by
    `AccountId`; `row_display_for_reveal` projects the live code
    through `AccountListMsg::Tick` so the row binds through the
    `LiveDisplayCache`.)
  - [x] On `save_durability_unconfirmed`, additionally post an
    `AdwToast` carrying the committed-but-uncertain warning so the
    row stays usable with the new code in hand. (Toast body lives
    at `crate::hotp_reveal::format_hotp_durability_unconfirmed_toast`;
    `RevealEffect::Refreshed { show_toast: true }` raises it on
    `AppModel::toast_overlay`.)
  - [x] On worker pre-commit failure (`save_not_committed`) or any
    other typed error, leave the previous reveal state unchanged
    (hidden if no reveal was open), zeroize the staged code, and
    surface the inline / status error. (`AdvanceDecision::Retain`
    drops the staged code via `Zeroizing<String>`; the matching
    `RevealEffect::Retained` arm raises
    `format_hotp_advance_failed_toast` on the overlay.)
  - [x] Hide the code and revert to the stored next counter when
    the reveal deadline elapses. (`AppModel::handle_tick` calls
    `expired_reveals` against the monotonic clock, removes the
    expired entries from `reveal_windows`, and re-emits
    `AccountListMsg::Tick` with `hidden_row_display(row)` so the
    row reverts to the stored next-counter projection.)
  - [x] Activating "next" during an open reveal advances again,
    consumes a fresh `hotp_peek` / `hotp_advance` round trip, and
    restarts the reveal timer with the newly committed code.
    (`apply_advance_decision` overwrites the entry for the same
    `AccountId`; the prior `RevealWindow` drops, zeroing its
    `Zeroizing<String>` bytes in place. The new deadline rebases
    on the worker's `completed_at`.)
  - [x] Hidden HOTP rows show the stored next counter as their
    visible label; during reveal, the row shows the
    `Code.counter_used` of the visible code until expiry. (Already
    wired through `crate::account_row::counter_display` /
    `project_row`: `None` visible code → `CounterText::Stored`;
    `Some(code)` with `counter_used` set → `CounterText::Used`.)
  - [x] Disable copy on hidden HOTP rows; during reveal, copy
    captures the visible code without advancing again. (The pure-
    logic side is in `crate::account_row::copy_enabled`, returning
    `false` for HOTP rows without a visible code and `true` while a
    `RevealWindow` is open; the copy button widget binding lands
    alongside the copy / clipboard bullet earlier in the
    `AccountRowComponent` cluster.)
- [x] Icon resolution (`gtk::IconTheme` lookup against
  `AccountSummary.icon_hint` with placeholder fallback).
  - [x] Implement `icons.rs` lookups against the system
    `gtk::IconTheme` for the slug carried in
    `AccountSummary.icon_hint`. (Lives in
    `crates/paladin-gtk/src/icon_resolution.rs`; the row factory in
    `account_list::build_row_factory` resolves the slug via
    `icon_resolution::resolve_display_icon` against
    `gtk::IconTheme::for_display(...).has_icon(...)` at bind time.)
  - [x] Fall back to a generic placeholder icon when the slug is
    `None`, empty, or unresolved. (`PLACEHOLDER_ICON_NAME =
    "dialog-password-symbolic"`; pinned by
    `tests/icon_resolution.rs` and used by `bind_row_icon`.)
  - [x] Ship the placeholder icon in the gresource bundle so it is
    available identically in native and Flatpak builds. (Lives at
    `crates/paladin-gtk/data/icons/scalable/actions/dialog-password-symbolic.svg`
    and is bundled by `data/paladin-gtk.gresource.xml`; the runtime
    `wire_app_icon_theme_resource_path` helper in
    `crates/paladin-gtk/src/app/model.rs` calls
    `IconTheme::for_display(display).add_resource_path(format_app_icon_theme_resource_path())`
    so the placeholder resolves against the embedded payload even in
    sandboxed Flatpak runtimes.)
- [x] In-app account rename (`RenameDialog` reachable from the row
  kebab menu; calls `Vault::rename` inside `Vault::mutate_and_save`).
  - [x] Add a `gtk::MenuButton` kebab on each row whose `gio::Menu`
    exposes "Rename…" alongside the existing "Remove…".
    (`account_list::build_row_factory` mounts a
    `gtk::MenuButton::builder().menu_model(&build_kebab_menu_model())`
    as the trailing row child; `build_kebab_menu_model` appends
    "Rename…" first and "Remove…" second, targeting
    `row.rename` / `row.remove` against the per-row
    `gio::SimpleActionGroup` installed by `install_row_action_group`.
    `kebab_visible` returns `true` for every `AccountKindSummary`
    and `kebab_enabled` returns `true`, so HOTP and TOTP rows both
    expose the menu unconditionally. Pinned by
    `account_row_logic::kebab_visible_always_on_for_totp_and_hotp`,
    `kebab_enabled_always_on`,
    `account_list_logic::build_kebab_menu_model_exposes_rename_and_remove_in_order`,
    `row_rename_action_name_is_rename`,
    `row_remove_action_name_is_remove`,
    `dispatch_row_action_routes_rename_to_open_rename_dialog`,
    `dispatch_row_action_routes_remove_to_open_remove_dialog`, and
    `account_row_output_request_rename_carries_account_id`.)
  - [x] Build `RenameDialogComponent` as a modal carrying a
    pre-populated `AdwEntryRow` for the label plus Save / Cancel
    buttons. The Save `gtk::Button` (with the `suggested-action`
    style class) sits beside the Cancel button in the dialog
    footer; the entry row is seeded imperatively from
    `RenameDialogState::draft` in `init` so the dialog opens with
    the user-editable current label in place.
  - [x] Validate the label inline (non-empty, §4.1 length limits) and
    gate the Save button. The keystroke-driven `connect_changed`
    signal re-runs `classify_submit` via
    `RenameDialogState::set_draft`; the Save button binds to
    `format_rename_dialog_save_button_sensitive(&model.state)` via
    `#[watch]` so the affirmative affordance dims whenever
    `last_validation` is `SubmitOutcome::InlineError` and the
    inline-error label renders the matching §4.1 rejection.
  - [x] On submit, call `Vault::rename(id, new_label, now)` inside
    `Vault::mutate_and_save` regardless of whether the new label
    equals the current one (so `updated_at` always bumps, matching
    the CLI). (`run_rename_worker` in `crate::rename_dialog`
    unconditionally invokes
    `Vault::mutate_and_save(|v| v.rename(account_id, &label, now))`
    against the live `(Vault, Store)` pair carried by the
    `RenameWorkerInput`; `classify_submit_with_label_matching_prior_after_trim_still_proceeds`
    pins that even a same-label draft routes to `SubmitOutcome::Proceed`
    rather than short-circuiting, and
    `run_rename_worker_same_label_still_bumps_updated_at` exercises
    the end-to-end worker with `new_label == prior_label` and asserts
    that the post-worker `updated_at` strictly exceeds the pre-worker
    timestamp. `run_rename_worker_plaintext_rename_succeeds_and_returns_live_pair`
    and `run_rename_worker_persists_label_to_disk` cover the happy-
    path projection and on-disk persistence respectively.)
  - [x] Handle `save_not_committed` by restoring the prior label in
    memory and keeping the dialog open with the inline error.
    (`classify_rename_error` routes
    `PaladinError::SaveNotCommitted { .. }` to
    `RenameErrorOutcome::RestorePrior(InlineError {
    kind: ErrorKind::SaveNotCommitted, .. })` regardless of whether
    a `.bak` rotation ran; `apply_msg` on
    `RenameDialogMsg::WorkerFailed(RestorePrior(_))` resets
    `state.draft` to `prior_label` so the visible label matches the
    rolled-back in-memory vault, then stores the outcome on
    `state.worker_outcome` for the body re-render. At the dispatch
    layer, `should_drop_rename_dialog_after` returns `false` for
    `RenameWorkerEffect::Failure(RestorePrior(_))` so the dialog
    stays mounted, and `should_refresh_list_after_rename` returns
    `false` because the rolled-back vault already matches what the
    row renders. Pinned by
    `classify_rename_error_save_not_committed_restores_prior`,
    `classify_rename_error_save_not_committed_with_backup_restores_prior`,
    `apply_msg_worker_failed_restore_prior_stores_outcome`,
    `apply_msg_worker_failed_restore_prior_resets_draft_to_init_label`,
    `apply_msg_worker_failed_restore_prior_with_backup_resets_draft_to_init_label`,
    `should_drop_rename_dialog_after_failure_restore_prior_returns_false`,
    and `should_refresh_list_after_rename_failure_restore_prior_returns_false`.)
  - [x] Handle `save_durability_unconfirmed` by keeping the new label
    in memory and attaching the warning to the dialog body.
    (`classify_rename_error` routes
    `PaladinError::SaveDurabilityUnconfirmed` to
    `RenameErrorOutcome::KeepNewWithWarning(InlineWarning {
    kind: ErrorKind::SaveDurabilityUnconfirmed, .. })`; `apply_msg`
    on `RenameDialogMsg::WorkerFailed(KeepNewWithWarning(_))` leaves
    `state.draft` unchanged on the user-typed new label and stores
    the outcome on `state.worker_outcome` so the dialog body
    re-renders with the warning attached. At the dispatch layer,
    `should_drop_rename_dialog_after` returns `false` for
    `Failure(KeepNewWithWarning(_))` so the warning surfaces inside
    the still-mounted dialog, while `should_refresh_list_after_rename`
    returns `true` because the rename did commit to memory and the
    `AccountListComponent` row must re-project off the reinstalled
    `(Vault, Store)` pair to show the new label. Pinned by
    `classify_rename_error_save_durability_unconfirmed_keeps_new_label`,
    `apply_msg_worker_failed_keep_new_with_warning_keeps_draft`,
    `should_drop_rename_dialog_after_failure_keep_new_with_warning_returns_false`,
    and `should_refresh_list_after_rename_failure_keep_new_with_warning_returns_true`.)
  - [x] On success, refresh `AccountListComponent` from the returned
    vault, close the dialog, and surface a status / toast confirmation.
    `AppMsg::RenameWorkerCompleted` routes the worker outcome through
    `compose_rename_dispatch`, which bundles
    `should_drop_rename_dialog_after` (drops the dialog on `Success`),
    `should_refresh_list_after_rename` (re-emits
    `AccountListMsg::Refresh` from the reinstalled `(Vault, Store)`
    pair on `Success` and `KeepNewWithWarning`), and
    `rename_success_toast_after` (returns
    `Some(format_rename_dialog_success_toast().to_string())` on
    `Success` only). The dispatch site raises the body as
    `self.toast_overlay.add_toast(adw::Toast::new(&body))` on the same
    `adw::ToastOverlay` used by the HOTP durability-unconfirmed
    surface; the failure branches stay `None` so the dialog's inline
    error / body warning is the only surface that conveys the typed
    outcome. Wording is pinned through `format_rename_dialog_success_toast`
    (`"Account renamed."`) so the helper, the projection, and the
    bundled `RenameDispatch::success_toast` field stay in lockstep.
  - [x] Reset the entry buffer on cancel / submit / dialog close.
    The label is non-secret, so the obligation is the standard
    widget-buffer reset (no zeroize-on-drop, unlike the URI /
    passphrase / manual-secret buffers covered by §"Secret entry
    handling"). Three dismissal paths converge on releasing the
    underlying `gtk::EntryBuffer`:
      * Cancel — `apply_msg(RenameDialogMsg::Cancel)` calls
        `RenameDialogState::clear()` (which delegates to
        `set_draft(String::new())`, wiping the shadow draft,
        cached `last_validation`, and any pending `worker_outcome`)
        and then emits `RenameDialogOutput::Cancel`; `AppModel`
        drops the live `RenameDialogComponent` controller on
        receipt, releasing the widget tree (and its
        `gtk::EntryBuffer`) with it.
      * Submit success — the worker reports
        `RenameWorkerEffect::Success`; the dispatch composer flips
        `RenameDispatch::drop_dialog = true`, and the same
        `AppModel` drop path runs.
      * Dialog close (auto-lock / parent navigation) — `AppModel`
        drops the controller as part of the lock transition,
        releasing the widget tree with it.
      `RenameDialogState::clear` survives the reset for
      `account_id` and `prior_label` so a defensive re-render
      against the cleared state still targets the same row.
      Pinned by `rename_dialog_state_clear_resets_draft_per_l1789`,
      `rename_dialog_state_clear_resets_worker_outcome_per_l1789`,
      `rename_dialog_state_clear_resets_last_validation_per_l1789`,
      `rename_dialog_state_clear_preserves_account_id_per_l1789`,
      `rename_dialog_state_clear_is_idempotent_per_l1789`,
      `apply_msg_cancel_clears_state_per_l1789`, and
      `apply_msg_cancel_still_emits_cancel_output_after_clear_per_l1789`;
      the submit-success drop path is pinned by
      `should_drop_rename_dialog_after_success_returns_true` in
      `tests/app_state_logic.rs`.
- [x] `RemoveDialog` confirmation flow (`AdwAlertDialog` with
  `destructive-action` styling gating `Vault::remove` inside
  `Vault::mutate_and_save`).
  - [x] Open `RemoveDialog` as an `AdwAlertDialog` with
    `destructive-action` styling on the destructive button when the
    user picks "Remove…" from the row kebab menu.
    (`RemoveDialogComponent`'s view! macro now uses
    `adw::AlertDialog` as `#[root]` with the body and inline
    error / warning labels in `set_extra_child`; `init`
    imperatively calls `add_response` for Cancel and Remove,
    `set_response_appearance(destructive_id, ResponseAppearance::Destructive)`,
    `set_default_response(Some(cancel_id))`, and
    `set_close_response(cancel_id)`. `connect_response(None, …)`
    routes the response id through the new
    `format_remove_dialog_destructive_response_id` /
    `format_remove_dialog_cancel_response_id` helpers into
    `RemoveDialogMsg::Confirm` / `Cancel`. `AppModel` now calls
    `controller.widget().present(Some(&self.content))` on
    `AccountListOutput::OpenRemoveDialog` and `force_close()` on
    worker success — the alert self-detaches on close so the prior
    `self.content.append` / `self.content.remove` plumbing is gone.
    Pinned by
    `tests/remove_dialog_logic.rs::format_remove_dialog_destructive_response_id_returns_remove`,
    `format_remove_dialog_cancel_response_id_returns_cancel`,
    `format_remove_dialog_response_ids_are_distinct`, and
    `format_remove_dialog_response_ids_are_non_empty_single_tokens`.)
  - [x] Render the dialog body using
    `summary_display_label(&AccountSummary)` so the wording matches
    the CLI / TUI (`<issuer>:<label>` when issuer is set; empty
    issuer collapses to the bare-label form so the body never
    renders a dangling `:label` colon).
    (`decide_remove_target` in `crate::remove_dialog` projects the
    matching `AccountSummary` through the re-exported
    `summary_display_label` into `RemoveDialogInit::display_label`;
    `RemoveDialogState::new` retains the pre-formatted heading on
    `self.init` so `RemoveDialogState::display_label()` returns the
    same `<issuer>:<label>` body the row factory uses, and the view!
    macro hands it to `format_remove_dialog_subtitle` for the
    `adw::StatusPage::set_description` binding. Empty-issuer collapse
    is pinned by
    `tests/remove_dialog_logic.rs::summary_display_label_with_empty_issuer_collapses_to_bare_label`
    and
    `decide_remove_target_drops_empty_issuer_in_display_label`; the
    subtitle helper is pinned by
    `format_remove_dialog_subtitle_renders_display_label`.)
  - [x] On confirm, call `Vault::remove(id)` inside
    `Vault::mutate_and_save`; handle `save_not_committed` by
    restoring the account at its previous position and keeping the
    dialog open with the inline error, and handle
    `save_durability_unconfirmed` by keeping the account removed
    from in-memory state and attaching the warning to the dialog
    body.
    (`run_remove_worker` calls
    `vault.mutate_and_save(&store, |v| v.remove(account_id))` on
    `gio::spawn_blocking` so the §4.3 atomic-write pipeline rolls back
    the in-memory removal on `save_not_committed` before returning;
    `classify_remove_error` routes the typed
    `PaladinError::SaveNotCommitted` to
    `RemoveErrorOutcome::RestorePrior(InlineError)` and
    `PaladinError::SaveDurabilityUnconfirmed` to
    `RemoveErrorOutcome::KeepRemovedWithWarning(InlineWarning)`.
    `apply_msg(WorkerFailed(...))` stashes the typed outcome on
    `RemoveDialogState::worker_outcome` so the view's #[watch]
    bindings re-render the matching inline error / warning text;
    `format_remove_dialog_inline_error_text` /
    `format_remove_dialog_inline_error_visible` /
    `format_remove_dialog_inline_warning_text` /
    `format_remove_dialog_inline_warning_visible` keep the projection
    pure and unit-testable. The dispatch site keeps the dialog
    mounted on both failure classes via the existing dispatch
    helpers in `app/state.rs`. Pinned by
    `tests/remove_dialog_logic.rs::classify_remove_error_save_not_committed_restores_prior`,
    `classify_remove_error_save_durability_unconfirmed_keeps_removed_with_warning`,
    `format_remove_dialog_inline_error_text_renders_restore_prior_body`,
    `format_remove_dialog_inline_warning_text_renders_keep_removed_body`,
    `format_remove_dialog_inline_error_and_warning_are_mutually_exclusive`,
    and the end-to-end
    `run_remove_worker_plaintext_remove_succeeds_and_returns_live_pair`
    / `run_remove_worker_persists_removal_to_disk` integration tests
    against tempfile-backed plaintext vaults.)
  - [x] Surface `invalid_state { state: "account_not_found" }`,
    `io_error`, and defensive `validation_error` inline without
    closing the dialog; the dialog never mutates visible state
    until the worker returns.
    (Every other typed `PaladinError` falls into the
    `classify_remove_error` defensive arm
    `RemoveErrorOutcome::InlineError(InlineError)`, which
    `apply_msg(WorkerFailed(...))` stashes onto
    `RemoveDialogState::worker_outcome`; the view! macro's
    `error_label` reads through
    `format_remove_dialog_inline_error_text` /
    `format_remove_dialog_inline_error_visible` so the typed message
    renders beneath the confirmation body without dropping the
    dialog. `Vault::mutate_and_save` is authoritative on rolling the
    in-memory state back, and `AppModel` reinstalls the returned
    `(Vault, Store)` pair before applying the typed outcome so visible
    state never drifts from disk until the worker returns. Pinned by
    `tests/remove_dialog_logic.rs::classify_remove_error_invalid_state_account_not_found_stays_inline`,
    `classify_remove_error_io_error_stays_inline`,
    `classify_remove_error_validation_error_stays_inline`,
    `apply_msg_worker_failed_defensive_inline_error_stores_outcome`,
    `format_remove_dialog_inline_error_text_renders_defensive_inline_error`,
    `format_remove_dialog_inline_error_visible_true_for_defensive_inline_error`,
    and the end-to-end
    `run_remove_worker_unknown_account_routes_inline_error_and_returns_pair`.)
  - [x] On success, refresh `AccountListComponent` from the returned
    vault, close the dialog, and surface a status / toast confirmation.
    `AppMsg::RemoveWorkerCompleted` routes the worker outcome through
    `compose_remove_dispatch`, which now bundles
    `should_drop_remove_dialog_after` (drops the dialog on `Success`),
    `should_refresh_list_after_remove` (re-emits
    `AccountListMsg::Refresh` from the reinstalled `(Vault, Store)`
    pair on `Success` and `KeepRemovedWithWarning`), and
    `remove_success_toast_after` (returns
    `Some(format_remove_dialog_success_toast().to_string())` on
    `Success` only). The dispatch site raises the body as
    `self.toast_overlay.add_toast(adw::Toast::new(&body))` on the same
    `adw::ToastOverlay` used by the rename / HOTP durability-unconfirmed
    surfaces; the failure branches stay `None` so the dialog's inline
    error / body warning is the only surface that conveys the typed
    outcome. Wording is pinned through `format_remove_dialog_success_toast`
    (`"Account removed."`) so the helper, the projection, and the
    bundled `RemoveDispatch::success_toast` field stay in lockstep.
    Pinned by
    `tests/remove_dialog_logic.rs::format_remove_dialog_success_toast_returns_removed`,
    `format_remove_dialog_success_toast_is_non_empty_single_sentence`,
    `tests/app_state_logic.rs::remove_success_toast_after_success_returns_body`,
    `remove_success_toast_after_failure_returns_none`, and
    `compose_remove_dispatch_populates_success_toast_only_on_success`.
  - [x] Cancel closes the dialog without mutating the vault.
    (`apply_msg(RemoveDialogMsg::Cancel)` emits
    `RemoveDialogOutput::Cancel` without touching
    `RemoveDialogState::worker_outcome` or the seeded init; the
    `AppMsg::RemoveDialogAction(RemoveDialogOutput::Cancel)` arm in
    `app/model.rs` drops the live `RemoveDialogComponent` controller
    and removes the dialog widget from the content tree without
    touching `(Vault, Store)`. Pinned by
    `tests/remove_dialog_logic.rs::apply_msg_cancel_emits_cancel_output`,
    `apply_msg_cancel_does_not_mutate_worker_outcome`, and
    `remove_dialog_output_cancel_is_distinct_variant`.)
- [x] `AddAccountComponent` shared shell and mutation pipeline.
  - [x] Wrap the manual form, the URI entry, and the clipboard QR path
    in an `AdwViewStack` controlled by an `AdwViewSwitcher` before the
    path-specific pages are wired.
    (`crate::secret_fields::AddPath` now carries three variants —
    `Manual`, `Uri`, `Qr` — and `crate::add_account` exposes
    `format_add_path_label` (`"Manual"` / `"URI"` /
    `"Scan clipboard"`), `format_add_path_name` (`"manual"` / `"uri"` /
    `"qr"`), and `format_add_path_order()` (`[Manual, Uri, Qr]`) so the
    widget can loop over the slice, calling
    `AdwViewStack::add_titled_with_name(child, format_add_path_name,
    format_add_path_label)` to seed the three pages in declared order
    without re-deriving the wording inline. `compose_active_path` /
    `compose_active_path_label` / `compose_active_path_name` project
    the live `AddSecretState::active_path` so the widget binds a single
    `#[watch]` to drive `AdwViewStack::set_visible_child_name` and any
    header subtitle beside the switcher.
    `compose_save_button_sensitive` returns `false` on the Qr path so
    the shared Save footer stays greyed out while the page-local
    "Scan clipboard" action button (lands in L2099) is the path's
    activation. `compose_submit_outcome`'s defensive Qr arm returns
    `SubmitOutcome::InlineError` with `ErrorKind::InvalidState` so a
    future caller that bypasses the sensitivity gate surfaces a benign
    rejection rather than a vault mutation it has no validated account
    for. `AddSecretState::switch_path` owns no buffer to wipe on a
    Qr-leaving switch (the QR page reads the clipboard texture on
    activation, not from a held buffer) and still drops any pending
    duplicate-add `Box<ValidatedAccount>` so the `ZeroizeOnDrop` impl on
    `paladin_core::Secret` wipes the carried bytes when the returned
    `Option` drops. Pinned by
    `tests/add_account_logic.rs::format_add_path_label_qr_returns_scan_clipboard`,
    `format_add_path_name_qr_returns_qr_slug`,
    `format_add_path_name_qr_is_distinct_from_label`,
    `format_add_path_order_matches_view_switcher_page_order`,
    `format_add_path_order_covers_every_addpath_variant`,
    `format_add_path_order_labels_align_with_format_add_path_label`,
    `format_add_path_order_names_align_with_format_add_path_name`,
    `compose_active_path_after_switch_to_qr_returns_qr`,
    `compose_active_path_label_after_switch_to_qr_returns_scan_clipboard`,
    `compose_active_path_name_after_switch_to_qr_returns_qr_slug`,
    `compose_save_button_sensitive_qr_path_is_false`,
    `compose_save_button_sensitive_qr_path_remains_false_with_prior_buffers`,
    `compose_submit_outcome_qr_path_rejects_inline_defensively`, and
    `tests/secret_fields_logic.rs::add_state_switch_manual_to_qr_clears_hidden_manual_secret`,
    `add_state_switch_uri_to_qr_clears_hidden_uri_text`,
    `add_state_switch_qr_to_manual_preserves_manual_buffer`,
    `add_state_switch_qr_to_uri_preserves_uri_buffer`,
    `add_state_switch_same_qr_is_noop`,
    `add_state_path_switch_to_qr_drops_pending_duplicate_add`.)
  - [x] Keep Add dialog submit / cancel / close handling centralized so
    every path can disable submit while a worker is in flight and can
    clear path-local pending state on dismissal.
    (`AddDialogState::busy` is the per-dialog mirror of the
    [`crate::account_list::BusyFlag`] latch; the
    `AddAccountMsg::SetBusy(bool)` dispatch arm in `apply_msg` flips
    the flag without forwarding an output, and
    `compose_save_button_sensitive` short-circuits to `false` while
    `state.is_busy()` so the shared Save footer dims regardless of
    the active sub-path. `AppModel` propagates the flip through
    `sync_add_dialog_busy`, the peer of `sync_account_list_busy` —
    both run after every dispatch (alongside
    `apply_ticker_transition` / `prune_reveals_if_locked`) and
    debounce against `AppModel::last_add_dialog_busy` so the
    `Unlocked → UnlockedBusy` transition that brackets the
    `gio::spawn_blocking Vault::mutate_and_save(|v| v.add(...))`
    worker emits a single message in each direction. The new
    `AddAccountMsg::Close` arm centralizes window-close /
    parent-navigation / modal-dismissal handling by routing through
    the same `AddSecretState::clear_for` helper as `Cancel` and
    `SubmitProceed` (with `ClearReason::Close`), draining
    `pending_duplicate_existing`, and forwarding the typed
    `AddAccountOutput::Close` so the existing
    `AppMsg::AddAccountAction(...)` dispatch in `app/model.rs`
    detaches the dialog through the same drop-controller arm Cancel
    uses without a `_` catch-all silently swallowing a future
    Close-only behavior. Pinned by
    `tests/add_account_logic.rs::add_dialog_state_fresh_is_not_busy`,
    `apply_msg_set_busy_true_emits_no_output_and_marks_busy`,
    `apply_msg_set_busy_false_clears_busy`,
    `apply_msg_set_busy_same_value_is_idempotent`,
    `apply_msg_set_busy_preserves_form_buffers`,
    `compose_save_button_sensitive_manual_path_busy_returns_false`,
    `compose_save_button_sensitive_uri_path_busy_returns_false`,
    `compose_save_button_sensitive_qr_path_busy_returns_false`,
    `compose_save_button_sensitive_re_enables_after_set_busy_false`,
    `compose_save_button_sensitive_busy_then_form_cleared_stays_false`,
    `apply_msg_close_routes_to_close_output`,
    `apply_msg_close_wipes_secret_state_buffers`,
    `apply_msg_close_wipes_uri_buffer`,
    `apply_msg_close_drops_pending_duplicate_and_existing_summary`,
    and `add_account_output_close_is_distinct_variant`.)
  - [x] On path switch, clear hidden secret-bearing fields (manual
    Base32 secret and URI text) plus any pending duplicate/add-anyway
    state before the newly selected page becomes active.
    (`AddAccountComponent`'s `view!` block now mounts an
    `adw::ViewStack` carrying three named pages — slugs from
    [`crate::add_account::format_add_path_name`], display labels from
    [`crate::add_account::format_add_path_label`], iteration order from
    [`crate::add_account::format_add_path_order`] — with an
    `adw::ViewSwitcherBar` bound to the same stack. The stack's
    `connect_visible_child_notify` reads
    `gtk::Stack::visible_child_name()` and routes the slug through
    [`crate::add_account::parse_add_path_name`] (the exact inverse of
    `format_add_path_name`); a recognized slug dispatches
    [`AddAccountMsg::SwitchPath`], whose existing `apply_msg` arm calls
    [`crate::secret_fields::AddSecretState::switch_path`] to wipe the
    leaving path's hidden secret-bearing buffer — the manual Base32
    secret on `Manual` → `*`, the URI text on `Uri` → `*` — and drops
    any pending duplicate-add [`paladin_core::ValidatedAccount`] via
    `Box`'s `ZeroizeOnDrop` impl. An unknown / case-folded /
    whitespace-padded slug routes through `parse_add_path_name` as
    `None` and the dispatch arm leaves visible state untouched so a
    future renamed / mistyped page cannot silently bypass the wipe.
    Programmatic state changes flip the stack's visible page through
    the `#[watch]`-bound [`crate::add_account::compose_active_path_name`]
    projection so the widget and pure-logic state stay in lockstep.
    Pinned by
    `tests/add_account_logic.rs::parse_add_path_name_manual_slug_returns_manual_path`,
    `parse_add_path_name_uri_slug_returns_uri_path`,
    `parse_add_path_name_qr_slug_returns_qr_path`,
    `parse_add_path_name_round_trips_format_add_path_name_for_every_variant`,
    `parse_add_path_name_empty_slug_returns_none`,
    `parse_add_path_name_unknown_slug_returns_none`,
    `parse_add_path_name_rejects_capitalized_label_form`,
    `parse_add_path_name_rejects_whitespace_padded_slug`, and
    `parse_add_path_name_is_case_sensitive`, plus the existing
    `apply_msg_switch_path_*` arms and the
    `tests/secret_fields_logic.rs::add_state_switch_*` invariants that
    cover the secret-buffer wipe + pending-duplicate drop on every
    sub-path transition.)
  - [x] Share one duplicate-detection / "add anyway" / serialized
    `Vault::mutate_and_save` insertion path for manual and URI
    submissions; QR clipboard imports use the import-report path
    described below.
    The shared Save click pipeline now spans the widget→parent
    boundary: clicking the dialog footer's Save button dispatches
    `AddAccountMsg::SaveClicked`, whose `apply_msg` arm forwards
    `AddAccountOutput::RequestSaveClick` up to `AppModel`. The
    `AppMsg::AddAccountAction(RequestSaveClick)` arm reads the
    cached dialog state via `ComponentController::model`, borrows
    the live `(Vault, Store)` pair, runs
    `compose_save_click_outcome(state, &vault, SystemTime::now())`
    on the main thread, and dispatches the routed
    `AddAccountMsg` back via
    `controller.emit(save_click_outcome_to_msg(outcome))`. Both
    sub-paths converge on the same downstream arms: a
    non-collision routes through `SubmitProceed { account }` and
    a collision routes through `StagePendingDuplicate { account,
    warnings, existing }`; the "add anyway" confirmation consumes
    the parked pending via `ConfirmAddAnyway`. All three pre-
    effect outcomes funnel into the single
    `AddAccountOutput::Submit { account }` boundary the existing
    `compose_add_worker_input` + `gio::spawn_blocking
    run_add_worker` pipeline handles, so the
    `Vault::mutate_and_save(|v| v.add(account))` worker stays a
    single shared insertion path. Serialization comes from the
    `AppModel::sync_add_dialog_busy` reconcile flipping
    `AddAccountMsg::SetBusy` around the worker lifetime;
    `compose_save_button_sensitive` dims the footer Save button
    while busy so a second Save cannot start until the prior
    `(Vault, Store)` pair returns. Pinned by
    `tests/add_account_logic.rs::apply_msg_save_clicked_routes_to_request_save_click_output`,
    `apply_msg_save_clicked_routes_identically_for_manual_and_uri_paths`,
    `apply_msg_save_clicked_preserves_manual_draft_state`,
    `apply_msg_save_clicked_preserves_uri_buffer`,
    `apply_msg_save_clicked_does_not_drop_pending_duplicate`,
    `apply_msg_save_clicked_does_not_clear_inline_error`, and
    `add_account_output_request_save_click_is_distinct_variant`,
    plus the existing
    `compose_save_click_outcome_*` /
    `save_click_outcome_to_msg_*` invariants that pin the per-
    path routing and the unified `AddAccountOutput::Submit`
    boundary.
  - [x] Keep successful manual and URI additions consistent with §7:
    refresh the list from the returned vault, close the dialog, and
    surface a status / toast confirmation.
    `AppMsg::AddWorkerCompleted` routes the worker outcome through
    `compose_add_dispatch`, which now bundles
    `should_drop_add_dialog_after` (drops the dialog on `Success`),
    `should_refresh_list_after_add` (re-emits
    `AccountListMsg::Refresh` from the reinstalled `(Vault, Store)`
    pair on `Success` and `KeepWithWarning`), and
    `add_success_toast_after` (returns
    `Some(format_add_dialog_success_toast().to_string())` on
    `Success` only). The dispatch site raises the body as
    `self.toast_overlay.add_toast(adw::Toast::new(&body))` on the same
    `adw::ToastOverlay` used by the rename / remove / HOTP
    durability-unconfirmed surfaces; the failure branches stay `None`
    so the dialog's inline error / body warning is the only surface
    that conveys the typed outcome. Wording is pinned through
    `format_add_dialog_success_toast` (`"Account added."`) so the
    helper, the projection, and the bundled
    `AddDispatch::success_toast` field stay in lockstep.
    Pinned by
    `tests/add_account_logic.rs::format_add_dialog_success_toast_returns_added`,
    `format_add_dialog_success_toast_is_non_empty_single_sentence`,
    `tests/app_state_logic.rs::add_success_toast_after_success_returns_body`,
    `add_success_toast_after_failure_returns_none`, and
    `compose_add_dispatch_populates_success_toast_only_on_success`.
  - [x] Keep successful clipboard-QR additions on a post-success counts
    panel until the user dismisses it, so imported / skipped / warning
    counts remain visible.
    (`AddDialogState::qr_success_counts: Option<QrImportSummary>` parks
    the imported / skipped / warning counts after a successful
    clipboard-QR worker completion; `AddAccountMsg::QrSuccess(QrImportSummary)`
    sets the slot (also dropping any prior `inline_error` /
    `worker_outcome` so the panel renders against a clean body), and
    `AddAccountMsg::DismissQrCountsPanel` drains it on the explicit
    Dismiss click. The panel survives between worker completion and
    the user's Dismiss; it is drained on `AddAccountMsg::Cancel` /
    `Close` and on `SwitchPath` off the QR sub-path so a follow-up
    open / manual or URI sub-path starts on a clean body. The widget
    binds `compose_qr_counts_panel_visible` for the panel container's
    visibility and `compose_qr_counts_panel_imported_label` /
    `compose_qr_counts_panel_skipped_label` /
    `compose_qr_counts_panel_warnings_label` for the per-row text,
    with the heading and dismiss-button wording pinned by
    `format_qr_counts_panel_heading` /
    `format_qr_counts_panel_dismiss_label`. The actual QR worker
    dispatch lands alongside §"Milestone 7 checklist" >
    `AddAccountComponent` QR clipboard image path (L2310) which
    populates this state via the `QrSuccess` arm. Pinned by
    `tests/add_account_logic.rs::qr_success_counts_is_none_by_default`,
    `apply_msg_qr_success_stores_summary_on_state`,
    `apply_msg_dismiss_qr_counts_panel_clears_slot`,
    `apply_msg_dismiss_qr_counts_panel_on_empty_state_is_noop`,
    `apply_msg_qr_success_replaces_prior_summary`,
    `apply_msg_qr_success_clears_prior_inline_error`,
    `apply_msg_qr_success_clears_prior_worker_outcome`,
    `apply_msg_cancel_clears_qr_success_counts`,
    `apply_msg_close_clears_qr_success_counts`,
    `apply_msg_switch_path_clears_qr_success_counts`,
    `apply_msg_switch_path_same_qr_preserves_counts`,
    `compose_qr_counts_panel_visible_returns_false_for_default_state`,
    `compose_qr_counts_panel_visible_returns_true_after_qr_success`,
    `compose_qr_counts_panel_visible_returns_false_after_dismiss`,
    `format_qr_counts_panel_imported_label_renders_count`,
    `format_qr_counts_panel_skipped_label_renders_count`,
    `format_qr_counts_panel_warnings_label_renders_count`,
    `format_qr_counts_panel_heading_is_non_empty`,
    `format_qr_counts_panel_dismiss_label_is_non_empty`,
    `compose_qr_counts_panel_imported_label_returns_some_after_success`,
    `compose_qr_counts_panel_skipped_label_returns_some_after_success`,
    and `compose_qr_counts_panel_warnings_label_returns_some_after_success`.)
- [x] `AddAccountComponent` manual fields path (label, issuer,
  Base32 secret, algorithm, digits, kind, TOTP period, HOTP counter,
  icon hint).
  - [x] Mount the manual form on the `AdwViewStack`'s "Manual" page
    using `AdwEntryRow` / `AdwSpinRow` / `AdwComboRow` rows that map
    onto `paladin_core::AccountInput`. The `AddAccountComponent`'s
    `view!` macro now populates the Manual page with four
    `adw::PreferencesGroup` clusters: an identity group
    (`adw::EntryRow` for label / issuer / icon-hint), a secret group
    (`adw::PasswordEntryRow` for the Base32 secret), a kind /
    algorithm / digits group (`adw::ComboRow` × 2 + `adw::SpinRow`),
    and a kind-conditional period / counter group
    (`adw::SpinRow` × 2 toggled via
    `compose_manual_period_secs_visible` /
    `compose_manual_counter_visible`). Every row's keystroke /
    selection signal dispatches the matching
    `AddAccountMsg::Manual*Changed` arm so `ManualDraftState` /
    `AddSecretState::manual_secret` stay in lockstep with the
    visible widget. The two `adw::ComboRow` dropdowns map index →
    enum through the new `parse_manual_kind_from_selected` /
    `parse_manual_algorithm_from_selected` inverses (each rejecting
    out-of-range / `gtk::INVALID_LIST_POSITION` values to `None` so
    a stray selection never dispatches a fallback enum). Pinned by
    `tests/add_account_logic.rs::parse_manual_kind_from_selected_zero_returns_totp`,
    `parse_manual_kind_from_selected_one_returns_hotp`,
    `parse_manual_kind_from_selected_out_of_range_returns_none`,
    `parse_manual_kind_from_selected_round_trips_format_manual_kind_selected`,
    `parse_manual_algorithm_from_selected_zero_returns_sha1`,
    `parse_manual_algorithm_from_selected_one_returns_sha256`,
    `parse_manual_algorithm_from_selected_two_returns_sha512`,
    `parse_manual_algorithm_from_selected_out_of_range_returns_none`,
    and `parse_manual_algorithm_from_selected_round_trips_format_manual_algorithm_selected`,
    plus the existing `apply_msg_manual_*_changed_*` /
    `format_manual_*_title` / `compose_manual_*` invariants that
    cover the dispatch and projection layers.
  - [x] Default the form fields to the CLI manual-add defaults from
    DESIGN §5 (TOTP, SHA1, 6 digits, 30 s period, HOTP counter 0,
    icon-hint mode `Default from issuer`). `ManualDraftState::default`
    already seeds the typed draft at the §5 defaults, and the
    `view!` macro reads each manual-form widget through the
    `compose_manual_*(&model.state)` projections so the dialog's
    first render already matches the CLI `paladin add` defaults
    without user input. Pinned by
    `tests/add_account_logic.rs::fresh_add_dialog_seeds_manual_form_to_design_section_5_cli_defaults`
    (aggregating contract over `compose_manual_kind_selected`,
    `compose_manual_algorithm_selected`, `compose_manual_digits_value`,
    `compose_manual_period_secs_value`, `compose_manual_counter_value`,
    `compose_manual_period_secs_visible`, `compose_manual_counter_visible`,
    `compose_manual_label_text`, `compose_manual_issuer_text`, and
    `compose_manual_icon_hint_text`) and
    `fresh_add_dialog_icon_hint_default_resolves_to_default_from_issuer_mode`
    (pins that the empty icon-hint entry threads through
    `paladin_core::parse_icon_hint_token` into
    `IconHintInput::Default`), on top of the existing per-field
    `compose_manual_*_fresh_dialog_*` /
    `manual_draft_state_default_matches_cli_manual_add_defaults` /
    `add_dialog_state_new_initializes_manual_draft_to_defaults`
    siblings.
  - [x] Normalize the icon-hint entry through
    `paladin_core::parse_icon_hint_token` so the slug / `default` /
    `none` parsing matches the CLI / TUI add modals exactly.
    `classify_manual_submit` threads the typed
    `ManualDraftState::icon_hint_text` (preserved verbatim — case and
    whitespace included — by `apply_msg(AddAccountMsg::ManualIconHintChanged)`
    per the L2364 widget binding) through
    `paladin_core::parse_icon_hint_token`, short-circuiting any
    malformed slug as `ManualSubmitOutcome::InlineError` before
    `validate_manual` runs. Empty / `none` (any case) / explicit
    lowercase slugs map to `IconHintInput::Default` /
    `IconHintInput::None` / `IconHintInput::Slug(s)` respectively
    — same boundary the CLI / TUI add flows cross. Pinned by
    `tests/add_account_logic.rs::classify_manual_submit_empty_icon_hint_defaults_from_issuer`,
    `classify_manual_submit_none_token_clears_icon_hint`,
    `classify_manual_submit_explicit_slug_stored_verbatim`, and
    `classify_manual_submit_malformed_slug_rejects_inline`.
  - [x] On submit, validate the inputs through
    `paladin_core::validate_manual`; parse errors (invalid Base32,
    empty label, out-of-range digits / period / counter) and any
    core-returned `validation_error` block submission inline without
    mutating the vault. `classify_manual_submit` calls
    `validate_manual(input, import_time)` after the icon-hint
    normalization above and wraps the `Err` as
    `ManualSubmitOutcome::InlineError(InlineError::from_error(&err))`
    so the typed §5 body propagates through the shared
    `compose_save_click_outcome` pipeline as
    `SaveClickOutcome::InlineError`. The Save handler dispatches
    `AddAccountMsg::RenderInlineError`, which parks the body in
    `AddDialogState::inline_error`; the `view!` macro `#[watch]`-
    binds `compose_inline_error_body(&model.state).unwrap_or("")` /
    `compose_inline_error_revealed(&model.state)` onto a new
    `inline_error_label` gtk::Label (`error` CSS class) so the
    rejection actually surfaces to the user without mutating
    vault state. Pinned by
    `tests/add_account_logic.rs::compose_inline_error_body_*` /
    `compose_inline_error_revealed_*` plus the existing
    `classify_manual_submit_*` rejection invariants.
  - [x] Render validation warnings inline via
    `paladin_core::format_validation_warning()` without blocking
    creation. The duplicate-collision `adw::AlertDialog` (presented
    by `AddAccountComponent::present_duplicate_alert` and worded by
    `compose_pending_duplicate_alert_body`) embeds the staged
    [`ValidationWarning`]s beneath the duplicate-confirm body
    through `format_duplicate_alert_body` →
    `format_pending_warnings_body` → `format_validation_warning`,
    so the warnings render alongside the "add anyway" prompt that
    consumes them — and they never block creation, since the
    confirm response forwards through to the normal Submit
    pipeline. Pinned by
    `tests/add_account_logic.rs::format_duplicate_alert_body_threads_through_pending_warnings_projection`,
    `format_pending_warnings_body_threads_through_format_validation_warning`,
    and the
    `compose_pending_duplicate_alert_body_with_staged_pending_returns_formatted_body`
    invariant that asserts the alert body equals
    `format_duplicate_alert_body(existing, warnings)`.
  - [x] On successful validation, call
    `Vault::find_duplicate(&validated)` and reject inline with the
    existing account; offer the "add anyway" confirmation that
    consumes the pending `ValidatedAccount` on the duplicate-allowed
    path (CLI parity with `--allow-duplicate`).
    `compose_save_click_outcome` (L630) calls
    `vault.find_duplicate(&validated)` synchronously before the
    mutation worker spawns; a collision routes to
    `SaveClickOutcome::AwaitConfirmation` and through
    `save_click_outcome_to_msg` into
    `AddAccountMsg::StagePendingDuplicate`, parking the pending
    [`ValidatedAccount`] in `AddSecretState::pending` and the
    colliding `AccountSummary` in
    `AddDialogState::pending_duplicate_existing`. The widget's
    `update()` post-routing branch captures
    `was_stage_pending = matches!(msg, StagePendingDuplicate { .. })`
    *before* `apply_msg` consumes the message and then consults
    `should_present_duplicate_alert(was_stage_pending, &state)` —
    which guards on
    `AddDialogState::has_pending_duplicate_for_alert` — to call
    `present_duplicate_alert(&sender)`. The
    `adw::AlertDialog` (heading
    `format_duplicate_alert_heading()` = `"Add anyway?"`, body
    `compose_pending_duplicate_alert_body`, buttons
    `format_duplicate_alert_confirm_label()` = `"Add anyway"` and
    `format_duplicate_alert_cancel_label()` = `"Cancel"`) routes
    the suggested-action confirm response to
    `AddAccountMsg::ConfirmAddAnyway` (which `consume_pending`s
    the validated account and emits `AddAccountOutput::Submit`)
    and the default cancel response — including Escape /
    outside-click via `set_close_response` — to the new
    `AddAccountMsg::DismissDuplicateAlert` arm, which calls
    `AddSecretState::drop_pending` (a fresh sibling of
    `consume_pending` that drains the pending without wiping the
    manual / URI shadow buffers, so the user can edit the
    colliding field and retry) plus clears
    `pending_duplicate_existing`, all *without* emitting
    `AddAccountOutput::Cancel` so the parent
    `AddAccountComponent` stays open. Pinned by
    `tests/add_account_logic.rs::compose_save_click_outcome_manual_await_confirmation_on_duplicate`,
    `compose_save_click_outcome_uri_path_await_confirmation_on_duplicate`,
    `should_present_duplicate_alert_fires_after_stage_pending_with_existing`,
    `should_present_duplicate_alert_does_not_fire_on_other_messages`,
    `should_present_duplicate_alert_does_not_fire_when_state_has_no_pending`,
    `has_pending_duplicate_for_alert_true_after_stage_pending`,
    `has_pending_duplicate_for_alert_false_after_confirm_add_anyway`,
    `has_pending_duplicate_for_alert_false_after_dismiss_duplicate_alert`,
    `apply_msg_dismiss_duplicate_alert_drains_pending_validated_account`,
    `apply_msg_dismiss_duplicate_alert_emits_no_output`,
    `apply_msg_dismiss_duplicate_alert_preserves_manual_draft_state`,
    `apply_msg_dismiss_duplicate_alert_with_no_pending_is_noop`,
    plus the existing
    `apply_msg_stage_pending_duplicate_*` /
    `apply_msg_confirm_add_anyway_*` invariants over the
    state-staging and consumption side of the round trip.
  - [x] Run successful manual additions inside
    `Vault::mutate_and_save`; handle `save_not_committed` rollback
    (the just-inserted account is removed) and
    `save_durability_unconfirmed` keep-with-warning per §"Effect
    errors". `AppModel::update`'s `AddAccountOutput::Submit` arm
    spawns `run_add_worker` on `gio::spawn_blocking`; the worker's
    `vault.mutate_and_save(&store, |v| { v.add(account); Ok(()) })`
    closure routes `Ok(())` as `AddWorkerEffect::Success` and the
    typed failures through `classify_add_post_effect_error` into
    `AddPostEffectOutcome::Inline` (`save_not_committed`,
    defensive `validation_error` / `invalid_state` / `io_error`)
    or `AddPostEffectOutcome::KeepWithWarning`
    (`save_durability_unconfirmed`). The completion message
    threads the typed outcome back to the dialog via
    `AddAccountMsg::WorkerFailed`, which parks it in
    `AddDialogState::worker_outcome`. The `view!` macro
    `#[watch]`-binds `compose_post_effect_inline_error_body`
    / `_revealed` onto a `post_effect_inline_error_label`
    (`error` CSS class) and `compose_post_effect_warning_body`
    / `_revealed` onto a `post_effect_warning_label` (`warning`
    CSS class) so the typed body actually surfaces to the user
    on both branches; the two labels are mutually exclusive so
    a single worker outcome never stacks them. Pinned by
    `tests/add_account_logic.rs::run_add_worker_save_failure_routes_inline_and_returns_pair`,
    `classify_add_post_effect_error_save_durability_unconfirmed_keeps_success_with_warning`,
    `compose_post_effect_inline_error_body_*` /
    `compose_post_effect_inline_error_revealed_*`,
    `compose_post_effect_warning_body_*` /
    `compose_post_effect_warning_revealed_*`, and the new
    cross-cutting mutual-exclusion invariants
    `compose_post_effect_inline_error_and_warning_revealed_are_mutually_exclusive_on_inline_outcome`,
    `compose_post_effect_inline_error_and_warning_revealed_are_mutually_exclusive_on_keep_with_warning_outcome`,
    and `compose_post_effect_inline_error_and_warning_revealed_both_false_when_no_outcome`.
  - [x] Zeroize the manual Base32 secret entry buffer on submit /
    cancel / dialog close / auto-lock and when the user switches
    away from the manual stack page.
    `AddSecretState::manual_secret` stores the
    `AddAccountMsg::ManualSecretChanged` shadow in a Paladin-owned
    `SecretEntry` (a `Zeroizing<String>` whose bytes wipe on drop /
    `take` / `set`), and `apply_msg` drains it through
    `AddSecretState::clear_for(ClearReason::Submit | Cancel | Close)`
    on the corresponding arms plus `AddSecretState::switch_path`
    on `SwitchPath` away from the manual page. Auto-lock routes
    through the shared dialog-drop path so the dialog's secret
    state drops alongside the live `(Vault, Store)` pair when
    `IdlePolicy::is_expired` fires. Pinned by
    `tests/add_account_logic.rs::apply_msg_manual_secret_changed_shadows_into_secret_state`,
    `apply_msg_cancel_wipes_secret_state_buffers`,
    `apply_msg_close_wipes_secret_state_buffers`,
    `apply_msg_submit_proceed_wipes_secret_state_buffers`,
    `apply_msg_switch_path_to_uri_flips_active_path_and_emits_no_output`,
    `apply_msg_switch_path_same_path_is_idempotent_noop`, plus
    `tests/secret_fields_logic.rs::*` for the `SecretEntry`
    zeroize invariants and
    `tests/add_account_logic.rs::inline_error_does_not_echo_manual_secret_text`
    for the §"Secret entry handling" redaction contract.
- [x] Add-via-`otpauth://`-URI paste path in `AddAccountComponent`,
  decoded via `paladin_core::parse_otpauth` and sharing the manual
  duplicate / validation paths.
  - [x] Add a URI `AdwEntryRow` for the `otpauth://` string on its
    dedicated stack page. The `AddAccountComponent`'s `view!` macro
    now mounts an `adw::PreferencesGroup` on the
    `AdwViewStack`'s "URI" page that wraps a single `adw::EntryRow`
    (`#[name = "uri_text_row"]`) whose `set_title` reads
    `format_uri_text_title()` (the existing `"otpauth:// URI"`
    helper) and whose `#[watch] set_text:` binding reads
    `compose_uri_text_value(&model.state)` so programmatic clears
    flush the visible entry text. The keystroke `connect_changed`
    signal dispatches `AddAccountMsg::UriTextChanged(entry.text())`
    so the typed bytes shadow into
    `AddSecretState::uri_text` — the same Paladin-owned
    `SecretEntry` that drains on cancel / switch / close / submit /
    auto-lock per the §"Secret entry handling" contract. Pinned by
    `tests/add_account_logic.rs::compose_uri_text_value_fresh_dialog_returns_empty`,
    `compose_uri_text_value_after_uri_text_changed_reflects_new_value`,
    `compose_uri_text_value_replaces_prior_shadow`,
    `compose_uri_text_value_returns_empty_after_cancel_clears_secret_state`,
    and `compose_uri_text_value_returns_empty_after_switch_path_away_from_uri`,
    on top of the existing
    `format_uri_text_title_returns_otpauth_uri` /
    `apply_msg_uri_text_changed_shadows_into_secret_state` /
    `apply_msg_uri_text_changed_replaces_prior_shadow` siblings.
  - [x] On submit, call `paladin_core::parse_otpauth` synchronously
    on the main thread (no I/O); surface parse failures inline
    without echoing the URI text. `compose_submit_outcome`
    dispatches to `compose_uri_submit_outcome` when the active path
    is `AddPath::Uri`; the helper threads
    `state.secret_state().uri_text.text()` through
    `paladin_core::parse_otpauth` synchronously
    (`tests/otpauth_uri_paste_logic.rs::classify_uri_submit_signature_takes_borrowed_str_so_caller_retains_buffer`
    pins the borrowed-`&str` signature so the call cannot escape
    the GTK main loop into a worker). Parse failures route as
    `UriSubmitOutcome::InlineError(InlineError { kind, rendered })`
    and surface through the shared `compose_save_click_outcome`
    pipeline → `AddAccountMsg::RenderInlineError` →
    `AddDialogState::inline_error`, which the `view!` macro
    `#[watch]`-binds onto the `inline_error_label`. Pinned by
    `tests/otpauth_uri_paste_logic.rs::classify_uri_submit_malformed_uri_rejects_inline`,
    `classify_uri_submit_unsupported_scheme_rejects_inline`,
    `inline_error_does_not_echo_uri_label_or_issuer`,
    `inline_error_does_not_echo_uri_secret_text`,
    `inline_error_does_not_echo_full_uri_text`,
    `classify_uri_submit_outcome_carries_only_validated_account_or_inline_error`,
    plus the
    `tests/add_account_logic.rs::compose_uri_submit_outcome_*` /
    `compose_inline_error_body_*` invariants that pin the
    dispatch and projection layers.
  - [x] Route the resulting `ValidatedAccount` through the same
    duplicate-detection / "add anyway" / `Vault::mutate_and_save`
    insertion path the manual form already uses. The
    `compose_save_click_outcome` pipeline routes the URI sub-path's
    `UriSubmitOutcome::Proceed(validated)` through the unified
    `SubmitOutcome::Proceed` arm — identical to the manual sub-
    path's surface — so `Vault::find_duplicate(&validated)` and the
    duplicate-confirm `AdwAlertDialog` consume the URI-derived
    `ValidatedAccount` from the same
    `AddSecretState::pending` slot the manual flow uses. Pinned by
    `tests/add_account_logic.rs::compose_save_click_outcome_uri_path_await_confirmation_on_duplicate`,
    `proceed_validated_account_threads_through_add_secret_state_pending`,
    and the existing `apply_msg_stage_pending_duplicate_*` /
    `apply_msg_confirm_add_anyway_*` siblings (the `mutate_and_save`
    worker and `classify_add_post_effect_error` routing are shared
    with the manual path so the URI sub-path inherits the
    `save_not_committed` rollback and
    `save_durability_unconfirmed` keep-with-warning behavior
    without per-sub-path branching).
  - [x] Clear the URI entry buffer (and any pending duplicate-add
    state) when the user switches stack pages, on submit, on cancel,
    on dialog close, and on auto-lock; never carry the URI in
    `AppMsg` or `AppOutput`. `AddSecretState::uri_text` is a
    Paladin-owned `SecretEntry` whose bytes wipe on drop /
    `take` / `set`; `apply_msg` drains it through
    `AddSecretState::clear_for(ClearReason::Submit | Cancel |
    Close)` on the corresponding arms and through
    `AddSecretState::switch_path` on `SwitchPath` away from the URI
    page, and auto-lock routes through the shared dialog-drop path.
    The `view!` macro's `#[watch] set_text:
    compose_uri_text_value(&model.state)` flushes the cleared
    buffer back to the visible entry. The §8 source guardrail in
    `tests/secret_message_boundaries.rs` keeps URI text out of the
    `AppMsg` / `AppOutput` long-lived types. Pinned by
    `tests/add_account_logic.rs::apply_msg_cancel_wipes_secret_state_buffers`,
    `apply_msg_close_wipes_secret_state_buffers`,
    `apply_msg_submit_proceed_wipes_secret_state_buffers`,
    `apply_msg_switch_path_to_uri_flips_active_path_and_emits_no_output`,
    plus the new
    `compose_uri_text_value_returns_empty_after_cancel_clears_secret_state` /
    `compose_uri_text_value_returns_empty_after_switch_path_away_from_uri`
    siblings, alongside `tests/secret_fields_logic.rs::*` for the
    `SecretEntry` zeroize invariants.
- [x] `AddAccountComponent` QR clipboard image path (`gdk::Clipboard`
  texture read → `paladin_core::import::qr_image_bytes` with
  `ImportConflict::Skip`). The live `AppMsg::AddAccountAction(
  AddAccountOutput::RequestScanClipboard)` arm now drives
  `gdk::Clipboard::read_texture_async` whose callback runs the four-
  step preflight pipeline (`load_clipboard_qr_capture`:
  no-image gate → `classify_layout_preflight` → `gdk::TextureDownloader`
  with `clipboard_qr_memory_format()` → `compose_qr_decode_outcome` +
  `classify_qr_outcome`) and posts the typed
  `Result<Vec<ValidatedAccount>, QrPreflightError>` back as the new
  `AppMsg::QrClipboardLoaded` variant. The wake-up handler routes
  through the new pure-logic `route_qr_clipboard_loaded` projection:
  `InlineError` arms emit `AddAccountMsg::RenderInlineError` to the
  still-mounted dialog without mutating vault state; `SpawnWorker`
  arms run the mirror of the manual / URI Save-click dispatch
  (`compose_qr_worker_input` + `apply_submit_add_inplace` +
  `gio::spawn_blocking run_qr_worker` → `AppMsg::QrWorkerCompleted`).
  Routing decisions pinned by
  `tests/add_account_logic.rs::route_qr_clipboard_loaded_*`.
  - [x] Mount the QR-clipboard action on the `AdwViewStack`'s "Scan
    clipboard" page; on activation, read a `gdk::Texture` from the
    GDK clipboard. The `AddAccountComponent`'s `view!` macro now
    mounts a page-local `gtk::Button` (`#[name = "scan_clipboard_button"]`,
    `"suggested-action"` CSS class) inside the Qr stack page's
    `gtk::Box`, with `set_label: format_scan_clipboard_button_label()`
    (`"Scan clipboard"`), `#[watch] set_sensitive:
    compose_scan_clipboard_button_sensitive(&model.state)`, and a
    `connect_clicked` handler that dispatches
    `AddAccountMsg::ScanClipboardClicked`. The `apply_msg` arm for
    that variant is currently a state-side no-op (initial-stage
    landing — parity with the `WorkerFailed` staged rollout); the
    `AppModel`-side handler that reads `gdk::Display::default()
    .clipboard()`, runs `gdk::TextureDownloader` (next sub-item), and
    dispatches the QR worker (subsequent sub-items) lands in
    follow-up commits. Pinned by
    `tests/add_account_logic.rs::format_scan_clipboard_button_label_is_non_empty`,
    `format_scan_clipboard_button_label_returns_scan_clipboard`,
    `compose_scan_clipboard_button_sensitive_active_on_qr_path_when_idle`,
    `compose_scan_clipboard_button_sensitive_inactive_on_manual_path`,
    `compose_scan_clipboard_button_sensitive_inactive_on_uri_path`,
    `compose_scan_clipboard_button_sensitive_inactive_when_busy`,
    `apply_msg_scan_clipboard_clicked_emits_no_output_in_initial_stage`,
    `apply_msg_scan_clipboard_clicked_preserves_active_path`, and
    `apply_msg_scan_clipboard_clicked_does_not_disturb_manual_or_uri_buffers`.
  - [x] Allocate an exact `width * height * 4` straight
    (non-premultiplied) RGBA8 buffer with overflow-checked
    multiplication; reject sizes above
    `paladin_core::QR_RGBA_MAX_BYTES` before allocation / download.
    `crate::qr_clipboard::prepare_rgba_layout` runs the
    overflow-checked multiplications (`u32 -> usize` widening +
    `checked_mul(height) -> checked_mul(4)`) and rejects oversized
    inputs with `QrLayoutError::ImageTooLarge` *before* any heap
    allocation; the validated `RgbaLayout` is then materialized via
    the new `crate::qr_clipboard::allocate_rgba_buffer(&RgbaLayout)
    -> Vec<u8>` helper, which returns a zero-initialized
    `Vec<u8>` of exactly `layout.buffer_bytes()` bytes — the
    destination for `gdk::TextureDownloader::download_into(...)` in
    the next sub-item. The helper signature takes `&RgbaLayout`
    rather than raw `(width, height)` so a caller cannot bypass
    the gate by handing in unvalidated dimensions; zero-init
    protects against a partial download leaking prior heap bytes
    into the QR decode buffer. Pinned by
    `tests/qr_clipboard_logic.rs::allocate_rgba_buffer_takes_validated_layout_so_callers_cannot_bypass_size_gate`,
    `allocate_rgba_buffer_returns_vec_with_length_matching_buffer_bytes`,
    `allocate_rgba_buffer_returns_vec_with_length_width_times_height_times_four`,
    `allocate_rgba_buffer_returns_vec_with_length_row_stride_times_height`,
    `allocate_rgba_buffer_is_zero_initialized`,
    `allocate_rgba_buffer_zero_initialization_extends_across_full_capacity`,
    `allocate_rgba_buffer_capacity_at_least_matches_length`, and
    `allocate_rgba_buffer_at_qr_rgba_max_bytes_succeeds`, on top of
    the existing `prepare_rgba_layout_*` rejection invariants.
  - [x] Download the texture via a `gdk::TextureDownloader` set to
    `gdk::MemoryFormat::R8g8b8a8` with row stride `width * 4` (the
    default `Texture::download` yields premultiplied pixels the QR
    decoder cannot consume).
    The format selection is exposed as the pure-logic helper
    `crate::qr_clipboard::clipboard_qr_memory_format() ->
    gdk::MemoryFormat`, returning `gdk::MemoryFormat::R8g8b8a8` so
    the live `AppModel`-side `gdk::TextureDownloader::set_format(...)`
    call reads the constant from one place rather than scattering
    the literal across the dispatch site. After the GDK
    `download_bytes(&self) -> (glib::Bytes, usize)` round trip,
    the defensive `crate::qr_clipboard::verify_download_layout(
    layout, downloaded_bytes, downloaded_stride) -> Result<(),
    DownloadMismatch>` helper compares GDK's returned byte length
    and row stride against the validated `RgbaLayout` — GDK is
    allowed to return a larger-than-asked stride (alignment
    padding) or buffer length, but the `rqrr` decoder upstream
    requires `width * 4` row stride exactly, so any drift is a
    hard reject that the dispatch projects into a typed inline
    error before `decode_clipboard_qr` sees the bytes. Pinned by
    `tests/qr_clipboard_logic.rs::clipboard_qr_memory_format_returns_straight_r8g8b8a8`,
    `clipboard_qr_memory_format_is_not_premultiplied`,
    `clipboard_qr_memory_format_signature_takes_no_arguments`,
    `verify_download_layout_accepts_matching_length_and_stride`,
    `verify_download_layout_rejects_short_buffer`,
    `verify_download_layout_rejects_long_buffer`,
    `verify_download_layout_rejects_mismatched_stride`,
    `verify_download_layout_signature_takes_layout_len_and_stride`,
    and `download_mismatch_display_does_not_echo_secret_bytes`.
    The live `AppModel`-side TextureDownloader wiring lands
    alongside the `gdk::Clipboard::read_texture_async` round trip
    in the subsequent sub-item (L2684), which reads the texture,
    runs the validated download against `clipboard_qr_memory_format()`,
    and dispatches `run_qr_worker` through the existing
    `compose_qr_worker_input` boundary.
  - [x] Pass width, height, bytes, and `import_time` into
    `paladin_core::import::qr_image_bytes`; the call returns
    `Vec<ValidatedAccount>` regardless of QR count.
    The new pure-logic helper
    `crate::qr_clipboard::compose_qr_decode_outcome(layout,
    downloaded_bytes, downloaded_stride, import_time) ->
    QrDecodeOutcome` ties the post-download `verify_download_layout`
    check to the `decode_clipboard_qr` call (which itself forwards
    `layout.width()`, `layout.height()`, the buffer, and
    `import_time` into `paladin_core::import::qr_image_bytes`) so
    the live `AppModel` clipboard-QR handler cannot bypass the
    stride / length gate before reaching the `rqrr`-backed decoder.
    The three outcome variants — `Decoded(Vec<ValidatedAccount>)`,
    `DownloadMismatch(DownloadMismatch)`, and
    `DecodeError(PaladinError)` — feed the inline-error / worker-
    dispatch routing that lands in the next sub-items. Pinned by
    `tests/qr_clipboard_logic.rs::compose_qr_decode_outcome_signature_takes_layout_bytes_stride_and_import_time`,
    `compose_qr_decode_outcome_returns_download_mismatch_when_stride_disagrees`,
    `compose_qr_decode_outcome_returns_download_mismatch_when_buffer_too_short`,
    `compose_qr_decode_outcome_returns_download_mismatch_when_buffer_too_long`,
    `compose_qr_decode_outcome_returns_decode_error_for_blank_buffer`,
    `compose_qr_decode_outcome_runs_verify_before_decode_for_short_buffer`,
    `compose_qr_decode_outcome_forwards_import_time_to_qr_image_bytes`,
    and
    `compose_qr_decode_outcome_decoded_carries_empty_vec_only_under_unreachable_path`,
    on top of the existing `decode_clipboard_qr_*` and
    `verify_download_layout_*` pins.
  - [x] Insert the returned accounts through
    `Vault::import_accounts(accounts, ImportConflict::Skip,
    import_time)` inside `Vault::mutate_and_save`; report
    imported / skipped / warning counts inline (parity with §6).
    `crate::add_account::run_qr_worker` runs the
    `vault.mutate_and_save(&store, |v|
    v.import_accounts(accounts, ImportConflict::Skip, import_time))`
    closure (the policy constant comes from
    `crate::qr_clipboard::CLIPBOARD_QR_CONFLICT_POLICY` so the
    worker cannot drift off `Skip`) and bundles the outcome into a
    `QrWorkerCompletion`. The new `AppMsg::QrWorkerCompleted` arm
    in `AppModel::update` reinstalls the live `(Vault, Store)` pair
    via the shared `apply_add_vault_install_inplace`, then drives
    the four `compose_qr_dispatch` decisions in a single shot:
    `apply_qr_dispatch_inplace` releases the
    `UnlockedBusy → Unlocked` busy gate, the bundled
    `AddAccountMsg::QrSuccess(QrImportSummary::from_report(report))`
    is forwarded to the still-mounted Add dialog (parked on
    `AddDialogState::qr_success_counts` and rendered by the
    `compose_qr_counts_panel_*` projections — imported / skipped /
    warning labels), `drop_dialog == false` keeps the counts panel
    visible, and `refresh_list == true` re-projects rows so the
    newly merged accounts surface in the visible list. Pinned by
    `tests/add_account_logic.rs::run_qr_worker_plaintext_import_succeeds_and_returns_live_pair_with_report`,
    `run_qr_worker_persists_imported_accounts_to_disk`,
    `run_qr_worker_skip_policy_skips_duplicate_with_same_secret_issuer_label`,
    `run_qr_worker_empty_input_returns_success_with_zero_counts`,
    `run_qr_worker_propagates_validation_warnings_through_report`,
    the
    `compose_qr_counts_panel_*` invariants, and the new
    `tests/app_state_logic.rs::apply_qr_dispatch_inplace_*` /
    `qr_pipeline_success_returns_to_unlocked_with_imported_account_and_keeps_dialog_mounted`
    composition-order pin.
  - [x] Handle `save_not_committed` by restoring the
    `Vault::mutate_and_save` snapshot and keeping the Add dialog open
    with the inline error; handle `save_durability_unconfirmed` by
    keeping the imported accounts visible and surfacing the warning on
    the counts panel.
    The rollback / durability-unconfirmed semantics live in
    `Vault::mutate_and_save` itself (DESIGN.md §4.3); the QR worker
    forwards the typed outcome through
    `classify_add_post_effect_error` into
    `QrWorkerEffect::Failure(AddPostEffectOutcome)`, and
    `compose_qr_dispatch` routes the two branches:
    `Inline` → `drop_dialog: false`, `refresh_list: false`,
    `dialog_msg: Some(WorkerFailed(Inline))` (dialog stays mounted,
    inline error renders, list keeps the rolled-back snapshot);
    `KeepWithWarning` → `drop_dialog: false`, `refresh_list: true`,
    `dialog_msg: Some(WorkerFailed(KeepWithWarning))` (dialog stays
    mounted, the durability warning renders via
    `post_effect_warning_label` against the body where the counts
    panel would sit, and the list re-projects so the newly merged
    accounts surface). The `apply_msg(WorkerFailed)` arm drains any
    prior `qr_success_counts` so a stale post-success panel from an
    earlier scan does not co-exist with the freshly rendered inline
    error or durability warning; the typed outcome is parked on
    `worker_outcome` so the existing `post_effect_inline_error_label` /
    `post_effect_warning_label` projections drive the body text.
    Pinned by
    `tests/add_account_logic.rs::apply_msg_worker_failed_inline_clears_prior_qr_success_counts`,
    `apply_msg_worker_failed_keep_with_warning_clears_prior_qr_success_counts`
    (dialog-side clearing invariant) and
    `tests/app_state_logic.rs::qr_pipeline_failure_keeps_pair_installed_and_returns_to_unlocked_with_inline_dialog_msg`,
    `qr_pipeline_failure_keep_with_warning_keeps_pair_installed_refreshes_list_and_keeps_dialog_mounted`
    (full QR worker → dispatch → app-state pipeline pins for both
    failure branches), on top of the existing
    `compose_qr_dispatch_failure_inline_keeps_dialog_mounted_no_refresh`,
    `compose_qr_dispatch_failure_keep_with_warning_refreshes_and_keeps_mounted`,
    `apply_msg_worker_failed_emits_no_output_and_stores_outcome`, and
    `apply_msg_worker_failed_keep_with_warning_stores_outcome`
    invariants.
  - [x] Surface no-image, image-decode failure, zero-decoded-QRs,
    and invalid-payload errors inline in the Add dialog; never
    mutate vault state on failure.
    The pure-logic chain is the new typed
    `crate::qr_clipboard::QrPreflightError` enum (four variants:
    `NoClipboardImage`, `LayoutRejected(QrLayoutError)`,
    `DownloadMismatch(DownloadMismatch)`, `Decode(PaladinError)`)
    plus the `classify_qr_outcome(QrDecodeOutcome) ->
    Result<Vec<ValidatedAccount>, QrPreflightError>` classifier
    that handles the post-download verify + decode + empty-batch-
    defense path (steps 3-5 of the clipboard-QR pipeline); the
    `NoClipboardImage` / `LayoutRejected` variants are constructed
    directly by the `AppModel`-side clipboard handler for steps
    1-2. `QrPreflightError::kind()` threads the stable §5
    `ErrorKind` through to the dialog: `NoClipboardImage` →
    `InvalidState`; `LayoutRejected` / `DownloadMismatch` →
    `InvalidPayload`; `Decode(PaladinError)` → the underlying
    `PaladinError::kind()` (`NoEntriesToImport` for zero decoded
    QRs, `ValidationError` for invalid payload, etc.). The
    `crate::add_account::InlineError::from_qr_preflight_error`
    converter feeds the projection into the existing
    `AddAccountMsg::RenderInlineError` arm so the dialog body
    surfaces the typed error via the shared
    `compose_inline_error_body` / `compose_inline_error_revealed`
    projections — same render path the manual / URI Save-click
    rejections use — and the vault is never mutated because the
    failure runs before the `Vault::mutate_and_save(|v|
    v.import_accounts(...))` worker is dispatched. The live GDK
    clipboard texture read / download / decode wiring on
    `AppModel::update` lands in a follow-up commit (initial-stage
    parity with the other QR sub-items L2651-L2798); the pure-
    logic helpers and routing decisions are pinned by
    `tests/qr_clipboard_logic.rs::qr_preflight_error_no_clipboard_image_kind_is_invalid_state`,
    `qr_preflight_error_layout_rejected_kind_is_invalid_payload`,
    `qr_preflight_error_download_mismatch_kind_is_invalid_payload`,
    `qr_preflight_error_decode_no_entries_kind_is_no_entries_to_import`,
    `qr_preflight_error_decode_validation_error_kind_is_validation_error`,
    `qr_preflight_error_no_clipboard_image_display_is_non_empty_and_does_not_panic`,
    `qr_preflight_error_layout_rejected_display_includes_underlying_qr_layout_error_body`,
    `qr_preflight_error_download_mismatch_display_includes_underlying_download_mismatch_body`,
    `qr_preflight_error_decode_display_includes_underlying_paladin_error_body`,
    `qr_preflight_error_display_does_not_echo_secret_bytes`,
    `qr_preflight_error_implements_std_error`,
    `classify_qr_outcome_decoded_non_empty_returns_ok_accounts`,
    `classify_qr_outcome_decoded_empty_returns_zero_decoded_qrs`,
    `classify_qr_outcome_download_mismatch_returns_preflight_error`,
    `classify_qr_outcome_decode_error_returns_preflight_decode_variant`,
    `classify_qr_outcome_routes_validation_error_through_decode_variant`,
    and
    `tests/add_account_logic.rs::inline_error_from_qr_preflight_no_clipboard_image_uses_invalid_state_kind`,
    `inline_error_from_qr_preflight_layout_rejected_uses_invalid_payload_kind`,
    `inline_error_from_qr_preflight_download_mismatch_uses_invalid_payload_kind`,
    `inline_error_from_qr_preflight_decode_no_entries_uses_no_entries_to_import_kind`,
    `inline_error_from_qr_preflight_decode_validation_error_uses_validation_error_kind`,
    `inline_error_from_qr_preflight_decode_uses_underlying_paladin_error_display_body`,
    `inline_error_from_qr_preflight_no_image_body_mentions_clipboard_or_image`,
    `apply_msg_qr_preflight_failure_routes_through_render_inline_error_arm`,
    and
    `apply_msg_qr_preflight_failure_renders_through_compose_inline_error_body`.
- [ ] `ImportDialogComponent` full implementation (file picker,
  format selector, on-conflict selector, passphrase prompt routing,
  merge call, error display).
  - [x] Pick the source file via `gtk::FileDialog` (the GTK 4.10+
    replacement for the deprecated `gtk::FileChooserNative`).
  - [x] Add a format selector (auto-detect / explicit `otpauth` /
    `aegis` / `paladin` / `qr`) and an on-conflict selector
    (`skip` / `replace` / `append`).
  - [x] Before any Paladin-bundle passphrase prompt, call
    `paladin_core::classify_paladin_import_precheck(path,
    forced_format)` and act on the returned variant:
    `PromptForPassphrase` prompts inside the dialog, `Reject(err)`
    surfaces the exact core error inline without prompting, and
    `NoPrompt` continues through `paladin_core::import::from_file`.
  - [x] Clear the bundle-passphrase row when the source path or
    forced format changes after entry, and restart the probe /
    prompt flow.
  - [x] Run the selected `paladin_core::import::from_file` call,
    the `Vault::import_accounts(accounts, conflict, import_time)`
    merge, and the surrounding `Vault::mutate_and_save` as one
    serialized `gio::spawn_blocking` worker (encrypted-Paladin runs
    Argon2id; keep it off the main loop).
  - [x] On success, refresh `AccountListComponent` from the returned
    vault and keep the dialog on a post-success counts panel until the
    user dismisses it.
  - [x] Surface post-merge counts (`imported` / `skipped` /
    `replaced` / `appended` / `warnings`) inline on the success panel.
  - [x] Handle `save_not_committed` by restoring the
    `Vault::mutate_and_save` snapshot and keeping the dialog open
    with the inline error; handle `save_durability_unconfirmed` by
    keeping the merged accounts and surfacing the warning inline.
  - [x] Surface importer errors inline without closing the dialog
    or mutating vault state: `unsupported_import_format`,
    `unsupported_plaintext_vault`, `unsupported_encrypted_aegis`,
    `unsupported_aegis_entry_type`, `validation_error`,
    `no_entries_to_import`, `decrypt_failed`, `invalid_header`,
    `invalid_payload`, `unsupported_format_version`,
    `kdf_params_out_of_bounds`, `io_error`.
  - [x] Zeroize the bundle-passphrase widget buffer on submit /
    cancel / dialog close / auto-lock.
- [ ] `ExportDialogComponent` full implementation (format selector,
  destination picker, overwrite gate, plaintext warning,
  twice-confirm passphrase, `write_secret_file_atomic` call).
  - [ ] Add a format selector (plaintext `otpauth://` JSON list or
    encrypted Paladin bundle) and pick the destination via
    `gtk::FileDialog`.
  - [ ] Reject overwriting an existing file unless the user
    confirms an inline overwrite gate (parity with CLI `--force`);
    resolve the overwrite gate before accepting any
    encrypted-bundle passphrase rows.
  - [ ] Render `paladin_core::format_plaintext_export_warning()`
    verbatim on the plaintext path and require explicit
    confirmation before the write proceeds.
  - [ ] Reset overwrite and plaintext-warning confirmations when
    the destination or format changes; clear the passphrase rows
    and re-prompt when the destination or format changes after
    passphrase entry.
  - [ ] Prompt twice for the encrypted-bundle passphrase; reject
    mismatch with `invalid_passphrase`
    (`reason: "confirmation_mismatch"`) and zero-length with
    `invalid_passphrase` (`reason: "zero_length"`) inline.
  - [ ] Dispatch the write on `gio::spawn_blocking` (encrypted
    bundle to keep the fresh-AEAD-key derivation off the main loop;
    plaintext for symmetry since `write_secret_file_atomic` chains
    multiple `fsync`s); the write goes through
    `paladin_core::write_secret_file_atomic`.
  - [ ] On success, close the dialog and surface the written path
    via `AdwToast` on the main toast overlay.
  - [ ] Surface writer errors (`io_error`, `save_not_committed`,
    `save_durability_unconfirmed`, `invalid_passphrase`) and the
    refused overwrite gate inline; export does not mutate the
    vault, so there is no rollback path.
  - [ ] Zeroize the encrypted-bundle passphrase widget buffers on
    submit / cancel / dialog close / auto-lock.
- [ ] `PassphraseDialogComponent` full implementation (`set` /
  `change` / `remove` sub-flows, gating, validation, error
  handling).
  - [ ] Add the three sub-flow entry points (`set` / `change` /
    `remove`) and gate the available sub-flow against
    `Vault::is_encrypted()`: `set` only when the getter returns
    `false`; `change` and `remove` only when it returns `true`.
  - [ ] Render `set` / `change` with twice-confirmed
    `AdwPasswordEntryRow` entries; mismatch returns inline with
    `invalid_passphrase` (`reason: "confirmation_mismatch"`).
  - [ ] Reject zero-length new passphrases on `set` / `change`
    inline with `invalid_passphrase` (`reason: "zero_length"`).
  - [ ] Render `remove` with
    `paladin_core::format_plaintext_storage_warning()` verbatim and
    require explicit confirmation before mutation.
  - [ ] Clear all passphrase rows and any pending
    plaintext-removal confirmation when the user switches
    sub-flows.
  - [ ] Dispatch the chosen transition on `gio::spawn_blocking` so
    the §4.5 KDF runs off the main loop; surface a spinner / busy
    affordance while the join is pending.
  - [ ] Surface `save_not_committed` and
    `save_durability_unconfirmed` inline (DESIGN §4.5 owns the
    in-memory mode / key rollback / replacement); the dialog stays
    open on both failure classes.
  - [ ] On success, update the visible vault-mode flag before
    closing the dialog, post a status / toast confirmation, and re-ask
    `IdlePolicy::should_arm` so the auto-lock timer state tracks the
    new on-disk mode.
  - [ ] Zeroize all passphrase widget buffers on submit / cancel /
    dialog close / auto-lock.
- [ ] `SettingsComponent` full implementation
  (`AdwPreferencesDialog` with toggles and spinners; live-apply
  through `Vault::mutate_and_save`).
  - [ ] Render the surface as an `AdwPreferencesDialog` with one
    `AdwPreferencesGroup` for auto-lock and one for
    clipboard-clear; do not use the libadwaita 1.6-deprecated
    `AdwPreferencesWindow`.
  - [ ] Mount toggles as `AdwSwitchRow` and timeouts as
    `AdwSpinRow` inside the matching `AdwPreferencesGroup`.
  - [ ] Clamp the timeout spinners to
    `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
    and
    `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`.
  - [ ] Live-apply each accepted change by invoking the matching
    setter inside `Vault::mutate_and_save`; debounce spinner
    changes 500 ms via `glib::timeout_add_local` so holding +/-
    coalesces to a single save with the most recent buffered value.
  - [ ] Revert the visible widget value on `save_not_committed`
    pre-commit rollback so memory matches disk.
  - [ ] Keep the new value visible on
    `save_durability_unconfirmed` and attach the warning to the
    changed `AdwPreferencesGroup` row.
  - [ ] On successful live-apply, keep the committed value visible
    and post a non-blocking settings-saved `AdwToast` through the
    shared toast overlay.
  - [ ] Re-ask `IdlePolicy::should_arm` after auto-lock toggle or
    timeout changes so the timer state tracks the new policy
    without re-inspecting the file.
- [ ] Header-bar `+` button and primary menu wired with the pinned
  entries (Import…, Export…, Passphrase…, Preferences, About Paladin,
  Quit) per §"libadwaita usage", with Unlocked / `UnlockedBusy` gating
  applied to the mutating entries.
  - [ ] Mount an `AdwHeaderBar` inside the `AdwToolbarView` top slot
    on the unlocked screen.
  - [ ] Add the primary "Add account" `+` button at the start of the
    right side (icon `list-add-symbolic`, tooltip "Add account")
    wired to open `AddAccountComponent`.
  - [ ] Add the search-toggle button bound to
    `gtk::SearchBar::search-mode-enabled` inside
    `AccountListComponent`.
  - [ ] Add the primary `gtk::MenuButton` driven by a `gio::Menu`
    with the fixed entries Import…, Export…, Passphrase…,
    Preferences, About Paladin, Quit.
  - [ ] Wire each menu entry to its target component (`ImportDialog`,
    `ExportDialog`, `PassphraseDialog` with the sub-flow gated by
    `Vault::is_encrypted()`, `SettingsComponent`'s
    `AdwPreferencesDialog`, `AdwAboutDialog`, application quit).
  - [ ] Disable the `+` button and the Import / Export / Passphrase /
    Preferences entries whenever `AppModel` is not `Unlocked`
    (Missing / Locked / StartupError) and while `UnlockedBusy` is
    active; keep About and Quit enabled in every state.
- [ ] About dialog (`AdwAboutDialog` wired to the primary menu's
  "About Paladin" entry, metadata sourced from Cargo package fields
  embedded at compile time).
  - [ ] Mount `AdwAboutDialog` behind the primary menu's "About
    Paladin" entry; pull `application-name`, `version`,
    `developers`, `website`, and `issue-tracker` from Cargo package
    metadata via `env!` / `option_env!` so the strings stay in sync
    with the workspace.
  - [ ] Ship the AGPL-3.0-or-later license text in the gresource
    bundle and surface it through
    `AdwAboutDialog::license-type` set to `Custom` with the bundled
    text.
  - [ ] Show the app icon `org.tamx.Paladin.Gui` and link to the
    repository / issue tracker URLs declared in the workspace
    `[workspace.package]` table.
- [ ] Clipboard + auto-lock parity with TUI (opt-in). Use
  `Vault::is_encrypted()` to decide whether to arm the auto-lock
  timer (encrypted only) and to track the visible vault-mode flag
  across passphrase transitions.
  - [ ] Wire `gtk::EventControllerKey` and pointer motion controllers
    at the `AppModel` root so idle events feed
    `paladin_core::policy::auto_lock::IdlePolicy`.
  - [ ] Drive the auto-lock timer via `glib::timeout_add_local`
    against `IdlePolicy::next_deadline` / `is_expired`; arm only
    when `IdlePolicy::should_arm` returns `true` for the current
    `Vault::is_encrypted()` value so plaintext vaults remain
    unarmed via the core decision (not a GUI shortcut).
  - [ ] On expiry, drop `Vault`, switch `AppModel` to `Locked`,
    discard open HOTP reveal windows, the search query, and any
    open dialog, then re-present `UnlockComponent`.
  - [ ] Re-ask `IdlePolicy::should_arm` after every successful
    `PassphraseDialog` transition so arm/disarm tracks the on-disk
    vault mode without re-inspecting the file.
  - [ ] Wire `gdk::Clipboard.read_text` / `set_text` for the copy
    and clear paths inside `clipboard.rs`.
  - [ ] Drive clipboard auto-clear via
    `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`
    at copy time and `should_clear` on wake against the current
    clipboard text (only-if-unchanged); apply mode-agnostically
    (both plaintext and encrypted vaults).
  - [ ] Keep pending copied values in a `Zeroizing<Vec<u8>>` buffer
    and zeroize after clear attempt or stale-token drop.
  - [ ] Preserve clipboard auto-clear timers across lock so a timer
    scheduled before lock still fires only-if-unchanged after lock.
- [ ] Serialized in-flight vault effects: one vault-touching worker at a time,
  mutating controls disabled while busy, and worker results restore
  `(Vault, Store)` before UI state applies success / typed failure handling;
  quit and auto-lock requests are deferred until the worker returns.
  - [ ] Add the `AppState::UnlockedBusy { effect, ui_snapshot }`
    variant and the transition from `Unlocked` whenever a
    vault-touching effect dispatches.
  - [ ] Move `(Vault, Store)` into the worker on
    `gio::spawn_blocking` for HOTP `next`, add / remove / rename /
    import / settings / passphrase / export operations.
  - [ ] Standardize the worker return type as
    `(Vault, Store, EffectOutcome)` on both success and typed
    failure; reinstall the pair before applying the UI outcome.
  - [ ] Disable mutating controls (row `next`, dialog submit buttons,
    passphrase actions, import / export, settings) while
    `UnlockedBusy` is active and surface the spinner / busy
    affordance on the current surface.
  - [ ] Defer quit and window-close requests until the worker
    returns.
  - [ ] On auto-lock expiry during `UnlockedBusy`, record a
    lock-after-effect request; apply it after the worker returns
    only if the returned vault is still encrypted, and discard it
    if the operation changed the vault to plaintext.
  - [ ] Coalesce settings spinner debounce to the latest pre-save
    value when an effect is in flight; refuse toggle changes that
    would overlap an active vault effect until the control is
    re-enabled.
  - [ ] Route workers that fail before returning the pair to
    `StartupErrorComponent` without trying to reconstruct in-memory
    vault state.
- [x] GUI runtime and dependency guardrails.
  - [x] Use GTK / GLib / Relm4 as the GUI event loop and run long work
    through `gio::spawn_blocking`; do not use `tokio` directly from
    `paladin-gtk` source.
  - [x] Keep `tokio` out of `paladin-gtk` direct dependencies; allow
    only the transitive `relm4 → tokio` carve-out captured in
    `deny.toml`.
  - [x] Enforce the source-level runtime/network guard with
    `crates/paladin-gtk/tests/no_tokio_source.rs`.
  - [x] Keep the GUI thinness guard in `tests/thinness.rs` so crypto,
    storage, import/export parsers, QR decoding, path discovery, and
    OTP primitives remain in `paladin-core`.
- [x] Use `paladin_core::account_matches_search` for `search.rs` filtering,
  `paladin_core::format_validation_warning()` for validation-warning
  messages, and `paladin_core::format_plaintext_export_warning()` for the
  `ExportDialog` plaintext path so the GUI never re-implements shared text
  or match-key logic.
- [x] Use `paladin_core::classify_paladin_import_precheck` before any
  encrypted-Paladin-bundle import prompt so the GUI shares the CLI / TUI
  Paladin header decision table.
- [ ] Linux desktop file, AppStream metadata, and icon.
  - [ ] Write `data/org.tamx.Paladin.Gui.desktop` with `Name=Paladin`,
    `Icon=org.tamx.Paladin.Gui`,
    `StartupWMClass=org.tamx.Paladin.Gui`,
    `Categories=Utility;Security;`, security/authenticator
    `Keywords=`, and `Exec=paladin-gtk` (no file/URI placeholders).
  - [ ] Write `data/metainfo/org.tamx.Paladin.Gui.metainfo.xml`
    AppStream metadata with the matching
    `<launchable type="desktop-id">` plus screenshots and release
    notes for v0.2.
  - [ ] Ship the scalable app icon at
    `data/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg` and
    16/24/32/48 PNG fallbacks under
    `data/icons/hicolor/<size>/apps/org.tamx.Paladin.Gui.png`.
  - [ ] Ship the symbolic variant at
    `data/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg`
    when the Adwaita palette warrants it.
  - [ ] Wire `build.rs` + `data/paladin-gtk.gresource.xml` to compile
    the gresource bundle deterministically via
    `glib-compile-resources` (fixed input order).
  - [ ] Add `desktop-file-validate` and the AppStream validator to
    the CI / packaging dry-run so both files are checked on every
    build.
- [ ] `.deb`, `.rpm`, Flatpak, and AppImage artifacts for `paladin-gtk`,
  signed and published per §11.3–§11.6; Flathub submission filed.
  - [ ] Update `crates/paladin-gtk/Cargo.toml` to inherit
    `description` / `repository` / `homepage` / `license` /
    `edition` / `rust-version` from `[workspace.package]` and set
    the binary-specific `keywords` / `categories` locally.
  - [ ] Add `packaging/deb/paladin-gtk.yaml` (`nfpm`) installing
    `/usr/bin/paladin-gtk`, the desktop entry, the AppStream
    metainfo, and the hicolor icon set; declare
    `libgtk-4-1 (>= 4.16)` and `libadwaita-1-0 (>= 1.6)`; no
    maintainer scripts.
  - [ ] Add `packaging/rpm/paladin-gtk.yaml` (`nfpm`) installing the
    same payload with matching `gtk4` / `libadwaita` package names.
  - [ ] Add `packaging/flatpak/paladin-gtk.yml` declaring
    `org.gnome.Platform//47` and the matching SDK, the §11.4 sandbox
    permissions (`xdg-data/paladin:create`,
    `xdg-config/paladin:create`, `--socket=wayland`,
    `--socket=fallback-x11`, `--share=ipc`), no `--share=network`,
    and exporting the metainfo file to `/usr/share/metainfo/`.
  - [ ] Wire AppImage assembly via `linuxdeploy` +
    `linuxdeploy-plugin-gtk` so GTK4 modules, schemas, and pixbuf
    loaders ship inside the bundle; output
    `paladin-gtk-<version>-x86_64.AppImage` with embedded `zsync`
    pointing at GitHub Releases.
  - [ ] Make the build reproducible: vendored deps,
    `cargo build --locked`, `SOURCE_DATE_EPOCH` from the release
    tag, with the gresource bundle and `linuxdeploy` step both
    deterministic.
  - [ ] Sign `.deb`, `.rpm`, and AppImage with `minisign` per §11.6;
    publish the public key + signature alongside each artifact on
    GitHub Releases.
  - [ ] File the Flathub submission and inherit Flatpak signing from
    Flathub.
  - [ ] Add the packaging dry-run job to CI: produces `.deb`,
    `.rpm`, Flatpak, and AppImage artifacts and runs
    `desktop-file-validate` plus the AppStream validator on the
    installed payload.
- [ ] Milestone 7 automated and manual sign-off stays tracked.
  - [x] Manual test plan documented in
    `crates/paladin-gtk/tests/manual/MANUAL_TEST_PLAN.md`, with
    `tests/manual_test_plan_doc.rs` guarding that the file exists and
    carries every required checklist item from this plan.
  - [ ] Execute every manual test-plan item cleanly on both a Wayland
    session and an X11 session before Milestone 7 sign-off.
  - [x] `xvfb-run` headless smoke test is green in CI for launch,
    plaintext unlock-to-list, rendered account rows, missing-vault
    `InitDialog` mount, encrypted-vault `UnlockComponent` mount, and
    corrupt-vault `StartupErrorComponent` mount.
  - [ ] Before checking off any remaining implementation item, add or
    update the matching pure-logic test, smoke-test assertion, or
    manual-test checklist entry named in §"Tests".

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

## GUI runtime carve-out

**No direct `tokio` use, with one transitive-dep carve-out.** GTK's
main loop is the executor; long work runs on `gio::spawn_blocking`
with results delivered back to the main thread via Relm4 messages.
`paladin-gtk` source files therefore must not contain `use tokio`
or `tokio::` references — `tests/no_tokio_source.rs` enforces this
the same way `tests/thinness.rs` enforces the crypto / storage
contract. The crate's own `[dependencies]` must not declare
`tokio` directly either.

The carve-out is the `tokio` package itself reaching `Cargo.lock`
transitively through `relm4` (`relm4 → tokio`), which `relm4` uses
for its mpsc-channel internals — a structured-concurrency
primitive, not a network stack. `cargo deny check` admits this
edge via the `wrappers = ["relm4"]` rule on `tokio` in
`deny.toml`; the lockfile-subtree guard in
`crates/paladin-core/tests/no_network.rs` continues to assert that
no banned dep is reachable from `paladin-core`, `paladin-cli`, or
`paladin-tui`, so the no-network rule remains in force for the
security-sensitive subtree. See DESIGN.md §8 bullet 10 for the
authoritative wording.

No other tokio-adjacent crate (`tokio-util`, `tokio-rustls`, …) is
permitted; only the base `tokio` package, only when reached via
`relm4`. New direct deps of `paladin-gtk` that would pull in a
different async runtime or network stack require a DESIGN.md update
before being added.

The `gio::spawn_blocking` worker contract types
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

- [x] Tests: `tests/thinness.rs` — a source-level guard that scans
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
  `tests/cli_global_args.rs`, `tests/startup_probes.rs`,
  `tests/app_state_logic.rs`, `tests/auto_lock_logic.rs`,
  `tests/clipboard_clear_logic.rs`, `tests/hotp_reveal_logic.rs`,
  `tests/secret_fields_logic.rs`, `tests/startup_error_logic.rs`,
  `tests/qr_clipboard_logic.rs`, `tests/account_list_logic.rs`,
  `tests/account_row_logic.rs`, `tests/init_dialog_logic.rs`,
  `tests/unlock_dialog_logic.rs`, `tests/add_account_logic.rs`,
  `tests/rename_dialog_logic.rs`, `tests/remove_dialog_logic.rs`,
  `tests/otpauth_uri_paste_logic.rs`, `tests/import_dialog_logic.rs`,
  `tests/export_dialog_logic.rs`, `tests/passphrase_dialog_logic.rs`,
  `tests/settings_logic.rs`, `tests/effect_ownership_logic.rs`), the
  `tests/gtk_smoke.rs` smoke-test bullets, the `tests/thinness.rs`
  and `tests/no_tokio_source.rs` source guards, the
  `tests/manual_test_plan_doc.rs` guard, and every step in
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
