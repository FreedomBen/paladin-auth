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
HOTP `next` with reveal window, add account (manual or scan-from-clipboard
image), remove account, import/export, settings (auto-lock +
clipboard-clear), passphrase set/change/remove.

Per §3 / CLAUDE.md: depends only on `paladin-core`. Never reaches into
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
│   ├── metainfo/          # AppStream metadata; Flatpak/native IDs updated with the final §11.4 app ID
│   ├── style.css
│   └── paladin-gtk.desktop
├── src/
│   ├── lib.rs             # re-exports internal modules so integration tests in tests/ can reach them; binary entry stays in main.rs
│   ├── main.rs            # adw::init, register resources, RelmApp::new("io.github.paladin_otp.Gui").run(...) — ID matches the §11.4 Flatpak app ID and the desktop file's StartupWMClass
│   ├── cli.rs             # GlobalArgs (--vault, --no-color); reject --json
│   ├── app/
│   │   ├── mod.rs         # AppModel + AppMsg + AppOutput
│   │   └── state.rs       # AppState variants: Missing / Locked / Unlocked / UnlockedBusy / StartupError
│   ├── components/
│   │   ├── init.rs        # InitDialog — vault creation (incl. create_force clobber confirmation)
│   │   ├── unlock.rs      # UnlockComponent — encrypted vaults only
│   │   ├── startup_error.rs # non-mutating startup/open error view
│   │   ├── account_list.rs    # AccountListComponent (gtk::ListView + factory)
│   │   ├── account_row.rs     # AccountRowComponent (label, code, gauge/next, copy, kebab → rename)
│   │   ├── add_account.rs     # AddAccountComponent (manual fields + otpauth:// URI paste + paste image)
│   │   ├── remove.rs          # RemoveDialog (confirmation gate)
│   │   ├── rename.rs          # RenameDialog (label edit; calls Vault::rename)
│   │   ├── import.rs          # ImportDialog (file picker + format + on-conflict + bundle passphrase)
│   │   ├── export.rs          # ExportDialog (file picker + format + overwrite + encrypted passphrase)
│   │   ├── passphrase.rs      # PassphraseDialog (set / change / remove flows)
│   │   └── settings.rs        # SettingsComponent (toggles + spinners)
│   ├── clipboard.rs       # gdk Clipboard + opt-in "clear if unchanged" wipe
│   ├── auto_lock.rs       # GLib idle/timeout source; encrypted-only; plaintext no-op
│   ├── hotp_reveal.rs     # per-row reveal window using paladin_core::HOTP_REVEAL_SECS
│   ├── icons.rs           # gtk::IconTheme lookup against AccountSummary.icon_hint
│   ├── secret_fields.rs   # extract/clear passphrase + manual-secret entries
│   ├── search.rs          # case-insensitive issuer/label filtering using paladin_core::account_matches_search (parity with CLI / TUI)
│   └── ticker.rs          # 250ms timeout source for TOTP gauge updates
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
  files; `unsafe_permissions` renders
  `paladin_core::format_unsafe_permissions(&err)` verbatim.
- `InitDialog` — only path that creates a vault from the GUI (v0.2;
  parity with DESIGN §6, §7). Two `AdwPasswordEntryRow` passphrase
  fields (twice-confirmed; empty selects plaintext) plus an explicit
  "create vault" confirmation button. The plaintext path renders
  `paladin_core::format_plaintext_storage_warning()` verbatim — the
  same wording `PassphraseDialog`'s remove flow and the CLI / TUI use —
  and the user must tick the confirmation before submission is enabled.
  Encrypted submission rejects empty new entries inline with
  `invalid_passphrase` (`reason: "zero_length"`) and rejects mismatch
  with `reason: "confirmation_mismatch"`. On submit, builds a
  `VaultInit` (`VaultInit::Plaintext` or
  `VaultInit::Encrypted(EncryptionOptions::new(secret))`) and calls
  `paladin_core::create(path, init)` on `gio::spawn_blocking` (the
  encrypted path runs the §4.4 Argon2id KDF). On success, swaps
  `AppModel` to `Unlocked` with the returned
  `(Vault, Store)` and routes to `AccountListComponent`. The dialog
  stays open and surfaces `unsafe_permissions` (rendered via
  `paladin_core::format_unsafe_permissions(&err)`),
  `save_not_committed`, and `save_durability_unconfirmed` inline.
  `vault_exists` (if a vault appeared between `inspect` and `create`)
  opens an in-dialog `AdwMessageDialog` with `destructive-action`
  styling whose body is rendered from
  `paladin_core::format_init_force_warning(existing_path)` so wording
  stays identical to the CLI `init --force` confirmation. On
  confirm, the dialog re-runs the operation with
  `paladin_core::create_force(path, init)` on `gio::spawn_blocking`,
  consuming the pending `VaultInit` created from the already-entered
  passphrase choice; on cancel, the
  destructive dialog closes and `InitDialog` returns to its
  `vault_exists` state without mutating the existing vault.
  `create_force` errors map identically to `create`
  (`save_not_committed` with `backup_path` set when the failure
  follows backup rotation; `save_durability_unconfirmed` after the
  primary rename) and stay inline. Passphrase entries are zeroized on
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
  matches. The CLI's `id:` prefix form is **not** honored by the GUI search
  (parity with the TUI).
- `AccountRowComponent` — label, code, progress (TOTP) / "next" button
  (HOTP), copy button, and a kebab `gtk::MenuButton` whose `gio::Menu`
  exposes "Rename…" (opens `RenameDialog` for that row's account) and
  "Remove…" (opens `RemoveDialog`). HOTP rows hide their code until the user activates
  "next" (advances counter and saves); after the shared
  `paladin_core::HOTP_REVEAL_SECS` reveal window (120 seconds) the code
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
  active path; CLI parity with `add` interactive / `--uri` / `--qr`).
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
  overflow-checked multiplication, and downloads via a
  `gdk::TextureDownloader` set to `gdk::MemoryFormat::R8g8b8a8` with row
  stride `width * 4`. The default `Texture::download` path is avoided
  because it yields premultiplied pixels the QR decoder cannot consume.
  Width, height, bytes, and `import_time` are then passed to
  `paladin_core::import::qr_image_bytes`. Manual fields cover label,
  optional issuer, Base32 secret, algorithm, digits, kind, TOTP period,
  HOTP counter, and the icon-hint mode (`Default from issuer`, `No icon`,
  or explicit slug), matching `paladin_core::AccountInput` and
  `IconHintInput`. UI defaults match the CLI manual-add defaults in DESIGN
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
  `(secret, issuer, label)` triple). Multi-QR imports use a fixed
  `ImportConflict::Skip` and report imported/skipped/warning counts (parity
  with §6). Successful manual, URI, and QR additions run the insertions inside
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
- `ImportDialog` — `gtk::FileChooserNative` for the source file, a format
  selector (auto-detect or explicit `otpauth` / `aegis` / `paladin` /
  `qr`), and an on-conflict selector (`skip` / `replace` / `append`).
  Before any Paladin-bundle passphrase prompt, the GUI mirrors the CLI / TUI
  import probe from DESIGN §5. When the selected format is auto-detect or
  explicit `paladin`, Paladin headers are probed only to decide whether a
  bundle passphrase is needed: encrypted bundles (`mode == 1`) prompt for
  the bundle passphrase inside the dialog, plaintext Paladin vaults
  (`mode == 0`) return `unsupported_plaintext_vault` inline without
  prompting, and malformed Paladin headers fail inline before any passphrase
  prompt. Missing files, non-Paladin content, and probe errors that do not
  identify an encrypted/plaintext Paladin bundle do not consume a passphrase;
  the dialog continues through `paladin_core::import::from_file` so the
  import facade owns `io_error`, `unsupported_import_format`, and any
  format-specific `invalid_header` behavior. The selected
  `paladin_core::import::from_file` call runs on
  `gio::spawn_blocking` (the encrypted-Paladin variant runs Argon2id),
  with results delivered back via Relm4 messages. On success,
  `Vault::import_accounts(accounts, conflict, import_time)` is called with
  the user's policy and the same `import_time` used by `ImportOptions`
  inside `Vault::mutate_and_save`;
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
  encrypted Paladin bundle) and `gtk::FileChooserNative` for the
  destination path. Overwriting an existing file is rejected unless
  the user confirms an inline overwrite gate (parity with CLI
  `--force`). Any overwrite gate is resolved before encrypted-bundle
  passphrase rows are accepted; if the destination or format changes
  after passphrase entry, password rows are cleared and the user is
  re-prompted. Encrypted exports prompt twice for the bundle passphrase
  and reject mismatch (`invalid_passphrase`
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
  returns `true`. Any stale invalid-state error stays in the dialog and does not
  mutate visible state.
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts. Spinners clamp to the §5 minimums
  (`auto_lock.timeout_secs >= 30`, `clipboard.clear_secs >= 5`). Uses
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
state. Two short-lived modal-local exceptions are required for confirmation
round trips: `AddAccountComponent` keeps a duplicate-collision
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
**plaintext-vault auto-lock no-op**. Implemented with GLib timeout sources
(`glib::timeout_add_local`) so they integrate with the GTK main loop.

- Auto-lock: idle timer reset on any input event sourced through
  `gtk::EventControllerKey` / pointer controllers wired at the `AppModel`
  root. On expiry, drop `Vault` and switch `AppModel` to `Locked`,
  re-presenting `UnlockComponent`. Locking discards open HOTP reveal
  windows, the search query, and any open dialog; a clipboard auto-clear
  timer scheduled before lock survives lock and still fires
  only-if-unchanged. For plaintext vaults the timer is never armed; the
  setting still persists for the encrypted-later case.
- Clipboard auto-clear: mode-agnostic — runs in both plaintext and
  encrypted vaults. At copy time, capture `(token, value)`. On wake,
  ignore stale tokens first, then read the current `gdk::Clipboard` text;
  if it equals `value`, clear; otherwise no-op. Pending copied values are
  zeroized after the clear attempt or stale-token drop.

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
- Plaintext → call `paladin_core::open(path, VaultLock::Plaintext)` directly,
  then jump to `AccountListComponent`.
- Encrypted → present `UnlockComponent`. On submit, call
  `paladin_core::open(path, VaultLock::Encrypted(secret))` on
  `gio::spawn_blocking` so the §4.4 Argon2 KDF (m=64 MiB defaults) does not
  block the GTK main loop; the dialog shows a spinner until the join
  completes. Wrong passphrase surfaces inline. `unsafe_permissions` and other
  non-authentication open errors
  (`wrong_vault_lock`, `invalid_header`, `invalid_payload`,
  `unsupported_format_version`, `kdf_params_out_of_bounds`, `io_error`)
  transition to `StartupErrorComponent` with a retry action that re-runs
  vault-path resolution and `inspect`; `unsafe_permissions` renders
  `paladin_core::format_unsafe_permissions(&err)` (§4.7) verbatim so the
  wording matches the CLI and TUI exactly.
- Missing → present `InitDialog`. v0.2 GUI creates vaults in-app on
  explicit user confirmation (DESIGN §6, §7). Plaintext path: empty
  passphrase fields plus the unencrypted-storage warning. Encrypted
  path: twice-confirmed passphrase. Both go through
  `paladin_core::create` on `gio::spawn_blocking`. If `create` returns
  `vault_exists` (a vault appeared between `inspect` and `create`), the
  dialog opens an `AdwMessageDialog` destructive-confirmation gate
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
  encrypted-bundle export (`ExportDialog`) all build
  `EncryptionOptions::new(secret)` with the §4.4 defaults
  (m=64 MiB, t=3, p=1) — no GUI surface exposes
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

- HOTP `next`: pre-commit save failures (`save_not_committed`) leave the
  in-memory counter and reveal state unchanged (per DESIGN §4.2 rollback)
  and surface an inline/status error. Durability-unconfirmed failures
  (`save_durability_unconfirmed`) reveal the new code with its
  `Code.counter_used` label and post an `AdwToast` carrying the
  committed-but-uncertain status — the user has the new code in hand
  even though durability is in question, and the toast is the
  surface that conveys the warning so the row stays usable. All
  other failures show an inline/status error and leave the row hidden.
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
  new state in memory (matching the committed on-disk state) and are
  shown as committed-but-uncertain, matching the core error.
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

- `data/paladin-gtk.desktop` shipped at
  `/usr/share/applications/paladin-gtk.desktop` per §11.3. Sets
  `Name=Paladin`, `Icon=paladin-gtk`, `StartupWMClass=io.github.paladin_otp.Gui`,
  `Categories=Utility;Security;`, and security/authenticator terms in
  `Keywords=`, and uses `Exec=paladin-gtk` with no file/URI placeholders.
  v0.2 does not register a MIME type or URI handler; imports start inside
  `ImportDialog`, matching the global-flag parser contract above. Native
  packages keep the `paladin-gtk.desktop` filename; the Flatpak manifest
  installs desktop and AppStream metadata under the finalized §11.4 app ID
  so Flathub's desktop-ID checks match the application ID.
- App icon at
  `/usr/share/icons/hicolor/scalable/apps/paladin-gtk.svg`. Symbolic
  variant at `…/symbolic/apps/paladin-gtk-symbolic.svg` if the
  Adwaita-style symbolic palette warrants it; a `16`/`24`/`32`/`48`
  PNG fallback set is shipped under
  `/usr/share/icons/hicolor/<size>/apps/` for non-SVG icon
  consumers.
- Adwaita-style CSS in `data/style.css`, scoped via `gtk::CssProvider`.

## Packaging (per §11)

`paladin-gtk` ships in `.deb`, `.rpm`, Flatpak, and AppImage in v0.2
(§11.1). Implementation owes the release pipeline:

- **Cargo.toml metadata.** `crates/paladin-gtk/Cargo.toml` inherits
  `description`, `repository`, `license = "AGPL-3.0-or-later"`,
  `edition`, and `rust-version` from `[workspace.package]` via
  per-field Cargo inheritance (`description.workspace = true`,
  `repository.workspace = true`, and so on; the workspace shape established by
  IMPLEMENTATION_PLAN_01_CORE.md Phase A) so `nfpm` and Flathub
  manifests read one source). It additionally sets the
  binary-specific `homepage`, `keywords`, and `categories` fields
  locally so `nfpm` produces correct Debian / RPM control metadata
  without per-format duplication.
- **`.deb` / `.rpm` (via `nfpm`).** `packaging/deb/paladin-gtk.yaml`
  and `packaging/rpm/paladin-gtk.yaml` install
  `/usr/bin/paladin-gtk`, the desktop entry at
  `/usr/share/applications/`, and the icon set under
  `/usr/share/icons/hicolor/`. Debian declares `libgtk-4-1
  (>= 4.10)` and `libadwaita-1-0 (>= 1.4)`; Fedora declares the
  matching `gtk4` and `libadwaita` package names. No maintainer
  scripts: packages do not create or alter vaults; vault files live under
  `$XDG_DATA_HOME/paladin/` when created by `paladin init` or by the
  GUI's `InitDialog`. The §11
  packaging pipeline validates the
  installed desktop entry with `desktop-file-validate` and verifies the
  hicolor icon install layout; it does not add package-owned
  post-install hooks.
- **Flatpak.** `packaging/flatpak/paladin-gtk.yml` declares
  `org.gnome.Platform//46` (and the matching SDK) — that runtime
  bundles GTK 4.14+ and libadwaita 1.5+, both ahead of the
  packaging baseline. No `--share=network`, and the §11.4 sandbox
  permissions:
  `xdg-data/paladin:create`, `xdg-config/paladin:create`, plus the
  Wayland and X11 fallback clipboard path required for `gdk::Clipboard`
  (`--socket=wayland`, `--socket=fallback-x11`, `--share=ipc`). The
  Flatpak app ID is the §11.4 placeholder `io.github.paladin_otp.Gui`,
  finalized at Flathub-submission time. The same string is passed to
  `RelmApp::new(...)` in `main.rs` and set as `StartupWMClass` in
  `data/paladin-gtk.desktop`, so window-to-launcher mapping works
  identically in both Flatpak and native installs. The manifest exports the
  matching AppStream metainfo file from `data/metainfo/` and validates it
  during the packaging dry-run. `flatpak-builder` consumes the
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

### libadwaita decision (2026-05-05)

Resolved: **adopt `libadwaita` for v0.2.** The runtime declaration in
§11.3 (`libadwaita-1-0 (>= 1.4)`) now matches the build-time crate
dependency in §"Dependencies" below; the GUI uses Adwaita widgets
where the GNOME HIG calls for them (see §"libadwaita usage" below).
No further action needed beyond keeping the build-time and
runtime-declared baselines aligned.

## Tests

The GUI itself is hard to test without a display server. Tests are split:

- **Pure-logic unit tests** (no display): icon resolution **fallback
  decision** (`None`/empty slug → placeholder; failed lookup → placeholder;
  the actual `gtk::IconTheme` lookup is exercised by the smoke test),
  search filtering through `paladin_core::account_matches_search`,
  startup-error routing for default-path / inspect / open failures,
  auto-lock state machine, clipboard "clear if unchanged"
  decision logic plus pending-value zeroization, HOTP reveal window timing
  via `paladin_core::HOTP_REVEAL_SECS` + counter labels,
  secret-field clearing/redaction invariants, QR RGBA
  byte-length/stride preparation,
  init dialog logic (plaintext vs encrypted routing, twice-confirm match
  / zero-length / mismatch handling, plaintext-warning gate,
  `vault_exists` triggering the destructive-confirmation gate that
  routes through `create_force` (with cancellation leaving the
  existing vault intact and zeroizing the pending `VaultInit`), and
  `unsafe_permissions` routing back to inline errors),
  rename dialog logic (label validation, always-call-`mutate_and_save`
  behavior matching the CLI when the new label equals the current one,
  prior-label restore on `save_not_committed`),
  otpauth URI paste logic (parse success → shared duplicate-detection
  with manual mode, parse-error mapping for malformed URIs and
  unsupported types, duplicate "add anyway" consuming a pending
  `ValidatedAccount`, zeroize-on-cancel of the URI entry buffer),
  import format-selector routing + on-conflict policy threading +
  post-merge counts mapping, export overwrite-gate + encrypted
  twice-confirm match logic + export writer error mapping,
  passphrase dialog logic (sub-flow gating against
  `Vault::is_encrypted()`, `set` / `change` twice-confirm match,
  `zero_length` and `confirmation_mismatch` rejections, `remove`
  plaintext-storage warning gate, secret-buffer zeroize on
  submit / cancel / close), settings logic (live-apply path through
  `Vault::mutate_and_save`, spinner clamping at the §5 minimums
  (`auto_lock.timeout_secs >= 30`, `clipboard.clear_secs >= 5`),
  500 ms debounce of repeated spinner changes, and pre-commit
  rollback that reverts the visible widget value on
  `save_not_committed`), in-flight effect ownership (only one
  vault-touching worker at a time, mutating controls disabled while busy,
  quit / window-close deferred while busy, auto-lock expiry deferred until the
  worker returns, `(Vault, Store)` reinstalled before UI outcome handling,
  settings debounce coalescing to the latest pre-save value, and fatal routing
  to `StartupErrorComponent` if a worker cannot return the vault/store pair).
- **Smoke test** in CI under `xvfb-run`: app launches, opens a prepared
  plaintext vault, the list renders. Required for Milestone 7 sign-off.
- **Manual test plan** (`tests/manual/MANUAL_TEST_PLAN.md`) per Milestone 7
  checklist: init plaintext vault (empty passphrase + warning gate); init
  encrypted vault (twice-confirm); init when a vault already exists at
  the path opens the destructive-confirmation gate, confirm runs
  `create_force` and rotates the prior vault to `vault.bin.bak`,
  cancel leaves the prior vault intact; init under the §10
  fault-injection hook surfaces `save_not_committed` and
  `save_durability_unconfirmed` inline; unlock encrypted vault; copy
  TOTP; HOTP next reveals + copies while showing the counter used;
  reveal expires; auto-lock fires; clipboard auto-clear honors
  if-unchanged; add manual; add via `otpauth://` URI paste (success +
  malformed-URI rejection + duplicate "add anyway" round-trip); add
  via clipboard image;
  import each format (otpauth, aegis plaintext, encrypted Paladin bundle,
  QR image file) with each on-conflict policy and verify reported counts; export
  plaintext (warning + confirmation, `0600` output) and encrypted
  Paladin bundle (twice-confirm, round-trip via Import); refused
  overwrite without confirmation; rename an account via the row
  kebab menu (label persists on reopen; renaming to the same label
  still saves and bumps `updated_at`; pre-commit fault injection rolls
  the label back); settings persist;
  passphrase set/change/remove; secret fields clear on cancel, submit,
  and auto-lock; icon theme resolution + fallback.

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
- [ ] Linux desktop file, AppStream metadata, and icon.
- [ ] `.deb`, `.rpm`, Flatpak, and AppImage artifacts for `paladin-gtk`,
  signed and published per §11.3–§11.6; Flathub submission filed.
- [ ] Manual test plan documented.
- [ ] `xvfb-run` headless smoke test green in CI (plaintext vault opens
  and renders the list).

## Dependencies (per §9)

`relm4`, `gtk4` (via `gtk4-rs`), `libadwaita` (via `libadwaita-rs`,
baseline 1.4 to match the §11.3 Debian dep declaration), `glib`,
`gio`, `gdk4`, `clap`, plus `paladin-core`. GDK
clipboard is the canonical Wayland/X11 path; `arboard` is **not** a
hard dependency for v0.2 and is only added if GDK clipboard proves
insufficient during implementation. Build-time tooling includes
`glib-compile-resources` (via the GLib development package or an equivalent
Rust build helper such as `glib-build-tools`) for the gresource bundle and
AppStream validation tooling for the Flatpak/native metadata dry-run.

`libadwaita` is adopted for v0.2 (decision 2026-05-05) so the GUI
follows the GNOME HIG out of the box and the §11.3 packaging
declaration matches the actual binary dependency. `data/style.css`
(scoped via `gtk::CssProvider`) carries only Paladin-specific tweaks
on top of Adwaita defaults — it never tries to recreate the Adwaita
palette.

**No `tokio`.** GTK's main loop is the executor; long work runs on
`gio::spawn_blocking` with results delivered back to the main thread via
Relm4 messages. This relies on `paladin_core::Vault` and
`paladin_core::Store` being `Send` so they can move across thread
boundaries during encrypted `open` / `create` / `create_force` and any
save-bearing dialog operation; the core plan documents `Send` as part
of their public contract.

## libadwaita usage

Components map to Adwaita widgets where the HIG calls for them; the
list below pins the v0.2 choices so the implementation does not drift
back into vanilla GTK4 widgets where Adwaita is idiomatic:

- **Window shell.** `AppModel`'s root is an `AdwApplicationWindow`
  whose content is an `AdwToolbarView`: the top bar holds an
  `AdwHeaderBar`, and the content slot holds the `AdwToastOverlay`
  (see below) wrapping whichever screen is active (`InitDialog` /
  `UnlockComponent` / `StartupErrorComponent` /
  `AccountListComponent`). The header bar carries
  the search-toggle button and a primary menu (`gtk::MenuButton`
  driven by `gio::Menu`). No custom title-bar drawing.
- **Toast surface.** `AppModel` wraps the main content in an
  `AdwToastOverlay`. Transient feedback that does not need a modal —
  copy confirmation, `save_durability_unconfirmed` after a HOTP
  advance, clipboard-clear-fired notice, settings-saved confirmation
  — is delivered via `AdwToast`. Status-line errors that block
  further interaction stay inline in the affected dialog.
- **Confirmation dialogs.** `RemoveDialog`, the plaintext-export
  consent step, and the export overwrite gate are
  `AdwMessageDialog`s with `destructive-action` styling on the
  destructive button. The §6 wording (e.g. the plaintext-export
  "this writes unencrypted secrets to disk" warning) is reused
  verbatim so the UX matches the TUI.
- **Preferences.** `SettingsComponent` renders inside an
  `AdwPreferencesWindow` with one `AdwPreferencesGroup` for
  auto-lock and one for clipboard-clear. Toggles use
  `AdwSwitchRow`; spinners use `AdwSpinRow`.
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
  to the row via `AdwEntryRow::add-css-class("error")` plus a
  status-line label below the row.
- **About / help.** `AdwAboutWindow` is wired to the application
  menu and pulls program metadata from Cargo package metadata embedded
  at compile time; the AGPL-3.0-or-later license text ships in the
  gresource bundle.

GTK-only widgets (`gtk::ListView`, `gtk::SearchEntry`,
`gtk::FileChooserNative`, `gtk::IconTheme`, `gdk::Clipboard`) keep
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
- `xvfb-run` headless smoke test green in CI.
- Manual test plan executes cleanly on a Wayland and an X11 session.
- `.deb`, `.rpm`, Flatpak, and AppImage artifacts build through the
  release pipeline; GitHub-hosted artifacts are signed with `minisign`
  and the Flathub submission is filed.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
- DESIGN.md is kept in sync with implemented GUI-visible behavior; if a
  contradiction surfaces, DESIGN.md is updated first.
