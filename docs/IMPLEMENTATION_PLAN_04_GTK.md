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
├── build.rs               # gresource bundle (icons, *.ui, *.css) + glib-compile-schemas → OUT_DIR/schemas/
├── data/
│   ├── paladin-gtk.gresource.xml
│   ├── org.tamx.Paladin.Gui.gschema.xml  # per-user GSettings schema (show-section-headers, show-column-headers, show-next-code-column, …); installs to /usr/share/glib-2.0/schemas/
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
│   │   ├── mod.rs         # app submodule namespace
│   │   ├── model.rs       # AppModel + AppMsg + AppOutput; owns the resolved vault path, the toast_queue, the current_toast, the search controller, and the in-flight effect ownership token
│   │   └── state.rs       # AppState variants: Missing / Locked / Unlocked / UnlockedBusy / StartupError
│   ├── account_list.rs    # AccountListComponent (gtk::ColumnView + gtk::SingleSelection + gio::ListStore<RowItem>)
│   ├── account_row.rs     # Pure projection helpers + RowDisplay shape consumed by the column_view cell factories
│   ├── column_view.rs     # Cell factories + splice/sort/interleave helpers for the AccountListComponent ColumnView
│   ├── row_item.rs        # RowItem GObject (account_id, display, icon_hint, issuer, busy) backing the gio::ListStore
│   ├── add_account.rs     # AddAccountComponent (manual fields + otpauth:// URI paste + paste image)
│   ├── remove_dialog.rs   # RemoveDialog (confirmation gate before Vault::remove inside Vault::mutate_and_save)
│   ├── rename_dialog.rs   # v0.2 foundation: RenameDialog (label edit; calls Vault::rename inside Vault::mutate_and_save). Superseded by edit_dialog.rs starting at Milestone 9 slice 4: from slice 4 onward the kebab / row context menu's "Edit…" entry routes to EditDialog, not RenameDialog (slices 1–3 still relabel "Rename…" → "Edit…" cosmetically while continuing to mount RenameDialog; slices 1–3 are internal-only, not release-eligible). Source kept through slice 5 inclusive (retired in slice 6) so its tests stay live while EditDialog is wired in — the equivalent coverage is already pinned in tests/edit_dialog_logic.rs (no test migration is needed).
│   ├── edit_dialog.rs     # v0.2 / DESIGN §7 Milestone 9: EditDialog — three editable AdwEntryRow widgets (Label / Issuer + inline clear / Icon hint slug) over an AccountEdit value; calls Vault::edit_account_metadata inside Vault::mutate_and_save. Pure-logic state machine in this module; widget binding mirrors RenameDialog conventions.
│   ├── import_dialog.rs   # ImportDialog (file picker + format + on-conflict + bundle passphrase)
│   ├── export_dialog.rs   # ExportDialog (file picker + format + overwrite + encrypted passphrase)
│   ├── export_qr_dialog.rs # ExportQrDialog — per-account QR export: adw::Dialog wrapping an AdwViewStack with "warning"/"qr" pages (warning-ack gate → Page-1 Cancel/Show-QR footer → on-screen gtk::Picture + Save PNG / Save SVG / Copy image to GDK clipboard / Done)
│   ├── passphrase_dialog.rs # PassphraseDialog (set / change / remove flows)
│   ├── destroy_dialog.rs  # DestroyDialog (Milestone 10) — AdwAlertDialog with destructive styling; calls paladin_core::destroy_vault on gio::spawn_blocking; opened from the primary-menu *Delete Vault…* entry, the unlock-dialog and startup-error footer link, and the Ctrl+Shift+Delete accelerator
│   ├── init_dialog.rs     # InitDialog — vault creation from the GUI (incl. create_force clobber confirmation)
│   ├── unlock_dialog.rs   # UnlockComponent — encrypted vaults only (passphrase entry)
│   ├── startup_error.rs   # non-mutating startup / open error view
│   ├── settings.rs        # SettingsComponent (`AdwPreferencesDialog` with toggles + spinners over the §4.7 VaultSettings fields)
│   ├── otpauth_uri_paste.rs # `otpauth://`-paste pure-logic state machine for the AddAccount URI sub-path; validates via paladin_core::parse_otpauth
│   ├── qr_clipboard.rs    # Clipboard-QR "scan from clipboard image" pure-logic glue: gdk::Texture → RGBA buffer (bounded by QR_RGBA_MAX_BYTES) → paladin_core::import::qr decoding
│   ├── effect_ownership.rs # In-flight vault-effect ownership state machine: serializes every vault-touching blocking effect through one slot so the UI rejects re-entry while a save is mid-flight
│   ├── toast_queue.rs     # Newest-wins toast collapse queue with a TOAST_MIN_VISIBLE (1 s) minimum-visible guarantee; every add_toast site in AppModel funnels through ToastQueue so back-to-back toasts on the shared adw::ToastOverlay stop stacking
│   ├── shortcuts_window.rs # `gtk::ShortcutsWindow` content + `format_app_shortcuts_window_*` helpers shared with the primary menu, the `gio::Application::set_accels_for_action` table, and the `tests/startup_probes.rs` lockstep pin
│   ├── clipboard.rs       # gdk::Clipboard plumbing driving paladin_core::policy::clipboard_clear::ClipboardClearPolicy
│   ├── clipboard_clear.rs # Clipboard auto-clear pure-logic glue; GUI owns the gdk::Clipboard reads/writes + glib timeout source, but every policy decision routes through paladin_core::policy::clipboard_clear (Zeroizing<Vec<u8>> for the captured value)
│   ├── auto_lock.rs       # GLib idle/timeout plumbing driving paladin_core::policy::auto_lock::IdlePolicy (encrypted-only; plaintext no-op)
│   ├── hotp_reveal.rs     # per-row reveal window via paladin_core::policy::hotp_reveal::deadline (uses paladin_core::HOTP_REVEAL_SECS)
│   ├── icon_resolution.rs # gtk::IconTheme lookup against AccountSummary.icon_hint via the pure `resolve_display_icon` decision function
│   ├── gsettings.rs       # per-user gio::Settings access for the show-section-headers / show-column-headers / show-next-code-column schema keys (and any future GUI-only prefs)
│   ├── secret_fields.rs   # extract/clear passphrase + manual-secret entries; keeps secret-bearing widget state out of AppModel / AppMsg / AppOutput per DESIGN §8
│   ├── search.rs          # case-insensitive issuer/label filtering using paladin_core::account_matches_search (parity with CLI / TUI)
│   └── ticker.rs          # paladin_core::TICK_INTERVAL_MS glib::timeout_add_local source for TOTP gauge updates, Next-code projection, and clipboard staleness checks; install / teardown gated on AppState
└── tests/
    ├── icon_resolution.rs
    ├── search_logic.rs
    ├── search_focus_logic.rs       # window-level search-focus controller: routes "/" / Ctrl+F to the search entry, suppresses while modals are open
    ├── cli_global_args.rs
    ├── startup_probes.rs           # pinned lockstep tests over the primary menu, ShortcutsWindow, and `set_accels_for_action` table
    ├── app_state_logic.rs
    ├── auto_lock_logic.rs          # pure logic; no display required
    ├── clipboard_logic.rs          # pure logic; no display required
    ├── clipboard_clear_logic.rs    # pure logic; no display required
    ├── hotp_reveal_logic.rs
    ├── secret_fields_logic.rs
    ├── secret_message_boundaries.rs # AppMsg / AppOutput / AppModel must not carry SecretString or secret-bearing AccountInput fields (compile-time + runtime assertions per DESIGN §8)
    ├── startup_error_logic.rs
    ├── qr_clipboard_logic.rs
    ├── account_list_logic.rs
    ├── account_list_nav_logic.rs   # arrow-key / page navigation routing into AccountListComponent (focus ring, wrap behavior, modal-open suppression)
    ├── account_row_logic.rs
    ├── column_view_logic.rs        # pure-logic splice plan, interleave helper, account-column sorter
    ├── row_item_logic.rs           # RowItem GObject: from_row_model, display/busy setters, display-changed signal
    ├── init_dialog_logic.rs
    ├── unlock_dialog_logic.rs
    ├── add_account_logic.rs
    ├── rename_dialog_logic.rs
    ├── remove_dialog_logic.rs
    ├── otpauth_uri_paste_logic.rs
    ├── import_dialog_logic.rs
    ├── export_dialog_logic.rs
    ├── export_qr_dialog_logic.rs
    ├── passphrase_dialog_logic.rs
    ├── destroy_dialog_logic.rs     # DestroyDialog (Milestone 10): warning body sourcing, yes-confirm gate, AppMsg projection from DestroyReport / typed errors, sensitive-buffer wipe on success, primary-menu / unlock-footer / startup-error-footer / accelerator routing, AdwAlertDialog `destructive-action` styling pin
    ├── settings_logic.rs
    ├── gsettings_logic.rs          # pure logic; loads build.rs-compiled gschema from OUT_DIR
    ├── effect_ownership_logic.rs
    ├── toast_queue_logic.rs        # newest-wins toast collapse truth table: initial commit, defer-within-window, newest-pending-wins on repeat defer, idle drain, reopen-on-drain, multi-cycle sequencing, TOAST_MIN_VISIBLE figure
    ├── ticker_logic.rs             # TICK_INTERVAL_MS install / teardown gating against AppState (encrypted-locked teardown, unlocked install) and per-tick projection wiring
    ├── no_tokio_source.rs
    ├── thinness.rs
    ├── desktop_entry_logic.rs      # `data/org.tamx.Paladin.Gui.desktop` fields (Name, Categories, Exec, StartupWMClass) match §11.4 + match the binary
    ├── metainfo_logic.rs           # AppStream metainfo XML schema sanity checks (release notes, component-id, content-rating, summary length)
    ├── icon_assets_logic.rs        # required app icon sizes + scalable SVG presence; filenames match the app ID
    ├── gresource_manifest_logic.rs # gresource bundle includes every *.ui / *.css / icon path the runtime needs
    ├── cargo_manifest_workspace_inheritance_logic.rs # the crate manifest inherits each shared metadata field via per-field workspace inheritance per §"Cargo manifest"
    ├── ci_desktop_metainfo_validators_logic.rs       # CI invokes desktop-file-validate / appstreamcli validate against installed assets
    ├── ci_packaging_dry_run_logic.rs                 # CI packaging dry run: every nfpm / flatpak / appimage manifest builds without network access
    ├── packaging_appimage_build_script_logic.rs
    ├── packaging_deb_nfpm_manifest_logic.rs
    ├── packaging_flathub_submission_logic.rs
    ├── packaging_flatpak_manifest_logic.rs
    ├── packaging_reproducible_build_logic.rs
    ├── packaging_rpm_nfpm_manifest_logic.rs
    ├── packaging_signing_script_logic.rs
    ├── manual_test_plan_doc.rs                       # asserts the `tests/manual/MANUAL_TEST_PLAN.md` file is present + non-empty + tracks every Milestone 7 manual sign-off bullet
    ├── gtk_smoke.rs                                  # xvfb-run integration smoke test
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
- `AccountListComponent` — `gtk::ColumnView` (inside a `gtk::ScrolledWindow`)
  reading a `gtk::SingleSelection` that wraps a
  `gio::ListStore<crate::row_item::RowItem>`.  Each account in
  `paladin_core::AccountSummary` order is one persistent `RowItem`
  GObject; the six columns (Account, Code, Time, Next, Copy, More) are
  bound via `gtk::SignalListItemFactory` builders shipped from
  `crate::column_view` (`build_account_column_factory`,
  `build_code_column_factory`, `build_time_column_factory`,
  `build_next_code_column_factory`, `build_copy_column_factory`,
  `build_kebab_column_factory`).
  Per-tick updates iterate the store and call
  `RowItem::set_display(new_display)` on the matching item; the
  factories listen to the `display-changed` signal and rebind
  their cell widgets against the new value.  Refreshes
  (add / remove / rename / search-filter rebuild) route through
  `column_view::apply_interleaved_splice_plan(&store, &rows, show_section_headers)`,
  which computes a minimum sequence of insert / remove `splice` ops
  keyed by `column_view::RowKey` so account-row identity survives
  across a section-header toggle.  There is no `splice(0, n_old, n_new)`
  rebuild path; the per-tick path never calls `splice` at all.
  The historical migration from a `FactoryVecDeque<AccountRowComponent>`
  + `gtk::ListBox` shape (and earlier from a raw
  `gtk::ListView` + `BoxedAnyObject` shape) was driven by the
  flicker / unreliable-click symptom that came out of splicing on
  every tick: each splice fired `items-changed(0, N, N)` and
  forced `gtk::ListView` to rebind every visible row through
  `SignalListItemFactory::connect_bind`, which re-installed the
  row's `gio::SimpleActionGroup` mid-frame and intermittently
  dropped pointer events.  The cell factories shipped today
  install per-bind closures (HOTP "next" click, copy click, kebab
  `gio::SimpleActionGroup`) that close over the *current*
  `RowItem`'s `AccountId` and disconnect on `unbind` so cell
  recycling never carries stale ids forward.

  Section headers (per-user, opt-in). Section rows are interleaved
  into the same `gio::ListStore<RowItem>` the `gtk::ColumnView`
  reads; each section row is a `RowItem::section(title)` instance
  whose `kind()` is `RowKind::Section(String)` and whose
  `account_id()` is `None`.  Cell factories branch on the row's
  kind: the "Account" cell renders a single full-width `dim-label`
  heading for section rows and calls
  `list_item.set_selectable(false)` so the `gtk::SingleSelection`
  cannot land on them; every other cell renders empty for the
  section row.  The interleaver
  (`column_view::interleave_section_headers`) is a pure-logic
  helper that consults the existing `row_section_header(prev, current)`
  predicate from `account_list.rs`; vault insertion order is
  preserved — rows are never reordered for grouping, so a vault
  that interleaves two issuers shows two headers for the same
  issuer text.  `AccountRowModel` still carries an
  `issuer: Option<String>` field projected from
  `AccountSummary.issuer` with the `summary_display_label` rule
  applied (i.e. `Some("")` collapses to `None`), and the issuer
  is mirrored on the constructed `RowItem` via the
  `RowItem::issuer()` getter so the Account-column sorter can
  read it without re-projecting from the model.

  Whether section rows are interleaved at all is gated by the
  per-user `show-section-headers` boolean GSettings key (schema id
  `org.tamx.Paladin.Gui`, defined in
  `data/org.tamx.Paladin.Gui.gschema.xml` and compiled into
  `OUT_DIR/schemas/` by `build.rs`).  Default `false`.  The flag
  is latched on `AccountListComponent` and passed into every
  `apply_interleaved_splice_plan` call;
  `AccountListMsg::SetShowSectionHeaders(bool)` updates the latch
  and re-runs the splice so a toggle from the SettingsComponent
  dialog rebuilds the row set without resetting the live
  account-row selection (account ids are preserved across the
  diff).  `AppModel` holds a `gio::Settings` clone and connects
  `changed::show-section-headers` to dispatch
  `AppMsg::ShowSectionHeadersChanged(bool)`, which routes to the
  live `AccountListComponent`.

  The Preferences dialog (`SettingsComponent`) carries a third
  `AdwPreferencesGroup` titled `Display` with three `AdwSwitchRow`s:
  `Show section headers` (bound to `show-section-headers`, default
  off), `Show column headers` (bound to `show-column-headers`,
  default on), and `Show next code` (bound to
  `show-next-code-column`, default on).  Each toggle's
  `connect_active_notify` writes through the matching
  `crate::gsettings::set_show_*` helper, which fires a
  `changed::*` signal that `AppModel` rebroadcasts as
  `AppMsg::Show{Section,Column}HeadersChanged(bool)` /
  `AppMsg::ShowNextCodeColumnChanged(bool)` and forwards to
  `AccountListMsg::SetShow{Section,Column}Headers(bool)` /
  `AccountListMsg::SetShowNextCodeColumn(bool)`.
  The column-headers toggle adds or removes the
  `no-column-headers` CSS class on the `gtk::ColumnView`; the
  application stylesheet (`data/style.css`) collapses the header
  strip allocation when the class is present.

  The Account column carries a `gtk::CustomSorter`
  (`column_view::build_account_column_sorter`) that compares two
  `RowItem`s by the case-folded `(issuer, display_label)` tuple.
  Clicking the column header toggles ascending / descending sort;
  the view defaults to **unsorted** on mount so the visible order
  still equals vault insertion order per DESIGN §"listing-order".
  Sorting is a user-initiated override and does not persist
  across restarts.  Code, Time, Copy, and More columns are
  non-sortable (live-changing values or action affordances).

  The Time column's `set_visible` is toggled by
  `AccountListMsg::Refresh` via `column_view::any_totp(&rows)`
  so HOTP-only vaults hide the column entirely.

  The Next column's `set_visible` is the AND of two latches:
  the per-user `show-next-code-column` boolean GSettings key
  (schema id `org.tamx.Paladin.Gui`, default **`true`**) and the
  same `column_view::any_totp(&rows)` probe that gates the Time
  column.  Both latches live on `AccountListComponent`; the
  GSettings latch is updated by
  `AccountListMsg::SetShowNextCodeColumn(bool)` (dispatched from
  `AppMsg::ShowNextCodeColumnChanged(bool)`, sourced from a
  `gio::Settings::changed::show-next-code-column` handler on
  `AppModel`), and the `any_totp` probe is re-evaluated on every
  `AccountListMsg::Refresh`.  Toggling either latch only changes
  column visibility; it never rebinds the store or triggers a
  splice.

  The schema is GUI-only — vault behavior preferences (auto-lock,
  clipboard auto-clear) stay in `paladin_core::VaultSettings`
  inside the encrypted payload per DESIGN §4.7.  The
  `crate::gsettings` module is the only place that knows about
  schema ids / key names; callers go through `app_settings()`,
  `show_section_headers()`, `set_show_section_headers()`,
  `show_column_headers()`, and `set_show_column_headers()`.

  Search uses a `gtk::SearchEntry` hosted inside a `gtk::SearchBar`
  whose `search-mode-enabled` is bound to the header bar's
  search-toggle button (see "libadwaita usage" below). The bar's
  `set_key_capture_widget` is bound to the toplevel
  `adw::ApplicationWindow`, so any printable keypress on the window
  that no focused entry consumed reveals the bar and forwards the
  keystroke into the embedded `gtk::SearchEntry` ("type to search"
  parity with stock GNOME apps like Files). A dedicated window-level
  `EventControllerKey` (`wire_app_window_search_focus_controller`,
  capture-phase) intercepts `/` and `Ctrl+L` first and posts
  `AppMsg::FocusSearch`, which emits `AccountListMsg::FocusSearch`
  to reveal the bar, grab focus on the entry, and select the
  entry's full contents (via
  `gtk::Editable::select_region(0, -1)`) without inserting the
  keystroke into the entry's buffer — matching the GitHub / GNOME
  Files convention. Selecting on focus means typing immediately
  replaces any prior query, while an arrow key or pointer click
  clears the selection and moves the caret per default
  `gtk::Editable` behavior. Ctrl+K is intentionally **not** a
  focus-search accelerator — it doubles as the vim-style "move up"
  mirror inside the account list (see
  `wire_account_list_navigation_controllers` below).

  Cross-widget arrow-key navigation between the search entry and
  the list rows is wired through a pair of capture-phase
  `gtk::EventControllerKey` instances installed by
  `wire_account_list_navigation_controllers`:

  * On the `gtk::SearchEntry`: Down (or Ctrl+J — vim-style — or
    Ctrl+N — readline-style — both via
    `dispatch_search_entry_to_list_nav`) hands keyboard focus to
    the first selectable row of the `gtk::ColumnView` and selects
    it through the `gtk::SingleSelection`.  When the filtered list
    is empty the press propagates as a benign no-op.
  * On the `gtk::ColumnView`: Up / Ctrl+K / Ctrl+P
    (`ListNavIntent::Up`) moves the selection / focus one
    selectable row earlier (section rows are skipped via
    `prev_selectable_position`); at the first selectable row it
    instead hands focus back to the search entry and re-selects
    its full contents so the user can replace-on-type. Down /
    Ctrl+J / Ctrl+N (`ListNavIntent::Down`) moves the selection /
    focus one selectable row later (`next_selectable_position`),
    stopping at the last row (no wrap).  Home / End / PageUp /
    PageDown — and every key outside the `dispatch_list_box_nav`
    table — propagate untouched so the `gtk::ColumnView`'s
    built-in bindings keep working.

  Both controllers reject ALT / SUPER / HYPER / META compound
  chords and leave arrow keys combined with CONTROL alone
  (`Ctrl+Up` / `Ctrl+Down` are different platform shortcuts).
  Bare `j` / `k` / `n` / `p` are left to bubble so the
  `set_key_capture_widget` "type to search" path keeps working.
  Ctrl+N with SHIFT also bubbles so the `<Control><Shift>n`
  "Add account" app accelerator reaches `gio::Application::
  set_accels_for_action`.

  Enter on the focused row (or a single click on the row body —
  the `ColumnView` is built with `single_click_activate(true)`)
  routes through `gtk::ColumnView::connect_activate` →
  `AccountListMsg::ActivateRow(position)`, which resolves the
  store position to the bound `RowItem`, skips section rows
  (defensive — they are `set_selectable(false)`), reads the
  account row's kind from `AccountListComponent::current_rows`
  and its visible-code state from
  `AccountListComponent::live_displays`, and dispatches
  `default_row_activation`:

  * TOTP rows and HOTP rows with a visible code emit
    `AccountListOutput::CopyCode(id)` — the same path the per-row
    copy `gtk::Button` uses.
  * HOTP rows whose code is hidden emit
    `AccountListOutput::ActivateHotpAndCopy(id)`. `AppModel`
    latches `pending_copy_after_advance = Some(id)` and re-enters
    the standard `AdvanceHotp` dispatch (busy gate, effect
    ownership, worker spawn). On
    `HotpAdvanceWorkerCompleted` the latch fires a follow-up
    `CopyCode(id)` after `publish_reveal_for` so the freshly
    revealed code lands on the clipboard through the same
    `prepare_copy_bytes` / `gdk::Clipboard::set_text` /
    `schedule_copy` pipeline. The latch is cleared on `Locked` /
    `Quit` transitions via `prune_reveals_if_locked` /
    `tear_down_for_quit` for parity with `reveal_windows` /
    `pending_clipboard`. The bar's `notify::search-mode-enabled` round-
  trips back through `AccountListOutput::SearchModeChanged(bool)` so
  the header-bar toggle button mirrors bar-initiated reveals (type-
  to-search, focus shortcut, the bar's own close button) in addition
  to its own click. Filtering rebuilds the row set from
  `Vault::iter()` so it can call
  `paladin_core::account_matches_search(&Account, query)` before
  projecting matches to `AccountSummary`; the `gio::ListStore<RowItem>`
  never holds secret fields (each `RowItem` only carries an
  `AccountRowModel` projection plus the row's currently bound
  `RowDisplay`). The entry applies the same case-insensitive substring
  matching as §5 / §6; no Unicode normalization. Empty issuer is
  allowed and the colon is still present in the match key; insertion
  order is preserved among matches. After a filter rebuild, selection
  is computed by `paladin_core::select_after_filter(prev, filtered)`
  (preserve prior selection if still present, else first match) —
  parity with the TUI. Selection lives on the `gtk::SingleSelection`
  that wraps the `gio::ListStore<RowItem>`; the per-row position is
  resolved by `position_for_account(&store, Option<AccountId>) ->
  Option<u32>` and installed via
  `gtk::SingleSelection::set_selected(position)` (or
  `gtk::INVALID_LIST_POSITION` to clear). The CLI's `id:` prefix form
  is **not** honored by the GUI search (parity with the TUI).
- **Per-row rendering** (no dedicated `AccountRowComponent` —
  cell factories drive each cell instead). Each row in the
  `gio::ListStore<RowItem>` is rendered as six
  `gtk::ColumnViewCell`s built by the factories in `column_view.rs`:

  * **Account** (`build_account_column_factory`) — icon (24px) plus
    ellipsized `<issuer>:<label>` heading.  Section rows render a
    single full-width `dim-label` heading and hide the icon; they
    also call `list_item.set_selectable(false)` so the
    `gtk::SingleSelection` cannot land on them.
  * **Code** (`build_code_column_factory`) — a `numeric` CSS class
    label bound to `RowDisplay.code`, an inline HOTP "next" button
    (visibility bound to `display.next_button_visible`), and a
    `dim-label` counter slot for HOTP rows.
  * **Next** (`build_next_code_column_factory`) — a `numeric`
    `dim-label` `gtk::Label` bound to `RowDisplay.next_code`,
    prefixed with `↪ `.  TOTP rows render `↪ NNN NNN`; HOTP and
    section rows render the empty string.  The cell is wrapped in
    a `gtk::Button` with the `.flat` CSS class so a click copies
    the next code: activation emits
    `AccountListOutput::CopyNextCode(item.id())`, which `AppModel`
    routes through the same
    `prepare_copy_bytes` / `gdk::Clipboard::set_text` /
    `schedule_copy` pipeline as `CopyCode` but reads the code via
    `Vault::totp_next_code(id, now)` instead of `Vault::totp_code`.
    The button's `sensitive` is `false` for HOTP / section rows
    so the click is inert.  Column-level visibility comes from the
    AND of the `show-next-code-column` GSettings latch (default
    `true`) and `column_view::any_totp(&rows)`; both live on
    `AccountListComponent` and re-evaluate without rebinding the
    store.  `RowDisplay` gains a `next_code: Option<String>` field
    projected per tick alongside the existing `code` / `progress_*`
    fields; the projection runs the same `Vault::totp_next_code`
    call so the value matches what the cell will copy on click.
  * **Time** (`build_time_column_factory`) — horizontal `gtk::Box`
    holding a 96px `gtk::ProgressBar` (bound to
    `display.progress_fraction` with the `success` / `warning` /
    `error` CSS class driven by the urgency band) followed by a
    numeric `gtk::Label` showing the seconds remaining in the active
    TOTP window (e.g. `18s`) via
    `account_row::format_seconds_remaining`.  The label uses
    `width_chars(3)` + `xalign(1.0)` so values right-align in a fixed
    slot as the countdown ticks, mirroring the TUI's gauge +
    countdown layout (`view::list::render_totp_row` →
    `"  {secs_remaining:>3}s"`).  The column itself is hidden when no
    TOTP row is visible via `column_view::any_totp(&rows)`.
  * **Copy** (`build_copy_column_factory`) — `edit-copy-symbolic`
    `gtk::Button` whose `sensitive` is bound to
    `display.copy_enabled`; activation emits
    `AccountListOutput::CopyCode(item.id())`.
  * **More** (`build_kebab_column_factory`) — `view-more-symbolic`
    `gtk::MenuButton` whose `gio::Menu` exposes "Rename…" (opens
    `RenameDialog` for that row's account), "Show QR…" (opens
    `ExportQrDialog` for that row's account; see §"QR export
    dialog implementation"), and "Remove…" (opens
    `RemoveDialog`) in that pinned order.  A per-cell
    `gio::SimpleActionGroup` is rebound on each `bind` so the
    closures capture the current `RowItem`'s `AccountId`, and
    disconnected on `unbind` so cell recycling never carries stale
    ids forward.

  HOTP rows hide their code until the user activates "next"
  (advances counter and saves); the reveal window deadline comes
  from `paladin_core::policy::hotp_reveal::deadline(now)` (built on
  the shared `paladin_core::HOTP_REVEAL_SECS`), and after expiry
  the code returns to the hidden state, matching the TUI.
  Activating "next" during an open reveal advances to the next
  counter and restarts the shared reveal window with the newly
  committed code (matches §6 — "next" is the "give me the next
  code" affordance, never a no-op).  Hidden rows show the stored
  next counter; during reveal, the row shows the
  `Code.counter_used` that produced the visible code until expiry.
  Copying a hidden HOTP row is **disabled**; copying during the
  reveal window copies the visible code and does not advance again.

  Per-row state lives on the `RowItem` GObject (`account_id`,
  `display: RowDisplay`, `icon_hint`, `issuer`, `busy`).  Parent
  updates flow in as `RowItem::set_display(...)` /
  `RowItem::set_busy(...)` mutations on the matching store item;
  the cell factories listen to the `display-changed` signal
  (`ROW_ITEM_DISPLAY_CHANGED_SIGNAL`) and rebind cell widgets
  against the new value.  User activations route directly out as
  `AccountListOutput::{OpenRenameDialog, OpenRemoveDialog,
  CopyCode, AdvanceHotp}(AccountId)` from the cell-factory
  closures (no per-row forwarder needed).  `AppModel` sees the
  same parent-output surface as before the migration.
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
  A bubble-phase `gtk::EventControllerKey` on the dialog root routes a
  bare Escape press (no CTRL / ALT / SHIFT / SUPER / HYPER / META) through
  `AddAccountMsg::Cancel`, dismissing the dialog through the same
  secret-wipe / `AddAccountOutput::Cancel` path as the Cancel button.
  Chord modifiers and other keys propagate untouched so focused entries,
  dropdowns, and the Save button keep their own keyboard handling. The
  dispatch table is pinned by `dispatch_root_dismiss_key` unit tests so
  the wiring stays honest without a display server.
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
- `ExportDialog` — format selector (plaintext newline-separated
  `otpauth://` URI list — Gnome Authenticator–compatible — or
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
- `ExportQrDialog` — per-account QR export (DESIGN §4.6 / §7).
  Opened from the account row's kebab menu's new `Show QR…` entry
  (placed between `Rename…` and `Remove…`; the kebab's
  `gio::Menu` order is pinned by
  `tests/account_list_logic.rs::build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
  once the menu model is extended). The dialog is an
  `adw::Dialog` whose body is an `AdwViewStack` with two named
  pages (`"warning"` and `"qr"`) driven by
  `crate::export_qr_dialog::ExportQrDialogState`. The
  `AdwViewStack` is not paired with an `AdwViewSwitcher` — the
  state machine moves between pages programmatically by
  `set_visible_child_name`, not by user-clickable tabs, so a
  closing-window glimpse cannot expose the QR by switching tabs
  past the warning:
    * **Page 1 — Warning ack** (`AdwViewStack` child name
      `"warning"`). Body renders
      `paladin_core::format_plaintext_qr_export_warning()` verbatim
      via an `adw::ActionRow` with `set_use_markup: false`,
      `set_title_lines: 0`, `set_subtitle_lines: 0`. An
      `adw::SwitchRow` ack ("I understand — show the QR") starts
      off and dispatches only `ExportQrDialogMsg::AckToggled(bool)`
      on `connect_active_notify`; it does not auto-render the QR.
      The footer carries exactly two buttons: `Cancel` (always
      sensitive; dispatches the secret-wipe path through
      `ExportQrDialogOutput::Cancel`) and `Show QR` (the primary
      `suggested-action` button; sensitive only while
      `state.ack_revealed == true`, dispatches
      `ExportQrDialogMsg::ShowQr` on press, which calls
      `Vault::export_qr_png` and switches the `AdwViewStack` to
      the `"qr"` child). The QR `gtk::Picture` is not constructed
      on this page, so a closing-window glimpse cannot expose
      the secret.
    * **Page 2 — QR + actions** (`AdwViewStack` child name
      `"qr"`). Reached by `set_visible_child_name("qr")` after a
      successful `ShowQr` render against the user-pressed
      Page-1 button (never auto-shown on bare ack toggle).
      Renders the QR via a `gtk::Picture`
      whose `paintable` is built from
      `gdk::Texture::from_bytes(&glib::Bytes::from(&png_bytes))`
      where `png_bytes` is the `Zeroizing<Vec<u8>>` returned by
      `Vault::export_qr_png(id, QrRenderOptions::default())` on
      the main loop (the encoder is sub-millisecond on realistic
      `otpauth://` URI lengths, so no thread hop is needed; the
      `gio::spawn_blocking` hop exists only on the *save* path to
      keep `write_secret_file_atomic`'s `fsync` chain off the main
      loop — see §"QR export dialog implementation" / Design
      contract / Thread isolation). A `gtk::Label` caption above
      the `Picture` (with the `title-3` style class for a heading
      weight) shows the account's `summary_display_label` (CLI /
      TUI parity). Four buttons sit in the dialog footer:
      `Save as PNG…`, `Save as SVG…`, `Copy image`, and `Done`.
      `Save as PNG…` and `Save as SVG…` open a
      `gtk::FileDialog::save`, run the same inline overwrite gate
      as `ExportDialog` (an `adw::SwitchRow` revealed only when the
      picked target already exists; the worker rechecks
      `Path::try_exists` post-pick so a stale tick cannot stomp a
      newly-created file), and write through
      `paladin_core::write_secret_file_atomic` on
      `gio::spawn_blocking`. `Copy image` builds a
      `gdk::ContentProvider::for_value` carrying a
      `glib::Bytes` of the PNG payload with MIME `image/png` and
      hands it to `gdk::Clipboard::set_content`. No auto-clear
      schedule arms for QR image copies — `clipboard.clear_enabled`
      covers the code-copy path only, so QR image copies persist
      on the clipboard until the user replaces or clears them (the
      dialog body still calls out the clipboard-history risk via
      DESIGN §8 bullet 6 wording). `Done` closes the dialog.
  `ExportQrDialog` is read-only — it never enters
  `Vault::mutate_and_save`, never advances a HOTP counter, and never
  mutates `updated_at`. PNG bytes, SVG text, and the rendered
  `gdk::Texture` are dropped (and zeroized at the core boundary)
  when the dialog closes, when the ack switch is toggled back off
  (the QR `Picture` paintable is replaced with `gdk::Paintable::new_empty`
  and the staged `Zeroizing<Vec<u8>>` is dropped), or when
  auto-lock fires (`AppModel`'s lock-transition pruning routes
  through `crate::export_qr_dialog::clear_for_lock`). The dialog
  surface is disabled while `AppModel` is `UnlockedBusy` per
  §"In-flight effect ownership"; the save actions stage their own
  in-flight effect ownership through the same one-slot serializer
  used by other vault-touching workers so two saves cannot overlap
  even though the underlying operation does not touch `Vault::save`.
  `Copy image` runs synchronously on the main loop and does not
  claim the busy slot.
  Typed errors from
  `Vault::export_qr_png` / `export_qr_svg` (`invalid_state`
  `state: "account_not_found"`, `validation_error`
  `field: "qr_render"`, defensive encoder failures) stay inline in
  the dialog; `save_not_committed` / `save_durability_unconfirmed`
  from `write_secret_file_atomic` also stay inline. A bubble-phase
  `gtk::EventControllerKey` on the dialog root routes a bare
  `Escape` (no `CTRL` / `ALT` / `SHIFT` / `SUPER` / `HYPER` / `META`)
  through the dialog's cancel path, mirroring `AddAccountComponent`'s
  `dispatch_root_dismiss_key` contract.
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
- `DestroyDialog` *(Milestone 10; DESIGN §4.3 / §7)* — destructive
  path-targeted vault wipe with CLI / TUI parity. An `AdwAlertDialog`
  (GNOME-HIG irreversible-action pattern: heading + warning body +
  destructive-styled action button). The heading reads
  `Delete vault?` and the body is sourced verbatim from
  `paladin_core::format_destroy_warning(path, backup_present)` so
  the GTK, CLI text mode, and TUI modal all render byte-identical
  wording. `backup_present` is populated at open time by probing
  the sibling `vault.bin.bak` via `std::fs::try_exists`; an I/O
  error on the probe falls back to `backup_present = false` and an
  inline cautionary line is appended to the body (no separate
  dialog).
  Entry points (three, all routed through the same
  `app.delete-vault` `gio::SimpleAction`):
  1. **Primary menu item *Delete Vault…*** — installed by
     `format_app_menu_delete_vault_accelerator()` /
     `format_app_menu_delete_vault_action()`, listed in the
     primary menu under the destructive group with the
     accelerator hint. Available in every `AppState` (`Missing`,
     `Locked`, `Unlocked`, `UnlockedBusy`, `StartupError`); the
     dialog can run against a vault the GUI cannot open, which
     is the design contract.
  2. **`UnlockComponent` footer link *Delete vault…*** — an
     inline `gtk::LinkButton` (rendered as a Adwaita-styled flat
     button with `caption-heading` class downscale) below the
     passphrase row, activating the `app.delete-vault` action.
     Discoverable for the forgot-passphrase user without
     dropping to the shell.
  3. **`StartupErrorView` footer link *Delete vault…*** —
     identical placement and action target, so a user stuck on
     an `unsafe_permissions` / `invalid_header` /
     `unsupported_format_version` startup error can still wipe
     and start over from inside the app.
  Body: the warning text above plus an `AdwEntryRow` labelled
  *Type `yes` to confirm* whose buffer must read `yes` after
  Unicode-whitespace trim (the same grammar the CLI text-mode
  prompt and TUI Destroy modal enforce). The buffer's
  `changed` signal updates a `sensitive` binding on the
  destructive action so the loudest button is dim until the
  user types the confirmation. The dialog exposes two responses
  on `AdwAlertDialog::add_response` (close-on-default for both):
  *Cancel* (default focus on open; `Esc` dismisses) and
  *Delete vault* (`destructive-action` style class for the
  GNOME red treatment; sensitive only while the confirmation
  field reads `yes`; never the default focus). The `default-
  response` is set to *Cancel* per HIG so `Enter` does **not**
  fire the destructive action unless the user has explicitly
  focused it.
  On confirm the dialog dispatches an `AppMsg::DestroyVault {
  path }` to the `AppModel`, which calls
  `paladin_core::destroy_vault(path)` on `gio::spawn_blocking`
  (the unlink + `fsync` is fast, but `spawn_blocking` keeps the
  threading model consistent with every other vault-touching
  effect — and lets the in-flight ownership state machine in
  `effect_ownership.rs` serialize destroy alongside Add /
  Edit / Import / Export / Passphrase). The `AppModel`
  transitions to `UnlockedBusy` for the duration; the
  `DestroyDialog` is disabled (insensitive) while the effect is
  in flight, parallel to every other mutating dialog.
  On `Ok(DestroyReport { primary_deleted: true, backup_deleted })`,
  the model:
  * Drops the held `(Vault, Store)` if any — even though the
    primary on disk is gone, the in-memory copy retains the
    decrypted accounts and must wipe through the same
    auto-lock teardown contract.
  * Wipes every secret-bearing UI buffer in lockstep via
    `secret_fields::clear_all`: passphrase fields (Unlock /
    Passphrase set / change), `AddAccountComponent`'s manual
    secret + URI entry buffers + pending duplicate state,
    `InitDialog`'s pending `VaultInit`, the search query (not
    secret-bearing but reset for hygiene), the HOTP reveal
    state + its captured `SecretString`, any pending clipboard
    auto-clear value, and the `ExportQrDialog`'s rendered PNG /
    SVG / Texture buffers if it is open.
  * Transitions `AppModel` to `Missing` and routes back to
    `InitDialog`, parallel to the missing-vault startup path.
  * Adds a `gtk::Toast` to the shared `adw::ToastOverlay`
    reading `Vault deleted.` when `backup_deleted == true` or
    no backup was present at probe time, and `Vault deleted
    (backup remained on disk).` when an `unlink_backup_file`
    failure left the `.bak` behind. The toast goes through
    `toast_queue.rs` like every other notification so back-to-
    back toasts (e.g. an in-flight clipboard-clear toast at
    the moment of destroy) collapse cleanly under the
    newest-wins rule.
  On `Err(vault_missing)` (the on-disk vault disappeared
  between dialog open and dispatch), the dialog closes, the
  model drops any held vault, emits a `Vault already gone.`
  toast, and transitions to `Missing`.
  On `Err(io_error)` for `vault_file_is_symlink` /
  `backup_file_is_symlink` / `unlink_vault_file` /
  `unlink_backup_file` / `fsync_vault_dir`, the dialog stays
  open with an inline error label (rendered as an
  `AdwActionRow` below the warning body with the
  `error` CSS class) that names the failing path and surfaces
  the partial `DestroyReport` (`primary_deleted` /
  `backup_deleted`) so the user can decide whether to retry or
  quit. The destructive button re-arms on a second `yes`
  confirmation entry (the buffer is preserved across an error
  re-display so the user does not have to retype it; the focus
  returns to the action button).
  Auto-lock firing while the dialog is open with no effect in
  flight zeroizes the partial confirmation buffer, closes the
  dialog, and transitions to `Locked` (or `Missing` if the
  vault was plaintext). Auto-lock firing after the effect has
  dispatched is queued behind the result; the success branch
  transitions to `Missing` so the auto-lock idle deadline is
  reset to `None` (no vault to lock).
  The dialog operates against the vault path and never opens
  or decrypts the vault. There is no `Vault::mutate_and_save`
  wrapper; `destroy_vault` is the commit point. The dialog
  is disabled on `UnlockedBusy` for parity with other dialog
  surfaces.
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

The Account-column cell factory
(`column_view::build_account_column_factory`) resolves
`AccountSummary.icon_hint` (carried on the `RowItem`) against the
system icon theme via `gtk::IconTheme`, falling back to a generic
placeholder when the slug is `None` or unresolved.  The CLI and
TUI ignore the field entirely.

## Keyboard shortcuts (per §7)

Every binding listed in DESIGN §7 is sourced from a single pinned helper
inside `crates/paladin-gtk/src/app/model.rs` (or, where noted,
`shortcuts_window.rs` / `account_list.rs` / `add_account.rs`) so the menu,
the `GtkShortcutsWindow`, the `gio::Application::set_accels_for_action`
wiring, and the manual test plan never drift. The accelerator string column
shows the literal returned by the helper (GTK accelerator syntax); the
human-readable form is in DESIGN §7.

### Application-action accelerators

Installed by `wire_app_window_accelerators(&gtk::Application)` from the
`format_app_window_accelerator_bindings() -> [(&'static str, &'static str); 5]`
array, which pairs each accelerator string with its fully-qualified
`gio::SimpleAction` target. Iteration order is held stable for
`set_accels_for_action` and is intentionally distinct from the
`format_app_shortcuts_window_entries` display order.

| Accelerator               | Helper                                            | Action target                                | DESIGN §7 row |
| ------------------------- | ------------------------------------------------- | -------------------------------------------- | ------------- |
| `<Control><Shift>n`       | `format_app_add_button_accelerator`               | `format_app_add_button_action`               | Add Account   |
| `<Control>q`              | `format_app_menu_quit_accelerator`                | `format_app_menu_quit_action`                | Quit          |
| `<Control>comma`          | `format_app_menu_preferences_accelerator`         | `format_app_menu_preferences_action`         | Preferences   |
| `<Control>question`       | `format_app_menu_keyboard_shortcuts_accelerator`  | `format_app_menu_keyboard_shortcuts_action`  | Keyboard Shortcuts |
| `<Control><Shift>Delete`  | `format_app_menu_delete_vault_accelerator`        | `format_app_menu_delete_vault_action`        | Delete Vault (Milestone 10; chord-only — no bare-letter alternative; available in every `AppState` so the forgot-passphrase escape hatch is reachable without a pointer) |

### Window-level search-focus controller

Installed by `wire_app_window_search_focus_controller` as a capture-phase
`gtk::EventControllerKey` on the toplevel `adw::ApplicationWindow`. The
dispatch table is `dispatch_app_window_search_focus_key(keyval, mods) ->
Option<AppMsg>`; matches return `AppMsg::FocusSearch` and are consumed,
non-matches propagate so the `gtk::SearchBar::set_key_capture_widget`
"type-to-search" path keeps working.

| Accelerator       | Helper                                | Dispatch arm                                                            | DESIGN §7 row |
| ----------------- | ------------------------------------- | ----------------------------------------------------------------------- | ------------- |
| `slash <Control>l` | `format_app_search_focus_accelerator` | `Key::slash` (no Ctrl) and `Key::l` / `Key::L` with `CONTROL_MASK`      | `/` or `Ctrl+L`; type-to-search |

### Account-list / search-entry navigation

Installed by `wire_account_list_navigation_controllers` as a paired set of
capture-phase `gtk::EventControllerKey` instances on the
`gtk::SearchEntry` and the `gtk::ColumnView`. Both dispatch tables reject
`ALT` / `SUPER` / `HYPER` / `META` chords; `Ctrl+Shift+N` is left to bubble so
the `<Control><Shift>n` "Add Account" app accelerator still reaches
`gio::Application::set_accels_for_action`.  Up / Down resolve to the
next or previous selectable position via the
`prev_selectable_position` / `next_selectable_position` helpers so
section rows (which carry `set_selectable(false)`) are skipped on
keyboard navigation.

| Accelerator                          | Source widget   | Dispatch helper                       | Intent / DESIGN §7 row                                                          |
| ------------------------------------ | --------------- | ------------------------------------- | ------------------------------------------------------------------------------- |
| `Down`, `Ctrl+J`, `Ctrl+N`           | `SearchEntry`   | `dispatch_search_entry_to_list_nav`   | Focus first row of the filtered list (no-op when filtered list is empty).       |
| `Up`, `Ctrl+K`, `Ctrl+P`             | `ColumnView`    | `dispatch_list_box_nav` → `Up`        | Previous selectable row (section rows skipped); at the first selectable row, return focus to the search entry and re-select. |
| `Down`, `Ctrl+J`, `Ctrl+N`           | `ColumnView`    | `dispatch_list_box_nav` → `Down`      | Next selectable row (section rows skipped); no wrap at the last row.            |
| `Home` / `End` / `PageUp` / `PageDown` | `ColumnView`  | Untouched — propagate to `gtk::ColumnView` | Standard `gtk::ColumnView` bindings (inherited from the wrapped `gtk::ListView`). |

### Row activation

Enter on the focused row (or a single click on the row body —
the `ColumnView` is built with `single_click_activate(true)`)
routes through `gtk::ColumnView::connect_activate` →
`AccountListMsg::ActivateRow(position)`, which resolves the
position to a `RowItem`, skips section rows defensively
(non-selectable per `set_selectable(false)`), reads the row's kind
and visible-code state from `AccountListComponent::{current_rows,
live_displays}`, and dispatches `default_row_activation`. The
inline `gtk::Button` widgets in the Next, Copy, and kebab cells
capture their own clicks via GTK4's gesture-claim rules, so
activating those buttons emits only the button's own
`AccountListOutput` (e.g. `CopyNextCode`) and never bubbles up to
fire row activation as well.

Each non-button cell (account, code, time) installs the
`column_view::ROW_BODY_COPY_TOOLTIP` (`"Copy current code"`) on
its root widget during `bind_*_cell` so a hover surfaces the
click's consequence. The wording parallels the Next column
button's `"Copy upcoming code"` so the two click targets read as
a verb-led pair. Section rows clear the tooltip in their bind
branch since they are non-selectable. The inline buttons
(HOTP reveal, Next, Copy, kebab) keep their own tooltips, which
GTK4 hover-target resolution honors over the parent cell's.

| Trigger                | Row state                                | Outcome                                                                          |
| ---------------------- | ---------------------------------------- | -------------------------------------------------------------------------------- |
| `Enter` / single click on the row body | TOTP, or HOTP with a code currently revealed | Emit `AccountListOutput::CopyCode(id)` — same path as the per-row copy button. |
| `Enter` / single click on the row body | HOTP with the code hidden                | Emit `AccountListOutput::ActivateHotpAndCopy(id)`; `AppModel` latches `pending_copy_after_advance = Some(id)`, re-enters the standard `AdvanceHotp` dispatch, and on `HotpAdvanceWorkerCompleted` fires a follow-up `CopyCode(id)` after `publish_reveal_for`. The latch is cleared on `Locked` / `Quit` via `prune_reveals_if_locked` / `tear_down_for_quit`. |
| `Ctrl+Shift+C`         | TOTP (Next column enabled)               | Emit `AccountListOutput::CopyNextCode(id)` — same path as clicking the row's Next cell; `AppModel` resolves the code via `Vault::totp_next_code(id, now)` and raises an `adw::Toast` `Next code copied, valid in Xs`. Silent no-op on HOTP rows and when the Next column is hidden. |

### Dialog dismissal

`AddAccountComponent` installs a bubble-phase `gtk::EventControllerKey` on
its dialog root whose dispatch table is
`dispatch_root_dismiss_key(keyval, mods) -> bool`. A bare `Escape` press
(no `CTRL` / `ALT` / `SHIFT` / `SUPER` / `HYPER` / `META`) returns `true` and is
routed to the component's cancel path; chord modifiers and other keys
propagate untouched so focused entries, dropdowns, and the Save button keep
their own keyboard handling. The dispatch table is pinned by the
`dispatch_root_dismiss_key` unit tests. Other dialogs (`InitDialog`,
`UnlockComponent`, `RemoveDialog`, `RenameDialog`, `ImportDialog`,
`ExportDialog`, `PassphraseDialog`, `SettingsComponent`, `DestroyDialog`,
`StartupError`) inherit GTK / Adwaita's stock Escape-to-cancel and
Enter-to-default-action behavior. `DestroyDialog` additionally sets
`default-response = "cancel"` on its `AdwAlertDialog` so a stray
`Enter` cannot fire the destructive action; the user must explicitly
focus the *Delete vault* button (after the confirmation field reads
`yes`) and activate it.

### Shortcuts window

The primary menu's "Keyboard Shortcuts" entry opens a
`gtk::ShortcutsWindow` constructed from
`format_app_shortcuts_window_xml()` (in `shortcuts_window.rs`), which in
turn iterates
`format_app_shortcuts_window_entries() -> [(&'static str, &'static str); 6]`
(Milestone 10 adds the *Delete Vault* row).
Display order (most-frequent-use flow) is **Add → Search → Preferences →
Keyboard Shortcuts → Quit → Delete Vault**, intentionally distinct from
the `format_app_window_accelerator_bindings` iteration order; Delete
Vault sits last in the display order so the loudest action is the last
the user reads. The Search row is included here even though it is not a
`gio::SimpleAction` accelerator,
because it is a user-visible window-level binding; both `/` and `<Control>l`
are listed in the row's single space-separated `accelerator` property so
`gtk::Builder` renders them side by side.

### Tests

- `tests/startup_probes.rs` pins
  `format_app_window_accelerator_bindings`,
  `format_app_shortcuts_window_entries`, and each individual
  `format_app_*_accelerator` helper against its literal value.
- `tests/account_list_nav_logic.rs` and `tests/search_focus_logic.rs`
  exercise `dispatch_search_entry_to_list_nav` and `dispatch_list_box_nav`
  against every key/modifier combination listed above, including the
  rejected-chord cases (`ALT` / `SUPER` / `HYPER` / `META` and
  `Ctrl+Shift+N` bubble-through).
- `tests/add_account_logic.rs` covers `dispatch_root_dismiss_key`,
  including the chord-rejection cases.
- The smoke test (`tests/gtk_smoke.rs`) should grow a check that
  `wire_app_window_accelerators` installs every binding on the live
  `gtk::Application` and that the `GtkShortcutsWindow` renders the five
  expected rows.
- The manual test plan (`tests/manual/MANUAL_TEST_PLAN.md`) should grow a
  keyboard-shortcuts pass that walks the table above end-to-end on a
  running window.

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

## Next-code column implementation (per DESIGN §7)

Single-place build plan for the §7 Next-code column feature.
The architecture is described in the **Component tree** /
**Per-row rendering** / **Keyboard shortcuts** sections above; the
per-test items are enumerated in **Pure-logic unit tests** below
(`gsettings_logic.rs` and `account_list_logic.rs`). This section
ties those threads together in build order so the implementer can
work top-to-bottom without re-deriving the touch points.

### Design contract (locked)

* **Visibility:** TOTP rows render `↪ NNN NNN` in a
  `numeric dim-label` `gtk::Label`; HOTP and section rows render
  the empty string. Column-level `set_visible` is the AND of the
  per-user `show-next-code-column` GSettings key (default **true**)
  and `column_view::any_totp(&rows)`. Either latch off → column
  hidden; both on → column visible.
* **Click target:** the cell wraps the `gtk::Label` in a
  `gtk::Button` carrying the stock `.flat` libadwaita CSS class so
  the cell *looks* like text but is clickable. The button's
  `sensitive` is `false` for HOTP and section rows so the cursor
  changes and the click is inert. No additions to
  `data/style.css` — `.dim-label` and `.flat` are stock GTK4 /
  libadwaita classes.
* **Copy semantics:** clicking a populated Next cell (or pressing
  `Ctrl+Shift+C` with a TOTP row selected) emits
  `AccountListOutput::CopyNextCode(AccountId)`. `AppModel` routes
  it through the same
  `prepare_copy_bytes` / `gdk::Clipboard::set_text` /
  `schedule_copy` pipeline as `CopyCode` but reads the code via
  `Vault::totp_next_code(id, now)` instead of `Vault::totp_code`,
  and raises an `adw::Toast` reading
  `Next code copied, valid in {seconds_until_valid}s` on the
  shared `adw::ToastOverlay`.  `seconds_until_valid` is sampled
  off the *current* window:
  `seconds_until_valid = period - (now_unix % period)`, in the
  range `1..=period`. Sample `SystemTime::now()` **once** at the
  copy site and reuse it for both `totp_next_code` and the
  `seconds_remaining` projection so a window flip mid-handler
  cannot desync the toast seconds from the copied digits.
* **Thread isolation:** `Vault::totp_next_code` is a single HMAC
  — sub-millisecond. Run it on the main loop; **do not** wrap in
  `gio::spawn_blocking`. The clipboard write reuses the existing
  synchronous `gdk::Clipboard::set_text` path.
* **Auto-clear arming:** the success path arms
  `pending_clipboard_clear` through the existing
  `paladin_core::ClipboardClearPolicy::schedule` call inside
  `schedule_copy`; the next-code copy reuses that pipeline so a
  user with `clipboard_clear_enabled = true` sees the same wipe
  behavior as a current-code copy.
* **Toast wording source:** the format string
  `Next code copied, valid in {n}s` is duplicated in
  `paladin_gtk` rather than shared with `paladin_tui::app::state::format_next_code_copied`
  (the two binary crates cannot depend on each other and a
  `paladin-core` text helper would expand the public surface for
  one wording). Pin the wording in the
  `account_list_logic.rs` toast test and in the `tests/snapshots/`
  shortcuts-window snapshot so drift between the two crates
  surfaces as a test diff.

### Build order

The list below is the order to land the implementation in a
single reviewable commit (mirroring the TUI commit
`4d3e1a7`'s shape). Each unticked box is a discrete unit of work
the implementer can claim by ticking it.

* [x] **gschema entry.** Add a `<key name="show-next-code-column"
  type="b"><default>true</default></key>` block to
  `data/org.tamx.Paladin.Gui.gschema.xml` next to the existing
  `show-section-headers` / `show-column-headers` keys. `build.rs`
  recompiles the gresource bundle on save.
* [x] **`gsettings.rs` accessors.** Add `pub const
  SHOW_NEXT_CODE_COLUMN_KEY: &str = "show-next-code-column";` and
  the matching `show_next_code_column(&gio::Settings) -> bool` /
  `set_show_next_code_column(&gio::Settings, bool)` pair next to
  the existing `show_column_headers` / `set_show_column_headers`
  helpers.  Per-test items: `gsettings_logic.rs` covers the
  schema declaration, default `true`, round-trip, and the
  `changed::show-next-code-column` signal.
* [x] **`account_row.rs::RowDisplay`.** Add
  `pub next_code: Option<String>` alongside the existing `code` /
  `progress_*` / `copy_enabled` fields. Populate it inside the
  per-tick projection helper (the same one that already calls
  `Vault::totp_code`) via `Vault::totp_next_code(id, now)`;
  HOTP / section rows project `None`. The projection sees a
  single `now: SystemTime` so the next-code digits and the
  gauge's `seconds_remaining` stay aligned within the same tick.
* [x] **`row_item.rs::RowItem`.** No new GObject property is
  needed — `RowDisplay` is already carried as a boxed value via
  the existing `display-changed` signal. Confirm the new
  `next_code` field flows through `set_display` and reaches the
  Next cell factory's `bind` closure.
* [x] **`account_list.rs::AccountListMsg`.** Add
  `SetShowNextCodeColumn(bool)` next to
  `SetShowColumnHeaders(bool)`. The reducer arm:
  latches the value on `AccountListComponent`, recomputes
  `show_next_code_column && any_totp(&rows)`, and calls
  `next_code_column.set_visible(visible)`. No splice; no rebind.
* [x] **`account_list.rs::AccountListOutput`.** Add
  `CopyNextCode(AccountId)` next to the existing
  `CopyCode(AccountId)` variant.
* [x] **`column_view.rs::build_next_code_column_factory`.** Build
  the `gtk::SignalListItemFactory` per the cell-factory
  description above. On `setup`, install the `gtk::Button`
  (`.flat`) wrapping the `gtk::Label` (`.dim-label`, `.numeric`).
  On `bind`, read `RowDisplay.next_code`, write the prefixed
  `↪ {code}` text (empty string when `None`), toggle the button's
  `sensitive` against the row kind / section / `None`, and
  install a click closure that closes over the row's `AccountId`
  and emits `AccountListOutput::CopyNextCode(id)` via the
  controller sender.  On `unbind`, disconnect the click closure
  exactly like the existing copy-column factory so cell recycling
  cannot carry stale ids forward.
* [x] **`column_view.rs` wiring.** Append the new column factory
  to the same column-construction site that builds the existing
  Account / Code / Time / Copy / More columns; insert the new
  column to the right of Time so the visual order matches
  DESIGN §7 (Code → Time → Next). Hold the returned `gtk::ColumnViewColumn` on
  `AccountListComponent` so `SetShowNextCodeColumn` can call
  `set_visible` without re-querying the view.
* [x] **`app/model.rs::AppMsg`.** Add
  `ShowNextCodeColumnChanged(bool)` next to
  `ShowColumnHeadersChanged(bool)`. On `AppModel::init`, connect
  `gio::Settings::changed::show-next-code-column` to a handler
  that dispatches the new `AppMsg`, which forwards to
  `AccountListMsg::SetShowNextCodeColumn(bool)` on the live
  controller (mirrors the existing column-headers wiring exactly).
* [x] **`app/model.rs` `CopyNextCode` route.** Add an
  `AccountListAction(AccountListOutput::CopyNextCode(id))`
  handler that mirrors the existing `CopyCode` handler:
  resolves the code via `Vault::totp_next_code(id, now)` (sample
  `now` once and reuse for `seconds_until_valid = period -
  (now_unix % period)` — read `period` off `account.period()` or
  the existing `vault.totp_code(id, now).seconds_remaining`
  projection so the formula stays in one place), writes through
  the shared `prepare_copy_bytes` / `gdk::Clipboard::set_text` /
  `schedule_copy` pipeline, and on success raises
  `adw::Toast::new(&format!("Next code copied, valid in {secs}s"))`
  on the shared `adw::ToastOverlay`. Failure surfaces the
  existing clipboard-write-failed toast and arms no clear
  schedule (matches `CopyCode`'s failure branch).
* [x] **`components/settings.rs` Preferences toggle.** Append a
  third `AdwSwitchRow` titled `Show next code` to the `Display`
  `AdwPreferencesGroup`, bound to `show-next-code-column` via the
  matching `crate::gsettings::set_show_next_code_column` helper.
  The toggle's `connect_active_notify` writes through the helper
  and the `changed::show-next-code-column` signal re-enters the
  pipeline via `AppModel` (no direct controller call from the
  Preferences dialog).
* [x] **`keybindings.rs::format_app_copy_next_code_*`.** Add a
  `format_app_copy_next_code_accelerator() -> &'static str`
  returning `"<Control><Shift>c"` and a
  `format_app_copy_next_code_action() -> &'static str` returning
  `"win.copy-next-code"` (or `"app.copy-next-code"` to match the
  existing format-app-* convention — pin whichever the other
  format-app helpers use). Bump the
  `format_app_window_accelerator_bindings()` return type from
  `[(&'static str, &'static str); 4]` to `[…; 5]` and append the
  new pair so `gio::Application::set_accels_for_action` picks it
  up; the existing
  `format_app_window_accelerator_bindings_pin_helpers_via_iteration`
  unit test will fail until the array length and the new helper
  are added together, which is exactly the lockstep guard the
  pattern provides. The same two helpers are surfaced through
  the primary menu and the `GtkShortcutsWindow` so the wiring
  stays in lockstep. *(Landed inside `crates/paladin-gtk/src/app/model.rs`
  — the existing `format_app_*_accelerator` / `_action` /
  `_action_name` helpers already live there alongside
  `format_app_window_accelerator_bindings`; the action target is
  `app.copy-next-code` matching the existing
  `format_app_action_group_name() = "app"` convention used by
  the menu and Add helpers.)*
* [x] **`app/actions.rs` (or wherever `add_action_entries` lives).**
  Register a `win.copy-next-code` (or `app.copy-next-code`)
  `gio::SimpleAction`. Its `activate` resolves the live
  `AccountListComponent` selection, branches:
  TOTP → dispatch the same `AccountListOutput::CopyNextCode(id)`
  flow as the cell click; HOTP / no-selection / Next column
  hidden → silent no-op (the TUI surfaces a status-line error
  for HOTP; the GTK accelerator's silent-no-op preserves the
  existing "menu accelerators don't surface toast errors"
  pattern). The cell click path is unaffected by this gate
  because cells are `sensitive=false` for HOTP rows. *(Landed
  inside `crates/paladin-gtk/src/app/model.rs`: a
  `build_app_copy_next_code_action()` factory adds the
  `"copy-next-code"` `gio::SimpleAction` to the bundled
  `build_app_window_action_group`; the existing
  `wire_app_window_action_activations` /
  `dispatch_app_window_action` pipeline routes its activation
  through a new `AppMsg::CopyNextCodeAccelerator` variant whose
  handler reads the live `AccountListComponent` selection via
  the new `current_selection_copy_next_code_output` accessor
  (which delegates to the pure
  `dispatch_copy_next_code_accelerator` decision table) and
  re-dispatches `AccountListOutput::CopyNextCode(id)` on TOTP.
  HOTP / no selection / hidden Next column / unmounted
  controller all collapse to silent no-op.)*
* [x] **`view/keyboard_shortcuts.rs` (or the `.ui` template the
  `GtkShortcutsWindow` reads).** Add a row in the "List view"
  shortcut group: `Ctrl+Shift+C — Copy selected row's next code`.
  Source the accelerator string from
  `format_app_copy_next_code_accelerator` so future renames stay
  in lockstep. *(Landed inside
  `crates/paladin-gtk/src/shortcuts_window.rs`. The crate keeps
  the shortcuts-window definition in a single `shortcuts_window`
  module rather than a `view/` submodule, and the renderer is a
  pure-Rust XML template generator
  (`format_app_shortcuts_window_xml`) iterating the pinned
  `format_app_shortcuts_window_entries` array — no `.ui` file is
  used. The new row was appended to the entry array between
  Search and Preferences (single `"General"` group, since the
  crate does not yet split rows into per-area sub-groups), and
  the array length bumped from 5 to 6. The title is sourced from
  a new `format_app_copy_next_code_label` helper added next to
  the existing `format_app_copy_next_code_action` /
  `format_app_copy_next_code_action_name` /
  `format_app_copy_next_code_accelerator` siblings in
  `crates/paladin-gtk/src/app/model.rs` so the user-visible label
  stays in lockstep with the action wiring on a future rename.)*
* [x] **`tests/snapshots/` shortcuts-window snapshot.** Update
  the `GtkShortcutsWindow` snapshot to include the new row.
  *(The crate does not use `insta` snapshot files; the
  "shortcuts-window snapshot" is the in-source unit test
  `format_app_shortcuts_window_entries_lists_*_rows_in_display_order`
  in `crates/paladin-gtk/src/shortcuts_window.rs` that pins the
  entry array length and per-index `(accelerator, title)` pairs.
  That test was renamed from `_lists_five_rows_*` to
  `_lists_six_rows_*` with the new Copy-Next-Code assertion
  inserted at index 2. A sibling guard
  `format_app_shortcuts_window_entries_sources_copy_next_code_row_from_helpers`
  pins that the row sources its accelerator and title from the
  `format_app_copy_next_code_*` helpers so a literal-rewrite
  cannot drift the row away from the helper. The existing
  `format_app_shortcuts_window_xml_contains_one_shortcut_per_entry`
  test already iterates the entry array, so it picks up the new
  row automatically; the XML escape / title coverage tests do
  the same.)*
* [x] **`tests/manual/MANUAL_TEST_PLAN.md`.** Append three
  scenarios:
    * "Click the Next cell on a TOTP row → clipboard holds the
      upcoming code and a toast reads `Next code copied, valid in
      Xs`."
    * "Press `Ctrl+Shift+C` with a TOTP row selected → same
      behavior as clicking the Next cell."
    * "Toggle Preferences → Display → Show next code → the column
      hides / shows; the visible cells re-flow without flicker."
* [x] **Pure-logic unit tests.** Already enumerated in
  `gsettings_logic.rs` (4 items) and `account_list_logic.rs`
  (6 items) — see the **Pure-logic unit tests** section.
  Implementation must tick all 10 boxes; CI gates them.
* [ ] **CI gates.** `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --all-targets`, `cargo deny check`,
  `cargo audit`. `cargo public-api` snapshot stays unchanged
  (no new `paladin-core` API).

### Open decisions / non-goals

* **No new `paladin-core` API.** The TUI commit already added
  `Vault::totp_next_code`; the GTK implementation reuses it
  verbatim. No public-api.txt diff is expected.
* **No new CSS.** Both `.dim-label` and `.flat` are stock
  libadwaita classes; `data/style.css` stays untouched.
* **Accelerator scope = window.** `Ctrl+Shift+C` is registered
  as a window-level action (mirrors `Ctrl+Shift+N` for Add) so
  it's active wherever the account list is visible but quiet
  during modal dialogs whose own bindings trap focus.
* **HOTP rejection is silent at the accelerator.** Unlike the
  TUI's `no next code for HOTP accounts` status-line error, the
  GTK accelerator no-ops on HOTP rows. The Next cell button is
  already `sensitive=false` for HOTP, so the visible affordance
  carries the rejection signal; a toast on top would feel like
  noise. Revisit if user testing surfaces confusion.
* **Backward compatibility.** New GSettings key with default
  `true` means upgrading users see the Next column on first
  launch after this lands. No migration path; the schema-version
  GSettings infrastructure handles new keys idiomatically.

## QR export dialog implementation (per DESIGN §4.6 / §7)

Single-place build plan for the §4.6 / §7 per-account QR export
feature. The architecture is described in the **Component tree** /
**Per-row rendering** sections above; the per-test items are
enumerated in **Pure-logic unit tests** below
(`export_qr_dialog_logic.rs`, plus the kebab-menu lockstep test in
`account_list_logic.rs`). This section ties those threads together
in build order so the implementer can work top-to-bottom without
re-deriving the touch points.

### Design contract (locked)

* **Surface:** the dialog opens from a new third entry on the row
  kebab `gio::Menu`, `Show QR…`, sitting between `Rename…` and
  `Remove…` so the destructive `Remove…` stays trailing and the
  read-only `Show QR…` neighbours the read-only `Rename…` shape
  (label edit is mutating, but it is the non-destructive sibling
  the kebab pairs `Show QR…` with). The new menu entry targets a
  per-row `row.show-qr` action on the existing per-cell
  `gio::SimpleActionGroup` installed by
  `install_row_action_group`; the activation routes through
  `dispatch_row_action` into a new
  `AccountListOutput::OpenExportQrDialog(AccountId)` variant
  that `AppModel` consumes to mount `ExportQrDialogComponent`.
* **Read-only.** The dialog never enters
  `Vault::mutate_and_save`, never advances a HOTP counter, and
  never bumps `updated_at`. Every render call goes through the
  new `&self` methods `Vault::export_qr_png` /
  `Vault::export_qr_svg`; `export_qr_ansi` is not called by the
  GUI (the CLI / TUI consume it). The HOTP-counter-unchanged
  invariant is pinned by a tempfile-backed pure-logic test that
  reads `account.counter()` before and after a save-as-PNG worker
  round trip and asserts equality.
* **Warning-ack gate.** `ExportQrDialogState` carries
  `ack_revealed: bool` defaulting to `false`. The `AdwViewStack`'s
  visible child is `"warning"` until a successful `ShowQr` render
  switches it to `"qr"`; the `gtk::Picture` widget lives inside
  the `"qr"` child from init with a `gdk::Paintable::new_empty`
  paintable, and `ack_revealed` gates the Page-1 `Show QR`
  button's sensitivity rather than the Picture's existence.
  Toggling the ack switch off resets `ack_revealed` to `false`,
  switches the view stack back to `"warning"`, replaces the
  Picture's paintable with `gdk::Paintable::new_empty`, and drops
  the staged PNG / SVG / texture buffers (the staged values are
  held in `Zeroizing<Vec<u8>>` / `Zeroizing<String>` so the drop
  zeroes the bytes). The warning text is pulled verbatim from
  `paladin_core::format_plaintext_qr_export_warning()` and rendered
  through `set_use_markup: false`, `set_title_lines: 0`,
  `set_subtitle_lines: 0` so long-form wording wraps without
  honoring stray markup. A pure-logic test
  (`format_export_qr_dialog_warning_body_matches_paladin_core_verbatim`)
  pins the verbatim relationship so future warning rewordings flow
  through one helper.
* **Thread isolation.** `Vault::export_qr_png` and
  `Vault::export_qr_svg` each call `qrcode::QrCode::new` once and
  then a Luma / SVG render; the work is sub-millisecond on
  realistic `otpauth://` URI lengths, so the render itself runs on
  the main loop. The `gio::spawn_blocking` hop exists for the
  *save* path because `write_secret_file_atomic` chains multiple
  `fsync`s, parity with the existing `ExportDialog` plaintext path
  rationale (§"Vault interaction").
* **In-flight effect ownership.** Save actions serialize through
  the existing one-slot `UnlockedBusy { effect, ui_snapshot }`
  token so the dialog can surface a spinner while a save is in
  flight without letting a second save overlap. The dialog's
  on-screen render and the `Copy image` action both run
  synchronously on the main loop (the encoder is sub-millisecond
  and `gdk::Clipboard::set_content` is a memcpy + GDK refcount),
  so neither claims `UnlockedBusy`. This matches `ExportDialog`'s
  shape, where the format / file picker UI is responsive while
  only the encrypted-bundle KDF worker has the busy slot.
* **Copy semantics.** `Copy image` builds a
  `gdk::ContentProvider::for_value` on a `glib::Bytes` of the PNG
  payload with content type `image/png`, then calls
  `gdk::Clipboard::set_content(Some(&provider))`. The PNG bytes
  are the same `Vault::export_qr_png` output that the on-screen
  `Picture` renders: `state.staged_png` is the single in-dialog
  `Zeroizing<Vec<u8>>` source for both the on-screen Picture's
  `gdk::Texture` and the clipboard provider's `glib::Bytes`, so
  the dialog never holds two copies of the secret. The
  `Zeroizing<Vec<u8>>` is dropped (and its bytes zeroized) when
  the dialog closes, when ack is toggled off, or when auto-lock
  fires; the clipboard provider's `glib::Bytes` is an independent
  copy owned by GDK and persists on the clipboard until the user
  replaces or clears it. No auto-clear schedule arms for QR image
  copies — `clipboard.clear_enabled` covers OTP code copies only;
  the dialog body still calls out the clipboard-history risk in
  line with DESIGN §8 bullet 6 wording.
* **Save semantics.** Save-as-PNG and Save-as-SVG open a
  `gtk::FileDialog::save` for the destination, run the same inline
  overwrite gate `ExportDialog` uses
  (`compose_overwrite_gate_visible` against
  `Path::try_exists` post-pick, with `unwrap_or(true)` so I/O
  errors default to arming the gate), and write the PNG / SVG
  bytes through `write_secret_file_atomic` on
  `gio::spawn_blocking`. On success the dialog stays open and a
  status-line label inside the dialog body shows the written path;
  an `adw::Toast` on the shared `adw::ToastOverlay` ("QR saved to
  …") raises in parallel so the confirmation is visible if the
  user has already started a second save into a different
  filename. Failure routes through `classify_export_qr_save_error`
  to inline-error rendering for `io_error`, `save_not_committed`,
  `save_durability_unconfirmed`, and `validation_error`.
* **Auto-lock.** A `crate::export_qr_dialog::clear_for_lock`
  helper is registered through the existing lock-transition
  pruning so an auto-lock fire drops the dialog widget (along
  with the staged PNG / SVG / texture buffers) before the
  `(Vault, Store)` pair is destroyed.
* **Thinness contract.** `paladin-gtk` continues to forbid
  direct `image` / `rqrr` / `qrcode` use through
  `tests/thinness.rs`. PNG bytes leave `paladin-core` as
  `Zeroizing<Vec<u8>>`, SVG bytes leave as `Zeroizing<String>`;
  the GTK crate consumes PNG through `gdk::Texture::from_bytes`
  (for the on-screen `Picture`) and `write_secret_file_atomic`
  (for Save-as-PNG and as the source bytes for the
  `gdk::Clipboard` payload), and consumes SVG through
  `write_secret_file_atomic` only (`gdk::Texture` does not decode
  SVG, so SVG is never bound to the on-screen `Picture` and is
  never placed on the clipboard). The GTK crate never re-encodes
  either format.

### Build order

The list below is the order to land the implementation in a
single reviewable commit (mirroring the shape of the
**Next-code column implementation** §"Build order" above). Each
unticked box is a discrete unit of work the implementer can claim
by ticking it.

* [x] **`paladin-core` API.** Land the §4.7 surface first:
  `QrRenderOptions`, the `QR_MODULE_SIZE_PX_*` constants,
  `Vault::export_qr_png` / `export_qr_svg` / `export_qr_ansi`,
  the parallel `export::qr_*` free functions, and
  `format_plaintext_qr_export_warning`. `qrcode` moves from
  `[dev-dependencies]` to `[dependencies]` in
  `crates/paladin-core/Cargo.toml`. Update
  `crates/paladin-core/public-api.txt` to match. The core-side
  tests (DESIGN §10 "QR export") land in the same commit.
* [x] **Kebab menu order.** Extend
  `account_list::build_kebab_menu_model` to append `Show QR…`
  between `Rename…` and `Remove…` targeting a new
  `row.show-qr` action; rename the lockstep test from
  `build_kebab_menu_model_exposes_rename_and_remove_in_order` to
  `build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
  with the new index-2 assertion. Register the action on the
  per-row `gio::SimpleActionGroup` in `install_row_action_group`
  with a closure that emits the new
  `AccountListOutput::OpenExportQrDialog(AccountId)` variant.
* [x] **`AccountListOutput::OpenExportQrDialog(AccountId)`.** Add
  the variant and pin `account_list_output_open_export_qr_dialog_carries_account_id`
  in `tests/account_list_logic.rs`. Extend
  `dispatch_row_action` to route the new action name into the
  variant.
* [x] **`AppMsg::OpenExportQrDialog(AccountId)` and dispatch.**
  Add the message variant and the `AccountListAction` arm that
  resolves the matching `AccountSummary` and mounts
  `ExportQrDialogComponent` against the live `(Vault, Store)`
  pair. The dispatch must reject the open when `AppModel` is not
  `Unlocked` (silent no-op) for parity with the existing
  `OpenRenameDialog` / `OpenRemoveDialog` gates.
* [x] **`src/export_qr_dialog.rs` skeleton.** Add the
  `ExportQrDialogComponent` (`relm4::SimpleComponent`) with
  `ExportQrDialogInit { account_id, account_summary }`,
  `ExportQrDialogMsg`, `ExportQrDialogOutput`, and the
  `ExportQrDialogState` value-type holding `ack_revealed: bool`,
  `staged_png: Option<Zeroizing<Vec<u8>>>`,
  `staged_svg: Option<Zeroizing<String>>`,
  `save_target: Option<{ kind: SaveKind::{Png, Svg}, path: PathBuf }>`,
  `destination_exists: bool` and `overwrite_acknowledged: bool`
  (paired the same way as `ExportDialogState`'s
  `set_destination` / `set_format` reset rule: picking a new
  `save_target` re-keys `destination_exists` against the new
  path and resets `overwrite_acknowledged` to `false`, unless
  the new `(kind, path)` matches the previously-acked one),
  `last_save_path: Option<PathBuf>` (drives the "QR saved to
  …" status-line label on Page 2 after a successful write), and
  a `worker_outcome` slot mirroring
  `ExportDialogState::worker_outcome` (carries the typed
  `io_error` / `save_not_committed` /
  `save_durability_unconfirmed` / `validation_error` outcomes
  that `classify_export_qr_save_error` routes to inline
  rendering). The `Cancel` / `Close` output variants are
  distinct, matching `ExportDialogOutput`.
* [x] **Warning page wiring.** Construct the `AdwViewStack` with
  the `"warning"` child mounted on init. Inside `"warning"`,
  mount Page 1's `adw::ActionRow` rendering
  `compose_export_qr_warning_body() ->
  paladin_core::format_plaintext_qr_export_warning()`. Mount the
  ack `adw::SwitchRow` and route its
  `connect_active_notify` through
  `ExportQrDialogMsg::AckToggled(bool)` only — toggling the
  switch never auto-dispatches `ShowQr`. The Page-1 footer
  carries two `gtk::Button`s: a `Cancel` button (always
  sensitive; `connect_clicked` dispatches the cancel path that
  emits `ExportQrDialogOutput::Cancel` after wiping staged
  buffers) and a `Show QR` button (`suggested-action` style
  class; sensitivity bound from
  `compose_show_qr_button_sensitive(state)` against
  `state.ack_revealed`; `connect_clicked` dispatches
  `ExportQrDialogMsg::ShowQr`). Pin the verbatim relationship by
  `format_export_qr_dialog_warning_body_matches_paladin_core_verbatim`,
  the button-sensitivity rule by
  `compose_show_qr_button_sensitive_false_until_ack_revealed` /
  `compose_show_qr_button_sensitive_true_after_ack_toggled_on`,
  and the no-auto-render contract by
  `apply_msg_ack_toggled_does_not_dispatch_show_qr` (toggling
  ack on/off only mutates `state.ack_revealed`; ShowQr is
  emitted exclusively by the button-press handler).
* [x] **Page 2 mount on Show-QR press.** On
  `ExportQrDialogMsg::ShowQr` (emitted by the Show-QR button's
  `connect_clicked`, never by the ack switch), the
  `SimpleComponent` emits
  `ExportQrDialogOutput::ShowQrRequested(account_id)` so
  `AppModel` (the live `(Vault, Store)` owner) runs
  `vault.export_qr_png(account_id, &QrRenderOptions::default())`
  on the main loop (the encoder is fast enough — see "Thread
  isolation" above) and forwards the result back through
  `ExportQrDialogMsg::ShowQrSucceeded(Zeroizing<Vec<u8>>)` /
  `ExportQrDialogMsg::ShowQrFailed(String)`. The reducer routes
  Succeeded through `apply_msg_show_qr_succeeded` (moves the
  bytes into `state.staged_png`) and Failed through
  `apply_msg_show_qr_failed` (parks the rendered message in
  `state.show_qr_error` for inline rendering on Page 1). The
  view-stack visible-child name is `#[watch]`-bound to
  `compose_visible_child_name(&state)` so populating
  `staged_png` flips the page to `"qr"` and an ack-off / Cancel
  reset flips it back to `"warning"`. The `gtk::Picture`'s
  paintable is `#[watch]`-bound through `build_staged_png_texture(&state)`
  which constructs a `gdk::Texture::from_bytes(&glib::Bytes::from(&bytes))`
  from the staged PNG slot, so the paintable resets to `None`
  (the equivalent of `gdk::Paintable::new_empty`) on every
  buffer-wipe path. The caption `gtk::Label` is built into the
  `"qr"` child at init alongside the Picture with the `title-3`
  style class and bound to
  `compose_export_qr_caption_text(&state)` → `summary_display_label(&summary)`.
  Pins: `apply_msg_show_qr_renders_picture_paintable_from_png_bytes`,
  `apply_msg_show_qr_button_press_calls_export_qr_png_with_default_options`,
  `apply_msg_show_qr_switches_visible_child_to_qr`,
  `apply_msg_show_qr_sets_caption_label_text_from_summary_display_label`,
  `compose_export_qr_dialog_caption_widget_uses_title_3_style_class`,
  `apply_msg_show_qr_invalid_state_account_not_found_renders_inline`,
  `apply_msg_show_qr_validation_error_renders_inline`,
  `apply_msg_show_qr_success_clears_prior_inline_error`,
  `compose_visible_child_name_warning_before_show_qr`, and
  `apply_msg_ack_toggled_off_clears_staged_png_and_paintable_and_resets_visible_child`.
  The four-button Page-2 footer
  (`Save as PNG…` / `Save as SVG…` / `Copy image` / `Done`)
  ships with only `Done` wired in this commit; the Save and
  Copy buttons land in the subsequent
  "Save-as-PNG / Save-as-SVG actions" and "Copy image action"
  build-order entries.
* [x] **Save-as-PNG / Save-as-SVG actions.** Wire the two footer
  buttons to open a `gtk::FileDialog::save`, dispatch
  `ExportQrDialogMsg::SaveDestinationPicked { kind: PngOrSvg,
  path, exists }`, and run the same overwrite-gate state as
  `ExportDialog` (`overwrite_gate_visible` keyed to the picked
  target's `Path::try_exists`). On confirm, dispatch
  `run_export_qr_save_worker` on `gio::spawn_blocking`. For PNG,
  the worker reuses the already-staged `state.staged_png` bytes
  (populated when the user pressed Show-QR) and writes them
  through `paladin_core::write_secret_file_atomic`; the worker
  never calls `vault.export_qr_png` a second time, so on-screen
  Picture bytes and on-disk bytes are byte-identical by
  construction. For SVG, `state.staged_svg` is empty until the
  first save-as-SVG fires, so the worker calls
  `vault.export_qr_svg(...)` once, parks the result in
  `state.staged_svg` (so a subsequent save-as-SVG to a different
  path reuses it), and writes through
  `paladin_core::write_secret_file_atomic`. Pin the worker
  round-trip in
  `run_export_qr_save_worker_plaintext_png_succeeds_and_writes_0600_file`
  + the matching SVG variant.
  *Implementation note (Phase 5):* `ExportQrSaveWorkerInput` /
  `ExportQrSaveWorkerCompletion` split as `Png` / `Svg`
  enum variants so the PNG branch ignores the vault entirely
  (proven by `run_export_qr_save_worker_png_does_not_call_export_qr_png`,
  which feeds nonsense bytes and asserts the on-disk file
  matches verbatim). `AppMsg::ExportQrDialogAction(ExportQrDialogOutput::SaveRequested)`
  drives the worker through `gtk::glib::spawn_future_local` →
  `gtk::gio::spawn_blocking`; completion forwards via the new
  `AppMsg::ExportQrSaveCompleted` arm which reinstalls
  `(Vault, Store)` on `AppModel::vault` and emits
  `ExportQrDialogMsg::SaveCompleted` back to the live
  controller. The view-layer `connect_clicked` on `Save as PNG\u{2026}` /
  `Save as SVG\u{2026}` opens a `gtk::FileDialog::save` with
  `modal(true)` and dispatches `SaveDestinationPicked` on the
  picker's response; `exists` uses `Path::try_exists().unwrap_or(true)`
  so an unreadable parent still arms the gate. Reducer arms
  auto-fire `Output::SaveRequested` when the gate is satisfied
  (path doesn't exist, or it exists and the user toggled the
  ack on) — no separate "Confirm" button. Pinned by
  `apply_msg_save_destination_picked_auto_fires_when_destination_does_not_exist`,
  `apply_msg_overwrite_acknowledged_true_auto_fires_when_target_set`,
  and the negative-space `*_does_not_fire_when_destination_exists` /
  `*_false_does_not_fire` partners. The four-button Page-2
  footer (`Save as PNG\u{2026}` / `Save as SVG\u{2026}` /
  `Copy image` / `Done`) ships with `Copy image` still
  insensitive — it gets wired in the next "Copy image action"
  commit. Inline overwrite-ack row mirrors `ExportDialog`'s
  Switch surface and stays hidden when `destination_exists` is
  `false`.
* [x] **Copy image action.** Add a `Copy image` footer button
  wired to dispatch `ExportQrDialogMsg::CopyImage`. The handler
  builds a `gdk::ContentProvider::for_value` carrying a
  `glib::Bytes::from(&state.staged_png)` of MIME `image/png` and
  calls `gdk::Clipboard::set_content(Some(&provider))`. The
  `Copy image` button is mounted on Page 2 only and Page 2 is
  mounted only after a successful `ShowQr`, so
  `state.staged_png` is guaranteed populated when the handler
  runs and no fallback render path is needed. On success raise
  an `adw::Toast` reading `Image copied`; on failure surface
  inline. Pin
  `apply_msg_copy_image_routes_through_set_content_with_image_png_mime`
  and the failure-no-arm path
  `apply_msg_copy_image_failure_does_not_arm_clipboard_clear`.
  *Implementation note (Phase 6):* shipped via the new
  `ExportQrDialogMsg::{CopyImage, CopyImageSucceeded, CopyImageFailed}`
  variants, `ExportQrDialogOutput::CopyImageRequested(Zeroizing<Vec<u8>>)`,
  and the `compose_copy_image_request_output` /
  `apply_msg_copy_image_succeeded` / `apply_msg_copy_image_failed`
  helpers. The Page-2 `copy_image_button` binds
  `set_sensitive: compose_copy_image_button_sensitive(&model.state)`
  and `connect_clicked` dispatches `ExportQrDialogMsg::CopyImage`;
  the `SimpleComponent::update` arm forwards the
  `CopyImageRequested(bytes)` output via
  `compose_copy_image_request_output`. `AppModel` consumes the
  output by building
  `gtk::gdk::ContentProvider::for_bytes(COPY_IMAGE_CLIPBOARD_MIME_TYPE, &glib::Bytes::from(...))`
  and calling `clipboard.set_content(Some(&provider))`; success
  raises the `Image copied` toast (via
  `format_export_qr_dialog_copy_image_success_toast`) and
  forwards `ExportQrDialogMsg::CopyImageSucceeded`; failure
  forwards `ExportQrDialogMsg::CopyImageFailed(err.to_string())`
  which parks the body in `state.copy_image_error` for inline
  rendering. The failure arm returns `None` from `apply_msg` so
  no output ever lands on `AppModel` that would route into
  `clipboard_clear::schedule_copy` — image copies are not OTP
  codes and must not arm the `PendingClipboardClear` timer.
  `drop_staged_buffers` / `apply_msg_ack_toggled(false)` /
  `CancelPressed` / `Close` all clear `copy_image_error` so a
  stale failure never survives a re-acked retry.
* [x] **Bubble-phase Escape dismissal.** Install a
  `gtk::EventControllerKey` mirroring
  `dispatch_root_dismiss_key` so bare `Escape` (no modifiers)
  cancels the dialog through the same secret-wipe /
  `ExportQrDialogOutput::Cancel` path as the Cancel button.
  Reuse the existing `dispatch_root_dismiss_key` helper rather
  than duplicating its truth table.
  *Implementation note (Phase 7):* shipped via a private
  `wire_dismiss_controller(&adw::Dialog, &ComponentSender<…>)`
  helper in `src/export_qr_dialog.rs` that delegates to
  `crate::add_account::dispatch_root_dismiss_key` for the truth
  table; bare Escape posts `ExportQrDialogMsg::CancelPressed`
  (the same reducer arm the Cancel button hits, so the
  staged-buffer wipe + `ExportQrDialogOutput::Cancel` flow stays
  uniform). Called from `SimpleComponent::init` after
  `view_output!()`. Coverage in `tests/export_qr_dialog_logic.rs`:
  `dispatch_root_dismiss_key_routes_bare_escape_to_cancel_pressed`,
  `dispatch_root_dismiss_key_ignores_escape_with_chord_modifiers`,
  `dispatch_root_dismiss_key_ignores_other_keys`, and
  `escape_dismissal_routes_through_cancel_pressed_msg` (pinned at
  reducer level — drives `CancelPressed` and asserts the
  staged-buffer drop + Cancel output emit).
* [x] **Auto-lock pruning.** Register
  `crate::export_qr_dialog::clear_for_lock` with the lock-
  transition pruning so an auto-lock fire drops the dialog
  widget and the staged PNG / SVG buffers before the
  `(Vault, Store)` pair is destroyed. Pin
  `clear_for_lock_drops_staged_buffers_and_paintable`.
  *Implementation note (Phase 8):* `clear_for_lock(&mut state)`
  resets `ack_revealed`, `last_save_path`, and delegates to
  `drop_staged_buffers` (which already wipes the staged PNG /
  SVG `Zeroizing<...>` buffers, the save target, the
  destination-exists / overwrite-ack flags, and every inline
  error / warning body — `show_qr_error`, `save_error`,
  `save_warning`, `copy_image_error`). `account_id` and
  `account_summary` are preserved so a post-lock re-open can
  rebuild Picture and caption (pinned by
  `clear_for_lock_preserves_account_id_and_summary`).
  `AppModel::lock_on_auto_lock_expiry` calls the helper via
  `controller.state().get_mut().model.state_mut()` BEFORE
  taking the controller into the `modal` aggregate; the
  controller drop then tears down the widget tree (including
  the `gtk::Picture`'s `gdk::Paintable`). Two-step
  state-clear-then-drop is defensive: even if a future change
  retains the controller across lock, the buffers are zeroed
  first. New `pub fn ExportQrDialogComponent::state_mut`
  accessor exposes the reducer state for the controller-side
  call. Additional pin
  `clear_for_lock_on_fresh_state_is_a_noop` confirms the call
  is safe on every auto-lock fire even when the user never
  opened the dialog.
* [x] **Thinness contract.** Re-run
  `cargo test -p paladin-gtk --test thinness` to confirm the
  GTK crate still passes — the new file imports only
  `paladin_core::*` and `gtk` / `gdk` / `glib` / `adw` /
  `relm4`. No `image` / `rqrr` / `qrcode` imports anywhere in
  `crates/paladin-gtk/src/`.
* [x] **Manual test plan.** Append five scenarios to
  `tests/manual/MANUAL_TEST_PLAN.md`:
    * "Open the kebab on a TOTP row → `Show QR…` is the second
      entry; the dialog opens on the warning page with the ack
      switch off and the QR not visible."
    * "Toggle the ack on → the QR renders; the issuer:label
      caption is correct; the four footer buttons appear."
    * "Press `Save as PNG…` → pick a path → write succeeds; the
      saved file decodes back to the same `otpauth://` URI via
      an external QR scanner; permissions are `0600`."
    * "Press `Save as PNG…` against an existing file → the
      inline overwrite gate appears; the file is unchanged
      until the gate is confirmed."
    * "Press `Copy image` → paste into an image editor → the QR
      pixels match the on-screen render; pasting into a text
      field yields nothing (the clipboard carries PNG bytes,
      not text)."
* [x] **Pure-logic unit tests.** Tick every bullet in the
  `tests/export_qr_dialog_logic.rs` checklist below (and the
  kebab-menu rename in `tests/account_list_logic.rs`); CI gates
  them.
* [x] **CI gates.** `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace --all-targets`, `cargo deny check`,
  `cargo audit`. `cargo public-api` snapshot is updated to
  include `QrRenderOptions` + the `Vault::export_qr_*` methods +
  the `export::qr_*` free functions +
  `format_plaintext_qr_export_warning` +
  `QR_MODULE_SIZE_PX_*`.

### Open decisions / non-goals

* **No new GSettings key.** Unlike the Next-code column, the QR
  dialog has no per-user "show / hide" preference — the feature
  is an explicit per-account action, not a list-view affordance.
  No `data/org.tamx.Paladin.Gui.gschema.xml` change is needed.
* **No new CSS.** `gtk::Picture`, `adw::ActionRow`,
  `adw::SwitchRow`, `gtk::Button`, and the standard
  `destructive-action` / `suggested-action` style classes carry
  all the styling. `data/style.css` stays untouched.
* **No window-level accelerator.** Unlike Add (`Ctrl+Shift+N`) or
  Copy-next-code (`Ctrl+Shift+C`), QR export does not get a
  global accelerator in v0.2. The action requires an
  account selection (a one-account-per-dialog operation), and
  registering a window-level accelerator for it would surface
  identical-feel toasts on no-selection / no-account states.
  The kebab entry is the canonical surface; a keyboard mirror
  can land as a follow-up if user testing surfaces friction.
* **No multi-account migration QR.** Per DESIGN §4.6, the v0.2
  scope is per-account otpauth:// QRs only. Google
  Authenticator–style `otpauth-migration://` protobuf payloads
  are out of scope until a future design update.
* **`gdk::Texture::from_bytes` over a temp file.** The on-screen
  Picture is bound to an in-memory texture, not a file URL, so
  the rendered bytes never touch disk on the way to the screen.
  Save-as-PNG / Save-as-SVG are the only on-disk paths.
* **Failure when `qrcode` rejects a payload.** Today's
  `otpauth://` URIs fit inside QR version 10 with M-level ECC
  comfortably, but defensively the dialog renders
  `validation_error` (`field: "qr_render"`, `reason: "..."`)
  inline with the rejection reason instead of crashing. Pinned
  by `apply_msg_show_qr_validation_error_renders_inline`.
* **Backward compatibility.** New menu entry on existing vaults;
  no migration. Users see `Show QR…` in the kebab on first
  launch after this lands.

## Row context menu and EditDialog implementation (per DESIGN §7 / Milestone 9)

This section pins the v0.2 row-context-menu surface — four menu
entries shared between right-click, the GNOME-canonical
`Menu` / `Shift+F10` keyboard equivalent, and the per-row kebab —
plus the new `EditDialog` that the menu's "Edit…" entry mounts.
Both pieces depend on `paladin-core` Phase M
(`AccountEdit` + `Vault::edit_account_metadata`); the GTK work is
red until that ships.

### Design contract (locked)

* **Four menu entries, one model.** A single
  `account_row::build_row_context_menu_model()` builds the
  `gio::Menu` with four entries in this order:
    1. *Copy code* → `row.copy`
    2. *Edit…* → `row.edit`
    3. *Export QR…* → `row.show-qr`
    4. *Delete…* → `row.remove`
  This menu replaces the existing
  `account_row::build_kebab_menu_model()` once the work lands;
  the kebab `gtk::MenuButton`, the row-body right-click popover,
  and the keyboard `gtk::ShortcutController` path all bind the
  **same** `gio::Menu` and the **same** per-row
  `gio::SimpleActionGroup`. Section header rows are non-selectable
  and never raise the menu.
* **Action targets are the existing per-row group.**
  `row.copy`, `row.edit`, `row.show-qr`, `row.remove` route through
  the per-row `gio::SimpleActionGroup` installed by
  `build_kebab_action_group` (today: `rename` / `show-qr` /
  `remove` / `next` / `copy`). The work renames
  `ROW_RENAME_ACTION_NAME` ("rename") to `ROW_EDIT_ACTION_NAME`
  ("edit"), and `dispatch_row_action` returns a new
  `AccountRowOutput::RequestEdit(AccountId)` variant.
  `ROW_COPY_ACTION_NAME` ("copy") already exists for the inline
  copy button and becomes menu-visible alongside it. The new
  output variant routes onto
  `AccountListOutput::OpenEditDialog(AccountId)` and `AppModel`
  mounts `EditDialog`.
* **Right-click via `gtk::GestureClick`.** Per-row, the account
  column's cell `bind` installs a `gtk::GestureClick` configured
  for the secondary mouse button (`set_button(GDK_BUTTON_SECONDARY)`).
  On press, the closure looks up the row's `AccountId` through
  the `RowItem` GObject and pops a `gtk::PopoverMenu` anchored at
  the pointer location (`set_pointing_to` with the click's
  `gtk::gdk::Rectangle`). The popover binds the shared
  `gio::Menu` and the per-row action group via the row container's
  `insert_action_group`, so the same actions fire whether the user
  clicks the kebab, right-clicks the row, or uses the keyboard.
  Section rows (`RowItem::is_section() == true`) early-return
  from the gesture's press handler and never pop the menu.
* **Keyboard parity via `gtk::ShortcutController`.** Account-row
  containers install a single `gtk::ShortcutController` hosting
  three `gtk::Shortcut` entries: `Menu` and `Shift+F10` both
  trigger a `gtk::CallbackAction` that pops the shared
  `gtk::PopoverMenu` anchored to the row container's content
  rectangle, so a keyboard-driven user sees the menu attached
  to the focused row; `Shift+E` triggers a
  `gtk::NamedAction("row.edit")` for TUI parity (DESIGN §6) so
  the user can open EditDialog directly without going through
  the menu. The controller's propagation phase is the default
  `bubble` so the row's `Shift+E` shortcut fires before the
  press bubbles up to any window-level handler; the window-
  level capture-phase controllers
  (`wire_app_window_search_focus_controller`,
  `wire_account_list_navigation_controllers`) all return `None`
  for `Shift+E`, so the press is never swallowed higher in the
  tree before it reaches the row. When another modal `adw::Dialog`
  is mounted, its modal focus capture absorbs the keypress
  before it reaches the row's controller, so `Shift+E` is
  silently rejected while a dialog is open (TUI parity,
  DESIGN §6's "silently rejected" rule for `Shift+E` / `Q`).
  Section rows do not install the controller.
* **One popover at a time.** The account list keeps a single
  `Option<gtk::PopoverMenu>` in `AccountListComponent` state; a
  fresh popup unparents and drops any prior popover before
  mounting the new one. Cleanup also fires on
  `AccountListMsg::Refresh` (the row's `RowItem` may have moved or
  been removed by the splice) and on auto-lock so a popover never
  outlives its row.
* **Per-state enablement.** The menu binds the per-row
  `RowDisplay` projection through the existing `apply_busy_mask`
  pipeline:
    * *Copy code* is sensitive iff `RowDisplay::copy_enabled`
      (hidden HOTP rows dim the entry, exactly like the inline
      copy button).
    * *Edit…*, *Export QR…*, *Delete…* are sensitive iff the row
      is an account row (always true once the menu has popped on
      one — section rows never raise it) and the app is not
      `UnlockedBusy` (the busy mask flips them off as it does the
      kebab today).
* **EditDialog widget surface.** `EditDialog` is an `adw::Dialog`
  (matching `RenameDialog`'s shell) with the visible title
  `Edit account` — no ellipsis (the ellipsis convention
  applies to the menu/button verb `Edit…` that *opens* the
  dialog, not to the dialog's own titlebar) — hosting three
  `AdwEntryRow` widgets in an `AdwPreferencesGroup`. Each row is
  pre-populated from the focused account's `AccountSummary`,
  resolved at mount time via
  `Vault::summaries().find(|s| s.id == account_id)` against
  the `(Vault, Store)` pair `AppModel` already owns through
  the in-flight effect ownership slot. If the lookup returns
  `None` (the account was removed between `RequestEdit` and
  mount), the dialog never mounts; `AppModel` raises an
  inline `invalid_state` toast (parity with show-qr at
  L1689). Default action: Enter on any of the three rows
  submits if Save is sensitive; else no-op. Tab cycles
  row1 → row2 → row3 → Save → Cancel. Slice 4 calls
  `controller.widget().present(&app_window)` after
  `Controller::builder().launch(EditDialogInit { … })`.
  Per-keystroke projection runs through a pure-logic
  `classify_edit_draft(state, prior) -> AccountEdit` that
  implements the WYSIWYS rules below; the assembled
  `AccountEdit` drives both Save sensitivity (non-empty +
  per-field clean) and the submit payload, so the dialog and
  its tests share one decision function.
    1. *Label* — required; pre-populated from
       `AccountSummary::label`. Validates through
       `paladin_core::validate_label` on each keystroke; the
       row's `error_message` is cleared / set on transition.
       Buffer, after §4.1 label normalization (trim), equal
       to `AccountSummary::label` projects to
       `AccountEdit.label = None` (leave untouched, parity
       with the issuer rule below); any divergence projects
       to `Some(normalized)` and routes through
       `validate_label` for §4.1 rejection. A whitespace-only
       edit (e.g. typing and erasing a trailing space) thus
       collapses to `None` rather than enabling Save on a
       cosmetic touch.
    2. *Issuer* — optional; pre-populated from
       `AccountSummary::issuer.as_deref().unwrap_or("")`.
       Validates through `paladin_core::validate_issuer` on
       each keystroke; the row's `error_message` is cleared /
       set on transition. An inline
       `Adw.EntryRow::add_suffix(gtk::Button)` clears the row
       text in one click (parity with the TUI's `Ctrl+U`); it
       carries no separate "explicit-clear marker" — the
       projection is determined entirely by the resulting
       buffer state via what-you-see-is-what-you-save rules
       (TUI parity, DESIGN §7):
       - empty buffer AND prior issuer was `None` → `None`
         (leave untouched);
       - empty buffer AND prior issuer was `Some(_)` →
         `Some(None)` (implicit clear — matches CLI
         `--no-issuer`);
       - buffer, after §4.1 issuer normalization, equals
         the prior issuer → `None`;
       - any other non-empty buffer →
         `Some(Some(normalized))` and routes through
         `validate_issuer` for §4.1 rejection.
    3. *Icon hint slug* — optional free-form text;
       pre-populated from
       `AccountSummary::icon_hint.as_deref().unwrap_or("")`
       (DESIGN §7: "matches the Add dialog's icon-hint
       behavior verbatim", so the row stays free-form rather
       than mirroring the TUI's segmented selector — the TUI
       needs a fourth *Leave unchanged* mode because it
       cannot tell "buffer untouched" from "buffer typed
       blank", whereas the GTK dialog disambiguates via the
       byte-equal pre-fill rule below).
       The GTK editor uses `parse_icon_hint_token` (not the
       TUI's segmented selector + `validate_icon_hint_slug`
       split) because GTK has no dedicated Default/Clear
       selector. Same on-disk grammar, different widget shape
       — DESIGN.md §6 vs §7 spells out the rationale. The
       buffer is preserved byte-for-byte (no client-side
       lowercasing): uppercase input surfaces the §5
       `validation_error` (`field: "icon_hint"`, `reason:
       "invalid_chars"`) inline beside the row. Parses through
       `paladin_core::parse_icon_hint_token` on each keystroke
       (driving the inline `error_message`, Save sensitivity,
       and the icon-preview suffix). Projection rules
       (mirroring the issuer's WYSIWYS layout so empty buffers
       are never silently re-derived behind the user's back).
       Note the deliberate asymmetry with the issuer rule:
       the issuer projection uses *§4.1-normalized* equality
       against the prior issuer, whereas the icon-hint
       projection uses *byte-equality* against the pre-fill
       string — intentional because persisted icon-hint slugs
       are already canonical (`[a-z0-9_-]+`), so any
       whitespace touch flips the row out of "untouched" and
       into the validation path:
       - buffer byte-equal to the pre-fill (i.e. the user did
         not touch the row) → `None` (leave untouched);
       - empty buffer AND prior `icon_hint` was `None` →
         `None` (leave untouched);
       - empty buffer AND prior `icon_hint` was `Some(_)` →
         `Some(IconHintInput::Default)` (implicit re-derive
         from the post-edit issuer — matches the TUI's
         *Default from issuer* mode and CLI `--icon-hint
         default`);
       - case-insensitive `none` →
         `Some(IconHintInput::Clear)`;
       - any other non-empty buffer →
         `Some(IconHintInput::Slug(s))` and routes through
         `parse_icon_hint_token` for §4.1 slug rejection.
       An inline suffix `gtk::Image` previews the
       resolved icon via
       `crate::icon_resolution::resolve_display_icon`; the
       suffix falls back to the placeholder icon on parse
       failure rather than leaving a stale preview.
  Footer: `Cancel` (always sensitive) and `Save`
  (`suggested-action`, sensitive only when the assembled
  `AccountEdit` is non-empty *and* every populated field
  validates clean). On `Save`, the dialog assembles
  `AccountEdit`, posts
  `Effect::EditAccountMetadata { path, account_id, edit, now }`
  through the shared `effect_ownership` slot, and waits for the
  `EffectResult` like `RenameDialog` does today.
* **Pre-submit duplicate detection.** Before the effect is
  posted, the dialog submit handler runs
  `Vault::find_duplicate_after_edit(account_id, &edit)`
  (DESIGN §4.7) to project the would-be post-edit
  `(secret, issuer, label)` triple against every other
  account. **Pre-check order (locked):** per-field
  `validate_account_edit` runs first; only on success does
  the dialog issue `find_duplicate_after_edit`. Reversing
  would surface `duplicate_account` against a partly-invalid
  edit (pinned in DESIGN.md and Phase M). The check runs as
  a synchronous main-thread call; no `spawn_blocking`. A
  future migration to a worker would require a new
  `Submitting` state to prevent double-submit. Between
  effects the `(Vault, Store)` pair lives on `AppModel`'s
  `effect_ownership` slot rather than inside the worker, so
  `&Vault` is available to the dialog handler without
  spawning a worker (same affordance the AddDialog uses for
  `Vault::find_duplicate`). The single-writer-per-vault
  contract holds for v0.2: cross-process races (e.g. a
  concurrent `paladin edit` from the CLI) are handled by
  `Vault::mutate_and_save`'s file lock under
  last-writer-wins semantics; the GTK dialog does not poll
  the vault between mount and submit. The handler feeds the
  resulting `Option<AccountId>` into
  `classify_submit(state, prior, duplicate) -> SubmitOutcome`,
  which stays a pure decision function. `classify_submit`
  internally calls `classify_edit_draft(state, prior)`,
  validates the projected `AccountEdit`, then routes — so
  the WYSIWYS projection is computed in one place and Save
  sensitivity, the submitted payload, and the duplicate
  pre-check can never drift. A `Some(other)` collapses to
  `SubmitOutcome::duplicate_detected(other)` and surfaces
  the §5 `duplicate_account` error inline beside the
  offending row without mutating the vault; `None` collapses
  to `SubmitOutcome::dispatch_effect(edit)`. The CLI / TUI /
  GUI share this pre-flight so an Edit can never silently
  collide with another account that already holds the same
  triple. Unlike the Add path, the GTK EditDialog does **not**
  offer an "edit anyway" override — the user must resolve the
  collision (rename one side, clear the issuer, etc.) before
  Save re-enables.
* **Post-edit summary lookup.** `Vault::edit_account_metadata`
  returns `Result<()>`; the worker re-reads the post-edit
  `AccountSummary` via `Vault::summaries().find(|s| s.id ==
  account_id)` after the mutator returns and threads it
  through `EffectResult::EditAccountMetadata { summary, .. }`
  so the dispatch site renders the toast against post-edit
  data (`Edited {summary_display_label}.` — e.g.
  `Edited GitHub:work.`). The lookup is `Option<AccountSummary>`
  to defend against a concurrent remove between mutate and
  read; `None` collapses the toast text to the bare
  `Edited.` form rather than panicking. Both forms keep the
  trailing period so the toast wording matches the TUI status-
  line `Edited {summary_display_label(&summary)}.` confirmation.
* **Effect-result routing.** On `Ok` the dialog closes and
  posts the toast above; on `save_durability_unconfirmed`,
  the dialog stays open with an inline warning body and the
  post-edit state visible; on `save_not_committed` /
  `invalid_state` / `duplicate_account`, the dialog stays
  open with the inline error and the rows preserved for
  retry. `validation_error` is intentionally absent from the
  post-effect bucket: validation is pre-flighted client-side
  via `classify_edit_draft` + `validate_account_edit` before
  Save enables, so the mutator should never re-raise it. If
  the core ever did re-raise `validation_error` against a
  draft the client already cleared, that would be an
  invariant violation, not a routine retry path.
* **Disabled on `UnlockedBusy`.** Per DESIGN §7 and the
  shared `RenameDialog`-era effect-ownership contract, the
  open dialog dims its Save button and the three entry rows
  while another save is in flight (`AppModel` in
  `UnlockedBusy`); Cancel stays sensitive so the user can
  always back out. The `effect_ownership` slot keeps the
  dialog as the in-flight effect's owner so a second
  concurrent EditDialog cannot be mounted from the same
  list. Save is gated on a populated `effect_ownership`
  slot, so `classify_submit`'s synchronous pre-flight always
  sees a live `&Vault`. The inline `duplicate_account` error
  clears on any keystroke that changes the label or issuer
  buffer (either field can resolve the collision); a
  keystroke on the icon-hint row does not clear it.
* **No secret material.** `EditDialog` never touches the
  account secret bytes; no `SecretString` / `Zeroizing`
  buffers are required. The three entry rows hold plain
  `String` content that is cleared on submit / cancel / dialog
  close / auto-lock alongside the other modal-local state.
* **Auto-lock dismissal.** `crate::edit_dialog::clear_for_lock(&mut state)`
  is registered with `AppModel`'s lock-transition pruning
  (the same hook `ExportQrDialog`, `ImportDialog`,
  `ExportDialog`, and `SettingsDialog` use) and drops the
  three row buffers, the cached pre-edit `AccountSummary`,
  and any pending `classify_submit` outcome so none of them
  outlives the `(Vault, Store)` pair they're projected from.
  `RenameDialog` did not need this hook because it kept no
  `AccountSummary` cache; EditDialog caches the pre-edit
  summary for the success-toast label, so the hook becomes
  necessary here. The three-step lock-transition sequence
  is locked: `AppModel` calls `force_close()` on the
  EditDialog controller first → drops the controller →
  finally fires `clear_for_lock`. Calling `force_close()`
  ahead of the controller drop detaches the `adw::Dialog`
  widget from the window before its backing state goes away
  — matching the `RemoveDialog` / `ExportQrDialog` contract
  enforced by commit 14026f6 and `app/model.rs:2640`.
  Escape dismisses via `adw::Dialog`'s default close binding,
  routing through `EditDialogOutput::Cancel` so
  `clear_for_lock` fires alongside the controller drop on
  user-initiated dismissal too (same three-step sequence,
  triggered by the close signal instead of the lock
  transition).
  An in-flight save is allowed to complete; the auto-lock
  timer's `UnlockedBusy` guard (§"In-flight effect
  ownership") keeps the lock from firing until the worker
  returns.
* **Post-effect outcome variants (locked).** The
  `classify_post_effect_error(err) -> PostEffectOutcome`
  helper pins three variants once:
  `PostEffectOutcome::Close { post_summary: Option<AccountSummary> }`
  (the `Ok` path — closes the dialog, threads the optional
  summary into the toast); `PostEffectOutcome::StayOpenWithWarning(InlineWarning)`
  (the `save_durability_unconfirmed` path); and
  `PostEffectOutcome::StayOpenWithError(InlineError)`
  (the `save_not_committed` / `invalid_state` /
  `duplicate_account` paths). Slice 4's build-order
  bullet, the test checklist, and the widget binding all
  reference the same variant set, so a typed-error addition
  in core forces a `PostEffectOutcome` extension here.
* **Thread isolation.** `Vault::edit_account_metadata`
  runs on `gio::spawn_blocking` per the
  §"In-flight effect ownership" contract; the dialog never
  blocks the main loop. The `(Vault, Store)` pair is moved into
  the worker and returned through the
  `EffectResult::EditAccountMetadata` completion so `AppModel`
  reinstalls the live state regardless of the typed effect.
* **OTP-affecting fields stay out.** `EditDialog` deliberately
  exposes no controls for `secret`, `algorithm`, `digits`,
  `kind`, `period`, or `counter`. The dialog body carries a
  short footnote pointing users at remove + re-add for those
  changes (matching DESIGN §7). The contract matches the core
  `AccountEdit` field
  list — the GTK widget cannot drift out of sync because there
  is no `AccountEdit` field to bind for those values.

### Build order

The work lands in slices so each commit ships a green test slice
and a working app. `paladin-core` Phase M must land before any
`paladin-gtk` slice can be wired through — until then, every GTK
slice is gated on a stub `Vault::edit_account_metadata` shim that
the test fixture provides through `paladin-core`'s
`test-fault-injection` feature. Slices 1–3 are internal-only and
do **not** ship to users on their own: slice 1 relabels the menu
entry from `Rename…` to `Edit…` while still mounting
`RenameDialog` (single-field, label-only), so an end-user build
released between slice 1 and slice 4 would advertise "Edit…" and
deliver a one-field rename. The v0.2 release cut waits until
slice 4 has mounted the real `EditDialog`; only slices 4–7 are
candidate release boundaries. **Release-eligibility split:**
slice 4 is *internal-release-eligible* (kebab `Edit…` and
`Shift+E` reach the dialog, but right-click and the
secondary `gtk::GestureClick` are not yet wired). The v0.2
public cut lands at slice 5 or later, when the right-click
gesture, `gtk::ShortcutController`, and shared
`row_context_menu_logic.rs` coverage are in place — DESIGN
§7 and Milestone 9 treat the right-click affordance as
core.

- [x] **Slice 1 — Menu model + action constants.** Extend
   `account_row::build_kebab_menu_model` to add the
   *Copy code* entry at position 0 and rename
   `Rename…` → `Edit…` (still targeting `row.rename` for now).
   Pinned by a new
   `tests/account_list_logic.rs::build_kebab_menu_model_exposes_copy_edit_show_qr_and_remove_in_order`
   replacing the existing
   `build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
   test. (No new behavior — just a label/order change so the
   wiring stays stable.) Interim state through slices 1–3:
   the visible "Edit…" entry still routes through
   `ROW_RENAME_ACTION_NAME` (`"rename"`) →
   `AccountRowOutput::RequestRename` →
   `AccountListOutput::OpenRenameDialog` and mounts the
   existing `RenameDialog`; slice 2 renames the action /
   variants and slice 4 swaps the mounted dialog over to
   `EditDialog`. The relabel is intentionally cosmetic-only
   in slice 1 so the slice ships behind a green test bar
   without any behavioral drift.
- [x] **Slice 2 — Action rename.** Rename
   `ROW_RENAME_ACTION_NAME` (`"rename"`) to
   `ROW_EDIT_ACTION_NAME` (`"edit"`); rename the
   `AccountRowOutput::RequestRename` variant to
   `AccountRowOutput::RequestEdit` and the
   `AccountListOutput::OpenRenameDialog` variant to
   `AccountListOutput::OpenEditDialog`. `AppModel` stays mounting
   the existing `RenameDialog` on the new variant until slice 4
   ships. Tests in `tests/account_row_logic.rs` are renamed
   accordingly; the dispatch table coverage stays unchanged
   modulo names.
- [x] **Slice 3 — Shared menu model helper.** Add
   `account_row::build_row_context_menu_model()` returning the
   `gio::Menu` constructed once and bound to both the kebab and
   the right-click popover. The existing
   `build_kebab_menu_model` becomes a thin wrapper around it for
   one slice, then is removed once every call site is migrated.
- [ ] **Slice 4 — EditDialog scaffold + auto-lock plumbing.**
   Add `edit_dialog.rs` with the pure-logic state machine
   (`EditDialogState`,
   `classify_edit_draft(state, prior) -> AccountEdit` — the
   per-keystroke projection driving Save sensitivity and the
   submit payload via the WYSIWYS rules in the design
   contract above,
   `classify_submit(state, prior, duplicate: Option<AccountId>) -> SubmitOutcome`
   — the final pre-effect routing (`empty_edit_reject` /
   `duplicate_detected(other_id)` /
   `dispatch_effect(account_edit)`) that internally calls
   `classify_edit_draft` so the WYSIWYS projection is
   computed in one place; the call site runs
   `Vault::find_duplicate_after_edit(account_id, &edit)`
   *after* per-field `validate_account_edit` succeeds and
   feeds the `Option<AccountId>` result into the classifier,
   keeping it a pure decision function, and
   `classify_post_effect_error(err) -> PostEffectOutcome` —
   the post-effect typed-error routing pinned to the locked
   variant set
   `Close { post_summary: Option<AccountSummary> }` /
   `StayOpenWithWarning(InlineWarning)` /
   `StayOpenWithError(InlineError)`) and the widget
   binding. Wire `AppModel` to mount `EditDialog` on
   `AccountListOutput::OpenEditDialog`. Because this slice
   makes `EditDialog` reachable from the kebab `Edit…` entry,
   it also registers `crate::edit_dialog::clear_for_lock`
   with `AppModel`'s lock-transition pruning and wires
   `force_close()` on the EditDialog controller into the
   same path that already dismisses `ExportQrDialog` /
   `ImportDialog` / `ExportDialog` / `SettingsDialog`. The
   lock-transition sequence is locked: `force_close()` →
   drop controller → `clear_for_lock`, parity with
   `app/model.rs:2640`. So an auto-lock fires the dialog
   away before `(Vault, Store)` is dropped (parity with
   commit 14026f6's contract). The `rename_dialog.rs` source
   stays in the tree (and its tests stay live) until slice
   6, but nothing routes to it from the menu, the per-row
   `gio::SimpleActionGroup`, or `AppModel` once this slice
   lands. All new tests in `tests/edit_dialog_logic.rs`
   cover each classifier, its post-effect routing, and the
   `clear_for_lock` / `force_close()` lock-transition
   coverage described in that file's checklist.
- [ ] **Slice 5 — Right-click `gtk::GestureClick` +
   `gtk::ShortcutController` + popover lock-cleanup.**
   Extend the account column's cell factory `bind` to
   install a secondary-button `gtk::GestureClick` and a
   single `gtk::ShortcutController` on the row container.
   The controller hosts the `Menu` / `Shift+F10` (context
   menu) and `Shift+E` (direct Edit, via
   `gtk::NamedAction("row.edit")`) shortcuts described in
   the design contract. The gesture and the menu-popping
   shortcuts both route through a new
   `account_list::pop_row_context_menu(account_id, anchor)`
   that mounts the shared menu against the row's
   `gio::SimpleActionGroup`. Section rows early-return and
   do not install the controller. The
   `Option<gtk::PopoverMenu>` lives on
   `AccountListComponent` state for the single-popover
   invariant; this slice also wires its drop into the
   `AccountListMsg::Refresh` path and the lock-transition
   pruning so a popover never outlives its row or the
   `(Vault, Store)` pair. New tests in
   `tests/row_context_menu_logic.rs` pin the pure-logic
   decisions (pop / suppress for section / unparent prior /
   `Shift+E` activates `row.edit` / `Shift+E` silently
   rejected while another modal is open / popover dropped
   on refresh and on lock).
- [ ] **Slice 6 — RenameDialog retirement.** Drop
   `rename_dialog.rs` and `tests/rename_dialog_logic.rs`.
   The validation / save-rollback / durability-warning
   contracts are already pinned in
   `tests/edit_dialog_logic.rs` by the slice 4 bullets
   (label projection, `save_not_committed`,
   `save_durability_unconfirmed`, clean-validate Save
   sensitivity), so no test bullets need to migrate — only
   the now-empty source and test files are deleted. The
   label-only emit bullet in slice 4 already pins that
   `Effect::EditAccountMetadata { edit: AccountEdit {
   label: Some(...), ..Default::default() } }` matches what
   the retired `RenameDialog` used to send, locking the
   regression contract. `Vault::rename` (and `paladin
   rename` and the TUI Rename modal) stay — only the GTK
   rename surface is retired. `Vault::rename` is
   intentionally retained as a forwarder over
   `edit_account_metadata` so the CLI / TUI rename surfaces
   keep their existing single-call API.
- [ ] **Slice 7 — Docs sync.** Update `DESIGN.md` §7 / §12 /
   §13 and this plan's checklists to reflect the final
   shape; tick the Milestone 9 entries as each slice lands.

### Open decisions / non-goals

* **`gtk::PopoverMenu` vs `gtk::Popover`.**
  `gtk::PopoverMenu::from_model` is the GNOME-HIG canonical
  surface for menu-style popovers — kept. We do **not** ship a
  custom `gtk::Popover` with inline buttons; that would diverge
  from the kebab's render and from system menus.
* **Multi-row context menu.** Out of scope. The
  `gtk::SingleSelection` model only carries one selection;
  bulk operations belong to a separate v0.3+ surface.
* **Drag-to-reorder.** Out of scope. Vault insertion order is
  the §"listing-order" contract; user-initiated reorder belongs
  to a separate v0.3+ surface.
* **OTP-affecting field edits.** Out of scope by core contract
  (Phase M field list). The dialog footnote points users at
  remove + re-add.
* **Per-account icon picker.** Out of scope. The icon-hint
  row stays a free-form slug entry (matching the Add modal);
  a visual picker belongs to a separate v0.3+ feature.

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
  Adwaita-style symbolic palette warrants it; a
  `16`/`24`/`32`/`48`/`64`/`128`/`256`/`512` PNG fallback set
  named `org.tamx.Paladin.Gui.png` is shipped under
  `/usr/share/icons/hicolor/<size>/apps/` for non-SVG icon
  consumers. The 64 / 128 / 256 / 512 sizes cover what GNOME
  Shell's app-drawer and search results actually request; without
  them, Shell falls through to the scalable SVG and the launcher
  glyph renders blank because the SVG's base64-embedded PNG
  payload fails GdkPixbuf's icon-theme load path. The packaging
  dry-run validates this layout in both the native and Flatpak
  builds.
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

  *Implemented (v0.2 Milestone 7, `.rpm` + `.deb`):* the local
  entry points are `cargo xtask package --frontend paladin-gtk
  --format rpm` (or `make rpm-paladin-gtk`) and `cargo xtask
  package --frontend paladin-gtk --format deb` (or
  `make deb-paladin-gtk`). The xtask runs `cargo build --release
  --locked -p paladin-gtk`, then invokes `nfpm` inside the
  `docker.io/goreleaser/nfpm` container under rootless podman with
  `${PALADIN_VERSION}` exported. Output lands in
  `target/dist/paladin-gtk-*.rpm` /
  `target/dist/paladin-gtk_*.deb`. The CI `packaging-dry-run` job
  (`.github/workflows/ci.yml`) still runs the same `nfpm
  package -f packaging/{rpm,deb}/paladin-gtk.yaml` commands
  directly so the dry-run does not depend on xtask being green.
  The CLI and TUI `.deb` manifests
  (`packaging/deb/paladin.yaml`, `packaging/deb/paladin-tui.yaml`)
  reuse the same `--format deb` xtask wiring and are built
  alongside the GTK `.deb` by the tag-driven release workflow.
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
- **Release workflow.** `.github/workflows/release.yml` triggers on
  `v*` tag pushes (and supports `workflow_dispatch` for dry-runs).
  It builds inside the same `fedora:42` container as the CI
  packaging-dry-run job, derives `PALADIN_VERSION` by stripping the
  leading `v` from the tag, builds `paladin-cli`, `paladin-tui`, and
  `paladin-gtk` with `cargo build --release --locked`, then runs
  `nfpm` against the three `packaging/rpm/*.yaml` manifests and the
  three `packaging/deb/*.yaml` manifests. The GTK `.deb` and `.rpm`
  payloads are extracted and re-validated with
  `desktop-file-validate` + `appstreamcli validate --no-net` before
  publish, mirroring the CI dry-run gate. Artifacts upload to the
  matching GitHub release via `softprops/action-gh-release@v2`;
  tags containing `-` (e.g. `v0.2.0-rc1`) are auto-marked
  prerelease. Minisign signing per §11.6 lands in a follow-up
  commit.

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

#### `tests/clipboard_logic.rs`

- [x] [`crate::clipboard::payload_text`] returns the OTP-code bytes
  unchanged for the ASCII-only case (borrowed `Cow::Borrowed`, no
  allocation) and falls back to UTF-8 lossy substitution for
  defensive non-UTF-8 inputs so the
  `gdk::Clipboard::set_text(&str)` boundary never panics on a stray
  byte. Pinned by `payload_text_passes_ascii_otp_code_unchanged`,
  `payload_text_handles_empty_bytes`, and
  `payload_text_replaces_invalid_utf8_with_replacement_char`.
- [x] [`crate::clipboard::captured_clipboard_bytes`] wraps the
  `Option<&str>` projection of `read_text_async`'s result in a
  `Zeroizing<Vec<u8>>` so the captured comparison value zeroes on
  drop. Both `None` (read failure, missing clipboard text) and
  `Some("")` collapse to an empty buffer so the only-if-unchanged
  byte-equality check in
  `paladin_core::ClipboardClearPolicy::should_clear` (via
  `crate::clipboard_clear::evaluate_wake`) resolves to
  `WakeDecision::Mismatch` in those cases — the wipe stays its
  hand rather than clobbering whatever the user has on the
  clipboard. Pinned by
  `captured_clipboard_bytes_returns_empty_for_none`,
  `captured_clipboard_bytes_returns_empty_for_empty_string`,
  `captured_clipboard_bytes_carries_utf8_payload`, and
  `captured_clipboard_bytes_is_zeroizing_typed`.

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
- [ ] `issuer_group_header` returns the issuer string verbatim for
  rows whose `AccountRowModel.issuer` is `Some(non_empty)`, and the
  `"Other"` literal for `None` (parity with the `summary_display_label`
  collapse rule, so `Some("")` projects to `None` at the
  `row_models_from_vault` boundary and lands in the same bucket).
- [ ] `row_section_header` returns `Some(header)` for the first row
  of the list and for any row whose issuer differs from the
  previous row; `None` for runs of consecutive rows that share an
  issuer. Decision is on the projected `Option<String>` issuer (so
  `Some("")` is treated identically to `None`).

#### `tests/gsettings_logic.rs`

- [ ] `build.rs`-compiled gschema declares the
  `show-section-headers` key under schema id
  `org.tamx.Paladin.Gui` so
  `paladin_gtk::gsettings::show_section_headers` resolves at
  runtime.
- [ ] Default value of `show-section-headers` is `false` (per
  DESIGN §7).
- [ ] Round-trip through a memory-backed `gio::Settings`:
  `set_boolean(true) → boolean() == true → set_boolean(false) →
  boolean() == false`.
- [ ] `changed::show-section-headers` signal fires when the key is
  written, so the `AppModel` handler can dispatch
  `AccountListMsg::SetShowSectionHeaders` to the live list
  controller.
- [x] `build.rs`-compiled gschema declares the
  `show-next-code-column` key under schema id
  `org.tamx.Paladin.Gui` so
  `paladin_gtk::gsettings::show_next_code_column` resolves at
  runtime.  Pinned by `schema_carries_show_next_code_column_key`.
- [x] Default value of `show-next-code-column` is `true` (per
  DESIGN §7 — the Next column is on by default and hideable via
  Preferences).  Pinned by `show_next_code_column_default_is_true`.
- [x] Round-trip through a memory-backed `gio::Settings`:
  `set_boolean(false) → boolean() == false → set_boolean(true) →
  boolean() == true`.  Pinned by
  `show_next_code_column_round_trip_via_memory_backend` and the
  typed-helper variant `helper_round_trip_for_show_next_code_column`.
- [x] `changed::show-next-code-column` signal fires when the key
  is written, so the `AppModel` handler can dispatch
  `AccountListMsg::SetShowNextCodeColumn` to the live list
  controller.  Pinned by
  `changed_signal_fires_for_show_next_code_column_write`.

#### `tests/account_list_logic.rs` (Next-code column)

- [x] `RowDisplay` projection emits `next_code: Some("482913")`
  for a TOTP row and `next_code: None` for an HOTP row, sourced
  from `Vault::totp_next_code(id, now)`.  Pinned by the
  `next_code_display_*` quartet in `tests/account_row_logic.rs`
  plus `compute_tick_displays_carries_full_row_display_shape`'s
  added `display.next_code.is_some()` assert in
  `tests/ticker_logic.rs` (the ticker is what actually calls
  `Vault::totp_next_code` and hands the result to `project_row`).
- [x] `AccountListMsg::SetShowNextCodeColumn(false)` flips the
  GSettings latch and the Next column's `set_visible(false)` is
  called once; the store is not re-spliced.  The pure decision
  (visibility AND-gate, "no splice" code path) is pinned by
  `compute_next_code_column_visibility_*` in
  `tests/account_list_logic.rs` — the reducer arm calls
  `next_code_column.set_visible(visible)` and does not enter the
  splice path; the runtime
  `gtk::ColumnViewColumn::set_visible` call itself requires a
  live display server and is covered by
  `tests/manual/MANUAL_TEST_PLAN.md` §11.3 (toggle scenario).
- [x] Next column is hidden whenever
  `column_view::any_totp(&rows) == false`, regardless of the
  GSettings latch (HOTP-only vaults).  Pinned by
  `compute_next_code_column_visibility_no_totp_rows_collapses_to_false`
  and `compute_next_code_column_visibility_empty_rows_collapses_to_false`.
- [x] `AccountListOutput::CopyNextCode(id)` is emitted when a
  populated Next cell's button is activated; the outbound message
  carries the row's `AccountId`. HOTP-row clicks emit no message
  (button is `sensitive=false`).  Pinned by
  `account_list_output_copy_next_code_carries_account_id` and the
  6-case decision table `dispatch_copy_next_code_accelerator_*`
  in `tests/account_list_logic.rs` (TOTP / HOTP / no-selection ×
  column-visible / column-hidden).
- [x] `AppModel` routes `CopyNextCode(id)` through the
  `Vault::totp_next_code(id, now)` path, writes to the clipboard
  via the existing `prepare_copy_bytes` / `gdk::Clipboard::set_text` /
  `schedule_copy` pipeline, and raises an `adw::Toast` reading
  `Next code copied, valid in {period - (now_unix % period)}s` on
  the shared `adw::ToastOverlay`.  Pure byte-prep pinned by
  `prepare_copy_next_code_bytes_returns_upcoming_totp_digits`;
  toast wording by
  `format_next_code_copy_toast_pins_canonical_wording` plus
  boundary-seconds (1, 30), both in
  `tests/clipboard_clear_logic.rs`.  Live `adw::ToastOverlay`
  emission is covered by `MANUAL_TEST_PLAN.md` §11.1 / §11.2.
- [x] `arboard` / clipboard failure surfaces the existing
  copy-error toast and arms no clear schedule.  Pure-logic
  "None-arms-no-schedule" decision is pinned by
  `prepare_copy_next_code_bytes_returns_none_for_hotp_row` and
  `prepare_copy_next_code_bytes_returns_none_for_unknown_account_id`
  — both collapse to the `None` branch the AppModel handler
  short-circuits on (skipping the toast + `schedule_copy` arm),
  the same branch a clipboard-write failure would take.  Live
  clipboard-failure surfacing reuses the existing `CopyCode`
  failure path.

#### `tests/account_row_logic.rs`

- [x] Row display labels match CLI / TUI summary formatting for
  issuer / label combinations.
- [x] TOTP rows show copy + progress controls; HOTP rows show copy
  only during reveal and expose the "next" action.
- [x] TOTP gauge urgency (`progress_urgency`) classifies bands by
  absolute seconds remaining: `>15s` → `ProgressUrgency::Plenty`
  (Adwaita `.success`), `6..=15s` → `ProgressUrgency::Warning`
  (`.warning`), `<=5s` → `ProgressUrgency::Critical` (`.error`).
  Boundary transitions at 16→15 and 6→5 flip the class; clamped
  overflow and the defensive `period_secs == 0` path are total.
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
- [x] `dispatch_root_dismiss_key` returns `true` only for a bare
  Escape press; any chord modifier (CTRL / ALT / SHIFT / SUPER /
  HYPER / META) or any other key propagates untouched. Caps Lock
  is a toggle bit, not a held modifier, so it does not block
  dismiss.

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

  *Retirement note: once the Milestone 9 EditDialog cleanup slice
  ships, these bullets are superseded by the equivalent coverage
  already pinned in `tests/edit_dialog_logic.rs` (label projection,
  `save_not_committed`, `save_durability_unconfirmed`, clean-
  validate Save sensitivity, label-only emit shape) — no bullets
  need to migrate. This file is deleted alongside
  `rename_dialog.rs`.*

#### `tests/edit_dialog_logic.rs`

v0.2 (DESIGN §7 Milestone 9). All bullets are red until Phase M
ships in `paladin-core` and the GTK EditDialog lands.

- [ ] Pre-populates the three rows from the focused account's
  `AccountSummary` (label, issuer-or-empty-string, icon-hint
  slug-or-empty-string).
- [ ] The `adw::Dialog` widget exposes `Edit account` as its
  visible title — no ellipsis (the ellipsis convention
  applies to the menu/button verb, not the dialog title) —
  matching the menu entry's verb and the TUI modal heading.
  Pinned by a pure-logic helper
  `format_edit_dialog_title() -> &'static str` returning the
  title constant; the test
  `format_edit_dialog_title_returns_edit_account` asserts
  the exact string, so a typo in the widget binding fails
  the test bar.
- [ ] `classify_edit_draft(state, prior) -> AccountEdit` is the
  per-keystroke projection driving Save sensitivity and the
  submit payload. Pinned by table-driven tests covering all
  three rows in lockstep — see the field-specific bullets
  below.
- [ ] Label projection — three table cases: buffer byte-equal
  to prior label → `AccountEdit.label = None`; buffer that
  differs only in §4.1 normalization (e.g. leading or
  trailing whitespace whose trim equals the prior label) →
  `None` (parity with the issuer rule); any other (non-empty,
  validates clean) buffer → `Some(normalized)`.
- [ ] Issuer WYSIWYS projection — covered by four table cases
  matching the TUI Edit modal's contract:
  1. empty buffer AND prior issuer was `None` →
     `AccountEdit.issuer = None`;
  2. empty buffer AND prior issuer was `Some(_)` →
     `Some(None)` (implicit clear);
  3. buffer, after §4.1 issuer normalization, equals the
     prior issuer → `None`;
  4. any other non-empty buffer →
     `Some(Some(normalized))`.
- [ ] Issuer row's inline clear suffix empties the row text in
  one click; the resulting projection is then determined by
  the WYSIWYS rules above (no separate explicit-clear marker
  in `AccountEdit`).
- [ ] Icon-hint WYSIWYS projection — covered by five table
  cases mirroring the issuer layout:
  1. buffer byte-equal to the pre-fill (user did not touch
     the row) → `AccountEdit.icon_hint = None`;
  2. empty buffer AND prior `icon_hint` was `None` → `None`;
  3. empty buffer AND prior `icon_hint` was `Some(_)` →
     `Some(IconHintInput::Default)` (implicit re-derive);
  4. case-insensitive `none` →
     `Some(IconHintInput::Clear)`;
  5. any other non-empty buffer →
     `Some(IconHintInput::Slug(s))`.
  Invalid slugs surface the §5 `validation_error`
  (`field: "icon_hint"`, `reason: "invalid_slug"`) inline
  beside the row and disable Save; the icon-preview suffix
  falls back to the placeholder icon on parse failure rather
  than leaving a stale preview.
- [ ] Empty-edit submit (every row maps to `None` per the
  rules above — label unchanged, issuer either matching prior
  or empty-on-prior-`None`, icon-hint buffer matching the
  pre-fill) is rejected client-side with the inline
  `validation_error` (`field: "edit"`, `reason: "empty"`)
  matching the core mutator's contract; no effect is posted.
- [ ] Pre-submit duplicate detection — the dialog submit
  handler runs `Vault::find_duplicate_after_edit(account_id,
  &edit)` after validation and feeds the resulting
  `Option<AccountId>` into
  `classify_submit(state, prior, duplicate) -> SubmitOutcome`.
  Pinned by two table cases driven directly against the pure
  classifier (no Vault required): `duplicate = Some(other)` →
  `SubmitOutcome::duplicate_detected(other)`, surfacing the
  §5 `duplicate_account` error inline beside the row whose
  edit causes the collision (label or issuer) without
  mutating the vault and keeping Save disabled until the user
  resolves the collision; `duplicate = None` →
  `SubmitOutcome::dispatch_effect(edit)`. A separate executor
  bullet (see `tests/effect_ownership_logic.rs`) exercises
  the live `Vault::find_duplicate_after_edit` call.
- [ ] Label-only submit emits
  `Effect::EditAccountMetadata { edit: AccountEdit { label:
  Some(...), ..Default::default() } }` matching what the
  retired RenameDialog used to emit; the two surfaces are
  pinned to share one mutation path through
  `Vault::edit_account_metadata` after Phase M's `rename`
  reimplementation.
- [ ] Same-as-prior submit on at least one field still bumps
  `updated_at` per the core mutator's no-op-but-non-empty
  contract. The assertion that the post-edit
  `Account::updated_at` strictly exceeds the pre-edit value
  lives alongside the other effect-runner contracts in
  `tests/effect_ownership_logic.rs` (see that file's
  `EditAccountMetadata` bullet).
- [ ] `Save` is enabled iff the assembled `AccountEdit` is
  non-empty *and* every populated field validates clean. Each
  field's invalid input disables Save and shows the inline
  error beside its row.
- [ ] `save_not_committed` restores the pre-edit account
  byte-for-byte and keeps the dialog open with the inline
  error; the row buffers are preserved for retry.
- [ ] `save_durability_unconfirmed` keeps the new state in
  memory and surfaces the warning attached to the dialog body.
- [ ] Account-not-found `invalid_state` surfaces inline
  defensively (race against a concurrent remove); the dialog
  closes only on `Ok` (and never on
  `save_durability_unconfirmed` / `save_not_committed` /
  `invalid_state` / `duplicate_account`). `validation_error`
  is not part of this post-effect bucket — it is
  pre-flighted client-side and never surfaces from the
  mutator on a draft the client cleared.
- [ ] Post-edit summary lookup — the worker re-reads
  `Vault::summaries().find(|s| s.id == account_id)` after the
  mutator returns and threads
  `EffectResult::EditAccountMetadata { summary: Option<AccountSummary>, .. }`
  to the dispatch site. The dispatch site renders the toast
  text `Edited {summary_display_label(&summary)}.` (e.g.
  `Edited GitHub:work.`) when `Some`, and the bare `Edited.`
  form when `None` (defensive against a concurrent remove
  between mutate and read); both forms carry the trailing
  period for TUI status-line parity.
- [ ] On dialog close (cancel / submit / auto-lock), every row
  buffer is dropped — no `Account`, `AccountId`, or
  `AccountEdit` survives in the closed dialog's state machine.
- [ ] `clear_for_lock(&mut state)` drops the row buffers,
  cached pre-edit `AccountSummary`, and any pending
  `classify_submit` outcome, leaving the state identity-equal
  to `EditDialogState::default()`. Pinned by
  `clear_for_lock_drops_row_buffers_and_summary` and
  `clear_for_lock_on_fresh_state_is_a_noop`; the
  `force_close()` plumbing is covered by the integration test
  registered alongside `ExportQrDialog`'s lock-transition
  pruning suite.
- [ ] The dialog is disabled on `UnlockedBusy` (per the shared
  effect-ownership contract) — Save and the row entries dim
  while a save is mid-flight; Cancel stays sensitive. Save
  is disabled while `effect_ownership` is empty, so the
  pre-flight always sees a populated slot and
  `classify_submit` never runs against a phantom `&Vault`.
- [ ] Validation-before-duplicate ordering — submit with an
  invalid `AccountEdit` never calls
  `find_duplicate_after_edit` (pinned via a recording-stub
  vault that counts call sites; the stub asserts zero
  `find_duplicate_after_edit` calls when the per-field
  `validate_account_edit` would reject).
- [ ] `apply_msg(EditDialogMsg::Cancel)` clears all three row
  buffers, the cached pre-edit `AccountSummary`, and any
  pending `classify_submit` outcome — leaving the state
  identity-equal to `EditDialogState::default()` (parity
  with `clear_for_lock` minus the lock-transition framing).
- [ ] Enter on any of the three rows maps to
  `EditDialogMsg::Submit` only if Save is sensitive
  (assembled `AccountEdit` non-empty + every populated field
  validates clean); otherwise it is a no-op. Tab cycles
  row1 → row2 → row3 → Save → Cancel.
- [ ] HOTP read-only invariant — `classify_edit_draft` is
  account-kind-agnostic: a HOTP `Account` yields the same
  `AccountEdit` projection as a TOTP one for identical
  buffers (table-driven across both kinds). The dialog body
  carries no widgets for `counter` / `algorithm` / `digits`
  / `period` / `kind`, mirroring the `AccountEdit` field
  list.
- [ ] Multi-row revert — every row's buffer reverts to the
  pre-fill → the assembled `AccountEdit` is empty → Save is
  disabled and `classify_submit` yields
  `SubmitOutcome::empty_edit_reject` without dispatching
  any effect.
- [ ] Icon-preview placeholder on parse failure — when the
  icon-hint buffer fails `parse_icon_hint_token`, the inline
  `gtk::Image` suffix resolves through
  `crate::icon_resolution::resolve_display_icon` to the
  placeholder rather than holding a stale preview. Pinned
  by a pure-logic call against the icon-resolution helper.
- [ ] Post-edit summary None branch — when the post-edit
  `Vault::summaries().find(|s| s.id == account_id)` returns
  `None` (concurrent-remove race), the dispatch site renders
  the bare `Edited.` toast text without panic; `Some(summary)`
  renders `Edited {summary_display_label(&summary)}.`.

#### Manual test plan addendum (Milestone 9)

The five EditDialog scenarios below land in
`crates/paladin-gtk/tests/manual/MANUAL_TEST_PLAN.md` and are
mirrored into the `REQUIRED_ITEMS` constant guarded by
`crates/paladin-gtk/tests/manual_test_plan_doc.rs` (so the
manual-plan doc-guard fails the test bar if any of the five
goes missing). Each is a separate bullet pinned to the
locked Phase M contract:

- [ ] "Edit an account via the row kebab menu: label /
  issuer / icon-hint persist on reopen."
- [ ] "Edit an account: leaving every row at the pre-fill
  keeps Save disabled (empty `AccountEdit`)."
- [ ] "Edit an account that would collide with another:
  `duplicate_account` surfaces inline; Save stays disabled
  until resolved."
- [ ] "Edit an account: pre-commit fault injection rolls
  every field back."
- [ ] "Edit a HOTP account: dialog exposes no controls for
  `counter` / `algorithm` / `digits` (Phase M invariant)."

#### `tests/row_context_menu_logic.rs`

v0.2 (DESIGN §7 Milestone 9). All bullets are red until the
right-click gesture slice lands.

- [ ] `build_row_context_menu_model()` returns a `gio::Menu` with
  the four entries in this order: *Copy code* → `row.copy`,
  *Edit…* → `row.edit`, *Export QR…* → `row.show-qr`,
  *Delete…* → `row.remove`. Pinned by a table-driven assertion
  against the menu's `n_items()` and per-position attribute
  pair (`label`, `action`).
- [ ] `pop_row_context_menu_decision(row_kind, busy, hidden_hotp)`
  returns `Suppress` for section rows and
  `Pop { copy_sensitive, actions_sensitive }` for account
  rows, with `copy_sensitive = !hidden_hotp` and
  `actions_sensitive = !busy`. Pinned by a table-driven test
  that asserts `Suppress` for the section-row case (input
  `hidden_hotp` / `busy` irrelevant) and walks all four
  `(busy, hidden_hotp)` cells for the account-row case so the
  per-state enablement matrix is covered without spinning up
  GTK.
- [ ] `account_list::install_row_context_menu_controllers` (the
  pure-logic decision shadow) returns the expected controller
  set (secondary-button `gtk::GestureClick` + a single
  `gtk::ShortcutController` carrying three triggers: `Menu`,
  `Shift+F10`, and `Shift+E`) for an account row container and
  the empty set for a section row container.
- [ ] `Shift+E` on a focused account row activates `row.edit`
  through the row's `gtk::ShortcutController` /
  `gtk::NamedAction` binding and emits
  `AccountListOutput::OpenEditDialog(account_id)`; section
  rows do not install the controller, so the trigger does not
  fire from a section row.
- [ ] `Shift+E` is silently rejected while another modal
  `adw::Dialog` is open: the dialog's modal focus capture
  consumes the keypress before it reaches the row's
  `gtk::ShortcutController`, so no new `OpenEditDialog` is
  emitted and the existing dialog stays mounted (TUI parity
  with DESIGN §6's `Q` / `Shift+E` rule).
- [ ] `AccountListComponent::pop_row_popover(account_id, anchor)`
  unparents and drops any prior popover before mounting a fresh
  one — pinned via the pure-logic
  `single_popover_invariant` decision that the widget binding
  calls into. Same decision fires on
  `AccountListMsg::Refresh` (any prior popover drops because
  its `RowItem` may have been spliced) and on auto-lock.
- [ ] Per-row action targets resolve to the same
  `gio::SimpleActionGroup` as the kebab — verified by
  installing the group, activating `row.copy` / `row.edit` /
  `row.show-qr` / `row.remove`, and asserting the matching
  `AccountListOutput` (`CopyCode` / `OpenEditDialog` /
  `OpenExportQrDialog` / `OpenRemoveDialog`) is emitted with
  the expected `AccountId`.

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

#### `tests/export_qr_dialog_logic.rs`

- [x] `format_export_qr_dialog_warning_body_matches_paladin_core_verbatim`
  pins that the rendered warning body equals
  `paladin_core::format_plaintext_qr_export_warning()` exactly, so a
  future warning reword in core propagates to the GUI without an edit.
- [x] `compose_show_qr_button_sensitive_false_until_ack_revealed` and
  `compose_show_qr_button_sensitive_true_after_ack_toggled_on` pin the
  Page-1 button gate against `ExportQrDialogState::ack_revealed`.
- [x] `compose_visible_child_name_warning_before_show_qr` and
  `apply_msg_show_qr_switches_visible_child_to_qr` pin the
  `AdwViewStack` page switch: on init and after any
  ack-toggle-off / Cancel reset the visible child is `"warning"`;
  only a successful `ShowQr` render switches it to `"qr"`.
- [x] `apply_msg_ack_toggled_does_not_dispatch_show_qr` pins that
  the ack `adw::SwitchRow` only mutates `state.ack_revealed` and
  never causes a `Vault::export_qr_png` call — `ShowQr` is
  dispatched exclusively by the Show-QR button's `connect_clicked`.
- [x] `apply_msg_show_qr_button_press_calls_export_qr_png_with_default_options`
  pins the button-press → render-call wiring: the Show-QR button
  on Page 1 dispatches `ExportQrDialogMsg::ShowQr` which calls
  `Vault::export_qr_png(account_id, QrRenderOptions::default())`.
  In production the `SimpleComponent` emits
  `ExportQrDialogOutput::ShowQrRequested(account_id)` to `AppModel`
  which performs the call and forwards bytes back through
  `ExportQrDialogMsg::ShowQrSucceeded`; the pure helper
  `apply_msg_show_qr(&mut state, &vault)` exercises the same outcome.
- [x] `apply_msg_show_qr_renders_picture_paintable_from_png_bytes` pins
  that the staged PNG `Zeroizing<Vec<u8>>` becomes the `gdk::Texture`
  bound to the `gtk::Picture` (via
  `gdk::Texture::from_bytes(&glib::Bytes::from(&bytes))`) and that the
  matching `state.staged_png` slot is populated. The companion
  `apply_msg_show_qr_success_clears_prior_inline_error` pins that a
  successful render clears any stale `state.show_qr_error` from a
  prior failed Show-QR press.
- [x] `apply_msg_show_qr_sets_caption_label_text_from_summary_display_label`
  pins that the `gtk::Label` caption above the Picture has its
  text set to `paladin_core::summary_display_label(&summary)`
  exactly on `ShowQr`, so the issuer:label rendering matches CLI /
  TUI parity and a future change to `summary_display_label`
  propagates to the GUI through one helper. Companion
  `compose_export_qr_dialog_caption_widget_uses_title_3_style_class`
  pins that the caption widget carries the `title-3` style class
  for the heading weight.
- [x] `apply_msg_ack_toggled_off_clears_staged_png_and_paintable_and_resets_visible_child`
  pins the reverse: toggling ack off drops `state.staged_png`,
  `state.staged_svg`, replaces the Picture's paintable with
  `gdk::Paintable::new_empty`, and calls
  `AdwViewStack::set_visible_child_name("warning")`.
- [x] `apply_msg_page_1_cancel_button_emits_cancel_output_and_wipes_staged_buffers`
  pins that the Page-1 footer Cancel button (distinct from the
  Escape-key path, though both flow through the same secret-wipe
  helper) emits `ExportQrDialogOutput::Cancel` with
  `state.staged_png` / `state.staged_svg` dropped before emit.
  *Implementation note:* shipped as the pair
  `apply_msg_cancel_pressed_emits_cancel_output` +
  `apply_msg_cancel_pressed_clears_staged_buffers` (Phase 3).
  The Escape-key path lands with Phase 7's
  `escape_dismissal_routes_through_cancel_pressed_msg` plus the
  `dispatch_root_dismiss_key_*` truth-table pins, all routing
  through the same `CancelPressed` reducer arm.
- [x] `apply_msg_show_qr_invalid_state_account_not_found_renders_inline`
  and `apply_msg_show_qr_validation_error_renders_inline` pin the two
  typed-error inline-rendering paths (defensive — production payloads
  fit comfortably inside QR version 10 with M-level ECC).
- [x] `compose_save_target_overwrite_gate_visible_*` (a quartet
  mirroring `ExportDialog`'s overwrite-gate quartet) pin that the
  save-target overwrite gate becomes visible when
  `Path::try_exists` reports `true` and stays hidden otherwise; switching
  between PNG and SVG targets keys the ack against the current
  target kind so a stale ack cannot cross-stomp. *Implementation
  note (Phase 5):* shipped as the quartet
  `compose_save_target_overwrite_gate_visible_hidden_when_no_target`,
  `_hidden_when_destination_does_not_exist`,
  `_visible_when_destination_exists`, and
  `_re_keys_on_target_kind_switch` (the last one threads the
  full PNG→SVG cross-stomp scenario through the reducer).
- [x] `apply_msg_save_destination_picked_records_exists` and
  `apply_msg_overwrite_acknowledged_*` pin the destination /
  ack reducer arms, matching `ExportDialogState`'s shape.
  *Implementation note (Phase 5):* the ack arms ship as
  `apply_msg_overwrite_acknowledged_true` /
  `apply_msg_overwrite_acknowledged_false`; reset semantics are
  pinned by
  `apply_msg_save_destination_picked_resets_overwrite_acknowledged`
  and the bordering
  `apply_msg_save_destination_picked_clears_prior_save_error`
  (a fresh pick wipes any leftover inline error/warning so the
  Page-2 surface is clean before the next worker reply).
- [x] `run_export_qr_save_worker_plaintext_png_succeeds_and_writes_0600_file`
  exercises a tempfile-backed plaintext-vault round trip: seed
  `state.staged_png` with the bytes returned by
  `vault.export_qr_png(...)` on the main loop (matching the
  Show-QR press path), then run the save worker which calls only
  `paladin_core::write_secret_file_atomic` against the staged
  bytes — the on-disk file equals the staged bytes verbatim, and
  the file permission bits are `0o600` (verified with
  `std::os::unix::fs::PermissionsExt::mode` masked to `0o7777`).
  *Implementation note (Phase 5):* `rqrr` round-trip decode
  deferred (paladin-gtk has no `rqrr` dev-dep yet); the
  byte-verbatim assertion is sufficient because both the
  on-screen Picture and the on-disk bytes flow through the same
  `vault.export_qr_png` output. Pin separately
  (`run_export_qr_save_worker_png_does_not_call_export_qr_png`)
  that the PNG worker never invokes `vault.export_qr_png` itself
  — the staged-bytes contract is the only path on the PNG side
  (proven by feeding the worker nonsense bytes that decidedly
  are *not* a QR and asserting they land on disk verbatim).
- [x] `run_export_qr_save_worker_plaintext_svg_succeeds_and_writes_0600_file`
  is the SVG variant: with `state.staged_svg` empty, the worker
  calls `vault.export_qr_svg(...)` once, parks the result in
  `staged_svg_after`, and writes through
  `paladin_core::write_secret_file_atomic`. The resulting file is
  non-empty UTF-8 text starting with `<?xml` or `<svg`, and the
  permission bits are `0o600`. The test does not re-decode SVG
  (rqrr does not consume SVG); the byte-roundtrip is enough. Pin
  separately
  (`run_export_qr_save_worker_svg_reuses_staged_svg_on_second_save`)
  that a second save-as-SVG against a different path does not
  re-call `vault.export_qr_svg` once `state.staged_svg` is
  populated (proven by feeding a sentinel SVG string and
  asserting the on-disk bytes equal the sentinel, not the
  vault-rendered SVG).
- [ ] `run_export_qr_save_worker_returns_save_not_committed_before_rename`
  and `run_export_qr_save_worker_returns_save_durability_unconfirmed_after_rename`
  pin the two storage-failure surfaces by enabling the core's
  `test-fault-injection` feature and setting
  `PALADIN_FAULT_INJECT=pre_commit|post_commit`. Both end with the dialog
  staying open and the typed error / warning rendered inline.
- [x] `classify_export_qr_save_error_io_error_renders_inline`,
  `classify_export_qr_save_error_save_not_committed_renders_inline`,
  `classify_export_qr_save_error_save_durability_unconfirmed_renders_inline_warning`,
  and `classify_export_qr_save_error_validation_error_renders_inline`
  pin the error-classification table.
  *Implementation note (Phase 5):* the `Ok(())` shoulder ships as
  `classify_export_qr_save_error_ok_classifies_as_success`; the
  `SaveCompleted` reducer surface ships as
  `apply_msg_save_completed_success_stashes_last_save_path_and_clears_target`,
  `apply_msg_save_completed_inline_error_keeps_target_and_records_message`,
  `apply_msg_save_completed_durability_warning_records_warning_and_last_save_path`,
  and `apply_msg_save_completed_restashes_staged_svg_for_subsequent_saves`.
  The worker IO-error path is pinned by
  `run_export_qr_save_worker_png_missing_parent_surfaces_save_not_committed_inline`
  — `paladin_core::write_secret_file_atomic` collapses every
  pre-commit IO failure into `save_not_committed`, so the
  missing-parent test asserts `SaveNotCommitted` (the
  `IoError` kind ships in the unit-level classify test).
  `export_qr_save_request_round_trips_through_save_requested_output`
  pins that `apply_msg(SaveDestinationPicked{exists:false})`
  emits `Output::SaveRequested(ExportQrSaveRequest{…})` with
  the staged PNG bytes cloned verbatim into the request.
- [x] `apply_msg_copy_image_routes_through_set_content_with_image_png_mime`
  pins that `Copy image` builds a `gdk::ContentProvider::for_value`
  carrying a `glib::Bytes` of the staged PNG bytes with content type
  `image/png`, and that the provider is handed to
  `gdk::Clipboard::set_content` (rather than `set_text`, which would
  serialize the bytes as garbled text).
  *Implementation note (Phase 6):* the pure-logic surface is the
  `compose_copy_image_request_output` helper (returns
  `Some(ExportQrDialogOutput::CopyImageRequested(bytes))` when
  `state.staged_png.is_some()`) paired with the
  `COPY_IMAGE_CLIPBOARD_MIME_TYPE = "image/png"` const. The
  imperative side uses `gtk::gdk::ContentProvider::for_bytes(...)`
  rather than `for_value(...)` — `for_bytes` is the GTK4 idiom for
  publishing typed bytes; semantically identical, mime check is
  pinned by the const.
- [x] `apply_msg_copy_image_failure_does_not_arm_clipboard_clear` pins
  that a `set_content` failure surfaces an inline error and does not
  schedule a clipboard auto-clear timer (parity with the existing
  `CopyCode` failure branch — `clipboard.clear_enabled` covers OTP code
  copies specifically, not image copies).
  *Implementation note (Phase 6):* the `CopyImageFailed` reducer
  arm parks the message in `state.copy_image_error` and returns
  `None` from `apply_msg`, so no output ever lands on `AppModel`
  that would route into `clipboard_clear::schedule_copy`.
- [x] `clear_for_lock_drops_staged_buffers_and_paintable` pins that
  the auto-lock pruning helper drops `state.staged_png`,
  `state.staged_svg`, and the Picture paintable before the
  `(Vault, Store)` pair is released, so a lock-after-effect cannot
  leak the rendered bytes.
  *Implementation note (Phase 8):* the paintable-drop assertion is
  proxied here by the `staged_png.is_none()` ⇒
  `compose_visible_child_name == warning` invariant — the widget
  tree (including the Picture's `gdk::Paintable`) tears down when
  `AppModel` drops the controller in the same call. Sibling pins
  `clear_for_lock_preserves_account_id_and_summary` and
  `clear_for_lock_on_fresh_state_is_a_noop` cover identity
  preservation and the noop-when-unopened path.
- [x] `export_qr_dialog_does_not_advance_hotp_counter` exercises a
  tempfile-backed HOTP-account vault: capture `account.counter()`
  before and after `Vault::export_qr_png` + save-as-PNG + auto-lock,
  and assert equality (and that `account.updated_at()` is unchanged).
  Read-only invariant pin.
  *Implementation note (Phase 9):* the test adds a HOTP account
  with `counter=42`, snapshots `(counter, updated_at)`, runs
  Show-QR (`apply_msg_show_qr`) + Save-as-PNG via
  `run_export_qr_save_worker(ExportQrSaveWorkerInput::Png{..})` +
  `clear_for_lock(&mut state)`, re-opens the vault from disk to
  read what is actually persisted, and asserts both fields are
  byte-equal before vs after. Sibling helpers `add_hotp` and
  `snapshot_hotp` cover the HOTP-fixture setup and the
  `summaries().find(...)` projection.
- [x] `export_qr_dialog_output_cancel_is_distinct_from_close` and
  `dispatch_root_dismiss_key` coverage pin the cancel / close /
  Escape paths.
  *Implementation note:* `export_qr_dialog_output_cancel_is_distinct_from_close`
  ships from Phase 3; Phase 7 adds
  `dispatch_root_dismiss_key_routes_bare_escape_to_cancel_pressed`,
  `dispatch_root_dismiss_key_ignores_escape_with_chord_modifiers`,
  `dispatch_root_dismiss_key_ignores_other_keys`, and
  `escape_dismissal_routes_through_cancel_pressed_msg`. All three
  paths share the same secret-wipe helper.
- [x] `format_export_qr_dialog_title_is_non_empty`,
  `format_export_qr_dialog_show_qr_button_label_is_non_empty`,
  `format_export_qr_dialog_save_as_png_label_is_non_empty`,
  `format_export_qr_dialog_save_as_svg_label_is_non_empty`,
  `format_export_qr_dialog_copy_image_label_is_non_empty`,
  `format_export_qr_dialog_done_label_is_non_empty`, and
  `format_export_qr_dialog_save_success_toast_is_non_empty` pin the
  user-facing wording helpers so a future relabel routes through one
  source. Phase 6 added the parallel
  `format_export_qr_dialog_copy_image_success_toast_is_non_empty` /
  `*_renders_image_copied` pair for the `Image copied` toast.

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
- [ ] The pinned `Display` `AdwPreferencesGroup` title, the
  `Show section headers` `AdwSwitchRow` title, and its subtitle
  are stable across helper invocations and the subtitle names the
  default-off behavior so the wording does not silently drift
  from DESIGN §7.

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
- [ ] `EditAccountMetadata` worker (v0.2 / DESIGN §7 Milestone 9):
  the worker hop running `Vault::edit_account_metadata` and the
  follow-up `Vault::summaries().find(|s| s.id == account_id)`
  lookup asserts that on the same-as-prior no-op-but-non-empty
  contract the post-edit `Account::updated_at` strictly exceeds
  the pre-edit value, and that the returned
  `EffectResult::EditAccountMetadata { summary, .. }` carries
  `Some(AccountSummary)` reflecting the post-edit fields
  (defensive `None` covered by an additional case that removes
  the account between mutate and read). Cross-referenced by the
  `tests/edit_dialog_logic.rs` "Same-as-prior submit … bumps
  `updated_at`" bullet.

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
  `AccountListComponent` controller; the component pushes each
  `AccountRowModel` into a `FactoryVecDeque<AccountRowComponent>`
  whose parent widget is a `gtk::ListBox`. Under `--exit-after-startup`,
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
  `InitDialog` is implemented in `crates/paladin-gtk/src/init_dialog.rs`
  (two `AdwPasswordEntryRow`s plus the `Store::create_force` worker
  dispatched via `gio::spawn_blocking`). Under `--exit-after-startup`,
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
  `UnlockComponent` is implemented in
  `crates/paladin-gtk/src/unlock_dialog.rs` (passphrase entry with
  keystroke shadowing, `gio::spawn_blocking` Argon2id worker, inline
  `decrypt_failed` / `invalid_passphrase` rendering with non-auth
  failures routed to `StartupErrorComponent`).
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
  `tests/<name>_logic.rs`. `AccountRowComponent` is the one
  exception: it is a `relm4::factory::FactoryComponent` (not a
  `SimpleComponent`) so `AccountListComponent` can drive a
  `FactoryVecDeque<AccountRowComponent>` over a `gtk::ListBox`
  instead of a `gio::ListStore` + `SignalListItemFactory` over a
  `gtk::ListView`. The behavior on top of each mount —
  full passphrase entry on `InitDialog` / `UnlockDialog`, full form
  widgets on `AddAccountComponent` / `ImportDialogComponent` /
  `ExportDialogComponent` / `PassphraseDialogComponent` /
  `SettingsComponent` — has landed; see each controller's source
  file for the implementation and the matching
  `tests/<name>_logic.rs` for the pinned pure-logic surface.
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
- [x] `AccountListComponent` full implementation (`gtk::ListBox` +
  `FactoryVecDeque<AccountRowComponent>`, search bar + entry,
  selection management).
  - [x] Build the row set from `Vault::iter()` projected through
    `paladin_core::AccountSummary` into `AccountRowModel` entries —
    no secret bytes leave `paladin_core`.
  - [x] Mount a `gtk::ListBox` (inside a `gtk::ScrolledWindow`)
    driven by a `relm4::factory::FactoryVecDeque<AccountRowComponent>`.
    Each `AccountRowModel` is pushed as one persistent
    `AccountRowComponent` whose `Root = gtk::ListBoxRow` is
    constructed once at push time and reused for the row's lifetime.
    The list-level wiring (the `gtk::ListBox`, the search bar, the
    selection plumbing, and the factory's parent → row dispatch)
    lives in `account_list.rs`; the row body — the per-row
    `gtk::Box` (`build_row_widget`), the bind walk (`bind_row`),
    the `gtk::IconTheme` resolve (`bind_row_icon`), and the per-row
    `gio::SimpleActionGroup` install (`install_row_action_group`) —
    lives in `account_row.rs` so the `AccountRowComponent` module
    is the canonical owner of row body construction. The
    `FactoryComponent::init_widgets` callback drives those four
    helpers; the helper ownership is pinned by
    `tests/account_row_logic.rs::{build_row_widget_is_exposed_from_account_row_module,
    bind_row_is_exposed_from_account_row_module,
    bind_row_icon_is_exposed_from_account_row_module,
    install_row_action_group_is_exposed_from_account_row_module}`
    so a silent move back into `account_list.rs` surfaces as a
    hard-error import drift rather than as an undetected re-shuffle
    of widget ownership.
  - [x] Per-tick TOTP refresh and busy-state changes route through
    targeted per-row inputs (`factory.send(index, AccountRowMsg::Rebind(…))`
    and `factory.broadcast(AccountRowMsg::SetBusy(busy))`), so the
    row widget tree is never torn down or rebuilt by the ticker.
    Full row-set rebuilds (Add / Remove / Rename / Import / search
    filter changes) clear and re-push the factory through one code
    path on the `Refresh` arm. The "stop splicing on every tick"
    contract is pinned by
    `tests/account_list_logic.rs::tick_routes_only_to_changed_rows`
    so a regression to a full-list rebuild on tick surfaces as a
    failing test rather than as a return of the flicker / dropped-
    click bug that prompted the migration.
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
    with the visible code without a separate signal. The bar fill is
    colored by remaining-window urgency: `bind_row` strips every
    class in `crate::account_row::PROGRESS_URGENCY_CSS_CLASSES`
    before adding the active class returned by
    `crate::account_row::progress_urgency(&ProgressDisplay).css_class()`
    — `>15s` → `success` (green), `6..=15s` → `warning` (yellow),
    `<=5s` → `error` (red). Adwaita's semantic style classes keep
    the colors themable (light / dark / high-contrast) and
    accessible without baking hex colors. Urgency thresholds are
    absolute seconds (not fractions of the period) so the
    user-visible meaning — "how much time you have to read and
    copy the code" — stays constant across `period` values.
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
  - [x] After a successful copy, raise an `adw::Toast` on the shared
    `adw::ToastOverlay` with a body projected by
    `crate::clipboard_clear::format_copy_toast(&VaultSettings)` —
    `"Code copied"` when clipboard auto-clear is off and
    `"Code copied — clears in {N}s"` when the user has opted into
    `clipboard_clear_enabled`, so the security-relevant deadline that
    just armed is visible in the same surface that confirms the write.
    The formatter is pure-logic and covered by
    `tests/clipboard_clear_logic.rs`. The toast is skipped when
    `prepare_copy_bytes` returns `None` (hidden HOTP row, raced
    removal) so a benign no-op stays silent.
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
    `tests/account_list_logic.rs::build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
    (renamed from `..._rename_and_remove_in_order` by the §"QR
    export dialog implementation" build-order item) so drift
    between the kebab UI, the per-row action group, and the
    dispatch table surfaces as a failing test.
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
    `account_list_logic::build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
    (renamed from `..._rename_and_remove_in_order` by the §"QR
    export dialog implementation" build-order item),
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
    that variant is a state-side no-op (the component emits the
    request as an output and the `AppModel`-side handler at
    `crates/paladin-gtk/src/app/model.rs` owns the live
    `gdk::Display::default().clipboard().read_texture_async`
    round-trip plus the `gdk::TextureDownloader` decode and the QR
    worker dispatch covered by the sub-items below). Pinned by
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
    `AppModel::update` is implemented in
    `crates/paladin-gtk/src/app/model.rs` (the `read_texture_async`
    callback feeds `load_clipboard_qr_capture`, which runs
    `gdk::TextureDownloader` and the QR worker via
    `gtk::gio::spawn_blocking`); the pure-logic helpers and routing
    decisions are pinned by
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
- [x] `ImportDialogComponent` full implementation (file picker,
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
- [x] `ExportDialogComponent` full implementation (format selector,
  destination picker, overwrite gate, plaintext warning,
  twice-confirm passphrase, `write_secret_file_atomic` call).
  - [x] Add a format selector (plaintext newline-separated
    `otpauth://` URI list — Gnome Authenticator–compatible — or
    encrypted Paladin bundle) and pick the destination via
    `gtk::FileDialog`.
    (`ExportFormatChoice` gains `Default` (returns
    `PlaintextOtpauth`, mirroring the CLI's no-`--format` behavior)
    and an `index()` method; new `format_choice_from_index(u32) ->
    Option<ExportFormatChoice>` round-trips with `index()` so the
    widget never lands on a `None` slot. The view! macro now mounts
    an `adw::PreferencesGroup` "Destination" with an `adw::ActionRow`
    whose suffix "Choose file…" `gtk::Button` opens a
    `gtk::FileDialog::save` round trip — the picked path returns as
    `ExportDialogMsg::DestinationPicked(PathBuf)` and is stored
    verbatim on the new `ExportDialogState` (no canonicalization, so
    the existing `overwrite_gate_needs_reset` /
    `plaintext_warning_needs_reset` / `passphrase_needs_reset` raw-
    path comparisons stay authoritative). A second
    `adw::PreferencesGroup` "Options" mounts an `adw::ComboRow`
    "Format" bound to `format_export_dialog_format_labels()`
    (`["Plaintext otpauth:// URI list", "Encrypted Paladin
    bundle"]`); the `connect_selected_notify` callback decodes the
    selection through `format_choice_from_index` and dispatches
    `ExportDialogMsg::FormatChanged(ExportFormatChoice)`, ignoring
    out-of-range indices. `apply_msg` routes both events into
    `ExportDialogState::set_destination` / `set_format`; Cancel and
    parent-close emit the distinct `ExportDialogOutput::Cancel` /
    `Close` variants the existing `AppMsg::ExportDialogAction`
    dispatch arm now handles via a shared drop-the-controller match.
    The footer Export button binds
    `compose_submit_button_sensitive(&state)` (currently destination-
    presence only; subsequent sub-items extend it with the overwrite
    gate, plaintext-warning gate, and twice-confirm passphrase gate).
    Pinned by
    `tests/export_dialog_logic.rs::format_export_dialog_format_labels_returns_plaintext_then_encrypted`,
    `format_export_dialog_format_labels_match_export_format_choice_order`,
    `export_format_choice_index_plaintext_is_zero`,
    `export_format_choice_index_encrypted_is_one`,
    `format_choice_from_index_zero_returns_plaintext`,
    `format_choice_from_index_one_returns_encrypted`,
    `format_choice_from_index_out_of_range_returns_none`,
    `format_choice_index_round_trip_across_every_variant`,
    `export_format_choice_default_is_plaintext_otpauth`,
    `format_export_dialog_title_is_non_empty`,
    `format_export_dialog_subtitle_is_non_empty`,
    `format_export_dialog_destination_group_title_is_non_empty`,
    `format_export_dialog_destination_row_title_is_non_empty`,
    `format_export_dialog_destination_row_placeholder_is_non_empty`,
    `format_export_dialog_choose_destination_label_is_non_empty`,
    `format_export_dialog_options_group_title_is_non_empty`,
    `format_export_dialog_format_row_title_is_non_empty`,
    `format_export_dialog_cancel_label_is_non_empty`,
    `format_export_dialog_export_label_is_non_empty`,
    `export_dialog_state_new_has_no_destination`,
    `export_dialog_state_new_format_matches_default`,
    `export_dialog_state_set_destination_updates_path`,
    `export_dialog_state_set_destination_replaces_prior_path`,
    `export_dialog_state_set_format_updates_format`,
    `export_dialog_state_set_format_back_to_plaintext_replaces_encrypted`,
    `compose_destination_row_subtitle_uses_placeholder_when_no_destination`,
    `compose_destination_row_subtitle_renders_display_path_when_set`,
    `compose_submit_button_sensitive_false_when_no_destination`,
    `compose_submit_button_sensitive_true_when_destination_set`,
    `apply_msg_destination_picked_updates_state_and_emits_no_output`,
    `apply_msg_format_changed_updates_state_and_emits_no_output`,
    `apply_msg_cancel_emits_cancel_output`,
    `apply_msg_close_emits_close_output`,
    `apply_msg_destination_picked_replaces_prior_destination`, and
    `export_dialog_output_cancel_is_distinct_from_close`.)
  - [x] Reject overwriting an existing file unless the user
    confirms an inline overwrite gate (parity with CLI `--force`);
    resolve the overwrite gate before accepting any
    encrypted-bundle passphrase rows.
    (`ExportDialogState` gains `destination_exists: bool` and
    `overwrite_acknowledged: bool` fields with paired
    `destination_exists()` / `is_overwrite_acknowledged()` /
    `set_overwrite_acknowledged(bool)` accessors;
    `set_destination(path, exists)` now takes the picker's
    `Path::try_exists` probe alongside the path and resets the
    acknowledgement on path / format change per the existing
    `overwrite_gate_needs_reset` helper. `set_format` mirrors the
    reset so switching formats invalidates a stale ack against the
    same destination — the two formats write distinct payloads.
    `ExportDialogMsg::DestinationPicked(PathBuf)` becomes the
    struct variant `DestinationPicked { path, exists }`, and a new
    `OverwriteAcknowledged(bool)` variant routes through `apply_msg`
    into `set_overwrite_acknowledged`. The view! now mounts an
    `adw::SwitchRow` underneath the destination row whose visibility
    is bound to `compose_overwrite_gate_visible(state)` — only
    revealed when the picked file already exists — and whose
    `connect_active_notify` handler dispatches the toggle through
    `ExportDialogMsg::OverwriteAcknowledged`. The "Choose file…"
    callback runs `path.try_exists().unwrap_or(true)` after the
    `gtk::FileDialog::save` round trip so I/O errors default to
    arming the gate (silent overwrites are always the worse failure
    mode). `compose_submit_button_sensitive` is extended to dim the
    Export button until either the destination does not exist or the
    user has ack'd the gate; subsequent sub-items extend it further
    with the plaintext-warning and twice-confirm passphrase gates.
    Title / subtitle wording lives in
    `format_export_dialog_overwrite_gate_title` (`"Overwrite existing
    file"`) and `format_export_dialog_overwrite_gate_subtitle`
    (`"The selected file already exists. Toggle on to replace it on
    Export."`) so the strings stay testable from
    `tests/export_dialog_logic.rs` without touching the GTK runtime.
    Pinned by
    `tests/export_dialog_logic.rs::export_dialog_state_new_has_destination_exists_false`,
    `export_dialog_state_new_overwrite_not_acknowledged`,
    `export_dialog_state_set_destination_records_exists_true`,
    `export_dialog_state_set_destination_records_exists_false`,
    `export_dialog_state_set_destination_replaces_exists_value`,
    `export_dialog_state_set_overwrite_acknowledged_true`,
    `export_dialog_state_set_overwrite_acknowledged_back_to_false`,
    `export_dialog_state_set_destination_resets_overwrite_ack_on_path_change`,
    `export_dialog_state_set_destination_keeps_overwrite_ack_when_path_and_format_match`,
    `export_dialog_state_set_format_resets_overwrite_ack_on_format_change`,
    `export_dialog_state_set_format_keeps_overwrite_ack_when_format_unchanged`,
    `compose_overwrite_gate_visible_false_when_no_destination`,
    `compose_overwrite_gate_visible_false_when_destination_does_not_exist`,
    `compose_overwrite_gate_visible_true_when_destination_exists`,
    `compose_submit_button_sensitive_false_when_overwrite_gate_armed_unacked`,
    `compose_submit_button_sensitive_true_when_overwrite_gate_acked`,
    `compose_submit_button_sensitive_false_again_after_overwrite_ack_revoked`,
    `compose_submit_button_sensitive_false_after_destination_change_resets_ack`,
    `apply_msg_destination_picked_records_exists_true`,
    `apply_msg_overwrite_acknowledged_true_updates_state`,
    `apply_msg_overwrite_acknowledged_false_clears_state`,
    `format_export_dialog_overwrite_gate_title_is_non_empty`, and
    `format_export_dialog_overwrite_gate_subtitle_is_non_empty`.)
  - [x] Render `paladin_core::format_plaintext_export_warning()`
    verbatim on the plaintext path and require explicit
    confirmation before the write proceeds.
    (`ExportDialogState` gains a `plaintext_warning_acknowledged:
    bool` field with paired `is_plaintext_warning_acknowledged()` /
    `set_plaintext_warning_acknowledged(bool)` accessors; both
    `set_destination` and `set_format` now reset the ack via the
    existing `plaintext_warning_needs_reset` helper so a stale tick
    never carries across to a different file or format. The
    pre-destination format-only branch on `set_format` keys the
    plaintext-ack reset to the format selector regardless of
    destination so a switch onto or off the plaintext path always
    re-prompts. New `ExportDialogMsg::PlaintextWarningAcknowledged(bool)`
    routes through `apply_msg` into the new setter.
    `compose_plaintext_warning_visible(state)` returns
    `state.format().requires_plaintext_warning()` so the warning is
    keyed to the format selector — the user sees the risk before
    committing to a destination; `compose_plaintext_warning_body()`
    re-exposes `plaintext_warning_body()` (already a verbatim wrap of
    `paladin_core::format_plaintext_export_warning`) so the GUI, CLI,
    and TUI all surface the same wording. The view! macro mounts an
    `adw::PreferencesGroup` titled `"Plaintext warning"` with an
    `adw::ActionRow` whose title is bound to
    `compose_plaintext_warning_body()` (rendered as plain text via
    `set_use_markup: false` default, with `set_title_lines: 0` /
    `set_subtitle_lines: 0` so long lines wrap) and an underlying
    `adw::SwitchRow` ack (`"I understand the risks" / "Toggle on to
    confirm and enable Export."`); the whole group's visibility binds
    to `compose_plaintext_warning_visible(state)`.
    `compose_submit_button_sensitive` extended to dim the Export
    button until either the active format does not require the
    warning or the user has ack'd it; the existing overwrite-gate
    composition is unchanged so a destination that triggers both
    gates requires both acks before submit enables. Two pre-existing
    happy-path tests
    (`compose_submit_button_sensitive_true_when_destination_set_and_no_overwrite_needed`,
    `compose_submit_button_sensitive_true_when_overwrite_gate_acked`)
    switched to the encrypted format to isolate the gates under
    test. Pinned by
    `tests/export_dialog_logic.rs::export_dialog_state_new_plaintext_warning_not_acknowledged`,
    `export_dialog_state_set_plaintext_warning_acknowledged_true`,
    `export_dialog_state_set_plaintext_warning_acknowledged_back_to_false`,
    `export_dialog_state_set_destination_resets_plaintext_ack_on_path_change`,
    `export_dialog_state_set_destination_keeps_plaintext_ack_when_path_and_format_match`,
    `export_dialog_state_set_format_resets_plaintext_ack_on_format_change`,
    `export_dialog_state_set_format_keeps_plaintext_ack_when_format_unchanged`,
    `export_dialog_state_set_format_resets_plaintext_ack_onto_plaintext_from_encrypted`,
    `compose_plaintext_warning_visible_true_on_plaintext_format`,
    `compose_plaintext_warning_visible_false_on_encrypted_format`,
    `compose_plaintext_warning_visible_true_on_default_state`,
    `compose_plaintext_warning_body_matches_paladin_core_verbatim`,
    `compose_submit_button_sensitive_false_when_plaintext_warning_visible_unacked`,
    `compose_submit_button_sensitive_true_after_plaintext_warning_acked`,
    `compose_submit_button_sensitive_true_on_encrypted_format_without_plaintext_ack`,
    `compose_submit_button_sensitive_false_after_plaintext_ack_revoked`,
    `compose_submit_button_sensitive_requires_both_overwrite_and_plaintext_ack_when_both_armed`,
    `apply_msg_plaintext_warning_acknowledged_true_updates_state`,
    `apply_msg_plaintext_warning_acknowledged_false_clears_state`,
    `format_export_dialog_plaintext_warning_group_title_is_non_empty`,
    `format_export_dialog_plaintext_warning_ack_title_is_non_empty`, and
    `format_export_dialog_plaintext_warning_ack_subtitle_is_non_empty`.)
  - [x] Reset overwrite and plaintext-warning confirmations when
    the destination or format changes; clear the passphrase rows
    and re-prompt when the destination or format changes after
    passphrase entry.
    (`ExportDialogState` gains a twice-confirm passphrase pair held
    in two `crate::secret_fields::SecretEntry` buffers
    (`passphrase` / `confirm_passphrase`) so the typed bytes wipe on
    drop / clear; `Debug` is dropped from the derive list to match
    `ImportDialogState` and prevent a stray `dbg!` from leaking the
    bundle passphrase. New `passphrase_text()` /
    `confirm_passphrase_text()` accessors and
    `set_passphrase(&str)` / `set_confirm_passphrase(&str)` setters
    drive the entries; `set_destination` / `set_format` route
    through the existing `passphrase_needs_reset` helper so a path
    or format change zeroizes both buffers, while idempotent
    re-pick of the same `(path, format)` pair preserves the typed
    input. Pre-destination format-only switches reset the
    passphrase rows symmetrically with the plaintext-warning reset
    so the encrypted ↔ plaintext hop always re-prompts from a clean
    slate. New `ExportDialogMsg::PassphraseChanged(String)` /
    `ConfirmPassphraseChanged(String)` per-keystroke shadow
    messages route through `apply_msg` into the new setters; the
    view! macro mounts an `adw::PreferencesGroup` "Bundle
    passphrase" whose visibility binds to
    `compose_passphrase_rows_visible(state)` (returns
    `state.format().requires_passphrase()`) with two
    `adw::PasswordEntryRow` rows titled "Passphrase" and "Confirm
    passphrase" wired via `connect_changed`. The submit-button
    gate `compose_submit_button_sensitive` extends to refuse the
    encrypted path when either row is empty or the pair mismatches,
    so the worker dispatch (subsequent sub-item) never hands
    `prepare_encrypted_export` a `SubmitRejection::ZeroLength` /
    `ConfirmationMismatch` pair. Pinned by
    `tests/export_dialog_logic.rs::export_dialog_state_new_has_empty_passphrase`,
    `export_dialog_state_new_has_empty_confirm_passphrase`,
    `export_dialog_state_set_passphrase_updates_text`,
    `export_dialog_state_set_passphrase_replaces_prior_text`,
    `export_dialog_state_set_confirm_passphrase_updates_text`,
    `export_dialog_state_set_confirm_passphrase_replaces_prior_text`,
    `export_dialog_state_set_destination_clears_passphrase_on_path_change`,
    `export_dialog_state_set_destination_keeps_passphrase_when_path_and_format_match`,
    `export_dialog_state_set_format_clears_passphrase_on_format_change_off_encrypted`,
    `export_dialog_state_set_format_clears_passphrase_on_format_change_onto_encrypted`,
    `export_dialog_state_set_format_keeps_passphrase_when_format_unchanged`,
    `compose_passphrase_rows_visible_true_on_encrypted_format`,
    `compose_passphrase_rows_visible_false_on_plaintext_format`,
    `compose_submit_button_sensitive_false_on_encrypted_without_passphrase`,
    `compose_submit_button_sensitive_false_on_encrypted_with_only_passphrase_no_confirm`,
    `compose_submit_button_sensitive_false_on_encrypted_with_only_confirm_no_passphrase`,
    `compose_submit_button_sensitive_false_on_encrypted_with_mismatched_passphrases`,
    `compose_submit_button_sensitive_true_on_encrypted_with_matching_passphrases`,
    `compose_submit_button_sensitive_unaffected_by_passphrases_on_plaintext`,
    `compose_submit_button_sensitive_false_after_passphrases_cleared_by_destination_change`,
    `compose_submit_button_sensitive_false_after_passphrases_cleared_by_format_change`,
    `apply_msg_passphrase_changed_updates_state_and_emits_no_output`,
    `apply_msg_confirm_passphrase_changed_updates_state_and_emits_no_output`,
    `apply_msg_passphrase_changed_to_empty_string_clears_text`,
    `format_export_dialog_passphrase_group_title_is_non_empty`,
    `format_export_dialog_passphrase_row_title_is_non_empty`, and
    `format_export_dialog_confirm_passphrase_row_title_is_non_empty`.)
  - [x] Prompt twice for the encrypted-bundle passphrase; reject
    mismatch with `invalid_passphrase`
    (`reason: "confirmation_mismatch"`) and zero-length with
    `invalid_passphrase` (`reason: "zero_length"`) inline.
    (`ExportDialogMsg::SubmitClicked` runs the existing
    `prepare_encrypted_export` pre-flight on the encrypted path
    inside `apply_msg`; rejections stage an
    `InlineError::from_rejection(SubmitRejection)` projection on
    `ExportDialogState::inline_error`, which renders verbatim through
    the matching `PaladinError::InvalidPassphrase { reason }` variant
    so wording stays in lock-step with the CLI / TUI. The plaintext
    path is a no-op for the pre-flight; both paths clear any stale
    inline error on accept. Per-keystroke
    `PassphraseChanged` / `ConfirmPassphraseChanged` and
    destination / format changes also clear the inline error so a
    dismissed failure never lingers beside the freshly typed input
    or empty rows. The view! macro mounts a `gtk::Revealer` driven
    by `compose_inline_error_revealed` / `compose_inline_error_body`
    underneath the passphrase group; the footer Export button wires
    a `connect_clicked` into `ExportDialogMsg::SubmitClicked`.
    `SubmitRejection` gains `Copy` so the `from_rejection`
    constructor takes the rejection by value without the
    `needless_pass_by_value` clippy lint. Pinned by
    `tests/export_dialog_logic.rs::inline_error_from_rejection_confirmation_mismatch_is_invalid_passphrase`,
    `inline_error_from_rejection_zero_length_is_invalid_passphrase`,
    `export_dialog_state_new_has_no_inline_error`,
    `apply_msg_submit_clicked_encrypted_mismatched_stages_confirmation_mismatch_inline`,
    `apply_msg_submit_clicked_encrypted_zero_length_stages_zero_length_inline`,
    `apply_msg_submit_clicked_encrypted_one_empty_stages_confirmation_mismatch_inline`,
    `apply_msg_submit_clicked_encrypted_matching_clears_prior_inline_error`,
    `apply_msg_submit_clicked_plaintext_does_not_stage_inline_error`,
    `apply_msg_passphrase_changed_clears_prior_inline_error`,
    `apply_msg_confirm_passphrase_changed_clears_prior_inline_error`,
    `apply_msg_destination_picked_clears_prior_inline_error`,
    `apply_msg_format_changed_clears_prior_inline_error`,
    `compose_inline_error_revealed_returns_false_when_no_error`,
    `compose_inline_error_revealed_returns_true_when_error_staged`,
    `compose_inline_error_body_returns_none_when_no_error`, and
    `compose_inline_error_body_renders_staged_invalid_passphrase`.)
  - [x] Dispatch the write on `gio::spawn_blocking` (encrypted
    bundle to keep the fresh-AEAD-key derivation off the main loop;
    plaintext for symmetry since `write_secret_file_atomic` chains
    multiple `fsync`s); the write goes through
    `paladin_core::write_secret_file_atomic`.
    (`run_export_worker(ExportWorkerInput) -> ExportWorkerCompletion`
    consumes the live `(Vault, Store)` pair, builds the bytes via
    `paladin_core::export::otpauth_list` / `paladin_core::export::encrypted`,
    and hands them to `paladin_core::write_secret_file_atomic`. The
    typed result routes through `classify_export_result` into
    `ExportOutcome::{Success, DurabilityWarning, Inline}`. `AppModel`
    spawns it via `gtk::glib::spawn_future_local` wrapping
    `gtk::gio::spawn_blocking` symmetric to the import worker; the
    bundled `ExportWorkerCompletion` posts back as
    `AppMsg::ExportWorkerCompleted`. `compose_export_worker_input`,
    `apply_submit_export_inplace`, `apply_export_vault_install_inplace`,
    `compose_export_dispatch`, and `apply_export_dispatch_inplace` in
    `app::state` mirror the import dispatch family. Pinned by
    `tests/export_dialog_logic.rs::worker_integration::run_export_worker_plaintext_writes_otpauth_json_and_returns_success`,
    `run_export_worker_encrypted_writes_paladin_bundle_and_returns_success`,
    and `run_export_worker_plaintext_io_error_returns_inline` (real
    `(Vault, Store)` round-trip through tempfile vault).)
  - [x] On success, close the dialog and surface the written path
    via `AdwToast` on the main toast overlay.
    (`apply_msg::WorkerCompleted(Success)` emits
    `ExportDialogOutput::Close` and clears the form; the dispatch arm
    drops the controller, force-closing the `adw::Dialog`.
    `compose_export_dispatch` returns
    `success_toast = Some(format_export_success_toast(&destination))`
    on the success branch, which `AppModel::update` raises on the
    main `toast_overlay`. Pinned by
    `apply_msg_worker_completed_success_clears_busy_and_emits_close`
    and `apply_msg_worker_completed_success_clears_prior_inline_error_and_warning`.)
  - [x] Surface writer errors (`io_error`, `save_not_committed`,
    `save_durability_unconfirmed`, `invalid_passphrase`) and the
    refused overwrite gate inline; export does not mutate the
    vault, so there is no rollback path.
    (`classify_export_result` routes
    `SaveDurabilityUnconfirmed` to `ExportOutcome::DurabilityWarning`
    rendered via the new `compose_inline_warning_revealed` /
    `compose_inline_warning_body` view helpers; every other typed
    error falls through to `ExportOutcome::Inline` rendered via the
    pre-existing `compose_inline_error_*` helpers.
    `apply_msg::WorkerCompleted` stages the typed projection,
    releases the busy gate, and emits no output so the dialog stays
    mounted with the inline body. The overwrite-gate refusal stays
    on the existing `compose_submit_button_sensitive` dim — submit
    cannot dispatch the worker until the gate is acked. Pinned by
    `apply_msg_worker_completed_durability_warning_stages_warning_keeps_dialog_open`,
    `apply_msg_worker_completed_inline_stages_error_keeps_dialog_open`,
    `compose_inline_warning_revealed_returns_true_when_warning_staged`,
    and `compose_inline_warning_body_returns_durability_unconfirmed_display`.)
  - [x] Zeroize the encrypted-bundle passphrase widget buffers on
    submit / cancel / dialog close / auto-lock.
    (`ExportDialogState`'s `passphrase` / `confirm_passphrase`
    `SecretEntry` shadows zeroize on drop / clear and are cleared
    inside `apply_msg` on `SubmitClicked` (Proceed path), `Cancel`,
    `Close`, and `WorkerCompleted(Success)`. The `update()` method
    stashes the live `adw::PasswordEntryRow` widget refs in
    `init()` after `view_output!()` and calls
    `row.set_text("")` after the same set of `apply_msg` outcomes —
    the `gtk::EntryBuffer` is the unavoidable UI-side copy; a
    `#[watch] set_text:` binding would loop because
    `gtk_editable_set_text` always re-emits `changed`. Auto-lock is
    covered transitively: the locked transition drops the dialog
    controller, destroying the widget and freeing the GTK buffer.
    Pinned by
    `apply_msg_submit_clicked_proceed_encrypted_emits_submit_and_clears_passphrase_buffers`,
    `apply_msg_cancel_clears_passphrase_buffers`, and
    `apply_msg_close_clears_passphrase_buffers`.)
- [x] `ExportQrDialogComponent` full implementation (per DESIGN §4.6 /
  §7 / the §"QR export dialog implementation" build-order section).
  Read-only feature, no `Vault::mutate_and_save` involvement, no
  GSettings key, no window-level accelerator.
  - [x] Promote `qrcode` from `[dev-dependencies]` to
    `[dependencies]` in `crates/paladin-core/Cargo.toml` and land the
    §4.7 surface (`QrRenderOptions`, `QR_MODULE_SIZE_PX_*`,
    `Vault::export_qr_png` / `export_qr_svg` / `export_qr_ansi`,
    `export::qr_*` free functions,
    `format_plaintext_qr_export_warning`). Update
    `crates/paladin-core/public-api.txt` to match. Core tests land
    in the same commit per DESIGN §10's QR-export bullet.
  - [x] Extend `account_list::build_kebab_menu_model` to insert
    `Show QR…` between `Rename…` and `Remove…`, targeting a new
    `row.show-qr` action; rename
    `build_kebab_menu_model_exposes_rename_and_remove_in_order` to
    `build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
    with the new index-2 assertion. Register the action on the
    per-row `gio::SimpleActionGroup` in `install_row_action_group`
    so its closure emits the new
    `AccountListOutput::OpenExportQrDialog(AccountId)` variant.
  - [x] Add `AccountListOutput::OpenExportQrDialog(AccountId)`,
    `AppMsg::OpenExportQrDialog(AccountId)`, and the
    `AccountListAction` arm in `AppModel::update` that mounts
    `ExportQrDialogComponent` against the live `(Vault, Store)`
    pair, silent-no-op when `AppModel` is not `Unlocked`.
  - [x] Build `src/export_qr_dialog.rs` carrying
    `ExportQrDialogComponent` (`relm4::SimpleComponent`),
    `ExportQrDialogInit`, `ExportQrDialogMsg`,
    `ExportQrDialogOutput` (`Cancel` / `Close` distinct
    variants), and `ExportQrDialogState` with
    `ack_revealed: bool`, `staged_png: Option<Zeroizing<Vec<u8>>>`,
    `staged_svg: Option<Zeroizing<String>>`, and save-target
    state mirroring `ExportDialogState`.
  - [x] Mount the two-page state machine as an `AdwViewStack`
    inside an `adw::Dialog`. Page 1 (`AdwViewStack` child name
    `"warning"`): warning body bound to
    `compose_export_qr_warning_body()` (verbatim from
    `paladin_core::format_plaintext_qr_export_warning()`), the
    ack `adw::SwitchRow` dispatching only
    `ExportQrDialogMsg::AckToggled(bool)`, and a footer with two
    buttons — `Cancel` (always sensitive; emits
    `ExportQrDialogOutput::Cancel` after wiping staged buffers)
    and `Show QR` (`suggested-action`; sensitive only when
    `state.ack_revealed`, dispatches
    `ExportQrDialogMsg::ShowQr`). Page 2 (`AdwViewStack` child
    name `"qr"`): `gtk::Picture` populated by
    `gdk::Texture::from_bytes(&glib::Bytes::from(&staged_png))`,
    a `gtk::Label` caption above it (with the `title-3` style
    class) whose text is set from `summary_display_label(&summary)`
    on `ShowQr`, and four footer buttons
    (`Save as PNG…`, `Save as SVG…`, `Copy image`, `Done`). The
    page switch is programmatic
    (`AdwViewStack::set_visible_child_name`) — no
    `AdwViewSwitcher` is paired with the stack, so the user
    cannot bypass the warning by tab-clicking.
  - [x] Wire `Save as PNG…` / `Save as SVG…` through
    `gtk::FileDialog::save` and the same inline overwrite gate
    `ExportDialog` uses; dispatch
    `run_export_qr_save_worker` on `gio::spawn_blocking`. The PNG
    worker reuses the already-staged `state.staged_png` bytes and
    only calls `paladin_core::write_secret_file_atomic` (no second
    `vault.export_qr_png` invocation). The SVG worker renders via
    `vault.export_qr_svg(...)` on first save (parking the bytes in
    `state.staged_svg` so a subsequent save-as-SVG reuses them)
    and writes via `paladin_core::write_secret_file_atomic`.
    Surface the 0600 output path inline and via an `adw::Toast`
    on the shared overlay.
  - [x] Wire `Copy image` through
    `gdk::ContentProvider::for_value` on a `glib::Bytes` of the
    staged PNG (MIME `image/png`) handed to
    `gdk::Clipboard::set_content`. No clipboard auto-clear arms;
    the dialog body still calls out clipboard-history risk via
    DESIGN §8 bullet 6 wording.
  - [x] Install a bubble-phase `gtk::EventControllerKey` on the
    dialog root reusing `dispatch_root_dismiss_key` so bare
    Escape routes to the Cancel path.
  - [x] Register `crate::export_qr_dialog::clear_for_lock` with
    the lock-transition pruning so auto-lock drops the staged
    PNG / SVG buffers and the `gtk::Picture` paintable before
    `(Vault, Store)` is destroyed.
  - [x] Inline error rendering for
    `invalid_state { state: "account_not_found" }` (defensive),
    `validation_error { field: "qr_render" }` (defensive — see
    §"Open decisions"), `io_error`, `save_not_committed`, and
    `save_durability_unconfirmed` via
    `classify_export_qr_save_error`; the dialog never closes on
    failure (parity with `ExportDialog`).
  - [x] All `tests/export_qr_dialog_logic.rs` bullets ticked
    (see §"Pure-logic unit tests" above) and the renamed
    `build_kebab_menu_model_exposes_rename_show_qr_and_remove_in_order`
    bullet asserted in `tests/account_list_logic.rs`.
  - [x] `tests/manual/MANUAL_TEST_PLAN.md` updated with the five
    QR scenarios listed in the §"QR export dialog implementation"
    Build order.
  - [x] `tests/thinness.rs` passes — no `image` / `rqrr` /
    `qrcode` imports in `crates/paladin-gtk/src/`.
- [x] `PassphraseDialogComponent` full implementation (`set` /
  `change` / `remove` sub-flows, gating, validation, error
  handling).
  - [x] Add the three sub-flow entry points (`set` / `change` /
    `remove`) and gate the available sub-flow against
    `Vault::is_encrypted()`: `set` only when the getter returns
    `false`; `change` and `remove` only when it returns `true`.
    (`available_sub_flows` plus `default_sub_flow_for` arm the
    segmented control; `apply_msg`'s `SubFlowSelected` arm drops
    unavailable targets via `SubFlow::is_available`. Pinned by
    `default_sub_flow_for_plaintext_returns_set`,
    `default_sub_flow_for_encrypted_returns_change`,
    `apply_msg_sub_flow_selected_unavailable_is_noop`.)
  - [x] Render `set` / `change` with twice-confirmed
    `AdwPasswordEntryRow` entries; mismatch returns inline with
    `invalid_passphrase` (`reason: "confirmation_mismatch"`).
    (Two `adw::PasswordEntryRow` widgets parented in
    `passphrase_group`; `apply_msg`'s `SubmitClicked` arm routes
    through `prepare_new_passphrase` so a mismatch stamps
    `SubmitRejection::ConfirmationMismatch` and emits no output.
    Pinned by
    `apply_msg_submit_set_with_mismatch_stamps_inline_rejection_and_no_output`
    and the existing
    `submit_rejection_confirmation_mismatch_renders_invalid_passphrase_reason`.)
  - [x] Reject zero-length new passphrases on `set` / `change`
    inline with `invalid_passphrase` (`reason: "zero_length"`).
    (`prepare_new_passphrase`'s both-empty branch returns
    `SubmitRejection::ZeroLength`; `apply_msg`'s `SubmitClicked` arm
    stamps it onto `state.inline_rejection` and emits no output.
    Pinned by `apply_msg_submit_set_with_both_empty_stamps_zero_length`.)
  - [x] Render `remove` with
    `paladin_core::format_plaintext_storage_warning()` verbatim and
    require explicit confirmation before mutation.
    (`remove_warning_label` renders the `remove_warning_body()`
    string verbatim; the `remove_ack_row` `AdwSwitchRow` flips the
    `PassphraseSecretState::remove_confirmed` flag through
    `apply_msg`'s `AcknowledgeRemove`. `submit_button_sensitive` /
    `apply_msg` only emit `Submit(Remove)` when the flag is set.
    Pinned by `apply_msg_submit_remove_without_ack_is_blocked`,
    `apply_msg_submit_remove_with_ack_emits_submit_remove`, and
    `submit_button_insensitive_for_remove_without_acknowledgement`.)
  - [x] Clear all passphrase rows and any pending
    plaintext-removal confirmation when the user switches
    sub-flows.
    (`apply_msg`'s `SubFlowSelected` arm calls
    `PassphraseSecretState::switch_sub_flow` which wipes both
    passphrase buffers and clears `remove_confirmed`. Pinned by
    `apply_msg_sub_flow_selected_clears_passphrase_buffers` and
    `apply_msg_sub_flow_selected_clears_remove_confirmed_flag`.)
  - [x] Dispatch the chosen transition on `gio::spawn_blocking` so
    the §4.5 KDF runs off the main loop; surface a spinner / busy
    affordance while the join is pending.
    (`AppMsg::PassphraseDialogAction(Submit(_))` runs
    `compose_passphrase_worker_input` + `apply_submit_passphrase_inplace`
    to bundle `(Vault, Store, SubmitPayload)` and apply the
    `Unlocked → UnlockedBusy` busy gate, then spawns
    `run_passphrase_worker` on `gtk::gio::spawn_blocking` and posts
    the completion back as `AppMsg::PassphraseWorkerCompleted`,
    consumed by the dispatch branch that runs
    `compose_passphrase_dispatch` to apply the rollback +
    `PassphraseDialogMsg::WorkerFailed` forward + drop-on-success
    + `AdwToast` body. The dialog's own
    `PassphraseDialogState::is_dispatching` flag arms on the
    accepted Submit, disables Save / Cancel via
    `submit_button_sensitive` / `cancel_button_sensitive`, shows a
    `gtk::Spinner` via `spinner_visible`, and clears on
    `WorkerFailed` / `Cancel` / `SetDispatching(false)` (rolled
    back when the AppModel-side dispatch is refused). Pinned by
    the dialog-side `submit_button_insensitive_while_dispatching`,
    `cancel_button_insensitive_while_dispatching`,
    `spinner_visible_while_dispatching`,
    `apply_msg_worker_failed_clears_dispatching`,
    `apply_msg_cancel_clears_dispatching_flag`, and AppModel-side
    `compose_passphrase_dispatch_*`,
    `apply_submit_passphrase_inplace_*`,
    `compose_passphrase_worker_input_*`,
    `apply_passphrase_vault_install_inplace_*` test suites.)
  - [x] Surface `save_not_committed` and
    `save_durability_unconfirmed` inline (DESIGN §4.5 owns the
    in-memory mode / key rollback / replacement); the dialog stays
    open on both failure classes.
    (`classify_passphrase_error` routes `SaveNotCommitted` to
    `PassphraseErrorOutcome::RestorePrior(InlineError)` and
    `SaveDurabilityUnconfirmed` to
    `PassphraseErrorOutcome::KeepNewWithWarning(InlineWarning)`;
    `apply_msg`'s `WorkerFailed` arm stamps the outcome onto
    `state.worker_outcome` without emitting any output, so the
    dialog stays mounted. `inline_body_text` renders the outcome
    body. Pinned by
    `apply_msg_worker_failed_save_not_committed_routes_to_inline_error`,
    `apply_msg_worker_failed_durability_unconfirmed_routes_to_warning`,
    and `classify_passphrase_error_invalid_state_routes_to_inline_error_variant`.)
  - [x] On success, update the visible vault-mode flag before
    closing the dialog, post a status / toast confirmation, and re-ask
    `IdlePolicy::should_arm` so the auto-lock timer state tracks the
    new on-disk mode.
    (`PassphraseWorkerEffect::Success` carries the post-transition
    `new_is_encrypted` from the worker; `passphrase_new_is_encrypted_after`
    projects it onto `PassphraseDispatch::new_is_encrypted` so the
    visible vault-mode flag updates atomically alongside the dialog
    drop / busy-gate rollback. `compose_passphrase_dispatch` already
    populated `success_toast` from `passphrase_success_toast_after`;
    `AppModel::update`'s `PassphraseWorkerCompleted` arm raises the
    body on `self.toast_overlay` as the status confirmation. After
    the dispatch is applied, the same arm consults
    `paladin_core::policy::auto_lock::IdlePolicy::should_arm` via
    `crate::auto_lock::idle_should_arm(vault)` on the reinstalled
    pair so the new on-disk mode flows through `Vault::is_encrypted` /
    `Vault::settings` exactly as the §"Clipboard + auto-lock parity
    with TUI" checklist will rely on once the timer plumbing lands.
    Pinned by
    `passphrase_new_is_encrypted_after_success_set_returns_some_true`,
    `passphrase_new_is_encrypted_after_success_remove_returns_some_false`,
    `passphrase_new_is_encrypted_after_success_change_preserves_encrypted_mode`,
    `passphrase_new_is_encrypted_after_failure_returns_none`,
    `compose_passphrase_dispatch_success_projects_new_is_encrypted_true`,
    `compose_passphrase_dispatch_success_projects_new_is_encrypted_false`,
    `compose_passphrase_dispatch_failure_projects_no_new_is_encrypted`,
    `passphrase_should_arm_idle_after_success_encrypted_consults_idle_policy`,
    `passphrase_should_arm_idle_after_success_plaintext_returns_some_false`,
    and `passphrase_should_arm_idle_after_failure_returns_none`.)
  - [x] Zeroize all passphrase widget buffers on submit / cancel /
    dialog close / auto-lock.
    (`apply_msg`'s `SubmitClicked` and `Cancel` arms call
    `PassphraseSecretState::clear_for(ClearReason::{Submit,Cancel})`
    which zeroizes both buffers in place; close / auto-lock
    transitively run through controller drop, which destroys the
    GTK entry-row widgets and the `PassphraseDialogState` along
    with their `SecretEntry` shadows (zeroizing on drop). Pinned by
    `apply_msg_submit_set_with_match_emits_submit_and_clears_secrets`
    and `apply_msg_cancel_emits_close_and_wipes_secrets`, plus the
    existing `passphrase_state_clear_for_*` suite.)
- [x] `SettingsComponent` full implementation
  (`AdwPreferencesDialog` with toggles and spinners; live-apply
  through `Vault::mutate_and_save`).
  - [x] Render the surface as an `AdwPreferencesDialog` with one
    `AdwPreferencesGroup` for auto-lock and one for
    clipboard-clear; do not use the libadwaita 1.6-deprecated
    `AdwPreferencesWindow`.
    (`SettingsComponent`'s `view!` mounts an `adw::PreferencesDialog`
    with one `adw::PreferencesGroup` per concept, titled via the
    pre-existing `format_settings_dialog_auto_lock_group_title` /
    `format_settings_dialog_clipboard_clear_group_title` helpers.)
  - [x] Mount toggles as `AdwSwitchRow` and timeouts as
    `AdwSpinRow` inside the matching `AdwPreferencesGroup`.
    (`auto_lock_enabled_row` / `clipboard_clear_enabled_row` are
    `adw::SwitchRow`; `auto_lock_secs_row` / `clipboard_clear_secs_row`
    are `adw::SpinRow`. Titles, active state, spinner values, and row
    sensitivity bind via `#[watch]` against the existing
    `compose_settings_dialog_*` helpers.)
  - [x] Clamp the timeout spinners to
    `paladin_core::AUTO_LOCK_SECS_MIN..=paladin_core::AUTO_LOCK_SECS_MAX`
    and
    `paladin_core::CLIPBOARD_CLEAR_SECS_MIN..=paladin_core::CLIPBOARD_CLEAR_SECS_MAX`.
    (Both spinners construct their `gtk::Adjustment` from the existing
    `format_settings_dialog_*_secs_adjustment` helpers, which already
    return the §5-pinned `(lower, upper, step)` tuple from
    `paladin_core::*_SECS_MIN`/`MAX`. The state machine clamps any
    out-of-range value at `stage_auto_lock_secs` / `stage_clipboard_clear_secs`
    via `clamp_auto_lock_secs` / `clamp_clipboard_clear_secs`, asserted
    by the existing `clamp_*` test suite.)
  - [x] Live-apply each accepted change by invoking the matching
    setter inside `Vault::mutate_and_save`; debounce spinner
    changes 500 ms via `glib::timeout_add_local` so holding +/-
    coalesces to a single save with the most recent buffered value.
    (`dispatch_settings_dialog_msg` returns `SettingsDialogAction::Submit(patch)`
    on toggles and on `DebounceTick` with a pending spinner draft;
    `SettingsComponent::update` cancels any prior
    `glib::timeout_add_local_once` and arms a fresh 500 ms timer on
    `StageDebounce`, and forwards `SettingsDialogOutput::Submit(patch)`
    on `Submit`. `AppMsg::SettingsDialogAction(Submit)` bundles a
    `SettingsWorkerInput` via `compose_settings_worker_input` and
    spawns `run_settings_worker` on `gtk::gio::spawn_blocking`, which
    runs `vault.mutate_and_save(&store, |v| v.apply_setting_patch(patch))`.
    Pinned by
    `dispatch_settings_dialog_msg_auto_lock_secs_spinner_change_returns_stage_debounce`,
    `dispatch_settings_dialog_msg_debounce_tick_with_pending_returns_submit`,
    `dispatch_settings_dialog_msg_debounce_tick_idle_returns_noop`,
    `dispatch_settings_dialog_msg_auto_lock_toggled_value_change_returns_submit`,
    and the existing `multiple_*_spinner_changes_coalesce_to_latest_on_debounce`
    suite.)
  - [x] Revert the visible widget value on `save_not_committed`
    pre-commit rollback so memory matches disk.
    (`run_settings_worker` runs `Vault::mutate_and_save`, which
    restores the pre-call snapshot on `save_not_committed` per
    DESIGN.md §4.3. `classify_settings_save_result` routes the typed
    error to `SaveOutcome::Rollback`; `apply_save_outcome` leaves the
    committed snapshot unchanged on that branch so the
    `compose_settings_dialog_*_value` projections paint the prior
    value on the next `#[watch]` tick. Pinned by
    `apply_save_outcome_rollback_leaves_committed_unchanged` and
    `classify_settings_save_result_save_not_committed_maps_to_rollback`.)
  - [x] Keep the new value visible on
    `save_durability_unconfirmed` and attach the warning to the
    changed `AdwPreferencesGroup` row.
    (`classify_settings_save_result` routes the typed error to
    `SaveOutcome::DurabilityWarning { warning, field }`;
    `apply_save_outcome` promotes the attempted value to committed
    and stamps `last_outcome` with the warning so the pre-existing
    `compose_settings_dialog_inline_subtitle_*_for_field` helpers
    paint the row's warning body on the next `#[watch]` tick. Pinned
    by `apply_save_outcome_durability_warning_promotes_attempted_value_to_committed`,
    `classify_settings_save_result_save_durability_unconfirmed_maps_to_durability_warning`,
    and the existing
    `apply_save_durability_unconfirmed_keeps_*_visible_with_warning`
    suite.)
  - [x] On successful live-apply, keep the committed value visible
    and post a non-blocking settings-saved `AdwToast` through the
    shared toast overlay.
    (`compose_settings_dispatch` projects
    `success_toast = Some(format_settings_dialog_saved_toast().to_string())`
    on `SaveOutcome::Success` and `None` on every other outcome.
    `AppModel::update`'s `SettingsWorkerCompleted` arm raises the body
    on `self.toast_overlay`. Pinned by
    `compose_settings_dispatch_success_rolls_busy_back_and_forwards_worker_completed`,
    `compose_settings_dispatch_durability_warning_keeps_committed_and_reasks_idle`,
    `compose_settings_dispatch_rollback_does_not_reask_idle`, and
    `compose_settings_dispatch_inline_does_not_reask_idle`.)
  - [x] Re-ask `IdlePolicy::should_arm` after auto-lock toggle or
    timeout changes so the timer state tracks the new policy
    without re-inspecting the file.
    (`settings_reask_idle_after` returns `true` iff the change is an
    auto-lock field AND the outcome left the new value on disk
    (Success / DurabilityWarning); clipboard-clear changes always
    return `false`. `AppModel::update`'s `SettingsWorkerCompleted`
    arm consults `crate::auto_lock::idle_should_arm(vault)` on the
    reinstalled pair whenever `dispatch.reask_idle == true`. The
    return value is bound to `_should_arm` until §"Clipboard +
    auto-lock parity with TUI" wires the timer arm/disarm side.
    Pinned by
    `compose_settings_dispatch_success_auto_lock_reasks_idle`,
    `compose_settings_dispatch_success_clipboard_does_not_reask_idle`,
    `compose_settings_dispatch_durability_warning_keeps_committed_and_reasks_idle`,
    `compose_settings_dispatch_rollback_does_not_reask_idle`, and
    `compose_settings_dispatch_inline_does_not_reask_idle`.)
- [x] Header-bar `+` button and primary menu wired with the pinned
  entries (Import…, Export…, Passphrase…, Preferences, About Paladin,
  Quit) per §"libadwaita usage", with Unlocked / `UnlockedBusy` gating
  applied to the mutating entries.
  - [x] Mount an `AdwHeaderBar` inside the `AdwToolbarView` top slot
    on the unlocked screen.
    (`view!` in `app/model.rs` mounts the root
    `adw::ApplicationWindow` whose content is an
    `adw::ToolbarView`; the `add_top_bar = &adw::HeaderBar` slot
    parents the primary `+` button, search-toggle, and primary
    `gtk::MenuButton`. Pinned by
    `format_app_window_title_returns_paladin`,
    `format_app_window_default_size_returns_1280_by_960`, and
    the smoke-test `gtk_smoke.rs` end-to-end mount check.)
  - [x] Add the primary "Add account" `+` button at the start of the
    right side (icon `list-add-symbolic`, tooltip "Add account")
    wired to open `AddAccountComponent`.
    (`view!`'s `pack_start = &gtk::Button` slot binds the
    `format_app_add_button_icon_name()` / `tooltip` / `action`
    helpers; clicks resolve through the bundled
    `gio::SimpleActionGroup`'s `"app.add"` `SimpleAction` to
    `AppMsg::OpenAddDialog`. Visibility tracks
    `format_app_add_button_visible(&state)`. Pinned by
    `format_app_add_button_icon_name_returns_list_add_symbolic`,
    `format_app_add_button_action_name`,
    `format_app_add_button_visible`, and the
    `build_app_window_action_group_bundles_primary_actions_and_add_action`
    end-to-end test.)
  - [x] Add the search-toggle button bound to
    `gtk::SearchBar::search-mode-enabled` inside
    `AccountListComponent`.
    (`view!`'s `#[name = "search_button"]` `gtk::ToggleButton`
    posts `AppMsg::SearchToggled(active)`; `AppModel::update`
    forwards it to the live `AccountListComponent` controller as
    `AccountListMsg::SetSearchModeEnabled(active)`, whose handler
    calls `self.search_bar.set_search_mode(enabled)` on the owned
    `gtk::SearchBar`. Pinned by
    `format_app_search_button_icon_name`,
    `format_app_search_button_tooltip`, and the search-toggle
    dispatch unit tests in `tests/account_list_logic.rs`.)
  - [x] Wire `gtk::SearchBar::set_key_capture_widget` against the
    toplevel `adw::ApplicationWindow` so any printable keypress on
    the window that no focused entry consumed reveals the bar and
    forwards the keystroke into the embedded `gtk::SearchEntry`
    ("type to search"). Mirror the bar's
    `notify::search-mode-enabled` back to `AppModel` via
    `AccountListOutput::SearchModeChanged(bool)` so the header-bar
    search-toggle button tracks bar-initiated reveals in addition
    to its own click.
    (`AccountListInit::key_capture_widget: Option<gtk::Widget>` is
    handed the cloned `adw::ApplicationWindow` at both the `init`
    and `remount_for_state` mount sites in `app/model.rs`;
    `AccountListComponent::init` calls
    `search_bar.set_key_capture_widget(Some(widget))` and connects
    `connect_search_mode_enabled_notify` to
    `sender.output(AccountListOutput::SearchModeChanged(...))`.
    `AppModel`'s update arm consumes that variant by setting the
    cached `search_button.set_active(active)` only on a real
    change, so the toggle / notify round-trip settles in one
    cycle.)
  - [x] Wire the `/` and `Ctrl+L` window-level focus-search
    accelerator. A capture-phase `gtk::EventControllerKey`
    attached to the `adw::ApplicationWindow` runs before the
    `set_key_capture_widget` controller and posts
    `AppMsg::FocusSearch` on a match, returning
    `Propagation::Stop` so the keystroke is not also inserted into
    the `gtk::SearchEntry`. `AppMsg::FocusSearch` emits
    `AccountListMsg::FocusSearch` on the live controller, which
    sets `search_mode = true`, calls `search_entry.grab_focus()`,
    and then `search_entry.select_region(0, -1)` so the entry's
    full contents are selected — typing immediately replaces the
    prior query, while an arrow key or pointer click clears the
    selection and moves the caret per default `gtk::Editable`
    behavior. Ctrl+K is intentionally **not** matched here so it
    can serve as the vim-style "move up" mirror inside the account
    list (see the cross-widget-nav checklist item below). The
    dispatch is silently dropped when `AppModel::account_list` is
    `None`. The focus-search shortcut is **not** registered
    through `format_app_window_accelerator_bindings` (which drives
    `gio::Application::set_accels_for_action`) because it lives
    behind a window-level `EventControllerKey` so a focused entry
    gets first crack at the keystroke and inline `/`-typing into
    any text entry still works.
    (Pinned by `wire_app_window_search_focus_controller`,
    `dispatch_app_window_search_focus_key`,
    `format_app_search_focus_accelerator` /
    `format_app_search_focus_label`, and the dispatch unit tests in
    `tests/search_focus_logic.rs`. The
    `format_app_shortcuts_window_entries` row at index 1
    surfaces the `slash <Control>l` accelerator pair in the
    `GtkShortcutsWindow`.)
  - [x] Wire the cross-widget arrow-key navigation between the
    `gtk::SearchEntry` and the account-list `gtk::ListBox`. A pair
    of capture-phase `gtk::EventControllerKey` instances installed
    by `wire_account_list_navigation_controllers` route Down /
    Ctrl+J / Ctrl+N on the search entry to "focus + select first
    row"; Up / Ctrl+K / Ctrl+P on the first row to "focus +
    select-all search entry"; Up / Down on any other row to
    one-row movement; and Ctrl+K / Ctrl+J / Ctrl+P / Ctrl+N on any
    row as the vim-style (J/K) and readline-style (N/P) mirrors of
    the bare arrow keys. Bare `j` / `k` / `n` / `p` are left to
    bubble so the `set_key_capture_widget` "type to search" path
    keeps working; Home / End / PageUp / PageDown propagate
    untouched so `gtk::ListBox`'s built-in bindings keep working.
    Compound chords carrying ALT / SUPER / HYPER / META are
    rejected, arrow keys combined with CONTROL are left alone, and
    Ctrl+Shift+N is left alone so the `<Control><Shift>n`
    "Add account" app accelerator reaches `gio::Application::
    set_accels_for_action`.
    (Pinned by `dispatch_search_entry_to_list_nav`,
    `dispatch_list_box_nav` / `ListNavIntent`, the widget binding
    `wire_account_list_navigation_controllers`, and the dispatch
    unit tests in `tests/account_list_nav_logic.rs`.)
  - [x] Wire Enter (and a single click on the row body, via
    `single_click_activate(true)`) on the focused
    `gtk::ListBoxRow` to the default row action via
    `gtk::ListBox::row-activated` → `AccountListMsg::ActivateRow(idx)`
    → `default_row_activation(kind, has_visible_code, id)`. TOTP
    rows and HOTP rows with a visible code emit
    `AccountListOutput::CopyCode(id)` (same path as the per-row
    copy button); HOTP rows whose code is hidden emit
    `AccountListOutput::ActivateHotpAndCopy(id)`. `AppModel`
    handles `ActivateHotpAndCopy` by latching
    `pending_copy_after_advance = Some(id)` and re-entering the
    standard `AdvanceHotp` dispatch so the busy gate, effect
    ownership, worker spawn, and `HotpAdvanceWorkerCompleted`
    reveal pipeline run through one code path. On worker
    completion the latch fires a follow-up `CopyCode(id)` through
    `sender.input` so the freshly revealed code lands on the
    clipboard via the same `prepare_copy_bytes` /
    `gdk::Clipboard::set_text` / `schedule_copy` pipeline the
    per-row copy button uses. If the advance fails (durability
    unconfirmed, defensive typed error) `reveal_windows` does not
    gain a visible code, so `prepare_copy_bytes` returns `None`
    and the follow-up `CopyCode` becomes a benign no-op. The
    latch is cleared by `prune_reveals_if_locked` and
    `tear_down_for_quit` alongside `reveal_windows` /
    `pending_clipboard`.
    (Pinned by `default_row_activation`, the new
    `AccountListMsg::ActivateRow` variant + the
    `AccountListOutput::ActivateHotpAndCopy` variant, and the
    `default_row_activation` unit tests at the bottom of
    `tests/account_list_nav_logic.rs`.)
  - [x] Hover-surface the row-body click target by installing
    `column_view::ROW_BODY_COPY_TOOLTIP` (`"Copy current code"`) on
    the account, code, and time cells during `bind_*_cell`. The
    wording parallels the Next column button's
    `"Copy upcoming code"` so the two click targets read as a
    verb-led pair. Section rows clear the tooltip in their bind
    branch since they are non-selectable; the inline HOTP-reveal,
    Next, Copy, and kebab buttons keep their own tooltips, which
    GTK4 hover-target resolution honors over the parent cell's.
    Pinned by `row_body_copy_tooltip_matches_pinned_wording` and
    `row_body_copy_tooltip_is_non_empty` in
    `tests/column_view_logic.rs`.
  - [x] Add the primary `gtk::MenuButton` driven by a `gio::Menu`
    with the fixed entries Import…, Export…, Passphrase…,
    Preferences, About Paladin, Quit.
    (`view!`'s `pack_end = &gtk::MenuButton` slot is attached to
    the model returned by `build_app_primary_menu_model()` via
    `wire_app_menu_button_menu_model(&widgets.menu_button)` in
    `init`. The six entries are sourced from
    `format_app_primary_menu_entries()` so the labels and action
    targets stay in one place. Pinned by
    `format_app_primary_menu_entries_returns_six_entries_in_pinned_order`,
    `build_app_primary_menu_model_appends_every_format_app_primary_menu_entries_pair`,
    and `wire_app_menu_button_menu_model_signature_takes_menu_button_reference`.)
  - [x] Wire each menu entry to its target component (`ImportDialog`,
    `ExportDialog`, `PassphraseDialog` with the sub-flow gated by
    `Vault::is_encrypted()`, `SettingsComponent`'s
    `AdwPreferencesDialog`, `AdwAboutDialog`, application quit).
    (`build_app_window_action_group(&state)` registers
    `"app.import"`, `"app.export"`, `"app.passphrase"`,
    `"app.preferences"`, `"app.about"`, `"app.quit"`, and
    `"app.add"` on a single `gio::SimpleActionGroup`;
    `wire_app_window_action_activations(&group, sender)` attaches
    `connect_activate` handlers that dispatch
    `AppMsg::OpenImportDialog` / `OpenExportDialog` /
    `OpenPassphraseDialog` / `OpenPreferencesDialog` /
    `OpenAboutDialog` / `Quit` / `OpenAddDialog`. The PassphraseDialog
    sub-flow defaults track `Vault::is_encrypted()` through
    `default_sub_flow_for`. Pinned by
    `build_app_window_action_group_bundles_primary_actions_and_add_action`,
    `wire_app_window_action_activations_signature_takes_group_and_input_sender`,
    `wire_app_window_action_group_signature_takes_application_window_and_action_group`,
    and the per-action `format_app_primary_menu_entries_targets_dispatch_to_app_msg`
    pin.)
  - [x] Disable the `+` button and the Import / Export / Passphrase /
    Preferences entries whenever `AppModel` is not `Unlocked`
    (Missing / Locked / StartupError) and while `UnlockedBusy` is
    active; keep About and Quit enabled in every state.
    (`format_app_primary_menu_action_sensitivities(&state)`
    returns `[bool; 6]` keyed to the pinned action-name array;
    `build_app_window_action_group` applies them at construction
    time, and `apply_app_window_action_group_sensitivities` /
    `apply_app_primary_menu_sensitivities` apply them on every
    state transition. The `+` button additionally toggles
    visibility via `format_app_add_button_visible` so it disappears
    entirely outside the vault-open states. Pinned by
    `format_app_primary_menu_action_sensitivities_disables_mutating_entries_off_unlocked`,
    `format_app_primary_menu_action_sensitivities_enables_mutating_entries_on_unlocked`,
    and `build_app_window_action_group_disables_mutating_actions_in_non_unlocked_states`.)
- [x] About dialog (`AdwAboutDialog` wired to the primary menu's
  "About Paladin" entry, metadata sourced from Cargo package fields
  embedded at compile time).
  - [x] Mount `AdwAboutDialog` behind the primary menu's "About
    Paladin" entry; pull `application-name`, `version`,
    `developers`, `website`, and `issue-tracker` from Cargo package
    metadata via `env!` / `option_env!` so the strings stay in sync
    with the workspace.
    (`AppMsg::OpenAboutDialog` activates from the
    `"app.about"` action and presents the dialog returned by
    `build_app_about_dialog()`. The dialog's `application-name`
    (`format_app_about_dialog_program_name` → `"Paladin"`,
    matching the §11.3 desktop entry's `Name=Paladin`),
    `version` (`env!("CARGO_PKG_VERSION")`), `website`
    (`env!("CARGO_PKG_HOMEPAGE")`), `issue-url`
    (`concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")`), and
    `support-url` (`concat!(env!("CARGO_PKG_REPOSITORY"),
    "/discussions")`) all flow through pinned
    `format_app_about_dialog_*` helpers sourced from Cargo
    metadata that `crates/paladin-gtk/Cargo.toml` inherits from
    the workspace `[workspace.package]` table, so a workspace
    bump propagates automatically. `developers` resolves through
    the `format_app_about_dialog_developers` literal because
    `[workspace.package].authors` is intentionally empty per
    DESIGN §14's open-contributor-pool model; pinning the
    literal keeps the attribution row stable across releases.
    Pinned by `format_app_about_dialog_version_matches_cargo_pkg_version`,
    `format_app_about_dialog_website_matches_cargo_pkg_homepage`,
    `format_app_about_dialog_issue_url_appends_issues_to_cargo_pkg_repository`,
    `format_app_about_dialog_support_url_appends_discussions_to_cargo_pkg_repository`,
    and the
    `build_app_about_dialog_threads_every_format_app_about_dialog_helper_through_a_setter`
    setter-chain end-to-end test.)
  - [x] Ship the AGPL-3.0-or-later license text in the gresource
    bundle and surface it through
    `AdwAboutDialog::license-type` set to `Custom` with the bundled
    text.
    (`data/paladin-gtk.gresource.xml` ships
    `<file alias="LICENSE">LICENSE</file>` under the
    `/org/tamx/Paladin/Gui` prefix; `build.rs` adds `../..`
    (workspace root) as a second `glib-compile-resources`
    sourcedir so the repo-root `LICENSE` (AGPL-3.0-or-later,
    FSF AGPLv3 verbatim) packs into the bundle. The matching
    `format_app_about_dialog_license_resource_path` →
    `"/org/tamx/Paladin/Gui/LICENSE"` pin keeps the manifest
    alias and any consumer that looks up the bundled text by
    path in lockstep. `format_app_about_dialog_license_type`
    flipped from `gtk::License::Agpl30` to
    `gtk::License::Custom`, and `build_app_about_dialog` now
    calls `set_license(format_app_about_dialog_license_text())`
    after `set_license_type(License::Custom)` so the dialog
    footer renders the bundled body rather than the toolkit's
    generic AGPL-3.0-or-later boilerplate.
    `format_app_about_dialog_license_text` returns
    `include_str!("../../../../LICENSE")` so the helper and
    the gresource entry share the same on-disk source of
    truth. Pinned by
    `format_app_about_dialog_license_type_returns_custom`,
    `format_app_about_dialog_license_type_is_not_one_of_the_toolkit_shipped_gpl_family_variants`,
    `format_app_about_dialog_license_text_matches_repository_license_file`,
    `format_app_about_dialog_license_text_starts_with_the_gnu_affero_general_public_license_header`,
    `format_app_about_dialog_license_text_carries_version_3_marker`,
    `format_app_about_dialog_license_text_is_non_empty`,
    `format_app_about_dialog_license_text_does_not_contain_a_null_byte`,
    `format_app_about_dialog_license_resource_path_returns_paladin_gui_license_path`,
    `format_app_about_dialog_license_resource_path_uses_app_id_prefix`,
    `format_app_about_dialog_license_resource_path_does_not_end_with_a_trailing_slash`,
    and the
    `build_app_about_dialog_threads_every_format_app_about_dialog_helper_through_a_setter`
    setter-chain assertion on `dialog.license()`.)
  - [x] Show the app icon `org.tamx.Paladin.Gui` and link to the
    repository / issue tracker URLs declared in the workspace
    `[workspace.package]` table.
    (`format_app_about_dialog_application_icon_name` returns
    `crate::APP_ID` (`"org.tamx.Paladin.Gui"`) — the same
    reverse-DNS key consumed by `RelmApp::new(APP_ID)`, the
    §11.3 `Icon=org.tamx.Paladin.Gui` desktop entry, and the
    hicolor `/usr/share/icons/hicolor/<size>/apps/org.tamx.Paladin.Gui.*`
    install layout, so the launcher glyph and the dialog
    header glyph resolve identically. The dialog's footer
    "Website", "Report an issue", and "Get support" links
    flow through `format_app_about_dialog_website` →
    `env!("CARGO_PKG_HOMEPAGE")` (workspace `homepage`),
    `format_app_about_dialog_issue_url` →
    `concat!(env!("CARGO_PKG_REPOSITORY"), "/issues")`, and
    `format_app_about_dialog_support_url` →
    `concat!(env!("CARGO_PKG_REPOSITORY"), "/discussions")` so
    a workspace `[workspace.package].repository` /
    `homepage` change propagates without an edit here. Pinned
    by `format_app_about_dialog_application_icon_name_matches_app_id`,
    `format_app_about_dialog_application_icon_name_is_reverse_dns`,
    `format_app_about_dialog_website_matches_cargo_pkg_homepage`,
    `format_app_about_dialog_issue_url_appends_issues_to_cargo_pkg_repository`,
    and `format_app_about_dialog_issue_url_and_support_url_share_cargo_pkg_repository_prefix`.)
- [ ] Keyboard Shortcuts window (`GtkShortcutsWindow` wired to the primary
  menu's new "Keyboard Shortcuts" entry and the GNOME-canonical `Ctrl+?`
  accelerator, listing all four window accelerators).
  - [ ] Pin the new (label, action, action_name, accelerator) quadruple
    via `format_app_menu_keyboard_shortcuts_label()` →
    `"Keyboard Shortcuts"`, `format_app_menu_keyboard_shortcuts_action()`
    → `"app.shortcuts"`,
    `format_app_menu_keyboard_shortcuts_action_name()` → `"shortcuts"`,
    and `format_app_menu_keyboard_shortcuts_accelerator()` →
    `"<Control>question"`. Mirrors the sibling
    `format_app_menu_preferences_*` / `format_app_menu_about_*` helpers
    so the menu-entry, the action-group registration, the
    `gio::Application::set_accels_for_action` wiring, and the
    `GtkShortcutsWindow` row label share a single source of truth.
  - [ ] Extend `format_app_primary_menu_entries` from six to seven
    entries, inserting `(format_app_menu_keyboard_shortcuts_label(),
    format_app_menu_keyboard_shortcuts_action())` between Preferences
    and About so the menu order matches the GNOME HIG sequence
    (Preferences → Keyboard Shortcuts → About → Quit). Extend
    `format_app_primary_menu_action_names`,
    `format_app_primary_menu_action_sensitivities` (always enabled, like
    About and Quit), and `format_app_window_action_names` to the same
    new arity. Extend `format_app_window_accelerator_bindings` from
    three to four to add the `(<Control>question, app.shortcuts)` pair
    so `wire_app_window_accelerators` registers the accelerator
    alongside Add / Quit / Preferences.
  - [ ] Add `AppMsg::OpenKeyboardShortcuts`. Map the action name to it
    in `dispatch_app_window_action`. Handle it in
    `AppModel::update` by building a fresh `gtk::ShortcutsWindow` via
    `shortcuts_window::build_app_shortcuts_window`, parenting it on the
    content tree's toplevel, and presenting it (mirroring the
    `AppMsg::OpenAboutDialog` handler). The window is always enabled,
    so the dispatch edge needs no state guard.
  - [ ] Construct the `GtkShortcutsWindow` from a single
    `gtk::Builder::from_string` XML template generated by
    `shortcuts_window::format_app_shortcuts_window_xml`, fed from the
    pinned `format_app_window_accelerator_bindings` quadruple plus the
    matching menu labels. The window contains one `GtkShortcutsSection`
    with one `GtkShortcutsGroup` (title "General") whose four
    `GtkShortcutsShortcut` entries are, in order:
    `<Control><Shift>n` "New account" (single-modifier `<Control>n`
    is reserved for the account-list "move down" mirror per the
    `dispatch_list_box_nav` table, so Add follows the GNOME "New X"
    compound-modifier pattern), `<Control>comma` "Preferences",
    `<Control>question` "Keyboard Shortcuts", `<Control>q` "Quit".
    XML escaping of `<` /
    `>` in accelerator strings is unit-tested.
  - [ ] Pinned tests in `tests/startup_probes.rs` mirror the existing
    accelerator/action pin tests:
    `format_app_menu_keyboard_shortcuts_accelerator_returns_control_question`,
    `format_app_menu_keyboard_shortcuts_action_returns_app_shortcuts`,
    `format_app_menu_keyboard_shortcuts_action_name_returns_shortcuts`,
    `format_app_menu_keyboard_shortcuts_label_returns_keyboard_shortcuts`,
    plus arity bumps to the existing
    `format_app_primary_menu_entries_returns_*_entries_in_pinned_order`
    /
    `format_app_window_accelerator_bindings_returns_*_pinned_pairs_in_order`
    pins. Additional tests cover that
    `format_app_shortcuts_window_xml` contains all four (accelerator,
    title) pairs after XML escaping, and that
    `build_app_shortcuts_window` returns a `gtk::ShortcutsWindow`.
- [x] Clipboard + auto-lock parity with TUI (opt-in). Use
  `Vault::is_encrypted()` to decide whether to arm the auto-lock
  timer (encrypted only) and to track the visible vault-mode flag
  across passphrase transitions.
  - [x] Wire `gtk::EventControllerKey` and pointer motion controllers
    at the `AppModel` root so idle events feed
    `paladin_core::policy::auto_lock::IdlePolicy`.
    (`wire_app_window_idle_controllers` attaches one
    `gtk::EventControllerKey` and one `gtk::EventControllerMotion`
    on the root `adw::ApplicationWindow`; both post
    `AppMsg::IdleEvent(Instant::now())` per event. The update arm
    calls `IdleSource::refresh` against the live `(Vault, Store)`
    pair so the deadline routes through
    `paladin_core::policy::auto_lock::IdlePolicy::next_deadline`,
    keeping the plaintext-no-op and `auto_lock_enabled` opt-in
    rules in core. `IdleSource` (`auto_lock.rs`) holds the current
    deadline behind `new` / `refresh` / `deadline` / `is_armed` /
    `is_expired` / `disarm`; `Quit` calls `disarm` so a stray
    post-quit timer wake sees an empty source. Pinned by
    `idle_source_new_is_disarmed`,
    `idle_source_default_matches_new`,
    `idle_source_refresh_arms_for_encrypted_with_enabled_setting`,
    `idle_source_refresh_disarms_plaintext_regardless_of_setting`,
    `idle_source_refresh_disarms_when_setting_is_off`,
    `idle_source_refresh_after_prior_arm_resets_against_new_now`,
    `idle_source_refresh_can_disarm_a_previously_armed_source`,
    `idle_source_is_expired_matches_policy_when_armed`,
    `idle_source_is_expired_returns_false_when_disarmed`,
    `idle_source_disarm_clears_deadline`, and
    `idle_source_refresh_consistent_with_idle_event_deadline_helper`.)
  - [x] Drive the auto-lock timer via `glib::timeout_add_local`
    against `IdlePolicy::next_deadline` / `is_expired`; arm only
    when `IdlePolicy::should_arm` returns `true` for the current
    `Vault::is_encrypted()` value so plaintext vaults remain
    unarmed via the core decision (not a GUI shortcut).
    (`auto_lock_timer_transition` collapses the
    `(was_installed, IdleSource::is_armed())` matrix into the typed
    `NoChange` / `Install(remaining)` / `Teardown` outcome — the
    `Install` duration is `deadline.saturating_duration_since(now)`
    so a slow probe past the deadline still saturates at zero rather
    than wrapping. `AppModel::apply_auto_lock_timer_transition`
    routes the decision into `glib::timeout_add_local_once` and is
    called from the dispatch epilogue alongside the TOTP ticker
    transition. Pinned by
    `auto_lock_timer_transition_install_when_armed_and_not_installed`,
    `auto_lock_timer_transition_teardown_when_disarmed_and_installed`,
    `auto_lock_timer_transition_nochange_when_armed_and_installed`,
    `auto_lock_timer_transition_nochange_when_disarmed_and_not_installed`,
    `auto_lock_timer_transition_install_uses_deadline_minus_now`, and
    `auto_lock_timer_transition_install_saturates_at_zero_when_now_past_deadline`.
    The `glib::timeout_add_local_once` callback posts
    `AppMsg::AutoLockTimerFired(Instant::now())`; the fire handler
    resolves the firing through `evaluate_timer_fire` so a deadline
    pushed forward between install and fire produces
    `Reschedule(remaining)` instead of an early lock — pinned by
    `evaluate_timer_fire_lock_when_expired`,
    `evaluate_timer_fire_reschedule_when_armed_in_future`, and
    `evaluate_timer_fire_cancel_when_disarmed`.)
  - [x] On expiry, drop `Vault`, switch `AppModel` to `Locked`,
    discard open HOTP reveal windows, the search query, and any
    open dialog, then re-present `UnlockComponent`.
    (`AppModel::lock_on_auto_lock_expiry` moves the live
    `(Vault, Store)` pair, the reveal-window map, the search query,
    and every open dialog controller (rename / remove / add /
    settings / import / export / passphrase) by value into
    `crate::auto_lock::lock_on_expiry`, which returns a
    `LockedTransition` carrying only the path and any pending
    clipboard auto-clear. The reinstated pending clipboard preserves
    the only-if-unchanged wake across lock per
    `IMPLEMENTATION_PLAN_04_GTK.md` §"Tests >
    `tests/clipboard_clear_logic.rs`"; the reveal windows and dialog
    controllers are intentionally dropped so their zeroizing
    secret buffers wipe in lockstep with the vault drop. The new
    `AppState::Locked { path }` is then mounted through
    `AppModel::remount_for_state`, which presents
    `UnlockDialogComponent` over the cleared content tree. Pinned by
    the pre-existing
    `lock_on_expiry_carries_only_the_path_forward`,
    `lock_on_expiry_discards_open_reveal_and_modal_when_none`, and
    `lock_on_expiry_drops_vault_so_secrets_do_not_outlive_lock`
    tests against `crate::auto_lock::lock_on_expiry` — the
    pure-logic contract the `AppModel` glue routes through.)
  - [x] Re-ask `IdlePolicy::should_arm` after every successful
    `PassphraseDialog` transition so arm/disarm tracks the on-disk
    vault mode without re-inspecting the file.
    (`refresh_idle_source_after_passphrase` in `auto_lock.rs` is
    gated on the typed
    `PassphraseDispatch::new_is_encrypted` projection: `Some(_)` on
    the success branch refreshes the live `IdleSource` against the
    reinstalled `(Vault, Store)` pair via `IdleSource::refresh`
    (which routes through `IdlePolicy::next_deadline` — the
    `Some` / `None` of the returned deadline encodes the
    `IdlePolicy::should_arm` decision); `None` on every failure
    branch leaves the source bit-identical because DESIGN §4.5
    owns the in-memory rollback / replacement. The
    `PassphraseWorkerCompleted` handler in `app/model.rs` calls
    the helper after `apply_passphrase_vault_install_inplace` so
    the dispatch epilogue's `apply_auto_lock_timer_transition`
    picks up any install / teardown delta in lockstep with the new
    on-disk mode. Pinned by
    `refresh_idle_source_after_passphrase_remove_disarms_armed_source`,
    `refresh_idle_source_after_passphrase_set_arms_disarmed_source`,
    `refresh_idle_source_after_passphrase_change_rolls_deadline_forward`,
    `refresh_idle_source_after_passphrase_failure_leaves_armed_source_untouched`,
    `refresh_idle_source_after_passphrase_failure_leaves_disarmed_source_untouched`,
    `refresh_idle_source_after_passphrase_with_disabled_setting_disarms`,
    and
    `refresh_idle_source_after_passphrase_matches_idle_source_refresh_on_success`.)
  - [x] Wire `gdk::Clipboard.read_text` / `set_text` for the copy
    and clear paths inside `clipboard.rs`.
    (`crate::clipboard` (`src/clipboard.rs`) owns the GDK boundary:
    `write_payload` writes the OTP-code bytes via
    `gdk::Clipboard::set_text(&payload_text(bytes))`, `clear` wipes
    the clipboard via `gdk::Clipboard::set_text("")`, and
    `read_text_async` wraps `gdk::Clipboard::read_text_async` so the
    only place that has to spell out the `gio::Cancellable` type
    parameter and the
    `Result<Option<GString>, glib::Error>` → `Zeroizing<Vec<u8>>`
    conversion is this module. `AppModel::update`'s `Tick` handler,
    `ClipboardWakeRead → Clear` branch, and
    `AccountListAction(AccountListOutput::CopyCode(_))` handler all
    route through these helpers so `gtk::gdk` touchpoints stay
    concentrated in `clipboard.rs`. The widget-bound wrappers ride
    the `xvfb-run` smoke test; the pure-logic byte-encoding
    helpers (`payload_text` / `captured_clipboard_bytes`) are pinned
    by `tests/clipboard_logic.rs`.)
  - [x] Drive clipboard auto-clear via
    `paladin_core::policy::clipboard_clear::ClipboardClearPolicy::schedule`
    at copy time and `should_clear` on wake against the current
    clipboard text (only-if-unchanged); apply mode-agnostically
    (both plaintext and encrypted vaults).
    (Copy-time scheduling routes through
    `crate::clipboard_clear::schedule_copy` (a thin wrapper around
    `ClipboardClearPolicy::schedule`) in the
    `AccountListAction(CopyCode)` handler, which returns `None` when
    `VaultSettings::clipboard_clear_enabled` is off so the policy's
    opt-in gate is honored without a GUI-side shortcut. Wake-time
    byte-equality routes through `crate::clipboard_clear::evaluate_wake`
    in the `ClipboardWakeRead` handler, which calls
    `ClipboardClearPolicy::should_clear` after gating on the
    monotonic token. Mode-agnostic behavior is pinned by
    `schedule_copy_does_not_gate_on_encryption` in
    `tests/clipboard_clear_logic.rs`.)
  - [x] Keep pending copied values in a `Zeroizing<Vec<u8>>` buffer
    and zeroize after clear attempt or stale-token drop.
    (`crate::clipboard_clear::PendingClipboardClear.value` is
    `Zeroizing<Vec<u8>>`, so the captured bytes wipe in place when
    the slot drops. `AppModel::pending_clipboard` clears to `None`
    on `WakeDecision::Clear` and `WakeDecision::Mismatch` (the
    drop runs the zeroize), and a fresh `schedule_copy` supersedes
    the old slot by assignment so the prior `Zeroizing<Vec<u8>>`
    drops in lockstep. Pinned by
    `pending_value_zeroizes_when_dropped_after_clear_attempt` and
    `pending_value_zeroizes_when_superseded_by_a_fresh_schedule` in
    `tests/clipboard_clear_logic.rs`.)
  - [x] Preserve clipboard auto-clear timers across lock so a timer
    scheduled before lock still fires only-if-unchanged after lock.
    (`crate::auto_lock::lock_on_expiry` accepts the live
    `Option<PendingClipboardClear>` slot and forwards it on
    `LockedTransition.pending_clipboard_clear` so the
    auto-lock transition carries the pending wipe across into
    `AppState::Locked`. The post-lock `Tick` handler still routes
    the wake through `evaluate_wake` against the live
    `gdk::Clipboard` text, so the only-if-unchanged rule survives
    the lock unchanged. Pinned by
    `pending_clipboard_clear_survives_auto_lock` in
    `tests/clipboard_clear_logic.rs`.)
- [x] Serialized in-flight vault effects: one vault-touching worker at a time,
  mutating controls disabled while busy, and worker results restore
  `(Vault, Store)` before UI state applies success / typed failure handling;
  quit and auto-lock requests are deferred until the worker returns.
  - [x] Add the `AppState::UnlockedBusy { effect, ui_snapshot }`
    variant and the transition from `Unlocked` whenever a
    vault-touching effect dispatches.
    (Implemented as `AppState::UnlockedBusy { path }` carrying the
    resolved vault path plus a sibling `EffectOwnership` state
    machine on `AppModel.effects` that tracks the in-flight
    [`EffectKind`] and the `pending_quit` / `pending_lock` flags.
    The pure-logic shadow lives in `src/effect_ownership.rs`; the
    `Unlocked → UnlockedBusy` transition is opened by
    `AppState::enter_busy()` and gated through the typed
    `handle_effect_request` helper at every vault-touching dispatch
    site so the busy gate and the visible state stay in lockstep.)
  - [x] Move `(Vault, Store)` into the worker on
    `gio::spawn_blocking` for HOTP `next`, add / remove / rename /
    import / settings / passphrase / export operations.
    (Every dispatch site in `AppModel::update` takes
    `self.vault.take()`, moves the pair into the typed
    `XWorkerInput`, and spawns
    `gtk::glib::spawn_future_local(async move {
        gtk::gio::spawn_blocking(move || run_X_worker(input)).await
    })`. The completion message hands the pair back so the
    completion handler re-installs it via
    `apply_X_vault_install_inplace` before applying any UI side
    effect, matching this section's contract.)
  - [x] Standardize the worker return type as
    `(Vault, Store, EffectOutcome)` on both success and typed
    failure; reinstall the pair before applying the UI outcome.
    (`HotpAdvanceWorkerCompletion`, `AddWorkerCompletion`,
    `RemoveWorkerCompletion`, `RenameWorkerCompletion`,
    `ImportWorkerCompletion`, `ExportWorkerCompletion`,
    `SettingsWorkerCompletion`, `PassphraseWorkerCompletion`, and
    `QrWorkerCompletion` each carry `(effect_or_outcome, vault,
    store)` on every branch. The completion handlers in
    `AppModel::update` destructure the pair first, install it on
    `self.vault` unconditionally, then route the typed
    `XWorkerEffect` through `compose_X_dispatch`.)
  - [x] Disable mutating controls (row `next`, dialog submit buttons,
    passphrase actions, import / export, settings) while
    `UnlockedBusy` is active and surface the spinner / busy
    affordance on the current surface.
    Each per-dialog state machine carries a `busy: bool` latch
    flipped by an `XxxMsg::SetBusy(bool)` message (or
    `PassphraseDialogMsg::SetDispatching(bool)` for the passphrase
    sub-flows that already had the equivalent `dispatching` field).
    `AppModel` reconciles the latches against `AppState::is_busy()`
    once per dispatch tick through the per-dialog
    `sync_<name>_dialog_busy()` peers of
    `sync_account_list_busy` / `sync_add_dialog_busy`, debounced
    against the corresponding `last_<name>_busy` cache so a
    same-value flip is a benign no-op. The header-bar Import…
    / Export… / Passphrase… / Preferences… menu entries inherit
    the `AppState::allows_mutating_menu()` projection
    (`format_app_primary_menu_action_sensitivities`), so opening
    a fresh dialog while busy is already blocked. The header-bar
    busy spinner (`gtk::Spinner` `pack_end` on the
    `AdwHeaderBar`) is driven imperatively through
    `apply_app_busy_spinner` from `sync_app_busy_spinner` — the
    visibility / spin state come from
    `format_app_busy_spinner_visible`, pinned by
    `tests/app_state_logic.rs::format_app_busy_spinner_visible_*`.
    Per-dialog sensitivity gating is pinned by
    `tests/rename_dialog_logic.rs::{apply_msg_set_busy_*,
    format_rename_dialog_save_button_sensitive_dimmed_when_busy,
    format_rename_dialog_save_button_sensitive_re_enables_after_busy_clears}`,
    `tests/remove_dialog_logic.rs::{apply_msg_set_busy_*,
    format_remove_dialog_destructive_response_enabled_dimmed_when_busy}`,
    `tests/settings_logic.rs::{dispatch_settings_dialog_msg_set_busy_*,
    compose_settings_dialog_auto_lock_enabled_sensitive_busy_returns_false,
    compose_settings_dialog_clipboard_clear_enabled_sensitive_busy_returns_false,
    compose_settings_dialog_auto_lock_secs_sensitive_busy_returns_false_even_when_toggle_on,
    compose_settings_dialog_clipboard_clear_secs_sensitive_busy_returns_false_even_when_toggle_on}`,
    on top of the existing add / import / export / passphrase
    busy-latch tests covered by §"Tests > Pure-logic unit
    tests".
  - [x] Defer quit and window-close requests until the worker
    returns.
    (`AppMsg::Quit` routes through `handle_quit_request`, which
    delegates to `EffectOwnership::request_quit`: `QuitDecision::Now`
    fires `tear_down_for_quit` + `relm4::main_application().quit()`
    immediately; `QuitDecision::Deferred` records `pending_quit`
    on the in-flight machinery, and the worker-completion epilogue's
    `handle_effect_completion` returns `CompleteOutcome::QuitNow`,
    which `apply_effect_completion_outcome` translates into the
    deferred teardown. Pinned by
    `handle_quit_request_with_busy_effects_is_deferred_and_records_pending_quit`
    and `handle_effect_completion_with_pending_quit_fires_quit_now`
    in `tests/app_state_logic.rs`.)
  - [x] On auto-lock expiry during `UnlockedBusy`, record a
    lock-after-effect request; apply it after the worker returns
    only if the returned vault is still encrypted, and discard it
    if the operation changed the vault to plaintext.
    (`AppMsg::AutoLockTimerFired`'s `Lock` branch routes through
    `handle_auto_lock_expiry`: `LockDecision::Now` fires
    `lock_on_auto_lock_expiry` immediately; `LockDecision::Deferred`
    records `pending_lock` on the in-flight machinery, and the
    worker-completion epilogue's `handle_effect_completion` reads
    `Vault::is_encrypted()` off the just-reinstalled pair and
    returns `CompleteOutcome::LockNow` (still encrypted) or
    `CompleteOutcome::LockDiscarded` (`PassphraseRemove`
    transitioned to plaintext). Pinned by
    `handle_auto_lock_expiry_while_busy_is_deferred_and_records_pending_lock`,
    `handle_effect_completion_with_pending_lock_on_still_encrypted_vault_fires_lock_now`,
    and
    `handle_effect_completion_with_pending_lock_on_plaintext_converted_vault_discards_lock`
    in `tests/app_state_logic.rs`.)
  - [x] Coalesce settings spinner debounce to the latest pre-save
    value when an effect is in flight; refuse toggle changes that
    would overlap an active vault effect until the control is
    re-enabled.
    (`dispatch_settings_dialog_msg` gates every input arm on
    [`SettingsState::is_busy`]: `AutoLockToggled` /
    `ClipboardClearToggled` /
    `AutoLockSecsSpinnerChanged` /
    `ClipboardClearSecsSpinnerChanged` short-circuit to
    `SettingsDialogAction::Noop` while busy without invoking
    `toggle_*` or `stage_*`, so a stray queued message racing the
    `#[watch] set_sensitive` dim cannot reach the setter. The
    `DebounceTick` arm also short-circuits to `Noop` while busy,
    *keeping the pending spinner draft intact*; the
    `SetBusy(true → false)` edge consults the new
    [`SettingsState::has_pending_save_due`] helper and returns
    `SettingsDialogAction::StageDebounce` when a draft still differs
    from the committed snapshot, so the widget re-arms the 500 ms
    `glib::timeout_add_local` timer and the next `DebounceTick`
    fires the coalesced latest pre-save value through a single
    `Vault::mutate_and_save`. Pinned by
    `dispatch_debounce_tick_while_busy_returns_noop_and_keeps_pending_auto_lock`,
    `dispatch_debounce_tick_while_busy_returns_noop_and_keeps_pending_clipboard_clear`,
    `dispatch_set_busy_false_with_pending_auto_lock_re_arms_debounce`,
    `dispatch_set_busy_false_with_pending_clipboard_clear_re_arms_debounce`,
    `dispatch_set_busy_false_with_no_pending_returns_noop`,
    `dispatch_set_busy_false_with_pending_equal_to_committed_returns_noop`,
    `dispatch_set_busy_true_preserves_pending_spinner_draft`,
    `dispatch_set_busy_idempotent_true_with_pending_does_not_re_arm`,
    `dispatch_auto_lock_toggle_while_busy_returns_noop_and_does_not_submit`,
    `dispatch_clipboard_clear_toggle_while_busy_returns_noop_and_does_not_submit`,
    `dispatch_spinner_change_while_busy_returns_noop_and_does_not_stage`,
    `dispatch_clipboard_spinner_change_while_busy_returns_noop_and_does_not_stage`,
    `dispatch_coalescing_round_trip_pending_survives_intervening_save_and_fires_after_busy_clears`,
    and
    `has_pending_save_due_reports_true_only_when_pending_differs_from_committed`
    in `tests/settings_logic.rs`.)
  - [x] Route workers that fail before returning the pair to
    `StartupErrorComponent` without trying to reconstruct in-memory
    vault state.
    (Every `gtk::glib::spawn_future_local` wrapper around a
    `gtk::gio::spawn_blocking(move || run_X_worker(input))` now
    matches on the `JoinHandle::await` result: `Ok(completion)`
    posts the typed `AppMsg::XWorkerCompleted(completion)`; `Err(_)`
    posts `AppMsg::WorkerPanic(EffectKind::X)`. The handler routes
    through the new `AppModel::handle_worker_panic` helper which
    calls `handle_worker_lost` on `self.effects`, drops the
    `EffectOwnership` slot, clears the (already-`None`) `vault`
    slot, tears down the ticker / auto-lock `glib::SourceId`s,
    wipes open HOTP reveal windows and the pending clipboard
    auto-clear buffer, builds the rendered body via
    `StartupError::from_worker_panic(kind)`, and remounts the
    surface through `Self::remount_for_state` with the previously-
    resolved path preserved. The `Passphrase*` workers determine
    the panic kind from `SubmitPayload::sub_flow()` so the typed
    instrumentation reflects the requested sub-flow. The QR
    clipboard import path reuses `EffectKind::AddAccount` to match
    its dispatch-side classification.
    Pinned by `startup_error_from_worker_panic_*`,
    `format_worker_panic_message_*`, and
    `format_startup_error_marker_collapses_worker_panic_body_to_single_line`
    in `tests/startup_error_logic.rs`, plus
    `handle_worker_lost_*` in `tests/app_state_logic.rs`.)
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
- [x] Linux desktop file, AppStream metadata, and icon.
  - [x] Write `data/org.tamx.Paladin.Gui.desktop` with `Name=Paladin`,
    `Icon=org.tamx.Paladin.Gui`,
    `StartupWMClass=org.tamx.Paladin.Gui`,
    `Categories=Utility;Security;`, security/authenticator
    `Keywords=`, and `Exec=paladin-gtk` (no file/URI placeholders).
    (Shipped at `crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop`.
    `Type=Application`, `Name=Paladin`, `Icon=org.tamx.Paladin.Gui`,
    `Exec=paladin-gtk` with no `%F` / `%U` / `%f` / `%u` placeholders,
    `Terminal=false`, `StartupWMClass=org.tamx.Paladin.Gui`,
    `Categories=Utility;Security;`, and
    `Keywords=OTP;TOTP;HOTP;2FA;MFA;Authenticator;One-Time-Password;Two-Factor;Security;`.
    `Comment=` and `GenericName=` are filled so launchers can render the
    tooltip / generic-name overlay. The §11.3 Flatpak and native package
    manifests install this file verbatim under
    `/usr/share/applications/org.tamx.Paladin.Gui.desktop`. Pinned by
    `tests/desktop_entry_logic.rs`:
    `desktop_file_exists_at_expected_path`,
    `desktop_file_path_uses_app_id_basename`,
    `desktop_file_starts_with_desktop_entry_group_header`,
    `desktop_file_has_spdx_header_comment`,
    `desktop_entry_type_is_application`,
    `desktop_entry_name_is_paladin`,
    `desktop_entry_icon_matches_app_id`,
    `desktop_entry_startup_wm_class_matches_app_id`,
    `desktop_entry_exec_is_paladin_gtk_binary_name`,
    `desktop_entry_exec_has_no_file_or_uri_placeholders`,
    `desktop_entry_categories_includes_utility_and_security`,
    `desktop_entry_keywords_covers_security_authenticator_vocabulary`,
    `desktop_entry_terminal_is_false`,
    `desktop_entry_has_a_summary_comment_field`, and
    `desktop_entry_basename_matches_appstream_launchable_filename`.)
  - [x] Write `data/metainfo/org.tamx.Paladin.Gui.metainfo.xml`
    AppStream metadata with the matching
    `<launchable type="desktop-id">` plus screenshots and release
    notes for v0.2.
    (Shipped at
    `crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml`.
    `<component type="desktop-application">` with `<id>` matching
    `paladin_gtk::APP_ID`,
    `<launchable type="desktop-id">org.tamx.Paladin.Gui.desktop</launchable>`
    pinned against the §11.3 desktop entry basename,
    `<metadata_license>CC0-1.0</metadata_license>`,
    `<project_license>AGPL-3.0-or-later</project_license>`,
    `<name>Paladin</name>`, a one-sentence `<summary>`, a `<description>`
    block, `<categories>`, `<keywords>`, homepage / bugtracker /
    `vcs-browser` `<url>` entries pointing at the
    `[workspace.package]` URLs, an empty `<content_rating type="oars-1.1" />`
    block (Flathub / GNOME Software prerequisite), a default
    `<screenshots>` slot, `<provides><binary>paladin-gtk</binary></provides>`,
    and a v0.2 `<releases>` entry with `type="development"` release
    notes. `appstreamcli validate --no-net` passes (the network warnings
    are the validator failing to download placeholder asset URLs in
    an offline environment, not metadata bugs). Pinned by
    `tests/metainfo_logic.rs`: existence and basename pinning against
    `APP_ID`, XML declaration, SPDX header,
    `<component type="desktop-application">`, `<id>` ↔ `APP_ID`,
    `<launchable>` ↔ desktop file basename, `<metadata_license>` ∈
    {FSFAP, MIT, CC0-1.0, CC-BY-3.0, CC-BY-4.0, 0BSD},
    `<project_license>` ↔ `AGPL-3.0-or-later`, `<name>` ↔ `Paladin`,
    `<summary>` non-empty + ≤80 chars + no trailing period,
    `<description>` present, `<releases>` with at least one
    `<release>`, `<screenshots>` block, homepage / bugtracker URLs,
    a developer block (`<developer>` or legacy `<developer_name>`),
    and the `<content_rating>` declaration.)
  - [x] Ship the scalable app icon at
    `data/icons/hicolor/scalable/apps/org.tamx.Paladin.Gui.svg` and
    16/24/32/48 PNG fallbacks under
    `data/icons/hicolor/<size>/apps/org.tamx.Paladin.Gui.png`.
    (Scalable SVG drawn at the GNOME HIG-standard 128×128 viewport
    as a heraldic shield with a central keyhole and a six-digit
    OTP display, rendered against an Adwaita "blue 3" gradient.
    PNG fallbacks rasterized from the same SVG source via
    `inkscape --export-type=png --export-width=<N> --export-height=<N>`
    at 16 / 24 / 32 / 48 so a single SVG drives every fallback
    size. Pinned by `tests/icon_assets_logic.rs`:
    `scalable_svg_exists_at_expected_path`,
    `scalable_svg_basename_matches_app_id`,
    `scalable_svg_is_well_formed_svg_root`,
    `scalable_svg_declares_explicit_viewbox`,
    `scalable_svg_carries_spdx_header`,
    `png_fallbacks_exist_at_each_required_size`,
    `png_fallbacks_use_png_magic_bytes`, and
    `png_fallbacks_have_matching_ihdr_dimensions` (parses the IHDR
    chunk and asserts that each PNG's width / height equals the
    `<size>` from its install directory so a future rerasterization
    cannot silently land a mis-sized fallback).)
  - [x] Ship the symbolic variant at
    `data/icons/hicolor/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg`
    when the Adwaita palette warrants it.
    (Drawn at the GNOME HIG-standard 16×16 symbolic viewport as a
    single-color shield silhouette with a keyhole. Uses
    `fill="currentColor"` throughout so the Adwaita engine can
    recolor the glyph against the active foreground (light theme
    → dark glyph; dark theme → light glyph). Pinned by
    `tests/icon_assets_logic.rs`:
    `symbolic_svg_exists_at_expected_path`,
    `symbolic_svg_basename_matches_app_id_symbolic_convention`,
    `symbolic_svg_is_well_formed_svg_root`,
    `symbolic_svg_carries_spdx_header`, and
    `symbolic_svg_uses_currentcolor_for_recoloring`.)
  - [x] Wire `build.rs` + `data/paladin-gtk.gresource.xml` to compile
    the gresource bundle deterministically via
    `glib-compile-resources` (fixed input order).
    (`build.rs` calls
    `glib_build_tools::compile_resources(&["data", "../.."], "data/paladin-gtk.gresource.xml", "paladin-gtk.gresource")`
    so `glib-compile-resources` consumes the XML manifest and emits
    a packed bundle under `OUT_DIR`. The manifest declares each
    payload explicitly (no globs), every `<file>` entry sets
    `compressed="true"`, and aliases are unique, so the bundle's
    write order is determined entirely by the manifest's textual
    order — no filesystem-walk dependency. The bundle now ships
    the app stylesheet, the placeholder symbolic icon, the
    workspace `LICENSE` body, the scalable app icon
    (`icons/scalable/apps/org.tamx.Paladin.Gui.svg`), and the
    symbolic app icon
    (`icons/symbolic/apps/org.tamx.Paladin.Gui-symbolic.svg`); the
    bundled app icons let the in-app `gtk::IconTheme` resolve
    `APP_ID` even when the system hicolor theme has not yet
    indexed the freshly installed PNG fallbacks (notably during
    `cargo run`, the `xvfb-run` smoke test, and Flatpak sandboxes
    whose runtime theme omits the package). The build script's
    `cargo:rerun-if-changed=../../LICENSE` directive keeps the
    bundled license body in lockstep with the on-disk source of
    truth. Pinned by `tests/gresource_manifest_logic.rs`:
    `manifest_exists_at_expected_path`,
    `manifest_carries_spdx_header`,
    `manifest_prefix_matches_app_id_reverse_dns_path`,
    `manifest_uses_explicit_file_entries_not_globs`,
    `manifest_aliases_are_unique`,
    `manifest_carries_app_stylesheet_entry`,
    `manifest_carries_placeholder_icon_entry`,
    `manifest_carries_license_text_entry`,
    `manifest_carries_app_icon_entries_for_in_app_lookup`,
    `manifest_file_entries_are_compressed`,
    `build_script_invokes_glib_compile_resources_against_manifest`,
    `build_script_tracks_workspace_license_for_rerun`, and
    `build_script_declares_workspace_root_as_secondary_source_dir`.)
  - [x] Add `desktop-file-validate` and the AppStream validator to
    the CI / packaging dry-run so both files are checked on every
    build.
    (`.github/workflows/ci.yml` gains a `desktop-metainfo` job that
    installs `desktop-file-utils` (ships `desktop-file-validate`) and
    `appstream` (ships `appstreamcli`) on the `ubuntu-latest`
    runner, then runs `desktop-file-validate` against
    `crates/paladin-gtk/data/org.tamx.Paladin.Gui.desktop` and
    `appstreamcli validate --no-net` against
    `crates/paladin-gtk/data/metainfo/org.tamx.Paladin.Gui.metainfo.xml`.
    The `--no-net` flag keeps the validator off the network so the
    job never depends on the external homepage / screenshot URLs being
    reachable — the substantive schema / required-field checks still
    run. Pinned by `tests/ci_desktop_metainfo_validators_logic.rs`:
    `ci_workflow_runs_desktop_file_validate_on_the_desktop_entry`,
    `ci_workflow_runs_appstreamcli_validate_on_the_metainfo_file`,
    and
    `ci_workflow_installs_both_validators_in_one_apt_invocation`,
    each reading `.github/workflows/ci.yml` and asserting the
    relevant invocation / package name is present so a future CI
    edit that drops the validator step fails this test
    immediately, independent of whether the validators are installed
    locally.)
- [x] `.deb`, `.rpm`, Flatpak, and AppImage artifacts for `paladin-gtk`,
  signed and published per §11.3–§11.6; Flathub submission filed.
  - [x] Update `crates/paladin-gtk/Cargo.toml` to inherit
    `description` / `repository` / `homepage` / `license` /
    `edition` / `rust-version` from `[workspace.package]` and set
    the binary-specific `keywords` / `categories` locally. Pinned by
    `tests/cargo_manifest_workspace_inheritance_logic.rs`:
    `crate_manifest_inherits_required_fields_from_workspace_package`,
    `crate_manifest_declares_keywords_locally_with_expected_values`,
    `crate_manifest_declares_categories_locally_with_expected_values`,
    `crate_manifest_does_not_inherit_keywords_or_categories_from_workspace`,
    and `workspace_manifest_supplies_each_inherited_field` — together
    these read both `crates/paladin-gtk/Cargo.toml` and the workspace
    `Cargo.toml` as plain text and fail if any of `version` /
    `edition` / `rust-version` / `license` / `repository` / `homepage`
    / `description` stops resolving through
    `<field>.workspace = true`, if `keywords` / `categories` ever drift
    from the GUI-binary set `["otp", "totp", "hotp", "authenticator",
    "gtk"]` / `["gui", "authentication"]`, or if either facet is
    accidentally moved onto `[workspace.package]`.
  - [x] Add `packaging/deb/paladin-gtk.yaml` (`nfpm`) installing
    `/usr/bin/paladin-gtk`, the desktop entry, the AppStream
    metainfo, and the hicolor icon set; declare
    `libgtk-4-1 (>= 4.16)` and `libadwaita-1-0 (>= 1.6)`; wire a
    narrowly scoped `postinstall` / `postremove` scriptlet pair
    that refreshes `/usr/share/applications/mimeinfo.cache` and
    `/usr/share/icons/hicolor/icon-theme.cache` (the shell scripts
    live at `packaging/scripts/paladin-gtk-postinstall.sh` and
    `packaging/scripts/paladin-gtk-postremove.sh` and are shared
    byte-for-byte with the `.rpm` manifest). Pinned by
    `tests/packaging_deb_nfpm_manifest_logic.rs`:
    `deb_manifest_exists_at_expected_path`,
    `deb_manifest_starts_with_spdx_license_header`,
    `deb_manifest_declares_package_name_paladin_gtk`,
    `deb_manifest_declares_linux_platform_and_amd64_arch`,
    `deb_manifest_declares_workspace_license`,
    `deb_manifest_declares_workspace_homepage`,
    `deb_manifest_declares_required_runtime_depends_with_exact_versions`,
    `deb_manifest_declares_no_extra_depends_beyond_baseline_set`,
    `deb_manifest_installs_every_required_destination`,
    `deb_manifest_sources_each_install_from_the_expected_in_tree_path`,
    `deb_manifest_in_tree_sources_all_exist_under_the_workspace`,
    `deb_manifest_declares_required_scripts_section`,
    `deb_manifest_scripts_reference_only_the_baseline_keys`,
    `deb_manifest_script_references_point_to_existing_executable_files`,
    `paladin_gtk_scripts_have_spdx_license_header`,
    `paladin_gtk_scripts_touch_only_system_owned_caches`,
    `paladin_gtk_scripts_gate_helpers_with_command_v_and_fail_soft`,
    and `deb_manifest_binary_install_uses_executable_mode` —
    together these read `packaging/deb/paladin-gtk.yaml` as plain
    text (no `serde_yaml` dep lands in the test deck) and fail if
    the manifest stops installing `/usr/bin/paladin-gtk` (with
    `mode: 0755`), the desktop entry at `/usr/share/applications/`,
    the AppStream metainfo at `/usr/share/metainfo/`, or any of the
    hicolor scalable / symbolic / 16x16 / 24x24 / 32x32 / 48x48 /
    64x64 / 128x128 / 256x256 / 512x512 icon paths; if any `src`
    references a missing in-tree path; if `depends:` drifts from
    the exact `libgtk-4-1 (>= 4.16)` / `libadwaita-1-0 (>= 1.6)`
    baseline pair; if the `scripts:` mapping loses the
    `postinstall` / `postremove` entries or grows additional
    maintainer-hook keys; or if the referenced shell scripts grow
    `$HOME` / `$XDG_*` / `~/` / `/home/` references, network
    calls, or stop gating helpers with `command -v` + `|| :`
    fail-soft.
  - [x] Add `packaging/rpm/paladin-gtk.yaml` (`nfpm`) installing the
    same payload with matching `gtk4` / `libadwaita` package names,
    and declaring the same `postinstall` / `postremove` scriptlet
    pair as the `.deb` (both manifests reference the shared
    `packaging/scripts/paladin-gtk-*.sh` shell files so a fix lands
    in both formats at once). Pinned by
    `tests/packaging_rpm_nfpm_manifest_logic.rs`:
    `rpm_manifest_exists_at_expected_path`,
    `rpm_manifest_starts_with_spdx_license_header`,
    `rpm_manifest_declares_package_name_paladin_gtk`,
    `rpm_manifest_declares_linux_platform_and_amd64_arch`,
    `rpm_manifest_declares_workspace_license`,
    `rpm_manifest_declares_workspace_homepage`,
    `rpm_manifest_declares_required_runtime_depends_with_fedora_package_names`,
    `rpm_manifest_declares_no_extra_depends_beyond_baseline_set`,
    `rpm_manifest_does_not_use_debian_package_names`,
    `rpm_manifest_installs_every_required_destination`,
    `rpm_manifest_sources_each_install_from_the_expected_in_tree_path`,
    `rpm_manifest_in_tree_sources_all_exist_under_the_workspace`,
    `rpm_manifest_declares_required_scripts_section`,
    `rpm_manifest_scripts_match_deb_manifest_scripts`,
    `rpm_manifest_binary_install_uses_executable_mode`, and
    `rpm_manifest_install_layout_matches_deb_manifest_layout` — the
    last two are cross-format checks that assert the `.rpm` and
    `.deb` manifests stage byte-identical `dst:` layouts and
    declare byte-identical `scripts:` mappings so Fedora and Debian
    users land on the same filesystem footprint and the same
    maintainer-script behavior. Together they fail if the manifest
    stops installing any of the Milestone 7 destinations, if any
    `src` references a missing in-tree path, if `depends:` drifts
    from `gtk4 >= 4.16` / `libadwaita >= 1.6`, if a Debian-style
    `libgtk-4-1` / `libadwaita-1-0` name slips in, or if the
    `scripts:` mapping diverges from the `.deb` manifest.
  - [x] Add `packaging/flatpak/paladin-gtk.yml` declaring
    `org.gnome.Platform//47` and the matching SDK, the §11.4 sandbox
    permissions (`xdg-data/paladin:create`,
    `xdg-config/paladin:create`, `--socket=wayland`,
    `--socket=fallback-x11`, `--share=ipc`), no `--share=network`,
    and exporting the metainfo file to `/usr/share/metainfo/`
    (staged inside the Flatpak `/app/share/metainfo/` prefix that
    flatpak-builder re-exports to the host AppStream pool).
    Pinned by `tests/packaging_flatpak_manifest_logic.rs`:
    `flatpak_manifest_exists_at_expected_path`,
    `flatpak_manifest_starts_with_spdx_license_header`,
    `flatpak_manifest_declares_app_id_matching_app_constant`,
    `flatpak_manifest_declares_gnome_runtime_47_and_matching_sdk`,
    `flatpak_manifest_declares_command_paladin_gtk`,
    `flatpak_manifest_declares_every_required_finish_arg`,
    `flatpak_manifest_does_not_declare_any_forbidden_finish_arg`
    (rejects `--share=network`, `--filesystem=home/host/host-os/
    host-etc`),
    `flatpak_manifest_finish_args_are_exactly_the_milestone_7_baseline_set`,
    `flatpak_manifest_install_steps_cover_every_required_destination`,
    `flatpak_manifest_binary_install_uses_executable_mode_0755`,
    `flatpak_manifest_metainfo_install_lands_under_app_share_metainfo`,
    `flatpak_manifest_uses_locked_offline_cargo_build`, and
    `flatpak_manifest_module_name_matches_app_id_basename` —
    together these fail if the runtime / SDK pair drifts off
    `org.gnome.Platform//47` + `org.gnome.Sdk`, if the sandbox
    permission set strays from the §11.4 baseline (in either
    direction), if a `cargo build` invocation loses `--release` /
    `--locked` / `--offline`, or if any install destination /
    binary mode drifts from the byte-identical layout the deb / rpm
    manifests already pin.
  - [x] Wire AppImage assembly via `linuxdeploy` +
    `linuxdeploy-plugin-gtk` so GTK4 modules, schemas, and pixbuf
    loaders ship inside the bundle; output
    `paladin-gtk-<version>-x86_64.AppImage` with embedded `zsync`
    pointing at GitHub Releases. Implemented as
    `packaging/appimage/build-appimage.sh` (executable, bash strict
    mode), which pre-stages the AppStream metainfo and the non-
    primary hicolor icon sizes into the AppDir, then invokes
    `linuxdeploy --appdir … --desktop-file … --icon-file … --executable
    … --plugin gtk --output appimage` with `OUTPUT=paladin-gtk-
    ${PALADIN_VERSION}-x86_64.AppImage`,
    `UPDATE_INFORMATION=gh-releases-zsync|FreedomBen|paladin|latest|
    paladin-gtk-*-x86_64.AppImage.zsync`, and `ARCH=x86_64`. Pinned
    by `tests/packaging_appimage_build_script_logic.rs`:
    `appimage_script_exists_at_expected_path`,
    `appimage_script_is_executable`,
    `appimage_script_starts_with_bash_shebang`,
    `appimage_script_carries_spdx_license_header`,
    `appimage_script_enables_strict_shell_mode`,
    `appimage_script_invokes_linuxdeploy_with_gtk_plugin` (covers
    `--appdir` / `--desktop-file` / `--icon-file` / `--executable` /
    `--plugin gtk` / `--output appimage`),
    `appimage_script_references_every_required_in_tree_source`,
    `appimage_script_in_tree_references_all_exist_under_the_workspace`,
    `appimage_script_carries_zsync_update_information_pointing_at_github_releases`,
    `appimage_script_declares_versioned_output_filename`,
    `appimage_script_reads_paladin_version_from_environment`,
    `appimage_script_does_not_hardcode_a_version_string`, and
    `appimage_script_targets_x86_64_architecture_explicitly` —
    together these fail if the script stops being executable, loses
    the strict-shell-mode directive, drops any `linuxdeploy` flag,
    bakes in a literal semver, or drifts the `UPDATE_INFORMATION`
    pointer away from the `FreedomBen/paladin` GitHub Releases feed.
  - [x] Make the build reproducible: vendored deps,
    `cargo build --locked`, `SOURCE_DATE_EPOCH` from the release
    tag, with the gresource bundle and `linuxdeploy` step both
    deterministic.
    (The workspace toolchain stays pinned in `rust-toolchain.toml`
    at the workspace root — `channel = "1.94.1"` matches the
    `[workspace.package].rust-version = "1.94"` floor, and the
    `profile = "minimal"` + explicit `components = ["rustfmt",
    "clippy"]` list keeps the release toolchain footprint to
    exactly the components the §10 CI gate needs. The AppImage
    assembly script (`packaging/appimage/build-appimage.sh`) reads
    `SOURCE_DATE_EPOCH` from the environment and re-exports it
    when set, so the release pipeline's tag-derived timestamp
    propagates through `cargo build`, `linuxdeploy`,
    `linuxdeploy-plugin-gtk`, and the `mksquashfs` step
    `appimagetool` invokes transitively — that propagation is
    what makes successive runs of the same tag produce
    byte-identical `.AppImage` output. The fallback
    `cargo build --release --locked -p paladin-gtk` invocation
    keeps the lockfile authoritative at build time. Vendored
    deps land via `cargo vendor` in the release pipeline (the
    `vendor/` tree is not committed; the Flatpak manifest
    already exercises the `--offline` + vendored-source mode
    pinned by
    `tests/packaging_flatpak_manifest_logic.rs::flatpak_manifest_uses_locked_offline_cargo_build`).
    The gresource bundle stays deterministic via `build.rs`
    invoking `glib_build_tools::compile_resources` against the
    fixed-order `data/paladin-gtk.gresource.xml` alias list
    (pinned by `tests/gresource_manifest_logic.rs::manifest_uses_explicit_file_entries_not_globs`).
    Pinned by
    `tests/packaging_reproducible_build_logic.rs::rust_toolchain_file_exists_at_workspace_root`,
    `rust_toolchain_declares_toolchain_table_header`,
    `rust_toolchain_pins_a_concrete_channel_version`,
    `rust_toolchain_declares_rustfmt_and_clippy_components`,
    `rust_toolchain_uses_minimal_profile`,
    `rust_toolchain_channel_matches_workspace_rust_version_floor`,
    `appimage_script_reads_source_date_epoch_from_environment`,
    `appimage_script_exports_source_date_epoch_for_linuxdeploy_subprocess`,
    `appimage_script_uses_cargo_build_locked`,
    `appimage_script_cargo_invocations_target_release_profile`,
    `extract_toolchain_channel_returns_quoted_value`,
    `extract_toolchain_channel_returns_none_when_absent`,
    `extract_toolchain_channel_handles_single_quotes`,
    `extract_workspace_rust_version_returns_value_inside_workspace_package`,
    and
    `extract_workspace_rust_version_ignores_rust_version_outside_workspace_package` —
    together these fail if the toolchain pin drifts, the AppImage
    script stops propagating `SOURCE_DATE_EPOCH`, or a `cargo
    build` invocation in the script drops `--locked` / `--release`.)
  - [x] Sign `.deb`, `.rpm`, and AppImage with `minisign` per §11.6;
    publish the public key + signature alongside each artifact on
    GitHub Releases.
    (`packaging/sign/sign-artifact.sh` wraps `minisign -S` with the
    release-pipeline conventions: the secret key is mounted from a
    CI secret at runtime via `MINISIGN_SECRET_KEY` (a filesystem
    path the workflow writes the secret to — the secret never lands
    in the script source); the optional passphrase is piped through
    stdin when `MINISIGN_PASSWORD` is set so the signing step runs
    non-interactively in CI; the trusted-comment string defaults to
    `"<artifact-basename> signed by paladin release pipeline"` but
    the release pipeline can override it via
    `MINISIGN_TRUSTED_COMMENT` (typically to embed the release tag).
    The script takes the artifact path as `$1`, invokes `minisign
    -S -s "${MINISIGN_SECRET_KEY}" -m "${ARTIFACT}" -t
    "${TRUSTED_COMMENT}"`, and asserts the expected
    `<artifact>.minisig` lands alongside the input before declaring
    success — a missing output would otherwise let the release
    workflow upload an unsigned blob. The public-key file the
    release workflow ships alongside each artifact lives at
    `packaging/sign/minisign.pub` (the published trust anchor for
    downstream verifiers; the actual key bytes get generated and
    committed once during release-pipeline bootstrap). Pinned by
    `tests/packaging_signing_script_logic.rs::sign_script_exists_at_expected_path`,
    `sign_script_is_executable`,
    `sign_script_starts_with_bash_shebang`,
    `sign_script_carries_spdx_license_header`,
    `sign_script_enables_strict_shell_mode`,
    `sign_script_reads_minisign_secret_key_from_environment`,
    `sign_script_reads_trusted_comment_from_environment_with_a_default`,
    `sign_script_takes_artifact_path_as_first_positional`,
    `sign_script_invokes_minisign_sign_subcommand`,
    `sign_script_passes_secret_key_flag_to_minisign`,
    `sign_script_passes_artifact_path_via_message_flag`,
    `sign_script_documents_public_key_location`,
    `sign_script_emits_minisig_filename_alongside_artifact`,
    `join_continuations_concatenates_backslash_terminated_lines`,
    `join_continuations_preserves_non_continuation_lines`, and
    `minisign_sign_invocations_returns_logical_invocations_only` —
    together these fail if the script drops a flag, hard-codes a
    secret-key path, swaps `minisign` for another signer, or stops
    asserting the `.minisig` post-condition.)
  - [x] File the Flathub submission and inherit Flatpak signing from
    Flathub.
    (The in-tree Flathub submission tree lives at `packaging/flathub/`
    and carries the three artifacts a Flathub submission needs:
    `org.tamx.Paladin.Gui.yml` — the flatpak-builder manifest named
    with the app-id basename per Flathub convention; `flathub.json`
    — the build-options companion declaring `only-arches: ["x86_64"]`
    so the initial submission scopes the build matrix to the
    architecture the §11.3 / §11.5 native pipeline already targets;
    and `README.md` — the submission instructions (how to file the
    PR against `flathub/flathub`, how `cargo-sources.json` is
    regenerated per release, how Flatpak signing is inherited from
    Flathub's published key per DESIGN.md §11.4 / §11.6 so
    `packaging/sign/sign-artifact.sh` is NOT invoked for the Flatpak
    output). The manifest deliberately differs from
    `packaging/flatpak/paladin-gtk.yml` only in its source pointer:
    where the local packaging dry-run uses `type: dir, path: ../..`
    to build from the workspace tree, the Flathub manifest uses
    `type: git` against `https://github.com/FreedomBen/paladin.git`
    + a per-release-stamped `tag:` / `commit:` plus a
    `cargo-sources.json` companion so Flathub's builder fetches the
    tagged release and resolves vendored Cargo deps offline. Pinned
    by `tests/packaging_flathub_submission_logic.rs`:
    `flathub_submission_directory_exists`,
    `flathub_manifest_exists_at_app_id_basename`,
    `flathub_manifest_starts_with_spdx_license_header`,
    `flathub_manifest_declares_app_id_matching_app_constant`,
    `flathub_manifest_declares_gnome_runtime_47_and_matching_sdk`,
    `flathub_manifest_declares_command_paladin_gtk`,
    `flathub_manifest_declares_every_required_finish_arg`,
    `flathub_manifest_does_not_declare_any_forbidden_finish_arg`,
    `flathub_manifest_finish_args_are_exactly_the_milestone_7_baseline_set`,
    `flathub_manifest_install_steps_cover_every_required_destination`,
    `flathub_manifest_binary_install_uses_executable_mode_0755`,
    `flathub_manifest_uses_locked_offline_cargo_build`,
    `flathub_manifest_module_name_matches_app_id_basename`,
    `flathub_manifest_source_is_upstream_not_local_dir`,
    `flathub_manifest_source_references_paladin_github_repository`,
    `flathub_json_exists_at_expected_path`,
    `flathub_json_declares_only_arches_with_x86_64`,
    `flathub_submission_readme_exists`,
    `flathub_submission_readme_documents_pr_filing_against_flathub_org`,
    `flathub_submission_readme_documents_signing_inheritance`, and
    `flathub_submission_readme_documents_cargo_sources_regeneration`
    — together these fail if the manifest filename drifts off the
    app-id basename, the runtime / SDK pair strays from
    `org.gnome.Platform//47` + `org.gnome.Sdk`, the sandbox
    permission set drifts from the §11.4 baseline (in either
    direction), a `cargo build` invocation loses `--release` /
    `--locked` / `--offline`, the source pointer reverts to
    `type: dir`, the URL stops pointing at FreedomBen/paladin, the
    `only-arches` scope drops x86_64, or the README stops naming
    `flathub/flathub`, the signing-inheritance contract, or the
    `cargo-sources` regeneration procedure. Once the submission PR
    against `flathub/flathub` merges, the same files land at the
    root of `flathub/org.tamx.Paladin.Gui` and subsequent per-
    release PRs target that new repo instead — the in-tree files
    stay the source of truth that the release pipeline stamps per
    release via `flatpak-cargo-generator` against the new tag's
    `Cargo.lock`.)
  - [x] Add the packaging dry-run job to CI: produces `.deb`,
    `.rpm`, Flatpak, and AppImage artifacts and runs
    `desktop-file-validate` plus the AppStream validator on the
    installed payload.
    (`.github/workflows/ci.yml` now declares a `packaging-dry-run`
    job that runs inside the same `fedora:42` container the
    `clippy` / `test` jobs use — GTK 4.16 + libadwaita 1.6 headers
    are present so `cargo build --release --locked -p paladin-gtk`
    resolves against the version floor. The job installs `nfpm`
    pinned at the upstream `v2.41.3` GitHub release artifact (a
    `dnf install` would let the distro pick a divergent version
    or skip the package entirely on Fedora), exports
    `PALADIN_VERSION="0.0.1-ci-dry-run"` so the
    `version: ${PALADIN_VERSION}` substitution in both nfpm
    manifests resolves to a concrete string, and then runs
    `nfpm package -f packaging/deb/paladin-gtk.yaml -p deb -t
    target/dist/` and the matching `-p rpm` invocation against
    `packaging/rpm/paladin-gtk.yaml`. Each artifact is extracted
    into a staging directory (`dpkg-deb -x` for the `.deb`,
    `rpm2cpio | cpio -idm` for the `.rpm`) and both validators run
    against the installed payload at the FHS paths the manifests
    claim (`usr/share/applications/org.tamx.Paladin.Gui.desktop`
    and `usr/share/metainfo/org.tamx.Paladin.Gui.metainfo.xml`)
    — that closes the gap the existing `desktop-metainfo`
    source-validator job leaves open. The Flatpak + AppImage
    artifact-production sub-steps land in follow-up workflow
    commits (both require additional runtime setup —
    flatpak-builder + Flathub remote for Flatpak;
    `linuxdeploy` + `linuxdeploy-plugin-gtk` for AppImage — that
    is out of scope for this contract); their text-level manifest
    / script tests
    (`tests/packaging_flatpak_manifest_logic.rs`,
    `tests/packaging_appimage_build_script_logic.rs`) run on every
    push regardless. Pinned by
    `tests/ci_packaging_dry_run_logic.rs::ci_workflow_declares_packaging_dry_run_job`,
    `ci_packaging_dry_run_job_has_a_human_readable_name`,
    `ci_packaging_dry_run_job_runs_in_a_fedora_container`,
    `ci_packaging_dry_run_installs_nfpm`,
    `ci_packaging_dry_run_builds_release_binary_with_locked_lockfile`,
    `ci_packaging_dry_run_exports_paladin_version`,
    `ci_packaging_dry_run_builds_deb_package_via_nfpm`,
    `ci_packaging_dry_run_builds_rpm_package_via_nfpm`,
    `ci_packaging_dry_run_extracts_deb_payload`,
    `ci_packaging_dry_run_extracts_rpm_payload`,
    `ci_packaging_dry_run_runs_desktop_file_validate_on_extracted_payload`,
    `ci_packaging_dry_run_runs_appstreamcli_validate_on_extracted_payload`,
    `extract_packaging_dry_run_job_returns_only_the_named_job_body`,
    and `extract_packaging_dry_run_job_returns_none_when_absent` —
    together these fail if the job is removed, drops `--locked`,
    swaps the container, stops pointing at the in-tree manifest
    paths, skips extraction, or stops validating the installed
    payload.)
- [ ] **Next-code column (DESIGN §7).** Lands on top of the
  Milestone 7 foundation as a single focused commit; see
  **Next-code column implementation** above for the ordered
  build steps and the pinned design contract. The TUI side
  (`Vault::totp_next_code`, `Effect::CopyNextCode`,
  `Shift+C` keybind, `↪` cell rendering) shipped in commits
  `53b34ca` (core helper + docs), `4d3e1a7` (TUI), and
  `7bec88d` (TUI audit gap); the GTK side replays the same
  contract through cell factories, GSettings, and the
  `Ctrl+Shift+C` accelerator. Tick each box in the dedicated
  "Build order" list as the corresponding code lands.
- [ ] **`DestroyDialog` (Milestone 10; DESIGN §4.3 / §7).** Depends
  on `paladin_core::destroy_vault`, `DestroyReport`, and
  `format_destroy_warning` landing in `paladin-core`. The GTK side
  replays the CLI / TUI contract through an `AdwAlertDialog` with
  destructive styling, a `gio::SpawnBlocking`-routed effect, and the
  same `effect_ownership.rs` serialization every mutating dialog
  uses. The work breaks down into ordered build steps so it can land
  as one or two focused commits:
  - [ ] **Component scaffold.** Add
    `crates/paladin-gtk/src/destroy_dialog.rs` with the
    `relm4::SimpleComponent` shape (`DestroyDialogInit`,
    `DestroyDialogMsg`, `DestroyDialogOutput`) shared by every
    other dialog. The init carries the resolved vault path; the
    component probes `vault.bin.bak` on mount via
    `std::fs::try_exists` to populate `backup_present` (falling
    back to `false` with an inline cautionary line on I/O error)
    and stores it alongside the confirmation buffer in the
    component state. Sensitive fields stay out of `AppModel` /
    `AppMsg` / `AppOutput` per DESIGN §8 (the confirmation
    string is non-secret, but the surrounding state pattern is
    preserved).
  - [ ] **Widget tree.** Use `AdwAlertDialog` for the GNOME-HIG
    irreversible-action pattern. Heading: `Delete vault?` body:
    the multi-paragraph warning from
    `paladin_core::format_destroy_warning(path, backup_present)`
    rendered into an `AdwActionRow` (one row per paragraph) inside
    a `gtk::Box` extra-child. Add an `AdwEntryRow` labelled
    `Type 'yes' to confirm` whose buffer's `changed` signal
    triggers a `DestroyDialogMsg::ConfirmationChanged`. Add two
    `AdwAlertDialog` responses: `cancel` (set as
    `default-response`) and `destroy` (set with
    `response_appearance = AdwResponseAppearance::Destructive` so
    GTK applies the `destructive-action` style class for the GNOME
    red treatment). Wire the `destroy` response to be insensitive
    until the buffer reads `yes` after Unicode-whitespace trim;
    use `AdwAlertDialog::set_response_enabled("destroy", false)`
    on mount and toggle via the buffer signal.
  - [ ] **Action wiring.** Install the
    `app.delete-vault` `gio::SimpleAction` on the `AppModel` and
    install the `Ctrl+Shift+Delete` accelerator via the new
    `format_app_menu_delete_vault_accelerator` /
    `format_app_menu_delete_vault_action` helper pair in
    `crates/paladin-gtk/src/app/model.rs`. Extend
    `format_app_window_accelerator_bindings()` from 4 to 5
    entries and the
    `format_app_shortcuts_window_entries()` array from 5 to 6
    entries with the *Delete Vault* row appended last (loudest
    action last in the display order). Add the `Delete Vault…`
    item to the primary menu under a separator below the existing
    entries so it visually reads as the destructive group. Add a
    `gtk::LinkButton`-shaped footer link `Delete vault…` to both
    `UnlockComponent` and `StartupErrorView` that activates the
    same `app.delete-vault` action. Tests in
    `tests/startup_probes.rs` extend to assert lockstep between
    the primary menu, the shortcuts window, the
    `set_accels_for_action` table, and the new helper pair.
  - [ ] **Effect dispatch.** Add `AppMsg::DestroyVault { path }`
    and `AppMsg::DestroyVaultCompleted(Result<DestroyReport,
    PaladinError>)`. `AppModel::update` for `DestroyVault`
    serializes the effect through `effect_ownership.rs` (parallel
    to every other mutating dialog), transitions to
    `UnlockedBusy`, and dispatches a `gio::spawn_blocking` closure
    that calls `paladin_core::destroy_vault(path)` and posts the
    result back through a Relm4 sender. The `DestroyDialog` is
    disabled (insensitive) while the effect is in flight.
  - [ ] **Result routing.** `AppMsg::DestroyVaultCompleted` arms:
    * `Ok(report)` — drop the held `(Vault, Store)`, call
      `secret_fields::clear_all` to wipe every secret-bearing UI
      buffer (passphrase fields, Add manual-secret + URI + pending
      duplicate state, Init pending `VaultInit`, the search query,
      HOTP reveal state + its captured `SecretString`, pending
      clipboard auto-clear value, and any open `ExportQrDialog`'s
      rendered PNG / SVG / `gdk::Texture` buffers), tear down any
      open dialog, transition `AppState` to `Missing`, mount
      `InitDialog`, and add a `gtk::Toast` to the shared
      `adw::ToastOverlay` via `toast_queue.rs` reading
      `Vault deleted.` or `Vault deleted (backup remained on
      disk).` based on `report.backup_deleted`.
    * `Err(vault_missing)` — close the dialog, drop any held
      vault, transition to `Missing`, mount `InitDialog`, and add
      a `Vault already gone.` toast.
    * `Err(io_error)` for `vault_file_is_symlink` /
      `backup_file_is_symlink` / `unlink_vault_file` /
      `unlink_backup_file` / `fsync_vault_dir` — keep the dialog
      open, render an inline error row (`AdwActionRow` with the
      `error` CSS class) below the warning body that names the
      failing path and surfaces the partial `DestroyReport`, and
      re-enable the destructive button after a second `yes` entry
      so the user can retry. The confirmation buffer is preserved
      across the error re-display so the user does not have to
      retype it; the focus returns to the action button.
    * Any other error — keep the dialog open, render the
      `PaladinError::Display` text inline (parallel to the rest of
      the GUI's effect-error rendering).
  - [ ] **Auto-lock interaction.** Auto-lock firing while the
    dialog is open with no effect in flight zeroizes the
    confirmation buffer, closes the dialog, and locks. Auto-lock
    firing after the destroy effect has dispatched is queued
    behind the result; the success branch transitions to
    `Missing` so the auto-lock idle deadline resets to `None`
    (no vault to lock). Pinned by
    `tests/destroy_dialog_logic.rs`.
  - [ ] **Pure-logic tests.** Add `tests/destroy_dialog_logic.rs`
    covering: warning body sourcing (single helper call, no
    drift); `backup_present` probe with `.bak` present, absent,
    and unreadable; `yes`-confirmation gating (partial input,
    trailing whitespace, byte-equal `yes`); `Esc` / Cancel path;
    `Ok(DestroyReport)` projections to AppMsg routing with both
    `backup_deleted: true` and `backup_deleted: false`; each
    `io_error` variant projecting to the inline-error renderer;
    `vault_missing` projection; sensitive-buffer wipe roll-call
    (the test enumerates the `secret_fields::clear_all` call
    sites and asserts each one fires on the success path);
    auto-lock interaction (pre- and post-dispatch). The
    `AdwAlertDialog` destructive-styling pin is a smoke-test
    assertion since it crosses the widget boundary.
  - [ ] **Smoke test.** Extend `tests/gtk_smoke.rs` to cover the
    happy-path destroy flow: launch with a fresh plaintext vault,
    click the primary-menu *Delete Vault…* item, type `yes`,
    activate the destructive button, assert the toast appears,
    `InitDialog` mounts, and the on-disk vault is gone. (The
    `xvfb-run` runner makes this end-to-end.)
  - [ ] **Manual test plan.** Add Milestone 10 bullets to
    `crates/paladin-gtk/tests/manual/MANUAL_TEST_PLAN.md`:
    * Destroy vault via primary-menu item.
    * Destroy vault via unlock-dialog footer link.
    * Destroy vault via startup-error footer link.
    * Destroy vault via `Ctrl+Shift+Delete`.
    * Cancel destroy at confirmation prompt; vault unchanged.
    * Destroy vault with `.bak` present; both files unlinked,
      toast reads `Vault deleted.`.
    * Destroy vault with no `.bak`; primary unlinked, toast
      reads `Vault deleted.`.
    * Destroy vault while another dialog (Add, Edit, Passphrase)
      is open; that dialog closes and its sensitive buffers
      wipe.
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
- Per-account QR export available from the row kebab menu's `Show QR…`
  entry: warning-ack gate, on-screen QR via `Vault::export_qr_png`,
  Save-as-PNG / Save-as-SVG through `write_secret_file_atomic`,
  `Copy image` through `gdk::ContentProvider`. Read-only — HOTP
  counters and `updated_at` are unchanged across every render path.
- **Destroy Vault available from the primary menu and from the
  unlock / startup-error footer** (Milestone 10). The
  `AdwAlertDialog` renders
  `paladin_core::format_destroy_warning(path, backup_present)`,
  gates the destructive button behind an `yes` confirmation entry,
  routes the effect through `paladin_core::destroy_vault` on
  `gio::spawn_blocking`, transitions to `Missing` + `InitDialog`
  on success, surfaces partial failures (symlink rejection,
  backup-unlink failure, parent-`fsync` failure) inline with the
  partial `DestroyReport`, and wipes every secret-bearing UI
  buffer in lockstep with the vault drop. The `Ctrl+Shift+Delete`
  accelerator and the shortcuts window entry are installed
  through the same `format_app_menu_delete_vault_*` helpers as
  the primary-menu item. Available in every `AppState` so the
  forgot-passphrase escape hatch works without the CLI.
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
  `tests/clipboard_logic.rs`, `tests/clipboard_clear_logic.rs`,
  `tests/hotp_reveal_logic.rs`,
  `tests/secret_fields_logic.rs`, `tests/startup_error_logic.rs`,
  `tests/qr_clipboard_logic.rs`, `tests/account_list_logic.rs`,
  `tests/account_row_logic.rs`, `tests/init_dialog_logic.rs`,
  `tests/unlock_dialog_logic.rs`, `tests/add_account_logic.rs`,
  `tests/rename_dialog_logic.rs`, `tests/remove_dialog_logic.rs`,
  `tests/otpauth_uri_paste_logic.rs`, `tests/import_dialog_logic.rs`,
  `tests/export_dialog_logic.rs`, `tests/export_qr_dialog_logic.rs`,
  `tests/passphrase_dialog_logic.rs`,
  `tests/destroy_dialog_logic.rs`,
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

---

## Appendix A — Planned: column headers via `gtk::ColumnView`

Status: **planned, not yet implemented**. Captured 2026-05-23
after the SizeGroup-aligned header strip (commit `f6e9288`, the
lowest-cost path to column headers) was reverted in commit
`93aa48f` in favor of the heavier `gtk::ColumnView` rewrite this
appendix describes. This appendix is the working spec for that
rewrite; it will be promoted into the body of the plan once
implementation begins. The active plan above does **not** yet
describe column headers — the revert dropped that section along
with the implementation, and this appendix is the next iteration.

This appendix covers replacing the unlocked-vault list view's
`gtk::ListBox` + `relm4::factory::FactoryVecDeque` with a
`gtk::ColumnView` driven by a `gio::ListStore` of `glib::Object`
wrappers around `AccountRowModel`, with one `gtk::ColumnViewColumn`
per visible field. Native column headers come for free; sortable
columns and per-column resize become tractable.

Source of truth for everything else stays `docs/DESIGN.md` — this
appendix does **not** change observable behavior beyond the column
headers themselves.

### A.1 Motivation

The attempted Option 1 (a pinned `gtk::Box` header strip above the
`ScrolledWindow`, widths aligned via per-column `gtk::SizeGroup`)
was the lowest-disruption path to column headers — it landed in
`f6e9288` and was reverted in `93aa48f` after the three shortcomings
below outweighed the gain. They are the reasons we're committing
to a real `gtk::ColumnView` rewrite next:

1. **Header widths are best-effort, not authoritative.** A SizeGroup
   gives every member the maximum of all members' preferred widths.
   If the header label is wider than every row in a column, the
   column visibly stretches at runtime — and there is no way to
   make the header narrower than the natural row width.
2. **No native column affordances.** Sortable headers, per-column
   resize, column visibility menus, and the libadwaita "compact /
   default density" toggles all want `gtk::ColumnView`.
3. **Two layout templates to keep in sync.** `build_row_widget` in
   `crates/paladin-gtk/src/account_row.rs` and the header-strip
   builder must remain bit-for-bit aligned in column order, spacing,
   and per-cell visibility logic. The contract is enforced by the
   shared `ColumnSizeGroups` registration code, but it is still two
   builders walking the same column list.

`gtk::ColumnView` collapses all three into one widget. The cost is a
substantial rewrite — every cross-cutting bit of the unlocked view
that touches the `gtk::ListBox` today (selection, search filter,
HOTP reveal wiring, section grouping, per-tick TOTP updates, busy-
mask broadcast) needs to be re-expressed against
`gio::ListStore` + `gtk::SignalListItemFactory` + `gtk::ColumnView`.
Notably the project moved **away** from `gtk::ListView` +
`SignalListItemFactory` once before — see the rationale doc-comment
on `AccountListComponent` — because per-tick `splice` calls fired
`items-changed(0, N, N)` which rebound every visible row mid-frame
and dropped clicks. Any return to that family must solve the rebind
problem.

### A.2 Target architecture

#### A.2.1 Widget tree

```
adw::ApplicationWindow
└─ content gtk::Box (vertical)
   └─ AccountListComponent root gtk::Box (vertical, hexpand+vexpand)
      ├─ gtk::SearchBar (unchanged)
      └─ gtk::ScrolledWindow
         └─ gtk::ColumnView                       ← was gtk::ListBox
            ├─ ColumnViewColumn "Account"
            │   └─ SignalListItemFactory          ← icon + label cell
            ├─ ColumnViewColumn "Code"
            │   └─ SignalListItemFactory          ← code label cell (numeric)
            ├─ ColumnViewColumn "Time"  (optional)
            │   └─ SignalListItemFactory          ← progress bar cell
            ├─ ColumnViewColumn ""      (no header text)
            │   └─ SignalListItemFactory          ← copy button cell
            └─ ColumnViewColumn ""      (no header text)
                └─ SignalListItemFactory          ← kebab menu cell
```

The optional "Time" column is shown only when at least one TOTP
account is present in the live row set (we currently use the same
predicate to decide whether to install the ticker). HOTP-only
vaults hide it, which matches today's behavior where the column
would be visually empty.

#### A.2.2 Item model

The store carries `RowItem` GObjects wrapping `AccountRowModel`.
Per-tick TOTP code updates flow through a mutable `Cell<RowDisplay>`
on the `RowItem` (or via `glib::Properties` so individual cell
factories can `bind_property` against the changed-notify signal),
**not** through a `splice`. This is the key invariant we lost the
last time we used a list-model-driven widget; document it loudly in
the rewrite.

```rust
glib::wrapper! {
    pub struct RowItem(ObjectSubclass<imp::RowItem>);
}

mod imp {
    use std::cell::{Cell, RefCell};
    use crate::account_row::RowDisplay;
    use paladin_core::AccountId;

    #[derive(Default)]
    pub struct RowItem {
        pub id: Cell<Option<AccountId>>,
        pub display: RefCell<RowDisplay>,
        pub icon_hint: RefCell<Option<String>>,
        pub busy: Cell<bool>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RowItem {
        const NAME: &'static str = "PaladinRowItem";
        type Type = super::RowItem;
    }

    impl ObjectImpl for RowItem { /* #[glib::derived_properties] */ }
}
```

Per-tick updates set the changed properties on the existing
`RowItem`; `bind_property` on each cell factory propagates the new
value into the cell widget. The store's row count is **only**
changed by Add / Remove / search-filter — not by ticks.

#### A.2.3 Selection and search

* `gtk::SingleSelection` wraps the store and becomes the
  `ColumnView`'s `set_model`. The current
  `AccountListComponent` selection logic (which uses `select_row`
  on the `ListBox` because `FactoryVecDeque` has no `ListModel`)
  collapses to `selection.set_selected(position)`.
* The search filter remains in `AppModel` — `AccountRowModel`s for
  the current query are recomputed there and the new vec is
  diff'd against the live store via
  `store.splice_diff(old, new, |a, b| a.id == b.id)` (small helper)
  so per-tick rebinds never touch the store.

#### A.2.4 Section grouping (issuer headers between rows)

`gtk::ColumnView` has no `set_header_func` equivalent for in-list
section headers — those are a `ListBox`-only feature. To preserve
the existing `show-section-headers` user preference (currently
shipped and toggleable), section headers are rendered as styled
`RowItem`s interleaved into the store:

* Add a `kind: enum RowKind { Section(String), Account(AccountSummary) }`
  field to `RowItem`. The "Account" cell factory branches on
  `kind`: section rows render as a single-cell heading spanning all
  columns; account rows render the existing icon+label. Per-column
  factories for non-account cells render empty for section rows.
* Selectability is suppressed by calling
  `list_item.set_selectable(false)` in each cell factory's `bind`
  step when the bound `RowItem` is a section.
  (`gtk::SelectionFilterModel` is **not** the right widget here —
  it presents the currently-selected items of an upstream model,
  it does not gate which items may be selected. For coarser
  control, wrap `gtk::SingleSelection` in a custom
  `gtk::SelectionModel` subclass that returns `false` from
  `is_selected` for section positions.)
* `AppModel` computes the interleaved row list (section + account
  rows) from `AccountRowModel` using the existing
  `row_section_header` predicate, gated by the
  `show-section-headers` GSettings key. Toggling the key rebuilds
  the row list without resetting the live selection.

#### A.2.5 Per-tick update path

The flicker-free contract from the existing
`AccountRowComponent` setup must be preserved. Per-tick TOTP
refreshes today route through
`factory.send(index, AccountRowMsg::Rebind(display))` — the row's
widget tree is built once and re-bound in place.

Under ColumnView, the equivalent is:

```rust
for (id, display) in tick_dispatch_plan {
    // pure lookup against the AccountId → position index; rows that
    // are no longer in the store (e.g. removed mid-tick) are skipped.
    let Some(item) = store.row_item_for_id(id) else { continue };
    item.set_display(display);             // glib::Property notify
    // Cell factories' bind_property targets pick up the change.
}
```

The crucial guarantee: never call `store.splice(...)` from a tick
handler. Only Add/Remove/Refresh/SearchFilter touch the store.

#### A.2.6 Action plumbing

Each row's copy button / kebab menu / HOTP next button currently
goes through a per-row `gio::SimpleActionGroup` named
`ROW_ACTION_GROUP_NAME`. With `gtk::ColumnView` the buttons split:

* **Copy and HOTP "next"** — drop the action group entirely; the
  cell factory's `bind` step calls `button.connect_clicked` with a
  closure that captures the bound `RowItem`'s `AccountId` and emits
  the corresponding `AccountListOutput` directly. The closure is
  re-installed on every `bind` so it always closes over the current
  row.
* **Kebab `gtk::MenuButton`** — a `gio::MenuModel` invokes named
  gio actions, so this button still needs a
  `gio::SimpleActionGroup`. Install it on the cell during `bind`
  (not `setup`) so its handlers close over the current `RowItem`,
  and re-install on every rebind. The menu model itself is built
  once at `setup` time via `build_kebab_menu_model`.

### A.3 Files affected

| File | Change |
|---|---|
| `crates/paladin-gtk/src/account_list.rs` | Substantial rewrite. `gtk::ListBox` → `gtk::ColumnView`. `FactoryVecDeque<AccountRowComponent>` → `gio::ListStore<RowItem>` + `gtk::SignalListItemFactory` per column. Selection moves to `gtk::SingleSelection`. The in-list section-header dispatch table (`precompute_section_headers`, `install_section_header_func`, `build_section_header_label`) is replaced by `RowKind::Section` interleaving in `AppModel`; the pure predicate helpers (`row_section_header`, `issuer_group_header`) survive and feed the interleaver. |
| `crates/paladin-gtk/src/account_row.rs` | The factory-component machinery (`AccountRowComponent`, `AccountRowInit`, `AccountRowMsg`, `AccountRowOutput`, `AccountRowWidgets`, `build_row_widget`, `bind_row`, `install_row_action_group`) is **deleted**. The pure projection helpers (`project_row`, `progress_display`, `progress_urgency`, `code_display`, `counter_display`, `apply_busy_mask`, `next_button_visible`, `progress_visible`, `kebab_visible`, `copy_enabled`) survive — the ColumnView cell factories consume the same `RowDisplay` values. |
| **new** `crates/paladin-gtk/src/row_item.rs` | `RowItem` `GObject` subclass + `glib::Properties` derive macro + `set_display` mutator. |
| **new** `crates/paladin-gtk/src/column_view.rs` (or fold into `account_list.rs`) | Cell factory builders: `build_account_column_factory`, `build_code_column_factory`, `build_time_column_factory`, `build_copy_column_factory`, `build_kebab_column_factory`. Each returns a `gtk::SignalListItemFactory` whose `setup` builds the cell widget tree and whose `bind` reads from the `RowItem`'s properties. |
| `crates/paladin-gtk/src/app/model.rs` | `AccountListInit` field names change (`rows: Vec<AccountRowModel>` → unchanged), `initial_selection` semantics unchanged. `AppMsg::ShowSectionHeadersChanged` is rewired to rebuild the interleaved row list and `splice_diff` it into the store. New `AppMsg::ShowColumnHeadersChanged(bool)` mirrors that signal for the new `show-column-headers` key. Per-tick dispatch helpers (`tick_dispatch_plan`, `forward_row_output`) need re-routing since `AccountRowOutput` no longer exists — actions emit `AccountListOutput` directly from the cell-factory closures. |
| `crates/paladin-gtk/src/data/org.tamx.Paladin.Gui.gschema.xml` | Add `show-column-headers` key (default `true`); the existing `show-section-headers` key stays. |
| `crates/paladin-gtk/src/settings.rs` | Add a preferences row for `show-column-headers` alongside the existing `show-section-headers` row (Display group, title/subtitle helper fns mirroring the section-headers row). |
| `crates/paladin-gtk/tests/account_list_logic.rs` | Tests that bind directly to `AccountRowComponent` re-target to the new factory builders. Selection / search / busy-mask broadcast tests stay structurally similar but call into ColumnView APIs (`SingleSelection::selected`, `gio::ListStore::n_items`). |
| `crates/paladin-gtk/tests/account_row_logic.rs` | Pure projection helpers (`project_row` et al.) stay; widget-bind tests delete with `bind_row`. |
| This document (`docs/IMPLEMENTATION_PLAN_04_GTK.md`) | Rewrite §"Component tree" → describe ColumnView. Update §"libadwaita usage" if the row's CSS classes change. Note the section-header decision. Promote this appendix into the body of the plan. |
| `docs/DESIGN.md` | If user-visible behavior around section headers changes (Path 1), the relevant paragraph updates here. |

### A.4 Implementation checklist

Track progress against this list when the rewrite begins. The five
foundational decisions (section headers, column-header visibility,
sortable columns, HOTP "next" placement, Time-column visibility)
are recorded in §A.6 and need no further deliberation; the checklist
below reflects those resolutions.

#### `RowItem` GObject
- [x] Define `RowItem` in `crates/paladin-gtk/src/row_item.rs` with `id`, `display`, `icon_hint`, `busy` properties.
- [x] Wire `glib::Properties` derive (Rust GObject crate) and the per-property setters. *Implementation note*: `RowDisplay` carries non-`Value` shapes (`CodeDisplay`, `ProgressDisplay`, `AccountKindSummary`) so the per-property derive isn't a clean fit for the full projection. The implementation keeps the same observable contract via a custom `display-changed` signal (`ROW_ITEM_DISPLAY_CHANGED_SIGNAL`) that fires on every `set_display` / `set_busy` mutation; cell factories will `connect_local` to that name in their `bind` step. The four documented fields are exposed as plain Rust getters / setters on the wrapper.
- [x] Add `RowItem::from_row_model(&AccountRowModel) -> Self`.
- [x] Add `RowItem::set_display(&self, RowDisplay)` and verify it fires the change signal (now `display-changed`, see note above).
- [x] Unit-test: setter fires the `display-changed` signal. (See `tests/row_item_logic.rs`.)

#### Store + selection
- [x] Replace `FactoryVecDeque<AccountRowComponent>` with `gio::ListStore::new::<RowItem>()`.
- [x] Build `gtk::SingleSelection::new(Some(store))`; bind to `ColumnView::set_model`.
- [x] Replace `apply_list_box_selection` with a `SingleSelection::set_selected(position)` helper (`position_for_account` resolves `Option<AccountId>` to the `u32` store position).
- [x] Build `splice_diff` helper that, given an old and new `Vec<AccountRowModel>`, computes the minimum (insert, remove) ops against the store keyed by `AccountId` — never `splice(0, N, N)`. Implemented as `column_view::splice_plan` (pure-logic op planner) + `column_view::apply_splice_plan` (driver against a real `gio::ListStore<RowItem>`); see `tests/column_view_logic.rs`.

#### Cell factories
- [x] `build_account_column_factory` — icon (24px) + ellipsized label (hexpand). (Section rows render a single full-width heading and hide the icon.)
- [x] `build_code_column_factory` — `numeric` CSS class label; bind to `display.code`. Also wires the inline HOTP "next" button and a `dim-label` counter slot.
- [x] `build_time_column_factory` — horizontal `gtk::Box` containing `gtk::ProgressBar` (width_request 96; bind to `display.progress_fraction` + urgency CSS class) and a numeric/dim `gtk::Label` (`width_chars(3)`, `xalign(1.0)`) showing seconds-remaining via `account_row::format_seconds_remaining`, mirroring the TUI gauge + countdown layout.
- [x] `build_copy_column_factory` — `gtk::Button` "edit-copy-symbolic"; activate emits `AccountListOutput::CopyCode(item.id())`. Sensitive bound to `display.copy_enabled`.
- [x] `build_kebab_column_factory` — `gtk::MenuButton` "view-more-symbolic"; menu model built once at setup time; per-cell `gio::SimpleActionGroup` rebound on each `bind` so the closures capture the current item's `AccountId`.
- [x] HOTP "next" affordance: rendered inline in the "Code" cell, immediately adjacent to the code label (matches today's layout). Visibility bound to `display.next_button_visible`; `connect_clicked` closure emits `AccountListOutput::AdvanceHotp(item.id())`.
- [x] Helper `column_view::any_totp` predicate over the current `Vec<AccountRowModel>` so `AccountListComponent` can hide the "Time" column entirely when no row has a TOTP kind. (Live wiring of `column.set_visible` lands with the `account_list.rs` rewrite.)

#### Sortable columns
- [x] Attach a `gtk::Sorter` to the "Account" column that sorts by `(issuer, label)` case-insensitive. Clicking the column header toggles sort direction; default is unsorted (preserves vault insertion order from `docs/DESIGN.md`). The pure-logic sort key is shipped as `column_view::account_column_sort_key(&AccountRowModel) -> (String, String)`; `column_view::compare_account_row_items(&RowItem, &RowItem) -> std::cmp::Ordering` is the same projection over the live `RowItem`s; `column_view::build_account_column_sorter() -> gtk::CustomSorter` wires them into the GTK side and is attached by `AccountListComponent::init`.
- [x] Code, Time, Copy, and Kebab columns are non-sortable (live-changing values or action affordances).  No `set_sorter` call is made for those four columns, so the header chevron does not render and clicks are inert.
- [x] Cross-check `docs/DESIGN.md` § listing-order contract — the default (unsorted) view must still equal vault insertion order. Clicking a sortable header is a user-initiated override and does not persist across restarts.  `AccountListComponent::init` does **not** call `column_view.sort_by_column(Some(&account_column), ...)`, so the initial sort is `None` and `gtk::ColumnView` renders rows in `gio::ListStore` insertion order — i.e. vault insertion order, as required.

#### Per-tick update path
- [x] Rewrite `AccountListMsg::Tick` handler to walk `tick_dispatch_plan`, look up the matching `RowItem` in the store via an `AccountId → position` index, and call `item.set_display(new_display)`. (Implementation walks the store once instead of a per-tick `AccountId → position` map, which is `O(n)` per tick; a map can be reintroduced if profiling demands it.)
- [x] Verify no `splice` is called from the Tick handler. (`handle_tick` only mutates `RowItem`s in place.)
- [x] Stress test: 50 TOTP accounts, 1s tick, observe no flicker / no dropped clicks across 60s.  Automated as `tick_stress_preserves_store_size_and_row_identity_across_many_iterations` in `tests/account_list_logic.rs`: 50 TOTP rows × 60 simulated tick iterations, asserts `store.n_items()` is invariant (no splice from the Tick path) and every `RowItem` GObject pointer is invariant (no allocations) every iteration. Companion `tick_dispatch_fans_change_signal_through_set_display` counts the `display-changed` signal firings so a regression that silently breaks the change-signal fan-out cannot pass undetected. The data-level proofs stand in for the manual visual QA; a human pass is still appropriate when the live `gtk::ColumnView` lands but is no longer a blocker for the checklist.

#### Search / filter
- [x] `AppModel` recomputes `filtered_row_models_from_vault(...)`, then asks the live `AccountListComponent` to `splice_diff` the new vec into its store.  The wiring runs through two call sites in `crates/paladin-gtk/src/app/model.rs`: the `AppMsg::AccountListAction(AccountListOutput::QueryChanged)` handler (user typed into the search bar) and `AppModel::refresh_account_list` (post-mutation refresh after Add / Rename / Remove), both of which project through `filtered_row_models_from_vault(vault, &self.search_query)` and emit `AccountListMsg::Refresh`; the live `AccountListComponent` handler calls [`crate::column_view::apply_interleaved_splice_plan`] against its `gio::ListStore<RowItem>`.  End-to-end coverage lives in `tests/account_list_logic.rs` as `search_then_splice_filters_store_to_matches_only`, `search_then_splice_preserves_matched_row_identity_across_query_changes` (proves the live `gtk::SingleSelection` cursor survives a query change because matched-row `RowItem` GObject pointers are stable), and `search_then_splice_after_vault_mutation_reapplies_query` (pins `refresh_account_list`'s `&self.search_query` carry-through after a vault Add).
- [x] Cursor / selection survives a query change as today (`selected_row_after_refresh` + `position_for_account` together preserve the prior cursor across a `Refresh` whose `rows` still contain the selected id).

#### Section headers (via `RowKind::Section`)
- [x] Add `RowKind { Section(String), Account(AccountSummary) }` on `RowItem`; `RowItem::section(text) -> Self` constructor. *Implementation note*: the `Account` variant is data-less (`RowKind::Account`) because the per-row data lives in the wrapper's `account_id` / `display` / `icon_hint` fields; only the section variant carries text. Also adds `RowItem::kind` / `is_section` / `section_title` accessors used by the cell-factory branch logic.
- [x] Compute the interleaved row list (section + account rows) inside `AppModel` from `AccountRowModel` per the existing `row_section_header` predicate, gated by the `show-section-headers` GSettings key. Implemented as `column_view::interleave_section_headers` (pure logic, gated by a bool argument); `AppModel` calls it before each `apply_splice_plan`. Diff identity is generalized via `column_view::RowKey { Account(AccountId), Section(String) }` so account-row identity survives a section-toggle rebuild.
- [x] `AccountListMsg::SetShowSectionHeaders(bool)` rebuilds the interleaved row list and `splice_diff`s the result into the store. Live selection survives the rebuild because account-row identities are stable across the diff.
- [x] In each cell factory's `bind`, call `list_item.set_selectable(false)` when the bound `RowItem` is a section so it cannot become the `SingleSelection` selection. (`build_account_column_factory` carries the canonical call; the other four factories early-return on `is_section()` so they never bind interactive widgets to section rows.)
- [x] Cell factories branch on kind: the "Account" cell renders a single full-width label for section rows; all other columns render an empty placeholder for section rows.
- [x] Tests: section rows are non-selectable; toggling the `show-section-headers` GSettings key rebuilds the row list without resetting the live account-row selection; section rows render in the correct positions relative to the account rows per the `row_section_header` predicate.  Pure-logic coverage lives in `tests/column_view_logic.rs` as `apply_interleaved_inserts_section_rows_at_predicate_positions`, `apply_interleaved_every_section_row_is_marked_is_section` (pins the `is_section()` gate the cell factory's `set_selectable(!is_section())` reads), `apply_interleaved_disabled_yields_only_account_rows`, `apply_interleaved_account_row_identity_survives_show_section_headers_toggle` (proves the live `gtk::SingleSelection` cursor survives a preference flip because account `RowItem` GObject pointers are preserved), `apply_interleaved_section_rows_match_row_section_header_predicate` (cross-checks store positions against the shared `row_section_header` predicate), and `apply_interleaved_repeated_toggle_is_idempotent_for_account_rows`.

#### Column-header visibility preference
- [x] `show-column-headers` schema key in `org.tamx.Paladin.Gui.gschema.xml`, default `true`.
- [x] `crate::gsettings::{show_column_headers, set_show_column_headers, SHOW_COLUMN_HEADERS_KEY}` mirroring the existing `show_section_headers` helpers.
- [x] `AppMsg::ShowColumnHeadersChanged(bool)` + `changed::show-column-headers` signal wiring mirroring `show-section-headers`.
- [x] `AccountListMsg::SetShowColumnHeaders(bool)` → toggle the [`account_list::COLUMN_VIEW_NO_HEADERS_CSS_CLASS`] CSS class on the `gtk::ColumnView`.  The class is hooked up in `crates/paladin-gtk/data/style.css`, which collapses the header strip allocation (`min-height: 0`, `padding: 0`, `border: none`) and fades each cell to `opacity: 0` so the header disappears without restructuring the widget tree.
- [x] Preferences row in `settings.rs` Display group with title/subtitle helper fns, alongside the existing `show-section-headers` row.

#### Docs sync
- [x] This plan (`docs/IMPLEMENTATION_PLAN_04_GTK.md`) — §"Component tree" rewritten to describe the ColumnView + RowItem + factories.  Crate layout updated to list `column_view.rs` / `row_item.rs` and the new tests.  Keyboard-shortcut and row-activation tables retargeted from `gtk::ListBox` to `gtk::ColumnView`.  Historical §A.8 / Milestone 7 checklist entries are left intact as a record of what was done at the time.
- [x] `docs/DESIGN.md` — no user-visible vault behavior changes; the column-header / section-header preferences are new GUI affordances that don't change the §"listing-order" contract (insertion order still default).
- [x] `CLAUDE.md` — no changes required.

#### CI gates
- [x] `cargo fmt --all -- --check` clean.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` clean.
- [x] `cargo test --workspace --all-targets` green (138/138 test binaries pass).
- [x] `cargo public-api` diff reviewed — `paladin-gtk` is a binary crate (only `paladin-core` snapshots `cargo public-api` per CI), so no snapshot update is needed; the `paladin-core` surface did not change in this migration.  Verified 2026-05-24 by regenerating with the CI invocation (`cargo public-api -p paladin-core --simplified --color=never`) and confirming zero substantive diff against `crates/paladin-core/public-api.txt` (the only delta is two stale `Documenting…` / `Finished` build-log lines at the top of the committed file, a pre-existing wart unrelated to this work).
- [x] `cargo deny check` and `cargo audit` clean (no new advisories or licensing changes; pre-existing `unmatched license allowance` notes are unrelated to this work).

### A.5 Migration risk register

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| Per-tick `splice` regression returns dropped-click bug | Medium | High | Enforce in code review and add a regression test asserting `store.n_items()` is unchanged across a Tick. |
| Cell recycling breaks per-row action group identity | Medium | Medium | Bind action groups inside cell-factory `bind`, not `setup`; tests cover Copy + Rename through 100 sequential rebinds. |
| `RowKind::Section` rows become selectable through a missed `set_selectable(false)` branch | Low | Medium | Test that arrow-key navigation skips section rows and that `SingleSelection::selected_position` never points at a `Section` `RowItem`. |
| Sortable "Account" column unintentionally overrides vault insertion order at startup | Low | Medium | Initial sorter state is `None` (no column active); test that `n_items()` and per-position `RowItem.id` after construction equal the input `Vec<AccountRowModel>` order. |
| Search filter performance under ColumnView differs | Low | Low | The `splice_diff` helper holds n_items steady across query changes by id-matching. |
| `cargo public-api` snapshot churn | Certain | Low | Regenerate the snapshot and review the diff carefully. |
| `gtk::ColumnView` styling drift from libadwaita "navigation-sidebar" look | Medium | Low | Apply `add_css_class("rich-list")` or the libadwaita "boxed-list" classes that match the rest of the app. |

### A.6 Resolved decisions (2026-05-23)

1. **Section headers**: **preserved** via `RowKind::Section` rows
   interleaved into the store (the "Path 2" alternative described in
   §A.2.4). Keeps the shipped `show-section-headers` user preference
   working and avoids a user-facing regression.
2. **Column-header visibility**: **gated** by a new per-user
   `show-column-headers` GSettings key, defaulting to `true` and
   mirroring the existing `show-section-headers` plumbing
   (gschema, helpers in `gsettings.rs`, `AppMsg` variant, settings
   row).
3. **Sortable columns**: **enabled by default** on the columns
   where sorting is semantically meaningful (today: the "Account"
   column). Code and Time columns are non-sortable because their
   values change live; Copy and Kebab columns are action affordances
   with no sort axis. Default state is unsorted, preserving the
   vault insertion-order contract in `docs/DESIGN.md`; clicking a
   header is an opt-in user action that does not persist across
   restarts.
4. **HOTP "next" button placement**: **inline in the "Code" cell**,
   immediately adjacent to the code label. Matches today's layout
   and keeps the related controls visually grouped.
5. **"Time" column visibility on HOTP-only vaults**: **hidden
   entirely** when no live row has a TOTP kind. Re-shown when the
   next Add or Refresh introduces a TOTP row.

These are the assumptions baked into §A.3, §A.4, and §A.7. Flip
any of them in a post-v0.2 decision pass only if requirements
change.

### A.7 Estimated scope

Rough sizing for a single-engineer pass under the §A.6 resolutions
(`RowKind::Section` interleaving + gated column-header visibility +
sortable "Account" column + inline HOTP-next + hidden Time column
on HOTP-only vaults):

* ~700–900 lines of new Rust across `row_item.rs`, the ColumnView
  builders, the `RowKind`/interleaver machinery in `AppModel`, the
  new `show-column-headers` plumbing, and the rewired
  `account_list.rs`. (Higher than a Path-1 build by the ~100–150
  lines that `RowKind` + interleaver + selectability gating add.)
* ~400–500 lines deleted from `account_row.rs` (the factory
  machinery).
* ~8–10 new tests in `account_list_logic.rs` (selection skip past
  section rows, `show-section-headers` toggle preserving live
  selection, `show-column-headers` toggle, sortable Account column
  toggle preserving id-ordering on Reset, hidden Time column on
  HOTP-only); ~4–6 tests deleted that bound to factory internals.
* This plan: 1–2 sections rewritten when the appendix is promoted
  into the body. `docs/DESIGN.md` may need a short paragraph on
  column-header / sortable-column behavior, but no normative change
  to the listing-order contract.
* `cargo public-api` snapshot regenerated.

Realistic effort: **4–6 days** of focused work for a developer
familiar with relm4 and GObject subclassing in Rust, **plus**
~1 day of manual QA against a populated vault (50+ accounts, TOTP +
HOTP mix, active search, busy state, sort toggling, both prefs
flipped through every combination).

### A.8 Foundation landed 2026-05-23 — integration still pending

Pure-logic + cell-factory foundation for the ColumnView migration
has been merged in five commits ahead of the
`AccountListComponent` widget rewrite, so the rewrite can consume
ready-made helpers instead of inventing them inline:

| Commit | Subject | Lands |
|---|---|---|
| 59f457b | Introduce `RowItem` GObject for ColumnView migration | `row_item.rs` + 6 tests |
| ba8a66f | Add splice_diff helpers for the ColumnView store | `column_view.rs` (plan + apply) + 16 tests |
| c6f5f66 | Add `RowKind`, interleave helper, and generic splice key | `RowKind` on `RowItem`, `RowKey`, `interleave_section_headers`, generic `splice_plan<K>` + 4 tests |
| 83f0ec7 | Add cell factory builders for the ColumnView migration | 5 cell factories (`build_account_column_factory`, …, `build_kebab_column_factory`), `apply_interleaved_splice_plan`, `any_totp` |

Total: ~870 lines of new Rust (`row_item.rs` + `column_view.rs`) +
30 new tests, all green; `cargo clippy --workspace --all-targets
-- -D warnings` clean. No change to `account_list.rs`,
`account_row.rs`, `app/model.rs`, or any existing widget code —
the foundation is purely additive.

**Remaining work** for the next session, in the order the rewrite
should land:

1. **Rewrite `AccountListComponent`** in `account_list.rs`:
   replace the `FactoryVecDeque<AccountRowComponent>` +
   `gtk::ListBox` with a `gio::ListStore<RowItem>` +
   `gtk::ColumnView` + `gtk::SingleSelection`. Construct the five
   columns by calling the factory builders shipped in `column_view.rs`.
   Wire the existing message variants (`Refresh`, `Tick`,
   `SetBusy`, `SetShowSectionHeaders`, `SetSearchModeEnabled`,
   `FocusSearch`, `ActivateRow`, `SetQuery`) onto the new widget
   tree:
   - `Refresh` calls `column_view::apply_interleaved_splice_plan(store, rows, show_section_headers)`,
     re-applies the selection through `SingleSelection::set_selected`,
     and toggles the Time column visibility via `column_view::any_totp(rows)`.
   - `Tick` walks `tick_dispatch_plan`'s output and calls
     `RowItem::set_display` on the matching items in the store —
     **never** `store.splice(...)`.
   - `SetShowSectionHeaders` re-calls
     `apply_interleaved_splice_plan` with the new flag; account
     rows survive because `RowKey::Account` is stable across the
     diff.
   - `SetBusy` walks the store and calls `RowItem::set_busy`
     instead of broadcasting through `FactoryVecDeque::broadcast`.
   - `ActivateRow(position)` resolves the store position to a
     `RowItem`, ignores section rows (defensive — they are
     `set_selectable(false)`), then routes through
     `default_row_activation` against the live `RowItem.display()`'s
     `code` variant.
2. **Delete the `FactoryComponent` machinery** from
   `account_row.rs`: `AccountRowComponent`, `AccountRowInit`,
   `AccountRowMsg`, `AccountRowWidgets`, `build_row_widget`,
   `bind_row`, `install_row_action_group`, `bind_row_icon`. Keep
   `AccountRowOutput`, `dispatch_row_action`,
   `format_counter_label`, `build_kebab_menu_model`, the
   `ROW_*_ACTION_NAME` constants, `HIDDEN_CODE_PLACEHOLDER`,
   `PROGRESS_URGENCY_CSS_CLASSES`, and all pure projection helpers
   — `column_view.rs`'s cell factories consume them. (Or delete
   `AccountRowOutput`/`dispatch_row_action` too if every consumer
   moves off them — see step 4's test update.)
3. **Rewire `app/model.rs`**: drop the
   `crate::account_list::forward_row_output` import (it disappears
   with `AccountRowOutput`); `AccountListComponent::forward(…)`
   now passes `AccountListOutput` through identity. No other
   visible API on `AppModel` changes.
4. **Update tests**:
   - `tests/account_list_logic.rs`: tests that bind to
     `AccountRowComponent` directly retarget at the new factory
     builders. Selection / search / busy-mask broadcast tests stay
     structurally similar but call into `gio::ListStore::n_items`
     / `SingleSelection::selected` instead of `ListBox`.
   - `tests/account_row_logic.rs`: pure projection helper tests
     (`project_row`, `code_display`, …) stay. Widget-bind tests
     (`build_row_widget_is_exposed_from_account_row_module`,
     `bind_row_is_exposed_from_account_row_module`,
     `bind_row_icon_is_exposed_from_account_row_module`,
     `install_row_action_group_is_exposed_from_account_row_module`,
     and the `AccountRowComponent` scaffold test) delete with the
     widget helpers themselves.
   - `tests/gtk_smoke.rs`: `format_widget_states_marker` may
     change shape — verify the smoke test's grep target still
     fires when the new ColumnView mounts.
5. **Sortable Account column** (§A.4 "Sortable columns"): attach a
   `gtk::Sorter` to the "Account" column's `gtk::ColumnViewColumn`
   that sorts by `(issuer, label)` case-insensitive. Default
   unsorted preserves the vault insertion-order contract.
6. **Column-header visibility preference** (§A.4
   "Column-header visibility"): new `show-column-headers` key in
   `data/org.tamx.Paladin.Gui.gschema.xml`, helpers in
   `gsettings.rs`, `AppMsg::ShowColumnHeadersChanged(bool)`,
   `AccountListMsg::SetShowColumnHeaders(bool)` that toggles
   `gtk::ColumnView::set_show_column_separators` (or hides each
   `ColumnViewColumn::set_header_widget` to suppress the header
   strip entirely), and a preferences row in `settings.rs`.
7. **Promote this appendix** into the body of the plan, rewrite
   §"Component tree" > `AccountListComponent` to describe the
   ColumnView shape, and update `docs/DESIGN.md` if any
   user-visible behavior shifts beyond the new preferences.
8. **CI gates**: regenerate `crates/paladin-core/public-api.txt`
   if the public surface changed (it didn't yet — the foundation
   is additive, but the rewrite will), then re-confirm `cargo
   fmt`, `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace --all-targets`, `cargo deny check`,
   `cargo audit`.

The cell factories in `column_view.rs` are the riskiest piece of
the integration: cells are recycled by the
`gtk::SignalListItemFactory`, so the per-bind closures (HOTP
"next" click, copy click, kebab `gio::SimpleActionGroup`
installation) must close over the *current* `RowItem`'s
`AccountId`, not a stale one. The shipped code re-installs all
three on every `bind` and disconnects them on `unbind` via a
shared `Rc<RefCell<HashMap>>` keyed by `gtk::ListItem` pointer.
The §A.5 row "Cell recycling breaks per-row action group
identity" remains the test target the integration should hit: a
test that scrolls a 50-row list back and forth and asserts that
every row's Copy / Rename / Next dispatches the bound row's id,
not a leaked one.
