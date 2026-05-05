# Implementation Plan 04 — `paladin-gtk`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4.6–§4.7, §5–§14.
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

> **Status: deferred to v0.2.** Per §13, the GUI is deferred to v0.2; the
> TUI ships in v0.1. This plan describes the v0.2 work and is included in the
> initial planning batch so the workspace shape and API contract on
> `paladin-core` accommodate it.

## Scope

Standalone GTK4 binary `paladin-gtk` built with **Relm4** on **GTK4** per §7.
Exposes the same operations as the TUI: search/list of accounts, copy code,
HOTP `next` with reveal window, add account (manual or scan-from-clipboard
image), remove account, settings (auto-lock + clipboard-clear), passphrase
set/change/remove.

Per §3 / CLAUDE.md: depends only on `paladin-core`. Never reaches into
`paladin-cli` or `paladin-tui`.

## Crate layout

```
crates/paladin-gtk/
├── Cargo.toml             # license = "AGPL-3.0-or-later"; bin = "paladin-gtk"
├── build.rs               # gresource bundle (icons, *.ui, *.css)
├── data/
│   ├── paladin-gtk.gresource.xml
│   ├── ui/                # *.ui templates
│   ├── icons/             # app icon + fallbacks
│   ├── style.css
│   └── paladin-gtk.desktop
├── src/
│   ├── main.rs            # gtk::init, register resources, RelmApp::new(...).run(...)
│   ├── cli.rs             # GlobalArgs (--vault, --no-color); reject --json
│   ├── app/
│   │   ├── mod.rs         # AppModel + AppMsg + AppOutput
│   │   └── state.rs       # Missing / Locked / Unlocked { vault, store }
│   ├── components/
│   │   ├── unlock.rs      # UnlockComponent — encrypted vaults only
│   │   ├── account_list.rs    # AccountListComponent (gtk::ListView + factory)
│   │   ├── account_row.rs     # AccountRowComponent (label, code, gauge/next, copy)
│   │   ├── add_account.rs     # AddAccountComponent (manual fields + paste image)
│   │   ├── remove.rs          # RemoveDialog (confirmation gate)
│   │   ├── import.rs          # ImportDialog (file picker + format + on-conflict + bundle passphrase)
│   │   ├── export.rs          # ExportDialog (file picker + format + overwrite + encrypted passphrase)
│   │   ├── passphrase.rs      # PassphraseDialog (set / change / remove flows)
│   │   └── settings.rs        # SettingsComponent (toggles + spinners)
│   ├── clipboard.rs       # gdk Clipboard + opt-in "clear if unchanged" wipe
│   ├── auto_lock.rs       # GLib idle/timeout source; encrypted-only; plaintext no-op
│   ├── hotp_reveal.rs     # 120s per-row reveal window
│   ├── icons.rs           # gtk::IconTheme lookup against Account.icon_hint
│   ├── search.rs          # case-insensitive issuer/label filtering
│   └── ticker.rs          # 250ms timeout source for TOTP gauge updates
└── tests/
    ├── icon_resolution.rs
    ├── search_logic.rs
    ├── auto_lock_logic.rs        # pure logic; no display required
    ├── clipboard_clear_logic.rs  # pure logic; no display required
    ├── hotp_reveal_logic.rs
    ├── gtk_smoke.rs              # xvfb-run integration smoke test
    └── manual/MANUAL_TEST_PLAN.md
```

Every new Rust source file carries the standard SPDX header
`// SPDX-License-Identifier: AGPL-3.0-or-later`. Vendored desktop assets
(icons, `.desktop`, CSS) require license-compat vetting per §14 before
inclusion.

## Component tree (per §7)

- `AppModel` — owns the `Missing`, `Locked`, or `Unlocked` state.
- `UnlockComponent` — passphrase entry, **shown only when the vault is
  encrypted**. Skipped entirely for plaintext vaults.
- `AccountListComponent` — `gtk::ListView` with a custom row factory bound
  to a `gio::ListStore` of `AccountRowModel`. Includes a search entry using
  the same case-insensitive `"{issuer}:{label}"` substring matching as §5 /
  §6 via `str::to_lowercase()`; no Unicode normalization. Empty issuer is
  allowed and the colon is still present in the match key; insertion order
  is preserved among matches. The CLI's `id:` prefix form is **not**
  honored by the GUI search (parity with the TUI).
- `AccountRowComponent` — label, code, progress (TOTP) / "next" button
  (HOTP), copy button. HOTP rows hide their code until the user activates
  "next" (advances counter and saves); after a 120-second reveal window the
  code returns to the hidden state, matching the TUI. Activating "next"
  during an open reveal advances to the next counter and restarts the
  120-second reveal window with the newly committed code (matches §6 —
  "next" is the "give me the next code" affordance, never a no-op). Copying
  a hidden HOTP row is **disabled**; copying during the reveal window copies
  the visible code and does not advance again.
- `AddAccountComponent` — manual fields + "scan from clipboard image". Reads
  a `gdk::Texture` from the GDK clipboard, downloads it into an RGBA8
  buffer, and passes width, height, bytes, and `import_time` to
  `paladin_core::import::qr_image_bytes`. Manual entries use
  `paladin_core::validate_manual`; validation warnings show inline and do
  not block creation. Manual duplicate collisions initially reject with the
  existing account in the dialog and offer an "add anyway" confirmation
  that re-submits the same input on the duplicate-allowed path (CLI parity
  with `--allow-duplicate`, appending a new account that shares the
  `(secret, issuer, label)` triple). Multi-QR imports use a fixed
  `ImportConflict::Skip` and report imported/skipped/warning counts (parity
  with §6). Successful manual and QR additions call `Vault::save(&Store)`
  after accounts are inserted.
- `RemoveDialog` — confirmation gate before calling `Vault::remove` followed
  by `Vault::save(&Store)`. Save errors surface inline.
- `ImportDialog` — `gtk::FileChooserNative` for the source file, a format
  selector (auto-detect or explicit `otpauth` / `aegis` / `paladin` /
  `qr`), and an on-conflict selector (`skip` / `replace` / `append`).
  Encrypted Paladin bundles (explicit `format == paladin` or
  auto-detected via the Paladin header) prompt for the bundle
  passphrase inside the dialog before invoking the importer. The
  selected `paladin_core::import::*` runs on `gio::spawn_blocking`
  (the encrypted-Paladin variant runs Argon2id) with results delivered
  back via Relm4 messages. On success,
  `Vault::import_accounts(accounts, conflict)` is called with the
  user's policy and persisted via `Vault::save(&Store)`;
  imported/skipped/replaced/appended/warning counts surface inline.
  Pre-commit save failures (`save_not_committed`) roll back the
  in-memory `import_accounts` mutation; durability-unconfirmed saves
  leave the merged accounts in memory and surface the warning inline.
  Importer errors (`unsupported_plaintext_vault`,
  `unsupported_encrypted_aegis`, `unsupported_aegis_entry_type`,
  `validation_error`, `no_entries_to_import`, `decrypt_failed`,
  `io_error`) stay in the dialog as inline errors and never mutate
  vault state.
- `ExportDialog` — format selector (plaintext `otpauth://` JSON list or
  encrypted Paladin bundle) and `gtk::FileChooserNative` for the
  destination path. Overwriting an existing file is rejected unless
  the user confirms an inline overwrite gate (parity with CLI
  `--force`). Encrypted exports prompt twice for the bundle passphrase
  and reject mismatch (`invalid_passphrase`
  `reason: "confirmation_mismatch"`) or empty entry
  (`reason: "zero_length"`) inline; the encrypted-bundle write runs on
  `gio::spawn_blocking` because it derives a fresh AEAD key.
  Plaintext exports show an explicit "this writes unencrypted secrets
  to disk" warning that the user must confirm before the write
  proceeds. Writes go through the same `0600` atomic-write pipeline
  used by the vault. On success the dialog closes with the written
  path surfaced inline; errors (`io_error`, refused-overwrite,
  `invalid_passphrase`) stay in the dialog. Export does not mutate
  the vault, so there is no rollback path.
- `PassphraseDialog` — three sub-flows mirroring CLI/TUI: `set` / `change` /
  `remove`. New passphrases prompted twice; mismatch returns to the dialog
  with an inline error. `remove` shows the plaintext-storage warning and
  requires explicit confirmation before mutation. `set` is enabled only for
  plaintext vaults; `change` and `remove` are enabled only for encrypted
  vaults. Any stale invalid-state error stays in the dialog and does not
  mutate visible state.
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts. Spinners clamp to the §5 minimums
  (`auto_lock.timeout_secs >= 30`, `clipboard.clear_secs >= 5`). Uses
  **live-apply** (each toggle / spinner change immediately invokes the
  matching setter and then `Vault::save(&Store)`), diverging from the TUI's
  buffer-then-Confirm modal — `gtk::Switch` and `gtk::SpinButton` are
  idiomatically immediate, and the §"Effect errors" pre-commit rollback
  reverts the visible widget value on `save_not_committed`. Setters
  validate but do not save themselves; the component owns the save call
  and surfaces any save error inline.

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
  if it equals `value`, clear; otherwise no-op.

## Icons (per §7)

`AccountRowComponent` resolves `Account.icon_hint` against the system icon
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
scripted.

## Vault interaction

- Resolve vault path from `--vault` or `directories::ProjectDirs::data_dir()`,
  then call `paladin_core::inspect(path)` to resolve the mode.
- Plaintext → call `paladin_core::open(path, VaultLock::Plaintext)` directly,
  then jump to `AccountListComponent`.
- Encrypted → present `UnlockComponent`. On submit, call
  `paladin_core::open(path, VaultLock::Encrypted(secret))` on
  `gio::spawn_blocking` so the §4.4 Argon2 KDF (m=64 MiB defaults) does not
  block the GTK main loop; the dialog shows a spinner until the join
  completes. Wrong passphrase surfaces inline; `unsafe_permissions` shows
  a dialog whose body is rendered via
  `paladin_core::format_unsafe_permissions(&err)` (§4.7) so the wording
  matches the CLI exactly and the GUI never depends on `paladin-cli`.
- Missing → show a non-mutating dialog telling the user to run
  `paladin init`. The GUI does not create vaults in v0.2 (parity with §6).
- Operations route through `Vault` and `Store` methods — no GUI-side
  duplication of OTP, validation, or import logic.

## Effect errors

Effects update visible state only after the underlying mutation succeeds:

- HOTP `next`: pre-commit save failures (`save_not_committed`) leave the
  in-memory counter and reveal state unchanged (per DESIGN §4.4 rollback)
  and surface an inline/status error. Durability-unconfirmed failures
  (`save_durability_unconfirmed`) reveal the new code and report the
  committed-but-uncertain status — the user has the new code in hand even
  though durability is in question. All other failures show an
  inline/status error and leave the row hidden.
- Copy: if the GDK clipboard write fails, show an inline/status error and do
  not schedule clipboard auto-clear.
- Add / remove / settings saves: validation failures occur before any
  in-memory mutation, so no rollback is needed; the dialog stays open with
  an inline error. Pre-commit save failures (`save_not_committed`) roll
  back the in-memory mutation so memory matches disk (Add removes the
  just-inserted account(s); Remove restores the removed account at its
  previous position; Settings restores the prior values), and the dialog
  stays open with the inline error so the user can retry.
  Durability-unconfirmed save errors leave the new state in memory
  (matching the committed on-disk state) and are shown as
  committed-but-uncertain, matching the core error.
- Passphrase set/change/remove: pre-commit and durability-unconfirmed
  handling lives in `Vault` itself per DESIGN §4.5 — the in-memory mode/key
  reverts on `save_not_committed` and is replaced on
  `save_durability_unconfirmed`. The dialog stays open and surfaces both
  failure classes inline; on success, the visible vault mode updates before
  the dialog closes.
- QR clipboard import errors — no image, image decode failure, zero decoded
  QRs, and invalid QR payloads — stay in the Add dialog with an inline error.
- Import / export: importer and exporter errors (the typed kinds listed
  in the component descriptions) stay in the active dialog as inline
  errors and never close it. Import save errors follow the
  Add/Remove/Settings rule: pre-commit (`save_not_committed`) rolls
  back the in-memory `import_accounts` merge so memory matches disk;
  durability-unconfirmed leaves the merged accounts and surfaces the
  warning. Export does not mutate vault state, so save-error rollback
  does not apply.

## Linux desktop integration

- `data/paladin-gtk.desktop` shipped at
  `/usr/share/applications/paladin-gtk.desktop` per §11.3. Sets
  `Categories=Utility;Security;`, the AGPL-aligned `Keywords=`, and
  `Exec=paladin-gtk %F` so file managers can hand off `otpauth://`
  files for import.
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

- **Cargo.toml metadata.** `crates/paladin-gtk/Cargo.toml` sets
  `description`, `homepage`, `repository`, `keywords`, `categories`,
  and `license = "AGPL-3.0-or-later"` so `nfpm` produces correct
  Debian / RPM control metadata without per-format duplication.
- **`.deb` / `.rpm` (via `nfpm`).** `packaging/deb/paladin-gtk.yaml`
  and `packaging/rpm/paladin-gtk.yaml` install
  `/usr/bin/paladin-gtk`, the desktop entry at
  `/usr/share/applications/`, and the icon set under
  `/usr/share/icons/hicolor/`. Debian declares `libgtk-4-1
  (>= 4.10)` (and `libadwaita-1-0 (>= 1.4)` if the v0.2 build
  depends on libadwaita — see "Open packaging question" below);
  Fedora declares the matching `gtk4` (and `libadwaita`) package
  names. No maintainer scripts: the vault is created on first use
  under `$XDG_DATA_HOME/paladin/`. The desktop-entry validator
  (`desktop-file-validate`) and the `gtk4-update-icon-cache` post-
  install hook are run by the §11 packaging pipeline, not by the
  package itself.
- **Flatpak.** `packaging/flatpak/paladin-gtk.yml` declares
  `org.gnome.Platform//46` (and the matching SDK), no
  `--share=network`, and the §11.4 sandbox permissions:
  `xdg-data/paladin:create`, `xdg-config/paladin:create`, plus the
  Wayland and X11 fallback sockets and clipboard access required
  for `gdk::Clipboard`. The Flatpak app ID is the §11.4
  placeholder `io.github.paladin_otp.Gui`, finalized at
  Flathub-submission time. `flatpak-builder` consumes the tagged
  release tarball with vendored Cargo deps so Flathub builds
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
  produces `.deb`, `.rpm`, and AppImage artifacts and verifies
  `desktop-file-validate` passes on the installed `.desktop`
  entry.

### Open packaging question — libadwaita

DESIGN §11.3 declares `libadwaita-1-0 (>= 1.4)` as a Debian dependency
for `paladin-gtk`, but this plan's "Dependencies" section says
**No `libadwaita` for v0.2** — styling stays on `gtk::CssProvider`.
The two are inconsistent: a runtime dep on libadwaita without a
build-time dep is misleading. Resolve before Milestone 7 — either
adopt `libadwaita` for v0.2 (and drop the §"No libadwaita" note) or
drop the libadwaita line from §11.3 and the packaging configs. Flag
the choice to the user; both paths are within the AGPL / GTK4
constraints, but the choice changes the dep declaration above.

## Tests

The GUI itself is hard to test without a display server. Tests are split:

- **Pure-logic unit tests** (no display): icon resolution **fallback
  decision** (`None`/empty slug → placeholder; failed lookup → placeholder;
  the actual `gtk::IconTheme` lookup is exercised by the smoke test),
  search filtering, auto-lock state machine, clipboard "clear if unchanged"
  decision logic, HOTP reveal window timing, import format-selector
  routing + on-conflict policy threading + post-merge counts mapping,
  export overwrite-gate + encrypted twice-confirm match logic.
- **Smoke test** in CI under `xvfb-run`: app launches, opens a prepared
  plaintext vault, the list renders. Required for Milestone 7 sign-off.
- **Manual test plan** (`tests/manual/MANUAL_TEST_PLAN.md`) per Milestone 7
  checklist: unlock encrypted vault; copy TOTP; HOTP next reveals + copies;
  reveal expires; auto-lock fires; clipboard auto-clear honors
  if-unchanged; add manual; add via clipboard image; import each format
  (otpauth, aegis plaintext, encrypted Paladin bundle, QR image file)
  with each on-conflict policy and verify reported counts; export
  plaintext (warning + confirmation, `0600` output) and encrypted
  Paladin bundle (twice-confirm, round-trip via Import); refused
  overwrite without confirmation; settings persist; passphrase
  set/change/remove; icon theme resolution + fallback.

## Milestone 7 checklist (expanded from §12)

- [ ] Relm4 component tree (Unlock / List / Row / Add / Remove /
  Import / Export / Passphrase / Settings).
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Clipboard + auto-lock parity with TUI (opt-in).
- [ ] Linux desktop file + icon.
- [ ] Manual test plan documented.
- [ ] `xvfb-run` headless smoke test green in CI (plaintext vault opens
  and renders the list).

## Dependencies (per §9)

`relm4`, `gtk4` (via `gtk4-rs`), `glib`, `gio`, `gdk4`, `clap`,
`directories`, plus `paladin-core`. GDK clipboard is the canonical
Wayland/X11 path; `arboard` is **not** a hard dependency for v0.2 and is
only added if GDK clipboard proves insufficient during implementation.

**No `libadwaita` for v0.2.** Styling is delegated to plain GTK4 widgets
plus the bundled `data/style.css` (Adwaita-style, scoped via
`gtk::CssProvider`). Adding `libadwaita` for `AdwApplicationWindow` /
`AdwHeaderBar` / `AdwToast` is a possible v0.3 polish step if the
manual test plan flags HIG gaps; it would require a §9 dependencies
update first.

**No `tokio`.** GTK's main loop is the executor; long work runs on
`gio::spawn_blocking` with results delivered back to the main thread via
Relm4 messages.

## Out of scope for v0.2

- Encrypted Aegis backup support (still a v0.2 stretch in §4.6, not blocking
  GUI release).
- Secret-service / OS keyring integration for passphrase caching — not in
  DESIGN.md, would require an explicit design update.
- macOS / Windows builds. Linux only for the v0.2 release.

## Definition of done

- Component tree above implemented.
- Plaintext vault opens to list directly; encrypted vault gates on unlock.
- Auto-lock and clipboard-clear are off by default; the plaintext-vault
  no-op rule applies to auto-lock only (clipboard-clear works in both modes).
- Icon resolution works against system theme with placeholder fallback.
- `xvfb-run` headless smoke test green in CI.
- Manual test plan executes cleanly on a Wayland and an X11 session.
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all`,
  `cargo deny check`, `cargo audit` clean.
- DESIGN.md unchanged unless a contradiction surfaces; in that case
  DESIGN.md is updated first.
