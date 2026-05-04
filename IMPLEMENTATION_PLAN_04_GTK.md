# Implementation Plan 04 — `paladin-gtk`

Source of truth: [DESIGN.md](DESIGN.md) §3, §4.6–§4.7, §5–§13.
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

> **Status: deferred to v0.2.** Per §12, the GUI is deferred to v0.2; the
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
(icons, `.desktop`, CSS) require license-compat vetting per §13 before
inclusion.

## Component tree (per §7)

- `AppModel` — owns the `Missing`, `Locked`, or `Unlocked` state.
- `UnlockComponent` — passphrase entry, **shown only when the vault is
  encrypted**. Skipped entirely for plaintext vaults.
- `AccountListComponent` — `gtk::ListView` with a custom row factory bound
  to a `gio::ListStore` of `AccountRowModel`. Includes a search entry using
  the same case-insensitive `"{issuer}:{label}"` substring matching as §5 /
  §6 via `str::to_lowercase()`; no Unicode normalization.
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
  not block creation. Manual duplicate collisions reject with the existing
  account in the dialog. Multi-QR imports use a fixed `ImportConflict::Skip`
  and report imported/skipped/warning counts (parity with §6). Successful
  manual and QR additions call `Vault::save(&Store)` after accounts are
  inserted.
- `RemoveDialog` — confirmation gate before calling `Vault::remove` followed
  by `Vault::save(&Store)`. Save errors surface inline.
- `PassphraseDialog` — three sub-flows mirroring CLI/TUI: `set` / `change` /
  `remove`. New passphrases prompted twice; mismatch returns to the dialog
  with an inline error. `remove` shows the plaintext-storage warning and
  requires explicit confirmation before mutation. `set` is enabled only for
  plaintext vaults; `change` and `remove` are enabled only for encrypted
  vaults. Any stale invalid-state error stays in the dialog and does not
  mutate visible state.
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts. Spinners clamp to the §5 minimums
  (`auto_lock.timeout_secs >= 30`, `clipboard.clear_secs >= 5`). Setters
  validate but do not save themselves; after a successful setter call the
  component invokes `Vault::save(&Store)` and surfaces any save error inline.

## Auto-lock and clipboard auto-clear (per §7)

Behave the same as the TUI, including **opt-in default** and the
**plaintext-vault auto-lock no-op**. Implemented with GLib timeout sources
(`glib::timeout_add_local`) so they integrate with the GTK main loop.

- Auto-lock: idle timer reset on any input event sourced through
  `gtk::EventControllerKey` / pointer controllers wired at the `AppModel`
  root. On expiry, drop `Vault` and switch `AppModel` to `Locked`,
  re-presenting `UnlockComponent`. For plaintext vaults the timer is never
  armed; the setting still persists for the encrypted-later case.
- Clipboard auto-clear: at copy time, capture `(token, value)`. On wake,
  ignore stale tokens first, then read the current `gdk::Clipboard` text; if
  it equals `value`, clear; otherwise no-op.

## Icons (per §7)

`AccountRowComponent` resolves `Account.icon_hint` against the system icon
theme via `gtk::IconTheme`, falling back to a generic placeholder when the
slug is `None` or unresolved. The CLI and TUI ignore the field entirely.

## Global flags

`--vault <path>` and `--no-color` are accepted (parity with siblings).
`--no-color` is a parser-level no-op in the GUI: there is no ANSI palette
to disable, and theming is delegated to Adwaita / the system theme.
`--json` is rejected at parse time — the GUI has no JSON mode.

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

- HOTP `next`: if `Vault::hotp_advance` fails, leave the row/reveal state
  unchanged and show an inline/status error.
- Copy: if the GDK clipboard write fails, show an inline/status error and do
  not schedule clipboard auto-clear.
- Add / remove / settings saves keep the active dialog open with an inline
  error. Durability-unconfirmed save errors are shown as committed but
  uncertain, matching the core error.
- Passphrase transition errors keep the passphrase dialog open. Successful
  transitions update the current vault mode before the dialog closes.
- QR clipboard import errors — no image, image decode failure, zero decoded
  QRs, and invalid QR payloads — stay in the Add dialog with an inline error.

## Linux desktop integration

- `data/paladin-gtk.desktop` shipped under `share/applications/`.
- App icon under `share/icons/hicolor/scalable/apps/paladin-gtk.svg`.
- Adwaita-style CSS in `data/style.css`, scoped via `gtk::CssProvider`.

## Tests

The GUI itself is hard to test without a display server. Tests are split:

- **Pure-logic unit tests** (no display): icon resolution **fallback
  decision** (`None`/empty slug → placeholder; failed lookup → placeholder;
  the actual `gtk::IconTheme` lookup is exercised by the smoke test),
  search filtering, auto-lock state machine, clipboard "clear if unchanged"
  decision logic, HOTP reveal window timing.
- **Smoke test** in CI under `xvfb-run`: app launches, opens a prepared
  plaintext vault, the list renders. Required for Milestone 7 sign-off.
- **Manual test plan** (`tests/manual/MANUAL_TEST_PLAN.md`) per Milestone 7
  checklist: unlock encrypted vault; copy TOTP; HOTP next reveals + copies;
  reveal expires; auto-lock fires; clipboard auto-clear honors
  if-unchanged; add manual; add via clipboard image; settings persist;
  passphrase set/change/remove; icon theme resolution + fallback.

## Milestone 7 checklist (expanded from §11)

- [ ] Relm4 component tree (Unlock / List / Row / Add / Remove /
  Passphrase / Settings).
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
