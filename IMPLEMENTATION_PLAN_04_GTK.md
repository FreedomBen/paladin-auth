# Implementation Plan 04 — `paladin-gtk`

Source of truth: [DESIGN.md](DESIGN.md) §3, §7, §11 (Milestone 7), §12.
Depends on: [`IMPLEMENTATION_PLAN_01_CORE.md`](IMPLEMENTATION_PLAN_01_CORE.md).

> **Status: deferred to v0.2.** Per §12, the GUI is deferred to v0.2; the
> TUI ships in v0.1. This plan describes the v0.2 work and is included in the
> initial planning batch so the workspace shape and API contract on
> `paladin-core` accommodate it.

## Scope

Standalone GTK4 binary `paladin-gtk` built with **Relm4** on **GTK4** per §7.
Exposes the same operations as the TUI: search/list of accounts, copy code,
HOTP `next` with reveal window, add account (manual or scan-from-clipboard
image), settings (auto-lock + clipboard-clear), passphrase set/change/remove.

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
│   │   └── state.rs       # Locked / Unlocked { vault, store, settings }
│   ├── components/
│   │   ├── unlock.rs      # UnlockComponent — encrypted vaults only
│   │   ├── account_list.rs    # AccountListComponent (gtk::ListView + factory)
│   │   ├── account_row.rs     # AccountRowComponent (label, code, gauge/next, copy)
│   │   ├── add_account.rs     # AddAccountComponent (manual fields + paste image)
│   │   └── settings.rs        # SettingsComponent (toggles + spinners)
│   ├── clipboard.rs       # gdk Clipboard + opt-in "clear if unchanged" wipe
│   ├── auto_lock.rs       # GLib idle/timeout source; encrypted-only; plaintext no-op
│   ├── hotp_reveal.rs     # 120s per-row reveal window
│   ├── icons.rs           # gtk::IconTheme lookup against Account.icon_hint
│   └── ticker.rs          # 250ms timeout source for TOTP gauge updates
└── tests/
    ├── icon_resolution.rs
    ├── auto_lock_logic.rs        # pure logic; no display required
    ├── clipboard_clear_logic.rs  # pure logic; no display required
    └── manual/MANUAL_TEST_PLAN.md
```

## Component tree (per §7)

- `AppModel` — owns the unlocked `Vault` (or `Locked` state).
- `UnlockComponent` — passphrase entry, **shown only when the vault is
  encrypted**. Skipped entirely for plaintext vaults.
- `AccountListComponent` — `gtk::ListView` with a custom row factory bound
  to a `gio::ListStore` of `AccountRowModel`.
- `AccountRowComponent` — label, code, progress (TOTP) / "next" button
  (HOTP), copy button. HOTP rows hide their code until the user activates
  "next" (advances counter and saves); after a 120-second reveal window the
  code returns to the hidden state, matching the TUI. Copying a hidden HOTP
  row is **disabled**; copying during the reveal window copies the visible
  code and does not advance again.
- `AddAccountComponent` — manual fields + "scan from clipboard image" (uses
  `paladin_core::import::qr_image_bytes` against raw RGBA bytes pulled from
  the GDK clipboard).
- `SettingsComponent` — toggles for auto-lock and clipboard-clear, with
  spinners for timeouts. Persisted via `Vault` setters.

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
  read the current `gdk::Clipboard` text; if it equals `value`, clear;
  otherwise no-op.

## Icons (per §7)

`AccountRowComponent` resolves `Account.icon_hint` against the system icon
theme via `gtk::IconTheme`, falling back to a generic placeholder when the
slug is `None` or unresolved. The CLI and TUI ignore the field entirely.

## Global flags

`--vault <path>` and `--no-color` are accepted (parity with siblings).
`--json` is rejected at parse time — the GUI has no JSON mode.

## Vault interaction

- On launch, `paladin_core::inspect(path)` resolves the mode.
- Plaintext → open directly, jump to `AccountListComponent`.
- Encrypted → present `UnlockComponent`. On submit, call
  `paladin_core::open(path, VaultLock::Encrypted(secret))`. Wrong passphrase
  surfaces inline; `unsafe_permissions` shows a dialog with the same human
  `chmod` repair string the CLI uses.
- Operations route through `Vault` and `Store` methods — no GUI-side
  duplication of OTP, validation, or import logic.

## Linux desktop integration

- `data/paladin-gtk.desktop` shipped under `share/applications/`.
- App icon under `share/icons/hicolor/scalable/apps/paladin-gtk.svg`.
- Adwaita-style CSS in `data/style.css`, scoped via `gtk::CssProvider`.

## Tests

The GUI itself is hard to test without a display server. Tests are split:

- **Pure-logic unit tests** (no display): icon resolution helpers,
  auto-lock state machine, clipboard "clear if unchanged" decision logic,
  HOTP reveal window timing.
- **Smoke test** in CI under `xvfb-run` if feasible: app launches, opens a
  prepared plaintext vault, the list renders.
- **Manual test plan** (`tests/manual/MANUAL_TEST_PLAN.md`) per Milestone 7
  checklist: unlock encrypted vault; copy TOTP; HOTP next reveals + copies;
  reveal expires; auto-lock fires; clipboard auto-clear honors
  if-unchanged; add manual; add via clipboard image; settings persist;
  passphrase set/change/remove; icon theme resolution + fallback.

## Milestone 7 checklist (per §11)

- [ ] Relm4 component tree (Unlock / List / Row / Add / Settings).
- [ ] Conditional unlock view (encrypted vaults only).
- [ ] Clipboard + auto-lock parity with TUI (opt-in).
- [ ] Linux desktop file + icon.
- [ ] Manual test plan documented.

## Dependencies (per §9)

`relm4`, `gtk4` (via `gtk4-rs`), `glib`, `gio`, `gdk4`, `arboard` (only
where GDK clipboard isn't sufficient — likely not needed since GDK
clipboard is the right path on Wayland/X11). Plus `paladin-core`.

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

- Component tree from §7 implemented.
- Plaintext vault opens to list directly; encrypted vault gates on unlock.
- Auto-lock and clipboard-clear are off by default; both honor the
  plaintext-vault no-op rule.
- Icon resolution works against system theme with placeholder fallback.
- Manual test plan executes cleanly on a Wayland and an X11 session.
- DESIGN.md unchanged unless a contradiction surfaces; in that case
  DESIGN.md is updated first.
