---
name: gtk4-relm4-design
description: Design and build GTK4 + relm4 (Rust) applications that follow the GNOME Human Interface Guidelines. Use when planning UI structure, picking widgets, laying out a window, wiring relm4 components/factories, choosing libadwaita patterns, or reviewing a Rust GTK frontend for HIG conformance. Triggers on requests to design, lay out, or critique a GTK/Adwaita interface, draft a relm4 component tree, or implement a specific HIG pattern (preferences, navigation split view, dialog, toast).
---

# GTK4 + relm4 design with the GNOME HIG

This skill is the rule-of-thumb reference when designing or building a
GNOME-native desktop app in Rust with GTK4 and relm4. It assumes
**libadwaita** (Adw) is available — modern GNOME apps target Adwaita,
not raw GTK styling. Use this when sketching layouts, picking widgets,
structuring components, or auditing existing UI for HIG fit.

The HIG itself is the source of truth: <https://developer.gnome.org/hig/>.
When in doubt, defer to the HIG and to the libadwaita widget gallery
(<https://gnome.pages.gitlab.gnome.org/libadwaita/doc/main/widget-gallery.html>).

## Before designing anything

1. **Re-read the relevant HIG section** for the pattern you need
   (navigation, dialogs, preferences, lists, toasts). Do not invent
   patterns; reuse Adw widgets that already encode the rules.
2. **Check what already exists** in the project — existing
   components, the app's window structure, naming conventions, and
   any design notes (`docs/DESIGN.md`, `docs/ui/*`). Don't fork the
   visual language inside one app.
3. **State the user task in one sentence** before touching widgets.
   "User adds a new TOTP entry by scanning a QR code or pasting an
   `otpauth://` URI" yields a different layout than "user manages a
   long list of entries." Widget choice flows from the task.
4. **Decide the window class.** Almost always
   `adw::ApplicationWindow` with an `AdwToolbarView` containing an
   `AdwHeaderBar`. Use `adw::Window` only for non-application
   sub-windows (dialogs prefer `AdwDialog`/`AdwAlertDialog`).

## Core HIG principles to keep front-of-mind

- **One primary task per window.** If a screen tries to do two
  different things, split it (navigation page, dialog, or separate
  window).
- **Progressive disclosure.** Show the common path; tuck advanced
  controls behind "Show more", a preferences page, or a menu.
- **Content first.** Chrome (toolbars, sidebars) supports content;
  it does not dominate it. Prefer flat header bars without borders.
- **Forgiving by default.** Destructive actions need confirmation
  (`AdwAlertDialog` with a destructive-action style class) and,
  where reasonable, undo via `AdwToast` with an action button.
- **Keyboard- and pointer-equal.** Every action reachable by mouse
  must be reachable by keyboard. Wire mnemonics, accelerators, and
  focus order deliberately.
- **Adaptive, not just responsive.** Use `AdwBreakpoint` so the same
  window collapses cleanly to mobile widths. Test at ~360dp width.
- **Accessibility is not optional.** Set `accessible-role`,
  `accessible-label`, and `accessible-description`. Honor
  `gtk-enable-animations` and high-contrast styles.

## Widget choice cheat-sheet (prefer Adw over raw GTK)

| Need                              | Use                                                                                                  |
|-----------------------------------|------------------------------------------------------------------------------------------------------|
| Top-level window                  | `adw::ApplicationWindow` + `adw::ToolbarView` + `adw::HeaderBar`                                     |
| Multi-page navigation             | `adw::NavigationView` (stack of pages) or `adw::NavigationSplitView` (sidebar + content)             |
| Master/detail that adapts to mobile | `adw::NavigationSplitView` with a `breakpoint`                                                     |
| Tabs                              | `adw::TabView` + `adw::TabBar` / `adw::TabOverview`                                                  |
| Preferences window                | `adw::PreferencesDialog` containing `adw::PreferencesPage` → `adw::PreferencesGroup` → rows         |
| Settings rows                     | `adw::ActionRow`, `adw::SwitchRow`, `adw::ComboRow`, `adw::EntryRow`, `adw::PasswordEntryRow`, `adw::SpinRow`, `adw::ExpanderRow` |
| Modal dialog                      | `adw::Dialog` (generic) or `adw::AlertDialog` (yes/no/destructive)                                   |
| Transient banner                  | `adw::Banner` (in-content) or `adw::Toast` via `adw::ToastOverlay` (transient feedback)              |
| Empty / loading / error state     | `adw::StatusPage` with an icon, title, description, and at most one primary action                   |
| Long content                      | `gtk::ScrolledWindow` wrapping `adw::Clamp` (max-width ~600 for forms, ~800 for reading)             |
| Form layout                       | `adw::PreferencesGroup` even outside a preferences window — it gives correct spacing and grouping    |
| Long list of items                | `gtk::ListView` + `gtk::SignalListItemFactory` (virtualized). Avoid `GtkListBox` for >100 rows.      |
| Selectable rows                   | `gtk::SelectionModel` (`SingleSelection` / `MultiSelection` / `NoSelection`)                         |
| Loading/spinner inline            | `adw::Spinner` (Adw 1.6+) or `gtk::Spinner`                                                          |
| Primary action button             | `.suggested-action` style class on a `gtk::Button`                                                   |
| Destructive action button         | `.destructive-action` style class                                                                    |
| Flat icon button                  | `.flat` style class                                                                                  |
| Pill button                       | `.pill` style class                                                                                  |

If you reach for `GtkBox` with hand-tuned margins to imitate one of
the patterns above, stop — the Adw widget already encodes the spacing,
animations, and adaptive behavior you want.

## Layout, spacing, and typography

- **Margin scale:** 6, 12, 18, 24, 36 px. Don't invent intermediates.
  The default for content padding inside a page is 12 px; between
  unrelated groups, 24 px.
- **Content width:** wrap forms and prose in `adw::Clamp` with
  `maximum-size: 600` (forms/settings) or `400` (single-column dense
  forms). Reading text can go up to 800.
- **Typography:** use the named CSS classes — `.title-1` … `.title-4`,
  `.heading`, `.body`, `.caption`, `.caption-heading`, `.monospace`,
  `.numeric`, `.dim-label`. Do not set point sizes directly; the
  user's font scale must be respected.
- **Numeric / tabular data:** `.numeric` ensures monospace digits
  without forcing a monospace font everywhere — use it for OTP codes,
  counters, timestamps.
- **Icons:** symbolic SVGs from the GNOME icon library
  (`-symbolic` suffix). They recolor automatically with the theme.
  Don't ship full-color icons in toolbars or rows.
- **Color:** never hard-code colors. Use named CSS variables
  (`@accent_color`, `@warning_color`, `@error_color`, `@card_bg_color`,
  …) so light/dark/high-contrast themes work. For Adw 1.6+, prefer
  `adw::StyleManager` to query and react to color scheme changes.

## Window structure recipe

A typical Adw application window:

```
AdwApplicationWindow
└── AdwBreakpoint(s)            // adaptive collapse rules
└── AdwToolbarView
    ├── [top]    AdwHeaderBar   // title widget, primary actions, menu
    ├── [top]    AdwBanner?     // optional in-app message
    ├── [content] AdwToastOverlay
    │             └── (the actual page: NavigationView / NavigationSplitView / Clamp+content)
    └── [bottom] (optional) action bar / status bar
```

- The header bar's title widget is usually `adw::WindowTitle` or
  `adw::ViewSwitcher`. For navigation flows, let
  `AdwNavigationPage`'s title bubble up automatically.
- The hamburger menu lives at the right end of the header bar; build
  it from a `Gio::Menu` model, not hand-coded buttons.
- Put global, in-content notifications in the `AdwToastOverlay` so
  they animate in/out correctly and stack.

## Dialog rules

- Modal yes/no/destructive: `adw::AlertDialog`. Always set
  `default-response`, `close-response`, and use the
  `destructive` / `suggested` response appearance.
- Generic content modal: `adw::Dialog` with `child` set to your
  layout. Present with `dialog.present(Some(&parent))`.
- Never pop a `gtk::Dialog` in new code — it's deprecated for app
  use. `AdwDialog` is bottom-sheet-on-mobile aware.
- Do not stack dialogs more than one deep. If you need multi-step,
  use a `NavigationView` *inside* the dialog.

## Adaptive layout (mobile / narrow)

- Add at least one `AdwBreakpoint` per top-level window. Common rule:
  collapse a `NavigationSplitView` at `max-width: 400sp`.
- Test by resizing the window narrow; verify nothing clips, no
  horizontal scrollbars appear, and the header bar remains usable.
- Hide non-essential header-bar buttons on narrow widths via
  breakpoints (`setters` flipping `visible`), not by deleting them.

## Accessibility checklist

- Every interactive widget has a label. For icon-only buttons, set
  `tooltip-text` *and* `accessible-label` (they're not the same).
- Group related controls with `accessible_role = "group"` and a
  `labelled_by` relation to the group heading.
- Tab order matches visual order. Override with `focusable` /
  `set_focus_chain` only when the visual order is wrong.
- Provide `mnemonic-widget` on labels that describe a single
  control, so Alt+letter focuses the control.
- Animations: respect `Settings:gtk-enable-animations`. relm4's
  `Transition` helpers do this automatically; raw GTK code may not.
- Contrast: the named `@*_color` variables already meet WCAG AA in
  the stock themes — don't override them.

## relm4 architecture patterns

relm4 is the Elm-style wrapper around gtk4-rs. Default to its
idioms; don't drop to raw `gtk4-rs` unless you need a widget relm4
doesn't yet wrap.

### Component selection

- **`Component`** — the workhorse. State + input/output messages +
  command futures. Use for any non-trivial screen, dialog, or
  reusable widget.
- **`SimpleComponent`** — same shape, no `CommandOutput` /
  background tasks. Use for pure-UI widgets (a settings row, a
  small dialog) where all work is synchronous.
- **`AsyncComponent`** — when `init` itself must `await` (e.g.,
  loading a vault before the first frame). Don't reach for it just
  because some commands are async — `Component` already handles
  async commands.
- **`FactoryComponent`** + `FactoryVecDeque` — for collections of
  identical sub-widgets (rows in a list). Pair with `AdwActionRow`
  or your own row component.
- **`Worker`** — long-running, non-UI background tasks (file I/O,
  crypto). Communicates via messages; never touches widgets.

### State and messages

- Keep `Model` minimal — only what the view needs to render. Derived
  values belong in `view!` expressions, not in the model.
- `Input` is what the user (or parent) does *to* the component.
  `Output` is what the component reports *back* to its parent. Don't
  conflate them; don't use `Output` for sibling-to-sibling chatter
  (route through the parent or use a shared `MessageBroker`).
- Make message enums exhaustive and self-describing
  (`Input::DeleteEntryRequested(EntryId)`, not `Input::Click`).
- Long-running work: emit `CommandOutput` from a `command_future`,
  don't block `update`.

### `view!` macro discipline

- One widget per line, indented to match the tree shape. Read it
  top-to-bottom and you should see the visual hierarchy.
- Bind dynamic properties with `#[watch]`; bind once-set properties
  without it. Over-watching causes needless re-renders.
- Use `#[name = "..."]` to capture handles you'll reach for in
  `update` (e.g., `toast_overlay.add_toast(...)`). Keep these rare —
  most state should flow through messages, not direct widget pokes.
- Connect signals with `connect_clicked[sender] => move |_| { sender.input(...) }`;
  never call `sender.input(...).unwrap()` — it's infallible, and the
  closure looks cleaner without it.
- Prefer `gtk::Box` with `orientation` and `spacing` over manual
  margins for stacking. Use `set_margin_*` only at container edges.

### Component composition

- Children are constructed via `Controller<ChildModel>` stored in
  the parent's `Model`. Forward child `Output` to parent `Input`
  with `forward(...)`.
- For dialogs, build the dialog as its own `Component`, present it
  from the parent, and forward its `Output` (e.g.,
  `Confirmed(Item) | Cancelled`).
- Avoid passing `gtk::Widget` references between components. Pass
  data (IDs, structs); let each component own its widgets.

### Threading & async

- `update` runs on the GTK main thread. Never block it — no
  synchronous file I/O on a vault, no `std::thread::sleep`.
- Spawn work via `sender.command(|out, shutdown| async move { ... })`
  or a `Worker`. Marshal results back as `CommandOutput` /
  messages.
- For app-wide signals (settings changed, vault locked), use a
  `MessageBroker<T>` instead of threading a sender through every
  component.

## Process for designing a new screen

1. **Write the user story** in one sentence (task, trigger,
   success).
2. **Pick the HIG pattern** that matches (preferences page, list
   with detail, status page, dialog, banner, …).
3. **Sketch the widget tree** top-down using the recipe above. Stop
   when every leaf is a concrete Adw/GTK widget.
4. **Identify the relm4 component boundary.** A new component is
   warranted when it has its own state, its own lifecycle, or is
   reused. Otherwise inline it in the parent's `view!`.
5. **List the messages** — `Input`, `Output`, `CommandOutput` —
   before writing code. If you can't name them, the design is fuzzy.
6. **Plan the adaptive behavior.** What collapses below 400sp?
   Which header-bar buttons disappear?
7. **Plan the empty, loading, and error states.** Each gets a
   concrete widget (usually `AdwStatusPage` or a `Banner`/`Toast`).
8. **Plan keyboard flow.** Default focus, tab order, shortcut
   accelerators (`Ctrl+N`, `Esc` to dismiss, `Enter` to confirm).
9. **Only now write the `view!` and `update`.**

## Reviewing existing UI for HIG fit

When asked to critique or improve a GTK4/relm4 screen, walk this
list and report concrete deltas:

- Is the window an `AdwApplicationWindow` with a `ToolbarView` +
  `HeaderBar`? If not, why?
- Are forms/settings using `AdwPreferencesGroup` rows, or hand-rolled
  `GtkBox`es with margins?
- Is destructive action confirmed via `AdwAlertDialog` with the
  destructive style class?
- Does feedback use `AdwToast`/`AdwBanner` rather than blocking
  dialogs?
- Empty / error / loading states present and implemented as
  `AdwStatusPage` (not blank space)?
- At least one `AdwBreakpoint`? Test at 360sp width.
- Symbolic icons only in toolbars/rows? No hard-coded colors?
- Every interactive widget has an accessible label and tooltip?
- relm4: is `update` non-blocking? Are commands used for async
  work? Are `#[watch]` annotations only on properties that actually
  change?

For each finding, cite the HIG section or libadwaita widget that
encodes the rule, and propose the smallest change that resolves
it.

## Anti-patterns (don't ship these)

- A `GtkWindow` with a hand-built title bar instead of `AdwHeaderBar`.
- `GtkMessageDialog` for confirmations (deprecated; use `AdwAlertDialog`).
- A `GtkListBox` rendering hundreds of rows (use `GtkListView` +
  factory).
- Forms laid out in `GtkGrid` with manual labels — `AdwPreferencesGroup`
  + rows is the HIG-approved equivalent.
- Modal dialogs that block the UI for I/O. Spawn a command;
  meanwhile show a spinner or progress.
- Hard-coded hex colors, point sizes, or pixel margins outside the
  6/12/18/24/36 scale.
- `#[watch]` on every property — it forces re-render churn.
- `unwrap()` in signal closures or `update`. Surface errors as
  `Output::Error(...)` and render them as a toast or banner.
- Re-implementing what's already a single Adw widget away
  (tab strips, sidebars, breadcrumbs, switchers).

## When the HIG and reality conflict

If a feature genuinely doesn't fit any HIG pattern (rare), name
it explicitly to the user, propose the closest pattern, and ask
before deviating. Don't silently invent a new visual language.

## References

- GNOME HIG — <https://developer.gnome.org/hig/>
- libadwaita docs — <https://gnome.pages.gitlab.gnome.org/libadwaita/doc/main/>
- Adwaita widget gallery — <https://gnome.pages.gitlab.gnome.org/libadwaita/doc/main/widget-gallery.html>
- gtk4-rs book — <https://gtk-rs.org/gtk4-rs/stable/latest/book/>
- relm4 book — <https://relm4.org/book/stable/>
- GNOME icon library — <https://developer.gnome.org/hig/reference/icons.html>
