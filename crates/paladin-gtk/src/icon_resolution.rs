// SPDX-License-Identifier: AGPL-3.0-or-later

//! Account-row icon resolution for `paladin-gtk`.
//!
//! `AccountRowComponent` renders each account's icon by feeding
//! `AccountSummary.icon_hint` through [`resolve_display_icon`]. The
//! decision is split out as a pure function so the §"Pure-logic unit
//! tests > `tests/icon_resolution.rs`" checklist in
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md` can exercise it without
//! `gtk::IconTheme` or a display server; the live theme lookup is
//! wired up by `AccountRowComponent` in the binary and is covered by
//! the `tests/gtk_smoke.rs` smoke test.
//!
//! Per the plan's §"Icons (per §7)": `AccountRowComponent` resolves
//! `AccountSummary.icon_hint` against the system icon theme via
//! `gtk::IconTheme`, falling back to a generic placeholder when the
//! slug is `None` or unresolved. The CLI and TUI ignore the field
//! entirely.

/// Generic placeholder icon used when an account's `icon_hint` is
/// `None` / empty or when the system icon theme cannot resolve the
/// slug.
///
/// `dialog-password-symbolic` is part of the freedesktop / Adwaita
/// icon name spec and ships with every GNOME-style icon theme, so the
/// fallback is guaranteed to render against the system theme. The
/// constant lives next to [`resolve_display_icon`] so a future change
/// to `AccountRowComponent`'s chrome can revisit the choice in one
/// place.
pub const PLACEHOLDER_ICON_NAME: &str = "dialog-password-symbolic";

/// Resolve the icon name to render for an account row.
///
/// * `hint` — the canonical slug from `AccountSummary.icon_hint`
///   (already validated by `paladin_core::validate_slug` /
///   `paladin_core::parse_icon_hint_token` on the add path).
/// * `has_icon` — the system-icon-theme membership probe; in the
///   live binary this is roughly `move |slug|
///   gtk::IconTheme::for_display(&display).has_icon(slug)`. The
///   closure is intentionally [`FnOnce`] so the pure-logic test can
///   pass a panicking closure that asserts the GTK lookup is **not**
///   invoked for the `None` / empty / whitespace-only cases.
///
/// `None`, empty, and whitespace-only hints route directly to
/// [`PLACEHOLDER_ICON_NAME`] without consulting `has_icon`. Any other
/// hint that the system theme cannot resolve also falls back to the
/// placeholder. The returned `&str` either borrows the supplied slug
/// or points at the `'static` placeholder constant — both cases are
/// usable wherever an icon-name `&str` is expected (for example
/// `gtk::Image::set_icon_name`).
pub fn resolve_display_icon(hint: Option<&str>, has_icon: impl FnOnce(&str) -> bool) -> &str {
    let Some(slug) = hint else {
        return PLACEHOLDER_ICON_NAME;
    };
    if slug.trim().is_empty() {
        return PLACEHOLDER_ICON_NAME;
    }
    if has_icon(slug) {
        slug
    } else {
        PLACEHOLDER_ICON_NAME
    }
}
