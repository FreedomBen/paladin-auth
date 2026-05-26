// SPDX-License-Identifier: AGPL-3.0-or-later

//! Workspace-wide keybindings table for `paladin-tui`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_03_TUI.md` "Help overlay" and the
//! "Packaging — Man page" bullet: the overlay's content is
//! generated from the same keybindings table that the workspace
//! `cargo xtask man` target appends into the man page (after the
//! clap-derived synopsis) so the two cannot drift.
//!
//! [`KEYBINDINGS`] is the single source of truth for the v0.1
//! `paladin-tui` keybindings: the read-only Help overlay
//! ([`crate::view::help`]) renders these rows verbatim, and the
//! future `cargo xtask man` target will read the same constant when
//! it appends the "Keybindings" section to `paladin-tui.1`. Editing
//! this table is the only way to change the documented bindings;
//! the reducer's input-handling lives in
//! [`crate::app::reducer`] and is asserted against
//! [`crate::app::reducer`]-level unit tests rather than the wording
//! here.

/// One row of the documented `paladin-tui` keybindings table.
///
/// The [`keys`](Self::keys) string lists the key(s) bound to
/// [`action`](Self::action). Multiple keys that share an action are
/// grouped in one row with their textual presentations joined by
/// `" / "` (alternative chords) or a single space (chorded modifier
/// pairs); see [`KEYBINDINGS`] for the full layout. Both fields are
/// `&'static str` so the table is `const`-constructible and lives
/// in `.rodata` rather than allocating at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keybinding {
    /// Textual presentation of the key(s). Examples: `"Enter"`,
    /// `"Ctrl-C"`, `"PgUp / PgDn"`, `"↑ ↓ / j k"`. Rendered verbatim
    /// in the Help overlay's left column and in the man page.
    pub keys: &'static str,

    /// Plain-English description of what the key(s) do. Phrased to
    /// stand on its own without the key column, so the man page can
    /// reformat into a definition list and the TUI overlay can
    /// render it as a right-column cell.
    pub action: &'static str,
}

/// Documented `paladin-tui` keybindings in row order.
///
/// Mirrors the "Keybindings (initial v0.1)" table in
/// [`docs/DESIGN.md`](../../../../docs/DESIGN.md) §6 and the matching table in
/// `docs/IMPLEMENTATION_PLAN_03_TUI.md`. The order is meaningful: the
/// Help overlay and the man page both render rows top-to-bottom, so
/// `?` lands at the bottom of the action keys (where the user
/// who just hit it expects to see it) and the global quit keys
/// (`Esc` / `q` / `Ctrl-C`) sit at the very bottom.
pub const KEYBINDINGS: &[Keybinding] = &[
    Keybinding {
        keys: "↑ ↓ / j k / Ctrl-P Ctrl-N",
        action: "Move selection up / down",
    },
    Keybinding {
        keys: "PgUp PgDn / Ctrl-B Ctrl-F",
        action: "Page up / down by viewport height",
    },
    Keybinding {
        keys: "Home End / gg G",
        action: "Jump to first / last row of filtered set",
    },
    Keybinding {
        keys: "Ctrl-U Ctrl-D",
        action: "Half-page up / down",
    },
    Keybinding {
        keys: "zz",
        action: "Recenter viewport on selected row",
    },
    Keybinding {
        keys: "Enter",
        action: "Copy selected code",
    },
    Keybinding {
        keys: "C",
        action: "Copy selected row's next code (TOTP only)",
    },
    Keybinding {
        keys: "n",
        action: "HOTP next-code (advance + reveal)",
    },
    Keybinding {
        keys: "a",
        action: "Open Add modal",
    },
    Keybinding {
        keys: "r",
        action: "Open Remove confirmation",
    },
    Keybinding {
        keys: "R",
        action: "Open Rename modal",
    },
    Keybinding {
        keys: "i",
        action: "Open Import modal",
    },
    Keybinding {
        keys: "e",
        action: "Open Export modal",
    },
    Keybinding {
        keys: "Q",
        action: "Open QR Export modal for the focused row",
    },
    Keybinding {
        keys: "/",
        action: "Focus search bar",
    },
    Keybinding {
        keys: "Tab / Shift-Tab",
        action: "Cycle focus between search bar and list",
    },
    Keybinding {
        keys: "p",
        action: "Open Passphrase modal",
    },
    Keybinding {
        keys: "s",
        action: "Open Settings modal",
    },
    Keybinding {
        keys: "?",
        action: "Open Help overlay",
    },
    Keybinding {
        keys: "Esc",
        action: "Close modal / overlay / search; step back in the create-vault wizard; quit on unlock / startup-error / create-vault ChooseMode",
    },
    Keybinding {
        keys: "q",
        action: "Quit from list, startup-error, and create-vault ChooseMode / ConfirmPlaintext (otherwise a typed passphrase character)",
    },
    Keybinding {
        keys: "Ctrl-C",
        action: "Quit (any screen)",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_actions_are_non_empty() {
        // Catch accidental empty rows that would render as a blank
        // line in the Help overlay or man page.
        for (idx, kb) in KEYBINDINGS.iter().enumerate() {
            assert!(
                !kb.keys.is_empty(),
                "row {idx}: empty keys string in KEYBINDINGS"
            );
            assert!(
                !kb.action.is_empty(),
                "row {idx}: empty action string for keys {:?}",
                kb.keys
            );
        }
    }

    #[test]
    fn covers_question_mark_and_quit_keys() {
        // The Help overlay must list its own opening chord and the
        // global quit chord; the test catches a regression where a
        // future trim accidentally drops one of those rows.
        let keys: Vec<&str> = KEYBINDINGS.iter().map(|kb| kb.keys).collect();
        assert!(keys.contains(&"?"), "missing `?` row");
        assert!(keys.contains(&"Esc"), "missing `Esc` row");
        assert!(keys.contains(&"q"), "missing `q` row");
        assert!(keys.contains(&"Ctrl-C"), "missing `Ctrl-C` row");
    }
}
