// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hicolor app-icon install-layout contract tests for `paladin-auth-gtk`.
//!
//! Per `docs/IMPLEMENTATION_PLAN_04_GTK.md` §"Linux desktop integration" and
//! the Milestone 7 checklist entries:
//!
//! * `data/icons/hicolor/scalable/apps/org.tamx.PaladinAuth.Gui.svg`
//! * 16 / 24 / 32 / 48 / 64 / 128 / 256 / 512 PNG fallbacks under
//!   `data/icons/hicolor/<size>/apps/org.tamx.PaladinAuth.Gui.png`
//! * `data/icons/hicolor/symbolic/apps/org.tamx.PaladinAuth.Gui-symbolic.svg`
//!
//! The hicolor layout is what `gtk::IconTheme` and the freedesktop
//! `Icon=` desktop-entry key consume; the same files install verbatim
//! under `/usr/share/icons/hicolor/...` in both native (`.deb` /
//! `.rpm`) and Flatpak builds so the launcher glyph, the
//! `AdwAboutDialog` icon-name lookup, and the window-class grouping
//! all resolve identically.

use std::fs;
use std::path::PathBuf;

use paladin_auth_gtk::APP_ID;

/// Hicolor PNG fallback sizes per §"Linux desktop integration".
///
/// 16 / 24 / 32 / 48 are the GNOME HIG fallback ladder (legacy menubar,
/// toolbar, dialog, launcher). 64 / 128 / 256 / 512 cover the sizes
/// GNOME Shell's app-drawer and search results actually request on
/// modern desktops — without them, Shell falls through to the
/// scalable SVG via `librsvg`, and a base64-PNG-in-SVG payload can
/// fail `GdkPixbuf`'s icon-theme path, leaving the launcher glyph
/// blank. Consumers that cannot render the SVG (older GTK panels,
/// certain embedded launchers) read the matching `<size>/apps/`
/// PNG directly.
const HICOLOR_PNG_SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256, 512];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn icons_root() -> PathBuf {
    crate_root().join("data").join("icons").join("hicolor")
}

fn scalable_svg_path() -> PathBuf {
    icons_root()
        .join("scalable")
        .join("apps")
        .join(format!("{APP_ID}.svg"))
}

fn symbolic_svg_path() -> PathBuf {
    icons_root()
        .join("symbolic")
        .join("apps")
        .join(format!("{APP_ID}-symbolic.svg"))
}

fn png_fallback_path(size: u32) -> PathBuf {
    icons_root()
        .join(format!("{size}x{size}"))
        .join("apps")
        .join(format!("{APP_ID}.png"))
}

fn read_svg(path: &PathBuf) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

// --- Scalable SVG ------------------------------------------------------------

#[test]
fn scalable_svg_exists_at_expected_path() {
    let path = scalable_svg_path();
    assert!(
        path.is_file(),
        "expected the scalable hicolor SVG at {}",
        path.display(),
    );
}

#[test]
fn scalable_svg_basename_matches_app_id() {
    let basename = scalable_svg_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("scalable SVG path has a basename");
    assert_eq!(basename, format!("{APP_ID}.svg"));
}

#[test]
fn scalable_svg_is_well_formed_svg_root() {
    let contents = read_svg(&scalable_svg_path());
    assert!(
        contents.trim_start().starts_with("<?xml ") || contents.trim_start().starts_with("<svg"),
        "scalable SVG must start with the XML declaration or the <svg> root",
    );
    assert!(
        contents.contains("<svg") && contents.contains("</svg>"),
        "scalable SVG must contain a well-formed <svg> root element",
    );
}

#[test]
fn scalable_svg_declares_explicit_viewbox() {
    let contents = read_svg(&scalable_svg_path());
    // freedesktop / GNOME HIG expects a viewBox-declared SVG so the
    // icon renderer can scale the artwork to any pixel size without
    // visible blur. Width/height are accepted but the viewBox is the
    // contract.
    assert!(
        contents.contains("viewBox"),
        "scalable SVG must declare an explicit viewBox so the renderer can rescale at any size",
    );
}

#[test]
fn scalable_svg_carries_spdx_header() {
    let contents = read_svg(&scalable_svg_path());
    assert!(
        contents.contains("SPDX-License-Identifier"),
        "scalable SVG must carry an SPDX-License-Identifier comment",
    );
}

// --- PNG fallbacks -----------------------------------------------------------

#[test]
fn png_fallbacks_exist_at_each_required_size() {
    for &size in HICOLOR_PNG_SIZES {
        let path = png_fallback_path(size);
        assert!(
            path.is_file(),
            "expected the {size}x{size} PNG fallback at {}",
            path.display(),
        );
    }
}

#[test]
fn png_fallbacks_use_png_magic_bytes() {
    // Hicolor-installed PNGs must be honest PNG files (the install
    // layout's contract). Read the first 8 bytes and assert against
    // the standard PNG signature: 89 50 4E 47 0D 0A 1A 0A.
    const PNG_SIGNATURE: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    for &size in HICOLOR_PNG_SIZES {
        let path = png_fallback_path(size);
        let bytes = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        assert!(
            bytes.len() >= PNG_SIGNATURE.len(),
            "{} is too short to be a PNG ({} bytes)",
            path.display(),
            bytes.len(),
        );
        assert_eq!(
            &bytes[..PNG_SIGNATURE.len()],
            PNG_SIGNATURE,
            "{} must start with the PNG magic-byte signature",
            path.display(),
        );
    }
}

#[test]
fn png_fallbacks_have_matching_ihdr_dimensions() {
    // The PNG IHDR chunk's first two big-endian u32s carry width and
    // height. Pin each PNG against the size encoded in its install
    // directory so a future rerasterization can't silently land a
    // mis-sized fallback.
    const IHDR_OFFSET: usize = 16; // 8 magic + 4 chunk length + 4 chunk type = "IHDR"
    for &size in HICOLOR_PNG_SIZES {
        let path = png_fallback_path(size);
        let bytes = fs::read(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        assert!(
            bytes.len() >= IHDR_OFFSET + 8,
            "{} is too short to carry an IHDR chunk ({} bytes)",
            path.display(),
            bytes.len(),
        );
        let width = u32::from_be_bytes([
            bytes[IHDR_OFFSET],
            bytes[IHDR_OFFSET + 1],
            bytes[IHDR_OFFSET + 2],
            bytes[IHDR_OFFSET + 3],
        ]);
        let height = u32::from_be_bytes([
            bytes[IHDR_OFFSET + 4],
            bytes[IHDR_OFFSET + 5],
            bytes[IHDR_OFFSET + 6],
            bytes[IHDR_OFFSET + 7],
        ]);
        assert_eq!(
            width,
            size,
            "{} IHDR width must equal the hicolor directory size",
            path.display(),
        );
        assert_eq!(
            height,
            size,
            "{} IHDR height must equal the hicolor directory size",
            path.display(),
        );
    }
}

// --- Symbolic variant --------------------------------------------------------

#[test]
fn symbolic_svg_exists_at_expected_path() {
    let path = symbolic_svg_path();
    assert!(
        path.is_file(),
        "expected the symbolic hicolor SVG at {}",
        path.display(),
    );
}

#[test]
fn symbolic_svg_basename_matches_app_id_symbolic_convention() {
    // The freedesktop icon-theme convention is to suffix symbolic
    // variants with `-symbolic`. Pin the basename so a future asset
    // rename can't drop the suffix without a matching test churn.
    let basename = symbolic_svg_path()
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .expect("symbolic SVG path has a basename");
    assert_eq!(basename, format!("{APP_ID}-symbolic.svg"));
}

#[test]
fn symbolic_svg_is_well_formed_svg_root() {
    let contents = read_svg(&symbolic_svg_path());
    assert!(
        contents.contains("<svg") && contents.contains("</svg>"),
        "symbolic SVG must contain a well-formed <svg> root element",
    );
}

#[test]
fn symbolic_svg_carries_spdx_header() {
    let contents = read_svg(&symbolic_svg_path());
    assert!(
        contents.contains("SPDX-License-Identifier"),
        "symbolic SVG must carry an SPDX-License-Identifier comment",
    );
}

#[test]
fn symbolic_svg_uses_currentcolor_for_recoloring() {
    // GNOME-style symbolic icons recolor on the fly. The contract is
    // that the body uses `currentColor` (or `color: currentColor`) so
    // the Adwaita palette can tint the symbolic against the active
    // foreground. A symbolic that hardcodes `fill="#xxxxxx"` shows up
    // tinted-wrong on dark themes.
    let contents = read_svg(&symbolic_svg_path());
    assert!(
        contents.contains("currentColor") || contents.contains("currentcolor"),
        "symbolic SVG must use currentColor so the Adwaita palette can recolor it",
    );
}
