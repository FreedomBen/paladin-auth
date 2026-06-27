// SPDX-License-Identifier: AGPL-3.0-or-later

//! `cargo xtask man` — render `paladin-auth.1` and `paladin-auth-tui.1` via
//! `clap_mangen` from the live clap Commands.
//!
//! Output lands at `target/man/paladin-auth.1` and
//! `target/man/paladin-auth-tui.1`. The packaging pipeline gzips each file
//! (`xtask::package`) before handing it to `nfpm`, matching the
//! `/usr/share/man/man1/<name>.1.gz` paths in
//! `packaging/rpm/paladin-auth.yaml` and `packaging/rpm/paladin-auth-tui.yaml`.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Front-ends whose clap Commands xtask renders man pages for.
///
/// `paladin-auth-gtk` is intentionally absent — the GUI does not ship a man
/// page (its discoverability surface is the `AppStream` metainfo / desktop
/// entry instead, validated by the `desktop-metainfo` job).
const FRONTENDS: &[Frontend] = &[
    Frontend {
        binary: "paladin-auth",
        command: paladin_auth_cli::clap_command,
    },
    Frontend {
        binary: "paladin-auth-tui",
        command: paladin_auth_tui::clap_command,
    },
];

struct Frontend {
    binary: &'static str,
    command: fn() -> clap::Command,
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Directory the rendered `<binary>.1` files are written to.
    /// Defaults to `target/man/` at the workspace root so the
    /// packaging step in `xtask::package` finds the source files
    /// without an explicit path.
    #[arg(long, value_name = "DIR")]
    out_dir: Option<PathBuf>,
}

pub(crate) fn run(args: &Args) -> Result<(), Box<dyn Error>> {
    let out_dir = match &args.out_dir {
        Some(dir) => dir.clone(),
        None => workspace_root()?.join("target").join("man"),
    };
    fs::create_dir_all(&out_dir)?;
    for frontend in FRONTENDS {
        let path = out_dir.join(format!("{}.1", frontend.binary));
        render(frontend, &path)?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

fn render(frontend: &Frontend, path: &Path) -> Result<(), Box<dyn Error>> {
    let cmd = (frontend.command)();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer: Vec<u8> = Vec::new();
    man.render(&mut buffer)?;
    fs::write(path, buffer)?;
    Ok(())
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let parent = manifest_dir
        .parent()
        .ok_or("xtask CARGO_MANIFEST_DIR has no parent — workspace root unresolved")?;
    Ok(parent.to_path_buf())
}

/// One `(binary-name, gzipped-man-bytes)` pair per registered
/// front-end. Returned by [`render_all_gzipped`] so `xtask::package`
/// can stage the .gz files without shelling out to `gzip(1)`.
pub(crate) type GzippedManPages = Vec<(&'static str, Vec<u8>)>;

/// Walk the registered front-end binaries and produce one
/// `(binary, gzipped-man-bytes)` pair per front-end. Used by
/// `xtask::package` so the packaging step does not need to shell out
/// to `gzip(1)`.
pub(crate) fn render_all_gzipped() -> Result<GzippedManPages, Box<dyn Error>> {
    let mut out = Vec::with_capacity(FRONTENDS.len());
    for frontend in FRONTENDS {
        let cmd = (frontend.command)();
        let mut raw: Vec<u8> = Vec::new();
        clap_mangen::Man::new(cmd).render(&mut raw)?;
        out.push((frontend.binary, gzip(&raw)?));
    }
    Ok(out)
}

fn gzip(input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(input)?;
    Ok(encoder.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_frontends_render_non_empty_man_pages() {
        // Smoke test — proves both clap Commands resolve and
        // clap_mangen accepts them. The shape of the rendered output
        // is asserted by per-frontend contract tests so this stays a
        // wiring check.
        for frontend in FRONTENDS {
            let cmd = (frontend.command)();
            let mut buffer: Vec<u8> = Vec::new();
            clap_mangen::Man::new(cmd).render(&mut buffer).unwrap();
            assert!(
                !buffer.is_empty(),
                "rendered man page for `{}` was empty",
                frontend.binary
            );
        }
    }

    #[test]
    fn rendered_pages_carry_binary_name_in_header() {
        for frontend in FRONTENDS {
            let cmd = (frontend.command)();
            let mut buffer: Vec<u8> = Vec::new();
            clap_mangen::Man::new(cmd).render(&mut buffer).unwrap();
            let text = String::from_utf8(buffer).unwrap();
            assert!(
                text.contains(frontend.binary),
                "rendered man page for `{}` did not include the binary name",
                frontend.binary,
            );
        }
    }

    #[test]
    fn out_dir_argument_writes_files() {
        let temp = tempfile::tempdir().unwrap();
        let args = Args {
            out_dir: Some(temp.path().to_path_buf()),
        };
        run(&args).unwrap();
        for frontend in FRONTENDS {
            let path = temp.path().join(format!("{}.1", frontend.binary));
            assert!(
                path.is_file(),
                "expected man page at {} after `xtask man --out-dir <tmp>`",
                path.display(),
            );
            let bytes = fs::read(&path).unwrap();
            assert!(!bytes.is_empty(), "{} was empty on disk", path.display());
        }
    }

    #[test]
    fn render_all_gzipped_produces_valid_gzip_streams() {
        use std::io::Read;

        use flate2::read::GzDecoder;

        let pairs = render_all_gzipped().unwrap();
        assert_eq!(
            pairs.len(),
            FRONTENDS.len(),
            "render_all_gzipped must emit one entry per registered front-end",
        );
        for (binary, gzipped) in pairs {
            assert!(
                gzipped.starts_with(&[0x1f, 0x8b]),
                "gzipped man page for `{binary}` missing the gzip magic header",
            );
            let mut decoder = GzDecoder::new(&gzipped[..]);
            let mut round_tripped = String::new();
            decoder.read_to_string(&mut round_tripped).unwrap();
            assert!(
                round_tripped.contains(binary),
                "round-tripped man page for `{binary}` lost the binary name",
            );
        }
    }
}
