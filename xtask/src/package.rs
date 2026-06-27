// SPDX-License-Identifier: AGPL-3.0-or-later

//! `cargo xtask package --frontend <name> --format rpm|deb` —
//! orchestrate the release build and the `nfpm` invocation.
//!
//! The actual `nfpm` run happens inside the official
//! `docker.io/goreleaser/nfpm` container under rootless podman, so no
//! host nfpm install is required. The container reads
//! `packaging/<format>/<frontend>.yaml`, substitutes
//! `${PALADIN_AUTH_VERSION}` from the env this process exports, and writes
//! the resulting `.rpm` / `.deb` to `target/dist/`.

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use clap::ValueEnum;

use crate::man;

/// Front-end packages xtask can produce. Names match the workspace
/// member binaries and the `packaging/<format>/<name>.yaml` filenames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
// Variants intentionally share the `PaladinAuth` prefix so they mirror the
// `paladin-auth` / `paladin-auth-tui` / `paladin-auth-gtk` package and binary
// names (see `package_name` / `cargo_package`).
#[allow(clippy::enum_variant_names)]
pub(crate) enum Frontend {
    PaladinAuth,
    PaladinAuthTui,
    PaladinAuthGtk,
}

impl Frontend {
    fn package_name(self) -> &'static str {
        match self {
            Self::PaladinAuth => "paladin-auth",
            Self::PaladinAuthTui => "paladin-auth-tui",
            Self::PaladinAuthGtk => "paladin-auth-gtk",
        }
    }

    /// Cargo workspace member name passed to `cargo build -p`. The
    /// CLI's published name is `paladin-auth` but its workspace member is
    /// `paladin-auth-cli`; the binary name and the package name diverge.
    fn cargo_package(self) -> &'static str {
        match self {
            Self::PaladinAuth => "paladin-auth-cli",
            Self::PaladinAuthTui => "paladin-auth-tui",
            Self::PaladinAuthGtk => "paladin-auth-gtk",
        }
    }

    fn ships_man_page(self) -> bool {
        matches!(self, Self::PaladinAuth | Self::PaladinAuthTui)
    }
}

/// Output formats xtask can produce. `rpm` and `deb` are both wired
/// up; `flatpak` and `appimage` join as their pipelines land per
/// `docs/IMPLEMENTATION_PLAN_04_GTK.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub(crate) enum Format {
    Rpm,
    Deb,
}

impl Format {
    fn nfpm_packager(self) -> &'static str {
        match self {
            Self::Rpm => "rpm",
            Self::Deb => "deb",
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Which front-end to package.
    #[arg(long)]
    frontend: Frontend,

    /// Which artifact format to produce.
    #[arg(long, default_value = "rpm")]
    format: Format,

    /// Version string interpolated into `${PALADIN_AUTH_VERSION}` inside
    /// the nfpm manifest. Defaults to the workspace
    /// `[workspace.package].version` so a developer build inherits
    /// the same string the release pipeline would inject.
    #[arg(long, value_name = "VERSION")]
    version: Option<String>,

    /// Override the directory `nfpm` writes the artifact to. Defaults
    /// to `target/dist/` at the workspace root, matching the CI
    /// `packaging-dry-run` job's `--target` path.
    #[arg(long, value_name = "DIR")]
    output_dir: Option<PathBuf>,

    /// Skip the `cargo build --release` step. Useful when the
    /// release binary is already built in `target/release/`.
    #[arg(long)]
    skip_build: bool,

    /// Container image used to run `nfpm`. Defaults to the upstream
    /// `docker.io/goreleaser/nfpm:latest`; override only when
    /// reproducibility audits pin a specific digest.
    #[arg(long, value_name = "IMAGE", default_value = DEFAULT_NFPM_IMAGE)]
    nfpm_image: String,

    /// Container runtime binary. Defaults to `podman` per
    /// `CLAUDE.md` ("always build and run with rootless podman
    /// unless explicitly told otherwise").
    #[arg(long, value_name = "BIN", default_value = "podman")]
    container_runtime: String,
}

const DEFAULT_NFPM_IMAGE: &str = "docker.io/goreleaser/nfpm:latest";
const WORKSPACE_VERSION: &str = "0.0.1";

pub(crate) fn run(args: &Args) -> Result<(), Box<dyn Error>> {
    let workspace = workspace_root()?;
    let version = args
        .version
        .clone()
        .unwrap_or_else(|| WORKSPACE_VERSION.to_string());
    let output_dir = args
        .output_dir
        .clone()
        .unwrap_or_else(|| workspace.join("target").join("dist"));
    fs::create_dir_all(&output_dir)?;

    if !args.skip_build {
        build_release(&workspace, args.frontend)?;
    }

    if args.frontend.ships_man_page() {
        stage_man_pages(&workspace)?;
    }

    let manifest = manifest_path(&workspace, args.frontend, args.format);
    if !manifest.is_file() {
        return Err(format!(
            "nfpm manifest not found at {} — packaging/{}/{}.yaml must exist",
            manifest.display(),
            args.format.nfpm_packager(),
            args.frontend.package_name(),
        )
        .into());
    }

    run_nfpm_in_container(args, &workspace, &output_dir, &manifest, &version)
}

fn build_release(workspace: &Path, frontend: Frontend) -> Result<(), Box<dyn Error>> {
    let status = ProcessCommand::new(cargo_bin())
        .arg("build")
        .arg("--release")
        .arg("--locked")
        .arg("-p")
        .arg(frontend.cargo_package())
        .current_dir(workspace)
        .status()?;
    if !status.success() {
        return Err(format!(
            "cargo build --release --locked -p {} failed (exit {:?})",
            frontend.cargo_package(),
            status.code(),
        )
        .into());
    }
    Ok(())
}

fn stage_man_pages(workspace: &Path) -> Result<(), Box<dyn Error>> {
    let man_dir = workspace.join("target").join("man");
    fs::create_dir_all(&man_dir)?;
    for (binary, gzipped) in man::render_all_gzipped()? {
        let path = man_dir.join(format!("{binary}.1.gz"));
        fs::write(&path, gzipped)?;
    }
    Ok(())
}

fn manifest_path(workspace: &Path, frontend: Frontend, format: Format) -> PathBuf {
    workspace
        .join("packaging")
        .join(format.nfpm_packager())
        .join(format!("{}.yaml", frontend.package_name()))
}

fn run_nfpm_in_container(
    args: &Args,
    workspace: &Path,
    output_dir: &Path,
    manifest: &Path,
    version: &str,
) -> Result<(), Box<dyn Error>> {
    let manifest_in_container = path_relative_to(manifest, workspace)?;
    let output_in_container = path_relative_to(output_dir, workspace)?;

    let workspace_mount = mount_arg(workspace, "/workspace");

    let mut cmd = ProcessCommand::new(&args.container_runtime);
    cmd.arg("run").arg("--rm");
    cmd.arg("-v").arg(workspace_mount);
    cmd.arg("-w").arg("/workspace");
    cmd.arg("-e").arg(format!("PALADIN_AUTH_VERSION={version}"));
    cmd.arg(&args.nfpm_image);
    cmd.arg("package");
    cmd.arg("-f")
        .arg(path_string(&manifest_in_container, "/workspace")?);
    cmd.arg("-p").arg(args.format.nfpm_packager());
    cmd.arg("-t")
        .arg(path_string(&output_in_container, "/workspace")?);

    let status = cmd.status().map_err(|err| {
        format!(
            "failed to spawn `{}`: {err} — install rootless podman or pass --container-runtime",
            args.container_runtime,
        )
    })?;
    if !status.success() {
        return Err(format!(
            "{} {} package failed (exit {:?})",
            args.container_runtime,
            args.nfpm_image,
            status.code()
        )
        .into());
    }
    println!(
        "produced {} artifact(s) in {}",
        args.format.nfpm_packager(),
        output_dir.display()
    );
    Ok(())
}

fn cargo_bin() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let parent = manifest_dir
        .parent()
        .ok_or("xtask CARGO_MANIFEST_DIR has no parent — workspace root unresolved")?;
    Ok(parent.to_path_buf())
}

fn path_relative_to(path: &Path, base: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let canonical_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let canonical_base = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
    let stripped = canonical_path.strip_prefix(&canonical_base).map_err(|_| {
        format!(
            "path {} is outside the workspace root {}; container mount cannot reach it",
            path.display(),
            base.display(),
        )
    })?;
    Ok(stripped.to_path_buf())
}

fn path_string(relative: &Path, mount_prefix: &str) -> Result<String, Box<dyn Error>> {
    let joined = Path::new(mount_prefix).join(relative);
    joined
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("non-UTF8 container path {}", joined.display()).into())
}

fn mount_arg(host: &Path, container: &str) -> OsString {
    let host = host.canonicalize().unwrap_or_else(|_| host.to_path_buf());
    let mut spec = OsString::from(host);
    spec.push(":");
    spec.push(container);
    spec.push(":z");
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontend_round_trip_value_enum() {
        assert_eq!(Frontend::PaladinAuth.package_name(), "paladin-auth");
        assert_eq!(Frontend::PaladinAuthTui.package_name(), "paladin-auth-tui");
        assert_eq!(Frontend::PaladinAuthGtk.package_name(), "paladin-auth-gtk");
        assert_eq!(Frontend::PaladinAuth.cargo_package(), "paladin-auth-cli");
        assert_eq!(Frontend::PaladinAuthTui.cargo_package(), "paladin-auth-tui");
        assert_eq!(Frontend::PaladinAuthGtk.cargo_package(), "paladin-auth-gtk");
    }

    #[test]
    fn only_cli_and_tui_ship_man_pages() {
        assert!(Frontend::PaladinAuth.ships_man_page());
        assert!(Frontend::PaladinAuthTui.ships_man_page());
        assert!(!Frontend::PaladinAuthGtk.ships_man_page());
    }

    #[test]
    fn manifest_path_matches_packaging_layout() {
        let workspace = PathBuf::from("/workspace-root");
        let path = manifest_path(&workspace, Frontend::PaladinAuth, Format::Rpm);
        assert_eq!(
            path,
            PathBuf::from("/workspace-root/packaging/rpm/paladin-auth.yaml")
        );
        let path = manifest_path(&workspace, Frontend::PaladinAuthGtk, Format::Rpm);
        assert_eq!(
            path,
            PathBuf::from("/workspace-root/packaging/rpm/paladin-auth-gtk.yaml")
        );
        let path = manifest_path(&workspace, Frontend::PaladinAuth, Format::Deb);
        assert_eq!(
            path,
            PathBuf::from("/workspace-root/packaging/deb/paladin-auth.yaml")
        );
        let path = manifest_path(&workspace, Frontend::PaladinAuthTui, Format::Deb);
        assert_eq!(
            path,
            PathBuf::from("/workspace-root/packaging/deb/paladin-auth-tui.yaml")
        );
        let path = manifest_path(&workspace, Frontend::PaladinAuthGtk, Format::Deb);
        assert_eq!(
            path,
            PathBuf::from("/workspace-root/packaging/deb/paladin-auth-gtk.yaml")
        );
    }

    #[test]
    fn format_nfpm_packager_matches_directory_name() {
        assert_eq!(Format::Rpm.nfpm_packager(), "rpm");
        assert_eq!(Format::Deb.nfpm_packager(), "deb");
    }
}
