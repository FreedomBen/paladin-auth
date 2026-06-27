#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Install the system packages and Rust toolchain needed to build, test, and
# package the paladin-auth workspace on Fedora.
#
# Mirrors the three `dnf install` blocks in .github/workflows/ci.yml so a
# local checkout can reproduce the CI environment (clippy / test / packaging
# dry-run). The GTK 4.16 + libadwaita 1.6 floor required by
# crates/paladin-auth-gtk/Cargo.toml's `v4_16` / `v1_6` feature gates is satisfied
# by Fedora 42+.
#
# Usage:
#   scripts/install-fedora-deps.sh              # install everything
#   scripts/install-fedora-deps.sh --no-gtk     # skip GTK + Xvfb
#   scripts/install-fedora-deps.sh --no-pkg     # skip packaging dry-run tools
#   scripts/install-fedora-deps.sh --no-rustup  # skip rustup bootstrap
#   scripts/install-fedora-deps.sh --help
#
# Re-run is safe: dnf install is idempotent and rustup is only bootstrapped
# when the `rustup` binary is missing.

set -euo pipefail

WITH_GTK=1
WITH_PACKAGING=1
WITH_RUSTUP=1

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "${arg}" in
        --no-gtk) WITH_GTK=0 ;;
        --no-pkg|--no-packaging) WITH_PACKAGING=0 ;;
        --no-rustup) WITH_RUSTUP=0 ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "error: unknown argument: ${arg}" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ ! -r /etc/os-release ]; then
    echo "error: /etc/os-release not found; this script is Fedora-only." >&2
    exit 1
fi
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
    fedora:*|*:*fedora*) ;;
    *)
        echo "error: this script targets Fedora (got ID=${ID:-unknown})." >&2
        exit 1
        ;;
esac

# Fedora 42+ ships GTK 4.16 / libadwaita 1.6; older releases fail the
# `v4_16` / `v1_6` feature gates in crates/paladin-auth-gtk/Cargo.toml.
if [ "${WITH_GTK}" -eq 1 ] && [ -n "${VERSION_ID:-}" ]; then
    major="${VERSION_ID%%.*}"
    if [ "${major}" -lt 42 ] 2>/dev/null; then
        echo "warning: Fedora ${VERSION_ID} ships GTK/libadwaita older than the" >&2
        echo "         4.16 / 1.6 floor paladin-auth-gtk needs. paladin-auth-gtk will" >&2
        echo "         fail to build until you upgrade to Fedora 42+." >&2
    fi
fi

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    if ! command -v sudo >/dev/null 2>&1; then
        echo "error: sudo is required when not running as root." >&2
        exit 1
    fi
    SUDO="sudo"
fi

# Core build deps — required for every workspace member.
# (Matches `clippy` job in .github/workflows/ci.yml.)
PKGS_CORE=(
    rustup
    gcc
    pkg-config
    openssl-devel
    git
    ca-certificates
)

# paladin-auth-gtk system bindings + Xvfb for the GTK smoke test.
# (Matches `test` job additions in .github/workflows/ci.yml.)
PKGS_GTK=(
    gtk4-devel
    libadwaita-devel
    xorg-x11-server-Xvfb
)

# Packaging dry-run tools — only needed if you build .deb / .rpm locally.
# (Matches the packaging dry-run job in .github/workflows/ci.yml. `nfpm`
# itself is fetched from upstream GitHub releases — see the workflow.)
PKGS_PACKAGING=(
    dpkg
    cpio
    rpm-build
    desktop-file-utils
    appstream
    curl
    tar
)

PKGS=("${PKGS_CORE[@]}")
if [ "${WITH_GTK}" -eq 1 ]; then
    PKGS+=("${PKGS_GTK[@]}")
fi
if [ "${WITH_PACKAGING}" -eq 1 ]; then
    PKGS+=("${PKGS_PACKAGING[@]}")
fi

echo "==> Installing Fedora packages with dnf:"
printf '      %s\n' "${PKGS[@]}"
${SUDO} dnf install -y --setopt=install_weak_deps=False "${PKGS[@]}"

# Bootstrap the rust toolchain pinned by rust-toolchain.toml (channel
# 1.94.1, profile minimal, rustfmt + clippy). The toolchain file is read
# automatically by every subsequent `cargo` / `rustup` invocation, so we
# only need rustup itself on PATH.
if [ "${WITH_RUSTUP}" -eq 1 ]; then
    if ! command -v rustup >/dev/null 2>&1; then
        echo "==> rustup not on PATH; running rustup-init."
        rustup-init -y --no-modify-path --default-toolchain none --profile minimal
        case ":${PATH}:" in
            *":${HOME}/.cargo/bin:"*) ;;
            *)
                echo
                echo "Note: add \"${HOME}/.cargo/bin\" to your PATH, e.g.:"
                echo "    echo 'export PATH=\"\${HOME}/.cargo/bin:\${PATH}\"' >> ~/.bashrc"
                ;;
        esac
    else
        echo "==> rustup already installed; skipping bootstrap."
    fi

    REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    if [ -f "${REPO_ROOT}/rust-toolchain.toml" ]; then
        echo "==> Pre-fetching pinned toolchain from rust-toolchain.toml."
        (cd "${REPO_ROOT}" && rustup show >/dev/null)
    fi
fi

echo
echo "Done. Next steps:"
echo "  cd $(cd "$(dirname "$0")/.." && pwd)"
echo "  cargo build --workspace"
echo "  cargo test  --workspace --all-targets"
