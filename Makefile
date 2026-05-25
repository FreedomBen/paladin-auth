# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Paladin Makefile.
#
# Build, test, lint, and install entry points for the Cargo workspace
# (paladin-core, paladin-cli, paladin-tui, paladin-gtk). The actual build
# rules live in Cargo; this file just standardizes the common commands so
# they match `DESIGN.md` §10 / `.github/workflows/ci.yml`.
#
# Override the build profile per-invocation:
#     make PROFILE=release build-all
#     make PROFILE=release test-tui
# Override the install prefix:
#     make PREFIX=/opt/paladin install

PREFIX  ?= /usr/local
BINDIR  ?= ${PREFIX}/bin
DESTDIR ?=

CARGO   ?= cargo
PROFILE ?= debug

# Packaging defaults — overridable per-invocation, e.g.
#     make PALADIN_VERSION=0.2.0-rc1 rpm
#     make CONTAINER_RUNTIME=docker rpm-paladin
#     make PALADIN_VERSION=0.2.0-rc1 deb
# `PALADIN_VERSION` is interpolated into the `version:` field of the
# nfpm manifests; defaults to a developer-build sentinel matching the
# CI `packaging-dry-run` job in `.github/workflows/ci.yml`.
PALADIN_VERSION   ?= 0.0.1-dev
NFPM_IMAGE        ?= docker.io/goreleaser/nfpm:latest
CONTAINER_RUNTIME ?= podman
# Output directory for both .rpm and .deb artifacts. `RPM_OUTPUT_DIR`
# stays as the canonical name for backward compatibility with existing
# callers; both formats land under the same path.
RPM_OUTPUT_DIR    ?= target/dist
PKG_OUTPUT_DIR    ?= ${RPM_OUTPUT_DIR}

ifeq (${PROFILE},release)
    PROFILE_FLAG := --release
else ifeq (${PROFILE},debug)
    PROFILE_FLAG :=
else
    $(error PROFILE must be 'debug' or 'release', got '${PROFILE}')
endif

# Cargo package names (the values under `[package] name = ...`).
CORE_PKG := paladin-core
CLI_PKG  := paladin-cli
TUI_PKG  := paladin-tui
GTK_PKG  := paladin-gtk

# Installed binary names (the values under `[[bin]] name = ...`).
# paladin-cli ships as `paladin`; paladin-tui and paladin-gtk match their
# crate names.
CLI_BIN := paladin
TUI_BIN := paladin-tui
GTK_BIN := paladin-gtk

.DEFAULT_GOAL := help

.PHONY: help \
        build build-all build-cli build-tui build-gtk release \
        test test-all test-core test-cli test-tui test-gtk \
        fmt fmt-check clippy check \
        clean install \
        man rpm rpm-paladin rpm-paladin-tui rpm-paladin-gtk \
        deb deb-paladin deb-paladin-tui deb-paladin-gtk

help: ## Show this help
	@awk 'BEGIN { \
		FS = ":.*?## "; \
		printf "Paladin -- Rust OTP authenticator (CLI + TUI + GTK)\n\n"; \
		printf "Usage: make [VAR=value ...] <target>\n\nTargets:\n"; \
	} /^[a-zA-Z_][a-zA-Z0-9_-]*:.*?## / { \
		printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2; \
	}' ${MAKEFILE_LIST}
	@printf "\nVariables (current value):\n"
	@printf "  PROFILE=%s   (debug | release)\n" "${PROFILE}"
	@printf "  PREFIX=%s\n"                       "${PREFIX}"
	@printf "  BINDIR=%s\n"                       "${BINDIR}"
	@printf "  DESTDIR=%s\n"                      "${DESTDIR}"
	@printf "  CARGO=%s\n"                        "${CARGO}"
	@printf "  PALADIN_VERSION=%s\n"              "${PALADIN_VERSION}"
	@printf "  NFPM_IMAGE=%s\n"                   "${NFPM_IMAGE}"
	@printf "  CONTAINER_RUNTIME=%s\n"            "${CONTAINER_RUNTIME}"
	@printf "  RPM_OUTPUT_DIR=%s\n"               "${RPM_OUTPUT_DIR}"
	@printf "  PKG_OUTPUT_DIR=%s\n"               "${PKG_OUTPUT_DIR}"

# --- Build -------------------------------------------------------------------

build: build-all ## Build every workspace crate (alias of build-all)

build-all: ## Build the full workspace: core lib + CLI + TUI + GTK
	${CARGO} build --workspace ${PROFILE_FLAG}

build-cli: ## Build only paladin-cli (produces the `paladin` binary)
	${CARGO} build -p ${CLI_PKG} ${PROFILE_FLAG}

build-tui: ## Build only paladin-tui
	${CARGO} build -p ${TUI_PKG} ${PROFILE_FLAG}

build-gtk: ## Build only paladin-gtk (requires gtk4>=4.16, libadwaita>=1.6)
	${CARGO} build -p ${GTK_PKG} ${PROFILE_FLAG}

release: ## Build the full workspace with the release profile
	${CARGO} build --workspace --release

# --- Test --------------------------------------------------------------------

test: test-all ## Run every test in the workspace (alias of test-all)

test-all: ## Run `cargo test --workspace --all-targets` (matches CI)
	${CARGO} test --workspace --all-targets

test-core: ## Run paladin-core tests (the shared library)
	${CARGO} test -p ${CORE_PKG} --all-targets

test-cli: ## Run paladin-cli tests
	${CARGO} test -p ${CLI_PKG} --all-targets

test-tui: ## Run paladin-tui tests
	${CARGO} test -p ${TUI_PKG} --all-targets

# paladin-gtk's smoke test needs an X server; wrap with `xvfb-run` in
# headless environments (e.g. `xvfb-run make test-gtk`).
test-gtk: ## Run paladin-gtk tests (needs X11; use xvfb-run if headless)
	${CARGO} test -p ${GTK_PKG} --all-targets

# --- Lint & format -----------------------------------------------------------

fmt: ## Format every crate with rustfmt
	${CARGO} fmt --all

fmt-check: ## Verify formatting without writing changes (matches CI)
	${CARGO} fmt --all -- --check

clippy: ## Run clippy across the workspace, denying warnings (matches CI)
	${CARGO} clippy --workspace --all-targets -- -D warnings

check: fmt-check clippy test-all ## Run the local CI gate (fmt + clippy + tests)

# --- Misc --------------------------------------------------------------------

clean: ## Remove cargo build artifacts
	${CARGO} clean

install: ## Install release binaries to ${DESTDIR}${BINDIR} (forces release)
	${CARGO} build --workspace --release
	install -d "${DESTDIR}${BINDIR}"
	install -m 0755 "target/release/${CLI_BIN}" "${DESTDIR}${BINDIR}/${CLI_BIN}"
	install -m 0755 "target/release/${TUI_BIN}" "${DESTDIR}${BINDIR}/${TUI_BIN}"
	install -m 0755 "target/release/${GTK_BIN}" "${DESTDIR}${BINDIR}/${GTK_BIN}"

# --- Packaging (.rpm / .deb) -------------------------------------------------
#
# All packaging targets delegate to `cargo xtask package`, which builds the
# release binary, renders + gzips the clap-derived man page (CLI / TUI only),
# and then runs `nfpm` inside the official `docker.io/goreleaser/nfpm`
# container under rootless podman per `docs/DESIGN.md` §11.3.
#
# Requirements: rootless podman (or set CONTAINER_RUNTIME=docker), network
# access to pull NFPM_IMAGE the first time, and write access to PKG_OUTPUT_DIR
# (defaults to RPM_OUTPUT_DIR for backward compatibility). The man-page-only
# `man` target needs neither podman nor network.

man: ## Render clap-derived man pages into target/man/ (no packaging step)
	${CARGO} run -p xtask --quiet -- man

rpm: rpm-paladin rpm-paladin-tui rpm-paladin-gtk ## Build .rpm for every front-end (CLI + TUI + GTK)

rpm-paladin: ## Build the paladin (CLI) .rpm into ${PKG_OUTPUT_DIR}
	${CARGO} run -p xtask --quiet -- package \
		--frontend paladin --format rpm \
		--version "${PALADIN_VERSION}" \
		--output-dir "${PKG_OUTPUT_DIR}" \
		--nfpm-image "${NFPM_IMAGE}" \
		--container-runtime "${CONTAINER_RUNTIME}"

rpm-paladin-tui: ## Build the paladin-tui .rpm into ${PKG_OUTPUT_DIR}
	${CARGO} run -p xtask --quiet -- package \
		--frontend paladin-tui --format rpm \
		--version "${PALADIN_VERSION}" \
		--output-dir "${PKG_OUTPUT_DIR}" \
		--nfpm-image "${NFPM_IMAGE}" \
		--container-runtime "${CONTAINER_RUNTIME}"

rpm-paladin-gtk: ## Build the paladin-gtk .rpm into ${PKG_OUTPUT_DIR}
	${CARGO} run -p xtask --quiet -- package \
		--frontend paladin-gtk --format rpm \
		--version "${PALADIN_VERSION}" \
		--output-dir "${PKG_OUTPUT_DIR}" \
		--nfpm-image "${NFPM_IMAGE}" \
		--container-runtime "${CONTAINER_RUNTIME}"

deb: deb-paladin deb-paladin-tui deb-paladin-gtk ## Build .deb for every front-end (CLI + TUI + GTK)

deb-paladin: ## Build the paladin (CLI) .deb into ${PKG_OUTPUT_DIR}
	${CARGO} run -p xtask --quiet -- package \
		--frontend paladin --format deb \
		--version "${PALADIN_VERSION}" \
		--output-dir "${PKG_OUTPUT_DIR}" \
		--nfpm-image "${NFPM_IMAGE}" \
		--container-runtime "${CONTAINER_RUNTIME}"

deb-paladin-tui: ## Build the paladin-tui .deb into ${PKG_OUTPUT_DIR}
	${CARGO} run -p xtask --quiet -- package \
		--frontend paladin-tui --format deb \
		--version "${PALADIN_VERSION}" \
		--output-dir "${PKG_OUTPUT_DIR}" \
		--nfpm-image "${NFPM_IMAGE}" \
		--container-runtime "${CONTAINER_RUNTIME}"

deb-paladin-gtk: ## Build the paladin-gtk .deb into ${PKG_OUTPUT_DIR}
	${CARGO} run -p xtask --quiet -- package \
		--frontend paladin-gtk --format deb \
		--version "${PALADIN_VERSION}" \
		--output-dir "${PKG_OUTPUT_DIR}" \
		--nfpm-image "${NFPM_IMAGE}" \
		--container-runtime "${CONTAINER_RUNTIME}"
