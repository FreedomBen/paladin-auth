#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# minisign artifact-signing wrapper for the paladin-auth release pipeline.
#
# Per docs/DESIGN.md §11.6 ("Signatures") and docs/IMPLEMENTATION_PLAN_04_GTK.md
# Milestone 7 checklist entry "Sign .deb, .rpm, and AppImage with
# minisign per §11.6", this script wraps `minisign -S` with the
# release-pipeline conventions:
#
#   * The secret key is mounted from a CI secret at runtime via
#     MINISIGN_SECRET_KEY (a filesystem path the workflow writes the
#     secret to before invoking this script). The secret never lands
#     in the script source.
#   * The signing passphrase (if the secret key is encrypted) is
#     read from MINISIGN_PASSWORD via the `-W` no-prompt flow when
#     present; otherwise minisign falls back to its own /dev/tty
#     prompt. CI mounts both env vars; local dry-runs may set them
#     by hand.
#   * The trusted-comment string written into the .minisig payload
#     defaults to "<artifact-basename> signed by paladin-auth release
#     pipeline" but the release pipeline can override it via
#     MINISIGN_TRUSTED_COMMENT (typically used to embed the release
#     tag).
#   * Output lands alongside the artifact as `<artifact>.minisig`
#     (the minisign default). The release workflow uploads both
#     files to GitHub Releases together.
#
# The public key that downstream verifiers should pin lives at
# packaging/sign/minisign.pub. The release workflow uploads that
# file alongside every release so verifiers can pull the trusted
# key from the same GitHub Releases asset namespace as the artifact
# they are verifying.
#
# Inputs (env vars):
#   MINISIGN_SECRET_KEY        Required. Filesystem path to the
#                              minisign secret key file. CI mounts
#                              this from a repository secret; a
#                              local dry-run reads it from
#                              ~/.minisign/minisign.key (or any
#                              other writable path).
#   MINISIGN_PASSWORD          Optional. Passphrase that protects the
#                              secret key. When set, the script
#                              pipes it to minisign through stdin so
#                              the signing step runs non-interactively
#                              in CI. When unset, minisign prompts
#                              on /dev/tty.
#   MINISIGN_TRUSTED_COMMENT   Optional. Override for the trusted
#                              comment minisign writes into the
#                              .minisig payload. Defaults to
#                              "<artifact-basename> signed by paladin-auth
#                              release pipeline".
#
# Inputs (CLI):
#   $1   Required. Filesystem path to the artifact to sign (.deb,
#        .rpm, or .AppImage). The script writes the signature
#        alongside it as `$1.minisig` via minisign's default
#        output path.
#
# Outputs:
#   <artifact>.minisig   Detached minisign signature in the same
#                        directory as the input artifact.
#
# Dependencies (must be on $PATH):
#   minisign     The reference signer/verifier from
#                https://jedisct1.github.io/minisign/.
#
# Contract pinned by
#   crates/paladin-auth-gtk/tests/packaging_signing_script_logic.rs

set -euo pipefail

# Bail loudly if the caller forgot the artifact path. The release
# pipeline always passes it; a local invocation that omits it would
# otherwise produce a confusing minisign "stat: -m: no such file"
# failure several lines down.
: "${1:?usage: sign-artifact.sh <artifact-path>}"

# Bail loudly if MINISIGN_SECRET_KEY is unset. minisign itself would
# fall back to ~/.minisign/minisign.key which is the wrong default
# for a release pipeline — the CI-mounted secret must be the
# authoritative source.
: "${MINISIGN_SECRET_KEY:?MINISIGN_SECRET_KEY must point to the minisign secret key file}"

ARTIFACT="$1"

if [ ! -f "${ARTIFACT}" ]; then
  echo "sign-artifact.sh: artifact not found: ${ARTIFACT}" >&2
  exit 1
fi

# Default the trusted comment to something meaningful so the
# verifier output is readable. The release pipeline overrides it
# with the release-tag string.
ARTIFACT_BASENAME="$(basename "${ARTIFACT}")"
TRUSTED_COMMENT="${MINISIGN_TRUSTED_COMMENT:-${ARTIFACT_BASENAME} signed by paladin-auth release pipeline}"

# Pipe MINISIGN_PASSWORD through stdin when set so the signing
# step runs non-interactively in CI. The two-line input shape
# matches minisign's expected stdin format when invoked with -W
# (no-prompt): the passphrase, then a newline confirmation.
if [ -n "${MINISIGN_PASSWORD:-}" ]; then
  printf '%s\n' "${MINISIGN_PASSWORD}" \
    | minisign -S \
        -s "${MINISIGN_SECRET_KEY}" \
        -m "${ARTIFACT}" \
        -t "${TRUSTED_COMMENT}"
else
  minisign -S \
    -s "${MINISIGN_SECRET_KEY}" \
    -m "${ARTIFACT}" \
    -t "${TRUSTED_COMMENT}"
fi

# Post-condition: the .minisig file must exist next to the artifact.
# minisign prints its own diagnostic on failure but a missing output
# would otherwise let the release workflow upload an unsigned blob.
if [ ! -f "${ARTIFACT}.minisig" ]; then
  echo "sign-artifact.sh: expected ${ARTIFACT}.minisig to exist after signing" >&2
  exit 1
fi

echo "Signed: ${ARTIFACT} -> ${ARTIFACT}.minisig"
echo "Verify with: minisign -V -p packaging/sign/minisign.pub -m ${ARTIFACT}"
