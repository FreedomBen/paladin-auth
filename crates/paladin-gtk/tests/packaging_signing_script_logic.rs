// SPDX-License-Identifier: AGPL-3.0-or-later

//! `minisign` artifact-signing script contract tests for the release pipeline.
//!
//! Per `docs/DESIGN.md` §11.6 ("Signatures") and
//! `docs/IMPLEMENTATION_PLAN_04_GTK.md` Milestone 7 checklist entry
//! "Sign `.deb`, `.rpm`, and `AppImage` with `minisign` per §11.6;
//! publish the public key + signature alongside each artifact on
//! `GitHub` Releases":
//!
//! * Lives at `packaging/sign/sign-artifact.sh`.
//! * Has the executable bit set (so a checkout-and-run path is
//!   `./packaging/sign/sign-artifact.sh <artifact>`, mirroring the
//!   `chmod +x` convention `build-appimage.sh` and the other CI
//!   scripts follow).
//! * Sets the strict shell mode `set -euo pipefail` so a missing
//!   dependency, an undefined variable, or a failed `minisign`
//!   step aborts the release immediately rather than producing a
//!   half-signed batch.
//! * Reads the signing secret-key path from `MINISIGN_SECRET_KEY`
//!   so the release pipeline can mount the key from a CI secret
//!   without it ever landing in the script source.
//! * Invokes `minisign -S` (the sign subcommand) with the
//!   `-s ${MINISIGN_SECRET_KEY}` and `-m <artifact>` flags. Output
//!   lands alongside the artifact as `<artifact>.minisig` per the
//!   minisign default — pinning that default explicitly so a future
//!   `-x` rename has to land an updated test too.
//! * Reads the optional pre-signature trusted comment from
//!   `MINISIGN_TRUSTED_COMMENT` (defaulting to the artifact filename
//!   + the release tag) so the verifier output is meaningful instead
//!     of `signature from secret key file`.
//! * Documents the public key publication location
//!   (`packaging/sign/minisign.pub` — the file shipped alongside the
//!   GitHub Releases artifacts so downstream verifiers can pin it).
//!
//! The script itself never holds the secret key inline — that is a
//! release-pipeline secret mounted at runtime. These tests pin the
//! script's contract on disk so a future regression that removes a
//! flag, drops `--locked` parity, or swaps `minisign` for a different
//! signer fails CI immediately.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

/// Path to the signing script, relative to the workspace root.
const SIGN_SCRIPT_RELPATH: &str = "packaging/sign/sign-artifact.sh";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> PathBuf {
    crate_root()
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| panic!("crate_root has no grandparent: {}", crate_root().display()))
        .to_path_buf()
}

fn sign_script_path() -> PathBuf {
    workspace_root().join(SIGN_SCRIPT_RELPATH)
}

fn read_sign_script() -> String {
    let path = sign_script_path();
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

/// Join shell continuation lines (`\\\n`) so a multi-line `minisign`
/// invocation becomes one searchable string. Mirrors the helper in
/// `tests/packaging_appimage_build_script_logic.rs`.
fn join_continuations(script: &str) -> String {
    let mut out = String::with_capacity(script.len());
    let lines: Vec<&str> = script.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(without_slash) = line.strip_suffix('\\') {
            out.push_str(without_slash);
            out.push(' ');
            i += 1;
            continue;
        }
        out.push_str(line);
        out.push('\n');
        i += 1;
    }
    out
}

// --- script-existence + shebang + permissions -------------------------------

#[test]
fn sign_script_exists_at_expected_path() {
    let path = sign_script_path();
    assert!(
        path.is_file(),
        "expected minisign signing script at {} — Milestone 7 packaging checklist requires \
         `packaging/sign/sign-artifact.sh`",
        path.display(),
    );
}

#[test]
fn sign_script_is_executable() {
    let path = sign_script_path();
    let metadata =
        fs::metadata(&path).unwrap_or_else(|err| panic!("stat {}: {err}", path.display()));
    let mode = metadata.permissions().mode();
    assert!(
        mode & 0o100 != 0,
        "minisign signing script at {} must have the executable bit set (current mode: \
         {:o})",
        path.display(),
        mode & 0o777,
    );
}

#[test]
fn sign_script_starts_with_bash_shebang() {
    let script = read_sign_script();
    let first_line = script.lines().next().unwrap_or("");
    assert!(
        first_line == "#!/usr/bin/env bash" || first_line == "#!/bin/bash",
        "minisign signing script must start with a bash shebang (`#!/usr/bin/env bash` or \
         `#!/bin/bash`) so the strict-mode flags below resolve against bash semantics; got: \
         {first_line:?}",
    );
}

#[test]
fn sign_script_carries_spdx_license_header() {
    let script = read_sign_script();
    let header_found = script
        .lines()
        .take(5)
        .any(|line| line.contains("SPDX-License-Identifier: AGPL-3.0-or-later"));
    assert!(
        header_found,
        "minisign signing script must declare `SPDX-License-Identifier: AGPL-3.0-or-later` \
         within its first 5 lines (the same SPDX convention every other workspace source \
         file follows)",
    );
}

#[test]
fn sign_script_enables_strict_shell_mode() {
    let script = read_sign_script();
    let landed = script.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == "set -euo pipefail"
            || trimmed == "set -eu -o pipefail"
            || trimmed == "set -e -u -o pipefail"
    });
    assert!(
        landed,
        "minisign signing script must enable strict shell mode via `set -euo pipefail` so a \
         missing dependency, an undefined variable, or a failed `minisign -S` step aborts \
         the release immediately; the script body did not contain that directive",
    );
}

// --- env-var contract -------------------------------------------------------

#[test]
fn sign_script_reads_minisign_secret_key_from_environment() {
    // The signing secret key never lives in the script source — it
    // is mounted from a CI secret at release time. Pin that the
    // script reads `MINISIGN_SECRET_KEY` (or the parameter-expansion
    // guard form `${MINISIGN_SECRET_KEY:?msg}`) so a future edit
    // that hard-codes a path or trades it for a non-secret env var
    // fails this test immediately.
    let script = read_sign_script();
    let landed =
        script.contains("${MINISIGN_SECRET_KEY}") || script.contains("${MINISIGN_SECRET_KEY:?");
    assert!(
        landed,
        "minisign signing script must read MINISIGN_SECRET_KEY from the environment so the \
         release pipeline can mount the secret without it landing in the script source; \
         the script body referenced neither `${{MINISIGN_SECRET_KEY}}` nor \
         `${{MINISIGN_SECRET_KEY:?...}}`",
    );
}

#[test]
fn sign_script_reads_trusted_comment_from_environment_with_a_default() {
    // `minisign -S` writes a trusted comment into the .minisig
    // payload that the verifier prints on success. Default it to
    // something meaningful — empty / generic strings make audit
    // logs useless. The script must consult
    // `MINISIGN_TRUSTED_COMMENT` so the release pipeline can inject
    // the artifact + tag string from outside.
    let script = read_sign_script();
    assert!(
        script.contains("MINISIGN_TRUSTED_COMMENT"),
        "minisign signing script must reference MINISIGN_TRUSTED_COMMENT so the release \
         pipeline can override the trusted comment minisign writes into the .minisig \
         payload; the script body did not contain that literal",
    );
}

#[test]
fn sign_script_takes_artifact_path_as_first_positional() {
    // The script signs one artifact at a time; the release pipeline
    // loops over `.deb` / `.rpm` / `.AppImage` outputs and invokes
    // the script per artifact. Pin that `$1` is the artifact path so
    // a future refactor that swaps the calling convention requires
    // an explicit test update.
    let script = read_sign_script();
    let landed = script.contains("${1}")
        || script.contains("${1:?")
        || script.contains("$1")
        || script.contains("\"$1\"");
    assert!(
        landed,
        "minisign signing script must take the artifact path as the first positional \
         argument (`${{1}}` or `${{1:?msg}}`); the script body did not reference $1",
    );
}

// --- minisign invocation ----------------------------------------------------

/// Filter `joined` down to the non-comment logical lines that
/// invoke `minisign -S`. The continuation-joining helper collapses
/// each `minisign -S \` plus its `\\\n`-continued flag lines into
/// one logical line, so a `contains("-s ")` test on the result
/// covers a multi-line invocation faithfully.
fn minisign_sign_invocations(joined: &str) -> Vec<&str> {
    joined
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with('#') && trimmed.contains("minisign -S")
        })
        .collect()
}

#[test]
fn sign_script_invokes_minisign_sign_subcommand() {
    let script = read_sign_script();
    let joined = join_continuations(&script);
    // `minisign -S` is the sign subcommand. The script must call it
    // — substituting it for `signify`, `gpg`, or `openssl` would
    // break the verifier convention DESIGN §11.6 ships against.
    let invocations = minisign_sign_invocations(&joined);
    assert!(
        !invocations.is_empty(),
        "minisign signing script must invoke `minisign -S` (the sign subcommand); the \
         joined script body did not contain that literal outside of comment lines",
    );
}

#[test]
fn sign_script_passes_secret_key_flag_to_minisign() {
    let script = read_sign_script();
    let joined = join_continuations(&script);
    // `-s <path>` is the minisign flag for the secret-key path.
    // Pin that the script passes the env-mounted key path through
    // that flag; a future refactor that switches to stdin-piped
    // keys (or omits the flag entirely and relies on
    // `~/.minisign/minisign.key`) would silently desync from the
    // release pipeline's CI-secret mount.
    let invocations = minisign_sign_invocations(&joined);
    assert!(
        !invocations.is_empty(),
        "minisign signing script must invoke `minisign -S`; the joined script body \
         contained none",
    );
    for invocation in &invocations {
        assert!(
            invocation.contains("-s "),
            "minisign signing script invocation must pass `-s <key>` to `minisign -S`; got: \
             {invocation:?}",
        );
    }
}

#[test]
fn sign_script_passes_artifact_path_via_message_flag() {
    let script = read_sign_script();
    let joined = join_continuations(&script);
    // `-m <path>` is the minisign flag for the message-to-sign
    // path. Pin that the script forwards the artifact path through
    // it rather than (e.g.) feeding the artifact via stdin.
    let invocations = minisign_sign_invocations(&joined);
    assert!(
        !invocations.is_empty(),
        "minisign signing script must invoke `minisign -S`; the joined script body \
         contained none",
    );
    for invocation in &invocations {
        assert!(
            invocation.contains("-m "),
            "minisign signing script invocation must pass `-m <artifact>` to `minisign -S`; \
             got: {invocation:?}",
        );
    }
}

// --- public-key publication -------------------------------------------------

#[test]
fn sign_script_documents_public_key_location() {
    // The release pipeline publishes the public key alongside each
    // signed artifact so downstream verifiers can pin it. The
    // script must mention `packaging/sign/minisign.pub` (or the
    // basename `minisign.pub`) so a future move requires updating
    // both the file and the contract in lockstep.
    let script = read_sign_script();
    let landed = script.contains("minisign.pub");
    assert!(
        landed,
        "minisign signing script must reference the published public-key filename \
         `minisign.pub` so downstream verifiers know where to pin the key; the script \
         body did not contain that literal",
    );
}

#[test]
fn sign_script_emits_minisig_filename_alongside_artifact() {
    // minisign defaults to writing `<artifact>.minisig` next to the
    // input; the script must reference that suffix somewhere
    // (output rename, post-condition check, or doc comment) so a
    // future change that overrides the default output path with
    // `-x` requires a matching update here.
    let script = read_sign_script();
    assert!(
        script.contains(".minisig"),
        "minisign signing script must reference the `.minisig` output suffix (either \
         implicitly via the default minisign behavior or explicitly via `-x`); the script \
         body did not contain that literal",
    );
}

// --- helper self-tests ------------------------------------------------------

#[test]
fn join_continuations_concatenates_backslash_terminated_lines() {
    let script = "\
minisign -S \\
  -s key \\
  -m artifact \\
  -t comment
";
    let joined = join_continuations(script);
    assert!(joined.contains("minisign -S"));
    assert!(joined.contains("-s key"));
    assert!(joined.contains("-m artifact"));
    assert!(joined.contains("-t comment"));
}

#[test]
fn join_continuations_preserves_non_continuation_lines() {
    let script = "\
set -euo pipefail
echo signed
";
    let joined = join_continuations(script);
    assert!(joined.contains("set -euo pipefail"));
    assert!(joined.contains("echo signed"));
}

#[test]
fn minisign_sign_invocations_returns_logical_invocations_only() {
    let joined = "\
# minisign -S in a comment must be ignored
minisign -S -s key -m artifact
other line
";
    let invocations = minisign_sign_invocations(joined);
    assert_eq!(invocations.len(), 1);
    assert!(invocations[0].contains("-s key"));
}
