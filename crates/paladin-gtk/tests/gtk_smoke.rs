// SPDX-License-Identifier: AGPL-3.0-or-later

//! `xvfb-run` headless smoke test for `paladin-gtk`.
//!
//! Per `IMPLEMENTATION_PLAN_04_GTK.md` §"Smoke test" / §"Tests", this
//! suite drives the GTK binary through a virtual X server so that
//! `adw::init()` and the relm4 bootstrap are exercised without
//! requiring a real desktop session. This file holds the bullets
//! enumerated under §"Smoke test (`tests/gtk_smoke.rs`)".
//!
//! Local developers without `xvfb-run` installed see each test skip
//! with a printed instruction line; CI (which installs `xvfb` per
//! the §"Smoke test" entry of the Milestone 7 checklist) runs them
//! for real. Tests that cannot run still return `Ok(())` so they do
//! not mask other regressions.
//!
//! The binary path is resolved at compile time via
//! `CARGO_BIN_EXE_paladin-gtk`, which Cargo provides to integration
//! tests of crates that declare a `[[bin]]` of that name.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use secrecy::SecretString;

/// Path to the built `paladin-gtk` binary. Cargo populates this at
/// compile time per the §"Crate layout" `[[bin]]` declaration.
const PALADIN_GTK_BIN: &str = env!("CARGO_BIN_EXE_paladin-gtk");

/// Wall-clock ceiling for an `xvfb-run paladin-gtk` invocation that
/// is expected to exit. Generous to absorb cold-cache startup on CI.
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Returns `true` when `xvfb-run` is on `$PATH` and reports a usable
/// `--help`. CI installs it; many local dev environments do not.
fn xvfb_run_available() -> bool {
    Command::new("xvfb-run")
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run `xvfb-run -a <bin> <args...>` with a fresh display, capture
/// stdout / stderr, and wait up to [`SMOKE_TIMEOUT`] for the child
/// to exit. Returns the exit-status output bundle.
fn run_under_xvfb(args: &[&str]) -> std::process::Output {
    assert!(
        Path::new(PALADIN_GTK_BIN).exists(),
        "CARGO_BIN_EXE_paladin-gtk does not point at an existing file: {PALADIN_GTK_BIN}",
    );

    let mut child = Command::new("xvfb-run")
        .arg("-a")
        .arg(PALADIN_GTK_BIN)
        .args(args)
        // Force a clean environment slice — no carried-over DISPLAY
        // from the host session, no XDG_RUNTIME_DIR from a logged-in
        // user that might steer GIO / libadwaita off the synthetic
        // server.
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn xvfb-run");

    let deadline = std::time::Instant::now() + SMOKE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "xvfb-run {PALADIN_GTK_BIN} did not exit within \
                         {SMOKE_TIMEOUT:?}; the smoke-test binary must \
                         terminate on its own.",
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("waiting on xvfb-run failed: {e}"),
        }
    }

    child.wait_with_output().expect("xvfb-run output read")
}

/// Plan bullet: "`xvfb-run` launches `paladin-gtk` and the process
/// exits". This is the lowest rung — it proves that the binary
/// links against the GTK / libadwaita / relm4 stack, initializes
/// libadwaita under a synthetic display, mounts the
/// `AppModel` relm4 component, and returns from the main loop
/// without the process getting stuck or panicking.
///
/// The hidden `--exit-after-startup` flag (see `cli.rs`) enqueues
/// `AppMsg::Quit` on the first frame so the relm4 main loop tears
/// down cleanly without a real desktop session to dismiss the
/// window. `clap`'s `--version` / `--help` short-circuit would
/// bypass `adw::init()` and `RelmApp::run` and so would not validate
/// the foundation, so they are intentionally not used here.
/// Subsequent bullets exercise the same path with a prepared vault.
#[test]
fn xvfb_run_launches_paladin_gtk_and_process_exits() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let output = run_under_xvfb(&["--exit-after-startup"]);
    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk exited with status {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Set up a `0700` tempdir containing an empty plaintext vault at
/// `<tempdir>/vault.bin`. Returns the tempdir handle (kept alive by
/// the caller so the directory is not unlinked mid-test) and the
/// vault path. The `(Vault, Store)` pair is dropped before returning
/// so the file handle is closed before `paladin-gtk` re-opens it.
fn prepare_empty_plaintext_vault() -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().expect("create tempdir for prepared vault");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let vault_path = tempdir.path().join("vault.bin");
    {
        let (vault, store) =
            paladin_core::Store::create(&vault_path, paladin_core::VaultInit::Plaintext)
                .expect("create plaintext vault on disk");
        vault.save(&store).expect("persist plaintext vault to disk");
    }
    (tempdir, vault_path)
}

/// Plan bullet: "App opens a prepared plaintext vault."
///
/// Pre-creates a plaintext vault at a temporary path via
/// `paladin_core::Store::create`, then launches `paladin-gtk` with
/// `--vault <path> --exit-after-startup` under `xvfb-run`. The binary
/// runs the §"Vault interaction" startup sequence — resolve path,
/// `paladin_core::inspect`, and `paladin_core::Store::open` with
/// `VaultLock::Plaintext` directly on the main loop — before the
/// hidden flag quits the main loop. Under `--exit-after-startup`,
/// `AppModel` emits a stable marker line to stdout naming the
/// resolved [`crate::app::state::AppState`] variant and the resolved
/// vault path; this test asserts on that marker so the foundation
/// the next bullet (`AccountListComponent` rendering) builds on is
/// observed rather than merely inferred from a clean exit.
#[test]
fn app_opens_prepared_plaintext_vault() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let (_tempdir, vault_path) = prepare_empty_plaintext_vault();

    let path_str = vault_path
        .to_str()
        .expect("tempfile produced a non-UTF-8 vault path");
    let output = run_under_xvfb(&["--vault", path_str, "--exit-after-startup"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk --vault {path_str} --exit-after-startup exited with status {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout,
        stderr,
    );

    // The marker format is fixed by `app::model::startup_state_marker`
    // and is documented next to that helper so test + implementation
    // share a single string contract.
    let expected = format!("paladin-gtk: startup_state=Unlocked path={path_str}");
    assert!(
        stdout.contains(&expected),
        "expected stdout to contain `{expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Plan bullet: "`AccountListComponent` renders the prepared accounts."
///
/// Pre-creates a plaintext vault containing two TOTP accounts and
/// one HOTP account, then launches `paladin-gtk` with
/// `--vault <path> --exit-after-startup` under `xvfb-run`. The
/// `AccountListComponent` binds rows from `paladin_core::Vault::summaries()`
/// via the `account_list::row_models_from_vault` projection; under
/// `--exit-after-startup`, the bound rows are emitted as a stable
/// stdout marker (`account_list::format_rendered_marker`). This test
/// asserts on that marker so the render side of the row factory is
/// observed rather than merely inferred from the `Unlocked` startup
/// state line.
#[test]
fn app_renders_prepared_accounts() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let tempdir = tempfile::tempdir().expect("create tempdir for prepared vault");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let vault_path = tempdir.path().join("vault.bin");

    {
        let (mut vault, store) =
            paladin_core::Store::create(&vault_path, paladin_core::VaultInit::Plaintext)
                .expect("create plaintext vault on disk");
        // Two TOTP + one HOTP so the marker exercises both kinds and
        // the issuer-collapse rule.
        add_validated_account(&mut vault, &store, Some("GitHub"), "ben", false);
        add_validated_account(&mut vault, &store, Some("GitLab"), "alice", false);
        add_validated_account(&mut vault, &store, None, "solo", true);
        vault.save(&store).expect("persist plaintext vault to disk");
    }

    let path_str = vault_path
        .to_str()
        .expect("tempfile produced a non-UTF-8 vault path");
    let output = run_under_xvfb(&["--vault", path_str, "--exit-after-startup"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk --vault {path_str} --exit-after-startup exited with status {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout,
        stderr,
    );

    // The marker format is fixed by
    // `account_list::format_rendered_marker`; the smoke test, the
    // pure-logic test in `tests/account_list_logic.rs`, and the
    // widget binding all use the same helper so the assertions
    // stay aligned.
    let expected = "paladin-gtk: account_list_rows=GitHub:ben|GitLab:alice|solo";
    assert!(
        stdout.contains(expected),
        "expected stdout to contain `{expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );

    // The widget-states marker fingerprints per-row affordance state
    // (currently the copy button's sensitive flag), driven by
    // `account_list::format_widget_states_marker` against the same
    // `hidden_row_display` projection the row factory binds. TOTP
    // rows render `copy:on`; the HOTP `solo` row renders `copy:off`
    // because its hidden state disables copy per
    // `IMPLEMENTATION_PLAN_04_GTK.md` §"Component tree" >
    // `AccountRowComponent`.
    let widget_states_expected = "paladin-gtk: account_list_widget_states=copy:on|copy:on|copy:off";
    assert!(
        stdout.contains(widget_states_expected),
        "expected stdout to contain `{widget_states_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Plan bullet: "`StartupErrorComponent` renders the
/// non-mutating error surface for the `StartupError` branch."
///
/// Pre-creates a corrupt vault file at a temporary path — bytes
/// that do not match the §4.4 header magic, exactly the fixture
/// used by `tests/startup_probes.rs::run_startup_probes_routes_corrupted_file_to_startup_error`.
/// `paladin_core::inspect` therefore routes to
/// `InvalidHeader`, which the `AppModel` startup sequence funnels
/// into `AppState::StartupError` tagged
/// `StartupErrorSource::Inspect`. Under `--exit-after-startup`,
/// `AppModel` emits two stdout markers from the `StartupError`
/// branch — the existing `startup_state=StartupError ...` line
/// (which is produced before the widget mount) and the new
/// `startup_error_body=...` line (which is only emitted after the
/// `StartupErrorComponent` is launched and bound). Asserting on
/// both proves that the widget actually mounted with the typed
/// error body rather than the binary having merely classified the
/// failure.
#[test]
fn app_renders_startup_error_for_corrupt_vault() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let tempdir = tempfile::tempdir().expect("create tempdir for corrupt vault");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let vault_path = tempdir.path().join("vault.bin");
    // Non-magic prefix → `paladin_core::inspect` returns
    // `PaladinError::InvalidHeader`, which routes to
    // `StartupErrorSource::Inspect` per §"Vault interaction".
    std::fs::write(&vault_path, b"not a paladin vault").expect("write corrupted vault");

    let path_str = vault_path
        .to_str()
        .expect("tempfile produced a non-UTF-8 vault path");
    let output = run_under_xvfb(&["--vault", path_str, "--exit-after-startup"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk --vault {path_str} --exit-after-startup exited with status {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout,
        stderr,
    );

    // The `startup_state` marker is emitted before any per-state
    // widget mount, so it proves only that `run_startup_probes`
    // reached the `StartupError` branch.
    let state_expected = format!("paladin-gtk: startup_state=StartupError path={path_str}");
    assert!(
        stdout.contains(&state_expected),
        "expected stdout to contain `{state_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );

    // The `startup_error_body` marker is emitted exclusively from
    // the `StartupError` branch immediately before
    // `StartupErrorComponent` is launched; its presence proves the
    // widget mounted with the typed error body. The body text comes
    // from `paladin_core::PaladinError::InvalidHeader`'s `Display`
    // impl (no `format_unsafe_permissions` projection for this
    // variant), which is the literal "invalid vault header".
    let body_expected = "paladin-gtk: startup_error_body=invalid vault header";
    assert!(
        stdout.contains(body_expected),
        "expected stdout to contain `{body_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );
}

/// Plan bullet: "`InitDialog` renders for the `Missing` branch
/// (no vault file at the resolved path)."
///
/// Routes the §"Vault interaction" startup sequence through
/// `paladin_core::inspect` → `VaultStatus::Missing` by pointing
/// `--vault` at a `0700`-mode tempdir entry that does not exist on
/// disk. `AppModel` then enters `AppState::Missing { path }` and
/// mounts `InitDialogComponent`. Under `--exit-after-startup`, the
/// model emits two stdout markers from the `Missing` branch — the
/// existing `startup_state=Missing ...` line (produced before any
/// per-state widget is mounted) and the new `init_dialog_path=...`
/// line (emitted exclusively from the `Missing` branch immediately
/// before `InitDialogComponent` is launched). Asserting on both
/// proves the widget actually mounted with the resolved vault path,
/// rather than the binary having merely classified the file as
/// missing.
#[test]
fn app_renders_init_dialog_for_missing_vault() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let tempdir = tempfile::tempdir().expect("create tempdir for missing vault");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    // Path is *inside* the 0700 tempdir but the file is deliberately
    // never created — `paladin_core::inspect` returns
    // `VaultStatus::Missing`, which `AppModel` maps to
    // `AppState::Missing { path }` per §"Vault interaction".
    let vault_path = tempdir.path().join("missing.bin");
    assert!(
        !vault_path.exists(),
        "tempdir entry must be absent before launching paladin-gtk: {}",
        vault_path.display()
    );

    let path_str = vault_path
        .to_str()
        .expect("tempfile produced a non-UTF-8 vault path");
    let output = run_under_xvfb(&["--vault", path_str, "--exit-after-startup"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk --vault {path_str} --exit-after-startup exited with status {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout,
        stderr,
    );

    let state_expected = format!("paladin-gtk: startup_state=Missing path={path_str}");
    assert!(
        stdout.contains(&state_expected),
        "expected stdout to contain `{state_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );

    // The `init_dialog_path` marker is emitted exclusively from the
    // `Missing` branch immediately before `InitDialogComponent` is
    // launched; its presence proves the widget mounted with the
    // resolved vault path. The marker format is fixed by
    // `init_dialog::format_init_dialog_marker` and pinned by
    // `tests/init_dialog_logic.rs::format_init_dialog_marker_renders_resolved_path`.
    let init_expected = format!("paladin-gtk: init_dialog_path={path_str}");
    assert!(
        stdout.contains(&init_expected),
        "expected stdout to contain `{init_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );

    // The `Missing` branch never enters the unlocked or
    // startup-error branches; assert their per-branch markers are
    // absent so an accidental fall-through to a non-rendering state
    // is caught here.
    assert!(
        !stdout.contains("paladin-gtk: account_list_rows="),
        "expected the Missing branch to skip the account list marker\n--- stdout ---\n{stdout}",
    );
    assert!(
        !stdout.contains("paladin-gtk: account_list_widget_states="),
        "expected the Missing branch to skip the widget-states marker\n--- stdout ---\n{stdout}",
    );
    assert!(
        !stdout.contains("paladin-gtk: startup_error_body="),
        "expected the Missing branch to skip the startup-error marker\n--- stdout ---\n{stdout}",
    );
}

/// Light Argon2 params for the encrypted-vault smoke fixture. Keeps
/// the KDF fast under CI (the §4.4 defaults at `m=64 MiB, t=3` are
/// designed for production and would balloon the suite); the same
/// shape is used by the paladin-tui test fixtures.
fn light_argon2_params() -> paladin_core::Argon2Params {
    paladin_core::Argon2Params {
        m_kib: 8192,
        t: 1,
        p: 1,
    }
}

/// Set up a `0700` tempdir containing an empty encrypted vault at
/// `<tempdir>/vault.bin`. Returns the tempdir handle (kept alive by
/// the caller so the directory is not unlinked mid-test) and the
/// vault path. The `(Vault, Store)` pair is dropped before returning
/// so the file handle is closed before `paladin-gtk` re-opens it.
fn prepare_empty_encrypted_vault(passphrase: &str) -> (tempfile::TempDir, PathBuf) {
    let tempdir = tempfile::tempdir().expect("create tempdir for encrypted vault");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tempdir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod tempdir to 0700");
    }
    let vault_path = tempdir.path().join("vault.bin");
    {
        let pp = SecretString::from(passphrase.to_string());
        let opts = paladin_core::EncryptionOptions::with_params(pp, light_argon2_params())
            .expect("encryption options accept light params");
        let (vault, store) =
            paladin_core::Store::create(&vault_path, paladin_core::VaultInit::Encrypted(opts))
                .expect("create encrypted vault on disk");
        vault.save(&store).expect("persist encrypted vault to disk");
    }
    (tempdir, vault_path)
}

/// Plan bullet: "`UnlockDialogComponent` renders the passphrase-
/// entry surface for the `Locked` branch."
///
/// Routes the §"Vault interaction" startup sequence through
/// `paladin_core::inspect` → `VaultStatus::Encrypted` by pre-
/// creating an encrypted vault at a temporary path. `AppModel`
/// then enters `AppState::Locked { path }` and mounts
/// `UnlockDialogComponent`. Under `--exit-after-startup`, the
/// model emits two stdout markers from the `Locked` branch — the
/// existing `startup_state=Locked ...` line (produced before any
/// per-state widget is mounted) and the new `unlock_dialog_path=...`
/// line (emitted exclusively from the `Locked` branch immediately
/// before `UnlockDialogComponent` is launched). Asserting on both
/// proves the widget actually mounted with the resolved vault path,
/// rather than the binary having merely classified the file as
/// encrypted.
#[test]
fn app_renders_unlock_dialog_for_encrypted_vault() {
    if !xvfb_run_available() {
        eprintln!(
            "skipping: `xvfb-run` is not on PATH. CI installs the xvfb \
             package; install it locally to exercise this smoke test."
        );
        return;
    }

    let (_tempdir, vault_path) = prepare_empty_encrypted_vault("hunter2");

    let path_str = vault_path
        .to_str()
        .expect("tempfile produced a non-UTF-8 vault path");
    let output = run_under_xvfb(&["--vault", path_str, "--exit-after-startup"]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "xvfb-run paladin-gtk --vault {path_str} --exit-after-startup exited with status {:?}\n\
         --- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        stdout,
        stderr,
    );

    // The `startup_state` marker is emitted before any per-state
    // widget mount, so it proves only that `run_startup_probes`
    // reached the `Locked` branch.
    let state_expected = format!("paladin-gtk: startup_state=Locked path={path_str}");
    assert!(
        stdout.contains(&state_expected),
        "expected stdout to contain `{state_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );

    // The `unlock_dialog_path` marker is emitted exclusively from
    // the `Locked` branch immediately before `UnlockDialogComponent`
    // is launched; its presence proves the widget mounted with the
    // resolved vault path. The marker format is fixed by
    // `unlock_dialog::format_unlock_dialog_marker` and pinned by
    // `tests/unlock_dialog_logic.rs::format_unlock_dialog_marker_renders_resolved_path`.
    let unlock_expected = format!("paladin-gtk: unlock_dialog_path={path_str}");
    assert!(
        stdout.contains(&unlock_expected),
        "expected stdout to contain `{unlock_expected}`\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
    );

    // The `Locked` branch never enters the unlocked, startup-error,
    // or init-dialog branches; assert their per-branch markers are
    // absent so an accidental fall-through to a non-rendering state
    // is caught here.
    assert!(
        !stdout.contains("paladin-gtk: account_list_rows="),
        "expected the Locked branch to skip the account list marker\n--- stdout ---\n{stdout}",
    );
    assert!(
        !stdout.contains("paladin-gtk: account_list_widget_states="),
        "expected the Locked branch to skip the widget-states marker\n--- stdout ---\n{stdout}",
    );
    assert!(
        !stdout.contains("paladin-gtk: startup_error_body="),
        "expected the Locked branch to skip the startup-error marker\n--- stdout ---\n{stdout}",
    );
    assert!(
        !stdout.contains("paladin-gtk: init_dialog_path="),
        "expected the Locked branch to skip the init-dialog marker\n--- stdout ---\n{stdout}",
    );
}

/// Add a validated TOTP or HOTP account to `vault` and persist to
/// `store`. The secret is a fixed RFC 6238 base32 fixture; the same
/// shape is used by the pure-logic fixtures in
/// `tests/account_list_logic.rs` so the smoke test and the
/// projection test stay aligned.
fn add_validated_account(
    vault: &mut paladin_core::Vault,
    store: &paladin_core::Store,
    issuer: Option<&str>,
    label: &str,
    hotp: bool,
) {
    let kind = if hotp {
        paladin_core::AccountKindInput::Hotp
    } else {
        paladin_core::AccountKindInput::Totp
    };
    let input = paladin_core::AccountInput {
        label: label.to_string(),
        issuer: issuer.map(str::to_string),
        secret: SecretString::from("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: paladin_core::Algorithm::Sha1,
        digits: 6,
        kind,
        period_secs: None,
        counter: if hotp { Some(0) } else { None },
        icon_hint: paladin_core::IconHintInput::Default,
    };
    let validated =
        paladin_core::validate_manual(input, SystemTime::now()).expect("valid manual input");
    vault.add(validated.account);
    vault.save(store).expect("commit added account");
}
