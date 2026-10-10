//! Self-update module for RCH binaries.
//!
//! Provides functionality to:
//! - Check for updates from GitHub releases
//! - Download and verify release artifacts
//! - Coordinate with daemon for safe updates
//! - Support rollback to previous versions
//! - Update fleet of workers

mod check;
mod download;
mod install;
mod lock;
mod types;
pub(crate) mod verify;

pub use check::{check_for_updates, spawn_update_check_if_needed};
pub use download::download_release;
pub use install::{install_update, rollback};
pub use types::{Channel, UpdateCheck};

use crate::commands;
use crate::ui::OutputContext;
use anyhow::{Context, Result};
use types::UpdateError;

/// Main entry point for the update command.
#[allow(clippy::too_many_arguments)]
pub async fn run_update(
    ctx: &OutputContext,
    check_only: bool,
    version: Option<String>,
    channel: Channel,
    fleet: bool,
    do_rollback: bool,
    verify_only: bool,
    dry_run: bool,
    yes: bool,
    skip_verify: bool,
    no_restart: bool,
    drain_timeout: u64,
    show_changelog: bool,
) -> Result<()> {
    if do_rollback {
        return rollback(ctx, dry_run, None)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e));
    }

    if verify_only {
        return verify_installation(ctx).await;
    }

    // An explicit `rch update` (including --check) always asks GitHub.
    let update_info = check_for_updates(channel, version.clone(), false).await?;

    if check_only {
        display_update_check(ctx, &update_info, show_changelog);
        return Ok(());
    }

    if !update_info.update_available {
        if !ctx.is_json() {
            println!("Already up to date ({})", update_info.current_version);
        } else {
            println!(
                "{}",
                serde_json::json!({
                    "update_available": false,
                    "current_version": update_info.current_version.to_string(),
                })
            );
        }
        return Ok(());
    }

    // Show what we're about to do
    if !ctx.is_json() && !yes {
        println!(
            "Update available: {} -> {}",
            update_info.current_version, update_info.latest_version
        );
        if show_changelog && let Some(ref notes) = update_info.release_notes {
            println!("\nRelease notes:\n{}", notes);
        }
        if !dry_run {
            println!("\nProceed with update? [y/N]");
            // In a real implementation, we'd read user input here
            // For now, require --yes flag
            if !yes {
                println!("Use --yes to confirm update");
                return Ok(());
            }
        }
    }

    if dry_run {
        println!("Dry run: would update to {}", update_info.latest_version);
        return Ok(());
    }

    // Download and verify
    let download = download_release(ctx, &update_info, skip_verify).await?;

    let asset = download
        .archive_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    // A checksum obtained alongside an archive proves integrity, not who
    // published it. Missing signature assets or a missing cosign executable
    // must not silently downgrade an ordinary update to checksum-only.
    // This gate precedes the install lock, daemon drain, replacement and fleet
    // deployment, so an unauthenticated download cannot mutate installation.
    require_update_verification(
        &asset,
        download.checksum_verified,
        download.signature_verified,
        skip_verify,
    )?;
    if skip_verify && (!download.checksum_verified || download.signature_verified != Some(true)) {
        tracing::warn!(
            asset = %asset,
            checksum_verified = download.checksum_verified,
            signature_verified = ?download.signature_verified,
            "Installing an unverified update by explicit --skip-verify request"
        );
        if !ctx.is_json() {
            println!(
                "Warning: installing {} without complete checksum/signature verification (--skip-verify)",
                asset
            );
        }
    }

    // Install
    let result = install_update(ctx, &download, !no_restart, drain_timeout).await?;

    if !ctx.is_json() {
        println!(
            "Successfully updated to {} (backup: {})",
            update_info.latest_version,
            result.backup_path.display()
        );
    }

    // Fleet update if requested
    if fleet {
        update_fleet(ctx, &update_info, dry_run).await?;
    }

    Ok(())
}

/// Authorize installation from completed cryptographic verification results,
/// never from the presence of signature metadata alone. Both supported
/// verifiers (pinned minisign or identity-bound Sigstore) report `Some(true)`.
/// An explicit operator override may permit absent verification, but a known
/// failed signature remains fatal. The download path already refuses invalid
/// signatures and mismatched checksums before it can construct these results.
fn require_update_verification(
    asset: &str,
    checksum_verified: bool,
    signature_verified: Option<bool>,
    skip_verify: bool,
) -> Result<(), UpdateError> {
    if signature_verified == Some(false) {
        return Err(UpdateError::SignatureVerificationFailed(format!(
            "refusing to install {asset}: its signature verification failed"
        )));
    }
    if !skip_verify {
        if !checksum_verified {
            return Err(UpdateError::ChecksumMissing {
                asset: asset.to_owned(),
            });
        }
        if signature_verified != Some(true) {
            return Err(UpdateError::SignatureVerificationFailed(format!(
                "refusing to install {asset} without an authenticated signature; \
                 a matching checksum alone does not prove release authenticity. \
                 Use a release with a valid pinned-key .minisig or a verified \
                 Sigstore bundle. --skip-verify is an explicit insecure override"
            )));
        }
    }
    Ok(())
}

/// Display update check results.
fn display_update_check(ctx: &OutputContext, info: &UpdateCheck, show_changelog: bool) {
    if ctx.is_json() {
        println!("{}", serde_json::to_string_pretty(info).unwrap());
        return;
    }

    if info.update_available {
        println!(
            "Update available: {} -> {}",
            info.current_version, info.latest_version
        );
        println!("Release URL: {}", info.release_url);

        if show_changelog {
            // Prefer changelog_diff (aggregated changes from all intermediate releases)
            // Fall back to release_notes (just the latest release) if diff isn't available
            if let Some(ref diff) = info.changelog_diff {
                println!("\nChanges since {}:\n{}", info.current_version, diff);
            } else if let Some(ref notes) = info.release_notes {
                println!("\nRelease notes:\n{}", notes);
            }
        }

        println!("\nRun 'rch update' to update.");
    } else {
        println!("Already up to date ({})", info.current_version);
    }
}

/// Check installed executables, not release signatures or file authenticity.
async fn verify_installation(ctx: &OutputContext) -> Result<()> {
    if !ctx.is_json() {
        println!("Checking installed binary versions...");
    }
    let report = inspect_installation(
        &std::env::current_exe()?,
        env!("CARGO_PKG_VERSION"),
        std::time::Duration::from_secs(10),
    )
    .await?;
    if ctx.is_json() {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for component in report["components"].as_array().into_iter().flatten() {
            println!(
                "{}: {}",
                component["name"].as_str().unwrap_or_default(),
                component["version"].as_str().unwrap_or_default()
            );
        }
        for name in report["absent_optional_components"]
            .as_array()
            .into_iter()
            .flatten()
        {
            println!(
                "{}: not installed (optional)",
                name.as_str().unwrap_or_default()
            );
        }
        println!("Installed binary version checks passed (not a checksum or signature check).");
    }
    Ok(())
}

/// Never search PATH for companion binaries: that could validate an unrelated
/// installation while the siblings actually used by this client are broken.
/// Client-only installations are supported; absent companions are disclosed,
/// but an unreadable, broken-link, or nonregular companion is not "absent".
async fn inspect_installation(
    executable: &std::path::Path,
    expected_version: &str,
    timeout: std::time::Duration,
) -> Result<serde_json::Value> {
    anyhow::ensure!(
        executable.is_absolute(),
        "installed client path must be absolute"
    );
    let directory = executable
        .parent()
        .context("installed client has no parent directory")?;
    let mut components = Vec::new();
    let mut absent = Vec::new();
    for name in ["rch", "rchd", "rch-wkr"] {
        let path = if name == "rch" {
            executable.to_owned()
        } else {
            directory.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
        };
        match std::fs::symlink_metadata(&path) {
            Err(error) if name != "rch" && error.kind() == std::io::ErrorKind::NotFound => {
                absent.push(name);
                continue;
            }
            result => {
                result.with_context(|| {
                    format!("cannot inspect installed {name}: {}", path.display())
                })?;
            }
        }
        anyhow::ensure!(
            std::fs::metadata(&path)
                .with_context(|| format!("cannot resolve installed {name}: {}", path.display()))?
                .is_file(),
            "installed {name} is not a regular executable file: {}",
            path.display()
        );
        let version = probe_installed_version(&path, name, expected_version, timeout).await?;
        components.push(serde_json::json!({"name": name, "path": path, "version": version}));
    }
    Ok(serde_json::json!({
        "verified": true,
        "verification_scope": "installed_binary_versions",
        "cryptographic_verification": false,
        "components": components,
        "absent_optional_components": absent,
    }))
}

/// A corrupt executable must not block the async runtime, consume unbounded
/// output memory, or claim a successful verification on a failed --version.
async fn probe_installed_version(
    path: &std::path::Path,
    name: &str,
    expected: &str,
    timeout: std::time::Duration,
) -> Result<String> {
    use crate::transfer::read_bounded_output_stream;
    use std::process::Stdio;

    let mut child = tokio::process::Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("cannot execute installed {name}: {}", path.display()))?;
    let stdout = child.stdout.take().context("version probe lacks stdout")?;
    let stderr = child.stderr.take().context("version probe lacks stderr")?;
    let captured = tokio::time::timeout(timeout, async {
        tokio::try_join!(
            read_bounded_output_stream(stdout, 64 * 1024),
            read_bounded_output_stream(stderr, 64 * 1024),
            child.wait(),
        )
    })
    .await;
    let (stdout, stderr, status) = match captured {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            let _ = child.start_kill();
            return Err(error).with_context(|| format!("installed {name} version probe failed"));
        }
        Err(_) => {
            let _ = child.start_kill();
            anyhow::bail!("installed {name} version probe timed out after {timeout:?}");
        }
    };
    anyhow::ensure!(
        status.success(),
        "installed {name} --version failed ({status}): {}",
        String::from_utf8_lossy(&stderr).trim()
    );
    anyhow::ensure!(
        stderr.is_empty(),
        "installed {name} --version produced diagnostics: {}",
        String::from_utf8_lossy(&stderr).trim()
    );
    let output = std::str::from_utf8(&stdout)
        .context("version output was not UTF-8")?
        .trim();
    let mut fields = output.split_whitespace();
    let reported_name = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or_default();
    anyhow::ensure!(
        !output.chars().any(char::is_control)
            && reported_name.strip_suffix(".exe").unwrap_or(reported_name) == name
            && version == expected,
        "installed {name} did not report the expected version {expected}: {output:?}"
    );
    Ok(version.to_owned())
}

/// Update fleet of workers.
async fn update_fleet(ctx: &OutputContext, _info: &UpdateCheck, dry_run: bool) -> Result<()> {
    if !ctx.is_json() {
        println!("Updating fleet...");
    }

    if dry_run {
        if !ctx.is_json() {
            println!("Dry run: would update all configured workers");
        }
        commands::workers_deploy_binary(None, true, false, true, ctx).await?;
        return Ok(());
    }

    // Deploy rch-wkr to all configured workers (version-aware, skips if already up-to-date).
    commands::workers_deploy_binary(None, true, false, false, ctx).await?;

    if !ctx.is_json() {
        println!("Fleet update complete.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::set_test_config_dir_override;
    use crate::ui::{OutputConfig, OutputMode};
    use types::Version;

    #[test]
    fn update_verification_rejects_checksum_only_installation() {
        // Covers missing .minisig/.sigstore.json assets, and a Sigstore-only
        // release on a host without cosign. All leave signature_verified=None
        // even when an attacker supplied a matching recomputed checksum.
        let error = require_update_verification("rch.tar.gz", true, None, false).unwrap_err();
        assert!(matches!(
            error,
            UpdateError::SignatureVerificationFailed(ref reason)
                if reason.contains("without an authenticated signature")
                    && reason.contains("rch.tar.gz")
        ));
    }

    #[test]
    fn update_verification_requires_both_checksum_and_signature() {
        assert!(require_update_verification("rch.tar.gz", true, Some(true), false).is_ok());
        assert!(matches!(
            require_update_verification("rch.tar.gz", false, Some(true), false),
            Err(UpdateError::ChecksumMissing { asset }) if asset == "rch.tar.gz"
        ));
    }

    #[test]
    fn update_verification_requires_explicit_override_for_absent_proof() {
        for checksum in [false, true] {
            assert!(require_update_verification("rch.zip", checksum, None, false).is_err());
            assert!(require_update_verification("rch.zip", checksum, None, true).is_ok());
        }
    }

    #[test]
    fn update_verification_never_permits_a_known_failed_signature() {
        for checksum in [false, true] {
            for skip_verify in [false, true] {
                assert!(matches!(
                    require_update_verification("rch.zip", checksum, Some(false), skip_verify),
                    Err(UpdateError::SignatureVerificationFailed(_))
                ));
            }
        }
    }

    #[test]
    fn test_channel_default() {
        assert_eq!(Channel::default(), Channel::Stable);
    }

    #[test]
    fn test_channel_variants() {
        // Test all channel variants exist
        let stable = Channel::Stable;
        let beta = Channel::Beta;
        let nightly = Channel::Nightly;

        assert_ne!(stable, beta);
        assert_ne!(beta, nightly);
        assert_ne!(stable, nightly);
    }

    fn create_test_output_context(json: bool) -> OutputContext {
        let config = OutputConfig {
            force_mode: Some(if json {
                OutputMode::Json
            } else {
                OutputMode::Plain
            }),
            json,
            ..Default::default()
        };
        OutputContext::new(config)
    }

    fn create_test_update_check(update_available: bool) -> UpdateCheck {
        UpdateCheck {
            current_version: Version::parse("1.0.0").unwrap(),
            latest_version: if update_available {
                Version::parse("2.0.0").unwrap()
            } else {
                Version::parse("1.0.0").unwrap()
            },
            update_available,
            release_url: "https://github.com/test/releases/v2.0.0".to_string(),
            release_notes: Some("Test release notes".to_string()),
            changelog_diff: None,
            assets: vec![],
        }
    }

    #[test]
    fn test_update_check_creation_no_update() {
        let check = create_test_update_check(false);
        assert!(!check.update_available);
        assert_eq!(check.current_version, check.latest_version);
    }

    #[test]
    fn test_update_check_creation_with_update() {
        let check = create_test_update_check(true);
        assert!(check.update_available);
        assert!(check.latest_version > check.current_version);
    }

    #[test]
    fn test_update_check_has_release_notes() {
        let check = create_test_update_check(true);
        assert!(check.release_notes.is_some());
        assert!(check.release_notes.as_ref().unwrap().contains("Test"));
    }

    #[test]
    fn test_update_check_release_url() {
        let check = create_test_update_check(true);
        assert!(!check.release_url.is_empty());
        assert!(check.release_url.contains("github"));
    }

    #[test]
    fn test_display_update_check_json_mode() {
        let ctx = create_test_output_context(true);
        let info = create_test_update_check(true);

        // This function prints to stdout - just verify it doesn't panic
        display_update_check(&ctx, &info, false);
    }

    #[test]
    fn test_display_update_check_no_update() {
        let ctx = create_test_output_context(false);
        let info = create_test_update_check(false);

        // Verify it doesn't panic
        display_update_check(&ctx, &info, false);
    }

    #[test]
    fn test_display_update_check_with_update() {
        let ctx = create_test_output_context(false);
        let info = create_test_update_check(true);

        // Verify it doesn't panic
        display_update_check(&ctx, &info, false);
    }

    #[test]
    fn test_display_update_check_with_changelog() {
        let ctx = create_test_output_context(false);
        let info = create_test_update_check(true);

        // Verify it doesn't panic with changelog display
        display_update_check(&ctx, &info, true);
    }

    #[test]
    fn test_update_check_empty_assets() {
        let check = create_test_update_check(true);
        assert!(check.assets.is_empty());
    }

    #[test]
    fn test_update_check_with_changelog_diff() {
        let mut check = create_test_update_check(true);
        check.changelog_diff = Some("## Changes\n- Feature A\n- Bug fix B".to_string());
        assert!(check.changelog_diff.is_some());
    }

    #[tokio::test]
    async fn test_verify_installation_plain_mode() {
        let ctx = create_test_output_context(false);
        // The libtest executable is not an installed rch binary. Its failed
        // --version probe used to be ignored and "Installation verified" printed.
        assert!(verify_installation(&ctx).await.is_err());
    }

    #[tokio::test]
    async fn test_verify_installation_json_mode() {
        let ctx = create_test_output_context(true);

        assert!(verify_installation(&ctx).await.is_err());
    }

    #[cfg(unix)]
    fn installed_fixture(
        directory: &std::path::Path,
        name: &str,
        body: &str,
    ) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join(name);
        std::fs::write(
            &path,
            format!("#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --version ] || exit 90\n{body}\n"),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installation_verification_checks_every_installed_sibling_without_mutation() {
        let directory = tempfile::tempdir().unwrap();
        for name in ["rch", "rchd", "rch-wkr"] {
            installed_fixture(
                directory.path(),
                name,
                &format!("printf '{name} 2.1.15 (commit 0123456789ab)\\n'"),
            );
        }
        let before = std::fs::read(directory.path().join("rch")).unwrap();
        let report = inspect_installation(
            &directory.path().join("rch"),
            "2.1.15",
            std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(report["components"].as_array().unwrap().len(), 3);
        assert_eq!(report["absent_optional_components"], serde_json::json!([]));
        assert_eq!(report["verification_scope"], "installed_binary_versions");
        assert_eq!(report["cryptographic_verification"], false);
        assert_eq!(std::fs::read(directory.path().join("rch")).unwrap(), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installation_verification_discloses_client_only_installations() {
        let directory = tempfile::tempdir().unwrap();
        let client = installed_fixture(directory.path(), "rch", "printf 'rch 2.1.15\\n'");
        let report = inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(report["components"].as_array().unwrap().len(), 1);
        assert_eq!(
            report["absent_optional_components"],
            serde_json::json!(["rchd", "rch-wkr"])
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installation_verification_refuses_failures_empty_and_misleading_output() {
        let directory = tempfile::tempdir().unwrap();
        for body in [
            "printf 'rch 2.1.15\\n'; exit 7",
            "exit 0",
            "printf 'not-rch 2.1.15\\n'",
            "printf 'rch 2.0.0\\n'",
            "printf 'rch 2.1.15\\n'; printf 'loader failure\\n' >&2",
            "printf 'rch 2.1.15\\nadditional output\\n'",
            "printf '\\377'",
        ] {
            let client = installed_fixture(directory.path(), "rch", body);
            assert!(
                inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(2))
                    .await
                    .is_err(),
                "{body}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installation_verification_refuses_broken_or_mismatched_companions() {
        for body in ["exit 8", "printf 'rchd 2.0.0\\n'", "printf 'rch 2.1.15\\n'"] {
            let directory = tempfile::tempdir().unwrap();
            let client = installed_fixture(directory.path(), "rch", "printf 'rch 2.1.15\\n'");
            installed_fixture(directory.path(), "rchd", body);
            let error = inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(2))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("rchd"), "{error}");
        }
        let directory = tempfile::tempdir().unwrap();
        let client = installed_fixture(directory.path(), "rch", "printf 'rch 2.1.15\\n'");
        std::os::unix::fs::symlink(
            directory.path().join("missing"),
            directory.path().join("rchd"),
        )
        .unwrap();
        assert!(
            inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(2))
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn installation_verification_bounds_hung_and_flooding_probes() {
        let directory = tempfile::tempdir().unwrap();
        for (body, reason) in [
            ("exec sleep 30", "timed out"),
            (
                "while :; do printf 'unbounded version output\\n'; done",
                "exceeded",
            ),
            (
                "while :; do printf 'unbounded diagnostics\\n' >&2; done",
                "exceeded",
            ),
        ] {
            let client = installed_fixture(directory.path(), "rch", body);
            let start = std::time::Instant::now();
            let error = inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(1))
                .await
                .unwrap_err();
            assert!(format!("{error:#}").contains(reason), "{error:#}");
            assert!(start.elapsed() < std::time::Duration::from_secs(5));
        }
    }

    #[tokio::test]
    async fn installation_verification_requires_a_real_client_file() {
        let directory = tempfile::tempdir().unwrap();
        let client = directory.path().join("rch");
        assert!(
            inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(2))
                .await
                .is_err()
        );
        std::fs::create_dir(&client).unwrap();
        assert!(
            inspect_installation(&client, "2.1.15", std::time::Duration::from_secs(2))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_update_fleet_dry_run() {
        // Set up a temp config directory for the test
        let temp_dir = std::env::temp_dir().join("rch_test_update_fleet_dry_run");
        let _ = std::fs::create_dir_all(&temp_dir);
        set_test_config_dir_override(Some(temp_dir.clone()));

        let ctx = create_test_output_context(false);
        let info = create_test_update_check(true);

        // Dry run should succeed (workers will be empty but that returns Ok)
        let result = update_fleet(&ctx, &info, true).await;
        assert!(result.is_ok());

        // Clean up
        set_test_config_dir_override(None);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    // current_thread: the config-dir override is thread-local, and this runs
    // the REAL (non-dry-run) fleet deploy path. On another thread it would
    // read the host's workers.toml and deploy to the live fleet over SSH.
    #[tokio::test(flavor = "current_thread")]
    async fn test_update_fleet_json_mode() {
        // Set up a temp config directory for the test
        let temp_dir = std::env::temp_dir().join("rch_test_update_fleet_json_mode");
        let _ = std::fs::create_dir_all(&temp_dir);
        set_test_config_dir_override(Some(temp_dir.clone()));
        // Fail closed before the real deploy path if isolation ever breaks.
        assert!(
            crate::commands::load_workers_from_config()
                .expect("load isolated workers")
                .is_empty(),
            "test config isolation failed: refusing to run a real fleet update"
        );

        let ctx = create_test_output_context(true);
        let info = create_test_update_check(true);

        // Should succeed (workers will be empty but that returns Ok)
        let result = update_fleet(&ctx, &info, false).await;
        assert!(result.is_ok());

        // Clean up
        set_test_config_dir_override(None);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
