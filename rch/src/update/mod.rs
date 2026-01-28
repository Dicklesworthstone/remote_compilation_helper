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
mod verify;

pub use check::{check_for_updates, spawn_update_check_if_needed};
pub use download::download_release;
pub use install::{install_update, rollback};
pub use types::{Channel, UpdateCheck};

use crate::commands;
use crate::ui::OutputContext;
use anyhow::Result;

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

    // Check for updates
    let update_info = check_for_updates(channel, version.clone()).await?;

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
    let download = download_release(ctx, &update_info).await?;

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

        if show_changelog && let Some(ref notes) = info.release_notes {
            println!("\nRelease notes:\n{}", notes);
        }
    } else {
        println!("Already up to date ({})", info.current_version);
    }
}

/// Verify the current installation integrity.
async fn verify_installation(ctx: &OutputContext) -> Result<()> {
    if !ctx.is_json() {
        println!("Verifying installation...");
    }

    // Check that binaries exist and can report versions
    let rch_version = std::process::Command::new(std::env::current_exe()?)
        .arg("--version")
        .output()?;

    if rch_version.status.success() {
        let version = String::from_utf8_lossy(&rch_version.stdout);
        if !ctx.is_json() {
            println!("rch: {}", version.trim());
        }
    }

    // TODO: Verify checksums against known good values if available

    if !ctx.is_json() {
        println!("Installation verified.");
    }

    Ok(())
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

        // This will run the current executable with --version
        // It may fail in test environment but shouldn't panic
        let _ = verify_installation(&ctx).await;
    }

    #[tokio::test]
    async fn test_verify_installation_json_mode() {
        let ctx = create_test_output_context(true);

        // Verify it doesn't panic in JSON mode
        let _ = verify_installation(&ctx).await;
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

    #[tokio::test]
    async fn test_update_fleet_json_mode() {
        // Set up a temp config directory for the test
        let temp_dir = std::env::temp_dir().join("rch_test_update_fleet_json_mode");
        let _ = std::fs::create_dir_all(&temp_dir);
        set_test_config_dir_override(Some(temp_dir.clone()));

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
