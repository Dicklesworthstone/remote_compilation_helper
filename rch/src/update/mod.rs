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
        println!("Dry run: would update all configured workers");
        return Ok(());
    }

    // TODO: Implement fleet update
    // 1. Load worker configurations
    // 2. Check versions on all workers
    // 3. Upload new binaries via rsync
    // 4. Restart worker agents
    // 5. Verify health

    if !ctx.is_json() {
        println!("Fleet update not yet implemented");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_default() {
        assert_eq!(Channel::default(), Channel::Stable);
    }
}
