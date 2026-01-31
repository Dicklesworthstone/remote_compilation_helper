//! First-run setup wizard for RCH.
//!
//! This module contains the interactive setup wizard that guides users
//! through initial RCH configuration.

use crate::ui::context::OutputContext;
use anyhow::Result;

use super::config::config_init;
use super::daemon::daemon_start;
use super::hook;
use super::workers::workers_probe;
use super::workers_deploy::workers_deploy_binary;
use super::workers_init::workers_discover;
use super::workers_setup::workers_sync_toolchain;

// =============================================================================
// Init Wizard Command
// =============================================================================

/// Interactive first-run setup wizard.
///
/// Guides the user through:
/// 1. Detecting potential workers from SSH config
/// 2. Selecting which hosts to use as workers
/// 3. Probing hosts for connectivity
/// 4. Deploying rch-wkr binary to workers
/// 5. Synchronizing Rust toolchain
/// 6. Starting the daemon
/// 7. Installing the Claude Code hook
/// 8. Running a test compilation
pub async fn init_wizard(yes: bool, skip_test: bool, ctx: &OutputContext) -> Result<()> {
    use dialoguer::Confirm;

    let style = ctx.theme();

    println!();
    println!("{}", style.format_header("RCH First-Run Setup Wizard"));
    println!();
    println!(
        "  {} This wizard will help you set up RCH for remote compilation.",
        style.muted("→")
    );
    println!();

    // Step 1: Initialize configuration
    println!("{}", style.highlight("Step 1/8: Initialize configuration"));
    config_init(ctx, false, yes)?;
    println!();

    // Step 2: Discover workers
    println!(
        "{}",
        style.highlight("Step 2/8: Discover potential workers")
    );
    workers_discover(true, false, yes, ctx).await?;
    println!();

    // Step 3: Add discovered workers
    println!("{}", style.highlight("Step 3/8: Add discovered workers"));
    if !yes {
        let add_workers = Confirm::new()
            .with_prompt("Add discovered workers to configuration?")
            .default(true)
            .interact()
            .unwrap_or(false);

        if add_workers {
            workers_discover(false, true, false, ctx).await?;
        }
    } else {
        workers_discover(false, true, true, ctx).await?;
    }
    println!();

    // Step 4: Probe worker connectivity
    println!("{}", style.highlight("Step 4/8: Probe worker connectivity"));
    workers_probe(None, true, ctx).await?;
    println!();

    // Step 5: Deploy worker binary
    println!("{}", style.highlight("Step 5/8: Deploy worker binary"));
    let deploy = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Deploy rch-wkr binary to workers?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if deploy {
        workers_deploy_binary(None, true, false, false, ctx).await?;
    }
    println!();

    // Step 6: Sync toolchain
    println!(
        "{}",
        style.highlight("Step 6/8: Synchronize Rust toolchain")
    );
    let sync_toolchain = if yes {
        true
    } else {
        Confirm::new()
            .with_prompt("Synchronize Rust toolchain to workers?")
            .default(true)
            .interact()
            .unwrap_or(false)
    };
    if sync_toolchain {
        workers_sync_toolchain(None, true, false, ctx).await?;
    }
    println!();

    // Step 7: Start daemon
    println!("{}", style.highlight("Step 7/8: Start daemon"));
    daemon_start(ctx).await?;
    println!();

    // Step 8: Install hook
    println!("{}", style.highlight("Step 8/8: Install Claude Code hook"));
    hook::hook_install(ctx)?;
    println!();

    // Optional: Test compilation
    if !skip_test {
        println!("{}", style.highlight("Bonus: Test compilation"));
        let run_test = if yes {
            true
        } else {
            Confirm::new()
                .with_prompt("Run a test compilation?")
                .default(true)
                .interact()
                .unwrap_or(false)
        };
        if run_test {
            hook::hook_test(ctx).await?;
        }
        println!();
    }

    // Summary
    println!("{}", style.format_success("Setup complete!"));
    println!();
    println!("{}", style.highlight("What's next:"));
    println!(
        "  {} Use Claude Code normally - compilation will be offloaded",
        style.muted("•")
    );
    println!(
        "  {} Monitor with: {}",
        style.muted("•"),
        style.info("rch status --workers --jobs")
    );
    println!(
        "  {} Check health with: {}",
        style.muted("•"),
        style.info("rch doctor")
    );

    Ok(())
}
