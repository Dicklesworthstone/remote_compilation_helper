//! Queue and cancel command implementations.

use anyhow::{Context, Result};
use rch_common::ApiResponse;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::config::load_config;
use crate::error::DaemonError;
#[cfg(not(unix))]
use crate::error::PlatformError;
use crate::status_types::{
    ActiveBuildFromApi, DaemonFullStatusResponse, QueuedBuildFromApi, WorkerStatusFromApi,
    extract_json_body,
};
use crate::ui::context::OutputContext;
use crate::ui::theme::Theme;

use super::send_daemon_command;

#[cfg(unix)]
use tokio::net::UnixStream;

const PROJECT_DISPLAY_MAX_CHARS: usize = 30;
const PROJECT_DISPLAY_PREFIX: &str = "...";

/// Display build queue - active builds and worker availability.
///
/// When `follow` is true, streams daemon events (like `tail -f`) instead of
/// showing a periodic snapshot.
pub async fn queue_status(watch: bool, follow: bool, ctx: &OutputContext) -> Result<()> {
    if follow {
        return queue_follow(ctx).await;
    }

    loop {
        // Query daemon for full status
        let response = send_daemon_command("GET /status\n").await?;
        let json = extract_json_body(&response)
            .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
        let status: DaemonFullStatusResponse =
            serde_json::from_str(json).context("Failed to parse daemon status response")?;

        // JSON output for scripting (pure JSON on stdout; no other output).
        if ctx.is_json() {
            let mut workers_available = 0;
            let mut workers_busy = 0;
            let mut workers_offline = 0;

            for worker in &status.workers {
                match worker.status.as_str() {
                    "healthy" | "degraded" | "draining" => {
                        if worker.used_slots >= worker.total_slots {
                            workers_busy += 1;
                        } else {
                            workers_available += 1;
                        }
                    }
                    "unreachable" | "drained" | "disabled" => workers_offline += 1,
                    _ => {}
                }
            }

            let queue_data = serde_json::json!({
                "active_builds": status.active_builds,
                "queued_builds": status.queued_builds,
                "queue_depth": status.queued_builds.len(),
                "workers_available": workers_available,
                "workers_busy": workers_busy,
                "workers_offline": workers_offline,
                "workers_total": status.daemon.workers_total,
                "workers_healthy": status.daemon.workers_healthy,
                "slots_available": status.daemon.slots_available,
                "slots_total": status.daemon.slots_total,
                "timestamp": chrono::Utc::now().to_rfc3339()
            });
            let _ = ctx.json(&ApiResponse::ok("queue", queue_data));
            return Ok(());
        }

        // In watch mode, clear screen
        if watch {
            print!("\x1B[2J\x1B[H"); // ANSI clear screen and move cursor to top
        }

        let style = ctx.style();

        // Header
        println!(
            "{} {}",
            style.highlight("Build Queue"),
            style.muted(&format!("({})", chrono::Local::now().format("%H:%M:%S")))
        );
        println!("{}", style.muted(&"─".repeat(40)));
        println!();

        // Active builds section
        if status.active_builds.is_empty() {
            println!("{}", style.muted("  No active builds"));
        } else {
            println!(
                "  {} {}",
                style.success("●"),
                style.key(&format!("{} Active Build(s)", status.active_builds.len()))
            );
            println!();

            for build in &status.active_builds {
                // Calculate elapsed time
                let elapsed =
                    if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&build.started_at) {
                        let duration = chrono::Utc::now().signed_duration_since(started);
                        format_build_duration(duration.num_seconds().max(0) as u64)
                    } else {
                        "?".to_string()
                    };

                // Truncate command for display
                let cmd_display = if build.command.len() > 50 {
                    format!(
                        "{}...",
                        rch_common::util::truncate_at_char_boundary(&build.command, 47)
                    )
                } else {
                    build.command.clone()
                };

                println!(
                    "  {} {} {} {} {} {}",
                    style.info(&format!("#{}", build.id)),
                    style.muted("on"),
                    style.key(&build.worker_id),
                    style.muted("|"),
                    style.value(&cmd_display),
                    style.warning(&format!("[{}]", elapsed))
                );

                // Show project
                let project_display = format_project_id_for_queue(&build.project_id);
                println!(
                    "      {} {}",
                    style.muted("project:"),
                    style.value(&project_display)
                );

                if ctx.is_verbose() {
                    debug!(target: "rch::verbose", build_id = build.id, "rendering verbose active build details");
                    for line in render_active_build_verbose_lines(build, style) {
                        println!("{line}");
                    }
                }
            }
        }
        println!();

        // Queued builds section
        if !status.queued_builds.is_empty() {
            println!(
                "  {} {}",
                style.warning("◌"),
                style.key(&format!("{} Queued Build(s)", status.queued_builds.len()))
            );
            println!();

            for build in &status.queued_builds {
                // Truncate command for display
                let cmd_display = if build.command.len() > 50 {
                    format!(
                        "{}...",
                        rch_common::util::truncate_at_char_boundary(&build.command, 47)
                    )
                } else {
                    build.command.clone()
                };

                // Show position and estimated wait
                let estimate_display = build
                    .estimated_start
                    .as_ref()
                    .map(|_| format!("~{}", build.wait_time))
                    .unwrap_or_else(|| build.wait_time.clone());

                println!(
                    "  {} {} {} {} {}",
                    style.info(&format!("#{}", build.id)),
                    style.muted("|"),
                    style.value(&cmd_display),
                    style.muted("waiting"),
                    style.warning(&format!("[{}]", estimate_display))
                );

                // Show project
                let project_display = format_project_id_for_queue(&build.project_id);
                println!(
                    "      {} {}  {} {}",
                    style.muted("project:"),
                    style.value(&project_display),
                    style.muted("position:"),
                    style.value(&build.position.to_string())
                );

                if ctx.is_verbose() {
                    debug!(target: "rch::verbose", build_id = build.id, "rendering verbose queued build details");
                    for line in render_queued_build_verbose_lines(build, style) {
                        println!("{line}");
                    }
                }
            }
            println!();
        }

        // Worker availability summary
        println!("{}", style.key("Worker Availability"));
        println!();

        let mut healthy_count = 0;
        let mut busy_count = 0;
        let mut offline_count = 0;

        for worker in &status.workers {
            match worker.status.as_str() {
                "healthy" | "degraded" | "draining" => {
                    if worker.used_slots >= worker.total_slots {
                        busy_count += 1;
                    } else {
                        healthy_count += 1;
                    }
                }
                "unreachable" | "drained" | "disabled" => offline_count += 1,
                _ => {}
            }
        }

        println!(
            "  {} {} available  {} {} busy  {} {} offline",
            style.success("●"),
            healthy_count,
            style.warning("●"),
            busy_count,
            style.error("●"),
            offline_count
        );
        println!();

        if ctx.is_verbose() {
            debug!(target: "rch::verbose", workers = status.workers.len(), "rendering verbose queue worker availability");
            for worker in &status.workers {
                println!("{}", render_worker_availability_verbose_line(worker, style));
            }
            println!();
        }

        // Slot summary
        println!(
            "  {} {} / {} slots free",
            style.info("→"),
            status.daemon.slots_available,
            status.daemon.slots_total
        );

        if !watch {
            break;
        }

        // Wait 1 second before refresh
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

fn render_active_build_verbose_lines(build: &ActiveBuildFromApi, style: &Theme) -> Vec<String> {
    vec![
        format!(
            "      {} {}",
            style.muted("command:"),
            style.value(&build.command)
        ),
        format!(
            "      {} {}",
            style.muted("started:"),
            style.value(&build.started_at)
        ),
    ]
}

fn render_queued_build_verbose_lines(build: &QueuedBuildFromApi, style: &Theme) -> Vec<String> {
    vec![
        format!(
            "      {} {}",
            style.muted("command:"),
            style.value(&build.command)
        ),
        format!(
            "      {} {}  {} {}",
            style.muted("slots:"),
            style.value(&build.slots_needed.to_string()),
            style.muted("queued:"),
            style.value(&build.queued_at)
        ),
    ]
}

fn render_worker_availability_verbose_line(worker: &WorkerStatusFromApi, style: &Theme) -> String {
    let status_indicator = match worker.status.as_str() {
        "healthy" => style.success("●"),
        "degraded" => style.warning("●"),
        "draining" => style.warning("◐"),
        "drained" => style.info("○"),
        "unreachable" => style.error("○"),
        "disabled" => style.muted("⊘"),
        _ => style.muted("?"),
    };
    let slots_display = format!("{}/{}", worker.used_slots, worker.total_slots);
    let circuit_display = match worker.circuit_state.as_str() {
        "closed" => style.success("ok"),
        "half_open" => style.warning("half"),
        "open" => style.error("open"),
        _ => style.muted(&worker.circuit_state),
    };

    format!(
        "    {} {} {} {} {}",
        status_indicator,
        style.key(&worker.id),
        style.muted(&format!("[{}]", slots_display)),
        style.muted("circuit:"),
        circuit_display
    )
}

fn format_project_id_for_queue(project_id: &str) -> String {
    if project_id.chars().count() <= PROJECT_DISPLAY_MAX_CHARS {
        return project_id.to_string();
    }

    let tail_chars =
        PROJECT_DISPLAY_MAX_CHARS.saturating_sub(PROJECT_DISPLAY_PREFIX.chars().count());
    let tail = project_id
        .chars()
        .rev()
        .take(tail_chars)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{PROJECT_DISPLAY_PREFIX}{tail}")
}

/// Stream daemon build events (like `tail -f`).
///
/// Connects to the daemon event bus (GET /events) and prints build-related
/// events as they happen. Runs until the connection drops or the user
/// interrupts with Ctrl-C.
#[cfg(not(unix))]
async fn queue_follow(_ctx: &OutputContext) -> Result<()> {
    Err(PlatformError::UnixOnly {
        feature: "follow mode".to_string(),
    })?
}

#[cfg(unix)]
async fn queue_follow(ctx: &OutputContext) -> Result<()> {
    let config = load_config()?;
    let expanded = shellexpand::tilde(&config.general.socket_path);
    let socket_path = Path::new(expanded.as_ref());
    if !socket_path.exists() {
        return Err(DaemonError::SocketNotFound {
            socket_path: socket_path.display().to_string(),
        }
        .into());
    }

    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    writer.write_all(b"GET /events\n").await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);

    // Skip the HTTP header (read until empty line)
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let n = reader.read_line(&mut header_line).await?;
        if n == 0 || header_line.trim().is_empty() {
            break;
        }
    }

    let style = ctx.style();

    if ctx.is_json() {
        // JSON mode: pass through raw event JSON lines
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break; // connection closed
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            println!("{trimmed}");
        }
    } else {
        // Human-readable mode: format build events
        println!(
            "{} {}",
            style.highlight("Following build events"),
            style.muted("(Ctrl-C to stop)")
        );
        println!("{}", style.muted(&"─".repeat(60)));

        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).await?;
            if n == 0 {
                break; // connection closed
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if let Ok(event) = serde_json::from_str::<serde_json::Value>(trimmed)
                && let Some(formatted) = format_build_event(&event, style)
            {
                println!("{formatted}");
            }
        }
    }

    Ok(())
}

/// Format a daemon event into a human-readable line.
///
/// Returns `None` for events that are not build-related (e.g. telemetry,
/// benchmark events) so they are silently skipped.
fn format_build_event(
    event: &serde_json::Value,
    style: &crate::ui::theme::Style,
) -> Option<String> {
    let event_name = event.get("event")?.as_str()?;
    let data = event.get("data")?;
    let ts = event
        .get("timestamp")
        .and_then(|t| t.as_str())
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "??:??:??".to_string());

    let ts_display = style.muted(&format!("[{ts}]"));

    match event_name {
        "build_queued" => {
            let cmd = data.get("command").and_then(|v| v.as_str()).unwrap_or("?");
            let id = data
                .get("queue_id")
                .and_then(|v| v.as_u64())
                .map(|n| format!("q-{n}"))
                .unwrap_or_else(|| "?".to_string());
            let pos = data
                .get("position")
                .and_then(|v| v.as_u64())
                .map(|n| format!("pos {n}"))
                .unwrap_or_default();
            Some(format!(
                "{ts_display} {} {id} {cmd} {pos}",
                style.warning("QUEUED    "),
            ))
        }
        "build_started" => {
            let cmd = data.get("command").and_then(|v| v.as_str()).unwrap_or("?");
            let id = data
                .get("build_id")
                .and_then(|v| v.as_u64())
                .map(|n| format!("b-{n}"))
                .unwrap_or_else(|| "?".to_string());
            let worker = data
                .get("worker_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!(
                "{ts_display} {} {id} {cmd} {} {worker}",
                style.success("STARTED   "),
                style.muted("→"),
            ))
        }
        "build_completed" => {
            let cmd = data.get("command").and_then(|v| v.as_str()).unwrap_or("?");
            let id = data
                .get("build_id")
                .and_then(|v| v.as_u64())
                .map(|n| format!("b-{n}"))
                .unwrap_or_else(|| "?".to_string());
            let exit_code = data.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
            let duration_ms = data
                .get("duration_ms")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let duration = format_build_duration(duration_ms / 1000);

            if exit_code == 0 {
                Some(format!(
                    "{ts_display} {} {id} {cmd} {} ({duration})",
                    style.success("COMPLETE  "),
                    style.success("✓"),
                ))
            } else {
                Some(format!(
                    "{ts_display} {} {id} {cmd} {} ({duration}, exit {exit_code})",
                    style.error("FAILED    "),
                    style.error("✗"),
                ))
            }
        }
        "build_queue_removed" => {
            let id = data
                .get("queue_id")
                .and_then(|v| v.as_u64())
                .map(|n| format!("q-{n}"))
                .unwrap_or_else(|| "?".to_string());
            let reason = data.get("reason").and_then(|v| v.as_str()).unwrap_or("?");
            Some(format!(
                "{ts_display} {} {id} {reason}",
                style.muted("DEQUEUED  "),
            ))
        }
        _ => None,
    }
}

/// Cancel an active build (or all builds) via the daemon API.
pub async fn cancel_build(
    build_id: Option<u64>,
    all: bool,
    force: bool,
    yes: bool,
    dry_run: bool,
    ctx: &OutputContext,
) -> Result<()> {
    use dialoguer::Confirm;

    if all && build_id.is_some() {
        debug!("Ignoring build_id since --all was provided");
    }

    // Dry-run mode: preview what would be cancelled
    if dry_run {
        return cancel_build_dry_run(build_id, all, ctx).await;
    }

    if all && !yes && !ctx.is_json() {
        let confirmed = Confirm::new()
            .with_prompt("Cancel all active builds?")
            .default(false)
            .interact()
            .unwrap_or(false);
        if !confirmed {
            println!("{}", ctx.style().muted("No builds cancelled."));
            return Ok(());
        }
    }

    let command = if all {
        format!(
            "POST /builds/cancel-all?force={}\n",
            if force { "true" } else { "false" }
        )
    } else {
        let build_id =
            build_id.ok_or_else(|| anyhow::anyhow!("Missing build id (or use --all)"))?;
        format!(
            "POST /builds/{}/cancel?force={}\n",
            build_id,
            if force { "true" } else { "false" }
        )
    };

    let response = send_daemon_command(&command).await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let payload: serde_json::Value =
        serde_json::from_str(json).context("Failed to parse cancellation response")?;

    let _ = ctx.json(&payload);
    if ctx.is_json() {
        return Ok(());
    }

    let style = ctx.style();
    let status = payload
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match status {
        "cancelled" => {
            let id = payload.get("build_id").and_then(|v| v.as_u64());
            let msg = payload
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(id) = id {
                println!(
                    "{} {} {}",
                    style.success("Cancelled"),
                    style.muted("build"),
                    style.value(&id.to_string())
                );
            } else {
                println!("{}", style.success("Cancelled build"));
            }
            if !msg.is_empty() {
                println!("  {}", style.muted(msg));
            }
        }
        "ok" => {
            // cancel-all response when nothing to do, or generic success
            if let Some(msg) = payload.get("message").and_then(|v| v.as_str()) {
                println!("{}", style.info(msg));
            } else {
                println!("{}", style.success("OK"));
            }
        }
        "error" => {
            let msg = payload
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("error");
            println!("{} {}", style.error("Error:"), style.value(msg));
        }
        other => {
            println!("{} {}", style.key("Status:"), style.value(other));
            if let Some(msg) = payload.get("message").and_then(|v| v.as_str()) {
                println!("  {}", style.muted(msg));
            }
        }
    }

    Ok(())
}

/// Dry-run mode: preview what builds would be cancelled.
async fn cancel_build_dry_run(build_id: Option<u64>, all: bool, ctx: &OutputContext) -> Result<()> {
    let style = ctx.style();

    // Query daemon for current active builds
    let response = send_daemon_command("GET /status\n").await?;
    let json = extract_json_body(&response)
        .ok_or_else(|| anyhow::anyhow!("Invalid response format from daemon"))?;
    let status: DaemonFullStatusResponse =
        serde_json::from_str(json).context("Failed to parse daemon status")?;

    let builds: Vec<&ActiveBuildFromApi> = if all {
        status.active_builds.iter().collect()
    } else {
        let target_id =
            build_id.ok_or_else(|| anyhow::anyhow!("Missing build id (or use --all)"))?;
        status
            .active_builds
            .iter()
            .filter(|b| b.id == target_id)
            .collect()
    };

    if ctx.is_json() {
        let json_builds: Vec<serde_json::Value> = builds
            .iter()
            .map(|b| {
                serde_json::json!({
                    "id": b.id,
                    "command": b.command,
                    "worker": b.worker_id,
                    "started_at": b.started_at,
                })
            })
            .collect();
        let _ = ctx.json(&serde_json::json!({
            "dry_run": true,
            "would_cancel": json_builds.len(),
            "builds": json_builds,
        }));
        return Ok(());
    }

    if builds.is_empty() {
        println!("{}", style.muted("No active builds to cancel."));
        return Ok(());
    }

    println!(
        "Would cancel {} build{}:",
        style.value(&builds.len().to_string()),
        if builds.len() == 1 { "" } else { "s" }
    );
    let now = chrono::Utc::now();
    for build in &builds {
        let elapsed = if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&build.started_at) {
            let secs = (now - started.with_timezone(&chrono::Utc))
                .num_seconds()
                .max(0) as u64;
            format_build_duration(secs)
        } else {
            "?".to_string()
        };
        println!(
            "  {}  {}  [worker: {}, {}]",
            style.value(&build.id.to_string()),
            style.muted(&build.command),
            style.key(&build.worker_id),
            style.muted(&elapsed),
        );
    }
    println!("\n{}", style.muted("Run without --dry-run to cancel."));

    Ok(())
}

/// Format build duration in human-readable form.
fn format_build_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    // -------------------------------------------------------------------------
    // format_build_duration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn format_build_duration_seconds() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(45), "45s");
    }

    #[test]
    fn format_build_duration_zero() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(0), "0s");
    }

    #[test]
    fn format_build_duration_minutes() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(90), "1m 30s");
    }

    #[test]
    fn format_build_duration_exact_minute() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(60), "1m 0s");
    }

    #[test]
    fn format_build_duration_hours() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(3661), "1h 1m");
    }

    #[test]
    fn format_build_duration_exact_hour() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(3600), "1h 0m");
    }

    #[test]
    fn format_build_duration_multiple_hours() {
        let _guard = test_guard!();
        assert_eq!(format_build_duration(7380), "2h 3m"); // 2h 3m
    }

    #[test]
    fn project_id_display_keeps_short_paths_unchanged() {
        let _guard = test_guard!();
        assert_eq!(
            format_project_id_for_queue("/tmp/rch/project"),
            "/tmp/rch/project"
        );
    }

    #[test]
    fn project_id_display_truncates_ascii_from_start() {
        let _guard = test_guard!();
        assert_eq!(
            format_project_id_for_queue("abcdefghijklmnopqrstuvwxyz0123456789"),
            "...jklmnopqrstuvwxyz0123456789"
        );
    }

    #[test]
    fn project_id_display_handles_multibyte_paths() {
        let _guard = test_guard!();
        let project_id = format!("/tmp/rch/{}/target", "é".repeat(20));
        let display = format_project_id_for_queue(&project_id);

        assert!(display.starts_with(PROJECT_DISPLAY_PREFIX));
        assert!(display.ends_with("/target"));
        assert!(display.chars().count() <= PROJECT_DISPLAY_MAX_CHARS);
    }

    #[test]
    fn test_queue_verbose_shows_worker_assignment() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let active: ActiveBuildFromApi = serde_json::from_value(serde_json::json!({
            "id": 42,
            "project_id": "rch",
            "worker_id": "builder-1",
            "command": "cargo test --workspace --all-targets",
            "started_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        let queued: QueuedBuildFromApi = serde_json::from_value(serde_json::json!({
            "id": 43,
            "project_id": "rch",
            "command": "cargo clippy --workspace --all-targets -- -D warnings",
            "queued_at": "2026-01-01T00:00:10Z",
            "position": 1,
            "slots_needed": 4,
            "estimated_start": null,
            "wait_time": "10s"
        }))
        .unwrap();
        let worker: WorkerStatusFromApi = serde_json::from_value(serde_json::json!({
            "id": "builder-1",
            "host": "127.0.0.1",
            "user": "ubuntu",
            "status": "healthy",
            "circuit_state": "closed",
            "used_slots": 2,
            "total_slots": 8,
            "speed_score": 92.0,
            "last_error": null
        }))
        .unwrap();

        let active_output = render_active_build_verbose_lines(&active, &style).join("\n");
        assert!(active_output.contains("cargo test --workspace --all-targets"));
        assert!(active_output.contains("started:"));

        let queued_output = render_queued_build_verbose_lines(&queued, &style).join("\n");
        assert!(queued_output.contains("cargo clippy --workspace"));
        assert!(queued_output.contains("slots: 4"));
        assert!(queued_output.contains("queued:"));

        let worker_output = render_worker_availability_verbose_line(&worker, &style);
        assert!(worker_output.contains("builder-1"));
        assert!(worker_output.contains("[2/8]"));
        assert!(worker_output.contains("circuit:"));
        assert!(worker_output.contains("ok"));
    }

    // -------------------------------------------------------------------------
    // format_build_event Tests
    // -------------------------------------------------------------------------

    #[test]
    fn format_build_event_started() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let event = serde_json::json!({
            "event": "build_started",
            "data": {
                "build_id": 42,
                "project_id": "my-project",
                "worker_id": "css",
                "command": "cargo build",
                "slots": 4,
            },
            "timestamp": "2026-01-28T14:32:15+00:00",
        });
        let formatted = format_build_event(&event, &style).unwrap();
        assert!(
            formatted.contains("STARTED"),
            "should contain STARTED: {formatted}"
        );
        assert!(
            formatted.contains("b-42"),
            "should contain build id: {formatted}"
        );
        assert!(
            formatted.contains("cargo build"),
            "should contain command: {formatted}"
        );
        assert!(
            formatted.contains("css"),
            "should contain worker: {formatted}"
        );
    }

    #[test]
    fn format_build_event_completed_success() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let event = serde_json::json!({
            "event": "build_completed",
            "data": {
                "build_id": 42,
                "project_id": "my-project",
                "worker_id": "css",
                "command": "cargo build",
                "exit_code": 0,
                "duration_ms": 90000,
                "location": "Remote",
            },
            "timestamp": "2026-01-28T14:33:45+00:00",
        });
        let formatted = format_build_event(&event, &style).unwrap();
        assert!(
            formatted.contains("COMPLETE"),
            "should contain COMPLETE: {formatted}"
        );
        assert!(
            formatted.contains("b-42"),
            "should contain build id: {formatted}"
        );
        assert!(
            formatted.contains("1m 30s"),
            "should contain duration: {formatted}"
        );
        assert!(
            formatted.contains("✓"),
            "should contain check mark: {formatted}"
        );
    }

    #[test]
    fn format_build_event_completed_failure() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let event = serde_json::json!({
            "event": "build_completed",
            "data": {
                "build_id": 43,
                "project_id": "my-project",
                "worker_id": "csd",
                "command": "cargo test",
                "exit_code": 1,
                "duration_ms": 104000,
                "location": "Remote",
            },
            "timestamp": "2026-01-28T14:34:02+00:00",
        });
        let formatted = format_build_event(&event, &style).unwrap();
        assert!(
            formatted.contains("FAILED"),
            "should contain FAILED: {formatted}"
        );
        assert!(
            formatted.contains("b-43"),
            "should contain build id: {formatted}"
        );
        assert!(
            formatted.contains("exit 1"),
            "should contain exit code: {formatted}"
        );
        assert!(
            formatted.contains("✗"),
            "should contain cross mark: {formatted}"
        );
    }

    #[test]
    fn format_build_event_queued() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let event = serde_json::json!({
            "event": "build_queued",
            "data": {
                "queue_id": 10,
                "project_id": "my-project",
                "command": "cargo check",
                "queued_at": "2026-01-28T14:30:00+00:00",
                "position": 2,
                "slots_needed": 2,
            },
            "timestamp": "2026-01-28T14:30:00+00:00",
        });
        let formatted = format_build_event(&event, &style).unwrap();
        assert!(
            formatted.contains("QUEUED"),
            "should contain QUEUED: {formatted}"
        );
        assert!(
            formatted.contains("q-10"),
            "should contain queue id: {formatted}"
        );
        assert!(
            formatted.contains("cargo check"),
            "should contain command: {formatted}"
        );
        assert!(
            formatted.contains("pos 2"),
            "should contain position: {formatted}"
        );
    }

    #[test]
    fn format_build_event_dequeued() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let event = serde_json::json!({
            "event": "build_queue_removed",
            "data": {
                "queue_id": 10,
                "project_id": "my-project",
                "reason": "hook_exited",
            },
            "timestamp": "2026-01-28T14:31:00+00:00",
        });
        let formatted = format_build_event(&event, &style).unwrap();
        assert!(
            formatted.contains("DEQUEUED"),
            "should contain DEQUEUED: {formatted}"
        );
        assert!(
            formatted.contains("q-10"),
            "should contain queue id: {formatted}"
        );
        assert!(
            formatted.contains("hook_exited"),
            "should contain reason: {formatted}"
        );
    }

    #[test]
    fn format_build_event_ignores_unknown_events() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        let event = serde_json::json!({
            "event": "telemetry:update",
            "data": {"cpu": 50},
            "timestamp": "2026-01-28T14:30:00+00:00",
        });
        assert!(format_build_event(&event, &style).is_none());
    }

    #[test]
    fn format_build_event_missing_fields_graceful() {
        let _guard = test_guard!();
        let style = crate::ui::theme::Style::new(false, true, false);
        // Missing event field entirely
        let event = serde_json::json!({"data": {}});
        assert!(format_build_event(&event, &style).is_none());

        // Missing data field
        let event = serde_json::json!({"event": "build_started"});
        assert!(format_build_event(&event, &style).is_none());
    }
}
