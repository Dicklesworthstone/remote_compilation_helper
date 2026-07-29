//! Human-facing job-output rendering: the compile-summary panel, the job
//! banner, and the duration/speed/profile/target formatting + detection
//! helpers that feed them.
//!
//! Pure presentation over a finished build's command/output — no daemon state.
//! Reaches `HookReporter` / `RchConsole` / `SyncResult` etc. from the parent via
//! `use super::*`. `format_duration_ms` / `estimate_local_time_ms` are
//! `pub(super)` for the hook hot path; `emit_job_banner` / `render_compile_summary`
//! / `cache_hit` / `detect_target_label` are `pub(super)` for the sibling
//! transfer-orchestration path; the remaining detectors stay module-private.
use super::*;

pub(super) fn format_duration_ms(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis >= 1000 {
        format!("{:.1}s", millis as f64 / 1000.0)
    } else {
        format!("{}ms", millis)
    }
}

fn format_speed(bytes: u64, duration_ms: u64) -> String {
    if duration_ms == 0 || bytes == 0 {
        return "--".to_string();
    }
    let secs = duration_ms as f64 / 1000.0;
    if secs <= 0.0 {
        return "--".to_string();
    }
    let per_sec = (bytes as f64 / secs).round() as u64;
    format!("{}/s", format_bytes(per_sec))
}

pub(super) fn cache_hit(sync: &SyncResult) -> bool {
    sync.bytes_transferred == 0 && sync.files_transferred == 0
}

pub(super) fn detect_target_label(command: &str, output: &str) -> Option<String> {
    if let Some(profile) = detect_profile_from_output(output) {
        return Some(profile);
    }
    if let Some(profile) = extract_profile_flag(command) {
        return Some(profile);
    }
    if command.contains("--release") {
        return Some("release".to_string());
    }
    None
}

fn detect_profile_from_output(output: &str) -> Option<String> {
    for line in output.lines() {
        if line.contains("Finished `release`") {
            return Some("release".to_string());
        }
        if line.contains("Finished `dev`") || line.contains("Finished `debug`") {
            return Some("debug".to_string());
        }
        if line.contains("Finished `bench`") {
            return Some("bench".to_string());
        }
    }
    None
}

fn extract_profile_flag(command: &str) -> Option<String> {
    for token in command.split_whitespace() {
        if let Some(profile) = token.strip_prefix("--profile=") {
            return Some(profile.to_string());
        }
    }

    let mut iter = command.split_whitespace();
    while let Some(token) = iter.next() {
        if token == "--profile"
            && let Some(value) = iter.next()
        {
            return Some(value.to_string());
        }
    }
    None
}

pub(super) fn emit_job_banner(
    console: &RchConsole,
    ctx: OutputContext,
    worker: &SelectedWorker,
    build_id: Option<u64>,
) {
    if console.is_machine() {
        return;
    }

    let job = build_id
        .map(|id| format!("j-{}", id))
        .unwrap_or_else(|| "job".to_string());
    let message = format!(
        "{} Job {} submitted to {} ({} slots remaining, speed {:.1})",
        Icons::status_healthy(ctx),
        job,
        worker.id,
        worker.slots_available,
        worker.speed_score
    );

    #[cfg(all(feature = "rich-ui", unix))]
    if console.is_rich() {
        let rich = format!(
            "[bold {}]{}[/] Job {} submitted to {} ({} slots remaining, speed {:.1})",
            RchTheme::INFO,
            Icons::status_healthy(ctx),
            job,
            worker.id,
            worker.slots_available,
            worker.speed_score
        );
        console.print_rich(&rich);
        return;
    }

    console.print_plain(&message);
}

#[allow(clippy::too_many_arguments)] // Presentation helper; wiring is clearer with explicit params.
pub(super) fn render_compile_summary(
    console: &RchConsole,
    ctx: OutputContext,
    worker: &SelectedWorker,
    build_id: Option<u64>,
    sync: &SyncResult,
    exec_ms: u64,
    artifacts: Option<&SyncResult>,
    artifacts_failed: bool,
    cache_hit: bool,
    success: bool,
) {
    if console.is_machine() {
        return;
    }

    let total_ms = sync.duration_ms + exec_ms + artifacts.map(|a| a.duration_ms).unwrap_or(0);
    let sync_duration = format_duration_ms(Duration::from_millis(sync.duration_ms));
    let exec_duration = format_duration_ms(Duration::from_millis(exec_ms));
    let total_duration = format_duration_ms(Duration::from_millis(total_ms));

    let sync_bytes = format_bytes(sync.bytes_transferred);
    let sync_speed = format_speed(sync.bytes_transferred, sync.duration_ms);

    let (artifact_line, artifact_duration) = if let Some(artifact) = artifacts {
        let bytes = format_bytes(artifact.bytes_transferred);
        let speed = format_speed(artifact.bytes_transferred, artifact.duration_ms);
        let duration = format_duration_ms(Duration::from_millis(artifact.duration_ms));
        (
            format!(
                "{} Artifacts: {} in {} ({})",
                Icons::arrow_down(ctx),
                bytes,
                duration,
                speed
            ),
            duration,
        )
    } else if artifacts_failed {
        ("Artifacts: failed".to_string(), "--".to_string())
    } else {
        ("Artifacts: skipped".to_string(), "--".to_string())
    };

    let job = build_id
        .map(|id| format!("j-{}", id))
        .unwrap_or_else(|| "job".to_string());

    let worker_line = format!(
        "{} Worker: {} | Job: {}",
        Icons::worker(ctx),
        worker.id,
        job
    );
    let timing_line = format!(
        "{} Total: {} (sync {}, build {}, artifacts {})",
        Icons::clock(ctx),
        total_duration,
        sync_duration,
        exec_duration,
        artifact_duration
    );
    let sync_line = format!(
        "{} Sync: {} in {} ({})",
        Icons::arrow_up(ctx),
        sync_bytes,
        sync_duration,
        sync_speed
    );
    let compile_line = format!("{} Compile: {}", Icons::compile(ctx), exec_duration);

    let cache_text = if cache_hit { "HIT" } else { "MISS" };
    let cache_line_plain = format!("{} Cache: {}", Icons::transfer(ctx), cache_text);

    let content_plain = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        worker_line, timing_line, sync_line, compile_line, artifact_line, cache_line_plain
    );

    #[cfg(all(feature = "rich-ui", unix))]
    if console.is_rich() {
        let cache_rich = if cache_hit {
            format!("[bold {}]HIT[/]", RchTheme::SUCCESS)
        } else {
            format!("[bold {}]MISS[/]", RchTheme::WARNING)
        };
        let cache_line = format!("{} Cache: {}", Icons::transfer(ctx), cache_rich);
        let content = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            worker_line, timing_line, sync_line, compile_line, artifact_line, cache_line
        );
        let title = if success {
            "Compilation Complete"
        } else {
            "Compilation Failed"
        };
        let border = if success {
            RchTheme::success()
        } else {
            RchTheme::error()
        };
        let panel = Panel::from_text(&content)
            .title(title)
            .border_style(border)
            .rounded();
        console.print_renderable(&panel);
        return;
    }

    console.print_plain(&content_plain);
}

#[allow(dead_code)] // May be used for timing estimates in run_exec
pub(super) fn estimate_local_time_ms(remote_ms: u64, worker_speed_score: f64) -> Option<u64> {
    if remote_ms == 0 || worker_speed_score <= 0.0 {
        return None;
    }
    // Don't clamp upper bound - allow scores > 100 (faster than baseline)
    // Lower bound 1.0 prevents zero/negative logic issues
    let normalized = worker_speed_score.max(1.0);

    // Formula: LocalTime = RemoteTime * (WorkerScore / BaselineScore)
    // Example: Worker=200 (2x fast), Remote=5s. Local=5*(200/100)=10s.
    let estimate = (remote_ms as f64) * (normalized / 100.0);
    Some(estimate.round().max(1.0) as u64)
}
