//! UI performance benchmarks for rich_rust integration.
//!
//! Measures overhead of rich terminal output vs. plain text to ensure
//! performance targets from bd-1bsa are met:
//! - Single line: <100μs overhead
//! - Table (10 rows): <1ms overhead
//! - Progress update: <50μs overhead
//! - Full pipeline: <5ms overhead

use criterion::{Criterion, criterion_group, criterion_main};
use rch_common::ui::{
    CompilationProgress, CompletionCelebration, ErrorPanel, ErrorSeverity, Icons, OutputContext,
    PipelineProgress, PipelineStage, RchTheme, TransferDirection, TransferProgress,
};
use rch_common::ui::progress::CelebrationSummary;
use std::hint::black_box;

/// Baseline: Output context detection should be fast.
fn bench_context_detection(c: &mut Criterion) {
    c.bench_function("ui/context_detect", |b| {
        b.iter(OutputContext::detect)
    });
}

/// Benchmark Icons retrieval (with fallback logic).
fn bench_icons(c: &mut Criterion) {
    let ctx = OutputContext::detect();
    let mut group = c.benchmark_group("ui/icons");

    group.bench_function("check", |b| b.iter(|| Icons::check(black_box(ctx))));
    group.bench_function("cross", |b| b.iter(|| Icons::cross(black_box(ctx))));
    group.bench_function("warning", |b| b.iter(|| Icons::warning(black_box(ctx))));
    group.bench_function("worker", |b| b.iter(|| Icons::worker(black_box(ctx))));

    group.finish();
}

/// Benchmark theme color retrieval.
fn bench_theme(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/theme");

    group.bench_function("success", |b| b.iter(|| RchTheme::SUCCESS));
    group.bench_function("error", |b| b.iter(|| RchTheme::ERROR));
    group.bench_function("primary", |b| b.iter(|| RchTheme::PRIMARY));

    group.finish();
}

/// Benchmark ErrorPanel creation and rendering.
fn bench_error_panel(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/error_panel");
    let _ctx = OutputContext::detect();

    // Simple error panel creation
    group.bench_function("create_simple", |b| {
        b.iter(|| {
            ErrorPanel::new("RCH-E100", "Connection Failed")
                .message("Could not connect to worker")
        })
    });

    // Full error panel with context and suggestions
    group.bench_function("create_full", |b| {
        b.iter(|| {
            ErrorPanel::new("RCH-E100", "Connection Failed")
                .with_severity(ErrorSeverity::Error)
                .message("Could not establish SSH connection to worker")
                .context("Host", "build1.internal (192.168.1.50:22)")
                .context("Timeout", "30s elapsed")
                .context("Last successful", "2h 15m ago")
                .suggestion("Check if worker is online: ssh build1.internal")
                .suggestion("Verify SSH key: ssh-add -l")
                .suggestion("Run: rch workers probe build1 --verbose")
        })
    });

    // Render to JSON (the main serialization path)
    let simple_error = ErrorPanel::new("RCH-E100", "Test Error").message("Test message");
    group.bench_function("to_json", |b| {
        b.iter(|| simple_error.to_json())
    });

    // Render to JSON
    group.bench_function("serialize_json", |b| {
        b.iter(|| serde_json::to_string(black_box(&simple_error)))
    });

    // Error panel batch: simulate 100 error creations
    group.bench_function("batch_100", |b| {
        b.iter(|| {
            for i in 0..100 {
                let _ = black_box(
                    ErrorPanel::new(format!("RCH-E{i:03}"), "Test Error")
                        .message("Test message")
                        .context("iteration", i.to_string()),
                );
            }
        })
    });

    group.finish();
}

/// Benchmark TransferProgress updates.
fn bench_transfer_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/transfer_progress");
    let ctx = OutputContext::detect();

    // Create transfer progress
    group.bench_function("create", |b| {
        b.iter(|| {
            TransferProgress::new(
                black_box(ctx),
                TransferDirection::Upload,
                "Syncing workspace",
                false, // not quiet
            )
        })
    });

    // Update progress (simulating rsync line parsing)
    let mut progress =
        TransferProgress::new(ctx, TransferDirection::Upload, "Syncing", false);
    group.bench_function("update_from_line", |b| {
        b.iter(|| {
            progress.update_from_line(black_box(
                "  1,234,567 100%   10.5MB/s    0:00:01 (xfr#123, ir-chk=456/789)",
            ))
        })
    });

    // High-frequency updates (1000 updates)
    group.bench_function("update_burst_1000", |b| {
        b.iter(|| {
            let mut p =
                TransferProgress::new(ctx, TransferDirection::Upload, "Syncing", false);
            for i in 0..1000 {
                let line = format!(
                    "  {},{} {}%   5.0MB/s    0:00:10 (xfr#{}, ir-chk={}/1000)",
                    i * 1024,
                    i % 1000,
                    (i * 100 / 1000).min(100),
                    i,
                    1000 - i
                );
                p.update_from_line(&line);
            }
        })
    });

    // Get stats
    group.bench_function("stats", |b| {
        let mut p =
            TransferProgress::new(ctx, TransferDirection::Upload, "Syncing", true);
        p.update_from_line("  512,000 50%   10.0MB/s    0:00:05 (xfr#50, ir-chk=450/500)");
        b.iter(|| p.stats())
    });

    group.finish();
}

/// Benchmark CompilationProgress updates.
fn bench_compilation_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/compile_progress");
    let ctx = OutputContext::detect();

    // Create compilation progress
    group.bench_function("create", |b| {
        b.iter(|| CompilationProgress::new(black_box(ctx), "worker1", false))
    });

    // Update with cargo output line
    let mut progress = CompilationProgress::new(ctx, "worker1", false);
    group.bench_function("update_from_line", |b| {
        b.iter(|| progress.update_from_line(black_box("   Compiling serde v1.0.193")))
    });

    // High-frequency crate updates
    group.bench_function("update_burst_100", |b| {
        b.iter(|| {
            let mut p = CompilationProgress::new(ctx, "worker1", false);
            for i in 0..100 {
                let line = format!("   Compiling test_crate_{i} v0.1.{i}");
                p.update_from_line(&line);
            }
        })
    });

    // Get stats
    group.bench_function("stats", |b| {
        let mut p = CompilationProgress::new(ctx, "worker1", true);
        p.update_from_line("   Compiling serde v1.0.193");
        b.iter(|| (p.phase(), p.crates_compiled(), p.warnings()))
    });

    group.finish();
}

/// Benchmark PipelineProgress for multi-stage operations.
fn bench_pipeline_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/pipeline_progress");
    let ctx = OutputContext::detect();

    // Create pipeline
    group.bench_function("create", |b| {
        b.iter(|| PipelineProgress::new(black_box(ctx), "worker1", true))
    });

    // Stage transitions
    let mut pipeline = PipelineProgress::new(ctx, "worker1", true);
    group.bench_function("start_stage", |b| {
        b.iter(|| {
            pipeline.start_stage(PipelineStage::Upload);
        })
    });

    // Full pipeline run simulation
    group.bench_function("full_run", |b| {
        b.iter(|| {
            let mut p = PipelineProgress::new(ctx, "worker1", true);
            for stage in PipelineStage::all() {
                p.start_stage(*stage);
                p.complete_stage();
            }
        })
    });

    group.finish();
}

/// Benchmark CompletionCelebration rendering.
fn bench_celebration(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/celebration");
    let ctx = OutputContext::detect();

    // Create celebration summary
    group.bench_function("create_summary", |b| {
        b.iter(|| {
            CelebrationSummary::new("test_project", 52000)
                .worker("worker1")
                .cache_hit(Some(true))
        })
    });

    // Create celebration
    let summary = CelebrationSummary::new("test_project", 52000)
        .worker("worker1")
        .cache_hit(Some(true));
    group.bench_function("create_celebration", |b| {
        b.iter(|| CompletionCelebration::new(black_box(summary.clone())))
    });

    // Render celebration
    let celebration = CompletionCelebration::new(summary.clone());
    group.bench_function("record_and_render", |b| {
        b.iter(|| celebration.record_and_render(ctx))
    });

    group.finish();
}

/// Comprehensive batch benchmark simulating realistic UI workload.
fn bench_realistic_workload(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/realistic");
    let ctx = OutputContext::detect();

    // Simulate a complete compilation cycle with UI updates
    group.bench_function("full_compile_cycle", |b| {
        b.iter(|| {
            // 1. Create pipeline (quiet=true to avoid output during benchmark)
            let mut pipeline = PipelineProgress::new(ctx, "worker1", true);

            // 2. Sync phase with transfer progress
            pipeline.start_stage(PipelineStage::Upload);
            let mut transfer =
                TransferProgress::new(ctx, TransferDirection::Upload, "Syncing", true);
            for i in 0..10 {
                let line = format!("  {} 50%   10.0MB/s    0:00:05", i * 100_000);
                transfer.update_from_line(&line);
            }
            pipeline.complete_stage();

            // 3. Build phase with compilation progress
            pipeline.start_stage(PipelineStage::Compilation);
            let mut compile = CompilationProgress::new(ctx, "worker1", true);
            for i in 0..20 {
                let line = format!("   Compiling crate_{i} v0.1.0");
                compile.update_from_line(&line);
            }
            pipeline.complete_stage();

            // 4. Artifact retrieval
            pipeline.start_stage(PipelineStage::ArtifactRetrieval);
            let mut artifacts =
                TransferProgress::new(ctx, TransferDirection::Download, "Fetching", true);
            for i in 0..5 {
                let line = format!("  {} 80%   20.0MB/s    0:00:02", i * 200_000);
                artifacts.update_from_line(&line);
            }
            pipeline.complete_stage();

            // 5. Celebration
            let summary = CelebrationSummary::new("test_project", 30000)
                .worker("worker1")
                .cache_hit(Some(true));
            let _ = CompletionCelebration::new(summary);
        })
    });

    // Simulate error scenario
    group.bench_function("error_scenario", |b| {
        b.iter(|| {
            let error = ErrorPanel::new("RCH-E100", "Build Failed")
                .with_severity(ErrorSeverity::Error)
                .message("Compilation failed on worker1")
                .context("Worker", "worker1.internal")
                .context("Exit code", "101")
                .context("Duration", "45.2s")
                .suggestion("Check compiler output above for details")
                .suggestion("Try: cargo build --message-format=short");

            // render() writes to stderr, use to_json() for benchmarking
            let _ = error.to_json();
            let _ = serde_json::to_string(&error);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_context_detection,
    bench_icons,
    bench_theme,
    bench_error_panel,
    bench_transfer_progress,
    bench_compilation_progress,
    bench_pipeline_progress,
    bench_celebration,
    bench_realistic_workload,
);

criterion_main!(benches);
