//! UI performance benchmarks for rich_rust integration.
//!
//! These benchmarks focus on "UI overhead" primitives in `rch-common::ui`.
//! The benches intentionally force `OutputContext::Plain` so the progress
//! renderers do not emit any terminal output during benchmarking.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rch_common::ui::{
    AnimatedSpinner, CelebrationSummary, CompilationProgress, CompletionCelebration, ErrorPanel,
    ErrorSeverity, Icons, OutputContext, PipelineProgress, PipelineStage, RchTheme, SpinnerStyle,
    TransferProgress,
};
use std::hint::black_box;

/// Baseline: Output context detection should be fast.
fn bench_context_detection(c: &mut Criterion) {
    c.bench_function("ui/context_detect", |b| b.iter(OutputContext::detect));
}

/// Benchmark Icons retrieval (with fallback logic).
fn bench_icons(c: &mut Criterion) {
    let ctx = OutputContext::Plain;
    let mut group = c.benchmark_group("ui/icons");

    group.bench_function("check", |b| b.iter(|| Icons::check(black_box(ctx))));
    group.bench_function("cross", |b| b.iter(|| Icons::cross(black_box(ctx))));
    group.bench_function("warning", |b| b.iter(|| Icons::warning(black_box(ctx))));
    group.bench_function("worker", |b| b.iter(|| Icons::worker(black_box(ctx))));

    group.finish();
}

/// Benchmark theme constant access.
fn bench_theme(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/theme");

    group.bench_function("success", |b| b.iter(|| RchTheme::SUCCESS));
    group.bench_function("error", |b| b.iter(|| RchTheme::ERROR));
    group.bench_function("primary", |b| b.iter(|| RchTheme::PRIMARY));

    group.finish();
}

/// Benchmark ErrorPanel creation and JSON serialization.
fn bench_error_panel(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/error_panel");

    group.bench_function("create_simple", |b| {
        b.iter(|| ErrorPanel::new("RCH-E100", "Connection Failed").message("Could not connect"))
    });

    group.bench_function("create_full", |b| {
        b.iter(|| {
            ErrorPanel::new("RCH-E100", "Connection Failed")
                .with_severity(ErrorSeverity::Error)
                .message("Could not establish SSH connection to worker")
                .context("Host", "build1.internal (192.168.1.50:22)")
                .context("Timeout", "30s elapsed")
                .suggestion("Check if worker is online: ssh build1.internal")
                .suggestion("Verify SSH key: ssh-add -l")
                .suggestion("Run: rch workers probe build1 --verbose")
        })
    });

    let sample = ErrorPanel::new("RCH-E100", "Test Error").message("Test message");
    group.bench_function("serialize_json", |b| {
        b.iter(|| serde_json::to_string(black_box(&sample)))
    });
    group.bench_function("serialize_compact_json", |b| {
        b.iter(|| sample.to_json_compact().unwrap())
    });

    group.finish();
}

/// Benchmark TransferProgress updates from rsync progress2 lines.
fn bench_transfer_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/transfer_progress");
    let ctx = OutputContext::Plain;

    const SAMPLE_LINE: &str = "1.00M  50%   10.00MB/s    0:00:05 (xfr#1, to-chk=9/10)";

    group.bench_function("create", |b| {
        b.iter(|| TransferProgress::upload(black_box(ctx), "Upload", false))
    });

    let mut progress = TransferProgress::upload(ctx, "Upload", false);
    group.bench_function("update_from_line", |b| {
        b.iter(|| progress.update_from_line(black_box(SAMPLE_LINE)))
    });

    group.bench_function("update_burst_1000", |b| {
        b.iter(|| {
            let mut p = TransferProgress::upload(ctx, "Upload", false);
            for _ in 0..1000 {
                p.update_from_line(SAMPLE_LINE);
            }
        })
    });

    group.finish();
}

/// Benchmark CompilationProgress updates from cargo output lines.
fn bench_compilation_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/compile_progress");
    let ctx = OutputContext::Plain;

    let lines = [
        ("compiling", "   Compiling serde v1.0.193"),
        (
            "checking",
            "    Checking rch-common v0.1.0 (/path/to/crate)",
        ),
        ("linking", "   Linking target/release/myapp"),
        (
            "testing",
            "     Running unittests src/lib.rs (target/debug/deps/rch-abcdef)",
        ),
        ("warning", "warning: 5 warnings emitted"),
        (
            "finished",
            "    Finished `release` profile [optimized] target(s) in 45.23s",
        ),
    ];

    for (name, line) in lines {
        group.bench_with_input(
            BenchmarkId::new("update_from_line", name),
            &line,
            |b, line| {
                let mut p = CompilationProgress::new(ctx, "worker1", false);
                b.iter(|| p.update_from_line(black_box(line)));
            },
        );
    }

    group.bench_function("burst_200_lines", |b| {
        b.iter(|| {
            let mut p = CompilationProgress::new(ctx, "worker1", false);
            for _ in 0..200 {
                p.update_from_line("   Compiling tokio v1.35.1");
            }
            p.update_from_line("    Finished `release` profile [optimized] target(s) in 45.23s");
        })
    });

    group.finish();
}

/// Benchmark PipelineProgress for multi-stage operations.
fn bench_pipeline_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/pipeline_progress");
    let ctx = OutputContext::Plain;

    group.bench_function("create", |b| {
        b.iter(|| PipelineProgress::new(black_box(ctx), "worker1", false))
    });

    group.bench_function("stage_transitions", |b| {
        b.iter(|| {
            let mut p = PipelineProgress::new(ctx, "worker1", false);
            p.start_stage(PipelineStage::WorkspaceAnalysis);
            p.set_stage_detail("425 files");
            p.complete_stage();
            p.start_stage(PipelineStage::Upload);
            p.set_stage_detail("78.1 MB");
            p.complete_stage();
        })
    });

    group.bench_function("full_run", |b| {
        b.iter(|| {
            let mut p = PipelineProgress::new(ctx, "worker1", false);
            for stage in PipelineStage::all() {
                p.start_stage(*stage);
                p.set_stage_detail(stage.short_label());
                p.complete_stage();
            }
            p.finish();
        })
    });

    group.finish();
}

/// Benchmark AnimatedSpinner creation and ticks (no terminal output in Plain context).
fn bench_spinner(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/spinner");
    let ctx = OutputContext::Plain;

    group.bench_function("create", |b| {
        b.iter(|| AnimatedSpinner::with_style(black_box(ctx), "Loading...", SpinnerStyle::Dots))
    });

    group.bench_function("tick_100", |b| {
        b.iter(|| {
            let mut s = AnimatedSpinner::with_style(ctx, "Loading...", SpinnerStyle::Dots);
            for _ in 0..100 {
                s.tick();
            }
        })
    });

    group.finish();
}

/// Benchmark building the completion summary and wrapper struct.
fn bench_celebration_summary(c: &mut Criterion) {
    let mut group = c.benchmark_group("ui/celebration");

    group.bench_function("summary_builder", |b| {
        b.iter(|| {
            CelebrationSummary::new("project-x", 52_000)
                .worker("worker1")
                .crates_compiled(Some(42))
                .cache_hit(Some(true))
                .target(Some("debug".to_string()))
                .quiet(true)
        })
    });

    let summary = CelebrationSummary::new("project-x", 52_000)
        .worker("worker1")
        .crates_compiled(Some(42))
        .cache_hit(Some(true))
        .target(Some("debug".to_string()))
        .quiet(true);
    group.bench_function("celebration_new", |b| {
        b.iter(|| CompletionCelebration::new(black_box(summary.clone())))
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
    bench_spinner,
    bench_celebration_summary,
);

criterion_main!(benches);
