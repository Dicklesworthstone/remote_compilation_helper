//! Benchmarks for command classification to verify AGENTS.md performance budgets.
//!
//! Performance requirements from AGENTS.md:
//! - Non-compilation commands: < 1ms (95th percentile)
//! - Compilation decision: < 5ms (95th percentile)
//!
//! In practice, we aim for microsecond-level performance.

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use rch_common::classify_command;

/// Tier 0 commands that should be instantly rejected.
/// Target: < 1 microsecond
const TIER0_REJECT: &[&str] = &[
    "cd /tmp",
    "ls -la",
    "cat file.txt",
    "git status",
    "echo hello",
    "pwd",
    "whoami",
    "date",
    "env",
    "export FOO=bar",
];

/// Commands with structure that prevents interception.
/// Target: < 5 microseconds
const STRUCTURE_REJECT: &[&str] = &[
    "cargo build 2>&1 | grep error",
    "cargo build > build.log",
    "cargo build &",
    "cargo build && echo done",
    "cargo build; ls",
    "$(cargo build --message-format=json)",
];

/// Compilation commands that should be matched.
/// Target: < 5 microseconds
const COMPILATION_MATCH: &[&str] = &[
    "cargo build",
    "cargo build --release",
    "cargo test",
    "cargo check",
    "cargo clippy",
    "cargo run",
    "rustc lib.rs",
    "gcc main.c -o main",
    "g++ main.cpp -o main",
    "clang main.c -o main",
    "make all",
    "make -j8",
    "ninja",
];

/// Never-intercept commands (match pattern but should reject).
/// Target: < 5 microseconds
const NEVER_INTERCEPT: &[&str] = &[
    "cargo install ripgrep",
    "cargo publish",
    "cargo fmt",
    "cargo clean",
    "cargo new myproject",
    "cargo --version",
    "rustc --version",
    "gcc --version",
    "make --version",
];

/// Complex commands (realistic usage).
/// Target: < 5 microseconds
const COMPLEX_COMMANDS: &[&str] = &[
    "RUSTFLAGS=\"-C target-cpu=native\" cargo build --release --features all",
    "cargo build --release --target x86_64-unknown-linux-musl",
    "cargo test --workspace --all-features -- --test-threads=1",
    "cargo clippy --all-targets --all-features -- -D warnings",
];

fn bench_tier0_reject(c: &mut Criterion) {
    let mut group = c.benchmark_group("classifier/tier0_reject");
    for cmd in TIER0_REJECT {
        let short_name = if cmd.len() > 15 { &cmd[..15] } else { cmd };
        group.bench_with_input(BenchmarkId::new("cmd", short_name), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }
    group.finish();
}

fn bench_structure_reject(c: &mut Criterion) {
    let mut group = c.benchmark_group("classifier/structure_reject");
    for cmd in STRUCTURE_REJECT {
        let short_name = if cmd.len() > 20 { &cmd[..20] } else { cmd };
        group.bench_with_input(BenchmarkId::new("cmd", short_name), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }
    group.finish();
}

fn bench_compilation_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("classifier/compilation_match");
    for cmd in COMPILATION_MATCH {
        let short_name = if cmd.len() > 20 { &cmd[..20] } else { cmd };
        group.bench_with_input(BenchmarkId::new("cmd", short_name), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }
    group.finish();
}

fn bench_never_intercept(c: &mut Criterion) {
    let mut group = c.benchmark_group("classifier/never_intercept");
    for cmd in NEVER_INTERCEPT {
        let short_name = if cmd.len() > 20 { &cmd[..20] } else { cmd };
        group.bench_with_input(BenchmarkId::new("cmd", short_name), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }
    group.finish();
}

fn bench_complex_commands(c: &mut Criterion) {
    let mut group = c.benchmark_group("classifier/complex");
    for cmd in COMPLEX_COMMANDS {
        let short_name = if cmd.len() > 25 { &cmd[..25] } else { cmd };
        group.bench_with_input(BenchmarkId::new("cmd", short_name), cmd, |b, cmd| {
            b.iter(|| classify_command(black_box(cmd)))
        });
    }
    group.finish();
}

/// Batch benchmark simulating realistic workload.
fn bench_batch_throughput(c: &mut Criterion) {
    let all_commands: Vec<&str> = TIER0_REJECT
        .iter()
        .chain(STRUCTURE_REJECT.iter())
        .chain(COMPILATION_MATCH.iter())
        .chain(NEVER_INTERCEPT.iter())
        .copied()
        .collect();

    c.bench_function("classifier/batch_100", |b| {
        b.iter(|| {
            for cmd in &all_commands {
                let _ = classify_command(black_box(cmd));
            }
        })
    });
}

criterion_group!(
    benches,
    bench_tier0_reject,
    bench_structure_reject,
    bench_compilation_match,
    bench_never_intercept,
    bench_complex_commands,
    bench_batch_throughput,
);

criterion_main!(benches);
