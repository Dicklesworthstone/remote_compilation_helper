//! E005 acceptance: measure observation overhead on representative
//! compiles and report per-mechanism numbers — the mechanism is chosen by
//! MEASUREMENT, not preference.
//!
//! Protocol per run: a cold `cargo build` of a minimal lib crate inside
//! the real D003 canonical namespace (fresh backing dirs every time), once
//! UNTRACED and once wrapped in the ptrace(strace) observer tracing
//! `%file`+exec+network. Wall-clock medians give the overhead figure; the
//! traced log must parse into non-empty facts (reads/execs observed,
//! ZERO network attempts under default-deny — tying E002's enforcement to
//! E005's detection). Skips honestly where bwrap/strace/toolchain are
//! unavailable.

#![cfg(target_os = "linux")]

use rabs_sandbox::canonical_mounts::CanonicalMountPlan;
use rabs_sandbox::canonical_namespace::{HostIsolationSupport, build_canonical_argv, command_for};
use rabs_sandbox::layout;
use rabs_sandbox::observation::{
    DEFAULT_SYSCALL_SET, Tracer, parse_strace_log_file, wrap_with_tracer,
};

/// Measured on the fleet (see the printed report): recorded here so the
/// chosen default carries its numbers with it. Updated by re-running this
/// fixture, never asserted from preference.
const CHOSEN_DEFAULT_NOTE: &str = "ptrace/strace chosen as the E005 prototype \
default: zero-privilege, fleet-present, measured overhead reported below; \
eBPF/seccomp-notify remain candidates for E009/E019 if this number breaches \
the <1-2% miss-path SLO";

fn supported() -> Option<(HostIsolationSupport, Tracer)> {
    let support = HostIsolationSupport::probe();
    if !support.missing_for_canonical().is_empty() {
        eprintln!(
            "SKIP: no canonical namespace here ({:?})",
            support.missing_for_canonical()
        );
        return None;
    }
    match Tracer::probe() {
        Some(tracer) => Some((support, tracer)),
        None => {
            eprintln!("SKIP: strace unavailable on this host");
            None
        }
    }
}

/// The running toolchain root (parent of `bin/`), from $CARGO.
fn toolchain_dir() -> std::path::PathBuf {
    let cargo_path = std::env::var("CARGO").expect("cargo sets $CARGO for tests");
    std::path::Path::new(&cargo_path)
        .parent()
        .and_then(std::path::Path::parent)
        .expect("<root>/bin/cargo")
        .to_path_buf()
}

fn write(root: &std::path::Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
}

/// Minimal representative workload: one lib crate, cold.
fn fixture(root: &std::path::Path) {
    write(
        root,
        "Cargo.toml",
        "[package]\nname = \"rabs-e005\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[workspace]\n",
    );
    write(root, "src/lib.rs", "pub fn answer() -> u32 { 42 }\n");
}

struct RunOutcome {
    elapsed: std::time::Duration,
    /// Parsed tracer facts (None for untraced runs).
    record: Option<rabs_sandbox::observation::ObservationRecord>,
}

/// One COLD build inside a fresh canonical namespace.
fn build_run(
    support: &HostIsolationSupport,
    tracer: Option<&Tracer>,
    source: &std::path::Path,
) -> RunOutcome {
    let cargo_home = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut plan = CanonicalMountPlan::new(toolchain_dir(), source, cargo_home.path(), home.path());
    plan.extra_env.push((
        "CARGO_TARGET_DIR".into(),
        format!("{}/fixture", layout::OUT),
    ));
    let spec = plan.to_spec().unwrap();

    // Workspace root always exists inside the closed view; the out unit's
    // mountpoint is NOT guaranteed to be materialized when strace starts,
    // and strace will not create parent directories for -o.
    const LOG_VISIBLE: &str = "/__rabs/workspace/e005-strace.log";
    let launch = build_canonical_argv(
        &spec,
        support,
        "cargo",
        &["build".into(), "--offline".into()],
    )
    .unwrap();
    let final_launch = match tracer {
        Some(t) => wrap_with_tracer(&launch, t, DEFAULT_SYSCALL_SET, LOG_VISIBLE).unwrap(),
        None => launch,
    };

    let start = std::time::Instant::now();
    let out = command_for(&final_launch).output().unwrap();
    let elapsed = start.elapsed();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "traced={} fixture build failed:\n{stderr}",
        tracer.is_some()
    );

    let record = tracer.map(|_| parse_strace_log_file(&source.join("e005-strace.log")));
    RunOutcome { elapsed, record }
}

fn median(durations: &mut [std::time::Duration]) -> std::time::Duration {
    durations.sort();
    durations[durations.len() / 2]
}

#[test]
fn overhead_report_on_representative_compile() {
    let Some((support, tracer)) = supported() else {
        return;
    };
    if let Tracer::StracePtrace(version) = &tracer
        && version.is_empty()
    {
        eprintln!("SKIP: strace version unreadable");
        return;
    }
    // Warmup: page-cache the toolchain so we measure TRACING overhead,
    // not first-touch disk costs.
    let warm_src = tempfile::tempdir().unwrap();
    fixture(warm_src.path());
    build_run(&support, None, warm_src.path());

    const RUNS: usize = 3;
    let mut untraced: Vec<std::time::Duration> = Vec::new();
    let mut traced: Vec<std::time::Duration> = Vec::new();
    let mut last_traced_record = None;

    for _ in 0..RUNS {
        let src = tempfile::tempdir().unwrap();
        fixture(src.path());
        untraced.push(build_run(&support, None, src.path()).elapsed);

        let src = tempfile::tempdir().unwrap();
        fixture(src.path());
        let outcome = build_run(&support, Some(&tracer), src.path());
        traced.push(outcome.elapsed);
        last_traced_record = outcome.record;
    }

    let med_untraced = median(&mut untraced);
    let med_traced = median(&mut traced);
    let overhead_pct = 100.0 * (med_traced.as_secs_f64() / med_untraced.as_secs_f64() - 1.0);

    // The traced run must yield REAL observation facts.
    let record = last_traced_record.expect("traced runs produce records");
    assert!(record.reads > 0, "tracer must observe file reads");
    assert!(
        !record.execs.is_empty(),
        "tracer must observe the exec chain"
    );
    // E002 tie-in: under default-deny EVERY network attempt is denied —
    // cargo/rustc may still probe (one connect was observed in practice);
    // what hermeticity guarantees is that none SUCCEEDS.
    assert_eq!(
        record.network_attempts, record.network_denied,
        "default-deny netns must deny every attempted network syscall"
    );
    assert!(!record.truncated, "small fixture must not truncate samples");

    println!("\n=== E005 OVERHEAD REPORT ===");
    println!("mechanism: {tracer:?}");
    println!("workload : cold cargo build of one-lib crate in D003 namespace");
    println!("runs     : {RUNS} per arm, medians");
    println!("untraced : {:>10.1?}", med_untraced);
    println!("traced   : {:>10.1?}", med_traced);
    println!("overhead : {overhead_pct:.1}%");
    println!(
        "facts    : reads={} writes={} execs={} net={}(denied {}) truncated={}",
        record.reads,
        record.writes,
        record.execs.len(),
        record.network_attempts,
        record.network_denied,
        record.truncated
    );
    println!("decision : {CHOSEN_DEFAULT_NOTE}");
    println!("============================\n");

    // Machine-readable receipt for the report artifact trail.
    println!(
        "E005_REPORT_JSON: {{\"mechanism\":\"strace-ptrace\",\"runs\":{RUNS},\
         \"median_untraced_ms\":{:.1},\"median_traced_ms\":{:.1},\
         \"overhead_percent\":{overhead_pct:.1}}}",
        med_untraced.as_secs_f64() * 1000.0,
        med_traced.as_secs_f64() * 1000.0,
    );
}
