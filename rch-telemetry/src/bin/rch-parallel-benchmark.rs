//! Operator entry point for the paired compilation throughput workload.

use clap::Parser;
use rch_telemetry::benchmarks::parallel_compilation::ParallelCompilationBenchmark;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Measure a fixed Rust crate graph serially and in parallel on this machine")]
struct Args {
    /// Compiler/proxy to resolve. Its selected sysroot supplies every compiler.
    #[arg(long, default_value = "rustc")]
    rustc: PathBuf,
    /// Maximum parallel compilers (also bounded by available parallelism).
    /// Omit to use available parallelism, capped at 16.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=16))]
    jobs: Option<u32>,
    /// One timeout for probes, warmup, both passes and output verification.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=600))]
    timeout_secs: u64,
    /// Emit raw, versioned measurements plus derived rates as JSON.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let mut benchmark = ParallelCompilationBenchmark {
        rustc_path: args.rustc,
        timeout: Duration::from_secs(args.timeout_secs),
        ..Default::default()
    };
    if let Some(jobs) = args.jobs {
        benchmark.jobs = jobs as usize;
    }
    match benchmark.run() {
        Ok(measurement) => {
            if args.json {
                let report = serde_json::json!({
                    "measurement": measurement,
                    "crates_per_second": measurement.crates_per_second(),
                    "parallel_speedup": measurement.parallel_speedup(),
                });
                println!("{report}");
            } else {
                println!("Workload version: {}", measurement.workload_version);
                println!("Crates per pass: {}", measurement.crates);
                println!("Parallel compilers: {}", measurement.jobs);
                println!("Serial wall time: {} ms", measurement.serial_ms);
                println!("Parallel wall time: {} ms", measurement.parallel_ms);
                println!(
                    "Compilation throughput: {:.3} crates/s",
                    measurement.crates_per_second().unwrap_or_default()
                );
                println!(
                    "Observed parallel speedup: {:.3}x",
                    measurement.parallel_speedup().unwrap_or_default()
                );
                println!("Outputs: byte-identical across both passes");
                println!("Compiler:\n{}", measurement.rustc_version);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if args.json {
                println!("{}", serde_json::json!({"error": error}));
            } else {
                eprintln!("{error}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_budget_and_compiler_are_not_lost() {
        let args = Args::try_parse_from([
            "rch-parallel-benchmark",
            "--jobs",
            "4",
            "--timeout-secs",
            "90",
            "--rustc",
            "/toolchains/custom/bin/rustc",
            "--json",
        ])
        .unwrap();
        assert_eq!(args.jobs, Some(4));
        assert_eq!(args.timeout_secs, 90);
        assert_eq!(args.rustc, PathBuf::from("/toolchains/custom/bin/rustc"));
        assert!(args.json);
    }

    #[test]
    fn invalid_concurrency_and_time_budgets_are_cli_errors() {
        for (flag, value) in [
            ("--jobs", "0"),
            ("--jobs", "17"),
            ("--jobs", "-1"),
            ("--timeout-secs", "0"),
            ("--timeout-secs", "601"),
            ("--timeout-secs", "invalid"),
        ] {
            assert!(Args::try_parse_from(["rch-parallel-benchmark", flag, value]).is_err());
        }
    }
}
