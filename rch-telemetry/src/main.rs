//! Telemetry collection CLI for RCH workers.
#![forbid(unsafe_code)]

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rch_telemetry::collect::cpu::CpuTelemetry;
use rch_telemetry::collect::disk::DiskCollector;
use rch_telemetry::collect::memory::MemoryTelemetry;
use rch_telemetry::collect::network::NetworkCollector;
use rch_telemetry::protocol::WorkerTelemetry;
use rch_telemetry::{LogConfig, init_logging};
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "rch-telemetry", about = "Telemetry collection for RCH workers")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Collect a telemetry snapshot and print it
    Collect {
        /// Output format (json or pretty)
        #[arg(long, default_value = "json")]
        format: OutputFormat,

        /// Sampling window in milliseconds for rate-based metrics
        #[arg(long, default_value_t = 200)]
        sample_ms: u64,

        /// Disable disk telemetry collection
        #[arg(long)]
        no_disk: bool,

        /// Disable network telemetry collection
        #[arg(long)]
        no_network: bool,

        /// Override worker ID (defaults to RCH_WORKER_ID or HOSTNAME)
        #[arg(long)]
        worker_id: Option<String>,
    },
}

#[derive(ValueEnum, Clone, Copy)]
enum OutputFormat {
    Json,
    Pretty,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut log_config = LogConfig::from_env("info").with_stderr();
    if cli.verbose {
        log_config = log_config.with_level("debug");
    }
    let _logging_guards = init_logging(&log_config)?;

    match cli.command {
        Commands::Collect {
            format,
            sample_ms,
            no_disk,
            no_network,
            worker_id,
        } => {
            let worker_id = resolve_worker_id(worker_id);
            let telemetry = collect_telemetry(sample_ms, !no_disk, !no_network, worker_id)?;

            let output = match format {
                OutputFormat::Json => telemetry.to_json()?,
                OutputFormat::Pretty => telemetry.to_json_pretty()?,
            };

            println!("{}", output);
        }
    }

    Ok(())
}

fn resolve_worker_id(override_id: Option<String>) -> String {
    if let Some(id) = override_id {
        return id;
    }

    if let Ok(id) = std::env::var("RCH_WORKER_ID") && !id.trim().is_empty() {
        return id;
    }

    if let Ok(id) = std::env::var("HOSTNAME") && !id.trim().is_empty() {
        return id;
    }

    "unknown-worker".to_string()
}

fn collect_telemetry(
    sample_ms: u64,
    include_disk: bool,
    include_network: bool,
    worker_id: String,
) -> Result<WorkerTelemetry> {
    let start = Instant::now();

    let (_baseline_cpu, prev_stats, prev_per_core) = CpuTelemetry::collect(None, None)?;

    let mut disk_collector = if include_disk {
        let mut collector = DiskCollector::new();
        let _ = collector.collect()?; // warm-up sample
        Some(collector)
    } else {
        None
    };

    let mut network_collector = if include_network {
        let mut collector = NetworkCollector::new();
        let _ = collector.collect()?; // warm-up sample
        Some(collector)
    } else {
        None
    };

    if sample_ms > 0 {
        std::thread::sleep(Duration::from_millis(sample_ms));
    }

    let (cpu, _curr_stats, _curr_per_core) =
        CpuTelemetry::collect(Some(&prev_stats), Some(&prev_per_core))?;
    let memory = MemoryTelemetry::collect()?;

    let disk = match disk_collector.as_mut() {
        Some(collector) => collector.collect()?,
        None => None,
    };

    let network = match network_collector.as_mut() {
        Some(collector) => Some(collector.collect()?),
        None => None,
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(WorkerTelemetry::new(
        worker_id,
        cpu,
        memory,
        disk,
        network,
        duration_ms,
    ))
}
