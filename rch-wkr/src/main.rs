//! Remote Compilation Helper - Worker Agent
//!
//! The worker agent runs on remote machines and executes compilation
//! commands, manages project caches, and responds to health checks.

#![forbid(unsafe_code)]

mod cache;
mod executor;
mod toolchain;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rch_common::WorkerCapabilities;
use rch_common::{LogConfig, init_logging};
use tracing::info;

#[derive(Parser)]
#[command(name = "rch-wkr")]
#[command(author, version, about = "RCH worker agent - remote execution")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a compilation command
    Execute {
        /// Working directory
        #[arg(short, long)]
        workdir: String,

        /// Command to execute
        #[arg(short, long)]
        command: String,

        /// Toolchain to use (e.g., "nightly", "nightly-2024-01-15", "stable")
        ///
        /// If specified, the worker will ensure this toolchain is available
        /// (installing via rustup if necessary) and wrap the command with
        /// `rustup run <toolchain>`.
        #[arg(short, long)]
        toolchain: Option<String>,
    },

    /// Respond to health check
    Health,

    /// Report system info (human-readable)
    Info,

    /// Report runtime capabilities (JSON output for daemon)
    ///
    /// Returns a JSON object with detected runtime versions for
    /// Rust, Bun, Node.js, and npm. Used by the daemon during
    /// health checks to populate WorkerCapabilities.
    Capabilities,

    /// Clean up old project caches
    Cleanup {
        /// Maximum age in hours
        #[arg(long, default_value = "168")]
        max_age_hours: u64,
    },

    /// Run a benchmark
    Benchmark,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let mut log_config = LogConfig::from_env("info").with_stderr();
    if cli.verbose {
        log_config = log_config.with_level("debug");
    }
    let _logging_guards = init_logging(&log_config)?;

    match cli.command {
        Commands::Execute {
            workdir,
            command,
            toolchain,
        } => {
            // Prepare the command, optionally wrapping with toolchain
            let final_command = if let Some(tc_str) = toolchain {
                // Parse toolchain string and ensure it's available
                let tc_info = toolchain::parse_toolchain_string(&tc_str);

                // Ensure toolchain is available (install if needed)
                match toolchain::ensure_toolchain(&tc_info) {
                    Ok(()) => {
                        info!("Toolchain {} ready", tc_str);
                    }
                    Err(e) => {
                        // Log but continue - fail-open behavior
                        tracing::warn!(
                            "Failed to ensure toolchain {}: {}. Continuing with default.",
                            tc_str,
                            e
                        );
                        // Fall through to execute without toolchain wrapping

                        // Touch the project cache to prevent cleanup
                        cache::touch_project(std::path::Path::new(&workdir));

                        return match executor::execute(&workdir, &command).await {
                            Ok(()) => Ok(()),
                            Err(err) => {
                                if let Some(failure) = err.downcast_ref::<executor::CommandFailed>()
                                {
                                    std::process::exit(failure.exit_code);
                                }
                                Err(err)
                            }
                        };
                    }
                }

                // Wrap command with rustup run
                rch_common::wrap_command_with_toolchain(&command, Some(&tc_info))
            } else {
                command
            };

            // Touch the project cache to prevent cleanup
            cache::touch_project(std::path::Path::new(&workdir));

            match executor::execute(&workdir, &final_command).await {
                Ok(()) => Ok(()),
                Err(err) => {
                    if let Some(failure) = err.downcast_ref::<executor::CommandFailed>() {
                        std::process::exit(failure.exit_code);
                    }
                    Err(err)
                }
            }
        }
        Commands::Health => {
            println!("OK");
            Ok(())
        }
        Commands::Info => {
            print_system_info();
            Ok(())
        }
        Commands::Capabilities => {
            let capabilities = probe_capabilities();
            // Output as JSON for the daemon to parse
            println!("{}", serde_json::to_string(&capabilities)?);
            Ok(())
        }
        Commands::Cleanup { max_age_hours } => cache::cleanup(max_age_hours).await,
        Commands::Benchmark => run_benchmark().await,
    }
}

fn print_system_info() {
    use std::process::Command;

    println!("=== System Info ===");

    // CPU cores
    if let Ok(output) = Command::new("nproc").output()
        && let Ok(cores) = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u32>()
    {
        println!("Cores: {}", cores);
    }

    // Memory
    if let Ok(output) = Command::new("free").args(["-h"]).output() {
        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.starts_with("Mem:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    println!("Memory: {}", parts[1]);
                }
            }
        }
    }

    // Rust toolchain
    println!("\n=== Rust ===");
    if let Ok(output) = Command::new("rustc").args(["--version"]).output() {
        println!("rustc: {}", String::from_utf8_lossy(&output.stdout).trim());
    }
    if let Ok(output) = Command::new("cargo").args(["--version"]).output() {
        println!("cargo: {}", String::from_utf8_lossy(&output.stdout).trim());
    }

    // C/C++ compilers
    println!("\n=== C/C++ ===");
    if let Ok(output) = Command::new("gcc").args(["--version"]).output() {
        let first_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!("gcc: {}", first_line);
    }
    if let Ok(output) = Command::new("clang").args(["--version"]).output() {
        let first_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!("clang: {}", first_line);
    }

    // Tools
    println!("\n=== Tools ===");
    if let Ok(output) = Command::new("zstd").args(["--version"]).output() {
        println!("zstd: {}", String::from_utf8_lossy(&output.stdout).trim());
    }
    if let Ok(output) = Command::new("rsync").args(["--version"]).output() {
        let first_line = String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        println!("rsync: {}", first_line);
    }

    // JavaScript/TypeScript runtimes
    println!("\n=== JavaScript Runtimes ===");
    if let Ok(output) = Command::new("bun").args(["--version"]).output() {
        if output.status.success() {
            println!("bun: {}", String::from_utf8_lossy(&output.stdout).trim());
        }
    } else {
        println!("bun: not installed");
    }
    if let Ok(output) = Command::new("node").args(["--version"]).output() {
        if output.status.success() {
            println!("node: {}", String::from_utf8_lossy(&output.stdout).trim());
        }
    } else {
        println!("node: not installed");
    }
    if let Ok(output) = Command::new("npm").args(["--version"]).output() {
        if output.status.success() {
            println!("npm: {}", String::from_utf8_lossy(&output.stdout).trim());
        }
    } else {
        println!("npm: not installed");
    }
}

/// Probe runtime capabilities and return structured data.
///
/// This function detects installed runtimes (Rust, Bun, Node.js, npm)
/// and returns a WorkerCapabilities struct suitable for JSON serialization.
fn probe_capabilities() -> WorkerCapabilities {
    use std::process::Command;

    let mut capabilities = WorkerCapabilities::new();

    // Probe rustc version
    if let Ok(output) = Command::new("rustc").args(["--version"]).output()
        && output.status.success()
    {
        let version_str = String::from_utf8_lossy(&output.stdout);
        capabilities.rustc_version = parse_rustc_version_stdout(&version_str);
    }

    // Probe bun version
    let bun_cmd = if let Ok(output) = Command::new("bun").args(["--version"]).output() {
        Some(output)
    } else {
        // Fallback: try ~/.bun/bin/bun
        if let Ok(home) = std::env::var("HOME") {
            let bun_path = std::path::Path::new(&home).join(".bun/bin/bun");
            if bun_path.exists() {
                Command::new(bun_path).args(["--version"]).output().ok()
            } else {
                None
            }
        } else {
            None
        }
    };

    if let Some(output) = bun_cmd
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            capabilities.bun_version = Some(version);
        }
    }

    // Probe node version
    if let Ok(output) = Command::new("node").args(["--version"]).output()
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout);
        capabilities.node_version = parse_node_version_stdout(&version);
    }

    // Probe npm version
    if let Ok(output) = Command::new("npm").args(["--version"]).output()
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            capabilities.npm_version = Some(version);
        }
    }

    // Probe system health metrics (bd-3eaa)
    capabilities.num_cpus = probe_num_cpus();
    if let Some((load1, load5, load15)) = probe_load_average() {
        capabilities.load_avg_1 = Some(load1);
        capabilities.load_avg_5 = Some(load5);
        capabilities.load_avg_15 = Some(load15);
    }
    if let Some((free_gb, total_gb)) = probe_disk_space() {
        capabilities.disk_free_gb = Some(free_gb);
        capabilities.disk_total_gb = Some(total_gb);
    }

    capabilities
}

/// Probe number of CPU cores.
fn probe_num_cpus() -> Option<u32> {
    use std::process::Command;

    // Try nproc first (Linux)
    if let Ok(output) = Command::new("nproc").output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(n) = parse_nproc_stdout(&stdout) {
            return Some(n);
        }
    }

    // Fallback: sysctl on macOS
    if let Ok(output) = Command::new("sysctl").args(["-n", "hw.ncpu"]).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(n) = parse_nproc_stdout(&stdout) {
            return Some(n);
        }
    }

    None
}

/// Probe load average (1, 5, 15 minute averages).
fn probe_load_average() -> Option<(f64, f64, f64)> {
    // Try /proc/loadavg first (Linux)
    if let Ok(contents) = std::fs::read_to_string("/proc/loadavg")
        && let Some(avg) = parse_proc_loadavg(&contents)
    {
        return Some(avg);
    }

    // Fallback: uptime command (macOS and Linux)
    if let Ok(output) = std::process::Command::new("uptime").output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return parse_uptime_loadavg(&stdout);
    }

    None
}

/// Probe disk space for /tmp (free and total in GB).
fn probe_disk_space() -> Option<(f64, f64)> {
    use std::process::Command;

    // Use df to get disk space for /tmp
    // Try POSIX format first (works on Linux and macOS)
    if let Ok(output) = Command::new("df").args(["-P", "-k", "/tmp"]).output()
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some((total_kb, avail_kb)) = parse_df_posix_kb(&stdout) {
            let total_gb = total_kb as f64 / (1024.0 * 1024.0);
            let free_gb = avail_kb as f64 / (1024.0 * 1024.0);
            return Some((free_gb, total_gb));
        }
    }

    None
}

fn parse_rustc_version_stdout(stdout: &str) -> Option<String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut tokens = trimmed.split_whitespace();
    let first = tokens.next()?;
    if first == "rustc"
        && let Some(version) = tokens.next()
        && !version.is_empty()
    {
        return Some(version.to_string());
    }

    Some(trimmed.to_string())
}

fn parse_node_version_stdout(stdout: &str) -> Option<String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.strip_prefix('v').unwrap_or(trimmed).to_string())
}

fn parse_nproc_stdout(stdout: &str) -> Option<u32> {
    stdout.trim().parse::<u32>().ok()
}

fn parse_proc_loadavg(contents: &str) -> Option<(f64, f64, f64)> {
    let parts: Vec<&str> = contents.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let load1 = parts[0].parse::<f64>().ok()?;
    let load5 = parts[1].parse::<f64>().ok()?;
    let load15 = parts[2].parse::<f64>().ok()?;
    Some((load1, load5, load15))
}

fn parse_uptime_loadavg(output: &str) -> Option<(f64, f64, f64)> {
    // Parse "load average: 1.23, 4.56, 7.89" or "load averages: 1.23 4.56 7.89"
    let idx = output
        .find("load average:")
        .or_else(|| output.find("load averages:"))?;
    let after = &output[idx..];

    let colon_idx = after.find(':')?;
    let numbers_part = &after[colon_idx + 1..];

    let parts: Vec<&str> = numbers_part
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .collect();

    if parts.len() < 3 {
        return None;
    }

    let load1 = parts[0].parse::<f64>().ok()?;
    let load5 = parts[1].parse::<f64>().ok()?;
    let load15 = parts[2].parse::<f64>().ok()?;
    Some((load1, load5, load15))
}

fn parse_df_posix_kb(stdout: &str) -> Option<(u64, u64)> {
    // Skip header line, parse first data line.
    // POSIX format: Filesystem 1024-blocks Used Available Capacity Mounted on
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            // parts[1] = total 1K blocks, parts[3] = available 1K blocks
            let total_kb = parts[1].parse::<u64>().ok()?;
            let avail_kb = parts[3].parse::<u64>().ok()?;
            return Some((total_kb, avail_kb));
        }
    }
    None
}

async fn run_benchmark() -> Result<()> {
    info!("Running benchmark...");

    // Create a simple benchmark project with a unique name
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_dir = std::env::temp_dir().join(format!("rch-benchmark-{}", timestamp));
    std::fs::create_dir_all(&temp_dir)?;

    // Write a simple Rust project
    let cargo_toml = r#"
[package]
name = "benchmark"
version = "0.1.0"
edition = "2021"

[dependencies]
"#;
    std::fs::write(temp_dir.join("Cargo.toml"), cargo_toml)?;

    let main_rs = r#"
fn main() {
    let sum: u64 = (1..1000000).sum();
    println!("Sum: {}", sum);
}
"#;
    std::fs::create_dir_all(temp_dir.join("src"))?;
    std::fs::write(temp_dir.join("src/main.rs"), main_rs)?;

    // Time the build
    let start = std::time::Instant::now();
    let output = std::process::Command::new("cargo")
        .args(["build", "--release"])
        .current_dir(&temp_dir)
        .output()?;

    let elapsed = start.elapsed();

    if output.status.success() {
        let score = 100.0 / elapsed.as_secs_f64();
        println!("Benchmark completed in {:.2}s", elapsed.as_secs_f64());
        println!("Score: {:.1}", score.min(100.0));
    } else {
        println!(
            "Benchmark failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Cleanup
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(lhs: f64, rhs: f64) -> bool {
        (lhs - rhs).abs() < 1e-9
    }

    #[test]
    fn test_cli_parses_health() {
        println!("TEST START: test_cli_parses_health");
        let cli = Cli::try_parse_from(["rch-wkr", "health"]).expect("cli parse should succeed");
        assert!(!cli.verbose);
        assert!(matches!(cli.command, Commands::Health));
        println!("TEST PASS: test_cli_parses_health");
    }

    #[test]
    fn test_cli_parses_execute_with_toolchain() {
        println!("TEST START: test_cli_parses_execute_with_toolchain");
        let cli = Cli::try_parse_from([
            "rch-wkr",
            "--verbose",
            "execute",
            "--workdir",
            "/tmp",
            "--command",
            "echo hello",
            "--toolchain",
            "nightly",
        ])
        .expect("cli parse should succeed");

        assert!(cli.verbose);
        match cli.command {
            Commands::Execute {
                workdir,
                command,
                toolchain,
            } => {
                assert_eq!(workdir, "/tmp");
                assert_eq!(command, "echo hello");
                assert_eq!(toolchain.as_deref(), Some("nightly"));
            }
            _ => panic!("expected execute command"),
        }
        println!("TEST PASS: test_cli_parses_execute_with_toolchain");
    }

    #[test]
    fn test_cli_parses_cleanup_default_age() {
        println!("TEST START: test_cli_parses_cleanup_default_age");
        let cli = Cli::try_parse_from(["rch-wkr", "cleanup"]).expect("cli parse should succeed");
        match cli.command {
            Commands::Cleanup { max_age_hours } => {
                assert_eq!(max_age_hours, 168);
            }
            _ => panic!("expected cleanup command"),
        }
        println!("TEST PASS: test_cli_parses_cleanup_default_age");
    }

    #[test]
    fn test_parse_rustc_version_stdout_extracts_semver() {
        println!("TEST START: test_parse_rustc_version_stdout_extracts_semver");
        let parsed = parse_rustc_version_stdout("rustc 1.87.0-nightly (abc 2026-01-01)\n");
        assert_eq!(parsed.as_deref(), Some("1.87.0-nightly"));
        println!("TEST PASS: test_parse_rustc_version_stdout_extracts_semver");
    }

    #[test]
    fn test_parse_node_version_stdout_strips_v_prefix() {
        println!("TEST START: test_parse_node_version_stdout_strips_v_prefix");
        let parsed = parse_node_version_stdout("v20.10.0\n");
        assert_eq!(parsed.as_deref(), Some("20.10.0"));
        println!("TEST PASS: test_parse_node_version_stdout_strips_v_prefix");
    }

    #[test]
    fn test_parse_proc_loadavg_parses_first_three_numbers() {
        println!("TEST START: test_parse_proc_loadavg_parses_first_three_numbers");
        let parsed = parse_proc_loadavg("0.11 0.22 0.33 1/234 5678\n");
        let (l1, l5, l15) = parsed.expect("should parse");
        assert!(approx_eq(l1, 0.11));
        assert!(approx_eq(l5, 0.22));
        assert!(approx_eq(l15, 0.33));
        println!("TEST PASS: test_parse_proc_loadavg_parses_first_three_numbers");
    }

    #[test]
    fn test_parse_uptime_loadavg_parses_comma_format() {
        println!("TEST START: test_parse_uptime_loadavg_parses_comma_format");
        let sample = " 10:30:00 up 1 day,  2 users,  load average: 0.30, 0.20, 0.10\n";
        let (l1, l5, l15) = parse_uptime_loadavg(sample).expect("should parse");
        assert!(approx_eq(l1, 0.30));
        assert!(approx_eq(l5, 0.20));
        assert!(approx_eq(l15, 0.10));
        println!("TEST PASS: test_parse_uptime_loadavg_parses_comma_format");
    }

    #[test]
    fn test_parse_uptime_loadavg_parses_space_format() {
        println!("TEST START: test_parse_uptime_loadavg_parses_space_format");
        let sample = " 10:30:00 up 1 day,  2 users,  load averages: 2.05 1.90 1.50\n";
        let (l1, l5, l15) = parse_uptime_loadavg(sample).expect("should parse");
        assert!(approx_eq(l1, 2.05));
        assert!(approx_eq(l5, 1.90));
        assert!(approx_eq(l15, 1.50));
        println!("TEST PASS: test_parse_uptime_loadavg_parses_space_format");
    }

    #[test]
    fn test_parse_df_posix_kb_parses_total_and_available() {
        println!("TEST START: test_parse_df_posix_kb_parses_total_and_available");
        let sample = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1048576 524288 524288 50% /tmp\n";
        let (total_kb, avail_kb) = parse_df_posix_kb(sample).expect("should parse");
        assert_eq!(total_kb, 1_048_576);
        assert_eq!(avail_kb, 524_288);
        println!("TEST PASS: test_parse_df_posix_kb_parses_total_and_available");
    }
}

// Global test logging initialization - enables JSONL output for all unit tests
#[cfg(test)]
#[ctor::ctor]
fn init_test_logging() {
    rch_common::testing::init_global_test_logging();
}
