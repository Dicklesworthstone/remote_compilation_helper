//! Remote Compilation Helper - Worker Agent
//!
//! The worker agent runs on remote machines and executes compilation
//! commands, manages project caches, and responds to health checks.

#![forbid(unsafe_code)]

mod cache;
mod executor;
mod prepare;
mod toolchain;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rch_common::{DEFAULT_ALIAS_PROJECT_ROOT, DEFAULT_CANONICAL_PROJECT_ROOT, WorkerCapabilities};
use rch_common::{LogConfig, init_logging};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "rch-wkr")]
#[command(
    author,
    version = rch_common::build_version_value_static(),
    about = "RCH worker agent - remote execution"
)]
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

    /// Collect a telemetry snapshot
    Telemetry {
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

    /// Run a benchmark
    Benchmark {
        /// Output format
        #[arg(long, value_enum, default_value = "pretty")]
        format: OutputFormat,

        /// Output JSON (shorthand for --format json)
        #[arg(long)]
        json: bool,
    },

    /// Pre-execution preparation (e.g. `bun install` for Node projects).
    ///
    /// For Bun/Node projects, fingerprints package.json + lockfiles, runs
    /// `bun install` / `pnpm install` / etc. on cache miss, and persists the
    /// fingerprint so subsequent prepare calls hit the cache. For Rust /
    /// non-Node runtimes this is a no-op (returns Skipped). Output is JSON.
    Prepare {
        /// Project root directory on the worker.
        #[arg(long)]
        project: String,

        /// Required runtime: rust | bun | node | none.
        #[arg(long, default_value = "none")]
        runtime: PrepareRuntime,

        /// Directory for install logs (default: <project>/.rch_prepare_logs/).
        #[arg(long)]
        log_dir: Option<String>,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum PrepareRuntime {
    Rust,
    Bun,
    Node,
    None,
}

impl From<PrepareRuntime> for rch_common::types::RequiredRuntime {
    fn from(value: PrepareRuntime) -> Self {
        match value {
            PrepareRuntime::Rust => Self::Rust,
            PrepareRuntime::Bun => Self::Bun,
            PrepareRuntime::Node => Self::Node,
            PrepareRuntime::None => Self::None,
        }
    }
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum OutputFormat {
    Json,
    Pretty,
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
        Commands::Telemetry {
            format,
            sample_ms,
            no_disk,
            no_network,
            worker_id,
        } => {
            use rch_telemetry::collect::{collect_telemetry, resolve_worker_id};
            let worker_id = resolve_worker_id(worker_id);
            let telemetry = collect_telemetry(sample_ms, !no_disk, !no_network, worker_id)?;

            let output = match format {
                OutputFormat::Json => telemetry.to_json()?,
                OutputFormat::Pretty => telemetry.to_json_pretty()?,
            };

            println!("{}", output);
            Ok(())
        }
        Commands::Benchmark { format, json } => {
            let fmt = if json { OutputFormat::Json } else { format };
            run_benchmark(fmt).await
        }
        Commands::Prepare {
            project,
            runtime,
            log_dir,
        } => {
            use std::path::PathBuf;
            let project_path = PathBuf::from(&project);
            let log_dir_path = log_dir
                .map(PathBuf::from)
                .unwrap_or_else(|| project_path.join(".rch_prepare_logs"));
            let report = prepare::prepare(&project_path, runtime.into(), &log_dir_path).await?;
            println!("{}", serde_json::to_string(&report)?);
            // Exit code mapping (callers and e2e tests rely on these):
            //   0 - Skipped (cache hit / no-op for non-Node) or Installed (success)
            //   1 - Failed (install ran but exited non-zero)
            //   2 - Timeout (install exceeded RCH_PREPARE_INSTALL_TIMEOUT_SECS, was killed)
            // The two non-zero codes are distinct so an agent / shell
            // wrapper can branch on a network-stall remediation (timeout)
            // vs. a real install error (failed).
            match report.action {
                prepare::PrepareAction::Skipped | prepare::PrepareAction::Installed => Ok(()),
                prepare::PrepareAction::Failed => std::process::exit(1),
                prepare::PrepareAction::Timeout => std::process::exit(2),
            }
        }
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

    // Probe rustc version. Resolve like the rustup inventory does so a
    // minimal service PATH cannot silently drop the Rust capability facts.
    let mut warnings = Vec::new();
    if let Some(rustc) = resolve_tool_binary("rustc") {
        if let Ok(output) = Command::new(&rustc.path).args(["--version"]).output()
            && output.status.success()
        {
            let version_str = String::from_utf8_lossy(&output.stdout);
            capabilities.rustc_version = parse_rustc_version_stdout(&version_str);
            if !rustc.from_path_lookup {
                warnings.push(format!(
                    "rustc resolved from fallback location {}",
                    rustc.path.display()
                ));
            }
        }
    } else if let Ok(output) = Command::new("rustc").args(["--version"]).output()
        && output.status.success()
    {
        let version_str = String::from_utf8_lossy(&output.stdout);
        capabilities.rustc_version = parse_rustc_version_stdout(&version_str);
    }

    let (toolchains, components, inventory_warnings) = probe_rustup_inventory();
    capabilities.rustup_toolchains = toolchains;
    capabilities.rustup_components = components;
    warnings.extend(inventory_warnings);
    capabilities.probe_warnings = warnings;

    // Probe bun version
    let bun_cmd = run_bun_version_command();

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

    // Probe nix version. We require BOTH a working `nix --version` AND a
    // populated `/nix/store`, since a `nix` binary alone (without a store) can't
    // build derivations. This gates `nix build` / `nix develop -c` routing.
    if nix_store_is_populated()
        && let Ok(output) = Command::new("nix").args(["--version"]).output()
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            capabilities.nix_version = Some(version);
        }
    }

    // Probe Go toolchain. Presence gates `go build`/`go test`/`go vet` routing to
    // this worker via `has_go()`.
    if let Ok(output) = Command::new("go").args(["version"]).output()
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            capabilities.go_version = Some(version);
        }
    }

    // Probe the zig cross-compilation toolchain. Both halves are required: the
    // `cargo-zigbuild` subcommand and the `zig` binary it drives as linker.
    // Probed as the hyphenated binary because `cargo zigbuild --version` is
    // rejected by cargo-zigbuild's own argument parser. Gates `cargo zigbuild`
    // routing via `has_zig()`.
    if let Ok(output) = Command::new("zig").args(["version"]).output()
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            capabilities.zig_version = Some(version);
        }
    }
    if let Ok(output) = Command::new("cargo-zigbuild").args(["--version"]).output()
        && output.status.success()
    {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !version.is_empty() {
            capabilities.cargo_zigbuild_version = Some(version);
        }
    }

    // Probe the x86-64 microarchitecture level (bd-6qchz / bd-68hon item 4):
    // a pre-v3 CPU (e.g. Ivy Bridge — AVX but no AVX2) SIGILLs any
    // build-script/proc-macro binary compiled for x86-64-v3, so the dispatcher
    // deprioritizes such workers proactively. None on non-x86 or when
    // /proc/cpuinfo is unavailable (macOS test runs).
    capabilities.cpu_microarch_level = probe_cpu_microarch_level();

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

    let (canonical_root, alias_root) = resolved_topology_roots();
    let (topology_ok, topology_issue) = probe_projects_topology(&canonical_root, &alias_root);
    capabilities.projects_root_ok = Some(topology_ok);
    capabilities.projects_root_issue = topology_issue;
    capabilities.projects_root_checked_at_unix_ms = Some(current_unix_ms());

    capabilities
}

/// Probe every installed rustup toolchain and retain toolchain-qualified,
/// normalized component facts for routing. A failed sub-probe contributes no
/// facts, which makes component admission fail closed for that toolchain.
fn probe_rustup_inventory() -> (Vec<String>, Vec<String>, Vec<String>) {
    use std::process::Command;

    let mut warnings = Vec::new();
    let Some(rustup) = resolve_tool_binary("rustup") else {
        return (Vec::new(), Vec::new(), Vec::new());
    };
    if !rustup.from_path_lookup {
        warnings.push(format!(
            "rustup resolved from fallback location {}",
            rustup.path.display()
        ));
    }
    let rustup = &rustup.path;

    let Ok(output) = Command::new(rustup).args(["toolchain", "list"]).output() else {
        warnings.push("rustup toolchain list failed to spawn".to_owned());
        return (Vec::new(), Vec::new(), warnings);
    };
    if !output.status.success() {
        warnings.push(format!(
            "rustup toolchain list exited {:?}",
            output.status.code()
        ));
        return (Vec::new(), Vec::new(), warnings);
    }

    let mut toolchains = parse_rustup_toolchains(&String::from_utf8_lossy(&output.stdout));
    let mut components = Vec::new();
    for toolchain in &toolchains {
        let host = Command::new(rustup)
            .args(["run", toolchain, "rustc", "-vV"])
            .output()
            .ok()
            .filter(|result| result.status.success())
            .and_then(|result| parse_rustc_host(&String::from_utf8_lossy(&result.stdout)));

        let Some(output) = Command::new(rustup)
            .args(["component", "list", "--installed", "--toolchain", toolchain])
            .output()
            .ok()
            .filter(|result| result.status.success())
        else {
            continue;
        };
        components.extend(parse_rustup_components(
            toolchain,
            host.as_deref(),
            &String::from_utf8_lossy(&output.stdout),
        ));
    }
    toolchains.sort();
    toolchains.dedup();
    components.sort();
    components.dedup();
    (toolchains, components, warnings)
}

/// Resolve a tool binary by name without relying solely on the caller's PATH.
///
/// Systemd system services inherit a minimal default PATH that does not
/// include `~/.cargo/bin`, so a root-run daemon probing bare-name `rustup`
/// silently got "not found" and capability probes reported empty component
/// facts even though the toolchain was fully installed (bd-deft5). Probe the
/// caller's PATH first, then the standard cargo/user install locations.
fn resolve_tool_binary(name: &str) -> Option<ResolvedTool> {
    resolve_tool_binary_in(
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("HOME").as_deref(),
        name,
    )
}

/// A resolved tool binary plus how it was found, so callers can distinguish
/// a plain PATH lookup from a well-known-location fallback worth reporting.
#[derive(Debug)]
struct ResolvedTool {
    path: std::path::PathBuf,
    from_path_lookup: bool,
}

fn resolve_tool_binary_in(
    path_var: Option<&std::ffi::OsStr>,
    home: Option<&std::ffi::OsStr>,
    name: &str,
) -> Option<ResolvedTool> {
    use std::path::PathBuf;

    // Windows installs `rustup.exe`; a bare-name lookup never matches it and
    // the whole rustup inventory silently vanishes (bd-jdcxd). Try the
    // platform executable suffix alongside the bare name everywhere.
    let names: Vec<String> = if std::env::consts::EXE_SUFFIX.is_empty() {
        vec![name.to_string()]
    } else {
        vec![
            name.to_string(),
            format!("{name}{}", std::env::consts::EXE_SUFFIX),
        ]
    };

    if let Some(paths) = path_var {
        for dir in std::env::split_paths(paths) {
            for candidate in names.iter().map(|n| dir.join(n)) {
                if candidate.is_file() {
                    return Some(ResolvedTool {
                        path: candidate,
                        from_path_lookup: true,
                    });
                }
            }
        }
    }
    let mut fallback_dirs: Vec<PathBuf> = Vec::new();
    if let Some(home) = home
        && !home.is_empty()
    {
        let home = PathBuf::from(home);
        fallback_dirs.push(home.join(".cargo").join("bin"));
        fallback_dirs.push(home.join(".local").join("bin"));
    }
    // Canonical locations for service contexts where HOME may be /root or
    // unset regardless of which user provisioned the toolchain.
    fallback_dirs.push(PathBuf::from("/root/.cargo/bin"));
    fallback_dirs.push(PathBuf::from("/usr/local/bin"));
    fallback_dirs
        .into_iter()
        .flat_map(|dir| names.iter().map(move |n| dir.join(n)).collect::<Vec<_>>())
        .find(|p| p.is_file())
        .map(|path| ResolvedTool {
            path,
            from_path_lookup: false,
        })
}

fn parse_rustup_toolchains(stdout: &str) -> Vec<String> {
    let mut toolchains = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    toolchains.sort();
    toolchains.dedup();
    toolchains
}

fn parse_rustc_host(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix("host:")
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_string)
    })
}

fn parse_rustup_components(toolchain: &str, host: Option<&str>, stdout: &str) -> Vec<String> {
    let host_suffix = host.map(|host| format!("-{host}"));
    let mut components = stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| !name.is_empty())
        .map(|name| {
            let normalized = host_suffix
                .as_deref()
                .and_then(|suffix| name.strip_suffix(suffix))
                .unwrap_or(name);
            format!("{toolchain}:{normalized}")
        })
        .collect::<Vec<_>>();
    components.sort();
    components.dedup();
    components
}

/// Resolve the worker's topology roots, honoring `RCH_WKR_CANONICAL_ROOT` /
/// `RCH_WKR_ALIAS_ROOT` (set in the worker's systemd unit or shell profile)
/// and falling back to the compile-time defaults. Hosts that don't ship
/// `/data/projects` + `/dp` need this so capability probes don't always
/// report `projects_root_ok = false` and get excluded by daemon preflight.
/// See rch#15.
fn resolved_topology_roots() -> (std::path::PathBuf, std::path::PathBuf) {
    resolve_topology_roots_from_env(
        std::env::var_os("RCH_WKR_CANONICAL_ROOT"),
        std::env::var_os("RCH_WKR_ALIAS_ROOT"),
    )
}

fn resolve_topology_roots_from_env(
    canonical_env: Option<std::ffi::OsString>,
    alias_env: Option<std::ffi::OsString>,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let canonical = canonical_env
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_CANONICAL_PROJECT_ROOT));
    let alias = alias_env
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_ALIAS_PROJECT_ROOT));
    (canonical, alias)
}

/// Whether `/nix/store` exists and contains at least one entry.
///
/// A `nix` binary without a populated store cannot actually build derivations
/// (every build resolves store paths), so capability detection requires both.
/// This is a cheap directory read — we only need to know that SOME entry exists,
/// so we stop at the first one.
fn nix_store_is_populated() -> bool {
    std::fs::read_dir("/nix/store")
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

fn run_bun_version_command() -> Option<std::process::Output> {
    if let Ok(output) = std::process::Command::new("bun")
        .args(["--version"])
        .output()
    {
        return Some(output);
    }

    let mut command = std::process::Command::new("bun");
    if let Some(path) = path_with_home_bun_bin(std::env::var_os("HOME"), std::env::var_os("PATH")) {
        command.env("PATH", path);
    }
    command.args(["--version"]).output().ok()
}

fn path_with_home_bun_bin(
    home: Option<std::ffi::OsString>,
    current_path: Option<std::ffi::OsString>,
) -> Option<std::ffi::OsString> {
    let home = home.filter(|value| !value.is_empty())?;
    let mut paths = vec![std::path::PathBuf::from(home).join(".bun/bin")];
    if let Some(current_path) = current_path {
        paths.extend(std::env::split_paths(&current_path));
    }
    std::env::join_paths(paths).ok()
}

fn current_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

fn probe_projects_topology(
    canonical_root: &std::path::Path,
    alias_root: &std::path::Path,
) -> (bool, Option<String>) {
    let canonical_meta = match std::fs::symlink_metadata(canonical_root) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (false, Some("canonical_missing".to_string()));
        }
        Err(err) => {
            return (false, Some(format!("canonical_probe_error:{err}")));
        }
    };
    if !canonical_meta.file_type().is_dir() {
        return (false, Some("canonical_not_directory".to_string()));
    }

    // The canonical↔alias dual-root symlink convention is Unix-only (rch#15).
    // Windows workers use a single build base (e.g. C:/rch) with no alias, so
    // requiring an alias symlink there would fail every Windows worker's
    // preflight. `validate_alias_symlink` enforces the symlink on Unix and is a
    // no-op on other platforms (the caller's canonical dir check is sufficient).
    validate_alias_symlink(canonical_root, alias_root)
}

#[cfg(unix)]
fn validate_alias_symlink(
    canonical_root: &std::path::Path,
    alias_root: &std::path::Path,
) -> (bool, Option<String>) {
    let alias_meta = match std::fs::symlink_metadata(alias_root) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (false, Some("alias_missing".to_string()));
        }
        Err(err) => {
            return (false, Some(format!("alias_probe_error:{err}")));
        }
    };
    if !alias_meta.file_type().is_symlink() {
        return (false, Some("alias_not_symlink".to_string()));
    }

    let alias_target = match std::fs::read_link(alias_root) {
        Ok(target) => target,
        Err(err) => return (false, Some(format!("alias_readlink_error:{err}"))),
    };
    let resolved_target = if alias_target.is_absolute() {
        alias_target
    } else if let Some(parent) = alias_root.parent() {
        parent.join(alias_target)
    } else {
        alias_target
    };

    let canonical_real =
        std::fs::canonicalize(canonical_root).unwrap_or_else(|_| canonical_root.to_path_buf());
    let target_real = std::fs::canonicalize(&resolved_target).unwrap_or(resolved_target);
    if canonical_real != target_real {
        return (
            false,
            Some(format!("alias_wrong_target:{}", target_real.display())),
        );
    }

    (true, None)
}

#[cfg(not(unix))]
fn validate_alias_symlink(
    _canonical_root: &std::path::Path,
    _alias_root: &std::path::Path,
) -> (bool, Option<String>) {
    // Non-Unix workers (Windows) have no canonical↔alias symlink topology; the
    // single build base already verified by the caller is sufficient. See rch#15.
    (true, None)
}

/// Probe the x86-64 microarchitecture level (1..=4) from `/proc/cpuinfo`.
///
/// Returns `None` when cpuinfo is unreadable or carries no x86 `flags` line
/// (non-x86 CPUs, macOS). Classification lives in
/// [`rch_common::x86_64_microarch_level_from_flags`] so the dispatcher-side
/// interpretation can never drift from the probe.
fn probe_cpu_microarch_level() -> Option<u8> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    let flags = cpuinfo
        .lines()
        .find(|line| line.starts_with("flags") && line.contains(':'))?
        .split_once(':')?
        .1;
    Some(rch_common::x86_64_microarch_level_from_flags(flags))
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

/// Probe disk space for project workspace filesystem (free and total in GB).
///
/// Worst-case free space across the project roots AND /tmp (bd-lvbax).
///
/// An earlier version preferred the project roots and only fell back to
/// /tmp, treating a small tmpfs as a false pressure signal. The opposite is
/// true in practice: vmi1149989's /tmp tmpfs hit 100% while / was healthy,
/// breaking scp/mktemp for every build on that worker while pressure scoring
/// stayed green. Pressure reporting must see the tightest mount a build can
/// actually touch, so sample all candidates and report the minimum free.
fn probe_disk_space() -> Option<(f64, f64)> {
    use std::path::Path;
    let (canonical, alias) = resolved_topology_roots();
    let mut worst: Option<(f64, f64)> = None;
    for path in [canonical.as_path(), alias.as_path(), Path::new("/tmp")] {
        if let Some((free_gb, total_gb)) = probe_disk_space_for(path) {
            worst = match worst {
                Some((worst_free, _)) if worst_free <= free_gb => worst,
                _ => Some((free_gb, total_gb)),
            };
        }
    }
    worst
}

fn probe_disk_space_for(path: &std::path::Path) -> Option<(f64, f64)> {
    use std::process::Command;

    if !path.exists() {
        return None;
    }

    let path_str = path.to_string_lossy();
    if let Ok(output) = Command::new("df").args(["-P", "-k", &path_str]).output()
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
    let [load1, load5, load15, ..] = parts.as_slice() else {
        return None;
    };

    let load1 = load1.parse::<f64>().ok()?;
    let load5 = load5.parse::<f64>().ok()?;
    let load15 = load15.parse::<f64>().ok()?;
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

    let [load1, load5, load15, ..] = parts.as_slice() else {
        return None;
    };

    let load1 = load1.parse::<f64>().ok()?;
    let load5 = load5.parse::<f64>().ok()?;
    let load15 = load15.parse::<f64>().ok()?;
    Some((load1, load5, load15))
}

fn parse_df_posix_kb(stdout: &str) -> Option<(u64, u64)> {
    // Skip header line, parse first data line.
    // POSIX format: Filesystem 1024-blocks Used Available Capacity Mounted on
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let [_, total_kb, _, avail_kb, ..] = parts.as_slice() else {
            continue;
        };
        let total_kb = total_kb.parse::<u64>().ok()?;
        let avail_kb = avail_kb.parse::<u64>().ok()?;
        return Some((total_kb, avail_kb));
    }
    None
}

async fn run_benchmark(format: OutputFormat) -> Result<()> {
    info!("Running benchmark...");

    // Run the real multi-dimensional benchmark suite from `rch-telemetry` and
    // score it with the weighted SpeedScore engine (CPU 30 / disk 20 /
    // compilation 20 / memory 15 / network 15).
    //
    // History (bd-speedscore-saturation): this used to build a single
    // zero-dependency crate and report `100.0 / elapsed_secs`, clamped to 100.
    // Every modern worker builds that in well under a second, so the clamp
    // pinned essentially the whole fleet at exactly 100.0 — the score could not
    // discriminate at all, and the only workers scoring below 100 were the ones
    // that happened to be *busy*, which inverted the ranking. It was also
    // single-threaded, so a 16-core box scored no better than a 4-core box.
    //
    // The component benchmarks are CPU-count aware (see `run_stable` variants,
    // which take the median of several runs to damp load noise), so a busy
    // worker no longer masquerades as a slow one.
    let start = std::time::Instant::now();

    let cpu = rch_telemetry::benchmarks::cpu::run_cpu_benchmark_stable();
    let memory = rch_telemetry::benchmarks::memory::run_memory_benchmark_stable();
    let disk = rch_telemetry::benchmarks::disk::run_disk_benchmark_stable();

    // Compilation is the one component that can legitimately fail (no cargo,
    // no toolchain, read-only tmp). Treat that as "component absent" rather
    // than failing the whole benchmark: `calculate_speedscore` re-weights
    // across the components it actually has.
    let compilation =
        match rch_telemetry::benchmarks::compilation::run_compilation_benchmark_stable() {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("compilation benchmark unavailable, scoring without it: {e}");
                None
            }
        };

    // Network is deliberately omitted here: it measures the controller↔worker
    // path, which is only meaningful when measured from the controller side.
    let mut results = rch_telemetry::speedscore::BenchmarkResults::new()
        .with_cpu(cpu.clone())
        .with_memory(memory.clone())
        .with_disk(disk.clone());
    if let Some(ref c) = compilation {
        results = results.with_compilation(c.clone());
    }

    let score = rch_telemetry::speedscore::calculate_speedscore(&results);
    let elapsed = start.elapsed();
    let cores = std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get);

    // serde_json maps NaN/Infinity to `null`, and rchd parses the score with
    // `json.get("score").and_then(Value::as_f64)`. A single non-finite value
    // would therefore emit `"score": null`, the daemon would fail to parse it,
    // and the worker would silently fall back into the "never benchmarked"
    // re-queue loop. A NaN is reachable if any benchmark divides 0/0, so clamp
    // every float we emit.
    fn finite(v: f64) -> f64 {
        if v.is_finite() { v } else { 0.0 }
    }
    fn round1(v: f64) -> f64 {
        (finite(v) * 10.0).round() / 10.0
    }

    match format {
        OutputFormat::Json => {
            // `score` stays a top-level f64 for backward compatibility: rchd's
            // `execute_benchmark_on_worker` parses exactly that field.
            let payload = serde_json::json!({
                "score": round1(score.total),
                "elapsed_secs": (elapsed.as_secs_f64() * 100.0).round() / 100.0,
                "cores": cores,
                "components": {
                    "cpu": finite(score.cpu_score),
                    "memory": finite(score.memory_score),
                    "disk": finite(score.disk_score),
                    "network": finite(score.network_score),
                    "compilation": finite(score.compilation_score),
                },
                "raw": {
                    "cpu_ops_per_second": finite(cpu.ops_per_second),
                    "memory_seq_bandwidth_gbps": finite(memory.seq_bandwidth_gbps),
                    "disk_seq_read_mbps": finite(disk.seq_read_mbps),
                    "disk_seq_write_mbps": finite(disk.seq_write_mbps),
                    "disk_random_read_iops": finite(disk.random_read_iops),
                    "compilation_release_build_ms": compilation.as_ref().map(|c| c.release_build_ms),
                },
            });
            println!("{payload}");
        }
        OutputFormat::Pretty => {
            println!("Benchmark completed in {:.2}s", elapsed.as_secs_f64());
            // Keep `Score: <float>` alone on its line and nothing else on it.
            // rchd's `parse_benchmark_score` fallback does
            // `strip_prefix("score:").trim().parse::<f64>()`, so appending the
            // rating here (e.g. "Score: 75.6 (excellent)") would make that
            // fallback fail to parse. Rating goes on its own line.
            println!("Score: {:.1}", finite(score.total));
            println!("Rating: {}", score.rating());
            println!("  cores       : {cores}");
            println!("  cpu         : {:.1}", finite(score.cpu_score));
            println!("  memory      : {:.1}", finite(score.memory_score));
            println!("  disk        : {:.1}", finite(score.disk_score));
            println!("  compilation : {:.1}", finite(score.compilation_score));
        }
    }

    Ok(())
}

// `benchmark_failure_summary` / `truncate_for_error` lived here to summarize raw
// stdout/stderr from the hand-rolled `cargo build` the old benchmark shelled out
// to. The benchmark now runs the typed `rch-telemetry` suite, which reports
// structured errors, so both helpers (and their tests) were removed with the
// code path they served.

#[cfg(test)]
mod tests {
    use super::*;
    use rch_common::test_guard;

    fn approx_eq(lhs: f64, rhs: f64) -> bool {
        (lhs - rhs).abs() < 1e-9
    }

    #[test]
    fn test_resolve_tool_binary_prefers_path_hit_with_provenance() {
        let _guard = test_guard!();
        let dir = tempfile::tempdir().expect("tempdir");
        let tool = dir.path().join("selftest-tool");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write tool");
        let path_var =
            std::env::join_paths(std::iter::once(dir.path().to_path_buf())).expect("join paths");
        let resolved = resolve_tool_binary_in(
            Some(&path_var),
            Some("/nonexistent-home".as_ref()),
            "selftest-tool",
        )
        .expect("tool should resolve from PATH");
        assert!(
            resolved.from_path_lookup,
            "PATH hit must be reported as such"
        );
        assert_eq!(resolved.path, tool);
    }

    #[test]
    fn test_resolve_tool_binary_falls_back_to_home_cargo_bin() {
        let _guard = test_guard!();
        let home = tempfile::tempdir().expect("tempdir");
        let cargo_bin = home.path().join(".cargo/bin");
        std::fs::create_dir_all(&cargo_bin).expect("mkdir cargo bin");
        let tool = cargo_bin.join("selftest-fallback-tool");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write tool");
        let resolved = resolve_tool_binary_in(
            Some("/definitely/not/a/tool/dir".as_ref()),
            Some(home.path().as_os_str()),
            "selftest-fallback-tool",
        )
        .expect("tool should resolve from ~/.cargo/bin fallback");
        assert!(
            !resolved.from_path_lookup,
            "fallback hit must not claim PATH provenance"
        );
        assert_eq!(resolved.path, tool);
    }

    #[test]
    fn test_resolve_tool_binary_absent_everywhere_is_none() {
        let _guard = test_guard!();
        // A name no plausible machine ships in /root/.cargo/bin or
        // /usr/local/bin; the resolver must answer None rather than inventing
        // a candidate.
        let resolved = resolve_tool_binary_in(
            Some("/definitely/not/a/tool/dir".as_ref()),
            Some("/definitely/not/a/home".as_ref()),
            "rch-wkr-resolver-absent-selftest-7f3a9c",
        );
        assert!(resolved.is_none(), "unexpected resolution: {resolved:?}");
    }

    /// Regression for bd-jdcxd: Windows ships `rustup.exe`, so a bare-name
    /// lookup found nothing and the whole rustup inventory silently vanished
    /// (the dispatcher then reported every component as missing).
    #[test]
    fn test_resolve_tool_binary_accepts_platform_exe_suffix() {
        let _guard = test_guard!();
        let dir = tempfile::tempdir().expect("tempdir");
        let tool = dir
            .path()
            .join(format!("selftest-suffixed{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write tool");
        let path_var =
            std::env::join_paths(std::iter::once(dir.path().to_path_buf())).expect("join paths");
        let resolved = resolve_tool_binary_in(
            Some(&path_var),
            Some("/nonexistent-home".as_ref()),
            "selftest-suffixed",
        )
        .expect("tool should resolve with the platform executable suffix");
        assert!(resolved.from_path_lookup);
        assert_eq!(resolved.path, tool);
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_tool_binary_bare_name_still_wins_on_windows() {
        let _guard = test_guard!();
        let dir = tempfile::tempdir().expect("tempdir");
        let bare = dir.path().join("selftest-both");
        let exe = dir.path().join("selftest-both.exe");
        std::fs::write(&bare, b"").expect("write bare");
        std::fs::write(&exe, b"").expect("write exe");
        let path_var =
            std::env::join_paths(std::iter::once(dir.path().to_path_buf())).expect("join paths");
        let resolved = resolve_tool_binary_in(Some(&path_var), None, "selftest-both")
            .expect("tool should resolve");
        assert_eq!(
            resolved.path, bare,
            "bare name is checked before the .exe form"
        );
    }

    #[test]
    fn test_cli_parses_health() {
        let _guard = test_guard!();
        println!("TEST START: test_cli_parses_health");
        let cli = Cli::try_parse_from(["rch-wkr", "health"]).expect("cli parse should succeed");
        assert!(!cli.verbose);
        assert!(matches!(cli.command, Commands::Health));
        println!("TEST PASS: test_cli_parses_health");
    }

    #[test]
    fn test_cli_parses_execute_with_toolchain() -> Result<()> {
        let _guard = test_guard!();
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
        let Commands::Execute {
            workdir,
            command,
            toolchain,
        } = cli.command
        else {
            anyhow::bail!("expected execute command");
        };
        assert_eq!(workdir, "/tmp");
        assert_eq!(command, "echo hello");
        assert_eq!(toolchain.as_deref(), Some("nightly"));
        println!("TEST PASS: test_cli_parses_execute_with_toolchain");
        Ok(())
    }

    #[test]
    fn test_cli_parses_cleanup_default_age() -> Result<()> {
        let _guard = test_guard!();
        println!("TEST START: test_cli_parses_cleanup_default_age");
        let cli = Cli::try_parse_from(["rch-wkr", "cleanup"]).expect("cli parse should succeed");
        let Commands::Cleanup { max_age_hours } = cli.command else {
            anyhow::bail!("expected cleanup command");
        };
        assert_eq!(max_age_hours, 168);
        println!("TEST PASS: test_cli_parses_cleanup_default_age");
        Ok(())
    }

    #[test]
    fn test_parse_rustc_version_stdout_extracts_semver() {
        let _guard = test_guard!();
        println!("TEST START: test_parse_rustc_version_stdout_extracts_semver");
        let parsed = parse_rustc_version_stdout("rustc 1.87.0-nightly (abc 2026-01-01)\n");
        assert_eq!(parsed.as_deref(), Some("1.87.0-nightly"));
        println!("TEST PASS: test_parse_rustc_version_stdout_extracts_semver");
    }

    #[test]
    fn test_parse_rustup_component_inventory_normalizes_only_the_exact_host_suffix() {
        let _guard = test_guard!();
        let toolchains = parse_rustup_toolchains(
            "stable-x86_64-unknown-linux-gnu\nnightly-2026-07-05-x86_64-unknown-linux-gnu (default)\n",
        );
        assert_eq!(
            toolchains,
            vec![
                "nightly-2026-07-05-x86_64-unknown-linux-gnu",
                "stable-x86_64-unknown-linux-gnu"
            ]
        );
        assert_eq!(
            parse_rustc_host("rustc 1.99.0-nightly\nhost: x86_64-unknown-linux-gnu\n").as_deref(),
            Some("x86_64-unknown-linux-gnu")
        );

        let components = parse_rustup_components(
            "nightly-2026-07-05-x86_64-unknown-linux-gnu",
            Some("x86_64-unknown-linux-gnu"),
            "cargo-x86_64-unknown-linux-gnu\nclippy-x86_64-unknown-linux-gnu\nclippy-preview\nrust-src\nrustfmt-x86_64-unknown-linux-gnu\n",
        );
        assert!(components.iter().any(|fact| fact.ends_with(":clippy")));
        assert!(components.iter().any(|fact| fact.ends_with(":rustfmt")));
        assert!(components.iter().any(|fact| fact.ends_with(":rust-src")));
        assert!(
            components
                .iter()
                .any(|fact| fact.ends_with(":clippy-preview"))
        );
        assert!(
            !components
                .iter()
                .any(|fact| fact.ends_with(":clippy-x86_64-unknown-linux-gnu"))
        );
    }

    #[test]
    fn test_parse_node_version_stdout_strips_v_prefix() {
        let _guard = test_guard!();
        println!("TEST START: test_parse_node_version_stdout_strips_v_prefix");
        let parsed = parse_node_version_stdout("v20.10.0\n");
        assert_eq!(parsed.as_deref(), Some("20.10.0"));
        println!("TEST PASS: test_parse_node_version_stdout_strips_v_prefix");
    }

    #[test]
    fn test_parse_proc_loadavg_parses_first_three_numbers() {
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
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
        let _guard = test_guard!();
        println!("TEST START: test_parse_df_posix_kb_parses_total_and_available");
        let sample = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1048576 524288 524288 50% /tmp\n";
        let (total_kb, avail_kb) = parse_df_posix_kb(sample).expect("should parse");
        assert_eq!(total_kb, 1_048_576);
        assert_eq!(avail_kb, 524_288);
        println!("TEST PASS: test_parse_df_posix_kb_parses_total_and_available");
    }

    fn make_temp_topology_paths(
        test_name: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let unique = format!(
            "rch-wkr-topology-{}-{}-{}",
            test_name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time should be after unix epoch")
                .as_nanos()
        );
        let base = std::env::temp_dir().join(unique);
        let canonical = base.join("data/projects");
        let alias = base.join("dp");
        std::fs::create_dir_all(&canonical).expect("create canonical root");
        (base, canonical, alias)
    }

    #[test]
    fn test_path_with_home_bun_bin_prepends_standard_bun_install_dir() {
        let _guard = test_guard!();
        let path = path_with_home_bun_bin(
            Some(std::ffi::OsString::from("/home/tester")),
            Some(std::ffi::OsString::from("/usr/bin:/bin")),
        )
        .expect("path should be built");

        let paths: Vec<std::path::PathBuf> = std::env::split_paths(&path).collect();
        assert_eq!(paths[0], std::path::PathBuf::from("/home/tester/.bun/bin"));
        assert!(paths.contains(&std::path::PathBuf::from("/usr/bin")));
        assert!(paths.contains(&std::path::PathBuf::from("/bin")));
    }

    #[test]
    fn test_path_with_home_bun_bin_ignores_empty_home() {
        let _guard = test_guard!();
        assert!(path_with_home_bun_bin(Some(std::ffi::OsString::new()), None).is_none());
        assert!(path_with_home_bun_bin(None, None).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_projects_topology_healthy_symlink() {
        let _guard = test_guard!();
        let (base, canonical, alias) = make_temp_topology_paths("healthy");
        std::os::unix::fs::symlink(&canonical, &alias).expect("create alias symlink");

        let (ok, issue) = probe_projects_topology(&canonical, &alias);
        assert!(ok);
        assert!(issue.is_none());

        std::fs::remove_dir_all(&base).expect("cleanup temp topology");
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_projects_topology_missing_alias() {
        let _guard = test_guard!();
        let (base, canonical, alias) = make_temp_topology_paths("missing-alias");

        let (ok, issue) = probe_projects_topology(&canonical, &alias);
        assert!(!ok);
        assert_eq!(issue.as_deref(), Some("alias_missing"));

        std::fs::remove_dir_all(&base).expect("cleanup temp topology");
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_projects_topology_missing_canonical_root() {
        let _guard = test_guard!();
        let (base, canonical, alias) = make_temp_topology_paths("missing-canonical");
        std::fs::remove_dir_all(&canonical).expect("remove canonical root");

        let (ok, issue) = probe_projects_topology(&canonical, &alias);
        assert!(!ok);
        assert_eq!(issue.as_deref(), Some("canonical_missing"));

        std::fs::remove_dir_all(&base).expect("cleanup temp topology");
    }

    #[test]
    fn test_resolve_topology_roots_from_env_uses_overrides() {
        let _guard = test_guard!();
        let canonical_override = std::ffi::OsString::from("/worker/projects");
        let alias_override = std::ffi::OsString::from("/worker/dp");

        let (canonical, alias) = resolve_topology_roots_from_env(
            Some(canonical_override.clone()),
            Some(alias_override.clone()),
        );

        assert_eq!(canonical, std::path::PathBuf::from(canonical_override));
        assert_eq!(alias, std::path::PathBuf::from(alias_override));
    }

    #[test]
    fn test_resolve_topology_roots_from_env_falls_back_for_empty_values() {
        let _guard = test_guard!();
        let (canonical, alias) =
            resolve_topology_roots_from_env(None, Some(std::ffi::OsString::new()));

        assert_eq!(
            canonical,
            std::path::PathBuf::from(DEFAULT_CANONICAL_PROJECT_ROOT)
        );
        assert_eq!(alias, std::path::PathBuf::from(DEFAULT_ALIAS_PROJECT_ROOT));
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_projects_topology_canonical_not_directory() {
        let _guard = test_guard!();
        let (base, canonical, alias) = make_temp_topology_paths("canonical-not-directory");
        std::fs::remove_dir_all(&canonical).expect("remove canonical directory");
        std::fs::write(&canonical, "not-a-directory").expect("create canonical file");

        let (ok, issue) = probe_projects_topology(&canonical, &alias);
        assert!(!ok);
        assert_eq!(issue.as_deref(), Some("canonical_not_directory"));

        std::fs::remove_dir_all(&base).expect("cleanup temp topology");
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_projects_topology_alias_not_symlink() {
        let _guard = test_guard!();
        let (base, canonical, alias) = make_temp_topology_paths("alias-not-symlink");
        std::fs::create_dir_all(&alias).expect("create alias directory");

        let (ok, issue) = probe_projects_topology(&canonical, &alias);
        assert!(!ok);
        assert_eq!(issue.as_deref(), Some("alias_not_symlink"));

        std::fs::remove_dir_all(&base).expect("cleanup temp topology");
    }

    #[cfg(unix)]
    #[test]
    fn test_probe_projects_topology_wrong_alias_target() {
        let _guard = test_guard!();
        let (base, canonical, alias) = make_temp_topology_paths("wrong-target");
        let wrong_target = base.join("some/other/path");
        std::fs::create_dir_all(&wrong_target).expect("create wrong target");
        std::os::unix::fs::symlink(&wrong_target, &alias).expect("create alias symlink");

        let (ok, issue) = probe_projects_topology(&canonical, &alias);
        assert!(!ok);
        assert!(
            issue
                .as_deref()
                .unwrap_or_default()
                .starts_with("alias_wrong_target:")
        );

        std::fs::remove_dir_all(&base).expect("cleanup temp topology");
    }
}
