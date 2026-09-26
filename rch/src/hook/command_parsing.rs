//! Pure, PLATFORM-NEUTRAL helper functions shared by every hook backend.
//!
//! Command-string parsing: tokenization and the cargo flag/env analyzers that
//! feed classification and core estimation. Principal items:
//! [`estimate_cores_for_command`] (offload core sizing) and
//! [`cargo_job_count_for_command`] are `pub(crate)` (also called by
//! `commands::status`); [`tokenize_command`] is the shared lexer; the
//! `--test-threads` / `-j` / `--ignored` / `--exact` / filtered-test detectors
//! are `pub(super)` for the test suite. The numeric `parse_*` helpers stay
//! module-private.
//!
//! Also hosts two more pure helpers that both the Unix hook and the non-Unix
//! stub need verbatim: project identity extraction (canonical path + short
//! blake3 suffix) and preferred-worker selection (`RCH_WORKER(S)` merged with
//! project `.rch/config.toml` `[routing] preferred_workers`).
//!
//! NOTHING in this module may depend on daemon/socket/SSH state or on a
//! specific parent module: it is included verbatim (`#[path]`) by the
//! non-Unix hook stub (bd-86oa1).

use rch_common::CompilationKind;
use rch_common::WorkerId;
use rch_common::normalize_project_path_with_policy;
use rch_common::path_topology::PathTopologyPolicy;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

fn parse_u32(value: &str) -> Option<u32> {
    value
        .trim_matches('"')
        .parse::<u32>()
        .ok()
        .filter(|n| *n > 0)
}

fn parse_env_u32(command: &str, key: &str) -> Option<u32> {
    let needle = format!("{}=", key);
    command
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&needle).and_then(parse_u32))
}

fn read_env_u32(key: &str) -> Option<u32> {
    if cfg!(test) {
        return None;
    }
    std::env::var(key).ok().and_then(|v| parse_u32(&v))
}

pub(super) fn parse_jobs_flag(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if (*token == "-j" || *token == "--jobs")
            && let Some(next) = tokens.get(idx + 1)
            && let Some(value) = parse_u32(next)
        {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("-j=").and_then(parse_u32) {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("-j").and_then(parse_u32) {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("--jobs=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
}

pub(crate) fn cargo_job_count_for_command(command: &str) -> Option<u32> {
    parse_jobs_flag(command)
        .or_else(|| parse_env_u32(command, "CARGO_BUILD_JOBS"))
        .or_else(|| read_env_u32("CARGO_BUILD_JOBS"))
}

pub(super) fn parse_test_threads(command: &str) -> Option<u32> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == "--test-threads"
            && let Some(next) = tokens.get(idx + 1)
            && let Some(value) = parse_u32(next)
        {
            return Some(value);
        }
        if let Some(value) = token.strip_prefix("--test-threads=").and_then(parse_u32) {
            return Some(value);
        }
    }
    None
}

fn tokenize_command(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for c in command.chars() {
        if escaped {
            current.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if c == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if c.is_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
            continue;
        }
        current.push(c);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Detect if a cargo test command has a test name filter.
///
/// Filtered tests (e.g., `cargo test my_test`) typically run fewer tests
/// and thus require fewer slots than a full test suite.
///
/// Returns true if the command appears to filter tests by name.
pub(super) fn is_filtered_test_command(command: &str) -> bool {
    let tokens = tokenize_command(command);

    // Find the position of "test" or "run" (for nextest) in the command
    let test_pos = tokens
        .iter()
        .position(|t| t == "test" || t == "t" || t == "run");
    let Some(test_idx) = test_pos else {
        return false;
    };

    // Flags that take a separate argument (not using =)
    let flags_with_args = [
        "-p",
        "--package",
        "--bin",
        "--test",
        "--bench",
        "--example",
        "--features",
        "--target",
        "--target-dir",
        "-j",
        "--jobs",
        "--color",
        "--message-format",
        "--manifest-path",
        "--profile",
        "--config",
        "-Z",
    ];

    let mut i = test_idx + 1;
    while i < tokens.len() {
        let token = &tokens[i];

        // Stop at the separator
        if token == "--" {
            // Check if there is a positional argument after --
            if i + 1 < tokens.len() {
                let next = &tokens[i + 1];
                if !next.starts_with('-') {
                    return true;
                }
            }
            break;
        }

        // Check if this is a flag that takes an argument
        if flags_with_args.contains(&token.as_str()) {
            i += 2;
            continue;
        }

        // Check if this is a flag=value style
        if flags_with_args
            .iter()
            .any(|&f| token.starts_with(&format!("{}=", f)))
        {
            i += 1;
            continue;
        }

        // Skip any other flag-like tokens
        if token.starts_with('-') {
            i += 1;
            continue;
        }

        // Found a non-flag token - this is a test name filter
        return true;
    }

    false
}

/// Check if the command has the --ignored flag (for running only ignored tests).
///
/// Tests marked with `#[ignore]` are typically a small subset, so they need
/// fewer slots. However, --include-ignored runs all tests plus ignored ones.
pub(super) fn has_ignored_only_flag(command: &str) -> bool {
    let tokens = tokenize_command(command);

    let has_ignored = tokens.iter().any(|t| t == "--ignored");
    let has_include_ignored = tokens.iter().any(|t| t == "--include-ignored");

    has_ignored && !has_include_ignored
}

/// Check if the command has the --exact flag for exact test name matching.
pub(super) fn has_exact_flag(command: &str) -> bool {
    tokenize_command(command).iter().any(|t| t == "--exact")
}

/// Locate Cargo without treating a wrapper's option value as the executable.
/// Wrapper `--` belongs to that wrapper, not to Cargo's argument passthrough.
/// Keep this platform-neutral: both hook backends use the profile analyzer.
fn cargo_profile_tokens(command: &str) -> Option<(Vec<String>, usize)> {
    let tokens = shell_words::split(command).ok()?;
    let assignment = |word: &str| {
        word.split_once('=')
            .is_some_and(|(key, _)| rch_common::ssh_utils::is_valid_env_key(key))
    };
    let mut index = 0;
    loop {
        while tokens.get(index).is_some_and(|word| assignment(word)) {
            index += 1;
        }
        let executable = Path::new(tokens.get(index)?).file_name()?.to_str()?;
        match executable {
            "cargo" | "cargo.exe" | "cargo-zigbuild" | "cargo-zigbuild.exe" | "cargo-xwin"
            | "cargo-xwin.exe" => return Some((tokens, index)),
            "env" | "time" => {
                let is_env = executable == "env";
                index += 1;
                while let Some(word) = tokens.get(index) {
                    if word == "--" {
                        index += 1;
                        break;
                    }
                    let takes_value = if is_env {
                        matches!(word.as_str(), "-u" | "--unset" | "-C" | "--chdir")
                    } else {
                        matches!(word.as_str(), "-f" | "--format" | "-o" | "--output")
                    };
                    if takes_value {
                        tokens.get(index + 1)?;
                        index += 2;
                        continue;
                    }
                    let flag = if is_env {
                        matches!(word.as_str(), "-i" | "--ignore-environment" | "--debug")
                            || word.starts_with("--unset=")
                            || word.starts_with("--chdir=")
                            || word.starts_with("-u") && word.len() > 2
                            || word.starts_with("-C") && word.len() > 2
                    } else {
                        matches!(
                            word.as_str(),
                            "-p" | "--portability"
                                | "-v"
                                | "--verbose"
                                | "-a"
                                | "--append"
                                | "-q"
                                | "--quiet"
                        ) || word.starts_with("--format=")
                            || word.starts_with("--output=")
                            || word.starts_with("-f") && word.len() > 2
                            || word.starts_with("-o") && word.len() > 2
                    };
                    if flag {
                        index += 1;
                    } else if word.starts_with('-') {
                        // In particular env -S reparses its payload; it is not
                        // an unchanged Cargo argv suffix we can inspect here.
                        return None;
                    } else {
                        break;
                    }
                }
            }
            "rustup" => {
                if tokens.get(index + 1)?.as_str() != "run" {
                    return None;
                }
                index += 2;
                if tokens.get(index).is_some_and(|word| word == "--install") {
                    index += 1;
                }
                if tokens.get(index).is_some_and(|word| word == "--") {
                    index += 1;
                }
                let channel = tokens.get(index)?;
                if channel.is_empty() || channel.starts_with('-') {
                    return None;
                }
                index += 1;
            }
            _ => {
                // Reuse the classifier for its other wrappers (nice, timeout,
                // taskset, ...), but only when it identifies an unchanged argv
                // suffix. Never search arbitrary argument values for "cargo".
                let remaining = shell_words::join(&tokens[index..]);
                let normalized = rch_common::patterns::normalize_command(&remaining);
                let suffix = shell_words::split(&normalized).ok()?;
                let start = tokens.len().checked_sub(suffix.len())?;
                if suffix.is_empty() || start <= index || tokens[start + 1..] != suffix[1..] {
                    return None;
                }
                index = start;
            }
        }
    }
}

/// Resolve the output-directory name cargo will use for the `--profile <name>`
/// this command selects — but only when it differs from the two directories
/// the default artifact globs already cover (`debug/`, `release/`).
///
/// cargo maps a profile to its output directory via the profile's *dir name*
/// (cargo `Profile::dir_name`): the built-in `dev` and `test` profiles write
/// to `target/debug/`, the built-in `release` and `bench` profiles write to
/// `target/release/`, and every CUSTOM profile writes to
/// `target/<profile-name>/`. (Verified empirically against cargo 1.93:
/// `--profile test` leaves no `test/` directory, and `--profile bench` leaves
/// no `bench/` directory — both reuse the covered dirs.) So:
///
/// - `cargo build`, `--release`, `-r`, `--profile dev|test|release|bench`
///   → `None` (output dir already covered by default patterns).
/// - `cargo build --profile release-perf` → `Some("release-perf")`.
///
/// Wrappers and their option values are skipped before inspecting Cargo's
/// arguments. Only Cargo's own `--` ends the scan. Values of other Cargo
/// options cannot masquerade as a profile selector. Profile names are plain
/// path components, never rsync patterns or traversal components.
pub(super) fn cargo_custom_profile_output_dir(command: &str) -> Option<String> {
    let (tokens, cargo_index) = cargo_profile_tokens(command)?;
    let mut iter = tokens[cargo_index + 1..].iter();
    while let Some(token) = iter.next() {
        if token == "--" {
            break;
        }
        let value = if token == "--profile" {
            iter.next()?.as_str()
        } else if let Some(name) = token.strip_prefix("--profile=") {
            name
        } else {
            // These values are opaque even if they look like --profile=P or
            // --. Joined options already keep their value in the same token.
            if matches!(
                token.as_str(),
                "--config"
                    | "--target"
                    | "--target-dir"
                    | "--manifest-path"
                    | "--lockfile-path"
                    | "--package"
                    | "-p"
                    | "--exclude"
                    | "--features"
                    | "-F"
                    | "--bin"
                    | "--example"
                    | "--test"
                    | "--bench"
                    | "--color"
                    | "--message-format"
                    | "--jobs"
                    | "-j"
                    | "-Z"
                    | "-C"
                    | "--artifact-dir"
                    | "--out-dir"
            ) {
                iter.next()?;
            }
            continue;
        };
        if matches!(value, "dev" | "test" | "release" | "bench") {
            return None;
        }
        let is_plain_profile_name = !value.is_empty()
            && !matches!(value, "." | "..")
            && !value.starts_with('-')
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        return is_plain_profile_name.then(|| value.to_string());
    }
    None
}

/// Recognize Cargo's build-only test/bench mode without treating another
/// option's value, a wrapper argument, or a libtest argument as --no-run.
/// This selects artifact/capacity policy; Cargo still validates the invocation.
/// Unknown option shapes retain the previous policy rather than guessing.
fn cargo_build_only_test_options(command: &str) -> Option<(CompilationKind, Option<u32>)> {
    let (tokens, cargo_index) = cargo_profile_tokens(command)?;
    if !matches!(
        Path::new(&tokens[cargo_index]).file_name()?.to_str()?,
        "cargo" | "cargo.exe"
    ) {
        return None;
    }
    let mut args = tokens[cargo_index + 1..].iter().peekable();
    if args.peek().is_some_and(|arg| arg.starts_with('+'))
        && args.next()?.len() == 1
    {
        return None;
    }
    let takes_value = |arg: &str| {
        matches!(
            arg,
            "--config" | "--target" | "--target-dir" | "--build-dir"
                | "--manifest-path" | "--lockfile-path" | "--package" | "-p"
                | "--exclude" | "--features" | "-F" | "--bin" | "--example"
                | "--test" | "--bench" | "--profile" | "--color"
                | "--message-format" | "--jobs" | "-j" | "-Z" | "-C"
                | "--artifact-dir" | "--out-dir"
        )
    };
    let mut kind = None;
    let mut no_run = false;
    let mut jobs = None;
    while let Some(arg) = args.next() {
        if arg == "--" {
            break;
        }
        if takes_value(arg) {
            let value = args.next()?;
            if matches!(arg.as_str(), "-j" | "--jobs") {
                jobs = parse_u32(value);
            }
            continue;
        }
        if arg == "--no-run" {
            // Cargo owns this flag, not a wrapper or a command alias value.
            kind?;
            no_run = true;
            continue;
        }
        if matches!(arg.as_str(), "--help" | "-h" | "--version" | "-V" | "--list" | "--doc") {
            return None;
        }
        if let Some(value) = arg.strip_prefix("--jobs=")
            .or_else(|| arg.strip_prefix("-j="))
            .or_else(|| arg.strip_prefix("-j"))
        {
            jobs = parse_u32(value);
            continue;
        }
        if arg.split_once('=').is_some_and(|(key, _)| takes_value(key))
            || ["-p", "-F", "-Z", "-C"].iter()
                .any(|prefix| arg.starts_with(*prefix) && arg.len() > prefix.len())
        {
            continue;
        }
        if matches!(
            arg.as_str(),
            "--workspace" | "--all" | "--lib" | "--bins" | "--tests" | "--benches"
                | "--examples" | "--all-targets" | "--all-features"
                | "--no-default-features" | "--no-fail-fast" | "--release"
                | "--quiet" | "--verbose" | "--frozen" | "--locked" | "--offline"
                | "--future-incompat-report" | "--timings" | "--keep-going" | "--ignore-rust-version"
        ) || arg.starts_with("--timings=")
            || arg.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty() && flags.chars().all(|flag| matches!(flag, 'v' | 'q' | 'r'))
            })
        {
            continue;
        }
        if arg.starts_with('-') || matches!(arg.as_str(), ";" | "&&" | "||" | "|" | "&") {
            return None;
        }
        if kind.is_none() {
            kind = Some(match arg.as_str() {
                "test" | "t" => CompilationKind::CargoTest,
                "bench" => CompilationKind::CargoBench,
                _ => return None,
            });
        }
        // Other positional arguments are test/bench name filters. They do not
        // reduce compilation work and cannot select the build-only mode.
    }
    no_run.then_some((kind?, jobs))
}

/// Whether the classified test/bench invocation explicitly compiles without
/// running. Nextest and other test runners have separate command contracts.
pub(super) fn cargo_build_only_test(kind: Option<CompilationKind>, command: &str) -> bool {
    matches!(kind, Some(CompilationKind::CargoTest | CompilationKind::CargoBench))
        && cargo_build_only_test_options(command)
            .is_some_and(|(selected, _)| Some(selected) == kind)
}

pub(crate) fn estimate_cores_for_command(
    kind: Option<CompilationKind>,
    command: &str,
    config: &rch_common::CompilationConfig,
) -> u32 {
    let build_default = config.build_slots.max(1);
    let test_default = config.test_slots.max(1);
    let check_default = config.check_slots.max(1);

    if matches!(kind, Some(CompilationKind::CargoTest | CompilationKind::CargoBench))
        && let Some((selected, jobs)) = cargo_build_only_test_options(command)
        && Some(selected) == kind
    {
        // --no-run starts no test harness. Name filters, --test-threads and
        // RUST_TEST_THREADS cannot shrink its compiler reservation. The jobs
        // value above came only from Cargo's argv, before its own -- separator.
        return jobs
            .or_else(|| parse_env_u32(command, "CARGO_BUILD_JOBS"))
            .or_else(|| read_env_u32("CARGO_BUILD_JOBS"))
            .unwrap_or(build_default);
    }

    // Slot reduction for filtered tests (fewer tests = fewer slots needed)
    let filtered_test_slots = (test_default / 2).max(2).min(test_default);

    match kind {
        Some(CompilationKind::CargoTest | CompilationKind::CargoNextest) => {
            // Priority order for test slot estimation:
            // 1. Explicit cargo -j/--jobs or CARGO_BUILD_JOBS
            // 2. Explicit --test-threads flag
            // 3. RUST_TEST_THREADS environment variable (inline or ambient)
            // 4. Inferred from test filtering (reduced slots)
            // 5. Default test_slots from config
            if let Some(jobs) = cargo_job_count_for_command(command) {
                return jobs.max(1);
            }
            if let Some(threads) = parse_test_threads(command) {
                return threads.max(1);
            }
            if let Some(threads) = parse_env_u32(command, "RUST_TEST_THREADS")
                .or_else(|| read_env_u32("RUST_TEST_THREADS"))
            {
                return threads.max(1);
            }

            // Reduce slots for filtered tests:
            // - Specific test name filter (cargo test my_test)
            // - --exact flag (single test match)
            // - --ignored only (typically few ignored tests)
            if is_filtered_test_command(command) || has_exact_flag(command) {
                return filtered_test_slots;
            }
            if has_ignored_only_flag(command) {
                return filtered_test_slots;
            }

            test_default.max(1)
        }
        Some(CompilationKind::BunTest) => {
            if let Some(threads) = parse_test_threads(command) {
                return threads.max(1);
            }
            if let Some(threads) = parse_env_u32(command, "RUST_TEST_THREADS")
                .or_else(|| read_env_u32("RUST_TEST_THREADS"))
            {
                return threads.max(1);
            }

            if is_filtered_test_command(command) || has_exact_flag(command) {
                return filtered_test_slots;
            }
            if has_ignored_only_flag(command) {
                return filtered_test_slots;
            }

            test_default.max(1)
        }
        Some(
            CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::BunTypecheck
            // `go vet` and `tsc --noEmit` are diagnostic passes, not builds.
            | CompilationKind::GoVet
            | CompilationKind::Tsc,
        ) => cargo_job_count_for_command(command)
            .unwrap_or(check_default)
            .max(1),
        // Go: `-j/--jobs` is meaningless (go uses `-p`), so don't try to parse a
        // cargo job count out of the command — take the default bucket directly.
        Some(CompilationKind::GoBuild) => build_default.max(1),
        Some(_) => cargo_job_count_for_command(command)
            .unwrap_or(build_default)
            .max(1),
        None => build_default,
    }
}

// --- Preferred-worker env selection (moved verbatim from hook.rs, bd-86oa1) ---

const RCH_WORKER_ENV: &str = "RCH_WORKER";
const RCH_WORKERS_ENV: &str = "RCH_WORKERS";

pub(crate) fn preferred_workers_from_env() -> Vec<WorkerId> {
    let mut preferred = Vec::new();
    if let Ok(value) = std::env::var(RCH_WORKER_ENV) {
        preferred.extend(parse_preferred_workers(&value));
    }
    if let Ok(value) = std::env::var(RCH_WORKERS_ENV) {
        preferred.extend(parse_preferred_workers(&value));
    }
    dedupe_worker_ids(preferred)
}

/// Env (`RCH_WORKER`/`RCH_WORKERS`) merged with project-local
/// `.rch/config.toml` `[routing] preferred_workers`, then deduped.
/// The daemon treats a non-empty list as a hard preference.
pub(crate) fn preferred_workers() -> Vec<WorkerId> {
    let mut combined = preferred_workers_from_env();
    combined.extend(preferred_workers_from_project_config());
    dedupe_worker_ids(combined)
}

/// Read `[routing] preferred_workers` from the project-local `.rch/config.toml`
/// relative to the current dir. Best-effort: missing/malformed/wrong-typed
/// config yields no pinning, never an error.
pub(crate) fn preferred_workers_from_project_config() -> Vec<WorkerId> {
    let path = std::env::current_dir()
        .map(|dir| dir.join(".rch/config.toml"))
        .unwrap_or_else(|_| PathBuf::from(".rch/config.toml"));
    preferred_workers_from_config_path(&path)
}

pub(super) fn preferred_workers_from_config_path(path: &Path) -> Vec<WorkerId> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_preferred_workers_from_toml(&contents),
        Err(_) => Vec::new(),
    }
}

/// Extract `[routing] preferred_workers = ["id", ...]` from project-config TOML.
/// Unknown sections are ignored; a wrong-typed or malformed value yields empty.
pub(super) fn parse_preferred_workers_from_toml(contents: &str) -> Vec<WorkerId> {
    #[derive(serde::Deserialize)]
    struct Doc {
        routing: Option<RoutingSection>,
    }
    #[derive(serde::Deserialize)]
    struct RoutingSection {
        preferred_workers: Option<Vec<String>>,
    }
    let Ok(doc) = toml::from_str::<Doc>(contents) else {
        return Vec::new();
    };
    doc.routing
        .and_then(|routing| routing.preferred_workers)
        .unwrap_or_default()
        .iter()
        .map(|id| id.trim())
        .filter(|id| !id.is_empty())
        .map(WorkerId::new)
        .collect()
}

pub(super) fn parse_preferred_workers(value: &str) -> Vec<WorkerId> {
    value
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map(WorkerId::new)
        .collect()
}

pub(super) fn dedupe_worker_ids(workers: Vec<WorkerId>) -> Vec<WorkerId> {
    let mut deduped = Vec::new();
    for worker in workers {
        if !deduped.contains(&worker) {
            deduped.push(worker);
        }
    }
    deduped
}

/// Default-policy convenience shim. Used where only the project identity is
/// needed (local-fallback incident records) and no topology policy is in scope.
pub(crate) fn extract_project_name() -> String {
    extract_project_name_with_policy(&PathTopologyPolicy::default())
}

/// Extract project name from current working directory, honoring the
/// supplied [`PathTopologyPolicy`].
pub(crate) fn extract_project_name_with_policy(policy: &PathTopologyPolicy) -> String {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("unknown"));
    let normalized_cwd = match normalize_project_path_with_policy(&cwd, policy) {
        Ok(normalized) => {
            for decision in normalized.decision_trace() {
                debug!("[RCH] project identity normalization: {}", decision);
            }
            normalized.canonical_path().to_path_buf()
        }
        Err(err) => {
            warn!(
                "Project path normalization failed for {}: {}",
                cwd.display(),
                err
            );
            for decision in err.decision_trace() {
                debug!(
                    "[RCH] project identity normalization failed at: {}",
                    decision
                );
            }
            cwd.clone()
        }
    };

    let name = normalized_cwd
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Compute short hash of the canonical project path to ensure stable identity
    // across equivalent aliases (for example /dp/repo and /data/projects/repo).
    // This prevents cache affinity collisions for projects with same dir name (e.g. "app")
    let hash = blake3::hash(normalized_cwd.to_string_lossy().as_bytes()).to_hex();
    let short_hash = &hash[..8];

    format!("{}-{}", name, short_hash)
}

#[cfg(test)]
mod cargo_profile_tests {
    use super::cargo_custom_profile_output_dir;

    #[test]
    fn build_only_test_mode_belongs_to_cargo_not_option_values_or_libtest() {
        use super::{CompilationKind, cargo_build_only_test};
        for command in [
            "cargo test --no-run",
            "cargo t -vv --no-run --release",
            "env -- cargo +nightly --config net.offline=true test --no-run",
            "env -u --no-run time -f cargo -- cargo test --no-run --profile release-perf",
            "rustup run nightly cargo test name_filter --no-run -- --exact",
            "cargo test --config --no-run --no-run",
        ] {
            assert!(cargo_build_only_test(Some(CompilationKind::CargoTest), command), "{command}");
        }
        assert!(cargo_build_only_test(
            Some(CompilationKind::CargoBench), "cargo bench --no-run --bench timing"
        ));
        for command in [
            "cargo test -- --no-run", "cargo test --no-runner", "cargo test --no-run=true",
            "cargo test --no-run --help", "cargo test --no-run --doc",
            "cargo --no-run test", "cargo run -- --no-run", "cargo build --no-run",
            "cargo nextest run --no-run", "cargo-zigbuild test --no-run",
            "env -u --no-run cargo test", "time -f --no-run cargo test",
            "printf '%s' 'cargo test --no-run'", "cargo test --no-run && echo done",
            "cargo test --no-run --unknown-option", "cargo test --no-run 'unterminated",
        ] {
            assert!(!cargo_build_only_test(Some(CompilationKind::CargoTest), command), "{command}");
        }
        for option in ["--config", "--package", "--test", "--bench", "--profile", "--features",
            "--target", "--target-dir", "--manifest-path", "--message-format", "-Z", "-C"]
        {
            let command = format!("cargo test {option} --no-run");
            assert!(!cargo_build_only_test(Some(CompilationKind::CargoTest), &command), "{command}");
        }
        assert!(!cargo_build_only_test(Some(CompilationKind::CargoBench), "cargo test --no-run"));
        assert!(!cargo_build_only_test(Some(CompilationKind::CargoTest), "cargo bench --no-run"));
    }

    #[test]
    fn build_only_tests_reserve_compiler_capacity_not_filtered_test_capacity() {
        use super::{CompilationKind, estimate_cores_for_command};
        let mut config = rch_common::CompilationConfig {
            build_slots: 12,
            test_slots: 4,
            ..Default::default()
        };
        for (kind, command, expected) in [
            (CompilationKind::CargoTest, "cargo test filter --no-run -- --exact --test-threads=1", 12),
            (CompilationKind::CargoTest, "RUST_TEST_THREADS=1 cargo test --no-run", 12),
            (CompilationKind::CargoTest, "cargo test --no-run -- --jobs=99", 12),
            (CompilationKind::CargoTest, "cargo test --no-run -j3 -- --jobs=99", 3),
            (CompilationKind::CargoTest, "cargo test --no-run -j=3", 3),
            (CompilationKind::CargoTest, "cargo --jobs 5 test --no-run", 5),
            (CompilationKind::CargoTest, "CARGO_BUILD_JOBS=6 cargo test --no-run", 6),
            (CompilationKind::CargoBench, "cargo bench --no-run --jobs=2", 2),
            (CompilationKind::CargoTest, "cargo test filter -- --exact --test-threads=1", 1),
        ] {
            assert_eq!(estimate_cores_for_command(Some(kind), command, &config), expected, "{command}");
        }
        config.build_slots = 0;
        assert_eq!(estimate_cores_for_command(
            Some(CompilationKind::CargoTest), "cargo test --no-run", &config
        ), 1);
    }

    #[test]
    fn cargo_profile_boundaries_skip_wrappers_without_losing_the_selected_output_tree() {
        for command in [
            "env -- cargo build --profile release-perf",
            "env -- KEY=value /usr/bin/cargo +nightly build --profile=release-perf",
            "env -u --profile=wrong -- cargo build --profile release-perf",
            "env -C 'directory with spaces' -- cargo build --profile release-perf",
            "/usr/bin/time -f cargo -- cargo build --profile release-perf",
            "/usr/bin/time --format=--profile=wrong -- cargo build --profile release-perf",
            "env -- /usr/bin/time -f '--profile=wrong' -- rustup run nightly cargo build --profile release-perf",
            "rustup run --install nightly cargo build --profile release-perf",
            "nice -n 10 env -- cargo build --profile release-perf",
            "timeout 60 env -- cargo build --profile release-perf",
            "env -- cargo-zigbuild zigbuild --profile release-perf --target aarch64-unknown-linux-gnu",
            "env -- cargo-xwin build --profile release-perf",
        ] {
            assert_eq!(
                cargo_custom_profile_output_dir(command).as_deref(),
                Some("release-perf"),
                "{command}"
            );
        }
    }

    #[test]
    fn cargo_profile_boundaries_ignore_other_option_values_and_program_arguments() {
        for option in [
            "--config",
            "--target",
            "--target-dir",
            "--manifest-path",
            "--package",
            "-p",
            "--exclude",
            "--features",
            "-F",
            "--bin",
            "--example",
            "--test",
            "--bench",
            "--color",
            "--message-format",
            "--jobs",
            "-j",
            "-Z",
            "-C",
            "--lockfile-path",
            "--artifact-dir",
            "--out-dir",
        ] {
            let command =
                format!("env -- cargo build {option} --profile=decoy --profile release-perf");
            assert_eq!(
                cargo_custom_profile_output_dir(&command).as_deref(),
                Some("release-perf"),
                "{command}"
            );
            assert_eq!(
                cargo_custom_profile_output_dir(&format!("cargo build {option} --profile=decoy")),
                None,
                "{option} value is not a profile selector"
            );
        }
        for command in [
            "env -- cargo run -- --profile release-perf",
            "rustup run nightly cargo test -- --profile=release-perf",
            "cargo build --config=--profile=decoy",
            "env -- print-args cargo build --profile release-perf",
            "printf '%s' 'cargo build --profile release-perf'",
        ] {
            assert_eq!(cargo_custom_profile_output_dir(command), None, "{command}");
        }
    }

    #[test]
    fn cargo_profile_boundaries_preserve_literals_and_refuse_pattern_or_path_components() {
        for profile in [
            "dev", "test", "release", "bench", "", ".", "..", "../peer", "a/b", "a*b", "a?b",
            "[ab]", "--", "-bad", "a\\b",
        ] {
            let command = shell_words::join(["cargo", "build", "--profile", profile]);
            assert_eq!(
                cargo_custom_profile_output_dir(&command),
                None,
                "{profile:?}"
            );
        }
        for command in [
            "cargo build --profile",
            "cargo build --profile=",
            "cargo build --profile 'unterminated",
            "cargo build --profile 'release\\-perf'",
        ] {
            assert_eq!(cargo_custom_profile_output_dir(command), None, "{command}");
        }
        assert_eq!(
            cargo_custom_profile_output_dir("cargo build --profile 'release-perf.v2'").as_deref(),
            Some("release-perf.v2")
        );
    }
}
