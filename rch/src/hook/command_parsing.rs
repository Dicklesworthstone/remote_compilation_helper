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
//! blake3 suffix) and preferred-worker env parsing (`RCH_WORKER(S)`).
//!
//! NOTHING in this module may depend on daemon/socket/SSH state or on a
//! specific parent module: it is included verbatim (`#[path]`) by the
//! non-Unix hook stub (bd-86oa1).

use rch_common::CompilationKind;
use rch_common::WorkerId;
use rch_common::normalize_project_path_with_policy;
use rch_common::path_topology::PathTopologyPolicy;
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
///
/// Exact matching typically results in running a single test.
pub(super) fn has_exact_flag(command: &str) -> bool {
    tokenize_command(command).iter().any(|t| t == "--exact")
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
///   → `None` (output dir already covered by `target/{debug,release}/**`).
/// - `--profile release-perf` (any custom name) → `Some("release-perf")`.
///
/// Without this, a custom-profile remote build syncs back only the loose
/// target-root metadata files (`.rustc_info.json`, `CACHEDIR.TAG`) while the
/// real binary stays on the worker — the local binary silently goes STALE
/// even though the build "succeeded" (bd-mpbav).
///
/// Only tokens BEFORE a bare `--` are considered: after `--`, arguments go to
/// the test/bench binary, not cargo (e.g. `cargo test -- --profile x` must
/// not be misread as a cargo profile). The value is validated as a plain
/// profile name (`[A-Za-z0-9._-]+`) because it is interpolated into rsync
/// include/exclude patterns — anything path-like or glob-like is rejected
/// (cargo itself would reject it too).
pub(super) fn cargo_custom_profile_output_dir(command: &str) -> Option<String> {
    let tokens = tokenize_command(command);
    let mut iter = tokens.iter().peekable();
    while let Some(token) = iter.next() {
        // End of cargo's own arguments: everything past `--` belongs to the
        // executed test/bench binary, never to cargo.
        if token == "--" {
            break;
        }
        let value = if token == "--profile" {
            // `--profile <name>`: the profile name is the next token.
            iter.next().cloned()?
        } else if let Some(name) = token.strip_prefix("--profile=") {
            // `--profile=<name>` single-token form.
            name.to_string()
        } else {
            continue;
        };
        // Built-in profiles reuse the already-covered dirs (see doc comment):
        // dev/test → debug, release/bench → release.
        if matches!(value.as_str(), "dev" | "test" | "release" | "bench") {
            return None;
        }
        // A custom profile name doubles as the output directory name. Restrict
        // to cargo's profile-name charset so the value can never smuggle a
        // path traversal or rsync wildcard into the artifact patterns.
        let is_plain_profile_name = !value.is_empty()
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
        return if is_plain_profile_name {
            Some(value)
        } else {
            None
        };
    }
    None
}

pub(crate) fn estimate_cores_for_command(
    kind: Option<CompilationKind>,
    command: &str,
    config: &rch_common::CompilationConfig,
) -> u32 {
    let build_default = config.build_slots.max(1);
    let test_default = config.test_slots.max(1);
    let check_default = config.check_slots.max(1);

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

/// Default-policy convenience shim (retained for test coverage).
#[allow(dead_code)]
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
