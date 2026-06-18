//! Remote cargo target-dir resolution / naming / command-rewrite for the hook.
//!
//! This submodule owns the logic that decides *where* a remote cargo build writes
//! its artifacts and *how* the delegated command is reshaped so the worker uses
//! that location, extracted from `hook.rs` per bead
//! `remote_compilation_helper-zcecy.14`:
//!
//! - **`CARGO_TARGET_DIR` forwarding** — [`resolve_forwarded_cargo_target_dir`]
//!   (and its lookup-injected core [`resolve_forwarded_cargo_target_dir_with_lookup`])
//!   decide whether the agent asked for a specific local target dir (via the
//!   environment or the delegated command tokens) so the artifacts can be synced
//!   back there, plus [`cargo_target_env_allowlist`] / [`cargo_target_env_overrides`]
//!   that thread `CARGO_TARGET_DIR` through the worker env.
//! - **Remote target-dir naming** — [`remote_cargo_target_dir_name`] (unique
//!   per-job) and [`remote_cargo_pooled_target_dir_name`] (the stable, cache-warm
//!   pooled name keyed on toolchain/triple/profile/feature-set), with
//!   [`sanitize_cargo_home_token`] producing the path-safe segment they share.
//!   [`target_reuse_disabled`] selects between the two; [`stale_target_reap_idle_hours`]
//!   tunes the abandoned-per-job-dir reaper.
//! - **Command rewriting** — [`rewrite_cargo_target_dir_command_for_remote`] strips
//!   any local `CARGO_TARGET_DIR` / `--target-dir` from the command before remote
//!   execution (so the worker-scoped dir is injected instead), built on the
//!   token-level [`strip_cargo_target_dir_assignments_from_command_tokens`],
//!   [`strip_cargo_target_dir_flags_from_command_tokens`], and
//!   [`extract_cargo_target_dir_from_command_tokens`] helpers.
//!
//! It reaches its support layer from the parent via `use super::*`: `HookReporter`,
//! the `rch_common` types (`CompilationKind`, `WorkerId`, `ToolchainInfo`,
//! `pooled_target_key::*`), the `RCH_DISABLE_TARGET_REUSE_ENV` const, and the
//! parent helpers `parse_command_tokens` / `join_exec_command` / `detect_target_label`.
//!
//! Items consumed by the parent (`run_hook` / `run_exec` call
//! `resolve_forwarded_cargo_target_dir` + `rewrite_cargo_target_dir_command_for_remote`,
//! and `add_cargo_isolation` shares `sanitize_cargo_home_token`) are re-exported
//! into `hook`; the sibling `transfer_orchestration` imports the six dir-naming /
//! env helpers it needs directly from `super::cargo_target_dir`. The remaining
//! `pub(super)` items are reached only by the hook test suite (which imports them
//! into `hook::tests`). Four helpers used solely within this cluster
//! (`env_allowlist_contains`, `cargo_kind_uses_target_dir`,
//! `default_host_target_triple`, `skip_env_option_prefix`) stay private.

use super::formatting::detect_target_label;
use super::*;
use std::collections::HashMap;

fn env_allowlist_contains(env_allowlist: &[String], key: &str) -> bool {
    env_allowlist
        .iter()
        .map(|item| item.trim())
        .any(|item| item == key)
}

fn cargo_kind_uses_target_dir(kind: Option<CompilationKind>) -> bool {
    matches!(
        kind,
        Some(
            CompilationKind::CargoBuild
                | CompilationKind::CargoCheck
                | CompilationKind::CargoClippy
                | CompilationKind::CargoDoc
                | CompilationKind::CargoTest
                | CompilationKind::CargoNextest
                | CompilationKind::CargoBench,
        )
    )
}

pub(super) fn resolve_forwarded_cargo_target_dir_with_lookup<F>(
    kind: Option<CompilationKind>,
    invocation_cwd: &Path,
    reporter: &HookReporter,
    mut lookup_env: F,
    command_tokens: Option<&[String]>,
) -> Option<PathBuf>
where
    F: FnMut(&str) -> Option<String>,
{
    if !cargo_kind_uses_target_dir(kind) {
        return None;
    }

    let raw = command_tokens
        .and_then(|tokens| {
            extract_cargo_target_dir_from_command_tokens(tokens).inspect(|_| {
                reporter.verbose(
                    "[RCH] CARGO_TARGET_DIR forwarding detected from delegated command tokens",
                );
            })
        })
        .or_else(|| {
            lookup_env("CARGO_TARGET_DIR").inspect(|_| {
                reporter.verbose("[RCH] CARGO_TARGET_DIR forwarding detected from environment");
            })
        });

    let resolved = raw.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            reporter.verbose("[RCH] CARGO_TARGET_DIR is empty; using default Cargo target dir");
            return None;
        }

        let requested = PathBuf::from(trimmed);
        Some(if requested.is_absolute() {
            requested
        } else {
            invocation_cwd.join(requested)
        })
    });

    let resolved = resolved.unwrap_or_else(|| invocation_cwd.join("target"));

    reporter.verbose(&format!(
        "[RCH] Cargo target sync active; forcing worker CARGO_TARGET_DIR to an isolated remote target and syncing back to {}",
        resolved.display()
    ));
    Some(resolved)
}

pub(super) fn resolve_forwarded_cargo_target_dir(
    kind: Option<CompilationKind>,
    invocation_cwd: &Path,
    reporter: &HookReporter,
    command_tokens: Option<&[String]>,
) -> Option<PathBuf> {
    resolve_forwarded_cargo_target_dir_with_lookup(
        kind,
        invocation_cwd,
        reporter,
        |key| std::env::var(key).ok(),
        command_tokens,
    )
}

pub(super) fn cargo_target_env_allowlist(
    env_allowlist: &[String],
    cargo_target_sync: bool,
) -> Vec<String> {
    let mut effective = env_allowlist.to_vec();
    if cargo_target_sync && !env_allowlist_contains(&effective, "CARGO_TARGET_DIR") {
        effective.push("CARGO_TARGET_DIR".to_string());
    }
    effective
}

pub(super) fn cargo_target_env_overrides(
    local_target_dir: Option<&Path>,
) -> Option<HashMap<String, String>> {
    let local_target_dir = local_target_dir?;
    let mut overrides = HashMap::new();
    overrides.insert(
        "CARGO_TARGET_DIR".to_string(),
        local_target_dir.to_string_lossy().to_string(),
    );
    Some(overrides)
}

/// Reduce an arbitrary token to a path-safe basename component: ASCII
/// alphanumerics, `-` and `_` are kept; everything else collapses to `-`,
/// leading/trailing `-` are trimmed, and an empty result falls back to
/// `"worker"`. Shared by the per-job target dir and isolated CARGO_HOME naming.
pub(super) fn sanitize_cargo_home_token(token: &str) -> String {
    let safe = token
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    let safe = safe.trim_matches('-');
    if safe.is_empty() {
        "worker".to_string()
    } else {
        safe.to_string()
    }
}

pub(super) fn remote_cargo_target_dir_name(build_id: Option<u64>, worker_id: &WorkerId) -> String {
    static REMOTE_CARGO_TARGET_DIR_SEQUENCE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    let safe_worker_id = sanitize_cargo_home_token(worker_id.as_str());
    let job_id = build_id
        .map(|id| format!("job-{id}"))
        .unwrap_or_else(|| format!("pid-{}", std::process::id()));
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence =
        REMOTE_CARGO_TARGET_DIR_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    format!(".rch-target-{safe_worker_id}-{job_id}-{timestamp}-{sequence}")
}

/// Whether remote target-dir REUSE is disabled via [`RCH_DISABLE_TARGET_REUSE_ENV`].
/// Any non-empty value other than `0`/`false`/`no`/`off` (case-insensitive) opts out.
pub(super) fn target_reuse_disabled() -> bool {
    target_reuse_disabled_from_value(std::env::var(RCH_DISABLE_TARGET_REUSE_ENV).ok())
}

/// Pure predicate behind [`target_reuse_disabled`] (env value injected so it is
/// unit-testable under `#![forbid(unsafe_code)]`, where `set_var` is unusable).
pub(super) fn target_reuse_disabled_from_value(value: Option<String>) -> bool {
    value
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !v.is_empty() && v != "0" && v != "false" && v != "no" && v != "off"
        })
        .unwrap_or(false)
}

/// The Rust target triple this build will compile for: an explicit `--target
/// <triple>` / `--target=<triple>` from the command wins, otherwise the host
/// default the binary was built for (`std::env::consts`-derived). This is a
/// pooled-dir cache DIMENSION — a cross-compile must not share a host build's
/// pool — so a stable, host-correct fallback matters.
pub(super) fn target_triple_for_command(command: &str) -> String {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut iter = tokens.iter();
    while let Some(token) = iter.next() {
        if let Some(value) = token.strip_prefix("--target=") {
            if !value.is_empty() {
                return value.to_string();
            }
        } else if *token == "--target"
            && let Some(value) = iter.next()
            && !value.is_empty()
        {
            return (*value).to_string();
        }
    }
    default_host_target_triple()
}

/// Best-effort host target triple, assembled from compile-time `std::env::consts`.
/// Cargo's own triples are `<arch>-<vendor>-<os>[-<env>]`; we reconstruct the
/// common Linux/macOS/Windows shapes. Only used as a *cache-key dimension* (and to
/// disambiguate pools), so an approximate-but-stable value is acceptable — it just
/// needs to be the SAME across invocations on the same host and DIFFERENT across
/// architectures/OSes.
fn default_host_target_triple() -> String {
    let arch = std::env::consts::ARCH; // e.g. "x86_64", "aarch64"
    match std::env::consts::OS {
        "linux" => format!("{arch}-unknown-linux-gnu"),
        "macos" => format!("{arch}-apple-darwin"),
        "windows" => format!("{arch}-pc-windows-msvc"),
        other => format!("{arch}-unknown-{other}"),
    }
}

/// Parse the cargo feature set that affects compiled artifacts from `command`.
/// Captures `--features <list>` / `--features=<list>` (space- or comma-separated),
/// `-F <list>`, `--all-features`, and `--no-default-features`. The result feeds
/// `PooledTargetDimensions` whose key derivation is order- and duplicate-insensitive,
/// so two commands that enable the same feature SET share a pool regardless of
/// flag order. `--all-features`/`--no-default-features` are recorded as sentinel
/// pseudo-features so they partition pools (they change the compiled output).
pub(super) fn feature_set_for_command(command: &str) -> Vec<String> {
    let mut features: Vec<String> = Vec::new();
    let push_list = |list: &str, features: &mut Vec<String>| {
        for f in list
            .split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            features.push(f.to_string());
        }
    };

    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut iter = tokens.iter().peekable();
    while let Some(token) = iter.next() {
        if let Some(value) = token.strip_prefix("--features=") {
            push_list(value, &mut features);
        } else if let Some(value) = token.strip_prefix("-F=") {
            push_list(value, &mut features);
        } else if *token == "--features" || *token == "-F" {
            if let Some(value) = iter.next() {
                push_list(value, &mut features);
            }
        } else if *token == "--all-features" {
            features.push("__rch_all_features".to_string());
        } else if *token == "--no-default-features" {
            features.push("__rch_no_default_features".to_string());
        }
    }
    features
}

/// Derive the STABLE pooled remote target-dir name for a build's cache dimensions,
/// so independent jobs sharing (project, toolchain, triple, profile, feature-set)
/// REUSE the same warm remote incremental cache instead of cold-recompiling into a
/// unique-per-job dir.
///
/// The key (`rch_common::PooledTargetKey`) is a domain-separated 32-char hex over
/// those dimensions; its native layout is `.rch-pool/<key>` but that contains a
/// `/` which `TransferPipeline::with_remote_cargo_target_dir_name` rejects (the
/// name must be a single path segment). So we flatten to one segment that keeps
/// the `.rch-target-` prefix the stale-dir reaper recognizes and adds a `-pool-`
/// marker the reaper's `REAP_GLOBS` matches: `.rch-target-<worker>-pool-<key>`.
///
/// CONCURRENCY: two concurrent jobs with identical dimensions now share one remote
/// target dir. cargo's own `target/.cargo-lock` (an flock) serializes them
/// correctly — this is expected/fine. The 12h-idle reaper won't evict an
/// actively-building dir (fresh mtime), so the immediate eviction race is
/// low-risk. (Fuller active-build pinning — marking a pool dir in-use for the
/// duration of a job — is a follow-up; the idle-based reaper + cargo flock are the
/// safety mechanism today.)
pub(super) fn remote_cargo_pooled_target_dir_name(
    worker_id: &WorkerId,
    normalized_project_root: &Path,
    toolchain: Option<&ToolchainInfo>,
    command: &str,
) -> String {
    let toolchain_id = toolchain
        .map(ToolchainInfo::rustup_toolchain)
        .unwrap_or_else(|| "unknown".to_string());
    let profile = detect_target_label(command, "").unwrap_or_else(|| "dev".to_string());
    let triple = target_triple_for_command(command);

    let dims = rch_common::pooled_target_key::PooledTargetDimensions::new(
        normalized_project_root.to_string_lossy().to_string(),
        toolchain_id,
        triple,
        profile,
    )
    .with_features(feature_set_for_command(command));

    let key = rch_common::pooled_target_key::PooledTargetKey::derive(&dims);
    let safe_worker_id = sanitize_cargo_home_token(worker_id.as_str());
    // Flatten `.rch-pool/<key>` to a single, slash-free segment while keeping the
    // reaper-recognized `.rch-target-…-pool-…` shape. The key is lowercase hex and
    // the worker id is sanitized, so the result is filesystem- and reaper-safe.
    format!(".rch-target-{safe_worker_id}-pool-{}", key.as_str())
}

/// Idle threshold (hours) after which an abandoned per-job remote target dir is
/// eligible for reaping. Defaults to 12h: empirically (ts2 disk-fill incident,
/// 2026-05) active per-job dirs are touched within ~2h while abandoned ones sit
/// idle 18h+, so 12h cleanly separates the two with margin. Overridable via
/// `RCH_STALE_TARGET_REAP_HOURS`; floored at 1h so a misconfiguration can never
/// reap a live incremental cache.
pub(super) fn stale_target_reap_idle_hours() -> u32 {
    parse_stale_target_reap_idle_hours(std::env::var("RCH_STALE_TARGET_REAP_HOURS").ok())
}

pub(super) fn parse_stale_target_reap_idle_hours(raw: Option<String>) -> u32 {
    const DEFAULT_IDLE_HOURS: u32 = 12;
    raw.and_then(|v| v.trim().parse::<u32>().ok())
        .map(|hours| hours.max(1))
        .unwrap_or(DEFAULT_IDLE_HOURS)
}

pub(super) fn rewrite_cargo_target_dir_command_for_remote(
    command: &str,
    command_tokens: Option<&[String]>,
    forwarded_cargo_target_dir: Option<&PathBuf>,
    reporter: &HookReporter,
) -> String {
    if forwarded_cargo_target_dir.is_none() {
        return command.to_string();
    }

    let parsed_tokens;
    let tokens = if let Some(tokens) = command_tokens {
        tokens
    } else {
        parsed_tokens = parse_command_tokens(command, reporter);
        let Some(tokens) = parsed_tokens.as_deref() else {
            return command.to_string();
        };
        tokens
    };

    let mut stripped = tokens.to_vec();
    let mut removed_target_dir = false;
    if let Some(without_assignments) =
        strip_cargo_target_dir_assignments_from_command_tokens(&stripped)
    {
        stripped = without_assignments;
        removed_target_dir = true;
    }
    if let Some(without_flags) = strip_cargo_target_dir_flags_from_command_tokens(&stripped) {
        stripped = without_flags;
        removed_target_dir = true;
    }
    if removed_target_dir {
        reporter.verbose(
            "[RCH] removed local Cargo target-dir setting before remote execution; worker-scoped target dir will be injected",
        );
        return join_exec_command(&stripped);
    }

    command.to_string()
}

pub(super) fn strip_cargo_target_dir_assignments_from_command_tokens(
    tokens: &[String],
) -> Option<Vec<String>> {
    fn strip_assignment_prefix(tokens: &mut Vec<String>, mut index: usize) -> bool {
        let mut changed = false;
        while let Some(token) = tokens.get(index) {
            let Some((key, _)) = token.split_once('=') else {
                break;
            };
            if key == "CARGO_TARGET_DIR" {
                tokens.remove(index);
                changed = true;
            } else {
                index += 1;
            }
        }
        changed
    }

    let mut stripped = tokens.to_vec();
    let mut index = 0usize;
    while let Some(token) = stripped.get(index) {
        match token.as_str() {
            "sudo" | "time" => {
                index += 1;
                while let Some(flag) = stripped.get(index) {
                    if flag.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                index = skip_env_option_prefix(&stripped, index + 1);
                return strip_assignment_prefix(&mut stripped, index).then_some(stripped);
            }
            _ => {
                return strip_assignment_prefix(&mut stripped, index).then_some(stripped);
            }
        }
    }

    None
}

fn skip_env_option_prefix(tokens: &[String], mut index: usize) -> usize {
    while let Some(flag) = tokens.get(index).map(String::as_str) {
        if flag == "--" {
            return index + 1;
        }

        match flag {
            "-u" | "--unset" => {
                index += 1;
                if tokens.get(index).is_some() {
                    index += 1;
                }
            }
            _ if flag.starts_with("--unset=") => {
                index += 1;
            }
            _ if flag.starts_with('-') && !flag.contains('=') => {
                index += 1;
            }
            _ => break,
        }
    }

    index
}

pub(super) fn strip_cargo_target_dir_flags_from_command_tokens(
    tokens: &[String],
) -> Option<Vec<String>> {
    let mut stripped = Vec::with_capacity(tokens.len());
    let mut changed = false;
    let mut index = 0usize;

    while let Some(token) = tokens.get(index) {
        if token == "--" {
            stripped.extend_from_slice(&tokens[index..]);
            break;
        }
        if token == "--target-dir" {
            changed = true;
            index += 1;
            if tokens.get(index).is_some() {
                index += 1;
            }
            continue;
        }

        if token
            .strip_prefix("--target-dir=")
            .is_some_and(|value| !value.is_empty())
        {
            changed = true;
            index += 1;
            continue;
        }

        stripped.push(token.clone());
        index += 1;
    }

    changed.then_some(stripped)
}

pub(super) fn extract_cargo_target_dir_from_command_tokens(tokens: &[String]) -> Option<String> {
    fn scan_assignment_prefix(tokens: &[String], start: usize) -> Option<String> {
        let mut index = start;
        while let Some(token) = tokens.get(index) {
            if let Some((key, value)) = token.split_once('=') {
                if key == "CARGO_TARGET_DIR" {
                    return Some(value.to_string());
                }
                index += 1;
                continue;
            }
            break;
        }
        None
    }

    fn scan_target_dir_flag(tokens: &[String]) -> Option<String> {
        let mut index = 0usize;
        while let Some(token) = tokens.get(index) {
            if token == "--" {
                break;
            }
            if token == "--target-dir" {
                return tokens.get(index + 1).cloned();
            }
            if let Some(value) = token.strip_prefix("--target-dir=")
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
            index += 1;
        }
        None
    }

    let mut index = 0usize;
    while let Some(token) = tokens.get(index) {
        match token.as_str() {
            "sudo" | "time" => {
                index += 1;
                while let Some(flag) = tokens.get(index) {
                    if flag.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "env" => {
                index = skip_env_option_prefix(tokens, index + 1);
                if let Some(value) = scan_assignment_prefix(tokens, index) {
                    return Some(value);
                }
                return scan_target_dir_flag(tokens);
            }
            _ => {
                if let Some(value) = scan_assignment_prefix(tokens, index) {
                    return Some(value);
                }
                return scan_target_dir_flag(tokens);
            }
        }
    }

    scan_target_dir_flag(tokens)
}
