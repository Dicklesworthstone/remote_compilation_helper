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
//! parent helpers `parse_command_tokens` / `join_exec_command`. `detect_target_label`
//! is imported directly from the sibling `super::formatting` module.
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
                | CompilationKind::CargoBench
                // Zigbuild writes into CARGO_TARGET_DIR exactly like a plain
                // build; omitting it here left the forwarded target dir (and
                // its sync-back) disengaged, so cross-built binaries stayed in
                // the worker's default .rch-target and never came home (hfdt
                // aarch64 release leg, 2026-08-06 — same class as the
                // command_uses_cargo_dependency_graph omission).
                | CompilationKind::CargoZigbuild,
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
    explicit_target_triple_for_command(command).unwrap_or_else(default_host_target_triple)
}

/// The explicit `--target <triple>` / `--target=<triple>` this command pins, if
/// any. `None` means the build is UNPINNED and therefore targets the host that
/// runs it — which, on an offloaded build, is the worker rather than the caller
/// (GitHub #65).
pub(super) fn explicit_target_triple_for_command(command: &str) -> Option<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    let mut iter = tokens.iter();
    while let Some(token) = iter.next() {
        if let Some(value) = token.strip_prefix("--target=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        } else if *token == "--target"
            && let Some(value) = iter.next()
            && !value.is_empty()
        {
            return Some((*value).to_string());
        }
    }
    None
}

/// Best-effort host target triple, assembled from compile-time `std::env::consts`.
/// Cargo's own triples are `<arch>-<vendor>-<os>[-<env>]`; we reconstruct the
/// common Linux/macOS/Windows shapes. Only used as a *cache-key dimension* (and to
/// disambiguate pools), so an approximate-but-stable value is acceptable — it just
/// needs to be the SAME across invocations on the same host and DIFFERENT across
/// architectures/OSes.
pub(super) fn default_host_target_triple() -> String {
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

/// Parse the supported literal command grammar and locate the Cargo executable.
/// Leading assignments are normalized with an explicit `env` token; the returned
/// index refers to this normalized argv, after any supported wrapper prefixes.
pub(super) fn managed_clean_overlay_cargo_tokens(
    command: &str,
) -> anyhow::Result<(Vec<String>, usize)> {
    // shell_words preserves literal argv, not shell evaluation. Refuse syntax
    // whose expansion or execution would change when those words are re-quoted.
    let mut quote = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            escaped = false;
        } else if ch == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if quote != Some('\'') && matches!(ch, '$' | '`')
            || quote.is_none()
                && matches!(
                    ch,
                    ';' | '|' | '&' | '<' | '>' | '\n' | '*' | '?' | '[' | '~' | '(' | ')'
                )
        {
            anyhow::bail!("cannot safely bind Cargo build directory across shell evaluation");
        }
    }
    let mut tokens = shell_words::split(command)?;
    let assignment = |token: &str| {
        token.split_once('=').is_some_and(|(key, _)| {
            !key.is_empty()
                && key.chars().enumerate().all(|(index, ch)| {
                    ch == '_' || ch.is_ascii_alphabetic() || index > 0 && ch.is_ascii_digit()
                })
        })
    };
    // Quoting an assignment as an entire shell word makes it an executable.
    // An explicit env prefix keeps the same assignment bytes as real argv.
    if tokens.first().is_some_and(|token| assignment(token)) {
        tokens.insert(0, "env".to_string());
    }
    let mut index = 0;
    loop {
        let token = tokens
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("missing Cargo command"))?;
        let executable = Path::new(token).file_name().and_then(|name| name.to_str());
        match executable {
            Some("cargo" | "cargo.exe") => break,
            Some("env") => {
                index += 1;
                while let Some(token) = tokens.get(index) {
                    match token.as_str() {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-i" | "--ignore-environment" => index += 1,
                        "-u" | "--unset" | "-C" | "--chdir" => {
                            anyhow::ensure!(
                                tokens.get(index + 1).is_some(),
                                "missing env option value"
                            );
                            index += 2;
                        }
                        value
                            if value.starts_with("--unset=")
                                || value.starts_with("--chdir=")
                                || assignment(value) =>
                        {
                            index += 1
                        }
                        value if value.starts_with('-') => anyhow::bail!(
                            "unsupported env option in managed Cargo command: {value}"
                        ),
                        _ => break,
                    }
                }
                while tokens.get(index).is_some_and(|token| assignment(token)) {
                    index += 1;
                }
            }
            Some("time") => {
                index += 1;
                while let Some(token) = tokens.get(index) {
                    match token.as_str() {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-p" | "--portability" | "-v" | "--verbose" | "-a" | "--append" | "-q"
                        | "--quiet" => index += 1,
                        "-f" | "--format" | "-o" | "--output" => {
                            anyhow::ensure!(
                                tokens.get(index + 1).is_some(),
                                "missing time option value"
                            );
                            index += 2;
                        }
                        value
                            if value.starts_with("--format=") || value.starts_with("--output=") =>
                        {
                            index += 1
                        }
                        value if value.starts_with('-') => anyhow::bail!(
                            "unsupported time option in managed Cargo command: {value}"
                        ),
                        _ => break,
                    }
                }
            }
            Some("rustup") => {
                anyhow::ensure!(
                    tokens.get(index + 1).is_some_and(|token| token == "run"),
                    "expected rustup run before Cargo"
                );
                index += 2;
                if tokens.get(index).is_some_and(|token| token == "--install") {
                    index += 1;
                }
                anyhow::ensure!(
                    tokens
                        .get(index)
                        .is_some_and(|token| !token.is_empty() && !token.starts_with('-')),
                    "missing rustup toolchain"
                );
                index += 1;
            }
            _ => anyhow::bail!("unsupported executable prefix in managed Cargo command: {token}"),
        }
    }
    Ok((tokens, index))
}

/// Bind Cargo's intermediate cache to the same managed directory as its
/// artifacts. A final CLI config wins over inherited files, environment and
/// earlier CLI config without intercepting either compiler wrapper.
pub(super) fn managed_clean_overlay_cargo_build_dir(
    command: &str,
    managed_target: &str,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        !managed_target.is_empty() && !managed_target.chars().any(char::is_control),
        "managed Cargo build directory must be a nonempty path without control characters"
    );
    let (mut tokens, cargo_index) = managed_clean_overlay_cargo_tokens(command)?;
    let mut index = cargo_index + 1;
    if tokens
        .get(index)
        .is_some_and(|token| token.starts_with('+'))
    {
        index += 1;
    }
    // Locate the subcommand without confusing option values for its name.
    while let Some(token) = tokens.get(index) {
        match token.as_str() {
            "--config" | "--color" | "-Z" | "-C" => {
                anyhow::ensure!(
                    tokens.get(index + 1).is_some_and(|value| value != "--"),
                    "missing Cargo global option value"
                );
                index += 2;
            }
            "-v" | "-vv" | "-q" | "--verbose" | "--quiet" | "--locked" | "--offline"
            | "--frozen" => index += 1,
            value
                if value.starts_with("--config=")
                    || value.starts_with("--color=")
                    || value.starts_with("-Z") && value.len() > 2 =>
            {
                index += 1
            }
            value if value.starts_with('-') => {
                anyhow::bail!("unsupported Cargo global option: {value}")
            }
            _ => break,
        }
    }
    let subcommand = tokens
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("missing Cargo subcommand"))?;
    if subcommand == "fmt" {
        return Ok(command.to_string());
    }
    anyhow::ensure!(
        matches!(
            subcommand.as_str(),
            "build"
                | "b"
                | "check"
                | "c"
                | "test"
                | "t"
                | "clippy"
                | "doc"
                | "d"
                | "bench"
                | "run"
                | "r"
                | "rustc"
                | "rustdoc"
                | "fix"
        ),
        "unsupported Cargo subcommand for managed build directory: {subcommand}"
    );
    let end = tokens[index + 1..]
        .iter()
        .position(|token| token == "--")
        .map_or(tokens.len(), |offset| index + 1 + offset);
    anyhow::ensure!(
        !tokens[index + 1..end]
            .iter()
            .any(|token| token == "--build-dir" || token.starts_with("--build-dir=")),
        "explicit --build-dir is unsupported for clean-overlay execution"
    );
    let value = format!(
        "build.build-dir={}",
        toml::Value::String(managed_target.to_string())
    );
    tokens.splice(end..end, ["--config".to_string(), value]);
    Ok(join_exec_command(&tokens))
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

#[cfg(test)]
mod managed_build_dir_tests {
    use super::{managed_clean_overlay_cargo_build_dir, managed_clean_overlay_cargo_tokens};

    #[test]
    fn source_pair_cargo_tokens_distinguishes_prefix_values_from_executable() {
        for (command, cargo_index) in [
            ("cargo test", 0),
            ("/opt/bin/cargo.exe +nightly test", 0),
            ("/usr/bin/time -f cargo cargo test", 3),
            ("rustup run cargo /opt/bin/cargo test", 3),
            (
                "CARGO_MARK='cargo' /usr/bin/time -f cargo env -u cargo -- X=cargo /opt/bin/cargo test",
                10,
            ),
        ] {
            let (tokens, actual_index) = managed_clean_overlay_cargo_tokens(command).unwrap();
            assert_eq!(actual_index, cargo_index, "{command}");
            let mut expected = shell_words::split(command).unwrap();
            if command.starts_with("CARGO_MARK=") {
                expected.insert(0, "env".to_string());
            }
            assert_eq!(tokens, expected, "{command}");
            assert!(matches!(
                std::path::Path::new(&tokens[actual_index])
                    .file_name()
                    .unwrap()
                    .to_str(),
                Some("cargo" | "cargo.exe")
            ));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn source_pair_build_dir_real_cargo_overrides_file_env_and_cli() {
        use std::io::Read as _;
        use std::path::{Path, PathBuf};

        let root = tempfile::tempdir().unwrap().keep();
        for directory in ["src", ".cargo", "bin", "cargo-home"] {
            std::fs::create_dir(root.join(directory)).unwrap();
        }
        std::fs::write(root.join("Cargo.toml"), "[package]\nname='managed_build_dir_fixture'\nversion='0.1.0'\nedition='2024'\n[workspace]\n").unwrap();
        std::fs::write(root.join("fixture.txt"), "sealed fixture").unwrap();
        std::fs::write(root.join("src/lib.rs"), "#[test] fn reads_fixture() { let root = std::path::Path::new(env!(\"CARGO_MANIFEST_DIR\")); assert_eq!(std::fs::read_to_string(root.join(\"fixture.txt\")).unwrap(), \"sealed fixture\"); }\n").unwrap();
        let outside: Vec<_> = ["outside-A", "outside-B", "outside-C"]
            .into_iter()
            .map(|name| root.join(name))
            .collect();
        let config_value = |path: &Path| toml::Value::String(path.to_str().unwrap().to_string());
        std::fs::write(
            root.join(".cargo/config.toml"),
            format!("[build]\nbuild-dir={}\n", config_value(&outside[0])),
        )
        .unwrap();
        // The harness's Cargo identifies the compiler used to build this test.
        // A managed toolchain shim retains its real executable beside it.
        let mut cargo = PathBuf::from(env!("CARGO"));
        if std::fs::metadata(&cargo).unwrap().len() <= 8 * 1024
            && std::fs::read_to_string(&cargo)
                .unwrap()
                .lines()
                .any(|line| line.starts_with("# rch-toolchain-wrap-version:"))
        {
            cargo.set_file_name("cargo-rch-real");
        }
        let mut magic = [0; 4];
        std::fs::File::open(&cargo)
            .unwrap()
            .read_exact(&mut magic)
            .unwrap();
        assert_eq!(
            &magic, b"\x7fELF",
            "fixture must execute a real Cargo binary"
        );
        let cargo_bin = cargo.parent().unwrap();
        let executable = root.join("bin/cargo");
        std::os::unix::fs::symlink(&cargo, &executable).unwrap();
        let path = std::env::join_paths(
            std::iter::once(cargo_bin.to_path_buf())
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        let pool = root.join("managed pool");
        for (subcommand, passthrough) in [("test", "--nocapture"), ("clippy", "-D warnings")] {
            let command = format!(
                "{} {subcommand} --offline --jobs 1 --message-format=json --config {} -- {passthrough}",
                shell_words::quote(executable.to_str().unwrap()),
                shell_words::quote(&format!("build.build-dir={}", config_value(&outside[2])))
            );
            let managed =
                managed_clean_overlay_cargo_build_dir(&command, pool.to_str().unwrap()).unwrap();
            let output = std::process::Command::new("sh")
                .args(["-c", &managed])
                .current_dir(&root)
                .env("PATH", &path)
                .env("CARGO_HOME", root.join("cargo-home"))
                .env("CARGO_TARGET_DIR", &pool)
                .env("CARGO_BUILD_BUILD_DIR", &outside[1])
                .env("RUSTC", cargo_bin.join("rustc"))
                .env("RUSTFLAGS", "")
                .env("RUSTUP_AUTO_INSTALL", "0")
                .env("RCH_CARGO_WRAPPER_BYPASS", "1")
                .env_remove("RUSTUP_TOOLCHAIN")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("CARGO_BUILD_RUSTC")
                .env_remove("CARGO_BUILD_TARGET")
                .env_remove("CARGO_BUILD_TARGET_DIR")
                .env_remove("CARGO_BUILD_RUSTFLAGS")
                .env_remove("RUSTC_WRAPPER")
                .env_remove("RUSTC_WORKSPACE_WRAPPER")
                .env_remove("CARGO_BUILD_RUSTC_WRAPPER")
                .env_remove("CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER")
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.status.success(),
                "{subcommand}: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let artifacts: Vec<_> = stdout
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .filter(|message| {
                    message["reason"] == "compiler-artifact"
                        && message["target"]["name"] == "managed_build_dir_fixture"
                })
                .collect();
            assert!(
                !artifacts.is_empty(),
                "real compiler artifact receipt required: {stdout}"
            );
            for artifact in artifacts {
                assert_eq!(
                    artifact["manifest_path"].as_str(),
                    root.join("Cargo.toml").to_str()
                );
                assert!(!artifact["filenames"].as_array().unwrap().is_empty());
                for filename in artifact["filenames"].as_array().unwrap() {
                    let filename = Path::new(filename.as_str().unwrap());
                    assert!(
                        filename.starts_with(&pool) && filename.is_file(),
                        "{}",
                        filename.display()
                    );
                }
            }
            if subcommand == "test" {
                assert!(stdout.contains("test reads_fixture ... ok"), "{stdout}");
            }
            assert!(
                outside.iter().all(|path| !path.exists()),
                "unmanaged cache directory was created"
            );
        }
        eprintln!(
            "managed build-dir real Cargo evidence retained at {}",
            root.display()
        );
    }

    #[test]
    fn source_pair_build_dir_keeps_wrappers_and_literal_arguments() {
        let command = "env -- CARGO_BUILD_BUILD_DIR='/outside cache' /usr/bin/time -f '%e seconds' rustup run nightly-2026-08-31 /opt/rust/bin/cargo +nightly test --config 'build.build-dir=\"/also outside\"' -p 'space name' -- 'literal $value; with quotes'";
        let target = "/managed/cache with 'single' and \"double\" quotes";
        let rewritten = managed_clean_overlay_cargo_build_dir(command, target).unwrap();
        let original = shell_words::split(command).unwrap();
        let actual = shell_words::split(&rewritten).unwrap();
        let separator = original.iter().rposition(|token| token == "--").unwrap();
        assert_eq!(&actual[..separator], &original[..separator]);
        assert_eq!(actual[separator], "--config");
        let config: toml::Value = toml::from_str(&actual[separator + 1]).unwrap();
        assert_eq!(config["build"]["build-dir"].as_str(), Some(target));
        assert_eq!(&actual[separator + 2..], &original[separator..]);
    }

    #[test]
    fn source_pair_build_dir_final_config_wins_before_clippy_passthrough() {
        let rewritten = managed_clean_overlay_cargo_build_dir(
            "RUSTC_WRAPPER='/wrapper with spaces' cargo --config 'build.build-dir=\"/global\"' clippy --all-targets --config=build.build-dir='\"/later\"' -- -D warnings",
            "/managed",
        ).unwrap();
        let tokens = shell_words::split(&rewritten).unwrap();
        assert_eq!(tokens[0], "env");
        assert_eq!(tokens[1], "RUSTC_WRAPPER=/wrapper with spaces");
        let separator = tokens.iter().position(|token| token == "--").unwrap();
        assert_eq!(&tokens[separator..], ["--", "-D", "warnings"]);
        assert_eq!(tokens[separator - 2], "--config");
        let config: toml::Value = toml::from_str(&tokens[separator - 1]).unwrap();
        assert_eq!(config["build"]["build-dir"].as_str(), Some("/managed"));
        assert!(
            tokens
                .iter()
                .any(|token| token == "--config=build.build-dir=\"/later\"")
        );
    }

    #[test]
    fn source_pair_build_dir_preserves_format_and_refuses_ambiguous_commands() {
        let fmt = "env RUSTUP_TOOLCHAIN=nightly cargo fmt --check";
        assert_eq!(
            managed_clean_overlay_cargo_build_dir(fmt, "/managed").unwrap(),
            fmt
        );
        for command in [
            "",
            "cargo",
            "cargo --config",
            "cargo test 'unterminated",
            "cargo test; echo surprise",
            "cargo test $(echo filter)",
            "cargo test $FILTER",
            "cargo test > output",
            "sh -c 'cargo test'",
            "env -S 'cargo test'",
            "env -u",
            "rustup run",
            "cargo custom-build",
            "cargo test --build-dir /unmanaged",
            "cargo test --build-dir=/unmanaged",
        ] {
            assert!(
                managed_clean_overlay_cargo_build_dir(command, "/managed").is_err(),
                "{command}"
            );
        }
        assert!(managed_clean_overlay_cargo_build_dir("cargo test", "").is_err());
        assert!(managed_clean_overlay_cargo_build_dir("cargo test", "/bad\npath").is_err());
        // This is a test-binary argument, not an override of Cargo's cache.
        let passthrough =
            managed_clean_overlay_cargo_build_dir("cargo test -- --build-dir=/literal", "/managed")
                .unwrap();
        assert_eq!(
            shell_words::split(&passthrough).unwrap().last().unwrap(),
            "--build-dir=/literal"
        );
    }
}
