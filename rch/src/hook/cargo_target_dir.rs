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

/// The Rust target triple this build will compile for: an explicit `--target`
/// or inline `--config build.target=...` wins, otherwise the host default the
/// binary was built for (`std::env::consts`-derived). This is a pooled-dir cache
/// DIMENSION — a cross-compile must not share a host build's pool.
pub(super) fn target_triple_for_command(command: &str) -> String {
    explicit_target_triple_for_command(command).unwrap_or_else(default_host_target_triple)
}

/// The target pinned by Cargo's own arguments, not arguments after `--`.
/// An explicit `--target` outranks inline `--config build.target=...`; repeated
/// string config overrides are applied left-to-right, as in Cargo. This does
/// not resolve config files, environment defaults, or multi-target arrays.
///
/// GitHub #68: ignoring inline build.target misclassified worker-host proc
/// macros as foreign target output, and also selected the wrong pooled cache.
pub(super) fn explicit_target_triple_for_command(command: &str) -> Option<String> {
    let (tokens, cargo_index) = cargo_command_tokens(command).ok()?;
    let mut iter = tokens[cargo_index + 1..].iter();
    let mut configured_target = None;
    while let Some(token) = iter.next() {
        if token == "--" {
            break;
        }
        if let Some(value) = token.strip_prefix("--target=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        } else if token == "--target" {
            if let Some(value) = iter.next().filter(|value| !value.is_empty()) {
                return Some(value.to_string());
            }
        } else {
            let config = if token == "--config" {
                iter.next().map(String::as_str)
            } else {
                token.strip_prefix("--config=")
            };
            if let Some(config) = config
                && let Ok(config) = toml::from_str::<toml::Value>(config)
                && let Some(target) = config.get("build").and_then(|build| build.get("target"))
            {
                configured_target = target
                    .as_str()
                    .filter(|value| !value.is_empty())
                    .map(str::to_string);
            }
        }
    }
    configured_target
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
    literal_cargo_tokens(command, false)
}

fn literal_cargo_tokens(
    command: &str,
    allow_classified_wrappers: bool,
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
    cargo_command_tokens_with_wrappers(command, allow_classified_wrappers)
}

/// Tokenize without evaluating shell syntax and skip supported executable
/// prefixes. Shared with target detection so `env --` and wrapper option values
/// are not mistaken for Cargo's argument separator or executable.
fn cargo_command_tokens(command: &str) -> anyhow::Result<(Vec<String>, usize)> {
    cargo_command_tokens_with_wrappers(command, false)
}

fn cargo_command_tokens_with_wrappers(
    command: &str,
    allow_classified_wrappers: bool,
) -> anyhow::Result<(Vec<String>, usize)> {
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
        let wrapper_start = index;
        match executable {
            Some(
                "cargo" | "cargo.exe" | "cargo-zigbuild" | "cargo-zigbuild.exe" | "cargo-xwin"
                | "cargo-xwin.exe",
            ) => break,
            Some("env") => {
                index += 1;
                while let Some(token) = tokens.get(index) {
                    match token.as_str() {
                        "--" => {
                            index += 1;
                            break;
                        }
                        "-i" | "--ignore-environment" => index += 1,
                        "--debug" if allow_classified_wrappers => index += 1,
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
                        value if value.starts_with('-') && allow_classified_wrappers => {
                            let cargo_index = classified_cargo_suffix(&tokens, wrapper_start)?;
                            return Ok((tokens, cargo_index));
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
                        value if value.starts_with('-') && allow_classified_wrappers => {
                            let cargo_index = classified_cargo_suffix(&tokens, wrapper_start)?;
                            return Ok((tokens, cargo_index));
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
            _ if allow_classified_wrappers => {
                let cargo_index = classified_cargo_suffix(&tokens, wrapper_start)?;
                return Ok((tokens, cargo_index));
            }
            _ => anyhow::bail!("unsupported executable prefix in managed Cargo command: {token}"),
        }
    }
    Ok((tokens, index))
}

/// Reuse the classifier's wrapper vocabulary only for an unchanged argv
/// suffix. Execution retains wrapper arguments and the actual executable path.
fn classified_cargo_suffix(tokens: &[String], wrapper_start: usize) -> anyhow::Result<usize> {
    let remaining = join_exec_command(&tokens[wrapper_start..]);
    let normalized = rch_common::patterns::normalize_command(&remaining);
    let suffix = shell_words::split(&normalized)?;
    let start = tokens.len().checked_sub(suffix.len());
    if let Some(start) = start.filter(|&start| start >= wrapper_start)
        && !suffix.is_empty()
        && matches!(
            Path::new(&tokens[start])
                .file_name()
                .and_then(|name| name.to_str()),
            Some(
                "cargo"
                    | "cargo.exe"
                    | "cargo-zigbuild"
                    | "cargo-zigbuild.exe"
                    | "cargo-xwin"
                    | "cargo-xwin.exe"
            )
        )
        && tokens[start + 1..] == suffix[1..]
    {
        return Ok(start);
    }
    anyhow::bail!("cannot locate an unchanged Cargo argv suffix: {remaining}");
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
    anyhow::ensure!(
        matches!(
            Path::new(&tokens[cargo_index])
                .file_name()
                .and_then(|name| name.to_str()),
            Some("cargo" | "cargo.exe")
        ),
        "managed clean-overlay build directory requires the Cargo executable"
    );
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

pub(super) fn bind_build_source_stamp(command: &str, stamp: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !stamp.is_empty() && !stamp.chars().any(char::is_control),
        "invalid build-source stamp"
    );
    let (mut tokens, cargo_index) = literal_cargo_tokens(command, true)?;
    let end = tokens
        .iter()
        .enumerate()
        .skip(cargo_index + 1)
        .find_map(|(index, token)| (token == "--").then_some(index))
        .unwrap_or(tokens.len());
    let value = format!(
        "env.RCH_BUILD_SOURCE.value={}",
        toml::Value::String(stamp.to_owned())
    );
    tokens.splice(
        end..end,
        [
            "--config".to_owned(),
            value,
            "--config".to_owned(),
            "env.RCH_BUILD_SOURCE.force=true".to_owned(),
        ],
    );
    Ok(join_exec_command(&tokens))
}

/// Refuse unselected worker Cargo configuration immediately before Unix Cargo.
/// The outer command prefixes run first, so the guard sees Cargo's effective
/// environment. This checks ordinary filesystem state, not atomic protection
/// against an adversary changing paths between inspection and execution.
pub(super) fn guard_clean_overlay_cargo_config(command: &str) -> anyhow::Result<String> {
    let (mut tokens, cargo_index) = managed_clean_overlay_cargo_tokens(command)?;
    let guard = r#"rch_config_refuse() {
    printf '%s\n' 'RCH-E413 clean-overlay unselected Cargo configuration' >&2
    exit 113
}
rch_config_directory() {
    [ -d "$1" ] && [ -r "$1" ] && [ -x "$1" ] || rch_config_refuse
    /bin/ls -a "$1" >/dev/null 2>&1 || rch_config_refuse
}
rch_config_absent() {
    for rch_config_name in config config.toml; do
        if [ -e "$1/$rch_config_name" ] || [ -L "$1/$rch_config_name" ]; then
            rch_config_refuse
        fi
    done
}
case "${CARGO_HOME-}" in
    /*) ;;
    *) rch_config_refuse ;;
esac
rch_config_directory "$CARGO_HOME"
rch_config_absent "$CARGO_HOME"
rch_config_parent=$(pwd -P) || rch_config_refuse
case "$rch_config_parent" in
    /*) ;;
    *) rch_config_refuse ;;
esac
while [ "$rch_config_parent" != / ]; do # ubs:ignore — compares a directory path with filesystem root, not a secret.
    rch_config_parent=${rch_config_parent%/*}
    [ -n "$rch_config_parent" ] || rch_config_parent=/
    rch_config_directory "$rch_config_parent"
    if [ -e "$rch_config_parent/.cargo" ] || [ -L "$rch_config_parent/.cargo" ]; then
        rch_config_directory "$rch_config_parent/.cargo"
        rch_config_absent "$rch_config_parent/.cargo"
    fi
done
exec "$@""#;
    tokens.splice(
        cargo_index..cargo_index,
        [
            "/bin/sh".to_string(),
            "-c".to_string(),
            guard.to_string(),
            "rch-clean-overlay-config".to_string(),
        ],
    );
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
    fn explicit_target_honors_inline_config_and_shell_quoting() {
        let target = "aarch64-apple-darwin";
        for command in [
            r#"cargo build --config 'build.target="aarch64-apple-darwin"'"#,
            r#"cargo build --config='build.target="aarch64-apple-darwin"'"#,
            r#"cargo --config "build.target = 'aarch64-apple-darwin'" build"#,
            r#"cargo build --target 'aarch64-apple-darwin'"#,
            r#"cargo build '--target=aarch64-apple-darwin'"#,
            r#"env -- CARGO_TARGET_DIR='/custom target' /opt/bin/cargo +nightly build --config 'build.target="aarch64-apple-darwin"'"#,
            r#"/usr/bin/time -f cargo env -u cargo -- rustup run nightly cargo build --config 'build.target="aarch64-apple-darwin"'"#,
        ] {
            assert_eq!(
                super::explicit_target_triple_for_command(command).as_deref(),
                Some(target),
                "{command}"
            );
            assert_eq!(super::target_triple_for_command(command), target);
        }
    }

    #[test]
    fn explicit_target_obeys_precedence_and_ignores_passthrough() {
        for command in [
            r#"cargo build --config 'build.target="x86_64-unknown-linux-gnu"' --target aarch64-apple-darwin"#,
            r#"cargo build --target=aarch64-apple-darwin --config 'build.target="x86_64-unknown-linux-gnu"'"#,
            r#"cargo build --config 'build.target="x86_64-unknown-linux-gnu"' --config 'build.target="aarch64-apple-darwin"' --config 'build.jobs=2'"#,
            r#"cargo rustc --config 'build.target="aarch64-apple-darwin"' -- --target x86_64-unknown-linux-gnu"#,
        ] {
            assert_eq!(
                super::explicit_target_triple_for_command(command).as_deref(),
                Some("aarch64-apple-darwin"),
                "{command}"
            );
        }
        for command in [
            "cargo build --release",
            "cargo build --target-dir /tmp/target",
            "cargo test -- --target aarch64-apple-darwin",
            r#"cargo test -- --config 'build.target="aarch64-apple-darwin"'"#,
            "cargo build --config .cargo/extra.toml",
            r#"cargo build --config 'build.target-dir="aarch64-apple-darwin"'"#,
            r#"cargo build --config 'build.target=["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]'"#,
            "cargo build --config 'unterminated",
        ] {
            assert_eq!(
                super::explicit_target_triple_for_command(command),
                None,
                "{command}"
            );
        }
    }

    #[test]
    fn configured_cross_target_artifacts_exclude_host_tools_but_keep_target_guard() {
        use super::super::artifact_triple::foreign_target_artifacts;

        let command = r#"cargo build --release --config 'build.target="aarch64-apple-darwin"' --config 'target.aarch64-apple-darwin.linker="/usr/local/bin/zigcc-aarch64-darwin"'"#;
        let pinned = super::explicit_target_triple_for_command(command).unwrap();
        for custom in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let prefix = if custom { "" } else { "target/" };
            let host = format!("{prefix}release/deps/libclap_derive-fixture.so");
            let target = format!("{prefix}{pinned}/release/app");
            for path in [&host, &target] {
                std::fs::create_dir_all(dir.path().join(path).parent().unwrap()).unwrap();
            }
            std::fs::write(dir.path().join(&host), b"\x7fELF\0\0\0\0").unwrap();
            std::fs::write(dir.path().join(&target), b"\xcf\xfa\xed\xfe\0\0\0\0").unwrap();
            let manifest = vec![host.clone(), target.clone()];
            assert!(
                foreign_target_artifacts(dir.path(), &manifest, custom, &pinned, Some(&pinned))
                    .is_empty()
            );
            // The exclusion is only for host tools. A foreign binary under the
            // requested triple still fails, and native builds keep their guard.
            std::fs::write(dir.path().join(&target), b"\x7fELF\0\0\0\0").unwrap();
            let foreign =
                foreign_target_artifacts(dir.path(), &manifest, custom, &pinned, Some(&pinned));
            assert_eq!(foreign.len(), 1);
            assert_eq!(foreign[0].path, target);
            let native = foreign_target_artifacts(dir.path(), &manifest, custom, &pinned, None);
            assert_eq!(native.len(), 1);
            assert_eq!(native[0].path, host);
        }
    }

    #[cfg(unix)]
    struct ConfigGuardFixture {
        root: std::path::PathBuf,
        project: std::path::PathBuf,
        home: std::path::PathBuf,
        cargo: std::path::PathBuf,
        sentinel: std::path::PathBuf,
    }

    #[cfg(unix)]
    impl ConfigGuardFixture {
        fn new() -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let root = tempfile::Builder::new()
                .prefix("rch-cfg-")
                .tempdir_in("/tmp")
                .unwrap()
                .keep();
            let project = root.join("project");
            let home = root.join("cargo home");
            let cargo = root.join("cargo");
            let sentinel = root.join("child-started");
            std::fs::create_dir(&project).unwrap();
            std::fs::create_dir(&home).unwrap();
            std::fs::write(
                &cargo,
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RCH_CONFIG_GUARD_SENTINEL\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self {
                root,
                project,
                home,
                cargo,
                sentinel,
            }
        }

        fn run(&self, prefix: &str) -> std::process::Output {
            let command = format!(
                "{prefix} {} test -- 'literal $value; with spaces'",
                shell_words::quote(self.cargo.to_str().unwrap())
            );
            let guarded = super::guard_clean_overlay_cargo_config(&command).unwrap();
            std::process::Command::new("/bin/sh") // ubs:ignore — executes the quoted guard under test with owned fixture argv.
                .args(["-c", &guarded])
                .current_dir(&self.project)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("CARGO_HOME", &self.home)
                .env("RCH_CONFIG_GUARD_SENTINEL", &self.sentinel)
                .output()
                .unwrap()
        }

        fn assert_refused(&self, output: &std::process::Output) {
            assert_eq!(output.status.code(), Some(113), "{output:?}");
            assert_eq!(
                output.stderr,
                b"RCH-E413 clean-overlay unselected Cargo configuration\n"
            );
            assert!(output.stdout.is_empty());
            assert!(!self.sentinel.exists(), "Cargo child must not start");
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_pair_config_guard_allows_clean_home_and_selected_project_config() {
        let fixture = ConfigGuardFixture::new();
        std::fs::create_dir(fixture.project.join(".cargo")).unwrap();
        std::fs::write(
            fixture.project.join(".cargo/config.toml"),
            "[build]\njobs=1\n",
        )
        .unwrap();
        let output = fixture.run("");
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty());
        assert_eq!(
            std::fs::read_to_string(&fixture.sentinel).unwrap(),
            "test\n--\nliteral $value; with spaces\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn source_pair_config_guard_refuses_home_config_and_broken_symlink() {
        for name in ["config", "config.toml"] {
            for symlink in [false, true] {
                let fixture = ConfigGuardFixture::new();
                let path = fixture.home.join(name);
                if symlink {
                    std::os::unix::fs::symlink(fixture.root.join("absent"), &path).unwrap();
                } else {
                    std::fs::write(&path, "secret-looking-config-value").unwrap();
                }
                fixture.assert_refused(&fixture.run(""));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_pair_config_guard_checks_inline_home_after_env_prefix() {
        let fixture = ConfigGuardFixture::new();
        let inline_home = fixture.root.join("inline 'cargo' home");
        std::fs::create_dir(&inline_home).unwrap();
        std::fs::write(inline_home.join("config.toml"), "must-not-be-printed").unwrap();
        let prefix = format!(
            "env -- CARGO_HOME={}",
            shell_words::quote(inline_home.to_str().unwrap())
        );
        fixture.assert_refused(&fixture.run(&prefix));
    }

    #[cfg(unix)]
    #[test]
    fn source_pair_config_guard_refuses_ancestor_config() {
        for name in ["config", "config.toml"] {
            let fixture = ConfigGuardFixture::new();
            std::fs::create_dir(fixture.root.join(".cargo")).unwrap();
            std::fs::write(fixture.root.join(".cargo").join(name), "unselected").unwrap();
            fixture.assert_refused(&fixture.run(""));
        }
    }

    #[cfg(unix)]
    #[test]
    fn source_pair_config_guard_refuses_unknown_home_and_non_directory() {
        for prefix in ["CARGO_HOME=relative", "CARGO_HOME=", "env -u CARGO_HOME"] {
            let fixture = ConfigGuardFixture::new();
            fixture.assert_refused(&fixture.run(prefix));
        }
        for exists in [false, true] {
            let fixture = ConfigGuardFixture::new();
            let unusable = fixture.root.join("unusable");
            if exists {
                std::fs::write(&unusable, "not a directory").unwrap();
            }
            let prefix = format!(
                "CARGO_HOME={}",
                shell_words::quote(unusable.to_str().unwrap())
            );
            fixture.assert_refused(&fixture.run(&prefix));
        }
    }

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
            let output = std::process::Command::new("sh") // ubs:ignore — executes the managed argv rewriter against an owned fixture.
                .args(["-c", &managed])
                .current_dir(&root)
                .env("PATH", &path)
                .env("CARGO_HOME", root.join("cargo-home"))
                .env("CARGO_BUILD_BUILD_DIR", &outside[1])
                .env("CARGO_TARGET_DIR", &pool)
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
    fn build_source_stamp_bind_places_config_before_cargo_separator() {
        let stamp = "a".repeat(40);
        let vergen_command = format!("env -- VERGEN_GIT_SHA={} cargo build", "b".repeat(40));
        let alias_command = format!(
            "RCH_GIT_COMMIT={} cargo test -- --config fixture",
            "c".repeat(40)
        );
        for command in [
            "cargo build",
            "cargo +nightly test -- --nocapture",
            "env -i cargo check",
            "env --debug cargo build",
            "env -uCARGO_HOME cargo build",
            "time -f%U cargo build",
            "time -l cargo build",
            "cargo-zigbuild zigbuild --target x86_64-unknown-linux-gnu",
            "env -i /opt/bin/cargo-zigbuild build --release",
            "rustup run nightly cargo-zigbuild zigbuild --locked",
            "cargo-xwin xwin build --release",
            "nice -n 10 cargo build",
            "nice --adjustment=+5 cargo build",
            "timeout -s KILL 90 cargo test -- --nocapture",
            "ionice -c 2 -n 4 cargo build",
            "sudo nice -n 5 cargo build",
            "/usr/bin/time -f cargo nice -n 5 cargo build",
            vergen_command.as_str(),
            alias_command.as_str(),
            "/usr/bin/time -f cargo rustup run nightly cargo build",
        ] {
            let bound = super::bind_build_source_stamp(command, &stamp)
                .unwrap_or_else(|error| panic!("{command}: {error}"));
            let original = shell_words::split(command).unwrap();
            let mut expected = original.clone();
            if original.first().is_some_and(|token| {
                token.split_once('=').is_some_and(|(key, _)| {
                    !key.is_empty()
                        && key
                            .chars()
                            .all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
                })
            }) {
                expected.insert(0, "env".to_string());
            }
            let actual = shell_words::split(&bound).unwrap();
            let configs: Vec<_> = actual
                .iter()
                .enumerate()
                .filter(|(index, token)| {
                    *token == "--config" && actual[index + 1].starts_with("env.RCH_BUILD_SOURCE.")
                })
                .collect();
            assert_eq!(configs.len(), 2, "{command}: {bound}");
            let (config_index, _) = configs[0];
            let value_config: toml::Value = toml::from_str(&actual[config_index + 1]).unwrap();
            assert_eq!(
                value_config["env"]["RCH_BUILD_SOURCE"]["value"].as_str(),
                Some(stamp.as_str()),
                "{command}"
            );
            assert_eq!(actual[config_index + 2], "--config", "{command}: {bound}");
            let force_config: toml::Value = toml::from_str(&actual[config_index + 3]).unwrap();
            assert_eq!(
                force_config["env"]["RCH_BUILD_SOURCE"]["force"].as_bool(),
                Some(true),
                "{command}"
            );
            assert_eq!(
                &actual[..config_index],
                &expected[..config_index],
                "{command}"
            );
            assert_eq!(
                &actual[config_index + 4..],
                &expected[config_index..],
                "{command}"
            );
            if let Some(token) = expected.get(config_index) {
                assert_eq!(token, "--", "{command}: {bound}");
            } else {
                assert_eq!(config_index, expected.len(), "{command}: {bound}");
            }
        }
    }

    #[test]
    fn build_source_stamp_bind_rejects_shell_evaluation_and_bad_stamps() {
        let stamp = "a".repeat(40);
        assert!(super::bind_build_source_stamp("cargo build $FLAGS", &stamp).is_err());
        assert!(super::bind_build_source_stamp("cargo build; echo x", &stamp).is_err());
        assert!(super::bind_build_source_stamp("env --debug cargo build; echo x", &stamp).is_err());
        assert!(super::bind_build_source_stamp("env -u cargo build", &stamp).is_err());
        assert!(super::bind_build_source_stamp("cargo test `id`", &stamp).is_err());
        assert!(super::bind_build_source_stamp("sh -c 'cargo test'", &stamp).is_err());
        assert!(super::bind_build_source_stamp("cargo build", "").is_err());
        assert!(super::bind_build_source_stamp("cargo build", "bad\nstamp").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_source_stamp_real_cargo_binds_stamp_through_build_script() {
        use std::io::Read as _;
        use std::path::PathBuf;

        let root = tempfile::tempdir().unwrap().keep();
        for directory in ["src", "bin", "cargo-home", "target", ".cargo"] {
            std::fs::create_dir(root.join(directory)).unwrap();
        }
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname='build_source_stamp_fixture'\nversion='0.1.0'\nedition='2021'\n[workspace]\n",
        )
        .unwrap();
        std::fs::write(
            root.join("build.rs"),
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../rch-common/build.rs"
            )),
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"{}\", option_env!(\"RCH_GIT_COMMIT\").unwrap_or(\"\")); }\n",
        )
        .unwrap();
        let fixture_git = |args: &[&str]| {
            let output = std::process::Command::new("git")
                .current_dir(&root)
                .args(args)
                .output()
                .expect("git fixture command runs");
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        fixture_git(&["init", "-q", "-b", "main"]);
        fixture_git(&["add", "Cargo.toml", "build.rs", "src/main.rs"]);
        fixture_git(&[
            "-c",
            "user.name=RCH-Test",
            "-c",
            "user.email=rch-test@example.invalid",
            "commit",
            "-q",
            "--no-gpg-sign",
            "-m",
            "fixture",
        ]);
        let fixture_head = fixture_git(&["rev-parse", "HEAD"]);
        assert_ne!(fixture_head, "a".repeat(40));

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
        let rustc = cargo_bin.join("rustc");

        let source_a = "a".repeat(40);
        let dirty_a = format!("{source_a}-dirty");
        let overlay = format!("{source_a}-overlay-{}", "b".repeat(64));
        let alias_c = "c".repeat(40);
        let alias_d = "d".repeat(40);
        let alias = |key: &str, value: &str| {
            [(key.to_owned(), value.to_owned())]
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>()
        };
        let cases: Vec<(&str, &str, std::collections::HashMap<String, String>, &str)> = vec![
            ("plain", &source_a, Default::default(), &source_a),
            ("dirty", &dirty_a, Default::default(), &dirty_a),
            ("overlay", &overlay, Default::default(), &overlay),
            ("unknown-stamp", "unknown", Default::default(), ""),
            ("malformed-stamp", "not a stamp!", Default::default(), ""),
            ("cargo-cli-config", &source_a, Default::default(), &alias_d),
            (
                "cargo-project-config",
                &source_a,
                Default::default(),
                &alias_d,
            ),
            (
                "cargo-cli-config-caller-wins",
                &source_a,
                alias("VERGEN_GIT_SHA", &alias_c),
                &alias_c,
            ),
            (
                "cargo-cli-config-empty-caller",
                &source_a,
                alias("VERGEN_GIT_SHA", ""),
                &source_a,
            ),
            (
                "cargo-cli-config-invalid-caller",
                &source_a,
                alias("VERGEN_GIT_SHA", "not-a-revision"),
                &source_a,
            ),
            (
                "explicit-rch-git-commit",
                &source_a,
                alias("RCH_GIT_COMMIT", &alias_c),
                &alias_c,
            ),
            (
                "explicit-vergen",
                &source_a,
                alias("VERGEN_GIT_SHA", &alias_d),
                &alias_d,
            ),
            (
                "caller-alias-precedence",
                &source_a,
                [
                    ("RCH_GIT_COMMIT".to_owned(), alias_c.clone()),
                    ("VERGEN_GIT_SHA".to_owned(), alias_d.clone()),
                ]
                .into_iter()
                .collect(),
                &alias_c,
            ),
        ];
        for (name, stamp, aliases, expected_stdout) in &cases {
            std::fs::write(
                root.join(".cargo/config.toml"),
                if *name == "cargo-project-config" {
                    format!("[env]\nVERGEN_GIT_SHA = '{alias_d}'\n")
                } else {
                    String::new()
                },
            )
            .unwrap();
            let extra_config = if name.starts_with("cargo-cli-config") {
                format!(
                    " --config {}",
                    shell_words::quote(&format!("env.VERGEN_GIT_SHA='{alias_d}'"))
                )
            } else {
                String::new()
            };
            let command = format!(
                "{} run --quiet --offline --jobs 1{extra_config}",
                shell_words::quote(executable.to_str().unwrap())
            );
            let bound = super::bind_build_source_stamp(&command, stamp).unwrap();
            let env = super::super::source_fidelity::build_source_commit_env(|key| {
                aliases.get(key).cloned()
            });
            let bound = super::super::source_fidelity::bind_build_source_aliases(&bound, &env);
            let mut process = std::process::Command::new("sh");
            process
                .args(["-c", &bound])
                .current_dir(&root)
                .env("PATH", &path)
                .env("HOME", &root)
                .env("CARGO_HOME", root.join("cargo-home"))
                .env("CARGO_TARGET_DIR", root.join("target"))
                .env("RUSTC", &rustc)
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
                .env_remove("RCH_BUILD_SOURCE");
            for key in rch_common::BUILD_COMMIT_ENV_VARS {
                process.env(key, "e".repeat(40));
            }
            let output = process.output().unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                output.status.success(),
                "{name}: {stdout}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                stdout.trim_end(),
                *expected_stdout,
                "{name}: stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let env_i_command = format!(
            "env -i PATH={} HOME={} RUSTC={} CARGO_HOME={} CARGO_TARGET_DIR={} RUSTUP_AUTO_INSTALL=0 RCH_CARGO_WRAPPER_BYPASS=1 {} run --quiet --offline --jobs 1",
            shell_words::quote(path.to_str().unwrap()),
            shell_words::quote(root.to_str().unwrap()),
            shell_words::quote(rustc.to_str().unwrap()),
            shell_words::quote(root.join("cargo-home").to_str().unwrap()),
            shell_words::quote(root.join("target").to_str().unwrap()),
            shell_words::quote(executable.to_str().unwrap()),
        );
        let bound = super::bind_build_source_stamp(&env_i_command, &source_a).unwrap();
        let bound = super::super::source_fidelity::bind_build_source_aliases(
            &bound,
            &alias("RCH_GIT_COMMIT", &alias_c),
        );
        let output = std::process::Command::new("sh")
            .args(["-c", &bound])
            .current_dir(&root)
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            output.status.success(),
            "env -i: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            stdout.trim_end(),
            source_a,
            "env -i: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::write(
            root.join(".cargo/config.toml"),
            format!("[env]\nVERGEN_GIT_SHA = '{alias_d}'\n"),
        )
        .unwrap();
        let output = std::process::Command::new("sh")
            .args(["-c", &bound])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "env -i with config: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim_end(),
            alias_d,
            "Cargo config must apply after caller env -i clears restored aliases"
        );
        eprintln!(
            "build-source real Cargo evidence retained at {}",
            root.display()
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
            "cargo-zigbuild build --release",
            "nice -n 5 cargo build",
            "env --debug cargo build",
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
