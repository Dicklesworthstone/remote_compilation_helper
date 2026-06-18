use super::*;
// Submodule helpers exercised directly by the hook test suite (the submodules
// keep them `pub(super)`; they are test-only so they are imported here rather
// than re-exported into the non-test hook namespace).
use super::artifact_patterns::{
    get_artifact_patterns, get_custom_target_artifact_patterns,
    kind_produces_transferable_artifacts,
};
use super::cargo_target_dir::{
    extract_cargo_target_dir_from_command_tokens, feature_set_for_command,
    parse_stale_target_reap_idle_hours, remote_cargo_pooled_target_dir_name,
    remote_cargo_target_dir_name, resolve_forwarded_cargo_target_dir_with_lookup,
    strip_cargo_target_dir_assignments_from_command_tokens,
    strip_cargo_target_dir_flags_from_command_tokens, target_reuse_disabled_from_value,
    target_triple_for_command,
};
use super::daemon_ipc::{
    DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS, DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS,
    daemon_response_timeout_for, queue_when_busy_enabled_from, urlencoding_encode,
};
use super::dependency_closure::{
    DEPENDENCY_PREFLIGHT_CODE_MISSING, DEPENDENCY_PREFLIGHT_CODE_STALE,
    DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE, DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING,
    DEPENDENCY_PREFLIGHT_REMEDIATION_STALE, DependencyPreflightCheck, SyncClosureMode,
    SyncClosurePlanEntry, SyncRootOutcome, build_dependency_preflight_report,
    build_remote_dependency_preflight_command, build_remote_dependency_preflight_commands,
    build_sync_closure_manifest, build_sync_closure_plan, canonicalize_sync_root_for_plan,
    cargo_package_source_entrypoints, cargo_workspace_member_source_entrypoints,
    dependency_preflight_checks_for_entry, is_within_sync_topology,
    parse_dependency_preflight_probe_output, synced_dependency_preflight_checks,
    verify_remote_dependency_manifests,
};
use super::repo_updater::{
    auto_tune_repo_updater_contract, build_repo_sync_idempotency_key_for_command,
    collect_repo_updater_roots_and_specs, hydrate_repo_updater_auth_context_defaults,
    infer_repo_updater_auth_context_with_env_lookup, repo_updater_command_name,
};
use super::timing_history::{
    MAX_TIMING_SAMPLES, ProjectTimingData, TimingEstimate, TimingHistory, TimingRecord,
    estimate_timing_for_build, record_build_timing, timing_cache,
};
use super::transfer_orchestration::wrap_command_with_telemetry;
use proptest::prelude::*;
use rch_common::mock::{
    self, MockConfig, MockRsyncConfig, clear_mock_overrides, set_mock_enabled_override,
    set_mock_rsync_config_override, set_mock_ssh_config_override,
};
use rch_common::test_guard;
use rch_common::{SelectionReason, TierDecision, ToolInput, classify_command_detailed};
use serial_test::serial;
use std::sync::OnceLock;
use tokio::io::BufReader as TokioBufReader;
use tokio::net::UnixListener;
use tokio::sync::Mutex;

fn delegated_command(output: &HookOutput) -> &str {
    if let HookOutput::AllowWithModifiedCommand(modified) = output {
        &modified.hook_specific_output.updated_input.command
    } else {
        assert!(
            matches!(output, HookOutput::AllowWithModifiedCommand(_)),
            "expected AllowWithModifiedCommand"
        );
        ""
    }
}

// ------------------------------------------------------------------
// join_exec_command tests — guard against the `.join(" ")` round-trip
// corruption that was present when `rch exec --` rebuilt a command
// string for `sh -c` (bug audit 2026-04-23).
// ------------------------------------------------------------------

#[test]
fn join_exec_command_plain_args_unchanged() {
    let _guard = test_guard!();
    let parts = vec![
        "cargo".to_string(),
        "build".to_string(),
        "--release".to_string(),
    ];
    let joined = join_exec_command(&parts);
    // shell_words::split of the result should reproduce the original argv.
    let round_trip = shell_words::split(&joined).expect("valid shell words");
    assert_eq!(round_trip, parts);
}

#[test]
fn join_exec_command_preserves_space_bearing_arg() {
    let _guard = test_guard!();
    // The outer shell merges `--features='foo bar'` into one argv
    // entry with a literal space. We must re-quote so `sh -c` does
    // not re-split it into two tokens.
    let parts = vec![
        "cargo".to_string(),
        "build".to_string(),
        "--features=foo bar".to_string(),
    ];
    let joined = join_exec_command(&parts);
    let round_trip = shell_words::split(&joined).expect("valid shell words");
    assert_eq!(
        round_trip, parts,
        "space must survive round-trip through sh"
    );
}

#[test]
fn join_exec_command_preserves_quote_metachars() {
    let _guard = test_guard!();
    let parts = vec![
        "cargo".to_string(),
        "run".to_string(),
        "--".to_string(),
        "he said \"hi\"".to_string(),
        "$PATH".to_string(),
        "a;b".to_string(),
    ];
    let joined = join_exec_command(&parts);
    let round_trip = shell_words::split(&joined).expect("valid shell words");
    assert_eq!(round_trip, parts);
}

#[test]
fn join_exec_command_splits_single_shell_command_arg() {
    let _guard = test_guard!();
    let parts =
        vec!["env RUSTFLAGS=\"-C linker=cc\" cargo build --bin generate_react_goldens".to_string()];
    let joined = join_exec_command(&parts);
    let round_trip = shell_words::split(&joined).expect("valid shell words");
    assert_eq!(
        round_trip,
        vec![
            "env".to_string(),
            "RUSTFLAGS=-C linker=cc".to_string(),
            "cargo".to_string(),
            "build".to_string(),
            "--bin".to_string(),
            "generate_react_goldens".to_string(),
        ]
    );
    assert!(
        !joined.starts_with("'env "),
        "env wrapper must remain the executable, not part of one quoted command: {joined}"
    );
}

#[test]
fn join_exec_command_preserves_already_split_env_prefix() {
    let _guard = test_guard!();
    let parts = vec![
        "env".to_string(),
        "RUSTFLAGS=-C linker=cc".to_string(),
        "cargo".to_string(),
        "build".to_string(),
    ];
    let joined = join_exec_command(&parts);
    let round_trip = shell_words::split(&joined).expect("valid shell words");
    assert_eq!(round_trip, parts);
}

#[test]
fn join_exec_command_empty_input() {
    let _guard = test_guard!();
    let parts: Vec<String> = Vec::new();
    assert_eq!(join_exec_command(&parts), "");
}

#[test]
fn local_fallback_command_bypasses_cargo_wrapper() {
    let _guard = test_guard!();
    let command = local_fallback_command("cargo test -p rch");

    let has_bypass = command.get_envs().any(|(key, value)| {
        key == std::ffi::OsStr::new(RCH_CARGO_WRAPPER_BYPASS_ENV)
            && value == Some(std::ffi::OsStr::new("1"))
    });
    assert!(
        has_bypass,
        "local fallback must bypass the PATH cargo wrapper to avoid recursive rch exec"
    );

    let args = command.get_args().collect::<Vec<_>>();
    assert_eq!(
        args,
        vec![
            std::ffi::OsStr::new("-c"),
            std::ffi::OsStr::new("cargo test -p rch")
        ]
    );
}

#[test]
fn remote_required_fallback_refuses_before_building_local_shell_command() {
    let _guard = test_guard!();
    let command = "bash -lc 'cargo test --lib focused_case -- --nocapture'";

    assert!(
        matches!(
            local_fallback_command_for_policy(command, true),
            Err(LocalFallbackRefusal::RemoteRequired)
        ),
        "remote-required policy must refuse before constructing a local shell fallback"
    );
    assert!(
        local_fallback_command_for_policy(command, false).is_ok(),
        "ordinary local fallback behavior remains available when remote is not required"
    );
}

#[test]
fn remote_required_non_compilation_shell_wrapped_cargo_has_stable_refusal_code() {
    let _guard = test_guard!();
    let parts = vec![
        "bash".to_string(),
        "-lc".to_string(),
        "cargo test --lib focused_case -- --nocapture".to_string(),
    ];
    let command = join_exec_command(&parts);
    let classification = classify_command(&command);

    assert!(
        !classification.is_compilation,
        "global classification should keep arbitrary shell wrappers out of hook-mode offload"
    );
    assert!(
        matches!(
            local_fallback_command_for_policy(&command, true),
            Err(LocalFallbackRefusal::RemoteRequired)
        ),
        "RCH_REQUIRE_REMOTE must prevent the shell from running locally even when classification rejects it"
    );
    assert!(remote_required_refusal_summary("non-compilation command").contains("RCH-E301"));
    assert!(
        !remote_required_refusal_summary("dependency preflight failed").contains("RCH-E301"),
        "dependency-topology refusals should remain distinguishable from command-classification refusals"
    );
}

#[test]
fn env_flag_enabled_accepts_common_truthy_values() {
    let _guard = test_guard!();

    for value in ["1", "true", "TRUE", "yes", "on"] {
        assert!(env_flag_enabled(value), "{value} should be truthy");
    }

    for value in ["", "0", "false", "no", "off", "remote"] {
        assert!(!env_flag_enabled(value), "{value} should not be truthy");
    }
}

#[test]
fn hook_panic_fail_open_can_be_enabled_without_env_var() {
    let _guard = test_guard!();

    let previous = HOOK_MODE_PANIC_FAIL_OPEN.swap(false, Ordering::AcqRel);
    enable_hook_mode_panic_fail_open();
    assert!(
        hook_mode_panic_fail_open_enabled(),
        "installing the hook panic handler must mark no-subcommand hook mode as fail-open even when RCH_HOOK_MODE is unset"
    );
    HOOK_MODE_PANIC_FAIL_OPEN.store(previous, Ordering::Release);
}

fn test_lock() -> &'static Mutex<()> {
    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_MUTEX.get_or_init(|| Mutex::new(()))
}

struct TestOverridesGuard;

impl TestOverridesGuard {
    fn set(socket_path: &str, ssh_config: MockConfig, rsync_config: MockRsyncConfig) -> Self {
        let mut config = rch_common::RchConfig::default();
        config.general.socket_path = socket_path.to_string();
        crate::config::set_test_config_override(Some(config));

        set_mock_enabled_override(Some(true));
        set_mock_ssh_config_override(Some(ssh_config));
        set_mock_rsync_config_override(Some(rsync_config));

        Self
    }
}

impl Drop for TestOverridesGuard {
    fn drop(&mut self) {
        crate::config::set_test_config_override(None);
        clear_mock_overrides();
    }
}

struct ConfigOverrideGuard;

impl ConfigOverrideGuard {
    fn set(config: rch_common::RchConfig) -> Self {
        crate::config::set_test_config_override(Some(config));
        Self
    }
}

impl Drop for ConfigOverrideGuard {
    fn drop(&mut self) {
        crate::config::set_test_config_override(None);
    }
}

/// RAII wrapper around `tempfile::TempDir` that always reports the
/// canonical form of the scratch path via `.path()`, so subdirectories
/// derived from it pass `starts_with` against a canonicalized
/// topology root even when the OS routes `/tmp` through a symlink
/// (macOS resolves `/tmp` to `/private/tmp`).
///
/// Deliberately mimics the `tempfile::TempDir` shape (`.path()` only)
/// so call sites can continue to write
/// `temp_dir.path().join("subdir")` without change.
struct CanonicalTempDir {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl CanonicalTempDir {
    fn path(&self) -> &Path {
        &self.path
    }
}

/// Create a platform-portable tempdir and a matching `PathTopologyPolicy`
/// whose canonical root points at the tempdir's canonical path.
///
/// Tests previously used `tempfile::tempdir_in("/data/projects")` +
/// `PathTopologyPolicy::default()` so the default `/data/projects`
/// topology would accept the tempdir paths. That pins tests to the
/// maintainer's dev machine and fails on every CI runner that doesn't
/// have `/data/projects`. This helper keeps the intent (tempdir paths
/// are "within topology") without the path pin — we simply build a
/// policy that recognises the tempdir itself as the topology root.
///
/// The tempdir path is canonicalized so macOS `/tmp -> /private/tmp`
/// and similar symlinks don't cause `starts_with` mismatches when
/// paths are compared against the policy.
///
/// The `alias_root` is set to a sibling path that is deliberately *not*
/// a prefix of the tempdir. This keeps
/// `normalize_project_path_with_policy` from trying to verify the alias
/// as a symlink (which fails when the alias is a plain directory or
/// missing) while still giving `is_within_sync_topology` a well-formed
/// second entry.
fn topology_tempdir() -> (CanonicalTempDir, PathTopologyPolicy) {
    let raw = tempfile::tempdir().expect("create tempdir");
    let canonical = std::fs::canonicalize(raw.path()).expect("canonicalize tempdir");
    let alias_root = canonical
        .parent()
        .map(|parent| {
            let leaf = canonical
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("tmp");
            parent.join(format!("{leaf}__rch_alias_sentinel"))
        })
        .unwrap_or_else(|| canonical.clone());
    let policy = PathTopologyPolicy::new(canonical.clone(), alias_root);
    (
        CanonicalTempDir {
            _dir: raw,
            path: canonical,
        },
        policy,
    )
}

async fn spawn_mock_daemon(socket_path: &str, response: SelectionResponse) {
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).expect("Failed to bind mock socket");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("Accept failed");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        let mut request_line = String::new();
        buf_reader
            .read_line(&mut request_line)
            .await
            .expect("Failed to read request");

        let body = serde_json::to_string(&response).expect("Serialize response");
        let http = format!("HTTP/1.1 200 OK\r\n\r\n{}", body);
        writer
            .write_all(http.as_bytes())
            .await
            .expect("Failed to write response");
        writer.flush().await.expect("Failed to flush response");
    });
}

#[tokio::test]
async fn test_non_bash_allowed() {
    let input = HookInput {
        tool_name: "Read".to_string(),
        tool_input: ToolInput {
            command: "anything".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_non_compilation_allowed() {
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "ls -la".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_process_hook_allows_beads_comment_with_embedded_build_text() {
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command:
                r#"br comments add ft-4tp7g.1 "remote proof blocked: cargo test -p rchd --lib""#
                    .to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    assert!(
        matches!(output, HookOutput::Allow(_)),
        "embedded build text in a Beads comment must not delegate to rch exec: {output:?}"
    );
}

#[tokio::test]
async fn test_process_hook_allows_env_prefixed_beads_comment_with_embedded_build_text() {
    let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: r#"AGENT_NAME=Codex br comments add ft-4tp7g.4 "proof lane: cargo clippy --workspace""#
                    .to_string(),
                description: None,
            },
            session_id: None,
        };

    let output = process_hook(input).await;
    assert!(
        matches!(output, HookOutput::Allow(_)),
        "env-prefixed Beads comments with build text must not delegate to rch exec: {output:?}"
    );
}

#[tokio::test]
async fn test_process_hook_bypasses_classification_cache_without_env_flag() {
    let unique_cmd = "echo rch-hook-cache-bypass-without-env-marker";
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: unique_cmd.to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    assert!(output.is_allow());

    assert!(
        crate::cache::global_cache().get(unique_cmd).is_none(),
        "process_hook must bypass the cache even when RCH_HOOK_MODE is unset"
    );
}

#[tokio::test]
async fn test_compilation_detected() {
    let _lock = test_lock().lock().await;
    // Disable mock mode to test real fail-open behavior (no daemon = allow)
    mock::set_mock_enabled_override(Some(false));

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build --release".to_string(),
            description: None,
        },
        session_id: None,
    };

    // Without daemon, should fail-open and allow local execution
    // This tests that classification works and fail-open behavior is preserved
    let output = process_hook(input).await;
    assert!(
        output.is_allow(),
        "Expected allow when daemon unavailable (fail-open)"
    );

    // Reset mock override
    mock::set_mock_enabled_override(None);
}

// ========================================================================
// TimingEstimate and Timing Gating Tests
// ========================================================================

#[test]
fn test_timing_estimate_struct() {
    let _guard = test_guard!();
    let estimate = TimingEstimate {
        predicted_local_ms: 5000,
        predicted_speedup: Some(2.5),
    };
    assert_eq!(estimate.predicted_local_ms, 5000);
    assert_eq!(estimate.predicted_speedup, Some(2.5));
}

#[test]
fn test_timing_estimate_no_speedup() {
    let _guard = test_guard!();
    let estimate = TimingEstimate {
        predicted_local_ms: 3000,
        predicted_speedup: None,
    };
    assert_eq!(estimate.predicted_local_ms, 3000);
    assert!(estimate.predicted_speedup.is_none());
}

#[test]
fn test_estimate_timing_returns_none_without_history() {
    let _guard = test_guard!();
    // Currently returns None (fail-open) since no timing history exists
    let config = rch_common::RchConfig::default();
    let estimate =
        estimate_timing_for_build("test-project", Some(CompilationKind::CargoBuild), &config);
    assert!(estimate.is_none());
}

#[test]
fn test_timing_gating_thresholds_default() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig::default();
    // Default min_local_time_ms: 2000ms
    assert_eq!(config.min_local_time_ms, 2000);
    // Default speedup threshold: 1.2x
    assert!((config.remote_speedup_threshold - 1.2).abs() < 0.001);
}

#[test]
fn test_urlencoding_encode_basic() {
    let _guard = test_guard!();
    assert_eq!(urlencoding_encode("hello world"), "hello%20world");
    assert_eq!(urlencoding_encode("path/to/file"), "path%2Fto%2Ffile");
    assert_eq!(urlencoding_encode("foo:bar"), "foo%3Abar");
}

#[test]
fn test_urlencoding_encode_special_chars() {
    let _guard = test_guard!();
    assert_eq!(urlencoding_encode("a&b=c"), "a%26b%3Dc");
    assert_eq!(urlencoding_encode("100%"), "100%25");
    assert_eq!(urlencoding_encode("hello+world"), "hello%2Bworld");
}

#[test]
fn test_urlencoding_encode_no_encoding_needed() {
    let _guard = test_guard!();
    assert_eq!(urlencoding_encode("simple"), "simple");
    assert_eq!(
        urlencoding_encode("with-dash_underscore.dot~tilde"),
        "with-dash_underscore.dot~tilde"
    );
    assert_eq!(urlencoding_encode("ABC123"), "ABC123");
}

#[test]
fn test_urlencoding_encode_unicode() {
    let _guard = test_guard!();
    // Unicode characters should be encoded as UTF-8 bytes
    let encoded = urlencoding_encode("café");
    assert!(encoded.contains("%")); // 'é' should be encoded
    assert!(encoded.starts_with("caf")); // ASCII part preserved
}

#[test]
fn test_parse_jobs_flag_variants() {
    let _guard = test_guard!();
    assert_eq!(parse_jobs_flag("cargo build -j 8"), Some(8));
    assert_eq!(parse_jobs_flag("cargo build -j8"), Some(8));
    assert_eq!(parse_jobs_flag("cargo build --jobs 4"), Some(4));
    assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
    assert_eq!(parse_jobs_flag("cargo build -j=16"), Some(16));
    assert_eq!(parse_jobs_flag("cargo build --jobs=12"), Some(12));
    assert_eq!(parse_jobs_flag("cargo build -j"), None);
    assert_eq!(parse_jobs_flag("cargo build --jobs"), None);
}

#[test]
fn test_parse_test_threads_variants() {
    let _guard = test_guard!();
    assert_eq!(
        parse_test_threads("cargo test -- --test-threads=4"),
        Some(4)
    );
    assert_eq!(
        parse_test_threads("cargo test -- --test-threads 2"),
        Some(2)
    );
    assert_eq!(parse_test_threads("cargo test"), None);
}

#[test]
fn test_estimate_cores_for_command() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 10,
        check_slots: 3,
        ..Default::default()
    };

    let build =
        estimate_cores_for_command(Some(CompilationKind::CargoBuild), "cargo build", &config);
    assert_eq!(build, 6);

    let build_jobs = estimate_cores_for_command(
        Some(CompilationKind::CargoBuild),
        "cargo build -j 12",
        &config,
    );
    assert_eq!(build_jobs, 12);

    let test_default =
        estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
    assert_eq!(test_default, 10);

    let test_threads = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -- --test-threads=4",
        &config,
    );
    assert_eq!(test_threads, 4);

    let test_jobs = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -j 1 -p rchd --lib",
        &config,
    );
    assert_eq!(test_jobs, 1);

    let test_long_jobs = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test --jobs=3 -p rchd --lib",
        &config,
    );
    assert_eq!(test_long_jobs, 3);

    let test_jobs_override_threads = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -j 1 -- --test-threads=8",
        &config,
    );
    assert_eq!(test_jobs_override_threads, 1);

    let test_build_jobs_env = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "CARGO_BUILD_JOBS=2 cargo test -p rchd --lib",
        &config,
    );
    assert_eq!(test_build_jobs_env, 2);

    let test_env = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "RUST_TEST_THREADS=3 cargo test",
        &config,
    );
    assert_eq!(test_env, 3);

    let check_default =
        estimate_cores_for_command(Some(CompilationKind::CargoCheck), "cargo check", &config);
    assert_eq!(check_default, 3);
}

// =========================================================================
// Classification + threshold interaction tests
// =========================================================================

#[test]
fn test_classification_confidence_levels() {
    let _guard = test_guard!();
    // High confidence: explicit cargo build
    let result = classify_command("cargo build");
    assert!(result.is_compilation);
    assert!(result.confidence >= 0.90);

    // Still compilation but different command
    let result = classify_command("cargo test --release");
    assert!(result.is_compilation);
    assert!(result.confidence >= 0.85);

    // Non-compilation cargo commands should not trigger
    let result = classify_command("cargo fmt");
    assert!(!result.is_compilation);
}

#[test]
fn test_classification_bun_commands() {
    let _guard = test_guard!();
    // Bun compilation commands should be intercepted
    let result = classify_command("bun test");
    assert!(result.is_compilation);

    let result = classify_command("bun typecheck");
    assert!(result.is_compilation);

    // Bun watch modes should NOT be intercepted
    let result = classify_command("bun test --watch");
    assert!(!result.is_compilation);

    let result = classify_command("bun typecheck --watch");
    assert!(!result.is_compilation);

    // Bun package management should NOT be intercepted
    let result = classify_command("bun install");
    assert!(!result.is_compilation);

    let result = classify_command("bun add react");
    assert!(!result.is_compilation);

    let result = classify_command("bun remove react");
    assert!(!result.is_compilation);

    let result = classify_command("bun link");
    assert!(!result.is_compilation);

    // Bun execution helpers should NOT be intercepted
    let result = classify_command("bun run build");
    assert!(!result.is_compilation);

    let result = classify_command("bun build");
    assert!(!result.is_compilation);

    let result = classify_command("bun dev");
    assert!(!result.is_compilation);

    let result = classify_command("bun repl");
    assert!(!result.is_compilation);

    let result = classify_command("bun x vite build");
    assert!(!result.is_compilation);

    let result = classify_command("bunx vite build");
    assert!(!result.is_compilation);
}

#[test]
fn test_classification_c_compilers_and_build_systems() {
    let _guard = test_guard!();
    let result = classify_command("gcc -O2 -o hello hello.c");
    assert!(result.is_compilation);

    let result = classify_command("g++ -std=c++20 -o hello hello.cpp");
    assert!(result.is_compilation);

    let result = classify_command("clang -o hello hello.c");
    assert!(result.is_compilation);

    let result = classify_command("clang++ -o hello hello.cpp");
    assert!(result.is_compilation);

    let result = classify_command("make");
    assert!(result.is_compilation);

    let result = classify_command("ninja -C build");
    assert!(result.is_compilation);

    let result = classify_command("cmake --build build");
    assert!(result.is_compilation);
}

#[test]
fn test_classification_env_wrapped_commands() {
    let _guard = test_guard!();
    let result = classify_command("RUST_BACKTRACE=1 cargo test");
    assert!(result.is_compilation);

    let result = classify_command("RUST_TEST_THREADS=4 cargo test");
    assert!(result.is_compilation);
}

#[test]
fn test_classification_rejects_shell_metachars() {
    let _guard = test_guard!();
    // Piped commands should not be intercepted
    let result = classify_command("cargo build | tee log.txt");
    assert!(!result.is_compilation);
    assert!(result.reason.contains("pipe"));

    // Backgrounded commands should not be intercepted
    let result = classify_command("cargo build &");
    assert!(!result.is_compilation);
    assert!(result.reason.contains("background"));

    // Redirected commands should not be intercepted
    let result = classify_command("cargo build > output.log");
    assert!(!result.is_compilation);
    assert!(result.reason.contains("redirect"));

    // Subshell capture should not be intercepted
    let result = classify_command("result=$(cargo build)");
    assert!(!result.is_compilation);
    assert!(result.reason.contains("subshell"));
}

#[test]
fn test_extract_project_name() {
    let _guard = test_guard!();
    // The function uses current directory, but we can test it runs
    let project = extract_project_name();
    // Should return something (either actual dir name or "unknown")
    assert!(!project.is_empty());
}

/// Regression test for GitHub #9: when a custom [`PathTopologyPolicy`]
/// is supplied and the cwd lives under the configured canonical root,
/// normalization must succeed and must not fall back to the
/// default `/data/projects` root.
#[test]
fn test_extract_project_name_honors_custom_policy() {
    let _guard = test_guard!();
    use std::fs;

    // Create an isolated canonical root inside the OS temp dir.
    let tmp = std::env::temp_dir().join(format!(
        "rch_extract_custom_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&tmp).expect("create canonical root");
    let project_dir = tmp.join("sample_project");
    fs::create_dir_all(&project_dir).expect("create project dir");

    // Resolve to the real path so symlinked temp dirs (e.g. /tmp -> /private/tmp
    // on macOS) don't trip the `OutsideCanonicalRoot` check.
    let canonical_tmp = fs::canonicalize(&tmp).expect("canonicalize tmp");
    let canonical_project = fs::canonicalize(&project_dir).expect("canonicalize project");

    let policy = PathTopologyPolicy::new(canonical_tmp.clone(), canonical_tmp.clone());

    let prev_cwd = std::env::current_dir().ok();
    std::env::set_current_dir(&canonical_project).expect("cd into project dir");

    let project = extract_project_name_with_policy(&policy);

    // Restore cwd before any assertion so failure doesn't poison other tests.
    if let Some(prev) = prev_cwd {
        let _ = std::env::set_current_dir(prev);
    }
    let _ = fs::remove_dir_all(&tmp);

    // The project name must be based on the configured root's subdir,
    // and crucially must not equal "unknown" (the fallback when
    // normalization against the default `/data/projects` policy fails).
    assert!(
        project.starts_with("sample_project-"),
        "expected project name to start with sample_project-, got {:?} \
             (cwd was {:?})",
        project,
        canonical_project
    );
}

// =========================================================================
// Hook output protocol tests
// =========================================================================

#[test]
fn test_hook_output_allow_is_empty() {
    let _guard = test_guard!();
    // Allow output should serialize to nothing (empty stdout = allow)
    let output = HookOutput::allow();
    assert!(output.is_allow());
}

#[test]
fn test_hook_output_deny_serializes() {
    let _guard = test_guard!();
    let output = HookOutput::deny("Test denial reason".to_string());
    let json = serde_json::to_string(&output).expect("Should serialize");
    assert!(json.contains("deny"));
    assert!(json.contains("Test denial reason"));
}

#[test]
fn test_selected_worker_to_config() {
    let _guard = test_guard!();
    let worker = SelectedWorker {
        id: rch_common::WorkerId::new("test-worker"),
        host: "192.168.1.100".to_string(),
        user: "ubuntu".to_string(),
        identity_file: "~/.ssh/id_rsa".to_string(),
        slots_available: 8,
        speed_score: 75.5,
    };

    let config = selected_worker_to_config(&worker);
    assert_eq!(config.id.as_str(), "test-worker");
    assert_eq!(config.host, "192.168.1.100");
    assert_eq!(config.user, "ubuntu");
    assert_eq!(config.total_slots, 8);
}

#[test]
fn test_parse_preferred_workers_dedupes_ordered_values() {
    let _guard = test_guard!();
    let workers = dedupe_worker_ids(parse_preferred_workers(" ts2, vmi1,,ts2 , vmi2 "));
    let ids: Vec<&str> = workers.iter().map(|worker| worker.as_str()).collect();
    assert_eq!(ids, vec!["ts2", "vmi1", "vmi2"]);
}

// =========================================================================
// Mock daemon socket tests
// =========================================================================

#[tokio::test]
async fn test_daemon_query_missing_socket() {
    // Query a non-existent socket should fail gracefully
    let result = query_daemon(
        "/tmp/nonexistent_rch_test.sock",
        "testproj",
        4,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        100, // 100µs classification time
        None,
        false,
        &[],
    )
    .await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("not found") || err_msg.contains("No such file"));
}

#[tokio::test]
async fn test_daemon_query_protocol() {
    // Create a mock daemon socket
    let socket_path = format!("/tmp/rch_test_daemon_{}.sock", std::process::id());

    // Clean up any existing socket
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

    // Spawn mock daemon handler
    let socket_path_clone = socket_path.clone();
    let daemon_handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        // Read the request line
        let mut request_line = String::new();
        buf_reader
            .read_line(&mut request_line)
            .await
            .expect("Failed to read request");

        // Verify request format
        assert!(request_line.starts_with("GET /select-worker"));
        assert!(request_line.contains("project="));
        assert!(request_line.contains("cores="));
        assert!(request_line.contains("command=cargo%20build"));
        assert!(request_line.contains("priority=normal"));

        // Send mock response
        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 16,
                speed_score: 95.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        let body = serde_json::to_string(&response).unwrap();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        writer
            .write_all(http_response.as_bytes())
            .await
            .expect("Failed to write response");
        writer.flush().await.expect("Failed to flush response");
    });

    // Give daemon time to start listening
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Query the mock daemon
    let result = query_daemon(
        &socket_path,
        "test-project",
        4,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        100,
        None,
        false,
        &[],
    )
    .await;

    // Clean up
    daemon_handle.await.expect("Daemon task panicked");
    let _ = std::fs::remove_file(&socket_path_clone);

    // Verify result
    let response = result.expect("Query should succeed");
    let worker = response.worker.expect("Should have worker");
    assert_eq!(worker.id.as_str(), "mock-worker");
    assert_eq!(worker.host, "mock.host.local");
    assert_eq!(worker.slots_available, 16);
}

#[tokio::test]
async fn test_daemon_query_sends_preferred_workers() {
    let socket_path = format!("/tmp/rch_test_daemon_preferred_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

    let socket_path_clone = socket_path.clone();
    let daemon_handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        let mut request_line = String::new();
        buf_reader
            .read_line(&mut request_line)
            .await
            .expect("Failed to read request");

        assert!(request_line.contains("worker=ts2"));
        assert!(request_line.contains("worker=vmi1264463"));
        assert!(request_line.contains("preferred_workers=ts2%2Cvmi1264463"));

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("ts2"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 16,
                speed_score: 95.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        let body = serde_json::to_string(&response).unwrap();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        writer
            .write_all(http_response.as_bytes())
            .await
            .expect("Failed to write response");
        writer.flush().await.expect("Failed to flush response");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let preferred = vec![
        rch_common::WorkerId::new("ts2"),
        rch_common::WorkerId::new("vmi1264463"),
    ];
    let result = query_daemon(
        &socket_path,
        "test-project",
        4,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        100,
        None,
        false,
        &preferred,
    )
    .await;

    daemon_handle.await.expect("Daemon task panicked");
    let _ = std::fs::remove_file(&socket_path_clone);

    let response = result.expect("Query should succeed");
    let worker = response.worker.expect("Should have worker");
    assert_eq!(worker.id.as_str(), "ts2");
}

#[tokio::test]
async fn test_daemon_query_wait_parameters() {
    let socket_path = format!("/tmp/rch_test_wait_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");
    let expected_wait_timeout_secs = daemon_response_timeout_for(true, None, None)
        .as_secs()
        .saturating_sub(1)
        .max(1);

    let socket_path_clone = socket_path.clone();
    let daemon_handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        let mut request_line = String::new();
        buf_reader
            .read_line(&mut request_line)
            .await
            .expect("Failed to read request");

        assert!(request_line.starts_with("GET /select-worker"));
        assert!(request_line.contains("wait=1"));
        assert!(request_line.contains(&format!("wait_timeout_secs={expected_wait_timeout_secs}")));

        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("mock-worker"),
                host: "mock.host.local".to_string(),
                user: "mockuser".to_string(),
                identity_file: "~/.ssh/mock_key".to_string(),
                slots_available: 16,
                speed_score: 95.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        let body = serde_json::to_string(&response).unwrap();
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        writer
            .write_all(http_response.as_bytes())
            .await
            .expect("Failed to write response");
        writer.flush().await.expect("Failed to flush response");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let result = query_daemon(
        &socket_path,
        "test-project",
        4,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        100,
        None,
        true,
        &[],
    )
    .await;

    daemon_handle.await.expect("Daemon task panicked");
    let _ = std::fs::remove_file(&socket_path_clone);

    let response = result.expect("Query should succeed");
    let worker = response.worker.expect("Should have worker");
    assert_eq!(worker.id.as_str(), "mock-worker");
}

#[tokio::test]
async fn test_daemon_query_url_encoding() {
    // Verify special characters in project name are encoded
    let socket_path = format!("/tmp/rch_test_url_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

    let socket_path_clone = socket_path.clone();
    let daemon_handle = tokio::spawn(async move {
        let (stream, _) = listener
            .accept()
            .await
            .expect("Failed to accept connection");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        // Read the request line
        let mut request_line = String::new();
        buf_reader.read_line(&mut request_line).await.expect("Read");

        // The project name "my project/test" should be URL encoded
        assert!(request_line.contains("my%20project%2Ftest"));

        // Send minimal response
        let response = SelectionResponse {
            worker: Some(SelectedWorker {
                id: rch_common::WorkerId::new("w1"),
                host: "h".to_string(),
                user: "u".to_string(),
                identity_file: "i".to_string(),
                slots_available: 1,
                speed_score: 1.0,
            }),
            reason: SelectionReason::Success,
            build_id: None,
            diagnostics: None,
        };
        let body = serde_json::to_string(&response).unwrap();
        let http = format!("HTTP/1.1 200 OK\r\n\r\n{}", body);
        writer.write_all(http.as_bytes()).await.expect("Write");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let result = query_daemon(
        &socket_path,
        "my project/test",
        2,
        "cargo build --release",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        150, // 150µs classification time
        None,
        false,
        &[],
    )
    .await;
    daemon_handle.await.expect("Daemon task");
    let _ = std::fs::remove_file(&socket_path_clone);

    assert!(result.is_ok());
}

// =========================================================================
// Fail-open behavior tests
// =========================================================================

#[tokio::test]
async fn test_fail_open_on_invalid_json() {
    let _lock = test_lock().lock().await;
    // Disable mock mode to test real fail-open behavior
    mock::set_mock_enabled_override(Some(false));

    let mut config = rch_common::RchConfig::default();
    config.general.socket_path = "/tmp/rch-test-no-daemon.sock".to_string();
    let _ = std::fs::remove_file(&config.general.socket_path);
    let _config_guard = ConfigOverrideGuard::set(config);

    // If hook input is invalid JSON, should allow (fail-open)
    // This tests the run_hook behavior implicitly through process_hook
    // We can't easily test run_hook directly as it reads stdin

    // But we can verify that process_hook with valid input returns Allow
    // when no daemon is available (which is the fail-open case)
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    // With no daemon running, should fail-open to allow
    let output = process_hook(input).await;
    mock::clear_mock_overrides();
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fail_open_on_config_error() {
    let _lock = test_lock().lock().await;
    // Disable mock mode to test real fail-open behavior
    mock::set_mock_enabled_override(Some(false));

    // If config is missing or invalid, should allow
    // This is tested implicitly by process_hook when config can't load
    // The current implementation falls back to allow
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build --release".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    mock::clear_mock_overrides();
    // Should allow because daemon isn't running (fail-open)
    assert!(output.is_allow());
}

#[tokio::test]
#[serial(mock_global)]
async fn test_process_hook_remote_success_mocked() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_hook_success_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("mock-worker"),
            host: "mock.host.local".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            slots_available: 8,
            speed_score: 90.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output: HookOutput = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Hook should return AllowWithModifiedCommand delegating to `rch exec`
    // The actual remote compilation happens when `rch exec` runs, not in the hook
    assert!(output.is_allow());
    let cmd = delegated_command(&output);
    assert!(
        cmd.starts_with("rch exec -- "),
        "Modified command should delegate to rch exec: {}",
        cmd
    );
    assert!(
        cmd.contains("cargo build"),
        "Modified command should contain original command: {}",
        cmd
    );

    // No rsync/SSH should be invoked during the hook - that happens in run_exec
    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let ssh_logs = mock::global_ssh_invocations_snapshot();
    assert!(
        rsync_logs.is_empty(),
        "Hook should not invoke rsync directly"
    );
    assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
}

#[tokio::test]
#[serial(mock_global)]
async fn test_force_local_allows_even_when_remote_available() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_hook_force_local_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let mut config = rch_common::RchConfig::default();
    config.general.socket_path = socket_path.to_string();
    config.general.force_local = true;
    crate::config::set_test_config_override(Some(config));

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("mock-worker"),
            host: "mock.host.local".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            slots_available: 8,
            speed_score: 90.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    assert!(output.is_allow());

    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let ssh_logs = mock::global_ssh_invocations_snapshot();
    assert!(rsync_logs.is_empty());
    assert!(ssh_logs.is_empty());
}

#[tokio::test]
#[serial(mock_global)]
async fn test_force_remote_bypasses_confidence_threshold() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_hook_force_remote_threshold_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let classification = classify_command("cargo build");
    assert!(classification.is_compilation);
    let high_threshold = (classification.confidence + 0.01).min(1.0);

    let mut config = rch_common::RchConfig::default();
    config.general.socket_path = socket_path.to_string();
    config.general.force_remote = true;
    config.compilation.confidence_threshold = high_threshold;
    crate::config::set_test_config_override(Some(config));

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("mock-worker"),
            host: "mock.host.local".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            slots_available: 8,
            speed_score: 90.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // force_remote should result in transparent interception (AllowWithModifiedCommand)
    // with delegation to `rch exec`
    assert!(output.is_allow());
    let cmd = delegated_command(&output);
    assert!(
        cmd.starts_with("rch exec -- "),
        "Should delegate to rch exec: {}",
        cmd
    );

    // No rsync/SSH should be invoked during the hook - that happens in run_exec
    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let ssh_logs = mock::global_ssh_invocations_snapshot();
    assert!(
        rsync_logs.is_empty(),
        "Hook should not invoke rsync directly"
    );
    assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
}

#[tokio::test]
#[serial(mock_global)]
async fn test_process_hook_delegates_to_rch_exec() {
    // Test that process_hook always delegates to `rch exec` without doing
    // any remote operations itself. Sync failures (if any) would happen
    // in run_exec, not in process_hook.
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_hook_delegate_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Even with sync_failure mock config, the hook should succeed
    // because it doesn't do sync - it just delegates to rch exec
    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::sync_failure(),
    );
    mock::clear_global_invocations();

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Hook should return AllowWithModifiedCommand delegating to rch exec
    assert!(output.is_allow());
    let cmd = delegated_command(&output);
    assert!(
        cmd.starts_with("rch exec -- "),
        "Should delegate to rch exec: {}",
        cmd
    );

    // No rsync/SSH should be invoked during the hook
    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let ssh_logs = mock::global_ssh_invocations_snapshot();
    assert!(
        rsync_logs.is_empty(),
        "Hook should not invoke rsync directly"
    );
    assert!(ssh_logs.is_empty(), "Hook should not invoke SSH directly");
}

#[tokio::test]
#[serial(mock_global)]
async fn test_process_hook_delegates_env_prefixed_cargo_command() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_hook_delegate_env_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::sync_failure(),
    );
    mock::clear_global_invocations();

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "env RUSTFLAGS=\"-C linker=cc\" cargo build --bin frankenctl".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    let cmd = delegated_command(&output);
    assert!(
        cmd.starts_with("rch exec -- env "),
        "env wrapper must remain an argv prefix in delegated command: {cmd}"
    );
    let tokens = shell_words::split(
        cmd.strip_prefix("rch exec -- ")
            .expect("delegated command prefix"),
    )
    .expect("delegated command should parse as shell words");
    assert_eq!(
        tokens,
        vec![
            "env".to_string(),
            "RUSTFLAGS=-C linker=cc".to_string(),
            "cargo".to_string(),
            "build".to_string(),
            "--bin".to_string(),
            "frankenctl".to_string(),
        ]
    );

    assert!(mock::global_rsync_invocations_snapshot().is_empty());
    assert!(mock::global_ssh_invocations_snapshot().is_empty());
}

#[tokio::test]
#[serial(mock_global)]
async fn test_process_hook_remote_nonzero_exit_uses_transparent_interception() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_hook_exit_nonzero_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig {
            default_exit_code: 2,
            ..MockConfig::default()
        },
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("mock-worker"),
            host: "mock.host.local".to_string(),
            user: "mockuser".to_string(),
            identity_file: "~/.ssh/mock_key".to_string(),
            slots_available: 8,
            speed_score: 90.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Remote failure should still use transparent interception (AllowWithModifiedCommand)
    // with "exit <code>" to preserve the exit code for the agent
    assert!(output.is_allow());
    assert!(
        matches!(output, HookOutput::AllowWithModifiedCommand(_)),
        "Expected AllowWithModifiedCommand for remote execution with non-zero exit"
    );
}

#[test]
fn test_transfer_config_defaults() {
    let _guard = test_guard!();
    // Verify TransferConfig has sensible defaults
    let config = TransferConfig::default();
    assert!(!config.exclude_patterns.is_empty());
    assert!(config.exclude_patterns.iter().any(|p| p.contains("target")));
}

#[test]
fn test_worker_config_from_selected_worker() {
    let _guard = test_guard!();
    // Test the conversion preserves all fields correctly
    let worker = SelectedWorker {
        id: rch_common::WorkerId::new("worker-alpha"),
        host: "alpha.example.com".to_string(),
        user: "deploy".to_string(),
        identity_file: "/keys/deploy.pem".to_string(),
        slots_available: 32,
        speed_score: 88.8,
    };

    let config = selected_worker_to_config(&worker);

    assert_eq!(config.id.as_str(), "worker-alpha");
    assert_eq!(config.host, "alpha.example.com");
    assert_eq!(config.user, "deploy");
    assert_eq!(config.identity_file, "/keys/deploy.pem");
    assert_eq!(config.total_slots, 32);
    assert_eq!(config.priority, 100); // Default priority
    assert!(config.tags.is_empty()); // Default empty tags
}

// =========================================================================
// Local fallback scenario tests (remote_compilation_helper-od4)
// =========================================================================

#[tokio::test]
async fn test_fallback_no_workers_configured() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_no_workers_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Daemon returns no workers configured
    let response = SelectionResponse {
        worker: None,
        reason: SelectionReason::NoWorkersConfigured,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_all_workers_unreachable() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_unreachable_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Daemon returns all workers unreachable
    let response = SelectionResponse {
        worker: None,
        reason: SelectionReason::AllWorkersUnreachable,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build --release".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_all_workers_busy() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_busy_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Daemon returns all workers busy
    let response = SelectionResponse {
        worker: None,
        reason: SelectionReason::AllWorkersBusy,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_all_circuits_open() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_circuits_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Daemon returns all circuits open (circuit breaker tripped)
    let response = SelectionResponse {
        worker: None,
        reason: SelectionReason::AllCircuitsOpen,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo check".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_selection_error() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_sel_err_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Daemon returns a selection error
    let response = SelectionResponse {
        worker: None,
        reason: SelectionReason::SelectionError("Internal error".to_string()),
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_daemon_error_response() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_daemon_err_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Spawn a daemon that returns HTTP 500 error
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        let mut request_line = String::new();
        buf_reader.read_line(&mut request_line).await.expect("read");

        // Return HTTP 500 error
        let http =
            "HTTP/1.1 500 Internal Server Error\r\n\r\n Расположение: {\"error\": \"internal\"}";
        writer.write_all(http.as_bytes()).await.expect("write");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution (fail-open)
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_daemon_malformed_json() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_malformed_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Spawn a daemon that returns malformed JSON
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        let mut request_line = String::new();
        buf_reader.read_line(&mut request_line).await.expect("read");

        // Return malformed JSON
        let http = "HTTP/1.1 200 OK\r\n\r\n{invalid json}";
        writer.write_all(http.as_bytes()).await.expect("write");
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution (fail-open on parse error)
    assert!(output.is_allow());
}

#[tokio::test]
async fn test_fallback_daemon_connection_reset() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_reset_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Spawn a daemon that immediately closes connection
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind");

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        // Immediately drop the stream to simulate connection reset
        drop(stream);
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fall back to local execution (fail-open on connection error)
    assert!(output.is_allow());
}

// =========================================================================
// Exit code handling tests (bead remote_compilation_helper-zerp)
// =========================================================================

#[test]
fn test_is_signal_killed() {
    let _guard = test_guard!();
    // Normal exit codes should not be signal-killed
    assert!(is_signal_killed(0).is_none());
    assert!(is_signal_killed(1).is_none());
    assert!(is_signal_killed(101).is_none());
    assert!(is_signal_killed(128).is_none()); // 128 is exactly at boundary

    // Signal kills (128 + signal)
    assert_eq!(is_signal_killed(129), Some(1)); // SIGHUP
    assert_eq!(is_signal_killed(130), Some(2)); // SIGINT
    assert_eq!(is_signal_killed(137), Some(9)); // SIGKILL
    assert_eq!(is_signal_killed(139), Some(11)); // SIGSEGV
    assert_eq!(is_signal_killed(143), Some(15)); // SIGTERM
}

#[test]
fn test_signal_name() {
    let _guard = test_guard!();
    assert_eq!(signal_name(1), "SIGHUP");
    assert_eq!(signal_name(2), "SIGINT");
    assert_eq!(signal_name(9), "SIGKILL");
    assert_eq!(signal_name(11), "SIGSEGV");
    assert_eq!(signal_name(15), "SIGTERM");
    assert_eq!(signal_name(99), "UNKNOWN");
}

#[test]
fn test_exit_code_constants() {
    let _guard = test_guard!();
    // Verify exit code constants match cargo's documented behavior
    assert_eq!(EXIT_SUCCESS, 0);
    assert_eq!(EXIT_BUILD_ERROR, 1);
    assert_eq!(EXIT_TEST_FAILURES, 101);
    assert_eq!(EXIT_SIGNAL_BASE, 128);
}

#[test]
fn test_remote_pipeline_failure_policy_ssh_timeout_fails_closed() {
    let _guard = test_guard!();
    let error = anyhow::anyhow!("SSH command timed out after 1800s");

    assert_eq!(
        classify_remote_pipeline_failure(&error),
        RemotePipelineFailurePolicy::FailClosedNoLocalFallback
    );
}

#[test]
fn test_remote_pipeline_failure_policy_wrapped_ssh_timeout_fails_closed() {
    let _guard = test_guard!();
    let error =
        anyhow::anyhow!("SSH command timed out after 1800s").context("remote execution failed");

    assert_eq!(
        classify_remote_pipeline_failure(&error),
        RemotePipelineFailurePolicy::FailClosedNoLocalFallback
    );
}

#[test]
fn test_remote_pipeline_failure_policy_non_timeout_allows_existing_fallback() {
    let _guard = test_guard!();
    let error = anyhow::anyhow!("rsync failed before remote execution");

    assert_eq!(
        classify_remote_pipeline_failure(&error),
        RemotePipelineFailurePolicy::AllowLocalFallback
    );
}

#[test]
fn test_is_toolchain_failure_basic() {
    let _guard = test_guard!();
    // Should detect toolchain issues
    assert!(is_toolchain_failure(
        "error: toolchain 'nightly-2025-01-01' is not installed",
        1
    ));
    assert!(is_toolchain_failure("rustup: command not found", 127));
    assert!(is_toolchain_failure(
        "error: no default toolchain configured",
        1
    ));
    assert!(is_toolchain_failure(
        "error: toolchain 'nightly-2025-01-01' does not have the binary `cargo`",
        1
    ));

    // Should not flag normal failures
    assert!(!is_toolchain_failure(
        "error[E0425]: cannot find value `x`",
        1
    ));
    assert!(!is_toolchain_failure(
        "test result: FAILED. 1 passed; 2 failed",
        101
    ));

    // Success should never be a toolchain failure
    assert!(!is_toolchain_failure("anything", 0));
}

#[test]
fn test_is_toolchain_failure_ignores_rustup_toolchain_paths_in_normal_failures() {
    let _guard = test_guard!();
    let stderr = r#"error: could not compile `serde` (lib)
Caused by:
  process didn't exit successfully: `/home/ubuntu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc --crate-name serde ...` (signal: 9, SIGKILL: kill)
"#;

    assert!(
        !is_toolchain_failure(stderr, 137),
        "SIGKILL/OOM stderr mentioning .rustup/toolchains paths must not trigger local fallback"
    );

    let compile_error = r#"error[E0425]: cannot find value `x` in this scope
note: the compiler executable is /home/ubuntu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc
"#;

    assert!(
        !is_toolchain_failure(compile_error, EXIT_BUILD_ERROR),
        "ordinary compile errors mentioning the rustc toolchain path must not trigger local fallback"
    );
}

#[test]
fn test_detect_worker_system_dependency_failure_from_pkg_config_output() {
    let _guard = test_guard!();
    let stderr = r#"thread 'main' panicked at build.rs:42:14:
called `Result::unwrap()` on an `Err` value:
pkg-config exited with status code 1
> PKG_CONFIG_ALLOW_SYSTEM_LIBS=1 pkg-config --libs --cflags x11 'x11 >= 1.4.99.1'

The system library `x11` required by crate `x11` was not found.
The file `x11.pc` needs to be installed and the PKG_CONFIG_PATH environment variable must contain its parent directory.
"#;

    let failure = detect_worker_system_dependency_failure(stderr, EXIT_BUILD_ERROR)
        .expect("pkg-config/system dependency failure should be detected");

    assert_eq!(failure.system_library.as_deref(), Some("x11"));
    assert_eq!(failure.crate_name.as_deref(), Some("x11"));
    assert_eq!(failure.pkg_config_file.as_deref(), Some("x11.pc"));
    assert_eq!(failure.summary(), "missing worker system package x11.pc");
    assert!(failure.remediation().contains("x11.pc"));
}

#[test]
fn test_detect_worker_system_dependency_failure_ignores_normal_compile_errors() {
    let _guard = test_guard!();
    let stderr = r#"error[E0425]: cannot find value `oops` in this scope
 --> src/main.rs:4:5
  |
4 |     oops();
  |     ^^^^ not found in this scope
"#;

    assert!(
        detect_worker_system_dependency_failure(stderr, EXIT_BUILD_ERROR).is_none(),
        "ordinary compile errors must not be misclassified as worker env failures"
    );
}

#[test]
fn test_exit_code_semantics_documented() {
    let _guard = test_guard!();
    // This test documents the expected behavior for different exit codes
    // Exit 0: Success - should deny local (verified in other tests)
    // Exit 101: Test failures - should deny local (re-running won't help)
    // Exit 1: Build error - should deny local (same error locally)
    // Exit 137: SIGKILL - should deny local (likely OOM)

    // Verify constants are what we expect
    assert_eq!(EXIT_SUCCESS, 0, "Success exit code should be 0");
    assert_eq!(EXIT_BUILD_ERROR, 1, "Build error exit code should be 1");
    assert_eq!(
        EXIT_TEST_FAILURES, 101,
        "Test failures exit code should be 101"
    );

    // Verify signal detection
    let sigkill = 128 + 9;
    assert_eq!(is_signal_killed(sigkill), Some(9), "Should detect SIGKILL");
    assert_eq!(signal_name(9), "SIGKILL", "Should name SIGKILL correctly");
}

// =========================================================================
// Cargo test integration tests (bead remote_compilation_helper-iyv1)
// =========================================================================

#[test]
fn test_wrap_command_with_telemetry_handles_comments() {
    let _guard = test_guard!();
    let worker_id = rch_common::WorkerId::new("worker1");
    let command = "echo hello # my comment";
    let wrapped = wrap_command_with_telemetry(command, &worker_id);

    // Ensure newline separation exists
    assert!(wrapped.contains(&format!("{}\nstatus=$?", command)));

    // Ensure status capture isn't commented out (it should be on a new line)
    let lines: Vec<&str> = wrapped.lines().collect();
    assert!(lines.iter().any(|l| l.starts_with("status=$?")));

    // Basic sanity check on structure
    assert!(wrapped.contains("rch-telemetry collect"));
    assert!(wrapped.contains("exit $status"));
}

#[test]
fn test_add_cargo_isolation_adds_unique_cargo_home() {
    let _guard = test_guard!();
    let worker_id = rch_common::WorkerId::new("test-worker");

    // Test cargo build command gets isolation
    let cargo_command = "cargo build --release";
    let isolated = add_cargo_isolation(cargo_command, &worker_id);

    assert!(isolated.starts_with("sh -c "));
    assert!(!isolated.starts_with("CARGO_HOME="));
    // The staging base is resolved on the worker (no hardcoded /tmp) and the
    // basename keeps the rch-cargo-home- prefix that cleanup matches.
    assert!(
        !isolated.contains("/tmp/rch-cargo-home-"),
        "must not hardcode /tmp: {isolated}"
    );
    assert!(isolated.contains("RCH_CH_BASE="));
    assert!(isolated.contains("/data/tmp"));
    assert!(isolated.contains("mkdir -p \"${RCH_CH_BASE}/rch-cargo-home-test-worker-"));
    assert!(isolated.contains("CARGO_HOME=\"${RCH_CH_BASE}/rch-cargo-home-test-worker-"));
    assert!(isolated.contains("cargo build --release"));
    assert!(isolated.contains("status=$?"));
    assert!(isolated.contains("exit $status"));
    assert!(isolated.contains("rm -rf \"${RCH_CH_BASE}/rch-cargo-home-test-worker-"));
}

#[test]
fn test_sanitize_cargo_home_token_collapses_unsafe_chars() {
    // Path-safe tokens pass through unchanged.
    assert_eq!(sanitize_cargo_home_token("worker-1_2"), "worker-1_2");
    // Spaces, slashes and other shell-meaningful chars collapse to '-'.
    assert_eq!(sanitize_cargo_home_token("a b/c"), "a-b-c");
    // Leading/trailing unsafe chars are trimmed, not left as dangling '-'.
    assert_eq!(sanitize_cargo_home_token("  weird!! "), "weird");
    // An entirely-unsafe (or empty) token falls back to a stable default.
    assert_eq!(sanitize_cargo_home_token("***"), "worker");
    assert_eq!(sanitize_cargo_home_token(""), "worker");
}

// =========================================================================
// Issue #19 Fix 3: pooled remote target-dir REUSE
// =========================================================================

#[test]
fn test_pooled_target_dir_same_dimensions_reuse_same_name() {
    // (a) The whole point: identical (project, toolchain, triple, profile,
    // features) yields the SAME remote dir name across calls, so the warm
    // remote incremental cache is reused instead of cold-recompiling.
    let _guard = test_guard!();
    let worker = rch_common::WorkerId::new("ts2");
    let root = Path::new("/data/projects/acme");
    let tc = ToolchainInfo::new("nightly", Some("2025-11-01".to_string()), "x");

    let a = remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build");
    let b = remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build");
    assert_eq!(a, b, "same dimensions must reuse the same pooled dir");

    // Feature SET (not order/dups) determines the key.
    let f1 = remote_cargo_pooled_target_dir_name(
        &worker,
        root,
        Some(&tc),
        "cargo build --features serde,tokio",
    );
    let f2 = remote_cargo_pooled_target_dir_name(
        &worker,
        root,
        Some(&tc),
        "cargo build --features tokio --features serde",
    );
    assert_eq!(f1, f2, "feature set is order/dup-insensitive");
}

#[test]
fn test_pooled_target_dir_each_dimension_change_invalidates() {
    // (b) Changing ANY cache dimension yields a DIFFERENT name, so an
    // incompatible build never reuses a contaminated pool.
    let _guard = test_guard!();
    let worker = rch_common::WorkerId::new("ts2");
    let root = Path::new("/data/projects/acme");
    let tc = ToolchainInfo::new("nightly", Some("2025-11-01".to_string()), "x");
    let base = remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build");

    // Profile (--release).
    assert_ne!(
        base,
        remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build --release"),
        "profile change must invalidate"
    );
    // Target triple.
    assert_ne!(
        base,
        remote_cargo_pooled_target_dir_name(
            &worker,
            root,
            Some(&tc),
            "cargo build --target wasm32-unknown-unknown"
        ),
        "triple change must invalidate"
    );
    // Toolchain.
    let tc2 = ToolchainInfo::new("nightly", Some("2026-01-01".to_string()), "x");
    assert_ne!(
        base,
        remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc2), "cargo build"),
        "toolchain change must invalidate"
    );
    // Features.
    assert_ne!(
        base,
        remote_cargo_pooled_target_dir_name(
            &worker,
            root,
            Some(&tc),
            "cargo build --features serde"
        ),
        "feature change must invalidate"
    );
    assert_ne!(
        base,
        remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build --all-features"),
        "--all-features must invalidate"
    );
    // Project root.
    assert_ne!(
        base,
        remote_cargo_pooled_target_dir_name(
            &worker,
            Path::new("/data/projects/other"),
            Some(&tc),
            "cargo build"
        ),
        "project change must invalidate (no cross-project contamination)"
    );
}

#[test]
fn test_pooled_target_dir_name_shape_is_single_segment_and_reapable() {
    // (d) The name has no `/` (so `with_remote_cargo_target_dir_name` accepts
    // it) and keeps the `.rch-target-…-pool-…` shape the reaper recognizes.
    let _guard = test_guard!();
    let worker = rch_common::WorkerId::new("ts2");
    let root = Path::new("/data/projects/acme");
    let tc = ToolchainInfo::new("nightly", Some("2025-11-01".to_string()), "x");
    let name = remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build");

    assert!(
        !name.contains('/'),
        "pooled name must be a single segment: {name}"
    );
    assert!(
        name.starts_with(".rch-target-"),
        "must keep the reaper-recognized prefix: {name}"
    );
    assert!(
        name.contains("-pool-"),
        "must carry the -pool- marker the reaper globs match: {name}"
    );
    assert!(
        rch_common::stale_target_reap::is_safe_reap_token(&name),
        "pooled name must be reap-token-safe: {name}"
    );
}

#[test]
fn test_target_reuse_opt_out_restores_unique_per_job_name() {
    // (c) The opt-out predicate is honored; under opt-out the legacy
    // unique-per-job name is used (distinct per call, distinct from pooled).
    let _guard = test_guard!();
    // Predicate: truthy values disable reuse; falsy/unset keep it on.
    assert!(target_reuse_disabled_from_value(Some("1".to_string())));
    assert!(target_reuse_disabled_from_value(Some("true".to_string())));
    assert!(target_reuse_disabled_from_value(Some("YES".to_string())));
    assert!(!target_reuse_disabled_from_value(None));
    assert!(!target_reuse_disabled_from_value(Some("0".to_string())));
    assert!(!target_reuse_disabled_from_value(Some("false".to_string())));
    assert!(!target_reuse_disabled_from_value(Some(String::new())));

    // The fallback path (unique-per-job) is non-pooled and unique per call.
    let worker = rch_common::WorkerId::new("ts2");
    let root = Path::new("/data/projects/acme");
    let tc = ToolchainInfo::new("nightly", Some("2025-11-01".to_string()), "x");
    let pooled = remote_cargo_pooled_target_dir_name(&worker, root, Some(&tc), "cargo build");
    let unique_a = remote_cargo_target_dir_name(Some(7), &worker);
    let unique_b = remote_cargo_target_dir_name(Some(7), &worker);
    assert_ne!(unique_a, unique_b, "opt-out name is unique per invocation");
    assert_ne!(
        pooled, unique_a,
        "opt-out name differs from the pooled name"
    );
    assert!(
        !unique_a.contains("-pool-"),
        "opt-out name is not a pool dir"
    );
}

#[test]
fn test_feature_and_triple_parsing_from_command() {
    let _guard = test_guard!();
    // --features list (comma-separated), the `=` form, and `-F`. The command
    // is a whitespace-tokenized string, so a single `--features` value is a
    // comma list (`a,b`); a space-separated `--features a b` lists `a` and
    // takes `b` as the next positional only if it follows the flag directly,
    // so we use the comma form (cargo's own canonical multi-feature syntax).
    assert_eq!(
        feature_set_for_command("cargo build --features a,b --features=c,d -F e"),
        vec!["a", "b", "c", "d", "e"]
    );
    assert!(
        feature_set_for_command("cargo build --all-features")
            .iter()
            .any(|f| f == "__rch_all_features")
    );
    assert!(
        feature_set_for_command("cargo build --no-default-features")
            .iter()
            .any(|f| f == "__rch_no_default_features")
    );

    // Triple: explicit wins, else host default (stable, non-empty).
    assert_eq!(
        target_triple_for_command("cargo build --target wasm32-unknown-unknown"),
        "wasm32-unknown-unknown"
    );
    assert_eq!(
        target_triple_for_command("cargo build --target=aarch64-apple-darwin"),
        "aarch64-apple-darwin"
    );
    let host = target_triple_for_command("cargo build");
    assert!(!host.is_empty(), "host triple fallback must be non-empty");
    assert_eq!(
        host,
        target_triple_for_command("cargo build"),
        "host triple fallback must be stable"
    );
}

#[test]
fn test_kind_produces_transferable_artifacts() {
    let _guard = test_guard!();
    // Build/doc/rustc + C/C++/build-system kinds produce required artifacts.
    for kind in [
        CompilationKind::CargoBuild,
        CompilationKind::CargoDoc,
        CompilationKind::Rustc,
        CompilationKind::Gcc,
        CompilationKind::Make,
        CompilationKind::CmakeBuild,
        CompilationKind::Ninja,
    ] {
        assert!(
            kind_produces_transferable_artifacts(Some(kind)),
            "{kind:?} must be artifact-producing"
        );
    }
    // Test/diagnostic kinds stream their results; no required artifact.
    for kind in [
        CompilationKind::CargoTest,
        CompilationKind::CargoNextest,
        CompilationKind::CargoBench,
        CompilationKind::CargoCheck,
        CompilationKind::CargoClippy,
        CompilationKind::BunTest,
        CompilationKind::BunTypecheck,
    ] {
        assert!(
            !kind_produces_transferable_artifacts(Some(kind)),
            "{kind:?} must NOT be treated as artifact-producing"
        );
    }
    assert!(!kind_produces_transferable_artifacts(None));
}

#[test]
fn test_add_cargo_isolation_skips_non_cargo_commands() {
    let _guard = test_guard!();
    let worker_id = rch_common::WorkerId::new("test-worker");

    // Test non-cargo command is unchanged
    let non_cargo_command = "echo hello world";
    let isolated = add_cargo_isolation(non_cargo_command, &worker_id);

    assert_eq!(isolated, non_cargo_command);
    assert!(!isolated.contains("CARGO_HOME"));
}

#[test]
fn test_add_cargo_isolation_handles_complex_cargo_commands() {
    let _guard = test_guard!();
    let worker_id = rch_common::WorkerId::new("worker-123");

    // Test complex cargo command with environment variables and arguments
    let complex_command =
        "cd /some/path && RUSTFLAGS=\"-C target-cpu=native\" cargo test --release --features=foo";
    let isolated = add_cargo_isolation(complex_command, &worker_id);

    assert!(isolated.starts_with("sh -c "));
    assert!(
        !isolated.contains("/tmp/rch-cargo-home-"),
        "must not hardcode /tmp: {isolated}"
    );
    assert!(isolated.contains("mkdir -p \"${RCH_CH_BASE}/rch-cargo-home-worker-123-"));
    assert!(isolated.contains("CARGO_HOME=\"${RCH_CH_BASE}/rch-cargo-home-worker-123-"));
    assert!(isolated.contains(
        "cd /some/path && RUSTFLAGS=\"-C target-cpu=native\" cargo test --release --features=foo"
    ));
    assert!(isolated.contains("status=$?"));
    assert!(isolated.contains("exit $status"));
    assert!(isolated.contains("rm -rf \"${RCH_CH_BASE}/rch-cargo-home-worker-123-"));
}

#[test]
fn test_add_cargo_isolation_survives_timeout_prefix_and_preserves_status() {
    let _guard = test_guard!();
    let worker_id = rch_common::WorkerId::new("timeout-worker");
    let isolated = add_cargo_isolation("printf cargo >/dev/null; exit 42", &worker_id);
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "timeout --foreground --preserve-status 5 {}",
            isolated
        ))
        .status()
        .expect("timeout-wrapped isolated command should execute");

    assert_eq!(
        status.code(),
        Some(42),
        "timeout must execute the shell wrapper and preserve the command status"
    );
}

#[test]
fn test_remote_cargo_target_dir_name_is_unique_and_path_safe() {
    let _guard = test_guard!();
    let worker_id = rch_common::WorkerId::new("worker/with spaces");
    let first = remote_cargo_target_dir_name(Some(42), &worker_id);
    let second = remote_cargo_target_dir_name(Some(42), &worker_id);

    assert!(first.starts_with(".rch-target-worker-with-spaces-job-42-"));
    assert!(!first.contains('/'));
    assert!(!first.contains(' '));
    assert_ne!(first, second);
}

#[test]
fn test_parse_stale_target_reap_idle_hours() {
    // Default when unset or unparseable.
    assert_eq!(parse_stale_target_reap_idle_hours(None), 12);
    assert_eq!(
        parse_stale_target_reap_idle_hours(Some("not-a-number".into())),
        12
    );
    assert_eq!(parse_stale_target_reap_idle_hours(Some(String::new())), 12);
    // Honors a valid override (with surrounding whitespace).
    assert_eq!(parse_stale_target_reap_idle_hours(Some("24".into())), 24);
    assert_eq!(parse_stale_target_reap_idle_hours(Some("  6 ".into())), 6);
    // Floors at 1h so a misconfiguration can never reap a live cache.
    assert_eq!(parse_stale_target_reap_idle_hours(Some("0".into())), 1);
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_reads_env_without_allowlist() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoBuild),
        Path::new("/tmp/rch"),
        &reporter,
        |_| Some("/tmp/rch-target-no-allowlist".to_string()),
        None,
    );

    assert_eq!(
        resolved,
        Some(PathBuf::from("/tmp/rch-target-no-allowlist"))
    );
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_defaults_for_cargo() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoBuild),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| None,
        None,
    );

    assert_eq!(
        resolved,
        Some(PathBuf::from(
            "/data/projects/remote_compilation_helper/target"
        ))
    );
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_ignores_non_cargo() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::BunTest),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| Some("/tmp/should-not-forward".to_string()),
        None,
    );

    assert!(resolved.is_none());
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_resolves_relative_path() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoBuild),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| Some("tmp/custom-target".to_string()),
        None,
    );

    assert_eq!(
        resolved,
        Some(PathBuf::from(
            "/data/projects/remote_compilation_helper/tmp/custom-target"
        ))
    );
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_extracts_env_wrapper_assignment() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "env".to_string(),
        "-u".to_string(),
        "RUST_LOG".to_string(),
        "RUST_BACKTRACE=1".to_string(),
        "CARGO_TARGET_DIR=/data/projects/custom-target".to_string(),
        "cargo".to_string(),
        "check".to_string(),
    ];
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoBuild),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| Some("/tmp/env-should-lose-to-command".to_string()),
        Some(&command_tokens),
    );

    assert_eq!(
        resolved,
        Some(PathBuf::from("/data/projects/custom-target"))
    );
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_extracts_inline_assignment() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "CARGO_TARGET_DIR=.rch-target-inline".to_string(),
        "cargo".to_string(),
        "build".to_string(),
    ];
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoBuild),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| None,
        Some(&command_tokens),
    );

    assert_eq!(
        resolved,
        Some(PathBuf::from(
            "/data/projects/remote_compilation_helper/.rch-target-inline"
        ))
    );
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_extracts_target_dir_flag() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "cargo".to_string(),
        "build".to_string(),
        "--target-dir".to_string(),
        "/data/tmp/rch-target-flag".to_string(),
        "--release".to_string(),
    ];
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoBuild),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| None,
        Some(&command_tokens),
    );

    assert_eq!(resolved, Some(PathBuf::from("/data/tmp/rch-target-flag")));
}

#[test]
fn test_resolve_forwarded_cargo_target_dir_extracts_target_dir_equals_flag() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "cargo".to_string(),
        "check".to_string(),
        "--target-dir=/data/tmp/rch-target-equals".to_string(),
    ];
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoCheck),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| None,
        Some(&command_tokens),
    );

    assert_eq!(resolved, Some(PathBuf::from("/data/tmp/rch-target-equals")));
}

#[test]
fn test_rewrite_cargo_target_dir_command_for_remote_strips_inline_assignment() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "env".to_string(),
        "-u".to_string(),
        "RUST_LOG".to_string(),
        "RUST_BACKTRACE=1".to_string(),
        "CARGO_TARGET_DIR=/data/projects/custom-target".to_string(),
        "cargo".to_string(),
        "build".to_string(),
        "--release".to_string(),
    ];

    let rewritten = rewrite_cargo_target_dir_command_for_remote(
        "env -u RUST_LOG RUST_BACKTRACE=1 CARGO_TARGET_DIR=/data/projects/custom-target cargo build --release",
        Some(&command_tokens),
        Some(&PathBuf::from("/data/projects/custom-target")),
        &reporter,
    );

    assert_eq!(
        rewritten,
        "env -u RUST_LOG 'RUST_BACKTRACE=1' cargo build --release"
    );
    assert!(!rewritten.contains("CARGO_TARGET_DIR=/data/projects/custom-target"));
}

#[test]
fn test_rewrite_cargo_target_dir_command_for_remote_strips_target_dir_flag() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "cargo".to_string(),
        "build".to_string(),
        "--target-dir".to_string(),
        "/data/tmp/rch-target-flag".to_string(),
        "--release".to_string(),
    ];

    let rewritten = rewrite_cargo_target_dir_command_for_remote(
        "cargo build --target-dir /data/tmp/rch-target-flag --release",
        Some(&command_tokens),
        Some(&PathBuf::from("/data/tmp/rch-target-flag")),
        &reporter,
    );

    assert_eq!(rewritten, "cargo build --release");
    assert!(!rewritten.contains("--target-dir"));
    assert!(!rewritten.contains("/data/tmp/rch-target-flag"));
}

#[test]
fn test_rewrite_cargo_target_dir_command_for_remote_strips_target_dir_equals_flag() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "cargo".to_string(),
        "check".to_string(),
        "--target-dir=/data/tmp/rch-target-equals".to_string(),
        "--workspace".to_string(),
    ];

    let rewritten = rewrite_cargo_target_dir_command_for_remote(
        "cargo check --target-dir=/data/tmp/rch-target-equals --workspace",
        Some(&command_tokens),
        Some(&PathBuf::from("/data/tmp/rch-target-equals")),
        &reporter,
    );

    assert_eq!(rewritten, "cargo check --workspace");
    assert!(!rewritten.contains("--target-dir"));
    assert!(!rewritten.contains("/data/tmp/rch-target-equals"));
}

#[test]
fn test_cargo_target_dir_scanner_ignores_args_after_delimiter() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "cargo".to_string(),
        "test".to_string(),
        "--".to_string(),
        "--target-dir".to_string(),
        "test-filter".to_string(),
    ];
    let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
        Some(CompilationKind::CargoTest),
        Path::new("/data/projects/remote_compilation_helper"),
        &reporter,
        |_| None,
        Some(&command_tokens),
    );
    let rewritten = rewrite_cargo_target_dir_command_for_remote(
        "cargo test -- --target-dir test-filter",
        Some(&command_tokens),
        Some(&PathBuf::from(
            "/data/projects/remote_compilation_helper/target",
        )),
        &reporter,
    );

    assert_eq!(
        resolved,
        Some(PathBuf::from(
            "/data/projects/remote_compilation_helper/target"
        ))
    );
    assert_eq!(rewritten, "cargo test -- --target-dir test-filter");
}

#[test]
fn test_rewrite_cargo_target_dir_command_preserves_args_after_delimiter() {
    let _guard = test_guard!();
    let reporter = HookReporter::new(OutputVisibility::Verbose);
    let command_tokens = vec![
        "cargo".to_string(),
        "test".to_string(),
        "--target-dir".to_string(),
        "/data/tmp/rch-target-flag".to_string(),
        "--".to_string(),
        "--nocapture".to_string(),
    ];

    let rewritten = rewrite_cargo_target_dir_command_for_remote(
        "cargo test --target-dir /data/tmp/rch-target-flag -- --nocapture",
        Some(&command_tokens),
        Some(&PathBuf::from("/data/tmp/rch-target-flag")),
        &reporter,
    );

    assert_eq!(rewritten, "cargo test -- --nocapture");
}

fn env_key_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Z_][A-Z0-9_]{0,16}")
        .expect("valid env key regex")
        .prop_filter("not the target dir key under test", |key| {
            key != "CARGO_TARGET_DIR"
        })
}

fn shell_safe_value_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9_./:+-]{0,40}").expect("valid env value regex")
}

fn relative_target_dir_strategy() -> impl Strategy<Value = String> {
    prop::string::string_regex("[A-Za-z0-9_.-]{1,16}(/[A-Za-z0-9_.-]{1,16}){0,2}")
        .expect("valid relative path regex")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn env_prefix_target_dir_parser_round_trips_and_rewrites(
        target_dir in relative_target_dir_strategy(),
        extra_envs in prop::collection::vec((env_key_strategy(), shell_safe_value_strategy()), 0..4),
        cargo_subcommand in prop_oneof![
            Just("build".to_string()),
            Just("check".to_string()),
            Just("test".to_string()),
            Just("clippy".to_string()),
        ],
    ) {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let mut tokens = vec!["env".to_string()];
        for (key, value) in &extra_envs {
            tokens.push(format!("{key}={value}"));
        }
        tokens.push(format!("CARGO_TARGET_DIR={target_dir}"));
        tokens.push("cargo".to_string());
        tokens.push(cargo_subcommand);
        tokens.push("--release".to_string());

        let command = join_exec_command(&tokens);
        let parsed = parse_command_tokens(&command, &reporter).expect("joined command should parse");
        prop_assert_eq!(&parsed, &tokens);
        prop_assert_eq!(
            extract_cargo_target_dir_from_command_tokens(&parsed),
            Some(target_dir.clone())
        );

        let invocation_cwd = Path::new("/tmp/rch-proptest-project");
        let resolved = resolve_forwarded_cargo_target_dir_with_lookup(
            Some(CompilationKind::CargoBuild),
            invocation_cwd,
            &reporter,
            |_| Some("/tmp/ambient-target".to_string()),
            Some(&parsed),
        );
        let expected_resolved = Some(invocation_cwd.join(&target_dir));
        prop_assert_eq!(resolved.as_ref(), expected_resolved.as_ref());

        let rewritten = rewrite_cargo_target_dir_command_for_remote(
            &command,
            Some(&parsed),
            resolved.as_ref(),
            &reporter,
        );
        prop_assert!(!rewritten.contains("CARGO_TARGET_DIR="));
        let rewritten_tokens = parse_command_tokens(&rewritten, &reporter)
            .expect("rewritten command should remain parseable");
        prop_assert_eq!(rewritten_tokens.first().map(String::as_str), Some("env"));
        for (key, value) in &extra_envs {
            let expected_assignment = format!("{key}={value}");
            prop_assert!(
                rewritten_tokens.contains(&expected_assignment),
                "rewritten command dropped env assignment {expected_assignment:?}"
            );
        }
        prop_assert!(rewritten_tokens.iter().any(|token| token == "cargo"));
    }

    #[test]
    fn env_prefix_helpers_do_not_panic_on_arbitrary_command_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..192),
    ) {
        let _guard = test_guard!();
        let reporter = HookReporter::new(OutputVisibility::Verbose);
        let command = String::from_utf8_lossy(&bytes).into_owned();

        if let Some(tokens) = parse_command_tokens(&command, &reporter) {
            let _ = extract_cargo_target_dir_from_command_tokens(&tokens);
            let _ = strip_cargo_target_dir_assignments_from_command_tokens(&tokens);
            let _ = strip_cargo_target_dir_flags_from_command_tokens(&tokens);

            let rewritten = rewrite_cargo_target_dir_command_for_remote(
                &command,
                Some(&tokens),
                Some(&PathBuf::from("/tmp/rch-proptest-target")),
                &reporter,
            );
            prop_assert!(
                parse_command_tokens(&rewritten, &reporter).is_some(),
                "parsed command rewrote to an unparsable command: {rewritten:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_collect_repo_updater_roots_and_specs_filters_to_git_roots_with_origin() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
    let with_origin = temp_dir.path().join("with_origin");
    let duplicate_origin = temp_dir.path().join("duplicate_origin");
    let without_origin = temp_dir.path().join("without_origin");
    let not_git = temp_dir.path().join("not_git");

    std::fs::create_dir_all(&with_origin).expect("create with_origin");
    std::fs::create_dir_all(&duplicate_origin).expect("create duplicate_origin");
    std::fs::create_dir_all(&without_origin).expect("create without_origin");
    std::fs::create_dir_all(&not_git).expect("create not_git");

    for repo in [&with_origin, &duplicate_origin, &without_origin] {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("init")
            .arg("-q")
            .status()
            .expect("git init should run");
        assert!(
            status.success(),
            "git init should succeed for {}",
            repo.display()
        );
    }

    let origin_url = "git@github.com:example/repo-with-origin.git";
    for repo in [&with_origin, &duplicate_origin] {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("remote")
            .arg("add")
            .arg("origin")
            .arg(origin_url)
            .status()
            .expect("git remote add should run");
        assert!(
            status.success(),
            "git remote add should succeed for {}",
            repo.display()
        );
    }

    let collected = collect_repo_updater_roots_and_specs(&[
        with_origin.clone(),
        without_origin.clone(),
        not_git.clone(),
        duplicate_origin.clone(),
    ])
    .await;

    assert_eq!(
        collected.roots,
        vec![with_origin.clone(), duplicate_origin.clone()]
    );
    assert_eq!(collected.specs, vec![origin_url.to_string()]);
}

#[test]
fn test_auto_tune_repo_updater_contract_autoseeds_allowlist_and_mode() {
    let _guard = test_guard!();
    let mut contract = RepoUpdaterAdapterContract::default();
    let repo_specs = vec!["github.com/example/repo".to_string()];
    let auth_context = RepoUpdaterAuthContext {
        source: RepoUpdaterCredentialSource::SshAgent,
        credential_id: "ssh-agent".to_string(),
        issued_at_unix_ms: 1_700_000_000_000,
        expires_at_unix_ms: 1_700_000_060_000,
        granted_scopes: vec![],
        revoked: false,
        verified_hosts: vec![],
    };
    let reporter = HookReporter::new(OutputVisibility::None);

    auto_tune_repo_updater_contract(
        &mut contract,
        &repo_specs,
        Some(&auth_context),
        false,
        false,
        &reporter,
    );

    assert_eq!(contract.trust_policy.allowlisted_repo_specs, repo_specs);
    assert_eq!(
        contract.auth_policy.mode,
        RepoUpdaterAuthMode::InheritEnvironment
    );
}

#[test]
fn test_hydrate_repo_updater_auth_context_defaults_populates_required_fields() {
    let _guard = test_guard!();
    let contract = RepoUpdaterAdapterContract::default();
    let now_ms = 1_700_000_000_000_i64;
    let mut auth_context = RepoUpdaterAuthContext {
        source: RepoUpdaterCredentialSource::TokenEnv,
        credential_id: String::new(),
        issued_at_unix_ms: 0,
        expires_at_unix_ms: 0,
        granted_scopes: vec![],
        revoked: false,
        verified_hosts: vec![],
    };

    hydrate_repo_updater_auth_context_defaults(&mut auth_context, now_ms, &contract);

    assert_eq!(auth_context.credential_id, "token-env");
    assert!(auth_context.issued_at_unix_ms > 0);
    assert!(auth_context.issued_at_unix_ms <= now_ms);
    assert!(auth_context.expires_at_unix_ms > now_ms);
    assert_eq!(
        auth_context.granted_scopes,
        contract.auth_policy.required_scopes
    );
    assert_eq!(
        auth_context.verified_hosts.len(),
        contract.auth_policy.trusted_host_identities.len()
    );
}

#[test]
fn test_infer_repo_updater_auth_context_returns_none_without_local_auth() {
    let _guard = test_guard!();
    assert!(
        infer_repo_updater_auth_context_with_env_lookup(1_700_000_000_000, |_| false).is_none()
    );
}

#[test]
fn test_infer_repo_updater_auth_context_uses_token_env_when_present() {
    let _guard = test_guard!();
    let auth_context =
        infer_repo_updater_auth_context_with_env_lookup(1_700_000_000_000, |key| key == "GH_TOKEN")
            .expect("token env should infer auth context");
    assert_eq!(auth_context.source, RepoUpdaterCredentialSource::TokenEnv);
    assert_eq!(auth_context.credential_id, "env:GH_TOKEN");
    assert_eq!(auth_context.granted_scopes, vec!["repo:read".to_string()]);
}

#[test]
fn test_repo_updater_command_name_is_stable() {
    let _guard = test_guard!();
    assert_eq!(
        repo_updater_command_name(RepoUpdaterAdapterCommand::SyncApply),
        "sync-apply"
    );
    assert_eq!(
        repo_updater_command_name(RepoUpdaterAdapterCommand::SyncDryRun),
        "sync-dry-run"
    );
    assert_eq!(
        repo_updater_command_name(RepoUpdaterAdapterCommand::StatusNoFetch),
        "status-no-fetch"
    );
}

#[test]
fn test_build_repo_sync_idempotency_key_for_command_distinguishes_commands() {
    let _guard = test_guard!();
    let worker_id = WorkerId::new("worker-a");
    let sync_roots = vec![
        PathBuf::from("/data/projects/repo-a"),
        PathBuf::from("/data/projects/repo-b"),
    ];

    let apply_key = build_repo_sync_idempotency_key_for_command(
        &worker_id,
        &sync_roots,
        RepoUpdaterAdapterCommand::SyncApply,
    );
    let dry_run_key = build_repo_sync_idempotency_key_for_command(
        &worker_id,
        &sync_roots,
        RepoUpdaterAdapterCommand::SyncDryRun,
    );
    let status_key = build_repo_sync_idempotency_key_for_command(
        &worker_id,
        &sync_roots,
        RepoUpdaterAdapterCommand::StatusNoFetch,
    );

    assert_ne!(apply_key, dry_run_key);
    assert_ne!(dry_run_key, status_key);
    assert_ne!(apply_key, status_key);
    assert!(apply_key.starts_with("rch-repo-sync-"));
}

#[test]
fn test_build_remote_dependency_preflight_command_empty_roots() {
    let _guard = test_guard!();
    assert!(build_remote_dependency_preflight_command(&[]).is_none());
}

#[test]
fn test_build_remote_dependency_preflight_command_separates_checks() {
    let _guard = test_guard!();
    let checks = vec![
        DependencyPreflightCheck {
            root: "/data/projects/repo-a".to_string(),
            manifest: "/data/projects/repo-a/Cargo.toml".to_string(),
            required_path: "/data/projects/repo-a/Cargo.toml".to_string(),
            required_kind: "manifest",
            is_primary: true,
        },
        DependencyPreflightCheck {
            root: "/data/projects/repo-b".to_string(),
            manifest: "/data/projects/repo-b/Cargo.toml".to_string(),
            required_path: "/data/projects/repo-b/src/lib.rs".to_string(),
            required_kind: "source_entrypoint",
            is_primary: false,
        },
    ];

    let command =
        build_remote_dependency_preflight_command(&checks).expect("command should be constructed");

    assert!(
        command.contains("for required in "),
        "generated command must batch paths through one bounded shell loop"
    );
    assert!(
        !command.contains("fi if ["),
        "generated command must not concatenate checks without separator"
    );
    assert!(
        command.contains("RCH_DEP_PRESENT:"),
        "generated command must emit structured present marker"
    );
    assert!(
        command.contains("RCH_DEP_MISSING:"),
        "generated command must emit structured missing marker"
    );
}

#[test]
fn test_build_remote_dependency_preflight_commands_batches_large_workspaces() {
    let _guard = test_guard!();
    let checks = (0..=DEPENDENCY_PREFLIGHT_PROBE_BATCH_SIZE)
        .map(|idx| DependencyPreflightCheck {
            root: "/data/projects/big".to_string(),
            manifest: "/data/projects/big/Cargo.toml".to_string(),
            required_path: format!("/data/projects/big/tests/case_{idx}.rs"),
            required_kind: "source_entrypoint",
            is_primary: true,
        })
        .collect::<Vec<_>>();

    let commands = build_remote_dependency_preflight_commands(&checks);

    assert_eq!(
        commands.len(),
        2,
        "one more than the batch size must be split into two SSH commands"
    );
    assert!(commands[0].contains("/data/projects/big/tests/case_127.rs"));
    assert!(!commands[0].contains("/data/projects/big/tests/case_128.rs"));
    assert!(commands[1].contains("/data/projects/big/tests/case_128.rs"));
}

#[test]
fn test_synced_dependency_preflight_checks_use_remote_paths() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let package_root = temp_dir.path().join("package");
    std::fs::create_dir_all(package_root.join("src")).expect("create package src");
    std::fs::write(
        package_root.join("Cargo.toml"),
        r#"[package]
name = "package"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write manifest");
    std::fs::write(package_root.join("src/lib.rs"), "pub fn package() {}\n").expect("write lib");

    let root_outcomes = vec![
        (
            SyncClosurePlanEntry {
                local_root: package_root,
                remote_root: "/data/projects/frankenterm".to_string(),
                project_id: "frankenterm".to_string(),
                root_hash: "hash-primary".to_string(),
                is_primary: true,
                mode: SyncClosureMode::Full,
            },
            SyncRootOutcome::Synced,
        ),
        (
            SyncClosurePlanEntry {
                local_root: PathBuf::from("/Users/jemanuel/projects/frankentui"),
                remote_root: "/data/projects/frankentui".to_string(),
                project_id: "frankentui".to_string(),
                root_hash: "hash-dep".to_string(),
                is_primary: false,
                mode: SyncClosureMode::Full,
            },
            SyncRootOutcome::Failed {
                error: "no sync".to_string(),
            },
        ),
    ];

    let synced = synced_dependency_preflight_checks(&root_outcomes);
    let required_paths = synced
        .iter()
        .map(|check| check.required_path.as_str())
        .collect::<Vec<_>>();
    assert!(required_paths.contains(&"/data/projects/frankenterm/Cargo.toml"));
    assert!(required_paths.contains(&"/data/projects/frankenterm/src/lib.rs"));
    assert!(
        !required_paths
            .iter()
            .any(|path| path.starts_with("/data/projects/frankentui")),
        "failed roots must not be probed as freshly synced"
    );
}

#[test]
fn test_parse_dependency_preflight_probe_output_extracts_markers() {
    let _guard = test_guard!();
    let stdout = "\
RCH_DEP_PRESENT:/data/projects/a/Cargo.toml
noise
RCH_DEP_MISSING:/data/projects/b/Cargo.toml
RCH_DEP_PRESENT:/data/projects/c/Cargo.toml
";

    let (present, missing) = parse_dependency_preflight_probe_output(stdout);

    assert_eq!(present.len(), 2);
    assert_eq!(missing.len(), 1);
    assert!(present.contains("/data/projects/a/Cargo.toml"));
    assert!(present.contains("/data/projects/c/Cargo.toml"));
    assert!(missing.contains("/data/projects/b/Cargo.toml"));
}

#[test]
fn test_dependency_preflight_error_codes_match_public_catalog() {
    let _guard = test_guard!();
    assert_eq!(
        DEPENDENCY_PREFLIGHT_CODE_MISSING,
        ErrorCode::DependencyPreflightMissing.code_string().as_str()
    );
    assert_eq!(
        DEPENDENCY_PREFLIGHT_CODE_STALE,
        ErrorCode::DependencyPreflightStale.code_string().as_str()
    );
    assert_eq!(
        DEPENDENCY_PREFLIGHT_CODE_UNKNOWN,
        ErrorCode::DependencyPreflightUnknown.code_string().as_str()
    );
    assert_eq!(
        DEPENDENCY_PREFLIGHT_CODE_POLICY,
        ErrorCode::DependencyPreflightPolicyViolation
            .code_string()
            .as_str()
    );
    assert_eq!(
        DEPENDENCY_PREFLIGHT_CODE_TIMEOUT,
        ErrorCode::DependencyPreflightTimeout.code_string().as_str()
    );
    assert_ne!(
        DEPENDENCY_PREFLIGHT_CODE_MISSING,
        ErrorCode::CancelSlotLeak.code_string().as_str(),
        "dependency preflight must not reuse the cancellation slot-leak code"
    );
}

fn make_sync_entry(root: &str, is_primary: bool) -> SyncClosurePlanEntry {
    SyncClosurePlanEntry {
        local_root: PathBuf::from(root),
        remote_root: root.to_string(),
        project_id: format!("id-{}", root.replace('/', "_")),
        root_hash: format!("hash-{}", root.replace('/', "_")),
        is_primary,
        mode: SyncClosureMode::Full,
    }
}

fn make_test_worker_config(id: &str) -> WorkerConfig {
    WorkerConfig {
        id: WorkerId::new(id),
        host: "worker.host".to_string(),
        user: "ubuntu".to_string(),
        identity_file: "~/.ssh/id_ed25519".to_string(),
        total_slots: 8,
        priority: 100,
        tags: Vec::new(),
    }
}

fn make_fail_open_plan(
    fail_open_reason: Option<&str>,
    issues: Vec<rch_common::DependencyPlanIssue>,
) -> DependencyClosurePlan {
    DependencyClosurePlan {
        state: rch_common::DependencyClosurePlanState::FailOpen,
        entry_manifest_path: PathBuf::from("/data/projects/example/Cargo.toml"),
        workspace_root: Some(PathBuf::from("/data/projects/example")),
        canonical_roots: Vec::new(),
        sync_order: Vec::new(),
        fail_open: true,
        fail_open_reason: fail_open_reason.map(ToString::to_string),
        issues,
    }
}

#[test]
fn test_classify_dependency_runtime_fail_open_policy_violation() {
    let _guard = test_guard!();
    let plan = make_fail_open_plan(
        Some("resolver produced path policy violation"),
        vec![rch_common::DependencyPlanIssue {
            code: "path-policy-violation".to_string(),
            message: "dependency path escapes canonical root".to_string(),
            risk: rch_common::DependencyRiskClass::High,
            diagnostics: vec!["dependency_path=/tmp/off-policy".to_string()],
        }],
    );

    let decision = classify_dependency_runtime_fail_open(&plan);
    assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_POLICY);
    assert_eq!(
        decision.remediation,
        DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY
    );
}

#[test]
fn test_classify_dependency_runtime_fail_open_timeout_signal() {
    let _guard = test_guard!();
    let plan = make_fail_open_plan(
        Some("cargo metadata timed out after 10s"),
        vec![rch_common::DependencyPlanIssue {
            code: "metadata-invocation-failure".to_string(),
            message: "metadata invocation timed out".to_string(),
            risk: rch_common::DependencyRiskClass::Critical,
            diagnostics: vec!["timeout=10s".to_string()],
        }],
    );

    let decision = classify_dependency_runtime_fail_open(&plan);
    assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_TIMEOUT);
    assert_eq!(
        decision.remediation,
        DEPENDENCY_PREFLIGHT_REMEDIATION_TIMEOUT
    );
}

#[test]
fn test_classify_dependency_runtime_fail_open_defaults_unknown() {
    let _guard = test_guard!();
    let plan = make_fail_open_plan(
        Some("resolver returned unverifiable graph ordering"),
        vec![rch_common::DependencyPlanIssue {
            code: "non-deterministic-order".to_string(),
            message: "graph order could not be proven".to_string(),
            risk: rch_common::DependencyRiskClass::Critical,
            diagnostics: vec!["planner_state=fail_open".to_string()],
        }],
    );

    let decision = classify_dependency_runtime_fail_open(&plan);
    assert_eq!(decision.reason_code, DEPENDENCY_PREFLIGHT_CODE_UNKNOWN);
    assert_eq!(
        decision.remediation,
        DEPENDENCY_PREFLIGHT_REMEDIATION_UNKNOWN
    );
}

#[test]
fn test_build_dependency_runtime_fail_open_report_uses_status_mapping() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-runtime-report");
    let project_root = PathBuf::from("/data/projects/runtime-policy");
    let decision = DependencyRuntimeFailOpenDecision {
        reason_code: DEPENDENCY_PREFLIGHT_CODE_POLICY,
        remediation: DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY,
        detail: "policy violation detail".to_string(),
    };

    let report = build_dependency_runtime_fail_open_report(&worker, &project_root, &decision);
    assert!(!report.verified);
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_POLICY));
    assert_eq!(
        report.remediation,
        Some(DEPENDENCY_PREFLIGHT_REMEDIATION_POLICY)
    );
    assert_eq!(report.evidence.len(), 1);
    assert_eq!(
        report.evidence[0].status,
        DependencyPreflightStatus::PolicyViolation
    );
}

#[test]
fn test_should_force_local_fallback_for_runtime_fail_open_policy_only() {
    let _guard = test_guard!();
    assert!(should_force_local_fallback_for_runtime_fail_open(
        DEPENDENCY_PREFLIGHT_CODE_POLICY
    ));
    assert!(!should_force_local_fallback_for_runtime_fail_open(
        DEPENDENCY_PREFLIGHT_CODE_UNKNOWN
    ));
    assert!(!should_force_local_fallback_for_runtime_fail_open(
        DEPENDENCY_PREFLIGHT_CODE_TIMEOUT
    ));
}

#[test]
fn test_e2e_dependency_preflight_verified_success_path() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-success");
    let entry = make_sync_entry("/data/projects/repo-success", true);
    let manifest = entry
        .local_root
        .join("Cargo.toml")
        .to_string_lossy()
        .to_string();
    let outcomes = vec![(entry, SyncRootOutcome::Synced)];
    let present = std::collections::BTreeSet::from([manifest]);
    let missing = std::collections::BTreeSet::new();

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(report.verified, "all-present manifests should verify");
    assert!(report.reason_code.is_none());
    assert!(report.remediation.is_none());
    assert_eq!(report.evidence.len(), 1);
    assert_eq!(
        report.evidence[0].status,
        DependencyPreflightStatus::Present,
        "evidence must mark synced+present roots as present"
    );
}

#[test]
fn test_build_dependency_preflight_report_uses_remote_manifest_paths() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-remote-paths");
    let entry = SyncClosurePlanEntry {
        local_root: PathBuf::from("/Users/jemanuel/projects/repo-success"),
        remote_root: "/data/projects/repo-success".to_string(),
        project_id: "id-remote-paths".to_string(),
        root_hash: "hash-remote-paths".to_string(),
        is_primary: true,
        mode: SyncClosureMode::Full,
    };
    let outcomes = vec![(entry, SyncRootOutcome::Synced)];
    let present =
        std::collections::BTreeSet::from([String::from("/data/projects/repo-success/Cargo.toml")]);
    let missing = std::collections::BTreeSet::new();

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(report.verified, "remote manifest markers should verify");
    assert_eq!(report.evidence.len(), 1);
    assert_eq!(
        report.evidence[0].root, "/data/projects/repo-success",
        "evidence should report the remote synced root"
    );
    assert_eq!(
        report.evidence[0].manifest, "/data/projects/repo-success/Cargo.toml",
        "manifest matching must use remote paths from the probe"
    );
    assert_eq!(
        report.evidence[0].status,
        DependencyPreflightStatus::Present
    );
}

#[test]
fn test_build_dependency_preflight_report_missing_stale_and_unknown_paths() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-mixed");
    // Use is_primary: true so the missing status triggers blocking.
    let synced_missing = make_sync_entry("/data/projects/repo-missing", true);
    let skipped_stale = make_sync_entry("/data/projects/repo-stale", false);
    let failed_unknown = make_sync_entry("/data/projects/repo-unknown", false);
    let missing_manifest = synced_missing
        .local_root
        .join("Cargo.toml")
        .to_string_lossy()
        .to_string();
    let outcomes = vec![
        (synced_missing, SyncRootOutcome::Synced),
        (
            skipped_stale,
            SyncRootOutcome::Skipped {
                reason: "transfer skipped by estimator".to_string(),
            },
        ),
        (
            failed_unknown,
            SyncRootOutcome::Failed {
                error: "rsync timeout".to_string(),
            },
        ),
    ];
    let present = std::collections::BTreeSet::new();
    let missing = std::collections::BTreeSet::from([missing_manifest]);

    let report = build_dependency_preflight_report(
        &worker,
        &outcomes,
        &present,
        &missing,
        Some("probe returned missing markers"),
    );

    assert!(
        !report.verified,
        "missing primary root evidence must block remote execution"
    );
    assert_eq!(
        report.reason_code,
        Some(DEPENDENCY_PREFLIGHT_CODE_MISSING),
        "missing primary should dominate failure reason"
    );
    assert_eq!(
        report.remediation,
        Some(DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|item| item.status == DependencyPreflightStatus::Missing)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|item| item.status == DependencyPreflightStatus::Stale)
    );
    assert!(
        report
            .evidence
            .iter()
            .any(|item| item.status == DependencyPreflightStatus::Unknown)
    );
}

#[test]
fn test_e2e_dependency_preflight_stale_fallback_path_maps_reason_code() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-stale");
    // Use is_primary: true so stale status triggers blocking.
    let stale_entry = make_sync_entry("/data/projects/repo-stale-only", true);
    let outcomes = vec![(
        stale_entry,
        SyncRootOutcome::Skipped {
            reason: "bandwidth guard skip".to_string(),
        },
    )];
    let present = std::collections::BTreeSet::new();
    let missing = std::collections::BTreeSet::new();

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(!report.verified);
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_STALE));
    assert_eq!(
        report.remediation,
        Some(DEPENDENCY_PREFLIGHT_REMEDIATION_STALE)
    );
}

#[test]
fn test_e2e_dependency_preflight_missing_fallback_path_maps_reason_code() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-missing");
    // Use is_primary: true so missing status triggers blocking.
    let entry = make_sync_entry("/data/projects/repo-missing-only", true);
    let manifest = entry
        .local_root
        .join("Cargo.toml")
        .to_string_lossy()
        .to_string();
    let outcomes = vec![(entry, SyncRootOutcome::Synced)];
    let present = std::collections::BTreeSet::new();
    let missing = std::collections::BTreeSet::from([manifest]);

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(!report.verified);
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
    assert_eq!(
        report.remediation,
        Some(DEPENDENCY_PREFLIGHT_REMEDIATION_MISSING)
    );
}

#[test]
fn test_cargo_package_source_entrypoints_include_auto_discovered_targets() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let package_root = temp_dir.path().join("auto-targets");
    for dir in [
        "src",
        "src/bin/nested",
        "examples/demo",
        "tests/integration",
        "benches/speed",
    ] {
        std::fs::create_dir_all(package_root.join(dir)).expect("create target dir");
    }
    std::fs::write(
        package_root.join("Cargo.toml"),
        r#"[package]
name = "auto-targets"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write manifest");
    for path in [
        "src/lib.rs",
        "src/main.rs",
        "src/bin/tool.rs",
        "src/bin/nested/main.rs",
        "examples/example.rs",
        "examples/demo/main.rs",
        "tests/integration.rs",
        "tests/integration/main.rs",
        "benches/speed.rs",
        "benches/speed/main.rs",
    ] {
        std::fs::write(package_root.join(path), "fn main() {}\n").expect("write entrypoint");
    }

    let entrypoints = cargo_package_source_entrypoints(&package_root);

    for path in [
        "src/lib.rs",
        "src/main.rs",
        "src/bin/tool.rs",
        "src/bin/nested/main.rs",
        "examples/example.rs",
        "examples/demo/main.rs",
        "tests/integration.rs",
        "tests/integration/main.rs",
        "benches/speed.rs",
        "benches/speed/main.rs",
    ] {
        assert!(
            entrypoints.contains(&PathBuf::from(path)),
            "missing auto-discovered entrypoint {path}"
        );
    }
}

#[test]
fn test_cargo_package_source_entrypoints_respect_auto_discovery_flags() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let package_root = temp_dir.path().join("manual-targets");
    for dir in ["src/bin", "examples", "tests", "benches", "custom"] {
        std::fs::create_dir_all(package_root.join(dir)).expect("create target dir");
    }
    std::fs::write(
        package_root.join("Cargo.toml"),
        r#"[package]
name = "manual-targets"
version = "0.1.0"
edition = "2024"
autolib = false
autobins = false
autoexamples = false
autotests = false
autobenches = false

[lib]
path = "custom/lib.rs"

[[bin]]
path = "custom/bin.rs"
"#,
    )
    .expect("write manifest");
    for path in [
        "src/lib.rs",
        "src/main.rs",
        "src/bin/tool.rs",
        "examples/example.rs",
        "tests/integration.rs",
        "benches/speed.rs",
        "custom/lib.rs",
        "custom/bin.rs",
    ] {
        std::fs::write(package_root.join(path), "fn main() {}\n").expect("write entrypoint");
    }

    let entrypoints = cargo_package_source_entrypoints(&package_root);

    assert_eq!(
        entrypoints,
        vec![
            PathBuf::from("custom/bin.rs"),
            PathBuf::from("custom/lib.rs")
        ]
    );
}

#[test]
fn test_workspace_member_source_entrypoints_include_all_targets_and_exclusions() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let workspace_root = temp_dir.path().join("workspace");

    for dir in [
        "crates/core/src",
        "crates/core/benches",
        "crates/core/examples",
        "crates/atlas-types/src",
        "crates/skipped/src",
        "tools/cli/src",
    ] {
        std::fs::create_dir_all(workspace_root.join(dir)).expect("create workspace dir");
    }
    std::fs::write(
        workspace_root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/*", "tools/cli"]
exclude = ["crates/skipped"]
"#,
    )
    .expect("write workspace manifest");
    for (manifest, name) in [
        ("crates/core/Cargo.toml", "core"),
        ("crates/atlas-types/Cargo.toml", "atlas-types"),
        ("crates/skipped/Cargo.toml", "skipped"),
        ("tools/cli/Cargo.toml", "cli"),
    ] {
        std::fs::write(
            workspace_root.join(manifest),
            format!(
                r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
"#
            ),
        )
        .expect("write member manifest");
    }
    for path in [
        "crates/core/src/lib.rs",
        "crates/core/benches/interval_tree_bench.rs",
        "crates/core/examples/atlas_packing_attestation.rs",
        "crates/atlas-types/src/lib.rs",
        "crates/skipped/src/lib.rs",
        "tools/cli/src/lib.rs",
    ] {
        std::fs::write(workspace_root.join(path), "pub fn marker() {}\n")
            .expect("write member entrypoint");
    }

    let entrypoints = cargo_workspace_member_source_entrypoints(&workspace_root);

    for path in [
        "crates/core/Cargo.toml",
        "crates/core/src/lib.rs",
        "crates/core/benches/interval_tree_bench.rs",
        "crates/core/examples/atlas_packing_attestation.rs",
        "crates/atlas-types/Cargo.toml",
        "crates/atlas-types/src/lib.rs",
        "tools/cli/Cargo.toml",
        "tools/cli/src/lib.rs",
    ] {
        assert!(
            entrypoints.contains(&PathBuf::from(path)),
            "missing workspace member entrypoint {path}"
        );
    }
    assert!(
        !entrypoints
            .iter()
            .any(|path| path.starts_with("crates/skipped")),
        "workspace exclude entries must not be preflighted"
    );
}

#[test]
fn test_dependency_preflight_checks_expand_virtual_workspace_all_targets() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let workspace_root = temp_dir.path().join("frankenterm");

    for dir in [
        "crates/frankenterm-core/src",
        "crates/frankenterm-core/benches",
        "crates/frankenterm-core/examples",
        "crates/frankenterm-core-atlas-pack-types/src",
        "crates/frankenterm-core-connectors/src",
        "crates/skipped/src",
    ] {
        std::fs::create_dir_all(workspace_root.join(dir)).expect("create workspace dir");
    }
    std::fs::write(
        workspace_root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/frankenterm-core", "crates/frankenterm-core-*", "crates/skipped"]
exclude = ["crates/skipped"]
"#,
    )
    .expect("write workspace manifest");
    for (manifest, name) in [
        ("crates/frankenterm-core/Cargo.toml", "frankenterm-core"),
        (
            "crates/frankenterm-core-atlas-pack-types/Cargo.toml",
            "frankenterm-core-atlas-pack-types",
        ),
        (
            "crates/frankenterm-core-connectors/Cargo.toml",
            "frankenterm-core-connectors",
        ),
        ("crates/skipped/Cargo.toml", "skipped"),
    ] {
        std::fs::write(
            workspace_root.join(manifest),
            format!(
                r#"[package]
name = "{name}"
version = "0.1.0"
edition = "2024"
"#
            ),
        )
        .expect("write member manifest");
    }
    for path in [
        "crates/frankenterm-core/src/lib.rs",
        "crates/frankenterm-core/benches/interval_tree_bench.rs",
        "crates/frankenterm-core/examples/atlas_packing_attestation.rs",
        "crates/frankenterm-core-atlas-pack-types/src/lib.rs",
        "crates/frankenterm-core-connectors/src/lib.rs",
        "crates/skipped/src/lib.rs",
    ] {
        std::fs::write(workspace_root.join(path), "pub fn marker() {}\n")
            .expect("write member entrypoint");
    }
    let entry = SyncClosurePlanEntry {
        local_root: workspace_root,
        remote_root: "/data/projects/frankenterm".to_string(),
        project_id: "frankenterm".to_string(),
        root_hash: "frankenterm-hash".to_string(),
        is_primary: true,
        mode: SyncClosureMode::Full,
    };

    let checks = dependency_preflight_checks_for_entry(&entry);
    let required_paths = checks
        .iter()
        .map(|check| check.required_path.as_str())
        .collect::<std::collections::BTreeSet<_>>();

    for path in [
        "/data/projects/frankenterm/Cargo.toml",
        "/data/projects/frankenterm/crates/frankenterm-core/Cargo.toml",
        "/data/projects/frankenterm/crates/frankenterm-core/src/lib.rs",
        "/data/projects/frankenterm/crates/frankenterm-core/benches/interval_tree_bench.rs",
        "/data/projects/frankenterm/crates/frankenterm-core/examples/atlas_packing_attestation.rs",
        "/data/projects/frankenterm/crates/frankenterm-core-atlas-pack-types/src/lib.rs",
        "/data/projects/frankenterm/crates/frankenterm-core-connectors/src/lib.rs",
    ] {
        assert!(
            required_paths.contains(path),
            "missing dependency preflight check for {path}"
        );
    }
    assert!(
        !required_paths
            .iter()
            .any(|path| path.contains("/crates/skipped/")),
        "workspace excluded members must not be preflighted"
    );
}

#[test]
fn test_dependency_preflight_blocks_missing_source_entrypoint() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-missing-source");
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let package_root = temp_dir.path().join("member");
    std::fs::create_dir_all(package_root.join("src")).expect("create src");
    std::fs::write(
        package_root.join("Cargo.toml"),
        r#"[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write manifest");
    std::fs::write(package_root.join("src/lib.rs"), "pub fn member() {}\n").expect("write lib");
    let entry = SyncClosurePlanEntry {
        local_root: package_root,
        remote_root: "/data/projects/app/crates/member".to_string(),
        project_id: "member".to_string(),
        root_hash: "member-hash".to_string(),
        is_primary: false,
        mode: SyncClosureMode::Full,
    };
    let outcomes = vec![(entry, SyncRootOutcome::Synced)];
    let present = std::collections::BTreeSet::from([String::from(
        "/data/projects/app/crates/member/Cargo.toml",
    )]);
    let missing = std::collections::BTreeSet::from([String::from(
        "/data/projects/app/crates/member/src/lib.rs",
    )]);

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(
        !report.verified,
        "a synced root with a missing package source entrypoint must not reach Cargo"
    );
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
    assert!(report.evidence.iter().any(|item| {
        item.required_kind == "source_entrypoint"
            && item.required_path == "/data/projects/app/crates/member/src/lib.rs"
            && item.status == DependencyPreflightStatus::Missing
    }));
    let failure = DependencyPreflightFailure::from_report(report);
    let summary = failure.evidence_summary();
    assert!(
        summary.contains("/data/projects/app/crates/member/src/lib.rs"),
        "summary should expose the missing path, got {summary}"
    );
    assert!(
        summary.contains("missing source_entrypoint"),
        "summary should expose the failure class and path kind, got {summary}"
    );
}

#[test]
fn test_dependency_preflight_probe_failure_compacts_unknown_source_entrypoints() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-probe-reset");
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let package_root = temp_dir.path().join("large-member");
    std::fs::create_dir_all(package_root.join("src")).expect("create src");
    std::fs::create_dir_all(package_root.join("tests")).expect("create tests");
    std::fs::write(
        package_root.join("Cargo.toml"),
        r#"[package]
name = "large-member"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write manifest");
    std::fs::write(package_root.join("src/lib.rs"), "pub fn member() {}\n").expect("write lib");
    for idx in 0..150 {
        std::fs::write(
            package_root.join("tests").join(format!("case_{idx}.rs")),
            "#[test]\nfn case() {}\n",
        )
        .expect("write test entrypoint");
    }
    let entry = SyncClosurePlanEntry {
        local_root: package_root,
        remote_root: "/data/projects/app/crates/large-member".to_string(),
        project_id: "large-member".to_string(),
        root_hash: "large-member-hash".to_string(),
        is_primary: false,
        mode: SyncClosureMode::Full,
    };
    let outcomes = vec![(entry, SyncRootOutcome::Synced)];
    let present = std::collections::BTreeSet::new();
    let missing = std::collections::BTreeSet::new();

    let report = build_dependency_preflight_report(
        &worker,
        &outcomes,
        &present,
        &missing,
        Some("probe exited with status Some(255); connection reset"),
    );

    assert!(!report.verified);
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_UNKNOWN));
    let unknown_source_entrypoints = report
        .evidence
        .iter()
        .filter(|item| {
            item.status == DependencyPreflightStatus::Unknown
                && item.required_kind == "source_entrypoint"
        })
        .collect::<Vec<_>>();
    assert_eq!(
        unknown_source_entrypoints.len(),
        1,
        "transport failures should keep one sample per root/kind instead of duplicating every source entrypoint"
    );
    assert!(
        unknown_source_entrypoints[0]
            .detail
            .contains("additional unreported paths"),
        "unknown sample should explain why the report is compacted"
    );
    assert!(
        report.evidence.len() < 10,
        "large all-unknown reports should be compact, got {} evidence rows",
        report.evidence.len()
    );
}

#[tokio::test]
async fn test_verify_remote_dependency_manifests_blocks_stale_outcomes_deterministically() {
    let _guard = test_guard!();
    // Disable mock mode so verify_remote_dependency_manifests reaches
    // the preflight report logic instead of short-circuiting.
    mock::set_thread_mock_override(Some(false));
    let worker = make_test_worker_config("worker-stale-verify");
    // Use is_primary: true so stale status triggers blocking.
    let outcomes = vec![(
        make_sync_entry("/data/projects/repo-stale-verify", true),
        SyncRootOutcome::Skipped {
            reason: "transfer budget skip".to_string(),
        },
    )];
    let reporter = HookReporter::new(OutputVisibility::Verbose);

    let err = verify_remote_dependency_manifests(&worker, &outcomes, &reporter)
        .await
        .expect_err("stale dependency evidence should block remote execution");
    let preflight = err
        .downcast_ref::<DependencyPreflightFailure>()
        .expect("error should preserve DependencyPreflightFailure type");
    assert_eq!(preflight.reason_code, DEPENDENCY_PREFLIGHT_CODE_STALE);
    assert_eq!(
        preflight.remediation,
        DEPENDENCY_PREFLIGHT_REMEDIATION_STALE
    );
    mock::set_thread_mock_override(None);
}

#[test]
fn test_non_primary_missing_deps_block_preflight() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-non-primary");
    let primary = make_sync_entry("/data/projects/main-project", true);
    let dep = make_sync_entry("/data/projects/sibling-dep", false);
    let primary_manifest = primary
        .local_root
        .join("Cargo.toml")
        .to_string_lossy()
        .to_string();
    let dep_manifest = dep
        .local_root
        .join("Cargo.toml")
        .to_string_lossy()
        .to_string();

    let outcomes = vec![
        (primary, SyncRootOutcome::Synced),
        (dep, SyncRootOutcome::Synced),
    ];
    let present = std::collections::BTreeSet::from([primary_manifest]);
    let missing = std::collections::BTreeSet::from([dep_manifest]);

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(
        !report.verified,
        "non-primary missing dep must block preflight to avoid stale sibling builds"
    );
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_MISSING));
}

#[test]
fn test_non_primary_stale_deps_block_preflight() {
    let _guard = test_guard!();
    let worker = make_test_worker_config("worker-non-primary-stale");
    let primary = make_sync_entry("/data/projects/main-project", true);
    let dep = make_sync_entry("/data/projects/sibling-dep-stale", false);
    let primary_manifest = primary
        .local_root
        .join("Cargo.toml")
        .to_string_lossy()
        .to_string();

    let outcomes = vec![
        (primary, SyncRootOutcome::Synced),
        (
            dep,
            SyncRootOutcome::Skipped {
                reason: "estimator skip".to_string(),
            },
        ),
    ];
    let present = std::collections::BTreeSet::from([primary_manifest]);
    let missing = std::collections::BTreeSet::new();

    let report = build_dependency_preflight_report(&worker, &outcomes, &present, &missing, None);

    assert!(
        !report.verified,
        "non-primary stale dep must block preflight to avoid stale sibling builds"
    );
    assert_eq!(report.reason_code, Some(DEPENDENCY_PREFLIGHT_CODE_STALE));
}

#[test]
fn test_build_sync_closure_plan_deterministic_under_permutation() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep_a = temp_dir.path().join("dep_a");
    let dep_b = temp_dir.path().join("dep_b");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep_a).expect("create dep_a");
    std::fs::create_dir_all(&dep_b).expect("create dep_b");

    let project_hash = "1234abcd";
    let plan_a = build_sync_closure_plan(
        &[dep_b.clone(), project_root.clone(), dep_a.clone()],
        &project_root,
        project_hash,
        &policy,
    );
    let plan_b = build_sync_closure_plan(
        &[dep_a.clone(), dep_b.clone(), project_root.clone()],
        &project_root,
        project_hash,
        &policy,
    );

    assert_eq!(plan_a, plan_b, "sync closure plan should be deterministic");
    assert!(
        plan_a
            .iter()
            .any(|entry| entry.is_primary && entry.root_hash == project_hash),
        "primary root must retain the closure hash"
    );
}

#[cfg(unix)]
#[test]
fn test_build_sync_closure_plan_dedupes_alias_entries() {
    let _guard = test_guard!();
    use std::os::unix::fs::symlink;

    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep = temp_dir.path().join("dep");
    let dep_alias = temp_dir.path().join("dep_alias");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep).expect("create dep root");
    symlink(&dep, &dep_alias).expect("create dep alias symlink");

    let dep_canonical = std::fs::canonicalize(&dep).expect("canonicalize dep");
    let plan = build_sync_closure_plan(
        &[dep_alias.clone(), dep.clone(), project_root.clone()],
        &project_root,
        "beefcafe",
        &policy,
    );

    let dep_entries = plan
        .iter()
        .filter(|entry| {
            std::fs::canonicalize(&entry.local_root)
                .map(|canonical| canonical == dep_canonical)
                .unwrap_or(false)
        })
        .count();
    assert_eq!(dep_entries, 1, "alias/canonical roots should deduplicate");
}

#[test]
fn test_build_sync_closure_plan_adds_workspace_metadata_for_member_roots() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep_workspace_root = temp_dir.path().join("dep_workspace");
    let dep_member_root = dep_workspace_root.join("crates/member");

    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep_member_root).expect("create member root");
    std::fs::write(
        dep_workspace_root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/member"]
"#,
    )
    .expect("write workspace manifest");
    std::fs::write(
        dep_member_root.join("Cargo.toml"),
        r#"[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write member manifest");

    let plan = build_sync_closure_plan(
        &[dep_member_root.clone(), project_root.clone()],
        &project_root,
        "workspace_hash",
        &policy,
    );

    assert!(
        plan.iter().any(|entry| entry.local_root == dep_member_root
            && entry.mode == SyncClosureMode::Full
            && !entry.is_primary),
        "workspace member root should remain a full sync root"
    );
    assert!(
        plan.iter()
            .any(|entry| entry.local_root == dep_workspace_root
                && entry.mode == SyncClosureMode::WorkspaceMetadata
                && !entry.is_primary),
        "workspace member roots should add a thin workspace metadata sync"
    );
    assert!(
        !plan
            .iter()
            .any(|entry| entry.local_root == dep_workspace_root
                && entry.mode == SyncClosureMode::Full),
        "workspace root should not become a full sync root unless it was explicitly requested"
    );
}

#[test]
fn test_build_dependency_runtime_plan_keeps_workspace_member_roots() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep_workspace_root = temp_dir.path().join("dep_workspace");
    let dep_member_root = dep_workspace_root.join("crates/member");

    std::fs::create_dir_all(project_root.join("src")).expect("create project src");
    std::fs::create_dir_all(dep_member_root.join("src")).expect("create member src");
    std::fs::write(
        project_root.join("Cargo.toml"),
        r#"[package]
name = "project"
version = "0.1.0"
edition = "2024"

[dependencies]
member = { path = "../dep_workspace/crates/member" }
"#,
    )
    .expect("write project manifest");
    std::fs::write(project_root.join("src/lib.rs"), "pub fn project() {}\n")
        .expect("write project lib");
    std::fs::write(
        dep_workspace_root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/member"]
"#,
    )
    .expect("write workspace manifest");
    std::fs::write(
        dep_member_root.join("Cargo.toml"),
        r#"[package]
name = "member"
version = "0.1.0"
edition = "2024"
"#,
    )
    .expect("write member manifest");
    std::fs::write(dep_member_root.join("src/lib.rs"), "pub fn member() {}\n")
        .expect("write member lib");

    let project_root = std::fs::canonicalize(&project_root).expect("canonicalize project");
    let dep_workspace_root =
        std::fs::canonicalize(&dep_workspace_root).expect("canonicalize workspace");
    let dep_member_root = std::fs::canonicalize(&dep_member_root).expect("canonicalize member");
    let reporter = HookReporter::new(OutputVisibility::None);

    let plan = build_dependency_runtime_plan(
        &project_root,
        Some(CompilationKind::CargoCheck),
        &reporter,
        &policy,
    );

    assert!(
        plan.fail_open_decision.is_none(),
        "dependency runtime planning should stay on the ready path"
    );
    assert!(
        plan.sync_roots.contains(&dep_member_root),
        "workspace member root must stay in the runtime sync roots"
    );
    assert!(
        !plan.sync_roots.contains(&dep_workspace_root),
        "workspace root should be added later as metadata-only sync, not full runtime root"
    );
    assert!(
        plan.sync_roots.contains(&project_root),
        "primary project root must remain in the sync roots"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_execute_remote_compilation_syncs_custom_cargo_target_dir_artifacts() {
    let _lock = test_lock().lock().await;
    let _guard = test_guard!();

    let socket_path = format!(
        "/tmp/rch_test_custom_target_artifacts_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    // `execute_remote_compilation` reads the current project root from
    // `std::env::current_dir()` and normalizes it through the supplied
    // topology policy. Pin the cwd to a tempdir and build a policy that
    // recognises it so the test runs anywhere (including CI runners with
    // no `/data/projects`).
    let (temp_dir, policy) = topology_tempdir();
    let project_dir = temp_dir.path().join("remote_compilation_helper");
    std::fs::create_dir_all(&project_dir).expect("create project dir");
    let custom_target_dir_path = project_dir.join(".rch-test-target-cache");
    let custom_target_dir = custom_target_dir_path.to_string_lossy().to_string();

    let prev_cwd = std::env::current_dir().ok();
    std::env::set_current_dir(&project_dir).expect("cd into project dir");

    let worker = SelectedWorker {
        id: rch_common::WorkerId::new("mock-worker"),
        host: "mock.host.local".to_string(),
        user: "mockuser".to_string(),
        identity_file: "~/.ssh/mock_key".to_string(),
        slots_available: 8,
        speed_score: 90.0,
    };

    let reporter = HookReporter::new(OutputVisibility::None);
    let result = execute_remote_compilation(
        &worker,
        "cargo build",
        TransferConfig::default(),
        Vec::new(),
        Some(PathBuf::from(&custom_target_dir)),
        &rch_common::CompilationConfig::default(),
        None,
        Some(CompilationKind::CargoBuild),
        &reporter,
        &socket_path,
        ColorMode::Auto,
        None,
        &policy,
    )
    .await;

    // Restore cwd before any assertion so a failure doesn't poison other tests.
    if let Some(prev) = prev_cwd {
        let _ = std::env::set_current_dir(prev);
    }

    let execution = result.expect("remote execution should succeed in mock mode");
    assert_eq!(execution.exit_code, 0);

    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let custom_target_artifact_sync = rsync_logs
        .iter()
        .find(|entry| {
            entry.phase == mock::Phase::Artifacts
                && entry.destination == custom_target_dir
                && entry.source.contains(".rch-target")
        })
        .expect(
            "expected artifact retrieval into custom CARGO_TARGET_DIR from worker .rch-target path",
        );
    assert!(
        custom_target_artifact_sync
            .source
            .contains(".rch-target-mock-worker-"),
        "expected per-job remote target dir, got {}",
        custom_target_artifact_sync.source
    );
    assert!(
        !custom_target_artifact_sync.source.contains("/.rch-target/"),
        "custom target sync must not use the shared .rch-target dir: {}",
        custom_target_artifact_sync.source
    );

    let ssh_logs = mock::global_ssh_invocations_snapshot();
    let execute_command = ssh_logs
        .iter()
        .find(|entry| entry.phase == mock::Phase::Execute)
        .and_then(|entry| entry.command.as_deref())
        .expect("execute command should be recorded");
    assert!(
        execute_command.contains("CARGO_TARGET_DIR=")
            && execute_command.contains(".rch-target-mock-worker-"),
        "expected remote Cargo execution to force per-job worker CARGO_TARGET_DIR, got {execute_command}"
    );
}

/// Issue #19 Fix 1: a SUCCESSFUL remote compile whose artifacts fail to sync
/// back must NOT report exit 0 for an artifact-producing kind — the local
/// build is incomplete, so the hook returns a non-zero, build-failure-class
/// code. (A test/diagnostic kind, which streams its output and needs no local
/// artifact, still returns the remote exit code on the same failure.)
#[tokio::test]
#[serial(mock_global)]
async fn test_artifact_sync_failure_fails_an_artifact_producing_build() {
    let _lock = test_lock().lock().await;
    let _guard = test_guard!();

    let socket_path = format!(
        "/tmp/rch_test_artifact_fail_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos()
    );

    // Mock SSH succeeds (remote compile exit 0) but rsync artifact retrieval
    // ALWAYS fails — exactly the silent-footgun scenario.
    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::artifact_failure(),
    );
    mock::clear_global_invocations();

    let (temp_dir, policy) = topology_tempdir();
    let project_dir = temp_dir.path().join("remote_compilation_helper");
    std::fs::create_dir_all(&project_dir).expect("create project dir");

    let prev_cwd = std::env::current_dir().ok();
    std::env::set_current_dir(&project_dir).expect("cd into project dir");

    let worker = SelectedWorker {
        id: rch_common::WorkerId::new("mock-worker"),
        host: "mock.host.local".to_string(),
        user: "mockuser".to_string(),
        identity_file: "~/.ssh/mock_key".to_string(),
        slots_available: 8,
        speed_score: 90.0,
    };
    let reporter = HookReporter::new(OutputVisibility::None);

    // Artifact-producing kind (cargo build): a failed sync-back is FATAL.
    let build = execute_remote_compilation(
        &worker,
        "cargo build",
        TransferConfig::default(),
        Vec::new(),
        None,
        &rch_common::CompilationConfig::default(),
        None,
        Some(CompilationKind::CargoBuild),
        &reporter,
        &socket_path,
        ColorMode::Auto,
        None,
        &policy,
    )
    .await;

    // Test kind (cargo test): output streamed, no required artifact — the
    // remote exit code (0) is preserved despite the same artifact failure.
    mock::clear_global_invocations();
    let test_run = execute_remote_compilation(
        &worker,
        "cargo test",
        TransferConfig::default(),
        Vec::new(),
        None,
        &rch_common::CompilationConfig::default(),
        None,
        Some(CompilationKind::CargoTest),
        &reporter,
        &socket_path,
        ColorMode::Auto,
        None,
        &policy,
    )
    .await;

    if let Some(prev) = prev_cwd {
        let _ = std::env::set_current_dir(prev);
    }

    let build = build.expect("remote execution should return Ok in mock mode");
    assert_ne!(
        build.exit_code, 0,
        "a successful compile with a failed artifact sync-back must NOT exit 0"
    );
    assert_eq!(
        build.exit_code, EXIT_ARTIFACT_TRANSFER_FAILED,
        "artifact-transfer failure must surface the build-failure-class exit code"
    );

    let test_run = test_run.expect("remote execution should return Ok in mock mode");
    assert_eq!(
        test_run.exit_code, 0,
        "cargo test streams its output; a missing artifact must not fail it"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_delegates_to_rch_exec() {
    // Test that cargo test commands are delegated to rch exec
    let _lock = test_lock().lock().await;
    let _guard = test_guard!();
    mock::clear_global_invocations();
    crate::config::set_test_config_override(Some(rch_common::RchConfig::default()));

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    crate::config::set_test_config_override(None);

    // Hook should delegate to rch exec
    assert!(
        output.is_allow(),
        "cargo test should be allowed via delegation"
    );
    let cmd = delegated_command(&output);
    assert_eq!(cmd, "rch exec -- cargo test");

    // No rsync/SSH during hook - that happens in run_exec
    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let ssh_logs = mock::global_ssh_invocations_snapshot();
    assert!(rsync_logs.is_empty(), "Hook should not invoke rsync");
    assert!(ssh_logs.is_empty(), "Hook should not invoke SSH");
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_with_args_delegates_correctly() {
    // Test that cargo test with arguments is delegated correctly
    let _lock = test_lock().lock().await;
    let _guard = test_guard!();
    mock::clear_global_invocations();
    crate::config::set_test_config_override(Some(rch_common::RchConfig::default()));

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test --release -- --nocapture".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    crate::config::set_test_config_override(None);

    // Hook should delegate with all arguments preserved
    assert!(output.is_allow());
    let cmd = delegated_command(&output);
    assert_eq!(cmd, "rch exec -- cargo test --release -- --nocapture");

    // No rsync/SSH during hook
    let rsync_logs = mock::global_rsync_invocations_snapshot();
    let ssh_logs = mock::global_ssh_invocations_snapshot();
    assert!(rsync_logs.is_empty(), "Hook should not invoke rsync");
    assert!(ssh_logs.is_empty(), "Hook should not invoke SSH");
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_remote_build_failure() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_cargo_test_build_fail_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Configure mock for build failure (exit 1)
    let _overrides = TestOverridesGuard::set(
            &socket_path,
            MockConfig {
                default_exit_code: 1,
                default_stderr: "error[E0425]: cannot find value `undefined_var` in this scope\n  --> src/lib.rs:10:5\n".to_string(),
                ..MockConfig::default()
            },
            MockRsyncConfig::success(),
        );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "test.host.local".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/test_key".to_string(),
            slots_available: 8,
            speed_score: 85.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Build failure (exit 1) should use transparent interception with exit code
    // Agent sees the error output and gets correct exit code
    assert!(
        output.is_allow(),
        "cargo test build failure should use transparent interception"
    );
    assert!(
        matches!(output, HookOutput::AllowWithModifiedCommand(_)),
        "cargo test build failure should return AllowWithModifiedCommand"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_with_filter() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_cargo_test_filter_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "test.host.local".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/test_key".to_string(),
            slots_available: 8,
            speed_score: 85.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    // Test with filter pattern
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test specific_test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Filtered test command should use transparent interception
    assert!(
        output.is_allow(),
        "Filtered cargo test should use transparent interception"
    );
    assert!(
        matches!(output, HookOutput::AllowWithModifiedCommand(_)),
        "Filtered cargo test should return AllowWithModifiedCommand"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_with_test_threads() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_cargo_test_threads_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "test.host.local".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/test_key".to_string(),
            slots_available: 8,
            speed_score: 85.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    // Test with --test-threads flag (should parse correctly for slot estimation)
    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test -- --test-threads=4".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should use transparent interception regardless of thread count
    assert!(
        output.is_allow(),
        "cargo test with --test-threads should use transparent interception"
    );
    assert!(
        matches!(output, HookOutput::AllowWithModifiedCommand(_)),
        "cargo test with --test-threads should return AllowWithModifiedCommand"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_signal_killed() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_cargo_test_signal_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Configure mock for OOM kill (exit 137 = 128 + 9 = SIGKILL)
    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig {
            default_exit_code: 137,
            default_stderr: "Killed\n".to_string(),
            ..MockConfig::default()
        },
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "test.host.local".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/test_key".to_string(),
            slots_available: 8,
            speed_score: 85.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Signal killed (likely OOM) should use transparent interception with exit code
    assert!(
        output.is_allow(),
        "Signal-killed cargo test should use transparent interception"
    );
    assert!(
        matches!(output, HookOutput::AllowWithModifiedCommand(_)),
        "Signal-killed cargo test should return AllowWithModifiedCommand"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_signal_killed_with_toolchain_path_does_not_fallback_local() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_cargo_test_signal_toolchain_path_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let stderr = "error: could not compile `serde` (lib)\nCaused by:\n  process didn't exit successfully: `/home/ubuntu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/bin/rustc --crate-name serde ...` (signal: 9, SIGKILL: kill)\n";

    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig {
            default_exit_code: 137,
            default_stderr: stderr.to_string(),
            ..MockConfig::default()
        },
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "test.host.local".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/test_key".to_string(),
            slots_available: 8,
            speed_score: 85.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    assert!(
        matches!(output, HookOutput::AllowWithModifiedCommand(_)),
        "signal-killed remote failures that mention .rustup/toolchains must preserve the remote exit code instead of falling back local"
    );
}

#[tokio::test]
#[serial(mock_global)]
async fn test_cargo_test_toolchain_fallback() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_cargo_test_toolchain_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Configure mock for toolchain failure - should allow local fallback
    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig {
            default_exit_code: 1,
            default_stderr: "error: toolchain 'nightly-2025-01-15' is not installed\n".to_string(),
            ..MockConfig::default()
        },
        MockRsyncConfig::success(),
    );
    mock::clear_global_invocations();

    let response = SelectionResponse {
        worker: Some(SelectedWorker {
            id: rch_common::WorkerId::new("test-worker"),
            host: "test.host.local".to_string(),
            user: "testuser".to_string(),
            identity_file: "~/.ssh/test_key".to_string(),
            slots_available: 8,
            speed_score: 85.0,
        }),
        reason: SelectionReason::Success,
        build_id: None,
        diagnostics: None,
    };
    spawn_mock_daemon(&socket_path, response).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo test".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Toolchain failure should allow local fallback
    // Local machine might have the toolchain
    assert!(
        output.is_allow(),
        "Toolchain failure should allow local fallback"
    );
}

#[test]
fn test_cargo_test_classification() {
    let _guard = test_guard!();
    // Verify cargo test commands are classified correctly
    let result = classify_command("cargo test");
    assert!(result.is_compilation, "cargo test should be compilation");
    assert_eq!(
        result.kind,
        Some(CompilationKind::CargoTest),
        "Should be CargoTest kind"
    );

    let result = classify_command("cargo test specific_test");
    assert!(result.is_compilation);
    assert_eq!(result.kind, Some(CompilationKind::CargoTest));

    let result = classify_command("cargo test -- --test-threads=4");
    assert!(result.is_compilation);
    assert_eq!(result.kind, Some(CompilationKind::CargoTest));

    let result = classify_command("cargo test --release");
    assert!(result.is_compilation);
    assert_eq!(result.kind, Some(CompilationKind::CargoTest));

    let result = classify_command("cargo test -p mypackage");
    assert!(result.is_compilation);
    assert_eq!(result.kind, Some(CompilationKind::CargoTest));
}

#[test]
fn test_cargo_nextest_classification() {
    let _guard = test_guard!();
    // Verify cargo nextest commands are classified correctly
    let result = classify_command("cargo nextest run");
    assert!(result.is_compilation, "cargo nextest should be compilation");
    assert_eq!(
        result.kind,
        Some(CompilationKind::CargoNextest),
        "Should be CargoNextest kind"
    );

    let result = classify_command("cargo nextest run --no-fail-fast");
    assert!(result.is_compilation);
    assert_eq!(result.kind, Some(CompilationKind::CargoNextest));
}

#[test]
fn test_artifact_patterns_for_test_commands() {
    let _guard = test_guard!();
    // Verify test commands use minimal artifact patterns
    let test_patterns = get_artifact_patterns(Some(CompilationKind::CargoTest));
    let check_patterns = get_artifact_patterns(Some(CompilationKind::CargoCheck));
    let clippy_patterns = get_artifact_patterns(Some(CompilationKind::CargoClippy));
    let build_patterns = get_artifact_patterns(Some(CompilationKind::CargoBuild));

    // Test patterns should be smaller (more targeted)
    // They should include coverage/results but not full target/
    assert!(
        !test_patterns.iter().any(|p| p == "target/"),
        "Test artifacts should not include full target/"
    );

    // Build patterns should include full build outputs
    assert!(
        build_patterns.iter().any(|p| p == "target/debug/**"),
        "Build artifacts should include target/debug/**"
    );
    assert!(
        build_patterns.iter().any(|p| p == "target/release/**"),
        "Build artifacts should include target/release/**"
    );
    assert!(
        !test_patterns.iter().any(|p| p == "target/debug/**"),
        "Test artifacts should not include target/debug/**"
    );
    assert!(
        !test_patterns.iter().any(|p| p == "target/release/**"),
        "Test artifacts should not include target/release/**"
    );
    assert!(
        !check_patterns.iter().any(|p| p == "target/debug/**"),
        "Cargo check artifacts should not include target/debug/**"
    );
    assert!(
        !clippy_patterns.iter().any(|p| p == "target/debug/**"),
        "Cargo clippy artifacts should not include target/debug/**"
    );
}

#[test]
fn test_custom_target_artifact_patterns_for_cargo_test_are_skipped() {
    let _guard = test_guard!();
    let patterns = get_custom_target_artifact_patterns(Some(CompilationKind::CargoTest));

    assert!(
        patterns.is_empty(),
        "cargo test output is streamed; do not sync a custom target dir after tests"
    );
}

#[test]
fn test_custom_target_artifact_patterns_for_diagnostic_commands_are_skipped() {
    let _guard = test_guard!();

    assert!(
        get_custom_target_artifact_patterns(Some(CompilationKind::CargoCheck)).is_empty(),
        "cargo check output is streamed; do not sync a custom target dir"
    );
    assert!(
        get_custom_target_artifact_patterns(Some(CompilationKind::CargoClippy)).is_empty(),
        "cargo clippy output is streamed; do not sync a custom target dir"
    );
}

#[test]
fn test_custom_target_artifact_patterns_for_nextest_are_target_relative() {
    let _guard = test_guard!();
    let patterns = get_custom_target_artifact_patterns(Some(CompilationKind::CargoNextest));

    assert!(
        !patterns.iter().any(|p| p == "**"),
        "nextest custom target retrieval must not sync the full target dir"
    );
    assert!(
        !patterns.iter().any(|p| p.starts_with("target/")),
        "custom target retrieval is already rooted at the target dir"
    );
    assert!(
        patterns.iter().any(|p| p == "nextest/**"),
        "nextest custom target retrieval should keep targeted test artifacts"
    );
}

#[test]
fn test_custom_target_artifact_patterns_for_build_commands_capture_outputs_only() {
    let _guard = test_guard!();
    for kind in [
        CompilationKind::CargoBuild,
        CompilationKind::CargoDoc,
        CompilationKind::Rustc,
    ] {
        let patterns = get_custom_target_artifact_patterns(Some(kind));

        // No longer the firehose: must NOT sync the entire per-job target dir.
        assert!(
            !patterns.iter().any(|p| p == "**"),
            "{kind:?}: build sync-back must not pull the whole target dir"
        );
        // The sync root IS the remote target dir, so patterns are already
        // rooted there — never re-prefixed with `target/`.
        assert!(
            !patterns.iter().any(|p| p.starts_with("target/")),
            "{kind:?}: custom-target patterns must be target-dir-relative: {patterns:?}"
        );

        // Build OUTPUTS are retained: final binaries/libs under `<profile>/`
        // (and the crate's own artifacts under `<profile>/deps`, which
        // `debug/**`/`release/**` cover). The final binary lives directly
        // under `<profile>/`, so the profile globs MUST be present.
        assert!(
            patterns.iter().any(|p| p == "debug/**"),
            "{kind:?}: must retain debug profile outputs (incl. the binary): {patterns:?}"
        );
        assert!(
            patterns.iter().any(|p| p == "release/**"),
            "{kind:?}: must retain release profile outputs (incl. the binary): {patterns:?}"
        );

        // Cache trees are EXCLUDED via `- <pat>` rules (emitted as rsync
        // `--exclude` before the includes).
        for needle in ["incremental/", ".fingerprint/", "build/", "*.d"] {
            assert!(
                patterns
                    .iter()
                    .any(|p| p.starts_with("- ") && p.contains(needle)),
                "{kind:?}: must exclude cargo cache tree {needle:?}: {patterns:?}"
            );
        }
    }
}

#[test]
fn test_custom_target_patterns_match_a_binary_but_not_cache() {
    // Verify against a realistic remote target layout that the output globs
    // match the final binary under `<profile>/` while the exclude rules drop
    // the cache trees. Mirrors how the rsync filter chain evaluates them:
    // an explicit `- <pat>` exclude wins over a later `debug/**` include.
    let _guard = test_guard!();
    let patterns = get_custom_target_artifact_patterns(Some(CompilationKind::CargoBuild));

    let (excludes, includes): (Vec<&String>, Vec<&String>) =
        patterns.iter().partition(|p| p.starts_with("- "));
    let exclude_payloads: Vec<&str> = excludes
        .iter()
        .map(|p| p.trim_start_matches("- "))
        .collect();

    // Helper mirroring rsync first-match-wins: an exclude rule that matches
    // the path wins (the excludes are emitted before the includes); otherwise
    // an include glob decides. Directory excludes (`<dir>/`, `*/<dir>/`) match
    // any path containing that segment; `*.d` matches by suffix.
    let excluded = |path: &str| -> bool {
        exclude_payloads.iter().any(|ex| {
            if let Some(dir) = ex.strip_suffix('/') {
                let segment = dir.trim_start_matches("*/");
                path.split('/').any(|comp| comp == segment)
            } else if let Some(suffix) = ex.strip_prefix('*') {
                path.ends_with(suffix)
            } else {
                path == *ex
            }
        })
    };
    let included = |path: &str| -> bool {
        if excluded(path) {
            return false;
        }
        includes.iter().any(|inc| {
            if let Some(prefix) = inc.strip_suffix("/**") {
                path.starts_with(&format!("{prefix}/"))
            } else {
                path == inc.as_str()
            }
        })
    };

    // The final binary (directly under the profile dir) IS retrieved.
    assert!(
        included("debug/my_app"),
        "the final debug binary must be synced back: {patterns:?}"
    );
    assert!(
        included("release/my_app"),
        "the final release binary must be synced back: {patterns:?}"
    );
    // The crate's compiled deps artifacts ARE retrieved.
    assert!(
        included("debug/deps/libmy_app.rlib"),
        "crate deps artifacts must be synced back: {patterns:?}"
    );
    // Cache trees are NOT retrieved.
    assert!(
        !included("debug/incremental/foo/bar.bin"),
        "incremental cache must not be synced back: {patterns:?}"
    );
    assert!(
        !included("debug/.fingerprint/my_app/lib.json"),
        ".fingerprint cache must not be synced back: {patterns:?}"
    );
    assert!(
        !included("debug/build/somecrate/out/generated.rs"),
        "build-script cache must not be synced back: {patterns:?}"
    );
    assert!(
        !included("debug/deps/my_app.d"),
        "dep (*.d) files must not be synced back: {patterns:?}"
    );
}

// =========================================================================
// Test filtering and special flags tests (bead remote_compilation_helper-ya16)
// =========================================================================

#[test]
fn test_is_filtered_test_command_basic() {
    let _guard = test_guard!();
    // Basic test name filter
    assert!(
        is_filtered_test_command("cargo test my_test"),
        "Should detect test name filter"
    );
    assert!(
        is_filtered_test_command("cargo test test_foo"),
        "Should detect test name filter"
    );
    assert!(
        is_filtered_test_command("cargo test some::module::test"),
        "Should detect module path filter"
    );

    // Full test suite (no filter)
    assert!(
        !is_filtered_test_command("cargo test"),
        "No filter in basic cargo test"
    );
    assert!(
        !is_filtered_test_command("cargo test --release"),
        "Flags are not filters"
    );
}

#[test]
fn test_is_filtered_test_command_with_flags() {
    let _guard = test_guard!();
    // Filter with flags
    assert!(
        is_filtered_test_command("cargo test --release my_test"),
        "Should detect filter after flags"
    );
    assert!(
        is_filtered_test_command("cargo test -p mypackage my_test"),
        "Should detect filter after package flag"
    );

    // Only package flag (not a name filter)
    assert!(
        !is_filtered_test_command("cargo test -p mypackage"),
        "Package is not a test name filter"
    );
    assert!(
        !is_filtered_test_command("cargo test --lib"),
        "--lib is not a test name filter"
    );
}

#[test]
fn test_is_filtered_test_command_with_separator() {
    let _guard = test_guard!();
    // Filter before --
    assert!(
        is_filtered_test_command("cargo test my_test -- --nocapture"),
        "Should detect filter before separator"
    );

    // No filter, args after --
    assert!(
        !is_filtered_test_command("cargo test -- --nocapture"),
        "Args after -- are not test name filters"
    );
    assert!(
        !is_filtered_test_command("cargo test -- --test-threads=4"),
        "Args after -- are not test name filters"
    );
}

#[test]
fn test_has_ignored_only_flag() {
    let _guard = test_guard!();
    // Only --ignored
    assert!(
        has_ignored_only_flag("cargo test -- --ignored"),
        "Should detect --ignored"
    );

    // --include-ignored (runs all tests)
    assert!(
        !has_ignored_only_flag("cargo test -- --include-ignored"),
        "--include-ignored runs all tests"
    );

    // Both flags (--include-ignored takes precedence)
    assert!(
        !has_ignored_only_flag("cargo test -- --ignored --include-ignored"),
        "--include-ignored takes precedence"
    );

    // No flags
    assert!(!has_ignored_only_flag("cargo test"), "No flags");
}

#[test]
fn test_has_exact_flag() {
    let _guard = test_guard!();
    assert!(
        has_exact_flag("cargo test my_test -- --exact"),
        "--exact detected"
    );
    assert!(!has_exact_flag("cargo test my_test"), "No --exact");
    assert!(!has_exact_flag("cargo test -- --nocapture"), "No --exact");
}

#[test]
fn test_estimate_cores_filtered_tests() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 10,
        check_slots: 3,
        ..Default::default()
    };

    // Full test suite gets default slots
    let full = estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
    assert_eq!(full, 10, "Full test suite uses default test_slots");

    // Filtered test gets reduced slots (test_slots / 2, min 2)
    let filtered = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test my_test",
        &config,
    );
    assert_eq!(filtered, 5, "Filtered test uses reduced slots");

    // --exact flag gets reduced slots
    let exact = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test my_test -- --exact",
        &config,
    );
    assert_eq!(exact, 5, "--exact uses reduced slots");

    // --ignored only gets reduced slots
    let ignored = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -- --ignored",
        &config,
    );
    assert_eq!(ignored, 5, "--ignored uses reduced slots");

    // --include-ignored gets full slots (runs all tests plus ignored)
    let include_ignored = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -- --include-ignored",
        &config,
    );
    assert_eq!(include_ignored, 10, "--include-ignored uses full slots");
}

#[test]
fn test_estimate_cores_explicit_threads_overrides_filter() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 10,
        check_slots: 3,
        ..Default::default()
    };

    // Explicit --test-threads should override filtering heuristics
    let explicit = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test my_test -- --test-threads=8",
        &config,
    );
    assert_eq!(explicit, 8, "Explicit --test-threads overrides filtering");

    // RUST_TEST_THREADS also overrides
    let env = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "RUST_TEST_THREADS=6 cargo test my_test",
        &config,
    );
    assert_eq!(env, 6, "RUST_TEST_THREADS overrides filtering");
}

#[test]
fn test_estimate_cores_filtered_minimum() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 2, // Very low test_slots
        check_slots: 3,
        ..Default::default()
    };

    // With test_slots=2, filtered should be max(2/2, 2) = max(1, 2) = 2
    let filtered = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test my_test",
        &config,
    );
    assert!(filtered >= 2, "Filtered slots should be at least 2");
}

#[test]
fn test_estimate_cores_filtered_never_exceeds_default() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 1, // Single-slot environment
        check_slots: 3,
        ..Default::default()
    };

    let filtered = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test my_test",
        &config,
    );
    assert_eq!(
        filtered, 1,
        "Filtered tests should not request more slots than test_slots"
    );
}

#[test]
fn test_nocapture_does_not_affect_slots() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 10,
        check_slots: 3,
        ..Default::default()
    };

    // --nocapture doesn't affect slot estimation
    let with_nocapture = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -- --nocapture",
        &config,
    );
    let without =
        estimate_cores_for_command(Some(CompilationKind::CargoTest), "cargo test", &config);
    assert_eq!(with_nocapture, without, "--nocapture doesn't affect slots");

    // --show-output also doesn't affect slots
    let with_show = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -- --show-output",
        &config,
    );
    assert_eq!(with_show, without, "--show-output doesn't affect slots");
}

#[test]
fn test_skip_pattern_uses_full_slots() {
    let _guard = test_guard!();
    let config = rch_common::CompilationConfig {
        build_slots: 6,
        test_slots: 10,
        check_slots: 3,
        ..Default::default()
    };

    // --skip doesn't reduce the test suite significantly
    // (still runs most tests, just skipping some)
    let with_skip = estimate_cores_for_command(
        Some(CompilationKind::CargoTest),
        "cargo test -- --skip slow_test",
        &config,
    );
    assert_eq!(with_skip, 10, "--skip uses full slots");
}

#[test]
fn test_parse_selection_response_accepts_known_newer_health_reason() {
    let _guard = test_guard!();
    let json = serde_json::json!({
        "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION,
        "worker": null,
        "reason": "no_workers_passed_health",
        "build_id": null,
        "diagnostics": null
    })
    .to_string();

    let response = parse_selection_response(&json).expect("selection response parses");

    assert_eq!(response.reason, SelectionReason::NoWorkersPassedHealth);
    assert!(response.worker.is_none());
}

#[test]
fn test_parse_selection_response_tolerates_unknown_unit_reason() {
    let _guard = test_guard!();
    let json = serde_json::json!({
        "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION,
        "worker": null,
        "reason": "future_selector_gate",
        "build_id": null,
        "diagnostics": null
    })
    .to_string();

    let response = parse_selection_response(&json).expect("unknown reason should not fail");

    assert!(response.worker.is_none());
    assert!(matches!(
        response.reason,
        SelectionReason::SelectionError(_)
    ));
    assert!(
        response
            .reason
            .to_string()
            .contains("unknown daemon selection reason")
    );
    assert!(
        response.reason.to_string().contains("future_selector_gate"),
        "unknown unit reason should preserve daemon detail: {}",
        response.reason
    );
}

#[test]
fn test_parse_selection_response_preserves_unknown_structured_reason_detail() {
    let _guard = test_guard!();
    let json = serde_json::json!({
        "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION,
        "worker": null,
        "reason": { "future_selector_gate": "runtime_probe_missing" },
        "build_id": null,
        "diagnostics": null
    })
    .to_string();

    let response = parse_selection_response(&json).expect("unknown reason should not fail");
    let detail = response.reason.to_string();

    assert!(matches!(
        response.reason,
        SelectionReason::SelectionError(_)
    ));
    assert!(
        detail.contains("future_selector_gate"),
        "unknown structured reason should preserve variant name: {detail}"
    );
    assert!(
        detail.contains("runtime_probe_missing"),
        "unknown structured reason should preserve daemon payload: {detail}"
    );
}

#[test]
fn test_parse_selection_response_rejects_unsupported_protocol_version() {
    let _guard = test_guard!();
    let json = serde_json::json!({
        "selection_protocol_version": rch_common::SELECTION_RESPONSE_PROTOCOL_VERSION + 1,
        "worker": null,
        "reason": "all_workers_busy",
        "build_id": null,
        "diagnostics": null
    })
    .to_string();

    let error = parse_selection_response(&json).expect_err("future protocol should fail");

    assert!(
        error.to_string().contains("exceeds client support"),
        "unexpected error: {error}"
    );
}

// =========================================================================
// Timeout handling tests (bead bd-1aim.2)
// =========================================================================

#[tokio::test]
async fn test_daemon_query_connect_timeout_fail_open() {
    // When the daemon socket exists but doesn't accept connections quickly,
    // the hook should timeout and fail-open to allow local execution.
    //
    // We simulate this by creating a socket that accepts but never responds.
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_connect_timeout_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Clean up any existing socket
    let _ = std::fs::remove_file(&socket_path);

    // Create a socket that accepts connections but never responds
    let listener = UnixListener::bind(&socket_path).expect("Failed to create test socket");

    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        // Accept the connection but do nothing with it
        let _ = listener.accept().await;
        // Hold connection open for longer than the timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    });

    // Give listener time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    // Query should timeout since daemon never responds
    let result: anyhow::Result<SelectionResponse> = query_daemon(
        &socket_path,
        "test-project",
        4,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        100,
        None,
        false,
        &[],
    )
    .await;

    let _ = std::fs::remove_file(&socket_path_clone);

    // Should fail due to read timeout (empty response)
    assert!(
        result.is_err(),
        "Query should fail when daemon doesn't respond"
    );
}

#[tokio::test]
async fn test_process_hook_timeout_fail_open() {
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_process_timeout_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    // Create test config with our socket
    let _overrides = TestOverridesGuard::set(
        &socket_path,
        MockConfig::default(),
        MockRsyncConfig::success(),
    );

    // Clean up any existing socket
    let _ = std::fs::remove_file(&socket_path);

    // Create a slow daemon that doesn't respond in time
    let listener = UnixListener::bind(&socket_path).expect("bind");

    tokio::spawn(async move {
        // Accept and hold connection but don't respond
        let (stream, _) = listener.accept().await.expect("accept");
        // Hold the stream open
        let (_reader, _writer) = stream.into_split();
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let input = HookInput {
        tool_name: "Bash".to_string(),
        tool_input: ToolInput {
            command: "cargo build".to_string(),
            description: None,
        },
        session_id: None,
    };

    let output = process_hook(input).await;
    let _ = std::fs::remove_file(&socket_path);

    // Should fail-open when daemon times out
    assert!(
        output.is_allow(),
        "Hook should fail-open when daemon query times out"
    );
}

#[tokio::test]
async fn test_daemon_query_partial_response_timeout() {
    // Test behavior when daemon sends partial response and then hangs
    let _lock = test_lock().lock().await;
    let socket_path = format!(
        "/tmp/rch_test_partial_timeout_{}_{}.sock",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind");

    let socket_path_clone = socket_path.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = TokioBufReader::new(reader);

        // Read request
        let mut request_line = String::new();
        let _ = buf_reader.read_line(&mut request_line).await;

        // Write partial HTTP response (no body)
        writer
            .write_all(b"HTTP/1.1 200 OK\r\n")
            .await
            .expect("write");
        // Hang without completing the response
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(25)).await;

    let result = query_daemon(
        &socket_path,
        "test-project",
        4,
        "cargo build",
        None,
        RequiredRuntime::None,
        CommandPriority::Normal,
        100,
        None,
        false,
        &[],
    )
    .await;

    let _ = std::fs::remove_file(&socket_path_clone);

    // Partial response should result in error (no body to parse)
    assert!(result.is_err(), "Partial response should result in error");
}

#[test]
fn test_queue_when_busy_enabled_parser() {
    let _guard = test_guard!();
    assert!(queue_when_busy_enabled_from(None));
    assert!(queue_when_busy_enabled_from(Some("1")));
    assert!(queue_when_busy_enabled_from(Some("true")));
    assert!(queue_when_busy_enabled_from(Some("yes")));
    assert!(!queue_when_busy_enabled_from(Some("0")));
    assert!(!queue_when_busy_enabled_from(Some("false")));
    assert!(!queue_when_busy_enabled_from(Some("off")));
}

#[test]
fn test_daemon_response_timeout_defaults_and_overrides() {
    let _guard = test_guard!();
    assert_eq!(
        daemon_response_timeout_for(false, None, None),
        Duration::from_secs(DEFAULT_DAEMON_RESPONSE_TIMEOUT_SECS)
    );
    assert_eq!(
        daemon_response_timeout_for(true, None, None),
        Duration::from_secs(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS)
    );
    assert_eq!(
        daemon_response_timeout_for(true, None, Some("900")),
        Duration::from_secs(900)
    );
    assert_eq!(
        daemon_response_timeout_for(true, Some("45"), Some("900")),
        Duration::from_secs(45)
    );
    assert_eq!(
        daemon_response_timeout_for(true, Some("invalid"), Some("invalid")),
        Duration::from_secs(DEFAULT_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS)
    );
}

// ============================================================================
// Auto-start (Self-Healing) Tests
// ============================================================================

/// Test helper to create a unique temp directory for auto-start tests
fn create_test_state_dir() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("Failed to create temp dir")
}

// Auto-start (Self-Healing) unit tests for these helpers now live in
// the `auto_start` submodule (`rch/src/hook/auto_start.rs`).

// -----------------------------------------------------------------------
// bd-session-history-remediation-ocv9i.3.1: hook socket-failure recovery.
// The six bead scenarios exercised against the pure decision cores and the
// structured incidents they emit — no daemon spawn required.
// -----------------------------------------------------------------------

#[test]
fn test_classify_socket_failure_missing_when_socket_not_found() {
    let err: anyhow::Error = super::DaemonError::SocketNotFound {
        socket_path: "/run/rch/rch.sock".to_string(),
    }
    .into();
    // The socket file is genuinely absent.
    assert_eq!(
        super::classify_socket_failure(&err, false),
        super::SocketFailureKind::Missing
    );
}

#[test]
fn test_classify_socket_failure_refused_socket() {
    // Scenario: refused socket (no live listener on an existing socket).
    let err = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
    assert_eq!(
        super::classify_socket_failure(&err, true),
        super::SocketFailureKind::Refused
    );
}

#[test]
fn test_classify_socket_failure_stale_socket_on_timeout() {
    // Scenario: stale socket. The 5s connect timeout is a plain anyhow
    // string error (no io::Error source).
    let err = anyhow::anyhow!("Daemon connect timed out after 5s");
    assert_eq!(
        super::classify_socket_failure(&err, true),
        super::SocketFailureKind::Stale
    );
    // A TimedOut io error classifies the same way.
    let io_timeout = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::TimedOut));
    assert_eq!(
        super::classify_socket_failure(&io_timeout, true),
        super::SocketFailureKind::Stale
    );
}

#[test]
fn test_detect_socket_path_mismatch_wrong_configured_socket() {
    // Scenario: wrong configured socket. Configured path differs from the
    // canonical default => reported mismatch (detection only).
    let mismatch = super::detect_socket_path_mismatch(
        "/tmp/custom-rch.sock",
        "/home/dev/.cache/rch/rch.sock",
        true,
    )
    .expect("differing paths must be reported as a mismatch");
    assert_eq!(mismatch.configured, "/tmp/custom-rch.sock");
    assert_eq!(mismatch.canonical, "/home/dev/.cache/rch/rch.sock");
    assert!(mismatch.canonical_exists);
    // Equivalent paths (ignoring surrounding whitespace) => no mismatch.
    assert!(
        super::detect_socket_path_mismatch(
            " /home/dev/.cache/rch/rch.sock ",
            "/home/dev/.cache/rch/rch.sock",
            true,
        )
        .is_none()
    );
}

#[test]
fn test_decide_recovery_action_daemon_start_success_proceeds_remote() {
    // Scenario: daemon start success. A successful retry proceeds remotely
    // regardless of proof mode.
    assert_eq!(
        super::decide_recovery_action(true, false),
        super::DaemonRecoveryAction::ProceedRemote
    );
    assert_eq!(
        super::decide_recovery_action(true, true),
        super::DaemonRecoveryAction::ProceedRemote
    );
}

#[test]
fn test_decide_recovery_action_daemon_start_failure_falls_back_open() {
    // Scenario: daemon start failure, convenience lane => fail open local.
    assert_eq!(
        super::decide_recovery_action(false, false),
        super::DaemonRecoveryAction::LocalFallback
    );
}

#[test]
fn test_decide_recovery_action_proof_mode_refuses() {
    // Scenario: proof-mode refusal. Retry failed under proof mode => fail
    // closed (refuse local fallback).
    assert_eq!(
        super::decide_recovery_action(false, true),
        super::DaemonRecoveryAction::Refuse
    );
}

#[test]
fn test_build_socket_failure_incident_records_reason_and_mismatch() {
    let mismatch = super::SocketPathMismatch {
        configured: "/home/alice/.cache/rch/rch.sock".to_string(),
        canonical: "/home/alice/.config/rch/rch.sock".to_string(),
        canonical_exists: true,
    };
    let event = super::build_socket_failure_incident(
        super::SocketFailureKind::Refused,
        Some(&mismatch),
        "demo-project",
        "cargo build --release",
        false,
        1_700_000_000_000,
    );
    assert_eq!(
        event.reason_code,
        rch_common::IncidentReasonCode::DaemonSocketRefused
    );
    assert_eq!(event.reason_code.code(), "RCH-I010");
    assert_eq!(event.source, rch_common::IncidentSource::Hook);
    assert_eq!(event.selected_mode, rch_common::SelectedMode::Local);
    assert!(
        event.local_fallback_allowed,
        "convenience lane permits fallback"
    );
    assert_eq!(
        event.details.get("socket_failure").map(String::as_str),
        Some("refused")
    );
    assert_eq!(
        event
            .details
            .get("socket_path_mismatch")
            .map(String::as_str),
        Some("true")
    );
    // Home segment must be masked in the recorded path detail.
    let configured = event.details.get("configured_socket").unwrap();
    assert!(
        configured.contains("<redacted>"),
        "home user must be masked: {configured}"
    );
    assert!(
        !configured.contains("alice"),
        "raw username must not leak: {configured}"
    );
    assert_eq!(
        event
            .details
            .get("canonical_socket_exists")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn test_build_recovery_terminal_incident_proof_vs_fallback() {
    // Proof mode => ProofRefusal (RCH-I012), no local fallback allowed.
    let refusal = super::build_recovery_terminal_incident(
        true,
        "demo",
        "cargo test",
        "daemon unavailable",
        1_700_000_000_001,
    );
    assert_eq!(
        refusal.reason_code,
        rch_common::IncidentReasonCode::ProofRefusal
    );
    assert_eq!(refusal.reason_code.code(), "RCH-I012");
    assert!(!refusal.local_fallback_allowed);
    assert!(refusal.control.strict_remote_policy);
    // Convenience mode => LocalFallback (RCH-I011), fallback allowed.
    let fallback = super::build_recovery_terminal_incident(
        false,
        "demo",
        "cargo test",
        "daemon unavailable",
        1_700_000_000_002,
    );
    assert_eq!(
        fallback.reason_code,
        rch_common::IncidentReasonCode::LocalFallback
    );
    assert_eq!(fallback.reason_code.code(), "RCH-I011");
    assert!(fallback.local_fallback_allowed);
    assert!(!fallback.control.strict_remote_policy);
}

#[test]
fn test_socket_failure_incident_durably_appends_to_ledger() {
    // End-to-end durable record: build the incident the hook emits, append
    // it to a temp ledger, and read it back — proving the structured
    // incident survives a process restart (no env mutation needed).
    let dir = create_test_state_dir();
    let ledger = rch_common::IncidentLedger::with_path(dir.path().join("incidents.jsonl"));
    let event = super::build_socket_failure_incident(
        super::SocketFailureKind::Stale,
        None,
        "demo",
        "cargo check",
        true,
        1_700_000_000_003,
    );
    ledger.append(&event).expect("append must succeed");
    let read = rch_common::IncidentLedger::with_path(ledger.path()).read_all();
    assert_eq!(read.len(), 1);
    assert_eq!(
        read[0].reason_code,
        rch_common::IncidentReasonCode::DaemonSocketRefused
    );
    assert_eq!(
        read[0].details.get("socket_failure").map(String::as_str),
        Some("stale")
    );
    assert!(
        !read[0].local_fallback_allowed,
        "proof mode records no fallback"
    );
}

// Auto-start socket-staleness, state-dir/path, and cooldown unit tests
// now live in the `auto_start` submodule (`rch/src/hook/auto_start.rs`).

// =========================================================================
// Timing History Tests
// =========================================================================

#[test]
fn test_timing_record_creation() {
    let _guard = test_guard!();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = TimingRecord {
        timestamp: now_secs,
        duration_ms: 5000,
        remote: true,
    };

    assert_eq!(record.duration_ms, 5000);
    assert!(record.remote);
    assert!(record.timestamp >= now_secs - 1 && record.timestamp <= now_secs + 1);
}

#[test]
fn test_project_timing_data_add_sample() {
    let _guard = test_guard!();
    let mut data = ProjectTimingData::default();

    // Add local sample
    data.add_sample(1000, false);
    assert_eq!(data.local_samples.len(), 1);
    assert_eq!(data.remote_samples.len(), 0);
    assert_eq!(data.local_samples[0].duration_ms, 1000);

    // Add remote sample
    data.add_sample(500, true);
    assert_eq!(data.local_samples.len(), 1);
    assert_eq!(data.remote_samples.len(), 1);
    assert_eq!(data.remote_samples[0].duration_ms, 500);
}

#[test]
fn test_project_timing_data_median_odd_count() {
    let _guard = test_guard!();
    let mut data = ProjectTimingData::default();
    data.add_sample(100, false);
    data.add_sample(300, false);
    data.add_sample(200, false);

    // Median of [100, 200, 300] = 200
    assert_eq!(data.median_duration(false), Some(200));
}

#[test]
fn test_project_timing_data_median_even_count() {
    let _guard = test_guard!();
    let mut data = ProjectTimingData::default();
    data.add_sample(100, true);
    data.add_sample(300, true);
    data.add_sample(200, true);
    data.add_sample(400, true);

    // Median of [100, 200, 300, 400] = (200 + 300) / 2 = 250
    assert_eq!(data.median_duration(true), Some(250));
}

#[test]
fn test_project_timing_data_median_empty() {
    let _guard = test_guard!();
    let data = ProjectTimingData::default();
    assert_eq!(data.median_duration(false), None);
    assert_eq!(data.median_duration(true), None);
}

#[test]
fn test_project_timing_data_speedup_ratio() {
    let _guard = test_guard!();
    let mut data = ProjectTimingData::default();
    // Local takes 1000ms
    data.add_sample(1000, false);
    // Remote takes 500ms
    data.add_sample(500, true);

    // Speedup = local / remote = 1000 / 500 = 2.0
    assert_eq!(data.speedup_ratio(), Some(2.0));
}

#[test]
fn test_project_timing_data_speedup_no_data() {
    let _guard = test_guard!();
    let mut data = ProjectTimingData::default();
    data.add_sample(1000, false);

    // No remote data, can't compute speedup
    assert_eq!(data.speedup_ratio(), None);
}

#[test]
fn test_project_timing_data_sample_truncation() {
    let _guard = test_guard!();
    let mut data = ProjectTimingData::default();

    // Add more than MAX_TIMING_SAMPLES
    for i in 0..25 {
        data.add_sample(i * 100, false);
    }

    // Should be capped at MAX_TIMING_SAMPLES (20)
    assert_eq!(data.local_samples.len(), MAX_TIMING_SAMPLES);
    // First sample should be removed (FIFO)
    assert_eq!(data.local_samples[0].duration_ms, 500); // Started at 0, removed 0-4
}

#[test]
fn test_timing_history_key() {
    let _guard = test_guard!();
    let key = TimingHistory::key("my_project", Some(CompilationKind::CargoTest));
    assert!(key.contains("my_project"));
    assert!(key.contains("CargoTest"));

    let key_unknown = TimingHistory::key("project2", None);
    assert!(key_unknown.contains("project2"));
    assert!(key_unknown.contains("Unknown"));
}

#[test]
fn test_timing_history_record_and_get() {
    let _guard = test_guard!();
    let mut history = TimingHistory::default();

    history.record("proj1", Some(CompilationKind::CargoBuild), 1000, true);
    history.record("proj1", Some(CompilationKind::CargoBuild), 800, true);

    let data = history.get("proj1", Some(CompilationKind::CargoBuild));
    assert!(data.is_some());
    let data = data.unwrap();
    assert_eq!(data.remote_samples.len(), 2);
    assert_eq!(data.median_duration(true), Some(900)); // (800 + 1000) / 2

    // Different kind should be separate
    let data2 = history.get("proj1", Some(CompilationKind::CargoTest));
    assert!(data2.is_none());
}

#[test]
fn test_timing_history_serialization() {
    let _guard = test_guard!();
    let mut history = TimingHistory::default();
    history.record("proj", Some(CompilationKind::CargoCheck), 500, false);
    history.record("proj", Some(CompilationKind::CargoCheck), 250, true);

    let json = serde_json::to_string(&history).unwrap();
    let loaded: TimingHistory = serde_json::from_str(&json).unwrap();

    let data = loaded
        .get("proj", Some(CompilationKind::CargoCheck))
        .unwrap();
    assert_eq!(data.local_samples.len(), 1);
    assert_eq!(data.remote_samples.len(), 1);
}

// ========================================================================
// t18 — record_build_timing lock-scope discipline. Verify the write
// guard is dropped BEFORE save_to_disk, so other readers/writers
// aren't blocked on disk I/O.
// ========================================================================

#[test]
fn test_record_build_timing_releases_guard_before_disk_io() {
    // Verify: between cache.write()-release and cache.read()-acquire
    // there is no overlap — i.e., another thread can acquire a
    // read lock while save_to_disk is in flight.
    //
    // Property tested indirectly: spawn many threads each calling
    // record_build_timing concurrently. With the OLD code (save
    // inside the write guard), high contention would serialize all
    // calls behind a 5-10ms disk write per thread. With the NEW
    // code, only the in-memory mutation serializes; disk writes
    // parallelize. A wallclock cap detects the regression.
    //
    // Per-thread project keys are uniquely prefixed so the test
    // doesn't depend on cache-clearing (which would race with other
    // tests sharing the global cache).
    let _guard = test_guard!();
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    let unique = format!(
        "t18-conc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    let n_threads = 8;
    let calls_per_thread = 5;
    let started = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    let t0 = Instant::now();
    for t in 0..n_threads {
        let started = Arc::clone(&started);
        let unique = unique.clone();
        handles.push(thread::spawn(move || {
            for i in 0..calls_per_thread {
                started.fetch_add(1, Ordering::Relaxed);
                let project = format!("{unique}-{t}-{i}");
                record_build_timing(
                    &project,
                    Some(CompilationKind::CargoBuild),
                    100 + (i as u64),
                    true,
                );
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }
    let elapsed = t0.elapsed();
    let total_calls = n_threads * calls_per_thread;
    assert_eq!(
        started.load(Ordering::Relaxed),
        total_calls,
        "all threads should have started"
    );
    // Wallclock cap: 8 threads × 5 calls × 50ms (slow disk fsync)
    // = 2000ms WORST case if serial. Allow 4s for very slow CI.
    // A regression to "save inside the write guard" would dominate
    // the wallclock at scale; this cap catches the worst regressions.
    assert!(
        elapsed < Duration::from_millis(4000),
        "{total_calls} concurrent record_build_timing calls took {elapsed:?} (expected <4s)"
    );
}

#[test]
fn test_record_build_timing_in_memory_state_survives_disk_failure() {
    // Even if save_to_disk fails (e.g., disk full, permission denied),
    // the in-memory cache MUST contain the recorded sample. The lock
    // is dropped before the I/O, so I/O failure can't corrupt the
    // cache state.
    //
    // Uses a unique key (PID + nanosecond timestamp) so the assertion
    // doesn't depend on cache-clearing — which would race with other
    // tests sharing the global cache.
    let _guard = test_guard!();

    let unique = format!(
        "t18-disk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    record_build_timing(&unique, Some(CompilationKind::CargoBuild), 1234, true);

    let history = timing_cache().read().expect("read");
    let entry = history.get(&unique, Some(CompilationKind::CargoBuild));
    assert!(
        entry.is_some(),
        "in-memory entry for key {unique:?} must be present even if disk write failed"
    );
    let data = entry.unwrap();
    assert!(
        !data.remote_samples.is_empty(),
        "at least one remote sample recorded"
    );
    // We're the only writer for this unique key, so the last sample
    // must be the one we recorded.
    assert_eq!(
        data.remote_samples.last().unwrap().duration_ms,
        1234,
        "recorded duration matches the call"
    );
}

// ========================================================================
// WS1.4: Tests for spawn_blocking wrappers (bd-3s1j)
// ========================================================================

#[tokio::test]
async fn test_spawn_blocking_load_with_valid_file() {
    let _guard = test_guard!();
    // Create a temp directory with a timing history file
    let temp_dir = tempfile::tempdir().unwrap();
    let history_path = temp_dir.path().join("timing_history.json");

    // Create valid timing data
    let mut history = TimingHistory::default();
    history.record(
        "test-project",
        Some(CompilationKind::CargoBuild),
        1000,
        false,
    );
    let json = serde_json::to_string_pretty(&history).unwrap();
    std::fs::write(&history_path, json).unwrap();

    // Load via spawn_blocking (simulating what we do in production)
    let path = history_path.clone();
    let loaded = tokio::task::spawn_blocking(move || {
        // In production we use timing_history_path(), here we test the pattern
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|content| serde_json::from_str::<TimingHistory>(&content).ok())
            .unwrap_or_default()
    })
    .await
    .unwrap();

    // Verify data loaded correctly
    let data = loaded.get("test-project", Some(CompilationKind::CargoBuild));
    assert!(data.is_some());
    assert_eq!(data.unwrap().local_samples.len(), 1);
}

#[tokio::test]
async fn test_spawn_blocking_load_missing_file() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().unwrap();
    let missing_path = temp_dir.path().join("nonexistent.json");

    let loaded = tokio::task::spawn_blocking(move || {
        std::fs::read_to_string(&missing_path)
            .ok()
            .and_then(|content| serde_json::from_str::<TimingHistory>(&content).ok())
            .unwrap_or_default()
    })
    .await
    .unwrap();

    // Should return default (empty history)
    assert!(loaded.entries.is_empty());
}

#[tokio::test]
async fn test_spawn_blocking_load_corrupt_json() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().unwrap();
    let corrupt_path = temp_dir.path().join("corrupt.json");
    std::fs::write(&corrupt_path, "not valid json {{{").unwrap();

    let loaded = tokio::task::spawn_blocking(move || {
        std::fs::read_to_string(&corrupt_path)
            .ok()
            .and_then(|content| serde_json::from_str::<TimingHistory>(&content).ok())
            .unwrap_or_default()
    })
    .await
    .unwrap();

    // Should return default on corrupt data (graceful degradation)
    assert!(loaded.entries.is_empty());
}

#[tokio::test]
async fn test_spawn_blocking_save_creates_file() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().unwrap();
    let save_path = temp_dir.path().join("saved_history.json");

    let mut history = TimingHistory::default();
    history.record(
        "saved-project",
        Some(CompilationKind::CargoTest),
        2000,
        true,
    );

    let path = save_path.clone();
    tokio::task::spawn_blocking(move || {
        let content = serde_json::to_string_pretty(&history).unwrap();
        std::fs::write(&path, content).unwrap();
    })
    .await
    .unwrap();

    // Verify file was created and has correct content
    assert!(save_path.exists());
    let content = std::fs::read_to_string(&save_path).unwrap();
    let loaded: TimingHistory = serde_json::from_str(&content).unwrap();
    let data = loaded.get("saved-project", Some(CompilationKind::CargoTest));
    assert!(data.is_some());
    assert_eq!(data.unwrap().remote_samples.len(), 1);
}

#[tokio::test]
async fn test_spawn_blocking_timeout_protection() {
    let _guard = test_guard!();
    // Verify spawn_blocking completes within reasonable time (not deadlocked)
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::task::spawn_blocking(|| {
            let history = TimingHistory::default();
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(10));
            history
        }),
    )
    .await;

    assert!(
        result.is_ok(),
        "spawn_blocking should complete within 5s timeout"
    );
}

#[tokio::test]
async fn test_spawn_blocking_concurrent_loads() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().unwrap();
    let history_path = temp_dir.path().join("concurrent.json");

    // Create test file
    let mut history = TimingHistory::default();
    history.record("concurrent", Some(CompilationKind::CargoBuild), 500, false);
    std::fs::write(&history_path, serde_json::to_string(&history).unwrap()).unwrap();

    // Spawn 5 concurrent loads
    let mut handles = Vec::new();
    for _ in 0..5 {
        let path = history_path.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|c| serde_json::from_str::<TimingHistory>(&c).ok())
                .unwrap_or_default()
        }));
    }

    // All should complete without deadlock
    for handle in handles {
        let loaded = handle.await.unwrap();
        assert!(
            loaded
                .get("concurrent", Some(CompilationKind::CargoBuild))
                .is_some()
        );
    }
}

#[tokio::test]
async fn test_spawn_blocking_concurrent_saves() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().unwrap();

    // Spawn 5 concurrent saves to different files
    let mut handles = Vec::new();
    for i in 0..5 {
        let path = temp_dir.path().join(format!("save_{}.json", i));
        let mut history = TimingHistory::default();
        history.record(
            &format!("project-{}", i),
            Some(CompilationKind::CargoBuild),
            100 * i as u64,
            false,
        );

        handles.push(tokio::task::spawn_blocking(move || {
            let content = serde_json::to_string(&history).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }));
    }

    // All should complete and files should exist
    for handle in handles {
        let path = handle.await.unwrap();
        assert!(path.exists(), "File should be created: {:?}", path);
    }
}

#[tokio::test]
async fn test_spawn_blocking_performance_budget() {
    let _guard = test_guard!();
    let temp_dir = tempfile::tempdir().unwrap();
    let history_path = temp_dir.path().join("perf_test.json");

    // Create a reasonably sized history file
    let mut history = TimingHistory::default();
    for i in 0..10 {
        history.record(
            &format!("project-{}", i),
            Some(CompilationKind::CargoBuild),
            1000 + i * 100,
            false,
        );
        history.record(
            &format!("project-{}", i),
            Some(CompilationKind::CargoBuild),
            800 + i * 50,
            true,
        );
    }
    std::fs::write(
        &history_path,
        serde_json::to_string_pretty(&history).unwrap(),
    )
    .unwrap();

    // Measure load time
    let load_path = history_path.clone();
    let start = std::time::Instant::now();
    let _loaded = tokio::task::spawn_blocking(move || {
        std::fs::read_to_string(&load_path)
            .ok()
            .and_then(|c| serde_json::from_str::<TimingHistory>(&c).ok())
            .unwrap_or_default()
    })
    .await
    .unwrap();
    let load_duration = start.elapsed();

    // Measure save time
    let save_path = temp_dir.path().join("perf_save.json");
    let start = std::time::Instant::now();
    tokio::task::spawn_blocking(move || {
        let content = serde_json::to_string_pretty(&history).unwrap();
        std::fs::write(&save_path, content).unwrap();
    })
    .await
    .unwrap();
    let save_duration = start.elapsed();

    let total = load_duration + save_duration;

    // Log timings for diagnostics (visible with --nocapture)
    eprintln!("Performance test results:");
    eprintln!("  Load: {:?}", load_duration);
    eprintln!("  Save: {:?}", save_duration);
    eprintln!("  Total: {:?}", total);

    // Total should be well under 2ms budget (leaving room for the rest of the 5ms)
    // On fast SSDs this is typically <1ms, but we allow up to 50ms for slow CI
    assert!(
        total < std::time::Duration::from_millis(50),
        "Load+save took {:?}, should be <50ms for CI compatibility",
        total
    );
}

// ── Multi-root sync manifest & partial failure tests (bd-vvmd.2.3 AC5) ──

#[test]
fn test_build_sync_closure_manifest_deterministic_entries() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep_a = temp_dir.path().join("dep_a");
    let dep_b = temp_dir.path().join("dep_b");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep_a).expect("create dep_a");
    std::fs::create_dir_all(&dep_b).expect("create dep_b");

    let plan = build_sync_closure_plan(
        &[dep_b.clone(), dep_a.clone(), project_root.clone()],
        &project_root,
        "abc123",
        &policy,
    );
    let manifest_a = build_sync_closure_manifest(&plan, &project_root);
    let manifest_b = build_sync_closure_manifest(&plan, &project_root);

    // Entries must be identical (order, roots, hashes, primary flag).
    assert_eq!(
        manifest_a.entries, manifest_b.entries,
        "manifest entries should be deterministic for the same plan"
    );
    assert_eq!(
        manifest_a.schema_version, manifest_b.schema_version,
        "schema version must be stable"
    );
    assert_eq!(
        manifest_a.project_root, manifest_b.project_root,
        "project root must be stable"
    );
}

#[test]
fn test_build_sync_closure_manifest_schema_version_stable() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    std::fs::create_dir_all(&project_root).expect("create project root");

    let plan = build_sync_closure_plan(
        std::slice::from_ref(&project_root),
        &project_root,
        "deadbeef",
        &policy,
    );
    let manifest = build_sync_closure_manifest(&plan, &project_root);

    assert_eq!(
        manifest.schema_version, "rch.sync_closure_manifest.v2",
        "schema version must match the documented v2 contract"
    );
}

#[test]
fn test_build_sync_closure_manifest_entries_faithfully_represent_plan() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep = temp_dir.path().join("dep");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep).expect("create dep");

    let plan = build_sync_closure_plan(
        &[dep.clone(), project_root.clone()],
        &project_root,
        "cafe0001",
        &policy,
    );
    let manifest = build_sync_closure_manifest(&plan, &project_root);

    assert_eq!(
        manifest.entries.len(),
        plan.len(),
        "manifest must have one entry per plan entry"
    );
    for (idx, (plan_entry, manifest_entry)) in plan.iter().zip(manifest.entries.iter()).enumerate()
    {
        assert_eq!(manifest_entry.order, idx + 1, "order must be 1-indexed");
        assert_eq!(
            manifest_entry.local_root,
            plan_entry.local_root.to_string_lossy().to_string()
        );
        assert_eq!(manifest_entry.remote_root, plan_entry.remote_root);
        assert_eq!(manifest_entry.project_id, plan_entry.project_id);
        assert_eq!(manifest_entry.root_hash, plan_entry.root_hash);
        assert_eq!(manifest_entry.is_primary, plan_entry.is_primary);
    }
}

#[test]
fn test_build_sync_closure_manifest_primary_root_present() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep = temp_dir.path().join("dep");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep).expect("create dep");

    let plan = build_sync_closure_plan(
        &[dep.clone(), project_root.clone()],
        &project_root,
        "primary_hash",
        &policy,
    );
    let manifest = build_sync_closure_manifest(&plan, &project_root);

    let primary_entries: Vec<_> = manifest.entries.iter().filter(|e| e.is_primary).collect();
    assert_eq!(
        primary_entries.len(),
        1,
        "exactly one manifest entry should be the primary root"
    );
    assert_eq!(
        primary_entries[0].root_hash, "primary_hash",
        "primary entry must carry the project-level hash"
    );
}

#[test]
fn test_build_sync_closure_plan_adds_primary_even_when_absent_from_roots() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep = temp_dir.path().join("dep");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep).expect("create dep");

    // Deliberately omit project_root from sync_roots list.
    let plan = build_sync_closure_plan(
        std::slice::from_ref(&dep),
        &project_root,
        "hash_auto_add",
        &policy,
    );
    let has_primary = plan.iter().any(|e| e.is_primary);
    assert!(
        has_primary,
        "primary root must be auto-added to plan even when not in sync_roots"
    );
    let primary = plan.iter().find(|e| e.is_primary).unwrap();
    assert_eq!(primary.root_hash, "hash_auto_add");
}

#[test]
fn test_sync_root_outcome_diagnostic_counting() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep_a = temp_dir.path().join("dep_a");
    let dep_b = temp_dir.path().join("dep_b");
    let dep_c = temp_dir.path().join("dep_c");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep_a).expect("create dep_a");
    std::fs::create_dir_all(&dep_b).expect("create dep_b");
    std::fs::create_dir_all(&dep_c).expect("create dep_c");

    let plan = build_sync_closure_plan(
        &[
            dep_a.clone(),
            dep_b.clone(),
            dep_c.clone(),
            project_root.clone(),
        ],
        &project_root,
        "diag_hash",
        &policy,
    );

    // Simulate outcomes: primary synced, one dep synced, one skipped, one failed.
    let outcomes: Vec<(&SyncClosurePlanEntry, SyncRootOutcome)> = plan
        .iter()
        .map(|entry| {
            let outcome = if entry.is_primary || entry.local_root.ends_with("dep_a") {
                SyncRootOutcome::Synced
            } else if entry.local_root.ends_with("dep_b") {
                SyncRootOutcome::Skipped {
                    reason: "size too small".to_string(),
                }
            } else {
                SyncRootOutcome::Failed {
                    error: "rsync timeout".to_string(),
                }
            };
            (entry, outcome)
        })
        .collect();

    let failed_count = outcomes
        .iter()
        .filter(|(_, o)| !matches!(o, SyncRootOutcome::Synced))
        .count();
    assert_eq!(
        failed_count, 2,
        "skipped + failed should count as non-synced"
    );

    let synced_count = outcomes
        .iter()
        .filter(|(_, o)| matches!(o, SyncRootOutcome::Synced))
        .count();
    assert_eq!(synced_count, 2, "primary + dep_a should be synced");
}

#[test]
fn test_build_sync_closure_manifest_serializes_to_json() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("project");
    let dep = temp_dir.path().join("dep");
    std::fs::create_dir_all(&project_root).expect("create project root");
    std::fs::create_dir_all(&dep).expect("create dep");

    let plan = build_sync_closure_plan(
        &[dep.clone(), project_root.clone()],
        &project_root,
        "serial_hash",
        &policy,
    );
    let manifest = build_sync_closure_manifest(&plan, &project_root);

    let json = serde_json::to_string_pretty(&manifest).expect("manifest should serialize to JSON");
    assert!(
        json.contains("rch.sync_closure_manifest.v2"),
        "JSON must contain schema_version"
    );
    assert!(
        json.contains("serial_hash"),
        "JSON must contain the primary root hash"
    );
    assert!(
        json.contains("\"is_primary\": true"),
        "JSON must contain primary flag"
    );

    // Roundtrip: deserialize should also work for consumers.
    let parsed: serde_json::Value =
        serde_json::from_str(&json).expect("manifest JSON should be valid");
    let entries = parsed["entries"]
        .as_array()
        .expect("entries should be an array");
    assert_eq!(entries.len(), plan.len());
}

// ── Closure topology validation tests (bd-vvmd.2.3 AC3) ──

#[test]
fn test_is_within_sync_topology_accepts_canonical_root() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    let path = PathBuf::from("/data/projects/my_project");
    assert!(
        is_within_sync_topology(&path, &policy),
        "paths under /data/projects should be accepted"
    );
}

#[test]
fn test_is_within_sync_topology_accepts_alias_root() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    let path = PathBuf::from("/dp/my_project");
    assert!(
        is_within_sync_topology(&path, &policy),
        "paths under /dp alias should be accepted"
    );
}

#[test]
fn test_is_within_sync_topology_rejects_outside_paths() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    assert!(
        !is_within_sync_topology(Path::new("/tmp/evil"), &policy),
        "/tmp paths should be rejected"
    );
    assert!(
        !is_within_sync_topology(Path::new("/home/user/project"), &policy),
        "/home paths should be rejected"
    );
    assert!(
        !is_within_sync_topology(Path::new("/var/lib/data"), &policy),
        "/var paths should be rejected"
    );
}

#[test]
fn test_build_sync_closure_plan_excludes_out_of_topology_roots() {
    let _guard = test_guard!();
    // Use paths under /data/projects (canonical root) for valid paths,
    // and a /tmp path for the invalid one. Since these dirs may not exist
    // on the test runner, the canonicalization will fall back to the raw
    // path, which is exactly what we want to test.
    let project_root = PathBuf::from("/data/projects/test_proj");
    let valid_dep = PathBuf::from("/data/projects/valid_dep");
    let invalid_dep = PathBuf::from("/tmp/not_allowed");

    let plan = build_sync_closure_plan(
        &[valid_dep.clone(), invalid_dep.clone(), project_root.clone()],
        &project_root,
        "topo_hash",
        &PathTopologyPolicy::default(),
    );

    // The plan should contain the primary root and valid dep, but NOT the invalid dep.
    let plan_paths: Vec<_> = plan.iter().map(|e| &e.local_root).collect();
    assert!(
        plan_paths
            .iter()
            .any(|p| p.starts_with("/data/projects/test_proj")),
        "primary root must be in plan"
    );
    assert!(
        plan_paths
            .iter()
            .any(|p| p.starts_with("/data/projects/valid_dep")),
        "valid dependency root must be in plan"
    );
    assert!(
        !plan_paths.iter().any(|p| p.starts_with("/tmp")),
        "out-of-topology dependency must be excluded from plan"
    );
}

#[test]
fn test_build_sync_closure_plan_topology_filter_preserves_primary() {
    let _guard = test_guard!();
    // Even with all deps invalid, the primary root must survive.
    let project_root = PathBuf::from("/data/projects/primary_proj");
    let bad_dep_a = PathBuf::from("/home/user/dep_a");
    let bad_dep_b = PathBuf::from("/var/lib/dep_b");

    let plan = build_sync_closure_plan(
        &[bad_dep_a, bad_dep_b],
        &project_root,
        "lonely_hash",
        &PathTopologyPolicy::default(),
    );

    assert_eq!(plan.len(), 1, "only the primary root should remain");
    assert!(
        plan[0].is_primary,
        "surviving entry must be the primary root"
    );
}

// ── bd-3jjc.6: canonicalize_sync_root_for_plan() edge cases ─────────

#[test]
fn test_canonicalize_existing_path() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let dir = temp_dir.path().join("real_dir");
    std::fs::create_dir_all(&dir).expect("create dir");

    let result = canonicalize_sync_root_for_plan(&dir, &policy);
    // Should be a canonical absolute path containing the dir name.
    assert!(result.is_absolute());
    assert!(
        result.to_string_lossy().contains("real_dir"),
        "canonicalized path should contain dir name: {}",
        result.display()
    );
}

#[test]
fn test_canonicalize_nonexistent_path() {
    let _guard = test_guard!();
    let path = PathBuf::from("/data/projects/does_not_exist_xyz_12345");
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    let result = canonicalize_sync_root_for_plan(&path, &policy);
    // Fallback: should return original path since normalize and canonicalize both fail.
    assert_eq!(result, path);
}

#[test]
fn test_canonicalize_trailing_slash() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let dir = temp_dir.path().join("trail");
    std::fs::create_dir_all(&dir).expect("create dir");

    let with_trailing = PathBuf::from(format!("{}/", dir.display()));
    let without_trailing = canonicalize_sync_root_for_plan(&dir, &policy);
    let with_result = canonicalize_sync_root_for_plan(&with_trailing, &policy);
    // Both should resolve to the same canonical path.
    assert_eq!(with_result, without_trailing);
}

#[cfg(unix)]
#[test]
fn test_canonicalize_symlink() {
    let _guard = test_guard!();
    use std::os::unix::fs::symlink;

    let (temp_dir, policy) = topology_tempdir();
    let real_dir = temp_dir.path().join("real");
    let link_dir = temp_dir.path().join("link");
    std::fs::create_dir_all(&real_dir).expect("create real dir");
    symlink(&real_dir, &link_dir).expect("create symlink");

    let from_real = canonicalize_sync_root_for_plan(&real_dir, &policy);
    let from_link = canonicalize_sync_root_for_plan(&link_dir, &policy);
    assert_eq!(
        from_real, from_link,
        "symlink and real path should canonicalize to the same path"
    );
}

#[test]
fn test_canonicalize_dp_alias() {
    let _guard = test_guard!();
    // /dp is an alias for /data/projects on the maintainer's dev host.
    // This test is environment-dependent: only meaningful when BOTH the
    // alias and the canonical target exist and the concrete subdir
    // (`remote_compilation_helper`) is present under each.
    //
    // Using `Path::exists()` alone isn't robust — CI runners occasionally
    // have a `/dp` inode that doesn't resolve through `canonicalize`
    // (broken or partially-populated mount). Guard on canonicalization
    // success of the actual input path instead, and skip otherwise.
    let dp_path = PathBuf::from("/dp/remote_compilation_helper");
    let canonical_expected = PathBuf::from("/data/projects/remote_compilation_helper");
    let (Ok(dp_canonical), true) = (std::fs::canonicalize(&dp_path), canonical_expected.exists())
    else {
        return;
    };
    if dp_canonical != canonical_expected {
        // Alias target exists but points somewhere else on this host —
        // nothing to assert here.
        return;
    }

    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    let result = canonicalize_sync_root_for_plan(&dp_path, &policy);
    assert_eq!(
        result, canonical_expected,
        "/dp alias should resolve to /data/projects"
    );
}

// ── bd-3jjc.7: is_within_sync_topology() edge cases ─────────────────

#[test]
fn test_topology_deeply_nested_accepted() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    let path = PathBuf::from("/data/projects/a/b/c/d/e/f/g");
    assert!(
        is_within_sync_topology(&path, &policy),
        "deeply nested /data/projects subpaths should be accepted"
    );
}

#[test]
fn test_topology_exact_root_match() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    // The exact root (/data/projects itself) should be accepted.
    assert!(
        is_within_sync_topology(Path::new("/data/projects"), &policy),
        "/data/projects itself should be accepted"
    );
    assert!(
        is_within_sync_topology(Path::new("/dp"), &policy),
        "/dp itself should be accepted"
    );
}

#[test]
fn test_topology_parent_of_root_rejected() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    assert!(
        !is_within_sync_topology(Path::new("/data"), &policy),
        "/data (parent of root) should be rejected"
    );
}

#[test]
fn test_topology_prefix_collision_rejected() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    // /data/projects_extra starts with /data/projects as a string prefix
    // but is NOT a child path. Path::starts_with uses component-based matching.
    assert!(
        !is_within_sync_topology(Path::new("/data/projects_extra"), &policy),
        "/data/projects_extra should be rejected (not a child path)"
    );
}

#[test]
fn test_topology_empty_path_rejected() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    assert!(
        !is_within_sync_topology(Path::new(""), &policy),
        "empty path should be rejected"
    );
}

#[test]
fn test_topology_root_slash_rejected() {
    let _guard = test_guard!();
    let policy = rch_common::path_topology::PathTopologyPolicy::default();
    assert!(
        !is_within_sync_topology(Path::new("/"), &policy),
        "root path (/) should be rejected"
    );
}

// ── bd-3jjc.8: build_sync_closure_plan() edge cases ─────────────────

#[test]
fn test_plan_empty_sync_roots() {
    let _guard = test_guard!();
    let project_root = PathBuf::from("/data/projects/solo_project");
    let plan = build_sync_closure_plan(
        &[],
        &project_root,
        "solo_hash",
        &PathTopologyPolicy::default(),
    );
    assert_eq!(
        plan.len(),
        1,
        "empty sync_roots should produce single primary entry"
    );
    assert!(plan[0].is_primary);
    assert_eq!(plan[0].root_hash, "solo_hash");
}

#[test]
fn test_plan_primary_is_only_root() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("only");
    std::fs::create_dir_all(&project_root).expect("create dir");

    let plan = build_sync_closure_plan(
        std::slice::from_ref(&project_root),
        &project_root,
        "only_hash",
        &policy,
    );
    assert_eq!(plan.len(), 1);
    assert!(plan[0].is_primary);
    assert_eq!(plan[0].root_hash, "only_hash");
}

#[test]
fn test_plan_large_root_set() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("main_proj");
    std::fs::create_dir_all(&project_root).expect("create main");

    let mut roots = Vec::new();
    for i in 0..100u32 {
        let dep = temp_dir.path().join(format!("dep_{i:04}"));
        std::fs::create_dir_all(&dep).expect("create dep");
        roots.push(dep);
    }
    roots.push(project_root.clone());

    let start = std::time::Instant::now();
    let plan = build_sync_closure_plan(&roots, &project_root, "large_hash", &policy);
    let elapsed = start.elapsed();

    // 100 deps + 1 primary (deduped) = 101 entries.
    assert_eq!(plan.len(), 101);
    assert!(
        elapsed.as_millis() < 500,
        "plan build took too long: {elapsed:?}"
    );

    // Verify lexicographic ordering.
    for window in plan.windows(2) {
        assert!(
            window[0].local_root <= window[1].local_root,
            "plan should be lexicographically ordered: {} > {}",
            window[0].local_root.display(),
            window[1].local_root.display(),
        );
    }
}

#[test]
fn test_plan_duplicate_roots_deduped() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("proj");
    let dep = temp_dir.path().join("dep");
    std::fs::create_dir_all(&project_root).expect("create proj");
    std::fs::create_dir_all(&dep).expect("create dep");

    let plan = build_sync_closure_plan(
        &[dep.clone(), dep.clone(), dep.clone(), project_root.clone()],
        &project_root,
        "dup_hash",
        &policy,
    );

    // dep appears 3 times in input but should be deduped to 1 entry + primary = 2.
    assert_eq!(plan.len(), 2, "duplicate roots should be deduped");
}

#[test]
fn test_plan_primary_via_dp_alias_canonical() {
    let _guard = test_guard!();
    // Verify /dp/X resolves to /data/projects/X — but only when the
    // maintainer's alias layout is actually present. `Path::exists`
    // alone is too permissive (some CI images have a broken `/dp`
    // node that `canonicalize` refuses).
    let dp_path = PathBuf::from("/dp/remote_compilation_helper");
    let Ok(canonical) = std::fs::canonicalize(&dp_path) else {
        return;
    };
    let plan = build_sync_closure_plan(&[], &dp_path, "dp_hash", &PathTopologyPolicy::default());
    assert_eq!(plan.len(), 1);
    assert!(plan[0].is_primary);
    assert_eq!(
        plan[0].local_root, canonical,
        "primary via /dp alias should canonicalize to the alias target"
    );
    assert_eq!(
        plan[0].remote_root, "/data/projects/remote_compilation_helper",
        "remote root should stay in worker canonical topology"
    );
}

#[test]
fn test_build_sync_closure_plan_maps_alias_target_roots_to_worker_canonical_topology() {
    let _guard = test_guard!();
    if let Ok(local_projects_root) = std::fs::canonicalize("/dp") {
        let project_root = local_projects_root.join("frankenterm");
        let dep_root = local_projects_root.join("frankentui");

        let plan = build_sync_closure_plan(
            &[dep_root.clone(), project_root.clone()],
            &project_root,
            "mapped_hash",
            &PathTopologyPolicy::default(),
        );

        assert!(
            plan.iter().any(|entry| entry.local_root == project_root
                && entry.remote_root == "/data/projects/frankenterm"),
            "primary root should map back to worker canonical topology"
        );
        assert!(
            plan.iter().any(|entry| entry.local_root == dep_root
                && entry.remote_root == "/data/projects/frankentui"),
            "dependency root should map back to worker canonical topology"
        );
    }
}

#[test]
fn test_plan_entry_ordering_is_lexicographic() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("proj");
    let dep_z = temp_dir.path().join("z_dep");
    let dep_a = temp_dir.path().join("a_dep");
    let dep_m = temp_dir.path().join("m_dep");
    std::fs::create_dir_all(&project_root).expect("create proj");
    std::fs::create_dir_all(&dep_z).expect("create dep_z");
    std::fs::create_dir_all(&dep_a).expect("create dep_a");
    std::fs::create_dir_all(&dep_m).expect("create dep_m");

    let plan = build_sync_closure_plan(
        &[dep_z, dep_a, dep_m, project_root.clone()],
        &project_root,
        "order_hash",
        &policy,
    );

    for window in plan.windows(2) {
        assert!(
            window[0].local_root <= window[1].local_root,
            "entries must be lexicographically sorted"
        );
    }
}

// ── bd-3jjc.9: build_sync_closure_manifest() edge cases ─────────────

#[test]
fn test_manifest_empty_plan() {
    let _guard = test_guard!();
    let project_root = PathBuf::from("/data/projects/empty_proj");
    let manifest = build_sync_closure_manifest(&[], &project_root);
    assert_eq!(manifest.entries.len(), 0);
    assert_eq!(manifest.project_root, "/data/projects/empty_proj");
    assert_eq!(manifest.schema_version, "rch.sync_closure_manifest.v2");
}

#[test]
fn test_manifest_generated_at_is_recent() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("proj");
    std::fs::create_dir_all(&project_root).expect("create proj");

    let before_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let plan = build_sync_closure_plan(
        std::slice::from_ref(&project_root),
        &project_root,
        "ts_hash",
        &policy,
    );
    let manifest = build_sync_closure_manifest(&plan, &project_root);
    let after_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    assert!(
        manifest.generated_at_unix_ms >= before_ms,
        "generated_at should be >= start time"
    );
    assert!(
        manifest.generated_at_unix_ms <= after_ms,
        "generated_at should be <= end time"
    );
}

#[test]
fn test_manifest_order_field_sequential() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let project_root = temp_dir.path().join("proj");
    std::fs::create_dir_all(&project_root).expect("create proj");

    let mut roots = Vec::new();
    for i in 0..10u32 {
        let dep = temp_dir.path().join(format!("dep_{i:02}"));
        std::fs::create_dir_all(&dep).expect("create dep");
        roots.push(dep);
    }
    roots.push(project_root.clone());

    let plan = build_sync_closure_plan(&roots, &project_root, "seq_hash", &policy);
    let manifest = build_sync_closure_manifest(&plan, &project_root);

    // Order field should be 1-indexed and sequential.
    for (idx, entry) in manifest.entries.iter().enumerate() {
        assert_eq!(
            entry.order,
            idx + 1,
            "order should be 1-indexed sequential, got {} at position {}",
            entry.order,
            idx
        );
    }
}

#[test]
fn test_manifest_unicode_paths() {
    let _guard = test_guard!();
    // Use synthetic plan entries with unicode paths.
    let entries = vec![SyncClosurePlanEntry {
        local_root: PathBuf::from("/data/projects/日本語プロジェクト"),
        remote_root: "/data/projects/日本語プロジェクト".to_string(),
        project_id: "日本語".to_string(),
        root_hash: "unicode_hash".to_string(),
        is_primary: true,
        mode: SyncClosureMode::Full,
    }];
    let manifest =
        build_sync_closure_manifest(&entries, Path::new("/data/projects/日本語プロジェクト"));
    assert_eq!(manifest.entries.len(), 1);
    assert!(manifest.entries[0].local_root.contains("日本語"));

    // Verify JSON serialization handles unicode.
    let json = serde_json::to_string(&manifest).expect("should serialize unicode");
    assert!(json.contains("日本語"));
}

#[test]
fn test_manifest_long_strings() {
    let _guard = test_guard!();
    let long_id = "x".repeat(10_000);
    let long_hash = "h".repeat(10_000);
    let entries = vec![SyncClosurePlanEntry {
        local_root: PathBuf::from("/data/projects/long_test"),
        remote_root: "/data/projects/long_test".to_string(),
        project_id: long_id.clone(),
        root_hash: long_hash.clone(),
        is_primary: true,
        mode: SyncClosureMode::Full,
    }];
    let manifest = build_sync_closure_manifest(&entries, Path::new("/data/projects/long_test"));
    assert_eq!(
        manifest.entries[0].project_id, long_id,
        "project_id should not be truncated"
    );
    assert_eq!(
        manifest.entries[0].root_hash, long_hash,
        "root_hash should not be truncated"
    );
}

// ── bd-3jjc.10: SyncRootOutcome variant coverage ────────────────────

#[test]
fn test_sync_root_outcome_all_synced() {
    let _guard = test_guard!();
    let outcomes: Vec<SyncRootOutcome> = (0..5).map(|_| SyncRootOutcome::Synced).collect();
    let non_synced = outcomes
        .iter()
        .filter(|o| !matches!(o, SyncRootOutcome::Synced))
        .count();
    assert_eq!(non_synced, 0);
}

#[test]
fn test_sync_root_outcome_all_failed() {
    let _guard = test_guard!();
    let outcomes: Vec<SyncRootOutcome> = (0..3)
        .map(|i| SyncRootOutcome::Failed {
            error: format!("error_{i}"),
        })
        .collect();
    let failed_count = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
        .count();
    assert_eq!(failed_count, 3);

    // Verify error messages are preserved.
    let errors: Vec<&str> = outcomes
        .iter()
        .filter_map(|o| match o {
            SyncRootOutcome::Failed { error } => Some(error.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(errors, vec!["error_0", "error_1", "error_2"]);
}

#[test]
fn test_sync_root_outcome_all_skipped() {
    let _guard = test_guard!();
    let outcomes: Vec<SyncRootOutcome> = (0..4)
        .map(|i| SyncRootOutcome::Skipped {
            reason: format!("reason_{i}"),
        })
        .collect();
    let skipped_count = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
        .count();
    assert_eq!(skipped_count, 4);
}

#[test]
fn test_sync_root_outcome_empty_collection() {
    let _guard = test_guard!();
    let outcomes: Vec<SyncRootOutcome> = vec![];
    let synced = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Synced))
        .count();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
        .count();
    let skipped = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
        .count();
    assert_eq!(synced, 0);
    assert_eq!(failed, 0);
    assert_eq!(skipped, 0);
}

#[test]
fn test_sync_root_outcome_mixed_with_reasons() {
    let _guard = test_guard!();
    let outcomes = [
        SyncRootOutcome::Synced,
        SyncRootOutcome::Synced,
        SyncRootOutcome::Skipped {
            reason: "stale".to_string(),
        },
        SyncRootOutcome::Failed {
            error: "timeout".to_string(),
        },
        SyncRootOutcome::Skipped {
            reason: "denied".to_string(),
        },
    ];

    let synced = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Synced))
        .count();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Failed { .. }))
        .count();
    let skipped = outcomes
        .iter()
        .filter(|o| matches!(o, SyncRootOutcome::Skipped { .. }))
        .count();

    assert_eq!(synced, 2);
    assert_eq!(failed, 1);
    assert_eq!(skipped, 2);

    // Verify reason extraction.
    let skip_reasons: Vec<&str> = outcomes
        .iter()
        .filter_map(|o| match o {
            SyncRootOutcome::Skipped { reason } => Some(reason.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(skip_reasons, vec!["stale", "denied"]);

    let error_msgs: Vec<&str> = outcomes
        .iter()
        .filter_map(|o| match o {
            SyncRootOutcome::Failed { error } => Some(error.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(error_msgs, vec!["timeout"]);
}

// ── bd-3jjc.13: E2E sync closure plan + manifest generation ─────────

#[test]
fn test_e2e_sync_closure_plan_and_manifest() {
    let _guard = test_guard!();
    let (temp_dir, policy) = topology_tempdir();
    let primary = temp_dir.path().join("primary_project");
    let dep_a = temp_dir.path().join("dep_a");
    let dep_b = temp_dir.path().join("dep_b");
    std::fs::create_dir_all(&primary).expect("create primary");
    std::fs::create_dir_all(&dep_a).expect("create dep_a");
    std::fs::create_dir_all(&dep_b).expect("create dep_b");

    // Step 2: Build plan with valid deps + an out-of-topology sentinel
    // that must be filtered. Pick any path that lies outside the
    // `topology_tempdir` root — `/var/empty` exists on Linux & macOS
    // and is not under our scratch area.
    let out_of_topology = PathBuf::from("/var/empty/invalid_dep");
    let plan = build_sync_closure_plan(
        &[
            primary.clone(),
            dep_a.clone(),
            dep_b.clone(),
            out_of_topology.clone(),
        ],
        &primary,
        "e2e_hash",
        &policy,
    );

    // Step 3: 3 entries (primary, dep_a, dep_b), out-of-topology excluded.
    assert_eq!(
        plan.len(),
        3,
        "plan should have 3 entries (primary + 2 deps), got {}",
        plan.len()
    );
    let out_of_topology_str = out_of_topology.to_string_lossy().to_string();
    assert!(
        !plan
            .iter()
            .any(|e| e.local_root.to_string_lossy() == out_of_topology_str),
        "out-of-topology dep should be excluded by topology filter"
    );

    // Step 4: Verify lexicographic ordering.
    for window in plan.windows(2) {
        assert!(
            window[0].local_root <= window[1].local_root,
            "plan entries should be lexicographically sorted"
        );
    }

    // Step 5: Primary entry has is_primary=true with correct hash.
    let primary_entry = plan
        .iter()
        .find(|e| e.is_primary)
        .expect("primary must exist");
    assert_eq!(primary_entry.root_hash, "e2e_hash");
    let non_primary: Vec<_> = plan.iter().filter(|e| !e.is_primary).collect();
    assert_eq!(non_primary.len(), 2, "should have 2 non-primary entries");

    // Step 6-7: Generate manifest.
    let before_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let manifest = build_sync_closure_manifest(&plan, &primary);
    let after_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    assert_eq!(manifest.schema_version, "rch.sync_closure_manifest.v2");
    assert_eq!(manifest.entries.len(), 3);
    assert!(manifest.generated_at_unix_ms >= before_ms);
    assert!(manifest.generated_at_unix_ms <= after_ms);

    // Step 8-9: JSON roundtrip.
    let json = serde_json::to_string_pretty(&manifest).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    let entries = parsed["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 3);

    // Step 10: Verify order fields are 1-indexed sequential.
    for (idx, entry) in manifest.entries.iter().enumerate() {
        assert_eq!(entry.order, idx + 1, "order should be 1-indexed sequential");
        assert_eq!(entry.is_primary, plan[idx].is_primary);
        assert_eq!(entry.root_hash, plan[idx].root_hash);
    }
}

// ── bd-3jjc.15: E2E topology validation with symlinks ───────────────

#[cfg(unix)]
#[test]
fn test_e2e_topology_validation_with_symlinks() {
    let _guard = test_guard!();
    use std::os::unix::fs::symlink;

    let (temp_dir, policy) = topology_tempdir();
    let valid_root = temp_dir.path().join("valid_root");
    let valid_sub = valid_root.join("sub");
    std::fs::create_dir_all(&valid_sub).expect("create valid_root/sub");

    let primary = temp_dir.path().join("primary");
    std::fs::create_dir_all(&primary).expect("create primary");

    // Create symlink alias within the same tempdir.
    let alias_link = temp_dir.path().join("alias_for_valid");
    symlink(&valid_root, &alias_link).expect("create symlink");

    // Build plan with mixed valid/invalid/alias paths. Rejection paths
    // are deliberately under system roots that won't overlap with the
    // `topology_tempdir` scratch area (which itself lives under
    // `/tmp/.tmpXXXX` on Linux or `/var/folders/...` on macOS).
    let reject_a = PathBuf::from("/etc/rch_should_reject");
    let reject_b = PathBuf::from("/usr/local/fake_project");
    let reject_c = PathBuf::from("/opt/fake_thing");
    let plan = build_sync_closure_plan(
        &[
            valid_root.clone(),
            alias_link.clone(), // should dedup with valid_root
            reject_a.clone(),
            reject_b.clone(),
            reject_c.clone(),
            primary.clone(),
        ],
        &primary,
        "topo_e2e_hash",
        &policy,
    );

    // Should contain primary + valid_root (deduped with alias) = 2 entries.
    assert_eq!(
        plan.len(),
        2,
        "plan should have 2 entries (primary + deduped valid_root), got {}",
        plan.len()
    );

    // Verify the three explicit rejection paths were excluded.
    let reject_strs: Vec<String> = [reject_a, reject_b, reject_c]
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    for entry in &plan {
        let path_str = entry.local_root.to_string_lossy().to_string();
        assert!(
            !reject_strs.contains(&path_str),
            "out-of-topology path should not appear in plan: {}",
            path_str
        );
    }

    // Verify alias was deduplicated (only one entry for valid_root).
    let valid_canonical = std::fs::canonicalize(&valid_root).expect("canonicalize");
    let matching_entries = plan
        .iter()
        .filter(|e| {
            std::fs::canonicalize(&e.local_root)
                .map(|c| c == valid_canonical)
                .unwrap_or(false)
        })
        .count();
    assert_eq!(
        matching_entries, 1,
        "symlink alias should be deduplicated with canonical path"
    );

    // Verify primary is present.
    assert!(
        plan.iter().any(|e| e.is_primary),
        "primary root must always be in plan"
    );
}

// =========================================================================
// Regression suite: Classification timing budget & edge cases (bd-vvmd.2.9)
// =========================================================================

/// Verify classification completes well within the 5ms panic threshold for
/// compilation commands, and within 1ms for non-compilation commands.
/// This acts as a regression gate: if any code change blows the budget,
/// this test catches it.
#[test]
fn test_classification_timing_budget_non_compilation() {
    let _guard = test_guard!();
    let non_compilation_cmds = [
        "ls -la",
        "pwd",
        "git status",
        "echo hello world",
        "cat Cargo.toml",
        "npm install",
        "python main.py",
        "docker build -t myapp .",
        "mkdir -p build",
        "rm -rf target/",
    ];

    for cmd in non_compilation_cmds {
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = classify_command(cmd);
        }
        let elapsed = start.elapsed();
        let per_call_us = elapsed.as_micros() / 100;
        // Non-compilation: budget <1ms, panic at 5ms
        // We check the median is under 1ms (1000us)
        assert!(
            per_call_us < 1000,
            "Non-compilation command {:?} exceeded 1ms budget: {}us per call",
            cmd,
            per_call_us
        );
    }
}

#[test]
fn test_classification_timing_budget_compilation() {
    let _guard = test_guard!();
    let compilation_cmds = [
        "cargo build --release",
        "cargo test --workspace",
        "cargo clippy --all-targets",
        "gcc -c main.c -o main.o",
        "make -j8",
        "bun test",
        "rustc main.rs",
        "ninja -j4",
    ];

    for cmd in compilation_cmds {
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let _ = classify_command(cmd);
        }
        let elapsed = start.elapsed();
        let per_call_us = elapsed.as_micros() / 100;
        // Compilation: budget <5ms, panic at 10ms
        assert!(
            per_call_us < 5000,
            "Compilation command {:?} exceeded 5ms budget: {}us per call",
            cmd,
            per_call_us
        );
    }
}

/// Verify that process_hook handles compilation commands correctly when
/// daemon is absent — the classification MUST work, and the hook MUST
/// fail-open to allow local execution.
#[tokio::test]
async fn test_hook_classification_fail_open_all_compilation_kinds() {
    let _lock = test_lock().lock().await;
    mock::set_mock_enabled_override(Some(false));

    let compilation_commands = [
        ("cargo build --release", "CargoBuild"),
        ("cargo test --workspace", "CargoTest"),
        ("cargo check --all-targets", "CargoCheck"),
        ("cargo clippy", "CargoClippy"),
        ("cargo doc --no-deps", "CargoDoc"),
        ("cargo run", "CargoRun"),
        ("cargo bench", "CargoBench"),
        ("cargo nextest run", "CargoNextest"),
        ("bun test", "BunTest"),
        ("bun typecheck", "BunTypecheck"),
    ];

    for (cmd, label) in compilation_commands {
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: cmd.to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(
            output.is_allow(),
            "Hook should fail-open for {} ({}) when daemon absent",
            label,
            cmd
        );
    }

    mock::set_mock_enabled_override(None);
}

/// Verify that non-compilation commands pass through the hook immediately
/// (are allowed without daemon interaction).
#[tokio::test]
async fn test_hook_non_compilation_passthrough() {
    let non_compilation = [
        "ls -la",
        "git status",
        "cargo fmt --check",
        "cargo install ripgrep",
        "bun install",
        "bun run dev",
        "echo hello",
        "cat Cargo.toml",
    ];

    for cmd in non_compilation {
        let input = HookInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInput {
                command: cmd.to_string(),
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(
            output.is_allow(),
            "Non-compilation command {:?} should pass through the hook (Allow)",
            cmd
        );
    }
}

/// Verify that non-Bash tool invocations are always allowed.
#[tokio::test]
async fn test_hook_non_bash_tools_always_allowed() {
    let tools = ["Read", "Write", "Edit", "Glob", "Grep", "WebSearch"];

    for tool in tools {
        let input = HookInput {
            tool_name: tool.to_string(),
            tool_input: ToolInput {
                command: "cargo build".to_string(), // Even compilation keyword
                description: None,
            },
            session_id: None,
        };

        let output = process_hook(input).await;
        assert!(
            output.is_allow(),
            "Non-Bash tool {:?} should always be allowed, even with compilation keyword",
            tool
        );
    }
}

/// Verify that classify_command_detailed produces valid structured output
/// for every tier decision path, enabling structured logging.
#[test]
fn test_structured_log_output_per_tier() {
    let _guard = test_guard!();

    // Tier 0 reject: empty command
    let d = classify_command_detailed("");
    assert_eq!(d.tiers.len(), 1);
    assert_eq!(d.tiers[0].tier, 0);
    assert_eq!(d.tiers[0].decision, TierDecision::Reject);
    assert!(!d.tiers[0].reason.is_empty());

    // Tier 1 reject: piped command
    let d = classify_command_detailed("cargo build | tee log");
    assert!(
        d.tiers
            .iter()
            .any(|t| t.tier == 1 && t.decision == TierDecision::Reject)
    );

    // Tier 2 reject: no keyword
    let d = classify_command_detailed("ls -la");
    assert!(
        d.tiers
            .iter()
            .any(|t| t.tier == 2 && t.decision == TierDecision::Reject)
    );

    // Tier 3 reject: never-intercept
    let d = classify_command_detailed("cargo install serde");
    assert!(
        d.tiers
            .iter()
            .any(|t| t.tier == 3 && t.decision == TierDecision::Reject)
    );

    // Tier 4 pass: full classification
    let d = classify_command_detailed("cargo build --release");
    assert!(
        d.tiers
            .iter()
            .any(|t| t.tier == 4 && t.decision == TierDecision::Pass)
    );
    assert!(d.classification.is_compilation);
    assert!(d.classification.confidence > 0.0);
    assert!(d.classification.kind.is_some());

    // Tier 4 reject: keyword present but no matching pattern
    let d = classify_command_detailed("cargo tree");
    assert!(
        d.tiers
            .iter()
            .any(|t| t.tier == 4 && t.decision == TierDecision::Reject)
    );
}
