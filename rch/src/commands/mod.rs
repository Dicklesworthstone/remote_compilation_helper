//! CLI command handler implementations.
//!
//! This module contains the actual business logic for each CLI subcommand.
//!
//! ## Module Organization
//!
//! - `types` - Response types for JSON output (WorkerInfo, etc.)
//! - Command handlers are implemented directly in this module

// Sub-modules
mod agents;
mod config;
mod config_doctor;
mod config_init;
mod daemon;
mod helpers;
mod hook;
mod init;
mod queue;
mod speedscore;
mod status;
pub mod types;
mod workers;
mod workers_deploy;
mod workers_init;
mod workers_setup;

// Re-export daemon commands for backward compatibility
pub use daemon::{
    daemon_logs, daemon_reload, daemon_restart, daemon_start, daemon_status, daemon_stop,
};

// Re-export hook commands for backward compatibility
pub use hook::{hook_install, hook_status, hook_test, hook_uninstall};

// Re-export status/diagnostics commands for backward compatibility
pub use status::{check, diagnose, self_test, status_overview};

// Re-export queue/cancel commands for backward compatibility
pub use queue::{cancel_build, queue_status};

// Re-export workers commands for backward compatibility
pub use workers::{
    workers_benchmark, workers_capabilities, workers_disable, workers_drain, workers_enable,
    workers_list, workers_probe,
};

// Re-export agents commands for backward compatibility
pub use agents::{agents_install_hook, agents_list, agents_status, agents_uninstall_hook};

// Re-export config commands for backward compatibility
pub use config::{
    config_diff, config_edit, config_export, config_get, config_lint, config_reset, config_set,
    config_show, config_validate,
};
pub use config_doctor::{ConfigDoctorResponse, config_doctor};
pub use config_init::config_init;

// Re-export speedscore command for backward compatibility
pub use speedscore::speedscore;

// Re-export workers init/discover commands for backward compatibility
pub use workers_init::{workers_discover, workers_init};

// Re-export workers deploy command for backward compatibility
pub use workers_deploy::workers_deploy_binary;

// Re-export workers setup commands for backward compatibility
pub use workers_setup::{workers_setup, workers_sync_toolchain};

// Re-export init wizard for backward compatibility
pub use init::init_wizard;

// Re-export types for backward compatibility
pub use types::*;

// Re-export config helpers from helpers module (single source of truth)
#[cfg(test)]
pub(crate) use helpers::set_test_config_dir_override;
pub use helpers::{config_dir, load_workers_from_config};

// Re-export commonly used helpers
#[cfg(not(unix))]
use crate::error::PlatformError;
use anyhow::Result;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;

// Note: Response types (WorkerInfo, WorkersListResponse, etc.) are now in types.rs
// and re-exported via `pub use types::*` at the top of this module.
// Helper functions (runtime_label, version helpers, SSH helpers, etc.) are in helpers.rs.
// Worker-specific helpers (has_any_capabilities, probe_local_capabilities,
// collect_local_capability_warnings, etc.) are in workers.rs.

// =============================================================================
// Diagnose Command
// =============================================================================

#[derive(Debug, Clone, Deserialize)]
struct DaemonHealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
}

#[cfg(not(unix))]
async fn query_daemon_health(_socket_path: &str) -> Result<DaemonHealthResponse> {
    Err(PlatformError::UnixOnly {
        feature: "daemon health check".to_string(),
    })?
}

#[cfg(unix)]
async fn query_daemon_health(socket_path: &str) -> Result<DaemonHealthResponse> {
    let stream = UnixStream::connect(socket_path).await?;
    let (reader, mut writer) = stream.into_split();

    let request = "GET /health\n";
    writer.write_all(request.as_bytes()).await?;
    writer.flush().await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut body = String::new();
    let mut in_body = false;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        if in_body {
            body.push_str(&line);
        } else if line.trim().is_empty() {
            in_body = true;
        }
    }

    let health: DaemonHealthResponse = serde_json::from_str(body.trim())?;
    Ok(health)
}

// NOTE: build_dry_run_summary and diagnose moved to status.rs

// Re-export send_daemon_command from helpers (single source of truth)
pub(crate) use helpers::send_daemon_command;

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::helpers::{
        default_socket_path, extract_version_numbers, indent_lines, major_minor_version,
        major_version, major_version_mismatch, runtime_label, rust_version_mismatch,
        urlencoding_encode,
    };
    use super::status::{build_diagnose_decision, build_dry_run_summary};
    use super::workers::{
        collect_local_capability_warnings, has_any_capabilities, summarize_capabilities,
    };
    use super::*;
    use crate::status_types::{WorkerCapabilitiesFromApi, format_bytes};
    use crate::ui::context::{OutputConfig, OutputContext, OutputMode};
    use crate::ui::writer::SharedOutputBuffer;
    use rch_common::test_guard;
    use rch_common::{ApiError, ApiResponse, ErrorCode, WorkerCapabilities, WorkerConfig};
    use rch_common::{Classification, CompilationKind, RequiredRuntime, WorkerId};
    use rch_common::{SelectedWorker, SelectionReason};
    use serde::Serialize;
    use std::path::PathBuf;

    struct TestConfigDirGuard;

    impl TestConfigDirGuard {
        fn new(path: PathBuf) -> Self {
            set_test_config_dir_override(Some(path));
            Self
        }
    }

    impl Drop for TestConfigDirGuard {
        fn drop(&mut self) {
            set_test_config_dir_override(None);
        }
    }

    fn json_test_context() -> (OutputContext, SharedOutputBuffer) {
        let stdout_buf = SharedOutputBuffer::new();
        let stderr_buf = SharedOutputBuffer::new();
        let ctx = OutputContext::with_writers(
            OutputConfig {
                force_mode: Some(OutputMode::Json),
                ..Default::default()
            },
            stdout_buf.as_writer(false),
            stderr_buf.as_writer(false),
        );
        (ctx, stdout_buf)
    }

    // -------------------------------------------------------------------------
    // ApiResponse Tests
    // -------------------------------------------------------------------------

    #[test]
    fn api_response_ok_creates_success_response() {
        let _guard = test_guard!();
        let response = ApiResponse::ok("test cmd", "test data".to_string());
        assert!(response.success);
        assert_eq!(response.command, Some("test cmd".to_string()));
        assert_eq!(response.api_version, "1.0");
        assert!(response.data.is_some());
        assert_eq!(response.data.unwrap(), "test data");
        assert!(response.error.is_none());
    }

    #[test]
    fn api_response_err_creates_error_response() {
        let _guard = test_guard!();
        let response: ApiResponse<()> =
            ApiResponse::err("failed cmd", ApiError::internal("error message"));
        assert!(!response.success);
        assert_eq!(response.command, Some("failed cmd".to_string()));
        assert!(response.data.is_none());
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, "RCH-E504"); // InternalStateError
    }

    #[test]
    fn api_response_err_with_specific_error_code() {
        let _guard = test_guard!();
        let response: ApiResponse<()> = ApiResponse::err(
            "cmd",
            ApiError::new(ErrorCode::SshConnectionFailed, "Worker not available"),
        );
        assert!(!response.success);
        assert!(response.error.is_some());
        let error = response.error.unwrap();
        assert_eq!(error.code, "RCH-E100"); // SshConnectionFailed
    }

    #[test]
    fn api_response_ok_serializes_without_error_field() {
        let _guard = test_guard!();
        let response = ApiResponse::ok("test", "data".to_string());
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("error").is_none());
        assert_eq!(json["data"], "data");
        assert!(json["success"].as_bool().unwrap());
    }

    #[test]
    fn api_response_err_serializes_without_data_field() {
        let _guard = test_guard!();
        let response: ApiResponse<String> =
            ApiResponse::err("test", ApiError::internal("error msg"));
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("data").is_none());
        assert!(json.get("error").is_some());
        assert!(!json["success"].as_bool().unwrap());
    }

    #[test]
    fn api_response_with_complex_data_serializes() {
        let _guard = test_guard!();
        #[derive(Serialize)]
        struct ComplexData {
            name: String,
            count: u32,
            items: Vec<String>,
        }
        let data = ComplexData {
            name: "test".to_string(),
            count: 3,
            items: vec!["a".to_string(), "b".to_string()],
        };
        let response = ApiResponse::ok("complex", data);
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["data"]["name"], "test");
        assert_eq!(json["data"]["count"], 3);
        assert_eq!(json["data"]["items"].as_array().unwrap().len(), 2);
    }

    // -------------------------------------------------------------------------
    // Config / Workers IO Tests (coverage)
    // -------------------------------------------------------------------------

    #[test]
    fn config_init_simple_json_creates_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx, stdout_buf) = json_test_context();
        config_init(&ctx, false, true).expect("config init should succeed");

        assert!(temp_dir.path().join("config.toml").exists());
        assert!(temp_dir.path().join("workers.toml").exists());

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config init");
        assert_eq!(value["data"]["created"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["data"]["already_existed"].as_array().unwrap().len(),
            0
        );
    }

    #[test]
    fn config_init_simple_json_reports_existing_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx1, _stdout_buf1) = json_test_context();
        config_init(&ctx1, false, true).expect("first config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        config_init(&ctx2, false, true).expect("second config init should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config init");
        assert_eq!(value["data"]["created"].as_array().unwrap().len(), 0);
        assert_eq!(
            value["data"]["already_existed"].as_array().unwrap().len(),
            2
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn workers_list_json_uses_config_override() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        // Seed example config files (includes one enabled worker)
        let (ctx, _stdout_buf) = json_test_context();
        config_init(&ctx, false, true).expect("config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        workers_list(false, &ctx2)
            .await
            .expect("workers list should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "workers list");
        assert_eq!(value["data"]["count"], 1);
        assert_eq!(value["data"]["workers"][0]["id"], "worker1");
    }

    #[test]
    fn config_validate_json_success_with_example_files() {
        let _guard = test_guard!();
        let temp_dir = tempfile::tempdir().expect("temp dir should be creatable");
        let _cfg_guard = TestConfigDirGuard::new(temp_dir.path().to_path_buf());

        let (ctx1, _stdout_buf1) = json_test_context();
        config_init(&ctx1, false, true).expect("config init should succeed");

        let (ctx2, stdout_buf2) = json_test_context();
        config_validate(&ctx2).expect("config validate should succeed");

        let value: serde_json::Value =
            serde_json::from_str(&stdout_buf2.to_string_lossy()).expect("json output");
        assert_eq!(value["success"], true);
        assert_eq!(value["command"], "config validate");
        assert_eq!(value["data"]["valid"], true);
        assert_eq!(value["data"]["errors"].as_array().unwrap().len(), 0);
    }

    // -------------------------------------------------------------------------
    // WorkerInfo Tests
    // -------------------------------------------------------------------------

    #[test]
    fn worker_info_from_worker_config_converts_all_fields() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("test-worker"),
            host: "192.168.1.100".to_string(),
            user: "admin".to_string(),
            identity_file: "~/.ssh/key.pem".to_string(),
            total_slots: 16,
            priority: 50,
            tags: vec!["fast".to_string(), "ssd".to_string()],
        };
        let info = WorkerInfo::from(&config);
        assert_eq!(info.id, "test-worker");
        assert_eq!(info.host, "192.168.1.100");
        assert_eq!(info.user, "admin");
        assert_eq!(info.total_slots, 16);
        assert_eq!(info.priority, 50);
        assert_eq!(info.tags, vec!["fast", "ssd"]);
    }

    #[test]
    fn worker_info_from_worker_config_with_empty_tags() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("minimal"),
            host: "host.example.com".to_string(),
            user: "ubuntu".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            total_slots: 8,
            priority: 100,
            tags: vec![],
        };
        let info = WorkerInfo::from(&config);
        assert!(info.tags.is_empty());
    }

    #[test]
    fn worker_info_serializes_correctly() {
        let _guard = test_guard!();
        let config = WorkerConfig {
            id: WorkerId::new("w1"),
            host: "host".to_string(),
            user: "user".to_string(),
            identity_file: "key".to_string(),
            total_slots: 4,
            priority: 75,
            tags: vec!["gpu".to_string()],
        };
        let info = WorkerInfo::from(&config);
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["id"], "w1");
        assert_eq!(json["host"], "host");
        assert_eq!(json["total_slots"], 4);
        assert_eq!(json["tags"].as_array().unwrap().len(), 1);
    }

    // -------------------------------------------------------------------------
    // Response Types Tests
    // -------------------------------------------------------------------------

    #[test]
    fn workers_list_response_serializes() {
        let _guard = test_guard!();
        let response = WorkersListResponse {
            workers: vec![],
            count: 0,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["count"], 0);
        assert!(json["workers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn workers_list_response_with_workers_serializes() {
        let _guard = test_guard!();
        let workers = vec![
            WorkerInfo {
                id: "w1".to_string(),
                host: "host1".to_string(),
                user: "u1".to_string(),
                total_slots: 8,
                priority: 100,
                tags: vec![],
                speedscore: None,
            },
            WorkerInfo {
                id: "w2".to_string(),
                host: "host2".to_string(),
                user: "u2".to_string(),
                total_slots: 16,
                priority: 50,
                tags: vec!["fast".to_string()],
                speedscore: Some(85.5),
            },
        ];
        let response = WorkersListResponse { workers, count: 2 };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["count"], 2);
        let workers_arr = json["workers"].as_array().unwrap();
        assert_eq!(workers_arr.len(), 2);
        assert_eq!(workers_arr[0]["id"], "w1");
        assert_eq!(workers_arr[1]["id"], "w2");
    }

    #[test]
    fn worker_probe_result_success_serializes() {
        let _guard = test_guard!();
        let result = WorkerProbeResult {
            id: "worker1".to_string(),
            host: "192.168.1.1".to_string(),
            status: "healthy".to_string(),
            latency_ms: Some(42),
            error: None,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["id"], "worker1");
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["latency_ms"], 42);
        assert!(json.get("error").is_none()); // skipped when None
    }

    #[test]
    fn worker_probe_result_failure_serializes() {
        let _guard = test_guard!();
        let result = WorkerProbeResult {
            id: "worker2".to_string(),
            host: "192.168.1.2".to_string(),
            status: "unreachable".to_string(),
            latency_ms: None,
            error: Some("Connection refused".to_string()),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "unreachable");
        assert!(json.get("latency_ms").is_none()); // skipped when None
        assert_eq!(json["error"], "Connection refused");
    }

    #[test]
    fn daemon_status_response_running_serializes() {
        let _guard = test_guard!();
        let response = DaemonStatusResponse {
            running: true,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: Some(3600),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["running"].as_bool().unwrap());
        assert_eq!(json["socket_path"], "/tmp/rch.sock");
        assert_eq!(json["uptime_seconds"], 3600);
    }

    #[test]
    fn daemon_status_response_not_running_serializes() {
        let _guard = test_guard!();
        let response = DaemonStatusResponse {
            running: false,
            socket_path: "/tmp/rch.sock".to_string(),
            uptime_seconds: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(!json["running"].as_bool().unwrap());
        assert!(json.get("uptime_seconds").is_none());
    }

    #[test]
    fn system_overview_serializes() {
        let _guard = test_guard!();
        let response = SystemOverview {
            daemon_running: true,
            hook_installed: true,
            workers_count: 3,
            workers: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["daemon_running"].as_bool().unwrap());
        assert!(json["hook_installed"].as_bool().unwrap());
        assert_eq!(json["workers_count"], 3);
        assert!(json.get("workers").is_none());
    }

    #[test]
    fn config_show_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigShowResponse {
            general: ConfigGeneralSection {
                enabled: true,
                force_local: false,
                force_remote: false,
                log_level: "info".to_string(),
                socket_path: "/tmp/rch.sock".to_string(),
            },
            compilation: ConfigCompilationSection {
                confidence_threshold: 0.85,
                min_local_time_ms: 2000,
            },
            transfer: ConfigTransferSection {
                compression_level: 3,
                exclude_patterns: vec!["target/".to_string()],
                remote_base: "/tmp/rch".to_string(),
                max_transfer_mb: None,
                max_transfer_time_ms: None,
                bwlimit_kbps: None,
                estimated_bandwidth_bps: None,
                adaptive_compression: false,
                min_compression_level: 1,
                max_compression_level: 19,
                verify_artifacts: false,
                verify_max_size_bytes: 100 * 1024 * 1024,
            },
            environment: ConfigEnvironmentSection {
                allowlist: vec!["RUSTFLAGS".to_string()],
            },
            circuit: ConfigCircuitSection {
                failure_threshold: 3,
                success_threshold: 2,
                error_rate_threshold: 0.5,
                window_secs: 60,
                open_cooldown_secs: 30,
                half_open_max_probes: 2,
            },
            output: ConfigOutputSection {
                visibility: rch_common::OutputVisibility::None,
                first_run_complete: false,
            },
            self_healing: ConfigSelfHealingSection {
                hook_starts_daemon: true,
                daemon_installs_hooks: true,
                auto_start_cooldown_secs: 30,
                auto_start_timeout_secs: 3,
            },
            sources: vec!["~/.config/rch/config.toml".to_string()],
            value_sources: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["general"]["enabled"].as_bool().unwrap());
        assert_eq!(json["compilation"]["confidence_threshold"], 0.85);
        assert_eq!(json["transfer"]["compression_level"], 3);
        assert_eq!(json["circuit"]["failure_threshold"], 3);
    }

    #[test]
    fn config_init_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigInitResponse {
            created: vec!["config.toml".to_string()],
            already_existed: vec!["workers.toml".to_string()],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["created"].as_array().unwrap().len(), 1);
        assert_eq!(json["already_existed"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn config_validation_response_valid_serializes() {
        let _guard = test_guard!();
        let response = ConfigValidationResponse {
            errors: vec![],
            warnings: vec![],
            valid: true,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["valid"].as_bool().unwrap());
        assert!(json["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn config_validation_response_with_issues_serializes() {
        let _guard = test_guard!();
        let response = ConfigValidationResponse {
            errors: vec![ConfigValidationIssue {
                file: "config.toml".to_string(),
                message: "Invalid syntax".to_string(),
            }],
            warnings: vec![ConfigValidationIssue {
                file: "workers.toml".to_string(),
                message: "Deprecated field".to_string(),
            }],
            valid: false,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(!json["valid"].as_bool().unwrap());
        assert_eq!(json["errors"][0]["message"], "Invalid syntax");
        assert_eq!(json["warnings"][0]["file"], "workers.toml");
    }

    #[test]
    fn config_set_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigSetResponse {
            key: "general.log_level".to_string(),
            value: "debug".to_string(),
            config_path: "/home/user/.config/rch/config.toml".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["key"], "general.log_level");
        assert_eq!(json["value"], "debug");
    }

    #[test]
    fn config_reset_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigResetResponse {
            key: "general.enabled".to_string(),
            value: "true".to_string(),
            config_path: "/home/user/.config/rch/config.toml".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["key"], "general.enabled");
        assert_eq!(json["value"], "true");
    }

    #[test]
    fn config_export_response_serializes() {
        let _guard = test_guard!();
        let response = ConfigExportResponse {
            format: "toml".to_string(),
            content: "[general]\nenabled = true".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["format"], "toml");
        assert!(json["content"].as_str().unwrap().contains("enabled"));
    }

    #[test]
    fn diagnose_decision_intercepts_when_confident() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build");
        let decision = build_diagnose_decision(&classification, 0.85);
        assert!(decision.would_intercept);
        // New format: "Compilation command with confidence 0.95 >= threshold 0.85"
        assert!(decision.reason.contains(">=") || decision.reason.contains("threshold"));
    }

    #[test]
    fn diagnose_decision_rejects_when_below_threshold() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoCheck, 0.80, "cargo check");
        let decision = build_diagnose_decision(&classification, 0.85);
        assert!(!decision.would_intercept);
        assert!(decision.reason.contains("below threshold"));
    }

    #[test]
    fn diagnose_response_serializes() {
        let _guard = test_guard!();
        let classification =
            Classification::compilation(CompilationKind::CargoBuild, 0.95, "cargo build");
        let response = DiagnoseResponse {
            classification,
            tiers: Vec::new(),
            command: "cargo build".to_string(),
            normalized_command: "cargo build".to_string(),
            decision: DiagnoseDecision {
                would_intercept: true,
                reason: "meets confidence threshold".to_string(),
            },
            threshold: DiagnoseThreshold {
                value: 0.85,
                source: "default".to_string(),
            },
            daemon: DiagnoseDaemonStatus {
                socket_path: "/tmp/rch.sock".to_string(),
                socket_exists: false,
                reachable: false,
                status: None,
                version: None,
                uptime_seconds: None,
                error: Some("daemon socket not found".to_string()),
            },
            required_runtime: RequiredRuntime::Rust,
            local_capabilities: None,
            capabilities_warnings: Vec::new(),
            worker_selection: None,
            dry_run: None,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["command"], "cargo build");
        assert_eq!(json["classification"]["confidence"], 0.95);
        assert_eq!(json["threshold"]["value"], 0.85);
    }

    #[test]
    fn workers_capabilities_report_serializes_with_local() {
        let _guard = test_guard!();
        let report = WorkersCapabilitiesReport {
            workers: vec![],
            local: Some(WorkerCapabilities {
                rustc_version: Some("rustc 1.87.0-nightly".to_string()),
                bun_version: None,
                node_version: None,
                npm_version: None,
                ..Default::default()
            }),
            required_runtime: Some(RequiredRuntime::Rust),
            warnings: vec!["warn".to_string()],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["local"]["rustc_version"], "rustc 1.87.0-nightly");
        assert_eq!(json["required_runtime"], "rust");
        assert!(json["warnings"].is_array());
    }

    #[test]
    fn local_capability_warnings_include_missing_and_mismatch() {
        let _guard = test_guard!();
        let local = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0-nightly".to_string()),
            bun_version: None,
            node_version: None,
            npm_version: None,
            ..Default::default()
        };
        let workers = vec![
            WorkerCapabilitiesFromApi {
                id: "w-missing".to_string(),
                host: "host".to_string(),
                user: "user".to_string(),
                capabilities: WorkerCapabilities::new(),
            },
            WorkerCapabilitiesFromApi {
                id: "w-old".to_string(),
                host: "host".to_string(),
                user: "user".to_string(),
                capabilities: WorkerCapabilities {
                    rustc_version: Some("rustc 1.86.0-nightly".to_string()),
                    bun_version: None,
                    node_version: None,
                    npm_version: None,
                    ..Default::default()
                },
            },
        ];
        let warnings = collect_local_capability_warnings(&workers, &local);
        assert!(warnings.iter().any(|w| w.contains("missing Rust runtime")));
        assert!(warnings.iter().any(|w| w.contains("Rust version mismatch")));
    }

    #[test]
    fn hook_action_response_success_serializes() {
        let _guard = test_guard!();
        let response = HookActionResponse {
            action: "install".to_string(),
            success: true,
            settings_path: "~/.config/claude-code/settings.json".to_string(),
            message: Some("Hook installed successfully".to_string()),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["action"], "install");
        assert!(json["success"].as_bool().unwrap());
        assert_eq!(json["message"], "Hook installed successfully");
    }

    #[test]
    fn hook_action_response_without_message_serializes() {
        let _guard = test_guard!();
        let response = HookActionResponse {
            action: "uninstall".to_string(),
            success: true,
            settings_path: "path".to_string(),
            message: None,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("message").is_none());
    }

    #[test]
    fn hook_test_response_serializes() {
        let _guard = test_guard!();
        let response = HookTestResponse {
            classification_tests: vec![ClassificationTestResult {
                command: "cargo build".to_string(),
                is_compilation: true,
                confidence: 0.95,
                expected_intercept: true,
                passed: true,
            }],
            daemon_connected: true,
            daemon_response: Some("OK".to_string()),
            workers_configured: 2,
            workers: vec![],
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["daemon_connected"].as_bool().unwrap());
        assert_eq!(json["workers_configured"], 2);
        let tests = json["classification_tests"].as_array().unwrap();
        assert_eq!(tests[0]["command"], "cargo build");
        assert!(tests[0]["passed"].as_bool().unwrap());
    }

    #[test]
    fn classification_test_result_serializes() {
        let _guard = test_guard!();
        let result = ClassificationTestResult {
            command: "bun test".to_string(),
            is_compilation: true,
            confidence: 0.92,
            expected_intercept: true,
            passed: true,
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["command"], "bun test");
        assert!(json["is_compilation"].as_bool().unwrap());
        assert_eq!(json["confidence"], 0.92);
    }

    // -------------------------------------------------------------------------
    // ErrorCode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn error_code_codes_have_rch_prefix() {
        let _guard = test_guard!();
        // Verify error codes follow RCH-Exxx format
        assert_eq!(ErrorCode::ConfigNotFound.code_string(), "RCH-E001");
        assert_eq!(ErrorCode::ConfigValidationError.code_string(), "RCH-E004");
        assert_eq!(ErrorCode::ConfigInvalidWorker.code_string(), "RCH-E008");
        assert_eq!(ErrorCode::SshConnectionFailed.code_string(), "RCH-E100");
        assert_eq!(
            ErrorCode::InternalDaemonNotRunning.code_string(),
            "RCH-E502"
        );
        assert_eq!(ErrorCode::InternalStateError.code_string(), "RCH-E504");
    }

    // -------------------------------------------------------------------------
    // config_dir Tests
    // -------------------------------------------------------------------------

    #[test]
    fn config_dir_returns_some() {
        let _guard = test_guard!();
        // config_dir should return a path on most systems
        let dir = config_dir();
        // We can't guarantee it returns Some on all systems, but if it does,
        // it should be a valid path that ends with "rch"
        if let Some(path) = dir {
            assert!(path.to_string_lossy().contains("rch"));
        }
    }

    // -------------------------------------------------------------------------
    // API_VERSION Tests
    // -------------------------------------------------------------------------

    #[test]
    fn api_version_is_expected_value() {
        let _guard = test_guard!();
        assert_eq!(rch_common::API_VERSION, "1.0");
    }

    // -------------------------------------------------------------------------
    // default_socket_path Tests
    // -------------------------------------------------------------------------

    #[test]
    fn default_socket_path_returns_valid_path() {
        let _guard = test_guard!();
        let path = default_socket_path();
        // Should end with rch.sock regardless of prefix
        assert!(
            path.ends_with("rch.sock"),
            "Socket path should end with rch.sock, got: {}",
            path
        );
        // Should be an absolute path
        assert!(
            path.starts_with('/'),
            "Socket path should be absolute, got: {}",
            path
        );
    }

    // -------------------------------------------------------------------------
    // Dry Run Summary Tests
    // -------------------------------------------------------------------------

    #[test]
    fn dry_run_summary_not_intercepted() {
        let _guard = test_guard!();
        let summary = build_dry_run_summary(false, "not a compilation command", &None, false);
        assert!(!summary.would_offload);
        assert_eq!(summary.reason, "not a compilation command");
        // Non-intercepted commands get single "Local execution" step
        assert_eq!(summary.pipeline_steps.len(), 1);
        assert_eq!(summary.pipeline_steps[0].name, "Local execution");
        assert!(!summary.pipeline_steps[0].skipped);
    }

    #[test]
    fn dry_run_summary_intercepted_no_daemon() {
        let _guard = test_guard!();
        let summary = build_dry_run_summary(
            true,
            "meets confidence threshold",
            &None,
            false, // daemon not reachable
        );
        // With no worker selection and daemon not reachable, would_offload is still true
        // because the function returns optimistic summary
        assert!(summary.would_offload);
        assert!(summary.reason.contains("worker available"));
        // Intercepted commands have 6 pipeline steps
        assert_eq!(summary.pipeline_steps.len(), 6);
        // Classification step should run
        assert!(!summary.pipeline_steps[0].skipped);
        assert_eq!(summary.pipeline_steps[0].name, "Classification");
        // Daemon query should be skipped (daemon not reachable)
        assert!(summary.pipeline_steps[1].skipped);
        assert_eq!(summary.pipeline_steps[1].name, "Daemon query");
    }

    #[test]
    fn dry_run_summary_intercepted_with_worker() {
        let _guard = test_guard!();
        let worker = SelectedWorker {
            id: WorkerId::new("test-worker"),
            host: "worker.example.com".to_string(),
            user: "rch".to_string(),
            identity_file: "~/.ssh/id_rsa".to_string(),
            slots_available: 4,
            speed_score: 1.5,
        };
        let worker_selection = DiagnoseWorkerSelection {
            estimated_cores: 4,
            worker: Some(worker),
            reason: SelectionReason::Success,
        };
        let summary = build_dry_run_summary(
            true,
            "meets confidence threshold",
            &Some(worker_selection),
            true, // daemon reachable
        );
        assert!(summary.would_offload);
        assert!(summary.reason.contains("worker available"));
        // Intercepted commands have 6 pipeline steps
        assert_eq!(summary.pipeline_steps.len(), 6);
        // All steps should run (not skipped) when worker is selected
        for step in &summary.pipeline_steps {
            assert!(!step.skipped, "Step {} should not be skipped", step.name);
        }
    }

    #[test]
    fn dry_run_pipeline_step_serializes() {
        let _guard = test_guard!();
        let step = DryRunPipelineStep {
            step: 1,
            name: "classify".to_string(),
            description: "Analyze command".to_string(),
            skipped: false,
            skip_reason: None,
            estimated_duration_ms: Some(2),
        };
        let json = serde_json::to_value(&step).unwrap();
        assert_eq!(json["step"], 1);
        assert_eq!(json["name"], "classify");
        assert_eq!(json["skipped"], false);
        assert_eq!(json["estimated_duration_ms"], 2);
        assert!(json.get("skip_reason").is_none());
    }

    #[test]
    fn dry_run_pipeline_step_skipped_serializes() {
        let _guard = test_guard!();
        let step = DryRunPipelineStep {
            step: 2,
            name: "select".to_string(),
            description: "Select worker".to_string(),
            skipped: true,
            skip_reason: Some("daemon not reachable".to_string()),
            estimated_duration_ms: None,
        };
        let json = serde_json::to_value(&step).unwrap();
        assert_eq!(json["skipped"], true);
        assert_eq!(json["skip_reason"], "daemon not reachable");
        assert!(json.get("estimated_duration_ms").is_none());
    }

    #[test]
    fn dry_run_transfer_estimate_serializes() {
        let _guard = test_guard!();
        let estimate = DryRunTransferEstimate {
            bytes: 1024 * 1024 * 10, // 10 MB
            human_size: "10.00 MB".to_string(),
            files: 150,
            estimated_time_ms: 2500,
            would_skip: false,
            skip_reason: None,
        };
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["bytes"], 10485760);
        assert_eq!(json["human_size"], "10.00 MB");
        assert_eq!(json["files"], 150);
        assert_eq!(json["estimated_time_ms"], 2500);
        assert_eq!(json["would_skip"], false);
    }

    #[test]
    fn dry_run_transfer_estimate_would_skip_serializes() {
        let _guard = test_guard!();
        let estimate = DryRunTransferEstimate {
            bytes: 1024 * 1024 * 500, // 500 MB
            human_size: "500.00 MB".to_string(),
            files: 5000,
            estimated_time_ms: 60000,
            would_skip: true,
            skip_reason: Some("exceeds max_transfer_mb threshold".to_string()),
        };
        let json = serde_json::to_value(&estimate).unwrap();
        assert_eq!(json["would_skip"], true);
        assert_eq!(json["skip_reason"], "exceeds max_transfer_mb threshold");
    }

    #[test]
    fn dry_run_summary_serializes() {
        let _guard = test_guard!();
        let summary = DryRunSummary {
            would_offload: true,
            reason: "compilation command meets threshold".to_string(),
            pipeline_steps: vec![DryRunPipelineStep {
                step: 1,
                name: "classify".to_string(),
                description: "Analyze command".to_string(),
                skipped: false,
                skip_reason: None,
                estimated_duration_ms: Some(2),
            }],
            transfer_estimate: None,
            total_estimated_ms: Some(100),
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["would_offload"], true);
        assert_eq!(json["reason"], "compilation command meets threshold");
        assert_eq!(json["pipeline_steps"].as_array().unwrap().len(), 1);
        assert_eq!(json["total_estimated_ms"], 100);
    }

    #[test]
    fn format_bytes_basic() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn format_bytes_fractional() {
        let _guard = test_guard!();
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1024 * 1024 + 512 * 1024), "1.5 MB");
    }

    // -------------------------------------------------------------------------
    // runtime_label Tests
    // -------------------------------------------------------------------------

    #[test]
    fn runtime_label_rust() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Rust), "rust");
    }

    #[test]
    fn runtime_label_bun() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Bun), "bun");
    }

    #[test]
    fn runtime_label_node() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::Node), "node");
    }

    #[test]
    fn runtime_label_none() {
        let _guard = test_guard!();
        assert_eq!(runtime_label(&RequiredRuntime::None), "none");
    }

    // -------------------------------------------------------------------------
    // has_any_capabilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn has_any_capabilities_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert!(!has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_rust() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_bun() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            bun_version: Some("1.2.3".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_node() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            node_version: Some("v20.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_npm() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            npm_version: Some("10.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    #[test]
    fn has_any_capabilities_with_all() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            bun_version: Some("1.2.3".to_string()),
            node_version: Some("v20.0.0".to_string()),
            npm_version: Some("10.0.0".to_string()),
            ..Default::default()
        };
        assert!(has_any_capabilities(&caps));
    }

    // -------------------------------------------------------------------------
    // extract_version_numbers Tests
    // -------------------------------------------------------------------------

    #[test]
    fn extract_version_numbers_simple() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("1.2.3"), vec![1, 2, 3]);
    }

    #[test]
    fn extract_version_numbers_with_prefix() {
        let _guard = test_guard!();
        assert_eq!(
            extract_version_numbers("rustc 1.87.0-nightly"),
            vec![1, 87, 0]
        );
    }

    #[test]
    fn extract_version_numbers_node_format() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("v20.11.1"), vec![20, 11, 1]);
    }

    #[test]
    fn extract_version_numbers_empty() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers(""), Vec::<u64>::new());
    }

    #[test]
    fn extract_version_numbers_no_numbers() {
        let _guard = test_guard!();
        assert_eq!(
            extract_version_numbers("no numbers here"),
            Vec::<u64>::new()
        );
    }

    #[test]
    fn extract_version_numbers_single() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("version 42"), vec![42]);
    }

    #[test]
    fn extract_version_numbers_large() {
        let _guard = test_guard!();
        assert_eq!(extract_version_numbers("2024.01.15"), vec![2024, 1, 15]);
    }

    // -------------------------------------------------------------------------
    // major_version Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_version_extracts_first() {
        let _guard = test_guard!();
        assert_eq!(major_version("rustc 1.87.0-nightly"), Some(1));
    }

    #[test]
    fn major_version_node() {
        let _guard = test_guard!();
        assert_eq!(major_version("v20.11.1"), Some(20));
    }

    #[test]
    fn major_version_empty() {
        let _guard = test_guard!();
        assert_eq!(major_version(""), None);
    }

    #[test]
    fn major_version_no_numbers() {
        let _guard = test_guard!();
        assert_eq!(major_version("no version"), None);
    }

    // -------------------------------------------------------------------------
    // major_minor_version Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_minor_version_extracts_both() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("rustc 1.87.0-nightly"), Some((1, 87)));
    }

    #[test]
    fn major_minor_version_node() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("v20.11.1"), Some((20, 11)));
    }

    #[test]
    fn major_minor_version_single_number() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version("version 42"), None);
    }

    #[test]
    fn major_minor_version_empty() {
        let _guard = test_guard!();
        assert_eq!(major_minor_version(""), None);
    }

    // -------------------------------------------------------------------------
    // rust_version_mismatch Tests
    // -------------------------------------------------------------------------

    #[test]
    fn rust_version_mismatch_same_version() {
        let _guard = test_guard!();
        assert!(!rust_version_mismatch(
            "rustc 1.87.0-nightly",
            "rustc 1.87.0-nightly"
        ));
    }

    #[test]
    fn rust_version_mismatch_different_patch() {
        let _guard = test_guard!();
        // Same major.minor, different patch - should NOT be a mismatch
        assert!(!rust_version_mismatch("rustc 1.87.0", "rustc 1.87.1"));
    }

    #[test]
    fn rust_version_mismatch_different_minor() {
        let _guard = test_guard!();
        assert!(rust_version_mismatch("rustc 1.87.0", "rustc 1.86.0"));
    }

    #[test]
    fn rust_version_mismatch_different_major() {
        let _guard = test_guard!();
        assert!(rust_version_mismatch("rustc 1.87.0", "rustc 2.0.0"));
    }

    #[test]
    fn rust_version_mismatch_invalid_local() {
        let _guard = test_guard!();
        // If local can't be parsed, returns false (no mismatch detectable)
        assert!(!rust_version_mismatch("invalid", "rustc 1.87.0"));
    }

    #[test]
    fn rust_version_mismatch_invalid_remote() {
        let _guard = test_guard!();
        assert!(!rust_version_mismatch("rustc 1.87.0", "invalid"));
    }

    // -------------------------------------------------------------------------
    // major_version_mismatch Tests
    // -------------------------------------------------------------------------

    #[test]
    fn major_version_mismatch_same() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("bun 1.2.3", "bun 1.5.0"));
    }

    #[test]
    fn major_version_mismatch_different() {
        let _guard = test_guard!();
        assert!(major_version_mismatch("bun 1.2.3", "bun 2.0.0"));
    }

    #[test]
    fn major_version_mismatch_invalid_local() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("no version", "bun 1.2.3"));
    }

    #[test]
    fn major_version_mismatch_invalid_remote() {
        let _guard = test_guard!();
        assert!(!major_version_mismatch("bun 1.2.3", "no version"));
    }

    // -------------------------------------------------------------------------
    // summarize_capabilities Tests
    // -------------------------------------------------------------------------

    #[test]
    fn summarize_capabilities_empty() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities::new();
        assert_eq!(summarize_capabilities(&caps), "unknown");
    }

    #[test]
    fn summarize_capabilities_rust_only() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("rustc 1.87.0".to_string()),
            ..Default::default()
        };
        assert_eq!(summarize_capabilities(&caps), "rustc rustc 1.87.0");
    }

    #[test]
    fn summarize_capabilities_all() {
        let _guard = test_guard!();
        let caps = WorkerCapabilities {
            rustc_version: Some("1.87".to_string()),
            bun_version: Some("1.2".to_string()),
            node_version: Some("20.0".to_string()),
            npm_version: Some("10.0".to_string()),
            ..Default::default()
        };
        let result = summarize_capabilities(&caps);
        assert!(result.contains("rustc 1.87"));
        assert!(result.contains("bun 1.2"));
        assert!(result.contains("node 20.0"));
        assert!(result.contains("npm 10.0"));
    }

    // -------------------------------------------------------------------------
    // indent_lines Tests
    // -------------------------------------------------------------------------

    #[test]
    fn indent_lines_single() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("hello", "  "), "  hello");
    }

    #[test]
    fn indent_lines_multiple() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("a\nb\nc", ">> "), ">> a\n>> b\n>> c");
    }

    #[test]
    fn indent_lines_empty() {
        let _guard = test_guard!();
        // Empty string has no lines, so output is also empty
        assert_eq!(indent_lines("", "  "), "");
    }

    #[test]
    fn indent_lines_empty_prefix() {
        let _guard = test_guard!();
        assert_eq!(indent_lines("a\nb", ""), "a\nb");
    }

    // -------------------------------------------------------------------------
    // urlencoding_encode Tests
    // -------------------------------------------------------------------------

    #[test]
    fn urlencoding_encode_alphanumeric() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("abc123"), "abc123");
    }

    #[test]
    fn urlencoding_encode_safe_chars() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn urlencoding_encode_spaces() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("hello world"), "hello%20world");
    }

    #[test]
    fn urlencoding_encode_special() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode("a=b&c"), "a%3Db%26c");
    }

    #[test]
    fn urlencoding_encode_unicode() {
        let _guard = test_guard!();
        // Multi-byte UTF-8 characters should be percent-encoded
        let result = urlencoding_encode("hello\u{00E9}"); // é
        assert!(result.starts_with("hello%"));
        assert!(result.len() > 6); // Should be longer due to encoding
    }

    #[test]
    fn urlencoding_encode_empty() {
        let _guard = test_guard!();
        assert_eq!(urlencoding_encode(""), "");
    }

    // -------------------------------------------------------------------------
    // is_default_verify_size Tests
    // -------------------------------------------------------------------------

    #[test]
    fn is_default_verify_size_true() {
        let _guard = test_guard!();
        assert!(is_default_verify_size(&(100 * 1024 * 1024)));
    }

    #[test]
    fn is_default_verify_size_false() {
        let _guard = test_guard!();
        assert!(!is_default_verify_size(&0));
        assert!(!is_default_verify_size(&(50 * 1024 * 1024)));
    }
}
