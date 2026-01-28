//! E2E Tests for Fleet Deployment Operations
//!
//! Verifies fleet deploy, rollback, status, and concurrent operations
//! using the shared E2E test harness.

use rch_common::e2e::{
    HarnessError, HarnessResult, LogLevel, LogSource, TestHarness, TestHarnessBuilder,
    WorkersFixture,
};
use rch_common::test_guard;
use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[allow(dead_code)]
struct FleetEnv {
    config_home: PathBuf,
    data_home: PathBuf,
    workers_path: PathBuf,
}

fn create_fleet_harness(test_name: &str) -> HarnessResult<TestHarness> {
    // Respect CARGO_TARGET_DIR if set, otherwise use default target/debug
    let target_dir = if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(target_dir).join("debug")
    } else {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."));
        let project_root = manifest_dir.parent().unwrap_or(&manifest_dir);
        project_root.join("target/debug")
    };

    TestHarnessBuilder::new(test_name)
        .cleanup_on_success(true)
        .cleanup_on_failure(false)
        .default_timeout(Duration::from_secs(30))
        .rch_binary(target_dir.join("rch"))
        .rchd_binary(target_dir.join("rchd"))
        .rch_wkr_binary(target_dir.join("rch-wkr"))
        .build()
}

fn setup_fleet_env(harness: &mut TestHarness, worker_count: usize) -> HarnessResult<FleetEnv> {
    let config_home = harness.test_dir().join("xdg_config");
    let data_home = harness.test_dir().join("xdg_data");

    std::fs::create_dir_all(&config_home)?;
    std::fs::create_dir_all(&data_home)?;

    harness.config.env_vars.insert(
        "XDG_CONFIG_HOME".to_string(),
        config_home.to_string_lossy().to_string(),
    );
    harness.config.env_vars.insert(
        "XDG_DATA_HOME".to_string(),
        data_home.to_string_lossy().to_string(),
    );
    harness
        .config
        .env_vars
        .insert("RCH_MOCK_SSH".to_string(), "1".to_string());
    harness
        .config
        .env_vars
        .insert("RCH_TEST_MODE".to_string(), "1".to_string());

    let rch_config_dir = config_home.join("rch");
    std::fs::create_dir_all(&rch_config_dir)?;

    let workers = WorkersFixture::mock_local(worker_count);
    let workers_path = rch_config_dir.join("workers.toml");
    std::fs::write(&workers_path, workers.to_toml())?;

    harness.logger.log_with_context(
        LogLevel::Info,
        LogSource::Custom("fleet".to_string()),
        format!("SETUP: workers_config={}", workers_path.display()),
        vec![("workers".to_string(), worker_count.to_string())],
    );

    Ok(FleetEnv {
        config_home,
        data_home,
        workers_path,
    })
}

fn parse_json(harness: &TestHarness, output: &str, context: &str) -> HarnessResult<Value> {
    serde_json::from_str::<Value>(output).map_err(|e| {
        let msg = format!("Failed to parse JSON for {context}: {e}");
        harness.logger.error(&msg);
        HarnessError::SetupFailed(msg)
    })
}

fn assert_json_success(harness: &TestHarness, json: &Value, context: &str) -> HarnessResult<()> {
    let success = json
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    harness.assert(success, context)
}

#[test]
fn test_fleet_deploy_all_workers() {
    let _guard = test_guard!();
    let mut harness = create_fleet_harness("fleet_deploy_all_workers").unwrap();
    let _env = setup_fleet_env(&mut harness, 3).unwrap();

    harness
        .logger
        .info("TEST START: test_fleet_deploy_all_workers");

    let result = harness
        .exec_rch(["fleet", "deploy", "--parallel", "2", "--json"])
        .unwrap();
    harness
        .assert_success(&result, "rch fleet deploy --parallel 2 --json")
        .unwrap();

    let json = parse_json(&harness, &result.stdout, "fleet deploy").unwrap();
    assert_json_success(&harness, &json, "fleet deploy success").unwrap();

    let data = &json["data"];
    harness
        .assert(
            data["status"].as_str() == Some("Success"),
            "fleet deploy status is Success",
        )
        .unwrap();
    harness
        .assert(
            data["deployed"].as_u64() == Some(3),
            "fleet deploy deployed count matches",
        )
        .unwrap();

    harness
        .logger
        .info("TEST PASS: test_fleet_deploy_all_workers");
    harness.mark_passed();
}

#[test]
fn test_fleet_partial_deploy() {
    let _guard = test_guard!();
    let mut harness = create_fleet_harness("fleet_partial_deploy").unwrap();
    let _env = setup_fleet_env(&mut harness, 3).unwrap();

    harness.logger.info("TEST START: test_fleet_partial_deploy");

    let result = harness
        .exec_rch(["fleet", "deploy", "--worker", "worker1,worker3", "--json"])
        .unwrap();
    harness
        .assert_success(&result, "rch fleet deploy --worker worker1,worker3 --json")
        .unwrap();

    let json = parse_json(&harness, &result.stdout, "fleet partial deploy").unwrap();
    assert_json_success(&harness, &json, "fleet partial deploy success").unwrap();

    let data = &json["data"];
    harness
        .assert(
            data["deployed"].as_u64() == Some(2),
            "fleet partial deploy deployed count matches",
        )
        .unwrap();

    harness.logger.info("TEST PASS: test_fleet_partial_deploy");
    harness.mark_passed();
}

#[test]
fn test_fleet_rollback_to_version() {
    let _guard = test_guard!();
    let mut harness = create_fleet_harness("fleet_rollback_to_version").unwrap();
    let _env = setup_fleet_env(&mut harness, 2).unwrap();

    harness
        .logger
        .info("TEST START: test_fleet_rollback_to_version");

    let result = harness
        .exec_rch(["fleet", "rollback", "--to-version", "0.0.1", "--json"])
        .unwrap();
    harness
        .assert_success(&result, "rch fleet rollback --to-version 0.0.1 --json")
        .unwrap();

    let json = parse_json(&harness, &result.stdout, "fleet rollback").unwrap();
    assert_json_success(&harness, &json, "fleet rollback success").unwrap();

    let data = json
        .get("data")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    harness
        .assert(
            data.len() == 2,
            "fleet rollback returns results for all workers",
        )
        .unwrap();

    for entry in data {
        harness
            .assert(
                entry.get("success").and_then(|v| v.as_bool()) == Some(true),
                "fleet rollback entry success",
            )
            .unwrap();
        harness
            .assert(
                entry.get("rolled_back_to").and_then(|v| v.as_str()) == Some("0.0.1"),
                "fleet rollback target version matches",
            )
            .unwrap();
    }

    harness
        .logger
        .info("TEST PASS: test_fleet_rollback_to_version");
    harness.mark_passed();
}

#[test]
fn test_fleet_status_health() {
    let _guard = test_guard!();
    let mut harness = create_fleet_harness("fleet_status_health").unwrap();
    let _env = setup_fleet_env(&mut harness, 2).unwrap();

    harness.logger.info("TEST START: test_fleet_status_health");

    let result = harness.exec_rch(["fleet", "status", "--json"]).unwrap();
    harness
        .assert_success(&result, "rch fleet status --json")
        .unwrap();

    let json = parse_json(&harness, &result.stdout, "fleet status").unwrap();
    assert_json_success(&harness, &json, "fleet status success").unwrap();

    let data = json
        .get("data")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    harness
        .assert(data.len() == 2, "fleet status returns 2 workers")
        .unwrap();

    for entry in data {
        harness
            .assert(
                entry.get("healthy").and_then(|v| v.as_bool()) == Some(true),
                "fleet status health true",
            )
            .unwrap();
    }

    harness.logger.info("TEST PASS: test_fleet_status_health");
    harness.mark_passed();
}

#[test]
fn test_fleet_concurrent_operations() {
    let _guard = test_guard!();
    let mut harness = create_fleet_harness("fleet_concurrent_ops").unwrap();
    let _env = setup_fleet_env(&mut harness, 2).unwrap();

    harness
        .logger
        .info("TEST START: test_fleet_concurrent_operations");

    let rch_bin = harness.config.rch_binary.clone();
    let work_dir = harness.test_dir().to_path_buf();
    let env_pairs: Vec<(String, String)> = harness
        .config
        .env_vars
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let logger = harness.logger.clone();

    let run_command = move |name: &str, args: Vec<&str>, rch_bin: PathBuf, work_dir: PathBuf| {
        let start = Instant::now();
        let mut cmd = std::process::Command::new(&rch_bin);
        cmd.args(&args)
            .current_dir(&work_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        for (k, v) in &env_pairs {
            cmd.env(k, v);
        }

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("fleet".to_string()),
            format!("CONCURRENT START: {name}"),
            vec![],
        );

        let output = cmd.output().expect("failed to run rch command");
        let duration = start.elapsed();

        logger.log_with_context(
            LogLevel::Info,
            LogSource::Custom("fleet".to_string()),
            format!("CONCURRENT END: {name}"),
            vec![("duration_ms".to_string(), duration.as_millis().to_string())],
        );

        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    };

    let status_handle = std::thread::spawn({
        let rch_bin = rch_bin.clone();
        let work_dir = work_dir.clone();
        let run_command = run_command.clone();
        move || {
            run_command(
                "fleet status",
                vec!["fleet", "status", "--json"],
                rch_bin,
                work_dir,
            )
        }
    });
    let verify_handle = std::thread::spawn({
        let rch_bin = rch_bin.clone();
        let work_dir = work_dir.clone();
        let run_command = run_command.clone();
        move || {
            run_command(
                "fleet verify",
                vec!["fleet", "verify", "--json"],
                rch_bin,
                work_dir,
            )
        }
    });

    let status_result = status_handle.join().unwrap();
    let verify_result = verify_handle.join().unwrap();

    harness
        .assert(status_result.0 == 0, "fleet status exit code 0")
        .unwrap();
    harness
        .assert(verify_result.0 == 0, "fleet verify exit code 0")
        .unwrap();

    let status_json = parse_json(&harness, &status_result.1, "fleet status").unwrap();
    let verify_json = parse_json(&harness, &verify_result.1, "fleet verify").unwrap();

    assert_json_success(&harness, &status_json, "fleet status success").unwrap();
    assert_json_success(&harness, &verify_json, "fleet verify success").unwrap();

    harness
        .logger
        .info("TEST PASS: test_fleet_concurrent_operations");
    harness.mark_passed();
}
