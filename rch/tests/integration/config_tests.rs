use rch_common::RchConfig;
use std::path::Path;
use std::process::{Command, Output};

use super::common::init_test_logging;

#[test]
fn test_default_config_enabled() {
    init_test_logging();
    crate::test_log!("TEST START: test_default_config_enabled");

    let config = RchConfig::default();
    assert!(
        config.general.enabled,
        "Expected RCH to be enabled by default"
    );

    crate::test_log!("TEST PASS: test_default_config_enabled");
}

const DISK_RATIO_CAP_KEY: &str = "selection.disk_critical_ratio_cap_gb";

fn run_config_cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rch"))
        .env_clear()
        .env("RCH_CONFIG_DIR", root.join("config"))
        .env("RCH_STATE_HOME", root.join("state"))
        .env("XDG_CONFIG_HOME", root.join("xdg-config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("XDG_DATA_HOME", root.join("data"))
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .env("RCH_NO_UPDATE_CHECK", "1")
        .env("NO_COLOR", "1")
        .current_dir(root)
        .arg("--no-self-healing")
        .args(args)
        .output()
        .expect("run the compiled rch CLI")
}

fn successful_stdout(output: Output) -> String {
    assert!(
        output.status.success(),
        "rch failed: status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8(output.stdout).expect("UTF-8 CLI output")
}

#[test]
fn disk_ratio_cap_cli_defaults_without_creating_config() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let config_path = root.join("config/config.toml");
    assert!(!config_path.exists());
    assert_eq!(
        successful_stdout(run_config_cli(root, &["config", "get", DISK_RATIO_CAP_KEY])).trim(),
        "25"
    );
    let output = successful_stdout(run_config_cli(
        root,
        &[
            "--json",
            "--format=json",
            "config",
            "get",
            DISK_RATIO_CAP_KEY,
            "--sources",
        ],
    ));
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response["success"], true);
    assert_eq!(response["data"]["key"], DISK_RATIO_CAP_KEY);
    assert_eq!(response["data"]["value"], "25");
    assert_eq!(response["data"]["source"], "default");
    assert!(
        !config_path.exists(),
        "reading the default must not configure the dispatcher"
    );
}

#[test]
fn disk_ratio_cap_cli_roundtrip_preserves_override_and_rejects_invalid_writes() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let config_path = root.join("config/config.toml");
    let ratio_key = "selection.disk_critical_free_ratio";
    for value in ["15", "uncapped"] {
        successful_stdout(run_config_cli(
            root,
            &["config", "set", DISK_RATIO_CAP_KEY, value],
        ));
        assert_eq!(
            successful_stdout(run_config_cli(root, &["config", "get", DISK_RATIO_CAP_KEY])).trim(),
            value
        );
    }
    successful_stdout(run_config_cli(
        root,
        &["config", "set", "selection.disk_gb_per_slot", "5"],
    ));
    assert_eq!(
        successful_stdout(run_config_cli(root, &["config", "get", DISK_RATIO_CAP_KEY])).trim(),
        "uncapped",
        "rewriting an unrelated setting must preserve the unconditional ratio policy"
    );
    let output = successful_stdout(run_config_cli(
        root,
        &[
            "--json",
            "--format=json",
            "config",
            "get",
            DISK_RATIO_CAP_KEY,
            "--sources",
        ],
    ));
    let response: serde_json::Value = serde_json::from_str(&output).unwrap();
    assert_eq!(response["data"]["value"], "uncapped");
    assert_eq!(
        response["data"]["source"],
        format!("user:{}", config_path.display())
    );
    successful_stdout(run_config_cli(root, &["config", "set", ratio_key, "0.04"]));
    assert_eq!(
        successful_stdout(run_config_cli(root, &["config", "get", ratio_key])).trim(),
        "0.04"
    );

    let original = std::fs::read(&config_path).unwrap();
    for (key, invalid) in [
        (DISK_RATIO_CAP_KEY, "9"),
        (DISK_RATIO_CAP_KEY, "NaN"),
        (DISK_RATIO_CAP_KEY, "inf"),
        (DISK_RATIO_CAP_KEY, "invalid"),
        (ratio_key, "0"),
        (ratio_key, "0.12"),
        (ratio_key, "NaN"),
    ] {
        let output = run_config_cli(root, &["config", "set", key, invalid]);
        assert!(!output.status.success(), "accepted invalid {key}={invalid}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(key),
            "failure must identify the invalid disk policy: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read(&config_path).unwrap(),
            original,
            "invalid {key}={invalid} changed the persisted policy"
        );
    }

    successful_stdout(run_config_cli(root, &["config", "reset", ratio_key]));
    for (key, expected) in [
        (ratio_key, "0.05"),
        (DISK_RATIO_CAP_KEY, "uncapped"),
        ("selection.disk_gb_per_slot", "5"),
    ] {
        assert_eq!(
            successful_stdout(run_config_cli(root, &["config", "get", key])).trim(),
            expected,
            "resetting the ratio must preserve unrelated settings"
        );
    }
    successful_stdout(run_config_cli(
        root,
        &["config", "reset", DISK_RATIO_CAP_KEY],
    ));
    assert_eq!(
        successful_stdout(run_config_cli(root, &["config", "get", DISK_RATIO_CAP_KEY])).trim(),
        "25"
    );
    let config: RchConfig = toml::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
    assert_eq!(config.selection.disk_critical_ratio_cap_gb, Some(25.0));
    assert_eq!(config.selection.disk_critical_free_ratio, 0.05);
    assert_eq!(config.selection.disk_gb_per_slot, 5.0);
}

// ProjectDirs uses XDG_CACHE_HOME on Linux; this fixture must never plant a
// legacy cache in a platform's native, unisolated user cache directory.
#[cfg(target_os = "linux")]
#[test]
fn disk_ratio_cap_cli_invalidates_legacy_cache_without_losing_explicit_policy() {
    for explicit_uncapped in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let config_path = root.join("config/config.toml");
        let cache_path = root.join("cache/rch/config.cache.json");
        if explicit_uncapped {
            successful_stdout(run_config_cli(
                root,
                &["config", "set", DISK_RATIO_CAP_KEY, "uncapped"],
            ));
        }
        let config_before = std::fs::read(&config_path).ok();
        assert_eq!(config_before.is_some(), explicit_uncapped);

        // `config get` and `show --sources` bypass this cache. Exercise the
        // normal show path, which shares the hook's cached effective config.
        let show = || {
            let output = successful_stdout(run_config_cli(
                root,
                &["--json", "--format=json", "config", "show"],
            ));
            let response: serde_json::Value = serde_json::from_str(&output).unwrap();
            assert_eq!(response["success"], true);
            assert_eq!(response["command"], "config show");
        };
        let read_cache = || -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(&cache_path).expect("CLI creates its cache"))
                .unwrap()
        };
        let expected_cap = if explicit_uncapped {
            serde_json::json!("uncapped")
        } else {
            serde_json::json!(25.0)
        };
        show();
        let mut legacy = read_cache();
        let current_schema = legacy["schema_version"].as_u64().unwrap();
        assert!(
            current_schema > 6,
            "the changed default must invalidate schema 6"
        );
        assert_eq!(
            legacy["config"]["selection"]["disk_critical_ratio_cap_gb"],
            expected_cap
        );
        let fingerprints = legacy["source_fingerprints"].clone();

        // Old effective defaults can contain null. The new parser correctly
        // preserves explicit null as uncapped, so the schema must force a
        // source/default reparse even though neither source fingerprint changed.
        legacy["schema_version"] = serde_json::json!(6);
        legacy["config"]["selection"]["disk_critical_ratio_cap_gb"] = serde_json::Value::Null;
        std::fs::write(&cache_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        show();

        let regenerated = read_cache();
        assert_eq!(regenerated["schema_version"], current_schema);
        assert_eq!(regenerated["source_fingerprints"], fingerprints);
        assert_eq!(
            regenerated["config"]["selection"]["disk_critical_ratio_cap_gb"],
            expected_cap
        );
        assert_eq!(
            std::fs::read(&config_path).ok(),
            config_before,
            "cache repair must neither create a user policy nor overwrite an explicit one"
        );
    }
}
