use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn make_config_home(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_nanos();
    let config_home = std::env::temp_dir().join(format!(
        "rch-verbose-{test_name}-{}-{nanos}",
        std::process::id()
    ));
    let rch_config_dir = config_home.join("rch");
    fs::create_dir_all(&rch_config_dir).expect("create test config directory");
    fs::write(
        rch_config_dir.join("workers.toml"),
        r#"
[[workers]]
id = "builder-1"
host = "127.0.0.1"
user = "ubuntu"
identity_file = "~/.ssh/rch_verbose_test"
total_slots = 8
priority = 100
tags = ["rust", "test"]
"#,
    )
    .expect("write test workers config");
    config_home
}

fn run_rch_with_config(test_name: &str, args: &[&str]) -> Output {
    let config_home = make_config_home(test_name);
    Command::new(env!("CARGO_BIN_EXE_rch"))
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .output()
        .expect("run rch")
}

#[test]
fn test_verbose_workers_list_shows_diagnostic_details() {
    let output = run_rch_with_config("workers-list-verbose", &["--verbose", "workers", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rch workers list --verbose failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("builder-1"));
    assert!(stdout.contains("SSH Key"));
    assert!(stdout.contains("~/.ssh/rch_verbose_test"));
    assert!(stdout.contains("Live status"));
}

#[test]
fn test_normal_workers_list_hides_diagnostic_details() {
    let output = run_rch_with_config("workers-list-normal", &["workers", "list"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rch workers list failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("builder-1"));
    assert!(!stdout.contains("SSH Key"));
    assert!(!stdout.contains("Live status"));
}

#[test]
fn test_verbose_json_workers_list_stays_machine_readable() {
    let output = run_rch_with_config(
        "workers-list-json",
        &["--verbose", "--json", "workers", "list"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rch workers list --verbose --json failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let parsed_result = serde_json::from_str::<serde_json::Value>(&stdout);
    assert!(
        parsed_result.is_ok(),
        "verbose JSON output should be valid JSON: {stdout}"
    );
    let parsed = parsed_result.unwrap_or(serde_json::Value::Null);
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["data"]["count"], 1);
    assert_eq!(parsed["data"]["workers"][0]["id"], "builder-1");
    assert!(!stdout.contains("SSH Key"));
    assert!(!stdout.contains("Live status"));
}
