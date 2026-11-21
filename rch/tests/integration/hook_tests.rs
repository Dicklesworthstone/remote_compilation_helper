use std::process::{Command, Stdio};

use super::common::init_test_logging;

#[test]
fn test_hook_allows_non_compilation() {
    init_test_logging();
    crate::test_log!("TEST START: test_hook_allows_non_compilation");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rch"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start rch hook");

    let input = "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls\"}}\n";
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        stdin
            .write_all(input.as_bytes())
            .expect("Failed to write hook input");
    }

    let output = child
        .wait_with_output()
        .expect("Failed to read hook output");
    assert!(output.status.success(), "Hook exited with failure");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().is_empty(),
        "Expected empty output, got: {stdout}"
    );

    crate::test_log!("TEST PASS: test_hook_allows_non_compilation");
}

const JOB_RULES: &str = r#"
[jobs]
intercept_enabled = true
required_tools = ["rustc"]

[[jobs.rules]]
name = "mutation-gate"
argv_prefix = ["gate-fixture", "gate"]
required_flags = ["--mutation"]
result_dirs = ["reports/default"]
require_tools = ["gate-fixture"]
output_flag = "--output"
"#;

/// Exercise the real no-argument hook entry point, including its startup
/// passthrough. No gate executable or worker is installed: interception must
/// only return a rewrite, never run the workload during PreToolUse.
fn configured_hook(
    user_config: &str,
    project_config: Option<&str>,
    command: &str,
) -> std::process::Output {
    use std::io::Write;

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let config_dir = home.join("config/rch");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::create_dir_all(project.join("member")).unwrap();
    std::fs::write(config_dir.join("config.toml"), user_config).unwrap();
    if let Some(contents) = project_config {
        std::fs::create_dir_all(project.join(".rch")).unwrap();
        std::fs::write(project.join(".rch/config.toml"), contents).unwrap();
    }
    let input = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
            "description": "Run the mutation gate",
            "timeout": 240000,
            "run_in_background": true
        }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("RCH_CONFIG_DIR", &config_dir)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home.join("cache"))
        .env("RCH_DISABLE_CONFIG_CACHE", "1")
        .env("RCH_DISABLE_DAEMON_AUTOSTART", "1")
        .current_dir(project.join("member"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn native hook");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.to_string().as_bytes()).unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "hook failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn configured_job_hook_rewrites_literal_argv_and_preserves_permission_and_tool_fields() {
    let command = "gate-fixture gate --mutation --output 'reports/run with spaces' -- '' 'a;$HOME'";
    let output = configured_hook(JOB_RULES, None, command);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let hook = &response["hookSpecificOutput"];
    assert_eq!(hook["hookEventName"], "PreToolUse");
    assert!(
        hook.get("permissionDecision").is_none(),
        "a configured arbitrary command must retain normal tool permission checks"
    );
    let updated = &hook["updatedInput"];
    assert_eq!(updated["timeout"], 240000);
    assert_eq!(updated["run_in_background"], true);
    assert_eq!(updated["description"], "Run the mutation gate");
    let rewritten = updated["command"].as_str().unwrap();
    let argv = shell_words::split(rewritten).unwrap();
    assert_eq!(
        &argv[..6],
        [
            "rch",
            "exec",
            "--job",
            "--result-dir=reports/run with spaces",
            "--require-tool=gate-fixture",
            "--",
        ]
    );
    let original_argv = shell_words::split(command).unwrap();
    assert_eq!(&argv[6..], original_argv.as_slice());
}

#[test]
fn configured_job_hook_respects_default_off_and_project_local_policy() {
    let command = "gate-fixture gate --mutation";
    for (user, project) in [
        ("", None),
        (JOB_RULES, Some("[jobs]\nintercept_enabled = false\n")),
        (JOB_RULES, Some("[jobs]\nrules = []\n")),
        (JOB_RULES, Some("[general]\nenabled = false\n")),
        (JOB_RULES, Some("[general]\nforce_local = true\n")),
    ] {
        let output = configured_hook(user, project, command);
        assert!(
            output.stdout.is_empty(),
            "expected unchanged local command: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    // A repository can opt in even when its global config has no job section;
    // the same rule must be found from a nested member working directory.
    let output = configured_hook("", Some(JOB_RULES), command);
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        response["hookSpecificOutput"]["updatedInput"]["command"]
            .as_str()
            .unwrap()
            .starts_with("rch exec --job ")
    );
}

#[test]
fn configured_job_hook_declines_ambiguous_commands_and_output_escape() {
    for command in [
        "gate-fixture gate",
        "gate-fixture gate -- --mutation",
        "gate-fixture gate --mutation | tee report",
        "gate-fixture gate --mutation > report",
        "gate-fixture gate --mutation && echo done",
        "gate-fixture gate --mutation --output ../outside",
        "gate-fixture gate --mutation --output /tmp/outside",
        "gate-fixture gate --mutation --output",
        "gate-fixture gate --mutation --output one --output two",
        "gate-fixture gate --mutation --output \"$REPORT_DIR\"",
        "env MODE=test gate-fixture gate --mutation",
        "rch exec --job -- gate-fixture gate --mutation",
    ] {
        let output = configured_hook(JOB_RULES, None, command);
        assert!(
            output.stdout.is_empty(),
            "{command}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn configured_job_hook_keeps_compilation_classification_precedence() {
    let config = r#"
[jobs]
intercept_enabled = true

[[jobs.rules]]
name = "broad-cargo"
argv_prefix = ["cargo"]
result_dirs = ["reports"]
"#;
    let output = configured_hook(config, None, "cargo build --release");
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        response["hookSpecificOutput"]["updatedInput"]["command"],
        "rch exec -- cargo build --release"
    );
}
