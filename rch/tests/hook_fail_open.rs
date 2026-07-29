//! Fail-open contract tests for `run_hook` at the binary level.
//!
//! These tests are the regression net for the project's most important
//! invariant (AGENTS.md): **any non-zero exit from the hook BLOCKS the
//! agent's Bash command.** When stdin is garbage / empty / malformed /
//! shape-mismatched, the hook MUST exit 0 with empty stdout so Claude
//! Code allows the command to proceed.
//!
//! Coverage gap closed: prior to this file, the only thing pinning
//! fail-open behavior was a code review (commit `68fcb7c`). Without
//! these tests, the next regression — by an agent who doesn't know the
//! contract — would silently break it.
//!
//! Each test invokes the `rch` binary as a subprocess (no internal
//! helpers, since the bug class lives at the entry point), feeds a
//! crafted stdin payload, and asserts:
//!   * exit code = 0
//!   * stdout is empty (Allow == empty stdout per the hook protocol)
//!   * stderr may contain diagnostic warnings (we don't assert on it)

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Build a fresh, empty config home for the test so the binary doesn't
/// pick up the operator's real `~/.config/rch/`. The hook still works
/// without a config (it fails-open even when no workers are configured),
/// but isolating the config prevents the test from interacting with the
/// developer's live setup.
fn fresh_config_home(test_name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "rch-failopen-{test_name}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(home.join("rch")).expect("create test config dir");
    home
}

/// Spawn `rch` in hook mode (`RCH_HOOK_MODE=1`, no subcommand args),
/// pipe `stdin_bytes` to it, and capture the result.
fn run_hook_with_stdin(test_name: &str, stdin_bytes: &[u8]) -> std::process::Output {
    let config_home = fresh_config_home(test_name);
    let mut child = Command::new(env!("CARGO_BIN_EXE_rch"))
        .env("RCH_HOOK_MODE", "1")
        .env("XDG_CONFIG_HOME", &config_home)
        // Silence the global daemon socket so the hook doesn't try to
        // talk to a daemon. Hook mode still proceeds; failure modes
        // tested here happen before any daemon interaction.
        .env("RCH_DISABLE_DAEMON_AUTOSTART", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rch");
    {
        let stdin = child.stdin.as_mut().expect("rch stdin pipe");
        let _ = stdin.write_all(stdin_bytes);
        // Drop stdin to signal EOF.
    }
    drop(child.stdin.take());
    child.wait_with_output().expect("wait_with_output")
}

fn assert_fail_open(test_name: &str, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "[{test_name}] exit code must be 0 (any non-zero BLOCKS the agent). \
         got status={:?}\nstdout={stdout}\nstderr={stderr}",
        output.status
    );
    assert!(
        stdout.is_empty(),
        "[{test_name}] stdout must be empty (Allow == empty per protocol). \
         got {} bytes: {stdout:?}",
        stdout.len()
    );
}

#[test]
fn fail_open_garbage_stdin_binary_noise() {
    // Binary noise that's not valid UTF-8 in some bytes.
    let payload = b"\xFF\xFEnot\x00json\x00\x01\x02";
    let out = run_hook_with_stdin("garbage_binary", payload);
    assert_fail_open("garbage_binary", &out);
}

#[test]
fn fail_open_empty_stdin() {
    let out = run_hook_with_stdin("empty_stdin", b"");
    assert_fail_open("empty_stdin", &out);
}

#[test]
fn fail_open_malformed_json_open_brace_only() {
    let out = run_hook_with_stdin("malformed_open_brace", b"{");
    assert_fail_open("malformed_open_brace", &out);
}

#[test]
fn fail_open_malformed_json_truncated_string() {
    let out = run_hook_with_stdin("malformed_truncated_str", b"{\"a\":\"value");
    assert_fail_open("malformed_truncated_str", &out);
}

#[test]
fn fail_open_missing_required_fields() {
    // Valid JSON object, but shape doesn't match HookInput.
    let out = run_hook_with_stdin("missing_required", b"{\"unrelated\":1}");
    assert_fail_open("missing_required", &out);
}

#[test]
fn fail_open_wrong_field_types() {
    // `tool_input.command` should be a string. Sending an integer
    // triggers serde failure → fail-open.
    let payload = b"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":42}}";
    let out = run_hook_with_stdin("wrong_types", payload);
    assert_fail_open("wrong_types", &out);
}

#[test]
fn fail_open_json_shape_mismatch_nested_wrong() {
    // Structurally valid JSON, but tool_input is the wrong type entirely.
    let payload = b"{\"tool_name\":\"Bash\",\"tool_input\":\"not-an-object\"}";
    let out = run_hook_with_stdin("shape_mismatch", payload);
    assert_fail_open("shape_mismatch", &out);
}

#[test]
fn fail_open_whitespace_only_stdin() {
    // Whitespace-only is trimmed to empty → silent allow per run_hook.
    let out = run_hook_with_stdin("whitespace_only", b"   \n\t  \n");
    assert_fail_open("whitespace_only", &out);
}

#[test]
fn fail_open_unicode_invalid_utf8_bytes() {
    // Invalid UTF-8 sequences mid-stream. stdin().read_to_string lossily
    // converts these; the parser then sees garbage and fails-open.
    let payload = b"\x80\x80\x80abc\xC0\xC0";
    let out = run_hook_with_stdin("invalid_utf8", payload);
    assert_fail_open("invalid_utf8", &out);
}

#[test]
fn fail_open_null_byte_in_command() {
    // Embedded NUL in the command string. JSON is valid; the underlying
    // shell would reject this — but the HOOK must still exit 0; the
    // user's downstream Bash will handle the NUL however it chooses.
    let payload = b"{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"cargo \\u0000 build\"}}";
    let out = run_hook_with_stdin("null_byte_cmd", payload);
    assert_fail_open("null_byte_cmd", &out);
}

#[test]
fn fail_open_huge_stdin_within_10mb_cap() {
    // 1 MB of bytes — well under the 10 MB cap. Should parse-fail and
    // fail-open within a reasonable wallclock.
    let payload = vec![b'X'; 1024 * 1024];
    let out = run_hook_with_stdin("huge_1mb", &payload);
    assert_fail_open("huge_1mb", &out);
}

#[test]
fn fail_open_exceeds_10mb_cap() {
    // 11 MB of bytes — exceeds the 10 MB cap; the take() limit kicks in.
    // The read returns truncated data which then fails to parse as JSON,
    // landing in the fail-open path. Critically: no panic, no non-zero exit.
    let payload = vec![b'Y'; 11 * 1024 * 1024];
    let out = run_hook_with_stdin("huge_11mb", &payload);
    assert_fail_open("huge_11mb", &out);
}

#[test]
fn fail_open_array_at_top_level_not_object() {
    // Top-level array is valid JSON but the wrong shape for HookInput.
    let out = run_hook_with_stdin("top_array", b"[1,2,3]");
    assert_fail_open("top_array", &out);
}

#[test]
fn fail_open_top_level_string_not_object() {
    let out = run_hook_with_stdin("top_string", b"\"just a string\"");
    assert_fail_open("top_string", &out);
}

#[test]
fn fail_open_top_level_number_not_object() {
    let out = run_hook_with_stdin("top_number", b"42");
    assert_fail_open("top_number", &out);
}

#[test]
fn fail_open_partial_json_no_closing_brace() {
    let payload = br#"{"tool_name":"Bash","tool_input":{"command":"echo hi""#;
    let out = run_hook_with_stdin("partial_no_close", payload);
    assert_fail_open("partial_no_close", &out);
}
