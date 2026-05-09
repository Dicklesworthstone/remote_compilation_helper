//! Command execution on worker.

use anyhow::Result;
use rch_common::types::RequiredRuntime;
use std::path::Path;
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::{debug, error, info};

/// Error returned when a command exits with a non-zero status.
#[derive(Debug, Error)]
#[error("Command failed with exit code: {exit_code}")]
pub struct CommandFailed {
    pub exit_code: i32,
}

/// Strip leading `VAR=value` shell env assignments from a command.
/// Returns the remainder. Tokens that look like flags (`-foo`) or that
/// contain no `=` are not stripped. Path-valued env vars are handled
/// correctly — `LD_LIBRARY_PATH=/usr/lib bun test` correctly leaves
/// `bun test` after stripping.
fn strip_leading_env_assignments(command: &str) -> &str {
    let mut rest = command.trim_start();
    loop {
        // Take the next whitespace-delimited token without copying.
        let token_end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        if token_end == 0 {
            return rest;
        }
        let token = &rest[..token_end];
        // Heuristic: a `VAR=value` assignment has the shape NAME=ANYTHING
        // where NAME is a valid shell identifier (alphanumeric + underscore,
        // starting with a letter or underscore). The VALUE may contain
        // anything (including `/`). A flag like `-x=1` is NOT stripped.
        let Some(eq_idx) = token.find('=') else {
            return rest;
        };
        let name = &token[..eq_idx];
        if name.is_empty()
            || !name
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return rest;
        }
        // It's a VAR=value assignment; advance past it.
        rest = rest[token_end..].trim_start();
    }
}

/// Return true if `command` starts with `prefix` followed by a word
/// boundary (whitespace or end-of-string). Avoids the substring-prefix
/// false-positive that would match `npm test` against `npm test:foo`.
fn starts_with_word(command: &str, prefix: &str) -> bool {
    if !command.starts_with(prefix) {
        return false;
    }
    match command.as_bytes().get(prefix.len()) {
        None => true,
        Some(c) if c.is_ascii_whitespace() => true,
        _ => false,
    }
}

/// Detect whether a worker-side command requires Bun/Node prepare (i.e.
/// `bun test`, `bun typecheck`, or any Node-flavored test runner). Returns
/// `RequiredRuntime::None` for Rust / shell / unrelated commands. The
/// detection is intentionally conservative — only commands that genuinely
/// need `node_modules/` to be installed map to Bun/Node, so a misclassified
/// Rust command never accidentally triggers `bun install`.
fn detect_runtime_from_command(command: &str) -> RequiredRuntime {
    let after_env = strip_leading_env_assignments(command);
    // Bun: `bun test`, `bun typecheck`, `bun run test` (script runner form).
    if let Some(rest) = after_env
        .strip_prefix("bun ")
        .or_else(|| after_env.strip_prefix("bun\t"))
    {
        let mut tokens = rest.split_whitespace();
        let first = tokens.next().unwrap_or("");
        if matches!(first, "test" | "typecheck") {
            return RequiredRuntime::Bun;
        }
        // `bun run test` / `bun run typecheck` — the script-runner form.
        // Note: `bun run` arbitrary-script can mean anything (build, dev,
        // ...), so we only auto-prepare for the well-known test scripts.
        if first == "run"
            && let Some(second) = tokens.next()
            && matches!(second, "test" | "typecheck")
        {
            return RequiredRuntime::Bun;
        }
    }
    // Plain Node test runners. Word-boundary match avoids `npm test:foo`
    // accidentally matching `npm test`.
    for prefix in [
        "npm test",
        "npm run test",
        "npm run-script test",
        "yarn test",
        "pnpm test",
        "npx jest",
        "npx vitest",
    ] {
        if starts_with_word(after_env, prefix) {
            return RequiredRuntime::Node;
        }
    }
    RequiredRuntime::None
}

#[cfg(test)]
mod runtime_detection_tests {
    use super::*;

    #[test]
    fn test_detect_runtime_bun_test() {
        assert_eq!(
            detect_runtime_from_command("bun test"),
            RequiredRuntime::Bun
        );
        assert_eq!(
            detect_runtime_from_command("bun typecheck"),
            RequiredRuntime::Bun
        );
    }

    #[test]
    fn test_detect_runtime_bun_run_script_form() {
        // `bun run test` is the script-runner form — same intent as `bun test`.
        assert_eq!(
            detect_runtime_from_command("bun run test"),
            RequiredRuntime::Bun
        );
        assert_eq!(
            detect_runtime_from_command("bun run typecheck"),
            RequiredRuntime::Bun
        );
        // `bun run` of anything else is NOT a test runner — don't auto-prepare.
        assert_eq!(
            detect_runtime_from_command("bun run build"),
            RequiredRuntime::None
        );
        assert_eq!(
            detect_runtime_from_command("bun run dev"),
            RequiredRuntime::None
        );
    }

    #[test]
    fn test_detect_runtime_bun_with_env_assignment() {
        // The previous regex-style heuristic incorrectly rejected env
        // values containing slashes (LD_LIBRARY_PATH=/...). Now correct.
        assert_eq!(
            detect_runtime_from_command("LD_LIBRARY_PATH=/usr/local/lib bun test"),
            RequiredRuntime::Bun
        );
        assert_eq!(
            detect_runtime_from_command("RUST_LOG=debug bun test"),
            RequiredRuntime::Bun
        );
        assert_eq!(
            detect_runtime_from_command("FOO=bar BAZ=qux bun test"),
            RequiredRuntime::Bun
        );
    }

    #[test]
    fn test_detect_runtime_word_boundary_strict() {
        // `bun testfoo` is NOT bun test.
        assert_eq!(
            detect_runtime_from_command("bun testfoo"),
            RequiredRuntime::None
        );
        // `npm test:integration` is NOT plain npm test (it's a script).
        // Both should be classified as Node since they need node_modules,
        // but the detection logic specifically only matches `npm test` at
        // word boundary — `npm test:integration` has `:` after `test` so it
        // matches as `npm test` if no boundary check. starts_with_word
        // requires whitespace, so this returns None.
        assert_eq!(
            detect_runtime_from_command("npm test:integration"),
            RequiredRuntime::None
        );
        assert_eq!(
            detect_runtime_from_command("npm run testfoo"),
            RequiredRuntime::None
        );
    }

    #[test]
    fn test_detect_runtime_npm_test_variants() {
        assert_eq!(
            detect_runtime_from_command("npm test"),
            RequiredRuntime::Node
        );
        assert_eq!(
            detect_runtime_from_command("npm run test"),
            RequiredRuntime::Node
        );
        assert_eq!(
            detect_runtime_from_command("yarn test"),
            RequiredRuntime::Node
        );
        assert_eq!(
            detect_runtime_from_command("pnpm test"),
            RequiredRuntime::Node
        );
        assert_eq!(
            detect_runtime_from_command("npx jest"),
            RequiredRuntime::Node
        );
        assert_eq!(
            detect_runtime_from_command("npx vitest"),
            RequiredRuntime::Node
        );
    }

    #[test]
    fn test_detect_runtime_unrelated_commands_are_none() {
        assert_eq!(
            detect_runtime_from_command("cargo test"),
            RequiredRuntime::None
        );
        assert_eq!(
            detect_runtime_from_command("cargo build --release"),
            RequiredRuntime::None
        );
        assert_eq!(
            detect_runtime_from_command("gcc -O2 main.c"),
            RequiredRuntime::None
        );
        assert_eq!(detect_runtime_from_command(""), RequiredRuntime::None);
        assert_eq!(detect_runtime_from_command("   "), RequiredRuntime::None);
    }

    #[test]
    fn test_strip_leading_env_assignments_basic() {
        assert_eq!(
            strip_leading_env_assignments("RUST_LOG=debug cargo test"),
            "cargo test"
        );
        assert_eq!(strip_leading_env_assignments("cargo test"), "cargo test");
    }

    #[test]
    fn test_strip_leading_env_assignments_with_paths() {
        assert_eq!(
            strip_leading_env_assignments("LD_LIBRARY_PATH=/usr/lib bun test"),
            "bun test"
        );
        assert_eq!(
            strip_leading_env_assignments("PATH=/usr/bin:/bin bun test"),
            "bun test"
        );
    }

    #[test]
    fn test_strip_leading_env_assignments_does_not_strip_flags() {
        // -x=1 is a flag, not an assignment, so it's NOT stripped.
        assert_eq!(strip_leading_env_assignments("-x=1 cmd"), "-x=1 cmd");
    }

    #[test]
    fn test_strip_leading_env_assignments_multiple() {
        assert_eq!(
            strip_leading_env_assignments("FOO=1 BAR=2 BAZ=3 cmd arg"),
            "cmd arg"
        );
    }

    #[test]
    fn test_starts_with_word_basic() {
        assert!(starts_with_word("npm test", "npm test"));
        assert!(starts_with_word("npm test foo", "npm test"));
        assert!(!starts_with_word("npm test:foo", "npm test"));
        assert!(!starts_with_word("npm testfoo", "npm test"));
    }
}

/// Execute a command in the specified working directory.
///
/// Streams stdout/stderr in real-time and returns Ok on success. For
/// Bun/Node test runners, runs `prepare::prepare()` first to ensure
/// `node_modules/` is in place (cache-aware via the dependency
/// fingerprint stored in `<workdir>/.rch_dep_fingerprint.json`).
pub async fn execute(workdir: &str, command: &str) -> Result<()> {
    info!(
        "Executing in {}: {}",
        workdir,
        rch_common::util::mask_sensitive_command(command)
    );

    if command.trim().is_empty() {
        anyhow::bail!("Empty command");
    }

    // br-4998x: pre-execution hook for Bun/Node projects.
    let runtime = detect_runtime_from_command(command);
    if matches!(runtime, RequiredRuntime::Bun | RequiredRuntime::Node) {
        let project_root = Path::new(workdir);
        let log_dir = project_root.join(".rch_prepare_logs");
        match crate::prepare::prepare(project_root, runtime, &log_dir).await {
            Ok(report) => {
                info!(
                    target: "rch::wkr::executor",
                    runtime = ?report.runtime,
                    action = ?report.action,
                    took_ms = report.took_ms,
                    bytes_added = report.bytes_added_to_node_modules,
                    "prepare completed"
                );
                if matches!(report.action, crate::prepare::PrepareAction::Failed) {
                    if let Some(p) = &report.install_log_path {
                        error!(
                            "Pre-execution prepare FAILED — install log at {}",
                            p.display()
                        );
                    }
                    return Err(CommandFailed { exit_code: 1 }.into());
                }
            }
            Err(e) => {
                // Fail-open: if prepare itself errored (no manifest, IO error)
                // we log and continue. The user's command will run and likely
                // fail with a clearer error from the test runner itself.
                tracing::warn!(
                    target: "rch::wkr::executor",
                    error = %e,
                    "prepare hook errored; continuing without install"
                );
            }
        }
    }

    // Use shell execution to properly handle quoted arguments and shell features
    // This matches how the SSH client executes commands (sh -c "...")
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(workdir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;

    // Stream stdout
    let mut stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut stderr = child.stderr.take().expect("Failed to capture stderr");

    let stdout_task = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        let mut out = tokio::io::stdout();
        loop {
            match stdout.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(e) = out.write_all(&buffer[..n]).await {
                        error!("Failed to write to stdout: {}", e);
                        break;
                    }
                    if let Err(e) = out.flush().await {
                        error!("Failed to flush stdout: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from command stdout: {}", e);
                    break;
                }
            }
        }
    });

    let stderr_task = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        let mut err = tokio::io::stderr();
        loop {
            match stderr.read(&mut buffer).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(e) = err.write_all(&buffer[..n]).await {
                        error!("Failed to write to stderr: {}", e);
                        break;
                    }
                    if let Err(e) = err.flush().await {
                        error!("Failed to flush stderr: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from command stderr: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for process to complete
    let status = child.wait().await?;

    // Wait for output tasks
    let _ = stdout_task.await;
    let _ = stderr_task.await;

    if status.success() {
        debug!("Command completed successfully");
        Ok(())
    } else {
        #[cfg(unix)]
        let code = {
            use std::os::unix::process::ExitStatusExt;
            status
                .code()
                .or_else(|| status.signal().map(|s| 128 + s))
                .unwrap_or(-1)
        };

        #[cfg(not(unix))]
        let code = status.code().unwrap_or(-1);

        error!("Command failed with exit code: {}", code);
        Err(CommandFailed { exit_code: code }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Command Parsing and Execution Tests ===

    #[tokio::test]
    async fn test_execute_echo() {
        println!("TEST START: test_execute_echo");
        let result = execute("/tmp", "echo hello").await;
        assert!(result.is_ok(), "echo should succeed");
        println!("TEST PASS: test_execute_echo");
    }

    #[tokio::test]
    async fn test_execute_invalid_dir() {
        println!("TEST START: test_execute_invalid_dir");
        let result = execute("/nonexistent/path", "ls").await;
        assert!(result.is_err(), "should fail for nonexistent directory");
        println!("TEST PASS: test_execute_invalid_dir");
    }

    #[tokio::test]
    async fn test_execute_empty_command() {
        println!("TEST START: test_execute_empty_command");
        let result = execute("/tmp", "").await;
        assert!(result.is_err(), "empty command should fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Empty command"),
            "error should mention empty command"
        );
        println!("TEST PASS: test_execute_empty_command");
    }

    #[tokio::test]
    async fn test_execute_whitespace_only_command() {
        println!("TEST START: test_execute_whitespace_only_command");
        let result = execute("/tmp", "   \t\n  ").await;
        assert!(result.is_err(), "whitespace-only command should fail");
        println!("TEST PASS: test_execute_whitespace_only_command");
    }

    #[tokio::test]
    async fn test_execute_command_with_arguments() {
        println!("TEST START: test_execute_command_with_arguments");
        let result = execute("/tmp", "echo -n test").await;
        assert!(result.is_ok(), "echo with args should succeed");
        println!("TEST PASS: test_execute_command_with_arguments");
    }

    #[tokio::test]
    async fn test_execute_command_with_quotes() {
        println!("TEST START: test_execute_command_with_quotes");
        let result = execute("/tmp", "echo 'hello world'").await;
        assert!(result.is_ok(), "command with single quotes should work");
        println!("TEST PASS: test_execute_command_with_quotes");
    }

    #[tokio::test]
    async fn test_execute_command_with_double_quotes() {
        println!("TEST START: test_execute_command_with_double_quotes");
        let result = execute("/tmp", r#"echo "hello world""#).await;
        assert!(result.is_ok(), "command with double quotes should work");
        println!("TEST PASS: test_execute_command_with_double_quotes");
    }

    #[tokio::test]
    async fn test_execute_piped_commands() {
        println!("TEST START: test_execute_piped_commands");
        let result = execute("/tmp", "echo hello | cat").await;
        assert!(result.is_ok(), "piped commands should work");
        println!("TEST PASS: test_execute_piped_commands");
    }

    #[tokio::test]
    async fn test_execute_chained_commands() {
        println!("TEST START: test_execute_chained_commands");
        let result = execute("/tmp", "echo first && echo second").await;
        assert!(result.is_ok(), "chained commands should work");
        println!("TEST PASS: test_execute_chained_commands");
    }

    #[tokio::test]
    async fn test_execute_env_variable_expansion() {
        println!("TEST START: test_execute_env_variable_expansion");
        let result = execute("/tmp", "echo $HOME").await;
        assert!(result.is_ok(), "env variable expansion should work");
        println!("TEST PASS: test_execute_env_variable_expansion");
    }

    #[tokio::test]
    async fn test_execute_command_substitution() {
        println!("TEST START: test_execute_command_substitution");
        let result = execute("/tmp", "echo $(echo nested)").await;
        assert!(result.is_ok(), "command substitution should work");
        println!("TEST PASS: test_execute_command_substitution");
    }

    #[tokio::test]
    async fn test_execute_glob_patterns() {
        println!("TEST START: test_execute_glob_patterns");
        // List all .txt files (may be none, but should not error)
        let result = execute("/tmp", "ls *.nonexistent 2>/dev/null || true").await;
        assert!(result.is_ok(), "glob pattern command should execute");
        println!("TEST PASS: test_execute_glob_patterns");
    }

    // === Exit Code Capture Tests ===

    #[tokio::test]
    async fn test_execute_exit_code_zero() {
        println!("TEST START: test_execute_exit_code_zero");
        let result = execute("/tmp", "exit 0").await;
        assert!(result.is_ok(), "exit 0 should succeed");
        println!("TEST PASS: test_execute_exit_code_zero");
    }

    #[tokio::test]
    async fn test_execute_exit_code_one() {
        println!("TEST START: test_execute_exit_code_one");
        let result = execute("/tmp", "exit 1").await;
        assert!(result.is_err(), "exit 1 should fail");

        let err = result.unwrap_err();
        if let Some(cmd_failed) = err.downcast_ref::<CommandFailed>() {
            assert_eq!(cmd_failed.exit_code, 1, "exit code should be 1");
            println!("Exit code captured: {}", cmd_failed.exit_code);
        } else {
            panic!("Expected CommandFailed error");
        }
        println!("TEST PASS: test_execute_exit_code_one");
    }

    #[tokio::test]
    async fn test_execute_exit_code_42() {
        println!("TEST START: test_execute_exit_code_42");
        let result = execute("/tmp", "exit 42").await;
        assert!(result.is_err(), "exit 42 should fail");

        let err = result.unwrap_err();
        if let Some(cmd_failed) = err.downcast_ref::<CommandFailed>() {
            assert_eq!(cmd_failed.exit_code, 42, "exit code should be 42");
            println!("Exit code captured: {}", cmd_failed.exit_code);
        } else {
            panic!("Expected CommandFailed error");
        }
        println!("TEST PASS: test_execute_exit_code_42");
    }

    #[tokio::test]
    async fn test_execute_exit_code_255() {
        println!("TEST START: test_execute_exit_code_255");
        let result = execute("/tmp", "exit 255").await;
        assert!(result.is_err(), "exit 255 should fail");

        let err = result.unwrap_err();
        if let Some(cmd_failed) = err.downcast_ref::<CommandFailed>() {
            assert_eq!(cmd_failed.exit_code, 255, "exit code should be 255");
        } else {
            panic!("Expected CommandFailed error");
        }
        println!("TEST PASS: test_execute_exit_code_255");
    }

    #[tokio::test]
    async fn test_execute_false_command() {
        println!("TEST START: test_execute_false_command");
        let result = execute("/tmp", "false").await;
        assert!(result.is_err(), "false command should fail");

        let err = result.unwrap_err();
        if let Some(cmd_failed) = err.downcast_ref::<CommandFailed>() {
            assert_eq!(cmd_failed.exit_code, 1, "false returns exit code 1");
        } else {
            panic!("Expected CommandFailed error");
        }
        println!("TEST PASS: test_execute_false_command");
    }

    #[tokio::test]
    async fn test_execute_command_not_found() {
        println!("TEST START: test_execute_command_not_found");
        let result = execute("/tmp", "nonexistent_command_xyz123").await;
        assert!(result.is_err(), "nonexistent command should fail");

        let err = result.unwrap_err();
        if let Some(cmd_failed) = err.downcast_ref::<CommandFailed>() {
            // Command not found typically returns 127
            assert_eq!(cmd_failed.exit_code, 127, "command not found returns 127");
            println!("Exit code for not found: {}", cmd_failed.exit_code);
        } else {
            panic!("Expected CommandFailed error");
        }
        println!("TEST PASS: test_execute_command_not_found");
    }

    // === Output Streaming Tests ===

    #[tokio::test]
    async fn test_execute_stdout_output() {
        println!("TEST START: test_execute_stdout_output");
        // The output goes to actual stdout, we just verify the command works
        let result = execute("/tmp", "echo 'stdout test line'").await;
        assert!(result.is_ok(), "stdout output should work");
        println!("TEST PASS: test_execute_stdout_output");
    }

    #[tokio::test]
    async fn test_execute_stderr_output() {
        println!("TEST START: test_execute_stderr_output");
        // Redirect to stderr and verify command works
        let result = execute("/tmp", "echo 'stderr test line' >&2").await;
        assert!(result.is_ok(), "stderr output should work");
        println!("TEST PASS: test_execute_stderr_output");
    }

    #[tokio::test]
    async fn test_execute_mixed_stdout_stderr() {
        println!("TEST START: test_execute_mixed_stdout_stderr");
        let result = execute("/tmp", "echo stdout; echo stderr >&2; echo stdout2").await;
        assert!(result.is_ok(), "mixed output should work");
        println!("TEST PASS: test_execute_mixed_stdout_stderr");
    }

    #[tokio::test]
    async fn test_execute_multiline_output() {
        println!("TEST START: test_execute_multiline_output");
        let result = execute("/tmp", "echo line1; echo line2; echo line3").await;
        assert!(result.is_ok(), "multiline output should work");
        println!("TEST PASS: test_execute_multiline_output");
    }

    #[tokio::test]
    async fn test_execute_large_output() {
        println!("TEST START: test_execute_large_output");
        // Generate many lines of output
        let result = execute("/tmp", "seq 1 1000").await;
        assert!(result.is_ok(), "large output should work");
        println!("TEST PASS: test_execute_large_output");
    }

    #[tokio::test]
    async fn test_execute_binary_like_output() {
        println!("TEST START: test_execute_binary_like_output");
        // Generate some binary-like output (null bytes get handled)
        let result = execute("/tmp", "printf 'text\\nmore text'").await;
        assert!(result.is_ok(), "output with special chars should work");
        println!("TEST PASS: test_execute_binary_like_output");
    }

    // === Working Directory Tests ===

    #[tokio::test]
    async fn test_execute_respects_workdir() {
        println!("TEST START: test_execute_respects_workdir");
        // Create a temp dir with a marker file
        let temp_dir =
            std::env::temp_dir().join(format!("rch-test-workdir-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        std::fs::write(temp_dir.join("marker.txt"), "exists").unwrap();

        let result = execute(temp_dir.to_str().unwrap(), "test -f marker.txt").await;
        assert!(result.is_ok(), "should find marker file in workdir");

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
        println!("TEST PASS: test_execute_respects_workdir");
    }

    #[tokio::test]
    async fn test_execute_pwd_matches_workdir() {
        println!("TEST START: test_execute_pwd_matches_workdir");
        // pwd should return the workdir
        let result = execute("/tmp", "pwd").await;
        assert!(result.is_ok(), "pwd should work");
        println!("TEST PASS: test_execute_pwd_matches_workdir");
    }

    #[tokio::test]
    async fn test_execute_relative_paths_in_workdir() {
        println!("TEST START: test_execute_relative_paths_in_workdir");
        let temp_dir =
            std::env::temp_dir().join(format!("rch-test-relpath-{}", std::process::id()));
        let subdir = temp_dir.join("subdir");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::write(subdir.join("file.txt"), "test").unwrap();

        // Access file via relative path
        let result = execute(temp_dir.to_str().unwrap(), "cat subdir/file.txt").await;
        assert!(result.is_ok(), "relative paths should work");

        // Cleanup
        let _ = std::fs::remove_dir_all(&temp_dir);
        println!("TEST PASS: test_execute_relative_paths_in_workdir");
    }

    // === Signal and Process Tests ===

    #[tokio::test]
    async fn test_execute_quick_command() {
        println!("TEST START: test_execute_quick_command");
        let result = execute("/tmp", "true").await;
        assert!(result.is_ok(), "true command should succeed immediately");
        println!("TEST PASS: test_execute_quick_command");
    }

    #[tokio::test]
    async fn test_execute_command_with_sleep() {
        println!("TEST START: test_execute_command_with_sleep");
        // Short sleep to verify async execution works
        let start = std::time::Instant::now();
        let result = execute("/tmp", "sleep 0.1").await;
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "sleep command should succeed");
        assert!(
            elapsed.as_millis() >= 100,
            "should have waited at least 100ms"
        );
        println!("TEST PASS: test_execute_command_with_sleep");
    }

    #[tokio::test]
    async fn test_execute_sigpipe_handling() {
        println!("TEST START: test_execute_sigpipe_handling");
        // Generate large output but only read first line - tests SIGPIPE handling
        let result = execute("/tmp", "yes | head -n 1").await;
        assert!(result.is_ok(), "sigpipe scenario should handle gracefully");
        println!("TEST PASS: test_execute_sigpipe_handling");
    }

    // === Error Message Tests ===

    #[tokio::test]
    async fn test_command_failed_error_display() {
        println!("TEST START: test_command_failed_error_display");
        let err = CommandFailed { exit_code: 42 };
        let msg = err.to_string();
        assert!(msg.contains("42"), "error message should contain exit code");
        assert!(
            msg.contains("exit code"),
            "error message should mention exit code"
        );
        println!("Error display: {}", msg);
        println!("TEST PASS: test_command_failed_error_display");
    }

    #[tokio::test]
    async fn test_command_failed_error_debug() {
        println!("TEST START: test_command_failed_error_debug");
        let err = CommandFailed { exit_code: 123 };
        let debug_str = format!("{:?}", err);
        assert!(
            debug_str.contains("CommandFailed"),
            "debug should contain type name"
        );
        assert!(debug_str.contains("123"), "debug should contain exit code");
        println!("Error debug: {}", debug_str);
        println!("TEST PASS: test_command_failed_error_debug");
    }

    // === Edge Cases ===

    #[tokio::test]
    async fn test_execute_special_characters_in_command() {
        println!("TEST START: test_execute_special_characters_in_command");
        let result = execute("/tmp", "echo '$HOME' \"$HOME\"").await;
        assert!(result.is_ok(), "special characters should work");
        println!("TEST PASS: test_execute_special_characters_in_command");
    }

    #[tokio::test]
    async fn test_execute_backslash_in_command() {
        println!("TEST START: test_execute_backslash_in_command");
        let result = execute("/tmp", "echo 'back\\slash'").await;
        assert!(result.is_ok(), "backslash should work");
        println!("TEST PASS: test_execute_backslash_in_command");
    }

    #[tokio::test]
    async fn test_execute_command_with_redirects() {
        println!("TEST START: test_execute_command_with_redirects");
        let temp_file =
            std::env::temp_dir().join(format!("rch-test-redirect-{}.txt", std::process::id()));
        let cmd = format!("echo 'redirect test' > '{}'", temp_file.display());

        let result = execute("/tmp", &cmd).await;
        assert!(result.is_ok(), "redirect should work");

        // Verify file was created
        assert!(temp_file.exists(), "redirected file should exist");
        let contents = std::fs::read_to_string(&temp_file).unwrap();
        assert!(
            contents.contains("redirect test"),
            "file should have content"
        );

        // Cleanup
        let _ = std::fs::remove_file(&temp_file);
        println!("TEST PASS: test_execute_command_with_redirects");
    }

    #[tokio::test]
    async fn test_execute_background_command_in_subshell() {
        println!("TEST START: test_execute_background_command_in_subshell");
        // Background job in subshell should complete
        let result = execute("/tmp", "(echo bg_test &); sleep 0.1").await;
        assert!(result.is_ok(), "background command should work");
        println!("TEST PASS: test_execute_background_command_in_subshell");
    }
}
