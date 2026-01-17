//! Command execution on worker.

use anyhow::Result;
use std::process::Stdio;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{debug, error, info};

/// Error returned when a command exits with a non-zero status.
#[derive(Debug, Error)]
#[error("Command failed with exit code: {exit_code}")]
pub struct CommandFailed {
    pub exit_code: i32,
}

/// Execute a command in the specified working directory.
///
/// Streams stdout/stderr in real-time and returns Ok on success.
pub async fn execute(workdir: &str, command: &str) -> Result<()> {
    info!("Executing in {}: {}", workdir, command);

    if command.trim().is_empty() {
        anyhow::bail!("Empty command");
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
    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    let stdout_task = tokio::spawn(async move {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await.ok().flatten() {
            println!("{}", line);
        }
    });

    let stderr_task = tokio::spawn(async move {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        while let Some(line) = lines.next_line().await.ok().flatten() {
            eprintln!("{}", line);
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
        let code = status.code().unwrap_or(-1);
        error!("Command failed with exit code: {}", code);
        Err(CommandFailed { exit_code: code }.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_execute_echo() {
        let result = execute("/tmp", "echo hello").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_invalid_dir() {
        let result = execute("/nonexistent/path", "ls").await;
        assert!(result.is_err());
    }
}
