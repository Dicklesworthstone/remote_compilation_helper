//! Linux force-stop binds the configured peer to a stable kernel PID handle.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub(super) async fn stop(socket_path: &Path, pid: u32) -> Result<()> {
    anyhow::ensure!(pid > 1 && pid != std::process::id(), "unsafe daemon PID");
    let mut child = Command::new("python3")
        .args(["-I", "-S", "-c", include_str!("force_stop.py")])
        .arg(socket_path)
        .arg(pid.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("cannot start Linux pidfd force-stop; Python 3.9+ is required; use --drain")?;
    let stdout = child.stdout.take().context("force-stop lacks stdout")?;
    let stderr = child.stderr.take().context("force-stop lacks stderr")?;
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::try_join!(
            crate::transfer::read_bounded_output_stream(stdout, 4096),
            crate::transfer::read_bounded_output_stream(stderr, 4096),
            child.wait(),
        )
    })
    .await;
    let (stdout, stderr, status) = match result {
        Ok(Ok(output)) => output,
        other => {
            let _ = child.start_kill();
            anyhow::bail!(
                "force-stop completion unconfirmed; no fallback signal or socket removal: {other:?}"
            );
        }
    };
    anyhow::ensure!(
        status.success()
            && stderr.is_empty()
            && stdout == format!("RCH_DAEMON_STOPPED_V1:{pid}\n").as_bytes(),
        "force-stop completion unconfirmed ({status}): {}; socket and admission require reconciliation",
        String::from_utf8_lossy(&stderr).trim()
    );
    Ok(())
}
