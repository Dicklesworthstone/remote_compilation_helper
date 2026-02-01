//! Windows/non-Unix stub hook implementation.
//!
//! RCH's daemon communication currently uses Unix domain sockets. On non-Unix
//! platforms we compile a fail-open stub so the CLI can build and the hook
//! never blocks local execution.

use crate::error::PlatformError;
use rch_common::{
    CommandPriority, CommandTimingBreakdown, CompilationKind, RequiredRuntime, SelectionResponse,
    ToolchainInfo, WorkerId,
};
use std::io::Read;

/// Run the PreToolUse hook.
///
/// On non-Unix platforms, RCH currently cannot talk to `rchd` (Unix sockets),
/// so we always allow the command (empty stdout).
pub async fn run_hook() -> anyhow::Result<()> {
    // Consume stdin to avoid surprising callers that expect input to be read,
    // but always fail-open.
    let mut _buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut _buf);
    Ok(())
}

/// Query the daemon for a worker.
///
/// On non-Unix platforms this returns an error, which upstream treats as
/// "daemon unreachable" and fails open to local execution.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn query_daemon(
    _socket_path: &str,
    _project: &str,
    _cores: u32,
    _command: &str,
    _toolchain: Option<&ToolchainInfo>,
    _required_runtime: RequiredRuntime,
    _command_priority: CommandPriority,
    _classification_duration_us: u64,
    _hook_pid: Option<u32>,
) -> anyhow::Result<SelectionResponse> {
    Err(PlatformError::UnixSocketUnsupported)?
}

/// Release reserved slots on a worker.
///
/// On non-Unix platforms this is a no-op.
pub(crate) async fn release_worker(
    _socket_path: &str,
    _worker_id: &WorkerId,
    _slots: u32,
    _build_id: Option<u64>,
    _exit_code: Option<i32>,
    _duration_ms: Option<u64>,
    _bytes_transferred: Option<u64>,
    _timing: Option<&CommandTimingBreakdown>,
) -> anyhow::Result<()> {
    Ok(())
}

/// Map a classification kind to required runtime.
pub(crate) fn required_runtime_for_kind(kind: Option<CompilationKind>) -> RequiredRuntime {
    match kind {
        Some(k) => match k {
            CompilationKind::CargoBuild
            | CompilationKind::CargoTest
            | CompilationKind::CargoCheck
            | CompilationKind::CargoClippy
            | CompilationKind::CargoDoc
            | CompilationKind::CargoNextest
            | CompilationKind::CargoBench
            | CompilationKind::Rustc => RequiredRuntime::Rust,

            CompilationKind::BunTest | CompilationKind::BunTypecheck => RequiredRuntime::Bun,

            _ => RequiredRuntime::None,
        },
        None => RequiredRuntime::None,
    }
}
