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
use std::path::PathBuf;

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

/// Execute a compilation command locally.
///
/// On non-Unix platforms we do not support daemon-based offloading, so `rch exec`
/// simply runs the provided command via the local shell.
pub async fn run_exec(
    base: Option<String>,
    clean_overlay: bool,
    overlay_paths: Vec<PathBuf>,
    no_overlay: bool,
    command_parts: Vec<String>,
) -> anyhow::Result<()> {
    if clean_overlay || base.is_some() || !overlay_paths.is_empty() || no_overlay {
        anyhow::bail!("clean-overlay remote execution is not supported on non-Unix clients");
    }
    let command = command_parts.join(" ");
    if command.is_empty() {
        anyhow::bail!("No command provided to exec");
    }

    let status = std::process::Command::new("cmd")
        .arg("/C")
        .arg(&command)
        .status()?;

    std::process::exit(status.code().unwrap_or(1));
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
    _wait_for_worker: bool,
    _preferred_workers: &[WorkerId],
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
            | CompilationKind::CargoZigbuild
            | CompilationKind::Rustc => RequiredRuntime::Rust,

            CompilationKind::BunTest | CompilationKind::BunTypecheck => RequiredRuntime::Bun,

            // Mirror the Unix hook (hook.rs): a nix build must carry the Nix
            // runtime so worker selection gates it to a nix-capable worker via
            // `has_nix()`. Without this, a nix build offloaded from a Windows
            // client fell through to `None` and could be dispatched to a
            // non-nix worker (where it would fail) instead of being gated.
            CompilationKind::NixBuild => RequiredRuntime::Nix,

            // Go builds/tests/vets must carry the Go runtime so worker selection
            // gates them to a go-capable worker via `has_go()`. Falling through to
            // the `_ => None` catch-all would disable capability gating entirely and
            // dispatch `go build` to a worker with no Go toolchain.
            CompilationKind::GoBuild | CompilationKind::GoTest | CompilationKind::GoVet => {
                RequiredRuntime::Go
            }

            // `tsc` / `npx tsc` run under Node.
            CompilationKind::Tsc => RequiredRuntime::Node,

            _ => RequiredRuntime::None,
        },
        None => RequiredRuntime::None,
    }
}
