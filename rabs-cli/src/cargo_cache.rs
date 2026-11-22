//! Ordinary local Cargo through the existing native cache preparation owner.
//!
//! The frontend never starts a daemon or compiler itself. One exec transfers
//! stdin, jobserver descriptors and the original Cargo arguments to the same
//! bounded native adapter used on RCH workers. That adapter alone owns setup,
//! authenticated daemon attachment and any safe pre-execution fallback.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn is_executable(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

fn absolute(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Explicit setup policy for the Cargo subcommand. The ordinary native cache
/// frontend and RCH workers retain their existing best-effort startup policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    pub no_start: bool,
    pub require_daemon: bool,
}

fn cargo_executable(frontend: &Path, worker: &Path) -> io::Result<PathBuf> {
    let selected = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    if selected.is_empty() {
        return Err(invalid("CARGO must name an executable"));
    }
    let selected = if selected.as_bytes().contains(&b'/') {
        PathBuf::from(selected)
    } else {
        let search = std::env::var_os("PATH")
            .ok_or_else(|| invalid("Cargo discovery requires CARGO or PATH"))?;
        std::env::split_paths(&search)
            .map(|directory| directory.join(&selected))
            .find(|path| is_executable(path))
            .ok_or_else(|| invalid("Cargo is not executable on PATH"))?
    };
    if !is_executable(&selected) {
        return Err(invalid("CARGO does not name an executable file"));
    }
    let metadata = std::fs::metadata(&selected)?;
    for launcher in [frontend, worker] {
        let other = std::fs::metadata(launcher)?;
        if metadata.dev() == other.dev() && metadata.ino() == other.ino() {
            return Err(invalid("CARGO resolves to a cache launcher itself"));
        }
    }
    // Preserve the final symlink spelling. A Rustup proxy selects its role
    // from argv[0], so canonicalizing cargo to rustup would change the command.
    absolute(selected)
}

/// Execute Cargo arguments after the caller has consumed its own controls and
/// delimiter. Do not strip another delimiter or reinterpret literal Cargo data.
pub(crate) fn run(arguments: &[OsString], frontend: &Path, policy: Policy) -> io::Result<()> {
    let worker = crate::cargo_rch::executable("rch-wkr", "CARGO_RABS_WORKER", frontend)?;
    let cargo = cargo_executable(frontend, &worker)?;
    let root_keys = [
        "CARGO_RABS_ROOT_BUDGET_DIR",
        "CARGO_RABS_ROOT_CAPACITY",
        "CARGO_RABS_ROOT_CGROUP",
    ];
    let root_admission = root_keys.iter().any(|key| std::env::var_os(key).is_some());
    let root_helper = if root_admission {
        if root_keys.iter().any(|key| std::env::var_os(key).is_none())
            || std::env::var_os("CARGO_RABS_ROOT_ACTIVE").is_some()
        {
            return Err(invalid(
                "local root admission requires all three controls and no active root",
            ));
        }
        Some(crate::cargo_rch::executable(
            "rabs-cargo-root",
            "CARGO_RABS_ROOT_HELPER",
            frontend,
        )?)
    } else {
        None
    };
    let mut command = Command::new(worker);
    command.args(["worker-cache", "--protocol", "v1"]);
    if policy.no_start {
        command.arg("--no-start");
    }
    if policy.require_daemon {
        command.arg("--require-daemon");
    }
    command.arg("--");
    if let Some(root_helper) = root_helper {
        // Explicit admission stays in the one execution chain even when cache
        // preparation declines. Only the native root owner validates cgroup
        // delegation, holds the grant and starts Cargo within its owned tree.
        command.arg(root_helper).arg("--");
    }
    command.arg(cargo);
    if arguments.is_empty() {
        command.arg("build");
    } else {
        command.args(arguments);
    }
    // No environment is synthesized here. In particular, a caller's explicit
    // wrapper opt-out and Cargo/Rustup selection reach the native adapter
    // unchanged, and the adapter retains the compiler-skip decision boundary.
    Err(command.exec())
}
