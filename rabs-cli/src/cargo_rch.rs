//! Profile-free, native handoff to RCH's worker-local RABS execution path.
//!
//! RCH remains the only execution owner. This frontend performs no daemon,
//! compiler or toolchain probe and replaces itself exactly once. In particular,
//! a remote failure can never come back here and start a local Cargo process.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Launcher controls must not become Cargo options. Once the program/test
/// separator appears, all remaining arguments are literal user data instead.
pub(crate) fn reject_frontend_controls(arguments: &[OsString]) -> io::Result<()> {
    for argument in arguments.iter().take_while(|argument| *argument != "--") {
        let bytes = argument.as_encoded_bytes();
        let name = bytes.split(|byte| *byte == b'=').next().unwrap_or(bytes);
        if bytes.starts_with(b"--rabs-")
            || matches!(
                name,
                b"--rch"
                    | b"--cache"
                    | b"--local"
                    | b"--remote"
                    | b"--worker"
                    | b"--rabsd"
                    | b"--stdin"
                    | b"--stdin-file"
            )
        {
            return Err(invalid(
                "select one frontend mode; launcher controls cannot be passed to Cargo",
            ));
        }
    }
    Ok(())
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
}

/// Follow the installed launcher's explicit-override, physical-sibling, then
/// PATH precedence. Keep the final symlink spelling for multi-call executables.
/// An invalid explicit override is a refusal, never permission to use PATH.
pub(crate) fn executable(name: &str, override_name: &str, current: &Path) -> io::Result<PathBuf> {
    let selected = if let Some(value) = std::env::var_os(override_name) {
        let candidate = PathBuf::from(value);
        if candidate.as_os_str().is_empty() || !is_executable(&candidate) {
            return Err(invalid(format!("{override_name} is not executable")));
        }
        candidate
    } else {
        let sibling = current
            .parent()
            .ok_or_else(|| invalid("frontend directory is unavailable"))?
            .join(name);
        if is_executable(&sibling) {
            sibling
        } else {
            std::env::var_os("PATH")
                .and_then(|path| {
                    std::env::split_paths(&path)
                        .map(|directory| directory.join(name))
                        .find(|candidate| is_executable(candidate))
                })
                .ok_or_else(|| {
                    invalid(format!(
                        "{name} is not installed; select {override_name} or install a matching sibling"
                    ))
                })?
        }
    };
    let selected = std::path::absolute(selected)?;
    let own = fs::metadata(current)?;
    let metadata = fs::metadata(&selected)?;
    if (metadata.dev(), metadata.ino()) == (own.dev(), own.ino()) {
        return Err(invalid(format!(
            "{override_name} resolves to this frontend"
        )));
    }
    Ok(selected)
}

/// Handoff after the Cargo subcommand has consumed its launcher controls. All
/// remaining arguments are Cargo data, including any additional delimiters.
pub(crate) fn run(arguments: &[OsString], current: &Path) -> io::Result<()> {
    // RCH's command boundary is Vec<String>. Refuse opaque bytes instead of
    // silently replacing them; stdin and inherited descriptors remain opaque.
    if arguments.iter().any(|argument| {
        argument
            .to_str()
            .is_none_or(|argument| argument.contains('\0'))
    }) {
        return Err(invalid("remote Cargo arguments must be UTF-8 without NUL"));
    }
    for key in [
        "CARGO_RABS_REMOTE_ACTIVE",
        "CARGO_RABS_CANONICAL_ACTIVE",
        "RCH_RABS_WORKER_ACTIVE",
    ] {
        if std::env::var_os(key).as_deref() == Some(OsStr::new("1")) {
            return Err(invalid("nested remote dispatch is unsupported"));
        }
    }
    if [
        "CARGO_RABS_ROOT_BUDGET_DIR",
        "CARGO_RABS_ROOT_CAPACITY",
        "CARGO_RABS_ROOT_CGROUP",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some())
    {
        return Err(invalid(
            "local Cargo root admission cannot combine with remote dispatch",
        ));
    }
    let rch = executable("rch", "CARGO_RABS_RCH", current)?;
    let mut command = Command::new(rch);
    command.args(["exec", "--source-content-receipt", "--", "cargo"]);
    if arguments.is_empty() {
        command.arg("build");
    } else {
        command.args(arguments);
    }
    command
        .env("RCH_REQUIRE_REMOTE", "1")
        .env("RCH_RABS_WORKER_CACHE", "1")
        .env("CARGO_RABS_REMOTE_ACTIVE", "1");
    // No spawn/wait/retry path and no change to cwd, streams or inherited
    // jobserver handles. RCH owns its admission and recovery policy from here.
    Err(command.exec())
}
