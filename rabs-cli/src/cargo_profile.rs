//! Bounded operator intent retained privately before one native-driver exec.

#[path = "cargo_worker.rs"]
mod worker;

use crate::cargo_cli::{Input, Mode, Options};
use rabs_sandbox::cargo_check::{CompilationCommand, CompilationSelection, CompilationStdin};
use rabs_sandbox::process_context::CommandContext;
use rustix::fs::{Mode as FileMode, OFlags};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const MAX_PROFILE: u64 = 64 * 1024;
const RUSTUP_DISCOVERY_BUDGET: Duration = Duration::from_secs(5);
const RUSTUP_REAP_BUDGET: Duration = Duration::from_millis(250);
const MAX_RUSTUP_PATH_BYTES: usize = 4097;
const RUSTUP_GUARD: &str = "--rabs-internal-rustup-discovery-v1";
const MAX_RUSTUP_REPLY_BYTES: usize = 16 * 1024;
const LOGICAL_FIELDS: &[&str] = &[
    "command",
    "selection",
    "stdin",
    "stdin_file",
    "manifest",
    "vendor",
    "source_selection",
    "jobs",
    "timeout_seconds",
    "env",
];

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn require(condition: bool, reason: &'static str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(reason))
    }
}

fn string<'a>(object: &'a Map<String, Value>, name: &str) -> io::Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("profile requires a string field"))
}

fn plain_absolute(value: &str) -> io::Result<PathBuf> {
    require(
        value.starts_with('/')
            && value.len() > 1
            && !value.contains(['\\', '\0'])
            && value
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "profile paths must be ordinary absolute paths without traversal",
    )?;
    Ok(PathBuf::from(value))
}

fn relative_member(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.contains(['\\', ':'])
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn open_directory(path: &Path) -> io::Result<File> {
    require(path.is_absolute(), "directory must be absolute")?;
    let mut descriptor = rustix::fs::open("/", directory_flags(), FileMode::empty())?;
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                descriptor =
                    rustix::fs::openat(&descriptor, name, directory_flags(), FileMode::empty())?;
            }
            _ => return Err(invalid("directory path contains traversal")),
        }
    }
    Ok(File::from(descriptor))
}

fn open_regular(path: &Path) -> io::Result<File> {
    let parent = open_directory(path.parent().ok_or_else(|| invalid("file has no parent"))?)?;
    let name = path
        .file_name()
        .ok_or_else(|| invalid("file has no name"))?;
    let file = File::from(rustix::fs::openat(
        &parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        FileMode::empty(),
    )?);
    require(
        file.metadata()?.is_file(),
        "profile inputs must be ordinary files",
    )?;
    Ok(file)
}

fn private_directory(path: &Path) -> io::Result<File> {
    let file = open_directory(path)?;
    let metadata = file.metadata()?;
    require(
        metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o077 == 0,
        "state, staging and output parents must be private to the current user",
    )?;
    Ok(file)
}

fn absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(invalid(
            "output destination already exists; choose a new destination",
        )),
    }
}

fn fingerprint(metadata: &fs::Metadata) -> [u64; 9] {
    [
        metadata.dev(),
        metadata.ino(),
        metadata.uid().into(),
        metadata.mode().into(),
        metadata.len(),
        metadata.mtime() as u64,
        metadata.mtime_nsec() as u64,
        metadata.ctime() as u64,
        metadata.ctime_nsec() as u64,
    ]
}

// Value's ordinary deserializer replaces duplicate object fields. A profile is
// execution intent, so every level must instead have exactly one spelling.
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object fields")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(|value| UniqueValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_owned())))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((name, UniqueValue(value))) =
                    entries.next_entry::<String, UniqueValue>()?
                {
                    if values.insert(name, value).is_some() {
                        return Err(de::Error::custom("duplicate profile field"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn read_profile(path: &Path) -> io::Result<Map<String, Value>> {
    let path = std::path::absolute(path)?;
    let mut file = open_regular(&path)?;
    let before = file.metadata()?;
    require(
        before.len() <= MAX_PROFILE
            && before.uid() == rustix::process::geteuid().as_raw()
            && before.mode() & 0o022 == 0,
        "profile must be bounded, owned and not writable by other users",
    )?;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_PROFILE + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() as u64 == before.len()
            && fingerprint(&before) == fingerprint(&file.metadata()?),
        "profile changed while reading",
    )?;
    let UniqueValue(value) = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("profile JSON is malformed or contains duplicate fields"))?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("profile must be a JSON object"))
}

fn logical(
    profile: &mut Map<String, Value>,
    options: &Options,
    service: bool,
) -> io::Result<CompilationCommand> {
    if let Some((command, selection)) = &options.selected {
        profile.insert("command".into(), serde_json::to_value(command)?);
        profile.insert("selection".into(), serde_json::to_value(selection)?);
    }
    if let Some(input) = &options.input {
        profile.remove("stdin");
        profile.remove("stdin_file");
        match input {
            Input::Policy(policy) => {
                profile.insert("stdin".into(), serde_json::to_value(policy)?);
            }
            Input::File(path) => {
                profile.insert("stdin_file".into(), Value::String(path.clone()));
            }
        }
    }
    let command: CompilationCommand = serde_json::from_value(
        profile
            .get("command")
            .cloned()
            .unwrap_or_else(|| Value::String("check".into())),
    )
    .map_err(|_| invalid("unsupported canonical Cargo command"))?;
    let selection: CompilationSelection = match profile.get("selection") {
        None | Some(Value::Null) => CompilationSelection::default(),
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|_| invalid("invalid native Cargo selection"))?,
    };
    selection.cargo_arguments(command)?;
    selection.runtime_arguments(command)?;
    let requested = match profile.get("stdin") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value::<CompilationStdin>(value.clone())
                .map_err(|_| invalid("stdin must be closed or inherit"))?,
        ),
    };
    let inherited = if let Some(value) = profile.get("stdin_file").filter(|value| !value.is_null())
    {
        require(requested.is_none(), "choose stdin or stdin_file, not both")?;
        require(
            command == CompilationCommand::Run
                || (matches!(
                    command,
                    CompilationCommand::Test | CompilationCommand::Bench
                ) && !selection.no_run),
            "captured stdin_file requires run, test or bench execution",
        )?;
        require(
            value.as_str().is_some_and(relative_member),
            "stdin_file must name an ordinary source-root-relative file",
        )?;
        false
    } else {
        command.stdin_policy(selection.no_run, requested)? == CompilationStdin::Inherit
    };
    require(
        !inherited || !service,
        "service run/test/bench requires explicit closed stdin or a captured stdin_file",
    )?;
    require(
        !inherited || !io::stdin().is_terminal(),
        "inherited run/test/bench stdin must be a pipe, file or /dev/null",
    )?;
    for (field, maximum) in [("jobs", 4096), ("timeout_seconds", 7200)] {
        if let Some(value) = profile.get(field) {
            require(
                value
                    .as_u64()
                    .is_some_and(|value| value > 0 && value <= maximum),
                "jobs or timeout_seconds is outside its native bounds",
            )?;
        }
    }
    let manifest = profile
        .get("manifest")
        .map_or(Some("Cargo.toml"), Value::as_str)
        .ok_or_else(|| invalid("manifest must name a relative Cargo.toml"))?;
    require(
        relative_member(manifest)
            && Path::new(manifest).file_name() == Some(OsStr::new("Cargo.toml")),
        "manifest must name a relative Cargo.toml",
    )?;
    if let Some(vendor) = profile.get("vendor").filter(|value| !value.is_null()) {
        require(
            vendor.as_str().is_some_and(relative_member),
            "vendor must be source-root-relative",
        )?;
    }
    if let Some(selection) = profile.get("source_selection") {
        require(
            selection.as_str() == Some("cargo-unit-graph-v1")
                && profile.get("vendor").is_none_or(Value::is_null),
            "source_selection must be cargo-unit-graph-v1 without vendor",
        )?;
    }
    let mut environment = vec![
        ("CARGO_INCREMENTAL".into(), "0".into()),
        ("CARGO_TARGET_DIR".into(), "/__rabs/out/cargo".into()),
        ("RUSTC".into(), "/__rabs/toolchain/bin/rustc".into()),
    ];
    if matches!(command, CompilationCommand::Test | CompilationCommand::Doc) {
        environment.push(("RUSTDOC".into(), "/__rabs/toolchain/bin/rustdoc".into()));
    }
    if command == CompilationCommand::Clippy {
        environment.push(("CARGO".into(), "/__rabs/toolchain/bin/cargo".into()));
    }
    command_environment(profile.get("env"), environment, "/__rabs/workspace")?;
    Ok(command)
}

fn command_environment(
    values: Option<&Value>,
    mut environment: Vec<(String, String)>,
    cwd: &str,
) -> io::Result<CommandContext> {
    if let Some(env) = values {
        for (name, value) in env
            .as_object()
            .ok_or_else(|| invalid("env must be an object of literal strings"))?
        {
            require(
                !matches!(
                    name.as_str(),
                    "CARGO" | "RUSTC" | "RUSTDOC" | "RUSTFLAGS" | "RUSTDOCFLAGS" | "GLIBC_TUNABLES"
                ) && ![
                    "CARGO_", "RUSTUP_", "RUSTC_", "RUSTDOC_", "CLIPPY_", "RABS_", "RCH_", "LD_",
                    "DYLD_",
                ]
                .iter()
                .any(|prefix| name.starts_with(prefix)),
                "env cannot replace compiler, loader or preparation controls",
            )?;
            environment.push((
                name.clone(),
                value
                    .as_str()
                    .ok_or_else(|| invalid("env values must be strings"))?
                    .to_owned(),
            ));
        }
    }
    CommandContext::new(cwd, environment)
        .map_err(|_| invalid("env exceeds the native identifier or value bounds"))
}

fn roots_disjoint(roots: &[PathBuf]) -> io::Result<()> {
    for (index, left) in roots.iter().enumerate() {
        for right in &roots[index + 1..] {
            require(
                !left.starts_with(right) && !right.starts_with(left),
                "captured, state, staging and output roots must be disjoint",
            )?;
        }
    }
    Ok(())
}

fn executable(path: &Path) -> io::Result<()> {
    let file = open_regular(path)?;
    require(
        file.metadata()?.mode() & 0o111 != 0
            && rustix::fs::accessat(
                rustix::fs::CWD,
                path,
                rustix::fs::Access::EXEC_OK,
                rustix::fs::AtFlags::EACCESS,
            )
            .is_ok(),
        "selected native tools must be executable ordinary files",
    )
}

fn rustup_executable(current: &Path) -> io::Result<PathBuf> {
    // Keep PATH order, relative/empty entries and the selected alias spelling.
    // Rustup's invocation location and environment choose the toolchain; the
    // profile directory and the later native daemon must never do that lookup.
    let available = |path: &Path| -> io::Result<bool> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Ok(false);
        }
        match rustix::fs::accessat(
            rustix::fs::CWD,
            path,
            rustix::fs::Access::EXEC_OK,
            rustix::fs::AtFlags::EACCESS,
        ) {
            Ok(()) => Ok(true),
            Err(error) => {
                let error = io::Error::from(error);
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
        }
    };
    let selected = if let Some(path) = std::env::var_os("CARGO_RABS_RUSTUP") {
        require(!path.is_empty(), "CARGO_RABS_RUSTUP must not be empty")?;
        let path = std::path::absolute(path)?;
        require(available(&path)?, "CARGO_RABS_RUSTUP is not executable")?;
        path
    } else {
        let search = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
        let mut selected = None;
        for directory in std::env::split_paths(&search) {
            let candidate = std::path::absolute(directory.join("rustup"))?;
            if available(&candidate)? {
                selected = Some(candidate);
                break;
            }
        }
        selected.ok_or_else(|| {
            invalid("Rustup is not installed; select CARGO_RABS_RUSTUP or toolchain_root")
        })?
    };
    let selected_metadata = fs::metadata(&selected)?;
    let own = fs::metadata(current)?;
    require(
        (selected_metadata.dev(), selected_metadata.ino()) != (own.dev(), own.ino()),
        "CARGO_RABS_RUSTUP resolves to this frontend",
    )?;
    Ok(selected)
}

struct RustupChild {
    child: Child,
    owned: bool,
}

impl RustupChild {
    fn waitable(&mut self) -> io::Result<bool> {
        use rustix::process::{Pid, WaitId, WaitIdOptions, waitid};
        match waitid(
            WaitId::Pid(Pid::from_child(&self.child)),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        ) {
            Ok(status) => Ok(status.is_some()),
            Err(rustix::io::Errno::INTR) => Ok(false),
            Err(error) => {
                if error == rustix::io::Errno::CHILD {
                    // Without a retained child status this numeric PGID is no
                    // longer ours to signal. Never retry cleanup through it.
                    self.owned = false;
                }
                Err(error.into())
            }
        }
    }

    fn finish(&mut self) -> io::Result<ExitStatus> {
        use rustix::process::{Pid, Signal, kill_process_group};
        require(self.owned, "Rustup discovery lost child ownership")?;
        let result = (|| {
            self.waitable()?;
            // NOWAIT keeps the leader's PID reserved even after it exits.
            // Kill remaining in-group writers before reaping that identity.
            let signal = kill_process_group(Pid::from_child(&self.child), Signal::KILL);
            if signal.is_err_and(|error| error != rustix::io::Errno::SRCH) {
                let _ = self.child.kill();
            }
            let until = Instant::now() + RUSTUP_REAP_BUDGET;
            loop {
                if self.waitable()? {
                    let status = self.child.wait()?;
                    return match signal {
                        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(status),
                        Err(error) => Err(error.into()),
                    };
                }
                if Instant::now() >= until {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "Rustup discovery cleanup could not be confirmed",
                    ));
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        })();
        // No numeric signaling after a reap, or after a failed bounded cleanup.
        // A cleanup failure is an explicit refusal, never a discovered SDK.
        self.owned = false;
        result
    }
}

impl Drop for RustupChild {
    fn drop(&mut self) {
        if self.owned {
            let _ = self.finish();
        }
    }
}

fn require_child_ownership() -> io::Result<()> {
    // An inherited ignored SIGCHLD auto-reaps the leader and removes the PID
    // reuse fence. No discovery process may be started under that policy.
    let mut status = String::new();
    File::open("/proc/self/status")?
        .take(64 * 1024)
        .read_to_string(&mut status)?;
    let ignored = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .ok_or_else(|| invalid("Rustup discovery cannot establish child ownership"))?;
    require(
        ignored & (1_u64 << (rustix::process::Signal::CHILD.as_raw() - 1)) == 0,
        "ignored SIGCHLD prevents Rustup discovery ownership",
    )
}

fn capture_rustup_toolchain(
    executable: &Path,
    selector: Option<&str>,
    cancelled: &mut impl FnMut() -> bool,
) -> io::Result<PathBuf> {
    use rustix::fs::{fcntl_getfl, fcntl_setfl};
    require_child_ownership()?;
    require(!cancelled(), "Rustup discovery caller disappeared")?;
    let mut command = Command::new(executable);
    command.arg("which");
    if let Some(selector) = selector {
        command.args(["--toolchain", selector]);
    }
    command
        .arg("rustc")
        .env("RUSTUP_AUTO_INSTALL", "0")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let started = Instant::now();
    let mut owner = RustupChild {
        child: command.spawn()?,
        owned: true,
    };
    let mut stdout = owner
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("Rustup discovery stdout is unavailable"))?;
    fcntl_setfl(&stdout, fcntl_getfl(&stdout)? | OFlags::NONBLOCK)?;
    let mut bytes = Vec::new();
    let mut eof = false;
    let outcome = (|| -> io::Result<()> {
        let mut buffer = [0_u8; 1024];
        loop {
            if cancelled() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Rustup discovery caller disappeared",
                ));
            }
            if started.elapsed() >= RUSTUP_DISCOVERY_BUDGET {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Rustup toolchain discovery timed out",
                ));
            }
            if !eof {
                let count = buffer.len().min(MAX_RUSTUP_PATH_BYTES + 1 - bytes.len());
                match stdout.read(&mut buffer[..count]) {
                    Ok(0) => eof = true,
                    Ok(count) => {
                        bytes.extend_from_slice(&buffer[..count]);
                        require(
                            bytes.len() <= MAX_RUSTUP_PATH_BYTES,
                            "Rustup toolchain path exceeds its output bound",
                        )?;
                        // Drain a bounded ready prefix without polling delay.
                        continue;
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
            if owner.waitable()? && eof {
                return Ok(());
            }
            std::thread::sleep(
                Duration::from_millis(2)
                    .min(RUSTUP_DISCOVERY_BUDGET.saturating_sub(started.elapsed())),
            );
        }
    })();
    drop(stdout);
    let status = owner.finish()?;
    outcome?;
    require(
        status.success(),
        "Rustup could not resolve an installed rustc; select an installed toolchain or toolchain_root",
    )?;
    let path =
        std::str::from_utf8(&bytes).map_err(|_| invalid("Rustup toolchain path must be UTF-8"))?;
    let path = path.strip_suffix('\n').unwrap_or(path);
    require(
        !path.chars().any(char::is_control),
        "Rustup must return exactly one toolchain path",
    )?;
    let compiler = plain_absolute(path)?;
    let bin = compiler
        .parent()
        .ok_or_else(|| invalid("Rustup compiler has no parent"))?;
    require(
        compiler.file_name() == Some(OsStr::new("rustc"))
            && bin.file_name() == Some(OsStr::new("bin")),
        "Rustup must select a physical toolchain bin/rustc",
    )?;
    Ok(bin
        .parent()
        .ok_or_else(|| invalid("Rustup toolchain root is unavailable"))?
        .to_owned())
}

/// A tiny independent owner keeps Rustup's process group bounded if the caller
/// receives SIGINT, SIGTERM or SIGKILL. Its direct-parent relation cannot be
/// recreated by PID reuse. Closing the private control pipe also cancels a
/// failed discovery while its frontend is still alive. No signal thread or
/// async runtime enters this command's dependency cone.
pub(crate) fn run_rustup_guard(arguments: &[OsString]) -> Option<io::Result<()>> {
    if arguments
        .first()
        .is_none_or(|argument| argument != RUSTUP_GUARD)
    {
        return None;
    }
    Some((|| {
        use rustix::fs::{fcntl_getfl, fcntl_setfl};
        require(
            matches!(arguments.len(), 3 | 4),
            "invalid Rustup discovery guard request",
        )?;
        let parent = arguments[1]
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid != 0)
            .ok_or_else(|| invalid("invalid Rustup discovery parent"))?;
        let executable = Path::new(&arguments[2]);
        require(
            executable.is_absolute(),
            "Rustup discovery executable must be absolute",
        )?;
        let selector = arguments
            .get(3)
            .map(|value| {
                value
                    .to_str()
                    .filter(|name| crate::cargo_cli::valid_toolchain_name(name))
                    .ok_or_else(|| invalid("invalid Rustup discovery selector"))
            })
            .transpose()?;
        let mut input = io::stdin();
        fcntl_setfl(&input, fcntl_getfl(&input)? | OFlags::NONBLOCK)?;
        let mut cancelled = || {
            if rustix::process::getppid().is_none_or(|pid| pid.as_raw_pid() as u32 != parent) {
                return true;
            }
            match input.read(&mut [0_u8; 1]) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    false
                }
                // No data is ever sent; EOF or any unexpected byte revokes the
                // private control capability, without consuming workload input.
                _ => true,
            }
        };
        let result = capture_rustup_toolchain(executable, selector, &mut cancelled)
            .map_err(|error| error.to_string());
        serde_json::to_writer(io::stdout().lock(), &result).map_err(io::Error::other)
    })())
}

struct RustupGuard {
    child: Child,
    control: Option<ChildStdin>,
    finished: bool,
}

impl RustupGuard {
    fn finish(&mut self) -> io::Result<ExitStatus> {
        self.control.take();
        // The guard observes revocation and drains its own retained group.
        // Never kill that owner before it can perform the child's cleanup.
        let until = Instant::now() + RUSTUP_REAP_BUDGET + Duration::from_millis(100);
        self.finished = true;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= until {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Rustup discovery guard cleanup could not be confirmed",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for RustupGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.finish();
        }
    }
}

fn discover_rustup_toolchain(selector: Option<&str>, current: &Path) -> io::Result<PathBuf> {
    use rustix::fs::{fcntl_getfl, fcntl_setfl};
    let executable = rustup_executable(current)?;
    require_child_ownership()?;
    let mut command = Command::new(current);
    command
        .arg(RUSTUP_GUARD)
        .arg(std::process::id().to_string())
        .arg(executable);
    if let Some(selector) = selector {
        command.arg(selector);
    }
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let started = Instant::now();
    let mut child = command.spawn()?;
    let control = child.stdin.take();
    let mut guard = RustupGuard {
        child,
        control,
        finished: false,
    };
    let mut stdout = guard
        .child
        .stdout
        .take()
        .ok_or_else(|| invalid("Rustup guard stdout is unavailable"))?;
    fcntl_setfl(&stdout, fcntl_getfl(&stdout)? | OFlags::NONBLOCK)?;
    let budget = RUSTUP_DISCOVERY_BUDGET + RUSTUP_REAP_BUDGET + Duration::from_millis(250);
    let mut bytes = Vec::new();
    let result = (|| {
        let mut buffer = [0_u8; 1024];
        loop {
            if started.elapsed() >= budget {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Rustup discovery guard exceeded its deadline",
                ));
            }
            let count = buffer.len().min(MAX_RUSTUP_REPLY_BYTES + 1 - bytes.len());
            match stdout.read(&mut buffer[..count]) {
                Ok(0) => return Ok(()),
                Ok(count) => {
                    bytes.extend_from_slice(&buffer[..count]);
                    require(
                        bytes.len() <= MAX_RUSTUP_REPLY_BYTES,
                        "Rustup guard reply exceeds its bound",
                    )?;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(
                        Duration::from_millis(2).min(budget.saturating_sub(started.elapsed())),
                    );
                }
                Err(error) => return Err(error),
            }
        }
    })();
    drop(stdout);
    let status = guard.finish()?;
    result?;
    require(status.success(), "Rustup discovery guard failed")?;
    let result: Result<PathBuf, String> = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Rustup discovery guard returned an invalid reply"))?;
    result.map_err(io::Error::other)
}

fn validate_profile(
    profile: &mut Map<String, Value>,
    options: &Options,
) -> io::Result<(PathBuf, Option<PathBuf>, CompilationCommand)> {
    let (version, physical) = match options.mode {
        Mode::Worker => return worker::validate_profile(profile, options),
        Mode::Local => (
            "canonical-compile-local-v1",
            vec![
                "version",
                "source_root",
                "toolchain_root",
                "toolchain",
                "state_root",
                "operation_root",
                "wrapper",
                "cargo_home_source",
                "service_socket",
                "target_cache",
            ],
        ),
        Mode::Remote => (
            "canonical-compile-remote-v1",
            vec![
                "version",
                "coordinator",
                "server_name",
                "coordinator_pin",
                "tls",
                "source_root",
                "toolchain_root",
                "toolchain",
                "staging_root",
                "output_root",
                "output_destination",
                "cargo_home_source",
                "settings",
                "artifact_reuse_root",
                "stdout_presentation",
            ],
        ),
    };
    require(
        profile.get("version").and_then(Value::as_str) == Some(version),
        "profile version does not match selected route",
    )?;
    require(
        profile.keys().all(|key| {
            physical.contains(&key.as_str())
                || (options.mode == Mode::Local && LOGICAL_FIELDS.contains(&key.as_str()))
        }),
        "unknown canonical profile field",
    )?;
    let service = options.mode == Mode::Remote
        || profile
            .get("service_socket")
            .is_some_and(|value| !value.is_null());
    let command = if options.mode == Mode::Local {
        logical(profile, options, service)?
    } else {
        let settings = profile
            .entry("settings")
            .or_insert_with(|| Value::Object(Map::new()));
        let settings = settings
            .as_object_mut()
            .ok_or_else(|| invalid("remote settings must be an object"))?;
        require(
            settings
                .keys()
                .all(|name| LOGICAL_FIELDS.contains(&name.as_str())),
            "unknown remote settings field",
        )?;
        logical(settings, options, true)?
    };
    let source = plain_absolute(string(profile, "source_root")?)?;
    open_directory(&source)?;
    let toolchain = profile
        .get("toolchain_root")
        .map(|_| plain_absolute(string(profile, "toolchain_root")?))
        .transpose()?;
    if let Some(toolchain) = &toolchain {
        open_directory(toolchain)?;
    }
    let mut roots = vec![source.clone()];
    roots.extend(toolchain.iter().cloned());
    if let Some(home) = profile
        .get("cargo_home_source")
        .filter(|value| !value.is_null())
    {
        let home = plain_absolute(
            home.as_str()
                .ok_or_else(|| invalid("cargo_home_source must be a path"))?,
        )?;
        open_directory(&home)?;
        roots.push(home);
        let settings = if options.mode == Mode::Local {
            &*profile
        } else {
            profile["settings"]
                .as_object()
                .ok_or_else(|| invalid("invalid settings"))?
        };
        require(
            settings.get("vendor").is_none_or(Value::is_null),
            "choose vendor or cargo_home_source, not both",
        )?;
    }
    let mut tools = vec!["cargo", "rustc"];
    if command == CompilationCommand::Clippy {
        tools.extend(["cargo-clippy", "clippy-driver"]);
    }
    if matches!(command, CompilationCommand::Test | CompilationCommand::Doc) {
        tools.push("rustdoc");
    }
    if let Some(toolchain) = &toolchain {
        for name in tools {
            executable(&toolchain.join("bin").join(name))?;
        }
    }
    let (operation_root, output_root) = if options.mode == Mode::Local {
        let state = plain_absolute(string(profile, "state_root")?)?;
        let operation = plain_absolute(string(profile, "operation_root")?)?;
        private_directory(&state)?;
        private_directory(&operation)?;
        roots.extend([state, operation.clone()]);
        let wrapper = plain_absolute(string(profile, "wrapper")?)?;
        executable(&wrapper)?;
        require(
            !roots
                .iter()
                .any(|root| toolchain.as_ref() != Some(root) && wrapper.starts_with(root)),
            "wrapper must be outside captured source and mutable operation roots",
        )?;
        if let Some(socket) = profile
            .get("service_socket")
            .filter(|value| !value.is_null())
        {
            let socket = plain_absolute(
                socket
                    .as_str()
                    .ok_or_else(|| invalid("service_socket must be an absolute path"))?,
            )?;
            require(
                !socket.starts_with(&source)
                    && toolchain
                        .as_ref()
                        .is_none_or(|root| !socket.starts_with(root))
                    && !socket.starts_with(&operation)
                    && profile
                        .get("cargo_home_source")
                        .and_then(Value::as_str)
                        .is_none_or(|home| !socket.starts_with(home)),
                "service socket must be outside captured inputs and operation root",
            )?;
        }
        if let Some(cache) = profile.get("target_cache").filter(|value| !value.is_null()) {
            let cache = cache
                .as_object()
                .ok_or_else(|| invalid("target_cache must be an object"))?;
            require(
                cache.keys().all(|key| {
                    matches!(key.as_str(), "runtime_epoch" | "max_bytes" | "max_families")
                }),
                "unknown target_cache field",
            )?;
            let epoch = string(cache, "runtime_epoch")?;
            require(
                !epoch.is_empty()
                    && epoch.len() <= 256
                    && epoch.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    }),
                "target_cache requires a bounded runtime_epoch",
            )?;
            for (field, limit) in [
                ("max_bytes", 8 * 1024 * 1024 * 1024_u64),
                ("max_families", 32),
            ] {
                if let Some(value) = cache.get(field) {
                    require(
                        value
                            .as_u64()
                            .is_some_and(|value| value > 0 && value <= limit),
                        "target_cache bound is invalid",
                    )?;
                }
            }
        }
        (operation, None)
    } else {
        let staging = plain_absolute(string(profile, "staging_root")?)?;
        private_directory(&staging)?;
        roots.push(staging.clone());
        require(
            profile.contains_key("output_root") != profile.contains_key("output_destination"),
            "remote profile requires exactly one output_root or output_destination",
        )?;
        let output_root = if profile.contains_key("output_root") {
            let root = plain_absolute(string(profile, "output_root")?)?;
            private_directory(&root)?;
            roots.push(root.clone());
            Some(root)
        } else {
            let destination = plain_absolute(string(profile, "output_destination")?)?;
            let parent = destination
                .parent()
                .ok_or_else(|| invalid("output destination has no parent"))?;
            private_directory(parent)?;
            roots.push(parent.to_path_buf());
            absent(&destination)?;
            None
        };
        let pin = string(profile, "coordinator_pin")?;
        require(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && pin.bytes().any(|byte| byte != b'0'),
            "coordinator_pin must be a nonzero lowercase SHA-256 pin",
        )?;
        let coordinator = string(profile, "coordinator")?;
        let server = string(profile, "server_name")?;
        require(
            !coordinator.is_empty()
                && coordinator.len() <= 1024
                && !coordinator.chars().any(char::is_control)
                && !server.is_empty()
                && server.len() <= 253
                && !server.chars().any(char::is_control),
            "coordinator and TLS server name must be bounded and explicit",
        )?;
        let tls = profile
            .get("tls")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("remote profile requires TLS credentials"))?;
        require(
            tls.len() == 3
                && ["ca", "certificate", "private_key"]
                    .iter()
                    .all(|name| tls.contains_key(*name)),
            "TLS requires exactly ca, certificate and private_key",
        )?;
        for name in ["ca", "certificate", "private_key"] {
            let credential = plain_absolute(string(tls, name)?)?;
            open_regular(&credential)?;
            if name == "private_key" {
                require(
                    !roots
                        .iter()
                        .take(roots.len() - 2)
                        .any(|root| credential.starts_with(root)),
                    "authentication key must be outside captured inputs",
                )?;
            }
        }
        if let Some(presentation) = profile.get("stdout_presentation") {
            require(
                matches!(
                    presentation.as_str(),
                    Some("raw" | "cargo-json-subscriber-v1" | "cargo-json-source-paths-v1")
                ),
                "unsupported stdout_presentation",
            )?;
        }
        if let Some(reuse) = profile
            .get("artifact_reuse_root")
            .filter(|value| !value.is_null())
        {
            let reuse = plain_absolute(
                reuse
                    .as_str()
                    .ok_or_else(|| invalid("artifact reuse root must be a path"))?,
            )?;
            private_directory(&reuse)?;
            require(
                !roots
                    .iter()
                    .take(roots.len() - 1)
                    .any(|root| reuse.starts_with(root) || root.starts_with(&reuse)),
                "artifact reuse must be outside source, compiler and staging roots",
            )?;
            require(
                !Path::new(string(tls, "private_key")?).starts_with(&reuse),
                "authentication key must be outside artifact reuse hints",
            )?;
            if let Some(output_root) = &output_root {
                require(
                    !output_root.starts_with(&reuse),
                    "artifact reuse cannot contain new output destinations",
                )?;
            }
            if let Some(destination) = profile.get("output_destination").and_then(Value::as_str) {
                let destination = Path::new(destination);
                require(
                    !reuse.starts_with(destination) && !destination.starts_with(&reuse),
                    "artifact reuse cannot overlap new output destination",
                )?;
            }
        }
        (staging, output_root)
    };
    roots_disjoint(&roots)?;
    Ok((operation_root, output_root, command))
}

fn validate(
    profile: &mut Map<String, Value>,
    options: &Options,
    current: &Path,
) -> io::Result<(PathBuf, Option<PathBuf>, CompilationCommand)> {
    require(
        profile.contains_key("toolchain") != profile.contains_key("toolchain_root"),
        "profile requires exactly one of toolchain_root or toolchain",
    )?;
    if let Some(selection) = profile.get("toolchain") {
        require(
            selection == "rustup",
            "toolchain must be rustup or use an explicit toolchain_root",
        )?;
        // All known source, output, credential and command intent is checked
        // before launching discovery. Only SDK-specific checks need its answer.
        validate_profile(profile, options)?;
        let root = discover_rustup_toolchain(options.toolchain.as_deref(), current)?;
        profile.remove("toolchain");
        profile.insert("toolchain_root".into(), serde_json::to_value(root)?);
    } else {
        require(
            options.toolchain.is_none(),
            "+toolchain requires a toolchain: rustup profile",
        )?;
    }
    validate_profile(profile, options)
}

fn driver(options: &Options, current: &Path) -> io::Result<PathBuf> {
    let selected = options
        .daemon
        .clone()
        .or_else(|| std::env::var_os("CARGO_RABS_DAEMON"));
    let path = if let Some(selected) = selected {
        require(
            !selected.is_empty(),
            "native driver override must not be empty",
        )?;
        PathBuf::from(selected)
    } else {
        current
            .parent()
            .ok_or_else(|| invalid("frontend directory is unavailable"))?
            .join("rabsd")
    };
    let path = fs::canonicalize(path).map_err(|_| {
        invalid("rabsd is unavailable; install a matching sibling or select --rabsd")
    })?;
    executable(&path)?;
    let selected = fs::metadata(&path)?;
    let own = fs::metadata(current)?;
    require(
        (selected.dev(), selected.ino()) != (own.dev(), own.ino()),
        "rabsd resolves to this frontend",
    )?;
    Ok(path)
}

fn same_directory(path: &Path, original: &File) -> io::Result<()> {
    let current = private_directory(path)?.metadata()?;
    let previous = original.metadata()?;
    require(
        (current.dev(), current.ino(), current.uid(), current.mode())
            == (
                previous.dev(),
                previous.ino(),
                previous.uid(),
                previous.mode(),
            ),
        "operation parent changed during profile retention",
    )
}

pub(crate) fn run(options: &Options, current: &Path) -> io::Result<()> {
    for marker in [
        "CARGO_RABS_CANONICAL_ACTIVE",
        "CARGO_RABS_REMOTE_ACTIVE",
        "RCH_RABS_WORKER_ACTIVE",
    ] {
        require(
            std::env::var_os(marker).as_deref() != Some(OsStr::new("1")),
            "nested canonical or remote dispatch is unsupported",
        )?;
    }
    for key in [
        "CARGO_RABS_ROOT_BUDGET_DIR",
        "CARGO_RABS_ROOT_CAPACITY",
        "CARGO_RABS_ROOT_CGROUP",
    ] {
        require(
            std::env::var_os(key).is_none(),
            "local root admission cannot combine with canonical operations",
        )?;
    }
    let daemon = driver(options, current)?;
    let mut profile = read_profile(Path::new(&options.profile))?;
    let (root, outputs, command) = validate(&mut profile, options, current)?;
    if options.mode == Mode::Worker {
        return worker::run(options, &daemon, &profile, &root);
    }
    let parent = private_directory(&root)?;
    let operation = tempfile::Builder::new()
        .prefix(&format!("cargo-{}-", command.as_str()))
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(&root)?
        .keep();
    same_directory(&root, &parent)?;
    let operation_directory = private_directory(&operation)?;
    if options.mode == Mode::Remote {
        let capture = operation.join("capture");
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&capture)?;
        profile.insert("staging_root".into(), serde_json::to_value(&capture)?);
        if let Some(outputs) = outputs {
            let destination = outputs.join(
                operation
                    .file_name()
                    .ok_or_else(|| invalid("operation has no name"))?,
            );
            absent(&destination)?;
            profile.remove("output_root");
            profile.insert(
                "output_destination".into(),
                serde_json::to_value(destination)?,
            );
        }
    }
    let bytes = serde_json::to_vec(&profile)?;
    require(
        bytes.len() as u64 <= MAX_PROFILE,
        "retained profile exceeds its native byte bound",
    )?;
    let retained = operation.join("profile.json");
    let mut file = File::from(rustix::fs::openat(
        &operation_directory,
        "profile.json",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FileMode::RUSR | FileMode::WUSR,
    )?);
    file.write_all(&bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    operation_directory.sync_all()?;
    parent.sync_all()?;
    same_directory(&root, &parent)?;
    // The native driver independently validates retained intent before any
    // source capture, transport admission, compilation or result publication.
    let _ = writeln!(
        io::stderr().lock(),
        "rabs-cargo: retained profile {}",
        retained.display()
    );
    let error = Command::new(daemon)
        .arg(if options.mode == Mode::Local {
            "--canonical-compile-local"
        } else {
            "--canonical-compile-remote"
        })
        .arg(retained)
        .env("CARGO_RABS_CANONICAL_ACTIVE", "1")
        .exec();
    Err(error)
}
