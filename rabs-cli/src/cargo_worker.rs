//! Direct-worker Cargo intent and one-way handoff to the existing native driver.
//!
//! The frontend owns no worker request number, scheduler or execution retry.
//! Its random operation name identifies retained local intent; `allocate` is
//! resolved only by the direct driver or durable daemon. The fixed recovery
//! records are the same contracts consumed by `rabs-recover`.

use super::{
    MAX_PROFILE, command_environment, executable, fingerprint, invalid, open_directory,
    plain_absolute, private_directory, relative_member, require, roots_disjoint, same_directory,
    string,
};
use crate::cargo_cli::{Input, Options};
use rabs_sandbox::cargo_artifacts::nextest::NextestTree;
use rabs_sandbox::cargo_check::{CompilationCommand, CompilationSelection, CompilationStdin};
use rabs_sandbox::process_context::CommandContext;
use rustix::fs::{Mode as FileMode, OFlags};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug)]
struct Worker {
    address: String,
    name: String,
    pin: String,
    endpoint: (IpAddr, u16),
}

impl Worker {
    fn read(fields: &Map<String, Value>) -> io::Result<Self> {
        let address = string(fields, "listen")?;
        let name = string(fields, "worker")?;
        let pin = string(fields, "worker_spki_sha256")?;
        require(
            address.len() <= 128 && !address.contains('%'),
            "worker listener must be a bounded literal IP and nonzero port",
        )?;
        let endpoint = address
            .parse::<SocketAddr>()
            .map_err(|_| invalid("worker listener must be a literal IP and nonzero port"))?;
        require(
            endpoint.port() != 0,
            "worker listener requires a nonzero port",
        )?;
        require(
            name.len() <= 128
                && name
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "worker identity must be a bounded ASCII identifier",
        )?;
        require(
            pin.len() == 64
                && pin
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                && pin.bytes().any(|byte| byte != b'0'),
            "worker pin must be a nonzero lowercase SHA-256 value",
        )?;
        let ip = match endpoint.ip() {
            IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
            ip => ip,
        };
        Ok(Self {
            address: address.to_owned(),
            name: name.to_owned(),
            pin: pin.to_owned(),
            endpoint: (ip, endpoint.port()),
        })
    }

    fn value(&self) -> Value {
        json!({"address":self.address, "worker":self.name, "worker_spki_sha256":self.pin})
    }
}

enum Placement {
    Single(Worker),
    Pool(Vec<Worker>),
}

fn placement(profile: &Map<String, Value>) -> io::Result<Placement> {
    let Some(value) = profile.get("workers") else {
        return Worker::read(profile).map(Placement::Single);
    };
    require(
        profile.contains_key("daemon_socket")
            && ["listen", "worker", "worker_spki_sha256"]
                .iter()
                .all(|field| !profile.contains_key(*field)),
        "worker pools require daemon_socket and no singular worker settings",
    )?;
    let values = value
        .as_array()
        .filter(|values| (1..=32).contains(&values.len()))
        .ok_or_else(|| invalid("worker pools require 1..=32 explicit workers"))?;
    let mut workers = Vec::<Worker>::new();
    let mut names = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for value in values {
        let fields = value
            .as_object()
            .filter(|fields| {
                fields.len() == 3
                    && ["listen", "worker", "worker_spki_sha256"]
                        .iter()
                        .all(|field| fields.contains_key(*field))
            })
            .ok_or_else(|| invalid("worker pool entries require only listen, worker and pin"))?;
        let worker = Worker::read(fields)?;
        let (ip, port) = worker.endpoint;
        require(
            names.insert(worker.name.clone())
                && pins.insert(worker.pin.clone())
                && !workers.iter().any(|other| {
                    port == other.endpoint.1
                        && (ip == other.endpoint.0
                            || ip.is_unspecified()
                            || other.endpoint.0.is_unspecified())
                }),
            "worker pool repeats a listener, worker identity or pin",
        )?;
        workers.push(worker);
    }
    Ok(Placement::Pool(workers))
}

struct DaemonSocket {
    path: PathBuf,
    parent: File,
    identity: [u64; 9],
}

impl DaemonSocket {
    fn open(value: &str) -> io::Result<Self> {
        let path = plain_absolute(value)?;
        require(
            path.as_os_str().as_encoded_bytes().len() < 108,
            "daemon socket exceeds the Linux socket path bound",
        )?;
        let parent = open_directory(
            path.parent()
                .ok_or_else(|| invalid("daemon socket has no parent"))?,
        )?;
        let metadata = parent.metadata()?;
        require(
            metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o022 == 0,
            "daemon socket parent must be owned and not writable by other users",
        )?;
        let metadata = fs::symlink_metadata(&path)?;
        require(
            metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o077 == 0,
            "daemon mode requires an existing private owned socket",
        )?;
        Ok(Self {
            path,
            parent,
            identity: fingerprint(&metadata),
        })
    }

    fn verify(&self) -> io::Result<()> {
        let current = Self::open(path_text(&self.path)?)?;
        let before = self.parent.metadata()?;
        let after = current.parent.metadata()?;
        require(
            self.identity == current.identity
                && (before.dev(), before.ino(), before.uid(), before.mode())
                    == (after.dev(), after.ino(), after.uid(), after.mode()),
            "daemon endpoint changed before native handoff",
        )
    }
}

fn selected(options: &Options) -> io::Result<(CompilationCommand, &CompilationSelection)> {
    let (command, selection) = options
        .selected
        .as_ref()
        .map(|(command, selection)| (*command, selection))
        .ok_or_else(|| invalid("worker profiles require an explicit Cargo command"))?;
    Ok((command, selection))
}

fn manifest(profile: &Map<String, Value>) -> io::Result<&str> {
    let manifest = profile
        .get("manifest")
        .map_or(Some("Cargo.toml"), Value::as_str)
        .ok_or_else(|| invalid("manifest must name a relative Cargo.toml"))?;
    require(
        relative_member(manifest)
            && Path::new(manifest).file_name() == Some(std::ffi::OsStr::new("Cargo.toml")),
        "manifest must name a relative Cargo.toml",
    )?;
    Ok(manifest)
}

fn context(
    profile: &Map<String, Value>,
    command: CompilationCommand,
) -> io::Result<CommandContext> {
    let mut controls = vec![(
        "CARGO_INCREMENTAL".into(),
        if profile.get("incremental") == Some(&Value::Bool(true)) {
            "1".into()
        } else {
            "0".into()
        },
    )];
    if matches!(
        command,
        CompilationCommand::Clippy | CompilationCommand::Nextest
    ) {
        controls.extend([
            ("CARGO".into(), "/__rabs/toolchain/bin/cargo".into()),
            ("RUSTC".into(), "/__rabs/toolchain/bin/rustc".into()),
        ]);
    } else if matches!(command, CompilationCommand::Doc | CompilationCommand::Test) {
        controls.extend([
            ("RUSTDOC".into(), "/__rabs/toolchain/bin/rustdoc".into()),
            ("RUSTC".into(), "/__rabs/toolchain/bin/rustc".into()),
        ]);
    }
    let manifest = Path::new("/__rabs/workspace").join(manifest(profile)?);
    let cwd = manifest
        .parent()
        .ok_or_else(|| invalid("manifest has no canonical directory"))?;
    command_environment(profile.get("env"), controls, path_text(cwd)?)
}

pub(super) fn validate_profile(
    profile: &Map<String, Value>,
    options: &Options,
) -> io::Result<(PathBuf, Option<PathBuf>, CompilationCommand)> {
    const FIELDS: &[&str] = &[
        "version",
        "source_root",
        "operation_root",
        "toolchain_root",
        "toolchain",
        "listen",
        "worker",
        "worker_spki_sha256",
        "workers",
        "daemon_socket",
        "manifest",
        "vendor",
        "cargo_home_source",
        "source_selection",
        "jobserver_grant",
        "env",
        "incremental",
        "live_stderr",
    ];
    require(
        profile.get("version").and_then(Value::as_str) == Some("canonical-cargo-v1")
            && profile.keys().all(|field| FIELDS.contains(&field.as_str())),
        "worker mode requires only canonical-cargo-v1 profile fields",
    )?;
    let (command, selection) = selected(options)?;
    selection.cargo_arguments(command)?;
    selection.runtime_arguments(command)?;
    match options.input.as_ref() {
        None | Some(Input::Policy(CompilationStdin::Closed)) => {}
        Some(Input::Policy(CompilationStdin::Inherit)) => {
            return Err(invalid(
                "direct workers do not forward inherited stdin; select --stdin-file or --stdin closed",
            ));
        }
        Some(Input::File(path)) => {
            require(
                relative_member(path)
                    && matches!(
                        command,
                        CompilationCommand::Run
                            | CompilationCommand::Test
                            | CompilationCommand::Nextest
                            | CompilationCommand::Bench
                    )
                    && !selection.no_run,
                "captured stdin requires an ordinary source-relative file and run, test, nextest or bench execution",
            )?;
        }
    }
    require(
        selection.target.iter().all(|target| {
            matches!(
                target.as_str(),
                "x86_64-unknown-linux-gnu"
                    | "aarch64-unknown-linux-gnu"
                    | "x86_64-unknown-linux-musl"
                    | "aarch64-unknown-linux-musl"
            )
        }),
        "worker targets must be supported explicit Linux triples",
    )?;
    require(
        command == CompilationCommand::Nextest
            || !selection.no_run
            || (selection.test_filter.is_none()
                && !selection.doc
                && selection.test_args.is_empty()),
        "filters, doctests and harness arguments require test or bench execution",
    )?;
    for field in ["incremental", "live_stderr"] {
        if let Some(value) = profile.get(field) {
            require(
                value.is_boolean(),
                "worker execution controls must be booleans",
            )?;
        }
    }
    require(
        command != CompilationCommand::Nextest
            || profile.get("incremental") != Some(&Value::Bool(true)),
        "worker nextest delivers its complete target tree and does not support private incremental projection",
    )?;
    if let Some(grant) = profile.get("jobserver_grant") {
        require(
            grant
                .as_u64()
                .is_some_and(|grant| (1..=4096).contains(&grant)),
            "jobserver_grant must be an integer from 1 to 4096",
        )?;
    }
    if command == CompilationCommand::Nextest {
        let build_jobs = profile
            .get("jobserver_grant")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .try_into()
            .map_err(|_| invalid("nextest build-job bound exceeds u32"))?;
        rabs_sandbox::cargo_artifacts::nextest::execution_slots(selection, build_jobs)?;
    } else {
        // Validate explicit harness controls before creating an operation. The
        // request still omits an absent grant, preserving the worker default.
        let build_jobs = u32::try_from(
            profile
                .get("jobserver_grant")
                .and_then(Value::as_u64)
                .unwrap_or(1),
        )
        .map_err(|_| invalid("compilation job bound exceeds u32"))?;
        rabs_sandbox::cargo_artifacts::test_threads::selection_execution_slots(
            command, selection, build_jobs,
        )?;
    }
    placement(profile)?;
    manifest(profile)?;
    if let Some(vendor) = profile.get("vendor") {
        require(
            vendor.as_str().is_some_and(relative_member)
                && !profile.contains_key("cargo_home_source"),
            "vendor must be a source member without cargo_home_source",
        )?;
    }
    if let Some(source) = profile.get("source_selection") {
        require(
            source == "cargo-unit-graph-v1",
            "source_selection must be cargo-unit-graph-v1",
        )?;
    }
    context(profile, command)?;
    let source = plain_absolute(string(profile, "source_root")?)?;
    let source_directory = open_directory(&source)?;
    if let Some(Input::File(path)) = &options.input {
        let input = File::from(rustix::fs::openat2(
            &source_directory,
            path.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC,
            FileMode::empty(),
            rustix::fs::ResolveFlags::BENEATH
                | rustix::fs::ResolveFlags::NO_SYMLINKS
                | rustix::fs::ResolveFlags::NO_MAGICLINKS
                | rustix::fs::ResolveFlags::NO_XDEV,
        )?);
        let metadata = input.metadata()?;
        require(
            metadata.is_file()
                && metadata.len() <= rabs_sandbox::captured_stdin::MAX_CAPTURED_STDIN_BYTES,
            "captured worker stdin must be an ordinary file of at most 16 MiB",
        )?;
    }
    let mut roots = vec![source];
    if let Some(toolchain) = profile.get("toolchain_root") {
        let root = plain_absolute(
            toolchain
                .as_str()
                .ok_or_else(|| invalid("toolchain_root must be a path"))?,
        )?;
        open_directory(&root)?;
        let mut tools = vec!["cargo", "rustc"];
        if command == CompilationCommand::Clippy {
            tools.extend(["cargo-clippy", "clippy-driver"]);
        }
        if command == CompilationCommand::Nextest {
            tools.push("cargo-nextest");
        }
        if matches!(command, CompilationCommand::Doc | CompilationCommand::Test) {
            tools.push("rustdoc");
        }
        for tool in tools {
            executable(&root.join("bin").join(tool))?;
        }
        roots.push(root);
    }
    if let Some(home) = profile.get("cargo_home_source") {
        let root = plain_absolute(
            home.as_str()
                .ok_or_else(|| invalid("cargo_home_source must be a path"))?,
        )?;
        open_directory(&root)?;
        roots.push(root);
    }
    if let Some(socket) = profile.get("daemon_socket") {
        let endpoint = DaemonSocket::open(
            socket
                .as_str()
                .ok_or_else(|| invalid("daemon_socket must be a path"))?,
        )?;
        require(
            roots.iter().all(|root| !endpoint.path.starts_with(root)),
            "daemon socket must be outside captured inputs",
        )?;
    }
    let operation = plain_absolute(string(profile, "operation_root")?)?;
    private_directory(&operation)?;
    roots.push(operation.clone());
    roots_disjoint(&roots)?;
    Ok((operation, None, command))
}

fn path_text(path: &Path) -> io::Result<&str> {
    path.to_str()
        .filter(|value| !value.is_empty() && value.len() <= 4096)
        .ok_or_else(|| invalid("worker paths must be bounded UTF-8"))
}

fn specification(profile: &Map<String, Value>, options: &Options) -> io::Result<Value> {
    let (command, selection) = selected(options)?;
    let nextest = (command == CompilationCommand::Nextest)
        .then(|| {
            NextestTree::new(
                manifest(profile)?.to_owned(),
                selection.clone(),
                profile
                    .get("jobserver_grant")
                    .and_then(Value::as_u64)
                    .unwrap_or(1)
                    .try_into()
                    .map_err(|_| invalid("nextest build-job bound exceeds u32"))?,
            )
        })
        .transpose()?;
    let args = if let Some(contract) = &nextest {
        contract.arguments()?
    } else {
        let mut args = selection.cargo_arguments(command)?;
        args.extend([
            "--locked".into(),
            "--offline".into(),
            "--message-format=json".into(),
            "--manifest-path".into(),
            format!("/__rabs/workspace/{}", manifest(profile)?),
            "--target-dir".into(),
            "/__rabs/out/cargo".into(),
        ]);
        args.extend(selection.runtime_arguments(command)?);
        args
    };
    let context = context(profile, command)?;
    let environment: Map<String, Value> = context
        .environment()
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    let incremental = profile.get("incremental") == Some(&Value::Bool(true));
    let execution = matches!(
        command,
        CompilationCommand::Test | CompilationCommand::Run | CompilationCommand::Bench
    ) && !selection.no_run;
    let mut contract = String::from("cargo-");
    if incremental {
        contract.push_str("private-incremental-");
    }
    if execution {
        contract.push_str(command.as_str());
        contract.push('-');
    }
    contract.push_str("json-v1");
    let mut source = json!({"manifest":manifest(profile)?});
    for (profile_field, request_field) in [
        ("vendor", "vendor"),
        ("cargo_home_source", "cargo_home_source"),
        ("source_selection", "selection"),
    ] {
        if let Some(value) = profile.get(profile_field) {
            source[request_field] = value.clone();
        }
    }
    let mut spec = json!({
        "kind":"canonical-exec", "request_id":"allocate",
        "program":if command == CompilationCommand::Clippy {
            "/__rabs/toolchain/bin/cargo-clippy"
        } else if command == CompilationCommand::Nextest {
            rabs_sandbox::cargo_artifacts::nextest::PROGRAM
        } else {
            "/__rabs/toolchain/bin/cargo"
        },
        "args":args,
        "command_context":{"version":"env-cwd-v1", "cwd":context.cwd(), "env":environment},
        "toolchain_source":string(profile, "toolchain_root")?,
        "cargo_source":source,
        "artifacts":{"unit":"cargo", "tree":"tree-files-v1", "files":[], "cargo":contract},
    });
    if let Some(contract) = nextest {
        spec["jobserver_grant"] = json!(contract.build_jobs);
        spec["artifacts"]["cargo"] = serde_json::to_value(contract)?;
    }
    if let Some(grant) = profile.get("jobserver_grant") {
        spec["jobserver_grant"] = grant.clone();
    }
    if let Some(Input::File(path)) = &options.input {
        spec["captured_stdin"] = json!({
            "version":rabs_sandbox::captured_stdin::CAPTURED_STDIN_VERSION,
            "path":path,
        });
    }
    Ok(spec)
}

fn operation_id() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    use std::fmt::Write as _;
    let mut id = String::with_capacity(32);
    for byte in bytes {
        write!(id, "{byte:02x}").map_err(|_| invalid("operation identity unavailable"))?;
    }
    Ok(id)
}

fn encoded(value: &Value) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    require(
        bytes.len() as u64 <= MAX_PROFILE,
        "worker retained intent exceeds its native byte bound",
    )?;
    Ok(bytes)
}

fn write_intent(directory: &File, name: &str, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::from(rustix::fs::openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        FileMode::RUSR | FileMode::WUSR,
    )?);
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()
}

pub(super) fn run(
    options: &Options,
    daemon: &Path,
    profile: &Map<String, Value>,
    root: &Path,
) -> io::Result<()> {
    let parent = private_directory(root)?;
    let endpoint = profile
        .get("daemon_socket")
        .map(|_| DaemonSocket::open(string(profile, "daemon_socket")?))
        .transpose()?;
    let placement = placement(profile)?;
    let spec = encoded(&specification(profile, options)?)?;
    let id = operation_id()?;
    let name = format!("cargo-{id}");
    let operation = root.join(&name);
    let bundle = path_text(&operation.join("bundle"))?.to_owned();
    let delivery = path_text(&operation.join("delivery"))?.to_owned();
    let output = path_text(&operation.join("outputs"))?.to_owned();
    let driver = path_text(daemon)?.to_owned();
    let pool_path = path_text(&operation.join("pool.json"))?.to_owned();
    let (placement_args, pool) = match placement {
        Placement::Single(worker) => (
            vec![
                worker.address,
                worker.name,
                worker.pin,
                bundle,
                delivery,
                output,
            ],
            None,
        ),
        Placement::Pool(workers) => (
            vec![
                "--worker-pool".into(),
                pool_path.clone(),
                bundle,
                delivery,
                output,
            ],
            Some(Value::Array(workers.iter().map(Worker::value).collect())),
        ),
    };
    let live_stderr = profile.get("live_stderr") == Some(&Value::Bool(true));
    let mut prefix = if endpoint.is_some() {
        vec![driver.clone(), "--job-build".into()]
    } else {
        vec![
            driver.clone(),
            "--worker-build-tls".into(),
            "--replay-diagnostics".into(),
        ]
    };
    if live_stderr {
        prefix.push("--live-stderr".into());
    }
    let mut record = json!({
        "version":"canonical-cargo-v1", "request_id":"allocate",
        "operation_directory":operation, "automatic_retry":false, "publication_authorized":false,
    });
    if let Some(endpoint) = &endpoint {
        let mut submit = vec![driver.clone()];
        if pool.is_some() {
            submit.extend(["--job-submit-pool".into(), id.clone(), pool_path]);
            submit.extend_from_slice(&placement_args[2..]);
        } else {
            submit.extend(["--job-submit-allocated".into(), id.clone()]);
            submit.extend(placement_args.clone());
        }
        let mut wait = vec![driver.clone(), "--job-wait".into()];
        if live_stderr {
            wait.push("--live-stderr".into());
        }
        wait.push(id.clone());
        record["job_id"] = id.clone().into();
        record["daemon_socket"] = serde_json::to_value(&endpoint.path)?;
        record["job_submit_argv"] = serde_json::to_value(submit)?;
        record["job_status_argv"] = json!([driver, "--job-status", id]);
        record["job_wait_argv"] = serde_json::to_value(wait)?;
        record["job_cancel_argv"] = json!([driver, "--job-cancel", id]);
        if let Some(pool) = &pool {
            record["worker_pool"] = pool.clone();
        }
        if let Some(live) = profile.get("live_stderr") {
            record["live_stderr"] = live.clone();
        }
    } else {
        let mut saved = prefix.clone();
        saved.extend(placement_args.clone());
        record["prepared_build_argv"] = serde_json::to_value(saved)?;
    }
    let record = encoded(&record)?;
    let pool = pool.as_ref().map(encoded).transpose()?;
    let mut native = prefix.split_off(1);
    native.extend([
        "--prepare-from".into(),
        string(profile, "source_root")?.to_owned(),
        path_text(&operation.join("spec.json"))?.to_owned(),
    ]);
    if endpoint.is_some() {
        native.push(id);
    }
    native.extend(placement_args);
    // All caller intent is validated and bounded before creating retained state.
    // Every later failure preserves it; there is no cleanup or execution retry.
    same_directory(root, &parent)?;
    rustix::fs::mkdirat(
        &parent,
        name.as_str(),
        FileMode::RUSR | FileMode::WUSR | FileMode::XUSR,
    )?;
    let directory = private_directory(&operation)?;
    same_directory(root, &parent)?;
    if let Some(pool) = &pool {
        write_intent(&directory, "pool.json", pool)?;
    }
    write_intent(&directory, "spec.json", &spec)?;
    write_intent(&directory, "operation.json", &record)?;
    directory.sync_all()?;
    parent.sync_all()?;
    same_directory(root, &parent)?;
    same_directory(&operation, &directory)?;
    if let Some(endpoint) = &endpoint {
        endpoint.verify()?;
    }
    let _ = writeln!(
        io::stderr().lock(),
        "rabs-cargo: retained worker operation {}",
        operation.display()
    );
    let toolchain = Path::new(string(profile, "toolchain_root")?);
    let mut native = {
        let mut command = Command::new(daemon);
        command
            .args(native)
            .env("CARGO_RABS_CANONICAL_ACTIVE", "1")
            .env("CARGO", toolchain.join("bin/cargo"))
            .env("RUSTC", toolchain.join("bin/rustc"));
        command
    };
    if let Some(endpoint) = endpoint {
        native.env("RABS_SOCKET_PATH", endpoint.path);
    }
    Err(native.exec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cargo_cli::{Invocation, Mode};
    use std::ffi::OsString;
    use std::os::unix::fs::symlink;

    const PIN: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SECOND_PIN: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn options(arguments: &[&str]) -> Box<Options> {
        let mut args: Vec<_> = ["--worker", "/private/profile.json", "--"]
            .into_iter()
            .map(OsString::from)
            .collect();
        args.extend(arguments.iter().map(|argument| OsString::from(*argument)));
        let Invocation::Run(options) = crate::cargo_cli::parse(&args).unwrap() else {
            panic!("worker command must parse as a run");
        };
        assert_eq!(options.mode, Mode::Worker);
        options
    }

    fn profile() -> Map<String, Value> {
        json!({
            "version":"canonical-cargo-v1", "source_root":"/private/source",
            "toolchain_root":"/private/sdk", "operation_root":"/private/operations",
            "listen":"127.0.0.1:7443", "worker":"worker-one", "worker_spki_sha256":PIN,
            "manifest":"nested/Cargo.toml", "env":{"BUILD_VALUE":"literal $value; 'quoted' α"},
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn set(profile: &mut Map<String, Value>, name: &str, value: Value) {
        profile.insert(name.to_owned(), value);
    }

    // These are real filesystem/profile tests, not compiler or TLS evidence.
    // Executable placeholders establish only the frontend's ordinary-file gate.
    fn filesystem_profile() -> (PathBuf, Map<String, Value>) {
        let root = tempfile::Builder::new()
            .prefix("rabs-worker-profile-")
            .tempdir()
            .unwrap()
            .keep();
        let mut profile = profile();
        for (field, directory) in [
            ("source_root", "source"),
            ("toolchain_root", "sdk"),
            ("operation_root", "operations"),
        ] {
            let path = root.join(directory);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            set(&mut profile, field, serde_json::to_value(path).unwrap());
        }
        let bin = root.join("sdk/bin");
        fs::create_dir(&bin).unwrap();
        for name in [
            "cargo",
            "rustc",
            "rustdoc",
            "cargo-clippy",
            "clippy-driver",
            "cargo-nextest",
        ] {
            let path = bin.join(name);
            fs::write(&path, b"frontend fixture; never executed").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        (root, profile)
    }

    fn worker_value(address: &str, name: &str, pin: &str) -> Value {
        json!({"listen":address, "worker":name, "worker_spki_sha256":pin})
    }

    #[test]
    fn worker_command_is_explicit_and_mixed_frontend_modes_are_refused() {
        for args in [
            vec!["--worker", "/profile"],
            vec!["--worker", "/profile", "+nightly"],
            vec!["--worker", "/profile", "--local", "/other", "build"],
            vec!["--remote", "/profile", "--worker", "/other", "build"],
        ] {
            let args: Vec<_> = args.into_iter().map(OsString::from).collect();
            assert!(crate::cargo_cli::parse(&args).is_err());
        }
        for args in [
            vec!["--worker", "/profile"],
            vec!["build", "--worker=/profile"],
        ] {
            let args: Vec<_> = args.into_iter().map(OsString::from).collect();
            assert!(crate::cargo_rch::reject_frontend_controls(&args).is_err());
        }
        let literal: Vec<_> = ["test", "--", "--worker=/literal"]
            .into_iter()
            .map(OsString::from)
            .collect();
        crate::cargo_rch::reject_frontend_controls(&literal).unwrap();
    }

    #[test]
    fn worker_spec_binds_selection_sources_environment_and_native_allocation() {
        let mut profile = profile();
        set(&mut profile, "jobserver_grant", json!(3));
        set(
            &mut profile,
            "source_selection",
            json!("cargo-unit-graph-v1"),
        );
        set(
            &mut profile,
            "cargo_home_source",
            json!("/private/cargo-cache"),
        );
        let options = options(&[
            "build",
            "--workspace",
            "-F",
            "feature-a,feature-b",
            "--bin",
            "app",
        ]);
        let spec = specification(&profile, &options).unwrap();
        assert_eq!(spec["kind"], "canonical-exec");
        assert_eq!(spec["request_id"], "allocate");
        assert_eq!(spec["program"], "/__rabs/toolchain/bin/cargo");
        assert_eq!(
            spec["args"],
            json!([
                "build",
                "--workspace",
                "--features",
                "feature-a,feature-b",
                "--bin",
                "app",
                "--locked",
                "--offline",
                "--message-format=json",
                "--manifest-path",
                "/__rabs/workspace/nested/Cargo.toml",
                "--target-dir",
                "/__rabs/out/cargo",
            ])
        );
        assert_eq!(spec["command_context"]["cwd"], "/__rabs/workspace/nested");
        assert_eq!(
            spec["command_context"]["env"],
            json!({
                "BUILD_VALUE":"literal $value; 'quoted' α", "CARGO_INCREMENTAL":"0",
            })
        );
        assert_eq!(spec["toolchain_source"], "/private/sdk");
        assert_eq!(
            spec["cargo_source"],
            json!({
                "manifest":"nested/Cargo.toml", "selection":"cargo-unit-graph-v1",
                "cargo_home_source":"/private/cargo-cache",
            })
        );
        assert_eq!(
            spec["artifacts"],
            json!({
                "unit":"cargo", "tree":"tree-files-v1", "files":[], "cargo":"cargo-json-v1",
            })
        );
        assert_eq!(spec["jobserver_grant"], 3);
        for field in [
            "daemon_socket",
            "listen",
            "worker",
            "worker_spki_sha256",
            "tls",
        ] {
            assert!(
                spec.get(field).is_none(),
                "local transport intent must not enter worker spec"
            );
        }
    }

    #[test]
    fn worker_runtime_and_incremental_artifact_contracts_follow_actual_command() {
        for (args, contract) in [
            (vec!["check"], "cargo-json-v1"),
            (vec!["test", "--no-run"], "cargo-json-v1"),
            (
                vec!["test", "selected", "--", "--nocapture"],
                "cargo-test-json-v1",
            ),
            (
                vec!["run", "--bin", "app", "--", "--worker", "literal"],
                "cargo-run-json-v1",
            ),
            (vec!["bench", "--no-run"], "cargo-json-v1"),
            (vec!["bench", "--", "--exact"], "cargo-bench-json-v1"),
        ] {
            for incremental in [false, true] {
                let mut profile = profile();
                set(&mut profile, "incremental", json!(incremental));
                let options = options(&args);
                let spec = specification(&profile, &options).unwrap();
                let expected = if incremental {
                    contract.replacen("cargo-", "cargo-private-incremental-", 1)
                } else {
                    contract.into()
                };
                assert_eq!(spec["artifacts"]["cargo"], expected);
                assert_eq!(
                    spec["command_context"]["env"]["CARGO_INCREMENTAL"],
                    if incremental { "1" } else { "0" }
                );
                let command = options.selected.as_ref().unwrap();
                let tail = command.1.runtime_arguments(command.0).unwrap();
                let actual: Vec<_> = spec["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|arg| arg.as_str().unwrap().to_owned())
                    .collect();
                assert!(actual.ends_with(&tail));
            }
        }
    }

    #[test]
    fn worker_multiple_target_builds_bind_all_targets_and_private_state_roots() {
        let (_root, mut profile) = filesystem_profile();
        let selected_options = options(&[
            "build",
            "--target=aarch64-unknown-linux-gnu",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--release",
        ]);
        for incremental in [false, true] {
            set(&mut profile, "incremental", json!(incremental));
            validate_profile(&profile, &selected_options).unwrap();
            let spec = specification(&profile, &selected_options).unwrap();
            let arguments = spec["args"].as_array().unwrap();
            let targets = arguments
                .windows(2)
                .filter(|pair| pair[0] == "--target")
                .map(|pair| pair[1].as_str().unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                targets,
                ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
            );
            assert_eq!(
                rabs_sandbox::cargo_artifacts::private_incremental_roots(&spec).unwrap(),
                incremental.then(|| vec![
                    "aarch64-unknown-linux-gnu/release/incremental".into(),
                    "release/incremental".into(),
                    "x86_64-unknown-linux-gnu/release/incremental".into(),
                ])
            );
        }
        let unsupported = options(&[
            "build",
            "--target=x86_64-unknown-linux-gnu",
            "--target=x86_64-pc-windows-msvc",
        ]);
        assert!(validate_profile(&profile, &unsupported).is_err());
    }

    #[test]
    fn worker_explicit_test_threads_preserve_argv_and_the_host_sized_default_grant() {
        let (_root, mut profile) = filesystem_profile();
        for command in ["test", "bench"] {
            let selected = options(&[command, "--", "--test-threads=8", "--test-threads", "1"]);
            validate_profile(&profile, &selected).unwrap();
            let original = profile.clone();
            let spec = specification(&profile, &selected).unwrap();
            assert!(spec.get("jobserver_grant").is_none());
            let contract = rabs_sandbox::cargo_artifacts::test_threads::requested(&spec)
                .unwrap()
                .unwrap();
            assert_eq!(contract.build_grant(16).unwrap(), 16);
            assert_eq!(contract.execution_slots(16).unwrap(), 16);
            assert!(contract.execution_slots(4).is_err());
            assert_eq!(profile, original);
            let args = spec["args"].as_array().unwrap();
            assert_eq!(
                &args[args.len() - 4..],
                &[
                    json!("--"),
                    json!("--test-threads=8"),
                    json!("--test-threads"),
                    json!("1")
                ]
            );
            set(&mut profile, "jobserver_grant", json!(2));
            let fixed = specification(&profile, &selected).unwrap();
            let contract = rabs_sandbox::cargo_artifacts::test_threads::requested(&fixed)
                .unwrap()
                .unwrap();
            assert_eq!(contract.build_grant(8).unwrap(), 2);
            assert_eq!(contract.execution_slots(8).unwrap(), 8);
            profile.remove("jobserver_grant");
        }
        set(&mut profile, "source_root", json!("/unopened/test-source"));
        for control in [
            "--test-threads=0",
            "--test-threads=4097",
            "--test-threads=custom",
        ] {
            let error = validate_profile(&profile, &options(&["test", "--", control])).unwrap_err();
            assert!(error.to_string().contains("concurrency"), "{error}");
        }
    }

    #[test]
    fn worker_nextest_requires_explicit_runtime_admission_before_opening_roots() {
        let mut profile = profile();
        set(
            &mut profile,
            "source_root",
            json!("/unopened/nextest-source"),
        );
        let error = validate_profile(&profile, &options(&["nextest", "run"])).unwrap_err();
        assert!(error.to_string().contains("test-threads"), "{error}");

        let (root, mut profile) = filesystem_profile();
        set(&mut profile, "jobserver_grant", json!(2));
        for (arguments, expected) in [
            (vec!["nextest", "run", "--test-threads", "8"], 8),
            (vec!["nextest", "run", "--test-threads", "1"], 2),
            (vec!["nextest", "run", "--no-run"], 2),
        ] {
            let options = options(&arguments);
            validate_profile(&profile, &options).unwrap();
            let request = specification(&profile, &options).unwrap();
            assert_eq!(
                rabs_sandbox::cargo_artifacts::nextest::fresh_execution_slots(&request).unwrap(),
                Some(expected)
            );
            assert_eq!(request["jobserver_grant"], 2);
            assert_eq!(request["artifacts"]["cargo"]["build_jobs"], 2);
        }
        for alias in ["--test-threads=8", "--jobs=8", "-j8", "--build-jobs=8"] {
            let arguments = ["nextest", "run", "--test-threads", "1", "--", alias];
            assert!(
                validate_profile(&profile, &options(&arguments)).is_err(),
                "{alias}"
            );
        }
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
    }

    #[test]
    fn worker_nextest_captures_shared_selection_and_exact_fresh_execution_contract() {
        use rabs_sandbox::cargo_artifacts::{CargoArtifactMode, requested};

        let (root, mut profile) = filesystem_profile();
        set(&mut profile, "jobserver_grant", json!(3));
        set(
            &mut profile,
            "source_selection",
            json!("cargo-unit-graph-v1"),
        );
        let options = options(&[
            "nextest",
            "run",
            "--workspace",
            "--cargo-profile",
            "release",
            "--profile",
            "ci",
            "--test-threads",
            "1",
            "--partition",
            "hash:2/3",
            "-E",
            "test(roundtrip)",
            "--",
            "--exact",
            "--message-format=json",
        ]);
        validate_profile(&profile, &options).unwrap();
        let spec = specification(&profile, &options).unwrap();
        assert_eq!(spec["program"], "/__rabs/toolchain/bin/cargo-nextest");
        assert_eq!(spec["jobserver_grant"], 3);
        assert_eq!(
            requested(&spec).unwrap(),
            Some(CargoArtifactMode::NextestExecution)
        );
        assert_eq!(spec["artifacts"]["cargo"]["version"], "nextest-tree-v1");
        assert_eq!(spec["artifacts"]["cargo"]["build_jobs"], 3);
        let contract: NextestTree =
            serde_json::from_value(spec["artifacts"]["cargo"].clone()).unwrap();
        assert_eq!(contract.selection, options.selected.as_ref().unwrap().1);
        assert_eq!(contract.selection.partition.as_deref(), Some("hash:2/3"));
        let args = spec["args"].as_array().unwrap();
        assert!(
            args.windows(2)
                .any(|pair| pair == [json!("--partition"), json!("hash:2/3")])
        );
        assert_eq!(&args[..2], &[json!("nextest"), json!("run")]);
        assert!(
            args.windows(2)
                .any(|pair| pair == [json!("--build-jobs"), json!("3")])
        );
        assert_eq!(
            &args[args.len() - 3..],
            &[
                json!("--"),
                json!("--exact"),
                json!("--message-format=json")
            ]
        );
        assert!(!args[..args.len() - 3].contains(&json!("--message-format=json")));
        assert_eq!(spec["cargo_source"]["selection"], "cargo-unit-graph-v1");
        assert_eq!(spec["command_context"]["env"]["CARGO_INCREMENTAL"], "0");

        profile.remove("jobserver_grant");
        let default = specification(&profile, &options).unwrap();
        assert_eq!(default["jobserver_grant"], 1);
        assert_eq!(default["artifacts"]["cargo"]["build_jobs"], 1);
        assert_eq!(
            requested(&default).unwrap(),
            Some(CargoArtifactMode::NextestExecution)
        );

        set(&mut profile, "incremental", json!(true));
        assert!(validate_profile(&profile, &options).is_err());
        set(&mut profile, "incremental", json!(false));
        fs::set_permissions(
            root.join("sdk/bin/cargo-nextest"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(validate_profile(&profile, &options).is_err());
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
    }

    #[test]
    fn worker_lint_and_documentation_controls_use_captured_companions() {
        let mut profile = profile();
        set(&mut profile, "vendor", json!("vendor"));
        let lint_options = options(&["clippy", "--no-deps", "--", "-D", "warnings"]);
        let spec = specification(&profile, &lint_options).unwrap();
        assert_eq!(spec["program"], "/__rabs/toolchain/bin/cargo-clippy");
        assert_eq!(
            spec["command_context"]["env"]["CARGO"],
            "/__rabs/toolchain/bin/cargo"
        );
        assert_eq!(
            spec["command_context"]["env"]["RUSTC"],
            "/__rabs/toolchain/bin/rustc"
        );
        assert_eq!(spec["cargo_source"]["vendor"], "vendor");
        let doc = specification(&profile, &options(&["doc", "--document-private-items"])).unwrap();
        assert_eq!(
            doc["command_context"]["env"]["RUSTDOC"],
            "/__rabs/toolchain/bin/rustdoc"
        );
        assert_eq!(doc["artifacts"]["cargo"], "cargo-json-v1");
    }

    #[test]
    fn worker_pool_preserves_order_and_rejects_aliases_and_ambiguous_identity() {
        let mut profile = profile();
        for key in ["listen", "worker", "worker_spki_sha256"] {
            profile.remove(key);
        }
        set(&mut profile, "daemon_socket", json!("/private/rabs.sock"));
        let first = worker_value("127.0.0.1:7443", "worker-one", PIN);
        let second = worker_value("[2001:db8::1]:7444", "worker-two", SECOND_PIN);
        set(&mut profile, "workers", json!([first, second]));
        let Placement::Pool(workers) = placement(&profile).unwrap() else {
            panic!("expected ordered worker pool");
        };
        assert_eq!(
            workers.iter().map(Worker::value).collect::<Vec<_>>(),
            vec![
                json!({"address":"127.0.0.1:7443", "worker":"worker-one", "worker_spki_sha256":PIN}),
                json!({"address":"[2001:db8::1]:7444", "worker":"worker-two", "worker_spki_sha256":SECOND_PIN}),
            ]
        );
        for conflicting in [
            worker_value("[::ffff:127.0.0.1]:7443", "worker-two", SECOND_PIN),
            worker_value("[::]:7443", "worker-two", SECOND_PIN),
            worker_value("192.0.2.1:7444", "worker-one", SECOND_PIN),
            worker_value("192.0.2.1:7444", "worker-two", PIN),
        ] {
            set(&mut profile, "workers", json!([first, conflicting]));
            assert!(placement(&profile).is_err());
        }
        set(&mut profile, "workers", json!([first, second]));
        set(&mut profile, "listen", json!("127.0.0.1:7443"));
        assert!(placement(&profile).is_err());
        profile.remove("listen");
        profile.remove("daemon_socket");
        assert!(placement(&profile).is_err());
    }

    #[test]
    fn invalid_worker_intent_refuses_before_creating_retained_state() {
        let (root, baseline) = filesystem_profile();
        let build_options = options(&["build"]);
        validate_profile(&baseline, &build_options).unwrap();
        for (field, value) in [
            ("version", json!("canonical-compile-local-v1")),
            ("unknown", json!(true)),
            ("incremental", json!(1)),
            ("live_stderr", json!("true")),
            ("jobserver_grant", json!(true)),
            ("jobserver_grant", json!(0)),
            ("jobserver_grant", json!(4097)),
            ("listen", json!("worker.example:7443")),
            ("listen", json!("[fe80::1%3]:7443")),
            ("listen", json!("127.0.0.1:0")),
            ("worker", json!("worker; echo bad")),
            ("worker_spki_sha256", json!("0".repeat(64))),
            ("worker_spki_sha256", json!("A".repeat(64))),
            ("manifest", json!("nested/../Cargo.toml")),
            ("vendor", json!("../outside")),
            ("source_selection", json!("unknown")),
            ("env", json!({"RABS_TLS_KEY":"must not be uploaded"})),
            ("env", json!({"HOME":"/other"})),
            ("env", json!({"RUSTFLAGS":"--cfg bypass"})),
            ("env", json!({"RUSTC_WRAPPER":"/another/compiler"})),
            ("env", json!({"BUILD_VALUE":false})),
            ("env", json!({"BUILD_VALUE":"bad\u{0}value"})),
        ] {
            let mut profile = baseline.clone();
            set(&mut profile, field, value);
            assert!(
                validate_profile(&profile, &build_options).is_err(),
                "invalid {field} must refuse"
            );
        }
        let mut conflicting = baseline.clone();
        set(&mut conflicting, "vendor", json!("vendor"));
        set(
            &mut conflicting,
            "cargo_home_source",
            baseline["source_root"].clone(),
        );
        assert!(validate_profile(&conflicting, &build_options).is_err());
        for input in [
            Input::Policy(CompilationStdin::Inherit),
            Input::File("../input.bin".into()),
        ] {
            let mut options = options(&["run"]);
            options.input = Some(input);
            assert!(validate_profile(&baseline, &options).is_err());
        }
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
    }

    #[test]
    fn selected_vendor_worker_profiles_retain_both_controls_without_creating_state() {
        for arguments in [
            vec!["check"],
            vec!["build"],
            vec!["clippy"],
            vec!["test", "--no-run"],
            vec!["nextest", "run", "--no-run"],
        ] {
            let (root, mut profile) = filesystem_profile();
            let options = options(&arguments);
            set(&mut profile, "vendor", json!("vendor"));
            set(
                &mut profile,
                "source_selection",
                json!("cargo-unit-graph-v1"),
            );
            validate_profile(&profile, &options).unwrap();
            let request = specification(&profile, &options).unwrap();
            assert_eq!(
                request["cargo_source"],
                json!({"manifest":"nested/Cargo.toml", "vendor":"vendor",
                    "selection":"cargo-unit-graph-v1"})
            );
            assert_eq!(request["request_id"], "allocate");
            assert!(request.get("publication_authorized").is_none());
            assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
        }
    }

    #[test]
    fn direct_live_stderr_is_presentation_only_and_accepts_explicit_false() {
        let (root, baseline) = filesystem_profile();
        let options = options(&["build"]);
        let original = specification(&baseline, &options).unwrap();
        for selected in [false, true] {
            let mut profile = baseline.clone();
            set(&mut profile, "live_stderr", json!(selected));
            validate_profile(&profile, &options).unwrap();
            assert!(profile.get("daemon_socket").is_none());
            assert_eq!(specification(&profile, &options).unwrap(), original);
        }
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
    }

    #[test]
    fn worker_captured_stdin_preserves_execution_selection_and_exact_request() {
        let (root, profile) = filesystem_profile();
        fs::create_dir(root.join("source/inputs")).unwrap();
        fs::write(root.join("source/inputs/request.bin"), b"\0input\xff").unwrap();
        for arguments in [
            vec!["run"],
            vec!["test"],
            vec!["bench"],
            vec!["nextest", "run", "--test-threads", "2"],
        ] {
            let mut options = options(&arguments);
            let closed = specification(&profile, &options).unwrap();
            options.input = Some(Input::File("inputs/request.bin".into()));
            validate_profile(&profile, &options).unwrap();
            let mut request = specification(&profile, &options).unwrap();
            assert_eq!(
                request["captured_stdin"],
                json!({
                    "version":"source-file-stdin-v1", "path":"inputs/request.bin",
                })
            );
            if arguments[0] == "nextest" {
                assert_eq!(request["jobserver_grant"], 1);
                assert_eq!(request["artifacts"]["cargo"]["build_jobs"], 1);
                assert_eq!(
                    request["artifacts"]["cargo"]["selection"]["test_threads"],
                    2
                );
                assert_eq!(
                    rabs_sandbox::cargo_artifacts::nextest::fresh_execution_slots(&request)
                        .unwrap(),
                    Some(2)
                );
            }
            request.as_object_mut().unwrap().remove("captured_stdin");
            assert_eq!(
                request, closed,
                "runtime input must preserve the Cargo command"
            );
        }
        for arguments in [
            vec!["build"],
            vec!["check"],
            vec!["test", "--no-run"],
            vec!["bench", "--no-run"],
            vec!["nextest", "run", "--no-run"],
        ] {
            let mut options = options(&arguments);
            options.input = Some(Input::File("inputs/request.bin".into()));
            assert!(
                validate_profile(&profile, &options).is_err(),
                "{arguments:?}"
            );
        }
    }

    #[test]
    fn worker_captured_stdin_refuses_oversize_and_nonregular_input_before_retention() {
        let (root, profile) = filesystem_profile();
        let input = File::create(root.join("source/input.bin")).unwrap();
        let mut options = options(&["run"]);
        options.input = Some(Input::File("input.bin".into()));
        validate_profile(&profile, &options).unwrap();
        input
            .set_len(rabs_sandbox::captured_stdin::MAX_CAPTURED_STDIN_BYTES)
            .unwrap();
        validate_profile(&profile, &options).unwrap();
        input
            .set_len(rabs_sandbox::captured_stdin::MAX_CAPTURED_STDIN_BYTES + 1)
            .unwrap();
        assert!(validate_profile(&profile, &options).is_err());
        symlink("input.bin", root.join("source/alias")).unwrap();
        fs::create_dir(root.join("source/directory")).unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.join("source/fifo"),
            FileMode::RUSR | FileMode::WUSR,
        )
        .unwrap();
        for path in ["alias", "directory", "fifo", "absent"] {
            options.input = Some(Input::File(path.into()));
            assert!(validate_profile(&profile, &options).is_err(), "{path}");
        }
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
    }

    #[test]
    fn worker_profile_checks_physical_roots_and_toolchain_before_retention() {
        let (root, baseline) = filesystem_profile();
        let clippy_options = options(&["clippy"]);
        validate_profile(&baseline, &clippy_options).unwrap();
        let alias = root.join("source-alias");
        symlink(root.join("source"), &alias).unwrap();
        let mut profile = baseline.clone();
        set(
            &mut profile,
            "source_root",
            serde_json::to_value(alias).unwrap(),
        );
        assert!(validate_profile(&profile, &clippy_options).is_err());
        let mut profile = baseline.clone();
        set(
            &mut profile,
            "operation_root",
            baseline["source_root"].clone(),
        );
        assert!(validate_profile(&profile, &clippy_options).is_err());
        fs::set_permissions(
            root.join("sdk/bin/clippy-driver"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(validate_profile(&baseline, &clippy_options).is_err());
        let build_options = options(&["build"]);
        validate_profile(&baseline, &build_options).unwrap();
        fs::set_permissions(root.join("operations"), fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_profile(&baseline, &build_options).is_err());
        assert_eq!(fs::read_dir(root.join("operations")).unwrap().count(), 0);
    }
}
