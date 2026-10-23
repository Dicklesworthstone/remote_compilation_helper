//! Real daemon and public CLI coverage for durable prepared operations.
//!
//! The ordinary tests hold an actual TLS listener without connecting a worker:
//! they exercise queue ownership, cancellation and crash recovery, not compiler
//! execution. The explicit canonical-host tests run the real worker and rustc.
//! Unsupported Unix sockets or missing OpenSSL fail, rather than become a pass.
#![cfg(target_os = "linux")]

use rabs_asupersync::worker_transport::TlsFiles;
use rabsd::coord::source_delivery::{prepare_source_bundle, prepare_source_template};
use serde_json::{Value, json};
use std::cell::Cell;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[path = "prepared_operation_live/dependency_worker.rs"]
mod dependency_worker;
#[path = "prepared_operation_live/live_dependency_worker.rs"]
mod live_dependency_worker;

const LOG_LIMIT: u64 = 2 * 1024 * 1024;

fn read_log(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    File::open(path)
        .unwrap()
        .take(LOG_LIMIT + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(
        bytes.len() as u64 <= LOG_LIMIT,
        "fixture log exceeded its bound"
    );
    bytes
}

fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command.env_clear();
    for name in ["PATH", "LD_LIBRARY_PATH", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

struct Process {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
    reaped: bool,
}

impl Process {
    fn spawn(root: &Path, name: &str, command: &mut Command) -> Self {
        let stdout = root.join(format!("{name}.stdout"));
        let stderr = root.join(format!("{name}.stderr"));
        let child = command
            .stdin(Stdio::null())
            .stdout(File::create(&stdout).unwrap())
            .stderr(File::create(&stderr).unwrap())
            .spawn()
            .expect("the actual fixture executable must be available");
        Self {
            child,
            stdout,
            stderr,
            reaped: false,
        }
    }

    fn wait(&mut self, budget: Duration) -> ExitStatus {
        let until = Instant::now() + budget;
        loop {
            for path in [&self.stdout, &self.stderr] {
                assert!(
                    fs::metadata(path).unwrap().len() <= LOG_LIMIT,
                    "unbounded child log"
                );
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                self.reaped = true;
                return status;
            }
            assert!(
                Instant::now() < until,
                "process timeout: {}",
                String::from_utf8_lossy(&read_log(&self.stderr))
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn terminate(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "daemon exited before shutdown"
        );
        let output = command("/bin/kill")
            .args(["-TERM", &self.child.id().to_string()])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            self.wait(Duration::from_secs(15)).success(),
            "{}",
            String::from_utf8_lossy(&read_log(&self.stderr))
        );
    }

    fn crash(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        self.child.kill().unwrap();
        assert!(!self.wait(Duration::from_secs(5)).success());
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct Certificates {
    server: TlsFiles,
    worker: TlsFiles,
}

impl Certificates {
    fn new(root: &Path) -> Self {
        fs::create_dir(root).unwrap();
        let run = |name: &str, args: &[&str]| {
            let mut cmd = command("openssl");
            cmd.current_dir(root).args(args);
            let mut process = Process::spawn(root, name, &mut cmd);
            assert!(
                process.wait(Duration::from_secs(20)).success(),
                "{}",
                String::from_utf8_lossy(&read_log(&process.stderr))
            );
        };
        run(
            "ca",
            &[
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=Prepared operation test CA",
                "-keyout",
                "ca.key",
                "-out",
                "ca.pem",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ],
        );
        for (name, usage, serial) in [("server", "serverAuth", "2"), ("worker", "clientAuth", "3")]
        {
            let key = format!("{name}.key");
            let csr = format!("{name}.csr");
            let certificate = format!("{name}.pem");
            let extensions = format!("{name}.ext");
            run(
                &format!("{name}-request"),
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-sha256",
                    "-subj",
                    "/CN=localhost",
                    "-keyout",
                    &key,
                    "-out",
                    &csr,
                ],
            );
            fs::write(root.join(&extensions), format!(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost\n"
            )).unwrap();
            run(
                &format!("{name}-sign"),
                &[
                    "x509",
                    "-req",
                    "-in",
                    &csr,
                    "-CA",
                    "ca.pem",
                    "-CAkey",
                    "ca.key",
                    "-set_serial",
                    serial,
                    "-days",
                    "1",
                    "-sha256",
                    "-extfile",
                    &extensions,
                    "-out",
                    &certificate,
                ],
            );
        }
        let files = |name: &str| TlsFiles {
            ca: root.join("ca.pem"),
            certificate: root.join(format!("{name}.pem")),
            private_key: root.join(format!("{name}.key")),
        };
        Self {
            server: files("server"),
            worker: files("worker"),
        }
    }

    fn pin(&self) -> String {
        self.worker
            .local_identity()
            .unwrap()
            .fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

struct Job {
    id: String,
    worker: String,
    bundle: PathBuf,
    delivery: PathBuf,
    output: PathBuf,
}

struct Fixture {
    owner: tempfile::TempDir,
    certificates: Certificates,
    sequence: Cell<u64>,
}

impl Fixture {
    fn new() -> Self {
        let owner = tempfile::tempdir().unwrap();
        fs::set_permissions(owner.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let certificates = Certificates::new(&owner.path().join("credentials"));
        Self {
            owner,
            certificates,
            sequence: Cell::new(0),
        }
    }

    fn command(&self) -> Command {
        let mut cmd = command(env!("CARGO_BIN_EXE_rabsd"));
        cmd.env("RABS_CONFIG", self.owner.path().join("absent-config.toml"))
            .env("RABS_SOCKET_PATH", self.owner.path().join("daemon.sock"))
            .env("RABS_BOOT_MARKER", self.owner.path().join("daemon.boot"))
            .env("RABS_STATE_DIR", self.owner.path().join("state"))
            .env("RABS_COORD_TLS_CA", &self.certificates.server.ca)
            .env("RABS_COORD_TLS_CERT", &self.certificates.server.certificate)
            .env("RABS_COORD_TLS_KEY", &self.certificates.server.private_key);
        cmd
    }

    fn next_name(&self, prefix: &str) -> String {
        let value = self.sequence.get();
        self.sequence.set(value + 1);
        format!("{prefix}-{value}")
    }

    fn daemon(&self) -> Process {
        self.daemon_with_environment(&[])
    }

    fn daemon_with_environment(&self, environment: &[(String, String)]) -> Process {
        let mut command = self.command();
        command.envs(environment.iter().map(|(name, value)| (name, value)));
        let mut daemon = Process::spawn(self.owner.path(), &self.next_name("daemon"), &mut command);
        let socket = self.owner.path().join("daemon.sock");
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(mut stream) = UnixStream::connect(&socket) {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                writeln!(
                    stream,
                    "{}",
                    json!({"kind":"hello", "transport":{"minimum_compatible":1,"current":1},
                    "application":{"minimum_compatible":1,"current":1}})
                )
                .unwrap();
                let mut line = String::new();
                BufReader::new(stream).read_line(&mut line).unwrap();
                let reply: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(reply["kind"], "hello-ok");
                return daemon;
            }
            if let Some(status) = daemon.child.try_wait().unwrap() {
                daemon.reaped = true;
                panic!(
                    "daemon exited before readiness ({status}): {}",
                    String::from_utf8_lossy(&read_log(&daemon.stderr))
                );
            }
            assert!(
                Instant::now() < until,
                "daemon socket readiness timeout: {}",
                String::from_utf8_lossy(&read_log(&daemon.stderr))
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn cli(&self, args: &[String]) -> (ExitStatus, Value) {
        let mut cmd = self.command();
        cmd.args(args);
        let mut process = Process::spawn(self.owner.path(), &self.next_name("cli"), &mut cmd);
        let status = process.wait(Duration::from_secs(15));
        let stdout = read_log(&process.stdout);
        let value = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
            panic!(
                "CLI JSON: {error}; stdout={}; stderr={}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&read_log(&process.stderr))
            )
        });
        (status, value)
    }

    fn operation(&self, args: &[String]) -> Value {
        let (status, value) = self.cli(args);
        assert!(status.success(), "{value}");
        assert_eq!(value["kind"], "prepared-operation");
        assert_eq!(value["publication_authorized"], false);
        assert_eq!(value["reexecute"], false);
        value["operation"].clone()
    }

    fn submission(&self, job: &Job) -> Vec<String> {
        vec![
            "--job-submit".into(),
            job.id.clone(),
            "127.0.0.1:0".into(),
            job.worker.clone(),
            self.certificates.pin(),
            job.bundle.to_str().unwrap().into(),
            job.delivery.to_str().unwrap().into(),
            job.output.to_str().unwrap().into(),
        ]
    }

    fn status(&self, job: &Job) -> Value {
        self.operation(&["--job-status".into(), job.id.clone()])
    }

    fn wait_for(&self, job: &Job, budget: Duration, predicate: impl Fn(&Value) -> bool) -> Value {
        let until = Instant::now() + budget;
        loop {
            let value = self.status(job);
            if predicate(&value) {
                return value;
            }
            assert!(
                Instant::now() < until,
                "operation did not reach the expected state: {value}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn prepare(&self, number: u64, native: bool) -> Job {
        self.prepare_with_allocation(number, native, false)
    }

    fn prepare_with_allocation(&self, number: u64, native: bool, allocated: bool) -> Job {
        let source = self.owner.path().join(format!("source-{number}"));
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("lib.rs"),
            b"pub const LABEL: &str = env!(\"PREPARED_LABEL\"); pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        let (toolchain, program, args, artifact) = if native {
            let cargo =
                fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
            let toolchain = cargo.parent().and_then(Path::parent).unwrap().to_path_buf();
            let compiler = fs::canonicalize(toolchain.join("bin/rustc")).unwrap();
            assert_eq!(
                compiler.file_name().unwrap(),
                "rustc",
                "use an installed toolchain, not rustup proxies"
            );
            (
                toolchain,
                "/__rabs/toolchain/bin/rustc",
                vec![
                    "lib.rs",
                    "--crate-name",
                    "prepared_fixture",
                    "--crate-type",
                    "lib",
                    "--emit=metadata",
                    "--edition=2021",
                    "-o",
                    "/__rabs/out/build/libprepared_fixture.rmeta",
                ],
                "libprepared_fixture.rmeta",
            )
        } else {
            // Real captured bytes, with no claim that this fixture is a compiler.
            // These tests never connect a worker or dispatch this executable.
            let toolchain = self.owner.path().join(format!("toolchain-{number}"));
            fs::create_dir_all(toolchain.join("bin")).unwrap();
            let executable = toolchain.join("bin/fixture");
            fs::write(&executable, b"#!/bin/sh\nexit 99\n").unwrap();
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
            (
                toolchain,
                "/__rabs/toolchain/bin/fixture",
                Vec::new(),
                "result.bin",
            )
        };
        let job = Job {
            id: format!("{number:032x}"),
            worker: "prepared-worker".into(),
            bundle: self.owner.path().join(format!("bundle-{number}")),
            delivery: self.owner.path().join(format!("delivery-{number}")),
            output: self.owner.path().join(format!("output-{number}")),
        };
        let mut request = json!({"kind":"canonical-exec", "request_id":number, "program":program, "args":args,
            "toolchain_source":toolchain, "toolchain_backing":toolchain, "source_files":["lib.rs"],
            "timeout_ms":90000, "jobserver_grant":1,
            "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace", "env":{"PREPARED_LABEL":"native-Δ"}},
            "artifacts":{"unit":"build", "files":[artifact]}});
        if allocated {
            request["request_id"] = json!("allocate");
            prepare_source_template(&source, &request, &job.bundle).unwrap();
        } else {
            prepare_source_bundle(&source, &request, &job.bundle).unwrap();
        }
        job
    }

    /// Exercise native source/toolchain capture and daemon admission without
    /// connecting a worker. These bytes are explicitly not a compiler fixture.
    fn start_allocated_build(&self, number: u64) -> (Job, Process) {
        self.start_allocated_build_with_pool(number, None)
    }

    fn start_allocated_build_with_pool(&self, number: u64, pool: Option<&Path>) -> (Job, Process) {
        let source = self.owner.path().join(format!("allocated-source-{number}"));
        fs::create_dir(&source).unwrap();
        fs::write(source.join("input.txt"), b"retained allocation fixture\n").unwrap();
        let toolchain = self
            .owner
            .path()
            .join(format!("allocated-toolchain-{number}"));
        fs::create_dir_all(toolchain.join("bin")).unwrap();
        let executable = toolchain.join("bin/fixture");
        fs::write(&executable, b"#!/bin/sh\nexit 99\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let specification = self.owner.path().join(format!("allocation-{number}.json"));
        fs::write(
            &specification,
            serde_json::to_vec(&json!({
                "kind":"canonical-exec", "request_id":"allocate",
                "program":"/__rabs/toolchain/bin/fixture", "args":[],
                "toolchain_source":toolchain, "source_files":["input.txt"],
                "timeout_ms":90000, "jobserver_grant":1,
                "artifacts":{"unit":"build", "files":["result.bin"]},
            }))
            .unwrap(),
        )
        .unwrap();
        let job = Job {
            id: format!("{number:032x}"),
            worker: "prepared-worker".into(),
            bundle: self.owner.path().join(format!("allocated-bundle-{number}")),
            delivery: self
                .owner
                .path()
                .join(format!("allocated-delivery-{number}")),
            output: self.owner.path().join(format!("allocated-output-{number}")),
        };
        let mut cmd = self.command();
        cmd.args(["--job-build", "--prepare-from"])
            .arg(source)
            .arg(specification)
            .arg(&job.id);
        if let Some(pool) = pool {
            cmd.arg("--worker-pool").arg(pool);
        } else {
            cmd.arg("127.0.0.1:0")
                .arg(&job.worker)
                .arg(self.certificates.pin());
        }
        cmd.arg(&job.bundle).arg(&job.delivery).arg(&job.output);
        let client = Process::spawn(self.owner.path(), &self.next_name("job-build"), &mut cmd);
        (job, client)
    }

    fn wait_for_submission(&self, job: &Job, client: &mut Process) -> Value {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let (status, reply) = self.cli(&["--job-status".into(), job.id.clone()]);
            if status.success() {
                assert_eq!(reply["kind"], "prepared-operation");
                assert_eq!(reply["operation"]["id"], job.id);
                return reply["operation"].clone();
            }
            assert_eq!(reply["kind"], "prepared-operation-error");
            assert!(
                client.child.try_wait().unwrap().is_none(),
                "job-build exited before admission: {}",
                String::from_utf8_lossy(&read_log(&client.stderr))
            );
            assert!(
                Instant::now() < until,
                "job-build did not submit its retained inputs: {}",
                String::from_utf8_lossy(&read_log(&client.stderr))
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn configured_daemon_runs_eight_owned_tls_listeners_and_reuses_released_capacity() {
    // Real daemon, public CLI and TLS listener owners; no worker connects and
    // these fixtures do not claim compiler execution or cache publication.
    let fixture = Fixture::new();
    let mut daemon =
        fixture.daemon_with_environment(&[("RABS_PREPARED_CONCURRENCY".into(), "8".into())]);
    let mut jobs = Vec::new();
    for number in 1..=9 {
        let mut job = fixture.prepare_with_allocation(number, false, true);
        job.worker = format!("capacity-worker-{number}");
        let mut submission = fixture.submission(&job);
        submission[0] = "--job-submit-allocated".into();
        submission[4] = format!("{number:064x}");
        fixture.operation(&submission);
        jobs.push(job);
    }
    let mut listeners = std::collections::BTreeSet::new();
    for job in &jobs[..8] {
        let running = fixture.wait_for(job, Duration::from_secs(15), |status| {
            status["state"] == "running" && status["listen_address"].is_string()
        });
        listeners.insert(running["listen_address"].as_str().unwrap().to_owned());
    }
    assert_eq!(
        listeners.len(),
        8,
        "every owned slot has a distinct real listener"
    );
    let queued = fixture.status(&jobs[8]);
    assert_eq!(queued["state"], "queued");
    assert_eq!(queued["attempt"], 0);
    assert!(queued["request_id"].is_null());
    let capacity = || {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            // This client uses its ordinary default configuration. The reply
            // must describe the daemon's actual eight-slot store.
            let (status, value) = fixture.cli(&["--coord-status".into()]);
            assert!(status.success(), "{value}");
            assert_eq!(value["kind"], "coord-status");
            if value["prepared_jobs"]["available"] == true {
                return value["prepared_jobs"].clone();
            }
            assert!(
                Instant::now() < until,
                "capacity status stayed unavailable: {value}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    assert_eq!(
        capacity(),
        json!({
            "available":true, "concurrency":8, "active":8, "queued":1,
            "accepting":true, "persistence_uncertain":false,
        })
    );
    fixture.operation(&["--job-cancel".into(), jobs[0].id.clone()]);
    fixture.wait_for(&jobs[0], Duration::from_secs(15), |status| {
        status["state"] == "cancelled"
    });
    let running = fixture.wait_for(&jobs[8], Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    assert_eq!(running["request_sha256"], queued["request_sha256"]);
    assert_eq!(running["worker"], queued["worker"]);
    assert!(running["request_id"].as_u64().is_some_and(|id| id > 0));
    assert_eq!(capacity()["active"], 8);
    assert_eq!(capacity()["queued"], 0);
    daemon.terminate();
}

#[test]
fn pooled_cli_builds_use_idle_workers_and_keep_placement_after_client_and_daemon_loss() {
    // This exercises real capture, native clients, the daemon UDS API and TLS
    // listener ownership. No worker is connected and no compiler is executed.
    let fixture = Fixture::new();
    let blocker = fixture.prepare(1, false);
    let mut daemon = fixture.daemon();
    fixture.operation(&fixture.submission(&blocker));
    let busy = fixture.wait_for(&blocker, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    let available = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = available.local_addr().unwrap().to_string();
    let workers = json!([
        {"address":busy["listen_address"], "worker":blocker.worker,
         "worker_spki_sha256":fixture.certificates.pin()},
        {"address":address, "worker":"pool-second", "worker_spki_sha256":"22".repeat(32)}
    ]);
    let pool = fixture.owner.path().join("pool.json");
    fs::write(&pool, serde_json::to_vec(&workers).unwrap()).unwrap();
    drop(available);

    let (second, mut second_client) = fixture.start_allocated_build_with_pool(103, Some(&pool));
    fixture.wait_for_submission(&second, &mut second_client);
    let running = fixture.wait_for(&second, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    assert_eq!(running["worker"], "pool-second");
    assert_eq!(running["address"], address);
    assert_eq!(running["listen_address"], address);
    assert!(running["request_id"].as_u64().is_some_and(|id| id > 0));
    assert_eq!(fixture.status(&blocker)["state"], "running");

    // Both candidates now have one running job. Stable input order queues the
    // next build on the first worker without allocating another worker ID.
    let (queued, mut queued_client) = fixture.start_allocated_build_with_pool(104, Some(&pool));
    let before = fixture.wait_for_submission(&queued, &mut queued_client);
    assert_eq!(before["state"], "queued");
    assert_eq!(before["worker"], blocker.worker);
    assert!(before["request_id"].is_null());
    queued_client.crash();
    let submit = vec![
        "--job-submit-pool".into(),
        queued.id.clone(),
        pool.to_str().unwrap().into(),
        queued.bundle.to_str().unwrap().into(),
        queued.delivery.to_str().unwrap().into(),
        queued.output.to_str().unwrap().into(),
    ];
    let retry = fixture.operation(&submit);
    assert_eq!(retry["state"], "queued");
    assert_eq!(retry["worker"], before["worker"]);
    assert_eq!(retry["request_sha256"], before["request_sha256"]);
    let reversed = json!([workers[1], workers[0]]);
    fs::write(&pool, serde_json::to_vec(&reversed).unwrap()).unwrap();
    let (status, reply) = fixture.cli(&submit);
    assert!(!status.success());
    assert_eq!(reply["kind"], "prepared-operation-error");
    fs::write(&pool, serde_json::to_vec(&workers).unwrap()).unwrap();

    daemon.crash();
    assert!(!second_client.wait(Duration::from_secs(15)).success());
    let mut restarted = fixture.daemon();
    let uncertain = fixture.status(&second);
    assert_eq!(uncertain["state"], "uncertain");
    for field in [
        "worker",
        "worker_spki_sha256",
        "address",
        "request_id",
        "request_sha256",
        "attempt",
    ] {
        assert_eq!(uncertain[field], running[field], "{field}");
    }
    let retained = fixture.operation(&submit);
    assert_eq!(retained["state"], "queued");
    assert_eq!(retained["worker"], before["worker"]);
    assert!(retained["request_id"].is_null());
    let cancelled = fixture.operation(&["--job-cancel".into(), queued.id.clone()]);
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["execution_may_have_run"], false);
    assert!(!queued.delivery.exists() && !queued.output.exists());
    restarted.terminate();
}

#[test]
fn allocated_cli_jobs_wait_without_ids_and_survive_the_waiting_client() {
    let fixture = Fixture::new();
    let blocker = fixture.prepare(1, false);
    let mut daemon = fixture.daemon();
    fixture.operation(&fixture.submission(&blocker));
    fixture.wait_for(&blocker, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });

    let (job, mut client) = fixture.start_allocated_build(101);
    let queued = fixture.wait_for_submission(&job, &mut client);
    assert_eq!(queued["state"], "queued");
    assert!(queued["request_id"].is_null());
    assert_eq!(queued["execution_may_have_run"], false);
    let template = fs::read(job.bundle.join("request.json")).unwrap();
    let intent: Value = serde_json::from_slice(&template).unwrap();
    assert_eq!(intent["request_id"], "allocate");
    assert!(!job.delivery.exists());
    assert!(!job.output.exists());

    client.crash();
    assert_eq!(fixture.status(&job)["state"], "queued");
    let mut retained_submission = fixture.submission(&job);
    retained_submission[0] = "--job-submit-allocated".into();
    let confirmed = fixture.operation(&retained_submission);
    assert_eq!(confirmed["state"], "queued");
    assert_eq!(confirmed["request_sha256"], queued["request_sha256"]);
    assert!(confirmed["request_id"].is_null());
    fixture.operation(&["--job-cancel".into(), blocker.id.clone()]);
    let running = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    assert!(running["request_id"].as_u64().is_some_and(|id| id > 1));
    assert_eq!(running["request_sha256"], queued["request_sha256"]);
    assert_eq!(fs::read(job.bundle.join("request.json")).unwrap(), template);
    let confirmed = fixture.operation(&retained_submission);
    assert_eq!(confirmed["state"], "running");
    assert_eq!(confirmed["request_id"], running["request_id"]);
    assert_eq!(confirmed["attempt"], running["attempt"]);

    fixture.operation(&["--job-cancel".into(), job.id.clone()]);
    let cancelled = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "cancelled"
    });
    assert_eq!(cancelled["request_id"], running["request_id"]);
    assert_eq!(cancelled["execution_may_have_run"], false);
    assert_eq!(cancelled["outputs_installed"], false);
    let mut command = fixture.command();
    command.args(["--job-wait", &job.id, "5"]);
    let mut wait = Process::spawn(fixture.owner.path(), "allocated-wait", &mut command);
    assert_eq!(wait.wait(Duration::from_secs(10)).code(), Some(130));
    assert!(read_log(&wait.stdout).is_empty());
    assert!(!job.delivery.exists());
    assert!(!job.output.exists());
    daemon.terminate();
}

#[test]
fn allocated_cli_job_keeps_its_bound_request_after_daemon_restart() {
    let fixture = Fixture::new();
    let mut daemon = fixture.daemon();
    let (job, mut client) = fixture.start_allocated_build(102);
    fixture.wait_for_submission(&job, &mut client);
    let running = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    assert!(running["request_id"].as_u64().is_some_and(|id| id > 0));
    let template = fs::read(job.bundle.join("request.json")).unwrap();
    daemon.crash();
    assert!(!client.wait(Duration::from_secs(15)).success());
    assert!(read_log(&client.stdout).is_empty());

    let mut restarted = fixture.daemon();
    let recovered = fixture.status(&job);
    assert_eq!(recovered["state"], "uncertain");
    assert_eq!(recovered["execution_may_have_run"], true);
    assert_eq!(recovered["request_id"], running["request_id"]);
    assert_eq!(recovered["request_sha256"], running["request_sha256"]);
    assert_eq!(recovered["attempt"], running["attempt"]);
    assert_eq!(fs::read(job.bundle.join("request.json")).unwrap(), template);
    let mut command = fixture.command();
    command.args(["--job-wait", &job.id, "5"]);
    let mut wait = Process::spawn(
        fixture.owner.path(),
        "uncertain-allocated-wait",
        &mut command,
    );
    assert!(!wait.wait(Duration::from_secs(10)).success());
    assert!(read_log(&wait.stdout).is_empty());
    let after_wait = fixture.status(&job);
    assert_eq!(after_wait["state"], "uncertain");
    assert_eq!(after_wait["request_id"], recovered["request_id"]);
    assert_eq!(after_wait["attempt"], recovered["attempt"]);
    assert!(!job.delivery.exists());
    assert!(!job.output.exists());
    restarted.terminate();
}

#[test]
fn queued_cli_operations_bind_identity_and_cancel_without_execution() {
    let fixture = Fixture::new();
    let first = fixture.prepare(1, false);
    let queued = fixture.prepare(2, false);
    let mut daemon = fixture.daemon();
    fixture.operation(&fixture.submission(&first));
    let running = fixture.wait_for(&first, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    let duplicate = fixture.operation(&fixture.submission(&first));
    assert_eq!(duplicate["request_sha256"], running["request_sha256"]);
    assert_eq!(duplicate["id"], first.id);
    assert_eq!(duplicate["state"], "running");

    let accepted = fixture.operation(&fixture.submission(&queued));
    assert_eq!(
        accepted["state"], "queued",
        "the first operation owns this worker"
    );
    assert_eq!(accepted["execution_may_have_run"], false);
    let request_path = queued.bundle.join("request.json");
    let original = fs::read(&request_path).unwrap();
    let mut changed: Value = serde_json::from_slice(&original).unwrap();
    changed["args"] = json!(["different-command"]);
    fs::write(&request_path, serde_json::to_vec(&changed).unwrap()).unwrap();
    let (status, refusal) = fixture.cli(&fixture.submission(&queued));
    assert!(!status.success());
    assert_eq!(refusal["kind"], "prepared-operation-error");
    assert_eq!(refusal["reexecute"], false);
    assert_eq!(
        fixture.status(&queued)["request_sha256"],
        accepted["request_sha256"]
    );
    fs::write(&request_path, original).unwrap();

    let cancelled = fixture.operation(&["--job-cancel".into(), queued.id.clone()]);
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["execution_may_have_run"], false);
    assert!(cancelled["listen_address"].is_null());
    assert!(!queued.delivery.exists());
    assert!(!queued.output.exists());
    assert_eq!(
        fixture.operation(&fixture.submission(&queued))["state"],
        "cancelled"
    );

    fixture.operation(&["--job-cancel".into(), first.id.clone()]);
    let stopped = fixture.wait_for(&first, Duration::from_secs(15), |status| {
        !matches!(
            status["state"].as_str(),
            Some("queued" | "running" | "cancelling")
        )
    });
    assert_eq!(stopped["state"], "cancelled", "no canonical-exec was sent");
    assert_eq!(stopped["execution_may_have_run"], false);
    assert!(!first.delivery.exists());
    assert!(!first.output.exists());
    daemon.terminate();
}

#[test]
fn killed_daemon_preserves_uncertainty_and_never_redispatches_on_restart() {
    let fixture = Fixture::new();
    let job = fixture.prepare(3, false);
    let mut daemon = fixture.daemon();
    fixture.operation(&fixture.submission(&job));
    let before = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    let original_address: std::net::SocketAddr =
        before["listen_address"].as_str().unwrap().parse().unwrap();
    assert_ne!(original_address.port(), 0);
    daemon.crash();
    let mut restarted = fixture.daemon();
    let recovered = fixture.status(&job);
    assert_eq!(recovered["state"], "uncertain");
    assert_eq!(recovered["execution_may_have_run"], true);
    assert_eq!(recovered["request_sha256"], before["request_sha256"]);
    assert_eq!(
        fixture.operation(&fixture.submission(&job))["state"],
        "uncertain"
    );
    let until = Instant::now() + Duration::from_millis(500);
    while Instant::now() < until {
        let status = fixture.status(&job);
        assert_eq!(status["state"], "uncertain");
        assert_eq!(status["request_sha256"], before["request_sha256"]);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!job.delivery.exists());
    assert!(!job.output.exists());

    // Recovery requires an explicit retrieval-only attempt with a new delivery
    // directory. Cancelling that attempt cannot clear the old execution doubt.
    let resumed_delivery = fixture.owner.path().join("resumed-delivery");
    let resumed = fixture.operation(&[
        "--job-resume".into(),
        job.id.clone(),
        resumed_delivery.to_str().unwrap().into(),
    ]);
    assert_eq!(resumed["mode"], "resume");
    assert_eq!(resumed["request_sha256"], before["request_sha256"]);
    assert_eq!(resumed["execution_may_have_run"], true);
    let resumed_running = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    assert_eq!(
        resumed_running["listen_address"], before["listen_address"],
        "the worker reconnects to its original endpoint after daemon recovery"
    );
    fixture.operation(&["--job-cancel".into(), job.id.clone()]);
    let cancelled_resume = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "uncertain"
    });
    assert_eq!(cancelled_resume["mode"], "resume");
    assert_eq!(cancelled_resume["execution_may_have_run"], true);
    assert_eq!(cancelled_resume["request_sha256"], before["request_sha256"]);
    assert!(!job.delivery.exists());
    assert!(!resumed_delivery.exists());
    assert!(!job.output.exists());
    restarted.terminate();
}

#[test]
#[ignore = "requires canonical-capable Linux and matching RABS_TEST_WORKER_BIN; runs the actual worker and installed rustc"]
fn daemon_prepared_job_compiles_over_native_tls_and_reuses_the_verified_completion() {
    native_tls_prepared_job(false);
}

#[test]
#[ignore = "requires canonical-capable Linux and matching RABS_TEST_WORKER_BIN; runs the actual worker and installed rustc"]
fn daemon_allocated_job_compiles_over_native_tls_and_reuses_the_verified_completion() {
    native_tls_prepared_job(true);
}

fn native_tls_prepared_job(allocated: bool) {
    let missing =
        rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical();
    assert!(
        missing.is_empty(),
        "canonical isolation is required: {missing:?}"
    );
    let worker = PathBuf::from(
        std::env::var_os("RABS_TEST_WORKER_BIN").expect("matching rabs-wkr executable"),
    );
    assert!(worker.is_absolute() && worker.is_file());
    let fixture = Fixture::new();
    let job = fixture.prepare_with_allocation(4, true, allocated);
    let request = fs::read(job.bundle.join("request.json")).unwrap();
    let mut submission = fixture.submission(&job);
    if allocated {
        submission[0] = "--job-submit-allocated".into();
        assert_eq!(
            serde_json::from_slice::<Value>(&request).unwrap()["request_id"],
            "allocate"
        );
    }
    let mut daemon = fixture.daemon();
    fixture.operation(&submission);
    let running = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    let mut cmd = command(worker);
    cmd.args([
        "--coordinator",
        running["listen_address"].as_str().unwrap(),
        "--worker-id",
        &job.worker,
        "--once",
    ])
    .env(
        "RABS_WORKER_STATE_DIR",
        fixture.owner.path().join("worker-state"),
    )
    .env("RABS_WORKER_TLS_CA", &fixture.certificates.worker.ca)
    .env(
        "RABS_WORKER_TLS_CERT",
        &fixture.certificates.worker.certificate,
    )
    .env(
        "RABS_WORKER_TLS_KEY",
        &fixture.certificates.worker.private_key,
    )
    .env("RABS_WORKER_TLS_SERVER_NAME", "localhost");
    let mut worker = Process::spawn(fixture.owner.path(), "native-worker", &mut cmd);
    let completed = fixture.wait_for(&job, Duration::from_secs(180), |status| {
        !matches!(
            status["state"].as_str(),
            Some("queued" | "running" | "cancelling")
        )
    });
    assert_eq!(completed["state"], "completed", "{completed}");
    assert_eq!(completed["exit_code"], 0);
    assert!(completed["stop_reason"].is_null());
    assert_eq!(completed["acknowledgments_confirmed"], true);
    assert!(
        worker.wait(Duration::from_secs(15)).success(),
        "{}",
        String::from_utf8_lossy(&read_log(&worker.stderr))
    );
    let artifact = fs::read(job.output.join("libprepared_fixture.rmeta")).unwrap();
    assert!(!artifact.is_empty());
    let receipt = fs::read(job.delivery.join("delivery.json")).unwrap();
    let verified: Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(verified["transport_authenticated"], true);
    assert_eq!(verified["worker_spki_sha256"], fixture.certificates.pin());
    assert_eq!(verified["request_id"], running["request_id"]);
    assert_eq!(completed["request_id"], running["request_id"]);
    assert_eq!(fixture.operation(&submission)["state"], "completed");
    daemon.terminate();
    let mut restarted = fixture.daemon();
    assert_eq!(fixture.status(&job)["state"], "completed");
    assert_eq!(fixture.operation(&submission)["state"], "completed");
    assert_eq!(fs::read(job.bundle.join("request.json")).unwrap(), request);
    assert_eq!(
        fs::read(job.delivery.join("delivery.json")).unwrap(),
        receipt
    );
    assert_eq!(
        fs::read(job.output.join("libprepared_fixture.rmeta")).unwrap(),
        artifact
    );
    restarted.terminate();
}
