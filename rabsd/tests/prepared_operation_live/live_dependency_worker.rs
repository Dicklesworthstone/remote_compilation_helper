//! The actual live wrapper, edge daemon and authenticated dependency worker.
//!
//! Run after building all three binaries on Linux with usable bubblewrap,
//! unprivileged user namespaces and OpenSSL:
//!
//!     cargo build -p rabsd -p rabs-wkr -p rabs-wrap
//!     RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
//!       RABS_TEST_WRAP_BIN="$PWD/target/debug/rabs-wrap" \
//!       cargo test -p rabsd --test prepared_operation_live \
//!       live_wrapper_remote_leaf_matches_stock_and_samples_replay \
//!       -- --ignored --nocapture
//!
//! Every compiler result is compared with stock rustc using exactly the same
//! source, argv, output spelling and environment. Durable worker receipts and
//! daemon decisions distinguish real remote production from sampled replay.

use super::*;
use std::net::TcpListener;

const WORKER_ID: &str = "live-dependency-worker";
const PACKAGE_NAME: &str = "remote_leaf";
const SUFFIX: &str = "-remoteleaf0000c0ffee";
const FLAVOR: &str = "spaces \"quotes\" $HOME\n雪";

struct Run {
    events: Vec<Value>,
    metadata: Vec<u8>,
}

impl Run {
    fn remote_key(&self) -> Option<&str> {
        let completed: Vec<_> = self
            .events
            .iter()
            .filter(|event| event["kind"] == "rabsd-remote-dependency-executed")
            .collect();
        assert!(
            completed.len() <= 1,
            "one wrapper invocation executed multiple remote actions: {:?}",
            self.events
        );
        completed.first().and_then(|event| event["key"].as_str())
    }

    fn assert_remote(&self, expected_key: Option<&str>) -> &str {
        let key = self
            .remote_key()
            .unwrap_or_else(|| panic!("missing real remote result: {:?}", self.events));
        if let Some(expected) = expected_key {
            assert_eq!(
                key, expected,
                "identical clean-target invocation split the remote action key"
            );
        }
        assert!(
            self.events
                .iter()
                .any(|event| event["kind"] == "rabsd-live-dependency"
                    && event["decision"] == "remote-offer"
                    && event["key"].as_str() == Some(key))
        );
        assert!(
            !self
                .events
                .iter()
                .any(|event| event["kind"] == "rabsd-live-dependency"
                    && matches!(
                        event["decision"].as_str(),
                        Some("execute" | "hit" | "served")
                    )),
            "a current remote producer must complete without an additional local execution or cache hit: {:?}",
            self.events
        );
        key
    }

    fn assert_hit(&self, key: &str) {
        assert!(
            self.remote_key().is_none(),
            "cache replay dispatched a remote worker"
        );
        let decisions: Vec<_> = self
            .events
            .iter()
            .filter(|event| event["kind"] == "rabsd-live-dependency")
            .filter_map(|event| event["decision"].as_str())
            .filter(|decision| *decision != "shadow")
            .collect();
        assert_eq!(decisions, ["hit", "served"], "{:?}", self.events);
        assert!(
            self.events
                .iter()
                .filter(|event| event["kind"] == "rabsd-live-dependency")
                .all(|event| event["key"].as_str().is_none_or(|value| value == key))
        );
    }
}

// Drop children before their storage owner even if an assertion fails.
struct LiveFixture {
    workers: Vec<LiveWorker>,
    daemon: Process,
    fixture: Fixture,
    wrapper: PathBuf,
    compiler: PathBuf,
    package: PathBuf,
    output: PathBuf,
    sequence: Cell<u64>,
}

struct LiveWorker {
    process: Process,
    state: PathBuf,
}

fn additional_worker_credentials(fixture: &Fixture, index: usize) -> TlsFiles {
    let root = fixture
        .owner
        .path()
        .join(format!("worker-credentials-{index}"));
    fs::create_dir(&root).unwrap();
    let run = |name: &str, args: &[&str]| {
        let mut command = command("openssl");
        command.current_dir(&root).args(args);
        let mut process = Process::spawn(&root, name, &mut command);
        assert!(
            process.wait(Duration::from_secs(20)).success(),
            "{}",
            String::from_utf8_lossy(&read_log(&process.stderr))
        );
    };
    run(
        "request",
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
            "worker.key",
            "-out",
            "worker.csr",
        ],
    );
    fs::write(
        root.join("worker.ext"),
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:localhost\n",
    )
    .unwrap();
    let ca = &fixture.certificates.worker.ca;
    let key = ca.with_file_name("ca.key");
    run(
        "sign",
        &[
            "x509",
            "-req",
            "-in",
            "worker.csr",
            "-CA",
            ca.to_str().unwrap(),
            "-CAkey",
            key.to_str().unwrap(),
            "-set_serial",
            &(index + 10).to_string(),
            "-days",
            "1",
            "-sha256",
            "-extfile",
            "worker.ext",
            "-out",
            "worker.pem",
        ],
    );
    TlsFiles {
        ca: ca.clone(),
        certificate: root.join("worker.pem"),
        private_key: root.join("worker.key"),
    }
}

impl LiveFixture {
    fn new() -> Self {
        Self::with_worker_count(1)
    }

    fn with_worker_count(worker_count: usize) -> Self {
        assert!((1..=2).contains(&worker_count));
        let missing = rabs_sandbox::canonical_namespace::HostIsolationSupport::probe()
            .missing_for_canonical();
        assert!(
            missing.is_empty(),
            "real dependency isolation is required: {missing:?}"
        );
        let binary = |name: &str| {
            let path =
                PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")));
            assert!(
                path.is_absolute() && path.is_file(),
                "{name} must be an absolute matching executable"
            );
            path
        };
        let worker_binary = binary("RABS_TEST_WORKER_BIN");
        let wrapper = binary("RABS_TEST_WRAP_BIN");
        let cargo =
            fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
        let toolchain = cargo.parent().and_then(Path::parent).unwrap();
        let compiler = toolchain.join("bin/rustc");
        assert_eq!(
            fs::canonicalize(&compiler).unwrap(),
            compiler,
            "use the installed rustc, not a rustup proxy or compiler symlink"
        );
        let fixture = Fixture::new();
        let package = fixture
            .owner
            .path()
            .join("cargo-home/registry/src/index.example-0123456789abcdef/remote_leaf-1.0.0");
        fs::create_dir_all(package.join("src")).unwrap();
        fs::write(
            package.join("Cargo.toml"),
            "[package]\nname=\"remote_leaf\"\nversion=\"1.0.0\"\nedition=\"2024\"\n",
        )
        .unwrap();
        fs::write(package.join(".cargo-ok"), "{\"v\":1}").unwrap();
        fs::write(
            package.join("src/lib.rs"),
            br#"pub const FLAVOR: &str = env!("DEPENDENCY_FLAVOR");
pub const JOBS: Option<&str> = option_env!("NUM_JOBS");
pub const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");
pub const HERE: &str = file!();
pub const INCLUDED: &str = include_str!("message.txt");
"#,
        )
        .unwrap();
        fs::write(
            package.join("src/message.txt"),
            b"exact retained dependency input\n",
        )
        .unwrap();
        let output = fixture.owner.path().join("consumer/target/debug/deps");
        fs::create_dir_all(&output).unwrap();

        // The real transport binds for each accepted action. Reserve a loopback
        // address long enough to select it, then let the daemon own each listen;
        // a bind conflict is a test failure, never a connection to another peer.
        let reserved: Vec<_> = (0..worker_count)
            .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let addresses: Vec<_> = reserved
            .iter()
            .map(|listener| listener.local_addr().unwrap().to_string())
            .collect();
        let credentials: Vec<_> = (0..worker_count)
            .map(|index| {
                if index == 0 {
                    fixture.certificates.worker.clone()
                } else {
                    additional_worker_credentials(&fixture, index)
                }
            })
            .collect();
        let mut remote_env = vec![("RABS_LIVE_DEPENDENCY".to_owned(), "1".to_owned())];
        if worker_count == 1 {
            remote_env.extend([
                ("RABS_DEPENDENCY_WORKER_LISTEN".into(), addresses[0].clone()),
                ("RABS_DEPENDENCY_WORKER_ID".into(), WORKER_ID.into()),
                (
                    "RABS_DEPENDENCY_WORKER_SPKI_SHA256".into(),
                    fixture.certificates.pin(),
                ),
            ]);
        } else {
            let pool: Vec<_> = addresses
                .iter()
                .zip(&credentials)
                .enumerate()
                .map(|(index, (address, tls))| {
                    let pin: String = tls
                        .local_identity()
                        .unwrap()
                        .fingerprint
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    json!({
                        "listen":address, "worker_id":format!("{WORKER_ID}-{index}"),
                        "worker_spki_sha256":pin,
                    })
                })
                .collect();
            remote_env.push((
                "RABS_DEPENDENCY_WORKERS_JSON".into(),
                json!(pool).to_string(),
            ));
        }
        drop(reserved);
        let daemon = fixture.daemon_with_environment(&remote_env);
        let workers = addresses
            .iter()
            .zip(&credentials)
            .enumerate()
            .map(|(index, (address, tls))| {
                let id = if worker_count == 1 {
                    WORKER_ID.to_owned()
                } else {
                    format!("{WORKER_ID}-{index}")
                };
                let state = fixture
                    .owner
                    .path()
                    .join(format!("live-worker-state-{index}"));
                let mut worker_command = command(&worker_binary);
                worker_command
                    .args(["--coordinator", address, "--worker-id", &id])
                    .env("RABS_WORKER_STATE_DIR", &state)
                    .env(
                        "RABS_WORKER_TOOLCHAIN_CACHE_BYTES",
                        rabs_sandbox::toolchain_dataset::ToolchainLimits::default()
                            .max_bytes
                            .to_string(),
                    )
                    .env("RABS_WORKER_TLS_CA", &tls.ca)
                    .env("RABS_WORKER_TLS_CERT", &tls.certificate)
                    .env("RABS_WORKER_TLS_KEY", &tls.private_key)
                    .env("RABS_WORKER_TLS_SERVER_NAME", "localhost");
                // Production workers reconnect with their own persistent
                // identity and retain the compiler dataset between sessions.
                let process = Process::spawn(fixture.owner.path(), &id, &mut worker_command);
                LiveWorker { process, state }
            })
            .collect();
        Self {
            workers,
            daemon,
            fixture,
            wrapper,
            compiler,
            package,
            output,
            sequence: Cell::new(0),
        }
    }

    fn events(&self) -> Vec<Value> {
        String::from_utf8(read_log(&self.daemon.stderr))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect()
    }

    fn environment(&self, flavor: &str) -> Vec<(String, String)> {
        let root = self.fixture.owner.path();
        let toolchain = self.compiler.parent().and_then(Path::parent).unwrap();
        vec![
            ("HOME".into(), root.join("home").display().to_string()),
            (
                "CARGO_HOME".into(),
                root.join("cargo-home").display().to_string(),
            ),
            (
                "CARGO_MANIFEST_DIR".into(),
                self.package.display().to_string(),
            ),
            ("CARGO_PKG_NAME".into(), PACKAGE_NAME.into()),
            ("CARGO_PKG_VERSION".into(), "1.0.0".into()),
            ("CARGO_CRATE_NAME".into(), PACKAGE_NAME.into()),
            ("DEPENDENCY_FLAVOR".into(), flavor.into()),
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            // Cargo searches both deps and its target/debug parent. The parent
            // must be independently observed and privately recreated on worker.
            (
                "LD_LIBRARY_PATH".into(),
                format!(
                    "{}:{}:{}",
                    self.output.display(),
                    self.output.parent().unwrap().display(),
                    toolchain.join("lib").display()
                ),
            ),
            (
                "RABS_SOCKET_PATH".into(),
                root.join("daemon.sock").display().to_string(),
            ),
            (
                "RABS_BREAKER_FILE".into(),
                root.join("wrapper.breaker").display().to_string(),
            ),
            ("RABS_LIVE_DECISION_MS".into(), "30000".into()),
            ("RABS_PREPARATION_WAIT_MS".into(), "180000".into()),
            ("RABS_REMOTE_WAIT_MS".into(), "600000".into()),
            ("RABS_INSTALL_WAIT_MS".into(), "60000".into()),
        ]
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--crate-name".into(),
            PACKAGE_NAME.into(),
            "--edition=2024".into(),
            self.package.join("src/lib.rs").display().to_string(),
            "--error-format=json".into(),
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat".into(),
            "--crate-type".into(),
            "lib".into(),
            "--emit=dep-info,metadata".into(),
            "-C".into(),
            "embed-bitcode=no".into(),
            "-C".into(),
            "debuginfo=2".into(),
            "-C".into(),
            "metadata=remoteleaf0000c0ffee".into(),
            "-C".into(),
            format!("extra-filename={SUFFIX}"),
            "--out-dir".into(),
            self.output.display().to_string(),
            "-L".into(),
            format!("dependency={}", self.output.display()),
            "--cap-lints".into(),
            "allow".into(),
        ]
    }

    fn compile(&self, flavor: &str) -> Run {
        let number = self.sequence.get();
        self.sequence.set(number + 1);
        let root = self.fixture.owner.path();
        // Each invocation sees the same original path and an actually empty
        // target, as after cargo clean. Archives stay outside every loader root.
        fs::rename(&self.output, root.join(format!("prior-target-{number}"))).unwrap();
        fs::create_dir(&self.output).unwrap();
        let env = self.environment(flavor);
        assert!(!env.iter().any(|(name, _)| name == "NUM_JOBS"));
        let args = self.args();
        let mut stock_command = Command::new(&self.compiler);
        stock_command
            .args(&args)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .current_dir(&self.package);
        let mut stock = Process::spawn(root, &format!("stock-{number}"), &mut stock_command);
        assert!(
            stock.wait(Duration::from_secs(90)).success(),
            "{}",
            String::from_utf8_lossy(&read_log(&stock.stderr))
        );
        let expected_stdout = read_log(&stock.stdout);
        let expected_stderr = read_log(&stock.stderr);
        let metadata_name = format!("lib{PACKAGE_NAME}{SUFFIX}.rmeta");
        let dep_info_name = format!("{PACKAGE_NAME}{SUFFIX}.d");
        let metadata = fs::read(self.output.join(&metadata_name)).unwrap();
        let dep_info = fs::read(self.output.join(&dep_info_name)).unwrap();
        assert!(!metadata.is_empty() && !dep_info.is_empty());
        fs::rename(&self.output, root.join(format!("stock-target-{number}"))).unwrap();
        fs::create_dir(&self.output).unwrap();
        let before = self.events().len();
        let mut wrapper_command = Command::new(&self.wrapper);
        wrapper_command
            .arg(&self.compiler)
            .args(&args)
            .env_clear()
            .envs(env.iter().map(|(name, value)| (name, value)))
            .current_dir(&self.package);
        let mut wrapper = Process::spawn(root, &format!("wrapper-{number}"), &mut wrapper_command);
        assert!(
            wrapper.wait(Duration::from_secs(660)).success(),
            "wrapper={}; daemon={}; worker={}",
            String::from_utf8_lossy(&read_log(&wrapper.stderr)),
            String::from_utf8_lossy(&read_log(&self.daemon.stderr)),
            String::from_utf8_lossy(&read_log(&self.workers[0].process.stderr))
        );
        assert_eq!(
            read_log(&wrapper.stdout),
            expected_stdout,
            "compiler stdout changed"
        );
        assert_eq!(
            read_log(&wrapper.stderr),
            expected_stderr,
            "compiler JSON transcript changed"
        );
        assert_eq!(
            fs::read(self.output.join(&metadata_name)).unwrap(),
            metadata,
            "metadata changed"
        );
        assert_eq!(
            fs::read(self.output.join(&dep_info_name)).unwrap(),
            dep_info,
            "dep-info changed"
        );
        let installed: std::collections::BTreeSet<_> = fs::read_dir(&self.output)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            installed,
            std::collections::BTreeSet::from([
                std::ffi::OsString::from(metadata_name),
                std::ffi::OsString::from(dep_info_name),
            ]),
            "installed output set is not exact"
        );

        // Local warmup may publish after its capture receipt. Resolve that one
        // terminal log before another request so the test never splices trails.
        let deadline = Instant::now() + Duration::from_secs(60);
        let events = loop {
            let events = self.events()[before..].to_vec();
            let local = events.iter().any(|event| {
                event["kind"] == "rabsd-live-dependency" && event["decision"] == "execute"
            });
            let settled = events.iter().any(|event| {
                event["kind"] == "rabsd-live-dependency"
                    && matches!(
                        event["decision"].as_str(),
                        Some(
                            "committed" | "verified" | "quarantined" | "not-published" | "refused"
                        )
                    )
            });
            if !local || settled {
                break events;
            }
            assert!(
                Instant::now() < deadline,
                "local warmup did not finish: {events:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            !events.iter().any(|event| matches!(
                event["kind"].as_str(),
                Some("rabsd-remote-dependency-failed" | "rabsd-remote-dependency-install-failed")
            )),
            "remote failure cannot count as an end-to-end success: {events:?}"
        );
        Run { events, metadata }
    }

    fn worker_receipt(&self) -> Value {
        self.worker_receipt_at(0)
    }

    fn worker_receipt_at(&self, index: usize) -> Value {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let bytes = fs::read(self.workers[index].state.join("requests.json")).unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            let last = &value["last"];
            if last["resolved"] == true && last["receipt"]["retained_result_released"] == true {
                assert_eq!(last["receipt"]["executed"], true);
                assert_eq!(last["receipt"]["exit_code"], 0);
                assert_eq!(last["receipt"]["residual_group_members"], 0);
                return last.clone();
            }
            assert!(
                Instant::now() < deadline,
                "worker did not seal and acknowledge its actual result: {value}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
#[ignore = "requires Linux isolation, matching RABS_TEST_WORKER_BIN and RABS_TEST_WRAP_BIN; runs actual wrapper/daemon/worker/rustc"]
fn live_wrapper_remote_leaf_matches_stock_and_samples_replay() {
    let mut live = LiveFixture::new();
    // The fresh daemon must retain the complete compiler dataset and finish
    // this first wrapper invocation on the actual authenticated worker.
    let first = live.compile(FLAVOR);
    let key = first.assert_remote(None).to_owned();
    let pending = first
        .events
        .iter()
        .position(|event| {
            event["kind"] == "rabsd-live-dependency"
                && event["decision"] == "preparing"
                && event["reason"] == "remote-toolchain-pending"
        })
        .unwrap_or_else(|| {
            panic!(
                "cold compiler preparation was not awaited: {:?}",
                first.events
            )
        });
    let executed = first
        .events
        .iter()
        .position(|event| event["kind"] == "rabsd-remote-dependency-executed")
        .expect("assert_remote required a real remote result");
    assert!(
        pending < executed,
        "the first wrapper must await preparation before remote execution: {:?}",
        first.events
    );
    let first_receipt = live.worker_receipt();
    let mut last_request_id = first_receipt["request_id"].as_u64().unwrap();
    // Enrollment requires the normal same-worker verification observations.
    // The current producer's own output is usable on every compile meanwhile.
    for _ in 0..2 {
        let run = live.compile(FLAVOR);
        run.assert_remote(Some(&key));
        assert_eq!(run.metadata, first.metadata);
        let receipt = live.worker_receipt();
        let request_id = receipt["request_id"].as_u64().unwrap();
        assert!(
            request_id > last_request_id,
            "real worker IDs must increase across sessions"
        );
        last_request_id = request_id;
    }
    let enrolled = live.worker_receipt();
    for _ in 0..16 {
        let hit = live.compile(FLAVOR);
        hit.assert_hit(&key);
        assert_eq!(hit.metadata, first.metadata);
        assert_eq!(
            live.worker_receipt(),
            enrolled,
            "a replay admitted another worker execution"
        );
    }
    let verification = live.compile(FLAVOR);
    verification.assert_remote(Some(&key));
    assert_eq!(verification.metadata, first.metadata);
    let sampled = live.worker_receipt();
    assert!(sampled["request_id"].as_u64().unwrap() > last_request_id);
    let renewed = live.compile(FLAVOR);
    renewed.assert_hit(&key);
    assert_eq!(live.worker_receipt(), sampled);

    // A changed compiler-read environment value requires real new production.
    let changed = live.compile("changed dependency flavor");
    assert_ne!(changed.assert_remote(None), key);
    assert_ne!(changed.metadata, first.metadata);
    assert!(
        live.worker_receipt()["request_id"].as_u64().unwrap()
            > sampled["request_id"].as_u64().unwrap()
    );
    live.daemon.terminate();
}

const CARGO_CONSUMER: &str = "cargo_remote_consumer";
const CARGO_MIDDLE: &str = "remote_middle";
const CARGO_TOP: &str = "remote_top";
const CARGO_DEPENDENCIES: [&str; 3] = [PACKAGE_NAME, CARGO_MIDDLE, CARGO_TOP];

struct CargoRun {
    dependencies: std::collections::BTreeMap<String, Run>,
    files: std::collections::BTreeMap<PathBuf, Vec<u8>>,
    diagnostics: Vec<Value>,
}

impl CargoRun {
    fn matches_stock(&self, stock: &Self) {
        assert_eq!(
            self.files, stock.files,
            "actual Cargo changed a dependency or the consumer's metadata/dep-info"
        );
        assert_eq!(
            self.diagnostics, stock.diagnostics,
            "actual Cargo compiler diagnostics changed"
        );
    }

    fn dependency(&self, name: &str) -> &Run {
        self.dependencies
            .get(name)
            .expect("observed Cargo dependency")
    }
}

/// Admission records name the crate; completion and installation records carry
/// only the action key. A different DAG node's terminal event proves nothing
/// about this crate, even when both were compiled in the same Cargo process.
fn cargo_dependency_events(current: &[Value], name: &str) -> Vec<Value> {
    let keys: std::collections::BTreeSet<_> = current
        .iter()
        .filter(|event| event["kind"] == "rabsd-live-dependency" && event["crate"] == name)
        .filter_map(|event| event["key"].as_str())
        .collect();
    current
        .iter()
        .filter(|event| {
            let matching_key = event["key"].as_str().is_some_and(|key| keys.contains(key));
            (event["kind"] == "rabsd-live-dependency" && (event["crate"] == name || matching_key))
                || (matching_key
                    && matches!(
                        event["kind"].as_str(),
                        Some(
                            "rabsd-remote-dependency-executed"
                                | "rabsd-remote-dependency-failed"
                                | "rabsd-remote-dependency-install-failed"
                        )
                    ))
        })
        .cloned()
        .collect()
}

/// Cold package/toolchain observations may outlast one wrapper preparation
/// deadline. Permit only these explicit preparation states before the first
/// remote result; a real remote shape refusal is never excused by an earlier
/// warming event from the same invocation.
fn cargo_dependency_warming(events: &[Value]) -> bool {
    if events.iter().any(|event| {
        event["decision"] == "remote-ineligible"
            && !event["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("warming"))
    }) {
        return false;
    }
    events.iter().any(|event| {
        (event["decision"] == "remote-ineligible"
            && event["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("warming")))
            || event["decision"] == "toolchain-warming"
            || (event["decision"] == "preparing"
                && matches!(
                    event["reason"].as_str(),
                    Some(
                        "toolchain-facts-pending"
                            | "package-facts-pending"
                            | "dependency-facts-pending"
                            | "remote-toolchain-pending"
                    )
                ))
    })
}

#[test]
fn cargo_dependency_events_bind_terminal_records_to_each_crate() {
    let events = vec![
        json!({"kind":"rabsd-live-dependency", "crate":PACKAGE_NAME,
            "decision":"remote-offer", "key":"leaf-key"}),
        json!({"kind":"rabsd-live-dependency", "crate":CARGO_MIDDLE,
            "decision":"remote-offer", "key":"middle-key"}),
        json!({"kind":"rabsd-remote-dependency-executed", "key":"leaf-key"}),
        json!({"kind":"rabsd-remote-dependency-failed", "key":"middle-key"}),
        json!({"kind":"rabsd-remote-dependency-executed", "key":"unrelated-key"}),
        json!({"kind":"rabsd-remote-dependency-install-failed"}),
    ];
    let leaf = cargo_dependency_events(&events, PACKAGE_NAME);
    assert_eq!(leaf, [events[0].clone(), events[2].clone()]);
    let middle = cargo_dependency_events(&events, CARGO_MIDDLE);
    assert_eq!(middle, [events[1].clone(), events[3].clone()]);
    assert!(cargo_dependency_events(&events, CARGO_TOP).is_empty());
    for reason in ["dependency-facts-pending", "remote-toolchain-pending"] {
        let preparing = json!({"decision":"preparing", "reason":reason});
        assert!(cargo_dependency_warming(std::slice::from_ref(&preparing)));
        assert!(!cargo_dependency_warming(&[
            preparing,
            json!({"decision":"remote-ineligible", "reason":"REMOTE_DEP_NATIVE_INPUTS"}),
        ]));
    }
    assert!(!cargo_dependency_warming(&[
        json!({"decision":"preparing", "reason":"unknown-facts"}),
    ]));
}

impl LiveFixture {
    fn prepare_cargo_consumer(&mut self) {
        let root = self.fixture.owner.path();
        let vendor = root.join("vendor");
        fs::create_dir(&vendor).unwrap();
        let package = vendor.join("remote_leaf-1.0.0");
        fs::rename(&self.package, &package).unwrap();
        self.package = package;
        // Preserve the leaf's environment/path-sensitive source and add a type
        // that the top crate must resolve through middle's metadata.
        let mut leaf = fs::read_to_string(self.package.join("src/lib.rs")).unwrap();
        leaf.push_str("\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\n");
        leaf.push_str("pub struct RemoteToken(pub u32);\n");
        fs::write(self.package.join("src/lib.rs"), leaf).unwrap();

        // The same valid offline directory-source setup is exercised by
        // rabs-wrap/tests/live_cargo_worktrees.rs. The empty checksum map is not
        // a source identity: the daemon still retains every package file.
        fs::write(
            self.package.join(".cargo-checksum.json"),
            "{\"files\":{}}\n",
        )
        .unwrap();
        for (name, dependency, source) in [
            (
                CARGO_MIDDLE,
                PACKAGE_NAME,
                "pub use remote_leaf::{FLAVOR, JOBS, MANIFEST, HERE, INCLUDED, RemoteToken};\n\
                 pub fn token() -> RemoteToken { RemoteToken(73) }\n",
            ),
            (
                CARGO_TOP,
                CARGO_MIDDLE,
                "pub use remote_middle::{FLAVOR, JOBS, MANIFEST, HERE, INCLUDED};\n\
                 pub fn transitive_value() -> u32 {\n\
                     let value = remote_middle::RemoteToken(73);\n\
                     value.0 + remote_middle::token().0\n\
                 }\n",
            ),
        ] {
            let package = vendor.join(format!("{name}-1.0.0"));
            fs::create_dir_all(package.join("src")).unwrap();
            fs::write(
                package.join("Cargo.toml"),
                format!(
                    "[package]\nname='{name}'\nversion='1.0.0'\nedition='2024'\n\
                     [dependencies]\n{dependency}='=1.0.0'\n"
                ),
            )
            .unwrap();
            fs::write(package.join(".cargo-checksum.json"), "{\"files\":{}}\n").unwrap();
            fs::write(package.join("src/lib.rs"), source).unwrap();
        }
        fs::create_dir_all(root.join("home")).unwrap();
        fs::write(
            root.join("cargo-home/config.toml"),
            format!(
                "[source.crates-io]\nreplace-with='fixture'\n\
                 [source.fixture]\ndirectory={}\n[net]\noffline=true\n",
                serde_json::to_string(vendor.to_str().unwrap()).unwrap()
            ),
        )
        .unwrap();
        let consumer = root.join("consumer");
        fs::create_dir_all(consumer.join("src")).unwrap();
        fs::write(
            consumer.join("Cargo.toml"),
            format!(
                "[package]\nname='{CARGO_CONSUMER}'\nversion='0.1.0'\nedition='2024'\n\
                 [dependencies]\n{CARGO_TOP}='=1.0.0'\n"
            ),
        )
        .unwrap();
        fs::write(
            consumer.join("src/lib.rs"),
            b"pub const FLAVOR: &str = remote_top::FLAVOR;\n\
              pub const JOBS: Option<&str> = remote_top::JOBS;\n\
              pub const MANIFEST: &str = remote_top::MANIFEST;\n\
              pub const HERE: &str = remote_top::HERE;\n\
              pub const INCLUDED: &str = remote_top::INCLUDED;\n\
              const _: [(); remote_top::INCLUDED.len()] = [(); 32];\n\
              pub fn transitive_value() -> u32 { remote_top::transitive_value() }\n",
        )
        .unwrap();
    }

    fn cargo_check(&self, wrapped: bool) -> CargoRun {
        let number = self.sequence.get();
        self.sequence.set(number + 1);
        let root = self.fixture.owner.path();
        let target = root.join("consumer/target");
        // Recreate the whole target so Cargo must schedule every DAG node again.
        // Keep original paths, sources and lockfile fixed; archives are outside
        // every target/loader root, including Cargo's per-unit layouts.
        fs::rename(&target, root.join(format!("cargo-target-{number}"))).unwrap();
        fs::create_dir(&target).unwrap();
        let toolchain = self.compiler.parent().and_then(Path::parent).unwrap();
        let mut cargo = Command::new(toolchain.join("bin/cargo"));
        cargo
            .current_dir(root.join("consumer"))
            .args(["check", "--offline", "--jobs=1", "--message-format=json"])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", root.join("home"))
            .env("CARGO_HOME", root.join("cargo-home"))
            .env("CARGO_TARGET_DIR", &target)
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TERM_COLOR", "never")
            .env("LANG", "C.UTF-8")
            .env("DEPENDENCY_FLAVOR", FLAVOR)
            .env("LD_LIBRARY_PATH", toolchain.join("lib"))
            // Invoke installed Cargo with its matching compiler, independently
            // of any rustup shim in the test runner's inherited PATH.
            .env("RUSTC", &self.compiler);
        for (name, value) in self.environment(FLAVOR) {
            if name.starts_with("RABS_") {
                cargo.env(name, value);
            }
        }
        if wrapped {
            cargo.env("RUSTC_WRAPPER", &self.wrapper);
        }
        let before = self.events().len();
        let mut process = Process::spawn(root, &format!("actual-cargo-{number}"), &mut cargo);
        assert!(
            process.wait(Duration::from_secs(660)).success(),
            "cargo={}; daemon={}; worker={}",
            String::from_utf8_lossy(&read_log(&process.stderr)),
            String::from_utf8_lossy(&read_log(&self.daemon.stderr)),
            String::from_utf8_lossy(&read_log(&self.workers[0].process.stderr))
        );
        let messages: Vec<Value> = String::from_utf8(read_log(&process.stdout))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("actual Cargo JSON message"))
            .collect();
        let finished: Vec<_> = messages
            .iter()
            .filter(|message| message["reason"] == "build-finished")
            .collect();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["success"], true);

        // Follow Cargo's artifact JSON instead of guessing target/debug/deps:
        // newer Cargo also uses target/debug/build/<crate>/<unit>/out.
        let mut files = std::collections::BTreeMap::new();
        let mut metadata_by_crate = std::collections::BTreeMap::new();
        for name in [PACKAGE_NAME, CARGO_MIDDLE, CARGO_TOP, CARGO_CONSUMER] {
            let artifacts: Vec<_> = messages
                .iter()
                .filter(|message| {
                    message["reason"] == "compiler-artifact" && message["target"]["name"] == name
                })
                .collect();
            assert_eq!(
                artifacts.len(),
                1,
                "missing actual Cargo artifact for {name}"
            );
            assert_eq!(
                artifacts[0]["fresh"], false,
                "the clean target must schedule {name}, not Cargo's own fresh reuse"
            );
            let metadata: Vec<_> = artifacts[0]["filenames"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "rmeta")
                })
                .collect();
            assert_eq!(metadata.len(), 1);
            let metadata = &metadata[0];
            let stem = metadata
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .and_then(|name| name.strip_prefix("lib"))
                .and_then(|name| name.strip_suffix(".rmeta"))
                .expect("Cargo's real library metadata filename");
            let dep_info = metadata.with_file_name(format!("{stem}.d"));
            for path in [metadata, &dep_info] {
                let bytes = fs::read(path).unwrap();
                assert!(!bytes.is_empty(), "empty actual compiler output: {path:?}");
                if CARGO_DEPENDENCIES.contains(&name) && path == metadata {
                    assert!(
                        metadata_by_crate
                            .insert(name.to_owned(), bytes.clone())
                            .is_none()
                    );
                }
                let relative = path
                    .strip_prefix(&target)
                    .expect("Cargo output belongs to its configured target")
                    .to_path_buf();
                assert!(files.insert(relative, bytes).is_none());
            }
        }
        assert_eq!(files.len(), 8);
        assert_eq!(metadata_by_crate.len(), CARGO_DEPENDENCIES.len());
        let diagnostics = messages
            .into_iter()
            .filter(|message| message["reason"] == "compiler-message")
            .collect();

        let deadline = Instant::now() + Duration::from_secs(60);
        let dependencies = loop {
            let all_events = self.events();
            let current = &all_events[before..];
            let mut pending = false;
            let mut dependencies = std::collections::BTreeMap::new();
            for name in CARGO_DEPENDENCIES {
                let events = cargo_dependency_events(current, name);
                let local = events.iter().any(|event| event["decision"] == "execute");
                let settled = events.iter().any(|event| {
                    matches!(
                        event["decision"].as_str(),
                        Some(
                            "committed" | "verified" | "quarantined" | "not-published" | "refused"
                        )
                    )
                });
                pending |= local && !settled;
                assert!(
                    !events.iter().any(|event| matches!(
                        event["kind"].as_str(),
                        Some(
                            "rabsd-remote-dependency-failed"
                                | "rabsd-remote-dependency-install-failed"
                        )
                    )),
                    "actual Cargo remote failure for {name} is not a successful oracle: {events:?}"
                );
                dependencies.insert(
                    name.to_owned(),
                    Run {
                        events,
                        metadata: metadata_by_crate[name].clone(),
                    },
                );
            }
            if !pending {
                break dependencies;
            }
            assert!(
                Instant::now() < deadline,
                "Cargo dependency publications did not settle"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        CargoRun {
            dependencies,
            files,
            diagnostics,
        }
    }
}

/// Run with the same prebuilt worker/wrapper prerequisites as the first oracle:
///
///     cargo test -p rabsd --test prepared_operation_live \
///       actual_offline_cargo_check_uses_remote_dependency_dag_then_replays \
///       -- --ignored --nocapture
///
/// Actual Cargo chooses argv, cwd, jobserver and loader environment. The graph
/// is leaf -> middle -> top -> consumer; top has no direct leaf dependency but
/// must resolve leaf's RemoteToken through middle's metadata. This fixture
/// supports shared or disjoint input/output directories under dependency-exec-v6,
/// never treats local fallback as evidence of a working remote DAG, and performs
/// no argv rewriting.
#[test]
#[ignore = "requires Linux isolation and matching RABS_TEST_WORKER_BIN/RABS_TEST_WRAP_BIN; actual offline Cargo dependency DAG plus daemon/worker"]
fn actual_offline_cargo_check_uses_remote_dependency_dag_then_replays() {
    let mut live = LiveFixture::new();
    live.prepare_cargo_consumer();
    let stock = live.cargo_check(false);
    assert!(stock.dependencies.values().all(|run| run.events.is_empty()));

    let until = Instant::now() + Duration::from_secs(1200);
    let mut observations: std::collections::BTreeMap<String, (String, usize)> =
        std::collections::BTreeMap::new();
    let mut receipt: Option<Value> = None;
    loop {
        let run = live.cargo_check(true);
        run.matches_stock(&stock);
        let mut remote_count = 0;
        let mut all_hit = true;
        for name in CARGO_DEPENDENCIES {
            let dependency = run.dependency(name);
            assert_eq!(dependency.metadata, stock.dependency(name).metadata);
            if dependency.remote_key().is_some() {
                all_hit = false;
                remote_count += 1_u64;
                let previous = observations.get(name).map(|(key, _)| key.as_str());
                let key = dependency.assert_remote(previous).to_owned();
                let observation = observations.entry(name.to_owned()).or_insert((key, 0));
                observation.1 += 1;
            } else if let Some((key, productions)) = observations.get(name) {
                dependency.assert_hit(key);
                assert!(
                    *productions >= 3,
                    "{name} was served before three actual remote qualification observations"
                );
            } else {
                all_hit = false;
                assert!(
                    cargo_dependency_warming(&dependency.events),
                    "{name} never reached remote admission; a local Cargo fallback does not prove the DAG: {:?}",
                    dependency.events
                );
            }
        }
        if remote_count != 0 {
            let next = live.worker_receipt();
            if let Some(previous) = &receipt {
                assert!(
                    next["request_id"].as_u64().unwrap()
                        >= previous["request_id"].as_u64().unwrap() + remote_count,
                    "each remote DAG production must advance the real worker's durable receipt"
                );
            }
            receipt = Some(next);
        } else if let Some(previous) = &receipt {
            assert_eq!(
                live.worker_receipt(),
                *previous,
                "cache replay unexpectedly executed a worker"
            );
        }
        if all_hit {
            assert_eq!(observations.len(), CARGO_DEPENDENCIES.len());
            let keys: std::collections::BTreeSet<_> =
                observations.values().map(|(key, _)| key.as_str()).collect();
            assert_eq!(
                keys.len(),
                CARGO_DEPENDENCIES.len(),
                "different DAG nodes must have distinct action identities"
            );
            assert!(receipt.is_some(), "no actual worker ever executed this DAG");
            break;
        }
        assert!(
            Instant::now() < until,
            "actual Cargo DAG never reached qualified replay: {observations:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    live.daemon.terminate();
}

struct FleetClient {
    dependency: &'static str,
    root: PathBuf,
}

struct FleetCargo {
    process: Process,
    events_start: usize,
}

struct FleetResult {
    action: Run,
    outputs: std::collections::BTreeMap<PathBuf, Vec<u8>>,
    diagnostics: Vec<Value>,
}

impl FleetResult {
    fn matches_stock(&self, stock: &Self) {
        assert_eq!(
            self.outputs, stock.outputs,
            "fleet outputs differ from stock Cargo"
        );
        assert_eq!(
            self.diagnostics, stock.diagnostics,
            "fleet diagnostics differ from stock Cargo"
        );
    }
}

impl FleetClient {
    fn prepare(live: &LiveFixture) -> [Self; 2] {
        let root = live.fixture.owner.path();
        let vendor = root.join("fleet-vendor");
        fs::create_dir(&vendor).unwrap();
        let cargo_home = root.join("fleet-cargo-home");
        fs::create_dir(&cargo_home).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        fs::write(
            cargo_home.join("config.toml"),
            format!(
                "[source.crates-io]\nreplace-with='fixture'\n\
                 [source.fixture]\ndirectory={}\n[net]\noffline=true\n",
                serde_json::to_string(vendor.to_str().unwrap()).unwrap(),
            ),
        )
        .unwrap();
        ["fleet_left", "fleet_right"].map(|dependency| {
            let package = vendor.join(format!("{dependency}-1.0.0"));
            fs::create_dir_all(package.join("src")).unwrap();
            fs::write(
                package.join("Cargo.toml"),
                format!("[package]\nname='{dependency}'\nversion='1.0.0'\nedition='2024'\n"),
            )
            .unwrap();
            fs::write(package.join(".cargo-checksum.json"), "{\"files\":{}}\n").unwrap();
            fs::write(
                package.join("src/lib.rs"),
                b"pub const NAME: &str = env!(\"CARGO_PKG_NAME\");\n\
                  pub const FLAVOR: &str = env!(\"DEPENDENCY_FLAVOR\");\n\
                  pub const MESSAGE: &str = include_str!(\"message.txt\");\n\
                  pub struct Token(pub [u8; MESSAGE.len()]);\n",
            )
            .unwrap();
            fs::write(package.join("src/message.txt"), dependency).unwrap();
            let project = root.join(format!("{dependency}-consumer"));
            fs::create_dir_all(project.join("src")).unwrap();
            fs::create_dir(project.join("target")).unwrap();
            fs::write(
                project.join("Cargo.toml"),
                format!(
                    "[package]\nname='{dependency}_consumer'\nversion='0.1.0'\nedition='2024'\n\
                     [dependencies]\n{dependency}='=1.0.0'\n",
                ),
            )
            .unwrap();
            fs::write(
                project.join("src/lib.rs"),
                format!(
                    "pub use {dependency}::Token;\n\
                     pub const NAME: &str = {dependency}::NAME;\n\
                     pub const FLAVOR: &str = {dependency}::FLAVOR;\n\
                     pub const MESSAGE: &str = {dependency}::MESSAGE;\n",
                ),
            )
            .unwrap();
            Self {
                dependency,
                root: project,
            }
        })
    }

    fn start(&self, live: &LiveFixture, wrapped: bool) -> FleetCargo {
        let number = live.sequence.get();
        live.sequence.set(number + 1);
        let root = live.fixture.owner.path();
        let target = self.root.join("target");
        fs::rename(&target, root.join(format!("fleet-target-{number}"))).unwrap();
        fs::create_dir(&target).unwrap();
        let toolchain = live.compiler.parent().and_then(Path::parent).unwrap();
        let mut cargo = Command::new(toolchain.join("bin/cargo"));
        cargo
            .current_dir(&self.root)
            .args(["check", "--offline", "--jobs=1", "--message-format=json"])
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", root.join("home"))
            .env("CARGO_HOME", root.join("fleet-cargo-home"))
            .env("CARGO_TARGET_DIR", target)
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TERM_COLOR", "never")
            .env("LANG", "C.UTF-8")
            .env("DEPENDENCY_FLAVOR", FLAVOR)
            .env("LD_LIBRARY_PATH", toolchain.join("lib"))
            .env("RUSTC", &live.compiler);
        for (name, value) in live.environment(FLAVOR) {
            if name.starts_with("RABS_") {
                cargo.env(name, value);
            }
        }
        if wrapped {
            cargo.env("RUSTC_WRAPPER", &live.wrapper);
        }
        let events_start = live.events().len();
        FleetCargo {
            process: Process::spawn(root, &format!("fleet-cargo-{number}"), &mut cargo),
            events_start,
        }
    }

    fn finish(&self, live: &LiveFixture, mut cargo: FleetCargo) -> FleetResult {
        assert!(
            cargo.process.wait(Duration::from_secs(660)).success(),
            "cargo={}; daemon={}; workers={:?}",
            String::from_utf8_lossy(&read_log(&cargo.process.stderr)),
            String::from_utf8_lossy(&read_log(&live.daemon.stderr)),
            live.workers
                .iter()
                .map(|worker| {
                    String::from_utf8_lossy(&read_log(&worker.process.stderr)).into_owned()
                })
                .collect::<Vec<_>>(),
        );
        let messages: Vec<Value> = String::from_utf8(read_log(&cargo.process.stdout))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("actual fleet Cargo message"))
            .collect();
        let finished: Vec<_> = messages
            .iter()
            .filter(|message| message["reason"] == "build-finished")
            .collect();
        assert_eq!(finished.len(), 1);
        assert_eq!(finished[0]["success"], true);
        let mut outputs = std::collections::BTreeMap::new();
        let mut metadata = None;
        for name in [
            self.dependency.to_owned(),
            format!("{}_consumer", self.dependency),
        ] {
            let artifacts: Vec<_> = messages
                .iter()
                .filter(|message| {
                    message["reason"] == "compiler-artifact" && message["target"]["name"] == name
                })
                .collect();
            assert_eq!(artifacts.len(), 1, "missing {name} artifact");
            assert_eq!(artifacts[0]["fresh"], false);
            let files = artifacts[0]["filenames"].as_array().unwrap();
            let rmeta: Vec<_> = files
                .iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "rmeta")
                })
                .collect();
            assert_eq!(rmeta.len(), 1);
            let rmeta = &rmeta[0];
            let stem = rmeta
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("lib")
                .unwrap()
                .strip_suffix(".rmeta")
                .unwrap();
            let dep_info = rmeta.with_file_name(format!("{stem}.d"));
            for path in [rmeta, &dep_info] {
                let bytes = fs::read(path).unwrap();
                assert!(!bytes.is_empty());
                if name == self.dependency && path == rmeta {
                    metadata = Some(bytes.clone());
                }
                assert!(
                    outputs
                        .insert(path.strip_prefix(&self.root).unwrap().to_path_buf(), bytes)
                        .is_none()
                );
            }
        }
        assert_eq!(outputs.len(), 4);
        let all_events = live.events();
        FleetResult {
            action: Run {
                events: cargo_dependency_events(&all_events[cargo.events_start..], self.dependency),
                metadata: metadata.unwrap(),
            },
            outputs,
            diagnostics: messages
                .into_iter()
                .filter(|message| message["reason"] == "compiler-message")
                .collect(),
        }
    }
}

/// A stopped real worker is a deliberate pressure condition, not a replacement
/// executor. Always resume it during unwinding so fixture teardown can drain.
struct PausedWorker(u32);

impl PausedWorker {
    fn pause(worker: &LiveWorker) -> Self {
        let paused = Self(worker.process.child.id());
        assert!(
            command("/bin/kill")
                .args(["-STOP", &paused.0.to_string()])
                .status()
                .unwrap()
                .success()
        );
        paused
    }
}

impl Drop for PausedWorker {
    fn drop(&mut self) {
        let _ = command("/bin/kill")
            .args(["-CONT", &self.0.to_string()])
            .status();
    }
}

#[test]
#[ignore = "requires Linux isolation and matching RABS_TEST_WORKER_BIN/RABS_TEST_WRAP_BIN; real Cargo, two independently pinned workers and cache replay"]
fn actual_cargo_pool_bypasses_occupied_worker_and_reuses_both_slots() {
    let mut live = LiveFixture::with_worker_count(2);
    let clients = FleetClient::prepare(&live);
    let stock = clients
        .each_ref()
        .map(|client| client.finish(&live, client.start(&live, false)));
    assert!(stock.iter().all(|result| result.action.events.is_empty()));

    let mut first = clients[0].start(&live, true);
    let until = Instant::now() + Duration::from_secs(240);
    let admitted_key = loop {
        let events = live.events();
        if let Some(event) = events[first.events_start..]
            .iter()
            .find(|event| event["kind"] == "rabsd-remote-dependency-admitted")
        {
            assert_eq!(event["worker_id"], format!("{WORKER_ID}-0"));
            break event["key"].as_str().unwrap().to_owned();
        }
        assert!(
            first.process.child.try_wait().unwrap().is_none(),
            "first Cargo completed without authenticated worker admission"
        );
        assert!(
            Instant::now() < until,
            "first action never reached a real authenticated worker: {events:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let paused = PausedWorker::pause(&live.workers[0]);
    assert!(
        !live.events().iter().any(|event| {
            event["kind"] == "rabsd-remote-dependency-executed" && event["key"] == admitted_key
        }),
        "the suspended action must still own the first slot"
    );

    let right = clients[1].finish(&live, clients[1].start(&live, true));
    right.matches_stock(&stock[1]);
    let right_key = right.action.assert_remote(None).to_owned();
    assert_ne!(right_key, admitted_key);
    assert!(
        first.process.child.try_wait().unwrap().is_none(),
        "a busy worker must not force the first action to run locally"
    );
    let right_receipt = live.worker_receipt_at(1);
    assert!(
        live.events().iter().any(|event| {
            event["kind"] == "rabsd-remote-dependency-admitted"
                && event["worker_id"] == format!("{WORKER_ID}-1")
                && event["key"] == right_key
        }),
        "the second authenticated worker must own the independent action"
    );

    drop(paused);
    let left = clients[0].finish(&live, first);
    left.matches_stock(&stock[0]);
    left.action.assert_remote(Some(&admitted_key));
    let mut receipts = [live.worker_receipt_at(0), right_receipt];
    let keys = [admitted_key, right_key];
    // Repeat real productions through the same sockets/state directories. Both
    // occupied flags and coordinator sessions must be released for these to run.
    for _ in 0..2 {
        let running = clients.each_ref().map(|client| client.start(&live, true));
        for (index, (client, cargo)) in clients.iter().zip(running).enumerate() {
            let result = client.finish(&live, cargo);
            result.matches_stock(&stock[index]);
            result.action.assert_remote(Some(&keys[index]));
        }
        let next = [live.worker_receipt_at(0), live.worker_receipt_at(1)];
        for (old, new) in receipts.iter().zip(&next) {
            assert!(new["request_id"].as_u64().unwrap() > old["request_id"].as_u64().unwrap());
        }
        receipts = next;
    }
    let running = clients.each_ref().map(|client| client.start(&live, true));
    for (index, (client, cargo)) in clients.iter().zip(running).enumerate() {
        let result = client.finish(&live, cargo);
        result.matches_stock(&stock[index]);
        result.action.assert_hit(&keys[index]);
    }
    assert_eq!(
        [live.worker_receipt_at(0), live.worker_receipt_at(1)],
        receipts,
        "qualified cache hits must not dispatch either worker"
    );
    for worker in &live.workers {
        let acquisitions: Vec<_> = String::from_utf8(read_log(&worker.process.stderr))
            .unwrap()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["kind"] == "worker-toolchain-acquired")
            .map(|event| event["disposition"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            acquisitions,
            ["captured", "reused", "reused"],
            "each worker must retain and revalidate its complete compiler across sessions"
        );
    }
    live.daemon.terminate();
}
