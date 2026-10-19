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
    worker: Process,
    daemon: Process,
    fixture: Fixture,
    wrapper: PathBuf,
    compiler: PathBuf,
    package: PathBuf,
    output: PathBuf,
    worker_state: PathBuf,
    sequence: Cell<u64>,
}

impl LiveFixture {
    fn new() -> Self {
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
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let remote_env = vec![
            ("RABS_LIVE_DEPENDENCY".to_owned(), "1".to_owned()),
            (
                "RABS_DEPENDENCY_WORKER_LISTEN".to_owned(),
                address.to_string(),
            ),
            ("RABS_DEPENDENCY_WORKER_ID".to_owned(), WORKER_ID.to_owned()),
            (
                "RABS_DEPENDENCY_WORKER_SPKI_SHA256".to_owned(),
                fixture.certificates.pin(),
            ),
        ];
        drop(reserved);
        let daemon = fixture.daemon_with_environment(&remote_env);
        let worker_state = fixture.owner.path().join("live-worker-state");
        let mut worker_command = command(worker_binary);
        worker_command
            .args([
                "--coordinator",
                &address.to_string(),
                "--worker-id",
                WORKER_ID,
            ])
            .env("RABS_WORKER_STATE_DIR", &worker_state)
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
        // A persistent production worker reconnects outward across verification
        // attempts, retaining the complete compiler dataset between sessions.
        let worker = Process::spawn(
            fixture.owner.path(),
            "live-dependency-worker",
            &mut worker_command,
        );
        Self {
            worker,
            daemon,
            fixture,
            wrapper,
            compiler,
            package,
            output,
            worker_state,
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
            String::from_utf8_lossy(&read_log(&self.worker.stderr))
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
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let bytes = fs::read(self.worker_state.join("requests.json")).unwrap();
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
    let warmup_deadline = Instant::now() + Duration::from_secs(1200);
    let first = loop {
        let run = live.compile(FLAVOR);
        if run.remote_key().is_some() {
            break run;
        }
        for event in &run.events {
            if event["kind"] == "rabsd-live-dependency" && event["decision"] == "remote-ineligible"
            {
                assert!(
                    event["reason"]
                        .as_str()
                        .is_some_and(|reason| reason.contains("warming")),
                    "the real Cargo-shaped leaf is outside remote execution: {event}"
                );
            }
        }
        assert!(
            Instant::now() < warmup_deadline,
            "retained remote toolchain never warmed: {:?}",
            run.events
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    let key = first.assert_remote(None).to_owned();
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
        self.dependencies.get(name).expect("observed Cargo dependency")
    }
}

/// Admission records name the crate; completion and installation records carry
/// only the action key. A different DAG node's terminal event proves nothing
/// about this crate, even when both were compiled in the same Cargo process.
fn cargo_dependency_events(current: &[Value], name: &str) -> Vec<Value> {
    let keys: std::collections::BTreeSet<_> = current
        .iter()
        .filter(|event| {
            event["kind"] == "rabsd-live-dependency" && event["crate"] == name
        })
        .filter_map(|event| event["key"].as_str())
        .collect();
    current
        .iter()
        .filter(|event| {
            let matching_key = event["key"]
                .as_str()
                .is_some_and(|key| keys.contains(key));
            (event["kind"] == "rabsd-live-dependency"
                && (event["crate"] == name || matching_key))
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
    let preparing = json!({"decision":"preparing", "reason":"dependency-facts-pending"});
    assert!(cargo_dependency_warming(&[preparing.clone()]));
    assert!(!cargo_dependency_warming(&[
        preparing,
        json!({"decision":"remote-ineligible", "reason":"REMOTE_DEP_DIRECTORY_NOT_EMPTY"}),
    ]));
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
            String::from_utf8_lossy(&read_log(&self.worker.stderr))
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
            assert_eq!(artifacts.len(), 1, "missing actual Cargo artifact for {name}");
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
                    assert!(metadata_by_crate.insert(name.to_owned(), bytes.clone()).is_none());
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
                        Some("committed" | "verified" | "quarantined" | "not-published" | "refused")
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
/// requires the supported disjoint input/output layout, never treats local
/// fallback as evidence of a working remote DAG, and performs no argv rewriting.
#[test]
#[ignore = "requires Linux isolation and matching RABS_TEST_WORKER_BIN/RABS_TEST_WRAP_BIN; actual offline Cargo dependency DAG plus daemon/worker"]
fn actual_offline_cargo_check_uses_remote_dependency_dag_then_replays() {
    let mut live = LiveFixture::new();
    live.prepare_cargo_consumer();
    let stock = live.cargo_check(false);
    assert!(
        stock.dependencies.values().all(|run| run.events.is_empty())
    );

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
