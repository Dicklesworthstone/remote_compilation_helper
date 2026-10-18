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
