//! Real daemon/worker/TLS oracles for dependency and canonical Cargo execution.
//!
//! Run on Linux with usable bubblewrap/user namespaces and OpenSSL:
//!
//!     cargo build -p rabsd -p rabs-wkr
//!     RABS_TEST_WORKER_BIN="$PWD/target/debug/rabs-wkr" \
//!       cargo test -p rabsd --test prepared_operation_live \
//!       path_preserving_dependency_matches_stock_over_real_tls_worker \
//!       -- --ignored --nocapture
//!
//! The explicit ignored test fails if its requested host/binary prerequisites
//! are unavailable. It proves prepared remote execution and durable delivery;
//! its assertions stop before wrapper action-cache admission.

use super::*;
use rabs_sandbox::cargo_artifacts::{
    CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION, CARGO_PRIVATE_INCREMENTAL_BENCH_ARTIFACTS_VERSION,
    CARGO_PRIVATE_INCREMENTAL_RUN_ARTIFACTS_VERSION,
};
use rabs_sandbox::dependency_context::DEPENDENCY_CONTEXT_VERSION;
use rabs_sandbox::runtime_cohort::observe_runtime_cohort;
use rabs_sandbox::toolchain_dataset::{
    TOOLCHAIN_DATASET_VERSION, ToolchainLimits, fingerprint_toolchain,
};

const FILES: [(&str, &[u8]); 2] = [
    (
        "src/lib.rs",
        br#"pub const FLAVOR: &str = env!("DEPENDENCY_FLAVOR");
pub const JOBS: Option<&str> = option_env!("NUM_JOBS");
pub const MANIFEST: &str = env!("CARGO_MANIFEST_DIR");
pub const HERE: &str = file!();
pub const INCLUDED: &str = include_str!("message.txt");
"#,
    ),
    ("src/message.txt", b"retained dependency include\n"),
];
const ARTIFACTS: [&str; 2] = ["dependency_fixture.d", "libdependency_fixture.rmeta"];

#[test]
#[ignore = "requires canonical-capable Linux and matching RABS_TEST_WORKER_BIN; actual daemon/worker/TLS/rustc byte oracle"]
fn path_preserving_dependency_matches_stock_over_real_tls_worker() {
    let missing =
        rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical();
    assert!(
        missing.is_empty(),
        "dependency isolation is required: {missing:?}"
    );
    let worker_binary = PathBuf::from(
        std::env::var_os("RABS_TEST_WORKER_BIN").expect("matching rabs-wkr executable"),
    );
    assert!(
        worker_binary.is_absolute() && worker_binary.is_file(),
        "RABS_TEST_WORKER_BIN must name the absolute matching worker executable"
    );
    let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
    let toolchain = cargo.parent().and_then(Path::parent).unwrap().to_path_buf();
    let compiler = toolchain.join("bin/rustc");
    assert_eq!(
        fs::canonicalize(&compiler).unwrap(),
        compiler,
        "use the installed toolchain, not rustup proxies or a compiler symlink"
    );
    assert_eq!(compiler.file_name().unwrap(), "rustc");

    let fixture = Fixture::new();
    let source = fixture.owner.path().join("dependency-source");
    let out = fixture.owner.path().join("dependency-target/debug/deps");
    let loader_parent = out.parent().unwrap().to_path_buf();
    let empty_search = fixture.owner.path().join("empty-dependency-search");
    fs::create_dir_all(source.join("src")).unwrap();
    fs::create_dir_all(&out).unwrap();
    fs::create_dir(&empty_search).unwrap();
    for (relative, bytes) in FILES {
        fs::write(source.join(relative), bytes).unwrap();
    }
    let loader = toolchain.join("lib");
    let environment = vec![
        (
            "CARGO_MANIFEST_DIR".to_owned(),
            source.to_str().unwrap().to_owned(),
        ),
        (
            "DEPENDENCY_FLAVOR".to_owned(),
            "spaces \"quotes\" $HOME\n雪".to_owned(),
        ),
        (
            "LD_LIBRARY_PATH".to_owned(),
            format!(
                "{}:{}:{}",
                out.display(),
                loader_parent.display(),
                loader.display()
            ),
        ),
    ];
    assert!(
        environment.iter().all(|(name, _)| name != "NUM_JOBS"),
        "the actual worker must preserve the absent option_env! observation"
    );
    let cohort = observe_runtime_cohort(&compiler, &toolchain, std::slice::from_ref(&loader), &out)
        .expect("the real host runtime must be representable by the measured cohort");
    let cohort_hex: String = cohort
        .bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let args = vec![
        "--crate-name".to_owned(),
        "dependency_fixture".to_owned(),
        "--crate-type".to_owned(),
        "lib".to_owned(),
        "--edition=2024".to_owned(),
        "--emit=dep-info,metadata".to_owned(),
        "-L".to_owned(),
        format!("dependency={}", out.display()),
        "-L".to_owned(),
        format!("dependency={}", empty_search.display()),
        "--out-dir".to_owned(),
        out.to_str().unwrap().to_owned(),
        "src/lib.rs".to_owned(),
    ];

    let mut stock_command = Command::new(&compiler);
    stock_command
        .env_clear()
        .envs(environment.iter().map(|(name, value)| (name, value)))
        .current_dir(&source)
        .args(&args);
    let mut stock = Process::spawn(
        fixture.owner.path(),
        "stock-dependency-rustc",
        &mut stock_command,
    );
    assert!(
        stock.wait(Duration::from_secs(90)).success(),
        "stock compiler failed: {}",
        String::from_utf8_lossy(&read_log(&stock.stderr))
    );
    let stock_stdout = read_log(&stock.stdout);
    let stock_stderr = read_log(&stock.stderr);
    let expected: Vec<_> = ARTIFACTS
        .iter()
        .map(|name| ((*name).to_owned(), fs::read(out.join(name)).unwrap()))
        .collect();
    assert!(expected.iter().all(|(_, bytes)| !bytes.is_empty()));

    // Preserve the stock bytes, then make the original visible search/output
    // directory empty before dispatch. The worker must bind its private output
    // here and must never write this subscriber-owned physical directory.
    fs::rename(&out, fixture.owner.path().join("retained-stock-target")).unwrap();
    fs::create_dir_all(&out).unwrap();

    let job = Job {
        id: format!("{:032x}", 5_u64),
        worker: "dependency-worker".to_owned(),
        bundle: fixture.owner.path().join("dependency-bundle"),
        delivery: fixture.owner.path().join("dependency-delivery"),
        output: fixture.owner.path().join("dependency-installed"),
    };
    let specification = json!({
        "kind":"canonical-exec",
        "request_id":5,
        "program":compiler,
        "args":args,
        "source_files":FILES.iter().map(|(path, _)| *path).collect::<Vec<_>>(),
        "toolchain_source":toolchain,
        "timeout_ms":240_000,
        "jobserver_grant":3,
        "dependency_context":{
            "version":DEPENDENCY_CONTEXT_VERSION,
            "execution_mode":"metadata",
            "source_root":source,
            "cwd":source,
            "toolchain_root":toolchain,
            "compiler":compiler,
            "out_dir":out,
            "dependency_dirs":[out, empty_search],
            "loader_dirs":[out, loader_parent],
            "artifact_roots":[],
            "generated_directories":[],
            "env":environment,
            "runtime_cohort_sha256":cohort_hex,
        },
        "artifacts":{"unit":"dependency-fixture","files":ARTIFACTS},
    });
    let prepared = prepare_source_bundle(&source, &specification, &job.bundle).unwrap();
    assert_eq!(prepared["executed"], false);
    assert_eq!(prepared["publication_authorized"], false);
    let request_bytes = fs::read(job.bundle.join("request.json")).unwrap();
    let request: Value = serde_json::from_slice(&request_bytes).unwrap();
    assert_eq!(
        request["dependency_context"],
        specification["dependency_context"]
    );
    assert_eq!(request["program"], specification["program"]);
    assert_eq!(request["args"], specification["args"]);
    for field in [
        "source_files",
        "toolchain_source",
        "workspace_backing",
        "toolchain_backing",
        "command_context",
    ] {
        assert!(
            request.get(field).is_none(),
            "unexpected execution field {field}"
        );
    }
    assert!(request["toolchain_transfer"].is_string());
    assert!(request["toolchain_identity"].is_object());
    assert_eq!(
        request["source_manifest"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|file| file["path"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>(),
        FILES
            .iter()
            .map(|(path, _)| format!("package/{path}"))
            .collect::<Vec<_>>(),
        "v3 seals one package projection without changing visible source paths"
    );
    for (relative, bytes) in FILES {
        assert_eq!(
            fs::read(job.bundle.join("source/package").join(relative)).unwrap(),
            bytes,
            "the prepared bundle must retain the exact package bytes"
        );
    }

    // Prepared operations consume their retained source owner. A mutable source
    // change cannot sneak into the remotely executed request after preparation.
    fs::write(
        source.join("src/lib.rs"),
        b"compile_error!(\"the mutable original must never execute\");\n",
    )
    .unwrap();

    let mut daemon = fixture.daemon();
    fixture.operation(&fixture.submission(&job));
    let running = fixture.wait_for(&job, Duration::from_secs(15), |status| {
        status["state"] == "running" && status["listen_address"].is_string()
    });
    let mut worker_command = command(worker_binary);
    worker_command
        .args([
            "--coordinator",
            running["listen_address"].as_str().unwrap(),
            "--worker-id",
            &job.worker,
            "--once",
        ])
        .env(
            "RABS_WORKER_STATE_DIR",
            fixture.owner.path().join("dependency-worker-state"),
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
    let mut worker = Process::spawn(
        fixture.owner.path(),
        "dependency-worker",
        &mut worker_command,
    );
    let completed = fixture.wait_for(&job, Duration::from_secs(360), |status| {
        !matches!(
            status["state"].as_str(),
            Some("queued" | "running" | "cancelling")
        )
    });
    assert_eq!(
        completed["state"],
        "completed",
        "{completed}; worker={}; daemon={}",
        String::from_utf8_lossy(&read_log(&worker.stderr)),
        String::from_utf8_lossy(&read_log(&daemon.stderr))
    );
    assert_eq!(completed["exit_code"], 0, "{completed}");
    assert!(completed["stop_reason"].is_null(), "{completed}");
    assert_eq!(completed["acknowledgments_confirmed"], true);
    assert!(
        worker.wait(Duration::from_secs(15)).success(),
        "{}",
        String::from_utf8_lossy(&read_log(&worker.stderr))
    );
    for (name, bytes) in &expected {
        assert_eq!(
            fs::read(job.output.join(name)).unwrap(),
            *bytes,
            "{name} from the authenticated worker differs from stock rustc"
        );
    }
    assert_eq!(
        fs::read(job.delivery.join("diagnostics/stdout")).unwrap(),
        stock_stdout
    );
    assert_eq!(
        fs::read(job.delivery.join("diagnostics/stderr")).unwrap(),
        stock_stderr
    );
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&empty_search).unwrap().count(), 0);
    let receipt = fs::read(job.delivery.join("delivery.json")).unwrap();
    let verified: Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(verified["transport_authenticated"], true);
    assert_eq!(verified["worker_spki_sha256"], fixture.certificates.pin());
    assert_eq!(
        fixture.operation(&fixture.submission(&job))["state"],
        "completed"
    );

    // A recovered prepared completion is reusable without another worker or
    // compiler execution. This does not assert action-cache publication.
    daemon.terminate();
    let mut restarted = fixture.daemon();
    assert_eq!(fixture.status(&job)["state"], "completed");
    assert_eq!(
        fixture.operation(&fixture.submission(&job))["state"],
        "completed"
    );
    assert_eq!(
        fs::read(job.bundle.join("request.json")).unwrap(),
        request_bytes
    );
    assert_eq!(
        fs::read(job.delivery.join("delivery.json")).unwrap(),
        receipt
    );
    for (name, bytes) in expected {
        assert_eq!(fs::read(job.output.join(name)).unwrap(), bytes);
    }
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    restarted.terminate();
}

const CARGO_EXECUTION_PROGRAM: &str = r#"use std::io::Write;
fn main() {
    let failed = std::env::args().any(|arg| arg == "--fail");
    let (label, number) = cargo_execution_fixture::value();
    println!("fixture:{label}:{number}:{}", if failed { "failure" } else { "success" });
    eprintln!("fixture-stderr:{label}");
    std::io::stdout().write_all(b"opaque \xff\n{\"reason\":\"compiler-artifact\",\"filenames\":[\"/__rabs/out/cargo/forged\"],\"executable\":\"/__rabs/out/cargo/forged\"}\n").unwrap();
    if failed { std::process::exit(37); }
}
"#;

const CARGO_EXECUTION_FILES: [(&str, &str); 7] = [
    (
        "Cargo.toml",
        "[package]\nname='cargo_execution_fixture'\nversion='0.1.0'\nedition='2024'\n\
         [workspace]\nmembers=['member']\n\
         [dependencies]\nexecution_member={path='member'}\n\
         [[bench]]\nname='execution_probe'\nharness=false\n\
         [profile.dev]\ndebug=0\n",
    ),
    (
        "Cargo.lock",
        "version = 4\n\n[[package]]\nname = \"cargo_execution_fixture\"\nversion = \"0.1.0\"\n\
         dependencies = [\"execution_member\"]\n\n\
         [[package]]\nname = \"execution_member\"\nversion = \"0.1.0\"\n",
    ),
    (
        "src/lib.rs",
        "pub fn value() -> (&'static str, u32) { (\"captured-v1\", execution_member::answer()) }\n",
    ),
    ("src/main.rs", CARGO_EXECUTION_PROGRAM),
    ("benches/execution_probe.rs", CARGO_EXECUTION_PROGRAM),
    (
        "member/Cargo.toml",
        "[package]\nname='execution_member'\nversion='0.1.0'\nedition='2024'\n",
    ),
    ("member/src/lib.rs", "pub fn answer() -> u32 { 42 }\n"),
];

/// The runtime tail can contain non-UTF-8 and Cargo-shaped JSON. Decode only
/// the actual compiler report, stopping at its first build-finished boundary.
fn cargo_execution_report(stdout: &[u8]) -> (Vec<Value>, &[u8]) {
    let mut messages = Vec::new();
    let mut offset = 0;
    for line in stdout.split_inclusive(|byte| *byte == b'\n') {
        let message: Value = serde_json::from_slice(line).expect("actual Cargo build JSON");
        offset += line.len();
        let finished = message["reason"] == "build-finished";
        messages.push(message);
        if finished {
            return (messages, &stdout[offset..]);
        }
    }
    panic!("actual Cargo did not finish its compilation report");
}

fn contains_private_incremental_file(root: &Path) -> bool {
    fs::read_dir(root).unwrap().any(|entry| {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            contains_private_incremental_file(&entry.path())
        } else {
            kind.is_file()
                && entry
                    .path()
                    .components()
                    .any(|part| part.as_os_str() == "incremental")
        }
    })
}

#[test]
#[ignore = "requires canonical-capable Linux and matching RABS_TEST_WORKER_BIN; actual Cargo, daemon, TLS worker and persistent private target state"]
fn actual_canonical_cargo_run_preserves_failures_and_reuses_edited_private_targets() {
    canonical_cargo_execution("run");
}

#[test]
#[ignore = "requires canonical-capable Linux and matching RABS_TEST_WORKER_BIN; actual Cargo bench/no-run, daemon, TLS worker and persistent private target state"]
fn actual_canonical_cargo_bench_preserves_no_run_failures_and_private_targets() {
    canonical_cargo_execution("bench");
}

fn canonical_cargo_execution(subcommand: &str) {
    let missing =
        rabs_sandbox::canonical_namespace::HostIsolationSupport::probe().missing_for_canonical();
    assert!(
        missing.is_empty(),
        "canonical isolation is required: {missing:?}"
    );
    let worker_binary = PathBuf::from(
        std::env::var_os("RABS_TEST_WORKER_BIN").expect("matching rabs-wkr executable"),
    );
    assert!(worker_binary.is_absolute() && worker_binary.is_file());
    let cargo = fs::canonicalize(std::env::var_os("CARGO").expect("Cargo test runner")).unwrap();
    let toolchain = cargo.parent().and_then(Path::parent).unwrap();
    let identity = fingerprint_toolchain(toolchain, &ToolchainLimits::default(), || false).unwrap();
    let identity = json!({
        "version":TOOLCHAIN_DATASET_VERSION,
        "sha256":identity.sha256.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "files":identity.files, "bytes":identity.bytes,
    });
    let fixture = Fixture::new();
    let root = fixture.owner.path();
    let source = root.join("cargo-execution-source");
    for (relative, contents) in CARGO_EXECUTION_FILES {
        let path = source.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    let state = root.join("cargo-execution-worker-state");
    let stock_target = root.join("stock-target");
    let stock_home = root.join("stock-home");
    fs::create_dir(&stock_home).unwrap();
    let mut daemon = fixture.daemon();
    let mut address = None;
    for phase in 0..3_u64 {
        if phase == 2 {
            fs::write(
                source.join("src/lib.rs"),
                "pub fn value() -> (&'static str, u32) { (\"captured-v2\", execution_member::answer()) }\n",
            )
            .unwrap();
        }
        let (selected_command, contract) = match (subcommand, phase) {
            ("run", 0) => ("build", CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION),
            ("run", _) => ("run", CARGO_PRIVATE_INCREMENTAL_RUN_ARTIFACTS_VERSION),
            ("bench", 0) => ("bench", CARGO_PRIVATE_INCREMENTAL_ARTIFACTS_VERSION),
            ("bench", _) => ("bench", CARGO_PRIVATE_INCREMENTAL_BENCH_ARTIFACTS_VERSION),
            _ => unreachable!("explicit run or bench fixture"),
        };
        let mut args = vec![
            selected_command.to_owned(),
            "--offline".into(),
            "--locked".into(),
            "--jobs=1".into(),
            "--message-format=json".into(),
            "--target-dir=/__rabs/out/cargo".into(),
        ];
        args.extend(
            if subcommand == "run" {
                ["--bin", "cargo_execution_fixture"]
            } else {
                ["--bench", "execution_probe"]
            }
            .map(str::to_owned),
        );
        if phase == 0 && subcommand == "bench" {
            args.push("--no-run".into());
        } else if phase != 0 {
            args.extend([
                "--".into(),
                if phase == 1 { "--fail" } else { "--success" }.into(),
            ]);
        }

        // Run the same Cargo command with the same real sources in this
        // invocation. Cargo decides the native failure code; a successful
        // build-finished record cannot replace the final process status.
        let mut stock_args = args.clone();
        stock_args[5] = format!("--target-dir={}", stock_target.display());
        let mut stock_command = command(&cargo);
        stock_command
            .current_dir(&source)
            .args(&stock_args)
            .env("HOME", &stock_home)
            .env("CARGO_HOME", stock_home.join("cargo"))
            .env("CARGO_INCREMENTAL", "1")
            .env("RUSTC", toolchain.join("bin/rustc"))
            .env("LD_LIBRARY_PATH", toolchain.join("lib"));
        let mut stock = Process::spawn(root, &format!("stock-cargo-{phase}"), &mut stock_command);
        let stock_status = stock.wait(Duration::from_secs(90));
        let stock_stdout = read_log(&stock.stdout);
        let (stock_messages, stock_tail) = cargo_execution_report(&stock_stdout);
        assert_eq!(stock_messages.last().unwrap()["success"], true);
        assert_eq!(
            stock_status.success(),
            phase != 1,
            "stock Cargo: {}",
            String::from_utf8_lossy(&read_log(&stock.stderr))
        );

        let number = 100 + phase;
        let job = Job {
            id: format!("{number:032x}"),
            worker: "cargo-execution-worker".into(),
            bundle: root.join(format!("cargo-bundle-{phase}")),
            delivery: root.join(format!("cargo-delivery-{phase}")),
            output: root.join(format!("cargo-installed-{phase}")),
        };
        let request = json!({
            "kind":"canonical-exec", "request_id":number,
            "program":"/__rabs/toolchain/bin/cargo", "args":args,
            "toolchain_backing":toolchain, "toolchain_identity":identity,
            "source_files":CARGO_EXECUTION_FILES.iter().map(|(path, _)| *path).collect::<Vec<_>>(),
            "timeout_ms":180_000, "jobserver_grant":1,
            "command_context":{"version":"env-cwd-v1", "cwd":"/__rabs/workspace",
                "env":{"CARGO_INCREMENTAL":"1"}},
            "artifacts":{"unit":"cargo", "files":[], "tree":"tree-files-v1", "cargo":contract},
        });
        prepare_source_bundle(&source, &request, &job.bundle).unwrap();
        let mut submission = fixture.submission(&job);
        if let Some(address) = &address {
            submission[2].clone_from(address);
        }
        fixture.operation(&submission);
        let running = fixture.wait_for(&job, Duration::from_secs(15), |status| {
            status["state"] == "running" && status["listen_address"].is_string()
        });
        // Both the durable journal and private target family bind this endpoint.
        // Reuse it across actual worker restarts instead of fabricating a seed.
        address = Some(running["listen_address"].as_str().unwrap().to_owned());
        let mut worker_command = command(&worker_binary);
        worker_command
            .args([
                "--coordinator",
                address.as_ref().unwrap(),
                "--worker-id",
                &job.worker,
                "--once",
                "--target-cache-bytes",
                "134217728",
                "--target-cache-epoch",
                "cargo-execution-v1",
            ])
            .env("RABS_WORKER_STATE_DIR", &state)
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
        let mut worker =
            Process::spawn(root, &format!("cargo-worker-{phase}"), &mut worker_command);
        let completed = fixture.wait_for(&job, Duration::from_secs(240), |status| {
            !matches!(
                status["state"].as_str(),
                Some("queued" | "running" | "cancelling")
            )
        });
        assert_eq!(
            completed["state"],
            "completed",
            "{completed}; worker={}; daemon={}",
            String::from_utf8_lossy(&read_log(&worker.stderr)),
            String::from_utf8_lossy(&read_log(&daemon.stderr))
        );
        assert_eq!(completed["exit_code"], stock_status.code().unwrap());
        assert_eq!(completed["succeeded"], phase != 1);
        assert_eq!(completed["outputs_installed"], phase != 1);
        assert!(completed["stop_reason"].is_null(), "{completed}");
        assert_eq!(completed["acknowledgments_confirmed"], true);
        assert!(
            worker.wait(Duration::from_secs(15)).success(),
            "{}",
            String::from_utf8_lossy(&read_log(&worker.stderr))
        );
        let receipt: Value =
            serde_json::from_slice(&fs::read(job.delivery.join("delivery.json")).unwrap()).unwrap();
        assert_eq!(receipt["transport_authenticated"], true);
        assert_eq!(receipt["worker_spki_sha256"], fixture.certificates.pin());
        assert_eq!(receipt["publication_authorized"], false);
        let stdout = fs::read(job.delivery.join("diagnostics/stdout")).unwrap();
        let (messages, tail) = cargo_execution_report(&stdout);
        assert_eq!(messages.last().unwrap()["success"], true);
        assert_eq!(
            tail, stock_tail,
            "remote program output differs from actual stock Cargo"
        );
        if phase == 0 {
            assert!(
                tail.is_empty(),
                "compilation/no-run must never execute the program"
            );
        } else {
            let label = if phase == 1 {
                "captured-v1"
            } else {
                "captured-v2"
            };
            assert!(tail.starts_with(format!("fixture:{label}:42:").as_bytes()));
            assert!(
                tail.contains(&0xff),
                "arbitrary program bytes must survive delivery"
            );
            let stderr = fs::read(job.delivery.join("diagnostics/stderr")).unwrap();
            let marker = format!("fixture-stderr:{label}\n");
            assert!(
                stderr
                    .windows(marker.len())
                    .any(|bytes| bytes == marker.as_bytes()),
                "executed program stderr must survive authenticated delivery"
            );
            let member = messages
                .iter()
                .find(|message| {
                    message["reason"] == "compiler-artifact"
                        && message["target"]["name"] == "execution_member"
                })
                .expect("real path dependency artifact");
            assert_eq!(
                member["fresh"], true,
                "the untouched dependency must remain warm"
            );
            if phase == 1 {
                assert!(
                    messages
                        .iter()
                        .filter(|message| message["reason"] == "compiler-artifact")
                        .all(|message| message["fresh"] == true),
                    "command selection must preserve Cargo freshness"
                );
            } else {
                assert!(
                    messages
                        .iter()
                        .any(|message| message["reason"] == "compiler-artifact"
                            && message["target"]["name"] == "cargo_execution_fixture"
                            && message["fresh"] == false),
                    "edited source must be recompiled"
                );
            }
        }
        if phase == 1 {
            assert!(
                !job.output.exists(),
                "a failed program must not install successful outputs"
            );
            assert!(receipt["artifact_manifest"].is_null());
        } else {
            let files = receipt["artifact_manifest"]["files"].as_array().unwrap();
            assert!(!files.is_empty());
            for file in files {
                let name = file["name"].as_str().unwrap();
                assert!(
                    !Path::new(name)
                        .components()
                        .any(|part| part.as_os_str() == "incremental"),
                    "worker-private compiler state escaped delivery: {name}"
                );
                assert!(
                    job.output.join(name).is_file(),
                    "reported output was not installed: {name}"
                );
            }
            assert!(files.iter().any(|file| file["executable"] == true));
        }
        let worker_log = read_log(&worker.stderr);
        let events: Vec<Value> = worker_log
            .split(|byte| *byte == b'\n')
            .filter_map(|line| serde_json::from_slice(line).ok())
            .collect();
        let disposition = ["cold", "restored-compatible", "restored-edited"][phase as usize];
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == "worker-target-state"
                    && event["request_id"] == number
                    && event["disposition"] == disposition),
            "expected {disposition} from actual private state: {}",
            String::from_utf8_lossy(&worker_log)
        );
        assert!(
            events
                .iter()
                .any(|event| event["kind"] == "worker-target-state-published"
                    && event["request_id"] == number
                    && event["seed_bytes"].as_u64().is_some_and(|bytes| bytes > 0)),
            "even a normal program failure must retain only its verified private build state"
        );
        assert!(
            contains_private_incremental_file(&state.join("target-cache")),
            "real incremental state must exist privately while being absent from delivered artifacts"
        );
    }
    daemon.terminate();
}
