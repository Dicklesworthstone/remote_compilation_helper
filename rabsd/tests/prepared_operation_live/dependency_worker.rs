//! Real daemon/worker/TLS oracle for the dependency-exec-v4 contract.
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
use rabs_sandbox::dependency_context::DEPENDENCY_CONTEXT_VERSION;
use rabs_sandbox::runtime_cohort::observe_runtime_cohort;

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
