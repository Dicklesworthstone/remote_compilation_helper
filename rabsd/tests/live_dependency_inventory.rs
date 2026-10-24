//! Real rustc artifacts through live observation, keying, publication and replay.
//!
//! The upstream compiler really creates a lib-prefixed .d file plus an rlib
//! and its metadata sibling. The metadata-only consumer explicitly names that rlib. No
//! descriptor, object digest, publication or verification sample is injected.
//! This is the in-process host-local lane, not Cargo/wrapper/remote-fleet proof.
#![cfg(target_os = "linux")]

use rabs_cas::metadata_store::RabsMetadataStore;
use rabs_key::live_dependency::{
    DependencyActionPlan, ExternFact, LiveRustcRequest, PlannedExtern, ToolchainFacts,
    canonicalize_placements, live_dependency_key, plan_dependency_action,
};
use rabs_protocol::input_evidence::{
    ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::result_identity::{ObjectId, TypedDigest};
use rabsd::coord::live::CoordLive;
use rabsd::coord::live_dependency::{
    CompletionOutcome, CompletionReport, InstallResult, LiveDecision, LiveDependencyLane,
    LiveDependencyRequest,
};
use rabsd::edge::live_facts::{FactsMiss, LiveFacts};
use rabsd::janitor::store::{LiveCas, mount_and_reconcile};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHILD: &str = "RABS_INVENTORY_NATIVE_TEST_CHILD";

fn success(output: &Output, stage: &str) {
    assert!(
        output.status.success(),
        "{stage}: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn compiler() -> PathBuf {
    // Resolve the selected toolchain once, then use its real binary for both
    // observation and execution. A rustup shim is not a compiler identity.
    let selected = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let probe = Command::new(selected)
        .args(["--print", "sysroot"])
        .stdin(Stdio::null())
        .output()
        .expect("native rustc must be available; this test never silently skips");
    success(&probe, "resolve native toolchain");
    let sysroot = String::from_utf8(probe.stdout).unwrap();
    let compiler = Path::new(sysroot.trim_end())
        .canonicalize()
        .unwrap()
        .join("bin/rustc");
    assert!(std::fs::symlink_metadata(&compiler).unwrap().is_file());
    compiler
}

struct NativeInventory {
    root: PathBuf,
    source: PathBuf,
    dependencies: PathBuf,
    compiler: PathBuf,
    env: Vec<(String, String)>,
    facts: Arc<LiveFacts>,
    toolchain: ToolchainFacts,
    cas: Arc<LiveCas>,
    lane: LiveDependencyLane,
}

impl NativeInventory {
    fn new(root: &Path) -> Self {
        let compiler = compiler();
        let cargo_home = root.join("cargo");
        let source = cargo_home.join("registry/src/inventory-index/consumer-1.0.0");
        let dependencies = root.join("dependencies");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir(&dependencies).unwrap();
        std::fs::write(
            source.join("Cargo.toml"),
            "[package]\nname = \"consumer\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::write(
            source.join("lib.rs"),
            "extern crate libupstream;\npub fn answer() -> u32 { libupstream::value() }\n",
        )
        .unwrap();
        let upstream = root.join("upstream.rs");
        std::fs::write(&upstream, "pub fn value() -> u32 { 42 }\n").unwrap();
        let produced = Command::new(&compiler)
            .arg(&upstream)
            .args([
                "--crate-name=libupstream",
                "--crate-type=rlib",
                "--emit=link,metadata,dep-info",
                "--edition=2021",
                "--out-dir",
            ])
            .arg(&dependencies)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        success(&produced, "compile real upstream artifacts");
        for name in [
            "libupstream.d",
            "liblibupstream.rlib",
            "liblibupstream.rmeta",
        ] {
            let metadata = std::fs::symlink_metadata(dependencies.join(name)).unwrap();
            assert!(
                metadata.is_file() && metadata.len() > 0,
                "missing real {name}"
            );
        }
        let mut env = vec![
            ("CARGO_HOME".into(), cargo_home.to_str().unwrap().into()),
            ("CARGO_MANIFEST_DIR".into(), source.to_str().unwrap().into()),
            ("CARGO_PKG_NAME".into(), "consumer".into()),
        ];
        for name in ["PATH", "LD_LIBRARY_PATH"] {
            if let Ok(value) = std::env::var(name) {
                env.push((name.into(), value));
            }
        }
        let facts = LiveFacts::new();
        // The real sysroot is much larger than a scripted identity fixture.
        // This is a bounded readiness failure, not a build-speed assertion.
        let deadline = Instant::now() + Duration::from_secs(120);
        let toolchain = loop {
            match facts.toolchain(&compiler, &env) {
                Ok(toolchain) => break toolchain,
                Err(FactsMiss::Pending) => {
                    assert!(Instant::now() < deadline, "native toolchain did not warm");
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("native toolchain refused: {error}"),
            }
        };
        let cas = Arc::new(mount_and_reconcile(&root.join("cas")).unwrap());
        let coord = Arc::new(CoordLive::with_cas(Arc::clone(&cas)));
        coord
            .acquire_boot_authority("native-inventory-test")
            .unwrap();
        coord.mark_up();
        Self {
            root: root.to_path_buf(),
            source,
            dependencies,
            compiler,
            env,
            facts,
            toolchain,
            cas,
            lane: LiveDependencyLane::new(coord),
        }
    }

    fn request(&self, number: usize) -> (LiveDependencyRequest, Vec<String>) {
        let out = self.root.join(format!("consumer-output-{number}"));
        std::fs::create_dir(&out).unwrap();
        let argv = vec![
            self.compiler.to_str().unwrap().into(),
            self.source.join("lib.rs").to_str().unwrap().into(),
            "--crate-name=consumer".into(),
            "--crate-type=rlib".into(),
            "--edition=2021".into(),
            "--emit=metadata,dep-info".into(),
            "--error-format=json".into(),
            "--json=artifacts".into(),
            "--cap-lints=allow".into(),
            "-Cmetadata=inventory-test".into(),
            "--out-dir".into(),
            out.to_str().unwrap().into(),
            "-L".into(),
            format!("dependency={}", self.dependencies.display()),
            "--extern".into(),
            format!("libupstream={}", self.archive().display()),
        ];
        let plan = plan_dependency_action(
            LiveRustcRequest {
                argv: &argv,
                cwd: self.source.to_str().unwrap(),
                env: &self.env,
            },
            self.toolchain.host_triple().unwrap(),
        )
        .unwrap();
        let package = self
            .facts
            .package(&self.source, plan.source_kind, None)
            .unwrap();
        let dependencies = self.facts.dependencies(&plan).unwrap();
        let inputs = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: package
                .files
                .iter()
                .map(|(relative, object, executable)| PositiveInput {
                    virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
                    object: ObjectId(object.clone()),
                    file_type: InputFileType::Regular,
                    executable: *executable,
                    symlink_resolution: Vec::new(),
                })
                .collect(),
            ..ActionInputManifest::default()
        };
        let externs: Vec<ExternFact> = plan
            .externs
            .iter()
            .filter_map(|entry| match entry {
                PlannedExtern::File { path, .. } => Some(ExternFact {
                    path: path.clone(),
                    content_digest: self.facts.file_digest(Path::new(path)).unwrap(),
                }),
                PlannedExtern::Toolchain { .. } => None,
            })
            .collect();
        assert_eq!(externs.len(), 1);
        let candidates = &dependencies.directories[0].artifacts;
        assert_eq!(
            candidates.len(),
            2,
            "only the real archive and metadata are inputs"
        );
        assert!(
            candidates.contains(&externs[0]),
            "exact archive disappeared from closure"
        );
        let key = live_dependency_key(
            &plan,
            &self.toolchain,
            &externs,
            &dependencies.directories,
            None,
            &inputs,
        )
        .unwrap();
        let toolchain = self
            .facts
            .toolchain_guard(&self.compiler, &self.toolchain)
            .unwrap();
        (
            LiveDependencyRequest {
                key,
                plan,
                inputs,
                package,
                dependencies,
                toolchain,
                externs: externs
                    .into_iter()
                    .map(|fact| (fact.path, fact.content_digest))
                    .collect(),
            },
            argv,
        )
    }

    fn archive(&self) -> PathBuf {
        self.dependencies.join("liblibupstream.rlib")
    }

    fn published(&self, key: &TypedDigest) -> Option<String> {
        self.cas
            .store()
            .lock()
            .unwrap()
            .published_manifest_key(key)
            .unwrap()
    }
}

fn output_bytes(plan: &DependencyActionPlan) -> BTreeMap<String, Vec<u8>> {
    plan.output_names()
        .into_iter()
        .map(|name| {
            let raw = std::fs::read(Path::new(&plan.out_dir).join(&name)).unwrap();
            let bytes = if name.ends_with(".d") {
                canonicalize_placements(&raw, plan).unwrap()
            } else {
                raw
            };
            (name, bytes)
        })
        .collect()
}

#[test]
fn real_compiler_inventory_earns_replay_and_rechecks_exact_archive() {
    if std::env::var_os(CHILD).is_none() {
        // Isolate process-wide policy initialization without unsafe env writes
        // or synthetic verification records. Fixed sampling is the production
        // default, not a special test bypass; its two comparisons are earned.
        let mut child = Command::new(std::env::current_exe().unwrap());
        for (name, _) in std::env::vars_os() {
            if name.as_encoded_bytes().starts_with(b"RABS_") {
                child.env_remove(name);
            }
        }
        let status = child
            .args([
                "--exact",
                "real_compiler_inventory_earns_replay_and_rechecks_exact_archive",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("RABS_SPRT_SAMPLING", "0")
            .stdin(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "native inventory child failed: {status}");
        return;
    }
    let temporary = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let fixture = NativeInventory::new(&root);
    let mut expected_key = None;
    let mut expected_outputs = None;
    let mut expected_transcript = None;
    let mut published_manifest = None;
    let mut consumer_compiles = 0;

    for (number, expected) in [
        CompletionOutcome::Committed,
        CompletionOutcome::Verified,
        CompletionOutcome::Verified,
    ]
    .into_iter()
    .enumerate()
    {
        let (request, argv) = fixture.request(number);
        let key = request.key.action_key.clone();
        let plan = request.plan.clone();
        if let Some(expected) = &expected_key {
            assert_eq!(&key, expected, "output placement fragmented the action key");
        } else {
            assert_eq!(fixture.published(&key), None);
            expected_key = Some(key.clone());
        }
        let LiveDecision::Execute(attempt) = fixture.lane.decide(request) else {
            panic!("each initial run must be an admitted real execution, not an early hit");
        };
        let output = Command::new(&fixture.compiler)
            .args(&argv[1..])
            .current_dir(&fixture.source)
            .env_clear()
            .envs(
                attempt
                    .execution_env()
                    .iter()
                    .map(|(name, value)| (name, value)),
            )
            .stdin(Stdio::null())
            .output()
            .unwrap();
        consumer_compiles += 1;
        success(&output, "compile admitted consumer");
        let report = CompletionReport {
            exit_code: output.status.code(),
            signal: output.status.signal(),
            stdout: output.stdout,
            stderr: output.stderr,
        };
        let bytes = output_bytes(&plan);
        let transcript = canonicalize_placements(&report.stderr, &plan).unwrap();
        if let Some(expected) = &expected_outputs {
            assert_eq!(&bytes, expected, "real compiler outputs diverged");
            assert_eq!(expected_transcript.as_ref(), Some(&transcript));
        } else {
            expected_outputs = Some(bytes);
            expected_transcript = Some(transcript);
        }
        let captured = attempt
            .capture(&report)
            .expect("capture actual compiler output");
        assert_eq!(
            fixture.published(&key),
            published_manifest,
            "immutable capture alone must not publish"
        );
        let manifest = captured.manifest_key().to_owned();
        if let Some(original) = &published_manifest {
            assert_eq!(
                &manifest, original,
                "equivalent outputs forked the manifest"
            );
        }
        assert_eq!(captured.publish().0, expected);
        published_manifest = Some(manifest);
        assert_eq!(fixture.published(&key), published_manifest);
    }

    let key = expected_key.unwrap();
    let (request, _) = fixture.request(3);
    assert_eq!(request.key.action_key, key);
    let plan = request.plan.clone();
    let LiveDecision::Hit(pending) = fixture.lane.decide(request) else {
        panic!("three actual matching compiles did not qualify normal replay");
    };
    assert_eq!(std::fs::read_dir(&plan.out_dir).unwrap().count(), 0);
    let InstallResult::Served {
        transcript,
        installed,
    } = pending.install()
    else {
        panic!("qualified result did not install through the real materializer");
    };
    assert_eq!(consumer_compiles, 3, "replay must not invoke the compiler");
    assert_eq!(
        installed.len(),
        1,
        "the native metadata artifact must be returned"
    );
    assert_eq!(Some(output_bytes(&plan)), expected_outputs);
    assert_eq!(
        Some(canonicalize_placements(&transcript, &plan).unwrap()),
        expected_transcript
    );
    assert_eq!(fixture.published(&key), published_manifest);

    let (request, _) = fixture.request(4);
    let output_root = PathBuf::from(&request.plan.out_dir);
    let LiveDecision::Hit(pending) = fixture.lane.decide(request) else {
        panic!("unchanged exact dependency should still preview a hit");
    };
    // The .rmeta sibling stays byte-for-byte unchanged. Mutating only the
    // explicitly consumed archive must invalidate this pending installation.
    let metadata_path = fixture.dependencies.join("liblibupstream.rmeta");
    let metadata_bytes = std::fs::read(&metadata_path).unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(fixture.archive())
        .unwrap()
        .write_all(b"changed exact archive input")
        .unwrap();
    assert!(matches!(pending.install(), InstallResult::Declined(_)));
    assert_eq!(std::fs::read_dir(output_root).unwrap().count(), 0);
    assert_eq!(std::fs::read(metadata_path).unwrap(), metadata_bytes);
    let (changed, _) = fixture.request(5);
    let changed_key = changed.key.action_key.clone();
    assert_ne!(
        changed_key, key,
        "exact archive bytes did not enter the key"
    );
    assert_eq!(fixture.published(&changed_key), None);
    let LiveDecision::Execute(unexecuted) = fixture.lane.decide(changed) else {
        panic!("changed exact archive must not reuse the old result");
    };
    drop(unexecuted);
    assert_eq!(fixture.published(&changed_key), None);
    assert_eq!(fixture.published(&key), published_manifest);
    assert_eq!(consumer_compiles, 3);
}

#[test]
fn real_metadata_consumer_of_reexported_macro_refuses_live_dependency_reuse() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let compiler = compiler();
    let cargo_home = root.join("cargo");
    let source = cargo_home.join("registry/src/macro-index/consumer-1.0.0");
    let dependencies = root.join("dependencies");
    let output = root.join("output");
    for directory in [&source, &dependencies, &output] {
        std::fs::create_dir_all(directory).unwrap();
    }
    let external = root.join("untracked-input.txt");
    std::fs::write(&external, "7\n").unwrap();
    let macro_source = root.join("macro.rs");
    std::fs::write(
        &macro_source,
        r#"extern crate proc_macro;
use proc_macro::TokenStream;
#[proc_macro]
pub fn external_length(_: TokenStream) -> TokenStream {
    let value = std::fs::read_to_string(env!("RABS_INVENTORY_TRANSITIVE_INPUT")).unwrap();
    format!("[u8; {}]", value.trim()).parse().unwrap()
}
"#,
    )
    .unwrap();
    let macro_build = Command::new(&compiler)
        .args([
            "--edition=2021",
            "--crate-name=external_macro",
            "--crate-type=proc-macro",
        ])
        .arg(&macro_source)
        .arg("--out-dir")
        .arg(&dependencies)
        .env("RABS_INVENTORY_TRANSITIVE_INPUT", &external)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    success(
        &macro_build,
        "compile real external-reading procedural macro",
    );
    let reexport_source = root.join("reexport.rs");
    std::fs::write(
        &reexport_source,
        "pub use external_macro::external_length;\n",
    )
    .unwrap();
    let reexport_build = Command::new(&compiler)
        .args([
            "--edition=2021",
            "--crate-name=reexport",
            "--crate-type=lib",
            "--emit=metadata,dep-info",
        ])
        .arg(&reexport_source)
        .arg("--out-dir")
        .arg(&dependencies)
        .arg("--extern")
        .arg(format!(
            "external_macro={}",
            dependencies.join("libexternal_macro.so").display()
        ))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    success(
        &reexport_build,
        "compile normal metadata reexporting the macro",
    );
    std::fs::write(
        source.join("lib.rs"),
        "pub type Value = reexport::external_length!();\n",
    )
    .unwrap();
    let mut env = vec![
        ("CARGO_HOME".into(), cargo_home.to_str().unwrap().into()),
        ("CARGO_MANIFEST_DIR".into(), source.to_str().unwrap().into()),
        ("CARGO_PKG_NAME".into(), "consumer".into()),
    ];
    for name in ["PATH", "LD_LIBRARY_PATH"] {
        if let Ok(value) = std::env::var(name) {
            env.push((name.into(), value));
        }
    }
    let argv = vec![
        compiler.to_str().unwrap().into(),
        source.join("lib.rs").to_str().unwrap().into(),
        "--crate-name=consumer".into(),
        "--crate-type=lib".into(),
        "--edition=2021".into(),
        "--emit=metadata,dep-info".into(),
        "--error-format=json".into(),
        "--cap-lints=allow".into(),
        "--out-dir".into(),
        output.to_str().unwrap().into(),
        "-L".into(),
        format!("dependency={}", dependencies.display()),
        "--extern".into(),
        format!(
            "reexport={}",
            dependencies.join("libreexport.rmeta").display()
        ),
    ];
    let version = Command::new(&compiler).arg("-vV").output().unwrap();
    success(&version, "identify native compiler host");
    let version = String::from_utf8(version.stdout).unwrap();
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap();
    let plan = plan_dependency_action(
        LiveRustcRequest {
            argv: &argv,
            cwd: source.to_str().unwrap(),
            env: &env,
        },
        host,
    )
    .expect("only a normal .rmeta appears in the consumer's explicit externs");
    rabs_key::live_dependency::check_dependency_cache_read_closure(&plan.invocation).unwrap();
    assert_eq!(plan.externs.len(), 1);
    assert!(
        matches!(&plan.externs[0], PlannedExtern::File { path, .. } if path.ends_with(".rmeta"))
    );
    let facts = LiveFacts::new();
    let package = facts.package(&source, plan.source_kind, None).unwrap();
    let compile = || {
        let result = Command::new(&compiler)
            .args(&argv[1..])
            .current_dir(&source)
            .env_clear()
            .envs(plan.execution_env.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::null())
            .output()
            .unwrap();
        success(
            &result,
            "compile metadata consumer through the transitive macro",
        );
        (
            std::fs::read(output.join("libconsumer.rmeta")).unwrap(),
            std::fs::read(output.join("consumer.d")).unwrap(),
        )
    };
    let before = compile();
    assert_eq!(
        compile(),
        before,
        "unchanged input must reproduce the same bytes"
    );
    let extern_before = std::fs::read(dependencies.join("libreexport.rmeta")).unwrap();
    let macro_before = std::fs::read(dependencies.join("libexternal_macro.so")).unwrap();
    assert!(
        matches!(facts.dependencies(&plan), Err(FactsMiss::Refused(reason))
        if reason.contains("untracked transitive procedural macro"))
    );

    std::fs::write(&external, "19\n").unwrap();
    let after = compile();
    assert_ne!(
        after.0, before.0,
        "an untracked macro read changed the compiler result"
    );
    assert_eq!(
        after.1, before.1,
        "rustc dep-info did not report the changed input"
    );
    assert!(
        !String::from_utf8(after.1)
            .unwrap()
            .contains("untracked-input.txt")
    );
    package.verify_unchanged(&source).unwrap();
    assert_eq!(
        std::fs::read(dependencies.join("libreexport.rmeta")).unwrap(),
        extern_before
    );
    assert_eq!(
        std::fs::read(dependencies.join("libexternal_macro.so")).unwrap(),
        macro_before
    );
    assert!(
        matches!(facts.dependencies(&plan), Err(FactsMiss::Refused(reason))
        if reason.contains("untracked transitive procedural macro"))
    );
}
