//! The production decoder and session admission gates, without a fake compiler
//! result. Real namespace/compiler execution is exercised in process_tree_linux.
use super::*;
use serde_json::{Value, json};

fn original_selection(mode: DependencyExecutionMode) -> DependencySelection {
    DependencySelection {
        version: DEPENDENCY_CONTEXT_VERSION,
        mode,
    }
}

fn context() -> Value {
    json!({
        "version":DEPENDENCY_CONTEXT_VERSION,
        "execution_mode":"metadata",
        "source_root":"/home/user/registry/package",
        "cwd":"/home/user/registry/package",
        "toolchain_root":"/home/user/toolchains/pinned",
        "compiler":"/home/user/toolchains/pinned/bin/rustc",
        "out_dir":"/work/target/debug/deps",
        "dependency_dirs":["/work/target/debug/deps"],
        "artifact_roots":[],
        "generated_directories":[],
        "env":[["DEPENDENCY_FLAVOR","spaces \"quotes\" $HOME\n雪"],["EXPLICIT_EMPTY",""]],
        "runtime_cohort_sha256":"ab".repeat(32),
    })
}

fn dependency_request() -> Value {
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    let manifest = SourceManifest::new(vec![SourceFile {
        path: "package/src/lib.rs".to_owned(),
        len: 1,
        sha256: [1; 32],
        executable: false,
    }])
    .unwrap();
    json!({
        "kind":"canonical-exec", "request_id":712,
        "program":"/home/user/toolchains/pinned/bin/rustc",
        "args":["--crate-name","leaf","--crate-type","lib","--emit=dep-info,metadata","src/lib.rs"],
        "source_manifest":{"files":[{"path":"package/src/lib.rs","bytes":1,"sha256":"01".repeat(32),"executable":false}],
            "manifest_sha256":rabs_wkr::source_transfer::hex(&manifest.digest())},
        "toolchain_transfer":TOOLCHAIN_TRANSFER_VERSION,
        "toolchain_identity":{"version":rabs_sandbox::toolchain_dataset::TOOLCHAIN_DATASET_VERSION,
            "sha256":"cd".repeat(32),"files":1,"bytes":1},
        "artifacts":{"unit":"leaf","files":["leaf.d","libleaf.rmeta"]},
        "dependency_context":context(),
    })
}

fn canonical_dependency_request() -> Value {
    let mut request = dependency_request();
    request["program"] = json!("/__rabs/toolchain/bin/rustc");
    request["args"] = json!([
        "--crate-name",
        "leaf",
        "--crate-type",
        "lib",
        "--emit=dep-info,metadata",
        "--out-dir",
        "/__rabs/out/cargo/debug/deps",
        "src/lib.rs",
    ]);
    request["dependency_context"] = json!({
        "version":CANONICAL_DEPENDENCY_CONTEXT_VERSION,
        "execution_mode":"metadata",
        "source_root":"/__rabs/cargo-home/registry/src/pinned/leaf-1.0.0",
        "cwd":"/__rabs/cargo-home/registry/src/pinned/leaf-1.0.0",
        "toolchain_root":"/__rabs/toolchain",
        "compiler":"/__rabs/toolchain/bin/rustc",
        "out_dir":"/__rabs/out/cargo/debug/deps",
        "dependency_dirs":["/__rabs/out/cargo/debug/deps"],
        "artifact_roots":[],
        "generated_directories":[],
        "env":[
            ["HOME","/__rabs/home"],
            ["CARGO_HOME","/__rabs/cargo-home"],
            ["CARGO_MANIFEST_DIR","/__rabs/cargo-home/registry/src/pinned/leaf-1.0.0"],
        ],
        "runtime_cohort_sha256":"ab".repeat(32),
    });
    request
}

fn canonical_workspace_request(archive: bool) -> Value {
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    let mut request = canonical_generated_request(archive, true);
    let context = &mut request["dependency_context"];
    context["version"] = json!(CANONICAL_WORKSPACE_CONTEXT_VERSION);
    context["source_root"] = json!("/__rabs/workspace");
    context["cwd"] = json!("/__rabs/workspace");
    context["source_directories"] = json!(["empty", "member", "member/src"]);
    for pair in context["env"].as_array_mut().unwrap() {
        if pair[0] == "CARGO_MANIFEST_DIR" {
            pair[1] = json!("/__rabs/workspace/member");
        }
    }
    context["env"]
        .as_array_mut()
        .unwrap()
        .push(json!(["CARGO_PRIMARY_PACKAGE", "1"]));
    *request["args"].as_array_mut().unwrap().last_mut().unwrap() = json!("member/src/lib.rs");
    let files = vec![
        SourceFile {
            path: "package/member/src/lib.rs".into(),
            len: 1,
            sha256: [1; 32],
            executable: false,
        },
        SourceFile {
            path: "generated/nested/input.rs".into(),
            len: 1,
            sha256: [2; 32],
            executable: false,
        },
    ];
    let manifest = SourceManifest::new(files).unwrap();
    request["source_manifest"] = json!({
        "manifest_sha256":rabs_wkr::source_transfer::hex(&manifest.digest()),
        "files":manifest.files().iter().map(|file| json!({
            "path":file.path,"bytes":file.len,
            "sha256":rabs_wkr::source_transfer::hex(&file.sha256),"executable":file.executable,
        })).collect::<Vec<_>>()
    });
    request
}

#[test]
fn workspace_decoder_preserves_primary_environment_relative_argv_and_both_input_trees() {
    for archive in [false, true] {
        let wire = canonical_workspace_request(archive);
        let parsed = parse_exec_request(&wire).unwrap();
        let context = parsed.dependency_context.as_ref().unwrap();
        assert!(context.canonical_cargo() && context.workspace_execution_only());
        assert_eq!(context.version(), CANONICAL_WORKSPACE_CONTEXT_VERSION);
        assert_eq!(
            context.source_directories(),
            ["empty", "member", "member/src"]
        );
        assert_eq!(context.generated_directories(), ["nested"]);
        assert_eq!(parsed.args.last().unwrap(), "member/src/lib.rs");
        assert!(
            context
                .env()
                .contains(&("CARGO_PRIMARY_PACKAGE".into(), "1".into()))
        );
        assert!(context.env().contains(&(
            "CARGO_MANIFEST_DIR".into(),
            "/__rabs/workspace/member".into()
        )));
        assert_eq!(wire, canonical_workspace_request(archive));
    }
}

#[test]
fn workspace_decoder_requires_its_exact_profile_and_complete_directory_shape() {
    let valid = canonical_workspace_request(false);
    for (field, value) in [
        ("version", json!(CANONICAL_DEPENDENCY_CONTEXT_VERSION)),
        ("source_root", json!("/__rabs/workspace/member")),
        ("source_directories", Value::Null),
        ("source_directories", json!(["member/src"])),
        ("source_directories", json!(["../escape"])),
        ("source_directories", json!(["member", "member"])),
        ("execution_mode", json!("rlib")),
    ] {
        let mut request = valid.clone();
        request["dependency_context"][field] = value;
        assert!(parse_exec_request(&request).is_err(), "{field}");
    }
    let mut missing = valid;
    missing["dependency_context"]
        .as_object_mut()
        .unwrap()
        .remove("source_directories");
    assert!(parse_exec_request(&missing).is_err());
    for mut request in [dependency_request(), canonical_dependency_request()] {
        request["dependency_context"]["source_directories"] = json!([]);
        assert!(parse_exec_request(&request).is_err());
    }
}

#[test]
fn canonical_dependency_decode_retains_exact_cargo_paths_and_closed_outputs() {
    let wire = canonical_dependency_request();
    let parsed = parse_exec_request(&wire).unwrap();
    let context = parsed.dependency_context.as_ref().unwrap();
    assert_eq!(context.version(), CANONICAL_DEPENDENCY_CONTEXT_VERSION);
    assert!(context.canonical_cargo());
    assert_eq!(context.execution_mode(), DependencyExecutionMode::Metadata);
    assert_eq!(context.compiler(), "/__rabs/toolchain/bin/rustc");
    assert_eq!(context.toolchain_root(), "/__rabs/toolchain");
    assert_eq!(
        context.cwd(),
        "/__rabs/cargo-home/registry/src/pinned/leaf-1.0.0"
    );
    assert_eq!(context.out_dir(), "/__rabs/out/cargo/debug/deps");
    assert_eq!(context.generated_root(), None);
    assert!(parsed.toolchain_backing.is_empty() && parsed.workspace_backing.is_empty());
    assert_eq!(
        wire,
        canonical_dependency_request(),
        "decoding must not rewrite request identity"
    );
    let ordinary = parse_exec_request(&dependency_request()).unwrap();
    let ordinary = ordinary.dependency_context.unwrap();
    assert_eq!(ordinary.version(), DEPENDENCY_CONTEXT_VERSION);
    assert!(!ordinary.canonical_cargo());
}

#[test]
fn canonical_dependency_context_requires_its_paths_and_matching_compiler_mode() {
    for (field, value) in [
        ("version", json!(DEPENDENCY_CONTEXT_VERSION)),
        ("execution_mode", json!("rlib")),
        ("generated_root", json!("/__rabs/out/cargo/debug/generated")),
        ("toolchain_root", json!("/home/user/toolchains/pinned")),
        ("compiler", json!("/home/user/toolchains/pinned/bin/rustc")),
        ("source_root", json!("/__rabs/cargo-home")),
        ("out_dir", json!("/__rabs/home/control")),
    ] {
        let mut request = canonical_dependency_request();
        request["dependency_context"][field] = value;
        assert!(parse_exec_request(&request).is_err(), "{field}");
    }
    let mut ordinary = dependency_request();
    ordinary["dependency_context"]["version"] = json!(CANONICAL_DEPENDENCY_CONTEXT_VERSION);
    assert!(parse_exec_request(&ordinary).is_err());
}

fn canonical_archive_request(separate_metadata: bool) -> Value {
    let mut request = canonical_dependency_request();
    request["dependency_context"]["execution_mode"] = json!("rlib");
    request["args"] = json!([
        "--crate-name",
        "leaf",
        "--crate-type",
        "rlib",
        if separate_metadata {
            "--emit=dep-info,metadata,link"
        } else {
            "--emit=dep-info,link"
        },
        "--out-dir",
        "/__rabs/out/cargo/debug/deps",
        "src/lib.rs",
    ]);
    request["artifacts"]["files"] = if separate_metadata {
        json!(["leaf.d", "libleaf.rmeta", "libleaf.rlib"])
    } else {
        json!(["leaf.d", "libleaf.rlib"])
    };
    request
}

fn canonical_generated_request(archive: bool, populated: bool) -> Value {
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    let mut request = if archive {
        canonical_archive_request(true)
    } else {
        canonical_dependency_request()
    };
    let generated = "/__rabs/out/cargo/debug/build/leaf-hash/out";
    request["dependency_context"]["generated_root"] = json!(generated);
    request["dependency_context"]["loader_dirs"] = json!(["/__rabs/out/cargo/debug"]);
    request["dependency_context"]["env"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!(["OUT_DIR", generated]),
            json!([
                "LD_LIBRARY_PATH",
                "/__rabs/out/cargo/debug:/__rabs/toolchain/lib"
            ]),
        ]);
    if populated {
        request["dependency_context"]["generated_directories"] = json!(["nested"]);
        let manifest = SourceManifest::new(vec![
            SourceFile {
                path: "package/src/lib.rs".into(),
                len: 1,
                sha256: [1; 32],
                executable: false,
            },
            SourceFile {
                path: "generated/nested/input.rs".into(),
                len: 1,
                sha256: [2; 32],
                executable: false,
            },
        ])
        .unwrap();
        request["source_manifest"]["files"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "path":"generated/nested/input.rs", "bytes":1,
                "sha256":"02".repeat(32), "executable":false,
            }));
        request["source_manifest"]["manifest_sha256"] =
            json!(rabs_wkr::source_transfer::hex(&manifest.digest()));
    }
    request
}

fn canonical_native_request() -> Value {
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    let mut request = canonical_generated_request(true, true);
    request["args"].as_array_mut().unwrap().extend([
        json!("-L"),
        json!("native=/__rabs/out/cargo/debug/build/leaf-hash/out/nested"),
        json!("-l"),
        json!("static=native"),
    ]);
    let manifest = SourceManifest::new(vec![
        SourceFile {
            path: "package/src/lib.rs".into(),
            len: 1,
            sha256: [1; 32],
            executable: false,
        },
        SourceFile {
            path: "generated/nested/input.rs".into(),
            len: 1,
            sha256: [2; 32],
            executable: false,
        },
        SourceFile {
            path: "generated/nested/libnative.a".into(),
            len: 8,
            sha256: [3; 32],
            executable: false,
        },
    ])
    .unwrap();
    request["source_manifest"]["files"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "path":"generated/nested/libnative.a", "bytes":8,
            "sha256":"03".repeat(32), "executable":false,
        }));
    request["source_manifest"]["manifest_sha256"] =
        json!(rabs_wkr::source_transfer::hex(&manifest.digest()));
    request
}

#[test]
fn canonical_native_archive_request_requires_closed_generated_inputs() {
    let request = canonical_native_request();
    let original = request.clone();
    let parsed = parse_exec_request(&request).unwrap();
    let context = parsed.dependency_context.unwrap();
    assert!(context.canonical_cargo());
    assert_eq!(context.execution_mode(), DependencyExecutionMode::Rlib);
    assert_eq!(context.generated_directories(), &["nested"]);
    assert!(
        parsed
            .args
            .iter()
            .any(|argument| argument == "static=native")
    );
    assert_eq!(
        request, original,
        "worker decoding must preserve native argv"
    );

    // An undeclared directory cannot be acquired just by spelling it beneath
    // OUT_DIR. Its complete topology belongs to the transferred input view.
    let mut missing_directory = request.clone();
    missing_directory["dependency_context"]["generated_directories"] = json!([]);
    assert!(parse_exec_request(&missing_directory).is_err());
    let mut metadata = canonical_generated_request(false, true);
    metadata["args"].as_array_mut().unwrap().extend([
        json!("-Lnative=/__rabs/out/cargo/debug/build/leaf-hash/out/nested"),
        json!("-lstatic=native"),
    ]);
    assert!(parse_exec_request(&metadata).is_err());
    let mut ordinary = dependency_request();
    ordinary["args"]
        .as_array_mut()
        .unwrap()
        .extend([json!("-Lnative=/work/generated"), json!("-lstatic=native")]);
    assert!(parse_exec_request(&ordinary).is_err());
}

#[test]
fn workspace_execution_cannot_inherit_generated_native_dependency_authority() {
    for archive in [false, true] {
        let baseline = canonical_workspace_request(archive);
        assert!(parse_exec_request(&baseline).is_ok());
        for extra in [
            vec!["-Lnative=/__rabs/out/cargo/debug/build/leaf-hash/out/nested"],
            vec![
                "-Lnative=/__rabs/out/cargo/debug/build/leaf-hash/out/nested",
                "-lstatic=native",
            ],
            vec!["-lstatic=native"],
        ] {
            let mut request = baseline.clone();
            request["args"]
                .as_array_mut()
                .unwrap()
                .extend(extra.iter().map(|argument| json!(argument)));
            let error = parse_exec_request(&request).unwrap_err();
            assert!(
                error.contains("dependency generated native inputs"),
                "archive={archive}, {extra:?}: {error}"
            );
        }
    }
}

#[test]
fn canonical_native_archives_refuse_system_dynamic_and_escaping_searches() {
    for extra in [
        vec!["-l", "native"],
        vec!["-l", "dylib=native"],
        vec!["-l", "framework=native"],
        vec!["-l", "static:-bundle=native"],
        vec!["-l", "static=native:renamed"],
        vec!["-l", "static=../native"],
        vec!["-L", "native=/usr/lib"],
        vec!["-L", "native=/__rabs/out/cargo/debug/build/other/out"],
        vec![
            "-L",
            "native=/__rabs/out/cargo/debug/build/leaf-hash/outside",
        ],
        vec![
            "-L",
            "native=/__rabs/out/cargo/debug/build/leaf-hash/out/../outside",
        ],
        vec![
            "-L",
            "native=/__rabs/out/cargo/debug/build/leaf-hash/out/nested/../nested",
        ],
        vec![
            "-L",
            "all=/__rabs/out/cargo/debug/build/leaf-hash/out/nested",
        ],
        vec!["-L", "/__rabs/out/cargo/debug/build/leaf-hash/out/nested"],
    ] {
        let mut request = canonical_native_request();
        request["args"]
            .as_array_mut()
            .unwrap()
            .extend(extra.iter().map(|argument| json!(argument)));
        assert!(parse_exec_request(&request).is_err(), "{extra:?}");
    }
}

#[test]
fn canonical_generated_context_decodes_empty_and_populated_trees_in_both_modes() {
    for archive in [false, true] {
        for populated in [false, true] {
            let wire = canonical_generated_request(archive, populated);
            let original = wire.clone();
            let parsed = parse_exec_request(&wire).unwrap();
            let context = parsed.dependency_context.unwrap();
            assert_eq!(context.version(), "canonical-dependency-exec-v4");
            assert!(context.canonical_cargo());
            assert_eq!(
                context.execution_mode(),
                if archive {
                    DependencyExecutionMode::Rlib
                } else {
                    DependencyExecutionMode::Metadata
                }
            );
            assert_eq!(
                context.generated_root(),
                Some("/__rabs/out/cargo/debug/build/leaf-hash/out")
            );
            assert!(context.env().contains(&(
                "OUT_DIR".into(),
                "/__rabs/out/cargo/debug/build/leaf-hash/out".into()
            )));
            assert_eq!(
                wire, original,
                "decoder changed the retained input contract"
            );
        }
    }
}

#[test]
fn canonical_archive_decode_preserves_mode_paths_and_complete_output_contract() {
    for separate_metadata in [false, true] {
        let original = canonical_archive_request(separate_metadata);
        let parsed = parse_exec_request(&original).unwrap();
        let context = parsed.dependency_context.as_ref().unwrap();
        assert!(context.canonical_cargo());
        assert_eq!(context.version(), CANONICAL_DEPENDENCY_CONTEXT_VERSION);
        assert_eq!(context.execution_mode(), DependencyExecutionMode::Rlib);
        assert_eq!(context.compiler(), "/__rabs/toolchain/bin/rustc");
        assert_eq!(context.out_dir(), "/__rabs/out/cargo/debug/deps");
        assert_eq!(original, canonical_archive_request(separate_metadata));
        for outputs in [
            json!(["leaf.d", "libleaf.rmeta"]),
            json!(["leaf.d", "libleaf.rlib", "unclaimed.o"]),
        ] {
            let mut request = original.clone();
            request["artifacts"]["files"] = outputs;
            assert!(parse_exec_request(&request).is_err());
        }
        for (field, value) in [
            ("version", json!("canonical-dependency-exec-v1")),
            ("version", json!("canonical-dependency-exec-v2")),
            ("version", json!(DEPENDENCY_CONTEXT_VERSION)),
            ("execution_mode", json!("metadata")),
            ("generated_root", json!("/__rabs/out/cargo/debug/generated")),
        ] {
            let mut request = original.clone();
            request["dependency_context"][field] = value;
            assert!(parse_exec_request(&request).is_err(), "{field}");
        }
    }
}

#[test]
fn canonical_generated_dependency_decode_requires_v4_and_exact_owned_out_dir() {
    let generated = "/__rabs/out/cargo/debug/build/leaf-123/out";
    for mut request in [
        canonical_dependency_request(),
        canonical_archive_request(true),
    ] {
        request["dependency_context"]["generated_root"] = json!(generated);
        request["dependency_context"]["env"]
            .as_array_mut()
            .unwrap()
            .push(json!(["OUT_DIR", generated]));
        let original = request.clone();
        let parsed = parse_exec_request(&request).unwrap();
        let context = parsed.dependency_context.unwrap();
        assert_eq!(context.version(), "canonical-dependency-exec-v4");
        assert_eq!(context.generated_root(), Some(generated));
        assert!(
            context
                .env()
                .contains(&("OUT_DIR".into(), generated.into()))
        );
        assert_eq!(request, original, "decoding changed exact request identity");

        for version in [
            "canonical-dependency-exec-v1",
            "canonical-dependency-exec-v2",
            "canonical-dependency-exec-v3",
            DEPENDENCY_CONTEXT_VERSION,
        ] {
            let mut obsolete = request.clone();
            obsolete["dependency_context"]["version"] = json!(version);
            assert!(parse_exec_request(&obsolete).is_err(), "{version}");
        }
        for root in [
            "/__rabs/out/cargo",
            "/__rabs/out/cargo/debug",
            "/__rabs/out/cargo/debug/deps",
            "/__rabs/out/cargo/debug/deps/generated",
            "/__rabs/out/cargo/debug/build/../out",
            "/__rabs/out/cargo-other/generated",
            "/__rabs/workspace/generated",
            "/__rabs/cargo-home/generated",
            "/__rabs/cargo-home/registry/src/pinned/leaf-1.0.0/generated",
            "/__rabs/toolchain/generated",
            "/__rabs/home/control",
            "/usr/generated",
        ] {
            let mut invalid = request.clone();
            invalid["dependency_context"]["generated_root"] = json!(root);
            *invalid["dependency_context"]["env"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap() = json!(["OUT_DIR", root]);
            assert!(parse_exec_request(&invalid).is_err(), "{root}");
        }
        for value in ["", "/__rabs/out/cargo/another-out"] {
            let mut mismatched = request.clone();
            *mismatched["dependency_context"]["env"]
                .as_array_mut()
                .unwrap()
                .last_mut()
                .unwrap() = json!(["OUT_DIR", value]);
            assert!(parse_exec_request(&mismatched).is_err());
        }
        let mut missing_root = request.clone();
        missing_root["dependency_context"]
            .as_object_mut()
            .unwrap()
            .remove("generated_root");
        assert!(parse_exec_request(&missing_root).is_err());
        let mut missing_environment = request.clone();
        missing_environment["dependency_context"]["env"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(parse_exec_request(&missing_environment).is_err());
        request["dependency_context"]["generated_root"] = Value::Null;
        assert!(parse_exec_request(&request).is_err());
    }
}

#[test]
fn canonical_archive_refuses_executable_externs_native_inputs_and_unretained_paths() {
    for extra in [
        vec!["--crate-type", "proc-macro"],
        vec![
            "--extern",
            "derive=/__rabs/out/cargo/debug/deps/libderive.so",
        ],
        vec!["--extern", "leaf=/outside/libleaf.rlib"],
        vec!["--extern", "unbound"],
        vec!["-l", "static=unretained"],
        vec!["-L", "native=/usr/lib"],
        vec!["-L", "dependency=/__rabs/out/cargo/unretained"],
        vec!["--sysroot", "/another/toolchain"],
        vec!["-C", "linker=/usr/bin/cc"],
        vec!["-C", "target-cpu=native"],
        vec!["-C", "incremental=/__rabs/out/cargo/incremental"],
        vec!["-C", "save-temps=yes"],
        vec!["-o", "/__rabs/out/cargo/unclaimed"],
        vec!["--emit=dep-info,metadata,link,llvm-ir"],
    ] {
        let mut request = canonical_archive_request(true);
        request["args"]
            .as_array_mut()
            .unwrap()
            .extend(extra.iter().map(|arg| json!(arg)));
        assert!(parse_exec_request(&request).is_err(), "{extra:?}");
    }
    for path in [
        "../outside.rs",
        "/__rabs/workspace/unretained/lib.rs",
        "src/../lib.rs",
    ] {
        let mut request = canonical_archive_request(true);
        *request["args"].as_array_mut().unwrap().last_mut().unwrap() = json!(path);
        assert!(parse_exec_request(&request).is_err(), "{path}");
    }
    let mut retained = canonical_archive_request(true);
    retained["args"].as_array_mut().unwrap().extend([
        json!("--extern"),
        json!("input=/__rabs/out/cargo/debug/deps/libinput.rlib"),
        json!("-L"),
        json!("dependency=/__rabs/out/cargo/debug/deps"),
    ]);
    assert!(parse_exec_request(&retained).is_ok());
}

#[test]
fn canonical_dependency_compiler_must_match_retained_inputs_and_complete_metadata_outputs() {
    for extra in [
        vec!["--crate-type", "proc-macro"],
        vec![
            "--extern",
            "derive=/__rabs/out/cargo/debug/deps/libderive.so",
        ],
        vec!["--extern", "leaf=/outside/libleaf.rmeta"],
        vec!["-L", "native=/usr/lib"],
        vec!["--sysroot", "/another/toolchain"],
        vec!["--out-dir", "/__rabs/out/cargo/other"],
        vec!["--emit=dep-info,metadata,link"],
    ] {
        let mut request = canonical_dependency_request();
        request["args"]
            .as_array_mut()
            .unwrap()
            .extend(extra.iter().map(|arg| json!(arg)));
        assert!(parse_exec_request(&request).is_err(), "{extra:?}");
    }
    let mut source = canonical_dependency_request();
    *source["args"].as_array_mut().unwrap().last_mut().unwrap() =
        json!("/__rabs/home/control/source.rs");
    assert!(parse_exec_request(&source).is_err());
    for outputs in [
        json!(["libleaf.rmeta"]),
        json!(["leaf.d", "libleaf.rmeta", "other.rmeta"]),
    ] {
        let mut request = canonical_dependency_request();
        request["artifacts"]["files"] = outputs;
        assert!(parse_exec_request(&request).is_err());
    }
}

#[test]
fn complete_dependency_decode_preserves_paths_values_and_input_owner_slots() {
    let original = dependency_request();
    let parsed = parse_exec_request(&original).unwrap();
    let context = parsed.dependency_context.as_ref().unwrap();
    assert_eq!(parsed.program, context.compiler());
    assert_eq!(context.cwd(), "/home/user/registry/package");
    assert_eq!(context.out_dir(), "/work/target/debug/deps");
    assert_eq!(
        context.env(),
        &[
            (
                "DEPENDENCY_FLAVOR".to_owned(),
                "spaces \"quotes\" $HOME\n雪".to_owned()
            ),
            ("EXPLICIT_EMPTY".to_owned(), String::new()),
        ]
    );
    assert!(!context.env().iter().any(|(name, _)| name == "NUM_JOBS"));
    assert!(parsed.toolchain_backing.is_empty() && parsed.workspace_backing.is_empty());
    assert!(parsed.toolchain_identity.is_some());
    assert_eq!(
        original,
        dependency_request(),
        "decoder does not project wire identity in place"
    );
}

fn archive_request(separate_metadata: bool) -> Value {
    let mut request = dependency_request();
    request["dependency_context"]["execution_mode"] = json!("rlib");
    let emit = if separate_metadata {
        "--emit=dep-info,metadata,link"
    } else {
        "--emit=dep-info,link"
    };
    request["args"] = json!([
        "--crate-name",
        "leaf",
        "--crate-type",
        "rlib",
        emit,
        "--out-dir",
        "/work/target/debug/deps",
        "src/lib.rs",
    ]);
    request["artifacts"]["files"] = if separate_metadata {
        json!(["leaf.d", "libleaf.rmeta", "libleaf.rlib"])
    } else {
        json!(["leaf.d", "libleaf.rlib"])
    };
    request
}

#[test]
fn closed_archive_decode_requires_its_mode_and_complete_derived_artifacts() {
    use rabs_sandbox::dependency_context::DependencyExecutionMode;
    for separate_metadata in [false, true] {
        let original = archive_request(separate_metadata);
        let parsed = parse_exec_request(&original).unwrap();
        assert_eq!(
            parsed.dependency_context.unwrap().execution_mode(),
            DependencyExecutionMode::Rlib
        );
        assert_eq!(original, archive_request(separate_metadata));
        let mut missing_archive = original.clone();
        missing_archive["artifacts"]["files"] = json!(["leaf.d", "libleaf.rmeta"]);
        assert!(parse_exec_request(&missing_archive).is_err());
        let mut extra_output = original.clone();
        extra_output["artifacts"]["files"]
            .as_array_mut()
            .unwrap()
            .push(json!("unclaimed.o"));
        assert!(parse_exec_request(&extra_output).is_err());
        let mut tree = original.clone();
        tree["artifacts"]["tree"] = json!("tree-files-v1");
        assert!(parse_exec_request(&tree).is_err());
        let mut missing_contract = original.clone();
        missing_contract
            .as_object_mut()
            .unwrap()
            .remove("artifacts");
        assert!(parse_exec_request(&missing_contract).is_err());
    }
}

#[test]
fn archive_mode_is_never_inferred_from_argv_or_silently_downgraded() {
    let mut absent = archive_request(true);
    absent["dependency_context"]
        .as_object_mut()
        .unwrap()
        .remove("execution_mode");
    assert!(parse_exec_request(&absent).is_err());
    for mode in [
        Value::Null,
        json!(true),
        json!("metadata"),
        json!("archive"),
        json!("rlib-v999"),
    ] {
        let mut wrong = archive_request(true);
        wrong["dependency_context"]["execution_mode"] = mode;
        assert!(parse_exec_request(&wrong).is_err());
    }
    let mut metadata = dependency_request();
    metadata["dependency_context"]["execution_mode"] = json!("rlib");
    assert!(parse_exec_request(&metadata).is_err());
    let mut old = archive_request(true);
    old["dependency_context"]["version"] = json!("dependency-exec-v6");
    assert!(parse_exec_request(&old).is_err());
}

#[test]
fn archive_worker_refuses_native_plugins_unretained_paths_and_output_overrides() {
    for extra in [
        vec!["-l", "static=unretained"],
        vec!["-L", "native=/usr/lib"],
        vec!["-L", "dependency=/unretained"],
        vec!["--extern", "unbound"],
        vec!["--extern", "derive=/work/target/debug/deps/libderive.so"],
        vec!["--extern", "other=/unretained/libother.rlib"],
        vec!["--sysroot", "/another/toolchain"],
        vec!["-C", "linker=/usr/bin/cc"],
        vec!["-C", "target-cpu=native"],
        vec!["-C", "incremental=/private/incremental"],
        vec!["-C", "save-temps=yes"],
        vec!["-o", "/unretained/output"],
        vec!["--crate-type", "dylib"],
        vec!["--emit=dep-info,metadata,link,llvm-ir"],
    ] {
        let mut request = archive_request(true);
        request["args"]
            .as_array_mut()
            .unwrap()
            .extend(extra.iter().map(|arg| json!(arg)));
        assert!(parse_exec_request(&request).is_err(), "{extra:?}");
    }
    for source in ["../outside.rs", "/unretained/source.rs", "src/../lib.rs"] {
        let mut request = archive_request(true);
        *request["args"].as_array_mut().unwrap().last_mut().unwrap() = json!(source);
        assert!(parse_exec_request(&request).is_err(), "{source}");
    }
    let mut output = archive_request(true);
    output["dependency_context"]["out_dir"] = json!("/different/output");
    assert!(parse_exec_request(&output).is_err());
    let mut direct = archive_request(true);
    direct["args"].as_array_mut().unwrap().extend([
        json!("--extern"),
        json!("leaf=/work/target/debug/deps/libinput.rlib"),
        json!("-L"),
        json!("dependency=/work/target/debug/deps"),
    ]);
    assert!(
        parse_exec_request(&direct).is_ok(),
        "retained Rust externs remain supported"
    );
}

#[test]
fn cargo_loader_parent_is_explicit_and_old_context_versions_cannot_ignore_it() {
    let mut request = dependency_request();
    request["dependency_context"]["loader_dirs"] =
        json!(["/work/target/debug/deps", "/work/target/debug"]);
    let value = "/work/target/debug/deps:/work/target/debug:/home/user/toolchains/pinned/lib";
    request["dependency_context"]["env"]
        .as_array_mut()
        .unwrap()
        .push(json!(["LD_LIBRARY_PATH", value]));
    let parsed = parse_exec_request(&request).unwrap();
    let context = parsed.dependency_context.unwrap();
    assert_eq!(
        context.loader_dirs(),
        &[
            "/work/target/debug".to_owned(),
            "/work/target/debug/deps".to_owned()
        ]
    );
    assert!(
        context
            .env()
            .contains(&("LD_LIBRARY_PATH".to_owned(), value.to_owned()))
    );
    for version in [
        "dependency-exec-v1",
        "dependency-exec-v2",
        "dependency-exec-v3",
        "dependency-exec-v4",
    ] {
        request["dependency_context"]["version"] = json!(version);
        assert!(
            parse_exec_request(&request).is_err(),
            "an old worker contract cannot select v5 execution: {version}"
        );
    }
    request["dependency_context"]["version"] = json!(DEPENDENCY_CONTEXT_VERSION);
    for invalid in [
        Value::Null,
        json!(["/work/target/debug/deps/nested"]),
        json!(["/usr/lib"]),
        json!([42]),
    ] {
        request["dependency_context"]["loader_dirs"] = invalid;
        assert!(parse_exec_request(&request).is_err());
    }
}

#[test]
fn generated_out_dir_requires_an_exact_optional_root_and_environment() {
    let mut request = dependency_request();
    assert!(
        parse_exec_request(&request)
            .unwrap()
            .dependency_context
            .unwrap()
            .generated_root()
            .is_none()
    );
    request["dependency_context"]["generated_root"] = Value::Null;
    assert!(
        parse_exec_request(&request)
            .unwrap()
            .dependency_context
            .unwrap()
            .generated_root()
            .is_none()
    );

    let generated = "/work/target/debug/build/generated-unit/out";
    request["dependency_context"]["generated_root"] = json!(generated);
    request["dependency_context"]["env"]
        .as_array_mut()
        .unwrap()
        .push(json!(["OUT_DIR", generated]));
    // No generated files is meaningful: the worker owns a private empty
    // read-only directory even when the build script produced no files.
    let original = request.clone();
    let decoded = parse_exec_request(&request).unwrap();
    let context = decoded.dependency_context.unwrap();
    assert_eq!(context.generated_root(), Some(generated));
    assert!(
        context
            .env()
            .contains(&("OUT_DIR".to_owned(), generated.to_owned()))
    );
    assert_eq!(
        request, original,
        "decoder changed the generated-root wire identity"
    );

    for invalid in [
        Value::Null,
        json!(true),
        json!(17),
        json!([]),
        json!({}),
        json!("/home/user/registry/package/generated"),
        json!("/home/user/toolchains/pinned/generated"),
        json!("/work/target/debug/deps/generated"),
        json!("/work/target/debug"),
        json!("/usr/generated"),
        json!("relative/generated"),
        json!("/work/generated/../out"),
    ] {
        let mut invalid_request = request.clone();
        invalid_request["dependency_context"]["generated_root"] = invalid.clone();
        // Keep coherent strings so path rejections exercise the root guard,
        // independently of the OUT_DIR agreement check.
        if invalid.is_string() {
            invalid_request["dependency_context"]["env"] = json!([["OUT_DIR", invalid]]);
        }
        assert!(parse_exec_request(&invalid_request).is_err());
    }
    for env in [
        json!([]),
        json!([["OUT_DIR", ""]]),
        json!([["OUT_DIR", "/work/other"]]),
    ] {
        let mut invalid_request = request.clone();
        invalid_request["dependency_context"]["env"] = env;
        assert!(parse_exec_request(&invalid_request).is_err());
    }
    request["dependency_context"]
        .as_object_mut()
        .unwrap()
        .remove("generated_root");
    assert!(
        parse_exec_request(&request).is_err(),
        "OUT_DIR needs an owned generated-root mapping"
    );
}

#[test]
fn generated_directory_context_requires_exact_bounded_topology_and_current_version() {
    for mut request in [
        dependency_request(),
        canonical_generated_request(false, false),
    ] {
        if request["dependency_context"]["generated_root"].is_null() {
            let generated = "/work/target/debug/build/generated-unit/out";
            request["dependency_context"]["generated_root"] = json!(generated);
            request["dependency_context"]["env"]
                .as_array_mut()
                .unwrap()
                .push(json!(["OUT_DIR", generated]));
        }
        request["dependency_context"]["generated_directories"] = json!(["empty", "empty/child"]);
        let original = request.clone();
        let context = parse_exec_request(&request)
            .unwrap()
            .dependency_context
            .unwrap();
        assert_eq!(context.generated_directories(), ["empty", "empty/child"]);
        assert_eq!(original, request);
        for directories in [
            Value::Null,
            json!([17]),
            json!([""]),
            json!(["../outside"]),
            json!(["/absolute"]),
            json!(["missing/parent"]),
            json!(["empty", "empty"]),
            json!(["empty/child", "empty"]),
            json!(["empty", "empty\\child"]),
        ] {
            let mut invalid = request.clone();
            invalid["dependency_context"]["generated_directories"] = directories;
            assert!(parse_exec_request(&invalid).is_err());
        }
        let mut omitted = request.clone();
        omitted["dependency_context"]
            .as_object_mut()
            .unwrap()
            .remove("generated_directories");
        assert!(parse_exec_request(&omitted).is_err());
        for old in ["dependency-exec-v7", "canonical-dependency-exec-v3"] {
            let mut obsolete = request.clone();
            obsolete["dependency_context"]["version"] = json!(old);
            assert!(parse_exec_request(&obsolete).is_err());
        }
    }
    let mut without_root = dependency_request();
    without_root["dependency_context"]["generated_directories"] = json!(["empty"]);
    assert!(parse_exec_request(&without_root).is_err());
}

fn dependency_dag_request() -> Value {
    use rabs_sandbox::source_transfer::{SourceFile, SourceManifest};
    let mut request = dependency_request();
    request["dependency_context"]["dependency_dirs"] = json!([
        "/work/inputs/z-first",
        "/work/target/debug/deps",
        "/work/inputs/a-second",
    ]);
    request["dependency_context"]["artifact_roots"] = json!([
        {"path":"/work/inputs/z-first", "prefix":"dependencies/0000"},
        {"path":"/work/inputs/a-second", "prefix":"dependencies/0002"},
    ]);
    let manifest = SourceManifest::new(vec![
        SourceFile {
            path: "package/src/lib.rs".to_owned(),
            len: 1,
            sha256: [1; 32],
            executable: false,
        },
        SourceFile {
            path: "dependencies/0000/libfirst.rmeta".to_owned(),
            len: 2,
            sha256: [2; 32],
            executable: false,
        },
        SourceFile {
            path: "dependencies/0002/libsecond.rlib".to_owned(),
            len: 3,
            sha256: [3; 32],
            executable: false,
        },
    ])
    .unwrap();
    let files: Vec<_> = manifest
        .files()
        .iter()
        .map(|file| {
            json!({
                "path":file.path, "bytes":file.len,
                "sha256":rabs_wkr::source_transfer::hex(&file.sha256),
                "executable":file.executable,
            })
        })
        .collect();
    request["source_manifest"] = json!({
        "files":files,
        "manifest_sha256":rabs_wkr::source_transfer::hex(&manifest.digest()),
    });
    request
}

#[test]
fn dependency_artifact_roots_preserve_first_use_mapping_when_paths_sort_differently() {
    let request = dependency_dag_request();
    let parsed = parse_exec_request(&request).unwrap();
    let context = parsed.dependency_context.unwrap();
    assert_eq!(
        context.dependency_dirs(),
        &[
            "/work/inputs/z-first".to_owned(),
            "/work/target/debug/deps".to_owned(),
            "/work/inputs/a-second".to_owned(),
        ]
    );
    // Sorting paired roots must preserve their original directory index.
    // The empty writable output root contributes no artifact mount.
    let roots = context.artifact_roots();
    assert_eq!(roots.len(), 2);
    assert_eq!(roots[0].path, "/work/inputs/a-second");
    assert_eq!(roots[0].prefix, "dependencies/0002");
    assert_eq!(roots[1].path, "/work/inputs/z-first");
    assert_eq!(roots[1].prefix, "dependencies/0000");
    assert_eq!(
        request,
        dependency_dag_request(),
        "decoder changed wire identity"
    );
}

#[test]
fn dependency_artifact_root_parser_admits_shared_output_only_under_current_contract() {
    let mut request = dependency_dag_request();
    // Keep the exact sealed manifest and first-use prefixes. This populated
    // root now also receives the worker-owned writable output directory.
    request["dependency_context"]["out_dir"] = json!("/work/inputs/z-first");
    let parsed = parse_exec_request(&request).unwrap();
    let context = parsed.dependency_context.unwrap();
    let shared = context
        .artifact_roots()
        .iter()
        .find(|root| root.path == context.out_dir())
        .unwrap();
    assert_eq!(shared.prefix, "dependencies/0000");
    for version in ["dependency-exec-v3", "dependency-exec-v4"] {
        request["dependency_context"]["version"] = json!(version);
        assert!(parse_exec_request(&request).is_err());
    }
}

#[test]
fn dependency_artifact_root_parser_requires_exact_bounded_mapping_records() {
    for removed in ["artifact_roots", "dependency_dirs"] {
        let mut request = dependency_dag_request();
        request["dependency_context"]
            .as_object_mut()
            .unwrap()
            .remove(removed);
        assert!(parse_exec_request(&request).is_err(), "{removed}");
    }
    for invalid in [
        Value::Null,
        json!(true),
        json!({}),
        json!(["/work/inputs/z-first"]),
        json!([Value::Null]),
        json!([{"path":"/work/inputs/z-first"}]),
        json!([{"prefix":"dependencies/0000"}]),
        json!([{"path":17, "prefix":"dependencies/0000"}]),
        json!([{"path":"/work/inputs/z-first", "prefix":17}]),
        json!([{"path":"/work/inputs/z-first", "prefix":"dependencies/0000", "backing":"/private"}]),
        json!([
            {"path":"/work/inputs/z-first", "prefix":"dependencies/0000"},
            {"path":"/work/inputs/z-first", "prefix":"dependencies/0000"},
        ]),
        json!([
            {"path":"/work/inputs/z-first", "prefix":"dependencies/0000"},
            {"path":"/work/inputs/a-second", "prefix":"dependencies/0000"},
        ]),
        json!([{"path":"/work/inputs/z-first", "prefix":"dependencies/0002"}]),
        json!([{"path":"/work/inputs/z-first", "prefix":"dependencies/0"}]),
        json!([{"path":"/work/inputs/z-first", "prefix":"dependencies/0000/nested"}]),
        json!([{"path":"/work/inputs/z-first", "prefix":"package"}]),
        json!([{"path":"/work/inputs/unmentioned", "prefix":"dependencies/0003"}]),
    ] {
        let mut request = dependency_dag_request();
        request["dependency_context"]["artifact_roots"] = invalid.clone();
        assert!(parse_exec_request(&request).is_err(), "{invalid}");
    }
    let mut oversized = dependency_dag_request();
    oversized["dependency_context"]["artifact_roots"] = Value::Array(
        (0..=rabs_sandbox::dependency_context::MAX_DEPENDENCY_DIRS)
            .map(|_| json!({"path":"/work/inputs/z-first", "prefix":"dependencies/0000"}))
            .collect(),
    );
    assert!(parse_exec_request(&oversized).is_err());
}

#[test]
fn dependency_context_requires_exact_negotiation_and_complete_authenticated_transfer() {
    let supported = [
        DependencyExecutionMode::Metadata,
        DependencyExecutionMode::Rlib,
    ];
    let grant = json!({
        "kind":"session-ok", "dependency_context":DEPENDENCY_CONTEXT_VERSION,
        "dependency_execution_mode":"metadata",
    })
    .to_string();
    assert_eq!(
        dependency_context_selection("{}", &supported, true, true, true, true, true).unwrap(),
        None,
    );
    assert_eq!(
        dependency_context_selection(&grant, &supported, true, true, true, true, true).unwrap(),
        Some(original_selection(DependencyExecutionMode::Metadata)),
    );
    for flags in [
        [false, true, true, true, true],
        [true, false, true, true, true],
        [true, true, false, true, true],
        [true, true, true, false, true],
        [true, true, true, true, false],
    ] {
        assert!(
            dependency_context_selection(
                &grant, &supported, flags[0], flags[1], flags[2], flags[3], flags[4],
            )
            .is_err()
        );
    }
    for bad in [
        Value::Null,
        json!(true),
        json!("dependency-exec-v1"),
        json!("dependency-exec-v2"),
        json!("dependency-exec-v3"),
        json!("dependency-exec-v4"),
        json!("dependency-exec-v5"),
        json!("dependency-exec-v6"),
        json!("dependency-exec-v999"),
        json!("canonical-dependency-exec-v1"),
        json!("canonical-dependency-exec-v2"),
    ] {
        assert!(
            dependency_context_selection(
                &json!({"dependency_context":bad}).to_string(),
                &supported,
                true,
                true,
                true,
                true,
                true
            )
            .is_err()
        );
    }
}

#[test]
fn dependency_mode_selection_never_infers_support_or_downgrades() {
    for mode in [
        DependencyExecutionMode::Metadata,
        DependencyExecutionMode::Rlib,
    ] {
        let grant = json!({
            "dependency_context":DEPENDENCY_CONTEXT_VERSION,
            "dependency_execution_mode":mode.as_str(),
        });
        assert_eq!(
            dependency_context_selection(
                &grant.to_string(), &[mode], true, true, true, true, true,
            ).unwrap(),
            Some(original_selection(mode)),
        );
        for unsupported in [
            vec![],
            vec![if mode == DependencyExecutionMode::Metadata {
                DependencyExecutionMode::Rlib
            } else {
                DependencyExecutionMode::Metadata
            }],
        ] {
            assert!(
                dependency_context_selection(
                    &grant.to_string(),
                    &unsupported,
                    true,
                    true,
                    true,
                    true,
                    true,
                )
                .is_err()
            );
        }
        let mut missing = grant.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("dependency_execution_mode");
        let mut unversioned = grant.clone();
        unversioned
            .as_object_mut()
            .unwrap()
            .remove("dependency_context");
        for bad in [missing, unversioned] {
            assert!(
                dependency_context_selection(
                    &bad.to_string(),
                    &[mode],
                    true,
                    true,
                    true,
                    true,
                    true,
                )
                .is_err()
            );
        }
        for bad_mode in [
            Value::Null,
            json!(true),
            json!([]),
            json!("Rlib"),
            json!("future"),
        ] {
            let mut bad = grant.clone();
            bad["dependency_execution_mode"] = bad_mode;
            assert!(
                dependency_context_selection(
                    &bad.to_string(),
                    &[mode],
                    true,
                    true,
                    true,
                    true,
                    true,
                )
                .is_err()
            );
        }
    }
}

#[test]
fn canonical_dependency_negotiation_binds_version_as_well_as_mode() {
    let grant = json!({
        "dependency_context":CANONICAL_DEPENDENCY_CONTEXT_VERSION,
        "dependency_execution_mode":"metadata",
    });
    let selected = dependency_context_selection(
        &grant.to_string(),
        &[DependencyExecutionMode::Metadata],
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap()
    .unwrap();
    assert_eq!(selected.version, CANONICAL_DEPENDENCY_CONTEXT_VERSION);
    assert_eq!(selected.mode, DependencyExecutionMode::Metadata);
    for previous in [
        "canonical-dependency-exec-v1",
        "canonical-dependency-exec-v2",
        "canonical-dependency-exec-v3",
    ] {
        let mut old = grant.clone();
        old["dependency_context"] = json!(previous);
        assert!(
            dependency_context_selection(
                &old.to_string(),
                &[DependencyExecutionMode::Metadata],
                true,
                true,
                true,
                true,
                true,
            )
            .is_err()
        );
    }
    for flags in [
        [false, true, true, true, true],
        [true, false, true, true, true],
        [true, true, false, true, true],
        [true, true, true, false, true],
        [true, true, true, true, false],
    ] {
        assert!(
            dependency_context_selection(
                &grant.to_string(),
                &[DependencyExecutionMode::Metadata],
                flags[0],
                flags[1],
                flags[2],
                flags[3],
                flags[4],
            )
            .is_err()
        );
    }
    let mut archive = grant.clone();
    archive["dependency_execution_mode"] = json!("rlib");
    let archive_selected = dependency_context_selection(
        &archive.to_string(),
        &[DependencyExecutionMode::Rlib],
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        archive_selected.version,
        CANONICAL_DEPENDENCY_CONTEXT_VERSION
    );
    assert_eq!(archive_selected.mode, DependencyExecutionMode::Rlib);
    assert!(
        dependency_context_selection(
            &archive.to_string(),
            &[DependencyExecutionMode::Metadata],
            true,
            true,
            true,
            true,
            true,
        )
        .is_err()
    );
    let mut report = report();
    report.dependency_modes = vec![DependencyExecutionMode::Metadata];
    let canonical = parse_exec_request(&canonical_dependency_request()).unwrap();
    let ordinary = parse_exec_request(&dependency_request()).unwrap();
    assert!(validate_execution_selection(&canonical, &report, Some(selected)).is_ok());
    assert_eq!(
        validate_execution_selection(&ordinary, &report, Some(selected)).unwrap_err(),
        "dependency context version does not match negotiation",
    );
    assert_eq!(
        validate_execution_selection(
            &canonical,
            &report,
            Some(original_selection(DependencyExecutionMode::Metadata))
        )
        .unwrap_err(),
        "dependency context version does not match negotiation",
    );
    let archive = parse_exec_request(&canonical_archive_request(true)).unwrap();
    assert!(validate_execution_selection(&archive, &report, Some(archive_selected)).is_err());
    report.dependency_modes = vec![
        DependencyExecutionMode::Metadata,
        DependencyExecutionMode::Rlib,
    ];
    assert!(validate_execution_selection(&archive, &report, Some(archive_selected)).is_ok());
    assert_eq!(
        validate_execution_selection(&archive, &report, Some(selected)).unwrap_err(),
        "dependency execution mode does not match negotiation"
    );
    assert_eq!(
        validate_execution_selection(&canonical, &report, Some(archive_selected)).unwrap_err(),
        "dependency execution mode does not match negotiation"
    );
}

#[test]
fn workspace_execution_requires_its_own_negotiated_version_in_both_modes() {
    let mut report = report();
    report.dependency_modes = vec![
        DependencyExecutionMode::Metadata,
        DependencyExecutionMode::Rlib,
    ];
    for (archive, mode) in [
        (false, DependencyExecutionMode::Metadata),
        (true, DependencyExecutionMode::Rlib),
    ] {
        let grant = json!({"dependency_context":CANONICAL_WORKSPACE_CONTEXT_VERSION,
            "dependency_execution_mode":mode.as_str()});
        let selected = dependency_context_selection(
            &grant.to_string(),
            &report.dependency_modes,
            true,
            true,
            true,
            true,
            true,
        )
        .unwrap()
        .unwrap();
        let workspace = parse_exec_request(&canonical_workspace_request(archive)).unwrap();
        assert!(validate_execution_selection(&workspace, &report, Some(selected)).is_ok());
        for version in [
            DEPENDENCY_CONTEXT_VERSION,
            CANONICAL_DEPENDENCY_CONTEXT_VERSION,
        ] {
            assert!(
                validate_execution_selection(
                    &workspace,
                    &report,
                    Some(DependencySelection { version, mode }),
                )
                .is_err()
            );
        }
        let dependency = parse_exec_request(&canonical_dependency_request()).unwrap();
        assert!(validate_execution_selection(&dependency, &report, Some(selected)).is_err());
    }
}

#[cfg(unix)]
#[test]
fn canonical_dependency_version_swap_refuses_before_input_or_durable_admission() {
    let root = private_root();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut report = report();
    report.dependency_modes = vec![DependencyExecutionMode::Metadata];
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(canonical_dependency_request());
    peer.frame(json!({"kind":"request-status","request_id":712}));
    peer.close();
    wait(drive_session_with_inputs(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        true,
        true,
        true,
        false,
        &ExecutionLeaseSelection::default(),
        false,
        Some(original_selection(DependencyExecutionMode::Metadata)),
        |_, _, _, _, _, _| panic!("wrong dependency path policy reached executor"),
        pressure,
    ))
    .unwrap();
    let replies = peer.replies();
    assert_eq!(replies[0]["kind"], "error");
    assert_eq!(
        replies[0]["reason"],
        "dependency context version does not match negotiation"
    );
    assert_eq!(replies[1]["status"], "unknown");
    assert_eq!(journal.high_water(), None);
}

#[test]
fn archive_only_capability_never_authorizes_metadata_or_canonical_commands() {
    let mut archive_only = report();
    archive_only.canonical_namespace = false;
    archive_only.dependency_modes = vec![DependencyExecutionMode::Rlib];
    let archive = parse_exec_request(&archive_request(true)).unwrap();
    let metadata = parse_exec_request(&dependency_request()).unwrap();
    let canonical = parse_exec_request(&request(19)).unwrap();
    assert!(
        validate_execution_selection(
            &archive,
            &archive_only,
            Some(original_selection(DependencyExecutionMode::Rlib)),
        )
        .is_ok()
    );
    assert!(validate_execution_selection(&archive, &archive_only, None).is_err());
    assert!(
        validate_execution_selection(
            &archive,
            &archive_only,
            Some(original_selection(DependencyExecutionMode::Metadata)),
        )
        .is_err()
    );
    assert!(
        validate_execution_selection(
            &metadata,
            &archive_only,
            Some(original_selection(DependencyExecutionMode::Rlib)),
        )
        .is_err()
    );
    assert!(
        validate_execution_selection(
            &metadata,
            &archive_only,
            Some(original_selection(DependencyExecutionMode::Metadata)),
        )
        .is_err()
    );
    assert!(validate_execution_selection(&canonical, &archive_only, None).is_err());
    assert!(
        validate_execution_selection(
            &canonical,
            &archive_only,
            Some(original_selection(DependencyExecutionMode::Rlib)),
        )
        .is_err()
    );
    archive_only.canonical_namespace = true;
    assert!(validate_execution_selection(&canonical, &archive_only, None).is_ok());
    assert!(
        validate_execution_selection(
            &canonical,
            &archive_only,
            Some(original_selection(DependencyExecutionMode::Rlib)),
        )
        .is_err()
    );
}

#[test]
fn dependency_decoder_refuses_unowned_inputs_ambiguous_context_and_unmodeled_loader() {
    for (key, value) in [
        (
            "command_context",
            json!({"version":"env-cwd-v1","cwd":"/__rabs/workspace","env":{}}),
        ),
        (
            "workspace_backing",
            json!("/private/caller-selected-source"),
        ),
        (
            "toolchain_backing",
            json!("/private/caller-selected-toolchain"),
        ),
        ("program", json!("/bin/sh")),
        ("dependency_context", Value::Null),
    ] {
        let mut request = dependency_request();
        request[key] = value;
        assert!(parse_exec_request(&request).is_err(), "{key}");
    }
    for removed in [
        "source_manifest",
        "toolchain_transfer",
        "toolchain_identity",
    ] {
        let mut request = dependency_request();
        request.as_object_mut().unwrap().remove(removed);
        assert!(parse_exec_request(&request).is_err(), "{removed}");
    }
    for (key, value) in [
        ("version", json!("dependency-exec-v999")),
        ("extra_backing", json!("/private/hidden")),
        ("runtime_cohort_sha256", json!("AB".repeat(32))),
        ("env", json!([["SECRET", "first"], ["SECRET", "second"]])),
        ("env", json!([["LD_PRELOAD", "/secret/control"]])),
    ] {
        let mut request = dependency_request();
        request["dependency_context"][key] = value;
        let reason = parse_exec_request(&request).unwrap_err();
        assert!(
            !reason.contains("/secret/control")
                && !reason.contains("first")
                && !reason.contains("second")
        );
    }
}

#[cfg(unix)]
#[test]
fn unnegotiated_dependency_request_never_burns_durable_admission() {
    let root = private_root();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(dependency_request());
    peer.frame(json!({"kind":"request-status","request_id":712}));
    peer.close();
    wait(drive_session(
        &mut wire,
        &report(),
        false,
        Some(&mut journal),
        false,
        |_, _, _| panic!("unnegotiated dependency reached executor"),
        pressure,
    ))
    .unwrap();
    let replies = peer.replies();
    assert_eq!(replies[0]["kind"], "error");
    assert_eq!(replies[0]["reason"], "dependency context not negotiated");
    assert_eq!(replies[1]["status"], "unknown");
    assert_eq!(journal.high_water(), None);
    let hello: Value = serde_json::from_str(&worker_hello(&report(), &journal)).unwrap();
    assert_eq!(
        hello["dependency_contexts"],
        json!([
            DEPENDENCY_CONTEXT_VERSION,
            CANONICAL_DEPENDENCY_CONTEXT_VERSION,
            CANONICAL_WORKSPACE_CONTEXT_VERSION
        ])
    );
    assert_eq!(hello["dependency_execution_modes"], json!([]));
}

#[cfg(unix)]
#[test]
fn archive_mode_mismatch_refuses_before_input_or_durable_admission() {
    let root = private_root();
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    let mut report = report();
    report.canonical_namespace = false;
    report.dependency_modes = vec![DependencyExecutionMode::Rlib];
    let hello: Value = serde_json::from_str(&worker_hello(&report, &journal)).unwrap();
    assert_eq!(hello["canonical"], false);
    assert_eq!(hello["dependency_execution_modes"], json!(["rlib"]));
    let mut wire = Wire::default();
    let peer = wire.clone();
    peer.frame(dependency_request());
    peer.frame(request(713));
    peer.frame(json!({"kind":"request-status","request_id":712}));
    peer.close();
    wait(drive_session_with_inputs(
        &mut wire,
        &report,
        false,
        Some(&mut journal),
        true,
        true,
        true,
        false,
        &ExecutionLeaseSelection::default(),
        false,
        Some(original_selection(DependencyExecutionMode::Rlib)),
        |_, _, _, _, _, _| panic!("mismatched namespace reached executor"),
        pressure,
    ))
    .unwrap();
    let replies = peer.replies();
    assert_eq!(
        replies[0]["reason"],
        "dependency execution mode does not match negotiation"
    );
    assert_eq!(
        replies[1]["reason"],
        "dependency session requires its negotiated execution context"
    );
    assert_eq!(replies[2]["status"], "unknown");
    assert_eq!(journal.high_water(), None);
}

#[cfg(unix)]
#[test]
fn retained_dependency_result_resumes_without_execution_or_input_grants() {
    assert_retained_dependency_resume(DEPENDENCY_CONTEXT_VERSION);
}

#[cfg(unix)]
#[test]
fn retained_v1_dependency_result_remains_recoverable_after_context_upgrade() {
    assert_retained_dependency_resume("dependency-exec-v1");
}

#[cfg(unix)]
#[test]
fn retained_v2_dependency_result_remains_recoverable_after_context_upgrade() {
    assert_retained_dependency_resume("dependency-exec-v2");
}

#[cfg(unix)]
#[test]
fn retained_v3_dependency_result_remains_recoverable_after_context_upgrade() {
    assert_retained_dependency_resume("dependency-exec-v3");
}

#[cfg(unix)]
#[test]
fn retained_v4_dependency_result_remains_recoverable_after_context_upgrade() {
    assert_retained_dependency_resume("dependency-exec-v4");
}

#[cfg(unix)]
#[test]
fn retained_v7_dependency_result_remains_recoverable_after_directory_contract_upgrade() {
    assert_retained_dependency_resume("dependency-exec-v7");
}

#[cfg(unix)]
fn assert_retained_dependency_resume(version: &str) {
    let root = private_root();
    let mut original = dependency_request();
    // This fixture seals known bytes to exercise result recovery only. It does
    // not claim rustc execution; the real compiler oracle is separate.
    original["artifacts"] = json!({"unit":"leaf","files":["lib.rlib"]});
    let execution = parse_exec_request(&original).unwrap();
    // Simulate bytes durably retained under the older accepted execution
    // context. The current worker must reject it for new execution, while the
    // exact saved fingerprint still authorizes retrieval-only recovery.
    original["dependency_context"]["version"] = json!(version);
    if version != DEPENDENCY_CONTEXT_VERSION {
        original["dependency_context"]
            .as_object_mut()
            .unwrap()
            .remove("generated_directories");
        if matches!(version, "dependency-exec-v1" | "dependency-exec-v2") {
            original["dependency_context"]
                .as_object_mut()
                .unwrap()
                .remove("artifact_roots");
        }
        assert!(parse_exec_request(&original).is_err());
    }
    let id = original["request_id"].as_u64().unwrap();
    {
        let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
        assert_eq!(
            journal.admit(&original, DEFAULT_EXECUTION_TIMEOUT).unwrap(),
            None
        );
        let mut task = retained_launch(
            root.path(),
            execution,
            DEFAULT_EXECUTION_TIMEOUT,
            artifacts::parse_plan(&original).unwrap(),
        )
        .unwrap();
        let completion = wait(task.wait());
        assert!(completion.is_ok(), "{completion:?}");
        journal_completion(
            Some(&mut journal),
            id,
            &completion,
            task.retained_result_digest().as_deref(),
        )
        .unwrap();
        assert!(journal.has_retained_result());
    }
    let mut journal = WorkerJournal::open(root.path(), "session-test", "coord").unwrap();
    journal.authorize_result_recipient(ResultRecipient::TlsSpki([7; 32]));
    let mut wire = Wire::default();
    let peer = wire.clone();
    let mut changed = original.clone();
    changed["dependency_context"]["cwd"] = json!("/home/user/registry/package/src");
    peer.frame(json!({"kind":"result-resume","request_id":id,"request":changed}));
    let mut changed_tree = original.clone();
    changed_tree["dependency_context"]["generated_directories"] = json!(["empty"]);
    peer.frame(json!({"kind":"result-resume","request_id":id,"request":changed_tree}));
    peer.frame(json!({"kind":"result-resume","request_id":id,"request":original}));
    let mut report = report();
    // Retained bytes remain recoverable even if the host can no longer create
    // any execution namespace after a worker restart.
    report.canonical_namespace = false;
    report.dependency_modes.clear();
    // This production compatibility wrapper selects no source, toolchain,
    // dependency context or execution-lease grant. Recovery needs only the
    // exact original request and authorized retained-result recipient.
    let mut driver = Box::pin(drive_session(
        &mut wire,
        &report,
        true,
        Some(&mut journal),
        true,
        |_, _, _| panic!("retained dependency recovery invoked execution"),
        pressure,
    ));
    pump(driver.as_mut(), &peer, 3);
    assert_eq!(peer.replies()[0]["kind"], "error");
    assert_eq!(peer.replies()[1]["kind"], "error");
    let resumed = peer.replies()[2].clone();
    assert_eq!(resumed["kind"], "exec-result");
    assert_eq!(resumed["resumed"], true);
    peer.frame(output_read(id, "stdout", 1, 3));
    peer.frame(
        json!({"kind":"artifact-read","request_id":id,"name":"lib.rlib","offset":0,"max_bytes":64}),
    );
    pump(driver.as_mut(), &peer, 5);
    assert_eq!(peer.replies()[3]["data_hex"], "00ff42");
    assert_eq!(peer.replies()[4]["data_hex"], "6172636869766500ff");
    peer.frame(output_ack(id));
    peer.frame(json!({"kind":"artifact-ack","request_id":id,
        "manifest_sha256":resumed["artifact_manifest"]["manifest_sha256"],
        "total_bytes":resumed["artifact_manifest"]["total_bytes"]}));
    wait(driver).unwrap();
    assert_eq!(
        journal.status(id)["receipt"]["retained_result_released"],
        true
    );
}
