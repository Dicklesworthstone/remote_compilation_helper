//! Conformance: the derived output set equals what rustc ACTUALLY
//! produces (bead bd-14t4j, derivation slice).
//!
//! `output_derivation` encodes rustc's file-naming rules. Encoded rules
//! drift from the tool they describe, and this particular drift is
//! expensive: a wrapper that skips a compile on the strength of a
//! derivation gets a build missing a file it was promised. So the oracle
//! here is not a table of expected strings — it is rustc. Each case runs
//! the real compiler into a scratch out-dir and compares the file set
//! that appears against the file set that was derived, exactly.
//!
//! `--print file-names` is deliberately NOT the oracle: it reports link
//! outputs only, so it would leave `.rmeta`/`.d` derivation unchecked —
//! the very outputs `cargo check` traffic consists of.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::process::Command;

use rabs_key::invocation::parse;
use rabs_key::output_derivation::{
    derive_dependency_output_declarations, derive_output_declarations,
    derive_workspace_output_declarations,
};

/// The host triple this rustc builds for by default.
fn host_triple() -> String {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .expect("run rustc -vV");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .expect("rustc -vV reports a host")
}

/// Run rustc for real and return the file names it wrote into `out_dir`.
fn actually_produced(
    args: &[String],
    source: &std::path::Path,
    out_dir: &std::path::Path,
) -> BTreeSet<String> {
    std::fs::create_dir_all(out_dir).unwrap();
    let output = Command::new("rustc")
        .args(args)
        .arg("--out-dir")
        .arg(out_dir)
        .arg(source)
        .output()
        .expect("run rustc");
    assert!(
        output.status.success(),
        "rustc failed for {args:?}:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read_dir(out_dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

fn derived(args: &[String], source: &std::path::Path, host: &str) -> BTreeSet<String> {
    let argv: Vec<String> = std::iter::once("rustc".to_owned())
        .chain(args.iter().cloned())
        .chain(std::iter::once(source.display().to_string()))
        .collect();
    let invocation = parse(&argv, None).expect("parse");
    derive_output_declarations(&invocation, host)
        .expect("derive")
        .declarations
        .into_iter()
        .map(|d| d.virtual_path)
        .collect()
}

fn case(args: &[&str]) -> Vec<String> {
    args.iter().map(|a| (*a).to_owned()).collect()
}

#[test]
fn derived_outputs_equal_what_rustc_writes() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib.rs");
    std::fs::write(&lib, "pub fn f() -> u32 { 7 }\n").unwrap();
    let main = dir.path().join("main.rs");
    std::fs::write(&main, "fn main() { println!(\"hi\"); }\n").unwrap();
    let host = host_triple();

    // (args, source) — the shapes cargo actually emits: a build, a
    // check, a binary, a cdylib, a staticlib, and the multi-emit and
    // multi-crate-type combinations.
    let cases: Vec<(Vec<String>, &std::path::Path)> = vec![
        (
            case(&["--crate-name", "foo", "--crate-type", "rlib"]),
            lib.as_path(),
        ),
        (
            case(&[
                "--crate-name",
                "foo",
                "--crate-type",
                "rlib",
                "--emit=link,metadata,dep-info",
                "-C",
                "extra-filename=-abc123",
            ]),
            lib.as_path(),
        ),
        (
            // `cargo check`: metadata + dep-info, no link. Cargo still
            // passes --crate-type (rustc's own default is `bin`, which
            // is why the derivation refuses rather than assuming `lib`).
            case(&[
                "--crate-name",
                "foo",
                "--crate-type",
                "lib",
                "--emit=metadata,dep-info",
                "-C",
                "extra-filename=-9f0e",
            ]),
            lib.as_path(),
        ),
        (
            case(&["--crate-name", "foo", "--crate-type", "lib"]),
            lib.as_path(),
        ),
        (
            case(&[
                "--crate-name",
                "app",
                "--crate-type",
                "bin",
                "--emit=link,dep-info",
            ]),
            main.as_path(),
        ),
        (
            case(&["--crate-name", "foo", "--crate-type", "cdylib"]),
            lib.as_path(),
        ),
        (
            case(&["--crate-name", "foo", "--crate-type", "staticlib"]),
            lib.as_path(),
        ),
        (
            case(&[
                "--crate-name",
                "foo",
                "--crate-type",
                "rlib",
                "--crate-type",
                "cdylib",
                "-C",
                "extra-filename=-multi",
            ]),
            lib.as_path(),
        ),
    ];

    for (index, (args, source)) in cases.iter().enumerate() {
        let out_dir = dir.path().join(format!("out{index}"));
        let produced = actually_produced(args, source, &out_dir);
        let derived = derived(args, source, &host);
        assert_eq!(
            derived, produced,
            "case {index} ({args:?}): derivation and rustc disagree\n\
             derived:  {derived:?}\n\
             produced: {produced:?}"
        );
    }
}

#[test]
fn workspace_binary_and_test_metadata_match_actual_empty_rmeta_and_dep_info() {
    let owner = tempfile::tempdir().unwrap();
    let source = owner.path().join("selected.rs");
    std::fs::write(
        &source,
        "fn main() {}\n#[test] fn checked_without_running() { panic!(\"metadata must not run tests\"); }\n",
    )
    .unwrap();
    let host = host_triple();
    for (index, shape) in [
        case(&["--crate-type=bin"]),
        case(&["--test"]),
        case(&["--test", "--crate-type=lib"]),
        case(&["--test", "--crate-type=rlib"]),
        case(&["--test", "--crate-type=bin"]),
    ]
    .into_iter()
    .enumerate()
    {
        let output = owner.path().join(format!("metadata-{index}"));
        let mut args = case(&[
            "--crate-name=selected",
            "--edition=2024",
            "--emit=dep-info,metadata",
            "-Cextra-filename=-checked",
        ]);
        args.extend(shape);
        let produced = actually_produced(&args, &source, &output);
        let argv = std::iter::once("rustc".to_owned())
            .chain(args)
            .chain(["--out-dir".into(), output.display().to_string()])
            .chain([source.display().to_string()])
            .collect::<Vec<_>>();
        let invocation = parse(&argv, None).unwrap();
        let expected = derive_workspace_output_declarations(&invocation, &host).unwrap();
        assert_eq!(
            produced,
            expected
                .declarations
                .iter()
                .map(|entry| entry.virtual_path.clone())
                .collect::<BTreeSet<_>>(),
            "actual compiler outputs differ for {argv:?}"
        );
        assert!(expected.declarations.iter().all(|entry| !entry.optional));
        assert_eq!(
            std::fs::metadata(output.join("libselected-checked.rmeta"))
                .unwrap()
                .len(),
            0
        );
        assert!(
            std::fs::metadata(output.join("selected-checked.d"))
                .unwrap()
                .len()
                > 0
        );
        assert!(derive_dependency_output_declarations(&invocation, &host).is_err());
    }
}

#[test]
fn a_refusal_is_returned_rather_than_a_wrong_answer() {
    // rustc DOES have a default crate type; we deliberately refuse
    // instead of encoding a guess that differs by rustc version. This
    // test pins that choice so nobody "helpfully" defaults it later
    // without also proving the default against the compiler.
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib.rs");
    std::fs::write(&lib, "pub fn f() {}\n").unwrap();
    let argv = vec![
        "rustc".to_owned(),
        "--crate-name".to_owned(),
        "foo".to_owned(),
        lib.display().to_string(),
    ];
    let invocation = parse(&argv, None).expect("parse");
    let outcome = derive_output_declarations(&invocation, &host_triple());
    assert!(
        outcome.is_err(),
        "a link build with no --crate-type must refuse, got {outcome:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn dependency_serving_declarations_match_real_build_and_check_in_two_roots() {
    use rabs_key::output_derivation::derive_dependency_output_declarations;

    let dir = tempfile::tempdir().unwrap();
    let host = host_triple();
    for emit in ["dep-info,metadata,link", "dep-info,metadata"] {
        let mut first_digest = None;
        for root in ["first worktree", "second worktree"] {
            let worktree = dir.path().join(emit).join(root);
            std::fs::create_dir_all(&worktree).unwrap();
            let source = worktree.join("lib.rs");
            std::fs::write(&source, "pub fn answer() -> u32 { 42 }\n").unwrap();
            let out_dir = worktree.join("target/debug/deps");
            let args = case(&[
                "--crate-name",
                "foo",
                "--crate-type",
                "lib",
                "--edition=2024",
                "--emit",
                emit,
                "-C",
                "extra-filename=-123",
                "-C",
                "debuginfo=2",
                "-C",
                "embed-bitcode=no",
                "--error-format=json",
                "--json=diagnostic-rendered-ansi,artifacts",
                "--check-cfg",
                "cfg(docsrs,test)",
            ]);
            let mut argv = vec!["rustc".to_owned()];
            argv.extend(args.iter().cloned());
            argv.extend([
                "--out-dir".to_owned(),
                out_dir.to_str().unwrap().to_owned(),
                source.to_str().unwrap().to_owned(),
            ]);
            let invocation = parse(&argv, None).unwrap();
            let declarations = derive_dependency_output_declarations(&invocation, &host).unwrap();
            let expected: BTreeSet<_> = declarations
                .declarations
                .iter()
                .map(|output| output.virtual_path.clone())
                .collect();
            assert_eq!(expected, actually_produced(&args, &source, &out_dir));
            let digest = declarations.declaration_digest().unwrap();
            if let Some(first) = &first_digest {
                assert_eq!(
                    first, &digest,
                    "subscriber root must not rename declared outputs"
                );
            } else {
                first_digest = Some(digest);
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cargo_separate_metadata_mode_produces_every_declared_output() {
    use rabs_key::output_derivation::derive_dependency_output_declarations;

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("lib.rs");
    std::fs::write(&source, "pub fn answer() -> u32 { 42 }\n").unwrap();
    let host = host_triple();
    for emit in ["dep-info,metadata,link", "dep-info,metadata"] {
        let out_dir = dir.path().join(emit);
        let args = case(&[
            "--crate-name",
            "foo",
            "--crate-type",
            "lib",
            "--edition=2024",
            "--emit",
            emit,
            "-Z",
            "embed-metadata=no",
            "-C",
            "embed-bitcode=no",
            "-C",
            "extra-filename=-123",
            "--error-format=json",
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
            "--cap-lints",
            "allow",
        ]);
        let mut argv = vec!["rustc".to_owned()];
        argv.extend(args.iter().cloned());
        argv.extend([
            "--out-dir".to_owned(),
            out_dir.to_str().unwrap().to_owned(),
            source.to_str().unwrap().to_owned(),
        ]);
        let invocation = parse(&argv, None).unwrap();
        let declared: BTreeSet<_> = derive_dependency_output_declarations(&invocation, &host)
            .unwrap()
            .declarations
            .into_iter()
            .map(|output| output.virtual_path)
            .collect();
        assert!(declared.contains("libfoo-123.rmeta"));
        assert_eq!(
            declared,
            actually_produced(&args, &source, &out_dir),
            "Cargo's separate-metadata mode must not hide or add any output"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn save_temps_really_adds_files_that_dependency_serving_must_not_omit() {
    use rabs_key::output_derivation::derive_dependency_output_declarations;

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("lib.rs");
    std::fs::write(&source, "pub fn answer() -> u32 { 42 }\n").unwrap();
    let out_dir = dir.path().join("out");
    let args = case(&[
        "--crate-name",
        "foo",
        "--crate-type",
        "rlib",
        "--emit=dep-info,metadata,link",
        "-C",
        "save-temps=yes",
    ]);
    let produced = actually_produced(&args, &source, &out_dir);
    let named = derived(&args, &source, &host_triple());
    assert!(
        !produced.is_subset(&named),
        "the regression must exercise real extra outputs: {produced:?}"
    );
    let mut argv = vec!["rustc".to_owned()];
    argv.extend(args);
    argv.extend([
        "--out-dir".to_owned(),
        out_dir.to_str().unwrap().to_owned(),
        source.to_str().unwrap().to_owned(),
    ]);
    let invocation = parse(&argv, None).unwrap();
    assert!(derive_dependency_output_declarations(&invocation, &host_triple()).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn real_rustc_diagnostic_widths_have_distinct_live_replay_keys() {
    use std::path::Path;

    use rabs_key::live_dependency::{
        LiveRustcRequest, ToolchainFacts, canonicalize_compiler_transcript, live_dependency_key,
        plan_dependency_action,
    };
    use rabs_key::typed_digest::compute;
    use rabs_protocol::input_evidence::{
        ActionInputManifest, INPUT_EVIDENCE_SCHEMA_VERSION, InputFileType, PositiveInput,
    };
    use rabs_protocol::raw_bytes::RawBytes;
    use rabs_protocol::result_identity::ObjectId;

    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .expect("probe real rustc sysroot");
    assert!(sysroot.status.success());
    let rustc = Path::new(String::from_utf8(sysroot.stdout).unwrap().trim()).join("bin/rustc");
    let version = Command::new(&rustc).arg("-vV").output().unwrap();
    assert!(version.status.success());
    // The fixture's fixed identities isolate the presentation component;
    // the actual compiler/version and source stay identical in all runs.
    let digest = |tag: u8| compute("rabs.test-object.v1", &[tag]);
    let facts = ToolchainFacts {
        compiler_binary_digest: digest(1),
        verbose_version: String::from_utf8(version.stdout).unwrap(),
        sysroot_root_digest: digest(2),
        runtime_libraries: vec![digest(3)],
    };
    let host = facts.host_triple().unwrap();
    let temporary = tempfile::tempdir().unwrap();
    let cargo_home = temporary.path().join("cargo-home");
    let package = cargo_home.join("registry/src/index.example-0123456789abcdef/width-1.0.0");
    std::fs::create_dir_all(package.join("src")).unwrap();
    std::fs::write(
        package.join("Cargo.toml"),
        "[package]\nname='width'\nversion='1.0.0'\n",
    )
    .unwrap();
    let source = package.join("src/lib.rs");
    std::fs::write(
        &source,
        "pub fn render() { let a_long_variable_name_that_is_deliberately_unused_to_exercise_the_compiler_diagnostic_width_contract = 1; }\n",
    )
    .unwrap();
    let environment = vec![
        ("CARGO_HOME".into(), cargo_home.display().to_string()),
        ("CARGO_MANIFEST_DIR".into(), package.display().to_string()),
        ("CARGO_PKG_NAME".into(), "width".into()),
    ];
    let mut runs = Vec::new();
    for (index, width, attached) in [(0, "30", false), (1, "160", false), (2, "30", true)] {
        let out = temporary.path().join(format!("out-{index}"));
        std::fs::create_dir(&out).unwrap();
        let mut arguments = vec![
            rustc.display().to_string(),
            "--crate-name=width".into(),
            "--crate-type=lib".into(),
            "--emit=dep-info,metadata".into(),
            "--error-format=json".into(),
            "--force-warn=unused_variables".into(),
            "--cap-lints=allow".into(),
            "--out-dir".into(),
            out.display().to_string(),
            source.display().to_string(),
        ];
        if attached {
            arguments.push(format!("--diagnostic-width={width}"));
        } else {
            arguments.extend(["--diagnostic-width".into(), width.into()]);
        }
        let plan = plan_dependency_action(
            LiveRustcRequest {
                argv: &arguments,
                cwd: package.to_str().unwrap(),
                env: &environment,
            },
            host,
        )
        .unwrap();
        let output = Command::new(&rustc)
            .args(&arguments[1..])
            .env_clear()
            .envs(plan.execution_env.iter().cloned())
            .current_dir(&package)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        let transcript = canonicalize_compiler_transcript(&output.stderr, &plan).unwrap();
        assert!(
            transcript
                .windows(b"unused variable".len())
                .any(|bytes| bytes == b"unused variable")
        );
        let input = |relative: &str, tag: u8| PositiveInput {
            virtual_path: RawBytes::new(plan.input_virtual_path(relative).into_bytes()),
            object: ObjectId(digest(tag)),
            file_type: InputFileType::Regular,
            executable: false,
            symlink_resolution: Vec::new(),
        };
        let inputs = ActionInputManifest {
            schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
            inputs: vec![input("Cargo.toml", 10), input("src/lib.rs", 11)],
            ..ActionInputManifest::default()
        };
        let key = live_dependency_key(&plan, &facts, &[], &[], None, &inputs)
            .unwrap()
            .action_key;
        runs.push((
            key,
            transcript,
            std::fs::read(out.join("libwidth.rmeta")).unwrap(),
        ));
    }
    assert_ne!(
        runs[0].1, runs[1].1,
        "real rustc renders different diagnostic widths"
    );
    assert_eq!(
        runs[0].2, runs[1].2,
        "only presentation changed, not metadata"
    );
    assert_ne!(
        runs[0].0, runs[1].0,
        "different real transcripts must have different replay keys"
    );
    assert_eq!(
        runs[0], runs[2],
        "attached and separate widths preserve exact output and reuse"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn compiler_option_errors_and_first_lint_cap_never_become_false_cache_hits() {
    use rabs_key::invocation::ParseError;
    use rabs_key::live_dependency::{LiveRefusal, LiveRustcRequest, plan_dependency_action};

    let owner = tempfile::tempdir().unwrap();
    let cargo_home = owner.path().join("cargo-home");
    let package = cargo_home.join("registry/src/index.example-0123456789abcdef/options-1.0.0");
    let out = owner.path().join("out");
    std::fs::create_dir_all(package.join("src")).unwrap();
    std::fs::create_dir(&out).unwrap();
    let source = package.join("src/lib.rs");
    std::fs::write(&source, "pub fn f() { let unused_variable = 1; }\n").unwrap();
    let host = host_triple();
    let env = vec![
        ("CARGO_HOME".into(), cargo_home.display().to_string()),
        ("CARGO_MANIFEST_DIR".into(), package.display().to_string()),
        ("CARGO_PKG_NAME".into(), "options".into()),
    ];
    let base = vec![
        "rustc".to_owned(),
        "--crate-name=options".into(),
        "--crate-type=lib".into(),
        "--edition=2021".into(),
        format!("--target={host}"),
        "--emit=dep-info,metadata".into(),
        "--error-format=json".into(),
        "-Dunused_variables".into(),
        "--out-dir".into(),
        out.display().to_string(),
        source.display().to_string(),
    ];
    let plan = |argv: &[String]| {
        plan_dependency_action(
            LiveRustcRequest {
                argv,
                cwd: package.to_str().unwrap(),
                env: &env,
            },
            &host,
        )
    };
    let run = |argv: &[String]| Command::new("rustc").args(&argv[1..]).output().unwrap();
    let mut valid = base.clone();
    valid.push("--cap-lints=allow".into());
    assert!(plan(&valid).is_ok());
    let output = run(&valid);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    for (flag, value) in [
        ("--crate-name", "options"),
        ("--edition", "2021"),
        ("--target", host.as_str()),
        ("--out-dir", out.to_str().unwrap()),
    ] {
        let mut duplicate = valid.clone();
        duplicate.extend([flag.to_owned(), value.to_owned()]);
        assert_eq!(
            parse(&duplicate, None),
            Err(ParseError::DuplicateOption(flag))
        );
        assert!(matches!(plan(&duplicate), Err(LiveRefusal::Unparseable(_))));
        let output = run(&duplicate);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("given more than once"));
    }
    for flag in ["--color", "--diagnostic-width"] {
        let mut missing = valid.clone();
        missing.push(flag.into());
        assert_eq!(parse(&missing, None), Err(ParseError::MissingValue(flag)));
        assert!(matches!(plan(&missing), Err(LiveRefusal::Unparseable(_))));
        let output = run(&missing);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!(
                "Argument to option '{}' missing",
                flag.trim_start_matches("--")
            )),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    for (first, last, succeeds, diagnostic) in [
        ("invalid", "allow", false, "unknown lint level"),
        ("allow", "invalid", true, ""),
        ("warn", "allow", true, "unused variable"),
        ("allow", "warn", true, ""),
        ("deny", "allow", false, "unused variable"),
        ("allow", "deny", true, ""),
    ] {
        let mut repeated = base.clone();
        repeated.extend([
            format!("--cap-lints={first}"),
            "--cap-lints".into(),
            last.into(),
        ]);
        assert_eq!(
            parse(&repeated, None).unwrap().cap_lints.as_deref(),
            Some(first)
        );
        assert_eq!(plan(&repeated).is_ok(), first == "allow");
        let output = run(&repeated);
        assert_eq!(output.status.success(), succeeds, "{first}, {last}");
        if diagnostic.is_empty() {
            assert!(output.stderr.is_empty(), "{first}, {last}");
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(diagnostic),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
