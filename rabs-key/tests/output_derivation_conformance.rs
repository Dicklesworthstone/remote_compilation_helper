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
use rabs_key::output_derivation::derive_output_declarations;

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
