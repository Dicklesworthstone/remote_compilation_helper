//! Conformance: the live dependency key treats the out-dir as placement
//! (bd-14t4j / bd-k52xe). That is only sound if rustc's library outputs do
//! not depend on where they are written. The oracle is the real compiler:
//! a two-crate chain is compiled into two different out-dirs, exactly the
//! way Cargo compiles a registry dependency in two worktrees.
//!
//! - `.rlib` and `.rmeta` bytes must be identical across out-dirs;
//! - dep-info and the JSON artifact transcript mention the out-dir, and
//!   must become identical after `canonicalize_out_dir`, and render back to
//!   the exact original bytes for each subscriber.
//!
//! If a future rustc starts embedding the out-dir in library bytes, this
//! test fails before a served hit could deliver another worktree's bytes.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use rabs_key::live_dependency::{
    LiveRefusal, LiveRustcRequest, check_dependency_cache_read_closure, plan_dependency_action,
};
use rabs_key::live_dependency::{canonicalize_out_dir, render_out_dir};

struct Compiled {
    out_dir: PathBuf,
    transcript: Vec<u8>,
}

fn compile(
    package: &Path,
    crate_name: &str,
    out_dir: &Path,
    externs: &[(&str, PathBuf)],
) -> Vec<u8> {
    let mut command = Command::new("rustc");
    command
        .current_dir(package)
        .args(["--crate-name", crate_name, "--edition=2021"])
        .arg(package.join("src/lib.rs"))
        .args([
            "--error-format=json",
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
            "--crate-type",
            "lib",
            "--emit=dep-info,metadata,link",
            "-C",
            "embed-bitcode=no",
            "-C",
            "debuginfo=2",
        ])
        .arg(format!("-Cmetadata={crate_name}0123"))
        .arg(format!("-Cextra-filename=-{crate_name}0123"))
        .arg("--out-dir")
        .arg(out_dir)
        .arg("-L")
        .arg(format!("dependency={}", out_dir.display()))
        .args(["--cap-lints", "allow"]);
    for (name, path) in externs {
        command
            .arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let output = command.output().expect("run rustc");
    assert!(
        output.status.success(),
        "rustc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "rustc wrote to stdout");
    output.stderr
}

fn build_chain(registry: &Path, out_dir: &Path) -> Compiled {
    std::fs::create_dir_all(out_dir).unwrap();
    let mut transcript = compile(&registry.join("a-1.0.0"), "a", out_dir, &[]);
    transcript.extend(compile(
        &registry.join("b-1.0.0"),
        "b",
        out_dir,
        &[("a", out_dir.join("liba-a0123.rmeta"))],
    ));
    Compiled {
        out_dir: out_dir.to_path_buf(),
        transcript,
    }
}

#[test]
fn library_bytes_ignore_the_out_dir_and_the_rest_canonicalizes_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let registry = dir.path().join("registry");
    for (package, source) in [
        (
            "a-1.0.0",
            "#[inline] pub fn twice(x: u32) -> u32 { x * 2 }\n\
             pub fn here() -> &'static str { file!() }\n\
             pub struct Wrapper(pub Vec<u32>);\n",
        ),
        (
            "b-1.0.0",
            "pub fn quad(x: u32) -> u32 { a::twice(a::twice(x)) }\n\
             pub fn there() -> &'static str { a::here() }\n\
             pub fn index(v: &a::Wrapper) -> u32 { v.0[3] }\n",
        ),
    ] {
        std::fs::create_dir_all(registry.join(package).join("src")).unwrap();
        std::fs::write(registry.join(package).join("src/lib.rs"), source).unwrap();
    }
    let first = build_chain(&registry, &dir.path().join("worktree-a/target/debug/deps"));
    let second = build_chain(&registry, &dir.path().join("worktree-b/target/debug/deps"));

    for file in [
        "liba-a0123.rlib",
        "liba-a0123.rmeta",
        "libb-b0123.rlib",
        "libb-b0123.rmeta",
    ] {
        assert_eq!(
            std::fs::read(first.out_dir.join(file)).unwrap(),
            std::fs::read(second.out_dir.join(file)).unwrap(),
            "{file} depends on the out-dir"
        );
    }

    let out = |compiled: &Compiled| compiled.out_dir.to_str().unwrap().to_owned();
    for file in ["a-a0123.d", "b-b0123.d"] {
        let raw_first = std::fs::read(first.out_dir.join(file)).unwrap();
        let raw_second = std::fs::read(second.out_dir.join(file)).unwrap();
        assert_ne!(
            raw_first, raw_second,
            "dep-info is expected to name the out-dir"
        );
        let canonical = canonicalize_out_dir(&raw_first, &out(&first)).unwrap();
        assert_eq!(
            canonical,
            canonicalize_out_dir(&raw_second, &out(&second)).unwrap()
        );
        assert_eq!(render_out_dir(&canonical, &out(&first)), raw_first);
        assert_eq!(render_out_dir(&canonical, &out(&second)), raw_second);
    }

    assert_ne!(first.transcript, second.transcript);
    let canonical = canonicalize_out_dir(&first.transcript, &out(&first)).unwrap();
    assert_eq!(
        canonical,
        canonicalize_out_dir(&second.transcript, &out(&second)).unwrap()
    );
    assert_eq!(render_out_dir(&canonical, &out(&second)), second.transcript);
    assert!(
        String::from_utf8(canonical)
            .unwrap()
            .contains("\"artifact\":\"/__rabs/out/libb-b0123.rmeta\"")
    );
}

/// A real compiler counterexample to using dep-info as complete codegen read
/// evidence. The assembler input lives outside every keyed source root, and a
/// macro introduces the assembly so a textual source scan is not an answer.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn assembler_input_changes_rlib_without_changing_dep_info_and_cannot_serve() {
    let temporary = tempfile::tempdir().unwrap();
    let cargo_home = temporary.path().join("cargo");
    let package = cargo_home.join("registry/src/closure-index/hidden_asm-1.0.0");
    let output = temporary.path().join("outputs");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::create_dir(&output).unwrap();
    let payload = temporary.path().join("untracked-payload.bin");
    std::fs::write(&payload, b"first___").unwrap();
    let source = package.join("lib.rs");
    let assembly = format!(
        ".section .rodata\n.global rabs_hidden_payload\nrabs_hidden_payload:\n.incbin \"{}\"\n",
        payload.display()
    );
    std::fs::write(
        &source,
        format!(
            "macro_rules! import_payload {{ () => {{ core::arch::global_asm!({assembly:?}); }}; }}\n\
             import_payload!();\npub fn answer() -> u32 {{ 42 }}\n"
        ),
    )
    .unwrap();
    let sysroot = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .unwrap();
    assert!(sysroot.status.success());
    let compiler =
        Path::new(std::str::from_utf8(&sysroot.stdout).unwrap().trim()).join("bin/rustc");
    let identity = Command::new(&compiler).arg("-vV").output().unwrap();
    assert!(identity.status.success());
    let identity = String::from_utf8(identity.stdout).unwrap();
    let host = identity
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .unwrap();
    let argv = vec![
        compiler.to_str().unwrap().to_owned(),
        source.to_str().unwrap().to_owned(),
        "--crate-name=hidden_asm".into(),
        "--crate-type=rlib".into(),
        "--edition=2021".into(),
        "--emit=metadata,dep-info,link".into(),
        "--cap-lints=allow".into(),
        "--error-format=json".into(),
        format!("--out-dir={}", output.display()),
    ];
    let environment = vec![
        ("CARGO_HOME".into(), cargo_home.to_str().unwrap().to_owned()),
        (
            "CARGO_MANIFEST_DIR".into(),
            package.to_str().unwrap().to_owned(),
        ),
        ("CARGO_PKG_NAME".into(), "hidden_asm".into()),
    ];
    let plan = plan_dependency_action(
        LiveRustcRequest {
            argv: &argv,
            cwd: package.to_str().unwrap(),
            env: &environment,
        },
        host,
    )
    .unwrap();
    assert_eq!(
        check_dependency_cache_read_closure(&plan.invocation),
        Err(LiveRefusal::UnclosedCodegenInputs)
    );
    let compile = || {
        let compiled = Command::new(&compiler)
            .args(&argv[1..])
            .current_dir(&package)
            .envs(environment.iter().map(|(name, value)| (name, value)))
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        (
            std::fs::read(output.join("hidden_asm.d")).unwrap(),
            std::fs::read(output.join("libhidden_asm.rmeta")).unwrap(),
            std::fs::read(output.join("libhidden_asm.rlib")).unwrap(),
        )
    };
    let before = compile();
    std::fs::write(&payload, b"second__").unwrap();
    let after = compile();
    assert_eq!(
        before.0, after.0,
        "rustc did not report this assembler input"
    );
    assert!(
        !String::from_utf8(before.0)
            .unwrap()
            .contains(payload.to_str().unwrap()),
        "this fixture must exercise a real dep-info observation gap"
    );
    assert_eq!(
        before.1, after.1,
        "metadata-only execution does not assemble the input"
    );
    assert_ne!(
        before.2, after.2,
        "codegen actually consumed the changed external bytes"
    );
}

/// Rustc bundles a native static archive into an rlib without listing that
/// archive in dep-info. Both command-line and source-attribute selection need
/// the complete generated-tree evidence used by the canonical worker class.
/// This is a real compiler/linker oracle; it does not claim namespace or daemon
/// serving evidence, which belongs to the separate native integration fixtures.
#[cfg(target_os = "linux")]
#[test]
fn bundled_static_archive_changes_executable_without_changing_dep_info() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("bridge.rs");
    let generated = directory.path().join("generated/native");
    let out = directory.path().join("out");
    std::fs::create_dir_all(&generated).unwrap();
    std::fs::create_dir(&out).unwrap();
    let checked = |command: &mut Command| {
        let output = command.output().expect("run real native compiler/linker");
        assert!(
            output.status.success(),
            "{command:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    };
    for attribute in [false, true] {
        std::fs::write(
            &source,
            format!(
                "{}unsafe extern \"C\" {{ fn rabs_native_answer() -> u32; }}\npub fn answer() -> u32 {{ unsafe {{ rabs_native_answer() }} }}\n",
                if attribute {
                    "#[link(name=\"rabs_answer\", kind=\"static\")]\n"
                } else {
                    ""
                }
            ),
        )
        .unwrap();
        let mut previous = None;
        for answer in [37, 41] {
            std::fs::write(
                generated.join("answer.c"),
                format!("unsigned int rabs_native_answer(void) {{ return {answer}; }}\n"),
            )
            .unwrap();
            checked(
                Command::new("cc")
                    .args(["-c", "-fPIC", "-o"])
                    .arg(generated.join("answer.o"))
                    .arg(generated.join("answer.c")),
            );
            checked(
                Command::new("ar")
                    .arg("crsD")
                    .arg(generated.join("librabs_answer.a"))
                    .arg(generated.join("answer.o")),
            );
            let mut compiler = Command::new("rustc");
            compiler
                .arg(&source)
                .args([
                    "--crate-name=native_bridge",
                    "--crate-type=rlib",
                    "--edition=2024",
                    "--emit=dep-info,metadata,link",
                    "--error-format=json",
                    "--cap-lints=allow",
                ])
                .arg("--out-dir")
                .arg(&out)
                .arg(format!("-Lnative={}", generated.display()));
            if !attribute {
                compiler.arg("-lstatic=rabs_answer");
            }
            checked(&mut compiler);
            let dep_info = std::fs::read(out.join("native_bridge.d")).unwrap();
            let archive = std::fs::read(out.join("libnative_bridge.rlib")).unwrap();
            assert!(
                !String::from_utf8_lossy(&dep_info).contains("librabs_answer.a"),
                "the oracle must exercise an input outside rustc's dep-info"
            );
            if let Some((old_dep_info, old_archive)) = previous {
                assert_eq!(dep_info, old_dep_info, "only the native object changed");
                assert_ne!(archive, old_archive, "native bytes must affect the rlib");
            }
            previous = Some((dep_info, archive));

            let main = directory.path().join("main.rs");
            std::fs::write(
                &main,
                format!(
                    "fn main() {{ assert_eq!(native_bridge::answer(), {answer}); println!(\"{{}}\", native_bridge::answer()); }}\n"
                ),
            )
            .unwrap();
            let binary = directory
                .path()
                .join(format!("native-{attribute}-{answer}"));
            // No native search path is supplied at final linking: a bundled
            // object must be sufficient, rather than a deferred library name.
            checked(
                Command::new("rustc")
                    .arg(&main)
                    .arg("--edition=2024")
                    .arg("--extern")
                    .arg(format!(
                        "native_bridge={}",
                        out.join("libnative_bridge.rlib").display()
                    ))
                    .arg("-o")
                    .arg(&binary),
            );
            assert_eq!(
                checked(&mut Command::new(&binary)).stdout,
                format!("{answer}\n").as_bytes(),
                "delivered native code must have the current behavior"
            );
        }
    }
}
