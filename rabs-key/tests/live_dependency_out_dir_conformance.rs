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
