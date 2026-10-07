//! Conformance: the locator-exact dependency closure
//! (`rabs_key::dependency_candidates`, bd-k52xe) against the real compiler.
//!
//! The closure keys only the search-directory files rustc's crate locator
//! can examine, by metadata identity. That is sound only if, for real rustc:
//!
//! - a dependent's metadata records every graph crate's Cargo extra
//!   filename verbatim (so the closure finds transitive groups);
//! - an `.rlib` carries byte-identical metadata to its `.rmeta` (so the
//!   group identity does not depend on which container exists);
//! - unrelated directory members and an absent transitive `.rlib` do not
//!   change a dependent's outputs (so leaving them out of the key cannot
//!   serve different bytes);
//! - a proc-macro reachable through a re-export is refused.
//!
//! Crates are compiled exactly the way Cargo compiles dependencies into one
//! `deps` directory that is both `--out-dir` and `-L dependency=`.
#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use rabs_key::dependency_candidates::{
    CandidateIdentity, ClosureRefusal, CrateFlavor, DependencyDirectoryFact, GroupIdentity,
    encode_candidates, read_candidate, referenced_candidates,
};
use rabs_key::typed_digest::compute;

const HASHES: [(&str, &str); 6] = [
    ("a", "a0a0a0a0a0a0a0a0"),
    ("b", "b0b0b0b0b0b0b0b0"),
    ("c", "c0c0c0c0c0c0c0c0"),
    ("m", "d0d0d0d0d0d0d0d0"),
    ("r", "e0e0e0e0e0e0e0e0"),
    ("u", "f0f0f0f0f0f0f0f0"),
];

fn hash(name: &str) -> &'static str {
    HASHES
        .iter()
        .find(|(crate_name, _)| *crate_name == name)
        .unwrap()
        .1
}

fn source(root: &Path, name: &str, body: &str) -> PathBuf {
    let path = root.join(format!("src-{name}/lib.rs"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, body).unwrap();
    path
}

fn compile(
    src: &Path,
    name: &str,
    crate_type: &str,
    out_dir: &Path,
    search: &Path,
    externs: &[(&str, PathBuf)],
) {
    compile_with(src, name, crate_type, out_dir, search, externs, &[]);
}

fn compile_with(
    src: &Path,
    name: &str,
    crate_type: &str,
    out_dir: &Path,
    search: &Path,
    externs: &[(&str, PathBuf)],
    extra: &[&str],
) {
    std::fs::create_dir_all(out_dir).unwrap();
    let mut command = Command::new("rustc");
    command.args(extra);
    command
        .args(["--crate-name", name, "--edition=2021"])
        .arg(src)
        .args([
            "--error-format=json",
            "--json=diagnostic-rendered-ansi,artifacts,future-incompat",
            "--crate-type",
            crate_type,
            "-C",
            "embed-bitcode=no",
            "-C",
            "debuginfo=2",
        ])
        .arg(if crate_type == "proc-macro" {
            "--emit=dep-info,link"
        } else {
            "--emit=dep-info,metadata,link"
        })
        .arg(format!("-Cmetadata={}", hash(name)))
        .arg(format!("-Cextra-filename=-{}", hash(name)))
        .arg("--out-dir")
        .arg(out_dir)
        .arg("-L")
        .arg(format!("dependency={}", search.display()))
        .args(["--cap-lints", "allow"]);
    if crate_type == "proc-macro" {
        command.args(["--extern", "proc_macro"]);
    }
    for (crate_name, path) in externs {
        command
            .arg("--extern")
            .arg(format!("{crate_name}={}", path.display()));
    }
    let output = command.output().expect("run rustc");
    assert!(
        output.status.success(),
        "rustc failed for {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn file(deps: &Path, name: &str, suffix: &str) -> PathBuf {
    deps.join(format!("lib{name}-{}.{suffix}", hash(name)))
}

fn close(deps: &Path, seeds: &[&Path]) -> Result<Vec<DependencyDirectoryFact>, ClosureRefusal> {
    let root = deps.to_str().unwrap().to_owned();
    let listing: Vec<String> = std::fs::read_dir(deps)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    let seeds: Vec<(usize, String)> = seeds
        .iter()
        .map(|path| (0, path.file_name().unwrap().to_str().unwrap().to_owned()))
        .collect();
    referenced_candidates(&[root], &[listing], &seeds, |_, name, flavor| {
        let bytes = std::fs::read(deps.join(name)).map_err(|error| error.to_string())?;
        Ok(read_candidate(
            flavor,
            &bytes,
            compute("test.exact", &bytes),
        ))
    })
}

fn stems(facts: &[DependencyDirectoryFact]) -> BTreeSet<String> {
    facts[0]
        .groups
        .iter()
        .map(|group| group.stem.clone())
        .collect()
}

fn encoded(facts: &[DependencyDirectoryFact]) -> Vec<u8> {
    encode_candidates(facts, |_| "/__rabs/deps/000".to_owned())
}

/// a <- b <- c: c's compile names only b; a is located transitively.
fn chain(root: &Path, deps: &Path) {
    let a = source(
        root,
        "a",
        "pub fn a() -> u32 { 1 }\n#[inline] pub fn g<T: Default>() -> T { T::default() }\n",
    );
    let b = source(
        root,
        "b",
        "pub fn b() -> u32 { a::a() + 1 }\npub use a::g;\n",
    );
    compile(&a, "a", "lib", deps, deps, &[]);
    compile(
        &b,
        "b",
        "lib",
        deps,
        deps,
        &[("a", file(deps, "a", "rmeta"))],
    );
}

fn compile_c(root: &Path, out_dir: &Path, search: &Path) -> (Vec<u8>, Vec<u8>) {
    let c = source(root, "c", "pub fn c() -> u32 { b::b() + b::g::<u32>() }\n");
    compile(
        &c,
        "c",
        "lib",
        out_dir,
        search,
        &[("b", file(search, "b", "rmeta"))],
    );
    (
        std::fs::read(file(out_dir, "c", "rlib")).unwrap(),
        std::fs::read(file(out_dir, "c", "rmeta")).unwrap(),
    )
}

#[test]
fn real_rustc_metadata_closes_the_graph_and_rlib_metadata_equals_rmeta() {
    let scratch = tempfile::tempdir().unwrap();
    let deps = scratch.path().join("deps");
    chain(scratch.path(), &deps);
    // Identity of a's group is the same through either container.
    let identity = |suffix: &str, flavor: CrateFlavor| {
        let bytes = std::fs::read(file(&deps, "a", suffix)).unwrap();
        read_candidate(flavor, &bytes, compute("test.exact", &bytes)).identity
    };
    let from_rmeta = identity("rmeta", CrateFlavor::Rmeta);
    assert!(
        matches!(from_rmeta, CandidateIdentity::Metadata(_)),
        "{from_rmeta:?}"
    );
    assert_eq!(identity("rlib", CrateFlavor::Rlib), from_rmeta);

    let facts = close(&deps, &[&file(&deps, "b", "rmeta")]).unwrap();
    assert!(
        stems(&facts).contains(&format!("liba-{}", hash("a"))),
        "the transitive crate is located through b's metadata: {:?}",
        stems(&facts)
    );
    for group in &facts[0].groups {
        assert!(
            matches!(group.identity, GroupIdentity::Metadata(_)),
            "{group:?}"
        );
    }
}

#[test]
fn unrelated_members_and_absent_transitive_rlibs_change_neither_key_nor_outputs() {
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let clean = root.join("clean");
    chain(root, &clean);
    let baseline_facts = close(&clean, &[&file(&clean, "b", "rmeta")]).unwrap();
    let baseline = compile_c(root, &root.join("out-clean"), &clean);

    // The same chain plus everything a warm target directory holds.
    let busy = root.join("busy");
    chain(root, &busy);
    let unrelated = source(root, "u", "pub fn u() {}\n");
    compile(&unrelated, "u", "lib", &busy, &busy, &[]);
    std::fs::write(
        busy.join("liba-0000000000000000.rlib"),
        b"stale other version",
    )
    .unwrap();
    std::fs::write(busy.join("proj-1111111111111111"), b"test executable").unwrap();
    std::fs::write(busy.join("x-0.x.1a2b-cgu.0.rcgu.o"), b"object").unwrap();
    std::fs::create_dir(busy.join("rmetaQwErTy")).unwrap();
    let busy_facts = close(&busy, &[&file(&busy, "b", "rmeta")]).unwrap();
    assert_eq!(encoded(&busy_facts), encoded(&baseline_facts));
    assert_eq!(compile_c(root, &root.join("out-busy"), &busy), baseline);

    // Pipelining: the transitive rlib does not exist yet.
    let early = root.join("early");
    chain(root, &early);
    std::fs::remove_file(file(&early, "a", "rlib")).unwrap();
    let early_facts = close(&early, &[&file(&early, "b", "rmeta")]).unwrap();
    assert_eq!(encoded(&early_facts), encoded(&baseline_facts));
    assert_eq!(compile_c(root, &root.join("out-early"), &early), baseline);

    // A different transitive crate DOES change the key.
    let changed = root.join("changed");
    let a = source(
        root,
        "a",
        "pub fn a() -> u32 { 2 }\n#[inline] pub fn g<T: Default>() -> T { T::default() }\n",
    );
    compile(&a, "a", "lib", &changed, &changed, &[]);
    let b = source(
        root,
        "b",
        "pub fn b() -> u32 { a::a() + 1 }\npub use a::g;\n",
    );
    compile(
        &b,
        "b",
        "lib",
        &changed,
        &changed,
        &[("a", file(&changed, "a", "rmeta"))],
    );
    let changed_facts = close(&changed, &[&file(&changed, "b", "rmeta")]).unwrap();
    assert_ne!(encoded(&changed_facts), encoded(&baseline_facts));
}

#[test]
fn a_proc_macro_reachable_through_a_reexport_is_refused() {
    if Command::new("cc").arg("--version").output().is_err() {
        eprintln!("SKIP: proc-macro linking needs a C linker");
        return;
    }
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let deps = root.join("deps");
    let m = source(
        root,
        "m",
        "use proc_macro::TokenStream;\n#[proc_macro_derive(Nothing)]\npub fn nothing(_: TokenStream) -> TokenStream { TokenStream::new() }\n",
    );
    compile(&m, "m", "proc-macro", &deps, &deps, &[]);
    let r = source(root, "r", "pub use m::Nothing;\npub fn r() {}\n");
    compile(
        &r,
        "r",
        "lib",
        &deps,
        &deps,
        &[("m", file(&deps, "m", "so"))],
    );
    let unrelated = source(root, "u", "pub fn u() {}\n");
    compile(&unrelated, "u", "lib", &deps, &deps, &[]);
    // A compile that names r can expand m's derive: refused.
    assert!(matches!(
        close(&deps, &[&file(&deps, "r", "rmeta")]),
        Err(ClosureRefusal::Dylib(path)) if path.ends_with(".so")
    ));
    // A compile that names only u never reaches m, though m sits beside it.
    let facts = close(&deps, &[&file(&deps, "u", "rmeta")]).unwrap();
    assert!(!stems(&facts).iter().any(|stem| stem.starts_with("libm-")));
}

/// The pinned Cargo passes `-Z embed-metadata=no`: an `.rlib` then carries
/// object code only and rustc reads metadata from the `.rmeta`. Such an
/// archive must neither split the group's identity nor matter to outputs.
#[test]
fn objects_only_rlibs_change_neither_key_nor_outputs() {
    let version = Command::new("rustc").arg("-vV").output().unwrap();
    if !String::from_utf8_lossy(&version.stdout).contains("nightly") {
        eprintln!("SKIP: -Z embed-metadata=no needs a nightly compiler");
        return;
    }
    let flags: &[&str] = &["-Z", "embed-metadata=no"];
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path();
    let build = |deps: &Path| {
        let a = source(
            root,
            "a",
            "pub fn a() -> u32 { 1 }\n#[inline] pub fn g<T: Default>() -> T { T::default() }\n",
        );
        let b = source(
            root,
            "b",
            "pub fn b() -> u32 { a::a() + 1 }\npub use a::g;\n",
        );
        compile_with(&a, "a", "lib", deps, deps, &[], flags);
        compile_with(
            &b,
            "b",
            "lib",
            deps,
            deps,
            &[("a", file(deps, "a", "rmeta"))],
            flags,
        );
    };
    let compile_c = |out: &Path, search: &Path| {
        let c = source(root, "c", "pub fn c() -> u32 { b::b() + b::g::<u32>() }\n");
        compile_with(
            &c,
            "c",
            "lib",
            out,
            search,
            &[("b", file(search, "b", "rmeta"))],
            flags,
        );
        (
            std::fs::read(file(out, "c", "rlib")).unwrap(),
            std::fs::read(file(out, "c", "rmeta")).unwrap(),
        )
    };
    let with_rlib = root.join("with-rlib");
    build(&with_rlib);
    let rlib = std::fs::read(file(&with_rlib, "a", "rlib")).unwrap();
    assert!(matches!(
        read_candidate(CrateFlavor::Rlib, &rlib, compute("test.exact", &rlib)).identity,
        CandidateIdentity::ObjectsOnly(_)
    ));
    let without_rlib = root.join("without-rlib");
    build(&without_rlib);
    std::fs::remove_file(file(&without_rlib, "a", "rlib")).unwrap();
    assert_eq!(
        encoded(&close(&with_rlib, &[&file(&with_rlib, "b", "rmeta")]).unwrap()),
        encoded(&close(&without_rlib, &[&file(&without_rlib, "b", "rmeta")]).unwrap())
    );
    assert_eq!(
        compile_c(&root.join("out-with"), &with_rlib),
        compile_c(&root.join("out-without"), &without_rlib)
    );
}
