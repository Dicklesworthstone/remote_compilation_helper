//! Exercises the actual observation/probe/guard path with a scripted rustc
//! identity query. These are filesystem and capture tests, not compiler wins.

use super::*;
use crate::edge::live_facts::{
    FactsMiss, LiveFacts, MAX_WARMING, Slot, digest_stable, probe_toolchain,
    tests::toolchain_fixture,
};
use std::os::unix::fs::symlink;
use std::sync::Arc;

fn library_root(compiler: &Path) -> PathBuf {
    compiler.parent().unwrap().parent().unwrap().join("lib")
}

fn backend_root(compiler: &Path) -> PathBuf {
    library_root(compiler).join("rustlib/test-host/codegen-backends")
}

fn backend_file(compiler: &Path) -> PathBuf {
    let root = backend_root(compiler);
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("librustc_codegen_llvm-fixture.so");
    std::fs::write(&path, b"backend-v1").unwrap();
    path
}

#[test]
fn loaded_backend_bytes_join_the_existing_streaming_batch_and_fact_identity() {
    let (_dir, compiler) = toolchain_fixture();
    let backend = backend_file(&compiler);
    let first = probe_toolchain(&compiler, &[]).unwrap();
    assert!(
        first
            .inputs
            .runtime_libraries
            .iter()
            .any(|(path, _)| path == &backend)
    );
    assert!(
        first
            .facts
            .runtime_libraries
            .contains(&digest_stable(&backend).unwrap().1)
    );
    let version = first.facts.verbose_version.clone();
    let binary = first.facts.compiler_binary_digest.clone();
    let standard_library = first.facts.sysroot_root_digest.clone();
    // A backend update need not touch rustc, its version, or any std file.
    std::fs::write(&backend, b"different backend implementation").unwrap();
    assert!(!first.still_current());
    let changed = probe_toolchain(&compiler, &[]).unwrap();
    assert_eq!(changed.facts.verbose_version, version);
    assert_eq!(changed.facts.compiler_binary_digest, binary);
    assert_eq!(changed.facts.sysroot_root_digest, standard_library);
    assert_ne!(
        changed.facts.runtime_libraries,
        first.facts.runtime_libraries
    );
}

#[test]
fn absence_empty_directory_and_new_backend_are_distinct_observations() {
    let (_dir, compiler) = toolchain_fixture();
    let absent = probe_toolchain(&compiler, &[]).unwrap();
    assert_eq!(
        absent.facts.runtime_libraries.last().unwrap().domain,
        DOMAIN_BACKENDS
    );
    std::fs::create_dir(backend_root(&compiler)).unwrap();
    assert!(!absent.still_current());
    let empty = probe_toolchain(&compiler, &[]).unwrap();
    assert_ne!(absent.facts, empty.facts);
    backend_file(&compiler);
    assert!(!empty.still_current());
    let present = probe_toolchain(&compiler, &[]).unwrap();
    assert_ne!(empty.facts, present.facts);
}

#[test]
fn backend_names_and_nested_members_are_canonical_inputs() {
    let (dir, compiler) = toolchain_fixture();
    let backend = backend_file(&compiler);
    let first = probe_toolchain(&compiler, &[]).unwrap();
    std::fs::rename(
        &backend,
        backend.with_file_name("librustc_codegen_other.so"),
    )
    .unwrap();
    let renamed = probe_toolchain(&compiler, &[]).unwrap();
    assert_ne!(
        first.facts, renamed.facts,
        "equal bytes under another loader name must not alias"
    );
    let nested = backend_root(&compiler).join("support/data");
    std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
    std::fs::write(&nested, b"backend support input").unwrap();
    let with_support = probe_toolchain(&compiler, &[]).unwrap();
    assert_ne!(renamed.facts, with_support.facts);
    assert!(
        with_support
            .inputs
            .runtime_libraries
            .iter()
            .any(|(path, _)| path == &nested)
    );
    std::fs::rename(&nested, dir.path().join("retained-support")).unwrap();
    assert!(!with_support.still_current());
}

#[test]
fn every_installed_backend_root_is_observed_before_the_host_probe() {
    let (_dir, compiler) = toolchain_fixture();
    backend_file(&compiler);
    let first = probe_toolchain(&compiler, &[]).unwrap();
    let other = library_root(&compiler).join("rustlib/future-target/codegen-backends");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("backend.so"), b"other host backend").unwrap();
    assert!(!first.still_current());
    assert_ne!(first.facts, probe_toolchain(&compiler, &[]).unwrap().facts);
}

#[test]
fn sibling_backend_aliases_hash_terminal_bytes_and_bind_retargeting() {
    let (dir, compiler) = toolchain_fixture();
    let root = backend_root(&compiler);
    std::fs::create_dir(&root).unwrap();
    for name in ["payload-a", "payload-b"] {
        std::fs::write(root.join(name), b"same backend bytes").unwrap();
    }
    let alias = root.join("librustc_codegen_llvm.so");
    symlink("payload-a", &alias).unwrap();
    let first = probe_toolchain(&compiler, &[]).unwrap();
    assert!(
        first
            .inputs
            .runtime_libraries
            .iter()
            .any(|(path, _)| path == &root.join("payload-a"))
    );
    std::fs::rename(&alias, dir.path().join("retained-alias")).unwrap();
    symlink("payload-b", &alias).unwrap();
    let retargeted = probe_toolchain(&compiler, &[]).unwrap();
    assert!(!first.still_current());
    assert_ne!(first.facts, retargeted.facts);
}

#[test]
fn an_equal_byte_replacement_cannot_refresh_the_original_request_guard() {
    let (dir, compiler) = toolchain_fixture();
    let backend = backend_file(&compiler);
    let probed = probe_toolchain(&compiler, &[]).unwrap();
    let expected = probed.facts.clone();
    let facts = LiveFacts::new();
    facts
        .toolchains
        .lock()
        .unwrap()
        .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
    let guard = facts.toolchain_guard(&compiler, &expected).unwrap();
    std::fs::rename(&backend, dir.path().join("retained-backend")).unwrap();
    std::fs::write(&backend, b"backend-v1").unwrap();
    let refreshed = probe_toolchain(&compiler, &[]).unwrap();
    assert_eq!(refreshed.facts, expected);
    facts
        .toolchains
        .lock()
        .unwrap()
        .insert(compiler.clone(), Slot::Ready(Arc::new(refreshed)));
    facts
        .toolchain_guard(&compiler, &expected)
        .unwrap()
        .verify_unchanged(&compiler)
        .unwrap();
    assert!(guard.verify_unchanged(&compiler).is_err());
}

#[test]
fn changed_backend_is_not_served_when_the_warm_pool_is_full() {
    let (_dir, compiler) = toolchain_fixture();
    let backend = backend_file(&compiler);
    let probed = probe_toolchain(&compiler, &[]).unwrap();
    let expected = probed.facts.clone();
    let facts = LiveFacts::new();
    facts
        .toolchains
        .lock()
        .unwrap()
        .insert(compiler.clone(), Slot::Ready(Arc::new(probed)));
    assert_eq!(facts.toolchain(&compiler, &[]).unwrap(), expected);
    *facts.warming.lock().unwrap() = MAX_WARMING;
    std::fs::write(backend, b"changed").unwrap();
    assert_eq!(facts.toolchain(&compiler, &[]), Err(FactsMiss::Pending));
    assert!(!facts.toolchains.lock().unwrap().contains_key(&compiler));
    assert_eq!(*facts.warming.lock().unwrap(), MAX_WARMING);
}

#[test]
fn escaped_dangling_cyclic_and_directory_backend_links_refuse_before_probing() {
    for target in [
        "missing",
        "../lib/libcore.rlib",
        "/outside/backend.so",
        "nested",
        "alias.so",
    ] {
        let (dir, compiler) = toolchain_fixture();
        let root = backend_root(&compiler);
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("nested")).unwrap();
        symlink(target, root.join("alias.so")).unwrap();
        let log = dir.path().join("probe-log");
        let env = vec![("RABS_TEST_LOG".into(), log.to_str().unwrap().into())];
        assert!(probe_toolchain(&compiler, &env).is_err(), "{target}");
        assert!(!log.exists(), "unclosed backend reached the identity probe");
    }
}

#[test]
fn backend_root_links_and_special_members_are_not_silently_omitted() {
    for root_link in [true, false] {
        let (dir, compiler) = toolchain_fixture();
        let root = backend_root(&compiler);
        let outside = dir.path().join("backend-tree");
        std::fs::create_dir(&outside).unwrap();
        if root_link {
            symlink(&outside, &root).unwrap();
        } else {
            std::fs::create_dir(&root).unwrap();
        }
        let _socket = std::os::unix::net::UnixListener::bind(
            (if root_link { outside } else { root }).join("backend.so"),
        )
        .unwrap();
        assert!(probe_toolchain(&compiler, &[]).is_err());
    }
}

#[test]
fn same_layout_and_bytes_are_independent_of_host_paths_and_creation_order() {
    let (_first_dir, first) = toolchain_fixture();
    let (_second_dir, second) = toolchain_fixture();
    for (compiler, names) in [(&first, ["a", "b"]), (&second, ["b", "a"])] {
        let root = backend_root(compiler);
        std::fs::create_dir(&root).unwrap();
        for name in names {
            std::fs::write(root.join(name), name.as_bytes()).unwrap();
        }
        symlink("a", root.join("alias.so")).unwrap();
    }
    assert_eq!(
        probe_toolchain(&first, &[]).unwrap().facts,
        probe_toolchain(&second, &[]).unwrap().facts
    );
}

#[test]
fn a_probe_cannot_mix_identity_with_a_changed_backend() {
    let (_dir, compiler) = toolchain_fixture();
    backend_file(&compiler);
    std::fs::write(
        &compiler,
        br#"#!/bin/sh
root=${0%/bin/rustc}
case "$*" in
 '-vV') printf changed > "$root/lib/rustlib/test-host/codegen-backends/librustc_codegen_llvm-fixture.so"; printf 'rustc fixture\nhost: x86_64-unknown-linux-gnu\n';;
 '--print sysroot') printf '%s\n' "$root";;
 *) exit 64;;
esac
"#,
    )
    .unwrap();
    assert!(probe_toolchain(&compiler, &[]).is_err());
}

#[test]
fn backend_aliases_share_the_remaining_top_level_link_budget() {
    let (_dir, compiler) = toolchain_fixture();
    let backend = backend_file(&compiler);
    symlink(
        backend.file_name().unwrap(),
        backend_root(&compiler).join("alias.so"),
    )
    .unwrap();
    let lib = library_root(&compiler);
    assert!(observe(&lib, 0).is_err());
    assert!(observe(&lib, 1).is_ok());
}

#[test]
fn entry_budget_is_charged_before_collecting_each_directory_member() {
    let dir = crate::test_util::private_tempdir();
    std::fs::write(dir.path().join("a"), b"a").unwrap();
    std::fs::write(dir.path().join("b"), b"b").unwrap();
    for budget in [1, 2] {
        let mut inventory = Inventory {
            library_root: dir.path(),
            remaining: budget,
            link_budget: 0,
            directories: Vec::new(),
            backend_directories: Vec::new(),
            bindings: BTreeMap::new(),
            links: BTreeMap::new(),
        };
        assert_eq!(inventory.entries(dir.path()).is_ok(), budget == 2);
        assert_eq!(inventory.remaining, 0);
    }
}
