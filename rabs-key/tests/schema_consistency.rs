//! Schema single-source-of-truth consistency suite (bead F030; risk
//! R107).
//!
//! R107 is the duplicate-representation hazard: if a semantic component
//! (working directory, environment, toolchain identity) were representable
//! in TWO schema locations, the two copies could drift and the action key
//! would silently depend on whichever copy a given code path consulted.
//! These tests pin the single authoritative location for every such
//! component and are written to break at compile time or assert time the
//! moment a duplicate field appears.

use rabs_key::action_key::compute_action_key;
use rabs_key::invocation::{NormalizedRustcInvocation, parse};
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn descriptor() -> ActionDescriptor {
    ActionDescriptor {
        key_epoch: 1,
        projection_epoch: 1,
        action_class: ActionClass::RustcDependencyCompile,
        normalized_invocation: d("rabs.invocation.v1", 1),
        virtual_working_directory: d("rabs.cwd.v1", 2),
        action_inputs: d("rabs.inputs.v1", 3),
        negative_dependencies: d("rabs.negdeps.v1", 4),
        dependency_inputs: d("rabs.deps.v1", 5),
        toolchain: d("rabs.toolchain.v1", 6),
        output_platform: d("rabs.platform.v1", 7),
        environment: d("rabs.env.v1", 8),
        sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 9),
        build_path_semantic_policy: d("rabs.path-policy.v1", 10),
        execution_semantics: d("rabs.exec-semantics.v1", 11),
        output_declarations: d("rabs.outputs.v1", 12),
    }
}

#[test]
fn key_breakdown_carries_exactly_one_cwd_digest() {
    // The F030 acceptance line verbatim: exactly one component in the
    // key breakdown names the working directory.
    let breakdown = compute_action_key(&descriptor());
    let cwd_components = breakdown
        .components
        .iter()
        .filter(|c| {
            c.name.contains("working_directory")
                || c.name.contains("cwd")
                || c.digest.domain.contains("cwd")
        })
        .count();
    assert_eq!(
        cwd_components, 1,
        "the working directory must appear exactly once in the key breakdown"
    );
    // And component NAMES are globally unique — no semantic slot can be
    // consulted ambiguously.
    let mut names: Vec<&str> = breakdown.components.iter().map(|c| c.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate key-component name");
}

#[test]
fn normalized_invocation_has_no_working_directory_field() {
    // Exhaustive destructure: `virtual_working_directory` lives in the
    // descriptor ONLY. Adding any cwd/working-dir/env/toolchain field to
    // NormalizedRustcInvocation makes this destructure fail to compile,
    // forcing the author to face R107 instead of drifting into it.
    let NormalizedRustcInvocation {
        wrapper_chain: _,
        stripped_wrapper_flags: _,
        compiler_argv0: _,
        source: _,
        crate_name: _,
        crate_types: _,
        edition: _,
        target: _,
        emit: _,
        codegen: _,
        unstable: _,
        cfgs: _,
        features: _,
        lints: _,
        cap_lints: _,
        externs: _,
        lib_search: _,
        native_libs: _,
        out_dir: _,
        passthrough: _,
        excluded_presentation: _,
    } = NormalizedRustcInvocation::default();
}

#[test]
fn compiler_identity_is_not_duplicated_into_invocation_bytes() {
    // Toolchain identity's single source is the F007 toolchain digest.
    // The invocation's compiler_argv0 is diagnostic: two parses that
    // differ ONLY in the rustc path spelling produce identical canonical
    // bytes — so the compiler cannot enter the key through this second
    // channel even in principle.
    let argv_a: Vec<String> = [
        "/toolchains/stable/bin/rustc",
        "--crate-name",
        "x",
        "lib.rs",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    let argv_b: Vec<String> = ["/other/spelling/rustc", "--crate-name", "x", "lib.rs"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let a = parse(&argv_a, None).unwrap();
    let b = parse(&argv_b, None).unwrap();
    assert_ne!(a.compiler_argv0, b.compiler_argv0);
    assert_eq!(
        a.canonical_bytes(),
        b.canonical_bytes(),
        "compiler path spelling must not leak into invocation bytes"
    );
}

#[test]
fn descriptor_key_slots_use_distinct_digest_domains() {
    // Each descriptor slot is filled under its own digest domain; two
    // slots sharing a domain would let one serializer's bytes be
    // mistaken for another's (the cross-domain-collision hazard R121
    // applied to the schema level).
    let mut domains: Vec<&str> = descriptor()
        .key_input_components()
        .into_iter()
        .map(|(_, digest)| digest.domain)
        .collect();
    domains.sort_unstable();
    let before = domains.len();
    domains.dedup();
    assert_eq!(before, domains.len(), "two key slots share a digest domain");
}
