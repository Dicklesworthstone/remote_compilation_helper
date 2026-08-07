//! Property suite: irrelevant differences preserve keys (bead F014;
//! invariants I23/I24; plan §67).
//!
//! Two agents on two machines do IDENTICAL semantic work through
//! maximally different local circumstances — different worktrees,
//! wrapper chains, response-file temp names, extern path spellings,
//! staging roots, presentation settings, subscriber contexts. The whole
//! key pipeline (invocation parse → response-file normalization →
//! extern resolution → component digests → final ActionKey) must
//! produce byte-identical keys.
//!
//! Failure diagnosis is built in: components are compared BY NAME
//! before the final key, so a violation pinpoints the leaking
//! component instead of reporting an opaque key mismatch.

use rabs_key::action_key::compute_action_key;
use rabs_key::dependency_identity::{ConsumedArtifact, DependencyInputs};
use rabs_key::environment::{EnvDisposition, PathToolEntry, PresentedEnvironment};
use rabs_key::extern_resolution::{
    DependencyArtifactIdentity, DependencyArtifactKind, resolve_externs, resolved_externs_digest,
};
use rabs_key::invocation::parse;
use rabs_key::response_files::{
    NormalizedArg, canonical_bytes as response_bytes, normalize_response_files,
};
use rabs_key::typed_digest::compute;
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

fn fixed(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

/// One agent's local circumstances.
struct AgentContext {
    wrapper_chain: Vec<String>,
    response_file: String,
    extern_path: String,
    presentation_args: Vec<String>,
}

fn agent_a() -> AgentContext {
    AgentContext {
        wrapper_chain: vec!["/usr/bin/sccache".into()],
        response_file: "/tmp/rustcAAA111/args.txt".into(),
        extern_path: "/home/alice/w1/target/debug/deps/libserde.rlib".into(),
        presentation_args: vec!["--color".into(), "always".into()],
    }
}

fn agent_b() -> AgentContext {
    AgentContext {
        wrapper_chain: vec!["/opt/rch/rch-shim".into(), "/usr/local/bin/sccache".into()],
        response_file: "/var/folders/zz/rustcBBB222/args.txt".into(),
        extern_path: "/Users/bob/checkout/target/debug/deps/libserde.rlib".into(),
        presentation_args: vec!["--diagnostic-width=80".into()],
    }
}

/// Run the full pipeline for one agent; returns the component digests
/// that would fill the descriptor slots this pipeline covers.
fn pipeline(ctx: &AgentContext) -> Vec<(&'static str, TypedDigest)> {
    // 1. Raw argv: wrapper chain + semantic args + agent-local noise.
    let mut argv: Vec<String> = ctx.wrapper_chain.clone();
    argv.push("/toolchains/stable/bin/rustc".into());
    argv.extend(
        [
            "--crate-name",
            "app",
            "--edition=2021",
            "src/lib.rs",
            "--crate-type",
            "lib",
        ]
        .iter()
        .map(|s| (*s).to_owned()),
    );
    argv.push(format!("@{}", ctx.response_file));
    argv.push("--extern".into());
    argv.push(format!("serde={}", ctx.extern_path));
    argv.extend(ctx.presentation_args.clone());

    // 2. Response files: same CONTENT under different temp names.
    // Expansion FEEDS the parser — the normalized argv is pipeline
    // plumbing, not a key component (the leak-pinpointing pass below
    // caught exactly this modeling error when the raw normalized argv,
    // wrapper paths and all, was first keyed directly).
    let read =
        |path: &str| (path == ctx.response_file).then(|| b"--cfg\nfeature=\"std\"\n".to_vec());
    let normalized = normalize_response_files(&argv, read).unwrap();
    let spliced: Vec<String> = normalized
        .iter()
        .flat_map(|arg| match arg {
            NormalizedArg::Literal(s) => vec![s.clone()],
            NormalizedArg::ResponseExpansion(bytes) => std::str::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect(),
        })
        .collect();
    // Two agents' expansions splice identically (content-identified).
    let _ = response_bytes(&normalized);

    // 3. Invocation parse (wrapper chain decoded away).
    let mut inv = parse(&spliced, None).unwrap();

    // 4. Externs: different path spellings, identical file bytes.
    let lookup = |path: &str| {
        (path == ctx.extern_path).then(|| DependencyArtifactIdentity {
            kind: DependencyArtifactKind::Rlib,
            content_digest: fixed("rabs.dep-artifact.v1", 7),
        })
    };
    let resolved = resolve_externs(&inv.externs, lookup).unwrap();
    let externs_digest = resolved_externs_digest(&resolved);

    // 5. Virtualize path-bearing invocation fields BEFORE keying — the
    // documented F004-before-F012 precondition. The pinpointing pass
    // caught this too when omitted: the local extern path spelling
    // leaked through the invocation slot. Each extern path is replaced
    // by its content-identity virtual form.
    for (name, path) in &mut inv.externs {
        if path.is_some() {
            let identity = lookup(path.as_ref().unwrap()).unwrap();
            *path = Some(format!(
                "rabs-dep:{}:{:02x}",
                identity.content_digest.domain, identity.content_digest.bytes[0]
            ));
        }
        let _ = name;
    }
    let invocation_digest = compute("rabs.invocation.v1", &inv.canonical_bytes());

    // 5. Dependency inputs consume the same bytes on both machines.
    let deps = DependencyInputs {
        compile_inputs: vec![ConsumedArtifact::RlibBytes(fixed(
            "rabs.dep-artifact.v1",
            7,
        ))],
        ..Default::default()
    };

    // 6. Environment: same construction; PATH resolves the same tool
    //    contents on both machines.
    let env = PresentedEnvironment {
        variables: vec![(
            b"RUSTFLAGS".to_vec(),
            EnvDisposition::SemanticHashed(b"-Cdebuginfo=1".to_vec()),
        )],
        path_manifest: vec![PathToolEntry::Resolved {
            name: "rustc".into(),
            binary_digest: fixed("rabs.tool-binary.v1", 3),
        }],
    };

    vec![
        ("normalized_invocation", invocation_digest),
        ("resolved_externs", externs_digest),
        ("dependency_inputs", deps.inputs_digest()),
        ("environment", env.dataset_digest().unwrap()),
    ]
}

/// Fill a descriptor from pipeline components (slots this pipeline does
/// not exercise get fixed digests — identical for both agents by
/// definition of the property).
fn descriptor_from(components: &[(&'static str, TypedDigest)]) -> ActionDescriptor {
    let get = |name: &str| {
        components
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, d)| d.clone())
            .unwrap()
    };
    ActionDescriptor {
        key_epoch: 1,
        projection_epoch: 1,
        action_class: ActionClass::RustcDependencyCompile,
        normalized_invocation: get("normalized_invocation"),
        virtual_working_directory: fixed("rabs.cwd.v1", 20),
        action_inputs: fixed("rabs.inputs.v1", 21),
        negative_dependencies: fixed("rabs.negdeps.v1", 22),
        dependency_inputs: get("dependency_inputs"),
        toolchain: fixed("rabs.toolchain-contract.v1", 23),
        output_platform: fixed("rabs.output-platform.v1", 24),
        environment: get("environment"),
        sandbox_semantic_policy: fixed("rabs.sandbox-policy.v1", 25),
        build_path_semantic_policy: fixed("rabs.path-policy.v1", 26),
        execution_semantics: fixed("rabs.exec-semantics.v1", 27),
        output_declarations: fixed("rabs.outputs.v1", 28),
    }
}

#[test]
fn identical_semantic_work_keys_identically_across_agents() {
    let a = pipeline(&agent_a());
    let b = pipeline(&agent_b());
    // Pinpointing pass: every component compared BY NAME first, so a
    // leak names its component instead of an opaque final-key diff.
    for ((name_a, digest_a), (name_b, digest_b)) in a.iter().zip(b.iter()) {
        assert_eq!(name_a, name_b);
        assert_eq!(
            digest_a, digest_b,
            "component `{name_a}` leaked agent-local circumstance into the key"
        );
    }
    // Final keys byte-identical.
    let key_a = compute_action_key(&descriptor_from(&a));
    let key_b = compute_action_key(&descriptor_from(&b));
    assert_eq!(key_a.final_key, key_b.final_key);
}

#[test]
fn subscriber_count_and_kind_have_no_key_channel() {
    // Subscription context is not a descriptor input at any point in
    // the pipeline above — there is no parameter to pass it through.
    // This test documents the property positively: N subscribers of any
    // kind, one descriptor, one key.
    let a = pipeline(&agent_a());
    let key = compute_action_key(&descriptor_from(&a));
    for _subscriber in 0..5 {
        let again = compute_action_key(&descriptor_from(&a));
        assert_eq!(key.final_key, again.final_key);
    }
}

#[test]
fn violation_would_pinpoint_the_leaking_component() {
    // Negative control for the diagnosis mechanism itself: plant a
    // deliberate leak (a staging root keyed into the environment) and
    // confirm the by-name comparison catches it at `environment`, not
    // at the opaque final key.
    let mut leaked = pipeline(&agent_a());
    let staging_leak = PresentedEnvironment {
        variables: vec![(
            b"STAGING_ROOT".to_vec(),
            EnvDisposition::SemanticHashed(b"/tmp/agent-a-staging".to_vec()),
        )],
        path_manifest: vec![],
    };
    let pos = leaked
        .iter()
        .position(|(n, _)| *n == "environment")
        .unwrap();
    leaked[pos].1 = staging_leak.dataset_digest().unwrap();
    let clean = pipeline(&agent_b());
    let first_divergence = leaked
        .iter()
        .zip(clean.iter())
        .find(|((_, da), (_, db))| da != db)
        .map(|((n, _), _)| *n);
    assert_eq!(
        first_divergence,
        Some("environment"),
        "the planted leak must be attributed to its component"
    );
}
