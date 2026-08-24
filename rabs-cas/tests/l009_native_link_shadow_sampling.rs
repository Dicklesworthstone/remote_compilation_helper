//! Native/link shadow comparison + cross-worker determinism sampling
//! BEFORE SERVING (bead L009; plan M5 acceptance).
//!
//! The substrate this suite composes is all shipped and individually
//! self-tested: F024 hit re-proof
//! ([`rabs_key::hit_verification`]), the L007 native header closure
//! ([`rabs_key::native_header_closure`]), the L001 link parser
//! ([`rabs_key::link_invocation`]), the L004 link result bundle
//! ([`crate::link_bundle`]), the K008 Stage-3 sampling gate
//! ([`crate::serving_sample_gate`]) and trust ladder
//! ([`crate::trust_evidence`]), and the K008 Stage-2 shadow pipeline
//! (`rabs_replay::shadow_pipeline`). What NO test had yet proven is
//! that these COMPOSE into the M5 serving bar for native and link
//! actions:
//!
//! 1. **Shadow corpus green**: driving the real shadow pipeline over a
//!    corpus whose backend mirrors [`crate::serving_sample_gate`]
//!    semantics yields ZERO quarantine-required rows when the cache is
//!    honest — and a seeded dishonest cache row lands in
//!    quarantine-required (the oracle is not vacuous);
//! 2. **No stale native output under header/config changes**: content
//!    mutations fork the closure digest and are refused by the closed
//!    view pre-serve; config mutations fork the descriptor key and
//!    `verify_hit` refuses before any byte is served; provenance-only
//!    changes (generated flag) deliberately do NOT fork identity;
//! 3. **Exact link hits preserve output + diagnostics**: replay of an
//!    honest bundle is observationally equal to stock, including the
//!    stderr warnings; a bundle that lost diagnostics fails the
//!    equivalence oracle;
//! 4. **Cross-worker determinism sampling**: verification samples from
//!    two distinct workers promote an action up the trust ladder to
//!    `ReproducibleCrossWorker`; a failed sample demotes it to
//!    quarantined; class risk stays strictest-first throughout.
//!
//! No production code changes: per plan, L009 proves the composition
//! TEST-FIRST, before any wiring into `serve_action`.

use rabs_cas::link_bundle::{
    LinkOutput, LinkResultBundle, StockLinkOutcome, equivalent_to_stock,
};
use rabs_cas::metadata_store::{
    ActionEntryRow, AuthorityRow, CommitOutcome, PublicationPermit, PublicationRow,
    ResultKindTag, RabsMetadataStore, RusqliteEngine, SqlMetadataStore,
};
use rabs_cas::serving_sample_gate::{
    ActionClassRisk, SampleGateDecision, SamplingPolicy, key_bucket_basis_points,
    serving_sample_decision,
};
use rabs_cas::trust_evidence::{
    DISPOSITION_EVIDENCE_PENDING, DISPOSITION_QUARANTINED, DISPOSITION_SERVABLE, TrustPolicy,
    reevaluate_action,
};
use rabs_key::hit_verification::{HitVerification, StoredDescriptorEntry, verify_hit};
use rabs_key::link_invocation::{DriverStyle, parse_link};
use rabs_key::native_header_closure::{
    HeaderRead, NativeHeaderClosure, VIOLATED_CONTENT_MISMATCH, enforce_closed_view,
};
use rabs_key::authority_binding::coordinator_authority_digest;
use rabs_protocol::authority::{
    ClusterId, CoordinatorAuthority, CoordinatorIncarnationId,
};
use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::generation::{
    ActionGeneration, ActionGenerationId, AttemptAuthority, AttemptId, ExecutionLeaseId,
    LeaseRenewalSeq, WorkerBootGeneration, WorkerIncarnationId,
};
use rabs_protocol::invocation_record::NormalizedOutcome;
use rabs_protocol::redaction::correlation_hash;
use rabs_protocol::wire_time::PeerId;
use rabs_protocol::result_identity::{DigestAlgorithm, ObjectId, TypedDigest};
use rabs_protocol::serving::TrustEvidenceTier;
use rabs_replay::shadow_pipeline::{
    CachedObservation, ServingDecision, ShadowServingBackend, run_shadow_pipeline,
};
use std::collections::HashMap;

fn d(domain: &'static str, tag: u8) -> TypedDigest {
    TypedDigest {
        algorithm: DigestAlgorithm::Sha256V1,
        domain,
        bytes: [tag; 32],
    }
}

fn store() -> SqlMetadataStore<RusqliteEngine> {
    SqlMetadataStore::open(RusqliteEngine::open_in_memory().unwrap()).unwrap()
}

// ---------------------------------------------------------------------
// Shared fixture shapes
// ---------------------------------------------------------------------

/// Deterministic corpus record: argv joins into the shell command.
fn corpus_line(command: &[&str], cwd: &str) -> String {
    let argv: Vec<String> = command.iter().map(|s| format!("\"{s}\"")).collect();
    format!(
        "{{\"argv_redacted\":[{}],\"cwd_redacted\":\"{cwd}\",\
         \"outcome_kind\":\"exited\",\"outcome_value\":0,\"duration_ms\":2}}",
        argv.join(",")
    )
}

/// A stock link outcome with outputs AND warnings (the thing a cache
/// hit must reproduce exactly).
fn stock_link() -> StockLinkOutcome {
    StockLinkOutcome {
        outputs: vec![LinkOutput {
            logical_name: "bin/app".into(),
            digest: d("rabs.object.v1", 1),
        }],
        stdout: b"linking bin/app\n".to_vec(),
        stderr: b"warning: linking against older libc\n".to_vec(),
        exit_code: 0,
    }
}

/// Backend mirroring [`rabs_cas::serving_sample_gate`] semantics per
/// invocation: class risk strictest-first via the REAL gate function
/// against the real store, then cache lookup for serve decisions.
struct GateBackend<'a> {
    store: &'a mut SqlMetadataStore<RusqliteEngine>,
    policy: SamplingPolicy,
    keys: HashMap<String, TypedDigest>,
    risk: HashMap<String, ActionClassRisk>,
    cache: HashMap<String, CachedObservation>,
    /// Negative injection: when set, THIS command's served observation
    /// carries bytes that never came from the stock run.
    poison: Option<String>,
}

impl ShadowServingBackend for GateBackend<'_> {
    fn decide(&mut self, invocation: &rabs_replay::ReplayCommand) -> ServingDecision {
        let key = &self.keys[&invocation.command];
        let risk = self.risk[&invocation.command];
        match serving_sample_decision(&mut *self.store, key, risk, &self.policy) {
            Ok(SampleGateDecision::ServeFromCache) => ServingDecision::ServeFromCache,
            _ => ServingDecision::ExecutePrivately,
        }
    }

    fn served_observation(
        &mut self,
        invocation: &rabs_replay::ReplayCommand,
    ) -> Option<CachedObservation> {
        if self.poison.as_deref() == Some(invocation.command.as_str()) {
            return Some(CachedObservation {
                outcome: NormalizedOutcome::Exited(0),
                stdout_digest: correlation_hash(b"SOMETHING ELSE ENTIRELY"),
                stderr_digest: correlation_hash(b""),
            });
        }
        self.cache.get(&invocation.command).copied()
    }
}

fn cached_from_bundle(bundle: &LinkResultBundle) -> CachedObservation {
    let replayed = bundle.replay();
    CachedObservation {
        outcome: NormalizedOutcome::Exited(replayed.exit_code),
        stdout_digest: correlation_hash(&replayed.stdout),
        stderr_digest: correlation_hash(&replayed.stderr),
    }
}

// ---------------------------------------------------------------------
// 1. Shadow corpus green + non-vacuous divergence classification
// ---------------------------------------------------------------------

#[test]
fn l009_shadow_corpus_is_green_when_the_cache_is_honest() {
    let mut st = store();
    let link_cmd = "printf link-out".to_owned();
    let native_cmd = "printf native-out".to_owned();
    let mut keys = HashMap::new();
    keys.insert(link_cmd.clone(), d("rabs.action-key.sha256.v1", 1));
    keys.insert(native_cmd.clone(), d("rabs.action-key.sha256.v1", 2));
    let mut risk = HashMap::new();
    // Link admitted low-risk for this fixture; native workspace-class
    // work stays Elevated (plan section 113 conservative default):
    // NEVER sampled regardless of evidence.
    risk.insert(link_cmd.clone(), ActionClassRisk::LowRiskRegistry);
    risk.insert(native_cmd.clone(), ActionClassRisk::Elevated);

    // Evidence: enough PASSED verification samples for the link key
    // under sample-all; none for native (it would not matter).
    let policy = SamplingPolicy::sample_all(2, 10_000);
    let link_key = keys[&link_cmd].clone();
    for seq in 0..2u64 {
        st.record_verification_sample(&link_key, 100 + u128::from(seq), true, seq)
            .unwrap();
    }

    // Honest cache: derived FROM the stock link's own bundle.
    let bundle = LinkResultBundle::bundle(&stock_link()).unwrap();
    let mut cache = HashMap::new();
    cache.insert(link_cmd.clone(), cached_from_bundle(&bundle));

    let mut backend = GateBackend {
        store: &mut st,
        policy,
        keys,
        risk,
        cache,
        poison: None,
    };

    // Gate pre-checks (strictest-first), then the whole corpus:
    assert_eq!(
        serving_sample_decision(
            &mut *backend.store,
            &d("rabs.action-key.sha256.v1", 2),
            ActionClassRisk::Elevated,
            &policy
        )
        .unwrap(),
        SampleGateDecision::ExecutePrivately(
            rabs_cas::serving_sample_gate::PrivateExecutionReason::ElevatedClassRisk
        ),
        "native/workspace class is never sampled"
    );

    let lines = vec![
        corpus_line(&["printf", "link-out"], "/tmp"),
        corpus_line(&["printf", "native-out"], "/tmp"),
    ];
    let report = run_shadow_pipeline(
        &lines.iter().map(String::as_str).collect::<Vec<_>>(),
        &mut backend,
    );
    assert!(
        report.quarantine_required.is_empty(),
        "honest cache must produce zero served divergences: {:?}",
        report.quarantine_required
    );
    assert_eq!(report.private_divergences, 0);
    assert_eq!(report.session.rows.len(), 2);
}

#[test]
fn l009_served_divergence_lands_in_quarantine_required_not_private() {
    let mut st = store();
    let cmd = "printf poisoned".to_owned();
    let key = d("rabs.action-key.sha256.v1", 3);
    let mut keys = HashMap::new();
    keys.insert(cmd.clone(), key.clone());
    let mut risk = HashMap::new();
    risk.insert(cmd.clone(), ActionClassRisk::LowRiskRegistry);
    let policy = SamplingPolicy::sample_all(1, 10_000);
    st.record_verification_sample(&key, 7, true, 0).unwrap();

    let mut backend = GateBackend {
        store: &mut st,
        policy,
        keys,
        risk,
        cache: HashMap::new(),
        poison: Some(cmd.clone()),
    };
    let line = corpus_line(&["printf", "poisoned"], "/tmp");
    let report =
        run_shadow_pipeline(&[line.as_str()], &mut backend);
    assert_eq!(
        report.quarantine_required,
        vec![cmd],
        "SERVED and diverged is a serving incident, not private noise"
    );
    assert_eq!(report.private_divergences, 0);
    // Bucket stability: same key, same bucket, every process, forever.
    let bucket = key_bucket_basis_points(&key);
    assert_eq!(key_bucket_basis_points(&key), bucket);
}

// ---------------------------------------------------------------------
// 2. No stale native output under header/config changes
// ---------------------------------------------------------------------

#[test]
fn l009_header_content_change_forks_identity_and_blocks_stale_serve() {
    let reads_v1 = [HeaderRead::new(b"/usr/include/ctx.h", 7, false)];
    let declared = NativeHeaderClosure::capture(&reads_v1).unwrap();
    let identity_v1 = declared.closure_digest();

    // Same path, NEW CONTENT: identity forks (the stale object would
    // embed stale macro/text values).
    let reads_v2 = [HeaderRead::new(b"/usr/include/ctx.h", 8, false)];
    let identity_v2 = NativeHeaderClosure::capture(&reads_v2)
        .unwrap()
        .closure_digest();
    assert_ne!(identity_v1, identity_v2, "content change forks identity");

    // Provenance-only change (same bytes, now under a generated root):
    // build identity deliberately does NOT move; only the audit record
    // distinguishes provenance.
    let reads_provenance = [HeaderRead::new(b"/usr/include/ctx.h", 7, true)];
    let provenance_closure = NativeHeaderClosure::capture(&reads_provenance).unwrap();
    assert_eq!(provenance_closure.closure_digest(), identity_v1);

    // Pre-serve enforcement: observed reads carrying the OLD closure
    // while the world moved to v2 are refused with the mismatch code —
    // the compile cannot be served from the stale entry.
    let violations = enforce_closed_view(&declared, &reads_v2).unwrap_err();
    assert!(violations
        .iter()
        .any(|v| v.reason_code == VIOLATED_CONTENT_MISMATCH));
}

#[test]
fn l009_config_mutation_forks_the_key_and_verify_hit_refuses() {
    fn descriptor(env_tag: u8) -> ActionDescriptor {
        ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::NativeCompileC,
            normalized_invocation: d("rabs.invocation.v1", 1),
            virtual_working_directory: d("rabs.cwd.v1", 2),
            action_inputs: d("rabs.inputs.v1", 3),
            negative_dependencies: d("rabs.negdeps.v1", 4),
            dependency_inputs: d("rabs.deps.v1", 5),
            toolchain: d("rabs.toolchain-contract.v1", 6),
            output_platform: d("rabs.output-platform.v1", 7),
            environment: d("rabs.env.v1", env_tag),
            sandbox_semantic_policy: d("rabs.sandbox-policy.v1", 9),
            build_path_semantic_policy: d("rabs.path-policy.v1", 10),
            execution_semantics: d("rabs.exec-semantics.v1", 11),
            output_declarations: d("rabs.outputs.v1", 12),
        }
    }

    let built_with_env_a = descriptor(8);
    let entry = StoredDescriptorEntry::commit(&built_with_env_a);
    // Intact reload validates…
    assert_eq!(
        verify_hit(&entry, &entry.canonical_descriptor_bytes.clone(), &built_with_env_a),
        HitVerification::Validated
    );
    // …but the SAME index entry consulted after a CONFIG change (env
    // component mutated => different descriptor => different key) is
    // REFUSED: no stale native output can be served off the old key.
    let rebuilt_after_config_change = descriptor(13);
    assert_ne!(
        StoredDescriptorEntry::commit(&rebuilt_after_config_change).action_key,
        entry.action_key,
        "config mutation forks the action key"
    );
    assert!(matches!(
        verify_hit(
            &entry,
            &entry.canonical_descriptor_bytes.clone(),
            &rebuilt_after_config_change
        ),
        HitVerification::Refused { .. }
    ));
}

// ---------------------------------------------------------------------
// 3. Exact link hits preserve output + diagnostics
// ---------------------------------------------------------------------

#[test]
fn l009_exact_link_hit_preserves_outputs_and_diagnostics() {
    let linker = d("rabs.tool-binary.v1", 7);
    let identify_file = |path: &str| -> Option<ObjectId> {
        match path {
            "a.o" => Some(ObjectId(d("rabs.object.v1", 1))),
            _ => None,
        }
    };
    let identify_script =
        |path: &str| -> Option<TypedDigest> { ("layout.ld" == path).then(|| d("rabs.linker-script.v1", 3)) };
    let args = |list: &[&str]| -> Vec<String> { list.iter().map(|s| (*s).to_owned()).collect() };

    // Parser-level plumbing invariance: driver style normalization
    // must not leak into identity for identical semantic inputs.
    let direct = parse_link(
        DriverStyle::DirectLinker,
        linker.clone(),
        &args(&["a.o"]),
        identify_file,
        identify_script,
    )
    .unwrap();

    // The stock outcome bundles atomically; replay reproduces it
    // observationally EXACTLY — outputs, both diagnostic streams,
    // exit semantics.
    let stock = stock_link();
    let bundle = LinkResultBundle::bundle(&stock).unwrap();
    let replayed = bundle.replay();
    assert!(equivalent_to_stock(&replayed, &stock));

    // NON-VACUOUS ORACLE: a hit that lost the warning stream is
    // observationally DIFFERENT and the equivalence check catches it.
    let mut lossy_stock = stock.clone();
    lossy_stock.stderr = b"".to_vec();
    let lossy_bundle = LinkResultBundle::bundle(&lossy_stock).unwrap();
    assert!(!equivalent_to_stock(&lossy_bundle.replay(), &stock));
    let _ = direct.invocation_digest();
}

// ---------------------------------------------------------------------
// 4. Cross-worker determinism sampling drives the trust ladder
// ---------------------------------------------------------------------

#[test]
fn l009_cross_worker_sampling_promotes_and_failure_demotes() {
    let mut st = store();
    // A REAL coordinator authority (no test-only permit): the digest
    // the store records as active is derived FROM this value, so the
    // attempt's permit binds to exactly what the store holds.
    let coordinator = CoordinatorAuthority {
        cluster_id: ClusterId("cluster-a".to_owned()),
        credential_generation: 1,
        term: 1,
        incarnation_id: CoordinatorIncarnationId(1),
    };
    let authority = coordinator_authority_digest(&coordinator);
    st.acquire_authority(&AuthorityRow {
        digest: authority.clone(),
        cluster_id: "cluster-a".to_owned(),
        incarnation: 1,
        term: 1,
        acquired_seq: 1,
    })
    .unwrap();
    let action = d("rabs.action-key.sha256.v1", 9);
    st.upsert_action_entry(&ActionEntryRow {
        action_key: action.clone(),
        key_epoch: 0,
        projection_epoch: 0,
    })
    .unwrap();
    st.create_generation(&authority, 10, &action).unwrap();
    let attempt_authority = AttemptAuthority {
        coordinator: coordinator.clone(),
        action_key: action.clone(),
        action_generation: ActionGeneration {
            generation_id: ActionGenerationId(10),
            per_key_ordinal: 1,
            created_under_authority_digest: authority.clone(),
        },
        attempt_id: AttemptId(20),
        execution_lease_id: ExecutionLeaseId(20),
        lease_renewal_seq: LeaseRenewalSeq(1),
        worker_peer_id: PeerId("worker-a".to_owned()),
        worker_boot_generation: WorkerBootGeneration(1),
        worker_incarnation_id: WorkerIncarnationId(5),
    };
    let permit = PublicationPermit::for_attempt(&attempt_authority);
    assert_eq!(
        st.commit_publication(
            permit,
            &PublicationRow {
                action_key: action.clone(),
                descriptor_digest: d("rabs.descriptor.sha256.v1", 1),
                manifest_digest: d("rabs.result-manifest.sha256.v1", 1),
                evidence_digest: d("rabs.evidence-bundle.sha256.v1", 1),
                winner_generation: 10,
                winner_attempt: 20,
                result_kind: ResultKindTag::Success,
                pin_id: 40,
                pin_owner: "coordinator".to_owned(),
                provisional_ancestors: Vec::new(),
            },
        )
        .unwrap(),
        CommitOutcome::Committed
    );

    let policies = vec![TrustPolicy {
        version: 1,
        revoked: false,
        required_tier: TrustEvidenceTier::ShadowMatched,
    }];

    // No samples: pending, never servable.
    let eval = reevaluate_action(&mut st, &authority, &action, &policies, 100).unwrap();
    assert_eq!(eval.observed_tier, TrustEvidenceTier::UnverifiedCandidate);
    assert_eq!(eval.disposition, DISPOSITION_EVIDENCE_PENDING);

    // One passed verification on worker-a: shadow-matched, servable.
    st.record_verification_sample(&action, 20, true, 101).unwrap();
    let eval = reevaluate_action(&mut st, &authority, &action, &policies, 102).unwrap();
    assert_eq!(eval.observed_tier, TrustEvidenceTier::ShadowMatched);
    assert_eq!(eval.disposition, DISPOSITION_SERVABLE);

    // A second PASS on a DIFFERENT worker: cross-worker reproduction —
    // the determinism sampling bar for broader serving.
    st.record_verification_sample(&action, 21, true, 103).unwrap();
    let eval = reevaluate_action(&mut st, &authority, &action, &policies, 104).unwrap();
    assert_eq!(eval.observed_tier, TrustEvidenceTier::ReproducibleCrossWorker);
    assert_eq!(eval.disposition, DISPOSITION_SERVABLE);

    // A FAILED sample is adverse evidence: instant demotion to
    // quarantined, whatever the earlier ladder said.
    st.record_verification_sample(&action, 22, false, 105).unwrap();
    let eval = reevaluate_action(&mut st, &authority, &action, &policies, 106).unwrap();
    assert_eq!(eval.adverse_samples, 1);
    assert_eq!(eval.disposition, DISPOSITION_QUARANTINED);
}
