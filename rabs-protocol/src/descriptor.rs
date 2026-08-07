//! Semantic `ActionDescriptor` versus non-key subscription/dispatch context
//! (bead A014; invariants I23/I24; plan Part VI §16).
//!
//! The split, enforced structurally:
//!
//! | Layer | Type | May contain | Keyed? |
//! |---|---|---|---|
//! | Semantic identity | [`ActionDescriptor`] | everything that can change output bytes or exit behavior | YES — its components are exactly the key inputs |
//! | Subscription | [`ActionSubscriptionContext`] | who is asking, presentation, path translation, minimum evidence, priority, deadline | never |
//! | Placement constraints | [`ExecutionRequirements`] | serving/placement constraints proven output-neutral | never |
//! | Concrete attempt | [`AttemptDispatchContext`] | selected worker, resource grant, sandbox implementation, object sources | never |
//!
//! `ActionDescriptor` is immutable after final key computation. Subscriber
//! priority can be promoted, path translation can change, workers can be
//! reselected — none of that may fragment or alter the artifact key. Any
//! requirement capable of changing output bytes belongs in the descriptor
//! (e.g. `OutputPlatformContract`), never in `ExecutionRequirements`.
//!
//! Component values are carried as [`TypedDigest`]s of their canonically
//! serialized forms — the component serializers land with their Epic F
//! beads (F003 invocation, F006 environment, F007 toolchain, ...); the
//! SHAPE of the split is fixed here so those beads fill slots instead of
//! inventing structure.

use crate::result_identity::{ObjectId, TypedDigest};
use crate::wire_time::{DeadlineBudget, PeerId};

/// The semantic action classes (plan §15). Purpose/priority are NOT
/// classes — a speculative and a foreground compile with identical
/// semantics must share one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)] // Variant names are the plan's own vocabulary.
pub enum ActionClass {
    CargoWholeCommandBounded,
    RustcDependencyCompile,
    RustcWorkspaceCompile,
    RustdocCompile,
    Link,
    BuildScriptCompile,
    BuildScriptRun,
    NativeCompileC,
    NativeCompileCxx,
    NativeArchive,
    BindgenGeneration,
    CodeGeneratorRun,
    NextestTestCase,
    TestBinaryBatch,
    DoctestCompile,
    DoctestRun,
    ClippyCompile,
    BenchmarkCompile,
    BenchmarkRun,
    ToolchainProbe,
    WorkerProbe,
}

/// The immutable semantic descriptor: its fields are EXACTLY the action-key
/// inputs (plan §16/§17). No subscriber, priority, worker, or presentation
/// field exists here — that absence is the boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDescriptor {
    /// Key epoch (cold-namespace invalidation lever).
    pub key_epoch: u32,
    /// Projection epoch (dependency/input projection versioning).
    pub projection_epoch: u32,
    /// Semantic output class.
    pub action_class: ActionClass,
    /// Digest of the normalized invocation (F003 owns serialization).
    pub normalized_invocation: TypedDigest,
    /// Digest of the single authoritative virtual working directory
    /// (exactly one representation — F030/R107).
    pub virtual_working_directory: TypedDigest,
    /// Digest of the positive `ActionInputManifest` (E010).
    pub action_inputs: TypedDigest,
    /// Digest of the `NegativeDependencySet` (E010/E020).
    pub negative_dependencies: TypedDigest,
    /// Digest over ordered conservative dependency-artifact inputs (F009).
    pub dependency_inputs: TypedDigest,
    /// Toolchain contract digest (F007).
    pub toolchain: TypedDigest,
    /// Output-platform contract digest (F008 keyed half).
    pub output_platform: TypedDigest,
    /// Presented-environment digest (F006).
    pub environment: TypedDigest,
    /// Sandbox semantic policy digest (E001; scheduler-only details excluded).
    pub sandbox_semantic_policy: TypedDigest,
    /// Build-path semantic policy digest (D030/I41).
    pub build_path_semantic_policy: TypedDigest,
    /// Execution-semantics contract digest.
    pub execution_semantics: TypedDigest,
    /// Logical output declarations digest (F011).
    pub output_declarations: TypedDigest,
}

impl ActionDescriptor {
    /// The ordered key-input component list — the SINGLE source of what
    /// enters `ActionKey` hashing (F034 frames these bytes). Exhaustive by
    /// destructuring: adding a descriptor field without deciding its key
    /// role becomes a compile error here.
    #[must_use]
    pub fn key_input_components(&self) -> Vec<(&'static str, &TypedDigest)> {
        let Self {
            key_epoch: _,
            projection_epoch: _,
            action_class: _,
            normalized_invocation,
            virtual_working_directory,
            action_inputs,
            negative_dependencies,
            dependency_inputs,
            toolchain,
            output_platform,
            environment,
            sandbox_semantic_policy,
            build_path_semantic_policy,
            execution_semantics,
            output_declarations,
        } = self;
        vec![
            ("normalized_invocation", normalized_invocation),
            ("virtual_working_directory", virtual_working_directory),
            ("action_inputs", action_inputs),
            ("negative_dependencies", negative_dependencies),
            ("dependency_inputs", dependency_inputs),
            ("toolchain", toolchain),
            ("output_platform", output_platform),
            ("environment", environment),
            ("sandbox_semantic_policy", sandbox_semantic_policy),
            ("build_path_semantic_policy", build_path_semantic_policy),
            ("execution_semantics", execution_semantics),
            ("output_declarations", output_declarations),
        ]
    }
}

/// Why a subscriber wants this action (never a key input; plan §21.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)] // Plan vocabulary.
pub enum SubscriberKind {
    ForegroundInteractive,
    ForegroundAgent,
    CiRequired,
    Speculative,
    GitPrewarm,
    VerificationAudit,
    DeterminismAudit,
    AdministrativeRepair,
}

/// Serving/placement constraints proven not to alter output bytes or exit
/// behavior (I23). Anything that CAN alter them belongs in the descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRequirements {
    /// Minimum isolation profile the subscriber will accept.
    pub minimum_isolation_profile: crate::authority_matrix::IsolationProfile,
    /// Privacy/access scope identifier.
    pub privacy_scope: String,
    /// Required worker capability names.
    pub required_worker_capabilities: Vec<String>,
}

/// Per-subscriber request context: presentation, translation, priority —
/// mutable through promotion WITHOUT touching the artifact key (I24).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionSubscriptionContext {
    /// Full command snapshot root (materialization/provenance — NOT
    /// automatically a fine-grained key component; I4/F019).
    pub execution_snapshot_root: ObjectId,
    /// The requesting edge.
    pub requesting_edge: PeerId,
    /// Why this subscriber wants the action.
    pub subscriber_kind: SubscriberKind,
    /// Presentation contract digest (color/width/rendering — I24).
    pub presentation: TypedDigest,
    /// Path-translation table identity (virtual -> this worktree).
    pub path_translation: TypedDigest,
    /// Placement constraints (output-neutral by contract).
    pub execution_requirements: ExecutionRequirements,
    /// Queue priority (promotable).
    pub queue_priority: u8,
    /// Optional deadline budget.
    pub deadline_budget: Option<DeadlineBudget>,
}

/// Concrete-attempt context, created only AFTER coordinator scheduling;
/// unique to one attempt and never part of semantic result identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptDispatchContext {
    /// The snapshot root selected for materialization.
    pub selected_execution_snapshot_root: ObjectId,
    /// The selected worker.
    pub selected_worker: PeerId,
    /// Sandbox implementation chosen (may vary within one semantic policy).
    pub sandbox_implementation: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_matrix::IsolationProfile;
    use crate::result_identity::DigestAlgorithm;

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
    fn key_components_are_exactly_the_twelve_semantic_digests() {
        let names: Vec<&str> = descriptor()
            .key_input_components()
            .iter()
            .map(|(n, _)| *n)
            .collect();
        assert_eq!(
            names,
            vec![
                "normalized_invocation",
                "virtual_working_directory",
                "action_inputs",
                "negative_dependencies",
                "dependency_inputs",
                "toolchain",
                "output_platform",
                "environment",
                "sandbox_semantic_policy",
                "build_path_semantic_policy",
                "execution_semantics",
                "output_declarations",
            ],
            "the key-input component list drifted — that is a key-epoch \
             decision (F002), not an incidental edit"
        );
    }

    #[test]
    fn subscription_and_dispatch_mutations_cannot_reach_the_key() {
        // The boundary proof at the type level: derive the key components,
        // then mutate EVERY subscription/dispatch field — the descriptor
        // (and therefore the key inputs) has no channel through which any
        // of it could flow.
        let desc = descriptor();
        let before: Vec<TypedDigest> = desc
            .key_input_components()
            .into_iter()
            .map(|(_, v)| v.clone())
            .collect();

        let mut sub = ActionSubscriptionContext {
            execution_snapshot_root: ObjectId(d("rabs.snapshot.v1", 20)),
            requesting_edge: PeerId("edge-a".into()),
            subscriber_kind: SubscriberKind::Speculative,
            presentation: d("rabs.presentation.v1", 21),
            path_translation: d("rabs.path-translation.v1", 22),
            execution_requirements: ExecutionRequirements {
                minimum_isolation_profile: IsolationProfile::StrictHermeticLinux,
                privacy_scope: "default".into(),
                required_worker_capabilities: vec![],
            },
            queue_priority: 3,
            deadline_budget: None,
        };
        // Promotion: speculative -> foreground, priority raised, deadline set.
        sub.subscriber_kind = SubscriberKind::ForegroundAgent;
        sub.queue_priority = 0;
        sub.deadline_budget = Some(DeadlineBudget::from_ms(30_000));
        // Different worker/sandbox choices per attempt.
        let _attempt_a = AttemptDispatchContext {
            selected_execution_snapshot_root: ObjectId(d("rabs.snapshot.v1", 20)),
            selected_worker: PeerId("wkr-1".into()),
            sandbox_implementation: "bubblewrap".into(),
        };
        let _attempt_b = AttemptDispatchContext {
            selected_execution_snapshot_root: ObjectId(d("rabs.snapshot.v1", 20)),
            selected_worker: PeerId("wkr-2".into()),
            sandbox_implementation: "namespaces-direct".into(),
        };

        let after: Vec<TypedDigest> = desc
            .key_input_components()
            .into_iter()
            .map(|(_, v)| v.clone())
            .collect();
        assert_eq!(before, after, "key inputs must be untouched by any of it");
    }

    #[test]
    fn speculative_and_foreground_share_semantics() {
        // SubscriberKind is not a descriptor field; two subscriptions of
        // different kinds against one descriptor imply one key (plan §15).
        let a = descriptor();
        let b = descriptor();
        assert_eq!(a, b);
        assert_eq!(a.key_input_components(), b.key_input_components());
    }
}
