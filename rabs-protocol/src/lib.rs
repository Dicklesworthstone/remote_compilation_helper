//! # rabs-protocol — stable RABS domain and wire schemas
//!
//! Shared by tiny wrappers, `rabs-edge`, `rabs-coord`, `rabs-wkr`, optional
//! gateways, fixtures, and test harnesses. This crate is the single canonical
//! owner of every type that crosses a process, wire, or persistence boundary
//! in RABS (invariant I14: stable public boundaries).
//!
//! ## Dependency rules (binding; enforced by dependency-direction CI, bead A002)
//!
//! - **No Asupersync dependency.** Asupersync implementation types must never
//!   appear in stable wire formats, durable rows, or public CLI JSON.
//!   Adapters in `rabs-asupersync` convert in both directions.
//! - **No Tokio dependency.**
//! - **No filesystem or process effects.** This crate defines data, codecs,
//!   and schema versions only.
//! - Canonical codecs and explicit schema versions for every type; bounded
//!   collections, recursion, and payloads; explicit forward/unknown-field
//!   policy; golden wire fixtures; compatibility tests for current and
//!   previous supported versions (N/N-1).
//!
//! ## Planned primary types (populated by beads A014, A017–A020, A023, A024,
//! F023, and Epic J)
//!
//! `ActionKey`, `ActionKeyEpoch`, `ActionClass`, `ResultKind`,
//! `ActionDescriptor`, `ActionSubscriptionContext`, `AttemptDispatchContext`,
//! `CanonicalActionResultManifest`, `AttemptEvidenceBundle`,
//! `ActionPublicationRecord`, `ActionTrustEvaluationRecord`, `ActionFailure`,
//! `BuildPathSemanticPolicyId`, `TrustEvidenceTier`, `SubscriberDeliveryState`,
//! `ObservableCommitKind`, `ExecutionSnapshotRoot`, `ActionInputManifest`,
//! `NegativeDependencySet`, `BuildOperationId`, `SubscriberId`,
//! `ActionGeneration`, `ActionGenerationId`, `AttemptId`, `ExecutionLeaseId`,
//! `LeaseRenewalSeq`, `CoordinatorAuthority`, `WorkerBootGeneration`,
//! `WorkerIncarnationId`, `EdgeBootGeneration`, `EdgeIncarnationId`,
//! `OutputPlatformContract`, `ExecutionEligibility`, `ToolchainContract`,
//! `SandboxSemanticPolicyId`, `PresentationContract`,
//! `CanonicalCompilerEvent`, `PathTranslationTable`, `DeadlineBudget`,
//! `CausalTimestamp`, `SequenceDomain`, `ObservedInputRecipe`,
//! `OutputDeclaration`, `TrustEvidenceRecord`, `WorkerCapabilities`,
//! `WorkerPressureSnapshot`, `DecisionReceipt`, `ProvenanceReceipt`, local
//! wrapper request/response/event envelopes, and ATP application payloads.
//!
//! On Unix, paths, argv elements, environment keys/values, and symlink
//! targets are canonical **byte strings**, never assumed UTF-8 (bead A019);
//! human/JSON displays use escaped presentation forms without changing the
//! keyed bytes.

pub mod authority;
pub mod authority_matrix;
pub mod capability_tokens;
pub mod class_policy;
pub mod compat_doctor;
pub mod computation_registry;
pub mod control_reserve;
pub mod decision_receipt;
pub mod descriptor;
pub mod domain_plumbing;
pub mod durable_ids;
pub mod envelope;
pub mod frame_extensions;
pub mod framing;
pub mod generation;
pub mod incremental_snapshot;
pub mod input_evidence;
pub mod invocation_record;
pub mod lease_semantics;
pub mod local_protocol;
pub mod messages;
pub mod nextest_runner;
pub mod nextest_serving_gate;
pub mod object_model;
pub mod object_transfer;
pub mod peer_limits;
pub mod peer_queues;
pub mod portability;
pub mod pressure;
pub mod raw_bytes;
pub mod reason_codes;
pub mod redaction;
pub mod resource_envelope;
pub mod result_identity;
pub mod schema_registry;
pub mod secret_redaction;
pub mod sequence_domains;
pub mod serving;
pub mod snapshot_lineage;
pub mod trust_domain;
pub mod version_negotiation;
pub mod volatility;
pub mod wire_time;
pub mod worker_fence;
pub mod zero_rtt_policy;
