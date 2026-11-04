//! Key-breakdown diffing and the stable miss-cause taxonomy (bead F013;
//! plan §102).
//!
//! A miss explanation is a **structured diff between prior and current
//! key breakdowns** — never prose. `rch why miss` renders these causes;
//! agents branch on them; the taxonomy is append-only (like reason codes,
//! A006) so automation never breaks on wording.
//!
//! Two layers:
//! - [`diff_breakdowns`] attributes a component-level miss (both
//!   breakdowns exist, keys differ);
//! - [`LookupOutcome`] covers the cases where there is nothing to diff
//!   (first seen, quarantined/expired/evicted, trust-refused,
//!   materialization-unavailable) — those come from the index, not the
//!   key.

use crate::action_key::{
    ActionKeyBreakdown, ActionKeyHeader, BorrowedKeyComponent, KeyReconstructionError,
    validate_key_inputs,
};

/// The stable miss-cause taxonomy (plan §102's list, component-attributed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MissCause {
    /// Positive source input set changed (`action_inputs`).
    SourceChanged,
    /// A previously failed open/listing/lookup now resolves differently
    /// (`negative_dependencies`).
    NegativeDependencyChanged,
    /// The exact dependency artifacts consumed changed
    /// (`dependency_inputs`).
    DependencyArtifactChanged,
    /// Invocation flags/profile/features changed
    /// (`normalized_invocation`).
    InvocationChanged,
    /// The presented environment changed (`environment`).
    EnvironmentChanged,
    /// Toolchain identity changed (`toolchain`).
    ToolchainChanged,
    /// Output-platform contract changed (`output_platform`).
    PlatformChanged,
    /// Sandbox semantic policy changed (`sandbox_semantic_policy`).
    SandboxPolicyChanged,
    /// Build-path semantic policy changed (`build_path_semantic_policy`).
    BuildPathPolicyChanged,
    /// Virtual working directory changed (`virtual_working_directory`).
    WorkingDirectoryChanged,
    /// Execution-semantics contract changed (`execution_semantics`).
    ExecutionSemanticsChanged,
    /// Declared logical outputs changed (`output_declarations`).
    OutputDeclarationsChanged,
    /// Key or projection epoch differs: a cold namespace, not a
    /// component change (F002).
    EpochMismatch,
    /// Action class differs (different semantic output class entirely).
    ActionClassChanged,
}

/// Map a breakdown component name to its miss cause. Total over A014's
/// component list; an unknown name is a schema drift bug and panics in
/// tests via the exhaustiveness check below.
#[must_use]
pub fn cause_for_component(name: &str) -> Option<MissCause> {
    Some(match name {
        "normalized_invocation" => MissCause::InvocationChanged,
        "virtual_working_directory" => MissCause::WorkingDirectoryChanged,
        "action_inputs" => MissCause::SourceChanged,
        "negative_dependencies" => MissCause::NegativeDependencyChanged,
        "dependency_inputs" => MissCause::DependencyArtifactChanged,
        "toolchain" => MissCause::ToolchainChanged,
        "output_platform" => MissCause::PlatformChanged,
        "environment" => MissCause::EnvironmentChanged,
        "sandbox_semantic_policy" => MissCause::SandboxPolicyChanged,
        "build_path_semantic_policy" => MissCause::BuildPathPolicyChanged,
        "execution_semantics" => MissCause::ExecutionSemanticsChanged,
        "output_declarations" => MissCause::OutputDeclarationsChanged,
        _ => return None,
    })
}

/// Index-level lookup outcomes with nothing to diff (plan §102 tail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupOutcome {
    /// No prior entry for this key: first seen.
    FirstSeen,
    /// Entry exists but its serving disposition blocks it (quarantined /
    /// expired / evicted — the disposition record says which, A020).
    ServingBlocked,
    /// Entry exists but the subscriber's minimum trust tier is unmet.
    TrustRefused,
    /// Entry exists but its object closure is not materializable now.
    MaterializationUnavailable,
}

/// Diff two breakdowns for the same logical unit. Returns every
/// component-level cause, in canonical component order; epoch/class
/// differences are reported first (they make component diffs moot but
/// the components are still listed for the audit trail).
#[must_use]
pub fn diff_breakdowns(prior: &ActionKeyBreakdown, current: &ActionKeyBreakdown) -> Vec<MissCause> {
    let mut causes = Vec::new();
    if prior.key_epoch != current.key_epoch || prior.projection_epoch != current.projection_epoch {
        causes.push(MissCause::EpochMismatch);
    }
    if prior.action_class_tag != current.action_class_tag {
        causes.push(MissCause::ActionClassChanged);
    }
    for (p, c) in prior.components.iter().zip(current.components.iter()) {
        if p.name == c.name
            && p.digest != c.digest
            && let Some(cause) = cause_for_component(p.name)
        {
            causes.push(cause);
        }
    }
    causes
}

/// Compare complete borrowed key inputs without inventing missing components
/// or requiring static lifetimes for persisted domains. A caller explaining
/// supplied action keys must also recompute and match each key first. These
/// differences do not establish a lookup decision or authorize serving.
///
/// # Errors
/// Either header or ordered component set is unsupported or incomplete.
pub fn diff_key_inputs(
    prior_header: ActionKeyHeader,
    prior: &[BorrowedKeyComponent<'_>],
    current_header: ActionKeyHeader,
    current: &[BorrowedKeyComponent<'_>],
) -> Result<Vec<MissCause>, KeyReconstructionError> {
    validate_key_inputs(prior_header, prior)?;
    validate_key_inputs(current_header, current)?;
    let mut causes = Vec::new();
    if prior_header.key_epoch != current_header.key_epoch
        || prior_header.projection_epoch != current_header.projection_epoch
    {
        causes.push(MissCause::EpochMismatch);
    }
    if prior_header.action_class_tag != current_header.action_class_tag {
        causes.push(MissCause::ActionClassChanged);
    }
    for (p, c) in prior.iter().zip(current) {
        if (p.domain != c.domain || p.bytes != c.bytes)
            && let Some(cause) = cause_for_component(p.name)
        {
            causes.push(cause);
        }
    }
    Ok(causes)
}

impl MissCause {
    /// Stable machine-readable reason code (K009 wire format; never
    /// renamed — consumers match on these strings).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SourceChanged => "source-changed",
            Self::NegativeDependencyChanged => "negative-dependency-changed",
            Self::DependencyArtifactChanged => "dependency-artifact-changed",
            Self::InvocationChanged => "invocation-changed",
            Self::EnvironmentChanged => "environment-changed",
            Self::ToolchainChanged => "toolchain-changed",
            Self::PlatformChanged => "platform-changed",
            Self::SandboxPolicyChanged => "sandbox-policy-changed",
            Self::BuildPathPolicyChanged => "build-path-policy-changed",
            Self::WorkingDirectoryChanged => "working-directory-changed",
            Self::ExecutionSemanticsChanged => "execution-semantics-changed",
            Self::OutputDeclarationsChanged => "output-declarations-changed",
            Self::EpochMismatch => "epoch-mismatch",
            Self::ActionClassChanged => "action-class-changed",
        }
    }

    /// One-line human explanation of why the prior entry missed.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::SourceChanged => "positive source input set changed",
            Self::NegativeDependencyChanged => {
                "a previously failed open/listing/lookup now resolves differently"
            }
            Self::DependencyArtifactChanged => "the exact dependency artifacts consumed changed",
            Self::InvocationChanged => "invocation flags/profile/features changed",
            Self::EnvironmentChanged => "the presented environment changed",
            Self::ToolchainChanged => "toolchain identity changed",
            Self::PlatformChanged => "output-platform contract changed",
            Self::SandboxPolicyChanged => "sandbox semantic policy changed",
            Self::BuildPathPolicyChanged => "build-path semantic policy changed",
            Self::WorkingDirectoryChanged => "virtual working directory changed",
            Self::ExecutionSemanticsChanged => "execution-semantics contract changed",
            Self::OutputDeclarationsChanged => "declared logical outputs changed",
            Self::EpochMismatch => {
                "key or projection epoch differs (cold namespace, not a component change)"
            }
            Self::ActionClassChanged => "action class differs entirely",
        }
    }
}

impl LookupOutcome {
    /// Stable machine-readable refusal/lookup reason code (K009).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::FirstSeen => "first-seen",
            Self::ServingBlocked => "serving-blocked",
            Self::TrustRefused => "trust-refused",
            Self::MaterializationUnavailable => "materialization-unavailable",
        }
    }

    /// One-line human explanation of the index-level outcome.
    #[must_use]
    pub const fn explain(self) -> &'static str {
        match self {
            Self::FirstSeen => "no prior entry for this key: first seen",
            Self::ServingBlocked => "entry exists but its serving disposition blocks it",
            Self::TrustRefused => "entry exists but the subscriber's minimum trust tier is unmet",
            Self::MaterializationUnavailable => {
                "entry exists but its object closure is not materializable now"
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_key::compute_action_key;
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

    fn borrowed_inputs(
        breakdown: &ActionKeyBreakdown,
    ) -> (ActionKeyHeader, Vec<BorrowedKeyComponent<'_>>) {
        (
            ActionKeyHeader {
                key_epoch: breakdown.key_epoch,
                projection_epoch: breakdown.projection_epoch,
                action_class_tag: breakdown.action_class_tag,
            },
            breakdown
                .components
                .iter()
                .map(|component| BorrowedKeyComponent {
                    name: component.name,
                    domain: component.digest.domain,
                    bytes: &component.digest.bytes,
                })
                .collect(),
        )
    }

    #[test]
    fn borrowed_diff_attributes_each_byte_or_domain_change_like_descriptor_breakdowns() {
        let prior = compute_action_key(&descriptor());
        let (prior_header, prior_inputs) = borrowed_inputs(&prior);
        assert_eq!(
            diff_key_inputs(prior_header, &prior_inputs, prior_header, &prior_inputs),
            Ok(vec![])
        );
        let expected_causes = [
            MissCause::InvocationChanged,
            MissCause::WorkingDirectoryChanged,
            MissCause::SourceChanged,
            MissCause::NegativeDependencyChanged,
            MissCause::DependencyArtifactChanged,
            MissCause::ToolchainChanged,
            MissCause::PlatformChanged,
            MissCause::EnvironmentChanged,
            MissCause::SandboxPolicyChanged,
            MissCause::BuildPathPolicyChanged,
            MissCause::ExecutionSemanticsChanged,
            MissCause::OutputDeclarationsChanged,
        ];
        for (index, expected) in expected_causes.into_iter().enumerate() {
            for change_domain in [false, true] {
                let mut current = prior.clone();
                if change_domain {
                    current.components[index].digest.domain = "rabs.alternate-component.v1";
                    assert_eq!(
                        current.components[index].digest.bytes,
                        prior.components[index].digest.bytes,
                    );
                } else {
                    current.components[index].digest.bytes[0] ^= 0x40;
                }
                let owned_domain = current.components[index].digest.domain.to_owned();
                let (current_header, mut current_inputs) = borrowed_inputs(&current);
                current_inputs[index].domain = &owned_domain;
                let causes =
                    diff_key_inputs(prior_header, &prior_inputs, current_header, &current_inputs)
                        .unwrap();
                assert_eq!(
                    causes,
                    vec![expected],
                    "component {index}, domain-only change {change_domain}"
                );
                assert_eq!(causes, diff_breakdowns(&prior, &current));
            }
        }
    }

    #[test]
    fn borrowed_diff_reports_epochs_then_class_then_components_in_canonical_order() {
        let prior = compute_action_key(&descriptor());
        let (prior_header, prior_inputs) = borrowed_inputs(&prior);
        for change_projection in [false, true] {
            let mut changed = descriptor();
            if change_projection {
                changed.projection_epoch = u32::MAX;
            } else {
                changed.key_epoch = u32::MAX;
            }
            changed.action_class = ActionClass::ClippyCompile;
            changed.toolchain.bytes[0] ^= 1;
            changed.action_inputs.bytes[0] ^= 1;
            let current = compute_action_key(&changed);
            let (current_header, current_inputs) = borrowed_inputs(&current);
            let causes =
                diff_key_inputs(prior_header, &prior_inputs, current_header, &current_inputs)
                    .unwrap();
            assert_eq!(
                causes,
                vec![
                    MissCause::EpochMismatch,
                    MissCause::ActionClassChanged,
                    MissCause::SourceChanged,
                    MissCause::ToolchainChanged,
                ]
            );
            assert_eq!(causes, diff_breakdowns(&prior, &current));
        }
    }

    #[test]
    fn borrowed_diff_rejects_incomplete_or_malformed_inputs_on_either_side() {
        let breakdown = compute_action_key(&descriptor());
        let (header, valid) = borrowed_inputs(&breakdown);
        let reject = |invalid: &[BorrowedKeyComponent<'_>], error| {
            assert_eq!(diff_key_inputs(header, invalid, header, &valid), Err(error));
            assert_eq!(diff_key_inputs(header, &valid, header, invalid), Err(error));
        };
        reject(&[], KeyReconstructionError::ComponentCount(0));
        reject(&valid[..11], KeyReconstructionError::ComponentCount(11));
        let mut excess = valid.clone();
        excess.push(valid[0]);
        reject(&excess, KeyReconstructionError::ComponentCount(13));
        let mut duplicate = valid.clone();
        duplicate[1].name = duplicate[0].name;
        reject(&duplicate, KeyReconstructionError::ComponentName(1));
        let mut reordered = valid.clone();
        reordered.swap(0, 1);
        reject(&reordered, KeyReconstructionError::ComponentName(0));
        let mut unknown = valid.clone();
        unknown[4].name = "future_component";
        reject(&unknown, KeyReconstructionError::ComponentName(4));
        let mut empty_domain = valid.clone();
        empty_domain[5].domain = "";
        reject(&empty_domain, KeyReconstructionError::EmptyDomain(5));

        for tag in [0, 22, u32::MAX] {
            let invalid_header = ActionKeyHeader {
                action_class_tag: tag,
                ..header
            };
            assert_eq!(
                diff_key_inputs(invalid_header, &valid, header, &valid),
                Err(KeyReconstructionError::UnsupportedActionClass(tag))
            );
            assert_eq!(
                diff_key_inputs(header, &valid, invalid_header, &valid),
                Err(KeyReconstructionError::UnsupportedActionClass(tag))
            );
        }
    }

    #[test]
    fn every_component_name_maps_to_a_cause() {
        // Exhaustiveness against A014's actual component list: schema
        // drift (a new component without a cause) fails here by name.
        let b = compute_action_key(&descriptor());
        for c in &b.components {
            assert!(
                cause_for_component(c.name).is_some(),
                "component `{}` has no miss cause — extend the taxonomy in \
                 the same change that adds a component (F013)",
                c.name
            );
        }
    }

    #[test]
    fn single_component_changes_attribute_precisely() {
        let prior = compute_action_key(&descriptor());
        let mut env_changed = descriptor();
        env_changed.environment = d("rabs.env.v1", 99);
        let current = compute_action_key(&env_changed);
        assert_eq!(
            diff_breakdowns(&prior, &current),
            vec![MissCause::EnvironmentChanged],
            "exactly one precise cause, no noise"
        );
        let mut dep_changed = descriptor();
        dep_changed.dependency_inputs = d("rabs.deps.v1", 99);
        assert_eq!(
            diff_breakdowns(&prior, &compute_action_key(&dep_changed)),
            vec![MissCause::DependencyArtifactChanged]
        );
    }

    #[test]
    fn multiple_changes_report_in_canonical_order() {
        let prior = compute_action_key(&descriptor());
        let mut m = descriptor();
        m.toolchain = d("rabs.toolchain.v1", 99);
        m.action_inputs = d("rabs.inputs.v1", 99);
        let causes = diff_breakdowns(&prior, &compute_action_key(&m));
        // Canonical component order: inputs (3rd) before toolchain (6th).
        assert_eq!(
            causes,
            vec![MissCause::SourceChanged, MissCause::ToolchainChanged]
        );
    }

    #[test]
    fn epoch_and_class_report_ahead_of_components() {
        let prior = compute_action_key(&descriptor());
        let mut m = descriptor();
        m.key_epoch = 2;
        m.environment = d("rabs.env.v1", 99);
        let causes = diff_breakdowns(&prior, &compute_action_key(&m));
        assert_eq!(causes[0], MissCause::EpochMismatch);
        assert!(causes.contains(&MissCause::EnvironmentChanged));
    }

    #[test]
    fn identical_breakdowns_diff_to_nothing() {
        let a = compute_action_key(&descriptor());
        let b = compute_action_key(&descriptor());
        assert!(diff_breakdowns(&a, &b).is_empty());
    }

    #[test]
    fn k009_cause_codes_are_unique_and_total() {
        let all = [
            MissCause::SourceChanged,
            MissCause::NegativeDependencyChanged,
            MissCause::DependencyArtifactChanged,
            MissCause::InvocationChanged,
            MissCause::EnvironmentChanged,
            MissCause::ToolchainChanged,
            MissCause::PlatformChanged,
            MissCause::SandboxPolicyChanged,
            MissCause::BuildPathPolicyChanged,
            MissCause::WorkingDirectoryChanged,
            MissCause::ExecutionSemanticsChanged,
            MissCause::OutputDeclarationsChanged,
            MissCause::EpochMismatch,
            MissCause::ActionClassChanged,
        ];
        let mut codes: Vec<&str> = all.iter().map(|c| c.code()).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total, "reason codes must be unique");
        assert!(
            all.iter()
                .all(|c| !c.code().is_empty() && !c.explain().is_empty())
        );
    }

    #[test]
    fn k009_outcome_codes_are_stable() {
        let outcomes = [
            (LookupOutcome::FirstSeen, "first-seen"),
            (LookupOutcome::ServingBlocked, "serving-blocked"),
            (LookupOutcome::TrustRefused, "trust-refused"),
            (
                LookupOutcome::MaterializationUnavailable,
                "materialization-unavailable",
            ),
        ];
        for (outcome, code) in outcomes {
            assert_eq!(outcome.code(), code);
            assert!(!outcome.explain().is_empty());
        }
    }
}
