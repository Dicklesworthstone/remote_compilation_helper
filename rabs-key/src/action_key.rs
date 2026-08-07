//! Action-key assembly and the `ActionKeyBreakdown` (bead F012; plan
//! §17/§10.3).
//!
//! Key construction returns the key AND a structured, redaction-safe
//! breakdown of contributing components — the breakdown is what `rch why
//! miss` diffs (F013), what offline audits inspect, and what makes every
//! miss attributable. The key is computed as:
//!
//! ```text
//! ActionKey = SHA-256_typed( DOMAIN_ACTION_KEY,
//!     canonical( key_epoch, projection_epoch, action_class_tag,
//!                the twelve component digests in declaration order ) )
//! ```
//!
//! using F001 canonical encoding, F034 typed framing, and A014's
//! exhaustive component list — so a descriptor field added without a key
//! decision is unrepresentable, and any serialization drift trips the
//! F001 goldens.

use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::{DOMAIN_ACTION_KEY, compute};

/// Stable canonical tag for each action class (wire-stable; NOT the Rust
/// discriminant — enum reordering must not change keys).
#[must_use]
pub const fn action_class_tag(class: ActionClass) -> u32 {
    match class {
        ActionClass::CargoWholeCommandBounded => 1,
        ActionClass::RustcDependencyCompile => 2,
        ActionClass::RustcWorkspaceCompile => 3,
        ActionClass::RustdocCompile => 4,
        ActionClass::Link => 5,
        ActionClass::BuildScriptCompile => 6,
        ActionClass::BuildScriptRun => 7,
        ActionClass::NativeCompileC => 8,
        ActionClass::NativeCompileCxx => 9,
        ActionClass::NativeArchive => 10,
        ActionClass::BindgenGeneration => 11,
        ActionClass::CodeGeneratorRun => 12,
        ActionClass::NextestTestCase => 13,
        ActionClass::TestBinaryBatch => 14,
        ActionClass::DoctestCompile => 15,
        ActionClass::DoctestRun => 16,
        ActionClass::ClippyCompile => 17,
        ActionClass::BenchmarkCompile => 18,
        ActionClass::BenchmarkRun => 19,
        ActionClass::ToolchainProbe => 20,
        ActionClass::WorkerProbe => 21,
    }
}

/// One breakdown row: component name + its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakdownComponent {
    /// Stable component name (matches A014's component list).
    pub name: &'static str,
    /// The component digest that entered the key.
    pub digest: TypedDigest,
}

/// The structured, redaction-safe key breakdown returned WITH every key.
/// Digests only — raw component values never appear here, so breakdowns
/// are safe to persist in receipts and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionKeyBreakdown {
    /// Key epoch used.
    pub key_epoch: u32,
    /// Projection epoch used.
    pub projection_epoch: u32,
    /// Canonical action-class tag.
    pub action_class_tag: u32,
    /// The twelve components in canonical order.
    pub components: Vec<BreakdownComponent>,
    /// The final action key.
    pub final_key: TypedDigest,
}

/// Compute the action key and its breakdown from a descriptor.
#[must_use]
pub fn compute_action_key(descriptor: &ActionDescriptor) -> ActionKeyBreakdown {
    let components: Vec<BreakdownComponent> = descriptor
        .key_input_components()
        .into_iter()
        .map(|(name, digest)| BreakdownComponent {
            name,
            digest: digest.clone(),
        })
        .collect();
    let mut enc = CanonicalEncoder::new();
    enc.u32(descriptor.key_epoch)
        .u32(descriptor.projection_epoch)
        .u32(action_class_tag(descriptor.action_class));
    for c in &components {
        // Component digests enter as (domain, bytes): the domain string
        // participates so a digest can never be replayed across component
        // slots that happen to share bytes.
        enc.str(c.digest.domain);
        enc.bytes(&c.digest.bytes);
    }
    let final_key = compute(DOMAIN_ACTION_KEY, &enc.finish());
    ActionKeyBreakdown {
        key_epoch: descriptor.key_epoch,
        projection_epoch: descriptor.projection_epoch,
        action_class_tag: action_class_tag(descriptor.action_class),
        components,
        final_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

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
    fn identical_descriptors_yield_identical_keys_and_breakdowns() {
        let a = compute_action_key(&descriptor());
        let b = compute_action_key(&descriptor());
        assert_eq!(a, b);
        assert_eq!(a.components.len(), 12);
        assert_eq!(a.final_key.domain, DOMAIN_ACTION_KEY);
    }

    #[test]
    fn every_component_mutation_changes_the_key() {
        // The F015 seed at the assembly layer: perturb each component
        // digest in isolation; the final key must change every time.
        let base = compute_action_key(&descriptor());
        let mutations: Vec<ActionDescriptor> = (0..12)
            .map(|i| {
                let mut m = descriptor();
                let bump = |t: &mut TypedDigest| t.bytes[0] ^= 0xFF;
                match i {
                    0 => bump(&mut m.normalized_invocation),
                    1 => bump(&mut m.virtual_working_directory),
                    2 => bump(&mut m.action_inputs),
                    3 => bump(&mut m.negative_dependencies),
                    4 => bump(&mut m.dependency_inputs),
                    5 => bump(&mut m.toolchain),
                    6 => bump(&mut m.output_platform),
                    7 => bump(&mut m.environment),
                    8 => bump(&mut m.sandbox_semantic_policy),
                    9 => bump(&mut m.build_path_semantic_policy),
                    10 => bump(&mut m.execution_semantics),
                    _ => bump(&mut m.output_declarations),
                }
                m
            })
            .collect();
        for (i, m) in mutations.iter().enumerate() {
            let k = compute_action_key(m);
            assert_ne!(
                k.final_key, base.final_key,
                "mutating component {i} did not change the key"
            );
        }
    }

    #[test]
    fn epochs_and_class_split_the_namespace() {
        let base = compute_action_key(&descriptor());
        let mut k = descriptor();
        k.key_epoch = 2;
        assert_ne!(compute_action_key(&k).final_key, base.final_key);
        let mut p = descriptor();
        p.projection_epoch = 2;
        assert_ne!(compute_action_key(&p).final_key, base.final_key);
        let mut c = descriptor();
        c.action_class = ActionClass::ClippyCompile;
        assert_ne!(compute_action_key(&c).final_key, base.final_key);
    }

    #[test]
    fn class_tags_are_wire_stable_and_unique() {
        // The tag table, not the Rust discriminant, is the wire identity.
        let all = [
            ActionClass::CargoWholeCommandBounded,
            ActionClass::RustcDependencyCompile,
            ActionClass::RustcWorkspaceCompile,
            ActionClass::RustdocCompile,
            ActionClass::Link,
            ActionClass::BuildScriptCompile,
            ActionClass::BuildScriptRun,
            ActionClass::NativeCompileC,
            ActionClass::NativeCompileCxx,
            ActionClass::NativeArchive,
            ActionClass::BindgenGeneration,
            ActionClass::CodeGeneratorRun,
            ActionClass::NextestTestCase,
            ActionClass::TestBinaryBatch,
            ActionClass::DoctestCompile,
            ActionClass::DoctestRun,
            ActionClass::ClippyCompile,
            ActionClass::BenchmarkCompile,
            ActionClass::BenchmarkRun,
            ActionClass::ToolchainProbe,
            ActionClass::WorkerProbe,
        ];
        let mut tags: Vec<u32> = all.iter().map(|c| action_class_tag(*c)).collect();
        let len = tags.len();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), len, "duplicate class tags");
        assert_eq!(action_class_tag(ActionClass::CargoWholeCommandBounded), 1);
        assert_eq!(action_class_tag(ActionClass::WorkerProbe), 21);
    }

    #[test]
    fn breakdown_carries_digests_only() {
        // Redaction safety: the breakdown's Debug dump contains component
        // names and hex-ish digest bytes, never raw values (there is no
        // field that COULD hold one — assert the shape).
        let b = compute_action_key(&descriptor());
        for c in &b.components {
            assert!(!c.name.is_empty());
            assert_eq!(c.digest.bytes.len(), 32);
        }
    }
}
