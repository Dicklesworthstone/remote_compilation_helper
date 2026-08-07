//! Conservative exact dependency-artifact identity (bead F009;
//! invariant I22; plan §62; risks R9/R11).
//!
//! The dependency-input slot of the descriptor hashes **the exact bytes
//! the compiler or linker will consume** — nothing finer, nothing
//! coarser:
//!
//! - if the downstream compile receives the `.rmeta`, the identity is
//!   the `.rmeta` bytes; if it receives an `.rlib`, the COMPLETE
//!   `.rlib` bytes (no attempt to prove which members are "really"
//!   used);
//! - proc-macros contribute the executable/dylib PLUS its runtime
//!   dependency closure (the macro executes; any library it loads can
//!   change its output);
//! - link actions contribute the ORDERED implementation artifacts plus
//!   a link-semantics component (flags/order semantics beyond member
//!   bytes) — link order is semantics, so this set is a sequence;
//! - under LTO every bitcode/rlib component actually consumed enters.
//!
//! **Early cutoff is emergent, never analyzed**: an upstream
//! implementation-only change that reproduces byte-identical consumed
//! artifacts yields byte-identical identities and therefore downstream
//! HITS — with zero source-level API analysis (no "API hash", no
//! semver reasoning; those would be unsound shortcuts — I22's point).

use rabs_protocol::result_identity::TypedDigest;

use crate::canonical::CanonicalEncoder;
use crate::typed_digest::compute;

/// Digest domain for the dependency-inputs slot.
pub const DOMAIN_DEPENDENCY_INPUTS: &str = "rabs.dependency-inputs.v1";

/// One consumed dependency artifact, identified by the exact bytes the
/// tool receives (wire-stable tags in `canonical_bytes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumedArtifact {
    /// A `.rmeta` handed to a (possibly pipelined) downstream compile.
    RmetaBytes(TypedDigest),
    /// A complete `.rlib` — the whole archive, member analysis refused.
    RlibBytes(TypedDigest),
    /// A dylib consumed at compile/link time.
    DylibBytes(TypedDigest),
    /// A proc-macro: the executable/dylib digest plus the sorted
    /// runtime-dependency closure digests (the macro EXECUTES; its
    /// loadable deps can change its output).
    ProcMacro {
        /// The proc-macro dylib itself.
        macro_dylib: TypedDigest,
        /// Runtime dependency closure (hashed as a sorted set).
        runtime_deps: Vec<TypedDigest>,
    },
    /// LTO bitcode/rlib component actually consumed.
    LtoComponent(TypedDigest),
}

/// The dependency-input set for one action. Compile-side artifacts are
/// a sorted set; link-side artifacts are an ORDERED sequence plus link
/// semantics (order is semantics for linkers).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DependencyInputs {
    /// Artifacts consumed by the compile step (set semantics).
    pub compile_inputs: Vec<ConsumedArtifact>,
    /// Ordered link implementation artifacts (sequence semantics).
    pub link_inputs: Vec<ConsumedArtifact>,
    /// Link-semantics component (flag/order semantics beyond member
    /// bytes), when the action links.
    pub link_semantics: Option<TypedDigest>,
}

fn encode_artifact(enc: &mut CanonicalEncoder, a: &ConsumedArtifact) {
    match a {
        ConsumedArtifact::RmetaBytes(d) => {
            enc.u32(1).str(d.domain).bytes(&d.bytes);
        }
        ConsumedArtifact::RlibBytes(d) => {
            enc.u32(2).str(d.domain).bytes(&d.bytes);
        }
        ConsumedArtifact::DylibBytes(d) => {
            enc.u32(3).str(d.domain).bytes(&d.bytes);
        }
        ConsumedArtifact::ProcMacro {
            macro_dylib,
            runtime_deps,
        } => {
            enc.u32(4).str(macro_dylib.domain).bytes(&macro_dylib.bytes);
            let mut deps: Vec<&TypedDigest> = runtime_deps.iter().collect();
            deps.sort_by(|a, b| (a.domain, &a.bytes).cmp(&(b.domain, &b.bytes)));
            enc.u64(deps.len() as u64);
            for d in deps {
                enc.str(d.domain).bytes(&d.bytes);
            }
        }
        ConsumedArtifact::LtoComponent(d) => {
            enc.u32(5).str(d.domain).bytes(&d.bytes);
        }
    }
}

impl DependencyInputs {
    /// Canonical bytes: compile inputs sorted (set), link inputs in
    /// order (sequence), link semantics tagged.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut enc = CanonicalEncoder::new();
        // Sort compile inputs by their own canonical encodings so
        // discovery order can never fork keys.
        let mut compile_encoded: Vec<Vec<u8>> = self
            .compile_inputs
            .iter()
            .map(|a| {
                let mut e = CanonicalEncoder::new();
                encode_artifact(&mut e, a);
                e.finish()
            })
            .collect();
        compile_encoded.sort_unstable();
        enc.u64(compile_encoded.len() as u64);
        for bytes in &compile_encoded {
            enc.bytes(bytes);
        }
        // Link inputs preserve order: link order IS semantics.
        enc.u64(self.link_inputs.len() as u64);
        for a in &self.link_inputs {
            encode_artifact(&mut enc, a);
        }
        match &self.link_semantics {
            None => {
                enc.u32(0);
            }
            Some(d) => {
                enc.u32(1).str(d.domain).bytes(&d.bytes);
            }
        }
        enc.finish()
    }

    /// The dependency-inputs digest — the descriptor's
    /// `dependency_inputs` slot.
    #[must_use]
    pub fn inputs_digest(&self) -> TypedDigest {
        compute(DOMAIN_DEPENDENCY_INPUTS, &self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::DigestAlgorithm;

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.dep-artifact.v1",
            bytes: [tag; 32],
        }
    }

    #[test]
    fn early_cutoff_emerges_from_byte_identical_rmeta() {
        // THE acceptance case: upstream crate changes implementation
        // only; its .rmeta reproduces byte-identical. The downstream
        // dependency identity — which consumed only the .rmeta — is
        // unchanged, so downstream HITS. No API analysis ran; equality
        // of consumed bytes IS the cutoff.
        let before = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::RmetaBytes(d(1))],
            ..Default::default()
        };
        let after_impl_only_change = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::RmetaBytes(d(1))],
            ..Default::default()
        };
        assert_eq!(
            before.inputs_digest(),
            after_impl_only_change.inputs_digest()
        );
        // Any consumed-byte change misses.
        let after_api_change = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::RmetaBytes(d(2))],
            ..Default::default()
        };
        assert_ne!(before.inputs_digest(), after_api_change.inputs_digest());
    }

    #[test]
    fn rmeta_and_rlib_of_one_crate_are_distinct_consumed_forms() {
        // Same underlying crate, different supplied artifact: distinct
        // identities even with equal content digests (the KIND tags).
        let via_rmeta = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::RmetaBytes(d(1))],
            ..Default::default()
        };
        let via_rlib = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::RlibBytes(d(1))],
            ..Default::default()
        };
        assert_ne!(via_rmeta.inputs_digest(), via_rlib.inputs_digest());
    }

    #[test]
    fn proc_macro_runtime_deps_participate_as_a_set() {
        let base = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::ProcMacro {
                macro_dylib: d(1),
                runtime_deps: vec![d(2), d(3)],
            }],
            ..Default::default()
        };
        // Discovery order of the closure is irrelevant…
        let reordered = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::ProcMacro {
                macro_dylib: d(1),
                runtime_deps: vec![d(3), d(2)],
            }],
            ..Default::default()
        };
        assert_eq!(base.inputs_digest(), reordered.inputs_digest());
        // …but a changed runtime dep changes macro output potential:
        // the identity must move (the macro EXECUTES).
        let changed_dep = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::ProcMacro {
                macro_dylib: d(1),
                runtime_deps: vec![d(2), d(4)],
            }],
            ..Default::default()
        };
        assert_ne!(base.inputs_digest(), changed_dep.inputs_digest());
    }

    #[test]
    fn compile_inputs_are_a_set_but_link_inputs_are_a_sequence() {
        let a = DependencyInputs {
            compile_inputs: vec![
                ConsumedArtifact::RmetaBytes(d(1)),
                ConsumedArtifact::RmetaBytes(d(2)),
            ],
            link_inputs: vec![
                ConsumedArtifact::RlibBytes(d(3)),
                ConsumedArtifact::RlibBytes(d(4)),
            ],
            link_semantics: Some(d(9)),
        };
        // Compile discovery order: irrelevant.
        let compile_reordered = DependencyInputs {
            compile_inputs: vec![
                ConsumedArtifact::RmetaBytes(d(2)),
                ConsumedArtifact::RmetaBytes(d(1)),
            ],
            ..a.clone()
        };
        assert_eq!(a.inputs_digest(), compile_reordered.inputs_digest());
        // Link order: SEMANTICS — reordering forks.
        let link_reordered = DependencyInputs {
            link_inputs: vec![
                ConsumedArtifact::RlibBytes(d(4)),
                ConsumedArtifact::RlibBytes(d(3)),
            ],
            ..a.clone()
        };
        assert_ne!(a.inputs_digest(), link_reordered.inputs_digest());
        // Link semantics component participates.
        let semantics_changed = DependencyInputs {
            link_semantics: Some(d(10)),
            ..a.clone()
        };
        assert_ne!(a.inputs_digest(), semantics_changed.inputs_digest());
    }

    #[test]
    fn lto_components_enter_individually() {
        let one = DependencyInputs {
            link_inputs: vec![ConsumedArtifact::LtoComponent(d(1))],
            ..Default::default()
        };
        let two = DependencyInputs {
            link_inputs: vec![
                ConsumedArtifact::LtoComponent(d(1)),
                ConsumedArtifact::LtoComponent(d(2)),
            ],
            ..Default::default()
        };
        assert_ne!(one.inputs_digest(), two.inputs_digest());
    }
}
