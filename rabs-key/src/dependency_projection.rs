//! Versioned dependency-projection framework, fail-closed (bead F010;
//! plan §62; risk R49).
//!
//! F009's exact identity is always SOUND but can over-invalidate: a
//! downstream compile that provably reads only the rlib's metadata
//! member would hit more often if keyed on that member alone. A
//! **reduced projection** is that optimization — and it is admitted
//! ONLY when four conditions hold simultaneously:
//!
//! 1. **Invocation-class proof**: the action's flag shape proves rustc
//!    cannot observe the omitted bytes (e.g. no LTO, no
//!    codegen-units-driven cross-crate inlining of the raw object
//!    members);
//! 2. **Versioned extractor**: the projection is produced by a named
//!    extractor version with a versioned schema — a silent extractor
//!    change cannot alias two different projections;
//! 3. **Zero-divergence shadow corpus**: the fleet's shadow corpus for
//!    this (extractor, toolchain) pair reports zero divergences;
//! 4. **No ambiguity**: ambiguous flags (`-C lto` in any non-off form,
//!    `-Z` unknowns touching codegen, linker-plugin-lto) or a toolchain
//!    change since corpus validation AUTO-DISABLE the projection.
//!
//! Failure of ANY condition falls back to F009 exact-artifact identity
//! — the sound default. Projection identity lives in
//! `projection_epoch`: enabling/changing projections bumps the epoch,
//! so projected and exact keys can never alias (I3's namespace rule).

use crate::dependency_identity::{ConsumedArtifact, DependencyInputs};

/// A versioned projection extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionExtractor {
    /// Extractor name (e.g. `"rlib-metadata-member"`).
    pub name: String,
    /// Extractor implementation version.
    pub version: u32,
    /// Projection schema version it emits.
    pub schema_version: u32,
}

/// Shadow-corpus verdict for one (extractor, toolchain) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowCorpusStatus {
    /// Corpus ran to completion with zero divergences on the CURRENT
    /// toolchain.
    ZeroDivergence,
    /// Divergences observed, corpus incomplete, or never run.
    NotClean,
    /// Toolchain changed since the corpus last validated.
    ToolchainChangedSinceValidation,
}

/// Invocation-class analysis of whether omitted bytes are observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservabilityProof {
    /// Proven unobservable for this invocation class/flag shape.
    OmittedBytesUnobservable,
    /// Observable, unknown, or ambiguous flags present (LTO in any
    /// non-off form, unknown codegen-touching -Z, linker-plugin-lto).
    AmbiguousOrObservable,
}

/// Analyze a flag shape for projection ambiguity. Conservative: only a
/// known-clean shape yields a proof; everything else is ambiguous.
#[must_use]
pub fn classify_flags(
    codegen: &[(String, Option<String>)],
    unstable: &[(String, Option<String>)],
) -> ObservabilityProof {
    for (name, value) in codegen {
        let v = value.as_deref().unwrap_or("");
        match name.as_str() {
            // Any LTO other than an explicit "off" makes raw members
            // observable downstream.
            "lto" if v != "off" => return ObservabilityProof::AmbiguousOrObservable,
            "linker-plugin-lto" => return ObservabilityProof::AmbiguousOrObservable,
            "embed-bitcode" if v == "yes" => {
                return ObservabilityProof::AmbiguousOrObservable;
            }
            _ => {}
        }
    }
    // Unknown -Z flags could touch codegen/metadata layout: ambiguous
    // unless on the tiny known-inert allowlist.
    const INERT_UNSTABLE: &[&str] = &["unstable-options", "terminal-urls"];
    for (name, _) in unstable {
        if !INERT_UNSTABLE.contains(&name.as_str()) {
            return ObservabilityProof::AmbiguousOrObservable;
        }
    }
    ObservabilityProof::OmittedBytesUnobservable
}

/// The dependency identity actually used, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionDecision {
    /// Reduced projection admitted (all four conditions held): key on
    /// the projected artifact under the given extractor identity.
    Projected {
        /// The extractor that produced the projection.
        extractor: ProjectionExtractor,
        /// The projected artifact identity.
        projected: ConsumedArtifact,
    },
    /// Fallback to F009 exact identity, with the failed condition named
    /// (diagnostics; the fallback itself is always sound).
    ExactFallback {
        /// Which admission condition failed.
        because: FallbackCause,
    },
}

/// Which of the four conditions failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackCause {
    /// Condition 1: flags ambiguous or omitted bytes observable.
    AmbiguousFlags,
    /// Condition 2: no versioned extractor registered for this artifact.
    NoVersionedExtractor,
    /// Condition 3: shadow corpus not clean.
    CorpusNotClean,
    /// Condition 4: toolchain changed since corpus validation.
    ToolchainChanged,
}

/// Admit or refuse a reduced projection. Every input must independently
/// pass; the first failure names itself and falls back to exact.
#[must_use]
pub fn decide_projection(
    proof: ObservabilityProof,
    extractor: Option<&ProjectionExtractor>,
    corpus: ShadowCorpusStatus,
    projected: &ConsumedArtifact,
) -> ProjectionDecision {
    if proof == ObservabilityProof::AmbiguousOrObservable {
        return ProjectionDecision::ExactFallback {
            because: FallbackCause::AmbiguousFlags,
        };
    }
    let Some(extractor) = extractor else {
        return ProjectionDecision::ExactFallback {
            because: FallbackCause::NoVersionedExtractor,
        };
    };
    match corpus {
        ShadowCorpusStatus::ToolchainChangedSinceValidation => {
            return ProjectionDecision::ExactFallback {
                because: FallbackCause::ToolchainChanged,
            };
        }
        ShadowCorpusStatus::NotClean => {
            return ProjectionDecision::ExactFallback {
                because: FallbackCause::CorpusNotClean,
            };
        }
        ShadowCorpusStatus::ZeroDivergence => {}
    }
    ProjectionDecision::Projected {
        extractor: extractor.clone(),
        projected: projected.clone(),
    }
}

/// Apply a decision to dependency inputs: projected identities replace
/// exact ones ONLY under a bumped projection epoch (the caller passes
/// the epoch the decision was made under; projected and exact keys can
/// never alias because the epoch is a descriptor key input).
#[must_use]
pub fn effective_inputs(
    decision: &ProjectionDecision,
    exact: &DependencyInputs,
) -> (DependencyInputs, u32) {
    match decision {
        ProjectionDecision::Projected { projected, .. } => {
            let projected_inputs = DependencyInputs {
                compile_inputs: vec![projected.clone()],
                link_inputs: exact.link_inputs.clone(),
                link_semantics: exact.link_semantics.clone(),
            };
            // Projection namespace: epoch 2 (versioned upward as
            // projection schemas evolve; exact space stays at 1).
            (projected_inputs, 2)
        }
        ProjectionDecision::ExactFallback { .. } => (exact.clone(), 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};

    fn d(tag: u8) -> TypedDigest {
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.dep-artifact.v1",
            bytes: [tag; 32],
        }
    }

    fn extractor() -> ProjectionExtractor {
        ProjectionExtractor {
            name: "rlib-metadata-member".into(),
            version: 1,
            schema_version: 1,
        }
    }

    fn pairs(list: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
        list.iter()
            .map(|(n, v)| ((*n).to_owned(), v.map(str::to_owned)))
            .collect()
    }

    #[test]
    fn all_four_conditions_admit_a_projection() {
        let decision = decide_projection(
            classify_flags(&pairs(&[("opt-level", Some("3"))]), &[]),
            Some(&extractor()),
            ShadowCorpusStatus::ZeroDivergence,
            &ConsumedArtifact::RmetaBytes(d(1)),
        );
        assert!(matches!(decision, ProjectionDecision::Projected { .. }));
    }

    #[test]
    fn ambiguous_flag_fixture_auto_falls_back_to_exact() {
        // THE acceptance fixture: -C lto=thin makes omitted rlib members
        // observable; the projection auto-disables (R49).
        for lto in ["thin", "fat", "yes", ""] {
            let flags = pairs(&[("lto", Some(lto))]);
            let decision = decide_projection(
                classify_flags(&flags, &[]),
                Some(&extractor()),
                ShadowCorpusStatus::ZeroDivergence,
                &ConsumedArtifact::RmetaBytes(d(1)),
            );
            assert_eq!(
                decision,
                ProjectionDecision::ExactFallback {
                    because: FallbackCause::AmbiguousFlags
                },
                "lto={lto:?} must fall back"
            );
        }
        // Explicit lto=off is the one clean LTO spelling.
        assert_eq!(
            classify_flags(&pairs(&[("lto", Some("off"))]), &[]),
            ObservabilityProof::OmittedBytesUnobservable
        );
        // Unknown -Z flags are ambiguous by default.
        assert_eq!(
            classify_flags(&[], &pairs(&[("mystery-codegen-knob", None)])),
            ObservabilityProof::AmbiguousOrObservable
        );
    }

    #[test]
    fn each_remaining_condition_fails_closed_by_name() {
        let clean = classify_flags(&[], &[]);
        // Condition 2: no versioned extractor.
        assert_eq!(
            decide_projection(
                clean,
                None,
                ShadowCorpusStatus::ZeroDivergence,
                &ConsumedArtifact::RmetaBytes(d(1)),
            ),
            ProjectionDecision::ExactFallback {
                because: FallbackCause::NoVersionedExtractor
            }
        );
        // Condition 3: corpus not clean.
        assert_eq!(
            decide_projection(
                clean,
                Some(&extractor()),
                ShadowCorpusStatus::NotClean,
                &ConsumedArtifact::RmetaBytes(d(1)),
            ),
            ProjectionDecision::ExactFallback {
                because: FallbackCause::CorpusNotClean
            }
        );
        // Condition 4: toolchain changed since validation.
        assert_eq!(
            decide_projection(
                clean,
                Some(&extractor()),
                ShadowCorpusStatus::ToolchainChangedSinceValidation,
                &ConsumedArtifact::RmetaBytes(d(1)),
            ),
            ProjectionDecision::ExactFallback {
                because: FallbackCause::ToolchainChanged
            }
        );
    }

    #[test]
    fn projection_and_exact_live_in_different_epochs() {
        let exact = DependencyInputs {
            compile_inputs: vec![ConsumedArtifact::RlibBytes(d(1))],
            ..Default::default()
        };
        let projected_decision = decide_projection(
            classify_flags(&[], &[]),
            Some(&extractor()),
            ShadowCorpusStatus::ZeroDivergence,
            &ConsumedArtifact::RmetaBytes(d(2)),
        );
        let (projected_inputs, projected_epoch) = effective_inputs(&projected_decision, &exact);
        let fallback = ProjectionDecision::ExactFallback {
            because: FallbackCause::CorpusNotClean,
        };
        let (exact_inputs, exact_epoch) = effective_inputs(&fallback, &exact);
        // Different epochs: the projection_epoch descriptor field keys,
        // so projected and exact identities can NEVER alias even if
        // their digests coincided.
        assert_ne!(projected_epoch, exact_epoch);
        assert_ne!(projected_inputs, exact_inputs);
        assert_eq!(exact_inputs, exact, "fallback is exactly F009 identity");
    }
}
