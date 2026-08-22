//! Build-script run-cache serving gate (bead N001; plan §196 Epic N).
//!
//! THE COUPLING, executable form: run-cache serving is DISABLED by
//! default and can only be enabled by admitting a [`FeasibilityProof`]
//! recording that a specific interception mechanism preserved build-
//! script semantics on a specific cargo channel — the exact contract the
//! N001 harness (`rabs-wrap/tests/n001_contract.rs`) measures per
//! channel. A negative result cannot enable anything (typed refusal);
//! the gate never flips from inference, configuration pressure, or
//! absence of evidence. If NO mechanism proves out on a channel, serving
//! stays off for that channel — the bead's "else no run-cache" clause,
//! encoded structurally.
//!
//! Zero dependencies; pure state machine like every schema here.

use crate::result_identity::TypedDigest;

/// Cargo release channels the N001 contracts are proven against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Stable cargo.
    Stable,
    /// Beta cargo.
    Beta,
    /// Nightly cargo (layout vintages vary; proofs pin the observed
    /// layout via the evidence digest).
    Nightly,
}

/// Interception mechanisms N001 evaluates, in plan preference order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mechanism {
    /// Canonical Cargo-driver integration intercepting the run without
    /// substituting path identity (mechanism 1).
    CanonicalDriverIntegration,
    /// Launcher shim installed at Cargo's expected build-script path,
    /// admissible ONLY with executable-identity/mtime/fingerprint/
    /// output-cache/jobserver evidence attached (mechanism 2).
    LauncherShim,
}

impl Channel {
    /// Stable registry spelling used in receipts and docs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        }
    }
}

impl Mechanism {
    /// Stable registry spelling used in receipts and docs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CanonicalDriverIntegration => "canonical-driver-integration",
            Self::LauncherShim => "launcher-shim",
        }
    }
}

/// One recorded outcome of the N001 contract harness for a
/// (channel, mechanism) pair. Produced by RUNNING the harness; the
/// digest binds the emitted JSON matrix row so an admitted proof names
/// its evidence rather than an assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeasibilityProof {
    /// Which channel was probed.
    pub channel: Channel,
    /// Which mechanism was probed.
    pub mechanism: Mechanism,
    /// Whether interception preserved semantics end to end (the
    /// harness's stock-vs-shim comparison).
    pub semantics_preserved: bool,
    /// Digest over the harness's JSON matrix row for this pair — the
    /// receipt points at measurements, not claims.
    pub evidence_digest: TypedDigest,
}

/// Typed gate refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// A negative result can never widen serving.
    ProofRecordsUnpreservedSemantics,
    /// Duplicate admission for an already-proven pair (idempotent no-op
    /// is fine; a CONFLICTING second proof is refused — history is not
    /// rewritten).
    ConflictingProofAlreadyAdmitted,
}

/// The run-cache serving gate. Default state: DISABLED for every
/// channel. Enabled per-channel only by admitted positive proofs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunCacheGate {
    admitted: Vec<(Channel, Mechanism, TypedDigest)>,
}

impl RunCacheGate {
    /// The factory-default posture: serving disabled everywhere.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Admit a feasibility proof. Positive proofs enable serving for
    /// their (channel, mechanism); negative proofs change nothing but
    /// are still refused loudly (they must not be silently swallowed —
    /// a negative that disappears looks like a positive later).
    ///
    /// # Errors
    /// [`GateRefusal::ProofRecordsUnpreservedSemantics`] when
    /// `semantics_preserved` is false;
    /// [`GateRefusal::ConflictingProofAlreadyAdmitted`] when the pair is
    /// already admitted under a different evidence digest.
    pub fn admit_proof(&mut self, proof: &FeasibilityProof) -> Result<(), GateRefusal> {
        if !proof.semantics_preserved {
            return Err(GateRefusal::ProofRecordsUnpreservedSemantics);
        }
        for (ch, mech, digest) in &self.admitted {
            if *ch == proof.channel && *mech == proof.mechanism {
                if *digest != proof.evidence_digest {
                    return Err(GateRefusal::ConflictingProofAlreadyAdmitted);
                }
                return Ok(()); // identical re-admission: idempotent
            }
        }
        self.admitted.push((
            proof.channel,
            proof.mechanism,
            proof.evidence_digest.clone(),
        ));
        Ok(())
    }

    /// Whether serving may proceed for this channel AT ALL (any
    /// mechanism proved out).
    #[must_use]
    pub fn serving_enabled(&self, channel: Channel) -> bool {
        self.admitted.iter().any(|(ch, _, _)| *ch == channel)
    }

    /// Whether THIS SPECIFIC mechanism may serve this channel.
    #[must_use]
    pub fn mechanism_enabled(&self, channel: Channel, mechanism: Mechanism) -> bool {
        self.admitted
            .iter()
            .any(|(ch, mech, _)| *ch == channel && *mech == mechanism)
    }

    /// Number of admitted proofs (bounded by construction: 6 distinct
    /// pairs max; no unbounding needed).
    #[must_use]
    pub fn admitted_count(&self) -> usize {
        self.admitted.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result_identity::DigestAlgorithm;

    fn evidence(seed: u8) -> TypedDigest {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain: "rabs.n001-matrix-row.sha256.v1",
            bytes,
        }
    }

    fn proof(
        channel: Channel,
        mechanism: Mechanism,
        preserved: bool,
        seed: u8,
    ) -> FeasibilityProof {
        FeasibilityProof {
            channel,
            mechanism,
            semantics_preserved: preserved,
            evidence_digest: evidence(seed),
        }
    }

    #[test]
    fn n001_serving_is_disabled_until_a_positive_proof_lands() {
        let gate = RunCacheGate::disabled();
        for ch in [Channel::Stable, Channel::Beta, Channel::Nightly] {
            assert!(
                !gate.serving_enabled(ch),
                "{} serving must ship disabled",
                ch.name()
            );
        }
        assert_eq!(gate.admitted_count(), 0);
    }

    #[test]
    fn n001_negative_proofs_never_enable_and_are_refused_loudly() {
        let mut gate = RunCacheGate::disabled();
        // The measured stable/beta shim stalls: a NEGATIVE result.
        assert_eq!(
            gate.admit_proof(&proof(Channel::Stable, Mechanism::LauncherShim, false, 1)),
            Err(GateRefusal::ProofRecordsUnpreservedSemantics)
        );
        assert!(!gate.serving_enabled(Channel::Stable));
        assert!(!gate.mechanism_enabled(Channel::Stable, Mechanism::LauncherShim));
        assert_eq!(gate.admitted_count(), 0, "negatives leave no residue");
    }

    #[test]
    fn n001_positive_proofs_enable_exactly_their_pair() {
        let mut gate = RunCacheGate::disabled();
        // Measured: nightly launcher-shim completed with correct outputs
        // and inherited jobserver descriptors.
        gate.admit_proof(&proof(Channel::Nightly, Mechanism::LauncherShim, true, 7))
            .expect("positive nightly shim proof admits");
        assert!(gate.serving_enabled(Channel::Nightly));
        assert!(gate.mechanism_enabled(Channel::Nightly, Mechanism::LauncherShim));
        // Other channel/mechanism pairs stay dark until THEIR proof lands.
        assert!(!gate.serving_enabled(Channel::Stable));
        assert!(!gate.serving_enabled(Channel::Beta));
        assert!(!gate.mechanism_enabled(Channel::Nightly, Mechanism::CanonicalDriverIntegration));
    }

    #[test]
    fn n001_conflicting_reproofs_refuse_idempotent_ones_pass() {
        let mut gate = RunCacheGate::disabled();
        gate.admit_proof(&proof(Channel::Nightly, Mechanism::LauncherShim, true, 7))
            .expect("first admission");
        // Same pair, SAME evidence: idempotent.
        gate.admit_proof(&proof(Channel::Nightly, Mechanism::LauncherShim, true, 7))
            .expect("idempotent re-admission");
        assert_eq!(gate.admitted_count(), 1);
        // Same pair, DIFFERENT evidence without a superseding story:
        // refuse — history is not rewritten.
        assert_eq!(
            gate.admit_proof(&proof(Channel::Nightly, Mechanism::LauncherShim, true, 8)),
            Err(GateRefusal::ConflictingProofAlreadyAdmitted)
        );
    }

    #[test]
    fn n001_registry_spellings_are_stable() {
        assert_eq!(Channel::Beta.name(), "beta");
        assert_eq!(
            Mechanism::CanonicalDriverIntegration.name(),
            "canonical-driver-integration"
        );
    }
}
