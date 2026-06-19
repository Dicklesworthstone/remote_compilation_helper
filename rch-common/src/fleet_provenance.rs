//! Release provenance, signature/checksum verification, and deploy audit for
//! fleet binary updates (bd-session-history-remediation-ocv9i.7.4).
//!
//! This is the pure, deterministic, I/O-free foundation. It answers, BEFORE a
//! fleet `rch-wkr` binary is pushed to a worker:
//!
//!   1. Is THIS artifact the intended release artifact for THIS worker
//!      (target-triple match + expected checksum + signature/provenance)?
//!   2. Under the active policy, may we proceed (verified), proceed with an
//!      explicit dev-artifact note, or must we fail closed?
//!
//! The expensive, side-effecting parts — computing the local checksum and
//! running the real cosign/sigstore verification — happen in the fleet deploy
//! path (`rch/src/fleet/executor.rs`, reusing `rch/src/update/verify.rs`).
//! Their *results* are fed into [`verify_artifact_provenance`] so the decision
//! logic stays a pure function that is exhaustively unit-testable, mirroring
//! the post-deploy validation classifiers (`classify_post_deploy`,
//! `classify_capabilities_handshake`) from sibling bead `.7.3`.
//!
//! Stable reason-code tokens are plain `&'static str` (see [`reason_code`]),
//! NOT [`crate::incident::IncidentReasonCode`] variants — the same choice the
//! `.7.3` post-deploy classifiers made (`os_arch_mismatch`,
//! `capabilities_handshake_failed`). The fleet path keeps one stable vocabulary
//! without churning the schema-pinned incident-ledger enum; a deploy site that
//! wants an incident-ledger entry maps the token at its boundary.

use serde::{Deserialize, Serialize};

use crate::schema_versions::{SchemaComponent, current_version};

/// Schema version for the persisted [`FleetDeployAuditRecord`].
pub const FLEET_DEPLOY_AUDIT_SCHEMA_VERSION: &str =
    current_version(SchemaComponent::FleetDeployAudit);

/// Stable reason-code tokens for provenance verification outcomes.
///
/// Append-only: never renumber or repurpose an existing token (dashboards, the
/// validation matrix, and the deploy audit trail key off these exact strings).
pub mod reason_code {
    /// Artifact targets a different OS/arch triple than the worker.
    pub const WRONG_TARGET_TRIPLE: &str = "provenance_wrong_target_triple";
    /// Expected checksum is known but the artifact's actual checksum differs.
    pub const CHECKSUM_MISMATCH: &str = "provenance_checksum_mismatch";
    /// Policy requires a checksum but none could be compared.
    pub const CHECKSUM_MISSING: &str = "provenance_checksum_missing";
    /// Signature material is present but failed cryptographic verification.
    pub const SIGNATURE_INVALID: &str = "provenance_signature_invalid";
    /// Policy requires a signature but the artifact has none.
    pub const SIGNATURE_MISSING: &str = "provenance_signature_missing";
    /// No verifiable material at all and policy forbids dev artifacts.
    pub const UNVERIFIABLE: &str = "provenance_unverifiable";
    /// No material, but policy explicitly permits a dev/local artifact.
    pub const DEV_ARTIFACT_ALLOWED: &str = "provenance_dev_artifact_allowed";
}

/// Signature / provenance material attached to a release artifact, as the
/// artifact resolver records it from a release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureMaterial {
    /// Reference to the signature bundle (e.g. a cosign bundle path or URL).
    pub bundle_ref: String,
    /// Certificate identity pattern the bundle must match (sigstore OIDC),
    /// e.g. the release-workflow identity regex used by `update/verify.rs`.
    pub identity_pattern: String,
}

/// Release provenance material the artifact resolver records for one fleet
/// binary / worker platform. Everything known about the *intended* release
/// artifact, used to prove the selected binary is the intended one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactProvenance {
    /// Stable artifact identity (e.g. the artifact file name).
    pub artifact_id: String,
    /// Source release / build id (git tag or release id). `None` for a
    /// locally-built dev artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// The Rust target triple this artifact targets.
    pub target_triple: String,
    /// Expected SHA-256 (lowercase hex, 64 chars) from the release manifest.
    /// `None` for an unverified dev artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    /// Signature / provenance material, when the release publishes one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureMaterial>,
    /// Builder / controller identity that produced the artifact (host or CI id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_identity: Option<String>,
    /// Worker protocol version this artifact expects to speak. `None` when the
    /// binary predates protocol negotiation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_protocol_version: Option<u32>,
}

impl ArtifactProvenance {
    /// A minimal dev-artifact record: a locally-built binary for `triple` with
    /// no release id, checksum, or signature.
    #[must_use]
    pub fn dev_artifact(artifact_id: impl Into<String>, triple: impl Into<String>) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            release_id: None,
            target_triple: triple.into(),
            expected_sha256: None,
            signature: None,
            builder_identity: None,
            expected_protocol_version: None,
        }
    }
}

/// Outcome of the real signature check performed by the deploy path (cosign /
/// sigstore). Fed into [`verify_artifact_provenance`] to keep that pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureCheck {
    /// No signature material was present on the artifact.
    Absent,
    /// Signature material present and cryptographically verified.
    Valid,
    /// Signature material present but failed verification.
    Invalid,
}

/// Policy controlling how strict provenance verification is for a deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenancePolicy {
    /// Require a valid signature; fail closed if absent or invalid.
    pub require_signature: bool,
    /// Require an expected checksum to compare against; fail closed if it
    /// cannot be compared.
    pub require_checksum: bool,
    /// Allow an unsigned / unverified locally-built dev artifact to proceed,
    /// recording an explicit reason. Has no effect when `require_signature` or
    /// `require_checksum` force a hard requirement.
    pub allow_dev_artifacts: bool,
}

impl ProvenancePolicy {
    /// Strict release policy: signature + checksum required, no dev artifacts.
    pub const STRICT: Self = Self {
        require_signature: true,
        require_checksum: true,
        allow_dev_artifacts: false,
    };

    /// Dev-friendly fleet policy: verify whatever material exists (fail closed
    /// on a MISMATCH or an INVALID signature), but permit an explicitly-noted
    /// dev artifact when no material is available.
    #[must_use]
    pub const fn dev_friendly() -> Self {
        Self {
            require_signature: false,
            require_checksum: false,
            allow_dev_artifacts: true,
        }
    }

    /// Resolve a policy from an environment-variable value (the contents of
    /// `RCH_FLEET_PROVENANCE`). A case-insensitive, trimmed `strict` selects
    /// [`Self::STRICT`]; an unset or any other value falls back to the
    /// dev-friendly default, so a fleet of locally-built binaries keeps
    /// deploying (fail-open) while still recording an explicit dev-artifact
    /// reason rather than refusing.
    #[must_use]
    pub fn from_env_value(value: Option<&str>) -> Self {
        match value.map(|v| v.trim().to_ascii_lowercase()).as_deref() {
            Some("strict") => Self::STRICT,
            _ => Self::dev_friendly(),
        }
    }
}

impl Default for ProvenancePolicy {
    fn default() -> Self {
        Self::dev_friendly()
    }
}

/// The pure verdict of provenance verification, computed BEFORE transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProvenanceVerdict {
    /// Fully verified: triple matches and at least one piece of provenance
    /// material (checksum and/or a valid signature) was positively checked.
    /// Safe to transfer.
    Verified,
    /// Material was absent but policy permits a dev artifact. Proceed, but the
    /// caller MUST record `reason` in the audit trail.
    DevArtifactAllowed { reason: String },
    /// Fail closed: do not transfer. Carries a stable `reason_code` token and a
    /// human `detail`.
    Rejected { reason_code: String, detail: String },
}

impl ProvenanceVerdict {
    /// Whether the artifact may be transferred to the worker.
    #[must_use]
    pub fn may_transfer(&self) -> bool {
        !matches!(self, Self::Rejected { .. })
    }

    /// Stable `verification_status` token for the audit trail.
    #[must_use]
    pub fn verification_status(&self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::DevArtifactAllowed { .. } => "dev_allowed",
            Self::Rejected { .. } => "rejected",
        }
    }

    /// Stable reason-code token, if any. `Verified` has none.
    #[must_use]
    pub fn reason_code(&self) -> Option<&str> {
        match self {
            Self::Verified => None,
            Self::DevArtifactAllowed { .. } => Some(reason_code::DEV_ARTIFACT_ALLOWED),
            Self::Rejected { reason_code, .. } => Some(reason_code.as_str()),
        }
    }
}

/// Verify an artifact's provenance against a worker platform and policy.
///
/// `actual_sha256` is the checksum the deploy path computed from the local
/// artifact file (lowercase hex), or `None` if it could not be computed.
/// `signature_check` is the result of the real cosign/sigstore verification.
/// Both are inputs so this function stays pure and exhaustively testable.
///
/// Checks run in fail-closed order; the FIRST failure rejects:
///   1. target triple must match the worker triple,
///   2. checksum: if an expected value is present it must equal `actual`
///      (mismatch rejects); a `require_checksum` policy with nothing to compare
///      rejects,
///   3. signature: `Invalid` rejects; `Absent` under `require_signature`
///      rejects,
///   4. otherwise `Verified` if any material was positively checked, else
///      `DevArtifactAllowed` when policy permits, else `Rejected`
///      (`UNVERIFIABLE`).
#[must_use]
pub fn verify_artifact_provenance(
    provenance: &ArtifactProvenance,
    worker_triple: &str,
    actual_sha256: Option<&str>,
    signature_check: SignatureCheck,
    policy: &ProvenancePolicy,
) -> ProvenanceVerdict {
    // 1. Target triple: a binary for the wrong OS/arch is wrong regardless of
    //    its hash, so this gate is first and unconditional.
    if provenance.target_triple != worker_triple {
        return ProvenanceVerdict::Rejected {
            reason_code: reason_code::WRONG_TARGET_TRIPLE.to_string(),
            detail: format!(
                "artifact {} targets {} but worker platform is {}",
                provenance.artifact_id, provenance.target_triple, worker_triple
            ),
        };
    }

    // 2. Checksum.
    let checksum_checked = match (provenance.expected_sha256.as_deref(), actual_sha256) {
        (Some(expected), Some(actual)) => {
            if !expected.eq_ignore_ascii_case(actual) {
                return ProvenanceVerdict::Rejected {
                    reason_code: reason_code::CHECKSUM_MISMATCH.to_string(),
                    detail: format!(
                        "artifact {} checksum mismatch (expected {expected}, got {actual})",
                        provenance.artifact_id
                    ),
                };
            }
            true
        }
        (Some(_), None) => {
            if policy.require_checksum {
                return ProvenanceVerdict::Rejected {
                    reason_code: reason_code::CHECKSUM_MISSING.to_string(),
                    detail: format!(
                        "artifact {} has an expected checksum but the actual checksum could not be computed",
                        provenance.artifact_id
                    ),
                };
            }
            false
        }
        (None, _) => {
            if policy.require_checksum {
                return ProvenanceVerdict::Rejected {
                    reason_code: reason_code::CHECKSUM_MISSING.to_string(),
                    detail: format!(
                        "no expected checksum is available for artifact {}",
                        provenance.artifact_id
                    ),
                };
            }
            false
        }
    };

    // 3. Signature.
    let signature_valid = match signature_check {
        SignatureCheck::Valid => true,
        SignatureCheck::Invalid => {
            return ProvenanceVerdict::Rejected {
                reason_code: reason_code::SIGNATURE_INVALID.to_string(),
                detail: format!(
                    "artifact {} signature failed verification",
                    provenance.artifact_id
                ),
            };
        }
        SignatureCheck::Absent => {
            if policy.require_signature {
                return ProvenanceVerdict::Rejected {
                    reason_code: reason_code::SIGNATURE_MISSING.to_string(),
                    detail: format!(
                        "artifact {} has no signature material and strict policy requires a valid signature",
                        provenance.artifact_id
                    ),
                };
            }
            false
        }
    };

    // 4. Outcome: at least one positive check => verified; else dev artifact.
    if checksum_checked || signature_valid {
        ProvenanceVerdict::Verified
    } else if policy.allow_dev_artifacts {
        ProvenanceVerdict::DevArtifactAllowed {
            reason: format!(
                "no signature/checksum material for artifact {} (release_id={}); permitted by dev-artifact policy",
                provenance.artifact_id,
                provenance.release_id.as_deref().unwrap_or("none")
            ),
        }
    } else {
        ProvenanceVerdict::Rejected {
            reason_code: reason_code::UNVERIFIABLE.to_string(),
            detail: format!(
                "artifact {} has no verifiable provenance material and policy forbids dev artifacts",
                provenance.artifact_id
            ),
        }
    }
}

/// Append-only audit record of a single fleet binary deploy attempt.
///
/// Serialized into the deploy E2E log and the rollback history so operators can
/// audit what was deployed where and which verification gate it passed. Field
/// set covers the bead's "rollback history records ..." and "E2E logs include
/// ..." acceptance criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetDeployAuditRecord {
    /// Schema version of this record (for migration of persisted history).
    pub schema_version: String,
    /// Correlates every event of one deploy run.
    pub run_id: String,
    /// Owning bead id (provenance for the audit row itself).
    pub bead_id: String,
    /// Target worker.
    pub worker_id: String,
    /// Remote user the binary was (or would be) installed as.
    pub remote_user: String,
    /// Exact remote path the binary was (or would be) installed at.
    pub remote_path: String,
    /// Identity of the artifact being deployed.
    pub artifact_id: String,
    /// Source release / build id, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    /// Target triple of the deployed artifact.
    pub target_triple: String,
    /// Identity of the artifact previously installed (rollback context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_artifact_id: Option<String>,
    /// Builder / controller identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_identity: Option<String>,
    /// Protocol version the artifact expects to speak.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_protocol_version: Option<u32>,
    /// When the deploy attempt occurred (Unix epoch millis).
    pub deployed_at_unix_ms: u64,
    /// How long the deploy attempt took, in milliseconds. Defaults to 0 and is
    /// set by the deploy path once the attempt completes (the verdict is
    /// recorded before transfer, so the duration is not yet known then).
    #[serde(default)]
    pub duration_ms: u64,
    /// `verified` | `dev_allowed` | `rejected` (from [`ProvenanceVerdict`]).
    pub verification_status: String,
    /// `none` | `rolled_back` | `rollback_failed`.
    pub rollback_status: String,
    /// Stable reason-code token, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// What triggered the deploy: `operator` | `remediation` | `canary_failure`
    /// | `scheduled`.
    pub trigger: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Stable rollback-status tokens for [`FleetDeployAuditRecord::rollback_status`].
pub mod rollback_status {
    /// No rollback was needed (deploy succeeded or was never applied).
    pub const NONE: &str = "none";
    /// A failed deploy was rolled back to the previous artifact.
    pub const ROLLED_BACK: &str = "rolled_back";
    /// A rollback was attempted but did not complete.
    pub const ROLLBACK_FAILED: &str = "rollback_failed";
}

impl FleetDeployAuditRecord {
    /// Build an audit record from a verdict and deploy facts. `rollback_status`
    /// defaults to `none` and `duration_ms` to 0; the deploy path overwrites
    /// them once a rollback runs / the attempt completes.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_verdict(
        run_id: impl Into<String>,
        bead_id: impl Into<String>,
        worker_id: impl Into<String>,
        remote_user: impl Into<String>,
        remote_path: impl Into<String>,
        provenance: &ArtifactProvenance,
        previous_artifact_id: Option<String>,
        deployed_at_unix_ms: u64,
        verdict: &ProvenanceVerdict,
        trigger: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: FLEET_DEPLOY_AUDIT_SCHEMA_VERSION.to_string(),
            run_id: run_id.into(),
            bead_id: bead_id.into(),
            worker_id: worker_id.into(),
            remote_user: remote_user.into(),
            remote_path: remote_path.into(),
            artifact_id: provenance.artifact_id.clone(),
            release_id: provenance.release_id.clone(),
            target_triple: provenance.target_triple.clone(),
            previous_artifact_id,
            builder_identity: provenance.builder_identity.clone(),
            expected_protocol_version: provenance.expected_protocol_version,
            deployed_at_unix_ms,
            duration_ms: 0,
            verification_status: verdict.verification_status().to_string(),
            rollback_status: rollback_status::NONE.to_string(),
            reason_code: verdict.reason_code().map(ToString::to_string),
            trigger: trigger.into(),
            detail: detail.into(),
        }
    }

    /// Record that a failed deploy was reverted to the previous artifact. This
    /// is the mutator the rollback path applies to a deploy's audit record
    /// before re-persisting it; the live deploy/rollback wiring is part of the
    /// `.7.4` continuation, so today only the rollback-after-canary unit tests
    /// exercise it.
    pub fn mark_rolled_back(&mut self) {
        self.rollback_status = rollback_status::ROLLED_BACK.to_string();
    }

    /// Record that a rollback was attempted but did not complete — the worker
    /// may be in a degraded state and needs operator attention. Like
    /// [`Self::mark_rolled_back`], this is applied by the (still-pending)
    /// deploy/rollback wiring; today only unit tests exercise it.
    pub fn mark_rollback_failed(&mut self) {
        self.rollback_status = rollback_status::ROLLBACK_FAILED.to_string();
    }

    /// Record how long the deploy attempt took once it completes. The verdict is
    /// computed before transfer, so the duration is not known at construction.
    pub fn set_duration_ms(&mut self, duration_ms: u64) {
        self.duration_ms = duration_ms;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_release(triple: &str, sha: &str) -> ArtifactProvenance {
        ArtifactProvenance {
            artifact_id: format!("rch-wkr-v1.0.42-{triple}"),
            release_id: Some("v1.0.42".to_string()),
            target_triple: triple.to_string(),
            expected_sha256: Some(sha.to_string()),
            signature: Some(SignatureMaterial {
                bundle_ref: "rch-wkr.sigstore.json".to_string(),
                identity_pattern: "^https://github.com/.*/release.yml@refs/.*$".to_string(),
            }),
            builder_identity: Some("github-actions".to_string()),
            expected_protocol_version: Some(1),
        }
    }

    const SHA: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const LINUX: &str = "x86_64-unknown-linux-musl";

    // Scenario: good signature (+ matching checksum) => Verified.
    #[test]
    fn good_signature_and_checksum_is_verified() {
        let p = signed_release(LINUX, SHA);
        let v = verify_artifact_provenance(
            &p,
            LINUX,
            Some(SHA),
            SignatureCheck::Valid,
            &ProvenancePolicy::STRICT,
        );
        assert_eq!(v, ProvenanceVerdict::Verified);
        assert!(v.may_transfer());
        assert_eq!(v.verification_status(), "verified");
        assert_eq!(v.reason_code(), None);
    }

    // Scenario: missing signature under STRICT policy => Rejected, fail closed.
    #[test]
    fn missing_signature_under_strict_policy_is_rejected() {
        let mut p = signed_release(LINUX, SHA);
        p.signature = None;
        let v = verify_artifact_provenance(
            &p,
            LINUX,
            Some(SHA),
            SignatureCheck::Absent,
            &ProvenancePolicy::STRICT,
        );
        assert!(!v.may_transfer());
        assert_eq!(v.reason_code(), Some(reason_code::SIGNATURE_MISSING));
        assert_eq!(v.verification_status(), "rejected");
    }

    // Scenario: an INVALID signature is rejected even under a lax policy.
    #[test]
    fn invalid_signature_is_rejected_under_any_policy() {
        let p = signed_release(LINUX, SHA);
        let v = verify_artifact_provenance(
            &p,
            LINUX,
            Some(SHA),
            SignatureCheck::Invalid,
            &ProvenancePolicy::dev_friendly(),
        );
        assert_eq!(v.reason_code(), Some(reason_code::SIGNATURE_INVALID));
        assert!(!v.may_transfer());
    }

    // Scenario: checksum mismatch => Rejected (takes precedence over signature).
    #[test]
    fn checksum_mismatch_is_rejected() {
        let p = signed_release(LINUX, SHA);
        let wrong = "0000000000000000000000000000000000000000000000000000000000000000";
        let v = verify_artifact_provenance(
            &p,
            LINUX,
            Some(wrong),
            SignatureCheck::Valid,
            &ProvenancePolicy::STRICT,
        );
        assert_eq!(v.reason_code(), Some(reason_code::CHECKSUM_MISMATCH));
        assert!(!v.may_transfer());
    }

    // Scenario: wrong target triple => Rejected (highest-priority gate).
    #[test]
    fn wrong_target_triple_is_rejected_even_with_valid_signature() {
        let p = signed_release(LINUX, SHA);
        let v = verify_artifact_provenance(
            &p,
            "aarch64-apple-darwin",
            Some(SHA),
            SignatureCheck::Valid,
            &ProvenancePolicy::STRICT,
        );
        assert_eq!(v.reason_code(), Some(reason_code::WRONG_TARGET_TRIPLE));
        assert!(!v.may_transfer());
    }

    // Scenario: local dev artifact (no material) under dev-friendly policy =>
    // DevArtifactAllowed with an explicit recorded reason.
    #[test]
    fn dev_artifact_is_allowed_with_explicit_reason() {
        let p = ArtifactProvenance::dev_artifact("rch-wkr-dev", LINUX);
        let v = verify_artifact_provenance(
            &p,
            LINUX,
            None,
            SignatureCheck::Absent,
            &ProvenancePolicy::dev_friendly(),
        );
        match &v {
            ProvenanceVerdict::DevArtifactAllowed { reason } => {
                assert!(reason.contains("dev-artifact policy"));
            }
            other => panic!("expected DevArtifactAllowed, got {other:?}"),
        }
        assert!(v.may_transfer());
        assert_eq!(v.verification_status(), "dev_allowed");
        assert_eq!(v.reason_code(), Some(reason_code::DEV_ARTIFACT_ALLOWED));
    }

    // A dev artifact under a policy that forbids dev artifacts but does not hard
    // -require material => Rejected(UNVERIFIABLE), never silently accepted.
    #[test]
    fn dev_artifact_without_allowance_is_unverifiable() {
        let p = ArtifactProvenance::dev_artifact("rch-wkr-dev", LINUX);
        let policy = ProvenancePolicy {
            require_signature: false,
            require_checksum: false,
            allow_dev_artifacts: false,
        };
        let v = verify_artifact_provenance(&p, LINUX, None, SignatureCheck::Absent, &policy);
        assert_eq!(v.reason_code(), Some(reason_code::UNVERIFIABLE));
        assert!(!v.may_transfer());
    }

    // A checksum-only artifact (no signature) under require_checksum but not
    // require_signature is Verified once the checksum matches.
    #[test]
    fn checksum_only_match_is_verified() {
        let mut p = signed_release(LINUX, SHA);
        p.signature = None;
        let policy = ProvenancePolicy {
            require_signature: false,
            require_checksum: true,
            allow_dev_artifacts: false,
        };
        let v = verify_artifact_provenance(&p, LINUX, Some(SHA), SignatureCheck::Absent, &policy);
        assert_eq!(v, ProvenanceVerdict::Verified);
    }

    // require_checksum with nothing to compare => Rejected(CHECKSUM_MISSING).
    #[test]
    fn require_checksum_without_value_is_rejected() {
        let p = ArtifactProvenance::dev_artifact("rch-wkr-dev", LINUX);
        let policy = ProvenancePolicy {
            require_signature: false,
            require_checksum: true,
            allow_dev_artifacts: true,
        };
        let v = verify_artifact_provenance(&p, LINUX, None, SignatureCheck::Absent, &policy);
        assert_eq!(v.reason_code(), Some(reason_code::CHECKSUM_MISSING));
    }

    #[test]
    fn checksum_comparison_is_case_insensitive() {
        let p = signed_release(LINUX, SHA);
        let upper = SHA.to_ascii_uppercase();
        let v = verify_artifact_provenance(
            &p,
            LINUX,
            Some(&upper),
            SignatureCheck::Valid,
            &ProvenancePolicy::STRICT,
        );
        assert_eq!(v, ProvenanceVerdict::Verified);
    }

    #[test]
    fn default_policy_is_dev_friendly() {
        assert_eq!(
            ProvenancePolicy::default(),
            ProvenancePolicy::dev_friendly()
        );
    }

    #[test]
    fn audit_record_from_verdict_carries_status_and_reason() {
        let p = signed_release(LINUX, SHA);
        let verdict = verify_artifact_provenance(
            &p,
            LINUX,
            Some(SHA),
            SignatureCheck::Valid,
            &ProvenancePolicy::STRICT,
        );
        let rec = FleetDeployAuditRecord::from_verdict(
            "run-1",
            "bd-session-history-remediation-ocv9i.7.4",
            "css",
            "ubuntu",
            "/home/ubuntu/.local/bin/rch-wkr",
            &p,
            Some("rch-wkr-v1.0.41-x86_64-unknown-linux-musl".to_string()),
            1_700_000_000_000,
            &verdict,
            "operator",
            "deploy verified",
        );
        assert_eq!(rec.schema_version, FLEET_DEPLOY_AUDIT_SCHEMA_VERSION);
        assert_eq!(rec.verification_status, "verified");
        assert_eq!(rec.rollback_status, rollback_status::NONE);
        assert_eq!(rec.reason_code, None);
        assert_eq!(rec.target_triple, LINUX);
        // duration_ms defaults to 0 until the deploy path sets it.
        assert_eq!(rec.duration_ms, 0);
        assert_eq!(rec.deployed_at_unix_ms, 1_700_000_000_000);
        assert_eq!(
            rec.previous_artifact_id.as_deref(),
            Some("rch-wkr-v1.0.41-x86_64-unknown-linux-musl")
        );
    }

    #[test]
    fn audit_record_serde_roundtrip_is_stable() {
        let p = ArtifactProvenance::dev_artifact("rch-wkr-dev", LINUX);
        let verdict = ProvenanceVerdict::DevArtifactAllowed {
            reason: "dev".to_string(),
        };
        let rec = FleetDeployAuditRecord::from_verdict(
            "run-2",
            "bd-x",
            "hz1",
            "ubuntu",
            "/home/ubuntu/.local/bin/rch-wkr",
            &p,
            None,
            42,
            &verdict,
            "remediation",
            "dev deploy",
        );
        let json = serde_json::to_string(&rec).unwrap();
        let back: FleetDeployAuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
        // Stable tagged-enum verdict serialization.
        let vjson = serde_json::to_string(&verdict).unwrap();
        assert!(vjson.contains("\"status\":\"dev_artifact_allowed\""));
    }

    #[test]
    fn verdict_is_tagged_with_snake_case_status() {
        let rejected = ProvenanceVerdict::Rejected {
            reason_code: reason_code::CHECKSUM_MISMATCH.to_string(),
            detail: "x".to_string(),
        };
        let json = serde_json::to_string(&rejected).unwrap();
        assert!(json.contains("\"status\":\"rejected\""));
        assert!(json.contains("provenance_checksum_mismatch"));

        // The internally-tagged UNIT variant must round-trip too (a classic
        // serde footgun for `#[serde(tag = ...)]` enums with unit variants).
        let verified = ProvenanceVerdict::Verified;
        let vjson = serde_json::to_string(&verified).unwrap();
        assert_eq!(vjson, "{\"status\":\"verified\"}");
        let back: ProvenanceVerdict = serde_json::from_str(&vjson).unwrap();
        assert_eq!(back, ProvenanceVerdict::Verified);
    }

    #[test]
    fn schema_version_is_pinned() {
        assert_eq!(FLEET_DEPLOY_AUDIT_SCHEMA_VERSION, "1.0.0");
    }

    #[test]
    fn policy_from_env_value_selects_strict_only_for_strict() {
        assert_eq!(
            ProvenancePolicy::from_env_value(Some("strict")),
            ProvenancePolicy::STRICT
        );
        // Case-insensitive + whitespace tolerant.
        assert_eq!(
            ProvenancePolicy::from_env_value(Some("  STRICT \n")),
            ProvenancePolicy::STRICT
        );
        // Anything else (including unset) is the dev-friendly fail-open default.
        for v in [
            None,
            Some(""),
            Some("dev"),
            Some("1"),
            Some("relaxed"),
            Some("strictish"),
        ] {
            assert_eq!(
                ProvenancePolicy::from_env_value(v),
                ProvenancePolicy::dev_friendly(),
                "value {v:?} should resolve to dev_friendly"
            );
        }
    }

    // Scenario: rollback after a failed canary deploy — the audit record is
    // updated from `none` to `rolled_back` and carries the elapsed duration.
    #[test]
    fn rollback_after_canary_marks_record_rolled_back() {
        let p = ArtifactProvenance::dev_artifact("rch-wkr", LINUX);
        let verdict = ProvenanceVerdict::DevArtifactAllowed {
            reason: "dev".to_string(),
        };
        let mut rec = FleetDeployAuditRecord::from_verdict(
            "run-canary",
            "bd-x",
            "css",
            "ubuntu",
            "/home/ubuntu/.local/bin/rch-wkr",
            &p,
            Some("rch-wkr-prev".to_string()),
            1,
            &verdict,
            "canary_failure",
            "canary failed, reverting",
        );
        assert_eq!(rec.rollback_status, rollback_status::NONE);
        rec.set_duration_ms(4_200);
        rec.mark_rolled_back();
        assert_eq!(rec.rollback_status, rollback_status::ROLLED_BACK);
        assert_eq!(rec.duration_ms, 4_200);
        // Round-trips with the mutated status.
        let json = serde_json::to_string(&rec).unwrap();
        let back: FleetDeployAuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
    }

    // Scenario: an interrupted deploy whose rollback also fails is flagged
    // `rollback_failed` so operators see the worker needs attention.
    #[test]
    fn interrupted_deploy_with_failed_rollback_is_flagged() {
        let p = ArtifactProvenance::dev_artifact("rch-wkr", LINUX);
        let verdict = ProvenanceVerdict::Verified;
        let mut rec = FleetDeployAuditRecord::from_verdict(
            "run-interrupt",
            "bd-x",
            "hz1",
            "ubuntu",
            "/home/ubuntu/.local/bin/rch-wkr",
            &p,
            None,
            1,
            &verdict,
            "operator",
            "transfer interrupted mid-deploy",
        );
        rec.mark_rollback_failed();
        assert_eq!(rec.rollback_status, rollback_status::ROLLBACK_FAILED);
    }
}
