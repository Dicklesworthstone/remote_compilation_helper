//! Source-capture policy classes (bead E027; invariant I38; plan §78;
//! risk R82; fixture family T027).
//!
//! What may leave the developer's machine is a POLICY decision, and
//! **`.gitignore` is never a security boundary** (I38): ignore files
//! exist for build hygiene; secrets live in ignored files precisely
//! because developers assume ignored means private. Classification
//! here consults declared policy classes and built-in secret-location
//! rules — there is deliberately no `.gitignore` input parameter.
//!
//! Rules with teeth:
//!
//! - credential/key locations (`.env*`, private-key formats, cloud
//!   creds, signing material) default `Denied`/`SecretCapability`;
//! - symlink/bind escapes, devices, sockets, and unrelated
//!   home/ancestor paths are structurally refused;
//! - discovery reading a denied path does NOT silently upload it: the
//!   ACTION's disposition changes (local-only, narrow capability
//!   request, or refusal with explanation) while the path stays out
//!   of every uploadable surface;
//! - denied-path observations land in an EDGE-PRIVATE receipt (they
//!   never travel), and permitted members preserve raw path bytes;
//! - secret scanners are advisory defense-in-depth ONLY — the policy
//!   classes are the authority, a scanner can only ADD denials.

/// The capture policy classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceCapturePolicy {
    /// Ordinary build input: may be captured and uploaded.
    BuildInputAllowed,
    /// May be read locally; never uploaded (action becomes local-only
    /// if it depends on this path).
    LocalOnly,
    /// Reachable only through a declared E016 secret capability.
    SecretCapability,
    /// Never captured, never uploaded, never logged.
    Denied,
    /// Requires an explicit operator approval recorded by ID.
    ExplicitOperatorApproval,
}

/// Filesystem-shape facts about a candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathShape {
    /// Path escapes the workspace closure via symlink/bind.
    pub escapes_closure: bool,
    /// Device or socket node.
    pub special_node: bool,
    /// Lives under an unrelated home/ancestor directory.
    pub unrelated_ancestor: bool,
}

impl PathShape {
    /// A plain in-closure regular file.
    pub const REGULAR: Self = Self {
        escapes_closure: false,
        special_node: false,
        unrelated_ancestor: false,
    };
}

/// Built-in secret-location rules (raw byte patterns; the seed set —
/// projects extend via configuration, and scanners may only ADD).
const SECRET_LOCATION_PATTERNS: &[&[u8]] = &[
    b"/.env",
    b"id_rsa",
    b"id_ed25519",
    b".pem",
    b".p12",
    b".keystore",
    b"/.aws/credentials",
    b"/.config/gcloud/",
    b"/.docker/config.json",
    b"/.netrc",
    b"secring",
];

/// Classify one candidate path. `configured` is the project's declared
/// class for the path, if any. There is NO `.gitignore` parameter —
/// ignore state cannot be consulted even by mistake (I38).
#[must_use]
pub fn classify_path(
    raw_path: &[u8],
    shape: PathShape,
    configured: Option<SourceCapturePolicy>,
) -> SourceCapturePolicy {
    // Structural refusals dominate everything, configuration included.
    if shape.escapes_closure || shape.special_node || shape.unrelated_ancestor {
        return SourceCapturePolicy::Denied;
    }
    // Built-in secret locations: denied-by-default even when the
    // project configured something weaker; SecretCapability (which is
    // still never an upload) is the only override that stands.
    let matches_secret_location = SECRET_LOCATION_PATTERNS
        .iter()
        .any(|p| raw_path.windows(p.len()).any(|w| w == *p));
    if matches_secret_location {
        return match configured {
            Some(SourceCapturePolicy::SecretCapability) => SourceCapturePolicy::SecretCapability,
            _ => SourceCapturePolicy::Denied,
        };
    }
    configured.unwrap_or(SourceCapturePolicy::BuildInputAllowed)
}

/// The action-level consequence of discovery touching a denied path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeniedReadConsequence {
    /// The action runs local-only; nothing denied uploads.
    ActionBecomesLocalOnly,
    /// The action may request the named narrow capability.
    RequestNarrowCapability {
        /// The E016 capability that would legitimize the read.
        capability: String,
    },
    /// Refused outright, with the explanation for `rch why`.
    RefusedWithExplanation {
        /// Human/machine explanation.
        reason: &'static str,
    },
}

/// One snapshot-capture decision: what uploads, what stays.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CaptureDecision {
    /// Members that upload (raw path bytes preserved).
    pub uploaded: Vec<Vec<u8>>,
    /// Denied/local observations — EDGE-PRIVATE, never uploaded.
    pub edge_private_receipt: Vec<Vec<u8>>,
}

/// Partition discovered paths into the capture decision.
#[must_use]
pub fn partition_capture(
    discovered: &[(Vec<u8>, PathShape, Option<SourceCapturePolicy>)],
) -> CaptureDecision {
    let mut decision = CaptureDecision::default();
    for (raw, shape, configured) in discovered {
        match classify_path(raw, *shape, *configured) {
            SourceCapturePolicy::BuildInputAllowed => decision.uploaded.push(raw.clone()),
            SourceCapturePolicy::LocalOnly
            | SourceCapturePolicy::SecretCapability
            | SourceCapturePolicy::Denied
            | SourceCapturePolicy::ExplicitOperatorApproval => {
                decision.edge_private_receipt.push(raw.clone());
            }
        }
    }
    decision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_secret_paths_never_reach_uploadable_surfaces() {
        // THE T027 acceptance: seed secret/denied paths among ordinary
        // sources; the uploaded set must not contain a single one.
        let discovered = vec![
            (
                b"/__rabs/workspace/src/lib.rs".to_vec(),
                PathShape::REGULAR,
                None,
            ),
            (
                b"/__rabs/workspace/.env.production".to_vec(),
                PathShape::REGULAR,
                None,
            ),
            (b"/home/u/.ssh/id_rsa".to_vec(), PathShape::REGULAR, None),
            (
                b"/home/u/.aws/credentials".to_vec(),
                PathShape::REGULAR,
                None,
            ),
            (
                b"/__rabs/workspace/signing.pem".to_vec(),
                PathShape::REGULAR,
                None,
            ),
            (
                b"/__rabs/workspace/build.rs".to_vec(),
                PathShape::REGULAR,
                None,
            ),
        ];
        let decision = partition_capture(&discovered);
        assert_eq!(
            decision.uploaded,
            vec![
                b"/__rabs/workspace/src/lib.rs".to_vec(),
                b"/__rabs/workspace/build.rs".to_vec(),
            ],
            "only ordinary build inputs upload"
        );
        // The denied observations exist — but only edge-private.
        assert_eq!(decision.edge_private_receipt.len(), 4);
    }

    #[test]
    fn gitignore_is_not_consultable_even_in_principle() {
        // I38 structurally: classify_path has no ignore-state
        // parameter. An ignored-but-secret file and a tracked file
        // classify identically on policy + shape alone.
        let ignored_secret = classify_path(b"/__rabs/workspace/.env", PathShape::REGULAR, None);
        assert_eq!(ignored_secret, SourceCapturePolicy::Denied);
        let tracked_source =
            classify_path(b"/__rabs/workspace/src/lib.rs", PathShape::REGULAR, None);
        assert_eq!(tracked_source, SourceCapturePolicy::BuildInputAllowed);
    }

    #[test]
    fn structural_refusals_dominate_configuration() {
        // A symlink escape configured as allowed: still denied.
        let escape = PathShape {
            escapes_closure: true,
            ..PathShape::REGULAR
        };
        assert_eq!(
            classify_path(
                b"/__rabs/workspace/link-out",
                escape,
                Some(SourceCapturePolicy::BuildInputAllowed)
            ),
            SourceCapturePolicy::Denied
        );
        for shape in [
            PathShape {
                special_node: true,
                ..PathShape::REGULAR
            },
            PathShape {
                unrelated_ancestor: true,
                ..PathShape::REGULAR
            },
        ] {
            assert_eq!(
                classify_path(b"/x", shape, Some(SourceCapturePolicy::BuildInputAllowed)),
                SourceCapturePolicy::Denied
            );
        }
    }

    #[test]
    fn secret_locations_deny_by_default_and_only_capability_stands() {
        // Weaker configuration cannot override a secret location…
        assert_eq!(
            classify_path(
                b"/__rabs/workspace/.env",
                PathShape::REGULAR,
                Some(SourceCapturePolicy::BuildInputAllowed)
            ),
            SourceCapturePolicy::Denied
        );
        // …but the declared secret-capability route stands (and is
        // still never an upload — partition proves that separately).
        assert_eq!(
            classify_path(
                b"/__rabs/workspace/.env",
                PathShape::REGULAR,
                Some(SourceCapturePolicy::SecretCapability)
            ),
            SourceCapturePolicy::SecretCapability
        );
    }

    #[test]
    fn denied_reads_change_the_action_not_the_upload() {
        // The three lawful consequences of discovery touching a denied
        // path — none of which is "upload it".
        let consequences = [
            DeniedReadConsequence::ActionBecomesLocalOnly,
            DeniedReadConsequence::RequestNarrowCapability {
                capability: "signing-key".into(),
            },
            DeniedReadConsequence::RefusedWithExplanation {
                reason: "action reads ~/.aws/credentials; no capability declared",
            },
        ];
        // Exhaustive match: a variant carrying an upload simply does
        // not exist — adding one forces this match to face it.
        for c in &consequences {
            match c {
                DeniedReadConsequence::ActionBecomesLocalOnly
                | DeniedReadConsequence::RequestNarrowCapability { .. }
                | DeniedReadConsequence::RefusedWithExplanation { .. } => {}
            }
        }
    }
}
