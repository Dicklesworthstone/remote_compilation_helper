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
//! - agent/session directory contents default `LocalOnly`; an explicit
//!   build-input class may override this hygiene default, never a secret
//!   or structural refusal;
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

/// Built-in secret-location rules (the seed set — projects extend via
/// configuration, and scanners may only ADD).
///
/// Patterns are lower case and matched against an ASCII-lowercased,
/// separator-anchored probe of the candidate path, so a spelling like
/// `.ENV` or a relative `.env` cannot walk past them (T027). Keep new
/// patterns lower case; a pattern beginning with `/` matches a whole
/// path component, one without it matches any substring.
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

/// Match only descendants of exact directory names, as in RCH's default
/// source-sync exclusions (#109). The leaf itself may be an ordinary file:
/// `fixtures/.ntm` is not evidence of a session directory. No generic scratch,
/// data, artifacts or project-configuration directory is classified here.
///
/// Paths use the capture protocol's `/` separator. Keep this byte-preserving
/// and case-sensitive, unlike the stronger, case-folded credential policy.
/// Directory entries can remain in a snapshot; their contents are not read,
/// retained, or materialized by the default membership policy.
fn is_agent_state_descendant(raw_path: &[u8]) -> bool {
    raw_path
        .rsplit(|byte| *byte == b'/')
        .skip(1)
        .any(|component| matches!(component, b".ntm" | b".beads-recovery" | b".beads"))
}

/// Classify one candidate path. `configured` is the project's declared
/// class for the path, if any. There is NO `.gitignore` parameter —
/// ignore state cannot be consulted even by mistake (I38).
/// The hygiene override uses this API argument; snapshot capture currently
/// supplies `None`. This does not add `.rchignore` support to RABS.
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
    //
    // The probe normalizes two things the seed set would otherwise be
    // silently sensitive to (T027):
    //
    // - CASE. The patterns are lower case and the match is byte-exact,
    //   but the filesystems this protects on are not case-sensitive. On
    //   macOS APFS and on Windows, `.ENV` and `.env` name the SAME
    //   FILE, so an upper-case spelling classified a credential as an
    //   ordinary build input and uploaded it. Erring toward denial is
    //   right here even on Linux, where they are different files: a
    //   false positive costs an action its remote execution, a false
    //   negative ships a credential off the machine.
    // - ANCHORING. Five patterns begin with `/` so they match a path
    //   COMPONENT rather than any substring, which is what keeps
    //   `app.environment` out of `/.env`'s reach. Nothing precedes the
    //   first component of a RELATIVE path, so a bare `.env` matched
    //   none of them. Prefixing the separator restores the component
    //   boundary without widening any pattern.
    let mut probe = Vec::with_capacity(raw_path.len() + 1);
    if raw_path.first() != Some(&b'/') {
        probe.push(b'/');
    }
    probe.extend(raw_path.iter().map(u8::to_ascii_lowercase));
    let matches_secret_location = SECRET_LOCATION_PATTERNS
        .iter()
        .any(|p| probe.windows(p.len()).any(|w| w == *p));
    if matches_secret_location {
        return match configured {
            Some(SourceCapturePolicy::SecretCapability) => SourceCapturePolicy::SecretCapability,
            _ => SourceCapturePolicy::Denied,
        };
    }
    configured.unwrap_or_else(|| {
        if is_agent_state_descendant(raw_path) {
            SourceCapturePolicy::LocalOnly
        } else {
            SourceCapturePolicy::BuildInputAllowed
        }
    })
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
    fn agent_state_is_local_only_at_every_depth() {
        for prefix in ["", "nested/", "/__rabs/workspace/nested/"] {
            for directory in [".ntm", ".beads-recovery", ".beads"] {
                for suffix in [
                    "state.json",
                    "sessions/log.txt",
                    "Cargo.lock",
                    ".cargo/config.toml",
                ] {
                    let path = format!("{prefix}{directory}/{suffix}");
                    assert_eq!(
                        classify_path(path.as_bytes(), PathShape::REGULAR, None),
                        SourceCapturePolicy::LocalOnly,
                        "{path}"
                    );
                }
            }
        }
        assert_eq!(
            classify_path(b".beads/.br_recovery/state.json", PathShape::REGULAR, None),
            SourceCapturePolicy::LocalOnly
        );
    }

    #[test]
    fn agent_state_policy_preserves_legitimate_inputs_and_raw_bytes() {
        for path in [
            &b"scratch/generated.rs"[..],
            b"data/input.bin",
            b"artifacts/fixture.txt",
            b".cargo/config.toml",
            b".claude/settings.json",
            b".rch/config.toml",
            b".ntm-fixtures/input.txt",
            b".beads-recovery-tools/input.txt",
            b"fixtures/.ntm",
            b"fixtures/.beads-recovery",
            b"fixtures/.beads",
            b".ntm",
            b".beads-recovery",
            b"raw-\xff/.ntm",
        ] {
            assert_eq!(
                classify_path(path, PathShape::REGULAR, None),
                SourceCapturePolicy::BuildInputAllowed,
                "{path:?}"
            );
        }
        assert_eq!(
            classify_path(b"raw-\xff/.ntm/log-\xfe", PathShape::REGULAR, None),
            SourceCapturePolicy::LocalOnly
        );
    }

    #[test]
    fn agent_state_explicit_classes_preserve_secret_and_structural_denials() {
        for policy in [
            SourceCapturePolicy::BuildInputAllowed,
            SourceCapturePolicy::LocalOnly,
            SourceCapturePolicy::SecretCapability,
            SourceCapturePolicy::Denied,
            SourceCapturePolicy::ExplicitOperatorApproval,
        ] {
            assert_eq!(
                classify_path(b".ntm/fixture.json", PathShape::REGULAR, Some(policy)),
                policy
            );
            for shape in [
                PathShape {
                    escapes_closure: true,
                    ..PathShape::REGULAR
                },
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
                    classify_path(b".ntm/fixture.json", shape, Some(policy)),
                    SourceCapturePolicy::Denied
                );
            }
            for secret in [&b".ntm/.env"[..], b".beads-recovery/signing.pem"] {
                let expected = if policy == SourceCapturePolicy::SecretCapability {
                    policy
                } else {
                    SourceCapturePolicy::Denied
                };
                assert_eq!(
                    classify_path(secret, PathShape::REGULAR, Some(policy)),
                    expected
                );
            }
        }
    }

    #[test]
    fn agent_state_partition_keeps_unapproved_observations_edge_private() {
        let input = b"src/raw-\xff.rs".to_vec();
        let local = b"nested/.ntm/log-\xfe".to_vec();
        let approved = b"fixtures/.beads-recovery/input.txt".to_vec();
        let secret = b".ntm/.env".to_vec();
        let decision = partition_capture(&[
            (input.clone(), PathShape::REGULAR, None),
            (local.clone(), PathShape::REGULAR, None),
            (
                approved.clone(),
                PathShape::REGULAR,
                Some(SourceCapturePolicy::BuildInputAllowed),
            ),
            (
                secret.clone(),
                PathShape::REGULAR,
                Some(SourceCapturePolicy::BuildInputAllowed),
            ),
        ]);
        assert_eq!(decision.uploaded, vec![input, approved]);
        assert_eq!(decision.edge_private_receipt, vec![local, secret]);
    }

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
