//! Namespace ACLs + pre-upload local-only/secret path policy (bead
//! S019; plan §106; enforced with the E027 source capture).
//!
//! Source-transfer authorization happens BEFORE any object upload:
//!
//! - the ACL maps path prefixes to scopes — `Uploadable`,
//!   `LocalOnly`, `SecretScoped { slot }` — and the MOST SPECIFIC
//!   matching prefix wins;
//! - a path with NO matching rule is `LocalOnly` (fail closed:
//!   unlisted paths never upload);
//! - a project may be TRUSTED FOR EXECUTION while selected paths
//!   stay local-only — execution trust never unlocks transfer;
//! - secret-scoped paths cross the wire as S007 SLOT REFERENCES,
//!   never as bytes (the admitted-entry enum has no bytes arm for
//!   them);
//! - the plan is the only path to an upload: `authorize_uploads`
//!   consumes the candidate list and returns admitted entries plus
//!   typed withholdings — nothing withheld can appear admitted.

/// The scope a namespace rule assigns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScope {
    /// May upload as object bytes.
    Uploadable,
    /// Never leaves the box.
    LocalOnly,
    /// Crosses the wire only as a capability slot reference.
    SecretScoped {
        /// The S007 logical slot standing in for the content.
        slot: String,
    },
}

/// One ACL rule: a path prefix and its scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceRule {
    /// Virtual path prefix (canonical namespace).
    pub prefix: String,
    /// Assigned scope.
    pub scope: PathScope,
}

/// The per-project namespace ACL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceAcl {
    /// The rules (order irrelevant; specificity decides).
    pub rules: Vec<NamespaceRule>,
    /// Project trusted for remote EXECUTION (does not unlock
    /// transfer of local-only paths).
    pub trusted_for_execution: bool,
}

impl NamespaceAcl {
    /// The effective scope for a path: most specific matching prefix
    /// wins; no match is fail-closed `LocalOnly`.
    #[must_use]
    pub fn scope_of(&self, path: &str) -> PathScope {
        self.rules
            .iter()
            .filter(|r| path.starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
            .map_or(PathScope::LocalOnly, |r| r.scope.clone())
    }
}

/// An admitted upload entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadEntry {
    /// Ordinary object bytes for this path.
    ObjectBytes {
        /// The path.
        path: String,
    },
    /// A slot reference — the bytes stay home.
    SlotReference {
        /// The path.
        path: String,
        /// The S007 slot the worker resolves through its own
        /// capability channel.
        slot: String,
    },
}

/// A typed withholding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Withheld {
    /// The path withheld.
    pub path: String,
    /// Why (stable reason code).
    pub reason_code: &'static str,
}

/// The pre-upload authorization outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPlan {
    /// Entries authorized to cross the wire.
    pub admitted: Vec<UploadEntry>,
    /// Paths withheld, each with its reason.
    pub withheld: Vec<Withheld>,
}

/// Authorize a candidate upload set BEFORE any transfer.
#[must_use]
pub fn authorize_uploads(acl: &NamespaceAcl, candidates: &[String]) -> UploadPlan {
    let mut admitted = Vec::new();
    let mut withheld = Vec::new();
    for path in candidates {
        match acl.scope_of(path) {
            PathScope::Uploadable => admitted.push(UploadEntry::ObjectBytes { path: path.clone() }),
            PathScope::LocalOnly => withheld.push(Withheld {
                path: path.clone(),
                reason_code: "UPLOAD_WITHHELD_LOCAL_ONLY",
            }),
            PathScope::SecretScoped { slot } => admitted.push(UploadEntry::SlotReference {
                path: path.clone(),
                slot,
            }),
        }
    }
    UploadPlan { admitted, withheld }
}

/// What happens to an ACTION that requires a withheld input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredInputDecision {
    /// Every required input may transfer: remote execution proceeds.
    RemoteEligible,
    /// A required input is local-only: the action RUNS LOCALLY —
    /// execution trust does not move the bytes.
    RunLocally,
}

/// Decide remote eligibility for an action's required inputs.
#[must_use]
pub fn required_input_decision(acl: &NamespaceAcl, required: &[String]) -> RequiredInputDecision {
    let any_local_only = required
        .iter()
        .any(|p| acl.scope_of(p) == PathScope::LocalOnly);
    if any_local_only {
        RequiredInputDecision::RunLocally
    } else {
        RequiredInputDecision::RemoteEligible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl() -> NamespaceAcl {
        NamespaceAcl {
            rules: vec![
                NamespaceRule {
                    prefix: "/__rabs/workspace/".into(),
                    scope: PathScope::Uploadable,
                },
                NamespaceRule {
                    prefix: "/__rabs/workspace/ops/".into(),
                    scope: PathScope::LocalOnly,
                },
                NamespaceRule {
                    prefix: "/__rabs/workspace/.cargo/credentials".into(),
                    scope: PathScope::SecretScoped {
                        slot: "cargo-registry-token".into(),
                    },
                },
            ],
            trusted_for_execution: true,
        }
    }

    #[test]
    fn authorization_happens_before_upload_and_partitions_exactly() {
        // THE acceptance fixture (with the E027 capture set): a mixed
        // candidate list partitions into admitted vs typed
        // withholdings, and nothing withheld appears admitted.
        let candidates = vec![
            "/__rabs/workspace/src/lib.rs".to_owned(),
            "/__rabs/workspace/ops/deploy-keys.toml".to_owned(),
            "/__rabs/workspace/.cargo/credentials".to_owned(),
        ];
        let plan = authorize_uploads(&acl(), &candidates);
        assert_eq!(
            plan.admitted,
            vec![
                UploadEntry::ObjectBytes {
                    path: "/__rabs/workspace/src/lib.rs".into()
                },
                UploadEntry::SlotReference {
                    path: "/__rabs/workspace/.cargo/credentials".into(),
                    slot: "cargo-registry-token".into(),
                },
            ]
        );
        assert_eq!(
            plan.withheld,
            vec![Withheld {
                path: "/__rabs/workspace/ops/deploy-keys.toml".into(),
                reason_code: "UPLOAD_WITHHELD_LOCAL_ONLY",
            }]
        );
        // Nothing withheld is admitted (the partition is exact).
        for w in &plan.withheld {
            assert!(!plan.admitted.iter().any(|e| match e {
                UploadEntry::ObjectBytes { path } | UploadEntry::SlotReference { path, .. } =>
                    path == &w.path,
            }));
        }
    }

    #[test]
    fn the_most_specific_prefix_wins_both_directions() {
        // /workspace is uploadable, but /workspace/ops is local-only:
        // the longer rule governs its subtree.
        let acl = acl();
        assert_eq!(
            acl.scope_of("/__rabs/workspace/ops/x.toml"),
            PathScope::LocalOnly
        );
        assert_eq!(
            acl.scope_of("/__rabs/workspace/src/main.rs"),
            PathScope::Uploadable
        );
        // And the inverse layering: local-only root, uploadable leaf.
        let inverse = NamespaceAcl {
            rules: vec![
                NamespaceRule {
                    prefix: "/data/".into(),
                    scope: PathScope::LocalOnly,
                },
                NamespaceRule {
                    prefix: "/data/public/".into(),
                    scope: PathScope::Uploadable,
                },
            ],
            trusted_for_execution: false,
        };
        assert_eq!(inverse.scope_of("/data/private.db"), PathScope::LocalOnly);
        assert_eq!(
            inverse.scope_of("/data/public/schema.json"),
            PathScope::Uploadable
        );
    }

    #[test]
    fn unlisted_paths_fail_closed_to_local_only() {
        assert_eq!(
            acl().scope_of("/etc/passwd"),
            PathScope::LocalOnly,
            "no rule = no upload, ever"
        );
        let plan = authorize_uploads(&acl(), &["/etc/passwd".to_owned()]);
        assert!(plan.admitted.is_empty());
        assert_eq!(plan.withheld.len(), 1);
    }

    #[test]
    fn execution_trust_never_unlocks_transfer() {
        // THE separation the bead names: the project IS trusted for
        // execution, and its ops/ paths still withhold — a required
        // local-only input routes the action to local execution
        // instead of moving the bytes.
        let acl = acl();
        assert!(acl.trusted_for_execution);
        assert_eq!(
            acl.scope_of("/__rabs/workspace/ops/deploy-keys.toml"),
            PathScope::LocalOnly
        );
        assert_eq!(
            required_input_decision(
                &acl,
                &[
                    "/__rabs/workspace/src/lib.rs".to_owned(),
                    "/__rabs/workspace/ops/deploy-keys.toml".to_owned(),
                ]
            ),
            RequiredInputDecision::RunLocally
        );
        // Without the withheld input, remote eligibility returns.
        assert_eq!(
            required_input_decision(&acl, &["/__rabs/workspace/src/lib.rs".to_owned()]),
            RequiredInputDecision::RemoteEligible
        );
    }

    #[test]
    fn secret_paths_cross_only_as_slot_references() {
        // Structural: the secret path's admitted entry carries a slot
        // name; the ObjectBytes arm is a DIFFERENT variant, and there
        // is no variant carrying both a secret path and bytes.
        let plan = authorize_uploads(&acl(), &["/__rabs/workspace/.cargo/credentials".to_owned()]);
        match &plan.admitted[0] {
            UploadEntry::SlotReference { slot, .. } => {
                assert_eq!(slot, "cargo-registry-token");
            }
            UploadEntry::ObjectBytes { .. } => panic!("secret bytes must never upload"),
        }
    }
}
