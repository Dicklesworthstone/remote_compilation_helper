//! Default-deny network namespace policy (bead E002; plan §186; couples to
//! plan §36's captured-fetch lane and S003's capability tokens).
//!
//! The D003 launcher already compiles network default-deny into the
//! canonical namespace argv (`--unshare-net` whenever the spec does not
//! explicitly allow the network; see [`crate::canonical_namespace`]). This
//! module completes E002 around that enforcement:
//!
//! - **The gate.** A namespace opens the network only through an explicit,
//!   currently-valid `CapabilityKind::OpenNetwork` token minted for exactly
//!   this session/operation ([`evaluate_open_network`]; zero or several
//!   valid grants refuse — one grant is least privilege). Applying the
//!   grant through [`apply_open_grant`] is the only production caller path
//!   to `CanonicalNamespaceSpec::allow_network == true` TODAY. It is a
//!   convention, not a type-level lock: `CanonicalNamespaceSpec::
//!   allow_network` and `CanonicalMountPlan::allow_network` stay `pub`
//!   until the fetch-lane bead wires the gate in, so a future caller could
//!   open the lane without this gate — any such open still produces honest
//!   evidence (`NotEnforced { open-network-capability }`, profile
//!   `host-sandbox-audit`), never a false record. Per-action closed views
//!   stay closed unconditionally (plan §36: fetching is its own action;
//!   the build action never sees the wire).
//! - **The record.** Every constructed launch derives its
//!   [`IsolationEvidenceRecord`] from what the argv ACTUALLY enforces
//!   ([`boundary_isolation_evidence`]) — enforcement facts per control,
//!   never aspiration (E010's schema).
//! - **The observation.** A network attempt inside a default-deny hermetic
//!   action is recorded as the observation fact it is
//!   ([`denied_attempt_observation`]) and classifies
//!   [`EffectClass::NetworkSensitive`] — never `Hermetic`.
//!
//! Attempt DETECTION (the syscall tracer that notices an attempted
//! connect) is E005/E009 scope; this module fixes the shape of the fact
//! those observers will produce and proves the denial end to end in
//! `tests/network_namespace_linux.rs`.

use crate::canonical_namespace::{CanonicalNamespaceSpec, NamespaceBoundary};
use rabs_protocol::capability_tokens::{self, CapabilityKind, CapabilityToken};
use rabs_protocol::input_evidence::{
    EnforcementState, INPUT_EVIDENCE_SCHEMA_VERSION, IsolationEvidenceRecord,
};
use rabs_protocol::raw_bytes::RawBytes;
use rabs_protocol::volatility::ObservedEffects;

/// One validated permission to open the network inside a canonical
/// namespace. Produced only by [`evaluate_open_network`] from a token that
/// validated for THIS session and operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkGrant {
    /// The exercised token (audit trail ties the open lane to its lease).
    pub token_id: u64,
    /// The declared endpoint scope carried by the token (e.g. an allow
    /// list entry such as `"crates.io:443"`); never the fetched bytes.
    pub scope: String,
}

/// Typed refusals from the network gate. Every refusal means: the
/// namespace STAYS default-deny — a refused open is never silently
/// degraded into an ambient-network run nor into a fabricated success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkGateRefusal {
    /// No `OpenNetwork` capability was presented: plain default-deny (the
    /// ordinary hermetic case, not an error condition for callers that
    /// never asked to open).
    NoOpenNetworkToken,
    /// An `OpenNetwork` token was presented but does not validate for this
    /// context (revoked, expired, wrong session/operation). Surfaced when
    /// it decides the outcome (no valid grant exists); alongside a valid
    /// grant the exercised-token receipt carries the audit trail instead.
    TokenInvalid {
        /// The failing token.
        token_id: u64,
        /// Why validation failed (typed refusal rendered).
        reason: String,
    },
    /// Several DISTINCT valid grants apply to this exact context. Least
    /// privilege demands exactly one explicit endpoint scope; ambiguity is
    /// a coordinator bug and refuses rather than guessing.
    AmbiguousOpenNetworkGrants {
        /// The competing valid token ids.
        valid_token_ids: Vec<u64>,
    },
}

/// Evaluate whether the caller may open the network inside the canonical
/// namespace. Pure: token validation only — no processes, no spec
/// mutation. Apply a returned grant with [`apply_open_grant`].
///
/// # Errors
/// [`NetworkGateRefusal`] as documented: no token, an invalid token, or an
/// ambiguous set of valid tokens.
pub fn evaluate_open_network(
    tokens: &[CapabilityToken],
    revoked_token_ids: &[u64],
    current_seq: u64,
    session_id: u64,
    operation_id: u64,
) -> Result<NetworkGrant, NetworkGateRefusal> {
    // Duplicate presentation of the SAME token is one grant, not
    // ambiguity: dedupe by issuer-assigned id before counting.
    let mut seen = std::collections::HashSet::new();
    let candidates: Vec<&CapabilityToken> = tokens
        .iter()
        .filter(|t| t.kind == CapabilityKind::OpenNetwork)
        .filter(|t| seen.insert(t.token_id))
        .collect();
    let mut valid: Vec<&CapabilityToken> = Vec::new();
    let mut invalid: Option<NetworkGateRefusal> = None;
    for token in &candidates {
        match capability_tokens::validate(
            token,
            revoked_token_ids,
            current_seq,
            session_id,
            operation_id,
        ) {
            Ok(()) => valid.push(token),
            // First invalid token wins the record: one honest refusal
            // beats a pile of duplicated diagnostics.
            Err(err) => {
                if invalid.is_none() {
                    invalid.replace(NetworkGateRefusal::TokenInvalid {
                        token_id: token.token_id,
                        reason: format!("{err:?}"),
                    });
                }
            }
        }
    }

    // Zero valid grants fall back to the typed record of WHY (an invalid
    // presented token is never silently swallowed); one valid grant opens
    // under least privilege; several refuse as a coordinator bug.
    match valid.as_slice() {
        [] => Err(invalid.unwrap_or(NetworkGateRefusal::NoOpenNetworkToken)),
        [token] => Ok(NetworkGrant {
            token_id: token.token_id,
            scope: token.scope.clone(),
        }),
        _ => Err(NetworkGateRefusal::AmbiguousOpenNetworkGrants {
            valid_token_ids: valid.iter().map(|t| t.token_id).collect(),
        }),
    }
}

/// Apply a granted open to the namespace spec. The only production caller
/// path to `allow_network == true` today (a convention, not a type-level
/// lock — see the module header). The strict-hermetic boundary honestly
/// stops being satisfiable afterwards, and [`boundary_isolation_evidence`]
/// records the open as a `NotEnforced` control rather than hiding it.
///
/// Per-action closed views (`build_action_view_argv`) ignore this flag by
/// construction — plan §36 keeps the fetch action separate from the build
/// action.
pub fn apply_open_grant(spec: &mut CanonicalNamespaceSpec, grant: &NetworkGrant) {
    let _ = grant; // Provenance only: possession of a grant IS the authority.
    spec.allow_network = true;
}

/// Derive the E010 isolation-evidence record from a constructed launch's
/// boundary. Every control states what the argv ENFORCED (`Enforced` with
/// the mechanism) or failed to enforce (`NotEnforced` with why) — the
/// record is derived from emitted facts, never asserted independently of
/// them.
///
/// The documented `host_usr_ro` softness is deliberately NOT a control
/// row: it is an enforced read-only bind and a named exception of the
/// strict-hermetic profile, already reflected in
/// [`NamespaceBoundary::satisfies_strict_hermetic_linux`].
#[must_use]
pub fn boundary_isolation_evidence(boundary: &NamespaceBoundary) -> IsolationEvidenceRecord {
    let enforced = |mechanism| EnforcementState::Enforced { mechanism };
    let controls = vec![
        (
            RawBytes::from("network-deny"),
            if boundary.net_isolated {
                EnforcementState::Enforced { mechanism: "netns" }
            } else {
                EnforcementState::NotEnforced {
                    reason: "open-network-capability",
                }
            },
        ),
        (
            RawBytes::from("user-namespaces"),
            if boundary.user_ns {
                enforced("user-ns")
            } else {
                EnforcementState::NotEnforced {
                    reason: "host-lacks-unprivileged-userns",
                }
            },
        ),
        (
            RawBytes::from("pid-namespace"),
            if boundary.pid_ns {
                enforced("pid-ns")
            } else {
                EnforcementState::NotEnforced {
                    reason: "shared-pid-space",
                }
            },
        ),
        (
            RawBytes::from("ipc-namespace"),
            if boundary.ipc_ns {
                enforced("ipc-ns")
            } else {
                EnforcementState::NotEnforced {
                    reason: "shared-ipc-space",
                }
            },
        ),
        (
            RawBytes::from("uts-hostname"),
            if boundary.uts_hostname.is_some() {
                enforced("uts-ns")
            } else {
                EnforcementState::NotEnforced {
                    reason: "host-hostname-visible",
                }
            },
        ),
        (
            RawBytes::from("closed-mount-view"),
            if boundary.mounts_closed_view {
                enforced("bubblewrap-binds")
            } else {
                EnforcementState::NotEnforced {
                    reason: "open-mount-view",
                }
            },
        ),
        (
            RawBytes::from("explicit-environment"),
            if boundary.clearenv {
                enforced("clearenv")
            } else {
                EnforcementState::NotEnforced {
                    reason: "ambient-env",
                }
            },
        ),
        (
            RawBytes::from("private-tmpfs"),
            if boundary.tmpfs_tmp {
                enforced("tmpfs")
            } else {
                EnforcementState::NotEnforced {
                    reason: "shared-temp",
                }
            },
        ),
        (
            RawBytes::from("private-procfs"),
            if boundary.proc_private {
                enforced("procfs")
            } else {
                EnforcementState::NotEnforced {
                    reason: "host-procfs",
                }
            },
        ),
        (
            RawBytes::from("die-with-parent"),
            if boundary.die_with_parent {
                enforced("prctl-pdeathsig")
            } else {
                EnforcementState::NotEnforced {
                    reason: "orphans-possible",
                }
            },
        ),
    ];
    let requested_profile = if boundary.satisfies_strict_hermetic_linux() {
        "strict-hermetic-linux"
    } else {
        "host-sandbox-audit"
    };
    IsolationEvidenceRecord {
        schema_version: INPUT_EVIDENCE_SCHEMA_VERSION,
        requested_profile: RawBytes::from(requested_profile),
        controls,
    }
}

/// Record a network attempt inside a default-deny hermetic action.
///
/// Contract: call ONLY when an observer actually saw the attempt (the
/// E002 acceptance probe, or an E005/E009 tracer once those land). Under
/// `--unshare-net` an observed attempt NECESSARILY failed — the kernel has
/// no route — so the fact is recorded with complete coverage of the
/// network axis. Classification through
/// [`rabs_protocol::volatility::classify`] is therefore
/// [`EffectClass::NetworkSensitive`]: one denied attempt makes the action
/// network-sensitive for shareability purposes, never silently `Hermetic`.
#[must_use]
pub fn denied_attempt_observation() -> ObservedEffects {
    ObservedEffects {
        observation_complete: true,
        touched_network: true,
        ..ObservedEffects::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_namespace::{Bind, HostIsolationSupport, build_canonical_argv};
    use crate::layout;
    use rabs_protocol::volatility::EffectClass;

    fn full_support() -> HostIsolationSupport {
        HostIsolationSupport {
            bubblewrap: Some("bubblewrap 0.11.1".into()),
            unprivileged_userns: true,
            overlayfs: true,
            cgroup_v2: true,
            landlock: true,
        }
    }

    fn open_token(token_id: u64, session: u64, operation: u64, scope: &str) -> CapabilityToken {
        capability_tokens::mint(
            token_id,
            CapabilityKind::OpenNetwork,
            session,
            operation,
            scope,
            100,
        )
        .expect("scope non-empty")
    }

    #[test]
    fn gate_refuses_when_no_token_presented() {
        let err = evaluate_open_network(&[], &[], 10, 1, 1).expect_err("must refuse");
        assert_eq!(err, NetworkGateRefusal::NoOpenNetworkToken);
    }

    #[test]
    fn gate_ignores_non_network_tokens_entirely() {
        let seed = capability_tokens::mint(
            1,
            CapabilityKind::MaterializeSnapshot,
            1,
            1,
            "staging-prefix",
            100,
        )
        .unwrap();
        let err = evaluate_open_network(std::slice::from_ref(&seed), &[], 10, 1, 1)
            .expect_err("a MaterializeSnapshot token cannot open the network");
        assert_eq!(err, NetworkGateRefusal::NoOpenNetworkToken);
    }

    #[test]
    fn gate_records_invalid_token_instead_of_silently_denying() {
        let stale = open_token(9, 1, 1, "crates.io:443");
        // Lease expired: current_seq beyond expires_seq.
        let err = evaluate_open_network(std::slice::from_ref(&stale), &[], 200, 1, 1)
            .expect_err("expired token must be a typed refusal");
        match err {
            NetworkGateRefusal::TokenInvalid { token_id, .. } => assert_eq!(token_id, 9),
            other => panic!("expected TokenInvalid, got {other:?}"),
        }
    }

    #[test]
    fn gate_grants_exactly_one_valid_token_with_scope() {
        let token = open_token(7, 5, 9, "crates.io:443");
        let grant = evaluate_open_network(std::slice::from_ref(&token), &[], 10, 5, 9).unwrap();
        assert_eq!(grant.token_id, 7);
        assert_eq!(grant.scope, "crates.io:443");
    }

    #[test]
    fn gate_refuses_token_minted_for_another_operation() {
        let token = open_token(7, 5, 9, "crates.io:443");
        let err = evaluate_open_network(std::slice::from_ref(&token), &[], 10, 5, 12)
            .expect_err("token bound to operation 9 refuses in operation 12");
        assert!(matches!(err, NetworkGateRefusal::TokenInvalid { .. }));
    }

    #[test]
    fn gate_refuses_ambiguous_valid_grants() {
        let a = open_token(1, 5, 9, "crates.io:443");
        let b = open_token(2, 5, 9, "static.crates.io:443");
        let err =
            evaluate_open_network(&[a, b], &[], 10, 5, 9).expect_err("two valid grants refuse");
        match err {
            NetworkGateRefusal::AmbiguousOpenNetworkGrants { valid_token_ids } => {
                assert_eq!(valid_token_ids, vec![1, 2]);
            }
            other => panic!("expected ambiguity, got {other:?}"),
        }
    }

    #[test]
    fn gate_treats_duplicate_presentation_of_one_token_as_one_grant() {
        let a = open_token(1, 5, 9, "crates.io:443");
        let a_again = open_token(1, 5, 9, "crates.io:443");
        let grant = evaluate_open_network(&[a.clone(), a_again], &[], 10, 5, 9)
            .expect("the same token twice is one grant, not ambiguity");
        assert_eq!(grant.token_id, 1);
    }

    #[test]
    fn applied_grant_is_the_only_path_to_an_open_argv() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds
            .push(Bind::new("/data/rabs/ws", layout::WORKSPACE));
        let grant = NetworkGrant {
            token_id: 7,
            scope: "crates.io:443".into(),
        };
        apply_open_grant(&mut spec, &grant);

        let launch = build_canonical_argv(&spec, &full_support(), "cargo", &["fetch".into()])
            .expect("spec builds");
        let argv: Vec<String> = launch
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into())
            .collect();
        assert!(!argv.iter().any(|a| a == "--unshare-net"), "lane is open");
        assert!(!launch.boundary.satisfies_strict_hermetic_linux());

        let record = boundary_isolation_evidence(&launch.boundary);
        assert!(
            !record.fully_enforced(),
            "an open lane is not fully enforced"
        );
        let network = record
            .controls
            .iter()
            .find(|(name, _)| name.as_utf8() == Some("network-deny"))
            .expect("network control present");
        assert_eq!(
            network.1,
            EnforcementState::NotEnforced {
                reason: "open-network-capability"
            }
        );
        assert_eq!(
            record.requested_profile.as_utf8(),
            Some("host-sandbox-audit")
        );
    }

    #[test]
    fn default_spec_stays_deny_and_evidence_fully_enforced() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds
            .push(Bind::new("/data/rabs/ws", layout::WORKSPACE));
        let launch = build_canonical_argv(&spec, &full_support(), "cargo", &["build".into()])
            .expect("spec builds");
        let argv: Vec<String> = launch
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into())
            .collect();
        assert!(argv.contains(&"--unshare-net".to_string()));
        assert!(launch.boundary.net_isolated);
        assert!(launch.boundary.satisfies_strict_hermetic_linux());

        let record = boundary_isolation_evidence(&launch.boundary);
        assert!(record.fully_enforced());
        assert_eq!(
            record.requested_profile.as_utf8(),
            Some("strict-hermetic-linux")
        );
        let network = &record.controls[0];
        assert_eq!(network.0.as_utf8(), Some("network-deny"));
        assert_eq!(network.1, EnforcementState::Enforced { mechanism: "netns" });
    }

    #[test]
    fn denied_attempt_classifies_network_sensitive() {
        let effects = denied_attempt_observation();
        assert_eq!(
            EffectClass::NetworkSensitive,
            rabs_protocol::volatility::classify(&effects)
        );
        // And the negative control: without the fact, clean effects stay Hermetic.
        let clean = ObservedEffects {
            observation_complete: true,
            ..ObservedEffects::default()
        };
        assert_eq!(
            EffectClass::Hermetic,
            rabs_protocol::volatility::classify(&clean)
        );
    }
}
