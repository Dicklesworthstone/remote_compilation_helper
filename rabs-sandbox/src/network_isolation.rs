//! Default-deny network namespace policy (beads E002/E025; plan §186 and
//! §82.1; couples to S003's capability tokens).
//!
//! The D003 launcher already compiles network default-deny into the
//! canonical namespace argv (`--unshare-net` whenever the spec does not
//! explicitly allow the network; see [`crate::canonical_namespace`]). This
//! module completes E002 around that enforcement:
//!
//! - **The gate.** A fetch may reach the network only through an explicit,
//!   currently-valid `CapabilityKind::OpenNetwork` token minted for exactly
//!   this session/operation ([`evaluate_open_network`]; zero or several
//!   valid grants refuse — one grant is least privilege). The grant is
//!   opaque outside this module and its redaction-safe scope MUST equal the
//!   digest of an exact [`BoundedNetworkPolicy`].
//! - **The enforcement.** [`prepare_brokered_fetch`] asks a trusted broker
//!   to install the exact authority, redirect, request, and byte bounds and
//!   exposes only a controlled inherited-FD or Unix-socket channel. The
//!   Cargo namespace RETAINS `--unshare-net`; DNS and remote sockets remain
//!   broker-owned. The returned lease owns the broker guard and must live
//!   through the fetch process. Failure leaves the spec closed.
//!   `allow_network` is crate-private and ordinary mount plans are always
//!   closed, so there is no public ambient-open bypass.
//!   Per-action build views stay closed unconditionally (plan §36: fetching
//!   is its own action; the build action never sees the wire).
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
use sha2::{Digest, Sha256};

/// Domain for the redaction-safe digest carried in an `OpenNetwork`
/// capability scope. The scope contains no URL, credential, or response
/// metadata: those facts stay in the policy/receipt available only to the
/// trusted fetch orchestration lane.
pub const BOUNDED_NETWORK_SCOPE_DOMAIN: &str = "rabs.bounded-network-scope.sha256.v1";

/// Network protocol admitted by a bounded fetch policy. Plain HTTP is
/// intentionally absent: registry/index/source acquisition must not
/// downgrade transport confidentiality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkScheme {
    /// TLS-protected HTTP.
    Https,
}

impl NetworkScheme {
    const fn tag(self) -> u8 {
        match self {
            Self::Https => 1,
        }
    }
}

/// One canonical destination authority. The host is either canonical
/// lowercase DNS or the canonical textual spelling of an IP address; a
/// trailing dot, userinfo, path, query, fragment, or non-ASCII/IDNA spelling
/// is refused instead of being normalized ambiguously.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetworkAuthority {
    scheme: NetworkScheme,
    host: String,
    port: u16,
}

impl NetworkAuthority {
    /// Validate and construct one exact authority.
    ///
    /// # Errors
    /// [`BoundedNetworkPolicyRefusal::InvalidAuthority`] when `host` is not
    /// already canonical or `port` is zero.
    pub fn new(
        scheme: NetworkScheme,
        host: impl Into<String>,
        port: u16,
    ) -> Result<Self, BoundedNetworkPolicyRefusal> {
        let host = host.into();
        if port == 0 || !canonical_host(&host) {
            return Err(BoundedNetworkPolicyRefusal::InvalidAuthority { host, port });
        }
        Ok(Self { scheme, host, port })
    }

    /// Transport protocol.
    #[must_use]
    pub const fn scheme(&self) -> NetworkScheme {
        self.scheme
    }

    /// Canonical DNS/IP host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Exact destination port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Request/response bounds enforced across one fetch-resolution operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkBudget {
    /// Total outbound requests, redirects included.
    pub max_requests: u32,
    /// Maximum redirects followed across all requests.
    pub max_redirects: u32,
    /// Total accepted response-body bytes.
    pub max_response_bytes: u64,
}

/// Exact egress declaration bound into an `OpenNetwork` token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedNetworkPolicy {
    authorities: Vec<NetworkAuthority>,
    budget: NetworkBudget,
}

/// Typed policy construction/open refusals. Every arm leaves the namespace
/// closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedNetworkPolicyRefusal {
    /// At least one destination is required.
    NoAuthorities,
    /// Two equal authorities make the declaration non-canonical.
    DuplicateAuthority(NetworkAuthority),
    /// Host/port spelling is not an exact safe authority.
    InvalidAuthority {
        /// Rejected host spelling.
        host: String,
        /// Rejected port.
        port: u16,
    },
    /// Every request/byte budget must be nonzero.
    ZeroBudget(&'static str),
    /// The token authorizes a different declaration.
    ScopeMismatch {
        /// Binding expected from the policy.
        expected: String,
        /// Binding carried by the validated grant.
        presented: String,
    },
    /// The trusted platform adapter could not install enforcement.
    EnforcementUnavailable(String),
    /// An empty enforcement mechanism would be unauditable.
    EnforcementMechanismMissing,
    /// A broker channel could expose ambient descriptors/paths.
    InvalidBrokerChannel,
    /// Brokered fetches must retain the closed network namespace.
    CanonicalNetworkMustRemainClosed,
}

impl BoundedNetworkPolicy {
    /// Build a canonical sorted, duplicate-free policy.
    ///
    /// # Errors
    /// A typed refusal for an empty/duplicate authority set or zero bound.
    pub fn new(
        mut authorities: Vec<NetworkAuthority>,
        budget: NetworkBudget,
    ) -> Result<Self, BoundedNetworkPolicyRefusal> {
        if authorities.is_empty() {
            return Err(BoundedNetworkPolicyRefusal::NoAuthorities);
        }
        if budget.max_requests == 0 {
            return Err(BoundedNetworkPolicyRefusal::ZeroBudget("max_requests"));
        }
        if budget.max_response_bytes == 0 {
            return Err(BoundedNetworkPolicyRefusal::ZeroBudget(
                "max_response_bytes",
            ));
        }
        authorities.sort();
        if let Some(duplicate) = authorities
            .windows(2)
            .find_map(|pair| (pair[0] == pair[1]).then(|| pair[0].clone()))
        {
            return Err(BoundedNetworkPolicyRefusal::DuplicateAuthority(duplicate));
        }
        Ok(Self {
            authorities,
            budget,
        })
    }

    /// Canonical authorities supplied to the enforcer.
    #[must_use]
    pub fn authorities(&self) -> &[NetworkAuthority] {
        &self.authorities
    }

    /// Request/redirect/body bounds supplied to the enforcer.
    #[must_use]
    pub const fn budget(&self) -> NetworkBudget {
        self.budget
    }

    /// Redaction-safe capability scope binding for this exact policy.
    #[must_use]
    pub fn scope_binding(&self) -> String {
        let mut framed = Vec::new();
        framed.extend_from_slice(&(self.authorities.len() as u64).to_le_bytes());
        for authority in &self.authorities {
            framed.push(authority.scheme.tag());
            framed.extend_from_slice(&(authority.host.len() as u64).to_le_bytes());
            framed.extend_from_slice(authority.host.as_bytes());
            framed.extend_from_slice(&authority.port.to_le_bytes());
        }
        framed.extend_from_slice(&self.budget.max_requests.to_le_bytes());
        framed.extend_from_slice(&self.budget.max_redirects.to_le_bytes());
        framed.extend_from_slice(&self.budget.max_response_bytes.to_le_bytes());

        let mut hasher = Sha256::new();
        hasher.update(BOUNDED_NETWORK_SCOPE_DOMAIN.as_bytes());
        hasher.update([0]);
        hasher.update((framed.len() as u64).to_le_bytes());
        hasher.update(framed);
        let digest = hasher.finalize();
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("{BOUNDED_NETWORK_SCOPE_DOMAIN}:{hex}")
    }
}

/// The only channel a fetch subprocess may use to reach the trusted broker.
/// Arbitrary inherited descriptors and filesystem paths are deliberately
/// not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerChannel {
    /// Explicitly inherited descriptor (standard streams are forbidden).
    InheritedFd(u32),
    /// Unix socket under the fixed broker directory.
    ControlledSocket(RawBytes),
}

impl BrokerChannel {
    /// Validate one controlled channel.
    ///
    /// # Errors
    /// [`BoundedNetworkPolicyRefusal::InvalidBrokerChannel`] for a standard
    /// descriptor or a noncanonical/non-broker socket path.
    pub fn validate(&self) -> Result<(), BoundedNetworkPolicyRefusal> {
        match self {
            Self::InheritedFd(fd) if *fd >= 3 => Ok(()),
            Self::ControlledSocket(path) => {
                let bytes = path.as_bytes();
                if bytes.starts_with(b"/run/rabs-broker/") && canonical_absolute_path(bytes) {
                    Ok(())
                } else {
                    Err(BoundedNetworkPolicyRefusal::InvalidBrokerChannel)
                }
            }
            Self::InheritedFd(_) => Err(BoundedNetworkPolicyRefusal::InvalidBrokerChannel),
        }
    }
}

/// Trusted platform boundary that installs and owns a fetch broker.
/// Implementations must enforce the exact policy for the lifetime of the
/// returned guard, including URL normalization, redirects, DNS answers,
/// proxy use, request count, and accepted response bytes. The broker, not
/// the sandboxed Cargo process, owns DNS and remote sockets. Returning
/// success without doing so is a privileged-adapter integrity bug.
pub trait BoundedFetchBroker {
    /// Guard whose lifetime owns the broker policy and channel.
    type Guard;

    /// Attach the exact policy to the controlled subprocess channel.
    fn attach(
        &mut self,
        policy: &BoundedNetworkPolicy,
        channel: &BrokerChannel,
    ) -> Result<Self::Guard, String>;

    /// Stable audit name of the concrete enforcement mechanism.
    fn mechanism(&self) -> &'static str;
}

/// Honest record of the broker bounds installed while the fetch namespace
/// itself remained network-isolated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedNetworkReceipt {
    /// Exercised capability token.
    pub token_id: u64,
    /// Exact redaction-safe policy binding.
    pub scope_binding: String,
    /// Canonical destinations actually installed.
    pub authorities: Vec<NetworkAuthority>,
    /// Installed request/redirect/body budgets.
    pub budget: NetworkBudget,
    /// Trusted adapter mechanism.
    pub mechanism: &'static str,
    /// Controlled channel presented to the fetch subprocess.
    pub channel: BrokerChannel,
}

/// Broker lifetime token. Callers must retain this value until the
/// fetch process and all descendants have exited; dropping it releases the
/// broker guard.
#[derive(Debug)]
pub struct BrokeredFetchLease<G> {
    guard: G,
    receipt: BoundedNetworkReceipt,
}

impl<G> BrokeredFetchLease<G> {
    /// Enforcement receipt for provenance.
    #[must_use]
    pub const fn receipt(&self) -> &BoundedNetworkReceipt {
        &self.receipt
    }

    /// Borrow the installed guard, primarily for lifecycle integration.
    #[must_use]
    pub const fn guard(&self) -> &G {
        &self.guard
    }
}

/// One validated permission to exercise the bounded fetch broker. Produced
/// only by [`evaluate_open_network`] from a token that validated for THIS
/// session and operation. Its fields are intentionally opaque: callers can
/// inspect but cannot fabricate a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkGrant {
    token_id: u64,
    scope: String,
}

impl NetworkGrant {
    /// Exercised token id for receipts.
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token_id
    }

    /// Redaction-safe bounded-policy binding carried by the token.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
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
    /// The same issuer-assigned token id was presented with different
    /// fields. Treating either presentation as authoritative would make
    /// the audit trail ambiguous.
    ConflictingTokenPresentations {
        /// Conflicting issuer-assigned id.
        token_id: u64,
    },
}

/// Evaluate whether the caller may exercise the bounded fetch broker. Pure:
/// token validation only — no processes, no namespace mutation. Bind a
/// returned grant to an exact policy with [`prepare_brokered_fetch`].
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
    // Duplicate presentation of byte-for-byte the SAME token is one grant.
    // Reusing one id with a changed scope/context/lease is an issuer/audit
    // conflict and refuses before any candidate can win by input order.
    let mut by_id = std::collections::BTreeMap::new();
    for token in tokens
        .iter()
        .filter(|token| token.kind == CapabilityKind::OpenNetwork)
    {
        if let Some(prior) = by_id.insert(token.token_id, token) {
            if prior != token {
                return Err(NetworkGateRefusal::ConflictingTokenPresentations {
                    token_id: token.token_id,
                });
            }
        }
    }
    let candidates: Vec<&CapabilityToken> = by_id.into_values().collect();
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

/// Bind a validated grant to an exact policy and attach a trusted broker to
/// a controlled subprocess channel. The canonical namespace MUST still be
/// closed: Cargo gets the broker channel, never an ambient route or DNS.
/// The returned lease owns the broker guard and must outlive the fetch.
///
/// # Errors
/// A typed policy refusal. The namespace is never mutated by this function.
pub fn prepare_brokered_fetch<B: BoundedFetchBroker>(
    spec: &CanonicalNamespaceSpec,
    grant: &NetworkGrant,
    policy: &BoundedNetworkPolicy,
    channel: BrokerChannel,
    broker: &mut B,
) -> Result<BrokeredFetchLease<B::Guard>, BoundedNetworkPolicyRefusal> {
    if spec.allow_network {
        return Err(BoundedNetworkPolicyRefusal::CanonicalNetworkMustRemainClosed);
    }
    channel.validate()?;
    let expected = policy.scope_binding();
    if grant.scope != expected {
        return Err(BoundedNetworkPolicyRefusal::ScopeMismatch {
            expected,
            presented: grant.scope.clone(),
        });
    }
    let mechanism = broker.mechanism();
    if mechanism.is_empty() {
        return Err(BoundedNetworkPolicyRefusal::EnforcementMechanismMissing);
    }
    let guard = broker
        .attach(policy, &channel)
        .map_err(BoundedNetworkPolicyRefusal::EnforcementUnavailable)?;
    Ok(BrokeredFetchLease {
        guard,
        receipt: BoundedNetworkReceipt {
            token_id: grant.token_id,
            scope_binding: expected,
            authorities: policy.authorities.clone(),
            budget: policy.budget,
            mechanism,
            channel,
        },
    })
}

fn canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.to_string() == host;
    }
    if host != host.to_ascii_lowercase() || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn canonical_absolute_path(path: &[u8]) -> bool {
    path.first() == Some(&b'/')
        && path.last() != Some(&b'/')
        && !path.contains(&0)
        && path
            .split(|byte| *byte == b'/')
            .skip(1)
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
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

    fn fetch_policy() -> BoundedNetworkPolicy {
        BoundedNetworkPolicy::new(
            vec![
                NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap(),
                NetworkAuthority::new(NetworkScheme::Https, "static.crates.io", 443).unwrap(),
            ],
            NetworkBudget {
                max_requests: 32,
                max_redirects: 4,
                max_response_bytes: 8 * 1024 * 1024,
            },
        )
        .unwrap()
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FakeBrokerGuard;

    struct FakeBroker {
        fail: bool,
        seen: Option<(BoundedNetworkPolicy, BrokerChannel)>,
        mechanism: &'static str,
    }

    impl BoundedFetchBroker for FakeBroker {
        type Guard = FakeBrokerGuard;

        fn attach(
            &mut self,
            policy: &BoundedNetworkPolicy,
            channel: &BrokerChannel,
        ) -> Result<Self::Guard, String> {
            self.seen = Some((policy.clone(), channel.clone()));
            if self.fail {
                Err("broker unavailable".into())
            } else {
                Ok(FakeBrokerGuard)
            }
        }

        fn mechanism(&self) -> &'static str {
            self.mechanism
        }
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
        assert_eq!(grant.token_id(), 7);
        assert_eq!(grant.scope(), "crates.io:443");
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
        assert_eq!(grant.token_id(), 1);
    }

    #[test]
    fn same_token_id_with_different_scope_refuses() {
        let a = open_token(1, 5, 9, "scope-a");
        let b = open_token(1, 5, 9, "scope-b");
        assert_eq!(
            evaluate_open_network(&[a, b], &[], 10, 5, 9),
            Err(NetworkGateRefusal::ConflictingTokenPresentations { token_id: 1 })
        );
    }

    #[test]
    fn brokered_fetch_keeps_namespace_closed_and_records_exact_bounds() {
        let mut spec = CanonicalNamespaceSpec::new();
        spec.rw_binds
            .push(Bind::new("/data/rabs/ws", layout::WORKSPACE));
        let policy = fetch_policy();
        let token = open_token(7, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        let channel = BrokerChannel::InheritedFd(7);
        let mut broker = FakeBroker {
            fail: false,
            seen: None,
            mechanism: "edge-fetch-broker-v1",
        };
        let lease = prepare_brokered_fetch(&spec, &grant, &policy, channel.clone(), &mut broker)
            .expect("exact bounded broker policy attaches");

        let launch = build_canonical_argv(&spec, &full_support(), "cargo", &["fetch".into()])
            .expect("spec builds");
        let argv: Vec<String> = launch
            .argv
            .iter()
            .map(|a| a.to_string_lossy().into())
            .collect();
        assert!(argv.iter().any(|a| a == "--unshare-net"));
        assert!(launch.boundary.satisfies_strict_hermetic_linux());

        let record = boundary_isolation_evidence(&launch.boundary);
        assert!(record.fully_enforced());
        assert_eq!(lease.receipt().token_id, 7);
        assert_eq!(lease.receipt().scope_binding, policy.scope_binding());
        assert_eq!(lease.receipt().channel, channel);
        assert_eq!(lease.receipt().mechanism, "edge-fetch-broker-v1");
        assert_eq!(broker.seen, Some((policy, BrokerChannel::InheritedFd(7))));
    }

    #[test]
    fn scope_mismatch_or_broker_failure_never_widens_network() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();
        let wrong = open_token(7, 5, 9, "rabs.bounded-network-scope.sha256.v1:wrong");
        let grant = evaluate_open_network(&[wrong], &[], 10, 5, 9).unwrap();
        let mut broker = FakeBroker {
            fail: false,
            seen: None,
            mechanism: "edge-fetch-broker-v1",
        };
        assert!(matches!(
            prepare_brokered_fetch(
                &spec,
                &grant,
                &policy,
                BrokerChannel::InheritedFd(7),
                &mut broker,
            ),
            Err(BoundedNetworkPolicyRefusal::ScopeMismatch { .. })
        ));
        assert!(broker.seen.is_none(), "mismatch refuses before broker use");

        let token = open_token(8, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        broker.fail = true;
        assert!(matches!(
            prepare_brokered_fetch(
                &spec,
                &grant,
                &policy,
                BrokerChannel::InheritedFd(7),
                &mut broker,
            ),
            Err(BoundedNetworkPolicyRefusal::EnforcementUnavailable(_))
        ));
        assert!(!spec.allow_network);
    }

    #[test]
    fn authorities_budgets_and_broker_channels_are_canonical() {
        for bad in [
            "Crates.io",
            "crates.io.",
            "user@crates.io",
            "crates.io/path",
            "xn--caf-dma.example.",
        ] {
            assert!(NetworkAuthority::new(NetworkScheme::Https, bad, 443).is_err());
        }
        assert!(NetworkAuthority::new(NetworkScheme::Https, "127.0.0.1", 443).is_ok());
        assert!(NetworkAuthority::new(NetworkScheme::Https, "2001:db8::1", 443).is_ok());
        assert!(matches!(
            BoundedNetworkPolicy::new(
                vec![NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap()],
                NetworkBudget {
                    max_requests: 0,
                    max_redirects: 0,
                    max_response_bytes: 1,
                },
            ),
            Err(BoundedNetworkPolicyRefusal::ZeroBudget("max_requests"))
        ));
        assert!(BrokerChannel::InheritedFd(2).validate().is_err());
        assert!(
            BrokerChannel::ControlledSocket(RawBytes::from("/run/rabs-broker/fetch.sock"))
                .validate()
                .is_ok()
        );
        assert!(
            BrokerChannel::ControlledSocket(RawBytes::from("/tmp/fetch.sock"))
                .validate()
                .is_err()
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
