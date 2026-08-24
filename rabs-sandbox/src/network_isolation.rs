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
//! - **The enforcement.** [`prepare_brokered_fetch`] asks a trusted EDGE
//!   adapter to install the exact authority, redirect, request, and byte
//!   bounds over a controlled inherited-FD or Unix-socket channel. Cargo is
//!   not running in this phase; its later namespace RETAINS `--unshare-net`
//!   and never receives the channel. DNS and remote sockets remain
//!   broker-owned. [`finish_brokered_fetch`] consumes the one-shot lease,
//!   revalidates capability authority, checks the broker's observations,
//!   and only then issues an opaque receipt. Failure leaves the spec closed.
//!   `allow_network` is private to the namespace module and ordinary mount plans are always
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
    /// The operation-bound capability stopped being valid before the
    /// brokered phase completed.
    GrantNoLongerValid(String),
    /// The authoritative capability ledger could not be consulted after the
    /// broker lane stopped.
    AuthorityStateUnavailable(String),
    /// The broker reported an authority outside the exact allowlist.
    ObservedAuthorityOutsidePolicy(NetworkAuthority),
    /// The broker's observed counters exceeded an installed bound or were
    /// internally inconsistent.
    ObservedBudgetInvalid(&'static str),
    /// A network-required broker phase completed without one observed
    /// request; that cannot prove acquisition happened.
    NoRequestsObserved,
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

/// The only channel the trusted EDGE fetch adapter may use to reach its
/// broker. This channel is never handed to Cargo: Cargo remains stopped
/// until acquisition has completed and its captured inputs can be replayed
/// with physical network denial. Arbitrary inherited descriptors and
/// filesystem paths are deliberately not accepted.
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

/// Operation/lease context supplied to the trusted broker. The broker must
/// stop accepting work no later than `expires_seq`; the coordinator also
/// revalidates revocation and expiry when the guard is finalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrokerLeaseContext {
    /// Session bound into the capability.
    pub session_id: u64,
    /// Operation bound into the capability.
    pub operation_id: u64,
    /// Sequence at which the gate most recently validated the capability.
    pub validated_at_seq: u64,
    /// First sequence for which the capability is expired.
    pub expires_seq: u64,
}

/// Fresh capability-authority state sampled only after a broker lane has
/// stopped. The constructor is intentionally explicit: callers provide an
/// authority callback to [`finish_brokered_fetch`], and the core invokes it
/// after `BoundedFetchBroker::finish` rather than accepting a stale snapshot
/// captured before the potentially blocking broker shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAuthoritySnapshot {
    current_seq: u64,
    revoked_token_ids: Vec<u64>,
}

impl CapabilityAuthoritySnapshot {
    /// Construct a fresh snapshot from the authoritative coordinator ledger.
    #[must_use]
    pub fn new(current_seq: u64, revoked_token_ids: Vec<u64>) -> Self {
        Self {
            current_seq,
            revoked_token_ids,
        }
    }

    /// Current monotonic coordinator sequence.
    #[must_use]
    pub const fn current_seq(&self) -> u64 {
        self.current_seq
    }

    /// Token ids revoked as of [`Self::current_seq`].
    #[must_use]
    pub fn revoked_token_ids(&self) -> &[u64] {
        &self.revoked_token_ids
    }
}

/// Observed facts returned by the trusted broker only after it has stopped
/// the fetch lane and all accepted response bytes are final. Authorities
/// are the actual destinations after redirect/DNS/proxy policy handling,
/// not merely the declared allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerObservation {
    /// Actual unique destination authorities, in any order.
    pub authorities: Vec<NetworkAuthority>,
    /// Total requests issued, including redirected requests.
    pub requests: u32,
    /// Redirects actually followed.
    pub redirects: u32,
    /// Total accepted response-body bytes.
    pub response_bytes: u64,
}

/// Trusted platform boundary that installs, owns, and FINALIZES a fetch
/// broker. Implementations must enforce the exact policy for the lifetime
/// of the returned guard, including URL normalization, redirects, DNS
/// answers, proxy use, request count, accepted response bytes, and lease
/// expiry. The broker, not Cargo, owns DNS and remote sockets. Returning
/// success without doing so is a privileged-adapter integrity bug.
pub trait BoundedFetchBroker {
    /// Guard whose lifetime owns the broker policy and channel.
    type Guard;

    /// Attach the exact policy and create the owned edge-to-broker channel.
    /// The core validates the returned channel before issuing a lease.
    fn attach(
        &mut self,
        policy: &BoundedNetworkPolicy,
        lease: BrokerLeaseContext,
    ) -> Result<(Self::Guard, BrokerChannel), String>;

    /// Stop the broker lane, consume its guard, and report enforced facts.
    /// A receipt is not issued until this succeeds and the core validates
    /// every observed authority/counter against the installed policy.
    fn finish(&mut self, guard: Self::Guard) -> Result<BrokerObservation, String>;

    /// Stable audit name of the concrete enforcement mechanism.
    fn mechanism(&self) -> &'static str;
}

/// Honest, opaque record of a COMPLETED broker phase while Cargo itself
/// remained network-isolated. External code can inspect but cannot
/// construct or mutate this proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedNetworkReceipt {
    token_id: u64,
    session_id: u64,
    operation_id: u64,
    completed_at_seq: u64,
    scope_binding: String,
    allowed_authorities: Vec<NetworkAuthority>,
    observed_authorities: Vec<NetworkAuthority>,
    budget: NetworkBudget,
    requests: u32,
    redirects: u32,
    response_bytes: u64,
    mechanism: &'static str,
    channel: BrokerChannel,
}

impl BoundedNetworkReceipt {
    /// Exercised token id.
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token_id
    }

    /// Session bound into the exercised token.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Operation bound into the exercised token.
    #[must_use]
    pub const fn operation_id(&self) -> u64 {
        self.operation_id
    }

    /// Coordinator sequence at successful broker finalization.
    #[must_use]
    pub const fn completed_at_seq(&self) -> u64 {
        self.completed_at_seq
    }

    /// Exact redaction-safe policy binding.
    #[must_use]
    pub fn scope_binding(&self) -> &str {
        &self.scope_binding
    }

    /// Canonical authorities installed as the allowlist.
    #[must_use]
    pub fn allowed_authorities(&self) -> &[NetworkAuthority] {
        &self.allowed_authorities
    }

    /// Actual canonical authorities observed by the broker.
    #[must_use]
    pub fn observed_authorities(&self) -> &[NetworkAuthority] {
        &self.observed_authorities
    }

    /// Installed request/redirect/body budgets.
    #[must_use]
    pub const fn budget(&self) -> NetworkBudget {
        self.budget
    }

    /// Total observed requests, redirects included.
    #[must_use]
    pub const fn requests(&self) -> u32 {
        self.requests
    }

    /// Redirects actually followed.
    #[must_use]
    pub const fn redirects(&self) -> u32 {
        self.redirects
    }

    /// Accepted response-body bytes.
    #[must_use]
    pub const fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    /// Stable trusted-adapter mechanism.
    #[must_use]
    pub const fn mechanism(&self) -> &'static str {
        self.mechanism
    }

    /// Controlled edge-to-broker channel.
    #[must_use]
    pub const fn channel(&self) -> &BrokerChannel {
        &self.channel
    }
}

/// Broker lifetime token. It is deliberately opaque and non-cloneable.
/// Finalize it with [`finish_brokered_fetch`]; merely attaching a broker
/// never yields provenance that a capture can seal.
#[derive(Debug)]
#[must_use = "finish the brokered fetch explicitly to obtain its one-shot receipt"]
pub struct BrokeredFetchLease<'broker, B: BoundedFetchBroker> {
    broker: &'broker mut B,
    guard: Option<B::Guard>,
    grant: NetworkGrant,
    policy: BoundedNetworkPolicy,
    mechanism: &'static str,
    channel: BrokerChannel,
}

impl<B: BoundedFetchBroker> BrokeredFetchLease<'_, B> {
    /// Broker-owned channel available to the trusted edge fetch client for
    /// the lifetime of this one-shot lease. The channel does not grant
    /// ambient network access: the broker enforces the installed policy and
    /// [`finish_brokered_fetch`] consumes the guard before issuing evidence.
    #[must_use]
    pub const fn channel(&self) -> &BrokerChannel {
        &self.channel
    }
}

impl<B: BoundedFetchBroker> Drop for BrokeredFetchLease<'_, B> {
    fn drop(&mut self) {
        // Cancellation, early return, and unwinding must not detach a live
        // broker lane. The explicit finalizer takes this guard before it
        // invokes `finish`, so this fallback cannot finalize the same guard
        // twice and deliberately discards observations rather than minting a
        // receipt without completion-time authority validation.
        if let Some(guard) = self.guard.take() {
            let _ = self.broker.finish(guard);
        }
    }
}

/// One validated permission to exercise the bounded fetch broker. Produced
/// only by [`evaluate_open_network`] from a token that validated for THIS
/// session and operation. Its fields are intentionally opaque: callers can
/// inspect but cannot fabricate a grant.
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkGrant {
    token: CapabilityToken,
    validated_at_seq: u64,
}

impl NetworkGrant {
    /// Exercised token id for receipts.
    #[must_use]
    pub const fn token_id(&self) -> u64 {
        self.token.token_id
    }

    /// Redaction-safe bounded-policy binding carried by the token.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.token.scope
    }

    /// Session context carried by the token.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.token.session_id
    }

    /// Operation context carried by the token.
    #[must_use]
    pub const fn operation_id(&self) -> u64 {
        self.token.operation_id
    }

    /// First sequence for which this grant is expired.
    #[must_use]
    pub const fn expires_seq(&self) -> u64 {
        self.token.expires_seq
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
    for token in tokens {
        if let Some(prior) = by_id.insert(token.token_id, token)
            && prior != token
        {
            return Err(NetworkGateRefusal::ConflictingTokenPresentations {
                token_id: token.token_id,
            });
        }
    }
    let candidates: Vec<&CapabilityToken> = by_id
        .into_values()
        .filter(|token| token.kind == CapabilityKind::OpenNetwork)
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
            token: (*token).clone(),
            validated_at_seq: current_seq,
        }),
        _ => Err(NetworkGateRefusal::AmbiguousOpenNetworkGrants {
            valid_token_ids: valid.iter().map(|t| t.token_id).collect(),
        }),
    }
}

/// Bind a validated grant to an exact policy and attach the trusted EDGE
/// fetch adapter to a controlled broker channel. The canonical namespace
/// MUST remain closed, and Cargo is not launched during this phase. The
/// returned one-shot lease owns the broker guard until finalization.
///
/// # Errors
/// A typed policy refusal. The namespace is never mutated by this function.
pub fn prepare_brokered_fetch<'broker, B: BoundedFetchBroker>(
    spec: &CanonicalNamespaceSpec,
    grant: NetworkGrant,
    policy: BoundedNetworkPolicy,
    broker: &'broker mut B,
    revoked_token_ids: &[u64],
    current_seq: u64,
) -> Result<BrokeredFetchLease<'broker, B>, BoundedNetworkPolicyRefusal> {
    if spec.allows_network() {
        return Err(BoundedNetworkPolicyRefusal::CanonicalNetworkMustRemainClosed);
    }
    let expected = policy.scope_binding();
    if grant.scope() != expected {
        return Err(BoundedNetworkPolicyRefusal::ScopeMismatch {
            expected,
            presented: grant.scope().to_owned(),
        });
    }
    if current_seq < grant.validated_at_seq {
        return Err(BoundedNetworkPolicyRefusal::GrantNoLongerValid(
            "coordinator lease sequence regressed".into(),
        ));
    }
    capability_tokens::validate(
        &grant.token,
        revoked_token_ids,
        current_seq,
        grant.session_id(),
        grant.operation_id(),
    )
    .map_err(|error| BoundedNetworkPolicyRefusal::GrantNoLongerValid(format!("{error:?}")))?;
    let mechanism = broker.mechanism();
    if mechanism.is_empty() {
        return Err(BoundedNetworkPolicyRefusal::EnforcementMechanismMissing);
    }
    let lease_context = BrokerLeaseContext {
        session_id: grant.session_id(),
        operation_id: grant.operation_id(),
        validated_at_seq: current_seq,
        expires_seq: grant.expires_seq(),
    };
    let (guard, channel) = broker
        .attach(&policy, lease_context)
        .map_err(BoundedNetworkPolicyRefusal::EnforcementUnavailable)?;
    if let Err(error) = channel.validate() {
        // `attach` has already activated the trusted adapter. Consume its
        // guard before refusing so an invalid returned channel cannot leave
        // a detached broker lane alive without a lease owner.
        let _ = broker.finish(guard);
        return Err(error);
    }
    Ok(BrokeredFetchLease {
        broker,
        guard: Some(guard),
        grant,
        policy,
        mechanism,
        channel,
    })
}

/// Finalize a one-shot broker lease and issue an opaque receipt only after
/// the adapter's observations satisfy the exact installed policy. The
/// capability is revalidated at completion so expiry/revocation cannot be
/// hidden by an earlier successful attach.
///
/// # Errors
/// A typed refusal for adapter failure, expired/revoked authority, an
/// out-of-policy destination, or invalid observed counters.
pub fn finish_brokered_fetch<B, A>(
    mut lease: BrokeredFetchLease<'_, B>,
    authority_state: A,
) -> Result<BoundedNetworkReceipt, BoundedNetworkPolicyRefusal>
where
    B: BoundedFetchBroker,
    A: FnOnce() -> Result<CapabilityAuthoritySnapshot, String>,
{
    let guard = lease.guard.take().ok_or_else(|| {
        BoundedNetworkPolicyRefusal::EnforcementUnavailable(
            "broker lease guard was already finalized".into(),
        )
    })?;
    let observation = lease
        .broker
        .finish(guard)
        .map_err(BoundedNetworkPolicyRefusal::EnforcementUnavailable)?;
    let authority =
        authority_state().map_err(BoundedNetworkPolicyRefusal::AuthorityStateUnavailable)?;
    let current_seq = authority.current_seq();
    if current_seq < lease.grant.validated_at_seq {
        return Err(BoundedNetworkPolicyRefusal::GrantNoLongerValid(
            "coordinator lease sequence regressed".into(),
        ));
    }
    capability_tokens::validate(
        &lease.grant.token,
        authority.revoked_token_ids(),
        current_seq,
        lease.grant.session_id(),
        lease.grant.operation_id(),
    )
    .map_err(|error| BoundedNetworkPolicyRefusal::GrantNoLongerValid(format!("{error:?}")))?;
    if observation.requests == 0 {
        return Err(BoundedNetworkPolicyRefusal::NoRequestsObserved);
    }
    if observation.authorities.is_empty() {
        return Err(BoundedNetworkPolicyRefusal::ObservedBudgetInvalid(
            "observed_authorities",
        ));
    }
    if observation.redirects > observation.requests
        || observation.requests > lease.policy.budget.max_requests
    {
        return Err(BoundedNetworkPolicyRefusal::ObservedBudgetInvalid(
            "requests/redirects",
        ));
    }
    if observation.redirects > lease.policy.budget.max_redirects {
        return Err(BoundedNetworkPolicyRefusal::ObservedBudgetInvalid(
            "max_redirects",
        ));
    }
    if observation.response_bytes > lease.policy.budget.max_response_bytes {
        return Err(BoundedNetworkPolicyRefusal::ObservedBudgetInvalid(
            "max_response_bytes",
        ));
    }

    let mut observed_authorities = observation.authorities;
    observed_authorities.sort();
    observed_authorities.dedup();
    for authority in &observed_authorities {
        if lease.policy.authorities.binary_search(authority).is_err() {
            return Err(BoundedNetworkPolicyRefusal::ObservedAuthorityOutsidePolicy(
                authority.clone(),
            ));
        }
    }

    Ok(BoundedNetworkReceipt {
        token_id: lease.grant.token_id(),
        session_id: lease.grant.session_id(),
        operation_id: lease.grant.operation_id(),
        completed_at_seq: current_seq,
        scope_binding: lease.policy.scope_binding(),
        allowed_authorities: lease.policy.authorities.clone(),
        observed_authorities,
        budget: lease.policy.budget,
        requests: observation.requests,
        redirects: observation.redirects,
        response_bytes: observation.response_bytes,
        mechanism: lease.mechanism,
        channel: lease.channel.clone(),
    })
}

fn canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.to_string() == host;
    }
    // libc/URL parsers commonly accept inet_aton-era IPv4 spellings that
    // Rust's strict `IpAddr` parser rejects: shortened dotted forms, octal,
    // hexadecimal, and one-component integers. Letting those fall through as
    // "DNS" would make the policy authorize one spelling while a broker
    // connects to another address (often loopback). Canonical IPv4 already
    // returned above; reject every all-numeric/hex-component legacy form.
    if looks_like_legacy_ipv4(host) {
        return false;
    }
    if host != host.to_ascii_lowercase() || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with("xn--")
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn looks_like_legacy_ipv4(host: &str) -> bool {
    host.split('.').all(|component| {
        !component.is_empty()
            && (component.bytes().all(|byte| byte.is_ascii_digit())
                || component.strip_prefix("0x").is_some_and(|hex| {
                    !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                }))
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
                    reason: "network-not-isolated",
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

    fn authority_at(
        current_seq: u64,
        revoked_token_ids: &[u64],
    ) -> impl FnOnce() -> Result<CapabilityAuthoritySnapshot, String> {
        let revoked_token_ids = revoked_token_ids.to_vec();
        move || {
            Ok(CapabilityAuthoritySnapshot::new(
                current_seq,
                revoked_token_ids,
            ))
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct FakeBrokerGuard;

    struct FakeBroker {
        fail: bool,
        finish_calls: u32,
        seen: Option<(BoundedNetworkPolicy, BrokerChannel, BrokerLeaseContext)>,
        channel: BrokerChannel,
        observation: BrokerObservation,
        mechanism: &'static str,
    }

    impl BoundedFetchBroker for FakeBroker {
        type Guard = FakeBrokerGuard;

        fn attach(
            &mut self,
            policy: &BoundedNetworkPolicy,
            lease: BrokerLeaseContext,
        ) -> Result<(Self::Guard, BrokerChannel), String> {
            self.seen = Some((policy.clone(), self.channel.clone(), lease));
            if self.fail {
                Err("broker unavailable".into())
            } else {
                Ok((FakeBrokerGuard, self.channel.clone()))
            }
        }

        fn finish(&mut self, _guard: Self::Guard) -> Result<BrokerObservation, String> {
            self.finish_calls += 1;
            if self.fail {
                Err("broker unavailable".into())
            } else {
                Ok(self.observation.clone())
            }
        }

        fn mechanism(&self) -> &'static str {
            self.mechanism
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum AuthorityMutation {
        AdvanceTo(u64),
        Revoke(u64),
    }

    struct AuthorityMutatingBroker {
        authority: std::rc::Rc<std::cell::RefCell<CapabilityAuthoritySnapshot>>,
        mutation: AuthorityMutation,
        finish_calls: u32,
    }

    impl BoundedFetchBroker for AuthorityMutatingBroker {
        type Guard = FakeBrokerGuard;

        fn attach(
            &mut self,
            _policy: &BoundedNetworkPolicy,
            _lease: BrokerLeaseContext,
        ) -> Result<(Self::Guard, BrokerChannel), String> {
            Ok((FakeBrokerGuard, BrokerChannel::InheritedFd(7)))
        }

        fn finish(&mut self, _guard: Self::Guard) -> Result<BrokerObservation, String> {
            self.finish_calls += 1;
            let mut authority = self.authority.borrow_mut();
            match self.mutation {
                AuthorityMutation::AdvanceTo(current_seq) => {
                    authority.current_seq = current_seq;
                }
                AuthorityMutation::Revoke(token_id) => {
                    authority.revoked_token_ids.push(token_id);
                }
            }
            Ok(BrokerObservation {
                authorities: vec![
                    NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443)
                        .expect("canonical test authority"),
                ],
                requests: 1,
                redirects: 0,
                response_bytes: 1,
            })
        }

        fn mechanism(&self) -> &'static str {
            "authority-mutating-test-broker"
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
    fn same_token_id_reused_across_capability_kinds_refuses() {
        let network = open_token(1, 5, 9, "scope-a");
        let snapshot = capability_tokens::mint(
            1,
            CapabilityKind::MaterializeSnapshot,
            5,
            9,
            "snapshot-a",
            100,
        )
        .unwrap();
        assert_eq!(
            evaluate_open_network(&[snapshot, network], &[], 10, 5, 9),
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
        let observed =
            NetworkAuthority::new(NetworkScheme::Https, "static.crates.io", 443).unwrap();
        let mut broker = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: channel.clone(),
            observation: BrokerObservation {
                authorities: vec![observed.clone()],
                requests: 3,
                redirects: 1,
                response_bytes: 4096,
            },
            mechanism: "edge-fetch-broker-v1",
        };
        let expected_policy = policy.clone();
        let lease = prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 11)
            .expect("exact bounded broker policy attaches");
        assert_eq!(lease.channel(), &channel);
        let receipt = finish_brokered_fetch(lease, authority_at(12, &[]))
            .expect("observed facts fit the installed policy");

        let launch = build_canonical_argv(&spec, &full_support(), "cargo", &["metadata".into()])
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
        assert_eq!(receipt.token_id(), 7);
        assert_eq!(receipt.session_id(), 5);
        assert_eq!(receipt.operation_id(), 9);
        assert_eq!(receipt.completed_at_seq(), 12);
        assert_eq!(receipt.scope_binding(), expected_policy.scope_binding());
        assert_eq!(receipt.allowed_authorities(), expected_policy.authorities());
        assert_eq!(receipt.observed_authorities(), &[observed]);
        assert_eq!(receipt.requests(), 3);
        assert_eq!(receipt.redirects(), 1);
        assert_eq!(receipt.response_bytes(), 4096);
        assert_eq!(receipt.channel(), &channel);
        assert_eq!(receipt.mechanism(), "edge-fetch-broker-v1");
        assert_eq!(
            broker.seen,
            Some((
                expected_policy,
                BrokerChannel::InheritedFd(7),
                BrokerLeaseContext {
                    session_id: 5,
                    operation_id: 9,
                    validated_at_seq: 11,
                    expires_seq: 100,
                },
            ))
        );
    }

    #[test]
    fn broker_lease_finishes_only_the_instance_that_attached_it() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();
        let token = open_token(7, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        let observation = BrokerObservation {
            authorities: vec![
                NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap(),
            ],
            requests: 1,
            redirects: 0,
            response_bytes: 1,
        };
        let mut owner = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(7),
            observation: observation.clone(),
            mechanism: "owner-broker",
        };
        let other = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(8),
            observation,
            mechanism: "other-broker",
        };

        let lease = prepare_brokered_fetch(&spec, grant, policy, &mut owner, &[], 11).unwrap();
        let receipt = finish_brokered_fetch(lease, authority_at(12, &[])).unwrap();

        assert_eq!(owner.finish_calls, 1);
        assert_eq!(other.finish_calls, 0);
        assert_eq!(receipt.mechanism(), "owner-broker");
        assert_eq!(receipt.channel(), &BrokerChannel::InheritedFd(7));
    }

    #[test]
    fn dropped_broker_lease_finalizes_once_without_minting_a_receipt() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();
        let token = open_token(7, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        let mut broker = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(7),
            observation: BrokerObservation {
                authorities: vec![
                    NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap(),
                ],
                requests: 1,
                redirects: 0,
                response_bytes: 1,
            },
            mechanism: "drop-test-broker",
        };

        let cancellation: std::thread::Result<()> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let lease =
                    prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 11).unwrap();
                assert_eq!(lease.channel(), &BrokerChannel::InheritedFd(7));
                // Simulate cancellation by unwinding before the receipt-
                // issuing finalizer and authority callback can run.
                panic!("cancel brokered fetch");
            }));

        assert!(cancellation.is_err());
        assert_eq!(
            broker.finish_calls, 1,
            "Drop must consume the attached guard exactly once"
        );
    }

    #[test]
    fn completion_queries_authority_after_broker_finish() {
        for (mutation, expected) in [
            (AuthorityMutation::Revoke(7), "Revoked"),
            (AuthorityMutation::AdvanceTo(100), "LeaseExpired"),
        ] {
            let spec = CanonicalNamespaceSpec::new();
            let policy = fetch_policy();
            let token = open_token(7, 5, 9, &policy.scope_binding());
            let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
            let authority = std::rc::Rc::new(std::cell::RefCell::new(
                CapabilityAuthoritySnapshot::new(11, vec![]),
            ));
            let mut broker = AuthorityMutatingBroker {
                authority: std::rc::Rc::clone(&authority),
                mutation,
                finish_calls: 0,
            };
            let lease = prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 11).unwrap();
            let authority_for_callback = std::rc::Rc::clone(&authority);

            let result =
                finish_brokered_fetch(lease, move || Ok(authority_for_callback.borrow().clone()));

            assert!(matches!(
                result,
                Err(BoundedNetworkPolicyRefusal::GrantNoLongerValid(message))
                    if message.contains(expected)
            ));
            assert_eq!(broker.finish_calls, 1);
        }
    }

    #[test]
    fn scope_mismatch_or_broker_failure_never_widens_network() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();
        let wrong = open_token(7, 5, 9, "rabs.bounded-network-scope.sha256.v1:wrong");
        let grant = evaluate_open_network(&[wrong], &[], 10, 5, 9).unwrap();
        let mut broker = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(7),
            observation: BrokerObservation {
                authorities: vec![],
                requests: 1,
                redirects: 0,
                response_bytes: 1,
            },
            mechanism: "edge-fetch-broker-v1",
        };
        assert!(matches!(
            prepare_brokered_fetch(&spec, grant, policy.clone(), &mut broker, &[], 10,),
            Err(BoundedNetworkPolicyRefusal::ScopeMismatch { .. })
        ));
        assert!(broker.seen.is_none(), "mismatch refuses before broker use");

        let token = open_token(8, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        broker.fail = true;
        assert!(matches!(
            prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 10,),
            Err(BoundedNetworkPolicyRefusal::EnforcementUnavailable(_))
        ));
        assert!(!spec.allows_network());

        let policy = fetch_policy();
        let token = open_token(9, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        broker.fail = false;
        broker.channel = BrokerChannel::InheritedFd(2);
        assert!(matches!(
            prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 10),
            Err(BoundedNetworkPolicyRefusal::InvalidBrokerChannel)
        ));
        assert_eq!(
            broker.finish_calls, 1,
            "an invalid post-attach channel must consume its broker guard"
        );
    }

    #[test]
    fn broker_completion_rechecks_authority_expiry_and_observed_destinations() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();

        let token = open_token(7, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        let mut broker = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(7),
            observation: BrokerObservation {
                authorities: vec![
                    NetworkAuthority::new(NetworkScheme::Https, "evil.example", 443).unwrap(),
                ],
                requests: 1,
                redirects: 0,
                response_bytes: 1,
            },
            mechanism: "edge-fetch-broker-v1",
        };
        let lease =
            prepare_brokered_fetch(&spec, grant, policy.clone(), &mut broker, &[], 10).unwrap();
        assert!(matches!(
            finish_brokered_fetch(lease, authority_at(11, &[])),
            Err(BoundedNetworkPolicyRefusal::ObservedAuthorityOutsidePolicy(
                _
            ))
        ));

        let token = open_token(8, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        broker.observation = BrokerObservation {
            authorities: vec![
                NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap(),
            ],
            requests: 1,
            redirects: 0,
            response_bytes: 1,
        };
        let lease = prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 10).unwrap();
        assert!(matches!(
            finish_brokered_fetch(lease, authority_at(100, &[])),
            Err(BoundedNetworkPolicyRefusal::GrantNoLongerValid(_))
        ));
    }

    #[test]
    fn broker_attach_rechecks_expiry_and_revocation_before_activation() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();
        let mut broker = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(7),
            observation: BrokerObservation {
                authorities: vec![
                    NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap(),
                ],
                requests: 1,
                redirects: 0,
                response_bytes: 1,
            },
            mechanism: "edge-fetch-broker-v1",
        };

        let expired = open_token(7, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[expired], &[], 10, 5, 9).unwrap();
        assert!(matches!(
            prepare_brokered_fetch(&spec, grant, policy.clone(), &mut broker, &[], 100),
            Err(BoundedNetworkPolicyRefusal::GrantNoLongerValid(_))
        ));
        assert!(broker.seen.is_none());

        let revoked = open_token(8, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[revoked], &[], 10, 5, 9).unwrap();
        assert!(matches!(
            prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[8], 11),
            Err(BoundedNetworkPolicyRefusal::GrantNoLongerValid(_))
        ));
        assert!(broker.seen.is_none());
    }

    #[test]
    fn broker_completion_rejects_missing_requests_and_counter_overflow() {
        let spec = CanonicalNamespaceSpec::new();
        let policy = fetch_policy();
        let token = open_token(7, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        let mut broker = FakeBroker {
            fail: false,
            finish_calls: 0,
            seen: None,
            channel: BrokerChannel::InheritedFd(7),
            observation: BrokerObservation {
                authorities: vec![],
                requests: 0,
                redirects: 0,
                response_bytes: 0,
            },
            mechanism: "edge-fetch-broker-v1",
        };
        let lease =
            prepare_brokered_fetch(&spec, grant, policy.clone(), &mut broker, &[], 10).unwrap();
        assert_eq!(
            finish_brokered_fetch(lease, authority_at(11, &[])),
            Err(BoundedNetworkPolicyRefusal::NoRequestsObserved)
        );

        let token = open_token(8, 5, 9, &policy.scope_binding());
        let grant = evaluate_open_network(&[token], &[], 10, 5, 9).unwrap();
        broker.observation = BrokerObservation {
            authorities: vec![
                NetworkAuthority::new(NetworkScheme::Https, "crates.io", 443).unwrap(),
            ],
            requests: 1,
            redirects: policy.budget().max_redirects + 1,
            response_bytes: 1,
        };
        let lease = prepare_brokered_fetch(&spec, grant, policy, &mut broker, &[], 10).unwrap();
        assert_eq!(
            finish_brokered_fetch(lease, authority_at(11, &[])),
            Err(BoundedNetworkPolicyRefusal::ObservedBudgetInvalid(
                "requests/redirects"
            ))
        );
    }

    #[test]
    fn authorities_budgets_and_broker_channels_are_canonical() {
        for bad in [
            "Crates.io",
            "crates.io.",
            "user@crates.io",
            "crates.io/path",
            "xn--caf-dma.example",
        ] {
            assert!(NetworkAuthority::new(NetworkScheme::Https, bad, 443).is_err());
        }
        assert!(NetworkAuthority::new(NetworkScheme::Https, "127.0.0.1", 443).is_ok());
        assert!(NetworkAuthority::new(NetworkScheme::Https, "2001:db8::1", 443).is_ok());
        assert!(NetworkAuthority::new(NetworkScheme::Https, "123.example", 443).is_ok());
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
    fn legacy_ipv4_spellings_never_fall_through_as_dns() {
        for ambiguous in ["127.1", "0177.0.0.1", "2130706433", "0x7f000001"] {
            assert!(
                NetworkAuthority::new(NetworkScheme::Https, ambiguous, 443).is_err(),
                "resolver-ambiguous IPv4 spelling must refuse: {ambiguous}"
            );
        }
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
