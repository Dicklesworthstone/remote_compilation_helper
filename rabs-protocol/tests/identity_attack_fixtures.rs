//! Session-level identity attack fixtures (bead S009; plan §106; the
//! regression suite the R008 `WorkerIdentityMismatch` runbook demands).
//!
//! The bead names three attack classes — WRONG IDENTITY, REPLAYED
//! handshakes/credentials, PROTOCOL DOWNGRADE — and requires each be
//! refused with a TYPED error, never a fallback, guess, or silent
//! acceptance. This suite composes the EXISTING primitives exactly as
//! a real handshake would meet them and pins the refusals:
//!
//! - wrong identity: [`rabs_protocol::identity_store`]'s transport
//!   binding (S002) against impersonation, forged fingerprints,
//!   stale-generation key replay, revocation, and label-as-proof
//!   shortcuts;
//! - replay: capability tokens (F-series) replayed across sessions,
//!   operations, expiries, and revocations; state-changing messages
//!   offered inside replayable 0-RTT (J022);
//! - downgrade: version negotiation (J002) refusing peers below the
//!   minimum-compatible line at either layer, malformed range claims,
//!   and skews beyond the supported N/N-1.
//!
//! Every refusal asserted here is a typed value from the producing
//! module's own API — the suite cannot pass against a system that
//! "fails open" by inventing an accept path.

use rabs_protocol::capability_tokens::{self, CapabilityKind, TokenRefusal};
use rabs_protocol::identity_store::{
    BindingRefusal, BoundSession, IdentityStore, LabelAliases, TransportIdentity, TrustScope,
};
use rabs_protocol::version_negotiation::{
    Negotiation, RefusedLayer, VersionHello, VersionRange, negotiate,
};
use rabs_protocol::zero_rtt_policy::{MessageClass, ZeroRttDecision, admit_zero_rtt};

const PEER: [u8; 32] = [7; 32];
const KEY_1: [u8; 32] = [1; 32];
const KEY_2: [u8; 32] = [2; 32];

/// A store with PEER registered at generation 1 under KEY_1.
fn store_with_peer() -> IdentityStore {
    let mut store = IdentityStore::default();
    store
        .create(PEER, KEY_1, TrustScope::Worker, 1)
        .expect("creates");
    store
}

// ---------------------------------------------------------------------------
// Attack class 1: wrong identity.
// ---------------------------------------------------------------------------

#[test]
fn a_channel_authenticated_as_one_peer_cannot_claim_another() {
    let store = store_with_peer();
    // The impostor authenticated its OWN key over the transport but
    // claims to BE the registered peer on the wire.
    let impostor = TransportIdentity {
        peer_id: [9; 32],
        fingerprint: [9; 32],
    };
    assert_eq!(
        store.bind_transport_identity(&PEER, &impostor, 100),
        Err(BindingRefusal::ClaimedIdMismatch),
        "the wire claim must BE the transport-authenticated peer"
    );
}

#[test]
fn a_forged_fingerprint_under_the_right_peer_is_refused() {
    let store = store_with_peer();
    // Right id, wrong key: the strongest-looking forgery is still a
    // fingerprint the store has NEVER seen.
    let forged = TransportIdentity {
        peer_id: PEER,
        fingerprint: [9; 32],
    };
    assert_eq!(
        store.bind_transport_identity(&PEER, &forged, 101),
        Err(BindingRefusal::FingerprintMismatch {
            matches_generation: None
        }),
        "a never-seen key refuses without naming any generation"
    );
}

#[test]
fn replaying_a_stale_generation_key_names_its_generation_and_refuses() {
    let mut store = store_with_peer();
    store.rotate(PEER, KEY_2, 2).expect("rotates");
    // The REPLAY of the generation-1 handshake after rotation: the old
    // key is recognized as history — and still refused, naming where
    // it came from so the operator sees a stale-replay, not a mystery.
    let stale_replay = TransportIdentity {
        peer_id: PEER,
        fingerprint: KEY_1,
    };
    assert_eq!(
        store.bind_transport_identity(&PEER, &stale_replay, 102),
        Err(BindingRefusal::FingerprintMismatch {
            matches_generation: Some(1)
        })
    );
}

#[test]
fn a_revoked_identity_cannot_bind_even_with_its_current_key() {
    let mut store = store_with_peer();
    store.rotate(PEER, KEY_2, 2).expect("rotates");
    store.revoke(PEER, 3).expect("revokes");
    let current_key = TransportIdentity {
        peer_id: PEER,
        fingerprint: KEY_2,
    };
    assert_eq!(
        store.bind_transport_identity(&PEER, &current_key, 103),
        Err(BindingRefusal::RevokedIdentity),
        "revocation is terminal: the freshest key proves nothing"
    );
}

#[test]
fn a_configuration_label_never_authorizes_a_session() {
    let mut store = store_with_peer();
    store
        .create([9; 32], [9; 32], TrustScope::Worker, 2)
        .expect("creates stranger");
    // The operator's label says this connection is "css" (= PEER).
    let mut aliases = LabelAliases::default();
    aliases.alias("css", PEER);
    let named = aliases.resolve("css").expect("label resolves");
    assert_eq!(named, PEER);
    // A stranger's channel SAYING the label's name is still the
    // stranger: resolving a label yields an expectation to verify,
    // never a credential.
    let stranger = TransportIdentity {
        peer_id: [9; 32],
        fingerprint: [9; 32],
    };
    assert_eq!(
        store.bind_transport_identity(&named, &stranger, 104),
        Err(BindingRefusal::ClaimedIdMismatch)
    );
}

// ---------------------------------------------------------------------------
// Attack class 2: replayed handshakes / credentials.
// ---------------------------------------------------------------------------

#[test]
fn a_capability_token_replayed_outside_its_context_refuses_typed() {
    let token = capability_tokens::mint(
        1,
        CapabilityKind::ExecuteAction,
        7, // session
        3, // operation
        "obj-digest",
        50,
    )
    .expect("mints");
    // Replay into ANOTHER session.
    assert_eq!(
        capability_tokens::validate(&token, &[], 10, 8, 3),
        Err(TokenRefusal::WrongSession)
    );
    // Replay into the same session but a DIFFERENT operation.
    assert_eq!(
        capability_tokens::validate(&token, &[], 10, 7, 4),
        Err(TokenRefusal::WrongOperation)
    );
}

#[test]
fn a_token_past_its_lease_refuses_at_replay_time() {
    let token = capability_tokens::mint(2, CapabilityKind::ReadObject, 7, 3, "obj-digest", 50)
        .expect("mints");
    // The lease advanced past the token's expiry: even the ORIGINAL
    // context refuses now.
    assert_eq!(
        capability_tokens::validate(&token, &[], 50, 7, 3),
        Err(TokenRefusal::LeaseExpired(50))
    );
}

#[test]
fn a_revoked_token_refuses_even_inside_its_own_context() {
    let token = capability_tokens::mint(
        3,
        CapabilityKind::MaterializeSnapshot,
        7,
        3,
        "staging/prefix",
        50,
    )
    .expect("mints");
    assert_eq!(
        capability_tokens::validate(&token, &[3], 10, 7, 3),
        Err(TokenRefusal::Revoked)
    );
}

#[test]
fn state_changing_messages_cannot_ride_replayable_zero_rtt() {
    // 0-RTT first flights are replayable BY DESIGN, so every
    // state-changing class demands the fully authenticated session.
    for class in [
        MessageClass::ActionSubmission,
        MessageClass::LeaseChange,
        MessageClass::Cancellation,
        MessageClass::Publication,
    ] {
        assert_eq!(
            admit_zero_rtt(class, "anything"),
            ZeroRttDecision::RequireFullSession,
            "{class:?} must refuse 0-RTT regardless of operation name"
        );
    }
    // Positive control: the reviewed read-only allowlist admits; a
    // read-only operation OFF the allowlist does not ride 0-RTT either.
    let allowlisted = rabs_protocol::zero_rtt_policy::ZERO_RTT_ALLOWLIST[0].operation;
    assert_eq!(
        admit_zero_rtt(MessageClass::ReadOnlyQuery, allowlisted),
        ZeroRttDecision::Admit
    );
    assert_eq!(
        admit_zero_rtt(MessageClass::ReadOnlyQuery, "not-on-the-allowlist"),
        ZeroRttDecision::RequireFullSession
    );
}

// ---------------------------------------------------------------------------
// Attack class 3: protocol downgrade.
// ---------------------------------------------------------------------------

fn hello(transport_min: u32, transport_cur: u32, app_min: u32, app_cur: u32) -> VersionHello {
    VersionHello {
        transport: VersionRange {
            minimum_compatible: transport_min,
            current: transport_cur,
        },
        application: VersionRange {
            minimum_compatible: app_min,
            current: app_cur,
        },
    }
}

#[test]
fn a_peer_below_the_minimum_compatible_line_refuses_per_layer() {
    // We speak transport 2..=3; the attacker offers ONLY version 1 —
    // the classic downgrade-to-weaker-protocol attempt.
    let ours = hello(2, 3, 1, 1);
    let theirs = hello(1, 1, 1, 1);
    assert_eq!(
        negotiate(&ours, &theirs),
        Negotiation::Refused(rabs_protocol::version_negotiation::VersionRefusal {
            layer: RefusedLayer::Transport,
            ours: ours.transport,
            theirs: theirs.transport,
        }),
        "the refusal carries BOTH ranges so the operator sees the gap"
    );
}

#[test]
fn an_application_layer_downgrade_refuses_even_when_transport_agrees() {
    // Transport negotiates fine; the APPLICATION half is dragged down —
    // refused independently, naming the application layer.
    let ours = hello(1, 3, 5, 5);
    let theirs = hello(1, 3, 1, 2);
    assert_eq!(
        negotiate(&ours, &theirs),
        Negotiation::Refused(rabs_protocol::version_negotiation::VersionRefusal {
            layer: RefusedLayer::Application,
            ours: ours.application,
            theirs: theirs.application,
        })
    );
}

#[test]
fn a_hello_with_inverted_ranges_is_malformed_not_negotiable() {
    // minimum > current claims to speak ONLY versions that do not
    // exist; that is a malformed hello, not a negotiation input.
    let ours = hello(1, 3, 1, 1);
    let inverted = hello(5, 2, 1, 1);
    assert_eq!(
        negotiate(&ours, &inverted),
        Negotiation::Refused(rabs_protocol::version_negotiation::VersionRefusal {
            layer: RefusedLayer::MalformedHello,
            ours: ours.transport,
            theirs: inverted.transport,
        })
    );
}

#[test]
fn one_version_of_skew_negotiates_but_a_two_version_downgrade_refuses() {
    // Positive control: N advertises N-1 as its compatible floor and
    // speaks with N-1, agreeing AT N-1 (the supported skew).
    let current = hello(2, 3, 2, 3);
    let one_behind = hello(2, 2, 2, 2);
    assert_eq!(
        negotiate(&current, &one_behind),
        Negotiation::Agreed {
            transport: 2,
            application: 2
        }
    );
    // Negative control: a peer that can ONLY go below the floor is
    // beyond the supported skew — no agreement can be talked into
    // existence.
    let two_behind = hello(1, 1, 1, 1);
    assert!(matches!(
        negotiate(&current, &two_behind),
        Negotiation::Refused(_)
    ));
}

// ---------------------------------------------------------------------------
// The full session story: every attacker step refused, the honest
// handshake admitted — composed in one place.
// ---------------------------------------------------------------------------

#[test]
fn the_full_handshake_story_admits_only_the_honest_path() {
    let mut store = store_with_peer();

    // Both sides advertise honestly and agree.
    let coordinator = hello(1, 1, 1, 1);
    let worker = hello(1, 1, 1, 1);
    assert!(matches!(
        negotiate(&coordinator, &worker),
        Negotiation::Agreed { .. }
    ));

    // Attacker step: wrong id → refused.
    let impostor = TransportIdentity {
        peer_id: [9; 32],
        fingerprint: [9; 32],
    };
    assert_eq!(
        store.bind_transport_identity(&PEER, &impostor, 200),
        Err(BindingRefusal::ClaimedIdMismatch)
    );

    // Honest path: the real peer binds at generation 1.
    let honest = TransportIdentity {
        peer_id: PEER,
        fingerprint: KEY_1,
    };
    let bound: BoundSession = store
        .bind_transport_identity(&PEER, &honest, 201)
        .expect("honest handshake binds");

    // Coordinator rotates; the OLD session is fenced typed...
    store.rotate(PEER, KEY_2, 2).expect("rotates");
    assert!(matches!(
        store.check_binding(&bound.binding),
        rabs_protocol::identity_store::BindingVerdict::StaleGeneration { .. }
    ));
    // ...and the replayed old-key handshake cannot re-enter.
    assert_eq!(
        store.bind_transport_identity(&PEER, &honest, 202),
        Err(BindingRefusal::FingerprintMismatch {
            matches_generation: Some(1)
        })
    );

    // Only a fresh handshake under the rotated key re-admits.
    let rotated = TransportIdentity {
        peer_id: PEER,
        fingerprint: KEY_2,
    };
    let rebound = store
        .bind_transport_identity(&PEER, &rotated, 203)
        .expect("re-handshake binds");
    assert_eq!(rebound.binding.generation, 2);
}
