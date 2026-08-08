//! Peer-credential admission on the wrapper socket (bead C003).
//!
//! The wrapper socket is the boundary between arbitrary local
//! processes and a daemon that can schedule fleet work — admission is
//! a POLICY DECISION over presented evidence, and this module is that
//! decision, pure and total. The edge daemon gathers the evidence
//! (`SO_PEERCRED`/`getpeereid`, `fstat` on the socket inode); nothing
//! here guesses:
//!
//! - the peer's UID must be the daemon's expected UID (same-user
//!   discipline; a root peer is still refused unless it IS the
//!   expected user — privilege is not identity);
//! - the socket inode must be owned by the expected UID and carry no
//!   group/other permission bits (a group- or world-accessible socket
//!   is an invitation, so it refuses loudly instead);
//! - the policy may additionally demand a per-request capability
//!   token (F-series `capability_tokens::validate` composes here);
//! - the TCP fallback is DISABLED by default; when explicitly enabled
//!   it admits loopback peers only, and — because TCP carries no
//!   kernel peer credential — a capability token is then MANDATORY,
//!   not optional (loopback-authenticated means authenticated, not
//!   merely local).
//!
//! Every refusal is typed and names the evidence that failed.

use crate::capability_tokens::{CapabilityToken, TokenRefusal, validate};

/// Kernel-reported peer credentials (`SO_PEERCRED` / `getpeereid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Peer process UID.
    pub uid: u32,
    /// Peer process GID.
    pub gid: u32,
}

/// `fstat` evidence about the socket inode itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketMetadata {
    /// Owning UID of the socket inode.
    pub owner_uid: u32,
    /// Permission bits (e.g. `0o600`).
    pub mode: u32,
}

/// The transport a connection arrived on, with its evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvidence {
    /// Unix-domain socket: kernel peer credentials + inode metadata.
    UnixSocket {
        /// Peer credentials.
        peer: PeerCredentials,
        /// Socket inode evidence.
        socket: SocketMetadata,
    },
    /// TCP fallback: no kernel credential exists; the only evidence is
    /// whether the remote address is loopback.
    Tcp {
        /// Whether the remote address is a loopback address.
        remote_is_loopback: bool,
    },
}

/// Admission policy for the wrapper socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionPolicy {
    /// The daemon's UID: the ONLY peer UID admitted.
    pub expected_uid: u32,
    /// Whether Unix-socket requests must ALSO present a capability
    /// token (defense in depth; optional).
    pub require_token_on_unix: bool,
    /// Whether the TCP fallback is enabled at all (default: false).
    pub tcp_enabled: bool,
}

impl AdmissionPolicy {
    /// The default posture for a daemon running as `uid`: Unix socket
    /// only, kernel credentials suffice, TCP disabled.
    #[must_use]
    pub const fn default_for_uid(uid: u32) -> Self {
        Self {
            expected_uid: uid,
            require_token_on_unix: false,
            tcp_enabled: false,
        }
    }
}

/// Permission bits that admit anyone but the owner. A socket carrying
/// ANY of these is refused regardless of who is connecting right now.
const GROUP_OTHER_BITS: u32 = 0o077;

/// Typed admission refusals — each names the failed evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefusal {
    /// Peer UID is not the expected daemon UID.
    PeerUidMismatch {
        /// The connecting peer's UID.
        peer_uid: u32,
        /// The only admitted UID.
        expected_uid: u32,
    },
    /// The socket inode is owned by someone else (a planted socket).
    SocketOwnerMismatch {
        /// The inode's owner.
        owner_uid: u32,
        /// The expected owner.
        expected_uid: u32,
    },
    /// The socket inode admits group/other access.
    SocketModeTooOpen {
        /// The offending mode bits.
        mode: u32,
    },
    /// TCP fallback is disabled by policy (the default).
    TcpDisabled,
    /// TCP fallback is enabled but the remote is not loopback.
    TcpNotLoopback,
    /// The policy (or the TCP transport) demands a capability token
    /// and none was presented.
    TokenRequired,
    /// A token was presented and failed validation.
    TokenInvalid(TokenRefusal),
}

/// Token-validation context for admission (the F-series bindings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenContext<'a> {
    /// Revoked token ids.
    pub revoked: &'a [u64],
    /// Current sequence (lease check).
    pub current_seq: u64,
    /// Session the request claims.
    pub session_id: u64,
    /// Operation the request claims.
    pub operation_id: u64,
}

fn check_token(
    token: Option<&CapabilityToken>,
    context: &TokenContext<'_>,
) -> Result<(), AdmissionRefusal> {
    let Some(token) = token else {
        return Err(AdmissionRefusal::TokenRequired);
    };
    validate(
        token,
        context.revoked,
        context.current_seq,
        context.session_id,
        context.operation_id,
    )
    .map_err(AdmissionRefusal::TokenInvalid)
}

/// Admit or refuse one connection. Pure: evidence in, decision out.
///
/// # Errors
/// The first failed check, as a typed [`AdmissionRefusal`].
pub fn admit(
    policy: &AdmissionPolicy,
    evidence: &ConnectionEvidence,
    token: Option<&CapabilityToken>,
    token_context: &TokenContext<'_>,
) -> Result<(), AdmissionRefusal> {
    match *evidence {
        ConnectionEvidence::UnixSocket { peer, socket } => {
            if peer.uid != policy.expected_uid {
                return Err(AdmissionRefusal::PeerUidMismatch {
                    peer_uid: peer.uid,
                    expected_uid: policy.expected_uid,
                });
            }
            if socket.owner_uid != policy.expected_uid {
                return Err(AdmissionRefusal::SocketOwnerMismatch {
                    owner_uid: socket.owner_uid,
                    expected_uid: policy.expected_uid,
                });
            }
            if socket.mode & GROUP_OTHER_BITS != 0 {
                return Err(AdmissionRefusal::SocketModeTooOpen { mode: socket.mode });
            }
            if policy.require_token_on_unix {
                check_token(token, token_context)?;
            }
            Ok(())
        }
        ConnectionEvidence::Tcp { remote_is_loopback } => {
            if !policy.tcp_enabled {
                return Err(AdmissionRefusal::TcpDisabled);
            }
            if !remote_is_loopback {
                return Err(AdmissionRefusal::TcpNotLoopback);
            }
            // TCP carries no kernel credential: the token is the
            // authentication, so it is MANDATORY here regardless of
            // the Unix-side setting.
            check_token(token, token_context)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_tokens::{CapabilityKind, mint};

    const DAEMON_UID: u32 = 1000;

    fn policy() -> AdmissionPolicy {
        AdmissionPolicy::default_for_uid(DAEMON_UID)
    }

    fn good_unix() -> ConnectionEvidence {
        ConnectionEvidence::UnixSocket {
            peer: PeerCredentials {
                uid: DAEMON_UID,
                gid: 1000,
            },
            socket: SocketMetadata {
                owner_uid: DAEMON_UID,
                mode: 0o600,
            },
        }
    }

    fn no_token_context() -> TokenContext<'static> {
        TokenContext {
            revoked: &[],
            current_seq: 1,
            session_id: 7,
            operation_id: 9,
        }
    }

    fn token() -> CapabilityToken {
        mint(1, CapabilityKind::ExecuteAction, 7, 9, "action:abc", 100).unwrap()
    }

    #[test]
    fn c003_same_uid_clean_socket_admits_and_wrong_uid_refuses() {
        assert_eq!(
            admit(&policy(), &good_unix(), None, &no_token_context()),
            Ok(())
        );
        // THE acceptance: an unauthorized peer (different UID —
        // including root) is refused with the evidence named.
        for intruder_uid in [0u32, 1001] {
            let evidence = ConnectionEvidence::UnixSocket {
                peer: PeerCredentials {
                    uid: intruder_uid,
                    gid: 0,
                },
                socket: SocketMetadata {
                    owner_uid: DAEMON_UID,
                    mode: 0o600,
                },
            };
            assert_eq!(
                admit(&policy(), &evidence, None, &no_token_context()),
                Err(AdmissionRefusal::PeerUidMismatch {
                    peer_uid: intruder_uid,
                    expected_uid: DAEMON_UID,
                })
            );
        }
    }

    #[test]
    fn c003_wrong_owner_and_open_mode_sockets_are_refused() {
        // A socket inode planted by another user.
        let planted = ConnectionEvidence::UnixSocket {
            peer: PeerCredentials {
                uid: DAEMON_UID,
                gid: 1000,
            },
            socket: SocketMetadata {
                owner_uid: 1001,
                mode: 0o600,
            },
        };
        assert_eq!(
            admit(&policy(), &planted, None, &no_token_context()),
            Err(AdmissionRefusal::SocketOwnerMismatch {
                owner_uid: 1001,
                expected_uid: DAEMON_UID,
            })
        );
        // Group- and world-accessible modes refuse even for the right
        // peer: the inode itself is the hazard.
        for mode in [0o660, 0o606, 0o666, 0o640, 0o604] {
            let open = ConnectionEvidence::UnixSocket {
                peer: PeerCredentials {
                    uid: DAEMON_UID,
                    gid: 1000,
                },
                socket: SocketMetadata {
                    owner_uid: DAEMON_UID,
                    mode,
                },
            };
            assert_eq!(
                admit(&policy(), &open, None, &no_token_context()),
                Err(AdmissionRefusal::SocketModeTooOpen { mode }),
                "mode {mode:o} must refuse"
            );
        }
        // 0o700 (owner-only, execute bit meaningless but owner-only)
        // and 0o600 both admit.
        for mode in [0o600, 0o700] {
            let clean = ConnectionEvidence::UnixSocket {
                peer: PeerCredentials {
                    uid: DAEMON_UID,
                    gid: 1000,
                },
                socket: SocketMetadata {
                    owner_uid: DAEMON_UID,
                    mode,
                },
            };
            assert_eq!(admit(&policy(), &clean, None, &no_token_context()), Ok(()));
        }
    }

    #[test]
    fn c003_optional_unix_token_and_composed_validation() {
        let strict = AdmissionPolicy {
            require_token_on_unix: true,
            ..policy()
        };
        // Token demanded, none presented.
        assert_eq!(
            admit(&strict, &good_unix(), None, &no_token_context()),
            Err(AdmissionRefusal::TokenRequired)
        );
        // Valid token admits.
        assert_eq!(
            admit(&strict, &good_unix(), Some(&token()), &no_token_context()),
            Ok(())
        );
        // Wrong-session token refuses THROUGH the F-series validator.
        let wrong_session = TokenContext {
            session_id: 8,
            ..no_token_context()
        };
        assert_eq!(
            admit(&strict, &good_unix(), Some(&token()), &wrong_session),
            Err(AdmissionRefusal::TokenInvalid(TokenRefusal::WrongSession))
        );
    }

    #[test]
    fn c003_tcp_fallback_is_disabled_by_default_and_token_mandatory_when_enabled() {
        // Default posture: TCP refuses outright, even loopback with a
        // valid token.
        assert_eq!(
            admit(
                &policy(),
                &ConnectionEvidence::Tcp {
                    remote_is_loopback: true
                },
                Some(&token()),
                &no_token_context()
            ),
            Err(AdmissionRefusal::TcpDisabled)
        );
        let tcp_on = AdmissionPolicy {
            tcp_enabled: true,
            ..policy()
        };
        // Enabled: non-loopback refuses.
        assert_eq!(
            admit(
                &tcp_on,
                &ConnectionEvidence::Tcp {
                    remote_is_loopback: false
                },
                Some(&token()),
                &no_token_context()
            ),
            Err(AdmissionRefusal::TcpNotLoopback)
        );
        // Loopback WITHOUT a token refuses: TCP has no kernel
        // credential, so the token IS the authentication.
        assert_eq!(
            admit(
                &tcp_on,
                &ConnectionEvidence::Tcp {
                    remote_is_loopback: true
                },
                None,
                &no_token_context()
            ),
            Err(AdmissionRefusal::TokenRequired)
        );
        // Loopback with a valid token admits.
        assert_eq!(
            admit(
                &tcp_on,
                &ConnectionEvidence::Tcp {
                    remote_is_loopback: true
                },
                Some(&token()),
                &no_token_context()
            ),
            Ok(())
        );
    }
}
