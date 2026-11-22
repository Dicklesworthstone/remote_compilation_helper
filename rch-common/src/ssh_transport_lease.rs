//! A local, connection-owned borrow of the daemon's authenticated SSH master.
//!
//! The socket remains open from `Ready` through `Released`. These frames grant
//! transport use only; worker admission, remote execution and recovery keep
//! their existing identities and authority. No frame permits direct redial.

use crate::{WorkerConfig, WorkerId, declared_os};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

pub const SSH_TRANSPORT_LEASE_ROUTE: &str = "/ssh-transport-v1";
pub const SSH_TRANSPORT_LEASE_VERSION: u32 = 1;
pub const MAX_SSH_TRANSPORT_LEASE_FRAME_BYTES: usize = 16 * 1024;
pub const SSH_TRANSPORT_LEASE_ACQUIRE_TIMEOUT_MS: u64 = 30_000;

/// Coordinates must match both the admitted build and the current worker.
/// An SSH control socket selects its original host regardless of later argv.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTransportEndpoint {
    pub worker_id: WorkerId,
    pub host: String,
    pub user: String,
    pub identity_file: String,
    pub declared_os: Option<String>,
}

impl SshTransportEndpoint {
    #[must_use]
    pub fn from_worker(worker: &WorkerConfig) -> Self {
        Self {
            worker_id: worker.id.clone(),
            host: worker.host.clone(),
            user: worker.user.clone(),
            identity_file: worker.identity_file.clone(),
            declared_os: declared_os(&worker.tags),
        }
    }

    #[must_use]
    pub fn matches_worker(&self, worker: &WorkerConfig) -> bool {
        self == &Self::from_worker(worker)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTransportLeaseRequest {
    pub version: u32,
    pub build_id: u64,
    pub local_wrapper_id: String,
    pub endpoint: SshTransportEndpoint,
    pub server_alive_interval_secs: u64,
    pub idle_timeout_secs: u64,
}

impl SshTransportLeaseRequest {
    /// Bound the frame independently of the socket reader's byte ceiling.
    /// Process birth and admission are verified by the daemon, not this type.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != SSH_TRANSPORT_LEASE_VERSION || self.build_id == 0 {
            return Err("unsupported SSH transport lease version or build identity".into());
        }
        if self.idle_timeout_secs == 0 {
            return Err("SSH transport leasing requires a positive idle timeout".into());
        }
        if !self
            .local_wrapper_id
            .starts_with(crate::job_identity::LOCAL_WRAPPER_ID_PREFIX)
            || self.local_wrapper_id.len() > 128
            || self.local_wrapper_id.len() <= crate::job_identity::LOCAL_WRAPPER_ID_PREFIX.len()
            || !self
                .local_wrapper_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("invalid SSH transport lease wrapper identity".into());
        }
        for value in [
            self.endpoint.worker_id.as_str(),
            self.endpoint.host.as_str(),
            self.endpoint.user.as_str(),
            self.endpoint.identity_file.as_str(),
        ] {
            if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                return Err("invalid SSH transport endpoint".into());
            }
        }
        if self.endpoint.declared_os.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 64 || value.chars().any(char::is_control)
        }) {
            return Err("invalid SSH transport endpoint OS".into());
        }
        Ok(())
    }
}

/// Each variant is one bounded newline-terminated JSON frame. `Unavailable`
/// permits the existing owned per-dispatch transport before any operation;
/// `Rejected` is an admission failure and must never be downgraded that way.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SshTransportLeaseResponse {
    Ready {
        request: SshTransportLeaseRequest,
        arguments: Vec<String>,
    },
    Unavailable {
        version: u32,
        reason: String,
    },
    Rejected {
        version: u32,
        reason: String,
    },
    Revoked {
        version: u32,
        reason: String,
    },
    Released {
        version: u32,
        build_id: u64,
        local_wrapper_id: String,
    },
}

/// Sent only after all attached channels have completed and been reaped.
/// Dropping the connection without this frame abandons the active-use guard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshTransportLeaseFinish {
    pub version: u32,
    pub build_id: u64,
    pub local_wrapper_id: String,
}

impl SshTransportLeaseFinish {
    #[must_use]
    pub fn matches_request(&self, request: &SshTransportLeaseRequest) -> bool {
        self.version == SSH_TRANSPORT_LEASE_VERSION
            && self.version == request.version
            && self.build_id == request.build_id
            && self.local_wrapper_id == request.local_wrapper_id
    }
}

/// Accept only the arguments issued by `OwnedSshTransport`. A malformed or
/// newer daemon reply must not introduce a proxy, destination, command or
/// OpenSSH background owner into the client's execution path.
pub fn validate_transport_arguments(arguments: &[String]) -> Result<(), String> {
    if !matches!(arguments.len(), 13 | 15) || arguments[0] != "-S" {
        return Err("invalid SSH transport attachment arguments".into());
    }
    let socket = Path::new(&arguments[1]);
    if arguments[1].len() > 4096
        || arguments[1].chars().any(char::is_control)
        || !socket.is_absolute()
        || !socket
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err("invalid SSH transport control socket".into());
    }
    let fixed = [
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPersist=no",
        "-o",
        "ProxyCommand=false",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "BatchMode=yes",
    ];
    if !arguments[2..12].iter().map(String::as_str).eq(fixed) {
        return Err("SSH transport attachment changed its no-redial policy".into());
    }
    if arguments[12..] != ["-T"] && arguments[12..] != ["-o", "ForkAfterAuthentication=no", "-T"] {
        return Err("invalid SSH transport attachment suffix".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments() -> Vec<String> {
        [
            "-S",
            "/tmp/rch test/master",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPersist=no",
            "-o",
            "ProxyCommand=false",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "BatchMode=yes",
            "-T",
        ]
        .map(str::to_owned)
        .to_vec()
    }

    #[test]
    fn ssh_transport_lease_attachment_refuses_redial_and_extra_argv() {
        let plain = arguments();
        validate_transport_arguments(&plain).unwrap();
        let mut foreground = plain.clone();
        foreground.splice(12..12, ["-o".into(), "ForkAfterAuthentication=no".into()]);
        validate_transport_arguments(&foreground).unwrap();
        for replacement in [
            "ProxyCommand=ssh elsewhere",
            "ProxyJump=elsewhere",
            "ControlMaster=auto",
        ] {
            let mut changed = plain.clone();
            changed[7] = replacement.into();
            assert!(validate_transport_arguments(&changed).is_err());
        }
        for socket in [
            "relative/master",
            "/tmp/../other/master",
            "/tmp/bad\nmaster",
        ] {
            let mut changed = plain.clone();
            changed[1] = socket.into();
            assert!(validate_transport_arguments(&changed).is_err());
        }
        let mut extra = plain;
        extra.push("other-host".into());
        assert!(validate_transport_arguments(&extra).is_err());
        assert!(validate_transport_arguments(&[]).is_err());
    }

    #[test]
    fn ssh_transport_lease_frames_preserve_exact_owner_and_reject_unknown_fields() {
        let request = SshTransportLeaseRequest {
            version: SSH_TRANSPORT_LEASE_VERSION,
            build_id: 17,
            local_wrapper_id: "rchw-owner".into(),
            endpoint: SshTransportEndpoint {
                worker_id: WorkerId::new("worker"),
                host: "host".into(),
                user: "builder".into(),
                identity_file: "/home/builder/.ssh/key with spaces".into(),
                declared_os: None,
            },
            server_alive_interval_secs: 15,
            idle_timeout_secs: 60,
        };
        request.validate().unwrap();
        let ready = SshTransportLeaseResponse::Ready {
            request: request.clone(),
            arguments: arguments(),
        };
        assert_eq!(
            serde_json::from_str::<SshTransportLeaseResponse>(
                &serde_json::to_string(&ready).unwrap()
            )
            .unwrap(),
            ready
        );
        let mut finish = SshTransportLeaseFinish {
            version: SSH_TRANSPORT_LEASE_VERSION,
            build_id: request.build_id,
            local_wrapper_id: request.local_wrapper_id.clone(),
        };
        assert!(finish.matches_request(&request));
        finish.build_id += 1;
        assert!(!finish.matches_request(&request));
        finish.build_id = request.build_id;
        finish.local_wrapper_id = "rchw-other".into();
        assert!(!finish.matches_request(&request));
        let mut encoded = serde_json::to_value(&ready).unwrap();
        encoded["redial"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SshTransportLeaseResponse>(encoded).is_err());
    }
}
