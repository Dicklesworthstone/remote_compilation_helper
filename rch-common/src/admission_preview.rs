//! Versioned worker-placement observations with no execution authority.
//!
//! A preview uses its own route, not a flag on `/select-worker`: an older
//! daemon must reject it rather than ignore an unfamiliar flag and reserve a
//! worker. The request cannot express queue ownership, a PID, or a wrapper ID.

use crate::{
    CommandPriority, RequiredRuntime, SelectionRequest, SelectionResponse, ToolchainInfo, WorkerId,
};
use serde::{Deserialize, Serialize};

pub const ROUTE: &str = "/admission-preview";
pub const PROTOCOL_VERSION: u64 = 1;
/// Includes the HTTP-like request line, its encoded query and final newline.
pub const MAX_REQUEST_BYTES: usize = 65_536;

#[derive(Debug, thiserror::Error)]
pub enum PreviewError {
    #[error("unsupported admission-preview protocol version {0}")]
    Version(u64),
    #[error("invalid admission-preview request: {0}")]
    InvalidRequest(&'static str),
    #[error("admission preview returned execution ownership")]
    UnexpectedOwnership,
    #[error("admission preview returned inconsistent worker and reason fields")]
    InconsistentSelection,
    #[error("invalid admission-preview JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Explicit routing inputs only. Unknown fields are rejected, not silently
/// interpreted as weaker requirements; new fields require a protocol decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewRequest {
    pub protocol_version: u64,
    pub project: String,
    pub command: String,
    pub estimated_cores: u32,
    #[serde(default)]
    pub disk_headroom_gib: u32,
    #[serde(default)]
    pub preferred_workers: Vec<WorkerId>,
    #[serde(default)]
    pub toolchain: Option<ToolchainInfo>,
    #[serde(default)]
    pub required_runtime: RequiredRuntime,
    #[serde(default)]
    pub job_mode: bool,
    #[serde(default)]
    pub required_tools: Vec<String>,
}

impl PreviewRequest {
    pub fn validate(&self) -> Result<(), PreviewError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(PreviewError::Version(self.protocol_version));
        }
        if self.project.trim().is_empty() || self.command.trim().is_empty() {
            return Err(PreviewError::InvalidRequest(
                "project and command are required",
            ));
        }
        if self.estimated_cores == 0 {
            return Err(PreviewError::InvalidRequest(
                "estimated_cores must be positive",
            ));
        }
        if self.required_tools.iter().any(|tool| tool.trim().is_empty())
            || self
                .preferred_workers
                .iter()
                .any(|worker| worker.as_str().trim().is_empty())
        {
            return Err(PreviewError::InvalidRequest(
                "empty worker or tool requirement",
            ));
        }
        Ok(())
    }

    /// Convert without acquiring or importing any execution identity.
    pub fn into_selection(self) -> Result<SelectionRequest, PreviewError> {
        self.validate()?;
        Ok(SelectionRequest {
            project: self.project,
            command: Some(self.command),
            command_priority: CommandPriority::Normal,
            estimated_cores: self.estimated_cores,
            disk_headroom_gib: self.disk_headroom_gib,
            preferred_workers: self.preferred_workers,
            toolchain: self.toolchain,
            required_runtime: self.required_runtime,
            classification_duration_us: None,
            job_mode: self.job_mode,
            required_tools: self.required_tools,
            hook_pid: None,
        })
    }

    /// Encode one bounded, newline-terminated request. Percent encoding keeps
    /// commands containing `&`, `+`, `?`, Unicode or newlines inside the JSON.
    pub fn request_line(&self) -> Result<String, PreviewError> {
        self.validate()?;
        let json = serde_json::to_vec(self)?;
        let mut line = format!("GET {ROUTE}?request=");
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        for byte in json {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                line.push(char::from(byte));
            } else {
                line.push('%');
                line.push(char::from(HEX[usize::from(byte >> 4)]));
                line.push(char::from(HEX[usize::from(byte & 15)]));
            }
            if line.len() >= MAX_REQUEST_BYTES {
                return Err(PreviewError::InvalidRequest(
                    "request exceeds the daemon line limit",
                ));
            }
        }
        line.push('\n');
        Ok(line)
    }

    /// Decode exactly one query parameter. Never lossy-decode UTF-8 or accept
    /// another parameter that could masquerade as an execution control.
    pub fn from_query(query: &str) -> Result<Self, PreviewError> {
        let raw = query
            .strip_prefix("request=")
            .ok_or(PreviewError::InvalidRequest(
                "expected exactly one request parameter",
            ))?;
        if raw.contains('&') || query.len() > MAX_REQUEST_BYTES {
            return Err(PreviewError::InvalidRequest("unexpected or oversized query"));
        }
        let mut bytes = Vec::with_capacity(raw.len());
        let mut input = raw.bytes();
        while let Some(byte) = input.next() {
            match byte {
                b'%' => {
                    let high = input.next().and_then(hex_value);
                    let low = input.next().and_then(hex_value);
                    let (Some(high), Some(low)) = (high, low) else {
                        return Err(PreviewError::InvalidRequest("invalid percent escape"));
                    };
                    bytes.push((high << 4) | low);
                }
                b'+' => bytes.push(b' '),
                byte => bytes.push(byte),
            }
        }
        // serde_json::from_slice rejects non-UTF-8 JSON strings; no replacement
        // characters can silently change the command or its requirements.
        let request: Self = serde_json::from_slice(&bytes)?;
        request.validate()?;
        Ok(request)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Only this versioned envelope is accepted by preview clients. A legacy
/// selection response is not evidence that the daemon honored read-only mode.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewResponse {
    pub protocol_version: u64,
    pub selection: SelectionResponse,
}

impl PreviewResponse {
    pub fn validate(&self) -> Result<(), PreviewError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(PreviewError::Version(self.protocol_version));
        }
        if self.selection.build_id.is_some() {
            return Err(PreviewError::UnexpectedOwnership);
        }
        let assigned = matches!(
            self.selection.reason,
            crate::SelectionReason::Success
                | crate::SelectionReason::AffinityPinned
                | crate::SelectionReason::AffinityFallback
        );
        if assigned != self.selection.worker.is_some() {
            return Err(PreviewError::InconsistentSelection);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SelectionReason;

    fn request() -> PreviewRequest {
        PreviewRequest {
            protocol_version: PROTOCOL_VERSION,
            project: "project with spaces".into(),
            command: "env NOTE='a&b=c+%? λ\\n' cargo +nightly check".into(),
            estimated_cores: 7,
            disk_headroom_gib: 31,
            preferred_workers: vec![WorkerId::new("worker-b")],
            toolchain: Some(ToolchainInfo {
                channel: "nightly".into(),
                date: None,
                full_version: "nightly".into(),
            }),
            required_runtime: RequiredRuntime::Rust,
            job_mode: true,
            required_tools: vec!["clang".into(), "llvm-ar".into()],
        }
    }

    fn encoded_query(json: &str) -> String {
        // Deliberately encode every byte, independently of request_line's
        // unreserved-byte fast path. Invalid-field tests must reach JSON
        // validation rather than fail on an unrelated '&' in the command.
        let mut query = String::from("request=");
        for byte in json.bytes() {
            query.push_str(&format!("%{byte:02X}"));
        }
        query
    }

    #[test]
    fn preview_roundtrip_preserves_every_routing_constraint_without_ownership() {
        let original = request();
        let line = original.request_line().unwrap();
        assert_eq!(line.lines().count(), 1);
        assert!(line.starts_with("GET /admission-preview?request="));
        assert!(!line.contains("/select-worker"));
        let query = line.trim_end_matches('\n').split_once('?').unwrap().1;
        let decoded = PreviewRequest::from_query(query).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        let selection = decoded.into_selection().unwrap();
        assert_eq!(selection.project, original.project);
        assert_eq!(selection.command.as_deref(), Some(original.command.as_str()));
        assert_eq!(selection.estimated_cores, 7);
        assert_eq!(selection.disk_headroom_gib, 31);
        assert_eq!(selection.preferred_workers, original.preferred_workers);
        assert_eq!(selection.required_tools, original.required_tools);
        assert_eq!(selection.required_runtime, RequiredRuntime::Rust);
        assert!(selection.job_mode);
        assert!(selection.hook_pid.is_none());
        assert!(selection.classification_duration_us.is_none());
        assert_eq!(selection.toolchain.unwrap().full_version, "nightly");
    }

    #[test]
    fn preview_rejects_execution_controls_unknown_constraints_and_duplicate_fields() {
        assert!(
            PreviewRequest::from_query(&encoded_query(
                &serde_json::to_string(&request()).unwrap()
            ))
            .is_ok()
        );
        for name in [
            "wait",
            "queue",
            "hook_pid",
            "local_wrapper_id",
            "dry_run",
            "future_requirement",
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value[name] = serde_json::json!(1);
            let error = PreviewRequest::from_query(&encoded_query(&value.to_string())).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{name}: {error}");
        }
        let json = serde_json::to_string(&request()).unwrap();
        let duplicate = format!("{{\"estimated_cores\":1,{}", &json[1..]);
        let error = PreviewRequest::from_query(&encoded_query(&duplicate)).unwrap_err();
        assert!(error.to_string().contains("duplicate field"), "{error}");
        let valid = request().request_line().unwrap();
        let query = valid.trim_end().split_once('?').unwrap().1;
        for tail in ["&wait=1", "&dry_run=0", "&request={}"] {
            assert!(PreviewRequest::from_query(&format!("{query}{tail}")).is_err());
        }
    }

    #[test]
    fn preview_refuses_invalid_encoding_versions_and_request_sizes() {
        for query in [
            "request=%",
            "request=%G0",
            "request=%0",
            "request=%FF",
            "project=test",
        ] {
            assert!(PreviewRequest::from_query(query).is_err(), "{query}");
        }
        let mut invalid = request();
        invalid.protocol_version += 1;
        assert!(invalid.request_line().is_err());
        invalid = request();
        invalid.estimated_cores = 0;
        assert!(invalid.request_line().is_err());
        invalid = request();
        invalid.command = "λ".repeat(MAX_REQUEST_BYTES);
        assert!(invalid.request_line().is_err());
    }

    #[test]
    fn preview_response_requires_a_version_and_cannot_own_a_build() {
        let selection = SelectionResponse {
            worker: None,
            reason: SelectionReason::AllWorkersBusy,
            build_id: None,
            diagnostics: None,
        };
        let legacy = serde_json::to_vec(&selection).unwrap();
        assert!(serde_json::from_slice::<PreviewResponse>(&legacy).is_err());
        let mut response = PreviewResponse {
            protocol_version: PROTOCOL_VERSION,
            selection,
        };
        assert!(response.validate().is_ok());
        response.protocol_version += 1;
        assert!(response.validate().is_err());
        response.protocol_version = PROTOCOL_VERSION;
        response.selection.build_id = Some(1);
        assert!(matches!(
            response.validate(),
            Err(PreviewError::UnexpectedOwnership)
        ));
        response.selection.build_id = None;
        response.selection.reason = SelectionReason::Success;
        assert!(matches!(
            response.validate(),
            Err(PreviewError::InconsistentSelection)
        ));
    }
}
