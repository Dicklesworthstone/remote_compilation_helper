//! Live custody of one authenticated terminal result before byte delivery.
//!
//! This evidence is created only by the ordinary receiver after validating a
//! successful, drained, durably sealed execution result and its exact declared
//! artifact manifest. It is never serialized or reconstructed from a receipt.
//! A still-owned live attempt may use it for one bounded result-only reconnect;
//! generic operator recovery does not acquire execution or publication rights.

use super::{
    Delivery, MAX_FRAME_BYTES, RESULT_RETENTION, WorkerAuthentication, digest, hash, is_hex,
    number, require, text,
};
use serde_json::{Map, Value};
use std::io;
use std::time::Instant;

/// An authenticated execution's sealed terminal metadata, not verified bytes.
///
/// Private fields and construction keep saved JSON, generic resumed receipts,
/// worker claims and unauthenticated peers from creating this live capability.
/// Cloning retains the exact original identities and absolute deadline. The
/// owning worker reservation independently limits continuation to one attempt.
#[derive(Debug, Clone)]
pub struct SealedResult {
    request_id: u64,
    request_sha256: String,
    worker: String,
    authentication: WorkerAuthentication,
    boot_generation: u64,
    incarnation: String,
    result: Value,
    total_bytes: u64,
    deadline: Instant,
}

// Spool reconstruction may change scratch spill paths. These fields instead
// bind every terminal outcome, complete transcript, artifact and transfer
// promise that can affect a live continuation. The full artifact manifest
// includes path names, byte identities, executable modes and directory layout.
const RESULT_FIELDS: [&str; 18] = [
    "kind",
    "request_id",
    "exit_code",
    "executed",
    "residual_group_members",
    "stop_reason",
    "output_transfer",
    "stdout_bytes",
    "stdout_sha256",
    "stderr_bytes",
    "stderr_sha256",
    "output_ack_required",
    "artifact_transfer",
    "artifact_manifest",
    "artifact_ack_required",
    "result_retention",
    "retained_result_sha256",
    "publication_authorized",
];

fn result_projection(result: &Value) -> Value {
    Value::Object(
        RESULT_FIELDS
            .into_iter()
            .map(|field| (field.to_owned(), result[field].clone()))
            .collect::<Map<_, _>>(),
    )
}

fn request_digest(request: &Value) -> io::Result<String> {
    let bytes = serde_json::to_vec(request)?;
    require(
        bytes.len() <= MAX_FRAME_BYTES,
        "live continuation request exceeds the frame bound",
    )?;
    Ok(hash(&bytes))
}

impl SealedResult {
    /// Called only after the ordinary receiver has validated the complete
    /// manifest against the request and checked its aggregate byte allowance.
    pub(super) fn observe(
        request: &Value,
        worker: &str,
        hello: &Value,
        authentication: Option<WorkerAuthentication>,
        result: &Value,
        total_bytes: u64,
        deadline: Option<Instant>,
    ) -> io::Result<Option<Self>> {
        let (Some(authentication), Some(deadline)) = (authentication, deadline) else {
            return Ok(None);
        };
        // Missing or expired transport custody never turns a result claim into
        // a continuation. Failed executions and result-only sessions cannot
        // mint evidence, even if their spool and transfer are otherwise valid.
        if deadline <= Instant::now()
            || authentication.session_id == 0
            || authentication.identity_generation == 0
            || result["resumed"] == true
            || result["executed"] != true
            || result["residual_group_members"].as_u64() != Some(0)
            || result["exit_code"].as_i64() != Some(0)
            || !result.get("stop_reason").is_some_and(Value::is_null)
            || result["result_retention"] != RESULT_RETENTION
            || result["output_transfer"] != "ranges-v1"
            || result["output_ack_required"] != true
            || result["artifact_transfer"] != "files-v1"
            || result["artifact_ack_required"] != true
            || !result["artifact_manifest"].is_object()
        {
            return Ok(None);
        }
        let request_id = number(request, "request_id")?;
        let boot_generation = number(hello, "boot_generation")?;
        let incarnation = text(hello, "incarnation")?;
        require(
            request["kind"] == "canonical-exec"
                && request_id != 0
                && result["kind"] == "exec-result"
                && result["request_id"].as_u64() == Some(request_id)
                && hello["worker_id"].as_str() == Some(worker)
                && boot_generation != 0
                && is_hex(incarnation, 32)
                && incarnation.bytes().any(|byte| byte != b'0'),
            "sealed result does not bind the admitted execution identity",
        )?;
        digest(result, "retained_result_sha256")?;
        Ok(Some(Self {
            request_id,
            request_sha256: request_digest(request)?,
            worker: worker.to_owned(),
            authentication,
            boot_generation,
            incarnation: incarnation.to_owned(),
            result: result_projection(result),
            total_bytes,
            deadline,
        }))
    }

    /// The first execution session's transfer deadline, never a fresh budget.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    fn matches_worker(&self, peer: &str, boot_generation: u64, incarnation: u128) -> bool {
        let spki: String = self
            .authentication
            .spki_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        peer == spki
            && boot_generation == self.boot_generation
            && format!("{incarnation:032x}") == self.incarnation
    }

    /// Bind the observation to the original retained execution authority's
    /// worker. The caller still validates that authority's action, generation,
    /// attempt and lease against its live coordinator owner.
    pub fn verify_authority(
        &self,
        authority: &rabs_protocol::generation::AttemptAuthority,
    ) -> io::Result<()> {
        require(
            self.matches_worker(
                &authority.worker_peer_id.0,
                authority.worker_boot_generation.0,
                authority.worker_incarnation_id.0,
            ),
            "sealed result differs from the retained live attempt authority",
        )
    }

    /// Bind the observation to the still-owned original worker session. A
    /// different boot or process cannot borrow this result-only continuation.
    pub fn verify_session(
        &self,
        session: &rabs_protocol::worker_fence::WorkerSessionOffer,
    ) -> io::Result<()> {
        require(
            self.matches_worker(
                &session.worker_peer_id.0,
                session.boot_generation.0,
                session.incarnation.0,
            ),
            "sealed result differs from the retained live worker session",
        )
    }

    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "live result continuation exceeded its original transfer deadline",
            ));
        }
        Ok(())
    }

    fn request_matches(&self, request: &Value) -> io::Result<()> {
        require(
            request["kind"] == "canonical-exec"
                && request["request_id"].as_u64() == Some(self.request_id)
                && request_digest(request)? == self.request_sha256,
            "live continuation differs from its exact original request",
        )
    }

    /// Check local intent before connecting or sending any recovery request.
    pub fn verify_request(&self, request: &Value) -> io::Result<()> {
        self.check_deadline()?;
        self.request_matches(request)
    }

    /// Require the same authenticated worker process, not merely the same pin.
    /// The new TLS session has its own challenge/session ID; its transport proof
    /// must retain the original identity generation and exact boot/incarnation.
    pub fn verify_peer(
        &self,
        hello: &Value,
        authentication: WorkerAuthentication,
    ) -> io::Result<()> {
        self.check_deadline()?;
        require(
            authentication.spki_sha256 == self.authentication.spki_sha256
                && authentication.identity_generation == self.authentication.identity_generation
                && authentication.session_id != 0
                && hello["worker_id"].as_str() == Some(self.worker.as_str())
                && hello["boot_generation"].as_u64() == Some(self.boot_generation)
                && hello["incarnation"].as_str() == Some(self.incarnation.as_str())
                && hello["request_high_water"].as_u64() == Some(self.request_id),
            "live continuation does not bind the original authenticated worker process",
        )
    }

    /// Compare every terminal/output identity before reading or acknowledging
    /// the resumed spool. The retained digest alone cannot substitute a changed
    /// manifest, transcript, mode or outcome under the original live attempt.
    pub fn verify_result(&self, result: &Value) -> io::Result<()> {
        self.check_deadline()?;
        require(
            result["resumed"] == true && result_projection(result) == self.result,
            "live continuation returned a different sealed result",
        )
    }

    /// Recheck a completely verified continuation against its original live
    /// custody. The caller must ALSO retain and validate the existing action,
    /// generation, attempt, worker session and original inputs. This does not
    /// authorize a generic resumed receipt or reconstruct any of those owners.
    ///
    /// Local capture/publication after delivery may take additional time; the
    /// transport already bounded transfer and ACK attempts by the original
    /// deadline; a missing ACK confirmation remains explicitly unconfirmed.
    pub fn verify_delivery(&self, delivery: &Delivery, request: &Value) -> io::Result<()> {
        self.request_matches(request)?;
        let receipt = &delivery.receipt;
        let spki: String = self
            .authentication
            .spki_sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        require(
            receipt["version"] == 1
                && receipt["kind"] == "verified-worker-delivery"
                && receipt["resumed"] == true
                && receipt["worker_identity_scope"] == "delivery-session"
                && receipt
                    .get("execution_boot_generation")
                    .is_some_and(Value::is_null)
                && receipt["transport_authenticated"] == true
                && receipt["worker_id"].as_str() == Some(self.worker.as_str())
                && receipt["worker_spki_sha256"].as_str() == Some(spki.as_str())
                && receipt["boot_generation"].as_u64() == Some(self.boot_generation)
                && receipt["incarnation"].as_str() == Some(self.incarnation.as_str())
                && receipt["identity_generation"].as_u64()
                    == Some(u64::from(self.authentication.identity_generation))
                && receipt["authenticated_session_id"]
                    .as_u64()
                    .is_some_and(|session| session != 0)
                && receipt["request_id"].as_u64() == Some(self.request_id)
                && receipt["request_sha256"].as_str() == Some(self.request_sha256.as_str())
                && receipt["total_bytes"].as_u64() == Some(self.total_bytes)
                && [
                    "exit_code",
                    "stop_reason",
                    "stdout_bytes",
                    "stdout_sha256",
                    "stderr_bytes",
                    "stderr_sha256",
                    "artifact_manifest",
                    "result_retention",
                    "retained_result_sha256",
                ]
                .into_iter()
                .all(|field| receipt[field] == self.result[field]),
            "verified continuation differs from the original sealed execution result",
        )
    }
}
