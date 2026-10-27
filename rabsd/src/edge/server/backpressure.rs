//! Cooperative backpressure before a live compiler decision or hit acceptance.
//!
//! Initial decisions acquire their permit from the existing blocking lane.
//! Only its synchronous Saturated refusal proves the decision closure never
//! ran. A verified hit may use the same hint before acceptance when its
//! independent installation lane has no capacity and its preview is dropped.
//! Work errors after admission cannot turn into this hint. There is no server
//! queue, action reservation, output writer, or capacity permit behind the reply.
//!
//! Keep pass-through as the wire decision: older wrappers compile normally.
//! New wrappers recognize the explicit versioned hint, retain their original
//! request/action identity, and use their existing bounded non-owning wait.

use super::liveness::{Limit, WorkError};
use super::rustc_request::{self, Decided, LiveEdge};
use serde_json::Value;
use std::sync::Arc;

const CAPACITY_RETRY: &str = concat!(
    "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",",
    "\"reason\":\"edge-capacity\",\"retry\":\"decision-capacity-v1\",",
    "\"compiler_skip_authorized\":false,\"materialization_started\":false}",
);
const CAPACITY_LEGACY: &str =
    "{\"kind\":\"rustc-decision\",\"decision\":\"pass-through\",\"reason\":\"edge-capacity\"}";

/// Report a capacity refusal before compiler or installation authority exists.
/// The phase is diagnostic only; keep the established retry wire contract.
pub(super) fn capacity_reply(may_wait: bool, phase: &str) -> String {
    super::log_line(
        "rabsd-live-dependency",
        &[
            (
                "decision",
                if may_wait {
                    "capacity-wait"
                } else {
                    "pass-through"
                },
            ),
            ("reason", "edge-capacity"),
            ("phase", phase),
        ],
    );
    if may_wait {
        CAPACITY_RETRY
    } else {
        CAPACITY_LEGACY
    }
    .to_owned()
}

/// This entry point is for INITIAL decisions only, never accepted-hit
/// installation, compiler completion, capture acknowledgment, or publication.
pub(super) async fn decide(
    lane: &Limit,
    live: Arc<LiveEdge>,
    request: Value,
) -> Result<Decided, WorkError> {
    let may_wait = request.get("wait_for_inflight").and_then(Value::as_bool) == Some(true);
    on_lane(lane, may_wait, move || {
        rustc_request::decide(&live, &request)
    })
    .await
}

async fn on_lane(
    lane: &Limit,
    may_wait: bool,
    work: impl FnOnce() -> Decided + Send + 'static,
) -> Result<Decided, WorkError> {
    match lane.spawn(work) {
        Ok(mut work) => work.wait().await,
        Err(WorkError::Saturated) => Ok(Decided::Reply(capacity_reply(may_wait, "decision"))),
        // Do not broaden this to arbitrary errors. A panic in an admitted
        // decision may already have reserved an attempt; its owner must settle
        // through the existing error path, not a synthetic non-owning wait.
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "backpressure_tests.rs"]
mod tests;
