//! Wrapper self-diagnostics + protocol-compatibility output (bead
//! C012; the surface `rch rabs doctor` consumes).
//!
//! A wrapper that misbehaves must be able to SAY what it sees, in one
//! bounded machine-readable report assembled purely from state the
//! wrapper already holds — no probing side effects in this module:
//!
//! - protocol compatibility: the wrapper's supported local-protocol
//!   range plus the last negotiation outcome (selected version or the
//!   both-sides ranges of an explicit refusal);
//! - edge reachability as last OBSERVED (connected / refused /
//!   timed out / never attempted) — a report never claims
//!   reachability it did not witness;
//! - breaker state (C004's persisted record, verbatim);
//! - the subscriber's delivery frontiers and the fallback permission
//!   they imply (C005 truth, not a re-derivation);
//! - the last refusal reasons as STABLE registry codes
//!   ([`crate::reason_codes`]): construction validates every code
//!   against the registry and refuses unknowns — a diagnostic report
//!   cannot mint ad-hoc reason strings;
//! - bounded: at most [`MAX_RECENT_REFUSALS`] refusals are carried,
//!   oldest dropped WITH a counter, so the report says how much it
//!   dropped instead of silently truncating.

use crate::local_protocol::{
    FallbackPermission, Negotiation, SubscriberFrontierReport, VersionRange,
};
use crate::reason_codes;
use crate::wrapper_breaker::BreakerState;

/// Refusal-history bound: the report carries at most this many.
pub const MAX_RECENT_REFUSALS: usize = 8;

/// Edge reachability as last observed by THIS wrapper process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeReachability {
    /// A connection was established and the handshake completed.
    Connected,
    /// The socket connect was refused (no listener).
    ConnectRefused,
    /// Connect or decision timed out under the C004 budgets.
    TimedOut,
    /// This wrapper never attempted a connection (e.g. breaker open,
    /// skip-to-local).
    NotAttempted,
}

impl EdgeReachability {
    /// Stable wire tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::ConnectRefused => "connect-refused",
            Self::TimedOut => "timed-out",
            Self::NotAttempted => "not-attempted",
        }
    }
}

/// Typed construction refusals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticsError {
    /// A refusal code is not in the stable registry — ad-hoc reason
    /// strings cannot enter a diagnostic report.
    UnknownReasonCode {
        /// The offending code.
        code: String,
    },
}

/// The bounded self-diagnostic report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperDiagnostics {
    /// The local-protocol range this wrapper speaks.
    pub supported_protocol: VersionRange,
    /// The last negotiation outcome, if one happened.
    pub last_negotiation: Option<Negotiation>,
    /// Edge reachability as last observed.
    pub edge_reachability: EdgeReachability,
    /// The persisted breaker state.
    pub breaker: BreakerState,
    /// The subscriber's frontier report (C005 truth).
    pub frontiers: SubscriberFrontierReport,
    /// Most recent refusal codes, registry-validated, newest last.
    recent_refusals: Vec<&'static str>,
    /// Refusals dropped by the bound (the truncation is visible).
    pub refusals_dropped: u64,
}

impl WrapperDiagnostics {
    /// Assemble a report. Every refusal code is validated against the
    /// stable registry; the newest [`MAX_RECENT_REFUSALS`] are kept
    /// and the drop count says what the bound discarded.
    ///
    /// # Errors
    /// [`DiagnosticsError::UnknownReasonCode`] on the first code not
    /// in the registry.
    pub fn assemble(
        supported_protocol: VersionRange,
        last_negotiation: Option<Negotiation>,
        edge_reachability: EdgeReachability,
        breaker: BreakerState,
        frontiers: SubscriberFrontierReport,
        refusal_codes: &[&str],
    ) -> Result<Self, DiagnosticsError> {
        let mut validated: Vec<&'static str> = Vec::with_capacity(refusal_codes.len());
        for code in refusal_codes {
            let Some(entry) = reason_codes::lookup(code) else {
                return Err(DiagnosticsError::UnknownReasonCode {
                    code: (*code).to_owned(),
                });
            };
            validated.push(entry.code);
        }
        let refusals_dropped = validated.len().saturating_sub(MAX_RECENT_REFUSALS) as u64;
        let kept: Vec<&'static str> = validated
            .split_off(validated.len().saturating_sub(MAX_RECENT_REFUSALS))
            .to_vec();
        Ok(Self {
            supported_protocol,
            last_negotiation,
            edge_reachability,
            breaker,
            frontiers,
            recent_refusals: kept,
            refusals_dropped,
        })
    }

    /// The retained refusal codes (newest last).
    #[must_use]
    pub fn recent_refusals(&self) -> &[&'static str] {
        &self.recent_refusals
    }

    /// The bounded JSON document `rch rabs doctor` consumes. Rendered
    /// by hand (this crate carries no serde): every value is a number,
    /// a fixed tag, or a registry code — nothing free-form, so the
    /// output needs no escaping and stays bounded by construction.
    #[must_use]
    pub fn to_json(&self) -> String {
        let negotiation = match &self.last_negotiation {
            None => r#""none""#.to_owned(),
            Some(Negotiation::Selected(version)) => {
                format!(r#"{{"selected":{}}}"#, version.0)
            }
            Some(Negotiation::Refused { wrapper, edge }) => format!(
                r#"{{"refused":{{"wrapper":[{},{}],"edge":[{},{}]}}}}"#,
                wrapper.min.0, wrapper.max.0, edge.min.0, edge.max.0
            ),
        };
        let breaker = match self.breaker {
            BreakerState::Closed {
                consecutive_failures,
            } => format!(r#"{{"state":"closed","consecutive_failures":{consecutive_failures}}}"#),
            BreakerState::Open {
                opened_at_ms,
                last_probe_started_at_ms,
            } => format!(
                r#"{{"state":"open","opened_at_ms":{opened_at_ms},"last_probe_started_at_ms":{}}}"#,
                last_probe_started_at_ms.map_or_else(|| "null".to_owned(), |ms| ms.to_string())
            ),
        };
        let fallback = match self.frontiers.permitted_fallback() {
            FallbackPermission::SeamlessNonpublishing => "seamless-nonpublishing",
            FallbackPermission::LabeledTranscriptRecoveryOnly => "labeled-recovery-only",
            FallbackPermission::NoUncoordinatedFallback => "no-uncoordinated-fallback",
        };
        let refusals: Vec<String> = self
            .recent_refusals
            .iter()
            .map(|c| format!(r#""{c}""#))
            .collect();
        format!(
            r#"{{"schema":"rabs.wrapper-diagnostics","schema_version":1,"supported_protocol":[{},{}],"last_negotiation":{negotiation},"edge_reachability":"{}","breaker":{breaker},"frontiers":{{"transcript_exposed":{},"transcript_uncertain":{},"stateful_intent_recorded":{},"stateful_uncertain":{},"last_fully_delivered_seq":{}}},"permitted_fallback":"{fallback}","recent_refusals":[{}],"refusals_dropped":{}}}"#,
            self.supported_protocol.min.0,
            self.supported_protocol.max.0,
            self.edge_reachability.tag(),
            self.frontiers.transcript_exposed,
            self.frontiers.transcript_uncertain,
            self.frontiers.stateful_intent_recorded,
            self.frontiers.stateful_uncertain,
            self.frontiers.last_fully_delivered_seq,
            refusals.join(","),
            self.refusals_dropped,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_protocol::LocalProtocolVersion;

    // rabs-protocol is a zero-dependency crate (no serde even in
    // tests): assertions run on the deterministic JSON text itself.

    fn frontiers() -> SubscriberFrontierReport {
        SubscriberFrontierReport {
            transcript_exposed: true,
            transcript_uncertain: false,
            stateful_intent_recorded: false,
            stateful_uncertain: false,
            last_fully_delivered_seq: 17,
        }
    }

    #[test]
    fn c012_report_assembles_and_renders_bounded_json() {
        let report = WrapperDiagnostics::assemble(
            VersionRange::exactly(1),
            Some(Negotiation::Selected(LocalProtocolVersion(1))),
            EdgeReachability::Connected,
            BreakerState::fresh(),
            frontiers(),
            &["FALLBACK_EDGE_UNAVAILABLE_ORIGINAL_CHAIN"],
        )
        .unwrap();
        let json = report.to_json();
        // Schema-tagged and carrying every section, byte-checkable
        // because nothing in the format is free-form.
        assert!(json.contains(r#""schema":"rabs.wrapper-diagnostics""#));
        assert!(json.contains(r#""supported_protocol":[1,1]"#));
        assert!(json.contains(r#""last_negotiation":{"selected":1}"#));
        assert!(json.contains(r#""edge_reachability":"connected""#));
        assert!(json.contains(r#""state":"closed","consecutive_failures":0"#));
        assert!(json.contains(r#""last_fully_delivered_seq":17"#));
        assert!(json.contains(r#""permitted_fallback":"labeled-recovery-only""#));
        assert!(json.contains(r#""recent_refusals":["FALLBACK_EDGE_UNAVAILABLE_ORIGINAL_CHAIN"]"#));
        assert!(json.contains(r#""refusals_dropped":0"#));
        // Balanced braces (well-formedness smoke check without a
        // parser dependency).
        assert_eq!(
            json.matches('{').count(),
            json.matches('}').count(),
            "unbalanced braces: {json}"
        );
    }

    #[test]
    fn c012_refusal_codes_are_registry_validated_never_ad_hoc() {
        let result = WrapperDiagnostics::assemble(
            VersionRange::exactly(1),
            None,
            EdgeReachability::NotAttempted,
            BreakerState::fresh(),
            SubscriberFrontierReport::default(),
            &["TOTALLY_MADE_UP_REASON"],
        );
        assert_eq!(
            result,
            Err(DiagnosticsError::UnknownReasonCode {
                code: "TOTALLY_MADE_UP_REASON".to_owned(),
            })
        );
    }

    #[test]
    fn c012_refusal_history_is_bounded_with_visible_drops() {
        // 12 valid refusals against a bound of 8: the NEWEST 8 stay,
        // 4 drops are counted — truncation is visible, never silent.
        let mut codes = vec!["FALLBACK_EDGE_UNAVAILABLE_ORIGINAL_CHAIN"; 11];
        codes.push("FALLBACK_UNCOORDINATED_STORM_MODE");
        let report = WrapperDiagnostics::assemble(
            VersionRange::exactly(1),
            None,
            EdgeReachability::TimedOut,
            BreakerState::Open {
                opened_at_ms: 5000,
                last_probe_started_at_ms: Some(9000),
            },
            SubscriberFrontierReport::default(),
            &codes,
        )
        .unwrap();
        assert_eq!(report.recent_refusals().len(), MAX_RECENT_REFUSALS);
        assert_eq!(report.refusals_dropped, 4);
        // Newest-last preserved: the distinct final code survives.
        assert_eq!(
            *report.recent_refusals().last().unwrap(),
            "FALLBACK_UNCOORDINATED_STORM_MODE"
        );
        let json = report.to_json();
        assert!(json.contains(r#""refusals_dropped":4"#));
        assert!(json.contains(r#""state":"open","opened_at_ms":5000"#));
        assert!(json.contains(r#""last_probe_started_at_ms":9000"#));
        assert!(json.contains(r#""edge_reachability":"timed-out""#));
    }

    #[test]
    fn c012_negotiation_refusal_carries_both_ranges() {
        // A refused negotiation is diagnosable from the report alone:
        // both sides' ranges are in the JSON (the C001 doctrine).
        let report = WrapperDiagnostics::assemble(
            VersionRange::exactly(1),
            Some(Negotiation::Refused {
                wrapper: VersionRange::exactly(1),
                edge: VersionRange::new(2, 3).unwrap(),
            }),
            EdgeReachability::Connected,
            BreakerState::fresh(),
            SubscriberFrontierReport::default(),
            &[],
        )
        .unwrap();
        let json = report.to_json();
        assert!(
            json.contains(r#""last_negotiation":{"refused":{"wrapper":[1,1],"edge":[2,3]}}"#),
            "{json}"
        );
        assert!(json.contains(r#""permitted_fallback":"seamless-nonpublishing""#));
        // An open-probe null renders as JSON null, not a string.
        let no_probe = WrapperDiagnostics::assemble(
            VersionRange::exactly(1),
            None,
            EdgeReachability::NotAttempted,
            BreakerState::Open {
                opened_at_ms: 1,
                last_probe_started_at_ms: None,
            },
            SubscriberFrontierReport::default(),
            &[],
        )
        .unwrap();
        assert!(
            no_probe
                .to_json()
                .contains(r#""last_probe_started_at_ms":null"#)
        );
    }
}
