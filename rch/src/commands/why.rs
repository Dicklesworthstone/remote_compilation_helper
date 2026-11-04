//! `rch why` — recorded action state, cache-miss attribution and refusal codes
//! (plan §102; bead K009).
//!
//! A miss explanation is the structured diff of two key breakdowns
//! (`rabs_key::diff_breakdowns`, bead F013) surfaced with STABLE reason
//! codes; index-level refusals render `LookupOutcome` codes. This is an
//! offline input path remains available. `why action` reads one consistent
//! snapshot of the daemon's existing metadata without creating or migrating
//! it. Recorded serving state is not current coordinator authorization.
//!
//! Stream separation holds: stdout carries data (human lines or the
//! JSON envelope); stderr carries diagnostics only.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use rabs_cas::action_inspection::{self, ActionInspection};
use rabs_key::action_key::{ActionKeyBreakdown, BreakdownComponent};
use rabs_key::key_diff::{LookupOutcome, diff_breakdowns};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use serde::Deserialize;

use crate::ui::context::OutputContext;
use rch_common::ApiResponse;

/// Subcommands under `rch why`.
#[derive(Subcommand, Debug)]
pub enum WhyAction {
    /// Inspect an action's recorded publication, serving state and key components
    #[command(
        after_help = "EXAMPLES:\n    rch why action <64-hex-action-key>\n    rch --json why action <action-key> --cas-root /path/to/rabs-state/cas"
    )]
    Action {
        /// SHA-256 action key, bare or prefixed with rabs.action-key.sha256.v1:
        key: String,
        /// Existing CAS root; defaults to RABS_STATE_DIR/cas or ~/.cache/rch/rabs-state/cas
        #[arg(long)]
        cas_root: Option<PathBuf>,
    },
    /// Explain a miss: structured diff of prior vs current key breakdowns
    #[command(
        after_help = "EXAMPLES:\n    rch why miss --prior prior.json --current current.json\n    cat current.json | rch why miss --prior prior.json --current -"
    )]
    Miss {
        /// Prior breakdown JSON path, or `-` for stdin
        #[arg(long)]
        prior: String,
        /// Current breakdown JSON path, or `-` for stdin
        #[arg(long)]
        current: String,
    },
    /// Explain an index-level refusal with its stable reason code
    #[command(
        after_help = "EXAMPLES:\n    rch why refusal --outcome first-seen\n    rch why refusal --outcome trust-refused"
    )]
    Refusal {
        /// Refusal outcome code (first-seen | serving-blocked |
        /// trust-refused | materialization-unavailable)
        #[arg(long)]
        outcome: String,
    },
}

/// One explained cause in its wire form.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct CauseExplanation {
    /// Stable reason code (never renamed; consumers match on it).
    pub code: &'static str,
    /// Human-readable one-line explanation.
    pub explanation: &'static str,
}

/// The full miss explanation payload (JSON-envelope data field).
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct MissExplanation {
    /// True when prior and current breakdowns agree (expected HIT).
    pub identical: bool,
    /// Every cause, canonical order (epoch/class first).
    pub causes: Vec<CauseExplanation>,
}

/// The refusal explanation payload.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RefusalExplanation {
    /// Stable reason code.
    pub code: &'static str,
    /// Human-readable one-line explanation.
    pub explanation: &'static str,
}

/// Bounded recorded rows; truncation must remain visible to callers.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedRows<T> {
    /// Rows present in the read snapshot, in stable order.
    pub items: Vec<T>,
    /// More rows exist than this inspection returns.
    pub truncated: bool,
}

/// Epochs from the actual action entry.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedActionEntry {
    /// Recorded action-key epoch.
    pub key_epoch: u32,
    /// Recorded result-projection epoch.
    pub projection_epoch: u32,
}

/// A committed publication, retained independently of its serving disposition.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedPublication {
    /// Typed canonical descriptor digest.
    pub descriptor: String,
    /// Typed canonical result-manifest digest.
    pub manifest: String,
    /// Winning generation identifier, in hexadecimal.
    pub winner_generation: String,
    /// Winning attempt identifier, in hexadecimal.
    pub winner_attempt: String,
    /// Recorded winning worker; absence is not a scheduler explanation.
    pub winner_worker: Option<String>,
    /// Recorded result kind, including deterministic failures.
    pub result_kind: String,
    /// Publication reachability pin identifier.
    pub pin_id: String,
}

/// Persisted serving evidence; no current clock or authority is inferred.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedServing {
    /// Recorded serving disposition.
    pub disposition: String,
    /// Stored serving schema version.
    pub version: u32,
    /// Monotonic serving-state revision.
    pub state_revision: u64,
    /// Authority that recorded this state.
    pub authority_key: String,
    /// Recorded evaluation time in its own clock domain.
    pub evaluated_at_micros: i64,
    /// Recorded maximum age, if bounded.
    pub max_age_micros: Option<u64>,
    /// Clock uncertainty recorded with the evaluation.
    pub clock_uncertainty_micros: u64,
    /// Evaluation clock epoch; this command does not establish the live epoch.
    pub clock_epoch: u64,
}

/// Legacy trust state and its recorded reason, separate from the live ledger.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedTrust {
    /// Stored trust state.
    pub state: String,
    /// Stored explanation, not a newly evaluated trust decision.
    pub reason: String,
}

/// Latest versioned evaluation from the live coordinator's append-only ledger.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedTrustEvaluation {
    /// Monotonic evaluation version.
    pub version: u32,
    /// Recorded evaluation state; access still depends on the requested tier.
    pub state: String,
    /// Evaluation's recorded reason.
    pub reason: String,
    /// Logical sequence of this evaluation.
    pub evaluated_seq: u64,
}

/// One named blocking reference and any corresponding quarantine reason.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedQuarantine {
    /// Quarantine scope.
    pub scope: String,
    /// Referenced subject.
    pub subject: String,
    /// None when the reference has no corresponding quarantine row.
    pub reason: Option<String>,
}

/// A component digest actually present in the metadata snapshot.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedComponent {
    /// Recorded component name.
    pub component: String,
    /// Recorded digest algorithm.
    pub algorithm: String,
    /// Recorded semantic digest domain.
    pub domain: String,
    /// Full digest bytes in lowercase hexadecimal.
    pub digest_hex: String,
}

/// Live-backed action diagnosis from one read-only metadata snapshot.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct ActionExplanation {
    /// Normalized typed action key.
    pub action_key: String,
    /// Metadata database that supplied these observations.
    pub metadata_path: String,
    /// Observed database schema version.
    pub schema_version: u32,
    /// Whether the inspected tables contain recorded facts for this action.
    pub observed: bool,
    /// Stable observation code; never a current cache-hit authorization.
    pub code: &'static str,
    /// Meaning of the observation code.
    pub explanation: &'static str,
    /// Always false: live coordinator authority and time are unavailable here.
    pub serving_authorization_evaluated: bool,
    /// Recorded action epochs, if present.
    pub entry: Option<RecordedActionEntry>,
    /// Runtime class recorded by the live descriptor admission path.
    pub runtime_class: Option<String>,
    /// Committed publication, even when serving is blocked.
    pub publication: Option<RecordedPublication>,
    /// Stored serving state and validity information.
    pub serving: Option<RecordedServing>,
    /// Latest recorded evaluation from the live trust ledger.
    pub trust_evaluation: Option<RecordedTrustEvaluation>,
    /// Legacy trust state, which is not synchronized with the live ledger.
    pub legacy_trust: Option<RecordedTrust>,
    /// Direct action-entry quarantine reason, if any.
    pub action_quarantine: Option<String>,
    /// Durable divergence independently vetoes serving.
    pub has_unresolved_divergence: bool,
    /// Named blocking references, with explicit truncation.
    pub blocking_quarantines: RecordedRows<RecordedQuarantine>,
    /// True only when at least one component was actually recorded.
    pub breakdown_recorded: bool,
    /// Recorded components; absent components are never synthesized.
    pub breakdown: RecordedRows<RecordedComponent>,
}

impl ActionExplanation {
    fn from_inspection(database: &Path, inspection: ActionInspection) -> Self {
        let blocked = inspection.action_quarantine.is_some()
            || inspection.has_unresolved_divergence
            || !inspection.blocking_quarantines.items.is_empty()
            || inspection.blocking_quarantines.truncated
            || inspection
                .serving
                .as_ref()
                .is_some_and(|state| state.disposition != "servable");
        let (code, explanation) = if !inspection.observed {
            (
                "no-recorded-action",
                "No action-specific facts were found in the inspected metadata tables.",
            )
        } else if inspection.publication.is_none() {
            (
                "no-recorded-publication",
                "The action has recorded metadata but no committed publication in this snapshot.",
            )
        } else if blocked {
            (
                "recorded-serving-blocker",
                "A publication exists together with a recorded serving restriction or blocking reference.",
            )
        } else {
            (
                "publication-recorded",
                "A publication is recorded; its current serving authorization has not been evaluated.",
            )
        };
        Self {
            action_key: inspection.action_key,
            metadata_path: database.display().to_string(),
            schema_version: inspection.schema_version,
            observed: inspection.observed,
            code,
            explanation,
            serving_authorization_evaluated: false,
            entry: inspection.entry.map(|entry| RecordedActionEntry {
                key_epoch: entry.key_epoch,
                projection_epoch: entry.projection_epoch,
            }),
            runtime_class: inspection.runtime_class,
            publication: inspection
                .publication
                .map(|publication| RecordedPublication {
                    descriptor: publication.descriptor,
                    manifest: publication.manifest,
                    winner_generation: publication.winner_generation,
                    winner_attempt: publication.winner_attempt,
                    winner_worker: publication.winner_worker,
                    result_kind: publication.result_kind,
                    pin_id: publication.pin_id,
                }),
            serving: inspection.serving.map(|serving| RecordedServing {
                disposition: serving.disposition,
                version: serving.version,
                state_revision: serving.state_revision,
                authority_key: serving.authority_key,
                evaluated_at_micros: serving.evaluated_at_micros,
                max_age_micros: serving.max_age_micros,
                clock_uncertainty_micros: serving.clock_uncertainty_micros,
                clock_epoch: serving.clock_epoch,
            }),
            trust_evaluation: inspection.trust_evaluation.map(|evaluation| {
                RecordedTrustEvaluation {
                    version: evaluation.version,
                    state: evaluation.state,
                    reason: evaluation.reason,
                    evaluated_seq: evaluation.evaluated_seq,
                }
            }),
            legacy_trust: inspection.legacy_trust.map(|trust| RecordedTrust {
                state: trust.state,
                reason: trust.reason,
            }),
            action_quarantine: inspection.action_quarantine,
            has_unresolved_divergence: inspection.has_unresolved_divergence,
            blocking_quarantines: RecordedRows {
                items: inspection
                    .blocking_quarantines
                    .items
                    .into_iter()
                    .map(|row| RecordedQuarantine {
                        scope: row.scope,
                        subject: row.subject,
                        reason: row.reason,
                    })
                    .collect(),
                truncated: inspection.blocking_quarantines.truncated,
            },
            breakdown_recorded: !inspection.breakdown.items.is_empty(),
            breakdown: RecordedRows {
                items: inspection
                    .breakdown
                    .items
                    .into_iter()
                    .map(|row| RecordedComponent {
                        component: row.component,
                        algorithm: row.algorithm,
                        domain: row.domain,
                        digest_hex: row.digest_hex,
                    })
                    .collect(),
                truncated: inspection.breakdown.truncated,
            },
        }
    }
}

/// Inspect a real, existing action index without opening the writer or migrating.
///
/// # Errors
/// Invalid action keys, unavailable stores, unsupported schemas or corrupt rows.
pub fn explain_action(key: &str, cas_root: &Path) -> anyhow::Result<ActionExplanation> {
    let database = cas_root.join("meta.sqlite");
    let inspection = action_inspection::inspect_action(&database, key)
        .map_err(|error| anyhow::anyhow!("{}: {error}", database.display()))?;
    Ok(ActionExplanation::from_inspection(&database, inspection))
}

fn format_action(explanation: &ActionExplanation) -> String {
    let mut lines = vec![
        format!("{}: {}", explanation.code, explanation.explanation),
        format!("action: {}", explanation.action_key),
        format!("metadata: {:?}", explanation.metadata_path),
    ];
    if let Some(entry) = &explanation.entry {
        lines.push(format!(
            "epochs: key={}, projection={}",
            entry.key_epoch, entry.projection_epoch
        ));
    }
    if let Some(class) = &explanation.runtime_class {
        lines.push(format!("recorded class: {class:?}"));
    }
    if let Some(publication) = &explanation.publication {
        lines.push(format!("publication: {:?}", publication.result_kind));
        lines.push(format!("descriptor: {}", publication.descriptor));
        lines.push(format!("manifest: {}", publication.manifest));
        lines.push(format!(
            "winner: generation={}, attempt={}, worker={:?}",
            publication.winner_generation,
            publication.winner_attempt,
            publication
                .winner_worker
                .as_deref()
                .unwrap_or("not recorded")
        ));
    }
    if let Some(serving) = &explanation.serving {
        lines.push(format!(
            "recorded serving: {:?}, revision={}, authority={:?}",
            serving.disposition, serving.state_revision, serving.authority_key
        ));
        lines.push(format!(
            "recorded validity: epoch={}, evaluated_at_us={}, max_age_us={:?}, uncertainty_us={}",
            serving.clock_epoch,
            serving.evaluated_at_micros,
            serving.max_age_micros,
            serving.clock_uncertainty_micros
        ));
    }
    if let Some(evaluation) = &explanation.trust_evaluation {
        lines.push(format!(
            "recorded trust evaluation: version={}, sequence={}, state={:?}, reason={:?}",
            evaluation.version, evaluation.evaluated_seq, evaluation.state, evaluation.reason
        ));
    }
    if let Some(trust) = &explanation.legacy_trust {
        lines.push(format!(
            "legacy trust state: {:?}: {:?}",
            trust.state, trust.reason
        ));
    }
    if let Some(reason) = &explanation.action_quarantine {
        lines.push(format!("action quarantine: {reason:?}"));
    }
    if explanation.has_unresolved_divergence {
        lines.push("unresolved divergence: recorded".to_owned());
    }
    for row in &explanation.blocking_quarantines.items {
        lines.push(format!(
            "blocking reference: scope={:?}, subject={:?}, reason={:?}",
            row.scope, row.subject, row.reason
        ));
    }
    if explanation.blocking_quarantines.truncated {
        lines.push("blocking references: additional rows omitted".to_owned());
    }
    if explanation.breakdown_recorded {
        for row in &explanation.breakdown.items {
            lines.push(format!(
                "component {:?}: {:?}:{} ({:?})",
                row.component, row.domain, row.digest_hex, row.algorithm
            ));
        }
        if explanation.breakdown.truncated {
            lines.push("key components: additional rows omitted".to_owned());
        }
    } else {
        lines.push("key component breakdown: not recorded".to_owned());
    }
    lines.push(
        "serving authorization: not evaluated; requires the coordinator's current authority and clock"
            .to_owned(),
    );
    lines.join("\n")
}

/// JSON input for one typed digest: domain + hex bytes. V1 SHA-256 is
/// the only authoritative algorithm, so none is accepted on input.
#[derive(Debug, Deserialize)]
struct DigestDto {
    domain: String,
    /// 64 hex chars (32 bytes).
    hex: String,
}

/// JSON input for one breakdown component.
#[derive(Debug, Deserialize)]
struct ComponentDto {
    name: String,
    digest: DigestDto,
}

/// JSON input mirroring `ActionKeyBreakdown`.
#[derive(Debug, Deserialize)]
struct BreakdownDto {
    key_epoch: u32,
    projection_epoch: u32,
    action_class_tag: u32,
    components: Vec<ComponentDto>,
    final_key: DigestDto,
}

impl DigestDto {
    fn into_typed(self) -> Result<TypedDigest, String> {
        let hex = self.hex.trim();
        let bytes = (0..32)
            .map(|i| {
                u8::from_str_radix(hex.get(i * 2..i * 2 + 2).ok_or("digest hex too short")?, 16)
                    .map_err(|e| format!("bad digest hex: {e}"))
            })
            .collect::<Result<Vec<u8>, _>>()?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| "digest hex wrong length")?;
        // The CLI process is short-lived; leaking input domains keeps
        // TypedDigest's 'static domain without a registry here (the
        // coordinator's intern table is the long-lived authority).
        let domain: &'static str = Box::leak(self.domain.into_boxed_str());
        Ok(TypedDigest {
            algorithm: DigestAlgorithm::Sha256V1,
            domain,
            bytes,
        })
    }
}

impl BreakdownDto {
    fn into_breakdown(self) -> Result<ActionKeyBreakdown, String> {
        let components = self
            .components
            .into_iter()
            .map(|c| {
                Ok(BreakdownComponent {
                    name: Box::leak(c.name.into_boxed_str()),
                    digest: c.digest.into_typed()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(ActionKeyBreakdown {
            key_epoch: self.key_epoch,
            projection_epoch: self.projection_epoch,
            action_class_tag: self.action_class_tag,
            components,
            final_key: self.final_key.into_typed()?,
        })
    }
}

/// Diff two seeded breakdowns into the wire explanation.
///
/// # Errors
/// Malformed breakdown JSON (shape, hex, missing fields).
pub fn explain_miss(prior_json: &str, current_json: &str) -> Result<MissExplanation, String> {
    let prior: BreakdownDto =
        serde_json::from_str(prior_json).map_err(|e| format!("prior breakdown: {e}"))?;
    let current: BreakdownDto =
        serde_json::from_str(current_json).map_err(|e| format!("current breakdown: {e}"))?;
    let causes = diff_breakdowns(&prior.into_breakdown()?, &current.into_breakdown()?);
    Ok(MissExplanation {
        identical: causes.is_empty(),
        causes: causes
            .into_iter()
            .map(|cause| CauseExplanation {
                code: cause.code(),
                explanation: cause.explain(),
            })
            .collect(),
    })
}

/// Explain an index-level refusal from its stable code.
///
/// # Errors
/// Unknown outcome code.
pub fn explain_refusal(code: &str) -> Result<RefusalExplanation, String> {
    let outcomes = [
        (LookupOutcome::FirstSeen, "first-seen"),
        (LookupOutcome::ServingBlocked, "serving-blocked"),
        (LookupOutcome::TrustRefused, "trust-refused"),
        (
            LookupOutcome::MaterializationUnavailable,
            "materialization-unavailable",
        ),
    ];
    let &(outcome, _) = outcomes
        .iter()
        .find(|(_, name)| *name == code)
        .ok_or_else(|| {
            format!(
                "unknown outcome '{code}'; expected one of: {}",
                outcomes
                    .iter()
                    .map(|(_, n)| *n)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
    Ok(RefusalExplanation {
        code: outcome.code(),
        explanation: outcome.explain(),
    })
}

fn read_input(path: &str) -> anyhow::Result<String> {
    if path == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| anyhow::anyhow!("stdin: {e}"))?;
        Ok(buf)
    } else {
        std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("{path}: {e}"))
    }
}

/// Entry point for `rch why <action>`.
///
/// # Errors
/// Propagates input/parse failures; exit-code mapping stays with the
/// caller's error convention.
pub async fn run(action: WhyAction, ctx: &OutputContext) -> anyhow::Result<()> {
    match action {
        WhyAction::Action { key, cas_root } => {
            let root = super::rabs_gc::resolve_cas_root(cas_root.as_deref())?;
            let explanation = explain_action(&key, &root)?;
            if ctx.is_json() {
                ctx.json(&ApiResponse::ok("why action", &explanation))?;
            } else {
                println!("{}", format_action(&explanation));
            }
        }
        WhyAction::Miss { prior, current } => {
            let explanation = explain_miss(&read_input(&prior)?, &read_input(&current)?)
                .map_err(anyhow::Error::msg)?;
            if ctx.is_json() {
                ctx.json(&ApiResponse::ok("why miss", &explanation))?;
            } else if explanation.identical {
                println!("identical: no component differs (expected hit)");
            } else {
                println!("miss: {} cause(s)", explanation.causes.len());
                for cause in &explanation.causes {
                    println!("{}: {}", cause.code, cause.explanation);
                }
            }
        }
        WhyAction::Refusal { outcome } => {
            let explanation = explain_refusal(&outcome).map_err(anyhow::Error::msg)?;
            if ctx.is_json() {
                ctx.json(&ApiResponse::ok("why refusal", &explanation))?;
            } else {
                println!("{}: {}", explanation.code, explanation.explanation);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inspection_fixture() -> ActionInspection {
        ActionInspection {
            action_key: format!("rabs.action-key.sha256.v1:{}", "ab".repeat(32)),
            schema_version: rabs_cas::metadata_store::SCHEMA_VERSION,
            observed: false,
            entry: None,
            publication: None,
            serving: None,
            trust_evaluation: None,
            legacy_trust: None,
            runtime_class: None,
            action_quarantine: None,
            has_unresolved_divergence: false,
            blocking_quarantines: action_inspection::InspectionRows {
                items: Vec::new(),
                truncated: false,
            },
            breakdown: action_inspection::InspectionRows {
                items: Vec::new(),
                truncated: false,
            },
        }
    }

    fn published_fixture() -> ActionInspection {
        let mut inspection = inspection_fixture();
        inspection.observed = true;
        inspection.entry = Some(action_inspection::ActionEntryInspection {
            key_epoch: 3,
            projection_epoch: 4,
        });
        inspection.publication = Some(action_inspection::PublicationInspection {
            descriptor: format!("rabs.descriptor.sha256.v1:{}", "01".repeat(32)),
            manifest: format!("rabs.manifest.sha256.v1:{}", "02".repeat(32)),
            winner_generation: format!("{:032x}", 1),
            winner_attempt: format!("{:032x}", 2),
            winner_worker: Some("worker-a".to_owned()),
            result_kind: "deterministic-failure".to_owned(),
            pin_id: format!("{:032x}", 3),
        });
        inspection.serving = Some(action_inspection::ServingInspection {
            disposition: "servable".to_owned(),
            version: 1,
            state_revision: 8,
            authority_key: "recorded-authority".to_owned(),
            evaluated_at_micros: 42,
            max_age_micros: Some(1_000),
            clock_uncertainty_micros: 3,
            clock_epoch: 7,
        });
        inspection
    }

    #[test]
    fn action_unknown_and_unpublished_remain_distinct_without_invented_evidence() {
        let mut inspection = inspection_fixture();
        let unknown =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection.clone());
        assert_eq!(unknown.code, "no-recorded-action");
        assert!(!unknown.observed);
        assert!(!unknown.breakdown_recorded);
        assert!(!unknown.serving_authorization_evaluated);
        assert!(format_action(&unknown).contains("key component breakdown: not recorded"));
        inspection.observed = true;
        inspection.runtime_class = Some("rabs-dependency-rlib-v1".to_owned());
        let unpublished =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection);
        assert_eq!(unpublished.code, "no-recorded-publication");
        assert!(unpublished.publication.is_none());
        assert!(unpublished.runtime_class.is_some());
    }

    #[test]
    fn published_action_keeps_winner_and_failure_kind_when_divergence_blocks_serving() {
        let mut inspection = published_fixture();
        inspection.has_unresolved_divergence = true;
        let explanation =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection);
        assert_eq!(explanation.code, "recorded-serving-blocker");
        let publication = explanation.publication.as_ref().unwrap();
        assert_eq!(publication.winner_worker.as_deref(), Some("worker-a"));
        assert_eq!(publication.result_kind, "deterministic-failure");
        assert_eq!(
            explanation.serving.as_ref().unwrap().disposition,
            "servable"
        );
        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["serving_authorization_evaluated"], false);
        assert_eq!(json["has_unresolved_divergence"], true);
        assert_eq!(json["publication"]["winner_worker"], "worker-a");
        assert!(format_action(&explanation).contains("unresolved divergence: recorded"));
    }

    #[test]
    fn recorded_servable_state_is_never_reported_as_a_current_cache_hit() {
        let explanation =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), published_fixture());
        assert_eq!(explanation.code, "publication-recorded");
        assert!(!explanation.serving_authorization_evaluated);
        assert!(format_action(&explanation).contains("serving authorization: not evaluated"));
        assert!(!format_action(&explanation).contains("expected hit"));
    }

    #[test]
    fn action_output_preserves_truncation_and_escapes_recorded_terminal_controls() {
        let mut inspection = published_fixture();
        inspection.action_quarantine = Some("reason\n\x1b[31mforged".to_owned());
        inspection.blocking_quarantines = action_inspection::InspectionRows {
            items: vec![action_inspection::QuarantineInspection {
                scope: "worker".to_owned(),
                subject: "worker-a".to_owned(),
                reason: None,
            }],
            truncated: true,
        };
        inspection.breakdown = action_inspection::InspectionRows {
            items: vec![action_inspection::BreakdownInspection {
                component: "toolchain".to_owned(),
                algorithm: "sha256-v1".to_owned(),
                domain: "rabs.component.v1".to_owned(),
                digest_hex: "03".repeat(32),
            }],
            truncated: true,
        };
        let explanation =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection);
        assert_eq!(explanation.code, "recorded-serving-blocker");
        assert!(explanation.breakdown_recorded);
        let human = format_action(&explanation);
        assert!(!human.contains('\x1b'));
        assert!(!human.contains("reason\n"));
        assert!(human.contains("blocking references: additional rows omitted"));
        assert!(human.contains("key components: additional rows omitted"));
        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["blocking_quarantines"]["truncated"], true);
        assert_eq!(json["breakdown"]["truncated"], true);
        assert_eq!(json["action_quarantine"], "reason\n\x1b[31mforged");
    }

    #[test]
    fn action_lookup_does_not_create_a_missing_store() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("absent-cas");
        let error = explain_action(&"ab".repeat(32), &root).unwrap_err();
        assert!(error.to_string().contains("meta.sqlite"));
        assert!(!root.exists());
    }

    #[test]
    fn latest_live_trust_evaluation_is_distinct_from_legacy_trust_state() {
        let mut inspection = inspection_fixture();
        inspection.observed = true;
        inspection.trust_evaluation = Some(action_inspection::TrustEvaluationInspection {
            version: 9,
            state: "denied".to_owned(),
            reason: "independent comparison failed".to_owned(),
            evaluated_seq: 42,
        });
        inspection.legacy_trust = Some(action_inspection::TrustInspection {
            state: "trusted".to_owned(),
            reason: "old legacy row".to_owned(),
        });
        let explanation =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection);
        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["trust_evaluation"]["version"], 9);
        assert_eq!(json["trust_evaluation"]["state"], "denied");
        assert_eq!(json["legacy_trust"]["state"], "trusted");
        assert!(!explanation.serving_authorization_evaluated);
        let human = format_action(&explanation);
        assert!(human.contains("recorded trust evaluation: version=9, sequence=42"));
        assert!(human.contains("legacy trust state:"));
    }

    /// The twelve canonical component slots (A014 order).
    const COMPONENTS: [&str; 12] = [
        "normalized_invocation",
        "virtual_working_directory",
        "action_inputs",
        "negative_dependencies",
        "dependency_inputs",
        "toolchain",
        "output_platform",
        "environment",
        "sandbox_semantic_policy",
        "build_path_semantic_policy",
        "execution_semantics",
        "output_declarations",
    ];

    fn digest_hex(tag: u8) -> String {
        format!("{tag:064x}")
    }

    fn seeded_breakdown(tag: u8, differing_component: Option<&str>) -> String {
        let components: Vec<String> = COMPONENTS
            .iter()
            .map(|name| {
                let t = if Some(*name) == differing_component {
                    tag.wrapping_add(0x40)
                } else {
                    tag
                };
                format!(
                    "{{\"name\": \"{name}\", \"digest\": {{\"domain\": \"rabs.test.v1\", \
                     \"hex\": \"{}\"}}}}",
                    digest_hex(t)
                )
            })
            .collect();
        format!(
            "{{\"key_epoch\": 1, \"projection_epoch\": 1, \"action_class_tag\": 3, \
             \"components\": [{}], \"final_key\": {{\"domain\": \"rabs.test.v1\", \
             \"hex\": \"{}\"}}}}",
            components.join(", "),
            digest_hex(tag)
        )
    }

    #[test]
    fn k009_explains_every_seeded_component_cause() {
        // cause_for_component maps each slot to its distinct MissCause;
        // seeding ONE component change must surface exactly that code.
        let expected = [
            ("normalized_invocation", "invocation-changed"),
            ("virtual_working_directory", "working-directory-changed"),
            ("action_inputs", "source-changed"),
            ("negative_dependencies", "negative-dependency-changed"),
            ("dependency_inputs", "dependency-artifact-changed"),
            ("toolchain", "toolchain-changed"),
            ("output_platform", "platform-changed"),
            ("environment", "environment-changed"),
            ("sandbox_semantic_policy", "sandbox-policy-changed"),
            ("build_path_semantic_policy", "build-path-policy-changed"),
            ("execution_semantics", "execution-semantics-changed"),
            ("output_declarations", "output-declarations-changed"),
        ];
        for (component, code) in expected {
            let explanation = explain_miss(
                &seeded_breakdown(1, None),
                &seeded_breakdown(1, Some(component)),
            )
            .unwrap();
            assert!(
                !explanation.identical,
                "{component}: unexpectedly identical"
            );
            assert_eq!(explanation.causes.len(), 1, "{component}: noisy causes");
            assert_eq!(explanation.causes[0].code, code, "{component}");
        }
    }

    #[test]
    fn k009_explains_seeded_epoch_and_class_causes() {
        let epoch_current =
            seeded_breakdown(1, None).replace("\"key_epoch\": 1", "\"key_epoch\": 2");
        let explanation = explain_miss(&seeded_breakdown(1, None), &epoch_current).unwrap();
        assert_eq!(explanation.causes[0].code, "epoch-mismatch");

        let class_current =
            seeded_breakdown(1, None).replace("\"action_class_tag\": 3", "\"action_class_tag\": 4");
        let explanation = explain_miss(&seeded_breakdown(1, None), &class_current).unwrap();
        assert_eq!(explanation.causes[0].code, "action-class-changed");
    }

    #[test]
    fn k009_identical_breakdowns_report_expected_hit() {
        let explanation =
            explain_miss(&seeded_breakdown(7, None), &seeded_breakdown(7, None)).unwrap();
        assert!(explanation.identical);
        assert!(explanation.causes.is_empty());
    }

    #[test]
    fn k009_refusals_carry_their_reason_codes() {
        for (code, outcome) in [
            ("first-seen", LookupOutcome::FirstSeen),
            ("serving-blocked", LookupOutcome::ServingBlocked),
            ("trust-refused", LookupOutcome::TrustRefused),
            (
                "materialization-unavailable",
                LookupOutcome::MaterializationUnavailable,
            ),
        ] {
            let explanation = explain_refusal(code).unwrap();
            assert_eq!(explanation.code, outcome.code());
            assert!(!explanation.explanation.is_empty());
        }
        assert!(explain_refusal("not-a-code").is_err());
    }

    #[test]
    fn k009_malformed_input_is_a_typed_string_error() {
        assert!(explain_miss("not json", "{}").is_err());
        assert!(explain_miss(&seeded_breakdown(1, None), "{\"components\": []}").is_err());
    }
}
