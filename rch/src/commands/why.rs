//! `rch why` — recorded action state, cache-miss attribution and refusal codes
//! (plan §102; bead K009).
//!
//! A miss explanation is the structured diff of two key breakdowns
//! (`rabs_key::diff_breakdowns`, bead F013) surfaced with STABLE reason
//! codes; index-level refusals render `LookupOutcome` codes. Both file inputs
//! and explicitly selected persisted keys are supported. `why action` reads one consistent
//! snapshot of the daemon's existing metadata without creating or migrating
//! it. Recorded serving state is not current coordinator authorization.
//!
//! Stream separation holds: stdout carries data (human lines or the
//! JSON envelope); stderr carries diagnostics only.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use rabs_cas::action_inspection::{self, ActionInspection};
use rabs_key::action_key::{ActionKeyHeader, BorrowedKeyComponent, recompute_action_key};
use rabs_key::key_diff::{LookupOutcome, diff_key_inputs};
use rabs_key::typed_digest::DOMAIN_ACTION_KEY;
use rabs_protocol::descriptor::ACTION_KEY_COMPONENT_NAMES;
use rabs_protocol::result_identity::TypedDigest;
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
    /// Compare verified key inputs from JSON files or two recorded action keys
    #[command(
        after_help = "EXAMPLES:\n    rch why miss --prior-key PRIOR --current-key CURRENT --cas-root /path/to/cas\n    rch why miss --prior prior.json --current current.json\n    cat current.json | rch why miss --prior prior.json --current -",
        group(clap::ArgGroup::new("miss_input").required(true).args(["prior", "prior_key"]))
    )]
    Miss {
        /// Prior breakdown JSON path, or `-` for stdin
        #[arg(long, requires = "current")]
        prior: Option<String>,
        /// Current breakdown JSON path, or `-` for stdin
        #[arg(long, requires = "prior", conflicts_with_all = ["prior_key", "current_key"])]
        current: Option<String>,
        /// Prior persisted action key, bare or domain-prefixed
        #[arg(long, requires = "current_key", conflicts_with_all = ["prior", "current"])]
        prior_key: Option<String>,
        /// Current persisted action key, bare or domain-prefixed
        #[arg(long, requires = "prior_key", conflicts_with_all = ["prior", "current"])]
        current_key: Option<String>,
        /// Existing CAS root for recorded keys; uses the same default as why action
        #[arg(long, requires_all = ["prior_key", "current_key"], conflicts_with_all = ["prior", "current"])]
        cas_root: Option<PathBuf>,
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
    /// True when both complete verified key identities agree; not a serving decision.
    pub identical: bool,
    /// Always true: neither a lookup decision nor serving authorization is evaluated.
    pub key_identity_only: bool,
    /// Every cause, canonical order (epoch/class first).
    pub causes: Vec<CauseExplanation>,
    /// Exact changed scalar or digest inputs in canonical order.
    pub changed_inputs: Vec<KeyInputDifference>,
}

/// One value from a verified key header or component digest.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum KeyInputValue {
    /// An epoch or canonical numeric action class.
    Number(u32),
    /// A complete typed component digest.
    Digest {
        /// Authoritative digest algorithm.
        algorithm: &'static str,
        /// Semantic domain preserved verbatim.
        domain: String,
        /// Complete lowercase digest bytes.
        hex: String,
    },
}

/// Exact values behind one reported key difference.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct KeyInputDifference {
    /// Canonical component or header-field name.
    pub input: &'static str,
    /// Recorded value in the prior key.
    pub prior: KeyInputValue,
    /// Recorded value in the current key.
    pub current: KeyInputValue,
}

/// Missing historical provenance; no causes can be inferred from this absence.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct KeyProvenanceUnavailable {
    /// Which supplied key lacks complete evidence: prior or current.
    pub side: &'static str,
    /// Normalized requested action key.
    pub action_key: String,
    /// Stable missing-evidence code.
    pub code: &'static str,
    /// Missing canonical component names, if any.
    pub missing_components: Vec<&'static str>,
}

/// Comparison of two explicit keys from one read-only metadata snapshot.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct StoredMissExplanation {
    /// Existing metadata database read by the command.
    pub metadata_path: String,
    /// Normalized prior action key.
    pub prior_action_key: String,
    /// Normalized current action key.
    pub current_action_key: String,
    /// Either compared or incomplete-key-provenance.
    pub status: &'static str,
    /// Always explicit-key-pair: no historical candidate relationship is inferred.
    pub comparison_basis: &'static str,
    /// Always false: no request's actual lookup decision is reconstructed.
    pub lookup_decision_evaluated: bool,
    /// Always false: equality does not establish permission to serve.
    pub serving_authorization_evaluated: bool,
    /// Present only when both complete breakdowns recompute to their requested keys.
    pub comparison: Option<MissExplanation>,
    /// Missing evidence for either supplied key.
    pub unavailable: Vec<KeyProvenanceUnavailable>,
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

/// Immutable header written with the descriptor's component digests at admission.
#[derive(Debug, PartialEq, Eq, serde::Serialize, schemars::JsonSchema)]
pub struct RecordedBreakdownHeader {
    /// Action-key namespace epoch.
    pub key_epoch: u32,
    /// Result-projection namespace epoch.
    pub projection_epoch: u32,
    /// Canonical numeric action class, distinct from the runtime serving policy.
    pub action_class_tag: u32,
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
    /// Persisted key header; historical missing fields are never inferred.
    pub breakdown_header: Option<RecordedBreakdownHeader>,
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
            breakdown_header: inspection
                .breakdown_header
                .map(|header| RecordedBreakdownHeader {
                    key_epoch: header.key_epoch,
                    projection_epoch: header.projection_epoch,
                    action_class_tag: header.action_class_tag,
                }),
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
    if let Some(header) = &explanation.breakdown_header {
        lines.push(format!(
            "key header: key_epoch={}, projection_epoch={}, action_class_tag={}",
            header.key_epoch, header.projection_epoch, header.action_class_tag
        ));
    } else {
        lines.push("key header: not recorded".to_owned());
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
#[serde(deny_unknown_fields)]
struct DigestDto {
    domain: String,
    /// 64 hex chars (32 bytes).
    hex: String,
}

/// JSON input for one breakdown component.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ComponentDto {
    name: String,
    digest: DigestDto,
}

/// JSON input mirroring `ActionKeyBreakdown`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakdownDto {
    key_epoch: u32,
    projection_epoch: u32,
    action_class_tag: u32,
    components: Vec<ComponentDto>,
    final_key: DigestDto,
}

impl DigestDto {
    fn bytes(&self) -> Result<[u8; 32], String> {
        if self.hex.len() != 64 || !self.hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("digest must contain exactly 64 hexadecimal digits".to_owned());
        }
        let mut bytes = [0; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&self.hex[index * 2..index * 2 + 2], 16)
                .map_err(|error| format!("invalid digest: {error}"))?;
        }
        Ok(bytes)
    }
}

struct OwnedKeyComponent {
    name: &'static str,
    domain: String,
    bytes: [u8; 32],
}

struct VerifiedBreakdown {
    header: ActionKeyHeader,
    components: Vec<OwnedKeyComponent>,
    key: TypedDigest,
}

impl VerifiedBreakdown {
    fn borrowed(&self) -> Vec<BorrowedKeyComponent<'_>> {
        self.components
            .iter()
            .map(|component| BorrowedKeyComponent {
                name: component.name,
                domain: &component.domain,
                bytes: &component.bytes,
            })
            .collect()
    }
}

impl BreakdownDto {
    fn into_breakdown(mut self) -> Result<VerifiedBreakdown, String> {
        if self.components.len() != ACTION_KEY_COMPONENT_NAMES.len() {
            return Err("a complete set of twelve key components is required".to_owned());
        }
        if self.final_key.domain != DOMAIN_ACTION_KEY {
            return Err("final key must use the action-key digest domain".to_owned());
        }
        let claimed = self.final_key.bytes()?;
        let header = ActionKeyHeader {
            key_epoch: self.key_epoch,
            projection_epoch: self.projection_epoch,
            action_class_tag: self.action_class_tag,
        };
        let mut components = Vec::with_capacity(ACTION_KEY_COMPONENT_NAMES.len());
        for name in ACTION_KEY_COMPONENT_NAMES {
            let index = self
                .components
                .iter()
                .position(|component| component.name == name)
                .ok_or_else(|| format!("missing or duplicated canonical component {name}"))?;
            let component = self.components.remove(index);
            if component.digest.domain.is_empty() || component.digest.domain.len() > 4096 {
                return Err(format!("invalid semantic domain for {name}"));
            }
            components.push(OwnedKeyComponent {
                name,
                bytes: component.digest.bytes()?,
                domain: component.digest.domain,
            });
        }
        let borrowed: Vec<_> = components
            .iter()
            .map(|component| BorrowedKeyComponent {
                name: component.name,
                domain: &component.domain,
                bytes: &component.bytes,
            })
            .collect();
        let key = recompute_action_key(header, &borrowed).map_err(|error| error.to_string())?;
        if key.bytes != claimed {
            return Err(
                "recorded key inputs do not recompute to the claimed action key".to_owned(),
            );
        }
        Ok(VerifiedBreakdown {
            header,
            components,
            key,
        })
    }
}

fn digest_value(component: &OwnedKeyComponent) -> KeyInputValue {
    KeyInputValue::Digest {
        algorithm: "sha256-v1",
        domain: component.domain.clone(),
        hex: rabs_protocol::raw_bytes::encode_hex(&component.bytes),
    }
}

fn compare_verified(
    prior: &VerifiedBreakdown,
    current: &VerifiedBreakdown,
) -> Result<MissExplanation, String> {
    let causes = diff_key_inputs(
        prior.header,
        &prior.borrowed(),
        current.header,
        &current.borrowed(),
    )
    .map_err(|error| error.to_string())?;
    let identical = prior.key == current.key;
    if identical != causes.is_empty() {
        return Err("verified key identity disagrees with its input differences".to_owned());
    }
    let mut changed_inputs = Vec::new();
    for (input, before, after) in [
        (
            "key_epoch",
            prior.header.key_epoch,
            current.header.key_epoch,
        ),
        (
            "projection_epoch",
            prior.header.projection_epoch,
            current.header.projection_epoch,
        ),
        (
            "action_class_tag",
            prior.header.action_class_tag,
            current.header.action_class_tag,
        ),
    ] {
        if before != after {
            changed_inputs.push(KeyInputDifference {
                input,
                prior: KeyInputValue::Number(before),
                current: KeyInputValue::Number(after),
            });
        }
    }
    for (before, after) in prior.components.iter().zip(&current.components) {
        if before.domain != after.domain || before.bytes != after.bytes {
            changed_inputs.push(KeyInputDifference {
                input: before.name,
                prior: digest_value(before),
                current: digest_value(after),
            });
        }
    }
    Ok(MissExplanation {
        identical,
        key_identity_only: true,
        causes: causes
            .into_iter()
            .map(|cause| CauseExplanation {
                code: cause.code(),
                explanation: cause.explain(),
            })
            .collect(),
        changed_inputs,
    })
}

const MAX_BREAKDOWN_BYTES: usize = 1024 * 1024;

/// Verify and compare two complete JSON breakdowns without leaking input strings.
///
/// # Errors
/// Excessive or malformed JSON, incomplete components, unsupported header values,
/// or any claimed key that does not match the canonical encoding of its inputs.
pub fn explain_miss(prior_json: &str, current_json: &str) -> Result<MissExplanation, String> {
    if prior_json.len() > MAX_BREAKDOWN_BYTES || current_json.len() > MAX_BREAKDOWN_BYTES {
        return Err("key breakdown exceeds the one MiB input limit".to_owned());
    }
    let prior: BreakdownDto =
        serde_json::from_str(prior_json).map_err(|e| format!("prior breakdown: {e}"))?;
    let current: BreakdownDto =
        serde_json::from_str(current_json).map_err(|e| format!("current breakdown: {e}"))?;
    let prior = prior
        .into_breakdown()
        .map_err(|error| format!("prior breakdown: {error}"))?;
    let current = current
        .into_breakdown()
        .map_err(|error| format!("current breakdown: {error}"))?;
    compare_verified(&prior, &current)
}

fn stored_breakdown(
    side: &'static str,
    action: &ActionInspection,
    unavailable: &mut Vec<KeyProvenanceUnavailable>,
) -> Result<Option<VerifiedBreakdown>, String> {
    if action.breakdown.truncated {
        return Err(format!("{side} key has truncated component evidence"));
    }
    let mut names = std::collections::BTreeSet::new();
    for component in &action.breakdown.items {
        if !ACTION_KEY_COMPONENT_NAMES.contains(&component.component.as_str())
            || !names.insert(component.component.as_str())
        {
            return Err(format!(
                "{side} key has unknown or duplicate component names"
            ));
        }
        if component.algorithm != "sha256-v1" {
            return Err(format!("{side} key has an unsupported component algorithm"));
        }
    }
    let missing_components: Vec<_> = ACTION_KEY_COMPONENT_NAMES
        .into_iter()
        .filter(|name| !names.contains(name))
        .collect();
    let code = if action.breakdown_header.is_none() {
        Some("key-header-not-recorded")
    } else if !missing_components.is_empty() {
        Some("key-components-incomplete")
    } else {
        None
    };
    if let Some(code) = code {
        unavailable.push(KeyProvenanceUnavailable {
            side,
            action_key: action.action_key.clone(),
            code,
            missing_components,
        });
        return Ok(None);
    }
    let header = action
        .breakdown_header
        .as_ref()
        .ok_or("key header missing")?;
    let hex = action
        .action_key
        .strip_prefix(DOMAIN_ACTION_KEY)
        .and_then(|tail| tail.strip_prefix(':'))
        .ok_or("invalid recorded action-key domain")?;
    let dto = BreakdownDto {
        key_epoch: header.key_epoch,
        projection_epoch: header.projection_epoch,
        action_class_tag: header.action_class_tag,
        components: action
            .breakdown
            .items
            .iter()
            .map(|component| ComponentDto {
                name: component.component.clone(),
                digest: DigestDto {
                    domain: component.domain.clone(),
                    hex: component.digest_hex.clone(),
                },
            })
            .collect(),
        final_key: DigestDto {
            domain: DOMAIN_ACTION_KEY.to_owned(),
            hex: hex.to_owned(),
        },
    };
    dto.into_breakdown()
        .map(Some)
        .map_err(|error| format!("{side} key provenance: {error}"))
}

fn compare_stored(
    database: &Path,
    prior: &ActionInspection,
    current: &ActionInspection,
) -> anyhow::Result<StoredMissExplanation> {
    let mut unavailable = Vec::new();
    let before = stored_breakdown("prior", prior, &mut unavailable).map_err(anyhow::Error::msg)?;
    let after =
        stored_breakdown("current", current, &mut unavailable).map_err(anyhow::Error::msg)?;
    let comparison = match (before, after) {
        (Some(before), Some(after)) => {
            Some(compare_verified(&before, &after).map_err(anyhow::Error::msg)?)
        }
        _ => None,
    };
    Ok(StoredMissExplanation {
        metadata_path: database.display().to_string(),
        prior_action_key: prior.action_key.clone(),
        current_action_key: current.action_key.clone(),
        status: if comparison.is_some() {
            "compared"
        } else {
            "incomplete-key-provenance"
        },
        comparison_basis: "explicit-key-pair",
        lookup_decision_evaluated: false,
        serving_authorization_evaluated: false,
        comparison,
        unavailable,
    })
}

/// Compare complete persisted action-key inputs from one SQLite snapshot.
/// Supplied keys do not prove the prior key was a request's actual cache candidate.
///
/// # Errors
/// Missing/incompatible stores, invalid keys, or corrupt/mismatched key evidence.
pub fn explain_stored_miss(
    prior: &str,
    current: &str,
    cas_root: &Path,
) -> anyhow::Result<StoredMissExplanation> {
    let database = cas_root.join("meta.sqlite");
    let (prior, current) = action_inspection::inspect_action_pair(&database, prior, current)
        .map_err(|error| anyhow::anyhow!("{}: {error}", database.display()))?;
    compare_stored(&database, &prior, &current)
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
        read_bounded(std::io::stdin(), "stdin")
    } else {
        let file = std::fs::File::open(path).map_err(|error| anyhow::anyhow!("{path}: {error}"))?;
        read_bounded(file, path)
    }
}

fn read_bounded(input: impl std::io::Read, label: &str) -> anyhow::Result<String> {
    let mut text = String::new();
    input
        .take(MAX_BREAKDOWN_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|error| anyhow::anyhow!("{label}: {error}"))?;
    anyhow::ensure!(
        text.len() <= MAX_BREAKDOWN_BYTES,
        "{label}: key breakdown exceeds one MiB"
    );
    Ok(text)
}

fn format_key_value(value: &KeyInputValue) -> String {
    match value {
        KeyInputValue::Number(value) => value.to_string(),
        KeyInputValue::Digest {
            algorithm,
            domain,
            hex,
        } => format!("{domain:?}:{hex} ({algorithm})"),
    }
}

fn format_miss(explanation: &MissExplanation) -> String {
    let mut lines = vec![if explanation.identical {
        "same-key: complete verified key inputs agree".to_owned()
    } else {
        format!("key-differences: {} cause(s)", explanation.causes.len())
    }];
    for cause in &explanation.causes {
        lines.push(format!("{}: {}", cause.code, cause.explanation));
    }
    for difference in &explanation.changed_inputs {
        lines.push(format!(
            "{}: {} -> {}",
            difference.input,
            format_key_value(&difference.prior),
            format_key_value(&difference.current)
        ));
    }
    lines.push("scope: verified key identity; serving authorization was not evaluated".to_owned());
    lines.join("\n")
}

fn format_stored_miss(explanation: &StoredMissExplanation) -> String {
    let mut lines = vec![
        format!("status: {}", explanation.status),
        format!("prior: {}", explanation.prior_action_key),
        format!("current: {}", explanation.current_action_key),
        format!("metadata: {:?}", explanation.metadata_path),
        "comparison basis: explicit key pair; no lookup decision was evaluated".to_owned(),
    ];
    if let Some(comparison) = &explanation.comparison {
        lines.push(format_miss(comparison));
    } else {
        for missing in &explanation.unavailable {
            lines.push(format!("{}: {}", missing.side, missing.code));
            if !missing.missing_components.is_empty() {
                lines.push(format!(
                    "missing components: {}",
                    missing.missing_components.join(", ")
                ));
            }
        }
        lines.push(
            "key differences are unavailable; serving authorization was not evaluated".to_owned(),
        );
    }
    lines.join("\n")
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
        WhyAction::Miss {
            prior,
            current,
            prior_key,
            current_key,
            cas_root,
        } => match (prior, current, prior_key, current_key) {
            (Some(prior), Some(current), None, None) if cas_root.is_none() => {
                anyhow::ensure!(
                    prior != "-" || current != "-",
                    "only one breakdown can be read from stdin"
                );
                let explanation = explain_miss(&read_input(&prior)?, &read_input(&current)?)
                    .map_err(anyhow::Error::msg)?;
                if ctx.is_json() {
                    ctx.json(&ApiResponse::ok("why miss", &explanation))?;
                } else {
                    println!("{}", format_miss(&explanation));
                }
            }
            (None, None, Some(prior), Some(current)) => {
                let root = super::rabs_gc::resolve_cas_root(cas_root.as_deref())?;
                let explanation = explain_stored_miss(&prior, &current, &root)?;
                if ctx.is_json() {
                    ctx.json(&ApiResponse::ok("why miss", &explanation))?;
                } else {
                    println!("{}", format_stored_miss(&explanation));
                }
            }
            _ => anyhow::bail!(
                "provide both --prior/--current files or both --prior-key/--current-key keys"
            ),
        },
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
            breakdown_header: None,
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
    fn action_output_preserves_the_admission_header_without_inventing_missing_fields() {
        let mut inspection = inspection_fixture();
        let missing =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection.clone());
        assert!(missing.breakdown_header.is_none());
        assert!(format_action(&missing).contains("key header: not recorded"));
        inspection.observed = true;
        inspection.breakdown_header = Some(action_inspection::BreakdownHeaderInspection {
            key_epoch: 7,
            projection_epoch: 3,
            action_class_tag: 2,
        });
        let explanation =
            ActionExplanation::from_inspection(Path::new("cas/meta.sqlite"), inspection);
        assert!(explanation.entry.is_none());
        assert!(explanation.runtime_class.is_none());
        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["breakdown_header"]["key_epoch"], 7);
        assert_eq!(json["breakdown_header"]["projection_epoch"], 3);
        assert_eq!(json["breakdown_header"]["action_class_tag"], 2);
        assert!(
            format_action(&explanation)
                .contains("key header: key_epoch=7, projection_epoch=3, action_class_tag=2")
        );
        assert!(!explanation.serving_authorization_evaluated);
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

    const COMPONENTS: [&str; 12] = ACTION_KEY_COMPONENT_NAMES;

    fn digest_hex(tag: u8) -> String {
        format!("{tag:064x}")
    }

    fn seeded_breakdown(tag: u8, differing_component: Option<&str>) -> String {
        seeded_with_header(
            tag,
            differing_component,
            ActionKeyHeader {
                key_epoch: 1,
                projection_epoch: 1,
                action_class_tag: 3,
            },
        )
    }

    fn seeded_with_header(
        tag: u8,
        differing_component: Option<&str>,
        header: ActionKeyHeader,
    ) -> String {
        let bytes: Vec<[u8; 32]> = COMPONENTS
            .iter()
            .map(|name| {
                let mut bytes = [0; 32];
                bytes[31] = if Some(*name) == differing_component {
                    tag.wrapping_add(0x40)
                } else {
                    tag
                };
                bytes
            })
            .collect();
        let components: Vec<_> = COMPONENTS
            .iter()
            .zip(&bytes)
            .map(|(name, bytes)| BorrowedKeyComponent {
                name,
                domain: "rabs.test.v1",
                bytes,
            })
            .collect();
        let key = recompute_action_key(header, &components).unwrap();
        serde_json::json!({
            "key_epoch": header.key_epoch,
            "projection_epoch": header.projection_epoch,
            "action_class_tag": header.action_class_tag,
            "components": components.iter().map(|component| serde_json::json!({
                "name": component.name,
                "digest": {"domain": component.domain, "hex": rabs_protocol::raw_bytes::encode_hex(component.bytes)},
            })).collect::<Vec<_>>(),
            "final_key": {"domain": key.domain, "hex": rabs_protocol::raw_bytes::encode_hex(&key.bytes)},
        }).to_string()
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
        let epoch_current = seeded_with_header(
            1,
            None,
            ActionKeyHeader {
                key_epoch: 2,
                projection_epoch: 1,
                action_class_tag: 3,
            },
        );
        let explanation = explain_miss(&seeded_breakdown(1, None), &epoch_current).unwrap();
        assert_eq!(explanation.causes[0].code, "epoch-mismatch");

        let class_current = seeded_with_header(
            1,
            None,
            ActionKeyHeader {
                key_epoch: 1,
                projection_epoch: 1,
                action_class_tag: 4,
            },
        );
        let explanation = explain_miss(&seeded_breakdown(1, None), &class_current).unwrap();
        assert_eq!(explanation.causes[0].code, "action-class-changed");
    }

    #[test]
    fn k009_identical_breakdowns_report_only_verified_key_identity() {
        let explanation =
            explain_miss(&seeded_breakdown(7, None), &seeded_breakdown(7, None)).unwrap();
        assert!(explanation.identical);
        assert!(explanation.causes.is_empty());
        assert!(explanation.key_identity_only);
        assert!(explanation.changed_inputs.is_empty());
        assert!(!format_miss(&explanation).contains("expected hit"));
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

    fn recorded_breakdown(json: &str) -> ActionInspection {
        let dto: BreakdownDto = serde_json::from_str(json).unwrap();
        let mut action = inspection_fixture();
        action.observed = true;
        action.action_key = format!("{}:{}", dto.final_key.domain, dto.final_key.hex);
        action.breakdown_header = Some(action_inspection::BreakdownHeaderInspection {
            key_epoch: dto.key_epoch,
            projection_epoch: dto.projection_epoch,
            action_class_tag: dto.action_class_tag,
        });
        action.breakdown.items = dto
            .components
            .into_iter()
            .map(|component| action_inspection::BreakdownInspection {
                component: component.name,
                algorithm: "sha256-v1".to_owned(),
                domain: component.digest.domain,
                digest_hex: component.digest.hex,
            })
            .collect();
        action
            .breakdown
            .items
            .sort_by(|a, b| a.component.cmp(&b.component));
        action
    }

    #[test]
    fn file_comparison_rejects_forged_keys_and_incomplete_or_mistyped_components() {
        let valid = seeded_breakdown(1, None);
        for case in [
            "missing",
            "duplicate",
            "unknown",
            "key-domain",
            "key-bytes",
            "key-short",
            "key-long",
            "component-long",
            "component-domain",
            "component-algorithm",
            "key-algorithm",
            "header",
            "class",
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
            match case {
                "missing" => {
                    value["components"].as_array_mut().unwrap().pop();
                }
                "duplicate" => value["components"][1] = value["components"][0].clone(),
                "unknown" => value["components"][0]["name"] = "unknown".into(),
                "key-domain" => value["final_key"]["domain"] = "wrong-domain".into(),
                "key-bytes" => value["final_key"]["hex"] = digest_hex(1).into(),
                "key-short" => value["final_key"]["hex"] = "ab".into(),
                "key-long" => value["final_key"]["hex"] = "ab".repeat(33).into(),
                "component-long" => {
                    value["components"][0]["digest"]["hex"] = "ab".repeat(33).into()
                }
                "component-domain" => {
                    value["components"][0]["digest"]["domain"] = "changed-domain".into()
                }
                "component-algorithm" => {
                    value["components"][0]["digest"]["algorithm"] = "blake3".into()
                }
                "key-algorithm" => value["final_key"]["algorithm"] = "blake3".into(),
                "header" => value["projection_epoch"] = 2.into(),
                _ => value["action_class_tag"] = 0.into(),
            }
            let changed = value.to_string();
            assert!(explain_miss(&valid, &changed).is_err(), "current {case}");
            assert!(explain_miss(&changed, &valid).is_err(), "prior {case}");
        }
    }

    #[test]
    fn file_component_order_is_canonicalized_and_changed_values_are_explicit() {
        let valid = seeded_breakdown(1, None);
        let mut reordered: serde_json::Value = serde_json::from_str(&valid).unwrap();
        reordered["components"].as_array_mut().unwrap().reverse();
        assert!(
            explain_miss(&valid, &reordered.to_string())
                .unwrap()
                .identical
        );
        let comparison = explain_miss(&valid, &seeded_breakdown(1, Some("toolchain"))).unwrap();
        assert_eq!(comparison.changed_inputs.len(), 1);
        assert_eq!(comparison.changed_inputs[0].input, "toolchain");
        assert_ne!(
            comparison.changed_inputs[0].prior,
            comparison.changed_inputs[0].current
        );
    }

    #[test]
    fn stored_comparison_attributes_exact_components_and_header_values() {
        let prior = recorded_breakdown(&seeded_breakdown(1, None));
        let current = recorded_breakdown(&seeded_with_header(
            1,
            Some("toolchain"),
            ActionKeyHeader {
                key_epoch: 2,
                projection_epoch: 3,
                action_class_tag: 4,
            },
        ));
        let explanation = compare_stored(Path::new("cas/meta.sqlite"), &prior, &current).unwrap();
        assert_eq!(explanation.status, "compared");
        assert_eq!(explanation.comparison_basis, "explicit-key-pair");
        assert!(!explanation.lookup_decision_evaluated);
        assert!(!explanation.serving_authorization_evaluated);
        let comparison = explanation.comparison.unwrap();
        assert_eq!(
            comparison
                .causes
                .iter()
                .map(|cause| cause.code)
                .collect::<Vec<_>>(),
            [
                "epoch-mismatch",
                "action-class-changed",
                "toolchain-changed"
            ]
        );
        assert_eq!(
            comparison
                .changed_inputs
                .iter()
                .map(|change| change.input)
                .collect::<Vec<_>>(),
            [
                "key_epoch",
                "projection_epoch",
                "action_class_tag",
                "toolchain"
            ]
        );
        assert_eq!(comparison.changed_inputs[0].prior, KeyInputValue::Number(1));
        assert_eq!(
            comparison.changed_inputs[0].current,
            KeyInputValue::Number(2)
        );
    }

    #[test]
    fn historical_headers_and_missing_components_are_not_inferred() {
        let mut prior = recorded_breakdown(&seeded_breakdown(1, None));
        prior.breakdown_header = None;
        prior.entry = Some(action_inspection::ActionEntryInspection {
            key_epoch: 1,
            projection_epoch: 1,
        });
        prior.runtime_class = Some("rustc-dependency-compile".to_owned());
        let mut current = recorded_breakdown(&seeded_breakdown(1, Some("toolchain")));
        current
            .breakdown
            .items
            .retain(|row| row.component != "toolchain");
        let explanation = compare_stored(Path::new("cas/meta.sqlite"), &prior, &current).unwrap();
        assert_eq!(explanation.status, "incomplete-key-provenance");
        assert!(explanation.comparison.is_none());
        assert_eq!(explanation.unavailable.len(), 2);
        assert_eq!(explanation.unavailable[0].code, "key-header-not-recorded");
        assert_eq!(explanation.unavailable[1].code, "key-components-incomplete");
        assert_eq!(explanation.unavailable[1].missing_components, ["toolchain"]);
        assert!(format_stored_miss(&explanation).contains("key differences are unavailable"));
    }

    #[test]
    fn corrupt_recorded_evidence_is_rejected_even_if_the_other_key_is_incomplete() {
        let mut prior = recorded_breakdown(&seeded_breakdown(1, None));
        prior.breakdown_header = None;
        for case in ["key", "domain", "algorithm", "truncated", "extra"] {
            let mut current = recorded_breakdown(&seeded_breakdown(1, Some("toolchain")));
            match case {
                "key" => current.action_key = prior.action_key.clone(),
                "domain" => current.breakdown.items[0].domain.push('!'),
                "algorithm" => current.breakdown.items[0].algorithm = "blake3".to_owned(),
                "truncated" => current.breakdown.truncated = true,
                _ => current
                    .breakdown
                    .items
                    .push(current.breakdown.items[0].clone()),
            }
            assert!(
                compare_stored(Path::new("cas/meta.sqlite"), &prior, &current).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn identical_recorded_keys_do_not_imply_a_hit_under_quarantine() {
        let mut action = recorded_breakdown(&seeded_breakdown(1, None));
        action.action_quarantine = Some("retained blocker".to_owned());
        let explanation = compare_stored(Path::new("cas/meta.sqlite"), &action, &action).unwrap();
        assert!(explanation.comparison.as_ref().unwrap().identical);
        assert!(!explanation.serving_authorization_evaluated);
        let json = serde_json::to_value(&explanation).unwrap();
        assert_eq!(json["lookup_decision_evaluated"], false);
        assert_eq!(json["comparison"]["key_identity_only"], true);
        assert!(!format_stored_miss(&explanation).contains("expected hit"));
    }

    #[test]
    fn miss_input_modes_require_complete_exclusive_pairs() {
        use clap::Parser;
        #[derive(Parser)]
        struct Arguments {
            #[command(subcommand)]
            action: WhyAction,
        }
        for args in [
            vec!["why", "miss", "--prior", "a.json", "--current", "b.json"],
            vec!["why", "miss", "--prior-key", "a", "--current-key", "b"],
            vec![
                "why",
                "miss",
                "--prior-key",
                "a",
                "--current-key",
                "b",
                "--cas-root",
                "/tmp/cas",
            ],
        ] {
            assert!(Arguments::try_parse_from(args).is_ok());
        }
        for args in [
            vec!["why", "miss"],
            vec!["why", "miss", "--prior", "a.json"],
            vec!["why", "miss", "--current-key", "b"],
            vec!["why", "miss", "--prior", "a.json", "--current-key", "b"],
            vec![
                "why",
                "miss",
                "--prior",
                "a.json",
                "--current",
                "b.json",
                "--cas-root",
                "/tmp/cas",
            ],
            vec![
                "why",
                "miss",
                "--prior",
                "a.json",
                "--current",
                "b.json",
                "--prior-key",
                "a",
                "--current-key",
                "b",
            ],
        ] {
            assert!(Arguments::try_parse_from(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn breakdown_reads_and_parsing_are_bounded() {
        let oversized = vec![b'x'; MAX_BREAKDOWN_BYTES + 1];
        assert!(read_bounded(oversized.as_slice(), "fixture").is_err());
        assert!(explain_miss(std::str::from_utf8(&oversized).unwrap(), "{}").is_err());
        assert_eq!(
            read_bounded(&oversized[..MAX_BREAKDOWN_BYTES], "fixture")
                .unwrap()
                .len(),
            MAX_BREAKDOWN_BYTES
        );
    }

    #[test]
    fn actual_writer_to_store_lookup_compares_both_actions_and_refuses_missing_stores() {
        use rabs_cas::metadata_store::{
            AuthorityRow, RabsMetadataStore, RusqliteEngine, SqlMetadataStore,
        };
        use rabs_protocol::descriptor::{ActionClass, ActionDescriptor};
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("meta.sqlite");
        let mut store = SqlMetadataStore::open(RusqliteEngine::open(&database).unwrap()).unwrap();
        let digest = rabs_key::typed_digest::compute("rabs.why-test.v1", b"input");
        let authority = AuthorityRow {
            digest: rabs_key::typed_digest::compute("rabs.why-authority.v1", b"active"),
            cluster_id: "why-test".to_owned(),
            incarnation: 1,
            term: 1,
            acquired_seq: 1,
        };
        store.acquire_authority(&authority).unwrap();
        let mut descriptor = ActionDescriptor {
            key_epoch: 1,
            projection_epoch: 1,
            action_class: ActionClass::RustcDependencyCompile,
            normalized_invocation: digest.clone(),
            virtual_working_directory: digest.clone(),
            action_inputs: digest.clone(),
            negative_dependencies: digest.clone(),
            dependency_inputs: digest.clone(),
            toolchain: digest.clone(),
            output_platform: digest.clone(),
            environment: digest.clone(),
            sandbox_semantic_policy: digest.clone(),
            build_path_semantic_policy: digest.clone(),
            execution_semantics: digest.clone(),
            output_declarations: digest,
        };
        store
            .record_action_key_provenance(
                &authority.digest,
                &descriptor,
                "rustc-dependency-compile",
            )
            .unwrap();
        let prior = rabs_cas::metadata_store::digest_key(
            &rabs_key::action_key::compute_action_key(&descriptor).final_key,
        );
        descriptor.toolchain = rabs_key::typed_digest::compute("rabs.why-test.v1", b"new compiler");
        store
            .record_action_key_provenance(
                &authority.digest,
                &descriptor,
                "rustc-dependency-compile",
            )
            .unwrap();
        let current = rabs_cas::metadata_store::digest_key(
            &rabs_key::action_key::compute_action_key(&descriptor).final_key,
        );
        drop(store);
        let explanation = explain_stored_miss(&prior, &current, directory.path()).unwrap();
        assert_eq!(
            explanation.comparison.unwrap().causes[0].code,
            "toolchain-changed"
        );
        let unknown = explain_stored_miss(&prior, &"ab".repeat(32), directory.path()).unwrap();
        assert_eq!(unknown.unavailable.len(), 1);
        assert_eq!(unknown.unavailable[0].side, "current");
        let absent = directory.path().join("absent");
        assert!(explain_stored_miss(&prior, &current, &absent).is_err());
        assert!(!absent.exists());
    }
}
