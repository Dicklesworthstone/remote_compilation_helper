//! `rch why` — cache-miss attribution and refusal reason codes
//! (plan §102; bead K009).
//!
//! A miss explanation is the structured diff of two key breakdowns
//! (`rabs_key::diff_breakdowns`, bead F013) surfaced with STABLE reason
//! codes; index-level refusals render `LookupOutcome` codes. This is an
//! offline/explainable command by design: it consumes SEEDED breakdown
//! JSON today, and the same explanation structures bind to live store
//! lookups when M4's registry cache lands its query plane.
//!
//! Stream separation holds: stdout carries data (human lines or the
//! JSON envelope); stderr carries diagnostics only.

use std::io::Read as _;

use clap::Subcommand;
use rabs_key::action_key::{ActionKeyBreakdown, BreakdownComponent};
use rabs_key::key_diff::{LookupOutcome, diff_breakdowns};
use rabs_protocol::result_identity::{DigestAlgorithm, TypedDigest};
use serde::Deserialize;

use crate::ui::context::OutputContext;
use rch_common::ApiResponse;

/// Subcommands under `rch why`.
#[derive(Subcommand, Debug)]
pub enum WhyAction {
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
